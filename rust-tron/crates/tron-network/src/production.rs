use std::{collections::HashMap, net::SocketAddr, sync::{Arc, Mutex}, time::Duration};

use prost::Message;
use tokio::{io::{AsyncRead, AsyncWrite}, net::{TcpListener, TcpStream, UdpSocket}, sync::mpsc, task::JoinHandle, time::Instant};
use tokio_util::sync::CancellationToken;
use tron_crypto::CryptoEngine;
use tron_execution::{ChainActorHandle, RawBlock};
use tron_primitives::Hash32;
use tron_protocol::protocol::{self, block_inventory, chain_inventory, inventory};

use crate::{
    app_hello::AppHello,
    app_message::{AppMessage, AppMessageType},
    connection::Direction,
    discovery::{decode_datagram, Candidate, CandidateSource, ConnectionPool, DiscoverMessage, Endpoint, KademliaTable, NodeRecord, NodeState, Pong, Neighbours, BUCKET_SIZE, MAX_DATAGRAM_LEN},
    gossip::{Advertisement, FetchRequest, GossipService},
    handlers::{handle_block_with_engine, BlockSink, PbftHandler, TransactionHandler, TransactionSink},
    peer::{InventoryItem, PeerConnection, PeerManager},
    persistence::{read_peers, PeerStore, PersistedPeer},
    session::{session_command_channel, session_event_channel, SessionClock, SessionCommand, SessionCommandSender, SessionConfig, SessionError, SessionEvent, SessionEventReceiver, SessionRegistry, TransportSession},
    sync::{answer_sync_request, ChainInventory, SyncBlockChain, SyncBlockId},
    tcp::FramedIo,
    watchdog::{PeerStatusCheck, PEER_STATUS_INTERVAL},
};

pub const MAINNET_NETWORK_ID: i32 = 728_126_428;
pub const MAINNET_P2P_PORT: u16 = 18_888;
pub const EXTERNAL_FRAME_LIMIT: usize = 5_242_880;
pub const DEFAULT_SESSION_COMMANDS: usize = 256;
pub const DEFAULT_SESSION_COMMAND_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_SESSION_EVENTS: usize = 256;
pub const DEFAULT_SESSION_EVENT_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_NETWORK_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum ProductionNetworkError {
    #[error("protobuf: {0}")]
    Protobuf(#[from] prost::DecodeError),
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("execution actor: {0}")]
    Execution(String),
    #[error("session: {0}")]
    Session(#[from] SessionError),
    #[error("network task failed: {0}")]
    Task(String),
}

pub fn decode_sync_block_chain(payload: &[u8]) -> Result<SyncBlockChain, ProductionNetworkError> {
    let wire = protocol::BlockInventory::decode(payload)?;
    if wire.r#type != block_inventory::Type::Sync as i32 { return Err(ProductionNetworkError::Invalid("sync inventory type")); }
    Ok(SyncBlockChain { ids: wire.ids.into_iter().map(|id| decode_sync_id(id.hash, id.number)).collect::<Result<_, _>>()? })
}

pub fn encode_sync_block_chain(value: &SyncBlockChain) -> Vec<u8> {
    protocol::BlockInventory { ids: value.ids.iter().map(|id| block_inventory::BlockId { hash: id.hash.to_vec(), number: id.number }).collect(), r#type: block_inventory::Type::Sync as i32 }.encode_to_vec()
}

pub fn decode_chain_inventory(payload: &[u8]) -> Result<ChainInventory, ProductionNetworkError> {
    let wire = protocol::ChainInventory::decode(payload)?;
    Ok(ChainInventory { ids: wire.ids.into_iter().map(|id| decode_sync_id(id.hash, id.number)).collect::<Result<_, _>>()?, remain: wire.remain_num })
}

pub fn encode_chain_inventory(value: &ChainInventory) -> Vec<u8> {
    protocol::ChainInventory { ids: value.ids.iter().map(|id| chain_inventory::BlockId { hash: id.hash.to_vec(), number: id.number }).collect(), remain_num: value.remain }.encode_to_vec()
}

pub fn decode_inventory(payload: &[u8]) -> Result<(crate::gossip::InventoryType, Vec<[u8; 32]>), ProductionNetworkError> {
    let wire = protocol::Inventory::decode(payload)?;
    let kind = match inventory::InventoryType::try_from(wire.r#type).map_err(|_| ProductionNetworkError::Invalid("inventory type"))? {
        inventory::InventoryType::Trx => crate::gossip::InventoryType::Transaction,
        inventory::InventoryType::Block => crate::gossip::InventoryType::Block,
    };
    let ids = wire.ids.into_iter().map(|id| id.try_into().map_err(|_| ProductionNetworkError::Invalid("inventory hash length"))).collect::<Result<_, _>>()?;
    Ok((kind, ids))
}

pub fn encode_inventory(kind: crate::gossip::InventoryType, ids: &[[u8; 32]]) -> Vec<u8> {
    let r#type = match kind { crate::gossip::InventoryType::Transaction => inventory::InventoryType::Trx, crate::gossip::InventoryType::Block => inventory::InventoryType::Block };
    protocol::Inventory { r#type: r#type as i32, ids: ids.iter().map(|id| id.to_vec()).collect() }.encode_to_vec()
}

fn decode_sync_id(hash: Vec<u8>, number: i64) -> Result<SyncBlockId, ProductionNetworkError> {
    Ok(SyncBlockId { hash: hash.try_into().map_err(|_| ProductionNetworkError::Invalid("block id hash length"))?, number })
}

pub trait NetworkBroadcaster: Send + Sync {
    fn broadcast(&self, message: AppMessage, except: SocketAddr);
    fn start_sync(&self, peer: SocketAddr);
}

#[derive(Clone)]
pub struct ActorTransactionSink {
    actor: ChainActorHandle,
    broadcaster: Arc<dyn NetworkBroadcaster>,
}
impl ActorTransactionSink { pub fn new(actor: ChainActorHandle, broadcaster: Arc<dyn NetworkBroadcaster>) -> Self { Self { actor, broadcaster } } }
impl TransactionSink for ActorTransactionSink {
    fn known_transaction(&self, id: &[u8; 32]) -> bool { self.actor.known_transaction(Hash32::from_array(*id)).unwrap_or(false) }
    fn process_transaction(&mut self, encoded: Vec<u8>, received_at: i64) -> Result<(), String> { self.actor.broadcast_raw(encoded, received_at, false).map(|_| ()).map_err(|error| error.to_string()) }
    fn broadcast_transaction(&mut self, encoded: &[u8], except: &PeerConnection) {
        if let Ok(message) = AppMessage::from_payload(AppMessageType::Transaction, encoded.to_vec()) { self.broadcaster.broadcast(message, except.address); }
    }
}

pub trait CanonicalNetworkView: Send + Sync {
    fn head_number(&self) -> i64;
    fn has_parent(&self, block: &RawBlock, engine: CryptoEngine) -> bool;
}

pub struct ActorBlockSink {
    actor: ChainActorHandle,
    view: Arc<dyn CanonicalNetworkView>,
    broadcaster: Arc<dyn NetworkBroadcaster>,
    engine: CryptoEngine,
    clock: Arc<dyn SessionClock>,
}
impl ActorBlockSink { pub fn new(actor: ChainActorHandle, view: Arc<dyn CanonicalNetworkView>, broadcaster: Arc<dyn NetworkBroadcaster>, engine: CryptoEngine, clock: Arc<dyn SessionClock>) -> Self { Self { actor, view, broadcaster, engine, clock } } }
impl BlockSink for ActorBlockSink {
    fn validate_block(&mut self, block: &RawBlock) -> Result<(), String> { self.actor.validate_network_block(block.message.encode_to_vec(), self.clock.unix_millis()).map(|_| ()).map_err(|error| error.to_string()) }
    fn has_parent(&self, block: &RawBlock) -> bool { self.view.has_parent(block, self.engine) }
    fn head_number(&self) -> i64 { self.view.head_number() }
    fn broadcast_block(&mut self, encoded: &[u8], except: &PeerConnection) { if let Ok(message) = AppMessage::from_payload(AppMessageType::Block, encoded.to_vec()) { self.broadcaster.broadcast(message, except.address); } }
    fn process_block(&mut self, block: RawBlock, received_at: i64) -> Result<(), String> { self.actor.accept_network_block(block.message.encode_to_vec(), received_at).map(|_| ()).map_err(|error| error.to_string()) }
    fn start_sync(&mut self, peer: &PeerConnection) { self.broadcaster.start_sync(peer.address); }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImmutableNetworkSnapshot {
    pub peers: Arc<[SocketAddr]>,
    pub active: usize,
    pub passive: usize,
    pub traffic_in: u64,
    pub traffic_out: u64,
}

pub struct ProductionSession {
    pub commands: SessionCommandSender,
    pub events: SessionEventReceiver,
}


pub struct ProductionPbftConfig {
    pub handler: Arc<Mutex<PbftHandler>>,
    pub context: Arc<dyn Fn(&[u8]) -> Result<tron_consensus::pbft::PbftContext, String> + Send + Sync>,
    pub persist: Arc<dyn Fn(&tron_consensus::pbft::CommitData) -> Result<(), String> + Send + Sync>,
    pub expire_blocks: i64,
    pub next_maintenance: Arc<dyn Fn() -> i64 + Send + Sync>,
    pub maintenance_interval: i64,
}

pub struct ProductionDiscoveryConfig {
    pub socket: UdpSocket,
    pub persist: Option<Arc<dyn PeerStore>>,
    pub refresh_interval: Duration,
}

pub struct ProductionNetworkConfig {
    pub listener: TcpListener,
    pub discovery: Option<ProductionDiscoveryConfig>,
    pub active_nodes: Vec<SocketAddr>,
    pub session: SessionConfig,
    pub app_hello: AppHello,
    pub transaction_sink: Box<dyn TransactionSink + Send>,
    pub block_sink: Box<dyn BlockSink + Send>,
    pub sync_head: Arc<dyn Fn() -> i64 + Send + Sync>,
    pub sync_id_at: Arc<dyn Fn(i64) -> Option<SyncBlockId> + Send + Sync>,
    pub sync_on_main: Arc<dyn Fn(&SyncBlockId) -> bool + Send + Sync>,
    pub pbft: Option<ProductionPbftConfig>,
    pub clock: Arc<dyn SessionClock>,
    pub engine: CryptoEngine,
}

struct NetworkState {
    peers: PeerManager,
    commands: HashMap<SocketAddr, SessionCommandSender>,
    sessions: HashMap<SocketAddr, JoinHandle<Result<crate::framing::Traffic, SessionError>>>,
    dispatchers: Vec<JoinHandle<()>>,
    gossip: GossipService,
    transactions: TransactionHandler,
}

pub struct ProductionNetwork {
    registry: SessionRegistry,
    cancel: CancellationToken,
    state: Arc<Mutex<NetworkState>>,
    fatal_tx: mpsc::Sender<String>,
    fatal_rx: tokio::sync::Mutex<mpsc::Receiver<String>>,
    listener: Mutex<Option<TcpListener>>,
    discovery: Mutex<Option<ProductionDiscoveryConfig>>,
    accept: Mutex<Option<JoinHandle<()>>>,
    background_tasks: Mutex<Vec<JoinHandle<()>>>,
    active_nodes: Vec<SocketAddr>,
    session: SessionConfig,
    app_hello: AppHello,
    transaction_sink: Arc<Mutex<Box<dyn TransactionSink + Send>>>,
    block_sink: Arc<Mutex<Box<dyn BlockSink + Send>>>,
    sync_head: Arc<dyn Fn() -> i64 + Send + Sync>,
    sync_id_at: Arc<dyn Fn(i64) -> Option<SyncBlockId> + Send + Sync>,
    sync_on_main: Arc<dyn Fn(&SyncBlockId) -> bool + Send + Sync>,
    pbft: Option<ProductionPbftConfig>,
    clock: Arc<dyn SessionClock>,
    engine: CryptoEngine,
}

impl ProductionNetwork {
    pub fn new(config: ProductionNetworkConfig) -> Result<Arc<Self>, ProductionNetworkError> {
        let address=config.listener.local_addr().map_err(|error|ProductionNetworkError::Task(error.to_string()))?;
        if config.session.admission.network_id==0{return Err(ProductionNetworkError::Invalid("network id"))}
        if config.session.local_hello.from.as_ref().is_none_or(|endpoint|endpoint.node_id.is_empty()){return Err(ProductionNetworkError::Invalid("local node identity"))}
        if address.port()==0{return Err(ProductionNetworkError::Invalid("prebound listener"))}
        let (fatal_tx,fatal_rx)=mpsc::channel(16);
        Ok(Arc::new(Self{registry:SessionRegistry::default(),cancel:CancellationToken::new(),state:Arc::new(Mutex::new(NetworkState{peers:PeerManager::default(),commands:HashMap::new(),sessions:HashMap::new(),dispatchers:Vec::new(),gossip:GossipService::default(),transactions:TransactionHandler::new(1024)})),fatal_tx,fatal_rx:tokio::sync::Mutex::new(fatal_rx),listener:Mutex::new(Some(config.listener)),discovery:Mutex::new(config.discovery),accept:Mutex::new(None),background_tasks:Mutex::new(Vec::new()),active_nodes:config.active_nodes,session:config.session,app_hello:config.app_hello,transaction_sink:Arc::new(Mutex::new(config.transaction_sink)),block_sink:Arc::new(Mutex::new(config.block_sink)),sync_head:config.sync_head,sync_id_at:config.sync_id_at,sync_on_main:config.sync_on_main,pbft:config.pbft,clock:config.clock,engine:config.engine}))
    }
    pub fn registry(&self)->SessionRegistry{self.registry.clone()}
    pub fn engine(&self)->CryptoEngine{self.engine}
    pub fn local_addr(&self)->Result<SocketAddr,ProductionNetworkError>{self.listener.lock().map_err(|_|ProductionNetworkError::Task("listener lock poisoned".into()))?.as_ref().ok_or(ProductionNetworkError::Invalid("network already started"))?.local_addr().map_err(|error|ProductionNetworkError::Task(error.to_string()))}
    pub async fn send_to(&self,peer:SocketAddr,message:AppMessage)->Result<(),ProductionNetworkError>{let sender=self.state.lock().map_err(|_|ProductionNetworkError::Task("network state lock poisoned".into()))?.commands.get(&peer).cloned().ok_or(ProductionNetworkError::Invalid("unknown peer"))?;sender.send(SessionCommand::Send(message.send_bytes())).await.map_err(Into::into)}
    pub async fn next_fatal(&self)->Option<String>{self.fatal_rx.lock().await.recv().await}
    pub fn start(self:&Arc<Self>)->Result<(),ProductionNetworkError>{
        let listener=self.listener.lock().map_err(|_|ProductionNetworkError::Task("listener lock poisoned".into()))?.take().ok_or(ProductionNetworkError::Invalid("network already started"))?;
        let owner=self.clone();let cancel=self.cancel.child_token();
        *self.accept.lock().map_err(|_|ProductionNetworkError::Task("accept lock poisoned".into()))?=Some(tokio::spawn(async move{loop{tokio::select!{_=cancel.cancelled()=>break,result=listener.accept()=>match result{Ok((stream,remote))=>{if let Err(error)=owner.attach(stream,remote,Direction::Passive){let _=owner.fatal_tx.send(error.to_string()).await;}},Err(error)=>{let _=owner.fatal_tx.send(error.to_string()).await;break}}}}}));
        if let Some(discovery)=self.discovery.lock().map_err(|_|ProductionNetworkError::Task("discovery lock poisoned".into()))?.take(){
            let owner=self.clone();let cancel=self.cancel.child_token();let local=self.app_hello.message().from.clone().map(|ep|Endpoint{address:ep.address,port:ep.port,node_id:ep.node_id,address_ipv6:ep.address_ipv6}).ok_or(ProductionNetworkError::Invalid("discovery endpoint"))?;
            let task=tokio::spawn(async move{
                let mut packet=[0u8;MAX_DATAGRAM_LEN+1];let mut table=KademliaTable::new(local.node_id.as_slice().try_into().unwrap_or([0;64]));let mut pool=ConnectionPool::new(4096);let mut ticker=tokio::time::interval(discovery.refresh_interval.max(Duration::from_millis(10)));let mut watchdog=tokio::time::interval(PEER_STATUS_INTERVAL);let mut persist_tick=tokio::time::interval(crate::persistence::PERSIST_INTERVAL);let store=discovery.persist;
                if let Some(store)=store.as_ref(){for peer in read_peers(store.as_ref()){if let Ok(address)=format!("{}:{}",peer.host,peer.port).parse(){pool.offer(Candidate{address,node_id:Vec::new(),source:CandidateSource::Persisted,update_time:peer.update_time,latency:None,failures:0});}}}
                loop{tokio::select!{
                    _=cancel.cancelled()=>{if let Some(store)=store.as_ref(){let peers=table.nodes().map(|n|PersistedPeer{host:n.address.ip().to_string(),port:n.address.port(),update_time:n.update_time});if let Err(error)=crate::persistence::write_peers(store.as_ref(),peers){let _=owner.fatal_tx.send(format!("peer persistence: {error}")).await;}}break},
                    _=ticker.tick()=>{let now=owner.clock.unix_millis();for remote in owner.active_nodes.iter().copied(){let ping=crate::discovery::Ping{from:Some(local.clone()),to:None,version:owner.session.local_hello.version,timestamp:now};if let Ok(bytes)=DiscoverMessage::Ping(ping).encode_datagram(){if let Err(error)=discovery.socket.send_to(&bytes,remote).await{let _=owner.fatal_tx.send(format!("discovery send {remote}: {error}")).await;break}}}},
                    _=persist_tick.tick()=>{if let Some(store)=store.as_ref(){let peers=table.nodes().map(|n|PersistedPeer{host:n.address.ip().to_string(),port:n.address.port(),update_time:n.update_time});if let Err(error)=crate::persistence::write_peers(store.as_ref(),peers){let _=owner.fatal_tx.send(format!("peer persistence: {error}")).await;break}}},
                    _=watchdog.tick()=>{let disconnects={let mut state=owner.state.lock().expect("network state lock poisoned");PeerStatusCheck.check(&mut state.peers,owner.clock.unix_millis())};for disconnect in disconnects{let sender={owner.state.lock().expect("network state lock poisoned").commands.get(&disconnect.address).cloned()};if let Some(sender)=sender{let _=sender.send(SessionCommand::Disconnect(crate::handshake::DisconnectReason::PingTimeout)).await;}}},
                    result=discovery.socket.recv_from(&mut packet)=>match result{Err(error)=>{let _=owner.fatal_tx.send(format!("discovery receive: {error}")).await;break},Ok((n,from))=>if let Ok(message)=decode_datagram(&packet[..n]){let now=owner.clock.unix_millis();let endpoint=match &message{DiscoverMessage::Ping(v)=>v.from.as_ref(),DiscoverMessage::Pong(v)=>v.from.as_ref(),DiscoverMessage::FindNeighbours(v)=>v.from.as_ref(),DiscoverMessage::Neighbours(v)=>v.from.as_ref()};if let Some(endpoint)=endpoint{if let Ok(address)=crate::discovery::validate_endpoint(endpoint,Some(from)){table.insert(NodeRecord{endpoint:endpoint.clone(),address,state:NodeState::Alive,update_time:now,last_seen:now,failures:0});pool.offer(Candidate{address,node_id:endpoint.node_id.clone(),source:CandidateSource::Discovered,update_time:now,latency:None,failures:0});}}
                        let reply=match message{DiscoverMessage::Ping(v)=>Some(DiscoverMessage::Pong(Pong{from:Some(local.clone()),echo:v.version,timestamp:now})),DiscoverMessage::FindNeighbours(v)=>Some(DiscoverMessage::Neighbours(Neighbours{from:Some(local.clone()),neighbours:table.closest(&v.target_id,BUCKET_SIZE).into_iter().map(|n|n.endpoint.clone()).collect(),timestamp:now})),DiscoverMessage::Neighbours(v)=>{for ep in v.neighbours{if let Ok(address)=crate::discovery::validate_endpoint(&ep,None){table.insert(NodeRecord{endpoint:ep.clone(),address,state:NodeState::Discovered,update_time:now,last_seen:now,failures:0});pool.offer(Candidate{address,node_id:ep.node_id,source:CandidateSource::Discovered,update_time:now,latency:None,failures:0});}}None},DiscoverMessage::Pong(_)=>None};if let Some(reply)=reply{if let Ok(bytes)=reply.encode_datagram(){let _=discovery.socket.send_to(&bytes,from).await;}}
                    }}
                }}
            });self.background_tasks.lock().expect("background tasks lock poisoned").push(task);
        }
        for remote in self.active_nodes.iter().copied(){let owner=self.clone();let cancel=self.cancel.child_token();let task=tokio::spawn(async move{tokio::select!{biased;_=cancel.cancelled()=>{},result=TcpStream::connect(remote)=>match result{Ok(stream)=>{if let Err(error)=owner.attach(stream,remote,Direction::Active){let _=owner.fatal_tx.try_send(error.to_string());}},Err(error)=>{let _=owner.fatal_tx.try_send(format!("{remote}: {error}"));}}}});self.background_tasks.lock().expect("background tasks lock poisoned").push(task);}
        Ok(())
    }
    fn attach(self:&Arc<Self>,stream:TcpStream,remote:SocketAddr,direction:Direction)->Result<(),ProductionNetworkError>{
        let mut config=self.session.clone();config.direction=direction;
        let session=self.spawn_session(FramedIo::new(stream,config.write_timeout),remote,config)?;
        let owner=self.clone();let commands=session.commands.clone();
        let dispatch=tokio::spawn(async move{owner.dispatch(remote,direction,commands,session.events).await;});
        self.state.lock().map_err(|_|ProductionNetworkError::Task("network state lock poisoned".into()))?.dispatchers.push(dispatch);Ok(())
    }
    pub fn spawn_session<T>(&self,io:FramedIo<T>,remote:SocketAddr,config:SessionConfig)->Result<ProductionSession,ProductionNetworkError> where T:AsyncRead+AsyncWrite+Unpin+Send+Sync+'static{
        let(command_tx,command_rx)=session_command_channel(DEFAULT_SESSION_COMMANDS,DEFAULT_SESSION_COMMAND_BYTES,Duration::from_secs(1));let(event_tx,event_rx)=session_event_channel(DEFAULT_SESSION_EVENTS,DEFAULT_SESSION_EVENT_BYTES,Duration::from_secs(1));
        let session=TransportSession::new(io,remote,config,self.registry.clone()).with_events(event_tx).with_commands(command_rx).with_clock(self.clock.clone());let cancel=self.cancel.child_token();let fatal=self.fatal_tx.clone();
        let join=tokio::spawn(async move{let result=session.run(cancel).await;if let Err(error)=&result{let _=fatal.try_send(format!("{remote}: {error}"));}result});
        let mut state=self.state.lock().map_err(|_|ProductionNetworkError::Task("network state lock poisoned".into()))?;if state.sessions.contains_key(&remote){return Err(ProductionNetworkError::Invalid("duplicate production session"))}state.commands.insert(remote,command_tx.clone());state.sessions.insert(remote,join);Ok(ProductionSession{commands:command_tx,events:event_rx})
    }
    async fn dispatch(self:Arc<Self>,remote:SocketAddr,direction:Direction,commands:SessionCommandSender,mut events:SessionEventReceiver){
        let mut app_connected=false;
        loop {
            let event=tokio::select!{biased;_=self.cancel.cancelled()=>break,event=events.recv()=>event.map(|event|event.into_event())};
            let Some(event)=event else{break};
            let result=match event{
                SessionEvent::State(crate::session::SessionState::Connected)=>commands.send(SessionCommand::Send(self.app_hello.clone().into_app_message().expect("configured hello").send_bytes())).await.map_err(ProductionNetworkError::from),
                SessionEvent::Message(bytes)=>self.dispatch_message(remote,direction,&commands,bytes,&mut app_connected).await,
                SessionEvent::Disconnected(_)|SessionEvent::State(crate::session::SessionState::Closed)=>break,
                _=>Ok(()),
            };if let Err(error)=result{let _=commands.try_send(SessionCommand::Disconnect(crate::handshake::DisconnectReason::BadProtocol));let _=self.fatal_tx.try_send(format!("{remote}: {error}"));break}
        }
        let mut state=self.state.lock().expect("network state lock poisoned");state.commands.remove(&remote);state.gossip.disconnect(remote);if let Some(mut peer)=state.peers.remove(remote){peer.cleanup();}
    }
    async fn dispatch_message(&self,remote:SocketAddr,direction:Direction,commands:&SessionCommandSender,bytes:Vec<u8>,app_connected:&mut bool)->Result<(),ProductionNetworkError>{
        let message=AppMessage::parse(bytes).map_err(|_|ProductionNetworkError::Invalid("application message"))?;let now=self.clock.unix_millis();
        if !*app_connected&&message.kind()!=AppMessageType::Hello{return Err(ProductionNetworkError::Invalid("expected application hello"))}
        if message.kind()==AppMessageType::Hello{let hello=AppHello::decode(message.payload().to_vec())?;if !hello.structurally_valid(){return Err(ProductionNetworkError::Invalid("application hello"))}let remote_head=hello.message().head_block_id.as_ref().map_or(0,|id|id.number);let local_head=(self.sync_head)();let mut state=self.state.lock().map_err(|_|ProductionNetworkError::Task("network state lock poisoned".into()))?;let mut peer=PeerConnection::new(remote,direction,now);peer.hello_received=Some(hello);peer.hello_sent=Some(self.app_hello.clone());peer.on_connected_heads(local_head,remote_head);state.gossip.add_peer(remote,peer.is_sync_finished());state.peers.add(peer);*app_connected=true;return Ok(())}
        match message.kind(){
            AppMessageType::Ping=>commands.send(SessionCommand::Send(AppMessage::pong().send_bytes())).await.map_err(Into::into),
            AppMessageType::Pong=>Ok(()),
            AppMessageType::Disconnect=>{commands.send(SessionCommand::Disconnect(crate::handshake::DisconnectReason::PeerQuiting)).await.map_err(Into::into)},
            AppMessageType::SyncBlockChain=>{let request=decode_sync_block_chain(message.payload())?;let head=(self.sync_head)();let response=answer_sync_request(&request,head,None,|id|(self.sync_on_main)(id),|height|(self.sync_id_at)(height)).map_err(|_|ProductionNetworkError::Invalid("sync request"))?;let reply=AppMessage::from_payload(AppMessageType::ChainInventory,encode_chain_inventory(&response)).map_err(|_|ProductionNetworkError::Invalid("chain inventory"))?;commands.send(SessionCommand::Send(reply.send_bytes())).await.map_err(Into::into)},
            AppMessageType::ChainInventory=>{let inventory=decode_chain_inventory(message.payload())?;let mut state=self.state.lock().map_err(|_|ProductionNetworkError::Task("network state lock poisoned".into()))?;let complete={let peer=state.peers.get_mut(remote).ok_or(ProductionNetworkError::Invalid("unknown peer"))?;peer.remain_num=inventory.remain;if inventory.remain==0{peer.need_sync_from_peer=false;}peer.is_sync_finished()};if inventory.remain==0{state.gossip.set_sync_complete(remote,complete);}Ok(())},
            AppMessageType::Inventory=>{let(kind,hashes)=decode_inventory(message.payload())?;let fetch={let mut state=self.state.lock().map_err(|_|ProductionNetworkError::Task("network state lock poisoned".into()))?;let accepted=state.gossip.receive_inventory(remote,Advertisement{kind,hashes},now).map_err(|_|ProductionNetworkError::Invalid("inventory"))?;let peer=state.peers.get_mut(remote).ok_or(ProductionNetworkError::Invalid("unknown peer"))?;let accepted_hashes=accepted.iter().map(|key|key.hash).collect::<Vec<_>>();for hash in &accepted_hashes{peer.check_and_put_request(InventoryItem{hash:*hash,kind:match kind{crate::gossip::InventoryType::Transaction=>0,crate::gossip::InventoryType::Block=>1}},now);}encode_inventory(kind,&accepted_hashes)};if fetch.len()>2{let request=AppMessage::from_payload(AppMessageType::FetchInventoryData,fetch).map_err(|_|ProductionNetworkError::Invalid("fetch"))?;commands.send(SessionCommand::Send(request.send_bytes())).await?;}Ok(())},
            AppMessageType::FetchInventoryData=>{let(kind,hashes)=decode_inventory(message.payload())?;let batches={let mut state=self.state.lock().map_err(|_|ProductionNetworkError::Task("network state lock poisoned".into()))?;state.gossip.serve_fetch(remote,&FetchRequest{kind,hashes},now,|_|false).map_err(|_|ProductionNetworkError::Invalid("fetch"))?};for batch in batches{for payload in batch{let kind=match payload.key.kind{crate::gossip::InventoryType::Transaction=>AppMessageType::Transaction,crate::gossip::InventoryType::Block=>AppMessageType::Block};commands.send(SessionCommand::Send(AppMessage::from_payload(kind,payload.bytes).map_err(|_|ProductionNetworkError::Invalid("payload"))?.send_bytes())).await?;} }Ok(())},
            AppMessageType::Transaction|AppMessageType::Transactions=>{let payload=if message.kind()==AppMessageType::Transaction{protocol::Transactions{transactions:vec![protocol::Transaction::decode(message.payload())?]}.encode_to_vec()}else{message.payload().to_vec()};let mut state=self.state.lock().map_err(|_|ProductionNetworkError::Task("network state lock poisoned".into()))?;let mut peer=state.peers.remove(remote).ok_or(ProductionNetworkError::Invalid("unknown peer"))?;let result=state.transactions.receive(&mut peer,&payload,now).map_err(|_|ProductionNetworkError::Invalid("transactions"));if result.is_ok(){state.transactions.drain(&peer,self.transaction_sink.lock().expect("transaction sink poisoned").as_mut(),usize::MAX);}state.peers.add(peer);result.map(|_|())},
            AppMessageType::Block=>{let mut state=self.state.lock().map_err(|_|ProductionNetworkError::Task("network state lock poisoned".into()))?;let peer=state.peers.get_mut(remote).ok_or(ProductionNetworkError::Invalid("unknown peer"))?;handle_block_with_engine(peer,message.payload(),now,false,self.engine,self.block_sink.lock().expect("block sink poisoned").as_mut()).map_err(|_|ProductionNetworkError::Invalid("block"))?;Ok(())},
            AppMessageType::PbftCommit=>{PbftHandler::decode_commit(message.payload()).map_err(|_|ProductionNetworkError::Invalid("pbft commit"))?;Ok(())},
            AppMessageType::Pbft=>{let pbft=self.pbft.as_ref().ok_or(ProductionNetworkError::Invalid("pbft unavailable"))?;let context=(pbft.context)(message.payload()).map_err(ProductionNetworkError::Task)?;let effects=pbft.handler.lock().map_err(|_|ProductionNetworkError::Task("pbft handler lock poisoned".into()))?.handle_wire(message.payload(),context,(self.sync_head)(),pbft.expire_blocks,(pbft.next_maintenance)(),pbft.maintenance_interval).map_err(|error|ProductionNetworkError::Task(error.to_string()))?;for effect in effects{match effect{tron_consensus::pbft::Effect::Forward(bytes)=>{let forward=AppMessage::from_payload(AppMessageType::Pbft,bytes).map_err(|_|ProductionNetworkError::Invalid("pbft forward"))?;self.broadcast(forward,remote)},tron_consensus::pbft::Effect::Commit(commit)=>(pbft.persist)(&commit).map_err(ProductionNetworkError::Task)?}}Ok(())},
            AppMessageType::Hello=>unreachable!(),
        }
    }
    pub fn broadcast(&self,message:AppMessage,except:SocketAddr){let senders=self.state.lock().expect("network state lock poisoned").commands.iter().filter(|(peer,_)|**peer!=except).map(|(_,sender)|sender.clone()).collect::<Vec<_>>();for sender in senders{let bytes=message.send_bytes();tokio::spawn(async move{let _=sender.send(SessionCommand::Send(bytes)).await;});}}
    pub fn publish(&self,payload:crate::gossip::Payload)->Result<(),ProductionNetworkError>{let now=self.clock.unix_millis();let key=payload.key.clone();let targets={let mut state=self.state.lock().map_err(|_|ProductionNetworkError::Task("network state lock poisoned".into()))?;state.gossip.cache(payload,now).map_err(|_|ProductionNetworkError::Invalid("gossip payload"))?;state.gossip.spread(key.clone(),now)};let inventory=AppMessage::from_payload(AppMessageType::Inventory,encode_inventory(key.kind,&[key.hash])).map_err(|_|ProductionNetworkError::Invalid("inventory"))?;for target in targets{let sender=self.state.lock().expect("network state lock poisoned").commands.get(&target).cloned();if let Some(sender)=sender{let bytes=inventory.send_bytes();tokio::spawn(async move{let _=sender.send(SessionCommand::Send(bytes)).await;});}}Ok(())}
    pub fn snapshot(&self)->ImmutableNetworkSnapshot{let state=self.state.lock().expect("network state lock poisoned");let mut peers=state.commands.keys().copied().collect::<Vec<_>>();peers.sort_unstable();let(active,passive)=state.peers.counts();ImmutableNetworkSnapshot{peers:peers.into(),active,passive,traffic_in:0,traffic_out:0}}
    pub async fn shutdown(&self)->Result<(),ProductionNetworkError>{self.shutdown_with_timeout(DEFAULT_NETWORK_SHUTDOWN_TIMEOUT).await}
    pub async fn shutdown_with_timeout(&self,timeout:Duration)->Result<(),ProductionNetworkError>{
        self.cancel.cancel();
        let senders=self.state.lock().map_err(|_|ProductionNetworkError::Task("network state lock poisoned".into()))?.commands.values().cloned().collect::<Vec<_>>();
        for sender in senders{let _=sender.try_send(SessionCommand::Disconnect(crate::handshake::DisconnectReason::PeerQuiting));}
        let mut tasks=Vec::new();
        if let Some(task)=self.accept.lock().expect("accept lock poisoned").take(){tasks.push(task);}
        tasks.extend(std::mem::take(&mut *self.background_tasks.lock().expect("background tasks lock poisoned")));
        let(sessions,dispatchers)={let mut state=self.state.lock().map_err(|_|ProductionNetworkError::Task("network state lock poisoned".into()))?;(std::mem::take(&mut state.sessions).into_values().collect::<Vec<_>>(),std::mem::take(&mut state.dispatchers))};
        let deadline=Instant::now()+timeout;
        let mut sessions=sessions;
        for index in 0..sessions.len() {
            if tokio::time::timeout_at(deadline,&mut sessions[index]).await.is_err(){
                for task in &sessions[index..]{task.abort();}for task in &tasks{task.abort();}for task in &dispatchers{task.abort();}
                for task in &mut sessions[index..]{let _=task.await;}for task in &mut tasks{let _=task.await;}for task in dispatchers{let _=task.await;}
                return Err(ProductionNetworkError::Task(format!("network shutdown deadline elapsed with {} sessions remaining",sessions.len()-index)));
            }
        }
        tasks.extend(dispatchers);
        for index in 0..tasks.len(){
            if tokio::time::timeout_at(deadline,&mut tasks[index]).await.is_err(){
                for task in &tasks[index..]{task.abort();}
                for task in &mut tasks[index..]{let _=task.await;}
                return Err(ProductionNetworkError::Task(format!("network shutdown deadline elapsed with {} tasks remaining",tasks.len()-index)));
            }
        }
        Ok(())
    }
}

impl NetworkBroadcaster for ProductionNetwork {fn broadcast(&self,message:AppMessage,except:SocketAddr){Self::broadcast(self,message,except)}fn start_sync(&self,_peer:SocketAddr){}}
