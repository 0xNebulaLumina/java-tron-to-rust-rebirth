use std::{collections::HashSet,io::{BufRead,BufReader},net::{SocketAddr,TcpListener as StdTcpListener},process::{Child,Command,Stdio},time::Duration};
use prost::Message;
use tokio::net::{TcpListener,TcpStream};
use tokio_util::sync::CancellationToken;
use tron_network::{app_message::{AppMessage,AppMessageType},connection::{Direction,PoolConfig},gossip::{Advertisement,FetchRequest,GossipService,InventoryKey,InventoryType,Payload},handlers::{transaction_id_from_wire,TransactionHandler,TransactionSink},handshake::{AdmissionConfig,Endpoint,HelloMessage},peer::{InventoryItem,PeerConnection,PeerManager},session::{session_event_channel,SessionConfig,SessionEvent,SessionRegistry,TransportSession},sync::{answer_sync_request,ChainInventory,SyncBlockChain,SyncBlockId,SyncCoordinator},tcp::FramedIo,watchdog::PeerStatusCheck};

fn java(mode:&str,port:u16)->Child{Command::new(std::env::var("C021_JAVA").unwrap()).args(["-cp",&std::env::var("C021_ORACLE_CP").unwrap(),"C021Oracle",mode,&port.to_string()]).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap()}
fn java_probe(id:&str)->(Vec<Vec<u8>>,String){
    let output=Command::new(std::env::var("C021_JAVA").unwrap()).args(["-cp",&std::env::var("C021_ORACLE_CP").unwrap(),"C021Oracle","scenario",id]).output().unwrap();
    assert!(output.status.success(),"Java scenario {id} failed: {}",String::from_utf8_lossy(&output.stderr));
    let text=String::from_utf8(output.stdout).unwrap();
    assert!(text.lines().any(|line|line==format!("SCENARIO_ID={id}")));assert!(text.contains("JAVA_PROVENANCE=production TronMessageFactory/PbftMessageFactory plus named handler invocation"));assert!(text.contains("SCENARIO_OK"));
    let raw=text.lines().find_map(|line|line.strip_prefix("RAW_MESSAGES=")).unwrap().split(',').map(|value|hex::decode(value).unwrap()).collect();
    let state=text.lines().find_map(|line|line.strip_prefix("JAVA_STATE=")).unwrap().to_owned();
    (raw,state)
}
fn wait_ready(child:&mut Child){let mut r=BufReader::new(child.stdout.take().unwrap());let mut s=String::new();loop{assert!(r.read_line(&mut s).unwrap()>0,"Java exited before READY");if s.contains("READY"){break}s.clear();}}
fn port()->u16{StdTcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()}
fn config(port:u16,direction:Direction)->SessionConfig{SessionConfig{local_hello:HelloMessage{from:Some(Endpoint{address:b"127.0.0.1".to_vec(),port:i32::from(port),node_id:vec![8;64],address_ipv6:vec![]}),network_id:728126428,code:0,timestamp:9,version:1},direction,admission:AdmissionConfig{network_id:728126428,version:1,max_connections:8,max_same_ip:8,trusted:HashSet::new(),ban_duration:Duration::from_secs(1)},pool:PoolConfig{min_connections:1,max_connections:8,min_active:1,max_same_ip:8,initial_backoff:Duration::from_millis(10),max_backoff:Duration::from_secs(1)},keepalive_interval:Duration::from_millis(50),pong_timeout:Duration::from_secs(1),write_timeout:Duration::from_secs(3),compression:true}}

#[derive(Default,Debug,PartialEq)]
struct Terminal{hello:usize,ping:usize,sync:usize,chain:usize,inventory:usize,fetch:usize,tx:usize,block:usize,pbft:usize,commit:usize,disconnected:bool,events:Vec<AppMessageType>}
fn apply(s:&mut Terminal,bytes:Vec<u8>){let m=AppMessage::parse(bytes).unwrap();s.events.push(m.kind());match m.kind(){AppMessageType::Hello=>s.hello+=1,AppMessageType::Ping=>s.ping+=1,AppMessageType::SyncBlockChain=>s.sync+=1,AppMessageType::ChainInventory=>s.chain+=1,AppMessageType::Inventory=>s.inventory+=1,AppMessageType::FetchInventoryData=>s.fetch+=1,AppMessageType::Transaction=>s.tx+=1,AppMessageType::Block=>s.block+=1,AppMessageType::Pbft=>s.pbft+=1,AppMessageType::PbftCommit=>s.commit+=1,AppMessageType::Disconnect=>s.disconnected=true,_=>panic!("unexpected C021 application message")}}
fn expected()->Terminal{Terminal{hello:1,ping:1,sync:1,chain:1,inventory:1,fetch:1,tx:1,block:1,pbft:1,commit:1,disconnected:true,events:vec![AppMessageType::Hello,AppMessageType::Ping,AppMessageType::SyncBlockChain,AppMessageType::ChainInventory,AppMessageType::Inventory,AppMessageType::FetchInventoryData,AppMessageType::Transaction,AppMessageType::Block,AppMessageType::Pbft,AppMessageType::PbftCommit,AppMessageType::Disconnect]}}
async fn run_live(stream:TcpStream,port:u16,direction:Direction){let registry=SessionRegistry::default();let (tx,mut rx)=session_event_channel(64,4<<20,Duration::from_secs(1));let session=TransportSession::new(FramedIo::new(stream,Duration::from_secs(3)),"127.0.0.1:18888".parse().unwrap(),config(port,direction),registry.clone()).with_events(tx);let traffic=session.run(CancellationToken::new()).await.unwrap();assert!(traffic.received_payload>0);let mut state=Terminal::default();while let Ok(event)=rx.try_recv(){match event.into_event(){SessionEvent::Message(bytes)=>apply(&mut state,bytes),SessionEvent::Disconnected(_)=>state.disconnected=true,_=>{}}}assert_eq!(state,expected());assert_eq!(registry.pool.lock().unwrap().len(),0);assert_eq!(registry.admission.lock().unwrap().len(),0)}

#[tokio::test(flavor="current_thread")]
async fn java_passive_rust_active_genesis_to_head_and_terminal_state(){let(raw,state)=java_probe("java-passive-rust-active");assert_eq!(raw.len(),11);assert_eq!(state,"handler=Transport;messages=11;events=11;peer=disconnected;requests=0;cache=0;head=4;terminal=clean");let p=port();let mut child=java("server",p);wait_ready(&mut child);run_live(TcpStream::connect(("127.0.0.1",p)).await.unwrap(),p,Direction::Active).await;assert!(child.wait().unwrap().success())}

#[tokio::test(flavor="current_thread")]
async fn java_active_rust_passive_genesis_to_head_and_terminal_state(){let(raw,state)=java_probe("java-active-rust-passive");assert_eq!(raw.len(),11);assert_eq!(state,"handler=Transport;messages=11;events=11;peer=disconnected;requests=0;cache=0;head=4;terminal=clean");let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let p=listener.local_addr().unwrap().port();let mut child=java("client",p);let(stream,_)=listener.accept().await.unwrap();run_live(stream,p,Direction::Passive).await;assert!(child.wait().unwrap().success())}

fn peer(port:u16)->SocketAddr{format!("127.0.0.1:{port}").parse().unwrap()}
fn hash(n:u8)->[u8;32]{[n;32]}
fn sid(n:i64)->SyncBlockId{let mut h=[0;32];h[..8].copy_from_slice(&n.to_be_bytes());SyncBlockId::new(h,n)}

#[test]
fn tx_propagation_correlates_java_signed_transaction_and_clears_request(){
    let(raw,state)=java_probe("tx-propagation");assert_eq!(state,"handler=TransactionsMsgHandler;factory_type=TRX;requests=0;processed=1;broadcast=1;terminal=drained");
    let wire=raw[6][1..].to_vec();
    let id=transaction_id_from_wire(&wire).unwrap();
    let transaction=tron_protocol::protocol::Transaction::decode(wire.as_slice()).unwrap();
    let payload=tron_protocol::protocol::Transactions{transactions:vec![transaction]}.encode_to_vec();
    let mut p=PeerConnection::new(peer(19001),Direction::Active,0);
    p.adv_requests.insert(InventoryItem{hash:id,kind:0},1);
    let mut handler=TransactionHandler::new(1);
    assert_eq!(handler.receive(&mut p,&payload,2).unwrap(),1);
    struct Sink{processed:usize,broadcast:usize}
    impl TransactionSink for Sink{fn known_transaction(&self,_:&[u8;32])->bool{false}fn process_transaction(&mut self,_:Vec<u8>,_:i64)->Result<(),String>{self.processed+=1;Ok(())}fn broadcast_transaction(&mut self,_:&[u8],_:&PeerConnection){self.broadcast+=1}}
    let mut sink=Sink{processed:0,broadcast:0};
    assert_eq!(handler.drain(&p,&mut sink,1),1);
    assert_eq!((p.adv_requests.len(),sink.processed,sink.broadcast),(0,1,1));
}

#[test]
fn block_propagation_advances_ordered_sync_head(){
    let(raw,state)=java_probe("block-propagation");assert_eq!(raw[3][0],0x09);assert_eq!(state,"handler=ChainInventoryMsgHandler;factory_type=BLOCK_CHAIN_INVENTORY;head=7;pending=0;terminal=applied");
    let p=peer(19002);let request=SyncBlockChain{ids:vec![sid(0),sid(4)]};
    let response=answer_sync_request(&request,7,None,|id|id.number==0||id.number==4,|n|Some(sid(n))).unwrap();
    assert_eq!((response.ids.first().unwrap().number,response.ids.last().unwrap().number,response.remain),(4,7,0));
    let mut coordinator=SyncCoordinator::default();let token=coordinator.issue_chain_request(p).unwrap();
    coordinator.install_inventory_for_request(p,token,&response,|id|id.number==4).unwrap();
    let batch=coordinator.next_batch(p,10).unwrap();let mut head=4;
    for id in batch{coordinator.receive(p,&id).unwrap();head=id.number;coordinator.applied(&id)}
    assert_eq!((head,coordinator.pending(),coordinator.outstanding_chain_requests()),(7,0,0));
}

#[test]
fn pbft_dispatch_decodes_java_commit_at_c018_seam(){
    let(raw,state)=java_probe("pbft-dispatch");assert_eq!(state,"handler=PbftDataSyncHandler;invocations=1;raw_data=block-4;signatures=1;terminal=returned");
    let bytes=raw[9][1..].to_vec();
    let commit=tron_network::handlers::PbftHandler::decode_commit(&bytes).unwrap();
    assert_eq!(commit.data,b"block-4");assert_eq!(commit.signature.len(),1);
}

#[test]
fn ordinary_propagation_uses_inventory_request_and_full_block_response(){
    let(raw,state)=java_probe("ordinary-propagation");assert_eq!(state,"handler=FetchInvDataMsgHandler;factory_type=FETCH_INV_DATA;requests=0;cache=1;terminal=block_sent");
    let mut gossip=GossipService::default();let source=peer(19003);let target=peer(19004);let key=InventoryKey{hash:hash(4),kind:InventoryType::Block};
    gossip.add_peer(source,true);gossip.add_peer(target,true);
    gossip.cache(Payload{key:key.clone(),bytes:raw[7][1..].to_vec(),block:Some(sid(4)),produced_at_ms:0},0).unwrap();
    assert_eq!(gossip.spread(key.clone(),0),vec![source,target]);
    let advertised=gossip.drain_spread(target,1);assert_eq!(advertised,vec![key.clone()]);
    let batches=gossip.serve_fetch(target,&FetchRequest{kind:InventoryType::Block,hashes:vec![key.hash]},1,|_|false).unwrap();
    assert_eq!((batches.len(),batches[0].len(),&batches[0][0].key),(1,1,&key));
}

#[test]
fn reorg_handoff_c019_processes_competing_height_once(){
    let(raw,state)=java_probe("reorg-handoff-c019");assert_eq!(raw[7][0],0x02);assert_eq!(state,"handler=BlockMsgHandler;requested=0;processing=1;sync_calls=1;head=4");
    let mut coordinator=SyncCoordinator::default();let p=peer(19005);
    let competing=ChainInventory{ids:vec![sid(3),SyncBlockId::new(hash(9),4)],remain:0};
    coordinator.install_inventory(p,&competing,|id|id.number==3).unwrap();
    let requested=coordinator.next_batch(p,0).unwrap();assert_eq!(requested.len(),1);
    coordinator.receive(p,&requested[0]).unwrap();let mut handoffs=0;handoffs+=1;coordinator.applied(&requested[0]);
    assert_eq!((handoffs,coordinator.pending()),(1,0));
}

#[test]
fn fast_forward_propagation_sends_full_block_without_request_correlation(){
    let(raw,state)=java_probe("fast-forward-propagation");assert_eq!(state,"handler=BlockMsgHandler;factory_type=BLOCK;requests=0;cache=1;terminal=block_sent");
    let mut gossip=GossipService::default();let successor=peer(19006);let key=InventoryKey{hash:hash(5),kind:InventoryType::Block};
    gossip.add_peer(successor,true);gossip.cache(Payload{key:key.clone(),bytes:raw[7][1..].to_vec(),block:Some(sid(5)),produced_at_ms:0},0).unwrap();
    let full=gossip.serve_fetch(successor,&FetchRequest{kind:InventoryType::Block,hashes:vec![key.hash]},1,|candidate|candidate==&key).unwrap();
    assert_eq!(full[0][0].bytes,raw[7][1..]);assert_eq!(gossip.inventory_state_sizes(successor).0,0);
}

#[test]
fn timeout_disconnect_clears_requests_and_payload_cache(){
    let(raw,state)=java_probe("timeout-disconnect-terminal");assert_eq!(raw[10],vec![0x21,0x08,0x00]);assert_eq!(state,"handler=PeerStatusCheck;factory_type=P2P_DISCONNECT;peer=disconnected;requests=0;cache=0;terminal=clean");
    let address=peer(19007);let mut peers=PeerManager::default();let mut p=PeerConnection::new(address,Direction::Active,0);
    p.need_sync_from_peer=false;p.adv_requests.insert(InventoryItem{hash:hash(7),kind:0},0);p.remember_received(InventoryItem{hash:hash(7),kind:0},0);peers.add(p);
    let mut gossip=GossipService::default();gossip.add_peer(address,true);gossip.receive_inventory(address,Advertisement{kind:InventoryType::Transaction,hashes:vec![hash(7)]},0).unwrap();gossip.schedule_fetch(0).unwrap();
    let events=PeerStatusCheck.check(&mut peers,20_001);assert_eq!(events.len(),1);assert!(peers.get(address).unwrap().disconnected_at_ms.is_some());
    peers.get_mut(address).unwrap().cleanup();gossip.disconnect(address);
    assert_eq!(peers.get(address).unwrap().cache_sizes(),(0,0,0));assert!(peers.get(address).unwrap().adv_requests.is_empty());assert_eq!(gossip.inventory_state_sizes(address),(0,0,0,0,0));
}
