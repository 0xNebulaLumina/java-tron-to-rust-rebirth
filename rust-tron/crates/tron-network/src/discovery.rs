//! libp2p 2.2.9 compatible legacy discovery datagrams and Kademlia table.
use prost::Message;
use std::{cmp::Ordering, collections::{HashMap, VecDeque}, io, net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket}, sync::{Arc, Mutex}, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::{net::UdpSocket, sync::{mpsc, watch}, task::JoinHandle};

pub const MIN_DATAGRAM_LEN: usize = 2;
pub const MAX_DATAGRAM_LEN: usize = 2047;
pub const KADEMLIA_BUCKETS: usize = 256;
pub const BUCKET_SIZE: usize = 16;
pub const MAX_AUTHENTICATED_PEERS: usize = 4096;

#[derive(Clone, PartialEq, Message)]
pub struct Endpoint { #[prost(bytes="vec", tag="1")] pub address: Vec<u8>, #[prost(int32, tag="2")] pub port: i32, #[prost(bytes="vec", tag="3")] pub node_id: Vec<u8>, #[prost(bytes="vec", tag="4")] pub address_ipv6: Vec<u8> }
#[derive(Clone, PartialEq, Message)] pub struct Ping { #[prost(message, optional, tag="1")] pub from: Option<Endpoint>, #[prost(message, optional, tag="2")] pub to: Option<Endpoint>, #[prost(int32, tag="3")] pub version: i32, #[prost(int64, tag="4")] pub timestamp: i64 }
#[derive(Clone, PartialEq, Message)] pub struct Pong { #[prost(message, optional, tag="1")] pub from: Option<Endpoint>, #[prost(int32, tag="2")] pub echo: i32, #[prost(int64, tag="3")] pub timestamp: i64 }
#[derive(Clone, PartialEq, Message)] pub struct FindNeighbours { #[prost(message, optional, tag="1")] pub from: Option<Endpoint>, #[prost(bytes="vec", tag="2")] pub target_id: Vec<u8>, #[prost(int64, tag="3")] pub timestamp: i64 }
#[derive(Clone, PartialEq, Message)] pub struct Neighbours { #[prost(message, optional, tag="1")] pub from: Option<Endpoint>, #[prost(message, repeated, tag="2")] pub neighbours: Vec<Endpoint>, #[prost(int64, tag="3")] pub timestamp: i64 }
#[derive(Clone, PartialEq, Message)] pub struct EndPoints { #[prost(message, repeated, tag="1")] pub nodes: Vec<Endpoint> }
#[derive(Clone, PartialEq, Message)] pub struct DnsTreeRoot { #[prost(bytes="vec", tag="1")] pub e_root:Vec<u8>, #[prost(bytes="vec", tag="2")] pub l_root:Vec<u8>, #[prost(int32, tag="3")] pub seq:i32 }
#[derive(Clone, PartialEq, Message)] pub struct DnsRoot { #[prost(message, optional, tag="1")] pub tree_root:Option<DnsTreeRoot>, #[prost(bytes="vec", tag="2")] pub signature:Vec<u8> }

#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[repr(u8)] pub enum MessageType { Ping=1, Pong=2, FindNeighbours=3, Neighbours=4 }
impl TryFrom<u8> for MessageType { type Error=DiscoveryError; fn try_from(v:u8)->Result<Self,Self::Error>{ match v {1=>Ok(Self::Ping),2=>Ok(Self::Pong),3=>Ok(Self::FindNeighbours),4=>Ok(Self::Neighbours),_=>Err(DiscoveryError::UnknownType(v))} } }
#[derive(Debug, Clone, PartialEq)] pub enum DiscoverMessage { Ping(Ping), Pong(Pong), FindNeighbours(FindNeighbours), Neighbours(Neighbours) }
impl DiscoverMessage { pub fn message_type(&self)->MessageType { match self {Self::Ping(_)=>MessageType::Ping,Self::Pong(_)=>MessageType::Pong,Self::FindNeighbours(_)=>MessageType::FindNeighbours,Self::Neighbours(_)=>MessageType::Neighbours} } pub fn encode_datagram(&self)->Result<Vec<u8>,DiscoveryError>{let mut out=vec![self.message_type() as u8]; match self {Self::Ping(v)=>v.encode(&mut out),Self::Pong(v)=>v.encode(&mut out),Self::FindNeighbours(v)=>v.encode(&mut out),Self::Neighbours(v)=>v.encode(&mut out)}?; if !(MIN_DATAGRAM_LEN..=MAX_DATAGRAM_LEN).contains(&out.len()){return Err(DiscoveryError::Length(out.len()));} Ok(out)} }
pub fn decode_datagram(data:&[u8])->Result<DiscoverMessage,DiscoveryError>{if !(MIN_DATAGRAM_LEN..=MAX_DATAGRAM_LEN).contains(&data.len()){return Err(DiscoveryError::Length(data.len()));} let ty=MessageType::try_from(data[0])?; let b=&data[1..]; Ok(match ty {MessageType::Ping=>DiscoverMessage::Ping(Ping::decode(b)?),MessageType::Pong=>DiscoverMessage::Pong(Pong::decode(b)?),MessageType::FindNeighbours=>DiscoverMessage::FindNeighbours(FindNeighbours::decode(b)?),MessageType::Neighbours=>DiscoverMessage::Neighbours(Neighbours::decode(b)?)})}

#[derive(Debug,thiserror::Error)] pub enum DiscoveryError { #[error("discovery datagram length {0} outside 2..=2047")] Length(usize), #[error("unknown discovery message type {0}")] UnknownType(u8), #[error("invalid protobuf: {0}")] Protobuf(#[from] prost::DecodeError), #[error("protobuf encoding failed: {0}")] Encode(#[from] prost::EncodeError), #[error("invalid endpoint: {0}")] Endpoint(&'static str), #[error("I/O: {0}")] Io(#[from] io::Error) }

pub fn validate_endpoint(ep: &Endpoint, captured: Option<SocketAddr>) -> Result<SocketAddr, DiscoveryError> {
    if ep.node_id.len() != 64 {
        return Err(DiscoveryError::Endpoint("node id must be 64 bytes"));
    }
    if !(1..=65535).contains(&ep.port) {
        return Err(DiscoveryError::Endpoint("port outside 1..=65535"));
    }

    let ipv4 = if ep.address.is_empty() {
        None
    } else {
        let text = std::str::from_utf8(&ep.address)
            .map_err(|_| DiscoveryError::Endpoint("address must be UTF-8 IPv4 text"))?;
        match text.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => Some(IpAddr::V4(ip)),
            _ => return Err(DiscoveryError::Endpoint("address must be IPv4 text")),
        }
    };
    let ipv6 = if ep.address_ipv6.is_empty() {
        None
    } else {
        let text = std::str::from_utf8(&ep.address_ipv6)
            .map_err(|_| DiscoveryError::Endpoint("address_ipv6 must be UTF-8 IPv6 text"))?;
        match text.parse::<IpAddr>() {
            Ok(IpAddr::V6(ip)) => Some(IpAddr::V6(ip)),
            _ => return Err(DiscoveryError::Endpoint("address_ipv6 must be IPv6 text")),
        }
    };
    let declared = ipv4.or(ipv6).ok_or(DiscoveryError::Endpoint("endpoint has no address"))?;
    if captured.is_some_and(|source| source.ip() != declared) {
        return Err(DiscoveryError::Endpoint("captured source does not match endpoint address"));
    }
    Ok(SocketAddr::new(declared, ep.port as u16))
}

#[derive(Debug,Clone,Copy,PartialEq,Eq)] pub enum NodeState { Discovered, Alive, Active, EvictionCandidate, Dead }
#[derive(Debug,Clone)] pub struct NodeRecord { pub endpoint:Endpoint, pub address:SocketAddr, pub state:NodeState, pub update_time:i64, pub last_seen:i64, pub failures:u8 }
#[derive(Debug)] pub struct KademliaTable { local_id:[u8;64], buckets:Vec<VecDeque<NodeRecord>>, replacements:Vec<VecDeque<NodeRecord>> }
impl KademliaTable { pub fn new(local_id:[u8;64])->Self{Self{local_id,buckets:(0..KADEMLIA_BUCKETS).map(|_|VecDeque::new()).collect(),replacements:(0..KADEMLIA_BUCKETS).map(|_|VecDeque::new()).collect()}} pub fn distance(a:&[u8],b:&[u8])->[u8;64]{let mut d=[0;64]; for (i,x) in d.iter_mut().enumerate(){*x=a.get(i).copied().unwrap_or(0)^b.get(i).copied().unwrap_or(0)}d} pub fn bucket_index(&self,id:&[u8])->Option<usize>{let d=Self::distance(&self.local_id,id); let leading=d.iter().take_while(|&&v|v==0).count(); if leading==64{return None;} Some((511-(leading*8+d[leading].leading_zeros() as usize))/2)} pub fn insert(&mut self,node:NodeRecord)->Option<NodeRecord>{let i=self.bucket_index(&node.endpoint.node_id)?; if let Some(pos)=self.buckets[i].iter().position(|n|n.endpoint.node_id==node.endpoint.node_id){self.buckets[i].remove(pos);self.buckets[i].push_back(node);return None;} if self.buckets[i].len()<BUCKET_SIZE{self.buckets[i].push_back(node);None}else{let candidate=self.buckets[i].front().cloned();self.replacements[i].push_back(node);while self.replacements[i].len()>BUCKET_SIZE{self.replacements[i].pop_front();}candidate}} pub fn mark_alive(&mut self,id:&[u8],now:i64){self.update(id,|n|{n.state=NodeState::Alive;n.last_seen=now;n.update_time=now;n.failures=0})} pub fn mark_failed(&mut self,id:&[u8],threshold:u8){self.update(id,|n|{n.failures=n.failures.saturating_add(1);n.state=if n.failures>=threshold{NodeState::Dead}else{NodeState::EvictionCandidate}}); self.evict_dead(id)} fn update(&mut self,id:&[u8],f:impl FnOnce(&mut NodeRecord)){if let Some(i)=self.bucket_index(id){if let Some(n)=self.buckets[i].iter_mut().find(|n|n.endpoint.node_id==id){f(n)}}} fn evict_dead(&mut self,id:&[u8]){let Some(i)=self.bucket_index(id) else{return}; if let Some(p)=self.buckets[i].iter().position(|n|n.endpoint.node_id==id&&n.state==NodeState::Dead){self.buckets[i].remove(p);if let Some(mut n)=self.replacements[i].pop_back(){n.state=NodeState::Discovered;self.buckets[i].push_back(n)}}} pub fn closest(&self,target:&[u8],limit:usize)->Vec<&NodeRecord>{let mut all:Vec<_>=self.buckets.iter().flat_map(|b|b.iter()).filter(|n|n.state!=NodeState::Dead).collect();all.sort_by(|a,b|Self::distance(&a.endpoint.node_id,target).cmp(&Self::distance(&b.endpoint.node_id,target)).then_with(||b.update_time.cmp(&a.update_time)));all.truncate(limit);all} pub fn nodes(&self)->impl Iterator<Item=&NodeRecord>{self.buckets.iter().flat_map(|b|b.iter())} }

#[derive(Debug, Clone)]
pub struct AuthenticatedDatagram {
    pub peer_id: Vec<u8>,
    pub peer_identity: IpAddr,
    pub session: u64,
    pub sequence: u64,
    pub source: SocketAddr,
    pub payload: Vec<u8>,
}

pub trait DatagramAuthenticator: Send + Sync + 'static {
    /// Opens an authenticated envelope received from the network.
    fn authenticate(&self, source: SocketAddr, packet: &[u8]) -> Option<AuthenticatedDatagram>;

    /// Seals `payload` for one configured peer. Implementations must bind every
    /// supplied field into the envelope authentication tag and reject unknown
    /// destination identities or endpoints. The default is deliberately
    /// non-producing: it never falls back to plaintext UDP.
    fn seal(
        &self,
        _destination_identity: IpAddr,
        _destination: SocketAddr,
        _local_identity: IpAddr,
        _source: SocketAddr,
        _session: u64,
        _sequence: u64,
        _payload: &[u8],
    ) -> Option<Vec<u8>> { None }
}

#[derive(Debug)]
struct SessionTracker { current: HashMap<Vec<u8>, (u64, u64)>, capacity: usize }

impl SessionTracker {
    fn new(capacity: usize) -> Self { Self { current: HashMap::new(), capacity: capacity.max(1) } }
    fn accept(&mut self, datagram: &AuthenticatedDatagram, received_from: SocketAddr) -> bool {
        if datagram.source != received_from || datagram.peer_identity != received_from.ip() || datagram.peer_id.len() != 64 { return false; }
        if !self.current.contains_key(&datagram.peer_id) {
            if self.current.len() >= self.capacity { return false; }
            self.current.insert(datagram.peer_id.clone(), (datagram.session, datagram.sequence));
            return true;
        }
        match self.current.get_mut(&datagram.peer_id).expect("session exists") {
            (session, sequence) if datagram.session > *session => { *session = datagram.session; *sequence = datagram.sequence; true }
            (session, sequence) if datagram.session == *session && datagram.sequence > *sequence => { *sequence = datagram.sequence; true }
            _ => false,
        }
    }
}

pub struct SecureReceiver { socket: Arc<UdpSocket>, auth: Arc<dyn DatagramAuthenticator>, sessions: SessionTracker }
impl SecureReceiver {
    pub fn new(socket: Arc<UdpSocket>, auth: Arc<dyn DatagramAuthenticator>) -> Self { Self::with_session_capacity(socket, auth, MAX_AUTHENTICATED_PEERS) }
    pub fn with_session_capacity(socket: Arc<UdpSocket>, auth: Arc<dyn DatagramAuthenticator>, capacity: usize) -> Self { Self { socket, auth, sessions: SessionTracker::new(capacity) } }
    pub async fn recv(&mut self) -> io::Result<AuthenticatedDatagram> {
        let mut buf = [0u8; 65535];
        loop {
            let (n, source) = self.socket.recv_from(&mut buf).await?;
            let Some(datagram) = self.auth.authenticate(source, &buf[..n]) else { continue };
            if self.sessions.accept(&datagram, source) { return Ok(datagram); }
        }
    }
}

pub struct SecureDatagramSocket {
    socket: StdUdpSocket,
    auth: Arc<dyn DatagramAuthenticator>,
    inbound_sessions: Mutex<SessionTracker>,
    outbound: Mutex<OutboundSessions>,
}

#[derive(Debug)]
struct OutboundSessions {
    session: u64,
    sequences: HashMap<SocketAddr, u64>,
    capacity: usize,
}

impl SecureDatagramSocket {
    pub fn new(socket: StdUdpSocket, auth: Arc<dyn DatagramAuthenticator>) -> Self {
        let session = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_nanos().min(u64::MAX as u128) as u64;
        Self::with_session_and_capacity(socket, auth, session.max(1), MAX_AUTHENTICATED_PEERS)
    }
    pub fn with_session_capacity(socket: StdUdpSocket, auth: Arc<dyn DatagramAuthenticator>, capacity: usize) -> Self {
        let session = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_nanos().min(u64::MAX as u128) as u64;
        Self::with_session_and_capacity(socket, auth, session.max(1), capacity)
    }
    pub fn with_session_and_capacity(socket: StdUdpSocket, auth: Arc<dyn DatagramAuthenticator>, session: u64, capacity: usize) -> Self {
        Self {
            socket,
            auth,
            inbound_sessions: Mutex::new(SessionTracker::new(capacity)),
            outbound: Mutex::new(OutboundSessions { session: session.max(1), sequences: HashMap::new(), capacity: capacity.max(1) }),
        }
    }
}

impl tron_consensus::backup::DatagramSocket for SecureDatagramSocket {
    fn send_to(&self, bytes: &[u8], address: SocketAddr) -> io::Result<usize> {
        let source = self.socket.local_addr()?;
        let mut outbound = self.outbound.lock().expect("secure outbound sessions poisoned");
        if !outbound.sequences.contains_key(&address) && outbound.sequences.len() >= outbound.capacity {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, "secure outbound peer capacity exhausted"));
        }
        let sequence = outbound.sequences.get(&address).copied().unwrap_or(0).checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "secure outbound sequence exhausted"))?;
        let envelope = self.auth.seal(address.ip(), address, source.ip(), source, outbound.session, sequence, bytes)
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "secure datagram destination is not authenticated"))?;
        self.socket.send_to(&envelope, address)?;
        outbound.sequences.insert(address, sequence);
        Ok(bytes.len())
    }
    fn recv_datagram(&self) -> io::Result<tron_consensus::backup::ReceivedDatagram> {
        let mut bytes = [0u8; 65535];
        loop {
            let (size, source) = self.socket.recv_from(&mut bytes)?;
            let Some(packet) = self.auth.authenticate(source, &bytes[..size]) else { continue };
            if !self.inbound_sessions.lock().expect("secure datagram sessions poisoned").accept(&packet, source) { continue; }
            return Ok(tron_consensus::backup::ReceivedDatagram::Authenticated(tron_consensus::backup::AuthenticatedDatagram {
                payload: packet.payload,
                source: packet.source,
                peer_identity: packet.peer_identity,
                session: packet.session,
                sequence: packet.sequence,
            }));
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> { self.socket.local_addr() }
}

pub struct SecureSocketFactory { auth: Arc<dyn DatagramAuthenticator> }
impl SecureSocketFactory { pub fn new(auth: Arc<dyn DatagramAuthenticator>) -> Self { Self { auth } } }
impl tron_consensus::backup::SocketFactory for SecureSocketFactory {
    fn bind(&self, address: SocketAddr) -> io::Result<Arc<dyn tron_consensus::backup::DatagramSocket>> {
        let socket = StdUdpSocket::bind(address)?;
        socket.set_nonblocking(true)?;
        Ok(Arc::new(SecureDatagramSocket::new(socket, self.auth.clone())))
    }
    fn supplies_authenticated_datagrams(&self) -> bool { true }
}

pub struct DiscoveryServer { stop:watch::Sender<bool>, task:JoinHandle<io::Result<()>> }
impl DiscoveryServer { pub async fn bind(address:SocketAddr,queue:usize)->io::Result<(Self,mpsc::Receiver<(SocketAddr,DiscoverMessage)>)>{let socket=UdpSocket::bind(address).await?;let(tx,rx)=mpsc::channel(queue.max(1));let(stop,mut stopped)=watch::channel(false);let task=tokio::spawn(async move{let mut buf=[0u8;MAX_DATAGRAM_LEN+1];loop{tokio::select!{r=socket.recv_from(&mut buf)=>{let(n,from)=r?;if let Ok(msg)=decode_datagram(&buf[..n]){if tx.send((from,msg)).await.is_err(){return Ok(())}}},_=stopped.changed()=>{return Ok(())}}}});Ok((Self{stop,task},rx))} pub async fn shutdown(self)->io::Result<()>{let _=self.stop.send(true);self.task.await.map_err(io::Error::other)?} }
pub fn now_millis()->i64{SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_millis().min(i64::MAX as u128) as i64}
pub fn compare_distance(target:&[u8],a:&[u8],b:&[u8])->Ordering{KademliaTable::distance(a,target).cmp(&KademliaTable::distance(b,target))}

#[derive(Debug,Clone,Copy,PartialEq,Eq)] pub enum CandidateSource { Active, Trusted, Dns, Persisted, Discovered }
#[derive(Debug,Clone)] pub struct Candidate { pub address:SocketAddr, pub node_id:Vec<u8>, pub source:CandidateSource, pub update_time:i64, pub latency:Option<Duration>, pub failures:u8 }
#[derive(Debug,Default)] pub struct ConnectionPool { candidates:HashMap<SocketAddr,Candidate>, connected:HashMap<SocketAddr,i64>, max_candidates:usize }
impl ConnectionPool { pub fn new(max_candidates:usize)->Self{Self{max_candidates:max_candidates.max(1),..Self::default()}} pub fn offer(&mut self,candidate:Candidate){match self.candidates.get(&candidate.address){Some(old) if rank(old)>=rank(&candidate)=>return,_=>{self.candidates.insert(candidate.address,candidate);}}while self.candidates.len()>self.max_candidates{if let Some(address)=self.ranked().last().map(|v|v.address){self.candidates.remove(&address);}}} pub fn connected(&mut self,address:SocketAddr,at:i64){self.connected.insert(address,at);self.candidates.remove(&address);} pub fn disconnected(&mut self,address:SocketAddr){self.connected.remove(&address);} pub fn ranked(&self)->Vec<&Candidate>{let mut values:Vec<_>=self.candidates.values().filter(|v|!self.connected.contains_key(&v.address)).collect();values.sort_by(|a,b|rank(b).cmp(&rank(a)).then_with(||a.address.cmp(&b.address)));values} pub fn len(&self)->usize{self.candidates.len()} pub fn is_empty(&self)->bool{self.candidates.is_empty()} }
fn rank(c:&Candidate)->(u8,u8,std::cmp::Reverse<u8>,i64,std::cmp::Reverse<Duration>){let source=match c.source{CandidateSource::Active=>5,CandidateSource::Trusted=>4,CandidateSource::Dns=>3,CandidateSource::Persisted=>2,CandidateSource::Discovered=>1};(source,u8::from(c.latency.is_some()),std::cmp::Reverse(c.failures),c.update_time,std::cmp::Reverse(c.latency.unwrap_or(Duration::MAX)))}
pub async fn status_probe(socket:&UdpSocket,peer:SocketAddr,ping:&Ping,timeout:Duration)->Result<Duration,DiscoveryError>{let packet=DiscoverMessage::Ping(ping.clone()).encode_datagram()?;let start=tokio::time::Instant::now();socket.send_to(&packet,peer).await?;let mut buf=[0u8;MAX_DATAGRAM_LEN+1];tokio::time::timeout(timeout,async{loop{let result=socket.recv_from(&mut buf).await?;if result.1==peer&&matches!(decode_datagram(&buf[..result.0]),Ok(DiscoverMessage::Pong(_))){return Ok(start.elapsed())}}}).await.map_err(|_|DiscoveryError::Io(io::Error::new(io::ErrorKind::TimedOut,"discovery probe timed out")))?}
