use std::{collections::HashMap, net::{IpAddr,SocketAddr}, time::{Duration,Instant}};
#[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum Direction{Active,Passive}
#[derive(Clone,Debug)] pub struct Peer { pub node_id:Vec<u8>, pub address:SocketAddr, pub direction:Direction, pub trusted:bool, pub connected_at:Instant, pub last_seen:Instant }
#[derive(Clone,Debug)] pub struct PoolConfig { pub min_connections:usize,pub max_connections:usize,pub min_active:usize,pub max_same_ip:usize,pub initial_backoff:Duration,pub max_backoff:Duration }
#[derive(Debug,Default)] pub struct ConnectionPool { peers:HashMap<Vec<u8>,Peer>, failures:HashMap<SocketAddr,(u32,Instant)> }
impl ConnectionPool {
 pub fn len(&self)->usize{self.peers.len()} pub fn active_len(&self)->usize{self.peers.values().filter(|p|p.direction==Direction::Active).count()} pub fn needs_connections(&self,cfg:&PoolConfig)->bool{self.len()<cfg.min_connections||self.active_len()<cfg.min_active}
 pub fn insert(&mut self,peer:Peer,cfg:&PoolConfig)->Result<(),PoolError>{if peer.node_id.len()!=crate::handshake::NODE_ID_LEN{return Err(PoolError::InvalidIdentity)};if self.peers.contains_key(&peer.node_id){return Err(PoolError::Duplicate)};if self.len()>=cfg.max_connections&&!peer.trusted{return Err(PoolError::Full)};if self.peers.values().filter(|p|p.address.ip()==peer.address.ip()).count()>=cfg.max_same_ip&&!peer.trusted{return Err(PoolError::SameIp)};self.failures.remove(&peer.address);self.peers.insert(peer.node_id.clone(),peer);Ok(())}
 pub fn remove(&mut self,id:&[u8])->Option<Peer>{self.peers.remove(id)}
 pub fn record_failure(&mut self,address:SocketAddr,cfg:&PoolConfig,now:Instant){let n=self.failures.get(&address).map_or(1,|(n,_)|n.saturating_add(1));let shift=n.saturating_sub(1).min(31);let delay=cfg.initial_backoff.saturating_mul(1u32<<shift).min(cfg.max_backoff);self.failures.insert(address,(n,now+delay));}
 pub fn may_connect(&self,address:SocketAddr,now:Instant)->bool{self.failures.get(&address).is_none_or(|(_,until)|*until<=now)}
 pub fn stale(&self,now:Instant,timeout:Duration)->Vec<Vec<u8>>{self.peers.iter().filter(|(_,p)|now.saturating_duration_since(p.last_seen)>=timeout).map(|(id,_)|id.clone()).collect()}
 pub fn ip_count(&self,ip:IpAddr)->usize{self.peers.values().filter(|p|p.address.ip()==ip).count()}
}
#[derive(Debug,thiserror::Error,PartialEq,Eq)] pub enum PoolError{#[error("node id must be exactly 64 bytes")]InvalidIdentity,#[error("duplicate peer")]Duplicate,#[error("connection pool full")]Full,#[error("too many peers with same IP")]SameIp}
