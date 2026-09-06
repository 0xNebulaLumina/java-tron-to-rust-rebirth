use prost::{Enumeration, Message};
use std::{collections::{HashMap, HashSet}, net::{IpAddr, Ipv4Addr, Ipv6Addr}, str::FromStr, time::{Duration, Instant}};

#[derive(Clone, PartialEq, Message)] pub struct Endpoint { #[prost(bytes="vec", tag="1")] pub address: Vec<u8>, #[prost(int32, tag="2")] pub port: i32, #[prost(bytes="vec", tag="3")] pub node_id: Vec<u8>, #[prost(bytes="vec", tag="4")] pub address_ipv6: Vec<u8> }
#[derive(Clone, PartialEq, Message)] pub struct KeepAliveMessage { #[prost(int64, tag="1")] pub timestamp: i64 }
#[derive(Clone, PartialEq, Message)] pub struct HelloMessage { #[prost(message, optional, tag="1")] pub from: Option<Endpoint>, #[prost(int32, tag="2")] pub network_id: i32, #[prost(int32, tag="3")] pub code: i32, #[prost(int64, tag="4")] pub timestamp: i64, #[prost(int32, tag="5")] pub version: i32 }
#[derive(Clone, PartialEq, Message)] pub struct StatusMessage { #[prost(message, optional, tag="1")] pub from: Option<Endpoint>, #[prost(int32, tag="2")] pub version: i32, #[prost(int32, tag="3")] pub network_id: i32, #[prost(int32, tag="4")] pub max_connections: i32, #[prost(int32, tag="5")] pub current_connections: i32, #[prost(int64, tag="6")] pub timestamp: i64 }
#[derive(Clone, PartialEq, Message)] pub struct P2pDisconnectMessage { #[prost(enumeration="DisconnectReason", tag="1")] pub reason: i32 }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)] #[repr(i32)] pub enum DisconnectReason { PeerQuiting=0, BadProtocol=1, TooManyPeers=2, DuplicatePeer=3, DifferentVersion=4, RandomElimination=5, EmptyMessage=6, PingTimeout=7, DiscoverMode=8, NoSuchMessage=10, BadMessage=11, TooManyPeersWithSameIp=12, RecentDisconnect=13, DupHandshake=14, Unknown=255 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum Control { KeepAlivePing, KeepAlivePong, HandshakeHello, Status, Disconnect }
impl Control { pub fn byte(self)->u8 { match self { Self::KeepAlivePing=>0xff,Self::KeepAlivePong=>0xfe,Self::HandshakeHello=>0xfd,Self::Status=>0xfc,Self::Disconnect=>0xfb } } pub fn parse(byte:u8)->Option<Self>{Some(match byte {0xff=>Self::KeepAlivePing,0xfe=>Self::KeepAlivePong,0xfd=>Self::HandshakeHello,0xfc=>Self::Status,0xfb=>Self::Disconnect,_=>return None})} }

pub const NODE_ID_LEN: usize = 64;
pub const MAX_IPV4_TEXT_LEN: usize = 15;
pub const MAX_IPV6_TEXT_LEN: usize = 45;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
 #[error("invalid protobuf: {0}")] Protobuf(#[from] prost::DecodeError),
 #[error("invalid endpoint: {0}")] Endpoint(&'static str),
}

pub fn validate_endpoint(endpoint: &Endpoint) -> Result<IpAddr, HandshakeError> {
 if endpoint.node_id.len() != NODE_ID_LEN { return Err(HandshakeError::Endpoint("node id must be 64 bytes")); }
 if !(1..=65535).contains(&endpoint.port) { return Err(HandshakeError::Endpoint("port outside 1..=65535")); }
 let ipv4 = if endpoint.address.is_empty() {
  None
 } else {
  if endpoint.address.len() > MAX_IPV4_TEXT_LEN { return Err(HandshakeError::Endpoint("IPv4 address exceeds textual limit")); }
  let text = std::str::from_utf8(&endpoint.address).map_err(|_| HandshakeError::Endpoint("IPv4 address is not UTF-8"))?;
  Some(Ipv4Addr::from_str(text).map_err(|_| HandshakeError::Endpoint("invalid IPv4 address"))?)
 };
 let ipv6 = if endpoint.address_ipv6.is_empty() {
  None
 } else {
  if endpoint.address_ipv6.len() > MAX_IPV6_TEXT_LEN { return Err(HandshakeError::Endpoint("IPv6 address exceeds textual limit")); }
  let text = std::str::from_utf8(&endpoint.address_ipv6).map_err(|_| HandshakeError::Endpoint("IPv6 address is not UTF-8"))?;
  Some(Ipv6Addr::from_str(text).map_err(|_| HandshakeError::Endpoint("invalid IPv6 address"))?)
 };
 ipv4.map(IpAddr::V4).or_else(|| ipv6.map(IpAddr::V6)).ok_or(HandshakeError::Endpoint("endpoint has no address"))
}

pub fn decode_hello(bytes: &[u8]) -> Result<HelloMessage, HandshakeError> {
 let hello = HelloMessage::decode(bytes)?;
 validate_endpoint(hello.from.as_ref().ok_or(HandshakeError::Endpoint("hello has no endpoint"))?)?;
 Ok(hello)
}

pub fn decode_status(bytes: &[u8]) -> Result<StatusMessage, HandshakeError> {
 let status = StatusMessage::decode(bytes)?;
 validate_endpoint(status.from.as_ref().ok_or(HandshakeError::Endpoint("status has no endpoint"))?)?;
 Ok(status)
}

#[derive(Debug, Clone)] pub struct AdmissionConfig { pub network_id:i32, pub version:i32, pub max_connections:usize, pub max_same_ip:usize, pub trusted:HashSet<IpAddr>, pub ban_duration:Duration }
#[derive(Debug, Default)] pub struct Admission { peers:HashMap<Vec<u8>,IpAddr>, per_ip:HashMap<IpAddr,usize>, banned:HashMap<IpAddr,Instant> }
impl Admission { pub fn len(&self)->usize{self.peers.len()} pub fn retained_identity_bytes(&self)->usize{self.peers.keys().map(Vec::len).sum()} }
impl Admission {
 pub fn ban(&mut self, ip:IpAddr, until:Instant){self.banned.insert(ip,until);}
 pub fn remove(&mut self,node:&[u8]){if let Some(ip)=self.peers.remove(node){if let Some(n)=self.per_ip.get_mut(&ip){*n=n.saturating_sub(1);}}}
 pub fn admit(&mut self, hello:&HelloMessage, remote_ip:IpAddr, local_node_id:&[u8], cfg:&AdmissionConfig, now:Instant)->Result<(),DisconnectReason>{
  let ep=hello.from.as_ref().ok_or(DisconnectReason::BadProtocol)?;
  validate_endpoint(ep).map_err(|_|DisconnectReason::BadProtocol)?;
  if local_node_id.len()!=NODE_ID_LEN{return Err(DisconnectReason::BadProtocol)}
  if ep.node_id==local_node_id{return Err(DisconnectReason::DuplicatePeer)}
  if hello.network_id!=cfg.network_id{return Err(DisconnectReason::BadProtocol)}
  if hello.version!=cfg.version{return Err(DisconnectReason::DifferentVersion)}
  if self.banned.get(&remote_ip).is_some_and(|t|*t>now) && !cfg.trusted.contains(&remote_ip){return Err(DisconnectReason::RecentDisconnect)}
  if self.peers.contains_key(&ep.node_id){return Err(DisconnectReason::DuplicatePeer)}
  if self.peers.len()>=cfg.max_connections && !cfg.trusted.contains(&remote_ip){return Err(DisconnectReason::TooManyPeers)}
  if self.per_ip.get(&remote_ip).copied().unwrap_or(0)>=cfg.max_same_ip && !cfg.trusted.contains(&remote_ip){return Err(DisconnectReason::TooManyPeersWithSameIp)}
  self.peers.insert(ep.node_id.clone(),remote_ip);*self.per_ip.entry(remote_ip).or_default()+=1;Ok(())
 }
}
