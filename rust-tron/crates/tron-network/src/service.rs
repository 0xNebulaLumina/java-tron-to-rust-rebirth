use std::{collections::HashSet, net::{IpAddr, SocketAddr}};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct P2pConfig {
 pub seed_nodes:Vec<SocketAddr>, pub active_nodes:Vec<SocketAddr>, pub trust_nodes:HashSet<IpAddr>, pub fast_forward_nodes:Vec<SocketAddr>,
 pub max_connections:usize, pub min_connections:usize, pub min_active_connections:usize, pub max_connections_per_ip:usize,
 pub port:u16, pub network_id:i32, pub disconnection_policy_enabled:bool, pub node_detect_enabled:bool, pub discovery_enabled:bool,
 pub ip:Option<IpAddr>, pub ipv6:Option<std::net::Ipv6Addr>, pub ipv6_enabled:bool, pub dns_tree_urls:Vec<String>,
}
#[derive(Clone, Debug, Default)] pub struct NetworkParameters { pub persisted_nodes:Vec<SocketAddr>, pub external_ip:Option<IpAddr> }
impl P2pConfig {
 pub fn compose(mut self,parameters:&NetworkParameters)->Self{
  self.seed_nodes.extend(parameters.persisted_nodes.iter().copied());
  for a in &self.active_nodes{self.trust_nodes.insert(a.ip());}for a in &self.fast_forward_nodes{self.trust_nodes.insert(a.ip());}
  self.min_connections=self.min_connections.min(self.max_connections);self.min_active_connections=self.min_active_connections.min(self.min_connections);
  self.disconnection_policy_enabled=false;
  if self.ip.is_none()&&crate::watchdog::has_ipv4_stack(local_ip_candidates()){self.ip=parameters.external_ip}
  if let Some(v6)=self.ipv6{self.active_nodes.retain(|a|a.ip()!=IpAddr::V6(v6)||a.port()!=self.port)}
  if !self.ipv6_enabled{self.ipv6=None}self
 }
}
fn local_ip_candidates()->[IpAddr;1]{[IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Component { Transport, EventHandler, Adv, Sync, PeerStatus, Resilience, Transactions, FetchBlock, NodePersist, Stats, PeerManager, Relay, Effective }
pub const START_ORDER:[Component;13]=[Component::Transport,Component::EventHandler,Component::Adv,Component::Sync,Component::PeerStatus,Component::Resilience,Component::Transactions,Component::FetchBlock,Component::NodePersist,Component::Stats,Component::PeerManager,Component::Relay,Component::Effective];
pub const CLOSE_ORDER:[Component;12]=[Component::PeerManager,Component::Stats,Component::NodePersist,Component::Adv,Component::Sync,Component::Resilience,Component::PeerStatus,Component::Transactions,Component::FetchBlock,Component::Effective,Component::Transport,Component::Relay];

#[derive(Debug,thiserror::Error,PartialEq,Eq)] pub enum ServiceError { #[error("component {component:?}: {message}")] Component{component:Component,message:String}, #[error("shutdown errors: {0:?}")] Shutdown(Vec<(Component,String)>) }
pub trait Lifecycle:Send { fn start(&mut self,cancel:CancellationToken)->Result<(),String>; fn close(&mut self)->Result<(),String>; }
pub struct ComponentService { pub component:Component, pub lifecycle:Box<dyn Lifecycle> }
pub struct TronNetService { config:P2pConfig, cancel:CancellationToken, components:Vec<ComponentService>, started:HashSet<Component>, running:bool }
impl TronNetService {
 pub fn new(config:P2pConfig,parameters:&NetworkParameters,components:Vec<ComponentService>)->Self{Self{config:config.compose(parameters),cancel:CancellationToken::new(),components,started:HashSet::new(),running:false}}
 pub fn config(&self)->&P2pConfig{&self.config} pub fn cancellation(&self)->CancellationToken{self.cancel.clone()} pub fn is_running(&self)->bool{self.running}
 fn component_mut(&mut self,c:Component)->Option<&mut ComponentService>{self.components.iter_mut().find(|x|x.component==c)}
 pub fn start(&mut self)->Result<(),ServiceError>{if self.running{return Ok(())}self.cancel=CancellationToken::new();for c in START_ORDER{let token=self.cancel.child_token();let Some(s)=self.component_mut(c) else{continue};if let Err(message)=s.lifecycle.start(token){self.cancel.cancel();self.close_started();return Err(ServiceError::Component{component:c,message})}self.started.insert(c);}self.running=true;Ok(())}
 fn close_started(&mut self){for c in CLOSE_ORDER{if self.started.remove(&c){if let Some(s)=self.component_mut(c){let _=s.lifecycle.close();}}}}
 pub fn close(&mut self)->Result<(),ServiceError>{if !self.running&&self.started.is_empty(){return Ok(())}self.cancel.cancel();let mut errors=Vec::new();for c in CLOSE_ORDER{if self.started.remove(&c){if let Some(s)=self.component_mut(c){if let Err(e)=s.lifecycle.close(){errors.push((c,e))}}}}self.running=false;if errors.is_empty(){Ok(())}else{Err(ServiceError::Shutdown(errors))}}
}
impl Drop for TronNetService { fn drop(&mut self){let _=self.close();} }
