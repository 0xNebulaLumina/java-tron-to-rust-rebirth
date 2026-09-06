use std::{collections::{HashMap, HashSet}, net::{IpAddr, SocketAddr}, time::Duration};
use tron_protocol::protocol::ReasonCode;
use crate::{connection::Direction, peer::{InventoryItem, PeerManager}};

pub const PEER_STATUS_INITIAL_DELAY: Duration = Duration::from_secs(5);
pub const PEER_STATUS_INTERVAL: Duration = Duration::from_secs(2);
pub const COMMON_TIMEOUT_MS: i64 = 30_000;
pub const ADV_TIMEOUT_MS: i64 = 20_000;
pub const SYNC_TIMEOUT_MS: i64 = 5_000;
pub const EFFECTIVE_INITIAL_DELAY: Duration = Duration::from_secs(60);
pub const EFFECTIVE_RETRY_INTERVAL: Duration = Duration::from_secs(5);
pub const MAX_HANDSHAKE_MS: i64 = 60_000;
pub const EFFECTIVE_CACHE_MS: i64 = 20 * 60_000;
pub const BLOCK_NOT_CHANGE_MS: i64 = 60_000;
pub const RETENTION_PERCENT: f64 = 0.8;
pub const MIN_BROADCAST_PEERS: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disconnect { pub address: SocketAddr, pub reason: ReasonCode }

#[derive(Clone, Debug, Default)] pub struct PeerStatusCheck;
impl PeerStatusCheck {
    pub fn check(&self, peers:&mut PeerManager, now_ms:i64)->Vec<Disconnect>{
        let mut out=Vec::new();
        for peer in peers.connected_mut(){
            let timed_out=(peer.need_sync_from_peer && peer.block_both_have_update_ms < now_ms-COMMON_TIMEOUT_MS)
                || peer.adv_requests.values().any(|&at|at < now_ms-ADV_TIMEOUT_MS)
                || peer.sync_requested.values().any(|&at|at < now_ms-SYNC_TIMEOUT_MS);
            if timed_out { peer.disconnect(ReasonCode::TimeOut,now_ms); out.push(Disconnect{address:peer.address,reason:ReasonCode::TimeOut}); }
        }
        out
    }
}

#[derive(Clone, Debug)] pub struct CandidateNode { pub address:SocketAddr, pub updated_ms:i64 }
#[derive(Clone, Debug)] pub struct EffectiveCheck { enabled:bool, current:Option<SocketAddr>, attempts:u32, cache:HashMap<SocketAddr,i64> }
#[derive(Clone, Debug, PartialEq, Eq)] pub enum EffectiveAction { Connect(SocketAddr), Disconnect(Disconnect), None }
impl EffectiveCheck {
    pub fn new(enabled:bool)->Self{Self{enabled,current:None,attempts:0,cache:HashMap::new()}}
    pub fn enabled(&self)->bool{self.enabled}
    pub fn current(&self)->Option<SocketAddr>{self.current}
    pub fn attempts(&self)->u32{self.attempts}
    pub fn is_isolated(peers:&PeerManager)->bool{let mut n=0;let mut need=0;for p in peers.connected(){n+=1;if p.need_sync_from_us{need+=1}}need==n}
    pub fn check(&mut self,peers:&mut PeerManager,nodes:&[CandidateNode],active_nodes:&HashSet<SocketAddr>,now_ms:i64)->EffectiveAction{
        if !self.enabled{return EffectiveAction::None}
        self.cache.retain(|_,at|now_ms.saturating_sub(*at)<EFFECTIVE_CACHE_MS);
        if !Self::is_isolated(peers){self.current=None;self.attempts=0;return EffectiveAction::None}
        if let Some(cur)=self.current{
            if let Some(peer)=peers.get_mut(cur){if now_ms.saturating_sub(peer.connected_at_ms)>=MAX_HANDSHAKE_MS{peer.disconnect(ReasonCode::BelowThanMe,now_ms);return EffectiveAction::Disconnect(Disconnect{address:cur,reason:ReasonCode::BelowThanMe})}}
            return EffectiveAction::None
        }
        let used:HashSet<_>=peers.connected().map(|p|p.address).collect();
        let chosen=nodes.iter().filter(|n|!self.cache.contains_key(&n.address)&&!used.contains(&n.address)&&!active_nodes.contains(&n.address)).max_by_key(|n|n.updated_ms);
        if let Some(node)=chosen{self.attempts=self.attempts.saturating_add(1);self.cache.insert(node.address,now_ms);self.current=Some(node.address);EffectiveAction::Connect(node.address)}else{EffectiveAction::None}
    }
    pub fn connection_failed(&mut self,address:SocketAddr){if self.current==Some(address){self.current=None}}
    pub fn on_disconnect(&mut self,address:SocketAddr){self.connection_failed(address)}
}

pub fn has_ipv4_stack(addrs:impl IntoIterator<Item=IpAddr>)->bool{addrs.into_iter().any(|a|a.is_ipv4())}

#[derive(Clone, Copy, Debug)] pub struct ResilienceConfig { pub max_connections:usize, pub min_connections:usize, pub min_active_connections:usize, pub inactive_threshold_ms:i64 }
#[derive(Clone, Debug)] pub struct DeterministicRng(u64);
impl DeterministicRng { pub fn new(seed:u64)->Self{Self(seed)} pub fn bounded(&mut self,bound:u64)->u64{assert!(bound>0);self.0=self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);((u128::from(self.0)*u128::from(bound))>>64) as u64} }
#[derive(Clone, Debug)] pub struct Resilience { pub config:ResilienceConfig, rng:DeterministicRng }
impl Resilience {
 pub fn new(config:ResilienceConfig,seed:u64)->Self{Self{config,rng:DeterministicRng::new(seed)}}
 fn disconnect(peers:&mut PeerManager,address:SocketAddr,reason:ReasonCode,now:i64)->Disconnect{peers.get_mut(address).expect("selected peer").disconnect(reason,now);Disconnect{address,reason}}
 pub fn disconnect_random(&mut self,peers:&mut PeerManager,now:i64)->Option<Disconnect>{
  if peers.connected().count()<self.config.max_connections{return None}
  let mut broadcast:Vec<_>=peers.connected().filter(|p|!p.trusted&&p.is_sync_finished()).map(|p|(p.address,p.block_received_ms,p.last_interactive_ms)).collect();
  if broadcast.len()>=MIN_BROADCAST_PEERS{broadcast.sort_by_key(|p|p.1);broadcast.truncate(broadcast.len()/2);let weights:Vec<_>=broadcast.iter().map(|p|((now-p.2) as f64/500.0).ceil().max(1.0) as u64).collect();let mut n=self.rng.bounded(weights.iter().sum());let mut ix=0;for (i,w) in weights.iter().enumerate(){if n<*w{ix=i;break}n-=*w}return Some(Self::disconnect(peers,broadcast[ix].0,ReasonCode::RandomElimination,now))}
  let need_count=peers.connected().filter(|p|!p.trusted&&p.need_sync_from_peer).count();let candidates:Vec<_>=peers.connected().filter(|p|!p.trusted&&if need_count>=2{p.need_sync_from_us||p.need_sync_from_peer}else{p.need_sync_from_us}).map(|p|p.address).collect();if candidates.is_empty(){None}else{let ix=self.rng.bounded(candidates.len() as u64) as usize;Some(Self::disconnect(peers,candidates[ix],ReasonCode::RandomElimination,now))}
 }
 pub fn is_lan(peers:&PeerManager,min_active:usize)->bool{let all=peers.connected().count();let active=peers.connected().filter(|p|p.direction==Direction::Active).count();all>=min_active&&all==active}
 pub fn disconnect_lan(&mut self,peers:&mut PeerManager,now:i64)->Option<Disconnect>{if !Self::is_lan(peers,self.config.min_active_connections)||peers.connected().count()<self.config.min_connections{return None}let one=peers.connected().filter(|p|!p.trusted&&p.is_sync_finished()&&now-p.last_interactive_ms>=self.config.inactive_threshold_ms).min_by_key(|p|p.last_interactive_ms).map(|p|p.address)?;Some(Self::disconnect(peers,one,ReasonCode::BadProtocol,now))}
 pub fn is_isolated(peers:&PeerManager,latest_save_ms:i64,now:i64)->bool{peers.connected().any(|p|p.is_sync_finished())&&now-latest_save_ms>=BLOCK_NOT_CHANGE_MS}
 pub fn disconnect_isolated(&mut self,peers:&mut PeerManager,latest_save_ms:i64,now:i64)->Vec<Disconnect>{let mut out=Vec::new();if !Self::is_isolated(peers,latest_save_ms,now){return out}let active_count=peers.connected().filter(|p|p.direction==Direction::Active).count();if active_count>=self.config.min_active_connections{if let Some(a)=peers.connected().filter(|p|!p.trusted&&p.direction==Direction::Active).min_by_key(|p|p.last_interactive_ms).map(|p|p.address){out.push(Self::disconnect(peers,a,ReasonCode::BadProtocol,now))}}let threshold=(self.config.max_connections as f64*RETENTION_PERCENT) as usize;let excess=peers.connected().count().saturating_sub(threshold);let mut passive:Vec<_>=peers.connected().filter(|p|!p.trusted&&p.direction==Direction::Passive).map(|p|(p.address,p.last_interactive_ms)).collect();passive.sort_by_key(|p|p.1);for (a,_) in passive.into_iter().take(excess){out.push(Self::disconnect(peers,a,ReasonCode::BadProtocol,now))}out}
}

#[derive(Clone, Debug)] struct FetchBlockInfo { hash:[u8;32], peer:SocketAddr, at_ms:i64 }
#[derive(Clone, Debug, PartialEq, Eq)] pub enum FetchAction { Request{peer:SocketAddr,item:InventoryItem}, Cleared, None }
#[derive(Clone, Debug)] pub struct FetchBlockService { timeout_ms:i64, current:Option<FetchBlockInfo> }
impl FetchBlockService {
    pub fn new(timeout_ms:i64)->Self{Self{timeout_ms,current:None}}
    pub fn fetch_block(&mut self,hashes:&[[u8;32]],peer:SocketAddr,head:i64,now:i64){if self.current.is_some(){return}if let Some(hash)=hashes.iter().find(|h|i64::from_be_bytes(h[..8].try_into().unwrap())==head+1){self.current=Some(FetchBlockInfo{hash:*hash,peer,at_ms:now})}}
    pub fn success(&mut self,hash:[u8;32]){if self.current.as_ref().is_some_and(|i|i.hash==hash){self.current=None}}
    pub fn process(&mut self,peers:&mut PeerManager,now:i64)->FetchAction{
        let Some(info)=self.current.clone() else{return FetchAction::None};
        let item=InventoryItem{hash:info.hash,kind:2};
        let old_p75=peers.get(info.peer).map_or(f64::INFINITY,|p|p.fetch_latency_p75_ms);
        let spent=now-info.at_ms;
        let mut candidates=Vec::new();
        for peer in peers.connected_mut(){if peer.address!=info.peer&&peer.is_idle()&&peer.received_contains(&item,now)&&peer.fetch_latency_p75_ms<=self.timeout_ms as f64{candidates.push((peer.address,peer.fetch_latency_p75_ms));}}
        candidates.sort_by(|a,b|a.1.total_cmp(&b.1));
        if let Some((address,new_p75))=candidates.first().copied(){if (old_p75>self.timeout_ms as f64||spent>=self.timeout_ms||(new_p75<(old_p75-spent as f64)*0.5&&spent as f64+new_p75<self.timeout_ms as f64))&&peers.get_mut(address).unwrap().check_and_put_request(item.clone(),now){self.current=None;return FetchAction::Request{peer:address,item}}}
        if spent>=self.timeout_ms{self.current=None;FetchAction::Cleared}else{FetchAction::None}
    }
}
