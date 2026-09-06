use std::{collections::{HashMap, HashSet, VecDeque}, hash::{Hash, Hasher}, net::SocketAddr, time::Duration};
use tron_protocol::protocol::hello_message::BlockId;
use crate::{app_hello::AppHello, connection::Direction, stats::MessageCount};

pub const INVENTORY_CACHE_LIMIT: usize = 20_000;
pub const SYNC_ID_CACHE_LIMIT: usize = 4_000;
pub const BAD_PEER_BAN: Duration = Duration::from_secs(3_600);
pub const DISCONNECTED_CLEANUP_DELAY_MS: i64 = 60_000;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InventoryItem { pub hash: [u8; 32], pub kind: i32 }
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockKey { pub hash: Vec<u8>, pub number: i64 }
impl From<&BlockId> for BlockKey { fn from(v: &BlockId) -> Self { Self { hash:v.hash.clone(), number:v.number } } }

#[derive(Clone, Debug)]
struct TimedCache<K> { entries: HashMap<K, (i64, u64)>, order: VecDeque<(K, u64)>, limit: usize, ttl_ms: Option<i64>, generation: u64 }
impl<K: Clone + Eq + std::hash::Hash> TimedCache<K> {
    fn new(limit: usize, ttl_ms: Option<i64>) -> Self { Self { entries:HashMap::new(),order:VecDeque::new(),limit,ttl_ms,generation:0 } }
    fn discard_stale_front(&mut self) { while self.order.front().is_some_and(|(k,g)| self.entries.get(k).is_none_or(|(_,current)| current!=g)) { self.order.pop_front(); } }
    fn purge(&mut self, now:i64) { if let Some(ttl)=self.ttl_ms { loop { self.discard_stale_front(); let expired=self.order.front().and_then(|(k,g)|self.entries.get(k).filter(|(_,current)|current==g)).is_some_and(|(at,_)|now.saturating_sub(*at)>=ttl); if !expired { break } if let Some((k,g))=self.order.pop_front(){if self.entries.get(&k).is_some_and(|(_,current)|*current==g){self.entries.remove(&k);}} } } }
    fn insert(&mut self,k:K,at:i64){self.purge(at);self.generation=self.generation.wrapping_add(1);let generation=self.generation;self.entries.insert(k.clone(),(at,generation));self.order.push_back((k,generation));while self.entries.len()>self.limit{self.discard_stale_front();if let Some((old,g))=self.order.pop_front(){if self.entries.get(&old).is_some_and(|(_,current)|*current==g){self.entries.remove(&old);}}else{break}}}
    fn clear(&mut self){self.entries.clear();self.order.clear()}
    fn len(&self)->usize{self.entries.len()}
    fn contains(&mut self,k:&K,now:i64)->bool{self.purge(now);self.entries.contains_key(k)}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum TronState { Init, Syncing, SyncCompleted }

#[derive(Clone, Debug)]
pub struct RateWindow { limit: u32, count: MessageCount }
impl RateWindow { pub fn new(limit:u32,now_sec:i64)->Self{Self{limit,count:MessageCount::new(now_sec)}} pub fn allow(&mut self,amount:u32,now_sec:i64)->bool{if self.count.count(1,now_sec).saturating_add(amount)>self.limit{return false}self.count.add(amount,now_sec);true} }

#[derive(Clone, Debug)]
pub struct PeerConnection {
    pub address: SocketAddr, pub direction: Direction, pub trusted: bool, pub latency_ms: u64, pub fetch_latency_p75_ms: f64, pub disconnected_at_ms: Option<i64>,
    pub disconnect_reason: Option<tron_protocol::protocol::ReasonCode>,
    pub relay_peer: bool, pub fetch_able: bool, pub bad_peer: bool, pub tron_state: TronState,
    pub last_interactive_ms: i64, pub block_received_ms: i64, pub block_both_have_update_ms: i64,
    pub connected_at_ms: i64, pub hello_received: Option<AppHello>, pub hello_sent: Option<AppHello>,
    adv_receive: TimedCache<InventoryItem>, adv_spread: TimedCache<InventoryItem>, pub adv_requests: HashMap<InventoryItem,i64>,
    sync_ids: TimedCache<Vec<u8>>, pub sync_to_fetch: VecDeque<BlockKey>, pub sync_requested: HashMap<BlockKey,i64>,
    pub sync_chain_requested: Option<(VecDeque<BlockKey>,i64)>, pub sync_in_process: HashSet<BlockKey>,
    pub need_sync_from_peer: bool, pub need_sync_from_us: bool, pub remain_num:i64, pub rates:HashMap<u8,RateWindow>,
}
impl PeerConnection {
    pub fn new(address:SocketAddr,direction:Direction,now_ms:i64)->Self{Self{address,direction,trusted:false,latency_ms:0,fetch_latency_p75_ms:0.0,disconnected_at_ms:None,disconnect_reason:None,relay_peer:false,fetch_able:false,bad_peer:false,tron_state:TronState::Init,last_interactive_ms:now_ms,block_received_ms:0,block_both_have_update_ms:now_ms,connected_at_ms:now_ms,hello_received:None,hello_sent:None,adv_receive:TimedCache::new(INVENTORY_CACHE_LIMIT,Some(3_600_000)),adv_spread:TimedCache::new(INVENTORY_CACHE_LIMIT,Some(3_600_000)),adv_requests:HashMap::new(),sync_ids:TimedCache::new(SYNC_ID_CACHE_LIMIT,None),sync_to_fetch:VecDeque::new(),sync_requested:HashMap::new(),sync_chain_requested:None,sync_in_process:HashSet::new(),need_sync_from_peer:true,need_sync_from_us:true,remain_num:0,rates:HashMap::new()}}
    pub fn is_sync_idle(&self)->bool{self.sync_requested.is_empty()&&self.sync_chain_requested.is_none()}
    pub fn is_idle(&self)->bool{self.adv_requests.is_empty()&&self.is_sync_idle()}
    pub fn is_sync_finished(&self)->bool{!(self.need_sync_from_peer||self.need_sync_from_us)}
    pub fn on_connected_heads(&mut self,local:i64,remote:i64){if remote>local{self.need_sync_from_us=false;self.tron_state=TronState::Syncing}else{self.need_sync_from_peer=false;if remote==local{self.need_sync_from_us=false}self.tron_state=TronState::SyncCompleted}}
    pub fn check_and_put_request(&mut self,item:InventoryItem,at:i64)->bool{if self.adv_requests.contains_key(&item){false}else{self.adv_requests.insert(item,at);true}}
    pub fn remember_received(&mut self,item:InventoryItem,at:i64){self.adv_receive.insert(item,at)}
    pub fn remember_spread(&mut self,item:InventoryItem,at:i64){self.adv_spread.insert(item,at)}
    pub fn received_contains(&mut self,item:&InventoryItem,now:i64)->bool{self.adv_receive.contains(item,now)}
    pub fn spread_contains(&mut self,item:&InventoryItem,now:i64)->bool{self.adv_spread.contains(item,now)}
    pub fn cache_sizes(&self)->(usize,usize,usize){(self.adv_receive.len(),self.adv_spread.len(),self.sync_ids.len())}
    pub fn cleanup(&mut self){self.adv_receive.clear();self.adv_spread.clear();self.adv_requests.clear();self.sync_ids.clear();self.sync_to_fetch.clear();self.sync_requested.clear();self.sync_in_process.clear();self.sync_chain_requested=None}
    pub fn ban_duration(reason:tron_protocol::protocol::ReasonCode)->Option<Duration>{matches!(reason,tron_protocol::protocol::ReasonCode::BadProtocol|tron_protocol::protocol::ReasonCode::BadBlock|tron_protocol::protocol::ReasonCode::BadTx).then_some(BAD_PEER_BAN)}
    pub fn disconnect(&mut self,reason:tron_protocol::protocol::ReasonCode,now_ms:i64){self.disconnect_reason=Some(reason);self.disconnected_at_ms=Some(now_ms)}
}
impl PartialEq for PeerConnection { fn eq(&self, other:&Self)->bool{self.address==other.address} }
impl Eq for PeerConnection {}
impl Hash for PeerConnection { fn hash<H:Hasher>(&self,state:&mut H){self.address.hash(state)} }

#[derive(Clone, Debug, Default)] pub struct PeerManager{peers:Vec<PeerConnection>}
impl PeerManager {
    pub fn add(&mut self,peer:PeerConnection)->bool{if self.peers.iter().any(|p|p.address==peer.address){false}else{self.peers.push(peer);true}}
    pub fn remove(&mut self,address:SocketAddr)->Option<PeerConnection>{self.peers.iter().position(|p|p.address==address).map(|i|self.peers.remove(i))}
    pub fn connected(&self)->impl Iterator<Item=&PeerConnection>{self.peers.iter().filter(|p|p.disconnected_at_ms.is_none())}
    pub fn connected_mut(&mut self)->impl Iterator<Item=&mut PeerConnection>{self.peers.iter_mut().filter(|p|p.disconnected_at_ms.is_none())}
    pub fn peers(&self)->&[PeerConnection]{&self.peers}
    pub fn peers_mut(&mut self)->&mut [PeerConnection]{&mut self.peers}
    pub fn get(&self,address:SocketAddr)->Option<&PeerConnection>{self.peers.iter().find(|p|p.address==address)}
    pub fn get_mut(&mut self,address:SocketAddr)->Option<&mut PeerConnection>{self.peers.iter_mut().find(|p|p.address==address)}
    pub fn sort_by_latency(&mut self){self.peers.sort_by_key(|p|p.latency_ms)}
    pub fn counts(&self)->(usize,usize){let active=self.connected().filter(|p|p.direction==Direction::Active).count();let passive=self.connected().filter(|p|p.direction==Direction::Passive).count();(active,passive)}
    pub fn cleanup_disconnected(&mut self,now_ms:i64)->usize{let before=self.peers.len();self.peers.retain(|p|p.disconnected_at_ms.is_none_or(|at|now_ms.saturating_sub(at)<=DISCONNECTED_CLEANUP_DELAY_MS));before-self.peers.len()}
}
