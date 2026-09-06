use std::{collections::{HashMap,VecDeque}, net::IpAddr};
use tron_protocol::protocol::ReasonCode;
use crate::app_message::{AppMessage, AppMessageType};

pub const STAT_SLOTS: usize = 60;

/// Java-compatible 60 one-second slots. Reset intentionally clears only the total.
#[derive(Clone, Debug)]
pub struct MessageCount { slots:[u32;STAT_SLOTS], index_time:i64, index:usize, total:u64 }
impl MessageCount {
    pub fn new(now_sec:i64)->Self{Self{slots:[0;STAT_SLOTS],index_time:now_sec,index:now_sec.rem_euclid(STAT_SLOTS as i64) as usize,total:0}}
    fn update(&mut self,now_sec:i64){let gap=now_sec-self.index_time;let k=if gap>STAT_SLOTS as i64{STAT_SLOTS}else if gap>0{gap as usize}else{0};if k>0{for i in 1..=k{self.slots[(self.index+i)%STAT_SLOTS]=0}self.index=now_sec.rem_euclid(STAT_SLOTS as i64) as usize;self.index_time=now_sec}}
    pub fn add(&mut self,amount:u32,now_sec:i64){self.update(now_sec);self.slots[self.index]=self.slots[self.index].wrapping_add(amount);self.total=self.total.wrapping_add(u64::from(amount))}
    /// Returns zero for intervals above 60, matching Java. Zero is valid and returns zero.
    pub fn count(&mut self,interval:usize,now_sec:i64)->u32{if interval>STAT_SLOTS{return 0}self.update(now_sec);let mut n=0u32;for i in 0..interval{n=n.wrapping_add(self.slots[(STAT_SLOTS+self.index-i)%STAT_SLOTS])}n}
    pub const fn total(&self)->u64{self.total}
    pub fn reset_total(&mut self){self.total=0}
}
#[derive(Clone, Debug, Default)]
pub struct NodeStatistics { remote:Option<ReasonCode>, local:Option<ReasonCode>, disconnect_times:u32 }
impl NodeStatistics {
    pub fn disconnect_reason(&self)->ReasonCode{self.local.or(self.remote).unwrap_or(ReasonCode::Unknown)}
    pub fn disconnected_remote(&mut self,reason:ReasonCode){self.remote=Some(reason);self.disconnect_times=self.disconnect_times.saturating_add(1)}
    pub fn disconnected_local(&mut self,reason:ReasonCode){self.local=Some(reason);self.disconnect_times=self.disconnect_times.saturating_add(1)}
    pub const fn disconnect_times(&self)->u32{self.disconnect_times}
    pub const fn remote_reason(&self)->Option<ReasonCode>{self.remote}
    pub const fn local_reason(&self)->Option<ReasonCode>{self.local}
}

#[derive(Clone, Debug)]
pub struct PeerStatistics { pub message_statistics:MessageStatistics }
impl PeerStatistics { pub fn new(now_sec:i64)->Self{Self{message_statistics:MessageStatistics::new(now_sec)}} }

pub const NODE_STATISTICS_CACHE_LIMIT:usize=3_000;
pub const TRAFFIC_INITIAL_DELAY_SECS:u64=1;
pub const TRAFFIC_INTERVAL_SECS:u64=1;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)] pub struct P2pTraffic { pub tcp_in:u64,pub tcp_out:u64,pub udp_in:u64,pub udp_out:u64 }
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)] pub struct TrafficDelta { pub tcp_in:u64,pub tcp_out:u64,pub udp_in:u64,pub udp_out:u64 }
#[derive(Clone, Debug, Default)]
pub struct TronStatsManager { previous:P2pTraffic, nodes:HashMap<IpAddr,NodeStatistics>, order:VecDeque<IpAddr> }
impl TronStatsManager {
    pub fn previous(&self)->P2pTraffic{self.previous}
    pub fn node_statistics(&mut self,address:IpAddr)->&mut NodeStatistics{if !self.nodes.contains_key(&address){if self.nodes.len()>=NODE_STATISTICS_CACHE_LIMIT{if let Some(old)=self.order.pop_front(){self.nodes.remove(&old);}}self.order.push_back(address);self.nodes.insert(address,NodeStatistics::default());}self.nodes.get_mut(&address).expect("inserted node statistics")}
    pub fn node_count(&self)->usize{self.nodes.len()}
    pub fn work(&mut self,current:P2pTraffic)->TrafficDelta{let delta=TrafficDelta{tcp_in:current.tcp_in.wrapping_sub(self.previous.tcp_in),tcp_out:current.tcp_out.wrapping_sub(self.previous.tcp_out),udp_in:current.udp_in.wrapping_sub(self.previous.udp_in),udp_out:current.udp_out.wrapping_sub(self.previous.udp_out)};self.previous=current;delta}
}

#[derive(Clone, Debug)]
pub struct ProtocolStats { inbound:HashMap<AppMessageType,MessageCount>,outbound:HashMap<AppMessageType,MessageCount>,in_bytes:u64,out_bytes:u64,epoch_sec:i64 }
impl ProtocolStats {
    pub fn new(now_sec:i64)->Self{Self{inbound:HashMap::new(),outbound:HashMap::new(),in_bytes:0,out_bytes:0,epoch_sec:now_sec}}
    pub fn record_in(&mut self,msg:&AppMessage,now_sec:i64){self.in_bytes=self.in_bytes.wrapping_add(msg.send_bytes().len() as u64);self.inbound.entry(msg.kind()).or_insert_with(||MessageCount::new(self.epoch_sec)).add(element_count(msg),now_sec)}
    pub fn record_out(&mut self,msg:&AppMessage,now_sec:i64){self.out_bytes=self.out_bytes.wrapping_add(msg.send_bytes().len() as u64);self.outbound.entry(msg.kind()).or_insert_with(||MessageCount::new(self.epoch_sec)).add(element_count(msg),now_sec)}
    pub fn inbound_count(&mut self,kind:AppMessageType,interval:usize,now_sec:i64)->u32{self.inbound.get_mut(&kind).map_or(0,|c|c.count(interval,now_sec))}
    pub fn outbound_count(&mut self,kind:AppMessageType,interval:usize,now_sec:i64)->u32{self.outbound.get_mut(&kind).map_or(0,|c|c.count(interval,now_sec))}
    pub const fn byte_totals(&self)->(u64,u64){(self.in_bytes,self.out_bytes)}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrafficStat {
    Message, Hello, Ping, Pong, Disconnect, SyncBlockChain, ChainInventory,
    TrxInventory, TrxInventoryElement, BlockInventory, BlockInventoryElement,
    TrxFetch, TrxFetchElement, BlockFetch, BlockFetchElement, Transaction,
    Transactions, Block, AdvBlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum InventoryKind { Transaction, Block }

#[derive(Clone, Debug)]
pub struct MessageStatistics { inbound:HashMap<TrafficStat,MessageCount>, outbound:HashMap<TrafficStat,MessageCount>, epoch_sec:i64 }
impl MessageStatistics {
    pub fn new(now_sec:i64)->Self{Self{inbound:HashMap::new(),outbound:HashMap::new(),epoch_sec:now_sec}}
    fn add(map:&mut HashMap<TrafficStat,MessageCount>,epoch:i64,stat:TrafficStat,amount:u32,now:i64){map.entry(stat).or_insert_with(||MessageCount::new(epoch)).add(amount,now)}
    pub fn record(&mut self,inbound:bool,kind:AppMessageType,inventory:Option<(InventoryKind,u32)>,transaction_count:Option<u32>,now:i64){let map=if inbound{&mut self.inbound}else{&mut self.outbound};Self::add(map,self.epoch_sec,TrafficStat::Message,1,now);match kind{
        AppMessageType::Hello=>Self::add(map,self.epoch_sec,TrafficStat::Hello,1,now),AppMessageType::Ping=>Self::add(map,self.epoch_sec,TrafficStat::Ping,1,now),AppMessageType::Pong=>Self::add(map,self.epoch_sec,TrafficStat::Pong,1,now),AppMessageType::Disconnect=>Self::add(map,self.epoch_sec,TrafficStat::Disconnect,1,now),AppMessageType::SyncBlockChain=>Self::add(map,self.epoch_sec,TrafficStat::SyncBlockChain,1,now),AppMessageType::ChainInventory=>Self::add(map,self.epoch_sec,TrafficStat::ChainInventory,1,now),
        AppMessageType::Inventory=>if let Some((k,n))=inventory{let (a,b)=if k==InventoryKind::Transaction{(TrafficStat::TrxInventory,TrafficStat::TrxInventoryElement)}else{(TrafficStat::BlockInventory,TrafficStat::BlockInventoryElement)};Self::add(map,self.epoch_sec,a,1,now);Self::add(map,self.epoch_sec,b,n,now)},
        AppMessageType::FetchInventoryData=>if let Some((k,n))=inventory{let (a,b)=if k==InventoryKind::Transaction{(TrafficStat::TrxFetch,TrafficStat::TrxFetchElement)}else{(TrafficStat::BlockFetch,TrafficStat::BlockFetchElement)};Self::add(map,self.epoch_sec,a,1,now);Self::add(map,self.epoch_sec,b,n,now)},
        AppMessageType::Transactions=>{Self::add(map,self.epoch_sec,TrafficStat::Transactions,1,now);Self::add(map,self.epoch_sec,TrafficStat::Transaction,transaction_count.unwrap_or(0),now)},AppMessageType::Transaction=>Self::add(map,self.epoch_sec,TrafficStat::Transaction,1,now),AppMessageType::Block=>Self::add(map,self.epoch_sec,TrafficStat::Block,1,now),AppMessageType::Pbft|AppMessageType::PbftCommit=>{}}
    }
    pub fn count(&mut self,inbound:bool,stat:TrafficStat,interval:usize,now:i64)->u32{let map=if inbound{&mut self.inbound}else{&mut self.outbound};map.get_mut(&stat).map_or(0,|c|c.count(interval,now))}
    pub fn total(&self,inbound:bool,stat:TrafficStat)->u64{let map=if inbound{&self.inbound}else{&self.outbound};map.get(&stat).map_or(0,MessageCount::total)}
}

pub fn need_to_log(kind:AppMessageType,inventory:Option<InventoryKind>)->bool{!matches!(kind,AppMessageType::Ping|AppMessageType::Pong|AppMessageType::Transactions|AppMessageType::Pbft|AppMessageType::PbftCommit)&&!(kind==AppMessageType::Inventory&&inventory==Some(InventoryKind::Transaction))}
fn element_count(_msg:&AppMessage)->u32{1}
