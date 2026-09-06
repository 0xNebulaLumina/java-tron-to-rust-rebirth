use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tron_protocol::protocol::{MetricsInfo, metrics_info};
use crate::prometheus::MetricsRegistry;

pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(60);
pub const METER_TICK_INTERVAL: Duration = Duration::from_secs(5);
pub const TRAFFIC_IN: &str = "in";
pub const TRAFFIC_OUT: &str = "out";

pub trait MetricsClock: Send + Sync { fn elapsed(&self) -> Duration; }

#[derive(Debug)]
struct SystemMetricsClock { started: Instant }
impl SystemMetricsClock { fn new() -> Self { Self { started: Instant::now() } } }
impl MetricsClock for SystemMetricsClock { fn elapsed(&self) -> Duration { self.started.elapsed() } }

#[derive(Clone, Copy, Debug, Default)]
pub struct RateSnapshot { pub count: i64, pub mean_rate: f64, pub one_minute_rate: f64, pub five_minute_rate: f64, pub fifteen_minute_rate: f64 }
impl From<RateSnapshot> for metrics_info::RateInfo { fn from(v: RateSnapshot) -> Self { Self { count:v.count, mean_rate:v.mean_rate, one_minute_rate:v.one_minute_rate, five_minute_rate:v.five_minute_rate, fifteen_minute_rate:v.fifteen_minute_rate } } }

#[derive(Clone, Copy, Debug)]
struct Ewma { alpha: f64, rate: f64, uncounted: i64, initialized: bool }
impl Ewma {
    fn new(minutes: f64) -> Self { Self { alpha: 1.0 - (-5.0 / (60.0 * minutes)).exp(), rate: 0.0, uncounted: 0, initialized: false } }
    fn update(&mut self, amount: i64) { self.uncounted = self.uncounted.saturating_add(amount); }
    fn tick(&mut self) { let instant_rate = self.uncounted as f64 / METER_TICK_INTERVAL.as_secs_f64(); self.uncounted = 0; if self.initialized { self.rate += self.alpha * (instant_rate - self.rate); } else { self.rate = instant_rate; self.initialized = true; } }
}

#[derive(Debug)]
struct MeterState { last_tick: Duration, one: Ewma, five: Ewma, fifteen: Ewma }
impl MeterState {
    fn tick_if_necessary(&mut self, now: Duration) { let age=now.saturating_sub(self.last_tick); let ticks=age.as_nanos()/METER_TICK_INTERVAL.as_nanos(); if ticks==0{return} self.last_tick=self.last_tick.saturating_add(METER_TICK_INTERVAL.saturating_mul(u32::try_from(ticks).unwrap_or(u32::MAX))); for _ in 0..ticks { self.one.tick(); self.five.tick(); self.fifteen.tick(); } }
}

#[derive(Debug)]
struct Meter { count: AtomicI64, started: Duration, state: Mutex<MeterState> }
impl Meter {
    fn new(now: Duration) -> Self { Self { count:AtomicI64::new(0),started:now,state:Mutex::new(MeterState{last_tick:now,one:Ewma::new(1.0),five:Ewma::new(5.0),fifteen:Ewma::new(15.0)}) } }
    fn mark(&self, amount:i64, now:Duration) { if amount <= 0 { return; } let mut state=self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner); state.tick_if_necessary(now); state.one.update(amount); state.five.update(amount); state.fifteen.update(amount); self.count.fetch_add(amount,Ordering::Relaxed); }
    fn snapshot(&self, now:Duration)->RateSnapshot { let count=self.count.load(Ordering::Relaxed); let elapsed=now.saturating_sub(self.started).as_secs_f64(); let mut state=self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner); state.tick_if_necessary(now); RateSnapshot{count,mean_rate:if elapsed>0.0{count as f64/elapsed}else{0.0},one_minute_rate:state.one.rate,five_minute_rate:state.five.rate,fifteen_minute_rate:state.fifteen.rate} }
}
#[derive(Debug, Default)]
struct Histogram { count:AtomicI64, values: Mutex<Vec<i64>> }
impl Histogram { fn observe(&self,v:i64){self.count.fetch_add(1,Ordering::Relaxed);let mut values=self.values.lock().unwrap_or_else(std::sync::PoisonError::into_inner);values.push(v);if values.len()>8_192{values.remove(0);}} fn stats(&self)->(i32,i32,i32,i32){let mut v=self.values.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();v.sort_unstable();(pct(&v,0.99),pct(&v,0.95),pct(&v,0.75),i32::try_from(self.count.load(Ordering::Relaxed)).unwrap_or(i32::MAX))} }
fn pct(v:&[i64],q:f64)->i32 { if v.is_empty(){return 0} let index=((v.len() as f64*q).ceil() as usize).saturating_sub(1).min(v.len()-1); i32::try_from(v[index]).unwrap_or(if v[index]<0{i32::MIN}else{i32::MAX}) }

#[derive(Clone)]
pub struct MonitorMetrics { inner:Arc<Inner> }
struct Inner {
    started:Duration, clock:Arc<dyn MetricsClock>, prometheus:MetricsRegistry,
    meters:Mutex<BTreeMap<String,Arc<Meter>>>, histograms:Mutex<BTreeMap<String,Arc<Histogram>>>, counters:Mutex<BTreeMap<String,Arc<AtomicI64>>>,
    head_num:AtomicI64, head_timestamp:AtomicI64, head_hash:Mutex<String>, transaction_cache:AtomicI64,
    fail_process_num:AtomicI64, fail_process_reason:Mutex<String>,
    node:Mutex<metrics_info::NodeInfo>, witnesses:Mutex<BTreeMap<String,i32>>, duplicate_witnesses:Mutex<BTreeMap<String,(i64,i32)>>,
    connections:AtomicI64, valid_connections:AtomicI64,
}
impl MonitorMetrics {
    #[must_use] pub fn new(enabled:bool)->Self { Self::with_clock(enabled,Arc::new(SystemMetricsClock::new())) }
    #[must_use] pub fn with_clock(enabled:bool,clock:Arc<dyn MetricsClock>)->Self { let now=clock.elapsed(); Self{inner:Arc::new(Inner{started:now,clock,prometheus:MetricsRegistry::new(enabled),meters:Mutex::new(BTreeMap::new()),histograms:Mutex::new(BTreeMap::new()),counters:Mutex::new(BTreeMap::new()),head_num:AtomicI64::new(0),head_timestamp:AtomicI64::new(0),head_hash:Mutex::new(String::new()),transaction_cache:AtomicI64::new(0),fail_process_num:AtomicI64::new(0),fail_process_reason:Mutex::new(String::new()),node:Mutex::new(metrics_info::NodeInfo::default()),witnesses:Mutex::new(BTreeMap::new()),duplicate_witnesses:Mutex::new(BTreeMap::new()),connections:AtomicI64::new(0),valid_connections:AtomicI64::new(0)})} }
    #[must_use] pub fn prometheus(&self)->&MetricsRegistry { &self.inner.prometheus }
    fn meter(&self,key:&str)->Arc<Meter>{let mut m=self.inner.meters.lock().unwrap_or_else(std::sync::PoisonError::into_inner);Arc::clone(m.entry(key.to_owned()).or_insert_with(||Arc::new(Meter::new(self.inner.started))))}
    fn histogram(&self,key:&str)->Arc<Histogram>{let mut h=self.inner.histograms.lock().unwrap_or_else(std::sync::PoisonError::into_inner);Arc::clone(h.entry(key.to_owned()).or_insert_with(||Arc::new(Histogram::default())))}
    pub fn meter_mark(&self,key:&str,amount:i64){self.meter(key).mark(amount,self.inner.clock.elapsed())}
    pub fn counter_inc(&self,key:&str){let counter={let mut c=self.inner.counters.lock().unwrap_or_else(std::sync::PoisonError::into_inner);Arc::clone(c.entry(key.to_owned()).or_insert_with(||Arc::new(AtomicI64::new(0))))};counter.fetch_add(1,Ordering::Relaxed);}
    pub fn histogram_update(&self,key:&str,value:i64){self.histogram(key).observe(value)}
    pub fn record_head(&self,number:i64,timestamp:i64,hash:impl Into<String>){self.inner.head_num.store(number,Ordering::Release);self.inner.head_timestamp.store(timestamp,Ordering::Release);*self.inner.head_hash.lock().unwrap_or_else(std::sync::PoisonError::into_inner)=hash.into();let _=self.inner.prometheus.gauge_set("tron:header_height",number as f64,&[]);let _=self.inner.prometheus.gauge_set("tron:header_time",timestamp as f64,&[]);}
    pub fn set_node(&self,node:metrics_info::NodeInfo){*self.inner.node.lock().unwrap_or_else(std::sync::PoisonError::into_inner)=node}
    pub fn set_connections(&self,total:i32,valid:i32){self.inner.connections.store(total.into(),Ordering::Relaxed);self.inner.valid_connections.store(valid.into(),Ordering::Relaxed);}
    pub fn set_transaction_cache_size(&self,size:i32){self.inner.transaction_cache.store(size.into(),Ordering::Relaxed)}
    pub fn set_fail_process_block(&self,number:i64,reason:impl Into<String>){self.inner.fail_process_num.store(number,Ordering::Release);*self.inner.fail_process_reason.lock().unwrap_or_else(std::sync::PoisonError::into_inner)=reason.into()}
    pub fn set_witness(&self,address:impl Into<String>,version:i32){self.inner.witnesses.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(address.into(),version);}
    pub fn record_duplicate_witness(&self,address:impl Into<String>,block_num:i64){let mut d=self.inner.duplicate_witnesses.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let e=d.entry(address.into()).or_insert((block_num,0));e.0=block_num;e.1=e.1.saturating_add(1);}
    pub fn record_transaction(&self,success:bool,detail:&'static str){self.meter_mark("blockchain.tps",1);let ty=if success{"success"}else{"fail"};let _=self.inner.prometheus.counter_inc("tron:txs",1.0,&[ty,detail]);}
    pub fn record_fork(&self,success:bool){let key=if success{"blockchain.forkCount"}else{"blockchain.failForkCount"};self.meter_mark(key,1);let _=self.inner.prometheus.counter_inc("tron:block_fork",1.0,&[if success{"success"}else{"fail"}]);}
    pub fn record_traffic(&self,transport:&str,inbound:bool,bytes:u64){let direction=if inbound{TRAFFIC_IN}else{TRAFFIC_OUT};let (legacy,prom)=match(transport,inbound){("tcp",true)=>("net.tcpInTraffic","tron:tcp_bytes"),("tcp",false)=>("net.tcpOutTraffic","tron:tcp_bytes"),("udp",true)=>("net.udpInTraffic","tron:udp_bytes"),("udp",false)=>("net.udpOutTraffic","tron:udp_bytes"),_=>return};self.meter_mark(legacy,i64::try_from(bytes).unwrap_or(i64::MAX));let _=self.inner.prometheus.histogram_observe(prom,bytes as f64,&[direction]);}
    pub fn record_disconnect(&self,reason:&str){self.meter_mark("net.disconnectionCount",1);self.counter_inc(&format!("net.disconnectionDetail.{reason}"));let _=self.inner.prometheus.counter_inc("tron:p2p_disconnect",1.0,&[reason]);}
    pub fn record_block_latency(&self,witness:&str,millis:i64){self.histogram_update("net.latency",millis);self.histogram_update(&format!("net.latency.witness.{witness}"),millis);if millis>=1000{self.counter_inc("net.latency.1S")}if millis>=2000{self.counter_inc("net.latency.2S")}if millis>=3000{self.counter_inc("net.latency.3S")}}
    #[must_use] pub fn snapshot(&self)->MetricsInfo { self.snapshot_at(self.inner.clock.elapsed()) }
    fn snapshot_at(&self,now:Duration)->MetricsInfo { MetricsInfo{interval:i64::try_from(now.saturating_sub(self.inner.started).as_secs()).unwrap_or(i64::MAX),node:Some(self.inner.node.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()),blockchain:Some(self.blockchain(now)),net:Some(self.net(now))} }
    fn rate(&self,key:&str,now:Duration)->metrics_info::RateInfo{self.meter(key).snapshot(now).into()}
    fn blockchain(&self,now:Duration)->metrics_info::BlockChainInfo{let witnesses=self.inner.witnesses.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter().map(|(address,version)|metrics_info::block_chain_info::Witness{address:address.clone(),version:*version}).collect();let dup_witness=self.inner.duplicate_witnesses.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter().map(|(address,(block_num,count))|metrics_info::block_chain_info::DupWitness{address:address.clone(),block_num:*block_num,count:*count}).collect();metrics_info::BlockChainInfo{head_block_num:self.inner.head_num.load(Ordering::Acquire),head_block_timestamp:self.inner.head_timestamp.load(Ordering::Acquire),head_block_hash:self.inner.head_hash.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),fork_count:self.rate("blockchain.forkCount",now).count as i32,fail_fork_count:self.rate("blockchain.failForkCount",now).count as i32,block_process_time:Some(self.rate("blockchain.blockProcessTime",now)),tps:Some(self.rate("blockchain.tps",now)),transaction_cache_size:self.inner.transaction_cache.load(Ordering::Relaxed) as i32,missed_transaction:Some(self.rate("blockchain.missedTransaction",now)),witnesses,fail_process_block_num:self.inner.fail_process_num.load(Ordering::Acquire),fail_process_block_reason:self.inner.fail_process_reason.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),dup_witness}}
    fn net(&self,now:Duration)->metrics_info::NetInfo{let disconnection_detail=self.inner.counters.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter().filter_map(|(k,v)|k.strip_prefix("net.disconnectionDetail.").map(|reason|metrics_info::net_info::DisconnectionDetailInfo{reason:reason.to_owned(),count:v.load(Ordering::Relaxed) as i32})).collect();metrics_info::NetInfo{error_proto_count:self.rate("net.errorProtoCount",now).count as i32,api:Some(metrics_info::net_info::ApiInfo{qps:Some(self.rate("net.api.qps",now)),fail_qps:Some(self.rate("net.api.failQps",now)),out_traffic:Some(self.rate("net.api.outTraffic",now)),detail:Vec::new()}),connection_count:self.inner.connections.load(Ordering::Relaxed) as i32,valid_connection_count:self.inner.valid_connections.load(Ordering::Relaxed) as i32,tcp_in_traffic:Some(self.rate("net.tcpInTraffic",now)),tcp_out_traffic:Some(self.rate("net.tcpOutTraffic",now)),udp_in_traffic:Some(self.rate("net.udpInTraffic",now)),udp_out_traffic:Some(self.rate("net.udpOutTraffic",now)),disconnection_count:self.rate("net.disconnectionCount",now).count as i32,disconnection_detail,latency:Some(self.latency())}}
    fn latency(&self)->metrics_info::net_info::LatencyInfo{let (top99,top95,top75,total_count)=self.histogram("net.latency").stats();let count=|key:&str|self.inner.counters.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(key).map_or(0,|v|v.load(Ordering::Relaxed) as i32);let details=self.inner.histograms.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter().filter_map(|(k,h)|k.strip_prefix("net.latency.witness.").map(|w|{let(a,b,c,d)=h.stats();metrics_info::net_info::latency_info::LatencyDetailInfo{witness:w.to_owned(),top99:a,top95:b,top75:c,count:d,delay1_s:0,delay2_s:0,delay3_s:0}})).collect();metrics_info::net_info::LatencyInfo{top99,top95,top75,total_count,delay1_s:count("net.latency.1S"),delay2_s:count("net.latency.2S"),delay3_s:count("net.latency.3S"),detail:details}}
}

pub trait MonitorProvider:Send+Sync{fn metrics(&self)->MetricsInfo;}
impl MonitorProvider for MonitorMetrics{fn metrics(&self)->MetricsInfo{self.snapshot()}}
