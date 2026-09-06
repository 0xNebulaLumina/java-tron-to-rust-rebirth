use std::{collections::{HashMap, VecDeque}, sync::Arc, sync::atomic::{AtomicU64, Ordering}, time::{Duration, Instant}};
use parking_lot::Mutex;
use tron_crypto::keccak256;
use tron_execution::{FilterEvent, FilterSink};
use tron_primitives::Hash32;

pub const BLOOM_BITS: usize = 2048;
pub const BLOOM_BYTES: usize = BLOOM_BITS / 8;
pub const BLOCKS_PER_SECTION: u64 = 2048;
pub const FILTER_LIFETIME: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bloom([u8; BLOOM_BYTES]);
impl Default for Bloom { fn default() -> Self { Self([0; BLOOM_BYTES]) } }
impl Bloom {
    pub fn from_bytes(bytes: [u8; BLOOM_BYTES]) -> Self { Self(bytes) }
    pub fn as_bytes(&self) -> &[u8; BLOOM_BYTES] { &self.0 }
    pub fn for_value(value: &[u8]) -> Self { Self::for_hash(&keccak256(value)) }
    pub fn for_hash(hash: &[u8; 32]) -> Self {
        let mut out=Self::default();
        for pair in hash[..6].chunks_exact(2) {
            let bit=(((pair[0] as usize)&7)<<8)|(pair[1] as usize);
            out.0[bit / 8] |= 1 << (bit % 8);
        }
        out
    }
    pub fn insert(&mut self, value: &[u8]) { self.or_assign(&Self::for_value(value)); }
    pub fn or_assign(&mut self, other: &Self) { for (a,b) in self.0.iter_mut().zip(other.0) { *a|=b; } }
    pub fn contains(&self, required: &Self) -> bool { self.0.iter().zip(required.0).all(|(a,b)| a & b == b) }
    pub fn set_bits(&self) -> impl Iterator<Item=usize> + '_ { (0..BLOOM_BITS).filter(|bit| self.0[*bit/8] & (1<<(*bit%8)) != 0) }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SectionBloom { sections: HashMap<(u64,usize), Vec<u64>> }
impl SectionBloom {
    pub fn index_block(&mut self, block_number:u64, bloom:&Bloom) {
        let section=block_number/BLOCKS_PER_SECTION; let offset=(block_number%BLOCKS_PER_SECTION) as usize;
        for bit in bloom.set_bits() { let words=self.sections.entry((section,bit)).or_insert_with(||vec![0;32]); words[offset/64]|=1u64<<(offset%64); }
    }
    pub fn candidates(&self, from:u64, to:u64, filter:&LogFilter)->Vec<u64> {
        if from>to{return Vec::new()} let first=from/BLOCKS_PER_SECTION; let last=to/BLOCKS_PER_SECTION; let groups=filter.bloom_groups(); let mut out=Vec::new();
        for section in first..=last { let mut possible=[u64::MAX;32];
            for alternatives in &groups { if alternatives.is_empty(){continue} let mut any=[0u64;32];
                for bloom in alternatives { let mut all=[u64::MAX;32]; for bit in bloom.set_bits(){ let words=self.sections.get(&(section,bit)); for i in 0..32 { all[i]&=words.map_or(0,|v|v[i]); } } for i in 0..32 {any[i]|=all[i]} }
                for i in 0..32 {possible[i]&=any[i]}
            }
            for offset in 0..BLOCKS_PER_SECTION as usize { let n=section*BLOCKS_PER_SECTION+offset as u64; if n>=from&&n<=to&&(possible[offset/64]&(1u64<<(offset%64))!=0){out.push(n)} }
        } out
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LogFilter { pub addresses: Vec<Vec<u8>>, pub topics: Vec<Option<Vec<Hash32>>>, pub from_block: Option<u64>, pub to_block: Option<u64>, pub block_hash: Option<Hash32> }
impl LogFilter {
    pub fn validate(&self, limits:&FilterLimits)->Result<(),FilterError>{
        if self.block_hash.is_some()&&(self.from_block.is_some()||self.to_block.is_some()){return Err(FilterError::Invalid("cannot specify both blockHash and fromBlock/toBlock".into()))}
        if self.topics.len()>4{return Err(FilterError::Invalid("topics size should be <= 4".into()))}
        if limits.max_addresses>0&&self.addresses.len()>limits.max_addresses{return Err(FilterError::Limit(format!("exceed max addresses: {}",limits.max_addresses)))}
        for values in self.topics.iter().flatten(){if limits.max_subtopics>0&&values.len()>limits.max_subtopics{return Err(FilterError::Limit(format!("exceed max topics: {}",limits.max_subtopics)))}}
        if let(Some(a),Some(b))=(self.from_block,self.to_block){if a>b{return Err(FilterError::Invalid("please verify: fromBlock <= toBlock".into()))} if limits.max_block_range>0&&b-a>limits.max_block_range{return Err(FilterError::Limit(format!("exceed max block range: {}",limits.max_block_range)))}}
        Ok(())
    }
    pub fn matches(&self, log:&RpcLog)->bool { if self.from_block.is_some_and(|n|log.block_number<n)||self.to_block.is_some_and(|n|log.block_number>n){return false} if !self.addresses.is_empty()&&!self.addresses.iter().any(|a|a==&log.address){return false} for(i,want)in self.topics.iter().enumerate(){if i>=log.topics.len(){return false} if let Some(want)=want {if !want.is_empty()&&!want.contains(&log.topics[i]){return false}}} true }
    fn bloom_groups(&self)->Vec<Vec<Bloom>> { let mut groups=Vec::new(); for t in &self.topics {groups.push(t.as_ref().map(|v|v.iter().map(|x|Bloom::for_value(x.as_bytes())).collect()).unwrap_or_default())} groups.push(self.addresses.iter().map(|a|Bloom::for_value(a)).collect()); groups }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcLog { pub address:Vec<u8>, pub topics:Vec<Hash32>, pub data:Vec<u8>, pub block_hash:Hash32, pub block_number:u64, pub transaction_hash:Hash32, pub transaction_index:u64, pub log_index:u64, pub removed:bool }

#[derive(Clone,Copy,Debug,Eq,Hash,PartialEq)] pub enum FilterView { Full, Solidity }
#[derive(Clone,Debug)] enum Kind {
    Blocks { changes: VecDeque<Hash32>, bytes: usize },
    Pending { changes: VecDeque<Hash32>, bytes: usize },
    Logs { filter: LogFilter, changes: VecDeque<RpcLog>, bytes: usize },
}
#[derive(Clone,Debug)] struct Entry { expires:Instant, kind:Kind }
#[derive(Clone,Debug,Default)] struct History { logs:VecDeque<RpcLog>, bytes:usize, newest_block:Option<u64> }
#[derive(Clone,Debug)] pub struct FilterLimits {
    pub max_block_filters:usize,
    pub max_log_filters:usize,
    pub max_pending_filters:usize,
    pub max_total_filters_per_view:usize,
    pub max_total_filters:usize,
    pub max_addresses:usize,
    pub max_subtopics:usize,
    pub max_block_range:u64,
    pub max_results:usize,
    pub max_queue_items:usize,
    pub max_queue_bytes:usize,
    pub max_total_queue_items:usize,
    pub max_total_queue_bytes:usize,
    pub max_publish_fanout:usize,
    pub max_publish_work:usize,
    pub history_blocks:u64,
    pub max_history_items:usize,
    pub max_history_bytes:usize,
}
impl Default for FilterLimits {fn default()->Self{Self{
    max_block_filters:4096,max_log_filters:4096,max_pending_filters:4096,
    max_total_filters_per_view:8192,max_total_filters:12_000,
    max_addresses:256,max_subtopics:256,max_block_range:5000,max_results:10_000,
    max_queue_items:1024,max_queue_bytes:1024*1024,
    max_total_queue_items:100_000,max_total_queue_bytes:32*1024*1024,
    max_publish_fanout:4096,max_publish_work:100_000,
    history_blocks:5000,max_history_items:100_000,max_history_bytes:64*1024*1024,
}}}
#[derive(Clone,Debug,Eq,PartialEq)] pub enum FilterError {NotFound,Invalid(String),Limit(String),Unavailable}
impl std::fmt::Display for FilterError{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{match self{Self::NotFound=>f.write_str("filter not found"),Self::Invalid(s)|Self::Limit(s)=>f.write_str(s),Self::Unavailable=>f.write_str("method not available")}}} impl std::error::Error for FilterError{}

pub trait FilterClock:Send+Sync+'static{fn now(&self)->Instant;}
#[derive(Default)]pub struct SystemFilterClock; impl FilterClock for SystemFilterClock{fn now(&self)->Instant{Instant::now()}}
struct State { maps:HashMap<FilterView,HashMap<u64,Entry>>, history:HashMap<FilterView,History>, kind_counts:HashMap<FilterView,[usize;3]>, total_filters:usize, queued_items:usize, queued_bytes:usize, last_prune:Instant }
#[derive(Clone,Copy,Debug,Default,Eq,PartialEq)] pub struct FilterUsage {pub filters:usize,pub queued_items:usize,pub queued_bytes:usize}
pub struct FilterManager {clock:Arc<dyn FilterClock>,limits:FilterLimits,next:AtomicU64,state:Mutex<State>}
impl FilterManager {
 pub fn new(clock:Arc<dyn FilterClock>,limits:FilterLimits)->Self{let now=clock.now();let mut maps=HashMap::new();maps.insert(FilterView::Full,HashMap::new());maps.insert(FilterView::Solidity,HashMap::new());let mut kind_counts=HashMap::new();kind_counts.insert(FilterView::Full,[0;3]);kind_counts.insert(FilterView::Solidity,[0;3]);Self{clock,limits,next:AtomicU64::new(1),state:Mutex::new(State{maps,history:HashMap::new(),kind_counts,total_filters:0,queued_items:0,queued_bytes:0,last_prune:now})}}
 pub fn system(limits:FilterLimits)->Self{Self::new(Arc::new(SystemFilterClock),limits)}
 pub fn shared(limits:FilterLimits)->Arc<Self>{Arc::new(Self::system(limits))}
 pub fn sink(self:&Arc<Self>)->ProductionFilterSink{ProductionFilterSink{manager:self.clone()}}
 pub fn usage(&self)->FilterUsage{let s=self.state.lock();FilterUsage{filters:s.total_filters,queued_items:s.queued_items,queued_bytes:s.queued_bytes}}
 fn kind_index(kind:&Kind)->usize{match kind{Kind::Blocks{..}=>0,Kind::Pending{..}=>1,Kind::Logs{..}=>2}}
 fn create(&self,view:FilterView,kind:Kind,cap:usize,label:&str)->Result<u64,FilterError>{let now=self.clock.now();let mut s=self.state.lock();if now.duration_since(s.last_prune)>=Duration::from_secs(1){Self::prune_locked(&mut s,now)}let view_count=s.maps[&view].len();if self.limits.max_total_filters_per_view>0&&view_count>=self.limits.max_total_filters_per_view{return Err(FilterError::Limit("exceed max filters for view".into()))}if self.limits.max_total_filters>0&&s.total_filters>=self.limits.max_total_filters{return Err(FilterError::Limit("exceed max total filters".into()))}let kind_index=Self::kind_index(&kind);if cap>0&&s.kind_counts[&view][kind_index]>=cap{return Err(FilterError::Limit(format!("exceed max {label} filters: {cap}, try again later")))}let id=self.next.fetch_add(1,Ordering::Relaxed);s.maps.get_mut(&view).unwrap().insert(id,Entry{expires:now+FILTER_LIFETIME,kind});s.kind_counts.get_mut(&view).unwrap()[kind_index]+=1;s.total_filters+=1;Ok(id)}
 pub fn new_block_filter(&self,view:FilterView)->Result<u64,FilterError>{self.create(view,Kind::Blocks{changes:VecDeque::new(),bytes:0},self.limits.max_block_filters,"block")}
 pub fn new_pending_filter(&self,view:FilterView)->Result<u64,FilterError>{self.create(view,Kind::Pending{changes:VecDeque::new(),bytes:0},self.limits.max_pending_filters,"pending transaction")}
 pub fn new_log_filter(&self,view:FilterView,filter:LogFilter)->Result<u64,FilterError>{filter.validate(&self.limits)?;self.create(view,Kind::Logs{filter,changes:VecDeque::new(),bytes:0},self.limits.max_log_filters,"log")}
 pub fn new_log_filter_deferred(&self,view:FilterView,filter:LogFilter)->Result<u64,FilterError>{let mut limits=self.limits.clone();limits.max_block_range=0;filter.validate(&limits)?;self.create(view,Kind::Logs{filter,changes:VecDeque::new(),bytes:0},self.limits.max_log_filters,"log")}
 pub fn uninstall(&self,view:FilterView,id:u64)->Result<bool,FilterError>{let now=self.clock.now();let mut s=self.state.lock();Self::prune_locked(&mut s,now);let result=s.maps.get_mut(&view).unwrap().remove(&id).map(|_|true).ok_or(FilterError::NotFound);Self::recount(&mut s);result}
 pub fn changes(&self,view:FilterView,id:u64)->Result<FilterChanges,FilterError>{let now=self.clock.now();let mut s=self.state.lock();Self::prune_locked(&mut s,now);let e=s.maps.get_mut(&view).unwrap().get_mut(&id).ok_or(FilterError::NotFound)?;e.expires=now+FILTER_LIFETIME;let result=match &mut e.kind{Kind::Blocks{changes,bytes}|Kind::Pending{changes,bytes}=>{*bytes=0;FilterChanges::Hashes(changes.drain(..).collect())},Kind::Logs{changes,bytes,..}=>{*bytes=0;FilterChanges::Logs(changes.drain(..).collect())}};Self::recount(&mut s);Ok(result)}
 pub fn filter_logs(&self,view:FilterView,id:u64)->Result<Vec<RpcLog>,FilterError>{self.prune();let s=self.state.lock();let m=s.maps.get(&view).unwrap();let f=match &m.get(&id).ok_or(FilterError::NotFound)?.kind{Kind::Logs{filter,..}=>filter,_=>return Err(FilterError::NotFound)};self.logs_locked(&s,view,f)}
 pub fn filter_logs_at(&self,view:FilterView,id:u64,current_head:u64)->Result<Vec<RpcLog>,FilterError>{self.prune();let s=self.state.lock();let m=s.maps.get(&view).unwrap();let mut f=match &m.get(&id).ok_or(FilterError::NotFound)?.kind{Kind::Logs{filter,..}=>filter.clone(),_=>return Err(FilterError::NotFound)};f.to_block=Some(f.to_block.unwrap_or(u64::MAX).min(current_head));f.validate(&self.limits)?;self.logs_locked(&s,view,&f)}
 pub fn get_logs(&self,view:FilterView,filter:&LogFilter)->Result<Vec<RpcLog>,FilterError>{filter.validate(&self.limits)?;let s=self.state.lock();self.logs_locked(&s,view,filter)}
 pub fn get_logs_at(&self,view:FilterView,filter:&LogFilter,current_head:u64)->Result<Vec<RpcLog>,FilterError>{let mut bounded=filter.clone();bounded.to_block=Some(bounded.to_block.unwrap_or(u64::MAX).min(current_head));bounded.validate(&self.limits)?;let s=self.state.lock();self.logs_locked(&s,view,&bounded)}
 fn logs_locked(&self,s:&State,view:FilterView,f:&LogFilter)->Result<Vec<RpcLog>,FilterError>{let matching=s.history.get(&view).into_iter().flat_map(|h|h.logs.iter()).filter(|l|f.block_hash.map_or(true,|h|h==l.block_hash)&&f.matches(l));let refs:Vec<_>=if self.limits.max_results==0{matching.collect()}else{matching.take(self.limits.max_results+1).collect()};if self.limits.max_results>0&&refs.len()>self.limits.max_results{return Err(FilterError::Limit("query returned more than allowed results".into()))}let mut v:Vec<_>=refs.into_iter().cloned().collect();v.sort_by_key(|l|(l.block_number,l.transaction_index,l.log_index));Ok(v)}
 pub fn publish_block(&self,view:FilterView,id:Hash32){let now=self.clock.now();let mut s=self.state.lock();Self::prune_locked(&mut s,now);let(mut total_items,mut total_bytes)=(s.queued_items,s.queued_bytes);let mut fanout=0;for e in s.maps.get_mut(&view).unwrap().values_mut(){if fanout>=self.limits.max_publish_fanout{break}if let Kind::Blocks{changes,bytes}=&mut e.kind{if Self::push_hash(changes,bytes,id,&self.limits,&mut total_items,&mut total_bytes){fanout+=1}}}s.queued_items=total_items;s.queued_bytes=total_bytes}
 pub fn publish_pending(&self,view:FilterView,id:Hash32){let now=self.clock.now();let mut s=self.state.lock();Self::prune_locked(&mut s,now);let(mut total_items,mut total_bytes)=(s.queued_items,s.queued_bytes);let mut fanout=0;for e in s.maps.get_mut(&view).unwrap().values_mut(){if fanout>=self.limits.max_publish_fanout{break}if let Kind::Pending{changes,bytes}=&mut e.kind{if Self::push_hash(changes,bytes,id,&self.limits,&mut total_items,&mut total_bytes){fanout+=1}}}s.queued_items=total_items;s.queued_bytes=total_bytes}
 pub fn publish_logs(&self,view:FilterView,logs:Vec<RpcLog>){let now=self.clock.now();let mut s=self.state.lock();Self::prune_locked(&mut s,now);let(mut total_items,mut total_bytes)=(s.queued_items,s.queued_bytes);let mut work=0;let mut fanout=0;for log in logs{for e in s.maps.get_mut(&view).unwrap().values_mut(){if work>=self.limits.max_publish_work||fanout>=self.limits.max_publish_fanout{break}work+=1;if let Kind::Logs{filter,changes,bytes}=&mut e.kind{if filter.matches(&log)&&Self::push_log(changes,bytes,log.clone(),&self.limits,&mut total_items,&mut total_bytes){fanout+=1}}}Self::push_history(s.history.entry(view).or_default(),log,&self.limits);if work>=self.limits.max_publish_work||fanout>=self.limits.max_publish_fanout{break}}s.queued_items=total_items;s.queued_bytes=total_bytes}
 pub fn prune(&self){let now=self.clock.now();Self::prune_locked(&mut self.state.lock(),now)}
 fn prune_locked(s:&mut State,now:Instant){for m in s.maps.values_mut(){m.retain(|_,e|e.expires>=now)}s.last_prune=now;Self::recount(s)}
 fn recount(s:&mut State){let mut items=0;let mut bytes=0;let mut total=0;for(view,map)in &s.maps{let mut counts=[0;3];for e in map.values(){total+=1;counts[Self::kind_index(&e.kind)]+=1;match &e.kind{Kind::Blocks{changes,bytes:b}|Kind::Pending{changes,bytes:b}=>{items+=changes.len();bytes+=*b},Kind::Logs{changes,bytes:b,..}=>{items+=changes.len();bytes+=*b}}}s.kind_counts.insert(*view,counts);}s.total_filters=total;s.queued_items=items;s.queued_bytes=bytes}
 fn reserve_global(items:&mut usize,bytes:&mut usize,size:usize,limits:&FilterLimits)->bool{if limits.max_total_queue_items==0||limits.max_total_queue_bytes<size||*items>=limits.max_total_queue_items||*bytes+size>limits.max_total_queue_bytes{return false}*items+=1;*bytes+=size;true}
 fn push_hash(q:&mut VecDeque<Hash32>,bytes:&mut usize,value:Hash32,limits:&FilterLimits,total_items:&mut usize,total_bytes:&mut usize)->bool{if limits.max_queue_items==0||limits.max_queue_bytes<32{return false}while q.len()>=limits.max_queue_items||*bytes+32>limits.max_queue_bytes{if q.pop_front().is_none(){break}*bytes-=32;*total_items-=1;*total_bytes-=32}if !Self::reserve_global(total_items,total_bytes,32,limits){return false}q.push_back(value);*bytes+=32;true}
 fn log_bytes(log:&RpcLog)->usize{log.address.len()+log.topics.len()*32+log.data.len()+32+32+8+8+8+1}
 fn push_log(q:&mut VecDeque<RpcLog>,bytes:&mut usize,value:RpcLog,limits:&FilterLimits,total_items:&mut usize,total_bytes:&mut usize)->bool{let size=Self::log_bytes(&value);if limits.max_queue_items==0||size>limits.max_queue_bytes{return false}while q.len()>=limits.max_queue_items||*bytes+size>limits.max_queue_bytes{let Some(old)=q.pop_front()else{break};let old_size=Self::log_bytes(&old);*bytes-=old_size;*total_items-=1;*total_bytes-=old_size}if !Self::reserve_global(total_items,total_bytes,size,limits){return false}q.push_back(value);*bytes+=size;true}
 fn push_history(history:&mut History,value:RpcLog,limits:&FilterLimits){let size=Self::log_bytes(&value);if limits.history_blocks==0||limits.max_history_items==0||size>limits.max_history_bytes{return}history.newest_block=Some(history.newest_block.map_or(value.block_number,|n|n.max(value.block_number)));let min_block=history.newest_block.unwrap().saturating_sub(limits.history_blocks-1);if value.block_number<min_block{return}while history.logs.front().is_some_and(|old|old.block_number<min_block){let old=history.logs.pop_front().unwrap();history.bytes-=Self::log_bytes(&old)}while history.logs.len()>=limits.max_history_items||history.bytes+size>limits.max_history_bytes{let Some(old)=history.logs.pop_front()else{break};history.bytes-=Self::log_bytes(&old)}history.bytes+=size;history.logs.push_back(value)}
 fn apply_filter_event(&self,view:FilterView,event:FilterEvent){match event{FilterEvent::Block{block_id,..}=>self.publish_block(view,block_id.hash()),FilterEvent::Logs{block_id,block_number,removed}=>{let hash=block_id.hash();let now=self.clock.now();let mut s=self.state.lock();Self::prune_locked(&mut s,now);let mut replay=Vec::new();if removed{if let Some(history)=s.history.get_mut(&view){replay.extend(history.logs.iter().filter(|l|l.block_hash==hash).cloned().map(|mut l|{l.removed=true;l}));history.logs.retain(|l|l.block_hash!=hash);history.bytes=history.logs.iter().map(Self::log_bytes).sum()}}else if let Some(history)=s.history.get(&view){replay.extend(history.logs.iter().filter(|l|l.block_hash==hash&&l.block_number==block_number as u64).cloned())}let(mut total_items,mut total_bytes)=(s.queued_items,s.queued_bytes);let mut fanout=0;let mut work=0;for log in replay{for e in s.maps.get_mut(&view).unwrap().values_mut(){if work>=self.limits.max_publish_work||fanout>=self.limits.max_publish_fanout{break}work+=1;if let Kind::Logs{filter,changes,bytes}=&mut e.kind{if filter.matches(&log)&&Self::push_log(changes,bytes,log.clone(),&self.limits,&mut total_items,&mut total_bytes){fanout+=1}}}}s.queued_items=total_items;s.queued_bytes=total_bytes}}}
}
#[derive(Clone)]pub struct ProductionFilterSink{manager:Arc<FilterManager>}
impl ProductionFilterSink{pub fn solidified(&mut self,event:FilterEvent){self.manager.apply_filter_event(FilterView::Solidity,event)}pub fn manager(&self)->&Arc<FilterManager>{&self.manager}}
impl FilterSink for ProductionFilterSink{fn filter(&mut self,event:FilterEvent){self.manager.apply_filter_event(FilterView::Full,event)}}
impl FilterSink for FilterManager{fn filter(&mut self,event:FilterEvent){self.apply_filter_event(FilterView::Full,event)}}
#[derive(Clone,Debug,Eq,PartialEq)]pub enum FilterChanges{Hashes(Vec<Hash32>),Logs(Vec<RpcLog>)}
pub fn encode_filter_id(id:u64)->String{format!("0x{id:x}")} pub fn decode_filter_id(s:&str)->Result<u64,FilterError>{u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s),16).map_err(|_|FilterError::Invalid("invalid filter id".into()))}
