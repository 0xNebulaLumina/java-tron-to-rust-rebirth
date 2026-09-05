use std::collections::{HashMap,VecDeque};
use tron_crypto::{selected_digest,CryptoEngine};
use tron_primitives::Hash32;

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct CacheConfig { pub maximum_entries:usize, pub ttl_millis:i64, pub bloom_blocks:i64, pub bloom_bits:usize }
impl Default for CacheConfig { fn default()->Self{Self{maximum_entries:100_000,ttl_millis:3_600_000,bloom_blocks:65_536,bloom_bits:1<<22}} }
#[derive(Clone,Debug,Eq,PartialEq)] pub enum CacheError { ZeroCapacity,NonPositiveTtl,NonPositiveRotation,TooFewBloomBits,TimeReversal{previous:i64,now:i64},BlockReversal{previous:i64,now:i64} }
impl core::fmt::Display for CacheError{fn fmt(&self,f:&mut core::fmt::Formatter<'_>)->core::fmt::Result{write!(f,"{self:?}")}} impl std::error::Error for CacheError{}

#[derive(Clone)] struct Bloom{bits:Vec<u64>}
impl Bloom{fn new(n:usize)->Self{Self{bits:vec![0;(n+63)/64]}}fn indexes(&self,id:&Hash32)->[usize;3]{let b=id.as_bytes();let n=self.bits.len()*64;[u64::from_le_bytes(b[0..8].try_into().unwrap()) as usize%n,u64::from_le_bytes(b[8..16].try_into().unwrap()) as usize%n,u64::from_le_bytes(b[16..24].try_into().unwrap()) as usize%n]}fn insert(&mut self,id:&Hash32){for i in self.indexes(id){self.bits[i/64]|=1u64<<(i%64)}}fn contains(&self,id:&Hash32)->bool{self.indexes(id).into_iter().all(|i|self.bits[i/64]&(1u64<<(i%64))!=0)}}

#[derive(Clone)]
pub struct TransactionCache { config:CacheConfig, entries:HashMap<Hash32,i64>, order:VecDeque<(Hash32,i64)>, blooms:[Bloom;2], active:usize, filter_start_block:Option<i64>, last_now:Option<i64>, last_block:Option<i64> }
impl TransactionCache{
 pub fn new(config:CacheConfig)->Result<Self,CacheError>{if config.maximum_entries==0{return Err(CacheError::ZeroCapacity)}if config.ttl_millis<=0{return Err(CacheError::NonPositiveTtl)}if config.bloom_blocks<=0{return Err(CacheError::NonPositiveRotation)}if config.bloom_bits<64{return Err(CacheError::TooFewBloomBits)}let b=Bloom::new(config.bloom_bits);Ok(Self{config,entries:HashMap::new(),order:VecDeque::new(),blooms:[b.clone(),b],active:0,filter_start_block:None,last_now:None,last_block:None})}
 pub fn insert_bytes(&mut self,engine:CryptoEngine,raw_data:&[u8],block:i64,now:i64)->Result<Hash32,CacheError>{let id=Hash32::from(selected_digest(engine,raw_data));self.insert(id,block,now)?;Ok(id)}
 pub fn insert(&mut self,id:Hash32,block:i64,now:i64)->Result<(),CacheError>{self.advance(block,now)?;self.entries.insert(id,now);self.order.push_back((id,now));self.blooms[self.active].insert(&id);while self.entries.len()>self.config.maximum_entries{if let Some((old,stamp))=self.order.pop_front(){if self.entries.get(&old)==Some(&stamp){self.entries.remove(&old);}}}Ok(())}
 pub fn might_contain(&mut self,id:&Hash32,now:i64)->Result<bool,CacheError>{self.expire(now)?;Ok(self.blooms[0].contains(id)||self.blooms[1].contains(id))}
 pub fn contains_recent(&mut self,id:&Hash32,now:i64)->Result<bool,CacheError>{self.expire(now)?;Ok(self.entries.contains_key(id))}
 #[must_use]pub fn len(&self)->usize{self.entries.len()}
 pub fn remove(&mut self,id:&Hash32)->bool{self.entries.remove(id).is_some()}
 pub fn clear(&mut self){self.entries.clear();self.order.clear();self.blooms=[Bloom::new(self.config.bloom_bits),Bloom::new(self.config.bloom_bits)];self.active=0;self.filter_start_block=None;self.last_now=None;self.last_block=None;}
 fn advance(&mut self,block:i64,now:i64)->Result<(),CacheError>{if let Some(p)=self.last_block{if block<p{return Err(CacheError::BlockReversal{previous:p,now:block})}}self.last_block=Some(block);self.expire(now)?;match self.filter_start_block{None=>self.filter_start_block=Some(block),Some(start) if block-start>self.config.bloom_blocks=>{self.active^=1;self.blooms[self.active]=Bloom::new(self.config.bloom_bits);self.filter_start_block=Some(block)},_=>{}}Ok(())}
 fn expire(&mut self,now:i64)->Result<(),CacheError>{if let Some(p)=self.last_now{if now<p{return Err(CacheError::TimeReversal{previous:p,now})}}self.last_now=Some(now);while let Some((id,stamp))=self.order.front().copied(){if now-stamp<self.config.ttl_millis{break}self.order.pop_front();if self.entries.get(&id)==Some(&stamp){self.entries.remove(&id);}}Ok(())}
}
