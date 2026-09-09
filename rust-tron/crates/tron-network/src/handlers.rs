use std::collections::{HashSet, VecDeque};
use prost::Message;
use sha2::{Digest, Sha256};
use tron_consensus::pbft::{Effect as PbftEffect, PbftContext, PbftError, PbftSidecar, SignedMessage};
use tron_execution::{BlockApplyError, BlockLimits, RawBlock};
use tron_protocol::protocol::{PbftCommitResult, Transactions};
use crate::peer::{BlockKey, InventoryItem, PeerConnection};

pub const MAX_NETWORK_BLOCK_BYTES: usize = 2_001_000;
pub const BLOCK_FUTURE_LIMIT_MS: i64 = 3_000;
pub const TRANSACTION_SIGNATURE_MIN: usize = 65;
pub const TRANSACTION_SIGNATURE_MAX: usize = 68;
pub const PBFT_DEDUP_LIMIT: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub enum HandlerDisconnect { BadMessage, BadTransaction, BadBlock }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandlerError {
    Malformed(&'static str), BlockTooLarge{size:usize,max:usize}, FutureBlock{timestamp:i64,now:i64},
    UnrequestedTransaction([u8;32]), DuplicateTransaction([u8;32]), MissingContract([u8;32]), BadSignatureLength{transaction:[u8;32],length:usize},
    UnrequestedBlock(BlockKey), InvalidBlock(String), Pbft(String), QueueFull,
}
impl HandlerError { pub const fn disconnect(&self)->HandlerDisconnect { match self { Self::MissingContract(_)|Self::BadSignatureLength{..}=>HandlerDisconnect::BadTransaction, Self::InvalidBlock(_)=>HandlerDisconnect::BadBlock, _=>HandlerDisconnect::BadMessage } } }
impl core::fmt::Display for HandlerError { fn fmt(&self,f:&mut core::fmt::Formatter<'_>)->core::fmt::Result{write!(f,"{self:?}")} } impl std::error::Error for HandlerError{}
pub fn validate_block_time(timestamp:i64,now:i64)->Result<(),HandlerError>{if timestamp.saturating_sub(now)>=BLOCK_FUTURE_LIMIT_MS{Err(HandlerError::FutureBlock{timestamp,now})}else{Ok(())}}

#[derive(Clone, Copy, Debug)]
struct RateBucket { permits_per_second: f64, stored: f64, last_ms: i64 }

#[derive(Clone, Debug, Default)]
pub struct P2pRateLimiter { buckets: std::collections::HashMap<u8, RateBucket> }

impl P2pRateLimiter {
    pub fn register(&mut self, message_type: u8, permits_per_second: f64, now: i64) {
        self.buckets.insert(message_type, RateBucket { permits_per_second, stored: 1.0, last_ms: now });
    }

    pub fn try_acquire(&mut self, message_type: u8, now: i64) -> bool {
        let Some(bucket) = self.buckets.get_mut(&message_type) else { return true };
        let elapsed = now.saturating_sub(bucket.last_ms).max(0) as f64 / 1_000.0;
        bucket.stored = (bucket.stored + elapsed * bucket.permits_per_second).min(1.0);
        bucket.last_ms = now;
        if bucket.stored < 1.0 { return false }
        bucket.stored -= 1.0;
        true
    }
}


pub trait TransactionSink {
    fn known_transaction(&self,id:&[u8;32])->bool;
    fn process_transaction(&mut self,encoded:Vec<u8>,received_at:i64)->Result<(),String>;
    fn broadcast_transaction(&mut self,encoded:&[u8],except:&PeerConnection);
}

pub struct TransactionHandler { queue:VecDeque<(Vec<u8>,i64)>, capacity:usize, closed:bool }
impl TransactionHandler {
    pub fn new(capacity:usize)->Self{Self{queue:VecDeque::new(),capacity,closed:false}}
    pub fn close(&mut self){self.closed=true;self.queue.clear()}
    pub fn queued(&self)->usize{self.queue.len()}
    pub fn receive(&mut self,peer:&mut PeerConnection,payload:&[u8],now:i64)->Result<usize,HandlerError>{
        if self.closed{return Ok(0)}
        let transactions=Transactions::decode(payload).map_err(|_|HandlerError::Malformed("transactions"))?;
        let transaction_bytes=length_delimited_fields(payload,1).map_err(|_|HandlerError::Malformed("transactions"))?;
        if transaction_bytes.len()!=transactions.transactions.len(){return Err(HandlerError::Malformed("transactions"))}
        let mut seen=HashSet::with_capacity(transactions.transactions.len()); let mut encoded=Vec::with_capacity(transactions.transactions.len());
        for (tx,bytes) in transactions.transactions.into_iter().zip(transaction_bytes) {
            let id=transaction_id_from_wire(bytes).map_err(|_|HandlerError::Malformed("transaction raw_data"))?;
            if !seen.insert(id){return Err(HandlerError::DuplicateTransaction(id))}
            let item=InventoryItem{hash:id,kind:0}; if !peer.adv_requests.contains_key(&item){return Err(HandlerError::UnrequestedTransaction(id))}
            let raw=tx.raw_data.as_ref().ok_or(HandlerError::MissingContract(id))?; if raw.contract.is_empty(){return Err(HandlerError::MissingContract(id))}
            for signature in &tx.signature { if !(TRANSACTION_SIGNATURE_MIN..=TRANSACTION_SIGNATURE_MAX).contains(&signature.len()){return Err(HandlerError::BadSignatureLength{transaction:id,length:signature.len()})} }
            encoded.push((item,bytes.to_vec()));
        }
        if self.queue.len().saturating_add(encoded.len())>self.capacity{return Err(HandlerError::QueueFull)}
        for (item,bytes) in encoded { peer.adv_requests.remove(&item); self.queue.push_back((bytes,now)); }
        Ok(self.queue.len())
    }
    pub fn drain<S:TransactionSink + ?Sized>(&mut self,peer:&PeerConnection,sink:&mut S,maximum:usize)->usize{
        let mut done=0; while done<maximum { let Some((bytes,at))=self.queue.pop_front()else{break}; let Ok(id)=transaction_id_from_wire(&bytes)else{done+=1;continue}; if !sink.known_transaction(&id)&&sink.process_transaction(bytes.clone(),at).is_ok(){sink.broadcast_transaction(&bytes,peer)} done+=1; } done
    }
}
pub fn transaction_id_from_wire(transaction:&[u8])->Result<[u8;32],()> {
    let raw=length_delimited_fields(transaction,1)?;
    if raw.len()!=1{return Err(())}
    Ok(Sha256::digest(raw[0]).into())
}
fn length_delimited_fields(mut bytes:&[u8],wanted:u64)->Result<Vec<&[u8]>,()> {
    let mut found=Vec::new();
    while !bytes.is_empty(){
        let (tag,n)=read_varint(bytes)?;bytes=&bytes[n..];let wire=tag&7;let field=tag>>3;if field==0{return Err(())}
        match wire {
            0=>{let (_,n)=read_varint(bytes)?;bytes=&bytes[n..];}
            1=>{if bytes.len()<8{return Err(())}bytes=&bytes[8..];}
            2=>{let (length,n)=read_varint(bytes)?;bytes=&bytes[n..];let length=usize::try_from(length).map_err(|_|())?;if bytes.len()<length{return Err(())}let value=&bytes[..length];if field==wanted{found.push(value)}bytes=&bytes[length..];}
            5=>{if bytes.len()<4{return Err(())}bytes=&bytes[4..];}
            _=>return Err(()),
        }
    }
    Ok(found)
}
fn read_varint(bytes:&[u8])->Result<(u64,usize),()> {let mut value=0u64;for(index,byte)in bytes.iter().copied().take(10).enumerate(){if index==9&&byte>1{return Err(())}value|=u64::from(byte&0x7f)<<(index*7);if byte&0x80==0{return Ok((value,index+1))}}Err(())}

pub trait BlockSink {
    fn validate_block(&mut self,block:&RawBlock)->Result<(),String>;
    fn has_parent(&self,block:&RawBlock)->bool;
    fn head_number(&self)->i64;
    fn broadcast_block(&mut self,encoded:&[u8],except:&PeerConnection);
    fn process_block(&mut self,block:RawBlock,received_at:i64)->Result<(),String>;
    fn start_sync(&mut self,peer:&PeerConnection);
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)] pub enum BlockDisposition{Sync,IgnoredLow,BroadcastAndProcessed}
pub fn handle_block<S:BlockSink + ?Sized>(peer:&mut PeerConnection,payload:&[u8],now:i64,fast_forward:bool,sink:&mut S)->Result<BlockDisposition,HandlerError>{
    handle_block_with_engine(peer, payload, now, fast_forward, tron_crypto::CryptoEngine::Secp256k1, sink)
}
pub fn handle_block_with_engine<S:BlockSink + ?Sized>(peer:&mut PeerConnection,payload:&[u8],now:i64,fast_forward:bool,engine:tron_crypto::CryptoEngine,sink:&mut S)->Result<BlockDisposition,HandlerError>{
    if payload.len()>MAX_NETWORK_BLOCK_BYTES{return Err(HandlerError::BlockTooLarge{size:payload.len(),max:MAX_NETWORK_BLOCK_BYTES})}
    let mut raw=RawBlock::decode(payload,BlockLimits{max_block_bytes:MAX_NETWORK_BLOCK_BYTES,..BlockLimits::default()}).map_err(map_block)?;
    let header=raw.message.block_header.as_ref().and_then(|h|h.raw_data.as_ref()).ok_or(HandlerError::Malformed("block header"))?;
    validate_block_time(header.timestamp,now)?;
    let id=raw.block_id(engine).map_err(map_block)?; let key=BlockKey{hash:id.as_bytes().to_vec(),number:id.height()}; let inv=InventoryItem{hash:id.hash().as_bytes().try_into().expect("Hash32 is 32 bytes"),kind:1};
    let sync=peer.sync_requested.contains_key(&key); if !fast_forward&&!peer.relay_peer&&!sync&&!peer.adv_requests.contains_key(&inv){return Err(HandlerError::UnrequestedBlock(key))}
    let sanitized=raw.message.encode_to_vec(); raw=RawBlock::decode(&sanitized,BlockLimits{max_block_bytes:MAX_NETWORK_BLOCK_BYTES,..BlockLimits::default()}).map_err(map_block)?;
    if sync {peer.sync_requested.remove(&key);peer.sync_in_process.insert(key);sink.process_block(raw,now).map_err(HandlerError::InvalidBlock)?;return Ok(BlockDisposition::Sync)}
    if peer.relay_peer{peer.remember_spread(inv.clone(),now)} peer.adv_requests.remove(&inv);
    sink.validate_block(&raw).map_err(HandlerError::InvalidBlock)?; if !sink.has_parent(&raw){sink.start_sync(peer);return Ok(BlockDisposition::Sync)} if id.height()<sink.head_number(){return Ok(BlockDisposition::IgnoredLow)}
    sink.broadcast_block(&sanitized,peer); sink.process_block(raw,now).map_err(HandlerError::InvalidBlock)?; peer.block_received_ms=now; Ok(BlockDisposition::BroadcastAndProcessed)
}
fn map_block(error:BlockApplyError)->HandlerError{HandlerError::InvalidBlock(error.to_string())}
pub struct PbftHandler { seen:VecDeque<[u8;32]>, sidecar:std::sync::Arc<std::sync::Mutex<PbftSidecar>> }
impl PbftHandler {
    pub fn new(sidecar:PbftSidecar)->Self{Self::from_shared(std::sync::Arc::new(std::sync::Mutex::new(sidecar)))}
    pub fn from_shared(sidecar:std::sync::Arc<std::sync::Mutex<PbftSidecar>>)->Self{Self{seen:VecDeque::new(),sidecar}}
    pub fn handle_wire(&mut self,payload:&[u8],context:PbftContext,head:i64,expire_blocks:i64,next_maintenance:i64,maintenance_interval:i64)->Result<Vec<PbftEffect>,HandlerError>{
        let message=SignedMessage::decode(payload).map_err(pbft)?;
        if message.raw.data_type==tron_consensus::pbft::DataType::Block&&head.saturating_sub(message.raw.view_n)>expire_blocks{return Ok(vec![])}
        if message.raw.data_type==tron_consensus::pbft::DataType::Srl&&next_maintenance.saturating_sub(message.raw.epoch)>maintenance_interval.saturating_mul(2){return Ok(vec![])}
        let id:[u8;32]=Sha256::digest(payload).into(); if self.seen.contains(&id){return Ok(vec![])}
        let effects=self.sidecar.lock().map_err(|_|HandlerError::Pbft("sidecar lock poisoned".into()))?.handle(message,context).map_err(pbft)?; self.seen.push_back(id); while self.seen.len()>PBFT_DEDUP_LIMIT{self.seen.pop_front();} Ok(effects)
    }
    pub fn decode_commit(payload:&[u8])->Result<PbftCommitResult,HandlerError>{PbftCommitResult::decode(payload).map_err(|_|HandlerError::Malformed("pbft commit"))}
}
fn pbft(error:PbftError)->HandlerError{HandlerError::Pbft(error.to_string())}
