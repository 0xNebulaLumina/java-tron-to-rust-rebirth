use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

pub const MAX_CHAIN_SUMMARY: usize = 30;
pub const SYNC_BATCH: usize = 2_000;
pub const MAX_CHAIN_INVENTORY: usize = SYNC_BATCH + 1;
pub const MAX_PENDING_BLOCKS: usize = 500;
pub const MAX_BLOCKS_PER_PEER: usize = 100;
pub const SYNC_REQUEST_TIMEOUT_MS: i64 = 5_000;
pub const SYNC_BLOCK_ID_BYTES: usize = 40;
pub const MAX_PENDING_BYTES: usize = MAX_PENDING_BLOCKS * SYNC_BLOCK_ID_BYTES;
pub const MAX_BLOCK_BYTES_PER_PEER: usize = MAX_BLOCKS_PER_PEER * SYNC_BLOCK_ID_BYTES;
pub const MAX_OUTSTANDING_CHAIN_REQUESTS: usize = 30;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SyncBlockId { pub hash: [u8; 32], pub number: i64 }
impl SyncBlockId { pub const fn new(hash:[u8;32],number:i64)->Self{Self{hash,number}} }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncBlockChain { pub ids: Vec<SyncBlockId> }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainInventory { pub ids: Vec<SyncBlockId>, pub remain: i64 }

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum SyncError {
    #[error("chain summary is empty")] EmptySummary,
    #[error("chain summary exceeds 30 entries")] SummaryTooLarge,
    #[error("first summary block is not on the main chain")] UnknownFirst,
    #[error("summary regresses behind the last synchronization response")] Regressed,
    #[error("no common block exists")] NoCommonBlock,
    #[error("chain inventory was not requested")] NotRequested,
    #[error("chain inventory is empty")] EmptyInventory,
    #[error("chain inventory exceeds 2001 entries")] InventoryTooLarge,
    #[error("non-final inventory is shorter than 2000 entries")] ShortInventory,
    #[error("negative remaining block count")] NegativeRemain,
    #[error("chain inventory is not consecutive")] NonConsecutive,
    #[error("inventory does not begin at a requested summary block")] UnlinkedInventory,
    #[error("inventory exceeds the permitted future height")] FutureInventory,
    #[error("sync block was not requested from this peer")] UnrequestedBlock,
    #[error("sync block response arrived out of order")] OutOfOrder,
    #[error("global pending block limit reached")] GlobalPendingLimit,
    #[error("peer pending block limit reached")] PeerPendingLimit,
    #[error("chain inventory response token is absent or already consumed")]
    InvalidRequestToken,
    #[error("global queued sync byte limit reached")]
    GlobalByteLimit,
    #[error("peer queued sync byte limit reached")]
    PeerByteLimit,
    #[error("global outstanding chain request limit reached")]
    ChainRequestLimit,
}

/// Java `SyncService`: start at the lowest retained canonical block and repeatedly
/// advance by `(real_high - low + 2) / 2`, ending at the current/fetched tip.
pub fn sparse_chain_summary<F>(mut low:i64, high:i64, mut id_at:F)->Vec<SyncBlockId>
where F:FnMut(i64)->Option<SyncBlockId>{
    if high<low{return Vec::new()}
    let mut summary=Vec::new();
    while low<=high && summary.len()<MAX_CHAIN_SUMMARY {if let Some(id)=id_at(low){summary.push(id)}let advance=(high-low+2)/2;if advance<=0{break}low=low.saturating_add(advance)}
    summary
}

pub fn common_block<F>(summary:&[SyncBlockId],mut on_main:F)->Option<SyncBlockId>
where F:FnMut(&SyncBlockId)->bool { summary.iter().rev().find(|id|on_main(id)).cloned() }

pub fn answer_sync_request<F>(request:&SyncBlockChain, head:i64, previous_last:Option<i64>, mut on_main:F, mut id_at:impl FnMut(i64)->Option<SyncBlockId>)->Result<ChainInventory,SyncError>
where F:FnMut(&SyncBlockId)->bool {
    if request.ids.is_empty(){return Err(SyncError::EmptySummary)}
    if request.ids.len()>MAX_CHAIN_SUMMARY{return Err(SyncError::SummaryTooLarge)}
    if !on_main(&request.ids[0]){return Err(SyncError::UnknownFirst)}
    let last=request.ids.last().expect("nonempty").number;
    if previous_last.is_some_and(|n|n>last){return Err(SyncError::Regressed)}
    let common=common_block(&request.ids,&mut on_main).ok_or(SyncError::NoCommonBlock)?;
    let end=head.min(common.number.saturating_add(SYNC_BATCH as i64));
    let ids=(common.number..=end).map(&mut id_at).collect::<Option<Vec<_>>>().ok_or(SyncError::NoCommonBlock)?;
    Ok(ChainInventory{remain:head.saturating_sub(end),ids})
}

pub fn validate_chain_inventory(inv:&ChainInventory, requested:&SyncBlockChain, max_future:i64)->Result<(),SyncError>{
    if inv.ids.is_empty(){return Err(SyncError::EmptyInventory)}
    if inv.ids.len()>MAX_CHAIN_INVENTORY{return Err(SyncError::InventoryTooLarge)}
    if inv.remain<0{return Err(SyncError::NegativeRemain)}
    if inv.remain!=0 && inv.ids.len()<SYNC_BATCH{return Err(SyncError::ShortInventory)}
    if inv.ids.windows(2).any(|w|w[1].number!=w[0].number+1){return Err(SyncError::NonConsecutive)}
    if !requested.ids.contains(&inv.ids[0]){return Err(SyncError::UnlinkedInventory)}
    if inv.ids.last().unwrap().number.saturating_add(inv.remain)>max_future{return Err(SyncError::FutureInventory)}
    Ok(())
}

#[derive(Clone,Copy,Debug,PartialEq,Eq,Hash)]
pub struct ChainRequestToken(u64);

#[derive(Clone,Copy,Debug)]
pub struct SyncLimits {
    pub global_count: usize,
    pub peer_count: usize,
    pub global_bytes: usize,
    pub peer_bytes: usize,
}
impl Default for SyncLimits {
    fn default() -> Self { Self { global_count: MAX_PENDING_BLOCKS, peer_count: MAX_BLOCKS_PER_PEER, global_bytes: MAX_PENDING_BYTES, peer_bytes: MAX_BLOCK_BYTES_PER_PEER } }
}

#[derive(Clone,Debug)]
pub struct SyncCoordinator {
    queues:HashMap<SocketAddr,VecDeque<SyncBlockId>>,
    requested:HashMap<SyncBlockId,(SocketAddr,i64)>,
    in_process:HashMap<SyncBlockId,SocketAddr>,
    chain_requests:HashMap<SocketAddr,ChainRequestToken>,
    next_token:u64,
    limits:SyncLimits,
}
impl Default for SyncCoordinator { fn default()->Self { Self::with_limits(SyncLimits::default()) } }
impl SyncCoordinator {
    pub fn with_limits(limits:SyncLimits)->Self { Self { queues:HashMap::new(), requested:HashMap::new(), in_process:HashMap::new(), chain_requests:HashMap::new(), next_token:0, limits } }
    pub fn issue_chain_request(&mut self,peer:SocketAddr)->Result<ChainRequestToken,SyncError> {
        if !self.chain_requests.contains_key(&peer) && self.chain_requests.len() >= MAX_OUTSTANDING_CHAIN_REQUESTS { return Err(SyncError::ChainRequestLimit); }
        self.next_token=self.next_token.wrapping_add(1);
        let token=ChainRequestToken(self.next_token);
        self.chain_requests.insert(peer,token);
        Ok(token)
    }
    pub fn install_inventory_for_request(&mut self,peer:SocketAddr,token:ChainRequestToken,inv:&ChainInventory,known:impl Fn(&SyncBlockId)->bool)->Result<(),SyncError>{
        if self.chain_requests.get(&peer)!=Some(&token){return Err(SyncError::InvalidRequestToken)}
        self.chain_requests.remove(&peer);
        self.install_inventory(peer,inv,known)
    }
    pub fn install_inventory(&mut self,peer:SocketAddr,inv:&ChainInventory,known:impl Fn(&SyncBlockId)->bool)->Result<(),SyncError>{
        let additions:Vec<_>=inv.ids.iter().skip(1).filter(|id|!known(id)&&!self.contains(id)).cloned().collect();
        let (global_count,global_bytes)=self.global_usage(); let (peer_count,peer_bytes)=self.peer_usage(peer);
        let add_count=additions.len(); let add_bytes=add_count.saturating_mul(SYNC_BLOCK_ID_BYTES);
        if global_count.saturating_add(add_count)>self.limits.global_count{return Err(SyncError::GlobalPendingLimit)}
        if global_bytes.saturating_add(add_bytes)>self.limits.global_bytes{return Err(SyncError::GlobalByteLimit)}
        if peer_count.saturating_add(add_count)>self.limits.peer_count{return Err(SyncError::PeerPendingLimit)}
        if peer_bytes.saturating_add(add_bytes)>self.limits.peer_bytes{return Err(SyncError::PeerByteLimit)}
        self.queues.entry(peer).or_default().extend(additions); Ok(())
    }
    pub fn next_batch(&mut self,peer:SocketAddr,now_ms:i64)->Result<Vec<SyncBlockId>,SyncError>{
        let requested_count=self.requested.values().filter(|(p,_)|*p==peer).count();
        let capacity=self.limits.peer_count.saturating_sub(requested_count+self.in_process.values().filter(|p|**p==peer).count());
        let q=self.queues.entry(peer).or_default(); let mut out=Vec::new();
        while out.len()<capacity {let Some(id)=q.pop_front()else{break}; self.requested.insert(id.clone(),(peer,now_ms)); out.push(id)}
        Ok(out)
    }
    pub fn receive(&mut self,peer:SocketAddr,id:&SyncBlockId)->Result<(),SyncError>{
        let Some((owner,_))=self.requested.get(id)else{return Err(SyncError::UnrequestedBlock)};
        if *owner!=peer{return Err(SyncError::UnrequestedBlock)}
        let lowest=self.requested.iter().filter(|(_, (p,_))|*p==peer).map(|(id,_)|id.number).min();
        if lowest!=Some(id.number){return Err(SyncError::OutOfOrder)}
        self.requested.remove(id); self.in_process.insert(id.clone(),peer); Ok(())
    }
    pub fn applied(&mut self,id:&SyncBlockId){self.in_process.remove(id);}
    pub fn retry_expired(&mut self,now_ms:i64)->Vec<SyncBlockId>{
        let mut expired:Vec<_>=self.requested.iter().filter(|(_,(_,at))|now_ms.saturating_sub(*at)>=SYNC_REQUEST_TIMEOUT_MS).map(|(id,(p,_))|(id.clone(),*p)).collect();
        expired.sort_by_key(|(id,peer)|(id.number,*peer));
        for (id,peer) in expired.iter().rev() {self.requested.remove(id);self.queues.entry(*peer).or_default().push_front(id.clone())}
        expired.into_iter().map(|(id,_)|id).collect()
    }
    pub fn disconnect(&mut self,peer:SocketAddr){self.chain_requests.remove(&peer);self.queues.remove(&peer);self.requested.retain(|_,(owner,_)|*owner!=peer);self.in_process.retain(|_,owner|*owner!=peer);}
    pub fn pending(&self)->usize{self.global_usage().0}
    pub fn usage(&self,peer:SocketAddr)->((usize,usize),(usize,usize)){(self.peer_usage(peer),self.global_usage())}
    pub fn outstanding_chain_requests(&self)->usize{self.chain_requests.len()}
    fn contains(&self,id:&SyncBlockId)->bool{self.queues.values().any(|q|q.contains(id))||self.requested.contains_key(id)||self.in_process.contains_key(id)}
    fn peer_usage(&self,peer:SocketAddr)->(usize,usize){let count=self.queues.get(&peer).map_or(0,VecDeque::len)+self.requested.values().filter(|(p,_)|*p==peer).count()+self.in_process.values().filter(|p|**p==peer).count();(count,count.saturating_mul(SYNC_BLOCK_ID_BYTES))}
    fn global_usage(&self)->(usize,usize){let count=self.queues.values().map(VecDeque::len).sum::<usize>()+self.requested.len()+self.in_process.len();(count,count.saturating_mul(SYNC_BLOCK_ID_BYTES))}
}
