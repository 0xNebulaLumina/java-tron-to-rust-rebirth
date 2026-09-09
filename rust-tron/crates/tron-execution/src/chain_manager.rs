use std::{collections::VecDeque, sync::{Arc, Mutex, mpsc::{self, SyncSender}}, thread::JoinHandle};

use tron_primitives::{BlockId, Hash32};
use tron_state::{CheckpointIdentity, CheckpointStack, SessionError};

use crate::{
    AdmissionClock, AdmissionOrigin, BlockApplyError, BlockApplyHooks, BlockConsensus, BlockEvent,
    BlockManager, BroadcastResult, ContractEvent, EventSink, FilterEvent, FilterSink, ForkManager,
    ForkSwitchError, PendingPool, PendingTransaction, ProcessContext, RawBlock, RawWireTransaction,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainManagerError {
    ReplicaReadOnly,
    Decode(String),
    Block(BlockApplyError),
    Fork(ForkSwitchError),
    State(String),
    Persistence(String),
    Restore { original: String, restoration: String },
}
impl core::fmt::Display for ChainManagerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "chain manager error: {self:?}") }
}
impl std::error::Error for ChainManagerError {}
impl From<BlockApplyError> for ChainManagerError { fn from(value: BlockApplyError) -> Self { Self::Block(value) } }
impl From<ForkSwitchError> for ChainManagerError { fn from(value: ForkSwitchError) -> Self { Self::Fork(value) } }
impl From<SessionError> for ChainManagerError { fn from(value: SessionError) -> Self { Self::State(value.to_string()) } }

#[derive(Default)]
struct BufferedEvents { contracts: Vec<ContractEvent>, blocks: Vec<BlockEvent> }
impl EventSink for BufferedEvents {
    fn contract(&mut self, event: ContractEvent) { self.contracts.push(event); }
    fn block(&mut self, event: BlockEvent) { self.blocks.push(event); }
}
#[derive(Default)]
struct BufferedFilters(Vec<FilterEvent>);
impl FilterSink for BufferedFilters { fn filter(&mut self, event: FilterEvent) { self.0.push(event); } }

pub struct CanonicalChainManager<C, H, E, F> {
    pub blocks: BlockManager<C, H>,
    pending: Option<PendingPool<RawWireTransaction>>,
    checkpoints: CheckpointStack,
    events: E,
    filters: F,
}

impl<C: BlockConsensus, H: BlockApplyHooks, E: EventSink, F: FilterSink> CanonicalChainManager<C, H, E, F> {
    pub fn new_full(blocks: BlockManager<C, H>, pending: PendingPool<RawWireTransaction>, checkpoints: CheckpointStack, events: E, filters: F) -> Self {
        Self { blocks, pending: Some(pending), checkpoints, events, filters }
    }

    pub fn new_replica(blocks: BlockManager<C, H>, checkpoints: CheckpointStack, events: E, filters: F) -> Self {
        Self { blocks, pending: None, checkpoints, events, filters }
    }

    pub fn broadcast_raw(&mut self, raw: impl AsRef<[u8]>, received_at: i64, smart: bool) -> Result<BroadcastResult, ChainManagerError> {
        let transaction = RawWireTransaction::decode(raw.as_ref().to_vec()).map_err(|error| ChainManagerError::Decode(error.to_string()))?;
        let id = transaction.transaction_id(self.blocks.engine);
        let shielded = transaction.message().raw_data.as_ref().is_some_and(|raw| raw.contract.iter().any(|contract| contract.r#type == 51));
        let head = self.blocks.khaos.get_head().ok_or_else(|| ChainManagerError::State("Khaos head is missing".into()))?;
        let header = head.value.raw.message.block_header.as_ref().and_then(|header| header.raw_data.as_ref()).ok_or_else(|| ChainManagerError::State("head raw header is missing".into()))?;
        let context = ProcessContext { origin: AdmissionOrigin::Network, clock: AdmissionClock { head_block_time: header.timestamp, next_block_slot_time: header.timestamp, now: received_at, block_number: header.number, head_slot: header.number }, expected_result: None, block_timestamp: header.timestamp };
        let pending = self.pending.as_mut().ok_or(ChainManagerError::ReplicaReadOnly)?;
        let processor = &mut self.blocks.processor;
        pending.admit(PendingTransaction { id, transaction, received_at, shielded, smart }, received_at, |item, session| {
            processor.process_pending(session, item.transaction.clone(), &context).map(|_| ()).map_err(|error| ChainManagerError::State(error.to_string()))
        })
    }

    pub fn validate_network_block(&mut self, raw: impl AsRef<[u8]>, now_millis: i64) -> Result<BlockId, ChainManagerError> {
        let mut block = RawBlock::decode(raw, self.blocks.limits)?;
        self.blocks.validate_block(&mut block, now_millis).map_err(Into::into)
    }

    pub fn accept_network_block(&mut self, raw: impl AsRef<[u8]>, received_at: i64) -> Result<BlockId, ChainManagerError> {
        let block = RawBlock::decode(raw, self.blocks.limits)?;
        self.accept_block(block, received_at, true)
    }

    pub fn apply_replica_block(&mut self, block: RawBlock, now_millis: i64) -> Result<BlockId, ChainManagerError> {
        if self.pending.is_some() { return Err(ChainManagerError::State("replica apply requires replica mode".into())); }
        self.apply_direct(block, now_millis)
    }

    pub fn pending_snapshot(&self) -> Vec<Hash32> { self.pending.as_ref().map_or_else(Vec::new, PendingPool::pending_ids) }
    pub fn pending_size(&self) -> usize { self.pending.as_ref().map_or(0, PendingPool::len) }

    pub fn pending_transaction(&self, id: &Hash32) -> Option<Vec<u8>> {
        self.pending.as_ref().and_then(|pending| pending.pending_transaction(id)).map(|item| item.transaction.full_bytes().to_vec())
    }

    pub fn known_transaction(&mut self, id: &Hash32) -> bool {
        self.pending.as_ref().is_some_and(|pending| pending.pending_transaction(id).is_some())
            || self.blocks.processor.cache.contains_recent(id, i64::MAX).unwrap_or(false)
            || self.blocks.sessions.read_view().store(tron_state::StoreKind::Transaction).get(id.as_bytes()).is_some()
    }

    pub fn shutdown(&mut self) -> Result<(), ChainManagerError> {
        if let Some(pending) = self.pending.as_mut() { pending.shutdown()?; }
        self.checkpoints.persist().map_err(|error| ChainManagerError::Persistence(error.to_string()))?;
        Ok(())
    }

    fn accept_block(&mut self, block: RawBlock, received_at: i64, allow_fork: bool) -> Result<BlockId, ChainManagerError> {
        let id = block.block_id(self.blocks.engine)?;
        let raw = block.message.block_header.as_ref().and_then(|header| header.raw_data.as_ref()).ok_or(BlockApplyError::MissingRawHeader)?;
        let head_number = self.blocks.khaos.get_head().ok_or(BlockApplyError::ParentMismatch)?.number;
        let direct = raw.parent_hash.as_slice() == self.blocks.khaos.get_head().expect("checked above").id.as_bytes();
        if direct { return self.apply_direct(block, received_at); }
        if !allow_fork { return Err(BlockApplyError::ParentMismatch.into()); }
        let new_height = raw.number;
        self.blocks.retain_competing_block(block, received_at)?;
        if new_height <= head_number { return Ok(id); }
        self.switch_fork(id, received_at)?;
        Ok(id)
    }

    fn apply_direct(&mut self, block: RawBlock, now: i64) -> Result<BlockId, ChainManagerError> {
        let id = block.block_id(self.blocks.engine)?;
        let cache_before = self.blocks.processor.cache.clone();
        let pending_snapshot = match self.pending.as_mut() { Some(pending) => Some(pending.suspend_for_fork()?), None => None };
        match self.blocks.apply_block(block, now) {
            Ok(applied) => {
                if let Some(pending) = self.pending.as_mut() {
                    pending.resume_after_fork(VecDeque::new(), &mut self.blocks.processor.cache, now)?;
                    Self::replay_pending(&mut self.blocks, pending, false, now)?;
                    pending.finish_fork_requeue();
                }
                if let Err(error) = self.checkpoints.persist() {
                    let restoration = self.rollback_direct(id, cache_before, pending_snapshot, now);
                    return match restoration { Ok(()) => Err(ChainManagerError::Persistence(error.to_string())), Err(restoration) => Err(ChainManagerError::Restore { original: error.to_string(), restoration: restoration.to_string() }) };
                }
                self.publish_applied(applied)?;
                Ok(applied)
            }
            Err(error) => {
                self.blocks.processor.cache = cache_before;
                if let (Some(pending), Some(snapshot)) = (self.pending.as_mut(), pending_snapshot) { pending.restore_after_failed_fork(snapshot)?; Self::replay_pending(&mut self.blocks, pending, true, now)?; }
                Err(error.into())
            }
        }
    }

    fn rollback_direct(&mut self, id: BlockId, cache: crate::TransactionCache, snapshot: Option<crate::ForkPendingSnapshot<RawWireTransaction>>, now: i64) -> Result<(), ChainManagerError> {
        if let Some(pending) = self.pending.as_mut() { pending.discard_fork_rebuild()?; }
        let identity = CheckpointIdentity::new(id.as_bytes().try_into().expect("block ids are 32 bytes"));
        if !self.blocks.sessions.rewind_checkpoint(identity).map_err(|error| ChainManagerError::State(error.to_string()))? { return Err(ChainManagerError::State("applied checkpoint was not rewindable".into())); }
        self.blocks.khaos.remove_blk(&id).map_err(|error| ChainManagerError::State(error.to_string()))?;
        self.blocks.processor.cache = cache;
        if let (Some(pending), Some(snapshot)) = (self.pending.as_mut(), snapshot) { pending.restore_after_failed_fork(snapshot)?; Self::replay_pending(&mut self.blocks, pending, true, now)?; }
        Ok(())
    }

    fn switch_fork(&mut self, new_head: BlockId, now: i64) -> Result<(), ChainManagerError> {
        let pending = self.pending.as_mut().ok_or(ChainManagerError::ReplicaReadOnly)?;
        let mut events = BufferedEvents::default();
        let mut filters = BufferedFilters::default();
        let outcome = ForkManager { blocks: &mut self.blocks, pending, events: &mut events, filters: &mut filters }.switch(new_head, now)?;
        self.checkpoints.persist().map_err(|error| ChainManagerError::Persistence(error.to_string()))?;
        for event in events.contracts { self.events.contract(event); }
        for event in events.blocks { self.events.block(event); }
        for event in filters.0 { self.filters.filter(event); }
        debug_assert_eq!(outcome.new_head, new_head);
        Ok(())
    }

    fn replay_pending(blocks: &mut BlockManager<C, H>, pending: &mut PendingPool<RawWireTransaction>, strict: bool, now: i64) -> Result<(), ChainManagerError> {
        let head = blocks.khaos.get_head().ok_or_else(|| ChainManagerError::State("Khaos head is missing during pending replay".into()))?;
        let raw = head.value.raw.message.block_header.as_ref().and_then(|header| header.raw_data.as_ref()).ok_or_else(|| ChainManagerError::State("head raw header is missing during pending replay".into()))?;
        let context = ProcessContext { origin: AdmissionOrigin::Network, clock: AdmissionClock { head_block_time: raw.timestamp, next_block_slot_time: raw.timestamp, now, block_number: raw.number, head_slot: raw.number }, expected_result: None, block_timestamp: raw.timestamp };
        let processor = &mut blocks.processor;
        pending.replay_speculative(strict, |item, session| { item.transaction.clear_signature_verification_cache(); processor.process_in_session(session, &mut item.transaction, &context).map(|_| ()).map_err(|error| error.to_string()) })?;
        Ok(())
    }

    fn publish_applied(&mut self, id: BlockId) -> Result<(), ChainManagerError> {
        let block = self.blocks.khaos.get_block(&id).ok_or_else(|| ChainManagerError::State("committed block is missing from Khaos".into()))?;
        for (transaction_index, bytes) in block.value.raw.transaction_bytes().enumerate() {
            let transaction = RawWireTransaction::decode(bytes.to_vec()).map_err(|error| ChainManagerError::Decode(error.to_string()))?;
            self.events.contract(ContractEvent { block_id: id, block_number: id.height(), transaction_id: transaction.transaction_id(self.blocks.engine), transaction_index, removed: false });
        }
        self.filters.filter(FilterEvent::Block { block_id: id, block_number: id.height() });
        self.filters.filter(FilterEvent::Logs { block_id: id, block_number: id.height(), removed: false });
        self.events.block(BlockEvent { block_id: id, block_number: id.height(), removed: false });
        Ok(())
    }

}

enum ActorRequest {
    Broadcast { raw: Vec<u8>, received_at: i64, smart: bool, reply: mpsc::Sender<Result<BroadcastResult, ChainManagerError>> },
    ValidateBlock { raw: Vec<u8>, now: i64, reply: mpsc::Sender<Result<BlockId, ChainManagerError>> },
    AcceptBlock { raw: Vec<u8>, received_at: i64, reply: mpsc::Sender<Result<BlockId, ChainManagerError>> },
    ReplicaBlock { block: RawBlock, now: i64, reply: mpsc::Sender<Result<BlockId, ChainManagerError>> },
    Pending { reply: mpsc::Sender<Vec<Hash32>> },
    PendingSize { reply: mpsc::Sender<usize> },
    PendingTransaction { id: Hash32, reply: mpsc::Sender<Option<Vec<u8>>> },
    Known { id: Hash32, reply: mpsc::Sender<bool> },
    Shutdown { reply: mpsc::Sender<Result<(), ChainManagerError>> },
}

#[derive(Clone)]
pub struct ChainActorHandle {
    sender: SyncSender<ActorRequest>,
}

impl ChainActorHandle {
    pub fn broadcast_raw(&self, raw: Vec<u8>, received_at: i64, smart: bool) -> Result<BroadcastResult, ChainManagerError> {
        self.request(|reply| ActorRequest::Broadcast { raw, received_at, smart, reply })?
    }
    pub fn validate_network_block(&self, raw: Vec<u8>, now: i64) -> Result<BlockId, ChainManagerError> {
        self.request(|reply| ActorRequest::ValidateBlock { raw, now, reply })?
    }
    pub fn accept_network_block(&self, raw: Vec<u8>, received_at: i64) -> Result<BlockId, ChainManagerError> {
        self.request(|reply| ActorRequest::AcceptBlock { raw, received_at, reply })?
    }
    pub fn apply_replica_block(&self, block: RawBlock, now: i64) -> Result<BlockId, ChainManagerError> {
        self.request(|reply| ActorRequest::ReplicaBlock { block, now, reply })?
    }
    pub fn pending_snapshot(&self) -> Result<Vec<Hash32>, ChainManagerError> { self.request(|reply| ActorRequest::Pending { reply }) }
    pub fn pending_size(&self) -> Result<usize, ChainManagerError> { self.request(|reply| ActorRequest::PendingSize { reply }) }
    pub fn pending_ids(&self) -> Result<Vec<Hash32>, ChainManagerError> { self.pending_snapshot() }
    pub fn pending_transaction(&self, id: Hash32) -> Result<Option<Vec<u8>>, ChainManagerError> { self.request(|reply| ActorRequest::PendingTransaction { id, reply }) }
    pub fn known_transaction(&self, id: Hash32) -> Result<bool, ChainManagerError> { self.request(|reply| ActorRequest::Known { id, reply }) }

    pub async fn accept_network_block_async(&self, raw: Vec<u8>, received_at: i64) -> Result<BlockId, ChainManagerError> {
        let handle = self.clone();
        tokio::task::spawn_blocking(move || handle.accept_network_block(raw, received_at)).await.map_err(|error| ChainManagerError::State(error.to_string()))?
    }
    pub async fn broadcast_raw_async(&self, raw: Vec<u8>, received_at: i64, smart: bool) -> Result<BroadcastResult, ChainManagerError> {
        let handle = self.clone();
        tokio::task::spawn_blocking(move || handle.broadcast_raw(raw, received_at, smart)).await.map_err(|error| ChainManagerError::State(error.to_string()))?
    }

    fn request<T>(&self, request: impl FnOnce(mpsc::Sender<T>) -> ActorRequest) -> Result<T, ChainManagerError> {
        let (reply, response) = mpsc::channel();
        self.sender.send(request(reply)).map_err(|_| ChainManagerError::State("execution actor is closed".into()))?;
        response.recv().map_err(|_| ChainManagerError::State("execution actor dropped its response".into()))
    }
}

pub struct ChainActor {
    handle: ChainActorHandle,
    join: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl ChainActor {
    pub fn spawn<C, H, E, F, B>(build: B, capacity: usize) -> Result<Self, ChainManagerError>
    where C: BlockConsensus + 'static, H: BlockApplyHooks + 'static, E: EventSink + 'static, F: FilterSink + 'static,
          B: FnOnce() -> Result<CanonicalChainManager<C, H, E, F>, ChainManagerError> + Send + 'static {
        if capacity == 0 { return Err(ChainManagerError::State("execution actor capacity must be positive".into())); }
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let (initialized, initialization) = mpsc::sync_channel(1);
        let join = std::thread::Builder::new().name("tron-execution".into()).spawn(move || {
            let mut manager = match build() {
                Ok(manager) => { let _ = initialized.send(Ok(())); manager }
                Err(error) => { let _ = initialized.send(Err(error)); return; }
            };
            while let Ok(request) = receiver.recv() {
                match request {
                    ActorRequest::Broadcast { raw, received_at, smart, reply } => { let _ = reply.send(manager.broadcast_raw(raw, received_at, smart)); }
                    ActorRequest::ValidateBlock { raw, now, reply } => { let _ = reply.send(manager.validate_network_block(raw, now)); }
                    ActorRequest::AcceptBlock { raw, received_at, reply } => { let _ = reply.send(manager.accept_network_block(raw, received_at)); }
                    ActorRequest::ReplicaBlock { block, now, reply } => { let _ = reply.send(manager.apply_replica_block(block, now)); }
                    ActorRequest::Pending { reply } => { let _ = reply.send(manager.pending_snapshot()); }
                    ActorRequest::PendingSize { reply } => { let _ = reply.send(manager.pending_size()); }
                    ActorRequest::PendingTransaction { id, reply } => { let _ = reply.send(manager.pending_transaction(&id)); }
                    ActorRequest::Known { id, reply } => { let _ = reply.send(manager.known_transaction(&id)); }
                    ActorRequest::Shutdown { reply } => { let _ = reply.send(manager.shutdown()); break; }
                }
            }
        }).map_err(|error| ChainManagerError::State(error.to_string()))?;
        initialization.recv().map_err(|_| ChainManagerError::State("execution actor exited during initialization".into()))??;
        Ok(Self { handle: ChainActorHandle { sender }, join: Arc::new(Mutex::new(Some(join))) })
    }
    pub fn handle(&self) -> ChainActorHandle { self.handle.clone() }

    pub fn shutdown(self) -> Result<(), ChainManagerError> {
        let result = self.handle.request(|reply| ActorRequest::Shutdown { reply })?;
        if let Some(join) = self.join.lock().map_err(|_| ChainManagerError::State("execution actor join lock poisoned".into()))?.take() {
            join.join().map_err(|_| ChainManagerError::State("execution actor panicked".into()))?;
        }
        result
    }
}
