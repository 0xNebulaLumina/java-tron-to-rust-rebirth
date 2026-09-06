use std::collections::VecDeque;

use tron_primitives::{BlockId, Hash32};
use tron_state::{dynamic, CheckpointIdentity, SessionError, StoreKind};

use crate::{
    AdmissionClock, AdmissionOrigin, BlockApplyError, BlockApplyHooks, BlockConsensus, BlockEvent,
    BlockManager, ContractEvent, EventSink, FilterEvent, FilterSink, ManagedBlock, PendingPool,
    PendingTransaction, ProcessContext, RawWireTransaction,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForkSwitchError {
    State(String),
    Graph(String),
    Apply { block: BlockId, error: BlockApplyError },
    Restore { original: Box<ForkSwitchError>, restoration: String },
}
impl core::fmt::Display for ForkSwitchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "fork switch error: {self:?}") }
}
impl std::error::Error for ForkSwitchError {}
impl From<SessionError> for ForkSwitchError { fn from(value: SessionError) -> Self { Self::State(value.to_string()) } }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkSwitchOutcome {
    pub old_head: BlockId,
    pub new_head: BlockId,
    pub common_ancestor: BlockId,
    pub removed: Vec<BlockId>,
    pub applied: Vec<BlockId>,
    pub popped_transactions: Vec<Hash32>,
}

pub struct ForkManager<'a, C, H, E, F> {
    pub blocks: &'a mut BlockManager<C, H>,
    pub pending: &'a mut PendingPool<RawWireTransaction>,
    pub events: &'a mut E,
    pub filters: &'a mut F,
}

impl<C: BlockConsensus, H: BlockApplyHooks, E: EventSink, F: FilterSink> ForkManager<'_, C, H, E, F> {
    pub fn switch(&mut self, new_head: BlockId, now: i64) -> Result<ForkSwitchOutcome, ForkSwitchError> {
        let old_head = self.canonical_head()?;
        let (new_nodes, old_nodes) = match self.blocks.khaos.get_branch(&new_head, &old_head) {
            Ok(branches) => branches,
            Err(error) => {
                self.remove_bad_branch(new_head);
                return Err(ForkSwitchError::Graph(error.to_string()));
            }
        };
        if new_nodes.is_empty() { return Ok(ForkSwitchOutcome { old_head, new_head: old_head, common_ancestor: old_head, removed: Vec::new(), applied: Vec::new(), popped_transactions: Vec::new() }); }
        let ancestor = new_nodes.last().and_then(|node| node.parent()).ok_or_else(|| ForkSwitchError::Graph("replacement branch has no retained ancestor".into()))?.id();
        let mut new_branch: Vec<ManagedBlock> = new_nodes.iter().rev().map(|node| node.block().value.clone()).collect();
        let old_branch: Vec<ManagedBlock> = old_nodes.iter().rev().map(|node| node.block().value.clone()).collect();
        let old_head_first: Vec<ManagedBlock> = old_nodes.iter().map(|node| node.block().value.clone()).collect();

        let mut abandoned = VecDeque::new();
        let mut popped_ids = Vec::new();
        for block in &old_head_first { self.collect_transactions(block, &mut abandoned, &mut popped_ids)?; }
        self.blocks.khaos.set_head(&old_head).map_err(|error| ForkSwitchError::Graph(error.to_string()))?;
        let pending_snapshot = self.pending.suspend_for_fork()?;
        let cache_before = self.blocks.processor.cache.clone();
        self.blocks.processor.cache.clear();
        for block in &mut new_branch { block.raw.clear_signature_verification_cache(); }
        let mut popped_count = 0usize;
        for block in &old_head_first {
            self.publish_removed(block)?;
            let popped = self.blocks.sessions.rewind_checkpoint(CheckpointIdentity::new(block.id.as_bytes().try_into().expect("block ids are 32 bytes"))).map_err(|error| ForkSwitchError::State(error.to_string()));
            if !matches!(popped, Ok(true)) {
                let original = popped.err().unwrap_or_else(|| ForkSwitchError::State("checkpoint stack ended before common ancestor".into()));
                let base = self.blocks.khaos.get_head().map(|head| head.id).unwrap_or(old_head);
                let replay: Vec<ManagedBlock> = old_head_first[..popped_count].iter().rev().cloned().collect();
                let restoration = self.restore(old_head, base, &new_branch, &replay, 0, cache_before, pending_snapshot, now);
                if restoration.is_ok() { self.publish_reapplied(&old_head_first[..=popped_count].iter().rev().cloned().collect::<Vec<_>>())?; }
                return match restoration { Ok(()) => Err(original), Err(error) => Err(ForkSwitchError::Restore { original: Box::new(original), restoration: error.to_string() }) };
            }
            if !self.blocks.khaos.pop() {
                let original = ForkSwitchError::Graph("Khaos head ended before common ancestor".into());
                let base = self.blocks.khaos.get_head().map(|head| head.id).unwrap_or(old_head);
                let replay: Vec<ManagedBlock> = old_head_first[..=popped_count].iter().rev().cloned().collect();
                let restoration = self.restore(old_head, base, &new_branch, &replay, 0, cache_before, pending_snapshot, now);
                if restoration.is_ok() { self.publish_reapplied(&replay)?; }
                return match restoration { Ok(()) => Err(original), Err(error) => Err(ForkSwitchError::Restore { original: Box::new(original), restoration: error.to_string() }) };
            }
            popped_count += 1;
        }
        self.blocks.khaos.set_head(&ancestor).map_err(|error| ForkSwitchError::Graph(error.to_string()))?;

        let mut applied = Vec::with_capacity(new_branch.len());
        let replay_result = (|| {
            for block in &new_branch {
                let id = block.id;
                self.blocks.apply_fork_block(block.raw.clone(), block.received_at).map_err(|error| ForkSwitchError::Apply { block: id, error })?;
                applied.push(id);
                
            }
            Ok::<(), ForkSwitchError>(())
        })();

        if let Err(original) = replay_result {
            let restoration = self.restore(old_head, ancestor, &new_branch, &old_branch, applied.len(), cache_before, pending_snapshot, now);
            if restoration.is_ok() { self.publish_reapplied(&old_branch)?; }
            return match restoration {
                Ok(()) => Err(original),
                Err(error) => Err(ForkSwitchError::Restore { original: Box::new(original), restoration: error.to_string() }),
            };
        }

        if let Err(error) = self.pending.resume_after_fork(abandoned, &mut self.blocks.processor.cache, now) {
            let original = ForkSwitchError::State(error.to_string());
            let discard = self.pending.discard_fork_rebuild().err().map(|error| error.to_string());
            if discard.is_some() { self.pending.force_discard_fork_rebuild(); }
            let restoration = self.restore(old_head, ancestor, &new_branch, &old_branch, applied.len(), cache_before, pending_snapshot, now);
            if restoration.is_ok() { self.publish_reapplied(&old_branch)?; }
            return Err(Self::pending_failure(original, discard, restoration));
        }
        if let Err(original) = self.replay_pending(false, now) {
            let discard = self.pending.discard_fork_rebuild().err().map(|error| error.to_string());
            if discard.is_some() { self.pending.force_discard_fork_rebuild(); }
            let restoration = self.restore(old_head, ancestor, &new_branch, &old_branch, applied.len(), cache_before, pending_snapshot, now);
            if restoration.is_ok() { self.publish_reapplied(&old_branch)?; }
            return Err(Self::pending_failure(original, discard, restoration));
        }
        self.pending.finish_fork_requeue();
        self.publish_reapplied(&new_branch)?;
        Ok(ForkSwitchOutcome { old_head, new_head, common_ancestor: ancestor, removed: old_head_first.iter().map(|block| block.id).collect(), applied, popped_transactions: popped_ids })
    }

    fn pending_failure(
        original: ForkSwitchError,
        discard: Option<String>,
        restoration: Result<(), ForkSwitchError>,
    ) -> ForkSwitchError {
        match (discard, restoration) {
            (None, Ok(())) => original,
            (Some(discard), Ok(())) => ForkSwitchError::Restore { original: Box::new(original), restoration: format!("pending discard failed: {discard}") },
            (None, Err(restoration)) => ForkSwitchError::Restore { original: Box::new(original), restoration: restoration.to_string() },
            (Some(discard), Err(restoration)) => ForkSwitchError::Restore { original: Box::new(original), restoration: format!("pending discard failed: {discard}; restoration failed: {restoration}") },
        }
    }

    fn restore(
        &mut self,
        old_head: BlockId,
        ancestor: BlockId,
        new_branch: &[ManagedBlock],
        old_branch: &[ManagedBlock],
        applied_count: usize,
        cache_before: crate::TransactionCache,
        pending_snapshot: crate::ForkPendingSnapshot<RawWireTransaction>,
        now: i64,
    ) -> Result<(), ForkSwitchError> {
        for block in new_branch[..applied_count].iter().rev() {
            if !self.blocks.sessions.rewind_checkpoint(CheckpointIdentity::new(block.id.as_bytes().try_into().expect("block ids are 32 bytes"))).map_err(|error| ForkSwitchError::State(error.to_string()))? {
                return Err(ForkSwitchError::State("checkpoint stack ended while retracting failed branch".into()));
            }
            if !self.blocks.khaos.pop() {
                return Err(ForkSwitchError::Graph("Khaos head ended while retracting failed branch".into()));
            }
        }
        for block in new_branch { let _ = self.blocks.khaos.remove_blk(&block.id); }
        self.blocks.khaos.set_head(&ancestor).map_err(|error| ForkSwitchError::Graph(error.to_string()))?;
        self.blocks.processor.cache.clear();
        for block in old_branch {
            let mut raw = block.raw.clone();
            raw.clear_signature_verification_cache();
            self.blocks.apply_fork_block(raw, block.received_at).map_err(|error| ForkSwitchError::Apply { block: block.id, error })?;
        }
        self.blocks.khaos.set_head(&old_head).map_err(|error| ForkSwitchError::Graph(error.to_string()))?;
        self.blocks.processor.cache = cache_before;
        self.pending.restore_after_failed_fork(pending_snapshot)?;
        self.replay_pending(true, now)?;
        Ok(())
    }

    fn canonical_head(&self) -> Result<BlockId, ForkSwitchError> {
        let key = dynamic::key("LATEST_BLOCK_HEADER_HASH").ok_or_else(|| ForkSwitchError::State("latest block hash property is unknown".into()))?;
        let bytes = self.blocks.sessions.read_view().store(StoreKind::DynamicProperties).get(key).ok_or_else(|| ForkSwitchError::State("latest block hash property is missing".into()))?;
        let hash = Hash32::try_from(bytes.as_slice()).map_err(|error| ForkSwitchError::State(error.to_string()))?;
        Ok(BlockId::from_overlaid_hash(hash))
    }

    fn collect_transactions(&self, block: &ManagedBlock, output: &mut VecDeque<PendingTransaction<RawWireTransaction>>, ids: &mut Vec<Hash32>) -> Result<(), ForkSwitchError> {
        for bytes in block.raw.transaction_bytes() {
            let transaction = RawWireTransaction::decode(bytes.to_vec()).map_err(|error| ForkSwitchError::State(error.to_string()))?;
            let id = transaction.transaction_id(self.blocks.engine);
            let shielded = transaction.message().raw_data.as_ref().is_some_and(|raw| raw.contract.iter().any(|contract| contract.r#type == 51));
            ids.push(id);
            output.push_back(PendingTransaction { id, transaction, received_at: block.received_at, shielded, smart: false });
        }
        Ok(())
    }
    fn replay_pending(&mut self, strict: bool, now: i64) -> Result<(), ForkSwitchError> {
        let head = self.blocks.khaos.get_head().ok_or_else(|| ForkSwitchError::Graph("Khaos head is missing during pending replay".into()))?;
        let raw = head.value.raw.message.block_header.as_ref().and_then(|header| header.raw_data.as_ref()).ok_or_else(|| ForkSwitchError::State("head raw header is missing during pending replay".into()))?;
        let context = ProcessContext {
            origin: AdmissionOrigin::Network,
            clock: AdmissionClock { head_block_time: raw.timestamp, next_block_slot_time: raw.timestamp, now, block_number: raw.number, head_slot: raw.number },
            expected_result: None,
            block_timestamp: raw.timestamp,
        };
        let processor = &mut self.blocks.processor;
        self.pending.replay_speculative(strict, |item, session| {
            item.transaction.clear_signature_verification_cache();
            processor.process_in_session(session, &mut item.transaction, &context).map(|_| ()).map_err(|error| error.to_string())
        }).map_err(|error| ForkSwitchError::State(error.to_string()))
    }



    fn publish_removed(&mut self, block: &ManagedBlock) -> Result<(), ForkSwitchError> {
        for (transaction_index, bytes) in block.raw.transaction_bytes().enumerate() {
            let tx = RawWireTransaction::decode(bytes.to_vec()).map_err(|error| ForkSwitchError::State(error.to_string()))?;
            self.events.contract(ContractEvent { block_id: block.id, block_number: block.id.height(), transaction_id: tx.transaction_id(self.blocks.engine), transaction_index, removed: true });
        }
        self.events.block(BlockEvent { block_id: block.id, block_number: block.id.height(), removed: true });
        self.filters.filter(FilterEvent::Logs { block_id: block.id, block_number: block.id.height(), removed: true });
        Ok(())
    }

    fn publish_reapplied(&mut self, branch: &[ManagedBlock]) -> Result<(), ForkSwitchError> {
        for block in branch {
            for (transaction_index, bytes) in block.raw.transaction_bytes().enumerate() {
                let tx = RawWireTransaction::decode(bytes.to_vec()).map_err(|error| ForkSwitchError::State(error.to_string()))?;
                self.events.contract(ContractEvent { block_id: block.id, block_number: block.id.height(), transaction_id: tx.transaction_id(self.blocks.engine), transaction_index, removed: false });
            }
            self.filters.filter(FilterEvent::Block { block_id: block.id, block_number: block.id.height() });
            self.filters.filter(FilterEvent::Logs { block_id: block.id, block_number: block.id.height(), removed: false });
            self.events.block(BlockEvent { block_id: block.id, block_number: block.id.height(), removed: false });
        }
        Ok(())
    }

    fn remove_bad_branch(&mut self, mut id: BlockId) {
        loop {
            let parent = self.blocks.khaos.get_block(&id).map(|block| BlockId::from_overlaid_hash(block.parent_id));
            if self.blocks.khaos.remove_blk(&id).is_err() { break; }
            let Some(next) = parent else { break };
            id = next;
        }
    }
}
