use tron_primitives::{BlockId, Hash32};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractEvent {
    pub block_id: BlockId,
    pub block_number: i64,
    pub transaction_id: Hash32,
    pub transaction_index: usize,
    pub removed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockEvent {
    pub block_id: BlockId,
    pub block_number: i64,
    pub removed: bool,
}

/// Synchronous seam consumed by C025. Implementations must return before the
/// switch continues; queueing or asynchronous delivery belongs outside execution.
/// As in Java's plugin loader boundary, delivery failures are contained by the
/// sink and are not allowed to abort or roll back an already-mutated fork state.
pub trait EventSink {
    fn contract(&mut self, event: ContractEvent);
    fn block(&mut self, event: BlockEvent);
}

impl EventSink for () {
    fn contract(&mut self, _: ContractEvent) {}
    fn block(&mut self, _: BlockEvent) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilterEvent {
    Block { block_id: BlockId, block_number: i64 },
    Logs { block_id: BlockId, block_number: i64, removed: bool },
}

/// Synchronous JSON-RPC filter callback seam. Removed logs are emitted while
/// the old block is still HEAD. Forward block then logs filters are emitted
/// oldest-first only after the complete replacement branch has committed.
/// Implementations contain downstream delivery errors at this boundary.
pub trait FilterSink {
    fn filter(&mut self, event: FilterEvent);
}

impl FilterSink for () {
    fn filter(&mut self, _: FilterEvent) {}
}
