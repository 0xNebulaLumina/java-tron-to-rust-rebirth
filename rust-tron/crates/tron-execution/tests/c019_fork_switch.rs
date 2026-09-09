use std::{cell::Cell, path::PathBuf, rc::Rc, sync::{Arc, LazyLock, atomic::{AtomicU64, Ordering}}, time::{SystemTime, UNIX_EPOCH}};

use prost::Message;
use tron_crypto::CryptoEngine;
use tron_execution::{
    ActuatorRegistry, BlockApplyError, BlockApplyHooks, BlockConsensus, BlockEvent, BlockLimits,
    BlockManager, CacheConfig, ContractEvent, EventSink, ExecutionConfig, ExecutionRuntimeConfig,
    FilterEvent, FilterSink, ForkManager, ForkSwitchError, ManagedBlock, PendingLimits, PendingPool,
    RawBlock, StateTransactionPipeline, TransactionCache, TransactionProcessor,
};
use tron_primitives::{BlockId, Hash32};
use tron_protocol::protocol::{block_header, Block, BlockHeader};
use tron_state::{dynamic, KhaosBlockData, KhaosDatabase, SessionManager, StateStore, StoreKind};

use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};
#[derive(Clone)]
struct Consensus;
impl BlockConsensus for Consensus {
    fn verify_witness_signature(&self, _: &[u8], signature: &[u8], _: &[u8]) -> bool { signature == [1] }
    fn scheduled_witness(&self, _: i64, _: i64, _: i64) -> Result<Vec<u8>, String> { Ok(vec![0x41; 21]) }
}

struct Hooks { fail_at: Rc<Cell<Option<i64>>> }
impl BlockApplyHooks for Hooks {
    fn process_proposals(&mut self, _: &tron_state::Session, _: i64) -> Result<(), String> {
        Ok(())
    }
    fn update_consensus_views(&mut self, _: &tron_state::Session, _: BlockId, number: i64, _: i64) -> Result<(), String> {
        if self.fail_at.get() == Some(number) { Err("injected apply failure".into()) } else { Ok(()) }
    }
}

#[derive(Default)]
struct Events(Vec<String>);
impl EventSink for Events {
    fn contract(&mut self, event: ContractEvent) { self.0.push(format!("contract:{}:{}", event.block_number, event.removed)); }
    fn block(&mut self, event: BlockEvent) { self.0.push(format!("block:{}:{}", event.block_number, event.removed)); }
}
#[derive(Default)]
struct Filters(Vec<String>);
impl FilterSink for Filters {
    fn filter(&mut self, event: FilterEvent) {
        self.0.push(match event {
            FilterEvent::Block { block_number, .. } => format!("block-filter:{block_number}"),
            FilterEvent::Logs { block_number, removed, .. } => format!("logs:{block_number}:{removed}"),
        });
    }
}

fn raw(parent: BlockId, number: i64, timestamp: i64, valid_signature: bool) -> RawBlock {
    let raw = block_header::Raw {
        timestamp,
        parent_hash: parent.as_bytes().to_vec(),
        number,
        witness_address: vec![0x41; 21],
        tx_trie_root: vec![0; 32],
        ..Default::default()
    };
    RawBlock::decode(Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader { raw_data: Some(raw), witness_signature: vec![u8::from(valid_signature)] }),
    }.encode_to_vec(), BlockLimits::default()).unwrap()
}

fn managed(raw: RawBlock, engine: CryptoEngine, received_at: i64) -> ManagedBlock {
    let id = raw.block_id(engine).unwrap();
    ManagedBlock { raw, id, received_at }
}

struct Fixture {
    manager: BlockManager<Consensus, Hooks>,
    pending: PendingPool<tron_execution::RawWireTransaction>,
    old_head: BlockId,
    new_head: BlockId,
    fail_at: Rc<Cell<Option<i64>>>,
}
static STORE_NONCE: AtomicU64 = AtomicU64::new(0);
fn store() -> StateStore {
    let path = PathBuf::from(std::env::temp_dir()).join(format!("c019-fork-{}-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(), STORE_NONCE.fetch_add(1, Ordering::Relaxed)));
    let requirements = OpenRequirements { identity: StorageIdentity { network: "c019".into(), genesis: "00".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()] };
    StateStore::new(StorageManager::new(requirements).open_store(&path).unwrap())
}

fn runtime_config() -> ExecutionRuntimeConfig {
    static PARAMETERS: LazyLock<Arc<tron_shielded::TronParameters>> = LazyLock::new(|| {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");
        tron_shielded::load_tron_parameters(root.join("sapling-spend.params"), root.join("sapling-output.params")).unwrap()
    });
    ExecutionRuntimeConfig { actuator_registry: Arc::new(ActuatorRegistry::empty()), operation_registry: Arc::new(tron_tvm::OperationRegistry::integration().unwrap()), shielded_parameters: Arc::clone(&PARAMETERS), execution_config: ExecutionConfig::default() }
}


fn fixture(invalid_new_tip: bool) -> Fixture {
    let sessions = SessionManager::new(store());
    let engine = CryptoEngine::Secp256k1;
    let pipeline = StateTransactionPipeline::new(Default::default(), runtime_config());
    let processor = TransactionProcessor::new(sessions.clone(), TransactionCache::new(CacheConfig::default()).unwrap(), pipeline);
    let genesis_raw = raw(BlockId::from_overlaid_hash(Hash32::ZERO), 0, 1_000, true);
    let genesis = managed(genesis_raw, engine, 1_000);
    let mut khaos = KhaosDatabase::new();
    khaos.start(KhaosBlockData::new(genesis.id, Hash32::ZERO, 0, genesis.clone())).unwrap();
    for (name, bytes) in [
        ("LATEST_BLOCK_HEADER_HASH", genesis.id.as_bytes().to_vec()),
        ("LATEST_BLOCK_HEADER_NUMBER", 0_i64.to_be_bytes().to_vec()),
        ("LATEST_BLOCK_HEADER_TIMESTAMP", 1_000_i64.to_be_bytes().to_vec()),
    ] { sessions.durable_store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(), &bytes).unwrap(); }
    let fail_at = Rc::new(Cell::new(None));
    let mut manager = BlockManager { sessions: sessions.clone(), processor, khaos, consensus: Consensus, hooks: Hooks { fail_at: fail_at.clone() }, limits: BlockLimits::default(), engine };
    let old1 = manager.apply_block(raw(genesis.id, 1, 2_000, true), 10_000).unwrap();
    let old2 = manager.apply_block(raw(old1, 2, 3_000, true), 10_000).unwrap();
    let new1 = managed(raw(genesis.id, 1, 2_100, true), engine, 4_000);
    let new2 = managed(raw(new1.id, 2, 3_100, true), engine, 4_100);
    let new3 = managed(raw(new2.id, 3, 4_100, !invalid_new_tip), engine, 4_200);
    for block in [&new1, &new2, &new3] {
        manager.khaos.push(KhaosBlockData::new(block.id, Hash32::try_from(block.raw.message.block_header.as_ref().unwrap().raw_data.as_ref().unwrap().parent_hash.as_slice()).unwrap(), block.id.height(), block.clone())).unwrap();
    }
    let pending = PendingPool::new(sessions, PendingLimits::default()).unwrap();
    Fixture { manager, pending, old_head: old2, new_head: new3.id, fail_at }
}

fn canonical(manager: &BlockManager<Consensus, Hooks>) -> BlockId {
    let bytes = manager.sessions.read_view().store(StoreKind::DynamicProperties).get(dynamic::key("LATEST_BLOCK_HEADER_HASH").unwrap()).unwrap();
    BlockId::from_overlaid_hash(Hash32::try_from(bytes.as_slice()).unwrap())
}
fn state_image(manager: &BlockManager<Consensus, Hooks>) -> Vec<(StoreKind, Vec<(Vec<u8>, Vec<u8>)>)> {
    let view = manager.sessions.read_view();
    StoreKind::ALL.into_iter().map(|kind| (kind, view.store(kind).prefix(&[]))).collect()
}

fn received_at(manager: &BlockManager<Consensus, Hooks>, id: BlockId) -> i64 {
    let bytes = manager.sessions.read_view().store(StoreKind::Common).get(id.as_bytes()).unwrap();
    i64::from_be_bytes(bytes[..8].try_into().unwrap())
}


struct HeadEvents { sessions: SessionManager, seen: Vec<(i64, bool, i64)> }
impl EventSink for HeadEvents {
    fn contract(&mut self, _: ContractEvent) {}
    fn block(&mut self, event: BlockEvent) {
        let bytes=self.sessions.read_view().store(StoreKind::DynamicProperties).get(dynamic::key("LATEST_BLOCK_HEADER_NUMBER").unwrap()).unwrap();
        self.seen.push((event.block_number,event.removed,i64::from_be_bytes(bytes.as_slice().try_into().unwrap())));
    }
}

#[test]
fn removed_callbacks_observe_each_old_block_as_current_head() {
    let mut f=fixture(false);
    let mut events=HeadEvents{sessions:f.manager.sessions.clone(),seen:Vec::new()};
    let mut filters=Filters::default();
    ForkManager{blocks:&mut f.manager,pending:&mut f.pending,events:&mut events,filters:&mut filters}.switch(f.new_head,10_000).unwrap();
    assert_eq!(events.seen,[(2,true,2),(1,true,1),(1,false,3),(2,false,3),(3,false,3)]);
}

#[test]
fn multi_branch_switch_rewinds_head_first_and_replays_oldest_first() {
    let mut f = fixture(false);
    let mut events = Events::default();
    let mut filters = Filters::default();
    let outcome = ForkManager { blocks: &mut f.manager, pending: &mut f.pending, events: &mut events, filters: &mut filters }.switch(f.new_head, 10_000).unwrap();
    assert_eq!(outcome.removed.iter().map(BlockId::height).collect::<Vec<_>>(), [2, 1]);
    assert_eq!(outcome.applied.iter().map(BlockId::height).collect::<Vec<_>>(), [1, 2, 3]);
    assert_eq!(canonical(&f.manager), f.new_head);
    assert_eq!(f.manager.sessions.checkpoint_points().iter().map(|point| point.block).collect::<Vec<_>>(), [1, 2, 3]);
    assert_eq!(received_at(&f.manager, outcome.applied[0]), 4_000);
    assert_eq!(received_at(&f.manager, outcome.applied[1]), 4_100);
    assert_eq!(received_at(&f.manager, outcome.applied[2]), 4_200);
    assert_eq!(events.0, ["block:2:true", "block:1:true", "block:1:false", "block:2:false", "block:3:false"]);
    assert_eq!(filters.0, ["logs:2:true", "logs:1:true", "block-filter:1", "logs:1:false", "block-filter:2", "logs:2:false", "block-filter:3", "logs:3:false"]);
}

#[test]
fn invalid_new_witness_signature_removes_branch_and_restores_old_head() {
    let mut f = fixture(true);
    let mut events = Events::default();
    let mut filters = Filters::default();
    let state_before = state_image(&f.manager);
    let checkpoints_before = f.manager.sessions.checkpoint_points();
    let error = ForkManager { blocks: &mut f.manager, pending: &mut f.pending, events: &mut events, filters: &mut filters }.switch(f.new_head, 10_000).unwrap_err();
    assert!(matches!(error, ForkSwitchError::Apply { error: BlockApplyError::InvalidSignature, .. }));
    assert_eq!(canonical(&f.manager), f.old_head);
    assert_eq!(f.manager.khaos.get_head().unwrap().id, f.old_head);
    assert!(!f.manager.khaos.contain_block(&f.new_head));
    assert_eq!(state_image(&f.manager), state_before);
    assert_eq!(f.manager.sessions.checkpoint_points(), checkpoints_before);
    assert_eq!(events.0, ["block:2:true", "block:1:true", "block:1:false", "block:2:false"]);
    assert_eq!(filters.0, ["logs:2:true", "logs:1:true", "block-filter:1", "logs:1:false", "block-filter:2", "logs:2:false"]);
}

#[test]
fn apply_failure_retracts_partial_new_branch_and_atomically_restores_old_branch() {
    let mut f = fixture(false);
    f.fail_at.set(Some(3));
    let mut events = Events::default();
    let mut filters = Filters::default();
    let state_before = state_image(&f.manager);
    let checkpoints_before = f.manager.sessions.checkpoint_points();
    let error = ForkManager { blocks: &mut f.manager, pending: &mut f.pending, events: &mut events, filters: &mut filters }.switch(f.new_head, 10_000).unwrap_err();
    assert!(matches!(error, ForkSwitchError::Apply { error: BlockApplyError::Hook(_), .. }));
    assert_eq!(canonical(&f.manager), f.old_head);
    assert_eq!(f.manager.khaos.get_head().unwrap().id, f.old_head);
    assert!(f.pending.is_empty());
    assert_eq!(state_image(&f.manager), state_before);
    assert_eq!(f.manager.sessions.checkpoint_points(), checkpoints_before);
    assert_eq!(events.0, ["block:2:true", "block:1:true", "block:1:false", "block:2:false"]);
    assert_eq!(filters.0, ["logs:2:true", "logs:1:true", "block-filter:1", "logs:1:false", "block-filter:2", "logs:2:false"]);
}

#[test]
fn replay_and_committed_discard_failure_still_restore_every_surface() {
    let mut f = fixture(false);
    let cache_id = Hash32::from([0x5a; 32]);
    f.manager.processor.cache.insert(cache_id, 2, 9_000).unwrap();
    f.pending.inject_replay_failure();
    f.pending.inject_committed_discard_failure();
    let state_before = state_image(&f.manager);
    let checkpoints_before = f.manager.sessions.checkpoint_points();
    let queue_before = f.pending.queue_ids();
    let mut events = Events::default();
    let mut filters = Filters::default();

    let error = ForkManager { blocks: &mut f.manager, pending: &mut f.pending, events: &mut events, filters: &mut filters }
        .switch(f.new_head, 10_000).unwrap_err();

    assert_eq!(error, ForkSwitchError::Restore {
        original: Box::new(ForkSwitchError::State("session is not the active top layer".into())),
        restoration: "pending discard failed: session is not the active top layer".into(),
    });
    assert_eq!(state_image(&f.manager), state_before);
    assert_eq!(canonical(&f.manager), f.old_head);
    assert_eq!(f.manager.khaos.get_head().unwrap().id, f.old_head);
    assert!(!f.manager.khaos.contain_block(&f.new_head));
    assert_eq!(f.manager.sessions.checkpoint_points(), checkpoints_before);
    assert!(f.manager.processor.cache.contains_recent(&cache_id, 10_000).unwrap());
    assert_eq!(f.manager.processor.cache.len(), 1);
    assert_eq!(f.pending.queue_ids(), queue_before);
    assert_eq!(events.0, ["block:2:true", "block:1:true", "block:1:false", "block:2:false"]);
    assert_eq!(filters.0, ["logs:2:true", "logs:1:true", "block-filter:1", "logs:1:false", "block-filter:2", "logs:2:false"]);
}

#[test]
fn transaction_signature_cache_can_be_invalidated_for_fork_revalidation() {
    let tx = tron_protocol::protocol::Transaction { raw_data: Some(Default::default()), ..Default::default() };
    let mut wire = tron_execution::RawWireTransaction::decode(tx.encode_to_vec()).unwrap();
    wire.set_signature_verification_cached(true);
    assert!(wire.signature_verification_cached());
    wire.clear_signature_verification_cache();
    assert!(!wire.signature_verification_cached());
}
