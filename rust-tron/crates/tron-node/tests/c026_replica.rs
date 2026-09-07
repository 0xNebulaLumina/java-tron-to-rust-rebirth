use std::{collections::VecDeque, sync::{Arc, atomic::{AtomicU64, AtomicUsize, Ordering}}, time::{Duration, SystemTime, UNIX_EPOCH}};
use parking_lot::Mutex;

use tron_apis::{ApiContext, DatabaseFuture, DatabaseSource, FilterLimits, FilterManager};
use tron_config::Config;
use tron_crypto::CryptoEngine;
use tron_execution::{ActuatorRegistry, CacheConfig, ExecutionConfig, PendingLimits, PendingPool, StateTransactionPipeline, TransactionCache, TransactionProcessor};
use tron_node::{CancellationToken, LifecycleError, MonotonicClock, NodeContext, NodeService, ServiceFailure, ServiceGraph, ServiceGraphState, ServiceMode, ServiceSpec, operations::{compose_production_node, NodeStatus, OperationalHooks, OperationalService, OperationsComponents, ProductionNode, ProductionNodeComposition, ProductionNodeDependencies, ProductionNodeServices, ProductionOperationsConfig, ProductionOperationalBindings, ShutdownPlan, StopCondition, StopController, StopHandle, API_SERVICE, NETWORK_SERVICE}, solidity_replica::{CAUGHT_UP_POLL, ERROR_RETRY, REPLICA_QUEUE_CAPACITY, ReplicaCheckpoint, SolidityReplica, StateReplicaCheckpoint, VerifiedBlockApplier, SOLIDITY_REPLICA_SERVICE}};
use tron_protocol::protocol::{block_header, Block, BlockHeader, DynamicProperties, NodeInfo};
use tron_state::{dynamic, CheckpointIdentity, CursorPoint, CursorSet, SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};
use tron_events_metrics::{DbStatService, EventQueues, MetricsRegistry, MonitorMetrics, QueueLimits};

static CHECKPOINT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn production_checkpoint(committed_height: u64, marker_height: i64) -> (std::path::PathBuf, SessionManager, ApiContext, Arc<StateReplicaCheckpoint>) {
    let path = std::env::temp_dir().join(format!("c026-replica-{}-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(), CHECKPOINT_SEQUENCE.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&path);
    let sessions = SessionManager::new(StateStore::new(StorageManager::new(OpenRequirements { identity: StorageIdentity { network: "c026".into(), genesis: "00".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()] }).open_store(&path).unwrap()));
    let genesis = CursorPoint { block: 0, identity: CheckpointIdentity::new([0; 32]) };
    sessions.record_checkpoint(genesis).unwrap();
    let committed = CursorPoint { block: committed_height, identity: CheckpointIdentity::new([committed_height as u8; 32]) };
    sessions.record_checkpoint(committed).unwrap();
    let marker = dynamic::key("LATEST_SOLIDIFIED_BLOCK_NUM").unwrap();
    sessions.store(StoreKind::DynamicProperties).put(marker, &marker_height.to_be_bytes()).unwrap();
    let cursors = CursorSet::new(&sessions, committed, Some(genesis), None, 0).unwrap();
    let processor = TransactionProcessor { sessions: sessions.clone(), cache: TransactionCache::new(CacheConfig::default()).unwrap(), pipeline: StateTransactionPipeline::new(Default::default(), ActuatorRegistry::empty(), ExecutionConfig::default()).unwrap() };
    let pending = PendingPool::new(sessions.clone(), PendingLimits::default()).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");
    let parameters = tron_shielded::load_tron_parameters(root.join("sapling-spend.params"), root.join("sapling-output.params")).unwrap();
    let api = ApiContext::new(cursors, processor, pending, parameters, CryptoEngine::Secp256k1);
    let checkpoint = Arc::new(StateReplicaCheckpoint::new(sessions.clone(), api.clone()));
    (path, sessions, api, checkpoint)
}

fn block(number: i64) -> Block {
    Block { block_header: Some(BlockHeader { raw_data: Some(block_header::Raw { number, ..Default::default() }), ..Default::default() }), ..Default::default() }
}

struct Source {
    tip: i64,
    blocks: Arc<Mutex<Vec<i64>>>,
    failures: VecDeque<i64>,
    wrong_once: Option<(i64, i64)>,
}
impl DatabaseSource for Source {
    fn get_dynamic_properties(&mut self) -> DatabaseFuture<'_, DynamicProperties> {
        let tip = self.tip;
        Box::pin(async move { Ok(DynamicProperties { last_solidity_block_num: tip }) })
    }
    fn get_block_by_num(&mut self, number: i64) -> DatabaseFuture<'_, Block> {
        self.blocks.lock().push(number);
        let fail = self.failures.front().copied() == Some(number);
        if fail { self.failures.pop_front(); }
        let returned = match self.wrong_once.take() {
            Some((request, returned)) if request == number => returned,
            Some(value) => { self.wrong_once = Some(value); number },
            None => number,
        };
        Box::pin(async move { if fail { Err(tonic::Status::unavailable("retry")) } else { Ok(block(returned)) } })
    }
    fn shutdown(&mut self) -> DatabaseFuture<'_, ()> { Box::pin(async { Ok(()) }) }
}

struct Applier { applied: Arc<Mutex<Vec<i64>>> }
impl VerifiedBlockApplier for Applier {
    fn apply_verified(&mut self, block: Block) -> Result<i64, String> {
        let number = block.block_header.unwrap().raw_data.unwrap().number;
        self.applied.lock().push(number);
        Ok(number)
    }
}

struct Checkpoint {
    initial: i64,
    published: Arc<Mutex<Vec<i64>>>,
    cancel: CancellationToken,
    stop_at: i64,
}
impl ReplicaCheckpoint for Checkpoint {
    fn latest_solidified(&self) -> Result<i64, String> { Ok(self.initial) }
    fn publish(&self, height: i64) -> Result<(), String> {
        self.published.lock().push(height);
        if height == self.stop_at { self.cancel.cancel(); }
        Ok(())
    }
}

#[tokio::test]
async fn retries_same_height_then_applies_exact_sequence_and_persists() {
    assert_eq!(REPLICA_QUEUE_CAPACITY, 100);
    assert_eq!(CAUGHT_UP_POLL, Duration::from_secs(3));
    assert_eq!(ERROR_RETRY, Duration::from_secs(1));
    let cancellation = CancellationToken::default();
    let fetched = Arc::new(Mutex::new(Vec::new()));
    let applied = Arc::new(Mutex::new(Vec::new()));
    let published = Arc::new(Mutex::new(Vec::new()));
    let source = Source { tip: 2, blocks: fetched.clone(), failures: VecDeque::from([1]), wrong_once: None };
    let checkpoint = Checkpoint { initial: 0, published: published.clone(), cancel: cancellation.clone(), stop_at: 2 };
    let mut replica = SolidityReplica::new(Box::new(source), Box::new(Applier { applied: applied.clone() }), Arc::new(checkpoint));
    replica.run(&cancellation).await.unwrap();
    assert_eq!(*fetched.lock(), [1, 1, 2]);
    assert_eq!(*applied.lock(), [1, 2]);
    assert_eq!(*published.lock(), [1, 2]);
}

struct RestartApplier {
    sessions: SessionManager,
    attempts: Arc<Mutex<Vec<i64>>>,
    observed_markers: Arc<Mutex<Vec<i64>>>,
    cancellation: CancellationToken,
}
impl VerifiedBlockApplier for RestartApplier {
    fn apply_verified(&mut self, block: Block) -> Result<i64, String> {
        let number = block.block_header.unwrap().raw_data.unwrap().number;
        self.attempts.lock().push(number);
        let marker = dynamic::key("LATEST_SOLIDIFIED_BLOCK_NUM").unwrap();
        let persisted = self.sessions.read_view().store(StoreKind::DynamicProperties).get(marker).unwrap();
        self.observed_markers.lock().push(i64::from_be_bytes(persisted.as_slice().try_into().unwrap()));
        self.cancellation.cancel();
        Ok(number)
    }
}

#[tokio::test]
async fn startup_reconciles_stale_marker_to_committed_head_before_fetching_next_height() {
    let marker = dynamic::key("LATEST_SOLIDIFIED_BLOCK_NUM").unwrap();

    let (path, sessions, _, checkpoint) = production_checkpoint(10, 3);
    let cancellation = CancellationToken::default();
    let fetched = Arc::new(Mutex::new(Vec::new()));
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let observed_markers = Arc::new(Mutex::new(Vec::new()));
    let source = Source { tip: 11, blocks: fetched.clone(), failures: VecDeque::new(), wrong_once: None };
    let applier = RestartApplier { sessions: sessions.clone(), attempts: attempts.clone(), observed_markers: observed_markers.clone(), cancellation: cancellation.clone() };
    let mut replica = SolidityReplica::new(Box::new(source), Box::new(applier), checkpoint);
    replica.run(&cancellation).await.unwrap();
    assert_eq!(*fetched.lock(), [11]);
    assert_eq!(*attempts.lock(), [11]);
    assert_eq!(*observed_markers.lock(), [10]);
    assert_eq!(i64::from_be_bytes(sessions.read_view().store(StoreKind::DynamicProperties).get(marker).unwrap().as_slice().try_into().unwrap()), 10);
    drop(sessions);
    std::fs::remove_dir_all(path).unwrap();

    let (path, sessions, _, checkpoint) = production_checkpoint(1, 1);
    let first_cancel = CancellationToken::default();
    let first_fetched = Arc::new(Mutex::new(Vec::new()));
    let source = Source { tip: 2, blocks: first_fetched.clone(), failures: VecDeque::new(), wrong_once: None };
    let applier = RestartApplier { sessions: sessions.clone(), attempts: Arc::new(Mutex::new(Vec::new())), observed_markers: Arc::new(Mutex::new(Vec::new())), cancellation: first_cancel.clone() };
    let mut replica = SolidityReplica::new(Box::new(source), Box::new(applier), checkpoint);
    replica.run(&first_cancel).await.unwrap();
    assert_eq!(*first_fetched.lock(), [2]);
    assert_eq!(i64::from_be_bytes(sessions.read_view().store(StoreKind::DynamicProperties).get(marker).unwrap().as_slice().try_into().unwrap()), 1);
    drop(replica);
    drop(sessions);
    std::fs::remove_dir_all(path).unwrap();

    let (path, sessions, _, checkpoint) = production_checkpoint(2, 1);
    let restart_cancel = CancellationToken::default();
    let fetched = Arc::new(Mutex::new(Vec::new()));
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let observed_markers = Arc::new(Mutex::new(Vec::new()));
    let source = Source { tip: 3, blocks: fetched.clone(), failures: VecDeque::new(), wrong_once: None };
    let applier = RestartApplier { sessions: sessions.clone(), attempts: attempts.clone(), observed_markers: observed_markers.clone(), cancellation: restart_cancel.clone() };
    let mut restarted = SolidityReplica::new(Box::new(source), Box::new(applier), checkpoint);
    restarted.run(&restart_cancel).await.unwrap();
    assert_eq!(*fetched.lock(), [3]);
    assert_eq!(*attempts.lock(), [3]);
    assert_eq!(*observed_markers.lock(), [2]);
    drop(sessions);
    std::fs::remove_dir_all(path).unwrap();

    let (path, sessions, _, checkpoint) = production_checkpoint(4, 5);
    let cancellation = CancellationToken::default();
    let fetched = Arc::new(Mutex::new(Vec::new()));
    let source = Source { tip: 6, blocks: fetched.clone(), failures: VecDeque::new(), wrong_once: None };
    let mut replica = SolidityReplica::new(Box::new(source), Box::new(Applier { applied: Arc::new(Mutex::new(Vec::new())) }), checkpoint);
    assert_eq!(replica.run(&cancellation).await.unwrap_err(), "solidified marker 5 is ahead of committed checkpoint 4");
    assert!(fetched.lock().is_empty());
    drop(sessions);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn returned_height_mismatch_retries_without_apply_or_cursor_advance() {
    let cancellation = CancellationToken::default();
    let fetched = Arc::new(Mutex::new(Vec::new()));
    let applied = Arc::new(Mutex::new(Vec::new()));
    let published = Arc::new(Mutex::new(Vec::new()));
    let source = Source { tip: 1, blocks: fetched.clone(), failures: VecDeque::new(), wrong_once: Some((1, 9)) };
    let checkpoint = Checkpoint { initial: 0, published: published.clone(), cancel: cancellation.clone(), stop_at: 1 };
    let mut replica = SolidityReplica::new(Box::new(source), Box::new(Applier { applied: applied.clone() }), Arc::new(checkpoint));
    replica.run(&cancellation).await.unwrap();
    assert_eq!(*fetched.lock(), [1, 1]);
    assert_eq!(*applied.lock(), [1]);
    assert_eq!(*published.lock(), [1]);
}


struct OrderedSource { events: Arc<Mutex<Vec<&'static str>>> }
impl DatabaseSource for OrderedSource {
    fn get_dynamic_properties(&mut self) -> DatabaseFuture<'_, DynamicProperties> { Box::pin(async { Ok(DynamicProperties { last_solidity_block_num: 1 }) }) }
    fn get_block_by_num(&mut self, number: i64) -> DatabaseFuture<'_, Block> { Box::pin(async move { Ok(block(number)) }) }
    fn shutdown(&mut self) -> DatabaseFuture<'_, ()> { let events=self.events.clone(); Box::pin(async move { events.lock().push("source-closed"); Ok(()) }) }
}
struct OrderedCheckpoint { events: Arc<Mutex<Vec<&'static str>>>, cancellation: CancellationToken }
impl ReplicaCheckpoint for OrderedCheckpoint {
    fn latest_solidified(&self) -> Result<i64, String> { Ok(0) }
    fn publish(&self, _: i64) -> Result<(), String> { self.events.lock().push("published"); self.cancellation.cancel(); Ok(()) }
}
struct Clock;
impl MonotonicClock for Clock { fn elapsed(&self) -> Duration { Duration::ZERO } }

#[tokio::test]
async fn service_shutdown_joins_publication_before_closing_database_client() {
    let cancellation=CancellationToken::default();
    let events=Arc::new(Mutex::new(Vec::new()));
    let status=NodeStatus::default(); status.mark_running();
    let (stop,mut controller)=StopController::new();
    let mut service=SolidityReplica::supervised(Box::new(OrderedSource { events: events.clone() }), Box::new(Applier { applied: Arc::new(Mutex::new(Vec::new())) }), Arc::new(OrderedCheckpoint { events: events.clone(), cancellation: cancellation.clone() }), status.clone(), stop);
    let context=NodeContext::new(Arc::new(Config::default()), cancellation.clone(), Arc::new(Clock));
    service.start(&context,Duration::from_secs(1)).await.unwrap();
    cancellation.cancelled().await;
    service.stop(&context,Duration::from_secs(1)).await.unwrap();
    assert_eq!(*events.lock(),["published","source-closed"]);
    assert!(status.is_ready());
    assert!(tokio::time::timeout(Duration::from_millis(20),controller.wait()).await.is_err());
}

struct FailingCheckpoint;
impl ReplicaCheckpoint for FailingCheckpoint {
    fn latest_solidified(&self) -> Result<i64, String> { Err("checkpoint unavailable".into()) }
    fn publish(&self, _: i64) -> Result<(), String> { unreachable!() }
}

struct PanickingCheckpoint;
impl ReplicaCheckpoint for PanickingCheckpoint {
    fn latest_solidified(&self) -> Result<i64, String> { panic!("checkpoint panic") }
    fn publish(&self, _: i64) -> Result<(), String> { unreachable!() }
}

#[tokio::test]
async fn replica_worker_failure_revokes_readiness_and_requests_fatal_stop() {
    let cancellation=CancellationToken::default();
    let status=NodeStatus::default(); status.mark_running();
    let (stop,mut controller)=StopController::new();
    let source=Source { tip: 0, blocks: Arc::new(Mutex::new(Vec::new())), failures: VecDeque::new(), wrong_once: None };
    let mut service=SolidityReplica::supervised(Box::new(source), Box::new(Applier { applied: Arc::new(Mutex::new(Vec::new())) }), Arc::new(FailingCheckpoint), status.clone(), stop);
    let context=NodeContext::new(Arc::new(Config::default()), cancellation, Arc::new(Clock));
    service.start(&context,Duration::from_secs(1)).await.unwrap();
    let condition=tokio::time::timeout(Duration::from_secs(1),controller.wait()).await.unwrap();
    let StopCondition::Fatal(failure)=condition else { panic!("expected fatal stop") };
    assert_eq!(failure.service,SOLIDITY_REPLICA_SERVICE);
    assert_eq!(failure.message,"checkpoint unavailable");
    assert!(!status.is_ready()&&!status.is_healthy()&&!status.accepts_ingress());
    assert_eq!(service.stop(&context,Duration::from_secs(1)).await.unwrap_err().message,"checkpoint unavailable");

    let status=NodeStatus::default(); status.mark_running();
    let (stop,mut controller)=StopController::new();
    let source=Source { tip: 0, blocks: Arc::new(Mutex::new(Vec::new())), failures: VecDeque::new(), wrong_once: None };
    let mut panicked=SolidityReplica::supervised(Box::new(source), Box::new(Applier { applied: Arc::new(Mutex::new(Vec::new())) }), Arc::new(PanickingCheckpoint), status.clone(), stop);
    let cancellation=CancellationToken::default();
    let context=NodeContext::new(Arc::new(Config::default()), cancellation, Arc::new(Clock));
    panicked.start(&context,Duration::from_secs(1)).await.unwrap();
    let StopCondition::Fatal(failure)=tokio::time::timeout(Duration::from_secs(1),controller.wait()).await.unwrap() else { panic!("expected fatal stop") };
    assert_eq!(failure.service,SOLIDITY_REPLICA_SERVICE);
    assert!(failure.message.contains("checkpoint panic"));
    assert!(!status.is_ready()&&!status.is_healthy()&&!status.accepts_ingress());
    assert!(panicked.stop(&context,Duration::from_secs(1)).await.unwrap_err().message.contains("checkpoint panic"));
}

struct FetchErrorSource { events: Arc<Mutex<Vec<&'static str>>>, cancellation: CancellationToken }
impl DatabaseSource for FetchErrorSource {
    fn get_dynamic_properties(&mut self) -> DatabaseFuture<'_, DynamicProperties> { Box::pin(async { Ok(DynamicProperties { last_solidity_block_num: 1 }) }) }
    fn get_block_by_num(&mut self, _: i64) -> DatabaseFuture<'_, Block> { let events=self.events.clone(); let cancellation=self.cancellation.clone(); Box::pin(async move { events.lock().push("fetch-error"); cancellation.cancel(); Err(tonic::Status::unavailable("closed during fetch")) }) }
    fn shutdown(&mut self) -> DatabaseFuture<'_, ()> { let events=self.events.clone(); Box::pin(async move { events.lock().push("source-shutdown"); Ok(()) }) }
}

#[tokio::test]
async fn source_fetch_error_during_shutdown_still_closes_database_source() {
    let cancellation=CancellationToken::default();
    let events=Arc::new(Mutex::new(Vec::new()));
    let mut service=SolidityReplica::new(Box::new(FetchErrorSource { events: events.clone(), cancellation: cancellation.clone() }), Box::new(Applier { applied: Arc::new(Mutex::new(Vec::new())) }), Arc::new(Checkpoint { initial: 0, published: Arc::new(Mutex::new(Vec::new())), cancel: cancellation.clone(), stop_at: 1 }));
    let context=NodeContext::new(Arc::new(Config::default()), cancellation.clone(), Arc::new(Clock));
    service.start(&context,Duration::ZERO).await.unwrap();
    cancellation.cancelled().await;
    service.stop(&context,Duration::from_secs(1)).await.unwrap();
    assert_eq!(*events.lock(),["fetch-error","source-shutdown"]);
}

#[tokio::test]
async fn durable_solidity_cursor_remains_readable_after_database_source_closes() {
    let marker=dynamic::key("LATEST_SOLIDIFIED_BLOCK_NUM").unwrap();
    let (path,sessions,_,checkpoint)=production_checkpoint(7,7);
    let events=Arc::new(Mutex::new(Vec::new()));
    let cancellation=CancellationToken::default(); cancellation.cancel();
    let mut service=SolidityReplica::new(Box::new(OrderedSource { events: events.clone() }), Box::new(Applier { applied: Arc::new(Mutex::new(Vec::new())) }), checkpoint.clone());
    let context=NodeContext::new(Arc::new(Config::default()), cancellation, Arc::new(Clock));
    service.start(&context,Duration::ZERO).await.unwrap();
    service.stop(&context,Duration::from_secs(1)).await.unwrap();
    assert_eq!(*events.lock(),["source-closed"]);
    assert_eq!(checkpoint.latest_solidified().unwrap(),7);
    assert_eq!(i64::from_be_bytes(sessions.read_view().store(StoreKind::DynamicProperties).get(marker).unwrap().as_slice().try_into().unwrap()),7);
    drop(checkpoint); drop(sessions); std::fs::remove_dir_all(path).unwrap();
}

struct InterruptSource { entered: Arc<tokio::sync::Notify>, events: Arc<Mutex<Vec<&'static str>>> }
impl DatabaseSource for InterruptSource {
    fn get_dynamic_properties(&mut self) -> DatabaseFuture<'_, DynamicProperties> { let entered=self.entered.clone(); Box::pin(async move { entered.notify_one(); std::future::pending().await }) }
    fn get_block_by_num(&mut self, _: i64) -> DatabaseFuture<'_, Block> { unreachable!() }
    fn shutdown(&mut self) -> DatabaseFuture<'_, ()> { let events=self.events.clone(); Box::pin(async move { events.lock().push("source-shutdown"); Ok(()) }) }
}

#[tokio::test]
async fn interrupt_cancels_inflight_replica_read_and_closes_database_source() {
    let cancellation=CancellationToken::default();
    let entered=Arc::new(tokio::sync::Notify::new());
    let events=Arc::new(Mutex::new(Vec::new()));
    let status=NodeStatus::default(); assert!(status.mark_running());
    let (stop,mut controller)=StopController::new();
    let mut service=SolidityReplica::supervised(Box::new(InterruptSource { entered: entered.clone(), events: events.clone() }), Box::new(Applier { applied: Arc::new(Mutex::new(Vec::new())) }), Arc::new(Checkpoint { initial: 0, published: Arc::new(Mutex::new(Vec::new())), cancel: cancellation.clone(), stop_at: 1 }), status.clone(), stop);
    let context=NodeContext::new(Arc::new(Config::default()), cancellation.clone(), Arc::new(Clock));
    service.start(&context,Duration::ZERO).await.unwrap();
    entered.notified().await; cancellation.cancel();
    service.stop(&context,Duration::from_secs(1)).await.unwrap();
    assert_eq!(*events.lock(),["source-shutdown"]);
    assert!(tokio::time::timeout(Duration::from_millis(20),controller.wait()).await.is_err());
    assert!(status.is_healthy());
}

struct BlockingShutdownSource {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    events: Arc<Mutex<Vec<&'static str>>>,
}
impl DatabaseSource for BlockingShutdownSource {
    fn get_dynamic_properties(&mut self) -> DatabaseFuture<'_, DynamicProperties> { Box::pin(async { std::future::pending().await }) }
    fn get_block_by_num(&mut self, _: i64) -> DatabaseFuture<'_, Block> { unreachable!() }
    fn shutdown(&mut self) -> DatabaseFuture<'_, ()> {
        let entered=self.entered.clone(); let release=self.release.clone(); let events=self.events.clone();
        Box::pin(async move { entered.notify_one(); release.notified().await; events.lock().push("source-shutdown"); Ok(()) })
    }
}

#[tokio::test]
async fn timed_out_replica_stop_remains_owned_and_retry_joins_source_shutdown() {
    let entered=Arc::new(tokio::sync::Notify::new());
    let release=Arc::new(tokio::sync::Notify::new());
    let events=Arc::new(Mutex::new(Vec::new()));
    let cancellation=CancellationToken::default();
    let mut config=Config::default(); config.node.trust_node="127.0.0.1:50051".into();
    let context=NodeContext::new(Arc::new(config),cancellation,Arc::new(Clock));
    let replica=SolidityReplica::new(Box::new(BlockingShutdownSource{entered:entered.clone(),release:release.clone(),events:events.clone()}),Box::new(Applier{applied:Arc::new(Mutex::new(Vec::new()))}),Arc::new(Checkpoint{initial:0,published:Arc::new(Mutex::new(Vec::new())),cancel:CancellationToken::default(),stop_at:1}));
    let mut graph=ServiceGraph::new(context,tron_config::NodeMode::Solidity,vec![Box::new(replica)]).unwrap();
    graph.start(Duration::from_secs(1),Duration::from_secs(1)).await.unwrap();
    assert_eq!(graph.shutdown(Duration::from_millis(20)).await.unwrap_err(),LifecycleError::ShutdownTimeout{service:SOLIDITY_REPLICA_SERVICE,timeout:Duration::from_millis(20)});
    assert_eq!(graph.state(),ServiceGraphState::Stopping);
    assert_eq!(graph.started_services().collect::<Vec<_>>(),vec![SOLIDITY_REPLICA_SERVICE]);
    assert!(events.lock().is_empty());
    release.notify_one();
    graph.shutdown(Duration::from_secs(1)).await.unwrap();
    assert_eq!(graph.state(),ServiceGraphState::Stopped);
    assert!(graph.started_services().next().is_none());
    assert_eq!(*events.lock(),["source-shutdown"]);
}

struct DualFailureSource;
impl DatabaseSource for DualFailureSource {
    fn get_dynamic_properties(&mut self) -> DatabaseFuture<'_, DynamicProperties> { Box::pin(async { Ok(DynamicProperties::default()) }) }
    fn get_block_by_num(&mut self, _: i64) -> DatabaseFuture<'_, Block> { unreachable!() }
    fn shutdown(&mut self) -> DatabaseFuture<'_, ()> { Box::pin(async { Err(tonic::Status::internal("shutdown exact cause")) }) }
}

#[tokio::test]
async fn replica_worker_and_database_shutdown_failures_preserve_both_exact_causes() {
    let cancellation=CancellationToken::default();
    let context=NodeContext::new(Arc::new(Config::default()),cancellation.clone(),Arc::new(Clock));
    let mut replica=SolidityReplica::new(Box::new(DualFailureSource),Box::new(Applier{applied:Arc::new(Mutex::new(Vec::new()))}),Arc::new(FailingCheckpoint));
    replica.start(&context,Duration::ZERO).await.unwrap();
    let failure=replica.stop(&context,Duration::from_secs(1)).await.unwrap_err();
    assert_eq!(failure,ServiceFailure{service:SOLIDITY_REPLICA_SERVICE,message:"replica worker failed: checkpoint unavailable; database source shutdown failed: status: Internal, message: \"shutdown exact cause\", details: [], metadata: MetadataMap { headers: {} }".into()});
}

struct StartedHook(Arc<std::sync::atomic::AtomicBool>);
impl OperationalHooks for StartedHook {
    fn start<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { self.0.store(true,std::sync::atomic::Ordering::Release); Box::pin(async { Ok(()) }) }
    fn stop<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { self.0.store(false,std::sync::atomic::Ordering::Release); Box::pin(async { Ok(()) }) }
}

struct IdleHooks;
impl OperationalHooks for IdleHooks {
    fn start<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { Box::pin(async { Ok(()) }) }
    fn stop<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { Box::pin(async { Ok(()) }) }
}

struct FailingReadiness;
impl OperationalHooks for FailingReadiness {
    fn start<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { Box::pin(async { Err("generic readiness failure".into()) }) }
    fn stop<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { Box::pin(async { Ok(()) }) }
}

fn production_node<F>(readiness: F, network: Box<dyn NodeService>) -> (std::path::PathBuf, SessionManager, Arc<StateReplicaCheckpoint>, ProductionNode)
where F: FnOnce(NodeStatus,StopHandle)->Box<dyn OperationalHooks> {
    let (path,sessions,api,checkpoint)=production_checkpoint(1,1);
    let queues=EventQueues::shared(QueueLimits::default());
    let metrics=Arc::new(MonitorMetrics::new(true));
    let filters=FilterManager::shared(FilterLimits::default());
    let bindings=ProductionOperationalBindings::new(api,Arc::new(NodeInfo::default),queues,filters,metrics);
    let context=NodeContext::new(Arc::new(Config::default()),CancellationToken::default(),Arc::new(Clock));
    let composition=ProductionNodeComposition{context,mode:tron_config::NodeMode::Full,bindings};
    let node=ProductionNode::from_service_factory(composition,move|status,stop|{
        let operations=OperationsComponents{api_provider:Box::new(IdleHooks),queues:Box::new(IdleHooks),plugin:Box::new(IdleHooks),zeromq:Box::new(IdleHooks),metrics:Box::new(IdleHooks),prometheus:Box::new(IdleHooks),db_stats:Box::new(IdleHooks),readiness:readiness(status,stop)};
        ProductionNodeServices{core_services:Vec::new(),network,apis:Box::new(OperationalService::new(ServiceSpec::new(API_SERVICE,&[NETWORK_SERVICE],&[ServiceMode::Full]),ShutdownPlan::Stop,Box::new(IdleHooks))),operations,replica:None}
    }).unwrap();
    (path,sessions,checkpoint,node)
}

#[test]
fn production_factory_validates_mode_config_before_factory_side_effects() {
    for trust_node in [
        "", "trust.example", "::1:50051", "host:1:50051", "host/path:50051",
        "http://host:50051", "user@host:50051", "host:50051?query", "host:50051#fragment",
    ] {
        let (path, sessions, api, checkpoint) = production_checkpoint(1, 1);
        let queues = EventQueues::shared(QueueLimits::default());
        let metrics = Arc::new(MonitorMetrics::new(true));
        let filters = FilterManager::shared(FilterLimits::default());
        let bindings = ProductionOperationalBindings::new(api, Arc::new(NodeInfo::default), queues, filters, metrics);
        let mut config = Config::default();
        config.node.trust_node = trust_node.into();
        let context = NodeContext::new(Arc::new(config), CancellationToken::default(), Arc::new(Clock));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = factory_calls.clone();
        let error = ProductionNode::from_service_factory(
            ProductionNodeComposition { context, mode: tron_config::NodeMode::Solidity, bindings },
            move |_, _| {
                observed_calls.fetch_add(1, Ordering::SeqCst);
                panic!("invalid configuration invoked the service/resource factory")
            },
        ).err().expect("invalid Solidity configuration must fail");
        assert!(matches!(error, LifecycleError::InvalidConfiguration(_)));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        drop(checkpoint);
        drop(sessions);
        std::fs::remove_dir_all(path).unwrap();
    }

    let factory_calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = factory_calls.clone();
    let network = Box::new(OperationalService::new(ServiceSpec::new(NETWORK_SERVICE, &[], &[ServiceMode::Full]), ShutdownPlan::Stop, Box::new(IdleHooks)));
    let (path, sessions, checkpoint, node) = production_node(move |_, _| {
        observed_calls.fetch_add(1, Ordering::SeqCst);
        Box::new(IdleHooks)
    }, network);
    assert_eq!(factory_calls.load(Ordering::SeqCst), 1);
    drop(node);
    drop(checkpoint);
    drop(sessions);
    std::fs::remove_dir_all(path).unwrap();
}

struct ObservedProductionService {
    spec: ServiceSpec,
    inspections: Arc<AtomicUsize>,
}

impl NodeService for ObservedProductionService {
    fn spec(&self) -> ServiceSpec {
        self.inspections.fetch_add(1, Ordering::SeqCst);
        self.spec.clone()
    }

    fn start<'a>(&'a mut self, _: &'a NodeContext, _: Duration) -> tron_node::LifecycleFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn stop<'a>(&'a mut self, _: &'a NodeContext, _: Duration) -> tron_node::LifecycleFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn observed_production_dependencies(
    trust_node: &str,
    inspections: Arc<AtomicUsize>,
) -> (std::path::PathBuf, SessionManager, ProductionNodeDependencies) {
    let (path, sessions, api, _) = production_checkpoint(1, 1);
    let queues = EventQueues::shared(QueueLimits::default());
    let metrics = Arc::new(MonitorMetrics::new(true));
    let filters = FilterManager::shared(FilterLimits::default());
    let bindings = ProductionOperationalBindings::new(api, Arc::new(NodeInfo::default), queues.clone(), filters, metrics.clone());
    let mut config = Config::default();
    config.node.trust_node = trust_node.into();
    let context = NodeContext::new(Arc::new(config), CancellationToken::default(), Arc::new(Clock));
    let service = |spec| Box::new(ObservedProductionService { spec, inspections: inspections.clone() }) as Box<dyn NodeService>;
    let dependencies = ProductionNodeDependencies {
        context,
        mode: tron_config::NodeMode::Solidity,
        core_services: Vec::new(),
        network: service(ServiceSpec::new(NETWORK_SERVICE, &[], &[ServiceMode::Full])),
        apis: service(ServiceSpec::new(API_SERVICE, &[], &[ServiceMode::Solidity])),
        bindings,
        sessions: sessions.clone(),
        verified_block_applier: Some(Box::new(Applier { applied: Arc::new(Mutex::new(Vec::new())) })),
        queues,
        metrics,
        db_stats: DbStatService::new(MetricsRegistry::new(false)),
    };
    (path, sessions, dependencies)
}

#[tokio::test]
async fn public_production_entrypoint_prevalidates_canonical_config_before_consuming_dependencies() {
    for trust_node in [
        "", "trust.example", "::1:50051", "host:1:50051", "host/path:50051",
        "http://host:50051", "user@host:50051", "host:50051?query", "host:50051#fragment",
    ] {
        let inspections = Arc::new(AtomicUsize::new(0));
        let (path, sessions, dependencies) = observed_production_dependencies(trust_node, inspections.clone());
        let error = compose_production_node(ProductionOperationsConfig::default(), dependencies)
            .err().expect("invalid canonical context config must fail");
        assert!(matches!(error, LifecycleError::InvalidConfiguration(_)));
        assert_eq!(inspections.load(Ordering::SeqCst), 0, "invalid config consumed an owned service");
        drop(sessions);
        std::fs::remove_dir_all(path).unwrap();
    }

    let inspections = Arc::new(AtomicUsize::new(0));
    let (path, sessions, dependencies) = observed_production_dependencies("127.0.0.1:50051", inspections.clone());
    let node = compose_production_node(ProductionOperationsConfig::default(), dependencies)
        .expect("valid canonical context config must compose");
    assert_eq!(inspections.load(Ordering::SeqCst), 3, "valid composition must build exactly one validated production graph");
    drop(node);
    drop(sessions);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn fatal_replica_before_readiness_start_never_becomes_healthy_ready_or_ingress_enabled() {
    let root_running=Arc::new(std::sync::atomic::AtomicBool::new(false));
    let network=Box::new(OperationalService::new(ServiceSpec::new(NETWORK_SERVICE,&[],&[ServiceMode::Full]),ShutdownPlan::Stop,Box::new(StartedHook(root_running.clone()))));
    let (path,sessions,checkpoint,mut node)=production_node(|_,_|Box::new(FailingReadiness),network);
    let status=node.status();
    let fatal=ServiceFailure{service:SOLIDITY_REPLICA_SERVICE,message:"checkpoint unavailable".into()};
    node.stop_handle().request(StopCondition::Fatal(fatal.clone())).unwrap();
    let error=node.start(Duration::from_secs(1),Duration::from_secs(1)).await.unwrap_err();
    let LifecycleError::StartupLifecycleFailure{fatals,startup,unwind}=error else {panic!("expected structured startup failure")};
    assert_eq!(fatals,vec![fatal]); assert_eq!(*startup,LifecycleError::StartupFailure(ServiceFailure{service:"node-readiness",message:"generic readiness failure".into()})); assert_eq!(unwind,None);
    assert_eq!(node.graph_state(),ServiceGraphState::Failed);
    assert!(!root_running.load(std::sync::atomic::Ordering::Acquire));
    assert!(status.is_fatal()&&!status.is_ready()&&!status.is_healthy()&&!status.accepts_ingress());
    drop(checkpoint);drop(sessions);std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn stop_controller_fatal_latch_preserves_nonfatal_queue_and_every_fatal_cause() {
    let (handle,mut controller)=StopController::new();
    let first=ServiceFailure{service:SOLIDITY_REPLICA_SERVICE,message:"first fatal".into()};
    let second=ServiceFailure{service:"event-plugin",message:"second fatal".into()};
    handle.request(StopCondition::Operator).unwrap();
    handle.request(StopCondition::Fatal(first.clone())).unwrap();
    handle.request(StopCondition::Interrupt).unwrap();
    handle.request(StopCondition::Fatal(second.clone())).unwrap();
    assert_eq!(controller.peek_fatal(),Some(first.clone()));
    assert_eq!(controller.drain_all_fatal(),vec![first,second]);
    assert_eq!(controller.peek_fatal(),None);
    assert_eq!(controller.wait().await,StopCondition::Operator);
    assert!(matches!(controller.wait().await,StopCondition::Fatal(_)));
    assert_eq!(controller.wait().await,StopCondition::Interrupt);
    assert!(matches!(controller.wait().await,StopCondition::Fatal(_)));
}

struct FactoryFatalReadiness { status:NodeStatus, stop:StopHandle }
impl OperationalHooks for FactoryFatalReadiness {
    fn start<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { Box::pin(async move {
        self.stop.request(StopCondition::Fatal(ServiceFailure{service:"factory-readiness",message:"shared-state fatal".into()})).map_err(|_|"fatal receiver closed".to_string())?;
        if self.status.is_fatal() { Err("shared state observed fatal".into()) } else { Ok(()) }
    }) }
    fn stop<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { Box::pin(async { Ok(()) }) }
}

#[tokio::test]
async fn production_factory_hooks_share_the_nodes_exact_status_and_stop_state() {
    let network=Box::new(OperationalService::new(ServiceSpec::new(NETWORK_SERVICE,&[],&[ServiceMode::Full]),ShutdownPlan::Stop,Box::new(IdleHooks)));
    let (path,sessions,checkpoint,mut node)=production_node(|status,stop|Box::new(FactoryFatalReadiness{status,stop}),network);
    let observed=node.status();
    let error=node.start(Duration::from_secs(1),Duration::from_secs(1)).await.unwrap_err();
    assert!(observed.is_fatal()&&!observed.is_ready()&&!observed.accepts_ingress());
    assert!(matches!(error,LifecycleError::StartupLifecycleFailure{fatals,startup,unwind:None}
        if fatals == vec![ServiceFailure{service:"factory-readiness",message:"shared-state fatal".into()}]
            && *startup == LifecycleError::StartupFailure(ServiceFailure{service:"node-readiness",message:"shared state observed fatal".into()})));
    drop(checkpoint);drop(sessions);std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn production_start_atomically_drains_every_concurrent_fatal_in_order() {
    let entered=Arc::new(tokio::sync::Notify::new());
    let readiness=TimeoutReadiness{entered:entered.clone()};
    let network=Box::new(OperationalService::new(ServiceSpec::new(NETWORK_SERVICE,&[],&[ServiceMode::Full]),ShutdownPlan::Stop,Box::new(IdleHooks)));
    let (path,sessions,checkpoint,mut node)=production_node(move|_,_|Box::new(readiness),network);
    let stop=node.stop_handle();
    let start=tokio::spawn(async move {let result=node.start(Duration::from_millis(50),Duration::from_secs(1)).await;(node,result)});
    entered.notified().await;
    let first=ServiceFailure{service:"replica",message:"first concurrent fatal".into()};
    let second=ServiceFailure{service:"event-delivery",message:"second concurrent fatal".into()};
    let order=Arc::new(tokio::sync::Mutex::new(()));
    let first_task={let stop=stop.clone();let order=order.clone();let first=first.clone();tokio::spawn(async move {let _guard=order.lock().await;stop.request(StopCondition::Fatal(first)).unwrap();})};
    let second_task={let stop=stop.clone();let order=order.clone();let second=second.clone();tokio::spawn(async move {tokio::task::yield_now().await;let _guard=order.lock().await;stop.request(StopCondition::Fatal(second)).unwrap();})};
    first_task.await.unwrap();second_task.await.unwrap();
    let (node,result)=start.await.unwrap();
    assert!(matches!(result.unwrap_err(),LifecycleError::StartupLifecycleFailure{fatals,startup,unwind:None}
        if fatals == vec![first,second] && *startup == LifecycleError::StartupTimeout{service:"node-readiness",timeout:Duration::from_millis(50)}));
    assert_eq!(node.graph_state(),ServiceGraphState::Failed);
    drop(checkpoint);drop(sessions);std::fs::remove_dir_all(path).unwrap();
}

struct RaceReadiness {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    stops: Arc<std::sync::atomic::AtomicUsize>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl OperationalHooks for RaceReadiness {
    fn start<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { Box::pin(async move {
        self.task=Some(tokio::spawn(std::future::pending()));
        self.entered.notify_one();
        self.release.notified().await;
        Ok(())
    }) }
    fn cancel_ingress<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { Box::pin(async { Ok(()) }) }
    fn stop<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { Box::pin(async move {
        self.stops.fetch_add(1,std::sync::atomic::Ordering::AcqRel);
        if let Some(task)=self.task.take(){task.abort();let _=task.await;}
        Err("cleanup failed".into())
    }) }
}

struct TimeoutReadiness {
    entered: Arc<tokio::sync::Notify>,
}
impl OperationalHooks for TimeoutReadiness {
    fn start<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { Box::pin(async move {
        self.entered.notify_one();
        std::future::pending().await
    }) }
    fn stop<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { Box::pin(async { Ok(()) }) }
}

#[tokio::test]
async fn production_start_preserves_fatal_when_later_service_times_out() {
    let entered=Arc::new(tokio::sync::Notify::new());
    let readiness=TimeoutReadiness{entered:entered.clone()};
    let network=Box::new(OperationalService::new(ServiceSpec::new(NETWORK_SERVICE,&[],&[ServiceMode::Full]),ShutdownPlan::Stop,Box::new(IdleHooks)));
    let (path,sessions,checkpoint,mut node)=production_node(move|_,_|Box::new(readiness),network);
    let stop=node.stop_handle();
    let fatal=ServiceFailure{service:SOLIDITY_REPLICA_SERVICE,message:"replica supervisor exited: checkpoint unavailable".into()};
    let start=tokio::spawn(async move {let result=node.start(Duration::from_millis(50),Duration::from_secs(1)).await;(node,result)});
    entered.notified().await;
    stop.request(StopCondition::Fatal(fatal.clone())).unwrap();
    let (node,error)=start.await.unwrap();
    match error.unwrap_err() {
        LifecycleError::StartupLifecycleFailure{fatals,startup,unwind} => {
            assert_eq!(fatals,vec![fatal]);
            assert_eq!(*startup,LifecycleError::StartupTimeout{service:"node-readiness",timeout:Duration::from_millis(50)});
            assert_eq!(unwind,None);
        }
        other=>panic!("expected all fatal startup causes with original timeout, got {other:?}"),
    }
    assert_eq!(node.graph_state(),ServiceGraphState::Failed);
    assert!(node.started_services().next().is_none());
    drop(checkpoint);drop(sessions);std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn production_start_fatal_after_graph_readiness_unwinds_every_started_resource_exactly_once() {
    let entered=Arc::new(tokio::sync::Notify::new());
    let release=Arc::new(tokio::sync::Notify::new());
    let stops=Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let readiness=RaceReadiness{entered:entered.clone(),release:release.clone(),stops:stops.clone(),task:None};
    let network=Box::new(OperationalService::new(ServiceSpec::new(NETWORK_SERVICE,&[],&[ServiceMode::Full]),ShutdownPlan::Stop,Box::new(IdleHooks)));
    let (path,sessions,checkpoint,mut node)=production_node(move|_,_|Box::new(readiness),network);
    let status=node.status();
    let cancellation=node.stop_handle();
    let fatal=ServiceFailure{service:SOLIDITY_REPLICA_SERVICE,message:"replica supervisor exited: checkpoint unavailable".into()};
    let start=tokio::spawn(async move {let result=node.start(Duration::from_secs(1),Duration::from_secs(1)).await;(node,result)});
    entered.notified().await;
    cancellation.request(StopCondition::Fatal(fatal.clone())).unwrap();
    release.notify_one();
    let (node,error)=start.await.unwrap();
    let error=error.unwrap_err();
    match error {
        LifecycleError::StartupLifecycleFailure{fatals,startup,unwind} => {
            assert_eq!(fatals,vec![fatal]);
            assert_eq!(*startup,LifecycleError::StartupFailure(ServiceFailure{service:"node-readiness",message:"node became fatally unhealthy during startup".into()}));
            assert!(matches!(unwind.as_deref(),Some(LifecycleError::ShutdownFailures(failures)) if failures == &[ServiceFailure{service:"node-readiness",message:"cleanup failed".into()}]));
        }
        other=>panic!("expected structured startup/unwind failure, got {other:?}"),
    }
    assert_eq!(node.graph_state(),ServiceGraphState::Stopping);
    assert_eq!(node.started_services().collect::<Vec<_>>(),vec!["node-readiness"]);
    assert!(status.is_fatal()&&!status.is_ready()&&!status.is_healthy()&&!status.accepts_ingress());
    assert_eq!(stops.load(std::sync::atomic::Ordering::Acquire),1);
    drop(checkpoint);drop(sessions);std::fs::remove_dir_all(path).unwrap();
}

struct FailingStopHooks;
impl OperationalHooks for FailingStopHooks {
    fn start<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { Box::pin(async { Ok(()) }) }
    fn stop<'a>(&'a mut self, _: Duration) -> tron_node::operations::HookFuture<'a> { Box::pin(async { Err("shutdown exact cause".into()) }) }
}

async fn assert_nonfatal_before_fatal_is_authoritative(trigger: StopCondition) {
    let network=Box::new(OperationalService::new(ServiceSpec::new(NETWORK_SERVICE,&[],&[ServiceMode::Full]),ShutdownPlan::Stop,Box::new(IdleHooks)));
    let (path,sessions,checkpoint,mut node)=production_node(|_,_|Box::new(IdleHooks),network);
    node.start(Duration::from_secs(1),Duration::from_secs(1)).await.unwrap();
    let fatal=ServiceFailure{service:SOLIDITY_REPLICA_SERVICE,message:"fatal queued after nonfatal trigger".into()};
    let stop=node.stop_handle();
    stop.request(trigger).unwrap();
    stop.request(StopCondition::Fatal(fatal.clone())).unwrap();
    assert_eq!(node.wait_and_shutdown(Duration::from_secs(1)).await.unwrap_err(),LifecycleError::FatalShutdown{fatals:vec![fatal],shutdown:None});
    assert_eq!(node.graph_state(),ServiceGraphState::Stopped);
    drop(checkpoint);drop(sessions);std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn production_operator_before_fatal_cannot_report_successful_shutdown() {
    assert_nonfatal_before_fatal_is_authoritative(StopCondition::Operator).await;
}

#[tokio::test]
async fn production_interrupt_before_fatal_cannot_report_successful_shutdown() {
    assert_nonfatal_before_fatal_is_authoritative(StopCondition::Interrupt).await;
}

#[tokio::test]
async fn production_fatal_and_graph_shutdown_error_are_structurally_aggregated() {
    let network=Box::new(OperationalService::new(ServiceSpec::new(NETWORK_SERVICE,&[],&[ServiceMode::Full]),ShutdownPlan::Stop,Box::new(FailingStopHooks)));
    let (path,sessions,checkpoint,mut node)=production_node(|_,_|Box::new(IdleHooks),network);
    node.start(Duration::from_secs(1),Duration::from_secs(1)).await.unwrap();
    let fatal=ServiceFailure{service:SOLIDITY_REPLICA_SERVICE,message:"fatal before failing cleanup".into()};
    let stop=node.stop_handle();
    stop.request(StopCondition::Operator).unwrap();
    stop.request(StopCondition::Fatal(fatal.clone())).unwrap();
    let error=node.wait_and_shutdown(Duration::from_secs(1)).await.unwrap_err();
    assert_eq!(error,LifecycleError::FatalShutdown{
        fatals:vec![fatal],
        shutdown:Some(Box::new(LifecycleError::ShutdownFailures(vec![ServiceFailure{service:NETWORK_SERVICE,message:"shutdown exact cause".into()}]))),
    });
    drop(checkpoint);drop(sessions);std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn production_nonfatal_shutdown_remains_successful() {
    let network=Box::new(OperationalService::new(ServiceSpec::new(NETWORK_SERVICE,&[],&[ServiceMode::Full]),ShutdownPlan::Stop,Box::new(IdleHooks)));
    let (path,sessions,checkpoint,mut node)=production_node(|_,_|Box::new(IdleHooks),network);
    node.start(Duration::from_secs(1),Duration::from_secs(1)).await.unwrap();
    node.stop_handle().request(StopCondition::Operator).unwrap();
    assert_eq!(node.wait_and_shutdown(Duration::from_secs(1)).await.unwrap(),StopCondition::Operator);
    assert_eq!(node.graph_state(),ServiceGraphState::Stopped);
    drop(checkpoint);drop(sessions);std::fs::remove_dir_all(path).unwrap();
}
