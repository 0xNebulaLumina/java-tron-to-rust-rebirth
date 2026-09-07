use std::{future::Future, pin::Pin, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use prost::Message;
use tron_apis::{ApiContext, DatabaseSource};
use tron_execution::{BlockApplyHooks, BlockConsensus, BlockManager, RawBlock};
use tron_protocol::protocol::Block;
use tron_state::{dynamic, CursorSet, SessionManager, StoreKind};

use crate::{CancellationToken, LifecycleFuture, NodeContext, NodeService, ServiceFailure, ServiceMode, ServiceSpec};
use crate::operations::{NodeStatus, StopCondition, StopHandle};

pub const SOLIDITY_REPLICA_SERVICE: &str = "solidity-replica";
pub const REPLICA_QUEUE_CAPACITY: usize = 100;
pub const CAUGHT_UP_POLL: Duration = Duration::from_secs(3);
pub const ERROR_RETRY: Duration = Duration::from_secs(1);

pub type ReplicaFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

pub trait VerifiedBlockApplier: Send {
    fn apply_verified(&mut self, block: Block) -> Result<i64, String>;
}


pub trait ReplicaCheckpoint: Send + Sync {
    fn latest_solidified(&self) -> Result<i64, String>;
    fn publish(&self, height: i64) -> Result<(), String>;
}

/// Invokes the verified C019 canonical block path without duplicating validation or execution.
pub fn apply_with_c019<C: BlockConsensus, H: BlockApplyHooks>(manager: &mut BlockManager<C, H>, block: Block) -> Result<i64, String> {
    let raw = RawBlock::decode(block.encode_to_vec(), manager.limits).map_err(|error| error.to_string())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|error| error.to_string())?.as_millis();
    let now = i64::try_from(now).map_err(|_| "system time exceeds i64".to_owned())?;
    manager.apply_block(raw, now).map(|id| id.height()).map_err(|error| error.to_string())
}

/// Publishes the durable solid marker and refreshes the live API Solidity cursor.
pub struct StateReplicaCheckpoint {
    sessions: SessionManager,
    api: ApiContext,
}
impl StateReplicaCheckpoint {
    pub fn new(sessions: SessionManager, api: ApiContext) -> Self { Self { sessions, api } }
}
impl ReplicaCheckpoint for StateReplicaCheckpoint {
    fn latest_solidified(&self) -> Result<i64, String> {
        let key = dynamic::key("LATEST_SOLIDIFIED_BLOCK_NUM").expect("known dynamic key");
        let published = match self.sessions.read_view().store(StoreKind::DynamicProperties).get(key) {
            None => 0,
            Some(bytes) => bytes.as_slice().try_into().map(i64::from_be_bytes).map_err(|_| "LATEST_SOLIDIFIED_BLOCK_NUM is not i64".to_owned())?,
        };
        let Some(committed) = self.sessions.latest_checkpoint() else { return Ok(published); };
        let committed_height = i64::try_from(committed.block).map_err(|_| "committed checkpoint height exceeds i64".to_owned())?;
        if published > committed_height {
            return Err(format!("solidified marker {published} is ahead of committed checkpoint {committed_height}"));
        }
        if published < committed_height {
            self.sessions.publish_committed_metadata(StoreKind::DynamicProperties, key, &committed_height.to_be_bytes()).map_err(|error| error.to_string())?;
            let cursors = CursorSet::with_live_solidity(&self.sessions, committed).map_err(|error| error.to_string())?;
            self.api.publish_cursors(cursors);
        }
        Ok(committed_height)
    }
    fn publish(&self, height: i64) -> Result<(), String> {
        let point = self.sessions.latest_checkpoint().ok_or_else(|| "missing committed block checkpoint".to_owned())?;
        if point.block != u64::try_from(height).map_err(|_| "negative solidified height".to_owned())? {
            return Err(format!("checkpoint height {} does not match applied height {height}", point.block));
        }
        let key = dynamic::key("LATEST_SOLIDIFIED_BLOCK_NUM").expect("known dynamic key");
        self.sessions.publish_committed_metadata(StoreKind::DynamicProperties, key, &height.to_be_bytes()).map_err(|error| error.to_string())?;
        let cursors = CursorSet::with_live_solidity(&self.sessions, point).map_err(|error| error.to_string())?;
        self.api.publish_cursors(cursors);
        Ok(())
    }
}

struct ReplicaRunner {
    source: Box<dyn DatabaseSource>,
    applier: Box<dyn VerifiedBlockApplier>,
    checkpoint: Arc<dyn ReplicaCheckpoint>,
}

pub struct SolidityReplica {
    runner: Option<ReplicaRunner>,
    task: Option<tokio::task::JoinHandle<Result<(), String>>>,
    supervisor: Option<(NodeStatus, StopHandle)>,
}
impl SolidityReplica {
    pub fn new(source: Box<dyn DatabaseSource>, applier: Box<dyn VerifiedBlockApplier>, checkpoint: Arc<dyn ReplicaCheckpoint>) -> Self {
        Self { runner: Some(ReplicaRunner { source, applier, checkpoint }), task: None, supervisor: None }
    }

    pub fn supervised(source: Box<dyn DatabaseSource>, applier: Box<dyn VerifiedBlockApplier>, checkpoint: Arc<dyn ReplicaCheckpoint>, status: NodeStatus, stop: StopHandle) -> Self {
        Self { runner: Some(ReplicaRunner { source, applier, checkpoint }), task: None, supervisor: Some((status, stop)) }
    }

    pub async fn run(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        let runner = self.runner.as_mut().ok_or_else(|| "Solidity replica is already running".to_owned())?;
        runner.run(cancellation).await
    }
}

impl ReplicaRunner {
    async fn run(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        let mut next = self.checkpoint.latest_solidified()?.checked_add(1).ok_or_else(|| "solidified height overflow".to_owned())?;
        let (queue_tx, mut queue_rx) = tokio::sync::mpsc::channel(REPLICA_QUEUE_CAPACITY);
        loop {
            if cancellation.is_cancelled() { return Ok(()); }
            let properties = match interrupt(cancellation, self.source.get_dynamic_properties()).await {
                Interrupted::Cancelled => return Ok(()),
                Interrupted::Ready(Ok(value)) => value,
                Interrupted::Ready(Err(_)) => { if sleep_or_cancel(cancellation, ERROR_RETRY).await { return Ok(()); } continue; }
            };
            if next > properties.last_solidity_block_num {
                if sleep_or_cancel(cancellation, CAUGHT_UP_POLL).await { return Ok(()); }
                continue;
            }
            let block = match interrupt(cancellation, self.source.get_block_by_num(next)).await {
                Interrupted::Cancelled => return Ok(()),
                Interrupted::Ready(Ok(value)) => value,
                Interrupted::Ready(Err(_)) => { if sleep_or_cancel(cancellation, ERROR_RETRY).await { return Ok(()); } continue; }
            };
            queue_tx.send(block).await.map_err(|_| "replica block queue closed".to_owned())?;
            let block = queue_rx.recv().await.ok_or_else(|| "replica block queue closed".to_owned())?;
            let returned = block.block_header.as_ref().and_then(|header| header.raw_data.as_ref()).map(|raw| raw.number);
            if returned != Some(next) {
                if sleep_or_cancel(cancellation, ERROR_RETRY).await { return Ok(()); }
                continue;
            }
            // Java lets the current pushVerifiedBlock finish, but shutdown/hit-down visibility
            // suppresses marker publication. The next startup reconciles that stale marker to the
            // durable local checkpoint before asking the trust node for the following height.
            match self.applier.apply_verified(block) {
                Ok(applied) if applied == next => {
                    if cancellation.is_cancelled() { return Ok(()); }
                    self.checkpoint.publish(next)?;
                    next = next.checked_add(1).ok_or_else(|| "solidified height overflow".to_owned())?;
                }
                Ok(_) | Err(_) => {
                    if cancellation.is_cancelled() { return Ok(()); }
                    if sleep_or_cancel(cancellation, ERROR_RETRY).await { return Ok(()); }
                }
            }
        }
    }
}

enum Interrupted<T> { Ready(T), Cancelled }
async fn interrupt<T>(cancellation: &CancellationToken, future: impl Future<Output = T>) -> Interrupted<T> {
    tokio::select! { value = future => Interrupted::Ready(value), () = cancellation.cancelled() => Interrupted::Cancelled }
}
async fn sleep_or_cancel(cancellation: &CancellationToken, duration: Duration) -> bool {
    tokio::select! { () = cancellation.cancelled() => true, () = tokio::time::sleep(duration) => false }
}

impl NodeService for SolidityReplica {
    fn spec(&self) -> ServiceSpec { ServiceSpec::new(SOLIDITY_REPLICA_SERVICE, &[], &[ServiceMode::Solidity]) }
    fn start<'a>(&'a mut self, context: &'a NodeContext, _deadline: Duration) -> LifecycleFuture<'a> {
        Box::pin(async move {
            let mut runner = self.runner.take().ok_or_else(|| ServiceFailure { service: SOLIDITY_REPLICA_SERVICE, message: "replica already started".into() })?;
            let cancellation = context.cancellation().clone();
            let supervisor = self.supervisor.clone();
            self.task = Some(tokio::spawn(async move {
                let worker_cancellation = cancellation.clone();
                let worker = tokio::spawn(async move {
                    let result = runner.run(&worker_cancellation).await;
                    let shutdown = runner.source.shutdown().await.map_err(|error| error.to_string());
                    match (result, shutdown) {
                        (Ok(()), Ok(())) => Ok(()),
                        (Err(worker), Ok(())) => Err(worker),
                        (Ok(()), Err(shutdown)) => Err(shutdown),
                        (Err(worker), Err(shutdown)) => Err(format!("replica worker failed: {worker}; database source shutdown failed: {shutdown}")),
                    }
                });
                let result = match worker.await {
                    Ok(result) => result,
                    Err(error) => Err(error.to_string()),
                };
                if !cancellation.is_cancelled() {
                    if let Some((status, stop)) = supervisor {
                        let message = match &result {
                            Ok(()) => "solidity replica worker exited unexpectedly".to_owned(),
                            Err(message) => message.clone(),
                        };
                        if stop.request(StopCondition::Fatal(ServiceFailure { service: SOLIDITY_REPLICA_SERVICE, message })).is_ok() { status.mark_unhealthy(); }
                    }
                }
                result
            }));
            Ok(())
        })
    }
    fn stop<'a>(&'a mut self, _context: &'a NodeContext, _deadline: Duration) -> LifecycleFuture<'a> {
        Box::pin(async move {
            let Some(task) = self.task.as_mut() else { return Ok(()); };
            let result = match task.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(message)) => Err(ServiceFailure { service: SOLIDITY_REPLICA_SERVICE, message }),
                Err(error) => Err(ServiceFailure { service: SOLIDITY_REPLICA_SERVICE, message: error.to_string() }),
            };
            self.task = None;
            result
        })
    }
}
