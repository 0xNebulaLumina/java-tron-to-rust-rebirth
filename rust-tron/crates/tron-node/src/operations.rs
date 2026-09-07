//! C025 operational-service composition and process stop coordination.

use std::{collections::VecDeque, future::Future, pin::Pin, sync::Arc, time::Duration};

use parking_lot::Mutex;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::{Semaphore, mpsc}, task::{JoinHandle, JoinSet}, time::Instant};
use tokio_util::sync::CancellationToken as TokioCancellationToken;
use tron_apis::{ApiContext, FilterManager, RpcApiServices, RpcDomainProvider, TonicDatabaseSource};
use tron_config::NodeMode;
use tron_events_metrics::{DbStatService, Delivery, DeliveryWorker, EventQueues, MetricsRegistry, MonitorMetrics, PluginConfig, ProcessPlugin, QueueClass, TransactionalEventSink, ZeroMqConfig, ZeroMqPublisher};
use tron_protocol::protocol::NodeInfo;
use tron_state::SessionManager;

use crate::{LifecycleError, LifecycleFuture, NodeContext, NodeService, ServiceFailure, ServiceGraph, ServiceGraphState, ServiceMode, ServiceSpec};
use crate::solidity_replica::{SolidityReplica, StateReplicaCheckpoint, VerifiedBlockApplier};

pub const NETWORK_SERVICE: &str = "network";
pub const API_SERVICE: &str = "apis";
pub const API_PROVIDER_SERVICE: &str = "operations-api-provider";
pub const EVENT_QUEUE_SERVICE: &str = "event-queues";
pub const EVENT_PLUGIN_SERVICE: &str = "event-plugin";
pub const ZEROMQ_SERVICE: &str = "zeromq";
pub const METRICS_SERVICE: &str = "monitor-metrics";
pub const PROMETHEUS_SERVICE: &str = "prometheus";
pub const DB_STATS_SERVICE: &str = "db-stats";
pub const READINESS_SERVICE: &str = "node-readiness";

pub type HookFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// Narrow ownership boundary implemented by concrete event, exporter, plugin, and task services.
pub trait OperationalHooks: Send {
    fn start<'a>(&'a mut self, deadline: Duration) -> HookFuture<'a>;
    fn cancel_ingress<'a>(&'a mut self, _deadline: Duration) -> HookFuture<'a> { Box::pin(async { Ok(()) }) }
    fn drain<'a>(&'a mut self, _deadline: Duration) -> HookFuture<'a> { Box::pin(async { Ok(()) }) }
    fn flush<'a>(&'a mut self, _deadline: Duration) -> HookFuture<'a> { Box::pin(async { Ok(()) }) }
    fn stop<'a>(&'a mut self, deadline: Duration) -> HookFuture<'a>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownPlan { CancelDrainFlushStop, DrainFlushStop, FlushStop, Stop }

pub struct OperationalService {
    spec: ServiceSpec,
    plan: ShutdownPlan,
    hooks: Box<dyn OperationalHooks>,
}

impl OperationalService {
    #[must_use]
    pub fn new(spec: ServiceSpec, plan: ShutdownPlan, hooks: Box<dyn OperationalHooks>) -> Self {
        Self { spec, plan, hooks }
    }
}

impl NodeService for OperationalService {
    fn spec(&self) -> ServiceSpec { self.spec.clone() }
    fn start<'a>(&'a mut self, _context: &'a NodeContext, deadline: Duration) -> LifecycleFuture<'a> {
        let name = self.spec.name;
        Box::pin(async move { self.hooks.start(deadline).await.map_err(|message| ServiceFailure { service: name, message }) })
    }
    fn stop<'a>(&'a mut self, _context: &'a NodeContext, deadline: Duration) -> LifecycleFuture<'a> {
        let name = self.spec.name;
        Box::pin(async move {
            let mut failures = Vec::new();
            if self.plan == ShutdownPlan::CancelDrainFlushStop {
                if let Err(error) = self.hooks.cancel_ingress(deadline).await { failures.push(error); }
            }
            if matches!(self.plan, ShutdownPlan::CancelDrainFlushStop | ShutdownPlan::DrainFlushStop) {
                if let Err(error) = self.hooks.drain(deadline).await { failures.push(error); }
            }
            if matches!(self.plan, ShutdownPlan::CancelDrainFlushStop | ShutdownPlan::DrainFlushStop | ShutdownPlan::FlushStop) {
                if let Err(error) = self.hooks.flush(deadline).await { failures.push(error); }
            }
            if let Err(error) = self.hooks.stop(deadline).await { failures.push(error); }
            if failures.is_empty() { Ok(()) } else { Err(ServiceFailure { service: name, message: failures.join("; ") }) }
        })
    }
}

/// Concrete C025 graph tail. The caller prepends state/consensus/network/API services.
pub struct OperationsComponents {
    pub api_provider: Box<dyn OperationalHooks>,
    pub queues: Box<dyn OperationalHooks>,
    pub plugin: Box<dyn OperationalHooks>,
    pub zeromq: Box<dyn OperationalHooks>,
    pub metrics: Box<dyn OperationalHooks>,
    pub prometheus: Box<dyn OperationalHooks>,
    pub db_stats: Box<dyn OperationalHooks>,
    pub readiness: Box<dyn OperationalHooks>,
}

fn operational_service_graph_with_roots(
    components: OperationsComponents,
    api_provider_dependencies: &'static [&'static str],
    metrics_dependencies: &'static [&'static str],
) -> Vec<Box<dyn NodeService>> {
    let all_modes = &[ServiceMode::Full, ServiceMode::Solidity][..0]; // enabled in either node mode
    vec![
        Box::new(OperationalService::new(ServiceSpec::new(API_PROVIDER_SERVICE, api_provider_dependencies, all_modes), ShutdownPlan::CancelDrainFlushStop, components.api_provider)),
        Box::new(OperationalService::new(ServiceSpec::new(EVENT_QUEUE_SERVICE, &[API_PROVIDER_SERVICE], all_modes), ShutdownPlan::CancelDrainFlushStop, components.queues)),
        Box::new(OperationalService::new(ServiceSpec::new(EVENT_PLUGIN_SERVICE, &[EVENT_QUEUE_SERVICE], all_modes), ShutdownPlan::DrainFlushStop, components.plugin)),
        Box::new(OperationalService::new(ServiceSpec::new(ZEROMQ_SERVICE, &[EVENT_QUEUE_SERVICE], all_modes), ShutdownPlan::DrainFlushStop, components.zeromq)),
        Box::new(OperationalService::new(ServiceSpec::new(METRICS_SERVICE, metrics_dependencies, all_modes), ShutdownPlan::FlushStop, components.metrics)),
        Box::new(OperationalService::new(ServiceSpec::new(PROMETHEUS_SERVICE, &[METRICS_SERVICE], all_modes), ShutdownPlan::CancelDrainFlushStop, components.prometheus)),
        Box::new(OperationalService::new(ServiceSpec::new(DB_STATS_SERVICE, &[METRICS_SERVICE], all_modes), ShutdownPlan::Stop, components.db_stats)),
        Box::new(OperationalService::new(ServiceSpec::new(READINESS_SERVICE, &[EVENT_PLUGIN_SERVICE, ZEROMQ_SERVICE, PROMETHEUS_SERVICE, DB_STATS_SERVICE], all_modes), ShutdownPlan::CancelDrainFlushStop, components.readiness)),
    ]
}

#[must_use]
pub fn operational_service_graph(components: OperationsComponents) -> Vec<Box<dyn NodeService>> {
    operational_service_graph_with_roots(components, &[NETWORK_SERVICE, API_SERVICE], &[NETWORK_SERVICE, API_SERVICE])
}

#[derive(Default)]
struct NodeStatusState {
    ready: bool,
    healthy: bool,
    accepting_ingress: bool,
    fatal: bool,
    causes: VecDeque<ServiceFailure>,
}

#[derive(Clone, Default)]
pub struct NodeStatus {
    state: Arc<Mutex<NodeStatusState>>,
}
impl NodeStatus {
    pub fn mark_running(&self) -> bool {
        let mut state = self.state.lock();
        if state.fatal { return false; }
        state.healthy = true;
        state.accepting_ingress = true;
        state.ready = true;
        true
    }
    pub fn revoke_readiness(&self) { let mut state = self.state.lock(); state.ready = false; state.accepting_ingress = false; }
    pub fn mark_unhealthy(&self) { let mut state = self.state.lock(); state.fatal = true; state.ready = false; state.accepting_ingress = false; state.healthy = false; }
    #[must_use] pub fn is_ready(&self) -> bool { self.state.lock().ready }
    #[must_use] pub fn is_healthy(&self) -> bool { self.state.lock().healthy }
    #[must_use] pub fn accepts_ingress(&self) -> bool { self.state.lock().accepting_ingress }
    #[must_use] pub fn is_fatal(&self) -> bool { self.state.lock().fatal }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopCondition { Interrupt, Terminate, Operator, Fatal(ServiceFailure) }

#[derive(Clone)]
pub struct StopHandle {
    sender: mpsc::UnboundedSender<StopCondition>,
    state: Arc<Mutex<NodeStatusState>>,
}
pub struct StopController {
    receiver: mpsc::UnboundedReceiver<StopCondition>,
    state: Arc<Mutex<NodeStatusState>>,
}
impl StopController {
    #[must_use]
    pub fn new() -> (StopHandle, Self) { Self::new_with_status(NodeStatus::default()) }
    #[must_use]
    pub fn new_with_status(status: NodeStatus) -> (StopHandle, Self) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let state = status.state;
        (StopHandle { sender, state: state.clone() }, Self { receiver, state })
    }
    pub async fn wait(&mut self) -> StopCondition { self.receiver.recv().await.unwrap_or(StopCondition::Operator) }
    #[must_use] pub fn peek_fatal(&self) -> Option<ServiceFailure> { self.state.lock().causes.front().cloned() }
    pub fn drain_all_fatal(&mut self) -> Vec<ServiceFailure> { self.state.lock().causes.drain(..).collect() }
    fn shares_status(&self, status: &NodeStatus) -> bool { Arc::ptr_eq(&self.state, &status.state) }
}
impl StopHandle {
    pub fn request(&self, condition: StopCondition) -> Result<(), StopCondition> {
        if let StopCondition::Fatal(failure) = &condition {
            let mut state = self.state.lock();
            state.causes.push_back(failure.clone());
            state.fatal = true;
            state.ready = false;
            state.accepting_ingress = false;
            state.healthy = false;
            if let Err(error) = self.sender.send(condition) {
                state.causes.pop_back();
                return Err(error.0);
            }
            Ok(())
        } else {
            self.sender.send(condition).map_err(|error| error.0)
        }
    }
}

#[must_use]
pub fn production_service_graph(mut core_services:Vec<Box<dyn NodeService>>,network:Box<dyn NodeService>,apis:Box<dyn NodeService>,operations:OperationsComponents)->Vec<Box<dyn NodeService>>{
    core_services.push(network);
    core_services.push(apis);
    core_services.extend(operational_service_graph(operations));
    core_services
}
/// Solidity composition starts replication after the core state/execution prefix, then exposes
/// standalone APIs and readiness. It deliberately excludes the network service: a Solidity node
/// consumes its trust node over the database client and never owns a P2P server.
#[must_use]
pub fn solidity_production_service_graph(
    mut core_services: Vec<Box<dyn NodeService>>,
    replica: Box<dyn NodeService>,
    _network: Box<dyn NodeService>,
    apis: Box<dyn NodeService>,
    operations: OperationsComponents,
) -> Vec<Box<dyn NodeService>> {
    core_services.push(replica);
    core_services.push(apis);
    core_services.extend(operational_service_graph_with_roots(
        operations,
        &[crate::solidity_replica::SOLIDITY_REPLICA_SERVICE, API_SERVICE],
        &[crate::solidity_replica::SOLIDITY_REPLICA_SERVICE, API_SERVICE],
    ));
    core_services
}


#[derive(Clone)]
pub struct ProductionOperationalBindings {
    api_context:ApiContext,
    provider:RpcDomainProvider,
    queues:Arc<EventQueues>,
    filters:Arc<FilterManager>,
    metrics:Arc<MonitorMetrics>,
}
impl ProductionOperationalBindings {
    #[must_use] pub fn new(api_context:ApiContext,node_info:Arc<dyn Fn()->NodeInfo+Send+Sync>,queues:Arc<EventQueues>,filters:Arc<FilterManager>,metrics:Arc<MonitorMetrics>)->Self{let monitor_metrics=metrics.clone();let monitor:Arc<dyn tron_apis::MonitorSource>=Arc::new(move||monitor_metrics.snapshot());let provider=RpcDomainProvider::with_operational_sources(api_context.clone(),monitor,node_info);Self{api_context,provider,queues,filters,metrics}}
    #[must_use] pub fn rpc_provider(&self)->RpcDomainProvider{self.provider.clone()}
    #[must_use] pub fn rpc_services(&self)->RpcApiServices{RpcApiServices::with_provider(self.api_context.clone(),self.provider.clone())}
    #[must_use] pub fn event_sink(&self)->TransactionalEventSink{self.queues.sink()}
    #[must_use] pub fn api_context(&self)->ApiContext{self.api_context.clone()}
    #[must_use] pub fn filter_sink(&self)->tron_apis::ProductionFilterSink{self.filters.sink()}
    #[must_use] pub fn metrics(&self)->Arc<MonitorMetrics>{self.metrics.clone()}
}

/// Neutral inputs for custom production composition. Fatal/readiness-aware hooks must be built
/// by the factory from the supplied `NodeStatus` and `StopHandle` clones.
pub struct ProductionNodeComposition {
    pub context: NodeContext,
    pub mode: NodeMode,
    pub bindings: ProductionOperationalBindings,
}

pub struct ProductionNodeServices {
    pub core_services: Vec<Box<dyn NodeService>>,
    pub network: Box<dyn NodeService>,
    pub apis: Box<dyn NodeService>,
    pub operations: OperationsComponents,
    pub replica: Option<Box<dyn NodeService>>,
}

pub struct ProductionNode {
    graph: ServiceGraph,
    status: NodeStatus,
    stop: StopHandle,
    controller: StopController,
    pub rpc_provider: RpcDomainProvider,
    pub rpc_services: RpcApiServices,
    pub event_sink: TransactionalEventSink,
    pub filter_sink: tron_apis::ProductionFilterSink,
    pub metrics: Arc<MonitorMetrics>,
}

impl ProductionNode {
    pub fn from_service_factory<F>(composition: ProductionNodeComposition, factory: F) -> Result<Self, LifecycleError>
    where
        F: FnOnce(NodeStatus, StopHandle) -> ProductionNodeServices,
    {
        composition.context.config().validate_for_mode(composition.mode).map_err(|error| LifecycleError::InvalidConfiguration(error.to_string()))?;
        let status=NodeStatus::default();
        let (stop,controller)=StopController::new_with_status(status.clone());
        let parts=factory(status.clone(),stop.clone());
        let provider=composition.bindings.rpc_provider();
        let rpc_services=composition.bindings.rpc_services();
        let event_sink=composition.bindings.event_sink();
        let filter_sink=composition.bindings.filter_sink();
        let metrics=composition.bindings.metrics();
        let services=match (composition.mode, parts.replica) {
            (NodeMode::Solidity, Some(replica)) => solidity_production_service_graph(parts.core_services, replica, parts.network, parts.apis, parts.operations),
            (NodeMode::Solidity, None) => return Err(LifecycleError::InvalidConfiguration("Solidity mode requires a replica service".into())),
            (_, Some(_)) => return Err(LifecycleError::InvalidConfiguration("replica service is only valid in Solidity mode".into())),
            (_, None) => production_service_graph(parts.core_services, parts.network, parts.apis, parts.operations),
        };
        let graph=ServiceGraph::new(composition.context,composition.mode,services)?;
        debug_assert!(controller.shares_status(&status));
        Ok(Self{graph,status,stop,controller,rpc_provider:provider,rpc_services,event_sink,filter_sink,metrics})
    }
    #[must_use] pub fn status(&self)->NodeStatus{self.status.clone()}
    #[must_use] pub fn stop_handle(&self)->StopHandle{self.stop.clone()}
    pub async fn start(&mut self,start_timeout:Duration,shutdown_timeout:Duration)->Result<(),LifecycleError>{
        if let Err(error) = self.graph.start(start_timeout,shutdown_timeout).await {
            return Err(self.startup_failure(error));
        }
        if self.status.mark_running(){return Ok(());}
        self.status.revoke_readiness();
        let original=LifecycleError::StartupFailure(ServiceFailure{service:READINESS_SERVICE,message:"node became fatally unhealthy during startup".into()});
        let error=match self.graph.shutdown(shutdown_timeout).await {
            Ok(())=>original,
            Err(unwind)=>LifecycleError::StartupUnwindFailure{startup:Box::new(original),unwind:Box::new(unwind)},
        };
        Err(self.startup_failure(error))
    }
    fn startup_failure(&mut self, error: LifecycleError) -> LifecycleError {
        let fatals=self.controller.drain_all_fatal();
        match error {
            LifecycleError::StartupUnwindFailure{startup,unwind}=>LifecycleError::StartupLifecycleFailure{
                fatals,
                startup,
                unwind:Some(unwind),
            },
            LifecycleError::StartupLifecycleFailure{fatals:mut existing,startup,unwind}=>{
                existing.extend(fatals);
                LifecycleError::StartupLifecycleFailure{fatals:existing,startup,unwind}
            }
            startup=>LifecycleError::StartupLifecycleFailure{fatals,startup:Box::new(startup),unwind:None},
        }
    }
    async fn finish_shutdown(&mut self, condition: StopCondition, shutdown_timeout: Duration) -> Result<StopCondition, LifecycleError> {
        self.status.revoke_readiness();
        let shutdown = self.graph.shutdown(shutdown_timeout).await.err();
        let fatals = self.controller.drain_all_fatal();
        if fatals.is_empty() {
            return shutdown.map_or(Ok(condition), Err);
        }
        Err(LifecycleError::FatalShutdown { fatals, shutdown: shutdown.map(Box::new) })
    }
    pub async fn wait_and_shutdown(&mut self,shutdown_timeout:Duration)->Result<StopCondition,LifecycleError>{
        let condition=self.controller.wait().await;
        self.finish_shutdown(condition,shutdown_timeout).await
    }
    #[cfg(unix)]
    pub async fn wait_for_signal_and_shutdown(&mut self,shutdown_timeout:Duration)->Result<StopCondition,LifecycleError>{
        use tokio::signal::unix::{SignalKind,signal};
        let mut interrupt=signal(SignalKind::interrupt()).expect("install SIGINT handler");
        let mut terminate=signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let condition=tokio::select!{_ = interrupt.recv()=>StopCondition::Interrupt,_ = terminate.recv()=>StopCondition::Terminate,requested=self.controller.wait()=>requested};
        self.finish_shutdown(condition,shutdown_timeout).await
    }
    #[must_use] pub fn started_services(&self)->impl Iterator<Item=&'static str>+'_ { self.graph.started_services() }
    #[must_use] pub fn graph_state(&self)->ServiceGraphState{self.graph.state()}
}

pub struct EventQueueHooks { queues: Arc<EventQueues> }
impl EventQueueHooks { #[must_use] pub fn new(queues: Arc<EventQueues>) -> Self { Self { queues } } }
impl OperationalHooks for EventQueueHooks {
    fn start<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.queues.open(); Ok(()) }) }
    fn cancel_ingress<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.queues.close(); Ok(()) }) }
    fn drain<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { for class in [QueueClass::History, QueueClass::Realtime, QueueClass::Solid] { let _ = self.queues.drain(class, usize::MAX); } Ok(()) }) }
    fn stop<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.queues.close(); Ok(()) }) }
}

#[derive(Debug)]
struct DeliveryTaskFailure {
    service: &'static str,
    message: String,
}

impl DeliveryTaskFailure {
    fn new(service: &'static str, error: impl ToString) -> Self {
        Self { service, message: error.to_string() }
    }

    fn service_failure(&self) -> ServiceFailure {
        ServiceFailure { service: self.service, message: self.message.clone() }
    }
}

pub struct EventDeliveryHooks {
    queues: Arc<EventQueues>,
    plugin_config: Option<PluginConfig>,
    zeromq_config: Option<ZeroMqConfig>,
    cancel: TokioCancellationToken,
    task: Option<JoinHandle<Result<(), DeliveryTaskFailure>>>,
    retry_limit: usize,
    status: NodeStatus,
    stop: StopHandle,
}
impl EventDeliveryHooks {
    #[must_use]
    pub fn new(queues: Arc<EventQueues>, plugin: Option<PluginConfig>, zeromq: Option<ZeroMqConfig>, status: NodeStatus, stop: StopHandle) -> Self {
        Self { queues, plugin_config: plugin, zeromq_config: zeromq, cancel: TokioCancellationToken::new(), task: None, retry_limit: 2, status, stop }
    }
}
impl OperationalHooks for EventDeliveryHooks {
    fn start<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move {
        self.queues.open();
        self.cancel = TokioCancellationToken::new();
        let plugin_config = self.plugin_config.clone();
        let mut plugin = if let Some(config) = plugin_config.clone() { Some(tokio::task::spawn_blocking(move || ProcessPlugin::start(&config)).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?) } else { None };
        let mut zeromq = if let Some(config) = self.zeromq_config { Some(ZeroMqPublisher::bind(config).await.map_err(|error| error.to_string())?) } else { None };
        let queues = self.queues.clone();
        let worker_queues = queues.clone();
        let cancel = self.cancel.clone();
        let worker_cancel = cancel.clone();
        let retry_limit = self.retry_limit;
        let status = self.status.clone();
        let stop = self.stop.clone();
        self.task = Some(tokio::spawn(async move {
            let worker = tokio::spawn(async move {
                let mut worker = DeliveryWorker::new(worker_queues, retry_limit);
                loop {
                    let mut failure_service = EVENT_QUEUE_SERVICE;
                    let dispatch = worker.drain(|queued| {
                        let Delivery::Event(event) = &queued.delivery else { return Ok(()); };
                        if let (Some(config), Some(plugin)) = (plugin_config.as_ref(), plugin.as_mut()) {
                            if config.accepts(event, queued.class == QueueClass::History, queued.class == QueueClass::Solid) {
                                plugin.publish(event).map_err(|error| { failure_service = EVENT_PLUGIN_SERVICE; error.to_string() })?;
                            }
                        }
                        if let Some(publisher) = zeromq.as_ref() {
                            let json = match plugin_config.as_ref() { Some(config) => config.event_json(event), None => event.to_json() }.map_err(|error| { failure_service = ZEROMQ_SERVICE; error.to_string() })?;
                            publisher.publish(event.topic(), json).map_err(|error| { failure_service = ZEROMQ_SERVICE; error.to_string() })?;
                        }
                        Ok(())
                    });
                    if let Err(error) = dispatch { return Err(DeliveryTaskFailure::new(failure_service, error)); }
                    if worker_cancel.is_cancelled() { break; }
                    if let Some(plugin) = plugin.as_mut() { plugin.pending_probe().map_err(|error| DeliveryTaskFailure::new(EVENT_PLUGIN_SERVICE, error))?; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                if let Some(publisher) = zeromq.as_mut() { publisher.shutdown().await.map_err(|error| DeliveryTaskFailure::new(ZEROMQ_SERVICE, error))?; }
                if let Some(mut plugin) = plugin { tokio::task::spawn_blocking(move || plugin.shutdown()).await.map_err(|error| DeliveryTaskFailure::new(EVENT_PLUGIN_SERVICE, error))?.map_err(|error| DeliveryTaskFailure::new(EVENT_PLUGIN_SERVICE, error))?; }
                Ok(())
            });
            let result = match worker.await {
                Ok(result) => result,
                Err(error) => Err(DeliveryTaskFailure::new(EVENT_QUEUE_SERVICE, error)),
            };
            if !cancel.is_cancelled() {
                queues.close();
                let failure = match &result {
                    Err(error) => error.service_failure(),
                    Ok(()) => ServiceFailure { service: EVENT_QUEUE_SERVICE, message: "event delivery worker exited unexpectedly".into() },
                };
                if stop.request(StopCondition::Fatal(failure)).is_ok() { status.mark_unhealthy(); }
            }
            result
        }));
        Ok(())
    }) }
    fn cancel_ingress<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.queues.close(); self.cancel.cancel(); Ok(()) }) }
    fn drain<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { while [QueueClass::History, QueueClass::Realtime, QueueClass::Solid].iter().any(|class| self.queues.len(*class) != 0) { if self.task.as_ref().is_some_and(JoinHandle::is_finished) { break; } tokio::time::sleep(Duration::from_millis(5)).await; } Ok(()) }) }
    fn flush<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async { Ok(()) }) }
    fn stop<'a>(&'a mut self, deadline: Duration) -> HookFuture<'a> { Box::pin(async move {
        self.cancel.cancel();
        let Some(mut task) = self.task.take() else { return Ok(()); };
        let timeout = if deadline.is_zero() { Duration::from_secs(5) } else { deadline };
        match tokio::time::timeout(timeout, &mut task).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(format!("{}: {}", error.service, error.message)),
            Ok(Err(error)) => Err(error.to_string()),
            Err(_) => { task.abort(); let _ = task.await; Err("event delivery worker shutdown timed out".into()) }
        }
    }) }
}

struct NoopHooks;
impl OperationalHooks for NoopHooks { fn start<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async { Ok(()) }) } fn stop<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async { Ok(()) }) } }

pub struct ProcessPluginHooks { config: Option<PluginConfig>, plugin: Option<ProcessPlugin> }
impl ProcessPluginHooks { #[must_use] pub fn new(config: Option<PluginConfig>) -> Self { Self { config, plugin: None } } }
impl OperationalHooks for ProcessPluginHooks {
    fn start<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move {
        let Some(config) = self.config.clone() else { return Ok(()); };
        let plugin = tokio::task::spawn_blocking(move || ProcessPlugin::start(&config)).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
        self.plugin = Some(plugin); Ok(())
    }) }
    fn flush<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { let Some(mut plugin) = self.plugin.take() else { return Ok(()); }; let (plugin, result) = tokio::task::spawn_blocking(move || { let result = plugin.pending_probe(); (plugin, result) }).await.map_err(|error| error.to_string())?; self.plugin = Some(plugin); result.map_err(|error| error.to_string()) }) }
    fn stop<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move {
        let Some(mut plugin) = self.plugin.take() else { return Ok(()); };
        tokio::task::spawn_blocking(move || plugin.shutdown()).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())
    }) }
}

pub struct ZeroMqHooks { config: Option<ZeroMqConfig>, publisher: Option<ZeroMqPublisher> }
impl ZeroMqHooks { #[must_use] pub fn new(config: Option<ZeroMqConfig>) -> Self { Self { config, publisher: None } } }
impl OperationalHooks for ZeroMqHooks {
    fn start<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { if let Some(config) = self.config { self.publisher = Some(ZeroMqPublisher::bind(config).await.map_err(|error| error.to_string())?); } Ok(()) }) }
    fn stop<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { if let Some(mut publisher) = self.publisher.take() { publisher.shutdown().await.map_err(|error| error.to_string())?; } Ok(()) }) }
}

pub struct MetricsHooks { metrics: Arc<MonitorMetrics> }
impl MetricsHooks { #[must_use] pub fn new(metrics: Arc<MonitorMetrics>) -> Self { Self { metrics } } }
impl OperationalHooks for MetricsHooks {
    fn start<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.metrics.prometheus().set_enabled(true); Ok(()) }) }
    fn flush<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { let _ = self.metrics.snapshot(); Ok(()) }) }
    fn stop<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { Ok(()) }) }
}

const PROMETHEUS_MAX_CONNECTIONS: usize = 16;
const PROMETHEUS_MAX_REQUEST_BYTES: usize = 8 * 1024;
const PROMETHEUS_REQUEST_DEADLINE: Duration = Duration::from_secs(2);
const PROMETHEUS_IDLE_DEADLINE: Duration = Duration::from_millis(500);

pub struct PrometheusHttpHooks { address: Option<std::net::SocketAddr>, registry: MetricsRegistry, cancel: TokioCancellationToken, task: Option<JoinHandle<Result<(), String>>> }
impl PrometheusHttpHooks { #[must_use] pub fn new(address: Option<std::net::SocketAddr>, registry: MetricsRegistry) -> Self { Self { address, registry, cancel: TokioCancellationToken::new(), task: None } } }

async fn prometheus_io<T>(cancel: &TokioCancellationToken, absolute: Instant, operation: impl Future<Output = std::io::Result<T>>) -> Result<T, String> {
    let idle = Instant::now() + PROMETHEUS_IDLE_DEADLINE;
    let deadline = absolute.min(idle);
    tokio::select! {
        () = cancel.cancelled() => Err("Prometheus HTTP request cancelled".into()),
        result = tokio::time::timeout_at(deadline, operation) => result.map_err(|_| "Prometheus HTTP request timed out".to_owned())?.map_err(|error| error.to_string()),
    }
}

async fn serve_prometheus_client(mut stream: TcpStream, registry: MetricsRegistry, cancel: TokioCancellationToken) -> Result<(), String> {
    let absolute = Instant::now() + PROMETHEUS_REQUEST_DEADLINE;
    let mut request = Vec::with_capacity(1024);
    loop {
        if request.len() == PROMETHEUS_MAX_REQUEST_BYTES { return Err("Prometheus HTTP request exceeded byte limit".into()); }
        let remaining = PROMETHEUS_MAX_REQUEST_BYTES - request.len();
        let mut buffer = [0u8; 1024];
        let read_len = remaining.min(buffer.len());
        let count = prometheus_io(&cancel, absolute, stream.read(&mut buffer[..read_len])).await?;
        if count == 0 { return Err("Prometheus HTTP client closed before sending headers".into()); }
        request.extend_from_slice(&buffer[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") { break; }
    }

    let metrics = request.starts_with(b"GET /metrics ");
    let body = if metrics { registry.scrape() } else { "not found\n".to_owned() };
    let status = if metrics { "200 OK" } else { "404 Not Found" };
    let header = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    prometheus_io(&cancel, absolute, stream.write_all(header.as_bytes())).await?;
    prometheus_io(&cancel, absolute, stream.write_all(body.as_bytes())).await?;
    prometheus_io(&cancel, absolute, stream.shutdown()).await
}

impl OperationalHooks for PrometheusHttpHooks {
    fn start<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move {
        let Some(address) = self.address else { return Ok(()); };
        if self.task.is_some() { return Err("Prometheus HTTP server is already running".into()); }
        let listener = TcpListener::bind(address).await.map_err(|error| error.to_string())?;
        self.cancel = TokioCancellationToken::new();
        let cancel = self.cancel.clone();
        let registry = self.registry.clone();
        self.task = Some(tokio::spawn(async move {
            let semaphore = Arc::new(Semaphore::new(PROMETHEUS_MAX_CONNECTIONS));
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    completed = workers.join_next(), if !workers.is_empty() => {
                        if let Some(Err(error)) = completed { eprintln!("Prometheus HTTP worker task failed: {error}"); }
                    }
                    accepted = listener.accept() => match accepted {
                        Ok((stream, peer)) => match semaphore.clone().try_acquire_owned() {
                            Ok(permit) => {
                                let registry = registry.clone();
                                let cancel = cancel.clone();
                                workers.spawn(async move {
                                    let _permit = permit;
                                    if let Err(error) = serve_prometheus_client(stream, registry, cancel).await {
                                        eprintln!("Prometheus HTTP client {peer} failed: {error}");
                                    }
                                });
                            }
                            Err(_) => eprintln!("Prometheus HTTP connection from {peer} rejected: connection limit reached"),
                        },
                        Err(error) => eprintln!("Prometheus HTTP accept failed: {error}"),
                    },
                }
            }
            drop(listener);
            let drain_deadline = Instant::now() + Duration::from_secs(1);
            while !workers.is_empty() {
                match tokio::time::timeout_at(drain_deadline, workers.join_next()).await {
                    Ok(Some(Err(error))) => eprintln!("Prometheus HTTP worker task failed during shutdown: {error}"),
                    Ok(Some(Ok(()))) => {}
                    Ok(None) => break,
                    Err(_) => { workers.abort_all(); while workers.join_next().await.is_some() {} break; }
                }
            }
            Ok(())
        }));
        Ok(())
    }) }
    fn cancel_ingress<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.cancel.cancel(); Ok(()) }) }
    fn stop<'a>(&'a mut self, deadline: Duration) -> HookFuture<'a> { Box::pin(async move {
        self.cancel.cancel();
        if let Some(mut task) = self.task.take() {
            let wait = if deadline.is_zero() { Duration::from_secs(2) } else { deadline };
            match tokio::time::timeout(wait, &mut task).await {
                Ok(Ok(result)) => result?,
                Ok(Err(error)) => return Err(error.to_string()),
                Err(_) => { task.abort(); let _ = task.await; return Err("Prometheus HTTP shutdown timed out".into()); }
            }
        }
        Ok(())
    }) }
}

pub struct DbStatsHooks { service: Option<DbStatService> }
impl DbStatsHooks { #[must_use] pub fn new(service: DbStatService) -> Self { Self { service: Some(service) } } }
impl OperationalHooks for DbStatsHooks { fn start<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async { Ok(()) }) } fn stop<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { if let Some(mut service) = self.service.take() { tokio::task::spawn_blocking(move || service.shutdown()).await.map_err(|error| error.to_string())?; } Ok(()) }) } }

pub struct SharedApiProviderHooks { _bindings: ProductionOperationalBindings }
impl SharedApiProviderHooks { #[must_use] pub fn new(bindings: ProductionOperationalBindings) -> Self { Self { _bindings: bindings } } }
impl OperationalHooks for SharedApiProviderHooks { fn start<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async { Ok(()) }) } fn stop<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async { Ok(()) }) } }

pub struct ReadinessHooks { status: NodeStatus }
impl ReadinessHooks { #[must_use] pub fn new(status: NodeStatus) -> Self { Self { status } } }
impl OperationalHooks for ReadinessHooks { fn start<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { if self.status.mark_running() { Ok(()) } else { Err("node became fatally unhealthy during startup".into()) } }) } fn cancel_ingress<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.status.revoke_readiness(); Ok(()) }) } fn stop<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.status.mark_unhealthy(); Ok(()) }) } }

#[derive(Clone, Default)]
pub struct ProductionOperationsConfig { pub plugin: Option<PluginConfig>, pub zeromq: Option<ZeroMqConfig>, pub prometheus_address: Option<std::net::SocketAddr> }

pub struct ProductionNodeDependencies {
    pub context: NodeContext,
    pub mode: NodeMode,
    pub core_services: Vec<Box<dyn NodeService>>,
    pub network: Box<dyn NodeService>,
    pub apis: Box<dyn NodeService>,
    pub bindings: ProductionOperationalBindings,
    pub sessions: SessionManager,
    /// The concrete C019 block manager, type-erased through `VerifiedBlockApplier`.
    pub verified_block_applier: Option<Box<dyn VerifiedBlockApplier>>,
    pub queues: Arc<EventQueues>,
    pub metrics: Arc<MonitorMetrics>,
    pub db_stats: DbStatService,
}

impl ProductionNode {
    pub fn from_dependencies(dependencies: ProductionNodeDependencies) -> Result<Self, LifecycleError> { Self::from_config(ProductionOperationsConfig::default(), dependencies) }
    pub fn from_config(config: ProductionOperationsConfig, dependencies: ProductionNodeDependencies) -> Result<Self, LifecycleError> {
        dependencies.context.config().validate_for_mode(dependencies.mode).map_err(|error| LifecycleError::InvalidConfiguration(error.to_string()))?;
        let status = NodeStatus::default();
        let (stop, controller) = StopController::new_with_status(status.clone());
        assert!(controller.shares_status(&status), "production stop controller must share node status state");
        let delivery = EventDeliveryHooks::new(dependencies.queues, config.plugin, config.zeromq, status.clone(), stop.clone());
        let operations = OperationsComponents {
            api_provider: Box::new(SharedApiProviderHooks::new(dependencies.bindings.clone())),
            queues: Box::new(delivery),
            plugin: Box::new(NoopHooks),
            zeromq: Box::new(NoopHooks),
            metrics: Box::new(MetricsHooks::new(dependencies.metrics.clone())),
            prometheus: Box::new(PrometheusHttpHooks::new(config.prometheus_address, dependencies.metrics.prometheus().clone())),
            db_stats: Box::new(DbStatsHooks::new(dependencies.db_stats)),
            readiness: Box::new(ReadinessHooks::new(status.clone())),
        };
        let services = if dependencies.mode == NodeMode::Solidity {
            let source = TonicDatabaseSource::from_host_port(&dependencies.context.config().node.trust_node).map_err(LifecycleError::InvalidConfiguration)?;
            let applier = dependencies.verified_block_applier.ok_or_else(|| LifecycleError::InvalidConfiguration("Solidity mode requires a C019 verified block applier".into()))?;
            let checkpoint = Arc::new(StateReplicaCheckpoint::new(dependencies.sessions, dependencies.bindings.api_context()));
            let replica = Box::new(SolidityReplica::supervised(Box::new(source), applier, checkpoint, status.clone(), stop.clone()));
            solidity_production_service_graph(dependencies.core_services, replica, dependencies.network, dependencies.apis, operations)
        } else {
            production_service_graph(dependencies.core_services, dependencies.network, dependencies.apis, operations)
        };
        let graph = ServiceGraph::new(dependencies.context, dependencies.mode, services)?;
        let bindings = dependencies.bindings;
        Ok(Self { graph, status, stop, controller, rpc_provider: bindings.rpc_provider(), rpc_services: bindings.rpc_services(), event_sink: bindings.event_sink(), filter_sink: bindings.filter_sink(), metrics: bindings.metrics() })
    }
}

pub fn compose_production_node(config: ProductionOperationsConfig, dependencies: ProductionNodeDependencies) -> Result<ProductionNode, LifecycleError> { ProductionNode::from_config(config, dependencies) }
