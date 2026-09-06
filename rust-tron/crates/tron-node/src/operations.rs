//! C025 operational-service composition and process stop coordination.

use std::{future::Future, pin::Pin, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};

use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::{Semaphore, mpsc}, task::{JoinHandle, JoinSet}, time::Instant};
use tokio_util::sync::CancellationToken as TokioCancellationToken;
use tron_apis::{ApiContext, FilterManager, RpcApiServices, RpcDomainProvider};
use tron_config::NodeMode;
use tron_events_metrics::{DbStatService, Delivery, DeliveryWorker, EventQueues, MetricsRegistry, MonitorMetrics, PluginConfig, ProcessPlugin, QueueClass, TransactionalEventSink, ZeroMqConfig, ZeroMqPublisher};
use tron_protocol::protocol::NodeInfo;

use crate::{LifecycleError, LifecycleFuture, NodeContext, NodeService, ServiceFailure, ServiceGraph, ServiceMode, ServiceSpec};

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

#[must_use]
pub fn operational_service_graph(components: OperationsComponents) -> Vec<Box<dyn NodeService>> {
    let all_modes = &[ServiceMode::Full, ServiceMode::Solidity][..0]; // enabled in either node mode
    vec![
        Box::new(OperationalService::new(ServiceSpec::new(API_PROVIDER_SERVICE, &[NETWORK_SERVICE, API_SERVICE], all_modes), ShutdownPlan::CancelDrainFlushStop, components.api_provider)),
        Box::new(OperationalService::new(ServiceSpec::new(EVENT_QUEUE_SERVICE, &[API_PROVIDER_SERVICE], all_modes), ShutdownPlan::CancelDrainFlushStop, components.queues)),
        Box::new(OperationalService::new(ServiceSpec::new(EVENT_PLUGIN_SERVICE, &[EVENT_QUEUE_SERVICE], all_modes), ShutdownPlan::DrainFlushStop, components.plugin)),
        Box::new(OperationalService::new(ServiceSpec::new(ZEROMQ_SERVICE, &[EVENT_QUEUE_SERVICE], all_modes), ShutdownPlan::DrainFlushStop, components.zeromq)),
        Box::new(OperationalService::new(ServiceSpec::new(METRICS_SERVICE, &[NETWORK_SERVICE, API_SERVICE], all_modes), ShutdownPlan::FlushStop, components.metrics)),
        Box::new(OperationalService::new(ServiceSpec::new(PROMETHEUS_SERVICE, &[METRICS_SERVICE], all_modes), ShutdownPlan::CancelDrainFlushStop, components.prometheus)),
        Box::new(OperationalService::new(ServiceSpec::new(DB_STATS_SERVICE, &[METRICS_SERVICE], all_modes), ShutdownPlan::Stop, components.db_stats)),
        Box::new(OperationalService::new(ServiceSpec::new(READINESS_SERVICE, &[EVENT_PLUGIN_SERVICE, ZEROMQ_SERVICE, PROMETHEUS_SERVICE, DB_STATS_SERVICE], all_modes), ShutdownPlan::CancelDrainFlushStop, components.readiness)),
    ]
}

#[derive(Clone, Default)]
pub struct NodeStatus {
    ready: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
    accepting_ingress: Arc<AtomicBool>,
}
impl NodeStatus {
    pub fn mark_running(&self) { self.healthy.store(true, Ordering::Release); self.accepting_ingress.store(true, Ordering::Release); self.ready.store(true, Ordering::Release); }
    pub fn revoke_readiness(&self) { self.ready.store(false, Ordering::Release); self.accepting_ingress.store(false, Ordering::Release); }
    pub fn mark_unhealthy(&self) { self.revoke_readiness(); self.healthy.store(false, Ordering::Release); }
    #[must_use] pub fn is_ready(&self) -> bool { self.ready.load(Ordering::Acquire) }
    #[must_use] pub fn is_healthy(&self) -> bool { self.healthy.load(Ordering::Acquire) }
    #[must_use] pub fn accepts_ingress(&self) -> bool { self.accepting_ingress.load(Ordering::Acquire) }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopCondition { Interrupt, Terminate, Operator, Fatal(ServiceFailure) }

#[derive(Clone)]
pub struct StopHandle(mpsc::UnboundedSender<StopCondition>);
pub struct StopController(mpsc::UnboundedReceiver<StopCondition>);
impl StopController {
    #[must_use] pub fn new() -> (StopHandle, Self) { let (tx, rx) = mpsc::unbounded_channel(); (StopHandle(tx), Self(rx)) }
    pub async fn wait(&mut self) -> StopCondition { self.0.recv().await.unwrap_or(StopCondition::Operator) }
}
impl StopHandle {
    pub fn request(&self, condition: StopCondition) -> Result<(), StopCondition> { self.0.send(condition).map_err(|error| error.0) }
}

#[must_use]
pub fn production_service_graph(mut core_services:Vec<Box<dyn NodeService>>,network:Box<dyn NodeService>,apis:Box<dyn NodeService>,operations:OperationsComponents)->Vec<Box<dyn NodeService>>{
    core_services.push(network);
    core_services.push(apis);
    core_services.extend(operational_service_graph(operations));
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
    #[must_use] pub fn filter_sink(&self)->tron_apis::ProductionFilterSink{self.filters.sink()}
    #[must_use] pub fn metrics(&self)->Arc<MonitorMetrics>{self.metrics.clone()}
}

/// Inputs owned by the production composition root. Core services are the C003 state,
/// execution, and consensus prefix; network and API are the concrete C020-C024 boundary.
pub struct ProductionNodeComponents {
    pub context: NodeContext,
    pub mode: NodeMode,
    pub core_services: Vec<Box<dyn NodeService>>,
    pub network: Box<dyn NodeService>,
    pub apis: Box<dyn NodeService>,
    pub operations: OperationsComponents,
    pub bindings:ProductionOperationalBindings,
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
    pub fn compose(parts: ProductionNodeComponents) -> Result<Self, LifecycleError> {
        let provider=parts.bindings.rpc_provider();
        let rpc_services=parts.bindings.rpc_services();
        let event_sink=parts.bindings.event_sink();
        let filter_sink=parts.bindings.filter_sink();
        let metrics=parts.bindings.metrics();
        let services=production_service_graph(parts.core_services,parts.network,parts.apis,parts.operations);
        let graph=ServiceGraph::new(parts.context,parts.mode,services)?;
        let (stop,controller)=StopController::new();
        Ok(Self{graph,status:NodeStatus::default(),stop,controller,rpc_provider:provider,rpc_services,event_sink,filter_sink,metrics})
    }
    #[must_use] pub fn status(&self)->NodeStatus{self.status.clone()}
    #[must_use] pub fn stop_handle(&self)->StopHandle{self.stop.clone()}
    pub async fn start(&mut self,start_timeout:Duration,shutdown_timeout:Duration)->Result<(),LifecycleError>{self.graph.start(start_timeout,shutdown_timeout).await?;self.status.mark_running();Ok(())}
    pub async fn wait_and_shutdown(&mut self,shutdown_timeout:Duration)->Result<StopCondition,LifecycleError>{let condition=self.controller.wait().await;self.status.revoke_readiness();self.graph.shutdown(shutdown_timeout).await?;Ok(condition)}
    #[cfg(unix)]
    pub async fn wait_for_signal_and_shutdown(&mut self,shutdown_timeout:Duration)->Result<StopCondition,LifecycleError>{
        use tokio::signal::unix::{SignalKind,signal};
        let mut interrupt=signal(SignalKind::interrupt()).expect("install SIGINT handler");
        let mut terminate=signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let condition=tokio::select!{_ = interrupt.recv()=>StopCondition::Interrupt,_ = terminate.recv()=>StopCondition::Terminate,requested=self.controller.wait()=>requested};
        self.status.revoke_readiness();self.graph.shutdown(shutdown_timeout).await?;Ok(condition)
    }
    #[must_use] pub fn started_services(&self)->impl Iterator<Item=&'static str>+'_ { self.graph.started_services() }
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
                status.mark_unhealthy();
                let failure = match &result {
                    Err(error) => error.service_failure(),
                    Ok(()) => ServiceFailure { service: EVENT_QUEUE_SERVICE, message: "event delivery worker exited unexpectedly".into() },
                };
                let _ = stop.request(StopCondition::Fatal(failure));
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
impl OperationalHooks for ReadinessHooks { fn start<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.status.mark_running(); Ok(()) }) } fn cancel_ingress<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.status.revoke_readiness(); Ok(()) }) } fn stop<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.status.mark_unhealthy(); Ok(()) }) } }

#[derive(Clone, Default)]
pub struct ProductionOperationsConfig { pub plugin: Option<PluginConfig>, pub zeromq: Option<ZeroMqConfig>, pub prometheus_address: Option<std::net::SocketAddr> }

pub struct ProductionNodeDependencies {
    pub context: NodeContext,
    pub mode: NodeMode,
    pub core_services: Vec<Box<dyn NodeService>>,
    pub network: Box<dyn NodeService>,
    pub apis: Box<dyn NodeService>,
    pub bindings: ProductionOperationalBindings,
    pub queues: Arc<EventQueues>,
    pub metrics: Arc<MonitorMetrics>,
    pub db_stats: DbStatService,
}

impl ProductionNode {
    pub fn from_dependencies(dependencies: ProductionNodeDependencies) -> Result<Self, LifecycleError> { Self::from_config(ProductionOperationsConfig::default(), dependencies) }
    pub fn from_config(config: ProductionOperationsConfig, dependencies: ProductionNodeDependencies) -> Result<Self, LifecycleError> {
        let status = NodeStatus::default();
        let (stop, controller) = StopController::new();
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
        let services = production_service_graph(dependencies.core_services, dependencies.network, dependencies.apis, operations);
        let graph = ServiceGraph::new(dependencies.context, dependencies.mode, services)?;
        let bindings = dependencies.bindings;
        Ok(Self { graph, status, stop, controller, rpc_provider: bindings.rpc_provider(), rpc_services: bindings.rpc_services(), event_sink: bindings.event_sink(), filter_sink: bindings.filter_sink(), metrics: bindings.metrics() })
    }
}

pub fn compose_production_node(config: ProductionOperationsConfig, dependencies: ProductionNodeDependencies) -> Result<ProductionNode, LifecycleError> { ProductionNode::from_config(config, dependencies) }
