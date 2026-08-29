//! Explicit composition, mode gating, and bounded lifecycle ownership for node services.
//!
//! This crate deliberately implements no storage, API, transport, or consensus behavior. The
//! composition root receives already-constructed services and owns their ordering and shutdown.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::sync::Notify;
use tron_config::{Config, NodeMode};

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<CancellationState>);

#[derive(Default)]
struct CancellationState {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CancellationToken {
    pub fn cancel(&self) {
        if !self.0.cancelled.swap(true, Ordering::AcqRel) {
            self.0.notify.notify_waiters();
        }
    }

    pub fn is_cancelled(&self) -> bool { self.0.cancelled.load(Ordering::Acquire) }

    pub async fn cancelled(&self) {
        loop {
            let notified = self.0.notify.notified();
            if self.is_cancelled() { return; }
            notified.await;
        }
    }
}

pub trait MonotonicClock: Send + Sync {
    fn elapsed(&self) -> Duration;
}

#[derive(Clone)]
pub struct NodeContext {
    config: Arc<Config>,
    cancellation: CancellationToken,
    clock: Arc<dyn MonotonicClock>,
}

impl NodeContext {
    pub fn new(config: Arc<Config>, cancellation: CancellationToken, clock: Arc<dyn MonotonicClock>) -> Self {
        Self { config, cancellation, clock }
    }
    pub fn config(&self) -> &Config { &self.config }
    pub fn cancellation(&self) -> &CancellationToken { &self.cancellation }
    pub fn clock(&self) -> &dyn MonotonicClock { self.clock.as_ref() }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServiceMode { Full, Solidity, Pbft, Witness, P2p }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    pub name: &'static str,
    pub dependencies: &'static [&'static str],
    pub modes: &'static [ServiceMode],
}

impl ServiceSpec {
    pub const fn new(name: &'static str, dependencies: &'static [&'static str], modes: &'static [ServiceMode]) -> Self {
        Self { name, dependencies, modes }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceFailure {
    pub service: &'static str,
    pub message: String,
}

pub type LifecycleFuture<'a> = Pin<Box<dyn Future<Output = Result<(), ServiceFailure>> + Send + 'a>>;

pub trait NodeService: Send {
    fn spec(&self) -> ServiceSpec;
    fn start<'a>(&'a mut self, context: &'a NodeContext, deadline: Duration) -> LifecycleFuture<'a>;
    fn stop<'a>(&'a mut self, context: &'a NodeContext, deadline: Duration) -> LifecycleFuture<'a>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceGraphState {
    New,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleOperation {
    Start,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    DuplicateService(&'static str),
    MissingDependency { service: &'static str, dependency: &'static str },
    DependencyOrder { service: &'static str, dependency: &'static str },
    InvalidTransition {
        operation: LifecycleOperation,
        state: ServiceGraphState,
    },
    StartupFailure(ServiceFailure),
    StartupTimeout { service: &'static str, timeout: Duration },
    StartupUnwindFailure {
        startup: Box<LifecycleError>,
        unwind: Box<LifecycleError>,
    },
    ShutdownFailures(Vec<ServiceFailure>),
    ShutdownTimeout { service: &'static str, timeout: Duration },
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateService(name) => write!(f, "duplicate service {name}"),
            Self::MissingDependency { service, dependency } => write!(f, "service {service} requires missing dependency {dependency}"),
            Self::DependencyOrder { service, dependency } => write!(f, "service {service} appears before dependency {dependency}"),
            Self::InvalidTransition { operation, state } => {
                write!(f, "cannot {operation:?} service graph while it is {state:?}")
            }
            Self::StartupFailure(failure) => write!(f, "service {} failed to start: {}", failure.service, failure.message),
            Self::StartupTimeout { service, timeout } => write!(f, "service {service} exceeded startup timeout {timeout:?}"),
            Self::StartupUnwindFailure { startup, unwind } => {
                write!(f, "{startup}; startup unwind also failed: {unwind}")
            }
            Self::ShutdownFailures(failures) => write!(f, "{} service(s) failed to stop", failures.len()),
            Self::ShutdownTimeout { service, timeout } => write!(f, "service {service} exceeded shutdown timeout {timeout:?}"),
        }
    }
}

impl std::error::Error for LifecycleError {}

pub struct ServiceGraph {
    context: NodeContext,
    services: Vec<Box<dyn NodeService>>,
    enabled: Vec<bool>,
    started: Vec<usize>,
    state: ServiceGraphState,
}

impl ServiceGraph {
    pub fn new(context: NodeContext, mode: NodeMode, services: Vec<Box<dyn NodeService>>) -> Result<Self, LifecycleError> {
        let enabled = services.iter().map(|service| service_enabled(&service.spec(), mode, context.config())).collect::<Vec<_>>();
        let mut positions = BTreeMap::new();
        for (index, service) in services.iter().enumerate().filter(|(index, _)| enabled[*index]) {
            let name = service.spec().name;
            if positions.insert(name, index).is_some() { return Err(LifecycleError::DuplicateService(name)); }
        }
        for (index, service) in services.iter().enumerate().filter(|(index, _)| enabled[*index]) {
            for dependency in service.spec().dependencies {
                let Some(dependency_index) = positions.get(dependency).copied() else {
                    return Err(LifecycleError::MissingDependency { service: service.spec().name, dependency });
                };
                if dependency_index >= index {
                    return Err(LifecycleError::DependencyOrder { service: service.spec().name, dependency });
                }
            }
        }
        Ok(Self { context, services, enabled, started: Vec::new(), state: ServiceGraphState::New })
    }

    pub async fn start(&mut self, per_service_timeout: Duration, shutdown_timeout: Duration) -> Result<(), LifecycleError> {
        if self.state != ServiceGraphState::New {
            return Err(LifecycleError::InvalidTransition {
                operation: LifecycleOperation::Start,
                state: self.state,
            });
        }
        self.state = ServiceGraphState::Starting;
        for index in 0..self.services.len() {
            if !self.enabled[index] { continue; }
            let name = self.services[index].spec().name;
            let deadline = self.context.clock().elapsed().saturating_add(per_service_timeout);
            let cancellation = self.context.cancellation().clone();
            let outcome = {
                let mut operation = self.services[index].start(&self.context, deadline);
                tokio::select! {
                    result = &mut operation => result.map_err(LifecycleError::StartupFailure),
                    () = cancellation.cancelled() => Err(LifecycleError::StartupFailure(ServiceFailure {
                        service: name,
                        message: "startup cancelled".into(),
                    })),
                    _ = tokio::time::sleep(per_service_timeout) => Err(LifecycleError::StartupTimeout {
                        service: name,
                        timeout: per_service_timeout,
                    }),
                }
            };
            if let Err(startup) = outcome {
                self.context.cancellation().cancel();
                self.state = ServiceGraphState::Stopping;
                return match self.stop_started(shutdown_timeout).await {
                    Ok(()) => {
                        self.state = ServiceGraphState::Failed;
                        Err(startup)
                    }
                    Err(unwind) => Err(LifecycleError::StartupUnwindFailure {
                        startup: Box::new(startup),
                        unwind: Box::new(unwind),
                    }),
                };
            }
            self.started.push(index);
        }
        self.state = ServiceGraphState::Running;
        Ok(())
    }

    pub async fn shutdown(&mut self, per_service_timeout: Duration) -> Result<(), LifecycleError> {
        match self.state {
            ServiceGraphState::Running | ServiceGraphState::Stopping => {}
            ServiceGraphState::Stopped | ServiceGraphState::Failed => return Ok(()),
            state => {
                return Err(LifecycleError::InvalidTransition {
                    operation: LifecycleOperation::Shutdown,
                    state,
                });
            }
        }
        self.context.cancellation().cancel();
        self.state = ServiceGraphState::Stopping;
        self.stop_started(per_service_timeout).await
    }

    async fn stop_started(&mut self, per_service_timeout: Duration) -> Result<(), LifecycleError> {
        let mut failures = Vec::new();
        let mut timed_out = Vec::new();
        let mut stopped = BTreeSet::new();
        for index in self.started.iter().rev().copied() {
            let name = self.services[index].spec().name;
            let deadline = self.context.clock().elapsed().saturating_add(per_service_timeout);
            match tokio::time::timeout(per_service_timeout, self.services[index].stop(&self.context, deadline)).await {
                Ok(Ok(())) => {
                    stopped.insert(index);
                }
                Ok(Err(failure)) => failures.push(failure),
                Err(_) => timed_out.push(name),
            }
        }
        self.started.retain(|index| !stopped.contains(index));
        if self.started.is_empty() {
            self.state = ServiceGraphState::Stopped;
        }

        if failures.is_empty() && timed_out.len() == 1 {
            return Err(LifecycleError::ShutdownTimeout {
                service: timed_out[0],
                timeout: per_service_timeout,
            });
        }
        failures.extend(timed_out.into_iter().map(|service| ServiceFailure {
            service,
            message: format!("shutdown exceeded timeout {per_service_timeout:?}"),
        }));
        if failures.is_empty() { Ok(()) } else { Err(LifecycleError::ShutdownFailures(failures)) }
    }

    pub fn started_services(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.started.iter().map(|index| self.services[*index].spec().name)
    }

    pub fn state(&self) -> ServiceGraphState { self.state }
}

fn service_enabled(spec: &ServiceSpec, mode: NodeMode, config: &Config) -> bool {
    if mode == NodeMode::KeystoreFactory { return false; }
    spec.modes.iter().all(|required| match required {
        ServiceMode::Full => mode == NodeMode::Full,
        ServiceMode::Solidity => mode == NodeMode::Solidity,
        ServiceMode::Pbft => config.committee.allow_pbft == 1,
        ServiceMode::Witness => config.node.witness,
        ServiceMode::P2p => mode == NodeMode::Full && !config.node.p2p_disable,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApiSurface { FullHttp, SolidityHttp, PbftHttp, FullRpc, SolidityRpc, PbftRpc, FullJsonRpc, SolidityJsonRpc, PbftJsonRpc }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositionError {
    DuplicatePort { port: u16, first: ApiSurface, second: ApiSurface },
    InvalidPort { surface: ApiSurface, port: i32 },
}

pub fn enabled_api_ports(config: &Config, mode: NodeMode) -> Result<BTreeMap<ApiSurface, u16>, CompositionError> {
    let mut candidates = Vec::new();
    let full = mode == NodeMode::Full;
    let solidity = mode == NodeMode::Solidity;
    let pbft = config.committee.allow_pbft == 1 && mode != NodeMode::KeystoreFactory;
    candidates.extend([
        (ApiSurface::FullHttp, config.node.http.full_node_enable && full, config.node.http.full_node_port),
        (ApiSurface::SolidityHttp, config.node.http.solidity_enable && solidity, config.node.http.solidity_port),
        (ApiSurface::PbftHttp, config.node.http.pbft_enable && pbft, config.node.http.pbft_port),
        (ApiSurface::FullRpc, config.node.rpc.enable && full, config.node.rpc.port),
        (ApiSurface::SolidityRpc, config.node.rpc.solidity_enable && solidity, config.node.rpc.solidity_port),
        (ApiSurface::PbftRpc, config.node.rpc.pbft_enable && pbft, config.node.rpc.pbft_port),
        (ApiSurface::FullJsonRpc, config.node.jsonrpc.http_full_node_enable && full, config.node.jsonrpc.http_full_node_port),
        (ApiSurface::SolidityJsonRpc, config.node.jsonrpc.http_solidity_enable && solidity, config.node.jsonrpc.http_solidity_port),
        (ApiSurface::PbftJsonRpc, config.node.jsonrpc.http_pbft_enable && pbft, config.node.jsonrpc.http_pbft_port),
    ]);
    let mut result = BTreeMap::new();
    let mut occupied = BTreeMap::new();
    for (surface, enabled, raw_port) in candidates {
        if !enabled { continue; }
        let port = u16::try_from(raw_port).ok().filter(|port| *port != 0).ok_or(CompositionError::InvalidPort { surface, port: raw_port })?;
        if let Some(first) = occupied.insert(port, surface) { return Err(CompositionError::DuplicatePort { port, first, second: surface }); }
        result.insert(surface, port);
    }
    Ok(result)
}

pub fn enabled_capabilities(config: &Config, mode: NodeMode) -> BTreeSet<ServiceMode> {
    let mut modes = BTreeSet::new();
    match mode { NodeMode::Full => { modes.insert(ServiceMode::Full); }, NodeMode::Solidity => { modes.insert(ServiceMode::Solidity); }, NodeMode::KeystoreFactory => {} }
    if config.committee.allow_pbft == 1 && mode != NodeMode::KeystoreFactory { modes.insert(ServiceMode::Pbft); }
    if config.node.witness && mode != NodeMode::KeystoreFactory { modes.insert(ServiceMode::Witness); }
    if !config.node.p2p_disable && mode == NodeMode::Full { modes.insert(ServiceMode::P2p); }
    modes
}
