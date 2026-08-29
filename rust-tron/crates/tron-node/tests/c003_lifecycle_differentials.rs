use std::{
    future::pending,
    sync::{Arc, Mutex},
    time::Duration,
};

use tron_config::{Config, NodeMode};
use tron_node::{
    enabled_api_ports, enabled_capabilities, CancellationToken, CompositionError,
    LifecycleError, LifecycleFuture, LifecycleOperation, MonotonicClock, NodeContext, NodeService,
    ServiceFailure, ServiceGraph, ServiceGraphState, ServiceMode, ServiceSpec,
};

#[derive(Default)]
struct Clock;

impl MonotonicClock for Clock {
    fn elapsed(&self) -> Duration { Duration::ZERO }
}

#[derive(Clone, Copy)]
enum Behavior {
    Complete,
    Fail,
    FailOnce,
    Never,
}

struct Service {
    name: &'static str,
    deps: &'static [&'static str],
    log: Arc<Mutex<Vec<String>>>,
    start: Behavior,
    stop: Behavior,
}

impl NodeService for Service {
    fn spec(&self) -> ServiceSpec { ServiceSpec::new(self.name, self.deps, &[]) }

    fn start<'a>(&'a mut self, _: &'a NodeContext, _: Duration) -> LifecycleFuture<'a> {
        Box::pin(async move {
            self.log.lock().expect("event log lock poisoned").push(format!("start:{}", self.name));
            match self.start {
                Behavior::Complete | Behavior::FailOnce => Ok(()),
                Behavior::Fail => Err(ServiceFailure { service: self.name, message: "boom".into() }),
                Behavior::Never => pending().await,
            }
        })
    }

    fn stop<'a>(&'a mut self, _: &'a NodeContext, _: Duration) -> LifecycleFuture<'a> {
        Box::pin(async move {
            self.log.lock().expect("event log lock poisoned").push(format!("stop:{}", self.name));
            match self.stop {
                Behavior::Complete => Ok(()),
                Behavior::Fail => Err(ServiceFailure { service: self.name, message: "stop-boom".into() }),
                Behavior::FailOnce => {
                    self.stop = Behavior::Complete;
                    Err(ServiceFailure { service: self.name, message: "stop-boom".into() })
                }
                Behavior::Never => pending().await,
            }
        })
    }
}

fn context(config: Config) -> NodeContext {
    NodeContext::new(Arc::new(config), CancellationToken::default(), Arc::new(Clock))
}

fn service(
    name: &'static str,
    deps: &'static [&'static str],
    log: &Arc<Mutex<Vec<String>>>,
) -> Box<dyn NodeService> {
    Box::new(Service {
        name,
        deps,
        log: log.clone(),
        start: Behavior::Complete,
        stop: Behavior::Complete,
    })
}

#[tokio::test]
async fn lifecycle_starts_forward_and_stops_reverse() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut graph = ServiceGraph::new(
        context(Config::default()),
        NodeMode::Full,
        vec![service("a", &[], &log), service("b", &["a"], &log)],
    )
    .unwrap();
    graph.start(Duration::from_secs(1), Duration::from_secs(1)).await.unwrap();
    graph.shutdown(Duration::from_secs(1)).await.unwrap();
    assert_eq!(
        *log.lock().expect("event log lock poisoned"),
        ["start:a", "start:b", "stop:b", "stop:a"]
    );
}

#[tokio::test]
async fn duplicate_start_is_rejected_before_any_service_restarts() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut graph = ServiceGraph::new(
        context(Config::default()),
        NodeMode::Full,
        vec![service("a", &[], &log)],
    )
    .unwrap();

    graph.start(Duration::from_secs(1), Duration::from_secs(1)).await.unwrap();
    assert_eq!(graph.state(), ServiceGraphState::Running);
    assert_eq!(
        graph.start(Duration::from_secs(1), Duration::from_secs(1)).await,
        Err(LifecycleError::InvalidTransition {
            operation: LifecycleOperation::Start,
            state: ServiceGraphState::Running,
        })
    );
    assert_eq!(*log.lock().expect("event log lock poisoned"), ["start:a"]);

    graph.shutdown(Duration::from_secs(1)).await.unwrap();
}

#[tokio::test]
async fn start_after_terminal_shutdown_is_rejected_without_starting_services() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut graph = ServiceGraph::new(
        context(Config::default()),
        NodeMode::Full,
        vec![service("a", &[], &log)],
    )
    .unwrap();

    graph.start(Duration::from_secs(1), Duration::from_secs(1)).await.unwrap();
    graph.shutdown(Duration::from_secs(1)).await.unwrap();
    assert_eq!(graph.state(), ServiceGraphState::Stopped);
    assert_eq!(
        graph.start(Duration::from_secs(1), Duration::from_secs(1)).await,
        Err(LifecycleError::InvalidTransition {
            operation: LifecycleOperation::Start,
            state: ServiceGraphState::Stopped,
        })
    );
    assert_eq!(
        *log.lock().expect("event log lock poisoned"),
        ["start:a", "stop:a"]
    );
}

#[tokio::test]
async fn shutdown_before_start_is_a_typed_invalid_transition() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut graph = ServiceGraph::new(
        context(Config::default()),
        NodeMode::Full,
        vec![service("a", &[], &log)],
    )
    .unwrap();

    assert_eq!(
        graph.shutdown(Duration::from_secs(1)).await,
        Err(LifecycleError::InvalidTransition {
            operation: LifecycleOperation::Shutdown,
            state: ServiceGraphState::New,
        })
    );
    assert!(log.lock().expect("event log lock poisoned").is_empty());
}

#[tokio::test]
async fn startup_failure_cancels_and_unwinds() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let cancellation = CancellationToken::default();
    let ctx = NodeContext::new(Arc::new(Config::default()), cancellation.clone(), Arc::new(Clock));
    let bad = Box::new(Service {
        name: "b",
        deps: &["a"],
        log: log.clone(),
        start: Behavior::Fail,
        stop: Behavior::Complete,
    });
    let mut graph = ServiceGraph::new(ctx, NodeMode::Full, vec![service("a", &[], &log), bad]).unwrap();
    assert!(matches!(
        graph.start(Duration::from_secs(1), Duration::from_secs(1)).await,
        Err(LifecycleError::StartupFailure(_))
    ));
    assert!(cancellation.is_cancelled());
    assert_eq!(*log.lock().expect("event log lock poisoned"), ["start:a", "start:b", "stop:a"]);
}

#[tokio::test]
async fn never_completing_start_is_cancelled_and_reverse_unwound() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let stuck = Box::new(Service {
        name: "b",
        deps: &["a"],
        log: log.clone(),
        start: Behavior::Never,
        stop: Behavior::Complete,
    });
    let mut graph = ServiceGraph::new(
        context(Config::default()),
        NodeMode::Full,
        vec![service("a", &[], &log), stuck],
    )
    .unwrap();
    assert!(matches!(
        graph.start(Duration::from_millis(1), Duration::from_secs(1)).await,
        Err(LifecycleError::StartupTimeout { service: "b", .. })
    ));
    assert_eq!(*log.lock().expect("event log lock poisoned"), ["start:a", "start:b", "stop:a"]);
}

#[tokio::test]
async fn never_completing_stop_is_retained_for_later_reverse_order_retries() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let stuck = Box::new(Service {
        name: "b",
        deps: &["a"],
        log: log.clone(),
        start: Behavior::Complete,
        stop: Behavior::Never,
    });
    let mut graph = ServiceGraph::new(
        context(Config::default()),
        NodeMode::Full,
        vec![service("a", &[], &log), stuck],
    )
    .unwrap();
    graph.start(Duration::from_secs(1), Duration::from_secs(1)).await.unwrap();
    assert!(matches!(
        graph.shutdown(Duration::from_millis(1)).await,
        Err(LifecycleError::ShutdownTimeout { service: "b", .. })
    ));
    assert_eq!(graph.started_services().collect::<Vec<_>>(), ["b"]);
    assert!(matches!(
        graph.shutdown(Duration::from_millis(1)).await,
        Err(LifecycleError::ShutdownTimeout { service: "b", .. })
    ));
    assert_eq!(
        *log.lock().expect("event log lock poisoned"),
        ["start:a", "start:b", "stop:b", "stop:a", "stop:b"]
    );
}

#[tokio::test]
async fn failed_stop_retries_then_becomes_idempotent_only_after_full_success() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let flaky = Box::new(Service {
        name: "b",
        deps: &["a"],
        log: log.clone(),
        start: Behavior::Complete,
        stop: Behavior::FailOnce,
    });
    let mut graph = ServiceGraph::new(
        context(Config::default()),
        NodeMode::Full,
        vec![service("a", &[], &log), flaky],
    )
    .unwrap();
    graph.start(Duration::from_secs(1), Duration::from_secs(1)).await.unwrap();
    assert!(matches!(
        graph.shutdown(Duration::from_secs(1)).await,
        Err(LifecycleError::ShutdownFailures(v)) if v.len() == 1
    ));
    assert_eq!(graph.started_services().collect::<Vec<_>>(), ["b"]);
    graph.shutdown(Duration::from_secs(1)).await.unwrap();
    graph.shutdown(Duration::from_secs(1)).await.unwrap();
    assert_eq!(
        *log.lock().expect("event log lock poisoned"),
        ["start:a", "start:b", "stop:b", "stop:a", "stop:b"]
    );
}

#[tokio::test]
async fn startup_failure_preserves_unwind_failure_for_retry() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let flaky = Box::new(Service {
        name: "a",
        deps: &[],
        log: log.clone(),
        start: Behavior::Complete,
        stop: Behavior::FailOnce,
    });
    let bad = Box::new(Service {
        name: "b",
        deps: &["a"],
        log: log.clone(),
        start: Behavior::Fail,
        stop: Behavior::Complete,
    });
    let mut graph = ServiceGraph::new(context(Config::default()), NodeMode::Full, vec![flaky, bad]).unwrap();
    assert!(matches!(
        graph.start(Duration::from_secs(1), Duration::from_secs(1)).await,
        Err(LifecycleError::StartupUnwindFailure { startup, unwind })
            if matches!(*startup, LifecycleError::StartupFailure(ServiceFailure { service: "b", .. }))
                && matches!(*unwind, LifecycleError::ShutdownFailures(ref failures) if failures.len() == 1)
    ));
    assert_eq!(graph.started_services().collect::<Vec<_>>(), ["a"]);
    graph.shutdown(Duration::from_secs(1)).await.unwrap();
}

#[test]
fn modes_gate_capabilities_and_services() {
    let mut config = Config::default();
    config.node.witness = true;
    assert!(!enabled_capabilities(&config, NodeMode::Solidity).contains(&ServiceMode::P2p));
    assert!(enabled_capabilities(&config, NodeMode::KeystoreFactory).is_empty());
    assert!(enabled_api_ports(&config, NodeMode::KeystoreFactory).unwrap().is_empty());
}

#[test]
fn duplicate_and_invalid_ports_are_rejected() {
    let mut config = Config::default();
    config.committee.allow_pbft = 1;
    config.node.http.pbft_port = config.node.http.full_node_port;
    assert!(matches!(
        enabled_api_ports(&config, NodeMode::Full),
        Err(CompositionError::DuplicatePort { .. })
    ));
    config.committee.allow_pbft = 0;
    config.node.http.full_node_port = 0;
    assert!(matches!(
        enabled_api_ports(&config, NodeMode::Full),
        Err(CompositionError::InvalidPort { .. })
    ));
}
