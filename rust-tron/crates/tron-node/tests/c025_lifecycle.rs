use std::{sync::{Arc, Mutex}, time::Duration};

use tron_config::{Config, NodeMode};
use tron_events_metrics::{BlockTrigger, Delivery, EventQueues, EventTrigger, MetricsRegistry, PluginConfig, QueueClass, QueueLimits, TriggerConfig, ZeroMqConfig};
use tron_node::{CancellationToken, LifecycleFuture, MonotonicClock, NodeContext, NodeService, ServiceFailure, ServiceGraph, ServiceSpec, operations::*};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn scrape(address: std::net::SocketAddr) -> String {
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_string(&mut response)).await.unwrap().unwrap();
    response
}

#[derive(Default)] struct Clock;
impl MonotonicClock for Clock { fn elapsed(&self) -> Duration { Duration::ZERO } }

struct Base { name: &'static str, deps: &'static [&'static str], log: Arc<Mutex<Vec<String>>> }
impl NodeService for Base {
    fn spec(&self) -> ServiceSpec { ServiceSpec::new(self.name, self.deps, &[]) }
    fn start<'a>(&'a mut self, _: &'a NodeContext, _: Duration) -> LifecycleFuture<'a> { Box::pin(async move { self.log.lock().unwrap().push(format!("start:{}", self.name)); Ok(()) }) }
    fn stop<'a>(&'a mut self, _: &'a NodeContext, _: Duration) -> LifecycleFuture<'a> { Box::pin(async move { self.log.lock().unwrap().push(format!("stop:{}", self.name)); Ok(()) }) }
}

struct Hook { name: &'static str, log: Arc<Mutex<Vec<String>>>, fail_stop: bool }
impl Hook { fn record(&self, phase: &str) { self.log.lock().unwrap().push(format!("{phase}:{}", self.name)); } }
impl OperationalHooks for Hook {
    fn start<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.record("start"); Ok(()) }) }
    fn cancel_ingress<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.record("cancel"); Ok(()) }) }
    fn drain<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.record("drain"); Ok(()) }) }
    fn flush<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.record("flush"); Ok(()) }) }
    fn stop<'a>(&'a mut self, _: Duration) -> HookFuture<'a> { Box::pin(async move { self.record("stop"); if self.fail_stop { Err("stop failed".into()) } else { Ok(()) } }) }
}

fn hook(name: &'static str, log: &Arc<Mutex<Vec<String>>>) -> Box<dyn OperationalHooks> { Box::new(Hook { name, log: log.clone(), fail_stop: false }) }
fn components(log: &Arc<Mutex<Vec<String>>>) -> OperationsComponents { OperationsComponents { api_provider:hook(API_PROVIDER_SERVICE,log), queues:hook(EVENT_QUEUE_SERVICE,log), plugin:hook(EVENT_PLUGIN_SERVICE,log), zeromq:hook(ZEROMQ_SERVICE,log), metrics:hook(METRICS_SERVICE,log), prometheus:hook(PROMETHEUS_SERVICE,log), db_stats:hook(DB_STATS_SERVICE,log), readiness:hook(READINESS_SERVICE,log) } }
fn context() -> NodeContext { let mut config=Config::default(); config.node.trust_node="127.0.0.1:50051".into(); NodeContext::new(Arc::new(config), CancellationToken::default(), Arc::new(Clock)) }

#[tokio::test]
async fn operations_start_after_network_and_apis_then_shutdown_in_reverse() {
    let log=Arc::new(Mutex::new(Vec::new()));
    let services=production_service_graph(
        vec![Box::new(Base{name:"core",deps:&[],log:log.clone()})],
        Box::new(Base{name:NETWORK_SERVICE,deps:&["core"],log:log.clone()}),
        Box::new(Base{name:API_SERVICE,deps:&[NETWORK_SERVICE],log:log.clone()}),
        components(&log),
    );
    let mut graph=ServiceGraph::new(context(),NodeMode::Full,services).unwrap();
    graph.start(Duration::from_secs(1),Duration::from_secs(1)).await.unwrap();
    assert_eq!(&log.lock().unwrap()[..5],["start:core","start:network","start:apis","start:operations-api-provider","start:event-queues"]);
    graph.shutdown(Duration::from_secs(1)).await.unwrap();
    let values=log.lock().unwrap();
    let readiness_stop=values.iter().position(|v|v=="stop:node-readiness").unwrap();
    let plugin_stop=values.iter().position(|v|v=="stop:event-plugin").unwrap();
    let queue_cancel=values.iter().position(|v|v=="cancel:event-queues").unwrap();
    let api_stop=values.iter().position(|v|v=="stop:apis").unwrap();
    assert!(readiness_stop < plugin_stop && plugin_stop < queue_cancel && queue_cancel < api_stop);
    println!("C025_LIFECYCLE startup=network,apis,operations-api-provider,event-queues shutdown=node-readiness,event-plugin,event-queues,apis");
}

#[tokio::test]
async fn solidity_starts_replica_before_standalone_apis_and_never_starts_p2p() {
    let log=Arc::new(Mutex::new(Vec::new()));
    let services=solidity_production_service_graph(
        vec![Box::new(Base{name:"core",deps:&[],log:log.clone()})],
        Box::new(Base{name:tron_node::solidity_replica::SOLIDITY_REPLICA_SERVICE,deps:&["core"],log:log.clone()}),
        Box::new(Base{name:NETWORK_SERVICE,deps:&["core"],log:log.clone()}),
        Box::new(Base{name:API_SERVICE,deps:&[tron_node::solidity_replica::SOLIDITY_REPLICA_SERVICE],log:log.clone()}),
        components(&log),
    );
    let mut graph=ServiceGraph::new(context(),NodeMode::Solidity,services).unwrap();
    graph.start(Duration::from_secs(1),Duration::from_secs(1)).await.unwrap();
    let started=graph.started_services().collect::<Vec<_>>();
    assert_eq!(&started[..4],["core",tron_node::solidity_replica::SOLIDITY_REPLICA_SERVICE,API_SERVICE,API_PROVIDER_SERVICE]);
    assert!(!started.contains(&NETWORK_SERVICE));
    assert!(!log.lock().unwrap().iter().any(|entry| entry=="start:network"));
    graph.shutdown(Duration::from_secs(1)).await.unwrap();
}

#[tokio::test]
async fn operational_stop_runs_every_phase_and_surfaces_combined_failure() {
    let log=Arc::new(Mutex::new(Vec::new()));
    let mut service=OperationalService::new(ServiceSpec::new("failing",&[],&[]),ShutdownPlan::CancelDrainFlushStop,Box::new(Hook{name:"failing",log:log.clone(),fail_stop:true}));
    service.start(&context(),Duration::ZERO).await.unwrap();
    let error=service.stop(&context(),Duration::ZERO).await.unwrap_err();
    assert_eq!(error,ServiceFailure{service:"failing",message:"stop failed".into()});
    assert_eq!(*log.lock().unwrap(),["start:failing","cancel:failing","drain:failing","flush:failing","stop:failing"]);
}

#[tokio::test]
async fn readiness_and_all_stop_conditions_share_one_control_path() {
    let status=NodeStatus::default(); status.mark_running(); assert!(status.is_ready()&&status.is_healthy()&&status.accepts_ingress());
    status.revoke_readiness(); assert!(!status.is_ready()&&!status.accepts_ingress()&&status.is_healthy());
    status.mark_unhealthy(); assert!(!status.is_healthy());
    for condition in [StopCondition::Interrupt,StopCondition::Terminate,StopCondition::Operator,StopCondition::Fatal(ServiceFailure{service:"plugin",message:"exited".into()})] {
        let (handle,mut controller)=StopController::new(); handle.request(condition.clone()).unwrap(); assert_eq!(controller.wait().await,condition);
    }
}

#[tokio::test]
async fn concrete_queue_zeromq_prometheus_and_readiness_adapters_stop_cleanly() {
    let queues=EventQueues::shared(QueueLimits::default());
    let mut queue=EventQueueHooks::new(queues.clone());
    queue.start(Duration::ZERO).await.unwrap();
    queues.push(QueueClass::Realtime,Delivery::Event(EventTrigger::Block(BlockTrigger{trigger_name:"blockTrigger".into(),block_number:1,..Default::default()}))).unwrap();
    queue.cancel_ingress(Duration::ZERO).await.unwrap(); queue.drain(Duration::ZERO).await.unwrap(); queue.stop(Duration::ZERO).await.unwrap();
    assert_eq!(queues.len(QueueClass::Realtime),0);

    let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap(); let port=listener.local_addr().unwrap().port(); drop(listener);
    let mut zeromq=ZeroMqHooks::new(Some(ZeroMqConfig{bind_port:port,send_hwm:1})); zeromq.start(Duration::ZERO).await.unwrap(); zeromq.stop(Duration::ZERO).await.unwrap();

    let registry=MetricsRegistry::new(true); let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap(); let address=listener.local_addr().unwrap(); drop(listener);
    let mut prometheus=PrometheusHttpHooks::new(Some(address),registry); prometheus.start(Duration::ZERO).await.unwrap();
    let response=tokio::task::spawn_blocking(move||{use std::io::{Read,Write};let mut stream=std::net::TcpStream::connect(address).unwrap();stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();let mut response=String::new();stream.read_to_string(&mut response).unwrap();response}).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK")); prometheus.stop(Duration::ZERO).await.unwrap();

    let status=NodeStatus::default(); let mut readiness=ReadinessHooks::new(status.clone()); readiness.start(Duration::ZERO).await.unwrap(); assert!(status.is_ready()); readiness.cancel_ingress(Duration::ZERO).await.unwrap(); readiness.stop(Duration::ZERO).await.unwrap(); assert!(!status.is_healthy());
}

#[tokio::test]
async fn prometheus_contains_silent_slow_error_and_flood_clients() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut prometheus = PrometheusHttpHooks::new(Some(address), MetricsRegistry::new(true));
    prometheus.start(Duration::ZERO).await.unwrap();

    let silent = tokio::net::TcpStream::connect(address).await.unwrap();
    assert!(scrape(address).await.starts_with("HTTP/1.1 200 OK"));

    let mut slow = tokio::net::TcpStream::connect(address).await.unwrap();
    slow.write_all(b"GET /met").await.unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(scrape(address).await.starts_with("HTTP/1.1 200 OK"));

    let error = tokio::net::TcpStream::connect(address).await.unwrap();
    drop(error);
    assert!(scrape(address).await.starts_with("HTTP/1.1 200 OK"));

    let mut flood = tokio::net::TcpStream::connect(address).await.unwrap();
    let _ = flood.write_all(&vec![b'x'; 8 * 1024]).await;
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(scrape(address).await.starts_with("HTTP/1.1 200 OK"));

    drop((silent, slow, flood));
    prometheus.stop(Duration::from_secs(2)).await.unwrap();
}

#[tokio::test]
async fn prometheus_bind_failure_is_propagated() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = occupied.local_addr().unwrap();
    let mut prometheus = PrometheusHttpHooks::new(Some(address), MetricsRegistry::new(true));
    let error = prometheus.start(Duration::ZERO).await.unwrap_err();
    assert!(!error.is_empty());
}

#[cfg(unix)]
fn exiting_plugin() -> (std::path::PathBuf, PluginConfig) {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    let path = std::env::temp_dir().join(format!("c025-delivery-exit-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::write(&path, "#!/bin/sh\nprintf '%s\\n' '{\"version\":\"3.0.0\"}'\nsleep 0.05\nexit 19\n").unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).unwrap();
    let config = PluginConfig {
        version: 3,
        start_sync_block_num: 0,
        plugin_path: path.clone(),
        server_address: String::new(),
        db_config: String::new(),
        triggers: vec![TriggerConfig { trigger_name: "block".into(), enabled: true, topic: "blocks".into(), ..TriggerConfig::default() }],
    };
    (path, config)
}

#[cfg(unix)]
#[tokio::test]
async fn delivery_plugin_exit_revokes_readiness_closes_ingress_and_requests_fatal_stop() {
    let (path, plugin) = exiting_plugin();
    let queues = EventQueues::shared(QueueLimits::default());
    let status = NodeStatus::default();
    status.mark_running();
    let (stop, mut controller) = StopController::new();
    let mut delivery = EventDeliveryHooks::new(queues.clone(), Some(plugin), None, status.clone(), stop);
    delivery.start(Duration::ZERO).await.unwrap();

    let condition = tokio::time::timeout(Duration::from_secs(2), controller.wait()).await.unwrap();
    let StopCondition::Fatal(failure) = condition else { panic!("expected fatal stop") };
    assert_eq!(failure.service, EVENT_PLUGIN_SERVICE);
    assert!(!failure.message.is_empty());
    assert!(!status.is_healthy() && !status.is_ready() && !status.accepts_ingress());
    assert!(!queues.is_accepting());
    assert!(queues.push(QueueClass::Realtime, Delivery::Event(EventTrigger::Block(BlockTrigger::default()))).is_err());
    assert!(delivery.stop(Duration::from_secs(1)).await.unwrap_err().contains(EVENT_PLUGIN_SERVICE));
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn delivery_shutdown_cancellation_is_not_fatal_and_joins_only_once() {
    let queues = EventQueues::shared(QueueLimits::default());
    let status = NodeStatus::default();
    status.mark_running();
    let (stop, mut controller) = StopController::new();
    let mut delivery = EventDeliveryHooks::new(queues.clone(), None, None, status.clone(), stop);
    delivery.start(Duration::ZERO).await.unwrap();
    delivery.cancel_ingress(Duration::ZERO).await.unwrap();
    delivery.drain(Duration::ZERO).await.unwrap();
    delivery.stop(Duration::from_secs(1)).await.unwrap();
    delivery.stop(Duration::from_secs(1)).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(50), controller.wait()).await.is_err());
    assert!(status.is_healthy());
    assert!(!queues.is_accepting());
}

#[tokio::test]
async fn zeromq_backpressure_is_a_fatal_delivery_failure() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let queues = EventQueues::shared(QueueLimits { realtime: 512, ..QueueLimits::default() });
    let status = NodeStatus::default();
    status.mark_running();
    let (stop, mut controller) = StopController::new();
    let mut delivery = EventDeliveryHooks::new(queues.clone(), None, Some(ZeroMqConfig { bind_port: port, send_hwm: 1 }), status.clone(), stop);
    delivery.start(Duration::ZERO).await.unwrap();
    for block_number in 0..256 {
        queues.push(QueueClass::Realtime, Delivery::Event(EventTrigger::Block(BlockTrigger { block_number, ..BlockTrigger::default() }))).unwrap();
    }
    let condition = tokio::time::timeout(Duration::from_secs(3), controller.wait()).await.unwrap();
    let StopCondition::Fatal(failure) = condition else { panic!("expected fatal stop") };
    assert_eq!(failure.service, ZEROMQ_SERVICE);
    assert!(!status.is_healthy() && !queues.is_accepting());
    assert!(delivery.stop(Duration::from_secs(1)).await.unwrap_err().contains(ZEROMQ_SERVICE));
}
