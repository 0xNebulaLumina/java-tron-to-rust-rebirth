use std::{sync::{Arc,atomic::{AtomicBool,Ordering}},time::Duration};
use tron_apis::{BlockingExecutor, JsonRpcServerConfig, JsonRpcSurface};

#[test]
fn mandatory_ports_and_surface_order_are_exact() {
    let mut config=JsonRpcServerConfig::default();
    assert_eq!((config.full_port,config.solidity_port,config.pbft_port),(8545,8555,8565));
    config.full_enabled=true;config.solidity_enabled=true;config.pbft_enabled=true;
    assert_eq!(config.enabled(),vec![(JsonRpcSurface::Full,8545),(JsonRpcSurface::Solidity,8555),(JsonRpcSurface::Pbft,8565)]);
    config.validate().unwrap();
}

#[test]
fn collisions_zero_capacity_and_zero_deadlines_are_rejected() {
    let mut config=JsonRpcServerConfig::default();config.full_enabled=true;config.solidity_enabled=true;config.solidity_port=config.full_port;
    assert!(config.validate().unwrap_err().contains("collide"));
    config.solidity_enabled=false;config.max_concurrent_requests=0;
    assert!(config.validate().unwrap_err().contains("concurrency"));
    config.max_concurrent_requests=1;config.request_deadline=Duration::ZERO;
    assert!(config.validate().unwrap_err().contains("deadlines"));
}

#[test]
fn node_jsonrpc_limits_map_without_hidden_unbounded_defaults() {
    let mut node=tron_config::JsonRpcConfig::default();node.http_full_node_enable=true;node.http_solidity_enable=true;node.http_pbft_enable=true;
    let config=JsonRpcServerConfig::from_node(&node).unwrap();
    assert_eq!(config.limits.max_request_bytes,4_194_304);
    assert_eq!(config.limits.max_response_bytes,26_214_400);
    assert_eq!(config.limits.max_batch_size,100);
    assert_eq!(config.filter_limits.max_block_range,5000);
    assert_eq!(config.filter_limits.max_addresses,1000);
    assert_eq!(config.filter_limits.max_subtopics,1000);
    assert_eq!(config.filter_limits.max_block_filters,50000);
    assert_eq!(config.filter_limits.max_log_filters,20000);
    assert_eq!(config.filter_limits.max_results,10000);
}

#[tokio::test]
async fn vm_work_is_bounded_deadlined_and_cancelled_when_saturated() {
    let executor=BlockingExecutor::new(1,Duration::from_millis(25)).unwrap();
    let holding=Arc::new(AtomicBool::new(true));let started=Arc::new(AtomicBool::new(false));let worker_holding=holding.clone();let worker_started=started.clone();let first_executor=executor.clone();
    let first=tokio::spawn(async move{first_executor.run(move |_|{worker_started.store(true,Ordering::Release);while worker_holding.load(Ordering::Acquire){std::thread::yield_now()}Ok(())}).await});
    while !started.load(Ordering::Acquire){tokio::task::yield_now().await}
    let status=executor.run(|_|Ok(())).await.unwrap_err();
    assert_eq!(status.code(),tonic::Code::DeadlineExceeded);
    holding.store(false,Ordering::Release);let _=first.await.unwrap();
}
