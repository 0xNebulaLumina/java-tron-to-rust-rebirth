use std::{net::TcpListener, time::Duration};

use tron_events_metrics::{ZeroMqConfig, ZeroMqError, ZeroMqPublisher, DEFAULT_SEND_HWM};
use zeromq::{Socket, SocketRecv, SubSocket};

#[tokio::test]
async fn live_subscriber_receives_topic_then_json_frames() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut publisher = ZeroMqPublisher::bind(ZeroMqConfig { bind_port: port, send_hwm: DEFAULT_SEND_HWM }).await.unwrap();
    assert_eq!(publisher.config().send_hwm, 1000);

    let mut subscriber = SubSocket::new();
    subscriber.connect(&format!("tcp://127.0.0.1:{port}")).await.unwrap();
    subscriber.subscribe("blockTrigger").await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    publisher.publish("blockTrigger", r#"{"blockNumber":1}"#).unwrap();
    let message = tokio::time::timeout(Duration::from_secs(3), subscriber.recv()).await.unwrap().unwrap();
    assert_eq!(message.len(), 2);
    assert_eq!(message.get(0).unwrap().as_ref(), b"blockTrigger");
    assert_eq!(message.get(1).unwrap().as_ref(), br#"{"blockNumber":1}"#);
    publisher.shutdown().await.unwrap();
}

#[test]
fn zero_port_and_zero_hwm_normalize_to_java_defaults() {
    let config = ZeroMqConfig { bind_port: 0, send_hwm: 0 }.normalized();
    assert_eq!(config.bind_port, 5555);
    assert_eq!(config.send_hwm, 1000);
    assert_eq!(config.bind_address(), "tcp://*:5555");
}

#[tokio::test]
async fn full_queue_rejects_without_blocking_and_shutdown_is_bounded() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut publisher = ZeroMqPublisher::bind(ZeroMqConfig { bind_port: port, send_hwm: 1 }).await.unwrap();
    let payload = "x".repeat(64 * 1024);
    let started = std::time::Instant::now();
    let mut full = false;
    for _ in 0..32 {
        if matches!(publisher.publish("topic", payload.clone()), Err(ZeroMqError::Full(1))) { full = true; break; }
    }
    assert!(full);
    assert!(started.elapsed() < Duration::from_secs(2));
    let shutdown_started = std::time::Instant::now();
    publisher.shutdown().await.unwrap();
    assert!(shutdown_started.elapsed() < Duration::from_secs(4));
}
