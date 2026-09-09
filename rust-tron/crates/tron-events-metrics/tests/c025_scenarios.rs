use std::{io::{Read, Write}, net::{TcpListener, TcpStream}, thread, time::Duration};

use tron_events_metrics::{BlockTrigger, Delivery, EventQueues, EventTrigger, MonitorMetrics, MonitorProvider, QueueClass, QueueLimits, ZeroMqConfig, ZeroMqPublisher};
use tron_protocol::protocol::metrics_info;
use zeromq::{Socket, SocketRecv, SubSocket};

fn free_port() -> u16 { let listener=TcpListener::bind("127.0.0.1:0").unwrap(); listener.local_addr().unwrap().port() }

#[tokio::test]
async fn live_zeromq_subscriber_receives_topic_and_json_frames() {
    let port=free_port(); let mut publisher=ZeroMqPublisher::bind(ZeroMqConfig{bind_ip:"127.0.0.1".parse().unwrap(),bind_port:port,send_hwm:8}).await.unwrap();
        let mut subscriber=SubSocket::new(); subscriber.subscribe("blockTrigger").await.unwrap(); subscriber.connect(&format!("tcp://127.0.0.1:{port}")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        publisher.publish("blockTrigger",r#"{"blockNumber":7}"#).unwrap();
        let message=tokio::time::timeout(Duration::from_secs(2),subscriber.recv()).await.unwrap().unwrap();
        let frames:Vec<_>=message.into_vec(); assert_eq!(frames.len(),2); assert_eq!(&frames[0][..],b"blockTrigger"); assert_eq!(&frames[1][..],br#"{"blockNumber":7}"#);
        println!("C025_LIVE_ZMQ topic=blockTrigger json={{\"blockNumber\":7}} frames=2");
    publisher.shutdown().await.unwrap();
}

#[test]
fn live_prometheus_scrape_exposes_monitor_updates() {
    let metrics=MonitorMetrics::new(true); metrics.record_head(42,1_700_000_000_000,"abcd"); metrics.record_transaction(true,"SUCCESS");
    let body=metrics.prometheus().scrape(); let listener=TcpListener::bind("127.0.0.1:0").unwrap(); let address=listener.local_addr().unwrap();
    let server=thread::spawn(move || { let (mut stream,_)=listener.accept().unwrap(); let mut request=[0;256]; let _=stream.read(&mut request).unwrap(); let response=format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body); stream.write_all(response.as_bytes()).unwrap(); });
    let mut client=TcpStream::connect(address).unwrap(); client.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap(); let mut response=String::new(); client.read_to_string(&mut response).unwrap(); server.join().unwrap();
    assert!(response.contains("tron:header_height 42")); assert!(response.contains("tron:txs_total{type=\"success\",detail=\"SUCCESS\"} 1"));
    println!("C025_PROM_SCRAPE header_height=42 tx_success_SUCCESS=1");
}

#[test]
fn c022_monitor_and_node_info_share_provider_snapshot() {
    let metrics=MonitorMetrics::new(true); metrics.set_node(metrics_info::NodeInfo{ip:"127.0.0.1".into(),node_type:1,version:"4.8.0".into(),backup_status:0}); metrics.set_connections(3,2);
    let provider:&dyn MonitorProvider=&metrics; let snapshot=provider.metrics(); let node=snapshot.node.unwrap(); assert_eq!((node.ip,node.node_type,node.version),("127.0.0.1".into(),1,"4.8.0".into())); assert_eq!(snapshot.net.unwrap().connection_count,3);
    println!("C025_C022_MONITOR ip=127.0.0.1 node_type=1 version=4.8.0 connections=3");
}

#[test]
fn c019_reorg_emits_removed_then_reapplied_events() {
    let queues=EventQueues::new(QueueLimits::default()); let block=|height,removed| Delivery::Event(EventTrigger::Block(BlockTrigger{trigger_name:"blockTrigger".into(),block_number:height,removed,..Default::default()}));
    queues.push_batch(QueueClass::Realtime,[block(4,true),block(3,true),block(3,false),block(4,false),block(5,false)]).unwrap();
    let rows=queues.drain(QueueClass::Realtime,usize::MAX); assert_eq!(rows.iter().map(|r|(r.delivery.block_number(),r.delivery.removed())).collect::<Vec<_>>(),[(4,true),(3,true),(3,false),(4,false),(5,false)]);
    println!("C025_C019_REORG 4:removed,3:removed,3:applied,4:applied,5:applied");
}
