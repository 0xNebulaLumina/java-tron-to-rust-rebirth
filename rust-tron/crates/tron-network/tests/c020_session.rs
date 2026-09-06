use bytes::Bytes;
use prost::Message;
use std::{collections::HashSet, net::SocketAddr, time::Duration};
use tokio::io::duplex;
use tokio_util::sync::CancellationToken;
use tron_network::{compression, connection::{Direction,PoolConfig}, handshake::{AdmissionConfig,Control,DisconnectReason,Endpoint,HelloMessage,KeepAliveMessage,StatusMessage}, session::{session_event_channel,SessionConfig,SessionError,SessionEvent,SessionRegistry,SessionState,TransportSession}, tcp::FramedIo};

fn endpoint(id:u8)->Endpoint{Endpoint{address:b"127.0.0.1".to_vec(),port:18888,node_id:vec![id;64],address_ipv6:vec![]}}
fn hello(id:u8,network:i32,version:i32)->HelloMessage{HelloMessage{from:Some(endpoint(id)),network_id:network,code:0,timestamp:9,version}}
fn config(direction:Direction)->SessionConfig{SessionConfig{local_hello:hello(1,7,2),direction,admission:AdmissionConfig{network_id:7,version:2,max_connections:4,max_same_ip:4,trusted:HashSet::new(),ban_duration:Duration::from_millis(100)},pool:PoolConfig{min_connections:1,max_connections:4,min_active:1,max_same_ip:4,initial_backoff:Duration::from_millis(10),max_backoff:Duration::from_millis(40)},keepalive_interval:Duration::from_millis(20),pong_timeout:Duration::from_millis(100),write_timeout:Duration::from_millis(100),compression:true}}
async fn control<T:tokio::io::AsyncRead+tokio::io::AsyncWrite+Unpin,M:Message>(io:&mut FramedIo<T>,kind:Control,msg:&M){let mut b=vec![kind.byte()];b.extend(msg.encode_to_vec());io.write_frame(Bytes::from(b)).await.unwrap()}

#[tokio::test]
async fn passive_session_integrates_hello_status_upgrade_compression_keepalive_disconnect_and_cleanup(){
 let (rust,peer)=duplex(1<<20);let registry=SessionRegistry::default();let (tx,mut rx)=session_event_channel(64,1<<20,Duration::from_secs(1));let cancel=CancellationToken::new();
 let session=TransportSession::new(FramedIo::new(rust,Duration::from_secs(1)),SocketAddr::from(([127,0,0,1],3000)),config(Direction::Passive),registry.clone()).with_events(tx);
 let task=tokio::spawn(session.run(cancel.clone()));let mut io=FramedIo::new(peer,Duration::from_secs(1));
 control(&mut io,Control::HandshakeHello,&hello(2,7,2)).await;assert_eq!(io.read_frame().await.unwrap()[0],Control::HandshakeHello.byte());
 assert_eq!(io.read_frame().await.unwrap()[0],Control::Status.byte());control(&mut io,Control::Status,&StatusMessage{from:Some(endpoint(2)),version:2,network_id:7,max_connections:4,current_connections:0,timestamp:10}).await;
 assert_eq!(&io.read_frame().await.unwrap()[..],&[0xfa,1]);io.write_frame(Bytes::from_static(&[0xfa,1])).await.unwrap();
 let app=vec![42;4096];io.write_frame(Bytes::from(compression::envelope(&app,true).unwrap().encode_to_vec())).await.unwrap();
 let ping=io.read_frame().await.unwrap();assert_eq!(ping[0],Control::KeepAlivePing.byte());let stamp=KeepAliveMessage::decode(&ping[1..]).unwrap().timestamp;control(&mut io,Control::KeepAlivePong,&KeepAliveMessage{timestamp:stamp}).await;
 cancel.cancel();let disconnect=io.read_frame().await.unwrap();assert_eq!(disconnect[0],Control::Disconnect.byte());let traffic=task.await.unwrap().unwrap();
 assert!(traffic.received_wire>traffic.received_payload&&traffic.sent_wire>traffic.sent_payload);assert_eq!(registry.admission.lock().unwrap().len(),0);assert_eq!(registry.pool.lock().unwrap().len(),0);
 let mut states=Vec::new();let mut got_app=false;while let Ok(queued)=rx.try_recv(){match queued.into_event(){SessionEvent::State(s)=>states.push(s),SessionEvent::Message(v)=>{assert_eq!(v,app);got_app=true},_=>{}}}assert!(got_app);assert!(states.contains(&SessionState::Connected));assert_eq!(states.last(),Some(&SessionState::Closed));
}

#[tokio::test]
async fn active_session_rejects_wrong_network_sends_reason_bans_and_backs_off(){
 let (rust,peer)=duplex(4096);let registry=SessionRegistry::default();let cfg=config(Direction::Active);let address=SocketAddr::from(([127,0,0,1],3001));let task=tokio::spawn(TransportSession::new(FramedIo::new(rust,Duration::from_secs(1)),address,cfg.clone(),registry.clone()).run(CancellationToken::new()));let mut io=FramedIo::new(peer,Duration::from_secs(1));
 assert_eq!(io.read_frame().await.unwrap()[0],Control::HandshakeHello.byte());control(&mut io,Control::HandshakeHello,&hello(2,8,2)).await;let reject=io.read_frame().await.unwrap();assert_eq!(reject[0],Control::Disconnect.byte());assert!(task.await.unwrap().is_err());
 assert!(!registry.pool.lock().unwrap().may_connect(address,std::time::Instant::now()));let admitted=registry.admission.lock().unwrap().admit(&hello(3,7,2),address.ip(),&vec![1;64],&cfg.admission,std::time::Instant::now());assert_eq!(admitted,Err(tron_network::handshake::DisconnectReason::RecentDisconnect));
}

#[test]
fn framing_decode_accounts_exact_varint_prefixes_at_boundaries_and_encode_does_not_claim_unsent_bytes(){use bytes::BytesMut;use tokio_util::codec::{Decoder,Encoder};use tron_network::framing::VarintFrameCodec;let mut codec=VarintFrameCodec::default();let mut wire=BytesMut::new();for n in [0,127,128,16383,16384]{codec.encode(Bytes::from(vec![0;n]),&mut wire).unwrap()}let expected_payload=(0+127+128+16383+16384)as u64;let expected_wire=expected_payload+1+1+2+2+3;assert_eq!(codec.traffic().sent_payload,0);assert_eq!(codec.traffic().sent_wire,0);for _ in 0..5{codec.decode(&mut wire).unwrap().unwrap();}assert!(wire.is_empty());assert_eq!(codec.traffic().received_payload,expected_payload);assert_eq!(codec.traffic().received_wire,expected_wire)}

async fn negotiate(direction: Direction, local_compression: bool, remote_compression: bool, keepalive: Duration, pong_timeout: Duration) -> (tokio::task::JoinHandle<Result<tron_network::framing::Traffic, SessionError>>, FramedIo<tokio::io::DuplexStream>) {
    let (rust, peer) = duplex(1 << 20);
    let mut cfg = config(direction);
    cfg.compression = local_compression;
    cfg.keepalive_interval = keepalive;
    cfg.pong_timeout = pong_timeout;
    let task = tokio::spawn(TransportSession::new(FramedIo::new(rust, Duration::from_secs(2)), SocketAddr::from(([127,0,0,1], 4000 + direction as u16)), cfg, SessionRegistry::default()).run(CancellationToken::new()));
    let mut io = FramedIo::new(peer, Duration::from_secs(2));
    match direction {
        Direction::Active => { assert_eq!(io.read_frame().await.unwrap()[0], Control::HandshakeHello.byte()); control(&mut io, Control::HandshakeHello, &hello(2,7,2)).await; }
        Direction::Passive => { control(&mut io, Control::HandshakeHello, &hello(2,7,2)).await; assert_eq!(io.read_frame().await.unwrap()[0], Control::HandshakeHello.byte()); }
    }
    assert_eq!(io.read_frame().await.unwrap()[0], Control::Status.byte());
    control(&mut io, Control::Status, &StatusMessage{from:Some(endpoint(2)),version:2,network_id:7,max_connections:4,current_connections:0,timestamp:10}).await;
    assert_eq!(&io.read_frame().await.unwrap()[..], &[0xfa, if local_compression {1} else {0}]);
    io.write_frame(Bytes::from(vec![0xfa, if remote_compression {1} else {0}])).await.unwrap();
    (task, io)
}

#[tokio::test]
async fn compression_upgrade_is_explicit_and_mixed_modes_fall_back_without_deadlock() {
    for direction in [Direction::Active, Direction::Passive] {
        for (local, remote) in [(false,false),(true,false),(false,true)] {
            let (task, mut io) = negotiate(direction, local, remote, Duration::from_secs(60), Duration::from_secs(60)).await;
            io.write_frame(Bytes::from_static(b"plain application frame")).await.unwrap();
            control(&mut io, Control::Disconnect, &tron_network::handshake::P2pDisconnectMessage{reason:DisconnectReason::PeerQuiting as i32}).await;
            assert!(task.await.unwrap().is_ok());
        }
    }
}

#[tokio::test]
async fn keepalive_preserves_oldest_ping_and_times_out_when_interval_is_shorter() {
    let (task, mut io) = negotiate(Direction::Passive, false, false, Duration::from_millis(15), Duration::from_millis(70)).await;
    let first = io.read_frame().await.unwrap();
    assert_eq!(first[0], Control::KeepAlivePing.byte());
    let first_timestamp = KeepAliveMessage::decode(&first[1..]).unwrap().timestamp;
    assert!(tokio::time::timeout(Duration::from_millis(40), io.read_frame()).await.is_err(), "an outstanding ping must suppress newer pings");
    control(&mut io, Control::KeepAlivePong, &KeepAliveMessage{timestamp:first_timestamp-1}).await;
    let disconnect = tokio::time::timeout(Duration::from_millis(80), io.read_frame()).await.unwrap().unwrap();
    assert_eq!(disconnect[0], Control::Disconnect.byte());
    assert!(matches!(task.await.unwrap(), Err(SessionError::Rejected(DisconnectReason::PingTimeout))));
}

#[tokio::test]
async fn matching_pong_clears_outstanding_ping_and_allows_the_next_ping() {
    let (task, mut io) = negotiate(Direction::Passive, false, false, Duration::from_millis(20), Duration::from_millis(100)).await;
    let first = io.read_frame().await.unwrap();
    let timestamp = KeepAliveMessage::decode(&first[1..]).unwrap().timestamp;
    control(&mut io, Control::KeepAlivePong, &KeepAliveMessage{timestamp}).await;
    let next = tokio::time::timeout(Duration::from_millis(60), io.read_frame()).await.unwrap().unwrap();
    assert_eq!(next[0], Control::KeepAlivePing.byte());
    control(&mut io, Control::Disconnect, &tron_network::handshake::P2pDisconnectMessage{reason:DisconnectReason::PeerQuiting as i32}).await;
    assert!(task.await.unwrap().is_ok());
}

#[tokio::test]
async fn slow_event_consumer_is_bounded_by_decompressed_payload_bytes_and_closes_session() {
    let (rust, peer) = duplex(1 << 20);
    let mut cfg = config(Direction::Passive); cfg.compression=true; cfg.keepalive_interval=Duration::from_secs(60);
    let (tx, mut rx) = session_event_channel(16, 8, Duration::from_millis(30));
    let task = tokio::spawn(TransportSession::new(FramedIo::new(rust,Duration::from_secs(1)),SocketAddr::from(([127,0,0,1],4999)),cfg,SessionRegistry::default()).with_events(tx).run(CancellationToken::new()));
    let mut io=FramedIo::new(peer,Duration::from_secs(1));
    control(&mut io,Control::HandshakeHello,&hello(2,7,2)).await;assert_eq!(io.read_frame().await.unwrap()[0],Control::HandshakeHello.byte());
    assert_eq!(io.read_frame().await.unwrap()[0],Control::Status.byte());control(&mut io,Control::Status,&StatusMessage{from:Some(endpoint(2)),version:2,network_id:7,max_connections:4,current_connections:0,timestamp:10}).await;
    assert_eq!(&io.read_frame().await.unwrap()[..], &[0xfa,1]);io.write_frame(Bytes::from_static(&[0xfa,1])).await.unwrap();
    while !matches!(&*rx.recv().await.unwrap(), SessionEvent::State(SessionState::Connected)) {}
    io.write_frame(Bytes::from(compression::envelope(b"12345678", true).unwrap().encode_to_vec())).await.unwrap();
    let held = rx.recv().await.unwrap(); assert!(matches!(&*held, SessionEvent::Message(_)));
    io.write_frame(Bytes::from(compression::envelope(b"abcdefgh", true).unwrap().encode_to_vec())).await.unwrap();
    let disconnect = tokio::time::timeout(Duration::from_millis(200), io.read_frame()).await.unwrap().unwrap();
    assert_eq!(disconnect[0], Control::Disconnect.byte());
    assert!(matches!(task.await.unwrap(), Err(SessionError::Backpressure)));
    drop(held);
}

#[tokio::test]
async fn ping_flood_with_nonreading_peer_and_cancellation_releases_session_capacity() {
    let (rust, peer) = duplex(128);
    let registry = SessionRegistry::default();
    let mut cfg = config(Direction::Passive);
    cfg.keepalive_interval = Duration::from_secs(60);
    cfg.write_timeout = Duration::from_millis(30);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(TransportSession::new(
        FramedIo::new(rust, Duration::from_secs(1)),
        SocketAddr::from(([127, 0, 0, 1], 5000)),
        cfg,
        registry.clone(),
    ).run(cancel.clone()));
    let mut io = FramedIo::new(peer, Duration::from_secs(1));
    control(&mut io, Control::HandshakeHello, &hello(2, 7, 2)).await;
    assert_eq!(io.read_frame().await.unwrap()[0], Control::HandshakeHello.byte());
    assert_eq!(io.read_frame().await.unwrap()[0], Control::Status.byte());
    control(&mut io, Control::Status, &StatusMessage { from: Some(endpoint(2)), version: 2, network_id: 7, max_connections: 4, current_connections: 0, timestamp: 10 }).await;
    assert_eq!(&io.read_frame().await.unwrap()[..], &[0xfa, 1]);
    io.write_frame(Bytes::from_static(&[0xfa, 1])).await.unwrap();

    let flood = tokio::spawn(async move {
        for timestamp in 0..1_000 {
            control(&mut io, Control::KeepAlivePing, &KeepAliveMessage { timestamp }).await;
        }
    });
    tokio::time::sleep(Duration::from_millis(15)).await;
    let started = std::time::Instant::now();
    cancel.cancel();
    let result = tokio::time::timeout(Duration::from_millis(200), task).await.expect("cancelled session remained stuck in a write").unwrap();
    assert!(result.is_ok() || matches!(result, Err(SessionError::WriteTimeout)));
    assert!(started.elapsed() < Duration::from_millis(200));
    assert_eq!(registry.admission.lock().unwrap().len(), 0);
    assert_eq!(registry.pool.lock().unwrap().len(), 0);
    flood.abort();
}
