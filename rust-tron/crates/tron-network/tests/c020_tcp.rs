use bytes::{Bytes,BytesMut};
use prost::Message;
use std::{collections::HashSet,net::{IpAddr,Ipv4Addr,SocketAddr},time::{Duration,Instant}};
use tokio_util::codec::{Decoder,Encoder};
use tron_network::{compression::{self,CompressMessage,CompressType},connection::{ConnectionPool,Direction,Peer,PoolConfig,PoolError},framing::{VarintFrameCodec,MAX_FRAME_SIZE},handshake::*};

#[test] fn protobuf_varint_frames_and_limits(){let mut c=VarintFrameCodec::default();let mut b=BytesMut::new();c.encode(Bytes::from_static(b"abc"),&mut b).unwrap();assert_eq!(&b[..],b"\x03abc");assert_eq!(&c.decode(&mut b).unwrap().unwrap()[..],b"abc");let mut over=BytesMut::from(&[0x81,0x80,0xc0,0x02][..]);assert!(c.decode(&mut over).is_err());let mut malformed=BytesMut::from(&[0x80;5][..]);assert!(c.decode(&mut malformed).is_err());assert_eq!(MAX_FRAME_SIZE,5_242_880)}
#[test] fn control_bytes_and_bounded_connect_schema(){
 assert_eq!(Control::KeepAlivePing.byte(),0xff);assert_eq!(Control::Disconnect.byte(),0xfb);assert!(Control::parse(0x20).is_none());
 let endpoint=Endpoint{address:b"127.0.0.1".to_vec(),port:18888,node_id:vec![1;64],address_ipv6:vec![]};
 let hello=HelloMessage{from:Some(endpoint.clone()),network_id:728126428,code:0,timestamp:9,version:1};
 assert_eq!(decode_hello(&hello.encode_to_vec()).unwrap(),hello);
 let status=StatusMessage{from:Some(endpoint),version:1,network_id:728126428,max_connections:30,current_connections:1,timestamp:9};
 assert_eq!(decode_status(&status.encode_to_vec()).unwrap(),status);
 assert_eq!(DisconnectReason::Unknown as i32,255);
}
#[test] fn compression_is_negotiated_and_bounded(){let input=vec![7;32_000];let e=compression::envelope(&input,true).unwrap();assert_eq!(e.r#type,CompressType::Snappy as i32);assert_eq!(compression::open(&e).unwrap(),input);assert!(compression::envelope(&vec![0;MAX_FRAME_SIZE+1],true).is_err());let forged=CompressMessage{r#type:99,data:vec![]};assert!(compression::open(&forged).is_err())}
#[test] fn admission_rejects_near_max_identity_without_retention_and_accepts_exact_64(){
 let now=Instant::now();let ip=IpAddr::V4(Ipv4Addr::LOCALHOST);let cfg=AdmissionConfig{network_id:1,version:2,max_connections:1,max_same_ip:1,trusted:HashSet::new(),ban_duration:Duration::from_secs(10)};
 let hello=|node_id|HelloMessage{from:Some(Endpoint{address:b"127.0.0.1".to_vec(),port:1,node_id,address_ipv6:vec![]}),network_id:1,code:0,timestamp:0,version:2};
 let mut admission=Admission::default();let local=vec![9;64];
 assert_eq!(admission.admit(&hello(vec![7;MAX_FRAME_SIZE-128]),ip,&local,&cfg,now),Err(DisconnectReason::BadProtocol));
 assert_eq!(admission.len(),0);assert_eq!(admission.retained_identity_bytes(),0,"rejected maximum-frame identity must not reach the HashMap");
 admission.admit(&hello(vec![1;64]),ip,&local,&cfg,now).unwrap();assert_eq!(admission.retained_identity_bytes(),64);
 assert_eq!(admission.admit(&hello(vec![1;64]),ip,&local,&cfg,now),Err(DisconnectReason::DuplicatePeer));
 admission.remove(&vec![1;64]);admission.ban(ip,now+Duration::from_secs(1));assert_eq!(admission.admit(&hello(vec![2;64]),ip,&local,&cfg,now),Err(DisconnectReason::RecentDisconnect));
}

#[test] fn malformed_endpoint_and_all_decoded_endpoint_fields_are_rejected(){
 let base=Endpoint{address:b"127.0.0.1".to_vec(),port:18888,node_id:vec![3;64],address_ipv6:vec![]};
 for endpoint in [Endpoint{address:vec![0xff],..base.clone()},Endpoint{address:vec![b'1';16],..base.clone()},Endpoint{address:vec![],address_ipv6:vec![b'a';46],..base.clone()},Endpoint{port:0,..base.clone()},Endpoint{node_id:vec![3;63],..base.clone()}] {
  let hello=HelloMessage{from:Some(endpoint.clone()),network_id:1,code:0,timestamp:0,version:1};assert!(decode_hello(&hello.encode_to_vec()).is_err());
  let status=StatusMessage{from:Some(endpoint),version:1,network_id:1,max_connections:1,current_connections:0,timestamp:0};assert!(decode_status(&status.encode_to_vec()).is_err());
 }
}

#[test] fn pool_tracks_direction_trust_backoff_and_rejects_identity_before_clone(){let now=Instant::now();let cfg=PoolConfig{min_connections:1,max_connections:1,min_active:1,max_same_ip:1,initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(8)};let addr=SocketAddr::from(([127,0,0,1],1));let mut p=ConnectionPool::default();assert_eq!(p.insert(Peer{node_id:vec![1;MAX_FRAME_SIZE-128],address:addr,direction:Direction::Active,trusted:false,connected_at:now,last_seen:now},&cfg),Err(PoolError::InvalidIdentity));assert_eq!(p.len(),0);p.insert(Peer{node_id:vec![1;64],address:addr,direction:Direction::Active,trusted:false,connected_at:now,last_seen:now},&cfg).unwrap();assert!(!p.needs_connections(&cfg));assert_eq!(p.insert(Peer{node_id:vec![2;64],address:SocketAddr::from(([127,0,0,2],2)),direction:Direction::Passive,trusted:false,connected_at:now,last_seen:now},&cfg),Err(PoolError::Full));p.record_failure(addr,&cfg,now);assert!(!p.may_connect(addr,now));assert!(p.may_connect(addr,now+Duration::from_secs(1)))}

#[test]
fn varint32_rejects_exact_malformed_fifth_bytes_without_eager_reserve() {
    for bytes in [[0x80, 0x80, 0x80, 0x80, 0x10], [0x80, 0x80, 0x80, 0x80, 0x80], [0xff, 0xff, 0xff, 0xff, 0x7f]] {
        let mut codec = VarintFrameCodec::default();
        assert!(codec.decode(&mut BytesMut::from(&bytes[..])).is_err());
    }
    let mut codec = VarintFrameCodec::default();
    let mut declared_max = BytesMut::from(&[0x80, 0x80, 0xc0, 0x02][..]);
    let capacity = declared_max.capacity();
    assert!(codec.decode(&mut declared_max).unwrap().is_none());
    assert_eq!(declared_max.capacity(), capacity, "decoder must not reserve the declared body");
}

#[tokio::test]
async fn tcp_pre_admission_timeout_and_cancel_are_bounded() {
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::sync::CancellationToken;
    use tron_network::tcp::{serve_with_config, ServeConfig};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let entered = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let observed = entered.clone();
    let active_handler = active.clone();
    let peak_handler = peak.clone();
    let server_cancel = cancel.clone();
    let server = tokio::spawn(async move {
        serve_with_config(listener, server_cancel, ServeConfig { max_connections: 2, max_connections_per_ip: 1, handshake_timeout: Duration::from_millis(80), write_timeout: Duration::from_millis(80), aggregate_buffer_bytes: 8192 }, move |_stream, _address| {
            observed.fetch_add(1, Ordering::SeqCst);
            let active = active_handler.clone();
            let peak = peak_handler.clone();
            async move {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(60)).await;
                active.fetch_sub(1, Ordering::SeqCst);
            }
        }).await.unwrap();
    });
    let mut clients = Vec::new();
    for _ in 0..32 { clients.push(TcpStream::connect(address).await.unwrap()); }
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(entered.load(Ordering::SeqCst), 1, "per-IP admission happens before spawning handlers");
    assert_eq!(peak.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _replacement = TcpStream::connect(address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(entered.load(Ordering::SeqCst) >= 2, "timed-out handshake must drain admission");
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), server).await.unwrap().unwrap();
    drop(clients);
}

#[tokio::test]
async fn cancellation_token_does_not_miss_cancel_race() {
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;
    use tron_network::tcp::serve;
    for _ in 0..64 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        tokio::time::timeout(Duration::from_millis(100), serve(listener, cancel, |_stream, _address| async {})).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn framed_io_accounts_and_releases_incremental_buffer_budget() {
    use tokio::io::{AsyncWriteExt, duplex};
    use tron_network::tcp::{BufferBudget, FramedIo};
    let (mut writer, reader) = duplex(128);
    writer.write_all(b"\x03one\x03two").await.unwrap();
    let budget = BufferBudget::new(8);
    let mut framed = FramedIo::with_budget(reader, Duration::from_secs(1), budget.clone());
    assert_eq!(&framed.read_frame().await.unwrap()[..], b"one");
    assert_eq!(&framed.read_frame().await.unwrap()[..], b"two");
    assert_eq!(budget.available(), 8, "consumed pipelined bytes must return aggregate permits");
    assert_eq!(framed.buffer_capacity(), 0, "completed frames must release retained allocation");
}

#[tokio::test]
async fn completed_large_frame_does_not_pin_capacity_for_small_tail() {
    use tokio::io::{AsyncWriteExt, duplex};
    use tron_network::tcp::{BufferBudget, FramedIo};
    let body = vec![3u8; 64 * 1024];
    let mut wire = BytesMut::new();
    VarintFrameCodec::default().encode(Bytes::from(body.clone()), &mut wire).unwrap();
    wire.extend_from_slice(&[1]);
    let (mut writer, reader) = duplex(wire.len());
    let sending = tokio::spawn(async move { writer.write_all(&wire).await.unwrap(); });
    let mut framed = FramedIo::with_budget(reader, Duration::from_secs(1), BufferBudget::new(256 * 1024));
    assert_eq!(framed.read_frame().await.unwrap().len(), body.len());
    assert!(framed.buffer_capacity() <= 8 * 1024 + 1, "small pipelined tail retained oversized frame allocation");
    sending.await.unwrap();
}

#[tokio::test]
async fn established_session_is_not_subject_to_handshake_timeout() {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::sync::CancellationToken;
    use tron_network::tcp::{ConnectionSession, ServeConfig, serve_with_config};
    struct SessionAlive(Arc<AtomicBool>);
    impl Drop for SessionAlive { fn drop(&mut self) { self.0.store(false, Ordering::SeqCst); } }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let alive = Arc::new(AtomicBool::new(false));
    let observed = alive.clone();
    let server_cancel = cancel.clone();
    let server = tokio::spawn(async move {
        serve_with_config(listener, server_cancel, ServeConfig { max_connections: 1, max_connections_per_ip: 1, handshake_timeout: Duration::from_millis(20), write_timeout: Duration::from_millis(20), aggregate_buffer_bytes: 1024 }, move |_framed, _address| {
            let observed = observed.clone();
            async move {
                Box::pin(async move {
                    observed.store(true, Ordering::SeqCst);
                    let _alive = SessionAlive(observed);
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }) as ConnectionSession
            }
        }).await.unwrap();
    });
    let _client = TcpStream::connect(address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(alive.load(Ordering::SeqCst));
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), server).await.unwrap().unwrap();
}

#[tokio::test]
async fn framed_io_counts_only_successful_wire_writes_and_credits_payload_on_completion() {
    use std::{io, pin::Pin, task::{Context, Poll}};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tron_network::tcp::FramedIo;

    struct PartialWriter { remaining: usize }
    impl AsyncRead for PartialWriter {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    }
    impl AsyncWrite for PartialWriter {
        fn poll_write(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            if self.remaining == 0 { return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected partial failure"))); }
            let written = self.remaining.min(buf.len()).min(2);
            self.remaining -= written;
            Poll::Ready(Ok(written))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    }

    let mut failed = FramedIo::new(PartialWriter { remaining: 3 }, Duration::from_secs(1));
    assert!(failed.write_frame(Bytes::from_static(b"hello")).await.is_err());
    assert_eq!(failed.traffic().sent_wire, 3);
    assert_eq!(failed.traffic().sent_payload, 0);

    let mut completed = FramedIo::new(PartialWriter { remaining: 6 }, Duration::from_secs(1));
    completed.write_frame(Bytes::from_static(b"hello")).await.unwrap();
    assert_eq!(completed.traffic().sent_wire, 6);
    assert_eq!(completed.traffic().sent_payload, 5);
}

#[tokio::test]
async fn whole_frame_write_uses_one_deadline_and_reports_typed_timeout() {
    use std::{io, pin::Pin, task::{Context, Poll}};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tron_network::tcp::{is_write_timeout, FramedIo};

    struct WriteOnceThenStall(bool);
    impl AsyncRead for WriteOnceThenStall {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> { Poll::Pending }
    }
    impl AsyncWrite for WriteOnceThenStall {
        fn poll_write(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
            if self.0 { Poll::Pending } else { self.0 = true; Poll::Ready(Ok(1)) }
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    }

    let deadline = Duration::from_millis(30);
    let mut io = FramedIo::with_timeouts(WriteOnceThenStall(false), Duration::from_secs(1), deadline);
    let started = Instant::now();
    let error = io.write_frame(Bytes::from_static(b"payload")).await.unwrap_err();
    assert!(is_write_timeout(&error));
    assert!(started.elapsed() < Duration::from_millis(150), "partial progress must not restart the deadline");
    assert_eq!(io.traffic().sent_wire, 1);
    assert_eq!(io.traffic().sent_payload, 0);
}

#[tokio::test]
async fn stalled_connections_release_server_admission_for_a_legitimate_peer() {
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::sync::CancellationToken;
    use tron_network::tcp::{serve_with_config, ServeConfig};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let entered = Arc::new(AtomicUsize::new(0));
    let observed = entered.clone();
    let server_cancel = cancel.clone();
    let server = tokio::spawn(async move {
        serve_with_config(listener, server_cancel, ServeConfig { max_connections: 2, max_connections_per_ip: 2, handshake_timeout: Duration::from_secs(1), write_timeout: Duration::from_millis(40), aggregate_buffer_bytes: 1 << 20 }, move |mut io, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            async move { let _ = io.write_frame(Bytes::from(vec![9; 5_000_000])).await; }
        }).await.unwrap();
    });
    let first = TcpStream::connect(address).await.unwrap();
    let second = TcpStream::connect(address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    let legitimate = TcpStream::connect(address).await.unwrap();
    tokio::time::timeout(Duration::from_millis(200), async {
        while entered.load(Ordering::SeqCst) < 3 { tokio::time::sleep(Duration::from_millis(5)).await; }
    }).await.expect("timed-out writes must release global and per-IP admission");
    drop((first, second, legitimate));
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), server).await.unwrap().unwrap();
}
