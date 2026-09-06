use std::{net::{IpAddr,Ipv4Addr,SocketAddr},time::Duration};
use tron_network::{discovery::*,dns, persistence::*};

fn endpoint(id:u8,ip:[u8;4],port:i32)->Endpoint{Endpoint{address:format!("{}.{}.{}.{}",ip[0],ip[1],ip[2],ip[3]).into_bytes(),port,node_id:vec![id;64],address_ipv6:vec![]}}
#[test]
fn raw_udp_envelope_and_endpoint_capture() {
    let ping=DiscoverMessage::Ping(Ping{from:Some(endpoint(1,[10,0,0,1],18888)),to:None,version:4,timestamp:7});
    let bytes=ping.encode_datagram().unwrap();
    assert_eq!(bytes[0],1);
    assert_eq!(decode_datagram(&bytes).unwrap(),ping);
    assert!(matches!(decode_datagram(&[1]),Err(DiscoveryError::Length(1))));
    assert!(matches!(decode_datagram(&vec![1;2048]),Err(DiscoveryError::Length(2048))));

    let ep=endpoint(1,[10,0,0,1],18888);
    assert_eq!(validate_endpoint(&ep,None).unwrap(),"10.0.0.1:18888".parse().unwrap());
    assert_eq!(validate_endpoint(&ep,Some("10.0.0.1:40000".parse().unwrap())).unwrap(),"10.0.0.1:18888".parse().unwrap());
    assert!(validate_endpoint(&ep,Some("203.0.113.9:40000".parse().unwrap())).is_err());
}

#[test]
fn endpoint_uses_textual_family_fields_and_ipv4_precedence() {
    let mut ep=endpoint(1,[192,0,2,1],18888);
    ep.address_ipv6=b"2001:db8::1".to_vec();
    assert_eq!(validate_endpoint(&ep,None).unwrap(),"192.0.2.1:18888".parse().unwrap());

    ep.address.clear();
    assert_eq!(validate_endpoint(&ep,None).unwrap(),"[2001:db8::1]:18888".parse().unwrap());
}

#[test]
fn endpoint_rejects_unproven_binary_malformed_ambiguous_and_mismatched_values() {
    let valid=endpoint(1,[127,0,0,1],18888);
    let mut cases=Vec::new();
    cases.push(Endpoint{address:vec![127,0,0,1],..valid.clone()});
    cases.push(Endpoint{address:vec![0xff],..valid.clone()});
    cases.push(Endpoint{address:b"2001:db8::1".to_vec(),..valid.clone()});
    cases.push(Endpoint{address_ipv6:b"127.0.0.1".to_vec(),..valid.clone()});
    cases.push(Endpoint{address:Vec::new(),address_ipv6:Vec::new(),..valid.clone()});
    cases.push(Endpoint{node_id:vec![1;63],..valid.clone()});
    cases.push(Endpoint{port:0,..valid});
    assert!(cases.iter().all(|ep| validate_endpoint(ep,None).is_err()));
}

#[test] fn kademlia_distance_ranking_and_eviction(){let mut table=KademliaTable::new([0;64]);for i in 1..=17{let ep=endpoint(i,[127,0,0,i],10000+i as i32);table.insert(NodeRecord{address:validate_endpoint(&ep,None).unwrap(),endpoint:ep,state:NodeState::Alive,update_time:i as i64,last_seen:0,failures:0});}let nearest=table.closest(&[1;64],4);assert!(!nearest.is_empty());let id=nearest[0].endpoint.node_id.clone();table.mark_failed(&id,1);assert!(table.nodes().all(|n|n.endpoint.node_id!=id));}
#[test] fn dns_entries_hash_and_captured_ip(){use prost::Message;let endpoints=EndPoints{nodes:vec![Endpoint{address:b"127.0.0.1".to_vec(),address_ipv6:vec![],port:18888,node_id:vec![7;64]}]};let text=format!("nodes:{}",base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,endpoints.encode_to_vec()));let parsed=dns::parse_entry(&text).unwrap();let dns::Entry::Nodes(nodes)=parsed else{panic!()};assert_eq!(dns::captured_ip(&nodes[0],Some(IpAddr::V4(Ipv4Addr::new(198,51,100,4)))).unwrap(),"198.51.100.4:18888".parse::<SocketAddr>().unwrap());assert_eq!(dns::label(&text).len(),26);assert_eq!(dns::parse_entry("tree-branch:a,b").unwrap(),dns::Entry::Branch(vec!["a".into(),"b".into()]));}
#[test] fn peers_are_sorted_deduplicated_and_limited(){let peers=(0..35).map(|i|PersistedPeer{host:format!("192.0.2.{i}"),port:18888,update_time:i});let bytes=encode_peers(peers).unwrap();let decoded=decode_peers(&bytes);assert_eq!(decoded.len(),30);assert_eq!(decoded[0].update_time,34);assert_eq!(decoded[29].update_time,5);assert_eq!(PEERS_KEY,"peers");}
#[test] fn candidate_priority_is_deterministic(){let address="127.0.0.1:1".parse().unwrap();let mut pool=ConnectionPool::new(2);pool.offer(Candidate{address,node_id:vec![1;64],source:CandidateSource::Persisted,update_time:1,latency:Some(Duration::from_millis(1)),failures:0});pool.offer(Candidate{address,node_id:vec![2;64],source:CandidateSource::Active,update_time:0,latency:None,failures:0});assert_eq!(pool.ranked()[0].node_id,vec![2;64]);}
#[tokio::test] async fn bounded_udp_server_stops(){let(server,_rx)=DiscoveryServer::bind("127.0.0.1:0".parse().unwrap(),1).await.unwrap();server.shutdown().await.unwrap();}

#[derive(Default)]
struct TestAuthenticator;

impl DatagramAuthenticator for TestAuthenticator {
    fn authenticate(&self, source: SocketAddr, packet: &[u8]) -> Option<AuthenticatedDatagram> {
        if packet.len() < 3 { return None; }
        let attested_source = if packet[0] == 0 { source } else { SocketAddr::new(source.ip(), source.port().wrapping_add(1)) };
        Some(AuthenticatedDatagram {
            peer_id: vec![7; 64],
            peer_identity: source.ip(),
            session: u64::from(packet[1]),
            sequence: u64::from(packet[2]),
            source: attested_source,
            payload: packet[3..].to_vec(),
        })
    }
}

#[tokio::test]
async fn secure_receiver_binds_source_and_permanently_retires_sessions() {
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    let receiving = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sending = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = receiving.local_addr().unwrap();
    let mut receiver = SecureReceiver::new(receiving, Arc::new(TestAuthenticator));
    sending.send_to(&[1, 1, 1, 9], target).await.unwrap();
    sending.send_to(&[0, 1, 1, 10], target).await.unwrap();
    assert_eq!(receiver.recv().await.unwrap().payload, vec![10]);
    sending.send_to(&[0, 2, 1, 11], target).await.unwrap();
    assert_eq!(receiver.recv().await.unwrap().session, 2);
    sending.send_to(&[0, 1, 255, 12], target).await.unwrap();
    sending.send_to(&[0, 2, 2, 13], target).await.unwrap();
    let accepted = receiver.recv().await.unwrap();
    assert_eq!((accepted.session, accepted.sequence, accepted.payload), (2, 2, vec![13]));
}

#[test]
fn c018_adapter_preserves_authenticated_identity_source_port_and_session() {
    use std::{net::UdpSocket, sync::Arc, thread};
    use tron_consensus::backup::{DatagramSocket, ReceivedDatagram};
    let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let target = raw.local_addr().unwrap();
    let adapter = SecureDatagramSocket::new(raw, Arc::new(TestAuthenticator));
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let source = sender.local_addr().unwrap();
    thread::spawn(move || { sender.send_to(&[0, 9, 17, 42], target).unwrap(); }).join().unwrap();
    let ReceivedDatagram::Authenticated(packet) = adapter.recv_datagram().unwrap() else { panic!("secure adapter returned unauthenticated data") };
    assert_eq!(packet.payload, vec![42]);
    assert_eq!(packet.source, source);
    assert_eq!(packet.peer_identity, source.ip());
    assert_eq!((packet.session, packet.sequence), (9, 17));
}

struct IdentityAuthenticator;
impl DatagramAuthenticator for IdentityAuthenticator {
    fn authenticate(&self, source: SocketAddr, packet: &[u8]) -> Option<AuthenticatedDatagram> {
        Some(AuthenticatedDatagram { peer_id: vec![*packet.first()?; 64], peer_identity: source.ip(), session: 1, sequence: u64::from(*packet.get(1)?), source, payload: packet.to_vec() })
    }
}

#[tokio::test]
async fn secure_receiver_caps_authenticated_peer_sessions() {
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    let receiving = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sending = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = receiving.local_addr().unwrap();
    let mut receiver = SecureReceiver::with_session_capacity(receiving, Arc::new(IdentityAuthenticator), 1);
    sending.send_to(&[1, 1], target).await.unwrap();
    assert_eq!(receiver.recv().await.unwrap().peer_id, vec![1; 64]);
    sending.send_to(&[2, 1], target).await.unwrap();
    sending.send_to(&[1, 2], target).await.unwrap();
    assert_eq!(receiver.recv().await.unwrap().peer_id, vec![1; 64], "new identities beyond the bound must not displace replay state");
}

#[tokio::test]
async fn status_probe_has_one_deadline_under_spoof_flood() {
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    let probe = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = probe.local_addr().unwrap();
    let flood = tokio::spawn(async move { loop { let _ = attacker.send_to(&[2, 8], target).await; tokio::task::yield_now().await; } });
    let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let started = tokio::time::Instant::now();
    let result = status_probe(&probe, peer, &Ping { from: None, to: None, version: 1, timestamp: 1 }, Duration::from_millis(30)).await;
    flood.abort();
    assert!(matches!(&result, Err(DiscoveryError::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut));
    assert!(started.elapsed() < Duration::from_millis(250));
}

#[derive(Clone)]
struct EnvelopeAuthenticator {
    local: SocketAddr,
    peer: SocketAddr,
    secret: [u8; 32],
}

impl EnvelopeAuthenticator {
    fn body(&self, source: SocketAddr, destination: SocketAddr, session: u64, sequence: u64, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(source.to_string().as_bytes());
        body.push(0);
        body.extend_from_slice(destination.to_string().as_bytes());
        body.push(0);
        body.extend_from_slice(&session.to_be_bytes());
        body.extend_from_slice(&sequence.to_be_bytes());
        body.extend_from_slice(payload);
        body
    }

    fn tag(&self, body: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(self.secret);
        hash.update(body);
        hash.update(self.secret);
        hash.finalize().into()
    }
}

impl DatagramAuthenticator for EnvelopeAuthenticator {
    fn authenticate(&self, source: SocketAddr, packet: &[u8]) -> Option<AuthenticatedDatagram> {
        if source != self.peer || packet.len() < 4 + 8 + 8 + 32 { return None; }
        let source_len = u16::from_be_bytes(packet.get(0..2)?.try_into().ok()?) as usize;
        let destination_len = u16::from_be_bytes(packet.get(2..4)?.try_into().ok()?) as usize;
        let header = 4usize.checked_add(source_len)?.checked_add(destination_len)?.checked_add(16)?;
        if packet.len() < header + 32 { return None; }
        let declared_source: SocketAddr = std::str::from_utf8(packet.get(4..4 + source_len)?).ok()?.parse().ok()?;
        let declared_destination: SocketAddr = std::str::from_utf8(packet.get(4 + source_len..4 + source_len + destination_len)?).ok()?.parse().ok()?;
        if declared_source != source || declared_destination != self.local { return None; }
        let session_offset = 4 + source_len + destination_len;
        let session = u64::from_be_bytes(packet.get(session_offset..session_offset + 8)?.try_into().ok()?);
        let sequence = u64::from_be_bytes(packet.get(session_offset + 8..session_offset + 16)?.try_into().ok()?);
        let payload = packet.get(header..packet.len() - 32)?;
        let body = self.body(source, self.local, session, sequence, payload);
        if self.tag(&body).as_slice() != packet.get(packet.len() - 32..)? { return None; }
        Some(AuthenticatedDatagram { peer_id: vec![7; 64], peer_identity: source.ip(), session, sequence, source, payload: payload.to_vec() })
    }

    fn seal(&self, destination_identity: IpAddr, destination: SocketAddr, local_identity: IpAddr, source: SocketAddr, session: u64, sequence: u64, payload: &[u8]) -> Option<Vec<u8>> {
        if destination != self.peer || destination_identity != self.peer.ip() || local_identity != self.local.ip() || source != self.local { return None; }
        let source_text = source.to_string();
        let destination_text = destination.to_string();
        let body = self.body(source, destination, session, sequence, payload);
        let mut packet = Vec::with_capacity(4 + source_text.len() + destination_text.len() + 16 + payload.len() + 32);
        packet.extend_from_slice(&u16::try_from(source_text.len()).ok()?.to_be_bytes());
        packet.extend_from_slice(&u16::try_from(destination_text.len()).ok()?.to_be_bytes());
        packet.extend_from_slice(source_text.as_bytes());
        packet.extend_from_slice(destination_text.as_bytes());
        packet.extend_from_slice(&session.to_be_bytes());
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(payload);
        packet.extend_from_slice(&self.tag(&body));
        Some(packet)
    }
}

#[test]
fn two_secure_adapters_exchange_exact_keepalives_and_reject_replay_and_tamper() {
    use std::{net::UdpSocket, sync::Arc};
    use tron_consensus::backup::{DatagramSocket, ReceivedDatagram};

    let raw_a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let injector_a = raw_a.try_clone().unwrap();
    let raw_b = UdpSocket::bind("127.0.0.1:0").unwrap();
    raw_a.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    raw_b.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let address_a = raw_a.local_addr().unwrap();
    let address_b = raw_b.local_addr().unwrap();
    let secret = [0x5a; 32];
    let adapter_a = SecureDatagramSocket::with_session_and_capacity(raw_a, Arc::new(EnvelopeAuthenticator { local: address_a, peer: address_b, secret }), 41, 2);
    let adapter_b = SecureDatagramSocket::with_session_and_capacity(raw_b, Arc::new(EnvelopeAuthenticator { local: address_b, peer: address_a, secret }), 73, 2);
    let payload_a = [0x05, 0x08, 0x01, 0x10, 0x00, 0xff, 0x00];
    let payload_b = [0x05, 0x08, 0x00, 0x10, 0x09];

    assert_eq!(adapter_a.send_to(&payload_a, address_b).unwrap(), payload_a.len());
    let ReceivedDatagram::Authenticated(received_a) = adapter_b.recv_datagram().unwrap() else { panic!() };
    assert_eq!((received_a.payload, received_a.source, received_a.session, received_a.sequence), (payload_a.to_vec(), address_a, 41, 1));
    assert_eq!(adapter_b.send_to(&payload_b, address_a).unwrap(), payload_b.len());
    let ReceivedDatagram::Authenticated(received_b) = adapter_a.recv_datagram().unwrap() else { panic!() };
    assert_eq!((received_b.payload, received_b.source, received_b.session, received_b.sequence), (payload_b.to_vec(), address_b, 73, 1));
    let auth_a = EnvelopeAuthenticator { local: address_a, peer: address_b, secret };
    let replay = auth_a.seal(address_b.ip(), address_b, address_a.ip(), address_a, 41, 1, &payload_a).unwrap();
    let rollover = auth_a.seal(address_b.ip(), address_b, address_a.ip(), address_a, 42, 1, &payload_b).unwrap();
    injector_a.send_to(&replay, address_b).unwrap();
    injector_a.send_to(&rollover, address_b).unwrap();
    let ReceivedDatagram::Authenticated(rolled) = adapter_b.recv_datagram().unwrap() else { panic!() };
    assert_eq!((rolled.session, rolled.sequence, rolled.payload), (42, 1, payload_b.to_vec()));
    let retired = auth_a.seal(address_b.ip(), address_b, address_a.ip(), address_a, 41, 99, &payload_a).unwrap();
    let fresh = auth_a.seal(address_b.ip(), address_b, address_a.ip(), address_a, 42, 2, &payload_a).unwrap();
    injector_a.send_to(&retired, address_b).unwrap();
    injector_a.send_to(&fresh, address_b).unwrap();
    let ReceivedDatagram::Authenticated(after_retired) = adapter_b.recv_datagram().unwrap() else { panic!() };
    assert_eq!((after_retired.session, after_retired.sequence), (42, 2));

    let mut wrong_destination = replay.clone();
    wrong_destination[4 + address_a.to_string().len()] ^= 1;
    assert!(EnvelopeAuthenticator { local: address_b, peer: address_a, secret }.authenticate(address_a, &wrong_destination).is_none());
    assert!(EnvelopeAuthenticator { local: address_b, peer: SocketAddr::new(address_a.ip(), address_a.port().wrapping_add(1)), secret }.authenticate(address_a, &replay).is_none());
}
