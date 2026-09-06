use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tron_config::NodeBackupConfig;
use tron_consensus::backup::{decode_keep_alive, encode_keep_alive, AuthenticatedDatagram, BackupClock, BackupConfig, BackupManager, BackupService, BackupStatus, DatagramSocket, DnsResolver, ReceivedDatagram, SocketFactory, SystemSocketFactory};
use tron_protocol::protocol::BackupMessage;

fn ip(value: &str) -> IpAddr { value.parse().unwrap() }

#[test]
fn pinned_java_keep_alive_vectors() {
    let cases = [
        (BackupMessage { flag: false, priority: 6 }, vec![0x05, 0x10, 0x06]),
        (BackupMessage { flag: true, priority: 10 }, vec![0x05, 0x08, 0x01, 0x10, 0x0a]),
        (BackupMessage { flag: false, priority: 0 }, vec![0x05]),
    ];
    for (message, expected) in cases {
        assert_eq!(encode_keep_alive(&message).unwrap(), expected);
        assert_eq!(decode_keep_alive(&expected).unwrap(), message);
    }
    assert!(decode_keep_alive(&[]).is_err());
    assert!(decode_keep_alive(&[0x04]).is_err());
    assert!(decode_keep_alive(&vec![0x05; 2048]).is_err());
}

#[test]
fn election_preserves_java_transitions_and_spelling() {
    let interval = Duration::from_secs(3);
    let mut manager = BackupManager::new(ip("127.0.0.1"), 6, interval, Duration::ZERO);
    assert_eq!(manager.status(), BackupStatus::INIT);
    assert_eq!(format!("{:?}", BackupStatus::SLAVER), "SLAVER");

    manager.on_keep_alive(ip("127.0.0.2"), &BackupMessage { flag: false, priority: 6 }, Duration::from_secs(1));
    assert_eq!(manager.status(), BackupStatus::INIT);
    manager.on_keep_alive(ip("127.0.0.2"), &BackupMessage { flag: true, priority: 6 }, Duration::from_secs(2));
    assert_eq!(manager.status(), BackupStatus::SLAVER);

    manager.tick(Duration::from_secs(20));
    assert_eq!(manager.status(), BackupStatus::SLAVER);
    manager.tick(Duration::from_secs(21));
    assert_eq!(manager.status(), BackupStatus::INIT);
    manager.tick(Duration::from_secs(40));
    assert_eq!(manager.status(), BackupStatus::MASTER);

    manager.on_keep_alive(ip("127.0.0.2"), &BackupMessage { flag: true, priority: 5 }, Duration::from_secs(40));
    assert_eq!(manager.status(), BackupStatus::MASTER);
    manager.on_keep_alive(ip("127.0.0.2"), &BackupMessage { flag: true, priority: 6 }, Duration::from_secs(41));
    assert_eq!(manager.status(), BackupStatus::SLAVER, "equal priority: lexicographically smaller local IP yields");
}

#[test]
fn higher_priority_wins_and_timeout_is_strictly_over_six_intervals() {
    let interval = Duration::from_millis(500);
    let mut manager = BackupManager::new(ip("10.0.0.9"), 10, interval, Duration::ZERO);
    manager.on_keep_alive(ip("10.0.0.8"), &BackupMessage { flag: false, priority: 11 }, Duration::ZERO);
    assert_eq!(manager.status(), BackupStatus::SLAVER);
    manager.tick(Duration::from_secs(3));
    assert_eq!(manager.status(), BackupStatus::SLAVER);
    manager.tick(Duration::from_millis(3001));
    assert_eq!(manager.status(), BackupStatus::INIT);
}

fn available_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port()
}

#[test]
fn plain_udp_forged_tuple_is_legacy_non_producing() {
    let port = available_port();
    let mut config = BackupConfig::new(
        SocketAddr::from(([127, 0, 0, 1], port)),
        ip("127.0.0.1"),
        vec!["127.0.0.2".into()],
        6,
    );
    config.keep_alive_interval = Duration::from_millis(25);
    let mut insecure_production = BackupService::production(config.clone(), Arc::new(SystemSocketFactory));
    let error = insecure_production.start().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let mut service = BackupService::system_legacy_java(config);
    assert!(service.start().unwrap());
    assert!(!service.is_producing());
    let packet = encode_keep_alive(&BackupMessage { flag: true, priority: 6 }).unwrap();
    let forged = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 2], port))).unwrap();
    forged.send_to(&packet, service.local_addr().unwrap()).unwrap();
    thread::sleep(Duration::from_millis(40));
    assert_eq!(service.status(), BackupStatus::INIT);
    service.close();
}

#[test]
fn server_requires_nonzero_port_and_members() {
    let base = BackupConfig::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        ip("127.0.0.1"),
        vec!["127.0.0.2".into()],
        1,
    );
    let mut zero_port = BackupService::system_legacy_java(base.clone());
    assert!(!zero_port.start().unwrap());

    let mut no_members = base;
    no_members.bind.set_port(available_port());
    no_members.members.clear();
    let mut service = BackupService::system_legacy_java(no_members);
    assert!(!service.start().unwrap());
}

#[derive(Default)]
struct FakeClock(AtomicU64);

impl BackupClock for FakeClock {
    fn now(&self) -> Duration { Duration::from_millis(self.0.load(Ordering::Acquire)) }
    fn sleep(&self, duration: Duration) { self.0.fetch_add(duration.as_millis() as u64, Ordering::AcqRel); }
}

struct FixedDns;

impl DnsResolver for FixedDns {
    fn resolve(&self, member: &str) -> io::Result<Vec<IpAddr>> {
        assert_eq!(member, "backup.example");
        Ok(vec![ip("192.0.2.7")])
    }
}

#[derive(Default)]
struct FakeSocket {
    sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    incoming: Mutex<Vec<ReceivedDatagram>>,
}

impl DatagramSocket for FakeSocket {
    fn send_to(&self, bytes: &[u8], address: SocketAddr) -> io::Result<usize> {
        self.sent.lock().unwrap().push((bytes.to_vec(), address));
        Ok(bytes.len())
    }
    fn recv_datagram(&self) -> io::Result<ReceivedDatagram> {
        self.incoming.lock().unwrap().pop().ok_or_else(|| io::ErrorKind::WouldBlock.into())
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, 19001)))
    }
}

struct FakeFactory {
    socket: Arc<FakeSocket>,
    binds: AtomicUsize,
}

impl SocketFactory for FakeFactory {
    fn bind(&self, _address: SocketAddr) -> io::Result<Arc<dyn DatagramSocket>> {
        self.binds.fetch_add(1, Ordering::AcqRel);
        Ok(self.socket.clone())
    }
    fn supplies_authenticated_datagrams(&self) -> bool { true }
}

#[test]
fn injected_clock_dns_and_socket_drive_deterministic_keepalive() {
    let clock = Arc::new(FakeClock::default());
    let socket = Arc::new(FakeSocket::default());
    let factory = Arc::new(FakeFactory { socket: socket.clone(), binds: AtomicUsize::new(0) });
    let config = BackupConfig::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 19001)),
        ip("192.0.2.1"),
        vec!["backup.example".into()],
        9,
    );
    let mut service = BackupService::new(config, clock, Arc::new(FixedDns), factory.clone());
    assert!(service.start().unwrap());
    for _ in 0..100 {
        if !socket.sent.lock().unwrap().is_empty() { break; }
        thread::sleep(Duration::from_millis(1));
    }
    service.close();
    let sent = socket.sent.lock().unwrap();
    assert!(!sent.is_empty());
    assert_eq!(sent[0].1, SocketAddr::new(ip("192.0.2.7"), 19001));
    assert_eq!(decode_keep_alive(&sent[0].0).unwrap(), BackupMessage { flag: false, priority: 9 });
    assert_eq!(factory.binds.load(Ordering::Acquire), 1);
}

struct RefreshingDns(AtomicUsize);

impl DnsResolver for RefreshingDns {
    fn resolve(&self, member: &str) -> io::Result<Vec<IpAddr>> {
        assert_eq!(member, "backup.example");
        let call = self.0.fetch_add(1, Ordering::AcqRel);
        Ok(if call == 0 {
            vec![ip("192.0.2.7"), ip("192.0.2.8")]
        } else {
            vec![ip("192.0.2.9"), ip("192.0.2.10")]
        })
    }
}

#[test]
fn dns_uses_java_first_answer_and_atomically_replaces_old_address() {
    let clock = Arc::new(FakeClock::default());
    let socket = Arc::new(FakeSocket::default());
    let factory = Arc::new(FakeFactory { socket: socket.clone(), binds: AtomicUsize::new(0) });
    let mut config = BackupConfig::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 19001)),
        ip("192.0.2.1"),
        vec!["backup.example".into()],
        9,
    );
    config.keep_alive_interval = Duration::from_millis(100);
    config.dns_refresh_interval = Duration::from_millis(1_050);
    let mut service = BackupService::new(
        config,
        clock,
        Arc::new(RefreshingDns(AtomicUsize::new(0))),
        factory,
    );
    service.start().unwrap();
    for _ in 0..100 {
        let destinations: BTreeSet<_> = socket.sent.lock().unwrap().iter().map(|(_, address)| address.ip()).collect();
        if destinations.contains(&ip("192.0.2.7")) && destinations.contains(&ip("192.0.2.9")) { break; }
        thread::sleep(Duration::from_millis(1));
    }
    service.close();
    let destinations: BTreeSet<_> = socket.sent.lock().unwrap().iter().map(|(_, address)| address.ip()).collect();
    assert!(destinations.contains(&ip("192.0.2.7")), "initial Java-first DNS answer used");
    assert!(destinations.contains(&ip("192.0.2.9")), "refreshed Java-first DNS answer used");
    assert!(!destinations.contains(&ip("192.0.2.8")), "second initial DNS answer ignored");
    assert!(!destinations.contains(&ip("192.0.2.10")), "second refreshed DNS answer ignored");
    let sent = socket.sent.lock().unwrap();
    let cutover = sent.iter().position(|(_, address)| address.ip() == ip("192.0.2.9")).unwrap();
    assert!(sent[cutover..].iter().all(|(_, address)| address.ip() != ip("192.0.2.7")), "old DNS address is removed at refresh cutover");
}

#[test]
fn authenticated_packets_enforce_identity_port_replay_and_session() {
    let socket = Arc::new(FakeSocket::default());
    let payload = encode_keep_alive(&BackupMessage { flag: true, priority: 9 }).unwrap();
    let packet = |source, identity, session, sequence| ReceivedDatagram::Authenticated(AuthenticatedDatagram {
        payload: payload.clone(), source, peer_identity: identity, session, sequence,
    });
    let expected = SocketAddr::new(ip("192.0.2.7"), 19001);
    socket.incoming.lock().unwrap().extend([
        packet(expected, ip("192.0.2.7"), 2, 1),
        packet(expected, ip("192.0.2.7"), 1, 99),
        packet(expected, ip("192.0.2.7"), 1, 1),
        packet(SocketAddr::new(ip("192.0.2.7"), 19002), ip("192.0.2.7"), 1, 1),
        packet(expected, ip("192.0.2.8"), 1, 1),
        ReceivedDatagram::Unauthenticated { payload, source: expected },
    ]);
    let factory = Arc::new(FakeFactory { socket, binds: AtomicUsize::new(0) });
    let mut config = BackupConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 19001)), ip("192.0.2.1"), vec!["backup.example".into()], 9);
    config.keep_alive_interval = Duration::from_secs(3_600);
    let mut service = BackupService::new(config, Arc::new(FakeClock::default()), Arc::new(FixedDns), factory);
    service.start().unwrap();
    for _ in 0..100 {
        if service.status() == BackupStatus::SLAVER { break; }
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(service.status(), BackupStatus::SLAVER, "only the fresh authenticated session packet elects SLAVER");
    service.close();
}

#[test]
fn deployment_config_seam_preserves_backup_settings_and_rejects_invalid_values() {
    let node = NodeBackupConfig {
        port: 19002,
        priority: 17,
        keep_alive_interval: 750,
        members: vec!["backup.example".into()],
    };
    let config = BackupConfig::from_node_config(ip("0.0.0.0"), ip("192.0.2.1"), &node).unwrap();
    assert_eq!(config.bind, SocketAddr::new(ip("0.0.0.0"), 19002));
    assert_eq!(config.local_ip, ip("192.0.2.1"));
    assert_eq!(config.priority, 17);
    assert_eq!(config.keep_alive_interval, Duration::from_millis(750));
    assert_eq!(config.members, vec!["backup.example"]);

    let mut invalid = node.clone();
    invalid.port = 0;
    assert!(BackupConfig::from_node_config(ip("0.0.0.0"), ip("192.0.2.1"), &invalid).is_err());
    invalid.port = 19002;
    invalid.keep_alive_interval = 0;
    assert!(BackupConfig::from_node_config(ip("0.0.0.0"), ip("192.0.2.1"), &invalid).is_err());
}
