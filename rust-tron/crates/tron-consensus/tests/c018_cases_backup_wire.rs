use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use tron_consensus::backup::{
    decode_keep_alive, encode_keep_alive, AuthenticatedDatagram, BackupClock, BackupConfig,
    BackupManager, BackupService, BackupStatus, DatagramSocket, DnsResolver, ReceivedDatagram,
    SocketFactory, BACKUP_KEEP_ALIVE,
};
use tron_protocol::protocol::BackupMessage;

#[derive(Deserialize)]
struct Manifest {
    schema: String,
    count: usize,
    family_counts: BTreeMap<String, usize>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    stable_id: String,
    case_id: String,
    java_source: String,
    java_source_sha256: String,
    java_symbol: String,
    java_expected_result: String,
    java_expected_digest: String,
    evidence_kind: String,
    operation: Value,
}

fn manifest() -> Manifest {
    serde_json::from_str(include_str!(
        "../../../../docs/oracles/c018-cases-backup-wire.v1.json"
    ))
    .unwrap()
}

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

fn hex_bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn string<'a>(operation: &'a Value, key: &str) -> &'a str {
    operation[key].as_str().unwrap()
}

fn number(operation: &Value, key: &str) -> u64 {
    operation[key].as_u64().unwrap()
}

fn strings(operation: &Value, key: &str) -> Vec<String> {
    operation[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect()
}

#[derive(Default)]
struct Clock(AtomicU64);

impl BackupClock for Clock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::Acquire))
    }

    fn sleep(&self, duration: Duration) {
        self.0
            .fetch_add(duration.as_millis() as u64, Ordering::AcqRel);
    }
}

struct ScriptedDns {
    answers: Mutex<VecDeque<io::Result<Vec<IpAddr>>>>,
    last: Mutex<Option<Vec<IpAddr>>>,
}

impl ScriptedDns {
    fn new(answers: Vec<io::Result<Vec<IpAddr>>>) -> Self {
        Self {
            answers: Mutex::new(answers.into()),
            last: Mutex::new(None),
        }
    }
}

impl DnsResolver for ScriptedDns {
    fn resolve(&self, member: &str) -> io::Result<Vec<IpAddr>> {
        if let Ok(address) = member.parse() {
            return Ok(vec![address]);
        }
        assert_eq!(member, "backup.example");
        if let Some(answer) = self.answers.lock().unwrap().pop_front() {
            if let Ok(addresses) = &answer {
                *self.last.lock().unwrap() = Some(addresses.clone());
            }
            return answer;
        }
        Ok(self.last.lock().unwrap().clone().unwrap_or_default())
    }
}

#[derive(Default)]
struct Socket {
    sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    incoming: Mutex<VecDeque<ReceivedDatagram>>,
}

impl DatagramSocket for Socket {
    fn send_to(&self, bytes: &[u8], address: SocketAddr) -> io::Result<usize> {
        self.sent.lock().unwrap().push((bytes.to_vec(), address));
        Ok(bytes.len())
    }

    fn recv_datagram(&self) -> io::Result<ReceivedDatagram> {
        self.incoming.lock().unwrap().pop_front().ok_or_else(|| io::ErrorKind::WouldBlock.into())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, 19001)))
    }
}

struct Factory(Arc<Socket>);

impl SocketFactory for Factory {
    fn bind(&self, _address: SocketAddr) -> io::Result<Arc<dyn DatagramSocket>> {
        Ok(self.0.clone())
    }
    fn supplies_authenticated_datagrams(&self) -> bool { true }
}


fn config(member: String) -> BackupConfig {
    let mut config = BackupConfig::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 19001)),
        ip("192.0.2.1"),
        vec![member],
        6,
    );
    config.keep_alive_interval = Duration::from_millis(100);
    config.dns_refresh_interval = Duration::from_millis(1_050);
    config
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    for _ in 0..1_000 {
        if condition() {
            return;
        }
        thread::sleep(Duration::from_micros(50));
    }
    panic!("deterministic backup worker did not reach the expected observation");
}

fn run_service(
    config: BackupConfig,
    dns: Arc<dyn DnsResolver>,
    socket: Arc<Socket>,
) -> BackupService {
    let mut service = BackupService::new(
        config,
        Arc::new(Clock::default()),
        dns,
        Arc::new(Factory(socket)),
    );
    assert!(service.start().unwrap());
    service
}

fn assert_case(case: &Case) {
    if case.evidence_kind == "source_assertion" {
        assert_eq!(case.java_source_sha256.len(), 64);
        assert!(case.java_expected_result.starts_with("source:"));
        return;
    }
    let operation = &case.operation;
    match string(operation, "kind") {
        "wire" => {
            let message = BackupMessage {
                flag: operation["flag"].as_bool().unwrap(),
                priority: number(operation, "priority") as i32,
            };
            let expected = hex_bytes(string(operation, "hex"));
            assert_eq!(encode_keep_alive(&message).unwrap(), expected, "{}", case.stable_id);
            assert_eq!(decode_keep_alive(&expected).unwrap(), message, "{}", case.stable_id);
        }
        "decode_reject" => {
            let error = decode_keep_alive(&hex_bytes(string(operation, "hex"))).unwrap_err();
            assert_eq!(error.to_string(), string(operation, "error"), "{}", case.stable_id);
        }
        "udp_type" => {
            let input = number(operation, "input") as u8;
            if operation["expected"].is_null() {
                assert!(decode_keep_alive(&[input]).is_err(), "{}", case.stable_id);
            } else {
                assert_eq!(input, BACKUP_KEEP_ALIVE, "{}", case.stable_id);
                assert_eq!(decode_keep_alive(&[input]).unwrap(), BackupMessage::default());
            }
        }
        "timestamp" => {
            let received = number(operation, "received_ms");
            let timeout = number(operation, "timeout_ms");
            let mut manager = BackupManager::new(
                ip("10.0.0.1"),
                6,
                Duration::from_millis(timeout / 6),
                Duration::ZERO,
            );
            manager.on_keep_alive(
                ip("10.0.0.2"),
                &BackupMessage { flag: true, priority: 6 },
                Duration::from_millis(received),
            );
            manager.tick(Duration::from_millis(received + timeout));
            assert_eq!(format!("{:?}", manager.status()), string(operation, "at_timeout_status"));
            manager.tick(Duration::from_millis(received + timeout + 1));
            assert_eq!(format!("{:?}", manager.status()), string(operation, "after_timeout_status"));
        }
        "sender" => {
            let priority = number(operation, "priority") as i32;
            let mut manager = BackupManager::new(
                ip(string(operation, "local")),
                priority,
                Duration::from_secs(1),
                Duration::ZERO,
            );
            manager.on_keep_alive(
                ip(string(operation, "sender")),
                &BackupMessage { flag: true, priority },
                Duration::ZERO,
            );
            assert_eq!(format!("{:?}", manager.status()), string(operation, "expected_status"));
        }
        "equality" => {
            let message = |side: &Value| BackupMessage {
                flag: side["flag"].as_bool().unwrap(),
                priority: side["priority"].as_i64().unwrap() as i32,
            };
            assert_eq!(
                message(&operation["left"]) == message(&operation["right"]),
                operation["equal"].as_bool().unwrap(),
                "{}",
                case.stable_id
            );
        }
        "debug" => {
            let text = format!(
                "{:?}",
                BackupMessage {
                    flag: operation["flag"].as_bool().unwrap(),
                    priority: number(operation, "priority") as i32,
                }
            );
            for expected in strings(operation, "contains") {
                assert!(text.contains(&expected), "{}: {text}", case.stable_id);
            }
        }
        "lifecycle" => {
            let port = number(operation, "port") as u16;
            let socket = Arc::new(Socket::default());
            let mut service = BackupService::new(
                BackupConfig::new(
                    SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                    ip("192.0.2.1"),
                    strings(operation, "members"),
                    6,
                ),
                Arc::new(Clock::default()),
                Arc::new(ScriptedDns::new(vec![])),
                Arc::new(Factory(socket)),
            );
            assert_eq!(service.start().unwrap(), operation["start"].as_bool().unwrap());
            assert_eq!(service.start().unwrap(), operation["duplicate"].as_bool().unwrap());
            service.close();
            assert_eq!(service.start().unwrap(), operation["restart"].as_bool().unwrap());
            service.close();
        }
        "lifecycle_disabled" => {
            let socket = Arc::new(Socket::default());
            let mut service = BackupService::new(
                BackupConfig::new(
                    SocketAddr::from((Ipv4Addr::LOCALHOST, number(operation, "port") as u16)),
                    ip("192.0.2.1"),
                    strings(operation, "members"),
                    6,
                ),
                Arc::new(Clock::default()),
                Arc::new(ScriptedDns::new(vec![])),
                Arc::new(Factory(socket)),
            );
            assert_eq!(service.start().unwrap(), operation["started"].as_bool().unwrap());
        }
        "dns_first" => {
            let answers: Vec<_> = strings(operation, "answers").into_iter().map(|x| ip(&x)).collect();
            let socket = Arc::new(Socket::default());
            let mut service = run_service(
                config("backup.example".into()),
                Arc::new(ScriptedDns::new(vec![Ok(answers)])),
                socket.clone(),
            );
            wait_until(|| !socket.sent.lock().unwrap().is_empty());
            service.close();
            let destinations: BTreeSet<_> = socket.sent.lock().unwrap().iter().map(|x| x.1.ip()).collect();
            assert!(destinations.contains(&ip(string(operation, "expected"))), "{}", case.stable_id);
            assert!(!destinations.contains(&ip(string(operation, "ignored"))), "{}", case.stable_id);
        }
        "dns_refresh" => {
            let addresses = |key| strings(operation, key).into_iter().map(|x| ip(&x)).collect();
            let socket = Arc::new(Socket::default());
            let mut service = run_service(
                config("backup.example".into()),
                Arc::new(ScriptedDns::new(vec![Ok(addresses("initial")), Ok(addresses("refresh"))])),
                socket.clone(),
            );
            wait_until(|| {
                let sent = socket.sent.lock().unwrap();
                sent.iter().any(|x| x.1.ip() == ip(string(operation, "expected_first")))
                    && sent.iter().any(|x| x.1.ip() == ip(string(operation, "expected_refreshed")))
            });
            service.close();
            let sent = socket.sent.lock().unwrap();
            if string(operation, "expected_first") == string(operation, "expected_refreshed") {
                assert!(!sent.iter().any(|x| x.1.ip() == ip(string(operation, "ignored_initial"))));
            } else {
                let cutover = sent.iter().position(|x| x.1.ip() == ip(string(operation, "expected_refreshed"))).unwrap();
                assert!(sent[..cutover].iter().all(|x| x.1.ip() != ip(string(operation, "ignored_initial"))));
                assert!(sent[cutover..].iter().all(|x| x.1.ip() != ip(string(operation, "ignored_refreshed"))));
            }
        }
        "dns_failure" => {
            let initial = ip(string(operation, "initial"));
            let socket = Arc::new(Socket::default());
            let mut service = run_service(
                config("backup.example".into()),
                Arc::new(ScriptedDns::new(vec![Ok(vec![initial]), Err(io::ErrorKind::NotFound.into())])),
                socket.clone(),
            );
            wait_until(|| socket.sent.lock().unwrap().len() >= 2);
            service.close();
            assert!(socket.sent.lock().unwrap().iter().all(|x| x.1.ip() == ip(string(operation, "expected_after_failure"))));
        }
        "dns_local_skip" => {
            let local = ip(string(operation, "local"));
            let socket = Arc::new(Socket::default());
            let mut cfg = config("backup.example".into());
            cfg.local_ip = local;
            let mut service = run_service(
                cfg,
                Arc::new(ScriptedDns::new(vec![Ok(vec![ip(string(operation, "resolved"))])])),
                socket.clone(),
            );
            wait_until(|| service.status() == BackupStatus::MASTER);
            service.close();
            assert_eq!(socket.sent.lock().unwrap().len(), number(operation, "sent_count") as usize);
        }
        "allowlist" => {
            let member = ip(string(operation, "member"));
            let spoof = ip(string(operation, "spoof"));
            let authenticated = operation["authenticated"].as_bool().unwrap();
            let source = SocketAddr::new(if authenticated { member } else { spoof }, 19001);
            let socket = Arc::new(Socket::default());
            let payload = encode_keep_alive(&BackupMessage { flag: true, priority: 6 }).unwrap();
            socket.incoming.lock().unwrap().push_back(if authenticated {
                ReceivedDatagram::Authenticated(AuthenticatedDatagram { payload, source, peer_identity: member, session: 1, sequence: 1 })
            } else {
                ReceivedDatagram::Unauthenticated { payload, source }
            });
            let mut allowlist_config = config(member.to_string());
            allowlist_config.keep_alive_interval = Duration::from_secs(3_600);
            let mut service = run_service(
                allowlist_config,
                Arc::new(ScriptedDns::new(vec![])),
                socket,
            );
            wait_until(|| service.status() != BackupStatus::INIT || !authenticated);
            service.close();
            assert_eq!(format!("{:?}", service.status()), string(operation, "expected_status"));
        }
        kind => panic!("{} has unknown operation {kind}", case.stable_id),
    }
}

#[test]
fn c018_backup_wire_rows_have_row_specific_executable_evidence() {
    let manifest = manifest();
    assert_eq!(manifest.schema, "c018-cases-backup-wire.v1");
    assert_eq!(manifest.count, 60);
    assert_eq!(manifest.family_counts.get("backup-wire"), Some(&31));
    assert_eq!(manifest.family_counts.get("backup-dns"), Some(&23));
    assert_eq!(manifest.family_counts.get("backup-lifecycle"), Some(&6));
    assert_eq!(manifest.cases.len(), manifest.count);

    let mut stable_ids = BTreeSet::new();
    let mut case_ids = BTreeSet::new();
    for case in &manifest.cases {
        assert!(stable_ids.insert(&case.stable_id));
        assert!(case_ids.insert(&case.case_id));
        assert!(case.stable_id.starts_with("PROD-") || case.stable_id.starts_with("TCASE-"));
        assert!(case.java_source.starts_with("java-tron/"));
        assert_eq!(case.java_source_sha256.len(), 64);
        assert!(!case.java_symbol.is_empty());
        assert!(!case.java_expected_result.is_empty());
        assert_eq!(case.java_expected_digest.len(), 64);
        assert_case(case);
        println!("{}={}", case.case_id, case.java_expected_result);
    }
    println!("executed_ids={}", case_ids.into_iter().map(String::as_str).collect::<Vec<_>>().join(","));
}
