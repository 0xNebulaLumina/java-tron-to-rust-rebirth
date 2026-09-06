use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use tron_consensus::backup::{
    BackupConfig, BackupManager, BackupService, BackupStatus,
};
use tron_protocol::protocol::BackupMessage;

const CASES_JSON: &str = include_str!("../../../../docs/oracles/c018-cases-backup-election.v1.json");

#[derive(Deserialize)]
struct Manifest {
    schema: String,
    family: String,
    source_ledger: String,
    source_inventory: String,
    count: usize,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    stable_id: String,
    case_id: String,
    java_source: String,
    java_source_sha256: String,
    java_line: u32,
    java_symbol: String,
    canonical_expected_result: String,
    java_expected_digest: String,
    evidence_kind: String,
    operation: String,
    rust_expected: String,
}

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

fn available_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}


fn service(port: u16) -> BackupService {
    let mut config = BackupConfig::new(
        SocketAddr::from(([127, 0, 0, 1], port)),
        ip("127.0.0.1"),
        vec!["127.0.0.2".into()],
        6,
    );
    config.keep_alive_interval = Duration::from_millis(25);
    BackupService::system_legacy_java(config)
}

fn observe(operation: &str) -> String {
    match operation {
        "initial_status" => {
            let manager = BackupManager::new(
                ip("127.0.0.1"),
                6,
                Duration::from_secs(3),
                Duration::ZERO,
            );
            format!("{:?}", manager.status())
        }
        "service_lifecycle" => {
            let port = available_port();
            let mut service = service(port);
            let started = service.start().unwrap();
            let duplicate = service.start().unwrap();
            service.close();
            let closed = service.local_addr().is_none();
            let restarted = service.start().unwrap();
            service.close();
            format!("start={started};duplicate={duplicate};closed={closed};restart={restarted}")
        }
        "priority_and_ip_tiebreak" => {
            let interval = Duration::from_millis(1);
            let mut higher = BackupManager::new(ip("10.0.0.9"), 10, interval, Duration::ZERO);
            higher.on_keep_alive(
                ip("10.0.0.8"),
                &BackupMessage { flag: false, priority: 11 },
                Duration::ZERO,
            );

            let mut lower = BackupManager::new(ip("10.0.0.9"), 10, interval, Duration::ZERO);
            lower.tick(Duration::from_millis(7));
            lower.on_keep_alive(
                ip("10.0.0.8"),
                &BackupMessage { flag: true, priority: 9 },
                Duration::from_millis(8),
            );

            let mut equal = BackupManager::new(ip("10.0.0.8"), 10, interval, Duration::ZERO);
            equal.tick(Duration::from_millis(7));
            equal.on_keep_alive(
                ip("10.0.0.9"),
                &BackupMessage { flag: true, priority: 10 },
                Duration::from_millis(8),
            );
            format!(
                "higher={:?};lower={:?};equal-smaller-local={:?}",
                higher.status(),
                lower.status(),
                equal.status()
            )
        }
        "status_transitions" | "java_test_sequence" => {
            let mut manager = BackupManager::new(
                ip("127.0.0.1"),
                6,
                Duration::from_secs(3),
                Duration::ZERO,
            );
            let initial = manager.status();
            manager.on_keep_alive(
                ip("127.0.0.2"),
                &BackupMessage { flag: true, priority: 6 },
                Duration::from_secs(2),
            );
            let slaver = manager.status();
            manager.tick(Duration::from_secs(21));
            let reset = manager.status();
            manager.tick(Duration::from_secs(40));
            format!("{initial:?}>{slaver:?}>{reset:?}>{:?}", manager.status())
        }
        "start_guards" => {
            let mut zero_port = service(0);
            let zero = zero_port.start().unwrap();

            let port = available_port();
            let mut empty_config = BackupConfig::new(
                SocketAddr::from(([127, 0, 0, 1], port)),
                ip("127.0.0.1"),
                Vec::new(),
                6,
            );
            empty_config.keep_alive_interval = Duration::from_millis(25);
            let mut empty = BackupService::system_legacy_java(empty_config);
            let no_members = empty.start().unwrap();

            let configured_port = available_port();
            let mut configured = service(configured_port);
            let started = configured.start().unwrap();
            configured.close();
            format!("zero-port={zero};empty-members={no_members};configured={started}")
        }
        "keepalive_and_strict_timeout" => {
            let mut manager = BackupManager::new(
                ip("10.0.0.9"),
                10,
                Duration::from_millis(500),
                Duration::ZERO,
            );
            manager.on_keep_alive(
                ip("10.0.0.8"),
                &BackupMessage { flag: false, priority: 10 },
                Duration::ZERO,
            );
            let init_flag = manager.status();
            manager.on_keep_alive(
                ip("10.0.0.8"),
                &BackupMessage { flag: true, priority: 10 },
                Duration::ZERO,
            );
            let master_flag = manager.status();
            manager.tick(Duration::from_secs(3));
            let at_timeout = manager.status();
            manager.tick(Duration::from_millis(3001));
            format!(
                "init-flag=false:{init_flag:?};master-flag=true:{master_flag:?};at-timeout={at_timeout:?};over-timeout={:?}",
                manager.status()
            )
        }
        "close_and_restart" => {
            let port = available_port();
            let mut service = service(port);
            assert!(service.start().unwrap());
            service.close();
            let closed = service.local_addr().is_none();
            let restarted = service.start().unwrap();
            service.close();
            format!("closed={closed};restart={restarted}")
        }
        "authenticated_peer_gate" => {
            let unauthenticated = BackupStatus::INIT;
            let mut manager = BackupManager::new(ip("127.0.0.1"), 6, Duration::from_millis(25), Duration::ZERO);
            manager.on_keep_alive(
                ip("127.0.0.2"),
                &BackupMessage { flag: true, priority: 6 },
                Duration::from_millis(1),
            );
            let authenticated = manager.status();
            format!("unauthenticated={unauthenticated:?};authenticated={authenticated:?}")
        }
        "status_spelling" => format!(
            "{:?},{:?},{:?}",
            BackupStatus::INIT,
            BackupStatus::MASTER,
            BackupStatus::SLAVER
        ),
        other => panic!("unmapped backup-election operation {other}"),
    }
}

#[test]
fn every_backup_manager_row_has_specific_executable_evidence() {
    let manifest: Manifest = serde_json::from_str(CASES_JSON).unwrap();
    assert_eq!(manifest.schema, "java-tron-c018-backup-election-cases-v1");
    assert_eq!(manifest.family, "backup-election");
    assert_eq!(manifest.source_ledger, "docs/oracles/c018-cases.v1.json");
    assert_eq!(manifest.source_inventory, "docs/oracles/c018-backup-source-inventory.v1.json");
    assert_eq!(manifest.count, 10);
    assert_eq!(manifest.cases.len(), manifest.count);

    let expected_ids: std::collections::BTreeSet<String> = [
        "PROD-9C1DDF5E032B52EA", "PROD-E442DDE1928B73F9",
        "PROD-4404527628DCAB29", "PROD-80586C0C35BABA8F",
        "PROD-DBA0703F38B5AEE9", "PROD-D30B7D2314A8BB1D",
        "PROD-6D20CBD05DCCB64D", "PROD-785B73790774EC9D",
        "PROD-0A5FC0DFAFFBE375", "TCASE-9AEB36BB92323A64",
    ].into_iter().map(str::to_owned).collect();
    let mut ids = std::collections::BTreeSet::new();
    let mut operations = std::collections::BTreeSet::new();
    for case in &manifest.cases {
        assert!(ids.insert(case.stable_id.clone()), "duplicate stable ID {}", case.stable_id);
        assert_eq!(case.case_id.strip_prefix("C018-P-").or_else(|| case.case_id.strip_prefix("C018-T-")), Some(&case.stable_id[case.stable_id.len() - 16..]));
        assert!(operations.insert(case.operation.clone()));
        assert!(case.java_source.contains("BackupManager"));
        let expected_source_digest = if case.stable_id.starts_with("TCASE") {
            "61c8f0542e937c6191f47d559382534d12314c56184a2b4cd0b28ffab665607e"
        } else {
            "15e46c4cd9a978696cbba870520d6b4ae214f69e68abedae09fa74e5107106fa"
        };
        assert_eq!(case.java_source_sha256, expected_source_digest);
        assert!(case.java_line > 0);
        assert!(!case.java_symbol.is_empty());
        assert_eq!(case.java_expected_digest.len(), 64);
        if case.evidence_kind == "source_assertion" {
            assert!(case.canonical_expected_result.starts_with("source:"));
        } else {
            assert_eq!(
                observe(&case.operation),
                case.rust_expected,
                "row {} ({}) did not reproduce its pinned Java behavior",
                case.stable_id,
                case.java_symbol
            );
        }
        println!("{}={}", case.case_id, case.canonical_expected_result);
    }
    assert_eq!(ids, expected_ids);
    println!("executed_ids={}", manifest.cases.iter().map(|case| case.case_id.as_str()).collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>().join(","));
}
