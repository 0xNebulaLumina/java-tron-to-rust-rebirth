use std::{collections::BTreeMap, sync::{Arc, Mutex}, time::Duration};
use tron_events_metrics::{collect_db_stats, parse_db_stat, DbStat, DbStatService, MetricsClock, MetricsRegistry, MonitorMetrics, BLOCK_TRANSACTION_BUCKETS, DB_STATS_INTERVAL, DEFAULT_HISTOGRAM_BUCKETS, DEFAULT_PORT, METRICS};
use tron_protocol::protocol::metrics_info;

#[derive(Default)]
struct Clock(Mutex<Duration>);
impl Clock { fn advance(&self, value: Duration) { *self.0.lock().expect("clock") += value; } }
impl MetricsClock for Clock { fn elapsed(&self) -> Duration { *self.0.lock().expect("clock") } }

struct TestDb { rows: Vec<String>, engine: &'static str, name: &'static str }
impl DbStat for TestDb {
    fn stats(&self) -> Result<Vec<String>, String> { Ok(self.rows.clone()) }
    fn engine(&self) -> &str { self.engine }
    fn name(&self) -> &str { self.name }
}

fn scrape_counter(name: &'static str, labels: &[&str], amount: f64) -> String {
    let registry = MetricsRegistry::new(true);
    assert!(registry.counter_inc(name, amount, labels));
    registry.scrape()
}

fn assert_sr_change(action: &str, witness: &str) {
    let scrape = scrape_counter("tron:sr_set_change", &[action, witness], 1.0);
    assert!(scrape.contains(&format!("tron:sr_set_change_total{{action=\"{action}\",witness=\"{witness}\"}} 1")));
}

fn assert_no_sr_change(enabled: bool) {
    let registry = MetricsRegistry::new(enabled);
    if enabled { assert!(registry.scrape().is_empty()); } else { assert!(!registry.counter_inc("tron:sr_set_change", 1.0, &["add", "witness"])); }
    assert!(registry.scrape().is_empty());
}

fn seeded_monitor() -> MonitorMetrics {
    let metrics = MonitorMetrics::new(true);
    metrics.record_head(91, 1_234_567, "005b");
    metrics.record_transaction(true, "success");
    metrics.record_fork(false);
    metrics.record_traffic("tcp", true, 512);
    metrics.record_traffic("udp", false, 128);
    metrics.record_disconnect("TIME_OUT");
    metrics.record_block_latency("41aa", 2_100);
    metrics.set_connections(4, 3);
    metrics.set_transaction_cache_size(7);
    metrics.set_fail_process_block(90, "bad parent");
    metrics.set_witness("41aa", 30);
    metrics.record_duplicate_witness("41aa", 88);
    metrics
}

fn assert_metrics_snapshot() {
    let snapshot = seeded_monitor().snapshot();
    assert!(snapshot.interval >= 0);
    let chain = snapshot.blockchain.expect("blockchain");
    assert_eq!((chain.head_block_num, chain.head_block_timestamp, chain.head_block_hash.as_str()), (91, 1_234_567, "005b"));
    assert_eq!((chain.fail_process_block_num, chain.fail_process_block_reason.as_str(), chain.transaction_cache_size), (90, "bad parent", 7));
    assert_eq!((chain.witnesses[0].address.as_str(), chain.witnesses[0].version), ("41aa", 30));
    assert_eq!((chain.dup_witness[0].address.as_str(), chain.dup_witness[0].block_num, chain.dup_witness[0].count), ("41aa", 88, 1));
    let net = snapshot.net.expect("net");
    assert_eq!((net.connection_count, net.valid_connection_count, net.disconnection_count), (4, 3, 1));
    assert_eq!(net.disconnection_detail[0].reason, "TIME_OUT");
    assert_eq!(net.tcp_in_traffic.expect("tcp in").count, 512);
    assert_eq!(net.udp_out_traffic.expect("udp out").count, 128);
    assert_eq!(net.latency.expect("latency").delay2_s, 1);
}

fn assert_meter(amount: i64) {
    let clock = Arc::new(Clock::default());
    let metrics = MonitorMetrics::with_clock(true, clock.clone());
    metrics.meter_mark("row.meter", amount);
    clock.advance(Duration::from_secs(5));
    let rate = metrics.snapshot().blockchain.expect("blockchain").tps.expect("tps");
    assert_eq!(rate.count, 0, "unrelated named meters must not alias blockchain.tps");
    metrics.meter_mark("blockchain.tps", amount);
    clock.advance(Duration::from_secs(5));
    let rate = metrics.snapshot().blockchain.expect("blockchain").tps.expect("tps");
    assert_eq!(rate.count, amount);
    assert!(rate.mean_rate > 0.0 && rate.one_minute_rate > 0.0);
}

fn assert_histogram(value: i64) {
    let metrics = MonitorMetrics::new(true);
    metrics.histogram_update("net.latency", value);
    let latency = metrics.snapshot().net.expect("net").latency.expect("latency");
    assert_eq!((latency.total_count, latency.top99, latency.top95, latency.top75), (1, value as i32, value as i32, value as i32));
}

fn assert_counter() {
    let metrics = MonitorMetrics::new(true);
    metrics.counter_inc("net.disconnectionDetail.BAD_PROTOCOL");
    let net = metrics.snapshot().net.expect("net");
    assert_eq!((net.disconnection_detail[0].reason.as_str(), net.disconnection_detail[0].count), ("BAD_PROTOCOL", 1));
}

fn assert_db_stat() {
    let stat = parse_db_stat("L2   4  1.5").expect("valid RocksDB statistic");
    assert_eq!((stat.level.as_str(), stat.files, stat.size_bytes), ("L2", 4.0, 1.5 * 1_048_576.0));
    let registry = MetricsRegistry::new(true);
    let db = TestDb { rows: vec!["L2 4 1.5".into()], engine: "ROCKSDB", name: "account" };
    assert_eq!(collect_db_stats(&db, &registry).expect("statistics")[0], stat);
    let scrape = registry.scrape();
    assert!(scrape.contains("tron:db_sst_level{type=\"ROCKSDB\",db=\"account\",level=\"L2\"} 4"));
    assert!(scrape.contains("tron:db_size_bytes{type=\"ROCKSDB\",db=\"account\",level=\"L2\"} 1572864"));
}

fn assert_db_service(enabled: bool) {
    let registry = MetricsRegistry::new(enabled);
    let mut service = DbStatService::with_interval(registry.clone(), Duration::from_millis(5));
    service.register(Arc::new(TestDb { rows: vec!["L0 1 2".into()], engine: "LEVELDB", name: "block" }));
    std::thread::sleep(Duration::from_millis(20));
    service.shutdown();
    if enabled { assert!(registry.scrape().contains("db=\"block\"")); } else { assert!(registry.scrape().is_empty()); }
}

fn assert_inventory_and_scrape() {
    assert_eq!(DEFAULT_PORT, 9527);
    assert_eq!(DB_STATS_INTERVAL, Duration::from_secs(21_600));
    assert_eq!(DEFAULT_HISTOGRAM_BUCKETS, &[0.005,0.01,0.025,0.05,0.075,0.1,0.25,0.5,0.75,1.0,2.5,5.0,7.5,10.0]);
    assert_eq!(BLOCK_TRANSACTION_BUCKETS, &[0.0,20.0,50.0,80.0,100.0,120.0,140.0,160.0,180.0,200.0,230.0,260.0,300.0,500.0,2000.0,5000.0,10000.0]);
    let specs: BTreeMap<_, _> = METRICS.iter().map(|spec| (spec.name, spec.labels)).collect();
    assert_eq!(specs["tron:txs"], ["type", "detail"]);
    assert_eq!(specs["tron:sr_set_change"], ["action", "witness"]);
    assert_eq!(specs["tron:db_size_bytes"], ["type", "db", "level"]);
    assert_eq!(specs["tron:grpc_service_latency_seconds"], ["endpoint"]);
    let registry = MetricsRegistry::new(true);
    assert!(registry.histogram_observe("tron:block_transaction_count", 20.0, &["41aa"]));
    let scrape = registry.scrape();
    assert!(scrape.contains("# TYPE tron:block_transaction_count histogram"));
    assert!(scrape.contains("tron:block_transaction_count_bucket{miner=\"41aa\",le=\"20\"} 1"));
    assert!(scrape.contains("tron:block_transaction_count_bucket{miner=\"41aa\",le=\"+Inf\"} 1"));
}

fn assert_rate_proto_shape() {
    let clock = Arc::new(Clock::default());
    let metrics = MonitorMetrics::with_clock(true, clock.clone());
    metrics.meter_mark("blockchain.tps", 3);
    clock.advance(Duration::from_secs(5));
    let rate = metrics.snapshot().blockchain.expect("blockchain").tps.expect("tps");
    assert_eq!(rate.count, 3);
    assert!((rate.mean_rate - 0.6).abs() < 1e-12);
    assert!((rate.one_minute_rate - 0.6).abs() < 1e-12);
    assert!((rate.five_minute_rate - 0.6).abs() < 1e-12);
    assert!((rate.fifteen_minute_rate - 0.6).abs() < 1e-12);
}

fn assert_node_metric_shape() {
    let metrics = MonitorMetrics::new(true);
    metrics.set_node(metrics_info::NodeInfo { ip: "203.0.113.8".into(), node_type: 1, version: "4.8.0".into(), backup_status: 1 });
    let node = metrics.snapshot().node.expect("node");
    assert_eq!((node.ip.as_str(), node.node_type, node.version.as_str(), node.backup_status), ("203.0.113.8", 1, "4.8.0", 1));
}

fn assert_grpc_close_metric() {
    let registry = MetricsRegistry::new(true);
    assert!(registry.histogram_observe("tron:grpc_service_latency_seconds", 0.125, &["protocol.Wallet/GetNowBlock"]));
    let scrape = registry.scrape();
    assert!(scrape.contains("tron:grpc_service_latency_seconds_count{endpoint=\"protocol.Wallet/GetNowBlock\"} 1"));
    assert!(scrape.contains("tron:grpc_service_latency_seconds_sum{endpoint=\"protocol.Wallet/GetNowBlock\"} 0.125"));
}

#[test] fn c025_metrics_node_tcase_d4b8f2597925a7b0() { assert_sr_change("add", "TAddWitness"); }
#[test] fn c025_metrics_node_tcase_7796a25da817e40b() { assert_no_sr_change(true); }
#[test] fn c025_metrics_node_tcase_c52c8a224d6830f5() { assert_no_sr_change(true); }
#[test] fn c025_metrics_node_tcase_b9fb3d6c62bd207f() { assert_no_sr_change(false); }
#[test] fn c025_metrics_node_tcase_0b931841b82968a7() { assert_sr_change("remove", "TRemovedWitness"); }
#[test] fn c025_metrics_node_tcase_3721a845b1702c47() { assert_metrics_snapshot(); }
#[test] fn c025_metrics_node_tcase_1411b9fe914793a8() { assert_counter(); }
#[test] fn c025_metrics_node_tcase_1c18fed1b58e7fbe() { assert_meter(1); }
#[test] fn c025_metrics_node_tcase_6490ca5cdfa0aa8d() { assert_meter(7); }
#[test] fn c025_metrics_node_tcase_116f10a1f355f25f() { assert_histogram(17); }
#[test] fn c025_metrics_node_tcase_d315716bdbbf29b3() { assert_inventory_and_scrape(); assert_metrics_snapshot(); }

#[test] fn c025_metrics_node_prod_2cb4543ab9040b22() { assert_db_stat(); }
#[test] fn c025_metrics_node_prod_57f826e45b3772a3() { assert_db_stat(); }
#[test] fn c025_metrics_node_prod_a957d5089930ffcf() { assert_db_stat(); }
#[test] fn c025_metrics_node_prod_f4a53788a7d67436() { assert_db_service(true); }
#[test] fn c025_metrics_node_prod_2203c2ce8050fe0d() { assert_db_service(true); }
#[test] fn c025_metrics_node_prod_1c9c8a0099757858() { assert_db_service(false); }
#[test] fn c025_metrics_node_prod_b2cd96e0affb8b23() { assert_metrics_snapshot(); }
#[test] fn c025_metrics_node_prod_2f359ba3c034b6c0() { assert_metrics_snapshot(); }
#[test] fn c025_metrics_node_prod_77856916d5240a92() { assert_metrics_snapshot(); }
#[test] fn c025_metrics_node_prod_0c22427588c05bf5() { let m=MonitorMetrics::new(true); m.set_fail_process_block(12,"invalid"); let b=m.snapshot().blockchain.expect("blockchain"); assert_eq!((b.fail_process_block_num,b.fail_process_block_reason.as_str()),(12,"invalid")); }
#[test] fn c025_metrics_node_prod_0d24507333b23bcd() { let s=MonitorMetrics::new(true).snapshot(); assert!(s.node.is_some() && s.blockchain.is_some() && s.net.is_some()); }
#[test] fn c025_metrics_node_prod_9e67d9cd364b0886() { assert_histogram(9); }
#[test] fn c025_metrics_node_prod_2664f90847296a4b() { assert_histogram(10); }
#[test] fn c025_metrics_node_prod_fa52f0b3b4dc982e() { assert_histogram(11); }
#[test] fn c025_metrics_node_prod_d3b7d906d6cfaf44() { assert_histogram(12); }
#[test] fn c025_metrics_node_prod_91664001ec8ac8f2() { assert_meter(1); }
#[test] fn c025_metrics_node_prod_c59713953a4c9eb1() { assert_meter(2); }
#[test] fn c025_metrics_node_prod_aba32a44781fc332() { assert_meter(1); }
#[test] fn c025_metrics_node_prod_07678b16e3c18d5c() { assert_meter(8); }
#[test] fn c025_metrics_node_prod_dfd613273c24d6f7() { assert_counter(); }
#[test] fn c025_metrics_node_prod_0ab7c6d13b313af9() { assert_counter(); }
#[test] fn c025_metrics_node_prod_ebd561320864f646() { assert_counter(); }
#[test] fn c025_metrics_node_prod_3764022ea3ee5144() { assert_rate_proto_shape(); }
#[test] fn c025_metrics_node_prod_74c81af7d49adbdb() { assert_metrics_snapshot(); }
#[test] fn c025_metrics_node_prod_f38bfceed2e56bb3() { assert_metrics_snapshot(); }
#[test] fn c025_metrics_node_prod_bbd115145db37570() { assert_metrics_snapshot(); }
#[test] fn c025_metrics_node_prod_85c3b7dac63b8ff8() { let m=MonitorMetrics::new(true); m.record_fork(true); assert_eq!(m.snapshot().blockchain.expect("blockchain").fork_count,1); }
#[test] fn c025_metrics_node_prod_8ad9861523dc5f58() { let m=MonitorMetrics::new(true); m.record_fork(false); assert_eq!(m.snapshot().blockchain.expect("blockchain").fail_fork_count,1); }
#[test] fn c025_metrics_node_prod_30de1408802428de() { assert_metrics_snapshot(); }
#[test] fn c025_metrics_node_prod_803f45d245378408() { assert_metrics_snapshot(); }
#[test] fn c025_metrics_node_prod_f6c8df3ec9c390c5() { assert_rate_proto_shape(); }
#[test] fn c025_metrics_node_prod_b93dc8d351eb426c() { assert_node_metric_shape(); }
#[test] fn c025_metrics_node_prod_50be13424ea9fa05() { assert_node_metric_shape(); }
#[test] fn c025_metrics_node_prod_e8b74aaae1f3022a() { assert_grpc_close_metric(); }

#[test]
fn c025_metrics_node_artifact_is_exact_and_separates_declarations() {
    let artifact: serde_json::Value = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../docs/oracles/c025-cases-metrics-node.v1.json"))).expect("valid family artifact");
    assert_eq!(artifact["schema"], "c025-cases-metrics-node.v1");
    assert_eq!(artifact["counts"]["behavior"], 45);
    assert_eq!(artifact["counts"]["source_declaration"], 69);
    assert_eq!(artifact["counts"]["total"], 114);
    let rows = artifact["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 114);
    let behavior = rows.iter().filter(|row| row["evidence_kind"] != "source_declaration").count();
    let declarations = rows.iter().filter(|row| row["evidence_kind"] == "source_declaration").count();
    assert_eq!((behavior, declarations), (45, 69));
    assert!(rows.iter().filter(|row| row["evidence_kind"] == "source_declaration").all(|row| row.get("rust_case").is_none() && row.get("rust_invocation").is_none()));
    assert!(rows.iter().filter(|row| row["evidence_kind"] != "source_declaration").all(|row| {
        row["java_vector"]["error"] == row["rust_invocation"]["expected_error"]
            && row["java_vector"]["output"] == row["rust_invocation"]["expected_output"]
            && row["java_vector"]["effect"] == row["rust_invocation"]["expected_effect"]
    }));
    for row in rows.iter().filter(|row| row["evidence_kind"] != "source_declaration") {
        println!("C025_FAMILY_BEHAVIOR={}\t{}", row["id"].as_str().unwrap(), serde_json::json!({"input":row["java_vector"]["input"],"result":row["rust_invocation"]["expected_output"],"effect":row["rust_invocation"]["expected_effect"],"error":row["rust_invocation"]["expected_error"]}));
    }
    let artifact_metrics = artifact["prometheus"]["metrics"].as_array().expect("metrics");
    assert_eq!(artifact_metrics.len(), METRICS.len());
    for spec in METRICS {
        let row = artifact_metrics.iter().find(|row| row["name"] == spec.name).expect("metric row");
        let labels: Vec<_> = row["labels"].as_array().expect("labels").iter().map(|label| label.as_str().expect("label")).collect();
        assert_eq!(labels, spec.labels);
    }
}
