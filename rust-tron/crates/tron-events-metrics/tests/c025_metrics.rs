use std::{sync::{Arc, Mutex}, time::Duration};
use tron_events_metrics::{BLOCK_TRANSACTION_BUCKETS, DbStat, MetricsClock, MetricsRegistry, MonitorMetrics, collect_db_stats};

#[test]
fn prometheus_names_labels_histograms_and_disabled_mode_match_java() {
    let metrics=MetricsRegistry::with_cardinality_limit(true,2);
    assert!(metrics.counter_inc("tron:txs",2.0,&["success","all"]));
    assert!(metrics.gauge_set("tron:peers",3.0,&["all"]));
    assert!(metrics.histogram_observe("tron:block_transaction_count",20.0,&["miner"]));
    let scrape=metrics.scrape();
    assert!(scrape.contains("# TYPE tron:txs counter"));
    assert!(scrape.contains("tron:txs_total{type=\"success\",detail=\"all\"} 2"));
    assert!(scrape.contains("tron:peers{type=\"all\"} 3"));
    assert!(scrape.contains("tron:block_transaction_count_bucket{miner=\"miner\",le=\"20\"} 1"));
    assert_eq!(BLOCK_TRANSACTION_BUCKETS.len(),17);
    metrics.set_enabled(false);
    assert!(!metrics.counter_inc("tron:txs",1.0,&["success","all"]));
    assert!(metrics.scrape().is_empty());
}

#[test]
fn state_network_and_disconnect_instrumentation_populates_monitor() {
    let metrics=MonitorMetrics::new(true);
    metrics.record_head(9,1234,"0009");
    metrics.record_transaction(true,"all");
    metrics.record_fork(false);
    metrics.record_traffic("tcp",true,512);
    metrics.record_disconnect("TIME_OUT");
    metrics.record_block_latency("41aa",2100);
    metrics.set_connections(3,2);
    metrics.set_transaction_cache_size(4);
    let snapshot=metrics.snapshot();
    let chain=snapshot.blockchain.unwrap();
    assert_eq!((chain.head_block_num,chain.head_block_timestamp,chain.head_block_hash.as_str()),(9,1234,"0009"));
    assert_eq!(chain.tps.unwrap().count,1);
    assert_eq!(chain.fail_fork_count,1);
    assert_eq!(chain.transaction_cache_size,4);
    let net=snapshot.net.unwrap();
    assert_eq!((net.connection_count,net.valid_connection_count),(3,2));
    assert_eq!(net.tcp_in_traffic.unwrap().count,512);
    assert_eq!(net.disconnection_detail[0].reason,"TIME_OUT");
    assert_eq!(net.latency.unwrap().delay2_s,1);
}

struct TestDb;
impl DbStat for TestDb { fn stats(&self)->Result<Vec<String>,String>{Ok(vec!["L0 3 1.5".into()])} fn engine(&self)->&str{"ROCKSDB"} fn name(&self)->&str{"account"} }
#[test]
fn db_stats_use_six_hour_format_and_mib_conversion(){let metrics=MetricsRegistry::new(true);let rows=collect_db_stats(&TestDb,&metrics).unwrap();assert_eq!(rows[0].size_bytes,1.5*1_048_576.0);let text=metrics.scrape();assert!(text.contains("type=\"ROCKSDB\",db=\"account\",level=\"L0\""));}

#[derive(Default)]
struct Clock(Mutex<Duration>);
impl Clock { fn advance(&self, duration:Duration) { let mut now=self.0.lock().unwrap(); *now=now.saturating_add(duration); } }
impl MetricsClock for Clock { fn elapsed(&self)->Duration { *self.0.lock().unwrap() } }

fn close(actual:f64, expected:f64) { assert!((actual-expected).abs()<1.0e-12,"{actual} != {expected}"); }

#[test]
fn dropwizard_meter_matches_java_burst_and_idle_ticks() {
    let clock=Arc::new(Clock::default());
    let metrics=MonitorMetrics::with_clock(true,clock.clone());
    metrics.meter_mark("blockchain.tps",3);
    assert_eq!(metrics.snapshot().blockchain.unwrap().tps.unwrap().one_minute_rate,0.0,"uncounted marks do not enter EWMA until the 5s tick");
    clock.advance(Duration::from_secs(5));
    let burst=metrics.snapshot().blockchain.unwrap().tps.unwrap();
    close(burst.mean_rate,0.6); close(burst.one_minute_rate,0.6); close(burst.five_minute_rate,0.6); close(burst.fifteen_minute_rate,0.6);
    clock.advance(Duration::from_secs(5));
    let idle=metrics.snapshot().blockchain.unwrap().tps.unwrap();
    close(idle.one_minute_rate,0.6*(-5.0_f64/60.0).exp());
    close(idle.five_minute_rate,0.6*(-5.0_f64/300.0).exp());
    close(idle.fifteen_minute_rate,0.6*(-5.0_f64/900.0).exp());
    clock.advance(Duration::from_secs(50));
    let long_idle=metrics.snapshot().blockchain.unwrap().tps.unwrap();
    close(long_idle.one_minute_rate,0.6*(-55.0_f64/60.0).exp());
    close(long_idle.five_minute_rate,0.6*(-55.0_f64/300.0).exp());
    close(long_idle.fifteen_minute_rate,0.6*(-55.0_f64/900.0).exp());
    assert_eq!(long_idle.count,3);
}
