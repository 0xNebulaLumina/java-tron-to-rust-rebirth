use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const DEFAULT_PORT: u16 = 9527;
pub const DEFAULT_HISTOGRAM_BUCKETS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0];
pub const BLOCK_TRANSACTION_BUCKETS: &[f64] = &[0.0, 20.0, 50.0, 80.0, 100.0, 120.0, 140.0, 160.0, 180.0, 200.0, 230.0, 260.0, 300.0, 500.0, 2000.0, 5000.0, 10000.0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricType { Counter, Gauge, Histogram }

#[derive(Clone, Copy, Debug)]
pub struct MetricSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub kind: MetricType,
    pub labels: &'static [&'static str],
    pub buckets: &'static [f64],
}

#[derive(Debug)]
struct HistogramValue { count: u64, sum: f64, buckets: Vec<u64> }
#[derive(Debug)]
enum Value { Number(AtomicU64), Histogram(Mutex<HistogramValue>) }
#[derive(Debug)]
struct Series { labels: Vec<String>, value: Value }

#[derive(Clone, Debug)]
pub struct MetricsRegistry {
    enabled: Arc<AtomicBool>,
    max_series_per_metric: usize,
    series: Arc<Mutex<BTreeMap<&'static str, BTreeMap<Vec<String>, Arc<Series>>>>>,
}

impl MetricsRegistry {
    #[must_use]
    pub fn new(enabled: bool) -> Self { Self::with_cardinality_limit(enabled, 1024) }
    #[must_use]
    pub fn with_cardinality_limit(enabled: bool, max_series_per_metric: usize) -> Self {
        Self { enabled: Arc::new(AtomicBool::new(enabled)), max_series_per_metric: max_series_per_metric.max(1), series: Arc::new(Mutex::new(BTreeMap::new())) }
    }
    pub fn set_enabled(&self, enabled: bool) { self.enabled.store(enabled, Ordering::Release); }
    #[must_use]
    pub fn enabled(&self) -> bool { self.enabled.load(Ordering::Acquire) }
    fn spec(name: &str) -> Option<&'static MetricSpec> { METRICS.iter().find(|s| s.name == name) }
    fn get_series(&self, name: &'static str, labels: &[&str]) -> Option<Arc<Series>> {
        if !self.enabled() { return None; }
        let spec = Self::spec(name)?;
        if labels.len() != spec.labels.len() { return None; }
        let key: Vec<String> = labels.iter().map(|v| (*v).to_owned()).collect();
        let mut all = self.series.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let group = all.entry(spec.name).or_default();
        if let Some(series) = group.get(&key) { return Some(Arc::clone(series)); }
        if group.len() >= self.max_series_per_metric { return None; }
        let value = match spec.kind {
            MetricType::Counter | MetricType::Gauge => Value::Number(AtomicU64::new(0f64.to_bits())),
            MetricType::Histogram => Value::Histogram(Mutex::new(HistogramValue { count: 0, sum: 0.0, buckets: vec![0; spec.buckets.len()] })),
        };
        let series = Arc::new(Series { labels: key.clone(), value });
        group.insert(key, Arc::clone(&series));
        Some(series)
    }
    pub fn counter_inc(&self, name: &'static str, amount: f64, labels: &[&str]) -> bool {
        if !amount.is_finite() || amount < 0.0 { return false; }
        let Some(series) = self.get_series(name, labels) else { return false; };
        let Value::Number(value) = &series.value else { return false; };
        atomic_add(value, amount); true
    }
    pub fn gauge_set(&self, name: &'static str, amount: f64, labels: &[&str]) -> bool {
        if !amount.is_finite() { return false; }
        let Some(series) = self.get_series(name, labels) else { return false; };
        let Value::Number(value) = &series.value else { return false; };
        value.store(amount.to_bits(), Ordering::Release); true
    }
    pub fn gauge_inc(&self, name: &'static str, amount: f64, labels: &[&str]) -> bool {
        if !amount.is_finite() { return false; }
        let Some(series) = self.get_series(name, labels) else { return false; };
        let Value::Number(value) = &series.value else { return false; };
        atomic_add(value, amount); true
    }
    pub fn histogram_observe(&self, name: &'static str, amount: f64, labels: &[&str]) -> bool {
        if !amount.is_finite() { return false; }
        let Some(series) = self.get_series(name, labels) else { return false; };
        let Value::Histogram(value) = &series.value else { return false; };
        let spec = Self::spec(name).expect("registered metric");
        let mut value = value.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        value.count = value.count.saturating_add(1); value.sum += amount;
        for (index, boundary) in spec.buckets.iter().enumerate() { if amount <= *boundary { value.buckets[index] = value.buckets[index].saturating_add(1); } }
        true
    }
    #[must_use]
    pub fn start_timer(&self, name: &'static str, labels: &[&str]) -> Timer { Timer { registry: self.clone(), name, labels: labels.iter().map(|v| (*v).to_owned()).collect(), started: Instant::now(), observed: false } }
    #[must_use]
    pub fn scrape(&self) -> String {
        if !self.enabled() { return String::new(); }
        let all = self.series.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = String::new();
        for spec in METRICS {
            let Some(group) = all.get(spec.name) else { continue; };
            let _ = writeln!(out, "# HELP {} {}", spec.name, spec.help);
            let _ = writeln!(out, "# TYPE {} {}", spec.name, match spec.kind { MetricType::Counter => "counter", MetricType::Gauge => "gauge", MetricType::Histogram => "histogram" });
            for series in group.values() { render_series(&mut out, spec, series); }
        }
        out
    }
}

pub struct Timer { registry: MetricsRegistry, name: &'static str, labels: Vec<String>, started: Instant, observed: bool }
impl Timer {
    pub fn observe(mut self) -> f64 { let elapsed = self.started.elapsed().as_secs_f64(); let labels: Vec<&str> = self.labels.iter().map(String::as_str).collect(); let _ = self.registry.histogram_observe(self.name, elapsed, &labels); self.observed = true; elapsed }
}
impl Drop for Timer { fn drop(&mut self) { if !self.observed { let labels: Vec<&str> = self.labels.iter().map(String::as_str).collect(); let _ = self.registry.histogram_observe(self.name, self.started.elapsed().as_secs_f64(), &labels); } } }

fn atomic_add(value: &AtomicU64, amount: f64) { let mut old = value.load(Ordering::Acquire); loop { let next = (f64::from_bits(old) + amount).to_bits(); match value.compare_exchange_weak(old, next, Ordering::AcqRel, Ordering::Acquire) { Ok(_) => break, Err(actual) => old = actual } } }
fn labels_text(names: &[&str], values: &[String], extra: Option<(&str, String)>) -> String {
    if names.is_empty() && extra.is_none() { return String::new(); }
    let mut pairs = VecDeque::new();
    for (name, value) in names.iter().zip(values) { pairs.push_back(format!("{name}=\"{}\"", escape(value))); }
    if let Some((name, value)) = extra { pairs.push_back(format!("{name}=\"{}\"", escape(&value))); }
    format!("{{{}}}", pairs.into_iter().collect::<Vec<_>>().join(","))
}
fn escape(value: &str) -> String { value.replace('\\', "\\\\").replace('\n', "\\n").replace('"', "\\\"") }
fn render_series(out: &mut String, spec: &MetricSpec, series: &Series) {
    match &series.value {
        Value::Number(value) => { let suffix = if spec.kind == MetricType::Counter { "_total" } else { "" }; let _ = writeln!(out, "{}{suffix}{} {}", spec.name, labels_text(spec.labels, &series.labels, None), f64::from_bits(value.load(Ordering::Acquire))); }
        Value::Histogram(value) => { let value = value.lock().unwrap_or_else(std::sync::PoisonError::into_inner); for (boundary, count) in spec.buckets.iter().zip(&value.buckets) { let _ = writeln!(out, "{}_bucket{} {}", spec.name, labels_text(spec.labels, &series.labels, Some(("le", boundary.to_string()))), count); } let _ = writeln!(out, "{}_bucket{} {}", spec.name, labels_text(spec.labels, &series.labels, Some(("le", "+Inf".into()))), value.count); let _ = writeln!(out, "{}_count{} {}", spec.name, labels_text(spec.labels, &series.labels, None), value.count); let _ = writeln!(out, "{}_sum{} {}", spec.name, labels_text(spec.labels, &series.labels, None), value.sum); }
    }
}

pub static METRICS: &[MetricSpec] = &[
    MetricSpec{name:"tron:txs",help:"tron  txs  info .",kind:MetricType::Counter,labels:&["type","detail"],buckets:&[]},
    MetricSpec{name:"tron:miner",help:"tron  miner info .",kind:MetricType::Counter,labels:&["miner","type"],buckets:&[]},
    MetricSpec{name:"tron:block_fork",help:"tron  block fork info .",kind:MetricType::Counter,labels:&["type"],buckets:&[]},
    MetricSpec{name:"tron:sr_set_change",help:"tron sr set change .",kind:MetricType::Counter,labels:&["action","witness"],buckets:&[]},
    MetricSpec{name:"tron:p2p_error",help:"tron p2p error  info .",kind:MetricType::Counter,labels:&["type"],buckets:&[]},
    MetricSpec{name:"tron:p2p_disconnect",help:"tron p2p disconnect .",kind:MetricType::Counter,labels:&["type"],buckets:&[]},
    MetricSpec{name:"tron:internal_service_fail",help:"internal Service fail.",kind:MetricType::Counter,labels:&["class","method"],buckets:&[]},
    MetricSpec{name:"tron:manager_queue_size",help:"tron  manager.queue.size .",kind:MetricType::Gauge,labels:&["type"],buckets:&[]},
    MetricSpec{name:"tron:header_height",help:"header  height .",kind:MetricType::Gauge,labels:&[],buckets:&[]}, MetricSpec{name:"tron:header_time",help:"header time .",kind:MetricType::Gauge,labels:&[],buckets:&[]},
    MetricSpec{name:"tron:peers",help:"tron peers.size .",kind:MetricType::Gauge,labels:&["type"],buckets:&[]}, MetricSpec{name:"tron:db_size_bytes",help:"tron  db  size .",kind:MetricType::Gauge,labels:&["type","db","level"],buckets:&[]}, MetricSpec{name:"tron:db_sst_level",help:"tron  db  files .",kind:MetricType::Gauge,labels:&["type","db","level"],buckets:&[]}, MetricSpec{name:"tron:tx_cache",help:"tron tx cache info.",kind:MetricType::Gauge,labels:&["type"],buckets:&[]},
    MetricSpec{name:"tron:internal_service_latency_seconds",help:"Internal Service latency.",kind:MetricType::Histogram,labels:&["class","method"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:http_service_latency_seconds",help:"Http Service latency.",kind:MetricType::Histogram,labels:&["url"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:grpc_service_latency_seconds",help:"Grpc Service latency.",kind:MetricType::Histogram,labels:&["endpoint"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:jsonrpc_service_latency_seconds",help:"JsonRpc Service latency.",kind:MetricType::Histogram,labels:&["method"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:miner_latency_seconds",help:"miner latency.",kind:MetricType::Histogram,labels:&["miner"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:ping_pong_latency_seconds",help:"node  ping pong  latency.",kind:MetricType::Histogram,labels:&[],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:verify_sign_latency_seconds",help:"verify sign latency for trx , block.",kind:MetricType::Histogram,labels:&["type"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:lock_acquire_latency_seconds",help:"lock acquire latency.",kind:MetricType::Histogram,labels:&["type"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:block_process_latency_seconds",help:"process block latency for TronNetDelegate.",kind:MetricType::Histogram,labels:&["sync"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:block_push_latency_seconds",help:"push block latency for Manager.",kind:MetricType::Histogram,labels:&[],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:block_generate_latency_seconds",help:"generate block latency.",kind:MetricType::Histogram,labels:&["address"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:process_transaction_latency_seconds",help:"process transaction latency.",kind:MetricType::Histogram,labels:&["type","contract"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:miner_delay_seconds",help:"miner delay time, actualTime - planTime.",kind:MetricType::Histogram,labels:&["miner"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:udp_bytes",help:"udp_bytes traffic.",kind:MetricType::Histogram,labels:&["type"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:tcp_bytes",help:"tcp_bytes traffic.",kind:MetricType::Histogram,labels:&["type"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:http_bytes",help:"http_bytes traffic.",kind:MetricType::Histogram,labels:&["url","status"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:internal_service_latency_seconds",help:"Internal Service latency.",kind:MetricType::Histogram,labels:&["class","method"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:message_process_latency_seconds",help:"process message latency.",kind:MetricType::Histogram,labels:&["type"],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:block_fetch_latency_seconds",help:"fetch block latency.",kind:MetricType::Histogram,labels:&[],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:block_receive_delay_seconds",help:"receive block delay time, receiveTime - blockTime.",kind:MetricType::Histogram,labels:&[],buckets:DEFAULT_HISTOGRAM_BUCKETS}, MetricSpec{name:"tron:block_transaction_count",help:"Distribution of transaction counts per block.",kind:MetricType::Histogram,labels:&["miner"],buckets:BLOCK_TRANSACTION_BUCKETS},
];
