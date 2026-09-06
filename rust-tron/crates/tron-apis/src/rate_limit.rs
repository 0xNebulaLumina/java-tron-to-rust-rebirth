use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::{Code, Status};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcquireMode {
    Blocking,
    NonBlocking,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EndpointLimit {
    Qps(f64),
    IpQps(f64),
    Preemptible { permits: usize },
}

#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    pub global_qps: f64,
    pub global_ip_qps: f64,
    pub default_endpoint_qps: f64,
    pub mode: AcquireMode,
    pub endpoints: HashMap<String, EndpointLimit>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateMapLimits {
    pub max_entries: usize,
    pub idle_ttl: Duration,
}

impl Default for RateMapLimits {
    fn default() -> Self {
        Self {
            max_entries: 4_096,
            idle_ttl: Duration::from_secs(300),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_qps: 50_000.0,
            global_ip_qps: 10_000.0,
            default_endpoint_qps: 1_000.0,
            mode: AcquireMode::Blocking,
            endpoints: HashMap::new(),
        }
    }
}

impl TryFrom<&tron_config::RateLimiterConfig> for RateLimitConfig {
    type Error = RateLimitError;
    fn try_from(config: &tron_config::RateLimiterConfig) -> Result<Self, Self::Error> {
        let mut endpoints = HashMap::new();
        for item in &config.rpc {
            if item.strategy.is_empty() {
                continue;
            }
            let limit = match item.strategy.as_str() {
                "GlobalPreemptibleAdapter" => EndpointLimit::Preemptible {
                    permits: parse_param::<usize>(&item.param_string, "permit")?,
                },
                "QpsRateLimiterAdapter" => {
                    EndpointLimit::Qps(parse_param::<f64>(&item.param_string, "qps")?)
                }
                "IPQPSRateLimiterAdapter" => {
                    EndpointLimit::IpQps(parse_param::<f64>(&item.param_string, "qps")?)
                }
                strategy => return Err(RateLimitError::UnknownStrategy(strategy.to_owned())),
            };
            endpoints.insert(item.component.clone(), limit);
        }
        Ok(Self {
            global_qps: f64::from(config.global.qps),
            global_ip_qps: f64::from(config.global.ip.qps),
            default_endpoint_qps: f64::from(config.global.api.qps),
            mode: if config.api_non_blocking {
                AcquireMode::NonBlocking
            } else {
                AcquireMode::Blocking
            },
            endpoints,
        })
    }
}

fn parse_param<T: std::str::FromStr>(
    input: &str,
    expected: &'static str,
) -> Result<T, RateLimitError> {
    let (name, value) = input
        .split_once('=')
        .ok_or_else(|| RateLimitError::InvalidParameter(input.to_owned()))?;
    if name.trim() != expected {
        return Err(RateLimitError::InvalidParameter(input.to_owned()));
    }
    value
        .trim()
        .parse()
        .map_err(|_| RateLimitError::InvalidParameter(input.to_owned()))
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    updated: Instant,
}
#[derive(Debug)]
struct TokenBucket {
    qps: f64,
    state: Mutex<BucketState>,
}

impl TokenBucket {
    fn new(qps: f64) -> Result<Self, RateLimitError> {
        if !qps.is_finite() || qps <= 0.0 {
            return Err(RateLimitError::InvalidQps(qps));
        }
        Ok(Self {
            qps,
            state: Mutex::new(BucketState {
                tokens: 1.0,
                updated: Instant::now(),
            }),
        })
    }
    async fn acquire(&self, mode: AcquireMode, deadline: Option<Instant>) -> bool {
        loop {
            let wait = {
                let now = Instant::now();
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let elapsed = now.saturating_duration_since(state.updated).as_secs_f64();
                state.tokens = (state.tokens + elapsed * self.qps).min(1.0);
                state.updated = now;
                if state.tokens >= 1.0 {
                    state.tokens -= 1.0;
                    return true;
                }
                if mode == AcquireMode::NonBlocking {
                    return false;
                }
                Duration::from_secs_f64((1.0 - state.tokens) / self.qps)
            };
            if deadline.is_some_and(|end| Instant::now().checked_add(wait).is_none_or(|ready| ready > end)) {
                return false;
            }
            tokio::time::sleep(wait).await;
        }
    }
}

#[derive(Debug)]
struct SemaphorePermit {
    _permit: OwnedSemaphorePermit,
}

#[derive(Debug)]
enum EndpointLimiter {
    Qps(TokenBucket),
    IpQps {
        qps: f64,
        buckets: Mutex<RateMap>,
    },
    Preemptible(Arc<Semaphore>),
}

#[derive(Debug)]
pub struct RequestPermit {
    _endpoint: Option<SemaphorePermit>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitError {
    InvalidQps(f64),
    InvalidPermitCount,
    InvalidParameter(String),
    UnknownStrategy(String),
    InvalidRateMapLimit,
    RateMapFull,
}
impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidQps(qps) => write!(f, "rate limit qps must be finite and positive: {qps}"),
            Self::InvalidPermitCount => f.write_str("preemptible permit count must be positive"),
            Self::InvalidParameter(value) => write!(f, "invalid rate limiter parameter: {value}"),
            Self::UnknownStrategy(strategy) => {
                write!(f, "undefined rate limiter adaptor: {strategy}")
            }
            Self::InvalidRateMapLimit => f.write_str("rate limiter map bounds must be positive"),
            Self::RateMapFull => f.write_str("rate limiter map is full"),
        }
    }
}
impl std::error::Error for RateLimitError {}

#[derive(Debug)]
struct RateMapEntry {
    bucket: Arc<TokenBucket>,
    last_used: Instant,
}

#[derive(Debug)]
struct RateMap {
    entries: HashMap<String, RateMapEntry>,
    limits: RateMapLimits,
}

impl RateMap {
    fn new(limits: RateMapLimits) -> Result<Self, RateLimitError> {
        if limits.max_entries == 0 || limits.idle_ttl.is_zero() {
            return Err(RateLimitError::InvalidRateMapLimit);
        }
        Ok(Self { entries: HashMap::new(), limits })
    }

    fn bucket(&mut self, key: &str, qps: f64) -> Result<Arc<TokenBucket>, RateLimitError> {
        let now = Instant::now();
        self.entries.retain(|_, entry| {
            now.saturating_duration_since(entry.last_used) < self.limits.idle_ttl
                || Arc::strong_count(&entry.bucket) > 1
        });
        if let Some(entry) = self.entries.get_mut(key) {
            entry.last_used = now;
            return Ok(Arc::clone(&entry.bucket));
        }
        if self.entries.len() >= self.limits.max_entries {
            let evict = self.entries.iter()
                .filter(|(_, entry)| Arc::strong_count(&entry.bucket) == 1)
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone());
            if let Some(key) = evict {
                self.entries.remove(&key);
            } else {
                return Err(RateLimitError::RateMapFull);
            }
        }
        let bucket = Arc::new(TokenBucket::new(qps)?);
        self.entries.insert(key.to_owned(), RateMapEntry { bucket: Arc::clone(&bucket), last_used: now });
        Ok(bucket)
    }
}

#[derive(Debug)]
pub struct ApiRateLimiter {
    mode: AcquireMode,
    global: TokenBucket,
    global_ip_qps: f64,
    global_ips: Mutex<RateMap>,
    default_endpoint_qps: f64,
    default_endpoints: Mutex<RateMap>,
    endpoints: HashMap<String, EndpointLimiter>,
}

impl ApiRateLimiter {
    pub fn new(config: RateLimitConfig) -> Result<Self, RateLimitError> {
        Self::new_with_map_limits(config, RateMapLimits::default())
    }

    pub fn new_with_map_limits(
        config: RateLimitConfig,
        map_limits: RateMapLimits,
    ) -> Result<Self, RateLimitError> {
        let global = TokenBucket::new(config.global_qps)?;
        TokenBucket::new(config.global_ip_qps)?;
        TokenBucket::new(config.default_endpoint_qps)?;
        let mut endpoints = HashMap::new();
        for (method, limit) in config.endpoints {
            let limiter = match limit {
                EndpointLimit::Qps(qps) => EndpointLimiter::Qps(TokenBucket::new(qps)?),
                EndpointLimit::IpQps(qps) => {
                    TokenBucket::new(qps)?;
                    EndpointLimiter::IpQps {
                        qps,
                        buckets: Mutex::new(RateMap::new(map_limits)?),
                    }
                }
                EndpointLimit::Preemptible { permits } => {
                    if permits == 0 {
                        return Err(RateLimitError::InvalidPermitCount);
                    }
                    EndpointLimiter::Preemptible(Arc::new(Semaphore::new(permits)))
                }
            };
            endpoints.insert(method, limiter);
        }
        Ok(Self {
            mode: config.mode,
            global,
            global_ip_qps: config.global_ip_qps,
            global_ips: Mutex::new(RateMap::new(map_limits)?),
            default_endpoint_qps: config.default_endpoint_qps,
            default_endpoints: Mutex::new(RateMap::new(map_limits)?),
            endpoints,
        })
    }

    /// Acquires in java-tron's order: endpoint, source IP global, then process global.
    pub async fn acquire(
        &self,
        method: &str,
        remote_ip: Option<&str>,
        deadline: Option<Instant>,
    ) -> Result<RequestPermit, Status> {
        let deadline = deadline.or_else(|| (self.mode == AcquireMode::Blocking)
            .then(|| Instant::now() + Duration::from_secs(5)));
        let endpoint = self.acquire_endpoint(method, remote_ip, deadline).await?;
        if let Some(ip) = remote_ip.filter(|ip| !ip.is_empty()) {
            let bucket =
                bucket_for(&self.global_ips, ip, self.global_ip_qps).map_err(internal_status)?;
            if !bucket.acquire(self.mode, deadline).await {
                return Err(overload_status(deadline));
            }
        }
        if !self.global.acquire(self.mode, deadline).await {
            return Err(overload_status(deadline));
        }
        Ok(RequestPermit { _endpoint: endpoint })
    }

    async fn acquire_endpoint(
        &self,
        method: &str,
        remote_ip: Option<&str>,
        deadline: Option<Instant>,
    ) -> Result<Option<SemaphorePermit>, Status> {
        match self.endpoints.get(method) {
            Some(EndpointLimiter::Qps(bucket)) => {
                bucket.acquire(self.mode, deadline).await.then_some(None)
                    .ok_or_else(|| overload_status(deadline))
            }
            Some(EndpointLimiter::IpQps { qps, buckets }) => {
                let bucket = bucket_for(buckets, remote_ip.unwrap_or(""), *qps)
                    .map_err(internal_status)?;
                bucket.acquire(self.mode, deadline).await.then_some(None)
                    .ok_or_else(|| overload_status(deadline))
            }
            Some(EndpointLimiter::Preemptible(limiter)) => {
                let permit = match self.mode {
                    AcquireMode::NonBlocking => limiter.clone().try_acquire_owned().ok(),
                    AcquireMode::Blocking => {
                        let acquire = limiter.clone().acquire_owned();
                        if let Some(end) = deadline {
                            let end = tokio::time::Instant::from_std(end);
                            tokio::time::timeout_at(end, acquire).await.ok().and_then(Result::ok)
                        } else {
                            acquire.await.ok()
                        }
                    }
                };
                permit.map(|permit| Some(SemaphorePermit { _permit: permit }))
                    .ok_or_else(|| overload_status(deadline))
            }
            None => {
                let bucket = bucket_for(&self.default_endpoints, method, self.default_endpoint_qps)
                    .map_err(internal_status)?;
                bucket.acquire(self.mode, deadline).await.then_some(None)
                    .ok_or_else(|| overload_status(deadline))
            }
        }
    }
    #[must_use]
    pub fn cached_entry_counts(&self) -> (usize, usize) {
        let global_ips = self.global_ips
            .lock().unwrap_or_else(std::sync::PoisonError::into_inner).entries.len();
        let default_endpoints = self.default_endpoints
            .lock().unwrap_or_else(std::sync::PoisonError::into_inner).entries.len();
        (global_ips, default_endpoints)
    }

}

fn bucket_for(
    cache: &Mutex<RateMap>,
    key: &str,
    qps: f64,
) -> Result<Arc<TokenBucket>, RateLimitError> {
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .bucket(key, qps)
}
fn internal_status(error: RateLimitError) -> Status {
    Status::internal(error.to_string())
}
fn overload_status(deadline: Option<Instant>) -> Status {
    if deadline.is_some_and(|end| Instant::now() >= end) {
        Status::deadline_exceeded("rate limiter deadline exceeded")
    } else {
        Status::new(Code::ResourceExhausted, "")
    }
}
