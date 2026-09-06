use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tonic::Code;
use tron_apis::{
    BlockingExecutor,
    interceptors::{ApiInterceptors, DISABLED_API_MESSAGE, LITE_API_MESSAGE, LITE_FILTER_METHODS},
    rate_limit::{AcquireMode, ApiRateLimiter, EndpointLimit, RateLimitConfig, RateMapLimits},
};

#[test]
fn disabled_and_lite_interceptors_preserve_java_lists_messages_and_precedence() {
    assert_eq!(LITE_FILTER_METHODS.len(), 43);
    assert!(LITE_FILTER_METHODS.contains(&"protocol.Database/GetBlockByNum"));
    assert!(!LITE_FILTER_METHODS.contains(&"protocol.Wallet/GetNowBlock"));
    let interceptors = ApiInterceptors::new(["getblockbynum".to_owned()], true, false);
    let disabled = interceptors
        .check("protocol.Wallet/GetBlockByNum")
        .unwrap_err();
    assert_eq!(
        (disabled.code(), disabled.message()),
        (Code::Unavailable, DISABLED_API_MESSAGE)
    );
    let lite = ApiInterceptors::new([], true, false)
        .check("protocol.Wallet/GetBlockByNum")
        .unwrap_err();
    assert_eq!(
        (lite.code(), lite.message()),
        (Code::Unavailable, LITE_API_MESSAGE)
    );
    assert!(
        ApiInterceptors::new([], true, true)
            .check("protocol.Wallet/GetBlockByNum")
            .is_ok()
    );
}

#[tokio::test]
async fn nonblocking_endpoint_global_and_ip_limits_return_resource_exhausted() {
    let config = RateLimitConfig {
        global_qps: 0.01,
        global_ip_qps: 0.01,
        default_endpoint_qps: 0.01,
        mode: AcquireMode::NonBlocking,
        endpoints: HashMap::new(),
    };
    let limiter = ApiRateLimiter::new(config).unwrap();
    drop(
        limiter
            .acquire("protocol.Wallet/GetNowBlock", Some("192.0.2.1"), None).await
            .unwrap(),
    );
    let endpoint = limiter
        .acquire("protocol.Wallet/GetNowBlock", Some("192.0.2.2"), None).await
        .unwrap_err();
    assert_eq!(endpoint.code(), Code::ResourceExhausted);
}

#[tokio::test]
async fn preemptible_permit_releases_on_completion_and_global_rejection() {
    let method = "protocol.Wallet/BroadcastTransaction".to_owned();
    let mut endpoints = HashMap::new();
    endpoints.insert(method.clone(), EndpointLimit::Preemptible { permits: 1 });
    let limiter = Arc::new(ApiRateLimiter::new(RateLimitConfig {
        global_qps: 10_000.0,
        global_ip_qps: 10_000.0,
        default_endpoint_qps: 10_000.0,
        mode: AcquireMode::Blocking,
        endpoints,
    }).unwrap());
    let first = limiter.acquire(&method, None, None).await.unwrap();
    let waiting = {
        let limiter = Arc::clone(&limiter);
        let method = method.clone();
        tokio::spawn(async move {
            limiter.acquire(&method, None, Some(Instant::now() + Duration::from_secs(1))).await.is_ok()
        })
    };
    tokio::task::yield_now().await;
    drop(first);
    assert!(waiting.await.unwrap());
    let held = limiter.acquire(&method, None, None).await.unwrap();
    let cancelled = tokio::time::timeout(
        Duration::from_millis(5),
        limiter.acquire(&method, None, None),
    ).await;
    assert!(cancelled.is_err());
    drop(held);
    assert!(limiter.acquire(&method, None, None).await.is_ok());

    let mut endpoints = HashMap::new();
    endpoints.insert(method.clone(), EndpointLimit::Preemptible { permits: 1 });
    let limiter = ApiRateLimiter::new(RateLimitConfig {
        global_qps: 100.0,
        global_ip_qps: 100.0,
        default_endpoint_qps: 100.0,
        mode: AcquireMode::NonBlocking,
        endpoints,
    }).unwrap();
    drop(limiter.acquire("protocol.Wallet/GetNowBlock", None, None).await.unwrap());
    assert_eq!(limiter.acquire(&method, None, None).await.unwrap_err().code(), Code::ResourceExhausted);
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert!(limiter.acquire(&method, None, None).await.is_ok());
}

#[tokio::test]
async fn blocking_acquire_honors_deadline_and_configuration_errors() {
    let method = "protocol.Wallet/GetAccount".to_owned();
    let mut endpoints = HashMap::new();
    endpoints.insert(method.clone(), EndpointLimit::Preemptible { permits: 1 });
    let limiter = ApiRateLimiter::new(RateLimitConfig {
        global_qps: 1_000.0,
        global_ip_qps: 1_000.0,
        default_endpoint_qps: 1_000.0,
        mode: AcquireMode::Blocking,
        endpoints,
    })
    .unwrap();
    let _held = limiter.acquire(&method, None, None).await.unwrap();
    let status = limiter
        .acquire(
            &method,
            None,
            Some(Instant::now() + Duration::from_millis(10)),
        )
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::DeadlineExceeded);
    let invalid = ApiRateLimiter::new(RateLimitConfig {
        global_qps: 0.0,
        ..RateLimitConfig::default()
    })
    .unwrap_err();
    assert!(invalid.to_string().contains("positive"));
}

#[tokio::test]
async fn per_ip_and_endpoint_maps_are_lru_bounded_and_expire_idle_entries() {
    let limiter = ApiRateLimiter::new_with_map_limits(
        RateLimitConfig {
            global_qps: 100_000.0,
            global_ip_qps: 100_000.0,
            default_endpoint_qps: 100_000.0,
            mode: AcquireMode::NonBlocking,
            endpoints: HashMap::new(),
        },
        RateMapLimits { max_entries: 2, idle_ttl: Duration::from_millis(5) },
    ).unwrap();
    for index in 0..10 {
        let method = format!("protocol.Wallet/Method{index}");
        let ip = format!("192.0.2.{index}");
        drop(limiter.acquire(&method, Some(&ip), None).await.unwrap());
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(limiter.cached_entry_counts(), (2, 2));
    tokio::time::sleep(Duration::from_millis(10)).await;
    drop(limiter.acquire("protocol.Wallet/Fresh", Some("198.51.100.1"), None).await.unwrap());
    assert_eq!(limiter.cached_entry_counts(), (1, 1));
}

#[tokio::test]
async fn blocking_executor_bounds_workers_cancels_and_releases_permits() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let bounded = BlockingExecutor::new(1, Duration::from_secs(1)).unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let executor = bounded.clone();
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        tasks.push(tokio::spawn(async move {
            executor.run(move |_| {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(5));
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }).await
        }));
    }
    for task in tasks { task.await.unwrap().unwrap(); }
    assert_eq!(peak.load(Ordering::SeqCst), 1);

    let timed = BlockingExecutor::new(1, Duration::from_millis(10)).unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&cancelled);
    let status = timed.run(move |cancel| {
        while !cancel.is_cancelled() { std::thread::sleep(Duration::from_millis(1)); }
        observed.store(true, Ordering::SeqCst);
        Ok(())
    }).await.unwrap_err();
    assert_eq!(status.code(), Code::DeadlineExceeded);
    tokio::time::timeout(Duration::from_millis(100), async {
        while !cancelled.load(Ordering::SeqCst) { tokio::task::yield_now().await; }
    }).await.unwrap();
    timed.run(move |_| Ok(())).await.unwrap();

    let saturated = BlockingExecutor::new(1, Duration::from_millis(15)).unwrap();
    let holding = Arc::new(AtomicBool::new(false));
    let worker_holding = Arc::clone(&holding);
    let executor = saturated.clone();
    let first = tokio::spawn(async move {
        executor.run(move |_| {
            worker_holding.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(50));
            Ok(())
        }).await
    });
    tokio::time::timeout(Duration::from_millis(100), async {
        while !holding.load(Ordering::SeqCst) { tokio::task::yield_now().await; }
    }).await.unwrap();
    let queued = saturated.run(move |_| Ok(())).await.unwrap_err();
    assert_eq!(queued.code(), Code::DeadlineExceeded);
    assert!(queued.message().contains("queue"));
    assert_eq!(first.await.unwrap().unwrap_err().code(), Code::DeadlineExceeded);
    tokio::time::sleep(Duration::from_millis(40)).await;
    saturated.run(move |_| Ok(())).await.unwrap();

    let aborted = BlockingExecutor::new(1, Duration::from_secs(1)).unwrap();
    let started = Arc::new(AtomicBool::new(false));
    let stopped = Arc::new(AtomicBool::new(false));
    let worker_started = Arc::clone(&started);
    let worker_stopped = Arc::clone(&stopped);
    let executor = aborted.clone();
    let task = tokio::spawn(async move {
        executor.run(move |cancel| {
            worker_started.store(true, Ordering::SeqCst);
            while !cancel.is_cancelled() { std::thread::sleep(Duration::from_millis(1)); }
            worker_stopped.store(true, Ordering::SeqCst);
            Ok(())
        }).await
    });
    tokio::time::timeout(Duration::from_millis(100), async {
        while !started.load(Ordering::SeqCst) { tokio::task::yield_now().await; }
    }).await.unwrap();
    task.abort();
    tokio::time::timeout(Duration::from_millis(100), async {
        while !stopped.load(Ordering::SeqCst) { tokio::task::yield_now().await; }
    }).await.unwrap();
    aborted.run(move |_| Ok(())).await.unwrap();
}

#[test]
fn blocking_executor_rejects_unbounded_configuration() {
    assert!(BlockingExecutor::new(0,Duration::from_secs(1)).is_err());
    assert!(BlockingExecutor::new(1,Duration::ZERO).is_err());
}
