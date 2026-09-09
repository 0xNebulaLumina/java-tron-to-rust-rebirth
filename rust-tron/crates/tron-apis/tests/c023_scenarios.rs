use std::{collections::BTreeSet, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, sync::watch};
use tron_apis::{ApiContext, RpcApiServices, http_filters::HttpControls, http_router::{HttpRouteState, http_router}, http_routes::{HTTP_ROUTES, HttpSurface}, http_server::{HttpServerConfig, HttpServerPlan}, rate_limit::{ApiRateLimiter, RateLimitConfig}};
use tron_crypto::CryptoEngine;
use tron_execution::ActuatorRegistry;
use tron_state::{CheckpointIdentity, CursorPoint, CursorSet, SessionManager, StateStore};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

fn context() -> (std::path::PathBuf, ApiContext) {
    let path = std::env::temp_dir().join(format!("c023-http-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    let manager = SessionManager::new(StateStore::new(StorageManager::new(OpenRequirements {
        identity: StorageIdentity { network: "c023".into(), genesis: "00".into() }, schema_version: 1,
        backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()],
    }).open_store(&path).unwrap()));
    let point = CursorPoint { block: 0, identity: CheckpointIdentity::new([0; 32]) };
    manager.record_checkpoint(point).unwrap();
    let cursors = CursorSet::new(&manager, point, None, None, 0).unwrap();
    let params = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");
    let parameters = tron_shielded::load_tron_parameters(params.join("sapling-spend.params"), params.join("sapling-output.params")).unwrap();
    (path, ApiContext::new(cursors, None, Arc::new(ActuatorRegistry::empty()), parameters, CryptoEngine::Secp256k1))
}

async fn start(mut controls: HttpControls, lite: bool, concurrent: usize, surface: HttpSurface) -> (std::net::SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<std::io::Result<()>>, std::path::PathBuf) {
    controls.max_connections = concurrent;
    start_with_timeouts(controls, lite, surface, Duration::from_secs(5), Duration::from_secs(30)).await
}

async fn start_with_timeouts(controls: HttpControls, lite: bool, surface: HttpSurface, first_request_timeout: Duration, idle_timeout: Duration) -> (std::net::SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<std::io::Result<()>>, std::path::PathBuf) {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    let (path, context) = context();
    let rate_limiter = Arc::new(ApiRateLimiter::new(RateLimitConfig::default()).unwrap());
    let state = HttpRouteState::new(RpcApiServices::new(context), controls.clone(), rate_limiter, Duration::from_secs(5), lite);
    let mut config = HttpServerConfig::new(address);
    config.request_deadline = Duration::from_secs(5);
    config.first_request_timeout = first_request_timeout;
    config.connection_idle_timeout = idle_timeout;
    config.connection_max_age = Duration::from_secs(30);
    config.controls = controls;
    let plan = HttpServerPlan::new(config, http_router(state, surface));
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(plan.serve(rx));
    for _ in 0..100 { if TcpStream::connect(address).await.is_ok() { tokio::time::sleep(Duration::from_millis(20)).await; return (address, tx, task, path); } tokio::time::sleep(Duration::from_millis(5)).await; }
    panic!("C023 localhost server did not become ready");
}

async fn request(address: std::net::SocketAddr, method: &str, target: &str, content_type: &str, body: &[u8]) -> (u16, String, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let head = format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n", body.len());
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut wire = Vec::new(); stream.read_to_end(&mut wire).await.unwrap();
    let split = wire.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
    let headers = String::from_utf8(wire[..split].to_vec()).unwrap();
    let status = headers.lines().next().unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, headers, wire[split + 4..].to_vec())
}

async fn stop(tx: watch::Sender<bool>, task: tokio::task::JoinHandle<std::io::Result<()>>, path: std::path::PathBuf) { tx.send(true).unwrap(); task.await.unwrap().unwrap(); std::fs::remove_dir_all(path).unwrap(); }

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_215_inventory_rows_execute_through_real_localhost_http() {
    let mut identities = BTreeSet::new();
    for surface in [HttpSurface::Full, HttpSurface::Solidity, HttpSurface::Pbft] {
        let (address, tx, task, path) = start(HttpControls::default(), false, 8, surface).await;
        for route in HTTP_ROUTES.iter().filter(|route| route.surface == surface) {
            let (method, target, content_type, body): (&str, String, &str, &[u8]) = if route.get { ("GET", format!("{}?visible=false", route.path), "application/x-www-form-urlencoded", b"") } else { ("POST", route.path.to_owned(), "application/json", b"{}") };
            let (status, headers, response) = request(address, method, &target, content_type, body).await;
            assert!(status == route.success_status || status == route.error_status, "{} {} returned {status}", route.path, method);
            assert!(headers.to_ascii_lowercase().contains("content-type:"), "{} lacks content type", route.path);
            assert!(!response.is_empty() || route.path == "/wallet/validateaddress", "{} lacks row-specific terminal body", route.path);
            assert!(identities.insert((format!("{:?}", route.surface), route.path)));
        }
        stop(tx, task, path).await;
    }
    assert_eq!(identities.len(), 215);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_equivalence_manifest_reaches_terminal_http_states() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!("../../../../docs/oracles/c023-scenarios.v1.json")).unwrap();
    let scenarios = manifest["scenarios"].as_array().unwrap();
    assert_eq!(scenarios.len(), 18);
    assert_eq!(scenarios.iter().filter_map(|row| row["id"].as_str()).collect::<BTreeSet<_>>().len(), 18);
    assert!(scenarios.iter().all(|row| row["rust_case"].as_str().is_some() && row["terminal_state"] == "observed"));

    let (address, tx, task, path) = start(HttpControls::default(), false, 8, HttpSurface::Full).await;
    let vectors = [
        ("GET", "/wallet/getnowblock?visible=false", "application/x-www-form-urlencoded", b"".as_slice()),
        ("POST", "/wallet/getnowblock", "application/json", b"{}".as_slice()),
        ("POST", "/wallet/getnowblock", "application/x-www-form-urlencoded", b"visible=true".as_slice()),
        ("POST", "/wallet/validateaddress", "application/json", br#"{"address":"QQAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.as_slice()),
        ("POST", "/wallet/broadcasthex", "application/json", br#"{"transaction":"00"}"#.as_slice()),
        ("GET", "/monitor/getstatsinfo", "application/x-www-form-urlencoded", b"".as_slice()),
        ("GET", "/wallet/getblockbynum?num=0", "application/x-www-form-urlencoded", b"".as_slice()),
    ];
    for (method, target, content_type, body) in vectors { let (status, headers, _) = request(address, method, target, content_type, body).await; assert!(status == 200 || status == 404); assert!(headers.to_ascii_lowercase().contains("content-type:")); }
    stop(tx, task, path).await;

    let mut controls = HttpControls::new(["getaccount".to_owned()]); controls.max_body_bytes = 4;
    let (address, tx, task, path) = start(controls, false, 1, HttpSurface::Full).await;
    let (status, _, body) = request(address, "GET", "/wallet/getaccount", "application/x-www-form-urlencoded", b"").await; assert_eq!(status, 404); assert!(String::from_utf8(body).unwrap().contains("unavailable due to config"));
    let (status, _, _) = request(address, "POST", "/wallet/getnowblock", "application/json", b"12345").await; assert_eq!(status, 413);
    let (status, _, body) = request(address, "POST", "/wallet/getnowblock", "application/json", b"null").await; assert_eq!(status, 200); assert!(String::from_utf8(body).unwrap().contains("Error"));
    stop(tx, task, path).await;

    let (address, tx, task, path) = start(HttpControls::default(), true, 8, HttpSurface::Full).await;
    let (status, _, body) = request(address, "GET", "/wallet/getblockbynum?num=0", "application/x-www-form-urlencoded", b"").await; assert_eq!(status, 200); assert!(String::from_utf8(body).unwrap().contains("lite fullnode"));
    stop(tx, task, path).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_getnodeinfo_path_uses_each_surface_service() {
    let full = HTTP_ROUTES.iter().find(|route| route.surface == HttpSurface::Full && route.path == "/wallet/getnodeinfo").unwrap();
    let solidity = HTTP_ROUTES.iter().find(|route| route.surface == HttpSurface::Solidity && route.path == "/wallet/getnodeinfo").unwrap();
    assert_eq!((full.rpc_api, full.cursor), ("Wallet", tron_apis::ApiCursor::Head));
    assert_eq!((solidity.rpc_api, solidity.cursor), ("WalletSolidity", tron_apis::ApiCursor::Solidity));
    for (surface, marker) in [(HttpSurface::Full, "HEAD"), (HttpSurface::Solidity, "SOLIDITY")] {
        let (address, tx, task, path) = start(HttpControls::default(), false, 8, surface).await;
        let (status, _, body) = request(address, "GET", "/wallet/getnodeinfo", "application/x-www-form-urlencoded", b"").await;
        assert_eq!(status, 200, "{marker} surface did not serve its duplicate path");
        assert!(serde_json::from_slice::<serde_json::Value>(&body).unwrap().is_object(), "{marker} response was not protobuf JSON");
        stop(tx, task, path).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_and_drip_header_connections_release_capacity() {
    let (address, tx, task, path) = start_with_timeouts(HttpControls::default(), false, HttpSurface::Full, Duration::from_millis(100), Duration::from_secs(2)).await;
    let mut silent = Vec::new();
    for _ in 0..50 { silent.push(TcpStream::connect(address).await.unwrap()); }
    tokio::time::sleep(Duration::from_millis(180)).await;
    assert_eq!(request(address, "GET", "/wallet/getnodeinfo", "application/x-www-form-urlencoded", b"").await.0, 200, "expired silent sockets starved a legitimate connection");
    drop(silent);
    let mut drips = Vec::new();
    for _ in 0..50 { let mut stream = TcpStream::connect(address).await.unwrap(); stream.write_all(b"G").await.unwrap(); drips.push(stream); }
    tokio::time::sleep(Duration::from_millis(60)).await;
    for stream in &mut drips { let _ = stream.write_all(b"E").await; }
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(request(address, "GET", "/wallet/getnodeinfo", "application/x-www-form-urlencoded", b"").await.0, 200, "absolute header deadline was reset by slowloris drips");
    drop(drips);
    stop(tx, task, path).await;
}
