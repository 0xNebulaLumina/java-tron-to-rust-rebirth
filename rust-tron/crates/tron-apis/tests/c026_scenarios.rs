use std::{collections::BTreeSet, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, sync::watch};
use tron_apis::{
    Account, AccountPaginated, ApiContext, EmptyMessage, RpcApiServices, ZksnarkRequest,
    database, extension, monitor, solidity, wallet, zksnark,
    http_filters::HttpControls,
    http_router::{HttpRouteState, http_router},
    http_routes::{HttpSurface, routes_for},
    http_server::{HttpServerConfig, HttpServerPlan},
    interceptors::{ApiInterceptors, IngressLayer},
    rate_limit::{ApiRateLimiter, RateLimitConfig},
    server::{GrpcServerPlan, ServerMode, serve_grpc},
};
use tron_config::{Config, RpcConfig};
use tron_crypto::CryptoEngine;
use tron_execution::ActuatorRegistry;
use tron_state::{CheckpointIdentity, CursorPoint, CursorSet, SessionManager, StateStore};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

fn context() -> (std::path::PathBuf, ApiContext) {
    let path = std::env::temp_dir().join(format!("c026-live-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    let manager = SessionManager::new(StateStore::new(StorageManager::new(OpenRequirements {
        identity: StorageIdentity { network: "c026".into(), genesis: "00".into() }, schema_version: 1,
        backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()],
    }).open_store(&path).unwrap()));
    let point = CursorPoint { block: 0, identity: CheckpointIdentity::new([0; 32]) };
    manager.record_checkpoint(point).unwrap();
    let cursors = CursorSet::new(&manager, point, None, None, 0).unwrap();
    let params = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");
    let parameters = tron_shielded::load_tron_parameters(params.join("sapling-spend.params"), params.join("sapling-output.params")).unwrap();
    (path, ApiContext::new(cursors, None, Arc::new(ActuatorRegistry::empty()), parameters, CryptoEngine::Secp256k1))
}

async fn free_address() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

async fn wait_ready(address: std::net::SocketAddr) {
    for _ in 0..100 {
        if TcpStream::connect(address).await.is_ok() { return; }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("standalone endpoint {address} did not become ready");
}

async fn http_request(address: std::net::SocketAddr, method: &str, target: &str, body: &[u8]) -> u16 {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len());
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut wire = Vec::new(); stream.read_to_end(&mut wire).await.unwrap();
    let headers = String::from_utf8(wire[..wire.windows(4).position(|part| part == b"\r\n\r\n").unwrap()].to_vec()).unwrap();
    headers.lines().next().unwrap().split_whitespace().nth(1).unwrap().parse().unwrap()
}
async fn grpc_probe(endpoint: String, path: &'static str) -> tonic::Status {
    let channel = tonic::transport::Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.unwrap();
    grpc.unary(
        tonic::Request::new(EmptyMessage::default()),
        tonic::codegen::http::uri::PathAndQuery::from_static(path),
        tonic::codec::ProstCodec::<EmptyMessage, EmptyMessage>::default(),
    ).await.unwrap_err()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_live_grpc_services_and_forbidden_families_are_observed() {
    let address = "127.0.0.1:50051".parse().unwrap();
    let (path, context) = context();
    let controls = IngressLayer::new(ApiInterceptors::new([], false, false), Arc::new(ApiRateLimiter::new(RateLimitConfig::default()).unwrap()), None);
    let mut plan = GrpcServerPlan::from_config(ServerMode::StandaloneSolidity, &RpcConfig::default(), true, true).unwrap();
    plan.listen = address;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(serve_grpc(plan, controls, RpcApiServices::new(context), async move { let _ = shutdown_rx.await; }));
    wait_ready(address).await;
    let endpoint = format!("http://{address}");

    let mut database = database::database_client::DatabaseClient::connect(endpoint.clone()).await.unwrap();
    assert_ne!(database.get_dynamic_properties(EmptyMessage::default()).await.unwrap_err().code(), tonic::Code::Unimplemented);
    let mut solidity = solidity::wallet_solidity_client::WalletSolidityClient::connect(endpoint.clone()).await.unwrap();
    assert_ne!(solidity.get_now_block(EmptyMessage::default()).await.unwrap_err().code(), tonic::Code::Unimplemented);
    let mut extension = extension::wallet_extension_client::WalletExtensionClient::connect(endpoint.clone()).await.unwrap();
    assert_eq!(extension.get_transactions_from_this(AccountPaginated::default()).await.unwrap_err().message(), "method is not implemented by the pinned Java service");
    let mut monitor = monitor::monitor_client::MonitorClient::connect(endpoint.clone()).await.unwrap();
    let stats = monitor.get_stats_info(EmptyMessage::default()).await.unwrap().into_inner();
    assert!(stats.node.is_some());

    let mut wallet = wallet::wallet_client::WalletClient::connect(endpoint.clone()).await.unwrap();
    assert_eq!(wallet.get_account(Account::default()).await.unwrap_err().code(), tonic::Code::Unimplemented);
    assert_eq!(grpc_probe(format!("http://{address}"), "/protocol.Network/ListNodes").await.code(), tonic::Code::Unimplemented);
    let mut zksnark = zksnark::tron_zksnark_client::TronZksnarkClient::connect(format!("http://{address}")).await.unwrap();
    assert_eq!(zksnark.check_zksnark_proof(ZksnarkRequest::default()).await.unwrap_err().code(), tonic::Code::Unimplemented);

    shutdown_tx.send(()).unwrap(); task.await.unwrap().unwrap(); std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_45_solidity_routes_execute_on_live_isolated_http() {
    let address = "127.0.0.1:8091".parse().unwrap();
    let (path, context) = context();
    let controls = HttpControls::default();
    let state = HttpRouteState::new(RpcApiServices::new(context), controls.clone(), Arc::new(ApiRateLimiter::new(RateLimitConfig::default()).unwrap()), Duration::from_secs(5), false);
    let mut config = HttpServerConfig::new(address); config.controls = controls;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(HttpServerPlan::new(config, http_router(state, HttpSurface::Solidity)).serve(shutdown_rx));
    wait_ready(address).await;
    let mut observed = BTreeSet::new();
    for route in routes_for(HttpSurface::Solidity) {
        let (method, target, body): (&str, String, &[u8]) = if route.get { ("GET", format!("{}?visible=false", route.path), b"") } else { ("POST", route.path.to_owned(), b"{}") };
        let status = http_request(address, method, &target, body).await;
        assert!(status == route.success_status || status == route.error_status, "{} returned {status}", route.path);
        assert_eq!(route.cursor, tron_apis::ApiCursor::Solidity);
        assert!(observed.insert(route.path));
    }
    assert_eq!(observed.len(), 45);
    shutdown_tx.send(true).unwrap(); task.await.unwrap().unwrap(); std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn forbidden_transport_ports_are_absent_and_default_live_ports_are_pinned() {
    for port in [50061, 8090, 8092, 50071, 18888, 8545] {
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err(), "forbidden default port {port} is listening");
    }
    let config = Config::default();
    assert_eq!(GrpcServerPlan::from_config(ServerMode::StandaloneSolidity, &config.node.rpc, false, false).unwrap().listen.port(), 50051);
    assert_eq!(HttpServerConfig::new("127.0.0.1:8091".parse().unwrap()).bind.port(), 8091);
}
