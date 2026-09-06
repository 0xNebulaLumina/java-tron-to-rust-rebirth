use std::{sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tron_apis::{
    Account, AccountPaginated, ApiContext, Note, NumberMessage, PrivateShieldedTrc20Parameters,
    ReceiveNote, RpcApiServices, RpcDomainProvider, database, extension,
    interceptors::{ApiInterceptors, DISABLED_API_MESSAGE, IngressLayer, LITE_API_MESSAGE}, monitor,
    network, rate_limit::{ApiRateLimiter, RateLimitConfig}, server::{serve_grpc, GrpcServerPlan, ServerMode},
    solidity, wallet, zksnark,
};
use tron_config::RpcConfig;
use tron_execution::{
    ActuatorRegistry, CacheConfig, ExecutionConfig, PendingLimits, PendingPool,
    StateTransactionPipeline, TransactionCache, TransactionProcessor,
};
use tron_state::{CheckpointIdentity, CursorPoint, CursorSet, SessionManager, StateStore};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};
use prost::Message;
use tron_crypto::{CryptoEngine, selected_digest};
use tron_primitives::BlockId;
use tron_protocol::protocol::{block_header, transaction};
fn parameters() -> Arc<tron_shielded::TronParameters> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");
    tron_shielded::load_tron_parameters(root.join("sapling-spend.params"), root.join("sapling-output.params")).unwrap()
}

fn context_with_engine(engine: CryptoEngine) -> (std::path::PathBuf, ApiContext) {
    let path = std::env::temp_dir().join(format!(
        "c022-rpc-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    let manager = SessionManager::new(StateStore::new(
        StorageManager::new(OpenRequirements {
            identity: StorageIdentity { network: "c022".into(), genesis: "00".into() },
            schema_version: 1,
            backend: "rustlog".into(),
            backend_format: "rustlog-v1".into(),
            supported_features: vec!["rustlog-v1".into()],
        }).open_store(&path).unwrap(),
    ));
    let point = CursorPoint { block: 0, identity: CheckpointIdentity::new([0; 32]) };
    manager.record_checkpoint(point).unwrap();
    let cursors = CursorSet::new(&manager, point, None, None, 0).unwrap();
    let processor = TransactionProcessor {
        sessions: manager.clone(),
        cache: TransactionCache::new(CacheConfig::default()).unwrap(),
        pipeline: StateTransactionPipeline::new(
            Default::default(), ActuatorRegistry::empty(), ExecutionConfig::default(),
        ).unwrap(),
    };
    let pending = PendingPool::new(manager, PendingLimits::default()).unwrap();
    (path, ApiContext::new(cursors, processor, pending, parameters(), engine))
}
fn context() -> (std::path::PathBuf, ApiContext) {
    context_with_engine(CryptoEngine::Secp256k1)
}

fn push_len_field(out: &mut Vec<u8>, field: u8, value: &[u8]) {
    out.push(field << 3 | 2);
    let mut len = value.len();
    while len >= 0x80 { out.push((len as u8) | 0x80); len >>= 7; }
    out.push(len as u8);
    out.extend_from_slice(value);
}

#[test]
fn block_and_transaction_extensions_use_configured_engine_and_preserved_wire() {
    let number = 0x0102_0304_0506_0708_i64;
    let mut raw_header = block_header::Raw { number, timestamp: 1234, ..Default::default() }.encode_to_vec();
    raw_header.extend_from_slice(&[0x98, 0x06, 0x2a]);
    let mut header = Vec::new();
    push_len_field(&mut header, 1, &raw_header);
    let mut raw_tx = transaction::Raw { timestamp: 999, ..Default::default() }.encode_to_vec();
    raw_tx.extend_from_slice(&[0x98, 0x06, 0x07]);
    let mut tx = Vec::new();
    push_len_field(&mut tx, 1, &raw_tx);
    let mut block = Vec::new();
    push_len_field(&mut block, 1, &tx);
    push_len_field(&mut block, 2, &header);

    for engine in [CryptoEngine::Secp256k1, CryptoEngine::Sm2] {
        let (path, context) = context_with_engine(engine);
        let extension = tron_apis::WalletQuery::head(context).block_extension_bytes(&block).unwrap();
        let expected_block = BlockId::new(number, selected_digest(engine, &raw_header).into());
        assert_eq!(extension.blockid, expected_block.as_bytes());
        assert_eq!(&extension.blockid[..8], &number.to_be_bytes());
        assert_eq!(extension.transactions[0].txid, selected_digest(engine, &raw_tx));
        std::fs::remove_dir_all(path).unwrap();
    }
}
#[test]
fn authenticated_parameters_build_a_real_mint_proof_and_exact_trigger() {
    let (path, context) = context();
    let keys = tron_shielded::external_key_path(&tron_shielded::zip32_xsk_master(b"C022 mint provider proof")).unwrap();
    let request = PrivateShieldedTrc20Parameters {
        ask: Vec::new(), nsk: Vec::new(), ovk: keys.ovk.to_vec(), from_amount: "7".into(),
        shielded_spends: Vec::new(), shielded_receives: vec![ReceiveNote { note: Some(Note { value: 7, payment_address: keys.payment_address.iter().map(|b|format!("{b:02x}")).collect(), rcm: tron_shielded::generate_r().to_vec(), memo: b"mint".to_vec() }) }],
        transparent_to_address: Vec::new(), to_amount: "0".into(), shielded_trc20_contract_address: [vec![0x41],vec![8;20]].concat(),
    };
    let result = RpcDomainProvider::new(context.clone()).shielded_trc20(request).unwrap();
    assert_eq!(result.parameter_type,"mint"); assert_eq!(result.trigger_contract_input.len(),2112);
    let output=&result.receive_description[0];let mut verify=tron_shielded::VerificationContext::new(context.shielded_parameters());
    assert!(verify.check_output(output.value_commitment.as_slice().try_into().unwrap(),output.note_commitment.as_slice().try_into().unwrap(),output.epk.as_slice().try_into().unwrap(),&output.zkproof).unwrap());
    assert!(verify.final_check(-7,result.binding_signature.as_slice().try_into().unwrap(),result.message_hash.as_slice().try_into().unwrap()));
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn descriptor_complete_tonic_server_routes_implemented_and_java_unimplemented_methods() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let (path, context) = context();
    let services = RpcApiServices::new(context);
    let controls = IngressLayer::new(
        ApiInterceptors::new([], false, false),
        Arc::new(ApiRateLimiter::new(RateLimitConfig::default()).unwrap()),
        None,
    );
    let server = tonic::transport::Server::builder()
        .layer(controls)
        .add_service(wallet::wallet_server::WalletServer::new(services.clone())
            .max_decoding_message_size(4_194_304).max_encoding_message_size(4_194_304))
        .add_service(solidity::wallet_solidity_server::WalletSolidityServer::new(
            services.clone(),
        ).max_decoding_message_size(4_194_304).max_encoding_message_size(4_194_304))
        .add_service(extension::wallet_extension_server::WalletExtensionServer::new(
            services.clone(),
        ).max_decoding_message_size(4_194_304).max_encoding_message_size(4_194_304))
        .add_service(database::database_server::DatabaseServer::new(services.clone())
            .max_decoding_message_size(4_194_304).max_encoding_message_size(4_194_304))
        .add_service(monitor::monitor_server::MonitorServer::new(services.clone())
            .max_decoding_message_size(4_194_304).max_encoding_message_size(4_194_304))
        .add_service(network::network_server::NetworkServer::new(services.clone())
            .max_decoding_message_size(4_194_304).max_encoding_message_size(4_194_304))
        .add_service(zksnark::tron_zksnark_server::TronZksnarkServer::new(services)
            .max_decoding_message_size(4_194_304).max_encoding_message_size(4_194_304));
    let task = tokio::spawn(async move { server.serve_with_incoming(incoming).await.unwrap() });

    let endpoint = format!("http://{address}");
    let mut wallet = wallet::wallet_client::WalletClient::connect(endpoint.clone())
        .await
        .unwrap();
    let status = wallet.get_account(Account::default()).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
    assert_eq!(status.message(), "account not found");

    let mut extension =
        extension::wallet_extension_client::WalletExtensionClient::connect(endpoint)
            .await
            .unwrap();
    let status = extension
        .get_transactions_from_this(AccountPaginated::default())
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unimplemented);
    assert_eq!(
        status.message(),
        "method is not implemented by the pinned Java service"
    );
    task.abort();
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn disabled_and_lite_interceptors_reject_live_calls_before_handler_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let (path, context) = context();
    let controls = IngressLayer::new(
        ApiInterceptors::new(["getaccount".to_owned()], true, false),
        Arc::new(ApiRateLimiter::new(RateLimitConfig::default()).unwrap()),
        None,
    );
    let mut plan = GrpcServerPlan::from_config(
        ServerMode::Full,
        &RpcConfig::default(),
        false,
        false,
    ).unwrap();
    plan.listen = address;
    plan.limits.max_request_bytes = 128;
    plan.limits.max_response_bytes = 128;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(serve_grpc(
        plan,
        controls,
        RpcApiServices::new(context),
        async move { let _ = shutdown_rx.await; },
    ));
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let mut client = wallet::wallet_client::WalletClient::connect(format!("http://{address}"))
        .await.unwrap();
    let status = client.get_account(Account::default()).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
    assert_eq!(status.message(), DISABLED_API_MESSAGE);
    let status = client.get_block_by_num(NumberMessage::default()).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
    assert_eq!(status.message(), LITE_API_MESSAGE);
    shutdown_tx.send(()).unwrap();
    task.await.unwrap().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn descriptor_inventory_has_exact_service_and_method_totals() {
    let source = include_str!("../../../../docs/oracles/c022-rpc-inventory.v1.json");
    assert!(source.contains("\"service_count\": 7"));
    assert!(source.contains("\"method_count\": 204"));
    assert!(source.contains("\"unmapped\": []"));
}
