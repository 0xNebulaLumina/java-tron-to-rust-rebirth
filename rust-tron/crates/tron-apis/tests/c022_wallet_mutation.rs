use prost::Message;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tonic::Code;
use tron_apis::{ApiContext, BlockingExecutor, RpcApiServices, interceptors::PreservedRawGrpcMessage, wallet::wallet_server::Wallet};
use tron_crypto::CryptoEngine;
use tron_execution::{
    ActuatorRegistry, CacheConfig, ExecutionConfig, PendingLimits, PendingPool,
    StateTransactionPipeline, TransactionCache, TransactionProcessor,
};
use tron_state::{dynamic, CheckpointIdentity, CursorPoint, CursorSet, SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

use tron_apis::{
    ShieldedWallet,
    error::{failure_return, success_return},
};
use tron_protocol::protocol::{ViewingKeyMessage, r#return::ResponseCode};

#[test]
fn return_fields_are_java_compatible() {
    let ok = success_return();
    assert!(ok.result);
    assert_eq!(ok.code, ResponseCode::Success as i32);
    assert!(ok.message.is_empty());
    let failed = failure_return(
        ResponseCode::ContractValidateError,
        b"bad contract".to_vec(),
    );
    assert!(!failed.result);
    assert_eq!(failed.code, ResponseCode::ContractValidateError as i32);
    assert_eq!(failed.message, b"bad contract");
}

#[test]
fn shielded_key_derivation_uses_c006_primitives_and_enforces_sizes() {
    let seed = [7u8; 32];
    let expanded = ShieldedWallet::expanded_spending_key(&seed).unwrap();
    assert_eq!(
        (expanded.ask.len(), expanded.nsk.len(), expanded.ovk.len()),
        (32, 32, 32)
    );
    let ak = ShieldedWallet::ak_from_ask(&expanded.ask).unwrap();
    let nk = ShieldedWallet::nk_from_nsk(&expanded.nsk).unwrap();
    let ivk = ShieldedWallet::incoming_viewing_key(&ViewingKeyMessage {
        ak: ak.value,
        nk: nk.value,
    })
    .unwrap();
    assert_eq!(ivk.ivk.len(), 32);
    assert!(ShieldedWallet::expanded_spending_key(&seed[..31]).is_err());
}

#[test]
fn shielded_scan_limits_are_bounded() {
    assert!(ShieldedWallet::validate_scan_range(10, 1010).is_ok());
    assert!(ShieldedWallet::validate_scan_range(10, 1011).is_err());
    assert!(ShieldedWallet::validate_scan_range(-1, 0).is_err());
    assert!(ShieldedWallet::validate_scan_range(2, 1).is_err());
}

fn rpc_context() -> (std::path::PathBuf, ApiContext) {
    let path = std::env::temp_dir().join(format!(
        "c022-broadcast-blocking-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
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
    for (name, value) in [
        ("LATEST_BLOCK_HEADER_TIMESTAMP", 100_i64),
        ("LATEST_BLOCK_HEADER_NUMBER", 7_i64),
    ] {
        manager.durable_store(StoreKind::DynamicProperties)
            .put(dynamic::key(name).unwrap(), &value.to_be_bytes()).unwrap();
    }
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
    let parameter_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../java-tron/framework/src/main/resources/params");
    let parameters = tron_shielded::load_tron_parameters(
        parameter_root.join("sapling-spend.params"),
        parameter_root.join("sapling-output.params"),
    ).unwrap();
    (path, ApiContext::new(cursors, processor, pending, parameters, CryptoEngine::Secp256k1))
}

#[tokio::test]
async fn broadcast_waits_for_blocking_permit_and_releases_it_after_timeout() {
    let (path, context) = rpc_context();
    let processor = context.processor();
    let held = processor.lock().unwrap();
    let service = RpcApiServices::with_blocking_executor(
        context,
        BlockingExecutor::new(1, Duration::from_millis(20)).unwrap(),
    );
    let transaction = tron_apis::Transaction {
        raw_data: Some(Default::default()),
        ..Default::default()
    };
    let mut request = tonic::Request::new(transaction.clone());
    request.extensions_mut().insert(PreservedRawGrpcMessage(transaction.encode_to_vec().into()));
    let status = service.broadcast_transaction(request)
        .await.unwrap_err();
    assert_eq!(status.code(), Code::DeadlineExceeded);
    drop(held);
    tokio::time::sleep(Duration::from_millis(10)).await;
    let mut request = tonic::Request::new(transaction.clone());
    request.extensions_mut().insert(PreservedRawGrpcMessage(transaction.encode_to_vec().into()));
    let response = service.broadcast_transaction(request)
        .await.unwrap().into_inner();
    assert!(!response.result);
    std::fs::remove_dir_all(path).unwrap();
}
