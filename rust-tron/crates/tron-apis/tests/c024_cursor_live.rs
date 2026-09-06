use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use serde_json::json;
use tron_apis::{ApiContext, ApiCursor, ContextJsonRpcBackend, FilterLimits, FilterManager, TronJsonRpcConfig, TronJsonRpcMethods};
use tron_apis::jsonrpc_filters::{FilterView,RpcLog};
use tron_crypto::CryptoEngine;
use tron_execution::{ActuatorRegistry, CacheConfig, ExecutionConfig, PendingLimits, PendingPool, StateTransactionPipeline, TransactionCache, TransactionProcessor};
use tron_protocol::protocol::{block_header, Block, BlockHeader};
use tron_state::{dynamic, CheckpointIdentity, CursorPoint, CursorSet, SessionManager, StateStore, StoreKind};
use tron_primitives::Hash32;
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

fn cursor_context() -> (std::path::PathBuf, ApiContext) {
    let path = std::env::temp_dir().join(format!(
        "c024-cursor-live-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    let manager = SessionManager::new(StateStore::new(StorageManager::new(OpenRequirements {
        identity: StorageIdentity { network: "c024-cursor-live".into(), genesis: "00".into() },
        schema_version: 1,
        backend: "rustlog".into(),
        backend_format: "rustlog-v1".into(),
        supported_features: vec!["rustlog-v1".into()],
    }).open_store(&path).unwrap()));
    let checkpoint = |number: i64, solid: i64, marker: u8| {
        let mut session = manager.build_session_enabled().unwrap();
        for block_number in [number, solid] {
            let id = [block_number as u8; 32];
            let block = Block { transactions: Vec::new(), block_header: Some(BlockHeader { raw_data: Some(block_header::Raw { number: block_number, ..Default::default() }), witness_signature: Vec::new() }) };
            session.store(StoreKind::BlockIndex).put(&block_number.to_be_bytes(), &id).unwrap();
            session.store(StoreKind::Block).put(&id, &block.encode_to_vec()).unwrap();
        }
        session.store(StoreKind::DynamicProperties).put(dynamic::key("LATEST_BLOCK_HEADER_NUMBER").unwrap(), &number.to_be_bytes()).unwrap();
        session.store(StoreKind::DynamicProperties).put(dynamic::key("LATEST_SOLIDIFIED_BLOCK_NUM").unwrap(), &solid.to_be_bytes()).unwrap();
        session.commit().unwrap();
        let point = CursorPoint { block: number as u64, identity: CheckpointIdentity::new([marker; 32]) };
        manager.record_checkpoint(point).unwrap();
        point
    };
    let pbft = checkpoint(7, 5, 7);
    let solidity = checkpoint(11, 9, 11);
    let head = checkpoint(15, 11, 15);
    let cursors = CursorSet::new(&manager, head, Some(solidity), Some(pbft), 2).unwrap();
    let processor = TransactionProcessor {
        sessions: manager.clone(),
        cache: TransactionCache::new(CacheConfig::default()).unwrap(),
        pipeline: StateTransactionPipeline::new(Default::default(), ActuatorRegistry::empty(), ExecutionConfig::default()).unwrap(),
    };
    let pending = PendingPool::new(manager, PendingLimits::default()).unwrap();
    let params = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");
    let parameters = tron_shielded::load_tron_parameters(params.join("sapling-spend.params"), params.join("sapling-output.params")).unwrap();
    (path, ApiContext::new(cursors, processor, pending, parameters, CryptoEngine::Secp256k1))
}
fn rpc_log(block:u64)->RpcLog{RpcLog{address:vec![2;21],topics:vec![],data:vec![],block_hash:Hash32::from_array([block as u8;32]),block_number:block,transaction_hash:Hash32::from_array([block as u8+32;32]),transaction_index:0,log_index:0,removed:false}}


#[test]
fn nonzero_divergent_head_solidity_pbft_numbers_are_read_live() {
    let (path, context) = cursor_context();
    let filters = FilterManager::shared(FilterLimits::default());
    for (cursor, expected_latest, expected_finalized) in [
        (ApiCursor::Head, "0xf", "0xb"),
        (ApiCursor::Solidity, "0xb", "0x9"),
        (ApiCursor::Pbft, "0x7", "0x5"),
    ] {
        let rpc = TronJsonRpcMethods::new(
            TronJsonRpcConfig::default(),
            ContextJsonRpcBackend::new(context.clone(), cursor, filters.clone()),
        );
        assert_eq!(rpc.execute("eth_blockNumber", &json!([])).unwrap(), expected_latest);
        assert_eq!(rpc.execute("eth_getBlockByNumber", &json!(["latest", false])).unwrap()["number"], expected_latest);
        assert_eq!(rpc.execute("eth_getBlockByNumber", &json!(["finalized", false])).unwrap()["number"], expected_finalized);
    }
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn log_filter_bounds_use_live_head_and_java_validation_timing() {
    let (path, context) = cursor_context();
    let filters = FilterManager::shared(FilterLimits::default());
    filters.publish_logs(FilterView::Full, vec![rpc_log(4),rpc_log(9),rpc_log(11),rpc_log(14),rpc_log(15)]);
    let backend=ContextJsonRpcBackend::new(context.clone(),ApiCursor::Head,filters.clone());
    let tracking=backend.normalize_log_filter(&json!({"fromBlock":"0x1","toBlock":"latest"})).unwrap();
    assert_eq!((tracking.from_block,tracking.to_block),(Some(1),Some(u64::MAX)));
    let rpc=TronJsonRpcMethods::new(TronJsonRpcConfig::default(),backend);
    let blocks=|filter:serde_json::Value|rpc.execute("eth_getLogs",&json!([filter])).unwrap().as_array().unwrap().iter().map(|log|log["blockNumber"].as_str().unwrap().to_owned()).collect::<Vec<_>>();
    assert_eq!(blocks(json!({})),vec!["0xf"]);
    assert_eq!(blocks(json!({"fromBlock":"0x9"})),vec!["0x9","0xb","0xe","0xf"]);
    assert_eq!(blocks(json!({"toBlock":"0xb"})),vec!["0xb"]);
    assert_eq!(blocks(json!({"toBlock":"latest"})),vec!["0xf"]);
    assert_eq!(blocks(json!({"fromBlock":"0x9","toBlock":"finalized"})),vec!["0x9","0xb"]);
    assert_eq!(rpc.execute("eth_getLogs",&json!([{"fromBlock":"0xc","toBlock":"0xb"}])).unwrap_err().code,-32602);
    assert_eq!(rpc.execute("eth_getLogs",&json!([{"fromBlock":"pending"}])).unwrap_err().message,"pending is not supported");
    assert_eq!(rpc.execute("eth_getLogs",&json!([{"toBlock":"safe"}])).unwrap_err().message,"safe is not supported");
    assert_eq!(rpc.execute("eth_getLogs",&json!([{"blockHash":format!("0x{}","01".repeat(32)),"fromBlock":"latest"}])).unwrap_err().code,-32602);
    for filter in [json!({"fromBlock":"finalized"}), json!({"toBlock":"finalized"})] {
        let error = rpc.execute("eth_newFilter", &json!([filter])).unwrap_err();
        assert_eq!(error.code, -32602);
        assert_eq!(error.message, "invalid block range params");
    }
    let id=rpc.execute("eth_newFilter",&json!([{}])).unwrap().as_str().unwrap().to_owned();
    filters.publish_logs(FilterView::Full,vec![rpc_log(16)]);
    assert_eq!(rpc.execute("eth_getFilterChanges",&json!([id])).unwrap().as_array().unwrap().iter().map(|log|log["blockNumber"].as_str().unwrap()).collect::<Vec<_>>(),vec!["0x10"]);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn new_filter_defers_range_history_validation_but_filter_logs_revalidates() {
    let (path, context) = cursor_context();
    let filters=FilterManager::shared(FilterLimits{max_block_range:5,..Default::default()});
    let rpc=TronJsonRpcMethods::new(TronJsonRpcConfig::default(),ContextJsonRpcBackend::new(context,ApiCursor::Head,filters));
    let id=rpc.execute("eth_newFilter",&json!([{"fromBlock":"earliest"}])).unwrap();
    assert_eq!(rpc.execute("eth_getFilterLogs",&json!([id])).unwrap_err().code,-32005);
    assert_eq!(rpc.execute("eth_getLogs",&json!([{"fromBlock":"earliest"}])).unwrap_err().code,-32005);
    std::fs::remove_dir_all(path).unwrap();
}
