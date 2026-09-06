use prost::Message;
use std::time::{SystemTime, UNIX_EPOCH};
use tron_execution::{
    ActuatorRegistry, CacheConfig, ExecutionConfig, PendingLimits, PendingPool,
    StateTransactionPipeline, TransactionCache, TransactionProcessor,
};
use tron_state::{CheckpointIdentity, CursorPoint, CursorSet, SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};
use std::collections::BTreeMap;
use tron_apis::{
    ApiContext, ApiError, NodeInfoService, NodeInfoSnapshot, NodeInfoSource, WalletExtensionQuery,
    WalletQuery,
};
use tron_protocol::protocol::node_info;

#[derive(Clone)]
struct Source;
impl NodeInfoSource for Source {
    fn snapshot(&self) -> NodeInfoSnapshot {
        NodeInfoSnapshot {
            begin_sync_num: 7,
            block: "head".into(),
            solidity_block: "solid".into(),
            current_connect_count: 3,
            active_connect_count: 2,
            passive_connect_count: 1,
            total_flow: 99,
            peers: vec![node_info::PeerInfo {
                host: "127.0.0.1".into(),
                port: 18888,
                node_id: "node".into(),
                ..Default::default()
            }],
            config: node_info::ConfigNodeInfo {
                code_version: "4.8".into(),
                p2p_version: "11111".into(),
                listen_port: 18888,
                discover_enable: true,
                support_constant: true,
                ..Default::default()
            },
            machine: node_info::MachineInfo {
                thread_count: 4,
                cpu_count: 2,
                os_name: "linux".into(),
                ..Default::default()
            },
            cheat_witnesses: BTreeMap::from([("witness".into(), "double produced".into())]),
        }
    }
}

#[test]
fn node_info_preserves_every_top_level_family() {
    let info = NodeInfoService::new(Source).get_node_info();
    assert_eq!(
        (
            info.begin_sync_num,
            info.block.as_str(),
            info.solidity_block.as_str()
        ),
        (7, "head", "solid")
    );
    assert_eq!(
        (
            info.current_connect_count,
            info.active_connect_count,
            info.passive_connect_count,
            info.total_flow
        ),
        (3, 2, 1, 99)
    );
    assert_eq!(info.peer_info_list[0].port, 18888);
    assert!(info.config_node_info.unwrap().support_constant);
    assert_eq!(info.machine_info.unwrap().cpu_count, 2);
    assert_eq!(info.cheat_witness_info_map["witness"], "double produced");
}

#[test]
fn wallet_extension_matches_java_unimplemented_surface() {
    let extension = WalletExtensionQuery;
    for result in [
        extension.transactions_from_this().map(|_| ()),
        extension.transactions_from_this2().map(|_| ()),
        extension.transactions_to_this().map(|_| ()),
        extension.transactions_to_this2().map(|_| ()),
    ] {
        assert!(
            matches!(result,Err(ApiError::Unavailable(message)) if message.starts_with("UNIMPLEMENTED:"))
        );
    }
}

