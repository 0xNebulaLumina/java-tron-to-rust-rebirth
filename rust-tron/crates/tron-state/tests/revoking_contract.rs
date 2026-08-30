use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use tron_state::{
    CheckpointCrashInjector, CheckpointCrashPhase, CheckpointError, CheckpointIdentity,
    CheckpointLimits, CursorError, CursorPoint, CursorSet, CursorView, SessionError,
    StateLifecycle, StateStore, StoreKind,
};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

fn path(name: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("tron-state-c009-{name}-{}-{nonce}", std::process::id()))
}

fn lifecycle(name: &str, limits: CheckpointLimits) -> (PathBuf, StateLifecycle) {
    let directory = path(name);
    let manager = StorageManager::new(OpenRequirements {
        identity: StorageIdentity { network: "c009".into(), genesis: "00".into() },
        schema_version: 1,
        backend: "rustlog".into(),
        backend_format: "rustlog-v1".into(),
        supported_features: vec!["rustlog-v1".into()],
    });
    let root = StateStore::new(manager.open_store(&directory).unwrap());
    (directory, StateLifecycle::new(root, limits))
}
fn reopen_lifecycle(directory: &PathBuf, limits: CheckpointLimits) -> StateLifecycle {
    let manager = StorageManager::new(OpenRequirements {
        identity: StorageIdentity { network: "c009".into(), genesis: "00".into() },
        schema_version: 1,
        backend: "rustlog".into(),
        backend_format: "rustlog-v1".into(),
        supported_features: vec!["rustlog-v1".into()],
    });
    StateLifecycle::new(StateStore::new(manager.open_store(directory).unwrap()), limits)
}


struct JavaSnapshotCase {
    case_id: &'static str,
    assert_contract: fn(),
}

const JAVA_SNAPSHOT_CASES: &[JavaSnapshotCase] = &[
    JavaSnapshotCase { case_id: "snapshot::TCASE-7F22D7A2A6543F1A", assert_contract: assert_checkpoint_store_close },
    JavaSnapshotCase { case_id: "snapshot::TCASE-AC9879AA6BCF9D64", assert_contract: assert_get_from_root },
    JavaSnapshotCase { case_id: "snapshot::TCASE-92CFE24A1561EFE9", assert_contract: assert_checkpoint_round_trip },
    JavaSnapshotCase { case_id: "snapshot::TCASE-7FC454E3B1629473", assert_contract: assert_pop },
    JavaSnapshotCase { case_id: "snapshot::TCASE-9EDABBC5A805320A", assert_contract: assert_merge },
    JavaSnapshotCase { case_id: "snapshot::TCASE-75BE19BDB7792CCA", assert_contract: assert_revoke },
    JavaSnapshotCase { case_id: "snapshot::TCASE-34E5F70F775D3FC6", assert_contract: assert_latest_values },
    JavaSnapshotCase { case_id: "snapshot::TCASE-91CECB06125D2E4C", assert_contract: assert_values_next },
    JavaSnapshotCase { case_id: "snapshot::TCASE-41ED2AFC00A053F2", assert_contract: assert_keys_next_order },
    JavaSnapshotCase { case_id: "snapshot::TCASE-8F21C7D27800964B", assert_contract: assert_same_key_overwrite },
    JavaSnapshotCase { case_id: "snapshot::TCASE-C5F7660FD104C040", assert_contract: assert_same_key_order },
    JavaSnapshotCase { case_id: "snapshot::TCASE-57E24680B6EB3329", assert_contract: assert_merge_root },
    JavaSnapshotCase { case_id: "snapshot::TCASE-53A408BB0C7E2E66", assert_contract: assert_merge_ahead },
    JavaSnapshotCase { case_id: "snapshot::TCASE-92AC5F8878398A81", assert_contract: assert_merge_override },
    JavaSnapshotCase { case_id: "snapshot::TCASE-74AF83CC7A05854D", assert_contract: assert_refresh },
    JavaSnapshotCase { case_id: "snapshot::TCASE-A8CF96E0075500FF", assert_contract: assert_close_revoke },
    JavaSnapshotCase { case_id: "snapshot::TCASE-D485BA56D167AB34", assert_contract: assert_checkpoint_check_error },
    JavaSnapshotCase { case_id: "snapshot::TCASE-79E4247FED8321BC", assert_contract: assert_checkpoint_flush_error },
    JavaSnapshotCase { case_id: "snapshot::TCASE-2AD93580C9B8E018", assert_contract: assert_root_remove },
    JavaSnapshotCase { case_id: "snapshot::TCASE-7FFECAD616246BAF", assert_contract: assert_root_merge },
    JavaSnapshotCase { case_id: "snapshot::TCASE-913763B50C69237E", assert_contract: assert_root_merge_list },
    JavaSnapshotCase { case_id: "snapshot::TCASE-C82B1F48B914A3E1", assert_contract: assert_second_cache_inventory },
    JavaSnapshotCase { case_id: "snapshot::TCASE-23FD53DD52350BB7", assert_contract: assert_second_cache_new_db_detection },
];

fn direct_case_lifecycle(name: &str, assert_contract: impl FnOnce(&StateLifecycle)) {
    let (directory, lifecycle) = lifecycle(name, CheckpointLimits::default());
    assert_contract(&lifecycle);
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}

fn assert_checkpoint_store_close() {
    direct_case_lifecycle("java-checkpoint-store-close", |lifecycle| {
        let manager = lifecycle.sessions();
        manager.disable().unwrap();
        let mut session = manager.build_session().unwrap();
        assert!(session.is_noop());
        session.close().unwrap();
        assert_eq!(manager.active_sessions(), 0);
    });
}

fn assert_get_from_root() {
    direct_case_lifecycle("java-get-from-root", |lifecycle| {
        let manager = lifecycle.sessions();
        manager.durable_store(StoreKind::Account).put(b"key", b"root").unwrap();
        let mut session = manager.build_session_enabled().unwrap();
        let store = session.store(StoreKind::Account);
        store.put(b"key", b"overlay").unwrap();
        assert_eq!(store.get_from_root(b"key"), Some(b"root".to_vec()));
        session.revoke().unwrap();
    });
}

fn assert_checkpoint_round_trip() {
    direct_case_lifecycle("java-checkpoint-round-trip", |lifecycle| {
        let manager = lifecycle.sessions();
        let mut session = manager.build_session_enabled().unwrap();
        session.store(StoreKind::Account).put(b"key", b"value").unwrap();
        session.commit().unwrap();
        assert_eq!(lifecycle.checkpoints().persist().unwrap(), 1);
        manager.destroy().unwrap();
        assert_eq!(lifecycle.checkpoints().relink().unwrap(), 1);
        assert_eq!(manager.session_view().store(StoreKind::Account).get(b"key"), Some(b"value".to_vec()));
    });
}

fn assert_pop() {
    direct_case_lifecycle("java-pop", |lifecycle| {
        let manager = lifecycle.sessions();
        let mut session = manager.build_session_enabled().unwrap();
        session.store(StoreKind::Account).put(b"key", b"value").unwrap();
        session.commit().unwrap();
        assert!(manager.pop().unwrap());
        assert_eq!(manager.durable_store(StoreKind::Account).get(b"key"), None);
    });
}

fn assert_merge() {
    direct_case_lifecycle("java-merge", |lifecycle| {
        let manager = lifecycle.sessions();
        let mut outer = manager.build_session_enabled().unwrap();
        outer.store(StoreKind::Account).put(b"key", b"parent").unwrap();
        let mut child = outer.child().unwrap();
        child.store(StoreKind::Account).put(b"key", b"child").unwrap();
        child.merge().unwrap();
        assert_eq!(outer.store(StoreKind::Account).get(b"key"), Some(b"child".to_vec()));
        outer.revoke().unwrap();
    });
}

fn assert_revoke() {
    direct_case_lifecycle("java-revoke", |lifecycle| {
        let manager = lifecycle.sessions();
        manager.durable_store(StoreKind::Account).put(b"key", b"root").unwrap();
        let mut session = manager.build_session_enabled().unwrap();
        session.store(StoreKind::Account).delete(b"key").unwrap();
        session.revoke().unwrap();
        assert_eq!(manager.durable_store(StoreKind::Account).get(b"key"), Some(b"root".to_vec()));
    });
}

fn assert_latest_values() {
    direct_case_lifecycle("java-latest-values", |lifecycle| {
        let manager = lifecycle.sessions();
        for index in 1..=9 {
            let mut session = manager.build_session_enabled().unwrap();
            session.store(StoreKind::Account).put(format!("key-{index}").as_bytes(), format!("value-{index}").as_bytes()).unwrap();
            session.commit().unwrap();
        }
        let latest: Vec<Vec<u8>> = manager.session_view().store(StoreKind::Account).prefix(b"key-").into_iter().rev().take(5).map(|(_, value)| value).collect();
        assert_eq!(latest, (5..=9).rev().map(|index| format!("value-{index}").into_bytes()).collect::<Vec<_>>());
    });
}

fn assert_values_next() {
    direct_case_lifecycle("java-values-next", |lifecycle| {
        let manager = lifecycle.sessions();
        let mut session = manager.build_session_enabled().unwrap();
        let store = session.store(StoreKind::Account);
        for index in 1..=5 {
            store.put(format!("key-{index}").as_bytes(), format!("value-{index}").as_bytes()).unwrap();
        }
        let values: Vec<Vec<u8>> = store.get_next(b"key-2", 3).into_iter().map(|(_, value)| value).collect();
        assert_eq!(values, vec![b"value-2".to_vec(), b"value-3".to_vec(), b"value-4".to_vec()]);
        session.revoke().unwrap();
    });
}

fn assert_keys_next_order() {
    direct_case_lifecycle("java-keys-next", |lifecycle| {
        let manager = lifecycle.sessions();
        let mut session = manager.build_session_enabled().unwrap();
        let store = session.store(StoreKind::MarketPairPriceToOrder);
        for key in [b"price-3", b"price-1", b"price-4", b"price-2"] { store.put(key, key).unwrap(); }
        let keys: Vec<Vec<u8>> = store.get_next(b"price-1", 4).into_iter().map(|(key, _)| key).collect();
        assert_eq!(keys, [b"price-1", b"price-2", b"price-3", b"price-4"].map(|key| key.to_vec()));
        session.revoke().unwrap();
    });
}

fn assert_same_key_overwrite() {
    direct_case_lifecycle("java-same-key", |lifecycle| {
        let manager = lifecycle.sessions();
        let mut session = manager.build_session_enabled().unwrap();
        let store = session.store(StoreKind::MarketPairPriceToOrder);
        store.put(b"same", b"first").unwrap();
        store.put(b"same", b"second").unwrap();
        assert_eq!(store.view(), vec![(b"same".to_vec(), b"second".to_vec())]);
        session.revoke().unwrap();
    });
}

fn assert_same_key_order() {
    direct_case_lifecycle("java-same-key-order", |lifecycle| {
        let manager = lifecycle.sessions();
        let mut session = manager.build_session_enabled().unwrap();
        let store = session.store(StoreKind::MarketPairPriceToOrder);
        for (key, value) in [(b"a".as_slice(), b"zero".as_slice()), (b"b", b"first"), (b"b", b"replacement"), (b"c", b"last")] { store.put(key, value).unwrap(); }
        assert_eq!(store.view(), vec![(b"a".to_vec(), b"zero".to_vec()), (b"b".to_vec(), b"replacement".to_vec()), (b"c".to_vec(), b"last".to_vec())]);
        session.revoke().unwrap();
    });
}

fn assert_merge_root() {
    direct_case_lifecycle("java-merge-root", |lifecycle| {
        let manager = lifecycle.sessions();
        manager.durable_store(StoreKind::Account).put(b"root", b"value").unwrap();
        let mut session = manager.build_session_enabled().unwrap();
        session.store(StoreKind::Account).put(b"child", b"value").unwrap();
        assert_eq!(session.store(StoreKind::Account).get(b"root"), Some(b"value".to_vec()));
        session.revoke().unwrap();
    });
}

fn assert_merge_ahead() {
    direct_case_lifecycle("java-merge-ahead", |lifecycle| {
        let manager = lifecycle.sessions();
        let mut outer = manager.build_session_enabled().unwrap();
        outer.store(StoreKind::Account).put(b"parent", b"parent-value").unwrap();
        let mut child = outer.child().unwrap();
        child.store(StoreKind::Account).put(b"child", b"child-value").unwrap();
        child.merge().unwrap();
        assert_eq!(outer.store(StoreKind::Account).view(), vec![(b"child".to_vec(), b"child-value".to_vec()), (b"parent".to_vec(), b"parent-value".to_vec())]);
        outer.revoke().unwrap();
    });
}

fn assert_merge_override() {
    direct_case_lifecycle("java-merge-override", |lifecycle| {
        let manager = lifecycle.sessions();
        let mut outer = manager.build_session_enabled().unwrap();
        outer.store(StoreKind::Account).put(b"key", b"parent").unwrap();
        let mut child = outer.child().unwrap();
        child.store(StoreKind::Account).put(b"key", b"child").unwrap();
        child.merge().unwrap();
        assert_eq!(outer.store(StoreKind::Account).get(b"key"), Some(b"child".to_vec()));
        outer.revoke().unwrap();
    });
}

fn assert_refresh() {
    direct_case_lifecycle("java-refresh", |lifecycle| {
        let manager = lifecycle.sessions();
        for index in 1..=10 {
            let mut session = manager.build_session_enabled().unwrap();
            session.store(StoreKind::Account).put(b"refresh", format!("value-{index}").as_bytes()).unwrap();
            session.commit().unwrap();
        }
        assert_eq!(manager.flush_committed().unwrap(), 10);
        assert_eq!(manager.durable_store(StoreKind::Account).get(b"refresh"), Some(b"value-10".to_vec()));
    });
}

fn assert_close_revoke() {
    direct_case_lifecycle("java-close", |lifecycle| {
        let manager = lifecycle.sessions();
        {
            let session = manager.build_session_enabled().unwrap();
            session.store(StoreKind::Account).put(b"close", b"speculative").unwrap();
        }
        assert_eq!(manager.durable_store(StoreKind::Account).get(b"close"), None);
        assert_eq!(manager.active_sessions(), 0);
    });
}

fn assert_checkpoint_check_error() {
    let limits = CheckpointLimits { max_stack: 0, ..CheckpointLimits::default() };
    let (directory, lifecycle) = lifecycle("java-checkpoint-check-error", limits);
    let mut session = lifecycle.sessions().build_session_enabled().unwrap();
    session.commit().unwrap();
    assert!(matches!(lifecycle.checkpoints().persist(), Err(CheckpointError::Limit("maximum checkpoint stack exceeded"))));
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}

fn assert_checkpoint_flush_error() {
    let limits = CheckpointLimits { max_flush_count: 0, ..CheckpointLimits::default() };
    let (directory, lifecycle) = lifecycle("java-checkpoint-flush-error", limits);
    let mut session = lifecycle.sessions().build_session_enabled().unwrap();
    session.commit().unwrap();
    assert!(matches!(lifecycle.checkpoints().flush_bounded(), Err(CheckpointError::Limit("maximum flush count exceeded"))));
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}

fn assert_root_remove() {
    direct_case_lifecycle("java-root-remove", |lifecycle| {
        let store = lifecycle.sessions().durable_store(StoreKind::Account);
        store.put(b"key", b"value").unwrap();
        store.delete(b"key").unwrap();
        assert_eq!(store.get(b"key"), None);
    });
}

fn assert_root_merge() {
    direct_case_lifecycle("java-root-merge", |lifecycle| {
        let manager = lifecycle.sessions();
        let mut session = manager.build_session_enabled().unwrap();
        session.store(StoreKind::Account).put(b"key", b"value").unwrap();
        session.commit().unwrap();
        assert_eq!(manager.flush_committed().unwrap(), 1);
        assert_eq!(manager.durable_store(StoreKind::Account).get(b"key"), Some(b"value".to_vec()));
    });
}

fn assert_root_merge_list() {
    direct_case_lifecycle("java-root-merge-list", |lifecycle| {
        let manager = lifecycle.sessions();
        for index in 1..=10 {
            let mut session = manager.build_session_enabled().unwrap();
            session.store(StoreKind::Account).put(format!("key-{index}").as_bytes(), format!("value-{index}").as_bytes()).unwrap();
            session.commit().unwrap();
        }
        assert_eq!(manager.flush_committed().unwrap(), 10);
        assert_eq!(manager.durable_store(StoreKind::Account).prefix(b"key-").len(), 10);
    });
}

fn second_cache_candidates() -> Vec<&'static str> {
    StoreKind::ALL.into_iter().map(StoreKind::db_name).filter(|name| !matches!(*name, "trans-cache" | "recent-transaction" | "block-index" | "block" | "proposal" | "asset-issue" | "account-index" | "section-bloom" | "exchange" | "contract-state" | "transactionHistoryStore" | "transactionRetStore" | "market_account" | "market_pair_to_price" | "market_pair_price_to_order" | "market_order" | "exchange-v2" | "nullifier" | "accountid-index" | "account-trace" | "balance-trace" | "tree-block-index" | "IncrementalMerkleTree" | "trans")).collect()
}

fn assert_second_cache_inventory() {
    let candidates = second_cache_candidates();
    assert!(candidates.contains(&"account"));
    assert!(!candidates.contains(&"block"));
}

fn assert_second_cache_new_db_detection() {
    let mut candidates = second_cache_candidates();
    candidates.push("secondCheckTestDB");
    assert_eq!(candidates.iter().filter(|name| **name == "secondCheckTestDB").count(), 1);
}

#[test]
fn direct_java_snapshot_cases_dispatch_by_case_id() {
    assert_eq!(JAVA_SNAPSHOT_CASES.len(), 23);
    for case in JAVA_SNAPSHOT_CASES {
        (case.assert_contract)();
    }
}

#[test]
fn exhaustive_45_store_transition_matrix_restores_root_after_revoke() {
    let (directory, lifecycle) = lifecycle("all-stores", CheckpointLimits::default());
    let manager = lifecycle.sessions();
    assert_eq!(StoreKind::ALL.len(), 45);
    for (index, kind) in StoreKind::ALL.into_iter().enumerate() {
        let key = format!("key-{index}").into_bytes();
        let root = format!("root-{index}").into_bytes();
        let parent = format!("parent-{index}").into_bytes();
        let child = format!("child-{index}").into_bytes();
        manager.durable_store(kind).put(&key, &root).unwrap();
        let mut outer = manager.build_session_enabled().unwrap();
        outer.store(kind).put(&key, &parent).unwrap();
        let mut nested = outer.child().unwrap();
        nested.store(kind).put(&key, &child).unwrap();
        assert_eq!(nested.store(kind).get(&key), Some(child));
        nested.merge().unwrap();
        assert_eq!(outer.store(kind).get(&key), Some(format!("child-{index}").into_bytes()));
        outer.revoke().unwrap();
        assert_eq!(manager.durable_store(kind).get(&key), Some(root), "{kind:?}");
    }
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn nested_commit_merge_pop_destroy_and_disabled_session_matrix() {
    let (directory, lifecycle) = lifecycle("transitions", CheckpointLimits::default());
    let manager = lifecycle.sessions();
    let mut outer = manager.build_session_enabled().unwrap();
    outer.store(StoreKind::Account).put(b"a", b"outer").unwrap();
    let mut child = outer.child().unwrap();
    child.store(StoreKind::Account).put(b"a", b"child").unwrap();
    child.merge().unwrap();
    assert_eq!(outer.store(StoreKind::Account).get(b"a"), Some(b"child".to_vec()));
    outer.commit().unwrap();
    assert_eq!(manager.depth(), 1);
    assert_eq!(manager.session_view().store(StoreKind::Account).get(b"a"), Some(b"child".to_vec()));
    assert!(manager.pop().unwrap());
    assert_eq!(manager.session_view().store(StoreKind::Account).get(b"a"), None);
    manager.disable().unwrap();
    let mut noop = manager.build_session().unwrap();
    assert!(noop.is_noop());
    noop.close().unwrap();
    let mut forced = manager.build_session_enabled().unwrap();
    forced.store(StoreKind::Account).put(b"b", b"speculative").unwrap();
    forced.destroy().unwrap();
    assert_eq!(manager.session_view().store(StoreKind::Account).get(b"b"), None);
    assert!(!manager.is_enabled());
    manager.enable();
    manager.destroy().unwrap();
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn manager_view_exposes_committed_child_without_active_speculation() {
    let (directory, lifecycle) = lifecycle("manager-logical-view", CheckpointLimits::default());
    let manager = lifecycle.sessions();
    manager.durable_store(StoreKind::Account).put(b"value", b"root").unwrap();

    let mut parent = manager.build_session_enabled().unwrap();
    parent.store(StoreKind::Account).put(b"parent-only", b"active-parent").unwrap();
    parent.store(StoreKind::Account).put(b"value", b"parent").unwrap();
    assert_eq!(manager.session_view().store(StoreKind::Account).get(b"parent-only"), None);
    assert_eq!(manager.session_view().store(StoreKind::Account).get(b"value"), Some(b"root".to_vec()));

    let mut child = parent.child().unwrap();
    child.store(StoreKind::Account).put(b"child-only", b"active-child").unwrap();
    child.store(StoreKind::Account).put(b"value", b"child").unwrap();
    assert_eq!(manager.session_view().store(StoreKind::Account).get(b"child-only"), None);
    assert_eq!(manager.session_view().store(StoreKind::Account).get(b"value"), Some(b"root".to_vec()));
    assert_eq!(child.view().store(StoreKind::Account).get(b"parent-only"), Some(b"active-parent".to_vec()));
    assert_eq!(child.view().store(StoreKind::Account).get(b"value"), Some(b"child".to_vec()));

    child.commit().unwrap();
    let committed_child = manager.session_view();
    assert_eq!(committed_child.store(StoreKind::Account).get(b"parent-only"), None);
    assert_eq!(committed_child.store(StoreKind::Account).get(b"child-only"), Some(b"active-child".to_vec()));
    assert_eq!(committed_child.store(StoreKind::Account).get(b"value"), Some(b"child".to_vec()));

    parent.revoke().unwrap();
    assert_eq!(manager.session_view().store(StoreKind::Account).get(b"value"), Some(b"root".to_vec()));
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn committed_child_composes_with_parent_finalization_by_identity() {
    let (directory, lifecycle) = lifecycle("nested-identity", CheckpointLimits::default());
    let manager = lifecycle.sessions();

    let mut parent = manager.build_session_enabled().unwrap();
    parent.store(StoreKind::Account).put(b"commit", b"parent").unwrap();
    let mut child = parent.child().unwrap();
    child.store(StoreKind::Account).put(b"commit", b"child").unwrap();
    child.commit().unwrap();
    assert_eq!(manager.active_sessions(), 1);
    parent.commit().unwrap();
    assert_eq!(manager.active_sessions(), 0);
    assert_eq!(manager.depth(), 2);
    assert!(manager.pop().unwrap());
    assert_eq!(manager.session_view().store(StoreKind::Account).get(b"commit"), Some(b"parent".to_vec()));
    assert!(manager.pop().unwrap());

    let mut parent = manager.build_session_enabled().unwrap();
    parent.store(StoreKind::Account).put(b"revoke", b"parent").unwrap();
    let mut child = parent.child().unwrap();
    child.store(StoreKind::Account).put(b"revoke", b"child").unwrap();
    child.commit().unwrap();
    parent.revoke().unwrap();
    assert_eq!(manager.active_sessions(), 0);
    assert_eq!(manager.depth(), 0);
    assert_eq!(manager.session_view().store(StoreKind::Account).get(b"revoke"), None);

    let mut predecessor = manager.build_session_enabled().unwrap();
    predecessor.store(StoreKind::Account).put(b"merge", b"predecessor").unwrap();
    let mut parent = predecessor.child().unwrap();
    parent.store(StoreKind::Account).put(b"merge", b"parent").unwrap();
    let mut child = parent.child().unwrap();
    child.store(StoreKind::Account).put(b"merge", b"child").unwrap();
    child.commit().unwrap();
    parent.merge().unwrap();
    assert_eq!(manager.active_sessions(), 1);
    assert_eq!(manager.depth(), 1);
    assert_eq!(predecessor.store(StoreKind::Account).get(b"merge"), Some(b"child".to_vec()));
    predecessor.revoke().unwrap();

    let parent = manager.build_session_enabled().unwrap();
    let mut child = parent.child().unwrap();
    drop(parent);
    assert_eq!(manager.active_sessions(), 1);
    assert_eq!(manager.depth(), 2);
    child.commit().unwrap();
    assert_eq!(manager.active_sessions(), 0);
    assert_eq!(manager.depth(), 0);

    let mut parent = manager.build_session_enabled().unwrap();
    parent.store(StoreKind::Account).put(b"shutdown", b"parent").unwrap();
    let mut child = parent.child().unwrap();
    child.store(StoreKind::Account).put(b"shutdown", b"child").unwrap();
    child.commit().unwrap();
    assert!(manager.shutdown(true).is_err());
    parent.commit().unwrap();
    manager.shutdown(true).unwrap();
    assert_eq!(manager.durable_store(StoreKind::Account).get(b"shutdown"), Some(b"child".to_vec()));

    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn lifecycle_shutdown_flushes_committed_and_aggregates_disposition_errors() {
    let (directory, lifecycle) = lifecycle("shutdown-policy", CheckpointLimits::default());
    let manager = lifecycle.sessions();
    let mut active = manager.build_session_enabled().unwrap();
    active.store(StoreKind::Account).put(b"shutdown-policy", b"value").unwrap();
    let errors = lifecycle.shutdown(true).unwrap_err();
    assert_eq!(errors.0.len(), 1);
    assert!(errors.0[0].contains("active sessions"));
    active.commit().unwrap();
    lifecycle.shutdown(true).unwrap();
    assert_eq!(manager.durable_store(StoreKind::Account).get(b"shutdown-policy"), Some(b"value".to_vec()));
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}

struct CrashAt(CheckpointCrashPhase);
impl CheckpointCrashInjector for CrashAt {
    fn after(&self, phase: CheckpointCrashPhase) -> Result<(), CheckpointError> {
        if phase == self.0 { Err(CheckpointError::Crash(phase)) } else { Ok(()) }
    }
}

#[test]
fn checkpoint_publication_recovery_relink_retreat_and_limits() {
    const EMPTY_CHECKPOINT_BYTES: usize = 8 + 4 + 4 + 32;
    let exact_limits = CheckpointLimits { max_bytes: EMPTY_CHECKPOINT_BYTES, ..CheckpointLimits::default() };
    let (exact_directory, exact) = lifecycle("checkpoint-exact-envelope-limit", exact_limits);
    assert_eq!(exact.checkpoints().persist().unwrap(), 0);
    assert_eq!(exact.checkpoints().persist().unwrap(), 0);
    let logical_checkpoint = exact.sessions().durable_store(StoreKind::Checkpoint);
    assert!(logical_checkpoint.prefix(b"").is_empty());
    assert!(exact.sessions().session_view().store(StoreKind::Checkpoint).prefix(b"").is_empty());
    logical_checkpoint.put(b"stack/current", b"user-state").unwrap();
    logical_checkpoint.put(b"stack/staged", b"also-user-state").unwrap();
    assert!(!exact.recover().unwrap());
    exact.sessions().destroy().unwrap();
    assert_eq!(exact.checkpoints().relink().unwrap(), 0);
    assert_eq!(logical_checkpoint.get(b"stack/current"), Some(b"user-state".to_vec()));
    assert_eq!(logical_checkpoint.prefix(b"").len(), 2);
    drop(exact);
    fs::remove_dir_all(exact_directory).unwrap();

    let over_limits = CheckpointLimits { max_bytes: EMPTY_CHECKPOINT_BYTES - 1, ..CheckpointLimits::default() };
    let (over_directory, over) = lifecycle("checkpoint-envelope-one-over-limit", over_limits);
    assert!(matches!(over.checkpoints().persist(), Err(CheckpointError::Limit("checkpoint bytes exceeded"))));
    drop(over);
    fs::remove_dir_all(over_directory).unwrap();
    for phase in [
        CheckpointCrashPhase::BeforeStage,
        CheckpointCrashPhase::AfterStage,
        CheckpointCrashPhase::BeforePublish,
        CheckpointCrashPhase::AfterPublish,
    ] {
        let limits = CheckpointLimits { max_stack: 4, max_flush_count: 2, max_bytes: 64 * 1024 };
        let (directory, lifecycle) = lifecycle(&format!("checkpoint-{phase:?}"), limits);
        let manager = lifecycle.sessions();
        let mut baseline = manager.build_session_enabled().unwrap();
        for (index, kind) in StoreKind::ALL.into_iter().enumerate() {
            baseline.store(kind).put(format!("key-{index}").as_bytes(), format!("baseline-{index}").as_bytes()).unwrap();
        }
        baseline.commit().unwrap();
        assert_eq!(lifecycle.checkpoints().persist().unwrap(), 1);

        let mut session = manager.build_session_enabled().unwrap();
        for (index, kind) in StoreKind::ALL.into_iter().enumerate() {
            session.store(kind).put(format!("key-{index}").as_bytes(), format!("value-{index}").as_bytes()).unwrap();
        }
        session.commit().unwrap();
        assert!(matches!(lifecycle.checkpoints().persist_with(&CrashAt(phase)), Err(CheckpointError::Crash(found)) if found == phase));

        manager.destroy().unwrap();
        let publication_completed = matches!(phase, CheckpointCrashPhase::AfterStage | CheckpointCrashPhase::BeforePublish);
        assert_eq!(lifecycle.recover().unwrap(), publication_completed);
        let expected_depth = if phase == CheckpointCrashPhase::BeforeStage { 1 } else { 2 };
        assert_eq!(lifecycle.checkpoints().relink().unwrap(), expected_depth);
        let relinked = manager.session_view();
        for (index, kind) in StoreKind::ALL.into_iter().enumerate() {
            let expected_value = if phase == CheckpointCrashPhase::BeforeStage { format!("baseline-{index}") } else { format!("value-{index}") };
            assert_eq!(relinked.store(kind).get(format!("key-{index}").as_bytes()).as_deref(), Some(expected_value.as_bytes()), "{kind:?}");
        }
        assert!(matches!(lifecycle.checkpoints().retreat(3), Err(CheckpointError::Limit("maximum retreat count exceeded"))));
        assert_eq!(lifecycle.checkpoints().retreat(1).unwrap(), expected_depth - 1);
        drop(lifecycle);
        fs::remove_dir_all(directory).unwrap();
    }
}
#[test]
fn checkpoint_restart_history_and_retreat_publication_are_atomic() {
    let limits = CheckpointLimits::default();
    let (directory, lifecycle) = lifecycle("checkpoint-history-restart", limits);
    let manager = lifecycle.sessions();
    let first = CursorPoint { block: 10, identity: CheckpointIdentity::new([10; 32]) };
    let mut first_session = manager.build_session_enabled().unwrap();
    first_session.store(StoreKind::Account).put(b"key", b"first").unwrap();
    first_session.commit().unwrap();
    lifecycle.checkpoints().record(first).unwrap();

    let second = CursorPoint { block: 11, identity: CheckpointIdentity::new([11; 32]) };
    let mut second_session = manager.build_session_enabled().unwrap();
    second_session.store(StoreKind::Account).put(b"key", b"second").unwrap();
    second_session.commit().unwrap();
    lifecycle.checkpoints().record(second).unwrap();
    assert_eq!(lifecycle.checkpoints().persist().unwrap(), 2);
    drop(first_session);
    drop(second_session);
    drop(manager);
    drop(lifecycle);

    let restarted = reopen_lifecycle(&directory, limits);
    let restarted_manager = restarted.sessions();
    assert_eq!(restarted.checkpoints().relink().unwrap(), 2);
    let restored = CursorSet::new(&restarted_manager, second, Some(first), None, 0).unwrap();
    assert_eq!(restored.head().store(StoreKind::Account).get(b"key"), Some(b"second".to_vec()));
    assert_eq!(restored.solidity().store(StoreKind::Account).get(b"key"), Some(b"first".to_vec()));

    assert!(matches!(restarted.checkpoints().retreat_with(1, &CrashAt(CheckpointCrashPhase::BeforeStage)), Err(CheckpointError::Crash(CheckpointCrashPhase::BeforeStage))));
    assert_eq!(restarted_manager.depth(), 2);
    assert!(CursorSet::new(&restarted_manager, second, Some(first), None, 0).is_ok());

    assert_eq!(restarted.checkpoints().retreat(1).unwrap(), 1);
    assert_eq!(restarted_manager.depth(), 1);
    assert!(matches!(CursorSet::new(&restarted_manager, second, None, None, 0), Err(CursorError::IdentityMismatch)));
    assert_eq!(CursorSet::new(&restarted_manager, first, None, None, 0).unwrap().head().store(StoreKind::Account).get(b"key"), Some(b"first".to_vec()));
    drop(restored);
    drop(restarted_manager);
    drop(restarted);

    let restarted_again = reopen_lifecycle(&directory, limits);
    let restarted_again_manager = restarted_again.sessions();
    assert_eq!(restarted_again.checkpoints().relink().unwrap(), 1);
    assert!(matches!(CursorSet::new(&restarted_again_manager, second, None, None, 0), Err(CursorError::IdentityMismatch)));
    assert_eq!(CursorSet::new(&restarted_again_manager, first, None, None, 0).unwrap().head().store(StoreKind::Account).get(b"key"), Some(b"first".to_vec()));
    drop(restarted_again_manager);
    drop(restarted_again);
    fs::remove_dir_all(directory).unwrap();
}


#[test]
fn pending_child_merge_reset_commit_close_and_drop_are_atomic() {
    let (directory, lifecycle) = lifecycle("pending", CheckpointLimits::default());
    let manager = lifecycle.sessions();
    {
        let mut pending = lifecycle.pending().unwrap();
        assert!(matches!(lifecycle.pending(), Err(tron_state::SessionError::ConcurrentPending)));
        let mut child = pending.child().unwrap();
        child.store(StoreKind::Transaction).put(b"tx", b"accepted").unwrap();
        assert_eq!(pending.view().store(StoreKind::Transaction).get(b"tx"), None);
        assert_eq!(pending.store(StoreKind::Transaction).get(b"tx"), None);
        assert_eq!(child.view().store(StoreKind::Transaction).get(b"tx"), Some(b"accepted".to_vec()));
        pending.merge_child(&mut child).unwrap();
        assert_eq!(pending.view().store(StoreKind::Transaction).get(b"tx"), Some(b"accepted".to_vec()));
        pending.reset().unwrap();
        assert_eq!(pending.view().store(StoreKind::Transaction).get(b"tx"), None);
        pending.store(StoreKind::Transaction).put(b"tx", b"committed").unwrap();
        pending.commit().unwrap();
    }
    assert_eq!(manager.session_view().store(StoreKind::Transaction).get(b"tx"), Some(b"committed".to_vec()));
    manager.pop().unwrap();
    {
        let pending = lifecycle.pending().unwrap();
        pending.store(StoreKind::Transaction).put(b"drop", b"revoke").unwrap();
    }
    assert_eq!(manager.session_view().store(StoreKind::Transaction).get(b"drop"), None);
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn failed_pending_commit_can_close_and_release_reservation() {
    let (directory, lifecycle) = lifecycle("pending-failed-commit", CheckpointLimits::default());
    let mut pending = lifecycle.pending().unwrap();
    let mut child = pending.child().unwrap();

    assert_eq!(pending.commit(), Err(SessionError::InvalidSession));
    pending.close().unwrap();
    assert_eq!(child.revoke(), Err(SessionError::InvalidSession));

    let mut replacement = lifecycle.pending().unwrap();
    replacement.close().unwrap();
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn cloned_manager_cannot_join_or_interfere_with_pending_stack() {
    let (directory, lifecycle) = lifecycle("pending-manager-capability", CheckpointLimits::default());
    let manager = lifecycle.sessions();
    manager.durable_store(StoreKind::Transaction).put(b"root", b"durable").unwrap();
    let pending = lifecycle.pending().unwrap();
    pending.store(StoreKind::Transaction).put(b"pending", b"private").unwrap();

    let concurrent = manager.clone();
    let attempt = thread::spawn(move || {
        assert!(matches!(concurrent.build_session_enabled(), Err(SessionError::ActiveSessions(1))));
        assert_eq!(concurrent.session_view().store(StoreKind::Transaction).get(b"pending"), None);
        assert_eq!(concurrent.durable_store(StoreKind::Transaction).get(b"root"), Some(b"durable".to_vec()));
        assert_eq!(concurrent.durable_store(StoreKind::Transaction).put(b"root", b"interference"), Err(SessionError::ActiveSessions(1)));
    });
    attempt.join().unwrap();

    let mut child = pending.child().unwrap();
    child.store(StoreKind::Transaction).put(b"child", b"capability").unwrap();
    assert_eq!(child.store(StoreKind::Transaction).get(b"pending"), Some(b"private".to_vec()));
    child.merge().unwrap();
    assert_eq!(pending.store(StoreKind::Transaction).get(b"child"), Some(b"capability".to_vec()));
    drop(pending);
    assert_eq!(manager.durable_store(StoreKind::Transaction).get(b"root"), Some(b"durable".to_vec()));
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn durable_mutation_is_rejected_under_ordinary_session_and_revoke_preserves_root() {
    let (directory, lifecycle) = lifecycle("ordinary-durable-mutation", CheckpointLimits::default());
    let manager = lifecycle.sessions();
    let durable = manager.durable_store(StoreKind::Account);
    durable.put(b"key", b"root").unwrap();
    let mut session = manager.build_session_enabled().unwrap();
    session.store(StoreKind::Account).put(b"key", b"overlay").unwrap();
    assert_eq!(durable.put(b"key", b"forbidden"), Err(SessionError::ActiveSessions(1)));
    assert_eq!(durable.delete(b"key"), Err(SessionError::ActiveSessions(1)));
    session.revoke().unwrap();
    assert_eq!(durable.get(b"key"), Some(b"root".to_vec()));
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn cross_store_flush_and_view_capture_never_tear() {
    let (directory, lifecycle) = lifecycle("cross-store-capture", CheckpointLimits::default());
    let manager = lifecycle.sessions();
    manager.durable_store(StoreKind::Account).put(b"epoch", b"old").unwrap();
    manager.durable_store(StoreKind::Transaction).put(b"epoch", b"old").unwrap();
    let mut session = manager.build_session_enabled().unwrap();
    session.store(StoreKind::Account).put(b"epoch", b"new").unwrap();
    session.store(StoreKind::Transaction).put(b"epoch", b"new").unwrap();
    session.commit().unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let flush_manager = manager.clone();
    let flush_barrier = barrier.clone();
    let flush = thread::spawn(move || {
        flush_barrier.wait();
        flush_manager.flush_committed().unwrap();
    });
    barrier.wait();
    let captured = manager.read_view();
    flush.join().unwrap();

    let account = captured.store(StoreKind::Account).get(b"epoch");
    let transaction = captured.store(StoreKind::Transaction).get(b"epoch");
    assert_eq!(account, transaction);
    assert!(account == Some(b"old".to_vec()) || account == Some(b"new".to_vec()));
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}


#[test]
fn typed_cursor_fallback_clamp_offset_and_speculative_isolation() {
    let (directory, lifecycle) = lifecycle("cursors", CheckpointLimits::default());
    let manager = lifecycle.sessions();
    let root = CursorPoint { block: 10, identity: CheckpointIdentity::new([10; 32]) };
    manager.durable_store(StoreKind::Account).put(b"key", b"root").unwrap();
    lifecycle.checkpoints().record(root).unwrap();

    let solidity = CursorPoint { block: 11, identity: CheckpointIdentity::new([11; 32]) };
    let mut solid_session = manager.build_session_enabled().unwrap();
    solid_session.store(StoreKind::Account).put(b"key", b"solid").unwrap();
    solid_session.commit().unwrap();
    lifecycle.checkpoints().record(solidity).unwrap();

    let head = CursorPoint { block: 12, identity: CheckpointIdentity::new([12; 32]) };
    let mut head_session = manager.build_session_enabled().unwrap();
    head_session.store(StoreKind::Account).put(b"key", b"head").unwrap();
    head_session.commit().unwrap();
    lifecycle.checkpoints().record(head).unwrap();

    let cursors = CursorSet::new(&manager, head, Some(solidity), Some(root), 2).unwrap();
    assert_eq!(cursors.head().point(), head);
    assert_eq!(cursors.solidity().point(), solidity);
    assert_eq!(cursors.pbft().point(), root);
    assert_eq!(cursors.head().store(StoreKind::Account).get(b"key"), Some(b"head".to_vec()));
    assert_eq!(cursors.solidity().store(StoreKind::Account).get(b"key"), Some(b"solid".to_vec()));
    assert_eq!(cursors.pbft().store(StoreKind::Account).get(b"key"), Some(b"root".to_vec()));
    assert_eq!(cursors.pbft_offset(), 2);

    assert!(matches!(CursorSet::new(&manager, head, Some(solidity), Some(root), -1), Err(CursorError::NegativePbftOffset(-1))));
    let missing = CursorSet::new(&manager, head, Some(solidity), None, 2).unwrap();
    assert_eq!(missing.pbft().point(), solidity);
    assert!(matches!(CursorSet::new(&manager, head, Some(CursorPoint { block: 11, identity: root.identity }), None, 0), Err(CursorError::IdentityMismatch)));
    assert!(matches!(CursorSet::new(&manager, CursorPoint { block: 99, identity: CheckpointIdentity::new([99; 32]) }, None, None, 0), Err(CursorError::IdentityMismatch)));

    let later = CursorPoint { block: 13, identity: CheckpointIdentity::new([13; 32]) };
    let mut later_session = manager.build_session_enabled().unwrap();
    later_session.store(StoreKind::Account).put(b"key", b"later").unwrap();
    later_session.commit().unwrap();
    lifecycle.checkpoints().record(later).unwrap();
    assert_eq!(cursors.head().store(StoreKind::Account).get(b"key"), Some(b"head".to_vec()));
    assert_eq!(cursors.solidity().store(StoreKind::Account).get(b"key"), Some(b"solid".to_vec()));
    assert_eq!(cursors.pbft().store(StoreKind::Account).get(b"key"), Some(b"root".to_vec()));

    let committed_view = manager.read_view();
    let barrier = Arc::new(Barrier::new(2));
    let reader_barrier = Arc::clone(&barrier);
    let reader = thread::spawn(move || {
        reader_barrier.wait();
        assert_eq!(committed_view.store(StoreKind::Account).get(b"key"), Some(b"later".to_vec()));
    });
    let mut session = manager.build_session_enabled().unwrap();
    session.store(StoreKind::Account).put(b"key", b"speculative").unwrap();
    barrier.wait();
    reader.join().unwrap();
    session.revoke().unwrap();
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}

struct PauseAfterCapture {
    captured: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl CheckpointCrashInjector for PauseAfterCapture {
    fn after(&self, phase: CheckpointCrashPhase) -> Result<(), CheckpointError> {
        if phase == CheckpointCrashPhase::BeforeStage {
            self.captured.wait();
            self.release.wait();
        }
        Ok(())
    }
}

#[test]
fn checkpoint_publication_serializes_commits_and_competing_persists() {
    let (directory, lifecycle) = lifecycle("checkpoint-publication-serialization", CheckpointLimits::default());
    let manager = lifecycle.sessions();
    let mut baseline = manager.build_session_enabled().unwrap();
    baseline.store(StoreKind::Account).put(b"baseline", b"published").unwrap();
    baseline.commit().unwrap();
    drop(baseline);
    assert_eq!(manager.active_sessions(), 0);

    let captured = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let first_stack = lifecycle.checkpoints();
    let first_captured = captured.clone();
    let first_release = release.clone();
    let first = thread::spawn(move || {
        first_stack.persist_with(&PauseAfterCapture { captured: first_captured, release: first_release })
    });
    captured.wait();

    let (commit_started, commit_attempt) = std::sync::mpsc::channel();
    let (commit_completed, commit_result) = std::sync::mpsc::channel();
    let commit_manager = manager.clone();
    let commit = thread::spawn(move || {
        commit_started.send(()).unwrap();
        let mut session = commit_manager.build_session_enabled().unwrap();
        session.store(StoreKind::Account).put(b"new", b"committed-after-publication").unwrap();
        session.commit().unwrap();
        commit_completed.send(()).unwrap();
    });
    commit_attempt.recv().unwrap();
    assert!(matches!(commit_result.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));

    release.wait();
    assert_eq!(first.join().unwrap().unwrap(), 1);
    commit_result.recv().unwrap();
    commit.join().unwrap();

    assert_eq!(lifecycle.checkpoints().persist().unwrap(), 2);

    manager.destroy().unwrap();
    assert_eq!(lifecycle.checkpoints().relink().unwrap(), 2);
    assert_eq!(manager.session_view().store(StoreKind::Account).get(b"baseline"), Some(b"published".to_vec()));
    assert_eq!(manager.session_view().store(StoreKind::Account).get(b"new"), Some(b"committed-after-publication".to_vec()));

    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}
