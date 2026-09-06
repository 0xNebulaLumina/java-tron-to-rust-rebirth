use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use tron_execution::*;
use tron_primitives::Hash32;
use tron_state::{SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

fn manager(name: &str) -> (PathBuf, SessionManager) {
    let p = std::env::temp_dir().join(format!("c016-pending-{name}-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    let r = OpenRequirements { identity: StorageIdentity { network: "c016".into(), genesis: "00".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()] };
    (p.clone(), SessionManager::new(StateStore::new(StorageManager::new(r).open_store(&p).unwrap())))
}

fn item(n: u8, at: i64, shielded: bool, smart: bool) -> PendingTransaction<u8> {
    PendingTransaction { id: [n; 32].into(), transaction: n, received_at: at, shielded, smart }
}

fn limits() -> PendingLimits {
    PendingLimits { maximum: 8, timeout_millis: 10, shielded_maximum: 2, smart_drain_limit: 1 }
}

fn cache() -> TransactionCache {
    TransactionCache::new(CacheConfig { maximum_entries: 8, ttl_millis: 100, bloom_blocks: 4, bloom_bits: 64 }).unwrap()
}

#[test]
fn typed_broadcast_limits_timeout_and_shutdown_reset() {
    let (p, m) = manager("limits");
    let mut q = PendingPool::new(m.clone(), PendingLimits { maximum: 4, shielded_maximum: 1, ..limits() }).unwrap();
    assert!(matches!(q.broadcast(item(1, 0, true, false), 0), BroadcastResult::Accepted { .. }));
    assert!(matches!(q.broadcast(item(2, 0, true, false), 0), BroadcastResult::Rejected { reason: PendingReject::ShieldedFull, .. }));
    assert!(matches!(q.broadcast(item(3, 0, false, false), 10), BroadcastResult::Rejected { reason: PendingReject::Expired, .. }));
    assert!(matches!(q.broadcast(item(1, 0, false, false), 0), BroadcastResult::Rejected { reason: PendingReject::Duplicate, .. }));
    q.shutdown().unwrap();
    assert!(q.is_empty());
    assert_eq!(m.active_sessions(), 0);
    assert!(matches!(q.broadcast(item(4, 0, false, false), 0), BroadcastResult::Rejected { reason: PendingReject::Closed, .. }));
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn held_session_merge_bounded_smart_drain_and_fork_requeue_are_exact() {
    let (p, m) = manager("flow");
    let mut q = PendingPool::new(m.clone(), PendingLimits { timeout_millis: 100, ..limits() }).unwrap();
    q.broadcast(item(1, 11, false, false), 11);
    q.broadcast(item(2, 12, false, false), 12);
    q.broadcast(item(3, 13, false, true), 13);
    q.broadcast(item(4, 14, false, true), 14);
    let first = q.execute_next(20, |_, s| s.store(StoreKind::Code).put(b"held", b"one").map_err(|e| e.to_string())).unwrap();
    assert!(matches!(first, BroadcastResult::Accepted { .. }));
    let second = q.execute_next(20, |_, s| { assert_eq!(s.store(StoreKind::Code).get(b"held"), Some(b"one".to_vec())); Ok(()) }).unwrap();
    assert!(matches!(second, BroadcastResult::Accepted { .. }));
    assert_eq!(q.drain_smart(20, |_, _| Ok(())).len(), 1);
    q.broadcast(item(5, 15, false, false), 20);
    let mut cache = cache();
    cache.insert([9; 32].into(), 1, 0).unwrap();
    q.requeue_after_fork(&mut cache, 50).unwrap();
    assert_eq!(q.pending_ids(), vec![Hash32::from([5u8; 32]), Hash32::from([1u8; 32]), Hash32::from([2u8; 32]), Hash32::from([3u8; 32]), Hash32::from([4u8; 32])]);
    assert_eq!(q.take_next(50).unwrap().received_at, 15);
    assert_eq!(q.take_next(50).unwrap().received_at, 50);
    assert_eq!(q.take_next(50).unwrap().received_at, 50);
    assert_eq!(q.take_next(50).unwrap().received_at, 50);
    assert_eq!(cache.len(), 0);
    assert_eq!(m.durable_store(StoreKind::Code).get(b"held"), None);
    q.shutdown().unwrap();
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn fork_requeue_preserves_multiple_pending_and_refreshes_multiple_popped() {
    let (p, m) = manager("timestamps");
    let mut q = PendingPool::new(m, limits()).unwrap();
    for (id, at) in [(1, 91), (2, 92), (3, 93), (4, 94), (5, 95)] { q.broadcast(item(id, at, false, false), at); }
    assert_eq!(q.execute_next(96, |_, _| Ok(())).unwrap(), BroadcastResult::Accepted { transaction_id: [1; 32].into() });
    assert_eq!(q.execute_next(96, |_, _| Ok(())).unwrap(), BroadcastResult::Accepted { transaction_id: [2; 32].into() });
    q.requeue_after_fork(&mut cache(), 100).unwrap();
    let replay: Vec<_> = (0..5).map(|_| q.take_next(100).unwrap()).map(|tx| (tx.transaction, tx.received_at)).collect();
    assert_eq!(replay, vec![(3, 93), (4, 94), (5, 95), (1, 100), (2, 100)]);
    q.shutdown().unwrap();
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn refreshed_popped_transactions_receive_a_full_new_timeout_window() {
    let (p, m) = manager("reexpiry");
    let mut q = PendingPool::new(m, limits()).unwrap();
    q.broadcast(item(1, 95, false, false), 95);
    q.broadcast(item(2, 96, false, false), 96);
    q.execute_next(99, |_, _| Ok(())).unwrap();
    q.requeue_after_fork(&mut cache(), 100).unwrap();
    assert_eq!(q.take_next(105).unwrap().transaction, 2);
    assert_eq!(q.take_next(109).unwrap().transaction, 1);
    q.mark_popped(item(3, 0, false, false));
    q.requeue_after_fork(&mut cache(), 200).unwrap();
    assert_eq!(q.take_next(209).unwrap().received_at, 200);
    q.mark_popped(item(4, 0, false, false));
    q.requeue_after_fork(&mut cache(), 300).unwrap();
    assert!(q.take_next(310).is_none());
    q.shutdown().unwrap();
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn pending_queries_match_java_pending_repush_and_popped_visibility() {
    let (p, m) = manager("query-visibility");
    let mut q = PendingPool::new(m, limits()).unwrap();
    q.broadcast(item(1, 1, false, false), 1);
    q.broadcast(item(2, 2, false, true), 2);
    q.broadcast(item(3, 3, false, false), 3);
    assert_eq!(q.execute_next(4, |_, _| Ok(())).unwrap(), BroadcastResult::Accepted { transaction_id: [1; 32].into() });

    assert_eq!(q.len(), 3, "popped transactions contribute to Java pending size");
    assert_eq!(q.pending_ids(), vec![Hash32::from([3; 32]), Hash32::from([2; 32])]);
    assert_eq!(q.pending_transaction(&Hash32::from([3; 32])).map(|tx| tx.transaction), Some(3));
    assert_eq!(q.pending_transaction(&Hash32::from([2; 32])).map(|tx| tx.transaction), Some(2));
    assert!(q.pending_transaction(&Hash32::from([1; 32])).is_none(), "popped transactions are not exposed by Java lookup");

    q.shutdown().unwrap();
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn admission_publishes_state_and_queue_only_after_success() {
    let (p, m) = manager("atomic-admission");
    let mut q = PendingPool::new(m.clone(), limits()).unwrap();

    let failed: Result<BroadcastResult, tron_state::SessionError> = q.admit(item(1, 1, false, false), 1, |_, session| {
        session.store(StoreKind::Code).put(b"atomic", b"rejected")?;
        Err(tron_state::SessionError::InvalidSession)
    });
    assert_eq!(failed.unwrap_err(), tron_state::SessionError::InvalidSession);
    assert!(q.is_empty());

    let accepted: Result<BroadcastResult, tron_state::SessionError> = q.admit(item(2, 2, false, false), 2, |_, session| {
        assert_eq!(session.store(StoreKind::Code).get(b"atomic"), None);
        session.store(StoreKind::Code).put(b"atomic", b"accepted")
    });
    assert_eq!(accepted.unwrap(), BroadcastResult::Accepted { transaction_id: [2; 32].into() });
    assert_eq!(q.len(), 1);
    assert_eq!(q.queue_ids(), (vec![Hash32::from([2; 32])], vec![], vec![]));
    assert_eq!(q.pending_ids(), vec![Hash32::from([2; 32])]);
    assert_eq!(q.pending_transaction(&Hash32::from([2; 32])).map(|tx| tx.transaction), Some(2));

    let smart: Result<BroadcastResult, tron_state::SessionError> = q.admit(item(3, 3, false, true), 3, |_, _| Ok(()));
    assert_eq!(smart.unwrap(), BroadcastResult::Accepted { transaction_id: [3; 32].into() });
    assert_eq!(q.queue_ids(), (vec![Hash32::from([2; 32])], vec![], vec![Hash32::from([3; 32])]));
    assert_eq!(q.pending_ids(), vec![Hash32::from([2; 32]), Hash32::from([3; 32])]);

    q.shutdown().unwrap();
    assert_eq!(m.durable_store(StoreKind::Code).get(b"atomic"), None);
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn fork_replay_covers_pending_popped_and_smart_without_changing_ownership() {
    let (p, m) = manager("replay-queues");
    let mut q = PendingPool::new(m, limits()).unwrap();
    q.broadcast(item(1, 1, false, false), 1);
    q.mark_popped(item(2, 2, true, false));
    q.broadcast(item(3, 3, false, true), 3);

    let mut replayed = Vec::new();
    q.replay_speculative(false, |transaction, _| {
        replayed.push(transaction.transaction);
        if transaction.transaction == 3 { Err("invalid on replacement branch".into()) } else { Ok(()) }
    }).unwrap();

    assert_eq!(replayed, vec![1, 2, 3]);
    assert_eq!(q.queue_ids(), (vec![Hash32::from([1; 32])], vec![Hash32::from([2; 32])], vec![]));
    assert_eq!(q.len(), 2);
    assert!(matches!(q.broadcast(item(4, 4, true, false), 4), BroadcastResult::Accepted { .. }));
    assert!(matches!(q.broadcast(item(5, 5, true, false), 5), BroadcastResult::Rejected { reason: PendingReject::ShieldedFull, .. }));

    q.shutdown().unwrap();
    fs::remove_dir_all(p).unwrap();
}
