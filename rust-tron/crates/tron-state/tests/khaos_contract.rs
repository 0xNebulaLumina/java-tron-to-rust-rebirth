use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use tron_primitives::{BlockId, Hash32};
use tron_state::{
    DynamicProperties, ForkClock, ForkController, ForkMath, ForkSchedule, ForkVersion,
    JavaForkMath, KhaosBlockData, KhaosDatabase, KhaosError, KhaosLimits, KhaosNode, RetainedSize,
    StateStore, StoreKind, StoreMutationKind,
};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

fn id(number: i64, marker: u8) -> BlockId {
    let mut hash = [marker; 32];
    hash[..8].copy_from_slice(&number.to_be_bytes());
    BlockId::from_overlaid_hash(Hash32::from_array(hash))
}

fn block(number: i64, marker: u8, parent: Option<BlockId>) -> KhaosBlockData<&'static str> {
    KhaosBlockData::new(id(number, marker), parent.map(BlockId::hash).unwrap_or(Hash32::ZERO), number, "block")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnedPayload {
    label: String,
    bytes: Vec<u8>,
}

impl RetainedSize for OwnedPayload {
    fn retained_size(&self) -> usize {
        self.label.retained_size().checked_add(self.bytes.retained_size()).unwrap_or(usize::MAX)
    }
}

fn owned_block(number: i64, marker: u8, parent: Option<BlockId>, payload_bytes: usize) -> KhaosBlockData<OwnedPayload> {
    KhaosBlockData::new(
        id(number, marker),
        parent.map(BlockId::hash).unwrap_or(Hash32::ZERO),
        number,
        OwnedPayload { label: "owned".to_owned(), bytes: vec![marker; payload_bytes] },
    )
}

#[test]
fn linked_orphan_number_and_strict_head_contract() {
    let root = id(0, 1);
    let mut db = KhaosDatabase::new();
    db.start(block(0, 1, None)).unwrap();
    db.push(block(1, 2, Some(root))).unwrap();

    let equal_height = id(1, 3);
    db.push(block(1, 3, Some(root))).unwrap();
    assert_eq!(db.get_head().unwrap().id, id(1, 2));
    assert!(db.contain_block_in_mini_store(&equal_height));

    let orphan = block(3, 4, Some(id(2, 9)));
    assert!(matches!(db.push(orphan), Err(KhaosError::UnlinkedBlock { .. })));
    assert!(db.contain_block(&id(3, 4)));
    assert!(!db.contain_block_in_mini_store(&id(3, 4)));

    assert_eq!(
        db.push(block(7, 5, Some(root))),
        Err(KhaosError::BadNumber { parent_number: 0, block_number: 7 })
    );
    assert!(!db.contain_block(&id(7, 5)));
}

#[test]
fn null_head_and_zero_parent_quirks_match_java() {
    let mut without_start = KhaosDatabase::new();
    let arbitrary_parent = id(8, 8);
    without_start.push(block(9, 9, Some(arbitrary_parent))).unwrap();
    assert_eq!(without_start.get_head().unwrap().number, 9);
    assert!(without_start.get_parent_block(&id(9, 9)).is_none());

    let mut db = KhaosDatabase::new();
    db.start(block(4, 1, None)).unwrap();
    db.push(block(99, 2, None)).unwrap();
    assert_eq!(db.get_head().unwrap().number, 99);
    assert!(db.get_parent_block(&id(99, 2)).is_none());
}

#[test]
fn insertion_list_replacement_removal_callbacks_are_java_shaped() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let linked_events = Rc::clone(&events);
    let mut db = KhaosDatabase::stores_with_callbacks(
        move |event| linked_events.borrow_mut().push(event),
        |_| {},
    );
    db.start(block(0, 1, None)).unwrap();

    let duplicate_id = id(1, 2);
    db.push(block(1, 2, Some(id(0, 1)))).unwrap();
    db.linked_store_mut().insert(
        KhaosNode::detached(KhaosBlockData::new(
            duplicate_id,
            id(0, 1).hash(),
            1,
            "replacement",
        )),
        Some(1),
    ).unwrap();
    assert_eq!(db.linked_store().size(), 2);
    assert_eq!(db.linked_store().get_block_by_num(1).unwrap().len(), 2);
    assert!(db.linked_store_mut().remove(&duplicate_id));
    assert!(db.linked_store().get_block_by_num(1).is_none());

    let kinds: Vec<_> = events.borrow().iter().map(|event| event.kind).collect();
    assert!(kinds.contains(&StoreMutationKind::Replaced));
    assert!(kinds.contains(&StoreMutationKind::Removed));
}

#[test]
fn height_window_eviction_uses_whole_buckets_with_capacity_two() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let linked_events = Rc::clone(&events);
    let mut db = KhaosDatabase::stores_with_callbacks(
        move |event| linked_events.borrow_mut().push(event),
        |_| {},
    );
    let root = id(0, 10);
    let first = id(1, 11);
    let sibling = id(1, 12);
    let second = id(2, 13);
    let third = id(3, 14);
    let fourth = id(4, 15);
    db.set_max_size(2);
    db.set_limits(KhaosLimits {
        max_list_entries: 64,
        max_total_bytes: usize::MAX,
        max_orphan_entries: 64,
        max_orphan_bytes: usize::MAX,
    });
    db.start(block(0, 10, None)).unwrap();
    db.push(block(1, 11, Some(root))).unwrap();
    db.push(block(1, 12, Some(root))).unwrap();
    db.push(block(2, 13, Some(first))).unwrap();
    db.push(block(3, 14, Some(second))).unwrap();
    db.push(block(4, 15, Some(third))).unwrap();

    assert!(!db.contain_block_in_mini_store(&root));
    for retained in [first, sibling, second, third, fourth] {
        assert!(db.contain_block_in_mini_store(&retained));
    }
    let evicted: Vec<_> = events
        .borrow()
        .iter()
        .filter(|event| event.kind == StoreMutationKind::Evicted)
        .map(|event| (event.id, event.number))
        .collect();
    assert_eq!(evicted, vec![(root, 0)]);
}

#[test]
fn removal_reselects_first_inserted_at_highest_height_and_weak_parent_disappears() {
    let mut db = KhaosDatabase::new();
    let root = id(0, 1);
    let first = id(1, 2);
    let second = id(1, 3);
    db.start(block(0, 1, None)).unwrap();
    db.push(block(1, 2, Some(root))).unwrap();
    db.push(block(1, 3, Some(root))).unwrap();

    db.remove_blk(&root).unwrap();
    assert_eq!(db.get_head().unwrap().id, first);
    assert!(db.get_parent_block(&first).is_none());
    db.remove_blk(&first).unwrap();
    assert_eq!(db.get_head().unwrap().id, second);
    assert_eq!(db.remove_blk(&second), Err(KhaosError::HeadWouldBeNull));
    assert!(!db.has_data());
    assert_eq!(db.get_head().unwrap().id, second);
}

#[test]
fn pop_moves_head_without_removing_data() {
    let mut db = KhaosDatabase::new();
    let root = id(0, 1);
    let child = id(1, 2);
    db.start(block(0, 1, None)).unwrap();
    db.push(block(1, 2, Some(root))).unwrap();
    assert!(db.pop());
    assert_eq!(db.get_head().unwrap().id, root);
    assert!(db.contain_block(&child));
    assert!(!db.pop());
}

#[test]
fn modern_branch_is_argument_oriented_tip_to_common_exclusive() {
    let root = id(0, 1);
    let a1 = id(1, 2);
    let a2 = id(2, 3);
    let b1 = id(1, 4);
    let mut db = KhaosDatabase::new();
    db.start(block(0, 1, None)).unwrap();
    db.push(block(1, 2, Some(root))).unwrap();
    db.push(block(2, 3, Some(a1))).unwrap();
    db.push(block(1, 4, Some(root))).unwrap();

    let (a, b) = db.get_branch(&a2, &b1).unwrap();
    assert_eq!(a.iter().map(|node| node.id()).collect::<Vec<_>>(), vec![a2, a1]);
    assert_eq!(b.iter().map(|node| node.id()).collect::<Vec<_>>(), vec![b1]);
    let (b, a) = db.get_branch(&b1, &a2).unwrap();
    assert_eq!(b.iter().map(|node| node.id()).collect::<Vec<_>>(), vec![b1]);
    assert_eq!(a.iter().map(|node| node.id()).collect::<Vec<_>>(), vec![a2, a1]);
}

#[test]
#[allow(deprecated)]
fn modern_and_deprecated_missing_behavior_differs() {
    let root = id(0, 1);
    let child = id(1, 2);
    let missing = id(9, 9);
    let mut db = KhaosDatabase::new();
    db.start(block(0, 1, None)).unwrap();
    db.push(block(1, 2, Some(root))).unwrap();

    assert_eq!(db.get_branch(&child, &missing), Err(KhaosError::NonCommonBlock));
    assert_eq!(db.get_branch_deprecated(&child, &missing).unwrap(), (Vec::new(), Vec::new()));

    db.remove_blk(&root).unwrap();
    assert_eq!(db.get_branch(&child, &child).unwrap().0.len(), 0);
}

#[test]
fn resource_limits_bound_duplicate_and_orphan_growth() {
    let mut db = KhaosDatabase::new();
    db.set_max_size(2);
    db.start(block(0, 1, None)).unwrap();
    let duplicate = id(1, 2);
    db.push(block(1, 2, Some(id(0, 1)))).unwrap();
    db.linked_store_mut()
        .insert(KhaosNode::detached(block(1, 2, Some(id(0, 1)))), Some(1))
        .unwrap();
    assert_eq!(db.linked_store().list_entries(), 2);
    assert_eq!(db.linked_store().get_by_hash(&duplicate).unwrap().id(), duplicate);

    for (number, marker) in [(1_000_000, 3), (2_000_000, 4), (3_000_000, 5)] {
        assert!(matches!(db.push(block(number, marker, Some(id(number - 1, 99)))), Err(KhaosError::UnlinkedBlock { .. })));
    }
    assert_eq!(db.unlinked_store().list_entries(), 2);
    assert!(db.unlinked_store().total_bytes() > 0);

    db.unlinked_store_mut().set_resource_limits(2, 1);
    assert!(matches!(
        db.push(block(4_000_000, 6, Some(id(3_999_999, 99)))),
        Err(KhaosError::ResourceLimit { resource: "khaos store", maximum: 1 })
    ));
    assert_eq!(db.unlinked_store().list_entries(), 2);
    let mut rejected_start = KhaosDatabase::new();
    rejected_start.linked_store_mut().set_resource_limits(1, 1);
    assert!(matches!(rejected_start.start(block(0, 7, None)), Err(KhaosError::ResourceLimit { .. })));
    assert!(rejected_start.get_head().is_none());
}

#[test]
fn linked_admission_retains_exact_parent_or_rejects_atomically() {
    let root = id(0, 30);
    let child = id(1, 31);
    let mut db = KhaosDatabase::new();
    db.start(block(0, 30, None)).unwrap();
    let parent = db.linked_store().get_by_hash(&root).unwrap();
    let entries = db.linked_store().list_entries();
    let bytes = db.linked_store().total_bytes();
    let head = db.get_head().unwrap().id;
    db.linked_store_mut().set_resource_limits(1, usize::MAX);

    assert!(matches!(
        db.push(block(1, 31, Some(root))),
        Err(KhaosError::ResourceLimit { resource: "khaos store", maximum: usize::MAX })
    ));

    let retained_parent = db.linked_store().get_by_hash(&root).unwrap();
    assert!(Rc::ptr_eq(&parent, &retained_parent));
    assert!(db.contain_block_in_mini_store(&root));
    assert!(!db.contain_block(&child));
    assert_eq!(db.get_head().unwrap().id, head);
    assert_eq!(db.linked_store().list_entries(), entries);
    assert_eq!(db.linked_store().total_bytes(), bytes);
}

#[test]
fn resource_pressure_skips_only_pinned_parent_and_preserves_same_height_sibling() {
    let root = id(0, 40);
    let sibling = id(0, 41);
    let child = id(1, 42);
    let mut db = KhaosDatabase::new();
    db.start(block(0, 40, None)).unwrap();
    db.linked_store_mut()
        .insert(KhaosNode::detached(block(0, 41, None)), None)
        .unwrap();
    db.linked_store_mut().set_resource_limits(2, usize::MAX);

    db.push(block(1, 42, Some(root))).unwrap();

    assert!(db.contain_block_in_mini_store(&root));
    assert!(!db.contain_block_in_mini_store(&sibling));
    assert!(db.contain_block_in_mini_store(&child));
    assert_eq!(db.linked_store().get_block_by_num(0).unwrap().len(), 1);
    assert_eq!(db.linked_store().list_entries(), 2);
}

#[test]
fn resource_pressure_follows_insertion_order_across_interleaved_heights() {
    let oldest = id(5, 50);
    let mut db = KhaosDatabase::new();
    db.linked_store_mut().set_resource_limits(3, usize::MAX);
    for (number, marker) in [(5, 50), (1, 51), (4, 52), (6, 53)] {
        db.linked_store_mut()
            .insert(KhaosNode::detached(block(number, marker, None)), None)
            .unwrap();
    }

    assert!(!db.contain_block_in_mini_store(&oldest));
    for retained in [id(1, 51), id(4, 52), id(6, 53)] {
        assert!(db.contain_block_in_mini_store(&retained));
    }
    assert_eq!(db.linked_store().list_entries(), 3);
}

#[test]
fn deep_payload_limits_reject_without_linked_or_orphan_mutation() {
    let limits = KhaosLimits {
        max_list_entries: 8,
        max_total_bytes: 128,
        max_orphan_entries: 8,
        max_orphan_bytes: 128,
    };
    let root = id(0, 20);
    let mut db = KhaosDatabase::new();
    db.set_limits(limits);
    db.start(owned_block(0, 20, None, 8)).unwrap();

    let linked_entries = db.linked_store().list_entries();
    let linked_bytes = db.linked_store().total_bytes();
    let head = db.get_head().unwrap().id;
    assert!(matches!(
        db.push(owned_block(1, 21, Some(root), 256)),
        Err(KhaosError::ResourceLimit { resource: "khaos store", maximum: 128 })
    ));
    assert_eq!(db.linked_store().list_entries(), linked_entries);
    assert_eq!(db.linked_store().total_bytes(), linked_bytes);
    assert_eq!(db.get_head().unwrap().id, head);
    assert!(!db.contain_block(&id(1, 21)));

    let first_orphan = id(7, 22);
    assert!(matches!(
        db.push(owned_block(7, 22, Some(id(6, 90)), 8)),
        Err(KhaosError::UnlinkedBlock { .. })
    ));
    let orphan_entries = db.unlinked_store().list_entries();
    let orphan_bytes = db.unlinked_store().total_bytes();
    assert!(matches!(
        db.push(owned_block(8, 23, Some(id(7, 91)), 256)),
        Err(KhaosError::ResourceLimit { resource: "khaos store", maximum: 128 })
    ));
    assert_eq!(db.unlinked_store().list_entries(), orphan_entries);
    assert_eq!(db.unlinked_store().total_bytes(), orphan_bytes);
    assert!(db.contain_block(&first_orphan));
    assert!(!db.contain_block(&id(8, 23)));
}

#[test]
fn branch_rejects_repeated_parent_ids_and_nondecreasing_heights() {
    let root = id(0, 1);
    let child = id(1, 2);
    let other = id(1, 3);
    let mut malformed = KhaosDatabase::new();
    malformed.start(block(0, 1, None)).unwrap();
    malformed.push(block(1, 2, Some(root))).unwrap();
    malformed.push(block(1, 3, Some(root))).unwrap();
    malformed
        .push(KhaosBlockData::new(root, root.hash(), 1, "replacement root"))
        .unwrap();
    assert!(matches!(malformed.get_branch(&child, &other), Err(KhaosError::MalformedChain { .. })));

    let mut cyclic = KhaosDatabase::new();
    cyclic.start(block(0, 1, None)).unwrap();
    cyclic.push(block(1, 2, Some(root))).unwrap();
    cyclic.push(block(1, 3, Some(root))).unwrap();
    let tip = id(2, 1);
    cyclic.push(block(2, 1, Some(child))).unwrap();
    cyclic
        .push(KhaosBlockData::new(root, tip.hash(), 3, "replacement root"))
        .unwrap();
    assert!(matches!(cyclic.get_branch(&root, &other), Err(KhaosError::CycleDetected { .. })));

    #[allow(deprecated)]
    {
        assert!(matches!(malformed.get_branch_deprecated(&child, &root), Err(KhaosError::MalformedChain { .. })));
        assert!(matches!(cyclic.get_branch_deprecated(&root, &other), Err(KhaosError::CycleDetected { .. })));
    }
}

#[test]
fn unsupported_inherited_is_not_empty_contract() {
    let store = tron_state::KhaosStore::<&str>::new();
    assert_eq!(store.is_not_empty(), Err(KhaosError::UnsupportedOperation("is_not_empty")));
}

struct ForkTestSchedule([ForkVersion; 6]);

impl ForkSchedule for ForkTestSchedule {
    fn versions(&self) -> &[ForkVersion] {
        &self.0
    }

    fn old_cutoff(&self) -> i32 {
        16
    }
}

struct ForkTestClock {
    number: i64,
    timestamp: i64,
}

impl ForkClock for ForkTestClock {
    fn latest_block_number(&self) -> i64 {
        self.number
    }

    fn latest_block_timestamp(&self) -> i64 {
        self.timestamp
    }
}

fn fork_state(name: &str) -> (PathBuf, StateStore, DynamicProperties) {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!(
        "tron-state-c011-{name}-{}-{nonce}",
        std::process::id()
    ));
    let requirements = OpenRequirements {
        identity: StorageIdentity { network: "c011".into(), genesis: "7f".into() },
        schema_version: 1,
        backend: "rustlog".into(),
        backend_format: "rustlog-v1".into(),
        supported_features: vec!["rustlog-v1".into()],
    };
    let state = StateStore::new(StorageManager::new(requirements).open_store(&path).unwrap());
    let properties = DynamicProperties::new(state.store(StoreKind::DynamicProperties));
    properties.save_int("VERSION_NUMBER", 0).unwrap();
    properties.save_long("MAINTENANCE_TIME_INTERVAL", 10).unwrap();
    (path, state, properties)
}

fn fork_schedule() -> ForkTestSchedule {
    ForkTestSchedule([
        ForkVersion { version: 4, hard_fork_time: 0, hard_fork_rate: 100 },
        ForkVersion { version: 5, hard_fork_time: 0, hard_fork_rate: 100 },
        ForkVersion { version: 6, hard_fork_time: i64::MAX, hard_fork_rate: 100 },
        ForkVersion { version: 16, hard_fork_time: i64::MAX, hard_fork_rate: 100 },
        ForkVersion { version: 17, hard_fork_time: 100, hard_fork_rate: 80 },
        ForkVersion { version: 18, hard_fork_time: 200, hard_fork_rate: 80 },
    ])
}

#[test]
fn test_pass_matches_old_new_energy_and_raw_stats_contract() {
    let (path, state, properties) = fork_state("pass");
    let schedule = fork_schedule();
    let math = JavaForkMath;
    let before = ForkTestClock { number: 4_727_889, timestamp: 99 };
    let controller = ForkController::new(properties.clone(), &schedule, &before, &math, 4_727_890);
    let active = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec(), b"e".to_vec()];

    assert!(!controller.pass(5, &active).unwrap());
    properties.save_fork_stats(4, &[1, 1, 1]).unwrap();
    assert!(controller.pass(4, &active).unwrap());
    properties.save_fork_stats(4, &[1, 2, 1]).unwrap();
    assert!(!controller.pass(4, &active).unwrap());
    properties.save_fork_stats(6, &[1, 1, 1, 1, 0]).unwrap();
    assert!(!controller.pass(6, &active).unwrap());
    properties.save_fork_stats(6, &[1, 1, 1]).unwrap();
    assert!(controller.pass(6, &active).unwrap());
    properties.save_fork_stats(17, &[1, 1, 1, 1, 0]).unwrap();
    assert!(!controller.pass(17, &active).unwrap());

    drop(controller);
    let at = ForkTestClock { number: 4_727_890, timestamp: 100 };
    let controller = ForkController::new(properties.clone(), &schedule, &at, &math, 4_727_890);
    assert!(controller.pass(5, &active).unwrap());
    assert!(controller.pass(6, &active).unwrap());
    assert!(controller.pass(17, &active).unwrap());
    properties.save_fork_stats(17, &[1, 1, 1]).unwrap();
    assert!(controller.pass(17, &active).unwrap());
    assert!(!controller.pass(99, &active).unwrap());

    drop(controller);
    drop(properties);
    drop(state);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn test_reset_preserves_passing_raw_length_and_resizes_failing_stats() {
    let (path, state, properties) = fork_state("reset");
    let schedule = fork_schedule();
    let clock = ForkTestClock { number: 0, timestamp: 250 };
    let math = JavaForkMath;
    let controller = ForkController::new(properties.clone(), &schedule, &clock, &math, i64::MAX);
    let active = vec![b"a".to_vec(), b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec(), b"e".to_vec()];
    properties.save_fork_stats(4, &[1, 1, 1, 1, 1]).unwrap();
    properties.save_fork_stats(6, &[1, 1, 1]).unwrap();
    properties.save_fork_stats(17, &[1, 1, 1, 1, 0]).unwrap();
    properties.save_fork_stats(18, &[1, 1, 1, 0, 0]).unwrap();

    controller.reset(&active).unwrap();

    assert_eq!(properties.fork_stats(4).unwrap(), vec![1; 5]);
    assert_eq!(properties.fork_stats(6).unwrap(), vec![1; 3]);
    assert_eq!(properties.fork_stats(17).unwrap(), vec![1, 1, 1, 1, 0]);
    assert_eq!(properties.fork_stats(18).unwrap(), vec![0; 6]);

    drop(controller);
    drop(properties);
    drop(state);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn test_update_uses_first_active_index_and_java_upgrade_order() {
    let (path, state, properties) = fork_state("update");
    let schedule = fork_schedule();
    let clock = ForkTestClock { number: 0, timestamp: 150 };
    let math = JavaForkMath;
    let controller = ForkController::new(properties.clone(), &schedule, &clock, &math, i64::MAX);
    let active = vec![b"a".to_vec(), b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
    properties.save_fork_stats(4, &[1, 1, 0]).unwrap();
    properties.save_fork_stats(6, &[1, 1, 0]).unwrap();
    properties.save_fork_stats(17, &[1, 1, 1, 0, 0]).unwrap();
    properties.save_fork_stats(18, &[1, 1, 1, 1, 0]).unwrap();

    controller.update(&active, b"a", 17).unwrap();
    assert!(!controller.pass(18, &active).unwrap());
    assert_eq!(properties.fork_stats(18).unwrap(), vec![0, 1, 1, 1, 0]);
    assert_eq!(properties.fork_stats(17).unwrap(), vec![1, 1, 1, 0, 0]);
    assert_eq!(properties.get_int("VERSION_NUMBER").unwrap(), 0);

    controller.update(&active, b"c", 17).unwrap();
    assert_eq!(properties.fork_stats(17).unwrap(), vec![1, 1, 1, 1, 0]);
    assert_eq!(properties.get_int("VERSION_NUMBER").unwrap(), 0);
    controller.update(&active, b"d", 17).unwrap();
    assert_eq!(properties.get_int("VERSION_NUMBER").unwrap(), 17);
    assert_eq!(properties.fork_stats(4).unwrap(), vec![1, 1, 1]);
    assert_eq!(properties.fork_stats(6).unwrap(), vec![1, 1, 1]);
    assert_eq!(properties.fork_stats(17).unwrap(), vec![1, 1, 1, 1, 0]);

    drop(controller);
    drop(properties);
    drop(state);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn test_update_resizes_candidate_locally_before_passing_upgrade() {
    let (path, state, properties) = fork_state("update-resize-order");
    let schedule = fork_schedule();
    let clock = ForkTestClock { number: 0, timestamp: 150 };
    let math = JavaForkMath;
    let controller = ForkController::new(properties.clone(), &schedule, &clock, &math, i64::MAX);
    let active = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec(), b"e".to_vec()];
    properties.save_fork_stats(4, &[1, 1, 1, 1, 0]).unwrap();
    properties.save_fork_stats(6, &[1, 1, 1, 1, 0]).unwrap();
    properties.save_fork_stats(17, &[1]).unwrap();

    controller.update(&active, b"e", 17).unwrap();

    assert_eq!(properties.get_int("VERSION_NUMBER").unwrap(), 17);
    assert_eq!(properties.fork_stats(4).unwrap(), vec![1; 5]);
    assert_eq!(properties.fork_stats(6).unwrap(), vec![1; 5]);
    assert_eq!(properties.fork_stats(17).unwrap(), vec![1]);

    drop(controller);
    drop(properties);
    drop(state);
    fs::remove_dir_all(path).unwrap();
}

const C011_CASE_TABLE: &[(&str, fn())] = &[
    ("khaos:linked", linked_orphan_number_and_strict_head_contract),
    ("khaos:orphan", linked_orphan_number_and_strict_head_contract),
    ("khaos:replacement", insertion_list_replacement_removal_callbacks_are_java_shaped),
    ("khaos:duplicate", insertion_list_replacement_removal_callbacks_are_java_shaped),
    ("khaos:eviction", height_window_eviction_uses_whole_buckets_with_capacity_two),
    ("khaos:head", linked_orphan_number_and_strict_head_contract),
    ("khaos:remove", removal_reselects_first_inserted_at_highest_height_and_weak_parent_disappears),
    ("khaos:pop", pop_moves_head_without_removing_data),
    ("khaos:weak-parent", removal_reselects_first_inserted_at_highest_height_and_weak_parent_disappears),
    ("khaos:modern-branch", modern_branch_is_argument_oriented_tip_to_common_exclusive),
    ("khaos:deprecated-branch", modern_and_deprecated_missing_behavior_differs),
    ("khaos:resource-limits", resource_limits_bound_duplicate_and_orphan_growth),
    ("khaos:parent-retention", linked_admission_retains_exact_parent_or_rejects_atomically),
    ("khaos:pinned-parent-sibling", resource_pressure_skips_only_pinned_parent_and_preserves_same_height_sibling),
    ("khaos:interleaved-resource-order", resource_pressure_follows_insertion_order_across_interleaved_heights),
    ("khaos:cycle-defense", branch_rejects_repeated_parent_ids_and_nondecreasing_heights),
    ("khaos:deep-payload-limits", deep_payload_limits_reject_without_linked_or_orphan_mutation),
    ("khaos:deprecated-cycle-defense", branch_rejects_repeated_parent_ids_and_nondecreasing_heights),
    ("khaos:unsupported-is-not-empty", unsupported_inherited_is_not_empty_contract),
    ("activation:old-version", test_pass_matches_old_new_energy_and_raw_stats_contract),
    ("activation:energy-height", test_pass_matches_old_new_energy_and_raw_stats_contract),
    ("activation:maintenance-rounding", test_pass_matches_old_new_energy_and_raw_stats_contract),
    ("activation:new-version-quorum", test_pass_matches_old_new_energy_and_raw_stats_contract),
    ("activation:old-v6-no-time", test_pass_matches_old_new_energy_and_raw_stats_contract),
    ("activation:reset", test_reset_preserves_passing_raw_length_and_resizes_failing_stats),
    ("activation:upgrade", test_update_uses_first_active_index_and_java_upgrade_order),
    ("activation:new-v17-path", test_pass_matches_old_new_energy_and_raw_stats_contract),
    ("activation:downgrade", test_update_uses_first_active_index_and_java_upgrade_order),
    ("activation:duplicate-witness", test_update_uses_first_active_index_and_java_upgrade_order),
    ("activation:resize-order", test_update_resizes_candidate_locally_before_passing_upgrade),
];

#[test]
fn c011_fixture_dispatch_is_complete_and_executable() {
    let selected = std::env::var("C011_CASE").ok();
    let mut matched = false;
    for (case_id, case) in C011_CASE_TABLE {
        if selected.as_deref().is_none_or(|wanted| wanted == *case_id) {
            matched = true;
            case();
        }
    }
    assert!(matched, "unknown C011_CASE: {selected:?}");
}
