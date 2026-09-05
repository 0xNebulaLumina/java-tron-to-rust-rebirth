use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use num_bigint::BigInt;
use prost::Message;
use tron_consensus::{apply_maintenance_block, delegation_key, ConsensusRead, MaintenanceConfig, StateFacade, VI_SCALE};
use tron_protocol::protocol::{Account, Vote, Votes, Witness};
use tron_state::{dynamic, value, SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

fn path() -> PathBuf { std::env::temp_dir().join(format!("c017-maintenance-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())) }
fn address(byte: u8) -> Vec<u8> { [vec![0x41], vec![byte; 20]].concat() }
fn manager() -> StorageManager { StorageManager::new(OpenRequirements { identity: StorageIdentity { network: "c017".into(), genesis: "00".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()] }) }
fn put_long(state: &StateStore, name: &str, value: i64) { state.store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(), &value.to_be_bytes()).unwrap(); }

#[test]
fn maintenance_removes_gr_applies_vote_delta_rotates_and_advances_atomically() {
    let directory = path(); let root = StateStore::new(manager().open_store(&directory).unwrap());
    let witnesses: Vec<_> = (0..30).map(|i| Witness { address: address(i), vote_count: 100 - i64::from(i), is_jobs: i < 27, ..Default::default() }).collect();
    for witness in &witnesses { root.store(StoreKind::Witness).put(&witness.address, &witness.encode_to_vec()).unwrap(); }
    root.store(StoreKind::WitnessSchedule).put(value::ACTIVE_WITNESSES_KEY, &witnesses[..27].iter().flat_map(|w|w.address.iter().copied()).collect::<Vec<_>>()).unwrap();
    root.store(StoreKind::Votes).put(b"voter", &Votes { address: address(99), old_votes: vec![Vote { vote_address: address(0), vote_count: 3 }], new_votes: vec![Vote { vote_address: address(29), vote_count: 50 }] }.encode_to_vec()).unwrap();
    for (name, value) in [("NEXT_MAINTENANCE_TIME", 10_000), ("MAINTENANCE_TIME_INTERVAL", 9_000), ("REMOVE_THE_POWER_OF_THE_GR", 1), ("CURRENT_CYCLE_NUMBER", 7), ("CHANGE_DELEGATION", 1)] { put_long(&root, name, value); }
    root.store(StoreKind::DynamicProperties).put(dynamic::key("STATE_FLAG").unwrap(), &0_i32.to_be_bytes()).unwrap();
    let sessions = SessionManager::new(root.clone()); let mut session = sessions.build_session().unwrap();
    let facade = StateFacade::new(&session);
    let result = apply_maintenance_block(&facade, 8, 28_001, &MaintenanceConfig { genesis_votes: vec![(address(0), 10)], witness_sort_optimized: true }).unwrap();
    assert!(result.applied); assert_eq!(result.consumed_vote_rows, 1); assert_eq!(result.next_maintenance_time, 37_000); assert_eq!(result.cycle, 8);
    assert_eq!(facade.witness(&address(0)).unwrap().unwrap().vote_count, 87);
    assert_eq!(facade.witness(&address(29)).unwrap().unwrap().vote_count, 121);
    assert!(facade.votes().unwrap().is_empty()); assert_eq!(facade.active_witnesses().unwrap().len(), 27); assert!(facade.current_witnesses().unwrap().is_empty());
    assert_eq!(facade.dynamic_long("REMOVE_THE_POWER_OF_THE_GR").unwrap(), -1); assert_eq!(facade.dynamic_int("STATE_FLAG").unwrap(), 1);
    session.revoke().unwrap();
    let committed = tron_consensus::StateView::new(sessions.read_view());
    assert_eq!(committed.witness(&address(0)).unwrap().unwrap().vote_count, 100); assert_eq!(committed.votes().unwrap().len(), 1);
    drop(committed); drop(sessions); drop(root); fs::remove_dir_all(directory).unwrap();
}

#[test]
fn maintenance_uses_pre_delta_votes_for_vi_then_active_order_for_legacy_incentive() {
    let directory = path(); let root = StateStore::new(manager().open_store(&directory).unwrap());
    let a = address(1); let b = address(2); let shuffled = address(9);
    for witness in [Witness { address: a.clone(), vote_count: 100, is_jobs: true, ..Default::default() }, Witness { address: b.clone(), vote_count: 50, ..Default::default() }] {
        root.store(StoreKind::Witness).put(&witness.address, &witness.encode_to_vec()).unwrap();
        root.store(StoreKind::Account).put(&witness.address, &Account { address: witness.address.clone(), ..Default::default() }.encode_to_vec()).unwrap();
    }
    root.store(StoreKind::WitnessSchedule).put(value::ACTIVE_WITNESSES_KEY, &a).unwrap();
    root.store(StoreKind::WitnessSchedule).put(value::CURRENT_SHUFFLED_WITNESSES_KEY, &shuffled).unwrap();
    root.store(StoreKind::Votes).put(b"voter", &Votes { address: address(7), old_votes: vec![Vote { vote_address: a.clone(), vote_count: 50 }], new_votes: vec![Vote { vote_address: b.clone(), vote_count: 100 }] }.encode_to_vec()).unwrap();
    for (name, value) in [("NEXT_MAINTENANCE_TIME", 10), ("MAINTENANCE_TIME_INTERVAL", 10), ("CURRENT_CYCLE_NUMBER", 4), ("CHANGE_DELEGATION", 0), ("NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE", 4), ("WITNESS_STANDBY_ALLOWANCE", 100)] { put_long(&root, name, value); }
    root.store(StoreKind::DynamicProperties).put(dynamic::key("STATE_FLAG").unwrap(), &0_i32.to_be_bytes()).unwrap();
    root.store(StoreKind::Delegation).put(&delegation_key(4, &a, "reward"), &100_i64.to_be_bytes()).unwrap();
    root.store(StoreKind::Delegation).put(&delegation_key(4, &b, "reward"), &100_i64.to_be_bytes()).unwrap();
    let sessions = SessionManager::new(root.clone()); let mut session = sessions.build_session().unwrap(); let facade = StateFacade::new(&session);
    apply_maintenance_block(&facade, 2, 10, &MaintenanceConfig { genesis_votes: vec![], witness_sort_optimized: true }).unwrap();
    assert_eq!(BigInt::from_signed_bytes_be(&facade.delegation(&delegation_key(4, &a, "vi")).unwrap()), BigInt::from(VI_SCALE));
    assert_eq!(BigInt::from_signed_bytes_be(&facade.delegation(&delegation_key(4, &b, "vi")).unwrap()), BigInt::from(2) * BigInt::from(VI_SCALE));
    assert_eq!(facade.active_witnesses().unwrap(), vec![b.clone(), a.clone()]);
    assert_eq!(facade.current_witnesses().unwrap(), vec![shuffled]);
    let allowance = |address: &[u8]| Account::decode(facade.store_get(StoreKind::Account, address).unwrap().as_slice()).unwrap().allowance;
    assert_eq!((allowance(&a), allowance(&b)), (25, 75));
    session.revoke().unwrap();
    let committed = tron_consensus::StateView::new(sessions.read_view());
    assert_eq!(committed.witness(&a).unwrap().unwrap().vote_count, 100); assert_eq!(committed.active_witnesses().unwrap(), vec![a]); assert!(committed.delegation(&delegation_key(4, &b, "vi")).is_none());
    drop(committed); drop(sessions); drop(root); fs::remove_dir_all(directory).unwrap();
}

#[test]
fn maintenance_child_rolls_back_active_votes_and_vi_when_legacy_account_is_missing() {
    let directory = path(); let root = StateStore::new(manager().open_store(&directory).unwrap()); let witness = address(3);
    root.store(StoreKind::Witness).put(&witness, &Witness { address: witness.clone(), vote_count: 10, ..Default::default() }.encode_to_vec()).unwrap();
    root.store(StoreKind::WitnessSchedule).put(value::ACTIVE_WITNESSES_KEY, &witness).unwrap();
    root.store(StoreKind::Votes).put(b"voter", &Votes { address: address(7), old_votes: vec![], new_votes: vec![Vote { vote_address: witness.clone(), vote_count: 1 }] }.encode_to_vec()).unwrap();
    for (name, value) in [("NEXT_MAINTENANCE_TIME", 10), ("MAINTENANCE_TIME_INTERVAL", 10), ("CURRENT_CYCLE_NUMBER", 2), ("CHANGE_DELEGATION", 0), ("NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE", 2), ("WITNESS_STANDBY_ALLOWANCE", 100)] { put_long(&root, name, value); }
    put_long(&root, "REMOVE_THE_POWER_OF_THE_GR", 0); root.store(StoreKind::DynamicProperties).put(dynamic::key("STATE_FLAG").unwrap(), &0_i32.to_be_bytes()).unwrap();
    root.store(StoreKind::Delegation).put(&delegation_key(2, &witness, "reward"), &10_i64.to_be_bytes()).unwrap();
    let sessions = SessionManager::new(root.clone()); let session = sessions.build_session().unwrap(); let facade = StateFacade::new(&session);
    assert!(apply_maintenance_block(&facade, 2, 10, &MaintenanceConfig { genesis_votes: vec![], witness_sort_optimized: true }).is_err());
    assert_eq!(facade.witness(&witness).unwrap().unwrap().vote_count, 10); assert_eq!(facade.votes().unwrap().len(), 1); assert!(facade.delegation(&delegation_key(2, &witness, "vi")).is_none());
    drop(session); drop(sessions); drop(root); fs::remove_dir_all(directory).unwrap();
}

#[test]
fn block_one_only_rounds_time_and_sets_state_flag() {
    let directory = path(); let root = StateStore::new(manager().open_store(&directory).unwrap());
    root.store(StoreKind::WitnessSchedule).put(value::ACTIVE_WITNESSES_KEY, &[]).unwrap();
    for (name, value) in [("NEXT_MAINTENANCE_TIME", 10_000), ("MAINTENANCE_TIME_INTERVAL", 9_000), ("CURRENT_CYCLE_NUMBER", 0)] { put_long(&root, name, value); }
    root.store(StoreKind::DynamicProperties).put(dynamic::key("STATE_FLAG").unwrap(), &0_i32.to_be_bytes()).unwrap();
    let sessions = SessionManager::new(root.clone()); let session = sessions.build_session().unwrap(); let facade = StateFacade::new(&session);
    let outcome = apply_maintenance_block(&facade, 1, 10_000, &MaintenanceConfig { genesis_votes: vec![], witness_sort_optimized: false }).unwrap();
    assert!(!outcome.applied); assert_eq!(outcome.next_maintenance_time, 19_000); assert_eq!(facade.dynamic_int("STATE_FLAG").unwrap(), 1);
    drop(session); drop(sessions); drop(root); fs::remove_dir_all(directory).unwrap();
}
