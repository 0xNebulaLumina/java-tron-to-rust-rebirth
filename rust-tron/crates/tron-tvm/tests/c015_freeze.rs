use prost::Message;
use serde::Deserialize;
use std::{collections::HashSet, fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use tron_primitives::{Address20, Hash32, TransactionId, TronAddress21};
use tron_protocol::protocol::{Account, ResourceCode};
use tron_state::{SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};
use tron_tvm::{ContractResult, EnergyMeter, FrameContext, Interpreter, Memory, OperationRegistry, Program, Repository, Stack1024, TvmRules, Unlimited, Word};

#[derive(Deserialize)]
struct Oracle {
    schema: String,
    classification: String,
    replacement_license: String,
    legal_review: LegalReview,
    initial_state: InitialState,
    expected_resource_contracts: Expected,
    programs: Vec<FixtureProgram>,
}
#[derive(Deserialize)] struct LegalReview { decision: String, status: String }
#[derive(Deserialize)] struct InitialState { timestamp_ms: i64, minimum_frozen_days: i64, owner_balance: i64, total_net_weight: i64, total_energy_weight: i64 }
#[derive(Deserialize)] struct Expected { self_bandwidth: SelfBandwidth, delegated_energy_after_self_freeze: DelegatedEnergy, pre_expiry_unfreeze_result: u64, at_expiry_final_owner_balance: i64, invalid_overspend_result: u64, v2_queues: Vec<serde_json::Value> }
#[derive(Deserialize)] struct SelfBandwidth { balance: i64, frozen: i64, expiry_ms: i64, total_net_weight: i64 }
#[derive(Deserialize)] struct DelegatedEnergy { owner_balance: i64, owner_delegated: i64, receiver_acquired: i64, expiry_ms: i64, total_energy_weight: i64 }
#[derive(Deserialize)] struct FixtureProgram { id: String, program_hex: String, sha256: String }

fn decode(value: &str) -> Vec<u8> {
    (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap()).collect()
}
fn address(byte: u8) -> TronAddress21 { TronAddress21::new(0x41, Address20::from_array([byte; 20])) }
fn manager() -> (PathBuf, SessionManager) {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("c015-freeze-{nonce}"));
    let requirements = OpenRequirements { identity: StorageIdentity { network: "c015-freeze".into(), genesis: "00".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()] };
    let root = StateStore::new(StorageManager::new(requirements).open_store(&path).unwrap());
    (path, SessionManager::new(root))
}
fn frame(owner: TronAddress21) -> FrameContext {
    FrameContext { code_address: owner, context_address: owner, origin: owner, caller: address(0x11), input: Vec::new(), call_value: Word::ZERO, token_value: Word::ZERO, token_id: Word::ZERO, root_txid: TransactionId::new(Hash32::from_array([0x15; 32])), contract_version: 0, depth: 0, is_static: false }
}
fn run(code: &[u8], owner: TronAddress21, repository: &mut Repository<'_>, rules: &TvmRules) -> (ContractResult, Stack1024) {
    let registry = OperationRegistry::integration().unwrap();
    let interpreter = Interpreter::new(&registry, rules);
    let mut program = Program::new(code.to_vec());
    let mut stack = Stack1024::default();
    let mut memory = Memory::default();
    let mut meter = EnergyMeter::new(500_000).unwrap();
    let mut limiter = Unlimited;
    let mut trace = tron_tvm::NoTrace;
    let outcome = interpreter.run(&frame(owner), &mut program, &mut stack, &mut memory, repository, &mut meter, &mut limiter, &mut trace);
    (outcome.contract_result, stack)
}
fn fixture<'a>(oracle: &'a Oracle, id: &str) -> &'a FixtureProgram { oracle.programs.iter().find(|row| row.id == id).unwrap() }

#[test]
fn clean_room_record_is_explicit_distinct_and_independently_approved() {
    let oracle: Oracle = serde_json::from_str(include_str!("../../../../docs/oracles/c015-freeze-cleanroom.v1.json")).unwrap();
    assert_eq!(oracle.schema, "c015-freeze-cleanroom.v1");
    assert_eq!(oracle.classification, "clean_room");
    assert_eq!(oracle.replacement_license, "Apache-2.0");
    assert_eq!(oracle.legal_review.status, "approved");
    assert!(oracle.legal_review.decision.contains("original UNLICENSED artifact remains prohibited"));
    assert_eq!(oracle.programs.len(), 5);
    assert_eq!(oracle.programs.iter().map(|row| row.sha256.as_str()).collect::<HashSet<_>>().len(), 5);
    assert!(oracle.programs.iter().all(|row| !row.program_hex.is_empty() && row.sha256.len() == 64));
}

#[test]
fn independently_authored_programs_cover_freeze_expiry_unfreeze_and_resources() {
    let oracle: Oracle = serde_json::from_str(include_str!("../../../../docs/oracles/c015-freeze-cleanroom.v1.json")).unwrap();
    let (path, manager) = manager();
    let session = manager.build_session().unwrap();
    let owner = address(0x21); let receiver = address(0x22);
    session.store(StoreKind::Account).put(owner.as_bytes(), &Account { address: owner.as_bytes().to_vec(), balance: oracle.initial_state.owner_balance, ..Default::default() }.encode_to_vec()).unwrap();
    for (key, value) in [("LATEST_BLOCK_HEADER_TIMESTAMP", oracle.initial_state.timestamp_ms), ("TOTAL_NET_WEIGHT", oracle.initial_state.total_net_weight), ("TOTAL_ENERGY_WEIGHT", oracle.initial_state.total_energy_weight)] {
        session.store(StoreKind::DynamicProperties).put(tron_state::dynamic::key(key).unwrap(), &value.to_be_bytes()).unwrap();
    }
    session.store(StoreKind::DynamicProperties).put(tron_state::dynamic::key("MIN_FROZEN_TIME").unwrap(), &(oracle.initial_state.minimum_frozen_days as i32).to_be_bytes()).unwrap();
    let mut repository = Repository::from_session(&session);
    let rules = TvmRules { freeze: true, ..Default::default() };

    let (_, stack) = run(&decode(&fixture(&oracle, "freeze-self-bandwidth").program_hex), owner, &mut repository, &rules);
    assert_eq!(stack.peek(0).unwrap(), Word::ONE);
    let account = repository.account(&owner).unwrap().unwrap();
    assert_eq!(account.balance, oracle.expected_resource_contracts.self_bandwidth.balance);
    assert_eq!(account.frozen[0].frozen_balance, oracle.expected_resource_contracts.self_bandwidth.frozen);
    assert_eq!(account.frozen[0].expire_time, oracle.expected_resource_contracts.self_bandwidth.expiry_ms);
    assert_eq!(repository.dynamic_i64("TOTAL_NET_WEIGHT").unwrap(), Some(oracle.expected_resource_contracts.self_bandwidth.total_net_weight));
    assert!(account.frozen_v2.is_empty() && account.unfrozen_v2.is_empty() && oracle.expected_resource_contracts.v2_queues.is_empty());

    let (_, stack) = run(&decode(&fixture(&oracle, "freeze-expiry-seconds").program_hex), owner, &mut repository, &rules);
    assert_eq!(stack.peek(0).unwrap(), Word::from((oracle.expected_resource_contracts.self_bandwidth.expiry_ms / 1000) as u64));
    let (_, stack) = run(&decode(&fixture(&oracle, "unfreeze-self-bandwidth").program_hex), owner, &mut repository, &rules);
    assert_eq!(stack.peek(0).unwrap(), Word::from(oracle.expected_resource_contracts.pre_expiry_unfreeze_result));

    let (_, stack) = run(&decode(&fixture(&oracle, "freeze-delegated-energy").program_hex), owner, &mut repository, &rules);
    assert_eq!(stack.peek(0).unwrap(), Word::ONE);
    let source = repository.account(&owner).unwrap().unwrap(); let target = repository.account(&receiver).unwrap().unwrap();
    let expected = &oracle.expected_resource_contracts.delegated_energy_after_self_freeze;
    assert_eq!(source.balance, expected.owner_balance);
    assert_eq!(source.account_resource.as_ref().unwrap().delegated_frozen_balance_for_energy, expected.owner_delegated);
    assert_eq!(target.account_resource.as_ref().unwrap().acquired_delegated_frozen_balance_for_energy, expected.receiver_acquired);
    assert_eq!(repository.freeze_expire_time(&owner, &receiver, Word::from(ResourceCode::Energy as u64)).unwrap(), expected.expiry_ms);
    assert_eq!(repository.dynamic_i64("TOTAL_ENERGY_WEIGHT").unwrap(), Some(expected.total_energy_weight));

    repository.set_dynamic_i64("LATEST_BLOCK_HEADER_TIMESTAMP", expected.expiry_ms).unwrap();
    let (_, stack) = run(&decode(&fixture(&oracle, "unfreeze-self-bandwidth").program_hex), owner, &mut repository, &rules);
    assert_eq!(stack.peek(0).unwrap(), Word::ONE);
    assert_eq!(repository.unfreeze_legacy(&owner, &receiver, Word::ONE).unwrap(), Some(expected.owner_delegated));
    assert_eq!(repository.account(&owner).unwrap().unwrap().balance, oracle.expected_resource_contracts.at_expiry_final_owner_balance);
    assert!(!repository.freeze_legacy(&owner, &owner, Word::from(20_000_000u64), Word::ZERO).unwrap());
    assert_eq!(oracle.expected_resource_contracts.invalid_overspend_result, 0);
    drop(repository); drop(session); drop(manager); fs::remove_dir_all(path).unwrap();
}

#[test]
fn create2_fixture_installs_empty_runtime_once_and_collides_on_replay() {
    let oracle: Oracle = serde_json::from_str(include_str!("../../../../docs/oracles/c015-freeze-cleanroom.v1.json")).unwrap();
    let (path, manager) = manager(); let session = manager.build_session().unwrap(); let owner = address(0x21);
    session.store(StoreKind::Account).put(owner.as_bytes(), &Account { address: owner.as_bytes().to_vec(), balance: 1, ..Default::default() }.encode_to_vec()).unwrap();
    let mut repository = Repository::from_session(&session); let rules = TvmRules { constantinople: true, ..Default::default() };
    let code = decode(&fixture(&oracle, "create2-empty-init").program_hex);
    let (result, stack) = run(&code, owner, &mut repository, &rules); assert_eq!(result, ContractResult::Success);
    let created = stack.peek(0).unwrap().to_tron_address(); assert_ne!(stack.peek(0).unwrap(), Word::ZERO);
    assert_eq!(repository.code(&created), Some(Vec::new())); assert!(repository.account(&created).unwrap().is_some());
    let (result, stack) = run(&code, owner, &mut repository, &rules); assert_eq!(result, ContractResult::Success); assert_eq!(stack.peek(0).unwrap(), Word::ZERO);
    drop(repository); drop(session); drop(manager); fs::remove_dir_all(path).unwrap();
}
