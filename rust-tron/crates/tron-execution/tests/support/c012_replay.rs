use std::{collections::{BTreeMap, BTreeSet}, fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

use prost::Message;
use serde_json::Value;
use tron_execution::{ActuatorRegistry, ActuatorResult, ExecutionConfig, RegistryError, ValidationContext};
use tron_protocol::protocol::{transaction::{result::Code, Contract}, Account};
use tron_state::{Session, SessionManager, StateStore, StoreEntry, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

const CAPTURE: &str = include_str!("../../../../../docs/oracles/c012-java-owned-real.v1.json");
const OWNED: &[&str] = &["AssetIssueActuator", "ParticipateAssetIssueActuator", "TransferAssetActuator", "UpdateAssetActuator", "UnfreezeAssetActuator", "WitnessCreateActuator", "WitnessUpdateActuator", "VoteWitnessActuator"];

fn hex(value: &str) -> Vec<u8> { value.as_bytes().chunks_exact(2).map(|pair| (digit(pair[0]) << 4) | digit(pair[1])).collect() }
fn digit(value: u8) -> u8 { match value { b'0'..=b'9' => value - b'0', b'a'..=b'f' => value - b'a' + 10, b'A'..=b'F' => value - b'A' + 10, _ => panic!("invalid hex digit") } }
fn bytes(value: &Value, field: &str) -> Option<Vec<u8>> { value.get(field).and_then(Value::as_str).map(hex) }
fn store(name: &str) -> StoreKind { StoreKind::ALL.into_iter().find(|kind| kind.db_name() == name).unwrap_or_else(|| panic!("unknown Java store {name}")) }
fn entry(value: Option<Vec<u8>>) -> StoreEntry { value.map_or(StoreEntry::Absent, StoreEntry::Present) }
fn error_message(error: &Value) -> Option<Vec<u8>> { error.as_object().map(|_| bytes(error, "message_utf8_hex").unwrap_or_default()) }
fn result(value: Option<&Value>) -> ActuatorResult {
    let Some(value) = value.filter(|value| !value.is_null()) else { return ActuatorResult::default() };
    ActuatorResult {
        fee: value["fee"].as_i64().unwrap(),
        code: if value["ret_number"].as_i64().unwrap() == 0 { Code::Sucess } else { Code::Failed },
        message: Vec::new(),
        asset_issue_id: bytes(value, "asset_issue_id_hex").unwrap(),
        deltas: Vec::new(),
    }
}
fn path(id: &str, ordinal: u64, mode: &str) -> PathBuf { std::env::temp_dir().join(format!("c012-capture-{id}-{ordinal}-{mode}-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())) }
fn create_manager(id: &str, ordinal: u64, mode: &str) -> (PathBuf, SessionManager) {
    let path = path(id, ordinal, mode);
    let requirements = OpenRequirements { identity: StorageIdentity { network: "c012-capture".into(), genesis: "00".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()] };
    let manager = SessionManager::new(StateStore::new(StorageManager::new(requirements).open_store(&path).unwrap()));
    (path, manager)
}
fn config(member: &Value, invocation: &Value) -> ExecutionConfig {
    let mut config = ExecutionConfig::default();
    for prior in member["invocations"].as_array().unwrap() {
        if prior["actuator_instance_ordinal"] != invocation["actuator_instance_ordinal"] || prior["ordinal"].as_u64().unwrap() > invocation["ordinal"].as_u64().unwrap() { continue; }
        for row in prior["read_dependencies"].as_array().unwrap() {
            if row["store"] == "account" { if let Some(value) = bytes(row, "value_hex") { if let Ok(account) = Account::decode(value.as_slice()) { if account.account_name == b"Blackhole" { config.blackhole_address = bytes(row, "key_hex").unwrap(); } } } }
        }
    }
    config
}
fn initial_rows(member: &Value, invocation: &Value) -> BTreeMap<(StoreKind, Vec<u8>), Option<Vec<u8>>> {
    let mut rows = BTreeMap::new();
    let instance = invocation["actuator_instance_ordinal"].as_u64().unwrap();
    let ordinal = invocation["ordinal"].as_u64().unwrap();
    for prior in member["invocations"].as_array().unwrap() {
        if prior["actuator_instance_ordinal"].as_u64().unwrap() != instance || prior["ordinal"].as_u64().unwrap() > ordinal { continue; }
        for row in prior["read_dependencies"].as_array().unwrap() {
            rows.insert((store(row["store"].as_str().unwrap()), bytes(row, "key_hex").unwrap()), bytes(row, "value_hex"));
        }
    }
    for row in invocation["ordered_store_deltas"].as_array().unwrap() {
        rows.insert((store(row["store"].as_str().unwrap()), bytes(row, "key_hex").unwrap()), bytes(row, "before_hex"));
    }
    rows
}
fn seed(session: &Session, member: &Value, invocation: &Value) {
    for ((kind, key), value) in initial_rows(member, invocation) { match value { Some(value) => session.store(kind).put(&key, &value).unwrap(), None => session.store(kind).delete(&key).unwrap() } }
}
fn assert_rollback(manager: &SessionManager, member: &Value, invocation: &Value, label: &str) {
    for ((kind, key), value) in initial_rows(member, invocation) { assert_eq!(manager.durable_store(kind).get(&key), value, "{label} rollback {}", kind.db_name()); }
}
fn assert_final(session: &Session, invocation: &Value, label: &str) {
    for row in invocation["ordered_store_deltas"].as_array().unwrap() {
        let kind = store(row["store"].as_str().unwrap()); let key = bytes(row, "key_hex").unwrap();
        assert_eq!(session.store(kind).get(&key), bytes(row, "after_hex"), "{label} final {}:{}", kind.db_name(), row["key_hex"]);
    }
}
fn assert_deltas(actual: &ActuatorResult, invocation: &Value, label: &str) {
    let expected = invocation["ordered_store_deltas"].as_array().unwrap();
    assert_eq!(actual.deltas.len(), expected.len(), "{label} ordered delta count: {:?}", actual.deltas);
    for (actual, expected) in actual.deltas.iter().zip(expected) {
        assert_eq!(actual.store, store(expected["store"].as_str().unwrap()), "{label} delta store");
        assert_eq!(actual.key, bytes(expected, "key_hex").unwrap(), "{label} delta key");
        assert_eq!(actual.before, entry(bytes(expected, "before_hex")), "{label} delta before");
        assert_eq!(actual.after, entry(bytes(expected, "after_hex")), "{label} delta after");
    }
}
fn observation_digest(invocation: &Value) -> String {
    let mut value = invocation.clone();
    let object = value.as_object_mut().unwrap();
    for field in ["invocation_id", "ordinal", "completion_ordinal", "actuator_instance_ordinal", "lifecycle_reference"] { object.remove(field); }
    value.to_string()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayStats { pub replayed_unique: usize, pub explicit_exclusions: usize, pub null_boundaries: usize }

pub fn replay(family: &str) -> ReplayStats {
    let document: Value = serde_json::from_str(CAPTURE).unwrap();
    let mut mapped_ids = BTreeSet::new(); let mut seen = BTreeSet::new(); let mut replayed_unique = BTreeSet::new(); let mut selected = 0usize; let mut replayed = 0usize; let mut null_boundaries = 0usize; let explicit_exclusions = 0usize;
    for member in document["members"].as_array().unwrap() {
        let stable_id = member["variant_id"].as_str().unwrap();
        for invocation in member["invocations"].as_array().unwrap() {
            let class = invocation["actuator_class"].as_str().unwrap(); let short = class.rsplit('.').next().unwrap();
            if !OWNED.contains(&short) { continue; }
            selected += 1; mapped_ids.insert(stable_id);
            let digest = observation_digest(invocation); replayed_unique.insert(digest.clone());
            if !short.contains(family) || !seen.insert(digest) { continue; }
            replayed += 1; let ordinal = invocation["ordinal"].as_u64().unwrap(); let label = format!("{stable_id}/invocation/{ordinal:03}");
            let expected_error = error_message(&invocation["error"]);
            let missing_manager = matches!(expected_error.as_deref(), Some(b"No account store or dynamic store!") | Some(b"No account store or witness store!"));
            let missing_contract = invocation["contract"]["contract_hex"].is_null();
            if missing_manager || missing_contract {
                null_boundaries += 1;
                assert!(invocation["read_dependencies"].as_array().unwrap().is_empty(), "{label} null boundary read state");
                let contract = (!missing_contract).then(|| Contract::decode(bytes(&invocation["contract"], "contract_hex").unwrap().as_slice()).unwrap());
                let manager_error = expected_error.as_deref().and_then(|value| std::str::from_utf8(value).ok()).unwrap_or("No account store or dynamic store!");
                let (directory, manager) = create_manager(stable_id, ordinal, "null-boundary"); let mut root = manager.build_session().unwrap(); seed(&root, member, invocation); root.commit().unwrap(); manager.flush_committed().unwrap();
                let mut execution = manager.build_session().unwrap(); let actual_result = ActuatorResult::default();
                let actual = ActuatorRegistry::empty().validate_optional((!missing_manager).then_some(&execution), contract.as_ref(), manager_error, config(member, invocation));
                assert_eq!(actual.err().and_then(|error| match error { RegistryError::Provider(message) => Some(message.into_bytes()), _ => None }), expected_error, "{label} null boundary error");
                assert_eq!(actual_result, ActuatorResult::default(), "{label} null boundary result"); assert!(actual_result.deltas.is_empty(), "{label} null boundary deltas");
                execution.commit().unwrap(); drop(execution); let mut reopened = manager.build_session().unwrap(); assert_rollback(&manager, member, invocation, &format!("{label} commit/reopen")); reopened.revoke().unwrap();
                let mut rollback = manager.build_session().unwrap(); let _ = ActuatorRegistry::empty().validate_optional((!missing_manager).then_some(&rollback), contract.as_ref(), manager_error, config(member, invocation)); rollback.revoke().unwrap(); assert_rollback(&manager, member, invocation, &format!("{label} rollback"));
                drop(manager); fs::remove_dir_all(directory).unwrap(); continue;
            }
            let contract_bytes = bytes(&invocation["contract"], "contract_hex").unwrap(); let contract = Contract::decode(contract_bytes.as_slice()).unwrap(); assert_eq!(contract.encode_to_vec(), contract_bytes, "{label} contract");
            let (directory, manager) = create_manager(stable_id, ordinal, "commit"); let mut initial = manager.build_session().unwrap(); seed(&initial, member, invocation); initial.commit().unwrap(); manager.flush_committed().unwrap();
            let actuator = match ActuatorRegistry::empty().actuator(&contract) {
                Ok(actuator) => actuator,
                Err(RegistryError::Provider(message)) => { assert_eq!(Some(message.into_bytes()), error_message(&invocation["error"]), "{label} construction error"); assert_rollback(&manager, member, invocation, &label); drop(manager); fs::remove_dir_all(directory).unwrap(); continue; }
                Err(error) => panic!("{label} actuator construction: {error:?}"),
            };
            let mut execution = manager.build_session().unwrap();
            if invocation["phase"] == "validate" {
                let actual = actuator.validate(&ValidationContext::new(&execution, config(member, invocation), None));
                assert_eq!(actual.as_ref().err().map(|error| error.message.as_bytes().to_vec()), expected_error, "{label} validation error");
            } else {
                let has_result = !invocation["result_after"].is_null(); let mut actual_result = result(invocation.get("result_before"));
                let actual = actuator.execute(&execution, has_result.then_some(&mut actual_result), config(member, invocation));
                assert_eq!(actual.as_ref().err().map(|error| error.message.as_bytes().to_vec()), expected_error, "{label} execution error");
                if has_result { let expected = result(invocation.get("result_after")); assert_eq!((actual_result.code, actual_result.fee, &actual_result.message, &actual_result.asset_issue_id), (expected.code, expected.fee, &expected.message, &expected.asset_issue_id), "{label} result"); assert_deltas(&actual_result, invocation, &label); }
                assert_final(&execution, invocation, &label);
            }
            execution.commit().unwrap(); drop(execution); let mut reopened = manager.build_session().unwrap(); assert_final(&reopened, invocation, &format!("{label} commit/reopen")); reopened.revoke().unwrap(); drop(manager); fs::remove_dir_all(&directory).unwrap();

            let (directory, manager) = create_manager(stable_id, ordinal, "rollback"); let mut root = manager.build_session().unwrap(); seed(&root, member, invocation); root.commit().unwrap(); manager.flush_committed().unwrap(); let mut child = manager.build_session().unwrap(); let actuator = ActuatorRegistry::empty().actuator(&contract).unwrap(); if invocation["phase"] == "validate" { let _ = actuator.validate(&ValidationContext::new(&child, config(member, invocation), None)); } else { let mut actual_result = result(invocation.get("result_before")); let _ = actuator.execute(&child, (!invocation["result_after"].is_null()).then_some(&mut actual_result), config(member, invocation)); } child.revoke().unwrap(); assert_rollback(&manager, member, invocation, &label); drop(manager); fs::remove_dir_all(&directory).unwrap();
        }
    }
    assert_eq!(selected, 239); assert_eq!(mapped_ids.len(), 133); assert_eq!(replayed_unique.len() + explicit_exclusions, 233); assert_eq!(explicit_exclusions, 0); assert!(replayed > 0, "no {family} observations replayed");
    ReplayStats { replayed_unique: replayed_unique.len(), explicit_exclusions, null_boundaries }
}
