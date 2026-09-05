use std::{collections::{BTreeMap, BTreeSet}, fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

use prost::Message;
use serde_json::Value;
use tron_execution::{ActuatorRegistry, ActuatorResult, ExecutionConfig, RegistryError, ValidationContext};
use tron_protocol::protocol::{transaction::{result::Code, Contract, Result as TransactionResult}, Account, Proposal};
use tron_state::{Session, SessionManager, StateStore, StoreEntry, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

const CAPTURE: &str = include_str!("../../../../../docs/oracles/c013-java-owned-real.v1.json");
const OWNED: &[&str] = &["CancelAllUnfreezeV2Actuator", "ClearABIContractActuator", "DelegateResourceActuator", "ExchangeCreateActuator", "ExchangeInjectActuator", "ExchangeTransactionActuator", "ExchangeWithdrawActuator", "FreezeBalanceActuator", "FreezeBalanceV2Actuator", "MarketCancelOrderActuator", "MarketSellAssetActuator", "ProposalApproveActuator", "ProposalCreateActuator", "ProposalDeleteActuator", "UnDelegateResourceActuator", "UnfreezeBalanceActuator", "UnfreezeBalanceV2Actuator", "UpdateBrokerageActuator", "UpdateEnergyLimitContractActuator", "UpdateSettingContractActuator", "WithdrawBalanceActuator", "WithdrawExpireUnfreezeActuator"];

fn hex(value: &str) -> Vec<u8> { value.as_bytes().chunks_exact(2).map(|pair| (digit(pair[0]) << 4) | digit(pair[1])).collect() }
fn digit(value: u8) -> u8 { match value { b'0'..=b'9' => value - b'0', b'a'..=b'f' => value - b'a' + 10, b'A'..=b'F' => value - b'A' + 10, _ => panic!("invalid hex digit") } }
fn bytes(value: &Value, field: &str) -> Option<Vec<u8>> { value.get(field).and_then(Value::as_str).map(hex) }
fn store(name: &str) -> StoreKind { StoreKind::ALL.into_iter().find(|kind| kind.db_name() == name).unwrap_or_else(|| panic!("unknown Java store {name}")) }
fn entry(value: Option<Vec<u8>>) -> StoreEntry { value.map_or(StoreEntry::Absent, StoreEntry::Present) }
fn error_message(error: &Value) -> Option<Vec<u8>> { error.as_object().map(|_| bytes(error, "message_utf8_hex").unwrap_or_default()) }
fn assert_exact_error(stable_id: &str, ordinal: u64, actual: Option<Vec<u8>>, java: Option<&[u8]>, label: &str) -> bool {
    match (stable_id, ordinal) {
        // The pinned Java test supplies indistinguishable store bytes here, but its
        // mocked property getter throws instead of returning the registry default.
        ("TCASE-F290E71C34309F8A", 7) => {
            let rust = Some(b"This value[MAX_CREATE_ACCOUNT_TX_SIZE] is only allowed to be greater than or equal to 500 and less than or equal to 10000!".as_slice());
            let expected_java = Some(b"Bad chain parameter id [MAX_CREATE_ACCOUNT_TX_SIZE]".as_slice());
            assert_eq!(java, expected_java, "{label} reviewed Java decision drift");
            assert_eq!(actual.as_deref(), rust, "{label} reviewed Rust decision drift");
            true
        }
        _ => { assert_eq!(actual.as_deref(), java, "{label} exact error"); false }
    }
}
fn assert_entry_eq(kind: StoreKind, actual: Option<Vec<u8>>, expected: Option<Vec<u8>>, label: &str) {
    if kind == StoreKind::Account {
        let actual = actual.map(|value| Account::decode(value.as_slice()).unwrap());
        let expected = expected.map(|value| Account::decode(value.as_slice()).unwrap());
        assert_eq!(actual, expected, "{label}");
    } else if kind == StoreKind::Proposal {
        let actual = actual.map(|value| Proposal::decode(value.as_slice()).unwrap());
        let expected = expected.map(|value| Proposal::decode(value.as_slice()).unwrap());
        assert_eq!(actual, expected, "{label}");
    } else {
        assert_eq!(actual, expected, "{label}");
    }
}
fn decoded_result(value: Option<&Value>, label: &str) -> TransactionResult {
    let Some(value) = value.filter(|value| !value.is_null()) else { return TransactionResult::default() };
    let data = bytes(value, "data_hex").unwrap_or_else(|| panic!("{label} missing result data_hex"));
    let decoded = TransactionResult::decode(data.as_slice()).unwrap_or_else(|error| panic!("{label} invalid result data_hex: {error}"));
    assert_eq!(decoded.fee, value["fee"].as_i64().unwrap(), "{label} result fee JSON mirror");
    assert_eq!(i64::from(decoded.ret), value["ret_number"].as_i64().unwrap(), "{label} result ret JSON mirror");
    assert_eq!(decoded.asset_issue_id.as_bytes(), bytes(value, "asset_issue_id_hex").unwrap(), "{label} result asset ID JSON mirror");
    decoded
}
fn result(value: Option<&Value>, label: &str) -> ActuatorResult {
    let value = decoded_result(value, label);
    assert_eq!(value.contract_ret, 0, "{label} unsupported nondefault contract_ret");
    assert_eq!(value.shielded_transaction_fee, 0, "{label} unsupported nondefault shielded_transaction_fee");
    ActuatorResult {
        fee: value.fee,
        code: Code::try_from(value.ret).unwrap_or_else(|_| panic!("{label} unknown result code {}", value.ret)),
        message: Vec::new(),
        asset_issue_id: value.asset_issue_id.into_bytes(),
        exchange_id: value.exchange_id,
        withdraw_amount: value.withdraw_amount,
        unfreeze_amount: value.unfreeze_amount,
        exchange_inject_another_amount: value.exchange_inject_another_amount,
        exchange_withdraw_another_amount: value.exchange_withdraw_another_amount,
        exchange_received_amount: value.exchange_received_amount,
        order_id: value.order_id,
        order_details: value.order_details,
        withdraw_expire_amount: value.withdraw_expire_amount,
        cancel_unfreeze_v2_amount: value.cancel_unfreeze_v2_amount.into_iter().collect(),
        deltas: Vec::new(),
    }
}
fn assert_result_eq(actual: &ActuatorResult, expected: &ActuatorResult, label: &str) {
    assert_eq!(actual.fee, expected.fee, "{label} result fee");
    assert_eq!(actual.code, expected.code, "{label} result code");
    assert_eq!(actual.message, expected.message, "{label} result message");
    assert_eq!(actual.withdraw_amount, expected.withdraw_amount, "{label} result withdraw_amount");
    assert_eq!(actual.unfreeze_amount, expected.unfreeze_amount, "{label} result unfreeze_amount");
    assert_eq!(actual.asset_issue_id, expected.asset_issue_id, "{label} result asset_issue_id");
    assert_eq!(actual.exchange_id, expected.exchange_id, "{label} result exchange_id");
    assert_eq!(actual.exchange_inject_another_amount, expected.exchange_inject_another_amount, "{label} result exchange_inject_another_amount");
    assert_eq!(actual.exchange_withdraw_another_amount, expected.exchange_withdraw_another_amount, "{label} result exchange_withdraw_another_amount");
    assert_eq!(actual.exchange_received_amount, expected.exchange_received_amount, "{label} result exchange_received_amount");
    assert_eq!(actual.order_id, expected.order_id, "{label} result order_id");
    assert_eq!(actual.order_details, expected.order_details, "{label} result ordered order_details");
    assert_eq!(actual.withdraw_expire_amount, expected.withdraw_expire_amount, "{label} result withdraw_expire_amount");
    assert_eq!(actual.cancel_unfreeze_v2_amount, expected.cancel_unfreeze_v2_amount, "{label} result cancel_unfreeze_v2_amount map");
}
fn path(id: &str, ordinal: u64, mode: &str) -> PathBuf { std::env::temp_dir().join(format!("c013-capture-{id}-{ordinal}-{mode}-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())) }
fn create_manager(id: &str, ordinal: u64, mode: &str) -> (PathBuf, SessionManager) {
    let path = path(id, ordinal, mode);
    let requirements = OpenRequirements { identity: StorageIdentity { network: "c013-capture".into(), genesis: "00".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()] };
    let manager = SessionManager::new(StateStore::new(StorageManager::new(requirements).open_store(&path).unwrap()));
    (path, manager)
}
fn config(member: &Value, invocation: &Value) -> ExecutionConfig {
    let mut config = ExecutionConfig::default();
    for prior in member["invocations"].as_array().unwrap() {
    if error_message(&invocation["error"]).is_some_and(|message| String::from_utf8_lossy(&message).contains("guard representative")) {
        if let Some(owner) = invocation["read_dependencies"].as_array().unwrap().iter().find(|row| row["store"] == "account").and_then(|row| bytes(row, "key_hex")) { config.guard_representatives.insert(owner); }
    }
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
        let kind = store(row["store"].as_str().unwrap());
        let key = bytes(row, "key_hex").unwrap();
        assert_entry_eq(kind, session.store(kind).get(&key), bytes(row, "after_hex"), &format!("{label} final {}:{}", kind.db_name(), row["key_hex"]));
    }
}
fn assert_deltas(actual: &ActuatorResult, invocation: &Value, label: &str) {
    let expected = invocation["ordered_store_deltas"].as_array().unwrap();
    let expected_keys: Vec<_> = expected.iter().map(|row| (store(row["store"].as_str().unwrap()), bytes(row, "key_hex").unwrap())).collect();
    let actual_keys: Vec<_> = actual.deltas.iter().map(|delta| (delta.store, delta.key.clone())).collect();
    assert_eq!(actual_keys.len(), expected_keys.len(), "{label} ordered delta count");
    assert_eq!(actual_keys, expected_keys, "{label} ordered delta keys/count");
    for (actual, expected) in actual.deltas.iter().zip(expected) {
        assert_eq!(actual.before, entry(bytes(expected, "before_hex")), "{label} delta before");
        if actual.store == StoreKind::Account {
            let actual_after = match &actual.after { StoreEntry::Present(value) => Some(Account::decode(value.as_slice()).unwrap()), StoreEntry::Absent => None };
            let expected_after = bytes(expected, "after_hex").map(|value| Account::decode(value.as_slice()).unwrap());
            assert_eq!(actual_after, expected_after, "{label} delta after");
        } else if actual.store == StoreKind::Proposal {
            let actual_after = match &actual.after { StoreEntry::Present(value) => Some(Proposal::decode(value.as_slice()).unwrap()), StoreEntry::Absent => None };
            let expected_after = bytes(expected, "after_hex").map(|value| Proposal::decode(value.as_slice()).unwrap());
            assert_eq!(actual_after, expected_after, "{label} delta after");
        } else {
            assert_eq!(actual.after, entry(bytes(expected, "after_hex")), "{label} delta after {}:{:?}", actual.store.db_name(), actual.key);
        }
    }
}
fn observation_digest(invocation: &Value) -> String {
    let mut value = invocation.clone();
    let object = value.as_object_mut().unwrap();
    for field in ["invocation_id", "ordinal", "completion_ordinal", "actuator_instance_ordinal", "lifecycle_reference"] { object.remove(field); }
    value.to_string()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayStats { pub captured_invocations: usize, pub total_unique: usize, pub executed_unique: usize, pub explicit_exclusions: usize, pub null_boundaries: usize }

fn belongs_to(family: &str, actuator: &str) -> bool {
    match family {
        "resource" => matches!(actuator, "CancelAllUnfreezeV2Actuator" | "DelegateResourceActuator" | "FreezeBalanceActuator" | "FreezeBalanceV2Actuator" | "UnDelegateResourceActuator" | "UnfreezeBalanceActuator" | "UnfreezeBalanceV2Actuator" | "WithdrawBalanceActuator" | "WithdrawExpireUnfreezeActuator"),
        "proposal_exchange" => matches!(actuator, "ProposalApproveActuator" | "ProposalCreateActuator" | "ProposalDeleteActuator" | "ExchangeCreateActuator" | "ExchangeInjectActuator" | "ExchangeTransactionActuator" | "ExchangeWithdrawActuator"),
        "market_misc" => matches!(actuator, "ClearABIContractActuator" | "MarketCancelOrderActuator" | "MarketSellAssetActuator" | "UpdateBrokerageActuator" | "UpdateEnergyLimitContractActuator" | "UpdateSettingContractActuator"),
        _ => false,
    }
}
pub fn prove_zero_invocation_methods(family: &str) -> usize {
    let expected: BTreeSet<&str> = match family {
        "resource" => ["TCASE-210D49DE1A14B238", "TCASE-2BA2C2171063B228", "TCASE-3A9B9DC369A80822", "TCASE-3CBB27945C893520", "TCASE-82CB6D9DCD5CC7CA", "TCASE-C3CF875CAFED108E", "TCASE-D40210190A4A66D3", "TCASE-ECC92CB6CBAB206D"].into_iter().collect(),
        "proposal_exchange" => ["TCASE-0AE4A9B2569DCE1D", "TCASE-6F0FEF76E6B542BB", "TCASE-FDA493C6EC872AA0"].into_iter().collect(),
        "market_misc" => ["TCASE-BF3FB3CA02E606D4", "TCASE-D6827BD24AC5F319"].into_iter().collect(),
        _ => panic!("unknown C013 family {family}"),
    };
    let document: Value = serde_json::from_str(CAPTURE).unwrap();
    let actual: BTreeSet<&str> = document["members"].as_array().unwrap().iter()
        .filter(|member| member["invocations"].as_array().unwrap().is_empty())
        .filter_map(|member| member["variant_id"].as_str())
        .filter(|stable_id| expected.contains(stable_id))
        .collect();
    assert_eq!(actual, expected, "zero-invocation Java helper disposition drift");
    actual.len()
}

pub fn replay(family: &str) -> ReplayStats {
    let document: Value = serde_json::from_str(CAPTURE).unwrap();
    let mut mapped_ids = BTreeSet::new(); let mut replayed_unique = BTreeSet::new(); let mut selected = 0usize; let mut replayed = 0usize; let mut null_boundaries = 0usize; let mut provisional_errors = 0usize; let mut error_decisions = BTreeSet::new(); let explicit_exclusions = 0usize;
    for member in document["members"].as_array().unwrap() {
        let stable_id = member["variant_id"].as_str().unwrap();
        for invocation in member["invocations"].as_array().unwrap() {
            let class = invocation["actuator_class"].as_str().unwrap(); let short = class.rsplit('.').next().unwrap();
            if !OWNED.contains(&short) { continue; }
            selected += 1; mapped_ids.insert(stable_id);
            let digest = observation_digest(invocation); replayed_unique.insert(digest.clone());
            if !belongs_to(family, short) { continue; }
            replayed += 1; let ordinal = invocation["ordinal"].as_u64().unwrap(); let label = format!("{stable_id}/invocation/{ordinal:03}");
            let expected_error = error_message(&invocation["error"]);
            let missing_manager = matches!(expected_error.as_deref(), Some(b"No dbManager!") | Some(b"No account store or dynamic store!") | Some(b"No account store or witness store!") | Some(b"No account store or contract store!"));
            let missing_contract = invocation["contract"]["contract_hex"].is_null();
            if missing_manager || missing_contract {
                null_boundaries += 1;
                assert!(invocation["read_dependencies"].as_array().unwrap().is_empty(), "{label} null boundary read state");
                let contract = (!missing_contract).then(|| Contract::decode(bytes(&invocation["contract"], "contract_hex").unwrap().as_slice()).unwrap());
                let manager_error = expected_error.as_deref().and_then(|value| std::str::from_utf8(value).ok()).unwrap_or("No account store or dynamic store!");
                let (directory, manager) = create_manager(stable_id, ordinal, "null-boundary"); let mut root = manager.build_session().unwrap(); seed(&root, member, invocation); root.commit().unwrap(); manager.flush_committed().unwrap();
                let mut execution = manager.build_session().unwrap(); let actual_result = ActuatorResult::default();
                let actual = ActuatorRegistry::empty().validate_optional((!missing_manager).then_some(&execution), contract.as_ref(), manager_error, config(member, invocation));
                if assert_exact_error(stable_id, ordinal, actual.err().and_then(|error| match error { RegistryError::Provider(message) => Some(message.into_bytes()), _ => None }), expected_error.as_deref(), &format!("{label} construction")) { error_decisions.insert((stable_id, ordinal)); }
                assert_eq!(actual_result, ActuatorResult::default(), "{label} null boundary result"); assert!(actual_result.deltas.is_empty(), "{label} null boundary deltas");
                execution.commit().unwrap(); drop(execution); let mut reopened = manager.build_session().unwrap(); assert_rollback(&manager, member, invocation, &format!("{label} commit/reopen")); reopened.revoke().unwrap();
                let mut rollback = manager.build_session().unwrap(); let _ = ActuatorRegistry::empty().validate_optional((!missing_manager).then_some(&rollback), contract.as_ref(), manager_error, config(member, invocation)); rollback.revoke().unwrap(); assert_rollback(&manager, member, invocation, &format!("{label} rollback"));
                drop(manager); fs::remove_dir_all(directory).unwrap(); continue;
            }
            let contract_bytes = bytes(&invocation["contract"], "contract_hex").unwrap(); let contract = Contract::decode(contract_bytes.as_slice()).unwrap(); assert_eq!(contract.encode_to_vec(), contract_bytes, "{label} contract");
            let (directory, manager) = create_manager(stable_id, ordinal, "commit"); let mut initial = manager.build_session().unwrap(); seed(&initial, member, invocation); initial.commit().unwrap(); manager.flush_committed().unwrap();
            let actuator = match ActuatorRegistry::empty().actuator(&contract) {
                Ok(actuator) => actuator,
                Err(RegistryError::Provider(message)) => { if assert_exact_error(stable_id, ordinal, Some(message.into_bytes()), expected_error.as_deref(), &format!("{label} construction")) { error_decisions.insert((stable_id, ordinal)); } assert_rollback(&manager, member, invocation, &label); drop(manager); fs::remove_dir_all(directory).unwrap(); continue; }
                Err(error) => panic!("{label} actuator construction: {error:?}"),
            };
            let mut execution = manager.build_session().unwrap();
            if invocation["phase"] == "validate" {
                let actual = actuator.validate(&ValidationContext::new(&execution, config(member, invocation), None));
                if assert_exact_error(stable_id, ordinal, actual.as_ref().err().map(|error| error.message.as_bytes().to_vec()), expected_error.as_deref(), &format!("{label} validation")) { error_decisions.insert((stable_id, ordinal)); }
            } else {
                let has_result = !invocation["result_after"].is_null();
                let initial_result = result(invocation.get("result_before"), &format!("{label} before"));
                if expected_error.is_some() && has_result {
                    provisional_errors += 1;
                    let provisional = ActuatorRegistry::empty().execute_body_provisionally(&contract, &execution, initial_result.clone(), config(member, invocation)).unwrap();
                    if assert_exact_error(stable_id, ordinal, provisional.error.as_ref().map(|error| error.message.as_bytes().to_vec()), expected_error.as_deref(), &format!("{label} provisional execution")) { error_decisions.insert((stable_id, ordinal)); }
                    let expected = result(invocation.get("result_after"), &format!("{label} after"));
                    assert_result_eq(&provisional.result, &expected, &label);
                    assert_deltas(&provisional.result, invocation, &label);
                    assert_eq!(provisional.deltas, provisional.result.deltas, "{label} provisional delta channel");
                    assert_final(provisional.session(), invocation, &format!("{label} provisional"));
                    provisional.revoke().unwrap();
                    assert_rollback(&manager, member, invocation, &format!("{label} provisional revoke"));

                    let mut atomic_result = initial_result;
                    let actual = actuator.execute_without_validation(&execution, Some(&mut atomic_result), config(member, invocation));
                    if assert_exact_error(stable_id, ordinal, actual.as_ref().err().map(|error| error.message.as_bytes().to_vec()), expected_error.as_deref(), &format!("{label} atomic execution")) { error_decisions.insert((stable_id, ordinal)); }
                    assert_eq!(atomic_result, ActuatorResult { code: tron_protocol::protocol::transaction::result::Code::Failed, ..ActuatorResult::default() }, "{label} production atomic failed result");
                    for ((kind,key),value) in initial_rows(member, invocation) { assert_eq!(execution.store(kind).get(&key), value, "{label} production atomic rollback {}", kind.db_name()); }
                } else {
                    let mut actual_result = initial_result;
                    let actual = actuator.execute_without_validation(&execution, has_result.then_some(&mut actual_result), config(member, invocation));
                    if assert_exact_error(stable_id, ordinal, actual.as_ref().err().map(|error| error.message.as_bytes().to_vec()), expected_error.as_deref(), &format!("{label} execution")) { error_decisions.insert((stable_id, ordinal)); }
                    if actual.is_ok() {
                        if has_result { let expected = result(invocation.get("result_after"), &format!("{label} after")); assert_result_eq(&actual_result, &expected, &label); assert_deltas(&actual_result, invocation, &label); }
                        assert_final(&execution, invocation, &label);
                    } else {
                        for ((kind,key),value) in initial_rows(member, invocation) { assert_eq!(execution.store(kind).get(&key), value, "{label} atomic error rollback {}", kind.db_name()); }
                    }
                }
            }
            execution.commit().unwrap(); drop(execution); let mut reopened = manager.build_session().unwrap();
            if expected_error.is_none() { assert_final(&reopened, invocation, &format!("{label} commit/reopen")); } else { for ((kind,key),value) in initial_rows(member, invocation) { assert_eq!(reopened.store(kind).get(&key), value, "{label} error commit/reopen {}", kind.db_name()); } }
            reopened.revoke().unwrap(); drop(manager); fs::remove_dir_all(&directory).unwrap();

            let (directory, manager) = create_manager(stable_id, ordinal, "rollback"); let mut root = manager.build_session().unwrap(); seed(&root, member, invocation); root.commit().unwrap(); manager.flush_committed().unwrap(); let mut child = manager.build_session().unwrap(); let actuator = ActuatorRegistry::empty().actuator(&contract).unwrap(); if invocation["phase"] == "validate" { let _ = actuator.validate(&ValidationContext::new(&child, config(member, invocation), None)); } else { let mut actual_result = result(invocation.get("result_before"), &format!("{label} rollback before")); let _ = actuator.execute_without_validation(&child, (!invocation["result_after"].is_null()).then_some(&mut actual_result), config(member, invocation)); } child.revoke().unwrap(); assert_rollback(&manager, member, invocation, &format!("{label} explicit revoke")); drop(manager); fs::remove_dir_all(directory).unwrap();
        }
    }
    let expected_provisional_errors = match family { "resource" => 0, "proposal_exchange" => 2, "market_misc" => 1, _ => unreachable!() };
    assert_eq!(provisional_errors, expected_provisional_errors, "{family} captured provisional error coverage");
    assert_eq!(error_decisions.len(), usize::from(family == "proposal_exchange"), "{family} reviewed exact-error decision count");
    assert_eq!(selected, 926); assert_eq!(mapped_ids.len() + 13, 370); assert_eq!(replayed_unique.len() + explicit_exclusions, 868); assert_eq!(explicit_exclusions, 0); assert!(replayed > 0, "no {family} observations replayed");
    ReplayStats { captured_invocations: selected, total_unique: replayed_unique.len(), executed_unique: replayed, explicit_exclusions, null_boundaries }
}
