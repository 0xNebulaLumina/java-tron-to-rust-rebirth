use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

use prost::Message;
use tron_execution::{Actuator, ActuatorRegistry, ActuatorResult, ExecutionConfig, TransferActuator, TRANSFER_FEE};
use tron_protocol::{google::protobuf::Any, protocol::{transaction::{result::Code, Contract}, Account, AccountType, SmartContract, TransferContract}};
use tron_state::{dynamic, SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

const ORACLE: &str = include_str!("../../../../docs/oracles/c012-transfer-real.v1.json");
const OWNER: [u8; 21] = hex_const("41548794500882809695a8a687866e76d4271a1abc");
const TO: [u8; 21] = hex_const("41abd4b9367799eaa3197fecb144eb71de1e049abc");
const MISSING: [u8; 21] = hex_const("41548794500882809695a8a687866e76d4271a3422");

const fn nibble(value: u8) -> u8 { match value { b'0'..=b'9' => value-b'0', b'a'..=b'f' => value-b'a'+10, _ => 0 } }
const fn hex_const<const N: usize>(value: &str) -> [u8; N] { let bytes=value.as_bytes(); let mut out=[0;N]; let mut i=0; while i<N { out[i]=(nibble(bytes[i*2])<<4)|nibble(bytes[i*2+1]); i+=1; } out }
fn hex(value: &str) -> Vec<u8> { value.as_bytes().chunks_exact(2).map(|pair|(nibble(pair[0])<<4)|nibble(pair[1])).collect() }
fn string_field<'a>(row: &'a str, key: &str) -> Option<&'a str> { let marker=format!("\"{key}\": "); let tail=row.split_once(&marker)?.1; if tail.starts_with("null") { None } else { let tail=tail.strip_prefix('"')?; Some(tail.split_once('"')?.0) } }
fn number_field(row: &str, key: &str) -> i64 { let marker=format!("\"{key}\": "); row.split_once(&marker).unwrap().1.split(|c:char| !c.is_ascii_digit() && c!='-').next().unwrap().parse().unwrap() }
fn object<'a>(row: &'a str, key: &str) -> &'a str { let marker=format!("\"{key}\": {{"); let tail=row.split_once(&marker).unwrap().1; tail.split_once("\n      }").unwrap().0 }
fn rows() -> Vec<&'static str> { ORACLE.split("    {\n      \"any_hex\"").skip(1).map(|tail| tail.split_once("\n    }").unwrap().0).collect() }
fn row_any_hex(row: &str) -> &str { row.strip_prefix(": \"").unwrap().split_once('"').unwrap().0 }
fn path(name:&str)->PathBuf { std::env::temp_dir().join(format!("c012-transfer-{name}-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())) }
fn put_long(manager:&SessionManager,name:&str,value:i64){ manager.durable_store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(),&value.to_be_bytes()).unwrap(); }
fn account(address:&[u8], name:&[u8], balance:i64, kind:AccountType)->Account { Account{account_name:name.to_vec(),address:address.to_vec(),balance,r#type:kind as i32,..Default::default()} }

#[test]
fn transfer_typed_any_preserves_unknown_fields_and_owner() {
    let owner = [vec![0x41], vec![3; 20]].concat();
    let contract = TransferContract { owner_address: owner.clone(), to_address: [vec![0x41], vec![4; 20]].concat(), amount: 7 };
    let mut value = contract.encode_to_vec(); value.extend_from_slice(&[0xa0, 0x06, 0x01]);
    let actuator = TransferActuator::new(Any { type_url: "type.googleapis.com/protocol.TransferContract".into(), value: value.clone() }).unwrap();
    assert_eq!(actuator.owner_address().unwrap(), owner); assert_eq!(actuator.raw_any().value, value); assert_eq!(TRANSFER_FEE, 0);
}

#[test]
fn transfer_rejects_wrong_any_type_before_execution() {
    let error = TransferActuator::new(Any { type_url: "type.googleapis.com/protocol.AccountUpdateContract".into(), value: TransferContract::default().encode_to_vec() }).err().unwrap();
    assert!(error.message.contains("contract type error"));
}

#[test]
fn java_transfer_real_oracle_replays_registry_commit_reopen_and_revoke() {
    assert!(ORACLE.contains("\"schema\": \"c012-transfer-real.v1\""));
    let observations=rows(); assert_eq!(observations.len(),20);
    for row in observations {
        let scenario=string_field(row,"scenario_id").unwrap();
        let directory=path(scenario); let requirements=OpenRequirements{identity:StorageIdentity{network:"c012-transfer".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]};
        let manager=SessionManager::new(StateStore::new(StorageManager::new(requirements).open_store(&directory).unwrap()));
        put_long(&manager,"LATEST_BLOCK_HEADER_TIMESTAMP",1_700_000_000_000); put_long(&manager,"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT",100_000); put_long(&manager,"ALLOW_MULTI_SIGN",0); put_long(&manager,"ALLOW_BLACKHOLE_OPTIMIZATION",0); put_long(&manager,"FORBID_TRANSFER_TO_CONTRACT",if scenario=="contract-forbid" {1}else{0}); put_long(&manager,"ALLOW_TVM_COMPATIBLE_EVM",if scenario.starts_with("contract-compatible") {1}else{0});
        let owner_balance=if scenario=="insufficient-fee" {-10_000}else{9_999_999};
        manager.durable_store(StoreKind::Account).put(&OWNER,&account(&OWNER,b"owner",owner_balance,AccountType::Normal).encode_to_vec()).unwrap();
        let recipient_balance=if scenario=="recipient-overflow" {i64::MAX}else{100_001};
        let recipient_kind=if scenario.starts_with("contract-") {AccountType::Contract}else{AccountType::Normal};
        let blackhole=[0x41;21]; manager.durable_store(StoreKind::Account).put(&blackhole,&account(&blackhole,b"blackhole",0,AccountType::Normal).encode_to_vec()).unwrap();
        manager.durable_store(StoreKind::Account).put(&TO,&account(&TO,if scenario.starts_with("contract-"){b"contract"}else{b"to"},recipient_balance,recipient_kind).encode_to_vec()).unwrap();
        if scenario=="contract-compatible-v1" { manager.durable_store(StoreKind::Contract).put(&TO,&SmartContract{contract_address:TO.to_vec(),origin_address:OWNER.to_vec(),version:1,..Default::default()}.encode_to_vec()).unwrap(); }
        let original_owner=manager.durable_store(StoreKind::Account).get(&OWNER); let original_to=manager.durable_store(StoreKind::Account).get(&TO); let original_missing=manager.durable_store(StoreKind::Account).get(&MISSING);
        let mut contract=Contract::decode(hex(string_field(row,"contract_hex").unwrap()).as_slice()).unwrap();
        assert_eq!(contract.encode_to_vec(),hex(string_field(row,"contract_hex").unwrap()),"{scenario} contract bytes");
        assert_eq!(contract.parameter.as_ref().unwrap_or_else(|| panic!("{scenario} missing decoded parameter")).encode_to_vec(),hex(row_any_hex(row)),"{scenario} Any bytes");
        if scenario=="no-contract" { contract.parameter=None; }
        let mut session=manager.build_session().unwrap(); let mut execution=session.child().unwrap(); let mut result=ActuatorResult::default();
        let actual=ActuatorRegistry::empty().execute(&contract,&execution,if scenario=="null-result"{None}else{Some(&mut result)},ExecutionConfig::default());
        let java_error=string_field(object(row,"result"),"error");
        if scenario=="null-manager" {
            assert!(actual.is_ok(),"Rust requires a live Session reference and therefore excludes Java's null-manager state: {actual:?}");
        } else {
            match (actual,java_error) { (Ok(()),None)=>{},(Err(error),Some(expected))=>{ let actual=format!("{error:?}"); let compatible=actual.contains(expected)||scenario=="recipient-overflow"&&actual.contains("overflow")||scenario=="wrong-type"&&actual.contains("contract type error")||scenario=="no-contract"&&actual.contains("MissingParameter")||scenario=="null-result"&&actual.contains("TransactionResultCapsule is null"); assert!(compatible,"{scenario}: {actual} != {expected}"); },(actual,expected)=>panic!("{scenario}: actual={actual:?} expected={expected:?}") }
        }
        execution.commit().unwrap();
        if java_error.is_none() || scenario=="null-manager" { assert_eq!(result.fee,if scenario=="null-manager"{0}else{number_field(object(row,"result"),"fee")},"{scenario} fee"); }
        let committed=object(row,"committed_reopen");
        if java_error.is_none() && scenario!="null-manager" { let reopened=manager.session_view(); assert_eq!(reopened.store(StoreKind::Account).get(&OWNER),string_field(committed,"owner_hex").map(hex),"{scenario} owner commit"); assert_eq!(reopened.store(StoreKind::Account).get(&TO),string_field(committed,"to_hex").map(hex),"{scenario} recipient commit"); assert_eq!(reopened.store(StoreKind::Account).get(&MISSING),string_field(committed,"missing_hex").map(hex),"{scenario} missing commit"); assert_eq!(result.code,Code::Sucess); }
        session.revoke().unwrap(); assert_eq!(manager.durable_store(StoreKind::Account).get(&OWNER),original_owner,"{scenario} owner revoke"); assert_eq!(manager.durable_store(StoreKind::Account).get(&TO),original_to,"{scenario} recipient revoke"); assert_eq!(manager.durable_store(StoreKind::Account).get(&MISSING),original_missing,"{scenario} missing revoke");
        drop(manager); fs::remove_dir_all(directory).unwrap();
    }
}
