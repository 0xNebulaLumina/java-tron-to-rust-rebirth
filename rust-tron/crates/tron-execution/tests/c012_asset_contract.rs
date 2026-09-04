use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use prost::Message;
use tron_execution::{Actuator, ActuatorRegistry, ActuatorResult, AssetIssueActuator, ExecutionConfig, ParticipateAssetIssueActuator, TransferAssetActuator, UnfreezeAssetActuator, UpdateAssetActuator};
use tron_protocol::{google::protobuf::Any, protocol::{transaction::{contract::ContractType, result::Code, Contract}, Account, AssetIssueContract, ParticipateAssetIssueContract, TransferAssetContract, UnfreezeAssetContract, UpdateAssetContract}};
use tron_state::{dynamic, Session, SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

const ORACLE: &str = include_str!("../../../../docs/oracles/c012-asset-real.v1.json");

fn any<M: Message>(name: &str, message: &M) -> Any { Any { type_url: format!("type.googleapis.com/protocol.{name}"), value: message.encode_to_vec() } }
fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value.as_bytes().chunks_exact(2).map(|pair| {
        let digit = |byte: u8| match byte { b'0'..=b'9' => byte - b'0', b'a'..=b'f' => byte - b'a' + 10, b'A'..=b'F' => byte - b'A' + 10, _ => panic!("invalid hex") };
        digit(pair[0]) << 4 | digit(pair[1])
    }).collect()
}
fn field_values(document: &str, field: &str) -> Vec<String> {
    let marker = format!("\"{field}\":\"");
    let mut rest = document;
    let mut values = Vec::new();
    while let Some(start) = rest.find(&marker) {
        rest = &rest[start + marker.len()..];
        let end = rest.find('"').unwrap();
        values.push(rest[..end].to_owned());
        rest = &rest[end + 1..];
    }
    values
}

const OWNER: &[u8] = &[0x41,0xab,0xd4,0xb9,0x36,0x77,0x99,0xea,0xa3,0x19,0x7f,0xec,0xb1,0x44,0xeb,0x71,0xde,0x1e,0x04,0x91,0x50];
const BUYER: &[u8] = &[0x41,0x54,0x87,0x94,0x50,0x08,0x82,0x80,0x96,0x95,0xa8,0xa6,0x87,0x86,0x6e,0x76,0xd4,0x27,0x1a,0x1a,0xbc];

fn path(name: &str) -> PathBuf { std::env::temp_dir().join(format!("c012-asset-{name}-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())) }
fn create_manager(name: &str) -> (PathBuf, SessionManager) {
    let directory = path(name);
    let requirements = OpenRequirements { identity: StorageIdentity { network: "c012-asset".into(), genesis: "00".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()] };
    (directory.clone(), SessionManager::new(StateStore::new(StorageManager::new(requirements).open_store(&directory).unwrap())))
}
fn put_long(session: &Session, name: &str, value: i64) { session.store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(), &value.to_be_bytes()).unwrap(); }
fn put_int(session: &Session, name: &str, value: i32) { session.store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(), &value.to_be_bytes()).unwrap(); }
fn setup(session: &Session) {
    for (name, value) in [("LATEST_BLOCK_HEADER_TIMESTAMP",86_400_000),("ALLOW_SAME_TOKEN_NAME",0),("TOKEN_ID_NUM",1_000_000),("ASSET_ISSUE_FEE",1_024_000_000),("ONE_DAY_NET_LIMIT",57_600_000_000),("ALLOW_ACCOUNT_ASSET_OPTIMIZATION",0),("ALLOW_BLACKHOLE_OPTIMIZATION",0),("CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT",100_000),("FORBID_TRANSFER_TO_CONTRACT",0),("ALLOW_MULTI_SIGN",0)] { put_long(session, name, value); }
    for (name, value) in [("MAX_FROZEN_SUPPLY_NUMBER",10),("MIN_FROZEN_SUPPLY_TIME",1),("MAX_FROZEN_SUPPLY_TIME",3652)] { put_int(session, name, value); }
    for (address, name, balance) in [(OWNER,b"owner".as_slice(),1_026_000_000),(BUYER,b"buyer".as_slice(),2_000_000)] { let account=Account { account_name:name.to_vec(),address:address.to_vec(),balance,..Default::default() }; session.store(StoreKind::Account).put(address,&account.encode_to_vec()).unwrap(); }
    let blackhole=Account { address:vec![0x41;21],..Default::default() }; session.store(StoreKind::Account).put(&blackhole.address,&blackhole.encode_to_vec()).unwrap();
}
fn execute(contract: &Contract, session: &Session) -> ActuatorResult { let mut result=ActuatorResult::default(); ActuatorRegistry::empty().execute(contract,session,Some(&mut result),ExecutionConfig::default()).unwrap(); result }

#[test]
fn java_asset_oracle_replays_real_c009_registry_commit_and_revoke_for_every_row() {
    let contracts=field_values(ORACLE,"contract_hex");
    let owners=field_values(ORACLE,"value_hex");
    assert_eq!(contracts.len(),5); assert_eq!(owners.len(),10);
    for target in 0..contracts.len() {
        let (directory, manager)=create_manager(&format!("commit-{target}")); let mut session=manager.build_session().unwrap(); setup(&session);
        for index in 0..=target { if index==3 { put_long(&session,"LATEST_BLOCK_HEADER_TIMESTAMP",86_402_000); } if index==4 { put_long(&session,"LATEST_BLOCK_HEADER_TIMESTAMP",172_801_000); } let contract=Contract::decode(unhex(&contracts[index]).as_slice()).unwrap(); let result=execute(&contract,&session); assert_eq!(result.code,Code::Sucess,"row {index}"); }
        assert_eq!(session.store(StoreKind::Account).get(OWNER),Some(unhex(&owners[target*2])),"row {target} owner delta");
        assert_eq!(session.store(StoreKind::Account).get(BUYER),Some(unhex(&owners[target*2+1])),"row {target} buyer delta");
        session.commit().unwrap(); let mut reopened=manager.build_session().unwrap(); assert_eq!(reopened.store(StoreKind::Account).get(OWNER),Some(unhex(&owners[target*2])),"row {target} commit/reopen"); reopened.revoke().unwrap(); drop(manager); fs::remove_dir_all(&directory).unwrap();

        let (directory, manager)=create_manager(&format!("revoke-{target}")); let mut session=manager.build_session().unwrap(); setup(&session);
        for index in 0..target { if index==3 { put_long(&session,"LATEST_BLOCK_HEADER_TIMESTAMP",86_402_000); } let contract=Contract::decode(unhex(&contracts[index]).as_slice()).unwrap(); execute(&contract,&session); }
        let before_owner=session.store(StoreKind::Account).get(OWNER); let before_buyer=session.store(StoreKind::Account).get(BUYER);
        let mut target_session=session.child().unwrap(); if target==3 { put_long(&target_session,"LATEST_BLOCK_HEADER_TIMESTAMP",86_402_000); } if target==4 { put_long(&target_session,"LATEST_BLOCK_HEADER_TIMESTAMP",172_801_000); } let contract=Contract::decode(unhex(&contracts[target]).as_slice()).unwrap(); execute(&contract,&target_session); target_session.revoke().unwrap();
        assert_eq!(session.store(StoreKind::Account).get(OWNER),before_owner,"row {target} revoke owner"); assert_eq!(session.store(StoreKind::Account).get(BUYER),before_buyer,"row {target} revoke buyer"); session.revoke().unwrap(); drop(manager); fs::remove_dir_all(&directory).unwrap();
    }
}

#[test]
fn java_real_artifact_dispatches_every_asset_family_contract_through_registry() {
    assert!(ORACLE.contains("\"scenario_count\":5"));
    assert!(ORACLE.contains("\"variant_count\":5"));
    assert!(ORACLE.contains("\"stable_id_count\":5"));
    assert!(!ORACLE.contains("org.junit"));
    let expected = [
        (ContractType::AssetIssueContract, "SameTokenNameCloseAssetIssueSuccess"),
        (ContractType::UpdateAssetContract, "successUpdateAssetBeforeSameTokenNameActive"),
        (ContractType::TransferAssetContract, "SameTokenNameCloseSuccessTransfer"),
        (ContractType::ParticipateAssetIssueContract, "sameTokenNameCloseRightAssetIssue"),
        (ContractType::UnfreezeAssetContract, "SameTokenNameCloseUnfreezeAsset"),
    ];
    let contracts = field_values(ORACLE, "contract_hex");
    assert_eq!(contracts.len(), expected.len());
    let registry = ActuatorRegistry::empty();
    for ((encoded, (kind, method)), index) in contracts.iter().zip(expected).zip(0..) {
        assert!(ORACLE.contains(method), "missing exact Java method {method}");
        let contract = Contract::decode(unhex(encoded).as_slice()).unwrap();
        assert_eq!(contract.r#type, kind as i32, "artifact row {index}");
        let decoded_owner = registry.owner_address(&contract).unwrap();
        let actuator = registry.actuator(&contract).unwrap();
        assert_eq!(actuator.owner_address().unwrap(), decoded_owner);
    }
}

#[test]
fn asset_family_constructors_retain_typed_owner() {
    let owner = [vec![0x41], vec![7; 20]].concat();
    assert_eq!(AssetIssueActuator::new(any("AssetIssueContract", &AssetIssueContract { owner_address: owner.clone(), ..Default::default() })).unwrap().owner_address().unwrap(), owner);
    assert_eq!(UpdateAssetActuator::new(any("UpdateAssetContract", &UpdateAssetContract { owner_address: owner.clone(), ..Default::default() })).unwrap().owner_address().unwrap(), owner);
    assert_eq!(TransferAssetActuator::new(any("TransferAssetContract", &TransferAssetContract { owner_address: owner.clone(), ..Default::default() })).unwrap().owner_address().unwrap(), owner);
    assert_eq!(ParticipateAssetIssueActuator::new(any("ParticipateAssetIssueContract", &ParticipateAssetIssueContract { owner_address: owner.clone(), ..Default::default() })).unwrap().owner_address().unwrap(), owner);
    assert_eq!(UnfreezeAssetActuator::new(any("UnfreezeAssetContract", &UnfreezeAssetContract { owner_address: owner.clone() })).unwrap().owner_address().unwrap(), owner);
}

#[test]
fn asset_actuators_reject_cross_typed_any() {
    let encoded = AssetIssueContract::default().encode_to_vec();
    let error = TransferAssetActuator::new(Any { type_url: "type.googleapis.com/protocol.AssetIssueContract".into(), value: encoded }).err().unwrap();
    assert!(error.message.contains("contract type error"));
}
