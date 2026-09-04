use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use prost::Message;
use tron_execution::{ActuatorRegistry, ActuatorResult, ExecutionConfig, RegistryError};
use tron_protocol::protocol::{transaction::Contract, Account};
use tron_state::{SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

const ORACLE: &str = include_str!("../../../../docs/oracles/c012-registry-real.v1.json");
const OWNER: &[u8] = &[0x41,0x54,0x87,0x94,0x50,0x08,0x82,0x80,0x96,0x95,0xa8,0xa6,0x87,0x86,0x6e,0x76,0xd4,0x27,0x1a,0x1a,0xbc];
const RECIPIENT: &[u8] = &[0x41,0xab,0xd4,0xb9,0x36,0x77,0x99,0xea,0xa3,0x19,0x7f,0xec,0xb1,0x44,0xeb,0x71,0xde,0x1e,0x04,0x9a,0xbc];

fn string_after<'a>(text: &'a str, start: usize, name: &str) -> &'a str {
    let marker = format!("\"{name}\": \"");
    let begin = text[start..].find(&marker).unwrap() + start + marker.len();
    &text[begin..begin + text[begin..].find('"').unwrap()]
}
fn decode_hex(value: &str) -> Vec<u8> { (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i+2], 16).unwrap()).collect() }
fn session(id: &str) -> (PathBuf, SessionManager, tron_state::Session) {
    let nonce=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path=std::env::temp_dir().join(format!("c012-registry-{id}-{nonce}"));
    let req=OpenRequirements{identity:StorageIdentity{network:"c012".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]};
    let root=StateStore::new(StorageManager::new(req).open_store(&path).unwrap());
    let manager=SessionManager::new(root); let outer=manager.build_session().unwrap(); (path,manager,outer)
}

#[test]
fn c012_registry_real_java_differential() {
    assert!(ORACLE.contains("\"scenario_count\": 13"));
    let registry=ActuatorRegistry::empty();
    let mut cursor=0; let mut count=0;
    while let Some(relative)=ORACLE[cursor..].find("\"stable_id\": \"TCASE-") {
        let stable=cursor+relative;
        let row=ORACLE[..stable].rfind("\n    {").unwrap();
        let row_end=ORACLE[stable..].find("\n    }").unwrap()+stable;
        let id=string_after(ORACLE,row,"stable_id");
        let contract_hex=decode_hex(string_after(ORACLE,row,"contract_hex"));
        let contract=Contract::decode(contract_hex.as_slice()).unwrap();
        assert_eq!(contract.encode_to_vec(),contract_hex,"{id} contract bytes");
        let expected_success=ORACLE[row..row_end].contains("\"error\": null");
        let commit_anchor=row+ORACLE[row..row_end].find("\"committed_reopen\"").unwrap();
        let expected_owner=decode_hex(string_after(ORACLE,commit_anchor,"owner_hex"));
        let expected_recipient=decode_hex(string_after(ORACLE,commit_anchor,"recipient_hex"));
        let rollback_anchor=row+ORACLE[row..row_end].find("\"rollback_root\"").unwrap();
        let original_owner=decode_hex(string_after(ORACLE,rollback_anchor,"owner_hex"));
        let original_recipient=decode_hex(string_after(ORACLE,rollback_anchor,"recipient_hex"));
        let(path,manager,mut committed)=session(id);
        committed.store(StoreKind::Account).put(OWNER,&Account{address:OWNER.to_vec(),account_name:b"owner".to_vec(),balance:9_999_999,..Default::default()}.encode_to_vec()).unwrap();
        committed.store(StoreKind::Account).put(RECIPIENT,&Account{address:RECIPIENT.to_vec(),account_name:b"recipient".to_vec(),balance:100_001,..Default::default()}.encode_to_vec()).unwrap();
        let mut result=ActuatorResult::default();
        let actual=registry.execute(&contract,&committed,Some(&mut result),ExecutionConfig::default());
        assert_eq!(actual.is_ok(),expected_success,"{id}: {actual:?}");
        assert_eq!(result.fee,0,"{id} fee");
        if expected_success {
            let owner_anchor=row+ORACLE[row..row_end].find("\"java_method\"").unwrap();
            assert_eq!(registry.owner_address(&contract).unwrap(),decode_hex(string_after(ORACLE,owner_anchor,"owner_hex")),"{id} owner");
        } else if id == "TCASE-5D1C840070F54FAB" {
            assert!(matches!(registry.decode(&contract),Err(RegistryError::TypeUrlMismatch{..})),"{id}");
        }
        committed.commit().unwrap();
        let mut committed_reopen=manager.build_session().unwrap();
        assert_eq!(committed_reopen.store(StoreKind::Account).get(OWNER),Some(expected_owner.clone()),"{id} committed owner");
        assert_eq!(committed_reopen.store(StoreKind::Account).get(RECIPIENT),Some(expected_recipient.clone()),"{id} committed recipient");
        committed_reopen.revoke().unwrap();
        let mut revoked=manager.build_session().unwrap();
        let mut revoke_result=ActuatorResult::default();
        let replay=registry.execute(&contract,&revoked,Some(&mut revoke_result),ExecutionConfig::default());
        assert_eq!(replay.is_ok(),expected_success,"{id} revoke replay: {replay:?}");
        revoked.revoke().unwrap();
        let mut revoked_reopen=manager.build_session().unwrap();
        assert_eq!(revoked_reopen.store(StoreKind::Account).get(OWNER),Some(expected_owner),"{id} revoked owner");
        assert_eq!(revoked_reopen.store(StoreKind::Account).get(RECIPIENT),Some(expected_recipient),"{id} revoked recipient");
        if !expected_success {
            assert_eq!(revoked_reopen.store(StoreKind::Account).get(OWNER),Some(original_owner),"{id} failure root owner");
            assert_eq!(revoked_reopen.store(StoreKind::Account).get(RECIPIENT),Some(original_recipient),"{id} failure root recipient");
        }
        revoked_reopen.revoke().unwrap();
        drop(manager); fs::remove_dir_all(path).unwrap();
        count+=1; cursor=row_end+6;
    }
    assert_eq!(count,13);
}
