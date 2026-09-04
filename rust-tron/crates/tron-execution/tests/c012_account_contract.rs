use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use prost::Message;
use tron_execution::{ActuatorRegistry, ActuatorResult, ExecutionConfig};
use tron_protocol::protocol::{transaction::{result::Code, Contract}, Account};
use tron_state::{dynamic, Session, SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

const ORACLE: &str = include_str!("../../../../docs/oracles/c012-account-real.v1.json");
const OWNER: [u8; 21] = hex_const("41548794500882809695a8a687866e76d4271a1abc");
const TARGET: [u8; 21] = hex_const("41abd4b9367799eaa3197fecb144eb71de1e049abc");
const KEY: [u8; 21] = hex_const("418cfc572cc20ca18b636bdd93b4fb15ea84cc2b4e");

const fn nibble(value: u8) -> u8 { match value { b'0'..=b'9' => value-b'0', b'a'..=b'f' => value-b'a'+10, _ => 0 } }
const fn hex_const<const N: usize>(value: &str) -> [u8; N] { let bytes=value.as_bytes(); let mut out=[0;N]; let mut i=0; while i<N { out[i]=(nibble(bytes[i*2])<<4)|nibble(bytes[i*2+1]); i+=1; } out }
fn hex(value: &str) -> Vec<u8> { value.as_bytes().chunks_exact(2).map(|pair|(nibble(pair[0])<<4)|nibble(pair[1])).collect() }
fn string_field<'a>(row: &'a str, key: &str) -> Option<&'a str> { let marker=format!("\"{key}\": "); let tail=row.split_once(&marker)?.1; if tail.starts_with("null") { None } else { let tail=tail.strip_prefix('"')?; Some(tail.split_once('"')?.0) } }
fn number_field(row: &str, key: &str) -> i64 { let marker=format!("\"{key}\": "); row.split_once(&marker).unwrap().1.split(|c:char| !c.is_ascii_digit() && c!='-').next().unwrap().parse().unwrap() }
fn rows() -> Vec<&'static str> {
    let mut rest=ORACLE.split_once("\"rows\": [").unwrap().1;
    let mut rows=Vec::new();
    loop {
        let Some(start)=rest.find('{') else { break }; rest=&rest[start..];
        let mut depth=0usize; let mut quoted=false; let mut escaped=false; let mut end=None;
        for (index,byte) in rest.bytes().enumerate() {
            if quoted { if escaped { escaped=false; } else if byte==b'\\' { escaped=true; } else if byte==b'"' { quoted=false; } continue; }
            match byte { b'"'=>quoted=true, b'{'=>depth+=1, b'}'=>{ depth-=1; if depth==0 { end=Some(index+1); break; } }, _=>{} }
        }
        let end=end.unwrap(); rows.push(&rest[..end]); rest=&rest[end..];
        if rest.trim_start().starts_with(']') { break; }
    }
    rows
}
fn path(name:&str)->PathBuf { std::env::temp_dir().join(format!("c012-account-{name}-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())) }
fn create_manager(name:&str)->(PathBuf,SessionManager) { let directory=path(name); let requirements=OpenRequirements{identity:StorageIdentity{network:"c012-account".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]}; let manager=SessionManager::new(StateStore::new(StorageManager::new(requirements).open_store(&directory).unwrap())); (directory,manager) }
fn put_long(session:&Session,name:&str,value:i64){ session.store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(),&value.to_be_bytes()).unwrap(); }
fn put_int(session:&Session,name:&str,value:i32){ session.store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(),&value.to_be_bytes()).unwrap(); }
fn base_account(name:Vec<u8>,balance:i64)->Account { Account { account_name:name,address:OWNER.to_vec(),balance,..Default::default() } }
fn setup(session:&Session,scenario:&str) {
    put_long(session,"LATEST_BLOCK_HEADER_TIMESTAMP",1_700_000_000_000); put_long(session,"ALLOW_MULTI_SIGN",1); put_int(session,"TOTAL_SIGN_NUM",5); put_long(session,"ALLOW_UPDATE_ACCOUNT_NAME",0); put_long(session,"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT",100_000); put_long(session,"ALLOW_BLACKHOLE_OPTIMIZATION",0); put_long(session,"UPDATE_ACCOUNT_PERMISSION_FEE",100_000_000);
    session.store(StoreKind::DynamicProperties).put(dynamic::key("ACTIVE_DEFAULT_OPERATIONS").unwrap(),&hex("7fff1fc0033e0000000000000000000000000000000000000000000000000000")).unwrap();
    session.store(StoreKind::DynamicProperties).put(dynamic::key("AVAILABLE_CONTRACT_TYPE").unwrap(),&[0xff;32]).unwrap();
    let mut owner=base_account(if scenario.starts_with("update-"){vec![]}else{b"owner".to_vec()},100_000_000);
    if scenario=="create-insufficient" { owner.balance=1; }
    if scenario=="setid-already-set" { owner.account_id=b"Old-id-01".to_vec(); }
    session.store(StoreKind::Account).put(&OWNER,&owner.encode_to_vec()).unwrap();
    let blackhole=Account{address:vec![0x41;21],..Default::default()}; session.store(StoreKind::Account).put(&blackhole.address,&blackhole.encode_to_vec()).unwrap();
    if scenario=="create-existing" { let target=Account{account_name:b"target".to_vec(),address:TARGET.to_vec(),balance:1,..Default::default()}; session.store(StoreKind::Account).put(&TARGET,&target.encode_to_vec()).unwrap(); }
    if scenario=="update-existing-name" { session.store(StoreKind::AccountIndex).put(b"alice",&KEY).unwrap(); }
    if scenario=="setid-duplicate" { session.store(StoreKind::AccountIdIndex).put(b"duplicate",&KEY).unwrap(); }
}
fn execute(row:&str,session:&Session) {
    let scenario=string_field(row,"scenario_id").unwrap();
    let encoded=hex(string_field(row,"contract_hex").unwrap()); let contract=Contract::decode(encoded.as_slice()).unwrap(); assert_eq!(contract.encode_to_vec(),encoded,"{scenario} contract bytes");
    let mut result=ActuatorResult::default(); let actual=ActuatorRegistry::empty().execute(&contract,session,Some(&mut result),ExecutionConfig::default()); let expected_error=string_field(row,"error");
    match (actual,expected_error) { (Ok(()),None)=>assert_eq!(result.code,Code::Sucess,"{scenario} code"),(Err(error),Some(expected))=>assert!(format!("{error:?}").contains(expected),"{scenario} error: {error:?}"),(actual,expected)=>panic!("{scenario}: actual={actual:?} expected={expected:?}") }
    assert_eq!(result.fee,number_field(row,"fee"),"{scenario} fee"); assert!(result.asset_issue_id.is_empty(),"{scenario} asset id");
    if let Some(expected)=string_field(row,"owner_hex") { assert_eq!(session.store(StoreKind::Account).get(&OWNER),Some(hex(expected)),"{scenario} owner bytes"); }
    let target=string_field(row,"target_hex").map(hex); assert_eq!(session.store(StoreKind::Account).get(&TARGET),target,"{scenario} target bytes");
}

#[test]
fn java_account_oracle_replays_real_c009_registry_commit_and_revoke_for_every_row() {
    assert!(ORACLE.contains("\"schema\": \"c012-account-real.v1\"")); assert!(ORACLE.contains("\"scenario_count\": 24")); assert!(ORACLE.contains("\"variant_count\": 63")); assert!(ORACLE.contains("\"stable_id_count\": 63"));
    let observations=rows(); assert_eq!(observations.len(),24);
    for row in observations {
        let scenario=string_field(row,"scenario_id").unwrap();
        let (directory,manager)=create_manager(&format!("commit-{scenario}")); let mut session=manager.build_session().unwrap(); setup(&session,scenario); execute(row,&session); session.commit().unwrap(); drop(session);
        let mut reopened=manager.build_session().unwrap(); if let Some(expected)=string_field(row,"owner_hex") { assert_eq!(reopened.store(StoreKind::Account).get(&OWNER),Some(hex(expected)),"{scenario} committed owner"); } assert_eq!(reopened.store(StoreKind::Account).get(&TARGET),string_field(row,"target_hex").map(hex),"{scenario} committed target"); reopened.revoke().unwrap(); drop(manager); fs::remove_dir_all(directory).unwrap();
        let (directory,manager)=create_manager(&format!("revoke-{scenario}")); let mut parent=manager.build_session().unwrap(); setup(&parent,scenario); let owner_before=parent.store(StoreKind::Account).get(&OWNER); let target_before=parent.store(StoreKind::Account).get(&TARGET); let mut child=parent.child().unwrap(); execute(row,&child); child.revoke().unwrap(); assert_eq!(parent.store(StoreKind::Account).get(&OWNER),owner_before,"{scenario} revoked owner"); assert_eq!(parent.store(StoreKind::Account).get(&TARGET),target_before,"{scenario} revoked target"); parent.revoke().unwrap(); drop(manager); fs::remove_dir_all(directory).unwrap();
    }
}
