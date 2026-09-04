use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use prost::Message;
use tron_execution::{Actuator, ActuatorRegistry, ActuatorResult, ExecutionConfig, RegistryError, VoteWitnessActuator};
use tron_protocol::{google::protobuf::Any, protocol::{account::Frozen, transaction::Contract, Account, VoteWitnessContract, Witness}};
use tron_state::{dynamic, Session, SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

const ORACLE: &str = include_str!("../../../../docs/oracles/c012-witness-real.v1.json");
const OWNER: &[u8] = &[0x41,0xab,0xd4,0xb9,0x36,0x77,0x99,0xea,0xa3,0x19,0x7f,0xec,0xb1,0x44,0xeb,0x71,0xde,0x1e,0x04,0x9a,0xbc];
const CANDIDATE: &[u8] = &[0x41,0x54,0x87,0x94,0x50,0x08,0x82,0x80,0x96,0x95,0xa8,0xa6,0x87,0x86,0x6e,0x76,0xd4,0x27,0x1a,0x1a,0xbc];

fn unhex(value: &str) -> Vec<u8> { (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i+2],16).unwrap()).collect() }
fn field<'a>(row: &'a str, key: &str) -> &'a str { let tail=row.split_once(&format!("\"{key}\":\"")).unwrap().1; tail.split_once('"').unwrap().0 }
fn number(row: &str,key:&str)->i64 { let tail=row.split_once(&format!("\"{key}\":" )).unwrap().1; tail.split(|c:char| !c.is_ascii_digit() && c!='-').next().unwrap().parse().unwrap() }
fn flag(row:&str,key:&str)->bool { row.split_once(&format!("\"{key}\":" )).unwrap().1.starts_with("true") }
fn optional_hex(row:&str,key:&str)->Option<Vec<u8>> { let tail=row.split_once(&format!("\"{key}\":" )).unwrap().1; if tail.starts_with("null"){None}else{Some(unhex(tail.strip_prefix('"').unwrap().split_once('"').unwrap().0))} }
fn hex_bytes(value:&[u8])->String { value.iter().map(|byte|format!("{byte:02x}")).collect() }
fn delta_entry(value:&tron_state::StoreEntry)->String { match value { tron_state::StoreEntry::Absent=>"null".into(),tron_state::StoreEntry::Present(bytes)=>format!("\"{}\"",hex_bytes(bytes)) } }
fn assert_deltas(row:&str,result:&ActuatorResult,id:&str){
 let encoded=row.split_once("\"deltas\":[").unwrap().1.split_once("],\"commit_account_hex\"").unwrap().0;
 assert_eq!(encoded.matches("\"store\":").count(),result.deltas.len(),"{id} delta count: {:?}",result.deltas);
 for delta in &result.deltas { let fragment=format!("{{\"store\":\"{:?}\",\"key_hex\":\"{}\",\"before_hex\":{},\"after_hex\":{}}}",delta.store,hex_bytes(&delta.key),delta_entry(&delta.before),delta_entry(&delta.after));assert!(encoded.contains(&fragment),"{id} missing delta {fragment}"); }
}
fn rows()->Vec<String> { ORACLE.split("{\"variant_id\"").skip(1).map(|tail| format!("{{\"variant_id\"{tail}")).collect() }
fn session(name:&str)->(PathBuf,SessionManager,Session){let nonce=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();let path=std::env::temp_dir().join(format!("c012-witness-{name}-{nonce}"));let req=OpenRequirements{identity:StorageIdentity{network:"c012".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]};let root=StateStore::new(StorageManager::new(req).open_store(&path).unwrap());let manager=SessionManager::new(root);let outer=manager.build_session().unwrap();(path,manager,outer)}
fn put_long(s:&Session,name:&str,value:i64){s.store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(),&value.to_be_bytes()).unwrap()}
fn setup(s:&Session,id:&str){
 let balance=if id=="witness-create-insufficient-balance"{99_999_999}else if id.starts_with("witness-create"){200_000_000_000}else{1};
 let power=if id=="vote-insufficient-power"{0}else if id=="vote-duplicate-order"{3_000_000}else{2_000_000};
 let owner=Account{address:OWNER.to_vec(),account_name:b"owner".to_vec(),balance,frozen:if power>0{vec![Frozen{frozen_balance:power,expire_time:0}]}else{vec![]},..Default::default()};
 s.store(StoreKind::Account).put(OWNER,&owner.encode_to_vec()).unwrap();
 if id!="vote-missing-candidate-account" { let candidate=Account{address:CANDIDATE.to_vec(),account_name:b"candidate".to_vec(),balance:300,..Default::default()};s.store(StoreKind::Account).put(CANDIDATE,&candidate.encode_to_vec()).unwrap(); }
 if id.contains("existing")||(id.starts_with("witness-update")&&id!="witness-update-missing-witness")||id.starts_with("vote-"){let w=Witness{address:OWNER.to_vec(),url:"https://tron.network".into(),..Default::default()};s.store(StoreKind::Witness).put(OWNER,&w.encode_to_vec()).unwrap();}
 if id!="vote-missing-witness"{let w=Witness{address:CANDIDATE.to_vec(),vote_count:10,url:"https://tron.network".into(),..Default::default()};s.store(StoreKind::Witness).put(CANDIDATE,&w.encode_to_vec()).unwrap();}
 put_long(s,"ACCOUNT_UPGRADE_COST",100_000_000);put_long(s,"TOTAL_CREATE_WITNESS_COST",7);put_long(s,"ALLOW_MULTI_SIGN",1);put_long(s,"ALLOW_NEW_RESOURCE_MODEL",0);put_long(s,"ALLOW_BLACKHOLE_OPTIMIZATION",0);s.store(StoreKind::DynamicProperties).put(dynamic::key("ACTIVE_DEFAULT_OPERATIONS").unwrap(),&unhex("7fff1fc0033e0000000000000000000000000000000000000000000000000000")).unwrap();
}
fn align_base(s:&Session,row:&str,owner:&[u8],blackhole:&[u8]){
 for (store,key,field) in [(StoreKind::Account,owner,"revoke_account_hex"),(StoreKind::Witness,owner,"revoke_witness_hex"),(StoreKind::Votes,owner,"revoke_votes_hex"),(StoreKind::Account,blackhole,"revoke_blackhole_hex")] {
  match optional_hex(row,field){Some(value)=>s.store(store).put(key,&value).unwrap(),None=>s.store(store).delete(key).unwrap()}
 }
}

#[test]
fn java_witness_oracle_replays_real_registry_commit_and_revoke(){
 assert!(ORACLE.contains("\"schema\":\"c012-witness-real-v1\""));assert!(ORACLE.contains("\"scenario_count\":15"));let all=rows();assert_eq!(all.len(),15);
 for row in &all {
  let id=field(row,"variant_id");let full=Contract::decode(unhex(field(row,"contract_hex")).as_slice()).unwrap();let any=full.parameter.as_ref().unwrap();assert_eq!(any.encode_to_vec(),unhex(field(row,"contract_any_hex")));
  let owner=match full.r#type {5=>tron_protocol::protocol::WitnessCreateContract::decode(any.value.as_slice()).unwrap().owner_address,8=>tron_protocol::protocol::WitnessUpdateContract::decode(any.value.as_slice()).unwrap().owner_address,4=>VoteWitnessContract::decode(any.value.as_slice()).unwrap().owner_address,other=>panic!("unexpected contract type {other}")};
  let blackhole=unhex(field(row,"blackhole_key_hex"));let(path,manager,mut setup_session)=session(id);setup(&setup_session,id);align_base(&setup_session,row,&owner,&blackhole);setup_session.commit().unwrap();manager.flush_committed().unwrap();
  let mut execution=manager.build_session().unwrap();let mut result=ActuatorResult::default();let actual=ActuatorRegistry::empty().execute(&full,&execution,Some(&mut result),ExecutionConfig{blackhole_address:blackhole.clone(),reward_callback:None});
  assert_eq!(actual.is_ok(),flag(row,"success"),"{id}");assert_eq!(result.fee,number(row,"fee"),"{id}");assert_eq!(result.code as i32,if actual.is_ok(){number(row,"result_code") as i32}else{1},"{id}");assert!(result.asset_issue_id.is_empty(),"{id}");
  if let Err(error)=actual{match error{RegistryError::Provider(message)=>assert_eq!(message,field(row,"error"),"{id}"),other=>panic!("{id}: unexpected registry error {other:?}")};assert!(result.deltas.is_empty(),"{id}");}
  assert_deltas(row,&result,id);
  assert_eq!(execution.store(StoreKind::Account).get(&owner),optional_hex(row,"commit_account_hex"),"{id} committed account");
  assert_eq!(execution.store(StoreKind::Witness).get(&owner),optional_hex(row,"commit_witness_hex"),"{id} committed witness");
  assert_eq!(execution.store(StoreKind::Votes).get(&owner),optional_hex(row,"commit_votes_hex"),"{id} committed votes");
  assert_eq!(execution.store(StoreKind::Account).get(&blackhole),optional_hex(row,"commit_blackhole_hex"),"{id} committed blackhole");
  assert_eq!(execution.store(StoreKind::DynamicProperties).get(dynamic::key("TOTAL_CREATE_WITNESS_COST").unwrap()),optional_hex(row,"commit_dynamic_hex"),"{id} committed dynamic");
  execution.revoke().unwrap();
  assert_eq!(manager.durable_store(StoreKind::Account).get(&owner),optional_hex(row,"revoke_account_hex"),"{id} revoked account");
  assert_eq!(manager.durable_store(StoreKind::Witness).get(&owner),optional_hex(row,"revoke_witness_hex"),"{id} revoked witness");
  assert_eq!(manager.durable_store(StoreKind::Votes).get(&owner),optional_hex(row,"revoke_votes_hex"),"{id} revoked votes");
  assert_eq!(manager.durable_store(StoreKind::Account).get(&blackhole),optional_hex(row,"revoke_blackhole_hex"),"{id} revoked blackhole");
  assert_eq!(manager.durable_store(StoreKind::DynamicProperties).get(dynamic::key("TOTAL_CREATE_WITNESS_COST").unwrap()),optional_hex(row,"revoke_dynamic_hex"),"{id} revoked dynamic");
  drop(manager);fs::remove_dir_all(path).unwrap();
 }
}

#[test]
fn reward_callback_precedes_vote_account_reload_and_duplicate_order_is_preserved(){
 use std::sync::{Arc,atomic::{AtomicBool,Ordering}};use tron_execution::{ActuatorError,ExecutionContext,RewardCallback};
 struct Callback(Arc<AtomicBool>);impl RewardCallback for Callback{fn withdraw_reward(&self,context:&mut ExecutionContext<'_>,address:&[u8])->Result<(),ActuatorError>{self.0.store(true,Ordering::SeqCst);let mut account:Account=context.decode(StoreKind::Account,address,"missing")?;account.balance+=9;context.put_message(StoreKind::Account,address,&account)}}
 let(path,manager,mut outer)=session("callback");setup(&outer,"vote-duplicate-order");let contract=VoteWitnessContract{owner_address:OWNER.to_vec(),votes:vec![tron_protocol::protocol::vote_witness_contract::Vote{vote_address:CANDIDATE.to_vec(),vote_count:1};3],support:false};let any=Any{type_url:"type.googleapis.com/protocol.VoteWitnessContract".into(),value:contract.encode_to_vec()};let called=Arc::new(AtomicBool::new(false));let mut result=ActuatorResult::default();VoteWitnessActuator::new(any).unwrap().execute(&outer,Some(&mut result),ExecutionConfig{blackhole_address:vec![0x41;21],reward_callback:Some(Arc::new(Callback(called.clone())))}).unwrap();assert!(called.load(Ordering::SeqCst));let stored=Account::decode(outer.store(StoreKind::Account).get(OWNER).unwrap().as_slice()).unwrap();assert_eq!(stored.balance,10);assert_eq!(stored.votes.len(),3);outer.revoke().unwrap();drop(manager);fs::remove_dir_all(path).unwrap();
}
