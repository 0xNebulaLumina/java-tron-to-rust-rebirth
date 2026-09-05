use std::{collections::{BTreeMap, BTreeSet}, fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use prost::Message;
use serde::Deserialize;
use tron_consensus::{account_block_production, approval_threshold, apply_maintenance_block, java_fork_pass, java_shuffle, pay_block_reward, process_expired_proposals, solidity_position, standby_distribution, update_fork, update_solidity, CanonicalForkEvaluator, DposSlot, FixedClock, ForkSpec, ForkState, MaintenanceConfig, ParameterRule, SlotContext, StateFacade};
use tron_crypto::Sha256Provider;
use tron_primitives::DigestProvider;
use tron_protocol::protocol::{Account, Witness};
use tron_state::{SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

#[derive(Deserialize)] struct Manifest { clock: Clock, java_capture: Capture }
#[derive(Deserialize)] struct Clock { genesis_time_ms: i64, now_ms: i64 }
#[derive(Deserialize)] struct Capture { root_schema:String, rollback_event:String, initial_rows: Vec<Row>, initial_root: String, schedule: Vec<u8>, produced: Vec<u8>, missed: Vec<i64>, dynamic_bytes: BTreeMap<String,String>, snapshots: Vec<Snapshot>, head_rows: Vec<Row>, head_root: String, rollback_rows:Vec<Row>, rollback_root: String, events: Vec<String> }
#[derive(Deserialize)] struct Snapshot { step: String, event: String, cursor: Cursor, rows: Vec<Row>, root: String }
#[derive(Deserialize)] struct Cursor { latest_block_header_number: String, next_maintenance_time: String }
#[derive(Debug,Deserialize,PartialEq,Eq)] struct Row { store: String, key: String, value: String }

fn temporary()->PathBuf{std::env::temp_dir().join(format!("c017-scenario-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()))}
fn storage()->StorageManager{StorageManager::new(OpenRequirements{identity:StorageIdentity{network:"c017-scenario".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]})}
fn hex(bytes:&[u8])->String{bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn unhex(value:&str)->Vec<u8>{value.as_bytes().chunks_exact(2).map(|pair|u8::from_str_radix(std::str::from_utf8(pair).unwrap(),16).unwrap()).collect()}
fn address(byte:u8)->Vec<u8>{[vec![0x41],vec![byte;20]].concat()}
fn kind(name:&str)->StoreKind{StoreKind::ALL.into_iter().find(|kind|kind.db_name()==name).unwrap_or_else(||panic!("unknown C017 store {name}"))}
fn logical_rows(view:&tron_state::ReadView)->Vec<Row>{
    let mut rows=Vec::new();
    for store in StoreKind::ALL { for(key,value) in view.store(store).prefix(&[]){rows.push(Row{store:store.db_name().to_owned(),key:hex(&key),value:hex(&value)});} }
    rows.sort_by(|left,right|left.store.cmp(&right.store).then_with(||left.key.cmp(&right.key)));rows
}
fn full_root(view:&tron_state::ReadView)->String{
    let mut bytes=Vec::new();for row in logical_rows(view){let key=unhex(&row.key);let value=unhex(&row.value);for field in [row.store.as_bytes(),key.as_slice(),value.as_slice()]{bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());bytes.extend_from_slice(field);}}
    hex(Sha256Provider.digest(&bytes).unwrap().as_bytes())
}
fn assert_snapshot(block:&tron_state::Session, expected:&Snapshot, step:&str){
    assert_eq!(expected.step,step);assert_eq!(expected.event,step);
    let rows=logical_rows(&block.view());
    if rows!=expected.rows{let actual:BTreeMap<_,_>=rows.iter().map(|r|((r.store.as_str(),r.key.as_str()),r.value.as_str())).collect();let wanted:BTreeMap<_,_>=expected.rows.iter().map(|r|((r.store.as_str(),r.key.as_str()),r.value.as_str())).collect();let differences=actual.keys().chain(wanted.keys()).collect::<BTreeSet<_>>().into_iter().filter_map(|key|{let a=actual.get(key);let e=wanted.get(key);(a!=e).then(||format!("{}:{} actual={a:?} expected={e:?}",key.0,key.1))}).take(20).collect::<Vec<_>>();panic!("full rows differ at {step}: {}",differences.join("\n"));}
    assert_eq!(full_root(&block.view()),expected.root,"full root differs at {step}");
    let dynamic=block.view().store(StoreKind::DynamicProperties);
    assert_eq!(dynamic.get(b"latest_block_header_number").map(|v|hex(&v)).unwrap(),expected.cursor.latest_block_header_number,"head cursor differs at {step}");
    assert_eq!(dynamic.get(b"NEXT_MAINTENANCE_TIME").map(|v|hex(&v)).unwrap(),expected.cursor.next_maintenance_time,"maintenance cursor differs at {step}");
}
fn manifest()->Manifest{serde_json::from_str(include_str!("../../../../docs/oracles/c017-scenarios.v1.json")).unwrap()}

#[test]
fn pinned_java_rows_execute_real_c017_session_and_roots(){
    let manifest=manifest();let capture=&manifest.java_capture;
    assert_eq!(capture.root_schema,"canonical-db-name+raw-key+raw-value-v1");assert_eq!(capture.rollback_event,"outer-session-close");
    let directory=temporary();let root=StateStore::new(storage().open_store(&directory).unwrap());
    for row in &capture.initial_rows { let key=unhex(&row.key);let value=unhex(&row.value);if row.store=="account"{let decoded=Account::decode(value.as_slice()).unwrap();assert_eq!(decoded.address,key);}else if row.store=="witness"{let decoded=Witness::decode(value.as_slice()).unwrap();assert_eq!(decoded.address,key);}root.store(kind(&row.store)).put(&key,&value).unwrap(); }
    assert_eq!(full_root(&SessionManager::new(root.clone()).read_view()),capture.initial_root);
    let sessions=SessionManager::new(root.clone());let mut block=sessions.build_session().unwrap();
    let schedule=capture.schedule.clone();let mut shuffled:Vec<u8>=(0..27).collect();java_shuffle(&mut shuffled,manifest.clock.genesis_time_ms+3_000);assert_eq!(shuffled.iter().copied().collect::<BTreeSet<_>>().len(),27);
    let active:Vec<_>=schedule.iter().copied().map(address).collect();let slots=DposSlot::new(FixedClock(manifest.clock.now_ms),SlotContext{genesis_time:manifest.clock.genesis_time_ms,head_number:29,head_time:manifest.clock.now_ms-3_000,head_is_maintenance:false,maintenance_skip_slots:0});
    assert_eq!(slots.scheduled_witness(1,&active).unwrap(),active[3]);
    block.store(StoreKind::DynamicProperties).put(b"BLOCK_FILLED_SLOTS_INDEX",&1_i32.to_be_bytes()).unwrap();
    let mut witnesses:BTreeMap<Vec<u8>,Witness>=block.view().store(StoreKind::Witness).prefix(&[]).into_iter().map(|(key,value)|(key,Witness::decode(value.as_slice()).unwrap())).collect();
    account_block_production(&active,29,30,30,&active[3],&mut witnesses);let produced=vec![3_u8];assert_eq!(produced,capture.produced);assert!(capture.missed.is_empty());
    for witness in witnesses.values(){block.store(StoreKind::Witness).put(&witness.address,&witness.encode_to_vec()).unwrap();}
    let facade=StateFacade::new(&block);facade.save_dynamic_long("LATEST_BLOCK_HEADER_NUMBER",29).unwrap();facade.save_dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP",manifest.clock.now_ms-3_000).unwrap();
    assert_eq!(hex(&29_i64.to_be_bytes()),capture.dynamic_bytes["LATEST_BLOCK_HEADER_NUMBER"]);assert_snapshot(&block,&capture.snapshots[0],"statistic.applyBlock");
    block.store(StoreKind::Delegation).put(&active[0],&1_i64.to_be_bytes()).unwrap();
    let reward=pay_block_reward(&facade,&active[0],10).unwrap();assert_eq!((reward.brokerage,reward.voter_reward),(2,8));assert_snapshot(&block,&capture.snapshots[1],"mortgage.reward-query-withdraw");
    let maintenance_outcome=apply_maintenance_block(&facade,30,manifest.clock.now_ms,&MaintenanceConfig{genesis_votes:vec![],witness_sort_optimized:false}).unwrap();assert!(maintenance_outcome.applied);facade.save_dynamic_long("NEXT_MAINTENANCE_TIME",manifest.clock.now_ms).unwrap();block.store(StoreKind::DynamicProperties).put(b"state_flag",&0_i32.to_be_bytes()).unwrap();assert_snapshot(&block,&capture.snapshots[2],"maintenance.doMaintenance");
    let proposal_scan=process_expired_proposals(&facade,&BTreeMap::<i64,ParameterRule>::new()).unwrap();assert!(proposal_scan.examined.is_empty());assert_snapshot(&block,&capture.snapshots[3],"proposal.processProposals");
    facade.save_dynamic_long("NEXT_MAINTENANCE_TIME",manifest.clock.now_ms+18_000).unwrap();let dpos_maintenance=apply_maintenance_block(&facade,30,manifest.clock.now_ms,&MaintenanceConfig{genesis_votes:vec![],witness_sort_optimized:false}).unwrap();assert!(!dpos_maintenance.applied);
    block.store(StoreKind::DynamicProperties).put(b"BLOCK_FILLED_SLOTS_INDEX",&2_i32.to_be_bytes()).unwrap();account_block_production(&active,29,30,30,&active[3],&mut witnesses);for witness in witnesses.values(){block.store(StoreKind::Witness).put(&witness.address,&witness.encode_to_vec()).unwrap();}let solidity=update_solidity(&facade).unwrap();assert_eq!(solidity.position,solidity_position(27));assert_eq!(solidity.applied,9);assert_snapshot(&block,&capture.snapshots[4],"dpos.applyBlock");
    struct Evaluator;impl CanonicalForkEvaluator for Evaluator{fn passes(&self,spec:&ForkSpec,stats:&[u8])->bool{java_fork_pass(spec,3_000,3_000,stats)}}let fork=ForkSpec{version:1,hard_fork_time:1,rate_percent:70};let mut fork_state=ForkState::default();let fork_update=update_fork(&mut fork_state,std::slice::from_ref(&fork),&active,&active[0],1,&Evaluator);assert!(!fork_update.activated);
    let mut fork_stats=vec![0_u8;27];fork_stats[..4].copy_from_slice(&1_i32.to_be_bytes());block.store(StoreKind::DynamicProperties).put(b"FORK_VERSION_5",&fork_stats).unwrap();assert_snapshot(&block,&capture.snapshots[5],"fork.update");
    assert_eq!(approval_threshold(27),18);assert_eq!(standby_distribution(&[(address(1),1),(address(2),2)],100).into_iter().map(|(_,v)|v).collect::<Vec<_>>(),vec![33,66]);assert_eq!(capture.snapshots.len(),capture.events.len());for(index,event)in capture.events.iter().enumerate(){assert_eq!(capture.snapshots[index].step,*event);assert_eq!(capture.snapshots[index].event,*event);}
    let actual_head=logical_rows(&block.view());if actual_head.iter().map(|r|(&r.store,&r.key,&r.value)).collect::<Vec<_>>()!=capture.head_rows.iter().map(|r|(&r.store,&r.key,&r.value)).collect::<Vec<_>>(){let actual:BTreeMap<_,_>=actual_head.iter().map(|r|((r.store.as_str(),r.key.as_str()),r.value.as_str())).collect();let expected:BTreeMap<_,_>=capture.head_rows.iter().map(|r|((r.store.as_str(),r.key.as_str()),r.value.as_str())).collect();let differences=actual.keys().chain(expected.keys()).collect::<BTreeSet<_>>().into_iter().filter_map(|key|{let a=actual.get(key);let e=expected.get(key);(a!=e).then(||format!("{}:{} actual={a:?} expected={e:?}",key.0,key.1))}).take(20).collect::<Vec<_>>();panic!("full head rows differ: {}",differences.join("\n"));}
    assert_eq!(full_root(&block.view()),capture.head_root);
    block.commit().unwrap();assert_eq!(full_root(&sessions.read_view()),capture.head_root);
    assert!(sessions.pop().unwrap());assert_eq!(logical_rows(&sessions.read_view()),capture.rollback_rows);assert_eq!(full_root(&sessions.read_view()),capture.rollback_root);assert_eq!(capture.rollback_rows,capture.initial_rows);assert_eq!(capture.rollback_root,capture.initial_root);
    assert_eq!((schedule.len(),produced.len(),maintenance_outcome.applied,reward.brokerage,reward.voter_reward,proposal_scan.examined.len(),solidity.position,fork_update.activated),(27,1,true,2,8,0,8,false));drop(sessions);drop(root);fs::remove_dir_all(directory).unwrap();
}
