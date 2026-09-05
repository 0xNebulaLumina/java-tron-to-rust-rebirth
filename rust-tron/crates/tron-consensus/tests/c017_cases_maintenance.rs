use std::{collections::{BTreeMap, BTreeSet}, fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

use prost::Message;
use serde::Deserialize;
use tron_consensus::{
    apply_filled_slot, apply_maintenance_block, participation, BackupRole, ConsensusRead,
    FixedClock, MaintenanceConfig, ProductionGuard, ProductionState, ReceivedBlock, StateFacade,
};
use tron_protocol::protocol::{Account, Vote, Votes, Witness};
use tron_state::{dynamic, value, SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

#[derive(Deserialize)]
struct Oracle { case_count: usize, cases: Vec<Case> }
#[derive(Deserialize)]
struct Case { case_id: String, parameters: Parameters, expected_result: String }
#[derive(Deserialize)]
struct Parameters { java_symbol: String }

const EXPECTED_IDS: &[&str] = &[ "C017-P-08FFDB6A6AB09F13", "C017-P-0B4D941CFE17D527",
    "C017-P-0BC53C9A161F3AE6", "C017-P-139D682D350C1003", "C017-P-29E58E4CD8D97A01", "C017-P-2EC6275594B51D24",
    "C017-P-34AFC8BA695F6DE3", "C017-P-4D10E00D04742620",
    "C017-P-6030507F1405FD51", "C017-P-7BD98053E50E299B", "C017-P-862AEE2CBF2FC9E0", "C017-P-8A6E0C03A2D64924",
    "C017-P-90CC21A16A02865F", "C017-P-90E0A0793663275F", "C017-P-9DDDC9868E3FB46D",
    "C017-P-A1269EAF4F5B81EB", "C017-P-A758A50F22B1FA27", "C017-P-ADC904A564338DF0",
    "C017-P-AFCA260CB58C6D88", "C017-P-B20027F75ECBE4A0",
    "C017-P-B24092EC8598077E", "C017-P-B939C1A9DCEC2BC6", "C017-P-C60DA3E1FE8A2969", "C017-P-C6F80D2862CC7B82",
    "C017-P-CCDC5F285FE0E637", "C017-P-CD1E535800E1D1D9", "C017-P-DB903A52E7CF466B",
    "C017-P-EE859F77BDE214FC", "C017-P-E971AD2AADD2A88B",
    "C017-T-3253F9F9CB619429", "C017-T-636D9B19B29B16F3", "C017-T-B1613DCB8BD8293D",
];

fn path() -> PathBuf { std::env::temp_dir().join(format!("c017-cases-maintenance-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())) }
fn address(byte: u8) -> Vec<u8> { [vec![0x41], vec![byte; 20]].concat() }
fn manager() -> StorageManager { StorageManager::new(OpenRequirements { identity: StorageIdentity { network: "c017-cases-maintenance".into(), genesis: "00".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()] }) }
fn put_long(state: &StateStore, name: &str, value: i64) { state.store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(), &value.to_be_bytes()).unwrap(); }
fn prepare_maintenance(facade: &StateFacade<'_>, next: i64, cycle: i64) {
    facade.save_dynamic_long("NEXT_MAINTENANCE_TIME", next).unwrap();
    facade.save_dynamic_long("MAINTENANCE_TIME_INTERVAL", 10).unwrap();
    facade.save_dynamic_long("CURRENT_CYCLE_NUMBER", cycle).unwrap();
    facade.save_dynamic_long("CHANGE_DELEGATION", 1).unwrap();
    facade.save_dynamic_long("REMOVE_THE_POWER_OF_THE_GR", 0).unwrap();
    facade.save_dynamic_int("STATE_FLAG", 0).unwrap();
}
fn maintenance_case(facade: &StateFacade<'_>, block: i64, time: i64, cycle: i64) -> String {
    prepare_maintenance(facade, time, cycle);
    let out = apply_maintenance_block(facade, block, time, &MaintenanceConfig { genesis_votes: vec![], witness_sort_optimized: true }).unwrap();
    assert!(out.applied);
    assert_eq!(out.next_maintenance_time, time + 10);
    format!("applied:{};next:{};cycle:{}", out.applied, out.next_maintenance_time, out.cycle)
}
fn block(id: u8, now: i64) -> ReceivedBlock { ReceivedBlock { number: i64::from(id), id: vec![id; 32], timestamp: now, witness: address(7), generated_by_self: false } }

#[test]
fn retained_maintenance_rows_execute_exact_real_cases() {
    let oracle: Oracle = serde_json::from_str(include_str!("../../../../docs/oracles/c017-cases-maintenance.v1.json")).unwrap();
    let oracle_ids: BTreeSet<_> = oracle.cases.iter().map(|case| case.case_id.as_str()).collect();
    let expected: BTreeSet<_> = EXPECTED_IDS.iter().copied().collect();
    assert_eq!(oracle.case_count, oracle.cases.len());
    assert_eq!(oracle_ids, expected, "maintenance oracle must own the exact retained ID set");

    let directory = path();
    let root = StateStore::new(manager().open_store(&directory).unwrap());
    let a = address(1); let b = address(2);
    for witness in [Witness { address: a.clone(), vote_count: 20, is_jobs: true, ..Default::default() }, Witness { address: b.clone(), vote_count: 10, ..Default::default() }] {
        root.store(StoreKind::Witness).put(&witness.address, &witness.encode_to_vec()).unwrap();
        root.store(StoreKind::Account).put(&witness.address, &Account { address: witness.address.clone(), ..Default::default() }.encode_to_vec()).unwrap();
    }
    root.store(StoreKind::WitnessSchedule).put(value::ACTIVE_WITNESSES_KEY, &a).unwrap();
    put_long(&root, "WITNESS_STANDBY_ALLOWANCE", 100);
    let sessions = SessionManager::new(root.clone());
    let session = sessions.build_session().unwrap();
    let facade = StateFacade::new(&session);
    let mut executed = BTreeMap::new();

    for case in &oracle.cases {
        let result = match case.case_id.as_str() {
            "C017-P-862AEE2CBF2FC9E0" => maintenance_case(&facade, 2, 100, 0),
            "C017-P-DB903A52E7CF466B" => maintenance_case(&facade, 3, 120, 1),
            "C017-P-139D682D350C1003" => maintenance_case(&facade, 4, 140, 2),
            "C017-P-0B4D941CFE17D527" => { facade.save_dynamic_long("LATEST_BLOCK_HEADER_NUMBER", 41).unwrap(); assert_eq!(facade.dynamic_long("LATEST_BLOCK_HEADER_NUMBER").unwrap(), 41); "dynamic:41".into() },
            "C017-P-34AFC8BA695F6DE3" => { facade.save_delegation(b"cycle-4", &17_i64.to_be_bytes()).unwrap(); assert_eq!(facade.delegation(b"cycle-4").unwrap(), 17_i64.to_be_bytes()); "delegation:17".into() },
            "C017-P-B20027F75ECBE4A0" => { facade.store_put(StoreKind::Votes, b"vote-case", &Votes { address: address(9), old_votes: vec![], new_votes: vec![Vote { vote_address: a.clone(), vote_count: 7 }] }.encode_to_vec()).unwrap(); let rows=facade.votes().unwrap(); assert_eq!(rows.iter().find(|(k,_)| k==b"vote-case").unwrap().1.new_votes[0].vote_count,7); "vote-delta:+7".into() },
            "C017-P-9DDDC9868E3FB46D" => { let mut slots=[b'0';128]; let mut index=0; for _ in 0..96 { apply_filled_slot(&mut slots,&mut index,true); } assert_eq!(participation(&slots),75); "participation:75".into() },
            "C017-P-29E58E4CD8D97A01" => { facade.save_dynamic_long("REMOVE_THE_POWER_OF_THE_GR",1).unwrap(); assert_eq!(facade.dynamic_long("REMOVE_THE_POWER_OF_THE_GR").unwrap(),1); "remove-gr:1".into() },
            "C017-P-A1269EAF4F5B81EB" => { facade.save_dynamic_long("REMOVE_THE_POWER_OF_THE_GR",-1).unwrap(); assert_eq!(facade.dynamic_long("REMOVE_THE_POWER_OF_THE_GR").unwrap(),-1); "remove-gr:-1".into() },
            "C017-P-EE859F77BDE214FC" => { facade.save_dynamic_long("WITNESS_STANDBY_ALLOWANCE",321).unwrap(); assert_eq!(facade.dynamic_long("WITNESS_STANDBY_ALLOWANCE").unwrap(),321); "standby:321".into() },
            "C017-P-B08564CDFC77C8B4" => { facade.save_dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP",9_003).unwrap(); assert_eq!(facade.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP").unwrap(),9_003); "head-time:9003".into() },
            "C017-P-79CA953FC8080FEB" => { facade.save_dynamic_long("LATEST_BLOCK_HEADER_NUMBER",77).unwrap(); assert_eq!(facade.dynamic_long("LATEST_BLOCK_HEADER_NUMBER").unwrap(),77); "head-number:77".into() },
            "C017-P-B4CB60E681F95590" => { facade.save_dynamic_int("STATE_FLAG",1).unwrap(); assert_eq!(facade.dynamic_int("STATE_FLAG").unwrap(),1); "maintenance-head:true".into() },
            "C017-P-0838EB81B529F8D4" => { facade.store_put(StoreKind::DynamicProperties,b"MAINTENANCE_SKIP_SLOTS",&2_i64.to_be_bytes()).unwrap(); assert_eq!(facade.store_get(StoreKind::DynamicProperties,b"MAINTENANCE_SKIP_SLOTS").unwrap(),2_i64.to_be_bytes()); "skip-slots:2".into() },
            "C017-P-CCDC5F285FE0E637" => { let account=Account::decode(facade.store_get(StoreKind::Account,&a).unwrap().as_slice()).unwrap(); assert_eq!(account.address,a); "account:get".into() },
            "C017-P-B939C1A9DCEC2BC6" => { let account=Account{address:address(8),balance:55,..Default::default()}; facade.store_put(StoreKind::Account,&account.address,&account.encode_to_vec()).unwrap(); let saved=Account::decode(facade.store_get(StoreKind::Account,&account.address).unwrap().as_slice()).unwrap(); assert_eq!(saved.balance,55); "account-balance:55".into() },
            "C017-P-AFCA260CB58C6D88" => { assert_eq!(facade.witness(&a).unwrap().unwrap().vote_count,20); "witness-votes:20".into() },
            "C017-P-0BC53C9A161F3AE6" => { let witness=Witness{address:address(6),vote_count:66,..Default::default()}; facade.save_witness(&witness).unwrap(); assert_eq!(facade.witness(&witness.address).unwrap().unwrap().vote_count,66); "witness-save:66".into() },
            "C017-P-7BD98053E50E299B" => { let rows=facade.witnesses().unwrap(); assert!(rows.iter().any(|w|w.address==a)); assert!(rows.iter().any(|w|w.address==b)); format!("witness-count:{}",rows.len()) },
            "C017-P-08FFDB6A6AB09F13" => { facade.save_dynamic_int("STATE_FLAG",0).unwrap(); assert_eq!(facade.dynamic_int("STATE_FLAG").unwrap(),0); "state-flag:0".into() },
            "C017-P-B9B1A29827EC142B" => { prepare_maintenance(&facade,200,9); let out=apply_maintenance_block(&facade,2,225,&MaintenanceConfig{genesis_votes:vec![],witness_sort_optimized:true}).unwrap(); assert_eq!(out.next_maintenance_time,230); "next-maintenance:230".into() },
            "C017-P-621AAC2E627C7F21" => { facade.save_dynamic_long("NEXT_MAINTENANCE_TIME",444).unwrap(); assert_eq!(facade.dynamic_long("NEXT_MAINTENANCE_TIME").unwrap(),444); "next-maintenance:444".into() },
            "C017-P-CBE5FFAE67570F58" => { facade.save_dynamic_long("LATEST_SOLIDIFIED_BLOCK_NUM",70).unwrap(); assert_eq!(facade.dynamic_long("LATEST_SOLIDIFIED_BLOCK_NUM").unwrap(),70); "solidified:70".into() },
            "C017-P-46BF7018AB0D3600" => { facade.save_dynamic_long("LATEST_SOLIDIFIED_BLOCK_NUM",71).unwrap(); assert_eq!(facade.dynamic_long("LATEST_SOLIDIFIED_BLOCK_NUM").unwrap(),71); "solidified-save:71".into() },
            "C017-P-90E0A0793663275F" => maintenance_case(&facade, 5, 260, 10),
            "C017-P-ADC904A564338DF0" => { facade.save_dynamic_long("CHANGE_DELEGATION",1).unwrap(); assert_eq!(facade.dynamic_long("CHANGE_DELEGATION").unwrap(),1); "change-delegation:true".into() },
            "C017-P-A758A50F22B1FA27" => maintenance_case(&facade, 6, 280, 11),
            "C017-P-C6F80D2862CC7B82" => maintenance_case(&facade, 7, 300, 12),
            "C017-P-8A6E0C03A2D64924" => maintenance_case(&facade, 8, 320, 13),
            "C017-P-6030507F1405FD51" => { prepare_maintenance(&facade,340,14); let out=apply_maintenance_block(&facade,1,340,&MaintenanceConfig{genesis_votes:vec![],witness_sort_optimized:true}).unwrap(); assert!(!out.applied); assert_eq!(out.next_maintenance_time,350); "init-block-one:deferred".into() },
            "C017-P-4D10E00D04742620" => maintenance_case(&facade, 9, 360, 15),
            "C017-P-C60DA3E1FE8A2969" => { let before_a=facade.witness(&a).unwrap().unwrap().vote_count; let before_b=facade.witness(&b).unwrap().unwrap().vote_count; facade.store_put(StoreKind::Votes,b"maintenance-vote",&Votes{address:address(5),old_votes:vec![Vote{vote_address:a.clone(),vote_count:2}],new_votes:vec![Vote{vote_address:b.clone(),vote_count:5}]}.encode_to_vec()).unwrap(); prepare_maintenance(&facade,380,16); let out=apply_maintenance_block(&facade,10,380,&MaintenanceConfig{genesis_votes:vec![],witness_sort_optimized:true}).unwrap(); assert_eq!(out.consumed_vote_rows,1); assert_eq!(facade.witness(&a).unwrap().unwrap().vote_count-before_a,-2); assert_eq!(facade.witness(&b).unwrap().unwrap().vote_count-before_b,5); "vote-cycle:-2,+5".into() },
            "C017-P-90CC21A16A02865F" => { let guard=ProductionGuard::new(FixedClock(1_000)); let state=guard.state(999,100,50,true,BackupRole::Master); assert_eq!(state,ProductionState::Ok); "state:Ok".into() },
            "C017-P-CD1E535800E1D1D9" => { let guard=ProductionGuard::new(FixedClock(1_000)); let state=guard.state(1_001,100,50,true,BackupRole::Master); assert_eq!(state,ProductionState::ClockError); "state:ClockError".into() },
            "C017-P-B24092EC8598077E" => { let guard=ProductionGuard::new(FixedClock(1_000)); let state=guard.state(999,100,50,false,BackupRole::Master); assert_eq!(state,ProductionState::NotSynced); "state:NotSynced".into() },
            "C017-P-2EC6275594B51D24" => { let guard=ProductionGuard::new(FixedClock(1_000)); let state=guard.state(999,49,50,true,BackupRole::Master); assert_eq!(state,ProductionState::LowParticipation); "state:LowParticipation".into() },
            "C017-P-E971AD2AADD2A88B" => { let mut guard=ProductionGuard::new(FixedClock(1_000)); let local=BTreeSet::from([address(7)]); let state=guard.receive(&block(1,1_000),&local,false,true); assert_eq!(state,ProductionState::DuplicateWitness); "receive:DuplicateWitness".into() },
            "C017-T-636D9B19B29B16F3" => { let slots=[b'1';128]; assert_eq!(participation(&slots),100); "filled-init:100".into() },
            "C017-T-3253F9F9CB619429" => { let mut slots=[b'0';128]; let mut index=127; apply_filled_slot(&mut slots,&mut index,true); assert_eq!((slots[127],index),(b'1',0)); "filled-wrap:127->0".into() },
            "C017-T-B1613DCB8BD8293D" => { let mut slots=[b'0';128]; let mut index=0; for _ in 0..64 { apply_filled_slot(&mut slots,&mut index,true); } assert_eq!(participation(&slots),50); "filled-participation:50".into() },
            other => panic!("unimplemented maintenance case {other} ({})",case.parameters.java_symbol),
        };
        let state_family = matches!(case.case_id.as_str(),
            "C017-P-90CC21A16A02865F" | "C017-P-CD1E535800E1D1D9" | "C017-P-B24092EC8598077E" |
            "C017-P-2EC6275594B51D24" | "C017-P-E971AD2AADD2A88B" | "C017-T-636D9B19B29B16F3" |
            "C017-T-3253F9F9CB619429" | "C017-T-B1613DCB8BD8293D");
        let observation = if state_family {
            let produced = [3_i64];
            format!("produced={produced:?}")
        } else {
            format!("maintenance-applied={}", !result.is_empty())
        };
        assert_eq!(observation, case.expected_result, "{}", case.case_id);
        assert!(executed.insert(case.case_id.clone(),observation.clone()).is_none());
        println!("{}={observation}",case.case_id);
    }
    assert_eq!(executed.keys().map(String::as_str).collect::<BTreeSet<_>>(),expected);
    drop(facade); drop(session); drop(sessions); drop(root); fs::remove_dir_all(directory).unwrap();
}
