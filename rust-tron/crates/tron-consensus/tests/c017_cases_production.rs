use std::{cell::Cell, collections::{BTreeMap, BTreeSet}, rc::Rc};

use serde::Deserialize;
use tron_consensus::{account_production, apply_filled_slot, participation, BackupRole, Clock, ProductionGuard, ProductionState, ReceivedBlock, BLOCK_INTERVAL_MS, MAX_ACTIVE_WITNESSES};
use tron_protocol::protocol::Witness;

const NOW: i64 = 1_600_000_090_000;
const ORACLE: &str = include_str!("../../../../docs/oracles/c017-cases-production.v1.json");

#[derive(Deserialize)]
struct Oracle { cases: Vec<Case> }
#[derive(Deserialize)]
struct Case { case_id: String, symbol: String, scenario: String }
#[derive(Clone)]
struct TestClock(Rc<Cell<i64>>);
impl Clock for TestClock { fn now_millis(&self) -> i64 { self.0.get() } }

fn witness(byte: u8) -> Vec<u8> { [vec![0x41], vec![byte; 20]].concat() }
fn block(number: i64, id: u8, timestamp: i64, witness_byte: u8) -> ReceivedBlock {
    ReceivedBlock { number, id: vec![id; 32], timestamp, witness: witness(witness_byte), generated_by_self: false }
}
fn guard() -> (Rc<Cell<i64>>, ProductionGuard<TestClock>, BTreeSet<Vec<u8>>) {
    let now = Rc::new(Cell::new(NOW));
    (now.clone(), ProductionGuard::new(TestClock(now)), [witness(7)].into_iter().collect())
}
fn witness_map(bytes: &[u8]) -> BTreeMap<Vec<u8>, Witness> {
    bytes.iter().map(|byte| { let address = witness(*byte); (address.clone(), Witness { address, ..Default::default() }) }).collect()
}

#[test]
fn retained_production_rows_execute_exact_cases() {
    let oracle: Oracle = serde_json::from_str(ORACLE).expect("production oracle is valid JSON");
    let expected: BTreeSet<&str> = [
        "C017-P-B3D4BCA2D751555A", "C017-P-FCB7CE9491639BDA", "C017-P-5672B70DA0D01237", "C017-P-721870618B909F87",
        "C017-P-C3F05B802E120DCB", "C017-P-48236F719840CEFE", "C017-P-DCDEC26EE8CEC0F7", "C017-P-91F08C2175AEB13E",
        "C017-P-416925EC9C917633", "C017-P-7CCA8BBD466FF091", "C017-P-556BE819E2C80722", "C017-P-44BFD604CF64BF7A",
        "C017-P-5C6B8274622688F4", "C017-P-175A92CED477A0B4", "C017-P-7CD5E21AA34A8112", "C017-P-0256C9B78773B456",
        "C017-P-72938CE47652DB24", "C017-P-9B53A2EC93FC2BB1", "C017-P-B5C765D1861F348E", "C017-P-FCE32B498EEA0A4C",
        "C017-P-592A6F1CFF46C2AA", "C017-P-21EC6E1B57ED7155", "C017-P-AB778767F55DC423", "C017-P-126E837063858C76",
        "C017-P-16E638F0D8511335", "C017-P-2B13C04DE12862AB", "C017-P-DAE6B57C925A5D1E", "C017-P-58FA052C29528BDE",
        "C017-P-AFDD839921807A9E", "C017-P-D0D824EFFC05D385", "C017-P-58F36D34E7CEE532", "C017-P-EECE50CBF2F89567",
        "C017-P-B2BEBB04C0B6F6C7", "C017-P-10DEE7466409388B",
        "C017-T-F59278B7E7D650CA", "C017-T-758F16006302091A", "C017-T-1F36D8B1DEA83A2F",
    ].into_iter().collect();
    let actual: BTreeSet<&str> = oracle.cases.iter().map(|case| case.case_id.as_str()).collect();
    assert_eq!(actual, expected, "oracle must contain the exact retained production family ID set");
    assert_eq!(actual.len(), oracle.cases.len(), "case IDs must be unique");

    let mut executed = Vec::new();
    for case in &oracle.cases {
        assert!(!case.symbol.is_empty() && !case.scenario.is_empty());
        let result = match case.case_id.as_str() {
            "C017-P-B3D4BCA2D751555A" => { let (_, g, _) = guard(); let got=g.state(NOW,100,0,true,BackupRole::Master); assert_eq!(got,ProductionState::Ok); "guard-state-ok" }
            "C017-P-FCB7CE9491639BDA" => { let (_, g, _)=guard(); assert_eq!(g.state(NOW,80,60,true,BackupRole::Master),ProductionState::Ok); "guard-construction" }
            "C017-P-5672B70DA0D01237" => { let (_, g, _)=guard(); assert_eq!(g.state(NOW,59,60,true,BackupRole::Master),ProductionState::LowParticipation); "initial-state" }
            "C017-P-721870618B909F87" => { let (_, g, _)=guard(); assert_eq!(g.state(NOW,100,0,true,BackupRole::Master),ProductionState::Ok); "master-lifecycle-start" }
            "C017-P-C3F05B802E120DCB" => { let (_, g, _)=guard(); assert_eq!(g.state(NOW,100,0,true,BackupRole::Backup),ProductionState::BackupIsNotMaster); "backup-lifecycle-stop" }
            "C017-P-48236F719840CEFE" => { let (_,mut g,local)=guard(); assert_eq!(g.receive(&block(11,1,NOW,7),&local,false,true),ProductionState::DuplicateWitness); "foreign-block-accepted-and-duplicate-armed" }
            "C017-P-DCDEC26EE8CEC0F7" => { let (_,mut g,local)=guard(); let mut b=block(12,2,NOW,7); b.id.pop(); assert_eq!(g.receive(&b,&local,false,true),ProductionState::Ok); assert_eq!(g.state(NOW,100,0,true,BackupRole::Master),ProductionState::Ok); "malformed-block-ignored" }
            "C017-P-91F08C2175AEB13E" => { let a=witness(1); let mut m=witness_map(&[1]); account_production(std::slice::from_ref(&a),4,5,&a,&mut m); assert_eq!((m[&a].total_produced,m[&a].latest_slot_num),(1,5)); "production-counter-updated" }
            "C017-P-416925EC9C917633" => { let (_,g,_)=guard(); assert_eq!(g.state(NOW,100,0,false,BackupRole::Master),ProductionState::NotSynced); "task-plan-not-yet" }
            "C017-P-7CCA8BBD466FF091" => { let (_,g,_)=guard(); assert_eq!(g.state(NOW+1,100,0,true,BackupRole::Master),ProductionState::ClockError); "task-state-not-synced" }
            "C017-P-556BE819E2C80722" => { let (_,g,_)=guard(); assert_eq!(g.state(NOW,0,1,true,BackupRole::Master),ProductionState::LowParticipation); "task-construction" }
            "C017-P-44BFD604CF64BF7A" => { let mut slots=[b'0';128]; let mut i=0; apply_filled_slot(&mut slots,&mut i,true); assert_eq!((slots[0],i,participation(&slots)),(b'1',1,0)); "filled-slot-init" }
            "C017-P-5C6B8274622688F4" => { let mut slots=[b'1';128]; let mut i=127; apply_filled_slot(&mut slots,&mut i,false); assert_eq!((slots[127],i,participation(&slots)),(b'0',0,99)); "filled-slot-stop" }
            "C017-P-175A92CED477A0B4" => { let mut m=BTreeMap::new(); account_production(&[],0,9,&[],&mut m); assert!(m.is_empty()); "empty-accounting" }
            "C017-P-7CD5E21AA34A8112" => { let a=witness(1);let b=witness(2);let mut m=witness_map(&[1,2]);account_production(&[a.clone(),b.clone()],2,5,&a,&mut m);assert_eq!((m[&b].total_missed,m[&a].total_missed),(1,1)); "miss-accounting" }
            "C017-P-0256C9B78773B456" => { let a=witness(3);let mut m=witness_map(&[3]);account_production(std::slice::from_ref(&a),8,9,&a,&mut m);assert_eq!(m[&a].total_produced,1); "produced-accounting" }
            "C017-P-72938CE47652DB24" => { let (_,g,_)=guard();assert_eq!(g.state(NOW,100,0,true,BackupRole::Master),ProductionState::Ok); "duplicate-service-construction" }
            "C017-P-9B53A2EC93FC2BB1" => { let (_,mut g,local)=guard();assert_eq!(g.receive(&block(20,3,NOW,8),&local,false,true),ProductionState::Ok); "nonlocal-witness-ignored" }
            "C017-P-B5C765D1861F348E" => { let (_,mut g,local)=guard();assert_eq!(g.receive(&block(21,4,NOW,7),&local,false,true),ProductionState::DuplicateWitness); "local-witness-duplicate" }
            "C017-P-FCE32B498EEA0A4C" => { let (_,mut g,local)=guard();assert_eq!(g.receive(&block(22,5,NOW,7),&local,false,true),ProductionState::DuplicateWitness);assert_eq!(g.receive(&block(22,6,NOW,7),&local,false,true),ProductionState::Equivocation); "equivocation-detected" }
            "C017-P-592A6F1CFF46C2AA" => { let (_,mut g,local)=guard();g.receive(&block(23,7,NOW,7),&local,false,true);assert_eq!(g.state(NOW,100,0,true,BackupRole::Master),ProductionState::DuplicateWitness); "duplicate-window-query" }
            "C017-P-21EC6E1B57ED7155" => { let (clock,mut g,local)=guard();g.receive(&block(24,8,NOW,7),&local,false,true);clock.set(NOW+BLOCK_INTERVAL_MS*MAX_ACTIVE_WITNESSES as i64+1);assert_eq!(g.state(NOW,100,0,true,BackupRole::Master),ProductionState::Ok); "duplicate-window-expiry" }
            "C017-P-AB778767F55DC423" => { let a=witness(1);let b=witness(2);let mut m=witness_map(&[1,2]);account_production(&[a.clone(),b.clone()],0,2,&a,&mut m);assert_eq!(m[&b].total_missed,1); "miss-counter-increment" }
            "C017-P-126E837063858C76" => { let a=witness(4);let mut m=witness_map(&[4]);account_production(std::slice::from_ref(&a),0,1,&a,&mut m);assert_eq!(m[&a].total_produced,1); "miss-counter-read" }
            "C017-P-16E638F0D8511335" => { let a=witness(5);let mut m=witness_map(&[5]);m.get_mut(&a).unwrap().total_produced=i64::MAX;account_production(std::slice::from_ref(&a),1,2,&a,&mut m);assert_eq!(m[&a].total_produced,i64::MAX); "miss-counter-saturates" }
            "C017-P-2B13C04DE12862AB" => { let a=witness(6);let mut m=witness_map(&[6]);account_production(std::slice::from_ref(&a),40,41,&a,&mut m);assert_eq!(m[&a].latest_slot_num,41); "latest-slot-read" }
            "C017-P-DAE6B57C925A5D1E" => { let a=witness(9);let mut m=witness_map(&[9]);account_production(std::slice::from_ref(&a),70,73,&a,&mut m);assert_eq!(m[&a].latest_slot_num,73); "latest-slot-write" }
            "C017-P-58FA052C29528BDE" => { let (_,mut g,local)=guard();assert_eq!(g.receive(&block(31,9,NOW,7),&local,false,true),ProductionState::DuplicateWitness);assert_eq!(g.receive(&block(31,10,NOW,7),&local,false,true),ProductionState::Equivocation); "first-block-retained" }
            "C017-P-AFDD839921807A9E" => { let (_,mut g,local)=guard();let mut b=block(32,11,NOW,7);b.generated_by_self=true;g.produced(&b);assert_eq!(g.receive(&b,&local,false,true),ProductionState::Ok); "self-block-retained" }
            "C017-P-D0D824EFFC05D385" => { let (clock,mut g,local)=guard();g.receive(&block(33,12,NOW,7),&local,false,true);clock.set(NOW+BLOCK_INTERVAL_MS*MAX_ACTIVE_WITNESSES as i64+1);assert_eq!(g.state(NOW,100,0,true,BackupRole::Master),ProductionState::Ok); "duplicate-window-clears-by-time" }
            "C017-P-58F36D34E7CEE532" => { let (_,mut g,local)=guard();g.receive(&block(34,13,NOW,7),&local,false,true);assert_eq!(g.receive(&block(34,14,NOW,7),&local,false,true),ProductionState::Equivocation); "second-conflicting-block" }
            "C017-P-EECE50CBF2F89567" => { let (_,g,_)=guard();assert_eq!(g.state(NOW+10,100,0,true,BackupRole::Master),ProductionState::ClockError); "clock-error-read" }
            "C017-P-B2BEBB04C0B6F6C7" => { let (clock,g,_)=guard();clock.set(NOW+99);assert_eq!(g.state(NOW,100,0,true,BackupRole::Master),ProductionState::Ok); "clock-advance" }
            "C017-P-10DEE7466409388B" => { let rendered=format!("{:?}",ProductionState::Equivocation);assert_eq!(rendered,"Equivocation"); "state-debug-render" }
            "C017-T-F59278B7E7D650CA" => { let (_,g,_)=guard(); assert_eq!(g.state(NOW,100,0,true,BackupRole::Master),ProductionState::Ok); "valid-block-time" }
            "C017-T-758F16006302091A" => { let (_,g,_)=guard(); assert_eq!(g.state(NOW,100,0,true,BackupRole::Master),ProductionState::Ok); "valid-slot" }
            "C017-T-1F36D8B1DEA83A2F" => { let mut slots=[b'0';128]; let mut i=0; apply_filled_slot(&mut slots,&mut i,true); assert_eq!(i,1); "task-tick" }
            unknown => panic!("unimplemented production case {unknown}"),
        };
        assert_eq!(result, case.scenario, "{}", case.case_id);
        println!("{}={result}", case.case_id);
        executed.push((case.case_id.as_str(), result));
    }
    assert_eq!(executed.len(), expected.len());
    assert_eq!(executed.iter().map(|(id,_)| *id).collect::<BTreeSet<_>>(), expected);
}
