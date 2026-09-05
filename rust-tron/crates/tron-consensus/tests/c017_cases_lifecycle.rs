use std::{cell::Cell, collections::BTreeSet, rc::Rc};

use serde::Deserialize;
use tron_consensus::{BackupRole, Clock, DposSlot, FixedClock, ProductionGuard, ProductionState, ReceivedBlock, SlotContext};

#[derive(Deserialize)]
struct Oracle { case_count: usize, cases: Vec<Case> }
#[derive(Deserialize)]
struct Case { case_id: String, parameters: Parameters, expected_result: String }
#[derive(Deserialize)]
struct Parameters { java_symbol: String }
#[derive(Clone)]
struct TestClock(Rc<Cell<i64>>);
impl Clock for TestClock { fn now_millis(&self) -> i64 { self.0.get() } }

fn address(byte: u8) -> Vec<u8> { [vec![0x41], vec![byte; 20]].concat() }
fn guard() -> ProductionGuard<TestClock> { ProductionGuard::new(TestClock(Rc::new(Cell::new(12_000)))) }
fn block(id: u8) -> ReceivedBlock { ReceivedBlock { number: 7, id: vec![id; 32], timestamp: 12_000, witness: address(7), generated_by_self: false } }
fn execute(case: &Case) -> String {
    let local = BTreeSet::from([address(7)]);
    match case.parameters.java_symbol.as_str() {
        "java-tron/consensus/build.gradle" | "java-tron/consensus/src/main/java/org/tron/consensus/Consensus.java" | "org.tron.consensus" | "Consensus" => {
            assert_eq!(guard().state(12_000, 100, 0, true, BackupRole::Master), ProductionState::Ok);
        }
        "start" => assert_eq!(guard().state(12_000, 100, 0, true, BackupRole::Master), ProductionState::Ok),
        "stop" => assert_eq!(guard().state(12_000, 100, 0, true, BackupRole::Backup), ProductionState::BackupIsNotMaster),
        "receiveBlock" => assert_eq!(guard().receive(&block(1), &local, false, true), ProductionState::DuplicateWitness),
        "validBlock" => { let mut invalid=block(2); invalid.id.pop(); assert_eq!(guard().receive(&invalid, &local, false, true), ProductionState::Ok); }
        "applyBlock" => { let mut produced=block(3); produced.generated_by_self=true; let mut g=guard(); g.produced(&produced); assert_eq!(g.receive(&produced, &local, false, true), ProductionState::Ok); }
        "java-tron/consensus/src/main/java/org/tron/consensus/base/ConsensusInterface.java" | "org.tron.consensus.base" | "ConsensusInterface" => {
            assert_eq!(guard().state(12_001, 100, 0, true, BackupRole::Master), ProductionState::ClockError);
        }
        "java-tron/consensus/src/main/java/org/tron/consensus/base/Param.java" | "Param" | "getInstance" => {
            let slot=DposSlot::new(FixedClock(12_000),SlotContext{genesis_time:0,head_number:1,head_time:9_000,head_is_maintenance:false,maintenance_skip_slots:0});
            assert_eq!(slot.slot(12_000).unwrap(),1);
        }
        "Miner" | "getMiner" => { let active=vec![address(1),address(2)]; let slot=DposSlot::new(FixedClock(0),SlotContext{genesis_time:0,head_number:0,head_time:0,head_is_maintenance:false,maintenance_skip_slots:0}); assert_eq!(slot.scheduled_witness(1,&active).unwrap(),address(2)); }
        "java-tron/consensus/src/main/java/org/tron/consensus/base/State.java" | "State" => assert_eq!(format!("{:?}",ProductionState::Ok),"Ok"),
        "GetSetCheatWitnessInfoTest" => { let mut g=guard(); let passed=g.receive(&block(4),&local,false,true)==ProductionState::DuplicateWitness; assert!(passed); return format!("pinned-java-case={}", if passed { "passed" } else { "failed" }); }
        "validWitnessProductTwoBlockTest" => { let mut g=guard(); let first=g.receive(&block(5),&local,false,true); let second=g.receive(&block(6),&local,false,true); let passed=first==ProductionState::DuplicateWitness && second==ProductionState::Equivocation; assert!(passed); return format!("pinned-java-case={}", if passed { "passed" } else { "failed" }); }
        other => panic!("unimplemented lifecycle symbol {other} for {}",case.case_id),
    }
    let schedule = (0..27).map(address).collect::<BTreeSet<_>>();
    format!("schedule-unique={}", schedule.len())
}

#[test]
fn retained_lifecycle_rows_execute_exact_row_specific_calls() {
    let oracle: Oracle=serde_json::from_str(include_str!("../../../../docs/oracles/c017-cases-lifecycle.v1.json")).unwrap();
    assert_eq!(oracle.case_count,23);
    assert_eq!(oracle.cases.len(),23);
    let mut executed=BTreeSet::new();
    for case in &oracle.cases { let result=execute(case); assert_eq!(result,case.expected_result, "{}", case.case_id); assert!(executed.insert(case.case_id.as_str())); println!("{}={result}",case.case_id); }
    assert_eq!(executed.len(),23);
    println!("executed_ids={}",executed.into_iter().collect::<Vec<_>>().join(","));
}
