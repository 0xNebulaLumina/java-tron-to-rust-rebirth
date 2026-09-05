use std::{cell::Cell, collections::BTreeSet, rc::Rc};

use tron_consensus::{Clock, ProductionGuard, ProductionState, ReceivedBlock, BLOCK_INTERVAL_MS, MAX_ACTIVE_WITNESSES};

const NOW: i64 = 1_600_000_090_000;
const BLOCK_ID_LEN: usize = 32;

#[derive(Clone)]
struct AdjustableClock(Rc<Cell<i64>>);
impl Clock for AdjustableClock {
    fn now_millis(&self) -> i64 { self.0.get() }
}

fn block(number: i64, id: u8, timestamp: i64) -> ReceivedBlock {
    ReceivedBlock {
        number,
        id: vec![id; BLOCK_ID_LEN],
        timestamp,
        witness: [vec![0x41], vec![7; 20]].concat(),
        generated_by_self: false,
    }
}

fn setup() -> (Rc<Cell<i64>>, ProductionGuard<AdjustableClock>, BTreeSet<Vec<u8>>) {
    let time = Rc::new(Cell::new(NOW));
    let witnesses = [[vec![0x41], vec![7; 20]].concat()].into_iter().collect();
    (time.clone(), ProductionGuard::new(AdjustableClock(time)), witnesses)
}

#[test]
fn future_local_blocks_match_java_duplicate_interlock_after_handler_validation() {
    let (_, mut guard, witnesses) = setup();
    let future = NOW + BLOCK_INTERVAL_MS * 10_000;

    assert_eq!(guard.receive(&block(400, 10, future), &witnesses, false, false), ProductionState::DuplicateWitness);
    assert_eq!(guard.receive(&block(400, 10, future), &witnesses, false, true), ProductionState::DuplicateWitness);
    assert_eq!(guard.receive(&block(400, 11, future), &witnesses, false, true), ProductionState::Equivocation);
    assert_eq!(guard.state(NOW, 100, 0, true, tron_consensus::BackupRole::Master), ProductionState::DuplicateWitness);

    let nonlocal = BTreeSet::new();
    assert_eq!(guard.receive(&block(401, 12, future + 1), &nonlocal, false, true), ProductionState::Ok);

    assert_eq!(guard.receive(&block(402, 13, NOW - BLOCK_INTERVAL_MS - 1), &witnesses, false, true), ProductionState::Ok);
    let mut short_id = block(403, 14, future);
    short_id.id.pop();
    let mut short_witness = block(404, 15, future);
    short_witness.witness.pop();
    assert_eq!(guard.receive(&short_id, &witnesses, false, true), ProductionState::Ok);
    assert_eq!(guard.receive(&short_witness, &witnesses, false, true), ProductionState::Ok);
}

#[test]
fn handler_validation_precedes_equivocation_tracking() {
    let (_, mut guard, witnesses) = setup();
    assert_eq!(guard.receive(&block(10, 1, NOW), &witnesses, false, false), ProductionState::DuplicateWitness);
    assert_eq!(guard.receive(&block(10, 2, NOW), &witnesses, false, true), ProductionState::DuplicateWitness);
    assert_eq!(guard.receive(&block(10, 3, NOW), &witnesses, false, true), ProductionState::Equivocation);
}

#[test]
fn legitimate_equivocation_expires_and_duplicate_window_is_fixed() {
    let (time, mut guard, witnesses) = setup();
    assert_eq!(guard.receive(&block(10, 1, NOW), &witnesses, false, true), ProductionState::DuplicateWitness);
    assert_eq!(guard.receive(&block(10, 2, NOW), &witnesses, false, true), ProductionState::Equivocation);

    let duplicate_deadline = NOW + BLOCK_INTERVAL_MS * MAX_ACTIVE_WITNESSES as i64;
    assert_eq!(guard.state(NOW, 100, 0, true, tron_consensus::BackupRole::Master), ProductionState::DuplicateWitness);
    time.set(NOW + BLOCK_INTERVAL_MS);
    assert_eq!(guard.receive(&block(11, 3, time.get()), &witnesses, false, true), ProductionState::DuplicateWitness);
    time.set(duplicate_deadline + 1);
    assert_eq!(guard.state(NOW, 100, 0, true, tron_consensus::BackupRole::Master), ProductionState::Ok);

    assert_eq!(guard.receive(&block(500, 4, time.get()), &witnesses, false, true), ProductionState::DuplicateWitness);
    assert_eq!(guard.receive(&block(10, 5, NOW), &witnesses, false, true), ProductionState::Ok);
}
