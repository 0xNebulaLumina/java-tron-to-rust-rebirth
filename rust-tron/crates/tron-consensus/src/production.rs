use std::collections::{BTreeMap, BTreeSet};

use crate::schedule::{Clock, DposSlot, ScheduleError, BLOCK_INTERVAL_MS, MAX_ACTIVE_WITNESSES};

#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub enum BackupRole { Master, Backup }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub enum ProductionState { Ok, NotSynced, DuplicateWitness, ClockError, NotMyTurn, NotTimeYet, PermissionError, LowParticipation, ProduceBlockFailed, BackupIsNotMaster, Equivocation }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct ProductionPlan { pub slot: i64, pub timestamp: i64, pub timeout: i64, pub witness: Vec<u8> }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct ReceivedBlock { pub number: i64, pub id: Vec<u8>, pub timestamp: i64, pub witness: Vec<u8>, pub generated_by_self: bool }

const BLOCK_ID_LEN: usize = 32;
const WITNESS_ADDRESS_LEN: usize = 21;
const SEEN_HEIGHT_WINDOW: i64 = 200;
const SEEN_SLOT_WINDOW: i64 = MAX_ACTIVE_WITNESSES as i64;
const SEEN_CAPACITY: usize = 200;

#[derive(Clone, Debug)]
struct SeenBlock { id: Vec<u8>, height: i64 }

pub struct ProductionGuard<C> {
    clock: C,
    duplicate_until: i64,
    local_block: Option<Vec<u8>>,
    latest_height: i64,
    seen: BTreeMap<(i64, Vec<u8>), SeenBlock>,
}
impl<C: Clock> ProductionGuard<C> {
    #[must_use] pub fn new(clock: C) -> Self { Self { clock, duplicate_until: 0, local_block: None, latest_height: 0, seen: BTreeMap::new() } }
    pub fn state(&self, head_time: i64, participation: i32, minimum: i32, synced: bool, role: BackupRole) -> ProductionState {
        let now = self.clock.now_millis();
        if now < head_time { return ProductionState::ClockError; }
        if !synced { return ProductionState::NotSynced; }
        if role != BackupRole::Master { return ProductionState::BackupIsNotMaster; }
        if now <= self.duplicate_until { return ProductionState::DuplicateWitness; }
        if participation < minimum { return ProductionState::LowParticipation; }
        ProductionState::Ok
    }
    pub fn plan(&self, slots: &DposSlot<C>, active: &[Vec<u8>], local: &BTreeSet<Vec<u8>>, timeout_percent: i64) -> Result<ProductionPlan, ProductionState> where C: Clone {
        let slot = slots.slot(self.clock.now_millis().saturating_add(50)).map_err(map_schedule)?;
        if slot == 0 { return Err(ProductionState::NotTimeYet); }
        let witness = slots.scheduled_witness(slot, active).map_err(map_schedule)?.to_vec();
        if !local.contains(&witness) { return Err(ProductionState::NotMyTurn); }
        let timestamp = slots.time(slot).map_err(map_schedule)?;
        let timeout = timestamp.checked_add((BLOCK_INTERVAL_MS / 2).saturating_mul(timeout_percent) / 100).ok_or(ProductionState::ProduceBlockFailed)?;
        Ok(ProductionPlan { slot, timestamp, timeout, witness })
    }
    pub fn produced(&mut self, block: &ReceivedBlock) {
        let now = self.clock.now_millis();
        if !valid_structure(block, now) { return; }
        self.local_block = Some(block.id.clone());
        self.retain(block, now);
    }
    pub fn receive(&mut self, block: &ReceivedBlock, local_witnesses: &BTreeSet<Vec<u8>>, syncing: bool, block_handle_ok: bool) -> ProductionState {
        let now = self.clock.now_millis();
        if !valid_structure(block, now) { return ProductionState::Ok; }
        if block.generated_by_self { self.produced(block); return ProductionState::Ok; }
        if self.local_block.as_deref() == Some(&block.id) || syncing || !local_witnesses.contains(&block.witness) { return ProductionState::Ok; }
        if !block_handle_ok { self.arm_duplicate(now); return ProductionState::DuplicateWitness; }
        if self.local_block.as_ref().is_some_and(|id| id > &block.id) { return ProductionState::Ok; }
        self.prune(block.number, now);

        let key = (block.timestamp, block.witness.clone());
        if self.seen.get(&key).is_some_and(|seen| seen.id != block.id) {
            self.arm_duplicate(now);
            return ProductionState::Equivocation;
        }
        self.retain(block, now);
        self.arm_duplicate(now);
        ProductionState::DuplicateWitness
    }

    fn arm_duplicate(&mut self, now: i64) {
        if now > self.duplicate_until {
            self.duplicate_until = now.saturating_add(BLOCK_INTERVAL_MS.saturating_mul(MAX_ACTIVE_WITNESSES as i64));
        }
    }

    fn retain(&mut self, block: &ReceivedBlock, now: i64) {
        self.prune(block.number, now);
        self.seen.insert((block.timestamp, block.witness.clone()), SeenBlock { id: block.id.clone(), height: block.number });
        while self.seen.len() > SEEN_CAPACITY {
            let oldest = self.seen.iter().min_by_key(|(key, seen)| (seen.height, *key)).map(|(key, _)| key.clone());
            if let Some(key) = oldest { self.seen.remove(&key); } else { break; }
        }
    }

    fn prune(&mut self, height: i64, now: i64) {
        self.latest_height = self.latest_height.max(height);
        let oldest_height = self.latest_height.saturating_sub(SEEN_HEIGHT_WINDOW);
        let oldest_time = now.saturating_sub(BLOCK_INTERVAL_MS.saturating_mul(SEEN_SLOT_WINDOW));
        self.seen.retain(|(timestamp, _), seen| *timestamp >= oldest_time && seen.height >= oldest_height);
    }
}

fn valid_structure(block: &ReceivedBlock, now: i64) -> bool {
    block.number >= 0
        && block.id.len() == BLOCK_ID_LEN
        && block.witness.len() == WITNESS_ADDRESS_LEN
        && block.timestamp >= now.saturating_sub(BLOCK_INTERVAL_MS)
}
fn map_schedule(error: ScheduleError) -> ProductionState { match error { ScheduleError::NoActiveWitnesses | ScheduleError::NegativeCurrentSlot | ScheduleError::Overflow => ProductionState::ProduceBlockFailed } }

pub fn account_production(active: &[Vec<u8>], previous_absolute_slot: i64, current_absolute_slot: i64, block_witness: &[u8], witnesses: &mut BTreeMap<Vec<u8>, tron_protocol::protocol::Witness>) {
    if current_absolute_slot > previous_absolute_slot + 1 && !active.is_empty() {
        for missed_slot in previous_absolute_slot + 1..current_absolute_slot {
            let index = usize::try_from(missed_slot.rem_euclid(active.len() as i64)).expect("nonnegative modulo");
            if let Some(witness) = witnesses.get_mut(&active[index]) { witness.total_missed = witness.total_missed.saturating_add(1); witness.latest_slot_num = missed_slot; }
        }
    }
    if let Some(witness) = witnesses.get_mut(block_witness) { witness.total_produced = witness.total_produced.saturating_add(1); witness.latest_slot_num = current_absolute_slot; }
}

/// Applies java-tron StatisticManager witness accounting for one accepted block.
pub fn account_block_production(active: &[Vec<u8>], previous_absolute_slot: i64, current_absolute_slot: i64, block_number: i64, block_witness: &[u8], witnesses: &mut BTreeMap<Vec<u8>, tron_protocol::protocol::Witness>) {
    account_production(active, previous_absolute_slot, current_absolute_slot, block_witness, witnesses);
    if let Some(witness) = witnesses.get_mut(block_witness) { witness.latest_block_num = block_number; }
}


#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::BTreeSet, rc::Rc};

    use super::*;

    #[derive(Clone)]
    struct TestClock(Rc<Cell<i64>>);
    impl Clock for TestClock { fn now_millis(&self) -> i64 { self.0.get() } }

    fn block(number: i64, id: u8, timestamp: i64, witness: u8) -> ReceivedBlock {
        ReceivedBlock { number, id: vec![id; BLOCK_ID_LEN], timestamp, witness: vec![witness; WITNESS_ADDRESS_LEN], generated_by_self: false }
    }

    fn guard(now: i64) -> (Rc<Cell<i64>>, ProductionGuard<TestClock>, BTreeSet<Vec<u8>>) {
        let time = Rc::new(Cell::new(now));
        let witnesses = [vec![7; WITNESS_ADDRESS_LEN]].into_iter().collect();
        (time.clone(), ProductionGuard::new(TestClock(time)), witnesses)
    }

    #[test]
    fn future_unique_flood_is_bounded_while_stale_and_malformed_blocks_are_rejected() {
        let now = 1_000_000;
        let (_, mut guard, witnesses) = guard(now);
        for id in 0..=255 {
            let timestamp = now + BLOCK_INTERVAL_MS + 1 + i64::from(id);
            assert_eq!(guard.receive(&block(i64::from(id), id, timestamp, 7), &witnesses, false, true), ProductionState::DuplicateWitness);
        }
        assert_eq!(guard.seen.len(), SEEN_CAPACITY);
        for id in 0..=255 {
            assert_eq!(guard.receive(&block(i64::from(id), id, now - BLOCK_INTERVAL_MS - 1, 7), &witnesses, false, true), ProductionState::Ok);
            let mut malformed = block(i64::from(id), id, now, 7);
            if id % 2 == 0 { malformed.id.pop(); } else { malformed.witness.pop(); }
            assert_eq!(guard.receive(&malformed, &witnesses, false, true), ProductionState::Ok);
        }
        assert_eq!(guard.seen.len(), SEEN_CAPACITY);
    }

    #[test]
    fn handler_rejection_cannot_seed_equivocation_history() {
        let now = 1_000_000;
        let (_, mut guard, witnesses) = guard(now);
        assert_eq!(guard.receive(&block(10, 1, now, 7), &witnesses, false, false), ProductionState::DuplicateWitness);
        assert!(guard.seen.is_empty());
        assert_eq!(guard.receive(&block(10, 2, now, 7), &witnesses, false, true), ProductionState::DuplicateWitness);
        assert_eq!(guard.seen.len(), 1);
    }

    #[test]
    fn validated_conflicting_blocks_are_equivocation() {
        let now = 1_000_000;
        let (_, mut guard, witnesses) = guard(now);
        assert_eq!(guard.receive(&block(10, 1, now, 7), &witnesses, false, true), ProductionState::DuplicateWitness);
        assert_eq!(guard.receive(&block(10, 2, now, 7), &witnesses, false, true), ProductionState::Equivocation);
        assert_eq!(guard.seen.len(), 1);
    }

    #[test]
    fn seen_history_prunes_by_slot_height_and_capacity() {
        let now = 1_000_000;
        let (time, mut guard, witnesses) = guard(now);
        for offset in 0..SEEN_CAPACITY + 20 {
            time.set(now + offset as i64);
            let mut candidate = block(offset as i64, (offset % 255) as u8, time.get(), 7);
            candidate.timestamp += offset as i64;
            guard.receive(&candidate, &witnesses, false, true);
        }
        assert!(guard.seen.len() <= SEEN_CAPACITY);

        time.set(now + BLOCK_INTERVAL_MS * (SEEN_SLOT_WINDOW + 2));
        guard.receive(&block(1_000, 3, time.get(), 7), &witnesses, false, true);
        assert_eq!(guard.seen.len(), 1);
        assert!(guard.seen.values().all(|seen| seen.height == 1_000));
    }

    #[test]
    fn duplicate_window_is_not_extended_by_repeated_blocks() {
        let now = 1_000_000;
        let (time, mut guard, witnesses) = guard(now);
        guard.receive(&block(10, 1, now, 7), &witnesses, false, true);
        let deadline = guard.duplicate_until;
        time.set(now + BLOCK_INTERVAL_MS);
        guard.receive(&block(11, 2, time.get(), 7), &witnesses, false, true);
        assert_eq!(guard.duplicate_until, deadline);
        assert_eq!(deadline, now + BLOCK_INTERVAL_MS * MAX_ACTIVE_WITNESSES as i64);
    }
    #[test]
    fn statistic_accounting_records_block_number() {
        let witness=vec![1;21];let mut witnesses=BTreeMap::from([(witness.clone(),tron_protocol::protocol::Witness{address:witness.clone(),..Default::default()})]);
        account_block_production(std::slice::from_ref(&witness),4,5,77,&witness,&mut witnesses);
        let updated=&witnesses[&witness];assert_eq!(updated.total_produced,1);assert_eq!(updated.latest_slot_num,5);assert_eq!(updated.latest_block_num,77);
    }

}
pub fn apply_filled_slot(slots: &mut [u8; 128], index: &mut usize, filled: bool) { slots[*index] = if filled { b'1' } else { b'0' }; *index = (*index + 1) % slots.len(); }
#[must_use] pub fn participation(slots: &[u8; 128]) -> i32 { (100 * slots.iter().filter(|&&slot| slot == b'1').count() / slots.len()) as i32 }
