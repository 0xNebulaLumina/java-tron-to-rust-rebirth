use std::collections::{BTreeMap, BTreeSet};
use tron_consensus::{account_production, apply_filled_slot, java_shuffle, participation, BackupRole, DposSlot, FixedClock, ProductionGuard, ProductionState, SlotContext, BLOCK_INTERVAL_MS};
use tron_protocol::protocol::Witness;

fn address(byte: u8) -> Vec<u8> { [vec![0x41], vec![byte; 20]].concat() }

#[test]
fn java_slot_arithmetic_maintenance_skip_and_single_repeat() {
    let genesis = 1_600_000_000_000;
    let clock = FixedClock(genesis + 12_345);
    let genesis_slots = DposSlot::new(clock, SlotContext { genesis_time: genesis, head_number: 0, head_time: genesis, head_is_maintenance: false, maintenance_skip_slots: 0 });
    assert_eq!(genesis_slots.time(0).unwrap(), clock.0);
    assert_eq!(genesis_slots.time(1).unwrap(), genesis + BLOCK_INTERVAL_MS);
    assert_eq!(genesis_slots.slot(genesis + 2_999).unwrap(), 0);
    assert_eq!(genesis_slots.slot(genesis + 3_000).unwrap(), 1);

    let slots = DposSlot::new(clock, SlotContext { genesis_time: genesis, head_number: 9, head_time: genesis + 10_234, head_is_maintenance: true, maintenance_skip_slots: 2 });
    assert_eq!(slots.time(1).unwrap(), genesis + 18_000);
    let witnesses: Vec<_> = (0..27).map(address).collect();
    assert_eq!(slots.scheduled_witness(1, &witnesses).unwrap(), witnesses[4]);
}

#[test]
fn pinned_java_shuffle_vector_and_twenty_seven_witness_rotation() {
    let mut vector: Vec<u8> = (0..10).collect();
    java_shuffle(&mut vector, 1_600_000_003_000);
    assert_eq!(vector, [9, 1, 0, 5, 6, 4, 2, 3, 8, 7]);

    let genesis = 1_600_000_000_000;
    let active: Vec<_> = (0..27).map(address).collect();
    let slots = DposSlot::new(FixedClock(genesis + 3_000), SlotContext { genesis_time: genesis, head_number: 0, head_time: genesis, head_is_maintenance: false, maintenance_skip_slots: 0 });
    for slot in 1..=54 { assert_eq!(slots.scheduled_witness(slot, &active).unwrap(), active[(slot as usize) % 27]); }
}

#[test]
fn production_guards_misses_participation_and_equivocation() {
    let genesis = 1_600_000_000_000;
    let clock = FixedClock(genesis + 3_000);
    let slots = DposSlot::new(clock, SlotContext { genesis_time: genesis, head_number: 0, head_time: genesis, head_is_maintenance: false, maintenance_skip_slots: 0 });
    let active: Vec<_> = (0..27).map(address).collect();
    let mut local = BTreeSet::new(); local.insert(active[1].clone());
    let guard = ProductionGuard::new(clock);
    assert_eq!(guard.state(genesis, 100, 70, true, BackupRole::Master), ProductionState::Ok);
    assert_eq!(guard.state(genesis, 69, 70, true, BackupRole::Master), ProductionState::LowParticipation);
    assert_eq!(guard.state(genesis, 100, 70, true, BackupRole::Backup), ProductionState::BackupIsNotMaster);
    assert_eq!(guard.plan(&slots, &active, &local, 100).unwrap().timestamp, genesis + 3_000);

    let mut witnesses: BTreeMap<_, _> = active.iter().cloned().map(|a| (a.clone(), Witness { address: a, ..Default::default() })).collect();
    account_production(&active, 1, 4, &active[4], &mut witnesses);
    assert_eq!(witnesses[&active[2]].total_missed, 1);
    assert_eq!(witnesses[&active[3]].total_missed, 1);
    assert_eq!(witnesses[&active[4]].total_produced, 1);

    let mut filled = [b'1'; 128]; let mut index = 0;
    apply_filled_slot(&mut filled, &mut index, false);
    assert_eq!(participation(&filled), 99);
}
