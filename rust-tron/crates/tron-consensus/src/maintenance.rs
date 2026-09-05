use std::{collections::BTreeMap, num::Wrapping};

use num_bigint::BigInt;
use prost::Message;
use tron_protocol::protocol::Account;
use tron_state::StoreKind;

use crate::{rewards::accumulate_vi, schedule::{sort_witnesses, MAX_ACTIVE_WITNESSES}, state::{delegation_brokerage_key, delegation_key, delegation_vote_key, ConsensusRead, StateError, StateFacade}};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceConfig { pub genesis_votes: Vec<(Vec<u8>, i64)>, pub witness_sort_optimized: bool }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceOutcome { pub applied: bool, pub before: Vec<Vec<u8>>, pub current: Vec<Vec<u8>>, pub consumed_vote_rows: usize, pub next_maintenance_time: i64, pub cycle: i64 }

pub fn apply_maintenance_block(state: &StateFacade<'_>, block_number: i64, block_time: i64, config: &MaintenanceConfig) -> Result<MaintenanceOutcome, StateError> {
    let mut child = state.child_session()?;
    let result = apply_maintenance_inner(&StateFacade::new(&child), block_number, block_time, config)?;
    child.merge()?;
    Ok(result)
}

fn apply_maintenance_inner(state: &StateFacade<'_>, block_number: i64, block_time: i64, config: &MaintenanceConfig) -> Result<MaintenanceOutcome, StateError> {
    let previous_next = state.dynamic_long("NEXT_MAINTENANCE_TIME")?;
    let due = previous_next <= block_time;
    let before = state.active_witnesses()?;
    let mut current = before.clone();
    let mut consumed = 0;
    let mut cycle = state.dynamic_long("CURRENT_CYCLE_NUMBER").unwrap_or(0);
    if due && block_number != 1 {
        let result = do_maintenance(state, config)?;
        current = result.0;
        consumed = result.1;
        cycle = result.2;
    }
    let next = if due { advance_maintenance(previous_next, block_time, state.dynamic_long("MAINTENANCE_TIME_INTERVAL")?)? } else { previous_next };
    if due { state.save_dynamic_long("NEXT_MAINTENANCE_TIME", next)?; }
    state.save_dynamic_int("STATE_FLAG", i32::from(due))?;
    Ok(MaintenanceOutcome { applied: due && block_number != 1, before, current, consumed_vote_rows: consumed, next_maintenance_time: next, cycle })
}

fn do_maintenance(state: &StateFacade<'_>, config: &MaintenanceConfig) -> Result<(Vec<Vec<u8>>, usize, i64), StateError> {
    if state.dynamic_long("REMOVE_THE_POWER_OF_THE_GR").unwrap_or(0) == 1 {
        for (address, votes) in &config.genesis_votes { if let Some(mut witness) = state.witness(address)? { witness.vote_count = witness.vote_count.checked_sub(*votes).ok_or(StateError::ArithmeticOverflow("genesis vote removal"))?; state.save_witness(&witness)?; } }
        state.save_dynamic_long("REMOVE_THE_POWER_OF_THE_GR", -1)?;
    }
    accumulate_reward_vi(state)?;
    let rows = state.votes()?;
    let mut deltas = BTreeMap::<Vec<u8>, i64>::new();
    for (key, votes) in &rows {
        for vote in &votes.old_votes { let value = deltas.entry(vote.vote_address.clone()).or_default(); *value = value.checked_sub(vote.vote_count).ok_or(StateError::ArithmeticOverflow("old vote"))?; }
        for vote in &votes.new_votes { let value = deltas.entry(vote.vote_address.clone()).or_default(); *value = value.checked_add(vote.vote_count).ok_or(StateError::ArithmeticOverflow("new vote"))?; }
        state.delete_votes(key)?;
    }
    for (address, delta) in deltas { if let Some(mut witness) = state.witness(&address)? { witness.vote_count = witness.vote_count.checked_add(delta).ok_or(StateError::ArithmeticOverflow("witness votes"))?; state.save_witness(&witness)?; } }
    let mut witnesses = state.witnesses()?;
    let active = if rows.is_empty() { state.active_witnesses()? } else {
        sort_witnesses(&mut witnesses, config.witness_sort_optimized);
        witnesses.iter().take(MAX_ACTIVE_WITNESSES).map(|witness| witness.address.clone()).collect()
    };
    if !rows.is_empty() {
        state.save_active_witnesses(&active)?;
        if state.dynamic_long("CHANGE_DELEGATION").unwrap_or(0) != 1 { pay_legacy_standby(state, &witnesses)?; }
        for witness in &mut witnesses { witness.is_jobs = active.iter().any(|address| address == &witness.address); state.save_witness(witness)?; }
    }
    let mut cycle = state.dynamic_long("CURRENT_CYCLE_NUMBER").unwrap_or(0);
    if state.dynamic_long("CHANGE_DELEGATION").unwrap_or(0) == 1 {
        cycle = cycle.checked_add(1).ok_or(StateError::ArithmeticOverflow("cycle"))?;
        state.save_dynamic_long("CURRENT_CYCLE_NUMBER", cycle)?;
        for witness in state.witnesses()? {
            let old_key = delegation_brokerage_key(-1, &witness.address);
            let brokerage = state.delegation(&old_key).and_then(|bytes| <[u8;4]>::try_from(bytes).ok()).map(i32::from_be_bytes).unwrap_or(20);
            state.save_delegation(&delegation_brokerage_key(cycle, &witness.address), &brokerage.to_be_bytes())?;
            state.save_delegation(&delegation_vote_key(cycle, &witness.address), &witness.vote_count.to_be_bytes())?;
        }
    }
    Ok((active, rows.len(), cycle))
}

fn accumulate_reward_vi(state: &StateFacade<'_>) -> Result<(), StateError> {
    if state.dynamic_long("NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE").unwrap_or(i64::MAX) == i64::MAX { return Ok(()); }
    let cycle = state.dynamic_long("CURRENT_CYCLE_NUMBER").unwrap_or(0);
    for witness in state.witnesses()? {
        let previous = state.delegation(&delegation_key(cycle - 1, &witness.address, "vi")).map(|bytes| BigInt::from_signed_bytes_be(&bytes)).unwrap_or_default();
        let reward = state.delegation(&delegation_key(cycle, &witness.address, "reward")).and_then(|bytes| <[u8; 8]>::try_from(bytes).ok()).map(i64::from_be_bytes).unwrap_or(0);
        let next = accumulate_vi(&previous, reward, witness.vote_count);
        if next != BigInt::from(0) { state.save_delegation(&delegation_key(cycle, &witness.address, "vi"), &next.to_signed_bytes_be())?; }
    }
    Ok(())
}

fn pay_legacy_standby(state: &StateFacade<'_>, witnesses: &[tron_protocol::protocol::Witness]) -> Result<(), StateError> {
    let witnesses = &witnesses[..witnesses.len().min(127)];
    let vote_sum = witnesses.iter().fold(Wrapping(0_i64), |sum, witness| sum + Wrapping(witness.vote_count)).0;
    if vote_sum <= 0 { return Ok(()); }
    let each_vote_pay = state.dynamic_long("WITNESS_STANDBY_ALLOWANCE")? as f64 / vote_sum as f64;
    for witness in witnesses {
        let reward = (witness.vote_count as f64 * each_vote_pay) as i64;
        let bytes = state.store_get(StoreKind::Account, &witness.address).ok_or_else(|| StateError::InvalidProtobuf { store: StoreKind::Account, key: witness.address.clone(), source: "missing witness account".into() })?;
        let mut account = Account::decode(bytes.as_slice()).map_err(|error| StateError::InvalidProtobuf { store: StoreKind::Account, key: witness.address.clone(), source: error.to_string() })?;
        account.allowance = (Wrapping(account.allowance) + Wrapping(reward)).0;
        state.store_put(StoreKind::Account, &witness.address, &account.encode_to_vec())?;
    }
    Ok(())
}

fn advance_maintenance(current: i64, block_time: i64, interval: i64) -> Result<i64, StateError> {
    if interval <= 0 { return Err(StateError::ArithmeticOverflow("maintenance interval")); }
    let difference = i128::from(block_time) - i128::from(current);
    let periods = difference / i128::from(interval) + 1;
    i64::try_from(i128::from(current) + periods * i128::from(interval)).map_err(|_|StateError::ArithmeticOverflow("next maintenance time"))
}
