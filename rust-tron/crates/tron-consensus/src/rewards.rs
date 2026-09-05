use std::num::Wrapping;
use num_bigint::BigInt;
use prost::Message;
use tron_protocol::protocol::Account;
use tron_state::StoreKind;
use crate::state::{delegation_brokerage_key, delegation_key, ConsensusRead, StateError, StateFacade};

pub const DEFAULT_BROKERAGE: i32 = 20;
pub const VI_SCALE: i64 = 1_000_000_000_000_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardPayment { pub address: Vec<u8>, pub gross: i64, pub voter_reward: i64, pub brokerage: i64 }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteReward { pub witness: Vec<u8>, pub votes: i64 }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardWithdrawal { pub reward: i64, pub begin_cycle: i64, pub end_cycle: i64 }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeePoolReward {
    pub pool_before: i64,
    pub transaction_fee_reward: i64,
    pub pool_after: i64,
    pub delegated_payment: Option<RewardPayment>,
}

fn account_cycle_key(address: &[u8], suffix: &str) -> Vec<u8> { delegation_key(-2, address, suffix) }
fn account_vote_key(cycle: i64, address: &[u8]) -> Vec<u8> { delegation_key(cycle, address, "account-vote") }
fn cycle_value(state: &StateFacade<'_>, address: &[u8], suffix: &str) -> i64 { read_i64(state.delegation(&account_cycle_key(address, suffix))).unwrap_or(0) }
fn save_cycle_value(state: &StateFacade<'_>, address: &[u8], suffix: &str, value: i64) -> Result<(), StateError> { state.save_delegation(&account_cycle_key(address, suffix), &value.to_be_bytes()) }
fn load_account(state: &StateFacade<'_>, address: &[u8]) -> Result<Option<Account>, StateError> { state.store_get(StoreKind::Account, address).map(|bytes| Account::decode(bytes.as_slice()).map_err(|e| StateError::InvalidProtobuf { store: StoreKind::Account, key: address.to_vec(), source: e.to_string() })).transpose() }

pub fn query_reward(state: &StateFacade<'_>, address: &[u8]) -> Result<i64, StateError> {
    if state.dynamic_long("CHANGE_DELEGATION").unwrap_or(0) != 1 { return Ok(0); }
    let Some(account) = load_account(state, address)? else { return Ok(0) };
    let current = state.dynamic_long("CURRENT_CYCLE_NUMBER")?;
    let mut begin = cycle_value(state, address, "begin-cycle");
    let end = cycle_value(state, address, "end-cycle");
    if begin > current { return Ok(account.allowance); }
    let mut reward = 0;
    if begin + 1 == end && begin < current {
        if let Some(snapshot) = load_vote_snapshot(state, begin, address)? { reward = compute_account_reward(state, begin, end, &snapshot)?; }
        begin += 1;
    }
    if !account.votes.is_empty() && begin < current { reward = reward.checked_add(compute_account_reward(state, begin, current, &account)?).ok_or(StateError::ArithmeticOverflow("query reward"))?; }
    account.allowance.checked_add(reward).ok_or(StateError::ArithmeticOverflow("query allowance"))
}

pub fn withdraw_reward(state: &StateFacade<'_>, address: &[u8]) -> Result<RewardWithdrawal, StateError> {
    let mut child = state.child_session()?;
    let result = withdraw_reward_inner(&StateFacade::new(&child), address)?;
    child.merge()?;
    Ok(result)
}

fn withdraw_reward_inner(state: &StateFacade<'_>, address: &[u8]) -> Result<RewardWithdrawal, StateError> {
    if state.dynamic_long("CHANGE_DELEGATION").unwrap_or(0) != 1 { return Ok(RewardWithdrawal { reward: 0, begin_cycle: cycle_value(state,address,"begin-cycle"), end_cycle: cycle_value(state,address,"end-cycle") }); }
    let Some(account) = load_account(state, address)? else { return Ok(RewardWithdrawal { reward: 0, begin_cycle: 0, end_cycle: 0 }) };
    let current = state.dynamic_long("CURRENT_CYCLE_NUMBER")?;
    let mut begin = cycle_value(state, address, "begin-cycle");
    let end = cycle_value(state, address, "end-cycle");
    if begin > current || (begin == current && state.delegation(&account_vote_key(begin,address)).is_some()) { return Ok(RewardWithdrawal { reward: 0, begin_cycle: begin, end_cycle: end }); }
    let mut paid = 0;
    if begin + 1 == end && begin < current {
        if let Some(snapshot) = load_vote_snapshot(state, begin, address)? { let reward=compute_account_reward(state,begin,end,&snapshot)?; adjust_allowance(state,address,reward)?; paid=reward; }
        begin += 1;
    }
    if account.votes.is_empty() { save_cycle_value(state,address,"begin-cycle",current+1)?; return Ok(RewardWithdrawal { reward: paid, begin_cycle: current+1, end_cycle: end }); }
    if begin < current { let reward=compute_account_reward(state,begin,current,&account)?; adjust_allowance(state,address,reward)?; paid=paid.checked_add(reward).ok_or(StateError::ArithmeticOverflow("withdraw reward"))?; }
    save_cycle_value(state,address,"begin-cycle",current)?;
    save_cycle_value(state,address,"end-cycle",current+1)?;
    state.save_delegation(&account_vote_key(current,address),&account.encode_to_vec())?;
    Ok(RewardWithdrawal { reward: paid, begin_cycle: current, end_cycle: current+1 })
}

fn load_vote_snapshot(state:&StateFacade<'_>,cycle:i64,address:&[u8])->Result<Option<Account>,StateError>{state.delegation(&account_vote_key(cycle,address)).map(|bytes|Account::decode(bytes.as_slice()).map_err(|e|StateError::InvalidProtobuf{store:StoreKind::Delegation,key:account_vote_key(cycle,address),source:e.to_string()})).transpose()}
fn compute_account_reward(state:&StateFacade<'_>,begin:i64,end:i64,account:&Account)->Result<i64,StateError>{
    let votes:Vec<VoteReward>=account.votes.iter().map(|v|VoteReward{witness:v.vote_address.clone(),votes:v.vote_count}).collect();
    let effective=state.dynamic_long("NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE").unwrap_or(i64::MAX);
    Ok(reward_across_cycles(begin,end,effective,&votes,|cycle,rows|legacy_cycle_reward(state,cycle,rows),|address,cycle|read_bigint(state.delegation(&delegation_key(cycle,address,"vi")))))
}
fn legacy_cycle_reward(state:&StateFacade<'_>,cycle:i64,votes:&[VoteReward])->i64{votes.iter().fold(0_i64,|sum,v|{let total=read_i64(state.delegation(&delegation_key(cycle,&v.witness,"reward"))).unwrap_or(0);let count=read_i64(state.delegation(&delegation_key(cycle,&v.witness,"vote"))).unwrap_or(0);if total<=0||count<=0{sum}else{sum.saturating_add(((v.votes as f64/count as f64)*total as f64)as i64)}})}
fn read_bigint(value:Option<Vec<u8>>)->BigInt{value.map(|bytes|BigInt::from_signed_bytes_be(&bytes)).unwrap_or_default()}

pub fn pay_reward(state: &StateFacade<'_>, address: &[u8], gross: i64) -> Result<RewardPayment, StateError> {
    let mut child=state.child_session()?;let payment=pay_reward_inner(&StateFacade::new(&child),address,gross)?;child.merge()?;Ok(payment)
}
fn pay_reward_inner(state:&StateFacade<'_>,address:&[u8],gross:i64)->Result<RewardPayment,StateError>{
    let cycle=state.dynamic_long("CURRENT_CYCLE_NUMBER")?;
    let brokerage=state.delegation(&delegation_brokerage_key(cycle,address)).and_then(|b|<[u8;4]>::try_from(b).ok()).map(i32::from_be_bytes).unwrap_or(DEFAULT_BROKERAGE);
    let brokerage_amount=((gross as f64)*(brokerage as f64/100.0)) as i64;
    let voter=(Wrapping(gross)-Wrapping(brokerage_amount)).0;
    let key=delegation_key(cycle,address,"reward");
    let current=read_i64(state.delegation(&key)).unwrap_or(0);
    state.save_delegation(&key,&(Wrapping(current)+Wrapping(voter)).0.to_be_bytes())?;
    adjust_allowance_java(state,address,brokerage_amount)?;
    Ok(RewardPayment{address:address.to_vec(),gross,voter_reward:voter,brokerage:brokerage_amount})
}
pub fn pay_block_reward(state:&StateFacade<'_>,address:&[u8],value:i64)->Result<RewardPayment,StateError>{pay_reward(state,address,value)}
pub fn pay_transaction_fee_reward(state:&StateFacade<'_>,address:&[u8],value:i64)->Result<RewardPayment,StateError>{pay_reward(state,address,value)}
pub fn pay_standby_rewards(state:&StateFacade<'_>,witnesses:&[(Vec<u8>,i64)],total:i64)->Result<Vec<RewardPayment>,StateError>{let mut child=state.child_session()?;let facade=StateFacade::new(&child);let mut payments=Vec::new();for(address,value)in standby_distribution(witnesses,total){payments.push(pay_reward_inner(&facade,&address,value)?);}child.merge()?;Ok(payments)}

pub fn standby_distribution(witnesses:&[(Vec<u8>,i64)],total:i64)->Vec<(Vec<u8>,i64)>{let sum:i64=witnesses.iter().map(|x|x.1).sum();if sum<1{return vec![]}let each=total as f64/sum as f64;witnesses.iter().map(|(a,v)|(a.clone(),(*v as f64*each)as i64)).collect()}
/// Mirrors `Manager.payReward`: fee-pool reward is independent from block and standby rewards,
/// is paid only to the producing witness, and leaves integer-division remainder in the pool.
pub fn pay_fee_pool_reward(state:&StateFacade<'_>,producer:&[u8],period:i64)->Result<Option<FeePoolReward>,StateError>{
    if state.dynamic_long("ALLOW_TRANSACTION_FEE_POOL").unwrap_or(0)!=1{return Ok(None)}
    if period==0{return Err(StateError::InvalidRewardPeriod(period))}
    let mut child=state.child_session()?;
    let facade=StateFacade::new(&child);
    let pool=facade.dynamic_long("TRANSACTION_FEE_POOL")?;
    let reward=java_floor_div(pool,period);
    let delegated_payment=if facade.dynamic_long("CHANGE_DELEGATION").unwrap_or(0)==1{
        Some(pay_reward_inner(&facade,producer,reward)?)
    }else{
        adjust_allowance_java(&facade,producer,reward)?;
        None
    };
    let pool_after=(Wrapping(pool)-Wrapping(reward)).0;
    facade.save_dynamic_long("TRANSACTION_FEE_POOL",pool_after)?;
    child.merge()?;
    Ok(Some(FeePoolReward{pool_before:pool,transaction_fee_reward:reward,pool_after,delegated_payment}))
}

fn java_floor_div(dividend:i64,divisor:i64)->i64{
    if dividend==i64::MIN&&divisor==-1{return i64::MIN}
    let quotient=dividend/divisor;
    let remainder=dividend%divisor;
    if remainder!=0&&(dividend<0)!=(divisor<0){quotient-1}else{quotient}
}

pub fn accumulate_vi(previous:&BigInt,reward:i64,vote_count:i64)->BigInt{if reward==0||vote_count==0{return previous.clone()}previous+(BigInt::from(reward)*BigInt::from(VI_SCALE)/BigInt::from(vote_count))}
pub fn reward_vi(begin:&BigInt,end:&BigInt,user_votes:i64)->i64{let delta=end-begin;if delta<=BigInt::from(0){0}else{(delta*BigInt::from(user_votes)/BigInt::from(VI_SCALE)).try_into().unwrap_or(0)}}
pub fn reward_across_cycles(begin:i64,end:i64,effective:i64,votes:&[VoteReward],legacy:impl Fn(i64,&[VoteReward])->i64,vi:impl Fn(&[u8],i64)->BigInt)->i64{if begin>=end{return 0}let old_end=end.min(effective);let mut reward=(begin..old_end).map(|c|legacy(c,votes)).sum();if old_end<end{for v in votes{reward+=reward_vi(&vi(&v.witness,old_end-1),&vi(&v.witness,end-1),v.votes);}}reward}

pub fn adjust_allowance(state:&StateFacade<'_>,address:&[u8],amount:i64)->Result<(),StateError>{if amount==0{return Ok(())}let bytes=state.store_get(StoreKind::Account,address).ok_or_else(||StateError::InvalidProtobuf{store:StoreKind::Account,key:address.to_vec(),source:"missing account".into()})?;let mut account=Account::decode(bytes.as_slice()).map_err(|e|StateError::InvalidProtobuf{store:StoreKind::Account,key:address.to_vec(),source:e.to_string()})?;account.allowance=account.allowance.checked_add(amount).filter(|value|*value>=0).ok_or(StateError::ArithmeticOverflow("allowance"))?;state.store_put(StoreKind::Account,address,&account.encode_to_vec())}
fn adjust_allowance_java(state:&StateFacade<'_>,address:&[u8],amount:i64)->Result<(),StateError>{
    if amount==0{return Ok(())}
    let bytes=state.store_get(StoreKind::Account,address).ok_or_else(||StateError::InvalidProtobuf{store:StoreKind::Account,key:address.to_vec(),source:"missing account".into()})?;
    let mut account=Account::decode(bytes.as_slice()).map_err(|e|StateError::InvalidProtobuf{store:StoreKind::Account,key:address.to_vec(),source:e.to_string()})?;
    account.allowance=(Wrapping(account.allowance)+Wrapping(amount)).0;
    state.store_put(StoreKind::Account,address,&account.encode_to_vec())
}
fn read_i64(value:Option<Vec<u8>>)->Option<i64>{value.and_then(|b|<[u8;8]>::try_from(b).ok()).map(i64::from_be_bytes)}
