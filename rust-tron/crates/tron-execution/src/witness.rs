use prost::Message;
use tron_protocol::{google::protobuf::Any, protocol::{transaction::result::Code, Account, ResourceCode, Vote, VoteWitnessContract, Votes, Witness, WitnessCreateContract, WitnessUpdateContract}};
use tron_state::StoreKind;

use crate::{account::{charge_fee, default_active_permission, default_owner_permission, default_witness_permission}, context::{checked_add, decode_typed_any, valid_address}, Actuator, ExecutionContext, ActuatorError, ActuatorResult, ValidationContext};

const WITNESS_CREATE: &str = "protocol.WitnessCreateContract";
const WITNESS_UPDATE: &str = "protocol.WitnessUpdateContract";
const VOTE_WITNESS: &str = "protocol.VoteWitnessContract";
const TRX_PRECISION: i64 = 1_000_000;
const MAX_VOTE_NUMBER: usize = 30;

fn hex(value: &[u8]) -> String { value.iter().map(|byte| format!("{byte:02x}")).collect() }
fn account(context: &ExecutionContext<'_>, address: &[u8], missing: &'static str) -> Result<Account, ActuatorError> { context.decode(StoreKind::Account, address, missing) }
fn put_account(context: &mut ExecutionContext<'_>, value: &Account) -> Result<(), ActuatorError> { context.put_message(StoreKind::Account, &value.address, value) }
fn valid_url(value: &[u8]) -> bool { !value.is_empty() && value.len() <= 256 }
fn checked_sum(mut values: impl Iterator<Item=i64>) -> Result<i64, ActuatorError> { values.try_fold(0_i64, checked_add) }
fn legacy_power(account: &Account) -> Result<i64, ActuatorError> {
    let frozen = checked_sum(account.frozen.iter().map(|value| value.frozen_balance))?;
    let resource = account.account_resource.as_ref();
    let energy = resource.and_then(|value| value.frozen_balance_for_energy.as_ref()).map_or(0, |value| value.frozen_balance);
    let frozen_v2 = checked_sum(account.frozen_v2.iter().filter(|value| value.r#type != ResourceCode::TronPower as i32).map(|value| value.amount))?;
    checked_sum([frozen, energy, account.delegated_frozen_balance_for_bandwidth, resource.map_or(0, |value| value.delegated_frozen_balance_for_energy), frozen_v2, account.delegated_frozen_v2_balance_for_bandwidth, resource.map_or(0, |value| value.delegated_frozen_v2_balance_for_energy)].into_iter())
}
fn tron_power_frozen(account: &Account) -> Result<i64, ActuatorError> {
    let v1 = account.tron_power.as_ref().map_or(0, |value| value.frozen_balance);
    let v2 = checked_sum(account.frozen_v2.iter().filter(|value| value.r#type == ResourceCode::TronPower as i32).map(|value| value.amount))?;
    checked_add(v1, v2)
}
fn all_power(account: &Account) -> Result<i64, ActuatorError> {
    let dedicated = tron_power_frozen(account)?;
    match account.old_tron_power { -1 => Ok(dedicated), 0 => checked_add(legacy_power(account)?, dedicated), value => checked_add(value, dedicated) }
}

pub struct WitnessCreateActuator { any: Any, contract: WitnessCreateContract }
impl WitnessCreateActuator { pub fn new(any: Any) -> Result<Self, ActuatorError> { let contract = decode_typed_any(&any, WITNESS_CREATE)?; Ok(Self { any, contract }) } pub fn raw_any(&self) -> &Any { &self.any } }
impl Actuator for WitnessCreateActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { if !valid_address(&self.contract.owner_address) { return Err(ActuatorError::validation("Invalid address")); }
    if !valid_url(&self.contract.url) { return Err(ActuatorError::validation("Invalid url")); }
    let owner = context.get(StoreKind::Account, &self.contract.owner_address)?.ok_or_else(|| ActuatorError::validation(format!("account[{}] not exists", hex(&self.contract.owner_address)))).and_then(|bytes| Account::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string())))?;
    if context.get(StoreKind::Witness, &self.contract.owner_address)?.is_some() { return Err(ActuatorError::validation(format!("Witness[{}] has existed", hex(&self.contract.owner_address)))); }
    if owner.balance < context.dynamic_long("ACCOUNT_UPGRADE_COST")? { return Err(ActuatorError::validation("balance < AccountUpgradeCost")); }
    Ok(()) }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let fee = context.dynamic_long("ACCOUNT_UPGRADE_COST")?;
        let witness = Witness { address: self.contract.owner_address.clone(), vote_count: 0, url: String::from_utf8_lossy(&self.contract.url).into_owned(), ..Default::default() };
        context.put_message(StoreKind::Witness, &witness.address, &witness)?;
        let mut owner = account(context, &self.contract.owner_address, "account does not exist")?;
        owner.is_witness = true;
        if context.dynamic_long("ALLOW_MULTI_SIGN")? == 1 {
            owner.owner_permission = Some(default_owner_permission(&owner.address));
            owner.witness_permission = Some(default_witness_permission(&owner.address));
            owner.active_permission = vec![default_active_permission(&owner.address, context.dynamic_raw("ACTIVE_DEFAULT_OPERATIONS")?)];
        }
        charge_fee(context, &mut owner, fee)?;
        put_account(context, &owner)?;
        context.put_dynamic_long("TOTAL_CREATE_WITNESS_COST", checked_add(context.dynamic_long("TOTAL_CREATE_WITNESS_COST")?, fee)?)?;
        result.fee = checked_add(result.fee, fee)?; result.code = Code::Sucess; Ok(())
    }
}

pub struct WitnessUpdateActuator { any: Any, contract: WitnessUpdateContract }
impl WitnessUpdateActuator { pub fn new(any: Any) -> Result<Self, ActuatorError> { let contract = decode_typed_any(&any, WITNESS_UPDATE)?; Ok(Self { any, contract }) } pub fn raw_any(&self) -> &Any { &self.any } }
impl Actuator for WitnessUpdateActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { if !valid_address(&self.contract.owner_address) { return Err(ActuatorError::validation("Invalid address")); }
    if context.get(StoreKind::Account, &self.contract.owner_address)?.is_none() { return Err(ActuatorError::validation("account does not exist")); }
    if !valid_url(&self.contract.update_url) { return Err(ActuatorError::validation("Invalid url")); }
    if context.get(StoreKind::Witness, &self.contract.owner_address)?.is_none() { return Err(ActuatorError::validation("Witness does not exist")); }
    Ok(()) }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let mut witness: Witness = context.decode(StoreKind::Witness, &self.contract.owner_address, "Witness does not exist")?;
        witness.url = String::from_utf8_lossy(&self.contract.update_url).into_owned(); context.put_message(StoreKind::Witness, &witness.address, &witness)?; result.code = Code::Sucess; Ok(())
    }
}

pub struct VoteWitnessActuator { any: Any, contract: VoteWitnessContract }
impl VoteWitnessActuator { pub fn new(any: Any) -> Result<Self, ActuatorError> { let contract = decode_typed_any(&any, VOTE_WITNESS)?; Ok(Self { any, contract }) } pub fn raw_any(&self) -> &Any { &self.any } }
impl Actuator for VoteWitnessActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { if !valid_address(&self.contract.owner_address) { return Err(ActuatorError::validation("Invalid address")); }
    if self.contract.votes.is_empty() { return Err(ActuatorError::validation("VoteNumber must more than 0")); }
    if self.contract.votes.len() > MAX_VOTE_NUMBER { return Err(ActuatorError::validation(format!("VoteNumber more than maxVoteNumber {MAX_VOTE_NUMBER}"))); }
    let mut sum = 0_i64;
    for vote in &self.contract.votes {
        if !valid_address(&vote.vote_address) { return Err(ActuatorError::validation("Invalid vote address!")); }
        if vote.vote_count <= 0 { return Err(ActuatorError::validation("vote count must be greater than 0")); }
        if context.get(StoreKind::Account, &vote.vote_address)?.is_none() { return Err(ActuatorError::validation(format!("Account[{}] not exists", hex(&vote.vote_address)))); }
        if context.get(StoreKind::Witness, &vote.vote_address)?.is_none() { return Err(ActuatorError::validation(format!("Witness[{}] not exists", hex(&vote.vote_address)))); }
        sum = checked_add(sum, vote.vote_count)?;
    }
    let owner = account(context, &self.contract.owner_address, "Account does not exist")?;
    let power = if context.dynamic_long("ALLOW_NEW_RESOURCE_MODEL")? == 1 { all_power(&owner)? } else { legacy_power(&owner)? };
    let votes = sum.checked_mul(TRX_PRECISION).ok_or_else(|| ActuatorError::arithmetic("long overflow"))?;
    if votes > power { return Err(ActuatorError::validation(format!("The total number of votes[{votes}] is greater than the tronPower[{power}]"))); }
    Ok(()) }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let address = self.contract.owner_address.clone();
        context.withdraw_reward(&address)?;
        let mut owner = account(context, &address, "Account does not exist")?;
        if context.dynamic_long("ALLOW_NEW_RESOURCE_MODEL")? == 1 && owner.old_tron_power == 0 { let power = legacy_power(&owner)?; owner.old_tron_power = if power == 0 { -1 } else { power }; }
        let mut votes = if let Some(bytes) = context.get(StoreKind::Votes, &address)? {
            Votes::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?
        } else {
            Votes { address: address.clone(), old_votes: owner.votes.clone(), new_votes: Vec::new() }
        };
        owner.votes.clear(); votes.new_votes.clear();
        for item in &self.contract.votes { let vote = Vote { vote_address: item.vote_address.clone(), vote_count: item.vote_count }; owner.votes.push(vote.clone()); votes.new_votes.push(vote); }
        put_account(context, &owner)?; context.put_message(StoreKind::Votes, &address, &votes)?; result.code = Code::Sucess; Ok(())
    }
}
