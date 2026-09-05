use prost::Message;
use tron_protocol::{
    google::protobuf::Any,
    protocol::{
        account::{FreezeV2, Frozen, UnFreezeV2},
        transaction::result::Code,
        Account, AccountType, CancelAllUnfreezeV2Contract, DelegateResourceContract,
        DelegatedResource, DelegatedResourceAccountIndex, FreezeBalanceContract,
        FreezeBalanceV2Contract, ResourceCode, UnDelegateResourceContract,
        UnfreezeBalanceContract, UnfreezeBalanceV2Contract, Vote, Votes, WithdrawBalanceContract,
        WithdrawExpireUnfreezeContract,
    },
};
use tron_state::{delegation, dynamic, StoreKind};
use tron_state::resource::{ResourceWindow, TRX_PRECISION};

use crate::context::{checked_add, checked_sub, decode_typed_any, valid_address};
use crate::{Actuator, ActuatorError, ActuatorResult, ExecutionContext, ValidationContext};

const DAY_MS: i64 = 86_400_000;
const BLOCK_MS: i64 = 3_000;
const DEFAULT_DELEGATE_LOCK_SLOTS: i64 = 3 * DAY_MS / BLOCK_MS;

fn account(context: &ExecutionContext<'_>, address: &[u8]) -> Result<Account, ActuatorError> {
    context.decode(StoreKind::Account, address, "Account does not exist")
}
fn save(context: &mut ExecutionContext<'_>, account: &Account) -> Result<(), ActuatorError> {
    context.put_message(StoreKind::Account, &account.address, account)
}
fn enabled(context: &ExecutionContext<'_>, name: &str) -> Result<bool, ActuatorError> {
    match context.dynamic_long(name) { Ok(value) => Ok(value == 1), Err(_) => Ok(false) }
}
fn long_or(context: &ExecutionContext<'_>, name: &str, default: i64) -> i64 { context.dynamic_long(name).unwrap_or(default) }
fn resource(value: i32) -> Result<ResourceCode, ActuatorError> {
    ResourceCode::try_from(value).map_err(|_| ActuatorError::validation("ResourceCode error"))
}
fn strict_resource(value: i32, allow_tron_power: bool) -> Result<ResourceCode, ActuatorError> {
    let kind = resource(value)?;
    if matches!(kind, ResourceCode::Bandwidth | ResourceCode::Energy)
        || allow_tron_power && kind == ResourceCode::TronPower
    {
        Ok(kind)
    } else {
        Err(ActuatorError::validation(if allow_tron_power {
            "ResourceCode error, valid ResourceCode[BANDWIDTH、ENERGY、TRON_POWER]"
        } else {
            "ResourceCode error, valid ResourceCode[BANDWIDTH、ENERGY]"
        }))
    }
}
fn validate_owner(context: &ValidationContext<'_>, address: &[u8]) -> Result<Account, ActuatorError> {
    if !valid_address(address) {
        return Err(ActuatorError::validation("Invalid address"));
    }
    match context.get(StoreKind::Account, address)? {
        Some(bytes) => Account::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string())),
        None => Err(ActuatorError::validation(format!("Account[{}] does not exist", hex(address)))),
    }
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes { output.push(DIGITS[(byte >> 4) as usize] as char); output.push(DIGITS[(byte & 15) as usize] as char); }
    output
}
fn validate_owner_not_exists(context: &ValidationContext<'_>, address: &[u8]) -> Result<Account, ActuatorError> {
    if !valid_address(address) { return Err(ActuatorError::validation("Invalid address")); }
    match context.get(StoreKind::Account, address)? {
        Some(bytes) => Account::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string())),
        None => Err(ActuatorError::validation(format!("Account[{}] not exists", hex(address)))),
    }
}
fn checked_mul(left: i64, right: i64) -> Result<i64, ActuatorError> {
    left.checked_mul(right).ok_or_else(|| ActuatorError::arithmetic("long overflow"))
}
fn checked_sum(values: impl IntoIterator<Item = i64>) -> Result<i64, ActuatorError> {
    values.into_iter().try_fold(0, checked_add)
}
fn frozen_v2(account: &Account, kind: ResourceCode) -> i64 {
    account.frozen_v2.iter().find(|item| item.r#type == kind as i32).map_or(0, |item| item.amount)
}
fn add_frozen_v2(account: &mut Account, kind: ResourceCode, delta: i64) -> Result<(), ActuatorError> {
    if let Some(item) = account.frozen_v2.iter_mut().find(|item| item.r#type == kind as i32) {
        item.amount = checked_add(item.amount, delta)?;
    } else {
        account.frozen_v2.push(FreezeV2 { r#type: kind as i32, amount: delta });
    }
    Ok(())
}
fn delegated_v2(account: &Account, kind: ResourceCode) -> i64 {
    match kind {
        ResourceCode::Bandwidth => account.delegated_frozen_v2_balance_for_bandwidth,
        ResourceCode::Energy => account.account_resource.as_ref().map_or(0, |resource| resource.delegated_frozen_v2_balance_for_energy),
        ResourceCode::TronPower => 0,
    }
}
fn weight_balance(account: &Account, kind: ResourceCode) -> Result<i64, ActuatorError> {
    checked_add(frozen_v2(account, kind), delegated_v2(account, kind))
}
fn weight_name(kind: ResourceCode) -> &'static str {
    match kind {
        ResourceCode::Bandwidth => "TOTAL_NET_WEIGHT",
        ResourceCode::Energy => "TOTAL_ENERGY_WEIGHT",
        ResourceCode::TronPower => "TOTAL_TRON_POWER_WEIGHT",
    }
}
fn change_weight(context: &mut ExecutionContext<'_>, kind: ResourceCode, old: i64, new: i64) -> Result<(), ActuatorError> {
    let name = weight_name(kind);
    context.put_dynamic_long(name, checked_add(context.dynamic_long(name)?, new / TRX_PRECISION - old / TRX_PRECISION)?)
}
fn legacy_power(account: &Account) -> Result<i64, ActuatorError> {
    let bandwidth = checked_sum(account.frozen.iter().map(|item| item.frozen_balance))?;
    let energy = account.account_resource.as_ref().and_then(|item| item.frozen_balance_for_energy.as_ref()).map_or(0, |item| item.frozen_balance);
    checked_sum([bandwidth, energy, account.delegated_frozen_balance_for_bandwidth,
        account.account_resource.as_ref().map_or(0, |item| item.delegated_frozen_balance_for_energy)])
}
fn legacy_vote_power(account: &Account) -> Result<i64, ActuatorError> {
    checked_add(
        legacy_power(account)?,
        checked_add(
            checked_sum(account.frozen_v2.iter().filter(|item| item.r#type != ResourceCode::TronPower as i32).map(|item| item.amount))?,
            checked_add(
                account.delegated_frozen_v2_balance_for_bandwidth,
                account.account_resource.as_ref().map_or(0, |resource| resource.delegated_frozen_v2_balance_for_energy),
            )?,
        )?,
    )
}
fn initialize_old_tron_power(account: &mut Account, new_model: bool) -> Result<(), ActuatorError> {
    if new_model && account.old_tron_power == 0 {
        let power = legacy_vote_power(account)?;
        account.old_tron_power = if power == 0 { -1 } else { power };
    }
    Ok(())
}
fn clear_votes(context: &mut ExecutionContext<'_>, account: &mut Account) -> Result<(), ActuatorError> {
    if account.votes.is_empty() { return Ok(()); }
    let mut votes = match context.get(StoreKind::Votes, &account.address)? {
        Some(bytes) => Votes::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?,
        None => Votes { address: account.address.clone(), old_votes: account.votes.clone(), new_votes: Vec::new() },
    };
    account.votes.clear();
    votes.new_votes.clear();
    context.put_message(StoreKind::Votes, &account.address, &votes)
}
fn scale_legacy_votes(context: &mut ExecutionContext<'_>, account: &mut Account, old_power: i64) -> Result<(), ActuatorError> {
    if account.votes.is_empty() { return Ok(()); }
    let total_votes = checked_sum(account.votes.iter().map(|vote| vote.vote_count))?;
    let remaining_power = legacy_vote_power(account)?;
    if total_votes == 0 || remaining_power >= checked_mul(total_votes, TRX_PRECISION)? { return Ok(()); }
    let mut votes = match context.get(StoreKind::Votes, &account.address)? {
        Some(bytes) => Votes::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?,
        None => Votes { address: account.address.clone(), old_votes: account.votes.clone(), new_votes: Vec::new() },
    };
    let scaled = account.votes.iter().filter_map(|vote| {
        let count = ((vote.vote_count as f64) * (remaining_power as f64) / (old_power as f64)) as i64;
        (count > 0).then(|| Vote { vote_address: vote.vote_address.clone(), vote_count: count })
    }).collect::<Vec<_>>();
    account.votes.clone_from(&scaled);
    votes.new_votes = scaled;
    context.put_message(StoreKind::Votes, &account.address, &votes)
}
fn clear_votes_force(context: &mut ExecutionContext<'_>, account: &mut Account) -> Result<(), ActuatorError> {
    let mut votes = match context.get(StoreKind::Votes, &account.address)? {
        Some(bytes) => Votes::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?,
        None => Votes { address: account.address.clone(), old_votes: account.votes.clone(), new_votes: Vec::new() },
    };
    account.votes.clear();
    votes.new_votes.clear();
    context.put_message(StoreKind::Votes, &account.address, &votes)
}
fn delegated(context: &ExecutionContext<'_>, key: &[u8], from: &[u8], to: &[u8]) -> Result<DelegatedResource, ActuatorError> {
    match context.get(StoreKind::DelegatedResource, key)? {
        Some(bytes) => DelegatedResource::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string())),
        None => Ok(DelegatedResource { from: from.to_vec(), to: to.to_vec(), ..Default::default() }),
    }
}
fn index(context: &ExecutionContext<'_>, address: &[u8]) -> Result<DelegatedResourceAccountIndex, ActuatorError> {
    match context.get(StoreKind::DelegatedResourceAccountIndex, address)? {
        Some(bytes) => DelegatedResourceAccountIndex::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string())),
        None => Ok(DelegatedResourceAccountIndex { account: address.to_vec(), ..Default::default() }),
    }
}
fn remove_indexes(context: &mut ExecutionContext<'_>, owner: &[u8], receiver: &[u8]) -> Result<(), ActuatorError> {
    if let Some(bytes) = context.get(StoreKind::DelegatedResourceAccountIndex, owner)? {
        let mut owner_index = DelegatedResourceAccountIndex::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?;
        owner_index.to_accounts.retain(|address| address != receiver);
        context.put_message(StoreKind::DelegatedResourceAccountIndex, owner, &owner_index)?;
    }
    if let Some(bytes) = context.get(StoreKind::DelegatedResourceAccountIndex, receiver)? {
        let mut receiver_index = DelegatedResourceAccountIndex::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?;
        receiver_index.from_accounts.retain(|address| address != owner);
        context.put_message(StoreKind::DelegatedResourceAccountIndex, receiver, &receiver_index)?;
    }
    Ok(())
}
fn remove_v2_indexes(context: &mut ExecutionContext<'_>, owner: &[u8], receiver: &[u8]) -> Result<(), ActuatorError> {
    context.delete(StoreKind::DelegatedResourceAccountIndex, &delegation::v2_from_index_key(owner, receiver))?;
    context.delete(StoreKind::DelegatedResourceAccountIndex, &delegation::v2_to_index_key(receiver, owner))
}
fn convert_indexes(context: &mut ExecutionContext<'_>, address: &[u8]) -> Result<(), ActuatorError> {
    let Some(bytes) = context.get(StoreKind::DelegatedResourceAccountIndex, address)? else { return Ok(()) };
    let current = DelegatedResourceAccountIndex::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?;
    let mutations = delegation::legacy_index_conversion(address, &current)
        .map_err(|_| ActuatorError::arithmetic("long overflow"))?;
    for mutation in mutations {
        match mutation {
            delegation::LegacyIndexMutation::Put { key, value } => {
                context.put_message(StoreKind::DelegatedResourceAccountIndex, &key, &value)?;
            }
            delegation::LegacyIndexMutation::Delete { key } => {
                context.delete(StoreKind::DelegatedResourceAccountIndex, &key)?;
            }
        }
    }
    Ok(())
}
fn unlock_expired(context: &mut ExecutionContext<'_>, owner: &[u8], receiver: &[u8], now: i64) -> Result<(), ActuatorError> {
    let locked_key = delegation::resource_v2_key(owner, receiver, true);
    let Some(bytes) = context.get(StoreKind::DelegatedResource, &locked_key)? else { return Ok(()); };
    let mut locked = DelegatedResource::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?;
    let energy_expired = locked.expire_time_for_energy < now;
    let bandwidth_expired = locked.expire_time_for_bandwidth < now;
    if !energy_expired && !bandwidth_expired { return Ok(()); }
    let unlocked_key = delegation::resource_v2_key(owner, receiver, false);
    let mut unlocked = delegated(context, &unlocked_key, owner, receiver)?;
    if bandwidth_expired {
        unlocked.frozen_balance_for_bandwidth = checked_add(unlocked.frozen_balance_for_bandwidth, locked.frozen_balance_for_bandwidth)?;
        locked.frozen_balance_for_bandwidth = 0;
        locked.expire_time_for_bandwidth = 0;
    }
    if energy_expired {
        unlocked.frozen_balance_for_energy = checked_add(unlocked.frozen_balance_for_energy, locked.frozen_balance_for_energy)?;
        locked.frozen_balance_for_energy = 0;
        locked.expire_time_for_energy = 0;
    }
    context.put_message(StoreKind::DelegatedResource, &unlocked_key, &unlocked)?;
    if locked.frozen_balance_for_bandwidth == 0 && locked.frozen_balance_for_energy == 0 {
        context.delete(StoreKind::DelegatedResource, &locked_key)?;
    } else {
        context.put_message(StoreKind::DelegatedResource, &locked_key, &locked)?;
    }
    Ok(())
}

macro_rules! ctor {
    ($name:ident, $ty:ty, $url:literal) => {
        impl $name {
            pub fn new(any: Any) -> Result<Self, ActuatorError> {
                let contract = decode_typed_any::<$ty>(&any, $url)?;
                Ok(Self { any, contract })
            }
            pub fn raw_any(&self) -> &Any { &self.any }
        }
    };
}

pub struct FreezeBalanceV2Actuator { any: Any, contract: FreezeBalanceV2Contract }
ctor!(FreezeBalanceV2Actuator, FreezeBalanceV2Contract, "protocol.FreezeBalanceV2Contract");
impl Actuator for FreezeBalanceV2Actuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> {
        if context.dynamic_long("UNFREEZE_DELAY_DAYS")? <= 0 { return Err(ActuatorError::validation("Not support FreezeV2 transaction, need to be opened by the committee")); }
        let owner = validate_owner_not_exists(context, &self.contract.owner_address)?;
        if self.contract.frozen_balance <= 0 { return Err(ActuatorError::validation("frozenBalance must be positive")); }
        if self.contract.frozen_balance < TRX_PRECISION { return Err(ActuatorError::validation("frozenBalance must be greater than or equal to 1 TRX")); }
        if self.contract.frozen_balance > owner.balance { return Err(ActuatorError::validation("frozenBalance must be less than or equal to accountBalance")); }
        strict_resource(self.contract.resource, enabled(context, "ALLOW_NEW_RESOURCE_MODEL")?)?;
        Ok(())
    }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let mut owner = account(context, &self.contract.owner_address)?;
        initialize_old_tron_power(&mut owner, enabled(context, "ALLOW_NEW_RESOURCE_MODEL")?)?;
        let kind = resource(self.contract.resource)?;
        let old = weight_balance(&owner, kind)?;
        add_frozen_v2(&mut owner, kind, self.contract.frozen_balance)?;
        owner.balance = checked_sub(owner.balance, self.contract.frozen_balance)?;
        change_weight(context, kind, old, weight_balance(&owner, kind)?)?;
        save(context, &owner)?;
        result.code = Code::Sucess;
        Ok(())
    }
}

pub struct UnfreezeBalanceV2Actuator { any: Any, contract: UnfreezeBalanceV2Contract }
ctor!(UnfreezeBalanceV2Actuator, UnfreezeBalanceV2Contract, "protocol.UnfreezeBalanceV2Contract");
impl Actuator for UnfreezeBalanceV2Actuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> {
        if context.dynamic_long("UNFREEZE_DELAY_DAYS")? <= 0 { return Err(ActuatorError::validation("Not support UnfreezeV2 transaction, need to be opened by the committee")); }
        let owner = validate_owner(context, &self.contract.owner_address)?;
        let kind = strict_resource(self.contract.resource, enabled(context, "ALLOW_NEW_RESOURCE_MODEL")?)?;
        if frozen_v2(&owner, kind) <= 0 {
            let name = match kind { ResourceCode::Bandwidth => "BANDWIDTH", ResourceCode::Energy => "Energy", ResourceCode::TronPower => "TronPower" };
            return Err(ActuatorError::validation(format!("no frozenBalance({name})")));
        }
        if self.contract.unfreeze_balance <= 0 || self.contract.unfreeze_balance > frozen_v2(&owner, kind) {
            return Err(ActuatorError::validation(format!("Invalid unfreeze_balance, [{}] is error", self.contract.unfreeze_balance)));
        }
        let now = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
        if owner.unfrozen_v2.iter().filter(|item| item.unfreeze_expire_time > now).count() >= 32 {
            return Err(ActuatorError::validation("Invalid unfreeze operation, unfreezing times is over limit"));
        }
        Ok(())
    }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        context.withdraw_reward(&self.contract.owner_address)?;
        let mut owner = account(context, &self.contract.owner_address)?;
        let now = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
        let mut expired = 0;
        owner.unfrozen_v2.retain(|item| { if item.unfreeze_expire_time <= now { expired += item.unfreeze_amount; false } else { true } });
        owner.balance = checked_add(owner.balance, expired)?;
        let new_model = enabled(context, "ALLOW_NEW_RESOURCE_MODEL")?;
        initialize_old_tron_power(&mut owner, new_model)?;
        let kind = resource(self.contract.resource)?;
        let old = weight_balance(&owner, kind)?;
        let old_vote_power = if new_model { 0 } else { legacy_vote_power(&owner)? };
        add_frozen_v2(&mut owner, kind, -self.contract.unfreeze_balance)?;
        change_weight(context, kind, old, weight_balance(&owner, kind)?)?;
        let expire = checked_add(now, checked_mul(context.dynamic_long("UNFREEZE_DELAY_DAYS")?, DAY_MS)?)?;
        owner.unfrozen_v2.push(UnFreezeV2 { r#type: kind as i32, unfreeze_amount: self.contract.unfreeze_balance, unfreeze_expire_time: expire });
        if new_model && owner.old_tron_power != -1 {
            clear_votes(context, &mut owner)?;
            owner.old_tron_power = -1;
        } else if !new_model {
            scale_legacy_votes(context, &mut owner, old_vote_power)?;
        } else if kind == ResourceCode::TronPower {
            clear_votes(context, &mut owner)?;
        }
        save(context, &owner)?;
        result.withdraw_expire_amount = expired;
        result.code = Code::Sucess;
        Ok(())
    }
}

pub struct WithdrawExpireUnfreezeActuator { any: Any, contract: WithdrawExpireUnfreezeContract }
ctor!(WithdrawExpireUnfreezeActuator, WithdrawExpireUnfreezeContract, "protocol.WithdrawExpireUnfreezeContract");
impl Actuator for WithdrawExpireUnfreezeActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> {
        if context.dynamic_long("UNFREEZE_DELAY_DAYS")? <= 0 { return Err(ActuatorError::validation("Not support WithdrawExpireUnfreeze transaction, need to be opened by the committee")); }
        let owner = validate_owner_not_exists(context, &self.contract.owner_address)?;
        let now = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
        if !owner.unfrozen_v2.iter().any(|item| item.unfreeze_expire_time <= now && item.unfreeze_amount > 0) {
            return Err(ActuatorError::validation("no unFreeze balance to withdraw "));
        }
        Ok(())
    }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let mut owner = account(context, &self.contract.owner_address)?;
        let now = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
        let mut amount = 0;
        owner.unfrozen_v2.retain(|item| { if item.unfreeze_expire_time <= now { amount += item.unfreeze_amount; false } else { true } });
        owner.balance = checked_add(owner.balance, amount)?;
        save(context, &owner)?;
        result.withdraw_expire_amount = amount;
        result.code = Code::Sucess;
        Ok(())
    }
}

pub struct CancelAllUnfreezeV2Actuator { any: Any, contract: CancelAllUnfreezeV2Contract }
ctor!(CancelAllUnfreezeV2Actuator, CancelAllUnfreezeV2Contract, "protocol.CancelAllUnfreezeV2Contract");
impl Actuator for CancelAllUnfreezeV2Actuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> {
        if !enabled(context, "ALLOW_CANCEL_ALL_UNFREEZE_V2")? { return Err(ActuatorError::validation("Not support CancelAllUnfreezeV2 transaction, need to be opened by the committee")); }
        let owner = validate_owner_not_exists(context, &self.contract.owner_address)?;
        if owner.unfrozen_v2.is_empty() { return Err(ActuatorError::validation("No unfreezeV2 list to cancel")); }
        Ok(())
    }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let mut owner = account(context, &self.contract.owner_address)?;
        let now = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
        let mut expired = 0;
        let mut cancelled = [(ResourceCode::Bandwidth, 0), (ResourceCode::Energy, 0), (ResourceCode::TronPower, 0)];
        for item in core::mem::take(&mut owner.unfrozen_v2) {
            if item.unfreeze_expire_time <= now {
                owner.balance = checked_add(owner.balance, item.unfreeze_amount)?;
                expired = checked_add(expired, item.unfreeze_amount)?;
            } else {
                let kind = strict_resource(item.r#type, true)?;
                let old = weight_balance(&owner, kind)?;
                add_frozen_v2(&mut owner, kind, item.unfreeze_amount)?;
                change_weight(context, kind, old, weight_balance(&owner, kind)?)?;
                let amount = &mut cancelled.iter_mut().find(|(resource, _)| *resource == kind).unwrap().1;
                *amount = checked_add(*amount, item.unfreeze_amount)?;
            }
        }
        save(context, &owner)?;
        result.withdraw_expire_amount = expired;
        result.cancel_unfreeze_v2_amount = cancelled.into_iter().map(|(resource, amount)| (resource.as_str_name().to_owned(), amount)).collect();
        result.code = Code::Sucess;
        Ok(())
    }
}

pub struct DelegateResourceActuator { any: Any, contract: DelegateResourceContract }
ctor!(DelegateResourceActuator, DelegateResourceContract, "protocol.DelegateResourceContract");
impl Actuator for DelegateResourceActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> {
        if !enabled(context, "ALLOW_DELEGATE_RESOURCE")? { return Err(ActuatorError::validation("No support for resource delegate")); }
        if context.dynamic_long("UNFREEZE_DELAY_DAYS")? <= 0 { return Err(ActuatorError::validation("Not support Delegate resource transaction, need to be opened by the committee")); }
        let owner = validate_owner_not_exists(context, &self.contract.owner_address)?;
        if self.contract.balance < TRX_PRECISION { return Err(ActuatorError::validation("delegateBalance must be greater than or equal to 1 TRX")); }
        let kind = strict_resource(self.contract.resource, false)?;
        let weighted_usage = match kind {
            ResourceCode::Bandwidth => usage_balance(owner.net_usage, context.dynamic_long("TOTAL_NET_WEIGHT")?, context.dynamic_long("TOTAL_NET_LIMIT")?)
                .saturating_sub(owner.frozen.iter().map(|item| item.frozen_balance).sum::<i64>())
                .saturating_sub(owner.acquired_delegated_frozen_balance_for_bandwidth)
                .saturating_sub(owner.acquired_delegated_frozen_v2_balance_for_bandwidth).max(0),
            ResourceCode::Energy => {
                let state = owner.account_resource.as_ref();
                usage_balance(state.map_or(0, |item| item.energy_usage), context.dynamic_long("TOTAL_ENERGY_WEIGHT")?, context.dynamic_long("TOTAL_ENERGY_CURRENT_LIMIT")?)
                    .saturating_sub(state.and_then(|item| item.frozen_balance_for_energy.as_ref()).map_or(0, |item| item.frozen_balance))
                    .saturating_sub(state.map_or(0, |item| item.acquired_delegated_frozen_balance_for_energy))
                    .saturating_sub(state.map_or(0, |item| item.acquired_delegated_frozen_v2_balance_for_energy)).max(0)
            }
            ResourceCode::TronPower => 0,
        };
        if self.contract.balance > frozen_v2(&owner, kind).saturating_sub(weighted_usage) {
            let name = if kind == ResourceCode::Bandwidth { "Bandwidth" } else { "Energy" };
            return Err(ActuatorError::validation(format!("delegateBalance must be less than or equal to available Freeze{name}V2 balance")));
        }
        if !valid_address(&self.contract.receiver_address) { return Err(ActuatorError::validation("Invalid receiverAddress")); }
        if self.contract.owner_address == self.contract.receiver_address { return Err(ActuatorError::validation("receiverAddress must not be the same as ownerAddress")); }
        let receiver = account(context, &self.contract.receiver_address)?;
        if receiver.r#type == AccountType::Contract as i32 { return Err(ActuatorError::validation("Do not allow delegate resources to contract addresses")); }
        if self.contract.lock {
            let maximum_bytes = context.get(StoreKind::DynamicProperties, dynamic::key("MAX_DELEGATE_LOCK_PERIOD").unwrap())?;
            let supports_maximum = maximum_bytes.is_some() && context.dynamic_long("UNFREEZE_DELAY_DAYS")? > 0;
            let maximum = maximum_bytes.and_then(|bytes| bytes.try_into().ok().map(i64::from_be_bytes)).unwrap_or(DEFAULT_DELEGATE_LOCK_SLOTS);
            let lock_period = if supports_maximum && self.contract.lock_period != 0 { self.contract.lock_period } else { DEFAULT_DELEGATE_LOCK_SLOTS };
            if supports_maximum && (lock_period < 0 || lock_period > maximum) { return Err(ActuatorError::validation(format!("The lock period of delegate resource cannot be less than 0 and cannot exceed {maximum}!"))); }
            let key = delegation::resource_v2_key(&self.contract.owner_address, &self.contract.receiver_address, true);
            if let Some(bytes) = context.get(StoreKind::DelegatedResource, &key)? {
                let existing = DelegatedResource::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?;
                let expire = if kind == ResourceCode::Bandwidth { existing.expire_time_for_bandwidth } else { existing.expire_time_for_energy };
                let now = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
                if checked_mul(lock_period, BLOCK_MS)? < expire - now {
                    let name = if kind == ResourceCode::Bandwidth { "BANDWIDTH" } else { "ENERGY" };
                    return Err(ActuatorError::validation(format!("The lock period for {name} this time cannot be less than the remaining time[{}ms] of the last lock period for {name}!", expire - now)));
                }
            }
        }
        Ok(())
    }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let now = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
        unlock_expired(context, &self.contract.owner_address, &self.contract.receiver_address, now)?;
        let kind = resource(self.contract.resource)?;
        let key = delegation::resource_v2_key(&self.contract.owner_address, &self.contract.receiver_address, self.contract.lock);
        let mut record = delegated(context, &key, &self.contract.owner_address, &self.contract.receiver_address)?;
        let supports_maximum = context.get(StoreKind::DynamicProperties, dynamic::key("MAX_DELEGATE_LOCK_PERIOD").unwrap())?.is_some() && context.dynamic_long("UNFREEZE_DELAY_DAYS")? > 0;
        let period = if supports_maximum && self.contract.lock_period != 0 { self.contract.lock_period } else { DEFAULT_DELEGATE_LOCK_SLOTS };
        let expire = if self.contract.lock { checked_add(now, checked_mul(period, BLOCK_MS)?)? } else { 0 };
        let mut owner = account(context, &self.contract.owner_address)?;
        let mut receiver = account(context, &self.contract.receiver_address)?;
        add_frozen_v2(&mut owner, kind, -self.contract.balance)?;
        match kind {
            ResourceCode::Bandwidth => {
                owner.delegated_frozen_v2_balance_for_bandwidth = checked_add(owner.delegated_frozen_v2_balance_for_bandwidth, self.contract.balance)?;
                receiver.acquired_delegated_frozen_v2_balance_for_bandwidth = checked_add(receiver.acquired_delegated_frozen_v2_balance_for_bandwidth, self.contract.balance)?;
                record.frozen_balance_for_bandwidth = checked_add(record.frozen_balance_for_bandwidth, self.contract.balance)?;
                record.expire_time_for_bandwidth = expire;
            }
            ResourceCode::Energy => {
                let owner_resource = owner.account_resource.get_or_insert_default();
                owner_resource.delegated_frozen_v2_balance_for_energy = checked_add(owner_resource.delegated_frozen_v2_balance_for_energy, self.contract.balance)?;
                let receiver_resource = receiver.account_resource.get_or_insert_default();
                receiver_resource.acquired_delegated_frozen_v2_balance_for_energy = checked_add(receiver_resource.acquired_delegated_frozen_v2_balance_for_energy, self.contract.balance)?;
                record.frozen_balance_for_energy = checked_add(record.frozen_balance_for_energy, self.contract.balance)?;
                record.expire_time_for_energy = expire;
            }
            ResourceCode::TronPower => unreachable!(),
        }
        context.put_message(StoreKind::DelegatedResource, &key, &record)?;
        let from_key = delegation::v2_from_index_key(&owner.address, &receiver.address);
        let to_key = delegation::v2_to_index_key(&receiver.address, &owner.address);
        let from_index = DelegatedResourceAccountIndex { account: receiver.address.clone(), timestamp: now, ..Default::default() };
        let to_index = DelegatedResourceAccountIndex { account: owner.address.clone(), timestamp: now, ..Default::default() };
        context.put_message(StoreKind::DelegatedResourceAccountIndex, &from_key, &from_index)?;
        context.put_message(StoreKind::DelegatedResourceAccountIndex, &to_key, &to_index)?;
        save(context, &owner)?;
        save(context, &receiver)?;
        result.code = Code::Sucess;
        Ok(())
    }
}

pub struct UnDelegateResourceActuator { any: Any, contract: UnDelegateResourceContract }
ctor!(UnDelegateResourceActuator, UnDelegateResourceContract, "protocol.UnDelegateResourceContract");
impl Actuator for UnDelegateResourceActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> {
        if !enabled(context, "ALLOW_DELEGATE_RESOURCE")? { return Err(ActuatorError::validation("No support for resource delegate")); }
        if context.dynamic_long("UNFREEZE_DELAY_DAYS")? <= 0 { return Err(ActuatorError::validation("Not support unDelegate resource transaction, need to be opened by the committee")); }
        validate_owner(context, &self.contract.owner_address)?;
        if !valid_address(&self.contract.receiver_address) { return Err(ActuatorError::validation("Invalid receiverAddress")); }
        if self.contract.owner_address == self.contract.receiver_address { return Err(ActuatorError::validation("receiverAddress must not be the same as ownerAddress")); }
        if self.contract.balance <= 0 { return Err(ActuatorError::validation("unDelegateBalance must be more than 0 TRX")); }
        let kind = strict_resource(self.contract.resource, false)?;
        let now = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
        let unlocked_key = delegation::resource_v2_key(&self.contract.owner_address, &self.contract.receiver_address, false);
        let locked_key = delegation::resource_v2_key(&self.contract.owner_address, &self.contract.receiver_address, true);
        let unlocked = context.get(StoreKind::DelegatedResource, &unlocked_key)?.map(|bytes| DelegatedResource::decode(bytes.as_slice())).transpose().map_err(|error| ActuatorError::execution(error.to_string()))?;
        let locked = context.get(StoreKind::DelegatedResource, &locked_key)?.map(|bytes| DelegatedResource::decode(bytes.as_slice())).transpose().map_err(|error| ActuatorError::execution(error.to_string()))?;
        if unlocked.is_none() && locked.is_none() { return Err(ActuatorError::validation("delegated Resource does not exist")); }
        let available = |record: &DelegatedResource| if kind == ResourceCode::Bandwidth { record.frozen_balance_for_bandwidth } else { record.frozen_balance_for_energy };
        let mut balance = unlocked.as_ref().map_or(0, available);
        if let Some(record) = locked.as_ref() {
            let expire = if kind == ResourceCode::Bandwidth { record.expire_time_for_bandwidth } else { record.expire_time_for_energy };
            if expire < now { balance = checked_add(balance, available(record))?; }
        }
        if balance < self.contract.balance {
            let message = if kind == ResourceCode::Bandwidth {
                format!("insufficient delegatedFrozenBalance(BANDWIDTH), request={}, unlock_balance={balance}", self.contract.balance)
            } else {
                format!("insufficient delegateFrozenBalance(Energy), request={}, unlock_balance={balance}", self.contract.balance)
            };
            return Err(ActuatorError::validation(message));
        }
        Ok(())
    }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let now = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
        let precise_windows = enabled(context, "ALLOW_CANCEL_ALL_UNFREEZE_V2")?;
        let kind = resource(self.contract.resource)?;
        let key = delegation::resource_v2_key(&self.contract.owner_address, &self.contract.receiver_address, false);
        let unlocked_existed = context.get(StoreKind::DelegatedResource, &key)?.is_some();
        let mut record = delegated(context, &key, &self.contract.owner_address, &self.contract.receiver_address)?;
        let locked_key = delegation::resource_v2_key(&self.contract.owner_address, &self.contract.receiver_address, true);
        let mut moved_from_locked = false;
        if let Some(bytes) = context.get(StoreKind::DelegatedResource, &locked_key)? {
            let mut locked = DelegatedResource::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?;
            if locked.frozen_balance_for_bandwidth > 0 && locked.expire_time_for_bandwidth < now {
                record.frozen_balance_for_bandwidth = checked_add(record.frozen_balance_for_bandwidth, locked.frozen_balance_for_bandwidth)?;
                moved_from_locked = true;
                locked.frozen_balance_for_bandwidth = 0;
                locked.expire_time_for_bandwidth = 0;
            }
            if locked.frozen_balance_for_energy > 0 && locked.expire_time_for_energy < now {
                record.frozen_balance_for_energy = checked_add(record.frozen_balance_for_energy, locked.frozen_balance_for_energy)?;
                moved_from_locked = true;
                locked.frozen_balance_for_energy = 0;
                locked.expire_time_for_energy = 0;
            }
            if locked.frozen_balance_for_bandwidth == 0 && locked.frozen_balance_for_energy == 0 {
                context.delete(StoreKind::DelegatedResource, &locked_key)?;
            } else {
                context.put_message(StoreKind::DelegatedResource, &locked_key, &locked)?;
            }
        }
        let mut owner = account(context, &self.contract.owner_address)?;
        let mut receiver = account(context, &self.contract.receiver_address).ok();
        add_frozen_v2(&mut owner, kind, self.contract.balance)?;
        match kind {
            ResourceCode::Bandwidth => {
                owner.delegated_frozen_v2_balance_for_bandwidth = checked_sub(owner.delegated_frozen_v2_balance_for_bandwidth, self.contract.balance)?;
                record.frozen_balance_for_bandwidth = checked_sub(record.frozen_balance_for_bandwidth, self.contract.balance)?;
                if let Some(account) = receiver.as_mut() {
                    let now_slot = now / BLOCK_MS;
                    let owner_remaining = remaining_window(owner.latest_consume_time, owner.net_window_size, owner.net_window_optimized, now_slot);
                    let receiver_remaining = remaining_window(account.latest_consume_time, account.net_window_size, account.net_window_optimized, now_slot);
                    account.net_usage = recovered_usage(account.net_usage, account.latest_consume_time, account.net_window_size, account.net_window_optimized, now_slot)?;
                    owner.net_usage = recovered_usage(owner.net_usage, owner.latest_consume_time, owner.net_window_size, owner.net_window_optimized, now_slot)?;
                    let acquired = account.acquired_delegated_frozen_v2_balance_for_bandwidth;
                    let transfer = if acquired < self.contract.balance {
                        account.acquired_delegated_frozen_v2_balance_for_bandwidth = 0;
                        0
                    } else {
                        let all_frozen = checked_add(checked_add(frozen_v2(account, kind), delegated_v2(account, kind))?, acquired)?;
                        let max_usage = usage_limit(self.contract.balance, context.dynamic_long("TOTAL_NET_LIMIT")?, context.dynamic_long("TOTAL_NET_WEIGHT")?);
                        account.acquired_delegated_frozen_v2_balance_for_bandwidth = checked_sub(acquired, self.contract.balance)?;
                        max_usage.min(proportional_usage(account.net_usage, self.contract.balance, all_frozen))
                    };
                    account.net_usage = account.net_usage.saturating_sub(transfer);
                    account.latest_consume_time = now_slot;
                    account.net_window_size = if acquired < self.contract.balance { 28_800 } else { receiver_remaining };
                    if transfer > 0 {
                        let combined_usage = checked_add(owner.net_usage, transfer)?;
                        owner.net_window_size = weighted_window(owner.net_usage, owner_remaining, transfer, receiver_remaining, combined_usage);
                        owner.net_usage = combined_usage;
                        owner.latest_consume_time = now_slot;
                    }
                    if precise_windows {
                        account.net_window_size = checked_mul(account.net_window_size, 1_000)?;
                        account.net_window_optimized = true;
                        if transfer > 0 {
                            owner.net_window_size = checked_mul(owner.net_window_size, 1_000)?;
                            owner.net_window_optimized = true;
                        }
                    }
                }
            }
            ResourceCode::Energy => {
                let owner_resource = owner.account_resource.get_or_insert_default();
                owner_resource.delegated_frozen_v2_balance_for_energy = checked_sub(owner_resource.delegated_frozen_v2_balance_for_energy, self.contract.balance)?;
                record.frozen_balance_for_energy = checked_sub(record.frozen_balance_for_energy, self.contract.balance)?;
                if let Some(account) = receiver.as_mut() {
                    let now_slot = now / BLOCK_MS;
                    let receiver_window = account.account_resource.as_ref().map_or(0, |item| item.energy_window_size);
                    let receiver_precise = account.account_resource.as_ref().is_some_and(|item| item.energy_window_optimized);
                    let receiver_latest = account.account_resource.as_ref().map_or(0, |item| item.latest_consume_time_for_energy);
                    let receiver_usage = recovered_usage(account.account_resource.as_ref().map_or(0, |item| item.energy_usage), receiver_latest, receiver_window, receiver_precise, now_slot)?;
                    let owner_window = owner_resource.energy_window_size;
                    let owner_usage = recovered_usage(owner_resource.energy_usage, owner_resource.latest_consume_time_for_energy, owner_window, owner_resource.energy_window_optimized, now_slot)?;
                    owner_resource.energy_usage = owner_usage;
                    let acquired = account.account_resource.as_ref().map_or(0, |item| item.acquired_delegated_frozen_v2_balance_for_energy);
                    let transfer = if acquired < self.contract.balance {
                        account.account_resource.get_or_insert_default().acquired_delegated_frozen_v2_balance_for_energy = 0;
                        0
                    } else {
                        let all_frozen = checked_add(checked_add(frozen_v2(account, kind), delegated_v2(account, kind))?, acquired)?;
                        let max_usage = usage_limit(self.contract.balance, context.dynamic_long("TOTAL_ENERGY_CURRENT_LIMIT")?, context.dynamic_long("TOTAL_ENERGY_WEIGHT")?);
                        account.account_resource.get_or_insert_default().acquired_delegated_frozen_v2_balance_for_energy = checked_sub(acquired, self.contract.balance)?;
                        max_usage.min(proportional_usage(receiver_usage, self.contract.balance, all_frozen))
                    };
                    let receiver_resource = account.account_resource.get_or_insert_default();
                    receiver_resource.energy_usage = receiver_usage.saturating_sub(transfer);
                    receiver_resource.latest_consume_time_for_energy = now / BLOCK_MS;
                    receiver_resource.energy_window_size = if acquired < self.contract.balance { 28_800 } else { receiver_window.max(28_800 - now_slot.saturating_sub(receiver_latest)).max(0) };
                    if transfer > 0 {
                        let owner_remaining = if owner_window <= 0 { 28_800 } else { owner_window }.saturating_sub(now_slot.saturating_sub(owner_resource.latest_consume_time_for_energy)).max(0);
                        let receiver_remaining = receiver_resource.energy_window_size;
                        let combined_usage = checked_add(owner_resource.energy_usage, transfer)?;
                        owner_resource.energy_window_size = weighted_window(owner_resource.energy_usage, owner_remaining, transfer, receiver_remaining, combined_usage);
                        owner_resource.energy_usage = combined_usage;
                        owner_resource.latest_consume_time_for_energy = now / BLOCK_MS;
                    }
                    if precise_windows {
                        receiver_resource.energy_window_size = checked_mul(receiver_resource.energy_window_size, 1_000)?;
                        receiver_resource.energy_window_optimized = true;
                        if transfer > 0 {
                            owner_resource.energy_window_size = checked_mul(owner_resource.energy_window_size, 1_000)?;
                            owner_resource.energy_window_optimized = true;
                        }
                    }
                }
            }
            ResourceCode::TronPower => unreachable!(),
        }
        if record.frozen_balance_for_bandwidth == 0 && record.frozen_balance_for_energy == 0 {
            if unlocked_existed || moved_from_locked { context.delete(StoreKind::DelegatedResource, &key)?; }
            if context.get(StoreKind::DelegatedResource, &locked_key)?.is_none() {
                remove_v2_indexes(context, &self.contract.owner_address, &self.contract.receiver_address)?;
            }
        } else {
            context.put_message(StoreKind::DelegatedResource, &key, &record)?;
        }
        save(context, &owner)?;
        if let Some(receiver) = receiver { save(context, &receiver)?; }
        result.code = Code::Sucess;
        Ok(())
    }
}
fn usage_limit(balance: i64, limit: i64, weight: i64) -> i64 {
    if balance <= 0 || limit <= 0 || weight <= 0 { 0 } else { ((balance as i128 * limit as i128) / (TRX_PRECISION as i128 * weight as i128)).min(i64::MAX as i128) as i64 }
}
fn proportional_usage(usage: i64, balance: i64, all_frozen: i64) -> i64 {
    if usage <= 0 || balance <= 0 || all_frozen <= 0 { 0 } else { ((usage as i128 * balance as i128) / all_frozen as i128).min(i64::MAX as i128) as i64 }
}
fn usage_balance(usage: i64, weight: i64, limit: i64) -> i64 {
    if usage <= 0 || weight <= 0 || limit <= 0 { 0 } else { ((usage as f64 * TRX_PRECISION as f64 * weight as f64 / limit as f64) as i64).max(0) }
}
fn recovered_usage(usage: i64, latest_slot: i64, window: i64, precise: bool, now: i64) -> Result<i64, ActuatorError> {
    ResourceWindow { usage, latest_slot, window, precise, standard_window: 28_800 }
        .recover(now)
        .map_err(|error| ActuatorError::arithmetic(error.to_string()))
}

fn remaining_window(latest_slot: i64, window: i64, precise: bool, now: i64) -> i64 {
    let slots = if window <= 0 { 28_800 } else if precise { window / 1_000 } else { window };
    slots.saturating_sub(now.saturating_sub(latest_slot)).max(0)
}
fn weighted_window(left_usage: i64, left_window: i64, right_usage: i64, right_window: i64, total_usage: i64) -> i64 {
    if total_usage <= 0 { return 28_800; }
    ((left_usage as i128 * left_window as i128 + right_usage as i128 * right_window as i128) / total_usage as i128)
        .clamp(0, 28_800) as i64
}
pub struct FreezeBalanceActuator { any: Any, contract: FreezeBalanceContract }
pub struct UnfreezeBalanceActuator { any: Any, contract: UnfreezeBalanceContract }
pub struct WithdrawBalanceActuator { any: Any, contract: WithdrawBalanceContract }
ctor!(FreezeBalanceActuator, FreezeBalanceContract, "protocol.FreezeBalanceContract");
ctor!(UnfreezeBalanceActuator, UnfreezeBalanceContract, "protocol.UnfreezeBalanceContract");
ctor!(WithdrawBalanceActuator, WithdrawBalanceContract, "protocol.WithdrawBalanceContract");
impl Actuator for FreezeBalanceActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> {
        let owner = validate_owner_not_exists(context, &self.contract.owner_address)?;
        if self.contract.frozen_balance <= 0 { return Err(ActuatorError::validation("frozenBalance must be positive")); }
        if self.contract.frozen_balance < TRX_PRECISION { return Err(ActuatorError::validation("frozenBalance must be greater than or equal to 1 TRX")); }
        if owner.frozen.len() > 1 { return Err(ActuatorError::validation("frozenCount must be 0 or 1")); }
        if self.contract.frozen_balance > owner.balance { return Err(ActuatorError::validation("frozenBalance must be less than or equal to accountBalance")); }
        let new_model = enabled(context, "ALLOW_NEW_RESOURCE_MODEL")?;
        let kind = strict_resource(self.contract.resource, new_model)?;
        if kind == ResourceCode::TronPower && !self.contract.receiver_address.is_empty() { return Err(ActuatorError::validation("TRON_POWER is not allowed to delegate to other accounts.")); }
        if !self.contract.receiver_address.is_empty() && enabled(context, "ALLOW_DELEGATE_RESOURCE")? {
            if self.contract.receiver_address == self.contract.owner_address { return Err(ActuatorError::validation("receiverAddress must not be the same as ownerAddress")); }
            if !valid_address(&self.contract.receiver_address) { return Err(ActuatorError::validation("Invalid receiverAddress")); }
            let receiver = account(context, &self.contract.receiver_address)?;
            if enabled(context, "ALLOW_TVM_CONSTANTINOPLE")? && receiver.r#type == AccountType::Contract as i32 { return Err(ActuatorError::validation("Do not allow delegate resources to contract addresses")); }
        }
        let minimum = i64::from(context.dynamic_int("MIN_FROZEN_TIME")?);
        let maximum = i64::from(context.dynamic_int("MAX_FROZEN_TIME")?);
        if self.contract.frozen_duration < minimum || self.contract.frozen_duration > maximum {
            return Err(ActuatorError::validation(format!("frozenDuration must be less than {maximum} days and more than {minimum} days")));
        }
        if long_or(context, "UNFREEZE_DELAY_DAYS", 0) > 0 { return Err(ActuatorError::validation("freeze v2 is open, old freeze is closed")); }
        Ok(())
    }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let mut owner = account(context, &self.contract.owner_address)?;
        initialize_old_tron_power(&mut owner, enabled(context, "ALLOW_NEW_RESOURCE_MODEL")?)?;
        let now = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
        let expire = checked_add(now, checked_mul(self.contract.frozen_duration, DAY_MS)?)?;
        let kind = resource(self.contract.resource)?;
        let receiver_present = !self.contract.receiver_address.is_empty() && enabled(context, "ALLOW_DELEGATE_RESOURCE")?;
        let old = legacy_resource_balance(&owner, kind);
        if receiver_present {
            let key = delegation::legacy_resource_key(&owner.address, &self.contract.receiver_address);
            let mut record = delegated(context, &key, &owner.address, &self.contract.receiver_address)?;
            let mut receiver = account(context, &self.contract.receiver_address)?;
            match kind {
                ResourceCode::Bandwidth => { owner.delegated_frozen_balance_for_bandwidth = checked_add(owner.delegated_frozen_balance_for_bandwidth, self.contract.frozen_balance)?; receiver.acquired_delegated_frozen_balance_for_bandwidth = checked_add(receiver.acquired_delegated_frozen_balance_for_bandwidth, self.contract.frozen_balance)?; record.frozen_balance_for_bandwidth = checked_add(record.frozen_balance_for_bandwidth, self.contract.frozen_balance)?; record.expire_time_for_bandwidth = expire; }
                ResourceCode::Energy => {
                    let owner_resource = owner.account_resource.get_or_insert_default();
                    owner_resource.delegated_frozen_balance_for_energy = checked_add(owner_resource.delegated_frozen_balance_for_energy, self.contract.frozen_balance)?;
                    let receiver_resource = receiver.account_resource.get_or_insert_default();
                    receiver_resource.acquired_delegated_frozen_balance_for_energy = checked_add(receiver_resource.acquired_delegated_frozen_balance_for_energy, self.contract.frozen_balance)?;
                    record.frozen_balance_for_energy = checked_add(record.frozen_balance_for_energy, self.contract.frozen_balance)?;
                    record.expire_time_for_energy = expire;
                }
                ResourceCode::TronPower => unreachable!(),
            }
            context.put_message(StoreKind::DelegatedResource, &key, &record)?;
            if enabled(context, "ALLOW_DELEGATE_OPTIMIZATION")? {
                convert_indexes(context, &owner.address)?;
                convert_indexes(context, &receiver.address)?;
                context.put_message(StoreKind::DelegatedResourceAccountIndex, &delegation::from_index_key(&owner.address, &receiver.address), &DelegatedResourceAccountIndex { account: receiver.address.clone(), timestamp: now, ..Default::default() })?;
                context.put_message(StoreKind::DelegatedResourceAccountIndex, &delegation::to_index_key(&receiver.address, &owner.address), &DelegatedResourceAccountIndex { account: owner.address.clone(), timestamp: now, ..Default::default() })?;
            } else {
                let mut owner_index = index(context, &owner.address)?; if !owner_index.to_accounts.contains(&receiver.address) { owner_index.to_accounts.push(receiver.address.clone()); }
                let mut receiver_index = index(context, &receiver.address)?; if !receiver_index.from_accounts.contains(&owner.address) { receiver_index.from_accounts.push(owner.address.clone()); }
                context.put_message(StoreKind::DelegatedResourceAccountIndex, &owner.address, &owner_index)?;
                context.put_message(StoreKind::DelegatedResourceAccountIndex, &receiver.address, &receiver_index)?;
            }
            save(context, &receiver)?;
        } else {
            match kind {
                ResourceCode::Bandwidth => { let amount = checked_add(owner.frozen.iter().map(|item| item.frozen_balance).sum(), self.contract.frozen_balance)?; owner.frozen = vec![Frozen { frozen_balance: amount, expire_time: expire }]; }
                ResourceCode::Energy => { let current = owner.account_resource.as_ref().and_then(|item| item.frozen_balance_for_energy.as_ref()).map_or(0, |item| item.frozen_balance); owner.account_resource.get_or_insert_default().frozen_balance_for_energy = Some(Frozen { frozen_balance: checked_add(current, self.contract.frozen_balance)?, expire_time: expire }); }
                ResourceCode::TronPower => { let current = owner.tron_power.as_ref().map_or(0, |item| item.frozen_balance); owner.tron_power = Some(Frozen { frozen_balance: checked_add(current, self.contract.frozen_balance)?, expire_time: expire }); }
            }
        }
        owner.balance = checked_sub(owner.balance, self.contract.frozen_balance)?;
        change_legacy_weight(context, kind, old, legacy_resource_balance(&owner, kind), self.contract.frozen_balance)?;
        save(context, &owner)?;
        result.code = Code::Sucess;
        Ok(())
    }
}
fn legacy_resource_balance(account: &Account, kind: ResourceCode) -> i64 {
    match kind {
        ResourceCode::Bandwidth => account.frozen.iter().map(|item| item.frozen_balance).sum(),
        ResourceCode::Energy => account.account_resource.as_ref().and_then(|item| item.frozen_balance_for_energy.as_ref()).map_or(0, |item| item.frozen_balance),
        ResourceCode::TronPower => account.tron_power.as_ref().map_or(0, |item| item.frozen_balance),
    }
}
fn change_legacy_weight(context: &mut ExecutionContext<'_>, kind: ResourceCode, old: i64, new: i64, amount: i64) -> Result<(), ActuatorError> {
    let delta = if enabled(context, "ALLOW_NEW_REWARD")? { new / TRX_PRECISION - old / TRX_PRECISION } else if amount >= 0 { amount / TRX_PRECISION } else { -(-amount / TRX_PRECISION) };
    let name = weight_name(kind);
    context.put_dynamic_long(name, checked_add(context.dynamic_long(name)?, delta)?)
}
impl Actuator for UnfreezeBalanceActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> {
        let owner = validate_owner(context, &self.contract.owner_address)?;
        let new_model = enabled(context, "ALLOW_NEW_RESOURCE_MODEL")?;
        let kind = strict_resource(self.contract.resource, new_model)?;
        let now = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
        if !self.contract.receiver_address.is_empty() && enabled(context, "ALLOW_DELEGATE_RESOURCE")? {
            if !valid_address(&self.contract.receiver_address) || self.contract.receiver_address == self.contract.owner_address { return Err(ActuatorError::validation("Invalid receiverAddress")); }
            let receiver = context.get(StoreKind::Account, &self.contract.receiver_address)?
                .map(|bytes| Account::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string())))
                .transpose()?;
            let constantinople = enabled(context, "ALLOW_TVM_CONSTANTINOPLE")?;
            if receiver.is_none() && !constantinople {
                return Err(ActuatorError::validation(format!("Receiver Account[{}] does not exist", hex(&self.contract.receiver_address))));
            }
            let key = delegation::legacy_resource_key(&self.contract.owner_address, &self.contract.receiver_address);
            let Some(bytes) = context.get(StoreKind::DelegatedResource, &key)? else { return Err(ActuatorError::validation("delegated Resource does not exist")); };
            let record = DelegatedResource::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?;
            let (amount, expire) = if kind == ResourceCode::Bandwidth { (record.frozen_balance_for_bandwidth, record.expire_time_for_bandwidth) } else { (record.frozen_balance_for_energy, record.expire_time_for_energy) };
            let enforce_acquired = !constantinople || (!enabled(context, "ALLOW_TVM_SOLIDITY_059")?
                && receiver.as_ref().is_some_and(|account| account.r#type != AccountType::Contract as i32));
            if enforce_acquired {
                let acquired = receiver.as_ref().map_or(0, |account| match kind {
                    ResourceCode::Bandwidth => account.acquired_delegated_frozen_balance_for_bandwidth,
                    ResourceCode::Energy => account.account_resource.as_ref().map_or(0, |resource| resource.acquired_delegated_frozen_balance_for_energy),
                    ResourceCode::TronPower => 0,
                });
                if acquired < amount {
                    let message = if kind == ResourceCode::Bandwidth {
                        format!("AcquiredDelegatedFrozenBalanceForBandwidth[{acquired}] < delegatedBandwidth[{amount}]")
                    } else {
                        format!("AcquiredDelegatedFrozenBalanceForEnergy[{acquired}] < delegatedEnergy[{amount}]")
                    };
                    return Err(ActuatorError::validation(message));
                }
            }
            if expire > now { return Err(ActuatorError::validation("It's not time to unfreeze.")); }
        } else {
            let frozen = match kind {
                ResourceCode::Bandwidth => owner.frozen.first(),
                ResourceCode::Energy => owner.account_resource.as_ref().and_then(|item| item.frozen_balance_for_energy.as_ref()),
                ResourceCode::TronPower => owner.tron_power.as_ref(),
            };
            let Some(frozen) = frozen else {
                let name = match kind { ResourceCode::Bandwidth => "BANDWIDTH", ResourceCode::Energy => "ENERGY", ResourceCode::TronPower => "TRON_POWER" };
                return Err(ActuatorError::validation(format!("no frozenBalance({name})")));
            };
            if frozen.expire_time > now {
                let message = match kind {
                    ResourceCode::Bandwidth => "It's not time to unfreeze(BANDWIDTH).",
                    ResourceCode::Energy => "It's not time to unfreeze(Energy).",
                    ResourceCode::TronPower => "It's not time to unfreeze(TronPower).",
                };
                return Err(ActuatorError::validation(message));
            }
        }
        Ok(())
    }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        context.withdraw_reward(&self.contract.owner_address)?;
        let mut owner = account(context, &self.contract.owner_address)?;
        let new_model = enabled(context, "ALLOW_NEW_RESOURCE_MODEL")?;
        initialize_old_tron_power(&mut owner, new_model)?;
        let kind = resource(self.contract.resource)?;
        let old = legacy_resource_balance(&owner, kind);
        let now = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
        let amount;
        let delegated_unfreeze = !self.contract.receiver_address.is_empty() && enabled(context, "ALLOW_DELEGATE_RESOURCE")?;
        if delegated_unfreeze {
            let key = delegation::legacy_resource_key(&owner.address, &self.contract.receiver_address);
            let mut record = delegated(context, &key, &owner.address, &self.contract.receiver_address)?;
            let mut receiver = account(context, &self.contract.receiver_address).ok();
            amount = if kind == ResourceCode::Bandwidth { let value = record.frozen_balance_for_bandwidth; record.frozen_balance_for_bandwidth = 0; owner.delegated_frozen_balance_for_bandwidth = checked_sub(owner.delegated_frozen_balance_for_bandwidth, value)?; if let Some(account) = receiver.as_mut() { account.acquired_delegated_frozen_balance_for_bandwidth = account.acquired_delegated_frozen_balance_for_bandwidth.saturating_sub(value).max(0); } value } else { let value = record.frozen_balance_for_energy; record.frozen_balance_for_energy = 0; owner.account_resource.get_or_insert_default().delegated_frozen_balance_for_energy = checked_sub(owner.account_resource.as_ref().unwrap().delegated_frozen_balance_for_energy, value)?; if let Some(account) = receiver.as_mut() { let resource = account.account_resource.get_or_insert_default(); resource.acquired_delegated_frozen_balance_for_energy = resource.acquired_delegated_frozen_balance_for_energy.saturating_sub(value).max(0); } value };
            if record.frozen_balance_for_bandwidth == 0 && record.frozen_balance_for_energy == 0 { context.delete(StoreKind::DelegatedResource, &key)?; remove_indexes(context, &owner.address, &self.contract.receiver_address)?; } else { context.put_message(StoreKind::DelegatedResource, &key, &record)?; }
            if let Some(receiver) = receiver { save(context, &receiver)?; }
        } else {
            amount = match kind {
                ResourceCode::Bandwidth => { let mut amount = 0; owner.frozen.retain(|item| { if item.expire_time <= now { amount += item.frozen_balance; false } else { true } }); amount }
                ResourceCode::Energy => owner.account_resource.get_or_insert_default().frozen_balance_for_energy.take().map_or(0, |item| item.frozen_balance),
                ResourceCode::TronPower => owner.tron_power.take().map_or(0, |item| item.frozen_balance),
            };
        }
        owner.balance = checked_add(owner.balance, amount)?;
        if delegated_unfreeze { change_legacy_weight(context, kind, amount, 0, -amount)?; } else { change_legacy_weight(context, kind, old, legacy_resource_balance(&owner, kind), -amount)?; }
        let clear = !new_model || owner.old_tron_power != -1 || kind == ResourceCode::TronPower;
        if clear { clear_votes_force(context, &mut owner)?; }
        if new_model && owner.old_tron_power != -1 { owner.old_tron_power = -1; }
        save(context, &owner)?;
        result.unfreeze_amount = amount;
        result.code = Code::Sucess;
        Ok(())
    }
}
impl Actuator for WithdrawBalanceActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> {
        let owner = validate_owner_not_exists(context, &self.contract.owner_address)?;
        if context.is_guard_representative(&self.contract.owner_address) { return Err(ActuatorError::validation(format!("Account[{}] is a guard representative and is not allowed to withdraw Balance", hex(&self.contract.owner_address)))); }
        let now = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
        let frozen_period = i64::from(context.dynamic_int("WITNESS_ALLOWANCE_FROZEN_TIME")?);
        if now - owner.latest_withdraw_time < checked_mul(frozen_period, DAY_MS)? {
            return Err(ActuatorError::validation(format!("The last withdraw time is {}, less than 24 hours", owner.latest_withdraw_time)));
        }
        if owner.allowance <= 0 { return Err(ActuatorError::validation("witnessAccount does not have any reward")); }
        checked_add(owner.balance, owner.allowance)?;
        Ok(())
    }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        context.withdraw_reward(&self.contract.owner_address)?;
        let mut owner = account(context, &self.contract.owner_address)?;
        let amount = owner.allowance;
        owner.balance = checked_add(owner.balance, amount)?;
        owner.allowance = 0;
        owner.latest_withdraw_time = context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;
        save(context, &owner)?;
        result.withdraw_amount = amount;
        result.code = Code::Sucess;
        Ok(())
    }
}
