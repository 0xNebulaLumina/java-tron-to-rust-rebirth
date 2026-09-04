use std::collections::BTreeSet;


use tron_protocol::{google::protobuf::Any, protocol::{permission::PermissionType, Account, AccountCreateContract, AccountPermissionUpdateContract, AccountUpdateContract, Key, Permission, SetAccountIdContract}};
use tron_state::StoreKind;

use crate::{Actuator, ExecutionContext, ActuatorError, ActuatorResult, ValidationContext};
use crate::context::{checked_add, checked_sub, decode_typed_any, valid_address};

const ACCOUNT_CREATE: &str = "protocol.AccountCreateContract";
const ACCOUNT_UPDATE: &str = "protocol.AccountUpdateContract";
const SET_ACCOUNT_ID: &str = "protocol.SetAccountIdContract";
const PERMISSION_UPDATE: &str = "protocol.AccountPermissionUpdateContract";

fn default_key(address: &[u8]) -> Key { Key { address: address.to_vec(), weight: 1 } }
pub fn default_owner_permission(address: &[u8]) -> Permission { Permission { r#type: PermissionType::Owner as i32, id: 0, permission_name: "owner".into(), threshold: 1, parent_id: 0, operations: Vec::new(), keys: vec![default_key(address)] } }
pub fn default_active_permission(address: &[u8], operations: Vec<u8>) -> Permission { Permission { r#type: PermissionType::Active as i32, id: 2, permission_name: "active".into(), threshold: 1, parent_id: 0, operations, keys: vec![default_key(address)] } }
pub fn default_witness_permission(address: &[u8]) -> Permission { Permission { r#type: PermissionType::Witness as i32, id: 1, permission_name: "witness".into(), threshold: 1, parent_id: 0, operations: Vec::new(), keys: vec![default_key(address)] } }
fn lowercase_hex(value: &[u8]) -> String { const DIGITS: &[u8; 16] = b"0123456789abcdef"; let mut encoded=String::with_capacity(value.len()*2); for byte in value { encoded.push(DIGITS[usize::from(byte >> 4)] as char); encoded.push(DIGITS[usize::from(byte & 0x0f)] as char); } encoded }

fn account(context: &ExecutionContext<'_>, address: &[u8], missing: &'static str) -> Result<Account, ActuatorError> { context.decode(StoreKind::Account, address, missing) }
fn store_account(context: &mut ExecutionContext<'_>, value: &Account) -> Result<(), ActuatorError> { context.put_message(StoreKind::Account, &value.address, value) }
pub(crate) fn charge_fee(context: &mut ExecutionContext<'_>, payer: &mut Account, fee: i64) -> Result<(), ActuatorError> {
    payer.balance = checked_sub(payer.balance, fee)?;
    if context.dynamic_long("ALLOW_BLACKHOLE_OPTIMIZATION")? == 1 {
        let burned = checked_add(context.dynamic_long("BURN_TRX_AMOUNT")?, fee)?;
        context.put_dynamic_long("BURN_TRX_AMOUNT", burned)
    } else {
        let blackhole_address = context.blackhole_address().to_vec();
        let mut blackhole = account(context, &blackhole_address, "blackhole account does not exist")?;
        blackhole.balance = checked_add(blackhole.balance, fee)?;
        store_account(context, &blackhole)
    }
}

pub struct AccountCreateActuator { any: Any, contract: AccountCreateContract }
impl AccountCreateActuator { pub fn new(any: Any) -> Result<Self, ActuatorError> { let contract = decode_typed_any(&any, ACCOUNT_CREATE)?; Ok(Self { any, contract }) } pub fn raw_any(&self) -> &Any { &self.any } }
impl Actuator for AccountCreateActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { if !valid_address(&self.contract.owner_address) { return Err(ActuatorError::validation("Invalid ownerAddress")); }
    let owner_exists = context.get(StoreKind::Account, &self.contract.owner_address)?.is_some();
    let owner: Account = context.decode(StoreKind::Account, &self.contract.owner_address, "Account does not exist").map_err(|error| if owner_exists { error } else { ActuatorError::validation(format!("Account[{}] not exists",lowercase_hex(&self.contract.owner_address))) })?;
    let fee = context.dynamic_long("CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT")?;
    if owner.balance < fee { return Err(ActuatorError::validation("Validate CreateAccountActuator error, insufficient fee.")); }
    if !valid_address(&self.contract.account_address) { return Err(ActuatorError::validation("Invalid account address")); }
    if context.get(StoreKind::Account, &self.contract.account_address)?.is_some() { return Err(ActuatorError::validation("Account has existed")); }
    Ok(()) }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let fee = context.dynamic_long("CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT")?;
        let mut owner = account(context, &self.contract.owner_address, "Account does not exist")?;
        let mut created = Account { address: self.contract.account_address.clone(), r#type: self.contract.r#type, create_time: context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?, ..Account::default() };
        if context.dynamic_long("ALLOW_MULTI_SIGN")? == 1 { created.owner_permission = Some(default_owner_permission(&created.address)); created.active_permission.push(default_active_permission(&created.address, context.dynamic_raw("ACTIVE_DEFAULT_OPERATIONS")?)); }
        store_account(context, &created)?;
        charge_fee(context, &mut owner, fee)?;
        store_account(context, &owner)?;
        result.fee = checked_add(result.fee, fee)?;
        result.code = tron_protocol::protocol::transaction::result::Code::Sucess;
        Ok(())
    }
}

pub struct AccountUpdateActuator { any: Any, contract: AccountUpdateContract }
impl AccountUpdateActuator { pub fn new(any: Any) -> Result<Self, ActuatorError> { let contract = decode_typed_any(&any, ACCOUNT_UPDATE)?; Ok(Self { any, contract }) } pub fn raw_any(&self) -> &Any { &self.any } }
impl Actuator for AccountUpdateActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { if self.contract.account_name.len() > 200 { return Err(ActuatorError::validation("Invalid accountName")); }
    if !valid_address(&self.contract.owner_address) { return Err(ActuatorError::validation("Invalid ownerAddress")); }
    let current = account(context, &self.contract.owner_address, "Account does not exist")?;
    let update_allowed = context.dynamic_long("ALLOW_UPDATE_ACCOUNT_NAME")? == 1;
    if !current.account_name.is_empty() && !update_allowed { return Err(ActuatorError::validation("This account name is already existed")); }
    if context.get(StoreKind::AccountIndex, &self.contract.account_name)?.is_some() && !update_allowed { return Err(ActuatorError::validation("This name is existed")); }
    Ok(()) }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let mut current = account(context, &self.contract.owner_address, "Account does not exist")?;
        current.account_name.clone_from(&self.contract.account_name);
        store_account(context, &current)?;
        context.put(StoreKind::AccountIndex, &current.account_name, &current.address)?;
        result.code = tron_protocol::protocol::transaction::result::Code::Sucess;
        Ok(())
    }
}

pub struct SetAccountIdActuator { any: Any, contract: SetAccountIdContract }
impl SetAccountIdActuator { pub fn new(any: Any) -> Result<Self, ActuatorError> { let contract = decode_typed_any(&any, SET_ACCOUNT_ID)?; Ok(Self { any, contract }) } pub fn raw_any(&self) -> &Any { &self.any } }
fn lower_root_ascii(value: &[u8]) -> Vec<u8> { value.iter().map(u8::to_ascii_lowercase).collect() }
impl Actuator for SetAccountIdActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { if !(8..=32).contains(&self.contract.account_id.len()) || !self.contract.account_id.iter().all(|byte| (0x21..=0x7e).contains(byte)) { return Err(ActuatorError::validation("Invalid accountId")); }
    if !valid_address(&self.contract.owner_address) { return Err(ActuatorError::validation("Invalid ownerAddress")); }
    let current = account(context, &self.contract.owner_address, "Account has not existed")?;
    if !current.account_id.is_empty() { return Err(ActuatorError::validation("This account id already set")); }
    if context.get(StoreKind::AccountIdIndex, &lower_root_ascii(&self.contract.account_id))?.is_some() { return Err(ActuatorError::validation("This id has existed")); }
    Ok(()) }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let mut current = account(context, &self.contract.owner_address, "Account has not existed")?;
        current.account_id.clone_from(&self.contract.account_id);
        store_account(context, &current)?;
        context.put(StoreKind::AccountIdIndex, &lower_root_ascii(&current.account_id), &current.address)?;
        result.code = tron_protocol::protocol::transaction::result::Code::Sucess;
        Ok(())
    }
}

pub struct AccountPermissionUpdateActuator { any: Any, contract: AccountPermissionUpdateContract }
impl AccountPermissionUpdateActuator { pub fn new(any: Any) -> Result<Self, ActuatorError> { let contract = decode_typed_any(&any, PERMISSION_UPDATE)?; Ok(Self { any, contract }) } pub fn raw_any(&self) -> &Any { &self.any } }
fn check_permission(context: &ExecutionContext<'_>, permission: &Permission) -> Result<(), ActuatorError> {
    let total = usize::try_from(context.dynamic_int("TOTAL_SIGN_NUM")?).unwrap_or(0);
    if permission.keys.len() > total { return Err(ActuatorError::validation(format!("number of keys in permission should not be greater than {total}"))); }
    if permission.keys.is_empty() { return Err(ActuatorError::validation("key's count should be greater than 0")); }
    if permission.r#type == PermissionType::Witness as i32 && permission.keys.len() != 1 { return Err(ActuatorError::validation("Witness permission's key count should be 1")); }
    if permission.threshold <= 0 { return Err(ActuatorError::validation("permission's threshold should be greater than 0")); }
    if permission.permission_name.encode_utf16().count() > 32 { return Err(ActuatorError::validation("permission's name is too long")); }
    if permission.parent_id != 0 { return Err(ActuatorError::validation("permission's parent should be owner")); }
    let mut distinct = BTreeSet::new();
    let mut sum = 0_i64;
    for key in &permission.keys {
        if !distinct.insert(key.address.clone()) { return Err(ActuatorError::validation(format!("address should be distinct in permission {}", permission.r#type))); }
        if !valid_address(&key.address) { return Err(ActuatorError::validation("key is not a validate address")); }
        if key.weight <= 0 { return Err(ActuatorError::validation("key's weight should be greater than 0")); }
        sum = checked_add(sum, key.weight)?;
    }
    if sum < permission.threshold { return Err(ActuatorError::validation(format!("sum of all key's weight should not be less than threshold in permission {}", permission.r#type))); }
    if permission.r#type != PermissionType::Active as i32 {
        if !permission.operations.is_empty() { return Err(ActuatorError::validation(format!("{} permission needn't operations", permission.r#type))); }
    } else {
        if permission.operations.len() != 32 { return Err(ActuatorError::validation("operations size must 32")); }
        let available = context.dynamic_raw("AVAILABLE_CONTRACT_TYPE")?;
        if available.len() != 32 { return Err(ActuatorError::validation("available contract type size must 32")); }
        for bit in 0..256 { if permission.operations[bit / 8] & (1 << (bit % 8)) != 0 && available[bit / 8] & (1 << (bit % 8)) == 0 { return Err(ActuatorError::validation(format!("{bit} isn't a validate ContractType"))); } }
    }
    Ok(())
}
impl Actuator for AccountPermissionUpdateActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { if context.dynamic_long("ALLOW_MULTI_SIGN")? != 1 { return Err(ActuatorError::validation("multi sign is not allowed, need to be opened by the committee")); }
    if !valid_address(&self.contract.owner_address) { return Err(ActuatorError::validation("invalidate ownerAddress")); }
    let current = account(context, &self.contract.owner_address, "ownerAddress account does not exist")?;
    let owner = self.contract.owner.as_ref().ok_or_else(|| ActuatorError::validation("owner permission is missed"))?;
    if current.is_witness && self.contract.witness.is_none() { return Err(ActuatorError::validation("witness permission is missed")); }
    if !current.is_witness && self.contract.witness.is_some() { return Err(ActuatorError::validation("account isn't witness can't set witness permission")); }
    if self.contract.actives.is_empty() { return Err(ActuatorError::validation("active permission is missed")); }
    if self.contract.actives.len() > 8 { return Err(ActuatorError::validation("active permission is too many")); }
    if owner.r#type != PermissionType::Owner as i32 { return Err(ActuatorError::validation("owner permission type is error")); }
    check_permission(context, owner)?;
    if let Some(witness) = &self.contract.witness { if witness.r#type != PermissionType::Witness as i32 { return Err(ActuatorError::validation("witness permission type is error")); } check_permission(context, witness)?; }
    for active in &self.contract.actives { if active.r#type != PermissionType::Active as i32 { return Err(ActuatorError::validation("active permission type is error")); } check_permission(context, active)?; }
    let fee = context.dynamic_long("UPDATE_ACCOUNT_PERMISSION_FEE")?;
    if current.balance < fee { return Err(ActuatorError::validation("Validate AccountPermissionUpdateActuator error, insufficient fee.")); }
    Ok(()) }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let fee = context.dynamic_long("UPDATE_ACCOUNT_PERMISSION_FEE")?;
        let mut current = account(context, &self.contract.owner_address, "ownerAddress account does not exist")?;
        let mut owner = self.contract.owner.clone().ok_or_else(|| ActuatorError::execution("owner permission is missed"))?; owner.id = 0;
        current.owner_permission = Some(owner);
        current.witness_permission = self.contract.witness.clone().map(|mut permission| { permission.id = 1; permission });
        current.active_permission = self.contract.actives.iter().cloned().enumerate().map(|(index, mut permission)| { permission.id = i32::try_from(index).unwrap_or(i32::MAX) + 2; permission }).collect();
        charge_fee(context, &mut current, fee)?;
        store_account(context, &current)?;
        result.fee = checked_add(result.fee, fee)?;
        result.code = tron_protocol::protocol::transaction::result::Code::Sucess;
        Ok(())
    }
}
