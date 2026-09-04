use prost::Message;
use tron_protocol::{google::protobuf::Any, protocol::{account, transaction::result::Code, Account, AccountType, AssetIssueContract, ParticipateAssetIssueContract, TransferAssetContract, UnfreezeAssetContract, UpdateAssetContract}};
use tron_state::StoreKind;

use crate::{account::{charge_fee, default_active_permission, default_owner_permission}, context::{checked_add, checked_sub, decode_typed_any, valid_address}, Actuator, ExecutionContext, ActuatorError, ActuatorResult, ValidationContext};

const ASSET_ISSUE: &str = "protocol.AssetIssueContract";
const UPDATE_ASSET: &str = "protocol.UpdateAssetContract";
const TRANSFER_ASSET: &str = "protocol.TransferAssetContract";
const PARTICIPATE_ASSET: &str = "protocol.ParticipateAssetIssueContract";
const UNFREEZE_ASSET: &str = "protocol.UnfreezeAssetContract";
const FROZEN_PERIOD: i64 = 86_400_000;

fn account(context: &ExecutionContext<'_>, address: &[u8], missing: &'static str) -> Result<Account, ActuatorError> { context.decode(StoreKind::Account, address, missing) }
fn put_account(context: &mut ExecutionContext<'_>, value: &Account) -> Result<(), ActuatorError> { context.put_message(StoreKind::Account, &value.address, value) }
fn readable(value: &[u8], max: usize) -> bool { !value.is_empty() && value.len() <= max && value.iter().all(|byte| (0x21..=0x7e).contains(byte)) }
fn valid_url(value: &[u8]) -> bool { !value.is_empty() && value.len() <= 256 }
fn valid_description(value: &[u8]) -> bool { value.len() <= 200 }
fn same_name(context: &ExecutionContext<'_>) -> Result<bool, ActuatorError> { Ok(context.dynamic_long("ALLOW_SAME_TOKEN_NAME")? != 0) }
fn optimized(context: &ExecutionContext<'_>) -> Result<bool, ActuatorError> { Ok(context.dynamic_long("ALLOW_ACCOUNT_ASSET_OPTIMIZATION")? == 1) }
fn issue(context: &ExecutionContext<'_>, key: &[u8]) -> Result<AssetIssueContract, ActuatorError> {
    context.decode(if same_name(context)? { StoreKind::AssetIssueV2 } else { StoreKind::AssetIssue }, key, "No asset!")
}
fn asset_balance(context: &ExecutionContext<'_>, account: &Account, key: &[u8], _issue: &AssetIssueContract) -> Result<i64, ActuatorError> {
    if same_name(context)? { context.account_asset_balance(account, key) } else { Ok(*account.asset.get(core::str::from_utf8(key).unwrap_or("")).unwrap_or(&0)) }
}
fn set_asset_balance(context: &mut ExecutionContext<'_>, account: &mut Account, key: &[u8], issue: &AssetIssueContract, value: i64) -> Result<(), ActuatorError> {
    if same_name(context)? {
        context.set_account_asset_balance(account, key, value)
    } else {
        let name = core::str::from_utf8(key).map_err(|_| ActuatorError::execution("asset key is not UTF-8"))?.to_owned();
        let id = issue.id.clone();
        if value == 0 { account.asset.remove(&name); } else { account.asset.insert(name, value); }
        if account.asset_optimized {
            context.set_account_asset_balance(account, id.as_bytes(), value)
        } else {
            if value == 0 { account.asset_v2.remove(&id); } else { account.asset_v2.insert(id, value); }
            Ok(())
        }
    }
}
fn add_asset(context: &mut ExecutionContext<'_>, account: &mut Account, key: &[u8], issue: &AssetIssueContract, amount: i64) -> Result<(), ActuatorError> {
    let next = checked_add(asset_balance(context, account, key, issue)?, amount)?;
    set_asset_balance(context, account, key, issue, next)
}

pub struct AssetIssueActuator { any: Any, contract: AssetIssueContract }
impl AssetIssueActuator { pub fn new(any: Any) -> Result<Self, ActuatorError> { let contract = decode_typed_any(&any, ASSET_ISSUE)?; Ok(Self { any, contract }) } pub fn raw_any(&self) -> &Any { &self.any } }
impl Actuator for AssetIssueActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { let c = &self.contract;
    if !valid_address(&c.owner_address) { return Err(ActuatorError::validation("Invalid ownerAddress")); }
    if !readable(&c.name, 32) { return Err(ActuatorError::validation("Invalid assetName")); }
    if same_name(context)? && c.name.eq_ignore_ascii_case(b"trx") { return Err(ActuatorError::validation("assetName can't be trx")); }
    if same_name(context)? && c.precision != 0 && !(0..=6).contains(&c.precision) { return Err(ActuatorError::validation("precision cannot exceed 6")); }
    if !c.abbr.is_empty() && !readable(&c.abbr, 32) { return Err(ActuatorError::validation("Invalid abbreviation for token")); }
    if !valid_url(&c.url) { return Err(ActuatorError::validation("Invalid url")); }
    if !valid_description(&c.description) { return Err(ActuatorError::validation("Invalid description")); }
    if c.start_time == 0 { return Err(ActuatorError::validation("Start time should be not empty")); }
    if c.end_time == 0 { return Err(ActuatorError::validation("End time should be not empty")); }
    if c.end_time <= c.start_time { return Err(ActuatorError::validation("End time should be greater than start time")); }
    if c.start_time <= context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")? { return Err(ActuatorError::validation("Start time should be greater than HeadBlockTime")); }
    if !same_name(context)? && context.get(StoreKind::AssetIssue, &c.name)?.is_some() { return Err(ActuatorError::validation("Token exists")); }
    if c.total_supply <= 0 { return Err(ActuatorError::validation("TotalSupply must greater than 0!")); }
    if c.trx_num <= 0 { return Err(ActuatorError::validation("TrxNum must greater than 0!")); }
    if c.num <= 0 { return Err(ActuatorError::validation("Num must greater than 0!")); }
    if c.public_free_asset_net_usage != 0 { return Err(ActuatorError::validation("PublicFreeAssetNetUsage must be 0!")); }
    if c.frozen_supply.len() > usize::try_from(context.dynamic_int("MAX_FROZEN_SUPPLY_NUMBER")?).unwrap_or(0) { return Err(ActuatorError::validation("Frozen supply list length is too long")); }
    let day = context.dynamic_long("ONE_DAY_NET_LIMIT")?;
    if c.free_asset_net_limit < 0 || c.free_asset_net_limit >= day { return Err(ActuatorError::validation("Invalid FreeAssetNetLimit")); }
    if c.public_free_asset_net_limit < 0 || c.public_free_asset_net_limit >= day { return Err(ActuatorError::validation("Invalid PublicFreeAssetNetLimit")); }
    let min = i64::from(context.dynamic_int("MIN_FROZEN_SUPPLY_TIME")?);
    let max = i64::from(context.dynamic_int("MAX_FROZEN_SUPPLY_TIME")?);
    let mut remain = c.total_supply;
    for frozen in &c.frozen_supply {
        if frozen.frozen_amount <= 0 { return Err(ActuatorError::validation("Frozen supply must be greater than 0!")); }
        if frozen.frozen_amount > remain { return Err(ActuatorError::validation("Frozen supply cannot exceed total supply")); }
        if !(min..=max).contains(&frozen.frozen_days) { return Err(ActuatorError::validation(format!("frozenDuration must be less than {max} days and more than {min} days"))); }
        c.start_time.checked_add(frozen.frozen_days.checked_mul(FROZEN_PERIOD).ok_or_else(|| ActuatorError::arithmetic("long overflow"))?).ok_or_else(|| ActuatorError::validation("Start time and frozen days would cause expire time overflow"))?;
        remain = checked_sub(remain, frozen.frozen_amount)?;
    }
    let owner = account(context, &c.owner_address, "Account not exists")?;
    if !owner.asset_issued_name.is_empty() { return Err(ActuatorError::validation("An account can only issue one asset")); }
    if owner.balance < context.dynamic_long("ASSET_ISSUE_FEE")? { return Err(ActuatorError::validation("No enough balance for fee!")); }
    Ok(()) }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let fee = context.dynamic_long("ASSET_ISSUE_FEE")?;
        let token = checked_add(context.dynamic_long("TOKEN_ID_NUM")?, 1)?;
        let id = token.to_string();
        let mut legacy = self.contract.clone(); legacy.id.clone_from(&id);
        let mut v2 = legacy.clone();
        if !same_name(context)? { v2.precision = 0; context.put_message(StoreKind::AssetIssue, &legacy.name, &legacy)?; }
        context.put_message(StoreKind::AssetIssueV2, id.as_bytes(), &v2)?;
        context.put_dynamic_long("TOKEN_ID_NUM", token)?;
        let mut owner = account(context, &legacy.owner_address, "Account not exists")?;
        charge_fee(context, &mut owner, fee)?;
        let mut remain = legacy.total_supply;
        owner.frozen_supply.clear();
        for frozen in &legacy.frozen_supply {
            let period = frozen.frozen_days.checked_mul(FROZEN_PERIOD).ok_or_else(|| ActuatorError::arithmetic("long overflow"))?;
            owner.frozen_supply.push(account::Frozen { frozen_balance: frozen.frozen_amount, expire_time: legacy.start_time.checked_add(period).ok_or_else(|| ActuatorError::arithmetic("long overflow"))? });
            remain = checked_sub(remain, frozen.frozen_amount)?;
        }
        owner.asset_issued_name = legacy.name.clone(); owner.asset_issued_id = id.as_bytes().to_vec();
        if !same_name(context)? { owner.asset.insert(String::from_utf8_lossy(&legacy.name).into_owned(), remain); }
        if optimized(context)? { owner.asset_optimized = true; context.set_account_asset_balance(&mut owner, id.as_bytes(), remain)?; } else { owner.asset_v2.insert(id.clone(), remain); }
        put_account(context, &owner)?;
        result.asset_issue_id = id.into_bytes(); result.fee = checked_add(result.fee, fee)?; result.code = Code::Sucess;
        Ok(())
    }
}

pub struct UpdateAssetActuator { any: Any, contract: UpdateAssetContract }
impl UpdateAssetActuator { pub fn new(any: Any) -> Result<Self, ActuatorError> { let contract = decode_typed_any(&any, UPDATE_ASSET)?; Ok(Self { any, contract }) } pub fn raw_any(&self) -> &Any { &self.any } }
impl Actuator for UpdateAssetActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { if !valid_address(&self.contract.owner_address) { return Err(ActuatorError::validation("Invalid ownerAddress")); }
    let owner = account(context, &self.contract.owner_address, "Account does not exist")?;
    let key = if same_name(context)? { &owner.asset_issued_id } else { &owner.asset_issued_name };
    if key.is_empty() { return Err(ActuatorError::validation("Account has not issued any asset")); }
    if context.get(if same_name(context)? { StoreKind::AssetIssueV2 } else { StoreKind::AssetIssue }, key)?.is_none() { return Err(ActuatorError::validation(if same_name(context)? { "Asset is not existed in AssetIssueV2Store" } else { "Asset is not existed in AssetIssueStore" })); }
    if !valid_url(&self.contract.url) { return Err(ActuatorError::validation("Invalid url")); }
    if !valid_description(&self.contract.description) { return Err(ActuatorError::validation("Invalid description")); }
    let day = context.dynamic_long("ONE_DAY_NET_LIMIT")?;
    if self.contract.new_limit < 0 || self.contract.new_limit >= day { return Err(ActuatorError::validation("Invalid FreeAssetNetLimit")); }
    if self.contract.new_public_limit < 0 || self.contract.new_public_limit >= day { return Err(ActuatorError::validation("Invalid PublicFreeAssetNetLimit")); }
    Ok(()) }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let owner = account(context, &self.contract.owner_address, "Account does not exist")?;
        let mut v2: AssetIssueContract = context.decode(StoreKind::AssetIssueV2, &owner.asset_issued_id, "Asset is not existed in AssetIssueV2Store")?;
        v2.free_asset_net_limit = self.contract.new_limit; v2.public_free_asset_net_limit = self.contract.new_public_limit; v2.url.clone_from(&self.contract.url); v2.description.clone_from(&self.contract.description);
        context.put_message(StoreKind::AssetIssueV2, &owner.asset_issued_id, &v2)?;
        if !same_name(context)? { let mut legacy = v2.clone(); context.put_message(StoreKind::AssetIssue, &owner.asset_issued_name, &legacy)?; legacy.id.clear(); }
        result.code = Code::Sucess; Ok(())
    }
}

pub struct TransferAssetActuator { any: Any, contract: TransferAssetContract }
impl TransferAssetActuator { pub fn new(any: Any) -> Result<Self, ActuatorError> { let contract = decode_typed_any(&any, TRANSFER_ASSET)?; Ok(Self { any, contract }) } pub fn raw_any(&self) -> &Any { &self.any } fn fee(&self, context: &ExecutionContext<'_>) -> Result<i64, ActuatorError> { if context.get(StoreKind::Account, &self.contract.to_address)?.is_none() { context.dynamic_long("CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT") } else { Ok(0) } } }
impl Actuator for TransferAssetActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { if !valid_address(&self.contract.owner_address) { return Err(ActuatorError::validation("Invalid ownerAddress")); }
    if !valid_address(&self.contract.to_address) { return Err(ActuatorError::validation("Invalid toAddress")); }
    if self.contract.amount <= 0 { return Err(ActuatorError::validation("Amount must be greater than 0.")); }
    if self.contract.owner_address == self.contract.to_address { return Err(ActuatorError::validation("Cannot transfer asset to yourself.")); }
    let owner = account(context, &self.contract.owner_address, "No owner account!")?;
    let issue = issue(context, &self.contract.asset_name)?;
    let balance = asset_balance(context, &owner, &self.contract.asset_name, &issue)?;
    if balance <= 0 { return Err(ActuatorError::validation("assetBalance must be greater than 0.")); }
    if self.contract.amount > balance { return Err(ActuatorError::validation("assetBalance is not sufficient.")); }
    if let Some(bytes) = context.get(StoreKind::Account, &self.contract.to_address)? { let to = Account::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?; if to.r#type == AccountType::Contract as i32 && context.dynamic_long("FORBID_TRANSFER_TO_CONTRACT")? == 1 { return Err(ActuatorError::validation("Cannot transfer asset to smartContract.")); } checked_add(asset_balance(context, &to, &self.contract.asset_name, &issue)?, self.contract.amount)?; }
    Ok(()) }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let fee = self.fee(context)?; let issue = issue(context, &self.contract.asset_name)?;
        let mut owner = account(context, &self.contract.owner_address, "No owner account!")?;
        let mut to = if let Some(bytes) = context.get(StoreKind::Account, &self.contract.to_address)? {
            Account::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?
        } else {
            let mut account = Account { address: self.contract.to_address.clone(), r#type: AccountType::Normal as i32, create_time: context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?, ..Account::default() };
            if context.dynamic_long("ALLOW_MULTI_SIGN")? == 1 {
                account.owner_permission = Some(default_owner_permission(&account.address));
                account.active_permission.push(default_active_permission(&account.address, context.dynamic_raw("ACTIVE_DEFAULT_OPERATIONS")?));
            }
            account
        };
        let owner_next = checked_sub(asset_balance(context, &owner, &self.contract.asset_name, &issue)?, self.contract.amount)?;
        let to_next = checked_add(asset_balance(context, &to, &self.contract.asset_name, &issue)?, self.contract.amount)?;
        set_asset_balance(context, &mut owner, &self.contract.asset_name, &issue, owner_next)?; set_asset_balance(context, &mut to, &self.contract.asset_name, &issue, to_next)?;
        if fee != 0 { charge_fee(context, &mut owner, fee)?; }
        put_account(context, &owner)?; put_account(context, &to)?; result.fee = checked_add(result.fee, fee)?; result.code = Code::Sucess; Ok(())
    }
}

pub struct ParticipateAssetIssueActuator { any: Any, contract: ParticipateAssetIssueContract }
impl ParticipateAssetIssueActuator { pub fn new(any: Any) -> Result<Self, ActuatorError> { let contract = decode_typed_any(&any, PARTICIPATE_ASSET)?; Ok(Self { any, contract }) } pub fn raw_any(&self) -> &Any { &self.any } }
impl Actuator for ParticipateAssetIssueActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { let c=&self.contract; if !valid_address(&c.owner_address) { return Err(ActuatorError::validation("Invalid ownerAddress")); } if !valid_address(&c.to_address) { return Err(ActuatorError::validation("Invalid toAddress")); } if c.amount<=0{return Err(ActuatorError::validation("Amount must greater than 0!"));} if c.owner_address==c.to_address{return Err(ActuatorError::validation("Cannot participate asset Issue yourself !"));}
    let owner=account(context,&c.owner_address,"Account does not exist!")?; if owner.balance<c.amount{return Err(ActuatorError::validation("No enough balance !"));} let issue=issue(context,&c.asset_name)?; if issue.owner_address!=c.to_address{return Err(ActuatorError::validation("The asset is not issued by toAddress"));} let now=context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?; if now>=issue.end_time||now<issue.start_time{return Err(ActuatorError::validation("No longer valid period!"));}
    let exchange=c.amount.checked_mul(i64::from(issue.num)).ok_or_else(||ActuatorError::arithmetic("long overflow"))?.div_euclid(i64::from(issue.trx_num)); if exchange<=0{return Err(ActuatorError::validation("Can not process the exchange!"));} let issuer=account(context,&c.to_address,"To account does not exist!")?; if asset_balance(context,&issuer,&c.asset_name,&issue)?<exchange{return Err(ActuatorError::validation("Asset balance is not enough !"));} Ok(()) }
    fn execute_in(&self, context:&mut ExecutionContext<'_>, result:&mut ActuatorResult)->Result<(),ActuatorError>{let c=&self.contract;let issue=issue(context,&c.asset_name)?;let exchange=c.amount.checked_mul(i64::from(issue.num)).ok_or_else(||ActuatorError::arithmetic("long overflow"))?.div_euclid(i64::from(issue.trx_num));let mut owner=account(context,&c.owner_address,"Account does not exist!")?;let mut issuer=account(context,&c.to_address,"To account does not exist!")?;owner.balance=checked_sub(owner.balance,c.amount)?;issuer.balance=checked_add(issuer.balance,c.amount)?;add_asset(context,&mut owner,&c.asset_name,&issue,exchange)?;let next=checked_sub(asset_balance(context,&issuer,&c.asset_name,&issue)?,exchange)?;set_asset_balance(context,&mut issuer,&c.asset_name,&issue,next)?;put_account(context,&owner)?;put_account(context,&issuer)?;result.code=Code::Sucess;Ok(())}
}

pub struct UnfreezeAssetActuator { any: Any, contract: UnfreezeAssetContract }
impl UnfreezeAssetActuator { pub fn new(any: Any)->Result<Self,ActuatorError>{let contract=decode_typed_any(&any,UNFREEZE_ASSET)?;Ok(Self{any,contract})} pub fn raw_any(&self)->&Any{&self.any} }
impl Actuator for UnfreezeAssetActuator {
 fn owner_address(&self)->Result<&[u8],ActuatorError>{Ok(&self.contract.owner_address)}
 fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { if !valid_address(&self.contract.owner_address){return Err(ActuatorError::validation("Invalid address"));}let owner=account(context,&self.contract.owner_address,"Account does not exist")?;if owner.frozen_supply.is_empty(){return Err(ActuatorError::validation("no frozen supply balance"));}if (same_name(context)?&&owner.asset_issued_id.is_empty())||(!same_name(context)?&&owner.asset_issued_name.is_empty()){return Err(ActuatorError::validation("this account has not issued any asset"));}let now=context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;if !owner.frozen_supply.iter().any(|f|f.expire_time<=now){return Err(ActuatorError::validation("It's not time to unfreeze asset supply"));}Ok(()) }
 fn execute_in(&self,context:&mut ExecutionContext<'_>,result:&mut ActuatorResult)->Result<(),ActuatorError>{let mut owner=account(context,&self.contract.owner_address,"Account does not exist")?;let now=context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;let mut amount=0_i64;let mut retained=Vec::with_capacity(owner.frozen_supply.len());for frozen in owner.frozen_supply.drain(..){if frozen.expire_time<=now{amount=checked_add(amount,frozen.frozen_balance)?;}else{retained.push(frozen);}}owner.frozen_supply=retained;let key=if same_name(context)?{owner.asset_issued_id.clone()}else{owner.asset_issued_name.clone()};let issue=issue(context,&key)?;add_asset(context,&mut owner,&key,&issue,amount)?;put_account(context,&owner)?;result.code=Code::Sucess;Ok(())}
}
