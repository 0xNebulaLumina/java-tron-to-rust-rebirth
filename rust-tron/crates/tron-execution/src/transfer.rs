use prost::Message;
use tron_protocol::{google::protobuf::Any, protocol::{Account, AccountType, SmartContract, TransferContract}};
use tron_state::StoreKind;

use crate::{account::{charge_fee, default_active_permission, default_owner_permission}, Actuator, ExecutionContext, ActuatorError, ActuatorResult, ValidationContext};
use crate::context::{checked_add, checked_sub, decode_typed_any, valid_address};

const TRANSFER: &str = "protocol.TransferContract";
pub const TRANSFER_FEE: i64 = 0;

pub struct TransferActuator { any: Any, contract: TransferContract }
impl TransferActuator {
    pub fn new(any: Any) -> Result<Self, ActuatorError> { let contract = decode_typed_any(&any, TRANSFER)?; Ok(Self { any, contract }) }
    pub fn raw_any(&self) -> &Any { &self.any }
    fn fee(&self, context: &ExecutionContext<'_>) -> Result<i64, ActuatorError> {
        if context.get(StoreKind::Account, &self.contract.to_address)?.is_none() { checked_add(TRANSFER_FEE, context.dynamic_long("CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT")?) } else { Ok(TRANSFER_FEE) }
    }
}
impl Actuator for TransferActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.contract.owner_address) }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { if !valid_address(&self.contract.owner_address) { return Err(ActuatorError::validation("Invalid ownerAddress!")); }
    if !valid_address(&self.contract.to_address) { return Err(ActuatorError::validation("Invalid toAddress!")); }
    if self.contract.owner_address == self.contract.to_address { return Err(ActuatorError::validation("Cannot transfer TRX to yourself.")); }
    let owner: Account = context.decode(StoreKind::Account, &self.contract.owner_address, "Validate TransferContract error, no OwnerAccount.")?;
    if self.contract.amount <= 0 { return Err(ActuatorError::validation("Amount must be greater than 0.")); }
    let recipient = context.get(StoreKind::Account, &self.contract.to_address)?.map(|bytes| Account::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))).transpose()?;
    if let Some(recipient) = &recipient {
        if recipient.r#type == AccountType::Contract as i32 && context.dynamic_long("FORBID_TRANSFER_TO_CONTRACT")? == 1 { return Err(ActuatorError::validation("Cannot transfer TRX to a smartContract.")); }
        if recipient.r#type == AccountType::Contract as i32 && context.dynamic_long("ALLOW_TVM_COMPATIBLE_EVM")? == 1 {
            let contract: SmartContract = context.decode(StoreKind::Contract, &self.contract.to_address, "Account type is Contract, but it is not exist in contract store.")?;
            if contract.version == 1 { return Err(ActuatorError::validation("Cannot transfer TRX to a smartContract which version is one. Instead please use TriggerSmartContract ")); }
        }
        checked_add(recipient.balance, self.contract.amount)?;
    }
    let total = checked_add(self.contract.amount, self.fee(context)?)?;
    if owner.balance < total { return Err(ActuatorError::validation("Validate TransferContract error, balance is not sufficient.")); }
    Ok(()) }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        let fee = self.fee(context)?;
        let mut owner: Account = context.decode(StoreKind::Account, &self.contract.owner_address, "Validate TransferContract error, no OwnerAccount.")?;
        let mut recipient = if let Some(bytes) = context.get(StoreKind::Account, &self.contract.to_address)? {
            Account::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))?
        } else {
            let mut created = Account { address: self.contract.to_address.clone(), r#type: AccountType::Normal as i32, create_time: context.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?, ..Account::default() };
            if context.dynamic_long("ALLOW_MULTI_SIGN")? == 1 {
                created.owner_permission = Some(default_owner_permission(&created.address));
                created.active_permission.push(default_active_permission(&created.address, context.dynamic_raw("ACTIVE_DEFAULT_OPERATIONS")?));
            }
            created
        };
        owner.balance = checked_sub(owner.balance, self.contract.amount)?;
        recipient.balance = checked_add(recipient.balance, self.contract.amount)?;
        context.put_message(StoreKind::Account, &recipient.address, &recipient)?;
        if fee != 0 { charge_fee(context, &mut owner, fee)?; }
        context.put_message(StoreKind::Account, &owner.address, &owner)?;
        result.fee = checked_add(result.fee, fee)?;
        result.code = tron_protocol::protocol::transaction::result::Code::Sucess;
        Ok(())
    }
}
