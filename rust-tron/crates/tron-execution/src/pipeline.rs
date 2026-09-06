use prost::Message;
use tron_primitives::Hash32;
use tron_protocol::protocol::{permission::PermissionType, transaction::{contract::ContractType, Result as TransactionResult}, Account, CreateSmartContract, Permission, SmartContract, Transaction, TransactionInfo, TransferAssetContract, TransferContract, TriggerSmartContract};
use tron_state::{dynamic, GlobalResource, ResourceWindow, Session, SessionError, SessionManager, StoreKind, global_limit};
use tron_tvm::{ContractResult, OperationRegistry};

use crate::{charge_metadata_fees, consume_bandwidth, default_active_permission, default_owner_permission, receipt::EnergyExecutionPlan, unsigned_create_account_size, ActuatorRegistry, ActuatorResult, AdmissionClock, AdmissionError, AdmissionOrigin, AdmissionPolicy, AdmissionValidator, BandwidthAccount, BandwidthPolicy, BillingTotals, EnergyAccount, EnergyBillingPolicy, EnergyOrigin, ExecutionConfig, PublicBandwidth, RawWireTransaction, Runtime, RuntimeKind, SignatureAdmission, TraceKind, TransactionCache, TransactionTrace};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineStage { Admission, Duplicate, Trace, Runtime, Retry, Witness, Billing, Finalization, PersistTransaction, PersistInfo, PersistCache }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessError {
    Duplicate(Hash32),
    Stage { stage: PipelineStage, message: String },
    State(String),
}
impl core::fmt::Display for ProcessError { fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "{self:?}") } }
impl std::error::Error for ProcessError {}
impl From<SessionError> for ProcessError { fn from(value: SessionError) -> Self { Self::State(value.to_string()) } }

#[derive(Clone, Debug)]
pub struct ProcessContext {
    pub origin: AdmissionOrigin,
    pub clock: AdmissionClock,
    pub expected_result: Option<ContractResult>,
    pub block_timestamp: i64,
}
#[derive(Clone, Debug)]
pub struct ProcessOutput {
    pub transaction_id: Hash32,
    pub transaction: Transaction,
    pub info: TransactionInfo,
    pub retried: bool,
}

/// The production transaction path. It owns all execution registries and resolves
/// authorization exclusively from the same C009 session used for execution.
pub struct StateTransactionPipeline {
    pub admission_policy: AdmissionPolicy,
    pub actuator_registry: ActuatorRegistry,
    pub operation_registry: OperationRegistry,
    pub execution_config: ExecutionConfig,
    pub bandwidth_policy: BandwidthPolicy,
    pub energy_billing_policy: EnergyBillingPolicy,
}
impl StateTransactionPipeline {
    pub fn new(admission_policy: AdmissionPolicy, actuator_registry: ActuatorRegistry, execution_config: ExecutionConfig) -> Result<Self, String> {
        let mut energy_billing_policy = EnergyBillingPolicy::default();
        // Networks supply the live price through dynamic properties; zero is the
        // safe embedded default for callers that have not installed that policy.
        energy_billing_policy.energy_price = 0;
        energy_billing_policy.allow_constantinople = true;
        Ok(Self { admission_policy, actuator_registry, operation_registry: OperationRegistry::integration().map_err(|error| format!("{error:?}"))?, execution_config, bandwidth_policy: BandwidthPolicy::default(), energy_billing_policy })
    }

    fn authorization(&self, tx: &RawWireTransaction, session: &Session) -> Result<(Option<Permission>, bool), AdmissionError> {
        let contract = tx.message().raw_data.as_ref().and_then(|raw| raw.contract.first()).ok_or(AdmissionError::MissingContract)?;
        let owner = self.actuator_registry.owner_address(contract).map_err(|error| AdmissionError::MalformedTransaction(format!("{error:?}")))?;
        let shielded = ContractType::try_from(contract.r#type).ok() == Some(ContractType::ShieldedTransferContract);
        let ownerless_shielded = shielded && owner.is_empty();
        if ownerless_shielded {
            let enabled = ["ALLOW_SHIELDED_TRANSACTION", "ALLOW_SHIELDED_TRC20_TRANSACTION"].into_iter().any(|name| dynamic::key(name).and_then(|key| session.store(StoreKind::DynamicProperties).get(key)).is_some_and(|bytes| bytes.as_slice() == 1_i64.to_be_bytes()));
            if !enabled { return Err(AdmissionError::PermissionDenied); }
            return Ok((None, true));
        }
        let bytes = session.store(StoreKind::Account).get(&owner).ok_or(AdmissionError::PermissionMissing { permission_id: contract.permission_id })?;
        let account = Account::decode(bytes.as_slice()).map_err(|error| AdmissionError::MalformedTransaction(error.to_string()))?;
        let permission = match contract.permission_id {
            0 => account.owner_permission.unwrap_or_else(|| default_owner_permission(&owner)),
            2 if account.active_permission.is_empty() => {
                let key=dynamic::key("ACTIVE_DEFAULT_OPERATIONS").ok_or_else(||AdmissionError::MalformedTransaction("ACTIVE_DEFAULT_OPERATIONS is unknown".into()))?;
                let operations=session.store(StoreKind::DynamicProperties).get(key).ok_or(AdmissionError::PermissionMissing{permission_id:2})?;
                default_active_permission(&owner,operations)
            }
            id => account.active_permission.into_iter().find(|permission| permission.id == id).ok_or(AdmissionError::PermissionMissing { permission_id: id })?,
        };
        if contract.permission_id == 0 && permission.r#type != PermissionType::Owner as i32 { return Err(AdmissionError::PermissionType); }
        Ok((Some(permission), false))
    }

    fn admit(&self, tx: &mut RawWireTransaction, session: &Session, context: &ProcessContext) -> Result<Hash32, ProcessError> {
        let (permission, ownerless_shielded) = self.authorization(tx, session).map_err(|error| stage(PipelineStage::Admission, error.to_string()))?;
        AdmissionValidator { policy: self.admission_policy }.validate(
            tx,
            context.origin,
            context.clock,
            SignatureAdmission { permission: permission.as_ref(), default_owner: None, default_active_operations: None, ownerless_shielded },
            |key| session.store(StoreKind::RecentBlock).get(key),
        ).map_err(|error| stage(PipelineStage::Admission, error.to_string()))
    }
    fn dynamic_long(session: &Session, name: &str) -> Result<i64, ProcessError> {
        let key = dynamic::key(name).ok_or_else(|| stage(PipelineStage::Billing, format!("unknown dynamic property {name}")))?;
        let bytes = session.store(StoreKind::DynamicProperties).get(key).ok_or_else(|| stage(PipelineStage::Billing, format!("missing dynamic property {name}")))?;
        bytes.as_slice().try_into().map(i64::from_be_bytes).map_err(|_| stage(PipelineStage::Billing, format!("invalid dynamic property {name}")))
    }

    fn put_dynamic_long(session: &Session, name: &str, value: i64) -> Result<(), ProcessError> {
        let key = dynamic::key(name).ok_or_else(|| stage(PipelineStage::Billing, format!("unknown dynamic property {name}")))?;
        session.store(StoreKind::DynamicProperties).put(key, &value.to_be_bytes()).map_err(|error| stage(PipelineStage::Billing, error.to_string()))
    }

    fn optional_dynamic_long(session: &Session, name: &str) -> Result<Option<i64>, ProcessError> {
        let key=dynamic::key(name).ok_or_else(||stage(PipelineStage::Runtime,format!("unknown dynamic property {name}")))?;
        session.store(StoreKind::DynamicProperties).get(key).map(|bytes|bytes.as_slice().try_into().map(i64::from_be_bytes).map_err(|_|stage(PipelineStage::Runtime,format!("invalid dynamic property {name}")))).transpose()
    }

    fn bandwidth_policy(&self, session: &Session) -> Result<BandwidthPolicy, ProcessError> {
        Ok(BandwidthPolicy {
            total_net_limit: Self::dynamic_long(session, "TOTAL_NET_LIMIT")?,
            total_net_weight: Self::dynamic_long(session, "TOTAL_NET_WEIGHT")?,
            free_net_limit: Self::dynamic_long(session, "FREE_NET_LIMIT")?,
            public_net_limit: Self::dynamic_long(session, "PUBLIC_NET_LIMIT")?,
            transaction_fee: Self::dynamic_long(session, "TRANSACTION_FEE")?,
            create_account_fee: Self::dynamic_long(session, "CREATE_ACCOUNT_FEE")?,
            create_account_bandwidth_rate: Self::dynamic_long(session, "CREATE_NEW_ACCOUNT_BANDWIDTH_RATE")?,
            max_create_account_tx_size: Self::dynamic_long(session, "MAX_CREATE_ACCOUNT_TX_SIZE")?,
            multi_sign_fee: Self::dynamic_long(session, "MULTI_SIGN_FEE")?,
            memo_fee: Self::dynamic_long(session, "MEMO_FEE")?,
            support_unfreeze_delay: Self::dynamic_long(session, "UNFREEZE_DELAY_DAYS")? > 0,
            harden_calculation: Self::dynamic_long(session, "ALLOW_HARDEN_RESOURCE_CALCULATION")? == 1,
        })
    }

    fn energy_policy(&self, session: &Session) -> Result<EnergyBillingPolicy, ProcessError> {
        let dynamic_price = Self::dynamic_long(session, "ENERGY_FEE")?;
        Ok(EnergyBillingPolicy {
            energy_price: if dynamic_price > 0 { dynamic_price } else { 100 },
            allow_constantinople: Self::dynamic_long(session, "ALLOW_TVM_CONSTANTINOPLE")? == 1,
            transaction_fee_pool: Self::dynamic_long(session, "ALLOW_TRANSACTION_FEE_POOL")? == 1,
            blackhole_optimization: Self::dynamic_long(session, "ALLOW_BLACKHOLE_OPTIMIZATION")? == 1,
            adaptive_energy: Self::dynamic_long(session, "ALLOW_ADAPTIVE_ENERGY")? == 1,
        })
    }

    fn owner_address(&self, tx: &RawWireTransaction) -> Result<Vec<u8>, ProcessError> {
        let contract = tx.message().raw_data.as_ref().and_then(|raw| raw.contract.first()).ok_or_else(|| stage(PipelineStage::Billing, "missing contract".into()))?;
        self.actuator_registry.owner_address(contract).map_err(|error| stage(PipelineStage::Billing, format!("{error:?}")))
    }

    fn creates_account(&self, tx: &RawWireTransaction, session: &Session) -> Result<bool, ProcessError> {
        let contract=tx.message().raw_data.as_ref().and_then(|raw|raw.contract.first()).ok_or_else(||stage(PipelineStage::Billing,"missing contract".into()))?;
        let destination=match ContractType::try_from(contract.r#type).ok(){Some(ContractType::AccountCreateContract)=>return Ok(true),Some(ContractType::TransferContract)=>contract.parameter.as_ref().and_then(|value|TransferContract::decode(value.value.as_slice()).ok()).map(|value|value.to_address),Some(ContractType::TransferAssetContract)=>contract.parameter.as_ref().and_then(|value|TransferAssetContract::decode(value.value.as_slice()).ok()).map(|value|value.to_address),_=>None};
        Ok(destination.is_some_and(|address|session.store(StoreKind::Account).get(&address).is_none()))
    }

    fn consume_bandwidth(&self, tx: &RawWireTransaction, session: &Session, context: &ProcessContext, trace: &mut TransactionTrace) -> Result<(), ProcessError> {
        let contract=tx.message().raw_data.as_ref().and_then(|raw|raw.contract.first()).ok_or_else(||stage(PipelineStage::Billing,"missing contract".into()))?;
        if ContractType::try_from(contract.r#type).ok()==Some(ContractType::ShieldedTransferContract){return Ok(())}
        let owner = self.owner_address(tx)?;
        if owner.is_empty() { return Ok(()); }
        let bytes = session.store(StoreKind::Account).get(&owner).ok_or_else(|| stage(PipelineStage::Billing, "bandwidth owner account is missing".into()))?;
        let mut account = Account::decode(bytes.as_slice()).map_err(|error| stage(PipelineStage::Billing, error.to_string()))?;
        let own_legacy=account.frozen.iter().try_fold(0_i64,|sum,item|sum.checked_add(item.frozen_balance)).ok_or_else(||stage(PipelineStage::Billing,"bandwidth overflow".into()))?;
        let own_v2=account.frozen_v2.iter().filter(|item|item.r#type==0).try_fold(0_i64,|sum,item|sum.checked_add(item.amount)).ok_or_else(||stage(PipelineStage::Billing,"bandwidth overflow".into()))?;
        let frozen_bandwidth=[own_legacy,account.acquired_delegated_frozen_balance_for_bandwidth,own_v2,account.acquired_delegated_frozen_v2_balance_for_bandwidth].into_iter().try_fold(0_i64,|sum,value|sum.checked_add(value)).ok_or_else(||stage(PipelineStage::Billing,"bandwidth overflow".into()))?;
        let mut bandwidth = BandwidthAccount { address: owner.clone(), balance: account.balance, frozen_bandwidth, net_usage: account.net_usage, free_net_usage: account.free_net_usage, latest_consume_time: account.latest_consume_time, latest_consume_free_time: account.latest_consume_free_time, latest_operation_time: account.latest_opration_time,net_window:account.net_window_size,net_window_optimized:account.net_window_optimized };
        let mut public = PublicBandwidth { usage: Self::dynamic_long(session, "PUBLIC_NET_USAGE")?, latest_time: Self::dynamic_long(session, "PUBLIC_NET_TIME")? };
        let policy = self.bandwidth_policy(session)?;
        let raw = tx.message().raw_data.as_ref().expect("admission checked raw_data");
        let support_vm=dynamic::key("ALLOW_CREATION_OF_CONTRACTS").and_then(|key|session.store(StoreKind::DynamicProperties).get(key)).is_some_and(|bytes|bytes.as_slice()==1_i64.to_be_bytes());
        let mut charged_size=if support_vm{tx.bytes_without_results().len()}else{tx.full_bytes().len()};
        if support_vm{charged_size=charged_size.checked_add(64).ok_or_else(||stage(PipelineStage::Billing,"bandwidth size overflow".into()))?;}
        let create_account=self.creates_account(tx,session)?;
        let unsigned_size=unsigned_create_account_size(i64::try_from(tx.bytes_without_results().len()).map_err(|_|stage(PipelineStage::Billing,"bandwidth size overflow".into()))?,tx.message().signature.len()).map_err(|error|stage(PipelineStage::Billing,error.to_string()))?;
        let charge = consume_bandwidth(&mut bandwidth, &mut public, i64::try_from(charged_size).map_err(|_|stage(PipelineStage::Billing,"bandwidth size overflow".into()))?, context.clock.head_slot, raw.timestamp, create_account, unsigned_size, policy).map_err(|error| stage(PipelineStage::Billing, error.to_string()))?;
        let (multi, memo) = charge_metadata_fees(&mut bandwidth, tx.message().signature.len(), !raw.data.is_empty(), policy).map_err(|error| stage(PipelineStage::Billing, error.to_string()))?;
        let metadata_fees=multi.checked_add(memo).ok_or_else(||stage(PipelineStage::Billing,"bandwidth fee overflow".into()))?;
        if charge.net_fee != 0 { self.route_fees(session, charge.net_fee, matches!(charge.source,crate::BandwidthSource::CreateAccountFee))?; }
        if metadata_fees != 0 { self.route_fees(session, metadata_fees, false)?; }
        account.balance = bandwidth.balance; account.net_usage = bandwidth.net_usage; account.free_net_usage = bandwidth.free_net_usage; account.latest_consume_time = bandwidth.latest_consume_time; account.latest_consume_free_time = bandwidth.latest_consume_free_time; account.latest_opration_time = bandwidth.latest_operation_time;account.net_window_size=bandwidth.net_window;account.net_window_optimized=bandwidth.net_window_optimized;
        session.store(StoreKind::Account).put(&owner, &account.encode_to_vec()).map_err(|error| stage(PipelineStage::Billing, error.to_string()))?;
        Self::put_dynamic_long(session, "PUBLIC_NET_USAGE", public.usage)?;
        Self::put_dynamic_long(session, "PUBLIC_NET_TIME", public.latest_time)?;
        trace.receipt.set_net_bill(charge.net_usage, charge.net_fee); trace.receipt.multi_sign_fee = multi; trace.receipt.memo_fee = memo; trace.net_fee_for_bandwidth = charge.net_fee_for_bandwidth;
        Ok(())
    }
    fn route_fees(&self, session: &Session, fee: i64, create_account: bool) -> Result<(), ProcessError> {
        let metric=if create_account{"TOTAL_CREATE_ACCOUNT_COST"}else{"TOTAL_TRANSACTION_COST"};
        let total = Self::dynamic_long(session, metric)?.checked_add(fee).ok_or_else(|| stage(PipelineStage::Billing, "transaction cost overflow".into()))?;
        Self::put_dynamic_long(session, metric, total)?;
        if Self::dynamic_long(session, "ALLOW_TRANSACTION_FEE_POOL")? == 1 {
            let pool = Self::dynamic_long(session, "TRANSACTION_FEE_POOL")?.checked_add(fee).ok_or_else(|| stage(PipelineStage::Billing, "fee pool overflow".into()))?;
            return Self::put_dynamic_long(session, "TRANSACTION_FEE_POOL", pool);
        }
        if Self::dynamic_long(session, "ALLOW_BLACKHOLE_OPTIMIZATION")? == 1 {
            let burned = Self::dynamic_long(session, "BURN_TRX_AMOUNT")?.checked_add(fee).ok_or_else(|| stage(PipelineStage::Billing, "burn total overflow".into()))?;
            return Self::put_dynamic_long(session, "BURN_TRX_AMOUNT", burned);
        }
        let address = &self.execution_config.blackhole_address;
        let bytes = session.store(StoreKind::Account).get(address).ok_or_else(|| stage(PipelineStage::Billing, "blackhole account is missing".into()))?;
        let mut account = Account::decode(bytes.as_slice()).map_err(|error| stage(PipelineStage::Billing, error.to_string()))?;
        account.balance = account.balance.checked_add(fee).ok_or_else(|| stage(PipelineStage::Billing, "blackhole balance overflow".into()))?;
        session.store(StoreKind::Account).put(address, &account.encode_to_vec()).map_err(|error| stage(PipelineStage::Billing, error.to_string()))
    }


    fn energy_account(&self, session:&Session, account:&Account, address:Vec<u8>, head_slot:i64)->Result<EnergyAccount,ProcessError>{
        let resource=account.account_resource.as_ref().cloned().unwrap_or_default();
        let own_v2=account.frozen_v2.iter().filter(|value|value.r#type==1).try_fold(0_i64,|sum,value|sum.checked_add(value.amount)).ok_or_else(||stage(PipelineStage::Runtime,"frozen energy overflow".into()))?;
        let frozen=resource.frozen_balance_for_energy.as_ref().map_or(0,|value|value.frozen_balance).checked_add(resource.acquired_delegated_frozen_balance_for_energy).and_then(|value|value.checked_add(own_v2)).and_then(|value|value.checked_add(resource.acquired_delegated_frozen_v2_balance_for_energy)).ok_or_else(||stage(PipelineStage::Runtime,"frozen energy overflow".into()))?;
        let global=GlobalResource{limit:Self::dynamic_long(session,"TOTAL_ENERGY_CURRENT_LIMIT")?,weight:Self::dynamic_long(session,"TOTAL_ENERGY_WEIGHT")?};
        let v2=Self::dynamic_long(session,"UNFREEZE_DELAY_DAYS")?>0;
        let hardened=Self::dynamic_long(session,"ALLOW_HARDEN_RESOURCE_CALCULATION")?==1;
        let limit=if global.weight<=0||global.limit<=0||frozen<=0{0}else if hardened{global_limit(frozen,global,v2).map_err(|error|stage(PipelineStage::Runtime,error.to_string()))?}else{let weight=if v2{frozen as f64/1_000_000f64}else{(frozen/1_000_000)as f64};(weight*(global.limit as f64/global.weight as f64))as i64};
        let window=ResourceWindow{usage:resource.energy_usage,latest_slot:resource.latest_consume_time_for_energy,window:resource.energy_window_size,precise:resource.energy_window_optimized,standard_window:28_800};
        let recovered=window.recover(head_slot).map_err(|error|stage(PipelineStage::Runtime,error.to_string()))?;
        Ok(EnergyAccount{address,balance:account.balance,frozen_energy_left:limit.checked_sub(recovered).unwrap_or(0).max(0),energy_usage:resource.energy_usage,latest_consume_slot:resource.latest_consume_time_for_energy,energy_window:resource.energy_window_size,energy_window_optimized:resource.energy_window_optimized,head_slot})
    }

    fn energy_execution_plan(&self,tx:&RawWireTransaction,session:&Session,context:&ProcessContext)->Result<EnergyExecutionPlan,ProcessError>{
        let raw=tx.message().raw_data.as_ref().ok_or_else(||stage(PipelineStage::Runtime,"missing raw data".into()))?;
        let envelope=raw.contract.first().ok_or_else(||stage(PipelineStage::Runtime,"missing contract".into()))?;
        let max_fee=Self::optional_dynamic_long(session,"MAX_FEE_LIMIT")?.unwrap_or(1_000_000_000);
        if raw.fee_limit<0||max_fee<0||raw.fee_limit>max_fee{return Err(stage(PipelineStage::Runtime,"fee_limit out of range".into()))}
        let caller_address=self.owner_address(tx)?;
        let caller_bytes=session.store(StoreKind::Account).get(&caller_address).ok_or_else(||stage(PipelineStage::Runtime,"energy caller account is missing".into()))?;
        let caller_account=Account::decode(caller_bytes.as_slice()).map_err(|error|stage(PipelineStage::Runtime,error.to_string()))?;
        let caller=self.energy_account(session,&caller_account,caller_address.clone(),context.clock.head_slot)?;
        let (call_value,smart_contract,create_same_origin)=match ContractType::try_from(envelope.r#type).ok(){Some(ContractType::TriggerSmartContract)=>{let trigger=envelope.parameter.as_ref().and_then(|value|TriggerSmartContract::decode(value.value.as_slice()).ok()).ok_or_else(||stage(PipelineStage::Runtime,"invalid trigger contract".into()))?;let metadata=session.store(StoreKind::Contract).get(&trigger.contract_address).map(|bytes|SmartContract::decode(bytes.as_slice()).map_err(|error|stage(PipelineStage::Runtime,error.to_string()))).transpose()?;(trigger.call_value,metadata,false)},Some(ContractType::CreateSmartContract)=>{let create=envelope.parameter.as_ref().and_then(|value|CreateSmartContract::decode(value.value.as_slice()).ok()).ok_or_else(||stage(PipelineStage::Runtime,"invalid create contract".into()))?;(create.new_contract.as_ref().map_or(0,|contract|contract.call_value),None,true)},_=>(0,None,false)};
        if call_value<0||caller.balance<call_value{return Err(stage(PipelineStage::Runtime,"call value exceeds caller balance".into()))}
        let policy=self.energy_policy(session)?;
        let liquid=caller.balance.checked_sub(call_value).ok_or_else(||stage(PipelineStage::Runtime,"call value overflow".into()))?;
        let affordable_paid=liquid/policy.energy_price;
        let fee_cap=raw.fee_limit/policy.energy_price;
        let caller_limit=caller.frozen_energy_left.checked_add(affordable_paid).ok_or_else(||stage(PipelineStage::Runtime,"caller energy overflow".into()))?.min(fee_cap);
        let caller_paid_energy_limit=caller_limit.checked_sub(caller.frozen_energy_left.min(caller_limit)).ok_or_else(||stage(PipelineStage::Runtime,"caller paid energy overflow".into()))?;
        let origin_percent=smart_contract.as_ref().map_or(0,|contract|100_i64.saturating_sub(contract.consume_user_resource_percent)).clamp(0,100);
        let origin_energy_limit=smart_contract.as_ref().map_or(0,|contract|contract.origin_energy_limit.max(0));
        let origin=if create_same_origin{EnergyOrigin::SameAsCaller}else{match smart_contract.as_ref(){
            None=>EnergyOrigin::Absent,
            Some(contract) if contract.origin_address==caller_address=>EnergyOrigin::SameAsCaller,
            Some(contract)=>{let bytes=session.store(StoreKind::Account).get(&contract.origin_address).ok_or_else(||stage(PipelineStage::Runtime,"origin account is missing".into()))?;let account=Account::decode(bytes.as_slice()).map_err(|error|stage(PipelineStage::Runtime,error.to_string()))?;EnergyOrigin::Distinct(self.energy_account(session,&account,contract.origin_address.clone(),context.clock.head_slot)?)},
        }};
        let origin_available=match &origin{EnergyOrigin::Distinct(account)=>account.frozen_energy_left.min(origin_energy_limit),EnergyOrigin::Absent|EnergyOrigin::SameAsCaller=>0};
        let creator_share=if origin_percent==0{0}else if origin_percent==100{origin_available}else{caller_limit.checked_mul(origin_percent).ok_or_else(||stage(PipelineStage::Runtime,"origin energy overflow".into()))?/(100-origin_percent)}.min(origin_available);
        let energy_limit=caller_limit.checked_add(creator_share).ok_or_else(||stage(PipelineStage::Runtime,"energy limit overflow".into()))?;
        Ok(EnergyExecutionPlan{caller,origin,origin_percent,origin_energy_limit,caller_paid_energy_limit,energy_limit,policy})
    }

    fn pay_energy(&self,session:&Session,trace:&mut TransactionTrace,context:&ProcessContext,plan:&EnergyExecutionPlan)->Result<(),ProcessError>{
        if !trace.needs_vm(){return Ok(())}
        let caller_address=plan.caller.address.clone();
        let bytes=session.store(StoreKind::Account).get(&caller_address).ok_or_else(||stage(PipelineStage::Billing,"energy caller account is missing".into()))?;
        let mut account=Account::decode(bytes.as_slice()).map_err(|error|stage(PipelineStage::Billing,error.to_string()))?;
        let mut totals=BillingTotals::default();
        let(caller,origin)=plan.settle(&mut trace.receipt,account.balance,&mut totals).map_err(|error|stage(PipelineStage::Billing,error.to_string()))?;
        account.balance=caller.balance;{let resource=account.account_resource.get_or_insert_default();resource.energy_usage=caller.energy_usage;resource.latest_consume_time_for_energy=caller.latest_consume_slot;resource.energy_window_size=caller.energy_window;resource.energy_window_optimized=caller.energy_window_optimized;}account.latest_opration_time=context.block_timestamp;session.store(StoreKind::Account).put(&caller_address,&account.encode_to_vec()).map_err(|error|stage(PipelineStage::Billing,error.to_string()))?;
        if let EnergyOrigin::Distinct(charged)=origin{let origin_address=charged.address.clone();let bytes=session.store(StoreKind::Account).get(&origin_address).ok_or_else(||stage(PipelineStage::Billing,"origin account is missing".into()))?;let mut account=Account::decode(bytes.as_slice()).map_err(|error|stage(PipelineStage::Billing,error.to_string()))?;let resource=account.account_resource.get_or_insert_default();resource.energy_usage=charged.energy_usage;resource.latest_consume_time_for_energy=charged.latest_consume_slot;resource.energy_window_size=charged.energy_window;resource.energy_window_optimized=charged.energy_window_optimized;account.latest_opration_time=context.block_timestamp;session.store(StoreKind::Account).put(&origin_address,&account.encode_to_vec()).map_err(|error|stage(PipelineStage::Billing,error.to_string()))?;}
        for(name,delta)in[("TRANSACTION_FEE_POOL",totals.transaction_fee_pool),("BURN_TRX_AMOUNT",totals.burned),("BLOCK_ENERGY_USAGE",totals.adaptive_block_energy)]{if delta!=0{Self::put_dynamic_long(session,name,Self::dynamic_long(session,name)?.checked_add(delta).ok_or_else(||stage(PipelineStage::Billing,"billing total overflow".into()))?)?;}}
        if totals.blackhole!=0{let address=&self.execution_config.blackhole_address;let bytes=session.store(StoreKind::Account).get(address).ok_or_else(||stage(PipelineStage::Billing,"blackhole account is missing".into()))?;let mut account=Account::decode(bytes.as_slice()).map_err(|error|stage(PipelineStage::Billing,error.to_string()))?;account.balance=account.balance.checked_add(totals.blackhole).ok_or_else(||stage(PipelineStage::Billing,"blackhole balance overflow".into()))?;session.store(StoreKind::Account).put(address,&account.encode_to_vec()).map_err(|error|stage(PipelineStage::Billing,error.to_string()))?;}
        Ok(())
    }

    fn execute(&self,tx:&RawWireTransaction,transaction_id:Hash32,session:&Session,plan:Option<&EnergyExecutionPlan>,retry:bool)->Result<crate::RuntimeResult,ProcessError>{
        let raw=tx.message().raw_data.as_ref().ok_or_else(||stage(PipelineStage::Runtime,"missing raw data".into()))?;
        let contract=raw.contract.first().ok_or_else(||stage(PipelineStage::Runtime,"missing contract".into()))?;
        let runtime=Runtime{actuator_registry:&self.actuator_registry,operation_registry:&self.operation_registry,execution_config:self.execution_config.clone()};
        let mut actuator=ActuatorResult::default();
        runtime.execute_transaction(contract,session,&mut actuator,transaction_id,plan,retry).map_err(|error|stage(if retry{PipelineStage::Retry}else{PipelineStage::Runtime},error.to_string()))
    }
}

pub struct TransactionProcessor {
    pub sessions: SessionManager,
    pub cache: TransactionCache,
    pub pipeline: StateTransactionPipeline,
}
impl TransactionProcessor {
    pub fn process_transaction(&mut self, mut tx: RawWireTransaction, context: ProcessContext) -> Result<ProcessOutput, ProcessError> {
        let mut session = self.sessions.build_session_enabled()?;
        let cache_before = self.cache.clone();
        let result = self.process_in_session(&session, &mut tx, &context).and_then(|output| {
            self.cache.insert(output.transaction_id, context.clock.block_number, context.clock.now).map_err(|error| stage(PipelineStage::PersistCache, error.to_string()))?;
            session.store(StoreKind::TransactionHistory).put(output.transaction_id.as_bytes(), &output.info.encode_to_vec()).map_err(|error| stage(PipelineStage::PersistInfo, error.to_string()))?;
            Ok(output)
        });
        match result {
            Ok(output) => match session.commit() {
                Ok(()) => Ok(output),
                Err(error) => { self.cache = cache_before; Err(error.into()) }
            },
            Err(error) => { self.cache = cache_before; session.revoke()?; Err(error) }
        }
    }

    /// Runs the canonical processor inside an already-owned pending child session.
    /// State remains speculative; the caller decides whether to merge or revoke the child.
    pub fn process_pending(&mut self, session: &Session, mut tx: RawWireTransaction, context: &ProcessContext) -> Result<ProcessOutput, ProcessError> {
        let cache_before = self.cache.clone();
        let result = self.process_in_session(session, &mut tx, context).and_then(|output| {
            self.cache.insert(output.transaction_id, context.clock.block_number, context.clock.now).map_err(|error| stage(PipelineStage::PersistCache, error.to_string()))?;
            session.store(StoreKind::TransactionHistory).put(output.transaction_id.as_bytes(), &output.info.encode_to_vec()).map_err(|error| stage(PipelineStage::PersistInfo, error.to_string()))?;
            Ok(output)
        });
        if result.is_err() { self.cache = cache_before; }
        result
    }

    pub fn process_in_session(&mut self, session: &Session, tx: &mut RawWireTransaction, context: &ProcessContext) -> Result<ProcessOutput, ProcessError> {
        let id = self.pipeline.admit(tx, session, context)?;
        tx.set_signature_verification_cached(true);
        // Cache is the fast-path reservation and rejects before any durable lookup.
        // The durable store remains authoritative after cache expiry or eviction.
        if self.cache.contains_recent(&id, context.clock.now).map_err(|error| stage(PipelineStage::Duplicate, error.to_string()))? { return Err(ProcessError::Duplicate(id)); }
        if session.store(StoreKind::Transaction).get(id.as_bytes()).is_some() {
            return Err(ProcessError::Duplicate(id));
        }
        let contract = tx.message().raw_data.as_ref().and_then(|raw| raw.contract.first()).ok_or_else(|| stage(PipelineStage::Trace, "missing contract".into()))?;
        let runtime_kind = Runtime::kind(contract).map_err(|error| stage(PipelineStage::Trace, error.to_string()))?;
        let trace_kind = match runtime_kind { RuntimeKind::NonVm => TraceKind::NonVm, RuntimeKind::Create => TraceKind::Create, RuntimeKind::Trigger => TraceKind::Trigger };
        let mut trace = TransactionTrace::new(trace_kind);
        trace.initialize();
        self.pipeline.consume_bandwidth(tx, session, context, &mut trace)?;
        let energy_plan = match runtime_kind {
            RuntimeKind::NonVm => None,
            RuntimeKind::Create | RuntimeKind::Trigger => {
                let is_constant_abi = Runtime::trigger_is_constant_abi(contract, session).map_err(|error| stage(PipelineStage::Trace, error.to_string()))?;
                Runtime::enforce_constant_policy(runtime_kind, self.pipeline.energy_policy(session)?.allow_constantinople, is_constant_abi).map_err(|error| stage(PipelineStage::Trace, error.to_string()))?;
                Some(self.pipeline.energy_execution_plan(tx,session,context)?)
            }
        };
        let first = self.pipeline.execute(tx, id, session, energy_plan.as_ref(), false)?;
        trace.set_runtime(first);
        let mut retried = false;
        if trace.needs_out_of_time_retry(context.origin, context.expected_result) {
            trace.initialize();
            trace.set_runtime(self.pipeline.execute(tx, id, session, energy_plan.as_ref(), true)?);
            retried = true;
        }
        trace.check_witness(context.expected_result).map_err(|error| stage(PipelineStage::Witness, error.to_string()))?;
        if let Some(energy_plan) = energy_plan.as_ref() {
            self.pipeline.pay_energy(session, &mut trace, context, energy_plan)?;
        }
        trace.delete_successful_contracts(session).map_err(|error| stage(PipelineStage::Finalization, error.to_string()))?;

        let mut transaction = tx.message().clone();
        let result: TransactionResult = trace.transaction_result().map_err(|error| stage(PipelineStage::Finalization, error.to_string()))?;
        transaction.ret = vec![result];
        let fee_pool_enabled = StateTransactionPipeline::dynamic_long(session, "ALLOW_TRANSACTION_FEE_POOL")? == 1;
        let info = trace.transaction_info(*id.as_array(), Some((context.clock.block_number, context.block_timestamp)), true, true, fee_pool_enabled).map_err(|error| stage(PipelineStage::Finalization, error.to_string()))?;

        session.store(StoreKind::Transaction).put(id.as_bytes(), &transaction.encode_to_vec()).map_err(|error| stage(PipelineStage::PersistTransaction, error.to_string()))?;
        Ok(ProcessOutput { transaction_id: id, transaction, info, retried })
    }
}
fn stage(stage: PipelineStage, message: String) -> ProcessError { ProcessError::Stage { stage, message } }
