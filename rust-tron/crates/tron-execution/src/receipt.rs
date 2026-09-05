use tron_protocol::protocol::{transaction::result::ContractResult as ProtoContractResult, ResourceReceipt};
use tron_state::ResourceWindow;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeeDestination { TransactionFeePool, Burn, Blackhole }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnergyBillingPolicy {
    pub energy_price: i64,
    pub allow_constantinople: bool,
    pub transaction_fee_pool: bool,
    pub blackhole_optimization: bool,
    pub adaptive_energy: bool,
}
impl Default for EnergyBillingPolicy {
    fn default() -> Self { Self { energy_price: 100, allow_constantinople: false, transaction_fee_pool: false, blackhole_optimization: false, adaptive_energy: false } }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnergyAccount {
    pub address: Vec<u8>,
    pub balance: i64,
    pub frozen_energy_left: i64,
    pub energy_usage: i64,
    pub latest_consume_slot: i64,
    pub energy_window: i64,
    pub energy_window_optimized: bool,
    pub head_slot: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnergyOrigin {
    Absent,
    SameAsCaller,
    Distinct(EnergyAccount),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EnergyExecutionPlan {
    pub caller: EnergyAccount,
    pub origin: EnergyOrigin,
    pub origin_percent: i64,
    pub origin_energy_limit: i64,
    pub caller_paid_energy_limit: i64,
    pub energy_limit: i64,
    pub policy: EnergyBillingPolicy,
}

impl EnergyExecutionPlan {
    pub fn settle(
        &self,
        receipt: &mut Receipt,
        caller_balance: i64,
        totals: &mut BillingTotals,
    ) -> Result<(EnergyAccount, EnergyOrigin), ReceiptError> {
        if receipt.resource.energy_usage_total > self.energy_limit {
            return Err(ReceiptError::Arithmetic);
        }
        let mut caller = self.caller.clone();
        caller.balance = caller_balance;
        let mut origin = self.origin.clone();
        receipt.origin_energy_left = match &origin {
            EnergyOrigin::Distinct(account) => account.frozen_energy_left,
            EnergyOrigin::Absent | EnergyOrigin::SameAsCaller => 0,
        };
        receipt.caller_energy_left = caller.frozen_energy_left;
        receipt.pay_energy_bill_planned(
            &mut origin,
            &mut caller,
            self.origin_percent,
            self.origin_energy_limit,
            self.caller_paid_energy_limit,
            self.policy,
            totals,
        )?;
        Ok((caller, origin))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BillingTotals { pub transaction_fee_pool: i64, pub burned: i64, pub blackhole: i64, pub adaptive_block_energy: i64 }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiptError { MissingOrigin, InsufficientBalance { address: Vec<u8> }, Arithmetic }
impl core::fmt::Display for ReceiptError { fn fmt(&self, f:&mut core::fmt::Formatter<'_>)->core::fmt::Result { match self { Self::MissingOrigin=>f.write_str("origin account is missing"), Self::InsufficientBalance{address}=>write!(f,"account {:02x?} insufficient balance",address), Self::Arithmetic=>f.write_str("long overflow") } } }
impl std::error::Error for ReceiptError {}

#[derive(Clone, Debug, PartialEq)]
pub struct Receipt {
    pub resource: ResourceReceipt,
    pub multi_sign_fee: i64,
    pub memo_fee: i64,
    pub origin_energy_left: i64,
    pub caller_energy_left: i64,
}
impl Default for Receipt { fn default()->Self { Self { resource:ResourceReceipt::default(), multi_sign_fee:0, memo_fee:0, origin_energy_left:0, caller_energy_left:0 } } }
impl Receipt {
    pub fn set_bill(&mut self, energy:i64) { self.resource.energy_usage_total=energy.max(0); }
    pub fn set_penalty(&mut self, penalty:i64) { self.resource.energy_penalty_total=penalty.max(0); }
    pub fn set_net_bill(&mut self, usage:i64, fee:i64) { self.resource.net_usage=usage; self.resource.net_fee=fee; }
    pub fn add_net_fee(&mut self, fee:i64)->Result<(),ReceiptError>{self.resource.net_fee=self.resource.net_fee.checked_add(fee).ok_or(ReceiptError::Arithmetic)?;Ok(())}
    pub fn total_fee(&self, actuator_fee:i64)->Result<i64,ReceiptError>{[actuator_fee,self.resource.energy_fee,self.resource.net_fee,self.multi_sign_fee,self.memo_fee].into_iter().try_fold(0i64,|v,n|v.checked_add(n).ok_or(ReceiptError::Arithmetic))}
    pub fn packing_fee(&self, fee_pool_enabled:bool, net_fee_for_bandwidth:bool)->i64 { if !fee_pool_enabled{return 0} let mut fee=if net_fee_for_bandwidth{self.resource.net_fee}else{0}; if self.resource.result!=ProtoContractResult::OutOfTime as i32 { fee=fee.saturating_add(self.resource.energy_fee); } fee }

    pub fn pay_energy_bill(&mut self,origin:&mut EnergyOrigin,caller:&mut EnergyAccount,origin_percent:i64,origin_energy_limit:i64,policy:EnergyBillingPolicy,totals:&mut BillingTotals)->Result<(),ReceiptError>{self.pay_energy_bill_planned(origin,caller,origin_percent,origin_energy_limit,i64::MAX,policy,totals)}
    fn pay_energy_bill_planned(&mut self, origin:&mut EnergyOrigin, caller:&mut EnergyAccount, origin_percent:i64, origin_energy_limit:i64, caller_paid_energy_limit:i64, policy:EnergyBillingPolicy, totals:&mut BillingTotals)->Result<(),ReceiptError>{
        self.resource.origin_energy_usage=0;
        let total=self.resource.energy_usage_total;
        if total<=0{return Ok(())}
        match origin {
            EnergyOrigin::Absent => {
                if !policy.allow_constantinople{return Err(ReceiptError::MissingOrigin)}
                self.charge(caller,total,caller_paid_energy_limit,policy,totals)
            }
            EnergyOrigin::SameAsCaller => self.charge(caller,total,caller_paid_energy_limit,policy,totals),
            EnergyOrigin::Distinct(origin) => {
                let requested=total.checked_mul(origin_percent.clamp(0,100)).ok_or(ReceiptError::Arithmetic)?/100;
                let origin_usage=requested.min(self.origin_energy_left).min(origin_energy_limit.max(0)).min(origin.frozen_energy_left.max(0));
                use_frozen(origin,origin_usage)?;
                self.resource.origin_energy_usage=origin_usage;
                self.charge(caller,total-origin_usage,caller_paid_energy_limit,policy,totals)
            }
        }
    }
    fn charge(&mut self, account:&mut EnergyAccount, usage:i64, paid_limit:i64, policy:EnergyBillingPolicy, totals:&mut BillingTotals)->Result<(),ReceiptError>{
        let available=self.caller_energy_left.min(account.frozen_energy_left).max(0);
        let frozen=available.min(usage);
        use_frozen(account,frozen)?;
        self.resource.energy_usage=frozen;
        let paid=usage-frozen;
        if paid > paid_limit.max(0) { return Err(ReceiptError::InsufficientBalance { address: account.address.clone() }); }
        if paid==0{return Ok(())}
        if policy.adaptive_energy{totals.adaptive_block_energy=totals.adaptive_block_energy.checked_add(paid).ok_or(ReceiptError::Arithmetic)?;}
        let fee=paid.checked_mul(policy.energy_price).ok_or(ReceiptError::Arithmetic)?;
        if account.balance<fee{return Err(ReceiptError::InsufficientBalance{address:account.address.clone()})}
        account.balance-=fee; self.resource.energy_fee=fee;
        if policy.transaction_fee_pool && self.resource.result!=ProtoContractResult::OutOfTime as i32 { totals.transaction_fee_pool=totals.transaction_fee_pool.checked_add(fee).ok_or(ReceiptError::Arithmetic)?; }
        else if policy.blackhole_optimization { totals.burned=totals.burned.checked_add(fee).ok_or(ReceiptError::Arithmetic)?; }
        else { totals.blackhole=totals.blackhole.checked_add(fee).ok_or(ReceiptError::Arithmetic)?; }
        Ok(())
    }
}
fn use_frozen(account:&mut EnergyAccount, usage:i64)->Result<(),ReceiptError>{
    if usage==0{return Ok(())}
    account.frozen_energy_left=account.frozen_energy_left.checked_sub(usage).ok_or(ReceiptError::Arithmetic)?;
    let consumed=ResourceWindow{usage:account.energy_usage,latest_slot:account.latest_consume_slot,window:account.energy_window,precise:account.energy_window_optimized,standard_window:28_800}.consume(usage,account.head_slot).map_err(|_|ReceiptError::Arithmetic)?;
    account.energy_usage=consumed.usage;
    account.latest_consume_slot=consumed.latest_slot;
    account.energy_window=consumed.window;
    account.energy_window_optimized=consumed.precise;
    Ok(())
}
