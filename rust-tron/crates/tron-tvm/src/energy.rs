use crate::VmFault;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnergyMeter { limit:i64, used:i64, penalty:i64 }
impl EnergyMeter {
    pub fn new(limit:i64)->Result<Self,VmFault>{if limit<0{return Err(VmFault::OutOfEnergy);}Ok(Self{limit,used:0,penalty:0})}
    #[must_use] pub fn limit(self)->i64{self.limit} #[must_use] pub fn used(self)->i64{self.used} #[must_use] pub fn remaining(self)->i64{self.limit-self.used} #[must_use] pub fn penalty(self)->i64{self.penalty}
    pub fn spend(&mut self,amount:i64)->Result<(),VmFault>{if amount<0{return Err(VmFault::Arithmetic);}self.used=self.used.checked_add(amount).ok_or(VmFault::OutOfEnergy)?;if self.used>self.limit{self.used=self.limit;return Err(VmFault::OutOfEnergy);}Ok(())}
    pub fn refund(&mut self,amount:i64)->Result<(),VmFault>{if amount<0||amount>self.used{return Err(VmFault::Arithmetic);}self.used-=amount;Ok(())}
    pub fn add_penalty(&mut self,amount:i64)->Result<(),VmFault>{if amount<0{return Err(VmFault::Arithmetic);}self.penalty=self.penalty.checked_add(amount).ok_or(VmFault::OutOfEnergy)?;Ok(())}
    pub fn exhaust(&mut self){self.used=self.limit;}
    #[must_use] pub fn memory_cost(bytes:usize)->Result<i64,VmFault>{let words=bytes.checked_add(31).ok_or(VmFault::OutOfMemory)?/32;let w=i64::try_from(words).map_err(|_|VmFault::OutOfMemory)?;let square=w.checked_mul(w).ok_or(VmFault::OutOfEnergy)?;w.checked_mul(3).and_then(|v|v.checked_add(square/512)).ok_or(VmFault::OutOfEnergy)}
    pub fn memory_delta(old_bytes:usize,new_bytes:usize)->Result<i64,VmFault>{Self::memory_cost(new_bytes)?.checked_sub(Self::memory_cost(old_bytes)?).ok_or(VmFault::Arithmetic)}
}

pub const DYNAMIC_ENERGY_DECIMAL: i64 = 10_000;
pub const DYNAMIC_ENERGY_DECREASE_DIVISOR: i64 = 4;

/// Applies a contract's dynamic-energy factor using Java's integer arithmetic.
/// The returned tuple is `(total_cost, penalty)`; the base cost is never itself
/// counted as penalty.
pub fn apply_dynamic_energy(base: i64, factor: i64) -> Result<(i64, i64), VmFault> {
    if base < 0 || factor < 0 {
        return Err(VmFault::Arithmetic);
    }
    let penalty = base
        .checked_mul(factor)
        .and_then(|value| value.checked_div(DYNAMIC_ENERGY_DECIMAL))
        .ok_or(VmFault::OutOfEnergy)?;
    let total = base.checked_add(penalty).ok_or(VmFault::OutOfEnergy)?;
    Ok((total, penalty))
}

/// EIP-150-style forwarding used by TVM CALL-family instructions after fixed,
/// memory, transfer, new-account and dynamic-penalty costs have been charged.
pub fn forwarded_call_energy(available: i64, requested: i64, energy_adjustment: bool) -> Result<i64, VmFault> {
    if available < 0 || requested < 0 {
        return Err(VmFault::OutOfEnergy);
    }
    let cap = if energy_adjustment {
        available.checked_sub(available / 64).ok_or(VmFault::OutOfEnergy)?
    } else {
        available
    };
    Ok(requested.min(cap))
}

/// Computes the next contract factor at a maintenance boundary. Busy contracts
/// increase by the configured percentage and are capped; idle contracts decay
/// by one quarter, matching Java's `DYNAMIC_ENERGY_DECREASE_DIVISION`.
pub fn next_dynamic_factor(current: i64, usage: i64, threshold: i64, increase_percent: i64, maximum: i64) -> Result<i64, VmFault> {
    if current < 0 || usage < 0 || threshold < 0 || increase_percent < 0 || maximum < 0 {
        return Err(VmFault::Arithmetic);
    }
    if usage > threshold {
        let increase = current
            .checked_add(DYNAMIC_ENERGY_DECIMAL)
            .and_then(|value| value.checked_mul(increase_percent))
            .and_then(|value| value.checked_div(100))
            .ok_or(VmFault::OutOfEnergy)?;
        current.checked_add(increase).map(|value| value.min(maximum)).ok_or(VmFault::OutOfEnergy)
    } else {
        Ok(current - current / DYNAMIC_ENERGY_DECREASE_DIVISOR)
    }
}

pub trait MonotonicClock { fn elapsed(&self)->Duration; }
pub trait ExecutionLimiter { fn check(&mut self)->Result<(),VmFault>; }
#[derive(Clone, Copy, Debug, Default)] pub struct Unlimited; impl ExecutionLimiter for Unlimited{fn check(&mut self)->Result<(),VmFault>{Ok(())}}
pub struct DeadlineLimiter<C>{clock:C,deadline:Duration}
impl<C:MonotonicClock> DeadlineLimiter<C>{#[must_use]pub fn new(clock:C,deadline:Duration)->Self{Self{clock,deadline}}}
impl<C:MonotonicClock> ExecutionLimiter for DeadlineLimiter<C>{fn check(&mut self)->Result<(),VmFault>{if self.clock.elapsed()>self.deadline{Err(VmFault::OutOfTime)}else{Ok(())}}}
#[derive(Clone, Copy, Debug, Default)] pub struct ManualMonotonicClock{elapsed:Duration} impl ManualMonotonicClock{pub fn advance(&mut self,d:Duration){self.elapsed+=d;}} impl MonotonicClock for ManualMonotonicClock{fn elapsed(&self)->Duration{self.elapsed}}
