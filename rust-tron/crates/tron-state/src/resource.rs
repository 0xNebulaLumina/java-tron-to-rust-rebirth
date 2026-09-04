use core::fmt;

pub const TRX_PRECISION: i64 = 1_000_000;
pub const RESOURCE_PRECISION: i64 = 1_000_000;
pub const WINDOW_SIZE_PRECISION: i64 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind { Bandwidth, Energy, TronPower }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceWindow {
    pub usage: i64,
    pub latest_slot: i64,
    /// Stored window value. Optimized windows use thousandths of a slot; legacy windows use slots.
    pub window: i64,
    pub precise: bool,
    /// Standard Java resource window, in slots, used when the stored value is absent or too small.
    pub standard_window: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalResource {
    pub limit: i64,
    pub weight: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptiveEnergy {
    pub base_limit: i64,
    pub current_limit: i64,
    pub target_limit: i64,
    pub average_usage: i64,
    pub multiplier: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeeSink { Pool, Burn, BlackHole }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeDisposition { pub payer_balance: i64, pub pool: i64, pub burned: i64, pub black_hole: i64 }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceError { NonPositiveWindow, InvalidRatio { numerator: i64, denominator: i64 }, TimeReversal { last: i64, now: i64 }, NegativeAmount(i64), InsufficientBalance, WeightOverflow { current: i64, delta: i64 }, Overflow }
impl fmt::Display for ResourceError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "resource arithmetic error: {self:?}") } }
impl std::error::Error for ResourceError {}

fn i64_exact(value: i128) -> Result<i64, ResourceError> { i64::try_from(value).map_err(|_| ResourceError::Overflow) }
fn ceil_div(value: i128, divisor: i128) -> i128 { let q=value/divisor; let r=value%divisor; q + i128::from(r>0) }
fn java_round_ratio(value: i128, numerator: i128, denominator: i128) -> i128 {
    let scaled=value*numerator;
    let q=scaled.div_euclid(denominator);
    let r=scaled.rem_euclid(denominator);
    q + i128::from(r*2 >= denominator)
}

impl ResourceWindow {
    pub fn window_slots(self) -> Result<i64, ResourceError> {
        if self.standard_window <= 0 { return Err(ResourceError::NonPositiveWindow); }
        if self.window == 0 || (self.precise && self.window < WINDOW_SIZE_PRECISION) {
            return Ok(self.standard_window);
        }
        if self.window < 0 { return Err(ResourceError::NonPositiveWindow); }
        Ok(if self.precise { self.window / WINDOW_SIZE_PRECISION } else { self.window })
    }

    fn precise_window(self) -> Result<i64, ResourceError> {
        if self.standard_window <= 0 || self.window < 0 { return Err(ResourceError::NonPositiveWindow); }
        if self.window == 0 {
            return i64_exact(i128::from(self.standard_window) * i128::from(WINDOW_SIZE_PRECISION));
        }
        if self.precise {
            Ok(self.window)
        } else {
            i64_exact(i128::from(self.window) * i128::from(WINDOW_SIZE_PRECISION))
        }
    }

    pub fn recover(self, now: i64) -> Result<i64, ResourceError> {
        let window=self.window_slots()?;
        if now < self.latest_slot { return Err(ResourceError::TimeReversal { last:self.latest_slot, now }); }
        let delta=now-self.latest_slot;
        if delta >= window { return Ok(0); }
        let average=ceil_div(i128::from(self.usage)*i128::from(RESOURCE_PRECISION), i128::from(window));
        let decayed=java_round_ratio(average, i128::from(window-delta), i128::from(window));
        i64_exact(decayed*i128::from(window)/i128::from(RESOURCE_PRECISION))
    }

    pub fn consume(self, amount: i64, now: i64) -> Result<Self, ResourceError> {
        if amount < 0 { return Err(ResourceError::NegativeAmount(amount)); }
        if now < self.latest_slot { return Err(ResourceError::TimeReversal { last:self.latest_slot, now }); }
        let standard_window=self.standard_window;
        if standard_window <= 0 { return Err(ResourceError::NonPositiveWindow); }
        let remaining=self.recover(now)?;
        let remaining_precise=i64_exact((i128::from(self.precise_window()?)-i128::from(now-self.latest_slot)*i128::from(WINDOW_SIZE_PRECISION)).max(0))?;
        let usage=i64_exact(i128::from(remaining)+i128::from(amount))?;
        let precise_window=if usage==0 { i128::from(standard_window)*i128::from(WINDOW_SIZE_PRECISION) } else {
            ceil_div(i128::from(remaining)*i128::from(remaining_precise)+i128::from(amount)*i128::from(standard_window)*i128::from(WINDOW_SIZE_PRECISION),i128::from(usage))
                .min(i128::from(standard_window)*i128::from(WINDOW_SIZE_PRECISION))
        };
        Ok(Self { usage, latest_slot:now, window:i64_exact(precise_window)?, precise:true, standard_window })
    }
}

pub fn global_limit(frozen_balance: i64, global: GlobalResource, v2: bool) -> Result<i64, ResourceError> {
    if frozen_balance <= 0 || global.weight <= 0 || global.limit <= 0 { return Ok(0); }
    let numerator=if v2 { i128::from(frozen_balance)*i128::from(global.limit) } else { i128::from(frozen_balance/TRX_PRECISION)*i128::from(global.limit) };
    let denominator=if v2 { i128::from(TRX_PRECISION)*i128::from(global.weight) } else { i128::from(global.weight) };
    i64_exact(numerator/denominator)
}

pub fn update_weight(current: i64, delta: i64, clamp_for_new_reward: bool) -> Result<i64, ResourceError> {
    let next=current.checked_add(delta).ok_or(ResourceError::WeightOverflow { current, delta })?;
    Ok(if clamp_for_new_reward && next<0 { 0 } else { next })
}

pub fn adaptive_energy_limit(state: AdaptiveEnergy, contract_rate:(i64,i64), expand_rate:(i64,i64)) -> Result<i64,ResourceError> {
    let (n,d)=if state.average_usage>state.target_limit { contract_rate } else { expand_rate };
    if n<=0 || d<=0 { return Err(ResourceError::InvalidRatio { numerator:n, denominator:d }); }
    if state.multiplier<0 { return Err(ResourceError::NegativeAmount(state.multiplier)); }
    let scaled=i64_exact(i128::from(state.current_limit)*i128::from(n)/i128::from(d))?;
    let upper=i64_exact(i128::from(state.base_limit)*i128::from(state.multiplier))?;
    Ok(scaled.max(state.base_limit).min(upper))
}

pub fn charge_fee(balance:i64, fee:i64, sink:FeeSink, mut totals:FeeDisposition)->Result<FeeDisposition,ResourceError>{
    if fee<0{return Err(ResourceError::NegativeAmount(fee));} if balance<fee{return Err(ResourceError::InsufficientBalance);}
    totals.payer_balance=balance-fee;
    match sink { FeeSink::Pool=>totals.pool=i64_exact(i128::from(totals.pool)+i128::from(fee))?, FeeSink::Burn=>totals.burned=i64_exact(i128::from(totals.burned)+i128::from(fee))?, FeeSink::BlackHole=>totals.black_hole=i64_exact(i128::from(totals.black_hole)+i128::from(fee))? }
    Ok(totals)
}
