use crate::{ApiError, TypedReadView, error::success_return};
use tron_protocol::protocol::{EstimateEnergyMessage, TransactionExtention, TriggerSmartContract};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConstantOutcome {
    pub result: Vec<u8>,
    pub energy_used: i64,
    pub energy_penalty: i64,
    pub runtime_error: String,
}
pub trait ReadOnlyVm: Send + Sync {
    fn execute(
        &self,
        view: &TypedReadView,
        request: &TriggerSmartContract,
        energy_limit: i64,
    ) -> Result<ConstantOutcome, ApiError>;
}

/// C014/C015 adapter: the executor receives only an immutable cursor snapshot. No revoking
/// session or durable store is exposed, so constant calls and energy probes cannot commit state.
pub struct ConstantService<V> {
    vm: V,
    support_constant: bool,
    max_energy: i64,
}
impl<V: ReadOnlyVm> ConstantService<V> {
    #[must_use]
    pub const fn new(vm: V, support_constant: bool, max_energy: i64) -> Self {
        Self {
            vm,
            support_constant,
            max_energy,
        }
    }
    pub fn trigger(
        &self,
        view: &TypedReadView,
        request: &TriggerSmartContract,
    ) -> Result<TransactionExtention, ApiError> {
        self.require_enabled()?;
        let out = self.vm.execute(view, request, self.max_energy)?;
        if !out.runtime_error.is_empty() {
            return Err(ApiError::FailedPrecondition(out.runtime_error));
        }
        Ok(TransactionExtention {
            constant_result: vec![out.result],
            result: Some(success_return()),
            energy_used: out.energy_used,
            energy_penalty: out.energy_penalty,
            ..Default::default()
        })
    }
    pub fn estimate(
        &self,
        view: &TypedReadView,
        request: &TriggerSmartContract,
    ) -> Result<EstimateEnergyMessage, ApiError> {
        self.require_enabled()?;
        if self.max_energy <= 0 {
            return Err(ApiError::FailedPrecondition(
                "energy estimation is disabled".into(),
            ));
        }
        let mut low = 0_i64;
        let mut high = self.max_energy;
        while low.saturating_add(1) < high {
            let mid = low + (high - low) / 2;
            let out = self.vm.execute(view, request, mid)?;
            if out.runtime_error.is_empty() {
                high = mid
            } else {
                low = mid
            }
        }
        let final_out = self.vm.execute(view, request, high)?;
        if !final_out.runtime_error.is_empty() {
            return Err(ApiError::FailedPrecondition(final_out.runtime_error));
        }
        Ok(EstimateEnergyMessage {
            result: Some(success_return()),
            energy_required: high,
        })
    }
    fn require_enabled(&self) -> Result<(), ApiError> {
        if self.support_constant {
            Ok(())
        } else {
            Err(ApiError::FailedPrecondition(
                "this node does not support constant".into(),
            ))
        }
    }
}
