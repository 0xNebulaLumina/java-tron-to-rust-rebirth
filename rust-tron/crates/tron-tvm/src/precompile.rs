use crate::{EnergyMeter, Repository, TvmRules, VmFault};
use std::sync::Arc;
use tron_shielded::TronParameters;
use tron_primitives::TronAddress21;

pub mod standard;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrecompileOutput { pub success: bool, pub output: Vec<u8>, pub energy: i64, pub fault: Option<VmFault> }

pub trait Precompile: Sync {
    fn energy(&self, input: &[u8], rules: &TvmRules) -> i64;
    fn execute(&self, input: &[u8], rules: &TvmRules, repository: &mut Repository<'_>) -> (bool, Vec<u8>);
    fn execute_with_caller(&self, input: &[u8], rules: &TvmRules, repository: &mut Repository<'_>, _caller: Option<TronAddress21>) -> (bool, Vec<u8>) { self.execute(input, rules, repository) }
}

struct ShieldedMarker(crate::ShieldedPrecompile);
static SHIELDED_MINT: ShieldedMarker = ShieldedMarker(crate::ShieldedPrecompile::VerifyMint);
static SHIELDED_TRANSFER: ShieldedMarker = ShieldedMarker(crate::ShieldedPrecompile::VerifyTransfer);
static SHIELDED_BURN: ShieldedMarker = ShieldedMarker(crate::ShieldedPrecompile::VerifyBurn);
static SHIELDED_MERKLE: ShieldedMarker = ShieldedMarker(crate::ShieldedPrecompile::MerkleHash);

impl Precompile for ShieldedMarker {
    fn energy(&self, _input: &[u8], _rules: &TvmRules) -> i64 { i64::try_from(self.0.energy()).unwrap_or(i64::MAX) }
    fn execute(&self, input: &[u8], _rules: &TvmRules, _repository: &mut Repository<'_>) -> (bool, Vec<u8>) {
        if self.0 == crate::ShieldedPrecompile::MerkleHash { let out = crate::execute_merkle_hash(input); (out.success, out.output) } else { (false, Vec::new()) }
    }
}

fn low_address(address: &TronAddress21) -> Option<u32> { let b=address.as_bytes(); if b[1..17].iter().any(|v|*v!=0){return None} Some(u32::from_be_bytes(b[17..21].try_into().ok()?)) }
fn shielded_marker(address: &TronAddress21, rules: &TvmRules) -> Option<&'static dyn Precompile> {
    match crate::ShieldedPrecompiles::resolve(low_address(address)?, rules.shielded_trc20)? { crate::ShieldedPrecompile::VerifyMint=>Some(&SHIELDED_MINT),crate::ShieldedPrecompile::VerifyTransfer=>Some(&SHIELDED_TRANSFER),crate::ShieldedPrecompile::VerifyBurn=>Some(&SHIELDED_BURN),crate::ShieldedPrecompile::MerkleHash=>Some(&SHIELDED_MERKLE) }
}

#[derive(Clone, Default)]
pub struct PrecompileRegistry { shielded_parameters: Option<Arc<TronParameters>> }
impl PrecompileRegistry {
    #[must_use] pub const fn new() -> Self { Self { shielded_parameters: None } }
    #[must_use] pub fn with_shielded_parameters(parameters: Arc<TronParameters>) -> Self { Self { shielded_parameters: Some(parameters) } }
    #[must_use] pub fn contract(&self, address: &TronAddress21, rules: &TvmRules) -> Option<&'static dyn Precompile> {
        standard::contract(address, rules).or_else(|| crate::precompile_tron::contract(address, rules)).or_else(|| shielded_marker(address, rules))
    }
    pub fn dispatch(&self, address: &TronAddress21, input: &[u8], rules: &TvmRules, repository: &mut Repository<'_>, meter: &mut EnergyMeter) -> Option<PrecompileOutput> { self.dispatch_with_caller(address, input, rules, repository, meter, None) }
    pub fn dispatch_with_caller(&self, address: &TronAddress21, input: &[u8], rules: &TvmRules, repository: &mut Repository<'_>, meter: &mut EnergyMeter, caller: Option<TronAddress21>) -> Option<PrecompileOutput> {
        let shielded = crate::ShieldedPrecompiles::resolve(low_address(address)?, rules.shielded_trc20);
        let contract = self.contract(address, rules)?;
        let energy = contract.energy(input, rules);
        if meter.spend(energy).is_err() { meter.exhaust(); return Some(PrecompileOutput { success:false, output:Vec::new(), energy:meter.used(), fault:Some(VmFault::OutOfEnergy) }); }
        let child = repository.begin_child(crate::ChildStorageMode::Copied);
        let (success, output) = if let Some(kind)=shielded {
            if kind == crate::ShieldedPrecompile::MerkleHash { let out=crate::execute_merkle_hash(input); (out.success,out.output) }
            else if let Some(parameters)=&self.shielded_parameters { let out=crate::ShieldedPrecompiles::new(Arc::clone(parameters)).execute(kind,input); (out.success,out.output) }
            else { (false,Vec::new()) }
        } else { contract.execute_with_caller(input, rules, repository, caller) };
        if success { let _ = repository.commit_child(child); } else { meter.exhaust(); let _ = repository.revoke_child(child); }
        let fault=if success{None}else if standard::modexp_fork_timeout(address,input,rules){Some(VmFault::OutOfTime)}else{Some(VmFault::PrecompiledContract)};
        Some(PrecompileOutput { success, output, energy:meter.used(), fault })
    }
}
