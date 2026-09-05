use crate::{Repository, RepositoryError};
use tron_state::ForkVersion;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TvmRules {
    pub multi_sign:bool,pub transfer_trc10:bool,pub constantinople:bool,pub solidity_059:bool,pub istanbul:bool,pub freeze:bool,pub vote:bool,pub london:bool,pub compatible_evm:bool,pub create2_depth_timeout:bool,pub higher_cpu_memory:bool,pub freeze_v2:bool,pub optimized_chain_id:bool,pub dynamic_energy:bool,pub dynamic_energy_threshold:i64,pub dynamic_energy_increase_factor:i64,pub dynamic_energy_max_factor:i64,pub shanghai:bool,pub energy_adjustment:bool,pub strict_math:bool,pub cancun:bool,pub disable_java_math:bool,pub blob:bool,pub selfdestruct_restriction:bool,pub osaka:bool,pub harden_resource:bool,pub shielded_trc20:bool,pub latest_block_number:i64,pub energy_limit_hardfork:bool,
}
fn value(repository:&Repository<'_>,name:&str)->Result<i64,RepositoryError>{Ok(repository.dynamic_i64(name)?.unwrap_or(0))}
fn flag(repository:&Repository<'_>,name:&str)->Result<bool,RepositoryError>{Ok(value(repository,name)?==1)}
const VERSION_4_8_1_1: ForkVersion = ForkVersion {
    version: 35,
    hard_fork_time: 1_596_780_000_000,
    hard_fork_rate: 70,
};
impl TvmRules {
    pub fn load(r:&Repository<'_>,energy_limit_height:i64)->Result<Self,RepositoryError>{
        let latest=value(r,"LATEST_BLOCK_HEADER_NUMBER")?;
        let create2_depth_timeout=r.canonical_fork_pass(VERSION_4_8_1_1)?;
        Ok(Self{multi_sign:flag(r,"ALLOW_MULTI_SIGN")?,transfer_trc10:flag(r,"ALLOW_TVM_TRANSFER_TRC10")?,constantinople:flag(r,"ALLOW_TVM_CONSTANTINOPLE")?,solidity_059:flag(r,"ALLOW_TVM_SOLIDITY_059")?,istanbul:flag(r,"ALLOW_TVM_ISTANBUL")?,freeze:flag(r,"ALLOW_TVM_FREEZE")?,vote:flag(r,"ALLOW_TVM_VOTE")?,london:flag(r,"ALLOW_TVM_LONDON")?,compatible_evm:flag(r,"ALLOW_TVM_COMPATIBLE_EVM")?,create2_depth_timeout,higher_cpu_memory:flag(r,"ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX")?,freeze_v2:value(r,"UNFREEZE_DELAY_DAYS")?>0,optimized_chain_id:flag(r,"ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID")?,dynamic_energy:flag(r,"ALLOW_DYNAMIC_ENERGY")?,dynamic_energy_threshold:value(r,"DYNAMIC_ENERGY_THRESHOLD")?,dynamic_energy_increase_factor:value(r,"DYNAMIC_ENERGY_INCREASE_FACTOR")?,dynamic_energy_max_factor:value(r,"DYNAMIC_ENERGY_MAX_FACTOR")?,shanghai:flag(r,"ALLOW_TVM_SHANGHAI")?,energy_adjustment:flag(r,"ALLOW_ENERGY_ADJUSTMENT")?,strict_math:flag(r,"ALLOW_STRICT_MATH")?,cancun:flag(r,"ALLOW_TVM_CANCUN")?,disable_java_math:flag(r,"DISABLE_JAVA_LANG_MATH")?,blob:flag(r,"ALLOW_TVM_BLOB")?,selfdestruct_restriction:flag(r,"ALLOW_TVM_SELFDESTRUCT_RESTRICTION")?,osaka:flag(r,"ALLOW_TVM_OSAKA")?,harden_resource:flag(r,"ALLOW_TVM_HARDEN_RESOURCE")?,shielded_trc20:flag(r,"ALLOW_SHIELDED_TRC20_TRANSACTION")?,latest_block_number:latest,energy_limit_hardfork:latest>=energy_limit_height})
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)] pub struct ExecutionOptions{pub vm_trace:bool,pub bypass_cpu_limit:bool,pub save_internal_transactions:bool}
