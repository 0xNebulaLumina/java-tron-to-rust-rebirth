/// Exact Java DynamicPropertiesStore byte-key inventory.
pub const KEYS: &[(&str, &[u8])] = &[
    ("LATEST_BLOCK_HEADER_TIMESTAMP", b"latest_block_header_timestamp"),
    ("LATEST_BLOCK_HEADER_NUMBER", b"latest_block_header_number"),
    ("LATEST_BLOCK_HEADER_HASH", b"latest_block_header_hash"),
    ("STATE_FLAG", b"state_flag"),
    ("LATEST_SOLIDIFIED_BLOCK_NUM", b"LATEST_SOLIDIFIED_BLOCK_NUM"),
    ("LATEST_PROPOSAL_NUM", b"LATEST_PROPOSAL_NUM"),
    ("LATEST_EXCHANGE_NUM", b"LATEST_EXCHANGE_NUM"),
    ("BLOCK_FILLED_SLOTS", b"BLOCK_FILLED_SLOTS"),
    ("BLOCK_FILLED_SLOTS_INDEX", b"BLOCK_FILLED_SLOTS_INDEX"),
    ("NEXT_MAINTENANCE_TIME", b"NEXT_MAINTENANCE_TIME"),
    ("MAX_FROZEN_TIME", b"MAX_FROZEN_TIME"),
    ("MIN_FROZEN_TIME", b"MIN_FROZEN_TIME"),
    ("MAX_FROZEN_SUPPLY_NUMBER", b"MAX_FROZEN_SUPPLY_NUMBER"),
    ("MAX_FROZEN_SUPPLY_TIME", b"MAX_FROZEN_SUPPLY_TIME"),
    ("MIN_FROZEN_SUPPLY_TIME", b"MIN_FROZEN_SUPPLY_TIME"),
    ("WITNESS_ALLOWANCE_FROZEN_TIME", b"WITNESS_ALLOWANCE_FROZEN_TIME"),
    ("MAINTENANCE_TIME_INTERVAL", b"MAINTENANCE_TIME_INTERVAL"),
    ("ACCOUNT_UPGRADE_COST", b"ACCOUNT_UPGRADE_COST"),
    ("WITNESS_PAY_PER_BLOCK", b"WITNESS_PAY_PER_BLOCK"),
    ("WITNESS_127_PAY_PER_BLOCK", b"WITNESS_127_PAY_PER_BLOCK"),
    ("WITNESS_STANDBY_ALLOWANCE", b"WITNESS_STANDBY_ALLOWANCE"),
    ("ENERGY_FEE", b"ENERGY_FEE"),
    ("MAX_CPU_TIME_OF_ONE_TX", b"MAX_CPU_TIME_OF_ONE_TX"),
    ("CREATE_ACCOUNT_FEE", b"CREATE_ACCOUNT_FEE"),
    ("CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT"),
    ("CREATE_NEW_ACCOUNT_BANDWIDTH_RATE", b"CREATE_NEW_ACCOUNT_BANDWIDTH_RATE"),
    ("TRANSACTION_FEE", b"TRANSACTION_FEE"),
    ("ASSET_ISSUE_FEE", b"ASSET_ISSUE_FEE"),
    ("UPDATE_ACCOUNT_PERMISSION_FEE", b"UPDATE_ACCOUNT_PERMISSION_FEE"),
    ("MULTI_SIGN_FEE", b"MULTI_SIGN_FEE"),
    ("SHIELDED_TRANSACTION_FEE", b"SHIELDED_TRANSACTION_FEE"),
    ("SHIELDED_TRANSACTION_CREATE_ACCOUNT_FEE", b"SHIELDED_TRANSACTION_CREATE_ACCOUNT_FEE"),
    ("TOTAL_SHIELDED_POOL_VALUE", b"TOTAL_SHIELDED_POOL_VALUE"),
    ("EXCHANGE_CREATE_FEE", b"EXCHANGE_CREATE_FEE"),
    ("EXCHANGE_BALANCE_LIMIT", b"EXCHANGE_BALANCE_LIMIT"),
    ("TOTAL_TRANSACTION_COST", b"TOTAL_TRANSACTION_COST"),
    ("TOTAL_CREATE_ACCOUNT_COST", b"TOTAL_CREATE_ACCOUNT_COST"),
    ("TOTAL_CREATE_WITNESS_COST", b"TOTAL_CREATE_WITNESS_FEE"),
    ("TOTAL_STORAGE_POOL", b"TOTAL_STORAGE_POOL"),
    ("TOTAL_STORAGE_TAX", b"TOTAL_STORAGE_TAX"),
    ("TOTAL_STORAGE_RESERVED", b"TOTAL_STORAGE_RESERVED"),
    ("STORAGE_EXCHANGE_TAX_RATE", b"STORAGE_EXCHANGE_TAX_RATE"),
    ("VERSION_NUMBER", b"VERSION_NUMBER"),
    ("REMOVE_THE_POWER_OF_THE_GR", b"REMOVE_THE_POWER_OF_THE_GR"),
    ("ALLOW_DELEGATE_RESOURCE", b"ALLOW_DELEGATE_RESOURCE"),
    ("ALLOW_ADAPTIVE_ENERGY", b"ALLOW_ADAPTIVE_ENERGY"),
    ("ALLOW_UPDATE_ACCOUNT_NAME", b"ALLOW_UPDATE_ACCOUNT_NAME"),
    ("ALLOW_SAME_TOKEN_NAME", b" ALLOW_SAME_TOKEN_NAME"),
    ("ALLOW_CREATION_OF_CONTRACTS", b"ALLOW_CREATION_OF_CONTRACTS"),
    ("TOTAL_SIGN_NUM", b"TOTAL_SIGN_NUM"),
    ("ALLOW_MULTI_SIGN", b"ALLOW_MULTI_SIGN"),
    ("TOKEN_ID_NUM", b"TOKEN_ID_NUM"),
    ("TOKEN_UPDATE_DONE", b"TOKEN_UPDATE_DONE"),
    ("ABI_MOVE_DONE", b"ABI_MOVE_DONE"),
    ("ALLOW_TVM_TRANSFER_TRC10", b"ALLOW_TVM_TRANSFER_TRC10"),
    ("ALLOW_SHIELDED_TRANSACTION", b"ALLOW_SHIELDED_TRANSACTION"),
    ("ALLOW_SHIELDED_TRC20_TRANSACTION", b"ALLOW_SHIELDED_TRC20_TRANSACTION"),
    ("ALLOW_TVM_ISTANBUL", b"ALLOW_TVM_ISTANBUL"),
    ("ALLOW_TVM_CONSTANTINOPLE", b"ALLOW_TVM_CONSTANTINOPLE"),
    ("ALLOW_TVM_SOLIDITY_059", b"ALLOW_TVM_SOLIDITY_059"),
    ("FORBID_TRANSFER_TO_CONTRACT", b"FORBID_TRANSFER_TO_CONTRACT"),
    ("ALLOW_PROTO_FILTER_NUM", b"ALLOW_PROTO_FILTER_NUM"),
    ("AVAILABLE_CONTRACT_TYPE", b"AVAILABLE_CONTRACT_TYPE"),
    ("ACTIVE_DEFAULT_OPERATIONS", b"ACTIVE_DEFAULT_OPERATIONS"),
    ("ALLOW_ACCOUNT_STATE_ROOT", b"ALLOW_ACCOUNT_STATE_ROOT"),
    ("CURRENT_CYCLE_NUMBER", b"CURRENT_CYCLE_NUMBER"),
    ("CHANGE_DELEGATION", b"CHANGE_DELEGATION"),
    ("ALLOW_PBFT", b"ALLOW_PBFT"),
    ("ALLOW_MARKET_TRANSACTION", b"ALLOW_MARKET_TRANSACTION"),
    ("MARKET_SELL_FEE", b"MARKET_SELL_FEE"),
    ("MARKET_CANCEL_FEE", b"MARKET_CANCEL_FEE"),
    ("MARKET_QUANTITY_LIMIT", b"MARKET_QUANTITY_LIMIT"),
    ("ALLOW_TRANSACTION_FEE_POOL", b"ALLOW_TRANSACTION_FEE_POOL"),
    ("TRANSACTION_FEE_POOL", b"TRANSACTION_FEE_POOL"),
    ("MAX_FEE_LIMIT", b"MAX_FEE_LIMIT"),
    ("BURN_TRX_AMOUNT", b"BURN_TRX_AMOUNT"),
    ("ALLOW_BLACKHOLE_OPTIMIZATION", b"ALLOW_BLACKHOLE_OPTIMIZATION"),
    ("ALLOW_NEW_RESOURCE_MODEL", b"ALLOW_NEW_RESOURCE_MODEL"),
    ("ALLOW_TVM_FREEZE", b"ALLOW_TVM_FREEZE"),
    ("ALLOW_TVM_VOTE", b"ALLOW_TVM_VOTE"),
    ("ALLOW_TVM_LONDON", b"ALLOW_TVM_LONDON"),
    ("ALLOW_TVM_COMPATIBLE_EVM", b"ALLOW_TVM_COMPATIBLE_EVM"),
    ("NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE", b"NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE"),
    ("ALLOW_ACCOUNT_ASSET_OPTIMIZATION", b"ALLOW_ACCOUNT_ASSET_OPTIMIZATION"),
    ("ALLOW_ASSET_OPTIMIZATION", b"ALLOW_ASSET_OPTIMIZATION"),
    ("ENERGY_PRICE_HISTORY", b"ENERGY_PRICE_HISTORY"),
    ("ENERGY_PRICE_HISTORY_DONE", b"ENERGY_PRICE_HISTORY_DONE"),
    ("BANDWIDTH_PRICE_HISTORY", b"BANDWIDTH_PRICE_HISTORY"),
    ("BANDWIDTH_PRICE_HISTORY_DONE", b"BANDWIDTH_PRICE_HISTORY_DONE"),
    ("SET_BLACKHOLE_ACCOUNT_PERMISSION", b"SET_BLACKHOLE_ACCOUNT_PERMISSION"),
    ("ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX", b"ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX"),
    ("ALLOW_NEW_REWARD", b"ALLOW_NEW_REWARD"),
    ("MEMO_FEE", b"MEMO_FEE"),
    ("MEMO_FEE_HISTORY", b"MEMO_FEE_HISTORY"),
    ("ALLOW_DELEGATE_OPTIMIZATION", b"ALLOW_DELEGATE_OPTIMIZATION"),
    ("ALLOW_DYNAMIC_ENERGY", b"ALLOW_DYNAMIC_ENERGY"),
    ("DYNAMIC_ENERGY_THRESHOLD", b"DYNAMIC_ENERGY_THRESHOLD"),
    ("DYNAMIC_ENERGY_INCREASE_FACTOR", b"DYNAMIC_ENERGY_INCREASE_FACTOR"),
    ("DYNAMIC_ENERGY_MAX_FACTOR", b"DYNAMIC_ENERGY_MAX_FACTOR"),
    ("UNFREEZE_DELAY_DAYS", b"UNFREEZE_DELAY_DAYS"),
    ("ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID", b"ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID"),
    ("ALLOW_TVM_SHANGHAI", b"ALLOW_TVM_SHANGHAI"),
    ("ALLOW_CANCEL_ALL_UNFREEZE_V2", b"ALLOW_CANCEL_ALL_UNFREEZE_V2"),
    ("MAX_DELEGATE_LOCK_PERIOD", b"MAX_DELEGATE_LOCK_PERIOD"),
    ("ALLOW_OLD_REWARD_OPT", b"ALLOW_OLD_REWARD_OPT"),
    ("ALLOW_ENERGY_ADJUSTMENT", b"ALLOW_ENERGY_ADJUSTMENT"),
    ("MAX_CREATE_ACCOUNT_TX_SIZE", b"MAX_CREATE_ACCOUNT_TX_SIZE"),
    ("ALLOW_STRICT_MATH", b"ALLOW_STRICT_MATH"),
    ("CONSENSUS_LOGIC_OPTIMIZATION", b"CONSENSUS_LOGIC_OPTIMIZATION"),
    ("ALLOW_TVM_CANCUN", b"ALLOW_TVM_CANCUN"),
    ("ALLOW_TVM_BLOB", b"ALLOW_TVM_BLOB"),
    ("PROPOSAL_EXPIRE_TIME", b"PROPOSAL_EXPIRE_TIME"),
    ("ALLOW_TVM_SELFDESTRUCT_RESTRICTION", b"ALLOW_TVM_SELFDESTRUCT_RESTRICTION"),
    ("ALLOW_TVM_OSAKA", b"ALLOW_TVM_OSAKA"),
    ("ALLOW_TVM_PRAGUE", b"ALLOW_TVM_PRAGUE"),
    ("BLOCK_HASH_HISTORY_INSTALLED", b"BLOCK_HASH_HISTORY_INSTALLED"),
    ("ALLOW_HARDEN_RESOURCE_CALCULATION", b"ALLOW_HARDEN_RESOURCE_CALCULATION"),
    ("ALLOW_HARDEN_EXCHANGE_CALCULATION", b"ALLOW_HARDEN_EXCHANGE_CALCULATION"),
    ("TURKISH_KEY_MIGRATION_DONE", b"TURKISH_KEY_MIGRATION_DONE"),
    ("ONE_DAY_NET_LIMIT", b"ONE_DAY_NET_LIMIT"),
    ("PUBLIC_NET_USAGE", b"PUBLIC_NET_USAGE"),
    ("PUBLIC_NET_LIMIT", b"PUBLIC_NET_LIMIT"),
    ("PUBLIC_NET_TIME", b"PUBLIC_NET_TIME"),
    ("FREE_NET_LIMIT", b"FREE_NET_LIMIT"),
    ("TOTAL_NET_WEIGHT", b"TOTAL_NET_WEIGHT"),
    ("TOTAL_NET_LIMIT", b"TOTAL_NET_LIMIT"),
    ("TOTAL_ENERGY_TARGET_LIMIT", b"TOTAL_ENERGY_TARGET_LIMIT"),
    ("TOTAL_ENERGY_CURRENT_LIMIT", b"TOTAL_ENERGY_CURRENT_LIMIT"),
    ("TOTAL_ENERGY_AVERAGE_USAGE", b"TOTAL_ENERGY_AVERAGE_USAGE"),
    ("TOTAL_ENERGY_AVERAGE_TIME", b"TOTAL_ENERGY_AVERAGE_TIME"),
    ("TOTAL_ENERGY_WEIGHT", b"TOTAL_ENERGY_WEIGHT"),
    ("TOTAL_TRON_POWER_WEIGHT", b"TOTAL_TRON_POWER_WEIGHT"),
    ("TOTAL_ENERGY_LIMIT", b"TOTAL_ENERGY_LIMIT"),
    ("BLOCK_ENERGY_USAGE", b"BLOCK_ENERGY_USAGE"),
    ("ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER", b"ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER"),
    ("ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO", b"ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO"),
];

/// Constructor-initialized defaults retain the canonical Java save expression.
pub const DEFAULTS: &[(&str, &str, &str)] = &[
    ("getTotalSignNum", "saveTotalSignNum", "5"),
    ("getAllowMultiSign", "saveAllowMultiSign", "CommonParameter.getInstance() .getAllowMultiSign()"),
    ("getLatestBlockHeaderTimestamp", "saveLatestBlockHeaderTimestamp", "0"),
    ("getLatestBlockHeaderNumber", "saveLatestBlockHeaderNumber", "0"),
    ("getLatestBlockHeaderHash", "saveLatestBlockHeaderHash", "ByteString.copyFrom(ByteArray.fromHexString(\"00\"))"),
    ("getStateFlag", "saveStateFlag", "0"),
    ("getLatestSolidifiedBlockNum", "saveLatestSolidifiedBlockNum", "0"),
    ("getLatestProposalNum", "saveLatestProposalNum", "0"),
    ("getLatestExchangeNum", "saveLatestExchangeNum", "0"),
    ("getBlockFilledSlotsIndex", "saveBlockFilledSlotsIndex", "0"),
    ("getTokenIdNum", "saveTokenIdNum", "1000000L"),
    ("getTokenUpdateDone", "saveTokenUpdateDone", "0"),
    ("getAbiMoveDone", "saveAbiMoveDone", "0"),
    ("getMaxFrozenTime", "saveMaxFrozenTime", "3"),
    ("getMinFrozenTime", "saveMinFrozenTime", "3"),
    ("getMaxFrozenSupplyNumber", "saveMaxFrozenSupplyNumber", "10"),
    ("getMaxFrozenSupplyTime", "saveMaxFrozenSupplyTime", "3652"),
    ("getMinFrozenSupplyTime", "saveMinFrozenSupplyTime", "1"),
    ("getWitnessAllowanceFrozenTime", "saveWitnessAllowanceFrozenTime", "1"),
    ("getWitnessPayPerBlock", "saveWitnessPayPerBlock", "32000000L"),
    ("getWitnessStandbyAllowance", "saveWitnessStandbyAllowance", "115_200_000_000L"),
    ("getMaintenanceTimeInterval", "saveMaintenanceTimeInterval", "CommonParameter.getInstance() .getMaintenanceTimeInterval()"),
    ("getAccountUpgradeCost", "saveAccountUpgradeCost", "9_999_000_000L"),
    ("getPublicNetUsage", "savePublicNetUsage", "0L"),
    ("getOneDayNetLimit", "saveOneDayNetLimit", "57_600_000_000L"),
    ("getPublicNetLimit", "savePublicNetLimit", "14_400_000_000L"),
    ("getPublicNetTime", "savePublicNetTime", "0L"),
    ("getFreeNetLimit", "saveFreeNetLimit", "5000L"),
    ("getTotalNetWeight", "saveTotalNetWeight", "0L"),
    ("getTotalNetLimit", "saveTotalNetLimit", "43_200_000_000L"),
    ("getTotalEnergyWeight", "saveTotalEnergyWeight", "0L"),
    ("getTotalTronPowerWeight", "saveTotalTronPowerWeight", "0L"),
    ("getAllowAdaptiveEnergy", "saveAllowAdaptiveEnergy", "CommonParameter.getInstance() .getAllowAdaptiveEnergy()"),
    ("getAdaptiveResourceLimitTargetRatio", "saveAdaptiveResourceLimitTargetRatio", "14400"),
    ("getTotalEnergyLimit", "saveTotalEnergyLimit", "50_000_000_000L"),
    ("getEnergyFee", "saveEnergyFee", "DEFAULT_ENERGY_FEE"),
    ("getMaxCpuTimeOfOneTx", "saveMaxCpuTimeOfOneTx", "50L"),
    ("getCreateAccountFee", "saveCreateAccountFee", "100_000L"),
    ("getShieldedTransactionFee", "saveShieldedTransactionFee", "100_000L"),
    ("getShieldedTransactionCreateAccountFee", "saveShieldedTransactionCreateAccountFee", "1_000_000L"),
    ("getTotalShieldedPoolValue", "saveTotalShieldedPoolValue", "0L"),
    ("getCreateNewAccountFeeInSystemContract", "saveCreateNewAccountFeeInSystemContract", "0L"),
    ("getCreateNewAccountBandwidthRate", "saveCreateNewAccountBandwidthRate", "1L"),
    ("getTransactionFee", "saveTransactionFee", "DEFAULT_TRANSACTION_FEE"),
    ("getAssetIssueFee", "saveAssetIssueFee", "1024000000L"),
    ("getUpdateAccountPermissionFee", "saveUpdateAccountPermissionFee", "100000000L"),
    ("getMultiSignFee", "saveMultiSignFee", "1000000L"),
    ("getExchangeCreateFee", "saveExchangeCreateFee", "1024000000L"),
    ("getExchangeBalanceLimit", "saveExchangeBalanceLimit", "1_000_000_000_000_000L"),
    ("getAllowMarketTransaction", "saveAllowMarketTransaction", "CommonParameter.getInstance().getAllowMarketTransaction()"),
    ("getMarketSellFee", "saveMarketSellFee", "0L"),
    ("getMarketCancelFee", "saveMarketCancelFee", "0L"),
    ("getMarketQuantityLimit", "saveMarketQuantityLimit", "1_000_000_000_000_000L"),
    ("getAllowTransactionFeePool", "saveAllowTransactionFeePool", "CommonParameter.getInstance().getAllowTransactionFeePool()"),
    ("getTransactionFeePool", "saveTransactionFeePool", "0L"),
    ("getTotalTransactionCost", "saveTotalTransactionCost", "0L"),
    ("getTotalCreateWitnessCost", "saveTotalCreateWitnessFee", "0L"),
    ("getTotalCreateAccountCost", "saveTotalCreateAccountFee", "0L"),
    ("getTotalStoragePool", "saveTotalStoragePool", "100_000_000_000_000L"),
    ("getTotalStorageTax", "saveTotalStorageTax", "0"),
    ("getTotalStorageReserved", "saveTotalStorageReserved", "128L * 1024 * 1024 * 1024"),
    ("getStorageExchangeTaxRate", "saveStorageExchangeTaxRate", "10"),
    ("getRemoveThePowerOfTheGr", "saveRemoveThePowerOfTheGr", "0"),
    ("getAllowDelegateResource", "saveAllowDelegateResource", "CommonParameter.getInstance() .getAllowDelegateResource()"),
    ("getAllowTvmTransferTrc10", "saveAllowTvmTransferTrc10", "CommonParameter.getInstance() .getAllowTvmTransferTrc10()"),
    ("getAllowTvmConstantinople", "saveAllowTvmConstantinople", "CommonParameter.getInstance() .getAllowTvmConstantinople()"),
    ("getAllowTvmSolidity059", "saveAllowTvmSolidity059", "CommonParameter.getInstance() .getAllowTvmSolidity059()"),
    ("getForbidTransferToContract", "saveForbidTransferToContract", "CommonParameter.getInstance() .getForbidTransferToContract()"),
    ("getAvailableContractType", "saveAvailableContractType", "bytes"),
    ("getActiveDefaultOperations", "saveActiveDefaultOperations", "bytes"),
    ("getAllowSameTokenName", "saveAllowSameTokenName", "CommonParameter.getInstance() .getAllowSameTokenName()"),
    ("getAllowUpdateAccountName", "saveAllowUpdateAccountName", "0"),
    ("getAllowCreationOfContracts", "saveAllowCreationOfContracts", "CommonParameter.getInstance() .getAllowCreationOfContracts()"),
    ("getAllowShieldedTransaction", "saveAllowShieldedTransaction", "0L"),
    ("getAllowShieldedTRC20Transaction", "saveAllowShieldedTRC20Transaction", "CommonParameter.getInstance().getAllowShieldedTRC20Transaction()"),
    ("getAllowTvmIstanbul", "saveAllowTvmIstanbul", "CommonParameter.getInstance().getAllowTvmIstanbul()"),
    ("getBlockFilledSlots", "saveBlockFilledSlots", "blockFilledSlots"),
    ("getNextMaintenanceTime", "saveNextMaintenanceTime", "Long.parseLong(CommonParameter.getInstance() .getGenesisBlock().getTimestamp())"),
    ("getTotalEnergyCurrentLimit", "saveTotalEnergyCurrentLimit", "getTotalEnergyLimit()"),
    ("getTotalEnergyTargetLimit", "saveTotalEnergyTargetLimit", "getTotalEnergyLimit() / 14400"),
    ("getTotalEnergyAverageUsage", "saveTotalEnergyAverageUsage", "0"),
    ("getAdaptiveResourceLimitMultiplier", "saveAdaptiveResourceLimitMultiplier", "1000"),
    ("getTotalEnergyAverageTime", "saveTotalEnergyAverageTime", "0"),
    ("getBlockEnergyUsage", "saveBlockEnergyUsage", "0"),
    ("getAllowAccountStateRoot", "saveAllowAccountStateRoot", "CommonParameter.getInstance() .getAllowAccountStateRoot()"),
    ("getAllowProtoFilterNum", "saveAllowProtoFilterNum", "CommonParameter.getInstance() .getAllowProtoFilterNum()"),
    ("getChangeDelegation", "saveChangeDelegation", "CommonParameter.getInstance() .getChangedDelegation()"),
    ("getAllowPBFT", "saveAllowPBFT", "CommonParameter.getInstance().getAllowPBFT()"),
    ("getMaxFeeLimit", "saveMaxFeeLimit", "1_000_000_000L"),
    ("getBurnTrxAmount", "saveBurnTrx", "0L"),
    ("getAllowBlackHoleOptimization", "saveAllowBlackHoleOptimization", "CommonParameter.getInstance().getAllowBlackHoleOptimization()"),
    ("getAllowNewResourceModel", "saveAllowNewResourceModel", "CommonParameter.getInstance().getAllowNewResourceModel()"),
    ("getAllowTvmFreeze", "saveAllowTvmFreeze", "CommonParameter.getInstance().getAllowTvmFreeze()"),
    ("getAllowTvmVote", "saveAllowTvmVote", "CommonParameter.getInstance().getAllowTvmVote()"),
    ("getAllowTvmLondon", "saveAllowTvmLondon", "CommonParameter.getInstance().getAllowTvmLondon()"),
    ("getAllowTvmCompatibleEvm", "saveAllowTvmCompatibleEvm", "CommonParameter.getInstance().getAllowTvmCompatibleEvm()"),
    ("getEnergyPriceHistoryDone", "saveEnergyPriceHistoryDone", "0"),
    ("getEnergyPriceHistory", "saveEnergyPriceHistory", "DEFAULT_ENERGY_PRICE_HISTORY"),
    ("getBandwidthPriceHistoryDone", "saveBandwidthPriceHistoryDone", "0"),
    ("getBandwidthPriceHistory", "saveBandwidthPriceHistory", "DEFAULT_BANDWIDTH_PRICE_HISTORY"),
    ("getSetBlackholeAccountPermission", "saveSetBlackholePermission", "0"),
    ("getAllowHigherLimitForMaxCpuTimeOfOneTx", "saveAllowHigherLimitForMaxCpuTimeOfOneTx", "CommonParameter.getInstance().getAllowHigherLimitForMaxCpuTimeOfOneTx()"),
    ("getAllowNewReward", "saveAllowNewReward", "CommonParameter.getInstance().getAllowNewReward()"),
    ("getMemoFee", "saveMemoFee", "memoFee"),
    ("getAllowDelegateOptimization", "saveAllowDelegateOptimization", "CommonParameter.getInstance().getAllowDelegateOptimization()"),
    ("getUnfreezeDelayDays", "saveUnfreezeDelayDays", "CommonParameter.getInstance().getUnfreezeDelayDays()"),
    ("getAllowOptimizedReturnValueOfChainId", "saveAllowOptimizedReturnValueOfChainId", "CommonParameter.getInstance().getAllowOptimizedReturnValueOfChainId()"),
    ("getAllowDynamicEnergy", "saveAllowDynamicEnergy", "CommonParameter.getInstance().getAllowDynamicEnergy()"),
    ("getDynamicEnergyThreshold", "saveDynamicEnergyThreshold", "CommonParameter.getInstance().getDynamicEnergyThreshold()"),
    ("getDynamicEnergyIncreaseFactor", "saveDynamicEnergyIncreaseFactor", "CommonParameter.getInstance().getDynamicEnergyIncreaseFactor()"),
    ("getDynamicEnergyMaxFactor", "saveDynamicEnergyMaxFactor", "CommonParameter.getInstance().getDynamicEnergyMaxFactor()"),
];

#[must_use] pub fn key(name: &str) -> Option<&'static [u8]> { KEYS.iter().find_map(|(n,k)| (*n == name).then_some(*k)) }
#[must_use] pub fn default_expression(getter: &str) -> Option<&'static str> { DEFAULTS.iter().find_map(|(g,_,v)| (*g == getter).then_some(*v)) }

use crate::TypedStore;

pub const AVAILABLE_CONTRACT_TYPES: [u8; 32] = [
    0x7f, 0xff, 0x1f, 0xc0, 0x03, 0x7e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Values supplied by Java's `CommonParameter` singleton to the constructor.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DynamicPropertyConfig {
    pub allow_multi_sign: i64,
    pub maintenance_time_interval: i64,
    pub allow_adaptive_energy: i64,
    pub allow_market_transaction: i64,
    pub allow_transaction_fee_pool: i64,
    pub allow_delegate_resource: i64,
    pub allow_tvm_transfer_trc10: i64,
    pub allow_tvm_constantinople: i64,
    pub allow_tvm_solidity_059: i64,
    pub forbid_transfer_to_contract: i64,
    pub allow_same_token_name: i64,
    pub allow_creation_of_contracts: i64,
    pub allow_shielded_trc20_transaction: i64,
    pub allow_tvm_istanbul: i64,
    pub allow_account_state_root: i64,
    pub allow_proto_filter_num: i64,
    pub changed_delegation: i64,
    pub allow_pbft: i64,
    pub allow_blackhole_optimization: i64,
    pub allow_new_resource_model: i64,
    pub allow_tvm_freeze: i64,
    pub allow_tvm_vote: i64,
    pub allow_tvm_london: i64,
    pub allow_tvm_compatible_evm: i64,
    pub allow_asset_optimization: i64,
    pub allow_account_asset_optimization: i64,
    pub allow_higher_limit_for_max_cpu_time_of_one_tx: i64,
    pub allow_new_reward_algorithm: i64,
    pub allow_new_reward: i64,
    pub memo_fee: i64,
    pub allow_delegate_optimization: i64,
    pub unfreeze_delay_days: i64,
    pub allow_optimized_return_value_of_chain_id: i64,
    pub allow_dynamic_energy: i64,
    pub dynamic_energy_threshold: i64,
    pub dynamic_energy_increase_factor: i64,
    pub dynamic_energy_max_factor: i64,
}

fn property_key(symbol: &str) -> &'static [u8] {
    key(symbol).unwrap_or_else(|| panic!("unknown dynamic property key {symbol}"))
}

fn initialize_paired_default(
    store: &TypedStore,
    source_key: &'static [u8],
    source_default: &[u8],
    derived_key: &'static [u8],
    derive: impl FnOnce(&[u8]) -> Vec<u8>,
) -> tron_storage::Result<usize> {
    let source = store.get(source_key);
    if store.contains_key(derived_key) {
        if source.is_some() { return Ok(0); }
        return store.put_if_absent(source_key, source_default).map(usize::from);
    }

    let source_value = source.as_deref().unwrap_or(source_default);
    let derived_value = derive(source_value);
    let mut batch = store.batch();
    if source.is_none() { batch.put(store.name(), source_key, source_default); }
    batch.put(store.name(), derived_key, &derived_value);
    batch.commit()?;
    Ok(usize::from(source.is_none()) + 1)
}

fn java_bytes_to_long(bytes: &[u8]) -> i64 {
    let mut value = [0_u8; 8];
    let suffix = bytes.get(bytes.len().saturating_sub(value.len())..).unwrap_or(bytes);
    value[8 - suffix.len()..].copy_from_slice(suffix);
    i64::from_be_bytes(value)
}

/// Installs exactly the values written by Java's constructor, without replacing persisted state.
/// Integer values use Java `ByteArray.fromInt/fromLong` big-endian encodings; byte and string
/// capsules are stored as their raw payloads.
pub fn initialize_missing(
    store: &TypedStore,
    config: &DynamicPropertyConfig,
    genesis_timestamp: i64,
    active_default_operations: &[u8],
) -> tron_storage::Result<usize> {
    let mut inserted = 0;
    macro_rules! raw { ($key:literal, $value:expr) => {{
        let value = $value;
        inserted += usize::from(store.put_if_absent(property_key($key), value.as_ref())?);
    }} }
    macro_rules! long { ($key:literal, $value:expr) => { raw!($key, ($value as i64).to_be_bytes()) } }
    macro_rules! int { ($key:literal, $value:expr) => { raw!($key, ($value as i32).to_be_bytes()) } }

    int!("TOTAL_SIGN_NUM", 5);
    long!("ALLOW_MULTI_SIGN", config.allow_multi_sign);
    long!("LATEST_BLOCK_HEADER_TIMESTAMP", 0);
    long!("LATEST_BLOCK_HEADER_NUMBER", 0);
    raw!("LATEST_BLOCK_HEADER_HASH", [0_u8]);
    int!("STATE_FLAG", 0);
    long!("LATEST_SOLIDIFIED_BLOCK_NUM", 0);
    long!("LATEST_PROPOSAL_NUM", 0);
    long!("LATEST_EXCHANGE_NUM", 0);
    int!("BLOCK_FILLED_SLOTS_INDEX", 0);
    long!("TOKEN_ID_NUM", 1_000_000);
    long!("TOKEN_UPDATE_DONE", 0);
    long!("ABI_MOVE_DONE", 0);
    int!("MAX_FROZEN_TIME", 3);
    int!("MIN_FROZEN_TIME", 3);
    int!("MAX_FROZEN_SUPPLY_NUMBER", 10);
    int!("MAX_FROZEN_SUPPLY_TIME", 3652);
    int!("MIN_FROZEN_SUPPLY_TIME", 1);
    int!("WITNESS_ALLOWANCE_FROZEN_TIME", 1);
    long!("WITNESS_PAY_PER_BLOCK", 32_000_000);
    long!("WITNESS_STANDBY_ALLOWANCE", 115_200_000_000_i64);
    long!("MAINTENANCE_TIME_INTERVAL", config.maintenance_time_interval);
    long!("ACCOUNT_UPGRADE_COST", 9_999_000_000_i64);
    long!("PUBLIC_NET_USAGE", 0);
    long!("ONE_DAY_NET_LIMIT", 57_600_000_000_i64);
    long!("PUBLIC_NET_LIMIT", 14_400_000_000_i64);
    long!("PUBLIC_NET_TIME", 0);
    long!("FREE_NET_LIMIT", 5000);
    long!("TOTAL_NET_WEIGHT", 0);
    long!("TOTAL_NET_LIMIT", 43_200_000_000_i64);
    long!("TOTAL_ENERGY_WEIGHT", 0);
    long!("TOTAL_TRON_POWER_WEIGHT", 0);
    long!("ALLOW_ADAPTIVE_ENERGY", config.allow_adaptive_energy);
    long!("ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO", 14_400);
    long!("TOTAL_ENERGY_LIMIT", 50_000_000_000_i64);
    long!("ENERGY_FEE", 100);
    long!("MAX_CPU_TIME_OF_ONE_TX", 50);
    long!("CREATE_ACCOUNT_FEE", 100_000);
    long!("SHIELDED_TRANSACTION_FEE", 100_000);
    long!("SHIELDED_TRANSACTION_CREATE_ACCOUNT_FEE", 1_000_000);
    long!("TOTAL_SHIELDED_POOL_VALUE", 0);
    long!("CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", 0);
    long!("CREATE_NEW_ACCOUNT_BANDWIDTH_RATE", 1);
    long!("TRANSACTION_FEE", 10);
    long!("ASSET_ISSUE_FEE", 1_024_000_000);
    long!("UPDATE_ACCOUNT_PERMISSION_FEE", 100_000_000);
    long!("MULTI_SIGN_FEE", 1_000_000);
    long!("EXCHANGE_CREATE_FEE", 1_024_000_000);
    long!("EXCHANGE_BALANCE_LIMIT", 1_000_000_000_000_000_i64);
    long!("ALLOW_MARKET_TRANSACTION", config.allow_market_transaction);
    long!("MARKET_SELL_FEE", 0);
    long!("MARKET_CANCEL_FEE", 0);
    long!("MARKET_QUANTITY_LIMIT", 1_000_000_000_000_000_i64);
    long!("ALLOW_TRANSACTION_FEE_POOL", config.allow_transaction_fee_pool);
    long!("TRANSACTION_FEE_POOL", 0);
    long!("TOTAL_TRANSACTION_COST", 0);
    long!("TOTAL_CREATE_WITNESS_COST", 0);
    long!("TOTAL_CREATE_ACCOUNT_COST", 0);
    long!("TOTAL_STORAGE_POOL", 100_000_000_000_000_i64);
    long!("TOTAL_STORAGE_TAX", 0);
    long!("TOTAL_STORAGE_RESERVED", 137_438_953_472_i64);
    long!("STORAGE_EXCHANGE_TAX_RATE", 10);
    long!("REMOVE_THE_POWER_OF_THE_GR", 0);
    long!("ALLOW_DELEGATE_RESOURCE", config.allow_delegate_resource);
    long!("ALLOW_TVM_TRANSFER_TRC10", config.allow_tvm_transfer_trc10);
    long!("ALLOW_TVM_CONSTANTINOPLE", config.allow_tvm_constantinople);
    long!("ALLOW_TVM_SOLIDITY_059", config.allow_tvm_solidity_059);
    long!("FORBID_TRANSFER_TO_CONTRACT", config.forbid_transfer_to_contract);
    raw!("AVAILABLE_CONTRACT_TYPE", AVAILABLE_CONTRACT_TYPES);
    raw!("ACTIVE_DEFAULT_OPERATIONS", active_default_operations);
    long!("ALLOW_SAME_TOKEN_NAME", config.allow_same_token_name);
    long!("ALLOW_UPDATE_ACCOUNT_NAME", 0);
    long!("ALLOW_CREATION_OF_CONTRACTS", config.allow_creation_of_contracts);
    long!("ALLOW_SHIELDED_TRANSACTION", 0);
    long!("ALLOW_SHIELDED_TRC20_TRANSACTION", config.allow_shielded_trc20_transaction);
    long!("ALLOW_TVM_ISTANBUL", config.allow_tvm_istanbul);
    raw!("BLOCK_FILLED_SLOTS", [b'1'; 128]);
    long!("NEXT_MAINTENANCE_TIME", genesis_timestamp);
    long!("TOTAL_ENERGY_CURRENT_LIMIT", 50_000_000_000_i64);
    long!("TOTAL_ENERGY_TARGET_LIMIT", 50_000_000_000_i64 / 14_400);
    long!("TOTAL_ENERGY_AVERAGE_USAGE", 0);
    long!("ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER", 1000);
    long!("TOTAL_ENERGY_AVERAGE_TIME", 0);
    long!("BLOCK_ENERGY_USAGE", 0);
    long!("ALLOW_ACCOUNT_STATE_ROOT", config.allow_account_state_root);
    long!("ALLOW_PROTO_FILTER_NUM", config.allow_proto_filter_num);
    long!("CHANGE_DELEGATION", config.changed_delegation);
    long!("ALLOW_PBFT", config.allow_pbft);
    long!("MAX_FEE_LIMIT", 1_000_000_000);
    long!("BURN_TRX_AMOUNT", 0);
    long!("ALLOW_BLACKHOLE_OPTIMIZATION", config.allow_blackhole_optimization);
    long!("ALLOW_NEW_RESOURCE_MODEL", config.allow_new_resource_model);
    long!("ALLOW_TVM_FREEZE", config.allow_tvm_freeze);
    long!("ALLOW_TVM_VOTE", config.allow_tvm_vote);
    long!("ALLOW_TVM_LONDON", config.allow_tvm_london);
    long!("ALLOW_TVM_COMPATIBLE_EVM", config.allow_tvm_compatible_evm);
    long!("ALLOW_ASSET_OPTIMIZATION", config.allow_asset_optimization);
    long!("ALLOW_ACCOUNT_ASSET_OPTIMIZATION", config.allow_account_asset_optimization);
    long!("ENERGY_PRICE_HISTORY_DONE", 0);
    raw!("ENERGY_PRICE_HISTORY", b"0:100");
    long!("BANDWIDTH_PRICE_HISTORY_DONE", 0);
    raw!("BANDWIDTH_PRICE_HISTORY", b"0:10");
    long!("SET_BLACKHOLE_ACCOUNT_PERMISSION", 0);
    long!("ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX", config.allow_higher_limit_for_max_cpu_time_of_one_tx);
    let reward_cycle = if config.allow_tvm_vote == 1 || config.allow_new_reward_algorithm == 1 || config.allow_new_reward == 1 { 0 } else { i64::MAX };
    long!("NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE", reward_cycle);
    long!("ALLOW_NEW_REWARD", config.allow_new_reward);
    let memo_fee = config.memo_fee.to_be_bytes();
    inserted += initialize_paired_default(
        store,
        property_key("MEMO_FEE"),
        &memo_fee,
        property_key("MEMO_FEE_HISTORY"),
        |fee| format!("0:{}", java_bytes_to_long(fee)).into_bytes(),
    )?;
    long!("ALLOW_DELEGATE_OPTIMIZATION", config.allow_delegate_optimization);
    long!("UNFREEZE_DELAY_DAYS", config.unfreeze_delay_days);
    long!("ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID", config.allow_optimized_return_value_of_chain_id);
    long!("ALLOW_DYNAMIC_ENERGY", config.allow_dynamic_energy);
    long!("DYNAMIC_ENERGY_THRESHOLD", config.dynamic_energy_threshold);
    long!("DYNAMIC_ENERGY_INCREASE_FACTOR", config.dynamic_energy_increase_factor);
    long!("DYNAMIC_ENERGY_MAX_FACTOR", config.dynamic_energy_max_factor);
    Ok(inserted)
}
