use std::{collections::{BTreeMap, BTreeSet}, sync::{Arc, RwLock}};

use prost::Message;
use tron_config::Config;
use tron_crypto::{derive_address, selected_digest, CryptoEngine, PublicKey, RecoverableSignature};
use tron_execution::{ActuatorError, BlockApplyHooks, BlockConsensus, ExecutionContext, RewardCallback};
use tron_primitives::BlockId;
use tron_protocol::protocol::{Account, Witness};
use tron_state::{GenesisConfig, Session, SessionManager, StoreKind};

use crate::{
    account_block_production, adjust_allowance, apply_filled_slot, apply_maintenance_block,
    java_fork_pass, pay_block_reward, pay_fee_pool_reward, pay_standby_rewards,
    process_expired_proposals, update_fork, update_solidity, withdraw_reward, BackupRole,
    ConsensusRead, DposSlot, ForkSpec, ForkState, MaintenanceConfig, ParameterRule,
    SlotContext, StateFacade, SystemClock, sort_witnesses, pbft::{PbftBounds, PbftSidecar},
};

pub const MAINTENANCE_SKIP_SLOTS: i64 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProductionConsensusError {
    InvalidGenesisTime,
    InvalidGenesisWitness(String),
    UnsupportedSm2Pbft,
    State(String),
}
impl core::fmt::Display for ProductionConsensusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "production consensus error: {self:?}") }
}
impl std::error::Error for ProductionConsensusError {}

#[derive(Clone)]
pub struct BackupRoleHandle(Arc<RwLock<BackupRole>>);
impl BackupRoleHandle {
    #[must_use] pub fn new(role: BackupRole) -> Self { Self(Arc::new(RwLock::new(role))) }
    #[must_use] pub fn role(&self) -> BackupRole { self.0.read().map_or(BackupRole::Backup, |role| *role) }
    pub fn set_role(&self, role: BackupRole) -> Result<(), ProductionConsensusError> {
        *self.0.write().map_err(|_| ProductionConsensusError::State("backup role lock poisoned".into()))? = role;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ProductionPbftHandle {
    enabled: bool,
    sidecar: Arc<std::sync::Mutex<PbftSidecar>>,
}
impl ProductionPbftHandle {
    #[must_use] pub fn disabled() -> Self { Self { enabled: false, sidecar: Arc::new(std::sync::Mutex::new(PbftSidecar::new(None, PbftBounds::default()))) } }
    #[must_use] pub fn enabled(quorum: Option<usize>, bounds: PbftBounds) -> Self { Self { enabled: true, sidecar: Arc::new(std::sync::Mutex::new(PbftSidecar::new(quorum, bounds))) } }
    #[must_use] pub fn is_enabled(&self) -> bool { self.enabled }
    #[must_use] pub fn sidecar(&self) -> Arc<std::sync::Mutex<PbftSidecar>> { self.sidecar.clone() }
}

#[derive(Clone)]
pub struct ProductionBlockConsensus {
    sessions: SessionManager,
    engine: CryptoEngine,
    genesis_time: i64,
}
impl ProductionBlockConsensus {
    pub fn new(sessions: SessionManager, engine: CryptoEngine, genesis_time: i64) -> Result<Self, ProductionConsensusError> {
        if genesis_time < 0 { return Err(ProductionConsensusError::InvalidGenesisTime); }
        Ok(Self { sessions, engine, genesis_time })
    }
}
impl BlockConsensus for ProductionBlockConsensus {
    fn verify_witness_signature(&self, raw_header: &[u8], signature: &[u8], witness: &[u8]) -> bool {
        let recovered = RecoverableSignature::from_consensus_wire(signature)
            .and_then(|signature| PublicKey::recover_prehash(self.engine, &selected_digest(self.engine, raw_header), &signature))
            .map(|key| derive_address(&key).as_bytes().to_vec());
        let Ok(recovered) = recovered else { return false };
        let view = self.sessions.read_view();
        let allow_multi_sign = StateFacadeRead(&view).dynamic_long("ALLOW_MULTI_SIGN").unwrap_or(0) == 1;
        if !allow_multi_sign { return recovered == witness; }
        let Some(bytes) = view.store(StoreKind::Account).get(witness) else { return false };
        let Ok(account) = Account::decode(bytes.as_slice()) else { return false };
        let expected = account.witness_permission.as_ref()
            .and_then(|permission| permission.keys.first())
            .map_or(account.address.as_slice(), |key| key.address.as_slice());
        recovered == expected
    }

    fn scheduled_witness(&self, parent_number: i64, parent_timestamp: i64, timestamp: i64) -> Result<Vec<u8>, String> {
        let view = self.sessions.read_view();
        let state = StateFacadeRead(&view);
        let active = state.active_witnesses().map_err(|error| error.to_string())?;
        let maintenance = state.dynamic_int("STATE_FLAG").map_err(|error| error.to_string())? == 1;
        let slots = DposSlot::new(SystemClock, SlotContext {
            genesis_time: self.genesis_time,
            head_number: parent_number,
            head_time: parent_timestamp,
            head_is_maintenance: maintenance,
            maintenance_skip_slots: MAINTENANCE_SKIP_SLOTS,
        });
        let slot = slots.slot(timestamp).map_err(|error| error.to_string())?;
        slots.scheduled_witness(slot, &active).map(Vec::from).map_err(|error| error.to_string())
    }
}

struct StateFacadeRead<'a>(&'a tron_state::ReadView);
impl ConsensusRead for StateFacadeRead<'_> {
    fn witness(&self, address: &[u8]) -> Result<Option<Witness>, crate::StateError> { crate::StateView::new(self.0.clone()).witness(address) }
    fn witnesses(&self) -> Result<Vec<Witness>, crate::StateError> { crate::StateView::new(self.0.clone()).witnesses() }
    fn votes(&self) -> Result<Vec<(Vec<u8>, tron_protocol::protocol::Votes)>, crate::StateError> { crate::StateView::new(self.0.clone()).votes() }
    fn active_witnesses(&self) -> Result<Vec<Vec<u8>>, crate::StateError> { crate::StateView::new(self.0.clone()).active_witnesses() }
    fn current_witnesses(&self) -> Result<Vec<Vec<u8>>, crate::StateError> { crate::StateView::new(self.0.clone()).current_witnesses() }
    fn dynamic_long(&self, name: &'static str) -> Result<i64, crate::StateError> { crate::StateView::new(self.0.clone()).dynamic_long(name) }
    fn dynamic_int(&self, name: &'static str) -> Result<i32, crate::StateError> { crate::StateView::new(self.0.clone()).dynamic_int(name) }
    fn dynamic_raw(&self, name: &'static str) -> Result<Vec<u8>, crate::StateError> { crate::StateView::new(self.0.clone()).dynamic_raw(name) }
    fn delegation(&self, key: &[u8]) -> Option<Vec<u8>> { crate::StateView::new(self.0.clone()).delegation(key) }
}

#[derive(Clone)]
pub struct ProductionBlockHooks {
    parameter_rules: Arc<BTreeMap<i64, ParameterRule>>,
    fork_schedule: Arc<Vec<ForkSpec>>,
    maintenance: MaintenanceConfig,
    backup_role: BackupRoleHandle,
    pbft: ProductionPbftHandle,
    current_witness: Option<Vec<u8>>,
    genesis_time: i64,
}
impl ProductionBlockHooks {
    pub fn from_config(config: &Config, genesis: &GenesisConfig, backup_role: BackupRoleHandle) -> Result<Self, ProductionConsensusError> {
        let engine = CryptoEngine::from_java_name(&config.misc.crypto_engine);
        if config.committee.allow_pbft == 1 && engine == CryptoEngine::Sm2 { return Err(ProductionConsensusError::UnsupportedSm2Pbft); }
        let genesis_votes = genesis.witnesses.iter().map(|witness| (witness.address.clone(), witness.vote_count)).collect();
        let genesis_time = genesis.timestamp().map_err(|_| ProductionConsensusError::InvalidGenesisTime)?;
        Ok(Self {
            parameter_rules: Arc::new(canonical_parameter_rules()),
            fork_schedule: Arc::new(canonical_fork_schedule()),
            maintenance: MaintenanceConfig { genesis_votes, witness_sort_optimized: config.committee.remaining.get("allowOptimizedWitnessSchedule").copied().unwrap_or(0) == 1 },
            backup_role,
            pbft: if config.committee.allow_pbft == 1 { ProductionPbftHandle::enabled(None, PbftBounds::default()) } else { ProductionPbftHandle::disabled() },
            current_witness: None,
            genesis_time,
        })
    }
    #[must_use] pub fn backup_role_handle(&self) -> BackupRoleHandle { self.backup_role.clone() }
    #[must_use] pub fn pbft_handle(&self) -> ProductionPbftHandle { self.pbft.clone() }
    #[must_use] pub fn parameter_rules(&self) -> &BTreeMap<i64, ParameterRule> { &self.parameter_rules }
    #[must_use] pub fn fork_schedule(&self) -> &[ForkSpec] { &self.fork_schedule }
}

impl BlockApplyHooks for ProductionBlockHooks {
    fn backup_master(&mut self, _session: &Session) -> Result<(), String> {
        let _ = self.backup_role.role();
        Ok(())
    }
    fn pay_reward(&mut self, session: &Session, witness: &[u8], _number: i64) -> Result<(), String> {
        self.current_witness = Some(witness.to_vec());
        let state = StateFacade::new(session);
        let value = state.dynamic_long("WITNESS_PAY_PER_BLOCK").map_err(|error| error.to_string())?;
        if state.dynamic_long("CHANGE_DELEGATION").unwrap_or(0) == 1 {
            pay_block_reward(&state, witness, value).map_err(|error| error.to_string())?;
            let standby = state.dynamic_long("WITNESS_STANDBY_ALLOWANCE").unwrap_or(0);
            let mut witnesses = state.witnesses().map_err(|error| error.to_string())?;
            sort_witnesses(&mut witnesses, self.maintenance.witness_sort_optimized);
            witnesses.truncate(127);
            let standby_witnesses = witnesses.into_iter().map(|witness| (witness.address, witness.vote_count)).collect::<Vec<_>>();
            pay_standby_rewards(&state, &standby_witnesses, standby).map_err(|error| error.to_string())?;
        } else {
            adjust_allowance(&state, witness, value).map_err(|error| error.to_string())?;
        }
        pay_fee_pool_reward(&state, witness, 1).map_err(|error| error.to_string())?;
        Ok(())
    }
    fn process_proposals(&mut self, session: &Session, _timestamp: i64) -> Result<(), String> {
        process_expired_proposals(&StateFacade::new(session), &self.parameter_rules).map(|_| ()).map_err(|error| error.to_string())
    }
    fn maintenance_and_dpos(&mut self, session: &Session, timestamp: i64) -> Result<(), String> {
        let state = StateFacade::new(session);
        let number = state.dynamic_long("LATEST_BLOCK_HEADER_NUMBER").unwrap_or(0).saturating_add(1);
        let previous_time = state.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP").map_err(|error| error.to_string())?;
        let active = state.active_witnesses().map_err(|error| error.to_string())?;
        let producer = self.current_witness.as_deref().ok_or_else(|| "reward hook did not record the block witness".to_owned())?;
        let previous_slot = (previous_time.wrapping_sub(self.genesis_time) / crate::BLOCK_INTERVAL_MS).max(0);
        let current_slot = (timestamp.wrapping_sub(self.genesis_time) / crate::BLOCK_INTERVAL_MS).max(0);
        let mut witnesses = state.witnesses().map_err(|error| error.to_string())?.into_iter().map(|witness| (witness.address.clone(), witness)).collect::<BTreeMap<_, _>>();
        account_block_production(&active, previous_slot, current_slot, number, &producer, &mut witnesses);
        for witness in witnesses.values() { state.save_witness(witness).map_err(|error| error.to_string())?; }
        let slots = state.dynamic_raw("BLOCK_FILLED_SLOTS").unwrap_or_else(|_| vec![b'1'; 128]);
        if slots.len() != 128 { return Err("invalid BLOCK_FILLED_SLOTS length".into()); }
        let mut filled: [u8; 128] = slots.as_slice().try_into().map_err(|_| "invalid BLOCK_FILLED_SLOTS length")?;
        let mut index = usize::try_from(state.dynamic_int("BLOCK_FILLED_SLOTS_INDEX").unwrap_or(0)).unwrap_or(0) % 128;
        let elapsed = current_slot.saturating_sub(previous_slot).max(1);
        if elapsed >= 128 {
            filled.fill(b'0');
            index = (index + usize::try_from(elapsed).unwrap_or(usize::MAX)) % 128;
        } else {
            for _ in 1..elapsed { apply_filled_slot(&mut filled, &mut index, false); }
        }
        apply_filled_slot(&mut filled, &mut index, true);
        state.save_dynamic_raw("BLOCK_FILLED_SLOTS", &filled).map_err(|error| error.to_string())?;
        state.save_dynamic_int("BLOCK_FILLED_SLOTS_INDEX", i32::try_from(index).unwrap_or(0)).map_err(|error| error.to_string())?;
        apply_maintenance_block(&state, number, timestamp, &self.maintenance).map(|_| ()).map_err(|error| error.to_string())
    }
    fn update_fork_stats(&mut self, session: &Session, version: i32, witness: &[u8]) -> Result<(), String> {
        let state = StateFacade::new(session);
        let active = state.active_witnesses().map_err(|error| error.to_string())?;
        let latest = state.dynamic_int("VERSION_NUMBER").unwrap_or(0);
        let mut fork_state = ForkState { latest_version: latest, stats: self.fork_schedule.iter().filter_map(|spec| state.store_get(StoreKind::DynamicProperties, format!("FORK_VERSION_{}", spec.version).as_bytes()).map(|stats| (spec.version, stats))).collect() };
        let latest_time = state.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP").unwrap_or(0);
        let interval = state.dynamic_long("MAINTENANCE_TIME_INTERVAL").map_err(|error| error.to_string())?;
        let outcome = update_fork(&mut fork_state, &self.fork_schedule, &active, witness, version, &|spec: &ForkSpec, stats: &[u8]| java_fork_pass(spec, latest_time, interval, stats));
        for (fork, stats) in fork_state.stats { state.store_put(StoreKind::DynamicProperties, format!("FORK_VERSION_{fork}").as_bytes(), &stats).map_err(|error| error.to_string())?; }
        if outcome.latest_version != latest { state.save_dynamic_int("VERSION_NUMBER", outcome.latest_version).map_err(|error| error.to_string())?; }
        Ok(())
    }
    fn update_consensus_views(&mut self, session: &Session, _id: BlockId, _number: i64, _timestamp: i64) -> Result<(), String> {
        update_solidity(&StateFacade::new(session)).map(|_| ()).map_err(|error| error.to_string())
    }
}

pub struct ConsensusRewardCallback;
impl RewardCallback for ConsensusRewardCallback {
    fn withdraw_reward(&self, context: &mut ExecutionContext<'_>, address: &[u8]) -> Result<(), ActuatorError> {
        context.with_reward_session(|session| withdraw_reward(&StateFacade::new(session), address).map(|_| ()).map_err(|error| ActuatorError::execution(error.to_string())))
    }
}

#[must_use]
pub fn canonical_fork_schedule() -> Vec<ForkSpec> {
    [(5,0,0),(6,0,0),(7,0,0),(8,0,0),(9,0,0),(10,0,0),(16,0,0),(17,1_596_780_000_000,80),(19,1_596_780_000_000,80),(20,1_596_780_000_000,80),(21,1_596_780_000_000,80),(22,1_596_780_000_000,80),(23,1_596_780_000_000,80),(24,1_596_780_000_000,80),(25,1_596_780_000_000,80),(26,1_596_780_000_000,80),(27,1_596_780_000_000,80),(28,1_596_780_000_000,80),(29,1_596_780_000_000,80),(30,1_596_780_000_000,80),(31,1_596_780_000_000,80),(32,1_596_780_000_000,80),(33,1_596_780_000_000,70),(34,1_596_780_000_000,80),(35,1_596_780_000_000,70),(36,1_596_780_000_000,80)]
        .into_iter().map(|(version, hard_fork_time, rate_percent)| ForkSpec { version, hard_fork_time, rate_percent }).collect()
}
#[must_use]
pub fn canonical_parameter_rules() -> BTreeMap<i64, ParameterRule> {
    let rows: &[(i64, &str)] = &[
        (0,"MAINTENANCE_TIME_INTERVAL"),(1,"ACCOUNT_UPGRADE_COST"),(2,"CREATE_ACCOUNT_FEE"),(3,"TRANSACTION_FEE"),(4,"ASSET_ISSUE_FEE"),(5,"WITNESS_PAY_PER_BLOCK"),(6,"WITNESS_STANDBY_ALLOWANCE"),(7,"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT"),(8,"CREATE_NEW_ACCOUNT_BANDWIDTH_RATE"),(9,"ALLOW_CREATION_OF_CONTRACTS"),(10,"REMOVE_THE_POWER_OF_THE_GR"),(11,"ENERGY_FEE"),(12,"EXCHANGE_CREATE_FEE"),(13,"MAX_CPU_TIME_OF_ONE_TX"),(14,"ALLOW_UPDATE_ACCOUNT_NAME"),(15,"ALLOW_SAME_TOKEN_NAME"),(16,"ALLOW_DELEGATE_RESOURCE"),(17,"TOTAL_ENERGY_LIMIT"),(18,"ALLOW_TVM_TRANSFER_TRC10"),(19,"TOTAL_ENERGY_LIMIT"),(20,"ALLOW_MULTI_SIGN"),(21,"ALLOW_ADAPTIVE_ENERGY"),(22,"UPDATE_ACCOUNT_PERMISSION_FEE"),(23,"MULTI_SIGN_FEE"),(24,"ALLOW_PROTO_FILTER_NUM"),(25,"ALLOW_ACCOUNT_STATE_ROOT"),(26,"ALLOW_TVM_CONSTANTINOPLE"),(29,"ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER"),(30,"CHANGE_DELEGATION"),(31,"WITNESS_127_PAY_PER_BLOCK"),(32,"ALLOW_TVM_SOLIDITY_059"),(33,"ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO"),(35,"FORBID_TRANSFER_TO_CONTRACT"),(39,"ALLOW_SHIELDED_TRC20_TRANSACTION"),(40,"ALLOW_PBFT"),(41,"ALLOW_TVM_ISTANBUL"),(44,"ALLOW_MARKET_TRANSACTION"),(45,"MARKET_SELL_FEE"),(46,"MARKET_CANCEL_FEE"),(47,"MAX_FEE_LIMIT"),(48,"ALLOW_TRANSACTION_FEE_POOL"),(49,"ALLOW_BLACKHOLE_OPTIMIZATION"),(51,"ALLOW_NEW_RESOURCE_MODEL"),(52,"ALLOW_TVM_FREEZE"),(53,"ALLOW_ACCOUNT_ASSET_OPTIMIZATION"),(59,"ALLOW_TVM_VOTE"),(60,"ALLOW_TVM_COMPATIBLE_EVM"),(61,"FREE_NET_LIMIT"),(62,"TOTAL_NET_LIMIT"),(63,"ALLOW_TVM_LONDON"),(65,"ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX"),(66,"ALLOW_ASSET_OPTIMIZATION"),(67,"ALLOW_NEW_REWARD"),(68,"MEMO_FEE"),(69,"ALLOW_DELEGATE_OPTIMIZATION"),(70,"UNFREEZE_DELAY_DAYS"),(71,"ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID"),(72,"ALLOW_DYNAMIC_ENERGY"),(73,"DYNAMIC_ENERGY_THRESHOLD"),(74,"DYNAMIC_ENERGY_INCREASE_FACTOR"),(75,"DYNAMIC_ENERGY_MAX_FACTOR"),(76,"ALLOW_TVM_SHANGHAI"),(77,"ALLOW_CANCEL_ALL_UNFREEZE_V2"),(78,"MAX_DELEGATE_LOCK_PERIOD"),(79,"ALLOW_OLD_REWARD_OPT"),(81,"ALLOW_ENERGY_ADJUSTMENT"),(82,"MAX_CREATE_ACCOUNT_TX_SIZE"),(83,"ALLOW_TVM_CANCUN"),(87,"ALLOW_STRICT_MATH"),(88,"CONSENSUS_LOGIC_OPTIMIZATION"),(89,"ALLOW_TVM_BLOB"),(92,"PROPOSAL_EXPIRE_TIME"),(94,"ALLOW_TVM_SELFDESTRUCT_RESTRICTION"),(95,"ALLOW_TVM_PRAGUE"),(96,"ALLOW_TVM_OSAKA"),(97,"ALLOW_HARDEN_RESOURCE_CALCULATION"),(98,"ALLOW_HARDEN_EXCHANGE_CALCULATION")
    ];
    let one_shot: BTreeSet<i64> = [10,20,21,44,77].into_iter().collect();
    rows.iter().map(|&(id, dynamic)| (id, ParameterRule { dynamic, depends_on: None, one_shot: one_shot.contains(&id) })).collect()
}
