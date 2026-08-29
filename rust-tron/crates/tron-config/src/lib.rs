//! Typed, source-owned java-tron configuration.
//!
//! The loader deliberately has no ambient environment or argument access. Callers select a
//! source, pass explicitly assigned command-line values, then run the documented event,
//! platform, and witness stages.

use std::{collections::{BTreeMap, BTreeSet}, path::{Path, PathBuf}};

use hocon::{Hocon, HoconLoader};
use serde::Deserialize;
use thiserror::Error;

pub const REFERENCE_CONF: &str = include_str!("reference.conf");
pub const PACKAGED_CONFIG_CONF: &str = include_str!("config.conf");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownKeyPolicy { Ignore, Reject }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource { Bundled, External(PathBuf) }

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration path is required")]
    BlankPath,
    #[error("Configuration path is required! No Such file {0}")]
    MissingPath(PathBuf),
    #[error("failed to read configuration {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("invalid HOCON configuration: {0}")]
    Parse(#[from] hocon::Error),
    #[error("unknown-key rejection requires a source inventory match; unknown keys: {0:?}")]
    UnknownKeys(Vec<String>),
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error("configuration exceeds {limit} limit ({actual})")]
    LimitExceeded { limit: &'static str, actual: usize },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub storage: StorageConfig,
    pub node: NodeConfig,
    pub vm: VmConfig,
    pub block: BlockConfig,
    pub committee: CommitteeConfig,
    pub event: EventRoot,
    pub rate: RateRoot,
    pub genesis: GenesisRoot,
    pub crypto: CryptoConfig,
    pub enery: EneryConfig,
    pub trx: TrxConfig,
    pub seed: SeedRoot,
    pub localwitness: Vec<String>,
    #[serde(rename = "localWitnessAccountAddress")]
    pub local_witness_account_address: Option<String>,
    pub localwitnesskeystore: Vec<String>,
    #[serde(skip)] pub misc: MiscConfig,
    #[serde(skip)] pub witness: LocalWitnessConfig,
    #[serde(skip)] pub runtime_event_subscribe: bool,
    #[serde(skip)] pub event_runtime: Option<EventRuntime>,
}

impl Default for Config {
    fn default() -> Self {
        Self { storage: StorageConfig::default(), node: NodeConfig::default(), vm: VmConfig::default(), block: BlockConfig::default(), committee: CommitteeConfig::default(), event: EventRoot::default(), rate: RateRoot::default(), genesis: GenesisRoot::default(), crypto: CryptoConfig::default(), enery: EneryConfig::default(), trx: TrxConfig::default(), seed: SeedRoot::default(), localwitness: vec![], local_witness_account_address: None, localwitnesskeystore: vec![], misc: MiscConfig::default(), witness: LocalWitnessConfig::default(), runtime_event_subscribe: false, event_runtime: None }
    }
}

impl Config {
    fn finish(mut self) -> Result<Self, ConfigError> {
        self.node.normalize();
        self.storage.normalize()?;
        self.vm.normalize()?;
        self.block.normalize()?;
        self.misc = MiscConfig { need_to_update_asset: self.storage.need_to_update_asset, history_balance_lookup: self.storage.balance.history.lookup, trx_reference_block: self.trx.reference.block.clone(), trx_expiration_time_in_milliseconds: self.trx.expiration.time_in_milliseconds, block_num_for_energy_limit: self.enery.limit.block.num, crypto_engine: self.crypto.engine.clone(), seed_node: SeedNode { addresses: self.seed.node.ip.list.clone() } };
        self.witness = LocalWitnessConfig { private_keys: self.localwitness.clone(), account_address: self.local_witness_account_address.clone(), keystores: self.localwitnesskeystore.clone(), initialized: false, source: WitnessKeySource::None, password: None };
        self.genesis.block.validate()?;
        Ok(self)
    }

    pub fn apply_cli(&mut self, cli: &CliOverrides) {
        if let Some(v) = &cli.output_directory { self.storage.output_directory = v.clone(); }
        if let Some(v) = &cli.storage_db_directory { self.storage.db.directory = v.clone(); }
        if let Some(v) = &cli.storage_db_engine { self.storage.db.engine = v.to_ascii_uppercase(); }
        if let Some(v) = cli.storage_db_sync { self.storage.db.sync = v; }
        if let Some(v) = &cli.transaction_history_switch { self.storage.trans_history.switch_value = v.clone(); }
        if let Some(v) = cli.contract_parse_enable { self.event.subscribe.contract_parse = v; }
        if let Some(v) = cli.support_constant { self.vm.support_constant = v; }
        if let Some(v) = cli.max_energy_limit_for_constant { self.vm.max_energy_limit_for_constant = v.max(100_000_000); }
        if let Some(v) = cli.lru_cache_size { self.vm.lru_cache_size = v; }
        if let Some(v) = cli.min_time_ratio { self.vm.min_time_ratio = v; }
        if let Some(v) = cli.max_time_ratio { self.vm.max_time_ratio = v; }
        if let Some(v) = cli.save_internal_tx { self.vm.save_internal_tx = v; }
        if let Some(v) = cli.save_featured_internal_tx { self.vm.save_featured_internal_tx = v; }
        if let Some(v) = cli.save_cancel_all_unfreeze_v2_details { self.vm.save_cancel_all_unfreeze_v2_details = v; }
        if let Some(v) = cli.long_running_time { self.vm.long_running_time = v; }
        if let Some(v) = cli.event_subscribe { self.runtime_event_subscribe = v; }
        if let Some(v) = cli.p2p_disable { self.node.p2p_disable = v; }
        if let Some(v) = cli.witness { self.node.witness = v; }
        if let Some(v) = cli.max_http_connect_number { self.node.max_http_connect_number = v; }
        if let Some(v) = cli.rpc_thread_num { self.node.rpc.thread = v; }
        if let Some(v) = cli.solidity_threads { self.node.solidity.threads = v; }
        if let Some(v) = cli.validate_sign_thread_num { self.node.validate_sign_thread_num = v; }
        if let Some(v) = &cli.trust_node { self.node.trust_node = v.clone(); }
        if let Some(v) = cli.history_balance_lookup { self.storage.balance.history.lookup = v; self.misc.history_balance_lookup = v; }
        if !cli.seed_nodes.is_empty() { self.misc.seed_node.addresses = cli.seed_nodes.clone(); }
    }

    pub fn apply_event_stage(&mut self) {
        self.runtime_event_subscribe |= self.event.subscribe.enable;
        if self.runtime_event_subscribe { self.event_runtime = Some(EventRuntime::from(&self.event.subscribe)); }
    }

    pub fn apply_platform_stage(&mut self, platform: Platform) {
        if platform == Platform::Arm64 { self.storage.db.engine = "ROCKSDB".into(); }
    }

    pub fn apply_witness_stage(&mut self, cli: &CliOverrides) -> Result<(), ConfigError> {
        self.witness = if !self.node.witness {
            LocalWitnessConfig::default()
        } else if let Some(private_key) = cli.private_key.as_ref().filter(|v| !v.trim().is_empty()) {
            LocalWitnessConfig { private_keys: vec![private_key.clone()], account_address: cli.witness_address.clone(), keystores: vec![], initialized: true, source: WitnessKeySource::CliPrivateKey, password: None }
        } else if !self.localwitness.is_empty() {
            LocalWitnessConfig { private_keys: self.localwitness.clone(), account_address: self.local_witness_account_address.clone(), keystores: vec![], initialized: true, source: WitnessKeySource::ConfigPrivateKeys, password: None }
        } else if !self.localwitnesskeystore.is_empty() {
            LocalWitnessConfig { private_keys: vec![], account_address: self.local_witness_account_address.clone(), keystores: self.localwitnesskeystore.clone(), initialized: true, source: WitnessKeySource::ConfigKeystores, password: cli.password.clone() }
        } else {
            return Err(ConfigError::Invalid("witness mode requires --private-key, localwitness, or localwitnesskeystore".into()));
        };
        Ok(())
    }

    pub fn compatibility_bridge(&self) -> CompatibilityBridge {
        CompatibilityBridge { support_constant: self.vm.support_constant, max_energy_limit_for_constant: self.vm.max_energy_limit_for_constant, db_engine: self.storage.db.engine.clone(), db_sync: self.storage.db.sync, db_directory: self.storage.db.directory.clone(), transaction_history_switch: self.storage.trans_history.switch_value.clone(), allow_pbft: self.committee.allow_pbft, pbft_expire_num: self.committee.pbft_expire_num, event_subscribe: self.runtime_event_subscribe, metrics_enable: self.node.metrics_enable, prometheus: self.node.metrics.prometheus.clone(), seed_nodes: self.misc.seed_node.addresses.clone(), open_history_query_when_lite_fn: self.node.open_history_query_when_lite_fn }
    }

}

#[derive(Debug, Clone, Copy)]
pub struct ConfigLimits {
    pub source_bytes: usize,
    pub parsed_depth: usize,
    pub parsed_nodes: usize,
    pub list_length: usize,
    pub string_bytes: usize,
}

impl Default for ConfigLimits {
    fn default() -> Self { Self { source_bytes: 1_048_576, parsed_depth: 32, parsed_nodes: 100_000, list_length: 10_000, string_bytes: 1_048_576 } }
}

pub struct ConfigLoader { unknown_keys: UnknownKeyPolicy, limits: ConfigLimits }
impl Default for ConfigLoader { fn default() -> Self { Self { unknown_keys: UnknownKeyPolicy::Ignore, limits: ConfigLimits::default() } } }
impl ConfigLoader {
    pub fn new(unknown_keys: UnknownKeyPolicy) -> Self { Self { unknown_keys, limits: ConfigLimits::default() } }
    pub fn with_limits(unknown_keys: UnknownKeyPolicy, limits: ConfigLimits) -> Self { Self { unknown_keys, limits } }
    pub fn load(&self, source: ConfigSource) -> Result<Config, ConfigError> {
        let overlay = match source {
            ConfigSource::Bundled => PACKAGED_CONFIG_CONF.to_owned(),
            ConfigSource::External(path) => read_external(&path, self.limits.source_bytes)?,
        };
        self.load_str(&overlay)
    }
    pub fn load_external_path(&self, path: impl AsRef<Path>) -> Result<Config, ConfigError> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() { return Err(ConfigError::BlankPath); }
        self.load(ConfigSource::External(path.to_owned()))
    }
    pub fn load_str(&self, overlay: &str) -> Result<Config, ConfigError> {
        check_source_limit(overlay, self.limits.source_bytes)?;
        let mut overlay_tree = HoconLoader::new().no_system().strict().load_str(overlay)?.hocon()?;
        check_tree_limits(&overlay_tree, self.limits)?;
        if self.unknown_keys == UnknownKeyPolicy::Reject {
            let known = known_schema()?;
            let mut unknown = BTreeSet::new();
            collect_unknown_paths(&overlay_tree, "", &known, &mut unknown);
            if !unknown.is_empty() { return Err(ConfigError::UnknownKeys(unknown.into_iter().collect())); }
        }
        normalize_legacy_aliases(&mut overlay_tree);
        let mut merged = HoconLoader::new().no_system().strict().load_str(REFERENCE_CONF)?.hocon()?;
        merge_hocon(&mut merged, overlay_tree);
        check_tree_limits(&merged, self.limits)?;
        hocon::de::from_str::<Config>(&render_hocon(&merged)?).map_err(ConfigError::Parse)?.finish()
    }
}

fn normalize_legacy_aliases(root: &mut Hocon) {
    let Hocon::Hash(root) = root else { return };
    if let Some(Hocon::Hash(node)) = root.get_mut("node") {
        for (legacy, canonical) in [
            ("maxActiveNodes", "maxConnections"),
            ("maxActiveNodesWithSameIp", "maxConnectionsWithSameIp"),
            ("openFullTcpDisconnect", "isOpenFullTcpDisconnect"),
        ] {
            if let Some(value) = node.remove(legacy) { node.insert(canonical.into(), value); }
        }
    }
    if let Some(Hocon::Hash(committee)) = root.get_mut("committee") {
        for (legacy, canonical) in [("allowPbft", "allowPBFT"), ("pbftExpireNum", "pBFTExpireNum")] {
            if let Some(value) = committee.remove(legacy) { committee.insert(canonical.into(), value); }
        }
    }
}

fn merge_hocon(base: &mut Hocon, overlay: Hocon) {
    match (base, overlay) {
        (Hocon::Hash(base), Hocon::Hash(overlay)) => {
            for (key, value) in overlay {
                if let Some(existing) = base.get_mut(&key) { merge_hocon(existing, value); }
                else { base.insert(key, value); }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn render_hocon(value: &Hocon) -> Result<String, ConfigError> {
    Ok(match value {
        Hocon::Real(value) => value.to_string(),
        Hocon::Integer(value) => value.to_string(),
        Hocon::String(value) => format!("{value:?}"),
        Hocon::Boolean(value) => value.to_string(),
        Hocon::Array(values) => format!("[{}]", values.iter().map(render_hocon).collect::<Result<Vec<_>, _>>()?.join(",")),
        Hocon::Hash(values) => {
            let fields = values.iter().map(|(key, value)| Ok(format!("{key:?}:{}", render_hocon(value)?))).collect::<Result<Vec<_>, ConfigError>>()?;
            format!("{{{}}}", fields.join(","))
        }
        Hocon::Null => "null".into(),
        Hocon::BadValue(error) => return Err(ConfigError::Invalid(format!("unresolved HOCON value: {error}"))),
    })
}

fn check_source_limit(source: &str, limit: usize) -> Result<(), ConfigError> {
    if source.len() > limit { Err(ConfigError::LimitExceeded { limit: "source bytes", actual: source.len() }) } else { Ok(()) }
}

fn read_external(path: &Path, limit: usize) -> Result<String, ConfigError> {
    if !path.is_file() { return Err(ConfigError::MissingPath(path.to_owned())); }
    let metadata = std::fs::metadata(path).map_err(|source| ConfigError::Read { path: path.to_owned(), source })?;
    if metadata.len() > limit as u64 { return Err(ConfigError::LimitExceeded { limit: "source bytes", actual: metadata.len() as usize }); }
    let source = std::fs::read_to_string(path).map_err(|source| ConfigError::Read { path: path.to_owned(), source })?;
    check_source_limit(&source, limit)?;
    Ok(source)
}

fn check_tree_limits(root: &Hocon, limits: ConfigLimits) -> Result<(), ConfigError> {
    fn visit(value: &Hocon, depth: usize, nodes: &mut usize, limits: ConfigLimits) -> Result<(), ConfigError> {
        if depth > limits.parsed_depth { return Err(ConfigError::LimitExceeded { limit: "parsed depth", actual: depth }); }
        *nodes += 1;
        if *nodes > limits.parsed_nodes { return Err(ConfigError::LimitExceeded { limit: "parsed nodes", actual: *nodes }); }
        match value {
            Hocon::String(value) if value.len() > limits.string_bytes => Err(ConfigError::LimitExceeded { limit: "string bytes", actual: value.len() }),
            Hocon::Array(values) => {
                if values.len() > limits.list_length { return Err(ConfigError::LimitExceeded { limit: "list length", actual: values.len() }); }
                for value in values { visit(value, depth + 1, nodes, limits)?; }
                Ok(())
            }
            Hocon::Hash(values) => {
                for (key, value) in values {
                    if key.len() > limits.string_bytes { return Err(ConfigError::LimitExceeded { limit: "string bytes", actual: key.len() }); }
                    visit(value, depth + 1, nodes, limits)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    visit(root, 0, &mut 0, limits)
}

fn known_schema() -> Result<BTreeSet<String>, ConfigError> {
    let mut paths = BTreeSet::new();
    for source in [REFERENCE_CONF, PACKAGED_CONFIG_CONF] {
        let tree = HoconLoader::new().no_system().strict().load_str(source)?.hocon()?;
        collect_paths(&tree, "", &mut paths);
    }
    for alias in ["node.maxActiveNodes", "node.maxActiveNodesWithSameIp", "node.openFullTcpDisconnect", "committee.allowPbft", "committee.pbftExpireNum"] { paths.insert(alias.into()); }
    Ok(paths)
}

fn collect_paths(value: &Hocon, path: &str, paths: &mut BTreeSet<String>) {
    if !path.is_empty() { paths.insert(path.to_owned()); }
    match value {
        Hocon::Hash(values) => for (key, value) in values { collect_paths(value, &join_path(path, key), paths); },
        Hocon::Array(values) => for value in values { collect_paths(value, &format!("{path}[]"), paths); },
        _ => {}
    }
}

fn collect_unknown_paths(value: &Hocon, path: &str, known: &BTreeSet<String>, unknown: &mut BTreeSet<String>) {
    if !path.is_empty() && !known.contains(path) { unknown.insert(path.to_owned()); return; }
    match value {
        Hocon::Hash(values) => for (key, value) in values { collect_unknown_paths(value, &join_path(path, key), known, unknown); },
        Hocon::Array(values) => for value in values { collect_unknown_paths(value, &format!("{path}[]"), known, unknown); },
        _ => {}
    }
}

fn join_path(parent: &str, key: &str) -> String { if parent.is_empty() { key.to_owned() } else { format!("{parent}.{key}") } }

#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Platform { X86_64, Arm64, Other }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode { Full, Solidity, KeystoreFactory }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliAction { Run, Help, Version }

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedCli {
    pub action: CliAction,
    pub mode: NodeMode,
    pub config_source: ConfigSource,
    pub log_config: Option<PathBuf>,
    pub fast_forward: Option<bool>,
    pub debug: Option<bool>,
    pub overrides: CliOverrides,
}

#[derive(Debug, Error, PartialEq)]
pub enum CliError {
    #[error("unknown option {option}")]
    UnknownOption { option: String },
    #[error("option {option} requires a value")]
    MissingValue { option: String },
    #[error("option {option} has invalid {expected} value {value:?}")]
    InvalidValue { option: String, value: String, expected: &'static str },
    #[error("mode options {first} and {second} cannot be combined")]
    ConflictingModes { first: &'static str, second: &'static str },
}

impl ParsedCli {
    pub fn parse<I, S>(arguments: I) -> Result<Self, CliError>
    where I: IntoIterator<Item = S>, S: Into<String> {
        let mut args = arguments.into_iter().map(Into::into).peekable();
        let mut parsed = Self { action: CliAction::Run, mode: NodeMode::Full, config_source: ConfigSource::Bundled, log_config: None, fast_forward: None, debug: None, overrides: CliOverrides::default() };
        while let Some(argument) = args.next() {
            let (option, inline) = argument.split_once('=').map_or((argument.as_str(), None), |(name, value)| (name, Some(value.to_owned())));
            let mut value = || inline.clone().or_else(|| args.next()).ok_or_else(|| CliError::MissingValue { option: option.to_owned() });
            let parse_bool = |raw: String| match raw.as_str() { "true" => Ok(true), "false" => Ok(false), _ => Err(CliError::InvalidValue { option: option.to_owned(), value: raw, expected: "boolean" }) };
            match option {
                "-h" | "--help" => parsed.action = CliAction::Help,
                "-v" | "--version" => parsed.action = CliAction::Version,
                "-c" | "--config" => parsed.config_source = ConfigSource::External(PathBuf::from(value()?)),
                "-d" | "--output-directory" => parsed.overrides.output_directory = Some(value()?),
                "--log-config" => parsed.log_config = Some(PathBuf::from(value()?)),
                "-w" | "--witness" => parsed.overrides.witness = Some(true),
                "-p" | "--private-key" => parsed.overrides.private_key = Some(value()?),
                "--witness-address" => parsed.overrides.witness_address = Some(value()?),
                "--password" => parsed.overrides.password = Some(value()?),
                "--solidity" => { if parsed.mode != NodeMode::KeystoreFactory { parsed.mode = NodeMode::Solidity; } }
                "--keystore-factory" => parsed.mode = NodeMode::KeystoreFactory,
                "--fast-forward" => parsed.fast_forward = Some(true),
                "--es" => parsed.overrides.event_subscribe = Some(true),
                "--p2p-disable" => parsed.overrides.p2p_disable = Some(parse_bool(value()?)?),
                "--storage-db-directory" => parsed.overrides.storage_db_directory = Some(value()?),
                "--storage-db-engine" => parsed.overrides.storage_db_engine = Some(value()?),
                "--storage-db-synchronous" => parsed.overrides.storage_db_sync = Some(java_boolean_value_of(&value()?)),
                "--storage-index-directory" | "--storage-index-switch" => { let _ = value()?; }
                "--storage-transactionHistory-switch" => parsed.overrides.transaction_history_switch = Some(value()?),
                "--contract-parse-enable" => parsed.overrides.contract_parse_enable = Some(java_boolean_value_of(&value()?)),
                "--support-constant" => parsed.overrides.support_constant = Some(true),
                "--max-energy-limit-for-constant" => parsed.overrides.max_energy_limit_for_constant = Some(parse_number(option, value()?, "integer")?),
                "--lru-cache-size" => parsed.overrides.lru_cache_size = Some(parse_number(option, value()?, "unsigned integer")?),
                "--debug" => parsed.debug = Some(true),
                "--min-time-ratio" => parsed.overrides.min_time_ratio = Some(parse_number(option, value()?, "number")?),
                "--max-time-ratio" => parsed.overrides.max_time_ratio = Some(parse_number(option, value()?, "number")?),
                "--save-internaltx" => parsed.overrides.save_internal_tx = Some(true),
                "--save-featured-internaltx" => parsed.overrides.save_featured_internal_tx = Some(true),
                "--save-cancel-all-unfreeze-v2-details" => parsed.overrides.save_cancel_all_unfreeze_v2_details = Some(true),
                "--long-running-time" => parsed.overrides.long_running_time = Some(parse_number(option, value()?, "integer")?),
                "--max-connect-number" => parsed.overrides.max_http_connect_number = Some(parse_number(option, value()?, "integer")?),
                "--rpc-thread" => parsed.overrides.rpc_thread_num = Some(parse_number(option, value()?, "integer")?),
                "--solidity-thread" => parsed.overrides.solidity_threads = Some(parse_number(option, value()?, "integer")?),
                "--validate-sign-thread" => parsed.overrides.validate_sign_thread_num = Some(parse_number(option, value()?, "integer")?),
                "--trust-node" => parsed.overrides.trust_node = Some(value()?),
                "--history-balance-lookup" => parsed.overrides.history_balance_lookup = Some(true),
                _ if option.starts_with('-') => return Err(CliError::UnknownOption { option: option.to_owned() }),
                _ => parsed.overrides.seed_nodes.push(argument),
            }
        }
        Ok(parsed)
    }
}

fn parse_number<T: std::str::FromStr>(option: &str, value: String, expected: &'static str) -> Result<T, CliError> {
    value.parse().map_err(|_| CliError::InvalidValue { option: option.to_owned(), value, expected })
}
fn java_boolean_value_of(value: &str) -> bool { value.eq_ignore_ascii_case("true") }

pub fn load_runtime_config(parsed: &ParsedCli, platform: Platform) -> Result<Config, ConfigError> {
    let mut config = ConfigLoader::default().load(parsed.config_source.clone())?;
    config.apply_cli(&parsed.overrides);
    config.apply_event_stage();
    config.apply_platform_stage(platform);
    config.storage.normalize()?;
    config.vm.normalize()?;
    config.apply_witness_stage(&parsed.overrides)?;
    Ok(config)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicNodeLists { pub active: Vec<String>, pub passive: Vec<String>, pub trust: Vec<String> }

impl DynamicNodeLists {
    pub fn from_config(config: &Config) -> Self {
        let mut trust = config.node.passive.clone();
        trust.extend(config.node.active.iter().cloned());
        trust.extend(config.node.fast_forward.iter().cloned());
        Self { active: config.node.active.clone(), passive: config.node.passive.clone(), trust }
    }

    pub fn reload(loader: &ConfigLoader, source: ConfigSource) -> Result<Self, ConfigError> {
        loader.load(source).map(|config| Self::from_config(&config))
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CliOverrides {
    pub output_directory: Option<String>, pub storage_db_directory: Option<String>, pub storage_db_engine: Option<String>, pub storage_db_sync: Option<bool>, pub transaction_history_switch: Option<String>, pub contract_parse_enable: Option<bool>, pub support_constant: Option<bool>, pub max_energy_limit_for_constant: Option<i64>, pub lru_cache_size: Option<usize>, pub min_time_ratio: Option<f64>, pub max_time_ratio: Option<f64>, pub save_internal_tx: Option<bool>, pub save_featured_internal_tx: Option<bool>, pub save_cancel_all_unfreeze_v2_details: Option<bool>, pub long_running_time: Option<i32>, pub event_subscribe: Option<bool>, pub p2p_disable: Option<bool>, pub witness: Option<bool>, pub private_key: Option<String>, pub witness_address: Option<String>, pub password: Option<String>, pub max_http_connect_number: Option<i32>, pub rpc_thread_num: Option<i32>, pub solidity_threads: Option<i32>, pub validate_sign_thread_num: Option<i32>, pub trust_node: Option<String>, pub history_balance_lookup: Option<bool>, pub seed_nodes: Vec<String>,
}

macro_rules! default_struct {
    ($name:ident { $($(#[$meta:meta])* $field:ident : $ty:ty = $value:expr),* $(,)? }) => {
        #[derive(Debug, Clone, Deserialize)]
        #[serde(default, rename_all = "camelCase")]
        pub struct $name { $($(#[$meta])* pub $field: $ty),* }
        impl Default for $name { fn default() -> Self { Self { $($field: $value),* } } }
    };
}

default_struct!(DbConfig { engine:String="LEVELDB".into(), sync:bool=false, directory:String="database".into() });
default_struct!(TransHistoryConfig { #[serde(rename="switch")] switch_value:String="on".into() });

#[derive(Debug, Clone, Deserialize)]
#[serde(default, rename_all="camelCase")]
pub struct StorageConfig { pub db:DbConfig, pub trans_history:TransHistoryConfig, pub properties:Vec<StorageProperty>, pub need_to_update_asset:bool, pub db_settings:DbSettings, pub balance:BalanceConfig, pub checkpoint:CheckpointConfig, pub snapshot:SnapshotConfig, pub tx_cache:TxCacheConfig, #[serde(skip)] pub output_directory:String }
impl Default for StorageConfig { fn default()->Self { Self { db:DbConfig::default(), trans_history:TransHistoryConfig::default(), properties:vec![], need_to_update_asset:true, db_settings:DbSettings::default(), balance:BalanceConfig::default(), checkpoint:CheckpointConfig::default(), snapshot:SnapshotConfig::default(), tx_cache:TxCacheConfig::default(), output_directory:"output-directory".into() } } }
impl StorageConfig { fn normalize(&mut self)->Result<(),ConfigError>{ self.db.engine=self.db.engine.to_ascii_uppercase(); if !matches!(self.db.engine.as_str(),"LEVELDB"|"ROCKSDB"){return Err(ConfigError::Invalid(format!("unsupported storage engine {}",self.db.engine)));} self.tx_cache.estimated_transactions=self.tx_cache.estimated_transactions.clamp(100,10_000); if self.snapshot.max_flush_count<1 { self.snapshot.max_flush_count=1; } let mut names=std::collections::BTreeSet::new(); for p in &self.properties { if p.name.is_empty(){return Err(ConfigError::Invalid("storage property name is required".into()));} if !names.insert(&p.name){return Err(ConfigError::Invalid(format!("duplicate storage property {}",p.name)));} } Ok(()) } }
default_struct!(StorageProperty { name:String=String::new(), path:String=String::new(), block_size:Option<i64>=None, write_buffer_size:Option<i64>=None, cache_size:Option<i64>=None, max_open_files:Option<i32>=None });
default_struct!(DbSettings { level_number:i32=7, compact_threads:i32=0, blocksize:i32=16, max_bytes_for_level_base:i32=256, max_bytes_for_level_multiplier:i32=10, level0_file_num_compaction_trigger:i32=2, target_file_size_base:i32=64, target_file_size_multiplier:i32=1, max_open_files:i32=5000 });
default_struct!(BalanceConfig { history:HistoryConfig=HistoryConfig::default() });
default_struct!(HistoryConfig { lookup:bool=false });
default_struct!(CheckpointConfig { version:i32=1, sync:bool=true });
default_struct!(SnapshotConfig { max_flush_count:i32=1 });
default_struct!(TxCacheConfig { estimated_transactions:i32=1000, init_optimization:bool=false });

#[derive(Debug, Clone, Deserialize)] #[serde(default, rename_all="camelCase")]
pub struct NodeConfig { pub trust_node:String, pub wallet_extension_api:bool, pub listen:ListenConfig, pub fetch_block:FetchBlockConfig, pub sync_fetch_batch_num:i32, pub max_pending_block_size:i32, pub validate_sign_thread_num:i32, #[serde(alias="maxActiveNodes")] pub max_connections:i32, pub min_connections:i32, pub min_active_connections:i32, #[serde(alias="maxActiveNodesWithSameIp")] pub max_connections_with_same_ip:i32, pub max_http_connect_number:i32, pub min_participation_rate:i32, pub open_print_log:bool, pub open_transaction_sort:bool, pub max_tps:i32, pub max_block_inv_per_second:i32, #[serde(rename="isOpenFullTcpDisconnect",alias="openFullTcpDisconnect")] pub open_full_tcp_disconnect:bool, pub discovery:DiscoveryConfig, pub backup:NodeBackupConfig, pub p2p:P2pConfig, pub http:HttpConfig, pub rpc:RpcConfig, pub jsonrpc:JsonRpcConfig, pub dynamic_config:DynamicConfig, pub dns:DnsConfig, pub metrics:MetricsConfig, pub metrics_enable:bool, pub active:Vec<String>, pub passive:Vec<String>, pub fast_forward:Vec<String>, pub disabled_api:Vec<String>, pub inactive_threshold:i64, pub max_fast_forward_num:i32, pub solidity:SolidityConfig, pub block_produced_time_out:i32, pub net_max_trx_per_second:i32, pub node_detect_enable:bool, pub enable_ipv6:bool, pub effective_check_enable:bool, pub unsolidified_block_check:bool, pub max_unsolidified_blocks:i32, pub block_cache_timeout:i32, pub max_transaction_pending_size:i32, pub pending_transaction_timeout:i64, pub max_trx_cache_size:i32, pub agree_node_count:i32, pub zen_token_id:String, pub shielded_trans_in_pending_max_counts:i32, pub valid_contract_proto:ValidContractProto, #[serde(rename="openHistoryQueryWhenLiteFN")] pub open_history_query_when_lite_fn:bool, pub shutdown:ShutdownConfig, #[serde(skip)] pub p2p_disable:bool, #[serde(skip)] pub witness:bool }
impl Default for NodeConfig { fn default()->Self { Self { trust_node:String::new(),wallet_extension_api:false,listen:ListenConfig::default(),fetch_block:FetchBlockConfig::default(),sync_fetch_batch_num:2000,max_pending_block_size:500,validate_sign_thread_num:0,max_connections:30,min_connections:8,min_active_connections:3,max_connections_with_same_ip:2,max_http_connect_number:50,min_participation_rate:0,open_print_log:true,open_transaction_sort:false,max_tps:1000,max_block_inv_per_second:10,open_full_tcp_disconnect:false,discovery:DiscoveryConfig::default(),backup:NodeBackupConfig::default(),p2p:P2pConfig::default(),http:HttpConfig::default(),rpc:RpcConfig::default(),jsonrpc:JsonRpcConfig::default(),dynamic_config:DynamicConfig::default(),dns:DnsConfig::default(),metrics:MetricsConfig::default(),metrics_enable:false,active:vec![],passive:vec![],fast_forward:vec![],disabled_api:vec![],inactive_threshold:600,max_fast_forward_num:4,solidity:SolidityConfig::default(),block_produced_time_out:50,net_max_trx_per_second:700,node_detect_enable:false,enable_ipv6:false,effective_check_enable:false,unsolidified_block_check:false,max_unsolidified_blocks:54,block_cache_timeout:60,max_transaction_pending_size:2000,pending_transaction_timeout:60000,max_trx_cache_size:50000,agree_node_count:0,zen_token_id:"000000".into(),shielded_trans_in_pending_max_counts:10,valid_contract_proto:ValidContractProto::default(),open_history_query_when_lite_fn:false,shutdown:ShutdownConfig::default(),p2p_disable:false,witness:false } } }
impl NodeConfig { fn normalize(&mut self){self.sync_fetch_batch_num=self.sync_fetch_batch_num.clamp(100,2000);self.max_pending_block_size=self.max_pending_block_size.clamp(50,2000);self.max_block_inv_per_second=self.max_block_inv_per_second.max(1);self.disabled_api.iter_mut().for_each(|v|*v=v.to_ascii_lowercase());} }
default_struct!(ListenConfig { port:i32=18888 }); default_struct!(FetchBlockConfig { timeout:i32=500 });
default_struct!(DiscoveryConfig { enable:bool=false,persist:bool=false,external:ExternalIp=ExternalIp::default() }); default_struct!(ExternalIp { ip:String=String::new() });
default_struct!(NodeBackupConfig { port:i32=10001,priority:i32=0,keep_alive_interval:i64=3000,members:Vec<String>=vec![] }); default_struct!(P2pConfig { version:i32=11111 });
default_struct!(HttpConfig { full_node_enable:bool=true,full_node_port:i32=8090,solidity_enable:bool=true,solidity_port:i32=8091, #[serde(rename="PBFTEnable")] pbft_enable:bool=true, #[serde(rename="PBFTPort")] pbft_port:i32=8092,max_message_size:i32=4_194_304 });
default_struct!(RpcConfig { enable:bool=true,port:i32=50051,solidity_enable:bool=true,solidity_port:i32=50061, #[serde(rename="PBFTEnable")] pbft_enable:bool=true, #[serde(rename="PBFTPort")] pbft_port:i32=50071,thread:i32=0,max_concurrent_calls_per_connection:i32=100,flow_control_window:i32=1_048_576,max_connection_idle_in_millis:i64=0,max_connection_age_in_millis:i64=0,max_message_size:i32=4_194_304,max_header_list_size:i32=8192,max_rst_stream:i32=0,seconds_per_window:i32=0,min_effective_connection:i32=1,reflection_service:bool=false,trx_cache_enable:bool=false });
default_struct!(JsonRpcConfig { http_full_node_enable:bool=false,http_full_node_port:i32=8545,http_solidity_enable:bool=false,http_solidity_port:i32=8555,#[serde(rename="httpPBFTEnable")] http_pbft_enable:bool=false,#[serde(rename="httpPBFTPort")] http_pbft_port:i32=8565,max_block_range:i64=5000,max_address_size:i32=1000,max_sub_topics:i32=1000,max_block_filter_num:i32=50000,max_batch_size:i32=100,max_response_size:i64=26214400,max_log_filter_num:i32=20000,max_message_size:i32=4194304 });
default_struct!(DynamicConfig { enable:bool=false,check_interval:i64=600 }); default_struct!(SolidityConfig { threads:i32=0 }); default_struct!(ValidContractProto { threads:i32=0 });
default_struct!(DnsConfig { tree_urls:Vec<String>=vec![],publish:bool=false,dns_domain:String=String::new(),dns_private:String=String::new(),known_urls:Vec<String>=vec![],static_nodes:Vec<String>=vec![],max_merge_size:i32=5,change_threshold:f64=0.1,server_type:String=String::new(),access_key_id:String=String::new(),access_key_secret:String=String::new(),aliyun_dns_endpoint:String=String::new(),aws_region:String=String::new(),aws_host_zone_id:String=String::new() });
#[derive(Debug,Clone,Deserialize,Default)] #[serde(default)] pub struct ShutdownConfig { #[serde(rename="BlockTime")] pub block_time:Option<String>,#[serde(rename="BlockHeight")] pub block_height:Option<i64>,#[serde(rename="BlockCount")] pub block_count:Option<i64> }

default_struct!(PrometheusConfig { enable:bool=false,port:i32=9527 }); default_struct!(MetricsConfig { prometheus:PrometheusConfig=PrometheusConfig::default() });
default_struct!(VmConfig { support_constant:bool=false,max_energy_limit_for_constant:i64=100_000_000,lru_cache_size:usize=500,min_time_ratio:f64=0.0,max_time_ratio:f64=5.0,save_internal_tx:bool=false,save_featured_internal_tx:bool=false,save_cancel_all_unfreeze_v2_details:bool=false,long_running_time:i32=10,estimate_energy:bool=false,estimate_energy_max_retry:i32=3,vm_trace:bool=false,constant_call_timeout_ms:i64=0 });
impl VmConfig { fn normalize(&mut self)->Result<(),ConfigError>{if self.constant_call_timeout_ms<0{return Err(ConfigError::Invalid("vm.constantCallTimeoutMs must be non-negative".into()));}if self.max_time_ratio<self.min_time_ratio{return Err(ConfigError::Invalid("vm.maxTimeRatio must be >= minTimeRatio".into()));}Ok(())} }
default_struct!(BlockConfig { need_sync_check:bool=false,maintenance_time_interval:i64=21_600_000,proposal_expire_time:i64=259_200_000,check_frozen_time:i32=1 }); impl BlockConfig { fn normalize(&mut self)->Result<(),ConfigError>{if self.maintenance_time_interval<=0{return Err(ConfigError::Invalid("block.maintenanceTimeInterval must be positive".into()));}Ok(())} }

#[derive(Debug,Clone,Deserialize)] #[serde(default,rename_all="camelCase")]
pub struct CommitteeConfig { pub allow_creation_of_contracts:i64,pub allow_multi_sign:i64,pub allow_adaptive_energy:i64,pub allow_delegate_resource:i64,pub allow_same_token_name:i64,pub allow_tvm_transfer_trc10:i64,pub allow_tvm_constantinople:i64,pub allow_tvm_solidity059:i64,pub forbid_transfer_to_contract:i64,#[serde(rename="allowShieldedTRC20Transaction")] pub allow_shielded_trc20_transaction:i64,pub allow_market_transaction:i64,pub allow_transaction_fee_pool:i64,pub allow_black_hole_optimization:i64,pub allow_new_resource_model:i64,pub allow_tvm_istanbul:i64,pub allow_proto_filter_num:i64,pub allow_account_state_root:i64,pub changed_delegation:i64,#[serde(rename="allowPBFT",alias="allowPbft")] pub allow_pbft:i64,#[serde(rename="pBFTExpireNum",alias="pbftExpireNum")] pub pbft_expire_num:i64,pub allow_receipts_merkle_root:i64,#[serde(flatten)] pub remaining:BTreeMap<String,i64> }
impl Default for CommitteeConfig { fn default()->Self{Self{allow_creation_of_contracts:0,allow_multi_sign:0,allow_adaptive_energy:0,allow_delegate_resource:0,allow_same_token_name:0,allow_tvm_transfer_trc10:0,allow_tvm_constantinople:0,allow_tvm_solidity059:0,forbid_transfer_to_contract:0,allow_shielded_trc20_transaction:0,allow_market_transaction:0,allow_transaction_fee_pool:0,allow_black_hole_optimization:0,allow_new_resource_model:0,allow_tvm_istanbul:0,allow_proto_filter_num:0,allow_account_state_root:0,changed_delegation:0,allow_pbft:0,pbft_expire_num:20,allow_receipts_merkle_root:0,remaining:BTreeMap::new()}} }

default_struct!(GenesisRoot { block:GenesisConfig=GenesisConfig::default() });
default_struct!(GenesisConfig { assets:Vec<GenesisAsset>=vec![],witnesses:Vec<GenesisWitness>=vec![],timestamp:String=String::new(),parent_hash:String=String::new() });
default_struct!(GenesisAsset { account_name:String=String::new(),account_type:String=String::new(),address:String=String::new(),balance:String=String::new() });
default_struct!(GenesisWitness { address:String=String::new(),url:String=String::new(),vote_count:i64=0 });
impl GenesisConfig { fn validate(&self)->Result<(),ConfigError>{if self.assets.is_empty()&&self.timestamp.is_empty(){return Ok(());}if !self.assets.iter().any(|a|a.account_name=="Blackhole"){return Err(ConfigError::Invalid("genesis requires Blackhole asset".into()));}self.timestamp.parse::<i64>().map_err(|_|ConfigError::Invalid("genesis timestamp is not an i64".into()))?;Ok(())} }

default_struct!(EventRoot { subscribe:EventConfig=EventConfig::default() });
default_struct!(EventConfig { enable:bool=false,#[serde(rename="native")] native_queue:NativeEventConfig=NativeEventConfig::default(),version:i32=0,start_sync_block_num:i64=0,path:String=String::new(),server:String=String::new(),dbconfig:String=String::new(),contract_parse:bool=true,topics:Vec<EventTopic>=vec![],filter:EventFilter=EventFilter::default() });
default_struct!(NativeEventConfig { use_native_queue:bool=false,bindport:i32=5555,sendqueuelength:i32=1000 });
default_struct!(EventTopic { trigger_name:String=String::new(),enable:bool=false,topic:String=String::new(),solidified:bool=false,eth_compatible:bool=false,redundancy:bool=false });
default_struct!(EventFilter { fromblock:String=String::new(),toblock:String=String::new(),contract_address:Vec<String>=vec![String::new()],contract_topic:Vec<String>=vec![String::new()] });
#[derive(Debug,Clone)] pub struct EventRuntime { pub version:i32,pub start_sync_block_num:i64,pub native:NativeEventConfig,pub plugin_path:Option<String>,pub server:Option<String>,pub dbconfig:Option<String>,pub topics:Vec<EventTopic>,pub filter:EventFilter }
impl From<&EventConfig> for EventRuntime { fn from(v:&EventConfig)->Self{let plugin=!v.native_queue.use_native_queue;Self{version:v.version,start_sync_block_num:v.start_sync_block_num,native:v.native_queue.clone(),plugin_path:plugin.then(||v.path.trim().to_owned()).filter(|s|!s.is_empty()),server:plugin.then(||v.server.trim().to_owned()).filter(|s|!s.is_empty()),dbconfig:plugin.then(||v.dbconfig.trim().to_owned()).filter(|s|!s.is_empty()),topics:v.topics.clone(),filter:EventFilter{fromblock:v.filter.fromblock.trim().into(),toblock:v.filter.toblock.trim().into(),contract_address:v.filter.contract_address.iter().filter(|s|!s.is_empty()).cloned().collect(),contract_topic:v.filter.contract_topic.iter().filter(|s|!s.is_empty()).cloned().collect()}}} }

default_struct!(RateRoot { limiter:RateLimiterConfig=RateLimiterConfig::default() }); default_struct!(RateLimiterConfig { global:RateGlobal=RateGlobal::default(),p2p:P2pRateLimiter=P2pRateLimiter::default(),http:Vec<RateLimiterItem>=vec![],rpc:Vec<RateLimiterItem>=vec![],api_non_blocking:bool=false }); default_struct!(RateGlobal { qps:i32=50000,ip:RateQps=RateQps{qps:10000},api:RateQps=RateQps{qps:1000} }); default_struct!(RateQps { qps:i32=1000 }); default_struct!(P2pRateLimiter { sync_block_chain:f64=3.0,fetch_inv_data:f64=3.0,disconnect:f64=1.0 }); default_struct!(RateLimiterItem { component:String=String::new(),strategy:String=String::new(),param_string:String=String::new() });
default_struct!(CryptoConfig { engine:String="eckey".into() }); default_struct!(EneryConfig { limit:EneryLimit=EneryLimit::default() }); default_struct!(EneryLimit { block:EneryBlock=EneryBlock::default() }); default_struct!(EneryBlock { num:i64=4_727_890 }); default_struct!(TrxConfig { reference:TrxReference=TrxReference::default(),expiration:TrxExpiration=TrxExpiration::default() }); default_struct!(TrxReference { block:String="solid".into() }); default_struct!(TrxExpiration { time_in_milliseconds:i64=60_000 }); default_struct!(SeedRoot { node:SeedNodeConfig=SeedNodeConfig::default() }); default_struct!(SeedNodeConfig { ip:SeedIp=SeedIp::default() }); default_struct!(SeedIp { list:Vec<String>=vec![] });

#[derive(Debug,Clone,Default)] pub struct SeedNode { pub addresses:Vec<String> }
#[derive(Debug,Clone,Copy,Default,PartialEq,Eq)] pub enum WitnessKeySource { #[default] None, CliPrivateKey, ConfigPrivateKeys, ConfigKeystores }
#[derive(Debug,Clone,Default)] pub struct LocalWitnessConfig { pub private_keys:Vec<String>,pub account_address:Option<String>,pub keystores:Vec<String>,pub initialized:bool,pub source:WitnessKeySource,pub password:Option<String> }
#[derive(Debug,Clone)] pub struct MiscConfig { pub need_to_update_asset:bool,pub history_balance_lookup:bool,pub trx_reference_block:String,pub trx_expiration_time_in_milliseconds:i64,pub block_num_for_energy_limit:i64,pub crypto_engine:String,pub seed_node:SeedNode }
impl Default for MiscConfig { fn default()->Self{Self{need_to_update_asset:true,history_balance_lookup:false,trx_reference_block:"solid".into(),trx_expiration_time_in_milliseconds:60_000,block_num_for_energy_limit:4_727_890,crypto_engine:"eckey".into(),seed_node:SeedNode::default()}} }

/// Temporary CommonParameter/Storage-shaped value object. `allowReceiptsMerkleRoot` is
/// intentionally absent: Java has no bridge for it and adding one changes observable state.
#[derive(Debug,Clone)] pub struct CompatibilityBridge { pub support_constant:bool,pub max_energy_limit_for_constant:i64,pub db_engine:String,pub db_sync:bool,pub db_directory:String,pub transaction_history_switch:String,pub allow_pbft:i64,pub pbft_expire_num:i64,pub event_subscribe:bool,pub metrics_enable:bool,pub prometheus:PrometheusConfig,pub seed_nodes:Vec<String>,pub open_history_query_when_lite_fn:bool }

pub const SOURCE_INVENTORY_VERSION: &str = "c003-config-sources-v2";
pub const SOURCE_INVENTORY: &[SourceInventoryItem] = &[
    SourceInventoryItem::new("reference", "java-tron/common/src/main/resources/reference.conf", "fallback defaults"),
    SourceInventoryItem::new("packaged", "java-tron/framework/src/main/resources/config.conf", "default FullNode overlay"),
    SourceInventoryItem::new("external", "-c/--config", "user overlay replacing packaged config"),
    SourceInventoryItem::new("cli", "explicitly assigned CLI fields", "assigned overrides only"),
    SourceInventoryItem::new("event", "event.subscribe", "post-CLI OR stage"),
    SourceInventoryItem::new("platform", "runtime architecture", "ARM64 forces ROCKSDB"),
    SourceInventoryItem::new("witness", "localwitness/localwitnesskeystore", "last initialization stage"),
];
#[derive(Debug,Clone,Copy)] pub struct SourceInventoryItem { pub id:&'static str,pub source:&'static str,pub role:&'static str }
impl SourceInventoryItem { pub const fn new(id:&'static str,source:&'static str,role:&'static str)->Self{Self{id,source,role}} }
