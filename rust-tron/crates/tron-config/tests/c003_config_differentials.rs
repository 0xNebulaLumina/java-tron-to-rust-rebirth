use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};
use tron_config::{CliError, Config, ConfigError, ConfigLimits, ConfigLoader, ConfigSource, DynamicNodeLists, NodeMode, ParsedCli, Platform, UnknownKeyPolicy, WitnessKeySource, load_runtime_config};

static EXTERNAL_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct ExternalConfig {
    path: PathBuf,
}

impl ExternalConfig {
    fn new(contents: &str) -> Self {
        for _ in 0..32 {
            let sequence = EXTERNAL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "tron-c003-{}-{sequence}.conf",
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(contents.as_bytes()).unwrap();
                    return Self { path };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("failed to create external config fixture: {error}"),
            }
        }
        panic!("failed to allocate external config fixture after 32 attempts");
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ExternalConfig {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[test]
fn reference_and_bundled_sources_are_distinct() {
    let loader = ConfigLoader::default();
    let bundled = loader.load(ConfigSource::Bundled).unwrap();
    assert_eq!(bundled.node.listen.port, 18888);
    assert_eq!(bundled.node.http.full_node_port, 8090);
}

#[test]
fn external_source_bypasses_packaged_overlay() {
    let external = ExternalConfig::new("node.listen.port = 19999\n");
    let config = ConfigLoader::default()
        .load(ConfigSource::External(external.path().to_owned()))
        .unwrap();
    assert_eq!(config.node.listen.port, 19999);
}

#[test]
fn cli_aliases_values_and_seed_operands_are_assigned() {
    let cli = ParsedCli::parse(["-d", "cli-output", "--rpc-thread", "7", "seed-a"]).unwrap();
    assert_eq!(cli.overrides.output_directory.as_deref(), Some("cli-output"));
    assert_eq!(cli.overrides.rpc_thread_num, Some(7));
    assert_eq!(cli.overrides.seed_nodes, ["seed-a"]);
}

#[test]
fn witness_config_private_keys_precede_keystore_fallback() {
    let cli = ParsedCli::parse(["-w", "--password", "secret"]).unwrap();
    let mut config = ConfigLoader::default().load_str("localwitness=[\"01\"]\nlocalwitnesskeystore=[\"key.json\"]").unwrap();
    config.apply_cli(&cli.overrides);
    config.apply_witness_stage(&cli.overrides).unwrap();
    assert_eq!(config.witness.source, WitnessKeySource::ConfigPrivateKeys);
    assert_eq!(config.witness.private_keys, ["01"]);

    let mut fallback = ConfigLoader::default().load_str("localwitness=[]\nlocalwitnesskeystore=[\"key.json\"]").unwrap();
    fallback.apply_cli(&cli.overrides);
    fallback.apply_witness_stage(&cli.overrides).unwrap();
    assert_eq!(fallback.witness.source, WitnessKeySource::ConfigKeystores);
    assert_eq!(fallback.witness.keystores, ["key.json"]);
    assert_eq!(fallback.witness.password.as_deref(), Some("secret"));
}

#[test]
fn witness_cli_material_has_priority() {
    let cli = ParsedCli::parse(["-w", "-p", "01", "--witness-address", "41aa"]).unwrap();
    let config = load_runtime_config(&cli, Platform::X86_64).unwrap();
    assert!(config.witness.initialized);
    assert_eq!(config.witness.source, WitnessKeySource::CliPrivateKey);
    assert_eq!(config.witness.private_keys, ["01"]);
}

#[test]
fn runtime_precedence_cli_platform_and_event() {
    let cli = ParsedCli::parse(["-d", "cli-output", "--es", "--storage-db-engine", "leveldb"]).unwrap();
    let config = load_runtime_config(&cli, Platform::Arm64).unwrap();
    assert_eq!(config.storage.output_directory, "cli-output");
    assert!(config.runtime_event_subscribe);
    assert_eq!(config.storage.db.engine, "ROCKSDB");
}

#[test]
fn canonical_transport_defaults_match_java() {
    let config = Config::default();
    assert_eq!((config.node.listen.port, config.node.http.full_node_port, config.node.rpc.port, config.node.metrics.prometheus.port), (18888, 8090, 50051, 9527));
}

#[test]
fn jsonrpc_pbft_non_default_values_feed_enabled_api_ports() {
    let config = ConfigLoader::default()
        .load_str("node.jsonrpc.httpPBFTEnable = true\nnode.jsonrpc.httpPBFTPort = 18565")
        .unwrap();
    assert!(config.node.jsonrpc.http_pbft_enable);
    assert_eq!(config.node.jsonrpc.http_pbft_port, 18565);
}

#[test]
fn canonical_lite_history_query_key_feeds_typed_and_bridge_state() {
    let config = ConfigLoader::default()
        .load_str("node.openHistoryQueryWhenLiteFN = true")
        .unwrap();
    assert!(config.node.open_history_query_when_lite_fn);
    assert!(config.compatibility_bridge().open_history_query_when_lite_fn);
}

#[test]
fn loader_substitutions_do_not_read_ambient_environment() {
    assert!(std::env::var_os("PATH").is_some(), "test process must provide PATH");
    assert!(ConfigLoader::default().load_str("node.trustNode = ${PATH}").is_err());
}

#[test]
fn dynamic_reload_preserves_java_trust_order_and_duplicates() {
    let mut config = Config::default();
    config.node.active = vec!["shared".into(), "a".into()];
    config.node.passive = vec!["p".into(), "shared".into()];
    config.node.fast_forward = vec!["f".into(), "shared".into()];
    let projection = DynamicNodeLists::from_config(&config);
    assert_eq!(projection.active, ["shared", "a"]);
    assert_eq!(projection.passive, ["p", "shared"]);
    assert_eq!(projection.trust, ["p", "shared", "shared", "a", "f", "shared"]);
}

#[test]
fn solidity_and_keystore_modes_are_accepted_with_keystore_precedence() {
    assert_eq!(ParsedCli::parse(["--solidity", "--keystore-factory"]).unwrap().mode, NodeMode::KeystoreFactory);
    assert_eq!(ParsedCli::parse(["--keystore-factory", "--solidity"]).unwrap().mode, NodeMode::KeystoreFactory);
}

#[test]
fn deprecated_string_booleans_match_java_boolean_value_of() {
    let cli = ParsedCli::parse(["--storage-db-synchronous", "TRUE", "--contract-parse-enable", "not-true"]).unwrap();
    assert_eq!(cli.overrides.storage_db_sync, Some(true));
    assert_eq!(cli.overrides.contract_parse_enable, Some(false));
}

#[test]
fn strict_schema_rejects_nested_dotted_and_object_list_unknown_keys() {
    let loader = ConfigLoader::new(UnknownKeyPolicy::Reject);
    for source in [
        "node.rpc.typo = 1",
        "node { rpc { typo = 1 } }",
        "storage.properties = [{ name=\"account\", path=\"x\", typo=1 }]",
    ] {
        assert!(matches!(loader.load_str(source), Err(ConfigError::UnknownKeys(_))), "accepted {source}");
    }
    loader.load_str("node.maxActiveNodes = 12\nenery.limit.block.num = 8").unwrap();
}

#[test]
fn loader_limits_apply_to_initial_and_dynamic_reload() {
    let limits = ConfigLimits { source_bytes: 64, parsed_depth: 8, parsed_nodes: 32, list_length: 2, string_bytes: 8 };
    let loader = ConfigLoader::with_limits(UnknownKeyPolicy::Ignore, limits);
    assert!(matches!(loader.load_str("node.active=[\"a\",\"b\",\"c\"]"), Err(ConfigError::LimitExceeded { limit: "list length", .. })));
    let external = ExternalConfig::new("node.active=[\"a\",\"b\",\"c\"]");
    assert!(matches!(DynamicNodeLists::reload(&loader, ConfigSource::External(external.path().to_owned())), Err(ConfigError::LimitExceeded { .. })));
}

#[test]
fn cli_errors_are_structured_and_side_effect_free() {
    assert_eq!(ParsedCli::parse(["--unknown"]), Err(CliError::UnknownOption { option: "--unknown".into() }));
    assert!(matches!(ParsedCli::parse(["--p2p-disable", "maybe"]), Err(CliError::InvalidValue { expected: "boolean", .. })));
    assert!(matches!(ParsedCli::parse(["--rpc-thread"]), Err(CliError::MissingValue { .. })));
}
