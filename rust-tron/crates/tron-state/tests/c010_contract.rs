use std::cell::Cell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use tron_storage::{migrate_generation, open_manifest, resume_migration, rollback_migration, DurablePhase, FaultInjector, FormatError, GenerationMigrator, NoFaults, OpenRequirements, RustLogOptions, StorageIdentity, StorageManager, WriteFaultInjector, WritePhase};
use tron_state::{
    account_trie_key, adaptive_energy_limit, build_genesis, charge_fee, global_limit,
    initialize_genesis_config, update_weight, AccountTrie, AdaptiveEnergy, AssetGate, AssetKeys,
    DynamicError, DynamicProperties, DynamicValue, FeeDisposition, FeeSink, ForkClock,
    ForkController, ForkError, ForkMath, ForkSchedule, ForkVersion, GenesisAssetConfig,
    GenesisConfig, GenesisError, GenesisInit, GenesisWitnessConfig, GlobalResource,
    JavaForkMath, PropertyEncoding, ResourceWindow, StateStore, StoreKind,
};
use tron_state::account_trie::{TrieError, TrieLimits, MAX_TRIE_DEPTH, MAX_TRON_ADDRESS_BYTES};
use tron_protocol::protocol::Account;

fn temporary(name: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("tron-state-c010-{name}-{}-{nonce}", std::process::id()))
}

fn requirements(schema_version: u32) -> OpenRequirements {
    OpenRequirements {
        identity: StorageIdentity { network: "c010".into(), genesis: "7f".into() },
        schema_version,
        backend: "rustlog".into(),
        backend_format: "rustlog-v1".into(),
        supported_features: vec!["rustlog-v1".into()],
    }
}

fn initialize(path: &Path) {
    let store = StorageManager::new(requirements(1)).open_store(path).unwrap();
    store.close().unwrap();
}
fn state_store(name: &str) -> (PathBuf, StateStore) {
    let path = temporary(name);
    let store = StorageManager::new(requirements(1)).open_store(&path).unwrap();
    (path, StateStore::new(store))
}

fn logical_root(rows: &[(&[u8], &[u8])]) -> String {
    let mut bytes = Vec::new();
    let mut ordered = rows.to_vec();
    ordered.sort_by(|left, right| left.0.cmp(right.0));
    for (key, value) in ordered {
        bytes.extend_from_slice(&(key.len() as u64).to_be_bytes());
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    tron_crypto::keccak256(&bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

struct LogicalSchemaMigrator;
impl GenerationMigrator for LogicalSchemaMigrator {
    fn migrate(&self, _source: &Path, destination: &Path) -> Result<String, FormatError> {
        let rows: [(&[u8], &[u8]); 4] = [
            (b"account/alice", b"balance=7;asset-v2=1000001:3"),
            (b"dynamic/ALLOW_SAME_TOKEN_NAME", &1_i64.to_be_bytes()),
            (b"dynamic/STATE_SCHEMA_VERSION", &2_i64.to_be_bytes()),
            (b"trie/root", b"recomputed-not-copied"),
        ];
        let state = destination.join("logical-state.v2");
        let mut encoded = Vec::new();
        for (key, value) in rows { encoded.extend_from_slice(key); encoded.push(0); encoded.extend_from_slice(value); encoded.push(b'\n'); }
        fs::write(state, encoded).unwrap();
        Ok(logical_root(&rows))
    }
}

struct FailAt { phase: DurablePhase, fired: Cell<bool> }
impl FaultInjector for FailAt {
    fn after(&self, phase: DurablePhase) -> io::Result<()> {
        if phase == self.phase && !self.fired.replace(true) { Err(io::Error::other("c010 injected migration crash")) } else { Ok(()) }
    }
}

struct BlockWriteFailAt(WritePhase);
impl WriteFaultInjector for BlockWriteFailAt {
    fn before(&self, phase: WritePhase) -> io::Result<()> {
        if phase == self.0 { Err(io::Error::other(format!("c010 injected {phase:?} block write crash"))) } else { Ok(()) }
    }
}

#[test]
fn schema_manifest_version_and_recomputed_root_are_published_atomically() {
    let path = temporary("publish"); initialize(&path);
    let expected = logical_root(&[
        (b"account/alice", b"balance=7;asset-v2=1000001:3"),
        (b"dynamic/ALLOW_SAME_TOKEN_NAME", &1_i64.to_be_bytes()),
        (b"dynamic/STATE_SCHEMA_VERSION", &2_i64.to_be_bytes()),
        (b"trie/root", b"recomputed-not-copied"),
    ]);
    let manifest = migrate_generation(&path, &requirements(1), 2, &LogicalSchemaMigrator, &NoFaults).unwrap();
    assert_eq!((manifest.manifest_version, manifest.schema_version, manifest.generation), (1, 2, 1));
    assert_eq!(manifest.state_root, expected);
    assert_eq!(open_manifest(&path, &requirements(2)).unwrap(), manifest);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn pre_switch_crashes_rollback_without_exposing_staged_schema() {
    for phase in [DurablePhase::Preflight, DurablePhase::StagingCreated, DurablePhase::DataWritten, DurablePhase::DataSynced] {
        let path = temporary("rollback"); initialize(&path);
        let fault = FailAt { phase, fired: Cell::new(false) };
        assert!(migrate_generation(&path, &requirements(1), 2, &LogicalSchemaMigrator, &fault).is_err());
        if path.join("tron-storage.migration").exists() { rollback_migration(&path).unwrap(); }
        let manifest = open_manifest(&path, &requirements(1)).unwrap();
        assert_eq!((manifest.schema_version, manifest.generation), (1, 0));
        assert!(!path.join("generation-1").exists());
        fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn durable_switch_crashes_resume_and_restart_idempotently() {
    for phase in [DurablePhase::JournalSynced, DurablePhase::BackupSynced, DurablePhase::GenerationPublished, DurablePhase::ManifestSwitched, DurablePhase::DirectorySynced] {
        let path = temporary("resume"); initialize(&path);
        let fault = FailAt { phase, fired: Cell::new(false) };
        assert!(migrate_generation(&path, &requirements(1), 2, &LogicalSchemaMigrator, &fault).is_err());
        let resumed = resume_migration(&path, &requirements(2)).unwrap();
        assert_eq!((resumed.schema_version, resumed.generation), (2, 1));
        assert_eq!(open_manifest(&path, &requirements(2)).unwrap(), resumed);
        assert!(!path.join("tron-storage.migration").exists());
        fs::remove_dir_all(path).unwrap();
    }
}

const SCHEMA_FIXTURES: &[(&str, DurablePhase, bool)] = &[
    ("schema-migrations:preflight-crash", DurablePhase::Preflight, false),
    ("schema-migrations:staging-created-crash", DurablePhase::StagingCreated, false),
    ("schema-migrations:data-written-crash", DurablePhase::DataWritten, false),
    ("schema-migrations:data-synced-crash", DurablePhase::DataSynced, false),
    ("schema-migrations:journal-synced-crash", DurablePhase::JournalSynced, true),
    ("schema-migrations:backup-synced-crash", DurablePhase::BackupSynced, true),
    ("schema-migrations:generation-published-crash", DurablePhase::GenerationPublished, true),
    ("schema-migrations:manifest-switched-crash", DurablePhase::ManifestSwitched, true),
    ("schema-migrations:directory-synced-crash", DurablePhase::DirectorySynced, true),
];

#[test]
fn generated_schema_migration_crash_phase_dispatch() {
    for &(id, phase, switched) in SCHEMA_FIXTURES {
        let path = temporary(id);
        initialize(&path);
        let fault = FailAt { phase, fired: Cell::new(false) };
        assert!(migrate_generation(&path, &requirements(1), 2, &LogicalSchemaMigrator, &fault).is_err(), "{id}");
        if switched {
            let manifest = resume_migration(&path, &requirements(2)).unwrap();
            assert_eq!((manifest.schema_version, manifest.generation), (2, 1), "{id}");
        } else {
            if path.join("tron-storage.migration").exists() { rollback_migration(&path).unwrap(); }
            assert_eq!(open_manifest(&path, &requirements(1)).unwrap().schema_version, 1, "{id}");
        }
        fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn generated_genesis_fixture_dispatch() {
    use tron_primitives::DigestProvider;
    use tron_protocol::protocol::AccountType;

    let first = [vec![0x41], vec![0x11; 20]].concat();
    let second = [vec![0x41], vec![0x22; 20]].concat();
    let config = GenesisConfig {
        timestamp_raw: "0".into(),
        parent_hash_raw: "00".into(),
        assets: vec![
            GenesisAssetConfig { account_name: b"Blackhole".to_vec(), account_type: AccountType::Normal, address: first.clone(), balance: 7 },
            GenesisAssetConfig { account_name: b"Second".to_vec(), account_type: AccountType::AssetIssue, address: second.clone(), balance: 9 },
        ],
        witnesses: vec![
            GenesisWitnessConfig { address: first.clone(), url: "https://first-witness.invalid".into(), vote_count: 1 },
            GenesisWitnessConfig { address: second.clone(), url: "https://second-witness.invalid".into(), vote_count: 2 },
        ],
    };
    let digest = tron_crypto::Sha256Provider;
    let genesis = build_genesis(&config, &digest).unwrap();
    let hex = |bytes: &[u8]| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let fixture = include_str!("../../../../docs/oracles/c010-state-fixtures.v1.json");
    assert!(fixture.contains("genesis:accounts-witnesses-assets-block"));
    assert!(fixture.contains(&format!("tx0={}", hex(&genesis.block.transactions[0].encode_to_vec()))));
    assert!(fixture.contains(&format!("tx1={}", hex(&genesis.block.transactions[1].encode_to_vec()))));
    let transfer = tron_protocol::protocol::TransferContract::decode(
        genesis.block.transactions[0].raw_data.as_ref().unwrap().contract[0].parameter.as_ref().unwrap().value.as_slice(),
    ).unwrap();
    assert_eq!(transfer.owner_address, b"0x000000000000000000000");
    assert_eq!(transfer.owner_address.len(), 23);
    let transaction_ids = genesis.block.transactions.iter().map(|transaction| digest.digest(&transaction.raw_data.as_ref().unwrap().encode_to_vec()).unwrap()).collect::<Vec<_>>();
    assert_eq!(genesis.transaction_ids, transaction_ids, "genesis:transaction-id-raw-data");
    let merkle_leaves = genesis.block.transactions.iter().map(|transaction| digest.digest(&transaction.encode_to_vec()).unwrap()).collect::<Vec<_>>();
    assert_ne!(transaction_ids, merkle_leaves, "transaction IDs and Merkle leaves have distinct protobuf boundaries");
    let merkle = tron_primitives::merkle_root(&digest, &merkle_leaves).unwrap();
    assert_eq!(genesis.block.block_header.as_ref().unwrap().raw_data.as_ref().unwrap().tx_trie_root, merkle.as_bytes());
    assert!(fixture.contains(&format!("merkle={}", hex(merkle.as_bytes()))));
    assert!(fixture.contains(&format!("block_id={}", hex(genesis.id.as_bytes()))));
    assert!(fixture.contains(&format!("block={}", hex(&genesis.bytes))));
    for id in ["genesis:network-genesis-mismatch", "genesis:persisted-store-rows", "genesis:advanced-state-restart", "genesis:substituted-genesis-rejected", "genesis:substituted-marker-rejected"] {
        assert!(fixture.contains(id), "missing fixture {id}");
    }
    let directory = temporary("genesis-persisted-rows");
    let state = StateStore::new(StorageManager::new(requirements(1)).open_store(&directory).unwrap());
    assert_eq!(initialize_genesis_config(&state, &config, &genesis).unwrap(), GenesisInit::Created(genesis.id));
    let expected_recent_value = genesis.id.as_bytes()[8..16].to_vec();
    assert_eq!(state.store(StoreKind::RecentBlock).prefix(&[]), vec![(vec![0, 0], expected_recent_value.clone())]);
    let expected_witnesses = [first.as_slice(), second.as_slice()].concat();
    assert_eq!(state.store(StoreKind::WitnessSchedule).prefix(&[]), vec![(b"active_witnesses".to_vec(), expected_witnesses.clone())]);
    assert!(fixture.contains(&format!("recent-block:0000={}", hex(&expected_recent_value))));
    assert!(fixture.contains(&format!("witness_schedule:active_witnesses={}", hex(&expected_witnesses))));
    let marker = state.store(StoreKind::Common).get(b"genesis-state-v1").unwrap();
    drop(state);
    let reopened = StateStore::new(StorageManager::new(requirements(1)).open_store(&directory).unwrap());
    let mut batch = reopened.batch();
    batch.put(reopened.store(StoreKind::RecentBlock).name(), &[0, 0], &[0; 8]);
    batch.put(reopened.store(StoreKind::DynamicProperties).name(), b"LATEST_BLOCK_HEADER_NUMBER", &7_i64.to_be_bytes());
    batch.put(reopened.store(StoreKind::Block).name(), &[0x77; 32], b"advanced-block");
    batch.commit().unwrap();
    assert_eq!(initialize_genesis_config(&reopened, &config, &genesis).unwrap(), GenesisInit::Existing(genesis.id), "genesis:advanced-state-restart");

    let mut batch = reopened.batch();
    batch.put(reopened.store(StoreKind::Block).name(), genesis.id.as_bytes(), b"substituted");
    batch.commit().unwrap();
    assert_eq!(initialize_genesis_config(&reopened, &config, &genesis), Err(GenesisError::CorruptState("genesis block")), "genesis:substituted-genesis-rejected");
    let mut batch = reopened.batch();
    batch.put(reopened.store(StoreKind::Block).name(), genesis.id.as_bytes(), &genesis.bytes);
    batch.put(reopened.store(StoreKind::BlockIndex).name(), &0_i64.to_be_bytes(), &[0x55; 32]);
    batch.commit().unwrap();
    assert_eq!(initialize_genesis_config(&reopened, &config, &genesis), Err(GenesisError::CorruptState("genesis chain id")), "genesis:substituted-genesis-rejected");
    let mut batch = reopened.batch();
    batch.put(reopened.store(StoreKind::BlockIndex).name(), &0_i64.to_be_bytes(), genesis.id.as_bytes());
    batch.put(reopened.store(StoreKind::Common).name(), b"genesis-state-v1", &[0x44; 64]);
    batch.commit().unwrap();
    assert_eq!(initialize_genesis_config(&reopened, &config, &genesis), Err(GenesisError::IncompatibleChain), "genesis:substituted-marker-rejected");
    let mut batch = reopened.batch();
    batch.put(reopened.store(StoreKind::Common).name(), b"genesis-state-v1", &marker);
    batch.commit().unwrap();
    let mut substituted_config = config.clone();
    substituted_config.assets[0].balance += 1;
    assert_eq!(initialize_genesis_config(&reopened, &substituted_config, &genesis), Err(GenesisError::IncompatibleChain), "genesis:network-genesis-mismatch");
    drop(reopened);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn generated_dynamic_defaults_fixture_dispatch() {
    let (path, state) = state_store("dynamic-dispatch");
    let properties = DynamicProperties::new(state.store(StoreKind::DynamicProperties));
    let defaults = vec![
        ("TOTAL_SIGN_NUM".to_owned(), DynamicValue::Int(27)),
        ("MEMO_FEE".to_owned(), DynamicValue::Long(9)),
        ("ALLOW_SAME_TOKEN_NAME".to_owned(), DynamicValue::Long(1)),
    ];
    assert_eq!(properties.initialize_migration_missing(&defaults).unwrap(), 3, "dynamic-defaults:fresh-chain-defaults");
    assert_eq!(properties.get_int("TOTAL_SIGN_NUM").unwrap(), 27, "dynamic-defaults:fresh-chain-defaults");
    properties.save_long("MEMO_FEE", 7).unwrap();
    assert_eq!(properties.initialize_migration_missing(&defaults).unwrap(), 0, "dynamic-defaults:missing-only-migration");
    assert_eq!(properties.get_long("MEMO_FEE").unwrap(), 7, "dynamic-defaults:missing-only-migration");
    assert_eq!(DynamicProperties::key("ALLOW_SAME_TOKEN_NAME").unwrap(), b" ALLOW_SAME_TOKEN_NAME", "dynamic-defaults:leading-space-property");
    assert_eq!(properties.get_long("ALLOW_SAME_TOKEN_NAME").unwrap(), 1, "dynamic-defaults:leading-space-property");
    drop(state);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn dynamic_block_slots_are_atomic_across_c007_precommit_faults_and_retry() {
    for phase in [WritePhase::Append, WritePhase::Flush, WritePhase::Sync] {
        let path = temporary(&format!("dynamic-block-{phase:?}"));
        let options = RustLogOptions { sync_on_write: true, compact_after_bytes: 0, ..RustLogOptions::default() };
        let manager = StorageManager::with_options(requirements(1), options).unwrap();
        let state = StateStore::new(manager.open_store(&path).unwrap());
        let properties = DynamicProperties::new(state.store(StoreKind::DynamicProperties));
        let mut old_slots = vec![0; 128];
        old_slots[..63].fill(1);
        properties.save_raw("BLOCK_FILLED_SLOTS", &old_slots).unwrap();
        properties.save_int("BLOCK_FILLED_SLOTS_INDEX", 127).unwrap();

        assert!(properties.apply_block_with_faults(true, &BlockWriteFailAt(phase)).is_err(), "dynamic-slots:atomic-precommit-retry {phase:?}");
        assert_eq!(properties.get_raw("BLOCK_FILLED_SLOTS").unwrap(), old_slots, "dynamic-slots:atomic-precommit-retry slots {phase:?}");
        assert_eq!(properties.get_int("BLOCK_FILLED_SLOTS_INDEX").unwrap(), 127, "dynamic-slots:atomic-precommit-retry index {phase:?}");

        drop(properties);
        drop(state);
        let reopened = StateStore::new(StorageManager::new(requirements(1)).open_store(&path).unwrap());
        let properties = DynamicProperties::new(reopened.store(StoreKind::DynamicProperties));
        assert_eq!(properties.get_raw("BLOCK_FILLED_SLOTS").unwrap(), old_slots, "dynamic-slots:atomic-precommit-retry reopen slots {phase:?}");
        assert_eq!(properties.get_int("BLOCK_FILLED_SLOTS_INDEX").unwrap(), 127, "dynamic-slots:atomic-precommit-retry reopen index {phase:?}");

        properties.apply_block(true).unwrap();
        let slots = properties.get_raw("BLOCK_FILLED_SLOTS").unwrap();
        assert_eq!(slots.iter().map(|&slot| u32::from(slot)).sum::<u32>(), 64, "dynamic-slots:atomic-precommit-retry retry {phase:?}");
        assert_eq!(properties.get_int("BLOCK_FILLED_SLOTS_INDEX").unwrap(), 0, "dynamic-slots:atomic-precommit-retry retry index {phase:?}");
        assert_eq!(properties.calculate_filled_slots_count().unwrap(), 50, "dynamic-slots:filled-percentage {phase:?}");
        drop(properties);
        drop(reopened);
        fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn generated_fork_fixture_dispatch() {
    let math = JavaForkMath;
    let activation = math.activation_time(100, 10).unwrap();
    for (id, height, expected) in [("fork-boundaries:before-at-after", 99, false), ("fork-boundaries:before-at-after", 100, true), ("fork-boundaries:before-at-after", 101, true)] {
        assert_eq!(height >= activation, expected, "{id} at {height}");
    }
    assert!(matches!(math.activation_time(i64::MIN, 10), Err(tron_state::ForkError::TimestampOverflow { operation: "subtract" })), "fork-boundaries:before-at-after hardForkTime MIN");
    assert_eq!(math.activation_time(100, 0), Err(tron_state::ForkError::InvalidInterval), "fork-boundaries:before-at-after zero interval");
    assert_eq!(math.activation_time(100, -1), Err(tron_state::ForkError::InvalidInterval), "fork-boundaries:before-at-after negative interval");

    let (path, state) = state_store("maintenance-overflow");
    let properties = DynamicProperties::new(state.store(StoreKind::DynamicProperties));
    properties.save_long("MAINTENANCE_TIME_INTERVAL", 1).unwrap();
    properties.save_long("NEXT_MAINTENANCE_TIME", i64::MAX).unwrap();
    assert!(matches!(properties.update_next_maintenance_time(i64::MAX), Err(DynamicError::MaintenanceTimestampOverflow { operation: "add" })), "fork-boundaries:before-at-after maintenance max");
    assert_eq!(properties.get_long("NEXT_MAINTENANCE_TIME").unwrap(), i64::MAX, "fork-boundaries:before-at-after max overflow no write");

    properties.save_long("NEXT_MAINTENANCE_TIME", i64::MIN).unwrap();
    assert_eq!(properties.update_next_maintenance_time(i64::MIN).unwrap(), i64::MIN + 1, "fork-boundaries:before-at-after maintenance min");
    properties.save_long("NEXT_MAINTENANCE_TIME", 77).unwrap();
    for interval in [0, -1] {
        properties.save_long("MAINTENANCE_TIME_INTERVAL", interval).unwrap();
        assert_eq!(properties.update_next_maintenance_time(100), Err(DynamicError::InvalidMaintenanceInterval), "fork-boundaries:before-at-after non-positive interval");
        assert_eq!(properties.get_long("NEXT_MAINTENANCE_TIME").unwrap(), 77, "fork-boundaries:before-at-after invalid interval no write");
    }
    drop(state);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn fork_version_number_uses_java_int_encoding() {
    let (path, state) = state_store("fork-version-int");
    let properties = DynamicProperties::new(state.store(StoreKind::DynamicProperties));
    assert_eq!(DynamicProperties::encoding("VERSION_NUMBER").unwrap(), PropertyEncoding::Int, "fork-boundaries:version-number-int-encoding");
    properties.save_long("MAINTENANCE_TIME_INTERVAL", 10).unwrap();
    properties.store().put(DynamicProperties::key("VERSION_NUMBER").unwrap(), &0_i32.to_be_bytes()).unwrap();
    properties.save_fork_stats(6, &[1]).unwrap();
    let schedule = QuorumSchedule([ForkVersion { version: 6, hard_fork_time: 0, hard_fork_rate: 100 }]);
    let clock = QuorumClock;
    let math = JavaForkMath;
    let controller = ForkController::new(properties.clone(), &schedule, &clock, &math, i64::MAX);
    assert_eq!(controller.init(&[b"a".to_vec()]).unwrap(), 6, "fork-boundaries:version-number-int-encoding activation");
    assert_eq!(properties.get_raw("VERSION_NUMBER").unwrap(), 6_i32.to_be_bytes(), "fork-boundaries:version-number-int-encoding persisted bytes");

    drop(controller);
    drop(properties);
    drop(state);
    let reopened = StateStore::new(StorageManager::new(requirements(1)).open_store(&path).unwrap());
    let properties = DynamicProperties::new(reopened.store(StoreKind::DynamicProperties));
    assert_eq!(properties.get_int("VERSION_NUMBER").unwrap(), 6, "fork-boundaries:version-number-int-encoding reopen");
    assert_eq!(properties.get_raw("VERSION_NUMBER").unwrap().len(), 4, "fork-boundaries:version-number-int-encoding reopen length");

    properties.store().put(DynamicProperties::key("VERSION_NUMBER").unwrap(), &6_i64.to_be_bytes()).unwrap();
    let controller = ForkController::new(properties.clone(), &schedule, &clock, &math, i64::MAX);
    assert!(matches!(controller.init(&[b"a".to_vec()]), Err(ForkError::Dynamic(DynamicError::InvalidLength { ref name, expected: 4, actual: 8 })) if name == "VERSION_NUMBER"), "fork-boundaries:version-number-int-encoding malformed length");
    assert_eq!(properties.get_raw("VERSION_NUMBER").unwrap(), 6_i64.to_be_bytes(), "fork-boundaries:version-number-int-encoding malformed no fallback");
    drop(controller);
    drop(properties);
    drop(reopened);
    fs::remove_dir_all(path).unwrap();
}

struct QuorumSchedule([ForkVersion; 1]);
impl ForkSchedule for QuorumSchedule { fn versions(&self) -> &[ForkVersion] { &self.0 } }
struct QuorumClock;
impl ForkClock for QuorumClock { fn latest_block_number(&self) -> i64 { 0 } fn latest_block_timestamp(&self) -> i64 { 1_000 } }

#[test]
fn fork_quorum_tracks_current_witness_identities() {
    let (path, state) = state_store("fork-quorum");
    let properties = DynamicProperties::new(state.store(StoreKind::DynamicProperties));
    properties.save_long("MAINTENANCE_TIME_INTERVAL", 10).unwrap();
    properties.save_int("VERSION_NUMBER", 0).unwrap();
    let schedule = QuorumSchedule([ForkVersion { version: 6, hard_fork_time: 0, hard_fork_rate: 67 }]);
    let clock = QuorumClock;
    let math = JavaForkMath;
    let controller = ForkController::new(properties.clone(), &schedule, &clock, &math, i64::MAX);
    let abc = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
    controller.update(&abc, b"a", 6).unwrap();
    controller.update(&abc, b"b", 6).unwrap();
    assert!(!controller.pass(6, &abc).unwrap(), "fork-quorum:no-premature-activation-before-threshold");
    controller.update(&abc, b"c", 6).unwrap();
    assert!(controller.pass(6, &abc).unwrap(), "fork-quorum:threshold-reached");
    assert_eq!(properties.get_int("VERSION_NUMBER").unwrap(), 0, "fork-quorum:no-premature-activation");

    let abcd = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
    assert!(controller.pass(6, &abcd).unwrap(), "fork-quorum:growth-preserves-current-identities");
    controller.update(&abcd, b"d", 6).unwrap();
    assert_eq!(properties.get_int("VERSION_NUMBER").unwrap(), 6, "fork-quorum:publish-after-normalized-pass");

    let ac = vec![b"a".to_vec(), b"c".to_vec()];
    assert!(controller.pass(6, &ac).unwrap(), "fork-quorum:shrink-preserves-current-identities");
    properties.save_int("VERSION_NUMBER", 0).unwrap();
    properties.store().delete(b"FORK_WITNESSES_6").unwrap();
    properties.save_fork_stats(6, &[1]).unwrap();
    assert!(!controller.pass(6, &abc).unwrap(), "fork-quorum:stale-short-resized");
    properties.save_fork_stats(6, &[1, 1, 1, 1]).unwrap();
    assert!(!controller.pass(6, &abc).unwrap(), "fork-quorum:stale-long-resized");
    properties.save_fork_stats(6, &[1, 2, 0]).unwrap();
    assert!(matches!(controller.pass(6, &abc), Err(ForkError::InvalidForkStatsValue { .. })), "fork-quorum:malformed-value-rejected");
    assert!(matches!(controller.pass(6, &[b"a".to_vec(), b"a".to_vec()]), Err(ForkError::InvalidWitnessMembership)), "fork-quorum:malformed-membership-rejected");
    drop(state);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn generated_resource_fixture_dispatch() {
    let legacy = ResourceWindow { usage: 100, latest_slot: 10, window: 20, precise: false, standard_window: 20 };
    assert_eq!(legacy.recover(15).unwrap(), 75, "resources:legacy-window");
    let precise = ResourceWindow { usage: 1000, latest_slot: 10, window: 2_000_000, precise: true, standard_window: 2_000 };
    assert_eq!(precise.window_slots().unwrap(), 2_000, "resources:precision-window units");
    assert_eq!(precise.recover(11).unwrap(), 999, "resources:precision-window");
    assert_eq!(precise.recover(1_010).unwrap(), 500, "resources:precision-window-midpoint");
    for (id, stored_window, expected_slots, expected_recovery) in [
        ("resources:precision-window-stored-1", 1, 2_000, 999),
        ("resources:precision-window-stored-999", 999, 2_000, 999),
        ("resources:precision-window-stored-1000", 1_000, 1, 0),
    ] {
        let boundary = ResourceWindow { usage: 1000, latest_slot: 10, window: stored_window, precise: true, standard_window: 2_000 };
        assert_eq!(boundary.window_slots().unwrap(), expected_slots, "{id} window slots");
        assert_eq!(boundary.recover(11).unwrap(), expected_recovery, "{id} recovery");
    }
    let adaptive = AdaptiveEnergy { base_limit: 1000, current_limit: 2000, target_limit: 10, average_usage: 11, multiplier: 10 };
    assert_eq!(adaptive_energy_limit(adaptive, (99, 100), (1000, 999)).unwrap(), 1980, "resources:adaptive-energy");
    let at_base = AdaptiveEnergy { current_limit: 1000, ..adaptive };
    assert_eq!(adaptive_energy_limit(at_base, (99, 100), (1000, 999)).unwrap(), 1000, "resources:adaptive-energy-base-floor");
    for sink in [FeeSink::Pool, FeeSink::Burn, FeeSink::BlackHole] {
        let result = charge_fee(100, 7, sink, FeeDisposition { payer_balance: 0, pool: 0, burned: 0, black_hole: 0 }).unwrap();
        assert_eq!(result.payer_balance, 93, "resources:fee-sinks");
    }
    assert_eq!(global_limit(1_000_000, GlobalResource { limit: 10, weight: 2 }, false).unwrap(), 5);
    assert!(update_weight(i64::MAX, 1, false).is_err(), "resources:weight-max-overflow");
    assert!(update_weight(i64::MIN, -1, false).is_err(), "resources:weight-min-overflow");
    assert_eq!(update_weight(-5, 3, true).unwrap(), 0, "resources:weight-clamp-interaction");
    assert!(adaptive_energy_limit(adaptive, (0, 1), (101, 100)).is_err(), "resources:adaptive-ratio-zero");
    assert!(adaptive_energy_limit(adaptive, (-1, 1), (101, 100)).is_err(), "resources:adaptive-ratio-negative");
    let (path, state) = state_store("adaptive-no-partial-write");
    let properties = DynamicProperties::new(state.store(StoreKind::DynamicProperties));
    properties.save_long("TOTAL_ENERGY_LIMIT", 100).unwrap();
    properties.save_long("TOTAL_ENERGY_CURRENT_LIMIT", 80).unwrap();
    properties.save_long("TOTAL_ENERGY_TARGET_LIMIT", 20).unwrap();
    properties.save_long("ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO", 0).unwrap();
    assert!(properties.save_total_energy_limit2(200).is_err(), "resources:adaptive-no-partial-write");
    assert_eq!(properties.get_long("TOTAL_ENERGY_LIMIT").unwrap(), 100, "resources:adaptive-no-partial-write");
    assert_eq!(properties.get_long("TOTAL_ENERGY_CURRENT_LIMIT").unwrap(), 80, "resources:adaptive-no-partial-write");
    assert_eq!(properties.get_long("TOTAL_ENERGY_TARGET_LIMIT").unwrap(), 20, "resources:adaptive-no-partial-write");
    drop(state);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn generated_asset_fixture_dispatch() {
    let keys = AssetKeys::new(b"USDT".to_vec(), b"1000001".to_vec()).unwrap();
    let (path, state) = state_store("asset-dispatch");
    let legacy = AssetGate { allow_same_token_name: false, optimize_account_assets: false };
    state.put_asset_issue(&keys, b"issue", legacy).unwrap();
    assert_eq!(state.asset_issue(b"USDT", legacy), Some(b"issue".to_vec()), "asset-transitions:legacy-dual-write");
    assert_eq!(state.asset_issue(b"1000001", AssetGate { allow_same_token_name: true, ..legacy }), Some(b"issue".to_vec()), "asset-transitions:legacy-dual-write");

    let v2 = AssetGate { allow_same_token_name: true, optimize_account_assets: false };
    state.put_asset_issue(&keys, b"v2", v2).unwrap();
    assert_eq!(state.asset_issue(b"1000001", v2), Some(b"v2".to_vec()), "asset-transitions:v2-only");

    let account = Account { address: vec![0x41; 21], ..Account::default() };
    let optimized = state.persist_asset_account(&account, &keys, 7, AssetGate { allow_same_token_name: true, optimize_account_assets: true }).unwrap();
    assert!(optimized.asset_v2.is_empty() && optimized.asset_optimized, "asset-transitions:externalized-balances");
    assert_eq!(state.all_account_assets(&optimized).unwrap().get("1000001"), Some(&7), "asset-transitions:externalized-balances");
    drop(state);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn generated_trie_rlp_fixture_dispatch() {
    let empty = AccountTrie::new().logical_root().unwrap();
    assert_eq!(empty, [0x56,0xe8,0x1f,0x17,0x1b,0xcc,0x55,0xa6,0xff,0x83,0x45,0xe6,0x92,0xc0,0xf8,0x6e,0x5b,0x48,0xe0,0x1b,0x99,0x6c,0xad,0xc0,0x01,0x62,0x2f,0xb5,0xe3,0x63,0xb4,0x21], "trie-rlp:empty-root");
    let decode_hex = |value: &str| -> Vec<u8> {
        value.as_bytes().chunks_exact(2).map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
        }).collect()
    };
    let mut single = AccountTrie::new();
    let single_account = Account { address: [vec![0x41], vec![0x11; 20]].concat(), balance: 7, allowance: 3, ..Account::default() };
    single.put_account(&single_account).unwrap();
    assert_eq!(single.logical_root().unwrap().as_slice(), decode_hex("6bb3e919f2027ff7ce0d7581a5ee6814161a798dfec064471e91fb5beb165c89"), "trie-rlp:single-tron-account-root");
    assert_eq!(single.root_node_encoding().unwrap().unwrap(), decode_hex("f49720954111111111111111111111111111111111111111119b1a1541111111111111111111111111111111111111111120075803"), "trie-rlp:single-tron-account-node");
    let mut shared = AccountTrie::new();
    for account in [
        Account { address: [vec![0x41], vec![0x11; 20]].concat(), balance: 7, allowance: 3, ..Account::default() },
        Account { address: [vec![0x41], vec![0x11; 19], vec![0x12]].concat(), balance: 9, ..Account::default() },
        Account { address: [vec![0x41], vec![0x22; 20]].concat(), balance: 11, allowance: 5, ..Account::default() },
    ] { shared.put_account(&account).unwrap(); }
    assert_eq!(shared.logical_root().unwrap().as_slice(), decode_hex("51932f64129c93edaadc133fa24deafe9916ec914dd69d968f5fdddd150fa502"), "trie-rlp:shared-prefix-root");
    assert_eq!(shared.root_node_encoding().unwrap().unwrap(), decode_hex("e583009541a05877f63628347e5ed54ab882f1d561b85680a9eec39095601aef441a21dac407"), "trie-rlp:shared-prefix-node");
    let mut forward = AccountTrie::new();
    forward.put_raw(account_trie_key(b"a").unwrap(), vec![1]).unwrap();
    forward.put_raw(account_trie_key(b"b").unwrap(), vec![2; 64]).unwrap();
    let forward_root = forward.logical_root().unwrap();
    let mut reverse = AccountTrie::new();
    reverse.put_raw(account_trie_key(b"b").unwrap(), vec![2; 64]).unwrap();
    reverse.put_raw(account_trie_key(b"a").unwrap(), vec![1]).unwrap();
    assert_eq!(forward_root, reverse.logical_root().unwrap(), "trie-rlp:insertion-order");
    assert_ne!(forward_root, empty, "trie-rlp:inline-child");
    assert!(forward.node(&forward_root).is_none(), "trie-rlp:hashed-child");
}

#[test]
fn generated_forced_root_fixture_dispatch() {
    let mut trie = AccountTrie::with_supplied_root(&[0; 32]).unwrap();
    trie.put_raw(account_trie_key(b"forced").unwrap(), vec![1]).unwrap();
    assert_eq!(trie.root_hash().unwrap(), [0; 32], "forced-root:report-vs-validation");
    assert!(trie.validate_supplied_root().is_err(), "forced-root:report-vs-validation");
}

#[test]
fn generated_duplicate_leaf_fixture_dispatch() {
    let mut trie = AccountTrie::new();
    let key = account_trie_key(b"duplicate").unwrap();
    trie.put_raw(key.clone(), b"first".to_vec()).unwrap();
    trie.put_raw(key, b"last".to_vec()).unwrap();
    assert_eq!(trie.get_address(b"duplicate").unwrap(), Some(b"last".as_slice()), "duplicate-leaf:last-value-replaces");
}

const TRIE_LIMIT_FIXTURES: &[&str] = &[
    "trie-limits:address-exact-max",
    "trie-limits:address-over-limit",
    "trie-limits:value-exact-max",
    "trie-limits:value-over-limit",
    "trie-limits:leaf-exact-max",
    "trie-limits:leaf-over-limit",
    "trie-limits:total-bytes-exact-max",
    "trie-limits:total-bytes-over-limit",
    "trie-limits:node-bytes-exact-max",
    "trie-limits:node-bytes-over-limit",
    "trie-limits:depth-exact-max",
    "trie-limits:depth-over-limit",
];
fn trie_limits(max_value_bytes: usize, max_leaves: usize, max_total_bytes: usize, max_node_bytes: usize, max_depth: usize) -> TrieLimits {

    TrieLimits { max_value_bytes, max_leaves, max_total_bytes, max_node_bytes, max_depth }
}

#[test]
fn generated_trie_limit_fixture_dispatch() {
    let mut account = Account { address: vec![0x41; MAX_TRON_ADDRESS_BYTES], ..Account::default() };
    assert_eq!(TRIE_LIMIT_FIXTURES.len(), 12);
    AccountTrie::new().put_account(&account).unwrap();
    account.address.push(0);
    assert_eq!(AccountTrie::new().put_account(&account), Err(TrieError::AddressTooLong { actual: 22, maximum: 21 }));

    let mut values = AccountTrie::with_limits(trie_limits(4, 4, 16, 1024, MAX_TRIE_DEPTH)).unwrap();
    values.put_raw([0; 32], vec![1; 4]).unwrap();
    assert_eq!(values.put_raw([1; 32], vec![1; 5]), Err(TrieError::ValueTooLarge { actual: 5, maximum: 4 }));

    let mut leaves = AccountTrie::with_limits(trie_limits(4, 2, 8, 1024, MAX_TRIE_DEPTH)).unwrap();
    leaves.put_raw([0; 32], vec![1]).unwrap();
    leaves.put_raw([1; 32], vec![1]).unwrap();
    assert_eq!(leaves.put_raw([2; 32], vec![1]), Err(TrieError::LeafLimitExceeded { actual: 3, maximum: 2 }));

    let mut total = AccountTrie::with_limits(trie_limits(4, 4, 5, 1024, MAX_TRIE_DEPTH)).unwrap();
    total.put_raw([0; 32], vec![1; 2]).unwrap();
    total.put_raw([1; 32], vec![1; 3]).unwrap();
    assert_eq!(total.put_raw([2; 32], vec![1]), Err(TrieError::TotalBytesLimitExceeded { actual: 6, maximum: 5 }));

    let mut exact_node = AccountTrie::with_limits(trie_limits(4, 1, 100, 36, MAX_TRIE_DEPTH)).unwrap();
    exact_node.put_raw([0; 32], vec![1]).unwrap();
    exact_node.logical_root().unwrap();
    let mut oversized_node = AccountTrie::with_limits(trie_limits(4, 1, 100, 35, MAX_TRIE_DEPTH)).unwrap();
    oversized_node.put_raw([0; 32], vec![1]).unwrap();
    assert_eq!(oversized_node.logical_root(), Err(TrieError::NodeBytesLimitExceeded { actual: 36, maximum: 35 }));

    let mut exact_depth = AccountTrie::new();
    exact_depth.put_raw([0; 32], vec![1]).unwrap();
    let mut exact_adjacent = [0; 32];
    exact_adjacent[31] = 1;
    exact_depth.put_raw(exact_adjacent, vec![1]).unwrap();
    exact_depth.logical_root().unwrap();

    let mut deep = AccountTrie::with_limits(trie_limits(4, 2, 8, 1024, MAX_TRIE_DEPTH - 1)).unwrap();
    deep.put_raw([0; 32], vec![1]).unwrap();
    let mut adjacent = [0; 32];
    adjacent[31] = 1;
    deep.put_raw(adjacent, vec![1]).unwrap();
    assert_eq!(deep.logical_root(), Err(TrieError::DepthLimitExceeded { actual: 64, maximum: 63 }));
}

#[test]
fn adversarial_shared_prefix_and_duplicate_roots_are_stable() {
    let mut shared = [0x11; 32];
    shared[31] = 0x12;
    let rows = [([0x11; 32], vec![1]), (shared, vec![2]), ([0x22; 32], vec![3])];
    let mut forward = AccountTrie::new();
    let mut reverse = AccountTrie::new();
    for (key, value) in &rows { forward.put_raw(*key, value.clone()).unwrap(); }
    for (key, value) in rows.iter().rev() { reverse.put_raw(*key, value.clone()).unwrap(); }
    assert_eq!(forward.logical_root().unwrap(), reverse.logical_root().unwrap(), "trie-rlp:shared-prefix");

    forward.put_raw(shared, vec![9]).unwrap();
    let mut replaced = AccountTrie::new();
    replaced.put_raw([0x11; 32], vec![1]).unwrap();
    replaced.put_raw(shared, vec![9]).unwrap();
    replaced.put_raw([0x22; 32], vec![3]).unwrap();
    assert_eq!(forward.logical_root().unwrap(), replaced.logical_root().unwrap(), "duplicate-leaf:bounded-replacement");
}

const C010_CASE_TABLE: &[(&str, fn())] = &[
    ("genesis:accounts-witnesses-assets-block", generated_genesis_fixture_dispatch),
    ("genesis:persisted-store-rows", generated_genesis_fixture_dispatch),
    ("genesis:network-genesis-mismatch", generated_genesis_fixture_dispatch),
    ("genesis:transaction-id-raw-data", generated_genesis_fixture_dispatch),
    ("genesis:advanced-state-restart", generated_genesis_fixture_dispatch),
    ("genesis:substituted-genesis-rejected", generated_genesis_fixture_dispatch),
    ("genesis:substituted-marker-rejected", generated_genesis_fixture_dispatch),
    ("dynamic-defaults:fresh-chain-defaults", generated_dynamic_defaults_fixture_dispatch),
    ("dynamic-defaults:missing-only-migration", generated_dynamic_defaults_fixture_dispatch),
    ("dynamic-defaults:leading-space-property", generated_dynamic_defaults_fixture_dispatch),
    ("dynamic-slots:atomic-precommit-retry", dynamic_block_slots_are_atomic_across_c007_precommit_faults_and_retry),
    ("dynamic-slots:filled-percentage", dynamic_block_slots_are_atomic_across_c007_precommit_faults_and_retry),
    ("fork-boundaries:before-at-after", generated_fork_fixture_dispatch),
    ("fork-boundaries:version-number-int-encoding", fork_version_number_uses_java_int_encoding),
    ("fork-quorum:current-membership", fork_quorum_tracks_current_witness_identities),
    ("resources:legacy-window", generated_resource_fixture_dispatch),
    ("resources:precision-window", generated_resource_fixture_dispatch),
    ("resources:precision-window-midpoint", generated_resource_fixture_dispatch),
    ("resources:precision-window-stored-1", generated_resource_fixture_dispatch),
    ("resources:precision-window-stored-999", generated_resource_fixture_dispatch),
    ("resources:precision-window-stored-1000", generated_resource_fixture_dispatch),
    ("resources:adaptive-energy", generated_resource_fixture_dispatch),
    ("resources:adaptive-energy-base-floor", generated_resource_fixture_dispatch),
    ("resources:fee-sinks", generated_resource_fixture_dispatch),
    ("resources:weight-max-overflow", generated_resource_fixture_dispatch),
    ("resources:weight-min-overflow", generated_resource_fixture_dispatch),
    ("resources:weight-clamp-interaction", generated_resource_fixture_dispatch),
    ("resources:adaptive-ratio-zero", generated_resource_fixture_dispatch),
    ("resources:adaptive-ratio-negative", generated_resource_fixture_dispatch),
    ("resources:adaptive-no-partial-write", generated_resource_fixture_dispatch),
    ("asset-transitions:legacy-dual-write", generated_asset_fixture_dispatch),
    ("asset-transitions:v2-only", generated_asset_fixture_dispatch),
    ("asset-transitions:externalized-balances", generated_asset_fixture_dispatch),
    ("trie-rlp:empty-root", generated_trie_rlp_fixture_dispatch),
    ("trie-rlp:inline-child", generated_trie_rlp_fixture_dispatch),
    ("trie-rlp:hashed-child", generated_trie_rlp_fixture_dispatch),
    ("trie-rlp:insertion-order", generated_trie_rlp_fixture_dispatch),
    ("trie-rlp:shared-prefix", adversarial_shared_prefix_and_duplicate_roots_are_stable),
    ("trie-rlp:single-tron-account-root", generated_trie_rlp_fixture_dispatch),
    ("trie-rlp:single-tron-account-node", generated_trie_rlp_fixture_dispatch),
    ("trie-rlp:shared-prefix-root", generated_trie_rlp_fixture_dispatch),
    ("trie-rlp:shared-prefix-node", generated_trie_rlp_fixture_dispatch),
    ("trie-limits:address-exact-max", generated_trie_limit_fixture_dispatch),
    ("trie-limits:address-over-limit", generated_trie_limit_fixture_dispatch),
    ("trie-limits:value-exact-max", generated_trie_limit_fixture_dispatch),
    ("trie-limits:value-over-limit", generated_trie_limit_fixture_dispatch),
    ("trie-limits:leaf-exact-max", generated_trie_limit_fixture_dispatch),
    ("trie-limits:leaf-over-limit", generated_trie_limit_fixture_dispatch),
    ("trie-limits:total-bytes-exact-max", generated_trie_limit_fixture_dispatch),
    ("trie-limits:total-bytes-over-limit", generated_trie_limit_fixture_dispatch),
    ("trie-limits:node-bytes-exact-max", generated_trie_limit_fixture_dispatch),
    ("trie-limits:node-bytes-over-limit", generated_trie_limit_fixture_dispatch),
    ("trie-limits:depth-exact-max", generated_trie_limit_fixture_dispatch),
    ("trie-limits:depth-over-limit", generated_trie_limit_fixture_dispatch),
    ("forced-root:report-vs-validation", generated_forced_root_fixture_dispatch),
    ("duplicate-leaf:last-value-replaces", generated_duplicate_leaf_fixture_dispatch),
    ("duplicate-leaf:bounded-replacement", adversarial_shared_prefix_and_duplicate_roots_are_stable),
    ("schema-migrations:manifest-version", schema_manifest_version_and_recomputed_root_are_published_atomically),
    ("schema-migrations:recomputed-root", schema_manifest_version_and_recomputed_root_are_published_atomically),
    ("schema-migrations:pre-switch-rollback", pre_switch_crashes_rollback_without_exposing_staged_schema),
    ("schema-migrations:post-switch-resume", durable_switch_crashes_resume_and_restart_idempotently),
    ("schema-migrations:restart-idempotence", durable_switch_crashes_resume_and_restart_idempotently),
    ("schema-migrations:preflight-crash", generated_schema_migration_crash_phase_dispatch),
    ("schema-migrations:staging-created-crash", generated_schema_migration_crash_phase_dispatch),
    ("schema-migrations:data-written-crash", generated_schema_migration_crash_phase_dispatch),
    ("schema-migrations:data-synced-crash", generated_schema_migration_crash_phase_dispatch),
    ("schema-migrations:journal-synced-crash", generated_schema_migration_crash_phase_dispatch),
    ("schema-migrations:backup-synced-crash", generated_schema_migration_crash_phase_dispatch),
    ("schema-migrations:generation-published-crash", generated_schema_migration_crash_phase_dispatch),
    ("schema-migrations:manifest-switched-crash", generated_schema_migration_crash_phase_dispatch),
    ("schema-migrations:directory-synced-crash", generated_schema_migration_crash_phase_dispatch),
];

#[test]
fn generated_c010_parameterized_case_dispatch() {
    for &(id, execute) in C010_CASE_TABLE {
        eprintln!("executing {id}");
        execute();
    }
}
