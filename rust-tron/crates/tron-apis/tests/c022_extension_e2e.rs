use prost::Message;
use prost_reflect::ReflectMessage;
use std::{
    collections::BTreeSet,
    fs,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tron_apis::{ActorExecutionProvider, ApiContext, ExtensionApi, WalletMutation};
use tron_crypto::{CryptoEngine, PrivateKey, derive_address};
use tron_execution::{
    Actuator, ActuatorError, ActuatorRegistry, ActuatorResult, BlockConsensus, BlockLimits,
    BlockManager, CacheConfig, CanonicalChainManager, ChainActor, ExecutionConfig,
    ExecutionContext, ExecutionRuntimeConfig, ExtensionActuatorProvider,
    ExtensionProviderMetadata, ManagedBlock, PendingLimits, PendingPool, ProviderCodeIdentity,
    RawBlock, StateTransactionPipeline, StoreAccess, TransactionCache, TransactionProcessor,
    TrustedExtensionProvider, ValidationContext,
};
use tron_protocol::{
    extensions::{ExtensionDescriptor, ExtensionRegistry, RegistrationError},
    protocol::{block_header, Account, Block, BlockHeader},
};
use tron_state::{
    dynamic, CheckpointIdentity, CheckpointLimits, CheckpointStack, CursorPoint, CursorSet,
    KhaosBlockData, KhaosDatabase, SessionManager, StateStore, StoreKind,
};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};
fn parameters() -> Arc<tron_shielded::TronParameters> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");
    tron_shielded::load_tron_parameters(root.join("sapling-spend.params"), root.join("sapling-output.params")).unwrap()
}

const DESCRIPTOR: &[u8] =
    include_bytes!("../../tron-protocol/tests/fixtures/extensions/example_actuator.pb");
const MESSAGE: &str = "org.tron.example.actuator.ExampleContract";
const TYPE_URL: &str = "type.googleapis.com/org.tron.example.actuator.ExampleContract";
const OWNER_KEY: [u8; 32] = [23; 32];
const SHA: [u8; 32] = [
    0x1e, 0x34, 0x0f, 0x78, 0x46, 0x9d, 0x9a, 0xdc, 0xd0, 0xa2, 0x42, 0x31, 0x13, 0x04, 0x91, 0x9b,
    0xeb, 0xa2, 0xfa, 0x6a, 0x2b, 0xc0, 0xba, 0x5c, 0x02, 0xcd, 0x7e, 0xa1, 0x8f, 0x55, 0x75, 0x95,
];

#[derive(Clone, PartialEq, Message)]
struct ExampleContract {
    #[prost(bytes = "vec", tag = "1")]
    owner_address: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    payload: Vec<u8>,
}
struct Provider;
impl ExtensionActuatorProvider for Provider {
    fn metadata(&self) -> ExtensionProviderMetadata {
        ExtensionProviderMetadata {
            extension_id: "org.tron.example.actuator".into(),
            priority: 5,
            message_full_name: MESSAGE.into(),
            contract_type: 1000,
            max_payload_bytes: 128,
            state_access: vec![StoreAccess {
                store: StoreKind::Account,
                read: true,
                write: true,
            }],
        }
    }
    fn owner_address(&self, payload: &[u8]) -> Result<Vec<u8>, ActuatorError> {
        ExampleContract::decode(payload)
            .map(|message| message.owner_address)
            .map_err(|error| ActuatorError::validation(error.to_string()))
    }
    fn create_actuator(&self, payload: &[u8]) -> Result<Box<dyn Actuator>, ActuatorError> {
        Ok(Box::new(ExampleActuator(
            ExampleContract::decode(payload)
                .map_err(|error| ActuatorError::validation(error.to_string()))?,
        )))
    }
}
struct ExampleActuator(ExampleContract);
impl Actuator for ExampleActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> {
        Ok(&self.0.owner_address)
    }
    fn validate(&self, _: &ValidationContext<'_>) -> Result<(), ActuatorError> {
        if self.0.payload == b"malformed" {
            Err(ActuatorError::validation("extension validation failure"))
        } else {
            Ok(())
        }
    }
    fn execute_in(
        &self,
        context: &mut ExecutionContext<'_>,
        _: &mut ActuatorResult,
    ) -> Result<(), ActuatorError> {
        context.put(StoreKind::Account, &self.0.owner_address, &self.0.payload)
    }
}

fn descriptor(id: &str) -> ExtensionDescriptor {
    ExtensionDescriptor {
        extension_id: id.into(),
        priority: 5,
        descriptor_set: DESCRIPTOR.to_vec(),
        descriptor_sha256: SHA,
        message_full_name: MESSAGE.into(),
        contract_type: 1000,
    }
}
fn registry() -> Arc<ActuatorRegistry> {
    let identity = ProviderCodeIdentity {
        provider_id: "reviewed.example.native".into(),
        code_sha256: [0x5a; 32],
    };
    Arc::new(
        ActuatorRegistry::new(
            [descriptor("org.tron.example.actuator")],
            [TrustedExtensionProvider {
                identity: identity.clone(),
                provider: Arc::new(Provider),
            }],
            &BTreeSet::from([identity]),
        )
        .unwrap(),
    )
}

#[derive(Clone)]
struct FixtureConsensus;
impl BlockConsensus for FixtureConsensus {
    fn verify_witness_signature(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool { true }
    fn scheduled_witness(&self, _: i64, _: i64, _: i64) -> Result<Vec<u8>, String> { Ok(vec![0x41; 21]) }
}
fn context(registry: ActuatorRegistry, owner: &[u8]) -> (std::path::PathBuf, ApiContext, ChainActor) {
    let path = std::env::temp_dir().join(format!(
        "c022-extension-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let requirements = OpenRequirements {
        identity: StorageIdentity {
            network: "c022".into(),
            genesis: "00".into(),
        },
        schema_version: 1,
        backend: "rustlog".into(),
        backend_format: "rustlog-v1".into(),
        supported_features: vec!["rustlog-v1".into()],
    };
    let manager = SessionManager::new(StateStore::new(
        StorageManager::new(requirements).open_store(&path).unwrap(),
    ));
    for (name, value) in [
        ("LATEST_BLOCK_HEADER_TIMESTAMP", 100_i64),
        ("LATEST_BLOCK_HEADER_NUMBER", 7_i64),
    ] {
        manager.durable_store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(), &value.to_be_bytes()).unwrap();
    }
    manager.durable_store(StoreKind::RecentBlock).put(&[0, 7], &[9; 8]).unwrap();
    manager.durable_store(StoreKind::Account).put(owner, &Account { address: owner.to_vec(), balance: 1_000_000, ..Default::default() }.encode_to_vec()).unwrap();
    for (name, value) in [
        ("ALLOW_SAME_TOKEN_NAME", 0_i64), ("TRANSACTION_FEE", 0_i64),
        ("CREATE_ACCOUNT_FEE", 0_i64), ("CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", 0_i64),
        ("MULTI_SIGN_FEE", 0_i64), ("MEMO_FEE", 0_i64), ("UNFREEZE_DELAY_DAYS", 0_i64),
        ("ALLOW_HARDEN_RESOURCE_CALCULATION", 0_i64), ("CREATE_NEW_ACCOUNT_BANDWIDTH_RATE", 1_i64),
        ("MAX_CREATE_ACCOUNT_TX_SIZE", 1_000_i64), ("TOTAL_NET_LIMIT", 43_200_000_000_i64),
        ("FREE_NET_LIMIT", 5_000_i64), ("TOTAL_NET_WEIGHT", 1_i64),
        ("PUBLIC_NET_LIMIT", 14_400_000_000_i64), ("PUBLIC_NET_USAGE", 0_i64),
        ("PUBLIC_NET_TIME", 0_i64), ("ALLOW_TRANSACTION_FEE_POOL", 0_i64),
    ] { manager.durable_store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(), &value.to_be_bytes()).unwrap(); }
    let head_wire = Block { transactions: Vec::new(), block_header: Some(BlockHeader { raw_data: Some(block_header::Raw { timestamp: 100, parent_hash: vec![0; 32], number: 7, witness_address: vec![0x41; 21], tx_trie_root: vec![0; 32], ..Default::default() }), witness_signature: Vec::new() }) };
    let raw = RawBlock::decode(head_wire.encode_to_vec(), BlockLimits::default()).unwrap();
    let id = raw.block_id(CryptoEngine::Secp256k1).unwrap();
    manager.durable_store(StoreKind::DynamicProperties).put(dynamic::key("LATEST_BLOCK_HEADER_HASH").unwrap(), id.as_bytes()).unwrap();
    let point = CursorPoint { block: 7, identity: CheckpointIdentity::new(id.as_bytes().try_into().unwrap()) };
    manager.record_checkpoint(point).unwrap();
    CheckpointStack::new(manager.clone(), CheckpointLimits::default()).persist().unwrap();
    let cursors = CursorSet::new(&manager, point, None, None, 0).unwrap();
    let actuators = Arc::new(registry);
    let actor_sessions = manager.clone();
    let actor_actuators = actuators.clone();
    let actor = ChainActor::spawn(move || {
        let managed = ManagedBlock { raw, id, received_at: 100 };
        let mut khaos = KhaosDatabase::new();
        khaos.start(KhaosBlockData::new(id, tron_primitives::Hash32::ZERO, 7, managed)).map_err(|error| tron_execution::ChainManagerError::State(error.to_string()))?;
        let runtime = ExecutionRuntimeConfig { actuator_registry: actor_actuators, operation_registry: Arc::new(tron_tvm::OperationRegistry::integration().map_err(|error| tron_execution::ChainManagerError::State(format!("{error:?}")))?), shielded_parameters: parameters(), execution_config: ExecutionConfig::default(), constant_call_timeout: None, deadline_observer: None };
        let processor = TransactionProcessor::new(actor_sessions.clone(), TransactionCache::new(CacheConfig::default()).map_err(|error| tron_execution::ChainManagerError::State(error.to_string()))?, StateTransactionPipeline::new(Default::default(), runtime));
        let blocks = BlockManager::new(actor_sessions.clone(), processor, khaos, FixtureConsensus, (), BlockLimits::default(), CryptoEngine::Secp256k1);
        let pending = PendingPool::new(actor_sessions.clone(), PendingLimits::default()).map_err(|error| tron_execution::ChainManagerError::State(error.to_string()))?;
        let checkpoints = CheckpointStack::new(actor_sessions, CheckpointLimits::default());
        Ok(CanonicalChainManager::new_full(blocks, pending, checkpoints, (), ()))
    }, 32).unwrap();
    let execution = Arc::new(ActorExecutionProvider::new(actor.handle()));
    let api = ApiContext::new(cursors, Some(execution), actuators, parameters(), CryptoEngine::Secp256k1);
    (path, api, actor)
}

#[test]
fn trusted_extension_constructs_and_decodes_registered_payload() {
    let key = PrivateKey::from_bytes(CryptoEngine::Secp256k1, &OWNER_KEY).unwrap();
    let owner = derive_address(&key.public_key()).as_bytes().to_vec();
    let registry = registry();
    let processor_registry = ActuatorRegistry::new(
        [descriptor("org.tron.example.actuator")],
        [TrustedExtensionProvider {
            identity: ProviderCodeIdentity { provider_id: "reviewed.example.native".into(), code_sha256: [0x5a; 32] },
            provider: Arc::new(Provider),
        }],
        &BTreeSet::from([ProviderCodeIdentity { provider_id: "reviewed.example.native".into(), code_sha256: [0x5a; 32] }]),
    ).unwrap();
    let (path, context, actor) = context(processor_registry, &owner);
    let api = ExtensionApi::new(Arc::clone(&registry), WalletMutation::new(context.clone()), true);
    let payload = ExampleContract { owner_address: owner.clone(), payload: b"stored-value".to_vec() }.encode_to_vec();
    let transaction = api.construct("org.tron.example.actuator", payload).unwrap().transaction.unwrap();
    assert_eq!(api.owner_address(&transaction).unwrap(), owner);
    let decoded = api.decode_payload(&transaction).unwrap();
    assert_eq!(decoded.descriptor().full_name(), MESSAGE);
    drop(context);
    actor.shutdown().unwrap();
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn malformed_payload_and_descriptor_collisions_fail_closed() {
    let registry = registry();
    let contract = ExtensionApi::contract(1000, TYPE_URL.into(), vec![0x0a, 0x80]);
    assert!(registry.owner_address(&contract).is_err());
    assert!(matches!(
        ExtensionRegistry::register([
            descriptor("org.tron.example.actuator"),
            descriptor("org.tron.example.actuator")
        ]),
        Err(RegistrationError::ExtensionIdCollision(_))
    ));
    let mut malformed = descriptor("malformed");
    malformed.descriptor_set = vec![0x0a, 0x80];
    assert!(ExtensionRegistry::register([malformed]).is_err());
}
