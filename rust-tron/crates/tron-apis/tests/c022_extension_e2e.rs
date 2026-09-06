use prost::Message;
use prost_reflect::ReflectMessage;
use std::{
    collections::BTreeSet,
    fs,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tron_apis::{ApiContext, ApiCursor, ExtensionApi, WalletMutation, WalletQuery};
use tron_crypto::{CryptoEngine, PrivateKey, derive_address, selected_digest};
use tron_execution::{
    Actuator, ActuatorError, ActuatorRegistry, ActuatorResult, CacheConfig, ExecutionConfig,
    ExecutionContext, ExtensionActuatorProvider, ExtensionProviderMetadata, PendingLimits,
    PendingPool, ProviderCodeIdentity, StateTransactionPipeline, StoreAccess, TransactionCache,
    TransactionProcessor, TrustedExtensionProvider, ValidationContext,
};
use tron_protocol::{
    extensions::{ExtensionDescriptor, ExtensionRegistry, RegistrationError},
    protocol::{Account, r#return::ResponseCode},
};
use tron_state::{
    CheckpointIdentity, CursorPoint, CursorSet, SessionManager, StateStore, StoreKind, dynamic,
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
fn context(registry: ActuatorRegistry, owner: &[u8]) -> (std::path::PathBuf, ApiContext) {
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
        manager
            .durable_store(StoreKind::DynamicProperties)
            .put(dynamic::key(name).unwrap(), &value.to_be_bytes())
            .unwrap();
    }
    manager
        .durable_store(StoreKind::DynamicProperties)
        .put(dynamic::key("LATEST_BLOCK_HEADER_HASH").unwrap(), &[9; 32])
        .unwrap();
    manager.durable_store(StoreKind::RecentBlock).put(&[0, 7], &[9; 8]).unwrap();
    manager.durable_store(StoreKind::Account).put(owner, &Account { address: owner.to_vec(), balance: 1_000_000, ..Default::default() }.encode_to_vec()).unwrap();
    for (name, value) in [
        ("ALLOW_SAME_TOKEN_NAME", 0_i64),
        ("TRANSACTION_FEE", 0_i64),
        ("CREATE_ACCOUNT_FEE", 0_i64),
        ("CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", 0_i64),
        ("MULTI_SIGN_FEE", 0_i64),
        ("MEMO_FEE", 0_i64),
        ("UNFREEZE_DELAY_DAYS", 0_i64),
        ("ALLOW_HARDEN_RESOURCE_CALCULATION", 0_i64),
        ("CREATE_NEW_ACCOUNT_BANDWIDTH_RATE", 1_i64),
        ("MAX_CREATE_ACCOUNT_TX_SIZE", 1_000_i64),
        ("TOTAL_NET_LIMIT", 43_200_000_000_i64),
        ("FREE_NET_LIMIT", 5_000_i64),
        ("TOTAL_NET_WEIGHT", 1_i64),
        ("PUBLIC_NET_LIMIT", 14_400_000_000_i64),
        ("PUBLIC_NET_USAGE", 0_i64),
        ("PUBLIC_NET_TIME", 0_i64),
        ("ALLOW_TRANSACTION_FEE_POOL", 0_i64),
    ] {
        manager.durable_store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(), &value.to_be_bytes()).unwrap();
    }
    let point = CursorPoint {
        block: 7,
        identity: CheckpointIdentity::new([7; 32]),
    };
    manager.record_checkpoint(point).unwrap();
    let cursors = CursorSet::new(&manager, point, None, None, 0).unwrap();
    let processor = TransactionProcessor {
        sessions: manager.clone(),
        cache: TransactionCache::new(CacheConfig::default()).unwrap(),
        pipeline: StateTransactionPipeline::new(
            Default::default(),
            registry,
            ExecutionConfig::default(),
        )
        .unwrap(),
    };
    let pending = PendingPool::new(manager, PendingLimits::default()).unwrap();
    (path, ApiContext::new(cursors, processor, pending, parameters(), CryptoEngine::Secp256k1))
}

#[test]
fn trusted_extension_construct_broadcast_execute_and_query_payload() {
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
    let (path, context) = context(processor_registry, &owner);
    let api = ExtensionApi::new(
        Arc::clone(&registry),
        WalletMutation::new(context.clone()),
        true,
    );
    let payload = ExampleContract {
        owner_address: owner.clone(),
        payload: b"stored-value".to_vec(),
    }
    .encode_to_vec();
    let extension = api.construct("org.tron.example.actuator", payload).unwrap();
    let mut transaction = extension.transaction.unwrap();
    assert_eq!(api.owner_address(&transaction).unwrap(), owner);
    let unsigned = api.broadcast(transaction.encode_to_vec(), 101).unwrap();
    assert_eq!((unsigned.code, unsigned.message), (ResponseCode::Sigerror as i32, b"Validate signature error: miss sig or contract".to_vec()));
    assert_eq!(context.pending().lock().unwrap().len(), 0);

    let sign = |transaction: &mut tron_protocol::protocol::Transaction| {
        let digest = selected_digest(CryptoEngine::Secp256k1, &transaction.raw_data.as_ref().unwrap().encode_to_vec());
        transaction.signature.push(key.sign_prehash(&digest).unwrap().to_wire().to_vec());
    };
    let mut bad_tapos = transaction.clone();
    bad_tapos.raw_data.as_mut().unwrap().ref_block_hash = vec![8; 8];
    sign(&mut bad_tapos);
    let bad_tapos = api.broadcast(bad_tapos.encode_to_vec(), 101).unwrap();
    assert_eq!((bad_tapos.code, bad_tapos.message), (ResponseCode::TaposError as i32, b"Tapos check error.".to_vec()));
    assert_eq!(context.pending().lock().unwrap().len(), 0);

    let mut expired = transaction.clone();
    expired.raw_data.as_mut().unwrap().expiration = 100;
    sign(&mut expired);
    let expired = api.broadcast(expired.encode_to_vec(), 101).unwrap();
    assert_eq!((expired.code, expired.message), (ResponseCode::TransactionExpirationError as i32, b"Transaction expired".to_vec()));
    assert_eq!(context.pending().lock().unwrap().len(), 0);

    let malformed_payload = ExampleContract { owner_address: owner.clone(), payload: b"malformed".to_vec() }.encode_to_vec();
    let mut malformed = api.construct("org.tron.example.actuator", malformed_payload).unwrap().transaction.unwrap();
    sign(&mut malformed);
    let malformed = api.broadcast(malformed.encode_to_vec(), 101).unwrap();
    assert_eq!(malformed.code, ResponseCode::ContractExeError as i32);
    assert_eq!(malformed.message, b"Contract execute error : Provider(\"extension validation failure\")");
    assert_eq!(context.pending().lock().unwrap().len(), 0);
    let decoded = api.decode_payload(&transaction).unwrap();
    assert_eq!(decoded.descriptor().full_name(), MESSAGE);
    sign(&mut transaction);
    let transaction_id = selected_digest(
        CryptoEngine::Secp256k1,
        &transaction.raw_data.as_ref().unwrap().encode_to_vec(),
    );
    let result = api.broadcast(transaction.encode_to_vec(), 101).unwrap();
    assert!(result.result, "{}", String::from_utf8_lossy(&result.message));
    assert_eq!(
        (result.result, result.code),
        (true, ResponseCode::Success as i32)
    );
    assert_eq!(context.pending().lock().unwrap().len(), 1);
    let query = WalletQuery::new(context.clone(), ApiCursor::Head);
    assert_eq!(query.pending_transaction(&transaction_id).unwrap(), transaction);
    let expected_id = transaction_id.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    assert_eq!(query.pending_ids().unwrap().tx_id, vec![expected_id]);
    let duplicate = api.broadcast(transaction.encode_to_vec(), 101).unwrap();
    assert_eq!((duplicate.code, duplicate.message), (ResponseCode::DupTransactionError as i32, b"Transaction already exists.".to_vec()));
    assert_eq!(context.pending().lock().unwrap().len(), 1);
    drop(context);
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
