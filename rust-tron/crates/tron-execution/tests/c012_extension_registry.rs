use std::{fs, path::PathBuf, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use prost::Message;
use tron_execution::{Actuator, ActuatorError, ActuatorRegistry, ActuatorResult, ExecutionConfig, ExecutionContext, ExtensionActuatorProvider, ExtensionProviderMetadata, ProviderCodeIdentity, RegistryError, StoreAccess, TrustedExtensionProvider, ValidationContext};
use tron_protocol::{extensions::ExtensionDescriptor, google::protobuf::Any, protocol::{transaction::{result::Code, Contract}}};
use tron_state::{Session, SessionManager, StateStore, StoreEntry, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

const DESCRIPTOR: &[u8] = include_bytes!("../../tron-protocol/tests/fixtures/extensions/example_actuator.pb");

const DR004_FIXTURES: &str = include_str!("../../../../docs/oracles/dr004-extension-fixtures.v1.json");

struct Dr004Example {
    extension_id: String,
    message_full_name: String,
    type_url: String,
    contract_type: i32,
    descriptor_sha256: [u8; 32],
}

fn dr004_string(key: &str) -> String {
    let marker = format!("\"{key}\": \"");
    let value = DR004_FIXTURES.split_once(&marker).unwrap().1;
    value.split_once('"').unwrap().0.to_owned()
}

fn dr004_contract_type() -> i32 {
    let value = DR004_FIXTURES.split_once("\"contract_type\": ").unwrap().1;
    value.split(|character: char| !character.is_ascii_digit()).next().unwrap().parse().unwrap()
}

fn decode_sha256(value: &str) -> [u8; 32] {
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    digest
}

fn dr004_example() -> Dr004Example {
    Dr004Example {
        extension_id: dr004_string("extension_id"),
        message_full_name: dr004_string("message_full_name"),
        type_url: dr004_string("type_url"),
        contract_type: dr004_contract_type(),
        descriptor_sha256: decode_sha256(&dr004_string("descriptor_sha256")),
    }
}

#[derive(Clone, PartialEq, Message)]
struct ExampleContract {
    #[prost(bytes = "vec", tag = "1")]
    owner_address: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    payload: Vec<u8>,
}

struct ExampleProvider { priority: i32, message_full_name: String }
impl ExtensionActuatorProvider for ExampleProvider {
    fn metadata(&self) -> ExtensionProviderMetadata {
        let example = dr004_example();
        ExtensionProviderMetadata {
            extension_id: example.extension_id, priority: self.priority,
            message_full_name: self.message_full_name.clone(), contract_type: example.contract_type,
            max_payload_bytes: 128, state_access: Vec::new(),
        }
    }
    fn owner_address(&self, payload: &[u8]) -> Result<Vec<u8>, ActuatorError> {
        ExampleContract::decode(payload).map(|value| value.owner_address).map_err(|error| ActuatorError::validation(error.to_string()))
    }
    fn create_actuator(&self, payload: &[u8]) -> Result<Box<dyn Actuator>, ActuatorError> {
        let owner = self.owner_address(payload)?;
        Ok(Box::new(ExampleActuator(owner)))
    }
}
struct ExampleActuator(Vec<u8>);
impl Actuator for ExampleActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.0) }
    fn validate(&self, _: &ValidationContext<'_>) -> Result<(), ActuatorError> { Ok(()) }
    fn execute_in(&self, _: &mut ExecutionContext<'_>, _: &mut ActuatorResult) -> Result<(), ActuatorError> { Ok(()) }
}

struct AtomicProvider { allowed: Vec<StoreAccess> }
impl ExtensionActuatorProvider for AtomicProvider {
    fn metadata(&self) -> ExtensionProviderMetadata {
        let example = dr004_example();
        ExtensionProviderMetadata { extension_id: example.extension_id, priority: 5, message_full_name: example.message_full_name, contract_type: example.contract_type, max_payload_bytes: 128, state_access: self.allowed.clone() }
    }
    fn owner_address(&self, payload: &[u8]) -> Result<Vec<u8>, ActuatorError> { ExampleContract::decode(payload).map(|value| value.owner_address).map_err(|error| ActuatorError::validation(error.to_string())) }
    fn create_actuator(&self, payload: &[u8]) -> Result<Box<dyn Actuator>, ActuatorError> { Ok(Box::new(AtomicActuator(ExampleContract::decode(payload).map_err(|error| ActuatorError::validation(error.to_string()))?))) }
}
struct AtomicActuator(ExampleContract);
impl Actuator for AtomicActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { Ok(&self.0.owner_address) }
    fn validate(&self, _: &ValidationContext<'_>) -> Result<(), ActuatorError> {
        if self.0.payload == b"validation-error" { return Err(ActuatorError::validation("extension validation failure")); }
        Ok(())
    }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        if self.0.payload == b"read-undeclared" { let _ = context.get(StoreKind::Witness, b"w")?; }
        context.put(StoreKind::Account, &self.0.owner_address, b"first")?;
        context.put(StoreKind::Account, &self.0.owner_address, b"after")?;
        result.fee = 99;
        result.asset_issue_id = b"leak".to_vec();
        if self.0.payload == b"error" { return Err(ActuatorError::execution("extension failure")); }
        if self.0.payload == b"undeclared" { context.put(StoreKind::Witness, b"w", b"bad")?; }
        Ok(())
    }
}

fn session(name: &str) -> (PathBuf, SessionManager, Session) {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("tron-execution-{name}-{}-{nonce}", std::process::id()));
    let requirements = OpenRequirements { identity: StorageIdentity { network: "c012".into(), genesis: "00".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()] };
    let root = StateStore::new(StorageManager::new(requirements).open_store(&path).unwrap());
    let manager = SessionManager::new(root);
    let session = manager.build_session().unwrap();
    (path, manager, session)
}

fn code_identity() -> ProviderCodeIdentity { ProviderCodeIdentity { provider_id: "reviewed.example.native".into(), code_sha256: [0x5a; 32] } }
fn build_registry(descriptors: Vec<ExtensionDescriptor>, providers: Vec<Arc<dyn ExtensionActuatorProvider>>) -> Result<ActuatorRegistry, RegistryError> {
    let identity = code_identity();
    let allowlist = [identity.clone()].into_iter().collect();
    let trusted = providers.into_iter().map(|provider| TrustedExtensionProvider { identity: identity.clone(), provider });
    ActuatorRegistry::new(descriptors, trusted, &allowlist)
}
fn write_access(store: StoreKind) -> StoreAccess { StoreAccess { store, read: true, write: true } }
fn atomic_registry(allowed: Vec<StoreAccess>) -> ActuatorRegistry { build_registry(vec![descriptor(5)], vec![Arc::new(AtomicProvider { allowed })]).unwrap() }
fn atomic_contract(mode: &[u8]) -> Contract {
    let example = dr004_example();
    let value = ExampleContract { owner_address: vec![0x41; 21], payload: mode.to_vec() }.encode_to_vec();
    Contract { r#type: example.contract_type, parameter: Some(Any { type_url: example.type_url, value }), ..Default::default() }
}

fn descriptor(priority: i32) -> ExtensionDescriptor {
    let example = dr004_example();
    ExtensionDescriptor {
        extension_id: example.extension_id,
        priority,
        descriptor_set: DESCRIPTOR.to_vec(),
        descriptor_sha256: example.descriptor_sha256,
        message_full_name: example.message_full_name,
        contract_type: example.contract_type,
    }
}

#[test]
fn dr004_c012_ext_01_owner_and_dispatch() {
    let example = dr004_example();
    let registry = build_registry(
        vec![descriptor(5)],
        vec![Arc::new(ExampleProvider { priority: 5, message_full_name: example.message_full_name.clone() })],
    ).unwrap();
    let contract = atomic_contract(b"ok");
    assert_eq!(registry.owner_address(&contract).unwrap(), vec![0x41; 21]);
    assert_eq!(registry.actuator(&contract).unwrap().owner_address().unwrap(), vec![0x41; 21]);
}

#[test]
fn dr004_c012_ext_02_declared_write_success() {
    let (path, manager, mut outer) = session("declared-write");
    let mut result = ActuatorResult::default();
    atomic_registry(vec![write_access(StoreKind::Account)]).execute(&atomic_contract(b"ok"), &outer, Some(&mut result), ExecutionConfig::default()).unwrap();
    assert_eq!(outer.store(StoreKind::Account).get(&vec![0x41; 21]), Some(b"after".to_vec()));
    assert_eq!((result.code, result.fee, result.asset_issue_id.as_slice()), (Code::Sucess, 99, b"leak".as_slice()));
    assert_eq!(result.deltas.len(), 1);
    assert_eq!(result.deltas[0].before, StoreEntry::Absent);
    assert_eq!(result.deltas[0].after, StoreEntry::Present(b"after".to_vec()));
    outer.revoke().unwrap(); drop(manager); fs::remove_dir_all(path).unwrap();
}

fn assert_revoke(mode: &[u8]) {
    let (path, manager, mut outer) = session("revoke");
    let mut result = ActuatorResult { fee: 7, code: Code::Sucess, message: b"old".to_vec(), asset_issue_id: b"old".to_vec(), deltas: Vec::new() };
    assert!(atomic_registry(vec![write_access(StoreKind::Account)]).execute(&atomic_contract(mode), &outer, Some(&mut result), ExecutionConfig::default()).is_err());
    assert_eq!(outer.store(StoreKind::Account).get(&vec![0x41; 21]), None);
    assert_eq!((result.code, result.fee), (Code::Failed, 0));
    assert!(result.asset_issue_id.is_empty() && result.deltas.is_empty());
    outer.revoke().unwrap(); drop(manager); fs::remove_dir_all(path).unwrap();
}

#[test]
fn dr004_c012_ext_03_validation_error_revoke() { assert_revoke(b"validation-error"); }

#[test]
fn dr004_c012_ext_04_execution_error_revoke() { assert_revoke(b"error"); }

#[test]
fn dr004_c012_ext_05_undeclared_store_revoke() {
    assert_revoke(b"read-undeclared");
    assert_revoke(b"undeclared");
}

#[test]
fn dr004_c012_ext_06_provider_metadata_mismatch() {
    let result = build_registry(
        vec![descriptor(5)],
        vec![Arc::new(ExampleProvider { priority: 5, message_full_name: "org.tron.example.actuator.MismatchedContract".into() })],
    );
    assert_eq!(result.err().unwrap(), RegistryError::ProviderMetadataMismatch(dr004_example().extension_id));
}

#[test]
fn dr004_c012_ext_07_provider_missing() {
    let result = build_registry(vec![descriptor(5)], Vec::new());
    assert_eq!(result.err().unwrap(), RegistryError::ProviderMissing(dr004_example().extension_id));
}

#[test]
fn dr004_c012_ext_08_provider_contract_type_collision() {
    let example = dr004_example();
    let providers = vec![
        Arc::new(ExampleProvider { priority: 5, message_full_name: example.message_full_name.clone() }) as Arc<dyn ExtensionActuatorProvider>,
        Arc::new(ExampleProvider { priority: 5, message_full_name: example.message_full_name }) as Arc<dyn ExtensionActuatorProvider>,
    ];
    assert_eq!(build_registry(vec![descriptor(5)], providers).err().unwrap(), RegistryError::ProviderCollision(example.extension_id));
}

#[test]
fn dr004_c012_ext_09_runtime_type_url_mismatch() {
    let mut contract = atomic_contract(b"ok");
    contract.parameter.as_mut().unwrap().type_url = "type.googleapis.com/org.tron.example.actuator.AlternateContract".into();
    assert_eq!(atomic_registry(vec![write_access(StoreKind::Account)]).owner_address(&contract).err().unwrap(), RegistryError::TypeUrlMismatch {
        expected: dr004_example().type_url,
        actual: "type.googleapis.com/org.tron.example.actuator.AlternateContract".into(),
    });
}

#[test]
fn dr004_c012_ext_10_payload_at_declared_bound() {
    let mut contract = atomic_contract(b"ok");
    contract.parameter.as_mut().unwrap().value.resize(128, 0);
    assert!(!matches!(atomic_registry(vec![write_access(StoreKind::Account)]).owner_address(&contract), Err(RegistryError::PayloadLimitExceeded { .. })));
}

#[test]
fn dr004_c012_ext_11_payload_over_declared_bound() {
    let mut contract = atomic_contract(b"ok");
    contract.parameter.as_mut().unwrap().value.resize(129, 0);
    assert_eq!(atomic_registry(vec![write_access(StoreKind::Account)]).owner_address(&contract).err().unwrap(), RegistryError::PayloadLimitExceeded {
        extension_id: dr004_example().extension_id, limit: 128, actual: 129,
    });
}

#[test]
fn dr004_c012_ext_12_declared_store_resource_bound() {
    let declarations = (0..65).map(|_| write_access(StoreKind::Account)).collect();
    assert_eq!(build_registry(vec![descriptor(5)], vec![Arc::new(AtomicProvider { allowed: declarations })]).err().unwrap(), RegistryError::ProviderStateAccessLimitExceeded {
        extension_id: dr004_example().extension_id, limit: 64, actual: 65,
    });
}
