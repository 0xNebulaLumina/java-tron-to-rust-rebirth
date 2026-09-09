use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tron_storage::snapshot_bundle::{decode_snapshot_bundle, encode_checkpoint_snapshot, RustLogSnapshotLimits, RustLogSnapshotMaterializer};
use tron_storage::{import_snapshot, OpenRequirements, SnapshotDescriptor, SnapshotSource, SnapshotVerifier, StableError, StorageIdentity, StorageManager};

fn root(name: &str) -> PathBuf { std::env::temp_dir().join(format!("c028-{name}-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())) }
fn requirements() -> OpenRequirements { OpenRequirements { identity: StorageIdentity { network: "mainnet".into(), genesis: "c028".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()] } }
struct Accept;
impl SnapshotVerifier for Accept { fn verify(&self, _: &SnapshotDescriptor, _: &SnapshotSource) -> tron_storage::FormatResult<()> { Ok(()) } }

#[test]
fn compact_bundle_round_trips_exact_logical_state() {
    let database = root("source"); let checkpoint = root("checkpoint"); let bundle = root("bundle"); let imported = root("imported");
    let manager = StorageManager::new(requirements());
    let mut store = manager.open_store(&database).unwrap();
    store.put(b"alpha".to_vec(), b"one".to_vec()).unwrap(); store.put(b"beta".to_vec(), b"two".to_vec()).unwrap();
    store.checkpoint(&checkpoint).unwrap(); store.close().unwrap();
    let metadata = encode_checkpoint_snapshot(&checkpoint, &bundle, RustLogSnapshotLimits::default()).unwrap();
    let bytes = fs::read(&bundle).unwrap(); let decoded = decode_snapshot_bundle(&bytes, RustLogSnapshotLimits::default()).unwrap();
    assert_eq!(decoded.metadata, metadata); assert_eq!(&decoded.physical_snapshot[..8], b"RLOGSNP1");
    let descriptor = SnapshotDescriptor { identity: requirements().identity, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), generation: 0, state_root: metadata.state_root.clone(), payload_sha256: Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect(), payload_size: bytes.len() as u64, authentication_envelope: vec![] };
    import_snapshot(&imported, &requirements(), &bundle, bytes.len(), &descriptor, &Accept, &RustLogSnapshotMaterializer::default()).unwrap();
    let imported_store = manager.open_store(&imported).unwrap(); assert_eq!(imported_store.get(b"alpha"), Some(b"one".to_vec())); assert_eq!(imported_store.get(b"beta"), Some(b"two".to_vec())); imported_store.close().unwrap();
    fs::remove_dir_all(database).unwrap(); fs::remove_dir_all(checkpoint).unwrap(); fs::remove_file(bundle).unwrap(); fs::remove_dir_all(imported).unwrap();
}

#[test]
fn bundle_rejects_hash_crc_trailing_and_bounds_before_materialization() {
    let database = root("bad-source"); let checkpoint = root("bad-checkpoint"); let bundle = root("bad-bundle");
    let manager = StorageManager::new(requirements()); let mut store = manager.open_store(&database).unwrap(); store.put(b"k".to_vec(), b"v".to_vec()).unwrap(); store.checkpoint(&checkpoint).unwrap(); store.close().unwrap();
    encode_checkpoint_snapshot(&checkpoint, &bundle, RustLogSnapshotLimits::default()).unwrap(); let bytes = fs::read(&bundle).unwrap();
    let mut bad_hash = bytes.clone(); bad_hash[20] ^= 1; assert_eq!(decode_snapshot_bundle(&bad_hash, RustLogSnapshotLimits::default()).unwrap_err().category, StableError::Integrity);
    let mut trailing = bytes.clone(); trailing.push(0); assert_eq!(decode_snapshot_bundle(&trailing, RustLogSnapshotLimits::default()).unwrap_err().category, StableError::SnapshotIncompatible);
    let tight = RustLogSnapshotLimits { max_bundle_bytes: bytes.len() - 1, ..RustLogSnapshotLimits::default() }; assert_eq!(decode_snapshot_bundle(&bytes, tight).unwrap_err().category, StableError::SourceTooLarge);
    fs::remove_dir_all(database).unwrap(); fs::remove_dir_all(checkpoint).unwrap(); fs::remove_file(bundle).unwrap();
}

#[test]
fn payload_binding_fails_before_verifier_or_destination_creation() {
    let snapshot = root("payload"); let destination = root("payload-destination"); fs::write(&snapshot, b"payload").unwrap();
    let descriptor = SnapshotDescriptor { identity: requirements().identity, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), generation: 0, state_root: "root".into(), payload_sha256: "00".repeat(32), payload_size: 7, authentication_envelope: vec![] };
    let error = import_snapshot(&destination, &requirements(), &snapshot, 7, &descriptor, &Accept, &RustLogSnapshotMaterializer::default()).unwrap_err();
    assert_eq!(error.category, StableError::Integrity); assert!(!destination.exists()); fs::remove_file(snapshot).unwrap();
}

#[test]
fn shared_close_is_idempotent_and_rejects_later_mutation() {
    let database = root("shared-close");
    let manager = StorageManager::new(requirements());
    let mut store = manager.open_store(&database).unwrap();
    store.put(b"before".to_vec(), b"close".to_vec()).unwrap();
    store.close_in_place().unwrap();
    store.close_in_place().unwrap();
    assert!(matches!(store.put(b"after".to_vec(), b"close".to_vec()), Err(tron_storage::StorageError::Closed)));
    fs::remove_dir_all(database).unwrap();
}
