use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::{Arc, Barrier};
use std::thread;

use tron_storage::{open_manifest, Corruption, OpenRequirements, RustLogOptions, StableError, StorageError, StorageIdentity, StorageManager, WriteBatch, WriteFaultInjector, WritePhase};

fn temporary_directory(name: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("tron-storage-{name}-{}-{nonce}", std::process::id()))
}

fn requirements() -> OpenRequirements {
    OpenRequirements {
        identity: StorageIdentity { network: "mainnet".into(), genesis: "00aa".into() },
        schema_version: 1,
        backend: "rustlog".into(),
        backend_format: "rustlog-v1".into(),
        supported_features: vec!["rustlog-v1".into()],
    }
}

fn manager() -> StorageManager { StorageManager::new(requirements()) }
struct RejectSync;

impl WriteFaultInjector for RejectSync {
    fn before(&self, phase: WritePhase) -> std::io::Result<()> {
        if phase == WritePhase::Sync {
            Err(std::io::Error::other("default write unexpectedly synchronized"))
        } else {
            Ok(())
        }
    }
}

fn tree(path: &Path) -> Vec<(String, Vec<u8>)> {
    fn visit(root: &Path, path: &Path, rows: &mut Vec<(String, Vec<u8>)>) {
        if !path.exists() { return; }
        let mut entries = fs::read_dir(path).unwrap().map(|entry| entry.unwrap()).collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let child = entry.path();
            let relative = child.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            if child.is_dir() { rows.push((format!("{relative}/"), Vec::new())); visit(root, &child, rows); }
            else { rows.push((relative, fs::read(child).unwrap())); }
        }
    }
    let mut rows = Vec::new(); visit(path, path, &mut rows); rows
}
fn initialization_journal() -> Vec<u8> {
    let mut body = b"TRON-RUST-STORAGE-INITIALIZATION\nversion=1\nphase=journal\n".to_vec();
    let mut crc = !0u32;
    for &byte in &body {
        crc ^= u32::from(byte);
        for _ in 0..8 { crc = (crc >> 1) ^ if crc & 1 == 1 { 0xedb8_8320 } else { 0 }; }
    }
    body.extend_from_slice(format!("checksum={:08x}\n", !crc).as_bytes());
    body
}

fn assert_format_rejection_without_writes(path: &Path, manager: &StorageManager, expected: StableError) {
    let before = tree(path);
    match manager.open_store(path) {
        Err(StorageError::Format(error)) => assert_eq!(error.category, expected, "unexpected rejection for {}: {error}", path.display()),
        Err(error) => panic!("unexpected rejection for {}: {error}", path.display()),
        Ok(_) => panic!("writable open unexpectedly accepted {}", path.display()),
    }
    assert_eq!(tree(path), before);
}

#[test]
fn writable_open_rejects_every_format_class_without_writes() {
    let java = temporary_directory("writable-java"); fs::create_dir(&java).unwrap(); fs::write(java.join("CURRENT"), b"sentinel").unwrap(); fs::set_permissions(&java, fs::Permissions::from_mode(0o755)).unwrap();
    assert_format_rejection_without_writes(&java, &manager(), StableError::JavaFormat);

    let ambiguous = temporary_directory("writable-ambiguous"); fs::create_dir(&ambiguous).unwrap(); fs::write(ambiguous.join("unknown"), b"sentinel").unwrap(); fs::set_permissions(&ambiguous, fs::Permissions::from_mode(0o755)).unwrap();
    assert_format_rejection_without_writes(&ambiguous, &manager(), StableError::AmbiguousNonempty);

    let corrupt = temporary_directory("writable-corrupt"); { let store = manager().open_store(&corrupt).unwrap(); drop(store); }
    let manifest_path = corrupt.join("tron-storage.manifest"); let mut bytes = fs::read(&manifest_path).unwrap(); bytes[8] ^= 1; fs::write(&manifest_path, bytes).unwrap();
    assert_format_rejection_without_writes(&corrupt, &manager(), StableError::Integrity);

    let newer = temporary_directory("writable-newer"); { let store = manager().open_store(&newer).unwrap(); drop(store); }
    let mut manifest = open_manifest(&newer, &requirements()).unwrap(); manifest.manifest_version = 2; fs::write(newer.join("tron-storage.manifest"), manifest.encode()).unwrap();
    assert_format_rejection_without_writes(&newer, &manager(), StableError::FormatNewer);

    let wrong_identity = temporary_directory("writable-identity"); { let store = manager().open_store(&wrong_identity).unwrap(); drop(store); }
    let wrong = StorageManager::new(OpenRequirements { identity: StorageIdentity { network: "testnet".into(), genesis: "00aa".into() }, ..requirements() });
    assert_format_rejection_without_writes(&wrong_identity, &wrong, StableError::WrongNetwork);

    let partial = temporary_directory("writable-partial"); { let store = manager().open_store(&partial).unwrap(); drop(store); } fs::write(partial.join("tron-storage.migration"), b"partial").unwrap();
    assert_format_rejection_without_writes(&partial, &manager(), StableError::PartialMigration);
    let mixed_initialization = temporary_directory("writable-mixed-initialization"); fs::create_dir(&mixed_initialization).unwrap(); fs::set_permissions(&mixed_initialization, fs::Permissions::from_mode(0o755)).unwrap(); fs::write(mixed_initialization.join("tron-storage.initializing"), initialization_journal()).unwrap(); fs::write(mixed_initialization.join("unknown"), b"sentinel").unwrap();
    assert_format_rejection_without_writes(&mixed_initialization, &manager(), StableError::AmbiguousNonempty);

    let malformed_initialization = temporary_directory("writable-malformed-initialization"); fs::create_dir(&malformed_initialization).unwrap(); fs::set_permissions(&malformed_initialization, fs::Permissions::from_mode(0o755)).unwrap(); fs::write(malformed_initialization.join("tron-storage.initializing"), b"malformed").unwrap();
    assert_format_rejection_without_writes(&malformed_initialization, &manager(), StableError::Integrity);

    for path in [java, ambiguous, corrupt, newer, wrong_identity, partial, mixed_initialization, malformed_initialization] { fs::remove_dir_all(path).unwrap(); }
}

#[test]
fn byte_api_batch_and_ordered_queries() {
    let path = temporary_directory("contract");
    let mut storage = manager().open_store(&path).unwrap();
    storage.put(b"b", b"2").unwrap();
    storage.put(b"a", b"1").unwrap();

    let mut batch = WriteBatch::new();
    batch.delete(b"b".to_vec()).put(b"aa".to_vec(), b"11".to_vec()).put(b"c".to_vec(), b"3".to_vec());
    storage.write(batch).unwrap();

    assert_eq!(storage.get(b"a"), Some(b"1".to_vec()));
    assert_eq!(storage.get(b"b"), None);
    assert_eq!(storage.seek(b"aa", 2), vec![(b"aa".to_vec(), b"11".to_vec()), (b"c".to_vec(), b"3".to_vec())]);
    assert_eq!(storage.prefix(b"a", 10).len(), 2);
    assert!(storage.prefix(b"a", 0).is_empty());
    assert_eq!(
        storage.range_bytes(Bound::Included(b"aa"), Bound::Excluded(b"d"), 10).len(),
        2
    );

    let mut iterator = storage.iterator();
    assert_eq!(iterator.first().unwrap().0, b"a");
    assert_eq!(iterator.seek(b"aa").unwrap().0, b"aa");
    assert_eq!(iterator.last().unwrap().0, b"c");
    drop(storage);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn flush_checkpoint_reopen_and_exclusive_lock() {
    let path = temporary_directory("checkpoint-source");
    let checkpoint_parent = temporary_directory("checkpoint-parent");
    fs::create_dir(&checkpoint_parent).unwrap();
    fs::set_permissions(&checkpoint_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let checkpoint = checkpoint_parent.join("checkpoint-copy");
    let mut storage = manager().open_store(&path).unwrap();
    storage.put(b"key", b"value").unwrap();
    storage.flush().unwrap();

    assert!(matches!(manager().open_store(&path), Err(StorageError::Locked { .. })));
    assert!(!checkpoint.exists());
    storage.checkpoint(&checkpoint).unwrap();
    storage.checkpoint(&checkpoint).unwrap();
    assert!(!fs::read_dir(checkpoint.parent().unwrap()).unwrap().any(|entry| {
        entry.unwrap().file_name().to_string_lossy().starts_with(".tron-storage-checkpoint.")
    }));
    drop(storage);

    let source = manager().open_store(&path).unwrap();
    assert_eq!(source.get(b"key"), Some(b"value".to_vec()));
    drop(source);
    let checkpoint_store = manager().open_store(&checkpoint).unwrap();
    assert_eq!(checkpoint_store.get(b"key"), Some(b"value".to_vec()));
    assert_eq!(fs::read(checkpoint.join("generation-0/rustlog-v1.wal")).unwrap(), b"RLOGWAL1");
    assert!(checkpoint.join("generation-0/rustlog-v1.snapshot").is_file());
    drop(checkpoint_store);
    fs::remove_dir_all(path).unwrap();
    fs::remove_dir_all(checkpoint_parent).unwrap();
}

#[test]
fn concurrent_fresh_initialization_has_one_locked_loser_and_complete_generation() {
    let path = temporary_directory("concurrent-fresh-initialization");
    let start = Arc::new(Barrier::new(2));
    let finish = Arc::new(Barrier::new(2));

    let handles: Vec<_> = (0..2).map(|_| {
        let path = path.clone();
        let start = Arc::clone(&start);
        let finish = Arc::clone(&finish);
        thread::spawn(move || {
            start.wait();
            let result = manager().open_store(&path);
            finish.wait();
            match result {
                Ok(store) => {
                    drop(store);
                    Ok(())
                }
                Err(error) => Err(error),
            }
        })
    }).collect();
    let mut locked = 0;
    for handle in handles {
        match handle.join().unwrap() {
            Ok(()) => {}
            Err(StorageError::Locked { .. }) => locked += 1,
            Err(error) => panic!("unexpected concurrent-open result: {error}"),
        }
    }
    assert_eq!(locked, 1);
    assert!(path.join("tron-storage.manifest").is_file());
    assert!(path.join("generation-0").is_dir());
    assert!(!path.join("tron-storage.initializing").exists());
    let reopened = manager().open_store(&path).unwrap();
    drop(reopened);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn snapshot_entry_limit_accepts_boundary_and_default_remains_usable() {
    let limited_path = temporary_directory("snapshot-entry-limit-boundary");
    let limited_manager = StorageManager::with_options(
        requirements(),
        RustLogOptions { max_snapshot_entries: 1, ..RustLogOptions::default() },
    ).unwrap();
    let mut limited = limited_manager.open_store(&limited_path).unwrap();
    limited.put(b"one", b"1").unwrap();
    limited.compact().unwrap();
    drop(limited);
    let limited = limited_manager.open_store(&limited_path).unwrap();
    assert_eq!(limited.get(b"one"), Some(b"1".to_vec()));
    drop(limited);

    let default_path = temporary_directory("snapshot-entry-limit-default");
    let mut default_store = manager().open_store(&default_path).unwrap();
    default_store.put(b"one", b"1").unwrap();
    default_store.put(b"two", b"2").unwrap();
    default_store.compact().unwrap();
    drop(default_store);
    let default_store = manager().open_store(&default_path).unwrap();
    assert_eq!(default_store.get(b"one"), Some(b"1".to_vec()));
    assert_eq!(default_store.get(b"two"), Some(b"2".to_vec()));
    drop(default_store);

    fs::remove_dir_all(limited_path).unwrap();
    fs::remove_dir_all(default_path).unwrap();
}

#[test]
fn default_write_policy_defers_sync_but_consuming_close_is_durable() {
    let path = temporary_directory("durable-close");
    let manager = manager();
    let mut storage = manager.open_store(&path).unwrap();
    assert!(!RustLogOptions::default().sync_on_write);
    let mut batch = WriteBatch::new();
    batch.put(b"close".to_vec(), b"durable".to_vec());
    storage.write_with_faults(batch, &RejectSync).unwrap();
    manager.close(storage).unwrap();

    let reopened = manager.open_store(&path).unwrap();
    assert_eq!(reopened.get(b"close"), Some(b"durable".to_vec()));
    reopened.close().unwrap();
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn recovery_truncates_incomplete_tail_but_reports_checksum_corruption() {
    let path = temporary_directory("recovery");
    let mut options = RustLogOptions::default();
    options.sync_on_write = true;
    let mut storage = StorageManager::with_options(requirements(), options).unwrap().open_store(&path).unwrap();
    storage.put(b"stable", b"value").unwrap();
    storage.flush().unwrap();
    drop(storage);

    let wal = path.join("generation-0/rustlog-v1.wal");
    OpenOptions::new().append(true).open(&wal).unwrap().write_all(&[4, 0, 0]).unwrap();
    let storage = manager().open_store(&path).unwrap();
    assert_eq!(storage.get(b"stable"), Some(b"value".to_vec()));
    drop(storage);

    let mut bytes = fs::read(&wal).unwrap();
    bytes[12] ^= 0xff;
    fs::write(&wal, bytes).unwrap();
    assert!(matches!(
        manager().open_store(&path),
        Err(StorageError::Corruption(Corruption::WalChecksum { .. }))
    ));
    fs::remove_dir_all(path).unwrap();
}
