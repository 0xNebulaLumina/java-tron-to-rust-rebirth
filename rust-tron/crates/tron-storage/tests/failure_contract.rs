use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use std::cell::Cell;

use tron_storage::{initialize_empty, inspect_read_only, CheckpointFaultInjector, CheckpointPhase, Corruption, DirectoryClassification, OpenRequirements, RustLogOptions, ShutdownFaultInjector, ShutdownPhase, StableError, StorageError, StorageIdentity, StorageManager, WriteBatch, WriteFaultInjector, WritePhase};

fn temporary_directory(name: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("tron-storage-failure-{name}-{}-{nonce}", std::process::id()))
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
fn initialization_journal(phase: &str) -> Vec<u8> {
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 { crc = (crc >> 1) ^ if crc & 1 == 1 { 0xedb8_8320 } else { 0 }; }
        }
        !crc
    }
    let mut body = format!("TRON-RUST-STORAGE-INITIALIZATION\nversion=1\nphase={phase}\n").into_bytes();
    let checksum = crc32(&body);
    body.extend_from_slice(format!("checksum={checksum:08x}\n").as_bytes());
    body
}
fn manager_with_options(options: RustLogOptions) -> StorageManager { StorageManager::with_options(requirements(), options).unwrap() }
struct FailCheckpointAt { target: CheckpointPhase, fired: Cell<bool> }

impl CheckpointFaultInjector for FailCheckpointAt {
    fn after(&self, phase: CheckpointPhase) -> io::Result<()> {
        if phase == self.target && !self.fired.replace(true) {
            Err(io::Error::new(io::ErrorKind::Other, "injected checkpoint failure"))
        } else {
            Ok(())
        }
    }
}

struct FailShutdownSyncWhileLocked<'a> {
    manager: &'a StorageManager,
    path: &'a std::path::Path,
    fired: Cell<bool>,
}

impl ShutdownFaultInjector for FailShutdownSyncWhileLocked<'_> {
    fn before(&self, phase: ShutdownPhase) -> io::Result<()> {
        if phase == ShutdownPhase::WalSync && !self.fired.replace(true) {
            assert!(matches!(self.manager.open_store(self.path), Err(StorageError::Locked { .. })));
            Err(io::Error::new(io::ErrorKind::Other, "injected shutdown sync failure"))
        } else {
            Ok(())
        }
    }
}
struct FailWriteAt {
    target: WritePhase,
    fired: Cell<bool>,
}

impl WriteFaultInjector for FailWriteAt {
    fn before(&self, phase: WritePhase) -> io::Result<()> {
        if phase == self.target && !self.fired.replace(true) {
            Err(io::Error::other(format!("injected {phase:?} failure")))
        } else {
            Ok(())
        }
    }
}

struct FailWriteAndRollbackAt {
    write: WritePhase,
    rollback: WritePhase,
}

impl WriteFaultInjector for FailWriteAndRollbackAt {
    fn before(&self, phase: WritePhase) -> io::Result<()> {
        if phase == self.write || phase == self.rollback {
            Err(io::Error::other(format!("injected {phase:?} failure")))
        } else {
            Ok(())
        }
    }
}

fn candidate_batch() -> WriteBatch {
    let mut batch = WriteBatch::new();
    batch.put(b"candidate".to_vec(), b"committed".to_vec());
    batch
}

fn assert_injected_io(error: StorageError, phase: WritePhase) {
    match error {
        StorageError::Io(error) => assert_eq!(error.to_string(), format!("injected {phase:?} failure")),
        error => panic!("{phase:?} mapped to unexpected storage error: {error:?}"),
    }
}

const CHECKPOINT_PHASES: [CheckpointPhase; 8] = [
    CheckpointPhase::Preflight,
    CheckpointPhase::StagingCreated,
    CheckpointPhase::SnapshotWritten,
    CheckpointPhase::WalWritten,
    CheckpointPhase::ManifestWritten,
    CheckpointPhase::TreeSynced,
    CheckpointPhase::Published,
    CheckpointPhase::ParentSynced,
];

fn checkpoint_staging_entries(parent: &std::path::Path) -> Vec<PathBuf> {
    fs::read_dir(parent).unwrap().filter_map(|entry| {
        let path = entry.unwrap().path();
        path.file_name().unwrap().to_string_lossy().starts_with(".tron-storage-checkpoint.").then_some(path)
    }).collect()
}

#[test]
fn shutdown_sync_failure_is_returned_before_lock_release() {
    let path = temporary_directory("shutdown-sync-failure");
    let manager = manager();
    let mut storage = manager.open_store(&path).unwrap();
    storage.put(b"pending", b"value").unwrap();
    let faults = FailShutdownSyncWhileLocked { manager: &manager, path: &path, fired: Cell::new(false) };

    assert!(storage.close_with_faults(&faults).is_err());
    assert!(faults.fired.get());
    let reopened = manager.open_store(&path).unwrap();
    assert_eq!(reopened.get(b"pending"), Some(b"value".to_vec()));
    reopened.close().unwrap();
    fs::remove_dir_all(path).unwrap();
}
#[test]
fn write_commit_points_are_atomic_across_reopen() {
    for phase in [WritePhase::Append, WritePhase::Flush, WritePhase::Sync] {
        let path = temporary_directory("write-commit-point");
        let options = RustLogOptions { sync_on_write: true, compact_after_bytes: 0, ..RustLogOptions::default() };
        let manager = manager_with_options(options);
        let mut storage = manager.open_store(&path).unwrap();
        storage.put(b"stable", b"value").unwrap();
        let fault = FailWriteAt { target: phase, fired: Cell::new(false) };

        assert_injected_io(storage.write_with_faults(candidate_batch(), &fault).unwrap_err(), phase);
        assert!(fault.fired.get());
        assert_eq!(storage.get(b"candidate"), None);
        drop(storage);

        let reopened = manager.open_store(&path).unwrap();
        assert_eq!(reopened.get(b"stable"), Some(b"value".to_vec()));
        assert_eq!(reopened.get(b"candidate"), None);
        drop(reopened);
        fs::remove_dir_all(path).unwrap();
    }

    let path = temporary_directory("write-commit-success");
    let options = RustLogOptions { sync_on_write: true, compact_after_bytes: 0, ..RustLogOptions::default() };
    let manager = manager_with_options(options);
    let mut storage = manager.open_store(&path).unwrap();
    storage.write(candidate_batch()).unwrap();
    drop(storage);
    let reopened = manager.open_store(&path).unwrap();
    assert_eq!(reopened.get(b"candidate"), Some(b"committed".to_vec()));
    drop(reopened);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn rollback_failures_poison_reject_operations_and_retain_lock() {
    const CHILD: &str = "TRON_STORAGE_ROLLBACK_POISON_CHILD";
    const CASE: &str = "TRON_STORAGE_ROLLBACK_POISON_CASE";
    const PATH: &str = "TRON_STORAGE_ROLLBACK_POISON_PATH";
    let cases = [
        (WritePhase::Append, WritePhase::Truncate),
        (WritePhase::Flush, WritePhase::RollbackSync),
    ];

    if std::env::var_os(CHILD).is_some() {
        let (write, rollback) = cases[std::env::var(CASE).unwrap().parse::<usize>().unwrap()];
        let path = PathBuf::from(std::env::var_os(PATH).unwrap());
        let options = RustLogOptions { sync_on_write: true, compact_after_bytes: 0, ..RustLogOptions::default() };
        let manager = manager_with_options(options);
        let mut storage = manager.open_store(&path).unwrap();
        let fault = FailWriteAndRollbackAt { write, rollback };

        assert!(matches!(storage.write_with_faults(candidate_batch(), &fault), Err(StorageError::Poisoned)));
        assert!(storage.is_poisoned());
        assert!(matches!(storage.put(b"later", b"value"), Err(StorageError::Poisoned)));
        assert!(matches!(storage.flush(), Err(StorageError::Poisoned)));
        assert!(matches!(storage.compact(), Err(StorageError::Poisoned)));
        assert!(matches!(storage.checkpoint(&path.with_extension("checkpoint")), Err(StorageError::Poisoned)));
        assert!(matches!(manager.open_store(&path), Err(StorageError::Locked { .. })));
        drop(storage);
        assert!(matches!(manager.open_store(&path), Err(StorageError::Locked { .. })));
        return;
    }

    for (index, _) in cases.into_iter().enumerate() {
        let parent = temporary_directory("write-rollback-poison");
        fs::create_dir(&parent).unwrap();
        let path = parent.join("store");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact").arg("rollback_failures_poison_reject_operations_and_retain_lock").arg("--nocapture")
            .env(CHILD, "1").env(CASE, index.to_string()).env(PATH, &path)
            .status().unwrap();
        assert!(status.success());

        let reopened = manager().open_store(&path).unwrap();
        assert_eq!(reopened.get(b"candidate"), None);
        assert_eq!(reopened.get(b"later"), None);
        drop(reopened);
        fs::remove_dir_all(parent).unwrap();
    }
}

#[test]
fn post_commit_metadata_and_compaction_failures_are_maintenance_errors() {
    for phase in [WritePhase::Metadata, WritePhase::Compaction] {
        let path = temporary_directory("write-maintenance-failure");
        let options = RustLogOptions { sync_on_write: true, compact_after_bytes: 1, ..RustLogOptions::default() };
        let manager = manager_with_options(options);
        let mut storage = manager.open_store(&path).unwrap();
        let fault = FailWriteAt { target: phase, fired: Cell::new(false) };

        storage.write_with_faults(candidate_batch(), &fault).unwrap();
        assert!(fault.fired.get());
        assert_eq!(storage.get(b"candidate"), Some(b"committed".to_vec()));
        assert_injected_io(storage.take_maintenance_error().expect("maintenance error"), phase);
        assert!(storage.maintenance_error().is_none());
        drop(storage);

        let reopened = manager.open_store(&path).unwrap();
        assert_eq!(reopened.get(b"candidate"), Some(b"committed".to_vec()));
        drop(reopened);
        fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn checkpoint_failure_injection_cleans_or_recovers_and_retries() {
    for phase in CHECKPOINT_PHASES {
        let parent = temporary_directory("checkpoint-failure-parent");
        fs::create_dir(&parent).unwrap();
        let source = parent.join("source");
        let destination = parent.join("checkpoint");
        let mut storage = manager().open_store(&source).unwrap();
        storage.put(b"stable", b"value").unwrap();
        let faults = FailCheckpointAt { target: phase, fired: Cell::new(false) };
        assert!(storage.checkpoint_with_faults(&destination, &faults).is_err());

        if matches!(phase, CheckpointPhase::Published | CheckpointPhase::ParentSynced) {
            assert_eq!(manager().open_store(&destination).unwrap().get(b"stable"), Some(b"value".to_vec()));
            storage.checkpoint(&destination).unwrap();
        } else {
            assert!(!destination.exists());
            assert!(checkpoint_staging_entries(&parent).is_empty());
            storage.checkpoint(&destination).unwrap();
        }
        drop(storage);
        assert_eq!(manager().open_store(&destination).unwrap().get(b"stable"), Some(b"value".to_vec()));
        fs::remove_dir_all(parent).unwrap();
    }
}

#[cfg(unix)]
enum CheckpointRace<'a> {
    SwapParent { parent:&'a PathBuf, retained:&'a PathBuf },
    PlantFinal { destination:&'a PathBuf, outside:&'a PathBuf },
}

#[cfg(unix)]
impl CheckpointFaultInjector for CheckpointRace<'_> {
    fn after(&self, phase: CheckpointPhase) -> io::Result<()> {
        if phase != CheckpointPhase::TreeSynced { return Ok(()); }
        match self {
            Self::SwapParent { parent, retained } => {
                fs::rename(parent, retained)?;
                fs::create_dir(parent)?;
            }
            Self::PlantFinal { destination, outside } => {
                std::os::unix::fs::symlink(outside, destination)?;
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
#[test]
fn checkpoint_rejects_destination_parent_swap_and_final_symlink_plant() {
    let parent = temporary_directory("checkpoint-parent-swap");
    fs::create_dir(&parent).unwrap();
    let retained = parent.with_extension("retained");
    let source = parent.join("source");
    let destination = parent.join("checkpoint");
    let mut storage = manager().open_store(&source).unwrap();
    storage.put(b"stable", b"value").unwrap();
    let error = storage.checkpoint_with_faults(&destination, &CheckpointRace::SwapParent { parent:&parent, retained:&retained }).unwrap_err();
    assert!(matches!(error, StorageError::ConcurrentOpen { .. }));
    assert!(!destination.exists());
    assert!(checkpoint_staging_entries(&retained).is_empty());
    fs::remove_dir_all(&parent).unwrap();
    fs::remove_dir_all(&retained).unwrap();

    let parent = temporary_directory("checkpoint-final-plant");
    fs::create_dir(&parent).unwrap();
    let source = parent.join("source");
    let destination = parent.join("checkpoint");
    let outside = parent.join("outside");
    fs::create_dir(&outside).unwrap();
    let mut storage = manager().open_store(&source).unwrap();
    storage.put(b"stable", b"value").unwrap();
    let error = storage.checkpoint_with_faults(&destination, &CheckpointRace::PlantFinal { destination:&destination, outside:&outside }).unwrap_err();
    assert!(matches!(error, StorageError::InvalidCheckpoint { .. }));
    assert!(fs::symlink_metadata(&destination).unwrap().file_type().is_symlink());
    assert!(checkpoint_staging_entries(&parent).is_empty());
    fs::remove_file(destination).unwrap();
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn snapshot_entry_limit_rejects_compact_and_checkpoint_without_partial_snapshot() {
    let parent = temporary_directory("snapshot-entry-limit");
    fs::create_dir(&parent).unwrap();
    let source = parent.join("source");
    let checkpoint = parent.join("checkpoint");
    let options = RustLogOptions { max_snapshot_entries: 1, ..RustLogOptions::default() };
    let limited_manager = manager_with_options(options.clone());
    let mut storage = limited_manager.open_store(&source).unwrap();
    storage.put(b"one", b"1").unwrap();
    storage.compact().unwrap();
    let snapshot_path = source.join("generation-0/rustlog-v1.snapshot");
    let prior_snapshot = fs::read(&snapshot_path).unwrap();

    storage.put(b"two", b"2").unwrap();
    assert!(matches!(
        storage.compact(),
        Err(StorageError::Corruption(Corruption::TooManySnapshotEntries { actual: 2, maximum: 1 }))
    ));
    assert_eq!(fs::read(&snapshot_path).unwrap(), prior_snapshot);

    assert!(matches!(
        storage.checkpoint(&checkpoint),
        Err(StorageError::Corruption(Corruption::TooManySnapshotEntries { actual: 2, maximum: 1 }))
    ));
    assert!(!checkpoint.exists());
    assert!(checkpoint_staging_entries(&parent).is_empty());
    assert_eq!(fs::read(&snapshot_path).unwrap(), prior_snapshot);

    drop(storage);
    drop(limited_manager);
    let reopened = manager_with_options(options).open_store(&source).unwrap();
    assert_eq!(reopened.get(b"one"), Some(b"1".to_vec()));
    assert_eq!(reopened.get(b"two"), Some(b"2".to_vec()));
    drop(reopened);
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn growing_manifest_is_rejected_at_the_bounded_read_boundary() {
    let path = temporary_directory("growing-manifest");
    fs::create_dir(&path).unwrap();
    let manifest = path.join("tron-storage.manifest");
    fs::write(&manifest, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    let writer_path = manifest.clone();
    let writer = std::thread::spawn(move || {
        let mut file = OpenOptions::new().append(true).open(writer_path).unwrap();
        for _ in 0..64 { file.write_all(&[b'y'; 4096]).unwrap(); }
    });
    let error = tron_storage::inspect_read_only(&path).unwrap_err();
    writer.join().unwrap();
    assert_eq!(error.category, tron_storage::StableError::ManifestCorrupt);
    fs::remove_dir_all(path).unwrap();
}

#[cfg(unix)]
#[test]
fn checkpoint_crash_child_terminates_at_publication_stage() {
    const CHILD: &str = "TRON_STORAGE_CHECKPOINT_CRASH_CHILD";
    const STAGE: &str = "TRON_STORAGE_CHECKPOINT_CRASH_STAGE";
    const SOURCE: &str = "TRON_STORAGE_CHECKPOINT_CRASH_SOURCE";
    const DESTINATION: &str = "TRON_STORAGE_CHECKPOINT_CRASH_DESTINATION";

    struct ExitAt(CheckpointPhase);
    impl CheckpointFaultInjector for ExitAt {
        fn after(&self, phase: CheckpointPhase) -> io::Result<()> {
            if phase == self.0 { std::process::exit(73); }
            Ok(())
        }
    }

    if std::env::var_os(CHILD).is_some() {
        let stage = std::env::var(STAGE).unwrap();
        let phase = CHECKPOINT_PHASES[stage.parse::<usize>().unwrap()];
        let mut storage = manager().open_store(PathBuf::from(std::env::var_os(SOURCE).unwrap())).unwrap();
        storage.checkpoint_with_faults(PathBuf::from(std::env::var_os(DESTINATION).unwrap()), &ExitAt(phase)).unwrap();
        panic!("checkpoint child did not terminate");
    }

    for (index, phase) in CHECKPOINT_PHASES.into_iter().enumerate() {
        let parent = temporary_directory("checkpoint-crash-parent");
        fs::create_dir(&parent).unwrap();
        let source = parent.join("source");
        let destination = parent.join("checkpoint");
        let mut storage = manager().open_store(&source).unwrap();
        storage.put(b"stable", b"value").unwrap();
        storage.flush().unwrap();
        drop(storage);

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact").arg("checkpoint_crash_child_terminates_at_publication_stage").arg("--nocapture")
            .env(CHILD, "1").env(STAGE, index.to_string()).env(SOURCE, &source).env(DESTINATION, &destination)
            .status().unwrap();
        assert_eq!(status.code(), Some(73));
        if matches!(phase, CheckpointPhase::Published | CheckpointPhase::ParentSynced) {
            let checkpoint = manager().open_store(&destination).unwrap();
            assert_eq!(checkpoint.get(b"stable"), Some(b"value".to_vec()));
            drop(checkpoint);
            let mut source_store = manager().open_store(&source).unwrap();
            source_store.checkpoint(&destination).unwrap();
        } else {
            assert!(!destination.join("tron-storage.manifest").exists());
        }
        fs::remove_dir_all(parent).unwrap();
    }
}

#[test]
fn rustlog_vectors_batch_atomicity_reopen_and_corruption() {
    let path = temporary_directory("vectors");
    let mut options = RustLogOptions::default(); options.sync_on_write = true; options.compact_after_bytes = 0;
    let mut storage = manager_with_options(options.clone()).open_store(&path).unwrap();
    assert_eq!(fs::read(path.join("generation-0/rustlog-v1.wal")).unwrap(), b"RLOGWAL1");

    let mut batch = WriteBatch::new(); batch.put(b"a".to_vec(), b"1".to_vec()).delete(b"missing".to_vec());
    storage.write(batch).unwrap(); storage.flush().unwrap(); drop(storage);
    let wal = fs::read(path.join("generation-0/rustlog-v1.wal")).unwrap();
    assert!(wal.windows(15).any(|window| window == [2,0,0,0,0,1,0,0,0,b'a',1,0,0,0,b'1']));
    assert_eq!(manager_with_options(options.clone()).open_store(&path).unwrap().get(b"a"), Some(b"1".to_vec()));

    let mut bytes = fs::read(path.join("generation-0/rustlog-v1.wal")).unwrap(); bytes[12] ^= 0x80; fs::write(path.join("generation-0/rustlog-v1.wal"), bytes).unwrap();
    assert!(matches!(manager_with_options(options.clone()).open_store(&path), Err(StorageError::Corruption(Corruption::WalChecksum { .. }))));
    fs::remove_dir_all(&path).unwrap();

    let path = temporary_directory("snapshot-corrupt");
    let mut storage = manager_with_options(options).open_store(&path).unwrap(); storage.put(b"k", b"v").unwrap(); storage.compact().unwrap(); drop(storage);
    let snapshot_path = path.join("generation-0/rustlog-v1.snapshot");
    let mut snapshot = fs::read(&snapshot_path).unwrap();
    *snapshot.last_mut().unwrap() ^= 1;
    fs::write(&snapshot_path, snapshot).unwrap();
    assert!(matches!(manager().open_store(&path), Err(StorageError::Corruption(Corruption::SnapshotChecksum))));
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn lock_permission_and_disk_full_categories_are_stable() {
    let path = temporary_directory("lock");
    {
        let _storage = manager().open_store(&path).unwrap();
        assert!(matches!(manager().open_store(&path), Err(StorageError::Locked { .. })));
    }
    fs::write(path.join("tron-storage.lock"), b"planted\n").unwrap();
    let storage = manager().open_store(&path).unwrap();
    drop(storage);
    assert!(path.join("tron-storage.lock").is_file());
    fs::remove_dir_all(path).unwrap();

    assert!(matches!(StorageError::from(io::Error::from(io::ErrorKind::PermissionDenied)), StorageError::Permission { .. }));
    assert!(matches!(StorageError::from(io::Error::from(io::ErrorKind::StorageFull)), StorageError::DiskFull { .. }));

    let path = temporary_directory("incomplete-batch");
    let mut storage = manager().open_store(&path).unwrap(); storage.put(b"stable", b"value").unwrap(); storage.flush().unwrap(); drop(storage);
    OpenOptions::new().append(true).open(path.join("generation-0/rustlog-v1.wal")).unwrap().write_all(&[100, 0, 0, 0, 1, 2]).unwrap();
    let storage = manager().open_store(&path).unwrap(); assert_eq!(storage.get(b"stable"), Some(b"value".to_vec())); drop(storage);
    fs::remove_dir_all(path).unwrap();
}

#[cfg(unix)]
#[test]
fn permission_denial_is_mandatory_under_dropped_credentials() {
    use std::os::unix::{fs::PermissionsExt, process::CommandExt};

    const CHILD_PATH: &str = "TRON_STORAGE_PERMISSION_CHILD_PATH";

    if let Some(path) = std::env::var_os(CHILD_PATH) {
        assert!(matches!(manager().open_store(PathBuf::from(path)), Err(StorageError::Permission { .. })));
        return;
    }

    let effective_uid = std::process::Command::new("id").arg("-u").output().unwrap();
    if effective_uid.stdout != b"0\n" {
        return;
    }

    let path = temporary_directory("permission-dropped-uid");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, PermissionsExt::from_mode(0o700)).unwrap();

    // A test binary below a root-only checkout cannot be executed after dropping uid.
    // Put an executable copy directly in the shared temporary directory instead.
    let child_executable = temporary_directory("permission-child-executable");
    fs::copy(std::env::current_exe().unwrap(), &child_executable).unwrap();
    fs::set_permissions(&child_executable, PermissionsExt::from_mode(0o755)).unwrap();

    let child_result = std::process::Command::new(&child_executable)
        .arg("--exact")
        .arg("permission_denial_is_mandatory_under_dropped_credentials")
        .arg("--nocapture")
        .env(CHILD_PATH, &path)
        .uid(65_534)
        .status();

    fs::remove_file(child_executable).unwrap();
    fs::remove_dir_all(path).unwrap();

    let status = child_result.expect("failed to run dropped-credential child");
    assert!(status.success(), "dropped-credential child did not prove permission denial");
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_storage_components_and_planted_files() {
    use std::os::unix::fs::symlink;

    let outside = temporary_directory("outside");
    fs::create_dir(&outside).unwrap();
    fs::set_permissions(&outside, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let parent = temporary_directory("symlink-parent");
    symlink(&outside, &parent).unwrap();
    assert!(matches!(manager().open_store(&parent), Err(StorageError::Format(_) | StorageError::Io(_) | StorageError::Permission { .. })));
    fs::remove_file(&parent).unwrap();

    let root = temporary_directory("planted-final");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    symlink(outside.join("wal-target"), root.join("rustlog-v1.wal")).unwrap();
    assert!(matches!(manager().open_store(&root), Err(StorageError::Format(_) | StorageError::Permission { .. } | StorageError::Io(_))));
    assert!(!outside.join("wal-target").exists());
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[cfg(unix)]
#[test]
fn retained_directory_and_lock_inodes_survive_path_replacement() {
    use std::os::unix::fs::symlink;

    let root = temporary_directory("parent-swap");
    let moved = root.with_extension("retained");
    let replacement = temporary_directory("replacement");
    fs::create_dir(&replacement).unwrap();
    fs::set_permissions(&replacement, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let mut storage = manager().open_store(&root).unwrap();
    fs::rename(&root, &moved).unwrap();
    symlink(&replacement, &root).unwrap();
    storage.put(b"pinned", b"inode").unwrap();
    storage.flush().unwrap();
    assert!(fs::metadata(moved.join("generation-0/rustlog-v1.wal")).unwrap().len() > 8);
    assert!(!replacement.join("rustlog-v1.wal").exists());

    fs::remove_file(moved.join("tron-storage.lock")).unwrap();
    fs::write(moved.join("tron-storage.lock"), b"replacement").unwrap();
    drop(storage);
    assert_eq!(fs::read(moved.join("tron-storage.lock")).unwrap(), b"replacement");

    fs::remove_file(root).unwrap();
    fs::remove_dir_all(moved).unwrap();
    fs::remove_dir_all(replacement).unwrap();
}

#[cfg(unix)]
#[test]
fn initialize_empty_reclassifies_valid_rust_before_creating_child_lock() {
    let root = temporary_directory("initialize-post-root-lock-classification");
    let retained_empty = root.with_extension("retained-empty");
    let initialized = root.with_extension("initialized");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    assert_eq!(inspect_read_only(&root).unwrap(), DirectoryClassification::Empty);

    initialize_empty(&initialized, &requirements()).unwrap();
    let manifest_before = fs::read(initialized.join("tron-storage.manifest")).unwrap();
    fs::rename(&root, &retained_empty).unwrap();
    fs::rename(&initialized, &root).unwrap();
    let mut entries_before = fs::read_dir(&root).unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
    entries_before.sort();

    let error = initialize_empty(&root, &requirements()).unwrap_err();
    assert_eq!(error.category, StableError::NotEmpty);
    assert_eq!(fs::read(root.join("tron-storage.manifest")).unwrap(), manifest_before);
    assert!(root.join("generation-0").is_dir());
    assert!(!root.join("tron-storage.lock").exists());
    let mut entries_after = fs::read_dir(&root).unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
    entries_after.sort();
    assert_eq!(entries_after, entries_before);

    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(retained_empty).unwrap();
}

#[cfg(unix)]
#[test]
fn active_initialization_journal_is_untouched_by_second_opener() {
    let root = temporary_directory("active-initialization-journal");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let journal = root.join("tron-storage.initializing");
    fs::write(&journal, initialization_journal("journal")).unwrap();
    let retained = fs::File::open(&root).unwrap();
    rustix::fs::flock(&retained, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();

    assert!(matches!(manager().open_store(&root), Err(StorageError::Locked { .. })));
    assert_eq!(fs::read(&journal).unwrap(), initialization_journal("journal"));
    assert!(!root.join("generation-0").exists());
    assert!(!root.join("tron-storage.manifest").exists());
    assert!(!root.join("tron-storage.lock").exists());

    drop(retained);
    fs::remove_dir_all(root).unwrap();
}
