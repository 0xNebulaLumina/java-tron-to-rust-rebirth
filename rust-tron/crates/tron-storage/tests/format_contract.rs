use std::cell::Cell;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::io;
use std::process::Command;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tron_storage::{
    import_snapshot, import_snapshot_with_faults, initialize_empty, inspect_read_only,
    migrate_generation, open_manifest, resume_migration, rollback_migration,
    write_clean_resync_marker, DirectoryClassification, DurablePhase, FaultInjector, FormatError,
    GenerationMigrator, Manifest, OpenRequirements, SnapshotDescriptor, SnapshotMaterializer,
    SnapshotSource, SnapshotVerifier, StableError, StorageIdentity, StorageManager,
};

fn temporary_directory(name: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("tron-storage-format-{name}-{}-{nonce}", std::process::id()))
}

fn requirements(schema_version: u32) -> OpenRequirements {
    OpenRequirements {
        identity: StorageIdentity { network: "mainnet".into(), genesis: "00aa".into() },
        schema_version,
        backend: "rustlog".into(),
        backend_format: "rustlog-v1".into(),
        supported_features: vec!["rustlog-v1".into()],
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

#[cfg(unix)]
fn tree_bytes_mode_timestamp(path: &Path) -> Vec<(String, Vec<u8>, u32, i64, i64)> {
    fn visit(root: &Path, path: &Path, rows: &mut Vec<(String, Vec<u8>, u32, i64, i64)>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        let relative = path.strip_prefix(root).unwrap().to_string_lossy();
        rows.push((relative.into_owned(), if metadata.is_file() { fs::read(path).unwrap() } else { Vec::new() }, metadata.mode(), metadata.mtime(), metadata.mtime_nsec()));
        if metadata.is_dir() {
            let mut entries = fs::read_dir(path).unwrap().map(|entry| entry.unwrap()).collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries { visit(root, &entry.path(), rows); }
        }
    }
    let mut rows = Vec::new();
    visit(path, path, &mut rows);
    rows
}
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 { crc = (crc >> 1) ^ if crc & 1 == 1 { 0xedb8_8320 } else { 0 }; }
    }
    !crc
}

fn add_manifest_field(bytes: &[u8], field: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).unwrap();
    let checksum = text.rfind("checksum=").unwrap();
    let mut body = text[..checksum].as_bytes().to_vec();
    body.extend_from_slice(field.as_bytes());
    body.push(b'\n');
    let sum = crc32(&body);
    body.extend_from_slice(format!("checksum={sum:08x}\n").as_bytes());
    body
}
fn initialization_journal(phase: &str) -> Vec<u8> {
    let mut body = format!("TRON-RUST-STORAGE-INITIALIZATION\nversion=1\nphase={phase}\n").into_bytes();
    let sum = crc32(&body);
    body.extend_from_slice(format!("checksum={sum:08x}\n").as_bytes());
    body
}

fn assert_initialization_rejection_without_writes(path: &Path, expected: StableError) {
    let before = tree(path);
    #[cfg(unix)] let before_metadata = tree_bytes_mode_timestamp(path);
    assert_eq!(inspect_read_only(path).unwrap_err().category, expected);
    assert_eq!(initialize_empty(path, &requirements(1)).unwrap_err().category, expected);
    assert_eq!(tree(path), before);
    #[cfg(unix)] assert_eq!(tree_bytes_mode_timestamp(path), before_metadata);
}

#[test]
fn initialization_classification_precedence_and_malformed_trees_are_no_write() {
    let cases: &[(&str, &[(&str, &[u8])], StableError)] = &[
        ("migration", &[("tron-storage.initializing", b"bad"), ("tron-storage.migration", b"partial")], StableError::PartialMigration),
        ("snapshot", &[("tron-storage.initializing", b"bad"), ("tron-storage.snapshot-import", b"partial")], StableError::PartialMigration),
        ("migration-stage", &[("tron-storage.initializing", b"bad"), (".migration-1", b"partial")], StableError::PartialMigration),
        ("snapshot-stage", &[("tron-storage.initializing", b"bad"), (".snapshot-import", b"partial")], StableError::PartialMigration),
        ("malformed", &[("tron-storage.initializing", b"TRON-RUST-STORAGE-INITIALIZATION\nversion=1\nphase=journal\nchecksum=00000000\n")], StableError::Integrity),
    ];
    for (name, entries, expected) in cases {
        let path = temporary_directory(name);
        fs::create_dir(&path).unwrap();
        #[cfg(unix)] fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        for (entry, bytes) in *entries { fs::write(path.join(entry), bytes).unwrap(); }
        assert_initialization_rejection_without_writes(&path, *expected);
        fs::remove_dir_all(path).unwrap();
    }
    let java = temporary_directory("java-unknown");
    fs::create_dir(&java).unwrap();
    #[cfg(unix)] fs::set_permissions(&java, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(java.join("CURRENT"), b"java").unwrap();
    fs::write(java.join("unknown"), b"sentinel").unwrap();
    let java_before = tree(&java);
    #[cfg(unix)] let java_before_metadata = tree_bytes_mode_timestamp(&java);
    assert_eq!(inspect_read_only(&java).unwrap(), DirectoryClassification::Java { marker: "CURRENT".into() });
    assert_eq!(initialize_empty(&java, &requirements(1)).unwrap_err().category, StableError::JavaFormat);
    assert_eq!(tree(&java), java_before);
    #[cfg(unix)] assert_eq!(tree_bytes_mode_timestamp(&java), java_before_metadata);
    fs::remove_dir_all(java).unwrap();

    let mixed = temporary_directory("initialization-mixed");
    fs::create_dir(&mixed).unwrap();
    #[cfg(unix)] fs::set_permissions(&mixed, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(mixed.join("tron-storage.initializing"), initialization_journal("journal")).unwrap();
    fs::write(mixed.join("unknown"), b"sentinel").unwrap();
    assert_initialization_rejection_without_writes(&mixed, StableError::AmbiguousNonempty);
    fs::remove_dir_all(mixed).unwrap();
}

#[test]
fn legitimate_abrupt_initialization_phases_recover_deterministically() {
    for (name, phase, generation, temporary, final_manifest) in [
        ("journal-only", "journal", false, false, false),
        ("generation-before-journal-update", "journal", true, false, false),
        ("generation", "generation", true, false, false),
        ("manifest-temporary", "generation", true, true, false),
        ("manifest-before-journal-update", "generation", true, false, true),
        ("manifest", "manifest", true, false, true),
    ] {
        let path = temporary_directory(name);
        fs::create_dir(&path).unwrap();
        #[cfg(unix)] fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(path.join("tron-storage.initializing"), initialization_journal(phase)).unwrap();
        if generation { fs::create_dir(path.join("generation-0")).unwrap(); }
        if temporary { fs::write(path.join(".tron-storage.manifest.abrupt.tmp"), b"partial").unwrap(); }
        if final_manifest { fs::write(path.join("tron-storage.manifest"), Manifest::new(&requirements(1)).encode()).unwrap(); }
        assert_eq!(inspect_read_only(&path).unwrap(), DirectoryClassification::InitializingEmpty);
        let recovered = initialize_empty(&path, &requirements(1)).unwrap();
        assert_eq!(recovered, Manifest::new(&requirements(1)));
        assert_eq!(tree(&path), vec![("generation-0/".into(), Vec::new()), ("tron-storage.manifest".into(), recovered.encode())]);
        fs::remove_dir_all(path).unwrap();
    }
}


#[test]
fn java_markers_are_rejected_without_writes() {
    let markers = ["engine.properties", "CURRENT", "LOG", "LOG.old", "LOCK", "MANIFEST-000001", "OPTIONS-000001", "000001.sst", "000001.ldb", "IDENTITY"];
    for marker in markers {
        let path = temporary_directory("java-marker");
        fs::create_dir(&path).unwrap();
        #[cfg(unix)] fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(path.join(marker), b"sentinel").unwrap();
        let before = tree(&path);
        #[cfg(unix)] let before_metadata = tree_bytes_mode_timestamp(&path);
        assert!(matches!(inspect_read_only(&path).unwrap(), DirectoryClassification::Java { marker: found } if found == marker));
        assert_eq!(initialize_empty(&path, &requirements(1)).unwrap_err().category, StableError::JavaFormat);
        assert_eq!(open_manifest(&path, &requirements(1)).unwrap_err().category, StableError::JavaFormat);
        assert_eq!(write_clean_resync_marker(&path, &requirements(1).identity, "rejected").unwrap_err().category, StableError::JavaFormat);
        assert_eq!(tree(&path), before, "rejecting {marker} modified the Java tree");
        #[cfg(unix)] assert_eq!(tree_bytes_mode_timestamp(&path), before_metadata, "rejecting {marker} modified Java bytes, mode, or timestamps");
        fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn clean_resync_marker_requires_matching_rust_identity_and_exclusive_open_release() {
    let path = temporary_directory("clean-resync-boundary");
    initialize_empty(&path, &requirements(1)).unwrap();
    let before = tree(&path);
    let wrong = StorageIdentity { network: "testnet".into(), genesis: "00aa".into() };
    assert_eq!(write_clean_resync_marker(&path, &wrong, "wrong-network").unwrap_err().category, StableError::WrongNetwork);
    assert_eq!(tree(&path), before);

    let store = StorageManager::new(requirements(1)).open_store(&path).unwrap();
    assert!(path.join("tron-storage.lock").is_file());
    assert_eq!(write_clean_resync_marker(&path, &requirements(1).identity, "while-open").unwrap_err().category, StableError::ConcurrentOpen);
    assert!(!path.join("tron-storage.clean-resync").exists());
    drop(store);
    assert!(!path.join("tron-storage.lock").exists());

    write_clean_resync_marker(&path, &requirements(1).identity, "trusted-checkpoint").unwrap();
    let marker = fs::read_to_string(path.join("tron-storage.clean-resync")).unwrap();
    assert_eq!(marker, "network=mainnet\ngenesis=00aa\norigin=trusted-checkpoint\n");
    assert_eq!(open_manifest(&path, &requirements(1)).unwrap().generation, 0);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn manifest_identity_corruption_and_newer_versions_are_stable() {
    let path = temporary_directory("manifest");
    let manifest = initialize_empty(&path, &requirements(1)).unwrap();
    assert_eq!(Manifest::decode(&manifest.encode(), Path::new("vector")).unwrap(), manifest);
    assert_eq!(open_manifest(&path, &requirements(1)).unwrap(), manifest);
    assert_eq!(open_manifest(&path, &OpenRequirements { identity: StorageIdentity { network: "testnet".into(), genesis: "00aa".into() }, ..requirements(1) }).unwrap_err().category, StableError::WrongNetwork);

    let manifest_path = path.join("tron-storage.manifest");
    let mut corrupt = fs::read(&manifest_path).unwrap(); corrupt[10] ^= 1; fs::write(&manifest_path, corrupt).unwrap();
    assert_eq!(inspect_read_only(&path).unwrap_err().category, StableError::Integrity);
    let mut newer = manifest.clone(); newer.manifest_version = 2;
    fs::write(&manifest_path, newer.encode()).unwrap();
    assert_eq!(inspect_read_only(&path).unwrap_err().category, StableError::FormatNewer);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn manifest_rejects_unknown_fields_and_noncanonical_features() {
    let path = temporary_directory("manifest-canonical");
    let manifest = initialize_empty(&path, &OpenRequirements { supported_features: vec!["b".into(), "a".into(), "a".into()], ..requirements(1) }).unwrap();
    assert_eq!(manifest.features, vec!["a", "b"]);

    let manifest_path = path.join("tron-storage.manifest");
    fs::write(&manifest_path, add_manifest_field(&manifest.encode(), "evil_required_semantics=enabled")).unwrap();
    assert_eq!(inspect_read_only(&path).unwrap_err().category, StableError::ManifestCorrupt);

    let mut duplicate = manifest.clone(); duplicate.features = vec!["a".into(), "a".into()];
    fs::write(&manifest_path, duplicate.encode()).unwrap();
    assert_eq!(inspect_read_only(&path).unwrap_err().category, StableError::ManifestCorrupt);
    let mut unsorted = manifest; unsorted.features = vec!["b".into(), "a".into()];
    fs::write(&manifest_path, unsorted.encode()).unwrap();
    assert_eq!(inspect_read_only(&path).unwrap_err().category, StableError::ManifestCorrupt);
    fs::remove_dir_all(path).unwrap();
}

struct CopyMigrator;
impl GenerationMigrator for CopyMigrator {
    fn migrate(&self, _: &Path, destination: &Path) -> Result<String, FormatError> {
        let nested = destination.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("state"), b"v2").unwrap();
        Ok("root-v2".into())
    }
}
struct FailAt { target: DurablePhase, fired: Cell<bool> }
impl FaultInjector for FailAt {
    fn after(&self, phase: DurablePhase) -> io::Result<()> {
        if phase == self.target && !self.fired.replace(true) { Err(io::Error::new(io::ErrorKind::Other, "crash")) } else { Ok(()) }
    }
}
struct Accept;
impl SnapshotVerifier for Accept { fn verify(&self, _: &SnapshotDescriptor, _: &SnapshotSource) -> Result<(), FormatError> { Ok(()) } }
impl SnapshotMaterializer for Accept {
    fn materialize(&self, snapshot: &SnapshotSource, destination: &Path) -> Result<String, FormatError> {
        assert_eq!(snapshot.bytes(), b"authenticated");
        let nested = destination.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("state"), b"snapshot").unwrap();
        Ok("snapshot-root".into())
    }
}

struct FailMaterializer;
impl SnapshotMaterializer for FailMaterializer {
    fn materialize(&self, _: &SnapshotSource, destination: &Path) -> Result<String, FormatError> {
        fs::write(destination.join("partial"), b"partial").unwrap();
        Err(FormatError { category:StableError::Io, path:destination.into(), detail:"materializer failed".into() })
    }
}

struct CountCalls<'a> { verifier: &'a AtomicUsize, materializer: &'a AtomicUsize }
impl SnapshotVerifier for CountCalls<'_> {
    fn verify(&self, _: &SnapshotDescriptor, _: &SnapshotSource) -> Result<(), FormatError> {
        self.verifier.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
impl SnapshotMaterializer for CountCalls<'_> {
    fn materialize(&self, _: &SnapshotSource, _: &Path) -> Result<String, FormatError> {
        self.materializer.fetch_add(1, Ordering::SeqCst);
        Ok("snapshot-root".into())
    }
}

#[test]
fn snapshot_import_rejects_oversize_growing_source_before_verification_or_materialization() {
    let snapshot = temporary_directory("snapshot-growing-oversize");
    fs::write(&snapshot, vec![0u8; 1025]).unwrap();
    let writer_path = snapshot.clone();
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        let mut file = fs::OpenOptions::new().append(true).open(writer_path).unwrap();
        for _ in 0..128 { file.write_all(&[1u8; 1024]).unwrap(); }
    });
    let destination = temporary_directory("snapshot-growing-oversize-destination");
    let verifier = AtomicUsize::new(0);
    let materializer = AtomicUsize::new(0);
    let calls = CountCalls { verifier: &verifier, materializer: &materializer };
    let error = import_snapshot(&destination, &requirements(1), &snapshot, 1024, &snapshot_descriptor(), &calls, &calls).unwrap_err();
    writer.join().unwrap();
    assert_eq!(error.category, StableError::SourceTooLarge);
    assert_eq!(verifier.load(Ordering::SeqCst), 0);
    assert_eq!(materializer.load(Ordering::SeqCst), 0);
    assert!(!destination.exists());
    fs::remove_file(snapshot).unwrap();
}

struct AbruptAt(DurablePhase);
impl FaultInjector for AbruptAt {
    fn after(&self, phase:DurablePhase)->io::Result<()> { if phase==self.0 { std::process::exit(86); } Ok(()) }
}

fn snapshot_descriptor()->SnapshotDescriptor {
    SnapshotDescriptor { identity:requirements(1).identity, schema_version:1, backend:"rustlog".into(), backend_format:"rustlog-v1".into(), state_root:"snapshot-root".into(), signature:vec![1] }
}

#[test]
fn snapshot_import_abrupt_child() {
    let Ok(destination)=std::env::var("TRON_SNAPSHOT_IMPORT_CHILD_DESTINATION") else { return };
    let snapshot=std::env::var("TRON_SNAPSHOT_IMPORT_CHILD_SNAPSHOT").unwrap();
    let phase=match std::env::var("TRON_SNAPSHOT_IMPORT_CHILD_PHASE").unwrap().as_str() {
        "Preflight"=>DurablePhase::Preflight, "JournalSynced"=>DurablePhase::JournalSynced,
        "StagingCreated"=>DurablePhase::StagingCreated, "DataWritten"=>DurablePhase::DataWritten,
        "DataSynced"=>DurablePhase::DataSynced, "GenerationPublished"=>DurablePhase::GenerationPublished,
        "ManifestSwitched"=>DurablePhase::ManifestSwitched, "DirectorySynced"=>DurablePhase::DirectorySynced,
        "CleanupSynced"=>DurablePhase::CleanupSynced, value=>panic!("unknown phase {value}"),
    };
    let _=import_snapshot_with_faults(destination,&requirements(1),Path::new(&snapshot),1024,&snapshot_descriptor(),&Accept,&Accept,&AbruptAt(phase));
    panic!("fault phase was not reached");
}

#[test]
fn snapshot_import_materializer_failure_and_abrupt_phases_are_retry_safe() {
    let snapshot=temporary_directory("snapshot-retry-file"); fs::write(&snapshot,b"authenticated").unwrap();
    let failed=temporary_directory("snapshot-materializer-failure");
    assert_eq!(import_snapshot(&failed,&requirements(1),&snapshot,1024,&snapshot_descriptor(),&Accept,&FailMaterializer).unwrap_err().category,StableError::Io);
    assert!(!failed.join(".snapshot-import").exists() && !failed.join("tron-storage.snapshot-import").exists());
    assert_eq!(import_snapshot(&failed,&requirements(1),&snapshot,1024,&snapshot_descriptor(),&Accept,&Accept).unwrap().state_root,"snapshot-root");
    fs::remove_dir_all(failed).unwrap();

    for phase in ["Preflight","JournalSynced","StagingCreated","DataWritten","DataSynced","GenerationPublished","ManifestSwitched","DirectorySynced","CleanupSynced"] {
        let destination=temporary_directory(&format!("snapshot-abrupt-{phase}"));
        let status=Command::new(std::env::current_exe().unwrap()).arg("--exact").arg("snapshot_import_abrupt_child").arg("--nocapture")
            .env("TRON_SNAPSHOT_IMPORT_CHILD_DESTINATION",&destination).env("TRON_SNAPSHOT_IMPORT_CHILD_SNAPSHOT",&snapshot).env("TRON_SNAPSHOT_IMPORT_CHILD_PHASE",phase).status().unwrap();
        assert_eq!(status.code(),Some(86),"child did not terminate at {phase}");
        let imported=import_snapshot(&destination,&requirements(1),&snapshot,1024,&snapshot_descriptor(),&Accept,&Accept).unwrap();
        assert_eq!(imported.state_root,"snapshot-root");
        assert_eq!(fs::read(destination.join("generation-0/nested/state")).unwrap(),b"snapshot");
        assert!(!destination.join(".snapshot-import").exists() && !destination.join("tron-storage.snapshot-import").exists());
        fs::remove_dir_all(destination).unwrap();
    }
    fs::remove_file(snapshot).unwrap();
}
#[cfg(unix)]
struct ReplaceSnapshotDuringVerify<'a> { path: &'a Path, retained: &'a Path, plant_symlink: bool }

#[cfg(unix)]
impl SnapshotVerifier for ReplaceSnapshotDuringVerify<'_> {
    fn verify(&self, _: &SnapshotDescriptor, snapshot: &SnapshotSource) -> Result<(), FormatError> {
        use std::os::unix::fs::symlink;
        assert_eq!(snapshot.bytes(), b"authenticated");
        fs::rename(self.path, self.retained).unwrap();
        if self.plant_symlink { symlink(self.retained, self.path).unwrap(); }
        else { fs::write(self.path, b"attacker replacement").unwrap(); }
        Ok(())
    }
}

#[cfg(unix)]
#[test]
fn snapshot_import_rejects_source_swap_and_symlink_plant_after_authentication() {
    for plant_symlink in [false, true] {
        let snapshot = temporary_directory("snapshot-source-race");
        let retained = snapshot.with_extension("authenticated-retained");
        let destination = temporary_directory("snapshot-source-race-destination");
        fs::write(&snapshot, b"authenticated").unwrap();
        let verifier = ReplaceSnapshotDuringVerify { path:&snapshot, retained:&retained, plant_symlink };
        let error = import_snapshot(&destination, &requirements(1), &snapshot, 1024, &snapshot_descriptor(), &verifier, &Accept).unwrap_err();
        assert_eq!(error.category, StableError::Integrity);
        assert!(!destination.exists(), "source replacement must fail before destination creation");
        if plant_symlink { fs::remove_file(&snapshot).unwrap(); } else { fs::remove_file(&snapshot).unwrap(); }
        fs::remove_file(retained).unwrap();
    }
}


#[test]
fn migration_crash_rollback_resume_and_snapshot_resync_matrix() {
    let pre_ready = [DurablePhase::Preflight, DurablePhase::StagingCreated, DurablePhase::DataWritten, DurablePhase::DataSynced];
    for phase in pre_ready {
        let path = temporary_directory("rollback"); initialize_empty(&path, &requirements(1)).unwrap();
        let fault = FailAt { target: phase, fired: Cell::new(false) };
        assert!(migrate_generation(&path, &requirements(1), 2, &CopyMigrator, &fault).is_err());
        if path.join("tron-storage.migration").exists() {
            assert_eq!(resume_migration(&path, &requirements(2)).unwrap_err().category, StableError::PartialMigration);
            rollback_migration(&path).unwrap();
        }
        assert_eq!(open_manifest(&path, &requirements(1)).unwrap().generation, 0);
        assert!(!path.join(".migration-1").exists());
        fs::remove_dir_all(path).unwrap();
    }

    let unsupported = temporary_directory("unsupported-edge"); initialize_empty(&unsupported, &requirements(1)).unwrap();
    assert_eq!(migrate_generation(&unsupported, &requirements(1), 3, &CopyMigrator, &tron_storage::NoFaults).unwrap_err().category, StableError::UnsupportedMigration);
    assert_eq!(open_manifest(&unsupported, &requirements(1)).unwrap().generation, 0);
    fs::remove_dir_all(unsupported).unwrap();

    for phase in [DurablePhase::JournalSynced, DurablePhase::BackupSynced, DurablePhase::GenerationPublished, DurablePhase::ManifestSwitched, DurablePhase::DirectorySynced] {
        let path = temporary_directory("resume"); initialize_empty(&path, &requirements(1)).unwrap();
        let fault = FailAt { target: phase, fired: Cell::new(false) };
        assert!(migrate_generation(&path, &requirements(1), 2, &CopyMigrator, &fault).is_err());
        assert!(fault.fired.get(), "migration did not reach {phase:?}");
        if phase == DurablePhase::GenerationPublished {
            assert!(path.join("generation-1").is_dir());
        }
        let resumed = resume_migration(&path, &requirements(2)).unwrap();
        assert_eq!((resumed.generation, resumed.schema_version, resumed.state_root.as_str()), (1, 2, "root-v2"));
        assert_eq!(open_manifest(&path, &requirements(2)).unwrap(), resumed);
        assert!(!path.join("tron-storage.migration").exists());
        assert!(!path.join("manifest-generation-0.backup").exists());
        fs::remove_dir_all(path).unwrap();
    }

    let cleaned = temporary_directory("cleanup-fault"); initialize_empty(&cleaned, &requirements(1)).unwrap();
    let cleanup_fault = FailAt { target: DurablePhase::CleanupSynced, fired: Cell::new(false) };
    assert!(migrate_generation(&cleaned, &requirements(1), 2, &CopyMigrator, &cleanup_fault).is_err());
    assert_eq!(open_manifest(&cleaned, &requirements(2)).unwrap().generation, 1);
    assert!(!cleaned.join("tron-storage.migration").exists());
    fs::remove_dir_all(cleaned).unwrap();

    let snapshot = temporary_directory("snapshot-file"); fs::write(&snapshot, b"authenticated").unwrap();
    let destination = temporary_directory("snapshot-destination");
    let descriptor = SnapshotDescriptor { identity: requirements(1).identity.clone(), schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), state_root: "snapshot-root".into(), signature: vec![1] };
    let imported = import_snapshot(&destination, &requirements(1), &snapshot, 1024, &descriptor, &Accept, &Accept).unwrap();
    assert_eq!(imported.state_root, "snapshot-root");
    assert_eq!(fs::read(destination.join("generation-0/nested/state")).unwrap(), b"snapshot");
    write_clean_resync_marker(&destination, &requirements(1).identity, "trusted-checkpoint").unwrap();
    let marker = fs::read_to_string(destination.join("tron-storage.clean-resync")).unwrap();
    assert!(marker.contains("network=mainnet") && marker.contains("genesis=00aa") && marker.contains("origin=trusted-checkpoint"));
    fs::remove_file(snapshot).unwrap(); fs::remove_dir_all(destination).unwrap();
}

#[cfg(unix)]
#[test]
fn format_boundary_rejects_symlink_roots_and_manifest_finals_without_writes() {
    use std::os::unix::fs::symlink;

    let outside = temporary_directory("symlink-outside");
    fs::create_dir(&outside).unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
    let root_link = temporary_directory("symlink-root");
    symlink(&outside, &root_link).unwrap();
    let before = tree(&outside);
    assert!(inspect_read_only(&root_link).is_err());
    assert_eq!(tree(&outside), before);
    fs::remove_file(root_link).unwrap();

    let root = temporary_directory("symlink-manifest");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let target = outside.join("manifest-target");
    symlink(&target, root.join("tron-storage.manifest")).unwrap();
    assert!(matches!(inspect_read_only(&root), Err(FormatError { category: StableError::Permission, .. })));
    assert!(!target.exists());
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}


#[cfg(unix)]
#[test]
fn abrupt_migration_process_death_releases_lock_and_recovers_durable_journal() {
    const ROOT_ENV: &str = "TRON_STORAGE_ABRUPT_MIGRATION_ROOT";
    const PHASE_ENV: &str = "TRON_STORAGE_ABRUPT_MIGRATION_PHASE";
    if let (Some(root), Ok(phase)) = (std::env::var_os(ROOT_ENV), std::env::var(PHASE_ENV)) {
        let phase = match phase.as_str() {
            "prepared" => DurablePhase::StagingCreated,
            "ready" => DurablePhase::JournalSynced,
            "generation-published" => DurablePhase::GenerationPublished,
            value => panic!("unknown abrupt migration phase {value}"),
        };
        let _ = migrate_generation(PathBuf::from(root), &requirements(1), 2, &CopyMigrator, &AbruptAt(phase));
        panic!("abrupt fault did not terminate the child");
    }

    for phase in ["prepared", "ready", "generation-published"] {
        let path = temporary_directory(&format!("abrupt-{phase}"));
        initialize_empty(&path, &requirements(1)).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("abrupt_migration_process_death_releases_lock_and_recovers_durable_journal")
            .arg("--nocapture")
            .env(ROOT_ENV, &path)
            .env(PHASE_ENV, phase)
            .status()
            .unwrap();
        assert!(!status.success());
        assert!(path.join("tron-storage.migration").exists());
        if phase == "prepared" {
            rollback_migration(&path).unwrap();
            assert_eq!(open_manifest(&path, &requirements(1)).unwrap().generation, 0);
        } else {
            if phase == "generation-published" {
                assert!(path.join("generation-1").is_dir());
            }
            let resumed = resume_migration(&path, &requirements(2)).unwrap();
            assert_eq!(resumed.generation, 1);
            assert_eq!(open_manifest(&path, &requirements(2)).unwrap(), resumed);
            assert!(!path.join("tron-storage.migration").exists());
            assert!(!path.join("manifest-generation-0.backup").exists());
        }
        fs::remove_dir_all(path).unwrap();
    }
}

#[cfg(unix)]
struct SwapRootAt<'a> { phase: DurablePhase, root: &'a Path, moved: &'a Path, fired: Cell<bool> }
#[cfg(unix)]
impl FaultInjector for SwapRootAt<'_> {
    fn after(&self, phase: DurablePhase) -> io::Result<()> {
        if phase == self.phase && !self.fired.replace(true) {
            fs::rename(self.root, self.moved)?;
            fs::create_dir(self.root)?;
            fs::set_permissions(self.root, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

#[cfg(unix)]
#[test]
fn migration_root_replacement_fails_before_publication_and_never_reopens_path() {
    for phase in [DurablePhase::Preflight, DurablePhase::DataSynced, DurablePhase::JournalSynced, DurablePhase::BackupSynced] {
        let root = temporary_directory("migration-root-swap");
        let moved = root.with_extension(format!("retained-{phase:?}"));
        initialize_empty(&root, &requirements(1)).unwrap();
        let fault = SwapRootAt { phase, root: &root, moved: &moved, fired: Cell::new(false) };
        let error = migrate_generation(&root, &requirements(1), 2, &CopyMigrator, &fault).unwrap_err();
        assert!(fault.fired.get());
        assert_eq!(error.category, StableError::ConcurrentOpen);
        assert!(!root.join("tron-storage.manifest").exists());
        fs::remove_dir_all(&root).unwrap();
        fs::rename(&moved, &root).unwrap();
        assert!(!root.join("tron-storage.migration").exists());
        assert!(!root.join(".migration-1").exists());
        assert!(!root.join("generation-1").exists());
        assert!(!root.join("manifest-generation-0.backup").exists());
        assert_eq!(open_manifest(&root, &requirements(1)).unwrap().generation, 0);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn inspect_to_open_path_and_nonempty_swaps_fail_without_mutation() {
    use std::os::unix::fs::symlink;

    let root = temporary_directory("inspect-open-swap");
    let retained = root.with_extension("retained");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(inspect_read_only(&root).unwrap(), DirectoryClassification::Empty);
    fs::rename(&root, &retained).unwrap();
    symlink(&retained, &root).unwrap();
    let retained_before = tree(&retained);
    assert!(StorageManager::new(requirements(1)).open_store(&root).is_err());
    assert_eq!(tree(&retained), retained_before);
    fs::remove_file(&root).unwrap();

    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(inspect_read_only(&root).unwrap(), DirectoryClassification::Empty);
    fs::remove_dir(&root).unwrap();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("foreign-state"), b"untouched").unwrap();
    let replacement_before = tree(&root);
    assert!(StorageManager::new(requirements(1)).open_store(&root).is_err());
    assert_eq!(tree(&root), replacement_before);
    assert!(!root.join("generation-0").exists());
    assert!(!root.join("tron-storage.manifest").exists());
    assert!(!root.join("tron-storage.lock").exists());

    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(retained).unwrap();
}
