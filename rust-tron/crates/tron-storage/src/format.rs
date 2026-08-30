use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use crate::fs::{sync_tree_dir, KernelLock, SecureDir};

pub const MANIFEST_FILE: &str = "tron-storage.manifest";
pub const RESYNC_FILE: &str = "tron-storage.clean-resync";
const MIGRATION_JOURNAL: &str = "tron-storage.migration";
const SNAPSHOT_IMPORT_JOURNAL: &str = "tron-storage.snapshot-import";
const SNAPSHOT_IMPORT_STAGING: &str = ".snapshot-import";
const SNAPSHOT_IMPORT_GENERATION: &str = "generation-0";
const INITIALIZATION_JOURNAL: &str = "tron-storage.initializing";
pub(crate) const MIGRATION_LOCK: &str = "tron-storage.lock";
const MANIFEST_MAGIC: &str = "TRON-RUST-STORAGE-MANIFEST";
const MANIFEST_VERSION: u32 = 1;
const INITIALIZATION_MAGIC: &str = "TRON-RUST-STORAGE-INITIALIZATION";
const INITIALIZATION_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitializationPhase { Journal, Generation, Manifest }

impl InitializationPhase {
    fn as_str(self) -> &'static str {
        match self { Self::Journal => "journal", Self::Generation => "generation", Self::Manifest => "manifest" }
    }
}

struct InitializationState {
    manifest_temporary: bool,
    manifest_final: bool,
}
const MANIFEST_FIELDS: [&str; 11] = [
    "backend",
    "backend_format",
    "features",
    "generation",
    "genesis",
    "manifest_version",
    "network",
    "parent_generation",
    "schema_version",
    "state",
    "state_root",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageIdentity {
    pub network: String,
    pub genesis: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub manifest_version: u32,
    pub schema_version: u32,
    pub network: String,
    pub genesis: String,
    pub backend: String,
    pub backend_format: String,
    pub features: Vec<String>,
    pub generation: u64,
    pub state: ManifestState,
    pub parent_generation: Option<u64>,
    pub state_root: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestState { Clean, Dirty }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenRequirements {
    pub identity: StorageIdentity,
    pub schema_version: u32,
    pub backend: String,
    pub backend_format: String,
    pub supported_features: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectoryClassification {
    Missing,
    Empty,
    InitializingEmpty,
    Rust(Manifest),
    Java { marker: String },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StableError {
    JavaFormat,
    AmbiguousNonempty,
    ManifestMissing,
    ManifestCorrupt,
    FormatUnknown,
    FormatNewer,
    WrongNetwork,
    WrongGenesis,
    BackendUnsupported,
    FeaturesUnsupported,
    PartialMigration,
    Locked,
    Permission,
    DiskFull,
    ConcurrentOpen,
    Integrity,
    SnapshotUnauthenticated,
    SnapshotIncompatible,
    NotEmpty,
    UnsupportedMigration,
    Io,
    SourceTooLarge,
}

#[derive(Debug)]
pub struct FormatError {
    pub category: StableError,
    pub path: PathBuf,
    pub detail: String,
}

impl FormatError {
    pub(crate) fn new(category: StableError, path: impl Into<PathBuf>, detail: impl Into<String>) -> Self {
        Self { category, path: path.into(), detail: detail.into() }
    }
}
impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}: {}", self.category, self.path.display(), self.detail)
    }
}
impl std::error::Error for FormatError {}
pub type FormatResult<T> = Result<T, FormatError>;

fn io_error(path: &Path, error: io::Error) -> FormatError {
    let category = match error.kind() {
        io::ErrorKind::PermissionDenied => StableError::Permission,
        io::ErrorKind::StorageFull => StableError::DiskFull,
        io::ErrorKind::WouldBlock => StableError::ConcurrentOpen,
        _ if error.raw_os_error() == Some(28) => StableError::DiskFull,
        _ => StableError::Io,
    };
    FormatError::new(category, path, error.to_string())
}

pub fn inspect_read_only(path: impl AsRef<Path>) -> FormatResult<DirectoryClassification> {
    let path = path.as_ref();
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(DirectoryClassification::Missing),
        Err(error) => return Err(io_error(path, error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(FormatError::new(StableError::AmbiguousNonempty, path, "storage path must be a real directory"));
    }
    let directory = SecureDir::open_read_only(path).map_err(|error| io_error(path, error))?;
    classify_at(&directory, path)
}
pub(crate) fn classify_open_read_only(path: &Path, requirements: &OpenRequirements) -> FormatResult<DirectoryClassification> {
    let classification = inspect_read_only(path)?;
    match &classification {
        DirectoryClassification::Java { marker } => {
            Err(FormatError::new(StableError::JavaFormat, path, marker.clone()))
        }
        DirectoryClassification::Rust(manifest) => {
            manifest.validate(requirements, path)?;
            Ok(classification)
        }
        DirectoryClassification::Missing
        | DirectoryClassification::Empty
        | DirectoryClassification::InitializingEmpty => Ok(classification),
    }
}

pub(crate) fn classify_at(directory: &SecureDir, path: &Path) -> FormatResult<DirectoryClassification> {
    let entries = directory.entries().map_err(|error| io_error(path, error))?;
    if entries.iter().any(|(_, kind)| kind.is_symlink()) {
        return Err(FormatError::new(StableError::Permission, path, "symbolic links are forbidden in storage state"));
    }
    let mut names: Vec<String> = entries.iter().map(|(name, _)| name.to_string_lossy().into_owned()).collect();
    names.sort();
    names.retain(|name| name != MIGRATION_LOCK);
    if names.is_empty() { return Ok(DirectoryClassification::Empty); }
    if let Some(marker) = names.iter().find(|name| java_marker(name)) {
        return Ok(DirectoryClassification::Java { marker: marker.clone() });
    }
    if names.iter().any(|name| name == MIGRATION_JOURNAL || name == SNAPSHOT_IMPORT_JOURNAL || name.starts_with(".migration-") || name == SNAPSHOT_IMPORT_STAGING) {
        return Err(FormatError::new(StableError::PartialMigration, path, "migration or snapshot import requires recovery"));
    }
    if names.iter().any(|name| name == INITIALIZATION_JOURNAL) {
        initialization_state(directory, path, &entries)?;
        return Ok(DirectoryClassification::InitializingEmpty);
    }
    let manifest_path = path.join(MANIFEST_FILE);
    if !names.iter().any(|name| name == MANIFEST_FILE) {
        return Err(FormatError::new(StableError::AmbiguousNonempty, manifest_path, "non-empty directory has no recognized storage format"));
    }
    let bytes = read_bounded_at(directory, MANIFEST_FILE, 1024 * 1024, &manifest_path)?;
    Ok(DirectoryClassification::Rust(Manifest::decode(&bytes, &manifest_path)?))
}

fn java_marker(name: &str) -> bool {
    name == "engine.properties" || name == "CURRENT" || name == "LOG" || name == "LOG.old"
        || name == "LOCK" || name.starts_with("MANIFEST-") || name.starts_with("OPTIONS-")
        || name.ends_with(".sst") || name.ends_with(".ldb") || name.starts_with("IDENTITY")
}

impl Manifest {
    pub fn new(requirements: &OpenRequirements) -> Self {
        let mut features = requirements.supported_features.clone();
        features.sort(); features.dedup();
        Self {
            manifest_version: MANIFEST_VERSION,
            schema_version: requirements.schema_version,
            network: requirements.identity.network.clone(), genesis: requirements.identity.genesis.clone(),
            backend: requirements.backend.clone(), backend_format: requirements.backend_format.clone(), features,
            generation: 0, state: ManifestState::Clean, parent_generation: None, state_root: String::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut fields = BTreeMap::new();
        fields.insert("backend", self.backend.clone());
        fields.insert("backend_format", self.backend_format.clone());
        fields.insert("features", self.features.join(","));
        fields.insert("generation", self.generation.to_string());
        fields.insert("genesis", self.genesis.clone());
        fields.insert("manifest_version", self.manifest_version.to_string());
        fields.insert("network", self.network.clone());
        fields.insert("parent_generation", self.parent_generation.map_or_else(|| "none".into(), |v| v.to_string()));
        fields.insert("schema_version", self.schema_version.to_string());
        fields.insert("state", match self.state { ManifestState::Clean => "clean", ManifestState::Dirty => "dirty" }.into());
        fields.insert("state_root", self.state_root.clone());
        let mut body = format!("{MANIFEST_MAGIC}\n").into_bytes();
        for (key, value) in fields { body.extend_from_slice(format!("{key}={}\n", escape(&value)).as_bytes()); }
        let checksum = crc32(&body);
        body.extend_from_slice(format!("checksum={checksum:08x}\n").as_bytes());
        body
    }

    pub fn decode(bytes: &[u8], path: &Path) -> FormatResult<Self> {
        let text = std::str::from_utf8(bytes).map_err(|_| FormatError::new(StableError::ManifestCorrupt, path, "manifest is not UTF-8"))?;
        let split = text.rfind("checksum=").ok_or_else(|| FormatError::new(StableError::ManifestCorrupt, path, "checksum missing"))?;
        let (body, checksum_line) = text.split_at(split);
        let claimed = checksum_line.strip_prefix("checksum=").and_then(|v| v.strip_suffix('\n')).and_then(|v| u32::from_str_radix(v, 16).ok())
            .ok_or_else(|| FormatError::new(StableError::ManifestCorrupt, path, "invalid checksum field"))?;
        if crc32(body.as_bytes()) != claimed { return Err(FormatError::new(StableError::Integrity, path, "manifest checksum mismatch")); }
        let mut lines = body.lines();
        if lines.next() != Some(MANIFEST_MAGIC) { return Err(FormatError::new(StableError::FormatUnknown, path, "unknown manifest magic")); }
        let mut fields = BTreeMap::new();
        for line in lines {
            let (key, value) = line.split_once('=').ok_or_else(|| FormatError::new(StableError::ManifestCorrupt, path, "malformed field"))?;
            if !MANIFEST_FIELDS.contains(&key) {
                return Err(FormatError::new(StableError::ManifestCorrupt, path, format!("unknown field {key}")));
            }
            if fields.insert(key, unescape(value).ok_or_else(|| FormatError::new(StableError::ManifestCorrupt, path, "invalid escaping"))?).is_some() {
                return Err(FormatError::new(StableError::ManifestCorrupt, path, "duplicate field"));
            }
        }
        if fields.len() != MANIFEST_FIELDS.len() {
            return Err(FormatError::new(StableError::ManifestCorrupt, path, "manifest field set is incomplete"));
        }
        let version = number(&fields, "manifest_version", path)?;
        if version > MANIFEST_VERSION { return Err(FormatError::new(StableError::FormatNewer, path, "manifest requires newer executable")); }
        if version != MANIFEST_VERSION { return Err(FormatError::new(StableError::FormatUnknown, path, "unsupported manifest version")); }
        let state = match required(&fields, "state", path)? { "clean" => ManifestState::Clean, "dirty" => ManifestState::Dirty, _ => return Err(FormatError::new(StableError::ManifestCorrupt, path, "invalid state")) };
        let parent = match required(&fields, "parent_generation", path)? { "none" => None, value => Some(value.parse().map_err(|_| FormatError::new(StableError::ManifestCorrupt, path, "invalid parent generation"))?) };
        let features = required(&fields, "features", path)?.split(',').filter(|v| !v.is_empty()).map(str::to_owned).collect::<Vec<_>>();
        if features.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(FormatError::new(StableError::ManifestCorrupt, path, "features must be sorted and unique"));
        }
        Ok(Self { manifest_version: version, schema_version: number(&fields,"schema_version",path)?, network: required(&fields,"network",path)?.into(), genesis: required(&fields,"genesis",path)?.into(), backend: required(&fields,"backend",path)?.into(), backend_format: required(&fields,"backend_format",path)?.into(), features, generation: number(&fields,"generation",path)?, state, parent_generation: parent, state_root: required(&fields,"state_root",path)?.into() })
    }

    pub fn validate(&self, requirements: &OpenRequirements, path: &Path) -> FormatResult<()> {
        if self.network != requirements.identity.network { return Err(FormatError::new(StableError::WrongNetwork,path,"network identity mismatch")); }
        if self.genesis != requirements.identity.genesis { return Err(FormatError::new(StableError::WrongGenesis,path,"genesis identity mismatch")); }
        if self.backend != requirements.backend || self.backend_format != requirements.backend_format { return Err(FormatError::new(StableError::BackendUnsupported,path,"backend identity unsupported")); }
        if self.schema_version > requirements.schema_version { return Err(FormatError::new(StableError::FormatNewer,path,"schema requires newer executable")); }
        if self.schema_version < requirements.schema_version { return Err(FormatError::new(StableError::UnsupportedMigration,path,"schema migration required")); }
        if self.features.iter().any(|f| !requirements.supported_features.contains(f)) { return Err(FormatError::new(StableError::FeaturesUnsupported,path,"required feature unsupported")); }
        if self.state != ManifestState::Clean { return Err(FormatError::new(StableError::Integrity,path,"manifest is dirty")); }
        Ok(())
    }
}

pub fn initialize_empty(path: impl AsRef<Path>, requirements: &OpenRequirements) -> FormatResult<Manifest> {
    let path = path.as_ref();
    match classify_open_read_only(path, requirements)? {
        DirectoryClassification::Missing | DirectoryClassification::Empty | DirectoryClassification::InitializingEmpty => {}
        DirectoryClassification::Rust(_) => {
            return Err(FormatError::new(StableError::NotEmpty, path, "already initialized"));
        }
        DirectoryClassification::Java { .. } => unreachable!("Java storage is rejected by read-only preflight"),
    }

    let directory = SecureDir::open_or_create(path).map_err(|error| io_error(path, error))?;
    let lock_path = path.join(MIGRATION_LOCK);
    let root_lock = directory.lock_root_exclusive().map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            FormatError::new(StableError::Locked, &lock_path, "storage is already open or mutating")
        } else {
            io_error(&lock_path, error)
        }
    })?;
    validate_retained_root(&directory, path)?;
    directory.reject_symlink_entries().map_err(|error| io_error(path, error))?;
    match classify_at(&directory, path)? {
        DirectoryClassification::Empty | DirectoryClassification::InitializingEmpty => {}
        DirectoryClassification::Rust(_) => return Err(FormatError::new(StableError::NotEmpty, path, "already initialized")),
        DirectoryClassification::Java { marker } => return Err(FormatError::new(StableError::JavaFormat, path, marker)),
        DirectoryClassification::Missing => return Err(FormatError::new(StableError::ManifestMissing, path, "retained storage directory is missing")),
    }
    let _lock = directory.finish_exclusive_lock(root_lock, MIGRATION_LOCK.as_ref()).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            FormatError::new(StableError::Locked, &lock_path, "storage is already open or mutating")
        } else {
            io_error(&lock_path, error)
        }
    })?;
    initialize_empty_at(&directory, path, requirements)
}

pub(crate) fn initialize_empty_at(directory: &SecureDir, path: &Path, requirements: &OpenRequirements) -> FormatResult<Manifest> {
    let classification = classify_at(directory, path)?;
    match classification {
        DirectoryClassification::Empty => {
            write_initialization_journal(directory, path, InitializationPhase::Journal, true)?;
        }
        DirectoryClassification::InitializingEmpty => {}
        DirectoryClassification::Missing => return Err(FormatError::new(StableError::ManifestMissing, path, "retained storage directory is missing")),
        DirectoryClassification::Java { marker } => return Err(FormatError::new(StableError::JavaFormat,path,marker)),
        DirectoryClassification::Rust(_) => return Err(FormatError::new(StableError::NotEmpty,path,"already initialized")),
    }

    let mut state = initialization_state(directory, path, &directory.entries().map_err(|error| io_error(path, error))?)?;
    if state.manifest_temporary {
        remove_initialization_manifest_temporaries(directory, path)?;
        state.manifest_temporary = false;
    }
    if state.manifest_final {
        let manifest_path = path.join(MANIFEST_FILE);
        let manifest = Manifest::decode(&read_bounded_at(directory, MANIFEST_FILE, 1024 * 1024, &manifest_path)?, &manifest_path)?;
        manifest.validate(requirements, path)?;
        write_initialization_journal(directory, path, InitializationPhase::Manifest, false)?;
        cleanup_initialization(directory, path)?;
        return Ok(manifest);
    }
    if !directory.contains(std::ffi::OsStr::new("generation-0")).map_err(|error| io_error(path, error))? {
        let generation_name = std::ffi::OsStr::new("generation-0");
        let generation = directory.create_dir(generation_name).map_err(|error| io_error(&path.join(generation_name), error))?;
        generation.sync().map_err(|error| io_error(&path.join(generation_name), error))?;
        directory.sync().map_err(|error| io_error(path, error))?;
    }
    write_initialization_journal(directory, path, InitializationPhase::Generation, false)?;
    let manifest = Manifest::new(requirements);
    install_atomic_at(directory, MANIFEST_FILE, &manifest.encode(), path)?;
    write_initialization_journal(directory, path, InitializationPhase::Manifest, false)?;
    cleanup_initialization(directory,path)?;
    Ok(manifest)
}

pub fn open_manifest(path: impl AsRef<Path>, requirements: &OpenRequirements) -> FormatResult<Manifest> {
    let path = path.as_ref();
    if path.join(SNAPSHOT_IMPORT_JOURNAL).exists() {
        let directory=SecureDir::open(path).map_err(|error|io_error(path,error))?;
        let _lock=acquire_storage_lock_at(&directory,path)?;
        if let Some(manifest)=recover_snapshot_import_locked(&directory,path,requirements)? { return Ok(manifest); }
    }
    match inspect_read_only(path)? {
        DirectoryClassification::Rust(manifest) => { manifest.validate(requirements,path)?; Ok(manifest) }
        DirectoryClassification::Java { marker } => Err(FormatError::new(StableError::JavaFormat,path,marker)),
        DirectoryClassification::InitializingEmpty => Err(FormatError::new(StableError::PartialMigration,path,"empty initialization requires recovery")),
        DirectoryClassification::Empty => Err(FormatError::new(StableError::ManifestMissing,path,"empty directory is not initialized")),
        DirectoryClassification::Missing => Err(FormatError::new(StableError::ManifestMissing,path,"directory does not exist")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurablePhase { Preflight, StagingCreated, DataWritten, DataSynced, JournalSynced, BackupSynced, GenerationPublished, ManifestSwitched, DirectorySynced, CleanupSynced }
pub trait FaultInjector { fn after(&self, phase: DurablePhase) -> io::Result<()>; }
pub struct NoFaults;
impl FaultInjector for NoFaults { fn after(&self, _: DurablePhase) -> io::Result<()> { Ok(()) } }

pub trait GenerationMigrator {
    fn migrate(&self, source: &Path, destination: &Path) -> FormatResult<String>;
}

#[derive(Clone, Copy)]
struct MigrationEdge {
    source_schema: u32,
    target_schema: u32,
    backend: &'static str,
    source_format: &'static str,
    target_format: &'static str,
    rollback_before_manifest_switch: bool,
}

const MIGRATION_EDGES: [MigrationEdge; 1] = [MigrationEdge {
    source_schema: 1,
    target_schema: 2,
    backend: "rustlog",
    source_format: "rustlog-v1",
    target_format: "rustlog-v1",
    rollback_before_manifest_switch: true,
}];

struct MigrationLock { _lock: KernelLock }

#[derive(Clone)]
struct MigrationJournal { from: u64, to: u64, source_schema: u32, target_schema: u32, phase: String, root: String }

#[derive(Clone)]
struct SnapshotImportJournal {
    identity: StorageIdentity,
    schema_version: u32,
    backend: String,
    backend_format: String,
    root: String,
    phase: String,
}

pub fn migrate_generation(path: impl AsRef<Path>, requirements: &OpenRequirements, target_schema: u32, migrator: &dyn GenerationMigrator, faults: &dyn FaultInjector) -> FormatResult<Manifest> {
    let path = path.as_ref();
    let directory = SecureDir::open(path).map_err(|error| io_error(path, error))?;
    let initial = open_manifest_at(&directory, path, requirements)?;
    let edge = migration_edge(&initial, target_schema).ok_or_else(|| FormatError::new(StableError::UnsupportedMigration,path,"migration edge is not registered"))?;
    let _lock = acquire_storage_lock_at(&directory, path)?;
    let old = open_manifest_at(&directory, path, requirements)?;
    if old != initial { return Err(FormatError::new(StableError::ConcurrentOpen,path,"manifest changed during migration preflight")); }
    faults.after(DurablePhase::Preflight).map_err(|e| io_error(path,e))?;
    validate_retained_root(&directory, path)?;
    let next = old.generation.checked_add(1).ok_or_else(|| FormatError::new(StableError::Integrity,path,"generation overflow"))?;
    let staging_name=format!(".migration-{next}");
    let generation_name=format!("generation-{next}");
    if directory.contains(staging_name.as_ref()).map_err(|error|io_error(path,error))? || directory.contains(MIGRATION_JOURNAL.as_ref()).map_err(|error|io_error(path,error))? || directory.contains(generation_name.as_ref()).map_err(|error|io_error(path,error))? { return Err(FormatError::new(StableError::PartialMigration,path,"resume or rollback required")); }
    let mut journal = MigrationJournal { from: old.generation, to: next, source_schema: old.schema_version, target_schema, phase: "prepared".into(), root: String::new() };
    install_atomic_at(&directory, MIGRATION_JOURNAL, &encode_journal(&journal),path)?;
    let staging=directory.create_dir(staging_name.as_ref()).map_err(|error|io_error(&path.join(&staging_name),error))?;
    directory.sync().map_err(|error|io_error(path,error))?;
    faults.after(DurablePhase::StagingCreated).map_err(|e| io_error(path,e))?;
    validate_retained_root_before_publication(&directory, path, &journal)?;
    let source_name=format!("generation-{}",old.generation);
    let root = migrator.migrate(&directory.child_access_path(source_name.as_ref()).map_err(|error|io_error(path,error))?, &staging.access_path())?;
    faults.after(DurablePhase::DataWritten).map_err(|e| io_error(path,e))?;
    validate_retained_root_before_publication(&directory, path, &journal)?;
    sync_tree_dir(&staging).map_err(|error|io_error(&path.join(&staging_name),error))?;
    faults.after(DurablePhase::DataSynced).map_err(|e| io_error(path,e))?;
    validate_retained_root_before_publication(&directory, path, &journal)?;
    journal.phase = "ready".into(); journal.root = root.clone();
    install_atomic_at(&directory, MIGRATION_JOURNAL, &encode_journal(&journal),path)?;
    faults.after(DurablePhase::JournalSynced).map_err(|e| io_error(path,e))?;
    validate_retained_root_before_publication(&directory, path, &journal)?;
    let backup_name=format!("manifest-generation-{}.backup",old.generation);
    write_sync_at(&directory, backup_name.as_ref(), &old.encode(), true, &path.join(&backup_name))?;
    directory.sync().map_err(|error|io_error(path,error))?;
    faults.after(DurablePhase::BackupSynced).map_err(|e| io_error(path,e))?;
    validate_retained_root_before_publication(&directory, path, &journal)?;
    directory.rename(staging_name.as_ref(),generation_name.as_ref()).map_err(|error|io_error(path,error))?;
    directory.sync().map_err(|error|io_error(path,error))?;
    faults.after(DurablePhase::GenerationPublished).map_err(|e| io_error(path,e))?;
    let mut new = old.clone(); new.schema_version=edge.target_schema; new.backend_format=edge.target_format.into(); new.generation=next; new.parent_generation=Some(old.generation); new.state_root=root;
    validate_retained_root_before_publication(&directory, path, &journal)?;
    install_atomic_at(&directory,MANIFEST_FILE,&new.encode(),path)?;
    faults.after(DurablePhase::ManifestSwitched).map_err(|e| io_error(path,e))?;
    validate_retained_root(&directory, path)?;
    directory.sync().map_err(|error|io_error(path,error))?;
    faults.after(DurablePhase::DirectorySynced).map_err(|e| io_error(path,e))?;
    validate_retained_root(&directory, path)?;
    cleanup_migration_at(&directory, path, &journal)?;
    faults.after(DurablePhase::CleanupSynced).map_err(|e| io_error(path,e))?;
    Ok(new)
}

pub fn rollback_migration(path: impl AsRef<Path>) -> FormatResult<()> {
    let path=path.as_ref();
    let directory=SecureDir::open(path).map_err(|error|io_error(path,error))?;
    let _lock=acquire_storage_lock_at(&directory,path)?;
    let journal=decode_journal_at(&directory,path)?;
    let edge=MIGRATION_EDGES.iter().find(|edge| edge.source_schema==journal.source_schema && edge.target_schema==journal.target_schema)
        .ok_or_else(||FormatError::new(StableError::UnsupportedMigration,path,"journal migration edge is not registered"))?;
    if !edge.rollback_before_manifest_switch { return Err(FormatError::new(StableError::UnsupportedMigration,path,"migration edge is not rollback-safe")); }
    if journal.phase!="prepared" || !journal.root.is_empty() { return Err(FormatError::new(StableError::PartialMigration,path,"ready migration must be resumed, not rolled back")); }
    let manifest_path=path.join(MANIFEST_FILE);
    let manifest=Manifest::decode(&read_bounded_at(&directory,MANIFEST_FILE,1024*1024,&manifest_path)?,&manifest_path)?;
    if manifest.generation==journal.to { return Err(FormatError::new(StableError::PartialMigration,path,"published migration must be resumed, not rolled back")); }
    if manifest.generation!=journal.from { return Err(FormatError::new(StableError::PartialMigration,path,"manifest does not match migration journal")); }
    rollback_unpublished_migration_at(&directory,path,&journal)
}

pub fn resume_migration(path: impl AsRef<Path>, requirements: &OpenRequirements) -> FormatResult<Manifest> {
    let path=path.as_ref();
    let directory=SecureDir::open(path).map_err(|error|io_error(path,error))?;
    let _lock=acquire_storage_lock_at(&directory,path)?;
    let journal=decode_journal_at(&directory,path)?;
    if journal.phase!="ready" || journal.root.is_empty() { return Err(FormatError::new(StableError::PartialMigration,path,"migration is not ready to resume; roll it back")); }
    let edge=MIGRATION_EDGES.iter().find(|edge| edge.source_schema==journal.source_schema && edge.target_schema==journal.target_schema)
        .ok_or_else(||FormatError::new(StableError::UnsupportedMigration,path,"journal migration edge is not registered"))?;
    let manifest_path=path.join(MANIFEST_FILE);
    let mut manifest=Manifest::decode(&read_bounded_at(&directory,MANIFEST_FILE,1024*1024,&manifest_path)?,&manifest_path)?;
    if manifest.generation==journal.to {
        if manifest.schema_version!=edge.target_schema || manifest.backend!=edge.backend || manifest.backend_format!=edge.target_format || manifest.parent_generation!=Some(journal.from) || manifest.state_root!=journal.root { return Err(FormatError::new(StableError::PartialMigration,path,"published manifest does not match ready migration journal")); }
        manifest.validate(requirements,path)?; validate_retained_root(&directory,path)?; cleanup_migration_at(&directory,path,&journal)?; return Ok(manifest);
    }
    if manifest.generation!=journal.from || manifest.schema_version!=edge.source_schema || manifest.backend!=edge.backend || manifest.backend_format!=edge.source_format { return Err(FormatError::new(StableError::PartialMigration,path,"manifest does not match ready migration journal")); }
    validate_retained_root(&directory,path)?;
    let staging=format!(".migration-{}",journal.to);
    let generation=format!("generation-{}",journal.to);
    let has_staging=directory.contains(staging.as_ref()).map_err(|error|io_error(path,error))?;
    let has_generation=directory.contains(generation.as_ref()).map_err(|error|io_error(path,error))?;
    match (has_staging,has_generation) {
        (true,false) => {
            directory.rename(staging.as_ref(),generation.as_ref()).map_err(|error|io_error(path,error))?;
            directory.sync().map_err(|error|io_error(path,error))?;
        }
        (false,true) => {},
        (false,false) => return Err(FormatError::new(StableError::PartialMigration,path,"completed generation is missing")),
        (true,true) => return Err(FormatError::new(StableError::PartialMigration,path,"staging and published generation both exist")),
    }
    directory.open_child(generation.as_ref()).map_err(|error|io_error(&path.join(&generation),error))?;
    manifest.schema_version=edge.target_schema; manifest.backend_format=edge.target_format.into(); manifest.generation=journal.to; manifest.parent_generation=Some(journal.from); manifest.state_root=journal.root.clone();
    manifest.validate(requirements,path)?;
    validate_retained_root(&directory,path)?;
    install_atomic_at(&directory,MANIFEST_FILE,&manifest.encode(),path)?;
    cleanup_migration_at(&directory,path,&journal)?;
    Ok(manifest)
}

pub fn write_clean_resync_marker(path: impl AsRef<Path>, identity: &StorageIdentity, origin: &str) -> FormatResult<()> {
    let path = path.as_ref();
    let initial = match inspect_read_only(path)? {
        DirectoryClassification::Rust(manifest) => manifest,
        DirectoryClassification::Java { marker } => return Err(FormatError::new(StableError::JavaFormat, path, marker)),
        DirectoryClassification::InitializingEmpty => return Err(FormatError::new(StableError::PartialMigration, path, "empty initialization requires recovery")),
        DirectoryClassification::Empty => return Err(FormatError::new(StableError::ManifestMissing, path, "empty directory is not initialized")),
        DirectoryClassification::Missing => return Err(FormatError::new(StableError::ManifestMissing, path, "directory does not exist")),
    };
    validate_resync_manifest(&initial, identity, path)?;

    let directory = SecureDir::open(path).map_err(|error| io_error(path, error))?;
    let _lock = acquire_storage_shared_lock_at(&directory, path)?;
    validate_retained_root(&directory, path)?;
    let manifest_path = path.join(MANIFEST_FILE);
    let current = Manifest::decode(&read_bounded_at(&directory, MANIFEST_FILE, 1024 * 1024, &manifest_path)?, &manifest_path)?;
    validate_resync_manifest(&current, identity, path)?;
    if current.generation != initial.generation || current.network != initial.network || current.genesis != initial.genesis {
        return Err(FormatError::new(StableError::ConcurrentOpen, path, "manifest identity or generation changed during clean-resync preflight"));
    }
    let generation = format!("generation-{}", current.generation);
    directory.open_child(generation.as_ref()).map_err(|error| io_error(&path.join(&generation), error))?;

    let body = format!("network={}\ngenesis={}\norigin={}\n", escape(&identity.network), escape(&identity.genesis), escape(origin));
    install_atomic_at(&directory, RESYNC_FILE, body.as_bytes(), path)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotDescriptor { pub identity: StorageIdentity, pub schema_version:u32, pub backend:String, pub backend_format:String, pub state_root:String, pub signature:Vec<u8> }

/// Immutable bytes read from one no-follow snapshot descriptor. The original pathname identity
/// is retained only so import can reject replacement before any destination state is published.
pub struct SnapshotSource {
    path: PathBuf,
    device: u64,
    inode: u64,
    bytes: Vec<u8>,
}

impl SnapshotSource {
    pub fn bytes(&self) -> &[u8] { &self.bytes }

    pub fn open(path: &Path, max_source_bytes: usize) -> FormatResult<Self> {
        const O_NOFOLLOW: i32 = 0o400000;
        const O_CLOEXEC: i32 = 0o2000000;
        let mut file = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW | O_CLOEXEC)
            .open(path).map_err(|error| io_error(path, error))?;
        let metadata = file.metadata().map_err(|error| io_error(path, error))?;
        if !metadata.is_file() {
            return Err(FormatError::new(StableError::Permission, path, "snapshot source must be a regular file"));
        }
        if metadata.len() > max_source_bytes as u64 {
            return Err(FormatError::new(StableError::SourceTooLarge, path, "snapshot source exceeds import policy bound"));
        }
        let bytes = read_capped(&mut file, max_source_bytes, path, StableError::SourceTooLarge)?;
        let after = reader_metadata(&file, path)?;
        if after.dev() != metadata.dev() || after.ino() != metadata.ino() || after.len() != metadata.len() || bytes.len() as u64 != metadata.len() {
            return Err(FormatError::new(StableError::Integrity, path, "snapshot source changed while being captured"));
        }
        Ok(Self { path:path.to_path_buf(), device:metadata.dev(), inode:metadata.ino(), bytes })
    }

    fn validate_path_identity(&self) -> FormatResult<()> {
        let metadata = fs::symlink_metadata(&self.path).map_err(|error| io_error(&self.path, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(FormatError::new(StableError::Integrity, &self.path, "snapshot source pathname was replaced during import"));
        }
        Ok(())
    }
}

pub trait SnapshotVerifier { fn verify(&self, descriptor:&SnapshotDescriptor, snapshot:&SnapshotSource) -> FormatResult<()>; }
pub trait SnapshotMaterializer { fn materialize(&self, snapshot:&SnapshotSource, destination:&Path) -> FormatResult<String>; }

pub fn import_snapshot(path: impl AsRef<Path>, requirements:&OpenRequirements, snapshot:&Path, max_source_bytes:usize, descriptor:&SnapshotDescriptor, verifier:&dyn SnapshotVerifier, materializer:&dyn SnapshotMaterializer) -> FormatResult<Manifest> {
    import_snapshot_with_faults(path,requirements,snapshot,max_source_bytes,descriptor,verifier,materializer,&NoFaults)
}

pub fn import_snapshot_with_faults(path: impl AsRef<Path>, requirements:&OpenRequirements, snapshot:&Path, max_source_bytes:usize, descriptor:&SnapshotDescriptor, verifier:&dyn SnapshotVerifier, materializer:&dyn SnapshotMaterializer, faults:&dyn FaultInjector) -> FormatResult<Manifest> {
    let path=path.as_ref();
    if descriptor.identity != requirements.identity || descriptor.schema_version != requirements.schema_version || descriptor.backend != requirements.backend || descriptor.backend_format != requirements.backend_format || descriptor.state_root.is_empty() { return Err(FormatError::new(StableError::SnapshotIncompatible,snapshot,"snapshot identity, root, or format mismatch")); }
    let snapshot=SnapshotSource::open(snapshot,max_source_bytes)?;
    verifier.verify(descriptor,&snapshot)?;
    snapshot.validate_path_identity()?;
    match inspect_read_only(path) { Ok(DirectoryClassification::Missing|DirectoryClassification::Empty)=>{}, Err(error) if error.category==StableError::PartialMigration=>{}, Ok(DirectoryClassification::Java{marker})=>return Err(FormatError::new(StableError::JavaFormat,path,marker)), Ok(DirectoryClassification::Rust(manifest)) if snapshot_manifest_matches(&manifest,descriptor,requirements)=>return Ok(manifest), Ok(_)=>return Err(FormatError::new(StableError::NotEmpty,path,"snapshot import requires empty destination")), Err(error)=>return Err(error) }
    let directory=SecureDir::open_or_create(path).map_err(|error|io_error(path,error))?;
    let _lock=acquire_storage_lock_at(&directory,path)?;
    validate_retained_root(&directory,path)?;
    if let Some(manifest)=recover_snapshot_import_locked(&directory,path,requirements)? {
        if snapshot_manifest_matches(&manifest,descriptor,requirements) { return Ok(manifest); }
        return Err(FormatError::new(StableError::NotEmpty,path,"destination contains a different imported snapshot"));
    }
    let entries=directory.entries().map_err(|error|io_error(path,error))?;
    if entries.iter().any(|(name,_)| name!=MIGRATION_LOCK) { return Err(FormatError::new(StableError::NotEmpty,path,"snapshot import requires empty destination")); }
    faults.after(DurablePhase::Preflight).map_err(|error|io_error(path,error))?;
    let mut journal=SnapshotImportJournal { identity:descriptor.identity.clone(), schema_version:descriptor.schema_version, backend:descriptor.backend.clone(), backend_format:descriptor.backend_format.clone(), root:descriptor.state_root.clone(), phase:"prepared".into() };
    validate_retained_root(&directory,path)?;
    install_atomic_at(&directory,SNAPSHOT_IMPORT_JOURNAL,&encode_snapshot_journal(&journal),path)?;
    faults.after(DurablePhase::JournalSynced).map_err(|error|{ let _=cleanup_snapshot_import(&directory,path,true); io_error(path,error) })?;
    let result=(|| {
        let staging=directory.create_dir(SNAPSHOT_IMPORT_STAGING.as_ref()).map_err(|error|io_error(&path.join(SNAPSHOT_IMPORT_STAGING),error))?;
        directory.sync().map_err(|error|io_error(path,error))?;
        faults.after(DurablePhase::StagingCreated).map_err(|error|io_error(path,error))?;
        snapshot.validate_path_identity()?;
        let root=materializer.materialize(&snapshot,&staging.access_path())?;
        faults.after(DurablePhase::DataWritten).map_err(|error|io_error(path,error))?;
        if root != descriptor.state_root { return Err(FormatError::new(StableError::Integrity,&snapshot.path,"logical root mismatch")); }
        sync_tree_dir(&staging).map_err(|error|io_error(&path.join(SNAPSHOT_IMPORT_STAGING),error))?;
        faults.after(DurablePhase::DataSynced).map_err(|error|io_error(path,error))?;
        journal.phase="ready".into(); install_atomic_at(&directory,SNAPSHOT_IMPORT_JOURNAL,&encode_snapshot_journal(&journal),path)?;
        validate_retained_root(&directory,path)?;
        directory.rename(SNAPSHOT_IMPORT_STAGING.as_ref(),SNAPSHOT_IMPORT_GENERATION.as_ref()).map_err(|error|io_error(path,error))?;
        directory.sync().map_err(|error|io_error(path,error))?;
        faults.after(DurablePhase::GenerationPublished).map_err(|error|io_error(path,error))?;
        journal.phase="published".into(); install_atomic_at(&directory,SNAPSHOT_IMPORT_JOURNAL,&encode_snapshot_journal(&journal),path)?;
        let mut manifest=Manifest::new(requirements); manifest.state_root=root;
        validate_retained_root(&directory,path)?;
        install_atomic_at(&directory,MANIFEST_FILE,&manifest.encode(),path)?;
        faults.after(DurablePhase::ManifestSwitched).map_err(|error|io_error(path,error))?;
        directory.sync().map_err(|error|io_error(path,error))?;
        faults.after(DurablePhase::DirectorySynced).map_err(|error|io_error(path,error))?;
        cleanup_snapshot_import(&directory,path,false)?;
        faults.after(DurablePhase::CleanupSynced).map_err(|error|io_error(path,error))?;
        Ok(manifest)
    })();
    if result.is_err() {
        let generation_exists=directory.contains(SNAPSHOT_IMPORT_GENERATION.as_ref()).unwrap_or(true);
        if !generation_exists { let _=cleanup_snapshot_import(&directory,path,true); }
    }
    result
}

fn snapshot_manifest_matches(manifest:&Manifest, descriptor:&SnapshotDescriptor, requirements:&OpenRequirements)->bool {
    manifest.generation==0 && manifest.parent_generation.is_none() && manifest.state==ManifestState::Clean && manifest.network==descriptor.identity.network && manifest.genesis==descriptor.identity.genesis && manifest.schema_version==descriptor.schema_version && manifest.backend==descriptor.backend && manifest.backend_format==descriptor.backend_format && manifest.state_root==descriptor.state_root && manifest.validate(requirements,Path::new(MANIFEST_FILE)).is_ok()
}

fn recover_snapshot_import_locked(directory:&SecureDir,path:&Path,requirements:&OpenRequirements)->FormatResult<Option<Manifest>> {
    if !directory.contains(SNAPSHOT_IMPORT_JOURNAL.as_ref()).map_err(|error|io_error(path,error))? { return Ok(None); }
    let journal_path=path.join(SNAPSHOT_IMPORT_JOURNAL);
    let journal=decode_snapshot_journal(&read_bounded_at(directory,SNAPSHOT_IMPORT_JOURNAL,4096,&journal_path)?,&journal_path)?;
    validate_retained_root(directory,path)?;
    if journal.identity!=requirements.identity || journal.schema_version!=requirements.schema_version || journal.backend!=requirements.backend || journal.backend_format!=requirements.backend_format || journal.root.is_empty() { return Err(FormatError::new(StableError::SnapshotIncompatible,&journal_path,"snapshot import journal identity, root, or format mismatch")); }
    let has_generation=directory.contains(SNAPSHOT_IMPORT_GENERATION.as_ref()).map_err(|error|io_error(path,error))?;
    let has_manifest=directory.contains(MANIFEST_FILE.as_ref()).map_err(|error|io_error(path,error))?;
    if !has_generation {
        if has_manifest || journal.phase=="published" { return Err(FormatError::new(StableError::Integrity,path,"published snapshot generation is missing")); }
        cleanup_snapshot_import(directory,path,true)?;
        return Ok(None);
    }
    if journal.phase=="prepared" { return Err(FormatError::new(StableError::Integrity,path,"snapshot generation exists before materialization completed")); }
    let manifest=if has_manifest {
        let manifest_path=path.join(MANIFEST_FILE);
        Manifest::decode(&read_bounded_at(directory,MANIFEST_FILE,1024*1024,&manifest_path)?,&manifest_path)?
    } else {
        validate_retained_root(directory,path)?;
        let mut manifest=Manifest::new(requirements); manifest.state_root=journal.root.clone(); install_atomic_at(directory,MANIFEST_FILE,&manifest.encode(),path)?; manifest
    };
    if manifest.generation!=0 || manifest.parent_generation.is_some() || manifest.state_root!=journal.root { return Err(FormatError::new(StableError::Integrity,path,"manifest does not match snapshot import journal")); }
    manifest.validate(requirements,path)?;
    directory.sync().map_err(|error|io_error(path,error))?;
    cleanup_snapshot_import(directory,path,false)?;
    Ok(Some(manifest))
}

fn cleanup_snapshot_import(directory:&SecureDir,path:&Path,remove_staging:bool)->FormatResult<()> {
    if remove_staging && directory.contains(SNAPSHOT_IMPORT_STAGING.as_ref()).map_err(|error|io_error(path,error))? { directory.remove_tree(SNAPSHOT_IMPORT_STAGING.as_ref()).map_err(|error|io_error(&path.join(SNAPSHOT_IMPORT_STAGING),error))?; }
    match directory.remove_file(SNAPSHOT_IMPORT_JOURNAL.as_ref()) { Ok(())=>{}, Err(error) if error.kind()==io::ErrorKind::NotFound=>{}, Err(error)=>return Err(io_error(&path.join(SNAPSHOT_IMPORT_JOURNAL),error)) }
    directory.sync().map_err(|error|io_error(path,error))
}

fn encode_snapshot_journal(journal:&SnapshotImportJournal)->Vec<u8> {
    let mut body=format!("TRON-RUST-STORAGE-SNAPSHOT-IMPORT\nbackend={}\nbackend_format={}\ngenesis={}\nnetwork={}\nphase={}\nroot={}\nschema_version={}\n",escape(&journal.backend),escape(&journal.backend_format),escape(&journal.identity.genesis),escape(&journal.identity.network),journal.phase,escape(&journal.root),journal.schema_version).into_bytes();
    let checksum=crc32(&body); body.extend_from_slice(format!("checksum={checksum:08x}\n").as_bytes()); body
}

fn decode_snapshot_journal(bytes:&[u8],path:&Path)->FormatResult<SnapshotImportJournal> {
    let text=std::str::from_utf8(bytes).map_err(|_|FormatError::new(StableError::PartialMigration,path,"snapshot import journal is not UTF-8"))?;
    let split=text.rfind("checksum=").ok_or_else(||FormatError::new(StableError::PartialMigration,path,"snapshot import journal checksum missing"))?;
    let (body,checksum_line)=text.split_at(split);
    let claimed=checksum_line.strip_prefix("checksum=").and_then(|value|value.strip_suffix('\n')).and_then(|value|u32::from_str_radix(value,16).ok()).ok_or_else(||FormatError::new(StableError::PartialMigration,path,"invalid snapshot import journal checksum"))?;
    if crc32(body.as_bytes())!=claimed { return Err(FormatError::new(StableError::Integrity,path,"snapshot import journal checksum mismatch")); }
    let mut lines=body.lines(); if lines.next()!=Some("TRON-RUST-STORAGE-SNAPSHOT-IMPORT") { return Err(FormatError::new(StableError::PartialMigration,path,"invalid snapshot import journal magic")); }
    let mut fields=BTreeMap::new(); for line in lines { let (key,value)=line.split_once('=').ok_or_else(||FormatError::new(StableError::PartialMigration,path,"malformed snapshot import journal"))?; if fields.insert(key,value).is_some(){return Err(FormatError::new(StableError::PartialMigration,path,"duplicate snapshot import journal field"));} }
    let expected=["backend","backend_format","genesis","network","phase","root","schema_version"];
    if fields.len()!=expected.len() || fields.keys().copied().ne(expected) { return Err(FormatError::new(StableError::PartialMigration,path,"invalid snapshot import journal field set")); }
    let phase=fields["phase"]; if phase!="prepared" && phase!="ready" && phase!="published" { return Err(FormatError::new(StableError::PartialMigration,path,"invalid snapshot import phase")); }
    let value=|key:&str|unescape(fields[key]).ok_or_else(||FormatError::new(StableError::PartialMigration,path,format!("invalid {key} escaping")));
    Ok(SnapshotImportJournal { identity:StorageIdentity { network:value("network")?, genesis:value("genesis")? }, schema_version:fields["schema_version"].parse().map_err(|_|FormatError::new(StableError::PartialMigration,path,"invalid schema_version"))?, backend:value("backend")?, backend_format:value("backend_format")?, root:value("root")?, phase:phase.into() })
}

fn migration_edge(manifest: &Manifest, target_schema: u32) -> Option<&'static MigrationEdge> {
    MIGRATION_EDGES.iter().find(|edge| {
        edge.source_schema == manifest.schema_version
            && edge.target_schema == target_schema
            && edge.backend == manifest.backend
            && edge.source_format == manifest.backend_format
    })
}

fn encode_initialization_journal(phase: InitializationPhase) -> Vec<u8> {
    let mut body = format!("{INITIALIZATION_MAGIC}\nversion={INITIALIZATION_VERSION}\nphase={}\n", phase.as_str()).into_bytes();
    let checksum = crc32(&body);
    body.extend_from_slice(format!("checksum={checksum:08x}\n").as_bytes());
    body
}

fn decode_initialization_journal(bytes: &[u8], path: &Path) -> FormatResult<InitializationPhase> {
    let text = std::str::from_utf8(bytes).map_err(|_| FormatError::new(StableError::Integrity, path, "initialization journal is not UTF-8"))?;
    let lines = text.strip_suffix('\n').ok_or_else(|| FormatError::new(StableError::Integrity, path, "initialization journal is not canonical"))?.split('\n').collect::<Vec<_>>();
    if lines.len() != 4 || lines[0] != INITIALIZATION_MAGIC || lines[1] != format!("version={INITIALIZATION_VERSION}") || !lines[2].starts_with("phase=") || !lines[3].starts_with("checksum=") {
        return Err(FormatError::new(StableError::Integrity, path, "initialization journal is malformed"));
    }
    let phase = match &lines[2][6..] {
        "journal" => InitializationPhase::Journal,
        "generation" => InitializationPhase::Generation,
        "manifest" => InitializationPhase::Manifest,
        _ => return Err(FormatError::new(StableError::Integrity, path, "initialization journal phase is unknown")),
    };
    if encode_initialization_journal(phase) != bytes {
        return Err(FormatError::new(StableError::Integrity, path, "initialization journal checksum or encoding is not canonical"));
    }
    Ok(phase)
}

fn initialization_state(directory: &SecureDir, path: &Path, entries: &[(std::ffi::OsString, fs::FileType)]) -> FormatResult<InitializationState> {
    let journal_path = path.join(INITIALIZATION_JOURNAL);
    if !entries.iter().any(|(name, kind)| name == INITIALIZATION_JOURNAL && kind.is_file()) {
        return Err(FormatError::new(StableError::Integrity, &journal_path, "initialization journal is not a regular file"));
    }
    let phase = decode_initialization_journal(&read_bounded_at(directory, INITIALIZATION_JOURNAL, 4096, &journal_path)?, &journal_path)?;
    let mut generation = false;
    let mut manifest_final = false;
    let mut manifest_temporary = false;
    for (name, kind) in entries {
        let text = name.to_string_lossy();
        if text == MIGRATION_LOCK || text == INITIALIZATION_JOURNAL { continue; }
        if text == "generation-0" && kind.is_dir() && !generation { generation = true; continue; }
        if text == MANIFEST_FILE && kind.is_file() && !manifest_final { manifest_final = true; continue; }
        if text.starts_with(".tron-storage.manifest.") && text.ends_with(".tmp") && kind.is_file() && !manifest_temporary { manifest_temporary = true; continue; }
        return Err(FormatError::new(StableError::AmbiguousNonempty, path, format!("initialization journal is mixed with unexpected entry {text}")));
    }
    let allowed = match phase {
        InitializationPhase::Journal => !manifest_temporary && !manifest_final,
        InitializationPhase::Generation => generation && !(manifest_temporary && manifest_final),
        InitializationPhase::Manifest => generation && manifest_final && !manifest_temporary,
    };
    if !allowed || (manifest_temporary || manifest_final) && !generation {
        return Err(FormatError::new(StableError::Integrity, path, "initialization remnants do not match the journal phase"));
    }
    Ok(InitializationState { manifest_temporary, manifest_final })
}

fn write_initialization_journal(directory: &SecureDir, path: &Path, phase: InitializationPhase, create_new: bool) -> FormatResult<()> {
    let journal_path = path.join(INITIALIZATION_JOURNAL);
    let mut journal = if create_new {
        directory.create_new(INITIALIZATION_JOURNAL.as_ref())
    } else {
        directory.truncate_existing(INITIALIZATION_JOURNAL.as_ref())
    }.map_err(|error| io_error(&journal_path, error))?;
    journal.write_all(&encode_initialization_journal(phase)).map_err(|error| io_error(&journal_path, error))?;
    journal.sync_all().map_err(|error| io_error(&journal_path, error))?;
    directory.sync().map_err(|error| io_error(path, error))
}

fn remove_initialization_manifest_temporaries(directory: &SecureDir, path: &Path) -> FormatResult<()> {
    for (name, kind) in directory.entries().map_err(|error| io_error(path, error))? {
        let text = name.to_string_lossy();
        if text.starts_with(".tron-storage.manifest.") && text.ends_with(".tmp") && kind.is_file() {
            directory.remove_file(&name).map_err(|error| io_error(&path.join(&name), error))?;
        }
    }
    directory.sync().map_err(|error| io_error(path, error))
}

fn cleanup_initialization(directory: &SecureDir, path: &Path) -> FormatResult<()> {
    remove_initialization_manifest_temporaries(directory, path)?;
    if directory.entries().map_err(|error|io_error(path,error))?.iter().any(|(name,_)|name==INITIALIZATION_JOURNAL) {
        directory.remove_file(INITIALIZATION_JOURNAL.as_ref()).map_err(|error|io_error(&path.join(INITIALIZATION_JOURNAL),error))?;
    }
    directory.sync().map_err(|error|io_error(path,error))
}


fn acquire_storage_lock_at(directory:&SecureDir,path:&Path)->FormatResult<MigrationLock> {
    let lock_path=path.join(MIGRATION_LOCK);
    let lock=directory.lock_exclusive(MIGRATION_LOCK.as_ref()).map_err(|error| {
        if error.kind()==io::ErrorKind::WouldBlock { FormatError::new(StableError::Locked,&lock_path,"storage is already open or mutating") } else { io_error(&lock_path,error) }
    })?;
    Ok(MigrationLock { _lock:lock })
}

fn acquire_storage_shared_lock_at(directory: &SecureDir, path: &Path) -> FormatResult<File> {
    let lock_path = path.join(MIGRATION_LOCK);
    let lock = directory.open_file(MIGRATION_LOCK.as_ref(), true, true).map_err(|error| io_error(&lock_path, error))?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockShared).map_err(|error| {
        let error: io::Error = error.into();
        if error.kind() == io::ErrorKind::WouldBlock {
            FormatError::new(StableError::ConcurrentOpen, &lock_path, "storage is exclusively open or mutating")
        } else {
            io_error(&lock_path, error)
        }
    })?;
    Ok(lock)
}

fn validate_resync_manifest(manifest: &Manifest, identity: &StorageIdentity, path: &Path) -> FormatResult<()> {
    if manifest.network != identity.network {
        return Err(FormatError::new(StableError::WrongNetwork, path, "network identity mismatch"));
    }
    if manifest.genesis != identity.genesis {
        return Err(FormatError::new(StableError::WrongGenesis, path, "genesis identity mismatch"));
    }
    if manifest.state != ManifestState::Clean {
        return Err(FormatError::new(StableError::Integrity, path, "manifest is dirty"));
    }
    Ok(())
}

fn encode_journal(journal: &MigrationJournal) -> Vec<u8> {
    let mut body = format!(
        "TRON-RUST-STORAGE-MIGRATION\nfrom={}\nto={}\nsource_schema={}\ntarget_schema={}\nphase={}\nroot={}\n",
        journal.from,
        journal.to,
        journal.source_schema,
        journal.target_schema,
        journal.phase,
        escape(&journal.root),
    ).into_bytes();
    let checksum = crc32(&body);
    body.extend_from_slice(format!("checksum={checksum:08x}\n").as_bytes());
    body
}

fn decode_journal_at(directory: &SecureDir, root_path: &Path) -> FormatResult<MigrationJournal> {
    let journal_path=root_path.join(MIGRATION_JOURNAL);
    let bytes = read_bounded_at(directory, MIGRATION_JOURNAL, 4096, &journal_path)?;
    let path=&journal_path;
    let text = std::str::from_utf8(&bytes).map_err(|_| FormatError::new(StableError::PartialMigration,path,"migration journal is not UTF-8"))?;
    let split = text.rfind("checksum=").ok_or_else(|| FormatError::new(StableError::PartialMigration,path,"migration journal checksum missing"))?;
    let (body, checksum_line) = text.split_at(split);
    let claimed = checksum_line.strip_prefix("checksum=").and_then(|value|value.strip_suffix('\n')).and_then(|value|u32::from_str_radix(value,16).ok())
        .ok_or_else(||FormatError::new(StableError::PartialMigration,path,"invalid migration journal checksum"))?;
    if crc32(body.as_bytes()) != claimed { return Err(FormatError::new(StableError::Integrity,path,"migration journal checksum mismatch")); }
    let mut lines=body.lines();
    if lines.next()!=Some("TRON-RUST-STORAGE-MIGRATION") { return Err(FormatError::new(StableError::PartialMigration,path,"invalid migration journal magic")); }
    let mut fields=BTreeMap::new();
    for line in lines { let (key,value)=line.split_once('=').ok_or_else(||FormatError::new(StableError::PartialMigration,path,"malformed migration journal"))?; if fields.insert(key,value).is_some(){return Err(FormatError::new(StableError::PartialMigration,path,"duplicate migration journal field"));} }
    let expected=["from","phase","root","source_schema","target_schema","to"];
    if fields.len()!=expected.len() || fields.keys().copied().ne(expected) { return Err(FormatError::new(StableError::PartialMigration,path,"invalid migration journal field set")); }
    let parse_u64=|key:&str| fields[key].parse::<u64>().map_err(|_|FormatError::new(StableError::PartialMigration,path,format!("invalid {key}")));
    let parse_u32=|key:&str| fields[key].parse::<u32>().map_err(|_|FormatError::new(StableError::PartialMigration,path,format!("invalid {key}")));
    let phase=fields["phase"];
    if phase!="prepared" && phase!="ready" { return Err(FormatError::new(StableError::PartialMigration,path,"invalid migration phase")); }
    Ok(MigrationJournal { from:parse_u64("from")?, to:parse_u64("to")?, source_schema:parse_u32("source_schema")?, target_schema:parse_u32("target_schema")?, phase:phase.into(), root:unescape(fields["root"]).ok_or_else(||FormatError::new(StableError::PartialMigration,path,"invalid journal root escaping"))? })
}

fn validate_retained_root_before_publication(directory: &SecureDir, path: &Path, journal: &MigrationJournal) -> FormatResult<()> {
    if let Err(identity_error) = validate_retained_root(directory, path) {
        return match rollback_unpublished_migration_at(directory, path, journal) {
            Ok(()) => Err(identity_error),
            Err(cleanup_error) => Err(FormatError::new(
                StableError::ConcurrentOpen,
                path,
                format!("{}; retained-root rollback failed: {}", identity_error.detail, cleanup_error.detail),
            )),
        };
    }
    Ok(())
}

fn rollback_unpublished_migration_at(directory: &SecureDir, path: &Path, journal: &MigrationJournal) -> FormatResult<()> {
    for candidate in [format!(".migration-{}",journal.to),format!("generation-{}",journal.to)] {
        if directory.contains(candidate.as_ref()).map_err(|error|io_error(path,error))? {
            directory.remove_tree(candidate.as_ref()).map_err(|error|io_error(&path.join(&candidate),error))?;
        }
    }
    cleanup_migration_at(directory,path,journal)
}

fn cleanup_migration_at(directory: &SecureDir, path: &Path, journal: &MigrationJournal) -> FormatResult<()> {
    for name in [MIGRATION_JOURNAL.to_string(),format!("manifest-generation-{}.backup",journal.from)] {
        match directory.remove_file(name.as_ref()) { Ok(()) => {}, Err(error) if error.kind()==io::ErrorKind::NotFound => {}, Err(error)=>return Err(io_error(&path.join(name),error)) }
    }
    directory.sync().map_err(|error|io_error(path,error))
}
pub(crate) fn open_manifest_at(directory:&SecureDir,path:&Path,requirements:&OpenRequirements)->FormatResult<Manifest> {
    let manifest_path=path.join(MANIFEST_FILE);
    let manifest=Manifest::decode(&read_bounded_at(directory,MANIFEST_FILE,1024*1024,&manifest_path)?,&manifest_path)?;
    manifest.validate(requirements,path)?;
    Ok(manifest)
}

fn validate_retained_root(directory:&SecureDir,path:&Path)->FormatResult<()> {
    directory.validate_path_identity().map_err(|error|FormatError::new(StableError::ConcurrentOpen,path,error.to_string()))
}
fn read_bounded_at(directory:&SecureDir,name:&str,max:usize,display:&Path)->FormatResult<Vec<u8>> {
    let mut file=directory.open_file(name.as_ref(),false,false).map_err(|error|io_error(display,error))?;
    let len=file.metadata().map_err(|error|io_error(display,error))?.len();
    if len>max as u64{return Err(FormatError::new(StableError::ManifestCorrupt,display,"file exceeds bound"));}
    read_capped(&mut file,max,display,StableError::ManifestCorrupt)
}
fn read_capped(file:&mut File,max:usize,display:&Path,category:StableError)->FormatResult<Vec<u8>> {
    let limit=max.checked_add(1).ok_or_else(||FormatError::new(category,display,"read bound is invalid"))?;
    let mut reader=file.take(limit as u64);
    let mut value=Vec::with_capacity(limit.min(8192));
    let mut chunk=[0u8;8192];
    loop {
        let read=reader.read(&mut chunk).map_err(|error|io_error(display,error))?;
        if read==0{break;}
        value.try_reserve(read).map_err(|error|FormatError::new(category,display,error.to_string()))?;
        value.extend_from_slice(&chunk[..read]);
    }
    if value.len()>max{return Err(FormatError::new(category,display,"file exceeds bound"));}
    Ok(value)
}
fn reader_metadata(file:&File,path:&Path)->FormatResult<fs::Metadata>{file.metadata().map_err(|error|io_error(path,error))}
fn write_sync_at(directory:&SecureDir,name:&std::ffi::OsStr,bytes:&[u8],create_new:bool,path:&Path)->FormatResult<()> {
    let mut file=if create_new { directory.create_new(name) } else { directory.truncate_existing(name) }.map_err(|error|io_error(path,error))?;
    file.write_all(bytes).map_err(|error|io_error(path,error))?;
    file.sync_all().map_err(|error|io_error(path,error))
}
fn install_atomic_at(directory:&SecureDir,name:&str,bytes:&[u8],display:&Path)->FormatResult<()> {
    let (temporary,mut file)=directory.temp_file(name).map_err(|error|io_error(display,error))?;
    let result=(|| { file.write_all(bytes).map_err(|error|io_error(display,error))?; file.sync_all().map_err(|error|io_error(display,error))?; directory.rename(&temporary,name.as_ref()).map_err(|error|io_error(display,error))?; directory.sync().map_err(|error|io_error(display,error)) })();
    if result.is_err(){let _=directory.remove_file(&temporary);} result
}
fn required<'a>(fields:&'a BTreeMap<&str,String>,key:&str,path:&Path)->FormatResult<&'a str>{fields.get(key).map(String::as_str).ok_or_else(||FormatError::new(StableError::ManifestCorrupt,path,format!("missing {key}")))}
fn number<T:std::str::FromStr>(fields:&BTreeMap<&str,String>,key:&str,path:&Path)->FormatResult<T>{required(fields,key,path)?.parse().map_err(|_|FormatError::new(StableError::ManifestCorrupt,path,format!("invalid {key}")))}
fn escape(value:&str)->String{let mut out=String::new();for b in value.bytes(){match b{b'%'|b'\n'|b'\r'|b'='|b','=>out.push_str(&format!("%{b:02X}")),_=>out.push(b as char)}}out}
fn unescape(value:&str)->Option<String>{let bytes=value.as_bytes();let mut out=Vec::new();let mut i=0;while i<bytes.len(){if bytes[i]==b'%' {if i+2>=bytes.len(){return None} let h=std::str::from_utf8(&bytes[i+1..i+3]).ok()?;out.push(u8::from_str_radix(h,16).ok()?);i+=3}else{out.push(bytes[i]);i+=1}}String::from_utf8(out).ok()}
fn crc32(bytes:&[u8])->u32{let mut crc=!0u32;for &byte in bytes{crc^=u32::from(byte);for _ in 0..8{crc=(crc>>1)^if crc&1==1{0xedb8_8320}else{0};}}!crc}
