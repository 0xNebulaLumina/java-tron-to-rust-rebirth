//! Rust-owned storage-format and backend ownership boundary.
//!
//! `rustlog-v1` is the initial, intentionally Java-incompatible backend. It keeps the
//! live index in a `BTreeMap`, persists atomic batches in a checksummed append-only WAL,
//! and periodically replaces it with an atomically installed compact snapshot.

pub mod format;
#[cfg(unix)]
mod fs;
pub use format::*;

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::ffi::OsString;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::{Bound, RangeBounds};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use crate::fs::{sync_tree_dir, KernelLock, SecureDir};

use tron_primitives::{compare_price_key, MARKET_PAIR_LENGTH};

const WAL_NAME: &str = "rustlog-v1.wal";
const SNAPSHOT_NAME: &str = "rustlog-v1.snapshot";
const LOCK_NAME: &str = MIGRATION_LOCK;
const WAL_MAGIC: &[u8; 8] = b"RLOGWAL1";
const SNAPSHOT_MAGIC: &[u8; 8] = b"RLOGSNP1";
const FRAME_HEADER_LEN: usize = 8;
const SNAPSHOT_HEADER_LEN: usize = 20;

pub type KeyValue = (Vec<u8>, Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustLogOptions {
    pub sync_on_write: bool,
    pub compact_after_bytes: u64,
    pub max_snapshot_bytes: usize,
    pub max_snapshot_entries: usize,
    pub max_frame_bytes: usize,
    pub max_key_bytes: usize,
    pub max_value_bytes: usize,
    pub max_batch_operations: usize,
}

impl Default for RustLogOptions {
    fn default() -> Self {
        Self {
            sync_on_write: false,
            compact_after_bytes: 16 * 1024 * 1024,
            max_frame_bytes: 64 * 1024 * 1024,
            max_snapshot_bytes: 1024 * 1024 * 1024,
            max_snapshot_entries: 1_000_000,
            max_key_bytes: 16 * 1024 * 1024,
            max_value_bytes: 64 * 1024 * 1024,
            max_batch_operations: 1_000_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Corruption {
    InvalidWalHeader,
    InvalidSnapshotHeader,
    WalChecksum { offset: u64 },
    SnapshotChecksum,
    FrameTooLarge { actual: u64, maximum: usize },
    KeyTooLarge { actual: u64, maximum: usize },
    ValueTooLarge { actual: u64, maximum: usize },
    TooManyOperations { actual: u64, maximum: usize },
    TooManySnapshotEntries { actual: u64, maximum: usize },
    InvalidOperation { tag: u8 },
    InvalidEncoding,
    TrailingSnapshotBytes,
}

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    DiskFull { path: Option<PathBuf> },
    Permission { path: Option<PathBuf> },
    ConcurrentOpen { path: Option<PathBuf> },
    Locked { path: PathBuf },
    Corruption(Corruption),
    InvalidOptions(&'static str),
    InvalidCheckpoint { path: PathBuf },
    MarketKey { actual: usize },
    Format(FormatError),
    Poisoned,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "storage I/O error: {error}"),
            Self::DiskFull { path } => write!(f, "storage disk is full{}", display_optional_path(path)),
            Self::Permission { path } => write!(f, "storage permission denied{}", display_optional_path(path)),
            Self::ConcurrentOpen { path } => write!(f, "storage concurrent open{}", display_optional_path(path)),
            Self::Locked { path } => write!(f, "storage is exclusively locked: {}", path.display()),
            Self::Corruption(error) => write!(f, "rustlog-v1 corruption: {error:?}"),
            Self::InvalidOptions(message) => write!(f, "invalid rustlog-v1 options: {message}"),
            Self::InvalidCheckpoint { path } => {
                write!(f, "checkpoint destination is not empty: {}", path.display())
            }
            Self::Format(error) => write!(f, "storage format error: {error}"),
            Self::Poisoned => write!(f, "storage handle is poisoned after WAL rollback failure"),
            Self::MarketKey { actual } => write!(f, "market key is shorter than 54 bytes: {actual}"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Format(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::PermissionDenied => Self::Permission { path: None },
            io::ErrorKind::StorageFull => Self::DiskFull { path: None },
            io::ErrorKind::WouldBlock => Self::ConcurrentOpen { path: None },
            _ if error.raw_os_error() == Some(28) => Self::DiskFull { path: None },
            _ => Self::Io(error),
        }
    }
}

impl From<FormatError> for StorageError {
    fn from(error: FormatError) -> Self {
        match error.category {
            StableError::Permission => Self::Permission { path: Some(error.path) },
            StableError::DiskFull => Self::DiskFull { path: Some(error.path) },
            StableError::ConcurrentOpen => Self::ConcurrentOpen { path: Some(error.path) },
            StableError::Locked => Self::Locked { path: error.path },
            _ => Self::Format(error),
        }
    }
}

fn display_optional_path(path: &Option<PathBuf>) -> String {
    path.as_ref().map_or_else(String::new, |path| format!(": {}", path.display()))
}

pub type Result<T, E = StorageError> = std::result::Result<T, E>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointPhase {
    Preflight,
    StagingCreated,
    SnapshotWritten,
    WalWritten,
    ManifestWritten,
    TreeSynced,
    Published,
    ParentSynced,
}

pub trait CheckpointFaultInjector {
    fn after(&self, phase: CheckpointPhase) -> io::Result<()>;
}

pub struct NoCheckpointFaults;

impl CheckpointFaultInjector for NoCheckpointFaults {
    fn after(&self, _: CheckpointPhase) -> io::Result<()> { Ok(()) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownPhase {
    WalSync,
    SnapshotSync,
    GenerationSync,
}

pub trait ShutdownFaultInjector {
    fn before(&self, phase: ShutdownPhase) -> io::Result<()>;
}

pub struct NoShutdownFaults;

impl ShutdownFaultInjector for NoShutdownFaults {
    fn before(&self, _: ShutdownPhase) -> io::Result<()> { Ok(()) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritePhase {
    Append,
    Flush,
    Sync,
    Truncate,
    RollbackSync,
    Metadata,
    Compaction,
}

pub trait WriteFaultInjector {
    fn before(&self, phase: WritePhase) -> io::Result<()>;
}

pub struct NoWriteFaults;

impl WriteFaultInjector for NoWriteFaults {
    fn before(&self, _: WritePhase) -> io::Result<()> { Ok(()) }
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchOperation {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WriteBatch {
    operations: Vec<BatchOperation>,
}

impl WriteBatch {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    #[must_use]
    pub fn len(&self) -> usize { self.operations.len() }

    #[must_use]
    pub fn is_empty(&self) -> bool { self.operations.is_empty() }

    pub fn put(&mut self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> &mut Self {
        self.operations.push(BatchOperation::Put { key: key.into(), value: value.into() });
        self
    }

    pub fn delete(&mut self, key: impl Into<Vec<u8>>) -> &mut Self {
        self.operations.push(BatchOperation::Delete { key: key.into() });
        self
    }

    #[must_use]
    pub fn operations(&self) -> &[BatchOperation] { &self.operations }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OrderedIterator {
    entries: Vec<KeyValue>,
    position: Option<usize>,
    exhausted: bool,
}

impl OrderedIterator {
    fn new(entries: Vec<KeyValue>) -> Self { Self { entries, position: None, exhausted: false } }

    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn first(&mut self) -> Option<&KeyValue> {
        self.position = (!self.entries.is_empty()).then_some(0);
        self.exhausted = self.position.is_none();
        self.current()
    }

    pub fn last(&mut self) -> Option<&KeyValue> {
        self.position = self.entries.len().checked_sub(1);
        self.exhausted = self.position.is_none();
        self.current()
    }

    pub fn seek(&mut self, target: &[u8]) -> Option<&KeyValue> {
        let index = self.entries.partition_point(|(key, _)| key.as_slice() < target);
        self.position = (index < self.entries.len()).then_some(index);
        self.exhausted = self.position.is_none();
        self.current()
    }

    #[must_use]
    pub fn current(&self) -> Option<&KeyValue> { self.position.and_then(|index| self.entries.get(index)) }

    pub fn next_entry(&mut self) -> Option<&KeyValue> {
        if self.exhausted {
            return None;
        }
        self.position = match self.position {
            Some(index) if index + 1 < self.entries.len() => Some(index + 1),
            None if !self.entries.is_empty() => Some(0),
            _ => {
                self.exhausted = true;
                None
            }
        };
        self.current()
    }

    pub fn previous_entry(&mut self) -> Option<&KeyValue> {
        if self.exhausted {
            return None;
        }
        self.position = match self.position {
            Some(index) if index > 0 => Some(index - 1),
            None if !self.entries.is_empty() => self.entries.len().checked_sub(1),
            _ => {
                self.exhausted = true;
                None
            }
        };
        self.current()
    }

    #[must_use]
    pub fn into_entries(self) -> Vec<KeyValue> { self.entries }
}
#[derive(Clone, Debug)]
pub struct StorageManager {
    requirements: OpenRequirements,
    options: RustLogOptions,
}

impl StorageManager {
    #[must_use]
    pub fn new(requirements: OpenRequirements) -> Self {
        Self { requirements, options: RustLogOptions::default() }
    }

    pub fn with_options(requirements: OpenRequirements, options: RustLogOptions) -> Result<Self> {
        validate_options(&options)?;
        Ok(Self { requirements, options })
    }

    pub fn open_store(&self, path: impl AsRef<Path>) -> Result<RustLog> {
        let path = path.as_ref();
        format::classify_open_read_only(path, &self.requirements)?;
        let root = SecureDir::open_or_create(path).map_err(StorageError::from)?;
        let root_lock = root.lock_root_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                StorageError::Locked { path: path.join(LOCK_NAME) }
            } else {
                StorageError::from(error)
            }
        })?;
        root.validate_path_identity().map_err(|_| StorageError::ConcurrentOpen { path: Some(path.to_path_buf()) })?;
        root.reject_symlink_entries().map_err(StorageError::from)?;

        let classification = format::classify_at(&root, path)?;
        if let DirectoryClassification::Java { ref marker } = classification {
            return Err(FormatError::new(StableError::JavaFormat, path, marker.clone()).into());
        }
        let lock = root.finish_exclusive_lock(root_lock, LOCK_NAME.as_ref()).map_err(StorageError::from)?;
        let manifest = match classification {
            DirectoryClassification::Empty | DirectoryClassification::InitializingEmpty => {
                format::initialize_empty_at(&root, path, &self.requirements)?
            }
            DirectoryClassification::Rust(manifest) => {
                manifest.validate(&self.requirements, path)?;
                manifest
            }
            DirectoryClassification::Java { .. } => unreachable!("Java storage returned before lock-file creation"),
            DirectoryClassification::Missing => {
                return Err(FormatError::new(StableError::ManifestMissing, path, "retained storage directory is missing").into());
            }
        };
        root.validate_path_identity().map_err(|_| StorageError::ConcurrentOpen { path: Some(path.to_path_buf()) })?;
        let current = format::open_manifest_at(&root, path, &self.requirements)?;
        if current != manifest {
            return Err(StorageError::ConcurrentOpen { path: Some(path.to_path_buf()) });
        }
        let generation_name = format!("generation-{}", current.generation);
        let generation = root.open_child(generation_name.as_ref()).map_err(StorageError::from)?;
        generation.reject_symlink_entries().map_err(StorageError::from)?;
        RustLog::open_generation(generation, self.options.clone(), lock, self.requirements.clone())
    }

    pub fn close(&self, store: RustLog) -> Result<()> { store.close() }
}

pub struct RustLog {
    directory: SecureDir,
    options: RustLogOptions,
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
    wal: File,
    lock: Option<KernelLock>,
    requirements: OpenRequirements,
    closed: bool,
    poisoned: bool,
    maintenance_error: Option<StorageError>,
}

impl RustLog {
    fn open_generation(directory: SecureDir, options: RustLogOptions, lock: KernelLock, requirements: OpenRequirements) -> Result<Self> {
        validate_options(&options)?;
        let mut entries = load_snapshot(&directory, &options)?;
        let mut wal = directory.open_file(WAL_NAME.as_ref(), true, true)?;
        recover_wal(&mut wal, &mut entries, &options)?;
        wal.seek(SeekFrom::End(0))?;
        Ok(Self {
            directory,
            options,
            entries,
            wal,
            lock: Some(lock),
            requirements,
            closed: false,
            poisoned: false,
            maintenance_error: None,
        })
    }

    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> { self.entries.get(key).cloned() }

    #[must_use]
    pub fn contains_key(&self, key: &[u8]) -> bool { self.entries.contains_key(key) }

    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn put(&mut self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Result<()> {
        let mut batch = WriteBatch::new();
        batch.put(key, value);
        self.write(batch)
    }

    pub fn delete(&mut self, key: impl Into<Vec<u8>>) -> Result<()> {
        let mut batch = WriteBatch::new();
        batch.delete(key);
        self.write(batch)
    }

    pub fn write(&mut self, batch: WriteBatch) -> Result<()> {
        self.write_with_faults(batch, &NoWriteFaults)
    }

    pub fn write_with_faults(&mut self, batch: WriteBatch, faults: &dyn WriteFaultInjector) -> Result<()> {
        self.ensure_usable()?;
        if batch.is_empty() {
            return Ok(());
        }
        let payload = encode_batch(&batch, &self.options)?;
        let frame = encode_frame(&payload)?;
        let wal_offset = self.wal.seek(SeekFrom::End(0))?;
        let append_result = (|| -> Result<()> {
            faults.before(WritePhase::Append)?;
            self.wal.write_all(&frame)?;
            faults.before(WritePhase::Flush)?;
            self.wal.flush()?;
            if self.options.sync_on_write {
                faults.before(WritePhase::Sync)?;
                self.wal.sync_data()?;
            }
            Ok(())
        })();
        if let Err(error) = append_result {
            if self.rollback_wal(wal_offset, faults).is_err() {
                self.poisoned = true;
                return Err(StorageError::Poisoned);
            }
            return Err(error);
        }

        apply_batch(&mut self.entries, batch.operations());
        let wal_length = match faults
            .before(WritePhase::Metadata)
            .and_then(|()| self.wal.metadata())
        {
            Ok(metadata) => Some(metadata.len()),
            Err(error) => {
                self.maintenance_error = Some(error.into());
                None
            }
        };
        let should_compact = self.options.compact_after_bytes > 0
            && wal_length.is_some_and(|length| length >= self.options.compact_after_bytes);
        if should_compact {
            let result = faults
                .before(WritePhase::Compaction)
                .map_err(StorageError::from)
                .and_then(|()| self.compact());
            if let Err(error) = result {
                self.maintenance_error = Some(error);
            }
        }
        Ok(())
    }

    fn rollback_wal(&mut self, wal_offset: u64, faults: &dyn WriteFaultInjector) -> Result<()> {
        faults.before(WritePhase::Truncate)?;
        self.wal.set_len(wal_offset)?;
        self.wal.seek(SeekFrom::Start(wal_offset))?;
        faults.before(WritePhase::RollbackSync)?;
        self.wal.sync_data()?;
        Ok(())
    }

    fn ensure_usable(&self) -> Result<()> {
        if self.poisoned { Err(StorageError::Poisoned) } else { Ok(()) }
    }

    #[must_use]
    pub fn is_poisoned(&self) -> bool { self.poisoned }

    #[must_use]
    pub fn maintenance_error(&self) -> Option<&StorageError> { self.maintenance_error.as_ref() }

    pub fn take_maintenance_error(&mut self) -> Option<StorageError> { self.maintenance_error.take() }

    #[must_use]
    pub fn iterator(&self) -> OrderedIterator {
        OrderedIterator::new(self.entries.iter().map(clone_entry).collect())
    }

    #[must_use]
    pub fn seek(&self, target: &[u8], limit: usize) -> Vec<KeyValue> {
        if limit == 0 {
            return Vec::new();
        }
        self.entries
            .range::<[u8], _>((Bound::Included(target), Bound::Unbounded))
            .take(limit)
            .map(clone_entry)
            .collect()
    }

    #[must_use]
    pub fn range<R>(&self, range: R, limit: usize) -> Vec<KeyValue>
    where
        R: RangeBounds<Vec<u8>>,
    {
        if limit == 0 {
            return Vec::new();
        }
        self.entries.range(range).take(limit).map(clone_entry).collect()
    }

    #[must_use]
    pub fn range_bytes(
        &self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        limit: usize,
    ) -> Vec<KeyValue> {
        if limit == 0 {
            return Vec::new();
        }
        self.entries.range::<[u8], _>((start, end)).take(limit).map(clone_entry).collect()
    }

    #[must_use]
    pub fn prefix(&self, prefix: &[u8], limit: usize) -> Vec<KeyValue> {
        if limit == 0 {
            return Vec::new();
        }
        self.entries
            .range::<[u8], _>((Bound::Included(prefix), Bound::Unbounded))
            .take_while(|(key, _)| key.starts_with(prefix))
            .take(limit)
            .map(clone_entry)
            .collect()
    }

    pub fn flush(&mut self) -> Result<()> {
        self.ensure_usable()?;
        self.wal.flush()?;
        self.wal.sync_all()?;
        self.directory.sync().map_err(StorageError::from)
    }

    pub fn close(self) -> Result<()> {
        self.close_with_faults(&NoShutdownFaults)
    }

    pub fn close_with_faults(mut self, faults: &dyn ShutdownFaultInjector) -> Result<()> {
        self.ensure_usable()?;
        self.sync_for_shutdown(faults)?;
        self.closed = true;
        Ok(())
    }

    fn sync_for_shutdown(&mut self, faults: &dyn ShutdownFaultInjector) -> Result<()> {
        self.wal.flush()?;
        faults.before(ShutdownPhase::WalSync)?;
        self.wal.sync_data()?;

        match self.directory.open_file(SNAPSHOT_NAME.as_ref(), false, false) {
            Ok(snapshot) => {
                faults.before(ShutdownPhase::SnapshotSync)?;
                snapshot.sync_data()?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        faults.before(ShutdownPhase::GenerationSync)?;
        self.directory.sync()?;
        Ok(())
    }

    pub fn compact(&mut self) -> Result<()> {
        self.ensure_usable()?;
        install_snapshot(&self.directory, &self.entries, &self.options)?;
        self.wal.set_len(0)?;
        self.wal.seek(SeekFrom::Start(0))?;
        self.wal.write_all(WAL_MAGIC)?;
        self.wal.sync_all()?;
        self.directory.sync().map_err(StorageError::from)
    }

    pub fn checkpoint(&mut self, destination: impl AsRef<Path>) -> Result<()> {
        self.checkpoint_with_faults(destination, &NoCheckpointFaults)
    }

    pub fn checkpoint_with_faults(
        &mut self,
        destination: impl AsRef<Path>,
        faults: &dyn CheckpointFaultInjector,
    ) -> Result<()> {
        self.ensure_usable()?;
        self.flush()?;
        let destination_path = destination.as_ref();
        if checkpoint_matches(destination_path, &self.requirements, &self.options, &self.entries)? {
            sync_published_checkpoint(destination_path)?;
            return Ok(());
        }
        match inspect_read_only(destination_path)? {
            DirectoryClassification::Missing | DirectoryClassification::Empty => {}
            _ => return Err(StorageError::InvalidCheckpoint { path: destination_path.to_path_buf() }),
        }
        faults.after(CheckpointPhase::Preflight)?;

        let destination_name = destination_path.file_name().ok_or_else(|| {
            StorageError::InvalidCheckpoint { path: destination_path.to_path_buf() }
        })?;
        let parent_path = destination_path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let parent = SecureDir::open_read_only(parent_path)?;
        parent.validate_path_identity().map_err(|_| StorageError::ConcurrentOpen { path: Some(parent_path.to_path_buf()) })?;
        let (staging_name, staging) = create_checkpoint_staging(&parent)?;
        let mut published = false;
        let result = (|| -> Result<()> {
            faults.after(CheckpointPhase::StagingCreated)?;
            let generation = staging.create_dir("generation-0".as_ref())?;
            install_snapshot(&generation, &self.entries, &self.options)?;
            faults.after(CheckpointPhase::SnapshotWritten)?;

            let mut checkpoint_wal = generation.create_new(WAL_NAME.as_ref())?;
            checkpoint_wal.write_all(WAL_MAGIC)?;
            checkpoint_wal.sync_all()?;
            faults.after(CheckpointPhase::WalWritten)?;

            let manifest = Manifest::new(&self.requirements);
            let mut manifest_file = staging.create_new(MANIFEST_FILE.as_ref())?;
            manifest_file.write_all(&manifest.encode())?;
            manifest_file.sync_all()?;
            faults.after(CheckpointPhase::ManifestWritten)?;

            sync_tree_dir(&staging)?;
            faults.after(CheckpointPhase::TreeSynced)?;
            drop(generation);
            drop(staging);
            parent.validate_path_identity().map_err(|_| StorageError::ConcurrentOpen { path: Some(parent_path.to_path_buf()) })?;
            parent.ensure_absent_nofollow(destination_name).map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists { StorageError::InvalidCheckpoint { path: destination_path.to_path_buf() } }
                else { StorageError::from(error) }
            })?;
            parent.rename_noreplace(&staging_name, destination_name).map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists { StorageError::InvalidCheckpoint { path: destination_path.to_path_buf() } }
                else { StorageError::from(error) }
            })?;
            published = true;
            if parent.validate_path_identity().is_err() {
                parent.remove_tree(destination_name)?;
                parent.sync()?;
                published = false;
                return Err(StorageError::ConcurrentOpen { path: Some(parent_path.to_path_buf()) });
            }
            faults.after(CheckpointPhase::Published)?;
            parent.sync()?;
            if parent.validate_path_identity().is_err() {
                parent.remove_tree(destination_name)?;
                parent.sync()?;
                published = false;
                return Err(StorageError::ConcurrentOpen { path: Some(parent_path.to_path_buf()) });
            }
            faults.after(CheckpointPhase::ParentSynced)?;
            Ok(())
        })();
        if result.is_err() && !published {
            let _ = parent.remove_tree(&staging_name);
            let _ = parent.sync();
        }
        result
    }


    pub fn market_ordered(&self, pair: Option<&[u8]>, limit: usize) -> Result<Vec<KeyValue>> {
        market_order(self.entries.iter().map(clone_entry), pair, limit)
    }

    pub fn market_seek(&self, target: &[u8], limit: usize) -> Result<Vec<KeyValue>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        validate_market_key(target)?;
        let pair = &target[..MARKET_PAIR_LENGTH];
        let ordered = self.market_ordered(Some(pair), usize::MAX)?;
        let index = ordered.partition_point(|(key, _)| market_total_cmp(key, target) == Ordering::Less);
        Ok(ordered.into_iter().skip(index).take(limit).collect())
    }
}
fn checkpoint_matches(
    path: &Path,
    requirements: &OpenRequirements,
    options: &RustLogOptions,
    expected: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<bool> {
    let manifest = match inspect_read_only(path)? {
        DirectoryClassification::Rust(manifest) => manifest,
        _ => return Ok(false),
    };
    if manifest != Manifest::new(requirements) {
        return Ok(false);
    }
    let root = SecureDir::open(path)?;
    root.reject_symlink_entries()?;
    let generation = root.open_child("generation-0".as_ref())?;
    generation.reject_symlink_entries()?;
    if load_snapshot(&generation, options)? != *expected {
        return Ok(false);
    }
    let mut wal = generation.open_file(WAL_NAME.as_ref(), false, false)?;
    if wal.metadata()?.len() != WAL_MAGIC.len() as u64 {
        return Ok(false);
    }
    let mut magic = [0u8; WAL_MAGIC.len()];
    wal.read_exact(&mut magic)?;
    Ok(&magic == WAL_MAGIC)
}

fn sync_published_checkpoint(path: &Path) -> Result<()> {
    let root = SecureDir::open(path)?;
    sync_tree_dir(&root)?;
    let parent_path = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
    SecureDir::open_read_only(parent_path)?.sync()?;
    Ok(())
}

fn create_checkpoint_staging(parent: &SecureDir) -> Result<(OsString, SecureDir)> {
    let mut random = File::open("/dev/urandom")?;
    for _ in 0..128 {
        let mut bytes = [0u8; 24];
        random.read_exact(&mut bytes)?;
        let suffix: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let name = OsString::from(format!(".tron-storage-checkpoint.{suffix}.tmp"));
        match parent.create_dir(&name) {
            Ok(directory) => return Ok((name, directory)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "unable to allocate checkpoint staging directory").into())
}

impl Drop for RustLog {
    fn drop(&mut self) {
        if self.poisoned {
            if let Some(lock) = self.lock.take() {
                std::mem::forget(lock);
            }
            return;
        }
        if !self.closed {
            let _ = self.sync_for_shutdown(&NoShutdownFaults);
        }
    }
}

pub fn market_order(
    entries: impl IntoIterator<Item = KeyValue>,
    pair: Option<&[u8]>,
    limit: usize,
) -> Result<Vec<KeyValue>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    if let Some(pair) = pair {
        if pair.len() != MARKET_PAIR_LENGTH {
            return Err(StorageError::MarketKey { actual: pair.len() });
        }
    }
    let mut entries = entries
        .into_iter()
        .filter(|(key, _)| pair.is_none_or(|pair| key.starts_with(pair)))
        .collect::<Vec<_>>();
    for (key, _) in &entries {
        validate_market_key(key)?;
    }
    entries.sort_by(|(left, _), (right, _)| market_total_cmp(left, right));
    entries.truncate(limit);
    Ok(entries)
}

#[must_use]
pub fn market_total_cmp(left: &[u8], right: &[u8]) -> Ordering {
    match compare_price_key(left, right) {
        Ok(Ordering::Equal) => left.cmp(right),
        Ok(ordering) => ordering,
        Err(_) => left.cmp(right),
    }
}

fn validate_market_key(key: &[u8]) -> Result<()> {
    compare_price_key(key, key)
        .map(|_| ())
        .map_err(|_| StorageError::MarketKey { actual: key.len() })
}

fn validate_options(options: &RustLogOptions) -> Result<()> {
    if options.max_frame_bytes == 0 {
        return Err(StorageError::InvalidOptions("max_frame_bytes must be nonzero"));
    }
    if options.max_snapshot_bytes == 0 {
        return Err(StorageError::InvalidOptions("max_snapshot_bytes must be nonzero"));
    }
    if options.max_snapshot_entries == 0 {
        return Err(StorageError::InvalidOptions("max_snapshot_entries must be nonzero"));
    }
    if options.max_key_bytes == 0 {
        return Err(StorageError::InvalidOptions("max_key_bytes must be nonzero"));
    }
    if options.max_batch_operations == 0 {
        return Err(StorageError::InvalidOptions("max_batch_operations must be nonzero"));
    }
    Ok(())
}


fn clone_entry((key, value): (&Vec<u8>, &Vec<u8>)) -> KeyValue { (key.clone(), value.clone()) }

fn apply_batch(entries: &mut BTreeMap<Vec<u8>, Vec<u8>>, operations: &[BatchOperation]) {
    for operation in operations {
        match operation {
            BatchOperation::Put { key, value } => {
                entries.insert(key.clone(), value.clone());
            }
            BatchOperation::Delete { key } => {
                entries.remove(key);
            }
        }
    }
}

fn encode_batch(batch: &WriteBatch, options: &RustLogOptions) -> Result<Vec<u8>> {
    check_limit(batch.len() as u64, options.max_batch_operations, |actual, maximum| {
        Corruption::TooManyOperations { actual, maximum }
    })?;
    let mut payload = Vec::new();
    push_u32(&mut payload, batch.len())?;
    for operation in batch.operations() {
        match operation {
            BatchOperation::Put { key, value } => {
                payload.push(0);
                encode_bytes(&mut payload, key, options.max_key_bytes, true)?;
                encode_bytes(&mut payload, value, options.max_value_bytes, false)?;
            }
            BatchOperation::Delete { key } => {
                payload.push(1);
                encode_bytes(&mut payload, key, options.max_key_bytes, true)?;
            }
        }
        if payload.len() > options.max_frame_bytes {
            return Err(StorageError::Corruption(Corruption::FrameTooLarge {
                actual: payload.len() as u64,
                maximum: options.max_frame_bytes,
            }));
        }
    }
    Ok(payload)
}

fn decode_batch(payload: &[u8], options: &RustLogOptions) -> Result<WriteBatch> {
    let mut cursor = SliceCursor::new(payload);
    let count = cursor.u32()? as usize;
    check_limit(count as u64, options.max_batch_operations, |actual, maximum| {
        Corruption::TooManyOperations { actual, maximum }
    })?;
    let mut operations = Vec::with_capacity(count);
    for _ in 0..count {
        let tag = cursor.byte()?;
        let key = cursor.bytes(options.max_key_bytes, true)?;
        match tag {
            0 => operations.push(BatchOperation::Put {
                key,
                value: cursor.bytes(options.max_value_bytes, false)?,
            }),
            1 => operations.push(BatchOperation::Delete { key }),
            _ => return Err(StorageError::Corruption(Corruption::InvalidOperation { tag })),
        }
    }
    if !cursor.is_finished() {
        return Err(StorageError::Corruption(Corruption::InvalidEncoding));
    }
    Ok(WriteBatch { operations })
}

fn encode_frame(payload: &[u8]) -> Result<Vec<u8>> {
    let length = u32::try_from(payload.len())
        .map_err(|_| StorageError::Corruption(Corruption::InvalidEncoding))?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&crc32(payload).to_le_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn recover_wal(
    wal: &mut File,
    entries: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    options: &RustLogOptions,
) -> Result<()> {
    let length = wal.metadata()?.len();
    if length == 0 {
        wal.write_all(WAL_MAGIC)?;
        wal.sync_all()?;
        return Ok(());
    }
    if length < WAL_MAGIC.len() as u64 {
        wal.set_len(0)?;
        wal.write_all(WAL_MAGIC)?;
        wal.sync_all()?;
        return Ok(());
    }
    wal.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 8];
    wal.read_exact(&mut magic)?;
    if &magic != WAL_MAGIC {
        return Err(StorageError::Corruption(Corruption::InvalidWalHeader));
    }
    let mut offset = WAL_MAGIC.len() as u64;
    loop {
        let frame_start = offset;
        let mut header = [0u8; FRAME_HEADER_LEN];
        match read_complete(wal, &mut header)? {
            ReadState::Eof => break,
            ReadState::Incomplete => {
                wal.set_len(frame_start)?;
                break;
            }
            ReadState::Complete => {}
        }
        offset += FRAME_HEADER_LEN as u64;
        let frame_length = u32::from_le_bytes(header[..4].try_into().expect("four-byte slice")) as usize;
        if frame_length > options.max_frame_bytes {
            return Err(StorageError::Corruption(Corruption::FrameTooLarge {
                actual: frame_length as u64,
                maximum: options.max_frame_bytes,
            }));
        }
        let expected_crc = u32::from_le_bytes(header[4..].try_into().expect("four-byte slice"));
        let mut payload = vec![0; frame_length];
        match read_complete(wal, &mut payload)? {
            ReadState::Complete => {}
            ReadState::Eof | ReadState::Incomplete => {
                wal.set_len(frame_start)?;
                break;
            }
        }
        if crc32(&payload) != expected_crc {
            return Err(StorageError::Corruption(Corruption::WalChecksum { offset: frame_start }));
        }
        let batch = decode_batch(&payload, options)?;
        apply_batch(entries, batch.operations());
        offset += frame_length as u64;
    }
    wal.seek(SeekFrom::End(0))?;
    Ok(())
}

fn load_snapshot(directory: &SecureDir, options: &RustLogOptions) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut file = match directory.open_file(SNAPSHOT_NAME.as_ref(), false, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(error.into()),
    };
    let length = file.metadata()?.len();
    if length < SNAPSHOT_HEADER_LEN as u64 {
        return Err(StorageError::Corruption(Corruption::InvalidSnapshotHeader));
    }
    let mut header = [0u8; SNAPSHOT_HEADER_LEN];
    file.read_exact(&mut header)?;
    if &header[..8] != SNAPSHOT_MAGIC {
        return Err(StorageError::Corruption(Corruption::InvalidSnapshotHeader));
    }
    let payload_length = u64::from_le_bytes(header[8..16].try_into().expect("eight-byte slice"));
    if payload_length > options.max_snapshot_bytes as u64 {
        return Err(StorageError::Corruption(Corruption::FrameTooLarge { actual: payload_length, maximum: options.max_snapshot_bytes }));
    }
    if length != SNAPSHOT_HEADER_LEN as u64 + payload_length {
        return Err(StorageError::Corruption(Corruption::TrailingSnapshotBytes));
    }
    let expected_crc = u32::from_le_bytes(header[16..20].try_into().expect("four-byte slice"));
    let mut payload = vec![0; payload_length as usize];
    file.read_exact(&mut payload)?;
    if crc32(&payload) != expected_crc { return Err(StorageError::Corruption(Corruption::SnapshotChecksum)); }
    decode_snapshot(&payload, options)
}

fn install_snapshot(directory: &SecureDir, entries: &BTreeMap<Vec<u8>, Vec<u8>>, options: &RustLogOptions) -> Result<()> {
    let payload = encode_snapshot(entries, options)?;
    let (temporary, mut file) = directory.temp_file(SNAPSHOT_NAME)?;
    let write_result = (|| -> Result<()> {
        file.write_all(SNAPSHOT_MAGIC)?;
        file.write_all(&(payload.len() as u64).to_le_bytes())?;
        file.write_all(&crc32(&payload).to_le_bytes())?;
        file.write_all(&payload)?;
        file.sync_all()?;
        directory.rename(&temporary, SNAPSHOT_NAME.as_ref())?;
        directory.sync()?;
        Ok(())
    })();
    if write_result.is_err() { let _ = directory.remove_file(&temporary); }
    write_result
}

fn encode_snapshot(entries: &BTreeMap<Vec<u8>, Vec<u8>>, options: &RustLogOptions) -> Result<Vec<u8>> {
    check_limit(entries.len() as u64, options.max_snapshot_entries, |actual, maximum| {
        Corruption::TooManySnapshotEntries { actual, maximum }
    })?;
    let mut payload = Vec::new();
    push_u32(&mut payload, entries.len())?;
    for (key, value) in entries {
        encode_bytes(&mut payload, key, options.max_key_bytes, true)?;
        encode_bytes(&mut payload, value, options.max_value_bytes, false)?;
        if payload.len() > options.max_snapshot_bytes {
            return Err(StorageError::Corruption(Corruption::FrameTooLarge {
                actual: payload.len() as u64,
                maximum: options.max_snapshot_bytes,
            }));
        }
    }
    Ok(payload)
}

fn decode_snapshot(payload: &[u8], options: &RustLogOptions) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut cursor = SliceCursor::new(payload);
    let count = cursor.u32()? as usize;
    check_limit(count as u64, options.max_snapshot_entries, |actual, maximum| {
        Corruption::TooManySnapshotEntries { actual, maximum }
    })?;
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let key = cursor.bytes(options.max_key_bytes, true)?;
        let value = cursor.bytes(options.max_value_bytes, false)?;
        entries.insert(key, value);
    }
    if !cursor.is_finished() {
        return Err(StorageError::Corruption(Corruption::InvalidEncoding));
    }
    Ok(entries)
}

fn encode_bytes(output: &mut Vec<u8>, bytes: &[u8], maximum: usize, key: bool) -> Result<()> {
    if bytes.len() > maximum {
        let corruption = if key {
            Corruption::KeyTooLarge { actual: bytes.len() as u64, maximum }
        } else {
            Corruption::ValueTooLarge { actual: bytes.len() as u64, maximum }
        };
        return Err(StorageError::Corruption(corruption));
    }
    push_u32(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn push_u32(output: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u32::try_from(value)
        .map_err(|_| StorageError::Corruption(Corruption::InvalidEncoding))?;
    output.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn check_limit(
    actual: u64,
    maximum: usize,
    error: impl FnOnce(u64, usize) -> Corruption,
) -> Result<()> {
    if actual > maximum as u64 {
        return Err(StorageError::Corruption(error(actual, maximum)));
    }
    Ok(())
}

enum ReadState {
    Complete,
    Eof,
    Incomplete,
}

fn read_complete(reader: &mut File, buffer: &mut [u8]) -> io::Result<ReadState> {
    let mut read = 0;
    while read < buffer.len() {
        match reader.read(&mut buffer[read..])? {
            0 if read == 0 => return Ok(ReadState::Eof),
            0 => return Ok(ReadState::Incomplete),
            count => read += count,
        }
    }
    Ok(ReadState::Complete)
}

struct SliceCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> SliceCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, position: 0 } }

    fn byte(&mut self) -> Result<u8> {
        let byte = self.bytes.get(self.position).copied().ok_or_else(invalid_encoding)?;
        self.position += 1;
        Ok(byte)
    }

    fn u32(&mut self) -> Result<u32> {
        let end = self.position.checked_add(4).ok_or_else(invalid_encoding)?;
        let bytes = self.bytes.get(self.position..end).ok_or_else(invalid_encoding)?;
        self.position = end;
        Ok(u32::from_le_bytes(bytes.try_into().expect("four-byte slice")))
    }

    fn bytes(&mut self, maximum: usize, key: bool) -> Result<Vec<u8>> {
        let length = self.u32()? as usize;
        if length > maximum {
            let corruption = if key {
                Corruption::KeyTooLarge { actual: length as u64, maximum }
            } else {
                Corruption::ValueTooLarge { actual: length as u64, maximum }
            };
            return Err(StorageError::Corruption(corruption));
        }
        let end = self.position.checked_add(length).ok_or_else(invalid_encoding)?;
        let bytes = self.bytes.get(self.position..end).ok_or_else(invalid_encoding)?;
        self.position = end;
        Ok(bytes.to_vec())
    }

    fn is_finished(&self) -> bool { self.position == self.bytes.len() }
}

fn invalid_encoding() -> StorageError { StorageError::Corruption(Corruption::InvalidEncoding) }


fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
