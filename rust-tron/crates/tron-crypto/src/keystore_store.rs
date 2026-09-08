use crate::keystore::{self, KeystoreRandom, ScryptProfile, WalletFile};
use crate::{CryptoEngine, PrivateKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const MAX_KEYSTORE_JSON_BYTES: usize = 8 * 1024;
pub const WINDOWS_PERMISSION_LIMITATION: &str = "descriptor-anchored keystore publication is unsupported on Windows";
#[cfg(unix)]
const REPLACE_JOURNAL: &str = ".keystore-replace.journal";
#[cfg(unix)]
const REPLACE_JOURNAL_TEMP: &str = ".keystore-replace.journal.tmp";
#[cfg(unix)]
const MAX_REPLACE_JOURNAL_BYTES: usize = 4096;

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReplacePhase { Prepared, BackedUp, Published }

#[cfg(unix)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplaceJournalPayload {
    version: u8,
    phase: ReplacePhase,
    destination: String,
    temporary: String,
    backup: String,
    original_sha256: Option<String>,
    original_address: Option<String>,
    original_identity: Option<FileIdentity>,
    replacement_sha256: String,
    replacement_address: String,
    replacement_identity: FileIdentity,
}

#[cfg(unix)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplaceJournal { payload: ReplaceJournalPayload, checksum: String }

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreWarning {
    DirectLoadFollowedSymlink { path: PathBuf },
    SkippedSymlink { path: PathBuf },
    SkippedNonRegular { path: PathBuf },
    SkippedOversized { path: PathBuf },
    SkippedUnreadable { path: PathBuf },
    SkippedInvalidJson { path: PathBuf },
    WindowsPermissionsBestEffort { path: PathBuf },
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicWriteHookStage { BeforeValidation, DestinationValidated, BackupRenamed, Published, BeforeCleanup }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicWriteStage { Serialization, Write, FileFsync, Rename, DirectoryFsync, RollbackRename, RollbackFsync }

#[derive(Debug)]
pub enum StoreError {
    Io { operation: &'static str, path: PathBuf, source: std::io::Error },
    AtomicWriteFailure(AtomicWriteStage),
    RollbackFailed { operation: Box<StoreError>, rollback: Box<StoreError> },
    Keystore(keystore::KeystoreError),
    SymlinkRefused(PathBuf),
    NotRegularFile(PathBuf),
    Oversized { path: PathBuf, max: usize },
    InsecurePermissions { path: PathBuf, mode: u32 },
    WrongOwner { path: PathBuf, owner: u32, effective_user: u32 },
    InsecureDirectory { path: PathBuf, owner: u32, effective_user: u32, mode: u32 },
    TargetExists(PathBuf),
    DuplicateAddress { address: String, files: Vec<PathBuf> },
    AddressNotFound(String),
    InodeChanged(PathBuf),
    ParentSymlink(PathBuf),
    ParentNotDirectory(PathBuf),
    ParentChanged(PathBuf),
    RecoveryRefused { path: PathBuf, reason: &'static str },
    UnsupportedPlatform(&'static str),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, path, source } => write!(f, "{operation} {}: {source}", path.display()),
            Self::AtomicWriteFailure(stage) => write!(f, "injected atomic-write failure at {stage:?}"),
            Self::RollbackFailed { operation, rollback } => write!(f, "{operation}; rollback also failed: {rollback}"),
            Self::Keystore(error) => write!(f, "{error}"),
            Self::SymlinkRefused(path) => write!(f, "refusing to mutate or scan symbolic link: {}", path.display()),
            Self::NotRegularFile(path) => write!(f, "not a regular file: {}", path.display()),
            Self::Oversized { path, max } => write!(f, "keystore exceeds {max} bytes: {}", path.display()),
            Self::InsecurePermissions { path, mode } => write!(f, "keystore must be POSIX 0600 (found {:04o}): {}", mode & 0o7777, path.display()),
            Self::WrongOwner { path, owner, effective_user } => write!(f, "keystore owner {owner} does not match effective user {effective_user}: {}", path.display()),
            Self::InsecureDirectory { path, owner, effective_user, mode } => write!(f, "keystore directory must be owned by effective user {effective_user} with POSIX mode 0700 (found owner {owner}, mode {:04o}): {}", mode & 0o7777, path.display()),
            Self::TargetExists(path) => write!(f, "target exists; overwrite was not requested: {}", path.display()),
            Self::DuplicateAddress { address, files } => write!(f, "multiple keystores found for address {address}: {}", files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")),
            Self::AddressNotFound(address) => write!(f, "no keystore found for address: {address}"),
            Self::InodeChanged(path) => write!(f, "keystore changed after selection; refusing mutation: {}", path.display()),
            Self::ParentSymlink(path) => write!(f, "refusing symbolic-link keystore parent: {}", path.display()),
            Self::ParentNotDirectory(path) => write!(f, "keystore parent component is not a directory: {}", path.display()),
            Self::ParentChanged(path) => write!(f, "keystore parent changed after verification: {}", path.display()),
            Self::RecoveryRefused { path, reason } => write!(f, "refusing unsafe keystore recovery at {}: {reason}", path.display()),
            Self::UnsupportedPlatform(reason) => write!(f, "unsupported keystore persistence platform: {reason}"),
        }
    }
}
impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Io { source, .. } => Some(source), Self::Keystore(error) => Some(error), Self::RollbackFailed { operation, .. } => Some(operation), _ => None }
    }
}
impl From<keystore::KeystoreError> for StoreError { fn from(value: keystore::KeystoreError) -> Self { Self::Keystore(value) } }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedKeystore { pub address: String, pub path: PathBuf }
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListReport { pub keystores: Vec<ListedKeystore>, pub warnings: Vec<StoreWarning> }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadResult { pub wallet: WalletFile, pub warnings: Vec<StoreWarning> }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredKeystore { pub wallet: WalletFile, pub path: PathBuf }


pub fn new_keystore<R: KeystoreRandom>(destination: impl AsRef<Path>, password: &str, key: &PrivateKey, checksum_engine: CryptoEngine, overwrite: bool, random: &mut R) -> Result<WalletFile, StoreError> {
    new_keystore_reporting(destination, password, key, checksum_engine, overwrite, random, |_| {}).map(|stored| stored.wallet)
}
pub fn new_keystore_reporting<R: KeystoreRandom, W: FnMut(&StoreWarning)>(destination: impl AsRef<Path>, password: &str, key: &PrivateKey, checksum_engine: CryptoEngine, overwrite: bool, random: &mut R, mut warning_sink: W) -> Result<StoredKeystore, StoreError> {
    let destination = destination.as_ref();
    let parent_path = destination.parent().unwrap_or_else(|| Path::new("."));
    let parent = AnchoredDirectory::open(parent_path, true)?;
    let wallet = keystore::create_with_random(password, key, checksum_engine, ScryptProfile::Standard, random)?;
    for warning in atomic_write_wallet_in_parent(&wallet, destination, overwrite, random, None, None, |_| {}, &parent)? { warning_sink(&warning); }
    Ok(StoredKeystore { wallet, path: destination.to_owned() })
}
pub fn import_keystore<R: KeystoreRandom>(directory: impl AsRef<Path>, destination: impl AsRef<Path>, password: &str, key: &PrivateKey, checksum_engine: CryptoEngine, force_duplicate: bool, overwrite: bool, random: &mut R) -> Result<WalletFile, StoreError> {
    import_keystore_reporting(directory, destination, password, key, checksum_engine, force_duplicate, overwrite, random, |_| {}).map(|stored| stored.wallet)
}
pub fn import_keystore_reporting<R: KeystoreRandom, W: FnMut(&StoreWarning)>(directory: impl AsRef<Path>, destination: impl AsRef<Path>, password: &str, key: &PrivateKey, checksum_engine: CryptoEngine, force_duplicate: bool, overwrite: bool, random: &mut R, mut warning_sink: W) -> Result<StoredKeystore, StoreError> {
    let directory = directory.as_ref();
    let destination = destination.as_ref();
    let parent_path = destination.parent().unwrap_or_else(|| Path::new("."));
    if parent_path != directory { return Err(StoreError::ParentChanged(parent_path.to_owned())); }
    let parent = AnchoredDirectory::open(directory, true)?;
    let candidate = keystore::create_with_random(password, key, checksum_engine, ScryptProfile::Standard, random)?;
    let address = candidate.address.as_deref().unwrap_or_default();
    let matches = matching_address_paths_locked_reporting(&parent, directory, address, &mut warning_sink)?;
    if !force_duplicate && !matches.is_empty() { return Err(StoreError::DuplicateAddress { address: address.to_owned(), files: matches }); }
    for warning in atomic_write_wallet_in_parent(&candidate, destination, overwrite, random, None, None, |_| {}, &parent)? { warning_sink(&warning); }
    Ok(StoredKeystore { wallet: candidate, path: destination.to_owned() })
}
pub fn list_keystores(directory: impl AsRef<Path>) -> Result<ListReport, StoreError> {
    let directory = directory.as_ref();
    let parent = match AnchoredDirectory::open(directory, false) {
        Ok(parent) => parent,
        Err(StoreError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => return Ok(ListReport::default()),
        Err(error) => return Err(error),
    };
    list_keystores_locked(&parent, directory)
}
pub fn load_keystore_direct(path: impl AsRef<Path>) -> Result<LoadResult, StoreError> {
    #[cfg(unix)]
    { return load_keystore_direct_unix(path.as_ref()); }
    #[cfg(not(unix))]
    { let _ = path; Err(StoreError::UnsupportedPlatform(WINDOWS_PERMISSION_LIMITATION)) }
}
pub fn update_keystore<R: KeystoreRandom>(directory: impl AsRef<Path>, address: &str, old_password: &str, new_password: &str, key_engine: CryptoEngine, checksum_engine: CryptoEngine, random: &mut R) -> Result<PathBuf, StoreError> {
    update_keystore_reporting(directory, address, old_password, new_password, key_engine, checksum_engine, random, |_| {}).map(|stored| stored.path)
}
pub fn update_keystore_reporting<R: KeystoreRandom, W: FnMut(&StoreWarning)>(directory: impl AsRef<Path>, address: &str, old_password: &str, new_password: &str, key_engine: CryptoEngine, checksum_engine: CryptoEngine, random: &mut R, mut warning_sink: W) -> Result<StoredKeystore, StoreError> {
    let directory = directory.as_ref();
    let parent = match AnchoredDirectory::open(directory, false) {
        Ok(parent) => parent,
        Err(StoreError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => return Err(StoreError::AddressNotFound(address.to_owned())),
        Err(StoreError::ParentNotDirectory(_)) => return Err(StoreError::AddressNotFound(address.to_owned())),
        Err(error) => return Err(error),
    };
    let matches = matching_mutation_candidates_locked_reporting(&parent, directory, address, &mut warning_sink)?;
    let selected = match matches.as_slice() {
        [] => return Err(StoreError::AddressNotFound(address.to_owned())),
        [selected] => selected,
        _ => return Err(StoreError::DuplicateAddress { address: address.to_owned(), files: matches.iter().map(|item| item.path.clone()).collect() }),
    };
    let key = keystore::decrypt(old_password, &selected.wallet, key_engine, checksum_engine)?;
    let replacement = keystore::create_with_random(new_password, &key, checksum_engine, ScryptProfile::Standard, random)?;
    for warning in atomic_write_wallet_in_parent(&replacement, &selected.path, true, random, Some(selected.identity), None, |_| {}, &parent)? { warning_sink(&warning); }
    Ok(StoredKeystore { wallet: replacement, path: selected.path.clone() })
}

pub fn atomic_write_wallet(wallet: &WalletFile, destination: &Path, overwrite: bool) -> Result<Vec<StoreWarning>, StoreError> {
    atomic_write_wallet_with_random(wallet, destination, overwrite, &mut rand_core::OsRng)
}

pub fn atomic_write_wallet_with_random<R: KeystoreRandom>(wallet: &WalletFile, destination: &Path, overwrite: bool, random_source: &mut R) -> Result<Vec<StoreWarning>, StoreError> {
    atomic_write_wallet_with_stage_hook(wallet, destination, overwrite, random_source, |_| {})
}

#[doc(hidden)]
pub fn atomic_write_wallet_with_hook<R: KeystoreRandom, H: FnOnce()>(wallet: &WalletFile, destination: &Path, overwrite: bool, random_source: &mut R, pre_publish_hook: H) -> Result<Vec<StoreWarning>, StoreError> {
    let mut hook = Some(pre_publish_hook);
    atomic_write_wallet_with_stage_hook(wallet, destination, overwrite, random_source, |stage| {
        if stage == AtomicWriteHookStage::BeforeValidation { if let Some(hook) = hook.take() { hook(); } }
    })
}

#[doc(hidden)]
pub fn atomic_write_wallet_with_stage_hook<R: KeystoreRandom, H: FnMut(AtomicWriteHookStage)>(wallet: &WalletFile, destination: &Path, overwrite: bool, random_source: &mut R, hook: H) -> Result<Vec<StoreWarning>, StoreError> {
    atomic_write_wallet_expected(wallet, destination, overwrite, random_source, None, None, None, hook)
}

pub fn atomic_write_wallet_with_failure<R: KeystoreRandom>(wallet: &WalletFile, destination: &Path, overwrite: bool, random_source: &mut R, failure: AtomicWriteStage) -> Result<Vec<StoreWarning>, StoreError> {
    atomic_write_wallet_expected(wallet, destination, overwrite, random_source, None, None, Some(failure), |_| {})
}

fn atomic_write_wallet_expected<R: KeystoreRandom, H: FnMut(AtomicWriteHookStage)>(wallet: &WalletFile, destination: &Path, overwrite: bool, random_source: &mut R, expected_identity: Option<FileIdentity>, expected_parent_identity: Option<FileIdentity>, failure: Option<AtomicWriteStage>, hook: H) -> Result<Vec<StoreWarning>, StoreError> {
    #[cfg(not(unix))]
    {
        let _ = (wallet, destination, overwrite, random_source, expected_identity, expected_parent_identity, failure, hook);
        return Err(StoreError::UnsupportedPlatform(WINDOWS_PERMISSION_LIMITATION));
    }
    #[cfg(unix)]
    atomic_write_wallet_expected_unix(wallet, destination, overwrite, random_source, expected_identity, expected_parent_identity, failure, hook)
}

#[cfg(unix)]
fn atomic_write_wallet_expected_unix<R: KeystoreRandom, H: FnMut(AtomicWriteHookStage)>(wallet: &WalletFile, destination: &Path, overwrite: bool, random_source: &mut R, expected_identity: Option<FileIdentity>, expected_parent_identity: Option<FileIdentity>, failure: Option<AtomicWriteStage>, hook: H) -> Result<Vec<StoreWarning>, StoreError> {
    let parent_path = destination.parent().unwrap_or_else(|| Path::new("."));
    let parent = AnchoredDirectory::open(parent_path, true)?;
    if expected_parent_identity.is_some_and(|expected| parent.identity != expected) { return Err(StoreError::ParentChanged(parent_path.to_owned())); }
    atomic_write_wallet_in_parent(wallet, destination, overwrite, random_source, expected_identity, failure, hook, &parent)
}

#[cfg(unix)]
fn atomic_write_wallet_in_parent<R: KeystoreRandom, H: FnMut(AtomicWriteHookStage)>(wallet: &WalletFile, destination: &Path, overwrite: bool, random_source: &mut R, expected_identity: Option<FileIdentity>, failure: Option<AtomicWriteStage>, mut hook: H, parent: &AnchoredDirectory) -> Result<Vec<StoreWarning>, StoreError> {
    use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags, linkat, openat, renameat, renameat_with, unlinkat};
    let parent_path = destination.parent().unwrap_or_else(|| Path::new("."));
    let name = destination.file_name().ok_or_else(|| StoreError::ParentNotDirectory(destination.to_owned()))?;
    let destination_name = name.to_str().ok_or_else(|| recovery_error(destination.to_owned(), "replacement destination name is not UTF-8"))?;
    let mut random = [0u8; 8];
    random_source.fill_bytes(&mut random);
    let suffix = format!("{:016x}", u64::from_le_bytes(random));
    let temp_name = format!(".keystore-{suffix}.tmp");
    let backup_name = format!(".keystore-{suffix}.backup");
    let temp_path = parent_path.join(&temp_name);
    let mut published = false;
    let mut backed_up = false;
    let mut journaled = false;
    let mut journal_payload = None;
    let result: Result<(), StoreError> = (|| {
        let temp_fd = openat(&parent.file, &temp_name, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::RUSR | Mode::WUSR)
            .map_err(|e| io_error("create temporary keystore", &temp_path, e.into()))?;
        let mut file = File::from(temp_fd);
        fail_atomic_write(failure, AtomicWriteStage::Serialization)?;
        let json = Zeroizing::new(wallet.to_json()?);
        fail_atomic_write(failure, AtomicWriteStage::Write)?;
        file.write_all(json.as_bytes()).map_err(|e| io_error("write temporary keystore", &temp_path, e))?;
        fail_atomic_write(failure, AtomicWriteStage::FileFsync)?;
        file.sync_all().map_err(|e| io_error("fsync temporary keystore", &temp_path, e))?;
        let replacement_identity = file_identity(&file.metadata().map_err(|e| io_error("inspect temporary keystore", &temp_path, e))?);
        drop(file);
        fail_atomic_write(failure, AtomicWriteStage::Rename)?;
        hook(AtomicWriteHookStage::BeforeValidation);
        if parent.reverify(parent_path).is_err() { return Err(StoreError::ParentChanged(parent_path.to_owned())); }
        if overwrite {
            let original = if reject_at_symlink_or_nonregular(&parent.file, name, destination, expected_identity)? {
                let (text, original_wallet, identity) = read_validated_wallet_at(parent, name, destination)?;
                Some((sha256_hex(text.as_bytes()), original_wallet.address.expect("validated discovery wallet"), identity))
            } else { None };
            hook(AtomicWriteHookStage::DestinationValidated);
            let replacement_address = wallet.address.as_deref().filter(|_| wallet.is_valid_discovery_file())
                .ok_or_else(|| recovery_error(destination.to_owned(), "replacement has no canonical wallet identity"))?;
            let payload = ReplaceJournalPayload {
                version: 1,
                phase: ReplacePhase::Prepared,
                destination: destination_name.to_owned(),
                temporary: temp_name.clone(),
                backup: backup_name.clone(),
                original_sha256: original.as_ref().map(|value| value.0.clone()),
                original_address: original.as_ref().map(|value| value.1.clone()),
                original_identity: original.as_ref().map(|value| value.2),
                replacement_sha256: sha256_hex(json.as_bytes()),
                replacement_address: replacement_address.to_owned(),
                replacement_identity,
            };
            write_replace_journal(parent, parent_path, payload.clone())?;
            journal_payload = Some(payload);
            journaled = true;
            if original.is_some() {
                renameat(&parent.file, name, &parent.file, &backup_name).map_err(|e| io_error("backup replaced keystore", destination, e.into()))?;
                backed_up = true;
                if parent.validate_recovery_wallet(&backup_name, &parent_path.join(&backup_name), journal_payload.as_ref().expect("journal payload recorded"))? != RecoveryWallet::Original {
                    return Err(recovery_error(parent_path.join(&backup_name), "backup inode does not match validated destination"));
                }
                parent.file.sync_all().map_err(|e| io_error("fsync keystore backup transition", parent_path, e))?;
                hook(AtomicWriteHookStage::BackupRenamed);
            }
            renameat(&parent.file, &temp_name, &parent.file, name).map_err(|e| io_error("replace keystore", destination, e.into()))?;
            published = true;
            hook(AtomicWriteHookStage::Published);
        } else {
            match renameat_with(&parent.file, &temp_name, &parent.file, name, RenameFlags::NOREPLACE) {
                Ok(()) => published = true,
                Err(rustix::io::Errno::EXIST) => return Err(StoreError::TargetExists(destination.to_owned())),
                Err(error) if matches!(error, rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP) => match linkat(&parent.file, &temp_name, &parent.file, name, AtFlags::empty()) {
                    Ok(()) => { unlinkat(&parent.file, &temp_name, AtFlags::empty()).map_err(|e| io_error("remove published temporary keystore", &temp_path, e.into()))?; published = true; }
                    Err(rustix::io::Errno::EXIST) => return Err(StoreError::TargetExists(destination.to_owned())),
                    Err(error) => return Err(io_error("publish keystore without replacement", destination, error.into())),
                },
                Err(error) => return Err(io_error("publish keystore without replacement", destination, error.into())),
            }
        }
        if parent.reverify(parent_path).is_err() { return Err(StoreError::ParentChanged(parent_path.to_owned())); }
        if matches!(failure, Some(AtomicWriteStage::RollbackRename | AtomicWriteStage::RollbackFsync)) {
            return Err(StoreError::AtomicWriteFailure(AtomicWriteStage::DirectoryFsync));
        }
        fail_atomic_write(failure, AtomicWriteStage::DirectoryFsync)?;
        parent.file.sync_all().map_err(|e| io_error("fsync keystore publication", parent_path, e))?;
        let (written, written_wallet, written_identity) = read_validated_wallet_at(parent, name, destination)?;
        if sha256_hex(written.as_bytes()) != sha256_hex(json.as_bytes()) || written_wallet.address != wallet.address || written_identity != replacement_identity {
            return Err(recovery_error(destination.to_owned(), "published keystore identity changed"));
        }
        // Publication is now durable and identity-validated. Cleanup failures must retain it
        // rather than deleting the only remaining discoverable wallet.
        published = false;
        hook(AtomicWriteHookStage::BeforeCleanup);
        if backed_up {
            parent.retain_recovery_artifact(&backup_name, &parent_path.join(&backup_name), journal_payload.as_ref().expect("journal payload recorded"), RecoveryWallet::Original)?;
            backed_up = false;
            parent.file.sync_all().map_err(|e| io_error("fsync keystore backup retention", parent_path, e))?;
        }
        if journaled {
            unlinkat(&parent.file, REPLACE_JOURNAL, AtFlags::empty()).map_err(|e| io_error("remove keystore replacement journal", &parent_path.join(REPLACE_JOURNAL), e.into()))?;
            journaled = false;
            parent.file.sync_all().map_err(|e| io_error("fsync keystore journal cleanup", parent_path, e))?;
        }
        Ok(())
    })();
    if let Err(operation) = result {
        if journaled {
            let payload = journal_payload.as_ref().expect("journal payload recorded before publication");
            if let Err(rollback) = parent.rollback_replacement(parent_path, payload, failure) {
                return Err(StoreError::RollbackFailed { operation: Box::new(operation), rollback: Box::new(rollback) });
            }
        } else {
            if let Err(error) = unlinkat(&parent.file, &temp_name, AtFlags::empty()) {
                return Err(StoreError::RollbackFailed {
                    operation: Box::new(operation),
                    rollback: Box::new(io_error("remove failed temporary keystore", &temp_path, error.into())),
                });
            }
            if let Err(error) = parent.file.sync_all() {
                return Err(StoreError::RollbackFailed {
                    operation: Box::new(operation),
                    rollback: Box::new(io_error("fsync failed temporary cleanup", parent_path, error)),
                });
            }
        }
        return Err(operation);
    }
    Ok(Vec::new())
}

#[cfg(unix)]
struct AnchoredDirectory { file: File, identity: FileIdentity }

#[cfg(unix)]
impl AnchoredDirectory {
    fn open(path: &Path, create: bool) -> Result<Self, StoreError> {
        let parent = Self::open_with_lock(path, create, true)?;
        parent.recover_replacement(path)?;
        Ok(parent)
    }

    fn open_with_lock(path: &Path, create: bool, lock: bool) -> Result<Self, StoreError> {
        use rustix::fs::{Mode, OFlags, open, openat, mkdirat};
        use std::path::Component;
        let mut current_path = PathBuf::new();
        let mut file = if path.is_absolute() {
            current_path.push("/");
            File::from(open("/", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|e| io_error("open keystore parent root", Path::new("/"), e.into()))?)
        } else {
            current_path.push(".");
            File::from(open(".", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|e| io_error("open keystore parent root", Path::new("."), e.into()))?)
        };
        for component in path.components() {
            let Component::Normal(name) = component else {
                if matches!(component, Component::RootDir | Component::CurDir) { continue; }
                return Err(StoreError::ParentNotDirectory(path.to_owned()));
            };
            current_path.push(name);
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let next = match openat(&file, name, flags, Mode::empty()) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) if create => {
                    match mkdirat(&file, name, Mode::RWXU) { Ok(()) | Err(rustix::io::Errno::EXIST) => {}, Err(e) => return Err(io_error("create keystore parent", &current_path, e.into())) }
                    openat(&file, name, flags, Mode::empty()).map_err(|e| parent_open_error(&file, name, &current_path, e))?
                }
                Err(error) => return Err(parent_open_error(&file, name, &current_path, error)),
            };
            let next_file = File::from(next);
            if !next_file.metadata().map_err(|e| io_error("inspect keystore parent component", &current_path, e))?.is_dir() {
                return Err(StoreError::ParentNotDirectory(current_path));
            }
            file = next_file;
        }
        let metadata = file.metadata().map_err(|e| io_error("inspect keystore parent", path, e))?;
        check_directory_security(path, &metadata)?;
        if lock {
            rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive).map_err(|error| io_error("lock keystore directory", path, error.into()))?;
        }
        let identity = file_identity(&metadata);
        Ok(Self { file, identity })
    }
    fn reverify(&self, path: &Path) -> Result<(), StoreError> {
        let reopened = Self::open_with_lock(path, false, false).map_err(|error| match error {
            StoreError::ParentNotDirectory(path) => StoreError::ParentNotDirectory(path),
            _ => StoreError::ParentChanged(path.to_owned()),
        })?;
        if reopened.identity != self.identity { return Err(StoreError::ParentChanged(path.to_owned())); }
        Ok(())
    }
    fn rollback_replacement(&self, directory: &Path, p: &ReplaceJournalPayload, failure: Option<AtomicWriteStage>) -> Result<(), StoreError> {
        use rustix::fs::{AtFlags, RenameFlags, renameat_with, unlinkat};
        let destination = directory.join(&p.destination);
        let temporary = directory.join(&p.temporary);
        let backup = directory.join(&p.backup);
        let state = (
            self.validate_recovery_wallet(&p.destination, &destination, p)?,
            self.validate_recovery_wallet(&p.temporary, &temporary, p)?,
            self.validate_recovery_wallet(&p.backup, &backup, p)?,
        );
        match state {
            (RecoveryWallet::Original, RecoveryWallet::Replacement, RecoveryWallet::Missing) => {
                self.retain_recovery_artifact(&p.temporary, &temporary, p, RecoveryWallet::Replacement)?;
            }
            (RecoveryWallet::Missing, RecoveryWallet::Replacement, RecoveryWallet::Original) => {
                fail_atomic_write(failure, AtomicWriteStage::RollbackRename)?;
                renameat_with(&self.file, &p.backup, &self.file, &p.destination, RenameFlags::NOREPLACE)
                    .map_err(|e| io_error("restore journaled keystore backup", &destination, e.into()))?;
                if self.validate_recovery_wallet(&p.destination, &destination, p)? != RecoveryWallet::Original {
                    return Err(recovery_error(destination, "restored keystore identity does not match journal"));
                }
                fail_atomic_write(failure, AtomicWriteStage::RollbackFsync)?;
                self.file.sync_all().map_err(|e| io_error("fsync restored keystore directory", directory, e))?;
                self.retain_recovery_artifact(&p.temporary, &temporary, p, RecoveryWallet::Replacement)?;
            }
            (RecoveryWallet::Replacement, RecoveryWallet::Missing, RecoveryWallet::Original) => {
                fail_atomic_write(failure, AtomicWriteStage::RollbackRename)?;
                renameat_with(&self.file, &p.backup, &self.file, &p.destination, RenameFlags::EXCHANGE)
                    .map_err(|e| io_error("exchange journaled keystore backup", &destination, e.into()))?;
                if self.validate_recovery_wallet(&p.destination, &destination, p)? != RecoveryWallet::Original
                    || self.validate_recovery_wallet(&p.backup, &backup, p)? != RecoveryWallet::Replacement {
                    return Err(recovery_error(destination, "restored keystore identities do not match journal"));
                }
                fail_atomic_write(failure, AtomicWriteStage::RollbackFsync)?;
                self.file.sync_all().map_err(|e| io_error("fsync restored keystore directory", directory, e))?;
                self.retain_recovery_artifact(&p.backup, &backup, p, RecoveryWallet::Replacement)?;
            }
            _ => return Err(recovery_error(directory.join(REPLACE_JOURNAL), "replacement artifacts changed before rollback")),
        }
        self.file.sync_all().map_err(|e| io_error("fsync rollback artifact cleanup", directory, e))?;
        unlinkat(&self.file, REPLACE_JOURNAL, AtFlags::empty()).map_err(|e| io_error("remove rolled-back keystore journal", &directory.join(REPLACE_JOURNAL), e.into()))?;
        self.file.sync_all().map_err(|e| io_error("fsync rollback journal cleanup", directory, e))
    }

}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryWallet { Missing, Original, Replacement }

#[cfg(unix)]
impl AnchoredDirectory {
    fn recover_replacement(&self, directory: &Path) -> Result<(), StoreError> {
        use rustix::fs::{AtFlags, RenameFlags, renameat_with, unlinkat};
        let stable = self.read_journal(directory, REPLACE_JOURNAL)?;
        let pending = self.read_journal(directory, REPLACE_JOURNAL_TEMP)?;
        let (journal, journal_name) = match (stable, pending) {
            (None, None) => return Ok(()),
            (Some(value), None) => (value, REPLACE_JOURNAL),
            (None, Some(value)) => (value, REPLACE_JOURNAL_TEMP),
            (Some(_), Some(_)) => return Err(recovery_error(directory.join(REPLACE_JOURNAL_TEMP), "multiple replacement journals")),
        };
        validate_journal_names(&journal.payload, directory)?;
        let p = &journal.payload;
        let destination = directory.join(&p.destination);
        let temporary = directory.join(&p.temporary);
        let backup = directory.join(&p.backup);
        let state = (
            self.validate_recovery_wallet(&p.destination, &destination, p)?,
            self.validate_recovery_wallet(&p.temporary, &temporary, p)?,
            self.validate_recovery_wallet(&p.backup, &backup, p)?,
        );
        match state {
            (RecoveryWallet::Original, RecoveryWallet::Replacement, RecoveryWallet::Missing) => self.retain_recovery_artifact(&p.temporary, &temporary, p, RecoveryWallet::Replacement)?,
            (RecoveryWallet::Missing, RecoveryWallet::Replacement, RecoveryWallet::Original) => {
                renameat_with(&self.file, &p.backup, &self.file, &p.destination, RenameFlags::NOREPLACE)
                    .map_err(|e| io_error("restore journaled keystore backup", &destination, e.into()))?;
                if self.validate_recovery_wallet(&p.destination, &destination, p)? != RecoveryWallet::Original {
                    return Err(recovery_error(destination.clone(), "restored keystore identity does not match journal"));
                }
                self.file.sync_all().map_err(|e| io_error("fsync restored keystore directory", directory, e))?;
                self.retain_recovery_artifact(&p.temporary, &temporary, p, RecoveryWallet::Replacement)?;
            }
            (RecoveryWallet::Replacement, RecoveryWallet::Missing, RecoveryWallet::Original) => self.retain_recovery_artifact(&p.backup, &backup, p, RecoveryWallet::Original)?,
            (RecoveryWallet::Replacement, RecoveryWallet::Missing, RecoveryWallet::Missing) => {}
            (RecoveryWallet::Original, RecoveryWallet::Missing, RecoveryWallet::Replacement) => self.retain_recovery_artifact(&p.backup, &backup, p, RecoveryWallet::Replacement)?,
            (RecoveryWallet::Original, RecoveryWallet::Missing, RecoveryWallet::Missing) if p.original_sha256.is_some() => {}
            (RecoveryWallet::Missing, RecoveryWallet::Replacement, RecoveryWallet::Missing) if p.original_sha256.is_none() => self.retain_recovery_artifact(&p.temporary, &temporary, p, RecoveryWallet::Replacement)?,
            _ => return Err(recovery_error(directory.join(journal_name), "replacement artifacts do not match a recoverable phase")),
        }
        self.file.sync_all().map_err(|e| io_error("fsync recovered keystore directory", directory, e))?;
        unlinkat(&self.file, journal_name, AtFlags::empty()).map_err(|e| io_error("remove recovered keystore journal", &directory.join(journal_name), e.into()))?;
        self.file.sync_all().map_err(|e| io_error("fsync keystore journal cleanup", directory, e))
    }

    fn read_journal(&self, directory: &Path, name: &str) -> Result<Option<ReplaceJournal>, StoreError> {
        use rustix::fs::{Mode, OFlags, openat};
        let path = directory.join(name);
        let fd = match openat(&self.file, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(recovery_error(path, "journal is unreadable or symbolic link")),
        };
        let file = File::from(fd);
        let metadata = file.metadata().map_err(|e| io_error("inspect keystore replacement journal", &path, e))?;
        if !metadata.is_file() { return Err(recovery_error(path, "journal is not a regular file")); }
        check_security(&path, &metadata)?;
        if metadata.len() > MAX_REPLACE_JOURNAL_BYTES as u64 { return Err(recovery_error(path, "journal exceeds size limit")); }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((MAX_REPLACE_JOURNAL_BYTES + 1) as u64).read_to_end(&mut bytes).map_err(|e| io_error("read keystore replacement journal", &path, e))?;
        if bytes.len() > MAX_REPLACE_JOURNAL_BYTES { return Err(recovery_error(path, "journal exceeds size limit")); }
        let journal: ReplaceJournal = serde_json::from_slice(&bytes).map_err(|_| recovery_error(path.clone(), "journal encoding is invalid"))?;
        let encoded = serde_json::to_vec(&journal.payload).map_err(|_| recovery_error(path.clone(), "journal payload is invalid"))?;
        if journal.payload.version != 1 || sha256_hex(&encoded) != journal.checksum { return Err(recovery_error(path, "journal checksum or version is invalid")); }
        Ok(Some(journal))
    }

    fn retain_recovery_artifact(&self, name: &str, path: &Path, journal: &ReplaceJournalPayload, expected: RecoveryWallet) -> Result<(), StoreError> {
        use rustix::fs::{RenameFlags, renameat_with};
        if self.validate_recovery_wallet(name, path, journal)? != expected {
            return Err(recovery_error(path.to_owned(), "artifact changed before retention"));
        }
        let retained_name = format!("{name}.retained");
        let retained_path = path.with_file_name(&retained_name);
        renameat_with(&self.file, name, &self.file, &retained_name, RenameFlags::NOREPLACE)
            .map_err(|e| io_error("retain keystore recovery artifact", &retained_path, e.into()))?;
        if self.validate_recovery_wallet(&retained_name, &retained_path, journal)? != expected {
            return Err(recovery_error(retained_path, "retained artifact inode does not match journal"));
        }
        Ok(())
    }

    fn validate_recovery_wallet(&self, name: &str, path: &Path, journal: &ReplaceJournalPayload) -> Result<RecoveryWallet, StoreError> {
        use rustix::fs::{Mode, OFlags, openat};
        let fd = match openat(&self.file, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(RecoveryWallet::Missing),
            Err(_) => return Err(recovery_error(path.to_owned(), "recovery artifact is unreadable or symbolic link")),
        };
        let file = File::from(fd);
        let metadata = validate_open_file(path, &file)?;
        let identity = file_identity(&metadata);
        let text = read_bounded(&file, path, metadata.len())?;
        let wallet = WalletFile::parse_strict(&text).map_err(|_| recovery_error(path.to_owned(), "recovery artifact is not canonical keystore JSON"))?;
        if !wallet.is_valid_discovery_file() { return Err(recovery_error(path.to_owned(), "recovery artifact has no canonical wallet identity")); }
        let digest = sha256_hex(text.as_bytes());
        let address = wallet.address.as_deref().expect("validated discovery wallet");
        if digest == journal.replacement_sha256 && address == journal.replacement_address {
            return if identity == journal.replacement_identity { Ok(RecoveryWallet::Replacement) } else { Err(recovery_error(path.to_owned(), "replacement inode does not match journal")) };
        }
        if journal.original_sha256.as_deref() == Some(&digest) && journal.original_address.as_deref() == Some(address) {
            return if journal.original_identity == Some(identity) { Ok(RecoveryWallet::Original) } else { Err(recovery_error(path.to_owned(), "original inode does not match journal")) };
        }
        Err(recovery_error(path.to_owned(), "recovery artifact identity does not match journal"))
    }
}

#[cfg(unix)]
fn recovery_error(path: PathBuf, reason: &'static str) -> StoreError { StoreError::RecoveryRefused { path, reason } }

#[cfg(unix)]
fn validate_journal_names(payload: &ReplaceJournalPayload, path: &Path) -> Result<(), StoreError> {
    fn simple(name: &str) -> bool { !name.is_empty() && name.len() <= 255 && name != "." && name != ".." && !name.as_bytes().contains(&b'/') && !name.as_bytes().contains(&0) }
    if !simple(&payload.destination) || !simple(&payload.temporary) || !simple(&payload.backup)
        || !payload.temporary.starts_with(".keystore-") || !payload.temporary.ends_with(".tmp")
        || !payload.backup.starts_with(".keystore-") || !payload.backup.ends_with(".backup")
        || payload.temporary == payload.backup || payload.destination == REPLACE_JOURNAL || payload.destination == REPLACE_JOURNAL_TEMP {
        return Err(recovery_error(path.join(REPLACE_JOURNAL), "journal contains unsafe names"));
    }
    Ok(())
}

#[cfg(unix)]
fn sha256_hex(bytes: &[u8]) -> String { Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect() }

#[cfg(unix)]
fn write_replace_journal(parent: &AnchoredDirectory, directory: &Path, payload: ReplaceJournalPayload) -> Result<(), StoreError> {
    use rustix::fs::{Mode, OFlags, openat, renameat};
    let encoded = serde_json::to_vec(&payload).map_err(|_| recovery_error(directory.join(REPLACE_JOURNAL), "journal payload cannot be encoded"))?;
    let journal = ReplaceJournal { checksum: sha256_hex(&encoded), payload };
    let bytes = serde_json::to_vec(&journal).map_err(|_| recovery_error(directory.join(REPLACE_JOURNAL), "journal cannot be encoded"))?;
    if bytes.len() > MAX_REPLACE_JOURNAL_BYTES { return Err(recovery_error(directory.join(REPLACE_JOURNAL), "journal exceeds size limit")); }
    let path = directory.join(REPLACE_JOURNAL_TEMP);
    let fd = openat(&parent.file, REPLACE_JOURNAL_TEMP, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::RUSR | Mode::WUSR)
        .map_err(|e| io_error("create keystore replacement journal", &path, e.into()))?;
    let mut file = File::from(fd);
    file.write_all(&bytes).map_err(|e| io_error("write keystore replacement journal", &path, e))?;
    file.sync_all().map_err(|e| io_error("fsync keystore replacement journal", &path, e))?;
    drop(file);
    renameat(&parent.file, REPLACE_JOURNAL_TEMP, &parent.file, REPLACE_JOURNAL).map_err(|e| io_error("publish keystore replacement journal", &directory.join(REPLACE_JOURNAL), e.into()))?;
    parent.file.sync_all().map_err(|e| io_error("fsync keystore journal directory", directory, e))
}

#[cfg(unix)]
fn parent_open_error(parent: &File, name: &std::ffi::OsStr, path: &Path, error: rustix::io::Errno) -> StoreError {
    match error {
        rustix::io::Errno::LOOP => StoreError::ParentSymlink(path.to_owned()),
        rustix::io::Errno::NOTDIR if rustix::fs::readlinkat(parent, name, Vec::new()).is_ok() => StoreError::ParentSymlink(path.to_owned()),
        rustix::io::Errno::NOTDIR => StoreError::ParentNotDirectory(path.to_owned()),
        error => io_error("open keystore parent", path, error.into()),
    }
}

#[cfg(unix)]
fn read_validated_wallet_at(parent: &AnchoredDirectory, name: &std::ffi::OsStr, path: &Path) -> Result<(Zeroizing<String>, WalletFile, FileIdentity), StoreError> {
    use rustix::fs::{Mode, OFlags, openat};
    let fd = openat(&parent.file, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|error| {
        if error == rustix::io::Errno::LOOP { StoreError::SymlinkRefused(path.to_owned()) } else { io_error("open keystore identity", path, error.into()) }
    })?;
    let file = File::from(fd);
    let metadata = validate_open_file(path, &file)?;
    let identity = file_identity(&metadata);
    let text = read_bounded(&file, path, metadata.len())?;
    let wallet = WalletFile::parse_strict(&text)?;
    if !wallet.is_valid_discovery_file() { return Err(recovery_error(path.to_owned(), "keystore has no canonical wallet identity")); }
    Ok((text, wallet, identity))
}

#[cfg(unix)]
fn reject_at_symlink_or_nonregular(parent: &File, name: &std::ffi::OsStr, path: &Path, expected_identity: Option<FileIdentity>) -> Result<bool, StoreError> {
    use rustix::fs::{Mode, OFlags, openat};
    match openat(parent, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()) {
        Ok(fd) => {
            let file = File::from(fd);
            let metadata = validate_open_file(path, &file)?;
            if expected_identity.is_some_and(|expected| file_identity(&metadata) != expected) { return Err(StoreError::InodeChanged(path.to_owned())); }
            Ok(true)
        }
        Err(rustix::io::Errno::NOENT) if expected_identity.is_none() => Ok(false),
        Err(rustix::io::Errno::NOENT) => Err(StoreError::InodeChanged(path.to_owned())),
        Err(rustix::io::Errno::LOOP) => Err(StoreError::SymlinkRefused(path.to_owned())),
        Err(error) => Err(io_error("open replacement target", path, error.into())),
    }
}

fn fail_atomic_write(failure: Option<AtomicWriteStage>, stage: AtomicWriteStage) -> Result<(), StoreError> {
    if failure == Some(stage) { Err(StoreError::AtomicWriteFailure(stage)) } else { Ok(()) }
}

fn matching_address_paths_locked_reporting<W: FnMut(&StoreWarning)>(parent: &AnchoredDirectory, directory: &Path, address: &str, warning_sink: &mut W) -> Result<Vec<PathBuf>, StoreError> {
    Ok(list_keystores_locked_reporting(parent, directory, warning_sink)?.into_iter().filter(|entry| entry.address == address).map(|entry| entry.path).collect())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FileIdentity { dev: u64, ino: u64 }
struct MutationCandidate { path: PathBuf, wallet: WalletFile, identity: FileIdentity }

fn matching_mutation_candidates_locked_reporting<W: FnMut(&StoreWarning)>(parent: &AnchoredDirectory, directory: &Path, address: &str, warning_sink: &mut W) -> Result<Vec<MutationCandidate>, StoreError> {
    let listed = list_keystores_locked_reporting(parent, directory, warning_sink)?;
    let mut candidates = Vec::new();
    for listed in listed.into_iter().filter(|item| item.address == address) {
        let name = listed.path.file_name().ok_or_else(|| StoreError::NotRegularFile(listed.path.clone()))?;
        let (wallet, identity) = read_mutation_wallet(parent, name, &listed.path)?;
        candidates.push(MutationCandidate { path: listed.path, wallet, identity });
    }
    Ok(candidates)
}

fn read_mutation_wallet(parent: &AnchoredDirectory, name: &std::ffi::OsStr, path: &Path) -> Result<(WalletFile, FileIdentity), StoreError> {
    use rustix::fs::{Mode, OFlags, openat};
    let fd = openat(&parent.file, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|error| {
        if error == rustix::io::Errno::LOOP { StoreError::SymlinkRefused(path.to_owned()) } else { io_error("open keystore for mutation", path, error.into()) }
    })?;
    let file = File::from(fd);
    let metadata = validate_open_file(path, &file)?;
    let identity = file_identity(&metadata);
    let text = read_bounded(&file, path, metadata.len())?;
    Ok((WalletFile::parse_strict(&text)?, identity))
}

fn list_keystores_locked(parent: &AnchoredDirectory, directory: &Path) -> Result<ListReport, StoreError> {
    let mut warnings = Vec::new();
    let keystores = list_keystores_locked_reporting(parent, directory, &mut |warning| warnings.push(warning.clone()))?;
    Ok(ListReport { keystores, warnings })
}

fn list_keystores_locked_reporting<W: FnMut(&StoreWarning)>(parent: &AnchoredDirectory, directory: &Path, warning_sink: &mut W) -> Result<Vec<ListedKeystore>, StoreError> {
    use std::os::unix::ffi::OsStringExt;
    let mut names = rustix::fs::Dir::read_from(&parent.file).map_err(|e| io_error("read directory", directory, e.into()))?
        .filter_map(Result::ok)
        .map(|entry| std::ffi::OsString::from_vec(entry.file_name().to_bytes().to_vec()))
        .filter(|name| Path::new(name).extension().is_some_and(|value| value == "json"))
        .collect::<Vec<_>>();
    names.sort();
    let mut keystores = Vec::new();
    for name in names {
        let path = directory.join(&name);
        match read_scan_wallet(parent, &name, &path) {
            Ok(wallet) if wallet.is_valid_discovery_file() => keystores.push(ListedKeystore { address: wallet.address.expect("checked"), path }),
            Ok(_) => warning_sink(&StoreWarning::SkippedInvalidJson { path }),
            Err(ScanFailure::Warning(warning)) => warning_sink(&warning),
            Err(ScanFailure::Fatal(error)) => return Err(error),
        }
    }
    Ok(keystores)
}

enum ScanFailure { Warning(StoreWarning), Fatal(StoreError) }
fn read_scan_wallet(parent: &AnchoredDirectory, name: &std::ffi::OsStr, path: &Path) -> Result<WalletFile, ScanFailure> {
    use rustix::fs::{Mode, OFlags, openat};
    let file = File::from(openat(&parent.file, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|error| ScanFailure::Warning(if error == rustix::io::Errno::LOOP { StoreWarning::SkippedSymlink { path: path.to_owned() } } else { StoreWarning::SkippedUnreadable { path: path.to_owned() } }))?);
    let metadata = file.metadata().map_err(|_| ScanFailure::Warning(StoreWarning::SkippedUnreadable { path: path.to_owned() }))?;
    if !metadata.is_file() { return Err(ScanFailure::Warning(StoreWarning::SkippedNonRegular { path: path.to_owned() })); }
    check_security(path, &metadata).map_err(ScanFailure::Fatal)?;
    if metadata.len() > MAX_KEYSTORE_JSON_BYTES as u64 { return Err(ScanFailure::Warning(StoreWarning::SkippedOversized { path: path.to_owned() })); }
    let text = read_bounded(&file, path, metadata.len()).map_err(|error| match error { StoreError::Oversized { .. } => ScanFailure::Warning(StoreWarning::SkippedOversized { path: path.to_owned() }), _ => ScanFailure::Warning(StoreWarning::SkippedUnreadable { path: path.to_owned() }) })?;
    WalletFile::parse_strict(&text).map_err(|_| ScanFailure::Warning(StoreWarning::SkippedInvalidJson { path: path.to_owned() }))
}
#[cfg(unix)]
fn load_keystore_direct_unix(path: &Path) -> Result<LoadResult, StoreError> {
    use rustix::fs::{Mode, OFlags, openat, readlinkat};
    use std::os::unix::ffi::OsStrExt;
    let parent_path = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| StoreError::NotRegularFile(path.to_owned()))?;
    let parent = AnchoredDirectory::open(parent_path, false)?;
    let (target_parent, target_name, followed_symlink) = match readlinkat(&parent.file, name, Vec::new()) {
        Ok(target) => {
            let target = PathBuf::from(std::ffi::OsStr::from_bytes(target.to_bytes()));
            let resolved = if target.is_absolute() { target } else { parent_path.join(target) };
            let resolved_parent_path = resolved.parent().unwrap_or_else(|| Path::new("."));
            let resolved_name = resolved.file_name().ok_or_else(|| StoreError::NotRegularFile(path.to_owned()))?.to_owned();
            let resolved_parent = if resolved_parent_path == parent_path { AnchoredDirectory::open_with_lock(resolved_parent_path, false, false)? } else { AnchoredDirectory::open(resolved_parent_path, false)? };
            (resolved_parent, resolved_name, true)
        }
        Err(rustix::io::Errno::INVAL) => (parent, name.to_owned(), false),
        Err(error) => return Err(io_error("resolve direct keystore", path, error.into())),
    };
    let fd = openat(&target_parent.file, &target_name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|error| {
        if error == rustix::io::Errno::LOOP { StoreError::SymlinkRefused(path.to_owned()) } else { io_error("open keystore", path, error.into()) }
    })?;
    let file = File::from(fd);
    let metadata = validate_open_file(path, &file)?;
    let text = read_bounded(&file, path, metadata.len())?;
    let warnings = if followed_symlink { vec![StoreWarning::DirectLoadFollowedSymlink { path: path.to_owned() }] } else { Vec::new() };
    Ok(LoadResult { wallet: WalletFile::parse(&text)?, warnings })
}


fn read_bounded(file: &File, path: &Path, length: u64) -> Result<Zeroizing<String>, StoreError> {
    if length > MAX_KEYSTORE_JSON_BYTES as u64 { return Err(StoreError::Oversized { path: path.to_owned(), max: MAX_KEYSTORE_JSON_BYTES }); }
    let mut bytes = Zeroizing::new(Vec::with_capacity(length as usize));
    file.take((MAX_KEYSTORE_JSON_BYTES + 1) as u64).read_to_end(&mut bytes).map_err(|e| io_error("read keystore", path, e))?;
    if bytes.len() > MAX_KEYSTORE_JSON_BYTES { return Err(StoreError::Oversized { path: path.to_owned(), max: MAX_KEYSTORE_JSON_BYTES }); }
    String::from_utf8(bytes.to_vec()).map(Zeroizing::new).map_err(|error| io_error("decode keystore UTF-8", path, std::io::Error::new(std::io::ErrorKind::InvalidData, error)))
}

fn validate_open_file(path: &Path, file: &File) -> Result<fs::Metadata, StoreError> {
    let metadata = file.metadata().map_err(|e| io_error("inspect opened keystore", path, e))?;
    if !metadata.is_file() { return Err(StoreError::NotRegularFile(path.to_owned())); }
    check_security(path, &metadata)?;
    if metadata.len() > MAX_KEYSTORE_JSON_BYTES as u64 { return Err(StoreError::Oversized { path: path.to_owned(), max: MAX_KEYSTORE_JSON_BYTES }); }
    Ok(metadata)
}


#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity { dev: metadata.dev(), ino: metadata.ino() }
}

#[cfg(unix)]
fn check_security(path: &Path, meta: &fs::Metadata) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode() & 0o7777;
    let effective_user = rustix::process::geteuid().as_raw();
    if meta.uid() != effective_user { return Err(StoreError::WrongOwner { path: path.to_owned(), owner: meta.uid(), effective_user }); }
    if mode != 0o600 { return Err(StoreError::InsecurePermissions { path: path.to_owned(), mode }); }
    Ok(())
}

#[cfg(unix)]
fn check_directory_security(path: &Path, meta: &fs::Metadata) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode() & 0o7777;
    let effective_user = rustix::process::geteuid().as_raw();
    if meta.uid() != effective_user || mode != 0o700 { return Err(StoreError::InsecureDirectory { path: path.to_owned(), owner: meta.uid(), effective_user, mode }); }
    Ok(())
}
#[cfg(not(unix))]
fn check_security(_: &Path, _: &fs::Metadata) -> Result<(), StoreError> { Ok(()) }
fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> StoreError { StoreError::Io { operation, path: path.to_owned(), source } }
