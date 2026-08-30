use crate::keystore::{self, KeystoreRandom, ScryptProfile, WalletFile};
use crate::{CryptoEngine, PrivateKey};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const MAX_KEYSTORE_JSON_BYTES: usize = 8 * 1024;
pub const WINDOWS_PERMISSION_LIMITATION: &str = "descriptor-anchored keystore publication is unsupported on Windows";

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicWriteStage { Serialization, Write, FileFsync, Rename, DirectoryFsync }

#[derive(Debug)]
pub enum StoreError {
    Io { operation: &'static str, path: PathBuf, source: std::io::Error },
    AtomicWriteFailure(AtomicWriteStage),
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
    UnsupportedPlatform(&'static str),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, path, source } => write!(f, "{operation} {}: {source}", path.display()),
            Self::AtomicWriteFailure(stage) => write!(f, "injected atomic-write failure at {stage:?}"),
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
            Self::UnsupportedPlatform(reason) => write!(f, "unsupported keystore persistence platform: {reason}"),
        }
    }
}
impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Io { source, .. } => Some(source), Self::Keystore(error) => Some(error), _ => None }
    }
}
impl From<keystore::KeystoreError> for StoreError { fn from(value: keystore::KeystoreError) -> Self { Self::Keystore(value) } }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedKeystore { pub address: String, pub path: PathBuf }
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListReport { pub keystores: Vec<ListedKeystore>, pub warnings: Vec<StoreWarning> }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadResult { pub wallet: WalletFile, pub warnings: Vec<StoreWarning> }

pub fn new_keystore<R: KeystoreRandom>(destination: impl AsRef<Path>, password: &str, key: &PrivateKey, checksum_engine: CryptoEngine, overwrite: bool, random: &mut R) -> Result<WalletFile, StoreError> {
    let destination = destination.as_ref();
    let parent_path = destination.parent().unwrap_or_else(|| Path::new("."));
    let parent = AnchoredDirectory::open(parent_path, true)?;
    let wallet = keystore::create_with_random(password, key, checksum_engine, ScryptProfile::Standard, random)?;
    atomic_write_wallet_in_parent(&wallet, destination, overwrite, random, None, None, || {}, &parent)?;
    Ok(wallet)
}
pub fn import_keystore<R: KeystoreRandom>(directory: impl AsRef<Path>, destination: impl AsRef<Path>, password: &str, key: &PrivateKey, checksum_engine: CryptoEngine, force_duplicate: bool, overwrite: bool, random: &mut R) -> Result<WalletFile, StoreError> {
    let directory = directory.as_ref();
    let destination = destination.as_ref();
    let parent_path = destination.parent().unwrap_or_else(|| Path::new("."));
    if parent_path != directory { return Err(StoreError::ParentChanged(parent_path.to_owned())); }
    let parent = AnchoredDirectory::open(directory, true)?;
    let candidate = keystore::create_with_random(password, key, checksum_engine, ScryptProfile::Standard, random)?;
    let address = candidate.address.as_deref().unwrap_or_default();
    let matches = matching_address_paths_locked(&parent, directory, address)?;
    if !force_duplicate && !matches.is_empty() { return Err(StoreError::DuplicateAddress { address: address.to_owned(), files: matches }); }
    atomic_write_wallet_in_parent(&candidate, destination, overwrite, random, None, None, || {}, &parent)?;
    Ok(candidate)
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
    let directory = directory.as_ref();
    let parent = AnchoredDirectory::open(directory, false)?;
    let matches = matching_mutation_candidates_locked(&parent, directory, address)?;
    let selected = match matches.as_slice() {
        [] => return Err(StoreError::AddressNotFound(address.to_owned())),
        [selected] => selected,
        _ => return Err(StoreError::DuplicateAddress { address: address.to_owned(), files: matches.iter().map(|item| item.path.clone()).collect() }),
    };
    let key = keystore::decrypt(old_password, &selected.wallet, key_engine, checksum_engine)?;
    let replacement = keystore::create_with_random(new_password, &key, checksum_engine, ScryptProfile::Standard, random)?;
    atomic_write_wallet_in_parent(&replacement, &selected.path, true, random, Some(selected.identity), None, || {}, &parent)?;
    Ok(selected.path.clone())
}

pub fn atomic_write_wallet(wallet: &WalletFile, destination: &Path, overwrite: bool) -> Result<Vec<StoreWarning>, StoreError> {
    atomic_write_wallet_with_random(wallet, destination, overwrite, &mut rand_core::OsRng)
}

pub fn atomic_write_wallet_with_random<R: KeystoreRandom>(wallet: &WalletFile, destination: &Path, overwrite: bool, random_source: &mut R) -> Result<Vec<StoreWarning>, StoreError> {
    atomic_write_wallet_with_hook(wallet, destination, overwrite, random_source, || {})
}

#[doc(hidden)]
pub fn atomic_write_wallet_with_hook<R: KeystoreRandom, H: FnOnce()>(wallet: &WalletFile, destination: &Path, overwrite: bool, random_source: &mut R, pre_publish_hook: H) -> Result<Vec<StoreWarning>, StoreError> {
    atomic_write_wallet_expected(wallet, destination, overwrite, random_source, None, None, None, pre_publish_hook)
}

pub fn atomic_write_wallet_with_failure<R: KeystoreRandom>(wallet: &WalletFile, destination: &Path, overwrite: bool, random_source: &mut R, failure: AtomicWriteStage) -> Result<Vec<StoreWarning>, StoreError> {
    atomic_write_wallet_expected(wallet, destination, overwrite, random_source, None, None, Some(failure), || {})
}

fn atomic_write_wallet_expected<R: KeystoreRandom, H: FnOnce()>(wallet: &WalletFile, destination: &Path, overwrite: bool, random_source: &mut R, expected_identity: Option<FileIdentity>, expected_parent_identity: Option<FileIdentity>, failure: Option<AtomicWriteStage>, pre_publish_hook: H) -> Result<Vec<StoreWarning>, StoreError> {
    #[cfg(not(unix))]
    {
        let _ = (wallet, destination, overwrite, random_source, expected_identity, expected_parent_identity, failure, pre_publish_hook);
        return Err(StoreError::UnsupportedPlatform(WINDOWS_PERMISSION_LIMITATION));
    }
    #[cfg(unix)]
    atomic_write_wallet_expected_unix(wallet, destination, overwrite, random_source, expected_identity, expected_parent_identity, failure, pre_publish_hook)
}

#[cfg(unix)]
fn atomic_write_wallet_expected_unix<R: KeystoreRandom, H: FnOnce()>(wallet: &WalletFile, destination: &Path, overwrite: bool, random_source: &mut R, expected_identity: Option<FileIdentity>, expected_parent_identity: Option<FileIdentity>, failure: Option<AtomicWriteStage>, pre_publish_hook: H) -> Result<Vec<StoreWarning>, StoreError> {
    let parent_path = destination.parent().unwrap_or_else(|| Path::new("."));
    let parent = AnchoredDirectory::open(parent_path, true)?;
    if expected_parent_identity.is_some_and(|expected| parent.identity != expected) { return Err(StoreError::ParentChanged(parent_path.to_owned())); }
    atomic_write_wallet_in_parent(wallet, destination, overwrite, random_source, expected_identity, failure, pre_publish_hook, &parent)
}

#[cfg(unix)]
fn atomic_write_wallet_in_parent<R: KeystoreRandom, H: FnOnce()>(wallet: &WalletFile, destination: &Path, overwrite: bool, random_source: &mut R, expected_identity: Option<FileIdentity>, failure: Option<AtomicWriteStage>, pre_publish_hook: H, parent: &AnchoredDirectory) -> Result<Vec<StoreWarning>, StoreError> {
    use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags, linkat, openat, renameat, renameat_with, unlinkat};
    let parent_path = destination.parent().unwrap_or_else(|| Path::new("."));
    let name = destination.file_name().ok_or_else(|| StoreError::ParentNotDirectory(destination.to_owned()))?;
    let mut random = [0u8; 8];
    random_source.fill_bytes(&mut random);
    let suffix = format!("{:016x}", u64::from_le_bytes(random));
    let temp_name = format!(".keystore-{suffix}.tmp");
    let backup_name = format!(".keystore-{suffix}.backup");
    let temp_path = parent_path.join(&temp_name);
    let mut published = false;
    let mut backed_up = false;
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
        drop(file);
        fail_atomic_write(failure, AtomicWriteStage::Rename)?;
        pre_publish_hook();
        if overwrite {
            if reject_at_symlink_or_nonregular(&parent.file, name, destination, expected_identity)? {
                renameat(&parent.file, name, &parent.file, &backup_name).map_err(|e| io_error("backup replaced keystore", destination, e.into()))?;
                backed_up = true;
            }
            renameat(&parent.file, &temp_name, &parent.file, name).map_err(|e| io_error("replace keystore", destination, e.into()))?;
            published = true;
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
        fail_atomic_write(failure, AtomicWriteStage::DirectoryFsync)?;
        parent.file.sync_all().map_err(|e| io_error("fsync keystore directory", parent_path, e))?;
        let written_fd = openat(&parent.file, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|e| io_error("open written keystore", destination, e.into()))?;
        validate_open_file(destination, &File::from(written_fd))?;
        if backed_up { unlinkat(&parent.file, &backup_name, AtFlags::empty()).map_err(|e| io_error("remove keystore backup", destination, e.into()))?; }
        Ok(())
    })();
    if result.is_err() {
        if published { let _ = unlinkat(&parent.file, name, AtFlags::empty()); }
        if backed_up { let _ = renameat(&parent.file, &backup_name, &parent.file, name); }
        let _ = unlinkat(&parent.file, &temp_name, AtFlags::empty());
        let _ = parent.file.sync_all();
    }
    result?;
    Ok(Vec::new())
}

#[cfg(unix)]
struct AnchoredDirectory { file: File, identity: FileIdentity }

#[cfg(unix)]
impl AnchoredDirectory {
    fn open(path: &Path, create: bool) -> Result<Self, StoreError> { Self::open_with_lock(path, create, true) }

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

fn matching_address_paths_locked(parent: &AnchoredDirectory, directory: &Path, address: &str) -> Result<Vec<PathBuf>, StoreError> {
    Ok(list_keystores_locked(parent, directory)?.keystores.into_iter().filter(|entry| entry.address == address).map(|entry| entry.path).collect())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity { dev: u64, ino: u64 }
struct MutationCandidate { path: PathBuf, wallet: WalletFile, identity: FileIdentity }

fn matching_mutation_candidates_locked(parent: &AnchoredDirectory, directory: &Path, address: &str) -> Result<Vec<MutationCandidate>, StoreError> {
    let report = list_keystores_locked(parent, directory)?;
    let mut candidates = Vec::new();
    for listed in report.keystores.into_iter().filter(|item| item.address == address) {
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
    use std::os::unix::ffi::OsStringExt;
    let mut names = rustix::fs::Dir::read_from(&parent.file).map_err(|e| io_error("read directory", directory, e.into()))?
        .filter_map(Result::ok)
        .map(|entry| std::ffi::OsString::from_vec(entry.file_name().to_bytes().to_vec()))
        .filter(|name| Path::new(name).extension().is_some_and(|value| value == "json"))
        .collect::<Vec<_>>();
    names.sort();
    let mut report = ListReport::default();
    for name in names {
        let path = directory.join(&name);
        match read_scan_wallet(parent, &name, &path) {
            Ok(wallet) if wallet.is_valid_discovery_file() => report.keystores.push(ListedKeystore { address: wallet.address.expect("checked"), path }),
            Ok(_) => report.warnings.push(StoreWarning::SkippedInvalidJson { path }),
            Err(ScanFailure::Warning(warning)) => report.warnings.push(warning),
            Err(ScanFailure::Fatal(error)) => return Err(error),
        }
    }
    Ok(report)
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
