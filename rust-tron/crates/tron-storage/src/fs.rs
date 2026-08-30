//! Descriptor-retaining, no-follow filesystem boundary for storage state.

#![cfg(unix)]

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const O_NOFOLLOW: i32 = 0o400000;
const O_DIRECTORY: i32 = 0o200000;
const O_CLOEXEC: i32 = 0o2000000;

fn child_name(value: &OsStr) -> io::Result<&OsStr> {
    let path = Path::new(value);
    if value.is_empty() || path.components().count() != 1 || !matches!(path.components().next(), Some(Component::Normal(_))) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "filesystem name must be one non-empty component"));
    }
    Ok(value)
}

fn directory_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    options
}

/// A retained directory descriptor. Child paths resolve through `/proc/self/fd`, pinning the
/// parent inode even if an attacker renames or replaces the original pathname.
pub(crate) struct SecureDir { fd: File, display: PathBuf }

impl SecureDir {
    pub(crate) fn open(path: &Path) -> io::Result<Self> { Self::walk(path, false, true) }
    pub(crate) fn open_read_only(path: &Path) -> io::Result<Self> { Self::walk(path, false, false) }
    pub(crate) fn open_or_create(path: &Path) -> io::Result<Self> { Self::walk(path, true, true) }

    fn walk(path: &Path, create_final: bool, enforce_private_root: bool) -> io::Result<Self> {
        if path.components().any(|component| matches!(component, Component::ParentDir | Component::Prefix(_))) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "parent path components are forbidden"));
        }
        let absolute = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) };
        let components: Vec<_> = absolute.components().filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        }).collect();
        if components.is_empty() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "storage root cannot be filesystem root")); }
        let mut fd = directory_options().open("/")?;
        for (index, component) in components.iter().enumerate() {
            let parent = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
            let candidate = parent.join(child_name(component)?);
            let final_component = index + 1 == components.len();
            fd = match directory_options().open(&candidate) {
                Ok(next) => next,
                Err(error) if final_component && create_final && error.kind() == io::ErrorKind::NotFound => {
                    match fs::create_dir(&candidate) {
                        Ok(()) => fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))?,
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(error),
                    }
                    directory_options().open(&candidate)?
                }
                Err(error) => return Err(error),
            };
        }
        if enforce_private_root {
            let metadata = fd.metadata()?;
            if metadata.uid() != unsafe_free_euid()? || metadata.permissions().mode() & 0o777 != 0o700 {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "storage directory must be owned by the effective uid with mode 0700"));
            }
        }
        Ok(Self { fd, display: path.to_path_buf() })
    }

    fn fd_path(&self) -> PathBuf { PathBuf::from(format!("/proc/self/fd/{}", self.fd.as_raw_fd())) }
    fn child_path(&self, child: &OsStr) -> io::Result<PathBuf> { Ok(self.fd_path().join(child_name(child)?)) }

    pub(crate) fn access_path(&self) -> PathBuf { self.fd_path() }
    pub(crate) fn child_access_path(&self, child: &OsStr) -> io::Result<PathBuf> { self.child_path(child) }
    pub(crate) fn sync(&self) -> io::Result<()> { self.fd.sync_all() }

    pub(crate) fn open_child(&self, child: &OsStr) -> io::Result<Self> {
        let fd = directory_options().open(self.child_path(child)?)?;
        Ok(Self { fd, display: self.display.join(child) })
    }

    pub(crate) fn create_dir(&self, child: &OsStr) -> io::Result<Self> {
        let path = self.child_path(child)?;
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        self.open_child(child)
    }

    pub(crate) fn open_file(&self, child: &OsStr, write: bool, create: bool) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true).write(write).create(create).mode(0o600).custom_flags(O_NOFOLLOW | O_CLOEXEC);
        options.open(self.child_path(child)?)
    }

    pub(crate) fn create_new(&self, child: &OsStr) -> io::Result<File> {
        OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC).open(self.child_path(child)?)
    }

    pub(crate) fn truncate_existing(&self, child: &OsStr) -> io::Result<File> {
        OpenOptions::new().read(true).write(true).truncate(true)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC).open(self.child_path(child)?)
    }

    pub(crate) fn rename(&self, old: &OsStr, new: &OsStr) -> io::Result<()> {
        fs::rename(self.child_path(old)?, self.child_path(new)?)
    }
    pub(crate) fn ensure_absent_nofollow(&self, child: &OsStr) -> io::Result<()> {
        match fs::symlink_metadata(self.child_path(child)?) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(io::Error::new(io::ErrorKind::AlreadyExists, "destination entry already exists")),
            Err(error) => Err(error),
        }
    }

    /// Atomically publishes a directory without replacing an attacker-planted final entry.
    pub(crate) fn rename_noreplace(&self, old: &OsStr, new: &OsStr) -> io::Result<()> {
        rustix::fs::renameat_with(
            &self.fd,
            child_name(old)?,
            &self.fd,
            child_name(new)?,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        Ok(())
    }
    pub(crate) fn remove_file(&self, child: &OsStr) -> io::Result<()> { fs::remove_file(self.child_path(child)?) }
    pub(crate) fn remove_dir(&self, child: &OsStr) -> io::Result<()> { fs::remove_dir(self.child_path(child)?) }

    pub(crate) fn remove_tree(&self, child: &OsStr) -> io::Result<()> {
        let directory = self.open_child(child)?;
        for (name, kind) in directory.entries()? {
            if kind.is_symlink() || kind.is_file() { directory.remove_file(&name)?; }
            else if kind.is_dir() { directory.remove_tree(&name)?; }
            else { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unsupported filesystem entry in storage tree")); }
        }
        drop(directory);
        self.remove_dir(child)
    }

    pub(crate) fn contains(&self, child: &OsStr) -> io::Result<bool> {
        Ok(self.entries()?.iter().any(|(name, _)| name == child))
    }

    pub(crate) fn entries(&self) -> io::Result<Vec<(OsString, fs::FileType)>> {
        fs::read_dir(self.fd_path())?.map(|entry| {
            let entry = entry?;
            Ok((entry.file_name(), entry.file_type()?))
        }).collect()
    }

    pub(crate) fn reject_symlink_entries(&self) -> io::Result<()> {
        if self.entries()?.iter().any(|(_, kind)| kind.is_symlink()) {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "symbolic links are forbidden in storage state"))
        } else { Ok(()) }
    }

    pub(crate) fn temp_file(&self, stem: &str) -> io::Result<(OsString, File)> {
        for _ in 0..128 {
            let suffix = random_suffix()?;
            let child = OsString::from(format!(".{stem}.{suffix}.tmp"));
            match self.create_new(&child) {
                Ok(file) => return Ok((child, file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(io::ErrorKind::AlreadyExists, "unable to allocate unpredictable temporary file"))
    }

    pub(crate) fn lock_root_exclusive(&self) -> io::Result<RootLock> {
        let root_guard = self.fd.try_clone()?;
        lock_nonblocking(&root_guard)?;
        Ok(RootLock { root_guard })
    }

    pub(crate) fn finish_exclusive_lock(&self, root_lock: RootLock, child: &OsStr) -> io::Result<KernelLock> {
        let parent = self.fd.try_clone()?;
        let (mut owner, created) = match self.create_new(child) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (self.open_file(child, true, false)?, false),
            Err(error) => return Err(error),
        };
        if !owner.metadata()?.is_file() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "storage lock must be a regular file"));
        }
        lock_nonblocking(&owner)?;
        owner.set_len(0)?;
        writeln!(owner, "{}", std::process::id())?;
        owner.sync_all()?;
        self.sync()?;
        Ok(KernelLock {
            owner,
            _root_guard: root_lock.root_guard,
            parent,
            child: child.to_os_string(),
            created,
        })
    }

    pub(crate) fn lock_exclusive(&self, child: &OsStr) -> io::Result<KernelLock> {
        let root_lock = self.lock_root_exclusive()?;
        self.finish_exclusive_lock(root_lock, child)
    }

    pub(crate) fn validate_path_identity(&self) -> io::Result<()> {
        let retained = self.fd.metadata()?;
        let current = fs::symlink_metadata(&self.display)?;
        if current.file_type().is_symlink() || !current.is_dir() || current.dev() != retained.dev() || current.ino() != retained.ino() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "storage root pathname no longer names the retained directory"));
        }
        Ok(())
    }
}
pub(crate) fn sync_tree_dir(directory: &SecureDir) -> io::Result<()> {
    for (name, kind) in directory.entries()? {
        if kind.is_symlink() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "symbolic links are forbidden in storage state"));
        }
        if kind.is_dir() {
            let child = directory.open_child(&name)?;
            sync_tree_dir(&child)?;
        } else if kind.is_file() {
            directory.open_file(&name, false, false)?.sync_all()?;
        } else {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unsupported filesystem entry in storage tree"));
        }
    }
    directory.sync()
}

pub(crate) struct RootLock { root_guard: File }

pub(crate) struct KernelLock {
    owner: File,
    _root_guard: File,
    parent: File,
    child: OsString,
    created: bool,
}
impl Drop for KernelLock {
    fn drop(&mut self) {
        if !self.created { return; }
        let Ok(owner) = self.owner.metadata() else { return };
        let parent = PathBuf::from(format!("/proc/self/fd/{}", self.parent.as_raw_fd()));
        let path = parent.join(&self.child);
        let Ok(current) = fs::symlink_metadata(&path) else { return };
        if current.file_type().is_file() && current.dev() == owner.dev() && current.ino() == owner.ino() {
            let _ = fs::remove_file(path);
            let _ = self.parent.sync_all();
        }
    }
}

fn lock_nonblocking(file: &File) -> io::Result<()> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        let error: io::Error = error.into();
        if matches!(error.kind(), io::ErrorKind::WouldBlock) {
            io::Error::new(io::ErrorKind::WouldBlock, "storage lock is held")
        } else {
            error
        }
    })
}

fn random_suffix() -> io::Result<String> {
    let mut random=[0u8;24];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(random.iter().map(|byte|format!("{byte:02x}")).collect())
}

fn unsafe_free_euid() -> io::Result<u32> {
    // `/proc/self/status` is kernel-generated and avoids an unsafe libc call in this forbid-unsafe crate.
    let status = fs::read_to_string("/proc/self/status")?;
    status.lines().find_map(|line| line.strip_prefix("Uid:").and_then(|uids| uids.split_whitespace().nth(1)).and_then(|uid| uid.parse().ok()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "effective uid unavailable"))
}
