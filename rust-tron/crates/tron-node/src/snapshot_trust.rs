use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use tron_crypto::artifact_auth::{verify_dsse_scoped, AuthClock, AuthLimits, DsseEnvelope, RoleName, TrustStoreV1};
use tron_storage::{FormatError, FormatResult, SnapshotDescriptor, SnapshotSource, SnapshotVerifier, StableError};

pub const SNAPSHOT_MANIFEST_PAYLOAD_TYPE: &str = "application/vnd.tron.snapshot-manifest.v1+json";
const WATERMARK_FILE: &str = "tron-storage.snapshot-watermark.json";
const PROVENANCE_FILE: &str = "tron-storage.snapshot-provenance.json";
const BOOTSTRAP_JOURNAL: &str = "tron-storage.snapshot-bootstrap.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedCheckpoint { pub height: u64, pub block_id: String, pub state_root: String }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotPolicy {
    pub minimum_height: u64,
    pub trusted_checkpoint: TrustedCheckpoint,
    pub maximum_age: Duration,
    pub maximum_future_skew: Duration,
    pub required_stores: Vec<String>,
    pub auth_limits: AuthLimits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifestV1 {
    pub schema: String,
    pub network: String,
    pub genesis: String,
    pub schema_version: u32,
    pub backend: String,
    pub backend_format: String,
    pub generation: u64,
    pub height: u64,
    pub block_id: String,
    pub state_root: String,
    pub stores: Vec<String>,
    pub payload_sha256: String,
    pub payload_size: u64,
    pub created_at: String,
}

pub struct PolicySnapshotVerifier<C> {
    trust_store: TrustStoreV1,
    policy: SnapshotPolicy,
    clock: C,
}

impl<C> PolicySnapshotVerifier<C> {
    #[must_use]
    pub fn new(trust_store: TrustStoreV1, policy: SnapshotPolicy, clock: C) -> Self { Self { trust_store, policy, clock } }
    #[must_use] pub fn policy(&self) -> &SnapshotPolicy { &self.policy }
    #[must_use] pub fn trust_store(&self) -> &TrustStoreV1 { &self.trust_store }
}

impl<C: AuthClock> SnapshotVerifier for PolicySnapshotVerifier<C> {
    fn verify(&self, descriptor: &SnapshotDescriptor, snapshot: &SnapshotSource) -> FormatResult<()> {
        let manifest = verify_snapshot_manifest(descriptor, snapshot, &self.trust_store, &self.policy, self.clock.now())?;
        if manifest.state_root != descriptor.state_root { return Err(rejected("manifest state root differs from descriptor")); }
        Ok(())
    }
}

pub fn verify_snapshot_manifest(
    descriptor: &SnapshotDescriptor,
    snapshot: &SnapshotSource,
    trust_store: &TrustStoreV1,
    policy: &SnapshotPolicy,
    now: OffsetDateTime,
) -> FormatResult<SnapshotManifestV1> {
    let envelope = DsseEnvelope::parse(&descriptor.authentication_envelope, policy.auth_limits).map_err(auth_error)?;
    let role = RoleName::snapshot(&descriptor.identity.network).map_err(auth_error)?;
    let scope = format!("snapshot:{}", descriptor.identity.network);
    let verified = verify_dsse_scoped(&envelope, SNAPSHOT_MANIFEST_PAYLOAD_TYPE, trust_store, &role, &scope, now, policy.auth_limits).map_err(auth_error)?;
    let manifest: SnapshotManifestV1 = serde_json::from_slice(&verified.payload).map_err(|e| rejected(&format!("invalid snapshot manifest: {e}")))?;
    if manifest.schema != "tron-snapshot-manifest-v1"
        || manifest.network != descriptor.identity.network || manifest.genesis != descriptor.identity.genesis
        || manifest.schema_version != descriptor.schema_version || manifest.backend != descriptor.backend
        || manifest.backend_format != descriptor.backend_format || manifest.generation != descriptor.generation
        || manifest.state_root != descriptor.state_root || manifest.payload_sha256 != descriptor.payload_sha256
        || manifest.payload_size != descriptor.payload_size || snapshot.len() as u64 != manifest.payload_size
        || snapshot.sha256() != manifest.payload_sha256 {
        return Err(rejected("signed snapshot manifest does not exactly bind descriptor and payload"));
    }
    if manifest.height < policy.minimum_height { return Err(rejected("snapshot is below minimum accepted height")); }
    let created = OffsetDateTime::parse(&manifest.created_at, &Rfc3339).map_err(|_| rejected("snapshot created_at is invalid"))?;
    if created > now + policy.maximum_future_skew || now - created > policy.maximum_age { return Err(rejected("snapshot freshness policy failed")); }
    let checkpoint = &policy.trusted_checkpoint;
    if checkpoint.height == 0 || !is_nonzero_sha256(&checkpoint.block_id) || !is_nonzero_sha256(&checkpoint.state_root) {
        return Err(rejected("trusted checkpoint must be a non-zero production height, block ID, and state root"));
    }
    if manifest.height != checkpoint.height || manifest.block_id != checkpoint.block_id || manifest.state_root != checkpoint.state_root {
        return Err(rejected("snapshot does not exactly match the independently trusted checkpoint"));
    }
    let mut stores = manifest.stores.clone(); stores.sort();
    if stores.is_empty() || stores.windows(2).any(|pair| pair[0] == pair[1]) { return Err(rejected("snapshot store inventory must be non-empty and unique")); }
    let mut required = policy.required_stores.clone(); required.sort();
    if required.is_empty() || required.windows(2).any(|pair| pair[0] == pair[1]) { return Err(rejected("trusted required store inventory is invalid")); }
    if stores != required { return Err(rejected("snapshot store inventory differs from the exact trusted inventory")); }
    Ok(manifest)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotWatermarkV1 {
    pub schema: String,
    pub trust_store_version: u64,
    pub height: u64,
    pub block_id: String,
    pub state_root: String,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBootstrapJournalV1 {
    pub schema: String,
    pub phase: String,
    pub descriptor_sha256: String,
    pub watermark: SnapshotWatermarkV1,
}

/// Begins acceptance before storage import. Ordinary startup must reject any retained journal.
pub fn begin_snapshot_acceptance(root: &Path, descriptor: &SnapshotDescriptor, manifest: &SnapshotManifestV1, trust_store_version: u64) -> FormatResult<SnapshotBootstrapJournalV1> {
    let directory = TrustDir::open_or_create(root).map_err(|e| io(root, e))?;
    let watermark = SnapshotWatermarkV1 { schema: "tron-snapshot-watermark-v1".into(), trust_store_version, height: manifest.height, block_id: manifest.block_id.clone(), state_root: manifest.state_root.clone(), payload_sha256: manifest.payload_sha256.clone() };
    enforce_monotonic(&directory, root, &watermark)?;
    let journal = SnapshotBootstrapJournalV1 { schema: "tron-snapshot-bootstrap-v1".into(), phase: "verified".into(), descriptor_sha256: descriptor_digest(descriptor), watermark };
    install_json(&directory, root, BOOTSTRAP_JOURNAL, &journal)?;
    Ok(journal)
}

/// Publishes provenance first, then the durable anti-rollback watermark, and removes the journal last.
pub fn publish_snapshot_acceptance(root: &Path, journal: &SnapshotBootstrapJournalV1, manifest: &SnapshotManifestV1) -> FormatResult<()> {
    let directory = TrustDir::open(root).map_err(|e| io(root, e))?;
    let retained = read_json::<SnapshotBootstrapJournalV1>(&directory, root, BOOTSTRAP_JOURNAL)?;
    if retained != *journal { return Err(integrity(root, "bootstrap journal changed")); }
    if retained.phase != "verified" && retained.phase != "imported" { return Err(integrity(root, "invalid bootstrap journal phase")); }
    let mut imported = retained.clone(); imported.phase = "imported".into();
    install_json(&directory, root, BOOTSTRAP_JOURNAL, &imported)?;
    install_json(&directory, root, PROVENANCE_FILE, manifest)?;
    install_json(&directory, root, WATERMARK_FILE, &imported.watermark)?;
    directory.remove_checked(BOOTSTRAP_JOURNAL).map_err(|e| io(&root.join(BOOTSTRAP_JOURNAL), e))?;
    directory.sync().map_err(|e| io(root, e))
}

/// Completes only acceptance phases whose imported storage root exactly matches the journal.
pub fn recover_snapshot_acceptance(root: &Path, installed_state_root: &str) -> FormatResult<bool> {
    let directory = TrustDir::open(root).map_err(|e| io(root, e))?;
    if !directory.contains_regular(BOOTSTRAP_JOURNAL).map_err(|e| io(&root.join(BOOTSTRAP_JOURNAL), e))? { return Ok(false); }
    let journal = read_json::<SnapshotBootstrapJournalV1>(&directory, root, BOOTSTRAP_JOURNAL)?;
    if journal.watermark.state_root != installed_state_root { return Err(integrity(root, "imported root is not covered by bootstrap journal")); }
    if journal.phase == "verified" { return Err(FormatError::new(StableError::PartialMigration, root, "snapshot import has not reached acceptance publication")); }
    let provenance: SnapshotManifestV1 = read_json(&directory, root, PROVENANCE_FILE)?;
    if provenance.state_root != installed_state_root || provenance.payload_sha256 != journal.watermark.payload_sha256 { return Err(integrity(root, "snapshot provenance mismatch")); }
    enforce_monotonic(&directory, root, &journal.watermark)?;
    install_json(&directory, root, WATERMARK_FILE, &journal.watermark)?;
    directory.remove_checked(BOOTSTRAP_JOURNAL).map_err(|e| io(&root.join(BOOTSTRAP_JOURNAL), e))?;
    directory.sync().map_err(|e| io(root, e))?;
    Ok(true)
}

pub fn snapshot_acceptance_ready(root: &Path, installed_state_root: &str) -> FormatResult<bool> {
    let directory = match TrustDir::open(root) { Ok(value) => value, Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false), Err(error) => return Err(io(root, error)) };
    if directory.contains_regular(BOOTSTRAP_JOURNAL).map_err(|e| io(&root.join(BOOTSTRAP_JOURNAL), e))? { return Ok(false); }
    let watermark: SnapshotWatermarkV1 = match read_json(&directory, root, WATERMARK_FILE) { Ok(value) => value, Err(error) if error.category == StableError::Io => return Ok(false), Err(error) => return Err(error) };
    let provenance: SnapshotManifestV1 = read_json(&directory, root, PROVENANCE_FILE)?;
    Ok(watermark.state_root == installed_state_root && provenance.state_root == installed_state_root && watermark.payload_sha256 == provenance.payload_sha256)
}

fn enforce_monotonic(directory: &TrustDir, root: &Path, candidate: &SnapshotWatermarkV1) -> FormatResult<()> {
    if !directory.contains_regular(WATERMARK_FILE).map_err(|e| io(&root.join(WATERMARK_FILE), e))? { return Ok(()); }
    let current: SnapshotWatermarkV1 = read_json(directory, root, WATERMARK_FILE)?;
    if candidate.trust_store_version < current.trust_store_version || candidate.height < current.height
        || (candidate.height == current.height && (candidate.block_id != current.block_id || candidate.state_root != current.state_root)) {
        return Err(rejected("snapshot anti-rollback watermark rejected candidate"));
    }
    Ok(())
}

fn descriptor_digest(descriptor: &SnapshotDescriptor) -> String {
    let mut hash = Sha256::new(); hash.update(b"TRON-SNAPSHOT-DESCRIPTOR-V1");
    for value in [&descriptor.identity.network, &descriptor.identity.genesis, &descriptor.backend, &descriptor.backend_format, &descriptor.state_root, &descriptor.payload_sha256] {
        hash.update((value.len() as u64).to_be_bytes()); hash.update(value.as_bytes());
    }
    hash.update(descriptor.schema_version.to_be_bytes()); hash.update(descriptor.generation.to_be_bytes()); hash.update(descriptor.payload_size.to_be_bytes());
    hash.update((descriptor.authentication_envelope.len() as u64).to_be_bytes()); hash.update(&descriptor.authentication_envelope);
    hex(&hash.finalize())
}

const MAX_TRUST_STATE_BYTES: u64 = 1024 * 1024;
const O_NOFOLLOW: i32 = 0o400000;
const O_DIRECTORY: i32 = 0o200000;
const O_CLOEXEC: i32 = 0o2000000;

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity { dev: u64, ino: u64 }

struct TrustDir { fd: File }

impl TrustDir {
    fn open(path: &Path) -> std::io::Result<Self> { Self::walk(path, false) }
    fn open_or_create(path: &Path) -> std::io::Result<Self> { Self::walk(path, true) }
    fn walk(path: &Path, create_final: bool) -> std::io::Result<Self> {
        if path.components().any(|part| matches!(part, Component::ParentDir | Component::Prefix(_))) { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "parent path components are forbidden")); }
        let absolute = if path.is_absolute() { path.to_owned() } else { std::env::current_dir()?.join(path) };
        let parts = absolute.components().filter_map(|part| if let Component::Normal(name) = part { Some(name.to_owned()) } else { None }).collect::<Vec<_>>();
        if parts.is_empty() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "trust directory cannot be filesystem root")); }
        let mut fd = Self::dir_options().open("/")?;
        for (index, name) in parts.iter().enumerate() {
            let candidate = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())).join(name);
            let final_part = index + 1 == parts.len();
            fd = match Self::dir_options().open(&candidate) {
                Ok(next) => next,
                Err(error) if create_final && final_part && error.kind() == std::io::ErrorKind::NotFound => {
                    match rustix::fs::mkdirat(&fd, name, rustix::fs::Mode::RWXU) { Ok(()) | Err(rustix::io::Errno::EXIST) => {}, Err(error) => return Err(error.into()) }
                    Self::dir_options().open(&candidate)?
                }
                Err(error) => return Err(error),
            };
        }
        let metadata = fd.metadata()?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o777 != 0o700 || metadata.nlink() < 2 { return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "trust directory must be owned by the effective uid with mode 0700")); }
        Ok(Self { fd })
    }
    fn dir_options() -> OpenOptions { let mut options = OpenOptions::new(); options.read(true).custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); options }
    fn open_regular(&self, name: &str) -> std::io::Result<(File, FileIdentity)> {
        let fd = rustix::fs::openat(&self.fd, name, rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK, rustix::fs::Mode::empty())?;
        let file = File::from(fd); let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1 || metadata.len() > MAX_TRUST_STATE_BYTES { return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "trust state must be a bounded, private, singly-linked regular file")); }
        Ok((file, FileIdentity { dev: metadata.dev(), ino: metadata.ino() }))
    }
    fn contains_regular(&self, name: &str) -> std::io::Result<bool> { match self.open_regular(name) { Ok(_) => Ok(true), Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false), Err(error) => Err(error) } }
    fn temp_file(&self, target: &str) -> std::io::Result<(OsString, File)> {
        let mut random = File::open("/dev/urandom")?;
        for _ in 0..128 { let mut bytes = [0u8; 16]; random.read_exact(&mut bytes)?; let name = OsString::from(format!(".{target}.{}.tmp", hex(&bytes))); match rustix::fs::openat(&self.fd, &name, rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR) { Ok(fd) => return Ok((name, File::from(fd))), Err(rustix::io::Errno::EXIST) => {}, Err(error) => return Err(error.into()) } }
        Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "unable to allocate unpredictable temporary trust file"))
    }
    fn identity(&self, name: &OsStr) -> std::io::Result<FileIdentity> { let metadata = rustix::fs::statat(&self.fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?; Ok(FileIdentity { dev: metadata.st_dev, ino: metadata.st_ino }) }
    fn install(&self, target: &str, temporary: &OsStr, expected: Option<FileIdentity>) -> std::io::Result<()> {
        match expected {
            None => rustix::fs::renameat_with(&self.fd, temporary, &self.fd, target, rustix::fs::RenameFlags::NOREPLACE).map_err(Into::into),
            Some(identity) => {
                rustix::fs::renameat_with(&self.fd, temporary, &self.fd, target, rustix::fs::RenameFlags::EXCHANGE)?;
                if self.identity(temporary)? != identity {
                    rustix::fs::renameat_with(&self.fd, temporary, &self.fd, target, rustix::fs::RenameFlags::EXCHANGE)?;
                    return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "trust state target changed before atomic replacement"));
                }
                rustix::fs::unlinkat(&self.fd, temporary, rustix::fs::AtFlags::empty()).map_err(Into::into)
            }
        }
    }
    fn remove_checked(&self, name: &str) -> std::io::Result<()> {
        let (_, expected) = self.open_regular(name)?;
        let (temporary, file) = self.temp_file(name)?;
        file.sync_all()?;
        rustix::fs::renameat_with(&self.fd, &temporary, &self.fd, name, rustix::fs::RenameFlags::EXCHANGE)?;
        if self.identity(&temporary)? != expected {
            rustix::fs::renameat_with(&self.fd, &temporary, &self.fd, name, rustix::fs::RenameFlags::EXCHANGE)?;
            let _ = rustix::fs::unlinkat(&self.fd, &temporary, rustix::fs::AtFlags::empty());
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "trust state changed before removal"));
        }
        rustix::fs::unlinkat(&self.fd, &temporary, rustix::fs::AtFlags::empty())?;
        rustix::fs::unlinkat(&self.fd, name, rustix::fs::AtFlags::empty())?;
        Ok(())
    }
    fn sync(&self) -> std::io::Result<()> { self.fd.sync_all() }
}

fn install_json<T: Serialize>(directory: &TrustDir, root: &Path, name: &str, value: &T) -> FormatResult<()> {
    let bytes = serde_json::to_vec(value).map_err(|e| rejected(&e.to_string()))?;
    if bytes.len() as u64 > MAX_TRUST_STATE_BYTES { return Err(integrity(&root.join(name), "trust state exceeds size limit")); }
    let expected = match directory.open_regular(name) { Ok((_, identity)) => Some(identity), Err(error) if error.kind() == std::io::ErrorKind::NotFound => None, Err(error) => return Err(io(&root.join(name), error)) };
    let (temporary, mut file) = directory.temp_file(name).map_err(|e| io(root, e))?;
    let result = (|| { file.write_all(&bytes)?; file.sync_all()?; directory.install(name, &temporary, expected)?; directory.sync() })();
    if result.is_err() { let _ = rustix::fs::unlinkat(&directory.fd, &temporary, rustix::fs::AtFlags::empty()); }
    result.map_err(|e| io(&root.join(name), e))
}
fn read_json<T: for<'de> Deserialize<'de>>(directory: &TrustDir, root: &Path, name: &str) -> FormatResult<T> { let path = root.join(name); let (file, _) = directory.open_regular(name).map_err(|e| io(&path, e))?; let mut bytes = Vec::new(); file.take(MAX_TRUST_STATE_BYTES + 1).read_to_end(&mut bytes).map_err(|e| io(&path, e))?; if bytes.len() as u64 > MAX_TRUST_STATE_BYTES { return Err(integrity(&path, "trust state exceeds size limit")); } serde_json::from_slice(&bytes).map_err(|e| integrity(&path, &e.to_string())) }
fn auth_error(error: impl std::fmt::Display) -> FormatError { FormatError::new(StableError::SnapshotUnauthenticated, PathBuf::from("snapshot authentication"), error.to_string()) }
fn rejected(detail: &str) -> FormatError { FormatError::new(StableError::SnapshotUnauthenticated, PathBuf::from("snapshot manifest"), detail) }
fn integrity(path: &Path, detail: &str) -> FormatError { FormatError::new(StableError::Integrity, path, detail) }
fn io(path: &Path, error: std::io::Error) -> FormatError { FormatError::new(StableError::Io, path, error.to_string()) }
fn is_nonzero_sha256(value: &str) -> bool { value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) && value.bytes().any(|byte| byte != b'0') }
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }

#[cfg(test)]
mod filesystem_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root(label: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("tron-snapshot-trust-{label}-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn planted_symlink_and_hardlink_are_rejected_for_every_trust_phase() {
        for name in [BOOTSTRAP_JOURNAL, PROVENANCE_FILE, WATERMARK_FILE] {
            let directory_path = root("redirect");
            let victim = directory_path.with_extension("victim");
            std::fs::write(&victim, b"do-not-touch").unwrap();
            symlink(&victim, directory_path.join(name)).unwrap();
            let directory = TrustDir::open(&directory_path).unwrap();
            assert!(install_json(&directory, &directory_path, name, &serde_json::json!({"phase":"attack"})).is_err());
            assert_eq!(std::fs::read(&victim).unwrap(), b"do-not-touch");
            std::fs::remove_file(directory_path.join(name)).unwrap();
            let source = directory_path.join("linked-source");
            std::fs::write(&source, b"private").unwrap();
            std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::hard_link(&source, directory_path.join(name)).unwrap();
            assert!(install_json(&directory, &directory_path, name, &serde_json::json!({"phase":"attack"})).is_err());
            assert_eq!(std::fs::read(&source).unwrap(), b"private");
            std::fs::remove_dir_all(&directory_path).unwrap();
            std::fs::remove_file(victim).unwrap();
        }
    }

    #[test]
    fn inode_swap_is_detected_and_rolled_back_for_every_trust_phase() {
        for target in [BOOTSTRAP_JOURNAL, PROVENANCE_FILE, WATERMARK_FILE] {
            let directory_path = root("swap");
            let directory = TrustDir::open(&directory_path).unwrap();
            std::fs::write(directory_path.join(target), b"original").unwrap();
            std::fs::set_permissions(directory_path.join(target), std::fs::Permissions::from_mode(0o600)).unwrap();
            let (_, expected) = directory.open_regular(target).unwrap();
            let (temporary, mut file) = directory.temp_file(target).unwrap();
            file.write_all(b"replacement").unwrap(); file.sync_all().unwrap();
            let displaced = directory_path.join("displaced");
            std::fs::rename(directory_path.join(target), &displaced).unwrap();
            std::fs::write(directory_path.join(target), b"intruder").unwrap();
            std::fs::set_permissions(directory_path.join(target), std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(directory.install(target, &temporary, Some(expected)).is_err());
            assert_eq!(std::fs::read(directory_path.join(target)).unwrap(), b"intruder");
            assert_eq!(std::fs::read(displaced).unwrap(), b"original");
            std::fs::remove_dir_all(directory_path).unwrap();
        }
    }

    #[test]
    fn acceptance_publish_and_recovery_remain_atomic_and_monotonic() {
        let directory_path = root("lifecycle");
        let descriptor = SnapshotDescriptor { identity: tron_storage::StorageIdentity { network: "mainnet".into(), genesis: "genesis".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), generation: 7, state_root: "22".repeat(32), payload_sha256: "33".repeat(32), payload_size: 10, authentication_envelope: vec![] };
        let manifest = SnapshotManifestV1 { schema: "tron-snapshot-manifest-v1".into(), network: "mainnet".into(), genesis: "genesis".into(), schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), generation: 7, height: 100, block_id: "11".repeat(32), state_root: descriptor.state_root.clone(), stores: vec!["account".into()], payload_sha256: descriptor.payload_sha256.clone(), payload_size: 10, created_at: "2026-01-01T00:00:00Z".into() };
        let journal = begin_snapshot_acceptance(&directory_path, &descriptor, &manifest, 9).unwrap();
        assert!(!snapshot_acceptance_ready(&directory_path, &manifest.state_root).unwrap());
        publish_snapshot_acceptance(&directory_path, &journal, &manifest).unwrap();
        assert!(snapshot_acceptance_ready(&directory_path, &manifest.state_root).unwrap());
        let mut lower = manifest.clone(); lower.height = 99;
        assert!(begin_snapshot_acceptance(&directory_path, &descriptor, &lower, 9).is_err());

        let recovery_path = root("recovery");
        let recovery_dir = TrustDir::open(&recovery_path).unwrap();
        let mut imported = journal.clone(); imported.phase = "imported".into();
        install_json(&recovery_dir, &recovery_path, BOOTSTRAP_JOURNAL, &imported).unwrap();
        install_json(&recovery_dir, &recovery_path, PROVENANCE_FILE, &manifest).unwrap();
        assert!(recover_snapshot_acceptance(&recovery_path, &manifest.state_root).unwrap());
        assert!(snapshot_acceptance_ready(&recovery_path, &manifest.state_root).unwrap());
        std::fs::remove_dir_all(directory_path).unwrap();
        std::fs::remove_dir_all(recovery_path).unwrap();
    }
}
