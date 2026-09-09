//! Offline, bounded release verification and retained-slot installation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tron_crypto::artifact_auth::{self, AuthLimits, DsseEnvelope, RoleName, TrustStoreV1};

pub const RELEASE_PAYLOAD_TYPE: &str = "application/vnd.tron.release-manifest.v1+json";
pub const PROVENANCE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_FILES: usize = 4096;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ReleaseId(String);

impl ReleaseId {
    pub fn parse(value: &str) -> Result<Self, ReleaseError> {
        let bytes = value.as_bytes();
        let first_is_alphanumeric = bytes.first().is_some_and(u8::is_ascii_alphanumeric);
        let rest_is_canonical = bytes.iter().skip(1).all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if bytes.len() > 128 || !first_is_alphanumeric || !rest_is_canonical {
            return Err(ReleaseError::Malformed("release ID is not canonical"));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

impl std::str::FromStr for ReleaseId {
    type Err = ReleaseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> { Self::parse(value) }
}

impl fmt::Display for ReleaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { formatter.write_str(self.as_str()) }
}

impl AsRef<std::ffi::OsStr> for ReleaseId {
    fn as_ref(&self) -> &std::ffi::OsStr { self.as_str().as_ref() }
}

impl<'de> Deserialize<'de> for ReleaseId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifestV1 {
    pub schema: String,
    pub release_id: ReleaseId,
    pub version: String,
    pub release_sequence: u64,
    pub channel: String,
    pub source_revision: String,
    pub source_date_epoch: i64,
    pub install_prefix: PathBuf,
    pub current_target: PathBuf,
    pub config_root: PathBuf,
    pub receipt_path: PathBuf,
    pub production_materials: Vec<ProductionMaterial>,
    pub platforms: Vec<PlatformRecord>,
    pub artifacts: Vec<ArtifactRecord>,
    pub operator_inputs: Vec<OperatorInputPolicy>,
    pub compatibility: ReleaseCompatibility,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionMaterial {
    pub name: String,
    pub sha256: String,
    pub version: String,
    pub license: String,
    pub provenance: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformRecord {
    pub platform_id: String,
    pub os: String,
    pub architecture: String,
    pub target: String,
    pub backend: String,
    pub backend_format: String,
    pub features: Vec<String>,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    pub logical_name: String,
    pub path: String,
    pub kind: String,
    pub platform_id: String,
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
    pub media_type: String,
    pub release_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorInputPolicy {
    pub kind: String,
    pub size: u64,
    pub blake2b_512: String,
    pub included: bool,
    pub redistribution_rights: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseCompatibility {
    pub minimum_sequence: u64,
    pub native_resources: Vec<String>,
}

pub trait ReleaseClock { fn now(&self) -> OffsetDateTime; }
#[derive(Clone, Copy, Debug)]
pub struct FixedReleaseClock(pub OffsetDateTime);
impl ReleaseClock for FixedReleaseClock { fn now(&self) -> OffsetDateTime { self.0 } }
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemReleaseClock;
impl ReleaseClock for SystemReleaseClock {
    fn now(&self) -> OffsetDateTime {
        let duration = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        OffsetDateTime::from_unix_timestamp_nanos(duration.as_nanos() as i128).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }
}

pub trait ReleaseFs {
    fn read_bounded(&self, path: &Path, max: u64) -> Result<Vec<u8>, ReleaseError>;
    fn inventory(&self, root: &Path, max_files: usize) -> Result<BTreeMap<String, FileFact>, ReleaseError>;
}
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalReleaseFs;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileFact { pub path: PathBuf, pub size: u64, pub mode: u32 }

impl ReleaseFs for LocalReleaseFs {
    fn read_bounded(&self, path: &Path, max: u64) -> Result<Vec<u8>, ReleaseError> {
        let meta = fs::symlink_metadata(path).map_err(ReleaseError::fs)?;
        if !meta.file_type().is_file() { return Err(ReleaseError::Filesystem("non-regular or symlink input")); }
        if meta.len() > max { return Err(ReleaseError::Limit); }
        let file = OpenOptions::new().read(true).custom_flags(libc_o_nofollow()).open(path).map_err(ReleaseError::fs)?;
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        file.take(max + 1).read_to_end(&mut bytes).map_err(ReleaseError::fs)?;
        if bytes.len() as u64 > max { return Err(ReleaseError::Limit); }
        Ok(bytes)
    }

    fn inventory(&self, root: &Path, max_files: usize) -> Result<BTreeMap<String, FileFact>, ReleaseError> {
        let meta = fs::metadata(root).map_err(ReleaseError::fs)?;
        if !meta.is_dir() { return Err(ReleaseError::Filesystem("bundle is not a directory")); }
        let mut out = BTreeMap::new();
        walk(root, root, max_files, &mut out)?;
        Ok(out)
    }
}

fn libc_o_nofollow() -> i32 { 0o400000 }

fn walk(root: &Path, dir: &Path, max: usize, out: &mut BTreeMap<String, FileFact>) -> Result<(), ReleaseError> {
    let mut entries = fs::read_dir(dir).map_err(ReleaseError::fs)?.collect::<Result<Vec<_>, _>>().map_err(ReleaseError::fs)?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(ReleaseError::fs)?;
        if meta.file_type().is_symlink() { return Err(ReleaseError::Filesystem("symlink in bundle")); }
        if meta.is_dir() { walk(root, &path, max, out)?; continue; }
        if !meta.is_file() { return Err(ReleaseError::Filesystem("non-regular bundle member")); }
        if out.len() >= max { return Err(ReleaseError::Limit); }
        let rel = path.strip_prefix(root).map_err(|_| ReleaseError::Filesystem("path escape"))?;
        let name = normalized_relative(rel)?;
        if out.insert(name, FileFact { path, size: meta.len(), mode: meta.permissions().mode() & 0o7777 }).is_some() {
            return Err(ReleaseError::Inventory("duplicate member"));
        }
    }
    Ok(())
}

pub struct VerifyBundleRequest<'a> {
    pub trust_store: &'a [u8],
    pub manifest_envelope: &'a [u8],
    pub bundle: &'a Path,
    pub platform_id: &'a str,
    pub minimum_sequence: u64,
    pub channel: &'a str,
    pub fs: &'a dyn ReleaseFs,
    pub clock: &'a dyn ReleaseClock,
    pub limits: AuthLimits,
}

#[derive(Debug)]
pub struct VerifiedRelease {
    manifest: ReleaseManifestV1,
    manifest_digest: String,
    files: Vec<VerifiedFile>,
}
impl VerifiedRelease {
    pub fn manifest(&self) -> &ReleaseManifestV1 { &self.manifest }
    pub fn manifest_digest(&self) -> &str { &self.manifest_digest }
}
#[derive(Debug)]
struct VerifiedFile { source: PathBuf, handle: File, device: u64, inode: u64, relative: String, mode: u32, digest: String, size: u64 }

#[derive(Debug)]
pub struct RetainedReleaseInput {
    handle: File,
    size: u64,
    mode: u32,
}

impl RetainedReleaseInput {
    pub fn open(path: &Path, max: u64) -> Result<Self, ReleaseError> {
        let handle = OpenOptions::new().read(true).custom_flags(libc_o_nofollow()).open(path).map_err(ReleaseError::fs)?;
        let metadata = handle.metadata().map_err(ReleaseError::fs)?;
        if !metadata.is_file() { return Err(ReleaseError::Filesystem("publication input is not a regular file")); }
        if metadata.len() > max { return Err(ReleaseError::Limit); }
        Ok(Self { handle, size: metadata.len(), mode: metadata.permissions().mode() & 0o7777 })
    }

    pub fn read(&self, max: u64) -> Result<Vec<u8>, ReleaseError> {
        let mut handle = self.handle.try_clone().map_err(ReleaseError::fs)?;
        handle.seek(SeekFrom::Start(0)).map_err(ReleaseError::fs)?;
        read_handle_bounded(&mut handle, max)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublicationObjectV1 {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
    pub authentication: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublicationInventoryV1 {
    pub schema: String,
    pub release_id: String,
    pub channel: String,
    pub release_sequence: u64,
    pub source_revision: String,
    pub manifest_sha256: String,
    pub objects: Vec<PublicationObjectV1>,
}

pub struct StagePublicationRequest<'a> {
    pub staging: &'a Path,
    pub manifest_name: &'a str,
    pub manifest_envelope: &'a RetainedReleaseInput,
    pub trust_update_name: Option<&'a str>,
    pub trust_update: Option<&'a RetainedReleaseInput>,
}

pub fn stage_verified_publication(verified: &VerifiedRelease, request: StagePublicationRequest<'_>) -> Result<PublicationInventoryV1, ReleaseError> {
    if request.staging.exists() { return Err(ReleaseError::Filesystem("publication staging already exists")); }
    fs::create_dir(request.staging).map_err(ReleaseError::fs)?;
    fs::set_permissions(request.staging, fs::Permissions::from_mode(0o700)).map_err(ReleaseError::fs)?;
    let result = (|| {
        let mut objects = Vec::with_capacity(verified.files.len() + 2);
        stage_retained(request.manifest_envelope, request.staging, request.manifest_name, "threshold-signed release manifest", &mut objects)?;
        match (request.trust_update_name, request.trust_update) {
            (Some(name), Some(input)) => stage_retained(input, request.staging, name, "root-threshold-signed trust update", &mut objects)?,
            (None, None) => {}
            _ => return Err(ReleaseError::Usage("trust update name and input must be supplied together")),
        }
        for file in &verified.files {
            let relative = format!("bundle/{}", file.relative);
            let dest = request.staging.join(&relative);
            if let Some(parent) = dest.parent() { create_private_dirs(request.staging, parent)?; }
            let mut src = file.handle.try_clone().map_err(ReleaseError::fs)?;
            src.seek(SeekFrom::Start(0)).map_err(ReleaseError::fs)?;
            let mut dst = OpenOptions::new().write(true).create_new(true).mode(file.mode & 0o555).open(&dest).map_err(ReleaseError::fs)?;
            let (size, digest) = copy_and_hash(&mut src, &mut dst, MAX_FILE_BYTES)?;
            dst.sync_all().map_err(ReleaseError::fs)?;
            if size != file.size || digest != file.digest { return Err(ReleaseError::Digest(file.relative.clone())); }
            objects.push(PublicationObjectV1 { path: relative, sha256: digest, size, mode: file.mode & 0o555, authentication: "release-manifest artifact digest".into() });
        }
        objects.sort_by(|a,b| a.path.cmp(&b.path));
        let inventory = PublicationInventoryV1 { schema: "tron-publication-inventory-v1".into(), release_id: verified.manifest.release_id.to_string(), channel: verified.manifest.channel.clone(), release_sequence: verified.manifest.release_sequence, source_revision: verified.manifest.source_revision.clone(), manifest_sha256: verified.manifest_digest.clone(), objects };
        let inventory_path = request.staging.join("publication-inventory.json");
        let bytes = serde_json::to_vec(&inventory).map_err(|_| ReleaseError::Malformed("publication inventory serialization failed"))?;
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o400).open(&inventory_path).map_err(ReleaseError::fs)?;
        file.write_all(&bytes).and_then(|_| file.sync_all()).map_err(ReleaseError::fs)?;
        sync_tree_dirs(request.staging)?;
        Ok(inventory)
    })();
    if result.is_err() { let _ = fs::remove_dir_all(request.staging); }
    result
}

fn stage_retained(input: &RetainedReleaseInput, root: &Path, name: &str, authentication: &str, objects: &mut Vec<PublicationObjectV1>) -> Result<(), ReleaseError> {
    normalized_relative(Path::new(name))?;
    let dest = root.join(name);
    if let Some(parent) = dest.parent() { create_private_dirs(root, parent)?; }
    let mut src = input.handle.try_clone().map_err(ReleaseError::fs)?;
    src.seek(SeekFrom::Start(0)).map_err(ReleaseError::fs)?;
    let mode = input.mode & 0o555;
    let mut dst = OpenOptions::new().write(true).create_new(true).mode(mode).open(&dest).map_err(ReleaseError::fs)?;
    let (size, digest) = copy_and_hash(&mut src, &mut dst, MAX_FILE_BYTES)?;
    dst.sync_all().map_err(ReleaseError::fs)?;
    if size != input.size { return Err(ReleaseError::Filesystem("retained publication input changed size")); }
    objects.push(PublicationObjectV1 { path: name.into(), sha256: digest, size, mode, authentication: authentication.into() });
    Ok(())
}

fn create_private_dirs(root: &Path, parent: &Path) -> Result<(), ReleaseError> {
    let relative = parent.strip_prefix(root).map_err(|_| ReleaseError::Filesystem("publication path escape"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) { return Err(ReleaseError::Filesystem("unsafe publication directory")); }
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).map_err(ReleaseError::fs)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(ReleaseError::fs(error)),
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct InstallRequest<'a> {
    pub prefix: &'a Path,
    pub config_root: &'a Path,
    pub receipt: &'a Path,
    pub retained_slots: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InstallReceiptV1 {
    pub schema: String,
    pub release_id: String,
    pub release_sequence: u64,
    pub platform_id: String,
    pub manifest_sha256: String,
    pub install_prefix: PathBuf,
    pub current_target: PathBuf,
    pub config_root: PathBuf,
    pub config_current_target: PathBuf,
    pub receipt_path: PathBuf,
    pub installed_at: String,
    pub files: Vec<ReceiptFile>,
    pub config_files: Vec<ReceiptFile>,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptFile { pub path: String, pub sha256: String, pub size: u64, pub mode: u32 }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseError {
    Usage(&'static str), Malformed(&'static str), Authentication(String), Limit,
    Inventory(&'static str), Digest(String), Metadata(&'static str), Platform(&'static str),
    Rollback, Filesystem(&'static str), Io(String),
}
impl ReleaseError {
    fn fs(error: std::io::Error) -> Self { Self::Io(error.to_string()) }
    pub fn exit_code(&self) -> i32 { match self { Self::Usage(_) | Self::Malformed(_) => 2, Self::Authentication(_) => 10, Self::Inventory(_) | Self::Digest(_) | Self::Limit => 11, Self::Metadata(_) => 12, Self::Platform(_) | Self::Rollback => 13, Self::Filesystem(_) | Self::Io(_) => 14 } }
}
impl fmt::Display for ReleaseError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { match self { Self::Usage(s)|Self::Malformed(s)|Self::Inventory(s)|Self::Metadata(s)|Self::Platform(s)|Self::Filesystem(s)=>f.write_str(s), Self::Authentication(s)|Self::Digest(s)|Self::Io(s)=>f.write_str(s), Self::Limit=>f.write_str("release verification limit exceeded"), Self::Rollback=>f.write_str("release rollback rejected") } } }
impl std::error::Error for ReleaseError {}

pub fn verify_bundle(request: VerifyBundleRequest<'_>) -> Result<VerifiedRelease, ReleaseError> {
    let trust = artifact_auth::parse_trust_store(request.trust_store, request.limits).map_err(auth)?;
    let envelope = DsseEnvelope::parse(request.manifest_envelope, request.limits).map_err(auth)?;
    let untrusted_payload = envelope.payload_bytes(request.limits).map_err(auth)?;
    let untrusted_manifest: ReleaseManifestV1 = serde_json::from_slice(&untrusted_payload).map_err(|_| ReleaseError::Malformed("malformed release manifest"))?;
    let scope = canonical_release_scope(&untrusted_manifest.channel)?;
    let role = RoleName::release(&untrusted_manifest.channel).map_err(auth)?;
    let verified = artifact_auth::verify_dsse_scoped(&envelope, RELEASE_PAYLOAD_TYPE, &trust, &role, &scope, request.clock.now(), request.limits).map_err(auth)?;
    let manifest: ReleaseManifestV1 = serde_json::from_slice(&verified.payload).map_err(|_| ReleaseError::Malformed("malformed release manifest"))?;
    validate_manifest(&manifest, request.platform_id, request.channel, request.minimum_sequence)?;
    let inventory = request.fs.inventory(request.bundle, MAX_FILES)?;
    let expected: BTreeSet<_> = manifest.artifacts.iter().map(|a| a.path.as_str()).collect();
    let actual: BTreeSet<_> = inventory.keys().map(String::as_str).collect();
    if expected != actual { return Err(ReleaseError::Inventory("bundle file set differs from manifest")); }
    let mut files = Vec::with_capacity(manifest.artifacts.len());
    for artifact in &manifest.artifacts {
        let fact = inventory.get(&artifact.path).ok_or(ReleaseError::Inventory("missing artifact"))?;
        if fact.size != artifact.size || fact.mode != artifact.mode { return Err(ReleaseError::Inventory("artifact size or mode differs")); }
        let mut handle = OpenOptions::new().read(true).custom_flags(libc_o_nofollow()).open(&fact.path).map_err(ReleaseError::fs)?;
        let metadata = handle.metadata().map_err(ReleaseError::fs)?;
        if !metadata.is_file() || metadata.len() != fact.size || metadata.permissions().mode() & 0o7777 != fact.mode { return Err(ReleaseError::Inventory("artifact changed while opening")); }
        let bytes = read_handle_bounded(&mut handle, MAX_FILE_BYTES)?;
        let digest = sha256(&bytes);
        if digest != artifact.sha256 { return Err(ReleaseError::Digest(artifact.path.clone())); }
        validate_metadata(artifact, &bytes, &manifest, &trust, request.clock.now(), request.limits)?;
        handle.seek(SeekFrom::Start(0)).map_err(ReleaseError::fs)?;
        files.push(VerifiedFile { source: fact.path.clone(), device: metadata.dev(), inode: metadata.ino(), handle, relative: artifact.path.clone(), mode: artifact.mode, digest, size: artifact.size });
    }
    Ok(VerifiedRelease { manifest, manifest_digest: sha256(&verified.payload), files })
}

fn validate_manifest(m: &ReleaseManifestV1, platform: &str, channel: &str, minimum: u64) -> Result<(), ReleaseError> {
    canonical_release_scope(&m.channel)?;
    canonical_release_scope(channel)?;
    if m.channel != channel { return Err(ReleaseError::Metadata("release channel differs from requested channel")); }
    validate_install_topology(&m.install_prefix, &m.current_target, &m.config_root, &m.receipt_path)?;
    if m.schema != "tron-release-manifest-v1" || m.release_sequence < minimum || m.release_sequence < m.compatibility.minimum_sequence { return Err(ReleaseError::Rollback); }
    if !is_hex(&m.source_revision, 40) { return Err(ReleaseError::Malformed("source revision is not a canonical Git SHA-1")); }
    if m.production_materials.len() != 1 {
        return Err(ReleaseError::Inventory("production executable materials must be explicit"));
    }
    let material = &m.production_materials[0];
    if material.name != "busybox" || !is_hex(&material.sha256, 64) || material.version.is_empty() || material.license.is_empty() || material.provenance.is_empty() {
        return Err(ReleaseError::Inventory("production executable material is malformed"));
    }
    let enabled: Vec<_> = m.platforms.iter().filter(|p| p.enabled).collect();
    if enabled.len() != 1 || enabled[0].platform_id != platform { return Err(ReleaseError::Platform("platform is not the sole enabled release platform")); }
    let required: BTreeSet<_> = ["tron-fullnode", "tron-solidity", "tron-toolkit", "tron-release-verify", "native-archive", "config-archive", "oci-image", "sbom", "provenance"].into_iter().collect();
    let names: BTreeSet<_> = m.artifacts.iter().map(|a| a.logical_name.as_str()).collect();
    if !required.is_subset(&names) || names.len() != m.artifacts.len() || m.artifacts.iter().any(|a| !required.contains(a.logical_name.as_str()) && !matches!(a.kind.as_str(), "oci-blob" | "oci-manifest" | "configuration")) { return Err(ReleaseError::Inventory("required artifact set is incomplete, extra, or duplicated")); }
    let mut paths = BTreeSet::new();
    for a in &m.artifacts {
        normalized_relative(Path::new(&a.path))?;
        if !paths.insert(&a.path) || a.release_id != m.release_id.as_str() || a.platform_id != platform || a.size > MAX_FILE_BYTES || a.mode & !0o777 != 0 || !is_hex(&a.sha256, 64) { return Err(ReleaseError::Inventory("invalid, mixed, or duplicate artifact")); }
    }
    for input in &m.operator_inputs {
        if input.included || input.redistribution_rights != "not_asserted" || !is_hex(&input.blake2b_512, 128) { return Err(ReleaseError::Inventory("operator input was shipped or malformed")); }
    }
    Ok(())
}

fn validate_install_topology(prefix: &Path, current: &Path, config_root: &Path, receipt_path: &Path) -> Result<(), ReleaseError> {
    let canonical = |path: &Path| path.is_absolute() && !path.components().any(|component| matches!(component, std::path::Component::CurDir | std::path::Component::ParentDir));
    if !canonical(prefix) || !canonical(current) || !canonical(config_root) || !canonical(receipt_path) || current != prefix.join("current") {
        return Err(ReleaseError::Filesystem("install topology must use canonical absolute paths and prefix/current"));
    }
    Ok(())
}

fn validate_metadata(a: &ArtifactRecord, bytes: &[u8], m: &ReleaseManifestV1, trust: &TrustStoreV1, now: OffsetDateTime, limits: AuthLimits) -> Result<(), ReleaseError> {
    match a.kind.as_str() {
        "sbom" => validate_sbom(bytes, m),
        "provenance" => validate_provenance(bytes, m, trust, now, limits),
        "oci" | "oci-index" | "oci-manifest" => validate_oci_descriptor(bytes, m),
        _ => Ok(()),
    }
}

fn validate_sbom(bytes: &[u8], m: &ReleaseManifestV1) -> Result<(), ReleaseError> {
    #[derive(Deserialize)] struct Sbom { #[serde(rename="spdxVersion")] version: String, files: Vec<SbomFile>, #[serde(default)] packages: Vec<SbomPackage> }
    #[derive(Deserialize)] struct SbomFile { #[serde(rename="fileName")] name: String, checksums: Vec<Checksum> }
    #[derive(Deserialize)] struct SbomPackage { name: String }
    #[derive(Deserialize)] struct Checksum { algorithm: String, #[serde(rename="checksumValue")] value: String }
    let sbom: Sbom = serde_json::from_slice(bytes).map_err(|_| ReleaseError::Metadata("malformed SPDX SBOM"))?;
    if sbom.version != "SPDX-2.3" || sbom.packages.iter().any(|p| p.name.to_ascii_lowercase().contains("sapling")) { return Err(ReleaseError::Metadata("invalid SPDX SBOM")); }
    let got: BTreeMap<_, _> = sbom.files.into_iter().filter_map(|f| f.checksums.into_iter().find(|c| c.algorithm == "SHA256").map(|c| (f.name, c.value))).collect();
    let want: BTreeMap<_, _> = m.artifacts.iter().filter(|a| a.kind != "sbom" && a.kind != "provenance").map(|a| (a.path.clone(), a.sha256.clone())).collect();
    if got != want { return Err(ReleaseError::Metadata("SBOM subjects differ from release")); }
    Ok(())
}

fn validate_provenance(bytes: &[u8], m: &ReleaseManifestV1, trust: &TrustStoreV1, now: OffsetDateTime, limits: AuthLimits) -> Result<(), ReleaseError> {
    let env = DsseEnvelope::parse(bytes, limits).map_err(auth)?;
    let role = RoleName::new(format!("provenance:{}", m.platforms.iter().find(|p| p.enabled).ok_or(ReleaseError::Metadata("missing platform"))?.platform_id)).map_err(auth)?;
    let payload = artifact_auth::verify_dsse(&env, PROVENANCE_PAYLOAD_TYPE, trust, &role, now, limits).map_err(auth)?;
    #[derive(Deserialize)] struct Statement { #[serde(rename="_type")] kind: String, subject: Vec<Subject>, #[serde(rename="predicateType")] predicate_type: String, predicate: Predicate }
    #[derive(Deserialize)] struct Subject { name: String, digest: BTreeMap<String,String> }
    #[derive(Deserialize)] struct Predicate { #[serde(default)] materials: Vec<Material> }
    #[derive(Deserialize)] struct Material { uri: String, digest: BTreeMap<String,String> }
    let statement: Statement = serde_json::from_slice(&payload.payload).map_err(|_| ReleaseError::Metadata("malformed provenance"))?;
    if statement.kind != "https://in-toto.io/Statement/v1" || !statement.predicate_type.contains("slsa") { return Err(ReleaseError::Metadata("invalid provenance predicate")); }
    let got: BTreeMap<_,_> = statement.subject.into_iter().filter_map(|s| s.digest.get("sha256").cloned().map(|d|(s.name,d))).collect();
    let want: BTreeMap<_,_> = m.artifacts.iter().filter(|a| a.kind != "provenance").map(|a|(a.path.clone(),a.sha256.clone())).collect();
    let source_bound = statement.predicate.materials.iter().any(|material| material.uri == "git+urn:tron:source" && material.digest.get("gitCommit") == Some(&m.source_revision));
    if got != want || !source_bound || !statement.predicate.materials.iter().all(|x| !x.uri.is_empty() && !x.digest.is_empty()) { return Err(ReleaseError::Metadata("provenance binding differs from release")); }
    Ok(())
}

fn validate_oci_descriptor(bytes: &[u8], release: &ReleaseManifestV1) -> Result<(), ReleaseError> {
    #[derive(Deserialize)] struct Descriptor { #[serde(rename="schemaVersion")] schema_version: u32, #[serde(default)] manifests: Vec<OciRef>, #[serde(default)] config: Option<OciRef>, #[serde(default)] layers: Vec<OciRef> }
    #[derive(Deserialize)] struct OciRef { digest: String, size: u64 }
    let value: Descriptor = serde_json::from_slice(bytes).map_err(|_| ReleaseError::Metadata("malformed OCI descriptor"))?;
    if value.schema_version != 2 { return Err(ReleaseError::Metadata("invalid OCI descriptor")); }
    let mut refs = value.manifests;
    if let Some(config) = value.config { refs.push(config); }
    refs.extend(value.layers);
    if refs.is_empty() { return Err(ReleaseError::Metadata("empty OCI descriptor")); }
    for reference in refs {
        let digest = reference.digest.strip_prefix("sha256:").ok_or(ReleaseError::Metadata("non-SHA256 OCI descriptor"))?;
        if !is_hex(digest, 64) || reference.size == 0 { return Err(ReleaseError::Metadata("invalid OCI descriptor subject")); }
        let blob_path = format!("blobs/sha256/{digest}");
        let artifact = release.artifacts.iter().find(|a| a.path == blob_path).ok_or(ReleaseError::Metadata("OCI descriptor references an undeclared blob"))?;
        if artifact.sha256 != digest || artifact.size != reference.size { return Err(ReleaseError::Metadata("OCI blob binding differs from descriptor")); }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPhase { Staged, SlotPublished, ConfigSlotPublished, ConfigCurrentPublished, ReceiptPublished, CurrentPublished, Pruned }

pub trait InstallFault { fn after(&self, _phase: InstallPhase) -> Result<(), ReleaseError> { Ok(()) } }
#[derive(Clone, Copy, Debug, Default)]
pub struct NoInstallFault;
impl InstallFault for NoInstallFault {}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallJournal {
    schema: String,
    phase: InstallPhase,
    staging: PathBuf,
    slot: PathBuf,
    config_staging: PathBuf,
    config_slot: PathBuf,
    current: PathBuf,
    previous_current: Option<PathBuf>,
    config_current: PathBuf,
    previous_config_current: Option<PathBuf>,
    receipt_path: PathBuf,
    previous_receipt_sha256: Option<String>,
    retained_slots: usize,
    prune_slots: Vec<PathBuf>,
    prune_config_slots: Vec<PathBuf>,
    receipt: InstallReceiptV1,
}

pub fn install_verified(verified: &VerifiedRelease, request: InstallRequest<'_>, clock: &dyn ReleaseClock) -> Result<InstallReceiptV1, ReleaseError> {
    install_verified_with_fault(verified, request, clock, &NoInstallFault)
}

pub fn install_verified_with_fault(verified: &VerifiedRelease, request: InstallRequest<'_>, clock: &dyn ReleaseClock, fault: &dyn InstallFault) -> Result<InstallReceiptV1, ReleaseError> {
    validate_install_topology(request.prefix, &request.prefix.join("current"), request.config_root, request.receipt)?;
    if request.prefix != verified.manifest.install_prefix || request.prefix.join("current") != verified.manifest.current_target || request.config_root != verified.manifest.config_root || request.receipt != verified.manifest.receipt_path { return Err(ReleaseError::Filesystem("install request differs from signed topology")); }
    if request.retained_slots == 0 { return Err(ReleaseError::Usage("retained_slots must be nonzero")); }
    let releases = request.prefix.join("releases");
    let config_releases = request.config_root.join("releases");
    fs::create_dir_all(&releases).map_err(ReleaseError::fs)?;
    fs::create_dir_all(&config_releases).map_err(ReleaseError::fs)?;
    recover_install(request.prefix)?;
    let platform = verified.manifest.platforms.iter().find(|p| p.enabled).ok_or(ReleaseError::Platform("missing enabled platform"))?.platform_id.clone();
    if let Ok(existing) = fs::read(request.receipt) {
        if let Ok(receipt) = serde_json::from_slice::<InstallReceiptV1>(&existing) {
            if receipt.manifest_sha256 == verified.manifest_digest { verify_install(verified, &receipt, request.receipt, request.prefix.join("current").as_path(), &LocalReleaseFs)?; return Ok(receipt); }
            if receipt.release_sequence >= verified.manifest.release_sequence { return Err(ReleaseError::Rollback); }
        }
    }
    let slot = releases.join(verified.manifest.release_id.as_ref());
    let config_slot = config_releases.join(verified.manifest.release_id.as_ref());
    if slot.exists() || config_slot.exists() { return Err(ReleaseError::Filesystem("release slot already exists with different receipt")); }
    let suffix = format!(".{}.staging-{}", verified.manifest.release_id, std::process::id());
    let staging = releases.join(&suffix);
    let config_staging = config_releases.join(&suffix);
    for path in [&staging, &config_staging] { if path.exists() { fs::remove_dir_all(path).map_err(ReleaseError::fs)?; } fs::create_dir(path).map_err(ReleaseError::fs)?; }
    let mut receipt_files = Vec::new();
    let mut config_files = Vec::new();
    let build = (|| {
        for file in &verified.files {
            revalidate_source(file)?;
            let (root, relative, inventory) = if let Some(relative) = file.relative.strip_prefix("config/") { (&config_staging, relative, &mut config_files) } else { (&staging, file.relative.as_str(), &mut receipt_files) };
            if relative.is_empty() { return Err(ReleaseError::Inventory("configuration artifact has no filename")); }
            let dest = root.join(relative);
            if let Some(parent) = dest.parent() { fs::create_dir_all(parent).map_err(ReleaseError::fs)?; }
            let mut src = file.handle.try_clone().map_err(ReleaseError::fs)?;
            src.seek(SeekFrom::Start(0)).map_err(ReleaseError::fs)?;
            let mut dst = OpenOptions::new().write(true).create_new(true).mode(file.mode).open(&dest).map_err(ReleaseError::fs)?;
            let (size, digest) = copy_and_hash(&mut src, &mut dst, MAX_FILE_BYTES)?;
            dst.sync_all().map_err(ReleaseError::fs)?;
            if size != file.size || digest != file.digest || dst.metadata().map_err(ReleaseError::fs)?.permissions().mode() & 0o7777 != file.mode { return Err(ReleaseError::Digest(file.relative.clone())); }
            revalidate_source(file)?;
            inventory.push(ReceiptFile { path: relative.to_owned(), sha256: file.digest.clone(), size: file.size, mode: file.mode });
        }
        if config_files.is_empty() { return Err(ReleaseError::Inventory("release contains no signed configuration artifacts")); }
        sync_tree_dirs(&staging)?;
        sync_tree_dirs(&config_staging)?;
        Ok(())
    })();
    if let Err(error) = build { let _ = fs::remove_dir_all(&staging); let _ = fs::remove_dir_all(&config_staging); return Err(error); }
    let config_current = request.config_root.join("current");
    let current = request.prefix.join("current");
    let previous_current = read_optional_link(&current)?;
    let previous_config_current = read_optional_link(&config_current)?;
    let previous_receipt_sha256 = match fs::read(request.receipt) { Ok(bytes) => Some(sha256(&bytes)), Err(error) if error.kind() == std::io::ErrorKind::NotFound => None, Err(error) => return Err(ReleaseError::fs(error)) };
    let receipt = InstallReceiptV1 { schema: "tron-install-receipt-v1".into(), release_id: verified.manifest.release_id.to_string(), release_sequence: verified.manifest.release_sequence, platform_id: platform, install_prefix: verified.manifest.install_prefix.clone(), current_target: verified.manifest.current_target.clone(), config_root: verified.manifest.config_root.clone(), config_current_target: config_current.clone(), receipt_path: verified.manifest.receipt_path.clone(), manifest_sha256: verified.manifest_digest.clone(), installed_at: clock.now().format(&Rfc3339).map_err(|_| ReleaseError::Malformed("bad clock"))?, files: receipt_files, config_files };
    let prune_slots = plan_prune_slots(&releases, request.retained_slots)?;
    let prune_config_slots = plan_prune_slots(&config_releases, request.retained_slots)?;
    let mut journal = InstallJournal { schema: "tron-install-journal-v1".into(), phase: InstallPhase::Staged, staging, slot, config_staging, config_slot, current, previous_current, config_current, previous_config_current, receipt_path: request.receipt.to_path_buf(), previous_receipt_sha256, retained_slots: request.retained_slots, prune_slots, prune_config_slots, receipt: receipt.clone() };
    write_journal(request.prefix, &journal)?;
    if let Err(error) = advance_install(request.prefix, &mut journal, fault) { recover_install(request.prefix)?; return Err(error); }
    Ok(receipt)
}

pub fn recover_install(prefix: &Path) -> Result<(), ReleaseError> {
    let path = journal_path(prefix);
    let bytes = match fs::read(&path) { Ok(bytes) => bytes, Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()), Err(error) => return Err(ReleaseError::fs(error)) };
    let mut journal: InstallJournal = serde_json::from_slice(&bytes).map_err(|_| ReleaseError::Malformed("malformed install journal"))?;
    validate_install_topology(&journal.receipt.install_prefix, &journal.receipt.current_target, &journal.receipt.config_root, &journal.receipt.receipt_path)?;
    let config_releases = journal.receipt.config_root.join("releases");
    let release_parent = prefix.join("releases");
    if journal.schema != "tron-install-journal-v1" || journal.current != prefix.join("current") || journal.config_current != journal.receipt.config_root.join("current") || journal.receipt.config_current_target != journal.config_current || journal.receipt.install_prefix != prefix || journal.receipt.current_target != journal.current || journal.receipt.receipt_path != journal.receipt_path || journal.slot.parent() != Some(release_parent.as_path()) || journal.staging.parent() != Some(release_parent.as_path()) || journal.config_slot.parent() != Some(config_releases.as_path()) || journal.config_staging.parent() != Some(config_releases.as_path()) || journal.prune_slots.iter().any(|path| path.parent() != Some(release_parent.as_path()) || path == &journal.slot) || journal.prune_config_slots.iter().any(|path| path.parent() != Some(config_releases.as_path()) || path == &journal.config_slot) { return Err(ReleaseError::Filesystem("install journal is not bound to signed topology")); }
    advance_install(prefix, &mut journal, &NoInstallFault)
}

fn advance_install(prefix: &Path, journal: &mut InstallJournal, fault: &dyn InstallFault) -> Result<(), ReleaseError> {
    if journal.phase == InstallPhase::Staged {
        reconcile_slot(&journal.staging, &journal.slot, &journal.receipt.files)?;
        fault.after(InstallPhase::Staged)?;
        set_phase(prefix, journal, InstallPhase::SlotPublished)?;
    }
    if journal.phase == InstallPhase::SlotPublished {
        reconcile_slot(&journal.config_staging, &journal.config_slot, &journal.receipt.config_files)?;
        fault.after(InstallPhase::SlotPublished)?;
        set_phase(prefix, journal, InstallPhase::ConfigSlotPublished)?;
    }
    if journal.phase == InstallPhase::ConfigSlotPublished {
        verify_file_inventory(&journal.receipt.config_files, &journal.config_slot, &LocalReleaseFs)?;
        reconcile_current(&journal.config_slot, &journal.config_current, journal.previous_config_current.as_deref())?;
        fault.after(InstallPhase::ConfigSlotPublished)?;
        set_phase(prefix, journal, InstallPhase::ConfigCurrentPublished)?;
    }
    if journal.phase == InstallPhase::ConfigCurrentPublished {
        verify_file_inventory(&journal.receipt.files, &journal.slot, &LocalReleaseFs)?;
        reconcile_receipt(journal)?;
        fault.after(InstallPhase::ConfigCurrentPublished)?;
        set_phase(prefix, journal, InstallPhase::ReceiptPublished)?;
    }
    if journal.phase == InstallPhase::ReceiptPublished {
        reconcile_current(&journal.slot, &journal.current, journal.previous_current.as_deref())?;
        verify_install_receipt(&journal.receipt, &journal.receipt_path, &journal.current, &LocalReleaseFs)?;
        fault.after(InstallPhase::ReceiptPublished)?;
        set_phase(prefix, journal, InstallPhase::CurrentPublished)?;
    }
    if journal.phase == InstallPhase::CurrentPublished {
        reconcile_pruning(&journal.prune_slots)?;
        reconcile_pruning(&journal.prune_config_slots)?;
        verify_install_receipt(&journal.receipt, &journal.receipt_path, &journal.current, &LocalReleaseFs)?;
        fault.after(InstallPhase::CurrentPublished)?;
        set_phase(prefix, journal, InstallPhase::Pruned)?;
    }
    fault.after(InstallPhase::Pruned)?;
    fs::remove_file(journal_path(prefix)).map_err(ReleaseError::fs)?;
    sync_dir(prefix)?;
    Ok(())
}

fn reconcile_slot(staging: &Path, slot: &Path, files: &[ReceiptFile]) -> Result<(), ReleaseError> {
    match (staging.exists(), slot.exists()) {
        (true, false) => {
            verify_file_inventory(files, staging, &LocalReleaseFs)?;
            fs::rename(staging, slot).map_err(ReleaseError::fs)?;
            sync_dir(slot.parent().ok_or(ReleaseError::Filesystem("slot has no parent"))?)?;
            verify_file_inventory(files, slot, &LocalReleaseFs)
        }
        (false, true) => verify_file_inventory(files, slot, &LocalReleaseFs),
        _ => Err(ReleaseError::Filesystem("ambiguous release slot publication state")),
    }
}

fn read_optional_link(link: &Path) -> Result<Option<PathBuf>, ReleaseError> {
    match fs::read_link(link) {
        Ok(target) => Ok(Some(target)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ReleaseError::Filesystem("current selector is not a symbolic link")),
    }
}

fn reconcile_current(target: &Path, link: &Path, previous: Option<&Path>) -> Result<(), ReleaseError> {
    match read_optional_link(link)? {
        Some(found) if found == target => Ok(()),
        found if found.as_deref() == previous => atomic_symlink(target, link),
        _ => Err(ReleaseError::Filesystem("current selector changed during activation")),
    }
}

fn reconcile_receipt(journal: &InstallJournal) -> Result<(), ReleaseError> {
    let desired = serde_json::to_vec(&journal.receipt).map_err(|_| ReleaseError::Malformed("JSON serialization failed"))?;
    match fs::read(&journal.receipt_path) {
        Ok(bytes) if bytes == desired => Ok(()),
        Ok(bytes) if Some(sha256(&bytes)).as_ref() == journal.previous_receipt_sha256.as_ref() => write_atomic_json(&journal.receipt_path, &journal.receipt),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && journal.previous_receipt_sha256.is_none() => write_atomic_json(&journal.receipt_path, &journal.receipt),
        Ok(_) => Err(ReleaseError::Filesystem("receipt changed during activation")),
        Err(error) => Err(ReleaseError::fs(error)),
    }
}

fn plan_prune_slots(parent: &Path, retain: usize) -> Result<Vec<PathBuf>, ReleaseError> {
    let mut dirs = fs::read_dir(parent).map_err(ReleaseError::fs)?.filter_map(Result::ok).filter(|entry| entry.path().is_dir() && !entry.file_name().to_string_lossy().starts_with('.')).collect::<Vec<_>>();
    dirs.sort_by_key(|entry| entry.metadata().and_then(|metadata| metadata.modified()).ok());
    let remove = dirs.len().saturating_add(1).saturating_sub(retain);
    Ok(dirs.into_iter().take(remove).map(|entry| entry.path()).collect())
}

fn reconcile_pruning(paths: &[PathBuf]) -> Result<(), ReleaseError> {
    for path in paths {
        match fs::remove_dir_all(path) {
            Ok(()) => sync_dir(path.parent().ok_or(ReleaseError::Filesystem("slot has no parent"))?)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ReleaseError::fs(error)),
        }
    }
    Ok(())
}

pub fn verify_install(verified: &VerifiedRelease, receipt: &InstallReceiptV1, receipt_path: &Path, current: &Path, fs_api: &dyn ReleaseFs) -> Result<(), ReleaseError> {
    if receipt.manifest_sha256 != verified.manifest_digest
        || receipt.release_id != verified.manifest.release_id.as_str()
        || receipt.release_sequence != verified.manifest.release_sequence
        || receipt.platform_id != verified.manifest.platforms.iter().find(|platform| platform.enabled).ok_or(ReleaseError::Platform("missing enabled platform"))?.platform_id
        || receipt.install_prefix != verified.manifest.install_prefix
        || receipt.current_target != verified.manifest.current_target
        || receipt.config_root != verified.manifest.config_root
        || receipt.receipt_path != verified.manifest.receipt_path
    { return Err(ReleaseError::Authentication("install receipt differs from authenticated release".into())); }
    let mut files = Vec::new();
    let mut config_files = Vec::new();
    for artifact in &verified.manifest.artifacts {
        let (path, inventory) = if let Some(path) = artifact.path.strip_prefix("config/") { (path, &mut config_files) } else { (artifact.path.as_str(), &mut files) };
        inventory.push(ReceiptFile { path: path.to_owned(), sha256: artifact.sha256.clone(), size: artifact.size, mode: artifact.mode });
    }
    if receipt.files != files || receipt.config_files != config_files { return Err(ReleaseError::Authentication("install receipt inventory differs from authenticated release".into())); }
    verify_install_receipt(receipt, receipt_path, current, fs_api)
}

fn verify_install_receipt(receipt: &InstallReceiptV1, receipt_path: &Path, current: &Path, fs_api: &dyn ReleaseFs) -> Result<(), ReleaseError> {
    if receipt.schema != "tron-install-receipt-v1" { return Err(ReleaseError::Malformed("unknown receipt schema")); }
    validate_install_topology(&receipt.install_prefix, &receipt.current_target, &receipt.config_root, &receipt.receipt_path)?;
    if receipt.config_current_target != receipt.config_root.join("current") { return Err(ReleaseError::Filesystem("receipt config selector is not canonical")); }
    if receipt_path != receipt.receipt_path { return Err(ReleaseError::Filesystem("receipt was relocated")); }
    if current != receipt.current_target { return Err(ReleaseError::Filesystem("receipt is not bound to requested install target")); }
    verify_file_inventory(&receipt.files, &receipt.current_target, fs_api)?;
    verify_file_inventory(&receipt.config_files, &receipt.config_current_target, fs_api)
}

fn verify_file_inventory(files: &[ReceiptFile], root: &Path, fs_api: &dyn ReleaseFs) -> Result<(), ReleaseError> {
    let inventory = fs_api.inventory(root, MAX_FILES)?;
    let want: BTreeSet<_> = files.iter().map(|f| f.path.as_str()).collect();
    let got: BTreeSet<_> = inventory.keys().map(String::as_str).collect();
    if want != got { return Err(ReleaseError::Inventory("installed file set differs from receipt")); }
    for file in files {
        let fact = inventory.get(&file.path).ok_or(ReleaseError::Inventory("installed file missing"))?;
        if fact.size != file.size || fact.mode != file.mode || sha256(&fs_api.read_bounded(&fact.path, MAX_FILE_BYTES)?) != file.sha256 { return Err(ReleaseError::Digest(file.path.clone())); }
    }
    Ok(())
}

pub fn verify_trust_update(current: &[u8], candidate: &[u8], clock: &dyn ReleaseClock, limits: AuthLimits) -> Result<TrustStoreV1, ReleaseError> {
    let current = artifact_auth::parse_trust_store(current, limits).map_err(auth)?;
    let candidate = DsseEnvelope::parse(candidate, limits).map_err(auth)?;
    Ok(artifact_auth::verify_trust_store_update(&current, &candidate, clock.now(), limits).map_err(auth)?.trust_store)
}

fn write_atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ReleaseError> {
    let parent = path.parent().ok_or(ReleaseError::Filesystem("receipt has no parent"))?;
    fs::create_dir_all(parent).map_err(ReleaseError::fs)?;
    let tmp = parent.join(format!(".atomic-{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let bytes = serde_json::to_vec(value).map_err(|_| ReleaseError::Malformed("JSON serialization failed"))?;
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(ReleaseError::fs)?;
    file.write_all(&bytes).and_then(|_| file.sync_all()).map_err(ReleaseError::fs)?;
    fs::rename(&tmp, path).map_err(ReleaseError::fs)?;
    sync_dir(parent)
}
fn atomic_symlink(target: &Path, link: &Path) -> Result<(), ReleaseError> {
    let parent = link.parent().ok_or(ReleaseError::Filesystem("current link has no parent"))?;
    let tmp = parent.join(format!(".current-{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    symlink(target, &tmp).map_err(ReleaseError::fs)?;
    fs::rename(tmp, link).map_err(ReleaseError::fs)?;
    sync_dir(parent)
}
fn prune_slots(parent: &Path, retain: usize, current: &Path) -> Result<(), ReleaseError> {
    let mut dirs = fs::read_dir(parent).map_err(ReleaseError::fs)?.filter_map(Result::ok).filter(|e| e.path().is_dir() && !e.file_name().to_string_lossy().starts_with('.')).collect::<Vec<_>>();
    dirs.sort_by_key(|e| e.metadata().and_then(|m| m.modified()).ok());
    while dirs.len() > retain { let e = dirs.remove(0); if e.path() != current { fs::remove_dir_all(e.path()).map_err(ReleaseError::fs)?; } }
    Ok(())
}
fn canonical_release_scope(channel: &str) -> Result<String, ReleaseError> {
    if channel.is_empty() || channel.len() > 64 || !channel.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_')) {
        return Err(ReleaseError::Malformed("release channel is not canonical"));
    }
    Ok(format!("release:{channel}"))
}
fn read_handle_bounded(file: &mut File, max: u64) -> Result<Vec<u8>, ReleaseError> {
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes).map_err(ReleaseError::fs)?;
    if bytes.len() as u64 > max { return Err(ReleaseError::Limit); }
    Ok(bytes)
}
fn copy_and_hash(src: &mut File, dst: &mut File, max: u64) -> Result<(u64, String), ReleaseError> {
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = src.read(&mut buffer).map_err(ReleaseError::fs)?;
        if read == 0 { break; }
        total = total.checked_add(read as u64).ok_or(ReleaseError::Limit)?;
        if total > max { return Err(ReleaseError::Limit); }
        dst.write_all(&buffer[..read]).map_err(ReleaseError::fs)?;
        hash.update(&buffer[..read]);
    }
    Ok((total, hex_lower_digest(hash.finalize())))
}
fn revalidate_source(file: &VerifiedFile) -> Result<(), ReleaseError> {
    let path = fs::symlink_metadata(&file.source).map_err(ReleaseError::fs)?;
    let descriptor = file.handle.metadata().map_err(ReleaseError::fs)?;
    if !path.file_type().is_file() || path.dev() != file.device || path.ino() != file.inode || descriptor.dev() != file.device || descriptor.ino() != file.inode || descriptor.len() != file.size || descriptor.permissions().mode() & 0o7777 != file.mode {
        return Err(ReleaseError::Filesystem("verified bundle member was replaced or changed"));
    }
    Ok(())
}
fn journal_path(prefix: &Path) -> PathBuf { prefix.join(".install-journal.json") }
fn write_journal(prefix: &Path, journal: &InstallJournal) -> Result<(), ReleaseError> { write_atomic_json(&journal_path(prefix), journal) }
fn set_phase(prefix: &Path, journal: &mut InstallJournal, phase: InstallPhase) -> Result<(), ReleaseError> { journal.phase = phase; write_journal(prefix, journal) }
fn sync_dir(path: &Path) -> Result<(), ReleaseError> { File::open(path).and_then(|file| file.sync_all()).map_err(ReleaseError::fs) }
fn sync_tree_dirs(root: &Path) -> Result<(), ReleaseError> {
    let mut dirs = vec![root.to_path_buf()];
    let mut index = 0;
    while index < dirs.len() {
        let dir = dirs[index].clone();
        index += 1;
        for entry in fs::read_dir(&dir).map_err(ReleaseError::fs)? {
            let entry = entry.map_err(ReleaseError::fs)?;
            if entry.file_type().map_err(ReleaseError::fs)?.is_dir() { dirs.push(entry.path()); }
        }
    }
    for dir in dirs.into_iter().rev() { sync_dir(&dir)?; }
    Ok(())
}
fn hex_lower_digest(bytes: impl AsRef<[u8]>) -> String { bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect() }
fn normalized_relative(path: &Path) -> Result<String, ReleaseError> {
    if path.as_os_str().is_empty() || path.is_absolute() || path.components().any(|c| !matches!(c, Component::Normal(_))) { return Err(ReleaseError::Filesystem("unsafe relative path")); }
    path.to_str().map(str::to_owned).ok_or(ReleaseError::Filesystem("non-UTF-8 path"))
}
fn sha256(bytes: &[u8]) -> String { let mut h=Sha256::new(); h.update(bytes); hex_lower_digest(h.finalize()) }
fn is_hex(value: &str, len: usize) -> bool { value.len()==len && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) }
fn auth(error: impl fmt::Display) -> ReleaseError { ReleaseError::Authentication(error.to_string()) }
