use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::format::{FormatError, FormatResult, SnapshotMaterializer, SnapshotSource, StableError};
use crate::{decode_snapshot, RustLogOptions};

pub const RUSTLOG_SNAPSHOT_MAGIC: &[u8; 8] = b"RUSTSNP1";
pub const RUSTLOG_SNAPSHOT_VERSION: u32 = 1;
const RLOG_MAGIC: &[u8; 8] = b"RLOGSNP1";
const WAL_MAGIC: &[u8; 8] = b"RLOGWAL1";
const HEADER_LEN: usize = 8 + 4 + 8 + 32;
const PHYSICAL_HEADER_LEN: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RustLogSnapshotLimits {
    pub max_bundle_bytes: usize,
    pub max_snapshot_bytes: usize,
    pub max_entries: usize,
    pub max_key_bytes: usize,
    pub max_value_bytes: usize,
}

impl Default for RustLogSnapshotLimits {
    fn default() -> Self {
        Self { max_bundle_bytes: 8 * 1024 * 1024 * 1024, max_snapshot_bytes: 8 * 1024 * 1024 * 1024, max_entries: 50_000_000, max_key_bytes: 4 * 1024 * 1024, max_value_bytes: 64 * 1024 * 1024 }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustLogSnapshotMetadata {
    pub physical_size: u64,
    pub physical_sha256: String,
    pub state_root: String,
    pub entries: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedRustLogSnapshot {
    pub metadata: RustLogSnapshotMetadata,
    pub physical_snapshot: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct RustLogSnapshotMaterializer {
    pub limits: RustLogSnapshotLimits,
}

impl RustLogSnapshotMaterializer {
    #[must_use]
    pub const fn new(limits: RustLogSnapshotLimits) -> Self { Self { limits } }
}

impl Default for RustLogSnapshotMaterializer {
    fn default() -> Self { Self::new(RustLogSnapshotLimits::default()) }
}

pub fn encode_checkpoint_snapshot(checkpoint_dir: &Path, output: &Path, limits: RustLogSnapshotLimits) -> FormatResult<RustLogSnapshotMetadata> {
    let generation = if checkpoint_dir.join("generation-0").is_dir() { checkpoint_dir.join("generation-0") } else { checkpoint_dir.to_path_buf() };
    let snapshot_path = generation.join("rustlog-v1.snapshot");
    let physical = read_bounded(&snapshot_path, limits.max_snapshot_bytes)?;
    let metadata = validate_physical(&physical, limits, &snapshot_path)?;
    let total = HEADER_LEN.checked_add(physical.len()).ok_or_else(|| incompatible(output, "snapshot bundle length overflow"))?;
    if total > limits.max_bundle_bytes { return Err(FormatError::new(StableError::SourceTooLarge, output, "snapshot bundle exceeds bound")); }
    let mut file = OpenOptions::new().write(true).create_new(true).open(output).map_err(|e| FormatError::new(StableError::Io, output, e.to_string()))?;
    let result = (|| {
        file.write_all(RUSTLOG_SNAPSHOT_MAGIC)?;
        file.write_all(&RUSTLOG_SNAPSHOT_VERSION.to_le_bytes())?;
        file.write_all(&(physical.len() as u64).to_le_bytes())?;
        file.write_all(&Sha256::digest(&physical))?;
        file.write_all(&physical)?;
        file.sync_all()
    })();
    if let Err(error) = result { let _ = fs::remove_file(output); return Err(FormatError::new(StableError::Io, output, error.to_string())); }
    Ok(metadata)
}

pub fn decode_snapshot_bundle(bytes: &[u8], limits: RustLogSnapshotLimits) -> FormatResult<DecodedRustLogSnapshot> {
    let display = Path::new("rustlog-snapshot-v1");
    if bytes.len() > limits.max_bundle_bytes { return Err(FormatError::new(StableError::SourceTooLarge, display, "snapshot bundle exceeds bound")); }
    if bytes.len() < HEADER_LEN || &bytes[..8] != RUSTLOG_SNAPSHOT_MAGIC { return Err(incompatible(display, "invalid snapshot bundle magic or header")); }
    let version = u32::from_le_bytes(bytes[8..12].try_into().expect("fixed slice"));
    if version != RUSTLOG_SNAPSHOT_VERSION { return Err(incompatible(display, "unsupported snapshot bundle version")); }
    let length = u64::from_le_bytes(bytes[12..20].try_into().expect("fixed slice"));
    let length = usize::try_from(length).map_err(|_| FormatError::new(StableError::SourceTooLarge, display, "snapshot body length does not fit platform"))?;
    if length > limits.max_snapshot_bytes || bytes.len() != HEADER_LEN.checked_add(length).ok_or_else(|| incompatible(display, "snapshot length overflow"))? {
        return Err(incompatible(display, "snapshot bundle length mismatch"));
    }
    let physical = &bytes[HEADER_LEN..];
    if Sha256::digest(physical).as_slice() != &bytes[20..52] { return Err(FormatError::new(StableError::Integrity, display, "snapshot body SHA-256 mismatch")); }
    let metadata = validate_physical(physical, limits, display)?;
    Ok(DecodedRustLogSnapshot { metadata, physical_snapshot: physical.to_vec() })
}

impl SnapshotMaterializer for RustLogSnapshotMaterializer {
    fn materialize(&self, snapshot: &SnapshotSource, destination: &Path) -> FormatResult<String> {
        if destination.read_dir().map_err(|e| FormatError::new(StableError::Io, destination, e.to_string()))?.next().is_some() {
            return Err(FormatError::new(StableError::NotEmpty, destination, "snapshot materializer requires empty staging directory"));
        }
        let decoded = decode_snapshot_bundle(snapshot.bytes(), self.limits)?;
        let snapshot_path = destination.join("rustlog-v1.snapshot");
        let wal_path = destination.join("rustlog-v1.wal");
        write_new_sync(&snapshot_path, &decoded.physical_snapshot)?;
        if let Err(error) = write_new_sync(&wal_path, WAL_MAGIC) { let _ = fs::remove_file(&snapshot_path); return Err(error); }
        File::open(destination).and_then(|file| file.sync_all()).map_err(|e| FormatError::new(StableError::Io, destination, e.to_string()))?;
        Ok(decoded.metadata.state_root)
    }
}

fn validate_physical(bytes: &[u8], limits: RustLogSnapshotLimits, path: &Path) -> FormatResult<RustLogSnapshotMetadata> {
    if bytes.len() < PHYSICAL_HEADER_LEN || &bytes[..8] != RLOG_MAGIC { return Err(incompatible(path, "invalid compact RLOGSNP1 body")); }
    let payload_len = u64::from_le_bytes(bytes[8..16].try_into().expect("fixed slice"));
    let payload_len = usize::try_from(payload_len).map_err(|_| FormatError::new(StableError::SourceTooLarge, path, "physical snapshot length does not fit platform"))?;
    if payload_len > limits.max_snapshot_bytes || bytes.len() != PHYSICAL_HEADER_LEN.checked_add(payload_len).ok_or_else(|| incompatible(path, "physical snapshot length overflow"))? {
        return Err(incompatible(path, "physical snapshot length mismatch"));
    }
    let payload = &bytes[PHYSICAL_HEADER_LEN..];
    let crc = u32::from_le_bytes(bytes[16..20].try_into().expect("fixed slice"));
    if crc32(payload) != crc { return Err(FormatError::new(StableError::Integrity, path, "physical snapshot CRC mismatch")); }
    let options = RustLogOptions { max_key_bytes: limits.max_key_bytes, max_value_bytes: limits.max_value_bytes, max_frame_bytes: limits.max_snapshot_bytes, max_snapshot_bytes: limits.max_snapshot_bytes, max_snapshot_entries: limits.max_entries, max_batch_operations: limits.max_entries, compact_after_bytes: 0, sync_on_write: true };
    let entries = decode_snapshot(payload, &options).map_err(|error| FormatError::new(StableError::SnapshotIncompatible, path, error.to_string()))?;
    let root = logical_root(&entries);
    Ok(RustLogSnapshotMetadata { physical_size: bytes.len() as u64, physical_sha256: hex(&Sha256::digest(bytes)), state_root: root, entries: entries.len() as u64 })
}

fn logical_root(entries: &BTreeMap<Vec<u8>, Vec<u8>>) -> String {
    let mut hash = Sha256::new();
    hash.update(b"RUSTLOG-SNAPSHOT-STATE-V1");
    hash.update((entries.len() as u64).to_be_bytes());
    for (key, value) in entries {
        hash.update((key.len() as u64).to_be_bytes()); hash.update(key);
        hash.update((value.len() as u64).to_be_bytes()); hash.update(value);
    }
    hex(&hash.finalize())
}

fn read_bounded(path: &Path, maximum: usize) -> FormatResult<Vec<u8>> {
    let file = File::open(path).map_err(|e| FormatError::new(StableError::Io, path, e.to_string()))?;
    let length = file.metadata().map_err(|e| FormatError::new(StableError::Io, path, e.to_string()))?.len();
    if length > maximum as u64 { return Err(FormatError::new(StableError::SourceTooLarge, path, "snapshot body exceeds bound")); }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take((maximum as u64).saturating_add(1)).read_to_end(&mut bytes).map_err(|e| FormatError::new(StableError::Io, path, e.to_string()))?;
    if bytes.len() > maximum { return Err(FormatError::new(StableError::SourceTooLarge, path, "snapshot body exceeds bound")); }
    Ok(bytes)
}

fn write_new_sync(path: &Path, bytes: &[u8]) -> FormatResult<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path).map_err(|e| FormatError::new(StableError::Io, path, e.to_string()))?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|e| FormatError::new(StableError::Io, path, e.to_string()))
}
fn incompatible(path: &Path, detail: &str) -> FormatError { FormatError::new(StableError::SnapshotIncompatible, path, detail) }
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn crc32(bytes: &[u8]) -> u32 { let mut crc=!0u32; for &byte in bytes { crc^=u32::from(byte); for _ in 0..8 { crc=(crc>>1)^if crc&1==1{0xedb8_8320}else{0}; } } !crc }
