use std::path::Path;

use sha2::{Digest, Sha256};
use tron_storage::{inspect_read_only, DirectoryClassification, OpenRequirements, StorageManager};

use super::inspect::{DbFailure, JAVA_REJECTION_GUIDANCE};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveOutcome { pub compacted: bool, pub entries_verified: usize, pub empty_directory: bool }

pub fn archive(path: &Path, requirements: &OpenRequirements, minimum_wal_mib: i64, verification_batch: usize) -> Result<ArchiveOutcome, DbFailure> {
    if verification_batch == 0 { return Err(DbFailure::new("operation_failure", "batch size must be greater than zero", 1)); }
    match inspect_read_only(path).map_err(DbFailure::from_format)? {
        DirectoryClassification::Java { marker } => return Err(DbFailure::new("java_format", format!("{}: detected Java storage marker '{marker}'. {JAVA_REJECTION_GUIDANCE}", path.display()), 1)),
        DirectoryClassification::Missing => return Err(DbFailure::new("not_found", format!("{} does not exist.", path.display()), 404)),
        DirectoryClassification::Empty | DirectoryClassification::InitializingEmpty => return Ok(ArchiveOutcome { compacted: false, entries_verified: 0, empty_directory: true }),
        DirectoryClassification::Rust(_) => {}
    }
    if minimum_wal_mib < 0 { return Ok(ArchiveOutcome { compacted: false, entries_verified: 0, empty_directory: false }); }
    let mut log = StorageManager::new(requirements.clone()).open_store(path).map_err(storage_failure)?;
    let minimum = (minimum_wal_mib as u64).saturating_mul(1024 * 1024);
    if log.wal_len().map_err(storage_failure)? < minimum {
        log.close().map_err(storage_failure)?;
        return Ok(ArchiveOutcome { compacted: false, entries_verified: 0, empty_directory: false });
    }
    let before = digest_entries(&log, verification_batch)?;
    let count = log.len();
    log.compact().map_err(storage_failure)?;
    let after = digest_entries(&log, verification_batch)?;
    if before != after { return Err(DbFailure::new("integrity", format!("{}: post-compact verification mismatch", path.display()), 1)); }
    log.close().map_err(storage_failure)?;
    Ok(ArchiveOutcome { compacted: true, entries_verified: count, empty_directory: false })
}

pub fn render_output(path: &Path, outcome: &ArchiveOutcome) -> Vec<u8> {
    if outcome.empty_directory { format!("Directory {} does not contain any database.\n", path.display()).into_bytes() } else { b"archive db done.\n".to_vec() }
}
pub fn success_output() -> &'static [u8] { b"archive db done.\n" }

fn digest_entries(log: &tron_storage::RustLog, batch: usize) -> Result<[u8; 32], DbFailure> {
    let mut digest = Sha256::new();
    let mut in_batch = 0;
    log.visit_entries::<tron_storage::StorageError>(|key, value| {
        digest.update((key.len() as u64).to_be_bytes()); digest.update(key);
        digest.update((value.len() as u64).to_be_bytes()); digest.update(value);
        in_batch += 1;
        if in_batch == batch { in_batch = 0; }
        Ok(())
    }).map_err(storage_failure)?;
    Ok(digest.finalize().into())
}
fn storage_failure(error: tron_storage::StorageError) -> DbFailure { match error { tron_storage::StorageError::Format(error) => DbFailure::from_format(error), other => DbFailure::new("operation_failure", other.to_string(), 1) } }
