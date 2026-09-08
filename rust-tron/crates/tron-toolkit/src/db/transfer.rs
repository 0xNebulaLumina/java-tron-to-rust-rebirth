use std::fs;
use std::path::{Component, Path, PathBuf};

use tron_storage::toolkit::{checkpoint_store, copy_store, move_store, CopyPolicy, StoreFingerprint};
use tron_storage::{inspect_read_only, DirectoryClassification, OpenRequirements};

use super::inspect::{DbFailure, JAVA_REJECTION_GUIDANCE};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferOutcome { NoOp, Published(StoreFingerprint) }

pub fn convert(source: &Path, destination: &Path) -> Result<TransferOutcome, DbFailure> {
    preflight_source(source)?;
    reject_conversion_source(source)?;
    Err(DbFailure::new("not_applicable", format!("{} -> {}: Java-to-Rust conversion is not implemented. Initialize an empty Rust directory and resynchronize from genesis, or import a verified Rust snapshot", source.display(), destination.display()), 1))
}
pub fn copy(source: &Path, destination: &Path, requirements: &OpenRequirements) -> Result<TransferOutcome, DbFailure> { copy_or_checkpoint(source, destination, requirements, false) }
pub fn checkpoint(source: &Path, destination: &Path, requirements: &OpenRequirements) -> Result<TransferOutcome, DbFailure> { copy_or_checkpoint(source, destination, requirements, true) }

fn copy_or_checkpoint(source: &Path, destination: &Path, requirements: &OpenRequirements, idempotent: bool) -> Result<TransferOutcome, DbFailure> {
    if !idempotent && fs::symlink_metadata(destination).is_ok() { return Err(destination_exists(destination)); }
    match inspect_read_only(destination) {
        Ok(DirectoryClassification::Missing) => {}
        Ok(DirectoryClassification::Rust(_)) if idempotent => {}
        Ok(_) => return Err(destination_exists(destination)),
        Err(_) if fs::symlink_metadata(destination).is_ok() => return Err(destination_exists(destination)),
        Err(error) => return Err(DbFailure::from_format(error)),
    }
    preflight_source(source)?;
    match inspect_read_only(source).map_err(DbFailure::from_format)? {
        DirectoryClassification::Empty | DirectoryClassification::InitializingEmpty => return Ok(TransferOutcome::NoOp),
        DirectoryClassification::Java { marker } => return Err(java_failure(source, &marker)),
        DirectoryClassification::Rust(_) => {}
        DirectoryClassification::Missing => unreachable!("source metadata was retained during preflight"),
    }
    let fingerprint = if idempotent { checkpoint_store(source, destination, requirements) } else { copy_store(source, destination, requirements, CopyPolicy::CreateNew) }.map_err(storage_failure)?;
    Ok(TransferOutcome::Published(fingerprint))
}

pub fn move_whole(source: &Path, destination: &Path, requirements: &OpenRequirements) -> Result<TransferOutcome, DbFailure> {
    if fs::symlink_metadata(destination).is_ok() { return Err(destination_exists(destination)); }
    preflight_source(source)?;
    match inspect_read_only(source).map_err(DbFailure::from_format)? {
        DirectoryClassification::Empty | DirectoryClassification::InitializingEmpty => return Ok(TransferOutcome::NoOp),
        DirectoryClassification::Java { marker } => return Err(java_failure(source, &marker)),
        DirectoryClassification::Rust(_) => {}
        DirectoryClassification::Missing => unreachable!("source metadata was retained during preflight"),
    }
    move_store(source, destination, requirements).map(TransferOutcome::Published).map_err(storage_failure)
}

pub fn reject_java_compatibility_move(database_directory: &Path, config: &Path) -> Result<TransferOutcome, DbFailure> {
    let before = metadata_identity(database_directory);
    let result = Err(DbFailure::new("not_applicable", format!("{} with config {}: Java per-database relocation and symlink replacement are reference-only; use whole-store `db mv SOURCE DESTINATION` for rustlog-v1", database_directory.display(), config.display()), 1));
    debug_assert_eq!(before, metadata_identity(database_directory));
    result
}
pub fn backup(source: &Path, backup_directory: &Path, name: &str, requirements: &OpenRequirements) -> Result<TransferOutcome, DbFailure> {
    if !normal_component(name) { return Err(DbFailure::new("operation_failure", "backup name must be one normal path component", 2)); }
    copy_or_checkpoint(source, &backup_directory.join(name), requirements, true)
}

fn preflight_source(source: &Path) -> Result<(), DbFailure> {
    let metadata = match fs::symlink_metadata(source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(DbFailure::new("not_found", format!("{} does not exist.", source.display()), 404)),
        Err(error) => return Err(DbFailure::new("operation_failure", format!("{}: {error}", source.display()), 1)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() { return Err(DbFailure::new("source_not_directory", format!("{} is not a directory.", source.display()), 403)); }
    Ok(())
}
fn reject_conversion_source(source: &Path) -> Result<(), DbFailure> {
    match inspect_read_only(source).map_err(DbFailure::from_format)? {
        DirectoryClassification::Java { marker } => Err(java_failure(source, &marker)),
        DirectoryClassification::Rust(_) => Err(DbFailure::new("not_applicable", format!("{} is already Rust storage; use db migrate", source.display()), 1)),
        _ => Ok(()),
    }
}
fn normal_component(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!((components.next(), components.next()), (Some(Component::Normal(_)), None)) && !name.contains('\\')
}
fn destination_exists(path: &Path) -> DbFailure { DbFailure::new("destination_exists", format!("{} exist, please delete it first.", path.display()), 402) }
fn java_failure(path: &Path, marker: &str) -> DbFailure { DbFailure::new("java_format", format!("{}: detected Java storage marker '{marker}'. {JAVA_REJECTION_GUIDANCE}", path.display()), 1) }
fn storage_failure(error: tron_storage::StorageError) -> DbFailure {
    match error {
        tron_storage::StorageError::Format(error) => DbFailure::from_format(error),
        tron_storage::StorageError::InvalidCheckpoint { path } => destination_exists(&path),
        other => DbFailure::new("operation_failure", other.to_string(), 1),
    }
}
fn metadata_identity(path: &Path) -> Option<(u64, u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(path).ok().map(|metadata| (metadata.dev(), metadata.ino(), metadata.len()))
}
pub fn backup_destination(directory: &Path, name: &str) -> Option<PathBuf> { normal_component(name).then(|| directory.join(name)) }
