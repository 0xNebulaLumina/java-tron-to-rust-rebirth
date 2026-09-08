use std::path::Path;

use tron_storage::{resume_migration, OpenRequirements};

use super::inspect::{reject_java, DbFailure};

pub fn migrate(path: &Path, _requirements: &OpenRequirements, target_schema: u32) -> Result<(), DbFailure> {
    reject_java(path)?;
    Err(DbFailure::new(
        "unsupported_migration",
        format!("{}: no compiled semantic migration edge targets schema {target_schema}", path.display()),
        1,
    ))
}

pub fn resume(path: &Path, requirements: &OpenRequirements) -> Result<(), DbFailure> {
    reject_java(path)?;
    resume_migration(path, requirements).map(|_| ()).map_err(DbFailure::from_format)
}

pub fn rollback(path: &Path, requirements: &OpenRequirements) -> Result<(), DbFailure> {
    reject_java(path)?;
    tron_storage::toolkit::rollback_migration_checked(path, requirements).map_err(storage_failure)
}

fn storage_failure(error: tron_storage::StorageError) -> DbFailure {
    match error { tron_storage::StorageError::Format(error) => DbFailure::from_format(error), other => DbFailure::new("operation_failure", other.to_string(), 1) }
}
