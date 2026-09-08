use std::path::{Path, PathBuf};

use tron_storage::{inspect_read_only, DirectoryClassification, FormatError, Manifest, StableError};

pub const JAVA_REJECTION_GUIDANCE: &str = "Rust tooling never opens, modifies, migrates, archives, checkpoints, moves, or converts Java LevelDB/RocksDB directories. Safe choices: use the pinned Java Toolkit on a copy, initialize an empty Rust directory and resynchronize from genesis, or import a verified Rust snapshot.";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InspectionKind {
    Missing,
    Empty,
    InitializingEmpty,
    Rust(Manifest),
    Java { marker: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inspection {
    pub path: PathBuf,
    pub kind: InspectionKind,
}

pub fn inspect(path: &Path) -> Result<Inspection, FormatError> {
    let kind = match inspect_read_only(path)? {
        DirectoryClassification::Missing => InspectionKind::Missing,
        DirectoryClassification::Empty => InspectionKind::Empty,
        DirectoryClassification::InitializingEmpty => InspectionKind::InitializingEmpty,
        DirectoryClassification::Rust(manifest) => InspectionKind::Rust(manifest),
        DirectoryClassification::Java { marker } => InspectionKind::Java { marker },
    };
    Ok(Inspection { path: path.to_owned(), kind })
}

pub fn reject_java(path: &Path) -> Result<(), DbFailure> {
    match inspect(path).map_err(DbFailure::from_format)? {
        Inspection { kind: InspectionKind::Java { marker }, .. } => Err(DbFailure {
            category: "java_format",
            detail: format!("{}: detected Java storage marker '{marker}'. {JAVA_REJECTION_GUIDANCE}", path.display()),
            logical_exit: 1,
        }),
        _ => Ok(()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbFailure {
    pub category: &'static str,
    pub detail: String,
    pub logical_exit: i32,
}

impl DbFailure {
    pub fn new(category: &'static str, detail: impl Into<String>, logical_exit: i32) -> Self {
        Self { category, detail: detail.into(), logical_exit }
    }

    pub fn render(&self) -> String { format!("error[{}]: {}\n", self.category, self.detail) }

    pub fn from_format(error: FormatError) -> Self {
        let category = match error.category {
            StableError::JavaFormat => "java_format",
            StableError::AmbiguousNonempty => "ambiguous_nonempty",
            StableError::ManifestMissing => "manifest_missing",
            StableError::ManifestCorrupt => "manifest_corrupt",
            StableError::FormatUnknown => "format_unknown",
            StableError::FormatNewer => "format_newer",
            StableError::WrongNetwork => "wrong_network",
            StableError::WrongGenesis => "wrong_genesis",
            StableError::BackendUnsupported => "backend_unsupported",
            StableError::FeaturesUnsupported => "features_unsupported",
            StableError::PartialMigration => "partial_migration",
            StableError::Locked => "locked",
            StableError::Permission => "permission",
            StableError::DiskFull => "disk_full",
            StableError::ConcurrentOpen => "concurrent_open",
            StableError::Integrity => "integrity",
            StableError::SourceTooLarge => "source_too_large",
            StableError::UnsupportedMigration => "unsupported_migration",
            StableError::SnapshotUnauthenticated => "snapshot_unauthenticated",
            StableError::SnapshotIncompatible => "snapshot_incompatible",
            StableError::NotEmpty => "destination_exists",
            StableError::Io => "operation_failure",
        };
        Self::new(category, format!("{}: {}", error.path.display(), error.detail), 1)
    }
}
