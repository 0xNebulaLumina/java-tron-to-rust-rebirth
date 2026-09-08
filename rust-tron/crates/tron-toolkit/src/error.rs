#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutcome { pub logical_exit: i32, pub stdout: Vec<u8>, pub stderr: Vec<u8> }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput { pub stdout: Vec<u8>, pub stderr: Vec<u8>, pub logical_exit: i32 }
impl CommandOutput {
    pub fn success() -> Self { Self { stdout: Vec::new(), stderr: Vec::new(), logical_exit: 0 } }
    pub fn stdout(bytes: impl Into<Vec<u8>>) -> Self { Self { stdout: bytes.into(), stderr: Vec::new(), logical_exit: 0 } }
    pub fn stderr(bytes: impl Into<Vec<u8>>, logical_exit: i32) -> Self { Self { stdout: Vec::new(), stderr: bytes.into(), logical_exit } }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseFailure { pub detail: String, pub usage: &'static str }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolkitError { Parity { code: i32, stdout: Vec<u8>, stderr: Vec<u8> }, Categorized { category: ErrorCategory, detail: String } }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCategory {
    JavaFormat, AmbiguousNonempty, ManifestMissing, ManifestCorrupt, FormatUnknown, FormatNewer,
    WrongNetwork, WrongGenesis, BackendUnsupported, FeaturesUnsupported, PartialMigration, Locked,
    Permission, DiskFull, ConcurrentOpen, Integrity, SourceTooLarge, UnsupportedMigration,
    DestinationExists, SourceNotDirectory, NotFound, NotDirectory, UnsupportedPlatform,
    UnsupportedBackend, NotApplicable, InvalidLiteDataset, IncompatibleLiteDataset,
    RecoveryRequired, InvalidPrivateKey, KeystoreInput, KeystoreSecurity,
}
impl ErrorCategory {
    pub const fn as_str(self) -> &'static str { match self {
        Self::JavaFormat=>"java_format", Self::AmbiguousNonempty=>"ambiguous_nonempty", Self::ManifestMissing=>"manifest_missing", Self::ManifestCorrupt=>"manifest_corrupt", Self::FormatUnknown=>"format_unknown", Self::FormatNewer=>"format_newer", Self::WrongNetwork=>"wrong_network", Self::WrongGenesis=>"wrong_genesis", Self::BackendUnsupported=>"backend_unsupported", Self::FeaturesUnsupported=>"features_unsupported", Self::PartialMigration=>"partial_migration", Self::Locked=>"locked", Self::Permission=>"permission", Self::DiskFull=>"disk_full", Self::ConcurrentOpen=>"concurrent_open", Self::Integrity=>"integrity", Self::SourceTooLarge=>"source_too_large", Self::UnsupportedMigration=>"unsupported_migration", Self::DestinationExists=>"destination_exists", Self::SourceNotDirectory=>"source_not_directory", Self::NotFound=>"not_found", Self::NotDirectory=>"not_directory", Self::UnsupportedPlatform=>"unsupported_platform", Self::UnsupportedBackend=>"unsupported_backend", Self::NotApplicable=>"not_applicable", Self::InvalidLiteDataset=>"invalid_lite_dataset", Self::IncompatibleLiteDataset=>"incompatible_lite_dataset", Self::RecoveryRequired=>"recovery_required", Self::InvalidPrivateKey=>"invalid_private_key", Self::KeystoreInput=>"keystore_input", Self::KeystoreSecurity=>"keystore_security" }
    }
}
impl ToolkitError {
    pub fn into_output(self) -> CommandOutput { match self {
        Self::Parity { code, stdout, stderr } => CommandOutput { stdout, stderr, logical_exit: code },
        Self::Categorized { category, detail } => CommandOutput::stderr(format!("error[{}]: {detail}\n", category.as_str()).into_bytes(), 1),
    }}
}
