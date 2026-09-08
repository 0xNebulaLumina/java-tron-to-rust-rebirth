//! Explicit, ambient-free toolkit capability selection.
//!
//! Callers provide platform facts from their build or release manifest. This module deliberately
//! does not inspect the environment, compile-time configuration, or the current host.

use std::str::FromStr;

use thiserror::Error;

pub const P_LINUX_X64: &str = "P-LINUX-X64";
pub const P_LINUX_ARM64: &str = "P-LINUX-ARM64";
pub const P_MACOS_X64: &str = "P-MACOS-X64";
pub const P_MACOS_ARM64: &str = "P-MACOS-ARM64";
pub const P_UNSUPPORTED: &str = "P-UNSUPPORTED";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformFacts {
    pub os: String,
    pub architecture: String,
    pub target: String,
}

impl PlatformFacts {
    pub fn new(os: impl Into<String>, architecture: impl Into<String>, target: impl Into<String>) -> Self {
        Self { os: os.into(), architecture: architecture.into(), target: target.into() }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolkitBackend {
    RustlogV1,
    JavaLevelDb,
    JavaRocksDb,
}

impl ToolkitBackend {
    pub const fn cli_name(self) -> &'static str {
        match self {
            Self::RustlogV1 => "rustlog-v1",
            Self::JavaLevelDb => "LEVELDB",
            Self::JavaRocksDb => "ROCKSDB",
        }
    }
}

impl std::fmt::Display for ToolkitBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.cli_name())
    }
}

impl FromStr for ToolkitBackend {
    type Err = ToolkitCapabilityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.eq_ignore_ascii_case("rustlog-v1") {
            Ok(Self::RustlogV1)
        } else if value.eq_ignore_ascii_case("leveldb") || value.eq_ignore_ascii_case("java-leveldb") {
            Ok(Self::JavaLevelDb)
        } else if value.eq_ignore_ascii_case("rocksdb") || value.eq_ignore_ascii_case("java-rocksdb") {
            Ok(Self::JavaRocksDb)
        } else {
            Err(ToolkitCapabilityError::UnknownBackend(value.to_owned()))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityState {
    Enabled,
    Future,
    ReferenceOnly,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendIdentity {
    pub backend: &'static str,
    pub backend_format: &'static str,
    pub required_feature: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendCapability {
    pub backend: ToolkitBackend,
    pub state: CapabilityState,
    pub readable: bool,
    pub writable: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolkitCapabilities {
    pub platform_id: String,
    pub facts: PlatformFacts,
    pub state: CapabilityState,
    pub reason: Option<String>,
    pub backends: Vec<BackendCapability>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ToolkitCapabilityError {
    #[error("unsupported toolkit backend {0}")]
    UnknownBackend(String),
    #[error("toolkit platform {id} is reserved but has no native executor")]
    FuturePlatform { id: String },
    #[error("unsupported toolkit platform {os}/{architecture} ({target})")]
    UnsupportedPlatform { os: String, architecture: String, target: String },
    #[error("{backend} is Java-reference-only under DR-001; Rust never opens or modifies Java database directories")]
    JavaReferenceOnly { backend: &'static str },
}

const FUTURE_REASON: &str = "reserved platform has no native executor or native runtime evidence";
const JAVA_REASON: &str = "Java-reference-only under DR-001; Rust never opens or modifies Java database directories";
const UNSUPPORTED_REASON: &str = "platform is outside the qualified toolkit matrix";

pub fn toolkit_capabilities(facts: PlatformFacts) -> ToolkitCapabilities {
    let (platform_id, state, reason) = match (facts.os.as_str(), facts.architecture.as_str(), facts.target.as_str()) {
        ("linux", "x86_64", "x86_64-unknown-linux-gnu") =>
            (P_LINUX_X64, CapabilityState::Enabled, None),
        ("linux", "aarch64", "aarch64-unknown-linux-gnu") =>
            (P_LINUX_ARM64, CapabilityState::Future, Some(FUTURE_REASON.to_owned())),
        ("macos", "x86_64", "x86_64-apple-darwin") =>
            (P_MACOS_X64, CapabilityState::Future, Some(FUTURE_REASON.to_owned())),
        ("macos", "aarch64", "aarch64-apple-darwin") =>
            (P_MACOS_ARM64, CapabilityState::Future, Some(FUTURE_REASON.to_owned())),
        _ => (P_UNSUPPORTED, CapabilityState::Unsupported, Some(UNSUPPORTED_REASON.to_owned())),
    };

    let rustlog_enabled = state == CapabilityState::Enabled;
    ToolkitCapabilities {
        platform_id: platform_id.to_owned(),
        facts,
        state,
        reason,
        backends: vec![
            BackendCapability {
                backend: ToolkitBackend::RustlogV1,
                state,
                readable: rustlog_enabled,
                writable: rustlog_enabled,
                reason: (!rustlog_enabled).then(|| {
                    if state == CapabilityState::Future { FUTURE_REASON } else { UNSUPPORTED_REASON }.to_owned()
                }),
            },
            BackendCapability {
                backend: ToolkitBackend::JavaLevelDb,
                state: CapabilityState::ReferenceOnly,
                readable: false,
                writable: false,
                reason: Some(JAVA_REASON.to_owned()),
            },
            BackendCapability {
                backend: ToolkitBackend::JavaRocksDb,
                state: CapabilityState::ReferenceOnly,
                readable: false,
                writable: false,
                reason: Some(JAVA_REASON.to_owned()),
            },
        ],
    }
}

pub fn validate_toolkit_backend(
    capabilities: &ToolkitCapabilities,
    backend: ToolkitBackend,
) -> Result<BackendIdentity, ToolkitCapabilityError> {
    match backend {
        ToolkitBackend::JavaLevelDb | ToolkitBackend::JavaRocksDb => {
            Err(ToolkitCapabilityError::JavaReferenceOnly { backend: backend.cli_name() })
        }
        ToolkitBackend::RustlogV1 => match capabilities.state {
            CapabilityState::Enabled => Ok(BackendIdentity {
                backend: "rustlog",
                backend_format: "rustlog-v1",
                required_feature: "rustlog-v1",
            }),
            CapabilityState::Future => Err(ToolkitCapabilityError::FuturePlatform {
                id: capabilities.platform_id.clone(),
            }),
            CapabilityState::Unsupported | CapabilityState::ReferenceOnly => {
                Err(ToolkitCapabilityError::UnsupportedPlatform {
                    os: capabilities.facts.os.clone(),
                    architecture: capabilities.facts.architecture.clone(),
                    target: capabilities.facts.target.clone(),
                })
            }
        },
    }
}
