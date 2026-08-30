use std::{fmt, io};

#[derive(Debug)]
pub enum ShieldedError {
    InvalidParameter(String),
    InvalidEncoding(&'static str),
    InvalidHandle,
    ContextLimit { max: usize },
    StateNotInitialized,
    StateFinalized,
    TreeFull,
    EmptyTree,
    ParameterIo { kind: ParameterKind, source: io::Error },
    ParameterSize { kind: ParameterKind, expected: u64, actual: u64 },
    ParameterHash { kind: ParameterKind, expected: &'static str, actual: String },
    ParameterDeserialize { kind: ParameterKind, source: io::Error },
    VerificationStateCorrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterKind { Spend, Output }

impl fmt::Display for ShieldedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter(s) => f.write_str(s),
            Self::InvalidEncoding(s) => write!(f, "invalid {s} encoding"),
            Self::InvalidHandle => f.write_str("invalid or retired native handle"),
            Self::ContextLimit { max } => write!(f, "shielded native context limit reached ({max})"),
            Self::StateNotInitialized => f.write_str("BLAKE2b state is not initialized"),
            Self::StateFinalized => f.write_str("BLAKE2b state is finalized"),
            Self::TreeFull => f.write_str("tree is full"),
            Self::EmptyTree => f.write_str("tree has no cursor"),
            Self::ParameterIo { kind, source } => write!(f, "couldn't load Sapling {} parameters file: {source}", kind.name()),
            Self::ParameterSize { kind, expected, actual } => write!(f, "Sapling {} parameter file size mismatch: expected {expected}, got {actual}", kind.name()),
            Self::ParameterHash { kind, expected, actual } => write!(f, "Sapling {} parameter file is not correct, expected BLAKE2b-512 {expected}, got {actual}", kind.name()),
            Self::ParameterDeserialize { kind, source } => write!(f, "couldn't deserialize Sapling {} parameters file: {source}", kind.name()),
            Self::VerificationStateCorrupt => f.write_str("accepted Sapling verification state could not be replayed"),
        }
    }
}

impl ParameterKind { fn name(self) -> &'static str { match self { Self::Spend => "spend", Self::Output => "output" } } }
impl std::error::Error for ShieldedError {}

pub type Result<T, E = ShieldedError> = std::result::Result<T, E>;
