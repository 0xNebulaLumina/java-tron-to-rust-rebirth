use base64::{Engine as _, engine::general_purpose::STANDARD};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoverableSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub recovery_id: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidPrehashLength,
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidNodeId,
    InvalidSignatureLength,
    InvalidSignature,
    InvalidRecoveryId,
    RecoveryFailed,
    RandomnessExhausted,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", match self {
            Self::InvalidPrehashLength => "prehash must be exactly 32 bytes",
            Self::InvalidPrivateKey => "invalid private key",
            Self::InvalidPublicKey => "invalid public key",
            Self::InvalidNodeId => "node ID must be exactly 64 bytes and encode a curve point",
            Self::InvalidSignatureLength => "signature must contain at least 65 bytes",
            Self::InvalidSignature => "invalid signature components",
            Self::InvalidRecoveryId => "invalid recovery identifier",
            Self::RecoveryFailed => "public-key recovery failed",
            Self::RandomnessExhausted => "bounded nonce generation exhausted",
        })
    }
}

impl std::error::Error for CryptoError {}

impl RecoverableSignature {
    /// Strict network/RPC ingress accepts the protocol's bounded 65..=68 bytes.
    pub fn from_ingress_wire(bytes: &[u8]) -> Result<Self, CryptoError> {
        if !(65..=68).contains(&bytes.len()) { return Err(CryptoError::InvalidSignatureLength); }
        Self::from_consensus_wire(bytes)
    }

    /// Consensus replay accepts every historical signature with at least 65 bytes,
    /// ignoring trailing padding exactly as java-tron's recovery path does.
    pub fn from_consensus_wire(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 65 { return Err(CryptoError::InvalidSignatureLength); }
        let mut r = [0; 32];
        let mut s = [0; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..64]);
        let recovery_id = bytes[64];
        if recovery_id > 3 { return Err(CryptoError::InvalidRecoveryId); }
        Ok(Self { r, s, recovery_id })
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, CryptoError> {
        Self::from_consensus_wire(bytes)
    }

    pub fn to_wire(self) -> [u8; 65] {
        let mut out = [0; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.recovery_id;
        out
    }

    pub fn from_java_base64(encoded: &str) -> Result<Self, CryptoError> {
        let bytes = STANDARD.decode(encoded).map_err(|_| CryptoError::InvalidSignature)?;
        if bytes.len() < 65 { return Err(CryptoError::InvalidSignatureLength); }
        let header = bytes[0];
        if !(27..=34).contains(&header) { return Err(CryptoError::InvalidRecoveryId); }
        let normalized = if header >= 31 { header - 4 } else { header };
        let mut r = [0; 32];
        let mut s = [0; 32];
        r.copy_from_slice(&bytes[1..33]);
        s.copy_from_slice(&bytes[33..65]);
        Ok(Self { r, s, recovery_id: normalized - 27 })
    }

    pub fn to_java_base64(self) -> Result<String, CryptoError> {
        if self.recovery_id > 3 { return Err(CryptoError::InvalidRecoveryId); }
        let mut bytes = [0; 65];
        bytes[0] = 27 + self.recovery_id;
        bytes[1..33].copy_from_slice(&self.r);
        bytes[33..].copy_from_slice(&self.s);
        Ok(STANDARD.encode(bytes))
    }
}

pub(crate) fn prehash(input: &[u8]) -> Result<&[u8; 32], CryptoError> {
    input.try_into().map_err(|_| CryptoError::InvalidPrehashLength)
}
