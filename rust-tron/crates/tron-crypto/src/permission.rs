use std::collections::HashSet;

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{CryptoEngine, CryptoError, RecoverableSignature, PublicKey, derive_address};
use tron_primitives::TronAddress21;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionKey {
    pub address: TronAddress21,
    pub weight: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionWeight {
    pub current_weight: i64,
    pub approved: Vec<TronAddress21>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplicateSignerPolicy {
    /// java-tron before VERSION_4_7_1 keyed duplicates by its canonical Base64
    /// reconstruction of the first 65 signature bytes. Trailing padding is ignored.
    CanonicalSignature,
    /// java-tron at and after VERSION_4_7_1 keys duplicates by recovered address.
    RecoveredAddress,
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionError {
    TooManySignatures,
    SignatureFormat,
    ComputeAddress,
    SignerNotInPermission,
    DuplicateSigner,
    WeightOverflow,
}

impl core::fmt::Display for PermissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::TooManySignatures => "signature count exceeds permission key count",
            Self::SignatureFormat => "signature has invalid consensus format",
            Self::ComputeAddress => "signature public-key recovery failed",
            Self::SignerNotInPermission => "recovered signer is not in permission",
            Self::DuplicateSigner => "permission signer has signed twice",
            Self::WeightOverflow => "permission weight overflow",
        })
    }
}

impl std::error::Error for PermissionError {}

/// Recover consensus signatures, truncate historical trailing padding, and apply the
/// duplicate identity selected by the VERSION_4_7_1 fork state.
pub fn recover_permission_weight(
    engine: CryptoEngine,
    prehash: &[u8],
    signatures: &[impl AsRef<[u8]>],
    keys: &[PermissionKey],
    duplicate_policy: DuplicateSignerPolicy,
) -> Result<PermissionWeight, PermissionError> {
    if signatures.len() > keys.len() { return Err(PermissionError::TooManySignatures); }
    let mut approved = Vec::with_capacity(signatures.len());
    let mut seen_signatures = HashSet::with_capacity(signatures.len());
    let mut seen_addresses = HashSet::with_capacity(signatures.len());
    let mut current_weight = 0i64;
    for bytes in signatures {
        let signature = RecoverableSignature::from_consensus_wire(bytes.as_ref())
            .map_err(map_signature_format)?;
        let public_key = PublicKey::recover_prehash(engine, prehash, &signature)
            .map_err(|_| PermissionError::ComputeAddress)?;
        let address = derive_address(&public_key);
        let weight = keys.iter().find(|key| key.address == address).map(|key| key.weight)
            .ok_or(PermissionError::SignerNotInPermission)?;
        if duplicate_policy == DuplicateSignerPolicy::CanonicalSignature {
            let canonical = canonical_java_signature_identity(signature);
            if !seen_signatures.insert(canonical) { return Err(PermissionError::DuplicateSigner); }
        }
        if duplicate_policy == DuplicateSignerPolicy::RecoveredAddress && !seen_addresses.insert(address) {
            return Err(PermissionError::DuplicateSigner);
        }
        current_weight = current_weight.checked_add(weight).ok_or(PermissionError::WeightOverflow)?;
        approved.push(address);
    }
    Ok(PermissionWeight { current_weight, approved })
}

fn canonical_java_signature_identity(signature: RecoverableSignature) -> String {
    let mut java_wire = [0; 65];
    java_wire[0] = signature.recovery_id + 27;
    java_wire[1..33].copy_from_slice(&signature.r);
    java_wire[33..].copy_from_slice(&signature.s);
    STANDARD.encode(java_wire)
}

fn map_signature_format(error: CryptoError) -> PermissionError {
    match error {
        CryptoError::InvalidSignatureLength | CryptoError::InvalidRecoveryId => PermissionError::SignatureFormat,
        _ => PermissionError::ComputeAddress,
    }
}
