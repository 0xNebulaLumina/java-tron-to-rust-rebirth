use k256::{PublicKey, SecretKey};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;

use crate::signature::{CryptoError, RecoverableSignature, prehash};

#[derive(Clone)]
pub struct Secp256k1Key {
    secret: SecretKey,
}

impl Secp256k1Key {
    pub fn generate() -> Self { Self { secret: SecretKey::random(&mut OsRng) } }

    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let secret = SecretKey::from_slice(bytes).map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(Self { secret })
    }

    pub fn private_bytes(&self) -> [u8; 32] { self.secret.to_bytes().into() }

    pub fn public_key(&self) -> Secp256k1PublicKey { Secp256k1PublicKey(self.secret.public_key()) }

    pub fn sign_prehash(&self, hash: &[u8]) -> Result<RecoverableSignature, CryptoError> {
        let hash = prehash(hash)?;
        let signing = SigningKey::from(&self.secret);
        let (signature, recovery_id) = signing.sign_prehash_recoverable(hash)
            .map_err(|_| CryptoError::InvalidSignature)?;
        let bytes = signature.to_bytes();
        let mut r = [0; 32];
        let mut s = [0; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Ok(RecoverableSignature { r, s, recovery_id: recovery_id.to_byte() })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secp256k1PublicKey(PublicKey);

impl Secp256k1PublicKey {
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        PublicKey::from_sec1_bytes(bytes).map(Self).map_err(|_| CryptoError::InvalidPublicKey)
    }

    pub fn from_node_id(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 { return Err(CryptoError::InvalidNodeId); }
        let mut encoded = [0; 65];
        encoded[0] = 4;
        encoded[1..].copy_from_slice(bytes);
        Self::from_sec1_bytes(&encoded).map_err(|_| CryptoError::InvalidNodeId)
    }

    pub fn to_uncompressed_sec1(&self) -> [u8; 65] {
        self.0.to_encoded_point(false).as_bytes().try_into().expect("uncompressed sec1 length")
    }

    pub fn to_compressed_sec1(&self) -> [u8; 33] {
        self.0.to_encoded_point(true).as_bytes().try_into().expect("compressed sec1 length")
    }

    pub fn node_id(&self) -> [u8; 64] {
        self.to_uncompressed_sec1()[1..].try_into().expect("node id length")
    }

    pub fn verify_prehash(&self, hash: &[u8], signature: &RecoverableSignature) -> Result<(), CryptoError> {
        let hash = prehash(hash)?;
        let sig = signature_value(signature)?;
        let normalized = sig.normalize_s().unwrap_or(sig);
        VerifyingKey::from(&self.0).verify_prehash(hash, &normalized)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    pub fn recover_prehash(hash: &[u8], signature: &RecoverableSignature) -> Result<Self, CryptoError> {
        let hash = prehash(hash)?;
        let mut sig = signature_value(signature)?;
        let mut recovery_id = signature.recovery_id;
        if let Some(normalized) = sig.normalize_s() {
            sig = normalized;
            recovery_id ^= 1;
        }
        let recovery_id = RecoveryId::try_from(recovery_id).map_err(|_| CryptoError::InvalidRecoveryId)?;
        VerifyingKey::recover_from_prehash(hash, &sig, recovery_id)
            .map(|key| Self(PublicKey::from(&key)))
            .map_err(|_| CryptoError::RecoveryFailed)
    }
}

fn signature_value(signature: &RecoverableSignature) -> Result<Signature, CryptoError> {
    if signature.recovery_id > 3 { return Err(CryptoError::InvalidRecoveryId); }
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&signature.r);
    bytes[32..].copy_from_slice(&signature.s);
    Signature::from_slice(&bytes).map_err(|_| CryptoError::InvalidSignature)
}
