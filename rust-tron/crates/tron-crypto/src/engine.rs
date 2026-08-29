use crate::{
    CryptoEngine, CryptoError, RecoverableSignature, Secp256k1Key, Secp256k1PublicKey,
    Sm2Key, Sm2PublicKey,
};

#[derive(Clone)]
pub enum PrivateKey {
    Secp256k1(Secp256k1Key),
    Sm2(Sm2Key),
}

impl PrivateKey {
    pub fn generate(engine: CryptoEngine) -> Self {
        match engine {
            CryptoEngine::Secp256k1 => Self::Secp256k1(Secp256k1Key::generate()),
            CryptoEngine::Sm2 => Self::Sm2(Sm2Key::generate()),
        }
    }

    pub fn from_bytes(engine: CryptoEngine, bytes: &[u8]) -> Result<Self, CryptoError> {
        match engine {
            CryptoEngine::Secp256k1 => Secp256k1Key::from_private_bytes(bytes).map(Self::Secp256k1),
            CryptoEngine::Sm2 => Sm2Key::from_private_bytes(bytes).map(Self::Sm2),
        }
    }

    pub fn private_bytes(&self) -> [u8; 32] {
        match self {
            Self::Secp256k1(key) => key.private_bytes(),
            Self::Sm2(key) => key.private_bytes(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Secp256k1(key) => PublicKey::Secp256k1(key.public_key()),
            Self::Sm2(key) => PublicKey::Sm2(key.public_key()),
        }
    }

    pub fn sign_prehash(&self, hash: &[u8]) -> Result<RecoverableSignature, CryptoError> {
        match self {
            Self::Secp256k1(key) => key.sign_prehash(hash),
            Self::Sm2(key) => key.sign_prehash(hash),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicKey {
    Secp256k1(Secp256k1PublicKey),
    Sm2(Sm2PublicKey),
}

impl PublicKey {
    pub fn from_sec1_bytes(engine: CryptoEngine, bytes: &[u8]) -> Result<Self, CryptoError> {
        match engine {
            CryptoEngine::Secp256k1 => Secp256k1PublicKey::from_sec1_bytes(bytes).map(Self::Secp256k1),
            CryptoEngine::Sm2 => Sm2PublicKey::from_sec1_bytes(bytes).map(Self::Sm2),
        }
    }

    pub fn from_node_id(engine: CryptoEngine, bytes: &[u8]) -> Result<Self, CryptoError> {
        match engine {
            CryptoEngine::Secp256k1 => Secp256k1PublicKey::from_node_id(bytes).map(Self::Secp256k1),
            CryptoEngine::Sm2 => Sm2PublicKey::from_node_id(bytes).map(Self::Sm2),
        }
    }

    pub fn recover_prehash(engine: CryptoEngine, hash: &[u8], signature: &RecoverableSignature) -> Result<Self, CryptoError> {
        match engine {
            CryptoEngine::Secp256k1 => Secp256k1PublicKey::recover_prehash(hash, signature).map(Self::Secp256k1),
            CryptoEngine::Sm2 => Sm2PublicKey::recover_prehash(hash, signature).map(Self::Sm2),
        }
    }

    pub fn to_uncompressed_sec1(&self) -> [u8; 65] {
        match self {
            Self::Secp256k1(key) => key.to_uncompressed_sec1(),
            Self::Sm2(key) => key.to_uncompressed_sec1(),
        }
    }

    pub fn to_compressed_sec1(&self) -> [u8; 33] {
        match self {
            Self::Secp256k1(key) => key.to_compressed_sec1(),
            Self::Sm2(key) => key.to_compressed_sec1(),
        }
    }

    pub fn node_id(&self) -> [u8; 64] {
        match self {
            Self::Secp256k1(key) => key.node_id(),
            Self::Sm2(key) => key.node_id(),
        }
    }

    pub fn verify_prehash(&self, hash: &[u8], signature: &RecoverableSignature) -> Result<(), CryptoError> {
        match self {
            Self::Secp256k1(key) => key.verify_prehash(hash, signature),
            Self::Sm2(key) => key.verify_prehash(hash, signature),
        }
    }
}
