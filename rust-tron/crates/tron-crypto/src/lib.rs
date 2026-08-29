//! Pure-Rust TRON cryptography boundary.
//!
//! SHA-256/SM3 engine selection is explicit. Legacy Keccak is deliberately
//! separate from FIPS SHA-3. Signing APIs accept already-computed 32-byte
//! prehashes and do not own keystore behavior.

mod address;
mod contract_address;
mod digest;
mod engine;
mod permission;
mod secp256k1;
mod signature;
mod sm2;

pub use address::{
    AddressError, BASE58_ADDRESS_LENGTH, TRON_ADDRESS_PREFIX, decode_address_base58check,
    decode_base58, decode_base58check, derive_address, derive_address_from_node_id,
    encode_address_base58check, encode_base58, encode_base58check, validate_address,
};
pub use contract_address::{create2_address, internal_create_address, top_level_contract_address};
pub use digest::{
    CryptoEngine, Sha256Provider, Sm3Provider, keccak256, keccak512, ripemd160,
    selected_digest, selected_digest_ranges, selected_digest_twice,
    selected_digest_twice_ranges,
};
pub use engine::{PrivateKey, PublicKey};
pub use permission::{
    DuplicateSignerPolicy, PermissionError, PermissionKey, PermissionWeight,
    recover_permission_weight,
};
pub use secp256k1::{Secp256k1Key, Secp256k1PublicKey};
pub use signature::{CryptoError, RecoverableSignature};
pub use sm2::{Sm2Key, Sm2PublicKey};
