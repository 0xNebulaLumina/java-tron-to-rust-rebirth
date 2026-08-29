use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::{Keccak256, Keccak512};
use sm3::Sm3;
use tron_primitives::{DigestProvider, Hash32};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoEngine {
    Secp256k1,
    Sm2,
}

impl CryptoEngine {
    pub fn from_java_name(name: &str) -> Self {
        if name.eq_ignore_ascii_case("ECKey") { Self::Secp256k1 } else { Self::Sm2 }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Sha256Provider;

#[derive(Clone, Copy, Debug, Default)]
pub struct Sm3Provider;

impl DigestProvider for Sha256Provider {
    type Error = core::convert::Infallible;

    fn digest(&self, input: &[u8]) -> Result<Hash32, Self::Error> {
        Ok(Hash32::from_array(Sha256::digest(input).into()))
    }
}

impl DigestProvider for Sm3Provider {
    type Error = core::convert::Infallible;

    fn digest(&self, input: &[u8]) -> Result<Hash32, Self::Error> {
        Ok(Hash32::from_array(Sm3::digest(input).into()))
    }
}

pub fn selected_digest(engine: CryptoEngine, input: &[u8]) -> [u8; 32] {
    match engine {
        CryptoEngine::Secp256k1 => Sha256::digest(input).into(),
        CryptoEngine::Sm2 => Sm3::digest(input).into(),
    }
}

pub fn selected_digest_twice(engine: CryptoEngine, input: &[u8]) -> [u8; 32] {
    selected_digest(engine, &selected_digest(engine, input))
}

pub fn selected_digest_ranges(engine: CryptoEngine, first: &[u8], second: &[u8]) -> [u8; 32] {
    match engine {
        CryptoEngine::Secp256k1 => {
            let mut digest = Sha256::new();
            digest.update(first);
            digest.update(second);
            digest.finalize().into()
        }
        CryptoEngine::Sm2 => {
            let mut digest = Sm3::new();
            digest.update(first);
            digest.update(second);
            digest.finalize().into()
        }
    }
}

/// Java compatibility: the two-range SM3 overload performs one round, while
/// the SHA-256 overload performs the documented second round.
pub fn selected_digest_twice_ranges(engine: CryptoEngine, first: &[u8], second: &[u8]) -> [u8; 32] {
    let first_round = selected_digest_ranges(engine, first, second);
    match engine {
        CryptoEngine::Secp256k1 => selected_digest(engine, &first_round),
        CryptoEngine::Sm2 => first_round,
    }
}

pub fn keccak256(input: &[u8]) -> [u8; 32] { Keccak256::digest(input).into() }

pub fn keccak512(input: &[u8]) -> [u8; 64] { Keccak512::digest(input).into() }

pub fn ripemd160(input: &[u8]) -> [u8; 20] { Ripemd160::digest(input).into() }
