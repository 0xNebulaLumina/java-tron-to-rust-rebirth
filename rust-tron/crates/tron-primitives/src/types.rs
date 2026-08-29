use core::{cmp::Ordering, fmt};
use num_bigint::BigUint;

pub const ADDRESS20_LENGTH: usize = 20;
pub const TRON_ADDRESS_LENGTH: usize = 21;
pub const HASH_LENGTH: usize = 32;
pub const DEFAULT_TRON_PREFIX: u8 = 0x41;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedBytesError {
    InvalidLength { expected: usize, actual: usize },
    InvalidAddressPrefix { expected: u8, actual: u8 },
}

impl fmt::Display for FixedBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => write!(f, "invalid byte length: expected {expected}, got {actual}"),
            Self::InvalidAddressPrefix { expected, actual } => write!(f, "invalid TRON address prefix: expected 0x{expected:02x}, got 0x{actual:02x}"),
        }
    }
}

impl std::error::Error for FixedBytesError {}

macro_rules! fixed_bytes {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const LENGTH: usize = $len;
            pub const ZERO: Self = Self([0; $len]);

            pub const fn from_array(bytes: [u8; $len]) -> Self { Self(bytes) }
            pub const fn as_array(&self) -> &[u8; $len] { &self.0 }
            pub const fn as_bytes(&self) -> &[u8] { &self.0 }
            pub const fn into_array(self) -> [u8; $len] { self.0 }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = FixedBytesError;
            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                let bytes = <[u8; $len]>::try_from(value).map_err(|_| FixedBytesError::InvalidLength { expected: $len, actual: value.len() })?;
                Ok(Self(bytes))
            }
        }

        impl From<[u8; $len]> for $name { fn from(value: [u8; $len]) -> Self { Self(value) } }
        impl From<$name> for [u8; $len] { fn from(value: $name) -> Self { value.0 } }
        impl AsRef<[u8]> for $name { fn as_ref(&self) -> &[u8] { &self.0 } }
        impl fmt::Debug for $name { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}({})", stringify!($name), crate::bytes::to_hex(&self.0)) } }
        impl fmt::Display for $name { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&crate::bytes::to_hex(&self.0)) } }
    };
}

fixed_bytes!(Address20, ADDRESS20_LENGTH);
fixed_bytes!(Hash32, HASH_LENGTH);

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct TronAddress21([u8; TRON_ADDRESS_LENGTH]);

impl TronAddress21 {
    pub const LENGTH: usize = TRON_ADDRESS_LENGTH;

    pub fn new(prefix: u8, payload: Address20) -> Self {
        let mut bytes = [0; TRON_ADDRESS_LENGTH];
        bytes[0] = prefix;
        bytes[1..].copy_from_slice(payload.as_bytes());
        Self(bytes)
    }

    pub fn validate(bytes: &[u8], expected_prefix: u8) -> Result<Self, FixedBytesError> {
        let bytes = <[u8; TRON_ADDRESS_LENGTH]>::try_from(bytes).map_err(|_| FixedBytesError::InvalidLength { expected: TRON_ADDRESS_LENGTH, actual: bytes.len() })?;
        if bytes[0] != expected_prefix {
            return Err(FixedBytesError::InvalidAddressPrefix { expected: expected_prefix, actual: bytes[0] });
        }
        Ok(Self(bytes))
    }

    pub fn validate_mainnet(bytes: &[u8]) -> Result<Self, FixedBytesError> { Self::validate(bytes, DEFAULT_TRON_PREFIX) }
    pub const fn prefix(&self) -> u8 { self.0[0] }
    pub fn payload(&self) -> Address20 { Address20::from_array(self.0[1..].try_into().expect("fixed slice")) }
    pub const fn as_bytes(&self) -> &[u8] { &self.0 }
    pub const fn into_array(self) -> [u8; TRON_ADDRESS_LENGTH] { self.0 }
}

impl AsRef<[u8]> for TronAddress21 { fn as_ref(&self) -> &[u8] { &self.0 } }
impl fmt::Debug for TronAddress21 { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "TronAddress21({})", crate::bytes::to_hex(&self.0)) } }
impl fmt::Display for TronAddress21 { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&crate::bytes::to_hex(&self.0)) } }

impl Hash32 {
    pub fn to_positive_biguint(self) -> BigUint { BigUint::from_bytes_be(&self.0) }
}

impl Ord for Hash32 {
    fn cmp(&self, other: &Self) -> Ordering { self.0.iter().rev().cmp(other.0.iter().rev()) }
}
impl PartialOrd for Hash32 { fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) } }

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransactionId(Hash32);
impl TransactionId { pub const fn new(hash: Hash32) -> Self { Self(hash) } pub const fn hash(self) -> Hash32 { self.0 } pub const fn as_bytes(&self) -> &[u8] { self.0.as_bytes() } }
impl From<Hash32> for TransactionId { fn from(value: Hash32) -> Self { Self(value) } }
impl From<TransactionId> for Hash32 { fn from(value: TransactionId) -> Self { value.0 } }

/// Java-compatible block identifier: equality covers all 32 overlaid bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BlockId(Hash32);
impl BlockId {
    pub fn new(height: i64, hash: Hash32) -> Self {
        let mut bytes = hash.into_array();
        bytes[..8].copy_from_slice(&height.to_be_bytes());
        Self(Hash32::from_array(bytes))
    }
    pub const fn from_overlaid_hash(hash: Hash32) -> Self { Self(hash) }
    pub const fn hash(self) -> Hash32 { self.0 }
    pub const fn as_bytes(&self) -> &[u8] { self.0.as_bytes() }
    pub fn height(&self) -> i64 { i64::from_be_bytes(self.0.as_bytes()[..8].try_into().expect("fixed slice")) }
    /// Matches Java `BlockId.compareTo(BlockId)`: compare only the overlaid signed block height.
    pub fn height_compare(&self, other: &Self) -> Ordering { self.height().cmp(&other.height()) }
    /// Forward unsigned lexicographic ordering across all 32 identifier bytes.
    /// This is deliberately separate from Java's height-only `BlockId` comparison.
    pub fn total_bytes_compare(&self, other: &Self) -> Ordering { self.as_bytes().cmp(other.as_bytes()) }
    /// Matches inherited Java `Sha256Hash.compareTo` for a non-`BlockId` hash (reverse-byte order).
    pub fn cmp_hash(&self, hash: &Hash32) -> Ordering { self.0.cmp(hash) }
}
impl From<BlockId> for Hash32 { fn from(value: BlockId) -> Self { value.0 } }
impl PartialEq<Hash32> for BlockId { fn eq(&self, other: &Hash32) -> bool { self.0 == *other } }
impl PartialEq<BlockId> for Hash32 { fn eq(&self, other: &BlockId) -> bool { *self == other.0 } }

pub trait DigestProvider {
    type Error;
    fn digest(&self, input: &[u8]) -> Result<Hash32, Self::Error>;
    fn digest_pair(&self, left: &Hash32, right: &Hash32) -> Result<Hash32, Self::Error> {
        let mut input = [0; HASH_LENGTH * 2];
        input[..HASH_LENGTH].copy_from_slice(left.as_bytes());
        input[HASH_LENGTH..].copy_from_slice(right.as_bytes());
        self.digest(&input)
    }
}
