use core::fmt;

use tron_primitives::BlockId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodecError {
    InvalidLength { kind: &'static str, expected: &'static str, actual: usize },
    MalformedProtobuf { kind: &'static str, source: String },
}
impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { match self {
        Self::InvalidLength { kind, expected, actual } => write!(f, "malformed {kind}: expected {expected}, got {actual} bytes"),
        Self::MalformedProtobuf { kind, source } => write!(f, "malformed {kind} protobuf: {source}"),
    } }
}
impl std::error::Error for CodecError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionValue {
    BlockNumber(i64),
    Transaction(Vec<u8>),
}
impl TransactionValue {
    #[must_use] pub fn encode(&self) -> Vec<u8> { match self { Self::BlockNumber(n) => n.to_be_bytes().to_vec(), Self::Transaction(bytes) => bytes.clone() } }
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() == 8 { return Ok(Self::BlockNumber(i64::from_be_bytes(bytes.try_into().expect("length checked")))); }
        prost::Message::decode(bytes).map(|_: tron_protocol::protocol::Transaction| Self::Transaction(bytes.to_vec())).map_err(|e| CodecError::MalformedProtobuf { kind: "transaction value", source: e.to_string() })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockIndexValue { BlockId(BlockId) }
impl BlockIndexValue {
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let hash = tron_primitives::Hash32::try_from(bytes).map_err(|_| CodecError::InvalidLength { kind: "block index value", expected: "32 bytes", actual: bytes.len() })?;
        Ok(Self::BlockId(BlockId::from_overlaid_hash(hash)))
    }
    #[must_use] pub fn encode(&self) -> Vec<u8> { match self { Self::BlockId(id) => id.as_bytes().to_vec() } }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionHistoryValue {
    BlockNumber(i64),
    TransactionInfo(Vec<u8>),
}
impl TransactionHistoryValue {
    #[must_use] pub fn encode(&self) -> Vec<u8> { match self { Self::BlockNumber(n) => n.to_be_bytes().to_vec(), Self::TransactionInfo(v) => v.clone() } }
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() == 8 { return Ok(Self::BlockNumber(i64::from_be_bytes(bytes.try_into().expect("length checked")))); }
        prost::Message::decode(bytes).map(|_: tron_protocol::protocol::TransactionInfo| Self::TransactionInfo(bytes.to_vec())).map_err(|e| CodecError::MalformedProtobuf { kind: "transaction history value", source: e.to_string() })
    }
}

pub const WITNESS_ADDRESS_LENGTH: usize = 21;
pub const ACTIVE_WITNESSES_KEY: &[u8] = b"active_witnesses";
pub const CURRENT_SHUFFLED_WITNESSES_KEY: &[u8] = b"current_shuffled_witnesses";
#[must_use] pub fn encode_witness_schedule(addresses: &[[u8; WITNESS_ADDRESS_LENGTH]]) -> Vec<u8> { addresses.concat() }
pub fn decode_witness_schedule(bytes: &[u8]) -> Result<Vec<[u8; WITNESS_ADDRESS_LENGTH]>, CodecError> {
    if bytes.len() % WITNESS_ADDRESS_LENGTH != 0 { return Err(CodecError::InvalidLength { kind: "witness schedule", expected: "a multiple of 21 bytes", actual: bytes.len() }); }
    Ok(bytes.chunks_exact(WITNESS_ADDRESS_LENGTH).map(|v| v.try_into().expect("chunk length")).collect())
}
#[must_use] pub const fn zk_proof_value(valid: bool) -> [u8; 1] { [valid as u8] }
pub fn decode_zk_proof_value(bytes: &[u8]) -> Result<bool, CodecError> { match bytes { [0] => Ok(false), [1] => Ok(true), _ => Err(CodecError::InvalidLength { kind: "zk proof flag", expected: "one byte containing 0 or 1", actual: bytes.len() }) } }
#[must_use] pub fn section_bloom_key(section: i32, bit_index: i32) -> Vec<u8> { format!("{:x}", i64::from(section) * 1_000_000 + i64::from(bit_index)).into_bytes() }
