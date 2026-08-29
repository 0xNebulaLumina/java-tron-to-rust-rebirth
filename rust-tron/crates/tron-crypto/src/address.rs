use crate::{CryptoEngine, PublicKey, keccak256, selected_digest_twice};
use tron_primitives::{Address20, TronAddress21};

pub const TRON_ADDRESS_PREFIX: u8 = 0x41;
pub const BASE58_ADDRESS_LENGTH: usize = 34;
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    InvalidLength,
    InvalidPrefix,
    InvalidBase58Character,
    InvalidChecksum,
}

impl core::fmt::Display for AddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "invalid TRON address length",
            Self::InvalidPrefix => "invalid TRON address prefix",
            Self::InvalidBase58Character => "invalid Bitcoin Base58 character",
            Self::InvalidChecksum => "invalid Base58Check checksum",
        })
    }
}

impl std::error::Error for AddressError {}

pub fn derive_address(public_key: &PublicKey) -> TronAddress21 {
    derive_address_from_node_id(&public_key.node_id())
}

pub fn derive_address_from_node_id(node_id: &[u8; 64]) -> TronAddress21 {
    let hash = keccak256(node_id);
    TronAddress21::new(TRON_ADDRESS_PREFIX, Address20::from_array(hash[12..].try_into().expect("fixed slice")))
}

pub fn validate_address(bytes: &[u8]) -> Result<TronAddress21, AddressError> {
    if bytes.len() != TronAddress21::LENGTH { return Err(AddressError::InvalidLength); }
    if bytes[0] != TRON_ADDRESS_PREFIX { return Err(AddressError::InvalidPrefix); }
    TronAddress21::validate_mainnet(bytes).map_err(|_| AddressError::InvalidLength)
}

pub fn encode_base58(input: &[u8]) -> String {
    if input.is_empty() { return String::new(); }
    let zeros = input.iter().take_while(|&&byte| byte == 0).count();
    let mut number = input.to_vec();
    let mut start = zeros;
    let mut encoded = Vec::with_capacity(input.len() * 2);
    while start < number.len() {
        let mut remainder = 0u32;
        for byte in &mut number[start..] {
            let value = (remainder << 8) | u32::from(*byte);
            *byte = (value / 58) as u8;
            remainder = value % 58;
        }
        encoded.push(BASE58_ALPHABET[remainder as usize]);
        while start < number.len() && number[start] == 0 { start += 1; }
    }
    encoded.extend(core::iter::repeat_n(BASE58_ALPHABET[0], zeros));
    encoded.reverse();
    String::from_utf8(encoded).expect("Bitcoin Base58 is ASCII")
}

pub fn decode_base58(input: &str) -> Result<Vec<u8>, AddressError> {
    if input.is_empty() { return Ok(Vec::new()); }
    let bytes = input.as_bytes();
    let zeros = bytes.iter().take_while(|&&byte| byte == BASE58_ALPHABET[0]).count();
    let mut digits = Vec::with_capacity(bytes.len());
    for byte in bytes {
        let digit = BASE58_ALPHABET.iter().position(|candidate| candidate == byte)
            .ok_or(AddressError::InvalidBase58Character)?;
        digits.push(digit as u8);
    }
    let mut start = zeros;
    let mut decoded = Vec::with_capacity(bytes.len());
    while start < digits.len() {
        let mut remainder = 0u32;
        for digit in &mut digits[start..] {
            let value = remainder * 58 + u32::from(*digit);
            *digit = (value / 256) as u8;
            remainder = value % 256;
        }
        decoded.push(remainder as u8);
        while start < digits.len() && digits[start] == 0 { start += 1; }
    }
    decoded.extend(core::iter::repeat_n(0, zeros));
    decoded.reverse();
    Ok(decoded)
}

pub fn encode_base58check(engine: CryptoEngine, payload: &[u8]) -> String {
    let checksum = selected_digest_twice(engine, payload);
    let mut checked = Vec::with_capacity(payload.len() + 4);
    checked.extend_from_slice(payload);
    checked.extend_from_slice(&checksum[..4]);
    encode_base58(&checked)
}

pub fn decode_base58check(engine: CryptoEngine, encoded: &str) -> Result<Vec<u8>, AddressError> {
    let checked = decode_base58(encoded)?;
    if checked.len() <= 4 { return Err(AddressError::InvalidLength); }
    let split = checked.len() - 4;
    let checksum = selected_digest_twice(engine, &checked[..split]);
    if checked[split..] != checksum[..4] { return Err(AddressError::InvalidChecksum); }
    Ok(checked[..split].to_vec())
}

pub fn encode_address_base58check(engine: CryptoEngine, address: &TronAddress21) -> String {
    encode_base58check(engine, address.as_bytes())
}

pub fn decode_address_base58check(engine: CryptoEngine, encoded: &str) -> Result<TronAddress21, AddressError> {
    if encoded.len() != BASE58_ADDRESS_LENGTH { return Err(AddressError::InvalidLength); }
    validate_address(&decode_base58check(engine, encoded)?)
}
