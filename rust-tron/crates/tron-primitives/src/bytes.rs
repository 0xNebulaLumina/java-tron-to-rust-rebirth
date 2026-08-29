use core::{cmp::Ordering, fmt};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::ToPrimitive;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ByteError {
    InvalidHex { index: usize, byte: u8 },
    InvalidRange { start: usize, end: usize, len: usize },
    WidthMismatch { expected: usize, actual: usize },
    InvalidUtf8,
    IntegerOutOfRange,
    LengthOverflow,
}

impl fmt::Display for ByteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex { index, byte } => write!(f, "invalid hexadecimal byte 0x{byte:02x} at index {index}"),
            Self::InvalidRange { start, end, len } => write!(f, "invalid byte range [{start}, {end}) for length {len}"),
            Self::WidthMismatch { expected, actual } => write!(f, "expected {expected} bytes, got {actual}"),
            Self::InvalidUtf8 => f.write_str("bytes are not valid UTF-8"),
            Self::IntegerOutOfRange => f.write_str("integer is out of range"),
            Self::LengthOverflow => f.write_str("concatenated byte length overflows usize"),
        }
    }
}
impl std::error::Error for ByteError {}

pub const fn i64_to_be_bytes(value: i64) -> [u8; 8] { value.to_be_bytes() }
pub const fn i64_to_le_bytes(value: i64) -> [u8; 8] { value.to_le_bytes() }
pub const fn i32_to_be_bytes(value: i32) -> [u8; 4] { value.to_be_bytes() }
pub const fn i32_to_le_bytes(value: i32) -> [u8; 4] { value.to_le_bytes() }
pub const fn i64_from_be_bytes(bytes: [u8; 8]) -> i64 { i64::from_be_bytes(bytes) }
pub const fn i64_from_le_bytes(bytes: [u8; 8]) -> i64 { i64::from_le_bytes(bytes) }
pub const fn i32_from_be_bytes(bytes: [u8; 4]) -> i32 { i32::from_be_bytes(bytes) }
pub const fn i32_from_le_bytes(bytes: [u8; 4]) -> i32 { i32::from_le_bytes(bytes) }

pub fn unsigned_lexicographic_cmp(left: &[u8], right: &[u8]) -> Ordering { left.cmp(right) }
pub fn reverse_unsigned_lexicographic_cmp(left: &[u8], right: &[u8]) -> Ordering { left.iter().rev().cmp(right.iter().rev()) }

pub fn concat(parts: &[&[u8]]) -> Result<Vec<u8>, ByteError> {
    let capacity = parts.iter().try_fold(0usize, |sum, part| sum.checked_add(part.len())).ok_or(ByteError::LengthOverflow)?;
    let mut output = Vec::with_capacity(capacity);
    for part in parts { output.extend_from_slice(part); }
    Ok(output)
}

pub fn concat_fixed<const N: usize>(parts: &[&[u8]]) -> Result<[u8; N], ByteError> {
    let bytes = concat(parts)?;
    let actual = bytes.len();
    bytes.try_into().map_err(|_: Vec<u8>| ByteError::WidthMismatch { expected: N, actual })
}

pub fn exact_slice(input: &[u8], start: usize, end: usize) -> Result<Vec<u8>, ByteError> {
    input.get(start..end).map(<[u8]>::to_vec).ok_or(ByteError::InvalidRange { start, end, len: input.len() })
}

/// Java ByteUtil.parseBytes: an offset at/past the end or zero length returns empty;
/// otherwise the result has exactly `len` bytes and is right-padded with zeroes.
pub fn parse_bytes(input: &[u8], offset: usize, len: usize) -> Vec<u8> {
    if offset >= input.len() || len == 0 { return Vec::new(); }
    let mut output = vec![0; len];
    let copied = len.min(input.len() - offset);
    output[..copied].copy_from_slice(&input[offset..offset + copied]);
    output
}

pub fn parse_word(input: &[u8], index: usize) -> Vec<u8> {
    index.checked_mul(32).map_or_else(Vec::new, |offset| parse_bytes(input, offset, 32))
}

pub fn increment_be(bytes: &mut [u8]) -> bool {
    for byte in bytes.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 { return true; }
    }
    false
}

pub fn long_to_32_bytes(value: i64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

pub fn int_to_bytes_no_leading_zeroes(value: i32) -> Vec<u8> {
    if value == 0 { return Vec::new(); }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len() - 1);
    bytes[first..].to_vec()
}

pub fn strip_leading_zeroes(input: Option<&[u8]>) -> Option<Vec<u8>> {
    input.map(|bytes| match bytes.iter().position(|byte| *byte != 0) {
        None => vec![0],
        Some(0) => bytes.to_vec(),
        Some(first) => bytes[first..].to_vec(),
    })
}

pub fn positive_biguint(input: Option<&[u8]>) -> BigUint { BigUint::from_bytes_be(input.unwrap_or_default()) }
pub fn positive_to_i64_truncating(input: Option<&[u8]>) -> i64 {
    let bytes = input.unwrap_or_default();
    let mut low = [0; 8];
    let copied = bytes.len().min(8);
    low[8 - copied..].copy_from_slice(&bytes[bytes.len() - copied..]);
    i64::from_be_bytes(low)
}
pub fn positive_to_i32_truncating(input: Option<&[u8]>) -> i32 {
    let bytes = input.unwrap_or_default();
    let mut low = [0; 4];
    let copied = bytes.len().min(4);
    low[4 - copied..].copy_from_slice(&bytes[bytes.len() - copied..]);
    i32::from_be_bytes(low)
}
pub fn positive_to_i64_exact(input: Option<&[u8]>) -> Result<i64, ByteError> {
    positive_biguint(input).to_i64().ok_or(ByteError::IntegerOutOfRange)
}

/// Java BigInteger.toByteArray-compatible two's-complement bytes, copied/truncated
/// from the source head and right-aligned. Java unconditionally skips the first
/// source byte when the signed representation is exactly one byte wider.
pub fn bigint_to_fixed_bytes(value: Option<&BigInt>, width: usize) -> Option<Vec<u8>> {
    value.map(|value| {
        let mut signed = value.to_signed_bytes_be();
        if signed.is_empty() { signed.push(0); }
        let source_start = usize::from(width.checked_add(1) == Some(signed.len()));
        let len = (signed.len() - source_start).min(width);
        let mut output = vec![0; width];
        output[width - len..].copy_from_slice(&signed[source_start..source_start + len]);
        output
    })
}

pub fn bigint_to_unsigned_bytes(value: Option<&BigInt>) -> Option<Vec<u8>> {
    value.map(|value| {
        let mut bytes = value.to_signed_bytes_be();
        if bytes.is_empty() { return vec![0]; }
        if bytes.len() != 1 && bytes[0] == 0 { bytes.remove(0); }
        bytes
    })
}

pub fn to_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input { output.push(HEX[(byte >> 4) as usize] as char); output.push(HEX[(byte & 0x0f) as usize] as char); }
    output
}

pub fn to_hex_or_empty(input: Option<&[u8]>) -> String { input.map_or_else(String::new, to_hex) }

pub fn from_hex(input: Option<&str>) -> Result<Vec<u8>, ByteError> {
    let Some(mut input) = input else { return Ok(Vec::new()); };
    if let Some(stripped) = input.strip_prefix("0x") { input = stripped; }
    let padded;
    if input.len() % 2 == 1 { padded = format!("0{input}"); input = &padded; }
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 2);
    for index in (0..bytes.len()).step_by(2) {
        let high = hex_nibble(bytes[index]).ok_or(ByteError::InvalidHex { index, byte: bytes[index] })?;
        let low = hex_nibble(bytes[index + 1]).ok_or(ByteError::InvalidHex { index: index + 1, byte: bytes[index + 1] })?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte { b'0'..=b'9' => Some(byte - b'0'), b'a'..=b'f' => Some(byte - b'a' + 10), b'A'..=b'F' => Some(byte - b'A' + 10), _ => None }
}

pub fn utf8_from_string(input: Option<&str>) -> Option<Vec<u8>> {
    input.and_then(|value| if value.trim().is_empty() { None } else { Some(value.as_bytes().to_vec()) })
}
pub fn utf8_to_string(input: Option<&[u8]>) -> Result<Option<String>, ByteError> {
    let Some(bytes) = input.filter(|bytes| !bytes.is_empty()) else { return Ok(None); };
    String::from_utf8(bytes.to_vec()).map(Some).map_err(|_| ByteError::InvalidUtf8)
}

/// Locale.ROOT-compatible full Unicode lowercase mapping for Rust UTF-8 strings.
///
/// Rust 1.85's pinned `str::to_lowercase` mapping is used on the complete string so
/// contextual and expanding mappings are preserved. The input domain is valid Unicode
/// scalar values; unpaired Java UTF-16 surrogates are outside Rust's `str` contract.
/// No Unicode normalization is performed.
pub fn locale_root_lowercase_key(input: &str) -> String { input.to_lowercase() }

/// Locale.ROOT-compatible full Unicode uppercase mapping with the same scalar-value
/// domain and no normalization.
pub fn locale_root_uppercase_key(input: &str) -> String { input.to_uppercase() }

pub fn bigint_from_positive_bytes(bytes: &[u8]) -> BigInt { BigInt::from_bytes_be(Sign::Plus, bytes) }
