//! Java-compatible encoding for constructed protobuf map fields.
//!
//! `prost::Message::encode` iterates the generated map representation rather than the caller's
//! insertion sequence. Map-bearing messages constructed or mutated in Rust must therefore use
//! this encoder at observable wire boundaries. Raw decoded messages remain the responsibility of
//! [`crate::wire::PreservedMessage`].

use std::{error::Error, fmt};

/// Hard bounds applied while constructing ordered map wire bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedMapLimits {
    /// Maximum number of map entries accepted by one encoder.
    pub max_entries: usize,
    /// Maximum encoded byte length accepted by one encoder.
    pub max_encoded_len: usize,
}

impl OrderedMapLimits {
    /// Creates explicit entry and byte limits.
    #[must_use]
    pub const fn new(max_entries: usize, max_encoded_len: usize) -> Self {
        Self { max_entries, max_encoded_len }
    }
}

/// An invalid field or bound exceeded while adding an ordered map entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderedMapError {
    /// A protobuf field number must be in the inclusive range `1..=536_870_911`.
    InvalidFieldNumber { field_number: u32 },
    /// Adding the entry would exceed `max_entries`.
    EntryLimit { max_entries: usize },
    /// Adding the entry would exceed `max_encoded_len`.
    EncodedLengthLimit { max_encoded_len: usize },
}

impl fmt::Display for OrderedMapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFieldNumber { field_number } => {
                write!(formatter, "invalid protobuf field number {field_number}")
            }
            Self::EntryLimit { max_entries } => write!(formatter, "ordered map entry limit {max_entries} exceeded"),
            Self::EncodedLengthLimit { max_encoded_len } => {
                write!(formatter, "ordered map encoded length limit {max_encoded_len} exceeded")
            }
        }
    }
}

impl Error for OrderedMapError {}

/// Bounded builder that emits protobuf map entries in exactly the order they are added.
///
/// The methods cover every key/value wire-kind combination in the canonical TRON schemas.
/// Each call is transactional: an error leaves the builder unchanged.
#[derive(Clone, Debug)]
pub struct OrderedMapEncoder {
    limits: OrderedMapLimits,
    entries: usize,
    bytes: Vec<u8>,
}

impl OrderedMapEncoder {
    /// Creates an empty encoder with mandatory resource bounds.
    #[must_use]
    pub fn new(limits: OrderedMapLimits) -> Self {
        Self { limits, entries: 0, bytes: Vec::new() }
    }

    /// Adds a `string -> int64` map entry under `field_number`.
    pub fn push_string_i64(
        &mut self,
        field_number: u32,
        key: &str,
        value: i64,
    ) -> Result<&mut Self, OrderedMapError> {
        self.push_entry(field_number, string_len(key).saturating_add(i64_len(value)), |entry| {
            encode_string(1, key, entry);
            encode_i64(2, value, entry);
        })
    }

    /// Adds a `string -> string` map entry under `field_number`.
    pub fn push_string_string(
        &mut self,
        field_number: u32,
        key: &str,
        value: &str,
    ) -> Result<&mut Self, OrderedMapError> {
        self.push_entry(field_number, string_len(key).saturating_add(string_len(value)), |entry| {
            encode_string(1, key, entry);
            encode_string(2, value, entry);
        })
    }

    /// Adds an `int64 -> int64` map entry under `field_number`.
    pub fn push_i64_i64(
        &mut self,
        field_number: u32,
        key: i64,
        value: i64,
    ) -> Result<&mut Self, OrderedMapError> {
        self.push_entry(field_number, i64_len(key).saturating_add(i64_len(value)), |entry| {
            encode_i64(1, key, entry);
            encode_i64(2, value, entry);
        })
    }

    /// Number of entries successfully added.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries
    }

    /// Encoded bytes accumulated so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the builder and returns the exact ordered wire bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn push_entry(
        &mut self,
        field_number: u32,
        entry_len: usize,
        encode: impl FnOnce(&mut Vec<u8>),
    ) -> Result<&mut Self, OrderedMapError> {
        if !(1..=536_870_911).contains(&field_number) {
            return Err(OrderedMapError::InvalidFieldNumber { field_number });
        }
        if self.entries >= self.limits.max_entries {
            return Err(OrderedMapError::EntryLimit { max_entries: self.limits.max_entries });
        }

        let added_len = varint_len((u64::from(field_number) << 3) | 2)
            .saturating_add(varint_len(entry_len as u64))
            .saturating_add(entry_len);
        if self.bytes.len().saturating_add(added_len) > self.limits.max_encoded_len {
            return Err(OrderedMapError::EncodedLengthLimit {
                max_encoded_len: self.limits.max_encoded_len,
            });
        }

        let mut entry = Vec::with_capacity(entry_len);
        encode(&mut entry);
        debug_assert_eq!(entry.len(), entry_len);
        encode_varint((u64::from(field_number) << 3) | 2, &mut self.bytes);
        encode_varint(entry.len() as u64, &mut self.bytes);
        self.bytes.extend_from_slice(&entry);
        self.entries += 1;
        Ok(self)
    }
}

fn string_len(value: &str) -> usize {
    if value.is_empty() {
        0
    } else {
        1usize
            .saturating_add(varint_len(value.len() as u64))
            .saturating_add(value.len())
    }
}

fn i64_len(value: i64) -> usize {
    if value == 0 { 0 } else { 1 + varint_len(value as u64) }
}

fn encode_string(field_number: u32, value: &str, output: &mut Vec<u8>) {
    if value.is_empty() {
        return;
    }
    encode_varint((u64::from(field_number) << 3) | 2, output);
    encode_varint(value.len() as u64, output);
    output.extend_from_slice(value.as_bytes());
}

fn encode_i64(field_number: u32, value: i64, output: &mut Vec<u8>) {
    if value == 0 {
        return;
    }
    encode_varint(u64::from(field_number) << 3, output);
    encode_varint(value as u64, output);
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn varint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        len += 1;
        value >>= 7;
    }
    len
}
