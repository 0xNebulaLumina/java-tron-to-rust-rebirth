//! Explicit boundary between preserved inbound protobuf bytes and Rust encoding.
//!
//! Java protobuf messages retain unknown fields and can therefore often re-encode an inbound
//! message byte-for-byte. Prost intentionally discards unknown fields. Code that hashes, verifies
//! signatures, or relays network/API payloads must consequently use [`PreservedMessage`] and
//! [`PreservedMessage::emit_original`], never re-encode its decoded message.
//!
//! Messages constructed or mutated in Rust cross the separate [`encode_constructed`] boundary.
//! That boundary is Java-compatible only for messages without map fields. Direct
//! `prost::Message::encode` (including through [`encode_constructed`]) on a constructed map-bearing
//! message is forbidden at observable wire boundaries because generated maps do not retain caller
//! insertion order. Encode those fields with [`crate::ordered_map::OrderedMapEncoder`] instead.
//! Field ordering, duplicate fields, explicit defaults, and unknown fields from an inbound payload
//! are preserved only by retaining the original bytes.

use prost::{DecodeError, Message};

/// A successfully decoded protobuf message paired with its exact inbound wire representation.
#[derive(Clone, Debug)]
pub struct PreservedMessage<M> {
    original: Vec<u8>,
    message: M,
}

impl<M> PreservedMessage<M>
where
    M: Message + Default,
{
    /// Decodes known fields while retaining every original byte, including unknown fields.
    ///
    /// Passing a `Vec<u8>` transfers ownership without copying; borrowed input is copied because
    /// the preservation boundary must own it.
    pub fn decode(bytes: impl Into<Vec<u8>>) -> Result<Self, DecodeError> {
        let original = bytes.into();
        let message = M::decode(original.as_slice())?;
        Ok(Self { original, message })
    }
}

impl<M> PreservedMessage<M> {
    /// Returns the decoded known-field view without permitting accidental mutation.
    #[must_use]
    pub fn message(&self) -> &M {
        &self.message
    }

    /// Returns the exact bytes supplied to [`Self::decode`].
    #[must_use]
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }

    /// Emits the exact inbound bytes. This is the relay/hash/signature-safe path.
    #[must_use]
    pub fn emit_original(&self) -> Vec<u8> {
        self.original.clone()
    }

    /// Consumes the preservation boundary and returns the decoded message for explicit mutation.
    /// Re-emission after this point must use [`encode_constructed`].
    #[must_use]
    pub fn into_message(self) -> M {
        self.message
    }

    /// Consumes the boundary and returns both representations.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, M) {
        (self.original, self.message)
    }
}

/// Deterministically encodes a constructed message that has no protobuf map fields.
///
/// Calling this for a map-bearing message is not Java-compatible and is forbidden at observable
/// wire boundaries; use [`crate::ordered_map::OrderedMapEncoder`]. This function also cannot restore
/// unknown fields or reproduce non-canonical inbound encodings; use
/// [`PreservedMessage::emit_original`] when exact inbound bytes are required.
#[must_use]
pub fn encode_constructed<M: Message>(message: &M) -> Vec<u8> {
    message.encode_to_vec()
}
