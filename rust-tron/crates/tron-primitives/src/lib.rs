//! Deterministic primitive-type ownership boundary.
//!
//! This crate owns Java-compatible fixed-width values, byte conversion and
//! ordering rules, integer arithmetic policy, and injected time boundaries.
//! Digest and floating-point engines are intentionally injected by later
//! layers; this L0 crate has no crypto engine or ambient clock dependency.

pub mod arithmetic;
pub mod bytes;
pub mod market;
pub mod merkle;
pub mod tapos;
pub mod time;
pub mod types;
pub mod wire;

pub use arithmetic::{ArithmeticError, ArithmeticMode, MathPolicy, PowProvider};
pub use market::{compare_price, compare_price_key, compare_unsigned, positive_bytes_to_i64_truncating, MarketKeyError, MarketPrice, MARKET_PAIR_LENGTH, MARKET_PRICE_KEY_LENGTH, MARKET_TOKEN_ID_LENGTH};
pub use merkle::merkle_root;
pub use tapos::{ref_block_bytes, ref_block_hash, ref_block_hash_from_id, TAPOS_REF_BLOCK_BYTES_LENGTH, TAPOS_REF_BLOCK_HASH_LENGTH};
pub use time::{ConsensusTime, MonotonicClock, MonotonicInstant, UnixMillis, WallClock};
pub use types::{Address20, BlockId, DigestProvider, FixedBytesError, Hash32, TransactionId, TronAddress21};
pub use wire::{BlockWire, TransactionWire};
