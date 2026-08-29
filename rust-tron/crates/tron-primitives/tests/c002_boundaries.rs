use core::cmp::Ordering;
use std::{cell::Cell, collections::HashSet, sync::{Arc, atomic::{AtomicUsize, Ordering as AtomicOrdering}}};

use num_bigint::BigInt;

use tron_primitives::{
    arithmetic::{
        abs_i64, add, float_operation, max_i32, max_i64, min_i32, min_i64, multiply,
        pow_bits, subtract, FloatMathProvider, FloatOperation, FloatResult,
    },
    bytes::{
        bigint_to_fixed_bytes, concat_fixed, exact_slice, i32_from_be_bytes,
        i32_from_le_bytes, i32_to_be_bytes, i32_to_le_bytes, i64_from_be_bytes,
        i64_from_le_bytes, i64_to_be_bytes, i64_to_le_bytes, locale_root_lowercase_key,
        locale_root_uppercase_key, ByteError,
    },
    compare_price, compare_price_key, merkle_root, positive_bytes_to_i64_truncating,
    ref_block_bytes, ref_block_hash, ArithmeticMode, BlockId, BlockWire, DigestProvider, Hash32,
    MarketPrice, MathPolicy, PowProvider, TransactionWire,
};

struct RecordingDigest { calls: Cell<usize> }
impl RecordingDigest { fn new() -> Self { Self { calls: Cell::new(0) } } }
impl DigestProvider for RecordingDigest {
    type Error = core::convert::Infallible;
    fn digest(&self, input: &[u8]) -> Result<Hash32, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        let mut output = [0u8; 32];
        for (index, byte) in input.iter().enumerate() { output[index % 32] ^= *byte; }
        Ok(Hash32::from_array(output))
    }
}

#[test]
fn merkle_empty_single_and_odd_promotion_match_java() {
    let digest = RecordingDigest::new();
    assert_eq!(merkle_root(&digest, &[]).unwrap(), Hash32::ZERO);
    let one = Hash32::from_array([1; 32]);
    assert_eq!(merkle_root(&digest, &[one]).unwrap(), one);
    let two = Hash32::from_array([2; 32]);
    let three = Hash32::from_array([3; 32]);
    let root = merkle_root(&digest, &[one, two, three]).unwrap();
    assert_eq!(root, digest.digest_pair(&digest.digest_pair(&one, &two).unwrap(), &three).unwrap());
}

#[test]
fn wire_hashes_use_distinct_raw_and_full_boundaries_without_provider_agnostic_caches() {
    let digest = RecordingDigest::new();
    let transaction = TransactionWire::new(vec![9, 8, 7], vec![1, 2]);
    let id = transaction.transaction_id(&digest).unwrap();
    assert_eq!(id.hash(), digest.digest(&[1, 2]).unwrap());
    let full = transaction.full_hash(&digest).unwrap();
    assert_eq!(full, digest.digest(&[9, 8, 7]).unwrap());
    let calls = digest.calls.get();
    assert_eq!(transaction.transaction_id(&digest).unwrap(), id);
    assert_eq!(transaction.full_hash(&digest).unwrap(), full);
    assert_eq!(digest.calls.get(), calls + 2);

    let block = BlockWire::new(vec![0xaa], vec![4, 5], 0x0102_0304_0506_0708);
    let block_id = block.block_id(&digest).unwrap();
    assert_eq!(&block_id.as_bytes()[..8], &0x0102_0304_0506_0708i64.to_be_bytes());
}

struct PrefixDigest { prefix: u8, calls: AtomicUsize }
impl PrefixDigest { fn new(prefix: u8) -> Self { Self { prefix, calls: AtomicUsize::new(0) } } }
impl DigestProvider for PrefixDigest {
    type Error = core::convert::Infallible;
    fn digest(&self, _input: &[u8]) -> Result<Hash32, Self::Error> {
        self.calls.fetch_add(1, AtomicOrdering::Relaxed);
        Ok(Hash32::from_array([self.prefix; 32]))
    }
}

#[test]
fn sequential_and_concurrent_digest_providers_cannot_poison_wire_ids() {
    let transaction = Arc::new(TransactionWire::new(vec![9], vec![1]));
    let first = PrefixDigest::new(0x11);
    let second = PrefixDigest::new(0x22);
    assert_eq!(transaction.transaction_id(&first).unwrap().as_bytes(), &[0x11; 32]);
    assert_eq!(transaction.transaction_id(&second).unwrap().as_bytes(), &[0x22; 32]);

    let block = Arc::new(BlockWire::new(vec![9], vec![1], 7));
    let providers = [Arc::new(PrefixDigest::new(0x33)), Arc::new(PrefixDigest::new(0x44))];
    let handles: Vec<_> = providers.iter().map(|provider| {
        let block = Arc::clone(&block);
        let provider = Arc::clone(provider);
        std::thread::spawn(move || block.block_id(provider.as_ref()).unwrap())
    }).collect();
    let ids: Vec<_> = handles.into_iter().map(|handle| handle.join().unwrap()).collect();
    assert_eq!(&ids[0].as_bytes()[8..], &[0x33; 24]);
    assert_eq!(&ids[1].as_bytes()[8..], &[0x44; 24]);
    assert_eq!(providers[0].calls.load(AtomicOrdering::Relaxed), 1);
    assert_eq!(providers[1].calls.load(AtomicOrdering::Relaxed), 1);
}

struct PowChoice(Cell<Option<&'static str>>);
impl PowProvider for PowChoice {
    type Error = core::convert::Infallible;
    fn strict_pow(&self, _: u64, _: u64) -> Result<u64, Self::Error> { self.0.set(Some("strict")); Ok(1) }
    fn legacy_pow(&self, _: u64, _: u64) -> Result<u64, Self::Error> { self.0.set(Some("legacy")); Ok(2) }
}

#[test]
fn math_flags_are_independent_and_integer_wrappers_never_wrap() {
    for allow_strict_math in [false, true] {
        for disable_java_lang_math in [false, true] {
            let policy = MathPolicy { allow_strict_math, disable_java_lang_math };
            let expected_mode = if disable_java_lang_math { ArithmeticMode::Strict } else { ArithmeticMode::Legacy };
            assert_eq!(policy.arithmetic_mode(), expected_mode);
            assert!(add(i64::MAX, 1, expected_mode).is_err());
            assert!(subtract(i64::MIN, 1, expected_mode).is_err());
            assert!(multiply(i64::MAX, 2, expected_mode).is_err());
            let pow = PowChoice(Cell::new(None));
            let _ = pow_bits(&pow, 0, 0, policy).unwrap();
            assert_eq!(pow.0.get(), Some(if allow_strict_math { "strict" } else { "legacy" }));
        }
    }
}

struct FloatChoice(Cell<Option<(&'static str, FloatOperation)>>);
impl FloatMathProvider for FloatChoice {
    type Error = core::convert::Infallible;
    fn strict_float(&self, operation: FloatOperation) -> Result<FloatResult, Self::Error> {
        self.0.set(Some(("strict", operation)));
        Ok(FloatResult::F64Bits(f64::NAN.to_bits()))
    }
    fn legacy_float(&self, operation: FloatOperation) -> Result<FloatResult, Self::Error> {
        self.0.set(Some(("legacy", operation)));
        Ok(FloatResult::I64(0))
    }
}

#[test]
fn signed_endian_concat_and_exact_slice_boundaries_match_java() {
    for value in [i64::MIN, -1, 0, 1, i64::MAX] {
        assert_eq!(i64_from_be_bytes(i64_to_be_bytes(value)), value);
        assert_eq!(i64_from_le_bytes(i64_to_le_bytes(value)), value);
    }
    for value in [i32::MIN, -1, 0, 1, i32::MAX] {
        assert_eq!(i32_from_be_bytes(i32_to_be_bytes(value)), value);
        assert_eq!(i32_from_le_bytes(i32_to_le_bytes(value)), value);
    }
    assert_eq!(concat_fixed::<4>(&[&[0x01, 0x02], &[0x03, 0x04]]).unwrap(), [1, 2, 3, 4]);
    assert_eq!(concat_fixed::<3>(&[&[1, 2], &[3, 4]]), Err(ByteError::WidthMismatch { expected: 3, actual: 4 }));
    assert_eq!(exact_slice(&[0, 1, 2, 3], 1, 3).unwrap(), [1, 2]);
    assert_eq!(exact_slice(&[0, 1, 2], 2, 4), Err(ByteError::InvalidRange { start: 2, end: 4, len: 3 }));
}

#[test]
fn bigint_fixed_width_copy_matches_java_sign_and_overflow_boundaries() {
    for (value, width, expected) in [
        (66_051, 2, vec![0x02, 0x03]),
        (128, 1, vec![0x80]),
        (-129, 1, vec![0x7f]),
        (-66_052, 1, vec![0xfe]),
    ] {
        assert_eq!(bigint_to_fixed_bytes(Some(&BigInt::from(value)), width), Some(expected));
    }
    assert_eq!(bigint_to_fixed_bytes(None, 2), None);
}

#[test]
fn deterministic_java_math_and_injected_float_boundaries_are_explicit() {
    assert_eq!((min_i32(7, -2), max_i32(7, -2)), (-2, 7));
    assert_eq!((min_i64(i64::MIN, 0), max_i64(i64::MAX, 0)), (i64::MIN, i64::MAX));
    assert_eq!(abs_i64(-7), 7);
    assert_eq!(abs_i64(i64::MIN), i64::MIN);

    let provider = FloatChoice(Cell::new(None));
    let cases = [
        FloatOperation::RoundF32 { input_bits: f32::NAN.to_bits() },
        FloatOperation::RoundF64 { input_bits: f64::NEG_INFINITY.to_bits() },
        FloatOperation::CeilF64 { input_bits: (-0.0f64).to_bits() },
        FloatOperation::SignumF64 { input_bits: f64::INFINITY.to_bits() },
    ];
    for operation in cases {
        let _ = float_operation(&provider, operation, true).unwrap();
        assert_eq!(provider.0.get(), Some(("strict", operation)));
        let _ = float_operation(&provider, operation, false).unwrap();
        assert_eq!(provider.0.get(), Some(("legacy", operation)));
    }
}

#[test]
fn locale_root_keys_use_full_unicode_casing_without_normalization() {
    assert_eq!(locale_root_lowercase_key("ΟΣ"), "ος");
    assert_eq!(locale_root_lowercase_key("ΟΣΑ"), "οσα");
    assert_eq!(locale_root_lowercase_key("İ"), "i\u{0307}");
    assert_eq!(locale_root_lowercase_key("iIıİ"), "iiıi\u{0307}");
    assert_eq!(locale_root_uppercase_key("iIıİ"), "IIIİ");
    assert_eq!(locale_root_uppercase_key("ß"), "SS");
    assert_eq!(locale_root_lowercase_key("𐐀"), "𐐨");
    assert_eq!(locale_root_uppercase_key("𐐨"), "𐐀");
}

#[test]
fn block_id_equality_and_explicit_comparators_are_collection_safe() {
    let left = BlockId::new(9, Hash32::from_array([1; 32]));
    let right = BlockId::new(9, Hash32::from_array([2; 32]));
    assert_eq!(left.height_compare(&right), Ordering::Equal);
    assert_ne!(left.total_bytes_compare(&right), Ordering::Equal);
    let ids = HashSet::from([left, right]);
    assert_eq!(ids.len(), 2);
}

#[test]
fn tapos_uses_low_two_height_and_middle_eight_hash_bytes() {
    assert_eq!(ref_block_bytes(0x0102_0304_0506_0708), [0x07, 0x08]);
    assert_eq!(ref_block_bytes(-1), [0xff, 0xff]);
    let hash = Hash32::from_array(core::array::from_fn(|index| index as u8));
    assert_eq!(ref_block_hash(&hash), [8, 9, 10, 11, 12, 13, 14, 15]);
}

#[test]
fn market_comparison_uses_unsigned_pairs_and_bigint_overflow_fallback() {
    assert_eq!(positive_bytes_to_i64_truncating(&[0xff; 8]), -1);
    assert_eq!(compare_price(
        MarketPrice { sell_quantity: i64::MAX, buy_quantity: i64::MAX },
        MarketPrice { sell_quantity: i64::MAX - 1, buy_quantity: i64::MAX },
    ), Ordering::Less);

    let mut left = [0u8; 54];
    let mut right = [0u8; 54];
    left[0] = 0x80;
    right[0] = 0x7f;
    assert_eq!(compare_price_key(&left, &right).unwrap(), Ordering::Greater);

    left[0] = 0;
    right[0] = 0;
    right[38..46].copy_from_slice(&1i64.to_be_bytes());
    right[46..54].copy_from_slice(&1i64.to_be_bytes());
    assert_eq!(compare_price_key(&left, &right).unwrap(), Ordering::Less);
}
