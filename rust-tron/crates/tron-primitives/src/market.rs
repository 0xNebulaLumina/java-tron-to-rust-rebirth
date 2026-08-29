use core::cmp::Ordering;
use num_bigint::BigInt;

pub const MARKET_TOKEN_ID_LENGTH: usize = 19;
pub const MARKET_PAIR_LENGTH: usize = MARKET_TOKEN_ID_LENGTH * 2;
pub const MARKET_PRICE_KEY_LENGTH: usize = MARKET_PAIR_LENGTH + 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarketPrice {
    pub sell_quantity: i64,
    pub buy_quantity: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarketKeyError {
    TooShort { minimum: usize, actual: usize },
}

/// Java/BouncyCastle unsigned lexicographic byte comparison.
pub fn compare_unsigned(left: &[u8], right: &[u8]) -> Ordering { left.cmp(right) }

/// Java `new BigInteger(1, bytes).longValue()`: positive parse followed by low-64-bit truncation.
pub fn positive_bytes_to_i64_truncating(bytes: &[u8]) -> i64 {
    let mut low = [0u8; 8];
    let source = if bytes.len() > 8 { &bytes[bytes.len() - 8..] } else { bytes };
    low[8 - source.len()..].copy_from_slice(source);
    i64::from_be_bytes(low)
}

pub fn compare_price(left: MarketPrice, right: MarketPrice) -> Ordering {
    match (
        left.buy_quantity.checked_mul(right.sell_quantity),
        right.buy_quantity.checked_mul(left.sell_quantity),
    ) {
        (Some(left_cross), Some(right_cross)) => left_cross.cmp(&right_cross),
        _ => {
            let left_cross = BigInt::from(left.buy_quantity) * BigInt::from(right.sell_quantity);
            let right_cross = BigInt::from(right.buy_quantity) * BigInt::from(left.sell_quantity);
            left_cross.cmp(&right_cross)
        }
    }
}

/// Compares the 54-byte Java market price-key prefix. Additional suffix bytes are ignored,
/// matching Java's fixed-range copies. Zero prices sort before nonzero prices.
pub fn compare_price_key(left: &[u8], right: &[u8]) -> Result<Ordering, MarketKeyError> {
    if left.len() < MARKET_PRICE_KEY_LENGTH {
        return Err(MarketKeyError::TooShort { minimum: MARKET_PRICE_KEY_LENGTH, actual: left.len() });
    }
    if right.len() < MARKET_PRICE_KEY_LENGTH {
        return Err(MarketKeyError::TooShort { minimum: MARKET_PRICE_KEY_LENGTH, actual: right.len() });
    }

    let pair_order = compare_unsigned(&left[..MARKET_PAIR_LENGTH], &right[..MARKET_PAIR_LENGTH]);
    if pair_order != Ordering::Equal {
        return Ok(pair_order);
    }

    let decode = |key: &[u8]| MarketPrice {
        sell_quantity: positive_bytes_to_i64_truncating(&key[MARKET_PAIR_LENGTH..MARKET_PAIR_LENGTH + 8]),
        buy_quantity: positive_bytes_to_i64_truncating(&key[MARKET_PAIR_LENGTH + 8..MARKET_PRICE_KEY_LENGTH]),
    };
    let left_price = decode(left);
    let right_price = decode(right);
    let left_zero = left_price.sell_quantity == 0 || left_price.buy_quantity == 0;
    let right_zero = right_price.sell_quantity == 0 || right_price.buy_quantity == 0;

    Ok(match (left_zero, right_zero) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => compare_price(left_price, right_price),
    })
}
