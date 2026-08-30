use std::cmp::Ordering;

use tron_storage::{market_order, market_total_cmp, StorageError};

fn key(pair_byte: u8, sell: u64, buy: u64, suffix: &[u8]) -> Vec<u8> {
    let mut key = vec![pair_byte; 38];
    key.extend_from_slice(&sell.to_be_bytes());
    key.extend_from_slice(&buy.to_be_bytes());
    key.extend_from_slice(suffix);
    key
}

#[test]
fn logical_market_order_uses_price_then_full_key_tie_break() {
    let pair = vec![7; 38];
    let zero = key(7, 0, 9, b"");
    let half_a = key(7, 2, 1, b"a");
    let half_b = key(7, 4, 2, b"b");
    let two = key(7, 1, 2, b"");
    let other_pair = key(8, 1, 1, b"");

    let ordered = market_order(
        vec![
            (two.clone(), vec![]),
            (half_b.clone(), vec![]),
            (other_pair, vec![]),
            (zero.clone(), vec![]),
            (half_a.clone(), vec![]),
        ],
        Some(&pair),
        usize::MAX,
    )
    .unwrap();

    assert_eq!(ordered.into_iter().map(|entry| entry.0).collect::<Vec<_>>(), vec![zero, half_a.clone(), half_b.clone(), two]);
    assert_eq!(market_total_cmp(&half_a, &half_b), half_a.cmp(&half_b));
}

#[test]
fn overflow_path_and_malformed_keys_are_deterministic() {
    let maximum = i64::MAX as u64;
    let low = key(3, maximum - 1, maximum / 2, b"");
    let high = key(3, maximum / 2, maximum - 1, b"");
    assert_eq!(market_total_cmp(&low, &high), Ordering::Less);
    assert!(matches!(
        market_order(vec![(vec![0; 53], vec![])], None, 1),
        Err(StorageError::MarketKey { actual: 53 })
    ));
    assert!(market_order(vec![(vec![0; 53], vec![])], None, 0).unwrap().is_empty());
}
