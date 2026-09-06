use prost::Message;
use serde_json::Value;
use tron_crypto::{selected_digest, CryptoEngine};
use tron_execution::{BlockApplyError, BlockLimits, RawBlock, JAVA_TRON_C019_REVISION};
use tron_primitives::{BlockId, Hash32};
use tron_protocol::protocol::{block_header, Block, BlockHeader, Transaction, transaction};

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }

fn push_varint(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        output.push(if value == 0 { byte } else { byte | 0x80 });
        if value == 0 { break; }
    }
}

#[test]
fn pinned_java_full_wire_merkle_vectors() {
    let oracle: Value = serde_json::from_str(include_str!("../../../../docs/oracles/c019-block-apply.v1.json")).unwrap();
    assert_eq!(oracle["java_revision"], JAVA_TRON_C019_REVISION);
    for vector in oracle["vectors"].as_array().unwrap() {
        let transactions = vector["transaction_full_bytes_hex"].as_array().unwrap().iter().map(|value| {
            let encoded = value.as_str().unwrap();
            (0..encoded.len()).step_by(2).map(|index| u8::from_str_radix(&encoded[index..index + 2], 16).unwrap()).collect::<Vec<_>>()
        }).collect::<Vec<_>>();
        let raw = block_header::Raw { number: 7, tx_trie_root: Vec::new(), ..Default::default() };
        let block = Block { transactions: transactions.iter().map(|bytes| Transaction::decode(bytes.as_slice()).unwrap()).collect(), block_header: Some(BlockHeader { raw_data: Some(raw), witness_signature: vec![1] }) };
        let decoded = RawBlock::decode(block.encode_to_vec(), BlockLimits::default()).unwrap();
        assert_eq!(hex(&decoded.transaction_merkle_root(CryptoEngine::Secp256k1)), vector["root_hex"].as_str().unwrap());
    }
}

#[test]
fn exact_raw_header_bytes_define_block_id() {
    let raw = block_header::Raw { timestamp: 3_000, parent_hash: vec![9; 32], number: 42, witness_address: vec![0x41; 21], version: 7, ..Default::default() };
    let raw_bytes = raw.encode_to_vec();
    let block = Block { transactions: Vec::new(), block_header: Some(BlockHeader { raw_data: Some(raw), witness_signature: vec![7; 65] }) };
    let decoded = RawBlock::decode(block.encode_to_vec(), BlockLimits::default()).unwrap();
    assert_eq!(decoded.raw_header_bytes(), raw_bytes);
    let expected = BlockId::new(42, Hash32::from_array(selected_digest(CryptoEngine::Secp256k1, &raw_bytes)));
    assert_eq!(decoded.block_id(CryptoEngine::Secp256k1).unwrap(), expected);
}

#[test]
fn malformed_or_ambiguous_wire_is_rejected_before_state() {
    assert_eq!(RawBlock::decode(vec![0xff], BlockLimits::default()).unwrap_err(), BlockApplyError::MalformedWire);
    let missing = Block { transactions: vec![Transaction { raw_data: Some(transaction::Raw::default()), ..Default::default() }], block_header: None };
    assert_eq!(RawBlock::decode(missing.encode_to_vec(), BlockLimits::default()).unwrap_err(), BlockApplyError::MissingRawHeader);
    let limits = BlockLimits::default();
    assert_eq!(limits.max_shielded_transactions, 1);
    assert!(limits.max_block_bytes >= 2_000_000);
    let graph = limits.khaos_limits(64, 2);
    assert!(graph.max_total_bytes >= limits.max_block_bytes * 64 * 2);
}

#[test]
fn bounded_ingress_rejects_before_decode_or_full_clone() {
    let limits = BlockLimits { max_block_bytes: 32, ..BlockLimits::default() };
    let oversized = vec![0xff; 33];
    assert_eq!(RawBlock::decode(&oversized, limits).unwrap_err(), BlockApplyError::TooLarge(33));
    assert_eq!(RawBlock::decode_reader(oversized.as_slice(), limits).unwrap_err(), BlockApplyError::TooLarge(33));
    for _ in 0..64 {
        assert_eq!(RawBlock::decode(&oversized, limits).unwrap_err(), BlockApplyError::TooLarge(33));
    }
}

#[test]
fn transaction_count_is_rejected_during_wire_scan() {
    let transaction = Transaction { raw_data: Some(transaction::Raw::default()), ..Default::default() };
    let block = Block {
        transactions: vec![transaction; 3],
        block_header: Some(BlockHeader { raw_data: Some(block_header::Raw::default()), witness_signature: Vec::new() }),
    };
    let limits = BlockLimits { max_transactions: 2, ..BlockLimits::default() };
    assert_eq!(RawBlock::decode(block.encode_to_vec(), limits).unwrap_err(), BlockApplyError::TooManyTransactions(3));
}

#[test]
fn maximum_valid_sized_block_is_accepted_without_transaction_copies() {
    let template = Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader { raw_data: Some(block_header::Raw::default()), witness_signature: Vec::new() }),
    }.encode_to_vec();
    let mut bytes = template;
    let padding = 4096usize.saturating_sub(bytes.len() + 4);
    bytes.push(0x1a);
    push_varint(padding, &mut bytes);
    bytes.extend(std::iter::repeat_n(0u8, padding));
    let limits = BlockLimits { max_block_bytes: bytes.len(), ..BlockLimits::default() };
    let decoded = RawBlock::decode(&bytes, limits).unwrap();
    assert_eq!(decoded.full_bytes, bytes);
    assert_eq!(decoded.transaction_bytes().len(), 0);
}
