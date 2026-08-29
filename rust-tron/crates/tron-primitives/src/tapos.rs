use crate::types::{BlockId, Hash32};

pub const TAPOS_REF_BLOCK_BYTES_LENGTH: usize = 2;
pub const TAPOS_REF_BLOCK_HASH_LENGTH: usize = 8;

/// Java `ref_block_bytes`: the low two bytes of the block number's big-endian form.
pub fn ref_block_bytes(height: i64) -> [u8; TAPOS_REF_BLOCK_BYTES_LENGTH] {
    height.to_be_bytes()[6..8].try_into().expect("fixed slice")
}

/// Java `ref_block_hash`: bytes 8 through 15 of the overlaid block ID/hash.
pub fn ref_block_hash(hash: &Hash32) -> [u8; TAPOS_REF_BLOCK_HASH_LENGTH] {
    hash.as_bytes()[8..16].try_into().expect("fixed slice")
}

pub fn ref_block_hash_from_id(block_id: &BlockId) -> [u8; TAPOS_REF_BLOCK_HASH_LENGTH] {
    ref_block_hash(&block_id.hash())
}
