use core::fmt;

use tron_primitives::{BlockId, Hash32, TransactionId, TronAddress21, ref_block_bytes};

#[must_use] pub const fn i64_key(value: i64) -> [u8; 8] { value.to_be_bytes() }
#[must_use] pub const fn i32_key(value: i32) -> [u8; 4] { value.to_be_bytes() }

#[must_use]
pub fn account_key(address: &[u8]) -> Vec<u8> { address.to_vec() }
#[must_use]
pub fn account_name_key(name: &[u8]) -> Vec<u8> { name.to_vec() }

/// Java `String.toLowerCase(Locale.ROOT)` equivalent for valid UTF-8 account IDs.
pub fn account_id_key(id: &[u8]) -> Result<Vec<u8>, core::str::Utf8Error> {
    Ok(core::str::from_utf8(id)?.to_lowercase().into_bytes())
}

#[must_use]
pub fn asset_name_key(name: &[u8]) -> Vec<u8> { name.to_vec() }
#[must_use]
pub fn asset_id_key(id: &str) -> Vec<u8> { id.as_bytes().to_vec() }
pub const MAX_EXTERNAL_ASSET_KEY_LENGTH: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExternalAssetKeyError {
    EmptyAsset,
    AssetTooLong(usize),
}

impl fmt::Display for ExternalAssetKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAsset => f.write_str("external asset key is empty"),
            Self::AssetTooLong(length) => write!(f, "external asset key is too long: {length} bytes"),
        }
    }
}

impl std::error::Error for ExternalAssetKeyError {}

pub fn external_asset_key(
    address: &TronAddress21,
    asset: &[u8],
) -> Result<Vec<u8>, ExternalAssetKeyError> {
    if asset.is_empty() {
        return Err(ExternalAssetKeyError::EmptyAsset);
    }
    if asset.len() > MAX_EXTERNAL_ASSET_KEY_LENGTH {
        return Err(ExternalAssetKeyError::AssetTooLong(asset.len()));
    }
    let mut key = Vec::with_capacity(TronAddress21::LENGTH + asset.len());
    key.extend_from_slice(address.as_bytes());
    key.extend_from_slice(asset);
    Ok(key)
}

#[must_use] pub const fn external_asset_value(balance: i64) -> [u8; 8] { balance.to_be_bytes() }

#[must_use] pub fn block_key(id: &BlockId) -> Vec<u8> { id.as_bytes().to_vec() }
#[must_use] pub const fn block_index_key(number: i64) -> [u8; 8] { number.to_be_bytes() }
#[must_use] pub fn transaction_key(id: &TransactionId) -> Vec<u8> { id.as_bytes().to_vec() }
#[must_use] pub const fn transaction_result_key(number: i64) -> [u8; 8] { number.to_be_bytes() }
#[must_use] pub fn recent_block_key(number: i64) -> [u8; 2] { ref_block_bytes(number) }
#[must_use] pub fn recent_transaction_key(id: &TransactionId) -> Vec<u8> { id.as_bytes().to_vec() }
#[must_use] pub const fn account_history_key(timestamp: i64) -> [u8; 8] { timestamp.to_be_bytes() }

#[must_use]
pub fn hash_key(hash: &Hash32) -> Vec<u8> { hash.as_bytes().to_vec() }

fn hex_lower(bytes: &[u8]) -> String { const H: &[u8;16]=b"0123456789abcdef"; let mut s=String::with_capacity(bytes.len()*2); for &b in bytes { s.push(H[(b>>4) as usize] as char); s.push(H[(b&15) as usize] as char); } s }
#[must_use] pub fn delegation_vote_key(cycle: i64, address: &[u8]) -> Vec<u8> { format!("{cycle}-{}-vote", hex_lower(address)).into_bytes() }
#[must_use] pub fn delegation_reward_key(cycle: i64, address: &[u8]) -> Vec<u8> { format!("{cycle}-{}-reward", hex_lower(address)).into_bytes() }
#[must_use] pub fn delegation_account_vote_key(cycle: i64, address: &[u8]) -> Vec<u8> { format!("{cycle}-{}-account-vote", hex_lower(address)).into_bytes() }
#[must_use] pub fn delegation_end_cycle_key(address: &[u8]) -> Vec<u8> { format!("end-{}", hex_lower(address)).into_bytes() }
#[must_use] pub fn delegation_brokerage_key(cycle: i64, address: &[u8]) -> Vec<u8> { format!("{cycle}-{}-brokerage", hex_lower(address)).into_bytes() }
#[must_use] pub fn delegation_vi_key(cycle: i64, address: &[u8]) -> Vec<u8> { format!("{cycle}-{}-vi", hex_lower(address)).into_bytes() }
#[must_use] pub fn pbft_srl_key(epoch: i64) -> Vec<u8> { format!("SRL{epoch}").into_bytes() }
#[must_use] pub fn pbft_block_key(number: i64) -> Vec<u8> { format!("BLOCK{number}").into_bytes() }
