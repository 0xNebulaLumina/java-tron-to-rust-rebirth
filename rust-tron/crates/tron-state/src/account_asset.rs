use core::fmt;
use std::collections::BTreeMap;

use prost::Message;
use tron_primitives::{FixedBytesError, TronAddress21};
use tron_protocol::protocol::Account;

use crate::keys::{ExternalAssetKeyError, external_asset_key};
use crate::{StateStore, StateWriteBatch, StoreKind, StoreName};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetWrite {
    pub key: Vec<u8>,
    pub value: Option<[u8; 8]>,
}

#[derive(Debug)]
pub enum AccountAssetError {
    Address(FixedBytesError),
    Key(ExternalAssetKeyError),
    MalformedRowKey(Vec<u8>),
    MalformedRowValue { key: Vec<u8>, length: usize },
    InvalidAssetUtf8 { key: Vec<u8> },
    Storage(tron_storage::StorageError),
}

impl fmt::Display for AccountAssetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(error) => write!(f, "invalid account address: {error}"),
            Self::Key(error) => error.fmt(f),
            Self::MalformedRowKey(key) => write!(f, "malformed external asset row key: {} bytes", key.len()),
            Self::MalformedRowValue { key, length } => write!(f, "malformed external asset value for {}-byte key: {length} bytes", key.len()),
            Self::InvalidAssetUtf8 { key } => write!(f, "external asset row has non-UTF-8 asset segment: {} bytes", key.len()),
            Self::Storage(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for AccountAssetError {}
impl From<FixedBytesError> for AccountAssetError { fn from(error: FixedBytesError) -> Self { Self::Address(error) } }
impl From<ExternalAssetKeyError> for AccountAssetError { fn from(error: ExternalAssetKeyError) -> Self { Self::Key(error) } }
impl From<tron_storage::StorageError> for AccountAssetError { fn from(error: tron_storage::StorageError) -> Self { Self::Storage(error) } }

fn account_address(account: &Account) -> Result<TronAddress21, AccountAssetError> {
    Ok(TronAddress21::validate_mainnet(&account.address)?)
}

pub fn external_asset_writes(account: &Account) -> Result<Vec<AssetWrite>, AccountAssetError> {
    let address = account_address(account)?;
    account.asset_v2.iter().map(|(asset, balance)| {
        Ok(AssetWrite {
            key: external_asset_key(&address, asset.as_bytes())?,
            value: (*balance != 0).then(|| balance.to_be_bytes()),
        })
    }).collect()
}

/// Lazy read: external values are loaded only for optimized accounts, then inline values win.
pub fn all_assets(
    account: &Account,
    mut external: impl FnMut(&[u8]) -> Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<BTreeMap<String, i64>, AccountAssetError> {
    let address = account_address(account)?;
    let mut result = BTreeMap::new();
    if account.asset_optimized {
        for (key, value) in external(address.as_bytes()) {
            let asset = key.strip_prefix(address.as_bytes())
                .filter(|asset| !asset.is_empty())
                .ok_or_else(|| AccountAssetError::MalformedRowKey(key.clone()))?;
            external_asset_key(&address, asset)?;
            let asset = core::str::from_utf8(asset)
                .map_err(|_| AccountAssetError::InvalidAssetUtf8 { key: key.clone() })?;
            let value = <[u8; 8]>::try_from(value.as_slice())
                .map_err(|_| AccountAssetError::MalformedRowValue { key: key.clone(), length: value.len() })?;
            result.insert(asset.to_owned(), i64::from_be_bytes(value));
        }
    }
    result.extend(account.asset_v2.iter().map(|(key, value)| (key.clone(), *value)));
    Ok(result)
}

pub fn balance(
    account: &Account,
    asset: &[u8],
    external: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
) -> Result<i64, AccountAssetError> {
    let address = account_address(account)?;
    let key = external_asset_key(&address, asset)?;
    if let Ok(name) = core::str::from_utf8(asset) {
        if let Some(value) = account.asset_v2.get(name) {
            return Ok(*value);
        }
    }
    if !account.asset_optimized {
        return Ok(0);
    }
    match external(&key) {
        None => Ok(0),
        Some(value) => {
            let length = value.len();
            let value = <[u8; 8]>::try_from(value.as_slice())
                .map_err(|_| AccountAssetError::MalformedRowValue { key, length })?;
            Ok(i64::from_be_bytes(value))
        }
    }
}

impl StateStore {
    /// Replaces an account's external assets atomically. Returned events describe the durable
    /// after-state writes and cannot mutate the committed batch.
    pub fn replace_account_assets(&self, account: &Account) -> Result<Vec<AssetWrite>, AccountAssetError> {
        let address = account_address(account)?;
        let account_store = StoreKind::Account.name();
        let asset_store = self.store(StoreKind::AccountAsset);
        let mut desired = external_asset_writes(account)?;
        desired.retain(|write| write.value.is_some());
        let existing = asset_store.prefix(address.as_bytes());
        let mut events = Vec::with_capacity(existing.len() + desired.len());
        let mut batch = self.batch();

        for (key, _) in existing {
            batch.delete(asset_store.name(), &key);
            events.push(AssetWrite { key, value: None });
        }
        for write in &desired {
            if let Some(value) = write.value {
                batch.put(asset_store.name(), &write.key, &value);
            }
        }
        events.append(&mut desired);

        let mut persisted = account.clone();
        persisted.asset_v2.clear();
        persisted.asset_optimized = true;
        batch.put(&account_store, address.as_bytes(), &persisted.encode_to_vec());
        batch.commit()?;
        Ok(events)
    }

    pub fn all_account_assets(&self, account: &Account) -> Result<BTreeMap<String, i64>, AccountAssetError> {
        let store = self.store(StoreKind::AccountAsset);
        all_assets(account, |prefix| store.prefix(prefix))
    }
}

pub fn apply_asset_writes(batch: &mut StateWriteBatch, store: &StoreName, writes: &[AssetWrite]) {
    for write in writes {
        match write.value {
            Some(value) => { batch.put(store, &write.key, &value); }
            None => { batch.delete(store, &write.key); }
        }
    }
}
