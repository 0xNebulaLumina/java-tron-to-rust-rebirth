use core::fmt;
use std::collections::BTreeMap;

use prost::Message;
use tron_protocol::protocol::Account;

use crate::{StateStore, StoreKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssetGate { pub allow_same_token_name: bool, pub optimize_account_assets: bool }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetKeys { pub name: Vec<u8>, pub id: Vec<u8> }

#[derive(Debug)]
pub enum AssetMigrationError { MissingId, InvalidName, InvalidId, Decode(prost::DecodeError), Storage(tron_storage::StorageError) }
impl fmt::Display for AssetMigrationError { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{write!(f,"asset migration error: {self:?}")} }
impl std::error::Error for AssetMigrationError {}
impl From<prost::DecodeError> for AssetMigrationError { fn from(e:prost::DecodeError)->Self{Self::Decode(e)} }
impl From<tron_storage::StorageError> for AssetMigrationError { fn from(e:tron_storage::StorageError)->Self{Self::Storage(e)} }

impl AssetKeys {
    pub fn new(name:impl Into<Vec<u8>>,id:impl Into<Vec<u8>>)->Result<Self,AssetMigrationError>{
        let value=Self{name:name.into(),id:id.into()};
        if value.name.is_empty(){return Err(AssetMigrationError::InvalidName)}
        if value.id.is_empty(){return Err(AssetMigrationError::InvalidId)}
        Ok(value)
    }
}

impl StateStore {
    /// Java-compatible lookup gate: names address the legacy store before the proposal,
    /// numeric IDs address V2 afterwards. No fallback is permitted across the gate.
    pub fn asset_issue(&self,key:&[u8],gate:AssetGate)->Option<Vec<u8>>{
        self.store(if gate.allow_same_token_name { StoreKind::AssetIssueV2 } else { StoreKind::AssetIssue }).get(key)
    }

    /// Writes the canonical V2 row always and the name-keyed legacy row only while names remain unique.
    pub fn put_asset_issue(&self,keys:&AssetKeys,value:&[u8],gate:AssetGate)->Result<(),AssetMigrationError>{
        let mut batch=self.batch();
        batch.put(&StoreKind::AssetIssueV2.name(),&keys.id,value);
        if !gate.allow_same_token_name { batch.put(&StoreKind::AssetIssue.name(),&keys.name,value); }
        batch.commit()?; Ok(())
    }

    /// Applies the one-way name-to-ID account migration and optionally externalizes the V2 map.
    /// The caller supplies the unambiguous legacy-name to token-ID mapping from the issue stores.
    pub fn migrate_account_assets(&self,account:&Account,name_to_id:&BTreeMap<String,String>,gate:AssetGate)->Result<Account,AssetMigrationError>{
        let mut migrated=account.clone();
        if !gate.allow_same_token_name {
            for (name,balance) in &account.asset {
                let id=name_to_id.get(name).ok_or(AssetMigrationError::MissingId)?;
                migrated.asset_v2.insert(id.clone(),*balance);
            }
        }
        if gate.optimize_account_assets {
            self.replace_account_assets(&migrated).map_err(|error| match error { crate::account_asset::AccountAssetError::Storage(e)=>AssetMigrationError::Storage(e), _=>AssetMigrationError::InvalidId })?;
            migrated.asset_v2.clear(); migrated.asset_optimized=true;
        }
        Ok(migrated)
    }

    /// Atomically persists issue-name/ID markers and balances according to both migration gates.
    pub fn persist_asset_account(&self,account:&Account,keys:&AssetKeys,balance:i64,gate:AssetGate)->Result<Account,AssetMigrationError>{
        let name=core::str::from_utf8(&keys.name).map_err(|_|AssetMigrationError::InvalidName)?.to_owned();
        let id=core::str::from_utf8(&keys.id).map_err(|_|AssetMigrationError::InvalidId)?.to_owned();
        let mut next=account.clone();
        next.asset_issued_name=keys.name.clone(); next.asset_issued_id=keys.id.clone();
        if !gate.allow_same_token_name { next.asset.insert(name,balance); }
        next.asset_v2.insert(id,balance);
        if gate.optimize_account_assets {
            self.replace_account_assets(&next).map_err(|error| match error { crate::account_asset::AccountAssetError::Storage(e)=>AssetMigrationError::Storage(e), _=>AssetMigrationError::InvalidId })?;
            next.asset_v2.clear(); next.asset_optimized=true;
        } else { self.store(StoreKind::Account).put(&next.address,&next.encode_to_vec())?; }
        Ok(next)
    }
}
