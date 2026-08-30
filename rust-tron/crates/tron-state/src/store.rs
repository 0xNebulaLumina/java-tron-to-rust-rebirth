use core::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use tron_storage::{RustLog, WriteBatch, WriteFaultInjector};

const NAMESPACE_VERSION: u8 = 1;
const INTERNAL_NAMESPACE_VERSION: u8 = 2;
const CHECKPOINT_INTERNAL_NAMESPACE: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StoreKind {
    Account, AccountIdIndex, AccountIndex, AccountAsset, AssetIssue, AssetIssueV2,
    Block, BlockIndex, Transaction, TransactionCache, TransactionRet, TransactionHistory,
    RecentBlock, RecentTransaction, Contract, Abi, Code, ContractState, StorageRow,
    Witness, WitnessSchedule, Votes, Proposal, Exchange, ExchangeV2, MarketAccount,
    MarketOrder, MarketPairToPrice, MarketPairPriceToOrder, DelegatedResource,
    DelegatedResourceAccountIndex, DynamicProperties, IncrementalMerkleTree, Nullifier,
    ZkProof, TreeBlockIndex, SectionBloom, AccountTrace, BalanceTrace, Delegation, Pbft,
    RewardVi, Common, Checkpoint, Temporary,
}
impl StoreKind {
    pub const ALL: [Self; 45] = [
        Self::Account, Self::AccountIdIndex, Self::AccountIndex, Self::AccountAsset,
        Self::AssetIssue, Self::AssetIssueV2, Self::Block, Self::BlockIndex, Self::Transaction,
        Self::TransactionCache, Self::TransactionRet, Self::TransactionHistory, Self::RecentBlock,
        Self::RecentTransaction, Self::Contract, Self::Abi, Self::Code, Self::ContractState,
        Self::StorageRow, Self::Witness, Self::WitnessSchedule, Self::Votes, Self::Proposal,
        Self::Exchange, Self::ExchangeV2, Self::MarketAccount, Self::MarketOrder,
        Self::MarketPairToPrice, Self::MarketPairPriceToOrder, Self::DelegatedResource,
        Self::DelegatedResourceAccountIndex, Self::DynamicProperties, Self::IncrementalMerkleTree,
        Self::Nullifier, Self::ZkProof, Self::TreeBlockIndex, Self::SectionBloom,
        Self::AccountTrace, Self::BalanceTrace, Self::Delegation, Self::Pbft, Self::RewardVi,
        Self::Common, Self::Checkpoint, Self::Temporary,
    ];

    #[must_use]
    pub const fn db_name(self) -> &'static str { match self {
        Self::Account => "account", Self::AccountIdIndex => "accountid-index",
        Self::AccountIndex => "account-index", Self::AccountAsset => "account-asset",
        Self::AssetIssue => "asset-issue", Self::AssetIssueV2 => "asset-issue-v2",
        Self::Block => "block", Self::BlockIndex => "block-index", Self::Transaction => "trans",
        Self::TransactionCache => "trans-cache", Self::TransactionRet => "transactionRetStore",
        Self::TransactionHistory => "transactionHistoryStore", Self::RecentBlock => "recent-block",
        Self::RecentTransaction => "recent-transaction", Self::Contract => "contract",
        Self::Abi => "abi", Self::Code => "code", Self::ContractState => "contract-state",
        Self::StorageRow => "storage-row", Self::Witness => "witness",
        Self::WitnessSchedule => "witness_schedule", Self::Votes => "votes",
        Self::Proposal => "proposal", Self::Exchange => "exchange", Self::ExchangeV2 => "exchange-v2",
        Self::MarketAccount => "market_account", Self::MarketOrder => "market_order",
        Self::MarketPairToPrice => "market_pair_to_price",
        Self::MarketPairPriceToOrder => "market_pair_price_to_order",
        Self::DelegatedResource => "DelegatedResource",
        Self::DelegatedResourceAccountIndex => "DelegatedResourceAccountIndex",
        Self::DynamicProperties => "properties", Self::IncrementalMerkleTree => "IncrementalMerkleTree",
        Self::Nullifier => "nullifier", Self::ZkProof => "zkProof", Self::TreeBlockIndex => "tree-block-index",
        Self::SectionBloom => "section-bloom", Self::AccountTrace => "account-trace",
        Self::BalanceTrace => "balance-trace", Self::Delegation => "delegation",
        Self::Pbft => "pbft-sign-data", Self::RewardVi => "reward-vi", Self::Common => "common",
        Self::Checkpoint => "checkpoint", Self::Temporary => "tmp",
    } }
    #[must_use] pub fn name(self) -> StoreName { StoreName(self.db_name().to_owned()) }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StoreName(String);
impl StoreName {
    pub fn new(name: impl Into<String>) -> Result<Self, StoreNameError> {
        let name = name.into();
        if name.is_empty() { return Err(StoreNameError::Empty); }
        if name.len() > u32::MAX as usize { return Err(StoreNameError::TooLong(name.len())); }
        Ok(Self(name))
    }
    #[must_use] pub fn as_str(&self) -> &str { &self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreNameError { Empty, TooLong(usize) }
impl fmt::Display for StoreNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { match self { Self::Empty => f.write_str("store name is empty"), Self::TooLong(n) => write!(f, "store name is too long: {n} bytes") } }
}
impl std::error::Error for StoreNameError {}

/// Collision-free physical encoding: version || u32(name length) || name || raw logical key.
#[must_use]
pub fn physical_key(store: &StoreName, logical_key: &[u8]) -> Vec<u8> {
    let name = store.as_str().as_bytes();
    let mut key = Vec::with_capacity(5 + name.len() + logical_key.len());
    key.push(NAMESPACE_VERSION);
    key.extend_from_slice(&(name.len() as u32).to_be_bytes());
    key.extend_from_slice(name);
    key.extend_from_slice(logical_key);
    key
}

#[derive(Clone)]
pub struct StateStore { log: Arc<Mutex<RustLog>> }
impl StateStore {
    #[must_use] pub fn new(log: RustLog) -> Self { Self { log: Arc::new(Mutex::new(log)) } }
    #[must_use] pub fn from_shared(log: Arc<Mutex<RustLog>>) -> Self { Self { log } }
    #[must_use] pub fn shared_log(&self) -> Arc<Mutex<RustLog>> { Arc::clone(&self.log) }
    pub fn namespace(&self, name: impl Into<String>) -> Result<TypedStore, StoreNameError> {
        Ok(TypedStore { state: self.clone(), name: StoreName::new(name)? })
    }
    #[must_use] pub fn store(&self, kind: StoreKind) -> TypedStore { TypedStore { state: self.clone(), name: kind.name() } }
    #[must_use] pub(crate) fn store_by_name(&self, name: StoreName) -> TypedStore { TypedStore { state: self.clone(), name } }
    #[must_use]
    pub(crate) fn checkpoint_metadata(&self) -> InternalStore {
        InternalStore { state: self.clone(), namespace: CHECKPOINT_INTERNAL_NAMESPACE }
    }
    pub fn flush(&self) -> tron_storage::Result<()> { self.lock().flush() }
    #[must_use] pub fn batch(&self) -> StateWriteBatch { StateWriteBatch { state: self.clone(), batch: WriteBatch::new() } }
    fn lock(&self) -> MutexGuard<'_, RustLog> { self.log.lock().unwrap_or_else(std::sync::PoisonError::into_inner) }
    pub(crate) fn snapshot_names(&self, names: &[StoreName]) -> std::collections::BTreeMap<StoreName, std::collections::BTreeMap<Vec<u8>, Vec<u8>>> {
        let log = self.lock();
        names.iter().cloned().map(|name| {
            let physical_prefix = physical_key(&name, &[]);
            let namespace_length = physical_prefix.len();
            let rows = log.prefix(&physical_prefix, usize::MAX).into_iter()
                .map(|(key, value)| (key[namespace_length..].to_vec(), value))
                .collect();
            (name, rows)
        }).collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreEntry { Absent, Present(Vec<u8>) }

#[derive(Clone)]
pub struct TypedStore { state: StateStore, name: StoreName }
impl TypedStore {
    #[must_use] pub fn name(&self) -> &StoreName { &self.name }
    #[must_use] pub fn batch(&self) -> StateWriteBatch { self.state.batch() }
    #[must_use] pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> { self.state.lock().get(&physical_key(&self.name, key)) }
    #[must_use] pub fn contains_key(&self, key: &[u8]) -> bool { self.state.lock().contains_key(&physical_key(&self.name, key)) }
    pub fn put(&self, key: &[u8], value: &[u8]) -> tron_storage::Result<()> { self.state.lock().put(physical_key(&self.name, key), value.to_vec()) }
    pub fn delete(&self, key: &[u8]) -> tron_storage::Result<()> { self.state.lock().delete(physical_key(&self.name, key)) }
    pub fn put_if_absent(&self, key: &[u8], value: &[u8]) -> tron_storage::Result<bool> {
        let physical = physical_key(&self.name, key);
        let mut log = self.state.lock();
        if log.contains_key(&physical) { return Ok(false); }
        log.put(physical, value.to_vec())?;
        Ok(true)
    }
    #[must_use] pub fn entry(&self, key: &[u8]) -> StoreEntry { self.get(key).map_or(StoreEntry::Absent, StoreEntry::Present) }
    #[must_use]
    pub fn prefix(&self, logical_prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let physical_prefix = physical_key(&self.name, logical_prefix);
        let namespace_length = physical_key(&self.name, &[]).len();
        self.state.lock().prefix(&physical_prefix, usize::MAX).into_iter()
            .map(|(key, value)| (key[namespace_length..].to_vec(), value))
            .collect()
    }
    pub fn delete_present(&self, key: &[u8]) -> tron_storage::Result<bool> {
        if !self.contains_key(key) { return Ok(false); }
        self.delete(key)?; Ok(true)
    }
}

fn internal_physical_key(namespace: u8, key: &[u8]) -> Vec<u8> {
    let mut physical = Vec::with_capacity(2 + key.len());
    physical.push(INTERNAL_NAMESPACE_VERSION);
    physical.push(namespace);
    physical.extend_from_slice(key);
    physical
}

#[derive(Clone)]
pub(crate) struct InternalStore { state: StateStore, namespace: u8 }
impl InternalStore {
    #[must_use]
    pub(crate) fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.state.lock().get(&internal_physical_key(self.namespace, key))
    }
    #[must_use]
    pub(crate) fn batch(&self) -> InternalWriteBatch {
        InternalWriteBatch { state: self.state.clone(), namespace: self.namespace, batch: WriteBatch::new() }
    }
}

pub(crate) struct InternalWriteBatch { state: StateStore, namespace: u8, batch: WriteBatch }
impl InternalWriteBatch {
    pub(crate) fn put(&mut self, key: &[u8], value: &[u8]) -> &mut Self {
        self.batch.put(internal_physical_key(self.namespace, key), value.to_vec());
        self
    }
    pub(crate) fn delete(&mut self, key: &[u8]) -> &mut Self {
        self.batch.delete(internal_physical_key(self.namespace, key));
        self
    }
    pub(crate) fn commit(self) -> tron_storage::Result<()> { self.state.lock().write(self.batch) }
}

/// C009 overlay handoff: collect operations from any logical store and commit them in one RustLog WAL frame.
pub struct StateWriteBatch { state: StateStore, batch: WriteBatch }
impl StateWriteBatch {
    pub fn put(&mut self, store: &StoreName, key: &[u8], value: &[u8]) -> &mut Self { self.batch.put(physical_key(store, key), value.to_vec()); self }
    pub fn delete(&mut self, store: &StoreName, key: &[u8]) -> &mut Self { self.batch.delete(physical_key(store, key)); self }
    #[must_use] pub fn is_empty(&self) -> bool { self.batch.is_empty() }
    pub fn commit(self) -> tron_storage::Result<()> { self.state.lock().write(self.batch) }
    pub fn commit_with_faults(self, faults: &dyn WriteFaultInjector) -> tron_storage::Result<()> { self.state.lock().write_with_faults(self.batch, faults) }
}
