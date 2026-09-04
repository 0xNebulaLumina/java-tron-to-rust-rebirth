use core::fmt;

use prost::Message;
use tron_crypto::{decode_address_base58check, CryptoEngine, Sha256Provider};
use tron_primitives::{merkle_root, BlockId, DigestProvider, Hash32};
use tron_protocol::{google::protobuf::Any, protocol::{block_header, transaction, Account, AccountTrace, AccountType, Block, BlockHeader, Transaction, TransferContract, Witness}};

use crate::{dynamic, keys, value, StateStore, StoreKind};

pub const GENESIS_OWNER_ADDRESS: &[u8] = b"0x000000000000000000000";
pub const GENESIS_WITNESS: &[u8] = b"A new system must allow existing systems to be linked together without requiring any central control or coordination";
pub const TRANSFER_CONTRACT_TYPE_URL: &str = "type.googleapis.com/protocol.TransferContract";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisAssetConfig {
    pub account_name: Vec<u8>,
    pub account_type: AccountType,
    pub address: Vec<u8>,
    pub balance: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisWitnessConfig {
    pub address: Vec<u8>,
    pub url: String,
    pub vote_count: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisConfig {
    pub timestamp_raw: String,
    pub parent_hash_raw: String,
    pub assets: Vec<GenesisAssetConfig>,
    pub witnesses: Vec<GenesisWitnessConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenesisConfigError {
    InvalidTimestamp,
    NegativeTimestamp,
    InvalidParentHash,
    BlankAccountName,
    InvalidAccountType(String),
    InvalidAddress,
    InvalidBalance,
    InvalidWitnessVoteCount,
    DuplicateAddress,
    DuplicateAccountName,
    DuplicateWitness,
    InvalidSupply,
    BlankWitnessUrl,
    MissingBlackhole,
}

impl fmt::Display for GenesisConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "invalid genesis configuration: {self:?}") }
}
impl std::error::Error for GenesisConfigError {}

impl GenesisConfig {
    pub fn from_java_config(config: &tron_config::GenesisConfig, engine: CryptoEngine) -> Result<Self, GenesisConfigError> {
        // Args.applyGenesisConfig discards witness-only overlays.
        if config.timestamp.is_empty() && config.assets.is_empty() {
            return Ok(Self { timestamp_raw: "0".into(), parent_hash_raw: "0".into(), assets: Vec::new(), witnesses: Vec::new() });
        }
        let timestamp = config.timestamp.parse::<i64>().map_err(|_| GenesisConfigError::InvalidTimestamp)?;
        if timestamp < 0 { return Err(GenesisConfigError::NegativeTimestamp); }
        let mut assets = Vec::with_capacity(config.assets.len());
        for source in &config.assets {
            if source.account_name.trim().is_empty() { return Err(GenesisConfigError::BlankAccountName); }
            let account_type = match source.account_type.to_ascii_lowercase().as_str() {
                "normal" => AccountType::Normal,
                "assetissue" => AccountType::AssetIssue,
                "contract" => AccountType::Contract,
                other => return Err(GenesisConfigError::InvalidAccountType(other.into())),
            };
            let address = decode_address_base58check(engine, &source.address).map_err(|_| GenesisConfigError::InvalidAddress)?.as_bytes().to_vec();
            let balance = source.balance.parse::<i64>().map_err(|_| GenesisConfigError::InvalidBalance)?;
            assets.push(GenesisAssetConfig { account_name: source.account_name.as_bytes().to_vec(), account_type, address, balance });
        }
        if !assets.iter().any(|asset| asset.account_name == b"Blackhole") { return Err(GenesisConfigError::MissingBlackhole); }
        let mut witnesses = Vec::with_capacity(config.witnesses.len());
        for source in &config.witnesses {
            if source.url.trim().is_empty() { return Err(GenesisConfigError::BlankWitnessUrl); }
            let address = decode_address_base58check(engine, &source.address).map_err(|_| GenesisConfigError::InvalidAddress)?.as_bytes().to_vec();
            witnesses.push(GenesisWitnessConfig { address, url: source.url.clone(), vote_count: source.vote_count });
        }
        let parsed = Self { timestamp_raw: config.timestamp.clone(), parent_hash_raw: config.parent_hash.clone(), assets, witnesses };
        validate_config(&parsed)?;
        Ok(parsed)
    }

    pub fn timestamp(&self) -> Result<i64, GenesisConfigError> {
        let value = self.timestamp_raw.parse().map_err(|_| GenesisConfigError::InvalidTimestamp)?;
        if value < 0 { Err(GenesisConfigError::NegativeTimestamp) } else { Ok(value) }
    }

    pub fn parent_hash(&self) -> Result<Vec<u8>, GenesisConfigError> {
        let text = self.parent_hash_raw.strip_prefix("0x").unwrap_or(&self.parent_hash_raw);
        let padded = if text.len() % 2 == 0 { text.to_owned() } else { format!("0{text}") };
        (0..padded.len()).step_by(2).map(|i| u8::from_str_radix(&padded[i..i + 2], 16).map_err(|_| GenesisConfigError::InvalidParentHash)).collect()
    }
}

#[derive(Clone, Debug)]
pub struct GenesisBlock {
    pub block: Block,
    pub bytes: Vec<u8>,
    pub id: BlockId,
    pub transaction_ids: Vec<Hash32>,
}

pub fn build_genesis<D>(config: &GenesisConfig, digest: &D) -> Result<GenesisBlock, GenesisError>
where D: DigestProvider, D::Error: fmt::Display {
    validate_config(config)?;
    let mut transactions = Vec::with_capacity(config.assets.len());
    let mut transaction_ids = Vec::with_capacity(config.assets.len());
    let mut merkle_leaves = Vec::with_capacity(config.assets.len());
    for asset in &config.assets {
        let transfer = TransferContract { owner_address: GENESIS_OWNER_ADDRESS.to_vec(), to_address: asset.address.clone(), amount: asset.balance };
        let contract = transaction::Contract { r#type: transaction::contract::ContractType::TransferContract as i32, parameter: Some(Any { type_url: TRANSFER_CONTRACT_TYPE_URL.into(), value: transfer.encode_to_vec() }), provider: Vec::new(), contract_name: Vec::new(), permission_id: 0 };
        let raw = transaction::Raw { contract: vec![contract], ..Default::default() };
        let raw_bytes = raw.encode_to_vec();
        let transaction = Transaction { raw_data: Some(raw), ..Default::default() };
        transaction_ids.push(digest.digest(&raw_bytes).map_err(|e| GenesisError::Digest(e.to_string()))?);
        merkle_leaves.push(digest.digest(&transaction.encode_to_vec()).map_err(|e| GenesisError::Digest(e.to_string()))?);
        transactions.push(transaction);
    }
    let root = merkle_root(digest, &merkle_leaves).map_err(|e| GenesisError::Digest(e.to_string()))?;
    let raw = block_header::Raw { timestamp: config.timestamp()?, tx_trie_root: root.as_bytes().to_vec(), parent_hash: config.parent_hash()?, number: 0, witness_address: GENESIS_WITNESS.to_vec(), ..Default::default() };
    let raw_bytes = raw.encode_to_vec();
    let hash = digest.digest(&raw_bytes).map_err(|e| GenesisError::Digest(e.to_string()))?;
    let id = BlockId::new(0, hash);
    let block = Block { transactions, block_header: Some(BlockHeader { raw_data: Some(raw), witness_signature: Vec::new() }) };
    let bytes = block.encode_to_vec();
    Ok(GenesisBlock { block, bytes, id, transaction_ids })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenesisError {
    Config(GenesisConfigError),
    Digest(String),
    IncompatibleChain,
    NonEmptyState,
    CorruptState(&'static str),
    Storage(String),
}
impl From<GenesisConfigError> for GenesisError { fn from(value: GenesisConfigError) -> Self { Self::Config(value) } }
impl fmt::Display for GenesisError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "genesis initialization failed: {self:?}") } }
impl std::error::Error for GenesisError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenesisInit { Created(BlockId), Existing(BlockId) }

pub fn initialize_genesis(root: &StateStore, genesis: &GenesisBlock) -> Result<GenesisInit, GenesisError> {
    initialize_genesis_config(root, &GenesisConfig { timestamp_raw: "0".into(), parent_hash_raw: "0".into(), assets: Vec::new(), witnesses: Vec::new() }, genesis)
}

const GENESIS_MARKER_KEY: &[u8] = b"genesis-state-v1";

fn validate_config(config: &GenesisConfig) -> Result<(), GenesisConfigError> {
    config.timestamp()?;
    config.parent_hash()?;
    let mut addresses = std::collections::BTreeSet::new();
    let mut names = std::collections::BTreeSet::new();
    let mut supply = 0_i64;
    for asset in &config.assets {
        if asset.account_name.iter().all(u8::is_ascii_whitespace) { return Err(GenesisConfigError::BlankAccountName); }
        if asset.address.is_empty() { return Err(GenesisConfigError::InvalidAddress); }
        if asset.balance < 0 { return Err(GenesisConfigError::InvalidBalance); }
        if !addresses.insert(asset.address.as_slice()) { return Err(GenesisConfigError::DuplicateAddress); }
        if !names.insert(asset.account_name.as_slice()) { return Err(GenesisConfigError::DuplicateAccountName); }
        supply = supply.checked_add(asset.balance).ok_or(GenesisConfigError::InvalidSupply)?;
    }
    let mut witness_addresses = std::collections::BTreeSet::new();
    for witness in &config.witnesses {
        if witness.address.is_empty() { return Err(GenesisConfigError::InvalidAddress); }
        if witness.url.trim().is_empty() { return Err(GenesisConfigError::BlankWitnessUrl); }
        if witness.vote_count < 0 { return Err(GenesisConfigError::InvalidWitnessVoteCount); }
        if !witness_addresses.insert(witness.address.as_slice()) { return Err(GenesisConfigError::DuplicateWitness); }
    }
    let _ = supply;
    Ok(())
}

type GenesisRows = std::collections::BTreeMap<StoreKind, std::collections::BTreeMap<Vec<u8>, Vec<u8>>>;

fn expected_rows(config: &GenesisConfig, genesis: &GenesisBlock) -> Result<GenesisRows, GenesisError> {
    validate_config(config)?;
    let timestamp = genesis.block.block_header.as_ref().and_then(|header| header.raw_data.as_ref()).map_or(0, |header| header.timestamp);
    let mut rows: GenesisRows = [StoreKind::Block, StoreKind::BlockIndex, StoreKind::RecentBlock, StoreKind::Account, StoreKind::AccountIndex, StoreKind::AccountIdIndex, StoreKind::Witness, StoreKind::WitnessSchedule, StoreKind::DynamicProperties, StoreKind::AccountTrace, StoreKind::BalanceTrace]
        .into_iter().map(|kind| (kind, std::collections::BTreeMap::new())).collect();
    let mut put = |store: StoreKind, key: Vec<u8>, value: Vec<u8>| -> Result<(), GenesisError> {
        if rows.entry(store).or_default().insert(key, value).is_some() { return Err(GenesisError::Config(GenesisConfigError::DuplicateAddress)); }
        Ok(())
    };
    put(StoreKind::Block, genesis.id.as_bytes().to_vec(), genesis.bytes.clone())?;
    put(StoreKind::BlockIndex, 0_i64.to_be_bytes().to_vec(), genesis.id.as_bytes().to_vec())?;
    put(StoreKind::RecentBlock, keys::recent_block_key(0).to_vec(), genesis.id.as_bytes()[8..16].to_vec())?;
    let mut accounts = std::collections::BTreeMap::<Vec<u8>, Account>::new();
    for asset in &config.assets {
        accounts.insert(asset.address.clone(), Account { account_name: asset.account_name.clone(), r#type: asset.account_type as i32, address: asset.address.clone(), balance: asset.balance, create_time: timestamp, ..Default::default() });
    }
    for witness in &config.witnesses {
        accounts.entry(witness.address.clone()).or_insert_with(|| Account { address: witness.address.clone(), create_time: timestamp, ..Default::default() }).is_witness = true;
    }
    for (address, account) in &accounts { put(StoreKind::Account, address.clone(), account.encode_to_vec())?; }
    for (position, asset) in config.assets.iter().enumerate() {
        put(StoreKind::AccountIndex, asset.account_name.clone(), asset.address.clone())?;
        let account = &accounts[&asset.address];
        if !account.account_id.is_empty() { put(StoreKind::AccountIdIndex, account.account_id.clone(), asset.address.clone())?; }
        put(StoreKind::AccountTrace, asset.address.clone(), AccountTrace { balance: asset.balance, placeholder: 0 }.encode_to_vec())?;
        let mut key = 0_i64.to_be_bytes().to_vec(); key.extend_from_slice(&asset.address);
        put(StoreKind::BalanceTrace, key, AccountTrace { balance: asset.balance, placeholder: position as i64 }.encode_to_vec())?;
    }
    for witness in &config.witnesses {
        put(StoreKind::Witness, witness.address.clone(), Witness { address: witness.address.clone(), vote_count: witness.vote_count, url: witness.url.clone(), is_jobs: true, ..Default::default() }.encode_to_vec())?;
    }
    let active_witnesses = config.witnesses.iter().flat_map(|witness| witness.address.iter().copied()).collect();
    put(StoreKind::WitnessSchedule, value::ACTIVE_WITNESSES_KEY.to_vec(), active_witnesses)?;
    for (name, value) in [
        ("LATEST_BLOCK_HEADER_NUMBER", 0_i64.to_be_bytes().to_vec()),
        ("LATEST_BLOCK_HEADER_HASH", genesis.id.as_bytes().to_vec()),
        ("LATEST_BLOCK_HEADER_TIMESTAMP", timestamp.to_be_bytes().to_vec()),
        ("LATEST_SOLIDIFIED_BLOCK_NUM", 0_i64.to_be_bytes().to_vec()),
    ] { put(StoreKind::DynamicProperties, dynamic::key(name).expect("known dynamic key").to_vec(), value)?; }
    Ok(rows)
}

fn state_root(rows: &GenesisRows) -> Hash32 {
    let mut bytes = Vec::new();
    for (store, entries) in rows {
        let name = store.db_name().as_bytes();
        bytes.extend_from_slice(&(name.len() as u32).to_be_bytes()); bytes.extend_from_slice(name);
        bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
        for (key, value) in entries {
            bytes.extend_from_slice(&(key.len() as u32).to_be_bytes()); bytes.extend_from_slice(key);
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes()); bytes.extend_from_slice(value);
        }
    }
    Sha256Provider.digest(&bytes).expect("infallible SHA-256")
}

fn marker(genesis: &GenesisBlock, root: Hash32) -> Vec<u8> {
    let mut value = Vec::with_capacity(64);
    value.extend_from_slice(genesis.id.as_bytes()); value.extend_from_slice(root.as_bytes()); value
}

pub fn initialize_genesis_config(root: &StateStore, config: &GenesisConfig, genesis: &GenesisBlock) -> Result<GenesisInit, GenesisError> {
    let rows = expected_rows(config, genesis)?;
    let root_hash = state_root(&rows);
    let expected_marker = marker(genesis, root_hash);
    let common = root.store(StoreKind::Common);
    let current_marker = common.get(GENESIS_MARKER_KEY);
    let occupied = StoreKind::ALL.into_iter().filter(|kind| *kind != StoreKind::Common).any(|kind| !root.store(kind).prefix(&[]).is_empty());
    if current_marker.is_some() || occupied {
        if current_marker.as_deref() != Some(expected_marker.as_slice()) { return Err(GenesisError::IncompatibleChain); }
        let block = root.store(StoreKind::Block);
        if block.get(genesis.id.as_bytes()).as_deref() != Some(genesis.bytes.as_slice()) {
            return Err(GenesisError::CorruptState("genesis block"));
        }
        let block_index = root.store(StoreKind::BlockIndex);
        if block_index.get(&0_i64.to_be_bytes()).as_deref() != Some(genesis.id.as_bytes()) {
            return Err(GenesisError::CorruptState("genesis chain id"));
        }
        return Ok(GenesisInit::Existing(genesis.id));
    }
    if !common.prefix(&[]).is_empty() { return Err(GenesisError::NonEmptyState); }
    let mut batch = root.batch();
    for (kind, entries) in &rows { let store = root.store(*kind); for (key, value) in entries { batch.put(store.name(), key, value); } }
    batch.put(common.name(), GENESIS_MARKER_KEY, &expected_marker);
    batch.commit().map_err(|error| GenesisError::Storage(error.to_string()))?;
    Ok(GenesisInit::Created(genesis.id))
}
