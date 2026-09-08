//! Streaming rustlog-v1 lite dataset transformations.
//! All validation happens in the `rewrite_store` build closure before its first sink write.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use crate::cli::LiteArgs;
use crate::db::DbServices;
use crate::error::{CommandOutput, ToolkitError};
use crate::io::CommandContext;

pub fn execute(
    args: &LiteArgs,
    _context: &mut CommandContext<'_>,
    services: &mut dyn DbServices,
) -> Result<CommandOutput, ToolkitError> {
    services.lite(args)
}


use tron_crypto::CryptoEngine;
use tron_execution::{BlockLimits, RawBlock, RawWireTransaction};
use sha2::{Digest, Sha256};
use tron_state::{physical_key, StoreKind};
use tron_storage::toolkit::{NoTransactionFaults, RewriteMode, RewriteOutcome, RewritePolicy, RewriteSink};
use tron_storage::{RustLog, StorageError, StorageManager};

pub const DESCRIPTOR_VERSION: u32 = 1;
pub const DESCRIPTOR_KEY: &[u8] = b"\0tron-toolkit/lite-descriptor-v1";
pub const HISTORY_BALANCE_DISABLED_KEY: &[u8] = b"\0tron-toolkit/history-balance-disabled-v1";
pub const ARCHIVE_STORES: [StoreKind; 5] = [StoreKind::Block, StoreKind::BlockIndex, StoreKind::Transaction, StoreKind::TransactionRet, StoreKind::TransactionHistory];
pub const TRANSIENT_STORES: [StoreKind; 3] = [StoreKind::TransactionCache, StoreKind::Checkpoint, StoreKind::Temporary];
pub const TRACE_STORES: [StoreKind; 2] = [StoreKind::BalanceTrace, StoreKind::AccountTrace];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiteKind { Snapshot, History }
impl LiteKind {
    fn text(self) -> &'static str { match self { Self::Snapshot => "snapshot", Self::History => "history" } }
    fn parse(value: &str) -> Result<Self, LiteError> { match value { "snapshot" => Ok(Self::Snapshot), "history" => Ok(Self::History), _ => Err(LiteError::InvalidDescriptor("unknown kind")) } }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteDescriptor {
    pub descriptor_version: u32,
    pub kind: LiteKind,
    pub network: String,
    pub genesis: String,
    pub schema_version: u32,
    pub backend_format: String,
    pub source_state_sha256: String,
    pub genesis_block_id: [u8; 32],
    pub min_block: i64,
    pub max_block: i64,
    pub recent_blocks: u64,
    pub excluded_stores: Vec<String>,
    pub history_balance_compatible: bool,
}
impl LiteDescriptor {
    pub fn encode(&self) -> Result<Vec<u8>, LiteError> {
        self.validate()?;
        let body = format!("descriptor_version={}\nkind={}\nnetwork={}\ngenesis={}\nschema_version={}\nbackend_format={}\nsource_state_sha256={}\ngenesis_block_id={}\nmin_block={}\nmax_block={}\nrecent_blocks={}\nexcluded_stores={}\nhistory_balance_compatible={}\n", self.descriptor_version, self.kind.text(), self.network, self.genesis, self.schema_version, self.backend_format, self.source_state_sha256, hex(&self.genesis_block_id), self.min_block, self.max_block, self.recent_blocks, self.excluded_stores.join(","), self.history_balance_compatible);
        let mut out = body.as_bytes().to_vec();
        out.extend_from_slice(format!("crc32={:08x}\n", crc32(body.as_bytes())).as_bytes());
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LiteError> {
        if bytes.len() > 16 * 1024 { return Err(LiteError::InvalidDescriptor("descriptor exceeds 16384 bytes")); }
        let text = std::str::from_utf8(bytes).map_err(|_| LiteError::InvalidDescriptor("descriptor is not UTF-8"))?;
        let (body, crc) = text.rsplit_once("crc32=").ok_or(LiteError::InvalidDescriptor("missing CRC32"))?;
        if !crc.ends_with('\n') || crc[..crc.len() - 1].contains('\n') { return Err(LiteError::InvalidDescriptor("CRC32 must be the final line")); }
        let claimed = u32::from_str_radix(&crc[..crc.len() - 1], 16).map_err(|_| LiteError::InvalidDescriptor("invalid CRC32"))?;
        if crc32(body.as_bytes()) != claimed { return Err(LiteError::InvalidDescriptor("CRC32 mismatch")); }
        let mut fields = BTreeMap::new();
        for line in body.lines() { let (key, value) = line.split_once('=').ok_or(LiteError::InvalidDescriptor("malformed field"))?; if fields.insert(key, value).is_some() { return Err(LiteError::InvalidDescriptor("duplicate field")); } }
        const KEYS: [&str; 13] = ["descriptor_version", "kind", "network", "genesis", "schema_version", "backend_format", "source_state_sha256", "genesis_block_id", "min_block", "max_block", "recent_blocks", "excluded_stores", "history_balance_compatible"];
        if fields.len() != KEYS.len() || KEYS.iter().any(|key| !fields.contains_key(key)) { return Err(LiteError::InvalidDescriptor("field set mismatch")); }
        let mut excluded_stores = if fields["excluded_stores"].is_empty() { Vec::new() } else { fields["excluded_stores"].split(',').map(str::to_owned).collect() };
        excluded_stores.sort();
        let descriptor = Self { descriptor_version: parse(&fields, "descriptor_version")?, kind: LiteKind::parse(fields["kind"] )?, network: fields["network"].to_owned(), genesis: fields["genesis"].to_owned(), schema_version: parse(&fields, "schema_version")?, backend_format: fields["backend_format"].to_owned(), source_state_sha256: fields["source_state_sha256"].to_owned(), genesis_block_id: decode_32(fields["genesis_block_id"] )?, min_block: parse(&fields, "min_block")?, max_block: parse(&fields, "max_block")?, recent_blocks: parse(&fields, "recent_blocks")?, excluded_stores, history_balance_compatible: parse(&fields, "history_balance_compatible")? };
        descriptor.validate()?;
        if descriptor.encode()?.as_slice() != bytes { return Err(LiteError::InvalidDescriptor("descriptor is not canonical")); }
        Ok(descriptor)
    }
    fn validate(&self) -> Result<(), LiteError> {
        if self.descriptor_version != DESCRIPTOR_VERSION { return Err(LiteError::InvalidDescriptor("unsupported descriptor version")); }
        if self.network.is_empty() || self.genesis.is_empty() || self.backend_format != "rustlog-v1" { return Err(LiteError::InvalidDescriptor("invalid identity")); }
        if self.source_state_sha256.len() != 64 || !self.source_state_sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err(LiteError::InvalidDescriptor("invalid source state hash")); }
        if self.min_block < 0 || self.max_block < self.min_block { return Err(LiteError::InvalidDescriptor("invalid block range")); }
        if self.excluded_stores.windows(2).any(|p| p[0] >= p[1]) || self.excluded_stores.iter().any(|v| v.is_empty() || v.contains([',', '\n'])) { return Err(LiteError::InvalidDescriptor("excluded stores are not sorted unique names")); }
        if [&self.network, &self.genesis, &self.backend_format].iter().any(|v| v.contains(['=', '\n'])) { return Err(LiteError::InvalidDescriptor("unsafe field character")); }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatasetIdentity { pub network: String, pub genesis: String, pub schema_version: u32 }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SplitRequest { pub source: PathBuf, pub dataset_path: PathBuf, pub kind: LiteKind, pub identity: DatasetIdentity, pub recent_blocks: u64, pub exclude_historical_balance: bool, pub max_batch_operations: usize }
pub struct MergeRequest { pub snapshot: PathBuf, pub history: PathBuf, pub max_batch_operations: usize }

/// Creates `dataset_path/snapshot` or `dataset_path/history`. The source state hash is derived
/// from the locked read view, so the descriptor and copied rows describe one consistent point.
pub fn rewrite_split(manager: &StorageManager, request: &SplitRequest) -> tron_storage::Result<RewriteOutcome> {
    if request.kind == LiteKind::Snapshot && request.recent_blocks == 0 {
        return Err(rejected(LiteError::InvalidReference("snapshot recent_blocks must be greater than zero")));
    }
    let policy = RewritePolicy { max_batch_operations: request.max_batch_operations };
    let destination = request.dataset_path.join(request.kind.text());
    manager.rewrite_store(&[request.source.clone()], &destination, RewriteMode::CreateNew, &policy, &NoTransactionFaults, |sources, sink| {
        let source = &sources[0];
        let source_state_sha256 = logical_state_sha256(source).map_err(rejected)?;
        let latest = latest_height(source).map_err(rejected)?;
        validate_range(source, 0, latest).map_err(rejected)?;
        let genesis = block_at(source, 0).map_err(rejected)?.id;
        let first_recent = latest.saturating_sub(i64::try_from(request.recent_blocks - 1).unwrap_or(i64::MAX)).max(0);
        let mut excluded = if request.exclude_historical_balance { vec![StoreKind::AccountTrace.db_name().to_owned(), StoreKind::BalanceTrace.db_name().to_owned()] } else { Vec::new() };
        excluded.sort();
        let descriptor = LiteDescriptor { descriptor_version: DESCRIPTOR_VERSION, kind: request.kind, network: request.identity.network.clone(), genesis: request.identity.genesis.clone(), schema_version: request.identity.schema_version, backend_format: "rustlog-v1".into(), source_state_sha256, genesis_block_id: genesis, min_block: match request.kind { LiteKind::Snapshot => first_recent.min(latest), LiteKind::History => 0 }, max_block: latest, recent_blocks: match request.kind { LiteKind::Snapshot => request.recent_blocks, LiteKind::History => 0 }, excluded_stores: excluded, history_balance_compatible: !request.exclude_historical_balance };
        match request.kind {
            LiteKind::History => copy_matching(source, sink, |key| ARCHIVE_STORES.iter().any(|kind| has_prefix(key, *kind)))?,
            LiteKind::Snapshot => {
                copy_matching(source, sink, |key| !ARCHIVE_STORES.iter().chain(TRANSIENT_STORES.iter()).any(|kind| has_prefix(key, *kind)) && !(request.exclude_historical_balance && TRACE_STORES.iter().any(|kind| has_prefix(key, *kind))))?;
                copy_snapshot_block(source, sink, 0).map_err(rejected)?;
                if first_recent <= latest { for height in first_recent..=latest { if height != 0 { copy_snapshot_block(source, sink, height).map_err(rejected)?; } } }
            }
        }
        sink.put(&physical_key(&StoreKind::Common.name(), DESCRIPTOR_KEY), &descriptor.encode().map_err(rejected)?)
    })
}

pub fn rewrite_merge(manager: &StorageManager, request: &MergeRequest) -> tron_storage::Result<RewriteOutcome> {
    let policy = RewritePolicy { max_batch_operations: request.max_batch_operations };
    manager.rewrite_store(&[request.snapshot.clone(), request.history.clone()], &request.snapshot, RewriteMode::Replace, &policy, &NoTransactionFaults, |sources, sink| {
        // rewrite_store canonicalizes source order, so identify by descriptor kind rather than position.
        let first = read_descriptor(&sources[0]).map_err(rejected)?;
        let second = read_descriptor(&sources[1]).map_err(rejected)?;
        let (snapshot, sd, history, hd) = match (first.kind, second.kind) { (LiteKind::Snapshot, LiteKind::History) => (&sources[0], first, &sources[1], second), (LiteKind::History, LiteKind::Snapshot) => (&sources[1], second, &sources[0], first), _ => return Err(rejected(LiteError::Incompatible("snapshot/history kind mismatch"))) };
        compatible(&sd, &hd).map_err(rejected)?;
        if hd.max_block < sd.min_block { return Err(rejected(LiteError::Incompatible("history does not reach snapshot range"))); }
        validate_range(history, 0, hd.max_block).map_err(rejected)?;
        validate_sparse_snapshot(snapshot, &sd).map_err(rejected)?;
        copy_matching(snapshot, sink, |key| !ARCHIVE_STORES.iter().any(|kind| has_prefix(key, *kind)) && key != physical_key(&StoreKind::Common.name(), DESCRIPTOR_KEY).as_slice())?;
        // Java's trimExtraHistory deliberately leaves transactionHistoryStore untouched even
        // when block/trans/ret rows above the snapshot tip are trimmed.
        copy_matching(history, sink, |key| has_prefix(key, StoreKind::TransactionHistory))?;
        let history_max = hd.max_block.min(sd.max_block);
        for height in 0..=history_max { copy_merged_block(history, sink, height).map_err(rejected)?; }
        for height in history_max.saturating_add(1)..=sd.max_block { copy_merged_block(snapshot, sink, height).map_err(rejected)?; }
        if !sd.history_balance_compatible || !hd.history_balance_compatible { sink.put(&physical_key(&StoreKind::Common.name(), HISTORY_BALANCE_DISABLED_KEY), b"1")?; }
        Ok(())
    })
}

fn logical_state_sha256(store: &RustLog) -> Result<String, LiteError> {
    let mut kinds = StoreKind::ALL;
    kinds.sort_by_key(|kind| kind.db_name());
    let mut hash = Sha256::new();
    hash.update(b"C027LOG1");
    let mut matched = 0u64;
    for kind in kinds {
        let name = kind.db_name().as_bytes();
        let prefix = physical_key(&kind.name(), &[]);
        store.visit_entries(|key, value| {
            if let Some(logical_key) = key.strip_prefix(prefix.as_slice()) {
                hash.update((name.len() as u32).to_be_bytes());
                hash.update(name);
                hash.update((logical_key.len() as u64).to_be_bytes());
                hash.update(logical_key);
                hash.update((value.len() as u64).to_be_bytes());
                hash.update(value);
                matched += 1;
            }
            Ok::<(), LiteError>(())
        })?;
    }
    let mut total = 0u64;
    store.visit_entries(|_, _| { total += 1; Ok::<(), LiteError>(()) })?;
    if matched != total { return Err(LiteError::InvalidReference("unknown physical namespace")); }
    Ok(hex(&hash.finalize()))
}

fn latest_height(store: &RustLog) -> Result<i64, LiteError> {
    let prefix = physical_key(&StoreKind::BlockIndex.name(), &[]);
    let mut latest = None;
    store.visit_entries(|key, _| { if let Some(logical) = key.strip_prefix(prefix.as_slice()) { if logical.len() != 8 { return Err(LiteError::InvalidReference("invalid block-index key")); } let height = i64::from_be_bytes(logical.try_into().expect("checked")); if height < 0 { return Err(LiteError::InvalidReference("negative block height")); } latest = Some(latest.map_or(height, |old: i64| old.max(height))); } Ok(()) })?;
    latest.ok_or(LiteError::MissingGenesis)
}
fn validate_range(store: &RustLog, first: i64, last: i64) -> Result<(), LiteError> { for height in first..=last { let _ = block_at(store, height)?; } Ok(()) }
fn validate_sparse_snapshot(store: &RustLog, descriptor: &LiteDescriptor) -> Result<(), LiteError> { let genesis = block_at(store, 0)?; if genesis.id != descriptor.genesis_block_id { return Err(LiteError::Incompatible("genesis block ID mismatch")); } for height in descriptor.min_block..=descriptor.max_block { let _ = block_at(store, height)?; } Ok(()) }

struct BlockRows { id: [u8; 32], encoded: Vec<u8>, transactions: Vec<([u8; 32], Vec<u8>)> }
fn block_at(store: &RustLog, height: i64) -> Result<BlockRows, LiteError> {
    let index_key = physical_key(&StoreKind::BlockIndex.name(), &height.to_be_bytes());
    let id = store.get(&index_key).ok_or(LiteError::InvalidReference("block height is absent"))?;
    let id: [u8; 32] = id.as_slice().try_into().map_err(|_| LiteError::InvalidReference("invalid block ID length"))?;
    let block_key = physical_key(&StoreKind::Block.name(), &id);
    let encoded = store.get(&block_key).ok_or(LiteError::InvalidReference("block-index references missing block"))?;
    let raw = RawBlock::decode(&encoded, BlockLimits::default()).map_err(|_| LiteError::InvalidProtobuf("invalid block protobuf"))?;
    let actual = raw.block_id(CryptoEngine::Secp256k1).map_err(|_| LiteError::InvalidProtobuf("missing raw block header"))?;
    if actual.as_bytes() != id || actual.height() != height { return Err(LiteError::InvalidReference("block identity does not match index")); }
    let mut transactions = Vec::with_capacity(raw.transaction_bytes().len());
    for bytes in raw.transaction_bytes() {
        let tx = RawWireTransaction::decode(bytes.to_vec()).map_err(|_| LiteError::InvalidProtobuf("invalid transaction protobuf"))?;
        let txid = tx.transaction_id(CryptoEngine::Secp256k1).into_array();
        let stored = store.get(&physical_key(&StoreKind::Transaction.name(), &txid)).ok_or(LiteError::InvalidReference("block references missing transaction"))?;
        if stored != bytes { return Err(LiteError::InvalidReference("stored transaction bytes differ from block")); }
        transactions.push((txid, stored));
    }
    Ok(BlockRows { id, encoded, transactions })
}
fn copy_snapshot_block(source: &RustLog, sink: &mut RewriteSink<'_>, height: i64) -> Result<(), LiteError> {
    let block = block_at(source, height)?;
    put_lite(sink, StoreKind::BlockIndex, &height.to_be_bytes(), &block.id)?;
    put_lite(sink, StoreKind::Block, &block.id, &block.encoded)?;
    for (id, bytes) in block.transactions { put_lite(sink, StoreKind::Transaction, &id, &bytes)?; }
    Ok(())
}
fn copy_merged_block(source: &RustLog, sink: &mut RewriteSink<'_>, height: i64) -> Result<(), LiteError> {
    let block = block_at(source, height)?;
    put_lite(sink, StoreKind::BlockIndex, &height.to_be_bytes(), &block.id)?;
    put_lite(sink, StoreKind::Block, &block.id, &block.encoded)?;
    for (id, bytes) in block.transactions {
        put_lite(sink, StoreKind::Transaction, &id, &bytes)?;
        copy_optional(source, sink, StoreKind::TransactionHistory, &id)?;
    }
    copy_optional(source, sink, StoreKind::TransactionRet, &height.to_be_bytes())?;
    Ok(())
}
fn put_lite(sink: &mut RewriteSink<'_>, kind: StoreKind, key: &[u8], value: &[u8]) -> Result<(), LiteError> { sink.put(&physical_key(&kind.name(), key), value).map_err(|_| LiteError::Storage("rewrite sink failed")) }
fn copy_optional(source: &RustLog, sink: &mut RewriteSink<'_>, kind: StoreKind, key: &[u8]) -> Result<(), LiteError> { if let Some(value) = source.get(&physical_key(&kind.name(), key)) { put_lite(sink, kind, key, &value)?; } Ok(()) }
fn copy_matching(source: &RustLog, sink: &mut RewriteSink<'_>, keep: impl Fn(&[u8]) -> bool) -> tron_storage::Result<()> { source.visit_entries(|key, value| if keep(key) { sink.put(key, value) } else { Ok(()) }) }
fn has_prefix(key: &[u8], kind: StoreKind) -> bool { key.starts_with(&physical_key(&kind.name(), &[])) }
fn read_descriptor(store: &RustLog) -> Result<LiteDescriptor, LiteError> { let bytes = store.get(&physical_key(&StoreKind::Common.name(), DESCRIPTOR_KEY)).ok_or(LiteError::MissingDescriptor)?; LiteDescriptor::decode(&bytes) }
fn compatible(a: &LiteDescriptor, b: &LiteDescriptor) -> Result<(), LiteError> { if a.network != b.network || a.genesis != b.genesis || a.schema_version != b.schema_version || a.backend_format != b.backend_format || a.genesis_block_id != b.genesis_block_id { Err(LiteError::Incompatible("identity, schema, backend, or genesis mismatch")) } else { Ok(()) } }
fn rejected(error: LiteError) -> StorageError { StorageError::RewriteRejected { category: error.category(), detail: error.to_string() } }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiteError { InvalidDescriptor(&'static str), MissingDescriptor, MissingGenesis, InvalidReference(&'static str), InvalidProtobuf(&'static str), Incompatible(&'static str), Storage(&'static str) }
impl LiteError { pub const fn category(&self) -> &'static str { match self { Self::Incompatible(_) => "incompatible_lite_dataset", _ => "invalid_lite_dataset" } } }
impl fmt::Display for LiteError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { let detail = match self { Self::InvalidDescriptor(v)|Self::InvalidReference(v)|Self::InvalidProtobuf(v)|Self::Incompatible(v)|Self::Storage(v) => *v, Self::MissingDescriptor => "lite descriptor is missing", Self::MissingGenesis => "genesis block is missing" }; write!(f, "{}: {detail}", self.category()) } }
impl std::error::Error for LiteError {}

fn parse<T: std::str::FromStr>(fields: &BTreeMap<&str, &str>, key: &'static str) -> Result<T, LiteError> { fields[key].parse().map_err(|_| LiteError::InvalidDescriptor(key)) }
fn decode_32(value: &str) -> Result<[u8; 32], LiteError> { if value.len() != 64 { return Err(LiteError::InvalidDescriptor("invalid genesis block ID")); } let mut out = [0; 32]; for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() { out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?; } Ok(out) }
fn nibble(value: u8) -> Result<u8, LiteError> { match value { b'0'..=b'9' => Ok(value-b'0'), b'a'..=b'f' => Ok(value-b'a'+10), _ => Err(LiteError::InvalidDescriptor("invalid lowercase hex")) } }
fn hex(bytes: &[u8]) -> String { const H: &[u8;16]=b"0123456789abcdef"; let mut out=String::with_capacity(bytes.len()*2); for &b in bytes { out.push(H[(b>>4) as usize] as char); out.push(H[(b&15) as usize] as char); } out }
fn crc32(bytes: &[u8]) -> u32 { let mut crc=!0u32; for &b in bytes { crc^=u32::from(b); for _ in 0..8 { crc=(crc>>1)^(0xedb8_8320 & 0u32.wrapping_sub(crc&1)); } } !crc }
