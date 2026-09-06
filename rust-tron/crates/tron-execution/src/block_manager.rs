use std::io::Read;
use std::ops::Range;

use prost::Message;
use tron_crypto::{selected_digest, CryptoEngine};
use tron_primitives::{BlockId, Hash32};
use tron_protocol::protocol::{block_header, Account, Block, TransactionRet};
use tron_state::{dynamic, AccountTrie, CheckpointIdentity, CursorPoint, KhaosBlockData, KhaosDatabase, KhaosLimits, RetainedSize, Session, SessionManager, StoreKind};

use crate::{AdmissionClock, AdmissionOrigin, ProcessContext, ProcessError, ProcessOutput, RawWireTransaction, TransactionProcessor};

pub const JAVA_TRON_C019_REVISION: &str = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockLimits {
    pub max_block_bytes: usize,
    pub max_transactions: usize,
    pub max_shielded_transactions: usize,
    pub max_decode_recursion: usize,
    pub min_version: i32,
    pub max_version: i32,
    pub max_future_millis: i64,
}
impl Default for BlockLimits {
    fn default() -> Self { Self { max_block_bytes: 2_000_000, max_transactions: 20_000, max_shielded_transactions: 1, max_decode_recursion: 64, min_version: 0, max_version: 32, max_future_millis: 3_000 } }
}

impl BlockLimits {
    pub fn khaos_limits(self, fork_depth: i64, branch_width: usize) -> KhaosLimits {
        KhaosLimits::for_block_policy(self.max_block_bytes, fork_depth, branch_width)
    }
}

#[derive(Clone, Debug)]
pub struct RawBlock {
    pub message: Block,
    pub full_bytes: Vec<u8>,
    raw_header_range: Range<usize>,
    transaction_ranges: Vec<Range<usize>>,
    transactions: Vec<Option<RawWireTransaction>>,
}
impl RawBlock {
    pub fn decode(full_bytes: impl AsRef<[u8]>, limits: BlockLimits) -> Result<Self, BlockApplyError> {
        let bytes = full_bytes.as_ref();
        if bytes.len() > limits.max_block_bytes { return Err(BlockApplyError::TooLarge(bytes.len())); }
        let (raw_header_range, transaction_ranges) = scan_block(bytes, limits.max_transactions, limits.max_decode_recursion)?;
        let message = Block::decode(bytes).map_err(|_| BlockApplyError::MalformedWire)?;
        let transactions = vec![None; transaction_ranges.len()];
        Ok(Self { message, full_bytes: bytes.to_vec(), raw_header_range, transaction_ranges, transactions })
    }
    pub fn decode_reader(mut reader: impl Read, limits: BlockLimits) -> Result<Self, BlockApplyError> {
        let bounded = limits.max_block_bytes.saturating_add(1);
        let mut bytes = Vec::with_capacity(bounded.min(64 * 1024));
        reader.by_ref().take(u64::try_from(bounded).unwrap_or(u64::MAX)).read_to_end(&mut bytes).map_err(|_| BlockApplyError::MalformedWire)?;
        Self::decode(bytes, limits)
    }
    pub fn raw_header_bytes(&self) -> &[u8] { &self.full_bytes[self.raw_header_range.clone()] }
    pub fn transaction_bytes(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.transaction_ranges.iter().map(|range| &self.full_bytes[range.clone()])
    }
    pub fn transaction_bytes_at(&self, index: usize) -> Option<&[u8]> {
        self.transaction_ranges.get(index).map(|range| &self.full_bytes[range.clone()])
    }
    pub fn clear_signature_verification_cache(&mut self) {
        for transaction in self.transactions.iter_mut().flatten() { transaction.clear_signature_verification_cache(); }
    }
    pub fn block_id(&self, engine: CryptoEngine) -> Result<BlockId, BlockApplyError> {
        let number = self.message.block_header.as_ref().and_then(|header| header.raw_data.as_ref()).ok_or(BlockApplyError::MissingRawHeader)?.number;
        Ok(BlockId::new(number, selected_digest(engine, self.raw_header_bytes()).into()))
    }

    pub fn transaction_merkle_root(&self, engine: CryptoEngine) -> Vec<u8> {
        merkle(engine, self.transaction_bytes().map(|bytes| Hash32::from_array(selected_digest(engine, bytes))).collect())
    }
}

#[derive(Clone, Debug)]
pub struct ManagedBlock { pub raw: RawBlock, pub id: BlockId, pub received_at: i64 }
impl RetainedSize for ManagedBlock {
    fn retained_size(&self) -> usize {
        self.raw.full_bytes.capacity().saturating_add(self.raw.transaction_ranges.capacity().saturating_mul(std::mem::size_of::<Range<usize>>()))
    }
}

pub trait BlockConsensus {
    fn verify_witness_signature(&self, raw_header: &[u8], signature: &[u8], witness: &[u8]) -> bool;
    fn scheduled_witness(&self, parent_number: i64, parent_timestamp: i64, timestamp: i64) -> Result<Vec<u8>, String>;
}

pub trait BlockApplyHooks {
    fn backup_master(&mut self, _session: &Session) -> Result<(), String> { Ok(()) }
    fn pay_reward(&mut self, _session: &Session, _witness: &[u8], _number: i64) -> Result<(), String> { Ok(()) }
    fn process_proposals(&mut self, _session: &Session, _timestamp: i64) -> Result<(), String> { Ok(()) }
    fn maintenance_and_dpos(&mut self, _session: &Session, _timestamp: i64) -> Result<(), String> { Ok(()) }
    fn update_fork_stats(&mut self, _session: &Session, _version: i32, _witness: &[u8]) -> Result<(), String> { Ok(()) }
    fn update_consensus_views(&mut self, _session: &Session, _id: BlockId, _number: i64, _timestamp: i64) -> Result<(), String> { Ok(()) }
}
impl BlockApplyHooks for () {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockApplyError {
    MalformedWire, MissingHeader, MissingRawHeader, RawHeaderMismatch, TransactionWireMismatch,
    Duplicate(BlockId), ParentMismatch, HeightMismatch, Timestamp, Version(i32), TooLarge(usize), TooManyTransactions(usize), TooManyShielded(usize),
    InvalidSignature, WrongWitness, InvalidTransaction(String), TransactionResultMismatch(usize), TransactionMerkleMismatch, AccountRootMismatch,
    State(String), Graph(String), Hook(String), Arithmetic,
}
impl core::fmt::Display for BlockApplyError { fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "block apply error: {self:?}") } }
impl std::error::Error for BlockApplyError {}
impl From<ProcessError> for BlockApplyError { fn from(value: ProcessError) -> Self { Self::InvalidTransaction(value.to_string()) } }

pub struct BlockManager<C, H = ()> {
    pub sessions: SessionManager,
    pub processor: TransactionProcessor,
    pub khaos: KhaosDatabase<ManagedBlock>,
    pub consensus: C,
    pub hooks: H,
    pub limits: BlockLimits,
    pub engine: CryptoEngine,
}

impl<C: BlockConsensus, H: BlockApplyHooks> BlockManager<C, H> {
    pub fn apply_block(&mut self, block: RawBlock, now: i64) -> Result<BlockId, BlockApplyError> {
        self.apply_block_mode(block, now, false)
    }

    /// Applies a block which is already retained by Khaos during a fork replay.
    /// The caller selects its parent as the Khaos head before invoking this method.
    pub fn apply_fork_block(&mut self, block: RawBlock, now: i64) -> Result<BlockId, BlockApplyError> {
        self.apply_block_mode(block, now, true)
    }
    pub fn apply_fork_block_at(&mut self, block: RawBlock, received_at: i64) -> Result<BlockId, BlockApplyError> {
        self.apply_block_mode(block, received_at, true)
    }


    fn apply_block_mode(&mut self, mut block: RawBlock, now: i64, retained: bool) -> Result<BlockId, BlockApplyError> {
        let header = block.message.block_header.as_ref().ok_or(BlockApplyError::MissingHeader)?;
        let raw = header.raw_data.as_ref().ok_or(BlockApplyError::MissingRawHeader)?.clone();
        if raw.encode_to_vec().as_slice() != block.raw_header_bytes() { return Err(BlockApplyError::RawHeaderMismatch); }
        if block.message.transactions.len() != block.transaction_ranges.len() || block.message.transactions.iter().zip(block.transaction_bytes()).any(|(tx, bytes)| tx.encode_to_vec().as_slice() != bytes) { return Err(BlockApplyError::TransactionWireMismatch); }
        let id = BlockId::new(raw.number, selected_digest(self.engine, block.raw_header_bytes()).into());
        if retained {
            if !self.khaos.contain_block_in_mini_store(&id) { return Err(BlockApplyError::Graph("fork block is not retained".into())); }
        } else if self.khaos.contain_block(&id) || self.sessions.read_view().store(StoreKind::Block).get(id.as_bytes()).is_some() { return Err(BlockApplyError::Duplicate(id)); }
        if block.full_bytes.len() > self.limits.max_block_bytes { return Err(BlockApplyError::TooLarge(block.full_bytes.len())); }
        if block.message.transactions.len() > self.limits.max_transactions { return Err(BlockApplyError::TooManyTransactions(block.message.transactions.len())); }
        if !(self.limits.min_version..=self.limits.max_version).contains(&raw.version) { return Err(BlockApplyError::Version(raw.version)); }
        let head = self.khaos.get_head().ok_or(BlockApplyError::ParentMismatch)?;
        if raw.parent_hash.as_slice() != head.id.as_bytes() { return Err(BlockApplyError::ParentMismatch); }
        if raw.number != head.number.checked_add(1).ok_or(BlockApplyError::Arithmetic)? { return Err(BlockApplyError::HeightMismatch); }
        let parent_raw = head.value.raw.message.block_header.as_ref().and_then(|h| h.raw_data.as_ref()).ok_or(BlockApplyError::MissingRawHeader)?;
        if raw.timestamp <= parent_raw.timestamp || raw.timestamp > now.checked_add(self.limits.max_future_millis).ok_or(BlockApplyError::Arithmetic)? { return Err(BlockApplyError::Timestamp); }
        if header.witness_signature.is_empty() || !self.consensus.verify_witness_signature(block.raw_header_bytes(), &header.witness_signature, &raw.witness_address) { return Err(BlockApplyError::InvalidSignature); }
        let scheduled = self.consensus.scheduled_witness(head.number, parent_raw.timestamp, raw.timestamp).map_err(BlockApplyError::Hook)?;
        if scheduled != raw.witness_address { return Err(BlockApplyError::WrongWitness); }
        let shielded = block.message.transactions.iter().filter(|tx| tx.raw_data.as_ref().is_some_and(|r| r.contract.iter().any(|c| c.r#type == 51))).count();
        if shielded > self.limits.max_shielded_transactions { return Err(BlockApplyError::TooManyShielded(shielded)); }
        if !retained {
            let retained_size = block.full_bytes.len().saturating_add(block.transaction_ranges.len().saturating_mul(std::mem::size_of::<Range<usize>>()));
            self.khaos.check_linked_resource(&head.id, retained_size).map_err(|error| BlockApplyError::Graph(error.to_string()))?;
        }


        let cache_before = self.processor.cache.clone();
        let mut session = self.sessions.build_session_enabled().map_err(|e| BlockApplyError::State(e.to_string()))?;
        let outcome = self.apply_in(&session, &mut block, id, now, &raw).and_then(|outputs| {
            self.hooks.backup_master(&session).map_err(BlockApplyError::Hook)?;
            self.hooks.pay_reward(&session, &raw.witness_address, raw.number).map_err(BlockApplyError::Hook)?;
            self.hooks.process_proposals(&session, raw.timestamp).map_err(BlockApplyError::Hook)?;
            self.hooks.maintenance_and_dpos(&session, raw.timestamp).map_err(BlockApplyError::Hook)?;
            self.hooks.update_fork_stats(&session, raw.version, &raw.witness_address).map_err(BlockApplyError::Hook)?;
            persist_block(&session, &block, id, &raw, now, &outputs)?;
            self.hooks.update_consensus_views(&session, id, raw.number, raw.timestamp).map_err(BlockApplyError::Hook)?;
            Ok(outputs)
        });
        if let Err(error) = outcome { self.processor.cache = cache_before; session.revoke().map_err(|e| BlockApplyError::State(e.to_string()))?; return Err(error); }
        let checkpoint = CursorPoint {
            block: u64::try_from(raw.number).map_err(|_| BlockApplyError::HeightMismatch)?,
            identity: CheckpointIdentity::new(id.as_bytes().try_into().map_err(|_| BlockApplyError::Arithmetic)?),
        };
        if !retained {
            let data = KhaosBlockData::new(id, Hash32::try_from(raw.parent_hash.as_slice()).map_err(|_| BlockApplyError::ParentMismatch)?, raw.number, ManagedBlock { raw: block, id, received_at: now });
            if let Err(error) = self.khaos.push(data) { self.processor.cache = cache_before; session.revoke().map_err(|e| BlockApplyError::State(e.to_string()))?; return Err(BlockApplyError::Graph(error.to_string())); }
        }
        if let Err(error) = session.commit_with_checkpoint(checkpoint) { self.processor.cache = cache_before; if !retained { let _ = self.khaos.remove_blk(&id); } return Err(BlockApplyError::State(error.to_string())); }
        if retained { self.khaos.set_head(&id).map_err(|error| BlockApplyError::Graph(error.to_string()))?; }
        Ok(id)
    }

    fn apply_in(&mut self, session: &Session, block: &mut RawBlock, id: BlockId, now: i64, raw: &block_header::Raw) -> Result<Vec<ProcessOutput>, BlockApplyError> {
        let mut outputs = Vec::with_capacity(block.transaction_ranges.len());
        let mut leaves = Vec::with_capacity(block.transaction_ranges.len());
        for index in 0..block.transaction_ranges.len() {
            let bytes = block.transaction_bytes_at(index).expect("range index checked");
            leaves.push(Hash32::from_array(selected_digest(self.engine, bytes)));
            let expected = block.message.transactions[index].ret.first().and_then(|r| tron_tvm::ContractResult::from_runtime_number(r.contract_ret));
            if block.transactions[index].is_none() {
                block.transactions[index] = Some(RawWireTransaction::decode(bytes.to_vec()).map_err(|e| BlockApplyError::InvalidTransaction(e.to_string()))?);
            }
            let tx = block.transactions[index].as_mut().expect("transaction initialized above");
            let context = ProcessContext { origin: AdmissionOrigin::Block, clock: AdmissionClock { head_block_time: raw.timestamp, next_block_slot_time: raw.timestamp, now, block_number: raw.number, head_slot: raw.number }, expected_result: expected, block_timestamp: raw.timestamp };
            let output = self.processor.process_in_session(session, tx, &context)?;
            if block.message.transactions[index].ret != output.transaction.ret { return Err(BlockApplyError::TransactionResultMismatch(index)); }
            self.processor.cache.insert(output.transaction_id, raw.number, now).map_err(|e| BlockApplyError::State(e.to_string()))?;
            session.store(StoreKind::TransactionHistory).put(output.transaction_id.as_bytes(), &output.info.encode_to_vec()).map_err(|e| BlockApplyError::State(e.to_string()))?;
            outputs.push(output);
        }
        if merkle(self.engine, leaves) != raw.tx_trie_root { return Err(BlockApplyError::TransactionMerkleMismatch); }
        if !raw.account_state_root.is_empty() {
            let mut trie = AccountTrie::new();
            for (_, bytes) in session.view().store(StoreKind::Account).prefix(&[]) { let account = Account::decode(bytes.as_slice()).map_err(|e| BlockApplyError::State(e.to_string()))?; trie.put_account(&account).map_err(|e| BlockApplyError::State(e.to_string()))?; }
            if trie.root_hash().map_err(|e| BlockApplyError::State(e.to_string()))?.as_slice() != raw.account_state_root { return Err(BlockApplyError::AccountRootMismatch); }
        }
        let _ = id;
        Ok(outputs)
    }
}

fn persist_block(session: &Session, block: &RawBlock, id: BlockId, raw: &block_header::Raw, now: i64, outputs: &[ProcessOutput]) -> Result<(), BlockApplyError> {
    session.store(StoreKind::Block).put(id.as_bytes(), &block.full_bytes).map_err(|e| BlockApplyError::State(e.to_string()))?;
    session.store(StoreKind::BlockIndex).put(&raw.number.to_be_bytes(), id.as_bytes()).map_err(|e| BlockApplyError::State(e.to_string()))?;
    session.store(StoreKind::RecentBlock).put(&raw.number.rem_euclid(65_536).to_be_bytes(), &id.as_bytes()[8..16]).map_err(|e| BlockApplyError::State(e.to_string()))?;
    let ret = TransactionRet { block_number: raw.number, block_time_stamp: raw.timestamp, transactioninfo: outputs.iter().map(|o| o.info.clone()).collect() };
    session.store(StoreKind::TransactionRet).put(&raw.number.to_be_bytes(), &ret.encode_to_vec()).map_err(|e| BlockApplyError::State(e.to_string()))?;
    for output in outputs { session.store(StoreKind::RecentTransaction).put(output.transaction_id.as_bytes(), &raw.number.to_be_bytes()).map_err(|e| BlockApplyError::State(e.to_string()))?; }
    for (name, bytes) in [("LATEST_BLOCK_HEADER_NUMBER", raw.number.to_be_bytes().to_vec()), ("LATEST_BLOCK_HEADER_TIMESTAMP", raw.timestamp.to_be_bytes().to_vec()), ("LATEST_BLOCK_HEADER_HASH", id.as_bytes().to_vec())] { if let Some(key) = dynamic::key(name) { session.store(StoreKind::DynamicProperties).put(key, &bytes).map_err(|e| BlockApplyError::State(e.to_string()))?; } }
    let mut metadata = Vec::with_capacity(48); metadata.extend_from_slice(&now.to_be_bytes()); metadata.extend_from_slice(&raw.timestamp.to_be_bytes()); metadata.extend_from_slice(id.as_bytes());
    session.store(StoreKind::Common).put(id.as_bytes(), &metadata).map_err(|e| BlockApplyError::State(e.to_string()))?;
    Ok(())
}

fn merkle(engine: CryptoEngine, mut level: Vec<Hash32>) -> Vec<u8> { if level.is_empty() { return vec![0; 32]; } while level.len() > 1 { let mut next = Vec::with_capacity((level.len()+1)/2); for pair in level.chunks(2) { if pair.len()==1 { next.push(pair[0]); } else { let mut bytes=[0;64]; bytes[..32].copy_from_slice(pair[0].as_bytes()); bytes[32..].copy_from_slice(pair[1].as_bytes()); next.push(Hash32::from_array(selected_digest(engine,&bytes))); } } level=next; } level[0].as_bytes().to_vec() }

fn scan_block(bytes: &[u8], max_transactions: usize, max_recursion: usize) -> Result<(Range<usize>, Vec<Range<usize>>), BlockApplyError> {
    if max_recursion < 2 { return Err(BlockApplyError::MalformedWire); }
    let mut txs = Vec::new();
    let mut header = None;
    scan_fields(bytes, 0, |number, range| {
        if number == 1 {
            if txs.len() == max_transactions { return Err(BlockApplyError::TooManyTransactions(txs.len().saturating_add(1))); }
            txs.push(range);
        } else if number == 2 {
            let payload = &bytes[range.clone()];
            let mut raw = None;
            scan_fields(payload, range.start, |n, nested| {
                if n == 1 { if raw.is_some() { return Err(BlockApplyError::MalformedWire); } raw = Some(nested); }
                Ok(())
            })?;
            header = raw;
        }
        Ok(())
    })?;
    Ok((header.ok_or(BlockApplyError::MissingRawHeader)?, txs))
}
fn scan_fields(mut bytes: &[u8], mut offset: usize, mut visit: impl FnMut(u32, Range<usize>) -> Result<(), BlockApplyError>) -> Result<(), BlockApplyError> {
    while !bytes.is_empty() {
        let (key, key_len) = varint(bytes)?;
        bytes = &bytes[key_len..]; offset = offset.checked_add(key_len).ok_or(BlockApplyError::MalformedWire)?;
        let field = (key >> 3) as u32; let wire = (key & 7) as u8;
        match wire {
            0 => { let (_, n) = varint(bytes)?; bytes = &bytes[n..]; offset += n; }
            1 => { if bytes.len() < 8 { return Err(BlockApplyError::MalformedWire); } bytes = &bytes[8..]; offset += 8; }
            2 => { let (len, n) = varint(bytes)?; let len = usize::try_from(len).map_err(|_| BlockApplyError::MalformedWire)?; bytes = &bytes[n..]; offset += n; if bytes.len() < len { return Err(BlockApplyError::MalformedWire); } let end = offset.checked_add(len).ok_or(BlockApplyError::MalformedWire)?; visit(field, offset..end)?; bytes = &bytes[len..]; offset = end; }
            5 => { if bytes.len() < 4 { return Err(BlockApplyError::MalformedWire); } bytes = &bytes[4..]; offset += 4; }
            _ => return Err(BlockApplyError::MalformedWire),
        }
    }
    Ok(())
}
fn varint(bytes: &[u8]) -> Result<(u64, usize), BlockApplyError> { let mut value=0; for(i,b)in bytes.iter().copied().take(10).enumerate(){if i==9&&b>1{return Err(BlockApplyError::MalformedWire)}value|=u64::from(b&0x7f)<<(7*i);if b&0x80==0{return Ok((value,i+1))}}Err(BlockApplyError::MalformedWire) }
