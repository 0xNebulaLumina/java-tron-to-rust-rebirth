use std::{collections::BTreeMap, sync::Mutex};

use prost::Message;
use tron_crypto::{derive_address, selected_digest, CryptoEngine, PublicKey, RecoverableSignature, Secp256k1Key};
use tron_protocol::protocol::{pbft_message, PbftCommitResult, PbftMessage, Srl};
use tron_state::{StateStore, StoreKind};

pub const DEFAULT_QUORUM: usize = 19;
pub const ROUND_TIMEOUT_MILLIS: i64 = 60_000;
pub const VOTE_CACHE_TTL_MILLIS: i64 = 120_000;
pub const BLOCK_KEY_PREFIX: &[u8] = b"BLOCK";
pub const SRL_KEY_PREFIX: &[u8] = b"SRL";
pub const LATEST_PBFT_BLOCK_NUM_KEY: &[u8] = b"LATEST_PBFT_BLOCK_NUM";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MsgType { ViewChange, Request, Preprepare, Prepare, Commit }
impl MsgType {
    const fn wire(self) -> i32 { match self { Self::ViewChange => 0, Self::Request => 1, Self::Preprepare => 2, Self::Prepare => 3, Self::Commit => 4 } }
    fn from_wire(value: i32) -> Result<Self, PbftError> { match value { 0 => Ok(Self::ViewChange), 1 => Ok(Self::Request), 2 => Ok(Self::Preprepare), 3 => Ok(Self::Prepare), 4 => Ok(Self::Commit), other => Err(PbftError::UnknownMsgType(other)) } }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataType { Block, Srl }
impl DataType {
    const fn wire(self) -> i32 { match self { Self::Block => 0, Self::Srl => 1 } }
    fn from_wire(value: i32) -> Result<Self, PbftError> { match value { 0 => Ok(Self::Block), 1 => Ok(Self::Srl), other => Err(PbftError::UnknownDataType(other)) } }
    const fn key_prefix(self) -> &'static [u8] { match self { Self::Block => BLOCK_KEY_PREFIX, Self::Srl => SRL_KEY_PREFIX } }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Raw { pub msg_type: MsgType, pub data_type: DataType, pub view_n: i64, pub epoch: i64, pub data: Vec<u8> }
impl Raw {
    #[must_use] pub fn to_proto(&self) -> pbft_message::Raw { pbft_message::Raw { msg_type: self.msg_type.wire(), data_type: self.data_type.wire(), view_n: self.view_n, epoch: self.epoch, data: self.data.clone() } }
    #[must_use] pub fn bytes(&self) -> Vec<u8> { self.to_proto().encode_to_vec() }
    pub fn from_proto(raw: pbft_message::Raw) -> Result<Self, PbftError> { Ok(Self { msg_type: MsgType::from_wire(raw.msg_type)?, data_type: DataType::from_wire(raw.data_type)?, view_n: raw.view_n, epoch: raw.epoch, data: raw.data }) }
    #[must_use] pub fn no(&self) -> String { format!("{}_{}", self.view_n, self.data_type.wire()) }
    #[must_use] pub fn data_key(&self) -> Vec<u8> { let mut key = self.no().into_bytes(); key.push(b'_'); append_hex(&mut key, &self.data); key }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedMessage { pub raw: Raw, pub signature: Vec<u8> }
impl SignedMessage {
    #[must_use] pub fn unsigned(raw: Raw) -> Self { Self { raw, signature: Vec::new() } }
    pub fn sign(raw: Raw, key: &Secp256k1Key) -> Result<Self, PbftError> { let hash = selected_digest(CryptoEngine::Secp256k1, &raw.bytes()); let signature = key.sign_prehash(&hash).map_err(PbftError::Crypto)?.to_wire().to_vec(); Ok(Self { raw, signature }) }
    #[must_use] pub fn to_proto(&self) -> PbftMessage { PbftMessage { raw_data: Some(self.raw.to_proto()), signature: self.signature.clone() } }
    #[must_use] pub fn bytes(&self) -> Vec<u8> { self.to_proto().encode_to_vec() }
    #[must_use] pub fn encoded_len(&self) -> usize { self.to_proto().encoded_len() }
    pub fn decode(bytes: &[u8]) -> Result<Self, PbftError> { let message = PbftMessage::decode(bytes).map_err(|error| PbftError::Malformed(error.to_string()))?; let raw = message.raw_data.ok_or(PbftError::MissingRaw)?; Ok(Self { raw: Raw::from_proto(raw)?, signature: message.signature }) }
    pub fn recover_witness(&self) -> Result<Vec<u8>, PbftError> { if self.signature.is_empty() { return Err(PbftError::MissingSignature); } let hash = selected_digest(CryptoEngine::Secp256k1, &self.raw.bytes()); let signature = RecoverableSignature::from_consensus_wire(&self.signature).map_err(PbftError::Crypto)?; let public = PublicKey::recover_prehash(CryptoEngine::Secp256k1, &hash, &signature).map_err(PbftError::Crypto)?; Ok(derive_address(&public).as_bytes().to_vec()) }
    pub fn signed_as(&self, msg_type: MsgType, key: &Secp256k1Key) -> Result<Self, PbftError> { let mut raw = self.raw.clone(); raw.msg_type = msg_type; Self::sign(raw, key) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quorum(usize);
impl Quorum {
    #[must_use] pub fn new(configured: Option<usize>, committee_len: usize) -> Self { let maximum = committee_len.max(1); Self(configured.unwrap_or(DEFAULT_QUORUM).clamp(1, maximum)) }
    #[must_use] pub const fn get(self) -> usize { self.0 }
    #[must_use] pub const fn reached(self, votes: usize) -> bool { votes >= self.0 }
}

#[derive(Clone)]
pub struct LocalSigner { pub witness: Vec<u8>, pub key: Secp256k1Key }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PbftBounds {
    pub round_timeout_millis: i64,
    pub vote_ttl_millis: i64,
    pub max_rounds: usize,
    pub max_votes: usize,
    pub max_raw_data_bytes: usize,
    pub max_encoded_message_bytes: usize,
    pub max_round_bytes: usize,
    pub max_retained_bytes: usize,
}
impl Default for PbftBounds {
    fn default() -> Self { Self { round_timeout_millis: ROUND_TIMEOUT_MILLIS, vote_ttl_millis: VOTE_CACHE_TTL_MILLIS, max_rounds: 1_000, max_votes: 10_000, max_raw_data_bytes: 1_048_576, max_encoded_message_bytes: 1_048_704, max_round_bytes: 4_194_304, max_retained_bytes: 16_777_216 } }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedProposal { pub data_type: DataType, pub view_n: i64, pub epoch: i64, pub proposer: Vec<u8>, pub data: Vec<u8> }
#[derive(Clone)]
pub struct PbftContext { pub now_millis: i64, pub syncing: bool, pub chain_switch: bool, pub current_witnesses: Vec<Vec<u8>>, pub before_witnesses: Vec<Vec<u8>>, pub before_maintenance_time: i64, pub local_signers: Vec<LocalSigner>, pub expected_proposals: Vec<ExpectedProposal> }
impl PbftContext {
    fn committee(&self, epoch: i64) -> &[Vec<u8>] { if epoch > self.before_maintenance_time { &self.current_witnesses } else { &self.before_witnesses } }
    fn signer_keys(&self, epoch: i64) -> impl Iterator<Item = &Secp256k1Key> { let committee = self.committee(epoch); self.local_signers.iter().filter(move |signer| committee.contains(&signer.witness)).map(|signer| &signer.key) }
    fn expected_proposal(&self, raw: &Raw) -> Option<&ExpectedProposal> { self.expected_proposals.iter().find(|proposal| proposal.data_type == raw.data_type && proposal.view_n == raw.view_n && proposal.epoch == raw.epoch) }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Effect { Forward(Vec<u8>), Commit(CommitData) }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitData { pub raw: Vec<u8>, pub data_type: DataType, pub number: i64, pub epoch: i64, pub signatures: Vec<Vec<u8>> }
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProposalIdentity { data_type: DataType, view_n: i64, epoch: i64, data: Vec<u8> }
impl From<&Raw> for ProposalIdentity { fn from(raw: &Raw) -> Self { Self { data_type: raw.data_type, view_n: raw.view_n, epoch: raw.epoch, data: raw.data.clone() } } }
#[derive(Default)]
struct Round { started_at: i64, identity: Option<ProposalIdentity>, prepare: BTreeMap<Vec<u8>, SignedMessage>, commit: BTreeMap<Vec<u8>, SignedMessage>, done: bool, retained_bytes: usize }

pub struct PbftSidecar {
    quorum: Option<usize>, bounds: PbftBounds, rounds: BTreeMap<String, Round>, completed: BTreeMap<String, i64>,
    pending_prepare: BTreeMap<Vec<u8>, (i64, SignedMessage)>, pending_commit: BTreeMap<Vec<u8>, (i64, SignedMessage)>, retained_bytes: usize,
}
impl PbftSidecar {
    #[must_use] pub fn new(quorum: Option<usize>, bounds: PbftBounds) -> Self { Self { quorum, bounds, rounds: BTreeMap::new(), completed: BTreeMap::new(), pending_prepare: BTreeMap::new(), pending_commit: BTreeMap::new(), retained_bytes: 0 } }
    fn checked_size(&self, message: &SignedMessage) -> Result<usize, PbftError> { if message.raw.data.len() > self.bounds.max_raw_data_bytes { return Err(PbftError::Capacity); } let size = message.encoded_len(); if size > self.bounds.max_encoded_message_bytes { return Err(PbftError::Capacity); } Ok(size) }
    fn reserve(&self, current_round: usize, added: usize) -> Result<(), PbftError> { if current_round.checked_add(added).is_none_or(|v| v > self.bounds.max_round_bytes) || self.retained_bytes.checked_add(added).is_none_or(|v| v > self.bounds.max_retained_bytes) { return Err(PbftError::Capacity); } Ok(()) }
    pub fn expire(&mut self, now_millis: i64) {
        let timeout = self.bounds.round_timeout_millis;
        let expired: Vec<_> = self.rounds.iter().filter(|(_, round)| now_millis.saturating_sub(round.started_at) > timeout).map(|(key, _)| key.clone()).collect();
        for key in expired { if let Some(round) = self.rounds.remove(&key) { self.retained_bytes = self.retained_bytes.saturating_sub(round.retained_bytes); } }
        let ttl = self.bounds.vote_ttl_millis;
        self.completed.retain(|_, at| now_millis.saturating_sub(*at) <= ttl);
        expire_pending(&mut self.pending_prepare, now_millis, ttl, &mut self.retained_bytes);
        expire_pending(&mut self.pending_commit, now_millis, ttl, &mut self.retained_bytes);
    }
    /// Handles an authenticated network packet. Every message kind, including PREPREPARE, must be signed by the active committee.
    pub fn handle(&mut self, message: SignedMessage, context: PbftContext) -> Result<Vec<Effect>, PbftError> {
        self.expire(context.now_millis); self.checked_size(&message)?;
        let witness = message.recover_witness()?;
        if !context.committee(message.raw.epoch).contains(&witness) { return Err(PbftError::NonWitness); }
        self.dispatch(message, Some(witness), context)
    }
    /// Starts a locally produced PREPREPARE. It is deliberately separate from authenticated network handling.
    pub fn local_preprepare(&mut self, message: SignedMessage, context: PbftContext) -> Result<Vec<Effect>, PbftError> {
        self.expire(context.now_millis); self.checked_size(&message)?;
        if message.raw.msg_type != MsgType::Preprepare { return Err(PbftError::LocalPreprepareOnly); }
        self.dispatch(message, None, context)
    }
    fn dispatch(&mut self, message: SignedMessage, witness: Option<Vec<u8>>, context: PbftContext) -> Result<Vec<Effect>, PbftError> {
        if self.completed.contains_key(&message.raw.no()) { return Ok(Vec::new()); }
        match message.raw.msg_type {
            MsgType::Preprepare => self.preprepare(message, witness, context),
            MsgType::Prepare => self.prepare(message, witness.expect("network witness"), context),
            MsgType::Commit => self.commit(message, witness.expect("network witness"), context),
            MsgType::Request | MsgType::ViewChange => Ok(Vec::new()),
        }
    }
    fn preprepare(&mut self, message: SignedMessage, witness: Option<Vec<u8>>, context: PbftContext) -> Result<Vec<Effect>, PbftError> {
        let no = message.raw.no();
        if context.chain_switch { self.remove_round(&no); return Ok(Vec::new()); }
        let expected = context.expected_proposal(&message.raw).ok_or(PbftError::ProposalMismatch)?;
        if expected.data != message.raw.data { return Err(PbftError::ProposalMismatch); }
        if witness.is_some_and(|signer| signer != expected.proposer) { return Err(PbftError::WrongProposer); }
        let identity = ProposalIdentity::from(&message.raw);
        if let Some(round) = self.rounds.get(&no) { if round.identity.as_ref() == Some(&identity) { return Ok(Vec::new()); } return Err(PbftError::ProposalMismatch); }
        if self.rounds.len() >= self.bounds.max_rounds { return Err(PbftError::Capacity); }
        let size = message.encoded_len(); self.reserve(0, size)?;
        let round = self.rounds.entry(no.clone()).or_insert_with(|| Round { started_at: context.now_millis, ..Round::default() }); round.identity = Some(identity.clone()); round.retained_bytes += size; self.retained_bytes += size;
        let mut effects = Vec::new();
        if !context.syncing { let keys: Vec<_> = context.signer_keys(message.raw.epoch).cloned().collect(); for key in keys { let prepare = message.signed_as(MsgType::Prepare, &key)?; effects.push(Effect::Forward(prepare.bytes())); let witness = prepare.recover_witness()?; effects.extend(self.prepare(prepare, witness, context.clone())?); } }
        let cached: Vec<_> = self.pending_prepare.iter().filter(|(_, (_, item))| ProposalIdentity::from(&item.raw) == identity).map(|(key, (_, item))| (key.clone(), item.clone())).collect();
        for (key, item) in cached { if let Some((_, removed)) = self.pending_prepare.remove(&key) { self.retained_bytes = self.retained_bytes.saturating_sub(removed.encoded_len()); } let signer = item.recover_witness()?; effects.extend(self.prepare(item, signer, context.clone())?); }
        Ok(effects)
    }
    fn prepare(&mut self, message: SignedMessage, witness: Vec<u8>, context: PbftContext) -> Result<Vec<Effect>, PbftError> {
        let no = message.raw.no(); let identity = ProposalIdentity::from(&message.raw);
        let Some(round_identity) = self.rounds.get(&no).and_then(|round| round.identity.as_ref()) else { self.cache_prepare(message, witness, context.now_millis)?; return Ok(Vec::new()); };
        if round_identity != &identity { return Err(PbftError::ProposalMismatch); }
        let cached_key = vote_key(&message.raw, &witness); let size = message.encoded_len();
        if let Some(previous) = self.rounds[&no].prepare.get(&witness) { if ProposalIdentity::from(&previous.raw) != identity { return Err(PbftError::Equivocation); } return Ok(Vec::new()); }
        let round = &self.rounds[&no]; if round.prepare.len() >= self.bounds.max_votes { return Err(PbftError::Capacity); } self.reserve(round.retained_bytes, size)?;
        let (votes, already_done) = { let round = self.rounds.get_mut(&no).expect("preprepared round"); round.prepare.insert(witness, message.clone()); round.retained_bytes += size; self.retained_bytes += size; (round.prepare.len(), round.done) };
        let mut effects = Vec::new();
        if let Some((_, cached)) = self.pending_commit.remove(&cached_key) { self.retained_bytes = self.retained_bytes.saturating_sub(cached.encoded_len()); let signer = cached.recover_witness()?; effects.extend(self.commit(cached, signer, context.clone())?); }
        if self.completed.contains_key(&no) { return Ok(effects); }
        let quorum = Quorum::new(self.quorum, context.committee(message.raw.epoch).len());
        if already_done || !quorum.reached(votes) || context.syncing { return Ok(effects); }
        self.rounds.get_mut(&no).expect("prepared round").done = true;
        let keys: Vec<_> = context.signer_keys(message.raw.epoch).cloned().collect(); for key in keys { let commit = message.signed_as(MsgType::Commit, &key)?; effects.push(Effect::Forward(commit.bytes())); let witness = commit.recover_witness()?; effects.extend(self.commit(commit, witness, context.clone())?); }
        Ok(effects)
    }
    fn commit(&mut self, message: SignedMessage, witness: Vec<u8>, context: PbftContext) -> Result<Vec<Effect>, PbftError> {
        let no = message.raw.no(); let identity = ProposalIdentity::from(&message.raw);
        let Some(round) = self.rounds.get(&no) else { self.cache_commit(message, witness, context.now_millis)?; return Ok(Vec::new()); };
        if round.identity.as_ref() != Some(&identity) { return Err(PbftError::ProposalMismatch); }
        let Some(prepare) = round.prepare.get(&witness) else { self.cache_commit(message, witness, context.now_millis)?; return Ok(Vec::new()); };
        if ProposalIdentity::from(&prepare.raw) != identity { return Err(PbftError::PrepareCommitMismatch); }
        if let Some(previous) = round.commit.get(&witness) { if ProposalIdentity::from(&previous.raw) != identity { return Err(PbftError::Equivocation); } return Ok(Vec::new()); }
        let size = message.encoded_len(); if round.commit.len() >= self.bounds.max_votes { return Err(PbftError::Capacity); } self.reserve(round.retained_bytes, size)?;
        let (signatures, reached) = { let round = self.rounds.get_mut(&no).expect("prepared round"); round.commit.insert(witness, message.clone()); round.retained_bytes += size; self.retained_bytes += size; let reached = Quorum::new(self.quorum, context.committee(message.raw.epoch).len()).reached(round.commit.len()); (round.commit.values().map(|vote| vote.signature.clone()).collect::<Vec<_>>(), reached) };
        if !reached { return Ok(Vec::new()); }
        let commit = CommitData { raw: message.raw.bytes(), data_type: message.raw.data_type, number: message.raw.view_n, epoch: message.raw.epoch, signatures };
        self.remove_round(&no); self.completed.insert(no, context.now_millis);
        Ok(if context.syncing { Vec::new() } else { vec![Effect::Commit(commit)] })
    }
    fn cache_prepare(&mut self, message: SignedMessage, witness: Vec<u8>, now: i64) -> Result<(), PbftError> { self.cache_pending(true, message, witness, now) }
    fn cache_commit(&mut self, message: SignedMessage, witness: Vec<u8>, now: i64) -> Result<(), PbftError> { self.cache_pending(false, message, witness, now) }
    fn cache_pending(&mut self, prepare: bool, message: SignedMessage, witness: Vec<u8>, now: i64) -> Result<(), PbftError> {
        let key = vote_key(&message.raw, &witness); let map = if prepare { &self.pending_prepare } else { &self.pending_commit };
        if let Some((_, previous)) = map.get(&key) { if ProposalIdentity::from(&previous.raw) != ProposalIdentity::from(&message.raw) { return Err(PbftError::Equivocation); } return Ok(()); }
        if map.len() >= self.bounds.max_votes { return Err(PbftError::Capacity); } let size = message.encoded_len(); self.reserve(0, size)?;
        let map = if prepare { &mut self.pending_prepare } else { &mut self.pending_commit }; map.insert(key, (now, message)); self.retained_bytes += size; Ok(())
    }
    fn remove_round(&mut self, no: &str) { if let Some(round) = self.rounds.remove(no) { self.retained_bytes = self.retained_bytes.saturating_sub(round.retained_bytes); } }
}
fn expire_pending(map: &mut BTreeMap<Vec<u8>, (i64, SignedMessage)>, now: i64, ttl: i64, retained: &mut usize) { let expired: Vec<_> = map.iter().filter(|(_, (at, _))| now.saturating_sub(*at) > ttl).map(|(key, _)| key.clone()).collect(); for key in expired { if let Some((_, message)) = map.remove(&key) { *retained = retained.saturating_sub(message.encoded_len()); } } }

pub trait PbftPersistence {
    type Error;
    /// Atomically writes the commit and raises the block cursor to `candidate_cursor` iff it is greater.
    fn persist_atomic(&self, key: &[u8], value: &[u8], candidate_cursor: Option<i64>) -> Result<Option<i64>, Self::Error>;
}
/// C009-backed persistence. The mutex serializes cursor compare/update and StateWriteBatch commits both rows in one WAL transaction.
pub struct StatePbftPersistence { state: StateStore, transaction: Mutex<()> }
impl StatePbftPersistence { #[must_use] pub fn new(state: StateStore) -> Self { Self { state, transaction: Mutex::new(()) } } }
impl PbftPersistence for StatePbftPersistence {
    type Error = tron_storage::StorageError;
    fn persist_atomic(&self, key: &[u8], value: &[u8], candidate_cursor: Option<i64>) -> Result<Option<i64>, Self::Error> {
        let _guard = self.transaction.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let latest = self.state.store(StoreKind::Common).get(LATEST_PBFT_BLOCK_NUM_KEY).and_then(|bytes| bytes.try_into().ok()).map(i64::from_be_bytes).unwrap_or(0);
        let advanced = candidate_cursor.filter(|candidate| *candidate > latest);
        let mut batch = self.state.batch(); batch.put(&StoreKind::Pbft.name(), key, value); if let Some(cursor) = advanced { batch.put(&StoreKind::Common.name(), LATEST_PBFT_BLOCK_NUM_KEY, &cursor.to_be_bytes()); } batch.commit()?; Ok(advanced)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedCommit { pub key: Vec<u8>, pub value: Vec<u8>, pub latest_pbft_block: Option<i64> }
pub fn persist_commit<P: PbftPersistence>(store: &P, commit: &CommitData) -> Result<PersistedCommit, P::Error> {
    let mut key = commit.data_type.key_prefix().to_vec(); key.extend_from_slice(match commit.data_type { DataType::Block => commit.number, DataType::Srl => commit.epoch }.to_string().as_bytes());
    let value = PbftCommitResult { data: commit.raw.clone(), signature: commit.signatures.clone() }.encode_to_vec();
    let latest_pbft_block = store.persist_atomic(&key, &value, (commit.data_type == DataType::Block).then_some(commit.number))?;
    Ok(PersistedCommit { key, value, latest_pbft_block })
}

#[must_use] pub fn encode_srl(addresses: &[Vec<u8>]) -> Vec<u8> { Srl { sr_address: addresses.to_vec() }.encode_to_vec() }
#[must_use] pub fn preprepare_block(block_id: Vec<u8>, block_number: i64, epoch: i64, key: Option<&Secp256k1Key>) -> Result<SignedMessage, PbftError> { build_preprepare(DataType::Block, block_id, block_number, epoch, key) }
#[must_use] pub fn preprepare_srl(addresses: &[Vec<u8>], epoch: i64, key: Option<&Secp256k1Key>) -> Result<SignedMessage, PbftError> { build_preprepare(DataType::Srl, encode_srl(addresses), epoch, epoch, key) }
fn build_preprepare(data_type: DataType, data: Vec<u8>, view_n: i64, epoch: i64, key: Option<&Secp256k1Key>) -> Result<SignedMessage, PbftError> { let raw = Raw { msg_type: MsgType::Preprepare, data_type, view_n, epoch, data }; match key { Some(key) => SignedMessage::sign(raw, key), None => Ok(SignedMessage::unsigned(raw)) } }
fn vote_key(raw: &Raw, witness: &[u8]) -> Vec<u8> { let mut key = raw.no().into_bytes(); key.push(b'_'); append_hex(&mut key, witness); key }
fn append_hex(output: &mut Vec<u8>, bytes: &[u8]) { const HEX: &[u8; 16] = b"0123456789abcdef"; output.reserve(bytes.len() * 2); for byte in bytes { output.push(HEX[(byte >> 4) as usize]); output.push(HEX[(byte & 15) as usize]); } }

#[derive(Debug)]
pub enum PbftError { Malformed(String), MissingRaw, MissingSignature, UnknownMsgType(i32), UnknownDataType(i32), Crypto(tron_crypto::CryptoError), NonWitness, Equivocation, Capacity, LocalPreprepareOnly, WrongProposer, ProposalMismatch, PrepareCommitMismatch }
impl core::fmt::Display for PbftError { fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "PBFT error: {self:?}") } }
impl std::error::Error for PbftError {}
