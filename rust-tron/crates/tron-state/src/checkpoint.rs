use core::fmt;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use tron_crypto::{selected_digest, CryptoEngine};

use crate::session::{CheckpointHistory, CheckpointLayer, CheckpointState};
use crate::{CursorError, CursorPoint, OverlayValue, SessionError, SessionManager, StoreName};

const MAGIC: &[u8; 8] = b"TSTKCP02";
const JOURNAL_KEY: &[u8] = b"stack/journal";
const STAGED_KEY: &[u8] = b"stack/staged";
const CURRENT_KEY: &[u8] = b"stack/current";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointLimits { pub max_stack: usize, pub max_flush_count: usize, pub max_bytes: usize }
impl Default for CheckpointLimits {
    fn default() -> Self { Self { max_stack: 256, max_flush_count: 64, max_bytes: 64 * 1024 * 1024 } }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointCrashPhase { BeforeStage, AfterStage, BeforePublish, AfterPublish }
pub trait CheckpointCrashInjector { fn after(&self, phase: CheckpointCrashPhase) -> Result<(), CheckpointError>; }
pub struct NoCheckpointCrash;
impl CheckpointCrashInjector for NoCheckpointCrash { fn after(&self, _: CheckpointCrashPhase) -> Result<(), CheckpointError> { Ok(()) } }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckpointError { Session(SessionError), Cursor(CursorError), Corrupt(&'static str), Limit(&'static str), Crash(CheckpointCrashPhase), Storage(String) }
impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "checkpoint error: {self:?}") }
}
impl std::error::Error for CheckpointError {}
impl From<SessionError> for CheckpointError { fn from(value: SessionError) -> Self { Self::Session(value) } }
impl From<CursorError> for CheckpointError { fn from(value: CursorError) -> Self { Self::Cursor(value) } }
impl From<tron_storage::StorageError> for CheckpointError { fn from(value: tron_storage::StorageError) -> Self { Self::Storage(value.to_string()) } }

#[derive(Clone)]
pub struct CheckpointStack { manager: SessionManager, limits: CheckpointLimits }
impl CheckpointStack {
    #[must_use] pub fn new(manager: SessionManager, limits: CheckpointLimits) -> Self { Self { manager, limits } }
    #[must_use] pub fn len(&self) -> usize { self.manager.depth() }

    /// Attaches block identity to the current committed state before publication.
    pub fn record(&self, point: CursorPoint) -> Result<(), CheckpointError> {
        self.manager.record_checkpoint(point)?;
        Ok(())
    }

    pub fn persist(&self) -> Result<usize, CheckpointError> { self.persist_with(&NoCheckpointCrash) }
    pub fn persist_with(&self, faults: &dyn CheckpointCrashInjector) -> Result<usize, CheckpointError> {
        self.manager.checkpoint_state_with(|checkpoint, root| self.publish(checkpoint, root, faults))
    }

    fn publish(&self, checkpoint: CheckpointState, root: crate::StateStore, faults: &dyn CheckpointCrashInjector) -> Result<usize, CheckpointError> {
        if checkpoint.layers.len() > self.limits.max_stack { return Err(CheckpointError::Limit("maximum checkpoint stack exceeded")); }
        let count = checkpoint.layers.len();
        let encoded = encode(&checkpoint, self.limits)?;
        faults.after(CheckpointCrashPhase::BeforeStage)?;
        let store = root.checkpoint_metadata();
        let mut stage = store.batch();
        stage.put(STAGED_KEY, &encoded).put(JOURNAL_KEY, &selected_digest(CryptoEngine::Secp256k1, &encoded));
        stage.commit()?;
        faults.after(CheckpointCrashPhase::AfterStage)?;
        faults.after(CheckpointCrashPhase::BeforePublish)?;
        let mut publish = store.batch();
        publish.put(CURRENT_KEY, &encoded).delete(STAGED_KEY).delete(JOURNAL_KEY);
        publish.commit()?;
        faults.after(CheckpointCrashPhase::AfterPublish)?;
        Ok(count)
    }

    pub fn recover(&self) -> Result<bool, CheckpointError> {
        self.manager.checkpoint_operation(|root| recover_store(&root, self.limits))
    }

    pub fn relink(&self) -> Result<usize, CheckpointError> {
        self.manager.replace_checkpoint_state_from(|root| {
            recover_store(&root, self.limits)?;
            let store = root.checkpoint_metadata();
            let encoded = store.get(CURRENT_KEY).ok_or(CheckpointError::Corrupt("missing current checkpoint"))?;
            decode(&encoded, self.limits)
        })
    }

    pub fn retreat(&self, count: usize) -> Result<usize, CheckpointError> { self.retreat_with(count, &NoCheckpointCrash) }

    pub fn retreat_with(&self, count: usize, faults: &dyn CheckpointCrashInjector) -> Result<usize, CheckpointError> {
        if count > self.limits.max_flush_count { return Err(CheckpointError::Limit("maximum retreat count exceeded")); }
        self.manager.retreat_checkpoint_with(count, |checkpoint, root| self.publish(checkpoint, root, faults))
    }

    pub fn flush_bounded(&self) -> Result<usize, CheckpointError> {
        let depth = self.manager.depth();
        if depth > self.limits.max_flush_count { return Err(CheckpointError::Limit("maximum flush count exceeded")); }
        Ok(self.manager.flush_committed()?)
    }
}

fn recover_store(root: &crate::StateStore, limits: CheckpointLimits) -> Result<bool, CheckpointError> {
    let store = root.checkpoint_metadata();
    let Some(expected) = store.get(JOURNAL_KEY) else { return Ok(false) };
    let staged = store.get(STAGED_KEY).ok_or(CheckpointError::Corrupt("journal without staged stack"))?;
    if expected.as_slice() != selected_digest(CryptoEngine::Secp256k1, &staged) { return Err(CheckpointError::Corrupt("staged checksum mismatch")); }
    decode(&staged, limits)?;
    let mut batch = store.batch();
    batch.put(CURRENT_KEY, &staged).delete(STAGED_KEY).delete(JOURNAL_KEY);
    batch.commit()?;
    Ok(true)
}

const ENVELOPE_BYTES: usize = MAGIC.len() + 32;
const MIN_LAYER_BYTES: usize = 8 + 1 + 4;
const MIN_ENTRY_BYTES: usize = 4 + 4 + 1;
const MIN_HISTORY_BYTES: usize = 32 + 8 + 1 + 4;

fn encode(checkpoint: &CheckpointState, limits: CheckpointLimits) -> Result<Vec<u8>, CheckpointError> {
    if checkpoint.layers.len() > limits.max_stack || checkpoint.history.len() > limits.max_stack {
        return Err(CheckpointError::Limit("maximum checkpoint stack exceeded"));
    }
    let mut body_bytes = 4usize;
    for layer in &checkpoint.layers {
        body_bytes = checked_add(body_bytes, MIN_LAYER_BYTES)?;
        let mut entries = 0usize;
        for (store, values) in &layer.values {
            for (key, value) in values {
                entries = entries.checked_add(1).ok_or(CheckpointError::Limit("checkpoint bytes exceeded"))?;
                body_bytes = checked_sized_bytes(body_bytes, store.as_str().len())?;
                body_bytes = checked_sized_bytes(body_bytes, key.len())?;
                body_bytes = checked_add(body_bytes, 1)?;
                if let OverlayValue::Put(value) = value { body_bytes = checked_sized_bytes(body_bytes, value.len())?; }
            }
        }
        u32::try_from(entries).map_err(|_| CheckpointError::Limit("checkpoint collection count exceeded"))?;
    }
    body_bytes = checked_add(body_bytes, 4)?;
    for entry in &checkpoint.history {
        body_bytes = checked_add(body_bytes, MIN_HISTORY_BYTES)?;
        if entry.parent.is_some() { body_bytes = checked_add(body_bytes, 32)?; }
        u32::try_from(entry.image.len()).map_err(|_| CheckpointError::Limit("checkpoint collection count exceeded"))?;
        for (store, rows) in &entry.image {
            body_bytes = checked_sized_bytes(body_bytes, store.as_str().len())?;
            body_bytes = checked_add(body_bytes, 4)?;
            u32::try_from(rows.len()).map_err(|_| CheckpointError::Limit("checkpoint collection count exceeded"))?;
            for (key, value) in rows {
                body_bytes = checked_sized_bytes(body_bytes, key.len())?;
                body_bytes = checked_sized_bytes(body_bytes, value.len())?;
            }
        }
    }
    let encoded_bytes = checked_add(ENVELOPE_BYTES, body_bytes)?;
    if encoded_bytes > limits.max_bytes { return Err(CheckpointError::Limit("checkpoint bytes exceeded")); }

    let layer_count = u32::try_from(checkpoint.layers.len()).map_err(|_| CheckpointError::Limit("checkpoint collection count exceeded"))?;
    let history_count = u32::try_from(checkpoint.history.len()).map_err(|_| CheckpointError::Limit("checkpoint collection count exceeded"))?;
    let mut body = Vec::with_capacity(body_bytes);
    body.extend_from_slice(&layer_count.to_be_bytes());
    for layer in &checkpoint.layers {
        body.extend_from_slice(&layer.id.to_be_bytes());
        body.push(u8::from(layer.committed));
        let entries = layer.values.values().try_fold(0usize, |count, values| count.checked_add(values.len()).ok_or(CheckpointError::Limit("checkpoint collection count exceeded")))?;
        body.extend_from_slice(&u32::try_from(entries).map_err(|_| CheckpointError::Limit("checkpoint collection count exceeded"))?.to_be_bytes());
        for (store, values) in &layer.values { for (key, value) in values {
            put_bytes(&mut body, store.as_str().as_bytes())?;
            put_bytes(&mut body, key)?;
            match value { OverlayValue::Put(value) => { body.push(1); put_bytes(&mut body, value)?; }, OverlayValue::Delete => body.push(0) }
        }}
    }
    body.extend_from_slice(&history_count.to_be_bytes());
    for entry in &checkpoint.history {
        body.extend_from_slice(&entry.point.identity.bytes());
        body.extend_from_slice(&entry.point.block.to_be_bytes());
        match entry.parent { Some(parent) => { body.push(1); body.extend_from_slice(&parent.bytes()); }, None => body.push(0) }
        body.extend_from_slice(&u32::try_from(entry.image.len()).map_err(|_| CheckpointError::Limit("checkpoint collection count exceeded"))?.to_be_bytes());
        for (store, rows) in &entry.image {
            put_bytes(&mut body, store.as_str().as_bytes())?;
            body.extend_from_slice(&u32::try_from(rows.len()).map_err(|_| CheckpointError::Limit("checkpoint collection count exceeded"))?.to_be_bytes());
            for (key, value) in rows {
                put_bytes(&mut body, key)?;
                put_bytes(&mut body, value)?;
            }
        }
    }
    debug_assert_eq!(body.len(), body_bytes);
    let mut output = Vec::with_capacity(encoded_bytes);
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&body);
    output.extend_from_slice(&selected_digest(CryptoEngine::Secp256k1, &body));
    Ok(output)
}

fn checked_add(current: usize, added: usize) -> Result<usize, CheckpointError> {
    current.checked_add(added).ok_or(CheckpointError::Limit("checkpoint bytes exceeded"))
}

fn checked_sized_bytes(current: usize, length: usize) -> Result<usize, CheckpointError> {
    u32::try_from(length).map_err(|_| CheckpointError::Limit("checkpoint byte string exceeded"))?;
    checked_add(checked_add(current, 4)?, length)
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), CheckpointError> {
    let length = u32::try_from(value.len()).map_err(|_| CheckpointError::Limit("checkpoint byte string exceeded"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn decode(encoded: &[u8], limits: CheckpointLimits) -> Result<CheckpointState, CheckpointError> {
    if encoded.len() > limits.max_bytes || encoded.len() < ENVELOPE_BYTES + 8 || &encoded[..MAGIC.len()] != MAGIC { return Err(CheckpointError::Corrupt("invalid checkpoint envelope")); }
    let (body, checksum) = encoded[MAGIC.len()..].split_at(encoded.len() - ENVELOPE_BYTES);
    if checksum != selected_digest(CryptoEngine::Secp256k1, body) { return Err(CheckpointError::Corrupt("checkpoint checksum mismatch")); }
    let mut input = body;
    let count = checked_collection_count(take_u32(&mut input)?, limits.max_stack, input.len(), MIN_LAYER_BYTES, "maximum checkpoint stack exceeded")?;
    let mut layer_ids = BTreeSet::new();
    let mut layers = Vec::with_capacity(count);
    for _ in 0..count {
        let id = take_u64(&mut input)?; let committed = take(&mut input, 1)?[0] != 0;
        let entries = checked_collection_count(take_u32(&mut input)?, usize::MAX, input.len(), MIN_ENTRY_BYTES, "checkpoint entry count exceeds remaining bytes")?;
        if !committed { return Err(CheckpointError::Corrupt("uncommitted checkpoint layer")); }
        if !layer_ids.insert(id) { return Err(CheckpointError::Corrupt("duplicate checkpoint layer")); }
        let mut values = BTreeMap::new();
        for _ in 0..entries {
            let store = StoreName::new(String::from_utf8(take_bytes(&mut input)?.to_vec()).map_err(|_| CheckpointError::Corrupt("invalid store name"))?).map_err(|_| CheckpointError::Corrupt("invalid store name"))?;
            let key = take_bytes(&mut input)?.to_vec(); let tag = take(&mut input, 1)?[0];
            let value = match tag { 0 => OverlayValue::Delete, 1 => OverlayValue::Put(take_bytes(&mut input)?.to_vec()), _ => return Err(CheckpointError::Corrupt("invalid value tag")) };
            if values.entry(store).or_insert_with(BTreeMap::new).insert(key, value).is_some() { return Err(CheckpointError::Corrupt("duplicate checkpoint entry")); }
        }
        layers.push(CheckpointLayer { id, committed, values });
    }
    let history_count = checked_collection_count(take_u32(&mut input)?, limits.max_stack, input.len(), MIN_HISTORY_BYTES, "maximum checkpoint history exceeded")?;
    let mut identities = HashSet::with_capacity(history_count);
    let mut history: Vec<CheckpointHistory> = Vec::with_capacity(history_count);
    for _ in 0..history_count {
        let identity = crate::CheckpointIdentity::new(take(&mut input, 32)?.try_into().expect("length checked"));
        let block = take_u64(&mut input)?;
        let parent = match take(&mut input, 1)?[0] { 0 => None, 1 => Some(crate::CheckpointIdentity::new(take(&mut input, 32)?.try_into().expect("length checked"))), _ => return Err(CheckpointError::Corrupt("invalid checkpoint parent tag")) };
        let store_count = checked_collection_count(take_u32(&mut input)?, usize::MAX, input.len(), 8, "checkpoint snapshot store count exceeds remaining bytes")?;
        let mut image = BTreeMap::new();
        for _ in 0..store_count {
            let store = StoreName::new(String::from_utf8(take_bytes(&mut input)?.to_vec()).map_err(|_| CheckpointError::Corrupt("invalid store name"))?).map_err(|_| CheckpointError::Corrupt("invalid store name"))?;
            let row_count = checked_collection_count(take_u32(&mut input)?, usize::MAX, input.len(), 8, "checkpoint snapshot row count exceeds remaining bytes")?;
            let mut rows = BTreeMap::new();
            for _ in 0..row_count {
                let key = take_bytes(&mut input)?.to_vec();
                let value = take_bytes(&mut input)?.to_vec();
                if rows.insert(key, value).is_some() { return Err(CheckpointError::Corrupt("duplicate checkpoint snapshot entry")); }
            }
            if image.insert(store, rows).is_some() { return Err(CheckpointError::Corrupt("duplicate checkpoint snapshot store")); }
        }
        if !identities.insert(identity) { return Err(CheckpointError::Corrupt("duplicate checkpoint identity")); }
        if history.last().is_some_and(|previous| parent != Some(previous.point.identity) || block <= previous.point.block) { return Err(CheckpointError::Corrupt("invalid checkpoint ancestry")); }
        if history.is_empty() && parent.is_some() { return Err(CheckpointError::Corrupt("invalid checkpoint ancestry")); }
        history.push(CheckpointHistory { point: CursorPoint { block, identity }, parent, image });
    }
    if !input.is_empty() { return Err(CheckpointError::Corrupt("trailing checkpoint bytes")); }
    Ok(CheckpointState { layers, history })
}

fn checked_collection_count(count: u32, policy_max: usize, remaining: usize, min_bytes: usize, error: &'static str) -> Result<usize, CheckpointError> {
    let count = usize::try_from(count).map_err(|_| CheckpointError::Limit(error))?;
    if count > policy_max || count > remaining / min_bytes { return Err(CheckpointError::Limit(error)); }
    Ok(count)
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], CheckpointError> { if input.len() < count { return Err(CheckpointError::Corrupt("truncated checkpoint")); } let (head, tail) = input.split_at(count); *input = tail; Ok(head) }
fn take_u32(input: &mut &[u8]) -> Result<u32, CheckpointError> { Ok(u32::from_be_bytes(take(input, 4)?.try_into().expect("length checked"))) }
fn take_u64(input: &mut &[u8]) -> Result<u64, CheckpointError> { Ok(u64::from_be_bytes(take(input, 8)?.try_into().expect("length checked"))) }
fn take_bytes<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], CheckpointError> { let length = take_u32(input)? as usize; take(input, length) }
