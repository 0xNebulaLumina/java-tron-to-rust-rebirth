use core::fmt;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::{CheckpointIdentity, CursorError, CursorPoint, StateStore, StoreEntry, StoreKind, StoreName, StoreNameError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OverlayValue {
    Put(Vec<u8>),
    Delete,
}

#[derive(Clone, Debug, Default)]
struct OverlayLayer {
    values: BTreeMap<StoreName, BTreeMap<Vec<u8>, OverlayValue>>,
    committed: bool,
    abandoned: bool,
    disable_on_exit: bool,
    id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionError {
    Disabled,
    NoActiveSession,
    ActiveSessions(usize),
    InvalidDepth { expected: usize, actual: usize },
    InvalidSession,
    AlreadyFinalized,
    Storage(String),
    ConcurrentPending,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShutdownErrors(pub Vec<String>);

impl fmt::Display for ShutdownErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "shutdown failures: {}", self.0.join("; ")) }
}
impl std::error::Error for ShutdownErrors {}


impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => f.write_str("session manager is disabled"),
            Self::NoActiveSession => f.write_str("there is no active session"),
            Self::ActiveSessions(count) => write!(f, "operation requires no active sessions, found {count}"),
            Self::InvalidDepth { expected, actual } => write!(f, "invalid overlay depth: expected {expected}, found {actual}"),
            Self::InvalidSession => f.write_str("session is not the active top layer"),
            Self::AlreadyFinalized => f.write_str("session is already finalized"),
            Self::ConcurrentPending => f.write_str("a pending outer session is already held"),
            Self::Storage(message) => write!(f, "storage error: {message}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<tron_storage::StorageError> for SessionError {
    fn from(value: tron_storage::StorageError) -> Self { Self::Storage(value.to_string()) }
}

struct ManagerState {
    root: StateStore,
    layers: Vec<OverlayLayer>,
    checkpoints: Vec<CommittedCheckpoint>,
    enabled: bool,
    active: usize,
    next_id: u64,
    pending_outer: Option<u64>,
}

#[derive(Clone)]
pub struct SessionManager {
    state: Arc<Mutex<ManagerState>>,
}

impl SessionManager {
    #[must_use]
    pub fn new(root: StateStore) -> Self {
        Self { state: Arc::new(Mutex::new(ManagerState { root, layers: Vec::new(), checkpoints: Vec::new(), enabled: true, active: 0, next_id: 1, pending_outer: None })) }
    }

    #[must_use]
    pub(crate) fn root(&self) -> StateStore { self.lock().root.clone() }

    #[must_use]
    pub fn is_enabled(&self) -> bool { self.lock().enabled }

    pub fn enable(&self) { self.lock().enabled = true; }

    pub fn disable(&self) -> Result<(), SessionError> {
        let mut state = self.lock();
        if state.active != 0 { return Err(SessionError::ActiveSessions(state.active)); }
        state.enabled = false;
        Ok(())
    }

    #[must_use]
    pub fn active_sessions(&self) -> usize { self.lock().active }

    #[must_use]
    pub fn depth(&self) -> usize { self.lock().layers.len() }

    #[must_use]
    pub fn is_active(&self) -> bool { self.active_sessions() != 0 }

    #[must_use]
    pub fn store(&self, kind: StoreKind) -> DurableStore { self.durable_store(kind) }

    pub fn namespace(&self, name: impl Into<String>) -> Result<DurableStore, StoreNameError> {
        self.durable_namespace(name)
    }
    #[must_use]
    pub fn durable_store(&self, kind: StoreKind) -> DurableStore { DurableStore { manager: self.clone(), name: kind.name() } }

    pub fn durable_namespace(&self, name: impl Into<String>) -> Result<DurableStore, StoreNameError> {
        Ok(DurableStore { manager: self.clone(), name: StoreName::new(name)? })
    }

    /// Captures the Java HEAD logical state: the durable root plus committed,
    /// non-abandoned overlay layers. Active speculative layers remain visible
    /// only through their owning session capabilities.
    #[must_use]
    pub fn read_view(&self) -> ReadView {
        let state = self.lock();
        ReadView::capture_committed(&state.root, &state.layers)
    }

    pub fn build_session(&self) -> Result<Session, SessionError> {
        self.build_root(false)
    }

    pub fn build_session_enabled(&self) -> Result<Session, SessionError> {
        self.build_root(true)
    }

    fn build_root(&self, temporarily_enable: bool) -> Result<Session, SessionError> {
        let mut state = self.lock();
        if state.active != 0 { return Err(SessionError::ActiveSessions(state.active)); }
        if !state.enabled && !temporarily_enable {
            return Ok(Session::noop(self.clone()));
        }
        Ok(Self::push_layer(&mut state, self.clone(), temporarily_enable))
    }

    fn build_child(&self, parent_id: u64) -> Result<Session, SessionError> {
        let mut state = self.lock();
        let Some(parent) = state.layers.last() else { return Err(SessionError::InvalidSession); };
        if parent.id != parent_id || parent.committed || parent.abandoned {
            return Err(SessionError::InvalidSession);
        }
        Ok(Self::push_layer(&mut state, self.clone(), true))
    }

    fn push_layer(state: &mut ManagerState, manager: Self, temporarily_enable: bool) -> Session {
        let disable_on_exit = temporarily_enable && !state.enabled;
        if disable_on_exit { state.enabled = true; }
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1).max(1);
        state.layers.push(OverlayLayer { id, disable_on_exit, ..OverlayLayer::default() });
        state.active += 1;
        Session { manager, id: Some(id), finalized: false }
    }

    pub(crate) fn build_pending_outer(&self) -> Result<Session, SessionError> {
        let mut state = self.lock();
        if state.pending_outer.is_some() { return Err(SessionError::ConcurrentPending); }
        if state.active != 0 { return Err(SessionError::ActiveSessions(state.active)); }
        let session = Self::push_layer(&mut state, self.clone(), true);
        state.pending_outer = session.id;
        Ok(session)
    }

    pub(crate) fn reset_pending_outer(&self, outer: &mut Session) -> Result<(), SessionError> {
        if !Arc::ptr_eq(&self.state, &outer.manager.state) { return Err(SessionError::InvalidSession); }
        let Some(id) = outer.id else { return Err(SessionError::InvalidSession); };
        let mut state = self.lock();
        if outer.finalized || state.pending_outer != Some(id) { return Err(SessionError::InvalidSession); }
        let Some(index) = state.layers.iter().position(|layer| layer.id == id) else { return Err(SessionError::InvalidSession); };
        if state.layers[index].committed || state.layers[index].abandoned { return Err(SessionError::InvalidSession); }
        if state.layers[index + 1..].iter().any(|layer| !layer.committed && !layer.abandoned) {
            return Err(SessionError::ActiveSessions(state.active));
        }

        let discarded = state.layers.split_off(index);
        let discarded_active = discarded.iter().filter(|layer| !layer.committed && !layer.abandoned).count();
        state.active = state.active.checked_sub(discarded_active).ok_or(SessionError::NoActiveSession)?;
        let disable_on_exit = discarded.iter().any(|layer| layer.disable_on_exit);
        let replacement_id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1).max(1);
        state.layers.push(OverlayLayer { id: replacement_id, disable_on_exit, ..OverlayLayer::default() });
        state.active += 1;
        state.pending_outer = Some(replacement_id);
        outer.id = Some(replacement_id);
        Ok(())
    }

    pub(crate) fn release_pending_outer(&self, id: u64) {
        let mut state = self.lock();
        if state.pending_outer == Some(id) { state.pending_outer = None; }
    }
    /// Captures the current Java HEAD logical state without active speculative layers.
    #[must_use]
    pub fn session_view(&self) -> ReadView { self.read_view() }
    /// Records one immutable committed block state and links it to the current checkpoint head.
    pub fn record_checkpoint(&self, point: CursorPoint) -> Result<(), CursorError> {
        let mut state = self.lock();
        if state.active != 0 || state.layers.iter().any(|layer| !layer.committed || layer.abandoned) {
            return Err(CursorError::UncommittedState);
        }
        if state.checkpoints.iter().any(|checkpoint| checkpoint.point.identity == point.identity) {
            return Err(CursorError::IdentityMismatch);
        }
        if state.checkpoints.last().is_some_and(|head| point.block <= head.point.block) {
            return Err(CursorError::UnrelatedCheckpoint);
        }
        let parent = state.checkpoints.last().map(|checkpoint| checkpoint.point.identity);
        let view = ReadView::capture(&state.root, &state.layers);
        state.checkpoints.push(CommittedCheckpoint { point, parent, view });
        Ok(())
    }

    pub(crate) fn committed_checkpoints(&self) -> Vec<CommittedCheckpoint> { self.lock().checkpoints.clone() }

    pub(crate) fn checkpoint_state_with<T, E>(
        &self,
        operation: impl FnOnce(CheckpointState, StateStore) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<SessionError>,
    {
        let state = self.lock();
        let checkpoint = checkpoint_state(&state).map_err(E::from)?;
        operation(checkpoint, state.root.clone())
    }

    pub(crate) fn checkpoint_operation<T, E>(&self, operation: impl FnOnce(StateStore) -> Result<T, E>) -> Result<T, E> {
        let state = self.lock();
        operation(state.root.clone())
    }

    pub(crate) fn replace_checkpoint_state_from<E>(
        &self,
        load: impl FnOnce(StateStore) -> Result<CheckpointState, E>,
    ) -> Result<usize, E>
    where
        E: From<SessionError>,
    {
        let mut state = self.lock();
        if state.active != 0 { return Err(E::from(SessionError::ActiveSessions(state.active))); }
        let checkpoint = load(state.root.clone())?;
        if checkpoint.layers.iter().any(|layer| !layer.committed) { return Err(E::from(SessionError::InvalidSession)); }
        let count = checkpoint.layers.len();
        state.next_id = checkpoint.layers.iter().map(|layer| layer.id).max().unwrap_or(0).wrapping_add(1).max(1);
        state.layers = checkpoint.layers.into_iter().map(|layer| OverlayLayer { id: layer.id, committed: true, values: layer.values, abandoned: false, disable_on_exit: false }).collect();
        state.checkpoints = materialize_history(&state.root, &state.layers, checkpoint.history);
        Ok(count)
    }

    pub(crate) fn retreat_checkpoint_with<T, E>(
        &self,
        count: usize,
        operation: impl FnOnce(CheckpointState, StateStore) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<SessionError>,
    {
        let mut state = self.lock();
        let current = checkpoint_state(&state).map_err(E::from)?;
        let retained = current.layers.len().saturating_sub(count);
        let history_retained = current.history.len().saturating_sub(count);
        let checkpoint = CheckpointState {
            layers: current.layers.into_iter().take(retained).collect(),
            history: current.history.into_iter().take(history_retained).collect(),
        };
        let result = operation(checkpoint.clone(), state.root.clone())?;
        state.layers.truncate(retained);
        state.checkpoints.truncate(checkpoint.history.len());
        Ok(result)
    }


    pub fn pop(&self) -> Result<bool, SessionError> {
        let mut state = self.lock();
        if state.active != 0 { return Err(SessionError::ActiveSessions(state.active)); }
        match state.layers.last() {
            Some(layer) if layer.committed => { state.layers.pop(); Ok(true) }
            Some(_) => Err(SessionError::InvalidSession),
            None => Ok(false),
        }
    }

    pub fn fast_pop(&self) -> Result<bool, SessionError> { self.pop() }

    pub fn flush_committed(&self) -> Result<usize, SessionError> {
        let mut state = self.lock();
        if state.active != 0 { return Err(SessionError::ActiveSessions(state.active)); }
        if state.layers.iter().any(|layer| !layer.committed) { return Err(SessionError::InvalidSession); }
        let mut merged: BTreeMap<StoreName, BTreeMap<Vec<u8>, OverlayValue>> = BTreeMap::new();
        for layer in &state.layers {
            for (store, entries) in &layer.values {
                merged.entry(store.clone()).or_default().extend(entries.clone());
            }
        }
        let count = state.layers.len();
        if !merged.is_empty() {
            let mut batch = state.root.batch();
            for (store, entries) in merged {
                for (key, value) in entries {
                    match value {
                        OverlayValue::Put(value) => { batch.put(&store, &key, &value); }
                        OverlayValue::Delete => { batch.delete(&store, &key); }
                    }
                }
            }
            batch.commit()?;
        }
        state.layers.clear();
        Ok(count)
    }

    pub fn destroy(&self) -> Result<(), SessionError> {
        let mut state = self.lock();
        if state.active != 0 { return Err(SessionError::ActiveSessions(state.active)); }
        state.layers.clear();
        Ok(())
    }

    pub fn shutdown(&self, flush_committed: bool) -> Result<(), SessionError> {
        if self.active_sessions() != 0 { return Err(SessionError::ActiveSessions(self.active_sessions())); }
        if flush_committed { self.flush_committed()?; } else { self.destroy()?; }
        self.root().flush()?;
        Ok(())
    }
    /// Attempts overlay disposition and durable flush independently, preserving every failure.
    pub fn shutdown_aggregated(&self, flush_committed: bool) -> Result<(), ShutdownErrors> {
        let mut errors = Vec::new();
        let disposition = if flush_committed { self.flush_committed().map(|_| ()) } else { self.destroy() };
        if let Err(error) = disposition { errors.push(error.to_string()); }
        if let Err(error) = self.root().flush() { errors.push(error.to_string()); }
        if errors.is_empty() { Ok(()) } else { Err(ShutdownErrors(errors)) }
    }


    fn lock(&self) -> MutexGuard<'_, ManagerState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
fn checkpoint_state(state: &ManagerState) -> Result<CheckpointState, SessionError> {
    if state.active != 0 { return Err(SessionError::ActiveSessions(state.active)); }
    if state.layers.iter().any(|layer| !layer.committed || layer.abandoned) { return Err(SessionError::InvalidSession); }
    let layers: Vec<_> = state.layers.iter().map(|layer| CheckpointLayer { id: layer.id, committed: true, values: layer.values.clone() }).collect();
    let history = state.checkpoints.iter().map(|checkpoint| CheckpointHistory {
        point: checkpoint.point,
        parent: checkpoint.parent,
        image: checkpoint.view.image().clone(),
    }).collect();
    Ok(CheckpointState { layers, history })
}

fn materialize_history(_root: &StateStore, _layers: &[OverlayLayer], history: Vec<CheckpointHistory>) -> Vec<CommittedCheckpoint> {
    history.into_iter().map(|entry| CommittedCheckpoint {
        point: entry.point,
        parent: entry.parent,
        view: ReadView::from_image(entry.image),
    }).collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CheckpointState {
    pub(crate) layers: Vec<CheckpointLayer>,
    pub(crate) history: Vec<CheckpointHistory>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CheckpointLayer {
    pub(crate) id: u64,
    pub(crate) committed: bool,
    pub(crate) values: BTreeMap<StoreName, BTreeMap<Vec<u8>, OverlayValue>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CheckpointHistory {
    pub(crate) point: CursorPoint,
    pub(crate) parent: Option<CheckpointIdentity>,
    pub(crate) image: BTreeMap<StoreName, BTreeMap<Vec<u8>, Vec<u8>>>,
}

#[derive(Clone)]
pub(crate) struct CommittedCheckpoint {
    pub(crate) point: CursorPoint,
    pub(crate) parent: Option<CheckpointIdentity>,
    pub(crate) view: ReadView,
}


/// Immutable read capability backed entirely by an eagerly materialized namespace image.
#[derive(Clone)]
pub struct ReadView {
    image: Arc<BTreeMap<StoreName, BTreeMap<Vec<u8>, Vec<u8>>>>,
}

impl ReadView {
    fn capture(root: &StateStore, layers: &[OverlayLayer]) -> Self {
        Self::capture_where(root, layers, |layer| !layer.abandoned)
    }

    fn capture_committed(root: &StateStore, layers: &[OverlayLayer]) -> Self {
        Self::capture_where(root, layers, |layer| layer.committed && !layer.abandoned)
    }

    fn capture_where(root: &StateStore, layers: &[OverlayLayer], include: impl Fn(&OverlayLayer) -> bool) -> Self {
        let mut names = StoreKind::ALL.into_iter().map(StoreKind::name).collect::<Vec<_>>();
        for layer in layers.iter().filter(|layer| include(layer)) {
            for name in layer.values.keys() {
                if !names.contains(name) { names.push(name.clone()); }
            }
        }
        let mut image = root.snapshot_names(&names);
        for layer in layers.iter().filter(|layer| include(layer)) {
            for (name, values) in &layer.values {
                let rows = image.entry(name.clone()).or_default();
                for (key, value) in values {
                    match value { OverlayValue::Put(value) => { rows.insert(key.clone(), value.clone()); } OverlayValue::Delete => { rows.remove(key); } }
                }
            }
        }
        Self { image: Arc::new(image) }
    }

    fn from_image(image: BTreeMap<StoreName, BTreeMap<Vec<u8>, Vec<u8>>>) -> Self {
        Self { image: Arc::new(image) }
    }

    fn image(&self) -> &BTreeMap<StoreName, BTreeMap<Vec<u8>, Vec<u8>>> { &self.image }

    #[must_use]
    pub fn store(&self, kind: StoreKind) -> ViewStore { self.store_by_name(kind.name()) }

    pub fn namespace(&self, name: impl Into<String>) -> Result<ViewStore, StoreNameError> { Ok(self.store_by_name(StoreName::new(name)?)) }

    fn store_by_name(&self, name: StoreName) -> ViewStore { ViewStore { image: Arc::clone(&self.image), name } }
}

#[derive(Clone)]
pub struct ViewStore {
    image: Arc<BTreeMap<StoreName, BTreeMap<Vec<u8>, Vec<u8>>>>,
    name: StoreName,
}

impl ViewStore {
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> { self.image.get(&self.name).and_then(|rows| rows.get(key)).cloned() }

    #[must_use]
    pub fn prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let Some(rows) = self.image.get(&self.name) else { return Vec::new(); };
        rows.range(prefix.to_vec()..).take_while(|(key, _)| key.starts_with(prefix)).map(|(key, value)| (key.clone(), value.clone())).collect()
    }
}


#[derive(Clone)]
pub struct DurableStore {
    manager: SessionManager,
    name: StoreName,
}

impl DurableStore {
    #[must_use] pub fn name(&self) -> &StoreName { &self.name }
    #[must_use] pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let state = self.manager.lock();
        state.root.store_by_name(self.name.clone()).get(key)
    }
    #[must_use] pub fn contains_key(&self, key: &[u8]) -> bool { self.get(key).is_some() }
    #[must_use] pub fn entry(&self, key: &[u8]) -> StoreEntry { self.get(key).map_or(StoreEntry::Absent, StoreEntry::Present) }
    #[must_use] pub fn prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let state = self.manager.lock();
        state.root.store_by_name(self.name.clone()).prefix(prefix)
    }
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), SessionError> {
        let state = self.manager.lock();
        if state.active != 0 { return Err(SessionError::ActiveSessions(state.active)); }
        state.root.store_by_name(self.name.clone()).put(key, value)?;
        Ok(())
    }
    pub fn delete(&self, key: &[u8]) -> Result<(), SessionError> {
        let state = self.manager.lock();
        if state.active != 0 { return Err(SessionError::ActiveSessions(state.active)); }
        state.root.store_by_name(self.name.clone()).delete(key)?;
        Ok(())
    }
    pub fn put_if_absent(&self, key: &[u8], value: &[u8]) -> Result<bool, SessionError> {
        let state = self.manager.lock();
        if state.active != 0 { return Err(SessionError::ActiveSessions(state.active)); }
        Ok(state.root.store_by_name(self.name.clone()).put_if_absent(key, value)?)
    }
    pub fn delete_present(&self, key: &[u8]) -> Result<bool, SessionError> {
        let state = self.manager.lock();
        if state.active != 0 { return Err(SessionError::ActiveSessions(state.active)); }
        Ok(state.root.store_by_name(self.name.clone()).delete_present(key)?)
    }
}

#[derive(Clone)]
pub struct OverlayStore {
    manager: SessionManager,
    name: StoreName,
    session_id: Option<u64>,
}

impl OverlayStore {
    #[must_use]
    pub fn name(&self) -> &StoreName { &self.name }

    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let state = self.manager.lock();
        let index = self.valid_index(&state)?;
        for layer in state.layers[..=index].iter().rev() {
            if let Some(value) = layer.values.get(&self.name).and_then(|values| values.get(key)) {
                return match value { OverlayValue::Put(value) => Some(value.clone()), OverlayValue::Delete => None };
            }
        }
        state.root.store_by_name(self.name.clone()).get(key)
    }

    #[must_use]
    pub fn get_from_root(&self, key: &[u8]) -> Option<Vec<u8>> {
        let state = self.manager.lock();
        self.valid_index(&state)?;
        state.root.store_by_name(self.name.clone()).get(key)
    }

    #[must_use]
    pub fn entry(&self, key: &[u8]) -> StoreEntry { self.get(key).map_or(StoreEntry::Absent, StoreEntry::Present) }

    #[must_use]
    pub fn contains_key(&self, key: &[u8]) -> bool { self.get(key).is_some() }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), SessionError> {
        self.mutate(key, OverlayValue::Put(value.to_vec()))
    }

    pub fn delete(&self, key: &[u8]) -> Result<(), SessionError> {
        self.mutate(key, OverlayValue::Delete)
    }

    fn mutate(&self, key: &[u8], value: OverlayValue) -> Result<(), SessionError> {
        let mut state = self.manager.lock();
        let index = self.valid_index(&state).ok_or(SessionError::InvalidSession)?;
        state.layers[index].values.entry(self.name.clone()).or_default().insert(key.to_vec(), value);
        Ok(())
    }

    fn valid_index(&self, state: &ManagerState) -> Option<usize> {
        let id = self.session_id?;
        let index = state.layers.iter().position(|layer| layer.id == id)?;
        let layer = &state.layers[index];
        (index + 1 == state.layers.len() && !layer.committed && !layer.abandoned).then_some(index)
    }

    #[must_use]
    pub fn view(&self) -> Vec<(Vec<u8>, Vec<u8>)> { self.prefix(&[]) }
    #[must_use]
    pub fn iterator(&self) -> Vec<(Vec<u8>, Vec<u8>)> { self.view() }

    #[must_use]
    pub fn get_next(&self, start: &[u8], limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.view().into_iter().filter(|(key, _)| key.as_slice() >= start).take(limit).collect()
    }

    #[must_use]
    pub fn root_view(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let state = self.manager.lock();
        if self.valid_index(&state).is_none() { return Vec::new(); }
        state.root.store_by_name(self.name.clone()).prefix(&[])
    }

    #[must_use]
    pub fn prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let state = self.manager.lock();
        let Some(index) = self.valid_index(&state) else { return Vec::new(); };
        let mut rows: BTreeMap<Vec<u8>, Vec<u8>> = state.root.store_by_name(self.name.clone()).prefix(prefix).into_iter().collect();
        for layer in &state.layers[..=index] {
            if let Some(values) = layer.values.get(&self.name) {
                for (key, value) in values.range(prefix.to_vec()..) {
                    if !key.starts_with(prefix) { break; }
                    match value { OverlayValue::Put(value) => { rows.insert(key.clone(), value.clone()); } OverlayValue::Delete => { rows.remove(key); } }
                }
            }
        }
        rows.into_iter().collect()
    }

    #[must_use]
    pub fn prefix_query(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> { self.prefix(prefix) }
}

pub struct Session {
    manager: SessionManager,
    id: Option<u64>,
    finalized: bool,
}

impl Session {
    fn noop(manager: SessionManager) -> Self { Self { manager, id: None, finalized: false } }

    #[must_use]
    pub fn is_noop(&self) -> bool { self.id.is_none() }

    #[must_use]
    pub fn is_active(&self) -> bool { !self.finalized && self.id.is_some() }

    pub fn commit(&mut self) -> Result<(), SessionError> { self.finish(Finish::Commit) }
    #[must_use]
    pub(crate) fn identity(&self) -> Option<u64> { self.id }
    pub fn child(&self) -> Result<Session, SessionError> {
        if self.finalized { return Err(SessionError::InvalidSession); }
        let id = self.id.ok_or(SessionError::InvalidSession)?;
        self.manager.build_child(id)
    }
    pub fn merge(&mut self) -> Result<(), SessionError> { self.finish(Finish::Merge) }
    pub fn revoke(&mut self) -> Result<(), SessionError> { self.finish(Finish::Revoke) }
    pub fn destroy(&mut self) -> Result<(), SessionError> { self.revoke() }
    #[must_use]
    pub fn view(&self) -> ReadView {
        let state = self.manager.lock();
        let layers = self.id.and_then(|id| state.layers.iter().position(|layer| layer.id == id))
            .map_or(&state.layers[..0], |index| &state.layers[..=index]);
        ReadView::capture(&state.root, layers)
    }

    #[must_use]
    pub fn store(&self, kind: StoreKind) -> OverlayStore {
        OverlayStore { manager: self.manager.clone(), name: kind.name(), session_id: self.id }
    }

    #[must_use]
    pub fn manager(&self) -> SessionManager { self.manager.clone() }

    pub fn close(&mut self) -> Result<(), SessionError> {
        if self.finalized { return Ok(()); }
        let Some(id) = self.id else {
            self.finalized = true;
            return Ok(());
        };
        let mut state = self.manager.lock();
        let Some(index) = state.layers.iter().position(|layer| layer.id == id) else {
            self.finalized = true;
            return Err(SessionError::InvalidSession);
        };
        if state.layers[index + 1..].iter().any(|layer| !layer.committed && !layer.abandoned) {
            state.layers[index].abandoned = true;
            state.active = state.active.checked_sub(1).ok_or(SessionError::NoActiveSession)?;
            self.finalized = true;
            return Err(SessionError::InvalidSession);
        }
        drop(state);
        self.finish(Finish::Revoke)
    }

    fn finish(&mut self, finish: Finish) -> Result<(), SessionError> {
        if self.finalized { return Ok(()); }
        let Some(id) = self.id else {
            self.finalized = true;
            return Ok(());
        };
        let mut state = self.manager.lock();
        let Some(index) = state.layers.iter().position(|layer| layer.id == id) else {
            self.finalized = true;
            return Err(SessionError::InvalidSession);
        };
        if state.layers[index].committed || state.layers[index].abandoned {
            return Err(SessionError::InvalidSession);
        }
        let actual = state.layers.len();
        let descendants_committed = state.layers[index + 1..].iter().all(|layer| layer.committed && !layer.abandoned);
        if !matches!(finish, Finish::Revoke) && !descendants_committed {
            return Err(SessionError::InvalidSession);
        }

        let mut disable_on_exit = state.layers[index].disable_on_exit;
        match finish {
            Finish::Commit => state.layers[index].committed = true,
            Finish::Merge => {
                if index == 0 { return Err(SessionError::InvalidDepth { expected: 2, actual }); }
                let descendants = state.layers.split_off(index);
                let predecessor = state.layers.last_mut().expect("predecessor checked");
                for layer in descendants {
                    disable_on_exit |= layer.disable_on_exit;
                    for (store, entries) in layer.values {
                        predecessor.values.entry(store).or_default().extend(entries);
                    }
                }
            }
            Finish::Revoke => {
                let discarded = state.layers.split_off(index);
                let discarded_active = discarded.iter().filter(|layer| !layer.committed && !layer.abandoned).count();
                disable_on_exit |= discarded.iter().any(|layer| layer.disable_on_exit);
                state.active = state.active.checked_sub(discarded_active).ok_or(SessionError::NoActiveSession)?;
            }
        }
        if !matches!(finish, Finish::Revoke) {
            state.active = state.active.checked_sub(1).ok_or(SessionError::NoActiveSession)?;
        }
        if let Some(abandoned_index) = state.layers.iter().position(|layer| layer.abandoned) {
            let abandoned = state.layers.split_off(abandoned_index);
            let abandoned_active = abandoned.iter().filter(|layer| !layer.committed && !layer.abandoned).count();
            state.active = state.active.checked_sub(abandoned_active).ok_or(SessionError::NoActiveSession)?;
            disable_on_exit |= abandoned.iter().any(|layer| layer.disable_on_exit);
        }
        if disable_on_exit { state.enabled = false; }
        self.finalized = true;
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) { let _ = self.close(); }
}

enum Finish { Commit, Merge, Revoke }
