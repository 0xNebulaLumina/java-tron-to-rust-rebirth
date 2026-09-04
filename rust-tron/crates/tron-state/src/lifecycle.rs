use core::fmt;

use tron_primitives::DigestProvider;

use crate::{build_genesis, initialize_genesis_config, CheckpointLimits, CheckpointStack, GenesisConfig, GenesisError, GenesisInit, PendingSession, SessionManager, ShutdownErrors, StateStore};

/// Runtime composition root for revoking state. It keeps lifecycle policy out of query code.
#[derive(Clone)]
pub struct StateLifecycle {
    sessions: SessionManager,
    checkpoints: CheckpointStack,
}

impl StateLifecycle {
    #[must_use]
    pub fn new(root: StateStore, limits: CheckpointLimits) -> Self {
        let sessions = SessionManager::new(root);
        let checkpoints = CheckpointStack::new(sessions.clone(), limits);
        Self { sessions, checkpoints }
    }

    #[must_use] pub fn sessions(&self) -> SessionManager { self.sessions.clone() }
    #[must_use] pub fn checkpoints(&self) -> CheckpointStack { self.checkpoints.clone() }
    pub fn pending(&self) -> Result<PendingSession, crate::SessionError> { PendingSession::new(self.sessions.clone()) }

    /// Builds and installs chain identity before speculative execution is allowed.
    pub fn initialize_genesis<D>(&self, config: &GenesisConfig, digest: &D) -> Result<GenesisInit, LifecycleGenesisError>
    where D: DigestProvider, D::Error: fmt::Display {
        if self.sessions.is_active() { return Err(LifecycleGenesisError::ActiveSessions(self.sessions.active_sessions())); }
        let genesis = build_genesis(config, digest).map_err(LifecycleGenesisError::Genesis)?;
        initialize_genesis_config(&self.sessions.root(), config, &genesis).map_err(LifecycleGenesisError::Genesis)
    }

    /// Recovers an interrupted checkpoint publication before any pending execution begins.
    pub fn recover(&self) -> Result<bool, crate::CheckpointError> { self.checkpoints.recover() }

    /// Flushes committed overlays according to policy and always attempts the backend flush.
    pub fn shutdown(&self, flush_committed: bool) -> Result<(), ShutdownErrors> {
        self.sessions.shutdown_aggregated(flush_committed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleGenesisError { ActiveSessions(usize), Genesis(GenesisError) }
impl fmt::Display for LifecycleGenesisError { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { write!(f,"runtime genesis error: {self:?}") } }
impl std::error::Error for LifecycleGenesisError {}
