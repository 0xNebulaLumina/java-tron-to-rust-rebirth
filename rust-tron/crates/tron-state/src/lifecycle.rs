use crate::{CheckpointLimits, CheckpointStack, PendingSession, SessionManager, ShutdownErrors, StateStore};

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

    /// Recovers an interrupted checkpoint publication before any pending execution begins.
    pub fn recover(&self) -> Result<bool, crate::CheckpointError> { self.checkpoints.recover() }

    /// Flushes committed overlays according to policy and always attempts the backend flush.
    pub fn shutdown(&self, flush_committed: bool) -> Result<(), ShutdownErrors> {
        self.sessions.shutdown_aggregated(flush_committed)
    }
}
