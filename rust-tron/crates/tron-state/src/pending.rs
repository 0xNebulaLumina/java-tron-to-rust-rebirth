use crate::{ReadView, Session, SessionError, SessionManager, StoreKind, OverlayStore};

/// Owns the outer speculative layer for pending block execution.
/// Child work is merged into the outer layer only on explicit success.
pub struct PendingSession {
    manager: SessionManager,
    outer: Option<Session>,
}

impl PendingSession {
    pub fn new(manager: SessionManager) -> Result<Self, SessionError> {
        let outer = manager.build_pending_outer()?;
        Ok(Self { manager, outer: Some(outer) })
    }

    #[must_use] pub fn view(&self) -> ReadView {
        self.outer.as_ref().expect("pending session is closed").view()
    }
    #[must_use] pub fn store(&self, kind: StoreKind) -> OverlayStore {
        self.outer.as_ref().expect("pending session is closed").store(kind)
    }
    pub fn child(&self) -> Result<Session, SessionError> {
        self.outer.as_ref().ok_or(SessionError::InvalidSession)?.child()
    }

    pub fn merge_child(&self, child: &mut Session) -> Result<(), SessionError> { child.merge() }

    /// Revokes all child layers and replaces the outer layer with a fresh empty one.
    pub fn reset(&mut self) -> Result<(), SessionError> {
        let outer = self.outer.as_mut().ok_or(SessionError::InvalidSession)?;
        self.manager.reset_pending_outer(outer)
    }

    /// Converts the held pending layer into a committed checkpoint layer.
    pub fn commit(&mut self) -> Result<(), SessionError> {
        let outer = self.outer.as_mut().ok_or(SessionError::InvalidSession)?;
        let id = outer.identity().ok_or(SessionError::InvalidSession)?;
        outer.commit()?;
        self.manager.release_pending_outer(id);
        self.outer.take();
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), SessionError> {
        let Some(outer) = self.outer.as_mut() else { return Ok(()); };
        let id = outer.identity().ok_or(SessionError::InvalidSession)?;
        outer.revoke()?;
        self.manager.release_pending_outer(id);
        self.outer.take();
        Ok(())
    }
}

impl Drop for PendingSession { fn drop(&mut self) { let _ = self.close(); } }
