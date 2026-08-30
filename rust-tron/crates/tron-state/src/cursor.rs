use core::fmt;

use crate::{ReadView, SessionManager, StoreKind, ViewStore};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CheckpointIdentity([u8; 32]);
impl CheckpointIdentity { #[must_use] pub const fn new(value: [u8; 32]) -> Self { Self(value) } #[must_use] pub const fn bytes(self) -> [u8; 32] { self.0 } }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CursorPoint { pub block: u64, pub identity: CheckpointIdentity }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CursorError {
    NegativePbftOffset(i64),
    IdentityMismatch,
    UnrelatedCheckpoint,
    UncommittedState,
    MissingCheckpoint,
    BeyondHead { requested: u64, head: u64 },
}
impl fmt::Display for CursorError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "cursor error: {self:?}") } }
impl std::error::Error for CursorError {}

pub trait CursorView: Clone {
    fn point(&self) -> CursorPoint;
    fn store(&self, kind: StoreKind) -> ViewStore;
}

macro_rules! cursor {
    ($name:ident) => {
        #[derive(Clone)]
        pub struct $name { point: CursorPoint, view: ReadView }
        impl CursorView for $name {
            fn point(&self) -> CursorPoint { self.point }
            fn store(&self, kind: StoreKind) -> ViewStore { self.view.store(kind) }
        }
    };
}
cursor!(HeadCursor);
cursor!(SolidityCursor);
cursor!(PbftCursor);

#[derive(Clone)]
pub struct CursorSet { head: HeadCursor, solidity: SolidityCursor, pbft: PbftCursor, pbft_offset: u64 }
impl CursorSet {
    pub fn new(manager: &SessionManager, head: CursorPoint, solidity: Option<CursorPoint>, pbft: Option<CursorPoint>, pbft_offset: i64) -> Result<Self, CursorError> {
        let history = manager.committed_checkpoints();
        let committed_head = history.last().ok_or(CursorError::MissingCheckpoint)?;
        if committed_head.point != head { return Err(CursorError::IdentityMismatch); }

        let solidity = resolve(&history, solidity.unwrap_or(head), committed_head.point.identity)?;
        if pbft_offset < 0 { return Err(CursorError::NegativePbftOffset(pbft_offset)); }
        let (pbft, effective_offset) = if pbft.is_none() {
            (solidity.clone(), 0)
        } else {
            let resolved = ancestor_at(&history, committed_head.point.identity, pbft_offset as u64)?;
            let expected = pbft.expect("checked above");
            if resolved.point != expected { return Err(CursorError::IdentityMismatch); }
            (resolved, pbft_offset as u64)
        };
        Ok(Self {
            head: HeadCursor { point: committed_head.point, view: committed_head.view.clone() },
            solidity: SolidityCursor { point: solidity.point, view: solidity.view.clone() },
            pbft: PbftCursor { point: pbft.point, view: pbft.view.clone() },
            pbft_offset: effective_offset,
        })
    }
    #[must_use] pub fn head(&self) -> HeadCursor { self.head.clone() }
    #[must_use] pub fn solidity(&self) -> SolidityCursor { self.solidity.clone() }
    #[must_use] pub fn pbft(&self) -> PbftCursor { self.pbft.clone() }
    #[must_use] pub const fn pbft_offset(&self) -> u64 { self.pbft_offset }

    pub fn validate_identity(&self, identity: CheckpointIdentity) -> Result<(), CursorError> {
        if self.head.point.identity != identity { return Err(CursorError::IdentityMismatch); }
        Ok(())
    }
}

fn resolve(history: &[crate::session::CommittedCheckpoint], point: CursorPoint, head: CheckpointIdentity) -> Result<crate::session::CommittedCheckpoint, CursorError> {
    let checkpoint = history.iter().find(|checkpoint| checkpoint.point.identity == point.identity).ok_or(CursorError::UnrelatedCheckpoint)?;
    if checkpoint.point != point { return Err(CursorError::IdentityMismatch); }
    if !is_ancestor(history, checkpoint.point.identity, head) { return Err(CursorError::UnrelatedCheckpoint); }
    Ok(checkpoint.clone())
}

fn ancestor_at(history: &[crate::session::CommittedCheckpoint], mut identity: CheckpointIdentity, offset: u64) -> Result<crate::session::CommittedCheckpoint, CursorError> {
    let mut current = history.iter().find(|checkpoint| checkpoint.point.identity == identity).ok_or(CursorError::UnrelatedCheckpoint)?;
    for _ in 0..offset {
        let Some(parent) = current.parent else { break };
        identity = parent;
        current = history.iter().find(|checkpoint| checkpoint.point.identity == identity).ok_or(CursorError::UnrelatedCheckpoint)?;
    }
    Ok(current.clone())
}

fn is_ancestor(history: &[crate::session::CommittedCheckpoint], ancestor: CheckpointIdentity, mut descendant: CheckpointIdentity) -> bool {
    loop {
        if ancestor == descendant { return true; }
        let Some(checkpoint) = history.iter().find(|checkpoint| checkpoint.point.identity == descendant) else { return false };
        let Some(parent) = checkpoint.parent else { return false };
        descendant = parent;
    }
}

