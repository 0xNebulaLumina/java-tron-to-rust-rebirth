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
    /// Reconstructs HEAD, SOLIDITY, and PBFT exclusively from durable markers and checkpoint
    /// history. Missing or malformed markers are errors; no synthetic genesis fallback is used.
    pub fn reconstruct(manager: &SessionManager) -> Result<Self, CursorError> {
        let dynamic = manager.durable_store(StoreKind::DynamicProperties);
        let common = manager.durable_store(StoreKind::Common);
        let number = marker_i64(dynamic.get(crate::dynamic::key("LATEST_BLOCK_HEADER_NUMBER").expect("known key")))?;
        let head_block = u64::try_from(number).map_err(|_| CursorError::IdentityMismatch)?;
        let head_hash = dynamic.get(crate::dynamic::key("LATEST_BLOCK_HEADER_HASH").expect("known key")).ok_or(CursorError::MissingCheckpoint)?;
        let head_identity = CheckpointIdentity::new(head_hash.as_slice().try_into().map_err(|_| CursorError::IdentityMismatch)?);
        let history = manager.checkpoint_points();
        let head = unique_point(&history, head_block)?.ok_or(CursorError::MissingCheckpoint)?;
        if head.identity != head_identity { return Err(CursorError::IdentityMismatch); }

        let solidity_block = u64::try_from(marker_i64(dynamic.get(crate::dynamic::key("LATEST_SOLIDIFIED_BLOCK_NUM").expect("known key")))?)
            .map_err(|_| CursorError::IdentityMismatch)?;
        let solidity = unique_point(&history, solidity_block)?.ok_or(CursorError::MissingCheckpoint)?;
        let pbft = match common.get(b"LATEST_PBFT_BLOCK_NUM") {
            None => None,
            Some(bytes) => {
                let block = u64::try_from(marker_i64(Some(bytes))?).map_err(|_| CursorError::IdentityMismatch)?;
                Some(unique_point(&history, block)?.ok_or(CursorError::MissingCheckpoint)?)
            }
        };
        let pbft_offset = pbft.map_or(0, |point| {
            let head_index = history.iter().position(|candidate| *candidate == head).expect("resolved head");
            let pbft_index = history.iter().position(|candidate| *candidate == point).expect("resolved PBFT");
            head_index.saturating_sub(pbft_index) as i64
        });
        Self::new(manager, head, Some(solidity), pbft, pbft_offset)
    }
    /// Publishes the current durable/committed image as SOLIDITY at the latest block checkpoint.
    /// This is used after standalone replication writes its solid marker after verified apply.
    pub fn with_live_solidity(manager: &SessionManager, point: CursorPoint) -> Result<Self, CursorError> {
        let mut cursors = Self::new(manager, point, Some(point), None, 0)?;
        cursors.solidity = SolidityCursor { point, view: manager.read_view() };
        Ok(cursors)
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


fn marker_i64(value: Option<Vec<u8>>) -> Result<i64, CursorError> {
    let bytes = value.ok_or(CursorError::MissingCheckpoint)?;
    Ok(i64::from_be_bytes(bytes.as_slice().try_into().map_err(|_| CursorError::IdentityMismatch)?))
}

fn unique_point(history: &[CursorPoint], block: u64) -> Result<Option<CursorPoint>, CursorError> {
    let mut matching = history.iter().copied().filter(|point| point.block == block);
    let first = matching.next();
    if matching.next().is_some() { return Err(CursorError::IdentityMismatch); }
    Ok(first)
}
