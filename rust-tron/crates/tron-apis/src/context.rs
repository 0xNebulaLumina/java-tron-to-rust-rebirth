use std::sync::{Arc, Mutex};

use tron_execution::{PendingPool, RawWireTransaction, TransactionProcessor};
use tron_crypto::CryptoEngine;
use tron_state::{CursorSet, CursorView, HeadCursor, PbftCursor, SolidityCursor};

use crate::{NetworkSnapshot, ReadOnlyVm};

/// Shared C022 composition boundary. Cursor reads are immutable snapshots while
/// processor and pending admission are serialized because both mutate canonical state.
#[derive(Clone)]
pub struct ApiContext {
    crypto_engine: CryptoEngine,
    cursors: CursorSet,
    processor: Arc<Mutex<TransactionProcessor>>,
    pending: Arc<Mutex<PendingPool<RawWireTransaction>>>,
    network: Arc<dyn NetworkSnapshot>,
    runtime: Option<Arc<dyn ReadOnlyVm>>,
    parameters: Arc<tron_shielded::TronParameters>,
    proof_generation: Arc<Mutex<()>>,
}

impl ApiContext {
    #[must_use]
    pub fn new(
        cursors: CursorSet,
        processor: TransactionProcessor,
        pending: PendingPool<RawWireTransaction>,
        parameters: Arc<tron_shielded::TronParameters>,
        crypto_engine: CryptoEngine,
    ) -> Self {
        Self::with_providers(
            cursors,
            processor,
            pending,
            Arc::new(crate::DisconnectedNetworkSnapshot::default()),
            None,
            parameters,
            crypto_engine,
        )
    }

    #[must_use]
    pub fn with_providers(
        cursors: CursorSet,
        processor: TransactionProcessor,
        pending: PendingPool<RawWireTransaction>,
        network: Arc<dyn NetworkSnapshot>,
        runtime: Option<Arc<dyn ReadOnlyVm>>,
        parameters: Arc<tron_shielded::TronParameters>,
        crypto_engine: CryptoEngine,
    ) -> Self {
        Self {
            crypto_engine,
            cursors,
            processor: Arc::new(Mutex::new(processor)),
            pending: Arc::new(Mutex::new(pending)),
            network,
            runtime,
            parameters,
            proof_generation: Arc::new(Mutex::new(())),
        }
    }

    #[must_use]
    pub const fn crypto_engine(&self) -> CryptoEngine {
        self.crypto_engine
    }
    #[must_use]
    pub fn head(&self) -> HeadCursor {
        self.cursors.head()
    }
    #[must_use]
    pub fn solidity(&self) -> SolidityCursor {
        self.cursors.solidity()
    }
    #[must_use]
    pub fn pbft(&self) -> PbftCursor {
        self.cursors.pbft()
    }
    #[must_use]
    pub fn cursors(&self) -> &CursorSet {
        &self.cursors
    }
    #[must_use]
    pub fn processor(&self) -> Arc<Mutex<TransactionProcessor>> {
        Arc::clone(&self.processor)
    }
    #[must_use]
    pub fn pending(&self) -> Arc<Mutex<PendingPool<RawWireTransaction>>> {
        Arc::clone(&self.pending)
    }
    #[must_use]
    pub fn network(&self) -> &dyn NetworkSnapshot {
        self.network.as_ref()
    }
    #[must_use]
    pub fn runtime(&self) -> Option<&dyn ReadOnlyVm> {
        self.runtime.as_deref()
    }
    #[must_use]
    pub fn shielded_parameters(&self) -> Arc<tron_shielded::TronParameters> {
        Arc::clone(&self.parameters)
    }
    pub(crate) fn proof_generation(&self) -> &Mutex<()> { self.proof_generation.as_ref() }
}

/// Stable cursor selection used by Wallet, WalletSolidity and PBFT adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiCursor {
    Head,
    Solidity,
    Pbft,
}

#[derive(Clone)]
pub enum TypedReadView {
    Head(HeadCursor),
    Solidity(SolidityCursor),
    Pbft(PbftCursor),
}
impl TypedReadView {
    #[must_use]
    pub fn point(&self) -> tron_state::CursorPoint {
        match self {
            Self::Head(v) => v.point(),
            Self::Solidity(v) => v.point(),
            Self::Pbft(v) => v.point(),
        }
    }
    #[must_use]
    pub fn store(&self, kind: tron_state::StoreKind) -> tron_state::ViewStore {
        match self {
            Self::Head(v) => v.store(kind),
            Self::Solidity(v) => v.store(kind),
            Self::Pbft(v) => v.store(kind),
        }
    }
}
impl ApiContext {
    #[must_use]
    pub fn view(&self, cursor: ApiCursor) -> TypedReadView {
        match cursor {
            ApiCursor::Head => TypedReadView::Head(self.head()),
            ApiCursor::Solidity => TypedReadView::Solidity(self.solidity()),
            ApiCursor::Pbft => TypedReadView::Pbft(self.pbft()),
        }
    }
}
