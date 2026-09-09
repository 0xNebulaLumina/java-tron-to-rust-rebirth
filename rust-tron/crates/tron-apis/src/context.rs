use std::sync::{Arc, Mutex};
use parking_lot::RwLock;

use tron_crypto::CryptoEngine;
use tron_execution::ActuatorRegistry;
use tron_state::{CursorSet, CursorView, HeadCursor, PbftCursor, SolidityCursor};

use crate::{ExecutionProvider, NetworkSnapshot, ReadOnlyVm};

/// Shared API composition boundary. Cursor reads are immutable snapshots and all
/// canonical mutations are delegated to the single execution actor.
#[derive(Clone)]
pub struct ApiContext {
    crypto_engine: CryptoEngine,
    cursors: Arc<RwLock<CursorSet>>,
    execution: Option<Arc<dyn ExecutionProvider>>,
    actuators: Arc<ActuatorRegistry>,
    network: Arc<dyn NetworkSnapshot>,
    runtime: Option<Arc<dyn ReadOnlyVm>>,
    parameters: Arc<tron_shielded::TronParameters>,
    proof_generation: Arc<Mutex<()>>,
}

impl ApiContext {
    #[must_use]
    pub fn new(
        cursors: CursorSet,
        execution: Option<Arc<dyn ExecutionProvider>>,
        actuators: Arc<ActuatorRegistry>,
        parameters: Arc<tron_shielded::TronParameters>,
        crypto_engine: CryptoEngine,
    ) -> Self {
        Self::with_providers(
            cursors,
            execution,
            actuators,
            Arc::new(crate::DisconnectedNetworkSnapshot::default()),
            None,
            parameters,
            crypto_engine,
        )
    }

    #[must_use]
    pub fn with_providers(
        cursors: CursorSet,
        execution: Option<Arc<dyn ExecutionProvider>>,
        actuators: Arc<ActuatorRegistry>,
        network: Arc<dyn NetworkSnapshot>,
        runtime: Option<Arc<dyn ReadOnlyVm>>,
        parameters: Arc<tron_shielded::TronParameters>,
        crypto_engine: CryptoEngine,
    ) -> Self {
        Self {
            crypto_engine,
            cursors: Arc::new(RwLock::new(cursors)),
            execution,
            actuators,
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
        self.cursors.read().head()
    }
    #[must_use]
    pub fn solidity(&self) -> SolidityCursor {
        self.cursors.read().solidity()
    }
    #[must_use]
    pub fn pbft(&self) -> PbftCursor {
        self.cursors.read().pbft()
    }
    #[must_use]
    pub fn cursors(&self) -> CursorSet {
        self.cursors.read().clone()
    }
    /// Atomically publishes a newly validated cursor set to every API clone.
    pub fn publish_cursors(&self, cursors: CursorSet) {
        *self.cursors.write() = cursors;
    }
    #[must_use]
    pub fn execution(&self) -> Option<&Arc<dyn ExecutionProvider>> {
        self.execution.as_ref()
    }
    #[must_use]
    pub fn actuators(&self) -> &Arc<ActuatorRegistry> {
        &self.actuators
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
