//! Canonical TRON logical state capsules, key/value codecs, and namespaced storage.
//! C009 builds revoking overlays on the atomic [`StateWriteBatch`] seam.

pub mod capsule;
pub mod account_asset;
pub mod contract;
pub mod keys;
pub mod delegation;
pub mod dynamic;
pub mod market;
pub mod store;
pub mod session;
pub mod checkpoint;
pub mod cursor;
pub mod pending;
pub mod lifecycle;
pub mod value;

pub use capsule::{BytesCapsule, CapsuleDecodeError, CodeCapsule, ProtoCapsule, StorageRow};
pub use store::{StateStore, StateWriteBatch, StoreEntry, StoreKind, StoreName, StoreNameError, TypedStore, physical_key};
pub use session::{DurableStore, OverlayStore, OverlayValue, ReadView, Session, SessionError, SessionManager, ShutdownErrors, ViewStore};
pub use checkpoint::{CheckpointCrashInjector, CheckpointCrashPhase, CheckpointError, CheckpointLimits, CheckpointStack, NoCheckpointCrash};
pub use cursor::{CheckpointIdentity, CursorError, CursorPoint, CursorSet, CursorView, HeadCursor, PbftCursor, SolidityCursor};
pub use pending::PendingSession;
pub use lifecycle::StateLifecycle;
