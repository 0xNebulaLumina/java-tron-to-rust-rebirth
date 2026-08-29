use std::sync::Arc;

use crate::types::{BlockId, DigestProvider, Hash32, TransactionId};

/// Immutable transaction wire boundary. Callers must supply the exact C001-preserved
/// transaction bytes and its exact preserved raw-data submessage bytes.
#[derive(Clone, Debug)]
pub struct TransactionWire {
    full: Arc<[u8]>,
    raw: Arc<[u8]>,
}

impl TransactionWire {
    pub fn new(full: impl Into<Arc<[u8]>>, raw: impl Into<Arc<[u8]>>) -> Self {
        Self { full: full.into(), raw: raw.into() }
    }

    pub fn full_bytes(&self) -> &[u8] { &self.full }
    pub fn raw_bytes(&self) -> &[u8] { &self.raw }

    /// Transaction ID hashes raw-data bytes only. Results are deliberately not cached because
    /// the digest provider is an explicit runtime dependency and different providers may coexist.
    pub fn transaction_id<D: DigestProvider>(&self, digest: &D) -> Result<TransactionId, D::Error> {
        digest.digest(self.raw_bytes()).map(TransactionId::new)
    }

    /// Merkle/full hash hashes the complete transaction wire bytes, including signatures.
    /// The provider is consulted on every call so provider identity cannot be hidden by a cache.
    pub fn full_hash<D: DigestProvider>(&self, digest: &D) -> Result<Hash32, D::Error> {
        digest.digest(self.full_bytes())
    }
}

/// Immutable block wire boundary. Block ID hashes only exact raw-header bytes and
/// overlays the signed block height into the first eight digest bytes.
#[derive(Clone, Debug)]
pub struct BlockWire {
    full: Arc<[u8]>,
    raw_header: Arc<[u8]>,
    height: i64,
}

impl BlockWire {
    pub fn new(full: impl Into<Arc<[u8]>>, raw_header: impl Into<Arc<[u8]>>, height: i64) -> Self {
        Self { full: full.into(), raw_header: raw_header.into(), height }
    }

    pub fn full_bytes(&self) -> &[u8] { &self.full }
    pub fn raw_header_bytes(&self) -> &[u8] { &self.raw_header }
    pub const fn height(&self) -> i64 { self.height }

    pub fn block_id<D: DigestProvider>(&self, digest: &D) -> Result<BlockId, D::Error> {
        digest.digest(self.raw_header_bytes()).map(|hash| BlockId::new(self.height, hash))
    }
}
