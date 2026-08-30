use core::{fmt, marker::PhantomData};

use prost::Message;
use tron_crypto::{CryptoEngine, selected_digest};
use tron_protocol::wire::{PreservedMessage, encode_constructed};

#[derive(Debug)]
pub struct CapsuleDecodeError {
    pub capsule: &'static str,
    pub source: prost::DecodeError,
}

impl fmt::Display for CapsuleDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed {} protobuf: {}", self.capsule, self.source)
    }
}
impl std::error::Error for CapsuleDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.source) }
}

/// Canonical protobuf capsule. Untouched decoded values retain their exact input bytes;
/// explicit mutation switches emission to prost's constructed-message encoding.
#[derive(Clone, Debug)]
pub struct ProtoCapsule<M> {
    message: M,
    original: Option<Vec<u8>>,
}

impl<M: Message + Default> ProtoCapsule<M> {
    pub fn decode(bytes: impl Into<Vec<u8>>, capsule: &'static str) -> Result<Self, CapsuleDecodeError> {
        let preserved = PreservedMessage::<M>::decode(bytes).map_err(|source| CapsuleDecodeError { capsule, source })?;
        let (original, message) = preserved.into_parts();
        Ok(Self { message, original: Some(original) })
    }

    #[must_use]
    pub fn new(message: M) -> Self { Self { message, original: None } }
    #[must_use]
    pub fn instance(&self) -> &M { &self.message }
    pub fn instance_mut(&mut self) -> &mut M {
        self.original = None;
        &mut self.message
    }
    #[must_use]
    pub fn into_instance(self) -> M { self.message }
    #[must_use]
    pub fn data(&self) -> Vec<u8> {
        self.original.clone().unwrap_or_else(|| encode_constructed(&self.message))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BytesCapsule(Vec<u8>);
impl BytesCapsule {
    #[must_use] pub fn new(bytes: impl Into<Vec<u8>>) -> Self { Self(bytes.into()) }
    #[must_use] pub fn data(&self) -> &[u8] { &self.0 }
    #[must_use] pub fn into_data(self) -> Vec<u8> { self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeCapsule {
    code: Vec<u8>,
    engine: CryptoEngine,
}
impl CodeCapsule {
    #[must_use] pub fn new(code: impl Into<Vec<u8>>, engine: CryptoEngine) -> Self { Self { code: code.into(), engine } }
    #[must_use] pub fn data(&self) -> &[u8] { &self.code }
    #[must_use] pub fn code_hash(&self) -> [u8; 32] { selected_digest(self.engine, &self.code) }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageRow {
    key: [u8; 32],
    value: [u8; 32],
    dirty: bool,
}
impl StorageRow {
    #[must_use] pub const fn new(key: [u8; 32], value: [u8; 32]) -> Self { Self { key, value, dirty: false } }
    #[must_use] pub const fn key(&self) -> &[u8; 32] { &self.key }
    #[must_use] pub const fn value(&self) -> &[u8; 32] { &self.value }
    #[must_use] pub const fn is_dirty(&self) -> bool { self.dirty }
    pub fn set_value(&mut self, value: [u8; 32]) { self.value = value; self.dirty = true; }
    #[must_use] pub fn is_zero(&self) -> bool { self.value == [0; 32] }
}

/// Type marker useful for store declarations that carry a protobuf type but no value.
#[derive(Clone, Copy, Debug, Default)]
pub struct CapsuleType<M>(PhantomData<fn() -> M>);

pub type AccountCapsule = ProtoCapsule<tron_protocol::protocol::Account>;
pub type PermissionCapsule = ProtoCapsule<tron_protocol::protocol::Permission>;
pub type AssetIssueCapsule = ProtoCapsule<tron_protocol::protocol::AssetIssueContract>;
pub type BlockCapsule = ProtoCapsule<tron_protocol::protocol::Block>;
pub type TransactionCapsule = ProtoCapsule<tron_protocol::protocol::Transaction>;
pub type TransactionInfoCapsule = ProtoCapsule<tron_protocol::protocol::TransactionInfo>;
pub type TransactionRetCapsule = ProtoCapsule<tron_protocol::protocol::TransactionRet>;
pub type ContractCapsule = ProtoCapsule<tron_protocol::protocol::SmartContract>;
pub type AbiCapsule = ProtoCapsule<tron_protocol::protocol::smart_contract::Abi>;
pub type AccountResourceCapsule = ProtoCapsule<tron_protocol::protocol::account::AccountResource>;
pub type AccountResourceMessageCapsule = ProtoCapsule<tron_protocol::protocol::AccountResourceMessage>;
pub type ContractStateCapsule = ProtoCapsule<tron_protocol::protocol::ContractState>;
pub type WitnessCapsule = ProtoCapsule<tron_protocol::protocol::Witness>;
pub type VotesCapsule = ProtoCapsule<tron_protocol::protocol::Votes>;
pub type ProposalCapsule = ProtoCapsule<tron_protocol::protocol::Proposal>;
pub type ExchangeCapsule = ProtoCapsule<tron_protocol::protocol::Exchange>;
pub type MarketOrderCapsule = ProtoCapsule<tron_protocol::protocol::MarketOrder>;
pub type MarketAccountOrderCapsule = ProtoCapsule<tron_protocol::protocol::MarketAccountOrder>;
pub type MarketPriceCapsule = ProtoCapsule<tron_protocol::protocol::MarketPrice>;
pub type MarketPriceListCapsule = ProtoCapsule<tron_protocol::protocol::MarketPriceList>;
pub type MarketOrderIdListCapsule = ProtoCapsule<tron_protocol::protocol::MarketOrderIdList>;
pub type DelegatedResourceCapsule = ProtoCapsule<tron_protocol::protocol::DelegatedResource>;
pub type DelegatedResourceAccountIndexCapsule = ProtoCapsule<tron_protocol::protocol::DelegatedResourceAccountIndex>;
pub type PbftMessageCapsule = ProtoCapsule<tron_protocol::protocol::PbftMessage>;
pub type PbftCommitResultCapsule = ProtoCapsule<tron_protocol::protocol::PbftCommitResult>;
pub type AccountTraceCapsule = ProtoCapsule<tron_protocol::protocol::AccountTrace>;
pub type IncrementalMerkleTreeCapsule = ProtoCapsule<tron_protocol::protocol::IncrementalMerkleTree>;
