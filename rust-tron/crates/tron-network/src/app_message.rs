use sha2::{Digest, Sha256};
use std::hash::{Hash, Hasher};

/// Positive application-layer message codes carried inside an established C020 session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AppMessageType {
    Transaction = 0x01,
    Block = 0x02,
    Transactions = 0x03,
    Inventory = 0x06,
    FetchInventoryData = 0x07,
    SyncBlockChain = 0x08,
    ChainInventory = 0x09,
    PbftCommit = 0x14,
    Hello = 0x20,
    Disconnect = 0x21,
    Ping = 0x22,
    Pong = 0x23,
    Pbft = 0x34,
}

impl AppMessageType {
    pub const fn byte(self) -> u8 { self as u8 }

    pub const fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            0x01 => Self::Transaction, 0x02 => Self::Block, 0x03 => Self::Transactions,
            0x06 => Self::Inventory, 0x07 => Self::FetchInventoryData,
            0x08 => Self::SyncBlockChain, 0x09 => Self::ChainInventory,
            0x14 => Self::PbftCommit, 0x20 => Self::Hello, 0x21 => Self::Disconnect,
            0x22 => Self::Ping, 0x23 => Self::Pong, 0x34 => Self::Pbft,
            _ => return None,
        })
    }
    pub const fn in_range(value: i8) -> bool { value < -1 }
    pub const fn in_p2p_range(value: u8) -> bool { value >= Self::Hello as u8 && value <= Self::Pong as u8 }
    pub const fn in_tron_range(value: u8) -> bool { value <= Self::PbftCommit as u8 }
    pub const fn in_pbft_range(value: u8) -> bool { value == Self::Pbft as u8 }
    pub const fn java_name(self) -> &'static str {
        match self {
            Self::Transaction => "TRX", Self::Block => "BLOCK", Self::Inventory => "INVENTORY",
            Self::FetchInventoryData => "FETCH_INV_DATA", Self::SyncBlockChain => "SYNC_BLOCK_CHAIN",
            _ => "UNKNOWN",
        }
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AppMessageError {
    #[error("empty application message")]
    Empty,
    #[error("unsupported application message type 0x{0:02x}")]
    Unsupported(u8),
    #[error("application {0} must have the single-byte protobuf payload 0xc0")]
    InvalidKeepAlive(&'static str),
}

/// Exact inbound application message. Payload bytes are never normalized or re-encoded.
#[derive(Clone, Debug)]
pub struct AppMessage { kind: AppMessageType, payload: Vec<u8> }

impl AppMessage {
    pub fn parse(frame: impl Into<Vec<u8>>) -> Result<Self, AppMessageError> {
        let frame = frame.into();
        let (&prefix, payload) = frame.split_first().ok_or(AppMessageError::Empty)?;
        let kind = AppMessageType::from_byte(prefix).ok_or(AppMessageError::Unsupported(prefix))?;
        if matches!(kind, AppMessageType::Ping | AppMessageType::Pong) && payload != [0xc0] {
            return Err(AppMessageError::InvalidKeepAlive(if kind == AppMessageType::Ping { "ping" } else { "pong" }));
        }
        Ok(Self { kind, payload: payload.to_vec() })
    }

    pub fn from_payload(kind: AppMessageType, payload: impl Into<Vec<u8>>) -> Result<Self, AppMessageError> {
        let payload = payload.into();
        Self::parse([vec![kind.byte()], payload].concat())
    }
    pub fn ping() -> Self { Self { kind: AppMessageType::Ping, payload: vec![0xc0] } }
    pub fn pong() -> Self { Self { kind: AppMessageType::Pong, payload: vec![0xc0] } }
    pub const fn kind(&self) -> AppMessageType { self.kind }
    pub fn payload(&self) -> &[u8] { &self.payload }
    pub fn send_bytes(&self) -> Vec<u8> { let mut out=Vec::with_capacity(self.payload.len()+1); out.push(self.kind.byte()); out.extend_from_slice(&self.payload); out }
    /// Java `Message.getMessageId()`: digest the protobuf payload, excluding its type byte.
    pub fn message_id(&self) -> [u8; 32] { Sha256::digest(&self.payload).into() }
}

// Java Message equality and hashCode deliberately compare payload only, not the type byte.
impl PartialEq for AppMessage { fn eq(&self, other: &Self) -> bool { self.payload == other.payload } }
impl Eq for AppMessage {}
impl Hash for AppMessage { fn hash<H: Hasher>(&self, state: &mut H) { self.payload.hash(state); } }
