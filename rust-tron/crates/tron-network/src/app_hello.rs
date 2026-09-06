use prost::Message;
use tron_protocol::protocol::{hello_message::BlockId, Endpoint, HelloMessage, ReasonCode};
use tron_protocol::wire::PreservedMessage;

use crate::app_message::{AppMessage, AppMessageError, AppMessageType};

pub const HELLO_HASH_LEN: usize = 32;
pub const HELLO_AUX_MAX_LEN: usize = 200;

#[derive(Clone, Debug, PartialEq)]
pub struct LocalHello {
    pub node_id: Vec<u8>, pub address_v4: Vec<u8>, pub address_v6: Vec<u8>, pub port: i32,
    pub version: i32, pub timestamp: i64, pub genesis: BlockId, pub solid: BlockId,
    pub head: BlockId, pub node_type: i32, pub lowest_block_num: i64,
    pub code_version: Vec<u8>, pub address: Vec<u8>, pub signature: Vec<u8>,
}

impl LocalHello {
    pub fn build(self) -> HelloMessage {
        HelloMessage {
            from: Some(Endpoint { address: self.address_v4, port: self.port, node_id: self.node_id, address_ipv6: self.address_v6 }),
            version: self.version, timestamp: self.timestamp, genesis_block_id: Some(self.genesis),
            solid_block_id: Some(self.solid), head_block_id: Some(self.head), address: self.address,
            signature: self.signature, node_type: self.node_type, lowest_block_num: self.lowest_block_num,
            code_version: self.code_version,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AppHello { preserved: PreservedMessage<HelloMessage> }
impl AppHello {
    pub fn decode(payload: impl Into<Vec<u8>>) -> Result<Self, prost::DecodeError> { Ok(Self { preserved: PreservedMessage::decode(payload)? }) }
    pub fn constructed(message: HelloMessage) -> Self { Self { preserved: PreservedMessage::decode(message.encode_to_vec()).expect("constructed hello encodes") } }
    pub fn message(&self) -> &HelloMessage { self.preserved.message() }
    pub fn payload(&self) -> &[u8] { self.preserved.original_bytes() }
    pub fn into_app_message(self) -> Result<AppMessage, AppMessageError> { AppMessage::from_payload(AppMessageType::Hello, self.preserved.emit_original()) }
    pub fn structurally_valid(&self) -> bool { validate_structure(self.message()) }
}

pub fn validate_structure(hello: &HelloMessage) -> bool {
    let hash_ok = |id: &Option<BlockId>| id.as_ref().is_some_and(|id| id.hash.len() == HELLO_HASH_LEN);
    hash_ok(&hello.genesis_block_id) && hash_ok(&hello.solid_block_id) && hash_ok(&hello.head_block_id)
        && hello.address.len() <= HELLO_AUX_MAX_LEN && hello.signature.len() <= HELLO_AUX_MAX_LEN
        && hello.code_version.len() <= HELLO_AUX_MAX_LEN
}

#[derive(Clone)]
pub struct HelloPolicy<'a> {
    pub version: i32,
    pub genesis_hash: &'a [u8],
    pub local_head_num: i64,
    pub local_lowest_num: i64,
    pub local_solid_num: i64,
    pub duplicate_hello: bool,
    pub duplicate_peer: bool,
    pub identity_valid: bool,
    pub effective_peer: bool,
    /// Tests whether a peer solid block is in our main chain. Called only where Java calls it.
    pub solid_in_main_chain: &'a dyn Fn(&BlockId) -> bool,
}

pub fn apply_policy(hello: &HelloMessage, policy: &HelloPolicy<'_>) -> Result<(), ReasonCode> {
    if policy.duplicate_hello { return Err(ReasonCode::BadProtocol); }
    if policy.duplicate_peer { return Err(ReasonCode::DuplicatePeer); }
    if !validate_structure(hello) { return Err(ReasonCode::IncompatibleProtocol); }
    if !policy.identity_valid { return Err(ReasonCode::UnexpectedIdentity); }
    if hello.lowest_block_num > policy.local_head_num { return Err(ReasonCode::LightNodeSyncFail); }
    if hello.version != policy.version { return Err(ReasonCode::IncompatibleVersion); }
    let genesis = hello.genesis_block_id.as_ref().expect("structure checked");
    if genesis.hash != policy.genesis_hash { return Err(ReasonCode::IncompatibleChain); }
    let solid = hello.solid_block_id.as_ref().expect("structure checked");
    if policy.local_solid_num >= solid.number && !(policy.solid_in_main_chain)(solid) {
        return Err(if policy.local_lowest_num <= solid.number { ReasonCode::Forked } else { ReasonCode::LightNodeSyncFail });
    }
    let head = hello.head_block_id.as_ref().expect("structure checked");
    if head.number < policy.local_head_num && policy.effective_peer { return Err(ReasonCode::BelowThanMe); }
    Ok(())
}
