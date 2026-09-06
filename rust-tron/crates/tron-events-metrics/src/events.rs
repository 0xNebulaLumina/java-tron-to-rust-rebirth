use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tron_execution::{BlockEvent, ContractEvent, FilterEvent};

pub const BLOCK_TRIGGER: &str = "blockTrigger";
pub const TRANSACTION_TRIGGER: &str = "transactionTrigger";
pub const CONTRACT_LOG_TRIGGER: &str = "contractLogTrigger";
pub const CONTRACT_EVENT_TRIGGER: &str = "contractEventTrigger";
pub const SOLIDITY_TRIGGER: &str = "solidityTrigger";
pub const SOLIDITY_LOG_TRIGGER: &str = "solidityLogTrigger";
pub const SOLIDITY_EVENT_TRIGGER: &str = "solidityEventTrigger";

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockTrigger {
    pub time_stamp: i64,
    #[serde(default = "block_trigger_name")]
    pub trigger_name: String,
    pub block_number: i64,
    pub block_hash: String,
    pub transaction_size: i64,
    pub latest_solidified_block_number: i64,
    #[serde(default)]
    pub transaction_list: Vec<String>,
    #[serde(default)]
    pub removed: bool,
}
fn block_trigger_name() -> String { BLOCK_TRIGGER.into() }

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InternalTransaction { pub hash: String, pub caller_address: String, pub transfer_to_address: String, pub call_value_info: Vec<CallValue>, pub note: String, pub rejected: bool, pub extra: String }
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallValue { pub call_value: i64, pub token_id: String }
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionLog { pub address: String, pub topics: Vec<String>, pub data: String }

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionTrigger {
    pub time_stamp: i64,
    #[serde(default = "transaction_trigger_name")]
    pub trigger_name: String,
    pub transaction_id: String,
    pub block_hash: String,
    #[serde(default = "minus_one")]
    pub block_number: i64,
    pub energy_usage: i64,
    pub energy_fee: i64,
    pub origin_energy_usage: i64,
    pub energy_usage_total: i64,
    pub net_usage: i64,
    pub net_fee: i64,
    pub result: String,
    pub contract_address: String,
    pub contract_type: String,
    pub fee_limit: i64,
    pub contract_call_value: i64,
    pub contract_result: String,
    pub from_address: String,
    pub to_address: String,
    pub asset_name: String,
    pub asset_amount: i64,
    pub latest_solidified_block_number: i64,
    #[serde(default)] pub internal_transaction_list: Vec<InternalTransaction>,
    pub data: String,
    pub transaction_index: i32,
    pub cumulative_energy_used: i64,
    pub pre_cumulative_log_count: i64,
    #[serde(default)] pub log_list: Vec<TransactionLog>,
    pub energy_unit_price: i64,
    #[serde(default)] pub ext_map: BTreeMap<String, i64>,
    #[serde(default)] pub removed: bool,
}
fn transaction_trigger_name() -> String { TRANSACTION_TRIGGER.into() }
const fn minus_one() -> i64 { -1 }

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractBase {
    pub time_stamp: i64,
    pub unique_id: String,
    pub transaction_id: String,
    pub contract_address: String,
    pub caller_address: String,
    pub origin_address: String,
    pub creator_address: String,
    pub block_number: i64,
    pub block_hash: String,
    pub removed: bool,
    pub latest_solidified_block_number: i64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractLogTrigger {
    #[serde(default = "contract_log_trigger_name")] pub trigger_name: String,
    #[serde(flatten)] pub base: ContractBase,
    #[serde(default)] pub topic_list: Vec<String>,
    pub data: String,
}
fn contract_log_trigger_name() -> String { CONTRACT_LOG_TRIGGER.into() }

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractEventTrigger {
    #[serde(default = "contract_event_trigger_name")] pub trigger_name: String,
    #[serde(flatten)] pub base: ContractBase,
    pub event_signature: String,
    pub event_signature_full: String,
    pub event_name: String,
    #[serde(default)] pub topic_map: BTreeMap<String, String>,
    #[serde(default)] pub data_map: BTreeMap<String, String>,
}
fn contract_event_trigger_name() -> String { CONTRACT_EVENT_TRIGGER.into() }

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolidityTrigger {
    pub time_stamp: i64,
    #[serde(default = "solidity_trigger_name")] pub trigger_name: String,
    pub latest_solidified_block_number: i64,
}
fn solidity_trigger_name() -> String { SOLIDITY_TRIGGER.into() }

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "trigger", rename_all = "camelCase")]
pub enum EventTrigger { Block(BlockTrigger), Transaction(TransactionTrigger), ContractLog(ContractLogTrigger), ContractEvent(ContractEventTrigger), Solidity(SolidityTrigger), SolidityLog(ContractLogTrigger), SolidityEvent(ContractEventTrigger) }

impl EventTrigger {
    pub fn topic(&self) -> &str { match self { Self::Block(_) => BLOCK_TRIGGER, Self::Transaction(_) => TRANSACTION_TRIGGER, Self::ContractLog(_) => CONTRACT_LOG_TRIGGER, Self::ContractEvent(_) => CONTRACT_EVENT_TRIGGER, Self::Solidity(_) => SOLIDITY_TRIGGER, Self::SolidityLog(_) => SOLIDITY_LOG_TRIGGER, Self::SolidityEvent(_) => SOLIDITY_EVENT_TRIGGER } }
    pub fn block_number(&self) -> Option<i64> { match self { Self::Block(v) => Some(v.block_number), Self::Transaction(v) => Some(v.block_number), Self::ContractLog(v) | Self::SolidityLog(v) => Some(v.base.block_number), Self::ContractEvent(v) | Self::SolidityEvent(v) => Some(v.base.block_number), Self::Solidity(v) => Some(v.latest_solidified_block_number) } }
    pub fn removed(&self) -> bool { match self { Self::Block(v) => v.removed, Self::Transaction(v) => v.removed, Self::ContractLog(v) | Self::SolidityLog(v) => v.base.removed, Self::ContractEvent(v) | Self::SolidityEvent(v) => v.base.removed, Self::Solidity(_) => false } }
    pub fn to_json(&self) -> Result<String, serde_json::Error> { match self { Self::Block(v) => serde_json::to_string(v), Self::Transaction(v) => serde_json::to_string(v), Self::ContractLog(v) | Self::SolidityLog(v) => serde_json::to_string(v), Self::ContractEvent(v) | Self::SolidityEvent(v) => serde_json::to_string(v), Self::Solidity(v) => serde_json::to_string(v) } }
}

impl From<BlockEvent> for EventTrigger {
    fn from(event: BlockEvent) -> Self { Self::Block(BlockTrigger { trigger_name: BLOCK_TRIGGER.into(), block_number: event.block_number, block_hash: hex(event.block_id.as_bytes()), removed: event.removed, ..BlockTrigger::default() }) }
}
impl From<ContractEvent> for EventTrigger {
    fn from(event: ContractEvent) -> Self { Self::ContractLog(ContractLogTrigger { trigger_name: CONTRACT_LOG_TRIGGER.into(), base: ContractBase { unique_id: format!("{}_{}", hex(event.transaction_id.as_bytes()), event.transaction_index), transaction_id: hex(event.transaction_id.as_bytes()), block_number: event.block_number, block_hash: hex(event.block_id.as_bytes()), removed: event.removed, ..ContractBase::default() }, ..ContractLogTrigger::default() }) }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilterTrigger(pub FilterEvent);
