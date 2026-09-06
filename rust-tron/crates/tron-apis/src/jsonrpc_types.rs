use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const JSONRPC_VERSION: &str = "2.0";
pub const TRON_ADDRESS_PREFIX: u8 = 0x41;
pub const MAX_BLOCK_NUMBER_TEXT: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcId { Null, Number(i64), String(String) }

impl JsonRpcId {
    pub fn from_value(value: &Value) -> Option<Self> {
        match value { Value::Null => Some(Self::Null), Value::Number(n) => n.as_i64().map(Self::Number), Value::String(s) => Some(Self::String(s.clone())), _ => None }
    }
    pub fn to_value(&self) -> Value { match self { Self::Null => Value::Null, Self::Number(n) => Value::from(*n), Self::String(s) => Value::String(s.clone()) } }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError { pub code: i32, pub message: String, #[serde(skip_serializing_if="Option::is_none")] pub data: Option<Value> }
impl JsonRpcError {
    pub fn new(code:i32,message:impl Into<String>)->Self { Self { code, message:message.into(), data:None } }
    pub fn parse()->Self { Self::new(-32700,"JSON parse error") }
    pub fn invalid_request()->Self { Self::new(-32600,"Invalid Request") }
    pub fn method_not_found()->Self { Self::new(-32601,"Method not found") }
    pub fn invalid_params(message:impl Into<String>)->Self { Self::new(-32602,message) }
    pub fn internal(message:impl Into<String>)->Self { Self::new(-32603,message) }
    pub fn exceed_limit(message:impl Into<String>)->Self { Self::new(-32005,message) }
    pub fn response_too_large(limit:usize)->Self { Self::new(-32003,format!("Response exceeds the limit of {limit} bytes")) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockTag { Latest, Earliest, Finalized, Number(u64) }

pub fn quantity(value:u64)->String { format!("0x{value:x}") }
pub fn quantity_u128(value:u128)->String { format!("0x{value:x}") }
pub fn bytes_hex(bytes:&[u8])->String { let mut s=String::with_capacity(2+bytes.len()*2); s.push_str("0x"); for b in bytes { use core::fmt::Write; let _=write!(s,"{b:02x}"); } s }
pub fn hash_hex(bytes:&[u8])->Result<String,JsonRpcError> { if bytes.len()!=32 { return Err(JsonRpcError::invalid_params("invalid hash")); } Ok(bytes_hex(bytes)) }
pub fn address_hex(bytes:&[u8])->Result<String,JsonRpcError> { match bytes.len() { 20=>Ok(bytes_hex(bytes)),21 if bytes[0]==TRON_ADDRESS_PREFIX=>Ok(bytes_hex(&bytes[1..])),_=>Err(JsonRpcError::invalid_params("invalid address")) } }

pub fn decode_hex(input:&str)->Result<Vec<u8>,JsonRpcError> {
    let text=input.strip_prefix("0x").ok_or_else(||JsonRpcError::invalid_params("invalid hex string"))?;
    if text.len()%2!=0 { return Err(JsonRpcError::invalid_params("invalid hex string")); }
    (0..text.len()).step_by(2).map(|i|u8::from_str_radix(&text[i..i+2],16).map_err(|_|JsonRpcError::invalid_params("invalid hex string"))).collect()
}
pub fn parse_address(input:&str)->Result<[u8;21],JsonRpcError> { let raw=decode_hex(input)?; let mut out=[0u8;21]; match raw.len(){20=>{out[0]=TRON_ADDRESS_PREFIX;out[1..].copy_from_slice(&raw)},21 if raw[0]==TRON_ADDRESS_PREFIX=>out.copy_from_slice(&raw),_=>return Err(JsonRpcError::invalid_params("invalid address"))}; Ok(out) }
pub fn parse_hash(input:&str)->Result<[u8;32],JsonRpcError> { let raw=decode_hex(input)?; raw.try_into().map_err(|_|JsonRpcError::invalid_params("invalid hash")) }
pub fn parse_quantity(input:&str)->Result<u64,JsonRpcError> { let text=input.strip_prefix("0x").ok_or_else(||JsonRpcError::invalid_params("invalid quantity"))?; if text.is_empty() || (text.len()>1&&text.starts_with('0')) { return Err(JsonRpcError::invalid_params("invalid quantity")); } u64::from_str_radix(text,16).map_err(|_|JsonRpcError::invalid_params("invalid quantity")) }
pub fn parse_block_tag(input:&str)->Result<BlockTag,JsonRpcError> { match input.to_ascii_lowercase().as_str(){"latest"=>Ok(BlockTag::Latest),"earliest"=>Ok(BlockTag::Earliest),"finalized"=>Ok(BlockTag::Finalized),_=>{if input.len()>MAX_BLOCK_NUMBER_TEXT{return Err(JsonRpcError::invalid_params("invalid block number"));} parse_quantity(input).map(BlockTag::Number)}} }

#[derive(Debug,Clone,Default,Serialize,Deserialize,PartialEq)]
#[serde(rename_all="camelCase")]
pub struct CallArguments { pub from:Option<String>, pub to:Option<String>, pub gas:Option<String>, pub gas_price:Option<String>, pub value:Option<String>, pub data:Option<String>, pub token_id:Option<String>, pub token_value:Option<String> }

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
#[serde(rename_all="camelCase")]
pub struct BuildArguments {
    pub from:String,
    pub to:Option<String>,
    #[serde(default="zero_quantity")]
    pub gas:String,
    pub gas_price:Option<String>,
    pub value:Option<String>,
    pub data:Option<String>,
    pub input:Option<String>,
    pub nonce:Option<String>,
    pub token_id:Option<i64>,
    pub token_value:Option<i64>,
    pub abi:Option<Value>,
    pub consume_user_resource_percent:Option<i64>,
    pub origin_energy_limit:Option<i64>,
    pub name:Option<String>,
    pub contract_type:Option<String>,
    pub permission_id:Option<i32>,
    pub fee_limit:Option<String>,
    pub extra_data:Option<String>,
    pub visible:Option<bool>,
}

fn zero_quantity()->String{"0x0".into()}

impl BuildArguments {
    pub fn resolved_data(&self)->Result<Option<Vec<u8>>,JsonRpcError>{
        let input=self.input.as_deref().map(decode_hex).transpose()?;
        let data=self.data.as_deref().map(decode_hex).transpose()?;
        if input.is_some()&&data.is_some()&&input!=data{return Err(JsonRpcError::invalid_params("both \"data\" and \"input\" are set and not equal. Please use \"input\" to pass transaction call data"));}
        Ok(input.or(data))
    }
}
