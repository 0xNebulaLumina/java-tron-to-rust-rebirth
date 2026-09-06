use serde_json::{json, Value};
use crate::jsonrpc_types::{bytes_hex, decode_hex, quantity, JsonRpcError};

pub const TRON_JSON_RPC_METHODS: [&str; 52] = [
 "web3_clientVersion","web3_sha3","eth_getBlockTransactionCountByHash","eth_getBlockTransactionCountByNumber","eth_getBlockByHash","eth_getBlockByNumber","net_version","eth_chainId","net_listening","eth_protocolVersion","eth_blockNumber","eth_getBalance","eth_getStorageAt","eth_getCode","eth_coinbase","eth_gasPrice","eth_estimateGas","eth_getTransactionByHash","eth_getTransactionByBlockHashAndIndex","eth_getTransactionByBlockNumberAndIndex","eth_getTransactionReceipt","eth_getBlockReceipts","eth_call","net_peerCount","eth_syncing","eth_getUncleByBlockHashAndIndex","eth_getUncleByBlockNumberAndIndex","eth_getUncleCountByBlockHash","eth_getUncleCountByBlockNumber","eth_getWork","eth_hashrate","eth_mining","eth_accounts","buildTransaction","eth_submitWork","eth_sendRawTransaction","eth_sendTransaction","eth_sign","eth_signTransaction","parity_nextNonce","eth_getTransactionCount","eth_getCompilers","eth_compileSolidity","eth_compileLLL","eth_compileSerpent","eth_submitHashrate","eth_newFilter","eth_newBlockFilter","eth_uninstallFilter","eth_getFilterChanges","eth_getLogs","eth_getFilterLogs"
];
pub const UNSUPPORTED_METHODS:[&str;12]=["eth_submitWork","eth_sendRawTransaction","eth_sendTransaction","eth_sign","eth_signTransaction","parity_nextNonce","eth_getTransactionCount","eth_getCompilers","eth_compileSolidity","eth_compileLLL","eth_compileSerpent","eth_submitHashrate"];

pub trait JsonRpcBackend: Send + Sync {
 fn execute(&self, method:&str, params:&Value)->Result<Value,JsonRpcError>;
}
impl<F> JsonRpcBackend for F where F:Fn(&str,&Value)->Result<Value,JsonRpcError>+Send+Sync { fn execute(&self,m:&str,p:&Value)->Result<Value,JsonRpcError>{self(m,p)} }

#[derive(Debug,Clone)]
pub struct TronJsonRpcConfig { pub client_version:String, pub network_version:String, pub protocol_version:String, pub genesis_hash:[u8;32], pub peer_count:u64, pub coinbase:Option<[u8;21]>, pub gas_price:u64, pub listening:bool }
impl Default for TronJsonRpcConfig { fn default()->Self{Self{client_version:"JavaTron".into(),network_version:"0".into(),protocol_version:"0x41".into(),genesis_hash:[0;32],peer_count:0,coinbase:None,gas_price:0,listening:true}} }
impl TronJsonRpcConfig { pub fn chain_id(&self)->String { bytes_hex(&self.genesis_hash[28..]) } }

pub struct TronJsonRpcMethods<B> { pub config:TronJsonRpcConfig, backend:B }
impl<B:JsonRpcBackend> TronJsonRpcMethods<B> {
 pub fn new(config:TronJsonRpcConfig,backend:B)->Self{Self{config,backend}}
 pub fn execute(&self,method:&str,params:&Value)->Result<Value,JsonRpcError>{
  if !TRON_JSON_RPC_METHODS.contains(&method){return Err(JsonRpcError::method_not_found())}
  if UNSUPPORTED_METHODS.contains(&method){return Err(JsonRpcError::method_not_found())}
  match method {
   "web3_clientVersion"=>Ok(json!(self.config.client_version)),
   "web3_sha3"=>{let p=first_string(params)?;Ok(json!(bytes_hex(&tron_crypto::keccak256(&decode_hex(p)?))))},
   "net_version"|"eth_chainId"=>Ok(json!(self.config.chain_id())),
   "net_listening"=>Ok(json!(self.config.listening)),
   "eth_protocolVersion"=>Ok(json!(self.config.protocol_version)),
   "net_peerCount"=>Ok(json!(quantity(self.config.peer_count))),
   "eth_coinbase"=>Ok(json!(self.config.coinbase.map(|a|bytes_hex(&a[1..])).unwrap_or_else(||"0x0000000000000000000000000000000000000000".into()))),
   "eth_gasPrice"=>Ok(json!(quantity(self.config.gas_price))),
   "eth_syncing"=>Ok(json!(false)), "eth_getWork"=>Ok(json!([])), "eth_hashrate"=>Ok(json!("0x0")), "eth_mining"=>Ok(json!(false)), "eth_accounts"=>Ok(json!([])),
   "eth_getUncleByBlockHashAndIndex"|"eth_getUncleByBlockNumberAndIndex"=>Ok(Value::Null),
   "eth_getUncleCountByBlockHash"|"eth_getUncleCountByBlockNumber"=>Ok(json!("0x0")),
   _=>self.backend.execute(method,params)
  }
 }
}
impl<B:JsonRpcBackend> JsonRpcBackend for TronJsonRpcMethods<B> {
 fn execute(&self,method:&str,params:&Value)->Result<Value,JsonRpcError>{TronJsonRpcMethods::execute(self,method,params)}
}
fn first_string(params:&Value)->Result<&str,JsonRpcError>{params.as_array().and_then(|a|a.first()).and_then(Value::as_str).ok_or_else(||JsonRpcError::invalid_params("Invalid params"))}

pub struct RejectingBackend;
impl JsonRpcBackend for RejectingBackend { fn execute(&self,_:&str,_:&Value)->Result<Value,JsonRpcError>{Err(JsonRpcError::method_not_found())} }
