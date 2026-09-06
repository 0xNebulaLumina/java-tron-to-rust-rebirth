use serde_json::{json,Value};
use crate::jsonrpc_methods::JsonRpcBackend;
use crate::jsonrpc_types::{JsonRpcError,JsonRpcId,JSONRPC_VERSION};

#[derive(Debug,Clone)]
pub struct JsonRpcLimits { pub max_request_bytes:usize, pub max_response_bytes:usize, pub max_batch_size:usize, pub max_nesting_depth:usize, pub max_token_count:usize }
impl Default for JsonRpcLimits { fn default()->Self{Self{max_request_bytes:1_000_000,max_response_bytes:1_000_000,max_batch_size:100,max_nesting_depth:1000,max_token_count:1_000_000}} }
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct JsonRpcHttpResponse { pub status:u16, pub content_type:&'static str, pub body:Vec<u8> }
impl JsonRpcHttpResponse { fn new(body:Vec<u8>)->Self{Self{status:200,content_type:"application/json-rpc",body}} }

pub struct JsonRpcProcessor<S>{service:S,limits:JsonRpcLimits}
impl<S:JsonRpcBackend> JsonRpcProcessor<S>{
 pub fn new(service:S,limits:JsonRpcLimits)->Self{Self{service,limits}}
 pub fn request_limit(&self)->usize{self.limits.max_request_bytes}
 pub fn handle_post(&self,body:&[u8])->JsonRpcHttpResponse{
  if self.limits.max_request_bytes>0&&body.len()>self.limits.max_request_bytes{return self.error_http(JsonRpcError::exceed_limit(format!("Request size {} exceeds the limit of {}",body.len(),self.limits.max_request_bytes)),None,false)}
  let root:Value=match serde_json::from_slice(body){Ok(v)=>v,Err(_)=>return self.error_http(JsonRpcError::parse(),None,false)};
  let (depth,tokens)=measure(&root,1); if (self.limits.max_nesting_depth>0&&depth>self.limits.max_nesting_depth)||(self.limits.max_token_count>0&&tokens>self.limits.max_token_count){return self.error_http(JsonRpcError::new(-32700,"JSON parse error"),None,false)}
  match root { Value::Object(_)=>self.single(root),Value::Array(items)=>self.batch(items),_=>self.error_http(JsonRpcError::invalid_request(),None,false) }
 }
 fn single(&self,v:Value)->JsonRpcHttpResponse{let id=request_id(&v);match self.invoke(&v){None=>JsonRpcHttpResponse::new(Vec::new()),Some(result)=>{let bytes=encode(&result);if self.limits.max_response_bytes>0&&bytes.len()>self.limits.max_response_bytes{self.error_http(JsonRpcError::response_too_large(self.limits.max_response_bytes),id,false)}else{JsonRpcHttpResponse::new(bytes)}}}}
 fn batch(&self,items:Vec<Value>)->JsonRpcHttpResponse{
  if items.is_empty(){return self.error_http(JsonRpcError::invalid_request(),None,false)}
  if self.limits.max_batch_size>0&&items.len()>self.limits.max_batch_size{return self.error_http(JsonRpcError::exceed_limit(format!("Batch size {} exceeds the limit of {}",items.len(),self.limits.max_batch_size)),None,true)}
  let mut out=Vec::new();let mut accumulated=2usize;let mut overflow=false;
  for item in items { let id=request_id(&item); if overflow {if !item.is_object(){out.push(error_value(JsonRpcError::invalid_request(),None))}else if id.is_some(){out.push(error_value(JsonRpcError::response_too_large(self.limits.max_response_bytes),id))}continue}
   let Some(response)=self.invoke(&item) else{continue};let addition=encode(&response).len()+usize::from(!out.is_empty());if self.limits.max_response_bytes>0&&accumulated+addition>self.limits.max_response_bytes{overflow=true;out.push(error_value(JsonRpcError::response_too_large(self.limits.max_response_bytes),id));}else{accumulated+=addition;out.push(response)} }
  if out.is_empty(){JsonRpcHttpResponse::new(Vec::new())}else{JsonRpcHttpResponse::new(encode(&Value::Array(out)))}
 }
 fn invoke(&self,v:&Value)->Option<Value>{
  let Some(obj)=v.as_object() else{return Some(error_value(JsonRpcError::invalid_request(),None))};let has_id=obj.contains_key("id");let id=obj.get("id").and_then(JsonRpcId::from_value);
  if obj.get("jsonrpc").and_then(Value::as_str)!=Some(JSONRPC_VERSION)||obj.get("method").and_then(Value::as_str).is_none()||obj.get("id").is_some_and(|x|JsonRpcId::from_value(x).is_none())||obj.get("params").is_some_and(|p|!p.is_array()&&!p.is_object()){return if has_id{Some(error_value(JsonRpcError::invalid_request(),id))}else{Some(error_value(JsonRpcError::invalid_request(),None))}}
  let method=obj["method"].as_str().expect("checked");let params=obj.get("params").cloned().unwrap_or_else(||json!([]));let result=self.service.execute(method,&params);
  if !has_id{return None} Some(match result{Ok(value)=>success_value(value,id),Err(error)=>error_value(error,id)})
 }
 fn error_http(&self,error:JsonRpcError,id:Option<JsonRpcId>,batch:bool)->JsonRpcHttpResponse{let v=error_value(error,id);let body=if batch{Value::Array(vec![v])}else{v};JsonRpcHttpResponse::new(encode(&body))}
}
fn request_id(v:&Value)->Option<JsonRpcId>{v.as_object()?.get("id").and_then(JsonRpcId::from_value)}
fn success_value(result:Value,id:Option<JsonRpcId>)->Value{json!({"jsonrpc":"2.0","result":result,"id":id.map_or(Value::Null,|x|x.to_value())})}
fn error_value(error:JsonRpcError,id:Option<JsonRpcId>)->Value{let mut e=serde_json::Map::new();e.insert("code".into(),json!(error.code));e.insert("message".into(),json!(error.message));if let Some(data)=error.data{e.insert("data".into(),data);}json!({"jsonrpc":"2.0","error":Value::Object(e),"id":id.map_or(Value::Null,|x|x.to_value())})}
fn encode(v:&Value)->Vec<u8>{serde_json::to_vec(v).expect("JSON values serialize")}
fn measure(v:&Value,depth:usize)->(usize,usize){match v{Value::Array(a)=>a.iter().fold((depth,1),|(d,t),x|{let(m,n)=measure(x,depth+1);(d.max(m),t+n)}),Value::Object(o)=>o.values().fold((depth,1+o.len()),|(d,t),x|{let(m,n)=measure(x,depth+1);(d.max(m),t+n)}),_=>(depth,1)}}
