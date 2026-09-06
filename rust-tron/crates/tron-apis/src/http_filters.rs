use std::{collections::HashSet, future::Future, sync::Arc};

use axum::{body::Body, http::{header::CONTENT_TYPE, Response, StatusCode}};
use bytes::Bytes;
use http_body_util::BodyExt;
use tokio::sync::Semaphore;
use serde_json::json;

pub const DEFAULT_MAX_HTTP_BODY_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_CONNECTIONS: usize = 50;
pub const LITE_DISABLED_TEXT: &str = "this API is closed because this node is a lite fullnode";
pub const DISABLED_API_TEXT: &str = "this API is unavailable due to config";
pub const RATE_LIMIT_TEXT: &str = "lack of computing resources";
pub const PAYLOAD_TOO_LARGE_PAGE: &str = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=ISO-8859-1\"/><title>Error 413 Request Entity Too Large</title></head><body><h2>HTTP ERROR 413 Request Entity Too Large</h2></body></html>";

#[derive(Clone, Debug)]
pub struct HttpControls {
    pub max_body_bytes: usize,
    pub max_form_bytes: usize,
    pub max_connections: usize,
    disabled: Arc<HashSet<String>>,
    lite_history_paths: Arc<HashSet<String>>,
}

impl Default for HttpControls {
    fn default() -> Self {
        Self { max_body_bytes: DEFAULT_MAX_HTTP_BODY_BYTES, max_form_bytes: DEFAULT_MAX_HTTP_BODY_BYTES, max_connections: DEFAULT_MAX_CONNECTIONS, disabled: Arc::new(HashSet::new()), lite_history_paths: Arc::new(default_lite_paths()) }
    }
}

impl HttpControls {
    #[must_use]
    pub fn new(disabled: impl IntoIterator<Item=String>) -> Self {
        let mut value=Self::default(); value.disabled=Arc::new(disabled.into_iter().map(|v|v.to_lowercase()).collect()); value
    }
    #[must_use]
    pub fn is_disabled(&self, path: &str) -> bool {
        normalized_method(path).is_some_and(|method| self.disabled.contains(&method))
    }
    #[must_use]
    pub fn is_lite_history_path(&self, path: &str) -> bool { self.lite_history_paths.contains(&normalize_path(path)) }
    #[must_use]
    pub fn disabled_response(&self) -> Option<Response<Body>> { Some(json_response(StatusCode::NOT_FOUND, json!({"Error":DISABLED_API_TEXT}).to_string())) }
    #[must_use]
    pub fn lite_response(&self) -> Response<Body> { response(StatusCode::OK, "application/json; charset=utf-8", LITE_DISABLED_TEXT) }
}

pub async fn collect_limited_body(mut body: Body, limit: usize) -> Result<Bytes, Response<Body>> {
    let mut bytes=Vec::new();
    while let Some(frame)=body.frame().await {
        let frame=frame.map_err(|_| process_error("java.io.IOException", "failed to read request body"))?;
        if let Ok(data)=frame.into_data() { if bytes.len().saturating_add(data.len())>limit{return Err(payload_too_large())} bytes.extend_from_slice(&data); }
    }
    Ok(Bytes::from(bytes))
}
#[must_use] pub fn payload_too_large()->Response<Body>{response(StatusCode::PAYLOAD_TOO_LARGE,"text/html;charset=iso-8859-1",PAYLOAD_TOO_LARGE_PAGE)}
#[must_use] pub fn disabled_api_response()->Response<Body>{json_response(StatusCode::NOT_FOUND,json!({"Error":DISABLED_API_TEXT}).to_string())}
#[must_use] pub fn lite_api_response()->Response<Body>{response(StatusCode::OK,"application/json; charset=utf-8",LITE_DISABLED_TEXT)}
#[must_use] pub fn process_error(class:&str,message:&str)->Response<Body>{json_response(StatusCode::OK,json!({"Error":format!("{class} : {message}")}).to_string())}
#[must_use]
pub fn rate_limit_response(status: &tonic::Status) -> Response<Body> {
    let class = if status.code() == tonic::Code::DeadlineExceeded {
        "java.util.concurrent.TimeoutException"
    } else {
        "class java.lang.IllegalAccessException"
    };
    process_error(class, RATE_LIMIT_TEXT)
}

pub trait PermitLimiter: Send + Sync { fn try_acquire(&self)->Option<Box<dyn Permit>>; }
pub trait Permit: Send {}
impl<T:Send> Permit for T {}

#[derive(Clone)]
pub struct ConcurrentLimiter { semaphore: Arc<Semaphore> }
impl ConcurrentLimiter { #[must_use] pub fn new(limit:usize)->Self{Self{semaphore:Arc::new(Semaphore::new(limit))}} #[must_use] pub fn available(&self)->usize{self.semaphore.available_permits()} }
struct OwnedSemaphorePermit { _permit: tokio::sync::OwnedSemaphorePermit }
impl PermitLimiter for ConcurrentLimiter { fn try_acquire(&self)->Option<Box<dyn Permit>>{self.semaphore.clone().try_acquire_owned().ok().map(|permit|Box::new(OwnedSemaphorePermit{_permit:permit})as Box<dyn Permit>)} }

#[derive(Clone)]
pub struct ConnectionCap { semaphore: Arc<Semaphore> }
impl ConnectionCap { #[must_use] pub fn new(max:usize)->Self{Self{semaphore:Arc::new(Semaphore::new(max))}} pub fn try_acquire(&self)->Option<ConnectionPermit>{self.semaphore.clone().try_acquire_owned().ok().map(|permit|ConnectionPermit{_permit:permit})} pub async fn run<T>(&self, future:impl Future<Output=T>)->Option<T>{let permit=self.try_acquire()?;let result=future.await;drop(permit);Some(result)} }
pub struct ConnectionPermit { _permit: tokio::sync::OwnedSemaphorePermit }

pub async fn with_rate_permits<T>(endpoint: Option<&dyn PermitLimiter>, global:&dyn PermitLimiter, action:impl Future<Output=T>)->Result<T,Response<Body>>{
    let endpoint_permit=match endpoint{Some(limiter)=>Some(limiter.try_acquire().ok_or_else(||process_error("class java.lang.IllegalAccessException",RATE_LIMIT_TEXT))?),None=>None};
    let global_permit=global.try_acquire().ok_or_else(||process_error("class java.lang.IllegalAccessException",RATE_LIMIT_TEXT))?;
    let result=action.await; drop(global_permit); drop(endpoint_permit); Ok(result)
}

#[must_use] pub fn json_response(status:StatusCode,body:String)->Response<Body>{response(status,"application/json; charset=utf-8",body+"\n")}
fn response(status:StatusCode,content_type:&str,body:impl Into<Body>)->Response<Body>{Response::builder().status(status).header(CONTENT_TYPE,content_type).body(body.into()).expect("valid response")}
fn normalize_path(path:&str)->String{let mut stack=Vec::new();for part in path.split('/'){match part{""|"."=>{},".."=>{stack.pop();},v=>stack.push(v.to_ascii_lowercase())}}format!("/{}",stack.join("/"))}
fn normalized_method(path:&str)->Option<String>{normalize_path(path).split('/').nth(2).filter(|v|!v.is_empty()).map(str::to_owned)}
fn default_lite_paths()->HashSet<String>{let methods=["getblockbyid","getblockbylatestnum","getblockbylimitnext","getblockbynum","getmerkletreevoucherinfo","gettransactionbyid","gettransactioncountbyblocknum","gettransactioninfobyid","isspend","scanandmarknotebyivk","scannotebyivk","scannotebyovk","gettransactioninfobyblocknum","getmarketorderbyaccount","getmarketorderbyid","getmarketpricebypair","getmarketorderlistbypair","getmarketpairlist","scanshieldedtrc20notesbyivk","scanshieldedtrc20notesbyovk","isshieldedtrc20contractnotespent"];let mut set=HashSet::new();for prefix in ["wallet","walletsolidity","walletpbft"]{for method in methods{set.insert(format!("/{prefix}/{method}"));}}set.insert("/wallet/gettransactionreceiptbyid".into());set.insert("/wallet/totaltransaction".into());set}
