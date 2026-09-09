use std::{collections::BTreeMap, io, net::{IpAddr, Ipv4Addr, SocketAddr}, sync::Arc, time::Duration};

use axum::{body::Body, extract::State, http::{header::CONTENT_TYPE, Request, Response, StatusCode}, routing::post, Router};
use tokio::sync::{watch, Semaphore};

use crate::{ApiContext, ApiCursor, BlockingExecutor, ContextJsonRpcBackend, FilterLimits, FilterManager, HttpServerConfig, HttpServerPlan, JsonRpcLimits, JsonRpcProcessor, TronJsonRpcConfig, TronJsonRpcMethods};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum JsonRpcSurface { Full, Solidity, Pbft }
impl JsonRpcSurface { pub const fn cursor(self)->ApiCursor{match self{Self::Full=>ApiCursor::Head,Self::Solidity=>ApiCursor::Solidity,Self::Pbft=>ApiCursor::Pbft}} }

#[derive(Clone, Debug)]
pub struct JsonRpcServerConfig {
    pub full_enabled: bool,
    pub bind_ip: IpAddr,
    pub solidity_enabled: bool,
    pub pbft_enabled: bool,
    pub full_port: u16,
    pub solidity_port: u16,
    pub pbft_port: u16,
    pub request_deadline: Duration,
    pub first_request_timeout: Duration,
    pub connection_idle_timeout: Duration,
    pub connection_max_age: Duration,
    pub max_connections: usize,
    pub max_concurrent_requests: usize,
    pub limits: JsonRpcLimits,
    pub filter_limits: FilterLimits,
}
impl Default for JsonRpcServerConfig {fn default()->Self{Self{bind_ip:IpAddr::V4(Ipv4Addr::UNSPECIFIED),full_enabled:false,solidity_enabled:false,pbft_enabled:false,full_port:8545,solidity_port:8555,pbft_port:8565,request_deadline:Duration::from_secs(30),first_request_timeout:Duration::from_secs(10),connection_idle_timeout:Duration::from_secs(30),connection_max_age:Duration::from_secs(300),max_connections:50,max_concurrent_requests:50,limits:JsonRpcLimits{max_request_bytes:4_194_304,max_response_bytes:26_214_400,max_batch_size:100,..Default::default()},filter_limits:FilterLimits::default()}}}
impl JsonRpcServerConfig {
    pub fn from_node(config:&tron_config::JsonRpcConfig)->Result<Self,String>{
        fn port(value:i32,name:&str)->Result<u16,String>{u16::try_from(value).ok().filter(|v|*v!=0).ok_or_else(||format!("{name} must be in 1..=65535"))}
        Ok(Self{bind_ip:IpAddr::V4(Ipv4Addr::UNSPECIFIED),full_enabled:config.http_full_node_enable,solidity_enabled:config.http_solidity_enable,pbft_enabled:config.http_pbft_enable,full_port:port(config.http_full_node_port,"full JSON-RPC port")?,solidity_port:port(config.http_solidity_port,"solidity JSON-RPC port")?,pbft_port:port(config.http_pbft_port,"PBFT JSON-RPC port")?,limits:JsonRpcLimits{max_request_bytes:positive(config.max_message_size),max_response_bytes:positive64(config.max_response_size),max_batch_size:positive(config.max_batch_size),..Default::default()},filter_limits:FilterLimits{max_block_filters:positive(config.max_block_filter_num),max_log_filters:positive(config.max_log_filter_num),max_pending_filters:positive(config.max_block_filter_num),max_addresses:positive(config.max_address_size),max_subtopics:positive(config.max_sub_topics),max_block_range:positive_u64(config.max_block_range),..Default::default()},..Default::default()})
    }
    pub fn enabled(&self)->Vec<(JsonRpcSurface,u16)>{[(JsonRpcSurface::Full,self.full_enabled,self.full_port),(JsonRpcSurface::Solidity,self.solidity_enabled,self.solidity_port),(JsonRpcSurface::Pbft,self.pbft_enabled,self.pbft_port)].into_iter().filter_map(|(s,e,p)|e.then_some((s,p))).collect()}
    pub fn validate(&self)->Result<(),String>{let enabled=self.enabled();for (i,(a,pa)) in enabled.iter().enumerate(){for(b,pb)in &enabled[i+1..]{if pa==pb{return Err(format!("JSON-RPC ports for {a:?} and {b:?} collide at {pa}"))}}}if self.request_deadline.is_zero()||self.first_request_timeout.is_zero()||self.connection_idle_timeout.is_zero()||self.connection_max_age.is_zero(){return Err("JSON-RPC deadlines must be positive".into())}if self.max_connections==0||self.max_concurrent_requests==0{return Err("JSON-RPC concurrency limits must be positive".into())}Ok(())}
}
fn positive(v:i32)->usize{if v<=0{0}else{v as usize}} fn positive64(v:i64)->usize{if v<=0{0}else{v as usize}} fn positive_u64(v:i64)->u64{if v<=0{0}else{v as u64}}

#[derive(Clone)] struct HandlerState{processor:Arc<JsonRpcProcessor<TronJsonRpcMethods<ContextJsonRpcBackend>>>,permits:Arc<Semaphore>,blocking:BlockingExecutor}
pub struct JsonRpcServerSet { plans:Vec<(JsonRpcSurface,HttpServerPlan)> }
impl JsonRpcServerSet {
    pub fn new(config:JsonRpcServerConfig,context:ApiContext,method_config:TronJsonRpcConfig,filters:Arc<FilterManager>)->Result<Self,String>{
        config.validate()?;let blocking=BlockingExecutor::new(config.max_concurrent_requests,config.request_deadline).map_err(|e|e.to_string())?;let mut plans=Vec::new();
        for(surface,port)in config.enabled(){let backend=ContextJsonRpcBackend::new(context.clone(),surface.cursor(),filters.clone());let state=HandlerState{processor:Arc::new(JsonRpcProcessor::new(TronJsonRpcMethods::new(method_config.clone(),backend),config.limits.clone())),permits:Arc::new(Semaphore::new(config.max_concurrent_requests)),blocking:blocking.clone()};let router=Router::new().route("/",post(handle)).fallback(not_found).with_state(state);let mut http=HttpServerConfig::new(SocketAddr::new(config.bind_ip,port));http.request_deadline=config.request_deadline;http.first_request_timeout=config.first_request_timeout;http.connection_idle_timeout=config.connection_idle_timeout;http.connection_max_age=config.connection_max_age;http.controls.max_connections=config.max_connections;plans.push((surface,HttpServerPlan::new(http,router)));}
        Ok(Self{plans})
    }
    pub fn surfaces(&self)->impl Iterator<Item=JsonRpcSurface>+'_ {self.plans.iter().map(|v|v.0)}
    pub async fn bind_all(self)->io::Result<BoundJsonRpcServerSet>{let mut bound=Vec::with_capacity(self.plans.len());for(surface,plan)in self.plans{match tokio::net::TcpListener::bind(plan.bind_address()).await{Ok(listener)=>bound.push((surface,plan,listener)),Err(error)=>return Err(error)}}Ok(BoundJsonRpcServerSet{bound})}
    pub async fn serve(self,cancellation:watch::Receiver<bool>)->io::Result<()>{self.bind_all().await?.start_bound(cancellation).await}
    pub fn bind_prebound(self, mut listeners: BTreeMap<JsonRpcSurface, tokio::net::TcpListener>) -> io::Result<BoundJsonRpcServerSet> {
        let mut bound = Vec::with_capacity(self.plans.len());
        for (surface, plan) in self.plans {
            let listener = listeners.remove(&surface).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("missing prebound {surface:?} JSON-RPC listener")))?;
            let actual = listener.local_addr()?;
            let expected = plan.bind_address();
            if actual.ip() != expected.ip() || (expected.port() != 0 && actual.port() != expected.port()) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("prebound {surface:?} JSON-RPC listener does not match server plan")));
            }
            bound.push((surface, plan, listener));
        }
        if !listeners.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unexpected prebound JSON-RPC listener"));
        }
        Ok(BoundJsonRpcServerSet { bound })
    }
}
pub struct BoundJsonRpcServerSet{bound:Vec<(JsonRpcSurface,HttpServerPlan,tokio::net::TcpListener)>}
impl BoundJsonRpcServerSet{
    pub fn surfaces(&self)->impl Iterator<Item=JsonRpcSurface>+'_ {self.bound.iter().map(|v|v.0)}
    pub async fn start_bound(self,cancellation:watch::Receiver<bool>)->io::Result<()>{let mut tasks=tokio::task::JoinSet::new();for(_,plan,listener)in self.bound{tasks.spawn(plan.serve_listener(listener,cancellation.clone()));}while let Some(result)=tasks.join_next().await{result.map_err(io::Error::other)??;}Ok(())}
 }

async fn handle(State(state):State<HandlerState>,request:Request<Body>)->Response<Body>{let permit=match state.permits.clone().try_acquire_owned(){Ok(v)=>v,Err(_)=>return JsonRpcErrorBody::limit()};let limit=state.processor_limits();let bytes=match crate::http_filters::collect_limited_body(request.into_body(),limit).await{Ok(v)=>v,Err(response)=>return response};let processor=state.processor.clone();let response=match state.blocking.run(move |_|Ok(processor.handle_post(&bytes))).await{Ok(v)=>v,Err(_)=>return JsonRpcErrorBody::limit()};drop(permit);Response::builder().status(response.status).header(CONTENT_TYPE,response.content_type).body(Body::from(response.body)).expect("valid JSON-RPC response")}
impl HandlerState{fn processor_limits(&self)->usize{self.processor.request_limit()}}
async fn not_found()->Response<Body>{Response::builder().status(StatusCode::NOT_FOUND).body(Body::empty()).unwrap()}
struct JsonRpcErrorBody;impl JsonRpcErrorBody{fn limit()->Response<Body>{Response::builder().status(StatusCode::OK).header(CONTENT_TYPE,"application/json-rpc").body(Body::from(r#"{"jsonrpc":"2.0","error":{"code":-32005,"message":"lack of computing resources"},"id":null}"#)).unwrap()}}
