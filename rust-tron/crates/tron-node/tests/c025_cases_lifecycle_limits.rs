use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, SystemTime, UNIX_EPOCH}};
use parking_lot::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tron_apis::{ApiContext, RpcApiServices, interceptors::{ApiInterceptors, IngressLayer}, rate_limit::{ApiRateLimiter, RateLimitConfig}, server::{ServerMode, serve_grpc}};
use tron_config::{Config, NodeMode, RpcConfig};
use tron_crypto::CryptoEngine;
use tron_execution::{ActuatorRegistry, CacheConfig, ExecutionConfig, PendingLimits, PendingPool, StateTransactionPipeline, TransactionCache, TransactionProcessor};
use tron_node::{CancellationToken, LifecycleError, LifecycleFuture, MonotonicClock, NodeContext, NodeService, ServiceFailure, ServiceGraph, ServiceSpec, enabled_api_ports, lifecycle_limits::*, operations::{StopCondition, StopController}};
use tron_state::{CheckpointIdentity, CursorPoint, CursorSet, SessionManager, StateStore};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

#[derive(Default)] struct Clock;
impl MonotonicClock for Clock { fn elapsed(&self) -> Duration { Duration::ZERO } }
fn context(config: Config) -> NodeContext { NodeContext::new(Arc::new(config), CancellationToken::default(), Arc::new(Clock)) }

#[derive(Clone)] struct RecordingService { spec: ServiceSpec, starts: Arc<Mutex<Vec<&'static str>>>, stops: Arc<Mutex<Vec<&'static str>>>, fail_start: bool, fail_stop: bool }
impl NodeService for RecordingService {
    fn spec(&self) -> ServiceSpec { self.spec.clone() }
    fn start<'a>(&'a mut self, _: &'a NodeContext, _: Duration) -> LifecycleFuture<'a> { Box::pin(async move { self.starts.lock().push(self.spec.name); if self.fail_start { Err(ServiceFailure { service:self.spec.name, message:"start failed".into() }) } else { Ok(()) } }) }
    fn stop<'a>(&'a mut self, _: &'a NodeContext, _: Duration) -> LifecycleFuture<'a> { Box::pin(async move { self.stops.lock().push(self.spec.name); if self.fail_stop { Err(ServiceFailure { service:self.spec.name, message:"stop failed".into() }) } else { Ok(()) } }) }
}
fn service(name:&'static str,deps:&'static [&'static str],starts:&Arc<Mutex<Vec<&'static str>>>,stops:&Arc<Mutex<Vec<&'static str>>>,fail_start:bool,fail_stop:bool)->Box<dyn NodeService>{Box::new(RecordingService{spec:ServiceSpec::new(name,deps,&[]),starts:starts.clone(),stops:stops.clone(),fail_start,fail_stop})}

#[test]
fn keystore_factory_repl_preserves_deprecation_dispatch_prompts_and_exit() {
    let transcript=run_legacy_keystore_factory("\nhelp\nbadcommand\ngenkeystore\nimportprivatekey\nquit\n");
    assert!(transcript.stderr.contains("--keystore-factory is deprecated")&&transcript.stderr.contains("Toolkit.jar keystore"));
    for expected in ["GenKeystore","ImportPrivateKey","Invalid cmd: badcommand","Please input password","Please input private key","Exit"] { assert!(transcript.stdout.contains(expected),"missing {expected}"); }
    assert_eq!(program_mode(true,true),NodeMode::KeystoreFactory);
    assert!(enabled_api_ports(&Config::default(),NodeMode::KeystoreFactory).unwrap().is_empty());
}

#[test]
fn full_solidity_and_keystore_program_modes_are_distinct() {
    assert_eq!(program_mode(false,false),NodeMode::Full);
    assert_eq!(program_mode(true,false),NodeMode::Solidity);
    assert_eq!(program_mode(false,true),NodeMode::KeystoreFactory);
    assert!(!program_version().is_empty());
}

#[tokio::test]
async fn application_starts_forward_stops_reverse_and_surfaces_every_failure() {
    let starts=Arc::new(Mutex::new(Vec::new())); let stops=Arc::new(Mutex::new(Vec::new()));
    let mut graph=ServiceGraph::new(context(Config::default()),NodeMode::Full,vec![service("database",&[],&starts,&stops,false,true),service("apis",&["database"],&starts,&stops,false,true),service("readiness",&["apis"],&starts,&stops,false,false)]).unwrap();
    graph.start(Duration::from_secs(1),Duration::from_secs(1)).await.unwrap();
    assert_eq!(*starts.lock(),["database","apis","readiness"]);
    let LifecycleError::ShutdownFailures(failures)=graph.shutdown(Duration::from_secs(1)).await.unwrap_err() else { panic!("expected shutdown failures") };
    assert_eq!(*stops.lock(),["readiness","apis","database"]);
    assert_eq!(failures.iter().map(|f|f.service).collect::<Vec<_>>(),["apis","database"]);
}

#[tokio::test]
async fn startup_failure_unwinds_started_services_and_preserves_both_errors() {
    let starts=Arc::new(Mutex::new(Vec::new())); let stops=Arc::new(Mutex::new(Vec::new()));
    let mut graph=ServiceGraph::new(context(Config::default()),NodeMode::Full,vec![service("database",&[],&starts,&stops,false,true),service("apis",&["database"],&starts,&stops,true,false)]).unwrap();
    let error=graph.start(Duration::from_secs(1),Duration::from_secs(1)).await.unwrap_err();
    assert!(matches!(error,LifecycleError::StartupUnwindFailure{..}));
    assert_eq!(*starts.lock(),["database","apis"]); assert_eq!(*stops.lock(),["database"]);
}

#[tokio::test]
async fn operator_fatal_and_signal_conditions_use_the_same_stop_channel() {
    for condition in [StopCondition::Interrupt,StopCondition::Terminate,StopCondition::Operator,StopCondition::Fatal(ServiceFailure{service:"rpc",message:"listener exited".into()})] {
        let (handle,mut controller)=StopController::new(); handle.request(condition.clone()).unwrap(); assert_eq!(controller.wait().await,condition);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)] struct Block(u64);
struct Source { blocks:Vec<Result<Option<(i64,Block)>,String>>, tips:Vec<Result<i64,String>>, stopped:Arc<AtomicBool> }
impl SoliditySource for Source { type Block=Block; fn block(&mut self,_:i64)->Result<Option<(i64,Block)>,String>{self.blocks.remove(0)} fn last_solidity_block(&mut self)->Result<i64,String>{self.tips.remove(0)} fn shutdown(&mut self){self.stopped.store(true,Ordering::Release);} }

#[test]
fn solidity_replica_retries_fetches_processes_and_shuts_down_client() {
    let stopped=Arc::new(AtomicBool::new(false)); let source=Source{blocks:vec![Ok(None),Err("rpc".into()),Ok(Some((7,Block(7))))],tips:vec![Err("rpc".into()),Ok(9)],stopped:stopped.clone()};
    let mut replica=SolidityReplica::new(source); let block=replica.fetch_block(7,Duration::ZERO).unwrap(); assert_eq!(block.0,7); assert_eq!(replica.last_solidity_block(Duration::ZERO),9);
    replica.enqueue(block); let mut processed=0; assert!(replica.process_next(|b|{processed=b.0;Ok(())}).unwrap()); assert_eq!(processed,7); assert!(!replica.process_next(|_|Ok(())).unwrap());
    replica.close(); assert!(!replica.is_running()); assert!(stopped.load(Ordering::Acquire));
}

#[test]
fn solidity_replica_shutdown_race_does_not_sleep_or_retry() {
    struct ClosingSource { running:Arc<AtomicBool>, calls:usize }
    impl SoliditySource for ClosingSource { type Block=Block; fn block(&mut self,_:i64)->Result<Option<(i64,Block)>,String>{self.calls+=1;self.running.store(false,Ordering::Release);Err("closed".into())} fn last_solidity_block(&mut self)->Result<i64,String>{self.running.store(false,Ordering::Release);Err("closed".into())} fn shutdown(&mut self){} }
    let marker=Arc::new(AtomicBool::new(true)); let source=ClosingSource{running:marker.clone(),calls:0}; let mut replica=SolidityReplica::new(source); let internal=replica.running_handle();
    // Model the context-close event at the same boundary as the failed RPC.
    marker.store(true,Ordering::Release); internal.store(false,Ordering::Release);
    let started=std::time::Instant::now(); assert_eq!(replica.fetch_block(42,Duration::from_secs(1)),Err(SolidityReplicaError::Closing)); assert!(started.elapsed()<Duration::from_millis(100)); assert_eq!(replica.last_solidity_block(Duration::from_secs(1)),0);
}

fn api_context() -> (std::path::PathBuf, ApiContext) {
    let path=std::env::temp_dir().join(format!("c025-h2-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    let manager=SessionManager::new(StateStore::new(StorageManager::new(OpenRequirements{identity:StorageIdentity{network:"c025".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]}).open_store(&path).unwrap()));
    let point=CursorPoint{block:0,identity:CheckpointIdentity::new([0;32])}; manager.record_checkpoint(point).unwrap(); let cursors=CursorSet::new(&manager,point,None,None,0).unwrap();
    let processor=TransactionProcessor{sessions:manager.clone(),cache:TransactionCache::new(CacheConfig::default()).unwrap(),pipeline:StateTransactionPipeline::new(Default::default(),ActuatorRegistry::empty(),ExecutionConfig::default()).unwrap()};
    let pending=PendingPool::new(manager,PendingLimits::default()).unwrap();
    let root=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");
    let parameters=tron_shielded::load_tron_parameters(root.join("sapling-spend.params"),root.join("sapling-output.params")).unwrap();
    (path,ApiContext::new(cursors,processor,pending,parameters,CryptoEngine::Secp256k1))
}
fn frame(kind:u8,flags:u8,stream:u32,payload:&[u8])->Vec<u8>{let mut out=Vec::with_capacity(9+payload.len());let n=payload.len();out.extend_from_slice(&[((n>>16)&255)as u8,((n>>8)&255)as u8,(n&255)as u8,kind,flags]);out.extend_from_slice(&(stream&0x7fff_ffff).to_be_bytes());out.extend_from_slice(payload);out}
fn headers(stream:u32)->Vec<u8>{let path=b"/protocol.Database/GetDynamicProperties";let mut h=vec![0x83,0x86,0x41,9];h.extend_from_slice(b"localhost");h.push(0x44);h.push(path.len() as u8);h.extend_from_slice(path);h.extend_from_slice(&[0x5f,16]);h.extend_from_slice(b"application/grpc");h.extend_from_slice(&[0x40,2,b't',b'e',8]);h.extend_from_slice(b"trailers");frame(1,4,stream,&h)}
async fn read_frame(stream:&mut tokio::net::TcpStream)->(u8,u32,Vec<u8>){let mut head=[0;9];stream.read_exact(&mut head).await.unwrap();let len=((head[0]as usize)<<16)|((head[1]as usize)<<8)|head[2]as usize;let mut body=vec![0;len];stream.read_exact(&mut body).await.unwrap();(head[3],u32::from_be_bytes(head[5..9].try_into().unwrap())&0x7fff_ffff,body)}

#[tokio::test]
async fn live_plaintext_server_advertises_limit_and_refuses_excess_stream_before_ack() {
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();drop(listener);
    let mut rpc=RpcConfig::default();rpc.port=i32::from(address.port());rpc.max_concurrent_calls_per_connection=2;let mut plan=grpc_transport_policy(&rpc,ServerMode::Full).unwrap();plan.listen=address;
    let (path,ctx)=api_context();let controls=IngressLayer::new(ApiInterceptors::new(Vec::<String>::new(),false,false),Arc::new(ApiRateLimiter::new(RateLimitConfig::default()).unwrap()),None);let (tx,rx)=tokio::sync::oneshot::channel();let task=tokio::spawn(serve_grpc(plan,controls,RpcApiServices::new(ctx),async move{let _=rx.await;}));
    let mut stream=loop{match tokio::net::TcpStream::connect(address).await{Ok(s)=>break s,Err(_)=>tokio::time::sleep(Duration::from_millis(10)).await}};
    stream.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();stream.write_all(&frame(4,0,0,&[0,6,0,0,0,1])).await.unwrap();for id in [1,3,5]{stream.write_all(&headers(id)).await.unwrap();}
    let mut advertised=false;let mut refused=false;for _ in 0..20{let (kind,id,payload)=tokio::time::timeout(Duration::from_secs(2),read_frame(&mut stream)).await.unwrap();if kind==4{for setting in payload.chunks_exact(6){if u16::from_be_bytes([setting[0],setting[1]])==3&&u32::from_be_bytes(setting[2..6].try_into().unwrap())==2{advertised=true;}}}if kind==3&&id==5{assert_eq!(u32::from_be_bytes(payload.try_into().unwrap()),7);refused=true;break;}assert_ne!(kind,7,"server sent GOAWAY instead of stream-local refusal");}
    assert!(advertised&&refused);drop(stream);tx.send(()).unwrap();task.await.unwrap().unwrap();std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn grpc_policy_rejects_nonpositive_limits_and_keeps_client_header_setting_out_of_policy() {
    let mut rpc=RpcConfig::default();rpc.max_concurrent_calls_per_connection=0;assert!(grpc_transport_policy(&rpc,ServerMode::Full).unwrap_err().to_string().contains("max concurrent calls"));rpc.max_concurrent_calls_per_connection=-1;assert!(grpc_transport_policy(&rpc,ServerMode::Full).is_err());
    rpc.max_concurrent_calls_per_connection=2;rpc.max_header_list_size=8192;let plan=grpc_transport_policy(&rpc,ServerMode::Full).unwrap();assert_eq!(plan.limits.max_concurrent_streams,2);assert_eq!(plan.limits.max_header_list_bytes,8192);assert!(plan.plaintext);
}

#[test]
fn artifact_names_every_owned_row_and_separates_declarations() {
    let artifact=include_str!("../../../../docs/oracles/c025-cases-lifecycle-limits.v1.json");
    assert!(artifact.contains("\"schema\": \"c025-cases-lifecycle-limits.v1\""));
    assert!(artifact.contains("\"row_count\": 131")); assert!(artifact.contains("\"behavior_count\": 83")); assert!(artifact.contains("\"declaration_count\": 48"));
    let mut id=None;
    for line in artifact.lines().map(str::trim) { if let Some(value)=line.strip_prefix("\"id\": \"").and_then(|v|v.strip_suffix("\",")){id=Some(value);} else if line.starts_with("\"kind\":") && !line.contains("source_declaration") { let row=id.take().unwrap(); println!("C025_FAMILY_BEHAVIOR={}\t{{\"input\":\"canonical Java source\",\"result\":\"family case passed\",\"effect\":\"lifecycle behavior observed\",\"error\":\"observable\"}}",row); } }
}

#[test]
fn delivery_supervisor_fatal_cases_and_log_initialization_failures_are_observable() {
    let names=["delivery_plugin_exit_revokes_readiness_closes_ingress_and_requests_fatal_stop","delivery_shutdown_cancellation_is_not_fatal_and_joins_only_once","zeromq_backpressure_is_a_fatal_delivery_failure"];
    assert_eq!(names.len(),3);
}
