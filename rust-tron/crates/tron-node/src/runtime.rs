use std::{collections::{BTreeMap, BTreeSet, HashSet}, net::SocketAddr, sync::{Arc, Mutex, Weak}, time::{Duration, Instant}};

use tokio::{net::{TcpListener, UdpSocket}, sync::watch, task::JoinHandle};
use tron_apis::{
    ActorExecutionProvider, ApiContext, ApiRateLimiter, FilterLimits, FilterManager, GrpcServerPlan,
    HttpServerConfig, HttpServerPlan, JsonRpcServerConfig, JsonRpcServerSet, JsonRpcSurface,
    NodeInfoSnapshot, ProductionNetworkSnapshot, RpcApiServices, ServerMode,
    http_filters::HttpControls,
    http_router::{HttpRouteState, http_router},
    http_routes::HttpSurface,
    interceptors::{ApiInterceptors, IngressLayer},
    rate_limit::RateLimitConfig,
    server::serve_grpc_with_listener,
    server::{ApiService, TransportLimits},
};
use prost::Message;
use tron_crypto::{CryptoEngine, DuplicateSignerPolicy, Sha256Provider, Sm3Provider};
use tron_events_metrics::{DbStatService, EventQueues, MonitorMetrics, QueueLimits, ZeroMqConfig};
use tron_execution::{ActuatorRegistry, AdmissionPolicy, BlockLimits, BlockManager, CacheConfig, CanonicalChainManager, ChainActor, ChainActorHandle, ExecutionConfig, ExecutionRuntimeConfig, PendingLimits, PendingPool, RawBlock, RawWireTransaction, StateTransactionPipeline, TransactionCache, TransactionProcessor};
use tron_consensus::{BackupRole, BackupRoleHandle, ConsensusRead, ConsensusRewardCallback, ProductionBlockConsensus, ProductionBlockHooks, backup::{BackupConfig, BackupService, BackupStatus}};
use tron_state::{dynamic, CheckpointIdentity, CheckpointLimits, CursorSet, CursorView, GenesisConfig, GenesisInit, StateLifecycle, StateStore, StoreKind};
use tron_network::{
    app_hello::AppHello,
    backup_auth::HmacSha256DatagramAuthenticator,
    connection::{Direction, PoolConfig},
    discovery::SecureSocketFactory,
    handshake::AdmissionConfig,
    production::{ActorBlockSink, ActorTransactionSink, CanonicalNetworkView, NetworkBroadcaster, ProductionDiscoveryConfig, ProductionNetwork, ProductionNetworkConfig, ProductionPbftConfig},
    session::{SessionClock, SessionConfig, SystemSessionClock},
    handlers::PbftHandler,
};

use crate::{
    ALL_NODE_MODES, CancellationToken, CONSENSUS_DEPS, EXECUTION_DEPS, FULL_API_DEPS,
    LifecycleFuture, MonotonicClock, NETWORK_DEPS, NodeContext, NodeService, SOLIDITY_API_DEPS,
    STATE_DEPS, ServiceFailure, ServiceMode, ServiceSpec,
    admin_http::{AdminHttpConfig, AdminHttpService},
    deployment::{DeploymentError, DeploymentMode, PreparedDeployment},
    operations::{
        API_SERVICE, NETWORK_SERVICE, NodeStatus, ProductionCoreServices, ProductionNode,
        ProductionNodeDependencies, ProductionOperationalBindings, ProductionOperationsConfig,
    },
    solidity_replica::VerifiedBlockApplier,
};

struct RuntimeClock(Instant);
impl MonotonicClock for RuntimeClock { fn elapsed(&self) -> Duration { self.0.elapsed() } }


struct ExecutionActorService { actor: Arc<Mutex<Option<ChainActor>>> }
impl NodeService for ExecutionActorService {
    fn spec(&self)->ServiceSpec{ServiceSpec::new(crate::EXECUTION_SERVICE,EXECUTION_DEPS,ALL_NODE_MODES)}
    fn start<'a>(&'a mut self,_:&'a NodeContext,_:Duration)->LifecycleFuture<'a>{Box::pin(async{Ok(())})}
    fn stop<'a>(&'a mut self,_:&'a NodeContext,_:Duration)->LifecycleFuture<'a>{Box::pin(async move{
        let actor=self.actor.lock().map_err(|_|ServiceFailure{service:crate::EXECUTION_SERVICE,message:"execution actor lock poisoned".into()})?.take();
        if let Some(actor)=actor{tokio::task::spawn_blocking(move||actor.shutdown()).await.map_err(|e|ServiceFailure{service:crate::EXECUTION_SERVICE,message:e.to_string()})?.map_err(|e|ServiceFailure{service:crate::EXECUTION_SERVICE,message:e.to_string()})?;} Ok(())
    })}
}

struct DurableStateService { lifecycle: StateLifecycle }
impl NodeService for DurableStateService {
    fn spec(&self)->ServiceSpec{ServiceSpec::new(crate::STATE_SERVICE,STATE_DEPS,ALL_NODE_MODES)}
    fn start<'a>(&'a mut self,_:&'a NodeContext,_:Duration)->LifecycleFuture<'a>{Box::pin(async{Ok(())})}
    fn stop<'a>(&'a mut self,_:&'a NodeContext,_:Duration)->LifecycleFuture<'a>{Box::pin(async move{self.lifecycle.shutdown(false).map_err(|e|ServiceFailure{service:crate::STATE_SERVICE,message:e.to_string()})})}
}


struct ConsensusService { backup:Option<Arc<Mutex<BackupService>>>, role:BackupRoleHandle, cancel:tokio_util::sync::CancellationToken, role_task:Option<JoinHandle<Result<(),String>>> }
impl NodeService for ConsensusService {
    fn spec(&self)->ServiceSpec{ServiceSpec::new(crate::CONSENSUS_SERVICE,CONSENSUS_DEPS,ALL_NODE_MODES)}
    fn start<'a>(&'a mut self,_:&'a NodeContext,_:Duration)->LifecycleFuture<'a>{Box::pin(async move{
        let Some(backup)=self.backup.as_ref()else{return Ok(())};
        backup.lock().map_err(|_|ServiceFailure{service:crate::CONSENSUS_SERVICE,message:"backup service lock poisoned".into()})?.start().map_err(|error|ServiceFailure{service:crate::CONSENSUS_SERVICE,message:error.to_string()})?;
        self.cancel=tokio_util::sync::CancellationToken::new();let cancel=self.cancel.clone();let backup=backup.clone();let role=self.role.clone();
        self.role_task=Some(tokio::spawn(async move{loop{tokio::select!{_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_millis(10))=>{let status=backup.lock().map_err(|_|"backup service lock poisoned".to_owned())?.status();role.set_role(if status==BackupStatus::MASTER{BackupRole::Master}else{BackupRole::Backup}).map_err(|error|error.to_string())?;}}}}));
        Ok(())
    })}
    fn stop<'a>(&'a mut self,_:&'a NodeContext,_:Duration)->LifecycleFuture<'a>{Box::pin(async move{
        self.cancel.cancel();
        if let Some(task)=self.role_task.take(){task.await.map_err(|error|ServiceFailure{service:crate::CONSENSUS_SERVICE,message:error.to_string()})?.map_err(|message|ServiceFailure{service:crate::CONSENSUS_SERVICE,message})?;}
        if let Some(backup)=self.backup.as_ref(){backup.lock().map_err(|_|ServiceFailure{service:crate::CONSENSUS_SERVICE,message:"backup service lock poisoned".into()})?.close();}
        self.role.set_role(BackupRole::Backup).map_err(|error|ServiceFailure{service:crate::CONSENSUS_SERVICE,message:error.to_string()})?;Ok(())
    })}
}
struct ActorVerifiedBlockApplier { actor: ChainActorHandle, limits: BlockLimits }
impl VerifiedBlockApplier for ActorVerifiedBlockApplier {
    fn apply_verified<'a>(&'a mut self,block:tron_protocol::protocol::Block)->crate::solidity_replica::ReplicaFuture<'a,i64>{
        let actor=self.actor.clone();let limits=self.limits;Box::pin(async move{
            let height=block.block_header.as_ref().and_then(|header|header.raw_data.as_ref()).map(|raw|raw.number).ok_or("replicated block has no header")?;
            let now=block.block_header.as_ref().and_then(|header|header.raw_data.as_ref()).map(|raw|raw.timestamp).ok_or("replicated block has no timestamp")?;
            let raw=RawBlock::decode(block.encode_to_vec(),limits).map_err(|e|e.to_string())?;
            tokio::task::spawn_blocking(move||actor.apply_replica_block(raw,now)).await.map_err(|e|e.to_string())?.map_err(|e|e.to_string())?;
            Ok(height)
        })
    }
}

struct CanonicalApiService {
    mode: DeploymentMode,
    context: ApiContext,
    services: RpcApiServices,
    listeners: BTreeMap<String, TcpListener>,
    filters: Arc<FilterManager>,
    tasks: Vec<JoinHandle<Result<(), String>>>,
    shutdown: Option<watch::Sender<bool>>,
}
impl CanonicalApiService {
    fn new(mode: DeploymentMode, context: ApiContext, services: RpcApiServices, listeners: BTreeMap<String, TcpListener>, filters: Arc<FilterManager>) -> Self {
        Self { mode, context, services, listeners, tasks: Vec::new(), shutdown: None, filters }
    }
}
pub const fn canonical_api_service_spec(mode: DeploymentMode) -> ServiceSpec {
    let dependencies = match mode {
        DeploymentMode::Full => FULL_API_DEPS,
        DeploymentMode::Solidity => SOLIDITY_API_DEPS,
    };
    ServiceSpec::new(API_SERVICE, dependencies, ALL_NODE_MODES)
}

impl NodeService for CanonicalApiService {
    fn spec(&self) -> ServiceSpec { canonical_api_service_spec(self.mode) }
    fn start<'a>(&'a mut self, _: &'a NodeContext, _: Duration) -> LifecycleFuture<'a> { Box::pin(async move {
        let (shutdown, receiver) = watch::channel(false);
        self.shutdown = Some(shutdown);
        let limiter = Arc::new(ApiRateLimiter::new(RateLimitConfig::default()).map_err(|error| ServiceFailure { service: API_SERVICE, message: error.to_string() })?);
        let ingress = IngressLayer::new(ApiInterceptors::new(Vec::<String>::new(), false, false), limiter.clone(), Some(Duration::from_secs(30)));
        if let Some(listener) = self.listeners.remove("grpc") {
            let listen = listener.local_addr().map_err(|error| ServiceFailure { service: API_SERVICE, message: error.to_string() })?;
            let server_mode = if self.mode == DeploymentMode::Full { ServerMode::Full } else { ServerMode::StandaloneSolidity };
            let mut enabled = BTreeSet::from([ApiService::Database]);
            if self.mode == DeploymentMode::Full { enabled.extend([ApiService::Wallet, ApiService::Network, ApiService::TronZksnark]); }
            else { enabled.insert(ApiService::WalletSolidity); }
            let plan = GrpcServerPlan { mode: server_mode, listen, plaintext: true, services: enabled, limits: TransportLimits { max_request_bytes: 4_194_304, max_response_bytes: 4_194_304, max_concurrent_streams: 100, max_header_list_bytes: 8192, initial_connection_window_bytes: 1_048_576, connection_idle: Some(Duration::from_secs(30)), connection_age: Some(Duration::from_secs(300)), request_deadline: Some(Duration::from_secs(30)) } };
            let services = self.services.clone(); let mut stop = receiver.clone(); let ingress = ingress.clone();
            self.tasks.push(tokio::spawn(async move { serve_grpc_with_listener(plan, listener, ingress, services, async move { let _ = stop.changed().await; }).await.map_err(|e| e.to_string()) }));
        }
        if let Some(listener) = self.listeners.remove("http") {
            let bind = listener.local_addr().map_err(|error| ServiceFailure { service: API_SERVICE, message: error.to_string() })?;
            let controls = HttpControls::default();
            let state = HttpRouteState::new(self.services.clone(), controls.clone(), limiter.clone(), Duration::from_secs(30), false);
            let surface = if self.mode == DeploymentMode::Full { HttpSurface::Full } else { HttpSurface::Solidity };
            let mut config = HttpServerConfig::new(bind); config.controls = controls;
            let plan = HttpServerPlan::new(config, http_router(state, surface)); let stop = receiver.clone();
            self.tasks.push(tokio::spawn(async move { plan.serve_listener(listener, stop).await.map_err(|e| e.to_string()) }));
        }
        if let Some(listener) = self.listeners.remove("jsonrpc") {
            if self.mode == DeploymentMode::Full {
                let bind = listener.local_addr().map_err(|error| ServiceFailure { service: API_SERVICE, message: error.to_string() })?;
                let mut config = JsonRpcServerConfig::default(); config.bind_ip = bind.ip(); config.full_enabled = true; config.solidity_enabled = false; config.pbft_enabled = false; config.full_port = bind.port();
                let set = JsonRpcServerSet::new(config, self.context.clone(), Default::default(), self.filters.clone()).map_err(|message| ServiceFailure { service: API_SERVICE, message })?;
                let bound = set.bind_prebound(BTreeMap::from([(JsonRpcSurface::Full, listener)])).map_err(|error| ServiceFailure { service: API_SERVICE, message: error.to_string() })?;
                let stop = receiver.clone();
                self.tasks.push(tokio::spawn(async move { bound.start_bound(stop).await.map_err(|e| e.to_string()) }));
            }
        }
        Ok(())
    }) }
    fn stop<'a>(&'a mut self, _: &'a NodeContext, _: Duration) -> LifecycleFuture<'a> { Box::pin(async move {
        if let Some(shutdown) = self.shutdown.take() { let _ = shutdown.send(true); }
        for task in self.tasks.drain(..) { task.await.map_err(|e| ServiceFailure { service: API_SERVICE, message: e.to_string() })?.map_err(|message| ServiceFailure { service: API_SERVICE, message })?; }
        Ok(())
    }) }
}

struct RuntimeNetworkBroadcaster(Mutex<Weak<ProductionNetwork>>);
impl NetworkBroadcaster for RuntimeNetworkBroadcaster {
    fn broadcast(&self,message:tron_network::app_message::AppMessage,except:SocketAddr){if let Some(network)=self.0.lock().expect("network broadcaster poisoned").upgrade(){network.broadcast(message,except)}}
    fn start_sync(&self,_peer:SocketAddr){}
}
struct RuntimeCanonicalNetworkView { cursors: CursorSet }
impl CanonicalNetworkView for RuntimeCanonicalNetworkView {
    fn head_number(&self)->i64{i64::try_from(self.cursors.head().point().block).unwrap_or(i64::MAX)}
    fn has_parent(&self,block:&RawBlock,_:CryptoEngine)->bool{let Some(raw)=block.message.block_header.as_ref().and_then(|header|header.raw_data.as_ref())else{return false};raw.number==self.head_number().saturating_add(1)&&raw.parent_hash.as_slice()==self.cursors.head().point().identity.bytes()}
}
struct ProductionNetworkNodeService { network: Option<Arc<ProductionNetwork>>, cancel:tokio_util::sync::CancellationToken, fatal_task:Option<JoinHandle<Result<(),String>>> }
impl NodeService for ProductionNetworkNodeService {
    fn spec(&self) -> ServiceSpec { ServiceSpec::new(NETWORK_SERVICE, NETWORK_DEPS, &[ServiceMode::Full]) }
    fn start<'a>(&'a mut self, _: &'a NodeContext, _: Duration) -> LifecycleFuture<'a> { Box::pin(async move {let Some(network)=self.network.as_ref()else{return Ok(())};network.start().map_err(|error|ServiceFailure{service:NETWORK_SERVICE,message:error.to_string()})?;self.cancel=tokio_util::sync::CancellationToken::new();let cancel=self.cancel.clone();let network=network.clone();self.fatal_task=Some(tokio::spawn(async move{tokio::select!{biased;_=cancel.cancelled()=>Ok(()),fatal=network.next_fatal()=>Err(fatal.unwrap_or_else(||"production network fatal channel closed".into()))}}));Ok(())}) }
    fn stop<'a>(&'a mut self, _: &'a NodeContext, deadline: Duration) -> LifecycleFuture<'a> { Box::pin(async move {self.cancel.cancel();let shutdown=if let Some(network)=self.network.as_ref(){network.shutdown_with_timeout(deadline).await.map_err(|error|ServiceFailure{service:NETWORK_SERVICE,message:error.to_string()})}else{Ok(())};let fatal=if let Some(mut task)=self.fatal_task.take(){match tokio::time::timeout(deadline,&mut task).await{Ok(result)=>result.map_err(|error|ServiceFailure{service:NETWORK_SERVICE,message:error.to_string()})?.map_err(|message|ServiceFailure{service:NETWORK_SERVICE,message}),Err(_)=>{task.abort();let _=task.await;Err(ServiceFailure{service:NETWORK_SERVICE,message:"network fatal monitor shutdown deadline elapsed".into()})}}}else{Ok(())};shutdown.and(fatal)}) }
}

pub struct RuntimeAssembly { prepared: PreparedDeployment, node: ProductionNode }
pub struct RuntimeFactory;
impl RuntimeFactory {
    pub async fn prepare(prepared: PreparedDeployment) -> Result<RuntimeAssembly, DeploymentError> {
        let mut listeners = BTreeMap::new();
        for (name, policy) in &prepared.deployment.listeners {
            if matches!(name.as_str(), "admin"|"grpc"|"http"|"jsonrpc"|"p2p")&&!(name=="p2p"&&(prepared.config.node.p2p_disable||prepared.deployment.mode!=DeploymentMode::Full)) {
                let address:SocketAddr=policy.bind.parse().map_err(|_| DeploymentError{category:"listener",message:format!("invalid bind for {name}")})?;
                listeners.insert(name.clone(), TcpListener::bind(address).await.map_err(|e|DeploymentError{category:"listener_bind",message:format!("{name}: {e}")})?);
            }
        }
        let store = tron_storage::StorageManager::new(prepared.open_requirements.clone()).open_store(&prepared.deployment.paths.data_directory).map_err(|e|DeploymentError{category:"storage",message:e.to_string()})?;
        let max_flush_count=usize::try_from(prepared.config.storage.snapshot.max_flush_count).ok().filter(|value|*value>0).ok_or_else(||DeploymentError{category:"state",message:"storage.snapshot.maxFlushCount must be positive".into()})?;
        let state=StateStore::new(store);
        let lifecycle=StateLifecycle::new(state.clone(),CheckpointLimits{max_flush_count,..CheckpointLimits::default()});
        let pbft_state=state.clone();
        let sessions=lifecycle.sessions();
        let recovered=lifecycle.recover_and_relink().map_err(|e|DeploymentError{category:"state",message:e.to_string()})?;
        let engine=CryptoEngine::from_java_name(&prepared.config.misc.crypto_engine);
        let genesis_config=GenesisConfig::from_java_config(&prepared.config.genesis.block,engine).map_err(|e|DeploymentError{category:"genesis",message:e.to_string()})?;
        let initialized=match engine { CryptoEngine::Secp256k1=>lifecycle.initialize_genesis(&genesis_config,&Sha256Provider), CryptoEngine::Sm2=>lifecycle.initialize_genesis(&genesis_config,&Sm3Provider) }.map_err(|e|DeploymentError{category:"genesis",message:e.to_string()})?;
        let genesis_id=match initialized { GenesisInit::Created(id)|GenesisInit::Existing(id)=>id };
        let genesis=tron_state::CursorPoint{block:0,identity:CheckpointIdentity::new(genesis_id.as_bytes().try_into().map_err(|_|DeploymentError{category:"genesis",message:"genesis block id is not 32 bytes".into()})?)};
        if matches!(initialized,GenesisInit::Created(_)) {
            dynamic::initialize_missing(&state.store(StoreKind::DynamicProperties),&dynamic::DynamicPropertyConfig::from(prepared.config.as_ref()),genesis_config.timestamp().map_err(|e|DeploymentError{category:"genesis",message:e.to_string()})?,&dynamic::ACTIVE_DEFAULT_OPERATIONS).map_err(|e|DeploymentError{category:"state",message:e.to_string()})?;
            sessions.record_checkpoint(genesis).map_err(|e|DeploymentError{category:"state",message:e.to_string()})?;
            lifecycle.checkpoints().persist().map_err(|e|DeploymentError{category:"state",message:e.to_string()})?;
        } else if recovered.is_none() {
            let head=sessions.read_view().store(StoreKind::DynamicProperties).get(dynamic::key("LATEST_BLOCK_HEADER_NUMBER").expect("known dynamic key")).and_then(|bytes|bytes.as_slice().try_into().ok()).map(i64::from_be_bytes).unwrap_or(0);
            if head!=0{return Err(DeploymentError{category:"state",message:"advanced durable state has no checkpoint metadata".into()});}
            sessions.record_checkpoint(genesis).map_err(|e|DeploymentError{category:"state",message:e.to_string()})?;
            lifecycle.checkpoints().persist().map_err(|e|DeploymentError{category:"state",message:e.to_string()})?;
        }
        let cursors=CursorSet::reconstruct(&sessions).map_err(|e|DeploymentError{category:"state",message:e.to_string()})?;
        let network_cursors=cursors.clone();
        let actuators=Arc::new(ActuatorRegistry::new([],[],&BTreeSet::new()).map_err(|e|DeploymentError{category:"execution",message:format!("{e:?}")})?);
        let operation_registry=Arc::new(tron_tvm::OperationRegistry::integration().map_err(|e|DeploymentError{category:"execution",message:format!("{e:?}")})?);
        let blackhole=genesis_config.assets.iter().find(|asset|asset.account_name==b"Blackhole").map(|asset|asset.address.clone()).ok_or_else(||DeploymentError{category:"genesis",message:"genesis Blackhole account is missing".into()})?;
        let guard_representatives=genesis_config.witnesses.iter().map(|witness|witness.address.clone()).collect::<BTreeSet<_>>();
        let checkpoints=lifecycle.checkpoints();
        let replica_sessions=sessions.clone();
        let queues=EventQueues::shared(QueueLimits::default());
        let metrics=Arc::new(MonitorMetrics::new(prepared.config.node.metrics_enable||prepared.config.node.metrics.prometheus.enable));
        let filters=FilterManager::shared(FilterLimits::default());
        let context=NodeContext::new(prepared.config.clone(),CancellationToken::default(),Arc::new(RuntimeClock(Instant::now())));
        let mode=prepared.deployment.mode;
        let prometheus_address=prepared.deployment.listeners.get("prometheus").and_then(|p|p.bind.parse().ok());
        let zeromq_config=prepared.deployment.listeners.get("zeromq").and_then(|p|p.bind.parse::<SocketAddr>().ok()).map(|a|ZeroMqConfig{bind_ip:a.ip(),bind_port:a.port(),send_hwm:1000});
        let backup_keyring=prepared.backup_keyring.clone();
        let backup_listener=prepared.deployment.listeners.get("backup").and_then(|policy|policy.bind.parse::<SocketAddr>().ok());
        let admin_listener=listeners.remove("admin");
        let p2p=listeners.remove("p2p");
        let p2p_udp=if mode==DeploymentMode::Full&&!prepared.config.node.p2p_disable{if let Some(listener)=p2p.as_ref(){Some(UdpSocket::bind(listener.local_addr().map_err(|e|DeploymentError{category:"listener",message:e.to_string()})?).await.map_err(|e|DeploymentError{category:"listener_bind",message:format!("p2p udp: {e}")})?)}else{None}}else{None};
        let operations_zeromq=zeromq_config.clone();
        let peer_store_path=prepared.deployment.paths.data_directory.join("peers.json");
        let chain_config=prepared.config.clone();
        let parameters=prepared.parameters.clone();
        let backup_role=BackupRoleHandle::new(BackupRole::Backup);
        let runtime_backup=if prepared.config.node.witness{
            let endpoint=backup_listener.ok_or_else(||DeploymentError{category:"backup_auth",message:"witness backup listener is not configured".into()})?;
            let keyring=backup_keyring.ok_or_else(||DeploymentError{category:"backup_auth",message:"witness backup keyring is not configured".into()})?;
            let auth=HmacSha256DatagramAuthenticator::new(keyring).map_err(|message|DeploymentError{category:"backup_auth",message})?;
            let mut backup_config=BackupConfig::from_node_config(endpoint.ip(),endpoint.ip(),&prepared.config.node.backup).map_err(|error|DeploymentError{category:"backup_auth",message:error.to_string()})?;
            backup_config.bind=endpoint;
            Some(Arc::new(Mutex::new(BackupService::production(backup_config,Arc::new(SecureSocketFactory::new(Arc::new(auth)))))))
        }else{None};
        let dependencies=ProductionNodeDependencies {
            context,
            mode: mode.node_mode(),
            core_factory: Box::new(move |status,stop| {
                let runtime_config=ExecutionRuntimeConfig{actuator_registry:actuators.clone(),operation_registry,shielded_parameters:parameters.clone(),execution_config:ExecutionConfig{blackhole_address:blackhole,reward_callback:Some(Arc::new(ConsensusRewardCallback)),guard_representatives},constant_call_timeout:(chain_config.vm.constant_call_timeout_ms>0).then(||Duration::from_millis(chain_config.vm.constant_call_timeout_ms as u64)),deadline_observer:None};
                let admission=AdmissionPolicy{engine,consensus_logic_optimization:chain_config.committee.remaining.get("allowConsensusLogicOptimization").copied().unwrap_or(0)==1,duplicate_signer_policy:DuplicateSignerPolicy::RecoveredAddress,total_signature_limit:5,max_transaction_bytes:tron_execution::TRANSACTION_MAX_BYTE_SIZE,expiration_horizon_millis:chain_config.misc.trx_expiration_time_in_milliseconds};
                let cache_config=CacheConfig{maximum_entries:usize::try_from(chain_config.node.max_trx_cache_size).map_err(|_|crate::LifecycleError::InvalidConfiguration("node.maxTrxCacheSize must be positive".into()))?,..CacheConfig::default()};
                let pending_limits=PendingLimits{maximum:usize::try_from(chain_config.node.max_transaction_pending_size).map_err(|_|crate::LifecycleError::InvalidConfiguration("node.maxTransactionPendingSize must be positive".into()))?,timeout_millis:chain_config.node.pending_transaction_timeout,shielded_maximum:usize::try_from(chain_config.node.shielded_trans_in_pending_max_counts).map_err(|_|crate::LifecycleError::InvalidConfiguration("node.shieldedTransInPendingMaxCounts must be nonnegative".into()))?,smart_drain_limit:100};
                let full=mode==DeploymentMode::Full;
                let block_limits=BlockLimits::default();
                let retained_depth=usize::try_from(chain_config.node.max_unsolidified_blocks).unwrap_or(54).max(1);
                let genesis_time=genesis_config.timestamp().map_err(|e|crate::LifecycleError::InvalidConfiguration(e.to_string()))?;
                let actor_sessions=replica_sessions.clone();let actor_genesis=genesis_config.clone();let actor_events=queues.sink();let actor_filters=filters.sink();
                let actor_backup_role=backup_role.clone();
                let consensus_backup=runtime_backup.clone();
                let hooks=ProductionBlockHooks::from_config(chain_config.as_ref(),&actor_genesis,actor_backup_role.clone()).map_err(|e|crate::LifecycleError::InvalidConfiguration(e.to_string()))?;
                let pbft_handle=hooks.pbft_handle();
                let actor=ChainActor::spawn(move||{
                    let cache=TransactionCache::new(cache_config).map_err(|e|tron_execution::ChainManagerError::State(e.to_string()))?;
                    let processor=TransactionProcessor::new(actor_sessions.clone(),cache,StateTransactionPipeline::new(admission,runtime_config));
                    let consensus=ProductionBlockConsensus::new(actor_sessions.clone(),engine,genesis_time).map_err(|e|tron_execution::ChainManagerError::State(e.to_string()))?;
                    let hooks=hooks;
                    let blocks=BlockManager::reopen(actor_sessions.clone(),processor,consensus,hooks,block_limits,engine,retained_depth)?;
                    if full{let pending=PendingPool::<RawWireTransaction>::new(actor_sessions,pending_limits)?;Ok(CanonicalChainManager::new_full(blocks,pending,checkpoints,actor_events,actor_filters))}else{Ok(CanonicalChainManager::new_replica(blocks,checkpoints,actor_events,actor_filters))}
                },256).map_err(|e|crate::LifecycleError::InvalidConfiguration(e.to_string()))?;
                let actor_handle=actor.handle();
                let actor_owner=Arc::new(Mutex::new(Some(actor)));
                let execution=full.then(||Arc::new(ActorExecutionProvider::new(actor_handle.clone())) as Arc<dyn tron_apis::ExecutionProvider>);
                let network_snapshot=Arc::new(ProductionNetworkSnapshot::new(Arc::new(||tron_protocol::protocol::NodeList{nodes:Vec::new()}),Arc::new(|head,solid|NodeInfoSnapshot{begin_sync_num:i64::try_from(head).unwrap_or(i64::MAX),block:head.to_string(),solidity_block:solid.to_string(),..NodeInfoSnapshot::default()})));
                let api=ApiContext::with_providers(cursors,execution,actuators,network_snapshot,None,parameters,engine);
                let node_api=api.clone();
                let bindings=ProductionOperationalBindings::new(api,Arc::new(move||node_api.network().node_info(node_api.head().point().block,node_api.solidity().point().block).into_proto()),queues.clone(),filters.clone(),metrics.clone());
                let mut core_services:Vec<Box<dyn NodeService>>=vec![Box::new(DurableStateService{lifecycle}),Box::new(ExecutionActorService{actor:actor_owner}),Box::new(ConsensusService{backup:consensus_backup,role:actor_backup_role,cancel:tokio_util::sync::CancellationToken::new(),role_task:None})];
                if let Some(listener)=admin_listener{let bind=listener.local_addr().expect("prebound admin address");core_services.insert(0,Box::new(AdminHttpService::from_prebound(AdminHttpConfig{bind,max_request_bytes:8192,request_timeout:Duration::from_secs(2)},status.clone(),listener)));}
                let network=if let Some(listener)=p2p{
                    let bind=listener.local_addr().map_err(|error|crate::LifecycleError::InvalidConfiguration(error.to_string()))?;
                    let clock=Arc::new(SystemSessionClock);
                    let broadcaster=Arc::new(RuntimeNetworkBroadcaster(Mutex::new(Weak::new())));
                    let broadcaster_trait:Arc<dyn NetworkBroadcaster>=broadcaster.clone();
                    let view=Arc::new(RuntimeCanonicalNetworkView{cursors:network_cursors.clone()});
                    let head=network_cursors.head().point();let solid=network_cursors.solidity().point();
                    let block_id=|point:tron_state::CursorPoint|tron_protocol::protocol::hello_message::BlockId{hash:point.identity.bytes().to_vec(),number:i64::try_from(point.block).unwrap_or(i64::MAX)};
                    let node_id=[genesis.identity.bytes(),genesis.identity.bytes()].concat();
                    let endpoint=tron_protocol::protocol::Endpoint{address:match bind.ip(){std::net::IpAddr::V4(ip)=>ip.octets().to_vec(),std::net::IpAddr::V6(_)=>Vec::new()},port:i32::from(bind.port()),node_id:node_id.clone(),address_ipv6:match bind.ip(){std::net::IpAddr::V6(ip)=>ip.octets().to_vec(),std::net::IpAddr::V4(_)=>Vec::new()}};
                    let hello=tron_protocol::protocol::HelloMessage{from:Some(endpoint),version:chain_config.node.p2p.version,timestamp:genesis_time,genesis_block_id:Some(block_id(genesis)),solid_block_id:Some(block_id(solid)),head_block_id:Some(block_id(head)),code_version:env!("CARGO_PKG_VERSION").as_bytes().to_vec(),..Default::default()};
                    let transport_hello=tron_network::handshake::HelloMessage{from:Some(tron_network::handshake::Endpoint{address:bind.ip().to_string().into_bytes(),port:i32::from(bind.port()),node_id,address_ipv6:Vec::new()}),network_id:tron_network::production::MAINNET_NETWORK_ID,code:0,timestamp:genesis_time,version:chain_config.node.p2p.version};
                    let session=SessionConfig{local_hello:transport_hello,direction:Direction::Passive,admission:AdmissionConfig{network_id:tron_network::production::MAINNET_NETWORK_ID,version:chain_config.node.p2p.version,max_connections:usize::try_from(chain_config.node.max_connections).unwrap_or(30),max_same_ip:usize::try_from(chain_config.node.max_connections_with_same_ip).unwrap_or(2),trusted:HashSet::new(),ban_duration:Duration::from_secs(3600)},pool:PoolConfig{min_connections:usize::try_from(chain_config.node.min_connections).unwrap_or(8),max_connections:usize::try_from(chain_config.node.max_connections).unwrap_or(30),min_active:usize::try_from(chain_config.node.min_active_connections).unwrap_or(3),max_same_ip:usize::try_from(chain_config.node.max_connections_with_same_ip).unwrap_or(2),initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(60)},keepalive_interval:Duration::from_secs(10),pong_timeout:Duration::from_secs(10),write_timeout:Duration::from_secs(10),compression:true};
                    let head_number=Arc::new(move||i64::try_from(network_cursors.head().point().block).unwrap_or(i64::MAX));let id_cursors=view.cursors.clone();let genesis_hash:[u8;32]=genesis.identity.bytes().try_into().expect("genesis identity length");
                    let pbft=if pbft_handle.is_enabled(){let context_sessions=replica_sessions.clone();let maintenance_sessions=replica_sessions.clone();let persistence=Arc::new(tron_consensus::pbft::StatePbftPersistence::new(pbft_state.clone()));Some(ProductionPbftConfig{handler:Arc::new(Mutex::new(PbftHandler::from_shared(pbft_handle.sidecar()))),context:Arc::new(move|wire|{let message=tron_consensus::pbft::SignedMessage::decode(wire).map_err(|e|e.to_string())?;let view=context_sessions.read_view();let state=tron_consensus::StateView::new(view);let current=state.current_witnesses().map_err(|e|e.to_string())?;let proposer=message.recover_witness().map_err(|e|e.to_string())?;Ok(tron_consensus::pbft::PbftContext{now_millis:SystemSessionClock.unix_millis(),syncing:false,chain_switch:false,current_witnesses:current.clone(),before_witnesses:current,before_maintenance_time:0,local_signers:Vec::new(),expected_proposals:vec![tron_consensus::pbft::ExpectedProposal{data_type:message.raw.data_type,view_n:message.raw.view_n,epoch:message.raw.epoch,proposer,data:message.raw.data.clone()}]})}),persist:Arc::new(move|commit|tron_consensus::pbft::persist_commit(persistence.as_ref(),commit).map(|_|()).map_err(|e|e.to_string())),expire_blocks:27,next_maintenance:Arc::new(move||{let view=maintenance_sessions.read_view();view.store(StoreKind::DynamicProperties).get(dynamic::key("NEXT_MAINTENANCE_TIME").expect("known key")).and_then(|v|v.as_slice().try_into().ok()).map(i64::from_be_bytes).unwrap_or(0)}),maintenance_interval:21_600_000})}else{None};let discovery=if chain_config.node.discovery.enable{p2p_udp.map(|socket|ProductionDiscoveryConfig{socket,persist:chain_config.node.discovery.persist.then(||Arc::new(tron_network::persistence::JsonFilePeerStore::new(peer_store_path.clone())) as Arc<dyn tron_network::persistence::PeerStore>),refresh_interval:Duration::from_secs(5)})}else{None};let owner=ProductionNetwork::new(ProductionNetworkConfig{listener,discovery,active_nodes:chain_config.misc.seed_node.addresses.iter().filter_map(|address|address.parse().ok()).collect(),session,app_hello:AppHello::constructed(hello),transaction_sink:Box::new(ActorTransactionSink::new(actor_handle.clone(),broadcaster_trait.clone())),block_sink:Box::new(ActorBlockSink::new(actor_handle.clone(),view,broadcaster_trait,engine,clock.clone())),sync_head:head_number,sync_id_at:Arc::new(move|number|{let point=id_cursors.head().point();(i64::try_from(point.block).ok()==Some(number)).then(||tron_network::sync::SyncBlockId::new(point.identity.bytes().try_into().expect("cursor identity length"),number))}),sync_on_main:Arc::new(move|id|id.number==0&&id.hash==genesis_hash),pbft,clock,engine}).map_err(|error|crate::LifecycleError::InvalidConfiguration(error.to_string()))?;
                    *broadcaster.0.lock().expect("network broadcaster poisoned")=Arc::downgrade(&owner);Some(owner)
                }else{None};
                let network=Box::new(ProductionNetworkNodeService{network,cancel:tokio_util::sync::CancellationToken::new(),fatal_task:None});
                let apis=Box::new(CanonicalApiService::new(mode,bindings.api_context(),bindings.rpc_services(),listeners,filters.clone()));
                let _ = stop;
                let verified_block_applier=(!full).then(||Box::new(ActorVerifiedBlockApplier{actor:actor_handle,limits:block_limits}) as Box<dyn VerifiedBlockApplier>);
                Ok(ProductionCoreServices{bindings,core_services,network,apis,sessions:replica_sessions,verified_block_applier,queues,metrics:metrics.clone(),db_stats:DbStatService::new(metrics.prometheus().clone()),readiness:None})
            }),
        };
        let config=ProductionOperationsConfig{plugin:None,zeromq:operations_zeromq,prometheus_address};
        let node=ProductionNode::from_config(config,dependencies).map_err(|e|DeploymentError{category:"composition",message:e.to_string()})?;
        Ok(RuntimeAssembly{prepared,node})
    }
}
impl RuntimeAssembly {
    pub async fn start(&mut self)->Result<(),String>{self.node.start(Duration::from_secs(self.prepared.deployment.runtime_limits.startup_timeout_seconds),Duration::from_secs(self.prepared.deployment.runtime_limits.shutdown_timeout_seconds)).await.map_err(|e|e.to_string())}
    pub async fn shutdown(&mut self)->Result<(),String>{self.node.stop_handle().request(crate::operations::StopCondition::Operator).map_err(|_|"node stop controller closed".to_owned())?;self.node.wait_and_shutdown(Duration::from_secs(self.prepared.deployment.runtime_limits.shutdown_timeout_seconds)).await.map(|_|()).map_err(|e|e.to_string())}
    pub async fn wait_for_stop(&mut self)->Result<(),String>{self.node.wait_for_signal_and_shutdown(Duration::from_secs(self.prepared.deployment.runtime_limits.shutdown_timeout_seconds)).await.map(|_|()).map_err(|e|e.to_string())}
    pub fn status(&self)->NodeStatus{self.node.status()}
}

#[cfg(test)]
mod tests {
 use super::*;
 use tokio::io::{AsyncReadExt,AsyncWriteExt};
 use tron_state::{CursorPoint,SessionManager};
 fn context(name:&str)->(std::path::PathBuf,ApiContext){
  let path=std::env::temp_dir().join(format!("c028-runtime-{name}-{}",std::process::id()));let _=std::fs::remove_dir_all(&path);
  let requirements=tron_storage::OpenRequirements{identity:tron_storage::StorageIdentity{network:"mainnet".into(),genesis:"java-compatible".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]};
  let sessions=SessionManager::new(StateStore::new(tron_storage::StorageManager::new(requirements).open_store(&path).unwrap()));let point=CursorPoint{block:0,identity:CheckpointIdentity::new([0;32])};sessions.record_checkpoint(point).unwrap();let cursors=CursorSet::new(&sessions,point,Some(point),None,0).unwrap();
  let root=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");let parameters=tron_shielded::load_tron_parameters(root.join("sapling-spend.params"),root.join("sapling-output.params")).unwrap();
  (path,ApiContext::new(cursors,None,Arc::new(ActuatorRegistry::new([],[],&BTreeSet::new()).unwrap()),parameters,CryptoEngine::Secp256k1))
 }
 async fn request(address:SocketAddr,path:&str,body:Option<&str>)->String{let mut stream=tokio::net::TcpStream::connect(address).await.unwrap();let request=match body{Some(body)=>format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()),None=>format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")};stream.write_all(request.as_bytes()).await.unwrap();let mut bytes=Vec::new();stream.read_to_end(&mut bytes).await.unwrap();String::from_utf8(bytes).unwrap()}
 async fn drill(mode:DeploymentMode){let(path,api)=context(if mode==DeploymentMode::Full{"full"}else{"solidity"});let services=RpcApiServices::new(api.clone());let filters=FilterManager::shared(FilterLimits::default());let mut listeners=BTreeMap::new();listeners.insert("http".into(),TcpListener::bind("127.0.0.1:0").await.unwrap());let http=listeners["http"].local_addr().unwrap();let json=if mode==DeploymentMode::Full{let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();listeners.insert("jsonrpc".into(),listener);Some(address)}else{None};let mut service=CanonicalApiService::new(mode,api,services,listeners,filters);let node=NodeContext::new(Arc::new(tron_config::Config::default()),CancellationToken::default(),Arc::new(RuntimeClock(Instant::now())));service.start(&node,Duration::from_secs(1)).await.unwrap();tokio::time::sleep(Duration::from_millis(25)).await;
  let(full,solid)=if mode==DeploymentMode::Full{("200 OK","404 Not Found")}else{("404 Not Found","200 OK")};assert!(request(http,"/wallet/getnowblock",None).await.contains(full));assert!(request(http,"/walletsolidity/getnowblock",None).await.contains(solid));if let Some(json)=json{let rpc=request(json,"/",Some(r#"{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}"#)).await;assert!(rpc.contains("JavaTron"));}service.stop(&node,Duration::from_secs(1)).await.unwrap();std::fs::remove_dir_all(path).unwrap();}
 #[tokio::test] async fn full_uses_real_api_surface(){drill(DeploymentMode::Full).await}
 #[tokio::test] async fn solidity_uses_real_api_surface(){drill(DeploymentMode::Solidity).await}
}
