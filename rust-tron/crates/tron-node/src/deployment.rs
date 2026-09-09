use std::{collections::BTreeMap, fs, net::{IpAddr, SocketAddr}, path::{Path, PathBuf}, sync::Arc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tron_config::{toolkit::{toolkit_capabilities, validate_toolkit_backend, PlatformFacts, ToolkitBackend}, Config, ConfigLoader, ConfigSource, NodeMode, UnknownKeyPolicy};
use tron_crypto::{artifact_auth::{parse_trust_store, AuthLimits, TrustStoreV1}, keystore_store::list_keystores, CryptoEngine, Sha256Provider, Sm3Provider};
use tron_network::backup_auth::{parse_keyring, BackupPeerKeyring};
use tron_shielded::{load_tron_parameters, TronParameters};
use tron_state::{build_genesis, GenesisConfig, StoreKind};
use tron_storage::{format::{inspect_read_only, DirectoryClassification, OpenRequirements, StorageIdentity}};
use crate::build_info::{BuildIdentity, BUILD_IDENTITY};

const MAX_DEPLOYMENT_BYTES: u64 = 1_048_576;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)] #[serde(rename_all="lowercase")] pub enum DeploymentMode { Full, Solidity }
impl DeploymentMode { pub const fn node_mode(self)->NodeMode { match self { Self::Full=>NodeMode::Full, Self::Solidity=>NodeMode::Solidity } } }
#[derive(Clone, Debug, Deserialize, Serialize)] #[serde(deny_unknown_fields)] pub struct ExpectedRelease { pub release_id:String, pub minimum_release_sequence:u64 }
#[derive(Clone, Debug, Deserialize, Serialize)] #[serde(deny_unknown_fields)] pub struct PlatformSpec { pub schema_version:u32, pub id:String, pub os:String, pub architecture:String, pub target:String, pub backend:String, pub backend_format:String, pub features:Vec<String> }
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)] #[serde(rename_all="kebab-case")] pub enum ListenerSecurity { PlaintextLoopback, TronP2pPlaintext, HmacSha256V1OverPrivateTunnel }
#[derive(Clone, Debug, Deserialize, Serialize)] #[serde(deny_unknown_fields)] pub struct ListenerPolicy { pub bind:String, pub public:bool, pub security:ListenerSecurity }
#[derive(Clone, Debug, Deserialize, Serialize)] #[serde(deny_unknown_fields)] pub struct DeploymentPaths { pub chain_config:PathBuf, pub data_directory:PathBuf, pub install_receipt:PathBuf, pub keystore_directory:PathBuf, pub sapling_output:PathBuf, pub sapling_spend:PathBuf, #[serde(default)] pub backup_keyring:Option<PathBuf>, pub snapshot_trust_store:PathBuf, pub snapshot_watermark:PathBuf }
#[derive(Clone, Debug, Deserialize, Serialize)] #[serde(deny_unknown_fields)] pub struct RuntimeLimits { pub max_release_artifacts:usize, pub max_release_manifest_bytes:u64, pub max_snapshot_bytes:u64, pub max_trust_store_bytes:u64, pub shutdown_timeout_seconds:u64, pub startup_timeout_seconds:u64 }
#[derive(Clone, Debug, Deserialize, Serialize)] #[serde(deny_unknown_fields)] pub struct ProductionSecurity { pub allow_cli_witness_password:bool, pub allow_inline_witness_private_key:bool, pub allow_public_plaintext_api:bool, pub require_authenticated_backup_for_witness:bool, pub require_verified_install_receipt:bool }
#[derive(Clone, Debug, Deserialize, Serialize)] #[serde(deny_unknown_fields)] pub struct LoggingPolicy { pub destination:String, pub format:String, pub level:String }
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)] #[serde(deny_unknown_fields)] pub struct TrustedCheckpointConfig { pub height:u64, pub block_id:String, pub state_root:String }
#[derive(Clone, Debug, Deserialize, Serialize)] #[serde(deny_unknown_fields)] pub struct SnapshotPolicyConfig { pub future_clock_skew_seconds:u64, pub max_age_seconds:u64, pub max_manifest_bytes:u64, pub max_payload_bytes:u64, pub minimum_acceptable_height:u64, pub required_trust_store_version:u64, pub trusted_checkpoint:TrustedCheckpointConfig, pub required_stores:Vec<String> }
#[derive(Clone, Debug, Deserialize, Serialize)] #[serde(deny_unknown_fields)] pub struct DeploymentConfigV1 { pub schema:String, pub mode:DeploymentMode, pub expected_release:ExpectedRelease, pub platform:PlatformSpec, pub paths:DeploymentPaths, pub listeners:BTreeMap<String,ListenerPolicy>, pub runtime_limits:RuntimeLimits, pub production_security:ProductionSecurity, pub logging:LoggingPolicy, pub snapshot_policy:SnapshotPolicyConfig }
#[derive(Clone, Debug, Deserialize)] #[serde(deny_unknown_fields)] struct ReceiptFile { path:String, sha256:String, size:u64, mode:u32 }
#[derive(Clone, Debug, Deserialize)] #[serde(deny_unknown_fields)] struct InstallReceipt { schema:String, release_id:String, release_sequence:u64, platform_id:String, manifest_sha256:String, install_prefix:PathBuf, current_target:PathBuf, config_root:PathBuf, config_current_target:PathBuf, receipt_path:PathBuf, installed_at:String, files:Vec<ReceiptFile>, config_files:Vec<ReceiptFile> }
#[derive(Clone, Debug, Serialize)] pub struct PreflightReport { pub schema:&'static str, pub mode:DeploymentMode, pub release_id:String, pub platform_id:String, pub compatibility_storage_engine:String, pub physical_backend:&'static str, pub backend_format:&'static str, pub decision:&'static str, pub storage_classification:String, pub listeners:Vec<String> }
pub struct PreparedDeployment { pub deployment:DeploymentConfigV1, pub config:Arc<Config>, pub parameters:Arc<TronParameters>, pub open_requirements:OpenRequirements, pub trust_store:TrustStoreV1, pub backup_keyring:Option<BackupPeerKeyring>, pub report:PreflightReport }
#[derive(Debug)] pub struct DeploymentError { pub category:&'static str, pub message:String }
impl std::fmt::Display for DeploymentError { fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{write!(f,"{}: {}",self.category,self.message)} } impl std::error::Error for DeploymentError {}
fn error(category:&'static str, message:impl ToString)->DeploymentError{DeploymentError{category,message:message.to_string()}}
fn read_bounded(path:&Path, max:u64)->Result<Vec<u8>,DeploymentError>{let meta=fs::symlink_metadata(path).map_err(|e|error("io",e))?;if meta.file_type().is_symlink()||!meta.is_file(){return Err(error("path_policy","file must be regular and not a symlink"));}if meta.len()>max{return Err(error("resource_limit",format!("{} exceeds {} bytes",path.display(),max)));}fs::read(path).map_err(|e|error("io",e))}
pub fn load_deployment(path:impl AsRef<Path>)->Result<DeploymentConfigV1,DeploymentError>{let bytes=read_bounded(path.as_ref(),MAX_DEPLOYMENT_BYTES)?;let mut de=serde_json::Deserializer::from_slice(&bytes);let value=DeploymentConfigV1::deserialize(&mut de).map_err(|e|error("deployment_config",e))?;de.end().map_err(|e|error("deployment_config",e))?;if value.schema!="tron-deployment-v1"{return Err(error("deployment_config","schema must be tron-deployment-v1"));}Ok(value)}
fn absolute(paths:&DeploymentPaths)->Result<(),DeploymentError>{for path in [&paths.chain_config,&paths.data_directory,&paths.install_receipt,&paths.keystore_directory,&paths.sapling_output,&paths.sapling_spend,&paths.snapshot_trust_store,&paths.snapshot_watermark]{if !path.is_absolute(){return Err(error("path_policy",format!("path must be absolute: {}",path.display())));}}if let Some(path)=&paths.backup_keyring{if !path.is_absolute(){return Err(error("path_policy",format!("path must be absolute: {}",path.display())));}}Ok(())}
fn validate_listeners(mode:DeploymentMode, listeners:&BTreeMap<String,ListenerPolicy>, allow_public_api:bool)->Result<Vec<String>,DeploymentError>{let allowed_full=["admin","backup","grpc","http","jsonrpc","p2p","prometheus","zeromq"];let allowed_solidity=["admin","grpc","http","prometheus","zeromq"];let allowed=if mode==DeploymentMode::Full{&allowed_full[..]}else{&allowed_solidity[..]};let mut sockets=BTreeMap::new();for (name,p) in listeners {if !allowed.contains(&name.as_str()){return Err(error("mode_surface",format!("listener {name} is forbidden in {mode:?}")));}let addr:SocketAddr=p.bind.parse().map_err(|_|error("listener",format!("invalid socket address for {name}")))?;if sockets.insert(addr,name).is_some(){return Err(error("listener_collision",format!("duplicate bind {addr}")));}let loopback=addr.ip().is_loopback();match p.security { ListenerSecurity::PlaintextLoopback if !loopback && (!allow_public_api||!p.public)=>return Err(error("plaintext_exposure",format!("{name} plaintext must bind loopback"))), ListenerSecurity::TronP2pPlaintext if name!="p2p"=>return Err(error("listener_security","TRON plaintext is P2P-only")), ListenerSecurity::HmacSha256V1OverPrivateTunnel if name!="backup"=>return Err(error("listener_security","HMAC tunnel policy is backup-only")), _=>{} }if p.public && name!="p2p" && !allow_public_api{return Err(error("plaintext_exposure",format!("public {name} is forbidden")));}if name=="p2p" && !p.public{return Err(error("listener_security","P2P listener must be explicitly public"));}}
Ok(sockets.into_iter().map(|(a,n)|format!("{n}={a}")).collect())}
fn validate_configured_listener_ports(mode: DeploymentMode, listeners: &BTreeMap<String, ListenerPolicy>, config: &Config) -> Result<(), DeploymentError> {
    let expected = if mode == DeploymentMode::Full {
        vec![
            ("p2p", config.node.listen.port), ("backup", config.node.backup.port),
            ("grpc", config.node.rpc.port), ("http", config.node.http.full_node_port),
            ("jsonrpc", config.node.jsonrpc.http_full_node_port),
            ("prometheus", config.node.metrics.prometheus.port),
            ("zeromq", config.event.subscribe.native_queue.bindport),
        ]
    } else {
        vec![
            ("grpc", config.node.rpc.solidity_port), ("http", config.node.http.solidity_port),
            ("prometheus", config.node.metrics.prometheus.port),
            ("zeromq", config.event.subscribe.native_queue.bindport),
        ]
    };
    for (name, configured) in expected {
        let Some(policy) = listeners.get(name) else { continue };
        let bound: SocketAddr = policy.bind.parse().map_err(|_| error("listener", format!("invalid socket address for {name}")))?;
        let configured = u16::try_from(configured).ok().filter(|port| *port != 0)
            .ok_or_else(|| error("listener", format!("configured chain port for {name} is invalid")))?;
        if bound.port() != configured {
            return Err(error("listener", format!("deployment {name} port {} differs from chain config port {configured}", bound.port())));
        }
    }
    Ok(())
}

fn configured_genesis_id(config: &Config) -> Result<String, DeploymentError> {
    let engine = CryptoEngine::from_java_name(&config.misc.crypto_engine);
    let genesis = GenesisConfig::from_java_config(&config.genesis.block, engine).map_err(|e| error("genesis", e))?;
    let block = match engine {
        CryptoEngine::Secp256k1 => build_genesis(&genesis, &Sha256Provider),
        CryptoEngine::Sm2 => build_genesis(&genesis, &Sm3Provider),
    }.map_err(|e| error("genesis", e))?;
    Ok(block.id.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect())
}
fn validate_platform(spec:&PlatformSpec, build:BuildIdentity)->Result<(),DeploymentError>{if spec.schema_version!=1||spec.backend!="rustlog"||spec.backend_format!="rustlog-v1"||spec.features!=["rustlog-v1"]{return Err(error("platform","backend/platform feature identity mismatch"));}let caps=toolkit_capabilities(PlatformFacts::new(&spec.os,&spec.architecture,&spec.target));validate_toolkit_backend(&caps,ToolkitBackend::RustlogV1).map_err(|e|error("platform",e))?;if spec.id!=caps.platform_id||spec.id!=build.platform_id||spec.target!=build.target{return Err(error("platform","deployment, host capability, and build identity differ"));}Ok(())}
fn validate_secure_file(path:&Path)->Result<(),DeploymentError>{let metadata=fs::symlink_metadata(path).map_err(|e|error("io",e))?;if metadata.file_type().is_symlink()||!metadata.is_file(){return Err(error("path_policy",format!("{} must be a regular non-symlink file",path.display())));}#[cfg(unix)]{use std::os::unix::fs::MetadataExt;let mode=metadata.mode()&0o777;if mode&0o077!=0{return Err(error("permissions",format!("{} must not be accessible by group or others (mode {mode:04o})",path.display())));}}Ok(())}
fn validate_trust_store(deployment:&DeploymentConfigV1)->Result<TrustStoreV1,DeploymentError>{validate_secure_file(&deployment.paths.snapshot_trust_store)?;let bytes=read_bounded(&deployment.paths.snapshot_trust_store,deployment.runtime_limits.max_trust_store_bytes)?;let limits=AuthLimits{max_payload_bytes:deployment.runtime_limits.max_trust_store_bytes as usize,..AuthLimits::default()};let store=parse_trust_store(&bytes,limits).map_err(|e|error("snapshot_trust",e))?;if store.version<deployment.snapshot_policy.required_trust_store_version{return Err(error("snapshot_trust","trust-store version is below deployment policy"));}if store.expires<=OffsetDateTime::now_utc(){return Err(error("snapshot_trust","trust store is expired"));}Ok(store)}
fn checked_snapshot_payload_limit(runtime:u64,policy:u64)->Result<usize,DeploymentError>{
 if runtime==0||policy==0{return Err(error("resource_limit","snapshot payload limits must be nonzero"));}
 let runtime=usize::try_from(runtime).map_err(|_|error("resource_limit","runtime snapshot payload limit does not fit platform usize"))?;
 let policy=usize::try_from(policy).map_err(|_|error("resource_limit","policy snapshot payload limit does not fit platform usize"))?;
 Ok(runtime.min(policy))
}
pub fn effective_snapshot_payload_limit(deployment:&DeploymentConfigV1)->Result<usize,DeploymentError>{checked_snapshot_payload_limit(deployment.runtime_limits.max_snapshot_bytes,deployment.snapshot_policy.max_payload_bytes)}

fn validate_snapshot_policy(deployment:&DeploymentConfigV1)->Result<(),DeploymentError>{
 let policy=&deployment.snapshot_policy;
 effective_snapshot_payload_limit(deployment)?;
 if policy.trusted_checkpoint.height==0||!is_nonzero_sha256(&policy.trusted_checkpoint.block_id)||!is_nonzero_sha256(&policy.trusted_checkpoint.state_root){return Err(error("snapshot_trust","trusted checkpoint must have a non-zero production height and non-placeholder 32-byte block_id/state_root"));}
 let mut required=policy.required_stores.clone();required.sort();
 if required.is_empty()||required.windows(2).any(|pair|pair[0]==pair[1]){return Err(error("snapshot_trust","required snapshot store inventory must be non-empty and unique"));}
 let mut canonical=StoreKind::ALL.into_iter().map(|kind|kind.db_name().to_owned()).collect::<Vec<_>>();canonical.sort();
 if required!=canonical{return Err(error("snapshot_trust","required snapshot stores must exactly equal the canonical StoreKind inventory"));}
 let watermark_parent=deployment.paths.snapshot_watermark.parent().ok_or_else(||error("path_policy","snapshot watermark has no parent"))?;
 if watermark_parent.starts_with(&deployment.paths.data_directory)||deployment.paths.data_directory.starts_with(watermark_parent){return Err(error("path_policy","snapshot acceptance journal and watermark must be outside the storage destination"));}
 Ok(())
}
fn is_nonzero_sha256(value:&str)->bool{value.len()==64&&value.bytes().all(|byte|byte.is_ascii_hexdigit())&&value.bytes().any(|byte|byte!=b'0')}
fn hex_digest(bytes:&[u8])->String{let mut hash=Sha256::new();hash.update(bytes);hash.finalize().iter().map(|b|format!("{b:02x}")).collect()}
fn validate_install_receipt(deployment_path:&Path,deployment:&DeploymentConfigV1,build:BuildIdentity)->Result<(),DeploymentError>{if !deployment.production_security.require_verified_install_receipt{return Ok(());}validate_secure_file(&deployment.paths.install_receipt)?;let bytes=read_bounded(&deployment.paths.install_receipt,deployment.runtime_limits.max_release_manifest_bytes)?;let receipt:InstallReceipt=serde_json::from_slice(&bytes).map_err(|e|error("install_receipt",e))?;if receipt.schema!="tron-install-receipt-v1"||receipt.release_id!=build.release_id||receipt.release_sequence!=build.release_sequence||receipt.platform_id!=build.platform_id||receipt.manifest_sha256.len()!=64||OffsetDateTime::parse(&receipt.installed_at,&time::format_description::well_known::Rfc3339).is_err(){return Err(error("install_receipt","receipt identity or schema does not match running binary"));}let canonical=|path:&Path|path.is_absolute()&&!path.components().any(|component|matches!(component,std::path::Component::CurDir|std::path::Component::ParentDir));if !canonical(&receipt.install_prefix)||!canonical(&receipt.current_target)||!canonical(&receipt.config_root)||!canonical(&receipt.config_current_target)||!canonical(&receipt.receipt_path)||receipt.current_target!=receipt.install_prefix.join("current")||receipt.config_current_target!=receipt.config_root.join("current"){return Err(error("install_receipt","receipt install topology is not canonical"));}if receipt.receipt_path!=deployment.paths.install_receipt{return Err(error("install_receipt","receipt was relocated"));}if deployment.paths.chain_config.parent()!=Some(receipt.config_current_target.as_path())||deployment_path.parent()!=Some(receipt.config_current_target.as_path()){return Err(error("install_receipt","deployment and chain configuration must use the signed current config selector"));}if receipt.files.len().saturating_add(receipt.config_files.len())>deployment.runtime_limits.max_release_artifacts{return Err(error("resource_limit","install receipt artifact count exceeds policy"));}let chain_name=deployment.paths.chain_config.file_name().and_then(|name|name.to_str()).ok_or_else(||error("install_receipt","chain configuration has no canonical filename"))?;let deployment_name=deployment_path.file_name().and_then(|name|name.to_str()).ok_or_else(||error("install_receipt","deployment configuration has no canonical filename"))?;let mut chain_verified=false;let mut deployment_verified=false;for file in receipt.files.iter().chain(receipt.config_files.iter()){if file.path.starts_with('/')||file.path.split('/').any(|p|p==".."||p.is_empty()){return Err(error("install_receipt","unsafe receipt artifact path"));}let root=if receipt.config_files.iter().any(|candidate|std::ptr::eq(candidate,file)){&receipt.config_current_target}else{&receipt.current_target};let path=root.join(&file.path);let data=read_bounded(&path,file.size)?;let metadata=fs::metadata(&path).map_err(|e|error("install_receipt",e))?;if metadata.len()!=file.size||hex_digest(&data)!=file.sha256{return Err(error("install_receipt",format!("artifact digest mismatch: {}",file.path)));}#[cfg(unix)]{use std::os::unix::fs::MetadataExt;if metadata.mode()&0o7777!=file.mode{return Err(error("install_receipt",format!("artifact mode mismatch: {}",file.path)));}}if root==&receipt.config_current_target&&file.path==chain_name{chain_verified=true;}if root==&receipt.config_current_target&&file.path==deployment_name{deployment_verified=true;}}if !chain_verified||!deployment_verified{return Err(error("install_receipt","deployment or chain configuration is absent from config receipt"));}Ok(())}
fn validate_keystore_policy(deployment:&DeploymentConfigV1,config:&Config)->Result<(),DeploymentError>{if !deployment.paths.keystore_directory.is_dir(){return Err(error("keystore_policy","keystore directory is missing"));}let report=list_keystores(&deployment.paths.keystore_directory).map_err(|e|error("keystore_policy",e))?;if !report.warnings.is_empty(){return Err(error("keystore_policy","keystore directory contains rejected entries"));}if config.node.witness&&!config.localwitness.is_empty()&&!deployment.production_security.allow_inline_witness_private_key{return Err(error("keystore_policy","inline witness private keys are forbidden"));}if config.node.witness&&config.witness.password.is_some()&&!deployment.production_security.allow_cli_witness_password{return Err(error("keystore_policy","CLI witness passwords are forbidden"));}Ok(())}
fn validate_backup_policy(deployment:&DeploymentConfigV1,config:&Config)->Result<Option<BackupPeerKeyring>,DeploymentError>{
 if !config.node.witness{return Ok(None)}
 if !deployment.production_security.require_authenticated_backup_for_witness{return Err(error("backup_auth","witness requires authenticated backup policy"))}
 let listener=deployment.listeners.get("backup").ok_or_else(||error("backup_auth","witness backup listener is not configured"))?;
 if listener.security!=ListenerSecurity::HmacSha256V1OverPrivateTunnel{return Err(error("backup_auth","witness backup listener must use hmac-sha256-v1-over-private-tunnel"))}
 let endpoint=listener.bind.parse::<SocketAddr>().map_err(|_|error("backup_auth","invalid witness backup listener"))?;
 let path=deployment.paths.backup_keyring.as_ref().ok_or_else(||error("backup_auth","witness backup keyring is not configured"))?;
 validate_secure_file(path)?;
 let bytes=read_bounded(path,deployment.runtime_limits.max_trust_store_bytes)?;
 let text=std::str::from_utf8(&bytes).map_err(|_|error("backup_auth","backup keyring must be UTF-8"))?;
 parse_keyring(endpoint.ip(),endpoint,text).map(Some).map_err(|message|error("backup_auth",message))
}
pub fn preflight_deployment(path:impl AsRef<Path>, fixed_mode:DeploymentMode)->Result<PreparedDeployment,DeploymentError>{preflight_deployment_with_build(path,fixed_mode,BUILD_IDENTITY)}
pub fn preflight_deployment_with_build(path:impl AsRef<Path>,fixed_mode:DeploymentMode,build:BuildIdentity)->Result<PreparedDeployment,DeploymentError>{let path=path.as_ref();let deployment=load_deployment(path)?;if deployment.mode!=fixed_mode{return Err(error("fixed_mode","deployment mode does not match executable"));}if deployment.expected_release.release_id!=build.release_id||deployment.expected_release.minimum_release_sequence>build.release_sequence{return Err(error("release_identity","binary release identity or anti-rollback sequence rejected"));}validate_platform(&deployment.platform,build)?;absolute(&deployment.paths)?;validate_snapshot_policy(&deployment)?;if deployment.runtime_limits.startup_timeout_seconds==0||deployment.runtime_limits.shutdown_timeout_seconds==0||deployment.runtime_limits.max_snapshot_bytes==0||deployment.runtime_limits.max_trust_store_bytes==0{return Err(error("resource_limit","runtime limits must be positive"));}let config=ConfigLoader::new(UnknownKeyPolicy::Reject).load(ConfigSource::External(deployment.paths.chain_config.clone())).map_err(|e|error("chain_config",e))?;config.validate_for_mode(fixed_mode.node_mode()).map_err(|e|error("fixed_mode",e))?;let listeners=validate_listeners(fixed_mode,&deployment.listeners,deployment.production_security.allow_public_plaintext_api)?;validate_configured_listener_ports(fixed_mode,&deployment.listeners,&config)?;let backup_keyring=validate_backup_policy(&deployment,&config)?;let genesis=configured_genesis_id(&config)?;validate_install_receipt(path,&deployment,build)?;let trust_store=validate_trust_store(&deployment)?;validate_keystore_policy(&deployment,&config)?;let parameters=load_tron_parameters(&deployment.paths.sapling_spend,&deployment.paths.sapling_output).map_err(|e|error("sapling_parameters",e))?;let open_requirements=OpenRequirements{identity:StorageIdentity{network:"mainnet".into(),genesis},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]};let classification=inspect_read_only(&deployment.paths.data_directory).map_err(|e|error("storage",e))?;let storage_classification=match classification{DirectoryClassification::Missing=>"missing",DirectoryClassification::Empty=>"empty",DirectoryClassification::InitializingEmpty=>"initializing-empty",DirectoryClassification::Rust(_)=>"rustlog",DirectoryClassification::Java{..}=>return Err(error("storage","Java storage is reference-only under DR-001"))}.into();let report=PreflightReport{schema:"tron-preflight-v1",mode:fixed_mode,release_id:build.release_id.into(),platform_id:build.platform_id.into(),compatibility_storage_engine:config.storage.db.engine.clone(),physical_backend:"rustlog",backend_format:"rustlog-v1",decision:"DR-001",storage_classification,listeners};Ok(PreparedDeployment{deployment,config:Arc::new(config),parameters,open_requirements,trust_store,backup_keyring,report})}
#[must_use] pub fn listener_ip(policy:&ListenerPolicy)->Option<IpAddr>{policy.bind.parse::<SocketAddr>().ok().map(|v|v.ip())}

#[cfg(test)]
mod snapshot_payload_limit_tests{
 use super::checked_snapshot_payload_limit;

 #[test]
 fn effective_limit_is_the_stricter_positive_limit(){
  assert_eq!(checked_snapshot_payload_limit(4096,1024).unwrap(),1024);
  assert_eq!(checked_snapshot_payload_limit(512,4096).unwrap(),512);
  assert_eq!(checked_snapshot_payload_limit(1024,1024).unwrap(),1024);
 }

 #[test]
 fn zero_limits_are_rejected(){
  assert_eq!(checked_snapshot_payload_limit(0,1).unwrap_err().category,"resource_limit");
  assert_eq!(checked_snapshot_payload_limit(1,0).unwrap_err().category,"resource_limit");
 }

 #[test]
 fn configured_limits_must_fit_usize(){
  if usize::BITS<u64::BITS{
   let overflow=(usize::MAX as u64)+1;
   assert_eq!(checked_snapshot_payload_limit(overflow,1).unwrap_err().category,"resource_limit");
   assert_eq!(checked_snapshot_payload_limit(1,overflow).unwrap_err().category,"resource_limit");
  }
 }
}
