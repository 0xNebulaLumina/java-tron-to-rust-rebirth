use std::{fs, io::Read, net::SocketAddr, path::{Path,PathBuf}, process::ExitCode};
use serde::Deserialize;
use time::Duration;
use tokio::{io::{AsyncReadExt,AsyncWriteExt},net::TcpStream};
use tron_crypto::artifact_auth::{AuthClock,AuthLimits,SystemAuthClock};
use tron_storage::{import_snapshot,SnapshotDescriptor,StorageManager,snapshot_bundle::{encode_checkpoint_snapshot,RustLogSnapshotLimits,RustLogSnapshotMaterializer}};
use crate::{build_info::BUILD_IDENTITY,deployment::{effective_snapshot_payload_limit,preflight_deployment,DeploymentMode,PreparedDeployment},logging::{init_logging,LoggingConfig},runtime::RuntimeFactory,snapshot_trust::{begin_snapshot_acceptance,publish_snapshot_acceptance,verify_snapshot_manifest,PolicySnapshotVerifier,SnapshotPolicy,TrustedCheckpoint}};

#[derive(Clone,Copy,Debug,Eq,PartialEq)] pub enum ProbeKind{Health,Ready}
#[derive(Clone,Debug,Eq,PartialEq)] pub enum NodeCommand{Run,Preflight{json:bool},Probe{kind:ProbeKind},BootstrapSnapshot{snapshot:PathBuf,descriptor:PathBuf},ExportSnapshot{output:PathBuf},Version}
#[derive(Clone,Debug)] pub struct BootstrapArgs{pub command:NodeCommand,pub deployment_config:PathBuf}
impl BootstrapArgs {
 pub fn parse(args:impl IntoIterator<Item=String>)->Result<Self,String>{
  let mut values=args.into_iter();let _=values.next();let mut remaining:Vec<String>=values.collect();
  if remaining.iter().any(|v|v=="--version"||v=="-V"){return Ok(Self{command:NodeCommand::Version,deployment_config:PathBuf::new()});}
  let verb=remaining.first().filter(|v|!v.starts_with('-')).cloned();if verb.is_some(){remaining.remove(0);}
  let value=|name:&str|remaining.windows(2).find(|w|w[0]==name).map(|w|PathBuf::from(&w[1]));
  let deployment=value("--deployment-config").ok_or("--deployment-config is required")?;
  let command=match verb.as_deref(){
   None=>NodeCommand::Run,
   Some("preflight")=>NodeCommand::Preflight{json:remaining.iter().any(|v|v=="--json")},
   Some("probe")=>NodeCommand::Probe{kind:match remaining.windows(2).find(|w|w[0]=="--kind").map(|w|w[1].as_str()){Some("health")=>ProbeKind::Health,Some("ready")=>ProbeKind::Ready,_=>return Err("probe requires --kind health|ready".into())}},
   Some("bootstrap-snapshot")=>NodeCommand::BootstrapSnapshot{snapshot:value("--snapshot").ok_or("bootstrap-snapshot requires --snapshot")?,descriptor:value("--descriptor").ok_or("bootstrap-snapshot requires --descriptor")?},
   Some("export-snapshot")=>NodeCommand::ExportSnapshot{output:value("--output").ok_or("export-snapshot requires --output")?},
   Some(other)=>return Err(format!("unknown command {other}")),
  };
  let allowed=["--deployment-config","--kind","--snapshot","--descriptor","--output"];
  let mut i=0;while i<remaining.len(){if remaining[i]=="--json"{i+=1;continue;}if allowed.contains(&remaining[i].as_str())&&remaining.get(i+1).is_some(){i+=2;continue;}return Err(format!("unknown argument {}",remaining[i]));}
  Ok(Self{command,deployment_config:deployment})
 }
}
pub async fn run_fixed_mode(mode:DeploymentMode,args:BootstrapArgs)->ExitCode{match execute(mode,args).await{Ok(())=>ExitCode::SUCCESS,Err((category,message))=>{eprintln!("{}",serde_json::json!({"schema":"tron-node-error-v1","category":category,"message":message}));ExitCode::from(2)}}}
async fn execute(mode:DeploymentMode,args:BootstrapArgs)->Result<(),(&'static str,String)>{
 if args.command==NodeCommand::Version{println!("{}",serde_json::to_string(&BUILD_IDENTITY).unwrap_or_default());return Ok(());}
 if let NodeCommand::Probe{kind}=args.command{return run_probe(&args.deployment_config,kind).await.map_err(|e|("probe",e));}
 let prepared=preflight_deployment(&args.deployment_config,mode).map_err(|e|(e.category,e.message))?;
 match &args.command{
  NodeCommand::Preflight{json}=>{if *json{println!("{}",serde_json::to_string(&prepared.report).map_err(|e|("serialization",e.to_string()))?);}else{println!("mode={:?} release_id={} platform_id={} physical_backend={} backend_format={} decision={}",prepared.report.mode,prepared.report.release_id,prepared.report.platform_id,prepared.report.physical_backend,prepared.report.backend_format,prepared.report.decision);}return Ok(());}
  NodeCommand::BootstrapSnapshot{snapshot,descriptor}=>return bootstrap_snapshot(&prepared,snapshot,descriptor).map_err(|e|("snapshot",e)),
  NodeCommand::ExportSnapshot{output}=>return export_snapshot(&prepared,output).map_err(|e|("snapshot",e)),
  _=>{}
 }
 init_logging(&LoggingConfig{level:prepared.deployment.logging.level.clone()},BUILD_IDENTITY,mode).map_err(|e|("logging",e.to_string()))?;
 let mut runtime=RuntimeFactory::prepare(prepared).await.map_err(|e|(e.category,e.message))?;
 runtime.start().await.map_err(|e|("runtime",e))?;
 runtime.wait_for_stop().await.map_err(|e|("shutdown",e))
}
pub async fn run_node(mode:DeploymentMode,args:BootstrapArgs)->ExitCode{run_fixed_mode(mode,args).await}
pub fn run_preflight(mode:DeploymentMode,path:PathBuf)->Result<crate::deployment::PreflightReport,crate::deployment::DeploymentError>{preflight_deployment(path,mode).map(|v|v.report)}
pub async fn run_probe(path:&Path,kind:ProbeKind)->Result<(),String>{let deployment=crate::deployment::load_deployment(path).map_err(|e|e.to_string())?;let admin=deployment.listeners.get("admin").ok_or("admin listener is not configured")?;let address:SocketAddr=admin.bind.parse().map_err(|_|"invalid admin address")?;let mut stream=TcpStream::connect(address).await.map_err(|e|e.to_string())?;let route=if kind==ProbeKind::Health{"/healthz"}else{"/readyz"};stream.write_all(format!("GET {route} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes()).await.map_err(|e|e.to_string())?;let mut bytes=Vec::new();stream.read_to_end(&mut bytes).await.map_err(|e|e.to_string())?;let response=String::from_utf8_lossy(&bytes);if response.starts_with("HTTP/1.1 200 "){Ok(())}else{Err(format!("probe failed: {}",response.lines().next().unwrap_or("invalid response")))}}

#[derive(Deserialize)] #[serde(deny_unknown_fields)] struct DescriptorWire{network:String,genesis:String,schema_version:u32,backend:String,backend_format:String,generation:u64,state_root:String,payload_sha256:String,payload_size:u64,authentication_envelope:serde_json::Value}
#[cfg(unix)]
fn read_descriptor_bytes_with(path:&Path,max:usize,after_open:impl FnOnce())->Result<Vec<u8>,String>{
 use std::os::unix::fs::{MetadataExt,OpenOptionsExt};
 const O_NOFOLLOW:i32=0o400000;
 const O_CLOEXEC:i32=0o2000000;
 let mut file=fs::OpenOptions::new().read(true).custom_flags(O_NOFOLLOW|O_CLOEXEC).open(path).map_err(|e|format!("snapshot descriptor open failed: {e}"))?;
 let before=file.metadata().map_err(|e|e.to_string())?;
 let mode=before.mode()&0o7777;
 if !before.is_file()||before.uid()!=rustix::process::geteuid().as_raw()||mode!=0o600||before.nlink()!=1{return Err("snapshot descriptor must be an owner-only, singly-linked regular file".into());}
 if before.len()>max as u64{return Err("snapshot descriptor exceeds policy".into());}
 if before.len()>0&&before.blocks().saturating_mul(512)<before.len(){return Err("snapshot descriptor must not be sparse".into());}
 after_open();
 let capacity=usize::try_from(before.len()).unwrap_or(max).min(max);
 let mut bytes=Vec::with_capacity(capacity);
 let mut limited=(&mut file).take((max as u64).saturating_add(1));
 let mut chunk=[0u8;8192];
 loop{let count=limited.read(&mut chunk).map_err(|e|e.to_string())?;if count==0{break;}bytes.extend_from_slice(&chunk[..count]);if bytes.len()>max{return Err("snapshot descriptor exceeds policy".into());}}
 let after=file.metadata().map_err(|e|e.to_string())?;
 let named=fs::symlink_metadata(path).map_err(|_|"snapshot descriptor was replaced while reading".to_string())?;
 if (before.dev(),before.ino(),before.len(),before.mtime(),before.mtime_nsec())!=(after.dev(),after.ino(),after.len(),after.mtime(),after.mtime_nsec())
  ||(before.dev(),before.ino())!=(named.dev(),named.ino())
  ||after.len()!=bytes.len() as u64{return Err("snapshot descriptor changed while reading".into());}
 Ok(bytes)
}
#[cfg(unix)]
fn read_descriptor_bytes(path:&Path,max:usize)->Result<Vec<u8>,String>{read_descriptor_bytes_with(path,max,||{})}
#[cfg(not(unix))]
fn read_descriptor_bytes(_path:&Path,_max:usize)->Result<Vec<u8>,String>{Err("secure snapshot descriptor reads are unsupported on this platform".into())}
fn read_descriptor(path:&Path,max:usize)->Result<SnapshotDescriptor,String>{let bytes=read_descriptor_bytes(path,max)?;let wire:DescriptorWire=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;let authentication_envelope=serde_json::to_vec(&wire.authentication_envelope).map_err(|e|e.to_string())?;Ok(SnapshotDescriptor{identity:tron_storage::StorageIdentity{network:wire.network,genesis:wire.genesis},schema_version:wire.schema_version,backend:wire.backend,backend_format:wire.backend_format,generation:wire.generation,state_root:wire.state_root,payload_sha256:wire.payload_sha256,payload_size:wire.payload_size,authentication_envelope})}
fn snapshot_policy(prepared:&PreparedDeployment)->SnapshotPolicy{let p=&prepared.deployment.snapshot_policy;SnapshotPolicy{minimum_height:p.minimum_acceptable_height,trusted_checkpoint:TrustedCheckpoint{height:p.trusted_checkpoint.height,block_id:p.trusted_checkpoint.block_id.clone(),state_root:p.trusted_checkpoint.state_root.clone()},maximum_age:Duration::seconds(p.max_age_seconds as i64),maximum_future_skew:Duration::seconds(p.future_clock_skew_seconds as i64),required_stores:p.required_stores.clone(),auth_limits:AuthLimits{max_envelope_bytes:p.max_manifest_bytes as usize,max_payload_bytes:p.max_manifest_bytes as usize,..AuthLimits::default()}}}
pub fn bootstrap_snapshot(prepared:&PreparedDeployment,snapshot:&Path,descriptor_path:&Path)->Result<(),String>{let payload_limit=effective_snapshot_payload_limit(&prepared.deployment).map_err(|e|e.to_string())?;let descriptor=read_descriptor(descriptor_path,prepared.deployment.snapshot_policy.max_manifest_bytes as usize)?;let source=tron_storage::SnapshotSource::open(snapshot,payload_limit).map_err(|e|e.to_string())?;let policy=snapshot_policy(prepared);let manifest=verify_snapshot_manifest(&descriptor,&source,&prepared.trust_store,&policy,SystemAuthClock.now()).map_err(|e|e.to_string())?;let watermark_root=prepared.deployment.paths.snapshot_watermark.parent().ok_or("snapshot watermark has no parent")?;let journal=begin_snapshot_acceptance(watermark_root,&descriptor,&manifest,prepared.trust_store.version).map_err(|e|e.to_string())?;let verifier=PolicySnapshotVerifier::new(prepared.trust_store.clone(),policy,SystemAuthClock);let materializer=RustLogSnapshotMaterializer::new(RustLogSnapshotLimits{max_bundle_bytes:payload_limit,max_snapshot_bytes:payload_limit,..RustLogSnapshotLimits::default()});import_snapshot(&prepared.deployment.paths.data_directory,&prepared.open_requirements,snapshot,payload_limit,&descriptor,&verifier,&materializer).map_err(|e|e.to_string())?;publish_snapshot_acceptance(watermark_root,&journal,&manifest).map_err(|e|e.to_string())}
pub fn export_snapshot(prepared:&PreparedDeployment,output:&Path)->Result<(),String>{if output.exists(){return Err("snapshot output already exists".into());}let manager=StorageManager::new(prepared.open_requirements.clone());let mut store=manager.open_store(&prepared.deployment.paths.data_directory).map_err(|e|e.to_string())?;let checkpoint=output.with_extension(format!("checkpoint-{}",std::process::id()));store.checkpoint(&checkpoint).map_err(|e|e.to_string())?;store.close().map_err(|e|e.to_string())?;let limits=RustLogSnapshotLimits{max_bundle_bytes:prepared.deployment.runtime_limits.max_snapshot_bytes as usize,max_snapshot_bytes:prepared.deployment.runtime_limits.max_snapshot_bytes as usize,..RustLogSnapshotLimits::default()};let result=encode_checkpoint_snapshot(&checkpoint,output,limits).map(|_|()).map_err(|e|e.to_string());let _=fs::remove_dir_all(checkpoint);result}

#[cfg(all(test,unix))]
mod descriptor_reader_tests{
 use super::*;
 use std::os::unix::fs::{symlink,OpenOptionsExt,PermissionsExt};
 use std::sync::atomic::{AtomicU64,Ordering};

 fn root(label:&str)->PathBuf{static NEXT:AtomicU64=AtomicU64::new(0);let path=std::env::temp_dir().join(format!("tron-descriptor-{label}-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));fs::create_dir(&path).unwrap();path}
 fn private_write(path:&Path,bytes:&[u8]){fs::write(path,bytes).unwrap();fs::set_permissions(path,fs::Permissions::from_mode(0o600)).unwrap();}

 #[test]
 fn descriptor_policy_rejects_symlink_sparse_and_oversize_before_reading(){
  let directory=root("policy");
  let target=directory.join("target");private_write(&target,b"{}");
  let link=directory.join("link");symlink(&target,&link).unwrap();
  assert!(read_descriptor_bytes(&link,64).unwrap_err().contains("open failed"));
  let public=directory.join("public");private_write(&public,b"{}");fs::set_permissions(&public,fs::Permissions::from_mode(0o640)).unwrap();
  assert!(read_descriptor_bytes(&public,64).unwrap_err().contains("owner-only"));
  let linked=directory.join("linked");private_write(&linked,b"{}");fs::hard_link(&linked,directory.join("second-link")).unwrap();
  assert!(read_descriptor_bytes(&linked,64).unwrap_err().contains("singly-linked"));
  let oversize=directory.join("oversize");private_write(&oversize,&[7;65]);
  assert_eq!(read_descriptor_bytes(&oversize,64).unwrap_err(),"snapshot descriptor exceeds policy");
  let sparse=directory.join("huge-sparse");let file=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&sparse).unwrap();file.set_len(1u64<<40).unwrap();drop(file);
  assert_eq!(read_descriptor_bytes(&sparse,1024).unwrap_err(),"snapshot descriptor exceeds policy");
  fs::remove_dir_all(directory).unwrap();
 }

 #[test]
 fn retained_descriptor_fd_detects_name_swap(){
  let directory=root("swap");let path=directory.join("descriptor.json");private_write(&path,b"original");
  let displaced=directory.join("displaced");
  let error=read_descriptor_bytes_with(&path,64,||{fs::rename(&path,&displaced).unwrap();private_write(&path,b"attacker");}).unwrap_err();
  assert!(error.contains("changed while reading"));
  assert_eq!(fs::read(&path).unwrap(),b"attacker");
  fs::remove_dir_all(directory).unwrap();
 }
}
