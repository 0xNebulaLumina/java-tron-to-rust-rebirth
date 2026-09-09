use std::{fs,path::PathBuf};
use tron_node::deployment::load_deployment;
fn temp(name:&str)->PathBuf{std::env::temp_dir().join(format!("tron-c028-{}-{name}",std::process::id()))}
#[test]
fn deployment_parser_rejects_unknown_fields_and_wrong_schema(){
 let path=temp("unknown.json");
 fs::write(&path,br#"{"schema":"tron-deployment-v1","mode":"full","unexpected":true}"#).unwrap();
 let error=load_deployment(&path).unwrap_err();
 assert_eq!(error.category,"deployment_config");
 fs::write(&path,br#"{"schema":"wrong","mode":"full"}"#).unwrap();
 assert!(load_deployment(&path).is_err());
 let _=fs::remove_file(path);
}
#[cfg(unix)]
#[test]
fn deployment_parser_refuses_symlink_input(){
 use std::os::unix::fs::symlink;
 let target=temp("target.json");let link=temp("link.json");
 fs::write(&target,b"{}").unwrap();symlink(&target,&link).unwrap();
 let error=load_deployment(&link).unwrap_err();assert_eq!(error.category,"path_policy");
 let _=fs::remove_file(link);let _=fs::remove_file(target);
}

#[test]
fn packaged_deployments_require_external_acceptance_and_canonical_store_inventory(){
 for name in ["fullnode.deployment.json","solidity.deployment.json"]{
  let path=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/config").join(name);
  let deployment=load_deployment(path).unwrap();
  assert!(deployment.snapshot_policy.trusted_checkpoint.height > 0);
  assert_eq!(deployment.snapshot_policy.minimum_acceptable_height,deployment.snapshot_policy.trusted_checkpoint.height);
  assert_eq!(deployment.snapshot_policy.trusted_checkpoint.block_id.len(),64);
  assert_eq!(deployment.snapshot_policy.trusted_checkpoint.state_root.len(),64);
  assert!(deployment.snapshot_policy.trusted_checkpoint.block_id.bytes().any(|byte|byte!=b'0'));
  assert!(deployment.snapshot_policy.trusted_checkpoint.state_root.bytes().any(|byte|byte!=b'0'));
  let mut configured=deployment.snapshot_policy.required_stores.clone();configured.sort();
  let mut canonical=tron_state::StoreKind::ALL.into_iter().map(|kind|kind.db_name().to_owned()).collect::<Vec<_>>();canonical.sort();
  assert_eq!(configured,canonical);
  let acceptance=deployment.paths.snapshot_watermark.parent().unwrap();
  assert!(!acceptance.starts_with(&deployment.paths.data_directory));
 }
}

#[test]
fn packaged_surfaces_match_runtime_and_solidity_json_rpc_is_forbidden(){
 let root=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging");
 let full=load_deployment(root.join("config/fullnode.deployment.json")).unwrap();
 let solidity=load_deployment(root.join("config/solidity.deployment.json")).unwrap();
 assert_eq!(full.listeners.keys().map(String::as_str).collect::<Vec<_>>(),vec!["admin","backup","grpc","http","jsonrpc","p2p","prometheus","zeromq"]);
 assert_eq!(solidity.listeners.keys().map(String::as_str).collect::<Vec<_>>(),vec!["admin","grpc","http","prometheus","zeromq"]);
 assert!(full.paths.backup_keyring.as_ref().is_some_and(|path|path==std::path::Path::new("/etc/tron/backup-keyring.txt")));
 let solidity_chain=fs::read_to_string(root.join("config/solidity.conf")).unwrap();
 assert!(!solidity_chain.contains("8555")&&!solidity_chain.to_ascii_lowercase().contains("jsonrpc"));
 let compose=fs::read_to_string(root.join("container/compose.yaml")).unwrap();
 assert!(!compose.contains("8555:8555"));
 for advertised in ["10001:10001/udp","8090:8090","50051:50051","8545:8545","8091:8091"]{assert!(compose.contains(advertised),"missing packaged surface {advertised}");}
}

use base64::{Engine as _,engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signer,SigningKey};
use serde_json::json;
use sha2::{Digest,Sha256};
use time::{Duration,OffsetDateTime,format_description::well_known::Rfc3339};
use tron_crypto::artifact_auth::{Algorithm,AuthLimits,DsseEnvelope,DsseSignature,KeyId,dsse_pae,parse_trust_store};
use tron_node::snapshot_trust::{SNAPSHOT_MANIFEST_PAYLOAD_TYPE,SnapshotPolicy,TrustedCheckpoint,verify_snapshot_manifest};
use tron_storage::{SnapshotDescriptor,SnapshotSource,StorageIdentity,StableError};

const CHECKPOINT_BLOCK:&str="1111111111111111111111111111111111111111111111111111111111111111";
const CHECKPOINT_ROOT:&str="2222222222222222222222222222222222222222222222222222222222222222";

fn signed_snapshot_case(height:u64,block_id:&str,state_root:&str)->(SnapshotDescriptor,SnapshotSource,tron_crypto::artifact_auth::TrustStoreV1,SnapshotPolicy,PathBuf){
 signed_snapshot_case_with_role(height,block_id,state_root,"snapshot:mainnet","snapshot:mainnet")
}

fn signed_snapshot_case_with_role(height:u64,block_id:&str,state_root:&str,role_name:&str,role_scope:&str)->(SnapshotDescriptor,SnapshotSource,tron_crypto::artifact_auth::TrustStoreV1,SnapshotPolicy,PathBuf){
 let now=OffsetDateTime::parse("2026-09-08T12:00:00Z",&Rfc3339).unwrap();
 let keys=[SigningKey::from_bytes(&[41;32]),SigningKey::from_bytes(&[42;32])];
 let ids=keys.iter().map(|key|KeyId::for_ed25519(&key.verifying_key().to_bytes()).as_str().to_owned()).collect::<Vec<_>>();
 let key_rows=keys.iter().map(|key|json!({"key_id":KeyId::for_ed25519(&key.verifying_key().to_bytes()).as_str(),"algorithm":"ed25519-v1","public_key_base64":BASE64.encode(key.verifying_key().to_bytes()),"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","revoked":false})).collect::<Vec<_>>();
 let trust_store=parse_trust_store(&serde_json::to_vec(&json!({"schema":"tron-trust-store-v1","version":1,"expires":"2027-01-01T00:00:00Z","keys":key_rows,"roles":[{"name":"root","key_ids":ids.clone(),"threshold":2,"scope":"trust-store"},{"name":role_name,"key_ids":ids,"threshold":2,"scope":role_scope}]})).unwrap(),AuthLimits::default()).unwrap();
 let nonce=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();let payload_path=temp(&format!("snapshot-payload-{height}-{nonce}.bin"));fs::write(&payload_path,b"immutable snapshot bytes").unwrap();
 let payload=fs::read(&payload_path).unwrap();let payload_sha256=format!("{:x}",Sha256::digest(&payload));
 let stores=tron_state::StoreKind::ALL.into_iter().map(|kind|kind.db_name().to_owned()).collect::<Vec<_>>();
 let manifest=serde_json::to_vec(&json!({"schema":"tron-snapshot-manifest-v1","network":"mainnet","genesis":"c028","schema_version":1,"backend":"rustlog","backend_format":"rustlog-v1","generation":0,"height":height,"block_id":block_id,"state_root":state_root,"stores":stores,"payload_sha256":payload_sha256,"payload_size":payload.len(),"created_at":"2026-09-08T12:00:00Z"})).unwrap();
 let pae=dsse_pae(SNAPSHOT_MANIFEST_PAYLOAD_TYPE,&manifest);
 let envelope=DsseEnvelope{payload_type:SNAPSHOT_MANIFEST_PAYLOAD_TYPE.into(),payload:BASE64.encode(&manifest),signatures:keys.iter().map(|key|DsseSignature{key_id:KeyId::for_ed25519(&key.verifying_key().to_bytes()),algorithm:Algorithm::Ed25519V1,signature:BASE64.encode(key.sign(&pae).to_bytes())}).collect()};
 let descriptor=SnapshotDescriptor{identity:StorageIdentity{network:"mainnet".into(),genesis:"c028".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),generation:0,state_root:state_root.into(),payload_sha256,payload_size:payload.len() as u64,authentication_envelope:serde_json::to_vec(&envelope).unwrap()};
 let source=SnapshotSource::open(&payload_path,1024).unwrap();
 let policy=SnapshotPolicy{minimum_height:100,trusted_checkpoint:TrustedCheckpoint{height:100,block_id:CHECKPOINT_BLOCK.into(),state_root:CHECKPOINT_ROOT.into()},maximum_age:Duration::days(7),maximum_future_skew:Duration::minutes(5),required_stores:tron_state::StoreKind::ALL.into_iter().map(|kind|kind.db_name().to_owned()).collect(),auth_limits:AuthLimits::default()};
 let _=now;
 (descriptor,source,trust_store,policy,payload_path)
}

#[test]
fn exact_operator_checkpoint_accepts_packaged_snapshot_layout(){
 let (descriptor,source,trust_store,policy,path)=signed_snapshot_case(100,CHECKPOINT_BLOCK,CHECKPOINT_ROOT);
 let now=OffsetDateTime::parse("2026-09-08T12:00:00Z",&Rfc3339).unwrap();
 let manifest=verify_snapshot_manifest(&descriptor,&source,&trust_store,&policy,now).unwrap();
 assert_eq!((manifest.height,manifest.block_id.as_str(),manifest.state_root.as_str()),(policy.trusted_checkpoint.height,policy.trusted_checkpoint.block_id.as_str(),policy.trusted_checkpoint.state_root.as_str()));
 fs::remove_file(path).unwrap();
}

#[test]
fn higher_unrelated_signer_snapshot_cannot_bypass_operator_checkpoint(){
 let (descriptor,source,trust_store,policy,path)=signed_snapshot_case(101,"3333333333333333333333333333333333333333333333333333333333333333","4444444444444444444444444444444444444444444444444444444444444444");
 let now=OffsetDateTime::parse("2026-09-08T12:00:00Z",&Rfc3339).unwrap();
 let error=verify_snapshot_manifest(&descriptor,&source,&trust_store,&policy,now).unwrap_err();
 assert_eq!(error.category,StableError::SnapshotUnauthenticated);
 assert!(error.detail.contains("exactly match"));
 fs::remove_file(path).unwrap();
}

#[test]
fn zero_placeholder_operator_checkpoint_is_rejected_even_with_valid_signatures(){
 let (descriptor,source,trust_store,mut policy,path)=signed_snapshot_case(100,CHECKPOINT_BLOCK,CHECKPOINT_ROOT);
 policy.trusted_checkpoint=TrustedCheckpoint{height:0,block_id:"0".repeat(64),state_root:"0".repeat(64)};
 let now=OffsetDateTime::parse("2026-09-08T12:00:00Z",&Rfc3339).unwrap();
 let error=verify_snapshot_manifest(&descriptor,&source,&trust_store,&policy,now).unwrap_err();
 assert_eq!(error.category,StableError::SnapshotUnauthenticated);
 assert!(error.detail.contains("non-zero production"));
 fs::remove_file(path).unwrap();
}

#[test]
fn matching_snapshot_role_with_wrong_scope_is_rejected(){
 let (descriptor,source,trust_store,policy,path)=signed_snapshot_case_with_role(100,CHECKPOINT_BLOCK,CHECKPOINT_ROOT,"snapshot:mainnet","snapshot:nile");
 let now=OffsetDateTime::parse("2026-09-08T12:00:00Z",&Rfc3339).unwrap();
 let error=verify_snapshot_manifest(&descriptor,&source,&trust_store,&policy,now).unwrap_err();
 assert_eq!(error.category,StableError::SnapshotUnauthenticated);
 assert!(error.detail.contains("scope does not match"));
 fs::remove_file(path).unwrap();
}

#[test]
fn signed_cross_network_snapshot_role_cannot_authorize_mainnet_import(){
 let (descriptor,source,trust_store,policy,path)=signed_snapshot_case_with_role(100,CHECKPOINT_BLOCK,CHECKPOINT_ROOT,"snapshot:nile","snapshot:nile");
 let now=OffsetDateTime::parse("2026-09-08T12:00:00Z",&Rfc3339).unwrap();
 let error=verify_snapshot_manifest(&descriptor,&source,&trust_store,&policy,now).unwrap_err();
 assert_eq!(error.category,StableError::SnapshotUnauthenticated);
 assert!(error.detail.contains("role is missing"));
 fs::remove_file(path).unwrap();
}
