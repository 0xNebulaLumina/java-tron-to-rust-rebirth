
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tron_toolkit::db::lite::{rewrite_merge, rewrite_split, DatasetIdentity, LiteDescriptor, LiteError, LiteKind, MergeRequest, SplitRequest, DESCRIPTOR_KEY, HISTORY_BALANCE_DISABLED_KEY};
use tron_crypto::{selected_digest, CryptoEngine};
use tron_state::{physical_key, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};
use tron_storage::toolkit::fingerprint_store;

static NONCE: AtomicU64 = AtomicU64::new(0);
fn root(name: &str) -> PathBuf { let path=std::env::temp_dir().join(format!("c027-lite-{name}-{}-{}",SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),NONCE.fetch_add(1,Ordering::Relaxed))); fs::create_dir(&path).unwrap(); fs::set_permissions(&path,fs::Permissions::from_mode(0o700)).unwrap(); path }
fn requirements() -> OpenRequirements { OpenRequirements { identity: StorageIdentity { network:"mainnet".into(), genesis:"c027".into() }, schema_version:1, backend:"rustlog".into(), backend_format:"rustlog-v1".into(), supported_features:vec!["rustlog-v1".into()] } }
fn varint(mut value:u64)->Vec<u8>{let mut out=Vec::new();loop{let mut b=(value&0x7f)as u8;value>>=7;if value!=0{b|=0x80}out.push(b);if value==0{return out}}}
fn bytes_field(number:u8,value:&[u8])->Vec<u8>{let mut out=vec![(number<<3)|2];out.extend(varint(value.len()as u64));out.extend(value);out}
fn number_field(number:u8,value:u64)->Vec<u8>{let mut out=vec![number<<3];out.extend(varint(value));out}
fn encoded_block(height:i64)->(Vec<u8>,[u8;32],Vec<u8>,[u8;32]){let raw_tx=number_field(3,height as u64+100);let tx=bytes_field(1,&raw_tx);let txid=selected_digest(CryptoEngine::Secp256k1,&raw_tx);let raw_header=number_field(7,height as u64);let header=bytes_field(1,&raw_header);let mut block=bytes_field(1,&tx);block.extend(bytes_field(2,&header));let mut id=selected_digest(CryptoEngine::Secp256k1,&raw_header);id[..8].copy_from_slice(&height.to_be_bytes());(block,id,tx,txid)}
fn populate(path:&PathBuf,count:i64){let manager=StorageManager::new(requirements());let mut store=manager.open_store(path).unwrap();for height in 0..count{let(block,id,tx,txid)=encoded_block(height);store.put(physical_key(&StoreKind::BlockIndex.name(),&height.to_be_bytes()),id.to_vec()).unwrap();store.put(physical_key(&StoreKind::Block.name(),&id),block).unwrap();store.put(physical_key(&StoreKind::Transaction.name(),&txid),tx).unwrap();store.put(physical_key(&StoreKind::TransactionRet.name(),&height.to_be_bytes()),vec![height as u8,1]).unwrap();store.put(physical_key(&StoreKind::TransactionHistory.name(),&txid),vec![height as u8,2]).unwrap();}store.put(physical_key(&StoreKind::Account.name(),b"alice"),b"state".to_vec()).unwrap();store.put(physical_key(&StoreKind::BalanceTrace.name(),b"trace"),b"balance".to_vec()).unwrap();store.put(physical_key(&StoreKind::TransactionCache.name(),b"cache"),b"transient".to_vec()).unwrap();store.close().unwrap()}
fn identity()->DatasetIdentity{DatasetIdentity{network:"mainnet".into(),genesis:"c027".into(),schema_version:1}}
fn split_request(source:PathBuf,destination:PathBuf,kind:LiteKind,exclude:bool)->SplitRequest{let dataset_path=destination.parent().unwrap().to_path_buf();SplitRequest{source,dataset_path,kind,identity:identity(),recent_blocks:3,exclude_historical_balance:exclude,max_batch_operations:2}}
fn descriptor(store:&tron_storage::RustLog)->LiteDescriptor{LiteDescriptor::decode(&store.get(&physical_key(&StoreKind::Common.name(),DESCRIPTOR_KEY)).unwrap()).unwrap()}

#[test]
fn descriptor_is_canonical_and_checksum_protected(){let d=LiteDescriptor{descriptor_version:1,kind:LiteKind::Snapshot,network:"mainnet".into(),genesis:"c027".into(),schema_version:1,backend_format:"rustlog-v1".into(),source_state_sha256:"ab".repeat(32),genesis_block_id:[7;32],min_block:4,max_block:9,recent_blocks:6,excluded_stores:vec!["account-trace".into(),"balance-trace".into()],history_balance_compatible:false};let encoded=d.encode().unwrap();assert_eq!(LiteDescriptor::decode(&encoded).unwrap(),d);let mut corrupt=encoded;corrupt[20]^=1;assert_eq!(LiteDescriptor::decode(&corrupt),Err(LiteError::InvalidDescriptor("CRC32 mismatch")))}

struct JavaLiteRow { id: &'static str, physical_variant: &'static str, decision: &'static str }

const JAVA_LITE_ROWS: [JavaLiteRow; 5] = [
    JavaLiteRow { id: "TCASE-07830A292D3A80E9", physical_variant: "leveldb-checkpoint-v1", decision: "DR-001" },
    JavaLiteRow { id: "TCASE-CA377A3F0CCDED17", physical_variant: "leveldb-checkpoint-v2", decision: "DR-001" },
    JavaLiteRow { id: "TCASE-3B94179296286BCD", physical_variant: "rocksdb-exclude-historical-balance", decision: "DR-001" },
    JavaLiteRow { id: "TCASE-73568EC3033FC84A", physical_variant: "rocksdb-checkpoint-v1", decision: "DR-001" },
    JavaLiteRow { id: "TCASE-1FDB8C6B77896021", physical_variant: "rocksdb-checkpoint-v2", decision: "DR-001" },
];

fn assert_rustlog_logical_equivalent(row: &JavaLiteRow) {
    assert_eq!(row.decision, "DR-001");
    assert!(row.physical_variant.ends_with("checkpoint-v1") || row.physical_variant.ends_with("checkpoint-v2"));
    let parent=root(row.physical_variant);let source=parent.join("full");let snapshot=parent.join("snapshot");let history=parent.join("history");populate(&source,6);let manager=StorageManager::new(requirements());let mut store=manager.open_store(&source).unwrap();store.delete(physical_key(&StoreKind::TransactionCache.name(),b"cache")).unwrap();store.close().unwrap();let expected=fingerprint_store(&source,&requirements()).unwrap();rewrite_split(&manager,&split_request(source.clone(),snapshot.clone(),LiteKind::Snapshot,false)).unwrap();rewrite_split(&manager,&split_request(source,history.clone(),LiteKind::History,false)).unwrap();let snapshot_store=manager.open_store(&snapshot).unwrap();let recent=(0i64..6).filter(|height|snapshot_store.contains_key(&physical_key(&StoreKind::BlockIndex.name(),&height.to_be_bytes()))).collect::<Vec<_>>();assert_eq!(recent,vec![0,3,4,5]);snapshot_store.close().unwrap();let history_store=manager.open_store(&history).unwrap();assert_eq!((0i64..6).filter(|height|history_store.contains_key(&physical_key(&StoreKind::TransactionRet.name(),&height.to_be_bytes()))).count(),6);history_store.close().unwrap();let merged=rewrite_merge(&manager,&MergeRequest{snapshot:snapshot.clone(),history,max_batch_operations:2}).unwrap();assert_eq!(merged.fingerprint.state_sha256,expected.state_sha256);let merged_store=manager.open_store(&snapshot).unwrap();assert!(!merged_store.contains_key(&physical_key(&StoreKind::Common.name(),DESCRIPTOR_KEY)));merged_store.close().unwrap();fs::remove_dir_all(parent).unwrap();
}

fn assert_excluded_balance_logical_equivalent(row: &JavaLiteRow) {
    assert_eq!((row.decision,row.physical_variant),("DR-001","rocksdb-exclude-historical-balance"));
    let parent=root("java-exclude-row");let source=parent.join("full");let snapshot=parent.join("snapshot");let history=parent.join("history");populate(&source,3);let manager=StorageManager::new(requirements());rewrite_split(&manager,&split_request(source.clone(),snapshot.clone(),LiteKind::Snapshot,true)).unwrap();rewrite_split(&manager,&split_request(source,history.clone(),LiteKind::History,true)).unwrap();rewrite_merge(&manager,&MergeRequest{snapshot:snapshot.clone(),history,max_batch_operations:2}).unwrap();let store=manager.open_store(&snapshot).unwrap();assert!(!store.contains_key(&physical_key(&StoreKind::BalanceTrace.name(),b"trace")));assert_eq!(store.get(&physical_key(&StoreKind::Common.name(),HISTORY_BALANCE_DISABLED_KEY)).unwrap(),b"1");store.close().unwrap();fs::remove_dir_all(parent).unwrap();
}

#[test]
fn java_db_lite_rows() {
    for row in &JAVA_LITE_ROWS {
        match row.id {
            "TCASE-07830A292D3A80E9" | "TCASE-CA377A3F0CCDED17" | "TCASE-73568EC3033FC84A" | "TCASE-1FDB8C6B77896021" => assert_rustlog_logical_equivalent(row),
            "TCASE-3B94179296286BCD" => assert_excluded_balance_logical_equivalent(row),
            _ => panic!("unmapped C027 Java lite row: {}",row.id),
        }
    }
}

#[test]
fn snapshot_rejects_zero_recent_window_before_staging() {
    let parent=root("zero-recent");let source=parent.join("full");let destination=parent.join("snapshot");populate(&source,2);let manager=StorageManager::new(requirements());let mut request=split_request(source,destination.clone(),LiteKind::Snapshot,false);request.recent_blocks=0;let error=rewrite_split(&manager,&request).unwrap_err();assert!(matches!(error,tron_storage::StorageError::RewriteRejected{category:"invalid_lite_dataset",..}));assert!(!destination.exists());assert_eq!(fs::read_dir(&parent).unwrap().count(),1);fs::remove_dir_all(parent).unwrap()
}

#[test]
fn snapshot_streams_genesis_and_inclusive_recent_without_ret_history(){let parent=root("snapshot");let source=parent.join("full");let snapshot=parent.join("snapshot");populate(&source,6);let manager=StorageManager::new(requirements());rewrite_split(&manager,&split_request(source,snapshot.clone(),LiteKind::Snapshot,false)).unwrap();let store=manager.open_store(&snapshot).unwrap();let heights=(0i64..6).filter(|h|store.contains_key(&physical_key(&StoreKind::BlockIndex.name(),&h.to_be_bytes()))).collect::<Vec<_>>();assert_eq!(heights,vec![0,3,4,5]);assert!(!store.contains_key(&physical_key(&StoreKind::TransactionRet.name(),&5i64.to_be_bytes())));let(_,_,_,txid)=encoded_block(5);assert!(!store.contains_key(&physical_key(&StoreKind::TransactionHistory.name(),&txid)));assert_eq!(descriptor(&store).min_block,3);store.close().unwrap();fs::remove_dir_all(parent).unwrap()}

#[test]
fn history_streams_all_five_archive_namespaces_and_no_live_state(){let parent=root("history");let source=parent.join("full");let history=parent.join("history");populate(&source,5);let manager=StorageManager::new(requirements());rewrite_split(&manager,&split_request(source,history.clone(),LiteKind::History,false)).unwrap();let store=manager.open_store(&history).unwrap();for height in 0i64..5{let(_,_,_,txid)=encoded_block(height);assert!(store.contains_key(&physical_key(&StoreKind::TransactionRet.name(),&height.to_be_bytes())));assert!(store.contains_key(&physical_key(&StoreKind::TransactionHistory.name(),&txid)));}assert!(!store.contains_key(&physical_key(&StoreKind::Account.name(),b"alice")));store.close().unwrap();fs::remove_dir_all(parent).unwrap()}

#[test]
fn merge_round_trip_restores_ret_by_height_and_removes_descriptor(){let parent=root("merge");let source=parent.join("full");let snapshot=parent.join("snapshot");let history=parent.join("history");populate(&source,7);let manager=StorageManager::new(requirements());rewrite_split(&manager,&split_request(source.clone(),snapshot.clone(),LiteKind::Snapshot,false)).unwrap();rewrite_split(&manager,&split_request(source,history.clone(),LiteKind::History,false)).unwrap();rewrite_merge(&manager,&MergeRequest{snapshot:snapshot.clone(),history,max_batch_operations:2}).unwrap();let store=manager.open_store(&snapshot).unwrap();for height in 0i64..7{assert!(store.contains_key(&physical_key(&StoreKind::TransactionRet.name(),&height.to_be_bytes())));}assert!(!store.contains_key(&physical_key(&StoreKind::Common.name(),DESCRIPTOR_KEY)));store.close().unwrap();fs::remove_dir_all(parent).unwrap()}

#[test]
fn trace_exclusion_survives_merge_as_permanent_marker(){let parent=root("trace");let source=parent.join("full");let snapshot=parent.join("snapshot");let history=parent.join("history");populate(&source,4);let manager=StorageManager::new(requirements());rewrite_split(&manager,&split_request(source.clone(),snapshot.clone(),LiteKind::Snapshot,true)).unwrap();rewrite_split(&manager,&split_request(source,history.clone(),LiteKind::History,true)).unwrap();rewrite_merge(&manager,&MergeRequest{snapshot:snapshot.clone(),history,max_batch_operations:2}).unwrap();let store=manager.open_store(&snapshot).unwrap();assert!(!store.contains_key(&physical_key(&StoreKind::BalanceTrace.name(),b"trace")));assert_eq!(store.get(&physical_key(&StoreKind::Common.name(),HISTORY_BALANCE_DISABLED_KEY)).unwrap(),b"1");store.close().unwrap();fs::remove_dir_all(parent).unwrap()}

#[test]
fn merge_accepts_later_history_lineage_and_trims_to_snapshot_tip(){let parent=root("later-history");let source=parent.join("full");let snapshot=parent.join("snapshot");let history=parent.join("history");populate(&source,6);let manager=StorageManager::new(requirements());rewrite_split(&manager,&split_request(source.clone(),snapshot.clone(),LiteKind::Snapshot,false)).unwrap();populate(&source,8);rewrite_split(&manager,&split_request(source,history.clone(),LiteKind::History,false)).unwrap();rewrite_merge(&manager,&MergeRequest{snapshot:snapshot.clone(),history,max_batch_operations:2}).unwrap();let store=manager.open_store(&snapshot).unwrap();let heights=(0i64..8).filter(|height|store.contains_key(&physical_key(&StoreKind::BlockIndex.name(),&height.to_be_bytes()))).collect::<Vec<_>>();assert_eq!(heights,vec![0,1,2,3,4,5]);for height in 0i64..8{let(_,_,_,txid)=encoded_block(height);assert!(store.contains_key(&physical_key(&StoreKind::TransactionHistory.name(),&txid)));if height>5{assert!(!store.contains_key(&physical_key(&StoreKind::Transaction.name(),&txid)));assert!(!store.contains_key(&physical_key(&StoreKind::TransactionRet.name(),&height.to_be_bytes())));}}assert!(!store.contains_key(&physical_key(&StoreKind::Common.name(),DESCRIPTOR_KEY)));store.close().unwrap();fs::remove_dir_all(parent).unwrap()}

#[test]
fn missing_transaction_rejects_before_destination_publication(){let parent=root("rollback");let source=parent.join("full");let destination=parent.join("snapshot");populate(&source,4);let manager=StorageManager::new(requirements());let mut store=manager.open_store(&source).unwrap();let(_,_,_,txid)=encoded_block(3);store.delete(physical_key(&StoreKind::Transaction.name(),&txid)).unwrap();store.close().unwrap();let error=rewrite_split(&manager,&split_request(source,destination.clone(),LiteKind::Snapshot,false)).unwrap_err();assert!(matches!(error,tron_storage::StorageError::RewriteRejected{category:"invalid_lite_dataset",..}));assert!(!destination.exists());assert_eq!(fs::read_dir(&parent).unwrap().count(),1);fs::remove_dir_all(parent).unwrap()}
