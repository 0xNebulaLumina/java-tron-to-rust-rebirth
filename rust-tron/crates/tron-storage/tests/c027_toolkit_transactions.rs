use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tron_storage::toolkit::{copy_store, fingerprint_store, rewrite_store, CopyPolicy, RewriteMode, RewritePolicy, TransactionFaultInjector, TransactionPhase};
use tron_storage::{OpenRequirements, StableError, StorageError, StorageIdentity, StorageManager, WriteBatch};

fn root(name: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("tron-storage-c027-{name}-{}-{nonce}", std::process::id()));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}
fn requirements() -> OpenRequirements {
    OpenRequirements { identity: StorageIdentity { network: "mainnet".into(), genesis: "00aa".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()] }
}
fn populate(path: &Path) {
    let manager=StorageManager::new(requirements());
    let mut store=manager.open_store(path).unwrap();
    store.put(b"z".to_vec(),b"last".to_vec()).unwrap();
    store.put(b"a".to_vec(),b"first".to_vec()).unwrap();
    store.put(b"m".to_vec(),b"middle".to_vec()).unwrap();
    store.close().unwrap();
}
fn tree(path:&Path)->Vec<(String,Vec<u8>)>{
    fn walk(root:&Path,path:&Path,out:&mut Vec<(String,Vec<u8>)>){
        if !path.exists(){return} let mut rows=fs::read_dir(path).unwrap().map(Result::unwrap).collect::<Vec<_>>(); rows.sort_by_key(|e|e.file_name());
        for row in rows { let child=row.path();let relative=child.strip_prefix(root).unwrap().to_string_lossy().into_owned();if child.is_dir(){out.push((format!("{relative}/"),vec![]));walk(root,&child,out)}else{out.push((relative,fs::read(child).unwrap()))} }
    }
    let mut out=vec![];walk(path,path,&mut out);out
}
fn tree_metadata(path:&Path)->Vec<(String,u32,u32,u32,u64,u64,i64,i64,Vec<u8>)>{
    use std::os::unix::fs::MetadataExt;
    fn walk(root:&Path,path:&Path,out:&mut Vec<(String,u32,u32,u32,u64,u64,i64,i64,Vec<u8>)>){let mut rows=fs::read_dir(path).unwrap().map(Result::unwrap).collect::<Vec<_>>();rows.sort_by_key(|entry|entry.file_name());for row in rows{let child=row.path();let metadata=fs::symlink_metadata(&child).unwrap();let relative=child.strip_prefix(root).unwrap().to_string_lossy().into_owned();let bytes=if metadata.is_file(){fs::read(&child).unwrap()}else{Vec::new()};out.push((relative,metadata.mode(),metadata.uid(),metadata.gid(),metadata.ino(),metadata.size(),metadata.mtime(),metadata.ctime(),bytes));if metadata.is_dir(){walk(root,&child,out);}}}
    let mut out=Vec::new();walk(path,path,&mut out);out
}

#[test]
fn borrowed_visit_is_ordered_and_copy_preserves_state() {
    let parent=root("copy"); let source=parent.join("source"); let destination=parent.join("destination"); populate(&source);
    let manager=StorageManager::new(requirements()); let store=manager.open_store(&source).unwrap(); let mut keys=Vec::new();
    store.visit_entries::<()>(|key,_|{keys.push(key.to_vec());Ok(())}).unwrap(); store.close().unwrap();
    assert_eq!(keys,vec![b"a".to_vec(),b"m".to_vec(),b"z".to_vec()]);
    let copied=copy_store(&source,&destination,&requirements(),CopyPolicy::CreateNew).unwrap();
    let source_fingerprint=fingerprint_store(&source,&requirements()).unwrap();
    assert_eq!(copied.state_sha256,source_fingerprint.state_sha256); assert_eq!(copied.entries,3);
    fs::remove_dir_all(parent).unwrap();
}

struct FailAt(TransactionPhase);
impl TransactionFaultInjector for FailAt { fn after(&self,phase:TransactionPhase)->io::Result<()>{if phase==self.0{Err(io::Error::other("injected"))}else{Ok(())}} }

struct PlantFinal { destination: PathBuf, victim: PathBuf }
impl TransactionFaultInjector for PlantFinal {
    fn after(&self,phase:TransactionPhase)->io::Result<()> {
        if phase==TransactionPhase::StagingCreated { std::os::unix::fs::symlink(&self.victim,&self.destination)?; }
        Ok(())
    }
}

struct AssertSourceLocked { source: PathBuf }
impl TransactionFaultInjector for AssertSourceLocked {
    fn after(&self,phase:TransactionPhase)->io::Result<()> {
        if phase==TransactionPhase::DestinationPublished {
            assert!(matches!(StorageManager::new(requirements()).open_store(&self.source),Err(StorageError::Locked{..})));
        }
        Ok(())
    }
}

#[test]
fn symlink_parent_and_final_component_swaps_never_receive_publication() {
    use std::os::unix::fs::symlink;
    let parent=root("symlink-races");let source=parent.join("source");populate(&source);
    let alias=parent.join("parent-alias");symlink(&parent,&alias).unwrap();
    assert!(copy_store(&source,&alias.join("destination"),&requirements(),CopyPolicy::CreateNew).is_err());
    let destination=parent.join("destination");let victim=parent.join("victim");fs::create_dir(&victim).unwrap();fs::set_permissions(&victim,fs::Permissions::from_mode(0o700)).unwrap();fs::write(victim.join("sentinel"),b"unchanged").unwrap();
    let manager=StorageManager::new(requirements());
    let result=rewrite_store(&manager,&[source],&destination,RewriteMode::CreateNew,&RewritePolicy::default(),&PlantFinal{destination:destination.clone(),victim:victim.clone()},|sources,sink|sources[0].visit_entries(|key,value|sink.put(key,value)));
    assert!(result.is_err());assert_eq!(fs::read(victim.join("sentinel")).unwrap(),b"unchanged");assert!(fs::symlink_metadata(&destination).unwrap().file_type().is_symlink());
    fs::remove_file(destination).unwrap();fs::remove_file(alias).unwrap();fs::remove_dir_all(parent).unwrap();
}

#[test]
fn unpublished_failure_removes_staging_and_preserves_source() {
    let parent=root("rollback");let source=parent.join("source");let destination=parent.join("destination");populate(&source);let before=tree(&source);
    let manager=StorageManager::new(requirements());
    let result=rewrite_store(&manager,&[source.clone()],&destination,RewriteMode::CreateNew,&RewritePolicy{max_batch_operations:1},&FailAt(TransactionPhase::DataWritten),|sources,sink|sources[0].visit_entries(|k,v|sink.put(k,v)));
    assert!(result.is_err());assert!(!destination.exists());assert_eq!(tree(&source),before);
    assert!(fs::read_dir(&parent).unwrap().all(|entry|!entry.unwrap().file_name().to_string_lossy().starts_with(".rewrite-")));
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn published_move_is_verified_and_resumed_before_source_removal() {
    let parent=root("move-resume"); let source=parent.join("source"); let destination=parent.join("destination"); populate(&source);
    let manager=StorageManager::new(requirements());
    let result=rewrite_store(&manager,&[source.clone()],&destination,RewriteMode::Move,&RewritePolicy::default(),&FailAt(TransactionPhase::DestinationPublished),|sources,sink|sources[0].visit_entries(|k,v|sink.put(k,v)));
    assert!(result.is_err()); assert!(source.exists()); assert!(destination.exists());
    let resumed=tron_storage::toolkit::resume_transaction(&destination,&requirements()).unwrap();
    assert_eq!(resumed.entries,3); assert!(!source.exists()); assert!(destination.exists());
    assert!(fs::read_dir(&parent).unwrap().all(|entry|!entry.unwrap().file_name().to_string_lossy().starts_with(".transaction-")));
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn move_holds_source_lock_until_quarantine_and_refuses_changed_resume_source() {
    let parent=root("move-source-guard");let source=parent.join("source");let destination=parent.join("destination");populate(&source);
    let manager=StorageManager::new(requirements());
    rewrite_store(&manager,&[source.clone()],&destination,RewriteMode::Move,&RewritePolicy::default(),&AssertSourceLocked{source:source.clone()},|sources,sink|sources[0].visit_entries(|key,value|sink.put(key,value))).unwrap();
    assert!(!source.exists());

    let changed_source=parent.join("changed-source");let changed_destination=parent.join("changed-destination");populate(&changed_source);
    let result=rewrite_store(&manager,&[changed_source.clone()],&changed_destination,RewriteMode::Move,&RewritePolicy::default(),&FailAt(TransactionPhase::DestinationPublished),|sources,sink|sources[0].visit_entries(|key,value|sink.put(key,value)));
    assert!(result.is_err());
    let mut changed=manager.open_store(&changed_source).unwrap();changed.put(b"attacker".to_vec(),b"changed".to_vec()).unwrap();changed.close().unwrap();
    assert!(tron_storage::toolkit::resume_transaction(&changed_destination,&requirements()).is_err());
    assert!(changed_source.exists());assert_eq!(manager.open_store(&changed_source).unwrap().get(b"attacker"),Some(b"changed".to_vec()));
    assert!(fs::read_dir(&parent).unwrap().any(|entry|entry.unwrap().file_name().to_string_lossy().starts_with(".transaction-")));
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn replace_can_read_destination_once_alongside_another_source() {
    let parent=root("replace-alias");let target=parent.join("target");let history=parent.join("history");populate(&target);populate(&history);
    let manager=StorageManager::new(requirements());
    let outcome=rewrite_store(&manager,&[target.clone(),history],&target,RewriteMode::Replace,&RewritePolicy::default(),&tron_storage::toolkit::NoTransactionFaults,|sources,sink|{
        for source in sources { source.visit_entries(|key,value|sink.put(key,value))?; } Ok(())
    }).unwrap();
    assert_eq!(outcome.destination,target);assert_eq!(outcome.fingerprint.entries,3);
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn symbolic_link_source_is_rejected_without_destination_writes() {
    use std::os::unix::fs::symlink;
    let parent=root("source-link");let real=parent.join("real");let link=parent.join("link");let destination=parent.join("destination");populate(&real);symlink(&real,&link).unwrap();let before=tree(&real);
    assert!(copy_store(&link,&destination,&requirements(),CopyPolicy::CreateNew).is_err());
    assert_eq!(tree(&real),before);assert!(!destination.exists());
    fs::remove_dir_all(parent).unwrap();
}

struct CrashAt(TransactionPhase);
impl TransactionFaultInjector for CrashAt { fn after(&self,phase:TransactionPhase)->io::Result<()>{if phase==self.0{std::process::exit(73)}Ok(())} }

#[test]
fn crash_phase_helper() {
    let Ok(source)=std::env::var("C027_CRASH_SOURCE") else{return};let destination=PathBuf::from(std::env::var("C027_CRASH_DESTINATION").unwrap());
    let phase=match std::env::var("C027_CRASH_PHASE").unwrap().as_str(){"staging"=>TransactionPhase::StagingCreated,"written"=>TransactionPhase::DataWritten,"synced"=>TransactionPhase::DataSynced,"verified"=>TransactionPhase::Verified,"journal_synced"=>TransactionPhase::JournalSynced,"backed_up"=>TransactionPhase::OriginalBackedUp,"published"=>TransactionPhase::DestinationPublished,"parents_synced"=>TransactionPhase::ParentsSynced,"source_quarantined"=>TransactionPhase::SourceQuarantined,_=>unreachable!()};
    let mode=match std::env::var("C027_CRASH_MODE").as_deref(){Ok("replace")=>RewriteMode::Replace,Ok("move")=>RewriteMode::Move,_=>RewriteMode::CreateNew};
    let manager=StorageManager::new(requirements());let source=PathBuf::from(source);let _=rewrite_store(&manager,&[source],&destination,mode,&RewritePolicy::default(),&CrashAt(phase),|sources,sink|sources[0].visit_entries(|key,value|sink.put(key,value)));
}

fn crash_rewrite(source:&Path,destination:&Path,mode:&str,phase:&str){
    let status=std::process::Command::new(std::env::current_exe().unwrap()).arg("--exact").arg("crash_phase_helper").arg("--nocapture").env("C027_CRASH_SOURCE",source).env("C027_CRASH_DESTINATION",destination).env("C027_CRASH_MODE",mode).env("C027_CRASH_PHASE",phase).status().unwrap();assert_eq!(status.code(),Some(73));
}
fn assert_no_transaction_debris(parent:&Path){assert!(fs::read_dir(parent).unwrap().all(|entry|{let name=entry.unwrap().file_name();let name=name.to_string_lossy();!name.starts_with(".transaction-")&&!name.starts_with(".rewrite-")&&!name.starts_with(".backup-")}));}

#[test]
fn every_prepublication_process_death_has_checked_rollback() {
    for phase in ["staging","written","synced","verified"] { let parent=root(&format!("crash-{phase}"));let source=parent.join("source");let destination=parent.join("destination");populate(&source);
        crash_rewrite(&source,&destination,"create",phase);
        tron_storage::toolkit::rollback_transaction(&destination,&requirements()).unwrap();assert!(!destination.exists());assert!(StorageManager::new(requirements()).open_store(&source).is_ok());assert_no_transaction_debris(&parent);fs::remove_dir_all(parent).unwrap(); }
}

#[test]
fn replace_deaths_rollback_or_resume_to_one_complete_generation() {
    for phase in ["verified","journal_synced","backed_up"] {let parent=root(&format!("replace-rollback-{phase}"));let source=parent.join("source");let destination=parent.join("destination");populate(&source);populate(&destination);let manager=StorageManager::new(requirements());let mut source_store=manager.open_store(&source).unwrap();source_store.put(b"generation".to_vec(),b"new".to_vec()).unwrap();source_store.close().unwrap();
        crash_rewrite(&source,&destination,"replace",phase);tron_storage::toolkit::rollback_transaction(&destination,&requirements()).unwrap();let old=manager.open_store(&destination).unwrap();assert!(!old.contains_key(b"generation"));old.close().unwrap();assert_no_transaction_debris(&parent);fs::remove_dir_all(parent).unwrap();}
    for phase in ["published","parents_synced"] {let parent=root(&format!("replace-resume-{phase}"));let source=parent.join("source");let destination=parent.join("destination");populate(&source);populate(&destination);let manager=StorageManager::new(requirements());let mut source_store=manager.open_store(&source).unwrap();source_store.put(b"generation".to_vec(),b"new".to_vec()).unwrap();source_store.close().unwrap();
        crash_rewrite(&source,&destination,"replace",phase);let recovered=tron_storage::toolkit::resume_transaction(&destination,&requirements()).unwrap();assert_eq!(recovered.entries,4);let new=manager.open_store(&destination).unwrap();assert_eq!(new.get(b"generation").unwrap(),b"new");new.close().unwrap();assert_no_transaction_debris(&parent);fs::remove_dir_all(parent).unwrap();}
}

#[test]
fn move_process_death_after_quarantine_resumes_checked_removal() {
    let parent=root("move-quarantine-crash");let source=parent.join("source");let destination=parent.join("destination");populate(&source);
    crash_rewrite(&source,&destination,"move","source_quarantined");
    assert!(!source.exists());assert!(destination.exists());
    let fingerprint=tron_storage::toolkit::resume_transaction(&destination,&requirements()).unwrap();assert_eq!(fingerprint.entries,3);
    assert_no_transaction_debris(&parent);fs::remove_dir_all(parent).unwrap();
}

#[test]
fn replace_rollback_refuses_mutated_backup_or_published_destination_and_retains_recovery() {
    for mutate_backup in [true,false] {
        let parent=root(if mutate_backup{"mutated-backup"}else{"mutated-published"});let source=parent.join("source");let destination=parent.join("destination");populate(&source);populate(&destination);
        let manager=StorageManager::new(requirements());let mut source_store=manager.open_store(&source).unwrap();source_store.put(b"generation".to_vec(),b"new".to_vec()).unwrap();source_store.close().unwrap();
        crash_rewrite(&source,&destination,"replace",if mutate_backup{"backed_up"}else{"published"});
        let target=if mutate_backup{
            fs::read_dir(&parent).unwrap().map(Result::unwrap).find(|entry|entry.file_name().to_string_lossy().starts_with(".backup-")).unwrap().path()
        }else{destination.clone()};
        let mut attacked=manager.open_store(&target).unwrap();attacked.put(b"attacker".to_vec(),b"changed".to_vec()).unwrap();attacked.close().unwrap();
        assert!(tron_storage::toolkit::rollback_transaction(&destination,&requirements()).is_err());
        assert!(target.exists());assert_eq!(manager.open_store(&target).unwrap().get(b"attacker"),Some(b"changed".to_vec()));
        assert!(fs::read_dir(&parent).unwrap().any(|entry|entry.unwrap().file_name().to_string_lossy().starts_with(".transaction-")));
        fs::remove_dir_all(parent).unwrap();
    }
}

struct SubstituteSourceBeforeRename { source:PathBuf, saved:PathBuf }
impl TransactionFaultInjector for SubstituteSourceBeforeRename {
    fn after(&self,phase:TransactionPhase)->io::Result<()> {
        if phase==TransactionPhase::ParentsSynced { fs::rename(&self.source,&self.saved)?;populate(&self.source); }
        Ok(())
    }
}

struct SubstituteQuarantineAfterRename { parent:PathBuf, saved:PathBuf }
impl TransactionFaultInjector for SubstituteQuarantineAfterRename {
    fn after(&self,phase:TransactionPhase)->io::Result<()> {
        if phase==TransactionPhase::SourceQuarantined {
            let quarantine=fs::read_dir(&self.parent)?.map(Result::unwrap).find(|entry|entry.file_name().to_string_lossy().starts_with(".quarantine-")).unwrap().path();
            fs::rename(&quarantine,&self.saved)?;populate(&quarantine);
        }
        Ok(())
    }
}

#[test]
fn move_never_deletes_same_uid_source_substitutions() {
    let parent=root("move-pre-substitute");let source=parent.join("source");let destination=parent.join("destination");let saved=parent.join("original");populate(&source);
    let manager=StorageManager::new(requirements());let result=rewrite_store(&manager,&[source.clone()],&destination,RewriteMode::Move,&RewritePolicy::default(),&SubstituteSourceBeforeRename{source:source.clone(),saved:saved.clone()},|sources,sink|sources[0].visit_entries(|key,value|sink.put(key,value)));
    assert!(result.is_err());assert!(source.exists());assert!(saved.exists());assert!(source.join("tron-storage.manifest").exists());fs::remove_dir_all(parent).unwrap();

    let parent=root("move-post-substitute");let source=parent.join("source");let destination=parent.join("destination");let saved=parent.join("original-quarantine");populate(&source);
    let result=rewrite_store(&manager,&[source],&destination,RewriteMode::Move,&RewritePolicy::default(),&SubstituteQuarantineAfterRename{parent:parent.clone(),saved:saved.clone()},|sources,sink|sources[0].visit_entries(|key,value|sink.put(key,value)));
    assert!(result.is_err());let planted=fs::read_dir(&parent).unwrap().map(Result::unwrap).find(|entry|entry.file_name().to_string_lossy().starts_with(".quarantine-")).unwrap().path();assert!(planted.exists());assert!(saved.exists());fs::remove_dir_all(parent).unwrap();
}

#[test]
fn crc_recomputed_journal_cannot_redirect_cleanup_to_sibling() {
    fn crc32(bytes:&[u8])->u32{let mut crc=!0u32;for &byte in bytes{crc^=u32::from(byte);for _ in 0..8{crc=(crc>>1)^if crc&1==1{0xedb8_8320}else{0};}}!crc}
    let parent=root("journal-redirect");let source=parent.join("source");let destination=parent.join("destination");let sibling=parent.join("sibling");populate(&source);populate(&sibling);
    crash_rewrite(&source,&destination,"create","verified");let journal=fs::read_dir(&parent).unwrap().map(Result::unwrap).find(|entry|entry.file_name().to_string_lossy().starts_with(".transaction-")).unwrap().path();
    let text=fs::read_to_string(&journal).unwrap();let split=text.rfind("checksum=").unwrap();let body=&text[..split];let staging=body.lines().find_map(|line|line.strip_prefix("staging=")).unwrap();let mut tampered=body.replace(&format!("backup={}",body.lines().find_map(|line|line.strip_prefix("backup=")).unwrap()),"backup=sibling");assert_ne!(staging,"sibling");let checksum=crc32(tampered.as_bytes());tampered.push_str(&format!("checksum={checksum:08x}\n"));fs::write(&journal,tampered).unwrap();
    assert!(tron_storage::toolkit::rollback_transaction(&destination,&requirements()).is_err());assert!(sibling.exists());assert!(sibling.join("tron-storage.manifest").exists());fs::remove_dir_all(parent).unwrap();
}

#[test]
fn non_utf8_paths_roundtrip_through_move_journal() {
    use std::os::unix::ffi::OsStringExt;
    let parent=root("nonutf8");let source=parent.join(std::ffi::OsString::from_vec(vec![b's',0xff,b'c']));let destination=parent.join(std::ffi::OsString::from_vec(vec![b'd',0xfe,b't']));populate(&source);
    let manager=StorageManager::new(requirements());let result=rewrite_store(&manager,&[source.clone()],&destination,RewriteMode::Move,&RewritePolicy::default(),&FailAt(TransactionPhase::DestinationPublished),|sources,sink|sources[0].visit_entries(|key,value|sink.put(key,value)));
    assert!(result.is_err());let fingerprint=tron_storage::toolkit::resume_transaction(&destination,&requirements()).unwrap();assert_eq!(fingerprint.entries,3);assert!(!source.exists());
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn checked_migration_rollback_validates_and_removes_pre_switch_state() {
    let parent=root("checked-migration");let store_path=parent.join("store");populate(&store_path);
    let mut body=b"TRON-RUST-STORAGE-MIGRATION\nfrom=0\nto=1\nsource_schema=1\ntarget_schema=2\nphase=prepared\nroot=\n".to_vec();let mut crc=!0u32;for &byte in &body{crc^=u32::from(byte);for _ in 0..8{crc=(crc>>1)^if crc&1==1{0xedb8_8320}else{0};}}body.extend_from_slice(format!("checksum={:08x}\n",!crc).as_bytes());
    fs::write(store_path.join("tron-storage.migration"),body).unwrap();fs::create_dir(store_path.join(".migration-1")).unwrap();fs::set_permissions(store_path.join(".migration-1"),fs::Permissions::from_mode(0o700)).unwrap();
    tron_storage::toolkit::rollback_migration_checked(&store_path,&requirements()).unwrap();assert!(!store_path.join("tron-storage.migration").exists());assert!(!store_path.join(".migration-1").exists());assert!(tron_storage::open_manifest(&store_path,&requirements()).is_ok());fs::remove_dir_all(parent).unwrap();
}

/// Emits the real six-row C027 RustLog fixture record for oracle artifact generation.
/// Run with: cargo test -p tron-storage --test c027_toolkit_transactions emit_c027_six_row_fixture_json -- --ignored --exact --nocapture
#[test]
#[ignore]
fn emit_c027_six_row_fixture_json() {
    use sha2::{Digest,Sha256};
    fn physical(store:&str,key:&[u8])->Vec<u8>{let mut out=vec![1];out.extend_from_slice(&(store.len() as u32).to_be_bytes());out.extend_from_slice(store.as_bytes());out.extend_from_slice(key);out}
    fn decode(value:&str)->Vec<u8>{value.as_bytes().chunks_exact(2).map(|pair|u8::from_str_radix(std::str::from_utf8(pair).unwrap(),16).unwrap()).collect()}
    fn digest(bytes:&[u8])->String{Sha256::digest(bytes).iter().map(|byte|format!("{byte:02x}")).collect()}
    let parent=root("fixture-emitter");let database=parent.join("rustlog");
    let requirements=OpenRequirements{identity:StorageIdentity{network:"mainnet".into(),genesis:"c027".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]};
    let rows=[("block","00","010203"),("block-index","6865696768743a30","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),("trans","74783a30","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),("transactionRetStore","7265743a30","00"),("transactionHistoryStore","686973746f72793a30","01"),("account","616c696365","00000000000003e8")];
    let manager=StorageManager::new(requirements.clone());let mut log=manager.open_store(&database).unwrap();let mut batch=WriteBatch::new();for (store,key,value) in rows{batch.put(physical(store,&decode(key)),decode(value));}log.write(batch).unwrap();log.close().unwrap();
    let fingerprint=fingerprint_store(&database,&requirements).unwrap();let manifest_path=database.join("tron-storage.manifest");let wal_path=database.join("generation-0/rustlog-v1.wal");let manifest=fs::read(&manifest_path).unwrap();let wal=fs::read(&wal_path).unwrap();let physical_size=manifest.len()+wal.len();
    println!("{{\"entry_count\":{},\"manifest\":{{\"path\":\"tron-storage.manifest\",\"sha256\":\"{}\",\"size\":{}}},\"manifest_sha256\":\"{}\",\"physical_size\":{},\"state_sha256\":\"{}\",\"tree_sha256\":\"{}\",\"wal\":{{\"path\":\"generation-0/rustlog-v1.wal\",\"sha256\":\"{}\",\"size\":{}}}}}",fingerprint.entries,digest(&manifest),manifest.len(),fingerprint.manifest_sha256,physical_size,fingerprint.state_sha256,fingerprint.tree_sha256,digest(&wal),wal.len());
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn java_marker_rejection_is_byte_identical_and_creates_nothing() {
    let parent=root("java");let source=parent.join("source");fs::create_dir(&source).unwrap();fs::set_permissions(&source,fs::Permissions::from_mode(0o700)).unwrap();fs::write(source.join("CURRENT"),b"sentinel").unwrap();let destination=parent.join("destination");let before=tree_metadata(&source);
    let error=copy_store(&source,&destination,&requirements(),CopyPolicy::CreateNew).unwrap_err();
    assert!(matches!(&error,StorageError::Format(error) if error.category==StableError::JavaFormat));
    assert_eq!(tree_metadata(&source),before);assert!(!destination.exists());assert_eq!(fs::read_dir(&parent).unwrap().count(),1);
    fs::remove_dir_all(parent).unwrap();
}
