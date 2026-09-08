//! Fault-safe whole-store transactions used by the Rust toolkit.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::{format::inspect_read_only, DirectoryClassification, OpenRequirements, Result, RustLog, StorageError, StorageManager, WriteBatch};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionPhase {
    Preflight,
    SourcesLocked,
    StagingCreated,
    DataWritten,
    DataSynced,
    Verified,
    JournalSynced,
    OriginalBackedUp,
    DestinationPublished,
    ParentsSynced,
    SourceQuarantined,
    SourceRemoved,
    CleanupSynced,
}

pub trait TransactionFaultInjector {
    fn after(&self, phase: TransactionPhase) -> io::Result<()>;
}

pub struct NoTransactionFaults;
impl TransactionFaultInjector for NoTransactionFaults {
    fn after(&self, _: TransactionPhase) -> io::Result<()> { Ok(()) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RewriteMode { CreateNew, Replace, Move }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewritePolicy { pub max_batch_operations: usize }
impl Default for RewritePolicy {
    fn default() -> Self { Self { max_batch_operations: 1024 } }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyPolicy { CreateNew, IdempotentExact }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreFingerprint {
    pub state_sha256: String,
    pub tree_sha256: String,
    pub manifest_sha256: String,
    pub entries: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewriteOutcome {
    pub fingerprint: StoreFingerprint,
    pub destination: PathBuf,
}

pub type StoreReadView = RustLog;

pub struct RewriteSink<'a> {
    store: &'a mut RustLog,
    batch: WriteBatch,
    maximum: usize,
}
impl RewriteSink<'_> {
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.batch.put(key.to_vec(), value.to_vec());
        if self.batch.len() >= self.maximum { self.flush()?; }
        Ok(())
    }
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.batch.delete(key.to_vec());
        if self.batch.len() >= self.maximum { self.flush()?; }
        Ok(())
    }
    pub fn flush(&mut self) -> Result<()> {
        if self.batch.is_empty() { return Ok(()); }
        self.store.write(std::mem::take(&mut self.batch))
    }
}

pub fn inspect_store(path: impl AsRef<Path>) -> crate::FormatResult<DirectoryClassification> {
    inspect_read_only(path)
}

pub fn rewrite_store(
    manager: &StorageManager,
    sources: &[PathBuf],
    destination: &Path,
    mode: RewriteMode,
    policy: &RewritePolicy,
    faults: &dyn TransactionFaultInjector,
    build: impl FnOnce(&[StoreReadView], &mut RewriteSink<'_>) -> Result<()>,
) -> Result<RewriteOutcome> {
    if policy.max_batch_operations == 0 { return Err(StorageError::InvalidOptions("rewrite batch bound must be non-zero")); }
    if !destination.is_absolute() || destination.components().any(|component| matches!(component, std::path::Component::ParentDir | std::path::Component::Prefix(_))) {
        return Err(StorageError::InvalidOptions("transaction paths must be absolute and normalized by the caller"));
    }
    let destination = destination.to_path_buf();
    let parent_path = destination.parent().ok_or(StorageError::InvalidOptions("destination must have a parent"))?;
    let destination_name = destination.file_name().ok_or(StorageError::InvalidOptions("destination must have a final component"))?;
    let retained_parent = crate::fs::SecureDir::open(parent_path).map_err(StorageError::from)?;
    validate_retained_private(&retained_parent, parent_path)?;
    retained_parent.validate_path_identity().map_err(|_| StorageError::ConcurrentOpen { path: Some(parent_path.to_path_buf()) })?;
    let parent_lock=retained_parent.lock_root_exclusive().map_err(StorageError::from)?;

    let destination_class = inspect_read_only(&destination)?;
    match (mode, &destination_class) {
        (RewriteMode::CreateNew | RewriteMode::Move, DirectoryClassification::Missing) => {}
        (RewriteMode::Replace, DirectoryClassification::Rust(_)) => {}
        (_, DirectoryClassification::Java { .. }) => {
            return match manager.open_store(&destination) { Err(error) => Err(error), Ok(store) => { drop(store); unreachable!("Java store opened") } };
        }
        _ => return Err(StorageError::InvalidCheckpoint { path: destination }),
    }

    let mut candidates = Vec::with_capacity(sources.len() + usize::from(mode == RewriteMode::Replace));
    for source in sources {
        if !source.is_absolute() || source.components().any(|component| matches!(component, std::path::Component::ParentDir | std::path::Component::Prefix(_))) {
            return Err(StorageError::InvalidOptions("transaction paths must be absolute and normalized by the caller"));
        }
        let retained = crate::fs::SecureDir::open(source).map_err(StorageError::from)?;
        validate_retained_private(&retained, source)?;
        retained.validate_path_identity().map_err(|_| StorageError::ConcurrentOpen { path: Some(source.clone()) })?;
        match crate::format::classify_at(&retained, source)? {
            DirectoryClassification::Rust(_) => {}
            DirectoryClassification::Java { marker } => return Err(crate::FormatError::new(crate::StableError::JavaFormat, source, marker).into()),
            _ => return Err(StorageError::InvalidCheckpoint { path: source.clone() }),
        }
        let metadata=fs::metadata(retained.access_path())?; let key=(metadata.dev(),metadata.ino());
        candidates.push((key, true, retained, source.clone()));
    }
    if mode == RewriteMode::Move && candidates.len() != 1 { return Err(StorageError::InvalidOptions("move requires exactly one source")); }
    let destination_retained = if mode == RewriteMode::Replace { Some(crate::fs::SecureDir::open(&destination).map_err(StorageError::from)?) } else { None };
    if let Some(retained) = destination_retained {
        let destination_metadata = fs::metadata(retained.access_path())?;
        let aliases_source = candidates.iter().any(|(_, _, source, _)| fs::metadata(source.access_path()).is_ok_and(|metadata| metadata.dev() == destination_metadata.dev() && metadata.ino() == destination_metadata.ino()));
        if !aliases_source {
            let key=(destination_metadata.dev(),destination_metadata.ino());
            candidates.push((key,false,retained,destination.clone()));
        }
    } else if mode != RewriteMode::Replace && candidates.iter().any(|(_, _, source, _)| retained_parent.open_child(destination_name).is_ok_and(|destination_root| {
        let left=fs::metadata(source.access_path()); let right=fs::metadata(destination_root.access_path()); matches!((left,right),(Ok(left),Ok(right)) if left.dev()==right.dev() && left.ino()==right.ino())
    })) { return Err(StorageError::InvalidOptions("source and destination name the same inode")); }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    if candidates.windows(2).any(|pair| pair[0].0 == pair[1].0) { return Err(StorageError::InvalidOptions("duplicate source store")); }
    faults.after(TransactionPhase::Preflight)?;

    let mut reads = Vec::with_capacity(sources.len());
    let mut destination_guard = None;
    let mut ordered = Vec::with_capacity(sources.len());
    for (_, source, retained, path) in candidates {
        let store = manager.open_retained_store(retained, &path)?;
        if source { ordered.push(path); reads.push(store); } else { destination_guard = Some(store); }
    }
    faults.after(TransactionPhase::SourcesLocked)?;

    let staging_name = random_name("rewrite", destination_name)?;
    let journal_name = random_name("transaction", destination_name)?;
    let backup_name = random_name("backup", destination_name)?;
    let quarantine_name = random_name("quarantine", destination_name)?;
    let mut journal = Journal::new(mode, destination_name, &staging_name, &backup_name, &quarantine_name, ordered.first().map(PathBuf::as_path), &StoreFingerprint::empty())?;
    if mode == RewriteMode::Move { let source=ordered.first().ok_or(StorageError::InvalidOptions("move requires one source"))?;let metadata=fs::metadata(source)?;journal.source_identity=Some(crate::fs::FileIdentity{dev:metadata.dev(),ino:metadata.ino()}); }
    write_journal_at(&retained_parent, &journal_name, &journal)?;
    retained_parent.sync()?;
    let staging = parent_path.join(&staging_name);
    let staging_root = match retained_parent.create_dir(&staging_name) {
        Ok(root) => root,
        Err(error) => {
            drop(destination_guard); for read in reads { drop(read); } drop(parent_lock);
            let _=rollback_transaction(&destination,&manager.requirements);
            return Err(StorageError::from(error));
        }
    };
    journal.staging_identity = Some(staging_root.identity()?);
    retained_parent.sync()?;
    journal.phase="staging_created".into(); update_journal_at(&retained_parent,&journal_name,&journal)?;
    if let Err(error)=faults.after(TransactionPhase::StagingCreated){
        drop(staging_root); drop(destination_guard); for read in reads { drop(read); } drop(parent_lock);
        let _=rollback_transaction(&destination,&manager.requirements);
        return Err(error.into());
    }

    let mut published = false;
    let result = (|| {
        let mut output = manager.open_retained_store(staging_root, &staging)?;
        {
            let mut sink = RewriteSink { store: &mut output, batch: WriteBatch::new(), maximum: policy.max_batch_operations };
            build(&reads, &mut sink)?;
            sink.flush()?;
        }
        output.flush()?;
        journal.phase="data_written".into(); update_journal_at(&retained_parent,&journal_name,&journal)?;
        faults.after(TransactionPhase::DataWritten)?;
        output.close()?;
        journal.phase="data_synced".into(); update_journal_at(&retained_parent,&journal_name,&journal)?;
        faults.after(TransactionPhase::DataSynced)?;
        let expected = fingerprint_retained(&staging, &manager.requirements, retained_parent.open_child(&staging_name)?, retained_parent.open_child(&staging_name)?)?;
        journal.fingerprint=expected.clone();
        if mode == RewriteMode::Move {
            let source = ordered.first().ok_or(StorageError::InvalidOptions("move requires one source"))?;
            let source_tree=crate::fs::SecureDir::open(source).map_err(StorageError::from)?;
            journal.source_fingerprint=Some(fingerprint_open(reads.first().ok_or(StorageError::InvalidOptions("move requires one source"))?,&source_tree)?);
        } else if mode == RewriteMode::Replace {
            let destination_tree=crate::fs::SecureDir::open(&destination).map_err(StorageError::from)?;
            if let Some(guard)=destination_guard.as_ref(){
                journal.source_fingerprint=Some(fingerprint_open(guard,&destination_tree)?);
            }else{
                let index=ordered.iter().position(|path|path==&destination).ok_or(StorageError::InvalidOptions("replace requires destination"))?;
                journal.source_fingerprint=Some(fingerprint_open(&reads[index],&destination_tree)?);
            }
        }
        journal.phase="verified".into(); update_journal_at(&retained_parent,&journal_name,&journal)?;
        faults.after(TransactionPhase::Verified)?;
        if mode != RewriteMode::Move { for read in reads.drain(..) { read.close()?; } }
        if let Some(guard) = destination_guard.take() { guard.close()?; }
        faults.after(TransactionPhase::JournalSynced)?;

        if mode == RewriteMode::Replace {
            retained_parent.rename_noreplace(destination_name, &backup_name)?;
            let backup = retained_parent.open_child(&backup_name)?;
            journal.backup_identity = Some(backup.identity()?);
            let original = journal.source_fingerprint.as_ref().ok_or(StorageError::InvalidCheckpoint { path: destination.clone() })?;
            let backup_actual = fingerprint_retained(&parent_path.join(&backup_name), &manager.requirements, retained_parent.open_child(&backup_name)?, backup)?;
            if &backup_actual != original { return Err(StorageError::InvalidCheckpoint { path: parent_path.join(&backup_name) }); }
            retained_parent.sync()?;
            journal.phase="original_backed_up".into();
            update_journal_at(&retained_parent,&journal_name,&journal)?;
            faults.after(TransactionPhase::OriginalBackedUp)?;
        }
        retained_parent.rename_noreplace(&staging_name, destination_name)?;
        if retained_parent.child_identity(destination_name)? != journal.staging_identity.ok_or(StorageError::InvalidCheckpoint { path: destination.clone() })? { return Err(StorageError::InvalidCheckpoint { path: destination.clone() }); }
        retained_parent.sync()?;
        published = true;
        journal.phase="destination_published".into();
        update_journal_at(&retained_parent,&journal_name,&journal)?;
        faults.after(TransactionPhase::DestinationPublished)?;
        retained_parent.validate_path_identity().map_err(|_| StorageError::ConcurrentOpen { path: Some(parent_path.to_path_buf()) })?;
        let published_path=parent_path.join(destination_name);
        let actual=fingerprint_retained(&published_path,&manager.requirements,retained_parent.open_child(destination_name)?,retained_parent.open_child(destination_name)?)?;
        if actual!=expected{return Err(StorageError::InvalidCheckpoint{path:published_path});}
        faults.after(TransactionPhase::ParentsSynced)?;

        if mode == RewriteMode::Move {
            let source = ordered.first().ok_or(StorageError::InvalidOptions("move requires one source"))?;
            let source_parent_path = source.parent().ok_or(StorageError::InvalidOptions("source must have a parent"))?;
            let source_name = source.file_name().ok_or(StorageError::InvalidOptions("source must have a final component"))?;
            let source_parent = crate::fs::SecureDir::open(source_parent_path).map_err(StorageError::from)?;
            source_parent.validate_path_identity().map_err(|_| StorageError::ConcurrentOpen { path: Some(source_parent_path.to_path_buf()) })?;
            let source_root=crate::fs::SecureDir::open(source).map_err(StorageError::from)?;
            source_root.validate_path_identity().map_err(|_| StorageError::ConcurrentOpen { path: Some(source.clone()) })?;
            let source_identity = source_root.identity()?;
            if Some(source_identity)!=journal.source_identity{return Err(StorageError::InvalidCheckpoint{path:source.clone()});}
            let source_read=reads.first().ok_or(StorageError::InvalidOptions("move requires one source"))?;
            let actual_source=fingerprint_open(source_read,&source_root)?;
            if Some(&actual_source)!=journal.source_fingerprint.as_ref(){return Err(StorageError::InvalidCheckpoint{path:source.clone()});}
            source_parent.rename_noreplace(source_name, &quarantine_name)?;
            if source_parent.child_identity(&quarantine_name)? != source_identity { return Err(StorageError::InvalidCheckpoint { path: source.clone() }); }
            let after_rename=fingerprint_open(source_read,&source_root)?;
            if after_rename!=actual_source{return Err(StorageError::InvalidCheckpoint{path:source.clone()});}
            journal.quarantine_identity=Some(source_identity);
            source_parent.sync()?;
            journal.phase="source_quarantined".into();
            update_journal_at(&retained_parent,&journal_name,&journal)?;
            faults.after(TransactionPhase::SourceQuarantined)?;
            reads.pop().expect("move source exists").close()?;
            source_parent.remove_tree_identity(&quarantine_name,source_identity)?;
            source_parent.sync()?;
            journal.phase="source_removed".into();
            update_journal_at(&retained_parent,&journal_name,&journal)?;
            faults.after(TransactionPhase::SourceRemoved)?;
        }
        if mode == RewriteMode::Replace {
            retained_parent.remove_tree_identity(&backup_name,journal.backup_identity.ok_or(StorageError::InvalidCheckpoint { path: parent_path.join(&backup_name) })?)?;
        }
        retained_parent.remove_file(&journal_name)?;
        retained_parent.sync()?;
        faults.after(TransactionPhase::CleanupSynced)?;
        Ok(RewriteOutcome { fingerprint: expected, destination: destination.clone() })
    })();
    if result.is_err() && !published {
        drop(destination_guard);
        for read in reads { drop(read); }
        drop(parent_lock);
        // Recovery owns all destructive cleanup. It validates every surviving generation,
        // durably restores a replacement backup, and only then removes the journal.
        let _ = rollback_transaction(&destination, &manager.requirements);
        return result;
    }
    drop(parent_lock);
    result
}

impl StorageManager {
    pub fn rewrite_store(
        &self, sources: &[PathBuf], destination: &Path, mode: RewriteMode,
        policy: &RewritePolicy, faults: &dyn TransactionFaultInjector,
        build: impl FnOnce(&[StoreReadView], &mut RewriteSink<'_>) -> Result<()>,
    ) -> Result<RewriteOutcome> {
        rewrite_store(self, sources, destination, mode, policy, faults, build)
    }
}
pub fn copy_store(source: &Path, destination: &Path, requirements: &OpenRequirements, policy: CopyPolicy) -> Result<StoreFingerprint> {
    let manager = StorageManager::new(requirements.clone());
    // CreateNew avoids a full source fingerprint; the staged verifier computes it once.
    if policy == CopyPolicy::IdempotentExact {
        match inspect_read_only(destination)? {
            DirectoryClassification::Missing => {}
            DirectoryClassification::Rust(_) => {
                let (source_fp,destination_fp)=fingerprint_pair_locked(source,destination,requirements)?;
                if destination_fp == source_fp { return Ok(destination_fp); }
            }
            DirectoryClassification::Java { .. } => { let _ = fingerprint_store(destination, requirements)?; unreachable!("Java fingerprint accepted") }
            _ => return Err(StorageError::InvalidCheckpoint { path: destination.to_path_buf() }),
        }
    }
    let outcome = rewrite_store(&manager, &[source.to_path_buf()], destination, RewriteMode::CreateNew, &RewritePolicy::default(), &NoTransactionFaults, |sources, sink| {
        sources[0].visit_entries(|key, value| sink.put(key, value))
    })?;
    Ok(outcome.fingerprint)
}

pub fn checkpoint_store(source: &Path, destination: &Path, requirements: &OpenRequirements) -> Result<StoreFingerprint> {
    copy_store(source, destination, requirements, CopyPolicy::IdempotentExact)
}

pub fn move_store(source: &Path, destination: &Path, requirements: &OpenRequirements) -> Result<StoreFingerprint> {
    let manager = StorageManager::new(requirements.clone());
    Ok(rewrite_store(&manager, &[source.to_path_buf()], destination, RewriteMode::Move, &RewritePolicy::default(), &NoTransactionFaults, |sources, sink| {
        sources[0].visit_entries(|key, value| sink.put(key, value))
    })?.fingerprint)
}

pub fn fingerprint_store(path: &Path, requirements: &OpenRequirements) -> Result<StoreFingerprint> {
    if !path.is_absolute() { return Err(StorageError::InvalidOptions("fingerprint path must be absolute")); }
    let state_root = crate::fs::SecureDir::open(path).map_err(StorageError::from)?;
    let tree_root = crate::fs::SecureDir::open(path).map_err(StorageError::from)?;
    fingerprint_retained(path, requirements, state_root, tree_root)
}

fn fingerprint_retained(path: &Path, requirements: &OpenRequirements, state_root: crate::fs::SecureDir, tree_root: crate::fs::SecureDir) -> Result<StoreFingerprint> {
    let manager = StorageManager::new(requirements.clone());
    let store = manager.open_retained_store(state_root, path)?;
    let fingerprint=fingerprint_open(&store,&tree_root)?;
    store.close()?;Ok(fingerprint)
}

fn fingerprint_open(store:&RustLog,tree_root:&crate::fs::SecureDir)->Result<StoreFingerprint>{
    let mut state=Sha256::new();state.update(b"C027LOG1");let mut entries=0u64;
    const INTERNAL_STORE:&str="\0physical";
    for (physical,value) in &store.entries { if decode_physical_key(physical).is_none(){hash_logical_row(&mut state,INTERNAL_STORE,physical,value);entries+=1;} }
    let namespaces=store.entries.keys().filter_map(|physical|decode_physical_key(physical).map(|(name,_)|name)).collect::<std::collections::BTreeSet<_>>();
    for name in namespaces { let mut prefix=Vec::with_capacity(5+name.len());prefix.push(1);prefix.extend_from_slice(&(name.len() as u32).to_be_bytes());prefix.extend_from_slice(name.as_bytes());for (physical,value) in store.entries.range(prefix.clone()..).take_while(|(physical,_)|physical.starts_with(&prefix)){hash_logical_row(&mut state,name,&physical[prefix.len()..],value);entries+=1;} }
    let mut manifest_bytes=Vec::new();tree_root.open_file(crate::MANIFEST_FILE.as_ref(),false,false)?.read_to_end(&mut manifest_bytes)?;
    let mut manifest_hash=Sha256::new();manifest_hash.update(&manifest_bytes);
    let mut tree=Sha256::new();tree.update(b"C027TREE1");hash_tree_at(tree_root,b"",&mut tree)?;
    Ok(StoreFingerprint{state_sha256:hex(state.finalize()),tree_sha256:hex(tree.finalize()),manifest_sha256:hex(manifest_hash.finalize()),entries})
}

fn hash_logical_row(hash:&mut Sha256,name:&str,key:&[u8],value:&[u8]){hash.update((name.len() as u32).to_be_bytes());hash.update(name.as_bytes());hash_field(hash,key);hash_field(hash,value);}

fn decode_physical_key(key:&[u8])->Option<(&str,&[u8])>{if key.len()<5||key[0]!=1{return None;}let length=u32::from_be_bytes(key[1..5].try_into().ok()?)as usize;let end=5usize.checked_add(length)?;Some((std::str::from_utf8(key.get(5..end)?).ok()?,key.get(end..)?))}

fn fingerprint_pair_locked(source:&Path,destination:&Path,requirements:&OpenRequirements)->Result<(StoreFingerprint,StoreFingerprint)>{
    let source_root=crate::fs::SecureDir::open(source).map_err(StorageError::from)?;let source_tree=crate::fs::SecureDir::open(source).map_err(StorageError::from)?;
    let destination_root=crate::fs::SecureDir::open(destination).map_err(StorageError::from)?;let destination_tree=crate::fs::SecureDir::open(destination).map_err(StorageError::from)?;
    let source_meta=fs::metadata(source_root.access_path())?;let destination_meta=fs::metadata(destination_root.access_path())?;
    let manager=StorageManager::new(requirements.clone());
    if (source_meta.dev(),source_meta.ino())==(destination_meta.dev(),destination_meta.ino()) { let store=manager.open_retained_store(source_root,source)?;let fp=fingerprint_open(&store,&source_tree)?;store.close()?;return Ok((fp.clone(),fp)); }
    let (source_store,destination_store)=if (source_meta.dev(),source_meta.ino())<(destination_meta.dev(),destination_meta.ino()) { let source_store=manager.open_retained_store(source_root,source)?;let destination_store=manager.open_retained_store(destination_root,destination)?;(source_store,destination_store) } else { let destination_store=manager.open_retained_store(destination_root,destination)?;let source_store=manager.open_retained_store(source_root,source)?;(source_store,destination_store) };
    let source_fp=fingerprint_open(&source_store,&source_tree)?;let destination_fp=fingerprint_open(&destination_store,&destination_tree)?;source_store.close()?;destination_store.close()?;Ok((source_fp,destination_fp))
}

pub fn resume_transaction(destination: &Path, requirements: &OpenRequirements) -> Result<StoreFingerprint> {
    let (parent_path,destination_name)=transaction_destination(destination)?;
    let parent=crate::fs::SecureDir::open(parent_path).map_err(StorageError::from)?;
    validate_retained_private(&parent,parent_path)?;
    let _parent_lock=parent.lock_root_exclusive().map_err(StorageError::from)?;
    parent.validate_path_identity().map_err(|_|StorageError::ConcurrentOpen{path:Some(parent_path.to_path_buf())})?;
    let (journal_name,mut journal)=find_journal_at(&parent,destination)?;
    let invalid=||StorageError::InvalidCheckpoint{path:destination.to_path_buf()};

    match (journal.mode,journal.phase.as_str()) {
        (RewriteMode::CreateNew|RewriteMode::Move,"verified") => {
            if parent.contains(destination_name)?||!parent.contains(journal.staging.as_ref())? { return Err(invalid()); }
            require_child_fingerprint(&parent,journal.staging.as_ref(),parent_path,requirements,&journal.fingerprint)?;
            let staging_identity=journal.staging_identity.ok_or_else(invalid)?;parent.rename_noreplace(journal.staging.as_ref(),destination_name)?;if parent.child_identity(destination_name)?!=staging_identity{return Err(invalid());}parent.sync()?;
            journal.phase="destination_published".into();update_journal_at(&parent,&journal_name,&journal)?;
        }
        (RewriteMode::Replace,"verified") => {
            let destination_exists=parent.contains(destination_name)?;let backup_exists=parent.contains(journal.backup.as_ref())?;
            if !parent.contains(journal.staging.as_ref())?||destination_exists==backup_exists{return Err(invalid());}
            require_child_fingerprint(&parent,journal.staging.as_ref(),parent_path,requirements,&journal.fingerprint)?;
            if destination_exists {
                fingerprint_child_at(&parent,destination_name,parent_path,requirements)?;
                let identity=parent.child_identity(destination_name)?;parent.rename_noreplace(destination_name,journal.backup.as_ref())?;if parent.child_identity(journal.backup.as_ref())?!=identity{return Err(invalid());}journal.backup_identity=Some(identity);parent.sync()?;
            } else {
                fingerprint_child_at(&parent,journal.backup.as_ref(),parent_path,requirements)?;
                let identity=journal.backup_identity.ok_or_else(invalid)?;if parent.child_identity(journal.backup.as_ref())?!=identity{return Err(invalid());}
            }
            journal.phase="original_backed_up".into();update_journal_at(&parent,&journal_name,&journal)?;
            let staging_identity=journal.staging_identity.ok_or_else(invalid)?;parent.rename_noreplace(journal.staging.as_ref(),destination_name)?;if parent.child_identity(destination_name)?!=staging_identity{return Err(invalid());}parent.sync()?;
            journal.phase="destination_published".into();update_journal_at(&parent,&journal_name,&journal)?;
        }
        (RewriteMode::Replace,"original_backed_up") => {
            if !parent.contains(journal.backup.as_ref())?{return Err(invalid());}
            let original=journal.source_fingerprint.as_ref().ok_or_else(invalid)?;
            require_child_fingerprint(&parent,journal.backup.as_ref(),parent_path,requirements,original)?;
            if parent.contains(journal.staging.as_ref())? {
                if parent.contains(destination_name)?{return Err(invalid());}
                require_child_fingerprint(&parent,journal.staging.as_ref(),parent_path,requirements,&journal.fingerprint)?;
                let staging_identity=journal.staging_identity.ok_or_else(invalid)?;parent.rename_noreplace(journal.staging.as_ref(),destination_name)?;if parent.child_identity(destination_name)?!=staging_identity{return Err(invalid());}parent.sync()?;
            } else if parent.contains(destination_name)? { require_child_fingerprint(&parent,destination_name,parent_path,requirements,&journal.fingerprint)?; }
            else{return Err(invalid());}
            journal.phase="destination_published".into();update_journal_at(&parent,&journal_name,&journal)?;
        }
        (_,"destination_published") | (RewriteMode::Move,"source_quarantined"|"source_removed") => {}
        _ => return Err(invalid()),
    }
    let fingerprint=require_child_fingerprint(&parent,destination_name,parent_path,requirements,&journal.fingerprint)?;
    if parent.contains(journal.staging.as_ref())?{return Err(invalid());}
    if journal.mode==RewriteMode::Replace&&parent.contains(journal.backup.as_ref())?{
        let original=journal.source_fingerprint.as_ref().ok_or_else(invalid)?;
        require_child_fingerprint(&parent,journal.backup.as_ref(),parent_path,requirements,original)?;
        parent.remove_tree_identity(journal.backup.as_ref(),journal.backup_identity.ok_or_else(invalid)?)?;parent.sync()?;
    }
    if journal.mode==RewriteMode::Move{
        let source=journal.source.as_ref().ok_or_else(invalid)?;
        let expected_source=journal.source_fingerprint.as_ref().ok_or_else(invalid)?;
        let source_parent_path=source.parent().ok_or(StorageError::InvalidOptions("source must have a parent"))?;
        let source_name=source.file_name().ok_or(StorageError::InvalidOptions("source must have a final component"))?;
        let source_parent=crate::fs::SecureDir::open(source_parent_path).map_err(StorageError::from)?;
        validate_retained_private(&source_parent,source_parent_path)?;
        source_parent.validate_path_identity().map_err(|_|StorageError::ConcurrentOpen{path:Some(source_parent_path.to_path_buf())})?;
        match journal.phase.as_str(){
            "destination_published"=>{
                if source_parent.child_identity(source_name)?!=journal.source_identity.ok_or_else(invalid)?{return Err(invalid());}
                if !source_parent.contains(source_name)?||source_parent.contains(journal.quarantine.as_ref())?{return Err(invalid());}
                let root=source_parent.open_child(source_name)?;let tree=source_parent.open_child(source_name)?;
                let manager=StorageManager::new(requirements.clone());let source_store=manager.open_retained_store(root,source)?;
                let actual=fingerprint_open(&source_store,&tree)?;if &actual!=expected_source{return Err(StorageError::InvalidCheckpoint{path:source.clone()});}
                let source_identity=tree.identity()?;
                source_parent.rename_noreplace(source_name,journal.quarantine.as_ref())?;
                if source_parent.child_identity(journal.quarantine.as_ref())?!=source_identity{return Err(invalid());}
                let after=fingerprint_open(&source_store,&tree)?;if &after!=expected_source{return Err(StorageError::InvalidCheckpoint{path:source.clone()});}
                journal.quarantine_identity=Some(source_identity);source_parent.sync()?;
                journal.phase="source_quarantined".into();update_journal_at(&parent,&journal_name,&journal)?;
                source_store.close()?;
            }
            "source_quarantined"=>{
                if source_parent.contains(source_name)?||!source_parent.contains(journal.quarantine.as_ref())?{return Err(invalid());}
                let identity=journal.quarantine_identity.ok_or_else(invalid)?;if source_parent.child_identity(journal.quarantine.as_ref())?!=identity{return Err(invalid());}
                require_child_fingerprint(&source_parent,journal.quarantine.as_ref(),source_parent_path,requirements,expected_source)?;
            }
            _=>return Err(invalid()),
        }
        if journal.phase=="source_quarantined"{source_parent.remove_tree_identity(journal.quarantine.as_ref(),journal.quarantine_identity.ok_or_else(invalid)?)?;source_parent.sync()?;journal.phase="source_removed".into();update_journal_at(&parent,&journal_name,&journal)?;}
    }
    parent.remove_file(&journal_name)?;parent.sync()?;Ok(fingerprint)
}
/// Rolls back a pre-switch generation migration after validating the journal and old manifest
/// under the same retained exclusive root lock.
pub fn rollback_migration_checked(path:&Path,requirements:&OpenRequirements)->Result<()> {
    let root=crate::fs::SecureDir::open(path).map_err(StorageError::from)?;
    let _lock=root.lock_exclusive(crate::format::MIGRATION_LOCK.as_ref()).map_err(StorageError::from)?;
    root.validate_path_identity().map_err(|_|StorageError::ConcurrentOpen{path:Some(path.to_path_buf())})?;
    let journal_path=path.join("tron-storage.migration");let mut bytes=Vec::new();root.open_file("tron-storage.migration".as_ref(),false,false)?.take(4096).read_to_end(&mut bytes)?;
    let text=std::str::from_utf8(&bytes).map_err(|_|StorageError::InvalidCheckpoint{path:journal_path.clone()})?;let split=text.rfind("checksum=").ok_or_else(||StorageError::InvalidCheckpoint{path:journal_path.clone()})?;let(body,checksum)=text.split_at(split);
    let claimed=u32::from_str_radix(checksum.trim().strip_prefix("checksum=").unwrap_or(""),16).map_err(|_|StorageError::InvalidCheckpoint{path:journal_path.clone()})?;if crc32(body.as_bytes())!=claimed{return Err(StorageError::InvalidCheckpoint{path:journal_path});}
    let mut fields=std::collections::BTreeMap::new();let mut lines=body.lines();if lines.next()!=Some("TRON-RUST-STORAGE-MIGRATION"){return Err(StorageError::InvalidCheckpoint{path:path.to_path_buf()});}for line in lines{let(key,value)=line.split_once('=').ok_or_else(||StorageError::InvalidCheckpoint{path:path.to_path_buf()})?;if fields.insert(key,value).is_some(){return Err(StorageError::InvalidCheckpoint{path:path.to_path_buf()});}}
    let expected=["from","phase","root","source_schema","target_schema","to"];if fields.keys().copied().collect::<Vec<_>>()!=expected||fields["phase"]!="prepared"||!fields["root"].is_empty(){return Err(StorageError::InvalidCheckpoint{path:path.to_path_buf()});}
    let from:u64=fields["from"].parse().map_err(|_|StorageError::InvalidCheckpoint{path:path.to_path_buf()})?;let to:u64=fields["to"].parse().map_err(|_|StorageError::InvalidCheckpoint{path:path.to_path_buf()})?;let source_schema:u32=fields["source_schema"].parse().map_err(|_|StorageError::InvalidCheckpoint{path:path.to_path_buf()})?;
    if source_schema!=requirements.schema_version||to!=from.checked_add(1).ok_or(StorageError::InvalidCheckpoint{path:path.to_path_buf()})?{return Err(StorageError::InvalidCheckpoint{path:path.to_path_buf()});}
    let mut manifest_bytes=Vec::new();root.open_file(crate::MANIFEST_FILE.as_ref(),false,false)?.take(1024*1024).read_to_end(&mut manifest_bytes)?;let manifest=crate::Manifest::decode(&manifest_bytes,&path.join(crate::MANIFEST_FILE))?;manifest.validate(requirements,path)?;if manifest.generation!=from{return Err(StorageError::InvalidCheckpoint{path:path.to_path_buf()});}
    for candidate in [format!(".migration-{to}"),format!("generation-{to}")] { if root.contains(candidate.as_ref())?{root.remove_tree(candidate.as_ref())?;} }
    root.remove_file("tron-storage.migration".as_ref())?;let backup=format!("manifest-generation-{from}.backup");if root.contains(backup.as_ref())?{root.remove_file(backup.as_ref())?;}root.sync()?;Ok(())
}

pub fn rollback_transaction(destination:&Path,requirements:&OpenRequirements)->Result<()> {
    let (parent_path,destination_name)=transaction_destination(destination)?;
    let parent=crate::fs::SecureDir::open(parent_path).map_err(StorageError::from)?;
    validate_retained_private(&parent,parent_path)?;
    let _parent_lock=parent.lock_root_exclusive().map_err(StorageError::from)?;
    parent.validate_path_identity().map_err(|_|StorageError::ConcurrentOpen{path:Some(parent_path.to_path_buf())})?;
    let (journal_name,journal)=find_journal_at(&parent,destination)?;
    let invalid=||StorageError::InvalidCheckpoint{path:destination.to_path_buf()};
    let destination_exists=parent.contains(destination_name)?;let staging_exists=parent.contains(journal.staging.as_ref())?;let backup_exists=parent.contains(journal.backup.as_ref())?;
    match (journal.mode,journal.phase.as_str()) {
        (RewriteMode::CreateNew|RewriteMode::Move,"prepared"|"staging_created"|"data_written"|"data_synced") if !destination_exists&&!backup_exists => {}
        (RewriteMode::CreateNew|RewriteMode::Move,"verified") if !destination_exists&&!backup_exists&&staging_exists => {require_child_fingerprint(&parent,journal.staging.as_ref(),parent_path,requirements,&journal.fingerprint)?;}
        (RewriteMode::Replace,"prepared"|"staging_created"|"data_written"|"data_synced") if destination_exists&&!backup_exists => {fingerprint_child_at(&parent,destination_name,parent_path,requirements)?;}
        (RewriteMode::Replace,"verified") if staging_exists&&destination_exists&&!backup_exists => {
            let original=journal.source_fingerprint.as_ref().ok_or_else(invalid)?;
            require_child_fingerprint(&parent,destination_name,parent_path,requirements,original)?;
            require_child_fingerprint(&parent,journal.staging.as_ref(),parent_path,requirements,&journal.fingerprint)?;
        }
        (RewriteMode::Replace,"verified"|"original_backed_up"|"destination_published") if backup_exists => {
            let original=journal.source_fingerprint.as_ref().ok_or_else(invalid)?;
            require_child_fingerprint(&parent,journal.backup.as_ref(),parent_path,requirements,original)?;
            if staging_exists{require_child_fingerprint(&parent,journal.staging.as_ref(),parent_path,requirements,&journal.fingerprint)?;}
            if destination_exists{
                require_child_fingerprint(&parent,destination_name,parent_path,requirements,&journal.fingerprint)?;
                let identity=journal.staging_identity.ok_or_else(invalid)?;if parent.child_identity(destination_name)?!=identity{return Err(invalid());}parent.remove_tree_identity(destination_name,identity)?;parent.sync()?;
            }
        }
        _ => return Err(invalid()),
    }
    if staging_exists{parent.remove_tree_identity(journal.staging.as_ref(),journal.staging_identity.ok_or_else(invalid)?)?;parent.sync()?;}
    if backup_exists{let identity=journal.backup_identity.ok_or_else(invalid)?;if parent.child_identity(journal.backup.as_ref())?!=identity{return Err(invalid());}parent.rename_noreplace(journal.backup.as_ref(),destination_name)?;if parent.child_identity(destination_name)?!=identity{return Err(invalid());}parent.sync()?;}
    if journal.mode==RewriteMode::Replace{
        let original=journal.source_fingerprint.as_ref();
        if let Some(original)=original{require_child_fingerprint(&parent,destination_name,parent_path,requirements,original)?;}
        else{fingerprint_child_at(&parent,destination_name,parent_path,requirements)?;}
    }
    parent.sync()?;
    parent.remove_file(&journal_name)?;parent.sync()?;Ok(())
}

fn transaction_destination(destination:&Path)->Result<(&Path,&OsStr)>{
    if !destination.is_absolute()||destination.components().any(|component|matches!(component,std::path::Component::ParentDir|std::path::Component::Prefix(_))){return Err(StorageError::InvalidOptions("transaction paths must be absolute and normalized by the caller"));}
    Ok((destination.parent().ok_or(StorageError::InvalidOptions("destination must have a parent"))?,destination.file_name().ok_or(StorageError::InvalidOptions("destination must have a final component"))?))
}
fn fingerprint_child_at(parent:&crate::fs::SecureDir,name:&OsStr,parent_path:&Path,requirements:&OpenRequirements)->Result<StoreFingerprint>{
    let path=parent_path.join(name);fingerprint_retained(&path,requirements,parent.open_child(name)?,parent.open_child(name)?)
}
fn require_child_fingerprint(parent:&crate::fs::SecureDir,name:&OsStr,parent_path:&Path,requirements:&OpenRequirements,expected:&StoreFingerprint)->Result<StoreFingerprint>{
    let actual=fingerprint_child_at(parent,name,parent_path,requirements)?;if &actual!=expected{return Err(StorageError::InvalidCheckpoint{path:parent_path.join(name)});}Ok(actual)
}

#[derive(Clone)]
struct Journal { phase:String, mode: RewriteMode, destination: String, staging: String, backup: String, quarantine: String, source: Option<PathBuf>, fingerprint: StoreFingerprint, source_fingerprint: Option<StoreFingerprint>, source_identity: Option<crate::fs::FileIdentity>, staging_identity: Option<crate::fs::FileIdentity>, backup_identity: Option<crate::fs::FileIdentity>, quarantine_identity: Option<crate::fs::FileIdentity> }
impl StoreFingerprint { fn empty()->Self{Self{state_sha256:String::new(),tree_sha256:String::new(),manifest_sha256:String::new(),entries:0}} }
impl Journal {
    fn new(mode: RewriteMode, destination: &OsStr, staging: &OsStr, backup: &OsStr, quarantine: &OsStr, source: Option<&Path>, fingerprint: &StoreFingerprint) -> Result<Self> {
        Ok(Self { phase:"prepared".into(), mode, destination: hex(destination.as_encoded_bytes()), staging: staging.to_string_lossy().into_owned(), backup: backup.to_string_lossy().into_owned(), quarantine: quarantine.to_string_lossy().into_owned(), source: source.map(Path::to_path_buf), fingerprint: fingerprint.clone(), source_fingerprint: None, source_identity: None, staging_identity: None, backup_identity: None, quarantine_identity: None })
    }
}

fn write_journal_at(parent: &crate::fs::SecureDir, name: &OsStr, journal: &Journal) -> Result<()> {
    let mode = match journal.mode { RewriteMode::CreateNew => "create", RewriteMode::Replace => "replace", RewriteMode::Move => "move" };
    let source = journal.source.as_ref().map_or_else(String::new, |path| hex(path.as_os_str().as_encoded_bytes()));
    let source_fingerprint=journal.source_fingerprint.clone().unwrap_or_else(StoreFingerprint::empty);
    let source_identity=journal.source_identity.unwrap_or(crate::fs::FileIdentity{dev:0,ino:0});
    let staging=journal.staging_identity.unwrap_or(crate::fs::FileIdentity{dev:0,ino:0});
    let backup=journal.backup_identity.unwrap_or(crate::fs::FileIdentity{dev:0,ino:0});
    let quarantine=journal.quarantine_identity.unwrap_or(crate::fs::FileIdentity{dev:0,ino:0});
    let body = format!("TRON-RUST-TOOLKIT-TRANSACTION\nversion=3\nphase={}\nmode={mode}\ndestination_hex={}\nstaging={}\nstaging_dev={}\nstaging_ino={}\nbackup={}\nbackup_dev={}\nbackup_ino={}\nquarantine={}\nquarantine_dev={}\nquarantine_ino={}\nsource_hex={source}\nsource_dev={}\nsource_ino={}\nstate_sha256={}\ntree_sha256={}\nmanifest_sha256={}\nentries={}\nsource_state_sha256={}\nsource_tree_sha256={}\nsource_manifest_sha256={}\nsource_entries={}\n", journal.phase, journal.destination, journal.staging, staging.dev, staging.ino, journal.backup, backup.dev, backup.ino, journal.quarantine, quarantine.dev, quarantine.ino,source_identity.dev,source_identity.ino,journal.fingerprint.state_sha256, journal.fingerprint.tree_sha256, journal.fingerprint.manifest_sha256, journal.fingerprint.entries, source_fingerprint.state_sha256, source_fingerprint.tree_sha256, source_fingerprint.manifest_sha256, source_fingerprint.entries);
    let checksum = crc32(body.as_bytes());
    let mut file = parent.create_new(name)?;
    write!(file, "{body}checksum={checksum:08x}\n")?; file.sync_all()?; Ok(())
}

fn update_journal_at(parent:&crate::fs::SecureDir,name:&OsStr,journal:&Journal)->Result<()>{
    let temporary=random_name("journal-update",name)?;write_journal_at(parent,&temporary,journal)?;parent.sync()?;parent.rename(&temporary,name)?;parent.sync()?;Ok(())
}

fn find_journal_at(parent:&crate::fs::SecureDir,destination:&Path)->Result<(std::ffi::OsString,Journal)>{
    use std::os::unix::ffi::OsStringExt;
    let invalid=||StorageError::InvalidCheckpoint{path:destination.to_path_buf()};
    let target=destination.file_name().ok_or(StorageError::InvalidOptions("destination must have a final component"))?;
    let prefix=format!(".transaction-{}-",name_scope(target));
    let mut matches=parent.entries()?.into_iter().filter(|(name,kind)|kind.is_file()&&valid_random_suffix(&name.to_string_lossy(),&prefix)).map(|(name,_)|name).collect::<Vec<_>>();
    if matches.len()!=1{return Err(invalid());}
    let name=matches.pop().unwrap();let mut bytes=Vec::new();parent.open_file(&name,false,false)?.take(64*1024).read_to_end(&mut bytes)?;
    let text=std::str::from_utf8(&bytes).map_err(|_|invalid())?;let split=text.rfind("checksum=").ok_or_else(invalid)?;let(body,checksum_line)=text.split_at(split);
    let expected=u32::from_str_radix(checksum_line.trim().strip_prefix("checksum=").unwrap_or(""),16).map_err(|_|invalid())?;if crc32(body.as_bytes())!=expected{return Err(invalid());}
    let mut fields=std::collections::BTreeMap::new();let mut lines=body.lines();if lines.next()!=Some("TRON-RUST-TOOLKIT-TRANSACTION"){return Err(invalid());}
    for line in lines{let(key,value)=line.split_once('=').ok_or_else(invalid)?;if fields.insert(key,value).is_some(){return Err(invalid());}}
    let expected_fields=["backup","backup_dev","backup_ino","destination_hex","entries","manifest_sha256","mode","phase","quarantine","quarantine_dev","quarantine_ino","source_dev","source_entries","source_hex","source_ino","source_manifest_sha256","source_state_sha256","source_tree_sha256","staging","staging_dev","staging_ino","state_sha256","tree_sha256","version"];
    if fields.keys().copied().collect::<Vec<_>>()!=expected_fields||fields.get("version")!=Some(&"3"){return Err(invalid());}
    let get=|key:&str|fields.get(key).copied().ok_or_else(invalid);
    let mode=match get("mode")?{"create"=>RewriteMode::CreateNew,"replace"=>RewriteMode::Replace,"move"=>RewriteMode::Move,_=>return Err(invalid())};
    let destination_hex=get("destination_hex")?.to_owned();if destination_hex!=hex(target.as_encoded_bytes()){return Err(invalid());}
    let staging=get("staging")?;let backup=get("backup")?;let quarantine=get("quarantine")?;
    if !valid_artifact_name(staging,"rewrite",target)||!valid_artifact_name(backup,"backup",target)||!valid_artifact_name(quarantine,"quarantine",target)||staging==backup||staging==quarantine||backup==quarantine{return Err(invalid());}
    let source_bytes=decode_hex(get("source_hex")?).ok_or_else(invalid)?;
    let source=if source_bytes.is_empty(){None}else{Some(PathBuf::from(std::ffi::OsString::from_vec(source_bytes)))};
    if let Some(source_path)=source.as_ref(){
        if !source_path.is_absolute()||source_path.components().any(|component|matches!(component,std::path::Component::ParentDir|std::path::Component::Prefix(_)))||source_path.file_name().is_none(){return Err(invalid());}
        if mode!=RewriteMode::Replace&&source_path==destination{return Err(invalid());}
        if mode!=RewriteMode::Replace {if let(Ok(left),Ok(right))=(fs::metadata(source_path),fs::metadata(destination)){if(left.dev(),left.ino())==(right.dev(),right.ino()){return Err(invalid());}}}
    }
    if mode==RewriteMode::Move&&source.is_none(){return Err(invalid());}
    let parse_identity=|dev:&str,ino:&str|->Result<Option<crate::fs::FileIdentity>>{let dev:u64=get(dev)?.parse().map_err(|_|invalid())?;let ino:u64=get(ino)?.parse().map_err(|_|invalid())?;match(dev,ino){(0,0)=>Ok(None),(0,_)|(_,0)=>Err(invalid()),(dev,ino)=>Ok(Some(crate::fs::FileIdentity{dev,ino}))}};
    let entries=get("entries")?.parse().map_err(|_|invalid())?;let source_entries=get("source_entries")?.parse().map_err(|_|invalid())?;
    let source_fingerprint=StoreFingerprint{state_sha256:get("source_state_sha256")?.into(),tree_sha256:get("source_tree_sha256")?.into(),manifest_sha256:get("source_manifest_sha256")?.into(),entries:source_entries};
    let journal=Journal{phase:get("phase")?.into(),mode,destination:destination_hex,staging:staging.into(),backup:backup.into(),quarantine:quarantine.into(),source,fingerprint:StoreFingerprint{state_sha256:get("state_sha256")?.into(),tree_sha256:get("tree_sha256")?.into(),manifest_sha256:get("manifest_sha256")?.into(),entries},source_fingerprint:if source_fingerprint.state_sha256.is_empty(){None}else{Some(source_fingerprint)},source_identity:parse_identity("source_dev","source_ino")?,staging_identity:parse_identity("staging_dev","staging_ino")?,backup_identity:parse_identity("backup_dev","backup_ino")?,quarantine_identity:parse_identity("quarantine_dev","quarantine_ino")?};
    Ok((name,journal))
}
fn valid_artifact_name(value:&str,kind:&str,destination:&OsStr)->bool{
    valid_random_suffix(value,&format!(".{kind}-{}-",name_scope(destination)))
}
fn valid_random_suffix(value:&str,prefix:&str)->bool{
    value.strip_prefix(prefix).is_some_and(|suffix|suffix.len()==48&&suffix.bytes().all(|byte|byte.is_ascii_digit()||(b'a'..=b'f').contains(&byte)))
}

fn effective_uid()->u32 { rustix::process::geteuid().as_raw() }
fn validate_retained_private(directory:&crate::fs::SecureDir,path:&Path)->Result<()> { let metadata=fs::metadata(directory.access_path())?; if metadata.uid()!=effective_uid()||metadata.mode()&0o777!=0o700{return Err(StorageError::Permission{path:Some(path.to_path_buf())});}Ok(()) }
fn random_name(kind:&str,destination:&OsStr)->Result<std::ffi::OsString>{let mut bytes=[0u8;24];File::open("/dev/urandom")?.read_exact(&mut bytes)?;Ok(format!(".{kind}-{}-{}",name_scope(destination),hex(bytes)).into())}
fn name_scope(value:&OsStr)->String{let digest=Sha256::digest(value.as_encoded_bytes());hex(&digest[..8])}
fn hash_field(hash:&mut Sha256,bytes:&[u8]){hash.update((bytes.len() as u64).to_be_bytes());hash.update(bytes);}
fn hash_tree_at(directory:&crate::fs::SecureDir,prefix:&[u8],hash:&mut Sha256)->Result<()> {
    let mut entries=directory.entries()?; entries.sort_by(|left,right|left.0.as_encoded_bytes().cmp(right.0.as_encoded_bytes()));
    for (name,kind) in entries {
        if name==crate::format::MIGRATION_LOCK { continue; }
        if kind.is_symlink() { return Err(StorageError::Permission{path:Some(directory.child_access_path(&name)?)}); }
        let mut relative=prefix.to_vec(); if !relative.is_empty(){relative.push(b'/');} relative.extend_from_slice(name.as_encoded_bytes());
        hash_field(hash,&relative);
        if kind.is_dir() {
            let child=directory.open_child(&name)?; let metadata=fs::metadata(child.access_path())?;
            hash.update(b"D"); hash.update((metadata.mode()&0o7777).to_be_bytes()); hash_tree_at(&child,&relative,hash)?;
        } else if kind.is_file() {
            let mut file=directory.open_file(&name,false,false)?; let metadata=file.metadata()?;
            hash.update(b"F"); hash.update((metadata.mode()&0o7777).to_be_bytes()); hash.update(metadata.len().to_be_bytes());
            let mut buffer=[0u8;64*1024]; loop{let count=file.read(&mut buffer)?;if count==0{break;}hash.update(&buffer[..count]);}
        } else { return Err(StorageError::Permission{path:Some(directory.child_access_path(&name)?)}); }
    }
    Ok(())
}
fn hex(bytes:impl AsRef<[u8]>)->String{bytes.as_ref().iter().map(|b|format!("{b:02x}")).collect()}
fn decode_hex(value:&str)->Option<Vec<u8>>{if value.len()%2!=0{return None;}value.as_bytes().chunks_exact(2).map(|pair|{let text=std::str::from_utf8(pair).ok()?;u8::from_str_radix(text,16).ok()}).collect()}
fn crc32(bytes:&[u8])->u32{let mut crc=!0u32;for &byte in bytes{crc^=u32::from(byte);for _ in 0..8{crc=(crc>>1)^if crc&1==1{0xedb8_8320}else{0};}}!crc}
