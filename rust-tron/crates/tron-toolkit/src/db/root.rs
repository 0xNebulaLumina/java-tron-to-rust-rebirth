use std::collections::BTreeMap;
use std::path::Path;
use sha2::{Digest, Sha256};
use tron_state::StoreKind;
use tron_storage::{DirectoryClassification, OpenRequirements, StorageManager};
use super::inspect::{DbFailure, JAVA_REJECTION_GUIDANCE};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreRoot { pub name: String, pub root: String }

pub fn calculate_roots(path: &Path, requested: &[String], requirements: &OpenRequirements) -> Result<Vec<StoreRoot>, DbFailure> {
    let wanted = requested.iter().filter(|name| StoreKind::ALL.into_iter().any(|kind| kind.db_name() == name.as_str())).cloned().collect::<Vec<_>>();
    if wanted.is_empty() { return Err(not_found(path)); }
    let mut accumulators = wanted.iter().cloned().map(|name| (name, MerkleAccumulator::default())).collect::<BTreeMap<_, _>>();
    match tron_storage::inspect_read_only(path).map_err(DbFailure::from_format)? {
        DirectoryClassification::Missing | DirectoryClassification::Empty | DirectoryClassification::InitializingEmpty => return Err(not_found(path)),
        DirectoryClassification::Java { marker } => return Err(java_unsupported(path, &marker)),
        DirectoryClassification::Rust(manifest) => manifest.validate(requirements, path).map_err(DbFailure::from_format)?,
    }
    let log = StorageManager::new(requirements.clone()).open_store(path).map_err(storage_failure)?;
    log.visit_entries::<tron_storage::StorageError>(|physical, value| {
        if let Some((name, logical)) = decode_physical_key(physical) {
            if let Some(accumulator) = accumulators.get_mut(name) { accumulator.push(hash_leaf(logical, value)); }
        }
        Ok(())
    }).map_err(storage_failure)?;
    log.close().map_err(storage_failure)?;
    Ok(wanted.into_iter().map(|name| StoreRoot { root: hex(&accumulators[&name].finish()), name }).collect())
}
fn not_found(path: &Path) -> DbFailure { DbFailure::new("not_found", format!("{}: none of the requested databases exist", path.display()), 404) }
fn java_unsupported(path: &Path, marker: &str) -> DbFailure { DbFailure::new("java_format", format!("{}: detected Java storage marker '{marker}'. {JAVA_REJECTION_GUIDANCE}", path.display()), 1) }
pub fn render_text(roots: &[StoreRoot]) -> Vec<u8> { let mut output=String::new(); for root in roots { output.push_str(&format!("db: {},root: {}\n",root.name,root.root)); } output.push_str("root task done.\n"); output.into_bytes() }
pub fn render_json(roots: &[StoreRoot]) -> Result<Vec<u8>,DbFailure> { let rows=roots.iter().map(|root|serde_json::json!({"db":root.name,"root":root.root})).collect::<Vec<_>>(); let mut output=serde_json::to_vec(&serde_json::json!({"roots":rows})).map_err(|e|DbFailure::new("operation_failure",e.to_string(),1))?; output.push(b'\n'); Ok(output) }
fn decode_physical_key(key:&[u8])->Option<(&str,&[u8])>{if key.len()<5||key[0]!=1{return None}let length=u32::from_be_bytes(key[1..5].try_into().ok()?)as usize;let end=5usize.checked_add(length)?;Some((std::str::from_utf8(key.get(5..end)?).ok()?,key.get(end..)?))}
fn hash_leaf(key:&[u8],value:&[u8])->[u8;32]{let mut d=Sha256::new();d.update(key);d.update(value);d.finalize().into()}
#[derive(Default)]struct MerkleAccumulator{levels:Vec<Option<[u8;32]>>}
impl MerkleAccumulator{fn push(&mut self,mut node:[u8;32]){let mut level=0;loop{if level==self.levels.len(){self.levels.push(Some(node));return}match self.levels[level].take(){None=>{self.levels[level]=Some(node);return}Some(left)=>{node=hash_pair(&left,&node);level+=1}}}}fn finish(&self)->[u8;32]{let mut right=None;for node in self.levels.iter().flatten(){right=Some(match right{None=>*node,Some(right)=>hash_pair(node,&right)});}right.unwrap_or([0;32])}}
fn hash_pair(left:&[u8;32],right:&[u8;32])->[u8;32]{let mut d=Sha256::new();d.update(left);d.update(right);d.finalize().into()}
fn hex(bytes:&[u8])->String{const H:&[u8;16]=b"0123456789abcdef";let mut o=String::with_capacity(bytes.len()*2);for b in bytes{o.push(H[(b>>4)as usize]as char);o.push(H[(b&15)as usize]as char);}o}
fn storage_failure(error:tron_storage::StorageError)->DbFailure{match error{tron_storage::StorageError::Format(error)=>DbFailure::from_format(error),other=>DbFailure::new("operation_failure",other.to_string(),1)}}
