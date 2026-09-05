use std::collections::BTreeSet;
use std::sync::Arc;

use tron_shielded::{merkle_hash, CheckOutputParams, CheckSpendParams, FinalCheckParams, ShieldedRawAdapter, TronParameters};

pub const VERIFY_MINT_ADDRESS: u32 = 0x0100_0001;
pub const VERIFY_TRANSFER_ADDRESS: u32 = 0x0100_0002;
pub const VERIFY_BURN_ADDRESS: u32 = 0x0100_0003;
pub const MERKLE_HASH_ADDRESS: u32 = 0x0100_0004;
pub const VERIFY_MINT_ENERGY: u64 = 150_000;
pub const VERIFY_TRANSFER_ENERGY: u64 = 200_000;
pub const VERIFY_BURN_ENERGY: u64 = 150_000;
pub const MERKLE_HASH_ENERGY: u64 = 500;
const TREE_WIDTH: u64 = 1u64 << 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShieldedPrecompile { VerifyMint, VerifyTransfer, VerifyBurn, MerkleHash }

impl ShieldedPrecompile {
    #[must_use] pub const fn address(self) -> u32 { match self { Self::VerifyMint=>VERIFY_MINT_ADDRESS, Self::VerifyTransfer=>VERIFY_TRANSFER_ADDRESS, Self::VerifyBurn=>VERIFY_BURN_ADDRESS, Self::MerkleHash=>MERKLE_HASH_ADDRESS } }
    #[must_use] pub const fn energy(self) -> u64 { match self { Self::VerifyMint=>VERIFY_MINT_ENERGY, Self::VerifyTransfer=>VERIFY_TRANSFER_ENERGY, Self::VerifyBurn=>VERIFY_BURN_ENERGY, Self::MerkleHash=>MERKLE_HASH_ENERGY } }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShieldedOutput { pub success: bool, pub output: Vec<u8> }
impl ShieldedOutput { fn zero() -> Self { Self { success:true, output:vec![0;32] } } }

pub struct ShieldedPrecompiles { adapter: ShieldedRawAdapter }
impl ShieldedPrecompiles {
    #[must_use] pub fn new(parameters: Arc<TronParameters>) -> Self { Self { adapter:ShieldedRawAdapter::new(parameters) } }
    #[must_use] pub fn resolve(address:u32, enabled:bool)->Option<ShieldedPrecompile>{ if !enabled{return None} match address {VERIFY_MINT_ADDRESS=>Some(ShieldedPrecompile::VerifyMint),VERIFY_TRANSFER_ADDRESS=>Some(ShieldedPrecompile::VerifyTransfer),VERIFY_BURN_ADDRESS=>Some(ShieldedPrecompile::VerifyBurn),MERKLE_HASH_ADDRESS=>Some(ShieldedPrecompile::MerkleHash),_=>None} }
    pub fn execute(&self, contract:ShieldedPrecompile, data:&[u8])->ShieldedOutput { match contract { ShieldedPrecompile::VerifyMint=>self.mint(data),ShieldedPrecompile::VerifyTransfer=>self.transfer(data),ShieldedPrecompile::VerifyBurn=>self.burn(data),ShieldedPrecompile::MerkleHash=>execute_merkle_hash(data) } }

    fn mint(&self,data:&[u8])->ShieldedOutput {
        if data.len()!=1504{return ShieldedOutput::zero()}
        let (Some(value),Some(leaf_count))=(word_i64(data,352),word_u64(data,1472)) else{return ShieldedOutput::zero()};
        let Some(value_balance)=value.checked_neg() else{return ShieldedOutput::zero()};
        if !frontier_fits(&data[416..1472],leaf_count,1){return ShieldedOutput::zero()}
        let Ok(ctx)=self.adapter.verification_ctx_init() else{return ShieldedOutput::zero()};
        let check=self.adapter.check_output(&CheckOutputParams{ctx:Some(ctx),cv:data[32..64].to_vec(),cm:data[0..32].to_vec(),ephemeral_key:data[64..96].to_vec(),zkproof:data[96..288].to_vec()}).unwrap_or(false)
            && self.adapter.final_check(&FinalCheckParams{ctx:Some(ctx),value_balance,binding_sig:data[288..352].to_vec(),sighash_value:data[384..416].to_vec()}).unwrap_or(false);
        let _=self.adapter.verification_ctx_free(ctx);
        if !check{return ShieldedOutput::zero()}
        insert_leaves(&data[416..1472],leaf_count,&[array32(&data[0..32])]).unwrap_or_else(ShieldedOutput::zero)
    }

    fn burn(&self,data:&[u8])->ShieldedOutput {
        if data.len()!=512{return ShieldedOutput::zero()}
        let Some(value)=word_i64(data,384) else{return ShieldedOutput::zero()};
        let Ok(ctx)=self.adapter.verification_ctx_init() else{return ShieldedOutput::zero()};
        let check=self.adapter.check_spend(&CheckSpendParams{ctx:Some(ctx),cv:data[64..96].to_vec(),anchor:data[32..64].to_vec(),nullifier:data[0..32].to_vec(),rk:data[96..128].to_vec(),zkproof:data[128..320].to_vec(),spend_auth_sig:data[320..384].to_vec(),sighash_value:data[480..512].to_vec()}).unwrap_or(false)
            && self.adapter.final_check(&FinalCheckParams{ctx:Some(ctx),value_balance:value,binding_sig:data[416..480].to_vec(),sighash_value:data[480..512].to_vec()}).unwrap_or(false);
        let _=self.adapter.verification_ctx_free(ctx);
        ShieldedOutput{success:true,output:bool_word(check)}
    }

    fn transfer(&self,data:&[u8])->ShieldedOutput {
        if !matches!(data.len(),2080|2368|2464|2752){return ShieldedOutput::zero()}
        let (Some(spend_off),Some(sig_off),Some(receive_off),Some(value),Some(leaf_count))=(word_usize(data,0),word_usize(data,32),word_usize(data,64),word_i64(data,192),word_u64(data,1280)) else{return ShieldedOutput::zero()};
        let (Some(sc),Some(sigc),Some(rc))=(count_at(data,spend_off),count_at(data,sig_off),count_at(data,receive_off)) else{return ShieldedOutput::zero()};
        if sc!=sigc || !(1..=2).contains(&sc) || !(1..=2).contains(&rc) || !frontier_fits(&data[224..1280],leaf_count,rc){return ShieldedOutput::zero()}
        let (Some(spend_items),Some(sig_items),Some(receive_items))=(spend_off.checked_add(32),sig_off.checked_add(32),receive_off.checked_add(32)) else{return ShieldedOutput::zero()};
        let (Some(spends),Some(sigs),Some(outputs))=(slice_items(data,spend_items,sc,320),slice_items(data,sig_items,sigc,64),slice_items(data,receive_items,rc,288)) else{return ShieldedOutput::zero()};
        let mut nfs=BTreeSet::new(); let mut cms=BTreeSet::new();
        if spends.iter().any(|v|!nfs.insert(&v[0..32])) || outputs.iter().any(|v|!cms.insert(&v[0..32])) {return ShieldedOutput::zero()}
        let sighash=data[160..192].to_vec();
        let Ok(ctx)=self.adapter.verification_ctx_init() else{return ShieldedOutput::zero()};
        let mut valid=true;
        for (s,sig) in spends.iter().zip(sigs.iter()) { valid &= self.adapter.check_spend(&CheckSpendParams{ctx:Some(ctx),nullifier:s[0..32].to_vec(),anchor:s[32..64].to_vec(),cv:s[64..96].to_vec(),rk:s[96..128].to_vec(),zkproof:s[128..320].to_vec(),spend_auth_sig:sig.to_vec(),sighash_value:sighash.clone()}).unwrap_or(false); }
        for o in &outputs { valid &= self.adapter.check_output(&CheckOutputParams{ctx:Some(ctx),cm:o[0..32].to_vec(),cv:o[32..64].to_vec(),ephemeral_key:o[64..96].to_vec(),zkproof:o[96..288].to_vec()}).unwrap_or(false); }
        valid &= self.adapter.final_check(&FinalCheckParams{ctx:Some(ctx),value_balance:value,binding_sig:data[96..160].to_vec(),sighash_value:sighash}).unwrap_or(false);
        let _=self.adapter.verification_ctx_free(ctx);
        if !valid{return ShieldedOutput::zero()}
        let leaves:Vec<[u8;32]>=outputs.iter().map(|o|array32(&o[0..32])).collect();
        insert_leaves(&data[224..1280],leaf_count,&leaves).unwrap_or_else(ShieldedOutput::zero)
    }
}

fn word_u64(data:&[u8],offset:usize)->Option<u64>{let w=data.get(offset..offset+32)?;if w[..24].iter().any(|&b|b!=0){return None}Some(u64::from_be_bytes(w[24..].try_into().ok()?))}
fn word_i64(data:&[u8],offset:usize)->Option<i64>{word_u64(data,offset).and_then(|v|i64::try_from(v).ok())}
pub fn execute_merkle_hash(data:&[u8])->ShieldedOutput { if data.len()!=96{return ShieldedOutput{success:false,output:Vec::new()}} let Some(level)=word_usize(data,0).filter(|&level|level<32) else{return ShieldedOutput{success:false,output:Vec::new()}}; match merkle_hash(level,array32(&data[32..64]),array32(&data[64..96])) {Ok(v)=>ShieldedOutput{success:true,output:v.to_vec()},Err(_)=>ShieldedOutput{success:false,output:Vec::new()}} }
fn word_usize(data:&[u8],offset:usize)->Option<usize>{usize::try_from(word_u64(data,offset)?).ok()}
fn count_at(data:&[u8],offset:usize)->Option<usize>{word_usize(data,offset)}
fn slice_items(data:&[u8],offset:usize,count:usize,size:usize)->Option<Vec<&[u8]>>{let end=offset.checked_add(count.checked_mul(size)?)?;let all=data.get(offset..end)?;Some(all.chunks_exact(size).collect())}
fn array32(v:&[u8])->[u8;32]{v.try_into().expect("32-byte slice")}
fn bool_word(v:bool)->Vec<u8>{let mut out=vec![0;32];out[31]=u8::from(v);out}

fn frontier_fits(frontier_bytes:&[u8],leaf_count:u64,leaf_len:usize)->bool {
    frontier_bytes.len()==33*32
        && leaf_len!=0
        && u64::try_from(leaf_len).ok().and_then(|len|leaf_count.checked_add(len)).is_some_and(|end|end<=TREE_WIDTH)
}
fn frontier_slot(index:u64)->Option<usize> {
    if index>=TREE_WIDTH{return None}
    if index&1==0{return Some(0)}
    Some(index.checked_add(1)?.trailing_zeros() as usize)
}
fn insert_leaves(frontier_bytes:&[u8],leaf_count:u64,leaves:&[[u8;32]])->Option<ShieldedOutput>{
    if !frontier_fits(frontier_bytes,leaf_count,leaves.len()){return None}
    let mut frontier:Vec<[u8;32]>=frontier_bytes.chunks_exact(32).map(array32).collect();
    let mut uncommitted=Vec::with_capacity(32);uncommitted.push(tron_shielded::tree_uncommitted());for level in 0..31{uncommitted.push(merkle_hash(level,uncommitted[level],uncommitted[level]).ok()?)}
    let slots:Vec<usize>=(0..leaves.len()).map(|i|u64::try_from(i).ok().and_then(|i|leaf_count.checked_add(i)).and_then(frontier_slot)).collect::<Option<_>>()?;
    let cap=32usize.checked_add(slots.iter().try_fold(0usize,|sum,slot|sum.checked_add(slot.checked_add(1)?.checked_mul(32)?))?)?;let mut payload=Vec::with_capacity(cap);
    let mut node_index=0u64;let mut node=[0;32];
    for (i,leaf) in leaves.iter().enumerate(){let slot=slots[i];let mut slot_word=[0;32];slot_word[31]=u8::try_from(slot).ok()?;payload.extend_from_slice(&slot_word);let offset=u64::try_from(i).ok()?;node_index=leaf_count.checked_add(offset)?.checked_add(TREE_WIDTH-1)?;node=*leaf;if slot==0{frontier[0]=node;continue}for level in 1..=slot{node=if node_index&1==0{node_index=(node_index-1)/2;merkle_hash(level-1,frontier[level-1],node).ok()?}else{node_index/=2;merkle_hash(level-1,node,uncommitted[level-1]).ok()?};payload.extend_from_slice(&node)}frontier[slot]=node}
    for level in slots[slots.len()-1]+1..=32{node=if node_index&1==0{node_index=(node_index-1)/2;merkle_hash(level-1,frontier[level-1],node).ok()?}else{node_index/=2;merkle_hash(level-1,node,uncommitted[level-1]).ok()?}}
    payload.extend_from_slice(&node);let mut output=bool_word(true);output.extend_from_slice(&payload);Some(ShieldedOutput{success:true,output})
}

/// Deterministic mint ABI seam used by wallet-side `getTriggerInput` implementations.
#[must_use] pub fn get_trigger_input_mint(cm:[u8;32],cv:[u8;32],epk:[u8;32],proof:[u8;192],binding_sig:[u8;64],value:u64,sighash:[u8;32],frontier:[[u8;32];33],leaf_count:u64)->Vec<u8>{let mut out=Vec::with_capacity(1504);out.extend_from_slice(&cm);out.extend_from_slice(&cv);out.extend_from_slice(&epk);out.extend_from_slice(&proof);out.extend_from_slice(&binding_sig);let mut word=[0;32];word[24..].copy_from_slice(&value.to_be_bytes());out.extend_from_slice(&word);out.extend_from_slice(&sighash);for node in frontier{out.extend_from_slice(&node)}word.fill(0);word[24..].copy_from_slice(&leaf_count.to_be_bytes());out.extend_from_slice(&word);out}
