use blake2::{Blake2sMac256, digest::{FixedOutput, Update}};
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use incrementalmerkletree::Hashable;
use sapling_crypto::{Diversifier, NullifierDerivingKey, PaymentAddress, Rseed, constants, keys::SpendValidatingKey, value::NoteValue, zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey}};
use zip32::{ChildIndex, DiversifierIndex};
use crate::{Result, ShieldedError};

fn array<const N:usize>(bytes:&[u8],name:&'static str)->Result<[u8;N]> { bytes.try_into().map_err(|_|ShieldedError::InvalidEncoding(name)) }
fn wide(bytes:[u8;32])->jubjub::Fr { let mut value=[0u8;64]; value[..32].copy_from_slice(&bytes); jubjub::Fr::from_bytes_wide(&value) }

pub fn zip32_xsk_master(seed:&[u8])->[u8;169] { ExtendedSpendingKey::master(seed).to_bytes() }
pub fn zip32_xsk_derive(parent:&[u8],child_index:u32)->Result<[u8;169]> { let parent=ExtendedSpendingKey::from_bytes(parent).map_err(|_|ShieldedError::InvalidEncoding("extended spending key"))?; let child=ChildIndex::from_index(child_index).ok_or(ShieldedError::InvalidParameter("ZIP32 child index must be hardened".into()))?; Ok(parent.derive_child(child).to_bytes()) }
pub fn zip32_xfvk_address(xfvk:&[u8],j:[u8;11])->Result<([u8;11],[u8;43])> { if xfvk.len()!=169{return Err(ShieldedError::InvalidEncoding("extended full viewing key"))} let raw:[u8;128]=xfvk[41..].try_into().expect("checked length"); let key=DiversifiableFullViewingKey::from_bytes(&raw).ok_or(ShieldedError::InvalidEncoding("diversifiable full viewing key"))?; let (found,address)=key.find_address(DiversifierIndex::from(j)).ok_or(ShieldedError::InvalidParameter("diversifier index exhausted".into()))?; Ok((*found.as_bytes(),address.to_bytes())) }
pub fn check_diversifier(d:[u8;11])->bool { Diversifier(d).g_d().is_some() }
pub fn crh_ivk(ak:[u8;32],nk:[u8;32])->[u8;32] { let mut state=Blake2sMac256::new_with_salt_and_personal(None,&[],b"Zcashivk").expect("constant personalization"); state.update(&ak); state.update(&nk); let mut out:[u8;32]=state.finalize_fixed().into(); out[31]&=0x07; out }
pub fn ask_to_ak(ask:[u8;32])->[u8;32] { (constants::SPENDING_KEY_GENERATOR*wide(ask)).to_bytes() }
pub fn nsk_to_nk(nsk:[u8;32])->[u8;32] { (constants::PROOF_GENERATION_KEY_GENERATOR*wide(nsk)).to_bytes() }
pub fn to_scalar(input:[u8;64])->[u8;32] { jubjub::Fr::from_bytes_wide(&input).to_repr() }
pub fn ivk_to_pkd(ivk:[u8;32],d:[u8;11])->Result<[u8;32]> { if ivk[31]>>3 != 0{return Err(ShieldedError::InvalidParameter("Most significant five bits of ivk should be 0.".into()))} let g= Diversifier(d).g_d().ok_or(ShieldedError::InvalidEncoding("diversifier"))?; let scalar=Option::<jubjub::Fr>::from(jubjub::Fr::from_repr(ivk)).ok_or(ShieldedError::InvalidEncoding("incoming viewing key"))?; Ok((g*scalar).to_bytes()) }
pub fn ka_derive_public(d:[u8;11],esk:[u8;32])->Result<[u8;32]> { let g=Diversifier(d).g_d().ok_or(ShieldedError::InvalidEncoding("diversifier"))?; let esk=Option::<jubjub::Fr>::from(jubjub::Fr::from_repr(esk)).ok_or(ShieldedError::InvalidEncoding("ephemeral secret key"))?; Ok((g*esk).to_bytes()) }
pub fn ka_agree(point:[u8;32],sk:[u8;32])->Result<[u8;32]> { let p=Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(&point)).ok_or(ShieldedError::InvalidEncoding("Jubjub point"))?; let sk=Option::<jubjub::Fr>::from(jubjub::Fr::from_repr(sk)).ok_or(ShieldedError::InvalidEncoding("key agreement scalar"))?; Ok((p.mul_by_cofactor()*sk).to_bytes()) }
fn note(d:[u8;11],pk_d:[u8;32],value:u64,rcm:[u8;32])->Result<sapling_crypto::Note> { let mut addr=[0u8;43]; addr[..11].copy_from_slice(&d); addr[11..].copy_from_slice(&pk_d); let recipient=PaymentAddress::from_bytes(&addr).ok_or(ShieldedError::InvalidEncoding("payment address"))?; let rcm=Option::<jubjub::Fr>::from(jubjub::Fr::from_repr(rcm)).ok_or(ShieldedError::InvalidEncoding("note commitment trapdoor"))?; Ok(recipient.create_note(NoteValue::from_raw(value),Rseed::BeforeZip212(rcm))) }
pub fn generate_r()->[u8;32] { jubjub::Fr::random(rand_core::OsRng).to_repr() }
pub fn spend_sig(ask:[u8;32],alpha:[u8;32],sighash:[u8;32])->Result<[u8;64]> { let ask=redjubjub::SigningKey::<redjubjub::SpendAuth>::try_from(ask).map_err(|_|ShieldedError::InvalidEncoding("spend authorizing key"))?; let alpha=Option::<jubjub::Fr>::from(jubjub::Fr::from_repr(alpha)).ok_or(ShieldedError::InvalidEncoding("spend randomizer"))?; Ok(ask.randomize(&alpha).sign(rand_core::OsRng,&sighash).into()) }
pub fn compute_cm(d:[u8;11],pk_d:[u8;32],value:u64,rcm:[u8;32])->Result<[u8;32]> { Ok(note(d,pk_d,value,rcm)?.cmu().to_bytes()) }
pub fn compute_nf(d:[u8;11],pk_d:[u8;32],value:u64,rcm:[u8;32],ak:[u8;32],nk:[u8;32],position:u64)->Result<[u8;32]> { SpendValidatingKey::temporary_zcash_from_bytes(&ak).ok_or(ShieldedError::InvalidEncoding("spend validating key"))?; let nk=Option::<jubjub::SubgroupPoint>::from(jubjub::SubgroupPoint::from_bytes(&nk)).filter(|p|!bool::from(p.is_identity())).map(NullifierDerivingKey).ok_or(ShieldedError::InvalidEncoding("nullifier deriving key"))?; Ok(note(d,pk_d,value,rcm)?.nf(&nk,position).0) }
pub fn merkle_hash(depth:usize,a:[u8;32],b:[u8;32])->Result<[u8;32]> { if depth>=63{return Err(ShieldedError::InvalidParameter("Merkle tree depth must be smaller than 63".into()))} Ok(sapling_crypto::merkle_hash(depth,&a,&b)) }
pub fn tree_uncommitted()->[u8;32] { <sapling_crypto::Node as Hashable>::empty_leaf().to_bytes() }
pub fn empty_root(depth:u8)->Result<[u8;32]> { if depth>62{return Err(ShieldedError::InvalidParameter("Merkle tree depth must be smaller than 63".into()))} let mut root=tree_uncommitted(); for level in 0..depth as usize { root=merkle_hash(level,root,root)?; } Ok(root) }
pub fn parse_node(bytes:&[u8])->Result<sapling_crypto::Node> { let bytes=array(bytes,"Merkle node")?; Option::from(sapling_crypto::Node::from_bytes(bytes)).ok_or(ShieldedError::InvalidEncoding("Merkle node")) }
