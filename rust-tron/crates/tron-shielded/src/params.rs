use crate::sodium::{
    AEAD_TAG_BYTES, MAX_SODIUM_AAD_BYTES, MAX_SODIUM_CIPHERTEXT_BYTES,
    MAX_SODIUM_MESSAGE_BYTES, MAX_SODIUM_OUTPUT_BYTES,
};

use crate::{Result, ShieldedError};

fn invalid(message: impl Into<String>) -> ShieldedError { ShieldedError::InvalidParameter(message.into()) }
fn exact(value: &[u8], len: usize) -> Result<()> {
    if value.is_empty() { return Err(invalid("param is null")); }
    if value.len() != len { return Err(invalid(format!("param length must be {len}"))); }
    Ok(())
}
fn non_negative(value: i64, message: &'static str) -> Result<()> { if value < 0 { Err(invalid(message)) } else { Ok(()) } }
fn exact_len(value: &[u8], declared: usize) -> Result<()> { if value.len() == declared { Ok(()) } else { Err(invalid(format!("param length must be {declared}"))) } }

pub trait Validate { fn validate(&self) -> Result<()>; }

#[derive(Clone, Debug)] pub struct InitZksnarkParams { pub spend_path: std::path::PathBuf, pub spend_hash: String, pub output_path: std::path::PathBuf, pub output_hash: String }
impl Validate for InitZksnarkParams { fn validate(&self) -> Result<()> { Ok(()) } }
#[derive(Clone, Debug)] pub struct Zip32XskMasterParams { pub data: Vec<u8>, pub size: usize }
impl Validate for Zip32XskMasterParams { fn validate(&self) -> Result<()> { Ok(()) } }
#[derive(Clone, Debug)] pub struct Zip32XskDeriveParams { pub data: [u8;169], pub child_index: u32 }
impl Validate for Zip32XskDeriveParams { fn validate(&self) -> Result<()> { Ok(()) } }
#[derive(Clone, Debug)] pub struct Zip32XfvkAddressParams { pub xfvk: [u8;169], pub j: [u8;11] }
impl Validate for Zip32XfvkAddressParams { fn validate(&self) -> Result<()> { Ok(()) } }

macro_rules! bytes_struct {
    ($name:ident { $($field:ident : $len:expr),+ $(,)? }) => {
        #[derive(Clone, Debug)] pub struct $name { $(pub $field: Vec<u8>),+ }
        impl Validate for $name { fn validate(&self) -> Result<()> { $(exact(&self.$field, $len)?;)+ Ok(()) } }
    };
}
bytes_struct!(CrhIvkParams { ak:32, nk:32, ivk:32 });
bytes_struct!(KaAgreeParams { p:32, sk:32, result:32 });
bytes_struct!(KaDerivePublicParams { diversifier:11, esk:32, result:32 });
bytes_struct!(SpendSigParams { ask:32, alpha:32, sighash:32, result:64 });
bytes_struct!(CheckOutputNewParams { cv:32, cm:32, ephemeral_key:32, zkproof:192 });
bytes_struct!(IvkToPkdBytes { ivk:32, d:11, pk_d:32 });

#[derive(Clone, Debug)] pub struct ComputeCmParams { pub d: Vec<u8>, pub pk_d: Vec<u8>, pub value: i64, pub r: Vec<u8>, pub cm: Vec<u8> }
impl Validate for ComputeCmParams { fn validate(&self)->Result<()> { non_negative(self.value,"Value should be non-negative.")?; exact(&self.d,11)?; exact(&self.pk_d,32)?; exact(&self.r,32)?; exact(&self.cm,32) } }
#[derive(Clone, Debug)] pub struct ComputeNfParams { pub d: Vec<u8>, pub pk_d: Vec<u8>, pub value:i64, pub r:Vec<u8>, pub ak:Vec<u8>, pub nk:Vec<u8>, pub position:i64, pub result:Vec<u8> }
impl Validate for ComputeNfParams { fn validate(&self)->Result<()> { non_negative(self.value,"Value should be non-negative.")?; non_negative(self.position,"Position should be non-negative.")?; exact(&self.d,11)?; exact(&self.pk_d,32)?; exact(&self.r,32)?; exact(&self.ak,32)?; exact(&self.nk,32)?; exact(&self.result,32) } }

#[derive(Clone, Debug)] pub struct SpendProofParams { pub ctx:u64, pub ak:Vec<u8>, pub nsk:Vec<u8>, pub d:Vec<u8>, pub r:Vec<u8>, pub alpha:Vec<u8>, pub value:i64, pub anchor:Vec<u8>, pub voucher_path:Vec<u8>, pub cv:Vec<u8>, pub rk:Vec<u8>, pub zkproof:Vec<u8> }
impl Validate for SpendProofParams { fn validate(&self)->Result<()> { non_negative(self.value,"Value should be non-negative.")?; exact(&self.ak,32)?; exact(&self.nsk,32)?; exact(&self.d,11)?; exact(&self.r,32)?; exact(&self.alpha,32)?; exact(&self.anchor,32)?; validate_voucher_path(&self.voucher_path)?; exact(&self.cv,32)?; exact(&self.rk,32)?; exact(&self.zkproof,192) } }
#[derive(Clone, Debug)] pub struct OutputProofParams { pub ctx:u64, pub esk:Vec<u8>, pub d:Vec<u8>, pub pk_d:Vec<u8>, pub r:Vec<u8>, pub value:i64, pub cv:Vec<u8>, pub zkproof:Vec<u8> }
impl Validate for OutputProofParams { fn validate(&self)->Result<()> { non_negative(self.value,"Value should be non-negative.")?; exact(&self.esk,32)?; exact(&self.d,11)?; exact(&self.pk_d,32)?; exact(&self.r,32)?; exact(&self.cv,32)?; exact(&self.zkproof,192) } }
#[derive(Clone, Debug)] pub struct BindingSigParams { pub ctx:u64, pub value_balance:i64, pub sighash:Vec<u8>, pub result:Vec<u8> }
impl Validate for BindingSigParams { fn validate(&self)->Result<()> { exact(&self.sighash,32)?; exact(&self.result,64) } }
#[derive(Clone, Debug)] pub struct CheckSpendParams { pub ctx:Option<u64>, pub cv:Vec<u8>, pub anchor:Vec<u8>, pub nullifier:Vec<u8>, pub rk:Vec<u8>, pub zkproof:Vec<u8>, pub spend_auth_sig:Vec<u8>, pub sighash_value:Vec<u8> }
impl Validate for CheckSpendParams { fn validate(&self)->Result<()> { exact(&self.cv,32)?; exact(&self.anchor,32)?; exact(&self.nullifier,32)?; exact(&self.rk,32)?; exact(&self.zkproof,192)?; exact(&self.spend_auth_sig,64)?; exact(&self.sighash_value,32) } }
#[derive(Clone, Debug)] pub struct CheckOutputParams { pub ctx:Option<u64>, pub cv:Vec<u8>, pub cm:Vec<u8>, pub ephemeral_key:Vec<u8>, pub zkproof:Vec<u8> }
impl Validate for CheckOutputParams { fn validate(&self)->Result<()> { exact(&self.cv,32)?; exact(&self.cm,32)?; exact(&self.ephemeral_key,32)?; exact(&self.zkproof,192) } }
#[derive(Clone, Debug)] pub struct FinalCheckParams { pub ctx:Option<u64>, pub value_balance:i64, pub binding_sig:Vec<u8>, pub sighash_value:Vec<u8> }
impl Validate for FinalCheckParams { fn validate(&self)->Result<()> { exact(&self.binding_sig,64)?; exact(&self.sighash_value,32) } }
pub type CheckSpendNewParams = CheckSpendParams;
pub type CheckOutputNewParamsAlias = CheckOutputParams;
#[derive(Clone, Debug)] pub struct FinalCheckNewParams { pub value_balance:i64, pub binding_sig:Vec<u8>, pub sighash_value:Vec<u8>, pub spend_cv:Vec<u8>, pub spend_cv_len:usize, pub output_cv:Vec<u8>, pub output_cv_len:usize }
impl Validate for FinalCheckNewParams { fn validate(&self)->Result<()> { exact(&self.binding_sig,64)?; exact(&self.sighash_value,32)?; if self.spend_cv_len == 0 || self.output_cv_len == 0 { return Err(invalid("spendCvLen and outputCvLen must be positive")); } if self.spend_cv_len%32 != 0 || self.output_cv_len%32 != 0 { return Err(invalid("spendCvLen and outputCvLen must be multiple of 32")); } exact_len(&self.spend_cv,self.spend_cv_len)?; exact_len(&self.output_cv,self.output_cv_len) } }
#[derive(Clone, Debug)] pub struct IvkToPkdParams { pub ivk:Vec<u8>, pub d:Vec<u8>, pub pk_d:Vec<u8> }
impl Validate for IvkToPkdParams { fn validate(&self)->Result<()> { exact(&self.ivk,32)?; exact(&self.d,11)?; exact(&self.pk_d,32)?; if self.ivk[31] >> 3 != 0 { return Err(invalid("Most significant five bits of ivk should be 0.")); } Ok(()) } }
#[derive(Clone, Debug)] pub struct MerkleHashParams { pub depth:i32, pub a:Vec<u8>, pub b:Vec<u8>, pub result:Vec<u8> }
impl Validate for MerkleHashParams { fn validate(&self)->Result<()> { if !(0..63).contains(&self.depth) { return Err(invalid("Merkle tree depth must be smaller than 63")); } exact(&self.a,32)?; exact(&self.b,32)?; exact(&self.result,32) } }

pub fn validate_voucher_path(path:&[u8])->Result<()> { exact(path,1065)?; if path[0] != 0x20 { return Err(invalid(format!("param {} not equals:32",path[0] as i8))); } for i in 0..32 { let p=1+i*33; if path[p]!=0x20 { return Err(invalid(format!("param {} not equals:32",path[p] as i8))); } } Ok(()) }

#[derive(Clone, Debug)] pub struct Blake2bInitSaltPersonalParams { pub state:u64, pub key:Vec<u8>, pub key_len:usize, pub out_len:usize, pub salt:Vec<u8>, pub personal:Vec<u8> }
impl Validate for Blake2bInitSaltPersonalParams { fn validate(&self)->Result<()> { if self.key_len != self.key.len() || self.key_len > 64 || self.out_len != 64 { return Err(invalid("invalid BLAKE2b length")); } if !self.salt.is_empty() { exact(&self.salt,16)?; } exact(&self.personal,16) } }
#[derive(Clone, Debug)] pub struct Blake2bUpdateParams { pub state:u64, pub input:Vec<u8>, pub in_len:usize }
impl Validate for Blake2bUpdateParams { fn validate(&self)->Result<()> { if self.input.len()!=self.in_len || !matches!(self.input.len(),33|34) { Err(invalid("param length must be 33 or 34")) } else { Ok(()) } } }
#[derive(Clone, Debug)] pub struct Blake2bFinalParams { pub state:u64, pub out_len:usize }
impl Validate for Blake2bFinalParams { fn validate(&self)->Result<()> { if matches!(self.out_len,11|64) { Ok(()) } else { Err(invalid("param length must be 11 or 64")) } } }
#[derive(Clone, Debug)] pub struct Black2bSaltPersonalParams { pub out_len:usize, pub input:Vec<u8>, pub in_len:usize, pub key:Vec<u8>, pub key_len:usize, pub salt:Vec<u8>, pub personal:Vec<u8> }
impl Validate for Black2bSaltPersonalParams { fn validate(&self)->Result<()> { if self.out_len != 32 || self.input.len() != self.in_len || self.input.len() > MAX_SODIUM_MESSAGE_BYTES || self.key_len != self.key.len() || self.key_len > 64 { return Err(invalid("invalid BLAKE2b length")); } if !self.salt.is_empty() { exact(&self.salt,16)?; } exact(&self.personal,16) } }
#[derive(Clone, Debug)] pub struct Chacha20poly1305IetfDecryptParams { pub output_len:usize, pub ciphertext:Vec<u8>, pub c_len:usize, pub aad:Vec<u8>, pub ad_len:usize, pub nonce:[u8;12], pub key:[u8;32] }
impl Validate for Chacha20poly1305IetfDecryptParams { fn validate(&self)->Result<()> { if self.ciphertext.len() != self.c_len || self.aad.len() != self.ad_len { return Err(invalid("declared AEAD length does not match input")); } let Some(plain_len) = self.ciphertext.len().checked_sub(AEAD_TAG_BYTES) else { return Err(invalid("ciphertext is shorter than the authentication tag")); }; if self.ciphertext.len() > MAX_SODIUM_CIPHERTEXT_BYTES || self.aad.len() > MAX_SODIUM_AAD_BYTES || self.output_len < plain_len || self.output_len > MAX_SODIUM_OUTPUT_BYTES { return Err(invalid("AEAD length exceeds node bound or output capacity")); } Ok(()) } }
#[derive(Clone, Debug)] pub struct Chacha20Poly1305IetfEncryptParams { pub output_len:usize, pub message:Vec<u8>, pub m_len:usize, pub aad:Vec<u8>, pub ad_len:usize, pub nonce:[u8;12], pub key:[u8;32] }
impl Validate for Chacha20Poly1305IetfEncryptParams { fn validate(&self)->Result<()> { if self.message.len() != self.m_len || self.aad.len() != self.ad_len { return Err(invalid("declared AEAD length does not match input")); } let Some(cipher_len) = self.message.len().checked_add(AEAD_TAG_BYTES) else { return Err(invalid("AEAD ciphertext length overflow")); }; if self.message.len() > MAX_SODIUM_MESSAGE_BYTES || self.aad.len() > MAX_SODIUM_AAD_BYTES || cipher_len > MAX_SODIUM_CIPHERTEXT_BYTES || self.output_len < cipher_len || self.output_len > MAX_SODIUM_OUTPUT_BYTES { return Err(invalid("AEAD length exceeds node bound or output capacity")); } Ok(()) } }
