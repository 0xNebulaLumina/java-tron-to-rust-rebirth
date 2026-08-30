//! Pure-Rust Sapling compatibility for java-tron's shielded boundary.
//! Parameters, proofs, verification contexts, pre-ZIP212 notes, and raw adapters are owned Rust values.

mod context;
mod error;
mod inventory;
mod merkle;
mod parameters;
mod note;
mod raw;
pub mod params;
mod primitives;
mod sodium;
mod zksnark_client;

pub use context::{ContextTable,OutputProof,ProvingContext,SpendProof,VerificationContext,DEFAULT_MAX_CONTEXTS};
pub use error::{ParameterKind,Result,ShieldedError};
pub use inventory::{JLIBRUSTZCASH_METHODS,JLIBSODIUM_METHODS,JLibrustzcashMethod,JLibsodiumMethod};
pub use merkle::{IncrementalMerkleTree,IncrementalMerkleVoucher,IncrementalWitness,JavaMerklePath};
pub use parameters::{TRON_OUTPUT_BLAKE2B512,TRON_OUTPUT_SIZE,TRON_SPEND_BLAKE2B512,TRON_SPEND_SIZE,TronParameters,load_tron_parameters};
pub use note::{decrypt_pre_zip212_note,encrypt_pre_zip212_note,external_key_path,recover_pre_zip212_note,DecryptedNote,EncryptedNote,ExternalKeyPath,ENC_CIPHERTEXT_BYTES,MEMO_BYTES,OUT_CIPHERTEXT_BYTES};
pub use raw::ShieldedRawAdapter;
pub use params::*;
pub use primitives::{ask_to_ak,check_diversifier,compute_cm,compute_nf,crh_ivk,empty_root,generate_r,ivk_to_pkd,ka_agree,ka_derive_public,merkle_hash,nsk_to_nk,spend_sig,to_scalar,tree_uncommitted,zip32_xfvk_address,zip32_xsk_derive,zip32_xsk_master};
pub use zksnark_client::{DEFAULT_ZKSNARK_ENDPOINT,MAX_ZKSNARK_REQUEST_BYTES,TronZksnarkGrpcClient,ZKSNARK_CONNECT_TIMEOUT,ZKSNARK_REQUEST_TIMEOUT,ZksnarkClientError};
pub use sodium::{AEAD_TAG_BYTES,AeadResult,FAILURE,LIBSODIUM_AEAD_MESSAGE_BYTES_MAX,MAX_SODIUM_AAD_BYTES,MAX_SODIUM_CIPHERTEXT_BYTES,MAX_SODIUM_MESSAGE_BYTES,MAX_SODIUM_OUTPUT_BYTES,SUCCESS,SodiumCompat,aead_decrypt,aead_encrypt,blake2b_salt_personal};
