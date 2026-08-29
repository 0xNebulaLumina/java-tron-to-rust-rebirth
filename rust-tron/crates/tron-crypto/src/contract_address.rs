use crate::keccak256;
use tron_primitives::{Address20, Hash32, TransactionId, TronAddress21};

fn tron_keccak_address(input: &[u8]) -> TronAddress21 {
    let hash = keccak256(input);
    TronAddress21::new(crate::TRON_ADDRESS_PREFIX, Address20::from_array(hash[12..].try_into().expect("fixed slice")))
}

/// Java `WalletUtil.generateContractAddress`: Keccak-256(txid || owner).
pub fn top_level_contract_address(txid: &TransactionId, owner: &TronAddress21) -> TronAddress21 {
    let mut input = [0; 53];
    input[..32].copy_from_slice(txid.as_bytes());
    input[32..].copy_from_slice(owner.as_bytes());
    tron_keccak_address(&input)
}

/// Java TVM `CREATE`: Keccak-256(root transaction id || signed nonce as i64 big-endian).
pub fn internal_create_address(root_txid: &TransactionId, nonce: i64) -> TronAddress21 {
    let mut input = [0; 40];
    input[..32].copy_from_slice(root_txid.as_bytes());
    input[32..].copy_from_slice(&nonce.to_be_bytes());
    tron_keccak_address(&input)
}

/// Java TVM `CREATE2`: Keccak-256(creator || salt || Keccak-256(init_code)).
///
/// Unlike Ethereum's EIP-1014 formula, java-tron does not prepend `0xff`.
pub fn create2_address(creator: &TronAddress21, salt: &Hash32, init_code: &[u8]) -> TronAddress21 {
    let code_hash = keccak256(init_code);
    let mut input = [0; 85];
    input[..21].copy_from_slice(creator.as_bytes());
    input[21..53].copy_from_slice(salt.as_bytes());
    input[53..].copy_from_slice(&code_hash);
    tron_keccak_address(&input)
}
