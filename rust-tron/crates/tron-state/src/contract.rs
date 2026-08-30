use tron_crypto::keccak256;
use tron_protocol::protocol::{ContractState, SmartContract, smart_contract::Abi};

use crate::capsule::ProtoCapsule;

#[derive(Clone, Debug)]
pub struct SplitContract {
    pub contract: ProtoCapsule<SmartContract>,
    pub abi: Option<ProtoCapsule<Abi>>,
}

/// Java ContractStore/AbiStore split: ABI is stored independently and cleared from SmartContract.
#[must_use]
pub fn split_contract(mut contract: SmartContract) -> SplitContract {
    let abi = contract.abi.take().map(ProtoCapsule::new);
    SplitContract { contract: ProtoCapsule::new(contract), abi }
}

#[must_use]
pub fn compose_contract(mut contract: SmartContract, abi: Option<Abi>) -> SmartContract {
    contract.abi = abi;
    contract
}

pub type ContractStateValue = ProtoCapsule<ContractState>;

/// TVM storage-row key: first 16 bytes of the address domain hash and last 16 bytes of
/// the raw slot (version 0) or slot hash (version 1). CREATE2 adds trx_hash to the address domain.
#[must_use]
pub fn storage_row_key(address: &[u8], slot: &[u8; 32], contract_version: i32, trx_hash: Option<&[u8; 32]>) -> [u8; 32] {
    let address_hash = if let Some(trx_hash) = trx_hash {
        let mut domain = Vec::with_capacity(address.len() + trx_hash.len());
        domain.extend_from_slice(address);
        domain.extend_from_slice(trx_hash);
        keccak256(&domain)
    } else { keccak256(address) };
    let slot_domain = if contract_version == 1 { keccak256(slot) } else { *slot };
    let mut key = [0; 32];
    key[..16].copy_from_slice(&address_hash[..16]);
    key[16..].copy_from_slice(&slot_domain[16..]);
    key
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageMutation { Put([u8; 32]), Delete }
#[must_use]
pub fn storage_mutation(value: [u8; 32]) -> StorageMutation {
    if value == [0; 32] { StorageMutation::Delete } else { StorageMutation::Put(value) }
}
