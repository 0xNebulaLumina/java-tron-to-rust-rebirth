use crate::{opcodes_c::CallKind, Word};

use tron_primitives::{Hash32, TronAddress21};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractResult { Success, Revert, IllegalOperation, OutOfEnergy, BadJumpDestination, OutOfTime, OutOfMemory, PrecompiledContract, StackTooSmall, StackTooLarge, JvmStackOverflow, TransferFailed, InvalidCode, Unknown }
impl ContractResult {
    /// Canonical protobuf spelling and numeric value. `STACK_OVERFLOW` (9) is
    /// intentionally absent because Java RuntimeImpl never selects it.
    #[must_use]
    pub const fn protobuf(self) -> (&'static str, i32) {
        match self {
            Self::Success => ("SUCCESS", 1),
            Self::Revert => ("REVERT", 2),
            Self::BadJumpDestination => ("BAD_JUMP_DESTINATION", 3),
            Self::OutOfMemory => ("OUT_OF_MEMORY", 4),
            Self::PrecompiledContract => ("PRECOMPILED_CONTRACT", 5),
            Self::StackTooSmall => ("STACK_TOO_SMALL", 6),
            Self::StackTooLarge => ("STACK_TOO_LARGE", 7),
            Self::IllegalOperation => ("ILLEGAL_OPERATION", 8),
            Self::OutOfEnergy => ("OUT_OF_ENERGY", 10),
            Self::OutOfTime => ("OUT_OF_TIME", 11),
            Self::JvmStackOverflow => ("JVM_STACK_OVER_FLOW", 12),
            Self::Unknown => ("UNKNOWN", 13),
            Self::TransferFailed => ("TRANSFER_FAILED", 14),
            Self::InvalidCode => ("INVALID_CODE", 15),
        }
    }

    #[must_use]
    pub const fn from_runtime_number(number: i32) -> Option<Self> {
        match number {
            1 => Some(Self::Success), 2 => Some(Self::Revert),
            3 => Some(Self::BadJumpDestination), 4 => Some(Self::OutOfMemory),
            5 => Some(Self::PrecompiledContract), 6 => Some(Self::StackTooSmall),
            7 => Some(Self::StackTooLarge), 8 => Some(Self::IllegalOperation),
            10 => Some(Self::OutOfEnergy), 11 => Some(Self::OutOfTime),
            12 => Some(Self::JvmStackOverflow), 13 => Some(Self::Unknown),
            14 => Some(Self::TransferFailed), 15 => Some(Self::InvalidCode),
            0 | 9 | _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitStatus { Succeeded, Reverted, Faulted(VmFault) }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmFault { IllegalOperation, OutOfEnergy, BadJumpDestination, OutOfTime, OutOfMemory, PrecompiledContract, StackTooSmall, StackTooLarge, JvmStackOverflow, TransferFailed, InvalidCode, StaticViolation, ReturnDataBounds, OutOfStorage, Arithmetic, Other }
impl VmFault {
    #[must_use] pub const fn contract_result(self)->ContractResult{match self{Self::IllegalOperation=>ContractResult::IllegalOperation,Self::OutOfEnergy=>ContractResult::OutOfEnergy,Self::BadJumpDestination=>ContractResult::BadJumpDestination,Self::OutOfTime=>ContractResult::OutOfTime,Self::OutOfMemory=>ContractResult::OutOfMemory,Self::PrecompiledContract=>ContractResult::PrecompiledContract,Self::StackTooSmall=>ContractResult::StackTooSmall,Self::StackTooLarge=>ContractResult::StackTooLarge,Self::JvmStackOverflow=>ContractResult::JvmStackOverflow,Self::TransferFailed=>ContractResult::TransferFailed,Self::InvalidCode=>ContractResult::InvalidCode,Self::StaticViolation|Self::ReturnDataBounds|Self::OutOfStorage|Self::Arithmetic|Self::Other=>ContractResult::Unknown}}
    #[must_use] pub const fn spends_remaining(self)->bool{!matches!(self,Self::TransferFailed)}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TvmLog { pub address: [u8;20], pub topics: Vec<[u8;32]>, pub data: Vec<u8> }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallRequest {
    pub kind: CallKind,
    pub data: Vec<u8>,
    pub destination: TronAddress21,
    pub energy_limit: i64,
    pub reserved_energy: i64,
    pub value: Word,
    pub token_value: Word,
    pub token_id: Word,
    pub output_offset: usize,
    pub output_size: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateKind { Create, Create2 }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateRequest {
    pub kind: CreateKind,
    pub init_code: Vec<u8>,
    pub energy_limit: i64,
    pub value: Word,
    pub salt: Option<Word>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InternalTransactionRecord { pub parent_hash: Hash32, pub sender: TronAddress21, pub transfer_to: Option<TronAddress21>, pub data: Vec<u8>, pub value: Word, pub token_info: Vec<(Word,Word)>, pub note: Vec<u8>, pub depth: u32, pub index: u32, pub nonce: i64, pub rejected: bool, pub extra: Vec<u8>, pub encoded: Vec<u8>, pub hash: Hash32 }
impl InternalTransactionRecord {
    #[must_use] pub fn child(parent_hash:Hash32,sender:TronAddress21,transfer_to:Option<TronAddress21>,data:Vec<u8>,value:Word,token_info:Vec<(Word,Word)>,note:&[u8],depth:u32,index:u32,nonce:i64)->Self{
        let mut encoded=Vec::with_capacity(32+transfer_to.map_or(0,|_|21)+data.len()+8);
        encoded.extend_from_slice(parent_hash.as_bytes());
        if note!=b"create" { if let Some(address)=transfer_to { encoded.extend_from_slice(address.as_bytes()); } }
        encoded.extend_from_slice(&data);
        encoded.extend_from_slice(&value.to_i64_safe().to_be_bytes());
        let mut hash_input=Vec::with_capacity(encoded.len()+8);hash_input.extend_from_slice(&encoded);hash_input.extend_from_slice(&nonce.to_be_bytes());
        let hash=Hash32::from_array(tron_crypto::keccak256(&hash_input));
        Self{parent_hash,sender,transfer_to,data,value,token_info,note:note.to_vec(),depth,index,nonce,rejected:false,extra:Vec::new(),encoded,hash}
    }
    pub fn reject(&mut self){self.rejected=true;}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionOutcome { pub status: ExitStatus, pub contract_result: ContractResult, pub return_data: Vec<u8>, pub created_contract: Option<TronAddress21>, pub energy_used: i64, pub energy_penalty: i64, pub logs: Vec<TvmLog>, pub internal_transactions: Vec<InternalTransactionRecord>, pub deleted_accounts: Vec<TronAddress21>, pub deltas: Vec<crate::RepositoryDelta> }
impl ExecutionOutcome { #[must_use] pub fn success()->Self{Self{status:ExitStatus::Succeeded,contract_result:ContractResult::Success,return_data:Vec::new(),created_contract:None,energy_used:0,energy_penalty:0,logs:Vec::new(),internal_transactions:Vec::new(),deleted_accounts:Vec::new(),deltas:Vec::new()}} #[must_use] pub fn revert(data:Vec<u8>)->Self{let mut v=Self::success();v.status=ExitStatus::Reverted;v.contract_result=ContractResult::Revert;v.return_data=data;v} #[must_use] pub fn fault(fault:VmFault)->Self{let mut v=Self::success();v.status=ExitStatus::Faulted(fault);v.contract_result=fault.contract_result();v} }
