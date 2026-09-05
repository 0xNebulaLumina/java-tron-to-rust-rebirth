//! TRON-specific virtual-machine foundation.
//!
//! This crate deliberately owns TVM semantics rather than adapting an Ethereum
//! runtime. Consensus-visible state changes are journaled over `tron-state`.

mod energy;
mod interpreter;
mod machine;
mod opcode;
pub mod opcodes_a;
pub mod opcodes_b;
pub mod opcodes_c;
mod repository;
mod result;
mod rules;
mod word;

pub use energy::{apply_dynamic_energy,forwarded_call_energy,next_dynamic_factor,DeadlineLimiter,EnergyMeter,ExecutionLimiter,ManualMonotonicClock,MonotonicClock,Unlimited,DYNAMIC_ENERGY_DECIMAL,DYNAMIC_ENERGY_DECREASE_DIVISOR};
pub use interpreter::{ExecutionTrace,Interpreter,NoTrace,TraceEvent};
pub use machine::{Memory,Program,Stack1024,MEMORY_LIMIT,STACK_LIMIT};
pub use opcode::{FrameContext,OperationContext,OperationControl,OperationEffects,OperationRegistry,OperationSpec,OperationVariant,RegistryError,ResolvedOperation,UNDEFINED_OPERATION};
pub use repository::{ChildId,ChildStorageMode,Repository,RepositoryDelta,RepositoryError};
pub use result::{CallRequest,CreateKind,CreateRequest,ContractResult,ExecutionOutcome,ExitStatus,InternalTransactionRecord,TvmLog,VmFault};
pub use rules::{ExecutionOptions,TvmRules};
pub use word::Word;
