use crate::{CallRequest,CreateRequest,EnergyMeter,ExecutionLimiter,InternalTransactionRecord,Memory,Program,Repository,Stack1024,TvmLog,TvmRules,VmFault,Word};
use tron_primitives::{TransactionId,TronAddress21};

pub type ActivationFn=fn(&TvmRules)->bool;
pub type VariantPredicate=fn(&TvmRules)->bool;
pub type EnergyFn=fn(&OperationContext<'_, '_>)->Result<i64,VmFault>;
pub type ExecuteFn=fn(&mut OperationContext<'_, '_>)->Result<OperationControl,VmFault>;
#[derive(Clone,Copy)] pub struct OperationVariant{pub when:VariantPredicate,pub energy:EnergyFn,pub execute:ExecuteFn}
#[derive(Clone,Copy)] pub struct OperationSpec{pub opcode:u8,pub required_before:u16,pub resulting_window:u16,pub activation:ActivationFn,pub variants:&'static[OperationVariant]}
#[derive(Clone,Copy)] pub struct ResolvedOperation{pub spec:&'static OperationSpec,pub variant:OperationVariant}
#[derive(Clone,Debug,Eq,PartialEq)] pub enum OperationControl{Continue,Halt(Vec<u8>),Revert(Vec<u8>),Call(CallRequest),Create(CreateRequest),SelfDestruct(TronAddress21)}
#[derive(Clone,Debug,Eq,PartialEq)] pub struct FrameContext{pub code_address:TronAddress21,pub context_address:TronAddress21,pub origin:TronAddress21,pub caller:TronAddress21,pub input:Vec<u8>,pub call_value:Word,pub token_value:Word,pub token_id:Word,pub root_txid:TransactionId,pub contract_version:i32,pub depth:u16,pub is_static:bool}
#[derive(Clone,Debug,Default,Eq,PartialEq)] pub struct OperationEffects{pub return_data:Vec<u8>,pub logs:Vec<TvmLog>,pub internal_transactions:Vec<InternalTransactionRecord>,pub deleted_accounts:Vec<TronAddress21>}
pub struct OperationContext<'a,'state>{pub rules:&'a TvmRules,pub frame:&'a FrameContext,pub program:&'a mut Program,pub stack:&'a mut Stack1024,pub memory:&'a mut Memory,pub effects:&'a mut OperationEffects,pub energy:&'a mut EnergyMeter,pub repository:&'a mut Repository<'state>,pub limiter:&'a mut dyn ExecutionLimiter}
const fn always(_: &TvmRules)->bool{true}
fn zero_energy(_: &OperationContext<'_,'_>)->Result<i64,VmFault>{Ok(0)}
fn illegal(_: &mut OperationContext<'_,'_>)->Result<OperationControl,VmFault>{Err(VmFault::IllegalOperation)}
const UNDEFINED_VARIANTS:[OperationVariant;1]=[OperationVariant{when:always,energy:zero_energy,execute:illegal}];
pub const UNDEFINED_OPERATION:OperationSpec=OperationSpec{opcode:0,required_before:0,resulting_window:0,activation:always,variants:&UNDEFINED_VARIANTS};

pub struct OperationRegistry{slots:[Option<&'static OperationSpec>;256]}
impl OperationRegistry{
    pub fn from_families(families:&[&'static[OperationSpec]])->Result<Self,RegistryError>{let mut slots=[None;256];for family in families{for spec in *family{let slot=&mut slots[usize::from(spec.opcode)];if slot.is_some(){return Err(RegistryError::Duplicate(spec.opcode));}if spec.variants.is_empty(){return Err(RegistryError::NoVariants(spec.opcode));}if spec.required_before>1024||spec.resulting_window>1024{return Err(RegistryError::InvalidShape(spec.opcode));}*slot=Some(spec);}}Ok(Self{slots})}
    pub fn integration()->Result<Self,RegistryError>{let registry=Self::from_families(&[crate::opcodes_a::operation_specs(),crate::opcodes_b::operation_specs(),crate::opcodes_c::operation_specs()])?;if registry.registered_count()!=165{return Err(RegistryError::WrongRegisteredCount(registry.registered_count()));}Ok(registry)}
    #[must_use] pub fn registered_count(&self)->usize{self.slots.iter().filter(|v|v.is_some()).count()}
    #[must_use] pub fn undefined_count(&self)->usize{256-self.registered_count()}
    pub fn validate_activation(&self,rules:&TvmRules)->Result<(),RegistryError>{for spec in self.slots.iter().flatten(){if (spec.activation)(rules)&&!spec.variants.iter().any(|variant|(variant.when)(rules)){return Err(RegistryError::NoActiveVariant(spec.opcode));}}Ok(())}
    #[must_use] pub fn resolve(&self,rules:&TvmRules)->[Option<ResolvedOperation>;256]{let mut out=[None;256];for (i,spec) in self.slots.iter().enumerate(){let Some(spec)=spec else{continue};if !(spec.activation)(rules){continue;}let mut selected=None;for variant in spec.variants{if (variant.when)(rules){selected=Some(*variant);}}out[i]=selected.map(|variant|ResolvedOperation{spec,variant});}out}
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]pub enum RegistryError{Duplicate(u8),NoVariants(u8),InvalidShape(u8),NoActiveVariant(u8),WrongRegisteredCount(usize)}

