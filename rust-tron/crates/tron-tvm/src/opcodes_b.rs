//! C014.03B STOP, stack, PUSH/DUP/SWAP, memory, storage, control, log, and halt opcodes.
use crate::{EnergyMeter,OperationContext,OperationControl,OperationSpec,OperationVariant,TvmRules,TvmLog,VmFault,Word};

const fn always(_: &TvmRules)->bool{true}
const fn shanghai(r:&TvmRules)->bool{r.shanghai}
const fn cancun(r:&TvmRules)->bool{r.cancun}
fn energy_zero(_: &OperationContext<'_,'_>)->Result<i64,VmFault>{Ok(0)}
fn energy_base(_: &OperationContext<'_,'_>)->Result<i64,VmFault>{Ok(2)}
fn energy_very_low(_: &OperationContext<'_,'_>)->Result<i64,VmFault>{Ok(3)}
fn energy_mid(_: &OperationContext<'_,'_>)->Result<i64,VmFault>{Ok(8)}
fn energy_high(_: &OperationContext<'_,'_>)->Result<i64,VmFault>{Ok(10)}
fn energy_special(_: &OperationContext<'_,'_>)->Result<i64,VmFault>{Ok(1)}
fn energy_sload(_: &OperationContext<'_,'_>)->Result<i64,VmFault>{Ok(50)}
fn energy_tstorage(_: &OperationContext<'_,'_>)->Result<i64,VmFault>{Ok(100)}
fn usize_word(v:Word)->usize{usize::try_from(v.to_i32_safe()).unwrap_or(usize::MAX)}
fn memory_end(offset:Word,size:Word)->Result<usize,VmFault>{let size=usize_word(size);if size==0{return Ok(0)}usize_word(offset).checked_add(size).ok_or(VmFault::OutOfMemory)}
fn memory_delta(ctx:&OperationContext<'_,'_>,end:usize)->Result<i64,VmFault>{if end==0||end<=ctx.memory.soft_len(){Ok(0)}else{EnergyMeter::memory_delta(ctx.memory.soft_len(),end)}}
fn energy_memory(ctx:&OperationContext<'_,'_>)->Result<i64,VmFault>{let op=ctx.program.code().get(ctx.program.pc().saturating_sub(1)).copied().ok_or(VmFault::IllegalOperation)?;let size=if op==0x53{Word::ONE}else{Word::from(32u64)};memory_delta(ctx,memory_end(ctx.stack.peek(0)?,size)?)?.checked_add(if ctx.rules.higher_cpu_memory{1}else{0}).ok_or(VmFault::OutOfEnergy)}
fn storage_value(ctx:&OperationContext<'_,'_>,slot:Word)->Option<Word>{ctx.repository.storage(&ctx.frame.context_address,slot,ctx.frame.contract_version,None)}
fn energy_sstore(ctx:&OperationContext<'_,'_>)->Result<i64,VmFault>{let old=storage_value(ctx,ctx.stack.peek(0)?);let new=ctx.stack.peek(1)?;Ok(if old.is_none()&&!new.is_zero(){20_000}else{5_000})}
fn copy_words(size:usize)->Result<i64,VmFault>{i64::try_from(size.checked_add(31).ok_or(VmFault::OutOfMemory)?/32).map_err(|_|VmFault::OutOfEnergy)?.checked_mul(3).ok_or(VmFault::OutOfEnergy)}
fn energy_mcopy(ctx:&OperationContext<'_,'_>)->Result<i64,VmFault>{let dst=ctx.stack.peek(0)?;let src=ctx.stack.peek(1)?;let size=ctx.stack.peek(2)?;let end=memory_end(if dst>src{dst}else{src},size)?;3i64.checked_add(memory_delta(ctx,end)?).and_then(|v|v.checked_add(copy_words(usize_word(size)).ok()?)).ok_or(VmFault::OutOfEnergy)}
fn energy_log(ctx:&OperationContext<'_,'_>)->Result<i64,VmFault>{let op=ctx.program.code().get(ctx.program.pc().saturating_sub(1)).copied().ok_or(VmFault::IllegalOperation)?;let topics=i64::from(op-0xa0);let size=usize_word(ctx.stack.peek(1)?);let data=i64::try_from(size).map_err(|_|VmFault::OutOfEnergy)?.checked_mul(8).ok_or(VmFault::OutOfEnergy)?;375i64.checked_add(topics*375).and_then(|v|v.checked_add(data)).and_then(|v|v.checked_add(memory_delta(ctx,memory_end(ctx.stack.peek(0).unwrap_or(Word::MAX),ctx.stack.peek(1).unwrap_or(Word::MAX)).ok()?).ok()?)).ok_or(VmFault::OutOfEnergy)}
fn energy_return(ctx:&OperationContext<'_,'_>)->Result<i64,VmFault>{memory_delta(ctx,memory_end(ctx.stack.peek(0)?,ctx.stack.peek(1)?)?)}
fn execute_stop(_: &mut OperationContext<'_,'_>)->Result<OperationControl,VmFault>{Ok(OperationControl::Halt(Vec::new()))}
fn execute_generic(ctx:&mut OperationContext<'_,'_>)->Result<OperationControl,VmFault>{let op=ctx.program.code().get(ctx.program.pc().saturating_sub(1)).copied().ok_or(VmFault::IllegalOperation)?;match op{
0x50=>{ctx.stack.pop()?;}
0x51=>{let o=usize_word(ctx.stack.pop()?);let b=ctx.memory.read(o,32)?;ctx.stack.push(Word::from_be_bytes(b.try_into().expect("32 bytes")))?;}
0x52=>{let o=usize_word(ctx.stack.pop()?);let v=ctx.stack.pop()?;ctx.memory.write(o,&v.to_be_bytes())?;}
0x53=>{let o=usize_word(ctx.stack.pop()?);let v=ctx.stack.pop()?;ctx.memory.write(o,&[v.to_be_bytes()[31]])?;}
0x54=>{let k=ctx.stack.pop()?;ctx.stack.push(storage_value(ctx,k).unwrap_or(Word::ZERO))?;}
0x55=>{if ctx.frame.is_static{return Err(VmFault::StaticViolation)}let k=ctx.stack.pop()?;let v=ctx.stack.pop()?;ctx.repository.set_storage(&ctx.frame.context_address,k,v,ctx.frame.contract_version,None);}
0x56=>{let p=usize_word(ctx.stack.pop()?);ctx.program.jump(p)?;}
0x57=>{let p=usize_word(ctx.stack.pop()?);let c=ctx.stack.pop()?;if !c.is_zero(){ctx.program.jump(p)?;}}
0x58=>ctx.stack.push(Word::from(u64::try_from(ctx.program.pc().saturating_sub(1)).unwrap_or(u64::MAX)))?,
0x59=>ctx.stack.push(Word::from(u64::try_from(ctx.memory.soft_len()).unwrap_or(u64::MAX)))?,
0x5a=>ctx.stack.push(Word::from(u64::try_from(ctx.energy.remaining()).unwrap_or(0)))?,
0x5b=>{}
0x5c=>{let k=ctx.stack.pop()?;ctx.stack.push(ctx.repository.transient(&ctx.frame.context_address,k))?;}
0x5d=>{if ctx.frame.is_static{return Err(VmFault::StaticViolation)}let k=ctx.stack.pop()?;let v=ctx.stack.pop()?;ctx.repository.set_transient(ctx.frame.context_address,k,v);}
0x5e=>{let d=usize_word(ctx.stack.pop()?);let s=usize_word(ctx.stack.pop()?);let n=usize_word(ctx.stack.pop()?);ctx.memory.copy_within(d,s,n)?;}
0x5f=>ctx.stack.push(Word::ZERO)?,
0x60..=0x7f=>ctx.stack.push(ctx.program.read_push(usize::from(op-0x5f)))?,
0x80..=0x8f=>{let n=usize::from(op-0x80);ctx.stack.push(ctx.stack.peek(n)?)?;}
0x90..=0x9f=>ctx.stack.swap(usize::from(op-0x8f))?,
0xa0..=0xa4=>{if ctx.frame.is_static{return Err(VmFault::StaticViolation)}let offset=usize_word(ctx.stack.pop()?);let size=usize_word(ctx.stack.pop()?);let mut topics=Vec::with_capacity(usize::from(op-0xa0));for _ in 0..usize::from(op-0xa0){topics.push(ctx.stack.pop()?.to_be_bytes());}let data=ctx.memory.read(offset,size)?;ctx.effects.logs.push(TvmLog{address:ctx.frame.context_address.payload().into_array(),topics,data});}
_=>return Err(VmFault::IllegalOperation)}Ok(OperationControl::Continue)}
fn execute_return(ctx:&mut OperationContext<'_,'_>)->Result<OperationControl,VmFault>{let o=usize_word(ctx.stack.pop()?);let n=usize_word(ctx.stack.pop()?);Ok(OperationControl::Halt(ctx.memory.read(o,n)?))}
fn execute_revert(ctx:&mut OperationContext<'_,'_>)->Result<OperationControl,VmFault>{let o=usize_word(ctx.stack.pop()?);let n=usize_word(ctx.stack.pop()?);Ok(OperationControl::Revert(ctx.memory.read(o,n)?))}

const V0:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_zero,execute:execute_stop}];
const V1:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_base,execute:execute_generic}];
const V2:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_memory,execute:execute_generic}];
const V3:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_sload,execute:execute_generic}];
const V4:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_sstore,execute:execute_generic}];
const V5:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_mid,execute:execute_generic}];
const V6:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_high,execute:execute_generic}];
const V7:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_special,execute:execute_generic}];
const V8:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_tstorage,execute:execute_generic}];
const V9:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_mcopy,execute:execute_generic}];
const V10:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_very_low,execute:execute_generic}];
const V11:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_log,execute:execute_generic}];
const V12:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_return,execute:execute_return}];
const V13:[OperationVariant;1]=[OperationVariant{when:always,energy:energy_return,execute:execute_revert}];

const SPECS:[OperationSpec;88]=[
OperationSpec{opcode:0x00,required_before:0,resulting_window:0,activation:always,variants:&V0},
OperationSpec{opcode:0x50,required_before:1,resulting_window:0,activation:always,variants:&V1},
OperationSpec{opcode:0x51,required_before:1,resulting_window:1,activation:always,variants:&V2},
OperationSpec{opcode:0x52,required_before:2,resulting_window:0,activation:always,variants:&V2},
OperationSpec{opcode:0x53,required_before:2,resulting_window:0,activation:always,variants:&V2},
OperationSpec{opcode:0x54,required_before:1,resulting_window:1,activation:always,variants:&V3},
OperationSpec{opcode:0x55,required_before:2,resulting_window:0,activation:always,variants:&V4},
OperationSpec{opcode:0x56,required_before:1,resulting_window:0,activation:always,variants:&V5},
OperationSpec{opcode:0x57,required_before:2,resulting_window:0,activation:always,variants:&V6},
OperationSpec{opcode:0x58,required_before:0,resulting_window:1,activation:always,variants:&V1},
OperationSpec{opcode:0x59,required_before:0,resulting_window:1,activation:always,variants:&V1},
OperationSpec{opcode:0x5a,required_before:0,resulting_window:1,activation:always,variants:&V1},
OperationSpec{opcode:0x5b,required_before:0,resulting_window:0,activation:always,variants:&V7},
OperationSpec{opcode:0x5c,required_before:1,resulting_window:1,activation:cancun,variants:&V8},
OperationSpec{opcode:0x5d,required_before:2,resulting_window:0,activation:cancun,variants:&V8},
OperationSpec{opcode:0x5e,required_before:3,resulting_window:0,activation:cancun,variants:&V9},
OperationSpec{opcode:0x5f,required_before:0,resulting_window:1,activation:shanghai,variants:&V1},
OperationSpec{opcode:0x60,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x61,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x62,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x63,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x64,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x65,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x66,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x67,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x68,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x69,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x6a,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x6b,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x6c,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x6d,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x6e,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x6f,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x70,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x71,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x72,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x73,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x74,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x75,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x76,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x77,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x78,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x79,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x7a,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x7b,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x7c,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x7d,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x7e,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x7f,required_before:0,resulting_window:1,activation:always,variants:&V10},
OperationSpec{opcode:0x80,required_before:1,resulting_window:2,activation:always,variants:&V10},
OperationSpec{opcode:0x81,required_before:2,resulting_window:3,activation:always,variants:&V10},
OperationSpec{opcode:0x82,required_before:3,resulting_window:4,activation:always,variants:&V10},
OperationSpec{opcode:0x83,required_before:4,resulting_window:5,activation:always,variants:&V10},
OperationSpec{opcode:0x84,required_before:5,resulting_window:6,activation:always,variants:&V10},
OperationSpec{opcode:0x85,required_before:6,resulting_window:7,activation:always,variants:&V10},
OperationSpec{opcode:0x86,required_before:7,resulting_window:8,activation:always,variants:&V10},
OperationSpec{opcode:0x87,required_before:8,resulting_window:9,activation:always,variants:&V10},
OperationSpec{opcode:0x88,required_before:9,resulting_window:10,activation:always,variants:&V10},
OperationSpec{opcode:0x89,required_before:10,resulting_window:11,activation:always,variants:&V10},
OperationSpec{opcode:0x8a,required_before:11,resulting_window:12,activation:always,variants:&V10},
OperationSpec{opcode:0x8b,required_before:12,resulting_window:13,activation:always,variants:&V10},
OperationSpec{opcode:0x8c,required_before:13,resulting_window:14,activation:always,variants:&V10},
OperationSpec{opcode:0x8d,required_before:14,resulting_window:15,activation:always,variants:&V10},
OperationSpec{opcode:0x8e,required_before:15,resulting_window:16,activation:always,variants:&V10},
OperationSpec{opcode:0x8f,required_before:16,resulting_window:17,activation:always,variants:&V10},
OperationSpec{opcode:0x90,required_before:2,resulting_window:2,activation:always,variants:&V10},
OperationSpec{opcode:0x91,required_before:3,resulting_window:3,activation:always,variants:&V10},
OperationSpec{opcode:0x92,required_before:4,resulting_window:4,activation:always,variants:&V10},
OperationSpec{opcode:0x93,required_before:5,resulting_window:5,activation:always,variants:&V10},
OperationSpec{opcode:0x94,required_before:6,resulting_window:6,activation:always,variants:&V10},
OperationSpec{opcode:0x95,required_before:7,resulting_window:7,activation:always,variants:&V10},
OperationSpec{opcode:0x96,required_before:8,resulting_window:8,activation:always,variants:&V10},
OperationSpec{opcode:0x97,required_before:9,resulting_window:9,activation:always,variants:&V10},
OperationSpec{opcode:0x98,required_before:10,resulting_window:10,activation:always,variants:&V10},
OperationSpec{opcode:0x99,required_before:11,resulting_window:11,activation:always,variants:&V10},
OperationSpec{opcode:0x9a,required_before:12,resulting_window:12,activation:always,variants:&V10},
OperationSpec{opcode:0x9b,required_before:13,resulting_window:13,activation:always,variants:&V10},
OperationSpec{opcode:0x9c,required_before:14,resulting_window:14,activation:always,variants:&V10},
OperationSpec{opcode:0x9d,required_before:15,resulting_window:15,activation:always,variants:&V10},
OperationSpec{opcode:0x9e,required_before:16,resulting_window:16,activation:always,variants:&V10},
OperationSpec{opcode:0x9f,required_before:17,resulting_window:17,activation:always,variants:&V10},
OperationSpec{opcode:0xa0,required_before:2,resulting_window:0,activation:always,variants:&V11},
OperationSpec{opcode:0xa1,required_before:3,resulting_window:0,activation:always,variants:&V11},
OperationSpec{opcode:0xa2,required_before:4,resulting_window:0,activation:always,variants:&V11},
OperationSpec{opcode:0xa3,required_before:5,resulting_window:0,activation:always,variants:&V11},
OperationSpec{opcode:0xa4,required_before:6,resulting_window:0,activation:always,variants:&V11},
OperationSpec{opcode:0xf3,required_before:2,resulting_window:0,activation:always,variants:&V12},
OperationSpec{opcode:0xfd,required_before:2,resulting_window:0,activation:always,variants:&V13},
];
/// Returns this family's immutable registry rows in numeric opcode order.
#[must_use] pub const fn operation_specs()->&'static [OperationSpec]{&SPECS}
