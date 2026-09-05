use crate::{VmFault, Word};
use std::collections::BTreeSet;
use std::sync::Arc;

pub const STACK_LIMIT: usize = 1024;
pub const MEMORY_LIMIT: usize = 3 * 1024 * 1024;
const MEMORY_CHUNK: usize = 1024;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Stack1024(Vec<Word>);
impl Stack1024 {
    #[must_use] pub fn len(&self)->usize{self.0.len()}
    #[must_use] pub fn is_empty(&self)->bool{self.0.is_empty()}
    pub fn check_shape(&self,required:u16,resulting:u16)->Result<(),VmFault>{let r=usize::from(required);if self.len()<r{return Err(VmFault::StackTooSmall);}let projected=self.len()-r+usize::from(resulting);if projected>STACK_LIMIT{return Err(VmFault::StackTooLarge);}Ok(())}
    pub fn push(&mut self,value:Word)->Result<(),VmFault>{if self.len()==STACK_LIMIT{return Err(VmFault::StackTooLarge);}self.0.push(value);Ok(())}
    pub fn pop(&mut self)->Result<Word,VmFault>{self.0.pop().ok_or(VmFault::StackTooSmall)}
    pub fn peek(&self,index_from_top:usize)->Result<Word,VmFault>{self.0.get(self.len().checked_sub(index_from_top+1).ok_or(VmFault::StackTooSmall)?).copied().ok_or(VmFault::StackTooSmall)}
    pub fn set(&mut self,index_from_top:usize,value:Word)->Result<(),VmFault>{let i=self.len().checked_sub(index_from_top+1).ok_or(VmFault::StackTooSmall)?;*self.0.get_mut(i).ok_or(VmFault::StackTooSmall)?=value;Ok(())}
    pub fn swap(&mut self,index_from_top:usize)->Result<(),VmFault>{let top=self.len().checked_sub(1).ok_or(VmFault::StackTooSmall)?;let other=top.checked_sub(index_from_top).ok_or(VmFault::StackTooSmall)?;self.0.swap(top,other);Ok(())}
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Memory { bytes: Vec<u8>, soft_len: usize }
impl Memory {
    #[must_use] pub fn soft_len(&self)->usize{self.soft_len}
    #[must_use] pub fn physical_len(&self)->usize{self.bytes.len()}
    pub fn expand(&mut self,offset:usize,size:usize)->Result<(),VmFault>{if size==0{return Ok(());}let end=offset.checked_add(size).ok_or(VmFault::OutOfMemory)?;if end>MEMORY_LIMIT{return Err(VmFault::OutOfMemory);}let soft=end.checked_add(31).ok_or(VmFault::OutOfMemory)?/32*32;if soft>self.soft_len{self.soft_len=soft;}let physical=end.checked_add(MEMORY_CHUNK-1).ok_or(VmFault::OutOfMemory)?/MEMORY_CHUNK*MEMORY_CHUNK;if physical>self.bytes.len(){self.bytes.resize(physical,0);}Ok(())}
    pub fn write(&mut self,offset:usize,data:&[u8])->Result<(),VmFault>{self.expand(offset,data.len())?;if !data.is_empty(){self.bytes[offset..offset+data.len()].copy_from_slice(data);}Ok(())}
    pub fn write_padded(&mut self,offset:usize,size:usize,source:&[u8],source_offset:usize)->Result<(),VmFault>{
        self.expand(offset,size)?;
        if size==0{return Ok(());}
        let destination=&mut self.bytes[offset..offset+size];
        destination.fill(0);
        if source_offset<source.len(){
            let copied=size.min(source.len()-source_offset);
            destination[..copied].copy_from_slice(&source[source_offset..source_offset+copied]);
        }
        Ok(())
    }
    pub fn read(&mut self,offset:usize,size:usize)->Result<Vec<u8>,VmFault>{self.expand(offset,size)?;Ok(if size==0{Vec::new()}else{self.bytes[offset..offset+size].to_vec()})}
    pub fn copy_within(&mut self,dst:usize,src:usize,size:usize)->Result<(),VmFault>{if size==0{return Ok(());}self.expand(src,size)?;self.expand(dst,size)?;self.bytes.copy_within(src..src+size,dst);Ok(())}
}

#[derive(Clone, Debug)]
pub struct Program { code: Arc<[u8]>, pc: usize, jumpdests: BTreeSet<usize> }
impl Program {
    #[must_use] pub fn new(code:impl Into<Arc<[u8]>>)->Self{let code=code.into();let mut jumpdests=BTreeSet::new();let mut i=0;while i<code.len(){let op=code[i];if op==0x5b{jumpdests.insert(i);}i+=1;if (0x60..=0x7f).contains(&op){i=i.saturating_add(usize::from(op-0x5f));}}Self{code,pc:0,jumpdests}}
    #[must_use] pub fn pc(&self)->usize{self.pc}
    #[must_use] pub fn code(&self)->&[u8]{&self.code}
    #[must_use] pub fn is_jumpdest(&self,pc:usize)->bool{self.jumpdests.contains(&pc)}
    pub fn jump(&mut self,pc:usize)->Result<(),VmFault>{if !self.is_jumpdest(pc){return Err(VmFault::BadJumpDestination);}self.pc=pc;Ok(())}
    pub fn next_opcode(&mut self)->Option<u8>{let op=self.code.get(self.pc).copied()?;self.pc+=1;Some(op)}
    pub fn read_push(&mut self,count:usize)->Word{let mut out=[0u8;32];let available=count.min(self.code.len().saturating_sub(self.pc));out[32-count..32-count+available].copy_from_slice(&self.code[self.pc..self.pc+available]);self.pc=self.pc.saturating_add(count);Word::from_be_bytes(out)}
}
