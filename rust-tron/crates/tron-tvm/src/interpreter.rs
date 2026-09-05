use crate::{
    opcodes_c::{child_frame, create2_address_no_ff, create_address, validate_deployed_code, CallKind},
    CallRequest, ContractResult, CreateKind, CreateRequest, EnergyMeter, ExecutionLimiter, ExecutionOutcome,
    ExitStatus, FrameContext, InternalTransactionRecord, Memory, OperationContext, OperationControl, OperationEffects,
    OperationRegistry, PrecompileRegistry, Program, Repository, ResolvedOperation, Stack1024, TvmRules, VmFault, Word,
};
use std::sync::Arc;
use tron_shielded::TronParameters;
use tron_primitives::TronAddress21;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceEvent { Fetched { pc: usize, opcode: u8 }, StackChecked { opcode: u8 }, EnergyCharged { opcode: u8, amount: i64 }, CpuChecked { opcode: u8 }, ActionCompleted { opcode: u8 }, Faulted { opcode: u8, fault: VmFault }, Finished }
pub trait ExecutionTrace { fn record(&mut self, event: TraceEvent); }
#[derive(Default)] pub struct NoTrace; impl ExecutionTrace for NoTrace { fn record(&mut self, _: TraceEvent) {} }

pub struct Interpreter<'a> { resolved: [Option<ResolvedOperation>; 256], rules: &'a TvmRules, precompiles: PrecompileRegistry }
impl<'a> Interpreter<'a> {
    pub fn new(registry:&OperationRegistry,rules:&'a TvmRules)->Self{Self{resolved:registry.resolve(rules),rules,precompiles:PrecompileRegistry::new()}}
    #[must_use] pub fn with_shielded_parameters(mut self, parameters:Arc<TronParameters>)->Self{self.precompiles=PrecompileRegistry::with_shielded_parameters(parameters);self}

    #[allow(clippy::too_many_arguments)]
    pub fn run(&self,frame:&FrameContext,program:&mut Program,stack:&mut Stack1024,memory:&mut Memory,repository:&mut Repository<'_>,meter:&mut EnergyMeter,limiter:&mut dyn ExecutionLimiter,trace:&mut dyn ExecutionTrace)->ExecutionOutcome{
        let root=repository.begin_child(crate::ChildStorageMode::Copied);
        let mut nonce=0i64;
        let mut outcome=self.execute_frame(frame,program,stack,memory,repository,meter,limiter,trace,&mut nonce,frame.root_txid.hash());
        if outcome.status==ExitStatus::Succeeded { let _=repository.commit_child(root); } else { let _=repository.revoke_child(root); outcome.logs.clear(); outcome.deleted_accounts.clear(); for tx in &mut outcome.internal_transactions { tx.reject(); } }
        outcome.deltas=repository.deltas();
        trace.record(TraceEvent::Finished);
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_frame(&self,frame:&FrameContext,program:&mut Program,stack:&mut Stack1024,memory:&mut Memory,repository:&mut Repository<'_>,meter:&mut EnergyMeter,limiter:&mut dyn ExecutionLimiter,trace:&mut dyn ExecutionTrace,nonce:&mut i64,parent_hash:tron_primitives::Hash32)->ExecutionOutcome{
        let mut effects=OperationEffects::default();
        loop {
            let pc=program.pc();
            let Some(opcode)=program.next_opcode() else{return self.outcome(ExitStatus::Succeeded,ContractResult::Success,effects,meter,repository)};
            trace.record(TraceEvent::Fetched{pc,opcode});
            let control=match self.step(opcode,frame,program,stack,memory,repository,meter,limiter,&mut effects,trace){Ok(v)=>v,Err(f)=>return self.fault_outcome(f,effects,meter,repository)};
            match control {
                OperationControl::Continue=>{}
                OperationControl::Halt(data)=>{effects.return_data=data;return self.outcome(ExitStatus::Succeeded,ContractResult::Success,effects,meter,repository)}
                OperationControl::Revert(data)=>{effects.return_data=data;return self.outcome(ExitStatus::Reverted,ContractResult::Revert,effects,meter,repository)}
                OperationControl::SelfDestruct(beneficiary)=>{
                    let current=*nonce;*nonce=nonce.saturating_add(1);
                    let balance=repository.balance(&frame.context_address).unwrap_or(0);
                    let token_info=repository.account(&frame.context_address).ok().flatten().map(|a|a.asset_v2.into_iter().map(|(id,value)|(Word::from(id.parse::<u64>().unwrap_or(0)),Word::from(value.max(0) as u64))).collect()).unwrap_or_default();
                    let mut tx=InternalTransactionRecord::child(parent_hash,frame.context_address,Some(beneficiary),Vec::new(),Word::from(balance.max(0) as u64),token_info,b"suicide",u32::from(frame.depth),current.max(0) as u32,current);
                    let deletes=!self.rules.selfdestruct_restriction||repository.is_new_contract(&frame.context_address);
                    let restricted_self_noop=self.rules.selfdestruct_restriction&&!deletes&&frame.context_address==beneficiary;
                    if !restricted_self_noop {match self.apply_selfdestruct(repository,frame.context_address,beneficiary){Ok(expired)=>{if expired>0{tx.value=tx.value.wrapping_add(Word::from(expired as u64));let n=*nonce;*nonce=nonce.saturating_add(1);effects.internal_transactions.push(InternalTransactionRecord::child(parent_hash,frame.context_address,Some(if frame.context_address==beneficiary{repository.blackhole_address()}else{beneficiary}),Vec::new(),Word::from(expired as u64),Vec::new(),b"withdrawExpireUnfreezeWhileSuiciding",u32::from(frame.depth),n.max(0) as u32,n));}},Err(_)=>return self.fault_outcome(VmFault::TransferFailed,effects,meter,repository)}}
                    if deletes{effects.deleted_accounts.push(frame.context_address);repository.delete_contract(&frame.context_address);}
                    effects.internal_transactions.insert(0,tx);return self.outcome(ExitStatus::Succeeded,ContractResult::Success,effects,meter,repository)
                }
                OperationControl::Call(request)=>self.drive_call(frame,request,stack,memory,repository,meter,limiter,trace,nonce,parent_hash,&mut effects),
                OperationControl::Create(request)=>if let Err(fault)=self.drive_create(frame,request,stack,repository,meter,limiter,trace,nonce,parent_hash,&mut effects){return self.fault_outcome(fault,effects,meter,repository)},
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn drive_call(&self,parent:&FrameContext,request:CallRequest,stack:&mut Stack1024,memory:&mut Memory,repository:&mut Repository<'_>,meter:&mut EnergyMeter,limiter:&mut dyn ExecutionLimiter,trace:&mut dyn ExecutionTrace,nonce:&mut i64,parent_hash:tron_primitives::Hash32,effects:&mut OperationEffects){
        let Some(spec)=child_frame(parent,request.destination,request.value,request.token_value,request.token_id,request.kind) else { self.reject_call_before_execution(&request,stack,meter,effects); return; };
        let feasible=match request.kind {
            CallKind::Call=>self.can_transfer_value(repository,parent.context_address,request.destination,request.value),
            CallKind::CallToken=>self.can_transfer_token(repository,parent.context_address,request.destination,request.token_id,request.token_value),
            CallKind::CallCode=>self.can_endow(repository,parent.context_address,request.value),
            CallKind::DelegateCall|CallKind::StaticCall=>Ok(()),
        };
        if feasible.is_err(){self.reject_call_before_execution(&request,stack,meter,effects);return;}
        let current=*nonce;*nonce=nonce.saturating_add(1);
        let token_info=if request.kind==CallKind::CallToken{vec![(request.token_id,request.token_value)]}else{Vec::new()};
        let mut record=InternalTransactionRecord::child(parent_hash,parent.context_address,Some(request.destination),request.data.clone(),if request.kind==CallKind::CallToken{Word::ZERO}else{request.value},token_info,b"call",u32::from(parent.depth),current.max(0) as u32,current);
        let id=repository.begin_child(crate::ChildStorageMode::Copied);
        let transfer=match request.kind {
            CallKind::Call=>self.transfer_value(repository,parent.context_address,request.destination,request.value),
            CallKind::CallToken=>self.transfer_token(repository,parent.context_address,request.destination,request.token_id,request.token_value),
            CallKind::CallCode|CallKind::DelegateCall|CallKind::StaticCall=>Ok(()),
        };
        if transfer.is_err(){let _=repository.revoke_child(id);record.reject();effects.internal_transactions.push(record);effects.return_data.clear();let _=stack.push(Word::ZERO);return;}
        let frame=FrameContext{code_address:spec.code_address,context_address:spec.context_address,origin:parent.origin,caller:spec.caller,input:request.data,call_value:spec.call_value,token_value:spec.token_value,token_id:spec.token_id,root_txid:parent.root_txid,contract_version:parent.contract_version,depth:spec.depth,is_static:spec.is_static};
        let mut child_meter=EnergyMeter::new(request.energy_limit.max(0)).expect("nonnegative");
        let mut outcome=if let Some(precompiled)=self.precompiles.dispatch_with_caller(&spec.code_address,&frame.input,self.rules,repository,&mut child_meter,Some(frame.caller)){
            let mut value=if precompiled.success{ExecutionOutcome::success()}else{ExecutionOutcome::fault(precompiled.fault.unwrap_or(VmFault::PrecompiledContract))};
            value.return_data=precompiled.output;value.energy_used=child_meter.used();value
        }else{
            let code=repository.code(&spec.code_address).unwrap_or_default();
            let mut child_program=Program::new(code);let mut child_stack=Stack1024::default();let mut child_memory=Memory::default();
            self.execute_frame(&frame,&mut child_program,&mut child_stack,&mut child_memory,repository,&mut child_meter,limiter,trace,nonce,record.hash)
        };
        let unused=request.reserved_energy.saturating_sub(outcome.energy_used.min(request.reserved_energy));let _=meter.refund(unused);
        effects.return_data=outcome.return_data.clone();
        let copy=request.output_size.min(outcome.return_data.len());let _=memory.write(request.output_offset,&outcome.return_data[..copy]);
        if outcome.status==ExitStatus::Succeeded {let _=repository.commit_child(id);effects.logs.append(&mut outcome.logs);effects.deleted_accounts.append(&mut outcome.deleted_accounts);effects.internal_transactions.push(record);effects.internal_transactions.append(&mut outcome.internal_transactions);let _=stack.push(Word::ONE);}else{let _=repository.revoke_child(id);record.reject();for tx in &mut outcome.internal_transactions{tx.reject();}effects.internal_transactions.push(record);effects.internal_transactions.append(&mut outcome.internal_transactions);let _=stack.push(Word::ZERO);}
    }

    fn reject_call_before_execution(&self,request:&CallRequest,stack:&mut Stack1024,meter:&mut EnergyMeter,effects:&mut OperationEffects){let _=meter.refund(request.reserved_energy);effects.return_data.clear();let _=stack.push(Word::ZERO);}

    fn can_endow(&self,repository:&Repository<'_>,from:TronAddress21,value:Word)->Result<(),VmFault>{let amount=value.to_i64_safe();if value>Word::from(amount as u64){return Err(VmFault::TransferFailed)}if repository.balance(&from).map_err(|_|VmFault::Other)?<amount{return Err(VmFault::TransferFailed)}Ok(())}

    fn can_transfer_value(&self,repository:&Repository<'_>,from:TronAddress21,to:TronAddress21,value:Word)->Result<(),VmFault>{self.can_endow(repository,from,value)?;let amount=value.to_i64_safe();repository.balance(&to).map_err(|_|VmFault::Other)?.checked_add(amount).ok_or(VmFault::TransferFailed)?;Ok(())}

    fn can_transfer_token(&self,repository:&Repository<'_>,from:TronAddress21,to:TronAddress21,id:Word,value:Word)->Result<(),VmFault>{let amount=value.to_i64_safe();if value>Word::from(amount as u64){return Err(VmFault::TransferFailed)}let token=String::from_utf8(id.no_leading_zero_bytes()).map_err(|_|VmFault::TransferFailed)?;if repository.token_balance(&from,&token).map_err(|_|VmFault::Other)?<amount{return Err(VmFault::TransferFailed)}repository.token_balance(&to,&token).map_err(|_|VmFault::Other)?.checked_add(amount).ok_or(VmFault::TransferFailed)?;Ok(())}

    #[allow(clippy::too_many_arguments)]
    fn drive_create(&self,parent:&FrameContext,request:CreateRequest,stack:&mut Stack1024,repository:&mut Repository<'_>,meter:&mut EnergyMeter,limiter:&mut dyn ExecutionLimiter,trace:&mut dyn ExecutionTrace,nonce:&mut i64,parent_hash:tron_primitives::Hash32,effects:&mut OperationEffects)->Result<(),VmFault>{
        if parent.depth>=64 {
            match request.kind {
                CreateKind::Create=>{let _=stack.push(Word::ZERO);return Ok(());}
                CreateKind::Create2 if self.rules.compatible_evm||self.rules.osaka=>{let _=stack.push(Word::ZERO);return Ok(());}
                CreateKind::Create2 if self.rules.create2_depth_timeout=>return Err(VmFault::OutOfTime),
                CreateKind::Create2=>{}
            }
        }
        if self.can_endow(repository,parent.context_address,request.value).is_err(){let _=stack.push(Word::ZERO);return Ok(());}
        let current=*nonce;*nonce=nonce.saturating_add(1);
        let address=request.salt.map_or_else(||create_address(parent,current),|salt|create2_address_no_ff(parent,salt,&request.init_code,self.rules.istanbul));
        let mut record=InternalTransactionRecord::child(parent_hash,parent.context_address,Some(address),request.init_code.clone(),request.value,Vec::new(),b"create",u32::from(parent.depth),current.max(0) as u32,current);
        let id=repository.begin_child(crate::ChildStorageMode::Copied);
        let collision=repository.create_destination_exists(&address,self.rules.constantinople).unwrap_or(true);
        if collision{let _=repository.revoke_child(id);record.reject();effects.internal_transactions.push(record);let _=meter.spend(request.energy_limit.min(meter.remaining()));let _=stack.push(Word::ZERO);return Ok(());}
        if repository.prepare_created_contract(address,parent.context_address,&parent.root_txid,request.kind==CreateKind::Create2,self.rules.constantinople,self.rules.compatible_evm,parent.contract_version).is_err(){let _=repository.revoke_child(id);record.reject();effects.internal_transactions.push(record);let _=stack.push(Word::ZERO);return Ok(());}
        if !request.value.is_zero()&&self.transfer_value(repository,parent.context_address,address,request.value).is_err(){let _=repository.revoke_child(id);record.reject();effects.internal_transactions.push(record);let _=stack.push(Word::ZERO);return Ok(());}
        let frame=FrameContext{code_address:address,context_address:address,origin:parent.origin,caller:parent.context_address,input:Vec::new(),call_value:request.value,token_value:Word::ZERO,token_id:Word::ZERO,root_txid:parent.root_txid,contract_version:parent.contract_version,depth:parent.depth+1,is_static:false};
        let mut program=Program::new(request.init_code);let mut child_stack=Stack1024::default();let mut memory=Memory::default();let mut child_meter=EnergyMeter::new(request.energy_limit.max(0)).expect("nonnegative");
        let mut outcome=self.execute_frame(&frame,&mut program,&mut child_stack,&mut memory,repository,&mut child_meter,limiter,trace,nonce,record.hash);
        if outcome.status==ExitStatus::Succeeded {
            let deposit=validate_deployed_code(&outcome.return_data,self.rules.london).and_then(|cost|if outcome.return_data.len()>24_576{Err(VmFault::OutOfEnergy)}else{child_meter.spend(cost)});
            if deposit.is_ok()&&repository.save_created_code(address,outcome.return_data.clone(),self.rules.constantinople).is_ok(){let _=repository.commit_child(id);effects.logs.append(&mut outcome.logs);effects.deleted_accounts.append(&mut outcome.deleted_accounts);effects.internal_transactions.push(record);effects.internal_transactions.append(&mut outcome.internal_transactions);if request.kind==CreateKind::Create||self.rules.osaka{effects.return_data.clear();}let _=stack.push(address_word(address));let _=meter.spend(child_meter.used().min(meter.remaining()));return Ok(());}
        }
        let _=meter.spend(child_meter.used().min(meter.remaining()));effects.return_data=outcome.return_data;let _=repository.revoke_child(id);record.reject();for tx in &mut outcome.internal_transactions{tx.reject();}effects.internal_transactions.push(record);effects.internal_transactions.append(&mut outcome.internal_transactions);let _=stack.push(Word::ZERO);Ok(())
    }

    fn transfer_value(&self,repository:&mut Repository<'_>,from:TronAddress21,to:TronAddress21,value:Word)->Result<(),VmFault>{let amount=value.to_i64_safe();if value>Word::from(amount as u64){return Err(VmFault::TransferFailed)}let balance=repository.balance(&from).map_err(|_|VmFault::Other)?;if balance<amount{return Err(VmFault::TransferFailed)}let target=repository.balance(&to).map_err(|_|VmFault::Other)?;repository.set_balance(&from,balance-amount).map_err(|_|VmFault::Other)?;repository.set_balance(&to,target.checked_add(amount).ok_or(VmFault::TransferFailed)?).map_err(|_|VmFault::Other)}
    fn transfer_token(&self,repository:&mut Repository<'_>,from:TronAddress21,to:TronAddress21,id:Word,value:Word)->Result<(),VmFault>{let amount=value.to_i64_safe();if value>Word::from(amount as u64){return Err(VmFault::TransferFailed)}let token=String::from_utf8(id.no_leading_zero_bytes()).map_err(|_|VmFault::TransferFailed)?;let balance=repository.token_balance(&from,&token).map_err(|_|VmFault::Other)?;if balance<amount{return Err(VmFault::TransferFailed)}let target=repository.token_balance(&to,&token).map_err(|_|VmFault::Other)?;repository.set_token_balance(&from,token.clone(),balance-amount).map_err(|_|VmFault::Other)?;repository.set_token_balance(&to,token,target.checked_add(amount).ok_or(VmFault::TransferFailed)?).map_err(|_|VmFault::Other)}
    fn apply_selfdestruct(&self,repository:&mut Repository<'_>,owner:TronAddress21,beneficiary:TronAddress21)->Result<i64,VmFault>{
        let inheritor=if owner==beneficiary{repository.blackhole_address()}else{beneficiary};let balance=repository.balance(&owner).map_err(|_|VmFault::Other)?;
        if owner==beneficiary{repository.set_balance(&owner,0).map_err(|_|VmFault::Other)?;if self.rules.transfer_trc10{let target=repository.balance(&inheritor).map_err(|_|VmFault::Other)?;repository.set_balance(&inheritor,target.checked_add(balance).ok_or(VmFault::TransferFailed)?).map_err(|_|VmFault::Other)?;}}
        else{let target=repository.balance(&beneficiary).map_err(|_|VmFault::Other)?;repository.set_balance(&owner,0).map_err(|_|VmFault::Other)?;repository.set_balance(&beneficiary,target.checked_add(balance).ok_or(VmFault::TransferFailed)?).map_err(|_|VmFault::Other)?;}
        if self.rules.transfer_trc10{if let Some(account)=repository.account(&owner).map_err(|_|VmFault::Other)?{for(token,amount)in account.asset_v2{let target=repository.token_balance(&inheritor,&token).map_err(|_|VmFault::Other)?;repository.set_token_balance(&owner,token.clone(),0).map_err(|_|VmFault::Other)?;repository.set_token_balance(&inheritor,token,target.checked_add(amount).ok_or(VmFault::TransferFailed)?).map_err(|_|VmFault::Other)?;}}}
        repository.transfer_selfdestruct_resources(&owner,&inheritor,self.rules.freeze,self.rules.freeze_v2,self.rules.selfdestruct_restriction).map_err(|_|VmFault::Other)
    }

    #[allow(clippy::too_many_arguments)]
    fn step(&self,opcode:u8,frame:&FrameContext,program:&mut Program,stack:&mut Stack1024,memory:&mut Memory,repository:&mut Repository<'_>,meter:&mut EnergyMeter,limiter:&mut dyn ExecutionLimiter,effects:&mut OperationEffects,trace:&mut dyn ExecutionTrace)->Result<OperationControl,VmFault>{
        let operation=self.resolved[usize::from(opcode)].ok_or_else(||{trace.record(TraceEvent::Faulted{opcode,fault:VmFault::IllegalOperation});VmFault::IllegalOperation})?;
        if let Err(fault)=stack.check_shape(operation.spec.required_before,operation.spec.resulting_window){trace.record(TraceEvent::Faulted{opcode,fault});return Err(fault)}trace.record(TraceEvent::StackChecked{opcode});
        let mut context=OperationContext{rules:self.rules,frame,program,stack,memory,effects,energy:meter,repository,limiter};
        let cost=(operation.variant.energy)(&context).map_err(|fault|{trace.record(TraceEvent::Faulted{opcode,fault});fault})?;context.energy.spend(cost).map_err(|fault|{trace.record(TraceEvent::Faulted{opcode,fault});fault})?;trace.record(TraceEvent::EnergyCharged{opcode,amount:cost});context.limiter.check().map_err(|fault|{trace.record(TraceEvent::Faulted{opcode,fault});fault})?;trace.record(TraceEvent::CpuChecked{opcode});
        match (operation.variant.execute)(&mut context){Ok(control)=>{trace.record(TraceEvent::ActionCompleted{opcode});Ok(control)},Err(fault)=>{trace.record(TraceEvent::Faulted{opcode,fault});Err(fault)}}
    }
    fn fault_outcome(&self,fault:VmFault,effects:OperationEffects,meter:&mut EnergyMeter,repository:&Repository<'_>)->ExecutionOutcome{if fault.spends_remaining(){meter.exhaust()}self.outcome(ExitStatus::Faulted(fault),fault.contract_result(),effects,meter,repository)}
    fn outcome(&self,status:ExitStatus,contract_result:ContractResult,effects:OperationEffects,meter:&EnergyMeter,repository:&Repository<'_>)->ExecutionOutcome{let mut deleted_accounts=effects.deleted_accounts;deleted_accounts.sort_by(|a,b|a.as_bytes().cmp(b.as_bytes()));deleted_accounts.dedup_by(|a,b|a.as_bytes()==b.as_bytes());ExecutionOutcome{status,contract_result,return_data:effects.return_data,created_contract:None,energy_used:meter.used(),energy_penalty:meter.penalty(),logs:effects.logs,internal_transactions:effects.internal_transactions,deleted_accounts,deltas:repository.deltas()}}
}
fn address_word(address:TronAddress21)->Word{let mut bytes=[0u8;32];bytes[12..].copy_from_slice(&address.as_bytes()[1..]);Word::from_be_bytes(bytes)}
