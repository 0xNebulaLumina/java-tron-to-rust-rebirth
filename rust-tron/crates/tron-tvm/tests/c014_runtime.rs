use std::{fs, path::PathBuf, time::{Duration, SystemTime, UNIX_EPOCH}};
use prost::Message;
use tron_primitives::{Address20, Hash32, TransactionId, TronAddress21};
use tron_protocol::protocol::{Account,AccountType,SmartContract};
use tron_state::{SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};
use tron_tvm::{
    apply_dynamic_energy, forwarded_call_energy, ContractResult, DeadlineLimiter, EnergyMeter,
    ExecutionTrace, FrameContext, Interpreter, ManualMonotonicClock, Memory, OperationRegistry,
    Program, Repository, Stack1024, TraceEvent, TvmRules, Unlimited, VmFault, Word,
};

fn manager(name: &str) -> (PathBuf, SessionManager) {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("c014-runtime-{name}-{nonce}"));
    let requirements = OpenRequirements {
        identity: StorageIdentity { network: "c014".into(), genesis: "00".into() },
        schema_version: 1,
        backend: "rustlog".into(),
        backend_format: "rustlog-v1".into(),
        supported_features: vec!["rustlog-v1".into()],
    };
    let root = StateStore::new(StorageManager::new(requirements).open_store(&path).unwrap());
    (path, SessionManager::new(root))
}

fn address(byte: u8) -> TronAddress21 {
    TronAddress21::new(0x41, Address20::from_array([byte; 20]))
}

fn frame() -> FrameContext {
    FrameContext {
        code_address: address(1), context_address: address(1), origin: address(2), caller: address(3),
        input: Vec::new(), call_value: Word::ZERO, token_value: Word::ZERO, token_id: Word::ZERO,
        root_txid: TransactionId::new(Hash32::from_array([7; 32])), contract_version: 0, depth: 0, is_static: false,
    }
}

#[derive(Default)]
struct Events(Vec<TraceEvent>);
impl ExecutionTrace for Events { fn record(&mut self, event: TraceEvent) { self.0.push(event); } }

#[test]
fn interpreter_observes_stack_energy_cpu_action_and_finish_order() {
    let (path, manager) = manager("ordering");
    let session = manager.build_session().unwrap();
    let mut repository = Repository::from_session(&session);
    let registry = OperationRegistry::integration().unwrap();
    let rules = TvmRules::default();
    let interpreter = Interpreter::new(&registry, &rules);
    let mut program = Program::new(vec![0x60, 1, 0x60, 2, 0x01, 0x00]);
    let mut stack = Stack1024::default();
    let mut memory = Memory::default();
    let mut meter = EnergyMeter::new(100).unwrap();
    let mut limiter = Unlimited;
    let mut trace = Events::default();
    let outcome = interpreter.run(&frame(), &mut program, &mut stack, &mut memory, &mut repository, &mut meter, &mut limiter, &mut trace);
    assert_eq!(outcome.contract_result, ContractResult::Success);
    assert_eq!(stack.peek(0).unwrap(), Word::from(3u64));
    assert_eq!(outcome.energy_used, 9);
    assert_eq!(trace.0.last(), Some(&TraceEvent::Finished));
    for opcode in [0x60, 0x60, 0x01, 0x00] {
        let fetched = trace.0.iter().position(|event| matches!(event, TraceEvent::Fetched { opcode: value, .. } if *value == opcode)).unwrap();
        let stack_checked = trace.0.iter().enumerate().skip(fetched).find(|(_, event)| matches!(event, TraceEvent::StackChecked { opcode: value } if *value == opcode)).unwrap().0;
        let charged = trace.0.iter().enumerate().skip(stack_checked).find(|(_, event)| matches!(event, TraceEvent::EnergyCharged { opcode: value, .. } if *value == opcode)).unwrap().0;
        let cpu = trace.0.iter().enumerate().skip(charged).find(|(_, event)| matches!(event, TraceEvent::CpuChecked { opcode: value } if *value == opcode)).unwrap().0;
        let action = trace.0.iter().enumerate().skip(cpu).find(|(_, event)| matches!(event, TraceEvent::ActionCompleted { opcode: value } if *value == opcode)).unwrap().0;
        assert!(fetched < stack_checked && stack_checked < charged && charged < cpu && cpu < action);
    }
    drop(repository); drop(session); drop(manager); fs::remove_dir_all(path).unwrap();
}

#[test]
fn timeout_happens_after_charge_and_fault_exhausts_energy() {
    let (path, manager) = manager("timeout");
    let session = manager.build_session().unwrap();
    let mut repository = Repository::from_session(&session);
    let registry = OperationRegistry::integration().unwrap();
    let rules = TvmRules::default();
    let interpreter = Interpreter::new(&registry, &rules);
    let mut program = Program::new(vec![0x60, 1]);
    let mut stack = Stack1024::default();
    let mut memory = Memory::default();
    let mut meter = EnergyMeter::new(20).unwrap();
    let mut clock = ManualMonotonicClock::default(); clock.advance(Duration::from_nanos(2));
    let mut limiter = DeadlineLimiter::new(clock, Duration::from_nanos(1));
    let mut trace = Events::default();
    let outcome = interpreter.run(&frame(), &mut program, &mut stack, &mut memory, &mut repository, &mut meter, &mut limiter, &mut trace);
    assert_eq!(outcome.contract_result, ContractResult::OutOfTime);
    assert_eq!(outcome.energy_used, 20);
    assert!(trace.0.iter().any(|event| matches!(event, TraceEvent::EnergyCharged { amount: 3, .. })));
    drop(repository); drop(session); drop(manager); fs::remove_dir_all(path).unwrap();
}

#[test]
fn result_numbers_dynamic_penalty_and_call_forwarding_are_exact() {
    assert_eq!(ContractResult::StackTooLarge.protobuf(), ("STACK_TOO_LARGE", 7));
    assert_eq!(ContractResult::JvmStackOverflow.protobuf(), ("JVM_STACK_OVER_FLOW", 12));
    assert_eq!(ContractResult::from_runtime_number(9), None);
    assert_eq!(apply_dynamic_energy(100_000, 2_500).unwrap(), (125_000, 25_000));
    assert_eq!(forwarded_call_energy(64_000, i64::MAX, true).unwrap(), 63_000);
    assert!(VmFault::TransferFailed.spends_remaining() == false);
}

#[test]
fn full_registry_has_exact_shape_and_activation_coverage() {
    let registry = OperationRegistry::integration().unwrap();
    assert_eq!(registry.registered_count(), 165);
    assert_eq!(registry.undefined_count(), 91);
    registry.validate_activation(&TvmRules::default()).unwrap();
    let all = TvmRules {
        multi_sign: true, transfer_trc10: true, constantinople: true, solidity_059: true,
        istanbul: true, freeze: true, vote: true, london: true, compatible_evm: true,
        higher_cpu_memory: true, freeze_v2: true, optimized_chain_id: true, dynamic_energy: true,
        shanghai: true, energy_adjustment: true, strict_math: true, cancun: true,
        disable_java_math: true, blob: true, selfdestruct_restriction: true, osaka: true,
        harden_resource: true, shielded_trc20: true, energy_limit_hardfork: true,
        ..TvmRules::default()
    };
    registry.validate_activation(&all).unwrap();
    assert_eq!(registry.resolve(&all).iter().flatten().count(), 165);
}

fn push_address(code:&mut Vec<u8>,value:TronAddress21){code.push(0x73);code.extend_from_slice(&value.as_bytes()[1..]);}
fn call_program(destination:TronAddress21,out_size:u8)->Vec<u8>{let mut code=vec![0x60,out_size,0x60,0,0x60,0,0x60,0,0x60,0];push_address(&mut code,destination);code.extend_from_slice(&[0x61,0xff,0xff,0xf1,0x00]);code}
fn value_call_program(destination:TronAddress21,value:u8)->Vec<u8>{let mut code=vec![0x60,0,0x60,0,0x60,0,0x60,0,0x60,value];push_address(&mut code,destination);code.extend_from_slice(&[0x61,0xff,0xff,0xf1,0x00]);code}
fn max_value_call_program(destination:TronAddress21)->Vec<u8>{let mut code=vec![0x60,0,0x60,0,0x60,0,0x60,0,0x7f];code.extend_from_slice(&[0xff;32]);push_address(&mut code,destination);code.extend_from_slice(&[0x61,0xff,0xff,0xf1,0x00]);code}
fn token_call_program(destination:TronAddress21,value:u8,token_id:u8)->Vec<u8>{let mut code=vec![0x60,0,0x60,0,0x60,0,0x60,0,0x60,token_id,0x60,value];push_address(&mut code,destination);code.extend_from_slice(&[0x61,0xff,0xff,0xd0,0x00]);code}

fn run_program(frame:&FrameContext,code:Vec<u8>,repository:&mut Repository<'_>,rules:&TvmRules)->(tron_tvm::ExecutionOutcome,Stack1024,EnergyMeter){let registry=OperationRegistry::integration().unwrap();let interpreter=Interpreter::new(&registry,rules);let mut program=Program::new(code);let mut stack=Stack1024::default();let mut memory=Memory::default();let mut meter=EnergyMeter::new(200_000).unwrap();let mut limiter=Unlimited;let mut trace=Events::default();let outcome=interpreter.run(frame,&mut program,&mut stack,&mut memory,repository,&mut meter,&mut limiter,&mut trace);(outcome,stack,meter)}

#[test]
fn call_preexecution_failures_refund_reserve_and_do_not_mutate_lineage(){
    let(path,manager)=manager("call-precheck");let session=manager.build_session().unwrap();let caller=frame().context_address;let destination=address(9);session.store(StoreKind::Account).put(caller.as_bytes(),&Account{address:caller.as_bytes().to_vec(),balance:7,..Default::default()}.encode_to_vec()).unwrap();session.store(StoreKind::Account).put(destination.as_bytes(),&Account{address:destination.as_bytes().to_vec(),balance:0,..Default::default()}.encode_to_vec()).unwrap();let mut repository=Repository::from_session(&session);
    let mut depth_frame=frame();depth_frame.depth=64;let(outcome,stack,meter)=run_program(&depth_frame,call_program(destination,0),&mut repository,&TvmRules::default());assert_eq!(stack.peek(0).unwrap(),Word::ZERO);assert!(outcome.internal_transactions.is_empty());assert_eq!(outcome.energy_used,61);assert_eq!(meter.remaining(),199_939);
    let(outcome,stack,meter)=run_program(&frame(),value_call_program(destination,8),&mut repository,&TvmRules::default());assert_eq!(stack.peek(0).unwrap(),Word::ZERO);assert!(outcome.internal_transactions.is_empty());assert_eq!(outcome.energy_used,9_061);assert_eq!(meter.remaining(),190_939);assert_eq!(repository.balance(&caller).unwrap(),7);assert_eq!(repository.balance(&destination).unwrap(),0);
    let(outcome,stack,meter)=run_program(&frame(),max_value_call_program(destination),&mut repository,&TvmRules::default());assert_eq!(stack.peek(0).unwrap(),Word::ZERO);assert!(outcome.internal_transactions.is_empty());assert_eq!(outcome.energy_used,9_061);assert_eq!(meter.remaining(),190_939);assert_eq!(repository.balance(&caller).unwrap(),7);assert_eq!(repository.balance(&destination).unwrap(),0);
    let mut token_owner=repository.account(&caller).unwrap().unwrap();token_owner.asset_v2.insert("1".into(),3);repository.put_account(&token_owner);let rules=TvmRules{transfer_trc10:true,..TvmRules::default()};let(outcome,stack,meter)=run_program(&frame(),token_call_program(destination,4,1),&mut repository,&rules);assert_eq!(stack.peek(0).unwrap(),Word::ZERO);assert!(outcome.internal_transactions.is_empty());assert_eq!(outcome.energy_used,9_064);assert_eq!(meter.remaining(),190_936);assert_eq!(repository.token_balance(&caller,"1").unwrap(),3);assert_eq!(repository.token_balance(&destination,"1").unwrap(),0);
    let returning=address(10);repository.put_code(returning,vec![0x60,0x2a,0x60,0,0x53,0x60,1,0x60,0,0xf3]);let mut code=call_program(returning,0);code.pop();code.push(0x50);let mut failed=value_call_program(destination,8);failed.pop();code.extend(failed);code.extend_from_slice(&[0x50,0x3d,0x00]);let(outcome,stack,_)=run_program(&frame(),code,&mut repository,&TvmRules::default());assert_eq!(stack.peek(0).unwrap(),Word::ZERO);assert_eq!(outcome.return_data,Vec::<u8>::new());assert_eq!(outcome.internal_transactions.len(),1);assert_eq!(outcome.internal_transactions[0].transfer_to,Some(returning));
    let mut code=value_call_program(destination,8);code.pop();code.extend_from_slice(&[0x50,0x60,0,0x60,0,0x60,0,0xf0,0x00]);let(outcome,stack,_)=run_program(&frame(),code,&mut repository,&TvmRules::default());let expected=tron_crypto::internal_create_address(&frame().root_txid,0);assert_eq!(stack.peek(0).unwrap().to_tron_address(),expected);assert_eq!(outcome.internal_transactions.len(),1);assert_eq!(outcome.internal_transactions[0].note,b"create");assert_eq!(outcome.internal_transactions[0].nonce,0);assert_eq!(outcome.internal_transactions[0].transfer_to,Some(expected));
    drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
}

#[test]
fn recursive_call_commits_success_and_copies_return_data(){
    let(path,manager)=manager("nested-success");let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);let child=address(9);
    repository.put_code(child,vec![0x60,0x2a,0x60,0,0x52,0x60,32,0x60,0,0xf3]);
    let registry=OperationRegistry::integration().unwrap();let rules=TvmRules::default();let interpreter=Interpreter::new(&registry,&rules);let mut program=Program::new(call_program(child,32));let mut stack=Stack1024::default();let mut memory=Memory::default();let mut meter=EnergyMeter::new(200_000).unwrap();let mut limiter=Unlimited;let mut trace=Events::default();
    let outcome=interpreter.run(&frame(),&mut program,&mut stack,&mut memory,&mut repository,&mut meter,&mut limiter,&mut trace);
    assert_eq!(outcome.contract_result,ContractResult::Success);assert_eq!(stack.peek(0).unwrap(),Word::ONE);assert_eq!(memory.read(0,32).unwrap()[31],0x2a);
    drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
}

#[test]
fn top_level_and_child_revert_revoke_sstore_deltas(){
    let(path,manager)=manager("rollback");let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);let registry=OperationRegistry::integration().unwrap();let rules=TvmRules::default();let interpreter=Interpreter::new(&registry,&rules);let mut limiter=Unlimited;let mut trace=Events::default();
    let mut program=Program::new(vec![0x60,7,0x60,1,0x55,0x60,0,0x60,0,0xfd]);let mut stack=Stack1024::default();let mut memory=Memory::default();let mut meter=EnergyMeter::new(200_000).unwrap();let outcome=interpreter.run(&frame(),&mut program,&mut stack,&mut memory,&mut repository,&mut meter,&mut limiter,&mut trace);assert_eq!(outcome.contract_result,ContractResult::Revert);assert!(outcome.deltas.is_empty());assert_eq!(repository.storage(&frame().context_address,Word::ONE,0,None),None);
    let child=address(8);repository.put_code(child,vec![0x60,9,0x60,2,0x55,0x60,0,0x60,0,0xfd]);let mut program=Program::new(call_program(child,0));let mut stack=Stack1024::default();let mut memory=Memory::default();let mut meter=EnergyMeter::new(200_000).unwrap();let outcome=interpreter.run(&frame(),&mut program,&mut stack,&mut memory,&mut repository,&mut meter,&mut limiter,&mut trace);assert_eq!(outcome.contract_result,ContractResult::Success);assert_eq!(stack.peek(0).unwrap(),Word::ZERO);assert_eq!(repository.storage(&child,Word::from(2u64),0,None),None);
    drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
}

#[test]
fn recursive_create_and_create2_execute_init_code_and_install_runtime() {
    let (path, manager) = manager("recursive-create");
    let session = manager.build_session().unwrap();
    let mut repository = Repository::from_session(&session);
    let registry = OperationRegistry::integration().unwrap();
    let rules = TvmRules { constantinople: true, ..TvmRules::default() };
    let interpreter = Interpreter::new(&registry, &rules);
    let init = [0x60, 0x00, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xf3];
    for (opcode, salt) in [(0xf0, None), (0xf5, Some(0x2au8))] {
        let mut code = vec![0x69];
        code.extend_from_slice(&init);
        code.extend_from_slice(&[0x60, 0x00, 0x52]);
        if let Some(salt) = salt { code.extend_from_slice(&[0x60, salt]); }
        code.extend_from_slice(&[0x60, 10, 0x60, 22, 0x60, 0, opcode, 0x00]);
        let mut program = Program::new(code);
        let mut stack = Stack1024::default();
        let mut memory = Memory::default();
        let mut meter = EnergyMeter::new(500_000).unwrap();
        let mut limiter = Unlimited;
        let mut trace = Events::default();
        let outcome = interpreter.run(&frame(), &mut program, &mut stack, &mut memory, &mut repository, &mut meter, &mut limiter, &mut trace);
        assert_eq!(outcome.contract_result, ContractResult::Success);
        let created = stack.peek(0).unwrap().to_tron_address();
        assert_ne!(created, address(0));
        assert_eq!(repository.code(&created), Some(vec![0x00]));
    }
    drop(repository); drop(session); drop(manager); fs::remove_dir_all(path).unwrap();
}

fn create2_program(init:&[u8],salt:u8,after:&[u8])->Vec<u8>{
    assert!(init.len()<=32);
    let mut code=vec![0x60+u8::try_from(init.len()).unwrap()-1];
    code.extend_from_slice(init);
    code.extend_from_slice(&[0x60,0,0x52,0x60,salt,0x60,u8::try_from(init.len()).unwrap(),0x60,u8::try_from(32-init.len()).unwrap(),0x60,0,0xf5]);
    code.extend_from_slice(after);
    code
}

#[test]
fn create_installs_contract_state_before_init_and_iscontract_observes_it_immediately(){
    let(path,manager)=manager("create-state-visible");let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);
    let init=[0x30,0xd4,0x60,0,0x52,0x60,1,0x60,31,0xf3];
    let(outcome,stack,_)=run_program(&frame(),create2_program(&init,7,&[0xd4,0x00]),&mut repository,&TvmRules{constantinople:true,solidity_059:true,istanbul:true,compatible_evm:true,..Default::default()});
    assert_eq!(outcome.contract_result,ContractResult::Success);assert_eq!(stack.peek(0).unwrap(),Word::ONE);
    let created=tron_crypto::create2_address(&frame().context_address,&Hash32::from_array(Word::from(7u64).to_be_bytes()),&init);
    let account=repository.account(&created).unwrap().unwrap();assert_eq!(account.r#type,AccountType::Contract as i32);
    let contract=repository.contract(&created).unwrap().unwrap();assert_eq!(contract.origin_address,frame().context_address.as_bytes());assert_eq!(contract.contract_address,created.as_bytes());assert_eq!(contract.consume_user_resource_percent,100);assert_eq!(contract.version,frame().contract_version);assert_eq!(contract.trx_hash,frame().root_txid.as_bytes());assert_eq!(contract.code_hash,tron_crypto::keccak256(&[1]));
    assert_eq!(repository.code(&created),Some(vec![1]));drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
}

#[test]
fn empty_runtime_persists_and_second_create2_to_same_address_collides(){
    let(path,manager)=manager("empty-runtime-collision");let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);let init=[0x60,0,0x60,0,0xf3];
    let mut code=create2_program(&init,9,&[0x50]);let second=create2_program(&init,9,&[0x00]);code.extend(second);
    let(outcome,stack,_)=run_program(&frame(),code,&mut repository,&TvmRules{constantinople:true,istanbul:true,..Default::default()});let created=tron_crypto::create2_address(&frame().context_address,&Hash32::from_array(Word::from(9u64).to_be_bytes()),&init);
    assert_eq!(stack.peek(0).unwrap(),Word::ZERO);assert_eq!(repository.code(&created),Some(Vec::new()));assert!(repository.contract(&created).unwrap().is_some());assert_eq!(outcome.internal_transactions.len(),2);assert!(!outcome.internal_transactions[0].rejected);assert!(outcome.internal_transactions[1].rejected);
    drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
}

#[test]
fn create_collision_follows_java_account_contract_fork_matrix(){
    for(case,constantinople,account,contract,code,success)in[("legacy-eoa",false,true,false,false,false),("modern-eoa",true,true,false,false,true),("modern-contract",true,true,true,false,false),("modern-code-only",true,false,false,true,true)]{
        let(path,manager)=manager(case);let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);let init=[0x60,0,0x60,0,0xf3];let created=tron_crypto::create2_address(&frame().context_address,&Hash32::from_array(Word::from(3u64).to_be_bytes()),&init);
        if account{repository.put_account(&Account{address:created.as_bytes().to_vec(),balance:17,acquired_delegated_frozen_balance_for_bandwidth:4,acquired_delegated_frozen_v2_balance_for_bandwidth:5,..Default::default()});}
        if contract{repository.put_contract(SmartContract{contract_address:created.as_bytes().to_vec(),..Default::default()});}if code{repository.put_code(created,vec![0xaa]);}
        let(_,stack,_)=run_program(&frame(),create2_program(&init,3,&[0x00]),&mut repository,&TvmRules{constantinople,istanbul:true,..Default::default()});assert_eq!(!stack.peek(0).unwrap().is_zero(),success,"{case}");
        if success{let a=repository.account(&created).unwrap().unwrap();assert_eq!(a.r#type,AccountType::Contract as i32);if account{assert_eq!(a.balance,17);assert_eq!(a.acquired_delegated_frozen_balance_for_bandwidth,0);assert_eq!(a.acquired_delegated_frozen_v2_balance_for_bandwidth,0);}assert!(repository.contract(&created).unwrap().is_some());assert_eq!(repository.code(&created),Some(Vec::new()));}
        drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn failed_create_init_rolls_back_account_contract_and_code(){
    let(path,manager)=manager("failed-create-rollback");let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);let init=[0xfe];let created=tron_crypto::create2_address(&frame().context_address,&Hash32::from_array(Word::from(4u64).to_be_bytes()),&init);
    let(_,stack,_)=run_program(&frame(),create2_program(&init,4,&[0x00]),&mut repository,&TvmRules{constantinople:true,istanbul:true,..Default::default()});assert_eq!(stack.peek(0).unwrap(),Word::ZERO);assert!(repository.account(&created).unwrap().is_none());assert!(repository.contract(&created).unwrap().is_none());assert!(repository.code(&created).is_none());
    drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
}

#[test]
fn production_rules_load_uses_persisted_version_35_fork_state() {
    const FORK_TIME:i64=1_596_780_000_000;
    for(case,current,timestamp,stats,expected)in[
        ("pre35",34i32,FORK_TIME-1,vec![1;27],false),
        ("pass35-before-publication",34i32,FORK_TIME,{let mut v=vec![1;19];v.extend(vec![0;8]);v},true),
        ("below-70-percent",34i32,FORK_TIME,{let mut v=vec![1;18];v.extend(vec![0;9]);v},false),
        ("current35-without-stats",35i32,FORK_TIME,Vec::new(),false),
    ]{
        let(path,manager)=manager(case);let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);
        repository.put_raw(StoreKind::DynamicProperties,tron_state::dynamic::key("VERSION_NUMBER").unwrap().to_vec(),current.to_be_bytes().to_vec());
        repository.set_dynamic_i64("MAINTENANCE_TIME_INTERVAL",1_000).unwrap();repository.set_dynamic_i64("LATEST_BLOCK_HEADER_TIMESTAMP",timestamp).unwrap();
        repository.put_raw(StoreKind::WitnessSchedule,tron_state::value::ACTIVE_WITNESSES_KEY.to_vec(),vec![0xff;22]);
        if !stats.is_empty(){repository.put_raw(StoreKind::DynamicProperties,b"FORK_VERSION_35".to_vec(),stats)}
        let rules=TvmRules::load(&repository,i64::MAX).unwrap();
        assert_eq!(rules.create2_depth_timeout,expected,"{case}");assert!(!rules.compatible_evm,"{case}");assert!(!rules.osaka,"{case}");
        drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn production_rules_load_rejects_malformed_fork_state_and_preserves_precedence_flags() {
    const FORK_TIME:i64=1_596_780_000_000;
    let(path,manager)=manager("malformed-fork35");let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);
    repository.put_raw(StoreKind::DynamicProperties,tron_state::dynamic::key("VERSION_NUMBER").unwrap().to_vec(),34i32.to_be_bytes().to_vec());repository.set_dynamic_i64("MAINTENANCE_TIME_INTERVAL",1_000).unwrap();repository.set_dynamic_i64("LATEST_BLOCK_HEADER_TIMESTAMP",FORK_TIME).unwrap();
    repository.put_raw(StoreKind::WitnessSchedule,tron_state::value::ACTIVE_WITNESSES_KEY.to_vec(),vec![0xff;22]);
    let mut malformed=vec![1;18];malformed.push(2);malformed.extend(vec![0;8]);repository.put_raw(StoreKind::DynamicProperties,b"FORK_VERSION_35".to_vec(),malformed);
    assert!(!TvmRules::load(&repository,i64::MAX).unwrap().create2_depth_timeout);
    let mut stats=vec![1;19];stats.extend(vec![0;8]);repository.put_raw(StoreKind::DynamicProperties,b"FORK_VERSION_35".to_vec(),stats);repository.set_dynamic_i64("ALLOW_TVM_COMPATIBLE_EVM",1).unwrap();repository.set_dynamic_i64("ALLOW_TVM_OSAKA",1).unwrap();
    let rules=TvmRules::load(&repository,i64::MAX).unwrap();assert!(rules.create2_depth_timeout);assert!(rules.compatible_evm);assert!(rules.osaka);
    drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
}

#[test]
fn create_prechecks_endowment_and_preserves_nonce_and_absent_sender(){
    let(path,manager)=manager("create-precheck");let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);let sender=frame().context_address;
    let code=vec![0x60,0,0x60,0,0x60,1,0xf0,0x50,0x60,0,0x60,0,0x60,0,0xf0,0x00];
    let(outcome,stack,_)=run_program(&frame(),code,&mut repository,&TvmRules::default());let created=tron_crypto::internal_create_address(&frame().root_txid,0);
    assert_eq!(stack.peek(0).unwrap().to_tron_address(),created);assert_eq!(outcome.internal_transactions.len(),1);assert_eq!(outcome.internal_transactions[0].nonce,0);assert!(!outcome.internal_transactions[0].rejected);assert!(repository.account(&sender).unwrap().is_none());let account=repository.account(&created).unwrap().unwrap();assert_eq!(account.account_name,b"CreatedByContract");assert_eq!(account.r#type,AccountType::Contract as i32);
    drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
}

#[test]
fn create2_source_and_ef_deployment_follow_istanbul_and_london(){
    let init=[0x60,0xef,0x60,0,0x53,0x60,1,0x60,0,0xf3];
    for(case,istanbul,london,success)in[("pre-istanbul-pre-london",false,false,true),("istanbul-pre-london",true,false,true),("istanbul-london",true,true,false)]{
        let(path,manager)=manager(case);let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);let rules=TvmRules{constantinople:true,istanbul,london,..Default::default()};let(outcome,stack,_)=run_program(&frame(),create2_program(&init,5,&[0x00]),&mut repository,&rules);let source=if istanbul{frame().context_address}else{frame().caller};let created=tron_crypto::create2_address(&source,&Hash32::from_array(Word::from(5u64).to_be_bytes()),&init);
        assert_eq!(!stack.peek(0).unwrap().is_zero(),success,"{case}");assert_eq!(repository.code(&created),if success{Some(vec![0xef])}else{None},"{case}");assert_eq!(outcome.internal_transactions.len(),1,"{case}");assert_eq!(outcome.internal_transactions[0].rejected,!success,"{case}");
        drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn create_collision_consumes_full_child_allowance(){
    let(path,manager)=manager("create-collision-energy");let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);let init=[0x60,0,0x60,0,0xf3];let created=tron_crypto::create2_address(&frame().context_address,&Hash32::from_array(Word::from(6u64).to_be_bytes()),&init);repository.put_account(&Account{address:created.as_bytes().to_vec(),r#type:AccountType::Contract as i32,..Default::default()});repository.put_contract(SmartContract{contract_address:created.as_bytes().to_vec(),..Default::default()});
    let(outcome,stack,meter)=run_program(&frame(),create2_program(&init,6,&[0x00]),&mut repository,&TvmRules{constantinople:true,istanbul:true,..Default::default()});assert_eq!(stack.peek(0).unwrap(),Word::ZERO);assert!(outcome.internal_transactions[0].rejected);assert_eq!(outcome.energy_used,meter.used());assert!(meter.remaining()<4_000,"remaining {}",meter.remaining());
    drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
}

#[test]
fn create_and_create2_depth_64_follow_java_fork_gates(){
    let init=[0x00];
    for(case,opcode,rules,expected_result,creates,expected_energy)in[
        ("create-always-zero",0xf0,TvmRules{constantinople:true,..Default::default()},ContractResult::Success,false,32_009),
        ("create2-legacy-proceeds",0xf5,TvmRules{constantinople:true,istanbul:true,..Default::default()},ContractResult::Success,true,32_027),
        ("create2-4811-timeout",0xf5,TvmRules{constantinople:true,istanbul:true,create2_depth_timeout:true,..Default::default()},ContractResult::OutOfTime,false,200_000),
        ("create2-compatible-zero",0xf5,TvmRules{constantinople:true,istanbul:true,create2_depth_timeout:true,compatible_evm:true,..Default::default()},ContractResult::Success,false,32_027),
        ("create2-osaka-zero",0xf5,TvmRules{constantinople:true,istanbul:true,create2_depth_timeout:true,osaka:true,..Default::default()},ContractResult::Success,false,32_027),
    ]{
        let(path,manager)=manager(case);let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);let mut depth=frame();depth.depth=64;
        let code=if opcode==0xf0{vec![0x60,0,0x60,0,0x60,0,0xf0,0x00]}else{create2_program(&init,11,&[0x00])};
        let(outcome,stack,meter)=run_program(&depth,code,&mut repository,&rules);assert_eq!(outcome.contract_result,expected_result,"{case}");
        let created=tron_crypto::create2_address(&depth.context_address,&Hash32::from_array(Word::from(11u64).to_be_bytes()),&init);
        if creates{assert_eq!(stack.peek(0).unwrap().to_tron_address(),created,"{case}");assert_eq!(repository.code(&created),Some(Vec::new()),"{case}");assert_eq!(outcome.internal_transactions.len(),1,"{case}");assert_eq!(outcome.internal_transactions[0].nonce,0,"{case}");assert!(!outcome.internal_transactions[0].rejected,"{case}");}
        else{if expected_result==ContractResult::Success{assert_eq!(stack.peek(0).unwrap(),Word::ZERO,"{case}");}assert!(repository.account(&created).unwrap().is_none(),"{case}");assert!(outcome.internal_transactions.is_empty(),"{case}");}
        assert_eq!(meter.used(),expected_energy,"{case}");assert_eq!(meter.remaining(),200_000-expected_energy,"{case}");
        drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn call_reserve_is_refunded_once_and_emits_java_internal_transaction(){
    let(path,manager)=manager("call-energy-internal");let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);let child=address(9);repository.put_code(child,vec![0x00]);
    let registry=OperationRegistry::integration().unwrap();let rules=TvmRules{energy_adjustment:true,..Default::default()};let interpreter=Interpreter::new(&registry,&rules);let mut program=Program::new(call_program(child,0));let mut stack=Stack1024::default();let mut memory=Memory::default();let mut meter=EnergyMeter::new(200_000).unwrap();let mut limiter=Unlimited;let mut trace=Events::default();
    let outcome=interpreter.run(&frame(),&mut program,&mut stack,&mut memory,&mut repository,&mut meter,&mut limiter,&mut trace);
    assert_eq!(outcome.energy_used,61);assert_eq!(outcome.internal_transactions.len(),1);let tx=&outcome.internal_transactions[0];assert_eq!(tx.parent_hash,frame().root_txid.hash());assert_eq!(tx.sender,frame().context_address);assert_eq!(tx.transfer_to,Some(child));assert_eq!(tx.note,b"call");assert_eq!(tx.depth,0);assert_eq!(tx.nonce,0);assert!(!tx.rejected);assert_eq!(tx.hash,Hash32::from_array(tron_crypto::keccak256(&[tx.encoded.as_slice(),&0i64.to_be_bytes()].concat())));
    drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
}

#[test]
fn selfdestruct_transfers_deletes_and_parent_fault_rolls_everything_back(){
    let(path,manager)=manager("selfdestruct");let session=manager.build_session().unwrap();let owner=frame().context_address;let beneficiary=address(8);session.store(StoreKind::Account).put(owner.as_bytes(),&Account{address:owner.as_bytes().to_vec(),balance:77,..Default::default()}.encode_to_vec()).unwrap();let mut repository=Repository::from_session(&session);
    let registry=OperationRegistry::integration().unwrap();let rules=TvmRules::default();let interpreter=Interpreter::new(&registry,&rules);let mut code=Vec::new();push_address(&mut code,beneficiary);code.push(0xff);let mut program=Program::new(code);let mut stack=Stack1024::default();let mut memory=Memory::default();let mut meter=EnergyMeter::new(100_000).unwrap();let mut limiter=Unlimited;let mut trace=Events::default();
    let outcome=interpreter.run(&frame(),&mut program,&mut stack,&mut memory,&mut repository,&mut meter,&mut limiter,&mut trace);assert_eq!(outcome.deleted_accounts,vec![owner]);assert_eq!(repository.account(&owner).unwrap(),None);assert_eq!(repository.balance(&beneficiary).unwrap(),77);assert_eq!(outcome.internal_transactions[0].note,b"suicide");assert_eq!(outcome.internal_transactions[0].value,Word::from(77u64));
    repository.set_balance(&owner,77).unwrap();repository.set_balance(&beneficiary,0).unwrap();repository.put_code(owner,{let mut child=Vec::new();push_address(&mut child,beneficiary);child.push(0xff);child});let mut parent=call_program(owner,0);let last=parent.len()-1;parent[last]=0xfe;let mut program=Program::new(parent);let mut stack=Stack1024::default();let mut memory=Memory::default();let mut meter=EnergyMeter::new(200_000).unwrap();let outcome=interpreter.run(&frame(),&mut program,&mut stack,&mut memory,&mut repository,&mut meter,&mut limiter,&mut trace);assert_eq!(outcome.contract_result,ContractResult::IllegalOperation);assert_eq!(repository.balance(&owner).unwrap(),77);assert_eq!(repository.balance(&beneficiary).unwrap(),0);assert!(outcome.internal_transactions.iter().all(|tx|tx.rejected));
    drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
}
