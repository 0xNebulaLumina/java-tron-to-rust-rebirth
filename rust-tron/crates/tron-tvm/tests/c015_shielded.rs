use std::{fs, path::{Path,PathBuf}, sync::Arc, time::{SystemTime,UNIX_EPOCH}};
use tron_primitives::{Address20,Hash32,TransactionId,TronAddress21};
use tron_shielded::{BindingSigParams,OutputProofParams,ShieldedRawAdapter,compute_cm,external_key_path,ka_derive_public,load_tron_parameters,tree_uncommitted,zip32_xsk_master};
use tron_state::{SessionManager,StateStore,StoreKind};
use tron_storage::{OpenRequirements,StorageIdentity,StorageManager};
use tron_tvm::{execute_merkle_hash,get_trigger_input_mint,ContractResult,EnergyMeter,FrameContext,Interpreter,Memory,NoTrace,OperationRegistry,PrecompileRegistry,Program,Repository,ShieldedPrecompile,ShieldedPrecompiles,Stack1024,TvmRules,Unlimited,Word,MERKLE_HASH_ENERGY,VERIFY_BURN_ENERGY,VERIFY_MINT_ENERGY,VERIFY_TRANSFER_ENERGY};

#[test]
fn shielded_activation_addresses_and_energy_match_java() {
    assert_eq!(ShieldedPrecompiles::resolve(0x0100_0001,false),None);
    assert_eq!(ShieldedPrecompiles::resolve(0x0100_0001,true),Some(ShieldedPrecompile::VerifyMint));
    assert_eq!(ShieldedPrecompiles::resolve(0x0100_0002,true),Some(ShieldedPrecompile::VerifyTransfer));
    assert_eq!(ShieldedPrecompiles::resolve(0x0100_0003,true),Some(ShieldedPrecompile::VerifyBurn));
    assert_eq!(ShieldedPrecompiles::resolve(0x0100_0004,true),Some(ShieldedPrecompile::MerkleHash));
    assert_eq!((VERIFY_MINT_ENERGY,VERIFY_TRANSFER_ENERGY,VERIFY_BURN_ENERGY,MERKLE_HASH_ENERGY),(150_000,200_000,150_000,500));
}

#[test]
fn merkle_hash_has_exact_abi_and_failure_channel() {
    let mut input=vec![0u8;96];
    input[63]=1; input[95]=1;
    let result=execute_merkle_hash(&input);
    assert!(result.success);
    assert_eq!(result.output,tron_shielded::merkle_hash(0,{let mut x=[0;32];x[31]=1;x},{let mut x=[0;32];x[31]=1;x}).unwrap());
    assert_eq!(execute_merkle_hash(&input[..95]),tron_tvm::ShieldedOutput{success:false,output:vec![]});
    let mut extended=input.clone();extended.push(0);assert!(!execute_merkle_hash(&extended).success);
    input[31]=32;
    assert!(!execute_merkle_hash(&input).success);
}

#[test]
fn authentic_parameter_backed_mint_proof_executes() {
    let root=Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");
    let parameters=load_tron_parameters(root.join("sapling-spend.params"),root.join("sapling-output.params")).unwrap();
    let adapter=ShieldedRawAdapter::new(Arc::clone(&parameters));let ctx=adapter.proving_ctx_init().unwrap();
    let keys=external_key_path(&zip32_xsk_master(b"C015 deterministic mint proof fixture")).unwrap();let pkd:[u8;32]=keys.payment_address[11..].try_into().unwrap();
    let mut scalar=[0u8;32];scalar[0]=1;let cm=compute_cm(keys.diversifier,pkd,7,scalar).unwrap();let epk=ka_derive_public(keys.diversifier,scalar).unwrap();
    let mut proof=OutputProofParams{ctx,esk:scalar.to_vec(),d:keys.diversifier.to_vec(),pk_d:pkd.to_vec(),r:scalar.to_vec(),value:7,cv:vec![0;32],zkproof:vec![0;192]};adapter.output_proof(&mut proof).unwrap();
    let sighash=[0x5a;32];let mut binding=BindingSigParams{ctx,value_balance:-7,sighash:sighash.to_vec(),result:vec![0;64]};adapter.binding_sig(&mut binding).unwrap();adapter.proving_ctx_free(ctx).unwrap();
    let mut frontier=[[0u8;32];33];frontier[0]=tree_uncommitted();let input=get_trigger_input_mint(cm,proof.cv.try_into().unwrap(),epk,proof.zkproof.try_into().unwrap(),binding.result.try_into().unwrap(),7,sighash,frontier,0);
    let result=ShieldedPrecompiles::new(parameters).execute(ShieldedPrecompile::VerifyMint,&input);assert!(result.success);assert_eq!(result.output.len(),96);assert_eq!(result.output[31],1);
}

#[test]
fn mint_frontier_bounds_reject_before_indexing_without_panics() {
    let root=Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");
    let parameters=load_tron_parameters(root.join("sapling-spend.params"),root.join("sapling-output.params")).unwrap();
    let adapter=ShieldedRawAdapter::new(Arc::clone(&parameters));let ctx=adapter.proving_ctx_init().unwrap();
    let keys=external_key_path(&zip32_xsk_master(b"C015 frontier bound proof fixture")).unwrap();let pkd:[u8;32]=keys.payment_address[11..].try_into().unwrap();
    let mut scalar=[0u8;32];scalar[0]=1;let cm=compute_cm(keys.diversifier,pkd,7,scalar).unwrap();let epk=ka_derive_public(keys.diversifier,scalar).unwrap();
    let mut proof=OutputProofParams{ctx,esk:scalar.to_vec(),d:keys.diversifier.to_vec(),pk_d:pkd.to_vec(),r:scalar.to_vec(),value:7,cv:vec![0;32],zkproof:vec![0;192]};adapter.output_proof(&mut proof).unwrap();
    let sighash=[0x7c;32];let mut binding=BindingSigParams{ctx,value_balance:-7,sighash:sighash.to_vec(),result:vec![0;64]};adapter.binding_sig(&mut binding).unwrap();adapter.proving_ctx_free(ctx).unwrap();
    let frontier=[[0u8;32];33];let precompiles=ShieldedPrecompiles::new(parameters);
    let input=get_trigger_input_mint(cm,proof.cv.try_into().unwrap(),epk,proof.zkproof.try_into().unwrap(),binding.result.try_into().unwrap(),7,sighash,frontier,(1u64<<32)-1);
    let boundary=precompiles.execute(ShieldedPrecompile::VerifyMint,&input);assert!(boundary.success);assert_eq!(boundary.output[31],1);assert_eq!(boundary.output.len(),1120);assert_eq!(boundary.output[63],32);
    for leaf_count in [1u64<<32,u64::MAX] { let mut invalid=input.clone();invalid[1496..1504].copy_from_slice(&leaf_count.to_be_bytes());let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||precompiles.execute(ShieldedPrecompile::VerifyMint,&invalid))).unwrap();assert_eq!(result.output,vec![0;32]); }
    let mut malformed_word=input.clone();malformed_word[1472]=1;let malformed=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||precompiles.execute(ShieldedPrecompile::VerifyMint,&malformed_word))).unwrap();assert_eq!(malformed.output,vec![0;32]);
    for malformed_frontier in [&input[..1472],&input[..1503]] { let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||precompiles.execute(ShieldedPrecompile::VerifyMint,malformed_frontier))).unwrap();assert_eq!(result.output,vec![0;32]); }
}
#[test]
fn mint_trigger_seam_is_exact_1504_byte_abi() {
    let mut cm=[0u8;32];cm[0]=1;let mut proof=[0u8;192];proof[191]=2;let mut frontier=[[0u8;32];33];frontier[32][31]=3;
    let input=get_trigger_input_mint(cm,[4;32],[5;32],proof,[6;64],7,[8;32],frontier,9);
    assert_eq!(input.len(),1504);assert_eq!(&input[..32],&cm);assert_eq!(input[287],2);assert_eq!(&input[376..384],&7u64.to_be_bytes());assert_eq!(input[1471],3);assert_eq!(&input[1496..1504],&9u64.to_be_bytes());
}

fn manager(name:&str)->(PathBuf,SessionManager){let nonce=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();let path=std::env::temp_dir().join(format!("c015-shielded-{name}-{nonce}"));let requirements=OpenRequirements{identity:StorageIdentity{network:"c015".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]};let root=StateStore::new(StorageManager::new(requirements).open_store(&path).unwrap());(path,SessionManager::new(root))}
fn address(value:u32)->TronAddress21{let mut raw=[0u8;20];raw[16..].copy_from_slice(&value.to_be_bytes());TronAddress21::new(0x41,Address20::from_array(raw))}
fn frame(input:Vec<u8>)->FrameContext{FrameContext{code_address:address(0x7777),context_address:address(0x7777),origin:address(0x8888),caller:address(0x9999),input,call_value:Word::ZERO,token_value:Word::ZERO,token_id:Word::ZERO,root_txid:TransactionId::new(Hash32::from_array([7;32])),contract_version:0,depth:0,is_static:false}}
fn load_rules(repository:&mut Repository<'_>,enabled:bool)->TvmRules{repository.set_dynamic_i64("MAINTENANCE_TIME_INTERVAL",21_600_000).unwrap();repository.set_dynamic_i64("LATEST_BLOCK_HEADER_TIMESTAMP",0).unwrap();repository.set_dynamic_i64("ALLOW_SHIELDED_TRC20_TRANSACTION",i64::from(enabled)).unwrap();TvmRules::load(repository,i64::MAX).unwrap()}
fn call_code(destination:u32,input_len:u16,output_len:u8)->Vec<u8>{let mut code=vec![0x61,(input_len>>8)as u8,input_len as u8,0x60,0,0x60,0,0x37,0x60,output_len,0x60,0,0x61,(input_len>>8)as u8,input_len as u8,0x60,0,0x60,0,0x73];code.extend_from_slice(&address(destination).as_bytes()[1..]);code.extend_from_slice(&[0x62,0x03,0x0d,0x40,0xf1,0x00]);code}

#[test]
fn canonical_activation_and_interpreter_registry_execute_actual_mint(){
    let root=Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");
    let parameters=load_tron_parameters(root.join("sapling-spend.params"),root.join("sapling-output.params")).unwrap();
    let adapter=ShieldedRawAdapter::new(Arc::clone(&parameters));let ctx=adapter.proving_ctx_init().unwrap();
    let keys=external_key_path(&zip32_xsk_master(b"C015 interpreter mint proof fixture")).unwrap();let pkd:[u8;32]=keys.payment_address[11..].try_into().unwrap();let mut scalar=[0u8;32];scalar[0]=1;
    let cm=compute_cm(keys.diversifier,pkd,7,scalar).unwrap();let epk=ka_derive_public(keys.diversifier,scalar).unwrap();let mut proof=OutputProofParams{ctx,esk:scalar.to_vec(),d:keys.diversifier.to_vec(),pk_d:pkd.to_vec(),r:scalar.to_vec(),value:7,cv:vec![0;32],zkproof:vec![0;192]};adapter.output_proof(&mut proof).unwrap();let sighash=[0x6b;32];let mut binding=BindingSigParams{ctx,value_balance:-7,sighash:sighash.to_vec(),result:vec![0;64]};adapter.binding_sig(&mut binding).unwrap();adapter.proving_ctx_free(ctx).unwrap();let mut frontier=[[0u8;32];33];frontier[0]=tree_uncommitted();let input=get_trigger_input_mint(cm,proof.cv.try_into().unwrap(),epk,proof.zkproof.try_into().unwrap(),binding.result.try_into().unwrap(),7,sighash,frontier,0);
    let(path,manager)=manager("interpreter");let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);let rules=load_rules(&mut repository,true);assert!(rules.shielded_trc20);
    let registry=PrecompileRegistry::with_shielded_parameters(Arc::clone(&parameters));assert!(registry.contract(&address(0x0100_0001),&rules).is_some());let mut direct_meter=EnergyMeter::new(VERIFY_MINT_ENERGY as i64).unwrap();let direct=registry.dispatch(&address(0x0100_0001),&input,&rules,&mut repository,&mut direct_meter).unwrap();assert!(direct.success);assert_eq!(direct.energy,VERIFY_MINT_ENERGY as i64);assert_eq!(direct.output.len(),96);assert_eq!(direct.output[31],1);assert_eq!(direct.output[63],0);assert_ne!(&direct.output[64..96],&[0u8;32]);
    let operations=OperationRegistry::integration().unwrap();let interpreter=Interpreter::new(&operations,&rules).with_shielded_parameters(parameters);let mut program=Program::new(call_code(0x0100_0001,input.len() as u16,96));let mut stack=Stack1024::default();let mut memory=Memory::default();let mut meter=EnergyMeter::new(400_000).unwrap();let mut limiter=Unlimited;let mut trace=NoTrace;let outcome=interpreter.run(&frame(input),&mut program,&mut stack,&mut memory,&mut repository,&mut meter,&mut limiter,&mut trace);assert_eq!(outcome.contract_result,ContractResult::Success);assert_eq!(stack.peek(0).unwrap(),Word::ONE);assert_eq!(memory.read(0,96).unwrap(),direct.output);assert!(outcome.energy_used>=VERIFY_MINT_ENERGY as i64);assert_eq!(outcome.deltas.iter().filter(|d|d.store==StoreKind::Account).count(),2);assert!(!outcome.deltas.iter().any(|d|matches!(d.store,StoreKind::Nullifier|StoreKind::IncrementalMerkleTree)));
    drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
}

#[test]
fn disabled_address_falls_back_and_enabled_missing_parameters_fails_and_rolls_back(){
    let(path,manager)=manager("activation");let session=manager.build_session().unwrap();let mut repository=Repository::from_session(&session);let disabled=load_rules(&mut repository,false);let registry=PrecompileRegistry::new();assert!(registry.contract(&address(0x0100_0001),&disabled).is_none());
    let operations=OperationRegistry::integration().unwrap();let interpreter=Interpreter::new(&operations,&disabled);let mut program=Program::new(call_code(0x0100_0001,0,0));let mut stack=Stack1024::default();let mut memory=Memory::default();let mut meter=EnergyMeter::new(400_000).unwrap();let mut limiter=Unlimited;let mut trace=NoTrace;let outcome=interpreter.run(&frame(Vec::new()),&mut program,&mut stack,&mut memory,&mut repository,&mut meter,&mut limiter,&mut trace);assert_eq!(outcome.contract_result,ContractResult::Success);assert_eq!(stack.peek(0).unwrap(),Word::ONE);
    let enabled=load_rules(&mut repository,true);let interpreter=Interpreter::new(&operations,&enabled);let mut program=Program::new(call_code(0x0100_0001,0,0));let mut stack=Stack1024::default();let mut memory=Memory::default();let mut meter=EnergyMeter::new(400_000).unwrap();let before=repository.deltas();let outcome=interpreter.run(&frame(Vec::new()),&mut program,&mut stack,&mut memory,&mut repository,&mut meter,&mut limiter,&mut trace);assert_eq!(outcome.contract_result,ContractResult::Success);assert_eq!(stack.peek(0).unwrap(),Word::ZERO);assert_eq!(repository.deltas(),before);assert!(outcome.energy_used>=VERIFY_MINT_ENERGY as i64);
    drop(repository);drop(session);drop(manager);fs::remove_dir_all(path).unwrap();
}
