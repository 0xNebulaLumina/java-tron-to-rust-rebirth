use std::{fs, path::PathBuf, sync::{Arc, LazyLock}, time::{SystemTime, UNIX_EPOCH}};
use prost::Message;
use tron_crypto::{derive_address, top_level_contract_address, CryptoEngine, PrivateKey};
use tron_execution::*;
use tron_primitives::TronAddress21;
use tron_protocol::{google::protobuf::Any, protocol::{account::Frozen, transaction::{contract::ContractType, Contract, Raw}, Account, AccountCreateContract, AccountType, AssetIssueContract, CreateSmartContract, Permission, SmartContract, Transaction, TransferAssetContract, TransferContract, TriggerSmartContract}};
use tron_state::{dynamic, SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};
use tron_tvm::{ContractResult, Repository, Word};

fn manager(name: &str) -> (PathBuf, SessionManager) { let p=std::env::temp_dir().join(format!("c016-pipeline-{name}-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));let r=OpenRequirements{identity:StorageIdentity{network:"c016".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]};(p.clone(),SessionManager::new(StateStore::new(StorageManager::new(r).open_store(&p).unwrap()))) }
fn cache() -> TransactionCache { TransactionCache::new(CacheConfig{maximum_entries:8,ttl_millis:100,bloom_blocks:8,bloom_bits:256}).unwrap() }
fn any<M: Message>(name: &str, value: &M) -> Any { Any{type_url:format!("type.googleapis.com/{name}"),value:value.encode_to_vec()} }
fn address(fill: u8) -> Vec<u8> { let mut value=vec![fill;21];value[0]=0x41;value }
fn sign(contract: Contract, key: &PrivateKey) -> RawWireTransaction { let raw=Raw{ref_block_bytes:vec![0xab,0xcd],ref_block_hash:vec![8,9,10,11,12,13,14,15],expiration:1_000,contract:vec![contract],timestamp:100,fee_limit:100_000_000,..Default::default()};let mut tx=Transaction{raw_data:Some(raw),..Default::default()};let unsigned=RawWireTransaction::decode(tx.encode_to_vec()).unwrap();tx.signature.push(key.sign_prehash(unsigned.transaction_id(CryptoEngine::Secp256k1).as_bytes()).unwrap().to_wire().to_vec());RawWireTransaction::decode(tx.encode_to_vec()).unwrap() }
fn sign_with_fee(contract:Contract,key:&PrivateKey,fee_limit:i64)->RawWireTransaction{let raw=Raw{ref_block_bytes:vec![0xab,0xcd],ref_block_hash:vec![8,9,10,11,12,13,14,15],expiration:1_000,contract:vec![contract],timestamp:100,fee_limit,..Default::default()};let mut tx=Transaction{raw_data:Some(raw),..Default::default()};let unsigned=RawWireTransaction::decode(tx.encode_to_vec()).unwrap();tx.signature.push(key.sign_prehash(unsigned.transaction_id(CryptoEngine::Secp256k1).as_bytes()).unwrap().to_wire().to_vec());RawWireTransaction::decode(tx.encode_to_vec()).unwrap()}
fn context(expected: Option<ContractResult>) -> ProcessContext { ProcessContext{origin:AdmissionOrigin::Network,clock:AdmissionClock{head_block_time:500,next_block_slot_time:600,now:1,block_number:9,head_slot:9},expected_result:expected,block_timestamp:700} }
fn runtime_config() -> ExecutionRuntimeConfig {
    static PARAMETERS: LazyLock<Arc<tron_shielded::TronParameters>> = LazyLock::new(|| {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");
        tron_shielded::load_tron_parameters(root.join("sapling-spend.params"), root.join("sapling-output.params")).unwrap()
    });
    ExecutionRuntimeConfig { actuator_registry: Arc::new(ActuatorRegistry::empty()), operation_registry: Arc::new(tron_tvm::OperationRegistry::integration().unwrap()), shielded_parameters: Arc::clone(&PARAMETERS), execution_config: ExecutionConfig::default() }
}
fn processor(manager: SessionManager) -> TransactionProcessor { TransactionProcessor::new(manager, cache(), StateTransactionPipeline::new(Default::default(), runtime_config())) }
fn seed(manager: &SessionManager, owner: &[u8], balance: i64, permission: Option<Permission>) { let mut account=Account{address:owner.to_vec(),balance,..Default::default()};account.owner_permission=permission;account.account_resource.get_or_insert_default().frozen_balance_for_energy=Some(Frozen{frozen_balance:1_000_000,expire_time:i64::MAX});manager.durable_store(StoreKind::Account).put(owner,&account.encode_to_vec()).unwrap();manager.durable_store(StoreKind::RecentBlock).put(&[0xab,0xcd],&[8,9,10,11,12,13,14,15]).unwrap();for(name,value)in[("TOTAL_NET_LIMIT",43_200_000_000_i64),("TOTAL_NET_WEIGHT",0),("FREE_NET_LIMIT",5_000),("PUBLIC_NET_LIMIT",57_600_000_000),("PUBLIC_NET_USAGE",0),("PUBLIC_NET_TIME",0),("TRANSACTION_FEE",1_000),("TOTAL_TRANSACTION_COST",0),("CREATE_ACCOUNT_FEE",100_000),("CREATE_NEW_ACCOUNT_BANDWIDTH_RATE",1),("MAX_CREATE_ACCOUNT_TX_SIZE",1_000),("MULTI_SIGN_FEE",1_000_000),("MEMO_FEE",0),("UNFREEZE_DELAY_DAYS",0),("ALLOW_CANCEL_ALL_UNFREEZE_V2",0),("ALLOW_HARDEN_RESOURCE_CALCULATION",0),("TOTAL_ENERGY_CURRENT_LIMIT",1_000_000),("TOTAL_ENERGY_WEIGHT",1),("ENERGY_FEE",0),("ALLOW_TVM_CONSTANTINOPLE",1),("ALLOW_TRANSACTION_FEE_POOL",0),("TRANSACTION_FEE_POOL",0),("ALLOW_BLACKHOLE_OPTIMIZATION",1),("BURN_TRX_AMOUNT",0),("ALLOW_ADAPTIVE_ENERGY",0),("BLOCK_ENERGY_USAGE",0),("MAINTENANCE_TIME_INTERVAL",21_600_000),("LATEST_BLOCK_HEADER_TIMESTAMP",0),("LATEST_BLOCK_HEADER_NUMBER",9)]{manager.durable_store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(),&value.to_be_bytes()).unwrap();}let blackhole=address(0x41);manager.durable_store(StoreKind::Account).put(&blackhole,&Account{address:blackhole.clone(),..Default::default()}.encode_to_vec()).unwrap(); }
fn set_long(manager: &SessionManager, name: &str, value: i64) { manager.durable_store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(), &value.to_be_bytes()).unwrap(); }

fn remove_vm_energy_dynamics(manager: &SessionManager) {
    for name in ["MAX_FEE_LIMIT", "ENERGY_FEE", "ALLOW_TVM_CONSTANTINOPLE", "ALLOW_ADAPTIVE_ENERGY", "TOTAL_ENERGY_CURRENT_LIMIT", "TOTAL_ENERGY_WEIGHT"] {
        manager.durable_store(StoreKind::DynamicProperties).delete(dynamic::key(name).unwrap()).unwrap();
    }
}

fn assert_no_energy_billing(manager: &SessionManager, owner: &[u8], output: &ProcessOutput) {
    let receipt = output.info.receipt.as_ref().unwrap();
    assert_eq!((receipt.energy_usage_total, receipt.energy_usage, receipt.origin_energy_usage, receipt.energy_fee), (0, 0, 0, 0));
    assert!(receipt.net_usage > 0 || receipt.net_fee > 0);
    let view = manager.read_view();
    let account = Account::decode(view.store(StoreKind::Account).get(owner).unwrap().as_slice()).unwrap();
    let resource = account.account_resource.as_ref().unwrap();
    assert_eq!((resource.energy_usage, resource.latest_consume_time_for_energy, resource.energy_window_size, resource.energy_window_optimized), (0, 0, 0, false));
    let block_energy = i64::from_be_bytes(view.store(StoreKind::DynamicProperties).get(dynamic::key("BLOCK_ENERGY_USAGE").unwrap()).unwrap().try_into().unwrap());
    assert_eq!(block_energy, 17);
}

#[test]
fn non_vm_actuators_ignore_vm_energy_policy_and_preserve_energy_state() {
    for case in ["transfer", "account", "asset"] {
        let (path, manager) = manager(case);
        let key = PrivateKey::from_bytes(CryptoEngine::Secp256k1, &[31; 32]).unwrap();
        let owner = derive_address(&key.public_key()).as_bytes().to_vec();
        let destination = address(match case { "transfer" => 32, "account" => 33, _ => 34 });
        seed(&manager, &owner, 1_000_000, None);
        set_long(&manager, "BLOCK_ENERGY_USAGE", 17);
        set_long(&manager, "TOTAL_CREATE_ACCOUNT_COST", 0);
        set_long(&manager, "CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", 0);
        set_long(&manager, "ALLOW_MULTI_SIGN", 0);
        remove_vm_energy_dynamics(&manager);

        let contract = match case {
            "transfer" => {
                manager.durable_store(StoreKind::Account).put(&destination, &Account { address: destination.clone(), ..Default::default() }.encode_to_vec()).unwrap();
                Contract { r#type: ContractType::TransferContract as i32, parameter: Some(any("protocol.TransferContract", &TransferContract { owner_address: owner.clone(), to_address: destination.clone(), amount: 7 })), ..Default::default() }
            }
            "account" => Contract { r#type: ContractType::AccountCreateContract as i32, parameter: Some(any("protocol.AccountCreateContract", &AccountCreateContract { owner_address: owner.clone(), account_address: destination.clone(), r#type: AccountType::Normal as i32 })), ..Default::default() },
            "asset" => {
                set_long(&manager, "ALLOW_SAME_TOKEN_NAME", 0);
                set_long(&manager, "FORBID_TRANSFER_TO_CONTRACT", 0);
                let mut owner_account = Account::decode(manager.durable_store(StoreKind::Account).get(&owner).unwrap().as_slice()).unwrap();
                owner_account.asset.insert("TOK".into(), 9);
                manager.durable_store(StoreKind::Account).put(&owner, &owner_account.encode_to_vec()).unwrap();
                manager.durable_store(StoreKind::Account).put(&destination, &Account { address: destination.clone(), ..Default::default() }.encode_to_vec()).unwrap();
                manager.durable_store(StoreKind::AssetIssue).put(b"TOK", &AssetIssueContract { name: b"TOK".to_vec(), owner_address: owner.clone(), total_supply: 9, ..Default::default() }.encode_to_vec()).unwrap();
                Contract { r#type: ContractType::TransferAssetContract as i32, parameter: Some(any("protocol.TransferAssetContract", &TransferAssetContract { asset_name: b"TOK".to_vec(), owner_address: owner.clone(), to_address: destination.clone(), amount: 2 })), ..Default::default() }
            }
            _ => unreachable!(),
        };

        let output = processor(manager.clone()).process_transaction(sign_with_fee(contract, &key, i64::MAX), context(None)).unwrap();
        assert_no_energy_billing(&manager, &owner, &output);
        assert!(manager.read_view().store(StoreKind::Account).get(&destination).is_some());
        drop(manager);
        fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn concrete_non_vm_pipeline_changes_state_persists_receipt_and_rejects_exact_duplicate() {
 let(p,m)=manager("non-vm");let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[1;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();let to=address(2);seed(&m,&owner,100,None);m.durable_store(StoreKind::Account).put(&to,&Account{address:to.clone(),balance:4,..Default::default()}.encode_to_vec()).unwrap();
 let contract=Contract{r#type:ContractType::TransferContract as i32,parameter:Some(any("protocol.TransferContract",&TransferContract{owner_address:owner.clone(),to_address:to.clone(),amount:7})),..Default::default()};let tx=sign(contract,&key);let mut processor=processor(m.clone());let out=processor.process_transaction(tx.clone(),context(None)).unwrap();
 let view=m.read_view();let owner_state=Account::decode(view.store(StoreKind::Account).get(&owner).unwrap().as_slice()).unwrap();let to_state=Account::decode(view.store(StoreKind::Account).get(&to).unwrap().as_slice()).unwrap();assert_eq!((owner_state.balance,to_state.balance),(93,11));assert_eq!(out.info.id,out.transaction_id.as_bytes());assert_eq!(out.info.receipt.as_ref().unwrap().net_usage,tx.full_bytes().len() as i64);assert!(view.store(StoreKind::Transaction).get(out.transaction_id.as_bytes()).is_some());assert!(view.store(StoreKind::TransactionHistory).get(out.transaction_id.as_bytes()).is_some());drop(view);assert_eq!(processor.cache.len(),1);assert!(matches!(processor.process_transaction(tx,context(None)),Err(ProcessError::Duplicate(id)) if id==out.transaction_id));let view=m.read_view();let owner_after=Account::decode(view.store(StoreKind::Account).get(&owner).unwrap().as_slice()).unwrap();let to_after=Account::decode(view.store(StoreKind::Account).get(&to).unwrap().as_slice()).unwrap();assert_eq!((owner_after.balance,to_after.balance),(93,11));fs::remove_dir_all(p).unwrap();
}

fn vm_transaction(key: &PrivateKey, owner: &[u8], contract_address: &[u8], permission_id: i32) -> RawWireTransaction { sign(Contract{r#type:ContractType::TriggerSmartContract as i32,permission_id,parameter:Some(any("protocol.TriggerSmartContract",&TriggerSmartContract{owner_address:owner.to_vec(),contract_address:contract_address.to_vec(),..Default::default()})),..Default::default()},key) }
fn seed_runtime(manager: &SessionManager, owner: &[u8], contract: &[u8], code: &[u8]) { manager.durable_store(StoreKind::Account).put(contract,&Account{address:contract.to_vec(),r#type:AccountType::Contract as i32,..Default::default()}.encode_to_vec()).unwrap();manager.durable_store(StoreKind::Contract).put(contract,&SmartContract{origin_address:owner.to_vec(),contract_address:contract.to_vec(),version:0,..Default::default()}.encode_to_vec()).unwrap();manager.durable_store(StoreKind::Code).put(contract,code).unwrap(); }

#[test]
fn successful_vm_flushes_but_revert_and_late_witness_failure_never_flush() {
 for (name,code,expected,persists) in [("success",vec![0x60,7,0x60,1,0x55,0],ContractResult::Success,true),("revert",vec![0x60,9,0x60,1,0x55,0x60,0,0x60,0,0xfd],ContractResult::Revert,false),("witness",vec![0x60,8,0x60,1,0x55,0],ContractResult::Revert,false)] { let(p,m)=manager(name);let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[2;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();let contract=address(9);seed(&m,&owner,100,None);seed_runtime(&m,&owner,&contract,&code);let tx=vm_transaction(&key,&owner,&contract,0);let id=tx.transaction_id(CryptoEngine::Secp256k1);let mut processor=processor(m.clone());let result=processor.process_transaction(tx,context(Some(expected)));if name=="witness"{assert!(matches!(result,Err(ProcessError::Stage{stage:PipelineStage::Witness,..})));assert_eq!(processor.cache.len(),0);assert!(m.read_view().store(StoreKind::Transaction).get(id.as_bytes()).is_none());}else{assert!(result.is_ok());}let session=m.build_session().unwrap();let repository=Repository::from_session(&session);assert_eq!(repository.storage(&TronAddress21::validate_mainnet(&contract).unwrap(),Word::from(1u64),0,None),persists.then_some(Word::from(7u64)));drop(repository);drop(session);fs::remove_dir_all(p).unwrap(); }
}

#[test]
fn transaction_data_cannot_substitute_runtime_code_frame_rules_or_energy() {
 let(p,m)=manager("canonical");let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[5;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();let contract=address(8);seed(&m,&owner,100,None);seed_runtime(&m,&owner,&contract,&[0x60,7,0x60,1,0x55,0]);let mut tx=vm_transaction(&key,&owner,&contract,0);let mut message=tx.message().clone();let trigger=TriggerSmartContract{owner_address:owner.clone(),contract_address:contract.clone(),data:vec![0x60,9,0x60,1,0x55,0],..Default::default()};message.raw_data.as_mut().unwrap().contract[0].parameter=Some(any("protocol.TriggerSmartContract",&trigger));tx=sign(message.raw_data.unwrap().contract.remove(0),&key);let mut processor=processor(m.clone());processor.process_transaction(tx,context(Some(ContractResult::Success))).unwrap();let session=m.build_session().unwrap();let repository=Repository::from_session(&session);assert_eq!(repository.storage(&TronAddress21::validate_mainnet(&contract).unwrap(),Word::from(1u64),0,None),Some(Word::from(7u64)));drop(repository);drop(session);fs::remove_dir_all(p).unwrap();
}

#[test]
fn fee_limit_caps_total_caller_energy() {
 let(p,m)=manager("fee-limit-zero");let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[25;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();let contract=address(25);seed(&m,&owner,1_000_000,None);set_long(&m,"ENERGY_FEE",2);seed_runtime(&m,&owner,&contract,&[0x60,7,0x60,1,0x55,0]);let envelope=Contract{r#type:ContractType::TriggerSmartContract as i32,parameter:Some(any("protocol.TriggerSmartContract",&TriggerSmartContract{owner_address:owner.clone(),contract_address:contract.clone(),..Default::default()})),..Default::default()};let out=processor(m.clone()).process_transaction(sign_with_fee(envelope.clone(),&key,0),context(Some(ContractResult::OutOfEnergy))).unwrap();let receipt=out.info.receipt.unwrap();assert_eq!(receipt.energy_usage_total,0);assert_eq!(receipt.energy_usage,0);assert_eq!(receipt.energy_fee,0);
 set_long(&m,"MAX_FEE_LIMIT",100);for fee in [-1,101]{let tx=sign_with_fee(envelope.clone(),&key,fee);assert!(matches!(processor(m.clone()).process_transaction(tx,context(None)),Err(ProcessError::Stage{stage:PipelineStage::Runtime,..})));}drop(m);fs::remove_dir_all(p).unwrap();
}

#[test]
fn fee_limit_frozen_and_energy_price_fallback_vectors() {
 for (name,price,fee_limit,frozen,expected_result,expected_total,expected_frozen,expected_fee) in [
  ("frozen-above-cap",2,4,true,ContractResult::OutOfEnergy,2,2,0),
  ("frozen-below-cap",2,6,false,ContractResult::Success,3,0,6),
  ("zero-price-fallback",0,300,false,ContractResult::Success,3,0,300),
  ("negative-price-fallback",-1,300,false,ContractResult::Success,3,0,300),
 ] {
  let(p,m)=manager(name);let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[27;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();let contract=address(27);seed(&m,&owner,1_000_000,None);if !frozen{let mut account=Account::decode(m.durable_store(StoreKind::Account).get(&owner).unwrap().as_slice()).unwrap();account.account_resource=None;m.durable_store(StoreKind::Account).put(&owner,&account.encode_to_vec()).unwrap();}set_long(&m,"ENERGY_FEE",price);seed_runtime(&m,&owner,&contract,&[0x60,1,0]);let envelope=Contract{r#type:ContractType::TriggerSmartContract as i32,parameter:Some(any("protocol.TriggerSmartContract",&TriggerSmartContract{owner_address:owner.clone(),contract_address:contract,..Default::default()})),..Default::default()};let out=processor(m.clone()).process_transaction(sign_with_fee(envelope,&key,fee_limit),context(Some(expected_result))).unwrap();let receipt=out.info.receipt.unwrap();assert_eq!((receipt.energy_usage_total,receipt.energy_usage,receipt.energy_fee),(expected_total,expected_frozen,expected_fee),"{name}");drop(m);fs::remove_dir_all(p).unwrap();
 }
}

#[test]
fn energy_settlement_preserves_vm_value_received_by_distinct_origin() {
 let(p,m)=manager("origin-live-balance");let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[26;32]).unwrap();let caller=derive_address(&key.public_key()).as_bytes().to_vec();let contract=address(26);seed(&m,&caller,100,None);let mut contract_account=Account{address:contract.clone(),r#type:AccountType::Contract as i32,..Default::default()};contract_account.account_resource.get_or_insert_default().frozen_balance_for_energy=Some(Frozen{frozen_balance:1_000_000,expire_time:i64::MAX});m.durable_store(StoreKind::Account).put(&contract,&contract_account.encode_to_vec()).unwrap();m.durable_store(StoreKind::Contract).put(&contract,&SmartContract{origin_address:contract.clone(),contract_address:contract.clone(),consume_user_resource_percent:50,origin_energy_limit:1_000,..Default::default()}.encode_to_vec()).unwrap();m.durable_store(StoreKind::Code).put(&contract,&[0]).unwrap();let envelope=Contract{r#type:ContractType::TriggerSmartContract as i32,parameter:Some(any("protocol.TriggerSmartContract",&TriggerSmartContract{owner_address:caller.clone(),contract_address:contract.clone(),call_value:7,..Default::default()})),..Default::default()};processor(m.clone()).process_transaction(sign(envelope,&key),context(Some(ContractResult::Success))).unwrap();let view=m.read_view();assert_eq!(Account::decode(view.store(StoreKind::Account).get(&caller).unwrap().as_slice()).unwrap().balance,93);assert_eq!(Account::decode(view.store(StoreKind::Account).get(&contract).unwrap().as_slice()).unwrap().balance,7);drop(view);drop(m);fs::remove_dir_all(p).unwrap();
}

#[test]
fn same_origin_preserves_live_value_balance_and_persists_one_energy_account_pre_and_post_constantinople() {
 for (name,allow) in [("same-origin-pre",0),("same-origin-post",1)] {
  let(p,m)=manager(name);let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[28;32]).unwrap();let caller=derive_address(&key.public_key()).as_bytes().to_vec();let contract=address(28);seed(&m,&caller,100,None);set_long(&m,"ALLOW_TVM_CONSTANTINOPLE",allow);seed_runtime(&m,&caller,&contract,&[0x60,1,0]);
  let trigger=TriggerSmartContract{owner_address:caller.clone(),contract_address:contract.clone(),call_value:7,..Default::default()};let tx=sign(Contract{r#type:ContractType::TriggerSmartContract as i32,parameter:Some(any("protocol.TriggerSmartContract",&trigger)),..Default::default()},&key);
  let out=processor(m.clone()).process_transaction(tx,context(Some(ContractResult::Success))).unwrap();let receipt=out.info.receipt.unwrap();let view=m.read_view();let caller_state=Account::decode(view.store(StoreKind::Account).get(&caller).unwrap().as_slice()).unwrap();let contract_state=Account::decode(view.store(StoreKind::Account).get(&contract).unwrap().as_slice()).unwrap();
  assert_eq!((caller_state.balance,contract_state.balance),(93,7));assert_eq!(receipt.origin_energy_usage,0);assert_eq!(caller_state.account_resource.as_ref().unwrap().energy_usage,receipt.energy_usage);assert!(receipt.energy_usage>0);assert_eq!(caller_state.balance+contract_state.balance,100);drop(view);drop(m);fs::remove_dir_all(p).unwrap();
 }
}

#[test]
fn create_uses_transaction_derived_address_init_code_and_contract_metadata() {
 let(p,m)=manager("create");let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[15;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();seed(&m,&owner,100,None);let init=vec![0x60,0x2a,0x60,0,0x53,0x60,1,0x60,0,0xf3];let create=CreateSmartContract{owner_address:owner.clone(),new_contract:Some(SmartContract{origin_address:address(99),contract_address:Vec::new(),bytecode:init,name:"canonical".into(),version:1,..Default::default()}),..Default::default()};let tx=sign(Contract{r#type:ContractType::CreateSmartContract as i32,parameter:Some(any("protocol.CreateSmartContract",&create)),..Default::default()},&key);let id=tx.transaction_id(CryptoEngine::Secp256k1);let expected=top_level_contract_address(&tron_primitives::TransactionId::new(id),&TronAddress21::validate_mainnet(&owner).unwrap());processor(m.clone()).process_transaction(tx,context(Some(ContractResult::Success))).unwrap();let view=m.read_view();assert_eq!(view.store(StoreKind::Code).get(expected.as_bytes()),Some(vec![0x2a]));let metadata=SmartContract::decode(view.store(StoreKind::Contract).get(expected.as_bytes()).unwrap().as_slice()).unwrap();assert_eq!(metadata.contract_address,expected.as_bytes());assert_eq!(metadata.origin_address,owner);assert_eq!(metadata.name,"canonical");assert!(metadata.bytecode.is_empty());drop(view);drop(m);fs::remove_dir_all(p).unwrap();
}

#[test]
fn state_permission_id_type_and_operations_cannot_be_bypassed_by_valid_signature() {
 let(p,m)=manager("auth");let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[4;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();let contract_address=address(7);let denied=Permission{r#type:tron_protocol::protocol::permission::PermissionType::Active as i32,id:2,permission_name:"denied".into(),threshold:1,parent_id:0,operations:vec![0;32],keys:vec![tron_protocol::protocol::Key{address:owner.clone(),weight:1}]};seed(&m,&owner,100,None);let mut account=Account::decode(m.durable_store(StoreKind::Account).get(&owner).unwrap().as_slice()).unwrap();account.active_permission.push(denied);m.durable_store(StoreKind::Account).put(&owner,&account.encode_to_vec()).unwrap();let tx=vm_transaction(&key,&owner,&contract_address,2);let id=tx.transaction_id(CryptoEngine::Secp256k1);let mut processor=processor(m.clone());assert!(matches!(processor.process_transaction(tx,context(Some(ContractResult::Success))),Err(ProcessError::Stage{stage:PipelineStage::Admission,..})));assert_eq!(processor.cache.len(),0);assert!(m.durable_store(StoreKind::TransactionHistory).get(id.as_bytes()).is_none());fs::remove_dir_all(p).unwrap();
}

#[test]
fn durable_duplicate_survives_cache_clear_and_eviction_semantics() {
 let(p,m)=manager("durable-duplicate");let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[6;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();let to=address(6);seed(&m,&owner,100,None);m.durable_store(StoreKind::Account).put(&to,&Account{address:to.clone(),..Default::default()}.encode_to_vec()).unwrap();let contract=Contract{r#type:ContractType::TransferContract as i32,parameter:Some(any("protocol.TransferContract",&TransferContract{owner_address:owner, to_address:to,amount:1})),..Default::default()};let tx=sign(contract,&key);let id=tx.transaction_id(CryptoEngine::Secp256k1);let mut processor=processor(m.clone());processor.process_transaction(tx.clone(),context(None)).unwrap();processor.cache.clear();assert!(matches!(processor.process_transaction(tx,context(None)),Err(ProcessError::Duplicate(found)) if found==id));assert!(m.read_view().store(StoreKind::Transaction).get(id.as_bytes()).is_some());drop(p);
}

#[test]
fn late_cache_block_reversal_rolls_back_all_session_and_cache_effects() {
 let(p,m)=manager("cache-reversal");let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[7;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();let to=address(7);seed(&m,&owner,100,None);m.durable_store(StoreKind::Account).put(&to,&Account{address:to.clone(),..Default::default()}.encode_to_vec()).unwrap();let make=|amount|sign(Contract{r#type:ContractType::TransferContract as i32,parameter:Some(any("protocol.TransferContract",&TransferContract{owner_address:owner.clone(),to_address:to.clone(),amount})),..Default::default()},&key);let first=make(1);let second=make(2);let second_id=second.transaction_id(CryptoEngine::Secp256k1);let mut processor=processor(m.clone());processor.process_transaction(first,context(None)).unwrap();let cache_len=processor.cache.len();let mut reversed=context(None);reversed.clock.now=2;reversed.clock.block_number=8;assert!(matches!(processor.process_transaction(second,reversed),Err(ProcessError::Stage{stage:PipelineStage::PersistCache,..})));assert_eq!(processor.cache.len(),cache_len);let view=m.read_view();assert!(view.store(StoreKind::Transaction).get(second_id.as_bytes()).is_none());let owner_state=Account::decode(view.store(StoreKind::Account).get(&owner).unwrap().as_slice()).unwrap();let to_state=Account::decode(view.store(StoreKind::Account).get(&to).unwrap().as_slice()).unwrap();assert_eq!((owner_state.balance,to_state.balance),(99,1));drop(view);drop(p);
}

#[test]
fn live_energy_policy_splits_origin_and_caller_and_persists_fee_pool() {
 let(p,m)=manager("paid-split");let caller_key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[9;32]).unwrap();let caller=derive_address(&caller_key.public_key()).as_bytes().to_vec();let origin=address(3);let contract=address(4);seed(&m,&caller,1_000_000,None);let mut caller_state=Account::decode(m.durable_store(StoreKind::Account).get(&caller).unwrap().as_slice()).unwrap();caller_state.account_resource=None;m.durable_store(StoreKind::Account).put(&caller,&caller_state.encode_to_vec()).unwrap();set_long(&m,"ENERGY_FEE",2);set_long(&m,"ALLOW_TRANSACTION_FEE_POOL",1);set_long(&m,"ALLOW_ADAPTIVE_ENERGY",1);let mut origin_account=Account{address:origin.clone(),balance:1_000_000,..Default::default()};origin_account.account_resource.get_or_insert_default().frozen_balance_for_energy=Some(Frozen{frozen_balance:1_000_000,expire_time:i64::MAX});m.durable_store(StoreKind::Account).put(&origin,&origin_account.encode_to_vec()).unwrap();m.durable_store(StoreKind::Contract).put(&contract,&SmartContract{origin_address:origin.clone(),contract_address:contract.clone(),consume_user_resource_percent:50,origin_energy_limit:1_000,..Default::default()}.encode_to_vec()).unwrap();m.durable_store(StoreKind::Account).put(&contract,&Account{address:contract.clone(),r#type:AccountType::Contract as i32,..Default::default()}.encode_to_vec()).unwrap();m.durable_store(StoreKind::Code).put(&contract,&[0x60,1,0x60,1,0x55,0]).unwrap();let tx=vm_transaction(&caller_key,&caller,&contract,0);let out=processor(m.clone()).process_transaction(tx,context(Some(ContractResult::Success))).unwrap();let receipt=out.info.receipt.unwrap();assert!(receipt.origin_energy_usage>0);assert!(receipt.energy_fee>0);let view=m.read_view();let updated_origin=Account::decode(view.store(StoreKind::Account).get(&origin).unwrap().as_slice()).unwrap();let updated_caller=Account::decode(view.store(StoreKind::Account).get(&caller).unwrap().as_slice()).unwrap();assert_eq!(updated_origin.account_resource.unwrap().energy_usage,receipt.origin_energy_usage);assert_eq!(updated_caller.balance,1_000_000-receipt.energy_fee);assert_eq!(i64::from_be_bytes(view.store(StoreKind::DynamicProperties).get(dynamic::key("TRANSACTION_FEE_POOL").unwrap()).unwrap().try_into().unwrap()),receipt.energy_fee);assert!(i64::from_be_bytes(view.store(StoreKind::DynamicProperties).get(dynamic::key("BLOCK_ENERGY_USAGE").unwrap()).unwrap().try_into().unwrap())>0);drop(view);drop(m);fs::remove_dir_all(p).unwrap();
}

#[test]
fn public_bandwidth_is_global_and_recovers_after_window() {
 let(p,m)=manager("public-global");let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[10;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();let to=address(10);seed(&m,&owner,100,None);m.durable_store(StoreKind::Account).put(&to,&Account{address:to.clone(),..Default::default()}.encode_to_vec()).unwrap();let make=|amount|sign(Contract{r#type:ContractType::TransferContract as i32,parameter:Some(any("protocol.TransferContract",&TransferContract{owner_address:owner.clone(),to_address:to.clone(),amount})),..Default::default()},&key);let first=make(1);set_long(&m,"PUBLIC_NET_LIMIT",first.full_bytes().len() as i64);let mut processor=processor(m.clone());processor.process_transaction(first,context(None)).unwrap();let used=i64::from_be_bytes(m.read_view().store(StoreKind::DynamicProperties).get(dynamic::key("PUBLIC_NET_USAGE").unwrap()).unwrap().try_into().unwrap());assert!(used>0);let second=make(2);let second_id=second.transaction_id(CryptoEngine::Secp256k1);assert!(matches!(processor.process_transaction(second.clone(),context(None)),Err(ProcessError::Stage{stage:PipelineStage::Billing,..})));assert!(m.read_view().store(StoreKind::Transaction).get(second_id.as_bytes()).is_none());let mut later=context(None);later.clock.head_slot=28_810;later.clock.now=200;processor.process_transaction(second,later).unwrap();assert!(m.read_view().store(StoreKind::Transaction).get(second_id.as_bytes()).is_some());drop(m);fs::remove_dir_all(p).unwrap();
}

#[test]
fn provisional_cache_reservation_rejects_before_any_durable_row() {
 let(p,m)=manager("provisional-cache");let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[11;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();let to=address(11);seed(&m,&owner,100,None);m.durable_store(StoreKind::Account).put(&to,&Account{address:to.clone(),..Default::default()}.encode_to_vec()).unwrap();let tx=sign(Contract{r#type:ContractType::TransferContract as i32,parameter:Some(any("protocol.TransferContract",&TransferContract{owner_address:owner.clone(),to_address:to.clone(),amount:1})),..Default::default()},&key);let id=tx.transaction_id(CryptoEngine::Secp256k1);let mut processor=processor(m.clone());processor.cache.insert(id,9,1).unwrap();assert!(m.read_view().store(StoreKind::Transaction).get(id.as_bytes()).is_none());assert!(matches!(processor.process_transaction(tx,context(None)),Err(ProcessError::Duplicate(found)) if found==id));let view=m.read_view();assert!(view.store(StoreKind::Transaction).get(id.as_bytes()).is_none());assert_eq!(Account::decode(view.store(StoreKind::Account).get(&owner).unwrap().as_slice()).unwrap().balance,100);assert_eq!(Account::decode(view.store(StoreKind::Account).get(&to).unwrap().as_slice()).unwrap().balance,0);drop(view);drop(m);fs::remove_dir_all(p).unwrap();
}

#[test]
fn head_slot_drives_bandwidth_decay_while_height_stays_cache_metadata() {
 let(p,m)=manager("head-slot");let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[12;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();let to=address(12);seed(&m,&owner,1_000_000,None);m.durable_store(StoreKind::Account).put(&to,&Account{address:to.clone(),..Default::default()}.encode_to_vec()).unwrap();let mut account=Account::decode(m.durable_store(StoreKind::Account).get(&owner).unwrap().as_slice()).unwrap();account.free_net_usage=5_000;account.latest_consume_free_time=1; m.durable_store(StoreKind::Account).put(&owner,&account.encode_to_vec()).unwrap();set_long(&m,"PUBLIC_NET_USAGE",57_600_000_000);set_long(&m,"PUBLIC_NET_TIME",1);let tx=sign(Contract{r#type:ContractType::TransferContract as i32,parameter:Some(any("protocol.TransferContract",&TransferContract{owner_address:owner.clone(),to_address:to,amount:1})),..Default::default()},&key);let mut c=context(None);c.clock.block_number=9;c.clock.head_slot=28_801;let mut processor=processor(m.clone());let out=processor.process_transaction(tx,c).unwrap();assert_eq!(out.info.receipt.unwrap().net_fee,0);let stored=Account::decode(m.read_view().store(StoreKind::Account).get(&owner).unwrap().as_slice()).unwrap();assert!(stored.free_net_usage<5_000);drop(processor);drop(m);fs::remove_dir_all(p).unwrap();
}

#[test]
fn bandwidth_fees_are_conserved_to_each_live_destination() {
 for (name,pool,burn) in [("pool",1,0),("burn",0,1),("blackhole",0,0)] { let(p,m)=manager(name);let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[13;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();let to=address(13);seed(&m,&owner,10_000_000,None);m.durable_store(StoreKind::Account).put(&to,&Account{address:to.clone(),..Default::default()}.encode_to_vec()).unwrap();set_long(&m,"FREE_NET_LIMIT",0);set_long(&m,"PUBLIC_NET_LIMIT",0);set_long(&m,"TRANSACTION_FEE",2);set_long(&m,"ALLOW_TRANSACTION_FEE_POOL",pool);set_long(&m,"ALLOW_BLACKHOLE_OPTIMIZATION",burn);let before=Account::decode(m.read_view().store(StoreKind::Account).get(&owner).unwrap().as_slice()).unwrap().balance;let tx=sign(Contract{r#type:ContractType::TransferContract as i32,parameter:Some(any("protocol.TransferContract",&TransferContract{owner_address:owner.clone(),to_address:to,amount:1})),..Default::default()},&key);let mut processor=processor(m.clone());let out=processor.process_transaction(tx,context(None)).unwrap();let fee=out.info.receipt.unwrap().net_fee;let view=m.read_view();let after=Account::decode(view.store(StoreKind::Account).get(&owner).unwrap().as_slice()).unwrap().balance;let dynamic_value=|n|i64::from_be_bytes(view.store(StoreKind::DynamicProperties).get(dynamic::key(n).unwrap()).unwrap().try_into().unwrap());assert_eq!(before-after,fee+1);assert_eq!(dynamic_value("TOTAL_TRANSACTION_COST"),fee);if pool==1{assert_eq!(dynamic_value("TRANSACTION_FEE_POOL"),fee)}else if burn==1{assert_eq!(dynamic_value("BURN_TRX_AMOUNT"),fee)}else{let blackhole=address(0x41);assert_eq!(Account::decode(view.store(StoreKind::Account).get(&blackhole).unwrap().as_slice()).unwrap().balance,fee)}drop(view);drop(processor);drop(m);fs::remove_dir_all(p).unwrap(); }
}

#[test]
fn root_vm_values_transfer_atomically_and_fail_without_state() {
 for (name,code,value,token_value,owner_balance,owner_token,expected) in [
  ("root-trx",vec![0x34,0x60,1,0x55,0],7,0,100,0,Ok((93,7,0,0))),
  ("root-token",vec![0],0,4,100,9,Ok((100,0,5,4))),
  ("root-revert",vec![0x60,0,0x60,0,0xfd],7,4,100,9,Ok((100,0,9,0))),
  ("root-insufficient",vec![0],101,0,100,0,Err(())),
 ] {
  let(p,m)=manager(name);let key=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[21;32]).unwrap();let owner=derive_address(&key.public_key()).as_bytes().to_vec();let contract=address(21);seed(&m,&owner,owner_balance,None);if owner_token!=0{let mut a=Account::decode(m.durable_store(StoreKind::Account).get(&owner).unwrap().as_slice()).unwrap();a.asset_v2.insert("1000001".into(),owner_token);m.durable_store(StoreKind::Account).put(&owner,&a.encode_to_vec()).unwrap();}seed_runtime(&m,&owner,&contract,&code);
  let trigger=TriggerSmartContract{owner_address:owner.clone(),contract_address:contract.clone(),call_value:value,call_token_value:token_value,token_id:1_000_001,..Default::default()};let tx=sign(Contract{r#type:ContractType::TriggerSmartContract as i32,parameter:Some(any("protocol.TriggerSmartContract",&trigger)),..Default::default()},&key);let result=processor(m.clone()).process_transaction(tx,context(Some(if name=="root-revert"{ContractResult::Revert}else{ContractResult::Success})));
  assert_eq!(result.is_ok(),expected.is_ok(),"{name}");let view=m.read_view();let from=Account::decode(view.store(StoreKind::Account).get(&owner).unwrap().as_slice()).unwrap();let to=Account::decode(view.store(StoreKind::Account).get(&contract).unwrap().as_slice()).unwrap();let observed=(from.balance,to.balance,*from.asset_v2.get("1000001").unwrap_or(&0),*to.asset_v2.get("1000001").unwrap_or(&0));assert_eq!(observed,expected.unwrap_or((100,0,0,0)),"{name}");drop(view);drop(p);
 }
}

#[test]
fn trigger_constant_abi_selector_obeys_constantinople_policy() {
 let(p,m)=manager("constant-abi");let contract=address(22);let selector=tron_crypto::keccak256(b"read(uint256)");let entry=tron_protocol::protocol::smart_contract::abi::Entry{name:"read".into(),constant:false,r#type:tron_protocol::protocol::smart_contract::abi::entry::EntryType::Function as i32,state_mutability:tron_protocol::protocol::smart_contract::abi::entry::StateMutabilityType::View as i32,inputs:vec![tron_protocol::protocol::smart_contract::abi::entry::Param{r#type:"uint256".into(),..Default::default()}],..Default::default()};let abi=tron_protocol::protocol::smart_contract::Abi{entrys:vec![entry]};m.durable_store(StoreKind::Abi).put(&contract,&abi.encode_to_vec()).unwrap();let trigger=TriggerSmartContract{owner_address:address(23),contract_address:contract,data:selector[..4].to_vec(),..Default::default()};let envelope=Contract{r#type:ContractType::TriggerSmartContract as i32,parameter:Some(any("protocol.TriggerSmartContract",&trigger)),..Default::default()};let session=m.build_session().unwrap();assert!(Runtime::trigger_is_constant_abi(&envelope,&session,&runtime_config()).unwrap());assert!(matches!(Runtime::enforce_constant_policy(RuntimeKind::Trigger,false,true),Err(RuntimeError::ConstantMethod)));assert!(Runtime::enforce_constant_policy(RuntimeKind::Trigger,true,true).is_ok());drop(session);drop(m);fs::remove_dir_all(p).unwrap();
}
