use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use num_bigint::BigInt;
use prost::Message;
use tron_consensus::{accumulate_vi,adjust_allowance,delegation_brokerage_key,delegation_key,pay_fee_pool_reward,query_reward,reward_across_cycles,reward_vi,standby_distribution,withdraw_reward,ConsensusRead,StateError,StateFacade,VoteReward,VI_SCALE};
use tron_protocol::protocol::{Account, Vote};
use tron_state::{dynamic, SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

fn path()->PathBuf{std::env::temp_dir().join(format!("c017-rewards-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()))}
fn manager()->StorageManager{StorageManager::new(OpenRequirements{identity:StorageIdentity{network:"c017-reward".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]})}
fn put_long(root:&StateStore,name:&str,value:i64){root.store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(),&value.to_be_bytes()).unwrap()}
fn save_i64(root:&StateStore,key:Vec<u8>,value:i64){root.store(StoreKind::Delegation).put(&key,&value.to_be_bytes()).unwrap()}
fn save_vi(root:&StateStore,key:Vec<u8>,value:BigInt){root.store(StoreKind::Delegation).put(&key,&value.to_signed_bytes_be()).unwrap()}
#[test] fn java_reward_rounding_brokerage_vi_and_effective_cycle(){assert_eq!(standby_distribution(&[(b"a".to_vec(),1),(b"b".to_vec(),2)],100),vec![(b"a".to_vec(),33),(b"b".to_vec(),66)]);let vi=accumulate_vi(&BigInt::from(7),99,3);assert_eq!(vi,BigInt::from(33)*BigInt::from(VI_SCALE)+7);assert_eq!(reward_vi(&BigInt::from(7),&vi,2),66);let votes=[VoteReward{witness:b"a".to_vec(),votes:2}];assert_eq!(reward_across_cycles(1,4,3,&votes,|_,_|5,|_,c|if c==2{BigInt::from(0)}else{BigInt::from(40)*BigInt::from(VI_SCALE)}),90);}
#[test]
fn java_manager_fee_pool_producer_routes_remainder_period_and_overflow_vectors(){
    let directory=path();
    let root=StateStore::new(manager().open_store(&directory).unwrap());
    let producer=vec![0x41;21];
    let other=vec![0x42;21];
    for (address,allowance) in [(&producer,10),(&other,20)] {
        root.store(StoreKind::Account).put(address,&Account{address:address.clone(),allowance,..Default::default()}.encode_to_vec()).unwrap();
    }
    for(name,value)in[("ALLOW_TRANSACTION_FEE_POOL",1),("TRANSACTION_FEE_POOL",101),("CHANGE_DELEGATION",1),("CURRENT_CYCLE_NUMBER",7)]{put_long(&root,name,value)}
    root.store(StoreKind::Delegation).put(&delegation_brokerage_key(7,&producer),&25_i32.to_be_bytes()).unwrap();

    let sessions=SessionManager::new(root.clone());
    let mut session=sessions.build_session().unwrap();
    let facade=StateFacade::new(&session);
    let paid=pay_fee_pool_reward(&facade,&producer,10).unwrap().unwrap();
    assert_eq!((paid.pool_before,paid.transaction_fee_reward,paid.pool_after),(101,10,91));
    assert_eq!(paid.delegated_payment.unwrap().brokerage,2);
    assert_eq!(facade.dynamic_long("TRANSACTION_FEE_POOL").unwrap(),91);
    assert_eq!(i64::from_be_bytes(facade.delegation(&delegation_key(7,&producer,"reward")).unwrap().try_into().unwrap()),8);
    let producer_account=Account::decode(facade.store_get(StoreKind::Account,&producer).unwrap().as_slice()).unwrap();
    let other_account=Account::decode(facade.store_get(StoreKind::Account,&other).unwrap().as_slice()).unwrap();
    assert_eq!((producer_account.allowance,other_account.allowance),(12,20));

    facade.save_dynamic_long("CHANGE_DELEGATION",0).unwrap();
    facade.save_dynamic_long("TRANSACTION_FEE_POOL",11).unwrap();
    let legacy=pay_fee_pool_reward(&facade,&producer,3).unwrap().unwrap();
    assert_eq!((legacy.transaction_fee_reward,legacy.pool_after,legacy.delegated_payment),(3,8,None));
    let producer_account=Account::decode(facade.store_get(StoreKind::Account,&producer).unwrap().as_slice()).unwrap();
    assert_eq!(producer_account.allowance,15);
    assert_eq!(i64::from_be_bytes(facade.delegation(&delegation_key(7,&producer,"reward")).unwrap().try_into().unwrap()),8);

    assert_eq!(pay_fee_pool_reward(&facade,&producer,0),Err(StateError::InvalidRewardPeriod(0)));
    assert_eq!(facade.dynamic_long("TRANSACTION_FEE_POOL").unwrap(),8);
    facade.store_put(StoreKind::Account,&producer,&Account{address:producer.clone(),allowance:i64::MAX,..Default::default()}.encode_to_vec()).unwrap();
    facade.save_dynamic_long("TRANSACTION_FEE_POOL",1).unwrap();
    let overflow=pay_fee_pool_reward(&facade,&producer,1).unwrap().unwrap();
    assert_eq!((overflow.transaction_fee_reward,overflow.pool_after),(1,0));
    assert_eq!(Account::decode(facade.store_get(StoreKind::Account,&producer).unwrap().as_slice()).unwrap().allowance,i64::MIN);

    facade.store_put(StoreKind::Account,&producer,&Account{address:producer.clone(),allowance:i64::MIN,..Default::default()}.encode_to_vec()).unwrap();
    facade.save_dynamic_long("TRANSACTION_FEE_POOL",i64::MIN).unwrap();
    let division_overflow=pay_fee_pool_reward(&facade,&producer,-1).unwrap().unwrap();
    assert_eq!((division_overflow.transaction_fee_reward,division_overflow.pool_after),(i64::MIN,0));
    assert_eq!(Account::decode(facade.store_get(StoreKind::Account,&producer).unwrap().as_slice()).unwrap().allowance,0);

    session.revoke().unwrap();drop(sessions);drop(root);fs::remove_dir_all(directory).unwrap();
}

#[test]
fn mortgage_query_withdraw_snapshots_and_allowance_match_java_lifecycle(){
    let directory=path();let root=StateStore::new(manager().open_store(&directory).unwrap());let voter=vec![0x41;21];let witness=vec![0x42;21];
    let account=Account{address:voter.clone(),allowance:5,votes:vec![Vote{vote_address:witness.clone(),vote_count:10}],..Default::default()};root.store(StoreKind::Account).put(&voter,&account.encode_to_vec()).unwrap();
    for(name,value)in[("CHANGE_DELEGATION",1),("CURRENT_CYCLE_NUMBER",4),("NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE",2)]{put_long(&root,name,value)}
    for cycle in 0..2{save_i64(&root,delegation_key(cycle,&witness,"reward"),100);save_i64(&root,delegation_key(cycle,&witness,"vote"),100)}
    save_vi(&root,delegation_key(1,&witness,"vi"),BigInt::from(3)*BigInt::from(VI_SCALE));save_vi(&root,delegation_key(3,&witness,"vi"),BigInt::from(8)*BigInt::from(VI_SCALE));
    let sessions=SessionManager::new(root.clone());let mut session=sessions.build_session().unwrap();let facade=StateFacade::new(&session);
    assert_eq!(query_reward(&facade,&voter).unwrap(),75);let withdrawn=withdraw_reward(&facade,&voter).unwrap();assert_eq!((withdrawn.reward,withdrawn.begin_cycle,withdrawn.end_cycle),(70,4,5));assert_eq!(query_reward(&facade,&voter).unwrap(),75);
    adjust_allowance(&facade,&voter,-25).unwrap();assert_eq!(query_reward(&facade,&voter).unwrap(),50);assert!(adjust_allowance(&facade,&voter,-51).is_err());
    session.revoke().unwrap();drop(sessions);drop(root);fs::remove_dir_all(directory).unwrap();
}
