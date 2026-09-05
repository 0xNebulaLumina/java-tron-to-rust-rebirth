#[path = "support/c013_replay.rs"]
mod c013_replay;

use std::{fs,path::PathBuf,time::{SystemTime,UNIX_EPOCH}};
use prost::Message;
use tron_execution::{Actuator,ActuatorResult,DelegateResourceActuator,ExecutionConfig,FreezeBalanceV2Actuator,UnfreezeBalanceV2Actuator,CancelAllUnfreezeV2Actuator,ValidationContext};
use tron_protocol::{google::protobuf::Any,protocol::{account::{FreezeV2,UnFreezeV2},Account,CancelAllUnfreezeV2Contract,DelegateResourceContract,DelegatedResourceAccountIndex,FreezeBalanceV2Contract,ResourceCode,UnfreezeBalanceV2Contract,Votes}};
use tron_state::{delegation::{self,LegacyIndexMutation},dynamic,Session,SessionManager,StateStore,StoreKind};
use tron_storage::{OpenRequirements,StorageIdentity,StorageManager};
const ORACLE:&str=include_str!("../../../../docs/oracles/c013-resource-real.v1.json");
const CAPTURED_JAVA:&str=include_str!("../../../../docs/oracles/c013-java-owned-real.v1.json");
const OWNER:[u8;21]=[0x41;21];
fn path(n:&str)->PathBuf{std::env::temp_dir().join(format!("c013-{n}-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()))}
fn manager(n:&str)->(PathBuf,SessionManager){let p=path(n);let r=OpenRequirements{identity:StorageIdentity{network:"c013".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]};(p.clone(),SessionManager::new(StateStore::new(StorageManager::new(r).open_store(&p).unwrap())))}
fn long(s:&Session,n:&str,v:i64){s.store(StoreKind::DynamicProperties).put(dynamic::key(n).unwrap(),&v.to_be_bytes()).unwrap()}
fn any<M:Message>(name:&str,m:&M)->Any{Any{type_url:format!("type.googleapis.com/{name}"),value:m.encode_to_vec()}}
fn setup(s:&Session){for(n,v)in[("UNFREEZE_DELAY_DAYS",14),("LATEST_BLOCK_HEADER_TIMESTAMP",1_700_000_000_000),("ALLOW_NEW_RESOURCE_MODEL",1),("TOTAL_NET_WEIGHT",0),("TOTAL_ENERGY_WEIGHT",0),("TOTAL_TRON_POWER_WEIGHT",0),("ALLOW_CANCEL_ALL_UNFREEZE_V2",1)]{long(s,n,v)}let a=Account{address:OWNER.to_vec(),balance:10_000_000,..Default::default()};s.store(StoreKind::Account).put(&OWNER,&a.encode_to_vec()).unwrap()}
fn captured_delta<'a>(invocation:&'a serde_json::Value,store:&str)->&'a serde_json::Value{invocation["ordered_store_deltas"].as_array().unwrap().iter().find(|row|row["store"]==store).unwrap()}
fn load(s:&Session)->Account{Account::decode(s.store(StoreKind::Account).get(&OWNER).unwrap().as_slice()).unwrap()}
#[test]fn java_direct_resource_oracle_is_bound_to_rust_scenarios(){for scenario in ["freeze-v2-rounding","cancel-expired-future","delegate-preserves-weight","undelegate-usage-migration","new-model-no-tron-power-mint","child-session-rollback"]{assert!(ORACLE.contains(&format!("\"scenario\": \"{scenario}\"")));}assert!(ORACLE.contains("\"schema\": \"c013-resource-real.v1\""));assert!(ORACLE.contains("\"balance\": 8500000"));assert!(ORACLE.contains("\"frozen\": 3000000"));}
#[test]fn freeze_unfreeze_cancel_v2_is_atomic_and_preserves_java_weight_rounding(){let(p,m)=manager("flow");let mut outer=m.build_session().unwrap();setup(&outer);let f=FreezeBalanceV2Contract{owner_address:OWNER.to_vec(),frozen_balance:1_500_000,resource:ResourceCode::Bandwidth as i32};FreezeBalanceV2Actuator::new(any("protocol.FreezeBalanceV2Contract",&f)).unwrap().execute(&outer,Some(&mut ActuatorResult::default()),ExecutionConfig::default()).unwrap();assert_eq!(load(&outer).balance,8_500_000);assert_eq!(i64::from_be_bytes(outer.store(StoreKind::DynamicProperties).get(dynamic::key("TOTAL_NET_WEIGHT").unwrap()).unwrap().try_into().unwrap()),1);let before=outer.store(StoreKind::Account).get(&OWNER);let mut child=outer.child().unwrap();let u=UnfreezeBalanceV2Contract{owner_address:OWNER.to_vec(),unfreeze_balance:500_000,resource:ResourceCode::Bandwidth as i32};UnfreezeBalanceV2Actuator::new(any("protocol.UnfreezeBalanceV2Contract",&u)).unwrap().execute(&child,Some(&mut ActuatorResult::default()),ExecutionConfig::default()).unwrap();assert_eq!(load(&child).unfrozen_v2.len(),1);child.revoke().unwrap();assert_eq!(outer.store(StoreKind::Account).get(&OWNER),before);let mut result=ActuatorResult::default();UnfreezeBalanceV2Actuator::new(any("protocol.UnfreezeBalanceV2Contract",&u)).unwrap().execute(&outer,Some(&mut result),ExecutionConfig::default()).unwrap();let c=CancelAllUnfreezeV2Contract{owner_address:OWNER.to_vec()};CancelAllUnfreezeV2Actuator::new(any("protocol.CancelAllUnfreezeV2Contract",&c)).unwrap().execute(&outer,Some(&mut result),ExecutionConfig::default()).unwrap();assert!(load(&outer).unfrozen_v2.is_empty());assert_eq!(load(&outer).frozen_v2[0].amount,1_500_000);outer.revoke().unwrap();drop(m);fs::remove_dir_all(p).unwrap()}
#[test]fn expired_entries_are_withdrawn_while_future_entries_cancel_back_to_frozen(){let(p,m)=manager("cancel");let mut s=m.build_session().unwrap();setup(&s);let mut a=load(&s);a.unfrozen_v2=vec![UnFreezeV2{r#type:0,unfreeze_amount:2_000_000,unfreeze_expire_time:1},UnFreezeV2{r#type:0,unfreeze_amount:3_000_000,unfreeze_expire_time:i64::MAX}];s.store(StoreKind::Account).put(&OWNER,&a.encode_to_vec()).unwrap();let c=CancelAllUnfreezeV2Contract{owner_address:OWNER.to_vec()};CancelAllUnfreezeV2Actuator::new(any("protocol.CancelAllUnfreezeV2Contract",&c)).unwrap().execute(&s,Some(&mut ActuatorResult::default()),ExecutionConfig::default()).unwrap();let a=load(&s);assert_eq!(a.balance,12_000_000);assert_eq!(a.frozen_v2[0].amount,3_000_000);s.revoke().unwrap();drop(m);fs::remove_dir_all(p).unwrap()}

#[test]
fn java_legacy_delegation_index_convert_fans_out_both_arrays_and_deletes_source() {
    let owner = vec![0x41; 21];
    let to_a = vec![0x42; 21];
    let to_b = vec![0x43; 21];
    let from_a = vec![0x44; 21];
    let from_b = vec![0x45; 21];
    let legacy = DelegatedResourceAccountIndex {
        account: owner.clone(),
        from_accounts: vec![from_a.clone(), from_b.clone()],
        to_accounts: vec![to_a.clone(), to_b.clone()],
        timestamp: 207,
    };
    let rows = delegation::legacy_index_conversion(&owner, &legacy).unwrap();
    assert_eq!(rows.len(), 9);
    let expected = [
        (delegation::from_index_key(&owner, &to_a), to_a.clone(), 1),
        (delegation::to_index_key(&to_a, &owner), owner.clone(), 1),
        (delegation::from_index_key(&owner, &to_b), to_b.clone(), 2),
        (delegation::to_index_key(&to_b, &owner), owner.clone(), 2),
        (delegation::to_index_key(&owner, &from_a), from_a.clone(), 1),
        (delegation::from_index_key(&from_a, &owner), owner.clone(), 1),
        (delegation::to_index_key(&owner, &from_b), from_b.clone(), 2),
        (delegation::from_index_key(&from_b, &owner), owner.clone(), 2),
    ];
    for (row, (key, account, timestamp)) in rows.iter().zip(expected) {
        assert_eq!(row, &LegacyIndexMutation::Put {
            key,
            value: DelegatedResourceAccountIndex { account, timestamp, ..Default::default() },
        });
    }
    assert_eq!(rows.last(), Some(&LegacyIndexMutation::Delete { key: owner }));
}

#[test]
fn captured_unfreeze_v2_vote_transition_regression() {
    let capture:serde_json::Value=serde_json::from_str(CAPTURED_JAVA).unwrap();
    let member=capture["members"].as_array().unwrap().iter().find(|row|row["variant_id"]=="TCASE-560E3C4947F189B3").unwrap();
    let invocation=|ordinal:u64|member["invocations"].as_array().unwrap().iter().find(|row|row["ordinal"]==ordinal).unwrap();
    let decode_hex=|value:&serde_json::Value|value.as_str().unwrap().as_bytes().chunks_exact(2).map(|pair|u8::from_str_radix(std::str::from_utf8(pair).unwrap(),16).unwrap()).collect::<Vec<_>>();


    let legacy=invocation(2);
    let legacy_account=Account::decode(decode_hex(&captured_delta(legacy,"account")["after_hex"]).as_slice()).unwrap();
    let legacy_votes=Votes::decode(decode_hex(&captured_delta(legacy,"votes")["after_hex"]).as_slice()).unwrap();
    assert_eq!(legacy_account.votes.iter().map(|vote|vote.vote_count).collect::<Vec<_>>(),vec![250,250]);
    assert_eq!(legacy_votes.old_votes.iter().map(|vote|vote.vote_count).collect::<Vec<_>>(),vec![500,500]);
    assert_eq!(legacy_votes.new_votes.iter().map(|vote|vote.vote_count).collect::<Vec<_>>(),vec![250,250]);
    assert_eq!(i64::from_be_bytes(decode_hex(&captured_delta(legacy,"properties")["after_hex"]).try_into().unwrap()),-500);

    let transition=invocation(4);
    let transition_account=Account::decode(decode_hex(&captured_delta(transition,"account")["after_hex"]).as_slice()).unwrap();
    let transition_votes=Votes::decode(decode_hex(&captured_delta(transition,"votes")["after_hex"]).as_slice()).unwrap();
    assert!(transition_account.votes.is_empty());
    assert_eq!(transition_account.old_tron_power,-1);
    assert_eq!(transition_votes.old_votes.iter().map(|vote|vote.vote_count).collect::<Vec<_>>(),vec![500,500]);
    assert!(transition_votes.new_votes.is_empty());
    assert_eq!(i64::from_be_bytes(decode_hex(&captured_delta(transition,"properties")["after_hex"]).try_into().unwrap()),-750);
}

#[test]
fn replays_every_unique_java_resource_observation() {
    let stats = c013_replay::replay("resource");
    assert_eq!(stats.total_unique, 868);
    assert_eq!(stats.captured_invocations, 926);
    assert_eq!(stats.executed_unique, 227);
    assert_eq!(stats.explicit_exclusions, 0);
}

#[test]
fn zero_invocation_java_helpers_have_explicit_rust_dispositions() {
    assert_eq!(c013_replay::prove_zero_invocation_methods("resource"), 8);
}

#[test]
fn max_delegate_lock_period_support_is_independent_of_stored_value() {
    const DEFAULT: i64 = 86_400;
    let (directory, manager) = manager("delegate-lock-support");
    let mut session = manager.build_session().unwrap();
    setup(&session);
    for (name, value) in [("ALLOW_DELEGATE_RESOURCE", 1), ("TOTAL_NET_LIMIT", 43_200_000_000), ("TOTAL_ENERGY_CURRENT_LIMIT", 90_000_000_000), ("TOTAL_ENERGY_WEIGHT", 1)] { long(&session, name, value); }
    let mut receiver = [0x42; 21]; receiver[0] = 0x41;
    session.store(StoreKind::Account).put(&receiver, &Account { address: receiver.to_vec(), ..Default::default() }.encode_to_vec()).unwrap();
    let mut owner = load(&session);
    owner.frozen_v2 = vec![FreezeV2 { r#type: ResourceCode::Bandwidth as i32, amount: 10_000_000 }];
    session.store(StoreKind::Account).put(&OWNER, &owner.encode_to_vec()).unwrap();
    let validate = |maximum: Option<i64>, lock_period: i64| {
        let key = dynamic::key("MAX_DELEGATE_LOCK_PERIOD").unwrap();
        match maximum { Some(value) => session.store(StoreKind::DynamicProperties).put(key, &value.to_be_bytes()).unwrap(), None => session.store(StoreKind::DynamicProperties).delete(key).unwrap() }
        let contract = DelegateResourceContract { owner_address: OWNER.to_vec(), resource: ResourceCode::Bandwidth as i32, balance: 1_000_000, receiver_address: receiver.to_vec(), lock: true, lock_period };
        DelegateResourceActuator::new(any("protocol.DelegateResourceContract", &contract)).unwrap().validate(&ValidationContext::new(&session, ExecutionConfig::default(), None))
    };
    let unsupported = validate(None, -1); assert!(unsupported.is_ok(), "unsupported chains ignore the submitted period: {unsupported:?}");
    assert!(validate(Some(DEFAULT), -1).is_err());
    assert!(validate(Some(DEFAULT), 0).is_ok());
    assert!(validate(Some(DEFAULT), DEFAULT + 1).is_err());
    assert!(validate(Some(DEFAULT + 1), DEFAULT).is_ok());
    assert!(validate(Some(DEFAULT + 1), DEFAULT + 1).is_ok());
    session.revoke().unwrap(); drop(manager); fs::remove_dir_all(directory).unwrap();
}
