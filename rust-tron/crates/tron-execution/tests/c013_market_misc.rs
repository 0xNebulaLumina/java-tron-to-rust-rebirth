#[path = "support/c013_replay.rs"]
mod c013_replay;

use std::{fs,path::PathBuf,time::{SystemTime,UNIX_EPOCH}};
use prost::Message;
use tron_execution::{Actuator,ActuatorRegistry,ActuatorResult,ClearAbiActuator,ExecutionConfig,MarketCancelOrderActuator,MarketSellAssetActuator,RegistryError,UpdateBrokerageActuator,UpdateEnergyLimitActuator,UpdateSettingActuator};
use tron_protocol::{google::protobuf::Any,protocol::{smart_contract::Abi,Account,ClearAbiContract,MarketOrder,MarketSellAssetContract,SmartContract,UpdateBrokerageContract,UpdateEnergyLimitContract,UpdateSettingContract,Witness}};
use tron_state::{dynamic,market::{pair_key,pair_price_head_key,pair_price_key},Session,SessionManager,StateStore,StoreKind};use tron_storage::{market_total_cmp,OpenRequirements,StorageIdentity,StorageManager};
const OWNER:[u8;21]=[0x41;21];const MAKER:[u8;21]=[0x41,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42];const CONTRACT:[u8;21]=[0x41,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43];const TOKEN:&[u8]=b"1000001";const ORACLE:&str=include_str!("../../../../docs/oracles/c013-market-misc-real.v1.json");
fn path(n:&str)->PathBuf{std::env::temp_dir().join(format!("c013-mm-{n}-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()))}fn manager(n:&str)->(PathBuf,SessionManager){let p=path(n);let r=OpenRequirements{identity:StorageIdentity{network:"c013".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]};(p.clone(),SessionManager::new(StateStore::new(StorageManager::new(r).open_store(&p).unwrap())))}fn long(s:&Session,n:&str,v:i64){s.store(StoreKind::DynamicProperties).put(dynamic::key(n).unwrap(),&v.to_be_bytes()).unwrap()}fn any<M:Message>(n:&str,m:&M)->Any{Any{type_url:format!("type.googleapis.com/{n}"),value:m.encode_to_vec()}}
fn setup(s:&Session){for(n,v)in[("ALLOW_MARKET_TRANSACTION",1),("MARKET_SELL_FEE",10),("MARKET_CANCEL_FEE",5),("MARKET_QUANTITY_LIMIT",1_000_000),("LATEST_BLOCK_HEADER_TIMESTAMP",1234),("ALLOW_BLACKHOLE_OPTIMIZATION",1),("BURN_TRX_AMOUNT",0),("ALLOW_TVM_CONSTANTINOPLE",1)]{long(s,n,v)}for(address,balance,tokens)in[(OWNER,10_000,1_000),(MAKER,10_000,1_000)]{let mut a=Account{address:address.to_vec(),balance,..Default::default()};a.asset_v2.insert("1000001".into(),tokens);s.store(StoreKind::Account).put(&address,&a.encode_to_vec()).unwrap()}s.store(StoreKind::AssetIssueV2).put(TOKEN,b"exists").unwrap();s.store(StoreKind::Witness).put(&OWNER,&Witness{address:OWNER.to_vec(),..Default::default()}.encode_to_vec()).unwrap();s.store(StoreKind::Contract).put(&CONTRACT,&SmartContract{contract_address:CONTRACT.to_vec(),origin_address:OWNER.to_vec(),origin_energy_limit:1,consume_user_resource_percent:10,..Default::default()}.encode_to_vec()).unwrap();s.store(StoreKind::Abi).put(&CONTRACT,&Abi::default().encode_to_vec()).unwrap()}
#[test]
fn pinned_java_storage_messages_are_explicitly_unsupported_transaction_types() {
    let oracle:serde_json::Value=serde_json::from_str(ORACLE).unwrap();
    assert_eq!(oracle["schema"],"c013-market-misc-real.v1");
    let compatibility=&oracle["storage_contract_compatibility"];
    assert_eq!(compatibility["decision"],"unsupported_transaction_contract_types");
    assert_eq!(compatibility["rust_rejection"].as_array().unwrap().len(),3);
    let registry=ActuatorRegistry::empty();
    for (index,(message,kind)) in [
        ("protocol.BuyStorageContract",21),
        ("protocol.BuyStorageBytesContract",22),
        ("protocol.SellStorageContract",23),
    ].into_iter().enumerate() {
        let evidence=&compatibility["rust_rejection"][index];
        assert_eq!(evidence["message"],message);
        assert_eq!(evidence["legacy_numeric_type"],kind);
        assert_eq!(evidence["registry_error"],format!("InvalidContractType({kind})"));
        let contract=tron_protocol::protocol::transaction::Contract{
            r#type:kind,
            parameter:Some(Any{type_url:format!("type.googleapis.com/{message}"),value:Vec::new()}),
            ..Default::default()
        };
        assert!(matches!(registry.decode(&contract),Err(RegistryError::InvalidContractType(actual)) if actual==kind));
        assert!(matches!(registry.owner_address(&contract),Err(RegistryError::InvalidContractType(actual)) if actual==kind));
        assert!(matches!(registry.actuator(&contract),Err(RegistryError::InvalidContractType(actual)) if actual==kind));
    }
}
#[test]fn market_sell_match_cancel_and_twenty_first_attempt_roll_back(){let(p,m)=manager("market");let mut s=m.build_session().unwrap();setup(&s);let maker=MarketSellAssetContract{owner_address:MAKER.to_vec(),sell_token_id:TOKEN.to_vec(),sell_token_quantity:100,buy_token_id:b"_".to_vec(),buy_token_quantity:200};let mut mr=ActuatorResult::default();MarketSellAssetActuator::new(any("protocol.MarketSellAssetContract",&maker)).unwrap().execute(&s,Some(&mut mr),ExecutionConfig::default()).unwrap();let taker=MarketSellAssetContract{owner_address:OWNER.to_vec(),sell_token_id:b"_".to_vec(),sell_token_quantity:250,buy_token_id:TOKEN.to_vec(),buy_token_quantity:100};let mut tr=ActuatorResult::default();MarketSellAssetActuator::new(any("protocol.MarketSellAssetContract",&taker)).unwrap().execute(&s,Some(&mut tr),ExecutionConfig::default()).unwrap();assert_eq!(tr.order_details.len(),1);let remaining=MarketOrder::decode(s.store(StoreKind::MarketOrder).get(&tr.order_id).unwrap().as_slice()).unwrap();let cancel=tron_protocol::protocol::MarketCancelOrderContract{owner_address:OWNER.to_vec(),order_id:remaining.order_id.clone()};MarketCancelOrderActuator::new(any("protocol.MarketCancelOrderContract",&cancel)).unwrap().execute(&s,Some(&mut ActuatorResult::default()),ExecutionConfig::default()).unwrap();assert_eq!(MarketOrder::decode(s.store(StoreKind::MarketOrder).get(&remaining.order_id).unwrap().as_slice()).unwrap().state,2);s.revoke().unwrap();drop(m);fs::remove_dir_all(p).unwrap()}
#[test]fn twenty_first_match_attempt_restores_every_store(){let(p,m)=manager("rollback");let mut s=m.build_session().unwrap();setup(&s);for _ in 0..21{let maker=MarketSellAssetContract{owner_address:MAKER.to_vec(),sell_token_id:TOKEN.to_vec(),sell_token_quantity:1,buy_token_id:b"_".to_vec(),buy_token_quantity:1};MarketSellAssetActuator::new(any("protocol.MarketSellAssetContract",&maker)).unwrap().execute(&s,Some(&mut ActuatorResult::default()),ExecutionConfig::default()).unwrap()}let before=[StoreKind::Account,StoreKind::MarketAccount,StoreKind::MarketOrder,StoreKind::MarketPairToPrice,StoreKind::MarketPairPriceToOrder,StoreKind::DynamicProperties].map(|kind|(kind,s.store(kind).view()));let taker=MarketSellAssetContract{owner_address:OWNER.to_vec(),sell_token_id:b"_".to_vec(),sell_token_quantity:21,buy_token_id:TOKEN.to_vec(),buy_token_quantity:21};let error=MarketSellAssetActuator::new(any("protocol.MarketSellAssetContract",&taker)).unwrap().execute(&s,Some(&mut ActuatorResult::default()),ExecutionConfig::default()).unwrap_err();assert_eq!(error.message,"Too many matches. MAX_MATCH_NUM = 20");for(kind,view)in before{assert_eq!(s.store(kind).view(),view)}s.revoke().unwrap();drop(m);fs::remove_dir_all(p).unwrap()}
#[test]
fn adversarial_many_price_levels_use_a_twenty_one_level_bounded_read() {
    let (p,m)=manager("bounded-levels");
    let s=m.build_session().unwrap();
    let pair=pair_key(TOKEN,b"_").unwrap();
    let head=pair_price_head_key(TOKEN,b"_").unwrap();
    let store=s.store(StoreKind::MarketPairPriceToOrder);
    store.put(&head,b"head").unwrap();
    let mut expected=Vec::new();
    for sell in 1..=4096 {
        let key=pair_price_key(TOKEN,b"_",sell,4097-sell).unwrap().to_vec();
        store.put(&key,b"level").unwrap();
        expected.push(key);
    }
    expected.sort_by(|left,right|market_total_cmp(left,right));
    expected.truncate(21);
    let start=std::sync::Arc::new(std::sync::Barrier::new(2));
    let competing_store=store.clone();
    let competing_pair=pair.clone();
    let competing_head=head.clone();
    let query=std::thread::scope(|scope|{
        let competing_start=start.clone();
        let competing=scope.spawn(move||{
            competing_start.wait();
            competing_store.market_ordered(&competing_pair,&competing_head,4096).unwrap()
        });
        start.wait();
        let query=store.market_ordered(&pair,&head,21).unwrap();
        assert_eq!(competing.join().unwrap().rows.len(),4096);
        query
    });
    let visited=query.visited;
    let actual=query.rows.into_iter().map(|(key,_)|key).collect::<Vec<_>>();
    assert_eq!(actual,expected);
    assert_eq!(actual.len(),21);
    assert!(visited <= 64, "market cursor visited {visited} entries");
    drop(s);drop(m);fs::remove_dir_all(p).unwrap();
}
#[test]fn brokerage_setting_energy_and_clear_abi_update_linked_stores(){let(p,m)=manager("misc");let mut s=m.build_session().unwrap();setup(&s);UpdateBrokerageActuator::new(any("protocol.UpdateBrokerageContract",&UpdateBrokerageContract{owner_address:OWNER.to_vec(),brokerage:25})).unwrap().execute(&s,Some(&mut ActuatorResult::default()),ExecutionConfig::default()).unwrap();UpdateSettingActuator::new(any("protocol.UpdateSettingContract",&UpdateSettingContract{owner_address:OWNER.to_vec(),contract_address:CONTRACT.to_vec(),consume_user_resource_percent:55})).unwrap().execute(&s,Some(&mut ActuatorResult::default()),ExecutionConfig::default()).unwrap();UpdateEnergyLimitActuator::new(any("protocol.UpdateEnergyLimitContract",&UpdateEnergyLimitContract{owner_address:OWNER.to_vec(),contract_address:CONTRACT.to_vec(),origin_energy_limit:999})).unwrap().execute(&s,Some(&mut ActuatorResult::default()),ExecutionConfig::default()).unwrap();ClearAbiActuator::new(any("protocol.ClearABIContract",&ClearAbiContract{owner_address:OWNER.to_vec(),contract_address:CONTRACT.to_vec()})).unwrap().execute(&s,Some(&mut ActuatorResult::default()),ExecutionConfig::default()).unwrap();let c=SmartContract::decode(s.store(StoreKind::Contract).get(&CONTRACT).unwrap().as_slice()).unwrap();assert_eq!((c.consume_user_resource_percent,c.origin_energy_limit),(55,999));assert_eq!(s.store(StoreKind::Abi).get(&CONTRACT),Some(Abi::default().encode_to_vec()));s.revoke().unwrap();drop(m);fs::remove_dir_all(p).unwrap()}

#[test]
fn instrumented_java_market_misc_invocations_replay_exactly() {
    let replay = c013_replay::replay("market_misc");
    assert_eq!(replay.captured_invocations, 926);
    assert_eq!(replay.total_unique, 868);
    assert_eq!(replay.executed_unique, 467);
    assert_eq!(replay.explicit_exclusions, 0);
}

#[test]
fn zero_invocation_java_helpers_have_explicit_rust_dispositions() {
    assert_eq!(c013_replay::prove_zero_invocation_methods("market_misc"), 2);
}
