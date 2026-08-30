use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use tron_protocol::protocol::{Account, MarketAccountOrder, MarketOrder, MarketOrderIdList};
use tron_state::account_asset::all_assets;
use tron_state::dynamic::{DynamicPropertyConfig, initialize_missing, key};
use tron_state::market::{LinkedOrder, MarketCodecError, MarketStoreError, append_market_order, append_order, gcd, market_price_count, market_price_keys, market_prices, pair_key, pair_price_head_key, pair_price_key, unlink_market_order, unlink_order};
use tron_state::{StateStore, StoreKind, physical_key};
use tron_storage::{OpenRequirements, RustLogOptions, StorageIdentity, StorageManager, WriteBatch, WriteFaultInjector, WritePhase};

const PRECOMMIT: [WritePhase; 3] = [WritePhase::Append, WritePhase::Flush, WritePhase::Sync];
fn path(name: &str) -> PathBuf { let nonce=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(); std::env::temp_dir().join(format!("tron-state-{name}-{}-{nonce}",std::process::id())) }
fn manager() -> StorageManager { StorageManager::new(OpenRequirements { identity:StorageIdentity{network:"c008".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()] }) }
fn sync_manager() -> StorageManager { let options=RustLogOptions{sync_on_write:true,compact_after_bytes:0,..RustLogOptions::default()}; StorageManager::with_options(OpenRequirements { identity:StorageIdentity{network:"c008".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()] },options).unwrap() }
struct FailAt(WritePhase);
impl WriteFaultInjector for FailAt { fn before(&self,phase:WritePhase)->io::Result<()> { if phase==self.0 {Err(io::Error::other(format!("injected {phase:?} crash")))}else{Ok(())} } }

#[test]
fn cross_store_batch_is_atomic_and_reopens() {
    let directory=path("batch-reopen"); let state=StateStore::new(manager().open_store(&directory).unwrap());
    let mut batch=state.batch(); batch.put(&StoreKind::Account.name(),b"alice",b"account").put(&StoreKind::DynamicProperties.name(),b"flag",b"\x01"); batch.commit().unwrap();
    drop(state); let reopened=StateStore::new(manager().open_store(&directory).unwrap());
    assert_eq!(reopened.store(StoreKind::Account).get(b"alice"),Some(b"account".to_vec())); assert_eq!(reopened.store(StoreKind::DynamicProperties).get(b"flag"),Some(b"\x01".to_vec()));
    drop(reopened); fs::remove_dir_all(directory).unwrap();
}

fn assert_crash_atomic(name:&str,batch:WriteBatch,checks:&[(StoreKind,&[u8])]) {
    for phase in PRECOMMIT {
        let directory=path(&format!("{name}-{phase:?}")); let state=StateStore::new(sync_manager().open_store(&directory).unwrap());
        assert!(state.shared_log().lock().unwrap().write_with_faults(batch.clone(),&FailAt(phase)).is_err());
        for (kind,key) in checks { assert_eq!(state.store(*kind).get(key),None,"{phase:?} {kind:?}"); }
        drop(state); let reopened=StateStore::new(manager().open_store(&directory).unwrap());
        for (kind,key) in checks { assert_eq!(reopened.store(*kind).get(key),None,"reopen {phase:?} {kind:?}"); }
        drop(reopened); fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn c007_precommit_crash_matrix_keeps_cross_store_batch_atomic() {
    let mut batch=WriteBatch::new(); batch.put(physical_key(&StoreKind::Account.name(),b"alice"),b"account".to_vec()); batch.put(physical_key(&StoreKind::DynamicProperties.name(),b"flag"),b"\x01".to_vec());
    assert_crash_atomic("cross-store",batch,&[(StoreKind::Account,b"alice"),(StoreKind::DynamicProperties,b"flag")]);
}

#[test]
fn market_linked_updates_are_atomic_across_crashes() {
    let mut head=Vec::new(); let mut tail=Vec::new(); let mut first=LinkedOrder{id:b"first".to_vec(),..Default::default()}; let mut second=LinkedOrder{id:b"second".to_vec(),..Default::default()}; let mut third=LinkedOrder{id:b"third".to_vec(),..Default::default()};
    append_order(&mut head,&mut tail,&mut first,None); append_order(&mut head,&mut tail,&mut second,Some(&mut first)); append_order(&mut head,&mut tail,&mut third,Some(&mut second)); unlink_order(&mut head,&mut tail,&mut second,Some(&mut first),Some(&mut third));
    assert_eq!(first.next,b"third"); assert_eq!(third.prev,b"first");
    let mut batch=WriteBatch::new(); batch.put(physical_key(&StoreKind::MarketOrder.name(),b"first"),first.next.clone()); batch.put(physical_key(&StoreKind::MarketOrder.name(),b"third"),third.prev.clone()); batch.put(physical_key(&StoreKind::MarketAccount.name(),b"head"),head);
    assert_crash_atomic("market",batch,&[(StoreKind::MarketOrder,b"first"),(StoreKind::MarketOrder,b"third"),(StoreKind::MarketAccount,b"head")]);
}

fn account(address_byte: u8, assets: &[(&str, i64)]) -> Account {
    let mut account = Account::default();
    account.address = [vec![0x41], vec![address_byte; 20]].concat();
    account.asset_v2.extend(assets.iter().map(|(key, value)| ((*key).to_owned(), *value)));
    account
}

#[test]
fn account_external_assets_persist_and_reopen() {
    let directory=path("account-assets"); let state=StateStore::new(manager().open_store(&directory).unwrap());
    let original=account(1,&[("1000001",7),("1000002",0)]); state.replace_account_assets(&original).unwrap(); drop(state);
    let reopened=StateStore::new(manager().open_store(&directory).unwrap());
    let stored=Account::decode(reopened.store(StoreKind::Account).get(&original.address).unwrap().as_slice()).unwrap();
    assert_eq!(reopened.all_account_assets(&stored).unwrap(),[("1000001".to_owned(),7)].into());
    assert_eq!(all_assets(&stored,|prefix|reopened.store(StoreKind::AccountAsset).prefix(prefix)).unwrap().len(),1);
    drop(reopened); fs::remove_dir_all(directory).unwrap();
}

#[test]
fn account_external_assets_are_atomic_across_crashes() {
    let mut stored=account(1,&[]); stored.asset_optimized=true;
    let address=stored.address.clone(); let asset_key=[address.as_slice(),b"1000001"].concat();
    let mut batch=WriteBatch::new();
    batch.put(physical_key(&StoreKind::Account.name(),&address),stored.encode_to_vec());
    batch.put(physical_key(&StoreKind::AccountAsset.name(),&asset_key),7_i64.to_be_bytes().to_vec());
    assert_crash_atomic("account-assets",batch,&[(StoreKind::Account,&address),(StoreKind::AccountAsset,&asset_key)]);
}

fn order(id:&[u8])->MarketOrder { MarketOrder { order_id:id.to_vec(),owner_address:b"owner".to_vec(),create_time:7,sell_token_id:b"1000001".to_vec(),sell_token_quantity:6,buy_token_id:b"1000002".to_vec(),buy_token_quantity:4,sell_token_quantity_remain:6,..Default::default() } }

#[test]
fn market_codec_returns_errors_and_uses_java_boundary_arithmetic() {
    assert!(matches!(pair_key(&[0;20],b"1"),Err(MarketCodecError::TokenIdTooLong{actual:20,..})));
    assert!(matches!(pair_price_key(b"1",b"2",0,1),Err(MarketCodecError::InvalidQuantity{..})));
    assert_eq!(gcd(i64::MIN,-1),-1); assert_eq!(gcd(i64::MIN,i64::MIN),i64::MIN);
}

#[test]
fn market_prices_use_java_logical_order_before_count_limit() {
    let directory=path("market-price-order"); let state=StateStore::new(manager().open_store(&directory).unwrap());
    let sell=b"1000001"; let buy=b"1000002"; let head=pair_price_head_key(sell,buy).unwrap();
    let lexicographically_first=pair_price_key(sell,buy,1,2).unwrap();
    let middle=pair_price_key(sell,buy,2,3).unwrap();
    let logically_first=pair_price_key(sell,buy,3,4).unwrap();
    let store=state.store(StoreKind::MarketPairPriceToOrder);
    store.put(&head,&[]).unwrap(); store.put(&lexicographically_first,&[]).unwrap(); store.put(&middle,&[]).unwrap(); store.put(&logically_first,&[]).unwrap();
    assert_eq!(market_price_keys(&state,sell,buy,2).unwrap(),vec![logically_first.to_vec(),middle.to_vec()]);
    let prices=market_prices(&state,sell,buy,2).unwrap().prices.into_iter().map(|price|(price.sell_token_quantity,price.buy_token_quantity)).collect::<Vec<_>>();
    assert_eq!(prices,vec![(3,4),(2,3)]);
    drop(state); fs::remove_dir_all(directory).unwrap();
}

#[test]
fn market_order_account_and_pair_stores_unlink_and_reopen() {
    let directory=path("market-persist"); let state=StateStore::new(manager().open_store(&directory).unwrap());
    append_market_order(&state,order(b"first")).unwrap(); append_market_order(&state,order(b"second")).unwrap();
    unlink_market_order(&state,b"first").unwrap(); drop(state);
    let reopened=StateStore::new(manager().open_store(&directory).unwrap());
    assert!(reopened.store(StoreKind::MarketOrder).get(b"first").is_none());
    let second=MarketOrder::decode(reopened.store(StoreKind::MarketOrder).get(b"second").unwrap().as_slice()).unwrap(); assert!(second.prev.is_empty()&&second.next.is_empty());
    let account=MarketAccountOrder::decode(reopened.store(StoreKind::MarketAccount).get(b"owner").unwrap().as_slice()).unwrap(); assert_eq!(account.orders,vec![b"second".to_vec()]); assert_eq!((account.count,account.total_count),(1,2));
    let pair=pair_key(b"1000001",b"1000002").unwrap(); assert_eq!(reopened.store(StoreKind::MarketPairToPrice).get(&pair),Some(1_i64.to_be_bytes().to_vec()));
    let head_key=pair_price_head_key(b"1000001",b"1000002").unwrap(); assert_eq!(reopened.store(StoreKind::MarketPairPriceToOrder).get(&head_key),Some(Vec::new())); let price_key=pair_price_key(b"1000001",b"1000002",6,4).unwrap(); assert_eq!(market_price_keys(&reopened,b"1000001",b"1000002",10).unwrap(),vec![price_key.to_vec()]); assert_eq!(market_prices(&reopened,b"1000001",b"1000002",10).unwrap().prices.len(),1); let ids=MarketOrderIdList::decode(reopened.store(StoreKind::MarketPairPriceToOrder).get(&price_key).unwrap().as_slice()).unwrap(); assert_eq!((ids.head,ids.tail),(b"second".to_vec(),b"second".to_vec()));
    drop(reopened); fs::remove_dir_all(directory).unwrap();
}

#[test]
fn market_unlink_rejects_wrong_backlinks_without_writes() {
    let directory=path("market-backlink"); let state=StateStore::new(manager().open_store(&directory).unwrap()); append_market_order(&state,order(b"first")).unwrap(); append_market_order(&state,order(b"second")).unwrap();
    let mut first=MarketOrder::decode(state.store(StoreKind::MarketOrder).get(b"first").unwrap().as_slice()).unwrap(); first.next=b"wrong".to_vec(); state.store(StoreKind::MarketOrder).put(b"first",&first.encode_to_vec()).unwrap();
    let pair=pair_key(b"1000001",b"1000002").unwrap(); let price_key=pair_price_key(b"1000001",b"1000002",6,4).unwrap(); let head_key=pair_price_head_key(b"1000001",b"1000002").unwrap();
    let before=[(StoreKind::MarketOrder,b"first".as_slice()),(StoreKind::MarketOrder,b"second".as_slice()),(StoreKind::MarketAccount,b"owner".as_slice()),(StoreKind::MarketPairToPrice,pair.as_slice()),(StoreKind::MarketPairPriceToOrder,price_key.as_slice()),(StoreKind::MarketPairPriceToOrder,head_key.as_slice())].map(|(kind,key)|(kind,key.to_vec(),state.store(kind).get(key)));
    assert!(matches!(unlink_market_order(&state,b"second"),Err(MarketStoreError::WrongNeighbor{order,neighbor}) if order==b"second" && neighbor==b"first"));
    for (kind,key,value) in before { assert_eq!(state.store(kind).get(&key),value); }
    drop(state); fs::remove_dir_all(directory).unwrap();
}

#[test]
fn market_unlink_rejects_cycles_without_writes() {
    let directory=path("market-cycle"); let state=StateStore::new(manager().open_store(&directory).unwrap()); append_market_order(&state,order(b"first")).unwrap();
    let mut first=MarketOrder::decode(state.store(StoreKind::MarketOrder).get(b"first").unwrap().as_slice()).unwrap(); first.next=b"first".to_vec(); state.store(StoreKind::MarketOrder).put(b"first",&first.encode_to_vec()).unwrap();
    assert!(matches!(unlink_market_order(&state,b"first"),Err(MarketStoreError::Cycle(id)) if id==b"first")); assert!(state.store(StoreKind::MarketOrder).contains_key(b"first"));
    drop(state); fs::remove_dir_all(directory).unwrap();
}

#[test]
fn market_pair_count_is_exact_java_signed_i64_and_removes_head_with_last_price() {
    let directory=path("market-count"); let state=StateStore::new(manager().open_store(&directory).unwrap()); append_market_order(&state,order(b"only")).unwrap();
    let pair=pair_key(b"1000001",b"1000002").unwrap(); let head=pair_price_head_key(b"1000001",b"1000002").unwrap(); assert_eq!(state.store(StoreKind::MarketPairToPrice).get(&pair).unwrap(),vec![0,0,0,0,0,0,0,1]); assert_eq!(market_price_count(&state,b"1000001",b"1000002").unwrap(),1); assert!(state.store(StoreKind::MarketPairPriceToOrder).contains_key(&head));
    unlink_market_order(&state,b"only").unwrap(); assert!(!state.store(StoreKind::MarketPairToPrice).contains_key(&pair)); assert!(!state.store(StoreKind::MarketPairPriceToOrder).contains_key(&head)); drop(state); fs::remove_dir_all(directory).unwrap();
}

#[test]
fn market_tail_mutation_ignores_large_unrelated_chain_and_touches_constant_neighbors() {
    let directory=path("market-constant-neighbors"); let state=StateStore::new(manager().open_store(&directory).unwrap()); let price_key=pair_price_key(b"1000001",b"1000002",6,4).unwrap(); let pair=pair_key(b"1000001",b"1000002").unwrap(); let head_key=pair_price_head_key(b"1000001",b"1000002").unwrap();
    let count=10_000usize; let ids=(0..count).map(|index|format!("seed-{index:05}").into_bytes()).collect::<Vec<_>>(); for (index,id) in ids.iter().enumerate() { let mut seeded=order(id); seeded.owner_address=b"seed-owner".to_vec(); if index>0 { seeded.prev=ids[index-1].clone(); } if index+1<count { seeded.next=ids[index+1].clone(); } state.store(StoreKind::MarketOrder).put(id,&seeded.encode_to_vec()).unwrap(); }
    state.store(StoreKind::MarketPairPriceToOrder).put(&price_key,&MarketOrderIdList{head:ids[0].clone(),tail:ids[count-1].clone()}.encode_to_vec()).unwrap(); state.store(StoreKind::MarketPairPriceToOrder).put(&head_key,&[]).unwrap(); state.store(StoreKind::MarketPairToPrice).put(&pair,&1_i64.to_be_bytes()).unwrap(); let mut corrupt=MarketOrder::decode(state.store(StoreKind::MarketOrder).get(&ids[count/2]).unwrap().as_slice()).unwrap(); corrupt.prev=b"unrelated-corruption".to_vec(); state.store(StoreKind::MarketOrder).put(&corrupt.order_id,&corrupt.encode_to_vec()).unwrap();
    append_market_order(&state,order(b"new-tail")).unwrap(); unlink_market_order(&state,b"new-tail").unwrap(); let tail=MarketOrder::decode(state.store(StoreKind::MarketOrder).get(&ids[count-1]).unwrap().as_slice()).unwrap(); assert!(tail.next.is_empty()); assert!(state.store(StoreKind::MarketOrder).contains_key(&ids[count/2])); drop(state); fs::remove_dir_all(directory).unwrap();
}

#[test]
fn market_pair_count_head_and_price_level_are_atomic_across_crash_reopen() {
    let pair=pair_key(b"1000001",b"1000002").unwrap(); let head=pair_price_head_key(b"1000001",b"1000002").unwrap(); let price=pair_price_key(b"1000001",b"1000002",6,4).unwrap(); let mut batch=WriteBatch::new(); batch.put(physical_key(&StoreKind::MarketPairToPrice.name(),&pair),1_i64.to_be_bytes().to_vec()); batch.put(physical_key(&StoreKind::MarketPairPriceToOrder.name(),&head),Vec::new()); batch.put(physical_key(&StoreKind::MarketPairPriceToOrder.name(),&price),MarketOrderIdList{head:b"one".to_vec(),tail:b"one".to_vec()}.encode_to_vec()); assert_crash_atomic("market-price-level",batch,&[(StoreKind::MarketPairToPrice,&pair),(StoreKind::MarketPairPriceToOrder,&head),(StoreKind::MarketPairPriceToOrder,&price)]);
}

#[test]
fn dynamic_defaults_are_idempotent_and_preserve_existing_values() {
    let directory=path("dynamic-defaults"); let state=StateStore::new(manager().open_store(&directory).unwrap());
    let properties=state.store(StoreKind::DynamicProperties);
    properties.put(key("TOTAL_SIGN_NUM").unwrap(),b"preserved").unwrap();
    let config=DynamicPropertyConfig { maintenance_time_interval:123,allow_multi_sign:1,memo_fee:7,..Default::default() };
    assert!(initialize_missing(&properties,&config,456,b"active-ops").unwrap()>0);
    assert_eq!(properties.get(key("TOTAL_SIGN_NUM").unwrap()),Some(b"preserved".to_vec()));
    assert_eq!(properties.get(key("MAINTENANCE_TIME_INTERVAL").unwrap()),Some(123_i64.to_be_bytes().to_vec()));
    assert_eq!(properties.get(key("NEXT_MAINTENANCE_TIME").unwrap()),Some(456_i64.to_be_bytes().to_vec()));
    assert_eq!(properties.get(key("ACTIVE_DEFAULT_OPERATIONS").unwrap()),Some(b"active-ops".to_vec()));
    assert_eq!(properties.get(key("ALLOW_SAME_TOKEN_NAME").unwrap()),Some(0_i64.to_be_bytes().to_vec()));
    assert_eq!(initialize_missing(&properties,&DynamicPropertyConfig::default(),999,b"replacement").unwrap(),0);
    assert_eq!(properties.get(key("NEXT_MAINTENANCE_TIME").unwrap()),Some(456_i64.to_be_bytes().to_vec()));
    assert_eq!(properties.get(key("ACTIVE_DEFAULT_OPERATIONS").unwrap()),Some(b"active-ops".to_vec()));
    drop(state); fs::remove_dir_all(directory).unwrap();
}

#[test]
fn dynamic_memo_history_repairs_from_persisted_fee_without_overwriting_it() {
    let directory=path("dynamic-memo-repair"); let state=StateStore::new(manager().open_store(&directory).unwrap());
    let properties=state.store(StoreKind::DynamicProperties); let persisted_fee=29_i64.to_be_bytes();
    properties.put(key("MEMO_FEE").unwrap(),&persisted_fee).unwrap();
    initialize_missing(&properties,&DynamicPropertyConfig{memo_fee:7,..Default::default()},0,b"").unwrap();
    assert_eq!(properties.get(key("MEMO_FEE").unwrap()),Some(persisted_fee.to_vec()));
    assert_eq!(properties.get(key("MEMO_FEE_HISTORY").unwrap()),Some(b"0:29".to_vec()));
    drop(state); fs::remove_dir_all(directory).unwrap();
}

#[test]
fn dynamic_memo_pair_precommit_failures_retry_to_a_consistent_default() {
    for phase in PRECOMMIT {
        let directory=path(&format!("dynamic-memo-pair-{phase:?}")); let state=StateStore::new(sync_manager().open_store(&directory).unwrap());
        let properties=state.store(StoreKind::DynamicProperties); let mut batch=properties.batch();
        batch.put(properties.name(),key("MEMO_FEE").unwrap(),&7_i64.to_be_bytes()).put(properties.name(),key("MEMO_FEE_HISTORY").unwrap(),b"0:7");
        assert!(batch.commit_with_faults(&FailAt(phase)).is_err()); drop(properties); drop(state);
        let reopened=StateStore::new(manager().open_store(&directory).unwrap()); let properties=reopened.store(StoreKind::DynamicProperties);
        assert_eq!(properties.get(key("MEMO_FEE").unwrap()),None); assert_eq!(properties.get(key("MEMO_FEE_HISTORY").unwrap()),None);
        initialize_missing(&properties,&DynamicPropertyConfig{memo_fee:7,..Default::default()},0,b"").unwrap();
        assert_eq!(properties.get(key("MEMO_FEE").unwrap()),Some(7_i64.to_be_bytes().to_vec()));
        assert_eq!(properties.get(key("MEMO_FEE_HISTORY").unwrap()),Some(b"0:7".to_vec()));
        drop(reopened); fs::remove_dir_all(directory).unwrap();
    }
}
