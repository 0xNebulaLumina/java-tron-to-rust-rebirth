use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::hash_map::DefaultHasher, hash::{Hash, Hasher}, net::SocketAddr, path::Path};
use tron_network::{
    app_hello::{apply_policy, validate_structure, HelloPolicy, LocalHello},
    app_message::AppMessageType,
    connection::Direction,
    peer::{BlockKey, InventoryItem, PeerConnection, PeerManager, RateWindow},
    stats::{need_to_log, InventoryKind},
};
use tron_protocol::protocol::{hello_message::BlockId, ReasonCode};

const CASES_JSON: &str = include_str!("../../../../docs/oracles/c021-cases-protocol-peer.v1.json");

#[derive(Deserialize)]
struct Manifest { schema:String, family:String, source_ledger:String, count:usize, cases:Vec<Case> }
#[derive(Deserialize)]
struct Case {
    stable_id:String, case_id:String, java_source:String, java_line:u32, java_symbol:String,
    owning_item:String, evidence_kind:String, source_assertion:SourceAssertion, operation:String,
    java_input:serde_json::Value, java_expected_result:String, java_expected_digest:String, rust_expected:String,
}
#[derive(Deserialize)]
struct SourceAssertion { declaration_kind:String, source_sha256:String, source_line_sha256:String, symbol:String }

fn block(byte:u8, number:i64)->BlockId { BlockId { hash:vec![byte;32], number } }
fn local()->LocalHello { LocalHello { node_id:vec![7;64], address_v4:b"127.0.0.1".to_vec(), address_v6:vec![], port:18888, version:1, timestamp:1_700_000_000_000, genesis:block(1,0), solid:block(2,90), head:block(3,100), node_type:0, lowest_block_num:0, code_version:b"4.7.4".to_vec(), address:vec![], signature:vec![] } }
fn peer(octet:u8,port:u16,direction:Direction)->PeerConnection { PeerConnection::new(SocketAddr::from(([127,0,0,octet],port)),direction,1_000) }
fn policy<'a>(duplicate_hello:bool,duplicate_peer:bool,identity_valid:bool,version:i32,genesis:&'a [u8],lowest:i64,solid_num:i64,effective:bool,on_chain:&'a dyn Fn(&BlockId)->bool)->HelloPolicy<'a>{HelloPolicy{version,genesis_hash:genesis,local_head_num:100,local_lowest_num:lowest,local_solid_num:solid_num,duplicate_hello,duplicate_peer,identity_valid,effective_peer:effective,solid_in_main_chain:on_chain}}
fn reason(result:Result<(),ReasonCode>)->String { match result { Ok(())=>"Ok".into(), Err(reason)=>format!("{reason:?}") } }
fn bools(values:&[bool])->String { values.iter().map(bool::to_string).collect::<Vec<_>>().join(",") }

fn observe_behavior(case:&Case)->String {
    assert_eq!(case.java_input["method"],case.java_symbol,"{} must pin its Java method",case.stable_id);
    match case.java_symbol.as_str() {
        "test" => { let limit=case.java_input["limit"].as_u64().unwrap() as u32;let mut registered=RateWindow::new(limit,0);let acquired=registered.allow(1,0);let within=registered.allow(1,0);let overflow=registered.allow(1,0);let mut unregistered=RateWindow::new(u32::MAX,0);bools(&[acquired,within,overflow,unregistered.allow(1,0)]) }
        "testVariableDefaultValue" => { let p=peer(1,1,Direction::Active);bools(&[p.bad_peer,p.fetch_able,p.is_idle(),p.relay_peer,p.need_sync_from_peer,p.need_sync_from_us,p.is_sync_finished()]) }
        "testOnDisconnect" => { let mut p=peer(1,1,Direction::Active);let item=InventoryItem{hash:[0;32],kind:0};p.remember_received(item.clone(),1);p.remember_spread(item,1);p.sync_to_fetch.push_back(BlockKey{hash:vec![],number:0});p.sync_requested.insert(BlockKey{hash:vec![],number:0},1);p.sync_in_process.insert(BlockKey{hash:vec![],number:0});p.cleanup();let s=p.cache_sizes();format!("{},{},{},{},{}",s.0,s.1,p.sync_to_fetch.len(),p.sync_requested.len(),p.sync_in_process.len()) }
        "testIsIdle" => { let mut p=peer(1,1,Direction::Active);let initial=p.is_idle();let item=InventoryItem{hash:[0;32],kind:0};p.adv_requests.insert(item.clone(),1);let request=p.is_idle();p.adv_requests.clear();let cleared=p.is_idle();p.sync_requested.insert(BlockKey{hash:vec![],number:0},1);let sync=p.is_idle();p.sync_requested.clear();let sync_cleared=p.is_idle();p.sync_chain_requested=Some((Default::default(),1));bools(&[initial,request,cleared,sync,sync_cleared,p.is_idle()]) }
        "testIsSyncIdle" => { let mut p=peer(1,1,Direction::Active);let initial=p.is_sync_idle();let item=InventoryItem{hash:[0;32],kind:0};p.adv_requests.insert(item,1);let request=p.is_sync_idle();p.adv_requests.clear();let cleared=p.is_sync_idle();p.sync_requested.insert(BlockKey{hash:vec![],number:0},1);let sync=p.is_sync_idle();p.sync_requested.clear();let sync_cleared=p.is_sync_idle();p.sync_chain_requested=Some((Default::default(),1));bools(&[initial,request,cleared,sync,sync_cleared,p.is_sync_idle()]) }
        "testOnConnect" => { let mut p=peer(1,1,Direction::Active);let mut out=Vec::new();for (local,remote) in [(2,1),(1,2),(1,1)]{p.need_sync_from_us=true;p.need_sync_from_peer=true;p.on_connected_heads(local,remote);out.push(format!("{},{}",p.need_sync_from_us,p.need_sync_from_peer));}out.join("|") }
        "testSetChannel" => { let mut p=peer(2,10001,Direction::Active);let first=p.relay_peer;p.relay_peer=p.address==SocketAddr::from(([127,0,0,2],10001));bools(&[first,p.relay_peer]) }
        "testIsSyncFinish" => { let mut p=peer(1,1,Direction::Active);let a=p.is_sync_finished();p.need_sync_from_us=false;let b=p.is_sync_finished();p.need_sync_from_peer=false;bools(&[a,b,p.is_sync_finished()]) }
        "testCheckAndPutAdvInvRequest" => { let mut p=peer(1,1,Direction::Active);let item=InventoryItem{hash:[0;32],kind:0};bools(&[p.check_and_put_request(item.clone(),1),p.check_and_put_request(item,1)]) }
        "testEquals" => { let p1=peer(2,10001,Direction::Active);let p2=peer(2,10002,Direction::Active);let p3=peer(2,10002,Direction::Passive);bools(&[p1==p1.clone(),p1==p2,p2==p3]) }
        "testHashCode" => { fn hash(p:&PeerConnection)->u64{let mut h=DefaultHasher::new();p.hash(&mut h);h.finish()}let p1=peer(2,10001,Direction::Active);let p2=peer(2,10002,Direction::Active);let p3=peer(2,10002,Direction::Passive);bools(&[hash(&p1)!=hash(&p2),hash(&p2)==hash(&p3)]) }
        "testNeedToLog" => bools(&[need_to_log(AppMessageType::Ping,None),need_to_log(AppMessageType::Pong,None),need_to_log(AppMessageType::Inventory,Some(InventoryKind::Transaction)),need_to_log(AppMessageType::Inventory,Some(InventoryKind::Block))]),
        "testAdd" => { let mut m=PeerManager::default();let p=peer(2,10001,Direction::Active);bools(&[m.add(p.clone()),m.add(p)]) }
        "testRemove" => { let mut m=PeerManager::default();let address=peer(2,10001,Direction::Active).address;let before=m.remove(address).is_some();m.add(peer(2,10001,Direction::Active));bools(&[before,m.remove(address).is_some()]) }
        "testGetPeerConnection" => { let mut m=PeerManager::default();let p=peer(2,10001,Direction::Active);let address=p.address;m.add(p);m.get(address).is_some().to_string() }
        "testGetPeers" => { let mut m=PeerManager::default();m.add(peer(1,10001,Direction::Active));let one=m.peers().len();m.add(peer(2,10001,Direction::Active));format!("{one},{}",m.peers().len()) }
        "testSortPeers" => { let mut m=PeerManager::default();let mut slow=peer(1,1,Direction::Active);slow.latency_ms=100_000;let mut fast=peer(2,2,Direction::Active);fast.latency_ms=1_000;m.add(slow);m.add(fast);m.sort_by_latency();m.peers()[0].latency_ms.to_string() }
        "testOkHelloMessage" => { let hello=local().build();let solid=hello.solid_block_id.clone().unwrap();let on_chain=|id:&BlockId|id==&solid;let g=vec![1;32];format!("{},{},{}",reason(apply_policy(&hello,&policy(false,false,true,1,&g,0,90,false,&on_chain))),reason(apply_policy(&hello,&policy(true,false,true,1,&g,0,90,false,&on_chain))),reason(apply_policy(&hello,&policy(false,true,true,1,&g,0,90,false,&on_chain)))) }
        "testInvalidHelloMessage" => { let mut hello=local().build();let head=validate_structure(&hello);hello.head_block_id.as_mut().unwrap().hash.pop();let bad_head=validate_structure(&hello);hello.head_block_id=Some(block(3,100));hello.genesis_block_id.as_mut().unwrap().hash.pop();let bad_genesis=validate_structure(&hello);hello.genesis_block_id=Some(block(1,0));hello.solid_block_id.as_mut().unwrap().hash.pop();bools(&[head,bad_head,bad_genesis,validate_structure(&hello)]) }
        "testInvalidHelloMessage2" => { let mut hello=local().build();let mut out=vec![validate_structure(&hello)];for field in ["address","signature","code_version"]{match field{"address"=>hello.address=vec![0;201],"signature"=>hello.signature=vec![0;201],_=>hello.code_version=vec![0;201]};out.push(validate_structure(&hello));match field{"address"=>hello.address=vec![0;200],"signature"=>hello.signature=vec![0;200],_=>hello.code_version=vec![0;200]};out.push(validate_structure(&hello));}bools(&out) }
        "testRelayHelloMessage" => { let mut hello=local().build();hello.address.clear();validate_structure(&hello).to_string() }
        "testLowAndGenesisBlockNum" => { let hello=local().build();let g=vec![1;32];let wrong=vec![9;32];let off_chain=|_:&BlockId|false;let mut low=hello.clone();low.lowest_block_num=101;format!("{},{},{},{}",reason(apply_policy(&low,&policy(false,false,true,1,&g,0,90,false,&off_chain))),reason(apply_policy(&hello,&policy(false,false,true,1,&wrong,0,90,false,&off_chain))),reason(apply_policy(&hello,&policy(false,false,true,1,&g,0,90,false,&off_chain))),reason(apply_policy(&hello,&policy(false,false,true,1,&g,91,90,false,&off_chain)))) }
        "testProcessHelloMessage" => { let mut hello=local().build();hello.head_block_id.as_mut().unwrap().hash.pop();let g=vec![1;32];let on_chain=|_:&BlockId|true;reason(apply_policy(&hello,&policy(false,false,true,1,&g,0,90,false,&on_chain))) }
        other=>panic!("unmapped Java behavior symbol {other}"),
    }
}

fn assert_declaration(case:&Case) {
    assert_eq!(case.source_assertion.symbol,case.java_symbol);
    assert!(matches!(case.source_assertion.declaration_kind.as_str(),"source-file"|"declaration"));
    let repo=Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3).unwrap();
    let source=std::fs::read(repo.join(&case.java_source)).unwrap();
    assert_eq!(hex::encode(Sha256::digest(&source)),case.source_assertion.source_sha256,"{} file provenance",case.stable_id);
    let line=source.split(|byte|*byte==b'\n').nth(case.java_line as usize-1).unwrap().strip_suffix(&[b'\r']).unwrap_or_else(||source.split(|byte|*byte==b'\n').nth(case.java_line as usize-1).unwrap());
    assert_eq!(hex::encode(Sha256::digest(line)),case.source_assertion.source_line_sha256,"{} line provenance",case.stable_id);
}

#[test]
fn every_protocol_peer_stable_row_executes_its_exact_family_contract() {
    let manifest:Manifest=serde_json::from_str(CASES_JSON).unwrap();
    assert_eq!(manifest.schema,"c021-cases-protocol-peer.v1");assert_eq!(manifest.family,"protocol-peer");assert_eq!(manifest.source_ledger,"docs/oracles/c021-ownership-reconciliation.v1.json");assert_eq!(manifest.count,manifest.cases.len());assert_eq!(manifest.count,151);
    let mut ids=std::collections::HashSet::new();
    for case in &manifest.cases {
        assert!(ids.insert(&case.stable_id),"duplicate {}",case.stable_id);assert_eq!(case.case_id,format!("C021-PP-{}",case.stable_id.split_once('-').unwrap().1));assert!(case.java_source.starts_with("java-tron/"));assert!(case.java_line>0);assert!(matches!(case.owning_item.as_str(),"C021.01"|"C021.02"|"C021.03"|"C021.08"));assert_eq!(case.java_input["operation"],case.operation);
        if case.evidence_kind=="source_assertion" { assert_declaration(case);println!("C021_CASE_RESULT={}\tdeclaration:{}",case.stable_id,case.source_assertion.source_line_sha256);continue }
        assert_eq!(case.evidence_kind,"java_test");assert_eq!(case.source_assertion.declaration_kind,"test-method");assert_declaration_test_hash(case);
        let actual=observe_behavior(case);assert_eq!(actual,case.rust_expected,"{} {}",case.stable_id,case.java_symbol);assert_eq!(actual,case.java_expected_result,"{}",case.stable_id);assert_eq!(hex::encode(Sha256::digest(actual.as_bytes())),case.java_expected_digest,"{}",case.stable_id);println!("C021_CASE_RESULT={}\t{}",case.stable_id,actual);
    }
}

fn assert_declaration_test_hash(case:&Case) {
    assert_eq!(case.source_assertion.symbol,case.java_symbol);
    let repo=Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3).unwrap();let source=std::fs::read(repo.join(&case.java_source)).unwrap();assert_eq!(hex::encode(Sha256::digest(&source)),case.source_assertion.source_sha256);let line=source.split(|byte|*byte==b'\n').nth(case.java_line as usize-1).unwrap();let line=line.strip_suffix(&[b'\r']).unwrap_or(line);assert_eq!(hex::encode(Sha256::digest(line)),case.source_assertion.source_line_sha256);
}

#[test]
fn refreshed_oldest_cache_entry_does_not_block_later_expiry() {
    let mut p=peer(1,1,Direction::Active);let oldest=InventoryItem{hash:[1;32],kind:0};let later=InventoryItem{hash:[2;32],kind:0};
    p.remember_received(oldest.clone(),0);p.remember_received(later.clone(),1_000);p.remember_received(oldest.clone(),2_000);
    assert!(!p.received_contains(&later,3_601_000));assert!(p.received_contains(&oldest,3_601_000));assert_eq!(p.cache_sizes().0,1);
}
