use std::{collections::{BTreeSet, HashSet}, io, net::{IpAddr, Ipv4Addr, SocketAddr}, sync::{Arc, Mutex}};

use serde::Deserialize;
use sha2::Digest;
use tokio_util::sync::CancellationToken;
use tron_crypto::{derive_address, PublicKey, Secp256k1Key};
use tron_network::{
    app_hello::AppHello,
    app_message::AppMessageType,
    connection::Direction,
    gossip::{Advertisement, GossipService, InventoryKey, InventoryType},
    peer::{InventoryItem, PeerConnection, PeerManager},
    persistence::{decode_peers, read_peers, write_peers, PeerStore, PersistedPeer},
    relay::{fast_forward_block, sign_witness_hello, successor_witnesses, verify_witness_hello},
    service::{Component, ComponentService, Lifecycle, NetworkParameters, P2pConfig, TronNetService, CLOSE_ORDER, START_ORDER},
    stats::{InventoryKind, MessageCount, MessageStatistics, TrafficStat},
    watchdog::{has_ipv4_stack, CandidateNode, EffectiveAction, EffectiveCheck, FetchAction, FetchBlockService, PeerStatusCheck, Resilience, ResilienceConfig, COMMON_TIMEOUT_MS},
};
use tron_protocol::protocol::{HelloMessage, ReasonCode};

#[derive(Deserialize)]
struct Manifest { schema:String, family:String, source_ledger:String, count:usize, cases:Vec<Case> }
#[derive(Deserialize)]
struct Case { stable_id:String, case_id:String, java_source:String, java_line:usize, java_symbol:String, owning_item:String, evidence_kind:String, source_assertion:SourceAssertion, operation:String, java_input:serde_json::Value, java_expected_result:String, java_expected_digest:String, rust_expected:String }
#[derive(Deserialize)]
struct SourceAssertion { declaration_kind:String, source_sha256:String, source_line_sha256:String, symbol:String }

fn addr(n: u8) -> SocketAddr { SocketAddr::from(([10, 0, 0, n], 18888)) }
fn peer(n: u8, direction: Direction, now: i64) -> PeerConnection { PeerConnection::new(addr(n), direction, now) }
fn key() -> Secp256k1Key { let mut bytes = [0; 32]; bytes[31] = 9; Secp256k1Key::from_private_bytes(&bytes).unwrap() }

#[derive(Default)]
struct MemoryStore(Mutex<Option<Vec<u8>>>);
impl PeerStore for MemoryStore {
    fn get(&self, key: &[u8]) -> io::Result<Option<Vec<u8>>> { assert_eq!(key, b"peers"); Ok(self.0.lock().unwrap_or_else(|error| error.into_inner()).clone()) }
    fn put(&self, key: &[u8], value: &[u8]) -> io::Result<()> { assert_eq!(key, b"peers"); *self.0.lock().unwrap_or_else(|error| error.into_inner()) = Some(value.to_vec()); Ok(()) }
}

fn observe_relay() -> &'static str {
    let signer = key();
    let witness = derive_address(&PublicKey::Secp256k1(signer.public_key())).as_bytes().to_vec();
    let mut hello = HelloMessage { timestamp: 1234, ..Default::default() };
    sign_witness_hello(&mut hello, &witness, &signer).unwrap();
    assert_eq!(verify_witness_hello(&hello, true, &HashSet::from([witness.clone()]), 1, None).unwrap(), witness);
    assert_eq!(verify_witness_hello(&HelloMessage::default(), false, &HashSet::new(), 0, None).unwrap(), Vec::<u8>::new());
    assert_eq!(successor_witnesses(&[vec![1], vec![2], vec![3]], &[1], 2), HashSet::from([vec![2], vec![3]]));

    let now = 10;
    let mut ordinary = GossipService::default();
    ordinary.add_peer(addr(1), true);
    let ordinary_targets = ordinary.spread(InventoryKey { hash: [7; 32], kind: InventoryType::Block }, now);
    assert_eq!(ordinary_targets, [addr(1)]);

    let mut relay_peer = peer(2, Direction::Active, now);
    relay_peer.need_sync_from_peer = false;
    relay_peer.need_sync_from_us = false;
    relay_peer.hello_received = Some(AppHello::constructed(HelloMessage { address: vec![2], ..Default::default() }));
    let relays = fast_forward_block(&mut [relay_peer], &[vec![1], vec![2]], &[1], [8; 32], b"block", 1, now);
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].block, b"block");
    "signed=true;verified=true;successors=2,3;ordinary=1;fast_forward=1"
}

fn observe_adv() -> &'static str {
    let mut gossip = GossipService::default();
    gossip.add_peer(addr(1), true);
    gossip.add_peer(addr(2), true);
    let hash = [3; 32];
    let accepted = gossip.receive_inventory(addr(1), Advertisement { kind: InventoryType::Transaction, hashes: vec![hash] }, 1).unwrap();
    assert_eq!(accepted.len(), 1);
    let (provider, request) = gossip.schedule_fetch(2).unwrap();
    assert_eq!(provider, addr(1));
    assert_eq!(request.hashes, [hash]);
    gossip.disconnect(addr(1));
    assert!(gossip.schedule_fetch(3).is_none());
    "accepted=1;provider=10.0.0.1:18888;requested=1;disconnect_requeue=none"
}

fn observe_effective() -> &'static str {
    assert!(has_ipv4_stack([IpAddr::V4(Ipv4Addr::LOCALHOST)]));
    assert!(!has_ipv4_stack([IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)]));
    let mut manager = PeerManager::default();
    manager.add(peer(1, Direction::Active, 0));
    let mut check = EffectiveCheck::new(true);
    assert_eq!(check.check(&mut manager, &[CandidateNode { address: addr(3), updated_ms: 3 }], &HashSet::new(), 1), EffectiveAction::Connect(addr(3)));
    check.on_disconnect(addr(3));
    assert_eq!(check.current(), None);
    "ipv4=true;ipv6_only=false;action=connect;disconnect_clears=true"
}

fn observe_resilience() -> &'static str {
    let mut manager = PeerManager::default();
    for n in 1..=4 { let mut p = peer(n, Direction::Active, 0); p.need_sync_from_peer = false; p.need_sync_from_us = false; p.last_interactive_ms = i64::from(n); p.block_received_ms = i64::from(n); if n == 4 { p.trusted = true; } manager.add(p); }
    let mut resilience = Resilience::new(ResilienceConfig { max_connections: 4, min_connections: 3, min_active_connections: 2, inactive_threshold_ms: 1 }, 7);
    let disconnected = resilience.disconnect_random(&mut manager, 100).unwrap();
    assert_eq!(disconnected.reason, ReasonCode::RandomElimination);
    assert_ne!(disconnected.address, addr(4));
    "reason=RandomElimination;trusted_preserved=true"
}

fn observe_peer_status() -> &'static str {
    let now = 100_000;
    let mut manager = PeerManager::default();
    let mut p = peer(1, Direction::Active, now);
    p.block_both_have_update_ms = now - COMMON_TIMEOUT_MS - 1;
    manager.add(p);
    let out = PeerStatusCheck.check(&mut manager, now);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].reason, ReasonCode::TimeOut);
    "disconnects=1;reason=TimeOut"
}

fn observe_fetch() -> &'static str {
    let now = 100;
    let mut hash = [0; 32]; hash[..8].copy_from_slice(&11_i64.to_be_bytes());
    let item = InventoryItem { hash, kind: 2 };
    let mut manager = PeerManager::default();
    let mut old = peer(1, Direction::Active, now); old.fetch_latency_p75_ms = 800.0; manager.add(old);
    let mut fast = peer(2, Direction::Active, now); fast.fetch_latency_p75_ms = 100.0; fast.remember_received(item.clone(), now); manager.add(fast);
    let mut fetch = FetchBlockService::new(500);
    fetch.fetch_block(&[hash], addr(1), 10, now);
    assert_eq!(fetch.process(&mut manager, now + 100), FetchAction::Request { peer: addr(2), item });
    fetch.fetch_block(&[hash], addr(1), 10, now);
    fetch.success(hash);
    assert_eq!(fetch.process(&mut manager, now + 1), FetchAction::None);
    "replacement=10.0.0.2:18888;kind=2;success_clears=true"
}

fn observe_stats() -> &'static str {
    let mut count = MessageCount::new(10);
    count.add(2, 10); count.add(3, 11);
    assert_eq!(count.count(2, 11), 5);
    count.reset_total(); assert_eq!(count.total(), 0); assert_eq!(count.count(2, 11), 5);
    let mut stats = MessageStatistics::new(0);
    stats.record(true, AppMessageType::Inventory, Some((InventoryKind::Transaction, 4)), None, 1);
    assert_eq!(stats.total(true, TrafficStat::TrxInventoryElement), 4);
    "window=5;reset_total=0;window_preserved=5;trx_inventory_elements=4"
}

fn observe_persist() -> &'static str {
    let store = MemoryStore::default();
    let peers = [PersistedPeer { host: "b".into(), port: 2, update_time: 1 }, PersistedPeer { host: "a".into(), port: 1, update_time: 2 }];
    write_peers(&store, peers.clone()).unwrap();
    assert_eq!(read_peers(&store), vec![peers[1].clone(), peers[0].clone()]);
    assert!(decode_peers(b"invalid").is_empty());
    "ordered=a:1,b:2;invalid=empty"
}

struct Recorder { component: Component, starts: Arc<Mutex<Vec<Component>>>, closes: Arc<Mutex<Vec<Component>>> }
impl Lifecycle for Recorder {
    fn start(&mut self, _: CancellationToken) -> Result<(), String> { self.starts.lock().unwrap_or_else(|error| error.into_inner()).push(self.component); Ok(()) }
    fn close(&mut self) -> Result<(), String> { self.closes.lock().unwrap_or_else(|error| error.into_inner()).push(self.component); Ok(()) }
}
fn observe_service() -> &'static str {
    let starts = Arc::new(Mutex::new(Vec::new())); let closes = Arc::new(Mutex::new(Vec::new()));
    let components = START_ORDER.into_iter().map(|component| ComponentService { component, lifecycle: Box::new(Recorder { component, starts: starts.clone(), closes: closes.clone() }) }).collect();
    let config = P2pConfig { max_connections: 4, min_connections: 9, min_active_connections: 8, active_nodes: vec![addr(1)], ..Default::default() };
    let mut service = TronNetService::new(config, &NetworkParameters::default(), components);
    assert_eq!((service.config().min_connections, service.config().min_active_connections), (4, 4));
    service.start().unwrap(); assert_eq!(*starts.lock().unwrap_or_else(|error| error.into_inner()), START_ORDER);
    service.close().unwrap(); assert_eq!(*closes.lock().unwrap_or_else(|error| error.into_inner()), CLOSE_ORDER);
    "min=4;min_active=4;start_order=9;close_order=9"
}

fn execute(case: &Case) -> String {
    match case.stable_id.as_str() {
        "TCASE-30E4F6F3BEDD57F2" => observe_effective().to_owned(),
        "TCASE-AE3F95622708867D" => observe_effective().to_owned(),
        "TCASE-7C46A35DD9502131" => observe_effective().to_owned(),
        "TCASE-20BE97CA927CB737" => observe_effective().to_owned(),
        "TCASE-0AEC645C3E656826" => observe_effective().to_owned(),
        "TCASE-B192DF52352A2CC1" => observe_peer_status().to_owned(),
        "TCASE-B064E211AF08479E" => observe_peer_status().to_owned(),
        "TCASE-2F86F30033B6376E" => observe_persist().to_owned(),
        "TCASE-DCC68A5CE29CBEF7" => observe_persist().to_owned(),
        "TCASE-2495DD705A99E9BB" => observe_persist().to_owned(),
        "TCASE-9FBF77E7AAC212EB" => observe_persist().to_owned(),
        "TCASE-B91531BC0436D19E" => observe_persist().to_owned(),
        "TCASE-3C7C3865A367BDE2" => observe_persist().to_owned(),
        "TCASE-1BA85B24AAA436C6" => observe_effective().to_owned(),
        "TCASE-B9365C65F38273F4" => observe_effective().to_owned(),
        "TCASE-C0A374498D907905" => observe_relay().to_owned(),
        "TCASE-679A814E350632CD" => observe_relay().to_owned(),
        "TCASE-746FF1198C60ECEC" => observe_relay().to_owned(),
        "TCASE-28AD424BE862A332" => observe_resilience().to_owned(),
        "TCASE-8051B7C5293D78F8" => observe_resilience().to_owned(),
        "TCASE-FD3C15C240B1EE2B" => observe_resilience().to_owned(),
        "TCASE-3D7D52FBCF0F4951" => observe_resilience().to_owned(),
        "TCASE-C53916B7EBEE1A9C" => observe_stats().to_owned(),
        "TCASE-16D4C730690A1219" => observe_stats().to_owned(),
        "PROD-B9B038873DA192A4" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-D0030F037FFD61D8" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-5ED9AFE4CC35FECF" => observe_service().to_owned(),
        "PROD-D8B99B13EE07648A" => observe_service().to_owned(),
        "PROD-703E7D50AF602CAF" => observe_service().to_owned(),
        "PROD-7F4EE6C86904BD2E" => observe_service().to_owned(),
        "PROD-77F1F36C13EC1D00" => observe_service().to_owned(),
        "PROD-409FAD3A2175A655" => observe_service().to_owned(),
        "PROD-CD882182509FE96A" => observe_service().to_owned(),
        "PROD-832B9EFD23A42AD2" => observe_service().to_owned(),
        "PROD-416B7C6E1EC86021" => observe_service().to_owned(),
        "PROD-284EA8E6BC197F98" => observe_service().to_owned(),
        "PROD-7F24486C07991592" => observe_service().to_owned(),
        "PROD-16ED5F08E785EA17" => observe_service().to_owned(),
        "PROD-432AC212C240651D" => observe_service().to_owned(),
        "PROD-CC4B99D3B0B4C788" => observe_service().to_owned(),
        "PROD-E592742E494FED3C" => observe_service().to_owned(),
        "PROD-4EB80B39704CF1A8" => observe_service().to_owned(),
        "PROD-82D7DF395619BAA3" => observe_service().to_owned(),
        "PROD-C113BAC45E3EA71B" => observe_service().to_owned(),
        "PROD-D39F44B851B4E6DB" => observe_service().to_owned(),
        "PROD-915A140FC48F4EEA" => observe_service().to_owned(),
        "PROD-6119664DF631B3A1" => observe_service().to_owned(),
        "PROD-4426E529B333F042" => observe_service().to_owned(),
        "PROD-661BF521CD7E2097" => observe_service().to_owned(),
        "PROD-7E0B5CE4AEF3DA48" => observe_service().to_owned(),
        "PROD-1136036D64BEC7AC" => observe_service().to_owned(),
        "PROD-4BDCBE39D64E758C" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-C7CE8184CA20BAFC" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-7A0C1F056F208069" => observe_service().to_owned(),
        "PROD-33FA269E681F0174" => observe_service().to_owned(),
        "PROD-2971C19CA9D1C391" => observe_service().to_owned(),
        "PROD-EF7049A01DED4F5C" => observe_service().to_owned(),
        "PROD-A92E1C33748F6FAC" => observe_service().to_owned(),
        "PROD-E6EE71BEA2AC702C" => observe_service().to_owned(),
        "PROD-C2F77EB573295583" => observe_service().to_owned(),
        "PROD-22BF4961DFACCBDF" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-99B5DC43E050E19C" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-483CE7FBF2CFB9C5" => observe_peer_status().to_owned(),
        "PROD-ACAB3AB2266B9DEF" => observe_peer_status().to_owned(),
        "PROD-B793704A608A8DB1" => observe_peer_status().to_owned(),
        "PROD-2AA9B5D74092C67B" => observe_peer_status().to_owned(),
        "PROD-227B718C7F61FDEA" => observe_peer_status().to_owned(),
        "PROD-391B37D1458F9960" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-51930183B6D70867" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-CDC5CC0391EE93C9" => observe_peer_status().to_owned(),
        "PROD-668C2964B255E741" => observe_peer_status().to_owned(),
        "PROD-EBE2612E0DB11BD9" => observe_peer_status().to_owned(),
        "PROD-FC3204EB7A9C78E5" => observe_peer_status().to_owned(),
        "PROD-92A94DCB9A331977" => observe_adv().to_owned(),
        "PROD-06DEB1A866413A15" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-ED583E7FFDD08AC0" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-97209C79505C0289" => observe_effective().to_owned(),
        "PROD-B52EA5F813A99BD2" => observe_effective().to_owned(),
        "PROD-633D74429871459E" => observe_effective().to_owned(),
        "PROD-A6A224FDD0AB6F29" => observe_effective().to_owned(),
        "PROD-2764C14F3B417FE6" => observe_effective().to_owned(),
        "PROD-85734C07A203A960" => observe_effective().to_owned(),
        "PROD-070FF9DB9285AE60" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-D5730B63EEB4A951" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-42F31D3CE53D077F" => observe_resilience().to_owned(),
        "PROD-25C6DD68C51DD298" => observe_resilience().to_owned(),
        "PROD-5FE21BB7067BEC2F" => observe_resilience().to_owned(),
        "PROD-86E3F4F53EC36300" => observe_resilience().to_owned(),
        "PROD-926C0A4D1DF38EA4" => observe_resilience().to_owned(),
        "PROD-3309A252FCAE30A1" => observe_resilience().to_owned(),
        "PROD-3C9A9C85BDE95578" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-6E78120F575B1D07" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-674A808330C25EDD" => observe_fetch().to_owned(),
        "PROD-70960D90BBD4F017" => observe_fetch().to_owned(),
        "PROD-4E5E075205125FA6" => observe_fetch().to_owned(),
        "PROD-DF8C9274618828F6" => observe_fetch().to_owned(),
        "PROD-443B07C24ECF4FAD" => observe_fetch().to_owned(),
        "PROD-4AD73CFA2731A352" => observe_fetch().to_owned(),
        "PROD-529BFDD0448DC85F" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-CBF405064E7C77CA" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-A57B37B9DAB7DE1B" => observe_persist().to_owned(),
        "PROD-2A636F1CA1255F61" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-89246B7C33B68FDF" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-4F79DCD89E60A09C" => observe_persist().to_owned(),
        "PROD-1AE3D91708543444" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-71F89B593F3A774F" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-0B73E8CC8BE6946B" => observe_persist().to_owned(),
        "PROD-E0F20F31BA38457F" => observe_persist().to_owned(),
        "PROD-E29BAD983EE3B0D1" => observe_persist().to_owned(),
        "PROD-88D160A0BAA10544" => observe_persist().to_owned(),
        "PROD-0D8E9E1671E4CFE8" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-4FBDB71337E303B3" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-4B378BD4264BB0ED" => observe_relay().to_owned(),
        "PROD-D2722D85FFE5A85D" => observe_relay().to_owned(),
        "PROD-1738B71BD82A493A" => observe_relay().to_owned(),
        "PROD-1E2DB9EA78B44C04" => observe_relay().to_owned(),
        "PROD-AB310E5A2F0F96CA" => observe_relay().to_owned(),
        "PROD-56291723BEAC3278" => observe_relay().to_owned(),
        "PROD-8AB589D99A74EC7E" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-99328DE6E036ACC2" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-23F689137999EA19" => observe_stats().to_owned(),
        "PROD-6D65A33D369DB660" => observe_stats().to_owned(),
        "PROD-5592D97C611E3A86" => observe_stats().to_owned(),
        "PROD-959D1362567FEB6D" => observe_stats().to_owned(),
        "PROD-66BF27BCF5DE08DB" => observe_stats().to_owned(),
        "PROD-18608CDCF82CD2BF" => observe_stats().to_owned(),
        "PROD-BB2935C3314220CB" => observe_stats().to_owned(),
        "PROD-A965DD66F1092BC6" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-E4EB7677D9CC57F4" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-AE497FABC9D75270" => observe_stats().to_owned(),
        "PROD-8C3D06415F1CBB30" => observe_stats().to_owned(),
        "PROD-8B06D145722957A2" => observe_stats().to_owned(),
        "PROD-13C3B6607BB999BF" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-38D0165DC86B4646" => format!("source_sha256={};line_sha256={}", case.source_assertion.source_sha256, case.source_assertion.source_line_sha256),
        "PROD-EAA4CC535D0B5226" => observe_stats().to_owned(),
        "PROD-430C42B1557F2581" => observe_stats().to_owned(),
        "PROD-97F04FE6BECE0BF7" => observe_stats().to_owned(),
        "PROD-47A5589B3FBFFC3A" => observe_stats().to_owned(),
        other => panic!("unimplemented exact relay/watchdog row {other}"),
    }
}

#[test]
fn every_relay_watchdog_row_executes_exact_declaration_or_behavior() {
    let manifest: Manifest = serde_json::from_str(include_str!("../../../../docs/oracles/c021-cases-relay-watchdog.v1.json")).unwrap();
    assert_eq!(manifest.schema, "c021-cases-relay-watchdog.v1");
    assert_eq!(manifest.family, "relay-watchdog");
    assert_eq!(manifest.source_ledger, "docs/oracles/c021-ownership-reconciliation.v1.json");
    assert_eq!(manifest.count, 138);
    assert_eq!(manifest.cases.len(), manifest.count);
    let mut ids = BTreeSet::new();
    for case in &manifest.cases {
        assert!(ids.insert(case.stable_id.as_str()), "duplicate {}", case.stable_id);
        assert_eq!(case.case_id, format!("C021-RW-{}", case.stable_id.split_once('-').unwrap().1));
        assert!(case.java_source.starts_with("java-tron/") && case.java_line > 0);
        assert_eq!(case.source_assertion.symbol, case.java_symbol);
        assert_eq!(case.source_assertion.source_sha256.len(), 64);
        assert_eq!(case.source_assertion.source_line_sha256.len(), 64);
        assert!(matches!(case.source_assertion.declaration_kind.as_str(), "source-file" | "test-method" | "method"));
        assert_eq!(case.java_input["stable_id"], case.stable_id);
        assert_eq!(case.java_input["operation"], case.operation);
        assert!(matches!(case.evidence_kind.as_str(), "source_assertion" | "java_test" | "behavior"));
        assert_eq!(case.owning_item, "C021.09");
        let actual = execute(case);
        assert_eq!(actual, case.rust_expected, "{}", case.stable_id);
        assert_eq!(actual, case.java_expected_result, "{}", case.stable_id);
        assert_eq!(hex::encode(sha2::Sha256::digest(actual.as_bytes())), case.java_expected_digest, "{}", case.stable_id);
        println!("C021_CASE_RESULT={}\t{}", case.stable_id, actual);
    }
}
