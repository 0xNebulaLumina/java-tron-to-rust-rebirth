use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tron_network::gossip::*;
use tron_network::sync::*;

#[derive(Deserialize)]
struct Manifest { schema:String, family:String, source_ledger:String, count:usize, cases:Vec<Case> }
#[derive(Deserialize)]
struct Case {
    stable_id:String, case_id:String, evidence_kind:String, java_expected_digest:String,
    java_expected_result:String, java_input:serde_json::Value, java_line:usize,
    java_source:String, java_symbol:String, operation:String, owning_item:String,
    rust_expected:String, source_assertion:SourceAssertion,
}
#[derive(Deserialize)]
struct SourceAssertion { declaration_kind:String, source_sha256:String, source_line_sha256:String, symbol:String }

fn peer(port: u16) -> SocketAddr { SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port) }
fn id(number: i64) -> SyncBlockId { let mut hash=[0;32]; hash[..8].copy_from_slice(&number.to_be_bytes()); SyncBlockId::new(hash,number) }
fn hash(number: u64) -> [u8;32] { let mut hash=[0;32]; hash[..8].copy_from_slice(&number.to_be_bytes()); hash }
fn key(number: u64, kind: InventoryType) -> InventoryKey { InventoryKey { hash: hash(number), kind } }
fn digest(value: &str) -> String { format!("{:x}", Sha256::digest(value.as_bytes())) }

fn observe(family: &str) -> String {
    match family {
        "sparse_summary" => {
            let summary=sparse_chain_summary(0,100,|n|Some(id(n)));
            assert_eq!(common_block(&summary,|block|block.number<=88),Some(id(76)));
            format!("summary={}",summary.iter().map(|x|x.number.to_string()).collect::<Vec<_>>().join(","))
        }
        "chain_inventory" => {
            let request=SyncBlockChain{ids:vec![id(0)]};
            let inventory=answer_sync_request(&request,2001,None,|x|x.number==0,|n|Some(id(n))).unwrap();
            validate_chain_inventory(&inventory,&request,2002).unwrap();
            format!("ids={};remain={}",inventory.ids.len(),inventory.remain)
        }
        "sync_request" => {
            let p=peer(1); let mut sync=SyncCoordinator::default(); let token=sync.issue_chain_request(p).unwrap();
            let inventory=ChainInventory{ids:vec![id(0),id(1)],remain:0};
            sync.install_inventory_for_request(p,token,&inventory,|_|false).unwrap();
            assert_eq!(sync.install_inventory_for_request(p,token,&inventory,|_|false),Err(SyncError::InvalidRequestToken));
            "token=single-use".into()
        }
        "ordered_receive" => {
            let p=peer(1); let mut sync=SyncCoordinator::default();
            sync.install_inventory(p,&ChainInventory{ids:vec![id(0),id(1),id(2)],remain:0},|_|false).unwrap();
            let requested=sync.next_batch(p,0).unwrap();
            assert_eq!(sync.receive(p,&requested[1]),Err(SyncError::OutOfOrder));
            sync.receive(p,&requested[0]).unwrap();
            "order=reject-second;accept-first".into()
        }
        "sync_queue" => {
            let p=peer(1); let limits=SyncLimits{global_count:3,peer_count:3,global_bytes:3*SYNC_BLOCK_ID_BYTES,peer_bytes:3*SYNC_BLOCK_ID_BYTES};
            let mut sync=SyncCoordinator::with_limits(limits);
            sync.install_inventory(p,&ChainInventory{ids:vec![id(0),id(1),id(2),id(3)],remain:0},|_|false).unwrap();
            assert_eq!(sync.usage(p),((3,3*SYNC_BLOCK_ID_BYTES),(3,3*SYNC_BLOCK_ID_BYTES)));
            let requested=sync.next_batch(p,0).unwrap(); sync.receive(p,&requested[0]).unwrap();
            assert_eq!(sync.usage(p).0.0,3);
            "queued=3;requested=3;in_process=1".into()
        }
        "inventory" => {
            let p=peer(1); let mut gossip=GossipService::default(); gossip.add_peer(p,true);
            let accepted=gossip.receive_inventory(p,Advertisement{kind:InventoryType::Transaction,hashes:vec![hash(1)]},0).unwrap();
            assert_eq!(gossip.receive_inventory(p,Advertisement{kind:InventoryType::Transaction,hashes:vec![hash(2),hash(2)]},0),Err(GossipError::Duplicate));
            format!("accepted={};duplicate=rejected",accepted.len())
        }
        "fetch" => {
            let p=peer(1); let mut gossip=GossipService::default(); gossip.add_peer(p,true);
            for n in 1..=2 { let k=key(n,InventoryType::Transaction); gossip.cache(Payload{key:k.clone(),bytes:vec![n as u8;600_000],block:None,produced_at_ms:0},0).unwrap(); gossip.spread(k,0); }
            let tx=gossip.serve_fetch(p,&FetchRequest{kind:InventoryType::Transaction,hashes:vec![hash(1),hash(2)]},1,|_|false).unwrap();
            let block=key(3,InventoryType::Block); gossip.cache(Payload{key:block.clone(),bytes:vec![3],block:Some(id(3)),produced_at_ms:0},0).unwrap(); gossip.spread(block,0);
            let blocks=gossip.serve_fetch(p,&FetchRequest{kind:InventoryType::Block,hashes:vec![hash(3)]},1,|_|false).unwrap();
            format!("tx_batches={};block_batches={}",tx.len(),blocks.len())
        }
        "cache_spread" => {
            let p=peer(1); let mut gossip=GossipService::default(); gossip.add_peer(p,true); let k=key(1,InventoryType::Transaction);
            gossip.cache(Payload{key:k.clone(),bytes:vec![1],block:None,produced_at_ms:0},0).unwrap();
            let spread=gossip.spread(k.clone(),0).len();
            let served=gossip.serve_fetch(p,&FetchRequest{kind:InventoryType::Transaction,hashes:vec![k.hash]},1,|_|false).unwrap();
            format!("spread={spread};cached={}",!served.is_empty())
        }
        "payload" => {
            let p=peer(1); let mut gossip=GossipService::default(); gossip.add_peer(p,true);
            gossip.receive_inventory(p,Advertisement{kind:InventoryType::Transaction,hashes:vec![hash(1)]},0).unwrap(); gossip.schedule_fetch(0).unwrap();
            let payload=Payload{key:key(1,InventoryType::Transaction),bytes:vec![1],block:None,produced_at_ms:0};
            gossip.receive_payload(p,payload.clone(),1).unwrap();
            assert_eq!(gossip.receive_payload(p,payload,2),Err(GossipError::Uncorrelated));
            "correlated=true;repeat=rejected".into()
        }
        "rates" => {
            let p=peer(1); let limits=GossipLimits{tx_inventory_per_10s:1,block_inventory_per_10s:1,provider_keys:1,provider_bytes:PROVIDER_KEY_BYTES+PROVIDER_PEER_BYTES};
            let mut gossip=GossipService::with_limits(limits); gossip.add_peer(p,true);
            gossip.receive_inventory(p,Advertisement{kind:InventoryType::Transaction,hashes:vec![hash(1)]},0).unwrap();
            assert_eq!(gossip.receive_inventory(p,Advertisement{kind:InventoryType::Transaction,hashes:vec![hash(2)]},1),Err(GossipError::InventoryRateLimited));
            assert_eq!(gossip.inventory_state_sizes(p).2,1);
            "limit=atomic".into()
        }
        other => panic!("unknown family {other}"),
    }
}

fn source_observation(case:&Case)->String {
    let root=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let bytes=std::fs::read(root.join(&case.java_source)).unwrap();
    let text=std::str::from_utf8(&bytes).unwrap();
    let line=text.lines().nth(case.java_line-1).unwrap().trim();
    let source_hash=digest(std::str::from_utf8(&bytes).unwrap());
    let line_hash=digest(line);
    assert_eq!(source_hash,case.source_assertion.source_sha256, "{} source",case.stable_id);
    assert_eq!(line_hash,case.source_assertion.source_line_sha256, "{} line",case.stable_id);
    assert_eq!(case.source_assertion.symbol,case.java_symbol);
    format!("source:{source_hash};line:{line_hash};symbol:{}",case.java_symbol)
}

#[test]
fn every_sync_gossip_reconciliation_row_executes_its_exact_case() {
    let manifest:Manifest=serde_json::from_str(include_str!("../../../../docs/oracles/c021-cases-sync-gossip.v1.json")).unwrap();
    assert_eq!(manifest.schema,"c021-cases-sync-gossip.v1"); assert_eq!(manifest.family,"sync-gossip");
    assert_eq!(manifest.source_ledger,"docs/oracles/c021-ownership-reconciliation.v1.json"); assert_eq!(manifest.count,102); assert_eq!(manifest.count,manifest.cases.len());
    let mut ids=HashSet::new();
    for case in manifest.cases {
        assert!(ids.insert(case.stable_id.clone()),"duplicate {}",case.stable_id);
        assert_eq!(case.case_id,format!("C021-SG-{}",case.stable_id.split_once('-').unwrap().1));
        assert!(matches!(case.owning_item.as_str(),"C021.04"|"C021.05"));
        assert_eq!(case.java_input["operation"],case.operation);
        let actual=if case.evidence_kind=="source_assertion" {
            assert_eq!(case.source_assertion.declaration_kind,"source-declaration");
            source_observation(&case)
        } else {
            assert!(matches!(case.evidence_kind.as_str(),"java_test"|"production"));
            assert!(matches!(case.source_assertion.declaration_kind.as_str(),"test-method"|"method"));
            observe(&case.operation)
        };
        assert_eq!(actual,case.rust_expected,"{} {}",case.stable_id,case.java_symbol);
        assert_eq!(actual,case.java_expected_result,"{}",case.stable_id);
        assert_eq!(digest(&actual),case.java_expected_digest,"{}",case.stable_id);
        println!("C021_CASE_RESULT={}\t{}",case.stable_id,actual);
    }
}

#[test]
fn sync_flood_is_rejected_before_install_and_disconnect_cleans_all_states() {
    let p=peer(7); let mut sync=SyncCoordinator::with_limits(SyncLimits{global_count:2,peer_count:2,global_bytes:2*SYNC_BLOCK_ID_BYTES,peer_bytes:2*SYNC_BLOCK_ID_BYTES});
    let flood=ChainInventory{ids:vec![id(0),id(1),id(2),id(3)],remain:0};
    assert_eq!(sync.install_inventory(p,&flood,|_|false),Err(SyncError::GlobalPendingLimit)); assert_eq!(sync.pending(),0);
    let accepted=ChainInventory{ids:vec![id(0),id(1),id(2)],remain:0}; sync.install_inventory(p,&accepted,|_|false).unwrap();
    let requested=sync.next_batch(p,0).unwrap(); sync.receive(p,&requested[0]).unwrap(); assert_eq!(sync.pending(),2);
    sync.disconnect(p); assert_eq!(sync.pending(),0); assert_eq!(sync.usage(p),((0,0),(0,0)));
}
