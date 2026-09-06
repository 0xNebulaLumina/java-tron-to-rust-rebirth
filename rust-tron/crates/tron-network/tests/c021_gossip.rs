use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tron_network::gossip::*;

fn peer(port:u16)->SocketAddr { SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST),port) }
fn hash(n:u64)->[u8;32] { let mut value=[0;32]; value[..8].copy_from_slice(&n.to_be_bytes()); value }
fn key(n:u64,kind:InventoryType)->InventoryKey { InventoryKey { hash:hash(n),kind } }
fn payload(n:u64,kind:InventoryType,size:usize,at:i64)->Payload { Payload { key:key(n,kind),bytes:vec![n as u8;size],block:None,produced_at_ms:at } }

#[test]
fn inventory_requires_sync_and_rejects_duplicates() {
    let mut g=GossipService::default(); g.add_peer(peer(1),false);
    let a=Advertisement { kind:InventoryType::Transaction,hashes:vec![hash(1)] };
    assert_eq!(g.receive_inventory(peer(1),a.clone(),0),Err(GossipError::Syncing));
    g.set_sync_complete(peer(1),true);
    assert_eq!(g.receive_inventory(peer(1),Advertisement { kind:a.kind,hashes:vec![hash(1),hash(1)] },0),Err(GossipError::Duplicate));
}

#[test]
fn least_queued_fetch_and_disconnect_requeue() {
    let mut g=GossipService::default();
    for p in [peer(1),peer(2)] { g.add_peer(p,true); g.receive_inventory(p,Advertisement { kind:InventoryType::Transaction,hashes:vec![hash(1)] },0).unwrap(); }
    let (first,_)=g.schedule_fetch(1).unwrap(); g.disconnect(first); let (second,_)=g.schedule_fetch(2).unwrap(); assert_ne!(first,second);
}

#[test]
fn correlated_fetch_batches_transactions_and_blocks_one_each() {
    let mut g=GossipService::default(); let p=peer(1); g.add_peer(p,true);
    for n in 1..=2 { g.cache(payload(n,InventoryType::Transaction,600_000,0),0).unwrap(); g.spread(key(n,InventoryType::Transaction),0); }
    assert_eq!(g.serve_fetch(p,&FetchRequest { kind:InventoryType::Transaction,hashes:vec![hash(1),hash(2)] },1,|_|false).unwrap().len(),2);
    g.cache(payload(3,InventoryType::Block,3,0),0).unwrap(); g.spread(key(3,InventoryType::Block),0);
    assert_eq!(g.serve_fetch(p,&FetchRequest { kind:InventoryType::Block,hashes:vec![hash(3)] },1,|_|false).unwrap().len(),1);
}

#[test]
fn multi_fetch_uncorrelated_second_preserves_first_for_corrected_retry() {
    let mut g = GossipService::default();
    let p = peer(10);
    g.add_peer(p, true);
    for n in 1..=2 {
        g.cache(payload(n, InventoryType::Transaction, 1, 0), 0).unwrap();
    }
    g.spread(key(1, InventoryType::Transaction), 0);

    let invalid = FetchRequest { kind: InventoryType::Transaction, hashes: vec![hash(1), hash(2)] };
    assert_eq!(g.serve_fetch(p, &invalid, 1, |_| false), Err(GossipError::Uncorrelated));

    g.spread(key(2, InventoryType::Transaction), 1);
    assert_eq!(g.serve_fetch(p, &invalid, 2, |_| false).unwrap().len(), 1);
}

#[test]
fn multi_fetch_missing_second_preserves_correlations_for_retry() {
    let mut g = GossipService::default();
    let p = peer(11);
    g.add_peer(p, true);
    g.cache(payload(1, InventoryType::Transaction, 1, 0), 0).unwrap();
    for n in 1..=2 {
        g.spread(key(n, InventoryType::Transaction), 0);
    }
    let request = FetchRequest { kind: InventoryType::Transaction, hashes: vec![hash(1), hash(2)] };
    assert_eq!(g.serve_fetch(p, &request, 1, |_| false), Err(GossipError::Missing));

    g.cache(payload(2, InventoryType::Transaction, 1, 1), 1).unwrap();
    assert_eq!(g.serve_fetch(p, &request, 2, |_| false).unwrap().len(), 1);
}

#[test]
fn duplicate_fetch_preserves_correlation_for_corrected_retry() {
    let mut g = GossipService::default();
    let p = peer(12);
    g.add_peer(p, true);
    g.cache(payload(1, InventoryType::Transaction, 1, 0), 0).unwrap();
    g.spread(key(1, InventoryType::Transaction), 0);

    let duplicate = FetchRequest { kind: InventoryType::Transaction, hashes: vec![hash(1), hash(1)] };
    assert_eq!(g.serve_fetch(p, &duplicate, 1, |_| false), Err(GossipError::Duplicate));

    let corrected = FetchRequest { kind: InventoryType::Transaction, hashes: vec![hash(1)] };
    assert_eq!(g.serve_fetch(p, &corrected, 2, |_| false).unwrap().len(), 1);
}

#[test]
fn overlimit_fetch_preserves_rate_and_correlation_for_corrected_retry() {
    let mut g = GossipService::default();
    let p = peer(13);
    g.add_peer(p, true);
    g.cache(payload(1, InventoryType::Transaction, 1, 0), 0).unwrap();
    g.spread(key(1, InventoryType::Transaction), 0);

    let overlimit = FetchRequest {
        kind: InventoryType::Transaction,
        hashes: (0..=MAX_TX_FETCH_PER_PEER as u64).map(hash).collect(),
    };
    assert_eq!(g.serve_fetch(p, &overlimit, 1, |_| false), Err(GossipError::FetchLimit));

    let corrected = FetchRequest { kind: InventoryType::Transaction, hashes: vec![hash(1)] };
    assert_eq!(g.serve_fetch(p, &corrected, 2, |_| false).unwrap().len(), 1);
}


#[test]
fn failed_full_rate_fetch_does_not_charge_corrected_retry() {
    let mut g = GossipService::default();
    let p = peer(14);
    g.add_peer(p, true);
    for n in 0..MAX_TX_FETCH_PER_PEER as u64 - 1 {
        g.cache(payload(n, InventoryType::Transaction, 1, 0), 0).unwrap();
    }
    let request = FetchRequest {
        kind: InventoryType::Transaction,
        hashes: (0..MAX_TX_FETCH_PER_PEER as u64).map(hash).collect(),
    };
    assert_eq!(g.serve_fetch(p, &request, 1, |_| true), Err(GossipError::Missing));

    let corrected = FetchRequest { kind: InventoryType::Transaction, hashes: vec![hash(0)] };
    assert_eq!(g.serve_fetch(p, &corrected, 2, |_| true).unwrap().len(), 1);
}
#[test]
fn provider_budget_backpressures_atomically_and_disconnect_prunes() {
    let p=peer(1); let limits=GossipLimits { tx_inventory_per_10s:10,block_inventory_per_10s:10,provider_keys:2,provider_bytes:2*(PROVIDER_KEY_BYTES+PROVIDER_PEER_BYTES) };
    let mut g=GossipService::with_limits(limits); g.add_peer(p,true);
    g.receive_inventory(p,Advertisement { kind:InventoryType::Transaction,hashes:vec![hash(1),hash(2)] },0).unwrap();
    assert_eq!(g.receive_inventory(p,Advertisement { kind:InventoryType::Transaction,hashes:vec![hash(3)] },1),Err(GossipError::ProviderLimit));
    assert_eq!(g.inventory_state_sizes(p).2,2); g.disconnect(p); assert_eq!(g.inventory_state_sizes(p),(0,0,0,0,0));
}

#[test]
fn near_frame_correlated_flood_stays_within_exact_cache_budgets() {
    let mut g=GossipService::default(); let p=peer(9); g.add_peer(p,true);
    let size=MAX_GOSSIP_PAYLOAD_BYTES-64;
    let tx_items=TX_CACHE_BYTE_LIMIT/size+3;
    for n in 0..tx_items as u64 {
        g.receive_inventory(p,Advertisement { kind:InventoryType::Transaction,hashes:vec![hash(n)] },n as i64*10_001).unwrap();
        g.schedule_fetch(n as i64*10_001).unwrap();
        g.receive_payload(p,payload(n,InventoryType::Transaction,size,n as i64*10_001),n as i64*10_001+1).unwrap();
        let ((count,bytes),_)=g.cache_usage(); assert_eq!(bytes,count*size); assert!(bytes<=TX_CACHE_BYTE_LIMIT);
    }
    let block_items=BLOCK_CACHE_BYTE_LIMIT/size+3;
    for n in 0..block_items as u64 {
        let number=10_000+n;
        g.cache(payload(number,InventoryType::Block,size,0),0).unwrap();
        let (_, (count,bytes))=g.cache_usage(); assert_eq!(bytes,count*size); assert!(bytes<=BLOCK_CACHE_BYTE_LIMIT);
    }
}

#[test]
fn oversize_replace_ttl_and_eviction_account_exact_bytes() {
    let mut g=GossipService::default();
    assert_eq!(g.cache(payload(1,InventoryType::Transaction,MAX_GOSSIP_PAYLOAD_BYTES+1,0),0),Err(GossipError::PayloadTooLarge));
    assert_eq!(g.cache_usage(),((0,0),(0,0)));
    g.cache(payload(1,InventoryType::Transaction,100,0),0).unwrap();
    g.cache(payload(1,InventoryType::Transaction,250,1),1).unwrap();
    assert_eq!(g.cache_usage().0,(1,250));
    g.cache(payload(2,InventoryType::Transaction,10,TX_CACHE_TTL_MS+1),TX_CACHE_TTL_MS+1).unwrap();
    assert_eq!(g.cache_usage().0,(1,10));
}

#[test]
fn oversize_correlated_payload_does_not_consume_request() {
    let mut g=GossipService::default(); let p=peer(4); g.add_peer(p,true);
    g.receive_inventory(p,Advertisement { kind:InventoryType::Transaction,hashes:vec![hash(1)] },0).unwrap(); g.schedule_fetch(0).unwrap();
    assert_eq!(g.receive_payload(p,payload(1,InventoryType::Transaction,MAX_GOSSIP_PAYLOAD_BYTES+1,0),1),Err(GossipError::PayloadTooLarge));
    g.receive_payload(p,payload(1,InventoryType::Transaction,1,0),2).unwrap();
}
