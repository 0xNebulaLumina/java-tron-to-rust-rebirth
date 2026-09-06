use std::net::{IpAddr,Ipv4Addr,SocketAddr};
use tron_network::sync::*;
fn id(n:i64)->SyncBlockId{let mut h=[0;32];h[..8].copy_from_slice(&n.to_be_bytes());SyncBlockId::new(h,n)}
#[test]fn sparse_summary_is_bounded_and_selects_latest_common(){let s=sparse_chain_summary(0,1_000_000,|n|Some(id(n)));assert!(s.len()<=30);assert_eq!(s[0].number,0);assert_eq!(s.last().unwrap().number,1_000_000);let common=common_block(&s,|x|x.number<=1000).unwrap();assert!(common.number<=1000)}
#[test]fn response_is_consecutive_and_batch_bounded(){let req=SyncBlockChain{ids:vec![id(0),id(10)]};let inv=answer_sync_request(&req,3000,None,|x|x.number==0,|n|Some(id(n))).unwrap();assert_eq!(inv.ids.len(),2001);assert_eq!(inv.remain,1000);assert!(validate_chain_inventory(&inv,&req,4000).is_ok())}
#[test]fn inventory_rejects_short_nonfinal_unlinked_and_future(){let req=SyncBlockChain{ids:vec![id(10)]};assert_eq!(validate_chain_inventory(&ChainInventory{ids:vec![id(10)],remain:1},&req,20),Err(SyncError::ShortInventory));let mut ids:Vec<_>=(10..2010).map(id).collect();ids[5]=id(99);assert_eq!(validate_chain_inventory(&ChainInventory{ids,remain:1},&req,3000),Err(SyncError::NonConsecutive));assert_eq!(validate_chain_inventory(&ChainInventory{ids:vec![id(9)],remain:0},&req,20),Err(SyncError::UnlinkedInventory))}
#[test]fn coordinator_enforces_order_and_retries(){let p=SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST),1);let mut c=SyncCoordinator::default();let inv=ChainInventory{ids:(0..4).map(id).collect(),remain:0};c.install_inventory(p,&inv,|_|false).unwrap();let got=c.next_batch(p,0).unwrap();assert_eq!(got.len(),3);assert_eq!(c.receive(p,&got[1]),Err(SyncError::OutOfOrder));assert!(c.receive(p,&got[0]).is_ok());assert_eq!(c.retry_expired(5000).len(),2)}
#[test]
fn repeated_chain_request_replaces_peer_token_and_replay_is_rejected() {
    let p=SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST),7);
    let mut c=SyncCoordinator::default();
    let first=c.issue_chain_request(p).unwrap();
    let second=c.issue_chain_request(p).unwrap();
    assert_eq!(c.outstanding_chain_requests(),1);
    let inv=ChainInventory{ids:vec![id(0),id(1)],remain:0};
    assert_eq!(c.install_inventory_for_request(p,first,&inv,|_|false),Err(SyncError::InvalidRequestToken));
    c.install_inventory_for_request(p,second,&inv,|_|false).unwrap();
    assert_eq!(c.outstanding_chain_requests(),0);
    assert_eq!(c.install_inventory_for_request(p,second,&inv,|_|false),Err(SyncError::InvalidRequestToken));
}

#[test]
fn chain_requests_are_globally_bounded_and_disconnect_releases_capacity() {
    let mut c=SyncCoordinator::default();
    for port in 1..=MAX_OUTSTANDING_CHAIN_REQUESTS as u16 {
        c.issue_chain_request(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST),port)).unwrap();
    }
    assert_eq!(c.outstanding_chain_requests(),MAX_OUTSTANDING_CHAIN_REQUESTS);
    let overflow=SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST),u16::MAX);
    assert_eq!(c.issue_chain_request(overflow),Err(SyncError::ChainRequestLimit));
    let released=SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST),1);
    c.disconnect(released);
    assert_eq!(c.outstanding_chain_requests(),MAX_OUTSTANDING_CHAIN_REQUESTS-1);
    c.issue_chain_request(overflow).unwrap();
    assert_eq!(c.outstanding_chain_requests(),MAX_OUTSTANDING_CHAIN_REQUESTS);
}

#[test]
fn near_inventory_flood_is_rejected_without_retaining_ids_or_bytes() {
    let p=SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST),9);
    let limits=SyncLimits { global_count:2,peer_count:2,global_bytes:2*SYNC_BLOCK_ID_BYTES,peer_bytes:2*SYNC_BLOCK_ID_BYTES };
    let mut c=SyncCoordinator::with_limits(limits);
    let flood=ChainInventory { ids:vec![id(0),id(1),id(2),id(3)],remain:0 };
    assert_eq!(c.install_inventory(p,&flood,|_|false),Err(SyncError::GlobalPendingLimit));
    assert_eq!(c.usage(p),((0,0),(0,0)));
    c.install_inventory(p,&ChainInventory { ids:vec![id(0),id(1),id(2)],remain:0 },|_|false).unwrap();
    assert_eq!(c.usage(p),((2,2*SYNC_BLOCK_ID_BYTES),(2,2*SYNC_BLOCK_ID_BYTES)));
    c.disconnect(p);
    assert_eq!(c.usage(p),((0,0),(0,0)));
}
