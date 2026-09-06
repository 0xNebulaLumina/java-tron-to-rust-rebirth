use std::collections::BTreeMap;
use std::sync::Arc;
use tron_events_metrics::{HealthStatus,NodeConfigObservation,NodeInfoObserver,NodeInfoProvider,OperationalStatus,PeerObservation,ReadinessStatus};

struct Provider;
impl NodeInfoProvider for Provider {
 fn begin_sync_number(&self)->i64{0} fn head_block_id(&self)->String{"9,0009".into()} fn solidity_block_id(&self)->String{"8,0008".into()}
 fn peers(&self)->Vec<PeerObservation>{vec![PeerObservation{disconnected:true,need_sync_from_peer:false,active:true,sync_to_fetch_size_peek_num:None,host:"/127.0.0.1".into(),local_disconnect_reason:None,remote_disconnect_reason:None,..Default::default()}]}
 fn config(&self)->NodeConfigObservation{NodeConfigObservation::default()}
 fn cheat_witnesses(&self)->BTreeMap<String,String>{BTreeMap::from([("41aa".into(),"times=2".into())])}
}
#[test]
fn node_info_preserves_observed_fields_and_java_peer_quirks(){let node=NodeInfoObserver::new(Arc::new(Provider)).snapshot();assert_eq!(node.block,"9,0009");assert_eq!((node.current_connect_count,node.active_connect_count,node.passive_connect_count),(1,1,0));let peer=&node.peer_info_list[0];assert!(peer.sync_flag);assert!(peer.need_sync_from_peer,"Java copies syncFlag rather than the source needSyncFromPeer field");assert_eq!(peer.sync_to_fetch_size_peek_num,-1);assert_eq!(peer.local_disconnect_reason,"");assert_eq!(node.config_node_info.unwrap().db_version,2);assert_eq!(node.cheat_witness_info_map["41aa"],"times=2");}
#[test]
fn health_and_readiness_are_derived_without_mutating_node_info(){let node=NodeInfoObserver::new(Arc::new(Provider)).snapshot();let status=OperationalStatus::from_node(&node,10_000,5_000);assert_eq!(status.health,HealthStatus::Healthy);assert_eq!(status.readiness,ReadinessStatus::Ready);let mut disconnected=node;disconnected.current_connect_count=0;assert_eq!(OperationalStatus::from_node(&disconnected,10_000,5_000).readiness,ReadinessStatus::NoPeers);}
