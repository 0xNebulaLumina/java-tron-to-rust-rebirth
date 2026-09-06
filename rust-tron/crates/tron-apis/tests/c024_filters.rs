use std::{sync::Arc,time::{Duration,Instant}};
use parking_lot::Mutex;
use tron_apis::jsonrpc_filters::*;
use tron_execution::{FilterEvent,FilterSink};
use tron_primitives::{BlockId,Hash32};

#[derive(Clone)]struct Clock(Arc<Mutex<Instant>>);impl FilterClock for Clock{fn now(&self)->Instant{*self.0.lock()}}
fn hash(n:u8)->Hash32{Hash32::from_array([n;32])}
fn log(block:u8,address:u8,topic:u8)->RpcLog{RpcLog{address:vec![address;20],topics:vec![hash(topic)],data:vec![],block_hash:hash(block),block_number:block as u64,transaction_hash:hash(block+20),transaction_index:0,log_index:0,removed:false}}

#[test]fn bloom_uses_java_bits_and_section_candidates(){let digest=[0,1,2,3,4,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];let b=Bloom::for_hash(&digest);assert_eq!(b.set_bits().collect::<Vec<_>>(),vec![1,515,1029]);let mut section=SectionBloom::default();section.index_block(2048,&b);let f=LogFilter{addresses:vec![vec![7;20]],..Default::default()};let address_bloom=Bloom::for_value(&[7;20]);section.index_block(2050,&address_bloom);assert_eq!(section.candidates(0,4095,&f),vec![2050]);}

#[test]fn exact_address_topic_and_range_semantics(){let f=LogFilter{addresses:vec![vec![1;20],vec![2;20]],topics:vec![Some(vec![hash(3),hash(4)]),None],from_block:Some(5),to_block:Some(10),block_hash:None};assert!(f.matches(&RpcLog{topics:vec![hash(4),hash(9)],..log(6,2,3)}));assert!(!f.matches(&log(6,7,4)));assert!(!f.matches(&log(6,2,8)));assert!(LogFilter{block_hash:Some(hash(1)),from_block:Some(1),..Default::default()}.validate(&FilterLimits::default()).is_err());}

#[test]fn maps_drain_refresh_expire_and_caps(){let start=Instant::now();let clock=Clock(Arc::new(Mutex::new(start)));let mut limits=FilterLimits::default();limits.max_block_filters=1;let manager=FilterManager::new(Arc::new(clock.clone()),limits);let full=manager.new_block_filter(FilterView::Full).unwrap();assert!(manager.new_block_filter(FilterView::Full).is_err());let solid=manager.new_block_filter(FilterView::Solidity).unwrap();manager.publish_block(FilterView::Full,hash(1));assert_eq!(manager.changes(FilterView::Full,full).unwrap(),FilterChanges::Hashes(vec![hash(1)]));assert_eq!(manager.changes(FilterView::Solidity,solid).unwrap(),FilterChanges::Hashes(vec![]));*clock.0.lock()+=Duration::from_secs(301);assert_eq!(manager.changes(FilterView::Full,full),Err(FilterError::NotFound));}

#[test]fn logs_queries_changes_and_reorg_removed_reapply(){let clock=Clock(Arc::new(Mutex::new(Instant::now())));let mut manager=FilterManager::new(Arc::new(clock),FilterLimits::default());let id=manager.new_log_filter(FilterView::Full,LogFilter{addresses:vec![vec![2;20]],topics:vec![Some(vec![hash(3)])],..Default::default()}).unwrap();manager.publish_logs(FilterView::Full,vec![log(8,2,3),log(9,4,3)]);assert_eq!(manager.changes(FilterView::Full,id).unwrap(),FilterChanges::Logs(vec![log(8,2,3)]));assert_eq!(manager.filter_logs(FilterView::Full,id).unwrap(),vec![log(8,2,3)]);let block=BlockId::from_overlaid_hash(hash(8));manager.filter(FilterEvent::Logs{block_id:block,block_number:8,removed:true});let removed=match manager.changes(FilterView::Full,id).unwrap(){FilterChanges::Logs(v)=>v,_=>panic!()};assert_eq!(removed.len(),1);assert!(removed[0].removed);assert!(manager.filter_logs(FilterView::Full,id).unwrap().is_empty());manager.filter(FilterEvent::Logs{block_id:block,block_number:8,removed:false});assert_eq!(manager.changes(FilterView::Full,id).unwrap(),FilterChanges::Logs(vec![]));assert!(manager.uninstall(FilterView::Full,id).unwrap());assert_eq!(manager.changes(FilterView::Full,id),Err(FilterError::NotFound));}

#[test]fn publish_prunes_expired_filters_before_amplification(){let start=Instant::now();let clock=Clock(Arc::new(Mutex::new(start)));let manager=FilterManager::new(Arc::new(clock.clone()),FilterLimits::default());let expired=manager.new_block_filter(FilterView::Full).unwrap();*clock.0.lock()+=FILTER_LIFETIME+Duration::from_secs(1);manager.publish_block(FilterView::Full,hash(1));assert_eq!(manager.changes(FilterView::Full,expired),Err(FilterError::NotFound));}

#[test]fn per_filter_queues_evict_oldest_by_count_and_bytes(){let mut limits=FilterLimits::default();limits.max_queue_items=2;limits.max_queue_bytes=64;let manager=FilterManager::system(limits);let id=manager.new_block_filter(FilterView::Full).unwrap();for n in 1..=3{manager.publish_block(FilterView::Full,hash(n))}assert_eq!(manager.changes(FilterView::Full,id).unwrap(),FilterChanges::Hashes(vec![hash(2),hash(3)]));}

#[test]fn history_is_bounded_and_reorg_removes_canonical_entries(){let mut limits=FilterLimits::default();limits.history_blocks=2;limits.max_history_items=2;limits.max_history_bytes=usize::MAX;let mut manager=FilterManager::system(limits);manager.publish_logs(FilterView::Full,vec![log(1,2,3),log(2,2,3),log(3,2,3)]);assert_eq!(manager.get_logs(FilterView::Full,&LogFilter::default()).unwrap(),vec![log(2,2,3),log(3,2,3)]);manager.filter(FilterEvent::Logs{block_id:BlockId::from_overlaid_hash(hash(2)),block_number:2,removed:true});assert_eq!(manager.get_logs(FilterView::Full,&LogFilter::default()).unwrap(),vec![log(3,2,3)]);}

#[test]fn oversized_history_and_queries_stop_at_limits(){let mut limits=FilterLimits::default();limits.max_history_bytes=1;let manager=FilterManager::system(limits);manager.publish_logs(FilterView::Full,vec![log(1,2,3)]);assert!(manager.get_logs(FilterView::Full,&LogFilter::default()).unwrap().is_empty());let mut limits=FilterLimits::default();limits.max_results=1;let manager=FilterManager::system(limits);manager.publish_logs(FilterView::Full,vec![log(1,2,3),log(2,2,3)]);assert!(matches!(manager.get_logs(FilterView::Full,&LogFilter::default()),Err(FilterError::Limit(_))));}
#[test]fn concurrent_ids_are_unique(){let manager=Arc::new(FilterManager::system(FilterLimits{max_block_filters:0,..Default::default()}));let threads:Vec<_>=(0..8).map(|_|{let m=manager.clone();std::thread::spawn(move|| (0..100).map(|_|m.new_block_filter(FilterView::Full).unwrap()).collect::<Vec<_>>())}).collect();let mut ids:Vec<_>=threads.into_iter().flat_map(|t|t.join().unwrap()).collect();ids.sort_unstable();ids.dedup();assert_eq!(ids.len(),800);}

#[test]
fn aggregate_filter_admission_rejects_creation_flood_across_views() {
    let manager = FilterManager::system(FilterLimits::default());
    let mut admitted = 0;
    for attempt in 0..120_000 {
        let view = if attempt % 2 == 0 { FilterView::Full } else { FilterView::Solidity };
        if manager.new_block_filter(view).is_ok() { admitted += 1; }
    }
    assert_eq!(admitted, FilterLimits::default().max_block_filters * 2);
    assert_eq!(manager.usage().filters, admitted);
}

#[test]
fn aggregate_queue_and_publish_fanout_are_globally_bounded() {
    let limits = FilterLimits {
        max_log_filters: 100,
        max_total_filters: 100,
        max_total_filters_per_view: 100,
        max_total_queue_items: 7,
        max_total_queue_bytes: usize::MAX,
        max_publish_fanout: 5,
        max_publish_work: 20,
        ..Default::default()
    };
    let manager = FilterManager::system(limits);
    let ids: Vec<_> = (0..100).map(|_| manager.new_log_filter(FilterView::Full, LogFilter::default()).unwrap()).collect();
    manager.publish_logs(FilterView::Full, vec![log(1, 2, 3), log(2, 2, 3)]);
    let delivered: usize = ids.into_iter().map(|id| match manager.changes(FilterView::Full,id).unwrap(){FilterChanges::Logs(v)=>v.len(),_=>0}).sum();
    assert!(delivered <= 5);
    assert!(manager.usage().queued_items <= 7);
}

#[test]
fn shared_sink_routes_full_and_solidified_transitions_to_separate_maps() {
    let manager = FilterManager::shared(FilterLimits::default());
    let full = manager.new_block_filter(FilterView::Full).unwrap();
    let solid = manager.new_block_filter(FilterView::Solidity).unwrap();
    let mut sink = manager.sink();
    sink.filter(FilterEvent::Block { block_id: BlockId::from_overlaid_hash(hash(1)), block_number: 1 });
    sink.solidified(FilterEvent::Block { block_id: BlockId::from_overlaid_hash(hash(2)), block_number: 2 });
    assert_eq!(manager.changes(FilterView::Full, full).unwrap(), FilterChanges::Hashes(vec![hash(1)]));
    assert_eq!(manager.changes(FilterView::Solidity, solid).unwrap(), FilterChanges::Hashes(vec![hash(2)]));
}

#[test]
fn aggregate_counters_release_on_drain_uninstall_and_expiry() {
    let start=Instant::now();
    let clock=Clock(Arc::new(Mutex::new(start)));
    let manager=FilterManager::new(Arc::new(clock.clone()),FilterLimits::default());
    let drained=manager.new_block_filter(FilterView::Full).unwrap();
    let removed=manager.new_block_filter(FilterView::Full).unwrap();
    manager.publish_block(FilterView::Full,hash(1));
    assert_eq!(manager.usage().queued_items,2);
    manager.changes(FilterView::Full,drained).unwrap();
    assert_eq!(manager.usage().queued_items,1);
    manager.uninstall(FilterView::Full,removed).unwrap();
    assert_eq!(manager.usage().queued_items,0);
    manager.new_block_filter(FilterView::Solidity).unwrap();
    *clock.0.lock() += FILTER_LIFETIME + Duration::from_secs(1);
    manager.prune();
    assert_eq!(manager.usage(),FilterUsage::default());
}
