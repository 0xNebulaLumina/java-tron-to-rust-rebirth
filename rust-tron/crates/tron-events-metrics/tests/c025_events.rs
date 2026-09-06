use std::time::{Duration, Instant};

use tron_events_metrics::{BlockTrigger, Delivery, DeliveryWorker, EventQueues, EventTrigger, QueueClass, QueueError, QueueLimits, FLUSH_INTERVAL};

fn block(number: i64, removed: bool) -> Delivery { Delivery::Event(EventTrigger::Block(BlockTrigger { trigger_name: "blockTrigger".into(), block_number: number, removed, ..BlockTrigger::default() })) }

#[test]
fn java_block_schema_uses_camel_case_and_removed() {
    let json = EventTrigger::Block(BlockTrigger { time_stamp: 7, trigger_name: "blockTrigger".into(), block_number: 9, block_hash: "ab".into(), transaction_size: 1, latest_solidified_block_number: 8, transaction_list: vec!["cd".into()], removed: true }).to_json().unwrap();
    assert_eq!(json, r#"{"timeStamp":7,"triggerName":"blockTrigger","blockNumber":9,"blockHash":"ab","transactionSize":1,"latestSolidifiedBlockNumber":8,"transactionList":["cd"],"removed":true}"#);
}

#[test]
fn bounded_batch_is_atomic_and_reorg_order_is_exact() {
    let queues = EventQueues::new(QueueLimits { history: 4, realtime: 3, solid: 4 });
    queues.push_batch(QueueClass::Realtime, [block(4, true), block(3, true), block(2, false), block(3, false)]).unwrap_err();
    assert_eq!(queues.len(QueueClass::Realtime), 0);
    assert_eq!(queues.push_batch(QueueClass::Realtime, [block(2, false), block(1, true)]), Err(QueueError::RemovalOrder));
    assert_eq!(queues.push_batch(QueueClass::Realtime, [block(3, false), block(2, false)]), Err(QueueError::ForwardOrder));
    queues.push_batch(QueueClass::Realtime, [block(3, true), block(1, false), block(2, false)]).unwrap();
    assert_eq!(queues.len(QueueClass::Realtime), 3);
    assert!(matches!(queues.push(QueueClass::Realtime, block(3, false)), Err(QueueError::Full(QueueClass::Realtime))));
}

#[test]
fn realtime_flush_waits_one_second_and_preserves_sequence() {
    let queues = EventQueues::new(QueueLimits::default());
    queues.push(QueueClass::Realtime, block(1, false)).unwrap();
    let start = Instant::now();
    assert!(queues.flush_due(start).is_empty());
    let flushed = queues.flush_due(start + FLUSH_INTERVAL + Duration::from_millis(1));
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0].sequence, 0);
}

#[test]
fn closing_shared_queues_revokes_every_producer_without_discarding_accepted_events() {
    let queues = EventQueues::shared(QueueLimits::default());
    let mut sink = queues.sink();
    queues.push(QueueClass::History, block(1, false)).unwrap();
    queues.close();
    assert_eq!(queues.push(QueueClass::Realtime, block(2, false)), Err(QueueError::Closed));
    assert_eq!(queues.push_batch(QueueClass::Solid, [block(3, false)]), Err(QueueError::Closed));
    assert_eq!(sink.enqueue(block(4, false)), Err(QueueError::Closed));
    assert_eq!(sink.last_error(), Some(&QueueError::Closed));
    assert_eq!(sink.failures(), 1);
    assert_eq!(queues.drain(QueueClass::History, usize::MAX).len(), 1);
    queues.open();
    assert!(queues.push(QueueClass::Realtime, block(5, false)).is_ok());
}

#[test]
fn delivery_worker_preserves_java_queue_order_and_retains_failed_head() {
    let queues = EventQueues::shared(QueueLimits::default());
    queues.push(QueueClass::Solid, block(30, false)).unwrap();
    queues.push(QueueClass::Realtime, block(20, false)).unwrap();
    queues.push(QueueClass::History, block(10, false)).unwrap();
    let mut worker = DeliveryWorker::new(queues.clone(), 1);
    let mut attempts = 0;
    let error = worker.drain(|delivery| { attempts += 1; if delivery.delivery.block_number() == 20 { Err("exporter full".into()) } else { Ok(()) } }).unwrap_err();
    assert!(error.contains("Realtime"));
    assert_eq!(attempts, 3);
    assert_eq!(queues.len(QueueClass::History), 0);
    assert_eq!(queues.len(QueueClass::Realtime), 1);
    assert_eq!(queues.len(QueueClass::Solid), 1);
    assert_eq!(worker.metrics().delivered, 1);
    assert_eq!(worker.metrics().failures, 2);
    assert_eq!(worker.metrics().retries, 1);
    let mut order = Vec::new();
    worker.drain(|delivery| { order.push(delivery.delivery.block_number()); Ok(()) }).unwrap();
    assert_eq!(order, [20, 30]);
}
