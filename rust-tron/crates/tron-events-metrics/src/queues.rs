use std::{collections::VecDeque, sync::{Arc, Mutex}, time::{Duration, Instant}};

use tron_execution::{BlockEvent, ContractEvent, EventSink, FilterEvent, FilterSink};

use crate::events::EventTrigger;

pub const REALTIME_QUEUE_CAPACITY: usize = 10_000;
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueClass { History, Realtime, Solid }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Delivery { Event(EventTrigger), Filter(FilterEvent) }
impl Delivery { pub fn removed(&self) -> bool { match self { Self::Event(v) => v.removed(), Self::Filter(FilterEvent::Logs { removed, .. }) => *removed, Self::Filter(FilterEvent::Block { .. }) => false } } pub fn block_number(&self) -> i64 { match self { Self::Event(v) => v.block_number().unwrap_or_default(), Self::Filter(FilterEvent::Logs { block_number, .. } | FilterEvent::Block { block_number, .. }) => *block_number } } }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedDelivery { pub sequence: u64, pub class: QueueClass, pub delivery: Delivery }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueLimits { pub history: usize, pub realtime: usize, pub solid: usize }
impl Default for QueueLimits { fn default() -> Self { Self { history: 50_000, realtime: REALTIME_QUEUE_CAPACITY, solid: REALTIME_QUEUE_CAPACITY } } }

#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum QueueError { #[error("{0:?} event queue is full")] Full(QueueClass), #[error("event queue ingress is closed")] Closed, #[error("reorg batch must contain removals before forwards")] RemovalOrder, #[error("forward reorg events must be oldest-first")] ForwardOrder }

struct State { accepting: bool, next_sequence: u64, history: VecDeque<QueuedDelivery>, realtime: VecDeque<QueuedDelivery>, solid: VecDeque<QueuedDelivery>, last_flush: Instant }
pub struct EventQueues { limits: QueueLimits, state: Mutex<State> }
impl EventQueues {
    pub fn new(limits: QueueLimits) -> Self { Self { limits, state: Mutex::new(State { accepting: true, next_sequence: 0, history: VecDeque::new(), realtime: VecDeque::new(), solid: VecDeque::new(), last_flush: Instant::now() }) } }
    pub fn shared(limits: QueueLimits) -> Arc<Self> { Arc::new(Self::new(limits)) }
    fn queue_mut(state: &mut State, class: QueueClass) -> &mut VecDeque<QueuedDelivery> { match class { QueueClass::History => &mut state.history, QueueClass::Realtime => &mut state.realtime, QueueClass::Solid => &mut state.solid } }
    fn cap(&self, class: QueueClass) -> usize { match class { QueueClass::History => self.limits.history, QueueClass::Realtime => self.limits.realtime.min(REALTIME_QUEUE_CAPACITY), QueueClass::Solid => self.limits.solid } }
    pub fn push(&self, class: QueueClass, delivery: Delivery) -> Result<u64, QueueError> { self.push_batch(class, [delivery]).map(|v| v[0]) }
    pub fn push_batch<I>(&self, class: QueueClass, deliveries: I) -> Result<Vec<u64>, QueueError> where I: IntoIterator<Item = Delivery> {
        let values: Vec<_> = deliveries.into_iter().collect();
        let mut seen_forward = false;
        let mut previous_forward = None;
        for value in &values {
            if value.removed() { if seen_forward { return Err(QueueError::RemovalOrder); } }
            else { seen_forward = true; let height = value.block_number(); if previous_forward.is_some_and(|old| height < old) { return Err(QueueError::ForwardOrder); } previous_forward = Some(height); }
        }
        let mut state = self.state.lock().expect("event queue lock poisoned");
        if !state.accepting { return Err(QueueError::Closed); }
        let cap = self.cap(class);
        if cap == 0 || Self::queue_mut(&mut state, class).len().saturating_add(values.len()) > cap { return Err(QueueError::Full(class)); }
        let mut sequences = Vec::with_capacity(values.len());
        for delivery in values { let sequence = state.next_sequence; state.next_sequence = state.next_sequence.wrapping_add(1); Self::queue_mut(&mut state, class).push_back(QueuedDelivery { sequence, class, delivery }); sequences.push(sequence); }
        Ok(sequences)
    }
    pub fn drain(&self, class: QueueClass, limit: usize) -> Vec<QueuedDelivery> { let mut state = self.state.lock().expect("event queue lock poisoned"); let queue = Self::queue_mut(&mut state, class); let count = limit.min(queue.len()); queue.drain(..count).collect() }
    pub fn front(&self, class: QueueClass) -> Option<QueuedDelivery> { let mut state = self.state.lock().expect("event queue lock poisoned"); Self::queue_mut(&mut state, class).front().cloned() }
    pub fn acknowledge(&self, class: QueueClass, sequence: u64) -> bool { let mut state = self.state.lock().expect("event queue lock poisoned"); let queue = Self::queue_mut(&mut state, class); if queue.front().is_some_and(|delivery| delivery.sequence == sequence) { queue.pop_front(); true } else { false } }
    pub fn flush_due(&self, now: Instant) -> Vec<QueuedDelivery> { let mut state = self.state.lock().expect("event queue lock poisoned"); if now.duration_since(state.last_flush) < FLUSH_INTERVAL { return Vec::new(); } state.last_flush = now; let mut out = Vec::with_capacity(state.realtime.len()); out.extend(state.realtime.drain(..)); out }
    pub fn len(&self, class: QueueClass) -> usize { let mut state = self.state.lock().expect("event queue lock poisoned"); Self::queue_mut(&mut state, class).len() }
    pub fn open(&self) { self.state.lock().expect("event queue lock poisoned").accepting = true; }
    pub fn close(&self) { self.state.lock().expect("event queue lock poisoned").accepting = false; }
    pub fn is_accepting(&self) -> bool { self.state.lock().expect("event queue lock poisoned").accepting }
    pub fn sink(self: &Arc<Self>) -> TransactionalEventSink { TransactionalEventSink { queues: self.clone(), class: QueueClass::Realtime, failures: 0, last_error: None } }
}

pub struct TransactionalEventSink { queues: Arc<EventQueues>, class: QueueClass, failures: u64, last_error: Option<QueueError> }
impl TransactionalEventSink {
    pub fn with_class(mut self, class: QueueClass) -> Self { self.class = class; self }
    pub const fn failures(&self) -> u64 { self.failures }
    pub fn last_error(&self) -> Option<&QueueError> { self.last_error.as_ref() }
    pub fn enqueue(&mut self, delivery: Delivery) -> Result<u64, QueueError> { let result = self.queues.push(self.class, delivery); if let Err(error) = &result { self.failures += 1; self.last_error = Some(error.clone()); } result }
    pub fn enqueue_reorg(&mut self, deliveries: Vec<Delivery>) -> Result<Vec<u64>, QueueError> { let result = self.queues.push_batch(self.class, deliveries); if let Err(error) = &result { self.failures += 1; self.last_error = Some(error.clone()); } result }
}
impl EventSink for TransactionalEventSink { fn contract(&mut self, event: ContractEvent) { let _ = self.enqueue(Delivery::Event(event.into())); } fn block(&mut self, event: BlockEvent) { let _ = self.enqueue(Delivery::Event(event.into())); } }

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeliveryWorkerMetrics { pub delivered: u64, pub failures: u64, pub retries: u64 }

pub struct DeliveryWorker { queues: Arc<EventQueues>, retry_limit: usize, metrics: DeliveryWorkerMetrics }
impl DeliveryWorker {
    pub fn new(queues: Arc<EventQueues>, retry_limit: usize) -> Self { Self { queues, retry_limit, metrics: DeliveryWorkerMetrics::default() } }
    pub const fn metrics(&self) -> DeliveryWorkerMetrics { self.metrics }
    pub fn drain<F>(&mut self, mut dispatch: F) -> Result<(), String> where F: FnMut(&QueuedDelivery) -> Result<(), String> {
        for class in [QueueClass::History, QueueClass::Realtime, QueueClass::Solid] {
            while let Some(delivery) = self.queues.front(class) {
                let mut failure = None;
                for attempt in 0..=self.retry_limit {
                    match dispatch(&delivery) {
                        Ok(()) => { failure = None; break; }
                        Err(error) => { failure = Some(error); self.metrics.failures = self.metrics.failures.saturating_add(1); if attempt < self.retry_limit { self.metrics.retries = self.metrics.retries.saturating_add(1); } }
                    }
                }
                if let Some(error) = failure { return Err(format!("{:?} delivery {} failed: {error}", class, delivery.sequence)); }
                if !self.queues.acknowledge(class, delivery.sequence) { return Err(format!("{:?} delivery {} changed before acknowledgement", class, delivery.sequence)); }
                self.metrics.delivered = self.metrics.delivered.saturating_add(1);
            }
        }
        Ok(())
    }
}
impl FilterSink for TransactionalEventSink { fn filter(&mut self, event: FilterEvent) { let _ = self.enqueue(Delivery::Filter(event)); } }
