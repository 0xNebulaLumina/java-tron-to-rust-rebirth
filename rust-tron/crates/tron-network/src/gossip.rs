use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use crate::sync::SyncBlockId;

pub const PENDING_INVENTORY_LIMIT: usize = 100_000;
pub const TX_CACHE_LIMIT: usize = 50_000;
pub const BLOCK_CACHE_LIMIT: usize = 10;
pub const SPREAD_QUEUE_LIMIT: usize = 1_000;
pub const INVENTORY_CACHE_LIMIT: usize = 20_000;
pub const INVENTORY_CACHE_TTL_MS: i64 = 3_600_000;
pub const PROVIDER_KEY_LIMIT: usize = 100_000;
pub const PROVIDER_BYTE_LIMIT: usize = 8 * 1024 * 1024;
pub const PROVIDER_KEY_BYTES: usize = 48;
pub const PROVIDER_PEER_BYTES: usize = 32;
pub const TX_INVENTORY_PER_10S: usize = 10_000;
pub const BLOCK_INVENTORY_PER_10S: usize = 100;
pub const TX_CACHE_TTL_MS: i64 = 3_600_000;
pub const BLOCK_CACHE_TTL_MS: i64 = 60_000;
pub const BLOCK_STALE_MS: i64 = 3_000;
pub const REQUEST_STALE_MS: i64 = 15_000;
pub const ADV_REQUEST_TIMEOUT_MS: i64 = 20_000;
pub const TX_BATCH_BYTES: usize = 1_000_000;
pub const MAX_TX_FETCH_PER_PEER: usize = 1_000;
pub const MAX_BLOCK_FETCH_PER_PEER: usize = 100;
pub const MAX_GOSSIP_PAYLOAD_BYTES: usize = crate::framing::MAX_FRAME_SIZE;
pub const TX_CACHE_BYTE_LIMIT: usize = 64 * 1024 * 1024;
pub const BLOCK_CACHE_BYTE_LIMIT: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)] pub enum InventoryType { Transaction, Block }
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)] pub struct InventoryKey { pub hash: [u8; 32], pub kind: InventoryType }
#[derive(Clone, Debug, PartialEq, Eq)] pub struct Advertisement { pub kind: InventoryType, pub hashes: Vec<[u8; 32]> }
#[derive(Clone, Debug, PartialEq, Eq)] pub struct FetchRequest { pub kind: InventoryType, pub hashes: Vec<[u8; 32]> }
#[derive(Clone, Debug, PartialEq, Eq)] pub struct Payload { pub key: InventoryKey, pub bytes: Vec<u8>, pub block: Option<SyncBlockId>, pub produced_at_ms: i64 }
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)] pub enum GossipError {
    #[error("duplicate inventory hash")] Duplicate,
    #[error("unsupported inventory type")] UnknownType,
    #[error("peer is not synchronization-complete")] Syncing,
    #[error("inventory message exceeds the Java-configured limit")] InventoryLimit,
    #[error("inventory rate exceeded")] InventoryRateLimited,
    #[error("provider inventory budget exhausted")] ProviderLimit,
    #[error("fetch did not correlate with an advertisement or sync response")] Uncorrelated,
    #[error("fetch exceeds the per-peer limit")] FetchLimit,
    #[error("fetch rate exceeded")] RateLimited,
    #[error("requested item is unavailable")] Missing,
    #[error("payload exceeds the individual frame ceiling")]
    PayloadTooLarge,
    #[error("payload exceeds its cache byte budget")]
    CacheByteLimit,
}
#[derive(Clone, Copy, Debug)] pub struct GossipLimits { pub tx_inventory_per_10s: usize, pub block_inventory_per_10s: usize, pub provider_keys: usize, pub provider_bytes: usize }
impl Default for GossipLimits { fn default() -> Self { Self { tx_inventory_per_10s: TX_INVENTORY_PER_10S, block_inventory_per_10s: BLOCK_INVENTORY_PER_10S, provider_keys: PROVIDER_KEY_LIMIT, provider_bytes: PROVIDER_BYTE_LIMIT } } }
#[derive(Clone, Debug)] struct Cached { payload: Payload, at: i64, sequence: u64 }
#[derive(Clone, Debug)] struct TimedKeys { entries: HashMap<InventoryKey, i64>, order: VecDeque<(InventoryKey, i64)> }
impl TimedKeys {
    fn new() -> Self { Self { entries: HashMap::new(), order: VecDeque::new() } }
    fn purge(&mut self, now: i64) { while self.order.front().is_some_and(|(key, at)| self.entries.get(key).is_none_or(|current| current != at || now.saturating_sub(*at) >= INVENTORY_CACHE_TTL_MS)) { if let Some((key, at)) = self.order.pop_front() { if self.entries.get(&key) == Some(&at) { self.entries.remove(&key); } } } }
    fn insert(&mut self, key: InventoryKey, now: i64) { self.purge(now); self.entries.insert(key.clone(), now); self.order.push_back((key, now)); while self.entries.len() > INVENTORY_CACHE_LIMIT { if let Some((old, at)) = self.order.pop_front() { if self.entries.get(&old) == Some(&at) { self.entries.remove(&old); } } } }
    fn contains(&mut self, key: &InventoryKey, now: i64) -> bool { self.purge(now); self.entries.contains_key(key) }
    fn len(&self) -> usize { self.entries.len() }
}
#[derive(Clone, Debug)] struct ProviderEntry { peers: BTreeMap<SocketAddr, i64> }
#[derive(Clone, Debug)] struct PeerGossip { complete: bool, received: TimedKeys, spread: TimedKeys, requested: HashMap<InventoryKey, i64>, queue: VecDeque<InventoryKey>, fetch_rate_start: i64, fetch_rate_count: usize, inventory_rate_start: [i64; 2], inventory_rate_count: [usize; 2] }
impl PeerGossip { fn new() -> Self { Self { complete: false, received: TimedKeys::new(), spread: TimedKeys::new(), requested: HashMap::new(), queue: VecDeque::new(), fetch_rate_start: 0, fetch_rate_count: 0, inventory_rate_start: [0; 2], inventory_rate_count: [0; 2] } } }
#[derive(Clone, Debug)] pub struct GossipService { peers: HashMap<SocketAddr, PeerGossip>, providers: HashMap<InventoryKey, ProviderEntry>, pending: VecDeque<InventoryKey>, tx: HashMap<[u8; 32], Cached>, blocks: HashMap<[u8; 32], Cached>, tx_bytes: usize, block_bytes: usize, limits: GossipLimits, sequence: u64 }
impl Default for GossipService { fn default() -> Self { Self::with_limits(GossipLimits::default()) } }
impl GossipService {
    pub fn with_limits(limits: GossipLimits) -> Self { Self { peers: HashMap::new(), providers: HashMap::new(), pending: VecDeque::new(), tx: HashMap::new(), blocks: HashMap::new(), tx_bytes: 0, block_bytes: 0, limits, sequence: 0 } }
    pub fn add_peer(&mut self, peer: SocketAddr, sync_complete: bool) { self.peers.entry(peer).or_insert_with(PeerGossip::new).complete = sync_complete }
    pub fn set_sync_complete(&mut self, peer: SocketAddr, value: bool) { self.peers.entry(peer).or_insert_with(PeerGossip::new).complete = value }
    pub fn cache(&mut self, payload: Payload, now: i64) -> Result<(), GossipError> {
        self.purge(now);
        let payload_bytes = payload.bytes.len();
        if payload_bytes > MAX_GOSSIP_PAYLOAD_BYTES { return Err(GossipError::PayloadTooLarge); }
        let (count_limit, byte_limit, map, retained_bytes) = match payload.key.kind {
            InventoryType::Transaction => (TX_CACHE_LIMIT, TX_CACHE_BYTE_LIMIT, &mut self.tx, &mut self.tx_bytes),
            InventoryType::Block => (BLOCK_CACHE_LIMIT, BLOCK_CACHE_BYTE_LIMIT, &mut self.blocks, &mut self.block_bytes),
        };
        if payload_bytes > byte_limit { return Err(GossipError::CacheByteLimit); }
        let replaced_bytes = map.get(&payload.key.hash).map_or(0, |cached| cached.payload.bytes.len());
        let mut projected = retained_bytes.saturating_sub(replaced_bytes).saturating_add(payload_bytes);
        while map.len() - usize::from(map.contains_key(&payload.key.hash)) >= count_limit || projected > byte_limit {
            let Some(old) = map.iter().filter(|(hash, _)| **hash != payload.key.hash).min_by_key(|(hash, value)| (value.at, value.sequence, **hash)).map(|(key, _)| *key) else { return Err(GossipError::CacheByteLimit) };
            if let Some(evicted) = map.remove(&old) { *retained_bytes = retained_bytes.saturating_sub(evicted.payload.bytes.len()); }
            projected = retained_bytes.saturating_sub(replaced_bytes).saturating_add(payload_bytes);
        }
        self.sequence = self.sequence.wrapping_add(1);
        if let Some(old) = map.insert(payload.key.hash, Cached { payload, at: now, sequence: self.sequence }) { *retained_bytes = retained_bytes.saturating_sub(old.payload.bytes.len()); }
        *retained_bytes = retained_bytes.saturating_add(payload_bytes);
        Ok(())
    }
    pub fn receive_inventory(&mut self, peer: SocketAddr, adv: Advertisement, now: i64) -> Result<Vec<InventoryKey>, GossipError> {
        self.purge(now);
        self.peers.entry(peer).or_insert_with(PeerGossip::new);
        if !self.peers[&peer].complete { return Err(GossipError::Syncing) }
        let mut seen = HashSet::with_capacity(adv.hashes.len());
        if adv.hashes.iter().any(|hash| !seen.insert(*hash)) { return Err(GossipError::Duplicate) }
        let kind_index = usize::from(adv.kind == InventoryType::Block);
        let rate_limit = if adv.kind == InventoryType::Transaction { self.limits.tx_inventory_per_10s } else { self.limits.block_inventory_per_10s };
        if adv.hashes.len() > rate_limit { return Err(GossipError::InventoryLimit) }
        let state = self.peers.get_mut(&peer).expect("peer inserted");
        if now.saturating_sub(state.inventory_rate_start[kind_index]) >= 10_000 { state.inventory_rate_start[kind_index] = now; state.inventory_rate_count[kind_index] = 0; }
        if state.inventory_rate_count[kind_index].saturating_add(adv.hashes.len()) > rate_limit { return Err(GossipError::InventoryRateLimited) }
        let keys: Vec<_> = adv.hashes.into_iter().map(|hash| InventoryKey { hash, kind: adv.kind }).collect();
        let new_keys = keys.iter().filter(|key| !self.providers.contains_key(*key)).count();
        let new_associations = keys.iter().filter(|key| self.providers.get(*key).is_none_or(|entry| !entry.peers.contains_key(&peer))).count();
        let projected_keys = self.providers.len().saturating_add(new_keys);
        let projected_bytes = self.provider_bytes().saturating_add(new_keys.saturating_mul(PROVIDER_KEY_BYTES)).saturating_add(new_associations.saturating_mul(PROVIDER_PEER_BYTES));
        if projected_keys > self.limits.provider_keys || projected_bytes > self.limits.provider_bytes { return Err(GossipError::ProviderLimit) }
        self.peers.get_mut(&peer).expect("peer inserted").inventory_rate_count[kind_index] += keys.len();
        let mut accepted = Vec::new();
        for key in keys { self.peers.get_mut(&peer).expect("peer inserted").received.insert(key.clone(), now); self.providers.entry(key.clone()).or_insert_with(|| ProviderEntry { peers: BTreeMap::new() }).peers.insert(peer, now); if !self.contains(&key) && !self.pending.contains(&key) && self.pending.len() < PENDING_INVENTORY_LIMIT { self.pending.push_back(key.clone()); accepted.push(key); } }
        Ok(accepted)
    }
    pub fn schedule_fetch(&mut self, now: i64) -> Option<(SocketAddr, FetchRequest)> { self.purge(now); while let Some(key) = self.pending.pop_front() { let Some(providers) = self.providers.get(&key) else { continue }; let peer = providers.peers.keys().filter(|candidate| self.peers.get(candidate).is_some_and(|state| state.complete && !state.requested.contains_key(&key))).min_by_key(|candidate| (self.peers.get(candidate).map_or(usize::MAX, |state| state.requested.len()), **candidate)).copied(); if let Some(peer) = peer { self.peers.get_mut(&peer)?.requested.insert(key.clone(), now); return Some((peer, FetchRequest { kind: key.kind, hashes: vec![key.hash] })); } } None }
    pub fn spread(&mut self, key: InventoryKey, now: i64) -> Vec<SocketAddr> { let mut peers: Vec<_> = self.peers.keys().copied().collect(); peers.sort_unstable(); let mut out = Vec::new(); for peer in peers { let state = self.peers.get_mut(&peer).expect("peer exists"); if state.complete && !state.received.contains(&key, now) && !state.spread.contains(&key, now) && state.queue.len() < SPREAD_QUEUE_LIMIT { state.queue.push_back(key.clone()); state.spread.insert(key.clone(), now); out.push(peer); } } out }
    pub fn drain_spread(&mut self, peer: SocketAddr, max: usize) -> Vec<InventoryKey> { let Some(state) = self.peers.get_mut(&peer) else { return vec![] }; let mut output = Vec::new(); while output.len() < max { let Some(key) = state.queue.pop_front() else { break }; output.push(key) } output.sort_by_key(|key| match key.kind { InventoryType::Block => self.blocks.get(&key.hash).and_then(|cached| cached.payload.block.as_ref()).map_or(i64::MAX, |block| block.number), InventoryType::Transaction => i64::MAX }); output }
    pub fn serve_fetch(&mut self, peer: SocketAddr, req: &FetchRequest, now: i64, sync_allowed: impl Fn(&InventoryKey) -> bool) -> Result<Vec<Vec<Payload>>, GossipError> {
        self.purge(now);

        let mut seen = HashSet::with_capacity(req.hashes.len());
        if req.hashes.iter().any(|hash| !seen.insert(*hash)) {
            return Err(GossipError::Duplicate);
        }

        let limit = if req.kind == InventoryType::Block { MAX_BLOCK_FETCH_PER_PEER } else { MAX_TX_FETCH_PER_PEER };
        if req.hashes.len() > limit {
            return Err(GossipError::FetchLimit);
        }

        let rate_count = self.peers.get(&peer).map_or(0, |state| {
            if now.saturating_sub(state.fetch_rate_start) >= 10_000 { 0 } else { state.fetch_rate_count }
        });
        if rate_count.saturating_add(req.hashes.len()) > limit {
            return Err(GossipError::RateLimited);
        }

        let state = self.peers.get(&peer);
        let mut validated = Vec::with_capacity(req.hashes.len());
        for hash in &req.hashes {
            let key = InventoryKey { hash: *hash, kind: req.kind };
            let advertised = state.is_some_and(|state| state.spread.entries.contains_key(&key));
            if !advertised && !sync_allowed(&key) {
                return Err(GossipError::Uncorrelated);
            }
            let cached = match req.kind {
                InventoryType::Transaction => self.tx.get(hash),
                InventoryType::Block => self.blocks.get(hash),
            }.ok_or(GossipError::Missing)?;
            validated.push((key, advertised, cached.payload.clone()));
        }

        let state = self.peers.entry(peer).or_insert_with(PeerGossip::new);
        if now.saturating_sub(state.fetch_rate_start) >= 10_000 {
            state.fetch_rate_start = now;
            state.fetch_rate_count = 0;
        }
        state.fetch_rate_count += req.hashes.len();
        for (key, advertised, _) in &validated {
            if *advertised {
                state.spread.entries.remove(key);
            }
        }

        let payloads = validated.into_iter().map(|(_, _, payload)| payload);
        if req.kind == InventoryType::Block {
            return Ok(payloads.map(|payload| vec![payload]).collect());
        }
        let mut batches = Vec::new();
        let mut batch = Vec::new();
        let mut size = 0usize;
        for payload in payloads {
            if !batch.is_empty() && size.saturating_add(payload.bytes.len()) > TX_BATCH_BYTES {
                batches.push(std::mem::take(&mut batch));
                size = 0;
            }
            size = size.saturating_add(payload.bytes.len());
            batch.push(payload);
        }
        if !batch.is_empty() {
            batches.push(batch);
        }
        Ok(batches)
    }
    pub fn receive_payload(&mut self, peer: SocketAddr, payload: Payload, now: i64) -> Result<(), GossipError> { if payload.bytes.len() > MAX_GOSSIP_PAYLOAD_BYTES { return Err(GossipError::PayloadTooLarge) } let at = *self.peers.get(&peer).and_then(|state| state.requested.get(&payload.key)).ok_or(GossipError::Uncorrelated)?; if now.saturating_sub(at) > ADV_REQUEST_TIMEOUT_MS { self.peers.get_mut(&peer).expect("peer exists").requested.remove(&payload.key); return Err(GossipError::Uncorrelated) } let key = payload.key.clone(); self.cache(payload, now)?; self.peers.get_mut(&peer).expect("peer exists").requested.remove(&key); Ok(()) }
    pub fn disconnect(&mut self, peer: SocketAddr) { if let Some(state) = self.peers.remove(&peer) { for key in state.requested.into_keys() { if self.providers.get(&key).is_some_and(|entry| entry.peers.keys().any(|candidate| *candidate != peer)) && self.pending.len() < PENDING_INVENTORY_LIMIT && !self.pending.contains(&key) { self.pending.push_front(key) } } } for entry in self.providers.values_mut() { entry.peers.remove(&peer); } self.providers.retain(|_, entry| !entry.peers.is_empty()); self.pending.retain(|key| self.providers.contains_key(key)); }
    pub fn expire_requests(&mut self, now: i64) { self.purge(now); let peers: Vec<_> = self.peers.keys().copied().collect(); for peer in peers { let stale: Vec<_> = self.peers[&peer].requested.iter().filter(|(_, at)| now.saturating_sub(**at) >= REQUEST_STALE_MS).map(|(key, _)| key.clone()).collect(); for key in stale { self.peers.get_mut(&peer).expect("peer exists").requested.remove(&key); if self.providers.contains_key(&key) && self.pending.len() < PENDING_INVENTORY_LIMIT && !self.pending.contains(&key) { self.pending.push_back(key) } } } }
    pub fn inventory_state_sizes(&self, peer: SocketAddr) -> (usize, usize, usize, usize, usize) { let (received, spread) = self.peers.get(&peer).map_or((0, 0), |state| (state.received.len(), state.spread.len())); (received, spread, self.providers.len(), self.provider_bytes(), self.pending.len()) }
    pub fn cache_usage(&self) -> ((usize, usize), (usize, usize)) { ((self.tx.len(), self.tx_bytes), (self.blocks.len(), self.block_bytes)) }
    fn provider_bytes(&self) -> usize { self.providers.values().fold(0usize, |total, entry| total.saturating_add(PROVIDER_KEY_BYTES).saturating_add(entry.peers.len().saturating_mul(PROVIDER_PEER_BYTES))) }
    fn contains(&self, key: &InventoryKey) -> bool { match key.kind { InventoryType::Transaction => self.tx.contains_key(&key.hash), InventoryType::Block => self.blocks.contains_key(&key.hash) } }
    fn purge(&mut self, now: i64) { self.tx.retain(|_, cached| now.saturating_sub(cached.at) < TX_CACHE_TTL_MS); self.tx_bytes = self.tx.values().map(|cached| cached.payload.bytes.len()).sum(); self.blocks.retain(|_, cached| now.saturating_sub(cached.at) < BLOCK_CACHE_TTL_MS && now.saturating_sub(cached.payload.produced_at_ms) < BLOCK_STALE_MS); self.block_bytes = self.blocks.values().map(|cached| cached.payload.bytes.len()).sum(); for state in self.peers.values_mut() { state.received.purge(now); state.spread.purge(now); } for entry in self.providers.values_mut() { entry.peers.retain(|_, at| now.saturating_sub(*at) < INVENTORY_CACHE_TTL_MS); } self.providers.retain(|_, entry| !entry.peers.is_empty()); self.pending.retain(|key| self.providers.contains_key(key)); }
}
