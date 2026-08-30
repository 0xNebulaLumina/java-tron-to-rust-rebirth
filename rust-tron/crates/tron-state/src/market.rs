use core::fmt;

use prost::Message;
use tron_crypto::keccak256;
use tron_protocol::protocol::{MarketAccountOrder, MarketOrder, MarketOrderIdList, MarketPrice, MarketPriceList};

use crate::{StateStore, StoreKind};

pub const TOKEN_ID_LENGTH: usize = 19;
pub const PAIR_KEY_LENGTH: usize = TOKEN_ID_LENGTH * 2;
pub const PAIR_PRICE_KEY_LENGTH: usize = PAIR_KEY_LENGTH + 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarketCodecError {
    TokenIdTooLong { maximum: usize, actual: usize },
    InvalidQuantity { sell: i64, buy: i64 },
}

impl fmt::Display for MarketCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TokenIdTooLong { maximum, actual } => write!(f, "market token id is {actual} bytes; maximum is {maximum}"),
            Self::InvalidQuantity { sell, buy } => write!(f, "market quantities must be positive: sell={sell}, buy={buy}"),
        }
    }
}
impl std::error::Error for MarketCodecError {}

#[derive(Debug)]
pub enum MarketStoreError {
    Codec(MarketCodecError),
    InvalidOrder(&'static str),
    Missing(&'static str, Vec<u8>),
    Corrupt(&'static str, prost::DecodeError),
    Detached(Vec<u8>),
    WrongNeighbor { order: Vec<u8>, neighbor: Vec<u8> },
    Cycle(Vec<u8>),
    Storage(tron_storage::StorageError),
}
impl From<MarketCodecError> for MarketStoreError { fn from(error: MarketCodecError) -> Self { Self::Codec(error) } }
impl From<tron_storage::StorageError> for MarketStoreError { fn from(error: tron_storage::StorageError) -> Self { Self::Storage(error) } }
impl fmt::Display for MarketStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => error.fmt(f),
            Self::InvalidOrder(reason) => write!(f, "invalid market order: {reason}"),
            Self::Missing(store, key) => write!(f, "missing {store} entry for {:02x?}", key),
            Self::Corrupt(store, error) => write!(f, "invalid {store} protobuf: {error}"),
            Self::Detached(id) => write!(f, "detached market order {:02x?}", id),
            Self::WrongNeighbor { order, neighbor } => write!(f, "wrong neighbor {:02x?} for market order {:02x?}", neighbor, order),
            Self::Cycle(id) => write!(f, "cycle in market order list at {:02x?}", id),
            Self::Storage(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for MarketStoreError {}

#[must_use]
pub fn gcd(a: i64, b: i64) -> i64 {
    if a == 0 || b == 0 { return 0; }
    let mut a = a;
    let mut b = b;
    while b != 0 { (a, b) = (b, a.wrapping_rem(b)); }
    a
}

fn padded_pair(sell: &[u8], buy: &[u8]) -> Result<[u8; PAIR_KEY_LENGTH], MarketCodecError> {
    for token in [sell, buy] {
        if token.len() > TOKEN_ID_LENGTH {
            return Err(MarketCodecError::TokenIdTooLong { maximum: TOKEN_ID_LENGTH, actual: token.len() });
        }
    }
    let mut out = [0; PAIR_KEY_LENGTH];
    out[..sell.len()].copy_from_slice(sell);
    out[TOKEN_ID_LENGTH..TOKEN_ID_LENGTH + buy.len()].copy_from_slice(buy);
    Ok(out)
}

pub fn pair_key(sell: &[u8], buy: &[u8]) -> Result<[u8; PAIR_KEY_LENGTH], MarketCodecError> { padded_pair(sell, buy) }

pub fn pair_price_key(sell: &[u8], buy: &[u8], sell_quantity: i64, buy_quantity: i64) -> Result<[u8; PAIR_PRICE_KEY_LENGTH], MarketCodecError> {
    if sell_quantity <= 0 || buy_quantity <= 0 {
        return Err(MarketCodecError::InvalidQuantity { sell: sell_quantity, buy: buy_quantity });
    }
    let divisor = gcd(sell_quantity, buy_quantity);
    pair_price_key_no_gcd(sell, buy, sell_quantity.wrapping_div(divisor), buy_quantity.wrapping_div(divisor))
}

pub fn pair_price_key_no_gcd(sell: &[u8], buy: &[u8], sell_quantity: i64, buy_quantity: i64) -> Result<[u8; PAIR_PRICE_KEY_LENGTH], MarketCodecError> {
    if sell_quantity <= 0 || buy_quantity <= 0 {
        return Err(MarketCodecError::InvalidQuantity { sell: sell_quantity, buy: buy_quantity });
    }
    let mut out = [0; PAIR_PRICE_KEY_LENGTH];
    out[..PAIR_KEY_LENGTH].copy_from_slice(&padded_pair(sell, buy)?);
    out[PAIR_KEY_LENGTH..PAIR_KEY_LENGTH + 8].copy_from_slice(&sell_quantity.to_be_bytes());
    out[PAIR_KEY_LENGTH + 8..].copy_from_slice(&buy_quantity.to_be_bytes());
    Ok(out)
}

pub fn pair_price_head_key(sell: &[u8], buy: &[u8]) -> Result<[u8; PAIR_PRICE_KEY_LENGTH], MarketCodecError> {
    let mut out = [0; PAIR_PRICE_KEY_LENGTH];
    out[..PAIR_KEY_LENGTH].copy_from_slice(&padded_pair(sell, buy)?);
    Ok(out)
}

pub fn order_id(address: &[u8], sell: &[u8], buy: &[u8], count: i64) -> Result<[u8; 32], MarketCodecError> {
    let pair = padded_pair(sell, buy)?;
    let mut input = Vec::with_capacity(address.len() + PAIR_KEY_LENGTH + 8);
    input.extend_from_slice(address);
    input.extend_from_slice(&pair);
    input.extend_from_slice(&count.to_be_bytes());
    Ok(keccak256(&input))
}

#[must_use]
pub fn decode_price(key: &[u8]) -> Option<(i64, i64)> {
    if key.len() != PAIR_PRICE_KEY_LENGTH { return None; }
    Some((i64::from_be_bytes(key[38..46].try_into().ok()?), i64::from_be_bytes(key[46..54].try_into().ok()?)))
}

#[must_use] pub fn pair_prefix(key: &[u8]) -> Option<&[u8]> { key.get(..PAIR_KEY_LENGTH) }

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinkedOrder { pub id: Vec<u8>, pub prev: Vec<u8>, pub next: Vec<u8> }

pub fn append_order(head: &mut Vec<u8>, tail: &mut Vec<u8>, current: &mut LinkedOrder, old_tail: Option<&mut LinkedOrder>) {
    current.prev.clear(); current.next.clear();
    if let Some(previous) = old_tail { previous.next.clone_from(&current.id); current.prev.clone_from(&previous.id); }
    else { head.clone_from(&current.id); }
    tail.clone_from(&current.id);
}

pub fn unlink_order(head: &mut Vec<u8>, tail: &mut Vec<u8>, current: &mut LinkedOrder, previous: Option<&mut LinkedOrder>, next: Option<&mut LinkedOrder>) {
    if let Some(prev) = previous { prev.next.clone_from(&current.next); } else { head.clone_from(&current.next); }
    if let Some(next) = next { next.prev.clone_from(&current.prev); } else { tail.clone_from(&current.prev); }
    current.prev.clear(); current.next.clear();
}

fn decode<T: Message + Default>(bytes: Vec<u8>, store: &'static str) -> Result<T, MarketStoreError> {
    T::decode(bytes.as_slice()).map_err(|error| MarketStoreError::Corrupt(store, error))
}

fn required(state: &StateStore, kind: StoreKind, key: &[u8], name: &'static str) -> Result<Vec<u8>, MarketStoreError> {
    state.store(kind).get(key).ok_or_else(|| MarketStoreError::Missing(name, key.to_vec()))
}

fn load_order(state: &StateStore, id: &[u8]) -> Result<MarketOrder, MarketStoreError> {
    let order: MarketOrder = decode(required(state, StoreKind::MarketOrder, id, "market_order")?, "market_order")?;
    if order.order_id != id { return Err(MarketStoreError::Detached(id.to_vec())); }
    Ok(order)
}

fn price_count(bytes: &[u8]) -> Result<i64, MarketStoreError> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| MarketStoreError::InvalidOrder("market price count must be an 8-byte signed integer"))?;
    Ok(i64::from_be_bytes(bytes))
}

fn validate_order_price(order: &MarketOrder, price_key: &[u8]) -> Result<(), MarketStoreError> {
    if pair_price_key(&order.sell_token_id, &order.buy_token_id, order.sell_token_quantity, order.buy_token_quantity)? != price_key {
        return Err(MarketStoreError::Detached(order.order_id.clone()));
    }
    Ok(())
}

pub fn market_price_count(state: &StateStore, sell: &[u8], buy: &[u8]) -> Result<i64, MarketStoreError> {
    let pair = pair_key(sell, buy)?;
    state.store(StoreKind::MarketPairToPrice).get(&pair).map_or(Ok(0), |bytes| price_count(&bytes))
}

pub fn market_price_keys(state: &StateStore, sell: &[u8], buy: &[u8], count: usize) -> Result<Vec<Vec<u8>>, MarketStoreError> {
    if count == 0 { return Ok(Vec::new()); }
    let pair = pair_key(sell, buy)?;
    let head = pair_price_head_key(sell, buy)?;
    let store = state.store(StoreKind::MarketPairPriceToOrder);
    if !store.contains_key(&head) { return Ok(Vec::new()); }
    let mut keys = store.prefix(&pair).into_iter().map(|(key, _)| key).filter(|key| key != &head).collect::<Vec<_>>();
    keys.sort_by(|left, right| tron_storage::market_total_cmp(left, right));
    keys.truncate(count);
    Ok(keys)
}
pub fn market_prices(state: &StateStore, sell: &[u8], buy: &[u8], count: usize) -> Result<MarketPriceList, MarketStoreError> {
    let prices = market_price_keys(state, sell, buy, count)?.into_iter().map(|key| {
        let (sell_token_quantity, buy_token_quantity) = decode_price(&key).expect("validated pair-price key");
        MarketPrice { sell_token_quantity, buy_token_quantity }
    }).collect();
    Ok(MarketPriceList { sell_token_id: sell.to_vec(), buy_token_id: buy.to_vec(), prices })
}


pub fn audit_market_price_chain(state: &StateStore, price_key: &[u8], limit: usize) -> Result<usize, MarketStoreError> {
    let ids: MarketOrderIdList = decode(required(state, StoreKind::MarketPairPriceToOrder, price_key, "market_pair_price_to_order")?, "market_pair_price_to_order")?;
    if ids.head.is_empty() != ids.tail.is_empty() { return Err(MarketStoreError::Detached(ids.head)); }
    let mut expected_prev = Vec::new();
    let mut id = ids.head;
    let mut visited = 0;
    while !id.is_empty() && visited < limit {
        let order = load_order(state, &id)?;
        if order.prev != expected_prev { return Err(MarketStoreError::WrongNeighbor { order: id, neighbor: order.prev }); }
        validate_order_price(&order, price_key)?;
        expected_prev = order.order_id;
        id = order.next;
        visited += 1;
    }
    if id.is_empty() && expected_prev != ids.tail { return Err(MarketStoreError::Detached(ids.tail)); }
    Ok(visited)
}

pub fn append_market_order(state: &StateStore, mut order: MarketOrder) -> Result<(), MarketStoreError> {
    if order.order_id.is_empty() || order.owner_address.is_empty() { return Err(MarketStoreError::InvalidOrder("order and owner IDs must be non-empty")); }
    if !order.prev.is_empty() || !order.next.is_empty() { return Err(MarketStoreError::Detached(order.order_id)); }
    if state.store(StoreKind::MarketOrder).contains_key(&order.order_id) { return Err(MarketStoreError::InvalidOrder("order ID already exists")); }
    let pair = pair_key(&order.sell_token_id, &order.buy_token_id)?;
    let price_key = pair_price_key(&order.sell_token_id, &order.buy_token_id, order.sell_token_quantity, order.buy_token_quantity)?;

    let mut account = match state.store(StoreKind::MarketAccount).get(&order.owner_address) {
        Some(bytes) => decode::<MarketAccountOrder>(bytes, "market_account")?,
        None => MarketAccountOrder { owner_address: order.owner_address.clone(), ..Default::default() },
    };
    if account.owner_address != order.owner_address || account.orders.iter().any(|id| id == &order.order_id)
        || account.count < 0 || account.count as usize != account.orders.len() || account.total_count < account.count {
        return Err(MarketStoreError::Detached(order.order_id));
    }

    let ids_store = state.store(StoreKind::MarketPairPriceToOrder);
    let existing_ids = ids_store.get(&price_key);
    let new_price = existing_ids.is_none();
    let mut ids = existing_ids.map_or(Ok(MarketOrderIdList::default()), |bytes| decode(bytes, "market_pair_price_to_order"))?;
    if ids.head.is_empty() != ids.tail.is_empty() { return Err(MarketStoreError::Detached(price_key.to_vec())); }
    let mut tail = if ids.tail.is_empty() { None } else { Some(load_order(state, &ids.tail)?) };
    if let Some(entry) = tail.as_ref() {
        if entry.order_id != ids.tail || !entry.next.is_empty() { return Err(MarketStoreError::WrongNeighbor { order: entry.order_id.clone(), neighbor: entry.next.clone() }); }
        validate_order_price(entry, &price_key)?;
        order.prev.clone_from(&entry.order_id);
    } else {
        ids.head.clone_from(&order.order_id);
    }
    ids.tail.clone_from(&order.order_id);

    let pair_store = state.store(StoreKind::MarketPairToPrice);
    let old_count = pair_store.get(&pair).map_or(Ok(0), |bytes| price_count(&bytes))?;
    if old_count < 0 || (old_count == 0) != !ids_store.contains_key(&pair_price_head_key(&order.sell_token_id, &order.buy_token_id)?) {
        return Err(MarketStoreError::Detached(pair.to_vec()));
    }
    let new_count = if new_price { old_count.checked_add(1).ok_or(MarketStoreError::InvalidOrder("market price count overflow"))? } else { old_count };

    account.orders.push(order.order_id.clone());
    account.count = account.count.checked_add(1).ok_or(MarketStoreError::InvalidOrder("account active count overflow"))?;
    account.total_count = account.total_count.checked_add(1).ok_or(MarketStoreError::InvalidOrder("account total count overflow"))?;

    let mut batch = state.batch();
    let order_store = StoreKind::MarketOrder.name();
    if let Some(entry) = tail.as_mut() {
        entry.next.clone_from(&order.order_id);
        batch.put(&order_store, &entry.order_id, &entry.encode_to_vec());
    }
    batch.put(&order_store, &order.order_id, &order.encode_to_vec());
    batch.put(&StoreKind::MarketAccount.name(), &order.owner_address, &account.encode_to_vec());
    if new_price {
        if old_count == 0 { batch.put(&StoreKind::MarketPairPriceToOrder.name(), &pair_price_head_key(&order.sell_token_id, &order.buy_token_id)?, &[]); }
        batch.put(&StoreKind::MarketPairToPrice.name(), &pair, &new_count.to_be_bytes());
    }
    batch.put(&StoreKind::MarketPairPriceToOrder.name(), &price_key, &ids.encode_to_vec());
    batch.commit()?;
    Ok(())
}

pub fn unlink_market_order(state: &StateStore, order_id: &[u8]) -> Result<MarketOrder, MarketStoreError> {
    let order = load_order(state, order_id)?;
    if order.prev == order_id || order.next == order_id { return Err(MarketStoreError::Cycle(order_id.to_vec())); }
    let pair = pair_key(&order.sell_token_id, &order.buy_token_id)?;
    let price_key = pair_price_key(&order.sell_token_id, &order.buy_token_id, order.sell_token_quantity, order.buy_token_quantity)?;
    let mut ids: MarketOrderIdList = decode(required(state, StoreKind::MarketPairPriceToOrder, &price_key, "market_pair_price_to_order")?, "market_pair_price_to_order")?;
    if ids.head.is_empty() != ids.tail.is_empty() || (order.prev.is_empty() != (ids.head == order_id)) || (order.next.is_empty() != (ids.tail == order_id)) {
        return Err(MarketStoreError::Detached(order_id.to_vec()));
    }
    let head_key = pair_price_head_key(&order.sell_token_id, &order.buy_token_id)?;
    if !state.store(StoreKind::MarketPairPriceToOrder).contains_key(&head_key) { return Err(MarketStoreError::Detached(pair.to_vec())); }
    let pair_count = price_count(&required(state, StoreKind::MarketPairToPrice, &pair, "market_pair_to_price")?)?;
    if pair_count <= 0 { return Err(MarketStoreError::Detached(pair.to_vec())); }
    let mut previous = if order.prev.is_empty() { None } else { Some(load_order(state, &order.prev)?) };
    let mut next = if order.next.is_empty() { None } else { Some(load_order(state, &order.next)?) };
    if let Some(entry) = previous.as_ref() {
        if entry.next != order_id { return Err(MarketStoreError::WrongNeighbor { order: order_id.to_vec(), neighbor: entry.order_id.clone() }); }
        validate_order_price(entry, &price_key)?;
    }
    if let Some(entry) = next.as_ref() {
        if entry.prev != order_id { return Err(MarketStoreError::WrongNeighbor { order: order_id.to_vec(), neighbor: entry.order_id.clone() }); }
        validate_order_price(entry, &price_key)?;
    }

    let mut account: MarketAccountOrder = decode(required(state, StoreKind::MarketAccount, &order.owner_address, "market_account")?, "market_account")?;
    if account.owner_address != order.owner_address || account.count <= 0 || account.count as usize != account.orders.len() || account.total_count < account.count {
        return Err(MarketStoreError::Detached(order.owner_address));
    }
    let account_position = account.orders.iter().position(|id| id == order_id).ok_or_else(|| MarketStoreError::Detached(order_id.to_vec()))?;
    if account.orders.iter().filter(|id| id.as_slice() == order_id).count() != 1 { return Err(MarketStoreError::Detached(order_id.to_vec())); }

    if let Some(entry) = previous.as_mut() { entry.next.clone_from(&order.next); } else { ids.head.clone_from(&order.next); }
    if let Some(entry) = next.as_mut() { entry.prev.clone_from(&order.prev); } else { ids.tail.clone_from(&order.prev); }
    account.orders.remove(account_position);
    account.count -= 1;

    let mut batch = state.batch();
    let order_store = StoreKind::MarketOrder.name();
    if let Some(entry) = previous { batch.put(&order_store, &entry.order_id, &entry.encode_to_vec()); }
    if let Some(entry) = next { batch.put(&order_store, &entry.order_id, &entry.encode_to_vec()); }
    batch.delete(&order_store, order_id);
    batch.put(&StoreKind::MarketAccount.name(), &account.owner_address, &account.encode_to_vec());
    if ids.head.is_empty() {
        batch.delete(&StoreKind::MarketPairPriceToOrder.name(), &price_key);
        if pair_count == 1 {
            batch.delete(&StoreKind::MarketPairToPrice.name(), &pair);
            batch.delete(&StoreKind::MarketPairPriceToOrder.name(), &head_key);
        } else {
            batch.put(&StoreKind::MarketPairToPrice.name(), &pair, &(pair_count - 1).to_be_bytes());
        }
    } else {
        batch.put(&StoreKind::MarketPairPriceToOrder.name(), &price_key, &ids.encode_to_vec());
    }
    batch.commit()?;
    Ok(order)
}
