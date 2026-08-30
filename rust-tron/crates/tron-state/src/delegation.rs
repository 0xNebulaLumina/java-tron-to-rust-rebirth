pub const FROM_PREFIX: u8 = 0x01;
pub const TO_PREFIX: u8 = 0x02;
pub const V2_FROM_PREFIX: u8 = 0x03;
pub const V2_TO_PREFIX: u8 = 0x04;
pub const LOCKED_PREFIX: u8 = 0x01;
pub const UNLOCKED_PREFIX: u8 = 0x00;

fn prefixed_pair(prefix: u8, first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + first.len() + second.len());
    key.push(prefix); key.extend_from_slice(first); key.extend_from_slice(second); key
}

#[must_use] pub fn legacy_resource_key(from: &[u8], to: &[u8]) -> Vec<u8> { let mut k=Vec::with_capacity(from.len()+to.len()); k.extend_from_slice(from); k.extend_from_slice(to); k }
#[must_use] pub fn resource_v2_key(from: &[u8], to: &[u8], locked: bool) -> Vec<u8> { prefixed_pair(if locked { LOCKED_PREFIX } else { UNLOCKED_PREFIX }, from, to) }
#[must_use] pub fn from_index_key(from: &[u8], to: &[u8]) -> Vec<u8> { prefixed_pair(FROM_PREFIX, from, to) }
#[must_use] pub fn to_index_key(to: &[u8], from: &[u8]) -> Vec<u8> { prefixed_pair(TO_PREFIX, to, from) }
#[must_use] pub fn v2_from_index_key(from: &[u8], to: &[u8]) -> Vec<u8> { prefixed_pair(V2_FROM_PREFIX, from, to) }
#[must_use] pub fn v2_to_index_key(to: &[u8], from: &[u8]) -> Vec<u8> { prefixed_pair(V2_TO_PREFIX, to, from) }
#[must_use] pub fn index_prefix(prefix: u8, address: &[u8]) -> Vec<u8> { let mut k=Vec::with_capacity(1+address.len()); k.push(prefix); k.extend_from_slice(address); k }
