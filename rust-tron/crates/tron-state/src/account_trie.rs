use core::fmt;
use std::collections::{BTreeMap, HashMap};

use prost::Message;
use tron_crypto::keccak256;
use tron_protocol::protocol::Account;

pub const MAX_TRON_ADDRESS_BYTES: usize = 21;
pub const MAX_REDUCED_ACCOUNT_BYTES: usize = 128;
pub const MAX_TRIE_LEAVES: usize = 1_000_000;
pub const MAX_TRIE_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TRIE_NODE_BYTES: usize = 1024;
pub const MAX_TRIE_DEPTH: usize = 64;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrieLimits {
    pub max_value_bytes: usize,
    pub max_leaves: usize,
    pub max_total_bytes: usize,
    pub max_node_bytes: usize,
    pub max_depth: usize,
}

impl Default for TrieLimits {
    fn default() -> Self {
        Self {
            max_value_bytes: MAX_REDUCED_ACCOUNT_BYTES,
            max_leaves: MAX_TRIE_LEAVES,
            max_total_bytes: MAX_TRIE_TOTAL_BYTES,
            max_node_bytes: MAX_TRIE_NODE_BYTES,
            max_depth: MAX_TRIE_DEPTH,
        }
    }
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrieError {
    EmptyAddress,
    AddressTooLong { actual: usize, maximum: usize },
    ValueTooLarge { actual: usize, maximum: usize },
    LeafLimitExceeded { actual: usize, maximum: usize },
    TotalBytesLimitExceeded { actual: usize, maximum: usize },
    NodeBytesLimitExceeded { actual: usize, maximum: usize },
    DepthLimitExceeded { actual: usize, maximum: usize },
    MissingNode([u8; 32]),
    InvalidLimits,

    InvalidRootLength(usize),
    SuppliedRootMismatch { expected: [u8; 32], actual: [u8; 32] },
}

impl fmt::Display for TrieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "account trie error: {self:?}")
    }
}

impl std::error::Error for TrieError {}
pub fn account_trie_key(address: &[u8]) -> Result<Vec<u8>, TrieError> {
    if address.is_empty() {
        return Err(TrieError::EmptyAddress);
    }
    if address.len() > MAX_TRON_ADDRESS_BYTES {
        return Err(TrieError::AddressTooLong { actual: address.len(), maximum: MAX_TRON_ADDRESS_BYTES });
    }
    Ok(rlp_bytes(address))
}

pub fn address_nibbles(address: &[u8]) -> Result<Vec<u8>, TrieError> {
    Ok(bytes_nibbles(&account_trie_key(address)?))
}

#[must_use]
pub fn reduced_account_value(account: &Account) -> Vec<u8> {
    let mut reduced = Account::default();
    reduced.address.clone_from(&account.address);
    reduced.balance = account.balance;
    reduced.allowance = account.allowance;
    reduced.encode_to_vec()
}

fn bytes_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(byte >> 4);
        out.push(byte & 15);
    }
    out
}

fn compact_key_path(key: &[u8], start: usize, end: usize, leaf: bool) -> Vec<u8> {
    let path = &key[start..end];
    let odd = path.len() % 2 == 1;
    let flag = if leaf { 2 } else { 0 } + u8::from(odd);
    let mut nibbles = Vec::with_capacity(path.len() + 2);
    nibbles.push(flag);
    if !odd {
        nibbles.push(0);
    }
    nibbles.extend_from_slice(path);
    nibbles.chunks_exact(2).map(|pair| (pair[0] << 4) | pair[1]).collect()
}

fn rlp_bytes(value: &[u8]) -> Vec<u8> {
    if value.len() == 1 && value[0] < 0x80 {
        return value.to_vec();
    }
    if value.len() < 56 {
        let mut out = Vec::with_capacity(value.len() + 1);
        out.push(0x80 + value.len() as u8);
        out.extend_from_slice(value);
        return out;
    }
    let len = (value.len() as u64).to_be_bytes();
    let first = len.iter().position(|&byte| byte != 0).unwrap_or(7);
    let size = &len[first..];
    let mut out = Vec::with_capacity(1 + size.len() + value.len());
    out.push(0xb7 + size.len() as u8);
    out.extend_from_slice(size);
    out.extend_from_slice(value);
    out
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let len = items.iter().map(Vec::len).sum::<usize>();
    let mut out = Vec::with_capacity(len + 9);
    if len < 56 {
        out.push(0xc0 + len as u8);
    } else {
        let raw = (len as u64).to_be_bytes();
        let first = raw.iter().position(|&byte| byte != 0).unwrap_or(7);
        let size = &raw[first..];
        out.push(0xf7 + size.len() as u8);
        out.extend_from_slice(size);
    }
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

#[derive(Clone, Debug)]
pub struct AccountTrie {
    leaves: BTreeMap<Vec<u8>, Vec<u8>>,
    total_bytes: usize,
    nodes: HashMap<[u8; 32], Vec<u8>>,
    forced_root: Option<[u8; 32]>,
    limits: TrieLimits,
}

impl Default for AccountTrie {
    fn default() -> Self {
        Self {
            leaves: BTreeMap::new(),
            total_bytes: 0,
            nodes: HashMap::new(),
            forced_root: None,
            limits: TrieLimits::default(),
        }
    }
}

impl AccountTrie {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_limits(limits: TrieLimits) -> Result<Self, TrieError> {
        if limits.max_depth > MAX_TRIE_DEPTH {
            return Err(TrieError::InvalidLimits);
        }
        Ok(Self { limits, ..Self::default() })
    }


    pub fn with_supplied_root(root: &[u8]) -> Result<Self, TrieError> {
        let root = <[u8; 32]>::try_from(root).map_err(|_| TrieError::InvalidRootLength(root.len()))?;
        Ok(Self { forced_root: Some(root), ..Self::default() })
    }

    pub fn force_root(&mut self, root: Option<[u8; 32]>) {
        self.forced_root = root;
    }

    pub fn put_raw<K: AsRef<[u8]>>(&mut self, key: K, value: Vec<u8>) -> Result<(), TrieError> {
        let key = bytes_nibbles(key.as_ref());
        if value.is_empty() {
            if let Some(old) = self.leaves.remove(&key) {
                self.total_bytes -= old.len();
            }
            self.nodes.clear();
            return Ok(());
        }
        if value.len() > self.limits.max_value_bytes {
            return Err(TrieError::ValueTooLarge { actual: value.len(), maximum: self.limits.max_value_bytes });
        }
        let old_len = self.leaves.get(&key).map_or(0, Vec::len);
        let leaf_count = self.leaves.len() + usize::from(old_len == 0);
        if leaf_count > self.limits.max_leaves {
            return Err(TrieError::LeafLimitExceeded { actual: leaf_count, maximum: self.limits.max_leaves });
        }
        let total_bytes = self.total_bytes - old_len + value.len();
        if total_bytes > self.limits.max_total_bytes {
            return Err(TrieError::TotalBytesLimitExceeded { actual: total_bytes, maximum: self.limits.max_total_bytes });
        }
        self.leaves.insert(key, value);
        self.total_bytes = total_bytes;
        self.nodes.clear();
        Ok(())
    }

    pub fn put_account(&mut self, account: &Account) -> Result<(), TrieError> {
        let key = account_trie_key(&account.address)?;
        self.put_raw(key, reduced_account_value(account))
    }

    pub fn remove_address(&mut self, address: &[u8]) -> Result<(), TrieError> {
        let key = bytes_nibbles(&account_trie_key(address)?);
        if let Some(old) = self.leaves.remove(&key) {
            self.total_bytes -= old.len();
        }
        self.nodes.clear();
        Ok(())
    }
    #[must_use]
    pub fn get_address(&self, address: &[u8]) -> Result<Option<&[u8]>, TrieError> {
        let key = bytes_nibbles(&account_trie_key(address)?);
        Ok(self.leaves.get(&key).map(Vec::as_slice))
    }
    #[must_use]
    pub fn node(&self, hash: &[u8; 32]) -> Option<&[u8]> {
        self.nodes.get(hash).map(Vec::as_slice)
    }

    pub fn root_node_encoding(&mut self) -> Result<Option<Vec<u8>>, TrieError> {
        self.nodes.clear();
        if self.leaves.is_empty() {
            return Ok(None);
        }
        let limits = self.limits;
        let entries = self.leaves.iter().collect::<Vec<_>>();
        let mut encoded_bytes = self.total_bytes;
        let result = Self::encode_node(&mut self.nodes, limits, &mut encoded_bytes, &entries, 0).map(Some);
        if result.is_err() {
            self.nodes.clear();
        }
        result
    }

    pub fn logical_root(&mut self) -> Result<[u8; 32], TrieError> {
        Ok(self.root_node_encoding()?.map_or_else(|| keccak256(&[0x80]), |encoded| keccak256(&encoded)))
    }

    pub fn root_hash(&mut self) -> Result<[u8; 32], TrieError> {
        let logical = self.logical_root()?;
        Ok(self.forced_root.unwrap_or(logical))
    }

    pub fn validate_supplied_root(&mut self) -> Result<[u8; 32], TrieError> {
        let actual = self.logical_root()?;
        if let Some(expected) = self.forced_root {
            if expected != actual {
                return Err(TrieError::SuppliedRootMismatch { expected, actual });
            }
        }
        Ok(actual)
    }

    fn checked_node(limits: TrieLimits, encoded_bytes: &mut usize, encoded: Vec<u8>) -> Result<Vec<u8>, TrieError> {
        if encoded.len() > limits.max_node_bytes {
            return Err(TrieError::NodeBytesLimitExceeded { actual: encoded.len(), maximum: limits.max_node_bytes });
        }
        let total = encoded_bytes.checked_add(encoded.len()).unwrap_or(usize::MAX);
        if total > limits.max_total_bytes {
            return Err(TrieError::TotalBytesLimitExceeded { actual: total, maximum: limits.max_total_bytes });
        }
        *encoded_bytes = total;
        Ok(encoded)
    }

    fn child_ref(nodes: &mut HashMap<[u8; 32], Vec<u8>>, encoded: Vec<u8>) -> Vec<u8> {
        if encoded.len() < 32 {
            encoded
        } else {
            let hash = keccak256(&encoded);
            nodes.insert(hash, encoded);
            rlp_bytes(&hash)
        }
    }

    fn encode_node(
        nodes: &mut HashMap<[u8; 32], Vec<u8>>,
        limits: TrieLimits,
        encoded_bytes: &mut usize,
        entries: &[(&Vec<u8>, &Vec<u8>)],
        depth: usize,
    ) -> Result<Vec<u8>, TrieError> {
        if depth > limits.max_depth {
            return Err(TrieError::DepthLimitExceeded { actual: depth, maximum: limits.max_depth });
        }
        if let Some(actual) = entries.iter().map(|entry| entry.0.len()).filter(|&len| len > limits.max_depth).max() {
            return Err(TrieError::DepthLimitExceeded { actual, maximum: limits.max_depth });
        }
        debug_assert!(!entries.is_empty());
        if entries.len() == 1 {
            let node = rlp_list(&[
                rlp_bytes(&compact_key_path(entries[0].0, depth, entries[0].0.len(), true)),
                rlp_bytes(entries[0].1),
            ]);
            return Self::checked_node(limits, encoded_bytes, node);
        }

        let shortest = entries.iter().map(|entry| entry.0.len()).min().unwrap_or(depth);
        let mut common = depth;
        while common < shortest
            && entries[1..].iter().all(|entry| entry.0[common] == entries[0].0[common])
        {
            common += 1;
        }
        if common > depth {
            let child = Self::encode_node(nodes, limits, encoded_bytes, entries, common)?;
            let child = Self::child_ref(nodes, child);
            let node = rlp_list(&[
                rlp_bytes(&compact_key_path(entries[0].0, depth, common, false)),
                child,
            ]);
            return Self::checked_node(limits, encoded_bytes, node);
        }
        if depth == limits.max_depth {
            return Err(TrieError::DepthLimitExceeded { actual: depth + 1, maximum: limits.max_depth });
        }

        let mut items = Vec::with_capacity(17);
        let mut cursor = usize::from(entries[0].0.len() == depth);
        for nibble in 0..16 {
            let start = cursor;
            while cursor < entries.len()
                && entries[cursor].0.len() > depth
                && usize::from(entries[cursor].0[depth]) == nibble
            {
                cursor += 1;
            }
            if start == cursor {
                items.push(rlp_bytes(&[]));
            } else {
                let child = Self::encode_node(nodes, limits, encoded_bytes, &entries[start..cursor], depth + 1)?;
                items.push(Self::child_ref(nodes, child));
            }
        }
        let branch_value = entries.first().filter(|entry| entry.0.len() == depth).map_or(&[][..], |entry| entry.1.as_slice());
        items.push(rlp_bytes(branch_value));
        Self::checked_node(limits, encoded_bytes, rlp_list(&items))
    }
}
