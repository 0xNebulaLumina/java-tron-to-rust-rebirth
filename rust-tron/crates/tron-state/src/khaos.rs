use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::rc::{Rc, Weak};

use tron_primitives::{BlockId, Hash32};

pub const DEFAULT_KHAOS_CAPACITY: i64 = 1024;
const KHAOS_BYTES_PER_CAPACITY: usize = 1024;
pub trait RetainedSize {
    fn retained_size(&self) -> usize;
}

macro_rules! impl_retained_size_primitive {
    ($($ty:ty),+ $(,)?) => {
        $(impl RetainedSize for $ty {
            fn retained_size(&self) -> usize { std::mem::size_of::<Self>() }
        })+
    };
}

impl_retained_size_primitive!(
    (), bool, char,
    u8, u16, u32, u64, u128, usize,
    i8, i16, i32, i64, i128, isize,
    f32, f64,
);

impl RetainedSize for str {
    fn retained_size(&self) -> usize { self.len() }
}

impl RetainedSize for String {
    fn retained_size(&self) -> usize { self.len() }
}

impl<T: RetainedSize + ?Sized> RetainedSize for &T {
    fn retained_size(&self) -> usize { (*self).retained_size() }
}

impl<T: RetainedSize + ?Sized> RetainedSize for Box<T> {
    fn retained_size(&self) -> usize { (**self).retained_size() }
}

impl<T: RetainedSize> RetainedSize for [T] {
    fn retained_size(&self) -> usize {
        self.iter().try_fold(0usize, |total, value| total.checked_add(value.retained_size())).unwrap_or(usize::MAX)
    }
}

impl<T: RetainedSize, const N: usize> RetainedSize for [T; N] {
    fn retained_size(&self) -> usize { self.as_slice().retained_size() }
}

impl<T: RetainedSize> RetainedSize for Vec<T> {
    fn retained_size(&self) -> usize { self.as_slice().retained_size() }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KhaosLimits {
    pub max_list_entries: usize,
    pub max_total_bytes: usize,
    pub max_orphan_entries: usize,
    pub max_orphan_bytes: usize,
}

impl KhaosLimits {
    fn from_capacity(capacity: i64) -> Self {
        let entries = usize::try_from(capacity.max(1)).unwrap_or(usize::MAX);
        let bytes = entries.saturating_mul(KHAOS_BYTES_PER_CAPACITY);
        Self { max_list_entries: entries, max_total_bytes: bytes, max_orphan_entries: entries, max_orphan_bytes: bytes }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KhaosBlockData<T> {
    pub id: BlockId,
    pub parent_id: Hash32,
    pub number: i64,
    pub value: T,
}

impl<T> KhaosBlockData<T> {
    pub fn new(id: BlockId, parent_id: Hash32, number: i64, value: T) -> Self {
        Self { id, parent_id, number, value }
    }
}

pub type KhaosBlock<T> = Rc<KhaosNode<T>>;

#[derive(Debug)]
pub struct KhaosNode<T> {
    block: KhaosBlockData<T>,
    parent: RefCell<Weak<KhaosNode<T>>>,
}

impl<T> KhaosNode<T> {
    pub fn detached(block: KhaosBlockData<T>) -> KhaosBlock<T> {
        Rc::new(Self { block, parent: RefCell::new(Weak::new()) })
    }

    fn new(block: KhaosBlockData<T>) -> KhaosBlock<T> { Self::detached(block) }

    pub fn block(&self) -> &KhaosBlockData<T> { &self.block }
    pub fn id(&self) -> BlockId { self.block.id }
    pub fn number(&self) -> i64 { self.block.number }
    pub fn parent_id(&self) -> Hash32 { self.block.parent_id }
    pub fn parent(&self) -> Option<KhaosBlock<T>> { self.parent.borrow().upgrade() }

    fn set_parent(&self, parent: &KhaosBlock<T>) {
        *self.parent.borrow_mut() = Rc::downgrade(parent);
    }
}

impl<T> PartialEq for KhaosNode<T> {
    fn eq(&self, other: &Self) -> bool { self.block.id == other.block.id }
}
impl<T> Eq for KhaosNode<T> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreMutationKind {
    Inserted,
    Replaced,
    Removed,
    Evicted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreMutation {
    pub kind: StoreMutationKind,
    pub id: BlockId,
    pub number: i64,
}

type StoreCallback = Box<dyn FnMut(StoreMutation)>;

pub struct KhaosStore<T> {
    by_hash: HashMap<BlockId, KhaosBlock<T>>,
    // Java uses a LinkedHashMap of height to ArrayList. A repeated ID therefore remains
    // in this insertion list even though the hash index points only at the replacement.
    by_number: HashMap<i64, Vec<KhaosBlock<T>>>,
    number_order: VecDeque<i64>,
    insertion_order: VecDeque<KhaosBlock<T>>,
    list_entries: usize,
    total_bytes: usize,
    max_capacity: i64,
    max_entries: usize,
    max_bytes: usize,
    callback: Option<StoreCallback>,
}

impl<T: RetainedSize> Default for KhaosStore<T> {
    fn default() -> Self { Self::new() }
}

impl<T: RetainedSize> KhaosStore<T> {
    pub fn new() -> Self {
        let limits = KhaosLimits::from_capacity(DEFAULT_KHAOS_CAPACITY);
        Self {
            by_hash: HashMap::new(),
            by_number: HashMap::new(),
            number_order: VecDeque::new(),
            insertion_order: VecDeque::new(),
            list_entries: 0,
            total_bytes: 0,
            max_capacity: DEFAULT_KHAOS_CAPACITY,
            max_entries: limits.max_list_entries,
            max_bytes: limits.max_total_bytes,
            callback: None,
        }
    }

    pub fn with_callback(callback: impl FnMut(StoreMutation) + 'static) -> Self {
        let mut store = Self::new();
        store.callback = Some(Box::new(callback));
        store
    }

    pub fn set_callback(&mut self, callback: Option<impl FnMut(StoreMutation) + 'static>) {
        self.callback = callback.map(|callback| Box::new(callback) as StoreCallback);
    }

    pub fn set_max_capacity(&mut self, max_capacity: i64) {
        self.max_capacity = max_capacity;
        let limits = KhaosLimits::from_capacity(max_capacity);
        self.max_entries = limits.max_list_entries;
        self.max_bytes = limits.max_total_bytes;
    }
    pub fn set_resource_limits(&mut self, max_entries: usize, max_bytes: usize) {
        self.max_entries = max_entries;
        self.max_bytes = max_bytes;
    }
    pub fn max_capacity(&self) -> i64 { self.max_capacity }
    pub fn list_entries(&self) -> usize { self.list_entries }
    pub fn total_bytes(&self) -> usize { self.total_bytes }
    pub fn size(&self) -> usize { self.by_hash.len() }
    pub fn is_empty(&self) -> bool { self.by_hash.is_empty() }
    pub fn is_not_empty(&self) -> Result<bool, KhaosError> { Err(KhaosError::UnsupportedOperation("is_not_empty")) }
    pub fn get_by_hash(&self, id: &BlockId) -> Option<KhaosBlock<T>> { self.by_hash.get(id).cloned() }
    pub fn get_block_by_num(&self, number: i64) -> Option<&[KhaosBlock<T>]> {
        self.by_number.get(&number).map(Vec::as_slice)
    }

    pub fn insert(&mut self, block: KhaosBlock<T>, head_number: Option<i64>) -> Result<(), KhaosError> {
        self.insert_pinning(block, head_number, None)
    }

    fn insert_pinning(
        &mut self,
        block: KhaosBlock<T>,
        head_number: Option<i64>,
        pinned: Option<&KhaosBlock<T>>,
    ) -> Result<(), KhaosError> {
        let block_bytes = Self::accounted_bytes(&block)
            .ok_or(KhaosError::ResourceLimit { resource: "khaos store", maximum: self.max_bytes })?;
        self.evict_for_resource_limit(block_bytes, pinned)?;
        if let Some(parent) = pinned {
            if !self.by_hash.get(&parent.id()).is_some_and(|retained| Rc::ptr_eq(retained, parent)) {
                return Err(KhaosError::ResourceLimit { resource: "khaos store", maximum: self.max_bytes });
            }
        }
        let id = block.id();
        let number = block.number();
        let kind = if self.by_hash.insert(id, Rc::clone(&block)).is_some() {
            StoreMutationKind::Replaced
        } else {
            StoreMutationKind::Inserted
        };
        if !self.by_number.contains_key(&number) {
            self.number_order.push_back(number);
        }
        self.by_number.entry(number).or_default().push(block);
        self.insertion_order.push_back(Rc::clone(self.by_number.get(&number).and_then(|blocks| blocks.last()).expect("inserted block")));
        self.list_entries += 1;
        self.total_bytes += block_bytes;
        self.notify(StoreMutation { kind, id, number });
        if let Some(head_number) = head_number {
            self.evict(head_number);
        }
        Ok(())
    }

    pub fn remove(&mut self, id: &BlockId) -> bool {
        let Some(block) = self.by_hash.get(id).cloned() else { return false };
        let number = block.number();
        let mut removed_bytes = 0usize;
        let mut removed_entries = 0usize;
        if let Some(blocks) = self.by_number.get_mut(&number) {
            blocks.retain(|candidate| {
                if candidate.id() == *id {
                    removed_entries += 1;
                    removed_bytes = removed_bytes.saturating_add(Self::accounted_bytes(candidate).unwrap_or(usize::MAX));
                    false
                } else {
                    true
                }
            });
            if blocks.is_empty() {
                self.by_number.remove(&number);
                self.number_order.retain(|candidate| *candidate != number);
            }
        }
        self.insertion_order.retain(|candidate| candidate.id() != *id || candidate.number() != number);
        self.list_entries = self.list_entries.saturating_sub(removed_entries);
        self.total_bytes = self.total_bytes.saturating_sub(removed_bytes);
        self.by_hash.remove(id);
        self.notify(StoreMutation { kind: StoreMutationKind::Removed, id: *id, number });
        true
    }

    fn evict(&mut self, head_number: i64) {
        let cutoff = 0_i64.max(head_number.saturating_sub(self.max_capacity));
        let expired: Vec<i64> = self.number_order.iter().copied().filter(|number| *number < cutoff).collect();
        for number in expired {
            self.evict_number_bucket(number);
        }
    }

    fn evict_number_bucket(&mut self, number: i64) {
        self.number_order.retain(|candidate| *candidate != number);
        if let Some(blocks) = self.by_number.remove(&number) {
            for block in blocks {
                let id = block.id();
                self.list_entries = self.list_entries.saturating_sub(1);
                self.total_bytes = self.total_bytes.saturating_sub(Self::accounted_bytes(&block).unwrap_or(usize::MAX));
                self.insertion_order.retain(|candidate| !Rc::ptr_eq(candidate, &block));
                // This deliberately mirrors Java: an old insertion-list entry removes
                // the current hash-index replacement with the same ID as well.
                self.by_hash.remove(&id);
                self.notify(StoreMutation { kind: StoreMutationKind::Evicted, id, number });
            }
        }
    }
    fn evict_entry(&mut self, victim: &KhaosBlock<T>) {
        let number = victim.number();
        let id = victim.id();
        let mut removed = false;
        if let Some(blocks) = self.by_number.get_mut(&number) {
            if let Some(index) = blocks.iter().position(|candidate| Rc::ptr_eq(candidate, victim)) {
                let block = blocks.remove(index);
                self.list_entries = self.list_entries.saturating_sub(1);
                self.total_bytes = self
                    .total_bytes
                    .saturating_sub(Self::accounted_bytes(&block).unwrap_or(usize::MAX));
                removed = true;
            }
            if blocks.is_empty() {
                self.by_number.remove(&number);
                self.number_order.retain(|candidate| *candidate != number);
            }
        }
        if removed {
            self.insertion_order.retain(|candidate| !Rc::ptr_eq(candidate, victim));
            if self.by_hash.get(&id).is_some_and(|indexed| Rc::ptr_eq(indexed, victim)) {
                self.by_hash.remove(&id);
            }
            self.notify(StoreMutation { kind: StoreMutationKind::Evicted, id, number });
        }
    }


    fn accounted_bytes(block: &KhaosBlock<T>) -> Option<usize> {
        std::mem::size_of::<BlockId>()
            .checked_add(std::mem::size_of::<Hash32>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<i64>()))
            .and_then(|overhead| overhead.checked_add(block.block.value.retained_size()))
    }

    fn evict_for_resource_limit(
        &mut self,
        incoming_bytes: usize,
        pinned: Option<&KhaosBlock<T>>,
    ) -> Result<(), KhaosError> {
        if self.max_entries == 0 || incoming_bytes > self.max_bytes {
            return Err(KhaosError::ResourceLimit { resource: "khaos store", maximum: self.max_bytes });
        }
        let mut remaining_entries = self.list_entries;
        let mut remaining_bytes = self.total_bytes;
        let mut victims = Vec::new();
        for candidate in &self.insertion_order {
            if remaining_entries < self.max_entries
                && remaining_bytes.checked_add(incoming_bytes).is_some_and(|total| total <= self.max_bytes)
            {
                break;
            }
            if pinned.is_some_and(|parent| Rc::ptr_eq(candidate, parent)) {
                continue;
            }
            remaining_entries = remaining_entries.saturating_sub(1);
            remaining_bytes = remaining_bytes
                .saturating_sub(Self::accounted_bytes(candidate).unwrap_or(usize::MAX));
            victims.push(Rc::clone(candidate));
        }
        if remaining_entries >= self.max_entries
            || remaining_bytes.checked_add(incoming_bytes).is_none_or(|total| total > self.max_bytes)
        {
            return Err(KhaosError::ResourceLimit { resource: "khaos store", maximum: self.max_bytes });
        }
        for victim in victims {
            self.evict_entry(&victim);
        }
        Ok(())
    }


    fn notify(&mut self, event: StoreMutation) {
        if let Some(callback) = &mut self.callback { callback(event); }
    }

    fn highest_first(&self) -> Option<KhaosBlock<T>> {
        let number = self.by_number.keys().max().copied()?;
        self.by_number.get(&number).and_then(|blocks| blocks.first()).cloned()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KhaosError {
    UnlinkedBlock { id: BlockId, parent_id: Hash32 },
    BadNumber { parent_number: i64, block_number: i64 },
    NonCommonBlock,
    HeadWouldBeNull,
    DeprecatedMissingAncestor,
    ResourceLimit { resource: &'static str, maximum: usize },
    MalformedChain { child_number: i64, parent_number: i64 },
    CycleDetected { id: BlockId },
    TraversalLimit { maximum: usize },
    UnsupportedOperation(&'static str),
}
impl fmt::Display for KhaosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnlinkedBlock { .. } => f.write_str("unlinked block"),
            Self::BadNumber { parent_number, block_number } => write!(f, "parent number: {parent_number} , block number: {block_number}"),
            Self::NonCommonBlock => f.write_str("blocks have no retained common ancestor"),
            Self::HeadWouldBeNull => f.write_str("khaosDB head should not be null."),
            Self::DeprecatedMissingAncestor => f.write_str("deprecated branch traversal reached a missing parent"),
            Self::ResourceLimit { resource, maximum } => write!(f, "{resource} resource limit exceeded (maximum {maximum})"),
            Self::MalformedChain { child_number, parent_number } => write!(f, "malformed chain: parent height {parent_number} is not below child height {child_number}"),
            Self::CycleDetected { .. } => f.write_str("cycle detected in khaos parent chain"),
            Self::TraversalLimit { maximum } => write!(f, "khaos branch traversal exceeded {maximum} steps"),
            Self::UnsupportedOperation(operation) => write!(f, "unsupported operation: {operation}"),
        }
    }
}
impl std::error::Error for KhaosError {}

pub struct KhaosDatabase<T> {
    head: Option<KhaosBlock<T>>,
    mini_store: KhaosStore<T>,
    mini_unlinked_store: KhaosStore<T>,
}

impl<T: RetainedSize> Default for KhaosDatabase<T> {
    fn default() -> Self { Self::new() }
}

impl<T: RetainedSize> KhaosDatabase<T> {
    pub fn new() -> Self {
        Self { head: None, mini_store: KhaosStore::new(), mini_unlinked_store: KhaosStore::new() }
    }

    pub fn stores_with_callbacks(
        linked: impl FnMut(StoreMutation) + 'static,
        unlinked: impl FnMut(StoreMutation) + 'static,
    ) -> Self {
        Self { head: None, mini_store: KhaosStore::with_callback(linked), mini_unlinked_store: KhaosStore::with_callback(unlinked) }
    }

    pub fn linked_store(&self) -> &KhaosStore<T> { &self.mini_store }
    pub fn linked_store_mut(&mut self) -> &mut KhaosStore<T> { &mut self.mini_store }
    pub fn unlinked_store(&self) -> &KhaosStore<T> { &self.mini_unlinked_store }
    pub fn unlinked_store_mut(&mut self) -> &mut KhaosStore<T> { &mut self.mini_unlinked_store }

    pub fn start(&mut self, block: KhaosBlockData<T>) -> Result<(), KhaosError> {
        let node = KhaosNode::new(block);
        self.mini_store.insert(Rc::clone(&node), Some(node.number()))?;
        self.head = Some(node);
        Ok(())
    }

    pub fn push(&mut self, block: KhaosBlockData<T>) -> Result<&KhaosBlockData<T>, KhaosError> {
        let node = KhaosNode::new(block);
        let mut resolved_parent = None;
        if self.head.is_some() && node.parent_id() != Hash32::ZERO {
            match self.mini_store.get_by_hash(&BlockId::from_overlaid_hash(node.parent_id())) {
                Some(parent) => {
                    if node.number() != parent.number() + 1 {
                        return Err(KhaosError::BadNumber { parent_number: parent.number(), block_number: node.number() });
                    }
                    resolved_parent = Some(parent);
                }
                None => {
                    let id = node.id();
                    let parent_id = node.parent_id();
                    self.mini_unlinked_store.insert(node, self.head.as_ref().map(|head| head.number()))?;
                    return Err(KhaosError::UnlinkedBlock { id, parent_id });
                }
            }
        }
        self.mini_store.insert_pinning(
            Rc::clone(&node),
            self.head.as_ref().map(|head| head.number()),
            resolved_parent.as_ref(),
        )?;
        if let Some(parent) = resolved_parent {
            node.set_parent(&parent);
        }
        if self.head.as_ref().is_none_or(|head| node.number() > head.number()) {
            self.head = Some(node);
        }
        Ok(&self.head.as_ref().expect("push establishes a head").block)
    }

    pub fn remove_blk(&mut self, id: &BlockId) -> Result<(), KhaosError> {
        if !self.mini_store.remove(id) {
            self.mini_unlinked_store.remove(id);
        }
        let Some(head) = self.mini_store.highest_first() else { return Err(KhaosError::HeadWouldBeNull) };
        self.head = Some(head);
        Ok(())
    }

    pub fn contain_block(&self, id: &BlockId) -> bool {
        self.mini_store.get_by_hash(id).is_some() || self.mini_unlinked_store.get_by_hash(id).is_some()
    }
    pub fn contain_block_in_mini_store(&self, id: &BlockId) -> bool { self.mini_store.get_by_hash(id).is_some() }
    pub fn get_block(&self, id: &BlockId) -> Option<&KhaosBlockData<T>> {
        self.mini_store.by_hash.get(id).or_else(|| self.mini_unlinked_store.by_hash.get(id)).map(|node| &node.block)
    }
    pub fn get_head(&self) -> Option<&KhaosBlockData<T>> { self.head.as_ref().map(|head| &head.block) }
    pub fn has_data(&self) -> bool { !self.mini_store.is_empty() }

    pub fn pop(&mut self) -> bool {
        let Some(parent) = self.head.as_ref().and_then(|head| head.parent()) else { return false };
        self.head = Some(parent);
        true
    }

    pub fn set_max_size(&mut self, max_size: i64) {
        self.mini_store.set_max_capacity(max_size);
        self.mini_unlinked_store.set_max_capacity(max_size);
        self.set_limits(KhaosLimits::from_capacity(max_size));
    }

    pub fn set_limits(&mut self, limits: KhaosLimits) {
        self.mini_store.set_resource_limits(limits.max_list_entries, limits.max_total_bytes);
        self.mini_unlinked_store.set_resource_limits(limits.max_orphan_entries, limits.max_orphan_bytes);
    }

    pub fn get_parent_block(&self, id: &BlockId) -> Option<KhaosBlock<T>> {
        let node = self.mini_store.by_hash.get(id).or_else(|| self.mini_unlinked_store.by_hash.get(id))?;
        let parent = node.parent()?;
        let retained = self.mini_store.by_hash.contains_key(&parent.id())
            || self.mini_unlinked_store.by_hash.contains_key(&parent.id());
        retained.then_some(parent)
    }

    pub fn get_branch(&self, first: &BlockId, second: &BlockId) -> Result<(Vec<KhaosBlock<T>>, Vec<KhaosBlock<T>>), KhaosError> {
        let mut first_node = self.mini_store.get_by_hash(first).ok_or(KhaosError::NonCommonBlock)?;
        let mut second_node = self.mini_store.get_by_hash(second).ok_or(KhaosError::NonCommonBlock)?;
        let mut first_branch = Vec::new();
        let mut second_branch = Vec::new();
        let mut first_seen = HashSet::from([first_node.id()]);
        let mut second_seen = HashSet::from([second_node.id()]);
        let mut steps = 0usize;
        let maximum = self.mini_store.list_entries.saturating_mul(2).saturating_add(2);
        while first_node.number() > second_node.number() {
            first_branch.push(Rc::clone(&first_node));
            first_node = self.checked_parent(&first_node, &mut first_seen, &mut steps, maximum)?;
        }
        while second_node.number() > first_node.number() {
            second_branch.push(Rc::clone(&second_node));
            second_node = self.checked_parent(&second_node, &mut second_seen, &mut steps, maximum)?;
        }
        while first_node.id() != second_node.id() {
            first_branch.push(Rc::clone(&first_node));
            second_branch.push(Rc::clone(&second_node));
            first_node = self.checked_parent(&first_node, &mut first_seen, &mut steps, maximum)?;
            second_node = self.checked_parent(&second_node, &mut second_seen, &mut steps, maximum)?;
        }
        Ok((first_branch, second_branch))
    }

    pub fn get_branch_deprecated(&self, first: &BlockId, second: &BlockId) -> Result<(Vec<KhaosBlock<T>>, Vec<KhaosBlock<T>>), KhaosError> {
        let (Some(mut first_node), Some(mut second_node)) = (self.mini_store.get_by_hash(first), self.mini_store.get_by_hash(second)) else {
            return Ok((Vec::new(), Vec::new()));
        };
        let mut first_branch = Vec::new();
        let mut second_branch = Vec::new();
        let mut first_seen = HashSet::from([first_node.id()]);
        let mut second_seen = HashSet::from([second_node.id()]);
        let mut steps = 0usize;
        let maximum = self.mini_store.list_entries;
        while first_node.id() != second_node.id() {
            if first_node.number() > second_node.number() {
                first_branch.push(Rc::clone(&first_node));
                first_node = self.checked_parent_deprecated(&first_node, &mut first_seen, &mut steps, maximum)?;
            } else if first_node.number() < second_node.number() {
                second_branch.push(Rc::clone(&second_node));
                second_node = self.checked_parent_deprecated(&second_node, &mut second_seen, &mut steps, maximum)?;
            } else {
                first_branch.push(Rc::clone(&first_node));
                second_branch.push(Rc::clone(&second_node));
                first_node = self.checked_parent_deprecated(&first_node, &mut first_seen, &mut steps, maximum)?;
                second_node = self.checked_parent_deprecated(&second_node, &mut second_seen, &mut steps, maximum)?;
            }
        }
        Ok((first_branch, second_branch))
    }

    fn checked_parent_deprecated(
        &self,
        block: &KhaosBlock<T>,
        visited: &mut HashSet<BlockId>,
        steps: &mut usize,
        maximum: usize,
    ) -> Result<KhaosBlock<T>, KhaosError> {
        *steps = steps.checked_add(1).ok_or(KhaosError::TraversalLimit { maximum })?;
        if *steps > maximum { return Err(KhaosError::TraversalLimit { maximum }); }
        let parent = block.parent().ok_or(KhaosError::DeprecatedMissingAncestor)?;
        if !visited.insert(parent.id()) { return Err(KhaosError::CycleDetected { id: parent.id() }); }
        if parent.number() >= block.number() {
            return Err(KhaosError::MalformedChain { child_number: block.number(), parent_number: parent.number() });
        }
        let resolved = self.mini_store.get_by_hash(&parent.id()).ok_or(KhaosError::DeprecatedMissingAncestor)?;
        if resolved.number() >= block.number() {
            return Err(KhaosError::MalformedChain { child_number: block.number(), parent_number: resolved.number() });
        }
        Ok(resolved)
    }

    fn checked_parent(
        &self,
        block: &KhaosBlock<T>,
        visited: &mut HashSet<BlockId>,
        steps: &mut usize,
        maximum: usize,
    ) -> Result<KhaosBlock<T>, KhaosError> {
        *steps = steps.saturating_add(1);
        if *steps > maximum { return Err(KhaosError::TraversalLimit { maximum }); }
        let parent = block.parent().ok_or(KhaosError::NonCommonBlock)?;
        if parent.number() >= block.number() {
            return Err(KhaosError::MalformedChain { child_number: block.number(), parent_number: parent.number() });
        }
        if !visited.insert(parent.id()) { return Err(KhaosError::CycleDetected { id: parent.id() }); }
        let resolved = self.mini_store.get_by_hash(&parent.id()).ok_or(KhaosError::NonCommonBlock)?;
        if resolved.number() >= block.number() {
            return Err(KhaosError::MalformedChain { child_number: block.number(), parent_number: resolved.number() });
        }
        Ok(resolved)
    }
}
