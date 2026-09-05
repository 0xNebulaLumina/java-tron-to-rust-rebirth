use core::fmt;

pub const BLOCK_INTERVAL_MS: i64 = 3_000;
pub const MAX_ACTIVE_WITNESSES: usize = 27;
pub const SINGLE_REPEAT: i64 = 1;
const RANDOM_GENERATOR_NUMBER: i64 = 2_685_821_657_736_338_717;

pub trait Clock { fn now_millis(&self) -> i64; }
#[derive(Clone, Copy, Debug)] pub struct SystemClock;
impl Clock for SystemClock { fn now_millis(&self) -> i64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |v| i64::try_from(v.as_millis()).unwrap_or(i64::MAX)) } }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct FixedClock(pub i64);
impl Clock for FixedClock { fn now_millis(&self) -> i64 { self.0 } }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotContext { pub genesis_time: i64, pub head_number: i64, pub head_time: i64, pub head_is_maintenance: bool, pub maintenance_skip_slots: i64 }
#[derive(Clone, Debug, Eq, PartialEq)] pub enum ScheduleError { Overflow, NegativeCurrentSlot, NoActiveWitnesses }
impl fmt::Display for ScheduleError { fn fmt(&self, f:&mut fmt::Formatter<'_>)->fmt::Result { write!(f,"schedule error: {self:?}") } }
impl std::error::Error for ScheduleError {}

#[derive(Clone, Copy, Debug)] pub struct DposSlot<C> { clock: C, context: SlotContext }
impl<C: Clock> DposSlot<C> {
    #[must_use] pub fn new(clock: C, context: SlotContext) -> Self { Self { clock, context } }
    #[must_use] pub fn absolute_slot(&self, time: i64) -> i64 { time.wrapping_sub(self.context.genesis_time) / BLOCK_INTERVAL_MS }
    pub fn slot(&self, time: i64) -> Result<i64, ScheduleError> { let first = self.time(1)?; Ok(if time < first { 0 } else { time.wrapping_sub(first) / BLOCK_INTERVAL_MS + 1 }) }
    pub fn time(&self, slot: i64) -> Result<i64, ScheduleError> {
        if slot == 0 { return Ok(self.clock.now_millis()); }
        if self.context.head_number == 0 { return self.context.genesis_time.checked_add(slot.checked_mul(BLOCK_INTERVAL_MS).ok_or(ScheduleError::Overflow)?).ok_or(ScheduleError::Overflow); }
        let slot = if self.context.head_is_maintenance { slot.checked_add(self.context.maintenance_skip_slots).ok_or(ScheduleError::Overflow)? } else { slot };
        let delta = self.context.head_time.wrapping_sub(self.context.genesis_time);
        let aligned = self.context.head_time.wrapping_sub(delta % BLOCK_INTERVAL_MS);
        aligned.checked_add(slot.checked_mul(BLOCK_INTERVAL_MS).ok_or(ScheduleError::Overflow)?).ok_or(ScheduleError::Overflow)
    }
    pub fn scheduled_witness<'a>(&self, slot: i64, active: &'a [Vec<u8>]) -> Result<&'a [u8], ScheduleError> {
        if active.is_empty() { return Err(ScheduleError::NoActiveWitnesses); }
        let current = self.absolute_slot(self.context.head_time).checked_add(slot).ok_or(ScheduleError::Overflow)?;
        if current < 0 { return Err(ScheduleError::NegativeCurrentSlot); }
        let repeat_span = i64::try_from(active.len()).map_err(|_|ScheduleError::Overflow)?.checked_mul(SINGLE_REPEAT).ok_or(ScheduleError::Overflow)?;
        let index = usize::try_from((current % repeat_span) / SINGLE_REPEAT).map_err(|_|ScheduleError::Overflow)?;
        Ok(&active[index])
    }
}

/// java-tron's signed-long xorshift shuffle, including its out-of-range skip quirk.
pub fn java_shuffle<T>(items: &mut [T], time: i64) {
    let head_time_hi = time.wrapping_shl(32);
    let len = items.len();
    for i in 0..len {
        let mut v = head_time_hi.wrapping_add((i as i64).wrapping_mul(RANDOM_GENERATOR_NUMBER));
        v ^= v >> 12; v ^= v << 25; v ^= v >> 27; v = v.wrapping_mul(RANDOM_GENERATOR_NUMBER);
        let remaining = i64::try_from(len - i).expect("slice length fits i64");
        let index = (i as i64).wrapping_add(v % remaining);
        if let Ok(index) = usize::try_from(index) { if index < len { items.swap(i, index); } }
    }
}

fn java_bytes_hash(bytes: &[u8]) -> i32 { let hash = bytes.iter().fold(bytes.len() as i32, |hash, byte| hash.wrapping_mul(31).wrapping_add(i32::from(*byte as i8))); if hash == 0 { 1 } else { hash } }
fn hex_desc(left: &[u8], right: &[u8]) -> core::cmp::Ordering { right.iter().flat_map(|b| [b >> 4, b & 15]).cmp(left.iter().flat_map(|b| [b >> 4, b & 15])) }

pub fn sort_witnesses(witnesses: &mut [tron_protocol::protocol::Witness], optimized: bool) {
    witnesses.sort_by(|left, right| right.vote_count.cmp(&left.vote_count).then_with(|| if optimized { hex_desc(&left.address, &right.address) } else { java_bytes_hash(&right.address).cmp(&java_bytes_hash(&left.address)) }));
}
pub fn sort_and_truncate_active(mut witnesses: Vec<tron_protocol::protocol::Witness>, optimized: bool) -> Vec<Vec<u8>> { sort_witnesses(&mut witnesses, optimized); witnesses.truncate(MAX_ACTIVE_WITNESSES); witnesses.into_iter().map(|w|w.address).collect() }
