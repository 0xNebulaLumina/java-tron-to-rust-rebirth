use core::{cell::Cell, fmt, time::Duration};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnixMillis(i64);
impl UnixMillis { pub const fn new(value: i64) -> Self { Self(value) } pub const fn get(self) -> i64 { self.0 } }

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicInstant(Duration);
impl MonotonicInstant {
    pub const fn from_duration(value: Duration) -> Self { Self(value) }
    pub const fn duration(self) -> Duration { self.0 }
    pub fn checked_add(self, duration: Duration) -> Option<Self> { self.0.checked_add(duration).map(Self) }
    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> { self.0.checked_sub(earlier.0) }
}

pub trait WallClock { fn now(&self) -> UnixMillis; }
pub trait MonotonicClock { fn now(&self) -> MonotonicInstant; }

/// Consensus code receives time as data. It cannot ask a clock implicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusTime(UnixMillis);
impl ConsensusTime { pub const fn from_unix_millis(value: UnixMillis) -> Self { Self(value) } pub const fn unix_millis(self) -> UnixMillis { self.0 } }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedWallClock { now: UnixMillis }
impl FixedWallClock { pub const fn new(now: UnixMillis) -> Self { Self { now } } }
impl WallClock for FixedWallClock { fn now(&self) -> UnixMillis { self.now } }

#[derive(Debug)]
pub struct ManualWallClock { now: Cell<UnixMillis> }
impl ManualWallClock {
    pub const fn new(now: UnixMillis) -> Self { Self { now: Cell::new(now) } }
    pub fn set(&self, now: UnixMillis) { self.now.set(now); }
    pub fn advance(&self, millis: i64) -> Result<(), ClockError> {
        let next = self.now.get().get().checked_add(millis).ok_or(ClockError::Overflow)?;
        self.now.set(UnixMillis::new(next));
        Ok(())
    }
}
impl WallClock for ManualWallClock { fn now(&self) -> UnixMillis { self.now.get() } }

#[derive(Debug)]
pub struct ManualMonotonicClock { now: Cell<MonotonicInstant> }
impl ManualMonotonicClock {
    pub const fn new(now: MonotonicInstant) -> Self { Self { now: Cell::new(now) } }
    pub fn advance(&self, duration: Duration) -> Result<(), ClockError> {
        let next = self.now.get().checked_add(duration).ok_or(ClockError::Overflow)?;
        self.now.set(next);
        Ok(())
    }
}
impl MonotonicClock for ManualMonotonicClock { fn now(&self) -> MonotonicInstant { self.now.get() } }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError { Overflow }
impl fmt::Display for ClockError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("clock value overflow") } }
impl std::error::Error for ClockError {}
