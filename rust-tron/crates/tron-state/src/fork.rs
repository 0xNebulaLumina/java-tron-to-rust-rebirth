use core::fmt;
use std::collections::BTreeMap;

use crate::dynamic_properties::{DynamicError, DynamicProperties};

const ENERGY_LIMIT_VERSION: i32 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkVersion {
    pub version: i32,
    pub hard_fork_time: i64,
    pub hard_fork_rate: i32,
}

pub trait ForkSchedule {
    fn versions(&self) -> &[ForkVersion];
    fn old_cutoff(&self) -> i32 {
        16
    }
}

pub trait ForkClock {
    fn latest_block_number(&self) -> i64;
    fn latest_block_timestamp(&self) -> i64;
}

pub trait ForkMath {
    fn activation_time(
        &self,
        hard_fork_time: i64,
        maintenance_interval: i64,
    ) -> Result<i64, ForkError>;
    fn required_witnesses(&self, count: usize, rate: i32) -> usize;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct JavaForkMath;

impl ForkMath for JavaForkMath {
    fn activation_time(&self, time: i64, interval: i64) -> Result<i64, ForkError> {
        if interval <= 0 {
            return Err(ForkError::InvalidInterval);
        }
        let overflow = |operation| ForkError::TimestampOverflow { operation };
        let numerator = time.checked_sub(1).ok_or_else(|| overflow("subtract"))?;
        let quotient = numerator.checked_div(interval).ok_or_else(|| overflow("divide"))?;
        quotient
            .checked_add(1)
            .ok_or_else(|| overflow("add"))?
            .checked_mul(interval)
            .ok_or_else(|| overflow("multiply"))
    }

    fn required_witnesses(&self, count: usize, rate: i32) -> usize {
        ((count as u128)
            .saturating_mul(rate.max(0) as u128)
            .saturating_add(99)
            / 100) as usize
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForkError {
    Dynamic(DynamicError),
    UnknownVersion(i32),
    InvalidInterval,
    TimestampOverflow { operation: &'static str },
    InvalidWitnessMembership,
    InvalidForkStatsValue { version: i32, index: usize, value: u8 },
    InvalidWitnessRoster { version: i32 },
    InvalidForkStatsSlot { version: i32, slot: usize, len: usize },
}

impl From<DynamicError> for ForkError {
    fn from(value: DynamicError) -> Self {
        Self::Dynamic(value)
    }
}

impl fmt::Display for ForkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fork controller error: {self:?}")
    }
}

impl std::error::Error for ForkError {}

pub struct ForkController<'a, S, C, M> {
    properties: DynamicProperties,
    schedule: &'a S,
    clock: &'a C,
    math: &'a M,
    energy_limit_height: i64,
}

impl<'a, S: ForkSchedule, C: ForkClock, M: ForkMath> ForkController<'a, S, C, M> {
    #[must_use]
    pub fn new(
        properties: DynamicProperties,
        schedule: &'a S,
        clock: &'a C,
        math: &'a M,
        energy_limit_height: i64,
    ) -> Self {
        Self { properties, schedule, clock, math, energy_limit_height }
    }

    pub fn init(&self, active: &[Vec<u8>]) -> Result<i32, ForkError> {
        let mut latest = self.latest_version()?;
        if latest == 0 {
            for item in self.schedule.versions() {
                if self.pass(item.version, active)? && latest < item.version {
                    latest = item.version;
                }
            }
            self.properties.save_int("VERSION_NUMBER", latest)?;
        }
        Ok(latest)
    }

    pub fn pass(&self, version: i32, _active: &[Vec<u8>]) -> Result<bool, ForkError> {
        if version == ENERGY_LIMIT_VERSION {
            return Ok(self.clock.latest_block_number() >= self.energy_limit_height);
        }
        if version <= self.schedule.old_cutoff() {
            return Ok(self.check_all(self.properties.fork_stats(version)));
        }

        let Some(item) = self.schedule.versions().iter().find(|item| item.version == version) else {
            return Ok(false);
        };
        let interval = self.properties.get_long("MAINTENANCE_TIME_INTERVAL")?;
        if self.clock.latest_block_timestamp()
            < self.math.activation_time(item.hard_fork_time, interval)?
        {
            return Ok(false);
        }
        let Some(stats) = self.properties.fork_stats(version) else {
            return Ok(false);
        };
        if stats.is_empty() {
            return Ok(false);
        }
        let upgrades = stats.iter().filter(|&&value| value == 1).count();
        Ok(upgrades >= self.math.required_witnesses(stats.len(), item.hard_fork_rate))
    }

    pub fn update(
        &self,
        active: &[Vec<u8>],
        witness: &[u8],
        candidate: i32,
    ) -> Result<(), ForkError> {
        let Some(slot) = active.iter().position(|active_witness| active_witness.as_slice() == witness)
        else {
            return Ok(());
        };
        if candidate < ENERGY_LIMIT_VERSION || self.latest_version()? >= candidate {
            return Ok(());
        }

        let mut writes = BTreeMap::new();
        for item in self.schedule.versions().iter().filter(|item| item.version > candidate) {
            if !self.pass_with_writes(item.version, &writes)? {
                if let Some(mut stats) = self.stats_with_writes(item.version, &writes) {
                    if slot >= stats.len() {
                        return Err(ForkError::InvalidForkStatsSlot {
                            version: item.version,
                            slot,
                            len: stats.len(),
                        });
                    }
                    stats[slot] = 0;
                    writes.insert(item.version, stats);
                }
            }
        }

        let mut candidate_stats = self.properties.fork_stats(candidate).unwrap_or_default();
        if candidate_stats.len() != active.len() {
            candidate_stats = vec![0; active.len()];
        }

        if self.pass_with_writes(candidate, &writes)? {
            for item in self.schedule.versions().iter().filter(|item| item.version < candidate) {
                if !self.pass_with_writes(item.version, &writes)? {
                    let mut stats = self.stats_with_writes(item.version, &writes).unwrap_or_default();
                    if stats.is_empty() {
                        stats.resize(candidate_stats.len(), 0);
                    }
                    stats.fill(1);
                    writes.insert(item.version, stats);
                }
            }
            self.commit(&writes, Some(candidate))
        } else {
            candidate_stats[slot] = 1;
            writes.insert(candidate, candidate_stats);
            self.commit(&writes, None)
        }
    }

    pub fn reset(&self, active: &[Vec<u8>]) -> Result<(), ForkError> {
        let mut writes = BTreeMap::new();
        for item in self.schedule.versions() {
            if self.properties.fork_stats(item.version).is_some()
                && !self.pass(item.version, active)?
            {
                writes.insert(item.version, vec![0; active.len()]);
            }
        }
        self.commit(&writes, None)
    }

    fn check_all(&self, stats: Option<Vec<u8>>) -> bool {
        stats.is_some_and(|stats| !stats.is_empty() && stats.iter().all(|&value| value == 1))
    }

    fn stats_with_writes(
        &self,
        version: i32,
        writes: &BTreeMap<i32, Vec<u8>>,
    ) -> Option<Vec<u8>> {
        writes.get(&version).cloned().or_else(|| self.properties.fork_stats(version))
    }

    fn pass_with_writes(
        &self,
        version: i32,
        writes: &BTreeMap<i32, Vec<u8>>,
    ) -> Result<bool, ForkError> {
        if version == ENERGY_LIMIT_VERSION {
            return Ok(self.clock.latest_block_number() >= self.energy_limit_height);
        }
        let stats = self.stats_with_writes(version, writes);
        if version <= self.schedule.old_cutoff() {
            return Ok(self.check_all(stats));
        }
        let Some(item) = self.schedule.versions().iter().find(|item| item.version == version) else {
            return Ok(false);
        };
        let interval = self.properties.get_long("MAINTENANCE_TIME_INTERVAL")?;
        if self.clock.latest_block_timestamp()
            < self.math.activation_time(item.hard_fork_time, interval)?
        {
            return Ok(false);
        }
        let Some(stats) = stats else { return Ok(false) };
        if stats.is_empty() {
            return Ok(false);
        }
        let upgrades = stats.iter().filter(|&&value| value == 1).count();
        Ok(upgrades >= self.math.required_witnesses(stats.len(), item.hard_fork_rate))
    }

    fn commit(
        &self,
        writes: &BTreeMap<i32, Vec<u8>>,
        version: Option<i32>,
    ) -> Result<(), ForkError> {
        if writes.is_empty() && version.is_none() {
            return Ok(());
        }
        let mut batch = self.properties.store().batch();
        let name = self.properties.store().name();
        for (&fork, stats) in writes {
            batch.put(name, format!("FORK_VERSION_{fork}").as_bytes(), stats);
        }
        if let Some(version) = version {
            batch.put(name, DynamicProperties::key("VERSION_NUMBER")?, &version.to_be_bytes());
        }
        batch.commit().map_err(|error| ForkError::Dynamic(DynamicError::Storage(error.to_string())))
    }

    fn latest_version(&self) -> Result<i32, ForkError> {
        match self.properties.get_optional_raw("VERSION_NUMBER")? {
            None => Ok(0),
            Some(bytes) => {
                let actual = bytes.len();
                let encoded: [u8; 4] = bytes.try_into().map_err(|_| DynamicError::InvalidLength {
                    name: "VERSION_NUMBER".into(),
                    expected: 4,
                    actual,
                })?;
                Ok(i32::from_be_bytes(encoded))
            }
        }
    }
}
