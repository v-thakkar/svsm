// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) SUSE LLC
//
// Author: Vaishali Thakkar <vaishali.thakkar@suse.com>

//! Monotonic clock implementation using SecureTSC.
//!
//! This module provides a monotonic clock that uses the SecureTSC facility
//! to provide reliable time measurement. The clock is initialized once at
//! boot time and provides lock-free access to the current time.

use crate::error::SvsmError;
use crate::sev::SECURE_TSC_ACCESSOR;
use crate::sev::secure_tsc::TscAccess;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use core::time::Duration;

/// Pre-computed conversion constants for TSC to duration conversion.
///
/// These constants are computed once at initialization time to avoid
/// expensive division operations during time queries.
#[derive(Debug, Clone, Copy)]
struct ClockParams {
    /// TSC frequency in Hz
    freq_hz: u64,
    /// Scaled nanoseconds per tick: (10^9 << 32) / freq_hz
    /// Used for fixed-point arithmetic conversion
    nanos_per_tick_scaled: u64,
    /// TSC value at boot time (when clock was initialized)
    boot_tsc: u64,
}

impl ClockParams {
    /// Create new clock parameters from the TSC frequency.
    ///
    /// # Arguments
    /// * `freq_hz` - TSC frequency in Hz
    /// * `boot_tsc` - TSC value at initialization time
    fn new(freq_hz: u64, boot_tsc: u64) -> Self {
        // Pre-compute nanos_per_tick_scaled = (10^9 << 32) / freq_hz
        // This allows us to convert ticks to nanos without division:
        // nanos = (ticks * nanos_per_tick_scaled) >> 32
        let nanos_per_tick_scaled = ((1_000_000_000u128) << 32) / (freq_hz as u128);
        debug_assert!(
            nanos_per_tick_scaled <= u64::MAX as u128,
            "nanos_per_tick_scaled overflows u64 for freq_hz = {}",
            freq_hz
        );

        Self {
            freq_hz,
            nanos_per_tick_scaled: nanos_per_tick_scaled as u64,
            boot_tsc,
        }
    }
}

/// Global clock parameters, initialized once at boot.
static CLOCK_PARAMS: ImmutAfterInitCell<ClockParams> = ImmutAfterInitCell::uninit();

/// Global monotonic clock accessor.
///
/// This is the primary interface for obtaining time measurements.
/// Use `MONOTONIC_CLOCK.get_instant()` to get the current instant, or
/// `MONOTONIC_CLOCK.elapsed_since_boot()` for time since boot.
pub static MONOTONIC_CLOCK: MonotonicClock = MonotonicClock::new();

/// Monotonic clock accessor.
///
/// Provides methods to query the current time and compute durations.
/// The clock uses SecureTSC as the underlying time source.
#[derive(Debug)]
pub struct MonotonicClock {
    _private: (),
}

impl MonotonicClock {
    /// Create a new MonotonicClock instance.
    pub const fn new() -> Self {
        Self { _private: () }
    }

    /// Check if the monotonic clock has been initialized.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        CLOCK_PARAMS.try_get_inner().is_ok()
    }

    /// Get the current instant.
    ///
    /// # Panics
    /// Panics if the clock has not been initialized.
    #[inline]
    pub fn get_instant(&self) -> Instant {
        self.try_get_instant()
            .expect("Monotonic clock not initialized - call init_monotonic_clock() first")
    }

    /// Try to get the current instant.
    ///
    /// Returns `None` if the clock has not been initialized.
    #[inline]
    pub fn try_get_instant(&self) -> Option<Instant> {
        let params = CLOCK_PARAMS.try_get_inner().ok()?;
        let tsc = SECURE_TSC_ACCESSOR.read_tsc();

        // Calculate ticks since boot, handling potential wraparound
        let ticks_since_boot = tsc.wrapping_sub(params.boot_tsc);

        Some(Instant { ticks_since_boot })
    }

    /// Get the duration elapsed since boot.
    ///
    /// # Panics
    /// Panics if the clock has not been initialized.
    #[inline]
    pub fn elapsed_since_boot(&self) -> Duration {
        self.get_instant().as_duration()
    }

    /// Try to get the duration elapsed since boot.
    ///
    /// Returns `None` if the clock has not been initialized.
    #[inline]
    pub fn try_elapsed_since_boot(&self) -> Option<Duration> {
        self.try_get_instant().map(|i| i.as_duration())
    }

    /// Get the TSC frequency in Hz.
    ///
    /// Returns `None` if the clock has not been initialized.
    pub fn frequency(&self) -> Option<u64> {
        CLOCK_PARAMS.try_get_inner().ok().map(|p| p.freq_hz)
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

/// A point in time measurement.
///
/// An `Instant` represents a moment in time, measured as TSC ticks since boot.
/// Instants are monotonically increasing (assuming no TSC wraparound within
/// the system's lifetime).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    /// TSC ticks since boot
    ticks_since_boot: u64,
}

impl Instant {
    /// Create an instant from raw ticks since boot.
    ///
    /// This is primarily for testing purposes.
    #[cfg(test)]
    pub fn from_ticks(ticks: u64) -> Self {
        Self {
            ticks_since_boot: ticks,
        }
    }

    /// Get the raw tick count since boot.
    #[inline]
    pub fn ticks(&self) -> u64 {
        self.ticks_since_boot
    }

    /// Calculate the duration elapsed since this instant.
    ///
    /// # Panics
    /// Panics if the clock has not been initialized.
    #[inline]
    pub fn elapsed(&self) -> Duration {
        MONOTONIC_CLOCK.get_instant().duration_since(*self)
    }

    /// Try to calculate the duration elapsed since this instant.
    ///
    /// Returns `None` if the clock has not been initialized.
    #[inline]
    pub fn try_elapsed(&self) -> Option<Duration> {
        MONOTONIC_CLOCK
            .try_get_instant()
            .map(|now| now.duration_since(*self))
    }

    /// Calculate the duration between this instant and an earlier one.
    ///
    /// If `earlier` is actually later than `self`, this returns a zero duration.
    #[inline]
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        let ticks = self
            .ticks_since_boot
            .saturating_sub(earlier.ticks_since_boot);
        ticks_to_duration(ticks)
    }

    /// Calculate the duration between this instant and an earlier one,
    /// returning `None` if `earlier` is later than `self`.
    #[inline]
    pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        if self.ticks_since_boot >= earlier.ticks_since_boot {
            Some(self.duration_since(earlier))
        } else {
            None
        }
    }

    /// Convert this instant to a Duration representing time since boot.
    #[inline]
    pub fn as_duration(&self) -> Duration {
        ticks_to_duration(self.ticks_since_boot)
    }
}

/// Convert TSC ticks to a Duration.
///
/// Uses fixed-point arithmetic to avoid runtime division.
#[inline]
pub fn ticks_to_duration(ticks: u64) -> Duration {
    let params = match CLOCK_PARAMS.try_get_inner() {
        Ok(p) => p,
        Err(_) => {
            debug_assert!(false, "ticks_to_duration called before clock initialization");
            return Duration::ZERO;
        }
    };

    // Use fixed-point multiplication to convert ticks to nanoseconds
    // nanos = (ticks * nanos_per_tick_scaled) >> 32
    let nanos = ((ticks as u128) * (params.nanos_per_tick_scaled as u128)) >> 32;

    Duration::from_nanos(nanos as u64)
}

/// Convert a Duration to TSC ticks.
///
/// This is the inverse of `ticks_to_duration`.
#[inline]
pub fn duration_to_ticks(duration: Duration) -> u64 {
    let params = match CLOCK_PARAMS.try_get_inner() {
        Ok(p) => p,
        Err(_) => {
            debug_assert!(false, "duration_to_ticks called before clock initialization");
            return 0;
        }
    };

    // ticks = nanos * freq_hz / 10^9
    let nanos = duration.as_nanos();
    let ticks = nanos.saturating_mul(params.freq_hz as u128) / 1_000_000_000;

    u64::try_from(ticks).unwrap_or(u64::MAX)
}

/// Initialize the monotonic clock.
///
/// This function should be called once during boot, after SecureTSC has been
/// configured. If SecureTSC is not enabled, this function succeeds but the
/// clock remains uninitialized (graceful degradation).
///
/// # Returns
/// - `Ok(())` on success or if SecureTSC is not available
/// - `Err(SvsmError)` if initialization fails unexpectedly
pub fn init_monotonic_clock() -> Result<(), SvsmError> {
    // Check if SecureTSC is enabled
    if !SECURE_TSC_ACCESSOR.use_secure_tsc() {
        log::info!("SecureTSC not enabled, monotonic clock not initialized");
        return Ok(());
    }

    // Get the TSC frequency
    let freq_hz = SECURE_TSC_ACCESSOR.read_tsc_frequency();
    if freq_hz == 0 {
        log::warn!("SecureTSC frequency is 0, monotonic clock not initialized");
        return Ok(());
    }

    // Read the current TSC as boot time
    let boot_tsc = SECURE_TSC_ACCESSOR.read_tsc();

    // Initialize clock parameters
    let params = ClockParams::new(freq_hz, boot_tsc);
    CLOCK_PARAMS.init(params)?;

    log::info!(
        "Monotonic clock initialized: frequency = {} Hz ({} MHz)",
        freq_hz,
        freq_hz / 1_000_000
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instant_ordering() {
        let earlier = Instant::from_ticks(100);
        let later = Instant::from_ticks(200);

        assert!(earlier < later);
        assert!(later > earlier);
        assert_eq!(earlier, Instant::from_ticks(100));
    }

    #[test]
    fn test_instant_ticks() {
        let instant = Instant::from_ticks(12345);
        assert_eq!(instant.ticks(), 12345);
    }

    #[test]
    fn test_clock_params_creation() {
        let params = ClockParams::new(1_000_000_000, 0); // 1 GHz
        assert_eq!(params.freq_hz, 1_000_000_000);
        assert_eq!(params.boot_tsc, 0);
        // nanos_per_tick_scaled should be approximately (10^9 << 32) / 10^9 = 2^32
        assert!(params.nanos_per_tick_scaled > 0);
    }

    #[test]
    fn test_duration_since_zero_when_earlier_is_later() {
        let earlier = Instant::from_ticks(200);
        let later = Instant::from_ticks(100);

        // duration_since uses saturating_sub, so should return 0
        let duration = later.duration_since(earlier);
        assert_eq!(duration, Duration::ZERO);
    }

    #[test]
    fn test_checked_duration_since() {
        let earlier = Instant::from_ticks(100);
        let later = Instant::from_ticks(200);

        assert!(later.checked_duration_since(earlier).is_some());
        assert!(earlier.checked_duration_since(later).is_none());
    }

    #[test]
    fn test_monotonic_clock_not_initialized() {
        // CLOCK_PARAMS is never initialized in unit tests, so the clock
        // should report as uninitialized and try_get_instant should return None.
        let clock = MonotonicClock::new();
        assert!(!clock.is_initialized());
        assert!(clock.try_get_instant().is_none());
        assert!(clock.frequency().is_none());
    }
}
