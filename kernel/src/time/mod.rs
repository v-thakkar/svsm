// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: COCONUT-SVSM Contributors

//! Monotonic timer infrastructure for COCONUT-SVSM.
//!
//! This module provides a reliable time measurement API using SecureTSC
//! as the time source.

mod monotonic;

pub use core::time::Duration;
pub use monotonic::{
    duration_to_ticks, init_monotonic_clock, ticks_to_duration, Instant, MonotonicClock,
    MONOTONIC_CLOCK,
};
