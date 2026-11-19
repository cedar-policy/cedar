// This file is `src/naive/mod.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples marked `ignore`; code behind chrono's Cargo features (not enabled in Cedar) removed;
//   code not used by Cedar removed.
//! Date and time types unconcerned with timezones.
//!
//! They are primarily building blocks for other types
//! (e.g. [`TimeZone`](../offset/trait.TimeZone.html)),
//! but can be also used for the simpler date and time handling.

use core::hash::Hash;

pub(crate) mod date;
pub(crate) mod datetime;
mod internals;
pub(crate) mod isoweek;
pub(crate) mod time;

pub use self::date::NaiveDate;
#[allow(deprecated)]
pub use self::datetime::NaiveDateTime;
pub use self::isoweek::IsoWeek;
pub use self::time::NaiveTime;

/// A duration in calendar days.
///
/// This is useful because when using `TimeDelta` it is possible that adding `TimeDelta::days(1)`
/// doesn't increment the day value as expected due to it being a fixed number of seconds. This
/// difference applies only when dealing with `DateTime<TimeZone>` data types and in other cases
/// `TimeDelta::days(n)` and `Days::new(n)` are equivalent.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Days(pub(crate) u64);

impl Days {}

#[cfg(test)]
mod test {}
