// Copyright 2012-2014 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// This file is `src/time_delta.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; code
//   behind chrono's Cargo features (not enabled in Cedar) removed; code not used by Cedar removed.

//! Temporal quantification

use core::fmt;
use core::ops::{Add, AddAssign, Div, Mul, Neg, Sub, SubAssign};
use core::time::Duration;

use crate::extensions::chrono::try_opt;

/// The number of nanoseconds in a millisecond.
const NANOS_PER_MILLI: i32 = 1_000_000;
/// The number of nanoseconds in seconds.
pub(crate) const NANOS_PER_SEC: i32 = 1_000_000_000;
/// The number of milliseconds per second.
const MILLIS_PER_SEC: i64 = 1000;
/// The number of (non-leap) seconds in days.
const SECS_PER_DAY: i64 = 86_400;

/// Time duration with nanosecond precision.
///
/// This also allows for negative durations; see individual methods for details.
///
/// A `TimeDelta` is represented internally as a complement of seconds and
/// nanoseconds. The range is restricted to that of `i64` milliseconds, with the
/// minimum value notably being set to `-i64::MAX` rather than allowing the full
/// range of `i64::MIN`. This is to allow easy flipping of sign, so that for
/// instance `abs()` can be called without any checks.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct TimeDelta {
    secs: i64,
    nanos: i32, // Always 0 <= nanos < NANOS_PER_SEC
}

/// The minimum possible `TimeDelta`: `-i64::MAX` milliseconds.
pub(crate) const MIN: TimeDelta = TimeDelta {
    secs: -i64::MAX / MILLIS_PER_SEC - 1,
    nanos: NANOS_PER_SEC + (-i64::MAX % MILLIS_PER_SEC) as i32 * NANOS_PER_MILLI,
};

/// The maximum possible `TimeDelta`: `i64::MAX` milliseconds.
pub(crate) const MAX: TimeDelta = TimeDelta {
    secs: i64::MAX / MILLIS_PER_SEC,
    nanos: (i64::MAX % MILLIS_PER_SEC) as i32 * NANOS_PER_MILLI,
};

impl TimeDelta {
    /// Makes a new `TimeDelta` with given number of seconds and nanoseconds.
    ///
    /// # Errors
    ///
    /// Returns `None` when the duration is out of bounds, or if `nanos` ≥ 1,000,000,000.
    pub const fn new(secs: i64, nanos: u32) -> Option<TimeDelta> {
        if secs < MIN.secs
            || secs > MAX.secs
            || nanos >= 1_000_000_000
            || (secs == MAX.secs && nanos > MAX.nanos as u32)
            || (secs == MIN.secs && nanos < MIN.nanos as u32)
        {
            return None;
        }
        Some(TimeDelta { secs, nanos: nanos as i32 })
    }

    /// Makes a new `TimeDelta` with the given number of days.
    ///
    /// Equivalent to `TimeDelta::try_seconds(days * 24 * 60 * 60)` with overflow
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `None` when the `TimeDelta` would be out of bounds.
    #[inline]
    pub const fn try_days(days: i64) -> Option<TimeDelta> {
        TimeDelta::try_seconds(try_opt!(days.checked_mul(SECS_PER_DAY)))
    }

    /// Makes a new `TimeDelta` with the given number of seconds.
    ///
    /// # Errors
    ///
    /// Returns `None` when `seconds` is more than `i64::MAX / 1_000` or less than
    /// `-i64::MAX / 1_000` (in this context, this is the same as `i64::MIN / 1_000` due to
    /// rounding).
    #[inline]
    pub const fn try_seconds(seconds: i64) -> Option<TimeDelta> {
        TimeDelta::new(seconds, 0)
    }

    /// Returns the total number of whole days in the `TimeDelta`.
    #[inline]
    pub const fn num_days(&self) -> i64 {
        self.num_seconds() / SECS_PER_DAY
    }

    /// Returns the total number of whole seconds in the `TimeDelta`.
    pub const fn num_seconds(&self) -> i64 {
        // If secs is negative, nanos should be subtracted from the duration.
        if self.secs < 0 && self.nanos > 0 { self.secs + 1 } else { self.secs }
    }

    /// Returns the total number of whole milliseconds in the `TimeDelta`.
    pub const fn num_milliseconds(&self) -> i64 {
        // A proper TimeDelta will not overflow, because MIN and MAX are defined such
        // that the range is within the bounds of an i64, from -i64::MAX through to
        // +i64::MAX inclusive. Notably, i64::MIN is excluded from this range.
        let secs_part = self.num_seconds() * MILLIS_PER_SEC;
        let nanos_part = self.subsec_nanos() / NANOS_PER_MILLI;
        secs_part + nanos_part as i64
    }

    /// Returns the number of nanoseconds in the fractional part of the duration.
    ///
    /// This is the number of nanoseconds such that
    /// `subsec_nanos() + num_seconds() * 1_000_000_000` is the total number of
    /// nanoseconds in the `TimeDelta`.
    pub const fn subsec_nanos(&self) -> i32 {
        if self.secs < 0 && self.nanos > 0 { self.nanos - NANOS_PER_SEC } else { self.nanos }
    }

    /// Add two `TimeDelta`s, returning `None` if overflow occurred.
    #[must_use]
    pub const fn checked_add(&self, rhs: &TimeDelta) -> Option<TimeDelta> {
        // No overflow checks here because we stay comfortably within the range of an `i64`.
        // Range checks happen in `TimeDelta::new`.
        let mut secs = self.secs + rhs.secs;
        let mut nanos = self.nanos + rhs.nanos;
        if nanos >= NANOS_PER_SEC {
            nanos -= NANOS_PER_SEC;
            secs += 1;
        }
        TimeDelta::new(secs, nanos as u32)
    }

    /// A `TimeDelta` where the stored seconds and nanoseconds are equal to zero.
    #[inline]
    pub const fn zero() -> TimeDelta {
        TimeDelta { secs: 0, nanos: 0 }
    }

    /// Creates a `TimeDelta` object from `std::time::Duration`
    ///
    /// This function errors when original duration is larger than the maximum
    /// value supported for this type.
    pub const fn from_std(duration: Duration) -> Result<TimeDelta, OutOfRangeError> {
        // We need to check secs as u64 before coercing to i64
        if duration.as_secs() > MAX.secs as u64 {
            return Err(OutOfRangeError(()));
        }
        match TimeDelta::new(duration.as_secs() as i64, duration.subsec_nanos()) {
            Some(d) => Ok(d),
            None => Err(OutOfRangeError(())),
        }
    }

    /// This duplicates `Neg::neg` because trait methods can't be const yet.
    pub(crate) const fn neg(self) -> TimeDelta {
        let (secs_diff, nanos) = match self.nanos {
            0 => (0, 0),
            nanos => (1, NANOS_PER_SEC - nanos),
        };
        TimeDelta { secs: -self.secs - secs_diff, nanos }
    }
}

impl Neg for TimeDelta {
    type Output = TimeDelta;

    #[inline]
    #[track_caller]
    fn neg(self) -> TimeDelta {
        let (secs_diff, nanos) = match self.nanos {
            0 => (0, 0),
            nanos => (1, NANOS_PER_SEC - nanos),
        };
        TimeDelta { secs: -self.secs - secs_diff, nanos }
    }
}

impl Add for TimeDelta {
    type Output = TimeDelta;

    #[track_caller]
    fn add(self, rhs: TimeDelta) -> TimeDelta {
        self.checked_add(&rhs).expect("`TimeDelta + TimeDelta` overflowed")
    }
}

impl<'a> core::iter::Sum<&'a TimeDelta> for TimeDelta {
    fn sum<I: Iterator<Item = &'a TimeDelta>>(iter: I) -> TimeDelta {
        iter.fold(TimeDelta::zero(), |acc, x| acc + *x)
    }
}

impl core::iter::Sum<TimeDelta> for TimeDelta {
    fn sum<I: Iterator<Item = TimeDelta>>(iter: I) -> TimeDelta {
        iter.fold(TimeDelta::zero(), |acc, x| acc + x)
    }
}

/// Represents error when converting `TimeDelta` to/from a standard library
/// implementation
///
/// The `std::time::Duration` supports a range from zero to `u64::MAX`
/// *seconds*, while this module supports signed range of up to
/// `i64::MAX` of *milliseconds*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfRangeError(());

#[cfg(test)]
mod tests {
    use super::TimeDelta;

    #[test]
    fn test_duration_num_days() {
        assert_eq!(TimeDelta::zero().num_days(), 0);
        assert_eq!(TimeDelta::try_days(1).unwrap().num_days(), 1);
        assert_eq!(TimeDelta::try_days(-1).unwrap().num_days(), -1);
        assert_eq!(TimeDelta::try_seconds(86_399).unwrap().num_days(), 0);
        assert_eq!(TimeDelta::try_seconds(86_401).unwrap().num_days(), 1);
        assert_eq!(TimeDelta::try_seconds(-86_399).unwrap().num_days(), 0);
        assert_eq!(TimeDelta::try_seconds(-86_401).unwrap().num_days(), -1);
        assert_eq!(TimeDelta::try_days(i32::MAX as i64).unwrap().num_days(), i32::MAX as i64);
        assert_eq!(TimeDelta::try_days(i32::MIN as i64).unwrap().num_days(), i32::MIN as i64);
    }

    #[test]
    fn test_duration_seconds_max_allowed() {
        let duration = TimeDelta::try_seconds(i64::MAX / 1_000).unwrap();
        assert_eq!(duration.num_seconds(), i64::MAX / 1_000);
        assert_eq!(
            duration.secs as i128 * 1_000_000_000 + duration.nanos as i128,
            i64::MAX as i128 / 1_000 * 1_000_000_000
        );
    }

    #[test]
    fn test_duration_seconds_max_overflow() {
        assert!(TimeDelta::try_seconds(i64::MAX / 1_000 + 1).is_none());
    }

    #[test]
    fn test_duration_seconds_min_allowed() {
        let duration = TimeDelta::try_seconds(i64::MIN / 1_000).unwrap(); // Same as -i64::MAX / 1_000 due to rounding
        assert_eq!(duration.num_seconds(), i64::MIN / 1_000); // Same as -i64::MAX / 1_000 due to rounding
        assert_eq!(
            duration.secs as i128 * 1_000_000_000 + duration.nanos as i128,
            -i64::MAX as i128 / 1_000 * 1_000_000_000
        );
    }

    #[test]
    fn test_duration_seconds_min_underflow() {
        assert!(TimeDelta::try_seconds(-i64::MAX / 1_000 - 1).is_none());
    }

    #[test]
    fn test_duration_sum() {
        let duration_list_1 = [TimeDelta::zero(), TimeDelta::try_seconds(1).unwrap()];
        let sum_1: TimeDelta = duration_list_1.iter().sum();
        assert_eq!(sum_1, TimeDelta::try_seconds(1).unwrap());

        let duration_list_2 = [
            TimeDelta::zero(),
            TimeDelta::try_seconds(1).unwrap(),
            TimeDelta::try_seconds(6).unwrap(),
            TimeDelta::try_seconds(10).unwrap(),
        ];
        let sum_2: TimeDelta = duration_list_2.iter().sum();
        assert_eq!(sum_2, TimeDelta::try_seconds(17).unwrap());

        let duration_arr = [
            TimeDelta::zero(),
            TimeDelta::try_seconds(1).unwrap(),
            TimeDelta::try_seconds(6).unwrap(),
            TimeDelta::try_seconds(10).unwrap(),
        ];
        let sum_3: TimeDelta = duration_arr.into_iter().sum();
        assert_eq!(sum_3, TimeDelta::try_seconds(17).unwrap());
    }
}
