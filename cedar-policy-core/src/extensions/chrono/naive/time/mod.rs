// This is a part of Chrono.
// See README.md and LICENSE.txt for details.
//
// This file is `src/naive/time/mod.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples marked `ignore`; code behind chrono's Cargo features (not enabled in Cedar) removed;
//   code not used by Cedar removed.

//! ISO 8601 time without timezone.

use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::time::Duration;
use core::{fmt, str};

use crate::extensions::chrono::format::{
    Fixed, Item, Numeric, Pad, ParseError, ParseResult, Parsed, parse,
    parse_and_remainder, write_hundreds,
};
use crate::extensions::chrono::{FixedOffset, TimeDelta, Timelike};
use crate::extensions::chrono::{expect, try_opt};

#[cfg(test)]
mod tests;

/// ISO 8601 time without timezone.
/// Allows for the nanosecond precision and optional leap second representation.
///
/// # Leap Second Handling
///
/// Since 1960s, the manmade atomic clock has been so accurate that
/// it is much more accurate than Earth's own motion.
/// It became desirable to define the civil time in terms of the atomic clock,
/// but that risks the desynchronization of the civil time from Earth.
/// To account for this, the designers of the Coordinated Universal Time (UTC)
/// made that the UTC should be kept within 0.9 seconds of the observed Earth-bound time.
/// When the mean solar day is longer than the ideal (86,400 seconds),
/// the error slowly accumulates and it is necessary to add a **leap second**
/// to slow the UTC down a bit.
/// (We may also remove a second to speed the UTC up a bit, but it never happened.)
/// The leap second, if any, follows 23:59:59 of June 30 or December 31 in the UTC.
///
/// Fast forward to the 21st century,
/// we have seen 26 leap seconds from January 1972 to December 2015.
/// Yes, 26 seconds. Probably you can read this paragraph within 26 seconds.
/// But those 26 seconds, and possibly more in the future, are never predictable,
/// and whether to add a leap second or not is known only before 6 months.
/// Internet-based clocks (via NTP) do account for known leap seconds,
/// but the system API normally doesn't (and often can't, with no network connection)
/// and there is no reliable way to retrieve leap second information.
///
/// Chrono does not try to accurately implement leap seconds; it is impossible.
/// Rather, **it allows for leap seconds but behaves as if there are *no other* leap seconds.**
/// Various operations will ignore any possible leap second(s)
/// except when any of the operands were actually leap seconds.
///
/// If you cannot tolerate this behavior,
/// you must use a separate `TimeZone` for the International Atomic Time (TAI).
/// TAI is like UTC but has no leap seconds, and thus slightly differs from UTC.
/// Chrono does not yet provide such implementation, but it is planned.
///
/// ## Representing Leap Seconds
///
/// The leap second is indicated via fractional seconds more than 1 second.
/// This makes possible to treat a leap second as the prior non-leap second
/// if you don't care about sub-second accuracy.
/// You should use the proper formatting to get the raw leap second.
///
/// All methods accepting fractional seconds will accept such values.
///
/// ```ignore
/// use chrono::{NaiveDate, NaiveTime};
///
/// let t = NaiveTime::from_hms_milli_opt(8, 59, 59, 1_000).unwrap();
///
/// let dt1 = NaiveDate::from_ymd_opt(2015, 7, 1)
///     .unwrap()
///     .and_hms_micro_opt(8, 59, 59, 1_000_000)
///     .unwrap();
///
/// let dt2 = NaiveDate::from_ymd_opt(2015, 6, 30)
///     .unwrap()
///     .and_hms_nano_opt(23, 59, 59, 1_000_000_000)
///     .unwrap()
///     .and_utc();
/// # let _ = (t, dt1, dt2);
/// ```
///
/// Note that the leap second can happen anytime given an appropriate time zone;
/// 2015-07-01 01:23:60 would be a proper leap second if UTC+01:24 had existed.
/// Practically speaking, though, by the time of the first leap second on 1972-06-30,
/// every time zone offset around the world has standardized to the 5-minute alignment.
///
/// ## Date And Time Arithmetic
///
/// As a concrete example, let's assume that `03:00:60` and `04:00:60` are leap seconds.
/// In reality, of course, leap seconds are separated by at least 6 months.
/// We will also use some intuitive concise notations for the explanation.
///
/// `Time + TimeDelta`
/// (short for [`NaiveTime::overflowing_add_signed`](#method.overflowing_add_signed)):
///
/// - `03:00:00 + 1s = 03:00:01`.
/// - `03:00:59 + 60s = 03:01:59`.
/// - `03:00:59 + 61s = 03:02:00`.
/// - `03:00:59 + 1s = 03:01:00`.
/// - `03:00:60 + 1s = 03:01:00`.
///   Note that the sum is identical to the previous.
/// - `03:00:60 + 60s = 03:01:59`.
/// - `03:00:60 + 61s = 03:02:00`.
/// - `03:00:60.1 + 0.8s = 03:00:60.9`.
///
/// `Time - TimeDelta`
/// (short for [`NaiveTime::overflowing_sub_signed`](#method.overflowing_sub_signed)):
///
/// - `03:00:00 - 1s = 02:59:59`.
/// - `03:01:00 - 1s = 03:00:59`.
/// - `03:01:00 - 60s = 03:00:00`.
/// - `03:00:60 - 60s = 03:00:00`.
///   Note that the result is identical to the previous.
/// - `03:00:60.7 - 0.4s = 03:00:60.3`.
/// - `03:00:60.7 - 0.9s = 03:00:59.8`.
///
/// `Time - Time`
/// (short for [`NaiveTime::signed_duration_since`](#method.signed_duration_since)):
///
/// - `04:00:00 - 03:00:00 = 3600s`.
/// - `03:01:00 - 03:00:00 = 60s`.
/// - `03:00:60 - 03:00:00 = 60s`.
///   Note that the difference is identical to the previous.
/// - `03:00:60.6 - 03:00:59.4 = 1.2s`.
/// - `03:01:00 - 03:00:59.8 = 0.2s`.
/// - `03:01:00 - 03:00:60.5 = 0.5s`.
///   Note that the difference is larger than the previous,
///   even though the leap second clearly follows the previous whole second.
/// - `04:00:60.9 - 03:00:60.1 =
///   (04:00:60.9 - 04:00:00) + (04:00:00 - 03:01:00) + (03:01:00 - 03:00:60.1) =
///   60.9s + 3540s + 0.9s = 3601.8s`.
///
/// In general,
///
/// - `Time + TimeDelta` unconditionally equals to `TimeDelta + Time`.
///
/// - `Time - TimeDelta` unconditionally equals to `Time + (-TimeDelta)`.
///
/// - `Time1 - Time2` unconditionally equals to `-(Time2 - Time1)`.
///
/// - Associativity does not generally hold, because
///   `(Time + TimeDelta1) - TimeDelta2` no longer equals to `Time + (TimeDelta1 - TimeDelta2)`
///   for two positive durations.
///
///     - As a special case, `(Time + TimeDelta) - TimeDelta` also does not equal to `Time`.
///
///     - If you can assume that all durations have the same sign, however,
///       then the associativity holds:
///       `(Time + TimeDelta1) + TimeDelta2` equals to `Time + (TimeDelta1 + TimeDelta2)`
///       for two positive durations.
///
/// ## Reading And Writing Leap Seconds
///
/// The "typical" leap seconds on the minute boundary are
/// correctly handled both in the formatting and parsing.
/// The leap second in the human-readable representation
/// will be represented as the second part being 60, as required by ISO 8601.
///
/// ```ignore
/// use chrono::NaiveDate;
///
/// let dt = NaiveDate::from_ymd_opt(2015, 6, 30)
///     .unwrap()
///     .and_hms_milli_opt(23, 59, 59, 1_000)
///     .unwrap()
///     .and_utc();
/// assert_eq!(format!("{:?}", dt), "2015-06-30T23:59:60Z");
/// ```
///
/// There are hypothetical leap seconds not on the minute boundary nevertheless supported by Chrono.
/// They are allowed for the sake of completeness and consistency; there were several "exotic" time
/// zone offsets with fractional minutes prior to UTC after all.
/// For such cases the human-readable representation is ambiguous and would be read back to the next
/// non-leap second.
///
/// A `NaiveTime` with a leap second that is not on a minute boundary can only be created from a
/// [`DateTime`](crate::extensions::chrono::DateTime) with fractional minutes as offset, or using
/// [`Timelike::with_nanosecond()`].
///
/// ```ignore
/// use chrono::{FixedOffset, NaiveDate, TimeZone};
///
/// let paramaribo_pre1945 = FixedOffset::east_opt(-13236).unwrap(); // -03:40:36
/// let leap_sec_2015 =
///     NaiveDate::from_ymd_opt(2015, 6, 30).unwrap().and_hms_milli_opt(23, 59, 59, 1_000).unwrap();
/// let dt1 = paramaribo_pre1945.from_utc_datetime(&leap_sec_2015);
/// assert_eq!(format!("{:?}", dt1), "2015-06-30T20:19:24-03:40:36");
/// assert_eq!(format!("{:?}", dt1.time()), "20:19:24");
///
/// let next_sec = NaiveDate::from_ymd_opt(2015, 7, 1).unwrap().and_hms_opt(0, 0, 0).unwrap();
/// let dt2 = paramaribo_pre1945.from_utc_datetime(&next_sec);
/// assert_eq!(format!("{:?}", dt2), "2015-06-30T20:19:24-03:40:36");
/// assert_eq!(format!("{:?}", dt2.time()), "20:19:24");
///
/// assert!(dt1.time() != dt2.time());
/// assert!(dt1.time().to_string() == dt2.time().to_string());
/// ```
///
/// Since Chrono alone cannot determine any existence of leap seconds,
/// **there is absolutely no guarantee that the leap second read has actually happened**.
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone)]
pub struct NaiveTime {
    secs: u32,
    frac: u32,
}

impl NaiveTime {
    /// Makes a new `NaiveTime` from hour, minute and second.
    ///
    /// The millisecond part is allowed to exceed 1,000,000,000 in order to represent a
    /// [leap second](#leap-second-handling), but only when `sec == 59`.
    ///
    /// # Errors
    ///
    /// Returns `None` on invalid hour, minute and/or second.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::NaiveTime;
    ///
    /// let from_hms_opt = NaiveTime::from_hms_opt;
    ///
    /// assert!(from_hms_opt(0, 0, 0).is_some());
    /// assert!(from_hms_opt(23, 59, 59).is_some());
    /// assert!(from_hms_opt(24, 0, 0).is_none());
    /// assert!(from_hms_opt(23, 60, 0).is_none());
    /// assert!(from_hms_opt(23, 59, 60).is_none());
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_hms_opt(hour: u32, min: u32, sec: u32) -> Option<NaiveTime> {
        NaiveTime::from_hms_nano_opt(hour, min, sec, 0)
    }

    /// Makes a new `NaiveTime` from hour, minute, second and millisecond.
    ///
    /// The millisecond part is allowed to exceed 1,000,000,000 in order to represent a
    /// [leap second](#leap-second-handling), but only when `sec == 59`.
    ///
    /// # Errors
    ///
    /// Returns `None` on invalid hour, minute, second and/or millisecond.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::NaiveTime;
    ///
    /// let from_hmsm_opt = NaiveTime::from_hms_milli_opt;
    ///
    /// assert!(from_hmsm_opt(0, 0, 0, 0).is_some());
    /// assert!(from_hmsm_opt(23, 59, 59, 999).is_some());
    /// assert!(from_hmsm_opt(23, 59, 59, 1_999).is_some()); // a leap second after 23:59:59
    /// assert!(from_hmsm_opt(24, 0, 0, 0).is_none());
    /// assert!(from_hmsm_opt(23, 60, 0, 0).is_none());
    /// assert!(from_hmsm_opt(23, 59, 60, 0).is_none());
    /// assert!(from_hmsm_opt(23, 59, 59, 2_000).is_none());
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_hms_milli_opt(
        hour: u32,
        min: u32,
        sec: u32,
        milli: u32,
    ) -> Option<NaiveTime> {
        let nano = try_opt!(milli.checked_mul(1_000_000));
        NaiveTime::from_hms_nano_opt(hour, min, sec, nano)
    }

    /// Makes a new `NaiveTime` from hour, minute, second and nanosecond.
    ///
    /// The nanosecond part is allowed to exceed 1,000,000,000 in order to represent a
    /// [leap second](#leap-second-handling), but only when `sec == 59`.
    ///
    /// # Errors
    ///
    /// Returns `None` on invalid hour, minute, second and/or nanosecond.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::NaiveTime;
    ///
    /// let from_hmsn_opt = NaiveTime::from_hms_nano_opt;
    ///
    /// assert!(from_hmsn_opt(0, 0, 0, 0).is_some());
    /// assert!(from_hmsn_opt(23, 59, 59, 999_999_999).is_some());
    /// assert!(from_hmsn_opt(23, 59, 59, 1_999_999_999).is_some()); // a leap second after 23:59:59
    /// assert!(from_hmsn_opt(24, 0, 0, 0).is_none());
    /// assert!(from_hmsn_opt(23, 60, 0, 0).is_none());
    /// assert!(from_hmsn_opt(23, 59, 60, 0).is_none());
    /// assert!(from_hmsn_opt(23, 59, 59, 2_000_000_000).is_none());
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_hms_nano_opt(hour: u32, min: u32, sec: u32, nano: u32) -> Option<NaiveTime> {
        if (hour >= 24 || min >= 60 || sec >= 60)
            || (nano >= 1_000_000_000 && sec != 59)
            || nano >= 2_000_000_000
        {
            return None;
        }
        let secs = hour * 3600 + min * 60 + sec;
        Some(NaiveTime { secs, frac: nano })
    }

    /// Makes a new `NaiveTime` from the number of seconds since midnight and nanosecond.
    ///
    /// The nanosecond part is allowed to exceed 1,000,000,000 in order to represent a
    /// [leap second](#leap-second-handling), but only when `secs % 60 == 59`.
    ///
    /// # Errors
    ///
    /// Returns `None` on invalid number of seconds and/or nanosecond.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::NaiveTime;
    ///
    /// let from_nsecs_opt = NaiveTime::from_num_seconds_from_midnight_opt;
    ///
    /// assert!(from_nsecs_opt(0, 0).is_some());
    /// assert!(from_nsecs_opt(86399, 999_999_999).is_some());
    /// assert!(from_nsecs_opt(86399, 1_999_999_999).is_some()); // a leap second after 23:59:59
    /// assert!(from_nsecs_opt(86_400, 0).is_none());
    /// assert!(from_nsecs_opt(86399, 2_000_000_000).is_none());
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_num_seconds_from_midnight_opt(secs: u32, nano: u32) -> Option<NaiveTime> {
        if secs >= 86_400 || nano >= 2_000_000_000 || (nano >= 1_000_000_000 && secs % 60 != 59) {
            return None;
        }
        Some(NaiveTime { secs, frac: nano })
    }

    /// Adds given `TimeDelta` to the current time, and also returns the number of *seconds*
    /// in the integral number of days ignored from the addition.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveTime, TimeDelta};
    ///
    /// let from_hms = |h, m, s| NaiveTime::from_hms_opt(h, m, s).unwrap();
    ///
    /// assert_eq!(
    ///     from_hms(3, 4, 5).overflowing_add_signed(TimeDelta::try_hours(11).unwrap()),
    ///     (from_hms(14, 4, 5), 0)
    /// );
    /// assert_eq!(
    ///     from_hms(3, 4, 5).overflowing_add_signed(TimeDelta::try_hours(23).unwrap()),
    ///     (from_hms(2, 4, 5), 86_400)
    /// );
    /// assert_eq!(
    ///     from_hms(3, 4, 5).overflowing_add_signed(TimeDelta::try_hours(-7).unwrap()),
    ///     (from_hms(20, 4, 5), -86_400)
    /// );
    /// ```
    #[must_use]
    pub const fn overflowing_add_signed(&self, rhs: TimeDelta) -> (NaiveTime, i64) {
        let mut secs = self.secs as i64;
        let mut frac = self.frac as i32;
        let secs_to_add = rhs.num_seconds();
        let frac_to_add = rhs.subsec_nanos();

        // Check if `self` is a leap second and adding `rhs` would escape that leap second.
        // If that is the case, update `frac` and `secs` to involve no leap second.
        // If it stays within the leap second or the second before, and only adds a fractional
        // second, just do that and return (this way the rest of the code can ignore leap seconds).
        if frac >= 1_000_000_000 {
            // check below is adjusted to not overflow an i32: `frac + frac_to_add >= 2_000_000_000`
            if secs_to_add > 0 || (frac_to_add > 0 && frac >= 2_000_000_000 - frac_to_add) {
                frac -= 1_000_000_000;
            } else if secs_to_add < 0 {
                frac -= 1_000_000_000;
                secs += 1;
            } else {
                return (NaiveTime { secs: self.secs, frac: (frac + frac_to_add) as u32 }, 0);
            }
        }

        let mut secs = secs + secs_to_add;
        frac += frac_to_add;

        if frac < 0 {
            frac += 1_000_000_000;
            secs -= 1;
        } else if frac >= 1_000_000_000 {
            frac -= 1_000_000_000;
            secs += 1;
        }

        let secs_in_day = secs.rem_euclid(86_400);
        let remaining = secs - secs_in_day;
        (NaiveTime { secs: secs_in_day as u32, frac: frac as u32 }, remaining)
    }

    /// Subtracts given `TimeDelta` from the current time, and also returns the number of *seconds*
    /// in the integral number of days ignored from the subtraction.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveTime, TimeDelta};
    ///
    /// let from_hms = |h, m, s| NaiveTime::from_hms_opt(h, m, s).unwrap();
    ///
    /// assert_eq!(
    ///     from_hms(3, 4, 5).overflowing_sub_signed(TimeDelta::try_hours(2).unwrap()),
    ///     (from_hms(1, 4, 5), 0)
    /// );
    /// assert_eq!(
    ///     from_hms(3, 4, 5).overflowing_sub_signed(TimeDelta::try_hours(17).unwrap()),
    ///     (from_hms(10, 4, 5), 86_400)
    /// );
    /// assert_eq!(
    ///     from_hms(3, 4, 5).overflowing_sub_signed(TimeDelta::try_hours(-22).unwrap()),
    ///     (from_hms(1, 4, 5), -86_400)
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn overflowing_sub_signed(&self, rhs: TimeDelta) -> (NaiveTime, i64) {
        let (time, rhs) = self.overflowing_add_signed(rhs.neg());
        (time, -rhs) // safe to negate, rhs is within +/- (2^63 / 1000)
    }

    /// Subtracts another `NaiveTime` from the current time.
    /// Returns a `TimeDelta` within +/- 1 day.
    /// This does not overflow or underflow at all.
    ///
    /// As a part of Chrono's [leap second handling](#leap-second-handling),
    /// the subtraction assumes that **there is no leap second ever**,
    /// except when any of the `NaiveTime`s themselves represents a leap second
    /// in which case the assumption becomes that
    /// **there are exactly one (or two) leap second(s) ever**.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveTime, TimeDelta};
    ///
    /// let from_hmsm = |h, m, s, milli| NaiveTime::from_hms_milli_opt(h, m, s, milli).unwrap();
    /// let since = NaiveTime::signed_duration_since;
    ///
    /// assert_eq!(since(from_hmsm(3, 5, 7, 900), from_hmsm(3, 5, 7, 900)), TimeDelta::zero());
    /// assert_eq!(
    ///     since(from_hmsm(3, 5, 7, 900), from_hmsm(3, 5, 7, 875)),
    ///     TimeDelta::try_milliseconds(25).unwrap()
    /// );
    /// assert_eq!(
    ///     since(from_hmsm(3, 5, 7, 900), from_hmsm(3, 5, 6, 925)),
    ///     TimeDelta::try_milliseconds(975).unwrap()
    /// );
    /// assert_eq!(
    ///     since(from_hmsm(3, 5, 7, 900), from_hmsm(3, 5, 0, 900)),
    ///     TimeDelta::try_seconds(7).unwrap()
    /// );
    /// assert_eq!(
    ///     since(from_hmsm(3, 5, 7, 900), from_hmsm(3, 0, 7, 900)),
    ///     TimeDelta::try_seconds(5 * 60).unwrap()
    /// );
    /// assert_eq!(
    ///     since(from_hmsm(3, 5, 7, 900), from_hmsm(0, 5, 7, 900)),
    ///     TimeDelta::try_seconds(3 * 3600).unwrap()
    /// );
    /// assert_eq!(
    ///     since(from_hmsm(3, 5, 7, 900), from_hmsm(4, 5, 7, 900)),
    ///     TimeDelta::try_seconds(-3600).unwrap()
    /// );
    /// assert_eq!(
    ///     since(from_hmsm(3, 5, 7, 900), from_hmsm(2, 4, 6, 800)),
    ///     TimeDelta::try_seconds(3600 + 60 + 1).unwrap() + TimeDelta::try_milliseconds(100).unwrap()
    /// );
    /// ```
    ///
    /// Leap seconds are handled, but the subtraction assumes that
    /// there were no other leap seconds happened.
    ///
    /// ```ignore
    /// # use chrono::{TimeDelta, NaiveTime};
    /// # let from_hmsm = |h, m, s, milli| { NaiveTime::from_hms_milli_opt(h, m, s, milli).unwrap() };
    /// # let since = NaiveTime::signed_duration_since;
    /// assert_eq!(since(from_hmsm(3, 0, 59, 1_000), from_hmsm(3, 0, 59, 0)),
    ///            TimeDelta::try_seconds(1).unwrap());
    /// assert_eq!(since(from_hmsm(3, 0, 59, 1_500), from_hmsm(3, 0, 59, 0)),
    ///            TimeDelta::try_milliseconds(1500).unwrap());
    /// assert_eq!(since(from_hmsm(3, 0, 59, 1_000), from_hmsm(3, 0, 0, 0)),
    ///            TimeDelta::try_seconds(60).unwrap());
    /// assert_eq!(since(from_hmsm(3, 0, 0, 0), from_hmsm(2, 59, 59, 1_000)),
    ///            TimeDelta::try_seconds(1).unwrap());
    /// assert_eq!(since(from_hmsm(3, 0, 59, 1_000), from_hmsm(2, 59, 59, 1_000)),
    ///            TimeDelta::try_seconds(61).unwrap());
    /// ```
    #[must_use]
    pub const fn signed_duration_since(self, rhs: NaiveTime) -> TimeDelta {
        //     |    |    :leap|    |    |    |    |    |    |    :leap|    |
        //     |    |    :    |    |    |    |    |    |    |    :    |    |
        // ----+----+-----*---+----+----+----+----+----+----+-------*-+----+----
        //          |   `rhs` |                             |    `self`
        //          |======================================>|       |
        //          |     |  `self.secs - rhs.secs`         |`self.frac`
        //          |====>|   |                             |======>|
        //      `rhs.frac`|========================================>|
        //          |     |   |        `self - rhs`         |       |

        let mut secs = self.secs as i64 - rhs.secs as i64;
        let frac = self.frac as i64 - rhs.frac as i64;

        // `secs` may contain a leap second yet to be counted
        if self.secs > rhs.secs && rhs.frac >= 1_000_000_000 {
            secs += 1;
        } else if self.secs < rhs.secs && self.frac >= 1_000_000_000 {
            secs -= 1;
        }

        let secs_from_frac = frac.div_euclid(1_000_000_000);
        let frac = frac.rem_euclid(1_000_000_000) as u32;

        expect(TimeDelta::new(secs + secs_from_frac, frac), "must be in range")
    }

    /// Adds given `FixedOffset` to the current time, and returns the number of days that should be
    /// added to a date as a result of the offset (either `-1`, `0`, or `1` because the offset is
    /// always less than 24h).
    ///
    /// This method is similar to [`overflowing_add_signed`](#method.overflowing_add_signed), but
    /// preserves leap seconds.
    pub(super) const fn overflowing_add_offset(&self, offset: FixedOffset) -> (NaiveTime, i32) {
        let secs = self.secs as i32 + offset.local_minus_utc();
        let days = secs.div_euclid(86_400);
        let secs = secs.rem_euclid(86_400);
        (NaiveTime { secs: secs as u32, frac: self.frac }, days)
    }

    /// Subtracts given `FixedOffset` from the current time, and returns the number of days that
    /// should be added to a date as a result of the offset (either `-1`, `0`, or `1` because the
    /// offset is always less than 24h).
    ///
    /// This method is similar to [`overflowing_sub_signed`](#method.overflowing_sub_signed), but
    /// preserves leap seconds.
    pub(super) const fn overflowing_sub_offset(&self, offset: FixedOffset) -> (NaiveTime, i32) {
        let secs = self.secs as i32 - offset.local_minus_utc();
        let days = secs.div_euclid(86_400);
        let secs = secs.rem_euclid(86_400);
        (NaiveTime { secs: secs as u32, frac: self.frac }, days)
    }

    /// Returns a triple of the hour, minute and second numbers.
    pub(crate) fn hms(&self) -> (u32, u32, u32) {
        let sec = self.secs % 60;
        let mins = self.secs / 60;
        let min = mins % 60;
        let hour = mins / 60;
        (hour, min, sec)
    }

    /// Returns the number of non-leap seconds past the last midnight.
    // This duplicates `Timelike::num_seconds_from_midnight()`, because trait methods can't be const
    // yet.
    #[inline]
    pub(crate) const fn num_seconds_from_midnight(&self) -> u32 {
        self.secs
    }

    /// Returns the number of nanoseconds since the whole non-leap second.
    // This duplicates `Timelike::nanosecond()`, because trait methods can't be const yet.
    #[inline]
    pub(crate) const fn nanosecond(&self) -> u32 {
        self.frac
    }

    /// The earliest possible `NaiveTime`
    pub const MIN: Self = Self { secs: 0, frac: 0 };
}

impl Timelike for NaiveTime {
    /// Returns the hour number from 0 to 23.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveTime, Timelike};
    ///
    /// assert_eq!(NaiveTime::from_hms_opt(0, 0, 0).unwrap().hour(), 0);
    /// assert_eq!(NaiveTime::from_hms_nano_opt(23, 56, 4, 12_345_678).unwrap().hour(), 23);
    /// ```
    #[inline]
    fn hour(&self) -> u32 {
        self.hms().0
    }

    /// Returns the minute number from 0 to 59.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveTime, Timelike};
    ///
    /// assert_eq!(NaiveTime::from_hms_opt(0, 0, 0).unwrap().minute(), 0);
    /// assert_eq!(NaiveTime::from_hms_nano_opt(23, 56, 4, 12_345_678).unwrap().minute(), 56);
    /// ```
    #[inline]
    fn minute(&self) -> u32 {
        self.hms().1
    }

    /// Returns the second number from 0 to 59.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveTime, Timelike};
    ///
    /// assert_eq!(NaiveTime::from_hms_opt(0, 0, 0).unwrap().second(), 0);
    /// assert_eq!(NaiveTime::from_hms_nano_opt(23, 56, 4, 12_345_678).unwrap().second(), 4);
    /// ```
    ///
    /// This method never returns 60 even when it is a leap second.
    /// ([Why?](#leap-second-handling))
    /// Use the proper [formatting method](#method.format) to get a human-readable representation.
    ///
    /// ```ignore
    /// # #[cfg(feature = "alloc")] {
    /// # use chrono::{NaiveTime, Timelike};
    /// let leap = NaiveTime::from_hms_milli_opt(23, 59, 59, 1_000).unwrap();
    /// assert_eq!(leap.second(), 59);
    /// assert_eq!(leap.format("%H:%M:%S").to_string(), "23:59:60");
    /// # }
    /// ```
    #[inline]
    fn second(&self) -> u32 {
        self.hms().2
    }

    /// Returns the number of nanoseconds since the whole non-leap second.
    /// The range from 1,000,000,000 to 1,999,999,999 represents
    /// the [leap second](#leap-second-handling).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveTime, Timelike};
    ///
    /// assert_eq!(NaiveTime::from_hms_opt(0, 0, 0).unwrap().nanosecond(), 0);
    /// assert_eq!(
    ///     NaiveTime::from_hms_nano_opt(23, 56, 4, 12_345_678).unwrap().nanosecond(),
    ///     12_345_678
    /// );
    /// ```
    ///
    /// Leap seconds may have seemingly out-of-range return values.
    /// You can reduce the range with `time.nanosecond() % 1_000_000_000`, or
    /// use the proper [formatting method](#method.format) to get a human-readable representation.
    ///
    /// ```ignore
    /// # #[cfg(feature = "alloc")] {
    /// # use chrono::{NaiveTime, Timelike};
    /// let leap = NaiveTime::from_hms_milli_opt(23, 59, 59, 1_000).unwrap();
    /// assert_eq!(leap.nanosecond(), 1_000_000_000);
    /// assert_eq!(leap.format("%H:%M:%S%.9f").to_string(), "23:59:60.000000000");
    /// # }
    /// ```
    #[inline]
    fn nanosecond(&self) -> u32 {
        self.frac
    }
}

/// Add `TimeDelta` to `NaiveTime`.
///
/// This wraps around and never overflows or underflows.
/// In particular the addition ignores integral number of days.
///
/// As a part of Chrono's [leap second handling], the addition assumes that **there is no leap
/// second ever**, except when the `NaiveTime` itself represents a leap second in which case the
/// assumption becomes that **there is exactly a single leap second ever**.
///
/// # Example
///
/// ```ignore
/// use chrono::{NaiveTime, TimeDelta};
///
/// let from_hmsm = |h, m, s, milli| NaiveTime::from_hms_milli_opt(h, m, s, milli).unwrap();
///
/// assert_eq!(from_hmsm(3, 5, 7, 0) + TimeDelta::zero(), from_hmsm(3, 5, 7, 0));
/// assert_eq!(from_hmsm(3, 5, 7, 0) + TimeDelta::try_seconds(1).unwrap(), from_hmsm(3, 5, 8, 0));
/// assert_eq!(from_hmsm(3, 5, 7, 0) + TimeDelta::try_seconds(-1).unwrap(), from_hmsm(3, 5, 6, 0));
/// assert_eq!(
///     from_hmsm(3, 5, 7, 0) + TimeDelta::try_seconds(60 + 4).unwrap(),
///     from_hmsm(3, 6, 11, 0)
/// );
/// assert_eq!(
///     from_hmsm(3, 5, 7, 0) + TimeDelta::try_seconds(7 * 60 * 60 - 6 * 60).unwrap(),
///     from_hmsm(9, 59, 7, 0)
/// );
/// assert_eq!(
///     from_hmsm(3, 5, 7, 0) + TimeDelta::try_milliseconds(80).unwrap(),
///     from_hmsm(3, 5, 7, 80)
/// );
/// assert_eq!(
///     from_hmsm(3, 5, 7, 950) + TimeDelta::try_milliseconds(280).unwrap(),
///     from_hmsm(3, 5, 8, 230)
/// );
/// assert_eq!(
///     from_hmsm(3, 5, 7, 950) + TimeDelta::try_milliseconds(-980).unwrap(),
///     from_hmsm(3, 5, 6, 970)
/// );
/// ```
///
/// The addition wraps around.
///
/// ```ignore
/// # use chrono::{TimeDelta, NaiveTime};
/// # let from_hmsm = |h, m, s, milli| { NaiveTime::from_hms_milli_opt(h, m, s, milli).unwrap() };
/// assert_eq!(from_hmsm(3, 5, 7, 0) + TimeDelta::try_seconds(22*60*60).unwrap(), from_hmsm(1, 5, 7, 0));
/// assert_eq!(from_hmsm(3, 5, 7, 0) + TimeDelta::try_seconds(-8*60*60).unwrap(), from_hmsm(19, 5, 7, 0));
/// assert_eq!(from_hmsm(3, 5, 7, 0) + TimeDelta::try_days(800).unwrap(), from_hmsm(3, 5, 7, 0));
/// ```
///
/// Leap seconds are handled, but the addition assumes that it is the only leap second happened.
///
/// ```ignore
/// # use chrono::{TimeDelta, NaiveTime};
/// # let from_hmsm = |h, m, s, milli| { NaiveTime::from_hms_milli_opt(h, m, s, milli).unwrap() };
/// let leap = from_hmsm(3, 5, 59, 1_300);
/// assert_eq!(leap + TimeDelta::zero(), from_hmsm(3, 5, 59, 1_300));
/// assert_eq!(leap + TimeDelta::try_milliseconds(-500).unwrap(), from_hmsm(3, 5, 59, 800));
/// assert_eq!(leap + TimeDelta::try_milliseconds(500).unwrap(), from_hmsm(3, 5, 59, 1_800));
/// assert_eq!(leap + TimeDelta::try_milliseconds(800).unwrap(), from_hmsm(3, 6, 0, 100));
/// assert_eq!(leap + TimeDelta::try_seconds(10).unwrap(), from_hmsm(3, 6, 9, 300));
/// assert_eq!(leap + TimeDelta::try_seconds(-10).unwrap(), from_hmsm(3, 5, 50, 300));
/// assert_eq!(leap + TimeDelta::try_days(1).unwrap(), from_hmsm(3, 5, 59, 300));
/// ```
///
/// [leap second handling]: crate::extensions::chrono::NaiveTime#leap-second-handling
impl Add<TimeDelta> for NaiveTime {
    type Output = NaiveTime;

    #[inline]
    fn add(self, rhs: TimeDelta) -> NaiveTime {
        self.overflowing_add_signed(rhs).0
    }
}

/// Add `std::time::Duration` to `NaiveTime`.
///
/// This wraps around and never overflows or underflows.
/// In particular the addition ignores integral number of days.
impl Add<Duration> for NaiveTime {
    type Output = NaiveTime;

    #[inline]
    fn add(self, rhs: Duration) -> NaiveTime {
        // We don't care about values beyond `24 * 60 * 60`, so we can take a modulus and avoid
        // overflow during the conversion to `TimeDelta`.
        // But we limit to double that just in case `self` is a leap-second.
        let secs = rhs.as_secs() % (2 * 24 * 60 * 60);
        let d = TimeDelta::new(secs as i64, rhs.subsec_nanos()).unwrap();
        self.overflowing_add_signed(d).0
    }
}

/// Add-assign `std::time::Duration` to `NaiveTime`.
///
/// This wraps around and never overflows or underflows.
/// In particular the addition ignores integral number of days.
impl AddAssign<Duration> for NaiveTime {
    #[inline]
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

/// Add `FixedOffset` to `NaiveTime`.
///
/// This wraps around and never overflows or underflows.
/// In particular the addition ignores integral number of days.
impl Add<FixedOffset> for NaiveTime {
    type Output = NaiveTime;

    #[inline]
    fn add(self, rhs: FixedOffset) -> NaiveTime {
        self.overflowing_add_offset(rhs).0
    }
}

/// Subtract `TimeDelta` from `NaiveTime`.
///
/// This wraps around and never overflows or underflows.
/// In particular the subtraction ignores integral number of days.
/// This is the same as addition with a negated `TimeDelta`.
///
/// As a part of Chrono's [leap second handling], the subtraction assumes that **there is no leap
/// second ever**, except when the `NaiveTime` itself represents a leap second in which case the
/// assumption becomes that **there is exactly a single leap second ever**.
///
/// # Example
///
/// ```ignore
/// use chrono::{NaiveTime, TimeDelta};
///
/// let from_hmsm = |h, m, s, milli| NaiveTime::from_hms_milli_opt(h, m, s, milli).unwrap();
///
/// assert_eq!(from_hmsm(3, 5, 7, 0) - TimeDelta::zero(), from_hmsm(3, 5, 7, 0));
/// assert_eq!(from_hmsm(3, 5, 7, 0) - TimeDelta::try_seconds(1).unwrap(), from_hmsm(3, 5, 6, 0));
/// assert_eq!(
///     from_hmsm(3, 5, 7, 0) - TimeDelta::try_seconds(60 + 5).unwrap(),
///     from_hmsm(3, 4, 2, 0)
/// );
/// assert_eq!(
///     from_hmsm(3, 5, 7, 0) - TimeDelta::try_seconds(2 * 60 * 60 + 6 * 60).unwrap(),
///     from_hmsm(0, 59, 7, 0)
/// );
/// assert_eq!(
///     from_hmsm(3, 5, 7, 0) - TimeDelta::try_milliseconds(80).unwrap(),
///     from_hmsm(3, 5, 6, 920)
/// );
/// assert_eq!(
///     from_hmsm(3, 5, 7, 950) - TimeDelta::try_milliseconds(280).unwrap(),
///     from_hmsm(3, 5, 7, 670)
/// );
/// ```
///
/// The subtraction wraps around.
///
/// ```ignore
/// # use chrono::{TimeDelta, NaiveTime};
/// # let from_hmsm = |h, m, s, milli| { NaiveTime::from_hms_milli_opt(h, m, s, milli).unwrap() };
/// assert_eq!(from_hmsm(3, 5, 7, 0) - TimeDelta::try_seconds(8*60*60).unwrap(), from_hmsm(19, 5, 7, 0));
/// assert_eq!(from_hmsm(3, 5, 7, 0) - TimeDelta::try_days(800).unwrap(), from_hmsm(3, 5, 7, 0));
/// ```
///
/// Leap seconds are handled, but the subtraction assumes that it is the only leap second happened.
///
/// ```ignore
/// # use chrono::{TimeDelta, NaiveTime};
/// # let from_hmsm = |h, m, s, milli| { NaiveTime::from_hms_milli_opt(h, m, s, milli).unwrap() };
/// let leap = from_hmsm(3, 5, 59, 1_300);
/// assert_eq!(leap - TimeDelta::zero(), from_hmsm(3, 5, 59, 1_300));
/// assert_eq!(leap - TimeDelta::try_milliseconds(200).unwrap(), from_hmsm(3, 5, 59, 1_100));
/// assert_eq!(leap - TimeDelta::try_milliseconds(500).unwrap(), from_hmsm(3, 5, 59, 800));
/// assert_eq!(leap - TimeDelta::try_seconds(60).unwrap(), from_hmsm(3, 5, 0, 300));
/// assert_eq!(leap - TimeDelta::try_days(1).unwrap(), from_hmsm(3, 6, 0, 300));
/// ```
///
/// [leap second handling]: crate::extensions::chrono::NaiveTime#leap-second-handling
impl Sub<TimeDelta> for NaiveTime {
    type Output = NaiveTime;

    #[inline]
    fn sub(self, rhs: TimeDelta) -> NaiveTime {
        self.overflowing_sub_signed(rhs).0
    }
}

/// Subtract `std::time::Duration` from `NaiveTime`.
///
/// This wraps around and never overflows or underflows.
/// In particular the subtraction ignores integral number of days.
impl Sub<Duration> for NaiveTime {
    type Output = NaiveTime;

    #[inline]
    fn sub(self, rhs: Duration) -> NaiveTime {
        // We don't care about values beyond `24 * 60 * 60`, so we can take a modulus and avoid
        // overflow during the conversion to `TimeDelta`.
        // But we limit to double that just in case `self` is a leap-second.
        let secs = rhs.as_secs() % (2 * 24 * 60 * 60);
        let d = TimeDelta::new(secs as i64, rhs.subsec_nanos()).unwrap();
        self.overflowing_sub_signed(d).0
    }
}

/// Subtract-assign `std::time::Duration` from `NaiveTime`.
///
/// This wraps around and never overflows or underflows.
/// In particular the subtraction ignores integral number of days.
impl SubAssign<Duration> for NaiveTime {
    #[inline]
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

/// Subtract `FixedOffset` from `NaiveTime`.
///
/// This wraps around and never overflows or underflows.
/// In particular the subtraction ignores integral number of days.
impl Sub<FixedOffset> for NaiveTime {
    type Output = NaiveTime;

    #[inline]
    fn sub(self, rhs: FixedOffset) -> NaiveTime {
        self.overflowing_sub_offset(rhs).0
    }
}

/// The `Debug` output of the naive time `t` is the same as
/// [`t.format("%H:%M:%S%.f")`](crate::extensions::chrono::format::strftime).
///
/// The string printed can be readily parsed via the `parse` method on `str`.
///
/// It should be noted that, for leap seconds not on the minute boundary,
/// it may print a representation not distinguishable from non-leap seconds.
/// This doesn't matter in practice, since such leap seconds never happened.
/// (By the time of the first leap second on 1972-06-30,
/// every time zone offset around the world has standardized to the 5-minute alignment.)
///
/// # Example
///
/// ```ignore
/// use chrono::NaiveTime;
///
/// assert_eq!(format!("{:?}", NaiveTime::from_hms_opt(23, 56, 4).unwrap()), "23:56:04");
/// assert_eq!(
///     format!("{:?}", NaiveTime::from_hms_milli_opt(23, 56, 4, 12).unwrap()),
///     "23:56:04.012"
/// );
/// assert_eq!(
///     format!("{:?}", NaiveTime::from_hms_micro_opt(23, 56, 4, 1234).unwrap()),
///     "23:56:04.001234"
/// );
/// assert_eq!(
///     format!("{:?}", NaiveTime::from_hms_nano_opt(23, 56, 4, 123456).unwrap()),
///     "23:56:04.000123456"
/// );
/// ```
///
/// Leap seconds may also be used.
///
/// ```ignore
/// # use chrono::NaiveTime;
/// assert_eq!(
///     format!("{:?}", NaiveTime::from_hms_milli_opt(6, 59, 59, 1_500).unwrap()),
///     "06:59:60.500"
/// );
/// ```
impl fmt::Debug for NaiveTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (hour, min, sec) = self.hms();
        let (sec, nano) = if self.frac >= 1_000_000_000 {
            (sec + 1, self.frac - 1_000_000_000)
        } else {
            (sec, self.frac)
        };

        use core::fmt::Write;
        write_hundreds(f, hour as u8)?;
        f.write_char(':')?;
        write_hundreds(f, min as u8)?;
        f.write_char(':')?;
        write_hundreds(f, sec as u8)?;

        if nano == 0 {
            Ok(())
        } else if nano % 1_000_000 == 0 {
            write!(f, ".{:03}", nano / 1_000_000)
        } else if nano % 1_000 == 0 {
            write!(f, ".{:06}", nano / 1_000)
        } else {
            write!(f, ".{nano:09}")
        }
    }
}

/// The `Display` output of the naive time `t` is the same as
/// [`t.format("%H:%M:%S%.f")`](crate::extensions::chrono::format::strftime).
///
/// The string printed can be readily parsed via the `parse` method on `str`.
///
/// It should be noted that, for leap seconds not on the minute boundary,
/// it may print a representation not distinguishable from non-leap seconds.
/// This doesn't matter in practice, since such leap seconds never happened.
/// (By the time of the first leap second on 1972-06-30,
/// every time zone offset around the world has standardized to the 5-minute alignment.)
///
/// # Example
///
/// ```ignore
/// use chrono::NaiveTime;
///
/// assert_eq!(format!("{}", NaiveTime::from_hms_opt(23, 56, 4).unwrap()), "23:56:04");
/// assert_eq!(
///     format!("{}", NaiveTime::from_hms_milli_opt(23, 56, 4, 12).unwrap()),
///     "23:56:04.012"
/// );
/// assert_eq!(
///     format!("{}", NaiveTime::from_hms_micro_opt(23, 56, 4, 1234).unwrap()),
///     "23:56:04.001234"
/// );
/// assert_eq!(
///     format!("{}", NaiveTime::from_hms_nano_opt(23, 56, 4, 123456).unwrap()),
///     "23:56:04.000123456"
/// );
/// ```
///
/// Leap seconds may also be used.
///
/// ```ignore
/// # use chrono::NaiveTime;
/// assert_eq!(
///     format!("{}", NaiveTime::from_hms_milli_opt(6, 59, 59, 1_500).unwrap()),
///     "06:59:60.500"
/// );
/// ```
impl fmt::Display for NaiveTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Parsing a `str` into a `NaiveTime` uses the same format,
/// [`%H:%M:%S%.f`](crate::extensions::chrono::format::strftime), as in `Debug` and `Display`.
///
/// # Example
///
/// ```ignore
/// use chrono::NaiveTime;
///
/// let t = NaiveTime::from_hms_opt(23, 56, 4).unwrap();
/// assert_eq!("23:56:04".parse::<NaiveTime>(), Ok(t));
///
/// let t = NaiveTime::from_hms_nano_opt(23, 56, 4, 12_345_678).unwrap();
/// assert_eq!("23:56:4.012345678".parse::<NaiveTime>(), Ok(t));
///
/// let t = NaiveTime::from_hms_nano_opt(23, 59, 59, 1_234_567_890).unwrap(); // leap second
/// assert_eq!("23:59:60.23456789".parse::<NaiveTime>(), Ok(t));
///
/// // Seconds are optional
/// let t = NaiveTime::from_hms_opt(23, 56, 0).unwrap();
/// assert_eq!("23:56".parse::<NaiveTime>(), Ok(t));
///
/// assert!("foo".parse::<NaiveTime>().is_err());
/// ```
impl str::FromStr for NaiveTime {
    type Err = ParseError;

    fn from_str(s: &str) -> ParseResult<NaiveTime> {
        const HOUR_AND_MINUTE: &[Item<'static>] = &[
            Item::Numeric(Numeric::Hour, Pad::Zero),
            Item::Space(""),
            Item::Literal(":"),
            Item::Numeric(Numeric::Minute, Pad::Zero),
        ];
        const SECOND_AND_NANOS: &[Item<'static>] = &[
            Item::Space(""),
            Item::Literal(":"),
            Item::Numeric(Numeric::Second, Pad::Zero),
            Item::Fixed(Fixed::Nanosecond),
            Item::Space(""),
        ];
        const TRAILING_WHITESPACE: [Item<'static>; 1] = [Item::Space("")];

        let mut parsed = Parsed::new();
        let s = parse_and_remainder(&mut parsed, s, HOUR_AND_MINUTE.iter())?;
        // Seconds are optional, don't fail if parsing them doesn't succeed.
        let s = parse_and_remainder(&mut parsed, s, SECOND_AND_NANOS.iter()).unwrap_or(s);
        parse(&mut parsed, s, TRAILING_WHITESPACE.iter())?;
        parsed.to_naive_time()
    }
}

