// This is a part of Chrono.
// See README.md and LICENSE.txt for details.
//
// This file is `src/datetime/mod.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples marked `ignore`; code behind chrono's Cargo features (not enabled in Cedar) removed;
//   code not used by Cedar removed.

//! ISO 8601 date and time with time zone.

use core::borrow::Borrow;
use core::cmp::Ordering;
use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::{fmt, str};

use crate::extensions::chrono::format::{parse, ParseError, ParseResult, Parsed, StrftimeItems};
use crate::extensions::chrono::naive::{NaiveDate, NaiveDateTime, NaiveTime};
use crate::extensions::chrono::offset::{FixedOffset, Offset, TimeZone, Utc};
use crate::extensions::chrono::TimeDelta;
use crate::extensions::chrono::{expect, try_opt};

#[cfg(test)]
mod tests;

/// ISO 8601 combined date and time with time zone.
///
/// There are some constructors implemented here (the `from_*` methods), but
/// the general-purpose constructors are all via the methods on the
/// [`TimeZone`](./offset/trait.TimeZone.html) implementations.
#[derive(Clone)]
pub struct DateTime<Tz: TimeZone> {
    datetime: NaiveDateTime,
    offset: Tz::Offset,
}

impl<Tz: TimeZone> DateTime<Tz> {
    /// Makes a new `DateTime` from its components: a `NaiveDateTime` in UTC and an `Offset`.
    ///
    /// This is a low-level method, intended for use cases such as deserializing a `DateTime` or
    /// passing it through FFI.
    ///
    /// For regular use you will probably want to use a method such as
    /// [`TimeZone::from_local_datetime`] or [`NaiveDateTime::and_local_timezone`] instead.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # #[cfg(feature = "clock")] {
    /// use chrono::{DateTime, Local};
    ///
    /// let dt = Local::now();
    /// // Get components
    /// let naive_utc = dt.naive_utc();
    /// let offset = dt.offset().clone();
    /// // Serialize, pass through FFI... and recreate the `DateTime`:
    /// let dt_new = DateTime::<Local>::from_naive_utc_and_offset(naive_utc, offset);
    /// assert_eq!(dt, dt_new);
    /// # }
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_naive_utc_and_offset(
        datetime: NaiveDateTime,
        offset: Tz::Offset,
    ) -> DateTime<Tz> {
        DateTime { datetime, offset }
    }

    /// Returns the number of non-leap seconds since January 1, 1970 0:00:00 UTC
    /// (aka "UNIX timestamp").
    ///
    /// The reverse operation of creating a [`DateTime`] from a timestamp can be performed
    /// using [`from_timestamp`](DateTime::from_timestamp) or [`TimeZone::timestamp_opt`].
    ///
    /// ```ignore
    /// use chrono::{DateTime, TimeZone, Utc};
    ///
    /// let dt: DateTime<Utc> = Utc.with_ymd_and_hms(2015, 5, 15, 0, 0, 0).unwrap();
    /// assert_eq!(dt.timestamp(), 1431648000);
    ///
    /// assert_eq!(DateTime::from_timestamp(dt.timestamp(), dt.timestamp_subsec_nanos()).unwrap(), dt);
    /// ```
    #[inline]
    #[must_use]
    pub const fn timestamp(&self) -> i64 {
        let gregorian_day = self.datetime.date().num_days_from_ce() as i64;
        let seconds_from_midnight = self.datetime.time().num_seconds_from_midnight() as i64;
        (gregorian_day - UNIX_EPOCH_DAY) * 86_400 + seconds_from_midnight
    }

    /// Returns the number of non-leap-milliseconds since January 1, 1970 UTC.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, Utc};
    ///
    /// let dt = NaiveDate::from_ymd_opt(1970, 1, 1)
    ///     .unwrap()
    ///     .and_hms_milli_opt(0, 0, 1, 444)
    ///     .unwrap()
    ///     .and_local_timezone(Utc)
    ///     .unwrap();
    /// assert_eq!(dt.timestamp_millis(), 1_444);
    ///
    /// let dt = NaiveDate::from_ymd_opt(2001, 9, 9)
    ///     .unwrap()
    ///     .and_hms_milli_opt(1, 46, 40, 555)
    ///     .unwrap()
    ///     .and_local_timezone(Utc)
    ///     .unwrap();
    /// assert_eq!(dt.timestamp_millis(), 1_000_000_000_555);
    /// ```
    #[inline]
    #[must_use]
    pub const fn timestamp_millis(&self) -> i64 {
        let as_ms = self.timestamp() * 1000;
        as_ms + self.timestamp_subsec_millis() as i64
    }

    /// Returns the number of milliseconds since the last second boundary.
    ///
    /// In event of a leap second this may exceed 999.
    #[inline]
    #[must_use]
    pub const fn timestamp_subsec_millis(&self) -> u32 {
        self.timestamp_subsec_nanos() / 1_000_000
    }

    /// Returns the number of nanoseconds since the last second boundary
    ///
    /// In event of a leap second this may exceed 999,999,999.
    #[inline]
    #[must_use]
    pub const fn timestamp_subsec_nanos(&self) -> u32 {
        self.datetime.time().nanosecond()
    }

    /// Retrieves an associated offset from UTC.
    #[inline]
    #[must_use]
    pub const fn offset(&self) -> &Tz::Offset {
        &self.offset
    }

    /// Retrieves an associated time zone.
    #[inline]
    #[must_use]
    pub fn timezone(&self) -> Tz {
        TimeZone::from_offset(&self.offset)
    }

    /// Changes the associated time zone.
    /// The returned `DateTime` references the same instant of time from the perspective of the
    /// provided time zone.
    #[inline]
    #[must_use]
    pub fn with_timezone<Tz2: TimeZone>(&self, tz: &Tz2) -> DateTime<Tz2> {
        tz.from_utc_datetime(&self.datetime)
    }

    /// Adds given `TimeDelta` to the current date and time.
    ///
    /// # Errors
    ///
    /// Returns `None` if the resulting date would be out of range.
    #[inline]
    #[must_use]
    pub fn checked_add_signed(self, rhs: TimeDelta) -> Option<DateTime<Tz>> {
        let datetime = self.datetime.checked_add_signed(rhs)?;
        let tz = self.timezone();
        Some(tz.from_utc_datetime(&datetime))
    }

    /// Subtracts another `DateTime` from the current date and time.
    /// This does not overflow or underflow at all.
    #[inline]
    #[must_use]
    pub fn signed_duration_since<Tz2: TimeZone>(
        self,
        rhs: impl Borrow<DateTime<Tz2>>,
    ) -> TimeDelta {
        self.datetime.signed_duration_since(rhs.borrow().datetime)
    }

    /// Returns a view to the naive UTC datetime.
    #[inline]
    #[must_use]
    pub const fn naive_utc(&self) -> NaiveDateTime {
        self.datetime
    }

    /// Returns a view to the naive local datetime.
    ///
    /// # Panics
    ///
    /// [`DateTime`] internally stores the date and time in UTC with a [`NaiveDateTime`]. This
    /// method will panic if the offset from UTC would push the local datetime outside of the
    /// representable range of a [`NaiveDateTime`].
    #[inline]
    #[must_use]
    pub fn naive_local(&self) -> NaiveDateTime {
        self.datetime
            .checked_add_offset(self.offset.fix())
            .expect("Local time out of range for `NaiveDateTime`")
    }

    /// Returns the naive local datetime.
    ///
    /// This makes use of the buffer space outside of the representable range of values of
    /// `NaiveDateTime`. The result can be used as intermediate value, but should never be exposed
    /// outside chrono.
    #[inline]
    #[must_use]
    pub(crate) fn overflowing_naive_local(&self) -> NaiveDateTime {
        self.datetime.overflowing_add_offset(self.offset.fix())
    }
}

impl DateTime<Utc> {
    /// Makes a new `DateTime<Utc>` from the number of non-leap seconds
    /// since January 1, 1970 0:00:00 UTC (aka "UNIX timestamp").
    ///
    /// This is a convenience wrapper around [`DateTime::from_timestamp`],
    /// which is useful in functions like [`Iterator::map`] to avoid a closure.
    ///
    /// This is guaranteed to round-trip with regard to [`timestamp`](DateTime::timestamp).
    ///
    /// If you need to create a `DateTime` with a [`TimeZone`] different from [`Utc`], use
    /// [`TimeZone::timestamp_opt`] or [`DateTime::with_timezone`]; if you need to create a
    /// `DateTime` with more precision, use [`DateTime::from_timestamp_micros`],
    /// [`DateTime::from_timestamp_millis`], or [`DateTime::from_timestamp_nanos`].
    ///
    /// # Errors
    ///
    /// Returns `None` on out-of-range number of seconds,
    /// otherwise returns `Some(DateTime {...})`.
    ///
    /// # Examples
    ///
    /// Using [`Option::and_then`]:
    ///
    /// ```ignore
    /// # use chrono::DateTime;
    /// let maybe_timestamp: Option<i64> = Some(1431648000);
    /// let maybe_dt = maybe_timestamp.and_then(DateTime::from_timestamp_secs);
    ///
    /// assert!(maybe_dt.is_some());
    /// assert_eq!(maybe_dt.unwrap().to_string(), "2015-05-15 00:00:00 UTC");
    /// ```
    ///
    /// Using [`Iterator::map`]:
    ///
    /// ```ignore
    /// # use chrono::{DateTime, Utc};
    /// let v = vec![i64::MIN, 1_000_000_000, 1_234_567_890, i64::MAX];
    /// let timestamps: Vec<Option<DateTime<Utc>>> = v
    ///     .into_iter()
    ///     .map(DateTime::from_timestamp_secs)
    ///     .collect();
    ///
    /// assert_eq!(vec![
    ///     None,
    ///     Some(DateTime::parse_from_rfc3339("2001-09-09 01:46:40Z").unwrap().to_utc()),
    ///     Some(DateTime::parse_from_rfc3339("2009-02-13 23:31:30Z").unwrap().to_utc()),
    ///     None,
    /// ], timestamps);
    /// ```
    ///
    #[inline]
    #[must_use]
    pub const fn from_timestamp_secs(secs: i64) -> Option<Self> {
        Self::from_timestamp(secs, 0)
    }

    /// Makes a new `DateTime<Utc>` from the number of non-leap seconds
    /// since January 1, 1970 0:00:00 UTC (aka "UNIX timestamp")
    /// and the number of nanoseconds since the last whole non-leap second.
    ///
    /// This is guaranteed to round-trip with regard to [`timestamp`](DateTime::timestamp) and
    /// [`timestamp_subsec_nanos`](DateTime::timestamp_subsec_nanos).
    ///
    /// If you need to create a `DateTime` with a [`TimeZone`] different from [`Utc`], use
    /// [`TimeZone::timestamp_opt`] or [`DateTime::with_timezone`].
    ///
    /// The nanosecond part can exceed 1,000,000,000 in order to represent a
    /// [leap second](NaiveTime#leap-second-handling), but only when `secs % 60 == 59`.
    /// (The true "UNIX timestamp" cannot represent a leap second unambiguously.)
    ///
    /// # Errors
    ///
    /// Returns `None` on out-of-range number of seconds and/or
    /// invalid nanosecond, otherwise returns `Some(DateTime {...})`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::DateTime;
    ///
    /// let dt = DateTime::from_timestamp(1431648000, 0).expect("invalid timestamp");
    ///
    /// assert_eq!(dt.to_string(), "2015-05-15 00:00:00 UTC");
    /// assert_eq!(DateTime::from_timestamp(dt.timestamp(), dt.timestamp_subsec_nanos()).unwrap(), dt);
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_timestamp(secs: i64, nsecs: u32) -> Option<Self> {
        let days = secs.div_euclid(86_400) + UNIX_EPOCH_DAY;
        let secs = secs.rem_euclid(86_400);
        if days < i32::MIN as i64 || days > i32::MAX as i64 {
            return None;
        }
        let date = try_opt!(NaiveDate::from_num_days_from_ce_opt(days as i32));
        let time = try_opt!(NaiveTime::from_num_seconds_from_midnight_opt(
            secs as u32,
            nsecs
        ));
        Some(date.and_time(time).and_utc())
    }

    /// The Unix Epoch, 1970-01-01 00:00:00 UTC.
    pub const UNIX_EPOCH: Self = expect(NaiveDate::from_ymd_opt(1970, 1, 1), "")
        .and_time(NaiveTime::MIN)
        .and_utc();
}

impl DateTime<FixedOffset> {
    /// Parses a string from a user-specified format into a `DateTime<FixedOffset>` value.
    ///
    /// Note that this method *requires a timezone* in the input string. See
    /// [`NaiveDateTime::parse_from_str`](./naive/struct.NaiveDateTime.html#method.parse_from_str)
    /// for a version that does not require a timezone in the to-be-parsed str. The returned
    /// [`DateTime`] value will have a [`FixedOffset`] reflecting the parsed timezone.
    ///
    /// See the [`format::strftime` module](crate::extensions::chrono::format::strftime) for supported format
    /// sequences.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use chrono::{DateTime, FixedOffset, NaiveDate, TimeZone};
    ///
    /// let dt = DateTime::parse_from_str("1983 Apr 13 12:09:14.274 +0000", "%Y %b %d %H:%M:%S%.3f %z");
    /// assert_eq!(
    ///     dt,
    ///     Ok(FixedOffset::east_opt(0)
    ///         .unwrap()
    ///         .from_local_datetime(
    ///             &NaiveDate::from_ymd_opt(1983, 4, 13)
    ///                 .unwrap()
    ///                 .and_hms_milli_opt(12, 9, 14, 274)
    ///                 .unwrap()
    ///         )
    ///         .unwrap())
    /// );
    /// ```
    pub fn parse_from_str(s: &str, fmt: &str) -> ParseResult<DateTime<FixedOffset>> {
        let mut parsed = Parsed::new();
        parse(&mut parsed, s, StrftimeItems::new(fmt))?;
        parsed.to_datetime()
    }
}

// We don't store a field with the `Tz` type, so it doesn't need to influence whether `DateTime` can
// be `Copy`. Implement it manually if the two types we do have are `Copy`.
impl<Tz: TimeZone> Copy for DateTime<Tz>
where
    <Tz as TimeZone>::Offset: Copy,
    NaiveDateTime: Copy,
{
}

impl<Tz: TimeZone, Tz2: TimeZone> PartialEq<DateTime<Tz2>> for DateTime<Tz> {
    fn eq(&self, other: &DateTime<Tz2>) -> bool {
        self.datetime == other.datetime
    }
}

impl<Tz: TimeZone> Eq for DateTime<Tz> {}

impl<Tz: TimeZone, Tz2: TimeZone> PartialOrd<DateTime<Tz2>> for DateTime<Tz> {
    /// Compare two DateTimes based on their true time, ignoring time zones
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::prelude::*;
    ///
    /// let earlier = Utc
    ///     .with_ymd_and_hms(2015, 5, 15, 2, 0, 0)
    ///     .unwrap()
    ///     .with_timezone(&FixedOffset::west_opt(1 * 3600).unwrap());
    /// let later = Utc
    ///     .with_ymd_and_hms(2015, 5, 15, 3, 0, 0)
    ///     .unwrap()
    ///     .with_timezone(&FixedOffset::west_opt(5 * 3600).unwrap());
    ///
    /// assert_eq!(earlier.to_string(), "2015-05-15 01:00:00 -01:00");
    /// assert_eq!(later.to_string(), "2015-05-14 22:00:00 -05:00");
    ///
    /// assert!(later > earlier);
    /// ```
    fn partial_cmp(&self, other: &DateTime<Tz2>) -> Option<Ordering> {
        self.datetime.partial_cmp(&other.datetime)
    }
}

/// Add `TimeDelta` to `DateTime`.
///
/// As a part of Chrono's [leap second handling], the addition assumes that **there is no leap
/// second ever**, except when the `NaiveDateTime` itself represents a leap second in which case
/// the assumption becomes that **there is exactly a single leap second ever**.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using [`DateTime<Tz>::checked_add_signed`] to get an `Option` instead.
impl<Tz: TimeZone> Add<TimeDelta> for DateTime<Tz> {
    type Output = DateTime<Tz>;

    #[inline]
    #[track_caller]
    fn add(self, rhs: TimeDelta) -> DateTime<Tz> {
        self.checked_add_signed(rhs)
            .expect("`DateTime + TimeDelta` overflowed")
    }
}

/// Add-assign `chrono::Duration` to `DateTime`.
///
/// As a part of Chrono's [leap second handling], the addition assumes that **there is no leap
/// second ever**, except when the `NaiveDateTime` itself represents a leap second in which case
/// the assumption becomes that **there is exactly a single leap second ever**.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using [`DateTime<Tz>::checked_add_signed`] to get an `Option` instead.
impl<Tz: TimeZone> AddAssign<TimeDelta> for DateTime<Tz> {
    #[inline]
    #[track_caller]
    fn add_assign(&mut self, rhs: TimeDelta) {
        let datetime = self
            .datetime
            .checked_add_signed(rhs)
            .expect("`DateTime + TimeDelta` overflowed");
        let tz = self.timezone();
        *self = tz.from_utc_datetime(&datetime);
    }
}

/// Subtract-assign `TimeDelta` from `DateTime`.
///
/// This is the same as the addition with a negated `TimeDelta`.
///
/// As a part of Chrono's [leap second handling], the addition assumes that **there is no leap
/// second ever**, except when the `DateTime` itself represents a leap second in which case
/// the assumption becomes that **there is exactly a single leap second ever**.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using [`DateTime<Tz>::checked_sub_signed`] to get an `Option` instead.
impl<Tz: TimeZone> SubAssign<TimeDelta> for DateTime<Tz> {
    #[inline]
    #[track_caller]
    fn sub_assign(&mut self, rhs: TimeDelta) {
        let datetime = self
            .datetime
            .checked_sub_signed(rhs)
            .expect("`DateTime - TimeDelta` overflowed");
        let tz = self.timezone();
        *self = tz.from_utc_datetime(&datetime)
    }
}

impl<Tz: TimeZone> Sub<DateTime<Tz>> for DateTime<Tz> {
    type Output = TimeDelta;

    #[inline]
    fn sub(self, rhs: DateTime<Tz>) -> TimeDelta {
        self.signed_duration_since(rhs)
    }
}

impl<Tz: TimeZone> fmt::Debug for DateTime<Tz> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.overflowing_naive_local().fmt(f)?;
        self.offset.fmt(f)
    }
}

// `fmt::Debug` is hand implemented for the `rkyv::Archive` variant of `DateTime` because
// deriving a trait recursively does not propagate trait defined associated types with their own
// constraints:
// In our case `<<Tz as offset::TimeZone>::Offset as Archive>::Archived`
// cannot be formatted using `{:?}` because it doesn't implement `Debug`.
// See below for further discussion:
// * https://github.com/rust-lang/rust/issues/26925
// * https://github.com/rkyv/rkyv/issues/333
// * https://github.com/dtolnay/syn/issues/370

/// Accepts a relaxed form of RFC3339.
/// A space or a 'T' are accepted as the separator between the date and time
/// parts.
///
/// All of these examples are equivalent:
/// ```ignore
/// # use chrono::{DateTime, Utc};
/// "2012-12-12T12:12:12Z".parse::<DateTime<Utc>>()?;
/// "2012-12-12 12:12:12Z".parse::<DateTime<Utc>>()?;
/// "2012-12-12 12:12:12+0000".parse::<DateTime<Utc>>()?;
/// "2012-12-12 12:12:12+00:00".parse::<DateTime<Utc>>()?;
/// # Ok::<(), chrono::ParseError>(())
/// ```
impl str::FromStr for DateTime<Utc> {
    type Err = ParseError;

    fn from_str(s: &str) -> ParseResult<DateTime<Utc>> {
        s.parse::<DateTime<FixedOffset>>()
            .map(|dt| dt.with_timezone(&Utc))
    }
}

/// Number of days between January 1, 1970 and December 31, 1 BCE which we define to be day 0.
/// 4 full leap year cycles until December 31, 1600     4 * 146097 = 584388
/// 1 day until January 1, 1601                                           1
/// 369 years until January 1, 1970                      369 * 365 = 134685
/// of which floor(369 / 4) are leap years          floor(369 / 4) =     92
/// except for 1700, 1800 and 1900                                       -3 +
///                                                                  --------
///                                                                  719163
pub(crate) const UNIX_EPOCH_DAY: i64 = 719_163;
