// This is a part of Chrono.
// See README.md and LICENSE.txt for details.
//
// This file is `src/naive/datetime/mod.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples removed; code behind chrono's Cargo features (not enabled in Cedar) removed; code not
//   used by Cedar removed.

//! ISO 8601 date and time without timezone.

use core::fmt::Write;
use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::time::Duration;
use core::{fmt, str};

use crate::extensions::chrono::format::{parse, ParseError, ParseResult, Parsed, StrftimeItems};
use crate::extensions::chrono::format::{Fixed, Item, Numeric, Pad};
use crate::extensions::chrono::naive::{IsoWeek, NaiveDate, NaiveTime};
use crate::extensions::chrono::offset::Utc;
use crate::extensions::chrono::{
    expect, try_opt, DateTime, Datelike, FixedOffset, TimeDelta, Timelike, Weekday,
};

#[cfg(test)]
mod tests;

/// ISO 8601 combined date and time without timezone.
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone)]
pub struct NaiveDateTime {
    date: NaiveDate,
    time: NaiveTime,
}

impl NaiveDateTime {
    /// Makes a new `NaiveDateTime` from date and time components.
    /// Equivalent to [`date.and_time(time)`](crate::extensions::chrono::NaiveDate::and_time)
    /// and many other helper constructors on `NaiveDate`.
    #[inline]
    pub const fn new(date: NaiveDate, time: NaiveTime) -> NaiveDateTime {
        NaiveDateTime { date, time }
    }

    /// Parses a string with the specified format string and returns a new `NaiveDateTime`.
    /// See the [`format::strftime` module](crate::extensions::chrono::format::strftime)
    /// on the supported escape sequences.
    pub fn parse_from_str(s: &str, fmt: &str) -> ParseResult<NaiveDateTime> {
        let mut parsed = Parsed::new();
        parse(&mut parsed, s, StrftimeItems::new(fmt))?;
        parsed.to_naive_datetime_with_offset(0) // no offset adjustment
    }

    /// Retrieves a date component.
    #[inline]
    pub const fn date(&self) -> NaiveDate {
        self.date
    }

    /// Retrieves a time component.
    #[inline]
    pub const fn time(&self) -> NaiveTime {
        self.time
    }

    /// Adds given `TimeDelta` to the current date and time.
    ///
    /// As a part of Chrono's [leap second handling](crate::extensions::chrono::NaiveTime#leap-second-handling),
    /// the addition assumes that **there is no leap second ever**,
    /// except when the `NaiveDateTime` itself represents a leap second
    /// in which case the assumption becomes that **there is exactly a single leap second ever**.
    ///
    /// # Errors
    ///
    /// Returns `None` if the resulting date would be out of range.
    #[must_use]
    pub const fn checked_add_signed(self, rhs: TimeDelta) -> Option<NaiveDateTime> {
        let (time, remainder) = self.time.overflowing_add_signed(rhs);
        let remainder = try_opt!(TimeDelta::try_seconds(remainder));
        let date = try_opt!(self.date.checked_add_signed(remainder));
        Some(NaiveDateTime { date, time })
    }

    /// Adds given `FixedOffset` to the current datetime.
    /// Returns `None` if the result would be outside the valid range for [`NaiveDateTime`].
    ///
    /// This method is similar to [`checked_add_signed`](crate::extensions::chrono::NaiveDateTime::checked_add_signed), but preserves
    /// leap seconds.
    #[must_use]
    pub const fn checked_add_offset(self, rhs: FixedOffset) -> Option<NaiveDateTime> {
        let (time, days) = self.time.overflowing_add_offset(rhs);
        let date = match days {
            -1 => try_opt!(self.date.pred_opt()),
            1 => try_opt!(self.date.succ_opt()),
            _ => self.date,
        };
        Some(NaiveDateTime { date, time })
    }

    /// Subtracts given `FixedOffset` from the current datetime.
    /// Returns `None` if the result would be outside the valid range for [`NaiveDateTime`].
    ///
    /// This method is similar to [`checked_sub_signed`](crate::extensions::chrono::NaiveDateTime::checked_sub_signed), but preserves
    /// leap seconds.
    pub const fn checked_sub_offset(self, rhs: FixedOffset) -> Option<NaiveDateTime> {
        let (time, days) = self.time.overflowing_sub_offset(rhs);
        let date = match days {
            -1 => try_opt!(self.date.pred_opt()),
            1 => try_opt!(self.date.succ_opt()),
            _ => self.date,
        };
        Some(NaiveDateTime { date, time })
    }

    /// Adds given `FixedOffset` to the current datetime.
    /// The resulting value may be outside the valid range of [`NaiveDateTime`].
    ///
    /// This can be useful for intermediate values, but the resulting out-of-range `NaiveDate`
    /// should not be exposed to library users.
    #[must_use]
    pub(crate) fn overflowing_add_offset(self, rhs: FixedOffset) -> NaiveDateTime {
        let (time, days) = self.time.overflowing_add_offset(rhs);
        let date = match days {
            -1 => self.date.pred_opt().unwrap_or(NaiveDate::BEFORE_MIN),
            1 => self.date.succ_opt().unwrap_or(NaiveDate::AFTER_MAX),
            _ => self.date,
        };
        NaiveDateTime { date, time }
    }

    /// Subtracts given `TimeDelta` from the current date and time.
    ///
    /// As a part of Chrono's [leap second handling](crate::extensions::chrono::NaiveTime#leap-second-handling),
    /// the subtraction assumes that **there is no leap second ever**,
    /// except when the `NaiveDateTime` itself represents a leap second
    /// in which case the assumption becomes that **there is exactly a single leap second ever**.
    ///
    /// # Errors
    ///
    /// Returns `None` if the resulting date would be out of range.
    #[must_use]
    pub const fn checked_sub_signed(self, rhs: TimeDelta) -> Option<NaiveDateTime> {
        let (time, remainder) = self.time.overflowing_sub_signed(rhs);
        let remainder = try_opt!(TimeDelta::try_seconds(remainder));
        let date = try_opt!(self.date.checked_sub_signed(remainder));
        Some(NaiveDateTime { date, time })
    }

    /// Subtracts another `NaiveDateTime` from the current date and time.
    /// This does not overflow or underflow at all.
    ///
    /// As a part of Chrono's [leap second handling](crate::extensions::chrono::NaiveTime#leap-second-handling),
    /// the subtraction assumes that **there is no leap second ever**,
    /// except when any of the `NaiveDateTime`s themselves represents a leap second
    /// in which case the assumption becomes that
    /// **there are exactly one (or two) leap second(s) ever**.
    #[must_use]
    pub const fn signed_duration_since(self, rhs: NaiveDateTime) -> TimeDelta {
        expect(
            self.date
                .signed_duration_since(rhs.date)
                .checked_add(&self.time.signed_duration_since(rhs.time)),
            "always in range",
        )
    }

    /// Converts the `NaiveDateTime` into the timezone-aware `DateTime<Utc>`.
    #[must_use]
    pub const fn and_utc(&self) -> DateTime<Utc> {
        DateTime::from_naive_utc_and_offset(*self, Utc)
    }
}

impl Datelike for NaiveDateTime {
    /// Returns the year number in the [calendar date](crate::extensions::chrono::NaiveDate#calendar-date).
    ///
    /// See also the [`NaiveDate::year`](crate::extensions::chrono::NaiveDate::year) method.
    #[inline]
    fn year(&self) -> i32 {
        self.date.year()
    }

    /// Returns the month number starting from 1.
    ///
    /// The return value ranges from 1 to 12.
    ///
    /// See also the [`NaiveDate::month`](crate::extensions::chrono::NaiveDate::month) method.
    #[inline]
    fn month(&self) -> u32 {
        self.date.month()
    }

    /// Returns the day of month starting from 1.
    ///
    /// The return value ranges from 1 to 31. (The last day of month differs by months.)
    ///
    /// See also the [`NaiveDate::day`](crate::extensions::chrono::NaiveDate::day) method.
    #[inline]
    fn day(&self) -> u32 {
        self.date.day()
    }

    /// Returns the day of year starting from 1.
    ///
    /// The return value ranges from 1 to 366. (The last day of year differs by years.)
    ///
    /// See also the [`NaiveDate::ordinal`](crate::extensions::chrono::NaiveDate::ordinal) method.
    #[inline]
    fn ordinal(&self) -> u32 {
        self.date.ordinal()
    }

    /// Returns the day of week.
    ///
    /// See also the [`NaiveDate::weekday`](crate::extensions::chrono::NaiveDate::weekday) method.
    #[inline]
    fn weekday(&self) -> Weekday {
        self.date.weekday()
    }

    #[inline]
    fn iso_week(&self) -> IsoWeek {
        self.date.iso_week()
    }

    /// Makes a new `NaiveDateTime` with the day of year (starting from 1) changed.
    ///
    /// See also the [`NaiveDate::with_ordinal`] method.
    ///
    /// # Errors
    ///
    /// Returns `None` if:
    /// - The resulting date does not exist (`with_ordinal(366)` in a non-leap year).
    /// - The value for `ordinal` is invalid.
    #[inline]
    fn with_ordinal(&self, ordinal: u32) -> Option<NaiveDateTime> {
        self.date
            .with_ordinal(ordinal)
            .map(|d| NaiveDateTime { date: d, ..*self })
    }
}

impl Timelike for NaiveDateTime {
    /// Returns the hour number from 0 to 23.
    ///
    /// See also the [`NaiveTime::hour`] method.
    #[inline]
    fn hour(&self) -> u32 {
        self.time.hour()
    }

    /// Returns the minute number from 0 to 59.
    ///
    /// See also the [`NaiveTime::minute`] method.
    #[inline]
    fn minute(&self) -> u32 {
        self.time.minute()
    }

    /// Returns the second number from 0 to 59.
    ///
    /// See also the [`NaiveTime::second`] method.
    #[inline]
    fn second(&self) -> u32 {
        self.time.second()
    }

    /// Returns the number of nanoseconds since the whole non-leap second.
    /// The range from 1,000,000,000 to 1,999,999,999 represents
    /// the [leap second](crate::extensions::chrono::NaiveTime#leap-second-handling).
    ///
    /// See also the [`NaiveTime#method.nanosecond`] method.
    #[inline]
    fn nanosecond(&self) -> u32 {
        self.time.nanosecond()
    }
}

/// Add `TimeDelta` to `NaiveDateTime`.
///
/// As a part of Chrono's [leap second handling], the addition assumes that **there is no leap
/// second ever**, except when the `NaiveDateTime` itself represents a leap  second in which case
/// the assumption becomes that **there is exactly a single leap second ever**.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using [`NaiveDateTime::checked_add_signed`] to get an `Option` instead.
impl Add<TimeDelta> for NaiveDateTime {
    type Output = NaiveDateTime;

    #[inline]
    #[track_caller]
    fn add(self, rhs: TimeDelta) -> NaiveDateTime {
        self.checked_add_signed(rhs)
            .expect("`NaiveDateTime + TimeDelta` overflowed")
    }
}

/// Add `std::time::Duration` to `NaiveDateTime`.
///
/// As a part of Chrono's [leap second handling], the addition assumes that **there is no leap
/// second ever**, except when the `NaiveDateTime` itself represents a leap  second in which case
/// the assumption becomes that **there is exactly a single leap second ever**.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using [`NaiveDateTime::checked_add_signed`] to get an `Option` instead.
impl Add<Duration> for NaiveDateTime {
    type Output = NaiveDateTime;

    #[inline]
    #[track_caller]
    fn add(self, rhs: Duration) -> NaiveDateTime {
        let rhs = TimeDelta::from_std(rhs)
            .expect("overflow converting from core::time::Duration to TimeDelta");
        self.checked_add_signed(rhs)
            .expect("`NaiveDateTime + TimeDelta` overflowed")
    }
}

/// Add-assign `std::time::Duration` to `NaiveDateTime`.
///
/// As a part of Chrono's [leap second handling], the addition assumes that **there is no leap
/// second ever**, except when the `NaiveDateTime` itself represents a leap  second in which case
/// the assumption becomes that **there is exactly a single leap second ever**.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using [`NaiveDateTime::checked_add_signed`] to get an `Option` instead.
impl AddAssign<Duration> for NaiveDateTime {
    #[inline]
    #[track_caller]
    fn add_assign(&mut self, rhs: Duration) {
        *self = self.add(rhs);
    }
}

/// Subtract `TimeDelta` from `NaiveDateTime`.
///
/// This is the same as the addition with a negated `TimeDelta`.
///
/// As a part of Chrono's [leap second handling] the subtraction assumes that **there is no leap
/// second ever**, except when the `NaiveDateTime` itself represents a leap second in which case
/// the assumption becomes that **there is exactly a single leap second ever**.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using [`NaiveDateTime::checked_sub_signed`] to get an `Option` instead.
impl Sub<TimeDelta> for NaiveDateTime {
    type Output = NaiveDateTime;

    #[inline]
    #[track_caller]
    fn sub(self, rhs: TimeDelta) -> NaiveDateTime {
        self.checked_sub_signed(rhs)
            .expect("`NaiveDateTime - TimeDelta` overflowed")
    }
}

/// Subtract `std::time::Duration` from `NaiveDateTime`.
///
/// As a part of Chrono's [leap second handling] the subtraction assumes that **there is no leap
/// second ever**, except when the `NaiveDateTime` itself represents a leap second in which case
/// the assumption becomes that **there is exactly a single leap second ever**.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using [`NaiveDateTime::checked_sub_signed`] to get an `Option` instead.
impl Sub<Duration> for NaiveDateTime {
    type Output = NaiveDateTime;

    #[inline]
    #[track_caller]
    fn sub(self, rhs: Duration) -> NaiveDateTime {
        let rhs = TimeDelta::from_std(rhs)
            .expect("overflow converting from core::time::Duration to TimeDelta");
        self.checked_sub_signed(rhs)
            .expect("`NaiveDateTime - TimeDelta` overflowed")
    }
}

/// Subtract-assign `TimeDelta` from `NaiveDateTime`.
///
/// This is the same as the addition with a negated `TimeDelta`.
///
/// As a part of Chrono's [leap second handling], the addition assumes that **there is no leap
/// second ever**, except when the `NaiveDateTime` itself represents a leap  second in which case
/// the assumption becomes that **there is exactly a single leap second ever**.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using [`NaiveDateTime::checked_sub_signed`] to get an `Option` instead.
impl SubAssign<TimeDelta> for NaiveDateTime {
    #[inline]
    #[track_caller]
    fn sub_assign(&mut self, rhs: TimeDelta) {
        *self = self.sub(rhs);
    }
}

/// The `Debug` output of the naive date and time `dt` uses the format
/// `%Y-%m-%dT%H:%M:%S%.f`.
///
/// The string printed can be readily parsed via the `parse` method on `str`.
///
/// It should be noted that, for leap seconds not on the minute boundary,
/// it may print a representation not distinguishable from non-leap seconds.
/// This doesn't matter in practice, since such leap seconds never happened.
/// (By the time of the first leap second on 1972-06-30,
/// every time zone offset around the world has standardized to the 5-minute alignment.)
impl fmt::Debug for NaiveDateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.date.fmt(f)?;
        f.write_char('T')?;
        self.time.fmt(f)
    }
}

/// The `Display` output of the naive date and time `dt` uses the format
/// `%Y-%m-%d %H:%M:%S%.f`.
///
/// It should be noted that, for leap seconds not on the minute boundary,
/// it may print a representation not distinguishable from non-leap seconds.
/// This doesn't matter in practice, since such leap seconds never happened.
/// (By the time of the first leap second on 1972-06-30,
/// every time zone offset around the world has standardized to the 5-minute alignment.)
impl fmt::Display for NaiveDateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.date.fmt(f)?;
        f.write_char(' ')?;
        self.time.fmt(f)
    }
}

/// Parsing a `str` into a `NaiveDateTime` uses the same format,
/// `%Y-%m-%dT%H:%M:%S%.f`, as in `Debug`.
impl str::FromStr for NaiveDateTime {
    type Err = ParseError;

    fn from_str(s: &str) -> ParseResult<NaiveDateTime> {
        const ITEMS: &[Item<'static>] = &[
            Item::Numeric(Numeric::Year, Pad::Zero),
            Item::Space(""),
            Item::Literal("-"),
            Item::Numeric(Numeric::Month, Pad::Zero),
            Item::Space(""),
            Item::Literal("-"),
            Item::Numeric(Numeric::Day, Pad::Zero),
            Item::Space(""),
            Item::Literal("T"), // XXX shouldn't this be case-insensitive?
            Item::Numeric(Numeric::Hour, Pad::Zero),
            Item::Space(""),
            Item::Literal(":"),
            Item::Numeric(Numeric::Minute, Pad::Zero),
            Item::Space(""),
            Item::Literal(":"),
            Item::Numeric(Numeric::Second, Pad::Zero),
            Item::Fixed(Fixed::Nanosecond),
            Item::Space(""),
        ];

        let mut parsed = Parsed::new();
        parse(&mut parsed, s, ITEMS.iter())?;
        parsed.to_naive_datetime_with_offset(0)
    }
}

/// The default value for a NaiveDateTime is 1st of January 1970 at 00:00:00.
///
/// Note that while this may look like the UNIX epoch, it is missing the
/// time zone. The actual UNIX epoch cannot be expressed by this type,
/// however it is available as [`DateTime::UNIX_EPOCH`].
impl Default for NaiveDateTime {
    fn default() -> Self {
        DateTime::UNIX_EPOCH.naive_local()
    }
}
