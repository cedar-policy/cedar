// This is a part of Chrono.
// See README.md and LICENSE.txt for details.
//
// This file is `src/naive/datetime/mod.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples marked `ignore`; code behind chrono's Cargo features (not enabled in Cedar) removed;
//   code not used by Cedar removed.

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
///
/// # Example
///
/// `NaiveDateTime` is commonly created from [`NaiveDate`].
///
/// ```ignore
/// use chrono::{NaiveDate, NaiveDateTime};
///
/// let dt: NaiveDateTime =
///     NaiveDate::from_ymd_opt(2016, 7, 8).unwrap().and_hms_opt(9, 10, 11).unwrap();
/// # let _ = dt;
/// ```
///
/// You can use typical [date-like](Datelike) and [time-like](Timelike) methods,
/// provided that relevant traits are in the scope.
///
/// ```ignore
/// # use chrono::{NaiveDate, NaiveDateTime};
/// # let dt: NaiveDateTime = NaiveDate::from_ymd_opt(2016, 7, 8).unwrap().and_hms_opt(9, 10, 11).unwrap();
/// use chrono::{Datelike, Timelike, Weekday};
///
/// assert_eq!(dt.weekday(), Weekday::Fri);
/// assert_eq!(dt.num_seconds_from_midnight(), 33011);
/// ```
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone)]
pub struct NaiveDateTime {
    date: NaiveDate,
    time: NaiveTime,
}

impl NaiveDateTime {
    /// Makes a new `NaiveDateTime` from date and time components.
    /// Equivalent to [`date.and_time(time)`](./struct.NaiveDate.html#method.and_time)
    /// and many other helper constructors on `NaiveDate`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
    ///
    /// let d = NaiveDate::from_ymd_opt(2015, 6, 3).unwrap();
    /// let t = NaiveTime::from_hms_milli_opt(12, 34, 56, 789).unwrap();
    ///
    /// let dt = NaiveDateTime::new(d, t);
    /// assert_eq!(dt.date(), d);
    /// assert_eq!(dt.time(), t);
    /// ```
    #[inline]
    pub const fn new(date: NaiveDate, time: NaiveTime) -> NaiveDateTime {
        NaiveDateTime { date, time }
    }

    /// Parses a string with the specified format string and returns a new `NaiveDateTime`.
    /// See the [`format::strftime` module](crate::extensions::chrono::format::strftime)
    /// on the supported escape sequences.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, NaiveDateTime};
    ///
    /// let parse_from_str = NaiveDateTime::parse_from_str;
    ///
    /// assert_eq!(
    ///     parse_from_str("2015-09-05 23:56:04", "%Y-%m-%d %H:%M:%S"),
    ///     Ok(NaiveDate::from_ymd_opt(2015, 9, 5).unwrap().and_hms_opt(23, 56, 4).unwrap())
    /// );
    /// assert_eq!(
    ///     parse_from_str("5sep2015pm012345.6789", "%d%b%Y%p%I%M%S%.f"),
    ///     Ok(NaiveDate::from_ymd_opt(2015, 9, 5)
    ///         .unwrap()
    ///         .and_hms_micro_opt(13, 23, 45, 678_900)
    ///         .unwrap())
    /// );
    /// ```
    ///
    /// Offset is ignored for the purpose of parsing.
    ///
    /// ```ignore
    /// # use chrono::{NaiveDateTime, NaiveDate};
    /// # let parse_from_str = NaiveDateTime::parse_from_str;
    /// assert_eq!(
    ///     parse_from_str("2014-5-17T12:34:56+09:30", "%Y-%m-%dT%H:%M:%S%z"),
    ///     Ok(NaiveDate::from_ymd_opt(2014, 5, 17).unwrap().and_hms_opt(12, 34, 56).unwrap())
    /// );
    /// ```
    ///
    /// [Leap seconds](./struct.NaiveTime.html#leap-second-handling) are correctly handled by
    /// treating any time of the form `hh:mm:60` as a leap second.
    /// (This equally applies to the formatting, so the round trip is possible.)
    ///
    /// ```ignore
    /// # use chrono::{NaiveDateTime, NaiveDate};
    /// # let parse_from_str = NaiveDateTime::parse_from_str;
    /// assert_eq!(
    ///     parse_from_str("2015-07-01 08:59:60.123", "%Y-%m-%d %H:%M:%S%.f"),
    ///     Ok(NaiveDate::from_ymd_opt(2015, 7, 1)
    ///         .unwrap()
    ///         .and_hms_milli_opt(8, 59, 59, 1_123)
    ///         .unwrap())
    /// );
    /// ```
    ///
    /// Missing seconds are assumed to be zero,
    /// but out-of-bound times or insufficient fields are errors otherwise.
    ///
    /// ```ignore
    /// # use chrono::{NaiveDateTime, NaiveDate};
    /// # let parse_from_str = NaiveDateTime::parse_from_str;
    /// assert_eq!(
    ///     parse_from_str("94/9/4 7:15", "%y/%m/%d %H:%M"),
    ///     Ok(NaiveDate::from_ymd_opt(1994, 9, 4).unwrap().and_hms_opt(7, 15, 0).unwrap())
    /// );
    ///
    /// assert!(parse_from_str("04m33s", "%Mm%Ss").is_err());
    /// assert!(parse_from_str("94/9/4 12", "%y/%m/%d %H").is_err());
    /// assert!(parse_from_str("94/9/4 17:60", "%y/%m/%d %H:%M").is_err());
    /// assert!(parse_from_str("94/9/4 24:00:00", "%y/%m/%d %H:%M:%S").is_err());
    /// ```
    ///
    /// All parsed fields should be consistent to each other, otherwise it's an error.
    ///
    /// ```ignore
    /// # use chrono::NaiveDateTime;
    /// # let parse_from_str = NaiveDateTime::parse_from_str;
    /// let fmt = "%Y-%m-%d %H:%M:%S = UNIX timestamp %s";
    /// assert!(parse_from_str("2001-09-09 01:46:39 = UNIX timestamp 999999999", fmt).is_ok());
    /// assert!(parse_from_str("1970-01-01 00:00:00 = UNIX timestamp 1", fmt).is_err());
    /// ```
    ///
    /// Years before 1 BCE or after 9999 CE, require an initial sign
    ///
    ///```ignore
    /// # use chrono::NaiveDateTime;
    /// # let parse_from_str = NaiveDateTime::parse_from_str;
    /// let fmt = "%Y-%m-%d %H:%M:%S";
    /// assert!(parse_from_str("10000-09-09 01:46:39", fmt).is_err());
    /// assert!(parse_from_str("+10000-09-09 01:46:39", fmt).is_ok());
    /// ```
    pub fn parse_from_str(s: &str, fmt: &str) -> ParseResult<NaiveDateTime> {
        let mut parsed = Parsed::new();
        parse(&mut parsed, s, StrftimeItems::new(fmt))?;
        parsed.to_naive_datetime_with_offset(0) // no offset adjustment
    }

    /// Retrieves a date component.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::NaiveDate;
    ///
    /// let dt = NaiveDate::from_ymd_opt(2016, 7, 8).unwrap().and_hms_opt(9, 10, 11).unwrap();
    /// assert_eq!(dt.date(), NaiveDate::from_ymd_opt(2016, 7, 8).unwrap());
    /// ```
    #[inline]
    pub const fn date(&self) -> NaiveDate {
        self.date
    }

    /// Retrieves a time component.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, NaiveTime};
    ///
    /// let dt = NaiveDate::from_ymd_opt(2016, 7, 8).unwrap().and_hms_opt(9, 10, 11).unwrap();
    /// assert_eq!(dt.time(), NaiveTime::from_hms_opt(9, 10, 11).unwrap());
    /// ```
    #[inline]
    pub const fn time(&self) -> NaiveTime {
        self.time
    }

    /// Adds given `TimeDelta` to the current date and time.
    ///
    /// As a part of Chrono's [leap second handling](./struct.NaiveTime.html#leap-second-handling),
    /// the addition assumes that **there is no leap second ever**,
    /// except when the `NaiveDateTime` itself represents a leap second
    /// in which case the assumption becomes that **there is exactly a single leap second ever**.
    ///
    /// # Errors
    ///
    /// Returns `None` if the resulting date would be out of range.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, TimeDelta};
    ///
    /// let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    ///
    /// let d = from_ymd(2016, 7, 8);
    /// let hms = |h, m, s| d.and_hms_opt(h, m, s).unwrap();
    /// assert_eq!(hms(3, 5, 7).checked_add_signed(TimeDelta::zero()), Some(hms(3, 5, 7)));
    /// assert_eq!(
    ///     hms(3, 5, 7).checked_add_signed(TimeDelta::try_seconds(1).unwrap()),
    ///     Some(hms(3, 5, 8))
    /// );
    /// assert_eq!(
    ///     hms(3, 5, 7).checked_add_signed(TimeDelta::try_seconds(-1).unwrap()),
    ///     Some(hms(3, 5, 6))
    /// );
    /// assert_eq!(
    ///     hms(3, 5, 7).checked_add_signed(TimeDelta::try_seconds(3600 + 60).unwrap()),
    ///     Some(hms(4, 6, 7))
    /// );
    /// assert_eq!(
    ///     hms(3, 5, 7).checked_add_signed(TimeDelta::try_seconds(86_400).unwrap()),
    ///     Some(from_ymd(2016, 7, 9).and_hms_opt(3, 5, 7).unwrap())
    /// );
    ///
    /// let hmsm = |h, m, s, milli| d.and_hms_milli_opt(h, m, s, milli).unwrap();
    /// assert_eq!(
    ///     hmsm(3, 5, 7, 980).checked_add_signed(TimeDelta::try_milliseconds(450).unwrap()),
    ///     Some(hmsm(3, 5, 8, 430))
    /// );
    /// ```
    ///
    /// Overflow returns `None`.
    ///
    /// ```ignore
    /// # use chrono::{TimeDelta, NaiveDate};
    /// # let hms = |h, m, s| NaiveDate::from_ymd_opt(2016, 7, 8).unwrap().and_hms_opt(h, m, s).unwrap();
    /// assert_eq!(hms(3, 5, 7).checked_add_signed(TimeDelta::try_days(1_000_000_000).unwrap()), None);
    /// ```
    ///
    /// Leap seconds are handled,
    /// but the addition assumes that it is the only leap second happened.
    ///
    /// ```ignore
    /// # use chrono::{TimeDelta, NaiveDate};
    /// # let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    /// # let hmsm = |h, m, s, milli| from_ymd(2016, 7, 8).and_hms_milli_opt(h, m, s, milli).unwrap();
    /// let leap = hmsm(3, 5, 59, 1_300);
    /// assert_eq!(leap.checked_add_signed(TimeDelta::zero()),
    ///            Some(hmsm(3, 5, 59, 1_300)));
    /// assert_eq!(leap.checked_add_signed(TimeDelta::try_milliseconds(-500).unwrap()),
    ///            Some(hmsm(3, 5, 59, 800)));
    /// assert_eq!(leap.checked_add_signed(TimeDelta::try_milliseconds(500).unwrap()),
    ///            Some(hmsm(3, 5, 59, 1_800)));
    /// assert_eq!(leap.checked_add_signed(TimeDelta::try_milliseconds(800).unwrap()),
    ///            Some(hmsm(3, 6, 0, 100)));
    /// assert_eq!(leap.checked_add_signed(TimeDelta::try_seconds(10).unwrap()),
    ///            Some(hmsm(3, 6, 9, 300)));
    /// assert_eq!(leap.checked_add_signed(TimeDelta::try_seconds(-10).unwrap()),
    ///            Some(hmsm(3, 5, 50, 300)));
    /// assert_eq!(leap.checked_add_signed(TimeDelta::try_days(1).unwrap()),
    ///            Some(from_ymd(2016, 7, 9).and_hms_milli_opt(3, 5, 59, 300).unwrap()));
    /// ```
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
    /// This method is similar to [`checked_add_signed`](#method.checked_add_offset), but preserves
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
    /// This method is similar to [`checked_sub_signed`](#method.checked_sub_signed), but preserves
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
    /// As a part of Chrono's [leap second handling](./struct.NaiveTime.html#leap-second-handling),
    /// the subtraction assumes that **there is no leap second ever**,
    /// except when the `NaiveDateTime` itself represents a leap second
    /// in which case the assumption becomes that **there is exactly a single leap second ever**.
    ///
    /// # Errors
    ///
    /// Returns `None` if the resulting date would be out of range.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, TimeDelta};
    ///
    /// let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    ///
    /// let d = from_ymd(2016, 7, 8);
    /// let hms = |h, m, s| d.and_hms_opt(h, m, s).unwrap();
    /// assert_eq!(hms(3, 5, 7).checked_sub_signed(TimeDelta::zero()), Some(hms(3, 5, 7)));
    /// assert_eq!(
    ///     hms(3, 5, 7).checked_sub_signed(TimeDelta::try_seconds(1).unwrap()),
    ///     Some(hms(3, 5, 6))
    /// );
    /// assert_eq!(
    ///     hms(3, 5, 7).checked_sub_signed(TimeDelta::try_seconds(-1).unwrap()),
    ///     Some(hms(3, 5, 8))
    /// );
    /// assert_eq!(
    ///     hms(3, 5, 7).checked_sub_signed(TimeDelta::try_seconds(3600 + 60).unwrap()),
    ///     Some(hms(2, 4, 7))
    /// );
    /// assert_eq!(
    ///     hms(3, 5, 7).checked_sub_signed(TimeDelta::try_seconds(86_400).unwrap()),
    ///     Some(from_ymd(2016, 7, 7).and_hms_opt(3, 5, 7).unwrap())
    /// );
    ///
    /// let hmsm = |h, m, s, milli| d.and_hms_milli_opt(h, m, s, milli).unwrap();
    /// assert_eq!(
    ///     hmsm(3, 5, 7, 450).checked_sub_signed(TimeDelta::try_milliseconds(670).unwrap()),
    ///     Some(hmsm(3, 5, 6, 780))
    /// );
    /// ```
    ///
    /// Overflow returns `None`.
    ///
    /// ```ignore
    /// # use chrono::{TimeDelta, NaiveDate};
    /// # let hms = |h, m, s| NaiveDate::from_ymd_opt(2016, 7, 8).unwrap().and_hms_opt(h, m, s).unwrap();
    /// assert_eq!(hms(3, 5, 7).checked_sub_signed(TimeDelta::try_days(1_000_000_000).unwrap()), None);
    /// ```
    ///
    /// Leap seconds are handled,
    /// but the subtraction assumes that it is the only leap second happened.
    ///
    /// ```ignore
    /// # use chrono::{TimeDelta, NaiveDate};
    /// # let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    /// # let hmsm = |h, m, s, milli| from_ymd(2016, 7, 8).and_hms_milli_opt(h, m, s, milli).unwrap();
    /// let leap = hmsm(3, 5, 59, 1_300);
    /// assert_eq!(leap.checked_sub_signed(TimeDelta::zero()),
    ///            Some(hmsm(3, 5, 59, 1_300)));
    /// assert_eq!(leap.checked_sub_signed(TimeDelta::try_milliseconds(200).unwrap()),
    ///            Some(hmsm(3, 5, 59, 1_100)));
    /// assert_eq!(leap.checked_sub_signed(TimeDelta::try_milliseconds(500).unwrap()),
    ///            Some(hmsm(3, 5, 59, 800)));
    /// assert_eq!(leap.checked_sub_signed(TimeDelta::try_seconds(60).unwrap()),
    ///            Some(hmsm(3, 5, 0, 300)));
    /// assert_eq!(leap.checked_sub_signed(TimeDelta::try_days(1).unwrap()),
    ///            Some(from_ymd(2016, 7, 7).and_hms_milli_opt(3, 6, 0, 300).unwrap()));
    /// ```
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
    /// As a part of Chrono's [leap second handling](./struct.NaiveTime.html#leap-second-handling),
    /// the subtraction assumes that **there is no leap second ever**,
    /// except when any of the `NaiveDateTime`s themselves represents a leap second
    /// in which case the assumption becomes that
    /// **there are exactly one (or two) leap second(s) ever**.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, TimeDelta};
    ///
    /// let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    ///
    /// let d = from_ymd(2016, 7, 8);
    /// assert_eq!(
    ///     d.and_hms_opt(3, 5, 7).unwrap().signed_duration_since(d.and_hms_opt(2, 4, 6).unwrap()),
    ///     TimeDelta::try_seconds(3600 + 60 + 1).unwrap()
    /// );
    ///
    /// // July 8 is 190th day in the year 2016
    /// let d0 = from_ymd(2016, 1, 1);
    /// assert_eq!(
    ///     d.and_hms_milli_opt(0, 7, 6, 500)
    ///         .unwrap()
    ///         .signed_duration_since(d0.and_hms_opt(0, 0, 0).unwrap()),
    ///     TimeDelta::try_seconds(189 * 86_400 + 7 * 60 + 6).unwrap()
    ///         + TimeDelta::try_milliseconds(500).unwrap()
    /// );
    /// ```
    ///
    /// Leap seconds are handled, but the subtraction assumes that
    /// there were no other leap seconds happened.
    ///
    /// ```ignore
    /// # use chrono::{TimeDelta, NaiveDate};
    /// # let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    /// let leap = from_ymd(2015, 6, 30).and_hms_milli_opt(23, 59, 59, 1_500).unwrap();
    /// assert_eq!(
    ///     leap.signed_duration_since(from_ymd(2015, 6, 30).and_hms_opt(23, 0, 0).unwrap()),
    ///     TimeDelta::try_seconds(3600).unwrap() + TimeDelta::try_milliseconds(500).unwrap()
    /// );
    /// assert_eq!(
    ///     from_ymd(2015, 7, 1).and_hms_opt(1, 0, 0).unwrap().signed_duration_since(leap),
    ///     TimeDelta::try_seconds(3600).unwrap() - TimeDelta::try_milliseconds(500).unwrap()
    /// );
    /// ```
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
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, Utc};
    /// let dt =
    ///     NaiveDate::from_ymd_opt(2023, 1, 30).unwrap().and_hms_opt(19, 32, 33).unwrap().and_utc();
    /// assert_eq!(dt.timezone(), Utc);
    /// ```
    #[must_use]
    pub const fn and_utc(&self) -> DateTime<Utc> {
        DateTime::from_naive_utc_and_offset(*self, Utc)
    }
}

impl Datelike for NaiveDateTime {
    /// Returns the year number in the [calendar date](./struct.NaiveDate.html#calendar-date).
    ///
    /// See also the [`NaiveDate::year`](./struct.NaiveDate.html#method.year) method.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{Datelike, NaiveDate, NaiveDateTime};
    ///
    /// let dt: NaiveDateTime =
    ///     NaiveDate::from_ymd_opt(2015, 9, 25).unwrap().and_hms_opt(12, 34, 56).unwrap();
    /// assert_eq!(dt.year(), 2015);
    /// ```
    #[inline]
    fn year(&self) -> i32 {
        self.date.year()
    }

    /// Returns the month number starting from 1.
    ///
    /// The return value ranges from 1 to 12.
    ///
    /// See also the [`NaiveDate::month`](./struct.NaiveDate.html#method.month) method.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{Datelike, NaiveDate, NaiveDateTime};
    ///
    /// let dt: NaiveDateTime =
    ///     NaiveDate::from_ymd_opt(2015, 9, 25).unwrap().and_hms_opt(12, 34, 56).unwrap();
    /// assert_eq!(dt.month(), 9);
    /// ```
    #[inline]
    fn month(&self) -> u32 {
        self.date.month()
    }

    /// Returns the day of month starting from 1.
    ///
    /// The return value ranges from 1 to 31. (The last day of month differs by months.)
    ///
    /// See also the [`NaiveDate::day`](./struct.NaiveDate.html#method.day) method.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{Datelike, NaiveDate, NaiveDateTime};
    ///
    /// let dt: NaiveDateTime =
    ///     NaiveDate::from_ymd_opt(2015, 9, 25).unwrap().and_hms_opt(12, 34, 56).unwrap();
    /// assert_eq!(dt.day(), 25);
    /// ```
    #[inline]
    fn day(&self) -> u32 {
        self.date.day()
    }

    /// Returns the day of year starting from 1.
    ///
    /// The return value ranges from 1 to 366. (The last day of year differs by years.)
    ///
    /// See also the [`NaiveDate::ordinal`](./struct.NaiveDate.html#method.ordinal) method.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{Datelike, NaiveDate, NaiveDateTime};
    ///
    /// let dt: NaiveDateTime =
    ///     NaiveDate::from_ymd_opt(2015, 9, 25).unwrap().and_hms_opt(12, 34, 56).unwrap();
    /// assert_eq!(dt.ordinal(), 268);
    /// ```
    #[inline]
    fn ordinal(&self) -> u32 {
        self.date.ordinal()
    }

    /// Returns the day of week.
    ///
    /// See also the [`NaiveDate::weekday`](./struct.NaiveDate.html#method.weekday) method.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{Datelike, NaiveDate, NaiveDateTime, Weekday};
    ///
    /// let dt: NaiveDateTime =
    ///     NaiveDate::from_ymd_opt(2015, 9, 25).unwrap().and_hms_opt(12, 34, 56).unwrap();
    /// assert_eq!(dt.weekday(), Weekday::Fri);
    /// ```
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
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{Datelike, NaiveDate, NaiveDateTime};
    ///
    /// let dt: NaiveDateTime =
    ///     NaiveDate::from_ymd_opt(2015, 9, 8).unwrap().and_hms_opt(12, 34, 56).unwrap();
    /// assert_eq!(
    ///     dt.with_ordinal(60),
    ///     Some(NaiveDate::from_ymd_opt(2015, 3, 1).unwrap().and_hms_opt(12, 34, 56).unwrap())
    /// );
    /// assert_eq!(dt.with_ordinal(366), None); // 2015 had only 365 days
    ///
    /// let dt: NaiveDateTime =
    ///     NaiveDate::from_ymd_opt(2016, 9, 8).unwrap().and_hms_opt(12, 34, 56).unwrap();
    /// assert_eq!(
    ///     dt.with_ordinal(60),
    ///     Some(NaiveDate::from_ymd_opt(2016, 2, 29).unwrap().and_hms_opt(12, 34, 56).unwrap())
    /// );
    /// assert_eq!(
    ///     dt.with_ordinal(366),
    ///     Some(NaiveDate::from_ymd_opt(2016, 12, 31).unwrap().and_hms_opt(12, 34, 56).unwrap())
    /// );
    /// ```
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
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, NaiveDateTime, Timelike};
    ///
    /// let dt: NaiveDateTime =
    ///     NaiveDate::from_ymd_opt(2015, 9, 8).unwrap().and_hms_milli_opt(12, 34, 56, 789).unwrap();
    /// assert_eq!(dt.hour(), 12);
    /// ```
    #[inline]
    fn hour(&self) -> u32 {
        self.time.hour()
    }

    /// Returns the minute number from 0 to 59.
    ///
    /// See also the [`NaiveTime::minute`] method.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, NaiveDateTime, Timelike};
    ///
    /// let dt: NaiveDateTime =
    ///     NaiveDate::from_ymd_opt(2015, 9, 8).unwrap().and_hms_milli_opt(12, 34, 56, 789).unwrap();
    /// assert_eq!(dt.minute(), 34);
    /// ```
    #[inline]
    fn minute(&self) -> u32 {
        self.time.minute()
    }

    /// Returns the second number from 0 to 59.
    ///
    /// See also the [`NaiveTime::second`] method.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, NaiveDateTime, Timelike};
    ///
    /// let dt: NaiveDateTime =
    ///     NaiveDate::from_ymd_opt(2015, 9, 8).unwrap().and_hms_milli_opt(12, 34, 56, 789).unwrap();
    /// assert_eq!(dt.second(), 56);
    /// ```
    #[inline]
    fn second(&self) -> u32 {
        self.time.second()
    }

    /// Returns the number of nanoseconds since the whole non-leap second.
    /// The range from 1,000,000,000 to 1,999,999,999 represents
    /// the [leap second](./struct.NaiveTime.html#leap-second-handling).
    ///
    /// See also the [`NaiveTime#method.nanosecond`] method.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, NaiveDateTime, Timelike};
    ///
    /// let dt: NaiveDateTime =
    ///     NaiveDate::from_ymd_opt(2015, 9, 8).unwrap().and_hms_milli_opt(12, 34, 56, 789).unwrap();
    /// assert_eq!(dt.nanosecond(), 789_000_000);
    /// ```
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
///
/// # Example
///
/// ```ignore
/// use chrono::{NaiveDate, TimeDelta};
///
/// let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
///
/// let d = from_ymd(2016, 7, 8);
/// let hms = |h, m, s| d.and_hms_opt(h, m, s).unwrap();
/// assert_eq!(hms(3, 5, 7) + TimeDelta::zero(), hms(3, 5, 7));
/// assert_eq!(hms(3, 5, 7) + TimeDelta::try_seconds(1).unwrap(), hms(3, 5, 8));
/// assert_eq!(hms(3, 5, 7) + TimeDelta::try_seconds(-1).unwrap(), hms(3, 5, 6));
/// assert_eq!(hms(3, 5, 7) + TimeDelta::try_seconds(3600 + 60).unwrap(), hms(4, 6, 7));
/// assert_eq!(
///     hms(3, 5, 7) + TimeDelta::try_seconds(86_400).unwrap(),
///     from_ymd(2016, 7, 9).and_hms_opt(3, 5, 7).unwrap()
/// );
/// assert_eq!(
///     hms(3, 5, 7) + TimeDelta::try_days(365).unwrap(),
///     from_ymd(2017, 7, 8).and_hms_opt(3, 5, 7).unwrap()
/// );
///
/// let hmsm = |h, m, s, milli| d.and_hms_milli_opt(h, m, s, milli).unwrap();
/// assert_eq!(hmsm(3, 5, 7, 980) + TimeDelta::try_milliseconds(450).unwrap(), hmsm(3, 5, 8, 430));
/// ```
///
/// Leap seconds are handled,
/// but the addition assumes that it is the only leap second happened.
///
/// ```ignore
/// # use chrono::{TimeDelta, NaiveDate};
/// # let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
/// # let hmsm = |h, m, s, milli| from_ymd(2016, 7, 8).and_hms_milli_opt(h, m, s, milli).unwrap();
/// let leap = hmsm(3, 5, 59, 1_300);
/// assert_eq!(leap + TimeDelta::zero(), hmsm(3, 5, 59, 1_300));
/// assert_eq!(leap + TimeDelta::try_milliseconds(-500).unwrap(), hmsm(3, 5, 59, 800));
/// assert_eq!(leap + TimeDelta::try_milliseconds(500).unwrap(), hmsm(3, 5, 59, 1_800));
/// assert_eq!(leap + TimeDelta::try_milliseconds(800).unwrap(), hmsm(3, 6, 0, 100));
/// assert_eq!(leap + TimeDelta::try_seconds(10).unwrap(), hmsm(3, 6, 9, 300));
/// assert_eq!(leap + TimeDelta::try_seconds(-10).unwrap(), hmsm(3, 5, 50, 300));
/// assert_eq!(leap + TimeDelta::try_days(1).unwrap(),
///            from_ymd(2016, 7, 9).and_hms_milli_opt(3, 5, 59, 300).unwrap());
/// ```
///
/// [leap second handling]: crate::extensions::chrono::NaiveTime#leap-second-handling
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
///
/// # Example
///
/// ```ignore
/// use chrono::{NaiveDate, TimeDelta};
///
/// let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
///
/// let d = from_ymd(2016, 7, 8);
/// let hms = |h, m, s| d.and_hms_opt(h, m, s).unwrap();
/// assert_eq!(hms(3, 5, 7) - TimeDelta::zero(), hms(3, 5, 7));
/// assert_eq!(hms(3, 5, 7) - TimeDelta::try_seconds(1).unwrap(), hms(3, 5, 6));
/// assert_eq!(hms(3, 5, 7) - TimeDelta::try_seconds(-1).unwrap(), hms(3, 5, 8));
/// assert_eq!(hms(3, 5, 7) - TimeDelta::try_seconds(3600 + 60).unwrap(), hms(2, 4, 7));
/// assert_eq!(
///     hms(3, 5, 7) - TimeDelta::try_seconds(86_400).unwrap(),
///     from_ymd(2016, 7, 7).and_hms_opt(3, 5, 7).unwrap()
/// );
/// assert_eq!(
///     hms(3, 5, 7) - TimeDelta::try_days(365).unwrap(),
///     from_ymd(2015, 7, 9).and_hms_opt(3, 5, 7).unwrap()
/// );
///
/// let hmsm = |h, m, s, milli| d.and_hms_milli_opt(h, m, s, milli).unwrap();
/// assert_eq!(hmsm(3, 5, 7, 450) - TimeDelta::try_milliseconds(670).unwrap(), hmsm(3, 5, 6, 780));
/// ```
///
/// Leap seconds are handled,
/// but the subtraction assumes that it is the only leap second happened.
///
/// ```ignore
/// # use chrono::{TimeDelta, NaiveDate};
/// # let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
/// # let hmsm = |h, m, s, milli| from_ymd(2016, 7, 8).and_hms_milli_opt(h, m, s, milli).unwrap();
/// let leap = hmsm(3, 5, 59, 1_300);
/// assert_eq!(leap - TimeDelta::zero(), hmsm(3, 5, 59, 1_300));
/// assert_eq!(leap - TimeDelta::try_milliseconds(200).unwrap(), hmsm(3, 5, 59, 1_100));
/// assert_eq!(leap - TimeDelta::try_milliseconds(500).unwrap(), hmsm(3, 5, 59, 800));
/// assert_eq!(leap - TimeDelta::try_seconds(60).unwrap(), hmsm(3, 5, 0, 300));
/// assert_eq!(leap - TimeDelta::try_days(1).unwrap(),
///            from_ymd(2016, 7, 7).and_hms_milli_opt(3, 6, 0, 300).unwrap());
/// ```
///
/// [leap second handling]: crate::extensions::chrono::NaiveTime#leap-second-handling
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

/// The `Debug` output of the naive date and time `dt` is the same as
/// [`dt.format("%Y-%m-%dT%H:%M:%S%.f")`](crate::extensions::chrono::format::strftime).
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
/// use chrono::NaiveDate;
///
/// let dt = NaiveDate::from_ymd_opt(2016, 11, 15).unwrap().and_hms_opt(7, 39, 24).unwrap();
/// assert_eq!(format!("{:?}", dt), "2016-11-15T07:39:24");
/// ```
///
/// Leap seconds may also be used.
///
/// ```ignore
/// # use chrono::NaiveDate;
/// let dt =
///     NaiveDate::from_ymd_opt(2015, 6, 30).unwrap().and_hms_milli_opt(23, 59, 59, 1_500).unwrap();
/// assert_eq!(format!("{:?}", dt), "2015-06-30T23:59:60.500");
/// ```
impl fmt::Debug for NaiveDateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.date.fmt(f)?;
        f.write_char('T')?;
        self.time.fmt(f)
    }
}

/// The `Display` output of the naive date and time `dt` is the same as
/// [`dt.format("%Y-%m-%d %H:%M:%S%.f")`](crate::extensions::chrono::format::strftime).
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
/// use chrono::NaiveDate;
///
/// let dt = NaiveDate::from_ymd_opt(2016, 11, 15).unwrap().and_hms_opt(7, 39, 24).unwrap();
/// assert_eq!(format!("{}", dt), "2016-11-15 07:39:24");
/// ```
///
/// Leap seconds may also be used.
///
/// ```ignore
/// # use chrono::NaiveDate;
/// let dt =
///     NaiveDate::from_ymd_opt(2015, 6, 30).unwrap().and_hms_milli_opt(23, 59, 59, 1_500).unwrap();
/// assert_eq!(format!("{}", dt), "2015-06-30 23:59:60.500");
/// ```
impl fmt::Display for NaiveDateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.date.fmt(f)?;
        f.write_char(' ')?;
        self.time.fmt(f)
    }
}

/// Parsing a `str` into a `NaiveDateTime` uses the same format,
/// [`%Y-%m-%dT%H:%M:%S%.f`](crate::extensions::chrono::format::strftime), as in `Debug`.
///
/// # Example
///
/// ```ignore
/// use chrono::{NaiveDateTime, NaiveDate};
///
/// let dt = NaiveDate::from_ymd_opt(2015, 9, 18).unwrap().and_hms_opt(23, 56, 4).unwrap();
/// assert_eq!("2015-09-18T23:56:04".parse::<NaiveDateTime>(), Ok(dt));
///
/// let dt = NaiveDate::from_ymd_opt(12345, 6, 7).unwrap().and_hms_milli_opt(7, 59, 59, 1_500).unwrap(); // leap second
/// assert_eq!("+12345-6-7T7:59:60.5".parse::<NaiveDateTime>(), Ok(dt));
///
/// assert!("foo".parse::<NaiveDateTime>().is_err());
/// ```
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
