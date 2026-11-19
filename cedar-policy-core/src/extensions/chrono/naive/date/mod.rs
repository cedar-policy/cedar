// This is a part of Chrono.
// See README.md and LICENSE.txt for details.
//
// This file is `src/naive/date/mod.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples marked `ignore`; other changes marked with `Cedar:` comments; code behind chrono's
//   Cargo features (not enabled in Cedar) removed; code not used by Cedar removed.

//! ISO 8601 calendar date without timezone.
//!
//! The implementation is optimized for determining year, month, day and day of week.
//!
//! Format of `NaiveDate`:
//! `YYYY_YYYY_YYYY_YYYY_YYYO_OOOO_OOOO_LWWW`
//! `Y`: Year
//! `O`: Ordinal
//! `L`: leap year flag (1 = common year, 0 is leap year)
//! `W`: weekday before the first day of the year
//! `LWWW`: will also be referred to as the year flags (`F`)

use core::num::NonZeroI32;
use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::{fmt, str};

use super::internals::{Mdf, YearFlags};
use crate::extensions::chrono::format::{
    Item, Numeric, Pad, ParseError, ParseResult, Parsed, StrftimeItems, parse,
    write_hundreds,
};
use crate::extensions::chrono::naive::{Days, IsoWeek, NaiveDateTime, NaiveTime};
use crate::extensions::chrono::{Datelike, TimeDelta, Weekday};
use crate::extensions::chrono::{expect, try_opt};

#[cfg(test)]
mod tests;

/// ISO 8601 calendar date without timezone.
/// Allows for every [proleptic Gregorian date] from Jan 1, 262145 BCE to Dec 31, 262143 CE.
/// Also supports the conversion from ISO 8601 ordinal and week date.
///
/// # Calendar Date
///
/// The ISO 8601 **calendar date** follows the proleptic Gregorian calendar.
/// It is like a normal civil calendar but note some slight differences:
///
/// * Dates before the Gregorian calendar's inception in 1582 are defined via the extrapolation.
///   Be careful, as historical dates are often noted in the Julian calendar and others
///   and the transition to Gregorian may differ across countries (as late as early 20C).
///
///   (Some example: Both Shakespeare from Britain and Cervantes from Spain seemingly died
///   on the same calendar date---April 23, 1616---but in the different calendar.
///   Britain used the Julian calendar at that time, so Shakespeare's death is later.)
///
/// * ISO 8601 calendars have the year 0, which is 1 BCE (a year before 1 CE).
///   If you need a typical BCE/BC and CE/AD notation for year numbers,
///   use the [`Datelike::year_ce`] method.
///
/// # Week Date
///
/// The ISO 8601 **week date** is a triple of year number, week number
/// and [day of the week](Weekday) with the following rules:
///
/// * A week consists of Monday through Sunday, and is always numbered within some year.
///   The week number ranges from 1 to 52 or 53 depending on the year.
///
/// * The week 1 of given year is defined as the first week containing January 4 of that year,
///   or equivalently, the first week containing four or more days in that year.
///
/// * The year number in the week date may *not* correspond to the actual Gregorian year.
///   For example, January 3, 2016 (Sunday) was on the last (53rd) week of 2015.
///
/// Chrono's date types default to the ISO 8601 [calendar date](#calendar-date), but
/// [`Datelike::iso_week`] and [`Datelike::weekday`] methods can be used to get the corresponding
/// week date.
///
/// # Ordinal Date
///
/// The ISO 8601 **ordinal date** is a pair of year number and day of the year ("ordinal").
/// The ordinal number ranges from 1 to 365 or 366 depending on the year.
/// The year number is the same as that of the [calendar date](#calendar-date).
///
/// This is currently the internal format of Chrono's date types.
///
/// [proleptic Gregorian date]: crate::extensions::chrono::NaiveDate#calendar-date
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone)]
pub struct NaiveDate {
    yof: NonZeroI32, // (year << 13) | of
}

impl NaiveDate {
    pub(crate) fn weeks_from(&self, day: Weekday) -> i32 {
        (self.ordinal() as i32 - self.weekday().days_since(day) as i32 + 6) / 7
    }

    /// Makes a new `NaiveDate` from year, ordinal and flags.
    /// Does not check whether the flags are correct for the provided year.
    const fn from_ordinal_and_flags(
        year: i32,
        ordinal: u32,
        flags: YearFlags,
    ) -> Option<NaiveDate> {
        if year < MIN_YEAR || year > MAX_YEAR {
            return None; // Out-of-range
        }
        if ordinal == 0 || ordinal > 366 {
            return None; // Invalid
        }
        debug_assert!(YearFlags::from_year(year).0 == flags.0);
        let yof = (year << 13) | (ordinal << 4) as i32 | flags.0 as i32;
        match yof & OL_MASK <= MAX_OL {
            true => Some(NaiveDate::from_yof(yof)),
            false => None, // Does not exist: Ordinal 366 in a common year.
        }
    }

    /// Makes a new `NaiveDate` from year and packed month-day-flags.
    /// Does not check whether the flags are correct for the provided year.
    const fn from_mdf(year: i32, mdf: Mdf) -> Option<NaiveDate> {
        if year < MIN_YEAR || year > MAX_YEAR {
            return None; // Out-of-range
        }
        Some(NaiveDate::from_yof((year << 13) | try_opt!(mdf.ordinal_and_flags())))
    }

    /// Makes a new `NaiveDate` from the [calendar date](#calendar-date)
    /// (year, month and day).
    ///
    /// # Errors
    ///
    /// Returns `None` if:
    /// - The specified calendar day does not exist (for example 2023-04-31).
    /// - The value for `month` or `day` is invalid.
    /// - `year` is out of range for `NaiveDate`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::NaiveDate;
    ///
    /// let from_ymd_opt = NaiveDate::from_ymd_opt;
    ///
    /// assert!(from_ymd_opt(2015, 3, 14).is_some());
    /// assert!(from_ymd_opt(2015, 0, 14).is_none());
    /// assert!(from_ymd_opt(2015, 2, 29).is_none());
    /// assert!(from_ymd_opt(-4, 2, 29).is_some()); // 5 BCE is a leap year
    /// assert!(from_ymd_opt(400000, 1, 1).is_none());
    /// assert!(from_ymd_opt(-400000, 1, 1).is_none());
    /// ```
    #[must_use]
    pub const fn from_ymd_opt(year: i32, month: u32, day: u32) -> Option<NaiveDate> {
        let flags = YearFlags::from_year(year);

        if let Some(mdf) = Mdf::new(month, day, flags) {
            NaiveDate::from_mdf(year, mdf)
        } else {
            None
        }
    }

    /// Makes a new `NaiveDate` from the [ordinal date](#ordinal-date)
    /// (year and day of the year).
    ///
    /// # Errors
    ///
    /// Returns `None` if:
    /// - The specified ordinal day does not exist (for example 2023-366).
    /// - The value for `ordinal` is invalid (for example: `0`, `400`).
    /// - `year` is out of range for `NaiveDate`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::NaiveDate;
    ///
    /// let from_yo_opt = NaiveDate::from_yo_opt;
    ///
    /// assert!(from_yo_opt(2015, 100).is_some());
    /// assert!(from_yo_opt(2015, 0).is_none());
    /// assert!(from_yo_opt(2015, 365).is_some());
    /// assert!(from_yo_opt(2015, 366).is_none());
    /// assert!(from_yo_opt(-4, 366).is_some()); // 5 BCE is a leap year
    /// assert!(from_yo_opt(400000, 1).is_none());
    /// assert!(from_yo_opt(-400000, 1).is_none());
    /// ```
    #[must_use]
    pub const fn from_yo_opt(year: i32, ordinal: u32) -> Option<NaiveDate> {
        let flags = YearFlags::from_year(year);
        NaiveDate::from_ordinal_and_flags(year, ordinal, flags)
    }

    /// Makes a new `NaiveDate` from the [ISO week date](#week-date)
    /// (year, week number and day of the week).
    /// The resulting `NaiveDate` may have a different year from the input year.
    ///
    /// # Errors
    ///
    /// Returns `None` if:
    /// - The specified week does not exist in that year (for example 2023 week 53).
    /// - The value for `week` is invalid (for example: `0`, `60`).
    /// - If the resulting date is out of range for `NaiveDate`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, Weekday};
    ///
    /// let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    /// let from_isoywd_opt = NaiveDate::from_isoywd_opt;
    ///
    /// assert_eq!(from_isoywd_opt(2015, 0, Weekday::Sun), None);
    /// assert_eq!(from_isoywd_opt(2015, 10, Weekday::Sun), Some(from_ymd(2015, 3, 8)));
    /// assert_eq!(from_isoywd_opt(2015, 30, Weekday::Mon), Some(from_ymd(2015, 7, 20)));
    /// assert_eq!(from_isoywd_opt(2015, 60, Weekday::Mon), None);
    ///
    /// assert_eq!(from_isoywd_opt(400000, 10, Weekday::Fri), None);
    /// assert_eq!(from_isoywd_opt(-400000, 10, Weekday::Sat), None);
    /// ```
    ///
    /// The year number of ISO week date may differ from that of the calendar date.
    ///
    /// ```ignore
    /// # use chrono::{NaiveDate, Weekday};
    /// # let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    /// # let from_isoywd_opt = NaiveDate::from_isoywd_opt;
    /// //           Mo Tu We Th Fr Sa Su
    /// // 2014-W52  22 23 24 25 26 27 28    has 4+ days of new year,
    /// // 2015-W01  29 30 31  1  2  3  4 <- so this is the first week
    /// assert_eq!(from_isoywd_opt(2014, 52, Weekday::Sun), Some(from_ymd(2014, 12, 28)));
    /// assert_eq!(from_isoywd_opt(2014, 53, Weekday::Mon), None);
    /// assert_eq!(from_isoywd_opt(2015, 1, Weekday::Mon), Some(from_ymd(2014, 12, 29)));
    ///
    /// // 2015-W52  21 22 23 24 25 26 27    has 4+ days of old year,
    /// // 2015-W53  28 29 30 31  1  2  3 <- so this is the last week
    /// // 2016-W01   4  5  6  7  8  9 10
    /// assert_eq!(from_isoywd_opt(2015, 52, Weekday::Sun), Some(from_ymd(2015, 12, 27)));
    /// assert_eq!(from_isoywd_opt(2015, 53, Weekday::Sun), Some(from_ymd(2016, 1, 3)));
    /// assert_eq!(from_isoywd_opt(2015, 54, Weekday::Mon), None);
    /// assert_eq!(from_isoywd_opt(2016, 1, Weekday::Mon), Some(from_ymd(2016, 1, 4)));
    /// ```
    #[must_use]
    pub const fn from_isoywd_opt(year: i32, week: u32, weekday: Weekday) -> Option<NaiveDate> {
        let flags = YearFlags::from_year(year);
        let nweeks = flags.nisoweeks();
        if week == 0 || week > nweeks {
            return None;
        }
        // ordinal = week ordinal - delta
        let weekord = week * 7 + weekday as u32;
        let delta = flags.isoweek_delta();
        let (year, ordinal, flags) = if weekord <= delta {
            // ordinal < 1, previous year
            let prevflags = YearFlags::from_year(year - 1);
            (year - 1, weekord + prevflags.ndays() - delta, prevflags)
        } else {
            let ordinal = weekord - delta;
            let ndays = flags.ndays();
            if ordinal <= ndays {
                // this year
                (year, ordinal, flags)
            } else {
                // ordinal > ndays, next year
                let nextflags = YearFlags::from_year(year + 1);
                (year + 1, ordinal - ndays, nextflags)
            }
        };
        NaiveDate::from_ordinal_and_flags(year, ordinal, flags)
    }

    /// Makes a new `NaiveDate` from a day's number in the proleptic Gregorian calendar, with
    /// January 1, 1 being day 1.
    ///
    /// # Errors
    ///
    /// Returns `None` if the date is out of range.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::NaiveDate;
    ///
    /// let from_ndays_opt = NaiveDate::from_num_days_from_ce_opt;
    /// let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    ///
    /// assert_eq!(from_ndays_opt(730_000), Some(from_ymd(1999, 9, 3)));
    /// assert_eq!(from_ndays_opt(1), Some(from_ymd(1, 1, 1)));
    /// assert_eq!(from_ndays_opt(0), Some(from_ymd(0, 12, 31)));
    /// assert_eq!(from_ndays_opt(-1), Some(from_ymd(0, 12, 30)));
    /// assert_eq!(from_ndays_opt(100_000_000), None);
    /// assert_eq!(from_ndays_opt(-100_000_000), None);
    /// ```
    #[must_use]
    pub const fn from_num_days_from_ce_opt(days: i32) -> Option<NaiveDate> {
        let days = try_opt!(days.checked_add(365)); // make December 31, 1 BCE equal to day 0
        let year_div_400 = days.div_euclid(146_097);
        let cycle = days.rem_euclid(146_097);
        let (year_mod_400, ordinal) = cycle_to_yo(cycle as u32);
        let flags = YearFlags::from_year_mod_400(year_mod_400 as i32);
        NaiveDate::from_ordinal_and_flags(year_div_400 * 400 + year_mod_400 as i32, ordinal, flags)
    }

    /// Parses a string with the specified format string and returns a new `NaiveDate`.
    /// See the [`format::strftime` module](crate::extensions::chrono::format::strftime)
    /// on the supported escape sequences.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::NaiveDate;
    ///
    /// let parse_from_str = NaiveDate::parse_from_str;
    ///
    /// assert_eq!(
    ///     parse_from_str("2015-09-05", "%Y-%m-%d"),
    ///     Ok(NaiveDate::from_ymd_opt(2015, 9, 5).unwrap())
    /// );
    /// assert_eq!(
    ///     parse_from_str("5sep2015", "%d%b%Y"),
    ///     Ok(NaiveDate::from_ymd_opt(2015, 9, 5).unwrap())
    /// );
    /// ```
    ///
    /// Time and offset is ignored for the purpose of parsing.
    ///
    /// ```ignore
    /// # use chrono::NaiveDate;
    /// # let parse_from_str = NaiveDate::parse_from_str;
    /// assert_eq!(
    ///     parse_from_str("2014-5-17T12:34:56+09:30", "%Y-%m-%dT%H:%M:%S%z"),
    ///     Ok(NaiveDate::from_ymd_opt(2014, 5, 17).unwrap())
    /// );
    /// ```
    ///
    /// Out-of-bound dates or insufficient fields are errors.
    ///
    /// ```ignore
    /// # use chrono::NaiveDate;
    /// # let parse_from_str = NaiveDate::parse_from_str;
    /// assert!(parse_from_str("2015/9", "%Y/%m").is_err());
    /// assert!(parse_from_str("2015/9/31", "%Y/%m/%d").is_err());
    /// ```
    ///
    /// All parsed fields should be consistent to each other, otherwise it's an error.
    ///
    /// ```ignore
    /// # use chrono::NaiveDate;
    /// # let parse_from_str = NaiveDate::parse_from_str;
    /// assert!(parse_from_str("Sat, 09 Aug 2013", "%a, %d %b %Y").is_err());
    /// ```
    pub fn parse_from_str(s: &str, fmt: &str) -> ParseResult<NaiveDate> {
        let mut parsed = Parsed::new();
        parse(&mut parsed, s, StrftimeItems::new(fmt))?;
        parsed.to_naive_date()
    }

    /// Add a duration in [`Days`] to the date
    ///
    /// # Errors
    ///
    /// Returns `None` if the resulting date would be out of range.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # use chrono::{NaiveDate, Days};
    /// assert_eq!(
    ///     NaiveDate::from_ymd_opt(2022, 2, 20).unwrap().checked_add_days(Days::new(9)),
    ///     Some(NaiveDate::from_ymd_opt(2022, 3, 1).unwrap())
    /// );
    /// assert_eq!(
    ///     NaiveDate::from_ymd_opt(2022, 7, 31).unwrap().checked_add_days(Days::new(2)),
    ///     Some(NaiveDate::from_ymd_opt(2022, 8, 2).unwrap())
    /// );
    /// assert_eq!(
    ///     NaiveDate::from_ymd_opt(2022, 7, 31).unwrap().checked_add_days(Days::new(1000000000000)),
    ///     None
    /// );
    /// ```
    #[must_use]
    pub const fn checked_add_days(self, days: Days) -> Option<Self> {
        match days.0 <= i32::MAX as u64 {
            true => self.add_days(days.0 as i32),
            false => None,
        }
    }

    /// Add a duration of `i32` days to the date.
    pub(crate) const fn add_days(self, days: i32) -> Option<Self> {
        // Fast path if the result is within the same year.
        // Also `DateTime::checked_(add|sub)_days` relies on this path, because if the value remains
        // within the year it doesn't do a check if the year is in range.
        // This way `DateTime:checked_(add|sub)_days(Days::new(0))` can be a no-op on dates were the
        // local datetime is beyond `NaiveDate::{MIN, MAX}.
        const ORDINAL_MASK: i32 = 0b1_1111_1111_0000;
        if let Some(ordinal) = ((self.yof() & ORDINAL_MASK) >> 4).checked_add(days) {
            if ordinal > 0 && ordinal <= (365 + self.leap_year() as i32) {
                let year_and_flags = self.yof() & !ORDINAL_MASK;
                return Some(NaiveDate::from_yof(year_and_flags | (ordinal << 4)));
            }
        }
        // do the full check
        let year = self.year();
        let (mut year_div_400, year_mod_400) = div_mod_floor(year, 400);
        let cycle = yo_to_cycle(year_mod_400 as u32, self.ordinal());
        let cycle = try_opt!((cycle as i32).checked_add(days));
        let (cycle_div_400y, cycle) = div_mod_floor(cycle, 146_097);
        year_div_400 += cycle_div_400y;

        let (year_mod_400, ordinal) = cycle_to_yo(cycle as u32);
        let flags = YearFlags::from_year_mod_400(year_mod_400 as i32);
        NaiveDate::from_ordinal_and_flags(year_div_400 * 400 + year_mod_400 as i32, ordinal, flags)
    }

    /// Makes a new `NaiveDateTime` from the current date and given `NaiveTime`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
    ///
    /// let d = NaiveDate::from_ymd_opt(2015, 6, 3).unwrap();
    /// let t = NaiveTime::from_hms_milli_opt(12, 34, 56, 789).unwrap();
    ///
    /// let dt: NaiveDateTime = d.and_time(t);
    /// assert_eq!(dt.date(), d);
    /// assert_eq!(dt.time(), t);
    /// ```
    #[inline]
    #[must_use]
    pub const fn and_time(&self, time: NaiveTime) -> NaiveDateTime {
        NaiveDateTime::new(*self, time)
    }

    /// Makes a new `NaiveDateTime` from the current date, hour, minute and second.
    ///
    /// No [leap second](./struct.NaiveTime.html#leap-second-handling) is allowed here;
    /// use `NaiveDate::and_hms_*_opt` methods with a subsecond parameter instead.
    ///
    /// # Errors
    ///
    /// Returns `None` on invalid hour, minute and/or second.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::NaiveDate;
    ///
    /// let d = NaiveDate::from_ymd_opt(2015, 6, 3).unwrap();
    /// assert!(d.and_hms_opt(12, 34, 56).is_some());
    /// assert!(d.and_hms_opt(12, 34, 60).is_none()); // use `and_hms_milli_opt` instead
    /// assert!(d.and_hms_opt(12, 60, 56).is_none());
    /// assert!(d.and_hms_opt(24, 34, 56).is_none());
    /// ```
    #[inline]
    #[must_use]
    pub const fn and_hms_opt(&self, hour: u32, min: u32, sec: u32) -> Option<NaiveDateTime> {
        let time = try_opt!(NaiveTime::from_hms_opt(hour, min, sec));
        Some(self.and_time(time))
    }

    /// Returns the packed month-day-flags.
    #[inline]
    const fn mdf(&self) -> Mdf {
        Mdf::from_ol((self.yof() & OL_MASK) >> 3, self.year_flags())
    }

    /// Makes a new `NaiveDate` for the next calendar date.
    ///
    /// # Errors
    ///
    /// Returns `None` when `self` is the last representable date.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::NaiveDate;
    ///
    /// assert_eq!(
    ///     NaiveDate::from_ymd_opt(2015, 6, 3).unwrap().succ_opt(),
    ///     Some(NaiveDate::from_ymd_opt(2015, 6, 4).unwrap())
    /// );
    /// assert_eq!(NaiveDate::MAX.succ_opt(), None);
    /// ```
    #[inline]
    #[must_use]
    pub const fn succ_opt(&self) -> Option<NaiveDate> {
        let new_ol = (self.yof() & OL_MASK) + (1 << 4);
        match new_ol <= MAX_OL {
            true => Some(NaiveDate::from_yof(self.yof() & !OL_MASK | new_ol)),
            false => NaiveDate::from_yo_opt(self.year() + 1, 1),
        }
    }

    /// Makes a new `NaiveDate` for the previous calendar date.
    ///
    /// # Errors
    ///
    /// Returns `None` when `self` is the first representable date.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::NaiveDate;
    ///
    /// assert_eq!(
    ///     NaiveDate::from_ymd_opt(2015, 6, 3).unwrap().pred_opt(),
    ///     Some(NaiveDate::from_ymd_opt(2015, 6, 2).unwrap())
    /// );
    /// assert_eq!(NaiveDate::MIN.pred_opt(), None);
    /// ```
    #[inline]
    #[must_use]
    pub const fn pred_opt(&self) -> Option<NaiveDate> {
        let new_shifted_ordinal = (self.yof() & ORDINAL_MASK) - (1 << 4);
        match new_shifted_ordinal > 0 {
            true => Some(NaiveDate::from_yof(self.yof() & !ORDINAL_MASK | new_shifted_ordinal)),
            false => NaiveDate::from_ymd_opt(self.year() - 1, 12, 31),
        }
    }

    /// Adds the number of whole days in the given `TimeDelta` to the current date.
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
    /// let d = NaiveDate::from_ymd_opt(2015, 9, 5).unwrap();
    /// assert_eq!(
    ///     d.checked_add_signed(TimeDelta::try_days(40).unwrap()),
    ///     Some(NaiveDate::from_ymd_opt(2015, 10, 15).unwrap())
    /// );
    /// assert_eq!(
    ///     d.checked_add_signed(TimeDelta::try_days(-40).unwrap()),
    ///     Some(NaiveDate::from_ymd_opt(2015, 7, 27).unwrap())
    /// );
    /// assert_eq!(d.checked_add_signed(TimeDelta::try_days(1_000_000_000).unwrap()), None);
    /// assert_eq!(d.checked_add_signed(TimeDelta::try_days(-1_000_000_000).unwrap()), None);
    /// assert_eq!(NaiveDate::MAX.checked_add_signed(TimeDelta::try_days(1).unwrap()), None);
    /// ```
    #[must_use]
    pub const fn checked_add_signed(self, rhs: TimeDelta) -> Option<NaiveDate> {
        let days = rhs.num_days();
        if days < i32::MIN as i64 || days > i32::MAX as i64 {
            return None;
        }
        self.add_days(days as i32)
    }

    /// Subtracts the number of whole days in the given `TimeDelta` from the current date.
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
    /// let d = NaiveDate::from_ymd_opt(2015, 9, 5).unwrap();
    /// assert_eq!(
    ///     d.checked_sub_signed(TimeDelta::try_days(40).unwrap()),
    ///     Some(NaiveDate::from_ymd_opt(2015, 7, 27).unwrap())
    /// );
    /// assert_eq!(
    ///     d.checked_sub_signed(TimeDelta::try_days(-40).unwrap()),
    ///     Some(NaiveDate::from_ymd_opt(2015, 10, 15).unwrap())
    /// );
    /// assert_eq!(d.checked_sub_signed(TimeDelta::try_days(1_000_000_000).unwrap()), None);
    /// assert_eq!(d.checked_sub_signed(TimeDelta::try_days(-1_000_000_000).unwrap()), None);
    /// assert_eq!(NaiveDate::MIN.checked_sub_signed(TimeDelta::try_days(1).unwrap()), None);
    /// ```
    #[must_use]
    pub const fn checked_sub_signed(self, rhs: TimeDelta) -> Option<NaiveDate> {
        let days = -rhs.num_days();
        if days < i32::MIN as i64 || days > i32::MAX as i64 {
            return None;
        }
        self.add_days(days as i32)
    }

    /// Subtracts another `NaiveDate` from the current date.
    /// Returns a `TimeDelta` of integral numbers.
    ///
    /// This does not overflow or underflow at all,
    /// as all possible output fits in the range of `TimeDelta`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{NaiveDate, TimeDelta};
    ///
    /// let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    /// let since = NaiveDate::signed_duration_since;
    ///
    /// assert_eq!(since(from_ymd(2014, 1, 1), from_ymd(2014, 1, 1)), TimeDelta::zero());
    /// assert_eq!(
    ///     since(from_ymd(2014, 1, 1), from_ymd(2013, 12, 31)),
    ///     TimeDelta::try_days(1).unwrap()
    /// );
    /// assert_eq!(since(from_ymd(2014, 1, 1), from_ymd(2014, 1, 2)), TimeDelta::try_days(-1).unwrap());
    /// assert_eq!(
    ///     since(from_ymd(2014, 1, 1), from_ymd(2013, 9, 23)),
    ///     TimeDelta::try_days(100).unwrap()
    /// );
    /// assert_eq!(
    ///     since(from_ymd(2014, 1, 1), from_ymd(2013, 1, 1)),
    ///     TimeDelta::try_days(365).unwrap()
    /// );
    /// assert_eq!(
    ///     since(from_ymd(2014, 1, 1), from_ymd(2010, 1, 1)),
    ///     TimeDelta::try_days(365 * 4 + 1).unwrap()
    /// );
    /// assert_eq!(
    ///     since(from_ymd(2014, 1, 1), from_ymd(1614, 1, 1)),
    ///     TimeDelta::try_days(365 * 400 + 97).unwrap()
    /// );
    /// ```
    #[must_use]
    pub const fn signed_duration_since(self, rhs: Self) -> TimeDelta {
        let year1 = self.year();
        let year2 = rhs.year();
        let (year1_div_400, year1_mod_400) = div_mod_floor(year1, 400);
        let (year2_div_400, year2_mod_400) = div_mod_floor(year2, 400);
        let cycle1 = yo_to_cycle(year1_mod_400 as u32, self.ordinal()) as i64;
        let cycle2 = yo_to_cycle(year2_mod_400 as u32, rhs.ordinal()) as i64;
        let days = (year1_div_400 as i64 - year2_div_400 as i64) * 146_097 + (cycle1 - cycle2);
        // The range of `TimeDelta` is ca. 585 million years, the range of `NaiveDate` ca. 525.000
        // years.
        expect(TimeDelta::try_days(days), "always in range")
    }

    /// Returns `true` if this is a leap year.
    ///
    /// ```ignore
    /// # use chrono::NaiveDate;
    /// assert_eq!(NaiveDate::from_ymd_opt(2000, 1, 1).unwrap().leap_year(), true);
    /// assert_eq!(NaiveDate::from_ymd_opt(2001, 1, 1).unwrap().leap_year(), false);
    /// assert_eq!(NaiveDate::from_ymd_opt(2002, 1, 1).unwrap().leap_year(), false);
    /// assert_eq!(NaiveDate::from_ymd_opt(2003, 1, 1).unwrap().leap_year(), false);
    /// assert_eq!(NaiveDate::from_ymd_opt(2004, 1, 1).unwrap().leap_year(), true);
    /// assert_eq!(NaiveDate::from_ymd_opt(2100, 1, 1).unwrap().leap_year(), false);
    /// ```
    pub const fn leap_year(&self) -> bool {
        self.yof() & (0b1000) == 0
    }

    // This duplicates `Datelike::year()`, because trait methods can't be const yet.
    #[inline]
    const fn year(&self) -> i32 {
        self.yof() >> 13
    }

    /// Returns the day of year starting from 1.
    // This duplicates `Datelike::ordinal()`, because trait methods can't be const yet.
    #[inline]
    const fn ordinal(&self) -> u32 {
        ((self.yof() & ORDINAL_MASK) >> 4) as u32
    }

    // This duplicates `Datelike::month()`, because trait methods can't be const yet.
    #[inline]
    const fn month(&self) -> u32 {
        self.mdf().month()
    }

    // This duplicates `Datelike::day()`, because trait methods can't be const yet.
    #[inline]
    const fn day(&self) -> u32 {
        self.mdf().day()
    }

    /// Returns the day of week.
    // This duplicates `Datelike::weekday()`, because trait methods can't be const yet.
    #[inline]
    pub(super) const fn weekday(&self) -> Weekday {
        match (((self.yof() & ORDINAL_MASK) >> 4) + (self.yof() & WEEKDAY_FLAGS_MASK)) % 7 {
            0 => Weekday::Mon,
            1 => Weekday::Tue,
            2 => Weekday::Wed,
            3 => Weekday::Thu,
            4 => Weekday::Fri,
            5 => Weekday::Sat,
            _ => Weekday::Sun,
        }
    }

    #[inline]
    const fn year_flags(&self) -> YearFlags {
        YearFlags((self.yof() & YEAR_FLAGS_MASK) as u8)
    }

    /// Counts the days in the proleptic Gregorian calendar, with January 1, Year 1 (CE) as day 1.
    // This duplicates `Datelike::num_days_from_ce()`, because trait methods can't be const yet.
    pub(crate) const fn num_days_from_ce(&self) -> i32 {
        // we know this wouldn't overflow since year is limited to 1/2^13 of i32's full range.
        let mut year = self.year() - 1;
        let mut ndays = 0;
        if year < 0 {
            let excess = 1 + (-year) / 400;
            year += excess * 400;
            ndays -= excess * 146_097;
        }
        let div_100 = year / 100;
        ndays += ((year * 1461) >> 2) - div_100 + (div_100 >> 2);
        ndays + self.ordinal() as i32
    }

    /// Create a new `NaiveDate` from a raw year-ordinal-flags `i32`.
    ///
    /// In a valid value an ordinal is never `0`, and neither are the year flags. This method
    /// doesn't do any validation in release builds.
    #[inline]
    const fn from_yof(yof: i32) -> NaiveDate {
        // The following are the invariants our ordinal and flags should uphold for a valid
        // `NaiveDate`.
        debug_assert!(((yof & OL_MASK) >> 3) > 1);
        debug_assert!(((yof & OL_MASK) >> 3) <= MAX_OL);
        debug_assert!((yof & 0b111) != 000);
        // Cedar: `unsafe { NonZeroI32::new_unchecked(yof) }` replaced with a checked conversion
        // because Cedar forbids `unsafe_code`. The invariants above guarantee `yof != 0`.
        NaiveDate { yof: expect(NonZeroI32::new(yof), "invalid year-ordinal-flags value") }
    }

    /// Get the raw year-ordinal-flags `i32`.
    #[inline]
    const fn yof(&self) -> i32 {
        self.yof.get()
    }

    /// One day before the minimum possible `NaiveDate` (December 31, 262145 BCE).
    pub(crate) const BEFORE_MIN: NaiveDate =
        NaiveDate::from_yof(((MIN_YEAR - 1) << 13) | (366 << 4) | 0o07 /* FE */);
    /// One day after the maximum possible `NaiveDate` (January 1, 262143 CE).
    pub(crate) const AFTER_MAX: NaiveDate =
        NaiveDate::from_yof(((MAX_YEAR + 1) << 13) | (1 << 4) | 0o17 /* F */);
}

impl Datelike for NaiveDate {
    /// Returns the year number in the [calendar date](#calendar-date).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{Datelike, NaiveDate};
    ///
    /// assert_eq!(NaiveDate::from_ymd_opt(2015, 9, 8).unwrap().year(), 2015);
    /// assert_eq!(NaiveDate::from_ymd_opt(-308, 3, 14).unwrap().year(), -308); // 309 BCE
    /// ```
    #[inline]
    fn year(&self) -> i32 {
        self.year()
    }

    /// Returns the month number starting from 1.
    ///
    /// The return value ranges from 1 to 12.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{Datelike, NaiveDate};
    ///
    /// assert_eq!(NaiveDate::from_ymd_opt(2015, 9, 8).unwrap().month(), 9);
    /// assert_eq!(NaiveDate::from_ymd_opt(-308, 3, 14).unwrap().month(), 3);
    /// ```
    #[inline]
    fn month(&self) -> u32 {
        self.month()
    }

    /// Returns the day of month starting from 1.
    ///
    /// The return value ranges from 1 to 31. (The last day of month differs by months.)
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{Datelike, NaiveDate};
    ///
    /// assert_eq!(NaiveDate::from_ymd_opt(2015, 9, 8).unwrap().day(), 8);
    /// assert_eq!(NaiveDate::from_ymd_opt(-308, 3, 14).unwrap().day(), 14);
    /// ```
    ///
    /// Combined with [`NaiveDate::pred_opt`](#method.pred_opt),
    /// one can determine the number of days in a particular month.
    /// (Note that this panics when `year` is out of range.)
    ///
    /// ```ignore
    /// use chrono::{Datelike, NaiveDate};
    ///
    /// fn ndays_in_month(year: i32, month: u32) -> u32 {
    ///     // the first day of the next month...
    ///     let (y, m) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
    ///     let d = NaiveDate::from_ymd_opt(y, m, 1).unwrap();
    ///
    ///     // ...is preceded by the last day of the original month
    ///     d.pred_opt().unwrap().day()
    /// }
    ///
    /// assert_eq!(ndays_in_month(2015, 8), 31);
    /// assert_eq!(ndays_in_month(2015, 9), 30);
    /// assert_eq!(ndays_in_month(2015, 12), 31);
    /// assert_eq!(ndays_in_month(2016, 2), 29);
    /// assert_eq!(ndays_in_month(2017, 2), 28);
    /// ```
    #[inline]
    fn day(&self) -> u32 {
        self.day()
    }

    /// Returns the day of year starting from 1.
    ///
    /// The return value ranges from 1 to 366. (The last day of year differs by years.)
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{Datelike, NaiveDate};
    ///
    /// assert_eq!(NaiveDate::from_ymd_opt(2015, 9, 8).unwrap().ordinal(), 251);
    /// assert_eq!(NaiveDate::from_ymd_opt(-308, 3, 14).unwrap().ordinal(), 74);
    /// ```
    ///
    /// Combined with [`NaiveDate::pred_opt`](#method.pred_opt),
    /// one can determine the number of days in a particular year.
    /// (Note that this panics when `year` is out of range.)
    ///
    /// ```ignore
    /// use chrono::{Datelike, NaiveDate};
    ///
    /// fn ndays_in_year(year: i32) -> u32 {
    ///     // the first day of the next year...
    ///     let d = NaiveDate::from_ymd_opt(year + 1, 1, 1).unwrap();
    ///
    ///     // ...is preceded by the last day of the original year
    ///     d.pred_opt().unwrap().ordinal()
    /// }
    ///
    /// assert_eq!(ndays_in_year(2015), 365);
    /// assert_eq!(ndays_in_year(2016), 366);
    /// assert_eq!(ndays_in_year(2017), 365);
    /// assert_eq!(ndays_in_year(2000), 366);
    /// assert_eq!(ndays_in_year(2100), 365);
    /// ```
    #[inline]
    fn ordinal(&self) -> u32 {
        ((self.yof() & ORDINAL_MASK) >> 4) as u32
    }

    /// Returns the day of week.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use chrono::{Datelike, NaiveDate, Weekday};
    ///
    /// assert_eq!(NaiveDate::from_ymd_opt(2015, 9, 8).unwrap().weekday(), Weekday::Tue);
    /// assert_eq!(NaiveDate::from_ymd_opt(-308, 3, 14).unwrap().weekday(), Weekday::Fri);
    /// ```
    #[inline]
    fn weekday(&self) -> Weekday {
        self.weekday()
    }

    #[inline]
    fn iso_week(&self) -> IsoWeek {
        IsoWeek::from_yof(self.year(), self.ordinal(), self.year_flags())
    }

    /// Makes a new `NaiveDate` with the day of year (starting from 1) changed.
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
    /// use chrono::{NaiveDate, Datelike};
    ///
    /// assert_eq!(NaiveDate::from_ymd_opt(2015, 1, 1).unwrap().with_ordinal(60),
    ///            Some(NaiveDate::from_ymd_opt(2015, 3, 1).unwrap()));
    /// assert_eq!(NaiveDate::from_ymd_opt(2015, 1, 1).unwrap().with_ordinal(366),
    ///            None); // 2015 had only 365 days
    ///
    /// assert_eq!(NaiveDate::from_ymd_opt(2016, 1, 1).unwrap().with_ordinal(60),
    ///            Some(NaiveDate::from_ymd_opt(2016, 2, 29).unwrap()));
    /// assert_eq!(NaiveDate::from_ymd_opt(2016, 1, 1).unwrap().with_ordinal(366),
    ///            Some(NaiveDate::from_ymd_opt(2016, 12, 31).unwrap()));
    /// ```
    #[inline]
    fn with_ordinal(&self, ordinal: u32) -> Option<NaiveDate> {
        if ordinal == 0 || ordinal > 366 {
            return None;
        }
        let yof = (self.yof() & !ORDINAL_MASK) | (ordinal << 4) as i32;
        match yof & OL_MASK <= MAX_OL {
            true => Some(NaiveDate::from_yof(yof)),
            false => None, // Does not exist: Ordinal 366 in a common year.
        }
    }
}

/// Add `TimeDelta` to `NaiveDate`.
///
/// This discards the fractional days in `TimeDelta`, rounding to the closest integral number of
/// days towards `TimeDelta::zero()`.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using [`NaiveDate::checked_add_signed`] to get an `Option` instead.
///
/// # Example
///
/// ```ignore
/// use chrono::{NaiveDate, TimeDelta};
///
/// let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
///
/// assert_eq!(from_ymd(2014, 1, 1) + TimeDelta::zero(), from_ymd(2014, 1, 1));
/// assert_eq!(from_ymd(2014, 1, 1) + TimeDelta::try_seconds(86399).unwrap(), from_ymd(2014, 1, 1));
/// assert_eq!(
///     from_ymd(2014, 1, 1) + TimeDelta::try_seconds(-86399).unwrap(),
///     from_ymd(2014, 1, 1)
/// );
/// assert_eq!(from_ymd(2014, 1, 1) + TimeDelta::try_days(1).unwrap(), from_ymd(2014, 1, 2));
/// assert_eq!(from_ymd(2014, 1, 1) + TimeDelta::try_days(-1).unwrap(), from_ymd(2013, 12, 31));
/// assert_eq!(from_ymd(2014, 1, 1) + TimeDelta::try_days(364).unwrap(), from_ymd(2014, 12, 31));
/// assert_eq!(
///     from_ymd(2014, 1, 1) + TimeDelta::try_days(365 * 4 + 1).unwrap(),
///     from_ymd(2018, 1, 1)
/// );
/// assert_eq!(
///     from_ymd(2014, 1, 1) + TimeDelta::try_days(365 * 400 + 97).unwrap(),
///     from_ymd(2414, 1, 1)
/// );
/// ```
///
/// [`NaiveDate::checked_add_signed`]: crate::extensions::chrono::NaiveDate::checked_add_signed
impl Add<TimeDelta> for NaiveDate {
    type Output = NaiveDate;

    #[inline]
    #[track_caller]
    fn add(self, rhs: TimeDelta) -> NaiveDate {
        self.checked_add_signed(rhs).expect("`NaiveDate + TimeDelta` overflowed")
    }
}

/// Add-assign of `TimeDelta` to `NaiveDate`.
///
/// This discards the fractional days in `TimeDelta`, rounding to the closest integral number of days
/// towards `TimeDelta::zero()`.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using [`NaiveDate::checked_add_signed`] to get an `Option` instead.
impl AddAssign<TimeDelta> for NaiveDate {
    #[inline]
    #[track_caller]
    fn add_assign(&mut self, rhs: TimeDelta) {
        *self = self.add(rhs);
    }
}

/// Add `Days` to `NaiveDate`.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using `NaiveDate::checked_add_days` to get an `Option` instead.
impl Add<Days> for NaiveDate {
    type Output = NaiveDate;

    #[track_caller]
    fn add(self, days: Days) -> Self::Output {
        self.checked_add_days(days).expect("`NaiveDate + Days` out of range")
    }
}

/// Subtract `TimeDelta` from `NaiveDate`.
///
/// This discards the fractional days in `TimeDelta`, rounding to the closest integral number of
/// days towards `TimeDelta::zero()`.
/// It is the same as the addition with a negated `TimeDelta`.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using [`NaiveDate::checked_sub_signed`] to get an `Option` instead.
///
/// # Example
///
/// ```ignore
/// use chrono::{NaiveDate, TimeDelta};
///
/// let from_ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
///
/// assert_eq!(from_ymd(2014, 1, 1) - TimeDelta::zero(), from_ymd(2014, 1, 1));
/// assert_eq!(from_ymd(2014, 1, 1) - TimeDelta::try_seconds(86399).unwrap(), from_ymd(2014, 1, 1));
/// assert_eq!(
///     from_ymd(2014, 1, 1) - TimeDelta::try_seconds(-86399).unwrap(),
///     from_ymd(2014, 1, 1)
/// );
/// assert_eq!(from_ymd(2014, 1, 1) - TimeDelta::try_days(1).unwrap(), from_ymd(2013, 12, 31));
/// assert_eq!(from_ymd(2014, 1, 1) - TimeDelta::try_days(-1).unwrap(), from_ymd(2014, 1, 2));
/// assert_eq!(from_ymd(2014, 1, 1) - TimeDelta::try_days(364).unwrap(), from_ymd(2013, 1, 2));
/// assert_eq!(
///     from_ymd(2014, 1, 1) - TimeDelta::try_days(365 * 4 + 1).unwrap(),
///     from_ymd(2010, 1, 1)
/// );
/// assert_eq!(
///     from_ymd(2014, 1, 1) - TimeDelta::try_days(365 * 400 + 97).unwrap(),
///     from_ymd(1614, 1, 1)
/// );
/// ```
///
/// [`NaiveDate::checked_sub_signed`]: crate::extensions::chrono::NaiveDate::checked_sub_signed
impl Sub<TimeDelta> for NaiveDate {
    type Output = NaiveDate;

    #[inline]
    #[track_caller]
    fn sub(self, rhs: TimeDelta) -> NaiveDate {
        self.checked_sub_signed(rhs).expect("`NaiveDate - TimeDelta` overflowed")
    }
}

/// Subtract-assign `TimeDelta` from `NaiveDate`.
///
/// This discards the fractional days in `TimeDelta`, rounding to the closest integral number of
/// days towards `TimeDelta::zero()`.
/// It is the same as the addition with a negated `TimeDelta`.
///
/// # Panics
///
/// Panics if the resulting date would be out of range.
/// Consider using [`NaiveDate::checked_sub_signed`] to get an `Option` instead.
impl SubAssign<TimeDelta> for NaiveDate {
    #[inline]
    #[track_caller]
    fn sub_assign(&mut self, rhs: TimeDelta) {
        *self = self.sub(rhs);
    }
}

/// The `Debug` output of the naive date `d` is the same as
/// [`d.format("%Y-%m-%d")`](crate::extensions::chrono::format::strftime).
///
/// The string printed can be readily parsed via the `parse` method on `str`.
///
/// # Example
///
/// ```ignore
/// use chrono::NaiveDate;
///
/// assert_eq!(format!("{:?}", NaiveDate::from_ymd_opt(2015, 9, 5).unwrap()), "2015-09-05");
/// assert_eq!(format!("{:?}", NaiveDate::from_ymd_opt(0, 1, 1).unwrap()), "0000-01-01");
/// assert_eq!(format!("{:?}", NaiveDate::from_ymd_opt(9999, 12, 31).unwrap()), "9999-12-31");
/// ```
///
/// ISO 8601 requires an explicit sign for years before 1 BCE or after 9999 CE.
///
/// ```ignore
/// # use chrono::NaiveDate;
/// assert_eq!(format!("{:?}", NaiveDate::from_ymd_opt(-1, 1, 1).unwrap()), "-0001-01-01");
/// assert_eq!(format!("{:?}", NaiveDate::from_ymd_opt(10000, 12, 31).unwrap()), "+10000-12-31");
/// ```
impl fmt::Debug for NaiveDate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use core::fmt::Write;

        let year = self.year();
        let mdf = self.mdf();
        if (0..=9999).contains(&year) {
            write_hundreds(f, (year / 100) as u8)?;
            write_hundreds(f, (year % 100) as u8)?;
        } else {
            // ISO 8601 requires the explicit sign for out-of-range years
            write!(f, "{year:+05}")?;
        }

        f.write_char('-')?;
        write_hundreds(f, mdf.month() as u8)?;
        f.write_char('-')?;
        write_hundreds(f, mdf.day() as u8)
    }
}

/// The `Display` output of the naive date `d` is the same as
/// [`d.format("%Y-%m-%d")`](crate::extensions::chrono::format::strftime).
///
/// The string printed can be readily parsed via the `parse` method on `str`.
///
/// # Example
///
/// ```ignore
/// use chrono::NaiveDate;
///
/// assert_eq!(format!("{}", NaiveDate::from_ymd_opt(2015, 9, 5).unwrap()), "2015-09-05");
/// assert_eq!(format!("{}", NaiveDate::from_ymd_opt(0, 1, 1).unwrap()), "0000-01-01");
/// assert_eq!(format!("{}", NaiveDate::from_ymd_opt(9999, 12, 31).unwrap()), "9999-12-31");
/// ```
///
/// ISO 8601 requires an explicit sign for years before 1 BCE or after 9999 CE.
///
/// ```ignore
/// # use chrono::NaiveDate;
/// assert_eq!(format!("{}", NaiveDate::from_ymd_opt(-1, 1, 1).unwrap()), "-0001-01-01");
/// assert_eq!(format!("{}", NaiveDate::from_ymd_opt(10000, 12, 31).unwrap()), "+10000-12-31");
/// ```
impl fmt::Display for NaiveDate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Parsing a `str` into a `NaiveDate` uses the same format,
/// [`%Y-%m-%d`](crate::extensions::chrono::format::strftime), as in `Debug` and `Display`.
///
/// # Example
///
/// ```ignore
/// use chrono::NaiveDate;
///
/// let d = NaiveDate::from_ymd_opt(2015, 9, 18).unwrap();
/// assert_eq!("2015-09-18".parse::<NaiveDate>(), Ok(d));
///
/// let d = NaiveDate::from_ymd_opt(12345, 6, 7).unwrap();
/// assert_eq!("+12345-6-7".parse::<NaiveDate>(), Ok(d));
///
/// assert!("foo".parse::<NaiveDate>().is_err());
/// ```
impl str::FromStr for NaiveDate {
    type Err = ParseError;

    fn from_str(s: &str) -> ParseResult<NaiveDate> {
        const ITEMS: &[Item<'static>] = &[
            Item::Numeric(Numeric::Year, Pad::Zero),
            Item::Space(""),
            Item::Literal("-"),
            Item::Numeric(Numeric::Month, Pad::Zero),
            Item::Space(""),
            Item::Literal("-"),
            Item::Numeric(Numeric::Day, Pad::Zero),
            Item::Space(""),
        ];

        let mut parsed = Parsed::new();
        parse(&mut parsed, s, ITEMS.iter())?;
        parsed.to_naive_date()
    }
}

const fn cycle_to_yo(cycle: u32) -> (u32, u32) {
    let mut year_mod_400 = cycle / 365;
    let mut ordinal0 = cycle % 365;
    let delta = YEAR_DELTAS[year_mod_400 as usize] as u32;
    if ordinal0 < delta {
        year_mod_400 -= 1;
        ordinal0 += 365 - YEAR_DELTAS[year_mod_400 as usize] as u32;
    } else {
        ordinal0 -= delta;
    }
    (year_mod_400, ordinal0 + 1)
}

const fn yo_to_cycle(year_mod_400: u32, ordinal: u32) -> u32 {
    year_mod_400 * 365 + YEAR_DELTAS[year_mod_400 as usize] as u32 + ordinal - 1
}

const fn div_mod_floor(val: i32, div: i32) -> (i32, i32) {
    (val.div_euclid(div), val.rem_euclid(div))
}

/// MAX_YEAR is one year less than the type is capable of representing. Internally we may sometimes
/// use the headroom, notably to handle cases where the offset of a `DateTime` constructed with
/// `NaiveDate::MAX` pushes it beyond the valid, representable range.
pub(super) const MAX_YEAR: i32 = (i32::MAX >> 13) - 1;

/// MIN_YEAR is one year more than the type is capable of representing. Internally we may sometimes
/// use the headroom, notably to handle cases where the offset of a `DateTime` constructed with
/// `NaiveDate::MIN` pushes it beyond the valid, representable range.
pub(super) const MIN_YEAR: i32 = (i32::MIN >> 13) + 1;

const ORDINAL_MASK: i32 = 0b1_1111_1111_0000;

const LEAP_YEAR_MASK: i32 = 0b1000;

// OL: ordinal and leap year flag.
// With only these parts of the date an ordinal 366 in a common year would be encoded as
// `((366 << 1) | 1) << 3`, and in a leap year as `((366 << 1) | 0) << 3`, which is less.
// This allows for efficiently checking the ordinal exists depending on whether this is a leap year.
const OL_MASK: i32 = ORDINAL_MASK | LEAP_YEAR_MASK;
const MAX_OL: i32 = 366 << 4;

// Weekday of the last day in the preceding year.
// Allows for quick day of week calculation from the 1-based ordinal.
const WEEKDAY_FLAGS_MASK: i32 = 0b111;

const YEAR_FLAGS_MASK: i32 = LEAP_YEAR_MASK | WEEKDAY_FLAGS_MASK;

const YEAR_DELTAS: &[u8; 401] = &[
    0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8,
    8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14,
    15, 15, 15, 15, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19, 20, 20, 20, 20,
    21, 21, 21, 21, 22, 22, 22, 22, 23, 23, 23, 23, 24, 24, 24, 24, 25, 25, 25, // 100
    25, 25, 25, 25, 25, 26, 26, 26, 26, 27, 27, 27, 27, 28, 28, 28, 28, 29, 29, 29, 29, 30, 30, 30,
    30, 31, 31, 31, 31, 32, 32, 32, 32, 33, 33, 33, 33, 34, 34, 34, 34, 35, 35, 35, 35, 36, 36, 36,
    36, 37, 37, 37, 37, 38, 38, 38, 38, 39, 39, 39, 39, 40, 40, 40, 40, 41, 41, 41, 41, 42, 42, 42,
    42, 43, 43, 43, 43, 44, 44, 44, 44, 45, 45, 45, 45, 46, 46, 46, 46, 47, 47, 47, 47, 48, 48, 48,
    48, 49, 49, 49, // 200
    49, 49, 49, 49, 49, 50, 50, 50, 50, 51, 51, 51, 51, 52, 52, 52, 52, 53, 53, 53, 53, 54, 54, 54,
    54, 55, 55, 55, 55, 56, 56, 56, 56, 57, 57, 57, 57, 58, 58, 58, 58, 59, 59, 59, 59, 60, 60, 60,
    60, 61, 61, 61, 61, 62, 62, 62, 62, 63, 63, 63, 63, 64, 64, 64, 64, 65, 65, 65, 65, 66, 66, 66,
    66, 67, 67, 67, 67, 68, 68, 68, 68, 69, 69, 69, 69, 70, 70, 70, 70, 71, 71, 71, 71, 72, 72, 72,
    72, 73, 73, 73, // 300
    73, 73, 73, 73, 73, 74, 74, 74, 74, 75, 75, 75, 75, 76, 76, 76, 76, 77, 77, 77, 77, 78, 78, 78,
    78, 79, 79, 79, 79, 80, 80, 80, 80, 81, 81, 81, 81, 82, 82, 82, 82, 83, 83, 83, 83, 84, 84, 84,
    84, 85, 85, 85, 85, 86, 86, 86, 86, 87, 87, 87, 87, 88, 88, 88, 88, 89, 89, 89, 89, 90, 90, 90,
    90, 91, 91, 91, 91, 92, 92, 92, 92, 93, 93, 93, 93, 94, 94, 94, 94, 95, 95, 95, 95, 96, 96, 96,
    96, 97, 97, 97, 97, // 400+1
];

