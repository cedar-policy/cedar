// This is a part of Chrono.
// See README.md and LICENSE.txt for details.
//
// This file is `src/format/parsed.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples removed; code behind chrono's Cargo features (not enabled in Cedar) removed; code not
//   used by Cedar removed.

//! A collection of parsed date and time items.
//! They can be constructed incrementally while being checked for consistency.

use super::{ParseResult, IMPOSSIBLE, NOT_ENOUGH, OUT_OF_RANGE};
use crate::extensions::chrono::naive::{NaiveDate, NaiveDateTime, NaiveTime};
use crate::extensions::chrono::offset::{FixedOffset, MappedLocalTime, TimeZone};
use crate::extensions::chrono::{DateTime, Datelike, TimeDelta, Timelike, Weekday};

/// A type to hold parsed fields of date and time that can check all fields are consistent.
///
/// There are three classes of methods:
///
/// - `set_*` methods to set fields you have available. They do a basic range check, and if the
///   same field is set more than once it is checked for consistency.
///
/// - `to_*` methods try to make a concrete date and time value out of set fields.
///   They fully check that all fields are consistent and whether the date/datetime exists.
///
/// - Methods to inspect the parsed fields.
///
/// `Parsed` is used internally by all parsing functions in chrono. It is a public type so that it
/// can be used to write custom parsers that reuse the resolving algorithm, or to inspect the
/// results of a string parsed with chrono without converting it to concrete types.
///
/// # Resolving algorithm
///
/// Resolving date/time parts is littered with lots of corner cases, which is why common date/time
/// parsers do not implement it correctly.
///
/// Chrono provides a complete resolution algorithm that checks all fields for consistency via the
/// `Parsed` type.
///
/// As an easy example, consider RFC 2822. The [RFC 2822 date and time format] has a day of the week
/// part, which should be consistent with the other date parts. But a `strptime`-based parse would
/// happily accept inconsistent input:
///
/// ```python
/// >>> import time
/// >>> time.strptime('Wed, 31 Dec 2014 04:26:40 +0000',
///                   '%a, %d %b %Y %H:%M:%S +0000')
/// time.struct_time(tm_year=2014, tm_mon=12, tm_mday=31,
///                  tm_hour=4, tm_min=26, tm_sec=40,
///                  tm_wday=2, tm_yday=365, tm_isdst=-1)
/// >>> time.strptime('Thu, 31 Dec 2014 04:26:40 +0000',
///                   '%a, %d %b %Y %H:%M:%S +0000')
/// time.struct_time(tm_year=2014, tm_mon=12, tm_mday=31,
///                  tm_hour=4, tm_min=26, tm_sec=40,
///                  tm_wday=3, tm_yday=365, tm_isdst=-1)
/// ```
///
/// [RFC 2822 date and time format]: https://tools.ietf.org/html/rfc2822#section-3.3
#[allow(clippy::manual_non_exhaustive)]
#[derive(Clone, PartialEq, Eq, Debug, Default, Hash)]
pub(crate) struct Parsed {
    #[doc(hidden)]
    pub(super) year: Option<i32>,
    #[doc(hidden)]
    year_div_100: Option<i32>,
    #[doc(hidden)]
    year_mod_100: Option<i32>,
    #[doc(hidden)]
    isoyear: Option<i32>,
    #[doc(hidden)]
    isoyear_div_100: Option<i32>,
    #[doc(hidden)]
    isoyear_mod_100: Option<i32>,
    #[doc(hidden)]
    quarter: Option<u32>,
    #[doc(hidden)]
    pub(super) month: Option<u32>,
    #[doc(hidden)]
    week_from_sun: Option<u32>,
    #[doc(hidden)]
    week_from_mon: Option<u32>,
    #[doc(hidden)]
    isoweek: Option<u32>,
    #[doc(hidden)]
    pub(super) weekday: Option<Weekday>,
    #[doc(hidden)]
    ordinal: Option<u32>,
    #[doc(hidden)]
    pub(super) day: Option<u32>,
    #[doc(hidden)]
    pub(super) hour_div_12: Option<u32>,
    #[doc(hidden)]
    pub(super) hour_mod_12: Option<u32>,
    #[doc(hidden)]
    pub(super) minute: Option<u32>,
    #[doc(hidden)]
    pub(super) second: Option<u32>,
    #[doc(hidden)]
    pub(super) nanosecond: Option<u32>,
    #[doc(hidden)]
    pub(super) timestamp: Option<i64>,
    #[doc(hidden)]
    pub(super) offset: Option<i32>,
    #[doc(hidden)]
    _dummy: (),
}

/// Checks if `old` is either empty or has the same value as `new` (i.e. "consistent"),
/// and if it is empty, set `old` to `new` as well.
#[inline]
fn set_if_consistent<T: PartialEq>(old: &mut Option<T>, new: T) -> ParseResult<()> {
    match old {
        Some(old) if *old != new => Err(IMPOSSIBLE),
        _ => {
            *old = Some(new);
            Ok(())
        }
    }
}

impl Parsed {
    /// Returns the initial value of parsed parts.
    #[must_use]
    pub(crate) fn new() -> Parsed {
        Parsed::default()
    }

    /// Set the [`year`](Parsed::year) field to the given value.
    ///
    /// The value can be negative, unlike the [`year_div_100`](Parsed::year_div_100) and
    /// [`year_mod_100`](Parsed::year_mod_100) fields.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is outside the range of an `i32`.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_year(&mut self, value: i64) -> ParseResult<()> {
        set_if_consistent(
            &mut self.year,
            i32::try_from(value).map_err(|_| OUT_OF_RANGE)?,
        )
    }

    /// Set the [`year_div_100`](Parsed::year_div_100) field to the given value.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is negative or if it is greater than `i32::MAX`.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_year_div_100(&mut self, value: i64) -> ParseResult<()> {
        if !(0..=i32::MAX as i64).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.year_div_100, value as i32)
    }

    /// Set the [`year_mod_100`](Parsed::year_mod_100) field to the given value.
    ///
    /// When set it implies that the year is not negative.
    ///
    /// If this field is set while the [`year_div_100`](Parsed::year_div_100) field is missing (and
    /// the full [`year`](Parsed::year) field is also not set), it assumes a default value for the
    /// [`year_div_100`](Parsed::year_div_100) field.
    /// The default is 19 when `year_mod_100 >= 70` and 20 otherwise.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is negative or if it is greater than 99.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_year_mod_100(&mut self, value: i64) -> ParseResult<()> {
        if !(0..100).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.year_mod_100, value as i32)
    }

    /// Set the [`isoyear`](Parsed::isoyear) field, that is part of an [ISO 8601 week date], to the
    /// given value.
    ///
    /// The value can be negative, unlike the [`isoyear_div_100`](Parsed::isoyear_div_100) and
    /// [`isoyear_mod_100`](Parsed::isoyear_mod_100) fields.
    ///
    /// [ISO 8601 week date]: crate::extensions::chrono::NaiveDate#week-date
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is outside the range of an `i32`.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_isoyear(&mut self, value: i64) -> ParseResult<()> {
        set_if_consistent(
            &mut self.isoyear,
            i32::try_from(value).map_err(|_| OUT_OF_RANGE)?,
        )
    }

    /// Set the [`isoyear_mod_100`](Parsed::isoyear_mod_100) field, that is part of an
    /// [ISO 8601 week date], to the given value.
    ///
    /// When set it implies that the year is not negative.
    ///
    /// If this field is set while the [`isoyear_div_100`](Parsed::isoyear_div_100) field is missing
    /// (and the full [`isoyear`](Parsed::isoyear) field is also not set), it assumes a default
    /// value for the [`isoyear_div_100`](Parsed::isoyear_div_100) field.
    /// The default is 19 when `year_mod_100 >= 70` and 20 otherwise.
    ///
    /// [ISO 8601 week date]: crate::extensions::chrono::NaiveDate#week-date
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is negative or if it is greater than 99.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_isoyear_mod_100(&mut self, value: i64) -> ParseResult<()> {
        if !(0..100).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.isoyear_mod_100, value as i32)
    }

    /// Set the [`quarter`](Parsed::quarter) field to the given value.
    ///
    /// Quarter 1 starts in January.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is not in the range 1-4.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_quarter(&mut self, value: i64) -> ParseResult<()> {
        if !(1..=4).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.quarter, value as u32)
    }

    /// Set the [`month`](Parsed::month) field to the given value.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is not in the range 1-12.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_month(&mut self, value: i64) -> ParseResult<()> {
        if !(1..=12).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.month, value as u32)
    }

    /// Set the [`week_from_sun`](Parsed::week_from_sun) week number field to the given value.
    ///
    /// Week 1 starts at the first Sunday of January.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is not in the range 0-53.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_week_from_sun(&mut self, value: i64) -> ParseResult<()> {
        if !(0..=53).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.week_from_sun, value as u32)
    }

    /// Set the [`week_from_mon`](Parsed::week_from_mon) week number field to the given value.
    /// Set the 'week number starting with Monday' field to the given value.
    ///
    /// Week 1 starts at the first Monday of January.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is not in the range 0-53.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_week_from_mon(&mut self, value: i64) -> ParseResult<()> {
        if !(0..=53).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.week_from_mon, value as u32)
    }

    /// Set the [`isoweek`](Parsed::isoweek) field for an [ISO 8601 week date] to the given value.
    ///
    /// [ISO 8601 week date]: crate::extensions::chrono::NaiveDate#week-date
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is not in the range 1-53.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_isoweek(&mut self, value: i64) -> ParseResult<()> {
        if !(1..=53).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.isoweek, value as u32)
    }

    /// Set the [`weekday`](Parsed::weekday) field to the given value.
    ///
    /// # Errors
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_weekday(&mut self, value: Weekday) -> ParseResult<()> {
        set_if_consistent(&mut self.weekday, value)
    }

    /// Set the [`ordinal`](Parsed::ordinal) (day of the year) field to the given value.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is not in the range 1-366.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_ordinal(&mut self, value: i64) -> ParseResult<()> {
        if !(1..=366).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.ordinal, value as u32)
    }

    /// Set the [`day`](Parsed::day) of the month field to the given value.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is not in the range 1-31.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_day(&mut self, value: i64) -> ParseResult<()> {
        if !(1..=31).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.day, value as u32)
    }

    /// Set the [`hour_div_12`](Parsed::hour_div_12) am/pm field to the given value.
    ///
    /// `false` indicates AM and `true` indicates PM.
    ///
    /// # Errors
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_ampm(&mut self, value: bool) -> ParseResult<()> {
        set_if_consistent(&mut self.hour_div_12, value as u32)
    }

    /// Set the [`hour_mod_12`](Parsed::hour_mod_12) field, for the hour number in 12-hour clocks,
    /// to the given value.
    ///
    /// Value must be in the canonical range of 1-12.
    /// It will internally be stored as 0-11 (`value % 12`).
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is not in the range 1-12.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_hour12(&mut self, mut value: i64) -> ParseResult<()> {
        if !(1..=12).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        if value == 12 {
            value = 0
        }
        set_if_consistent(&mut self.hour_mod_12, value as u32)
    }

    /// Set the [`hour_div_12`](Parsed::hour_div_12) and [`hour_mod_12`](Parsed::hour_mod_12)
    /// fields to the given value for a 24-hour clock.
    ///
    /// # Errors
    ///
    /// May return `OUT_OF_RANGE` if `value` is not in the range 0-23.
    /// Currently only checks the value is not out of range for a `u32`.
    ///
    /// Returns `IMPOSSIBLE` one of the fields was already set to a different value.
    #[inline]
    pub(super) fn set_hour(&mut self, value: i64) -> ParseResult<()> {
        let (hour_div_12, hour_mod_12) = match value {
            hour @ 0..=11 => (0, hour as u32),
            hour @ 12..=23 => (1, hour as u32 - 12),
            _ => return Err(OUT_OF_RANGE),
        };
        set_if_consistent(&mut self.hour_div_12, hour_div_12)?;
        set_if_consistent(&mut self.hour_mod_12, hour_mod_12)
    }

    /// Set the [`minute`](Parsed::minute) field to the given value.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is not in the range 0-59.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_minute(&mut self, value: i64) -> ParseResult<()> {
        if !(0..=59).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.minute, value as u32)
    }

    /// Set the [`second`](Parsed::second) field to the given value.
    ///
    /// The value can be 60 in the case of a leap second.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is not in the range 0-60.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_second(&mut self, value: i64) -> ParseResult<()> {
        if !(0..=60).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.second, value as u32)
    }

    /// Set the [`nanosecond`](Parsed::nanosecond) field to the given value.
    ///
    /// This is the number of nanoseconds since the whole second.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is not in the range 0-999,999,999.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_nanosecond(&mut self, value: i64) -> ParseResult<()> {
        if !(0..=999_999_999).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.nanosecond, value as u32)
    }

    /// Set the [`timestamp`](Parsed::timestamp) field to the given value.
    ///
    /// A Unix timestamp is defined as the number of non-leap seconds since midnight UTC on
    /// January 1, 1970.
    ///
    /// # Errors
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_timestamp(&mut self, value: i64) -> ParseResult<()> {
        set_if_consistent(&mut self.timestamp, value)
    }

    /// Set the [`offset`](Parsed::offset) field to the given value.
    ///
    /// The offset is in seconds from local time to UTC.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_RANGE` if `value` is outside the range of an `i32`.
    ///
    /// Returns `IMPOSSIBLE` if this field was already set to a different value.
    #[inline]
    pub(super) fn set_offset(&mut self, value: i64) -> ParseResult<()> {
        set_if_consistent(
            &mut self.offset,
            i32::try_from(value).map_err(|_| OUT_OF_RANGE)?,
        )
    }

    /// Returns a parsed naive date out of given fields.
    ///
    /// This method is able to determine the date from given subset of fields:
    ///
    /// - Year, month, day.
    /// - Year, day of the year (ordinal).
    /// - Year, week number counted from Sunday or Monday, day of the week.
    /// - ISO week date.
    ///
    /// Gregorian year and ISO week date year can have their century number (`*_div_100`) omitted,
    /// the two-digit year is used to guess the century number then.
    ///
    /// It checks all given date fields are consistent with each other.
    ///
    /// # Errors
    ///
    /// This method returns:
    /// - `IMPOSSIBLE` if any of the date fields conflict.
    /// - `NOT_ENOUGH` if there are not enough fields set in `Parsed` for a complete date.
    /// - `OUT_OF_RANGE`
    ///   - if any of the date fields of `Parsed` are set to a value beyond their acceptable range.
    ///   - if the value would be outside the range of a [`NaiveDate`].
    ///   - if the date does not exist.
    pub(crate) fn to_naive_date(&self) -> ParseResult<NaiveDate> {
        fn resolve_year(
            y: Option<i32>,
            q: Option<i32>,
            r: Option<i32>,
        ) -> ParseResult<Option<i32>> {
            match (y, q, r) {
                // if there is no further information, simply return the given full year.
                // this is a common case, so let's avoid division here.
                (y, None, None) => Ok(y),

                // if there is a full year *and* also quotient and/or modulo,
                // check if present quotient and/or modulo is consistent to the full year.
                // since the presence of those fields means a positive full year,
                // we should filter a negative full year first.
                (Some(y), q, r @ Some(0..=99)) | (Some(y), q, r @ None) => {
                    if y < 0 {
                        return Err(IMPOSSIBLE);
                    }
                    let q_ = y / 100;
                    let r_ = y % 100;
                    if q.unwrap_or(q_) == q_ && r.unwrap_or(r_) == r_ {
                        Ok(Some(y))
                    } else {
                        Err(IMPOSSIBLE)
                    }
                }

                // the full year is missing but we have quotient and modulo.
                // reconstruct the full year. make sure that the result is always positive.
                (None, Some(q), Some(r @ 0..=99)) => {
                    if q < 0 {
                        return Err(IMPOSSIBLE);
                    }
                    let y = q.checked_mul(100).and_then(|v| v.checked_add(r));
                    Ok(Some(y.ok_or(OUT_OF_RANGE)?))
                }

                // we only have modulo. try to interpret a modulo as a conventional two-digit year.
                // note: we are affected by Rust issue #18060. avoid multiple range patterns.
                (None, None, Some(r @ 0..=99)) => Ok(Some(r + if r < 70 { 2000 } else { 1900 })),

                // otherwise it is an out-of-bound or insufficient condition.
                (None, Some(_), None) => Err(NOT_ENOUGH),
                (_, _, Some(_)) => Err(OUT_OF_RANGE),
            }
        }

        let given_year = resolve_year(self.year, self.year_div_100, self.year_mod_100)?;
        let given_isoyear = resolve_year(self.isoyear, self.isoyear_div_100, self.isoyear_mod_100)?;

        // verify the normal year-month-day date.
        let verify_ymd = |date: NaiveDate| {
            let year = date.year();
            let (year_div_100, year_mod_100) = if year >= 0 {
                (Some(year / 100), Some(year % 100))
            } else {
                (None, None) // they should be empty to be consistent
            };
            let month = date.month();
            let day = date.day();
            self.year.unwrap_or(year) == year
                && self.year_div_100.or(year_div_100) == year_div_100
                && self.year_mod_100.or(year_mod_100) == year_mod_100
                && self.month.unwrap_or(month) == month
                && self.day.unwrap_or(day) == day
        };

        // verify the ISO week date.
        let verify_isoweekdate = |date: NaiveDate| {
            let week = date.iso_week();
            let isoyear = week.year();
            let isoweek = week.week();
            let weekday = date.weekday();
            let (isoyear_div_100, isoyear_mod_100) = if isoyear >= 0 {
                (Some(isoyear / 100), Some(isoyear % 100))
            } else {
                (None, None) // they should be empty to be consistent
            };
            self.isoyear.unwrap_or(isoyear) == isoyear
                && self.isoyear_div_100.or(isoyear_div_100) == isoyear_div_100
                && self.isoyear_mod_100.or(isoyear_mod_100) == isoyear_mod_100
                && self.isoweek.unwrap_or(isoweek) == isoweek
                && self.weekday.unwrap_or(weekday) == weekday
        };

        // verify the ordinal and other (non-ISO) week dates.
        let verify_ordinal = |date: NaiveDate| {
            let ordinal = date.ordinal();
            let week_from_sun = date.weeks_from(Weekday::Sun);
            let week_from_mon = date.weeks_from(Weekday::Mon);
            self.ordinal.unwrap_or(ordinal) == ordinal
                && self.week_from_sun.map_or(week_from_sun, |v| v as i32) == week_from_sun
                && self.week_from_mon.map_or(week_from_mon, |v| v as i32) == week_from_mon
        };

        // test several possibilities.
        // tries to construct a full `NaiveDate` as much as possible, then verifies that
        // it is consistent with other given fields.
        let (verified, parsed_date) = match (given_year, given_isoyear, self) {
            (
                Some(year),
                _,
                &Parsed {
                    month: Some(month),
                    day: Some(day),
                    ..
                },
            ) => {
                // year, month, day
                let date = NaiveDate::from_ymd_opt(year, month, day).ok_or(OUT_OF_RANGE)?;
                (verify_isoweekdate(date) && verify_ordinal(date), date)
            }

            (
                Some(year),
                _,
                &Parsed {
                    ordinal: Some(ordinal),
                    ..
                },
            ) => {
                // year, day of the year
                let date = NaiveDate::from_yo_opt(year, ordinal).ok_or(OUT_OF_RANGE)?;
                (
                    verify_ymd(date) && verify_isoweekdate(date) && verify_ordinal(date),
                    date,
                )
            }

            (
                Some(year),
                _,
                &Parsed {
                    week_from_sun: Some(week),
                    weekday: Some(weekday),
                    ..
                },
            ) => {
                // year, week (starting at 1st Sunday), day of the week
                let date = resolve_week_date(year, week, weekday, Weekday::Sun)?;
                (
                    verify_ymd(date) && verify_isoweekdate(date) && verify_ordinal(date),
                    date,
                )
            }

            (
                Some(year),
                _,
                &Parsed {
                    week_from_mon: Some(week),
                    weekday: Some(weekday),
                    ..
                },
            ) => {
                // year, week (starting at 1st Monday), day of the week
                let date = resolve_week_date(year, week, weekday, Weekday::Mon)?;
                (
                    verify_ymd(date) && verify_isoweekdate(date) && verify_ordinal(date),
                    date,
                )
            }

            (
                _,
                Some(isoyear),
                &Parsed {
                    isoweek: Some(isoweek),
                    weekday: Some(weekday),
                    ..
                },
            ) => {
                // ISO year, week, day of the week
                let date = NaiveDate::from_isoywd_opt(isoyear, isoweek, weekday);
                let date = date.ok_or(OUT_OF_RANGE)?;
                (verify_ymd(date) && verify_ordinal(date), date)
            }

            (_, _, _) => return Err(NOT_ENOUGH),
        };

        if !verified {
            return Err(IMPOSSIBLE);
        } else if let Some(parsed) = self.quarter {
            if parsed != parsed_date.quarter() {
                return Err(IMPOSSIBLE);
            }
        }

        Ok(parsed_date)
    }

    /// Returns a parsed naive time out of given fields.
    ///
    /// This method is able to determine the time from given subset of fields:
    ///
    /// - Hour, minute. (second and nanosecond assumed to be 0)
    /// - Hour, minute, second. (nanosecond assumed to be 0)
    /// - Hour, minute, second, nanosecond.
    ///
    /// It is able to handle leap seconds when given second is 60.
    ///
    /// # Errors
    ///
    /// This method returns:
    /// - `OUT_OF_RANGE` if any of the time fields of `Parsed` are set to a value beyond
    ///   their acceptable range.
    /// - `NOT_ENOUGH` if an hour field is missing, if AM/PM is missing in a 12-hour clock,
    ///   if minutes are missing, or if seconds are missing while the nanosecond field is present.
    pub(crate) fn to_naive_time(&self) -> ParseResult<NaiveTime> {
        let hour_div_12 = match self.hour_div_12 {
            Some(v @ 0..=1) => v,
            Some(_) => return Err(OUT_OF_RANGE),
            None => return Err(NOT_ENOUGH),
        };
        let hour_mod_12 = match self.hour_mod_12 {
            Some(v @ 0..=11) => v,
            Some(_) => return Err(OUT_OF_RANGE),
            None => return Err(NOT_ENOUGH),
        };
        let hour = hour_div_12 * 12 + hour_mod_12;

        let minute = match self.minute {
            Some(v @ 0..=59) => v,
            Some(_) => return Err(OUT_OF_RANGE),
            None => return Err(NOT_ENOUGH),
        };

        // we allow omitting seconds or nanoseconds, but they should be in the range.
        let (second, mut nano) = match self.second.unwrap_or(0) {
            v @ 0..=59 => (v, 0),
            60 => (59, 1_000_000_000),
            _ => return Err(OUT_OF_RANGE),
        };
        nano += match self.nanosecond {
            Some(v @ 0..=999_999_999) if self.second.is_some() => v,
            Some(0..=999_999_999) => return Err(NOT_ENOUGH), // second is missing
            Some(_) => return Err(OUT_OF_RANGE),
            None => 0,
        };

        NaiveTime::from_hms_nano_opt(hour, minute, second, nano).ok_or(OUT_OF_RANGE)
    }

    /// Returns a parsed naive date and time out of given fields, except for the offset field.
    ///
    /// The offset is assumed to have a given value. It is not compared against the offset field set
    /// in the `Parsed` type, so it is allowed to be inconsistent.
    ///
    /// This method is able to determine the combined date and time from date and time fields or
    /// from a single timestamp field. It checks all fields are consistent with each other.
    ///
    /// # Errors
    ///
    /// This method returns:
    /// - `IMPOSSIBLE`  if any of the date fields conflict, or if a timestamp conflicts with any of
    ///   the other fields.
    /// - `NOT_ENOUGH` if there are not enough fields set in `Parsed` for a complete datetime.
    /// - `OUT_OF_RANGE`
    ///   - if any of the date or time fields of `Parsed` are set to a value beyond their acceptable
    ///     range.
    ///   - if the value would be outside the range of a [`NaiveDateTime`].
    ///   - if the date does not exist.
    pub(crate) fn to_naive_datetime_with_offset(&self, offset: i32) -> ParseResult<NaiveDateTime> {
        let date = self.to_naive_date();
        let time = self.to_naive_time();
        if let (Ok(date), Ok(time)) = (date, time) {
            let datetime = date.and_time(time);

            // verify the timestamp field if any
            // the following is safe, `timestamp` is very limited in range
            let timestamp = datetime.and_utc().timestamp() - i64::from(offset);
            if let Some(given_timestamp) = self.timestamp {
                // if `datetime` represents a leap second, it might be off by one second.
                if given_timestamp != timestamp
                    && !(datetime.nanosecond() >= 1_000_000_000 && given_timestamp == timestamp + 1)
                {
                    return Err(IMPOSSIBLE);
                }
            }

            Ok(datetime)
        } else if let Some(timestamp) = self.timestamp {
            use super::ParseError as PE;
            use super::ParseErrorKind::{Impossible, OutOfRange};

            // if date and time is problematic already, there is no point proceeding.
            // we at least try to give a correct error though.
            match (date, time) {
                (Err(PE(OutOfRange)), _) | (_, Err(PE(OutOfRange))) => return Err(OUT_OF_RANGE),
                (Err(PE(Impossible)), _) | (_, Err(PE(Impossible))) => return Err(IMPOSSIBLE),
                (_, _) => {} // one of them is insufficient
            }

            // reconstruct date and time fields from timestamp
            let ts = timestamp
                .checked_add(i64::from(offset))
                .ok_or(OUT_OF_RANGE)?;
            let mut datetime = DateTime::from_timestamp_secs(ts)
                .ok_or(OUT_OF_RANGE)?
                .naive_utc();

            // fill year, ordinal, hour, minute and second fields from timestamp.
            // if existing fields are consistent, this will allow the full date/time reconstruction.
            let mut parsed = self.clone();
            if parsed.second == Some(60) {
                // `datetime.second()` cannot be 60, so this is the only case for a leap second.
                match datetime.second() {
                    // it's okay, just do not try to overwrite the existing field.
                    59 => {}
                    // `datetime` is known to be off by one second.
                    0 => {
                        datetime -= TimeDelta::try_seconds(1).unwrap();
                    }
                    // otherwise it is impossible.
                    _ => return Err(IMPOSSIBLE),
                }
            // ...and we have the correct candidates for other fields.
            } else {
                parsed.set_second(i64::from(datetime.second()))?;
            }
            parsed.set_year(i64::from(datetime.year()))?;
            parsed.set_ordinal(i64::from(datetime.ordinal()))?; // more efficient than ymd
            parsed.set_hour(i64::from(datetime.hour()))?;
            parsed.set_minute(i64::from(datetime.minute()))?;

            // validate other fields (e.g. week) and return
            let date = parsed.to_naive_date()?;
            let time = parsed.to_naive_time()?;
            Ok(date.and_time(time))
        } else {
            // reproduce the previous error(s)
            date?;
            time?;
            unreachable!()
        }
    }

    /// Returns a parsed timezone-aware date and time out of given fields.
    ///
    /// This method is able to determine the combined date and time from date, time and offset
    /// fields, and/or from a single timestamp field. It checks all fields are consistent with each
    /// other.
    ///
    /// # Errors
    ///
    /// This method returns:
    /// - `IMPOSSIBLE`  if any of the date fields conflict, or if a timestamp conflicts with any of
    ///   the other fields.
    /// - `NOT_ENOUGH` if there are not enough fields set in `Parsed` for a complete datetime
    ///   including offset from UTC.
    /// - `OUT_OF_RANGE`
    ///   - if any of the fields of `Parsed` are set to a value beyond their acceptable
    ///     range.
    ///   - if the value would be outside the range of a [`NaiveDateTime`] or [`FixedOffset`].
    ///   - if the date does not exist.
    pub(crate) fn to_datetime(&self) -> ParseResult<DateTime<FixedOffset>> {
        // If there is no explicit offset, consider a timestamp value as indication of a UTC value.
        let offset = match (self.offset, self.timestamp) {
            (Some(off), _) => off,
            (None, Some(_)) => 0, // UNIX timestamp may assume 0 offset
            (None, None) => return Err(NOT_ENOUGH),
        };
        let datetime = self.to_naive_datetime_with_offset(offset)?;
        let offset = FixedOffset::east_opt(offset).ok_or(OUT_OF_RANGE)?;

        match offset.from_local_datetime(&datetime) {
            MappedLocalTime::None => Err(IMPOSSIBLE),
            MappedLocalTime::Single(t) => Ok(t),
            MappedLocalTime::Ambiguous(..) => Err(NOT_ENOUGH),
        }
    }
}

/// Create a `NaiveDate` when given a year, week, weekday, and the definition at which day of the
/// week a week starts.
///
/// Returns `IMPOSSIBLE` if `week` is `0` or `53` and the `weekday` falls outside the year.
fn resolve_week_date(
    year: i32,
    week: u32,
    weekday: Weekday,
    week_start_day: Weekday,
) -> ParseResult<NaiveDate> {
    if week > 53 {
        return Err(OUT_OF_RANGE);
    }

    let first_day_of_year = NaiveDate::from_yo_opt(year, 1).ok_or(OUT_OF_RANGE)?;
    // Ordinal of the day at which week 1 starts.
    let first_week_start = 1 + week_start_day.days_since(first_day_of_year.weekday()) as i32;
    // Number of the `weekday`, which is 0 for the first day of the week.
    let weekday = weekday.days_since(week_start_day) as i32;
    let ordinal = first_week_start + (week as i32 - 1) * 7 + weekday;
    if ordinal <= 0 {
        return Err(IMPOSSIBLE);
    }
    first_day_of_year
        .with_ordinal(ordinal as u32)
        .ok_or(IMPOSSIBLE)
}

#[cfg(test)]
mod tests {
    use super::super::{IMPOSSIBLE, NOT_ENOUGH, OUT_OF_RANGE};
    use super::Parsed;
    use crate::extensions::chrono::naive::{NaiveDate, NaiveTime};

    #[test]
    fn test_parsed_set_fields() {
        // year*, isoyear*
        let mut p = Parsed::new();
        assert_eq!(p.set_year(1987), Ok(()));
        assert_eq!(p.set_year(1986), Err(IMPOSSIBLE));
        assert_eq!(p.set_year(1988), Err(IMPOSSIBLE));
        assert_eq!(p.set_year(1987), Ok(()));
        assert_eq!(p.set_year_div_100(20), Ok(())); // independent to `year`
        assert_eq!(p.set_year_div_100(21), Err(IMPOSSIBLE));
        assert_eq!(p.set_year_div_100(19), Err(IMPOSSIBLE));
        assert_eq!(p.set_year_mod_100(37), Ok(())); // ditto
        assert_eq!(p.set_year_mod_100(38), Err(IMPOSSIBLE));
        assert_eq!(p.set_year_mod_100(36), Err(IMPOSSIBLE));

        let mut p = Parsed::new();
        assert_eq!(p.set_year(0), Ok(()));
        assert_eq!(p.set_year_div_100(0), Ok(()));
        assert_eq!(p.set_year_mod_100(0), Ok(()));

        let mut p = Parsed::new();
        assert_eq!(p.set_year_div_100(-1), Err(OUT_OF_RANGE));
        assert_eq!(p.set_year_mod_100(-1), Err(OUT_OF_RANGE));
        assert_eq!(p.set_year(-1), Ok(()));
        assert_eq!(p.set_year(-2), Err(IMPOSSIBLE));
        assert_eq!(p.set_year(0), Err(IMPOSSIBLE));

        let mut p = Parsed::new();
        assert_eq!(p.set_year_div_100(0x1_0000_0008), Err(OUT_OF_RANGE));
        assert_eq!(p.set_year_div_100(8), Ok(()));
        assert_eq!(p.set_year_div_100(0x1_0000_0008), Err(OUT_OF_RANGE));

        // month, week*, isoweek, ordinal, day, minute, second, nanosecond, offset
        let mut p = Parsed::new();
        assert_eq!(p.set_month(7), Ok(()));
        assert_eq!(p.set_month(1), Err(IMPOSSIBLE));
        assert_eq!(p.set_month(6), Err(IMPOSSIBLE));
        assert_eq!(p.set_month(8), Err(IMPOSSIBLE));
        assert_eq!(p.set_month(12), Err(IMPOSSIBLE));

        let mut p = Parsed::new();
        assert_eq!(p.set_month(8), Ok(()));
        assert_eq!(p.set_month(0x1_0000_0008), Err(OUT_OF_RANGE));

        // hour
        let mut p = Parsed::new();
        assert_eq!(p.set_hour(12), Ok(()));
        assert_eq!(p.set_hour(11), Err(IMPOSSIBLE));
        assert_eq!(p.set_hour(13), Err(IMPOSSIBLE));
        assert_eq!(p.set_hour(12), Ok(()));
        assert_eq!(p.set_ampm(false), Err(IMPOSSIBLE));
        assert_eq!(p.set_ampm(true), Ok(()));
        assert_eq!(p.set_hour12(12), Ok(()));
        assert_eq!(p.set_hour12(0), Err(OUT_OF_RANGE)); // requires canonical representation
        assert_eq!(p.set_hour12(1), Err(IMPOSSIBLE));
        assert_eq!(p.set_hour12(11), Err(IMPOSSIBLE));

        let mut p = Parsed::new();
        assert_eq!(p.set_ampm(true), Ok(()));
        assert_eq!(p.set_hour12(7), Ok(()));
        assert_eq!(p.set_hour(7), Err(IMPOSSIBLE));
        assert_eq!(p.set_hour(18), Err(IMPOSSIBLE));
        assert_eq!(p.set_hour(19), Ok(()));

        // timestamp
        let mut p = Parsed::new();
        assert_eq!(p.set_timestamp(1_234_567_890), Ok(()));
        assert_eq!(p.set_timestamp(1_234_567_889), Err(IMPOSSIBLE));
        assert_eq!(p.set_timestamp(1_234_567_891), Err(IMPOSSIBLE));
    }

    #[test]
    fn test_parsed_to_naive_time() {
        macro_rules! parse {
            ($($k:ident: $v:expr),*) => (
                Parsed { $($k: Some($v),)* ..Parsed::new() }.to_naive_time()
            )
        }

        let hms = |h, m, s| Ok(NaiveTime::from_hms_opt(h, m, s).unwrap());
        let hmsn = |h, m, s, n| Ok(NaiveTime::from_hms_nano_opt(h, m, s, n).unwrap());

        // omission of fields
        assert_eq!(parse!(), Err(NOT_ENOUGH));
        assert_eq!(parse!(hour_div_12: 0), Err(NOT_ENOUGH));
        assert_eq!(parse!(hour_div_12: 0, hour_mod_12: 1), Err(NOT_ENOUGH));
        assert_eq!(
            parse!(hour_div_12: 0, hour_mod_12: 1, minute: 23),
            hms(1, 23, 0)
        );
        assert_eq!(
            parse!(hour_div_12: 0, hour_mod_12: 1, minute: 23, second: 45),
            hms(1, 23, 45)
        );
        assert_eq!(
            parse!(hour_div_12: 0, hour_mod_12: 1, minute: 23, second: 45,
                          nanosecond: 678_901_234),
            hmsn(1, 23, 45, 678_901_234)
        );
        assert_eq!(
            parse!(hour_div_12: 1, hour_mod_12: 11, minute: 45, second: 6),
            hms(23, 45, 6)
        );
        assert_eq!(parse!(hour_mod_12: 1, minute: 23), Err(NOT_ENOUGH));
        assert_eq!(
            parse!(hour_div_12: 0, hour_mod_12: 1, minute: 23, nanosecond: 456_789_012),
            Err(NOT_ENOUGH)
        );

        // out-of-range conditions
        assert_eq!(
            parse!(hour_div_12: 2, hour_mod_12: 0, minute: 0),
            Err(OUT_OF_RANGE)
        );
        assert_eq!(
            parse!(hour_div_12: 1, hour_mod_12: 12, minute: 0),
            Err(OUT_OF_RANGE)
        );
        assert_eq!(
            parse!(hour_div_12: 0, hour_mod_12: 1, minute: 60),
            Err(OUT_OF_RANGE)
        );
        assert_eq!(
            parse!(hour_div_12: 0, hour_mod_12: 1, minute: 23, second: 61),
            Err(OUT_OF_RANGE)
        );
        assert_eq!(
            parse!(hour_div_12: 0, hour_mod_12: 1, minute: 23, second: 34,
                          nanosecond: 1_000_000_000),
            Err(OUT_OF_RANGE)
        );

        // leap seconds
        assert_eq!(
            parse!(hour_div_12: 0, hour_mod_12: 1, minute: 23, second: 60),
            hmsn(1, 23, 59, 1_000_000_000)
        );
        assert_eq!(
            parse!(hour_div_12: 0, hour_mod_12: 1, minute: 23, second: 60,
                          nanosecond: 999_999_999),
            hmsn(1, 23, 59, 1_999_999_999)
        );
    }

    #[test]
    fn issue_551() {
        use crate::extensions::chrono::Weekday;
        let mut parsed = Parsed::new();

        parsed.year = Some(2002);
        parsed.week_from_mon = Some(22);
        parsed.weekday = Some(Weekday::Mon);
        assert_eq!(
            NaiveDate::from_ymd_opt(2002, 6, 3).unwrap(),
            parsed.to_naive_date().unwrap()
        );

        parsed.year = Some(2001);
        assert_eq!(
            NaiveDate::from_ymd_opt(2001, 5, 28).unwrap(),
            parsed.to_naive_date().unwrap()
        );
    }
}
