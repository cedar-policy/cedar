// This is a part of Chrono.
// See README.md and LICENSE.txt for details.
//
// This file is `src/naive/isoweek.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples removed; code behind chrono's Cargo features (not enabled in Cedar) removed; code not
//   used by Cedar removed.

//! ISO 8601 week.

use core::fmt;

use super::internals::YearFlags;

/// ISO 8601 week.
///
/// This type, combined with [`Weekday`](crate::extensions::chrono::weekday::Weekday),
/// constitutes the ISO 8601 [week date](crate::extensions::chrono::NaiveDate#week-date).
/// One can retrieve this type from the existing [`Datelike`](crate::extensions::chrono::traits::Datelike) types
/// via the [`Datelike::iso_week`](crate::extensions::chrono::traits::Datelike::iso_week) method.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash)]
pub(crate) struct IsoWeek {
    // Note that this allows for larger year range than `NaiveDate`.
    // This is crucial because we have an edge case for the first and last week supported,
    // which year number might not match the calendar year number.
    ywf: i32, // (year << 10) | (week << 4) | flag
}

impl IsoWeek {
    /// Returns the corresponding `IsoWeek` from the year and the `Of` internal value.
    //
    // Internal use only. We don't expose the public constructor for `IsoWeek` for now
    // because the year range for the week date and the calendar date do not match, and
    // it is confusing to have a date that is out of range in one and not in another.
    // Currently we sidestep this issue by making `IsoWeek` fully dependent of `Datelike`.
    pub(super) fn from_yof(year: i32, ordinal: u32, year_flags: YearFlags) -> Self {
        let rawweek = (ordinal + year_flags.isoweek_delta()) / 7;
        let (year, week) = if rawweek < 1 {
            // previous year
            let prevlastweek = YearFlags::from_year(year - 1).nisoweeks();
            (year - 1, prevlastweek)
        } else {
            let lastweek = year_flags.nisoweeks();
            if rawweek > lastweek {
                // next year
                (year + 1, 1)
            } else {
                (year, rawweek)
            }
        };
        let flags = YearFlags::from_year(year);
        IsoWeek {
            ywf: (year << 10) | (week << 4) as i32 | i32::from(flags.0),
        }
    }

    /// Returns the year number for this ISO week.
    #[inline]
    pub(crate) const fn year(&self) -> i32 {
        self.ywf >> 10
    }

    /// Returns the ISO week number starting from 1.
    ///
    /// The return value ranges from 1 to 53. (The last week of year differs by years.)
    #[inline]
    pub(crate) const fn week(&self) -> u32 {
        ((self.ywf >> 4) & 0x3f) as u32
    }
}

/// The `Debug` output of the ISO week `w` uses the format
/// `%G-W%V`.
impl fmt::Debug for IsoWeek {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let year = self.year();
        let week = self.week();
        if (0..=9999).contains(&year) {
            write!(f, "{year:04}-W{week:02}")
        } else {
            // ISO 8601 requires the explicit sign for out-of-range years
            write!(f, "{year:+05}-W{week:02}")
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::extensions::chrono::naive::date::NaiveDate;
    use crate::extensions::chrono::Datelike;

    #[test]
    fn test_iso_week_equivalence_for_first_week() {
        let monday = NaiveDate::from_ymd_opt(2024, 12, 30).unwrap();
        let friday = NaiveDate::from_ymd_opt(2025, 1, 3).unwrap();

        assert_eq!(monday.iso_week(), friday.iso_week());
    }

    #[test]
    fn test_iso_week_equivalence_for_last_week() {
        let monday = NaiveDate::from_ymd_opt(2026, 12, 28).unwrap();
        let friday = NaiveDate::from_ymd_opt(2027, 1, 1).unwrap();

        assert_eq!(monday.iso_week(), friday.iso_week());
    }

    #[test]
    fn test_iso_week_ordering_for_first_week() {
        let monday = NaiveDate::from_ymd_opt(2024, 12, 30).unwrap();
        let friday = NaiveDate::from_ymd_opt(2025, 1, 3).unwrap();

        assert!(monday.iso_week() >= friday.iso_week());
        assert!(monday.iso_week() <= friday.iso_week());
    }

    #[test]
    fn test_iso_week_ordering_for_last_week() {
        let monday = NaiveDate::from_ymd_opt(2026, 12, 28).unwrap();
        let friday = NaiveDate::from_ymd_opt(2027, 1, 1).unwrap();

        assert!(monday.iso_week() >= friday.iso_week());
        assert!(monday.iso_week() <= friday.iso_week());
    }
}
