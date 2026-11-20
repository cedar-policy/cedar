// This file is `src/traits.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples removed; other changes marked with `Cedar:` comments; code not used by Cedar removed.
use crate::extensions::chrono::{IsoWeek, Weekday};

/// The common set of methods for date component.
///
/// Methods such as [`year`], [`month`], [`day`] and [`weekday`] can be used to get basic
/// information about the date.
///
/// The `with_*` methods can change the date.
///
/// [`year`]: Datelike::year
/// [`month`]: Datelike::month
/// [`day`]: Datelike::day
/// [`weekday`]: Datelike::weekday
pub(super) trait Datelike: Sized {
    /// Returns the year number in the [calendar date](crate::extensions::chrono::NaiveDate#calendar-date).
    fn year(&self) -> i32;

    /// Returns the quarter number starting from 1.
    ///
    /// The return value ranges from 1 to 4.
    #[inline]
    fn quarter(&self) -> u32 {
        (self.month() - 1).div_euclid(3) + 1
    }

    /// Returns the month number starting from 1.
    ///
    /// The return value ranges from 1 to 12.
    fn month(&self) -> u32;

    /// Returns the day of month starting from 1.
    ///
    /// The return value ranges from 1 to 31. (The last day of month differs by months.)
    fn day(&self) -> u32;

    /// Returns the day of year starting from 1.
    ///
    /// The return value ranges from 1 to 366. (The last day of year differs by years.)
    fn ordinal(&self) -> u32;

    /// Returns the day of week.
    fn weekday(&self) -> Weekday;

    /// Returns the ISO week.
    fn iso_week(&self) -> IsoWeek;

    /// Makes a new value with the day of year (starting from 1) changed.
    ///
    /// # Errors
    ///
    /// Returns `None` when:
    ///
    /// - The resulting date does not exist (`with_ordinal(366)` in a non-leap year).
    /// - In case of [`DateTime<Tz>`] if the resulting date and time fall within a timezone
    ///   transition such as from DST to standard time.
    /// - The value for `ordinal` is out of range.
    ///
    /// [`DateTime<Tz>`]: crate::extensions::chrono::DateTime
    fn with_ordinal(&self, ordinal: u32) -> Option<Self>;
}

/// The common set of methods for time component.
pub(super) trait Timelike: Sized {
    /// Returns the hour number from 0 to 23.
    fn hour(&self) -> u32;

    /// Returns the minute number from 0 to 59.
    fn minute(&self) -> u32;

    /// Returns the second number from 0 to 59.
    fn second(&self) -> u32;

    /// Returns the number of nanoseconds since the whole non-leap second.
    /// The range from 1,000,000,000 to 1,999,999,999 represents
    /// the [leap second](crate::extensions::chrono::NaiveTime#leap-second-handling).
    fn nanosecond(&self) -> u32;
}
