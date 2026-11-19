// This file is `src/weekday.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples marked `ignore`; other changes marked with `Cedar:` comments; code behind chrono's
//   Cargo features (not enabled in Cedar) removed; code not used by Cedar removed.
use core::fmt;

/// The day of week.
///
/// The order of the days of week depends on the context.
/// (This is why this type does *not* implement `PartialOrd` or `Ord` traits.)
/// One should prefer `*_from_monday` or `*_from_sunday` methods to get the correct result.
///
/// # Example
/// ```ignore
/// use chrono::Weekday;
///
/// let monday = "Monday".parse::<Weekday>().unwrap();
/// assert_eq!(monday, Weekday::Mon);
///
/// let sunday = Weekday::try_from(6).unwrap();
/// assert_eq!(sunday, Weekday::Sun);
///
/// assert_eq!(sunday.num_days_from_monday(), 6); // starts counting with Monday = 0
/// assert_eq!(sunday.number_from_monday(), 7); // starts counting with Monday = 1
/// assert_eq!(sunday.num_days_from_sunday(), 0); // starts counting with Sunday = 0
/// assert_eq!(sunday.number_from_sunday(), 1); // starts counting with Sunday = 1
///
/// assert_eq!(sunday.succ(), monday);
/// assert_eq!(sunday.pred(), Weekday::Sat);
/// ```
#[derive(PartialEq, Eq, Copy, Clone, Debug, Hash)]
pub enum Weekday {
    /// Monday.
    Mon = 0,
    /// Tuesday.
    Tue = 1,
    /// Wednesday.
    Wed = 2,
    /// Thursday.
    Thu = 3,
    /// Friday.
    Fri = 4,
    /// Saturday.
    Sat = 5,
    /// Sunday.
    Sun = 6,
}

impl Weekday {
    /// Returns a day-of-week number starting from Monday = 0.
    ///
    /// `w`:                        | `Mon` | `Tue` | `Wed` | `Thu` | `Fri` | `Sat` | `Sun`
    /// --------------------------- | ----- | ----- | ----- | ----- | ----- | ----- | -----
    /// `w.num_days_from_monday()`: | 0     | 1     | 2     | 3     | 4     | 5     | 6
    ///
    /// # Example
    ///
    /// ```ignore
    /// # #[cfg(feature = "clock")] {
    /// # use chrono::{Local, Datelike};
    /// // MTWRFSU is occasionally used as a single-letter abbreviation of the weekdays.
    /// // Use `num_days_from_monday` to index into the array.
    /// const MTWRFSU: [char; 7] = ['M', 'T', 'W', 'R', 'F', 'S', 'U'];
    ///
    /// let today = Local::now().weekday();
    /// println!("{}", MTWRFSU[today.num_days_from_monday() as usize]);
    /// # }
    /// ```
    #[inline]
    pub const fn num_days_from_monday(&self) -> u32 {
        self.days_since(Weekday::Mon)
    }

    /// The number of days since the given day.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use chrono::Weekday::*;
    /// assert_eq!(Mon.days_since(Mon), 0);
    /// assert_eq!(Sun.days_since(Tue), 5);
    /// assert_eq!(Wed.days_since(Sun), 3);
    /// ```
    pub const fn days_since(&self, other: Weekday) -> u32 {
        let lhs = *self as u32;
        let rhs = other as u32;
        if lhs < rhs {
            7 + lhs - rhs
        } else {
            lhs - rhs
        }
    }
}

impl fmt::Display for Weekday {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad(match *self {
            Weekday::Mon => "Mon",
            Weekday::Tue => "Tue",
            Weekday::Wed => "Wed",
            Weekday::Thu => "Thu",
            Weekday::Fri => "Fri",
            Weekday::Sat => "Sat",
            Weekday::Sun => "Sun",
        })
    }
}

// Cedar: `impl num_traits::FromPrimitive for Weekday` removed so Cedar does not need the `num-traits`
// dependency. Cedar does not use it.

// the actual `FromStr` implementation is in the `format` module to leverage the existing code

#[cfg(test)]
mod tests {
    use super::Weekday;

    #[test]
    fn test_formatting_alignment() {
        // No exhaustive testing here as we just delegate the
        // implementation to Formatter::pad. Just some basic smoke
        // testing to ensure that it's in fact being done.
        assert_eq!(format!("{:x>7}", Weekday::Mon), "xxxxMon");
        assert_eq!(format!("{:^7}", Weekday::Mon), "  Mon  ");
        assert_eq!(format!("{:Z<7}", Weekday::Mon), "MonZZZZ");
    }
}
