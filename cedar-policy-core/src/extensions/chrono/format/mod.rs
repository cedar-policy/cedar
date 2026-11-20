// This is a part of Chrono.
// See README.md and LICENSE.txt for details.
//
// This file is `src/format/mod.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples removed; other changes marked with `Cedar:` comments; code behind chrono's Cargo
//   features (not enabled in Cedar) removed; code not used by Cedar removed.

//! Parsing utilities for date and time.
//!
//! This module provides the common types and routines to implement,
//! for example, the [`DateTime::parse_from_str`](crate::extensions::chrono::DateTime::parse_from_str) method.
//! For most cases you should use these high-level interfaces.
//!
//! Internally the parsing uses abstract **formatting items**,
//! which are just an [`Iterator`](https://doc.rust-lang.org/std/iter/trait.Iterator.html) of
//! the [`Item`](crate::extensions::chrono::format::Item) type.
//! They are generated from more readable **format strings**;
//! currently Chrono supports a built-in syntax closely resembling
//! C's `strftime` format. The available options can be found [here](crate::extensions::chrono::format::strftime).

use core::fmt;
// Cedar: always use `std::error::Error`; upstream gates it on chrono's `std` feature, and Cedar
// always builds with `std`.
use std::error::Error;

mod formatting;
mod parsed;

// due to the size of parsing routines, they are in separate modules.
mod parse;
mod scan;

mod strftime;

pub(super) use formatting::write_hundreds;
pub(super) use parse::{parse, parse_and_remainder};
pub(super) use parsed::Parsed;
pub(super) use strftime::StrftimeItems;

/// Padding characters for numeric items.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub(super) enum Pad {
    /// No padding.
    None,
    /// Zero (`0`) padding.
    Zero,
    /// Space padding.
    Space,
}

/// Numeric item types.
/// They have associated formatting width (FW) and parsing width (PW).
///
/// The **formatting width** is the minimal width to be formatted.
/// If the number is too short, and the padding is not [`Pad::None`](crate::extensions::chrono::format::Pad::None),
/// then it is left-padded.
/// If the number is too long or (in some cases) negative, it is printed as is.
///
/// The **parsing width** is the maximal width to be scanned.
/// The parser only tries to consume from one to given number of digits (greedily).
/// It also trims the preceding whitespace if any.
/// It cannot parse the negative number, so some date and time cannot be formatted then
/// parsed with the same formatting items.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub(super) enum Numeric {
    /// Full Gregorian year (FW=4, PW=∞).
    /// May accept years before 1 BCE or after 9999 CE, given an initial sign (+/-).
    Year,
    /// Gregorian year divided by 100 (century number; FW=PW=2). Implies the non-negative year.
    YearDiv100,
    /// Gregorian year modulo 100 (FW=PW=2). Cannot be negative.
    YearMod100,
    /// Year in the ISO week date (FW=4, PW=∞).
    /// May accept years before 1 BCE or after 9999 CE, given an initial sign.
    IsoYear,
    /// Year in the ISO week date, modulo 100 (FW=PW=2). Cannot be negative.
    IsoYearMod100,
    /// Quarter (FW=PW=1).
    Quarter,
    /// Month (FW=PW=2).
    Month,
    /// Day of the month (FW=PW=2).
    Day,
    /// Week number, where the week 1 starts at the first Sunday of January (FW=PW=2).
    WeekFromSun,
    /// Week number, where the week 1 starts at the first Monday of January (FW=PW=2).
    WeekFromMon,
    /// Week number in the ISO week date (FW=PW=2).
    IsoWeek,
    /// Day of the week, where Sunday = 0 and Saturday = 6 (FW=PW=1).
    NumDaysFromSun,
    /// Day of the week, where Monday = 1 and Sunday = 7 (FW=PW=1).
    WeekdayFromMon,
    /// Day of the year (FW=PW=3).
    Ordinal,
    /// Hour number in the 24-hour clocks (FW=PW=2).
    Hour,
    /// Hour number in the 12-hour clocks (FW=PW=2).
    Hour12,
    /// The number of minutes since the last whole hour (FW=PW=2).
    Minute,
    /// The number of seconds since the last whole minute (FW=PW=2).
    Second,
    /// The number of nanoseconds since the last whole second (FW=PW=9).
    /// Note that this is *not* left-aligned;
    /// see also [`Fixed::Nanosecond`](crate::extensions::chrono::format::Fixed::Nanosecond).
    Nanosecond,
    /// The number of non-leap seconds since the midnight UTC on January 1, 1970 (FW=1, PW=∞).
    /// For formatting, it assumes UTC upon the absence of time zone offset.
    Timestamp,
}

/// Fixed-format item types.
///
/// They have their own rules of formatting and parsing.
/// Otherwise noted, they print in the specified cases but parse case-insensitively.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub(super) enum Fixed {
    /// Abbreviated month names.
    ///
    /// Prints a three-letter-long name in the title case, reads the same name in any case.
    ShortMonthName,
    /// Full month names.
    ///
    /// Prints a full name in the title case, reads either a short or full name in any case.
    LongMonthName,
    /// Abbreviated day of the week names.
    ///
    /// Prints a three-letter-long name in the title case, reads the same name in any case.
    ShortWeekdayName,
    /// Full day of the week names.
    ///
    /// Prints a full name in the title case, reads either a short or full name in any case.
    LongWeekdayName,
    /// AM/PM.
    ///
    /// Prints in lower case, reads in any case.
    LowerAmPm,
    /// AM/PM.
    ///
    /// Prints in upper case, reads in any case.
    UpperAmPm,
    /// An optional dot plus one or more digits for left-aligned nanoseconds.
    /// May print nothing, 3, 6 or 9 digits according to the available accuracy.
    /// See also [`Numeric::Nanosecond`](crate::extensions::chrono::format::Numeric::Nanosecond).
    Nanosecond,
    /// Same as [`Nanosecond`](crate::extensions::chrono::format::Fixed::Nanosecond) but the accuracy is fixed to 3.
    Nanosecond3,
    /// Same as [`Nanosecond`](crate::extensions::chrono::format::Fixed::Nanosecond) but the accuracy is fixed to 6.
    Nanosecond6,
    /// Same as [`Nanosecond`](crate::extensions::chrono::format::Fixed::Nanosecond) but the accuracy is fixed to 9.
    Nanosecond9,
    /// Timezone name.
    ///
    /// It does not support parsing, its use in the parser is an immediate failure.
    TimezoneName,
    /// Offset from the local time to UTC (`+09:00` or `-04:00` or `+00:00`).
    ///
    /// In the parser, the colon can be omitted and/or surrounded with any amount of whitespace.
    /// The offset is limited from `-24:00` to `+24:00`,
    /// which is the same as [`FixedOffset`](crate::extensions::chrono::offset::FixedOffset)'s range.
    TimezoneOffsetColon,
    /// Offset from the local time to UTC with seconds (`+09:00:00` or `-04:00:00` or `+00:00:00`).
    ///
    /// In the parser, the colon can be omitted and/or surrounded with any amount of whitespace.
    /// The offset is limited from `-24:00:00` to `+24:00:00`,
    /// which is the same as [`FixedOffset`](crate::extensions::chrono::offset::FixedOffset)'s range.
    TimezoneOffsetDoubleColon,
    /// Offset from the local time to UTC without minutes (`+09` or `-04` or `+00`).
    ///
    /// In the parser, the colon can be omitted and/or surrounded with any amount of whitespace.
    /// The offset is limited from `-24` to `+24`,
    /// which is the same as [`FixedOffset`](crate::extensions::chrono::offset::FixedOffset)'s range.
    TimezoneOffsetTripleColon,
    /// Same as [`TimezoneOffsetColon`](crate::extensions::chrono::format::Fixed::TimezoneOffsetColon) but prints no colon.
    /// Parsing allows an optional colon.
    TimezoneOffset,
    /// RFC 3339 & ISO 8601 date and time syntax.
    RFC3339,

    /// Internal uses only.
    ///
    /// This item exists so that one can add additional internal-only formatting
    /// without breaking major compatibility (as enum variants cannot be selectively private).
    Internal(InternalFixed),
}

/// An opaque type representing fixed-format item types for internal uses only.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct InternalFixed {
    val: InternalInternal,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum InternalInternal {
    /// A time zone offset that allows missing minutes (per [ISO 8601][iso8601]).
    ///
    /// # Panics
    ///
    /// If you try to use this for printing.
    ///
    /// [iso8601]: https://en.wikipedia.org/wiki/ISO_8601#Time_offsets_from_UTC
    TimezoneOffsetPermissive,
    /// Same as [`Nanosecond`](crate::extensions::chrono::format::Fixed::Nanosecond) but the accuracy is fixed to 3 and there is no leading dot.
    Nanosecond3NoDot,
    /// Same as [`Nanosecond`](crate::extensions::chrono::format::Fixed::Nanosecond) but the accuracy is fixed to 6 and there is no leading dot.
    Nanosecond6NoDot,
    /// Same as [`Nanosecond`](crate::extensions::chrono::format::Fixed::Nanosecond) but the accuracy is fixed to 9 and there is no leading dot.
    Nanosecond9NoDot,
}

/// A single formatting item. This is used for both formatting and parsing.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub(crate) enum Item<'a> {
    /// A literally printed and parsed text.
    Literal(&'a str),
    /// Whitespace. Prints literally but reads zero or more whitespace.
    Space(&'a str),
    /// Numeric item. Can be optionally padded to the maximal length (if any) when formatting;
    /// the parser simply ignores any padded whitespace and zeroes.
    Numeric(Numeric, Pad),
    /// Fixed-format item.
    Fixed(Fixed),
    /// Issues a formatting error. Used to signal an invalid format string.
    Error,
}

const fn num(numeric: Numeric) -> Item<'static> {
    Item::Numeric(numeric, Pad::None)
}

const fn num0(numeric: Numeric) -> Item<'static> {
    Item::Numeric(numeric, Pad::Zero)
}

const fn nums(numeric: Numeric) -> Item<'static> {
    Item::Numeric(numeric, Pad::Space)
}

const fn fixed(fixed: Fixed) -> Item<'static> {
    Item::Fixed(fixed)
}

const fn internal_fixed(val: InternalInternal) -> Item<'static> {
    Item::Fixed(Fixed::Internal(InternalFixed { val }))
}

/// An error from the `parse` function.
#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash)]
pub struct ParseError(ParseErrorKind);

/// The category of parse error
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash)]
enum ParseErrorKind {
    /// Given field is out of permitted range.
    OutOfRange,

    /// There is no possible date and time value with given set of fields.
    ///
    /// This does not include the out-of-range conditions, which are trivially invalid.
    /// It includes the case that there are one or more fields that are inconsistent to each other.
    Impossible,

    /// Given set of fields is not enough to make a requested date and time value.
    ///
    /// Note that there *may* be a case that given fields constrain the possible values so much
    /// that there is a unique possible value. Chrono only tries to be correct for
    /// most useful sets of fields however, as such constraint solving can be expensive.
    NotEnough,

    /// The input string has some invalid character sequence for given formatting items.
    Invalid,

    /// The input string has been prematurely ended.
    TooShort,

    /// All formatting items have been read but there is a remaining input.
    TooLong,

    /// There was an error on the formatting string, or there were non-supported formatting items.
    BadFormat,

    // TODO: Change this to `#[non_exhaustive]` (on the enum) with the next breaking release.
    #[doc(hidden)]
    __Nonexhaustive,
}

/// Same as `Result<T, ParseError>`.
pub(super) type ParseResult<T> = Result<T, ParseError>;

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            ParseErrorKind::OutOfRange => write!(f, "input is out of range"),
            ParseErrorKind::Impossible => write!(f, "no possible date and time matching input"),
            ParseErrorKind::NotEnough => write!(f, "input is not enough for unique date and time"),
            ParseErrorKind::Invalid => write!(f, "input contains invalid characters"),
            ParseErrorKind::TooShort => write!(f, "premature end of input"),
            ParseErrorKind::TooLong => write!(f, "trailing input"),
            ParseErrorKind::BadFormat => write!(f, "bad or unsupported format string"),
            _ => unreachable!(),
        }
    }
}

// Cedar: implemented unconditionally (upstream: `#[cfg(any(feature = "core-error", feature = "std"))]`)
// because `cedar-policy-symcc` wraps `ParseError` in a `thiserror` `#[source]`.
impl Error for ParseError {
    fn description(&self) -> &str {
        "parser error, see to_string() for details"
    }
}

// to be used in this module and submodules
const OUT_OF_RANGE: ParseError = ParseError(ParseErrorKind::OutOfRange);
const IMPOSSIBLE: ParseError = ParseError(ParseErrorKind::Impossible);
const NOT_ENOUGH: ParseError = ParseError(ParseErrorKind::NotEnough);
const INVALID: ParseError = ParseError(ParseErrorKind::Invalid);
const TOO_SHORT: ParseError = ParseError(ParseErrorKind::TooShort);
const TOO_LONG: ParseError = ParseError(ParseErrorKind::TooLong);
const BAD_FORMAT: ParseError = ParseError(ParseErrorKind::BadFormat);

// this implementation is here only because we need some private code from `scan`
