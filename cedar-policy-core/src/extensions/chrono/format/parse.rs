// This is a part of Chrono.
// Portions copyright (c) 2015, John Nagle.
// See README.md and LICENSE.txt for details.
//
// This file is `src/format/parse.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples removed; code behind chrono's Cargo features (not enabled in Cedar) removed; code not
//   used by Cedar removed.

//! Date and time parsing routines.

use core::borrow::Borrow;
use core::str;

use super::scan;
use super::{Fixed, InternalFixed, InternalInternal, Item, Numeric, Pad, Parsed};
use super::{ParseError, ParseResult};
use super::{BAD_FORMAT, INVALID, OUT_OF_RANGE, TOO_LONG, TOO_SHORT};
use crate::extensions::chrono::{DateTime, FixedOffset, Weekday};

fn set_weekday_with_num_days_from_sunday(p: &mut Parsed, v: i64) -> ParseResult<()> {
    p.set_weekday(match v {
        0 => Weekday::Sun,
        1 => Weekday::Mon,
        2 => Weekday::Tue,
        3 => Weekday::Wed,
        4 => Weekday::Thu,
        5 => Weekday::Fri,
        6 => Weekday::Sat,
        _ => return Err(OUT_OF_RANGE),
    })
}

fn set_weekday_with_number_from_monday(p: &mut Parsed, v: i64) -> ParseResult<()> {
    p.set_weekday(match v {
        1 => Weekday::Mon,
        2 => Weekday::Tue,
        3 => Weekday::Wed,
        4 => Weekday::Thu,
        5 => Weekday::Fri,
        6 => Weekday::Sat,
        7 => Weekday::Sun,
        _ => return Err(OUT_OF_RANGE),
    })
}

/// Tries to parse given string into `parsed` with given formatting items.
/// Returns `Ok` when the entire string has been parsed (otherwise `parsed` should not be used).
/// There should be no trailing string after parsing;
/// use a stray [`Item::Space`](crate::extensions::chrono::format::Item::Space) to trim whitespaces.
///
/// This particular date and time parser is:
///
/// - Greedy. It will consume the longest possible prefix.
///   For example, `April` is always consumed entirely when the long month name is requested;
///   it equally accepts `Apr`, but prefers the longer prefix in this case.
///
/// - Padding-agnostic (for numeric items).
///   The [`Pad`](crate::extensions::chrono::format::Pad) field is completely ignored,
///   so one can prepend any number of whitespace then any number of zeroes before numbers.
///
/// - (Still) obeying the intrinsic parsing width. This allows, for example, parsing `HHMMSS`.
pub(crate) fn parse<'a, I, B>(parsed: &mut Parsed, s: &str, items: I) -> ParseResult<()>
where
    I: Iterator<Item = B>,
    B: Borrow<Item<'a>>,
{
    match parse_internal(parsed, s, items) {
        Ok("") => Ok(()),
        Ok(_) => Err(TOO_LONG), // if there are trailing chars it is an error
        Err(e) => Err(e),
    }
}

/// Tries to parse given string into `parsed` with given formatting items.
/// Returns `Ok` with a slice of the unparsed remainder.
///
/// This particular date and time parser is:
///
/// - Greedy. It will consume the longest possible prefix.
///   For example, `April` is always consumed entirely when the long month name is requested;
///   it equally accepts `Apr`, but prefers the longer prefix in this case.
///
/// - Padding-agnostic (for numeric items).
///   The [`Pad`](crate::extensions::chrono::format::Pad) field is completely ignored,
///   so one can prepend any number of zeroes before numbers.
///
/// - (Still) obeying the intrinsic parsing width. This allows, for example, parsing `HHMMSS`.
pub(crate) fn parse_and_remainder<'a, 'b, I, B>(
    parsed: &mut Parsed,
    s: &'b str,
    items: I,
) -> ParseResult<&'b str>
where
    I: Iterator<Item = B>,
    B: Borrow<Item<'a>>,
{
    parse_internal(parsed, s, items)
}

fn parse_internal<'a, 'b, I, B>(
    parsed: &mut Parsed,
    mut s: &'b str,
    items: I,
) -> Result<&'b str, ParseError>
where
    I: Iterator<Item = B>,
    B: Borrow<Item<'a>>,
{
    macro_rules! try_consume {
        ($e:expr) => {{
            match $e {
                Ok((s_, v)) => {
                    s = s_;
                    v
                }
                Err(e) => return Err(e),
            }
        }};
    }

    for item in items {
        match *item.borrow() {
            Item::Literal(prefix) => {
                if s.len() < prefix.len() {
                    return Err(TOO_SHORT);
                }
                if !s.starts_with(prefix) {
                    return Err(INVALID);
                }
                s = &s[prefix.len()..];
            }

            Item::Space(_) => {
                s = s.trim_start();
            }

            Item::Numeric(ref spec, ref _pad) => {
                use super::Numeric::*;
                type Setter = fn(&mut Parsed, i64) -> ParseResult<()>;

                let (width, signed, set): (usize, bool, Setter) = match *spec {
                    Year => (4, true, Parsed::set_year),
                    YearDiv100 => (2, false, Parsed::set_year_div_100),
                    YearMod100 => (2, false, Parsed::set_year_mod_100),
                    IsoYear => (4, true, Parsed::set_isoyear),
                    IsoYearMod100 => (2, false, Parsed::set_isoyear_mod_100),
                    Quarter => (1, false, Parsed::set_quarter),
                    Month => (2, false, Parsed::set_month),
                    Day => (2, false, Parsed::set_day),
                    WeekFromSun => (2, false, Parsed::set_week_from_sun),
                    WeekFromMon => (2, false, Parsed::set_week_from_mon),
                    IsoWeek => (2, false, Parsed::set_isoweek),
                    NumDaysFromSun => (1, false, set_weekday_with_num_days_from_sunday),
                    WeekdayFromMon => (1, false, set_weekday_with_number_from_monday),
                    Ordinal => (3, false, Parsed::set_ordinal),
                    Hour => (2, false, Parsed::set_hour),
                    Hour12 => (2, false, Parsed::set_hour12),
                    Minute => (2, false, Parsed::set_minute),
                    Second => (2, false, Parsed::set_second),
                    Nanosecond => (9, false, Parsed::set_nanosecond),
                    Timestamp => (usize::MAX, false, Parsed::set_timestamp),
                };

                s = s.trim_start();
                let v = if signed {
                    if s.starts_with('-') {
                        let v = try_consume!(scan::number(&s[1..], 1, usize::MAX));
                        0i64.checked_sub(v).ok_or(OUT_OF_RANGE)?
                    } else if s.starts_with('+') {
                        try_consume!(scan::number(&s[1..], 1, usize::MAX))
                    } else {
                        // if there is no explicit sign, we respect the original `width`
                        try_consume!(scan::number(s, 1, width))
                    }
                } else {
                    try_consume!(scan::number(s, 1, width))
                };
                set(parsed, v)?;
            }

            Item::Fixed(ref spec) => {
                use super::Fixed::*;

                match spec {
                    &ShortMonthName => {
                        let month0 = try_consume!(scan::short_month0(s));
                        parsed.set_month(i64::from(month0) + 1)?;
                    }

                    &LongMonthName => {
                        let month0 = try_consume!(scan::short_or_long_month0(s));
                        parsed.set_month(i64::from(month0) + 1)?;
                    }

                    &ShortWeekdayName => {
                        let weekday = try_consume!(scan::short_weekday(s));
                        parsed.set_weekday(weekday)?;
                    }

                    &LongWeekdayName => {
                        let weekday = try_consume!(scan::short_or_long_weekday(s));
                        parsed.set_weekday(weekday)?;
                    }

                    &LowerAmPm | &UpperAmPm => {
                        if s.len() < 2 {
                            return Err(TOO_SHORT);
                        }
                        let ampm = match (s.as_bytes()[0] | 32, s.as_bytes()[1] | 32) {
                            (b'a', b'm') => false,
                            (b'p', b'm') => true,
                            _ => return Err(INVALID),
                        };
                        parsed.set_ampm(ampm)?;
                        s = &s[2..];
                    }

                    &Nanosecond => {
                        if s.starts_with('.') {
                            let nano = try_consume!(scan::nanosecond(&s[1..]));
                            parsed.set_nanosecond(nano as i64)?;
                        }
                    }

                    &Nanosecond3 => {
                        if s.starts_with('.') {
                            let nano = try_consume!(scan::nanosecond_fixed(&s[1..], 3));
                            parsed.set_nanosecond(nano)?;
                        }
                    }

                    &Nanosecond6 => {
                        if s.starts_with('.') {
                            let nano = try_consume!(scan::nanosecond_fixed(&s[1..], 6));
                            parsed.set_nanosecond(nano)?;
                        }
                    }

                    &Nanosecond9 => {
                        if s.starts_with('.') {
                            let nano = try_consume!(scan::nanosecond_fixed(&s[1..], 9));
                            parsed.set_nanosecond(nano)?;
                        }
                    }

                    &Internal(InternalFixed {
                        val: InternalInternal::Nanosecond3NoDot,
                    }) => {
                        if s.len() < 3 {
                            return Err(TOO_SHORT);
                        }
                        let nano = try_consume!(scan::nanosecond_fixed(s, 3));
                        parsed.set_nanosecond(nano)?;
                    }

                    &Internal(InternalFixed {
                        val: InternalInternal::Nanosecond6NoDot,
                    }) => {
                        if s.len() < 6 {
                            return Err(TOO_SHORT);
                        }
                        let nano = try_consume!(scan::nanosecond_fixed(s, 6));
                        parsed.set_nanosecond(nano)?;
                    }

                    &Internal(InternalFixed {
                        val: InternalInternal::Nanosecond9NoDot,
                    }) => {
                        if s.len() < 9 {
                            return Err(TOO_SHORT);
                        }
                        let nano = try_consume!(scan::nanosecond_fixed(s, 9));
                        parsed.set_nanosecond(nano)?;
                    }

                    &TimezoneName => {
                        try_consume!(Ok((s.trim_start_matches(|c: char| !c.is_whitespace()), ())));
                    }

                    &TimezoneOffsetColon
                    | &TimezoneOffsetDoubleColon
                    | &TimezoneOffsetTripleColon
                    | &TimezoneOffset => {
                        let offset = try_consume!(scan::timezone_offset(
                            s.trim_start(),
                            scan::colon_or_space,
                            false,
                            false,
                            true,
                        ));
                        parsed.set_offset(i64::from(offset))?;
                    }

                    &Internal(InternalFixed {
                        val: InternalInternal::TimezoneOffsetPermissive,
                    }) => {
                        let offset = try_consume!(scan::timezone_offset(
                            s.trim_start(),
                            scan::colon_or_space,
                            true,
                            true,
                            true,
                        ));
                        parsed.set_offset(i64::from(offset))?;
                    }

                    &RFC3339 => {
                        // Used for the `%+` specifier, which has the description:
                        // "Same as `%Y-%m-%dT%H:%M:%S%.f%:z` (...)
                        // This format also supports having a `Z` or `UTC` in place of `%:z`."
                        // Use the relaxed parser to match this description.
                        try_consume!(parse_rfc3339_relaxed(parsed, s))
                    }
                }
            }

            Item::Error => {
                return Err(BAD_FORMAT);
            }
        }
    }
    Ok(s)
}

/// Accepts a relaxed form of RFC3339.
/// A space or a 'T' are accepted as the separator between the date and time
/// parts. Additional spaces are allowed between each component.
impl str::FromStr for DateTime<FixedOffset> {
    type Err = ParseError;

    fn from_str(s: &str) -> ParseResult<DateTime<FixedOffset>> {
        let mut parsed = Parsed::new();
        let (s, _) = parse_rfc3339_relaxed(&mut parsed, s)?;
        if !s.trim_start().is_empty() {
            return Err(TOO_LONG);
        }
        parsed.to_datetime()
    }
}

/// Accepts a relaxed form of RFC3339.
///
/// Differences with RFC3339:
/// - Values don't require padding to two digits.
/// - Years outside the range 0...=9999 are accepted, but they must include a sign.
/// - `UTC` is accepted as a valid timezone name/offset (for compatibility with the debug format of
///   `DateTime<Utc>`.
/// - There can be spaces between any of the components.
/// - The colon in the offset may be missing.
fn parse_rfc3339_relaxed<'a>(parsed: &mut Parsed, mut s: &'a str) -> ParseResult<(&'a str, ())> {
    const DATE_ITEMS: &[Item<'static>] = &[
        Item::Numeric(Numeric::Year, Pad::Zero),
        Item::Space(""),
        Item::Literal("-"),
        Item::Numeric(Numeric::Month, Pad::Zero),
        Item::Space(""),
        Item::Literal("-"),
        Item::Numeric(Numeric::Day, Pad::Zero),
    ];
    const TIME_ITEMS: &[Item<'static>] = &[
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

    s = parse_internal(parsed, s, DATE_ITEMS.iter())?;

    s = match s.as_bytes().first() {
        Some(&b't' | &b'T' | &b' ') => &s[1..],
        Some(_) => return Err(INVALID),
        None => return Err(TOO_SHORT),
    };

    s = parse_internal(parsed, s, TIME_ITEMS.iter())?;
    s = s.trim_start();
    let (s, offset) = if s.len() >= 3 && "UTC".as_bytes().eq_ignore_ascii_case(&s.as_bytes()[..3]) {
        (&s[3..], 0)
    } else {
        scan::timezone_offset(s, scan::colon_or_space, true, false, true)?
    };
    parsed.set_offset(i64::from(offset))?;
    Ok((s, ()))
}

#[cfg(test)]
mod tests {
    use crate::extensions::chrono::format::*;
    use crate::extensions::chrono::Weekday;

    macro_rules! parsed {
        ($($k:ident: $v:expr),*) => (#[allow(unused_mut)] {
            let mut expected = Parsed::new();
            $(expected.$k = Some($v);)*
            Ok(expected)
        });
    }

    #[test]
    fn test_parse_whitespace_and_literal() {
        use crate::extensions::chrono::format::Item::{Literal, Space};

        // empty string
        parses("", &[]);
        check(" ", &[], Err(TOO_LONG));
        check("a", &[], Err(TOO_LONG));
        check("abc", &[], Err(TOO_LONG));
        check("🤠", &[], Err(TOO_LONG));

        // whitespaces
        parses("", &[Space("")]);
        parses(" ", &[Space(" ")]);
        parses("  ", &[Space("  ")]);
        parses("   ", &[Space("   ")]);
        parses(" ", &[Space("")]);
        parses("  ", &[Space(" ")]);
        parses("   ", &[Space("  ")]);
        parses("    ", &[Space("  ")]);
        parses("", &[Space(" ")]);
        parses(" ", &[Space("  ")]);
        parses("  ", &[Space("   ")]);
        parses("  ", &[Space("  "), Space("  ")]);
        parses("   ", &[Space("  "), Space("  ")]);
        parses("  ", &[Space(" "), Space(" ")]);
        parses("   ", &[Space("  "), Space(" ")]);
        parses("   ", &[Space(" "), Space("  ")]);
        parses("   ", &[Space(" "), Space(" "), Space(" ")]);
        parses("\t", &[Space("")]);
        parses(" \n\r  \n", &[Space("")]);
        parses("\t", &[Space("\t")]);
        parses("\t", &[Space(" ")]);
        parses(" ", &[Space("\t")]);
        parses("\t\r", &[Space("\t\r")]);
        parses("\t\r ", &[Space("\t\r ")]);
        parses("\t \r", &[Space("\t \r")]);
        parses(" \t\r", &[Space(" \t\r")]);
        parses(" \n\r  \n", &[Space(" \n\r  \n")]);
        parses(" \t\n", &[Space(" \t")]);
        parses(" \n\t", &[Space(" \t\n")]);
        parses("\u{2002}", &[Space("\u{2002}")]);
        // most unicode whitespace characters
        parses(
            "\u{00A0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{3000}",
            &[Space(
                "\u{00A0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{3000}",
            )],
        );
        // most unicode whitespace characters
        parses(
            "\u{00A0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{3000}",
            &[
                Space("\u{00A0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}"),
                Space("\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{3000}"),
            ],
        );
        check("a", &[Space("")], Err(TOO_LONG));
        check("a", &[Space(" ")], Err(TOO_LONG));
        // a Space containing a literal does not match a literal
        check("a", &[Space("a")], Err(TOO_LONG));
        check("abc", &[Space("")], Err(TOO_LONG));
        check("abc", &[Space(" ")], Err(TOO_LONG));
        check(" abc", &[Space("")], Err(TOO_LONG));
        check(" abc", &[Space(" ")], Err(TOO_LONG));

        // `\u{0363}` is combining diacritic mark "COMBINING LATIN SMALL LETTER A"

        // literal
        parses("", &[Literal("")]);
        check("", &[Literal("a")], Err(TOO_SHORT));
        check(" ", &[Literal("a")], Err(INVALID));
        parses("a", &[Literal("a")]);
        parses("+", &[Literal("+")]);
        parses("-", &[Literal("-")]);
        parses("−", &[Literal("−")]); // MINUS SIGN (U+2212)
        parses(" ", &[Literal(" ")]); // a Literal may contain whitespace and match whitespace
        check("aa", &[Literal("a")], Err(TOO_LONG));
        check("🤠", &[Literal("a")], Err(INVALID));
        check("A", &[Literal("a")], Err(INVALID));
        check("a", &[Literal("z")], Err(INVALID));
        check("a", &[Literal("🤠")], Err(TOO_SHORT));
        check("a", &[Literal("\u{0363}a")], Err(TOO_SHORT));
        check("\u{0363}a", &[Literal("a")], Err(INVALID));
        parses("\u{0363}a", &[Literal("\u{0363}a")]);
        check("a", &[Literal("ab")], Err(TOO_SHORT));
        parses("xy", &[Literal("xy")]);
        parses("xy", &[Literal("x"), Literal("y")]);
        parses("1", &[Literal("1")]);
        parses("1234", &[Literal("1234")]);
        parses("+1234", &[Literal("+1234")]);
        parses("-1234", &[Literal("-1234")]);
        parses("−1234", &[Literal("−1234")]); // MINUS SIGN (U+2212)
        parses("PST", &[Literal("PST")]);
        parses("🤠", &[Literal("🤠")]);
        parses("🤠a", &[Literal("🤠"), Literal("a")]);
        parses("🤠a🤠", &[Literal("🤠"), Literal("a🤠")]);
        parses("a🤠b", &[Literal("a"), Literal("🤠"), Literal("b")]);
        // literals can be together
        parses("xy", &[Literal("xy")]);
        parses("xyz", &[Literal("xyz")]);
        // or literals can be apart
        parses("xy", &[Literal("x"), Literal("y")]);
        parses("xyz", &[Literal("x"), Literal("yz")]);
        parses("xyz", &[Literal("xy"), Literal("z")]);
        parses("xyz", &[Literal("x"), Literal("y"), Literal("z")]);
        //
        check("x y", &[Literal("x"), Literal("y")], Err(INVALID));
        parses("xy", &[Literal("x"), Space(""), Literal("y")]);
        parses("x y", &[Literal("x"), Space(""), Literal("y")]);
        parses("x y", &[Literal("x"), Space(" "), Literal("y")]);

        // whitespaces + literals
        parses("a\n", &[Literal("a"), Space("\n")]);
        parses("\tab\n", &[Space("\t"), Literal("ab"), Space("\n")]);
        parses(
            "ab\tcd\ne",
            &[
                Literal("ab"),
                Space("\t"),
                Literal("cd"),
                Space("\n"),
                Literal("e"),
            ],
        );
        parses(
            "+1ab\tcd\r\n+,.",
            &[
                Literal("+1ab"),
                Space("\t"),
                Literal("cd"),
                Space("\r\n"),
                Literal("+,."),
            ],
        );
        // whitespace and literals can be intermixed
        parses("a\tb", &[Literal("a\tb")]);
        parses("a\tb", &[Literal("a"), Space("\t"), Literal("b")]);
    }

    #[test]
    fn test_parse_fixed() {
        use crate::extensions::chrono::format::Fixed::*;
        use crate::extensions::chrono::format::Item::{Literal, Space};

        // fixed: month and weekday names
        check("apr", &[fixed(ShortMonthName)], parsed!(month: 4));
        check("Apr", &[fixed(ShortMonthName)], parsed!(month: 4));
        check("APR", &[fixed(ShortMonthName)], parsed!(month: 4));
        check("ApR", &[fixed(ShortMonthName)], parsed!(month: 4));
        check("\u{0363}APR", &[fixed(ShortMonthName)], Err(INVALID));
        check("April", &[fixed(ShortMonthName)], Err(TOO_LONG)); // `Apr` is parsed
        check("A", &[fixed(ShortMonthName)], Err(TOO_SHORT));
        check("Sol", &[fixed(ShortMonthName)], Err(INVALID));
        check("Apr", &[fixed(LongMonthName)], parsed!(month: 4));
        check("Apri", &[fixed(LongMonthName)], Err(TOO_LONG)); // `Apr` is parsed
        check("April", &[fixed(LongMonthName)], parsed!(month: 4));
        check("Aprill", &[fixed(LongMonthName)], Err(TOO_LONG));
        check(
            "Aprill",
            &[fixed(LongMonthName), Literal("l")],
            parsed!(month: 4),
        );
        check(
            "Aprl",
            &[fixed(LongMonthName), Literal("l")],
            parsed!(month: 4),
        );
        check(
            "April",
            &[fixed(LongMonthName), Literal("il")],
            Err(TOO_SHORT),
        ); // do not backtrack
        check(
            "thu",
            &[fixed(ShortWeekdayName)],
            parsed!(weekday: Weekday::Thu),
        );
        check(
            "Thu",
            &[fixed(ShortWeekdayName)],
            parsed!(weekday: Weekday::Thu),
        );
        check(
            "THU",
            &[fixed(ShortWeekdayName)],
            parsed!(weekday: Weekday::Thu),
        );
        check(
            "tHu",
            &[fixed(ShortWeekdayName)],
            parsed!(weekday: Weekday::Thu),
        );
        check("Thursday", &[fixed(ShortWeekdayName)], Err(TOO_LONG)); // `Thu` is parsed
        check("T", &[fixed(ShortWeekdayName)], Err(TOO_SHORT));
        check("The", &[fixed(ShortWeekdayName)], Err(INVALID));
        check("Nop", &[fixed(ShortWeekdayName)], Err(INVALID));
        check(
            "Thu",
            &[fixed(LongWeekdayName)],
            parsed!(weekday: Weekday::Thu),
        );
        check("Thur", &[fixed(LongWeekdayName)], Err(TOO_LONG)); // `Thu` is parsed
        check("Thurs", &[fixed(LongWeekdayName)], Err(TOO_LONG)); // `Thu` is parsed
        check(
            "Thursday",
            &[fixed(LongWeekdayName)],
            parsed!(weekday: Weekday::Thu),
        );
        check("Thursdays", &[fixed(LongWeekdayName)], Err(TOO_LONG));
        check(
            "Thursdays",
            &[fixed(LongWeekdayName), Literal("s")],
            parsed!(weekday: Weekday::Thu),
        );
        check(
            "Thus",
            &[fixed(LongWeekdayName), Literal("s")],
            parsed!(weekday: Weekday::Thu),
        );
        check(
            "Thursday",
            &[fixed(LongWeekdayName), Literal("rsday")],
            Err(TOO_SHORT),
        ); // do not backtrack

        // fixed: am/pm
        check("am", &[fixed(LowerAmPm)], parsed!(hour_div_12: 0));
        check("pm", &[fixed(LowerAmPm)], parsed!(hour_div_12: 1));
        check("AM", &[fixed(LowerAmPm)], parsed!(hour_div_12: 0));
        check("PM", &[fixed(LowerAmPm)], parsed!(hour_div_12: 1));
        check("am", &[fixed(UpperAmPm)], parsed!(hour_div_12: 0));
        check("pm", &[fixed(UpperAmPm)], parsed!(hour_div_12: 1));
        check("AM", &[fixed(UpperAmPm)], parsed!(hour_div_12: 0));
        check("PM", &[fixed(UpperAmPm)], parsed!(hour_div_12: 1));
        check("Am", &[fixed(LowerAmPm)], parsed!(hour_div_12: 0));
        check(
            " Am",
            &[Space(" "), fixed(LowerAmPm)],
            parsed!(hour_div_12: 0),
        );
        check(
            "Am🤠",
            &[fixed(LowerAmPm), Literal("🤠")],
            parsed!(hour_div_12: 0),
        );
        check(
            "🤠Am",
            &[Literal("🤠"), fixed(LowerAmPm)],
            parsed!(hour_div_12: 0),
        );
        check("\u{0363}am", &[fixed(LowerAmPm)], Err(INVALID));
        check("\u{0360}am", &[fixed(LowerAmPm)], Err(INVALID));
        check(" Am", &[fixed(LowerAmPm)], Err(INVALID));
        check("Am ", &[fixed(LowerAmPm)], Err(TOO_LONG));
        check("a.m.", &[fixed(LowerAmPm)], Err(INVALID));
        check("A.M.", &[fixed(LowerAmPm)], Err(INVALID));
        check("ame", &[fixed(LowerAmPm)], Err(TOO_LONG)); // `am` is parsed
        check("a", &[fixed(LowerAmPm)], Err(TOO_SHORT));
        check("p", &[fixed(LowerAmPm)], Err(TOO_SHORT));
        check("x", &[fixed(LowerAmPm)], Err(TOO_SHORT));
        check("xx", &[fixed(LowerAmPm)], Err(INVALID));
        check("", &[fixed(LowerAmPm)], Err(TOO_SHORT));
    }

    #[test]
    fn test_parse_fixed_nanosecond() {
        use crate::extensions::chrono::format::Fixed::{
            Nanosecond, Nanosecond3, Nanosecond6, Nanosecond9,
        };
        use crate::extensions::chrono::format::InternalInternal::*;
        use crate::extensions::chrono::format::Item::Literal;
        use crate::extensions::chrono::format::Numeric::Second;

        // fixed: dot plus nanoseconds
        check("", &[fixed(Nanosecond)], parsed!()); // no field set, but not an error
        check(".", &[fixed(Nanosecond)], Err(TOO_SHORT));
        check("4", &[fixed(Nanosecond)], Err(TOO_LONG)); // never consumes `4`
        check("4", &[fixed(Nanosecond), num(Second)], parsed!(second: 4));
        check(".0", &[fixed(Nanosecond)], parsed!(nanosecond: 0));
        check(".4", &[fixed(Nanosecond)], parsed!(nanosecond: 400_000_000));
        check(
            ".42",
            &[fixed(Nanosecond)],
            parsed!(nanosecond: 420_000_000),
        );
        check(
            ".421",
            &[fixed(Nanosecond)],
            parsed!(nanosecond: 421_000_000),
        );
        check(
            ".42195",
            &[fixed(Nanosecond)],
            parsed!(nanosecond: 421_950_000),
        );
        check(
            ".421951",
            &[fixed(Nanosecond)],
            parsed!(nanosecond: 421_951_000),
        );
        check(
            ".4219512",
            &[fixed(Nanosecond)],
            parsed!(nanosecond: 421_951_200),
        );
        check(
            ".42195123",
            &[fixed(Nanosecond)],
            parsed!(nanosecond: 421_951_230),
        );
        check(
            ".421950803",
            &[fixed(Nanosecond)],
            parsed!(nanosecond: 421_950_803),
        );
        check(
            ".4219508035",
            &[fixed(Nanosecond)],
            parsed!(nanosecond: 421_950_803),
        );
        check(
            ".42195080354",
            &[fixed(Nanosecond)],
            parsed!(nanosecond: 421_950_803),
        );
        check(
            ".421950803547",
            &[fixed(Nanosecond)],
            parsed!(nanosecond: 421_950_803),
        );
        check(".000000003", &[fixed(Nanosecond)], parsed!(nanosecond: 3));
        check(".0000000031", &[fixed(Nanosecond)], parsed!(nanosecond: 3));
        check(".0000000035", &[fixed(Nanosecond)], parsed!(nanosecond: 3));
        check(
            ".000000003547",
            &[fixed(Nanosecond)],
            parsed!(nanosecond: 3),
        );
        check(".0000000009", &[fixed(Nanosecond)], parsed!(nanosecond: 0));
        check(
            ".000000000547",
            &[fixed(Nanosecond)],
            parsed!(nanosecond: 0),
        );
        check(
            ".0000000009999999999999999999999999",
            &[fixed(Nanosecond)],
            parsed!(nanosecond: 0),
        );
        check(
            ".4🤠",
            &[fixed(Nanosecond), Literal("🤠")],
            parsed!(nanosecond: 400_000_000),
        );
        check(".4x", &[fixed(Nanosecond)], Err(TOO_LONG));
        check(".  4", &[fixed(Nanosecond)], Err(INVALID));
        check("  .4", &[fixed(Nanosecond)], Err(TOO_LONG)); // no automatic trimming

        // fixed-length fractions of a second
        check("", &[fixed(Nanosecond3)], parsed!()); // no field set, but not an error
        check("4", &[fixed(Nanosecond3)], Err(TOO_LONG)); // never consumes `4`
        check(".12", &[fixed(Nanosecond3)], Err(TOO_SHORT));
        check(
            ".123",
            &[fixed(Nanosecond3)],
            parsed!(nanosecond: 123_000_000),
        );
        check(".1234", &[fixed(Nanosecond3)], Err(TOO_LONG));
        check(
            ".1234",
            &[fixed(Nanosecond3), Literal("4")],
            parsed!(nanosecond: 123_000_000),
        );

        check("", &[fixed(Nanosecond6)], parsed!()); // no field set, but not an error
        check("4", &[fixed(Nanosecond6)], Err(TOO_LONG)); // never consumes `4`
        check(".12345", &[fixed(Nanosecond6)], Err(TOO_SHORT));
        check(
            ".123456",
            &[fixed(Nanosecond6)],
            parsed!(nanosecond: 123_456_000),
        );
        check(".1234567", &[fixed(Nanosecond6)], Err(TOO_LONG));
        check(
            ".1234567",
            &[fixed(Nanosecond6), Literal("7")],
            parsed!(nanosecond: 123_456_000),
        );

        check("", &[fixed(Nanosecond9)], parsed!()); // no field set, but not an error
        check("4", &[fixed(Nanosecond9)], Err(TOO_LONG)); // never consumes `4`
        check(".12345678", &[fixed(Nanosecond9)], Err(TOO_SHORT));
        check(
            ".123456789",
            &[fixed(Nanosecond9)],
            parsed!(nanosecond: 123_456_789),
        );
        check(".1234567890", &[fixed(Nanosecond9)], Err(TOO_LONG));
        check(
            ".1234567890",
            &[fixed(Nanosecond9), Literal("0")],
            parsed!(nanosecond: 123_456_789),
        );

        // fixed: nanoseconds without the dot
        check("", &[internal_fixed(Nanosecond3NoDot)], Err(TOO_SHORT));
        check(".", &[internal_fixed(Nanosecond3NoDot)], Err(TOO_SHORT));
        check("0", &[internal_fixed(Nanosecond3NoDot)], Err(TOO_SHORT));
        check("4", &[internal_fixed(Nanosecond3NoDot)], Err(TOO_SHORT));
        check("42", &[internal_fixed(Nanosecond3NoDot)], Err(TOO_SHORT));
        check(
            "421",
            &[internal_fixed(Nanosecond3NoDot)],
            parsed!(nanosecond: 421_000_000),
        );
        check("4210", &[internal_fixed(Nanosecond3NoDot)], Err(TOO_LONG));
        check(
            "42143",
            &[internal_fixed(Nanosecond3NoDot), num(Second)],
            parsed!(nanosecond: 421_000_000, second: 43),
        );
        check(
            "421🤠",
            &[internal_fixed(Nanosecond3NoDot), Literal("🤠")],
            parsed!(nanosecond: 421_000_000),
        );
        check(
            "🤠421",
            &[Literal("🤠"), internal_fixed(Nanosecond3NoDot)],
            parsed!(nanosecond: 421_000_000),
        );
        check("42195", &[internal_fixed(Nanosecond3NoDot)], Err(TOO_LONG));
        check(
            "123456789",
            &[internal_fixed(Nanosecond3NoDot)],
            Err(TOO_LONG),
        );
        check("4x", &[internal_fixed(Nanosecond3NoDot)], Err(TOO_SHORT));
        check("  4", &[internal_fixed(Nanosecond3NoDot)], Err(INVALID));
        check(".421", &[internal_fixed(Nanosecond3NoDot)], Err(INVALID));

        check("", &[internal_fixed(Nanosecond6NoDot)], Err(TOO_SHORT));
        check(".", &[internal_fixed(Nanosecond6NoDot)], Err(TOO_SHORT));
        check("0", &[internal_fixed(Nanosecond6NoDot)], Err(TOO_SHORT));
        check("1234", &[internal_fixed(Nanosecond6NoDot)], Err(TOO_SHORT));
        check("12345", &[internal_fixed(Nanosecond6NoDot)], Err(TOO_SHORT));
        check(
            "421950",
            &[internal_fixed(Nanosecond6NoDot)],
            parsed!(nanosecond: 421_950_000),
        );
        check(
            "000003",
            &[internal_fixed(Nanosecond6NoDot)],
            parsed!(nanosecond: 3000),
        );
        check(
            "000000",
            &[internal_fixed(Nanosecond6NoDot)],
            parsed!(nanosecond: 0),
        );
        check(
            "1234567",
            &[internal_fixed(Nanosecond6NoDot)],
            Err(TOO_LONG),
        );
        check(
            "123456789",
            &[internal_fixed(Nanosecond6NoDot)],
            Err(TOO_LONG),
        );
        check("4x", &[internal_fixed(Nanosecond6NoDot)], Err(TOO_SHORT));
        check("     4", &[internal_fixed(Nanosecond6NoDot)], Err(INVALID));
        check(".42100", &[internal_fixed(Nanosecond6NoDot)], Err(INVALID));

        check("", &[internal_fixed(Nanosecond9NoDot)], Err(TOO_SHORT));
        check(".", &[internal_fixed(Nanosecond9NoDot)], Err(TOO_SHORT));
        check("42195", &[internal_fixed(Nanosecond9NoDot)], Err(TOO_SHORT));
        check(
            "12345678",
            &[internal_fixed(Nanosecond9NoDot)],
            Err(TOO_SHORT),
        );
        check(
            "421950803",
            &[internal_fixed(Nanosecond9NoDot)],
            parsed!(nanosecond: 421_950_803),
        );
        check(
            "000000003",
            &[internal_fixed(Nanosecond9NoDot)],
            parsed!(nanosecond: 3),
        );
        check(
            "42195080354",
            &[internal_fixed(Nanosecond9NoDot), num(Second)],
            parsed!(nanosecond: 421_950_803, second: 54),
        ); // don't skip digits that come after the 9
        check(
            "1234567890",
            &[internal_fixed(Nanosecond9NoDot)],
            Err(TOO_LONG),
        );
        check(
            "000000000",
            &[internal_fixed(Nanosecond9NoDot)],
            parsed!(nanosecond: 0),
        );
        check(
            "00000000x",
            &[internal_fixed(Nanosecond9NoDot)],
            Err(INVALID),
        );
        check(
            "        4",
            &[internal_fixed(Nanosecond9NoDot)],
            Err(INVALID),
        );
        check(
            ".42100000",
            &[internal_fixed(Nanosecond9NoDot)],
            Err(INVALID),
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_parse_practical_examples() {
        use crate::extensions::chrono::format::InternalInternal::*;
        use crate::extensions::chrono::format::Item::{Literal, Space};
        use crate::extensions::chrono::format::Numeric::*;

        // some practical examples
        check(
            "2015-02-04T14:37:05+09:00",
            &[
                num(Year), Literal("-"), num(Month), Literal("-"), num(Day), Literal("T"),
                num(Hour), Literal(":"), num(Minute), Literal(":"), num(Second),
                fixed(Fixed::TimezoneOffset),
            ],
            parsed!(
                year: 2015, month: 2, day: 4, hour_div_12: 1, hour_mod_12: 2, minute: 37,
                second: 5, offset: 32400
            ),
        );
        check(
            "2015-02-04T14:37:05-09:00",
            &[
                num(Year), Literal("-"), num(Month), Literal("-"), num(Day), Literal("T"),
                num(Hour), Literal(":"), num(Minute), Literal(":"), num(Second),
                fixed(Fixed::TimezoneOffset),
            ],
            parsed!(
                year: 2015, month: 2, day: 4, hour_div_12: 1, hour_mod_12: 2, minute: 37,
                second: 5, offset: -32400
            ),
        );
        check(
            "2015-02-04T14:37:05−09:00", // timezone offset using MINUS SIGN (U+2212)
            &[
                num(Year), Literal("-"), num(Month), Literal("-"), num(Day), Literal("T"),
                num(Hour), Literal(":"), num(Minute), Literal(":"), num(Second),
                fixed(Fixed::TimezoneOffset)
            ],
            parsed!(
                year: 2015, month: 2, day: 4, hour_div_12: 1, hour_mod_12: 2, minute: 37,
                second: 5, offset: -32400
            ),
        );
        check(
            "20150204143705567",
            &[
                num(Year), num(Month), num(Day), num(Hour), num(Minute), num(Second),
                internal_fixed(Nanosecond3NoDot)
            ],
            parsed!(
                year: 2015, month: 2, day: 4, hour_div_12: 1, hour_mod_12: 2, minute: 37,
                second: 5, nanosecond: 567000000
            ),
        );
        check(
            "Mon, 10 Jun 2013 09:32:37 GMT",
            &[
                fixed(Fixed::ShortWeekdayName), Literal(","), Space(" "), num(Day), Space(" "),
                fixed(Fixed::ShortMonthName), Space(" "), num(Year), Space(" "), num(Hour),
                Literal(":"), num(Minute), Literal(":"), num(Second), Space(" "), Literal("GMT")
            ],
            parsed!(
                year: 2013, month: 6, day: 10, weekday: Weekday::Mon,
                hour_div_12: 0, hour_mod_12: 9, minute: 32, second: 37
            ),
        );
        check(
            "🤠Mon, 10 Jun🤠2013 09:32:37  GMT🤠",
            &[
                Literal("🤠"), fixed(Fixed::ShortWeekdayName), Literal(","), Space(" "), num(Day),
                Space(" "), fixed(Fixed::ShortMonthName), Literal("🤠"), num(Year), Space(" "),
                num(Hour), Literal(":"), num(Minute), Literal(":"), num(Second), Space("  "),
                Literal("GMT"), Literal("🤠")
            ],
            parsed!(
                year: 2013, month: 6, day: 10, weekday: Weekday::Mon,
                hour_div_12: 0, hour_mod_12: 9, minute: 32, second: 37
            ),
        );
        check(
            "Sun Aug 02 13:39:15 CEST 2020",
            &[
                fixed(Fixed::ShortWeekdayName), Space(" "), fixed(Fixed::ShortMonthName),
                Space(" "), num(Day), Space(" "), num(Hour), Literal(":"), num(Minute),
                Literal(":"), num(Second), Space(" "), fixed(Fixed::TimezoneName), Space(" "),
                num(Year)
            ],
            parsed!(
                year: 2020, month: 8, day: 2, weekday: Weekday::Sun,
                hour_div_12: 1, hour_mod_12: 1, minute: 39, second: 15
            ),
        );
        check(
            "20060102150405",
            &[num(Year), num(Month), num(Day), num(Hour), num(Minute), num(Second)],
            parsed!(
                year: 2006, month: 1, day: 2, hour_div_12: 1, hour_mod_12: 3, minute: 4, second: 5
            ),
        );
        check(
            "3:14PM",
            &[num(Hour12), Literal(":"), num(Minute), fixed(Fixed::LowerAmPm)],
            parsed!(hour_div_12: 1, hour_mod_12: 3, minute: 14),
        );
        check(
            "12345678901234.56789",
            &[num(Timestamp), Literal("."), num(Nanosecond)],
            parsed!(nanosecond: 56_789, timestamp: 12_345_678_901_234),
        );
        check(
            "12345678901234.56789",
            &[num(Timestamp), fixed(Fixed::Nanosecond)],
            parsed!(nanosecond: 567_890_000, timestamp: 12_345_678_901_234),
        );

        // docstring examples from `impl str::FromStr`
        check(
            "2000-01-02T03:04:05Z",
            &[
                num(Year), Literal("-"), num(Month), Literal("-"), num(Day), Literal("T"),
                num(Hour), Literal(":"), num(Minute), Literal(":"), num(Second),
                internal_fixed(TimezoneOffsetPermissive)
            ],
            parsed!(
                year: 2000, month: 1, day: 2, hour_div_12: 0, hour_mod_12: 3, minute: 4, second: 5,
                offset: 0
            ),
        );
        check(
            "2000-01-02 03:04:05Z",
            &[
                num(Year), Literal("-"), num(Month), Literal("-"), num(Day), Space(" "),
                num(Hour), Literal(":"), num(Minute), Literal(":"), num(Second),
                internal_fixed(TimezoneOffsetPermissive)
            ],
            parsed!(
                year: 2000, month: 1, day: 2, hour_div_12: 0, hour_mod_12: 3, minute: 4, second: 5,
                offset: 0
            ),
        );
    }

    #[track_caller]
    fn parses(s: &str, items: &[Item]) {
        let mut parsed = Parsed::new();
        assert!(parse(&mut parsed, s, items.iter()).is_ok());
    }

    #[track_caller]
    fn check(s: &str, items: &[Item], expected: ParseResult<Parsed>) {
        let mut parsed = Parsed::new();
        let result = parse(&mut parsed, s, items.iter());
        let parsed = result.map(|_| parsed);
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_issue_1010() {
        let dt = crate::extensions::chrono::NaiveDateTime::parse_from_str(
            "\u{c}SUN\u{e}\u{3000}\0m@J\u{3000}\0\u{3000}\0m\u{c}!\u{c}\u{b}\u{c}\u{c}\u{c}\u{c}%A\u{c}\u{b}\0SU\u{c}\u{c}",
            "\u{c}\u{c}%A\u{c}\u{b}\0SUN\u{c}\u{c}\u{c}SUNN\u{c}\u{c}\u{c}SUN\u{c}\u{c}!\u{c}\u{b}\u{c}\u{c}\u{c}\u{c}%A\u{c}\u{b}%a",
        );
        assert_eq!(dt, Err(ParseError(ParseErrorKind::Invalid)));
    }
}
