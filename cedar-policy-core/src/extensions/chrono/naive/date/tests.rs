// This file is `src/naive/date/tests.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; code
//   behind chrono's Cargo features (not enabled in Cedar) removed; code not used by Cedar removed.
use super::{NaiveDate, MAX_YEAR, MIN_YEAR};
use crate::extensions::chrono::naive::internals::{
    YearFlags, A, AG, B, BA, C, CB, D, DC, E, ED, F, FE, G, GF,
};
use crate::extensions::chrono::{Datelike, TimeDelta, Weekday};

#[test]
fn test_date_from_ymd() {
    let from_ymd = NaiveDate::from_ymd_opt;

    assert!(from_ymd(2012, 0, 1).is_none());
    assert!(from_ymd(2012, 1, 1).is_some());
    assert!(from_ymd(2012, 2, 29).is_some());
    assert!(from_ymd(2014, 2, 29).is_none());
    assert!(from_ymd(2014, 3, 0).is_none());
    assert!(from_ymd(2014, 3, 1).is_some());
    assert!(from_ymd(2014, 3, 31).is_some());
    assert!(from_ymd(2014, 3, 32).is_none());
    assert!(from_ymd(2014, 12, 31).is_some());
    assert!(from_ymd(2014, 13, 1).is_none());
}

#[test]
fn test_date_from_yo() {
    let from_yo = NaiveDate::from_yo_opt;
    let ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();

    assert_eq!(from_yo(2012, 0), None);
    assert_eq!(from_yo(2012, 1), Some(ymd(2012, 1, 1)));
    assert_eq!(from_yo(2012, 2), Some(ymd(2012, 1, 2)));
    assert_eq!(from_yo(2012, 32), Some(ymd(2012, 2, 1)));
    assert_eq!(from_yo(2012, 60), Some(ymd(2012, 2, 29)));
    assert_eq!(from_yo(2012, 61), Some(ymd(2012, 3, 1)));
    assert_eq!(from_yo(2012, 100), Some(ymd(2012, 4, 9)));
    assert_eq!(from_yo(2012, 200), Some(ymd(2012, 7, 18)));
    assert_eq!(from_yo(2012, 300), Some(ymd(2012, 10, 26)));
    assert_eq!(from_yo(2012, 366), Some(ymd(2012, 12, 31)));
    assert_eq!(from_yo(2012, 367), None);
    assert_eq!(from_yo(2012, (1 << 28) | 60), None);

    assert_eq!(from_yo(2014, 0), None);
    assert_eq!(from_yo(2014, 1), Some(ymd(2014, 1, 1)));
    assert_eq!(from_yo(2014, 2), Some(ymd(2014, 1, 2)));
    assert_eq!(from_yo(2014, 32), Some(ymd(2014, 2, 1)));
    assert_eq!(from_yo(2014, 59), Some(ymd(2014, 2, 28)));
    assert_eq!(from_yo(2014, 60), Some(ymd(2014, 3, 1)));
    assert_eq!(from_yo(2014, 100), Some(ymd(2014, 4, 10)));
    assert_eq!(from_yo(2014, 200), Some(ymd(2014, 7, 19)));
    assert_eq!(from_yo(2014, 300), Some(ymd(2014, 10, 27)));
    assert_eq!(from_yo(2014, 365), Some(ymd(2014, 12, 31)));
    assert_eq!(from_yo(2014, 366), None);
}

#[test]
fn test_date_from_isoywd() {
    let from_isoywd = NaiveDate::from_isoywd_opt;
    let ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();

    assert_eq!(from_isoywd(2004, 0, Weekday::Sun), None);
    assert_eq!(from_isoywd(2004, 1, Weekday::Mon), Some(ymd(2003, 12, 29)));
    assert_eq!(from_isoywd(2004, 1, Weekday::Sun), Some(ymd(2004, 1, 4)));
    assert_eq!(from_isoywd(2004, 2, Weekday::Mon), Some(ymd(2004, 1, 5)));
    assert_eq!(from_isoywd(2004, 2, Weekday::Sun), Some(ymd(2004, 1, 11)));
    assert_eq!(from_isoywd(2004, 52, Weekday::Mon), Some(ymd(2004, 12, 20)));
    assert_eq!(from_isoywd(2004, 52, Weekday::Sun), Some(ymd(2004, 12, 26)));
    assert_eq!(from_isoywd(2004, 53, Weekday::Mon), Some(ymd(2004, 12, 27)));
    assert_eq!(from_isoywd(2004, 53, Weekday::Sun), Some(ymd(2005, 1, 2)));
    assert_eq!(from_isoywd(2004, 54, Weekday::Mon), None);

    assert_eq!(from_isoywd(2011, 0, Weekday::Sun), None);
    assert_eq!(from_isoywd(2011, 1, Weekday::Mon), Some(ymd(2011, 1, 3)));
    assert_eq!(from_isoywd(2011, 1, Weekday::Sun), Some(ymd(2011, 1, 9)));
    assert_eq!(from_isoywd(2011, 2, Weekday::Mon), Some(ymd(2011, 1, 10)));
    assert_eq!(from_isoywd(2011, 2, Weekday::Sun), Some(ymd(2011, 1, 16)));

    assert_eq!(from_isoywd(2018, 51, Weekday::Mon), Some(ymd(2018, 12, 17)));
    assert_eq!(from_isoywd(2018, 51, Weekday::Sun), Some(ymd(2018, 12, 23)));
    assert_eq!(from_isoywd(2018, 52, Weekday::Mon), Some(ymd(2018, 12, 24)));
    assert_eq!(from_isoywd(2018, 52, Weekday::Sun), Some(ymd(2018, 12, 30)));
    assert_eq!(from_isoywd(2018, 53, Weekday::Mon), None);
}

#[test]
fn test_date_from_isoywd_and_iso_week() {
    for year in 2000..2401 {
        for week in 1..54 {
            for &weekday in [
                Weekday::Mon,
                Weekday::Tue,
                Weekday::Wed,
                Weekday::Thu,
                Weekday::Fri,
                Weekday::Sat,
                Weekday::Sun,
            ]
            .iter()
            {
                let d = NaiveDate::from_isoywd_opt(year, week, weekday);
                if let Some(d) = d {
                    assert_eq!(d.weekday(), weekday);
                    let w = d.iso_week();
                    assert_eq!(w.year(), year);
                    assert_eq!(w.week(), week);
                }
            }
        }
    }

    for year in 2000..2401 {
        for month in 1..13 {
            for day in 1..32 {
                let d = NaiveDate::from_ymd_opt(year, month, day);
                if let Some(d) = d {
                    let w = d.iso_week();
                    let d_ = NaiveDate::from_isoywd_opt(w.year(), w.week(), d.weekday());
                    assert_eq!(d, d_.unwrap());
                }
            }
        }
    }
}

#[test]
fn test_date_fields() {
    fn check(year: i32, month: u32, day: u32, ordinal: u32) {
        let d1 = NaiveDate::from_ymd_opt(year, month, day).unwrap();
        assert_eq!(d1.year(), year);
        assert_eq!(d1.month(), month);
        assert_eq!(d1.day(), day);
        assert_eq!(d1.ordinal(), ordinal);

        let d2 = NaiveDate::from_yo_opt(year, ordinal).unwrap();
        assert_eq!(d2.year(), year);
        assert_eq!(d2.month(), month);
        assert_eq!(d2.day(), day);
        assert_eq!(d2.ordinal(), ordinal);

        assert_eq!(d1, d2);
    }

    check(2012, 1, 1, 1);
    check(2012, 1, 2, 2);
    check(2012, 2, 1, 32);
    check(2012, 2, 29, 60);
    check(2012, 3, 1, 61);
    check(2012, 4, 9, 100);
    check(2012, 7, 18, 200);
    check(2012, 10, 26, 300);
    check(2012, 12, 31, 366);

    check(2014, 1, 1, 1);
    check(2014, 1, 2, 2);
    check(2014, 2, 1, 32);
    check(2014, 2, 28, 59);
    check(2014, 3, 1, 60);
    check(2014, 4, 10, 100);
    check(2014, 7, 19, 200);
    check(2014, 10, 27, 300);
    check(2014, 12, 31, 365);
}

#[test]
fn test_date_weekday() {
    assert_eq!(
        NaiveDate::from_ymd_opt(1582, 10, 15).unwrap().weekday(),
        Weekday::Fri
    );
    // May 20, 1875 = ISO 8601 reference date
    assert_eq!(
        NaiveDate::from_ymd_opt(1875, 5, 20).unwrap().weekday(),
        Weekday::Thu
    );
    assert_eq!(
        NaiveDate::from_ymd_opt(2000, 1, 1).unwrap().weekday(),
        Weekday::Sat
    );
}

#[test]
fn test_date_with_ordinal() {
    let d = NaiveDate::from_ymd_opt(2000, 5, 5).unwrap();
    assert_eq!(d.with_ordinal(0), None);
    assert_eq!(
        d.with_ordinal(1),
        Some(NaiveDate::from_ymd_opt(2000, 1, 1).unwrap())
    );
    assert_eq!(
        d.with_ordinal(60),
        Some(NaiveDate::from_ymd_opt(2000, 2, 29).unwrap())
    );
    assert_eq!(
        d.with_ordinal(61),
        Some(NaiveDate::from_ymd_opt(2000, 3, 1).unwrap())
    );
    assert_eq!(
        d.with_ordinal(366),
        Some(NaiveDate::from_ymd_opt(2000, 12, 31).unwrap())
    );
    assert_eq!(d.with_ordinal(367), None);
    assert_eq!(d.with_ordinal((1 << 28) | 60), None);
    let d = NaiveDate::from_ymd_opt(1999, 5, 5).unwrap();
    assert_eq!(d.with_ordinal(366), None);
    assert_eq!(d.with_ordinal(u32::MAX), None);
}

#[test]
fn test_date_num_days_from_ce() {
    assert_eq!(
        NaiveDate::from_ymd_opt(1, 1, 1).unwrap().num_days_from_ce(),
        1
    );

    for year in -9999..10001 {
        assert_eq!(
            NaiveDate::from_ymd_opt(year, 1, 1)
                .unwrap()
                .num_days_from_ce(),
            NaiveDate::from_ymd_opt(year - 1, 12, 31)
                .unwrap()
                .num_days_from_ce()
                + 1
        );
    }
}

#[test]
fn test_date_signed_duration_since() {
    fn check(lhs: Option<NaiveDate>, rhs: Option<NaiveDate>, delta: TimeDelta) {
        assert_eq!(lhs.unwrap().signed_duration_since(rhs.unwrap()), delta);
        assert_eq!(rhs.unwrap().signed_duration_since(lhs.unwrap()), -delta);
    }
    let ymd = NaiveDate::from_ymd_opt;

    check(ymd(2014, 1, 1), ymd(2014, 1, 1), TimeDelta::zero());
    check(
        ymd(2014, 1, 2),
        ymd(2014, 1, 1),
        TimeDelta::try_days(1).unwrap(),
    );
    check(
        ymd(2014, 12, 31),
        ymd(2014, 1, 1),
        TimeDelta::try_days(364).unwrap(),
    );
    check(
        ymd(2015, 1, 3),
        ymd(2014, 1, 1),
        TimeDelta::try_days(365 + 2).unwrap(),
    );
    check(
        ymd(2018, 1, 1),
        ymd(2014, 1, 1),
        TimeDelta::try_days(365 * 4 + 1).unwrap(),
    );
    check(
        ymd(2414, 1, 1),
        ymd(2014, 1, 1),
        TimeDelta::try_days(365 * 400 + 97).unwrap(),
    );

    check(
        ymd(MAX_YEAR, 12, 31),
        ymd(0, 1, 1),
        TimeDelta::try_days(MAX_DAYS_FROM_YEAR_0 as i64).unwrap(),
    );
    check(
        ymd(MIN_YEAR, 1, 1),
        ymd(0, 1, 1),
        TimeDelta::try_days(MIN_DAYS_FROM_YEAR_0 as i64).unwrap(),
    );
}

#[test]
fn test_date_addassignment() {
    let ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    let mut date = ymd(2016, 10, 1);
    date += TimeDelta::try_days(10).unwrap();
    assert_eq!(date, ymd(2016, 10, 11));
    date += TimeDelta::try_days(30).unwrap();
    assert_eq!(date, ymd(2016, 11, 10));
}

#[test]
fn test_date_subassignment() {
    let ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    let mut date = ymd(2016, 10, 11);
    date -= TimeDelta::try_days(10).unwrap();
    assert_eq!(date, ymd(2016, 10, 1));
    date -= TimeDelta::try_days(2).unwrap();
    assert_eq!(date, ymd(2016, 9, 29));
}

#[test]
fn test_date_fmt() {
    assert_eq!(
        format!("{:?}", NaiveDate::from_ymd_opt(2012, 3, 4).unwrap()),
        "2012-03-04"
    );
    assert_eq!(
        format!("{:?}", NaiveDate::from_ymd_opt(0, 3, 4).unwrap()),
        "0000-03-04"
    );
    assert_eq!(
        format!("{:?}", NaiveDate::from_ymd_opt(-307, 3, 4).unwrap()),
        "-0307-03-04"
    );
    assert_eq!(
        format!("{:?}", NaiveDate::from_ymd_opt(12345, 3, 4).unwrap()),
        "+12345-03-04"
    );

    assert_eq!(
        NaiveDate::from_ymd_opt(2012, 3, 4).unwrap().to_string(),
        "2012-03-04"
    );
    assert_eq!(
        NaiveDate::from_ymd_opt(0, 3, 4).unwrap().to_string(),
        "0000-03-04"
    );
    assert_eq!(
        NaiveDate::from_ymd_opt(-307, 3, 4).unwrap().to_string(),
        "-0307-03-04"
    );
    assert_eq!(
        NaiveDate::from_ymd_opt(12345, 3, 4).unwrap().to_string(),
        "+12345-03-04"
    );

    // the format specifier should have no effect on `NaiveTime`
    assert_eq!(
        format!("{:+30?}", NaiveDate::from_ymd_opt(1234, 5, 6).unwrap()),
        "1234-05-06"
    );
    assert_eq!(
        format!("{:30?}", NaiveDate::from_ymd_opt(12345, 6, 7).unwrap()),
        "+12345-06-07"
    );
}

#[test]
fn test_date_from_str() {
    // valid cases
    let valid = [
        "-0000000123456-1-2",
        "    -123456 - 1 - 2    ",
        "-12345-1-2",
        "-1234-12-31",
        "-7-6-5",
        "350-2-28",
        "360-02-29",
        "0360-02-29",
        "2015-2 -18",
        "2015-02-18",
        "+70-2-18",
        "+70000-2-18",
        "+00007-2-18",
    ];
    for &s in &valid {
        eprintln!("test_date_from_str valid {s:?}");
        let d = match s.parse::<NaiveDate>() {
            Ok(d) => d,
            Err(e) => panic!("parsing `{s}` has failed: {e}"),
        };
        eprintln!("d {d:?} (NaiveDate)");
        let s_ = format!("{d:?}");
        eprintln!("s_ {s_:?}");
        // `s` and `s_` may differ, but `s.parse()` and `s_.parse()` must be same
        let d_ = match s_.parse::<NaiveDate>() {
            Ok(d) => d,
            Err(e) => {
                panic!("`{s}` is parsed into `{d:?}`, but reparsing that has failed: {e}")
            }
        };
        eprintln!("d_ {d_:?} (NaiveDate)");
        assert!(
            d == d_,
            "`{s}` is parsed into `{d:?}`, but reparsed result \
                            `{d_:?}` does not match"
        );
    }

    // some invalid cases
    // since `ParseErrorKind` is private, all we can do is to check if there was an error
    let invalid = [
        "",                     // empty
        "x",                    // invalid
        "Fri, 09 Aug 2013 GMT", // valid date, wrong format
        "Sat Jun 30 2012",      // valid date, wrong format
        "1441497364.649",       // valid datetime, wrong format
        "+1441497364.649",      // valid datetime, wrong format
        "+1441497364",          // valid datetime, wrong format
        "2014/02/03",           // valid date, wrong format
        "2014",                 // datetime missing data
        "2014-01",              // datetime missing data
        "2014-01-00",           // invalid day
        "2014-11-32",           // invalid day
        "2014-13-01",           // invalid month
        "2014-13-57",           // invalid month, day
        "9999999-9-9",          // invalid year (out of bounds)
    ];
    for &s in &invalid {
        eprintln!("test_date_from_str invalid {s:?}");
        assert!(s.parse::<NaiveDate>().is_err());
    }
}

#[test]
fn test_date_parse_from_str() {
    let ymd = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    assert_eq!(
        NaiveDate::parse_from_str("2014-5-7T12:34:56+09:30", "%Y-%m-%dT%H:%M:%S%z"),
        Ok(ymd(2014, 5, 7))
    ); // ignore time and offset
    assert_eq!(
        NaiveDate::parse_from_str("2015-W06-1=2015-033 Q1", "%G-W%V-%u = %Y-%j Q%q"),
        Ok(ymd(2015, 2, 2))
    );
    assert_eq!(
        NaiveDate::parse_from_str("Fri, 09 Aug 13", "%a, %d %b %y"),
        Ok(ymd(2013, 8, 9))
    );
    assert!(NaiveDate::parse_from_str("Sat, 09 Aug 2013", "%a, %d %b %Y").is_err());
    assert!(NaiveDate::parse_from_str("2014-57", "%Y-%m-%d").is_err());
    assert!(NaiveDate::parse_from_str("2014", "%Y").is_err()); // insufficient

    assert!(NaiveDate::parse_from_str("2014-5-7 Q3", "%Y-%m-%d Q%q").is_err()); // mismatched quarter

    assert_eq!(
        NaiveDate::parse_from_str("2020-01-0", "%Y-%W-%w").ok(),
        NaiveDate::from_ymd_opt(2020, 1, 12),
    );

    assert_eq!(
        NaiveDate::parse_from_str("2019-01-0", "%Y-%W-%w").ok(),
        NaiveDate::from_ymd_opt(2019, 1, 13),
    );
}

#[test]
fn test_leap_year() {
    for year in 0..=MAX_YEAR {
        let date = NaiveDate::from_ymd_opt(year, 1, 1).unwrap();
        let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        assert_eq!(date.leap_year(), is_leap);
        assert_eq!(date.leap_year(), date.with_ordinal(366).is_some());
    }
}

#[test]
fn test_date_yearflags() {
    for (year, year_flags, _) in YEAR_FLAGS {
        assert_eq!(
            NaiveDate::from_yo_opt(year, 1).unwrap().year_flags(),
            year_flags
        );
    }
}

#[test]
fn test_isoweekdate_with_yearflags() {
    for (year, year_flags, _) in YEAR_FLAGS {
        // January 4 should be in the first week
        let jan4 = NaiveDate::from_ymd_opt(year, 1, 4).unwrap();
        let iso_week = jan4.iso_week();
        assert_eq!(jan4.year_flags(), year_flags);
        assert_eq!(iso_week.week(), 1);
    }
}

#[test]
fn test_date_to_mdf_to_date() {
    for (year, year_flags, _) in YEAR_FLAGS {
        for ordinal in 1..=year_flags.ndays() {
            let date = NaiveDate::from_yo_opt(year, ordinal).unwrap();
            assert_eq!(date, NaiveDate::from_mdf(date.year(), date.mdf()).unwrap());
        }
    }
}

// Used for testing some methods with all combinations of `YearFlags`.
// (year, flags, first weekday of year)
const YEAR_FLAGS: [(i32, YearFlags, Weekday); 14] = [
    (2006, A, Weekday::Sun),
    (2005, B, Weekday::Sat),
    (2010, C, Weekday::Fri),
    (2009, D, Weekday::Thu),
    (2003, E, Weekday::Wed),
    (2002, F, Weekday::Tue),
    (2001, G, Weekday::Mon),
    (2012, AG, Weekday::Sun),
    (2000, BA, Weekday::Sat),
    (2016, CB, Weekday::Fri),
    (2004, DC, Weekday::Thu),
    (2020, ED, Weekday::Wed),
    (2008, FE, Weekday::Tue),
    (2024, GF, Weekday::Mon),
];

//   MAX_YEAR-12-31 minus 0000-01-01
// = (MAX_YEAR-12-31 minus 0000-12-31) + (0000-12-31 - 0000-01-01)
// = MAX_YEAR * 365 + (# of leap years from 0001 to MAX_YEAR) + 365
// = (MAX_YEAR + 1) * 365 + (# of leap years from 0001 to MAX_YEAR)
const MAX_DAYS_FROM_YEAR_0: i32 =
    (MAX_YEAR + 1) * 365 + MAX_YEAR / 4 - MAX_YEAR / 100 + MAX_YEAR / 400;

//   MIN_YEAR-01-01 minus 0000-01-01
// = MIN_YEAR * 365 + (# of leap years from MIN_YEAR to 0000)
const MIN_DAYS_FROM_YEAR_0: i32 = MIN_YEAR * 365 + MIN_YEAR / 4 - MIN_YEAR / 100 + MIN_YEAR / 400;
