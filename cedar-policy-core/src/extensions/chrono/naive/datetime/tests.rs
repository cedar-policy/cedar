// This file is `src/naive/datetime/tests.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; code
//   behind chrono's Cargo features (not enabled in Cedar) removed; code not used by Cedar removed.
use super::NaiveDateTime;
use crate::extensions::chrono::{NaiveDate, TimeDelta, Utc};

#[test]
fn test_datetime_sub() {
    let ymdhms = |y, m, d, h, n, s| {
        NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, n, s)
            .unwrap()
    };
    let since = NaiveDateTime::signed_duration_since;
    assert_eq!(
        since(ymdhms(2014, 5, 6, 7, 8, 9), ymdhms(2014, 5, 6, 7, 8, 9)),
        TimeDelta::zero()
    );
    assert_eq!(
        since(ymdhms(2014, 5, 6, 7, 8, 10), ymdhms(2014, 5, 6, 7, 8, 9)),
        TimeDelta::try_seconds(1).unwrap()
    );
    assert_eq!(
        since(ymdhms(2014, 5, 6, 7, 8, 9), ymdhms(2014, 5, 6, 7, 8, 10)),
        TimeDelta::try_seconds(-1).unwrap()
    );
    assert_eq!(
        since(ymdhms(2014, 5, 7, 7, 8, 9), ymdhms(2014, 5, 6, 7, 8, 10)),
        TimeDelta::try_seconds(86399).unwrap()
    );
    assert_eq!(
        since(ymdhms(2001, 9, 9, 1, 46, 39), ymdhms(1970, 1, 1, 0, 0, 0)),
        TimeDelta::try_seconds(999_999_999).unwrap()
    );
}

#[test]
fn test_core_duration_ops() {
    use core::time::Duration;

    let mut dt = NaiveDate::from_ymd_opt(2023, 8, 29)
        .unwrap()
        .and_hms_opt(11, 34, 12)
        .unwrap();
    let same = dt + Duration::ZERO;
    assert_eq!(dt, same);

    dt += Duration::new(3600, 0);
    assert_eq!(
        dt,
        NaiveDate::from_ymd_opt(2023, 8, 29)
            .unwrap()
            .and_hms_opt(12, 34, 12)
            .unwrap()
    );
}

#[test]
#[should_panic]
fn test_core_duration_max() {
    use core::time::Duration;

    let mut utc_dt = NaiveDate::from_ymd_opt(2023, 8, 29)
        .unwrap()
        .and_hms_opt(11, 34, 12)
        .unwrap();
    utc_dt += Duration::MAX;
}

#[test]
fn test_datetime_from_str() {
    // valid cases
    let valid = [
        "2001-02-03T04:05:06",
        "2012-12-12T12:12:12",
        "2015-02-18T23:16:09.153",
        "2015-2-18T23:16:09.153",
        "-77-02-18T23:16:09",
        "+82701-05-6T15:9:60.898989898989",
        "  +82701  -  05  -  6  T  15  :  9  : 60.898989898989   ",
    ];
    for &s in &valid {
        eprintln!("test_parse_naivedatetime valid {s:?}");
        let d = match s.parse::<NaiveDateTime>() {
            Ok(d) => d,
            Err(e) => panic!("parsing `{s}` has failed: {e}"),
        };
        let s_ = format!("{d:?}");
        // `s` and `s_` may differ, but `s.parse()` and `s_.parse()` must be same
        let d_ = match s_.parse::<NaiveDateTime>() {
            Ok(d) => d,
            Err(e) => {
                panic!("`{s}` is parsed into `{d:?}`, but reparsing that has failed: {e}")
            }
        };
        assert!(
            d == d_,
            "`{s}` is parsed into `{d:?}`, but reparsed result \
             `{d_:?}` does not match"
        );
    }

    // some invalid cases
    // since `ParseErrorKind` is private, all we can do is to check if there was an error
    let invalid = [
        "",                              // empty
        "x",                             // invalid / missing data
        "15",                            // missing data
        "15:8:9",                        // looks like a time (invalid date)
        "15-8-9",                        // looks like a date (invalid)
        "Fri, 09 Aug 2013 23:54:35 GMT", // valid date, wrong format
        "Sat Jun 30 23:59:60 2012",      // valid date, wrong format
        "1441497364.649",                // valid date, wrong format
        "+1441497364.649",               // valid date, wrong format
        "+1441497364",                   // valid date, wrong format
        "2014/02/03 04:05:06",           // valid date, wrong format
        "2015-15-15T15:15:15",           // invalid date
        "2012-12-12T12:12:12x",          // bad timezone / trailing literal
        "2012-12-12T12:12:12+00:00",     // unexpected timezone / trailing literal
        "2012-12-12T12:12:12 +00:00",    // unexpected timezone / trailing literal
        "2012-12-12T12:12:12 GMT",       // unexpected timezone / trailing literal
        "2012-123-12T12:12:12",          // invalid month
        "2012-12-12t12:12:12",           // bad divider 't'
        "2012-12-12 12:12:12",           // missing divider 'T'
        "2012-12-12T12:12:12Z",          // trailing char 'Z'
        "+ 82701-123-12T12:12:12",       // strange year, invalid month
        "+802701-123-12T12:12:12",       // out-of-bound year, invalid month
    ];
    for &s in &invalid {
        eprintln!("test_datetime_from_str invalid {s:?}");
        assert!(s.parse::<NaiveDateTime>().is_err());
    }
}

#[test]
fn test_datetime_parse_from_str_with_spaces() {
    let parse_from_str = NaiveDateTime::parse_from_str;
    let dt = NaiveDate::from_ymd_opt(2013, 8, 9)
        .unwrap()
        .and_hms_opt(23, 54, 35)
        .unwrap();
    // with varying spaces - should succeed
    assert_eq!(
        parse_from_str(" Aug 09 2013 23:54:35", " %b %d %Y %H:%M:%S"),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("Aug 09 2013 23:54:35 ", "%b %d %Y %H:%M:%S "),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str(" Aug 09 2013  23:54:35 ", " %b %d %Y  %H:%M:%S "),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("  Aug 09 2013 23:54:35", "  %b %d %Y %H:%M:%S"),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("   Aug 09 2013 23:54:35", "   %b %d %Y %H:%M:%S"),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("\n\tAug 09 2013 23:54:35  ", "\n\t%b %d %Y %H:%M:%S  "),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("\tAug 09 2013 23:54:35\t", "\t%b %d %Y %H:%M:%S\t"),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("Aug  09 2013 23:54:35", "%b  %d %Y %H:%M:%S"),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("Aug    09 2013 23:54:35", "%b    %d %Y %H:%M:%S"),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("Aug  09 2013\t23:54:35", "%b  %d %Y\t%H:%M:%S"),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("Aug  09 2013\t\t23:54:35", "%b  %d %Y\t\t%H:%M:%S"),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("Aug 09 2013 23:54:35 ", "%b %d %Y %H:%M:%S\n"),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("Aug 09 2013 23:54:35", "%b %d %Y\t%H:%M:%S"),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("Aug 09 2013 23:54:35", "%b %d %Y %H:%M:%S "),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("Aug 09 2013 23:54:35", " %b %d %Y %H:%M:%S"),
        Ok(dt)
    );
    assert_eq!(
        parse_from_str("Aug 09 2013 23:54:35", "%b %d %Y %H:%M:%S\n"),
        Ok(dt)
    );
    // with varying spaces - should fail
    // leading space in data
    assert!(parse_from_str(" Aug 09 2013 23:54:35", "%b %d %Y %H:%M:%S").is_err());
    // trailing space in data
    assert!(parse_from_str("Aug 09 2013 23:54:35 ", "%b %d %Y %H:%M:%S").is_err());
    // trailing tab in data
    assert!(parse_from_str("Aug 09 2013 23:54:35\t", "%b %d %Y %H:%M:%S").is_err());
    // mismatched newlines
    assert!(parse_from_str("\nAug 09 2013 23:54:35", "%b %d %Y %H:%M:%S\n").is_err());
    // trailing literal in data
    assert!(parse_from_str("Aug 09 2013 23:54:35 !!!", "%b %d %Y %H:%M:%S ").is_err());
}

#[test]
fn test_and_utc() {
    let ndt = NaiveDate::from_ymd_opt(2023, 1, 30)
        .unwrap()
        .and_hms_opt(19, 32, 33)
        .unwrap();
    let dt_utc = ndt.and_utc();
    assert_eq!(dt_utc.naive_local(), ndt);
    assert_eq!(dt_utc.timezone(), Utc);
}
