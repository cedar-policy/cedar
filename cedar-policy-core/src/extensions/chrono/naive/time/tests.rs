// This file is `src/naive/time/tests.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; code
//   behind chrono's Cargo features (not enabled in Cedar) removed; code not used by Cedar removed.
use super::NaiveTime;
use crate::extensions::chrono::FixedOffset;

#[test]
fn test_time_from_hms_milli() {
    assert_eq!(
        NaiveTime::from_hms_milli_opt(3, 5, 7, 0),
        Some(NaiveTime::from_hms_nano_opt(3, 5, 7, 0).unwrap())
    );
    assert_eq!(
        NaiveTime::from_hms_milli_opt(3, 5, 7, 777),
        Some(NaiveTime::from_hms_nano_opt(3, 5, 7, 777_000_000).unwrap())
    );
    assert_eq!(
        NaiveTime::from_hms_milli_opt(3, 5, 59, 1_999),
        Some(NaiveTime::from_hms_nano_opt(3, 5, 59, 1_999_000_000).unwrap())
    );
    assert_eq!(NaiveTime::from_hms_milli_opt(3, 5, 59, 2_000), None);
    assert_eq!(NaiveTime::from_hms_milli_opt(3, 5, 59, 5_000), None); // overflow check
    assert_eq!(NaiveTime::from_hms_milli_opt(3, 5, 59, u32::MAX), None);
}

#[test]
fn test_core_duration_ops() {
    use core::time::Duration;

    let mut t = NaiveTime::from_hms_opt(11, 34, 23).unwrap();
    let same = t + Duration::ZERO;
    assert_eq!(t, same);

    t += Duration::new(3600, 0);
    assert_eq!(t, NaiveTime::from_hms_opt(12, 34, 23).unwrap());

    t -= Duration::new(7200, 0);
    assert_eq!(t, NaiveTime::from_hms_opt(10, 34, 23).unwrap());
}

#[test]
fn test_time_from_str() {
    // valid cases
    let valid = [
        "0:0:0",
        "0:0:0.0000000",
        "0:0:0.0000003",
        " 4 : 3 : 2.1 ",
        " 09:08:07 ",
        " 09:08 ",
        " 9:8:07 ",
        "01:02:03",
        "4:3:2.1",
        "9:8:7",
        "09:8:7",
        "9:08:7",
        "9:8:07",
        "09:08:7",
        "09:8:07",
        "09:08:7",
        "9:08:07",
        "09:08:07",
        "9:8:07.123",
        "9:08:7.123",
        "09:8:7.123",
        "09:08:7.123",
        "9:08:07.123",
        "09:8:07.123",
        "09:08:07.123",
        "09:08:07.123",
        "09:08:07.1234",
        "09:08:07.12345",
        "09:08:07.123456",
        "09:08:07.1234567",
        "09:08:07.12345678",
        "09:08:07.123456789",
        "09:08:07.1234567891",
        "09:08:07.12345678912",
        "23:59:60.373929310237",
    ];
    for &s in &valid {
        eprintln!("test_time_parse_from_str valid {s:?}");
        let d = match s.parse::<NaiveTime>() {
            Ok(d) => d,
            Err(e) => panic!("parsing `{s}` has failed: {e}"),
        };
        let s_ = format!("{d:?}");
        // `s` and `s_` may differ, but `s.parse()` and `s_.parse()` must be same
        let d_ = match s_.parse::<NaiveTime>() {
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
        "",                  // empty
        "x",                 // invalid
        "15",                // missing data
        "15:8:",             // trailing colon
        "15:8:x",            // invalid data
        "15:8:9x",           // invalid data
        "23:59:61",          // invalid second (out of bounds)
        "23:54:35 GMT",      // invalid (timezone non-sensical for NaiveTime)
        "23:54:35 +0000",    // invalid (timezone non-sensical for NaiveTime)
        "1441497364.649",    // valid datetime, not a NaiveTime
        "+1441497364.649",   // valid datetime, not a NaiveTime
        "+1441497364",       // valid datetime, not a NaiveTime
        "001:02:03",         // invalid hour
        "01:002:03",         // invalid minute
        "01:02:003",         // invalid second
        "12:34:56.x",        // invalid fraction
        "12:34:56. 0",       // invalid fraction format
        "09:08:00000000007", // invalid second / invalid fraction format
    ];
    for &s in &invalid {
        eprintln!("test_time_parse_from_str invalid {s:?}");
        assert!(s.parse::<NaiveTime>().is_err());
    }
}

#[test]
fn test_overflowing_offset() {
    let hmsm = |h, m, s, n| NaiveTime::from_hms_milli_opt(h, m, s, n).unwrap();

    let positive_offset = FixedOffset::east_opt(4 * 60 * 60).unwrap();
    // regular time
    let t = hmsm(5, 6, 7, 890);
    assert_eq!(t.overflowing_add_offset(positive_offset), (hmsm(9, 6, 7, 890), 0));
    assert_eq!(t.overflowing_sub_offset(positive_offset), (hmsm(1, 6, 7, 890), 0));
    // leap second is preserved, and wrap to next day
    let t = hmsm(23, 59, 59, 1_000);
    assert_eq!(t.overflowing_add_offset(positive_offset), (hmsm(3, 59, 59, 1_000), 1));
    assert_eq!(t.overflowing_sub_offset(positive_offset), (hmsm(19, 59, 59, 1_000), 0));
    // wrap to previous day
    let t = hmsm(1, 2, 3, 456);
    assert_eq!(t.overflowing_sub_offset(positive_offset), (hmsm(21, 2, 3, 456), -1));
    // an odd offset
    let negative_offset = FixedOffset::west_opt(((2 * 60) + 3) * 60 + 4).unwrap();
    let t = hmsm(5, 6, 7, 890);
    assert_eq!(t.overflowing_add_offset(negative_offset), (hmsm(3, 3, 3, 890), 0));
    assert_eq!(t.overflowing_sub_offset(negative_offset), (hmsm(7, 9, 11, 890), 0));

    assert_eq!(t.overflowing_add_offset(positive_offset).0, t + positive_offset);
    assert_eq!(t.overflowing_sub_offset(positive_offset).0, t - positive_offset);
}

