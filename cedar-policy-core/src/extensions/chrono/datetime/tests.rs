// This file is `src/datetime/tests.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; code
//   behind chrono's Cargo features (not enabled in Cedar) removed; code not used by Cedar removed.
use super::DateTime;
use crate::extensions::chrono::naive::NaiveDate;
use crate::extensions::chrono::offset::{FixedOffset, Offset, TimeZone, Utc};
use crate::extensions::chrono::NaiveDateTime;

#[test]
fn test_datetime_from_timestamp_secs() {
    let valid = [-2208936075, 0, 119731017, 1234567890, 2034061609];

    for timestamp_secs in valid.iter().copied() {
        let datetime = DateTime::from_timestamp_secs(timestamp_secs).unwrap();
        assert_eq!(timestamp_secs, datetime.timestamp());
        assert_eq!(DateTime::from_timestamp(timestamp_secs, 0).unwrap(), datetime);
    }
}

#[test]
fn test_datetime_from_timestamp() {
    let ymdhms = |y, m, d, h, n, s| {
        NaiveDate::from_ymd_opt(y, m, d).unwrap().and_hms_opt(h, n, s).unwrap().and_utc()
    };
    assert_eq!(DateTime::from_timestamp_secs(-1), Some(ymdhms(1969, 12, 31, 23, 59, 59)));
    assert_eq!(DateTime::from_timestamp_secs(0), Some(ymdhms(1970, 1, 1, 0, 0, 0)));
    assert_eq!(DateTime::from_timestamp_secs(1), Some(ymdhms(1970, 1, 1, 0, 0, 1)));
    assert_eq!(DateTime::from_timestamp_secs(1_000_000_000), Some(ymdhms(2001, 9, 9, 1, 46, 40)));
    assert_eq!(DateTime::from_timestamp_secs(0x7fffffff), Some(ymdhms(2038, 1, 19, 3, 14, 7)));
    assert_eq!(DateTime::from_timestamp_secs(i64::MIN), None);
    assert_eq!(DateTime::from_timestamp_secs(i64::MAX), None);
}

#[test]
fn test_datetime_timestamp() {
    let to_timestamp = |y, m, d, h, n, s| {
        NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, n, s)
            .unwrap()
            .and_utc()
            .timestamp()
    };
    assert_eq!(to_timestamp(1969, 12, 31, 23, 59, 59), -1);
    assert_eq!(to_timestamp(1970, 1, 1, 0, 0, 0), 0);
    assert_eq!(to_timestamp(1970, 1, 1, 0, 0, 1), 1);
    assert_eq!(to_timestamp(2001, 9, 9, 1, 46, 40), 1_000_000_000);
    assert_eq!(to_timestamp(2038, 1, 19, 3, 14, 7), 0x7fffffff);
}

#[test]
fn test_parse_datetime_utc() {
    // valid cases
    let valid = [
        "2001-02-03T04:05:06Z",
        "2001-02-03T04:05:06+0000",
        "2001-02-03T04:05:06-00:00",
        "2001-02-03T04:05:06-01:00",
        "2012-12-12 12:12:12Z",
        "2012-12-12t12:12:12Z",
        "2012-12-12T12:12:12Z",
        "2012 -12-12T12:12:12Z",
        "2012  -12-12T12:12:12Z",
        "2012- 12-12T12:12:12Z",
        "2012-  12-12T12:12:12Z",
        "2012-12-12T 12:12:12Z",
        "2012-12-12T12 :12:12Z",
        "2012-12-12T12  :12:12Z",
        "2012-12-12T12: 12:12Z",
        "2012-12-12T12:  12:12Z",
        "2012-12-12T12 : 12:12Z",
        "2012-12-12T12:12:12Z ",
        " 2012-12-12T12:12:12Z",
        "2015-02-18T23:16:09.153Z",
        "2015-2-18T23:16:09.153Z",
        "+2015-2-18T23:16:09.153Z",
        "-77-02-18T23:16:09Z",
        "+82701-05-6T15:9:60.898989898989Z",
    ];
    for &s in &valid {
        eprintln!("test_parse_datetime_utc valid {s:?}");
        let d = match s.parse::<DateTime<Utc>>() {
            Ok(d) => d,
            Err(e) => panic!("parsing `{s}` has failed: {e}"),
        };
        let s_ = format!("{d:?}");
        // `s` and `s_` may differ, but `s.parse()` and `s_.parse()` must be same
        let d_ = match s_.parse::<DateTime<Utc>>() {
            Ok(d) => d,
            Err(e) => {
                panic!("`{s}` is parsed into `{d:?}`, but reparsing that has failed: {e}")
            }
        };
        assert!(
            d == d_,
            "`{s}` is parsed into `{d:?}`, but reparsed result `{d_:?}` does not match"
        );
    }

    // some invalid cases
    // since `ParseErrorKind` is private, all we can do is to check if there was an error
    let invalid = [
        "",                                                          // empty
        "Z",                                                         // missing data
        "15Z",                                                       // missing data
        "15:8:9Z",                                                   // missing date
        "15-8-9Z",                                                   // missing time or date
        "Fri, 09 Aug 2013 23:54:35 GMT",                             // valid datetime, wrong format
        "Sat Jun 30 23:59:60 2012",                                  // valid datetime, wrong format
        "1441497364.649",                                            // valid datetime, wrong format
        "+1441497364.649",                                           // valid datetime, wrong format
        "+1441497364",                                               // valid datetime, wrong format
        "+1441497364Z",                                              // valid datetime, wrong format
        "2014/02/03 04:05:06Z",                                      // valid datetime, wrong format
        "2001-02-03T04:05:0600:00", // valid datetime, timezone too close
        "2015-15-15T15:15:15Z",     // invalid datetime
        "2012-12-12T12:12:12x",     // invalid timezone
        "2012-123-12T12:12:12Z",    // invalid month
        "2012-12-77T12:12:12Z",     // invalid day
        "2012-12-12T26:12:12Z",     // invalid hour
        "2012-12-12T12:61:12Z",     // invalid minute
        "2012-12-12T12:12:62Z",     // invalid second
        "2012-12-12 T12:12:12Z",    // space after date
        "2012-12-12T12:12:12ZZ",    // trailing literal 'Z'
        "+802701-12-12T12:12:12Z",  // invalid year (out of bounds)
        "+ 2012-12-12T12:12:12Z",   // invalid space before year
        "  +82701  -  05  -  6  T  15  :  9  : 60.898989898989   Z", // valid datetime, wrong format
    ];
    for &s in &invalid {
        eprintln!("test_parse_datetime_utc invalid {s:?}");
        assert!(s.parse::<DateTime<Utc>>().is_err());
    }
}

#[test]
fn test_datetime_is_send_and_copy() {
    #[derive(Clone)]
    struct Tz {
        _not_send: *const i32,
    }
    impl TimeZone for Tz {
        type Offset = Off;

        fn from_offset(_: &Self::Offset) -> Self {
            unimplemented!()
        }
        fn offset_from_local_datetime(
            &self,
            _: &NaiveDateTime,
        ) -> crate::extensions::chrono::offset::MappedLocalTime<Self::Offset> {
            unimplemented!()
        }
        fn offset_from_utc_datetime(&self, _: &NaiveDateTime) -> Self::Offset {
            unimplemented!()
        }
    }

    #[derive(Copy, Clone, Debug)]
    struct Off(());
    impl Offset for Off {
        fn fix(&self) -> FixedOffset {
            unimplemented!()
        }
    }

    fn _assert_send_copy<T: Send + Copy>() {}
    // `DateTime` is `Send + Copy` if the offset is.
    _assert_send_copy::<DateTime<Tz>>();
}

// Some targets, such as `wasm32-wasi`, have a problematic definition of `SystemTime`, such as an
// `i32` (year 2035 problem), or an `u64` (no values before `UNIX-EPOCH`).
// See https://github.com/rust-lang/rust/issues/44394.

