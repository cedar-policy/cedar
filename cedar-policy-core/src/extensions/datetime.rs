/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! This module contains the Cedar 'datetime' extension.

use chrono::{NaiveDate, NaiveDateTime, NaiveTime, TimeDelta};
use itertools::Itertools;
use regex::Regex;

// Unix time, represented internally as an integer.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
struct DateTime {
    epoch: NaiveDateTime,
}

fn get_d4(d1: &char, d2: &char, d3: &char, d4: &char) -> Option<u16> {
    Some(
        (d1.to_digit(10)? * 1000
            + d2.to_digit(10)? * 100
            + d3.to_digit(10)? * 10
            + d4.to_digit(10)?)
        .try_into()
        .unwrap(),
    )
}

fn get_d3(d1: &char, d2: &char, d3: &char) -> Option<u16> {
    Some(
        (d1.to_digit(10)? * 100 + d2.to_digit(10)? * 10 + d3.to_digit(10)?)
            .try_into()
            .unwrap(),
    )
}

fn get_d2(d1: &char, d2: &char) -> Option<u8> {
    Some(
        (d1.to_digit(10)? * 10 + d2.to_digit(10)?)
            .try_into()
            .unwrap(),
    )
}

fn get_date(
    y1: &char,
    y2: &char,
    y3: &char,
    y4: &char,
    m1: &char,
    m2: &char,
    d1: &char,
    d2: &char,
) -> Option<NaiveDate> {
    NaiveDate::from_ymd_opt(
        get_d4(y1, y2, y3, y4)?.into(),
        get_d2(m1, m2)?.into(),
        get_d2(d1, d2)?.into(),
    )
}

fn get_time_hms(
    h1: &char,
    h2: &char,
    mm1: &char,
    mm2: &char,
    s1: &char,
    s2: &char,
) -> Option<NaiveTime> {
    NaiveTime::from_hms_opt(
        get_d2(h1, h2)?.into(),
        get_d2(mm1, mm2)?.into(),
        get_d2(s1, s2)?.into(),
    )
}

fn get_time_hms_milli(
    h1: &char,
    h2: &char,
    mm1: &char,
    mm2: &char,
    s1: &char,
    s2: &char,
    ss1: &char,
    ss2: &char,
    ss3: &char,
) -> Option<NaiveTime> {
    NaiveTime::from_hms_micro_opt(
        get_d2(h1, h2)?.into(),
        get_d2(mm1, mm2)?.into(),
        get_d2(s1, s2)?.into(),
        get_d3(ss1, ss2, ss3)?.into(),
    )
}

fn get_offset(hh1: &char, hh2: &char, mmm1: &char, mmm2: &char) -> Option<TimeDelta> {
    let hour = get_d2(hh1, hh2)?;
    let minute = get_d2(mmm1, mmm2)?;
    if hour < 24 && minute < 60 {
        Some(TimeDelta::new(hour as i64 * 3600 + minute as i64 * 60, 0).unwrap())
    } else {
        None
    }
}

fn parse_duration(s: &str) -> Option<TimeDelta> {
    if s.len() < 2 {
        None
    } else {
        let duration_pattern =
            Regex::new(r"^-?([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?([0-9]+ms)?$").unwrap();
        let captures = duration_pattern.captures(s)?;
        let d: u64 = captures.get(1).map_or("0", |m| m.as_str()).parse().ok()?;
        let h: u64 = captures.get(2).map_or("0", |m| m.as_str()).parse().ok()?;
        let m: u64 = captures.get(3).map_or("0", |m| m.as_str()).parse().ok()?;
        let sec: u64 = captures.get(4).map_or("0", |m| m.as_str()).parse().ok()?;
        let ms: u16 = captures.get(5).map_or("0", |m| m.as_str()).parse().ok()?;
        let mut second: i64 = i64::checked_mul(d.try_into().ok()?, 24 * 3600)?;
        second = i64::checked_add(second, i64::checked_mul(h.try_into().ok()?, 3600)?)?;
        second = i64::checked_add(second, i64::checked_mul(m.try_into().ok()?, 60)?)?;
        second = i64::checked_add(second, sec.try_into().ok()?)?;
        if ms < 1000 {
            if s.starts_with('-') {
                Some(TimeDelta::new(-second, ms as u32 * 1_000_000)?)
            } else {
                Some(TimeDelta::new(second, ms as u32 * 1_000_000)?)
            }
        } else {
            None
        }
    }
}

fn parse_datetime(s: &str) -> Option<NaiveDateTime> {
    if s.len() > 28 {
        return None;
    }
    match s.chars().collect_vec().as_slice() {
        [y1, y2, y3, y4, '-', m1, m2, '-', d1, d2] => Some(NaiveDateTime::new(
            get_date(y1, y2, y3, y4, m1, m2, d1, d2)?,
            NaiveTime::from_hms_opt(0, 0, 0)?,
        )),
        [y1, y2, y3, y4, '-', m1, m2, '-', d1, d2, 'T', h1, h2, ':', mm1, mm2, ':', s1, s2, 'Z'] => {
            Some(NaiveDateTime::new(
                get_date(y1, y2, y3, y4, m1, m2, d1, d2)?,
                get_time_hms(h1, h2, mm1, mm2, s1, s2)?,
            ))
        }
        [y1, y2, y3, y4, '-', m1, m2, '-', d1, d2, 'T', h1, h2, ':', mm1, mm2, ':', s1, s2, '.', ss1, ss2, ss3, 'Z'] => {
            Some(NaiveDateTime::new(
                get_date(y1, y2, y3, y4, m1, m2, d1, d2)?,
                get_time_hms_milli(h1, h2, mm1, mm2, s1, s2, ss1, ss2, ss3)?,
            ))
        }
        [y1, y2, y3, y4, '-', m1, m2, '-', d1, d2, 'T', h1, h2, ':', mm1, mm2, ':', s1, s2, '+', hh1, hh2, mmm1, mmm2] => {
            Some(
                NaiveDateTime::new(
                    get_date(y1, y2, y3, y4, m1, m2, d1, d2)?,
                    get_time_hms(h1, h2, mm1, mm2, s1, s2)?,
                ) + get_offset(hh1, hh2, mmm1, mmm2)?,
            )
        }
        [y1, y2, y3, y4, '-', m1, m2, '-', d1, d2, 'T', h1, h2, ':', mm1, mm2, ':', s1, s2, '-', hh1, hh2, mmm1, mmm2] => {
            Some(
                NaiveDateTime::new(
                    get_date(y1, y2, y3, y4, m1, m2, d1, d2)?,
                    get_time_hms(h1, h2, mm1, mm2, s1, s2)?,
                ) - get_offset(hh1, hh2, mmm1, mmm2)?,
            )
        }
        [y1, y2, y3, y4, '-', m1, m2, '-', d1, d2, 'T', h1, h2, ':', mm1, mm2, ':', s1, s2, '.', ss1, ss2, ss3, '+', hh1, hh2, mmm1, mmm2] => {
            Some(
                NaiveDateTime::new(
                    get_date(y1, y2, y3, y4, m1, m2, d1, d2)?,
                    get_time_hms_milli(h1, h2, mm1, mm2, s1, s2, ss1, ss2, ss3)?,
                ) + get_offset(hh1, hh2, mmm1, mmm2)?,
            )
        }
        [y1, y2, y3, y4, '-', m1, m2, '-', d1, d2, 'T', h1, h2, ':', mm1, mm2, ':', s1, s2, '.', ss1, ss2, ss3, '-', hh1, hh2, mmm1, mmm2] => {
            Some(
                NaiveDateTime::new(
                    get_date(y1, y2, y3, y4, m1, m2, d1, d2)?,
                    get_time_hms_milli(h1, h2, mm1, mm2, s1, s2, ss1, ss2, ss3)?,
                ) - get_offset(hh1, hh2, mmm1, mmm2)?,
            )
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use cool_asserts::assert_matches;

    use crate::extensions::datetime::parse_datetime;

    #[test]
    fn test_parse_pos() {
        let s = "2024-10-15";
        assert_matches!(parse_datetime(s), Some(_));
        let s = "2024-10-15T11:38:02Z";
        assert_matches!(parse_datetime(s), Some(_));
        let s = "2024-10-15T11:38:02.101Z";
        assert_matches!(parse_datetime(s), Some(_));
        let s = "2024-10-15T11:38:02.101+1234";
        assert_matches!(parse_datetime(s), Some(_));
        let s = "2024-10-15T11:38:02.101-1234";
        assert_matches!(parse_datetime(s), Some(_));

        let s = "2024-10-15T11:38:02+1234";
        assert_matches!(parse_datetime(s), Some(_));

        let s = "2024-10-15T11:38:02-1234";
        assert_matches!(parse_datetime(s), Some(_));
    }

    #[test]
    fn test_parse_neg() {
        for s in [
            "",
            "a",
            "-",
            "-1",
            "11-12-13",
            "1111-1x-20",
            "2024-10-15Z",
            "2024-10-15T11:38:02ZZ",
        ] {
            assert!(parse_datetime(s).is_none());
        }
    }

    #[test]
    fn parse_duration_pos() {}
}
