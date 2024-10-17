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
use regex::Regex;

// The `datetime` type, represented internally as an `i64`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
struct DateTime {
    // The number of non-leap milliseconds from the Unix epoch
    epoch: i64,
}

impl DateTime {
    const DAY_IN_MILLISECONDS: i64 = 1000 * 3600 * 24;

    fn offset(&self, duration: Duration) -> Option<Self> {
        self.epoch
            .checked_add(duration.ms)
            .map(|epoch| Self { epoch })
    }

    fn durationSince(&self, other: DateTime) -> Option<Duration> {
        self.epoch
            .checked_sub(other.epoch)
            .map(|ms| Duration { ms })
    }

    fn toDate(&self) -> Self {
        Self {
            epoch: self.epoch / Self::DAY_IN_MILLISECONDS,
        }
    }

    fn toTime(&self) -> Self {
        Self {
            epoch: self.epoch % Self::DAY_IN_MILLISECONDS,
        }
    }
}

impl From<NaiveDateTime> for DateTime {
    fn from(value: NaiveDateTime) -> Self {
        let delta = value - NaiveDateTime::UNIX_EPOCH;
        Self {
            epoch: delta.num_milliseconds(),
        }
    }
}

// The `duration` type
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Duration {
    // The number of milliseconds
    ms: i64,
}

impl Duration {
    fn toMilliseconds(&self) -> i64 {
        self.ms
    }

    fn toSeconds(&self) -> i64 {
        self.toMilliseconds() / 1000
    }

    fn toMinutes(&self) -> i64 {
        self.toSeconds() / 60
    }

    fn toHours(&self) -> i64 {
        self.toMinutes() / 60
    }

    fn toDays(&self) -> i64 {
        self.toHours() / 24
    }
}

fn parse_duration(s: &str) -> Option<Duration> {
    if s.len() < 2 {
        None
    } else {
        let duration_pattern =
            Regex::new(r"^-?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?$")
                .unwrap();
        let captures = duration_pattern.captures(s)?;
        let d: u64 = captures.get(2).map_or("0", |m| m.as_str()).parse().ok()?;
        let h: u64 = captures.get(4).map_or("0", |m| m.as_str()).parse().ok()?;
        let m: u64 = captures.get(6).map_or("0", |m| m.as_str()).parse().ok()?;
        let sec: u64 = captures.get(8).map_or("0", |m| m.as_str()).parse().ok()?;
        let ms: u16 = captures.get(10).map_or("0", |m| m.as_str()).parse().ok()?;
        if s.starts_with('-') {
            let mut ms = i64::try_from(-(ms as i128)).ok()?;
            ms = ms.checked_sub(i64::checked_mul(sec.try_into().ok()?, 1000)?)?;
            ms = ms.checked_sub(i64::checked_mul(m.try_into().ok()?, 1000 * 60)?)?;
            ms = ms.checked_sub(i64::checked_mul(h.try_into().ok()?, 1000 * 60 * 60)?)?;
            ms = ms.checked_sub(i64::checked_mul(d.try_into().ok()?, 1000 * 60 * 60 * 24)?)?;
            Some(Duration { ms })
        } else {
            let mut ms = i64::try_from(ms).ok()?;
            ms = ms.checked_add(i64::checked_mul(sec.try_into().ok()?, 1000)?)?;
            ms = ms.checked_add(i64::checked_mul(m.try_into().ok()?, 1000 * 60)?)?;
            ms = ms.checked_add(i64::checked_mul(h.try_into().ok()?, 1000 * 60 * 60)?)?;
            ms = ms.checked_add(i64::checked_mul(d.try_into().ok()?, 1000 * 60 * 60 * 24)?)?;
            Some(Duration { ms })
        }
    }
}

fn parse_datetime(s: &str) -> Option<NaiveDateTime> {
    // Get date first
    let date_pattern = Regex::new(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})").unwrap();
    let (date_str, [year, month, day]) = date_pattern.captures(s)?.extract();
    let date = NaiveDate::from_ymd_opt(
        year.parse().unwrap(),
        month.parse().unwrap(),
        day.parse().unwrap(),
    )?;

    // A complete match; simply return
    if date_str.len() == s.len() {
        return Some(NaiveDateTime::new(
            date,
            NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
        ));
    }

    // Get hour, minute, and second
    let s = &s[date_str.len()..];
    let hms_pattern = Regex::new(r"^T([0-9]{2}):([0-9]{2}):([0-9]{2})").unwrap();
    let (hms_str, [h, m, sec]) = hms_pattern.captures(s)?.extract();
    let h: u32 = h.parse().unwrap();
    let m: u32 = m.parse().unwrap();
    let sec: u32 = sec.parse().unwrap();

    // Get millisecond and offset
    let s = &s[hms_str.len()..];
    let ms_and_offset_pattern =
        Regex::new(r"^(\.([0-9]{3}))?(Z|((\+|-)([0-9]{2})([0-9]{2})))$").unwrap();
    let captures = ms_and_offset_pattern.captures(s)?;
    let ms: u32 = if captures.get(1).is_some() {
        captures[2].parse().unwrap()
    } else {
        0
    };
    let offset: Option<TimeDelta> = if captures.get(4).is_some() {
        let sign = &captures[5] == "+";
        let offset_hour: u32 = captures[6].parse().unwrap();
        let offset_min: u32 = captures[7].parse().unwrap();
        if offset_hour < 24 && offset_min < 60 {
            let offset_in_secs = (offset_hour * 3600 + offset_min * 60) as i64;
            Some(
                TimeDelta::new(
                    if sign {
                        offset_in_secs
                    } else {
                        -offset_in_secs
                    },
                    0,
                )
                .unwrap(),
            )
        } else {
            None
        }
    } else {
        Some(TimeDelta::default())
    };
    let time = NaiveTime::from_hms_milli_opt(h, m, sec, ms)? + offset?;
    Some(NaiveDateTime::new(date, time))
}

#[cfg(test)]
mod tests {
    use cool_asserts::assert_matches;

    use crate::extensions::datetime::{parse_datetime, parse_duration, Duration};

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

    #[track_caller]
    fn milliseconds_to_duration(ms: i128) -> String {
        let sign = if ms < 0 { "-" } else { "" };
        let mut ms = ms.abs();
        let milliseconds = ms % 1000;
        ms /= 1000;
        let seconds = ms % 60;
        ms /= 60;
        let minutes = ms % 60;
        ms /= 60;
        let hours = ms % 24;
        ms /= 24;
        let days = ms;
        format!("{sign}{days}d{hours}h{minutes}m{seconds}s{milliseconds}ms")
    }

    #[test]
    fn parse_duration_pos() {
        assert_eq!(parse_duration("1h"), Some(Duration { ms: 3600 * 1000 }));
        assert_eq!(
            parse_duration("-10h"),
            Some(Duration {
                ms: -3600 * 10 * 1000
            })
        );
        assert_eq!(
            parse_duration("5d3ms"),
            Some(Duration {
                ms: 3600 * 24 * 5 * 1000 + 3
            })
        );
        assert_eq!(
            parse_duration("-3h5m"),
            Some(Duration {
                ms: -3600 * 3 * 1000 - 300 * 1000
            })
        );
        assert!(parse_duration(&milliseconds_to_duration(i64::MAX.into())).is_some());
        assert!(parse_duration(&milliseconds_to_duration(i64::MIN.into())).is_some());
    }

    #[test]
    fn parse_duration_neg() {
        assert!(parse_duration(&milliseconds_to_duration(i64::MAX as i128 + 1)).is_none());
        assert!(parse_duration(&milliseconds_to_duration(i64::MIN as i128 - 1)).is_none());
    }
}
