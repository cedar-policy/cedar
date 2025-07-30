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

//! This module defines Cedar datetime and duration values and functions.
//! It is based on
//! <https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/Cedar/Spec/Ext/Datetime.lean>

/// A datetime value is measured in milliseconds and constructed from a datetime string.
/// A datetime string must be of one of the forms:
///   - `YYYY-MM-DD` (date only)
///   - `YYYY-MM-DDThh:mm:ssZ` (UTC)
///   - `YYYY-MM-DDThh:mm:ss.SSSZ` (UTC with millisecond precision)
///   - `YYYY-MM-DDThh:mm:ss(+|-)hhmm` (With timezone offset in hours and minutes)
///   - `YYYY-MM-DDThh:mm:ss.SSS(+|-)hhmm` (With timezone offset in hours and minutes and millisecond precision)
///
/// Regardless of the timezone, offset is always normalized to UTC.
///
/// The datetime type does not provide a way to create a datetime from a Unix timestamp.
/// One of the readable formats listed above must be used instead.
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Datetime {
    val: i64,
}

const MILLISECONDS_PER_SECOND: i64 = 1000;
const MILLISECONDS_PER_DAY: i64 = 86400000;

impl Datetime {
    pub fn offset(&self, duration: &Duration) -> Option<Datetime> {
        Some(Self {
            val: self.val.checked_add(duration.val)?,
        })
    }

    pub fn duration_since(&self, other: &Self) -> Option<Duration> {
        Some(Duration {
            val: self.val.checked_sub(other.val)?,
        })
    }

    pub fn to_date(&self) -> Option<Datetime> {
        if self.val >= 0 {
            Some(Self {
                val: MILLISECONDS_PER_DAY * (self.val / MILLISECONDS_PER_DAY),
            })
        } else if self.val % MILLISECONDS_PER_DAY == 0 {
            Some(self.clone())
        } else {
            Some(Self {
                val: ((self.val / MILLISECONDS_PER_DAY) - 1) * MILLISECONDS_PER_DAY,
            })
        }
    }

    pub fn to_time(&self) -> Option<Datetime> {
        if self.val >= 0 {
            Some(Self {
                val: self.val % MILLISECONDS_PER_DAY,
            })
        } else {
            let rem = self.val % MILLISECONDS_PER_DAY;
            if rem == 0 {
                Some(Self { val: rem })
            } else {
                Some(Self {
                    val: rem + MILLISECONDS_PER_DAY,
                })
            }
        }
    }

    // Returns true iff s is a datetime str in one of our accepted formats and contains a leap second
    fn date_contains_leap_seconds(s: &str) -> bool {
        s.len() >= 20 && s.get(17..19) == Some("60")
    }

    // Returns true iff s contains the expected delimiters within one of our accepted datetime str formats
    fn check_component_len(s: &str) -> bool {
        let check_date_component = |s: &str| -> bool {
            match s.split('-').collect::<Vec<_>>().as_slice() {
                [year, month, day] => year.len() == 4 && month.len() == 2 && day.len() == 2,
                _ => false,
            }
        };
        let check_time_component = |s: &str| -> bool {
            match s
                .find(['.', '+', '-', 'Z'])
                .and_then(|pos| s.split_at_checked(pos))
            {
                Some((time, ms_and_tz)) => match time.split(':').collect::<Vec<_>>().as_slice() {
                    [h, m, s] => {
                        h.len() == 2 && m.len() == 2 && s.len() == 2 && !ms_and_tz.contains(':')
                    }
                    _ => false,
                },
                None => false,
            }
        };

        match s.split('T').collect::<Vec<_>>().as_slice() {
            [date] => check_date_component(date),
            [date, time] => check_date_component(date) && check_time_component(time),
            _ => false,
        }
    }

    fn tz_offset_mins_lt_60(s: &str) -> bool {
        // Doesn't contain time
        s.len() <= 10
            // is UTC
            || s.ends_with('Z')
            // Specifies TZ using +xxxx format
            || s.get((s.len() - 2)..)
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|mins_offset| mins_offset < 60)
    }

    pub fn parse(s: &str) -> Option<Self> {
        // Validate datetime str
        if Self::date_contains_leap_seconds(s)
            || !Self::check_component_len(s)
            || !Self::tz_offset_mins_lt_60(s)
        {
            return None;
        }

        // Define the format strings
        const DATE_ONLY: &str = "%Y-%m-%d";
        const DATE_UTC: &str = "%Y-%m-%dT%H:%M:%SZ";
        const DATE_UTC_MILLIS: &str = "%Y-%m-%dT%H:%M:%S.%3fZ";
        // The documentation states that %z accepts TZ specified as +xxxx or -xxxx
        // but in practice also accepts +xx:xx and -xx::xx. Thus we need to independently
        // Validate date strings with TZ do not contain ':' in TZ.
        const DATE_WITH_OFFSET: &str = "%Y-%m-%dT%H:%M:%S%z";
        const DATE_WITH_OFFSET_MILLIS: &str = "%Y-%m-%dT%H:%M:%S.%3f%z";

        const MAX_OFFSET_SECONDS: i32 = 86400; // 24 hours in seconds

        // Try parsing with each format
        // PANIC SAFETY
        #[allow(
            clippy::unwrap_used,
            reason = "Should be able to construct a datetime with hour = 0, minute = 0, seconds = 0"
        )]
        // Cannot parse a datetime from just date format so use NaiveDate then append time == midnight
        let datetime = NaiveDate::parse_from_str(s, DATE_ONLY)
            .map(|date| date.and_hms_opt(0, 0, 0).unwrap())
            // Datetime expects TZ info to be provided in date string regardless of format str. Use NaiveDatetime for default 'Z' TZ
            .or_else(|_| NaiveDateTime::parse_from_str(s, DATE_UTC))
            .or_else(|_| NaiveDateTime::parse_from_str(s, DATE_UTC_MILLIS))
            // Convert NaiveDatetimes to UTC datetimes
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
            // Parse date strings that include time zones.
            .or_else(|_| {
                DateTime::parse_from_str(s, DATE_WITH_OFFSET).map(|dt| dt.with_timezone(&Utc))
            })
            .or_else(|_| {
                DateTime::parse_from_str(s, DATE_WITH_OFFSET_MILLIS)
                    .map(|dt| dt.with_timezone(&Utc))
            })
            .ok()?;

        // Check if the original timezone offset is within bounds (need to parse again for offset checks)
        let offset = if let Ok(dt) = DateTime::parse_from_str(s, DATE_WITH_OFFSET) {
            dt.offset().local_minus_utc()
        } else if let Ok(dt) = DateTime::parse_from_str(s, DATE_WITH_OFFSET_MILLIS) {
            dt.offset().local_minus_utc()
        } else {
            0 // UTC or local time
        };

        if offset.abs() < MAX_OFFSET_SECONDS {
            Some(Self {
                val: datetime.timestamp_millis(),
            })
        } else {
            None
        }
    }
}

impl From<Datetime> for i128 {
    fn from(dt: Datetime) -> Self {
        i128::from(dt.val)
    }
}

impl From<&Datetime> for i128 {
    fn from(dt: &Datetime) -> Self {
        i128::from(dt.val)
    }
}

impl From<i128> for Datetime {
    fn from(bv_inner: i128) -> Self {
        Self {
            val: bv_inner as i64,
        }
    }
}

#[allow(
    clippy::derivable_impls,
    reason = "Make explicit as require the default be 0"
)]
impl Default for Datetime {
    fn default() -> Self {
        Self { val: 0 }
    }
}

/// A duration value is measured in milliseconds and constructed from a duration string.
/// A duration string is a concatenated sequence of quantity-unit pairs where the quantity
/// is a natural number and unit is one of the following:
///   - `d` (for days)
///   - `h` (for hours)
///   - `m` (for minutes)
///   - `s` (for seconds)
///   - `ms` (for milliseconds)
///
/// Duration strings are required to be ordered from largest unit to smallest
/// unit, and contain one quantity per unit. Units with zero quantity may be
/// omitted.
///
/// A duration may be negative. Negative duration strings must begin with `-`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration {
    val: i64,
}

impl Duration {
    pub fn to_milliseconds(&self) -> i64 {
        self.val
    }

    pub fn to_seconds(&self) -> i64 {
        self.val / MILLISECONDS_PER_SECOND
    }

    pub fn to_minutes(&self) -> i64 {
        self.to_seconds() / 60
    }

    pub fn to_hours(&self) -> i64 {
        self.to_minutes() / 60
    }

    pub fn to_days(&self) -> i64 {
        self.to_hours() / 24
    }

    fn parse_unit<'a>(s: &'a str, is_neg: bool, suffix: &str) -> Option<(i64, &'a str)> {
        match s.strip_suffix(suffix) {
            Some(prefix) => {
                let pos = prefix
                    .rfind(|c: char| !c.is_ascii_digit())
                    .map_or(0, |i| i + 1);
                // PANIC SAFETY: by construction pos must be a valid index into prefix
                let (prefix, digits) = prefix.split_at(pos);

                // Compute the unscaled unit value (# of days/hrs/min/sec/ms)
                let val = if is_neg && digits == "9223372036854775808" {
                    // ensure we don't overflow when parsing
                    i64::MIN
                } else {
                    // Parse absolute value. Any remaining overflow / parse errors
                    let abs_val = digits.parse::<i64>().ok()?;
                    // negate as necessary
                    if is_neg {
                        -abs_val
                    } else {
                        abs_val
                    }
                };
                let ms_val = match suffix {
                    "ms" => val,
                    "s" => val.checked_mul(1000)?,
                    "m" => val.checked_mul(60 * 1000)?,
                    "h" => val.checked_mul(60 * 60 * 1000)?,
                    "d" => val.checked_mul(24 * 60 * 60 * 1000)?,
                    _ => return None,
                };
                Some((ms_val, prefix))
            }
            None => Some((0, s)),
        }
    }

    pub fn parse(s: &str) -> Option<Duration> {
        let (is_neg, s) = match s.strip_prefix('-') {
            Some(s) => (true, s),
            None => (false, s),
        };

        if s.is_empty() {
            return None;
        }

        let (ms, s) = Self::parse_unit(s, is_neg, "ms")?;
        let (sec, s) = Self::parse_unit(s, is_neg, "s")?;
        let (min, s) = Self::parse_unit(s, is_neg, "m")?;
        let (hr, s) = Self::parse_unit(s, is_neg, "h")?;
        let (days, s) = Self::parse_unit(s, is_neg, "d")?;

        if !s.is_empty() {
            return None;
        }

        Some(Self {
            val: days
                .checked_add(hr)?
                .checked_add(min)?
                .checked_add(sec)?
                .checked_add(ms)?,
        })
    }
}

#[allow(
    clippy::derivable_impls,
    reason = "Make explicit as require the default be 0"
)]
impl Default for Duration {
    fn default() -> Self {
        Self { val: 0 }
    }
}

impl From<Duration> for i128 {
    fn from(d: Duration) -> Self {
        i128::from(d.val)
    }
}

impl From<&Duration> for i128 {
    fn from(d: &Duration) -> Self {
        i128::from(d.val)
    }
}

impl From<i128> for Duration {
    fn from(bv_inner: i128) -> Self {
        Self {
            val: bv_inner as i64,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::symcc::extension_types::datetime::{Datetime, Duration};

    fn datetime(i: i64) -> Option<Datetime> {
        Some(Datetime { val: i })
    }

    fn test_valid_datetime(str: &str, rep: i64) {
        assert_eq!(Datetime::parse(str), datetime(rep));
    }

    fn test_invalid_datetime(str: &str, msg: &str) {
        assert_eq!(Datetime::parse(str), None, "{}", msg);
    }

    #[test]
    fn tests_for_valid_datetime_strings() {
        test_valid_datetime("2022-10-10", 1665360000000);
        test_valid_datetime("1969-12-31", -86400000);
        test_valid_datetime("1969-12-31T23:59:59Z", -1000);
        test_valid_datetime("1969-12-31T23:59:59.001Z", -999);
        test_valid_datetime("1969-12-31T23:59:59.999Z", -1);
        test_valid_datetime("2024-10-15", 1728950400000);
        test_valid_datetime("2024-10-15T11:38:02Z", 1728992282000);
        test_valid_datetime("2024-10-15T11:38:02.101Z", 1728992282101);
        test_valid_datetime("2024-10-15T11:38:02.101-1134", 1729033922101);
        test_valid_datetime("2024-10-15T11:38:02.101+1134", 1728950642101);
        test_valid_datetime("2024-10-15T11:38:02+1134", 1728950642000);
        test_valid_datetime("2024-10-15T11:38:02-1134", 1729033922000);
    }

    #[test]
    fn tests_for_invalid_datetime_strings() {
        test_invalid_datetime("", "empty string");
        test_invalid_datetime("a", "string is letter");
        test_invalid_datetime("-", "string is character");
        test_invalid_datetime("-1", "string is integer");
        test_invalid_datetime(" 2022-10-10", "leading space");
        test_invalid_datetime("2022-10-10 ", "trailing space");
        test_invalid_datetime("2022-10- 10", "interior space");
        test_invalid_datetime("11-12-13", "two digits for year");
        test_invalid_datetime("011-12-13", "three digits for year");
        test_invalid_datetime("00011-12-13", "five digits for year");
        test_invalid_datetime("0001-2-13", "one digit for month");
        test_invalid_datetime("0001-012-13", "three digits for month");
        test_invalid_datetime("0001-02-3", "one digit for day");
        test_invalid_datetime("0001-02-003", "three digits for day");
        test_invalid_datetime("0001-01-01T1:01:01Z", "one digit for hour");
        test_invalid_datetime("0001-01-01T001:01:01Z", "three digits for hour");
        test_invalid_datetime("0001-01-01T01:1:01Z", "one digit for minutes");
        test_invalid_datetime("0001-01-01T01:001:01Z", "three digits for minutes");
        test_invalid_datetime("0001-01-01T01:01:1Z", "one digit for seconds");
        test_invalid_datetime("0001-01-01T01:01:001Z", "three digits for seconds");
        test_invalid_datetime("0001-01-01T01:01:01.01Z", "two digits for ms");
        test_invalid_datetime("0001-01-01T01:01:01.0001Z", "four digits for ms");
        test_invalid_datetime("0001-01-01T01:01:01.001+01", "two digits for offset");
        test_invalid_datetime("0001-01-01T01:01:01.001+001", "three digits for offset");
        test_invalid_datetime("0001-01-01T01:01:01.001+000001", "six digits for offset");
        test_invalid_datetime("0001-01-01T01:01:01.001+00:01", "offset with colon");
        test_invalid_datetime("0001-01-01T01:01:01.001+00:00:01", "six offset with colon");
        test_invalid_datetime("-0001-01-01", "negative year");
        test_invalid_datetime("1111-1x-20", "invalid month");
        test_invalid_datetime("1111-Jul-20", "abbreviated month");
        test_invalid_datetime("1111-July-20", "full month");
        test_invalid_datetime("1111-J-20", "single letter month");
        test_invalid_datetime("2024-10-15Z", "Zulu code invalid for date");
        test_invalid_datetime("2024-10-15T11:38:02ZZ", "double Zulu code");
        test_invalid_datetime("2024-01-01T", "separator not needed");
        test_invalid_datetime("2024-01-01Ta", "unexpected character 'a'");
        test_invalid_datetime("2024-01-01T01:", "only hours");
        test_invalid_datetime("2024-01-01T01:02", "no seconds");
        test_invalid_datetime("2024-01-01T01:02:0b", "unexpected character 'b'");
        test_invalid_datetime("2024-01-01T01::02:03", "double colon");
        test_invalid_datetime("2024-01-01T01::02::03", "double colons");
        test_invalid_datetime("2024-01-01T31:02:03Z", "invalid hour range");
        test_invalid_datetime("2024-01-01T01:60:03Z", "invalid minute range");
        test_invalid_datetime("2016-12-31T23:59:60Z", "leap second");
        test_invalid_datetime("2016-12-31T23:59:61Z", "invalid second range");
        test_invalid_datetime("2024-01-01T00:00:00", "timezone not specified");
        test_invalid_datetime("2024-01-01T00:00:00T", "separator is not timezone");
        test_invalid_datetime("2024-01-01T00:00:00ZZ", "double Zulu code");
        test_invalid_datetime("2024-01-01T00:00:00x001Z", "typo in milliseconds separator");
        test_invalid_datetime("2024-01-01T00:00:00.001ZZ", "double Zulu code w/ millis");
        test_invalid_datetime("2016-12-31T23:59:60.000Z", "leap second (millis/UTC)");
        test_invalid_datetime(
            "2016-12-31T23:59:60.000+0200",
            "leap second (millis/offset)",
        );
        test_invalid_datetime("2024-01-01T00:00:00➕0000", "sign `+` is an emoji");
        test_invalid_datetime("2024-01-01T00:00:00➖0000", "sign `-` is an emoji");
        test_invalid_datetime(
            "2024-01-01T00:00:00.0001Z",
            "fraction of seconds is 4 digits",
        );
        test_invalid_datetime("2024-01-01T00:00:00.001➖0000", "sign `+` is an emoji");
        test_invalid_datetime("2024-01-01T00:00:00.001➕0000", "sign `-` is an emoji");
        test_invalid_datetime("2024-01-01T00:00:00.001+00000", "offset is 5 digits");
        test_invalid_datetime("2024-01-01T00:00:00.001-00000", "offset is 5 digits");
        test_invalid_datetime("2016-01-01T00:00:00+2400", "invalid offset hour range");
        test_invalid_datetime("2016-01-01T00:00:00+0060", "invalid offset minute range");
        test_invalid_datetime(
            "2016-01-01T00:00:00+9999",
            "invalid offset hour and minute range",
        );
    }

    fn duration(i: i64) -> Option<Duration> {
        Some(Duration { val: i })
    }

    fn test_valid_duration(str: &str, rep: i64) {
        assert_eq!(Duration::parse(str), duration(rep));
    }

    fn test_invalid_duration(str: &str, msg: &str) {
        assert_eq!(Duration::parse(str), None, "{}", msg);
    }

    #[test]
    fn tests_for_valid_duration_strings() {
        test_valid_duration("0ms", 0);
        test_valid_duration("0d0s", 0);
        test_valid_duration("1ms", 1);
        test_valid_duration("1s", 1000);
        test_valid_duration("1m", 60000);
        test_valid_duration("1h", 3600000);
        test_valid_duration("1d", 86400000);
        test_valid_duration("12s340ms", 12340);
        test_valid_duration("1s234ms", 1234);
        test_valid_duration("-1ms", -1);
        test_valid_duration("-1s", -1000);
        test_valid_duration("-4s200ms", -4200);
        test_valid_duration("-9s876ms", -9876);
        test_valid_duration("106751d23h47m16s854ms", 9223372036854);
        test_valid_duration("-106751d23h47m16s854ms", -9223372036854);
        test_valid_duration("-9223372036854775808ms", i64::MIN);
        test_valid_duration("9223372036854775807ms", i64::MAX);
        test_valid_duration("1d2h3m4s5ms", 93784005);
        test_valid_duration("2d12h", 216000000);
        test_valid_duration("3m30s", 210000);
        test_valid_duration("1h30m45s", 5445000);
        test_valid_duration("2d5h20m", 192000000);
        test_valid_duration("-1d12h", -129600000);
        test_valid_duration("-3h45m", -13500000);
        test_valid_duration("1d1ms", 86400001);
        test_valid_duration("59m59s999ms", 3599999);
        test_valid_duration("23h59m59s999ms", 86399999);
        test_valid_duration("0d0h0m0s0ms", 0);
    }

    #[test]
    fn tests_for_invalid_duration_strings() {
        test_invalid_duration("", "empty string");
        test_invalid_duration("d", "unit but no amount");
        test_invalid_duration("1d-1s", "invalid use of -");
        test_invalid_duration("1d2h3m4s5ms6", "trailing amount");
        test_invalid_duration("1x2m3s", "invalid unit");
        test_invalid_duration("1.23s", "amounts must be integral");
        test_invalid_duration("1s1d", "invalid order");
        test_invalid_duration("1s1s", "repeated units");
        test_invalid_duration("1d2h3m4s5ms ", "trailing space");
        test_invalid_duration(" 1d2h3m4s5ms", "leading space");
        test_invalid_duration("1d9223372036854775807ms", "overflow");
        test_invalid_duration("1d92233720368547758071ms", "overflow ms");
        test_invalid_duration("9223372036854776s1ms", "overflow s");
    }
}
