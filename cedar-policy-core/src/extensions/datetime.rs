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

use std::{fmt::Display, i64, sync::Arc};

use chrono::{NaiveDate, NaiveDateTime, NaiveTime, TimeDelta};
use constants::{
    DATETIME_CONSTRUCTOR_NAME, DATE_PATTERN, DURATION_CONSTRUCTOR_NAME, DURATION_PATTERN,
    DURATION_SINCE_NAME, HMS_PATTERN, MS_AND_OFFSET_PATTERN, OFFSET_METHOD_NAME,
};
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

use crate::{
    ast::{
        CallStyle, Extension, ExtensionFunction, ExtensionOutputValue, ExtensionValue, Literal,
        Name, RepresentableExtensionValue, RestrictedExpr, Type, Value, ValueKind,
    },
    entities::SchemaType,
    evaluator::{self, EvaluationError},
};

const DATETIME_EXTENSION_NAME: &str = "datetime";

// PANIC SAFETY The `Name`s and `Regex` here are valid
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod constants {
    use regex::Regex;

    use crate::{ast::Name, extensions::datetime::DATETIME_EXTENSION_NAME};

    lazy_static::lazy_static! {
        pub static ref DATETIME_CONSTRUCTOR_NAME : Name = Name::parse_unqualified_name(DATETIME_EXTENSION_NAME).expect("should be a valid identifier");
        pub static ref DURATION_CONSTRUCTOR_NAME : Name = Name::parse_unqualified_name("duration").expect("should be a valid identifier");
        pub static ref OFFSET_METHOD_NAME : Name = Name::parse_unqualified_name("offset").expect("should be a valid identifier");
        pub static ref DURATION_SINCE_NAME : Name = Name::parse_unqualified_name("durationSince").expect("should be a valid identifier");
        pub static ref TO_DATE_NAME : Name = Name::parse_unqualified_name("toDate").expect("should be a valid identifier");
        pub static ref TO_TIME_NAME : Name = Name::parse_unqualified_name("toTime").expect("should be a valid identifier");
        pub static ref TO_MILLISECONDS_NAME : Name = Name::parse_unqualified_name("toMilliseconds").expect("should be a valid identifier");
        pub static ref TO_SECONDS_NAME : Name = Name::parse_unqualified_name("toSeconds").expect("should be a valid identifier");
        pub static ref TO_MINUTES_NAME : Name = Name::parse_unqualified_name("toMinutes").expect("should be a valid identifier");
        pub static ref TO_HOURS_NAME : Name = Name::parse_unqualified_name("toHours").expect("should be a valid identifier");
        pub static ref TO_DAYS_NAME : Name = Name::parse_unqualified_name("toDays").expect("should be a valid identifier");
    }

    // Global regex, initialized at first use
    // PANIC SAFETY: These are valid `Regex`
    lazy_static::lazy_static! {
        pub static ref DURATION_PATTERN: Regex =
        Regex::new(r"^-?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?$").unwrap();
        pub static ref DATE_PATTERN: Regex = Regex::new(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})").unwrap();
        pub static ref HMS_PATTERN: Regex = Regex::new(r"^T([0-9]{2}):([0-9]{2}):([0-9]{2})").unwrap();
        pub static ref MS_AND_OFFSET_PATTERN: Regex =
        Regex::new(r"^(\.([0-9]{3}))?(Z|((\+|-)([0-9]{2})([0-9]{2})))$").unwrap();
    }
}

// The `datetime` type, represented internally as an `i64`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
struct DateTime {
    // The number of non-leap milliseconds from the Unix epoch
    epoch: i64,
}

fn extension_err(msg: String, extension_name: &crate::ast::Name) -> evaluator::EvaluationError {
    evaluator::EvaluationError::failed_extension_function_application(
        extension_name.clone(),
        msg,
        None, // source loc will be added by the evaluator
    )
}

fn construct_from_str<Ext>(
    arg: Value,
    constructor: impl Fn(&str) -> Result<Ext, EvaluationError>,
) -> evaluator::Result<ExtensionOutputValue>
where
    Ext: ExtensionValue + std::cmp::Ord + 'static + std::clone::Clone + Into<RestrictedExpr>,
{
    let s = arg.get_as_string()?;
    let ext_value: Ext = constructor(s)?;
    let arg_source_loc = arg.source_loc().cloned();
    let e = RepresentableExtensionValue::new(Arc::new(ext_value));
    Ok(Value {
        value: ValueKind::ExtensionValue(Arc::new(e)),
        loc: arg_source_loc, // follow the same convention as the `decimal` extension
    }
    .into())
}

/// Cedar function that constructs a `datetime` Cedar type from a
/// Cedar string
fn datetime_from_str(arg: Value) -> evaluator::Result<ExtensionOutputValue> {
    construct_from_str(arg, |s| {
        parse_datetime(s)
            .map(DateTime::from)
            .map_err(|err| extension_err(err.to_string(), &DATETIME_CONSTRUCTOR_NAME))
    })
}

/// Help message to display when a String was provided where a decimal value was expected.
/// This error is likely due to confusion between "1.23" and decimal("1.23").
const ADVICE_MSG: &str = "maybe you forgot to apply the `decimal` constructor?";

fn as_ext<'a, Ext>(v: &'a Value, type_name: &'a Name) -> Result<&'a Ext, evaluator::EvaluationError>
where
    Ext: ExtensionValue + std::cmp::Ord + 'static,
{
    match &v.value {
        ValueKind::ExtensionValue(ev) if ev.typename() == *type_name => {
            // PANIC SAFETY Conditional above performs a typecheck
            #[allow(clippy::expect_used)]
            let ext = ev
                .value()
                .as_any()
                .downcast_ref::<Ext>()
                .expect("already typechecked, so this downcast should succeed");
            Ok(ext)
        }
        ValueKind::Lit(Literal::String(_)) => {
            Err(evaluator::EvaluationError::type_error_with_advice_single(
                Type::Extension {
                    name: type_name.to_owned(),
                },
                v,
                ADVICE_MSG.into(),
            ))
        }
        _ => Err(evaluator::EvaluationError::type_error_single(
            Type::Extension {
                name: type_name.to_owned(),
            },
            v,
        )),
    }
}

/// Check that `v` is a datetime type and, if it is, return the wrapped value
fn as_datetime(v: &Value) -> Result<&DateTime, evaluator::EvaluationError> {
    as_ext(v, &DATETIME_CONSTRUCTOR_NAME)
}

/// Check that `v` is a duration type and, if it is, return the wrapped value
fn as_duration(v: &Value) -> Result<&Duration, evaluator::EvaluationError> {
    as_ext(v, &DURATION_CONSTRUCTOR_NAME)
}

fn offset(datetime: Value, duration: Value) -> evaluator::Result<ExtensionOutputValue> {
    let datetime = as_datetime(&datetime)?;
    let duration = as_duration(&duration)?;
    let ret = datetime.offset(duration.clone()).ok_or(extension_err(
        format!(
            "overflows when adding an offset: {}+({})",
            datetime, duration
        ),
        &OFFSET_METHOD_NAME,
    ))?;
    let e = RepresentableExtensionValue::new(Arc::new(ret.clone()));
    Ok(Value {
        value: ValueKind::ExtensionValue(Arc::new(e)),
        loc: None,
    }
    .into())
}

fn duration_since(lhs: Value, rhs: Value) -> evaluator::Result<ExtensionOutputValue> {
    let lhs = as_datetime(&lhs)?;
    let rhs = as_datetime(&rhs)?;
    let ret = lhs.duration_since(rhs.clone()).ok_or(extension_err(
        format!("overflows when computing the duration between {lhs} and {rhs}",),
        &DURATION_SINCE_NAME,
    ))?;
    let e = RepresentableExtensionValue::new(Arc::new(ret.clone()));
    Ok(Value {
        value: ValueKind::ExtensionValue(Arc::new(e)),
        loc: None,
    }
    .into())
}

fn to_date(value: Value) -> evaluator::Result<ExtensionOutputValue> {
    let d = as_datetime(&value)?;
    let ret = d.to_date();
    let e = RepresentableExtensionValue::new(Arc::new(ret.clone()));
    Ok(Value {
        value: ValueKind::ExtensionValue(Arc::new(e)),
        loc: None,
    }
    .into())
}

fn to_time(value: Value) -> evaluator::Result<ExtensionOutputValue> {
    let d = as_datetime(&value)?;
    let ret = d.to_time();
    let e = RepresentableExtensionValue::new(Arc::new(ret.clone()));
    Ok(Value {
        value: ValueKind::ExtensionValue(Arc::new(e)),
        loc: None,
    }
    .into())
}

// Note that this implementation cannot always generate valid input strings
// because they only represent a small subset of `datetime`
// And we just use `NaiveDateTime`'s implementation, which does not pad
// milliseconds with leading zeros
impl Display for DateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.epoch {
            i64::MIN => {
                // PANIC SAFETY: `i64::MIN` + 1 is a valid millisecond for `TimeDelta`
                #[allow(clippy::unwrap_used)]
                let delta = TimeDelta::try_milliseconds(i64::MIN + 1).unwrap();
                // PANIC SAFETY: 1 is a valid millisecond for `TimeDelta`
                #[allow(clippy::unwrap_used)]
                let date_time =
                    NaiveDateTime::UNIX_EPOCH + delta - TimeDelta::try_milliseconds(1).unwrap();
                date_time.fmt(f)
            }
            _ => {
                // PANIC SAFETY: any `i64` other than `i64::MIN` is a valid millisecond for `TimeDelta`
                #[allow(clippy::unwrap_used)]
                let delta = TimeDelta::try_milliseconds(self.epoch).unwrap();
                let date_time = NaiveDateTime::UNIX_EPOCH + delta;
                date_time.fmt(f)
            }
        }
    }
}

impl ExtensionValue for DateTime {
    fn typename(&self) -> crate::ast::Name {
        DATETIME_CONSTRUCTOR_NAME.to_owned()
    }
}

impl DateTime {
    const DAY_IN_MILLISECONDS: i64 = 1000 * 3600 * 24;
    const UNIX_EPOCH_STR: &str = "1970-01-01";

    fn offset(&self, duration: Duration) -> Option<Self> {
        self.epoch
            .checked_add(duration.ms)
            .map(|epoch| Self { epoch })
    }

    fn duration_since(&self, other: DateTime) -> Option<Duration> {
        self.epoch
            .checked_sub(other.epoch)
            .map(|ms| Duration { ms })
    }

    fn to_date(&self) -> Self {
        Self {
            epoch: self.epoch / Self::DAY_IN_MILLISECONDS,
        }
    }

    fn to_time(&self) -> Duration {
        Duration {
            ms: self.epoch % Self::DAY_IN_MILLISECONDS,
        }
    }
}

impl From<DateTime> for RestrictedExpr {
    fn from(value: DateTime) -> Self {
        RestrictedExpr::call_extension_fn(
            OFFSET_METHOD_NAME.clone(),
            vec![
                RestrictedExpr::call_extension_fn(
                    DATETIME_CONSTRUCTOR_NAME.clone(),
                    vec![Value::from(DateTime::UNIX_EPOCH_STR).into()],
                ),
                Duration { ms: value.epoch }.into(),
            ],
        )
    }
}

impl From<Duration> for RestrictedExpr {
    fn from(value: Duration) -> Self {
        RestrictedExpr::call_extension_fn(
            DURATION_CONSTRUCTOR_NAME.clone(),
            vec![Value::from(value.to_string()).into()],
        )
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

impl Display for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}d{}h{}m{}s{}ms",
            self.to_days(),
            self.to_hours(),
            self.to_minutes(),
            self.to_seconds(),
            self.ms % 1000
        )
    }
}

impl ExtensionValue for Duration {
    fn typename(&self) -> crate::ast::Name {
        DURATION_CONSTRUCTOR_NAME.to_owned()
    }
}

/// Cedar function that constructs a `duration` Cedar type from a
/// Cedar string
fn duration_from_str(arg: Value) -> evaluator::Result<ExtensionOutputValue> {
    construct_from_str(arg, |s| {
        parse_duration(s).map_err(|err| extension_err(err.to_string(), &DURATION_CONSTRUCTOR_NAME))
    })
}

impl Duration {
    fn to_milliseconds(&self) -> i64 {
        self.ms
    }

    fn to_seconds(&self) -> i64 {
        self.to_milliseconds() / 1000
    }

    fn to_minutes(&self) -> i64 {
        self.to_seconds() / 60
    }

    fn to_hours(&self) -> i64 {
        self.to_minutes() / 60
    }

    fn to_days(&self) -> i64 {
        self.to_hours() / 24
    }
}

fn duration_method(
    value: Value,
    internal_func: impl Fn(&Duration) -> i64,
) -> evaluator::Result<ExtensionOutputValue> {
    let d = as_duration(&value)?;
    Ok(Value::from(internal_func(d)).into())
}

#[derive(Debug, Clone, Error, Diagnostic)]
enum DurationParseError {
    #[error("invalid duration pattern")]
    #[help("A valid duration string is a concatenated sequence of quantity-unit pairs")]
    InvalidPattern,
    #[error("Duration overflows internal representation")]
    #[help("A duration in milliseconds must be representable by a signed 64 bit integer")]
    Overflow,
}

fn parse_duration(s: &str) -> Result<Duration, DurationParseError> {
    let captures = DURATION_PATTERN
        .captures(s)
        .ok_or(DurationParseError::InvalidPattern)?;
    let get_number = |idx| {
        captures
            .get(idx)
            .map_or(Some(0), |m| m.as_str().parse().ok())
            .ok_or(DurationParseError::Overflow)
    };
    let d: u64 = get_number(2)?;
    let h: u64 = get_number(4)?;
    let m: u64 = get_number(6)?;
    let sec: u64 = get_number(8)?;
    let ms: u64 = get_number(10)?;
    let checked_op = |x, y: u64, mul| {
        (if s.starts_with('-') {
            i64::checked_sub
        } else {
            i64::checked_add
        })(
            x,
            i64::checked_mul(y.try_into().map_err(|_| DurationParseError::Overflow)?, mul)
                .ok_or(DurationParseError::Overflow)?,
        )
        .ok_or(DurationParseError::Overflow)
    };
    let mut ms = if s.starts_with('-') {
        i64::try_from(-(ms as i128)).map_err(|_| DurationParseError::Overflow)?
    } else {
        i64::try_from(ms).map_err(|_| DurationParseError::Overflow)?
    };
    ms = checked_op(ms, sec, 1000)?;
    ms = checked_op(ms, m, 1000 * 60)?;
    ms = checked_op(ms, h, 1000 * 60 * 60)?;
    ms = checked_op(ms, d, 1000 * 60 * 60 * 24)?;
    Ok(Duration { ms })
}

#[derive(Debug, Clone, Error, Diagnostic)]
enum DateTimeParseError {
    #[error("invalid date pattern")]
    #[help("A valid datetime string should start with YYYY-MM-DD")]
    InvalidDatePattern,
    #[error("invalid date: {0}")]
    InvalidDate(SmolStr),
    #[error("invalid hour/minute/second pattern")]
    #[help("A valid datetime string should have HH:MM:SS after the date")]
    InvalidHMSPattern,
    #[error("invalid hour/minute/second: {0}")]
    InvalidHMS(SmolStr),
    #[error("invalid millisecond and/or offset pattern")]
    #[help("A valid datetime should end with Z|.SSSZ|(+|-)hhmm|.SSS(+|-)hhmm")]
    InvalidMSOffsetPattern,
    #[error("invalid offset range: {}{}", ._0.0, ._0.1)]
    #[help("A valid offset hour range should be [0,12) and minute range should be [0, 60)")]
    InvalidOffset((u32, u32)),
}

fn parse_datetime(s: &str) -> Result<NaiveDateTime, DateTimeParseError> {
    // Get date first
    let (date_str, [year, month, day]) = DATE_PATTERN
        .captures(s)
        .ok_or(DateTimeParseError::InvalidDatePattern)?
        .extract();
    // PANIC SAFETY: `year`, `month`, and `day` should be all valid given the limit on the number of digits.
    #[allow(clippy::unwrap_used)]
    let date = NaiveDate::from_ymd_opt(
        year.parse().unwrap(),
        month.parse().unwrap(),
        day.parse().unwrap(),
    )
    .ok_or(DateTimeParseError::InvalidDate(date_str.into()))?;

    // A complete match; simply return
    if date_str.len() == s.len() {
        // PANIC SAFETY: `0`s should be all valid given the limit on the number of digits.
        #[allow(clippy::unwrap_used)]
        return Ok(NaiveDateTime::new(
            date,
            NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
        ));
    }

    // Get hour, minute, and second
    let s = &s[date_str.len()..];

    let (hms_str, [h, m, sec]) = HMS_PATTERN
        .captures(s)
        .ok_or(DateTimeParseError::InvalidHMSPattern)?
        .extract();
    // PANIC SAFETY: `h`, `m`, and `sec` should be all valid given the limit on the number of digits.
    #[allow(clippy::unwrap_used)]
    let (h, m, sec): (u32, u32, u32) =
        (h.parse().unwrap(), m.parse().unwrap(), sec.parse().unwrap());

    // Get millisecond and offset
    let s = &s[hms_str.len()..];

    let captures = MS_AND_OFFSET_PATTERN
        .captures(s)
        .ok_or(DateTimeParseError::InvalidMSOffsetPattern)?;
    let ms: u32 = if captures.get(1).is_some() {
        // PANIC SAFETY: should be valid given the limit on the number of digits.
        #[allow(clippy::unwrap_used)]
        captures[2].parse().unwrap()
    } else {
        0
    };
    let offset: Result<TimeDelta, DateTimeParseError> = if captures.get(4).is_some() {
        let sign = &captures[5] == "+";
        // PANIC SAFETY: should be valid given the limit on the number of digits.
        #[allow(clippy::unwrap_used)]
        let (offset_hour, offset_min): (u32, u32) =
            (captures[6].parse().unwrap(), captures[7].parse().unwrap());
        if offset_hour < 12 && offset_min < 60 {
            let offset_in_secs = (offset_hour * 3600 + offset_min * 60) as i64;
            // PANIC SAFETY: should be valid because the limit on the values of offsets.
            #[allow(clippy::unwrap_used)]
            Ok(TimeDelta::new(
                if sign {
                    offset_in_secs
                } else {
                    -offset_in_secs
                },
                0,
            )
            .unwrap())
        } else {
            Err(DateTimeParseError::InvalidOffset((offset_hour, offset_min)))
        }
    } else {
        Ok(TimeDelta::default())
    };
    let time = NaiveTime::from_hms_milli_opt(h, m, sec, ms)
        .ok_or(DateTimeParseError::InvalidHMS(hms_str.into()))?
        + offset?;
    Ok(NaiveDateTime::new(date, time))
}

/// Construct the extension
pub fn extension() -> Extension {
    let datetime_type = SchemaType::Extension {
        name: DATETIME_CONSTRUCTOR_NAME.to_owned(),
    };
    let duration_type = SchemaType::Extension {
        name: DURATION_CONSTRUCTOR_NAME.to_owned(),
    };
    Extension::new(
        constants::DATETIME_CONSTRUCTOR_NAME.clone(),
        vec![
            ExtensionFunction::unary(
                constants::DATETIME_CONSTRUCTOR_NAME.clone(),
                CallStyle::FunctionStyle,
                Box::new(datetime_from_str),
                datetime_type.clone(),
                SchemaType::String,
            ),
            ExtensionFunction::unary(
                constants::DURATION_CONSTRUCTOR_NAME.clone(),
                CallStyle::FunctionStyle,
                Box::new(duration_from_str),
                duration_type.clone(),
                SchemaType::String,
            ),
            ExtensionFunction::binary(
                constants::OFFSET_METHOD_NAME.clone(),
                CallStyle::MethodStyle,
                Box::new(offset),
                datetime_type.clone(),
                (datetime_type.clone(), duration_type.clone()),
            ),
            ExtensionFunction::binary(
                constants::DURATION_SINCE_NAME.clone(),
                CallStyle::MethodStyle,
                Box::new(duration_since),
                duration_type.clone(),
                (datetime_type.clone(), duration_type.clone()),
            ),
            ExtensionFunction::unary(
                constants::TO_DATE_NAME.clone(),
                CallStyle::MethodStyle,
                Box::new(to_date),
                datetime_type.clone(),
                datetime_type.clone(),
            ),
            ExtensionFunction::unary(
                constants::TO_TIME_NAME.clone(),
                CallStyle::MethodStyle,
                Box::new(to_time),
                duration_type.clone(),
                datetime_type.clone(),
            ),
            ExtensionFunction::unary(
                constants::TO_MILLISECONDS_NAME.clone(),
                CallStyle::MethodStyle,
                Box::new(|value| duration_method(value, Duration::to_milliseconds)),
                SchemaType::Long,
                duration_type.clone(),
            ),
            ExtensionFunction::unary(
                constants::TO_SECONDS_NAME.clone(),
                CallStyle::MethodStyle,
                Box::new(|value| duration_method(value, Duration::to_seconds)),
                SchemaType::Long,
                duration_type.clone(),
            ),
            ExtensionFunction::unary(
                constants::TO_MINUTES_NAME.clone(),
                CallStyle::MethodStyle,
                Box::new(|value| duration_method(value, Duration::to_minutes)),
                SchemaType::Long,
                duration_type.clone(),
            ),
            ExtensionFunction::unary(
                constants::TO_HOURS_NAME.clone(),
                CallStyle::MethodStyle,
                Box::new(|value| duration_method(value, Duration::to_hours)),
                SchemaType::Long,
                duration_type.clone(),
            ),
            ExtensionFunction::unary(
                constants::TO_DAYS_NAME.clone(),
                CallStyle::MethodStyle,
                Box::new(|value| duration_method(value, Duration::to_days)),
                SchemaType::Long,
                duration_type.clone(),
            ),
        ],
    )
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use chrono::NaiveDateTime;

    use crate::extensions::datetime::{parse_datetime, parse_duration, Duration};

    #[test]
    fn test_parse_pos() {
        let s = "2024-10-15";
        assert_eq!(
            parse_datetime(s).unwrap(),
            NaiveDateTime::from_str("2024-10-15T00:00:00").unwrap()
        );
        let s = "2024-10-15T11:38:02Z";
        assert_eq!(
            parse_datetime(s).unwrap(),
            NaiveDateTime::from_str("2024-10-15T11:38:02").unwrap()
        );
        let s = "2024-10-15T11:38:02.101Z";
        assert_eq!(
            parse_datetime(s).unwrap(),
            NaiveDateTime::from_str("2024-10-15T11:38:02.101").unwrap()
        );
        let s = "2024-10-15T11:38:02.101+1134";
        assert_eq!(
            parse_datetime(s).unwrap(),
            NaiveDateTime::from_str("2024-10-15T23:12:02.101").unwrap()
        );
        let s = "2024-10-15T11:38:02.101-1134";
        assert_eq!(
            parse_datetime(s).unwrap(),
            NaiveDateTime::from_str("2024-10-15T00:04:02.101").unwrap()
        );
        let s = "2024-10-15T11:38:02+1134";
        assert_eq!(
            parse_datetime(s).unwrap(),
            NaiveDateTime::from_str("2024-10-15T23:12:02").unwrap()
        );
        let s = "2024-10-15T11:38:02-1134";
        assert_eq!(
            parse_datetime(s).unwrap(),
            NaiveDateTime::from_str("2024-10-15T00:04:02").unwrap()
        );
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
            assert!(parse_datetime(s).is_err());
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
        assert_eq!(parse_duration("1h").unwrap(), Duration { ms: 3600 * 1000 });
        assert_eq!(
            parse_duration("-10h").unwrap(),
            Duration {
                ms: -3600 * 10 * 1000
            }
        );
        assert_eq!(
            parse_duration("5d3ms").unwrap(),
            Duration {
                ms: 3600 * 24 * 5 * 1000 + 3
            }
        );
        assert_eq!(
            parse_duration("-3h5m").unwrap(),
            Duration {
                ms: -3600 * 3 * 1000 - 300 * 1000
            }
        );
        assert!(parse_duration(&milliseconds_to_duration(i64::MAX.into())).is_ok());
        assert!(parse_duration(&milliseconds_to_duration(i64::MIN.into())).is_ok());
    }

    #[test]
    fn parse_duration_neg() {
        assert!(parse_duration(&milliseconds_to_duration(i64::MAX as i128 + 1)).is_err());
        assert!(parse_duration(&milliseconds_to_duration(i64::MIN as i128 - 1)).is_err());
    }
}
