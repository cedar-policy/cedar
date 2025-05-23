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
use std::{fmt::Display, sync::Arc};

use chrono::{NaiveDate, NaiveDateTime, NaiveTime, TimeDelta};
use constants::{
    DATETIME_CONSTRUCTOR_NAME, DATE_PATTERN, DURATION_CONSTRUCTOR_NAME, DURATION_PATTERN,
    DURATION_SINCE_NAME, HMS_PATTERN, MS_AND_OFFSET_PATTERN, OFFSET_METHOD_NAME, TO_DATE_NAME,
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
    parser::IntoMaybeLoc,
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
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct DateTime {
    // The number of non-leap milliseconds from the Unix epoch
    epoch: i64,
}

fn extension_err(
    msg: String,
    extension_name: &crate::ast::Name,
    advice: Option<String>,
) -> evaluator::EvaluationError {
    evaluator::EvaluationError::failed_extension_function_application(
        extension_name.clone(),
        msg,
        None, // source loc will be added by the evaluator
        advice,
    )
}

fn construct_from_str<Ext>(
    arg: &Value,
    constructor_name: Name,
    constructor: impl Fn(&str) -> Result<Ext, EvaluationError>,
) -> evaluator::Result<ExtensionOutputValue>
where
    Ext: ExtensionValue + std::cmp::Ord + 'static + std::clone::Clone,
{
    let s = arg.get_as_string()?;
    let ext_value: Ext = constructor(s)?;
    let arg_source_loc = arg.source_loc().into_maybe_loc();
    let e = RepresentableExtensionValue::new(
        Arc::new(ext_value),
        constructor_name,
        vec![arg.clone().into()],
    );
    Ok(Value {
        value: ValueKind::ExtensionValue(Arc::new(e)),
        loc: arg_source_loc, // follow the same convention as the `decimal` extension
    }
    .into())
}

/// Cedar function that constructs a `datetime` Cedar type from a
/// Cedar string
fn datetime_from_str(arg: &Value) -> evaluator::Result<ExtensionOutputValue> {
    construct_from_str(arg, DATETIME_CONSTRUCTOR_NAME.clone(), |s| {
        parse_datetime(s).map(DateTime::from).map_err(|err| {
            extension_err(
                err.to_string(),
                &DATETIME_CONSTRUCTOR_NAME,
                err.help().map(|v| v.to_string()),
            )
        })
    })
}

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
                format!("maybe you forgot to apply the `{type_name}` constructor?"),
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
fn as_datetime(v: &Value) -> Result<DateTime, evaluator::EvaluationError> {
    as_ext(v, &DATETIME_CONSTRUCTOR_NAME).copied()
}

/// Check that `v` is a duration type and, if it is, return the wrapped value
fn as_duration(v: &Value) -> Result<Duration, evaluator::EvaluationError> {
    as_ext(v, &DURATION_CONSTRUCTOR_NAME).copied()
}

fn offset(datetime: &Value, duration: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let datetime = as_datetime(datetime)?;
    let duration = as_duration(duration)?;
    let ret = datetime.offset(duration).ok_or_else(|| {
        extension_err(
            format!(
                "overflows when adding an offset: {}+({})",
                RestrictedExpr::from(datetime),
                duration
            ),
            &OFFSET_METHOD_NAME,
            None,
        )
    })?;
    Ok(Value {
        value: ValueKind::ExtensionValue(Arc::new(ret.into())),
        loc: None,
    }
    .into())
}

fn duration_since(lhs: &Value, rhs: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let lhs = as_datetime(lhs)?;
    let rhs = as_datetime(rhs)?;
    let ret = lhs.duration_since(rhs).ok_or_else(|| {
        extension_err(
            format!(
                "overflows when computing the duration between {} and {}",
                RestrictedExpr::from(lhs),
                RestrictedExpr::from(rhs)
            ),
            &DURATION_SINCE_NAME,
            None,
        )
    })?;
    Ok(Value {
        value: ValueKind::ExtensionValue(Arc::new(ret.into())),
        loc: None,
    }
    .into())
}

fn to_date(value: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let d = as_datetime(value)?;
    let ret = d.to_date().ok_or_else(|| {
        extension_err(
            format!(
                "overflows when computing the date of {}",
                RestrictedExpr::from(d),
            ),
            &TO_DATE_NAME,
            None,
        )
    })?;
    Ok(Value {
        value: ValueKind::ExtensionValue(Arc::new(ret.into())),
        loc: None,
    }
    .into())
}

fn to_time(value: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let d = as_datetime(value)?;
    let ret = d.to_time();
    Ok(Value {
        value: ValueKind::ExtensionValue(Arc::new(ret.into())),
        loc: None,
    }
    .into())
}

impl ExtensionValue for DateTime {
    fn typename(&self) -> crate::ast::Name {
        DATETIME_CONSTRUCTOR_NAME.to_owned()
    }
    fn supports_operator_overloading(&self) -> bool {
        true
    }
}

impl DateTime {
    const DAY_IN_MILLISECONDS: i64 = 1000 * 3600 * 24;
    const UNIX_EPOCH_STR: &'static str = "1970-01-01";

    fn offset(self, duration: Duration) -> Option<Self> {
        self.epoch
            .checked_add(duration.ms)
            .map(|epoch| Self { epoch })
    }

    fn duration_since(self, other: DateTime) -> Option<Duration> {
        self.epoch
            .checked_sub(other.epoch)
            .map(|ms| Duration { ms })
    }

    // essentially `self.epoch.div_floor(Self::DAY_IN_MILLISECONDS) * Self::DAY_IN_MILLISECONDS`
    // but `div_floor` is only available on nightly
    fn to_date(self) -> Option<Self> {
        if self.epoch.is_negative() {
            if self.epoch % Self::DAY_IN_MILLISECONDS == 0 {
                Some(self.epoch)
            } else {
                (self.epoch / Self::DAY_IN_MILLISECONDS - 1).checked_mul(Self::DAY_IN_MILLISECONDS)
            }
        } else {
            Some((self.epoch / Self::DAY_IN_MILLISECONDS) * Self::DAY_IN_MILLISECONDS)
        }
        .map(|epoch| Self { epoch })
    }

    fn to_time(self) -> Duration {
        Duration {
            ms: if self.epoch.is_negative() {
                let rem = self.epoch % Self::DAY_IN_MILLISECONDS;
                if rem == 0 {
                    rem
                } else {
                    rem + Self::DAY_IN_MILLISECONDS
                }
            } else {
                self.epoch % Self::DAY_IN_MILLISECONDS
            },
        }
    }

    fn as_ext_func_call(self) -> (Name, Vec<RestrictedExpr>) {
        (
            OFFSET_METHOD_NAME.clone(),
            vec![
                RestrictedExpr::call_extension_fn(
                    DATETIME_CONSTRUCTOR_NAME.clone(),
                    vec![Value::from(DateTime::UNIX_EPOCH_STR).into()],
                ),
                Duration { ms: self.epoch }.into(),
            ],
        )
    }
}

impl From<DateTime> for RestrictedExpr {
    fn from(value: DateTime) -> Self {
        let (func, args) = value.as_ext_func_call();
        Self::call_extension_fn(func, args)
    }
}

impl From<DateTime> for RepresentableExtensionValue {
    fn from(value: DateTime) -> Self {
        let (func, args) = value.as_ext_func_call();
        Self {
            func,
            args,
            value: Arc::new(value),
        }
    }
}

impl From<NaiveDateTime> for DateTime {
    fn from(value: NaiveDateTime) -> Self {
        let delta = chrono::DateTime::from_naive_utc_and_offset(value, chrono::Utc)
            - chrono::DateTime::UNIX_EPOCH;
        Self {
            epoch: delta.num_milliseconds(),
        }
    }
}

// The `duration` type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Duration {
    // The number of milliseconds
    ms: i64,
}

impl Display for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ms", self.ms)
    }
}

impl ExtensionValue for Duration {
    fn typename(&self) -> crate::ast::Name {
        DURATION_CONSTRUCTOR_NAME.to_owned()
    }
    fn supports_operator_overloading(&self) -> bool {
        true
    }
}

impl From<Duration> for RestrictedExpr {
    fn from(value: Duration) -> Self {
        let (func, args) = value.as_ext_func_call();
        RestrictedExpr::call_extension_fn(func, args)
    }
}

impl From<Duration> for RepresentableExtensionValue {
    fn from(value: Duration) -> Self {
        let (func, args) = value.as_ext_func_call();
        Self {
            func,
            args,
            value: Arc::new(value),
        }
    }
}

/// Cedar function that constructs a `duration` Cedar type from a
/// Cedar string
fn duration_from_str(arg: &Value) -> evaluator::Result<ExtensionOutputValue> {
    construct_from_str(arg, DURATION_CONSTRUCTOR_NAME.clone(), |s| {
        parse_duration(s).map_err(|err| {
            extension_err(
                err.to_string(),
                &DURATION_CONSTRUCTOR_NAME,
                err.help().map(|v| v.to_string()),
            )
        })
    })
}

impl Duration {
    fn to_milliseconds(self) -> i64 {
        self.ms
    }

    fn to_seconds(self) -> i64 {
        self.to_milliseconds() / 1000
    }

    fn to_minutes(self) -> i64 {
        self.to_seconds() / 60
    }

    fn to_hours(self) -> i64 {
        self.to_minutes() / 60
    }

    fn to_days(self) -> i64 {
        self.to_hours() / 24
    }

    fn as_ext_func_call(self) -> (Name, Vec<RestrictedExpr>) {
        (
            DURATION_CONSTRUCTOR_NAME.clone(),
            vec![Value::from(self.to_string()).into()],
        )
    }
}

fn duration_method(
    value: &Value,
    internal_func: impl Fn(Duration) -> i64,
) -> evaluator::Result<ExtensionOutputValue> {
    let d = as_duration(value)?;
    Ok(Value::from(internal_func(d)).into())
}

#[derive(Debug, Clone, Error, Diagnostic)]
enum DurationParseError {
    #[error("invalid duration pattern")]
    #[help("A valid duration string is a concatenated sequence of quantity-unit pairs with an optional `-` at the beginning")]
    InvalidPattern,
    #[error("Duration overflows internal representation")]
    #[help("A duration in milliseconds must be representable by a signed 64 bit integer")]
    Overflow,
}

fn parse_duration(s: &str) -> Result<Duration, DurationParseError> {
    if s.is_empty() || s == "-" {
        return Err(DurationParseError::InvalidPattern);
    }
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
        i64::try_from(-i128::from(ms)).map_err(|_| DurationParseError::Overflow)?
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
    #[help("A valid offset hour range should be [0,24) and minute range should be [0, 60)")]
    InvalidOffset((u32, u32)),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UTCOffset {
    positive: bool,
    hh: u32,
    mm: u32,
}

impl UTCOffset {
    const MAX_HH: u32 = 24;
    const MAX_MM: u32 = 60;

    fn to_seconds(&self) -> i64 {
        let offset_in_seconds_unsigned = i64::from(self.hh * 3600 + self.mm * 60);
        if self.positive {
            offset_in_seconds_unsigned
        } else {
            -offset_in_seconds_unsigned
        }
    }

    fn is_valid(&self) -> bool {
        self.hh < Self::MAX_HH && self.mm < Self::MAX_MM
    }
}

impl PartialOrd for UTCOffset {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UTCOffset {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_seconds().cmp(&other.to_seconds())
    }
}

fn parse_datetime(s: &str) -> Result<NaiveDateTime, DateTimeParseError> {
    // Get date first
    let (date_str, [year, month, day]) = DATE_PATTERN
        .captures(s)
        .ok_or(DateTimeParseError::InvalidDatePattern)?
        .extract();

    // It's a closure because we want to perform syntactical check first and
    // hence delay semantic check
    // Both checks are from left to right
    // PANIC SAFETY: `year`, `month`, and `day` should be all valid given the limit on the number of digits.
    #[allow(clippy::unwrap_used)]
    let date = || {
        NaiveDate::from_ymd_opt(
            year.parse().unwrap(),
            month.parse().unwrap(),
            day.parse().unwrap(),
        )
        .ok_or_else(|| DateTimeParseError::InvalidDate(date_str.into()))
    };

    // A complete match; simply return
    if date_str.len() == s.len() {
        // PANIC SAFETY: `0`s should be all valid given the limit on the number of digits.
        #[allow(clippy::unwrap_used)]
        return Ok(NaiveDateTime::new(
            date()?,
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

    let date = date()?;
    let time = NaiveTime::from_hms_milli_opt(h, m, sec, ms)
        .ok_or_else(|| DateTimeParseError::InvalidHMS(hms_str[1..].into()))?;
    let offset: Result<TimeDelta, DateTimeParseError> = if captures.get(4).is_some() {
        let positive = &captures[5] == "+";
        // PANIC SAFETY: should be valid given the limit on the number of digits.
        #[allow(clippy::unwrap_used)]
        let (offset_hour, offset_min): (u32, u32) =
            (captures[6].parse().unwrap(), captures[7].parse().unwrap());
        let offset = UTCOffset {
            positive,
            hh: offset_hour,
            mm: offset_min,
        };
        if offset.is_valid() {
            let offset_in_secs = offset.to_seconds();
            // PANIC SAFETY: should be valid because the limit on the values of offsets.
            #[allow(clippy::unwrap_used)]
            Ok(TimeDelta::new(-offset_in_secs, 0).unwrap())
        } else {
            Err(DateTimeParseError::InvalidOffset((offset_hour, offset_min)))
        }
    } else {
        Ok(TimeDelta::default())
    };
    Ok(NaiveDateTime::new(date, time) + offset?)
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
                datetime_type,
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
                duration_type,
            ),
        ],
        [
            DATETIME_CONSTRUCTOR_NAME.clone(),
            DURATION_CONSTRUCTOR_NAME.clone(),
        ],
    )
}

#[cfg(test)]
#[allow(clippy::cognitive_complexity)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use chrono::NaiveDateTime;
    use cool_asserts::assert_matches;
    use nonempty::nonempty;

    use crate::{
        ast::{Eid, EntityUID, EntityUIDEntry, Expr, Request, Type, Value, ValueKind},
        entities::Entities,
        evaluator::{EvaluationError, Evaluator},
        extensions::{
            datetime::{
                constants::{
                    DURATION_CONSTRUCTOR_NAME, TO_DATE_NAME, TO_DAYS_NAME, TO_HOURS_NAME,
                    TO_MILLISECONDS_NAME, TO_MINUTES_NAME, TO_SECONDS_NAME, TO_TIME_NAME,
                },
                parse_datetime, parse_duration, DateTimeParseError, Duration,
            },
            Extensions,
        },
        parser::parse_expr,
    };

    use super::{constants::DATETIME_CONSTRUCTOR_NAME, DateTime};

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
            NaiveDateTime::from_str("2024-10-15T00:04:02.101").unwrap()
        );
        let s = "2024-10-15T11:38:02.101-1134";
        assert_eq!(
            parse_datetime(s).unwrap(),
            NaiveDateTime::from_str("2024-10-15T23:12:02.101").unwrap()
        );
        let s = "2024-10-15T11:38:02+1134";
        assert_eq!(
            parse_datetime(s).unwrap(),
            NaiveDateTime::from_str("2024-10-15T00:04:02").unwrap()
        );
        let s = "2024-10-15T11:38:02-1134";
        assert_eq!(
            parse_datetime(s).unwrap(),
            NaiveDateTime::from_str("2024-10-15T23:12:02").unwrap()
        );
        let s = "2024-10-15T23:59:00+2359";
        assert_eq!(
            parse_datetime(s).unwrap(),
            NaiveDateTime::from_str("2024-10-15T00:00:00").unwrap()
        );
        let s = "2024-10-15T00:00:00-2359";
        assert_eq!(
            parse_datetime(s).unwrap(),
            NaiveDateTime::from_str("2024-10-15T23:59:00").unwrap()
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

        // invalid dates
        assert_matches!(
            parse_datetime("0000-0a-01"),
            Err(DateTimeParseError::InvalidDatePattern)
        );
        assert_matches!(
            parse_datetime("10000-01-01"),
            Err(DateTimeParseError::InvalidDatePattern)
        );
        assert_matches!(
            parse_datetime("10000-01-01T00:00:00Z"),
            Err(DateTimeParseError::InvalidDatePattern)
        );
        assert_matches!(parse_datetime("2024-00-01"), Err(DateTimeParseError::InvalidDate(s)) if s == "2024-00-01");
        assert_matches!(parse_datetime("2024-01-00"), Err(DateTimeParseError::InvalidDate(s)) if s == "2024-01-00");
        assert_matches!(parse_datetime("2024-02-30"), Err(DateTimeParseError::InvalidDate(s)) if s == "2024-02-30");
        assert_matches!(parse_datetime("2025-02-29"), Err(DateTimeParseError::InvalidDate(s)) if s == "2025-02-29");
        assert_matches!(parse_datetime("2024-20-01"), Err(DateTimeParseError::InvalidDate(s)) if s == "2024-20-01");
        assert_matches!(parse_datetime("2024-01-32"), Err(DateTimeParseError::InvalidDate(s)) if s == "2024-01-32");
        assert_matches!(parse_datetime("2024-01-99"), Err(DateTimeParseError::InvalidDate(s)) if s == "2024-01-99");
        assert_matches!(parse_datetime("2024-04-31"), Err(DateTimeParseError::InvalidDate(s)) if s == "2024-04-31");

        // invalid hms
        assert_matches!(
            parse_datetime("2024-01-01T"),
            Err(DateTimeParseError::InvalidHMSPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01Ta"),
            Err(DateTimeParseError::InvalidHMSPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T01:"),
            Err(DateTimeParseError::InvalidHMSPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T01:02"),
            Err(DateTimeParseError::InvalidHMSPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T01:02:0b"),
            Err(DateTimeParseError::InvalidHMSPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T01::02:03"),
            Err(DateTimeParseError::InvalidHMSPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T01::02::03"),
            Err(DateTimeParseError::InvalidHMSPattern)
        );
        assert_matches!(parse_datetime("2024-01-01T31:02:03Z"), Err(DateTimeParseError::InvalidHMS(s)) if s == "31:02:03");
        assert_matches!(parse_datetime("2024-01-01T01:60:03Z"), Err(DateTimeParseError::InvalidHMS(s)) if s == "01:60:03");
        // we disallow `60`th second (i.e., potentially a leap second) because
        // we can't check if it's a true leap second or not, though we can
        // handle any computation if it's deemed to be a valid leap second
        // Note that `2016-12-31T23:59:60Z` is the latest leap second as of
        // writing
        assert_matches!(parse_datetime("2016-12-31T23:59:60Z"), Err(DateTimeParseError::InvalidHMS(s)) if s == "23:59:60");
        assert_matches!(parse_datetime("2016-12-31T23:59:61Z"), Err(DateTimeParseError::InvalidHMS(s)) if s == "23:59:61");

        assert_matches!(
            parse_datetime("2024-01-01T00:00:00"),
            Err(DateTimeParseError::InvalidMSOffsetPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T00:00:00T"),
            Err(DateTimeParseError::InvalidMSOffsetPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T00:00:00ZZ"),
            Err(DateTimeParseError::InvalidMSOffsetPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T00:00:00x001Z"),
            Err(DateTimeParseError::InvalidMSOffsetPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T00:00:00.001ZZ"),
            Err(DateTimeParseError::InvalidMSOffsetPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T00:00:00➕0000"),
            Err(DateTimeParseError::InvalidMSOffsetPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T00:00:00➖0000"),
            Err(DateTimeParseError::InvalidMSOffsetPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T00:00:00.0001Z"),
            Err(DateTimeParseError::InvalidMSOffsetPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T00:00:00.001➖0000"),
            Err(DateTimeParseError::InvalidMSOffsetPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T00:00:00.001➕0000"),
            Err(DateTimeParseError::InvalidMSOffsetPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T00:00:00.001+00000"),
            Err(DateTimeParseError::InvalidMSOffsetPattern)
        );
        assert_matches!(
            parse_datetime("2024-01-01T00:00:00.001-00000"),
            Err(DateTimeParseError::InvalidMSOffsetPattern)
        );
        assert_matches!(
            parse_datetime("2016-12-31T00:00:00+1160"),
            Err(DateTimeParseError::InvalidOffset((11, 60)))
        );
        assert_matches!(
            parse_datetime("2016-12-31T00:00:00+1199"),
            Err(DateTimeParseError::InvalidOffset((11, 99)))
        );
        assert_matches!(
            parse_datetime("2016-12-31T00:00:00+2400"),
            Err(DateTimeParseError::InvalidOffset((24, 0)))
        );
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
        for s in [
            "", "a", "-", "-1", "➖1ms", "11dd", "00000mm", "-d", "-h", "-1hh", "-h2d", "-ms",
            // incorrect ordering
            "1ms1s", "1ms1m", "1ms1h", "0ms1d", "1s1m", "1s1h", "0s0d", "0m0h", "0m0d", "1h1d",
            "1ms1m1d",
        ] {
            assert!(parse_duration(s).is_err());
        }
        assert!(parse_duration(&milliseconds_to_duration(i128::from(i64::MAX) + 1)).is_err());
        assert!(parse_duration(&milliseconds_to_duration(i128::from(i64::MIN) - 1)).is_err());
    }

    #[test]
    fn test_offset() {
        let unix_epoch = DateTime { epoch: 0 };
        let date_time_max = unix_epoch
            .offset(parse_duration(&milliseconds_to_duration(i64::MAX.into())).unwrap())
            .expect("valid datetime");
        let date_time_min = unix_epoch
            .offset(parse_duration(&milliseconds_to_duration(i64::MIN.into())).unwrap())
            .expect("valid datetime");
        assert!(date_time_max
            .offset(parse_duration("1ms").unwrap())
            .is_none());
        assert_eq!(
            date_time_max.offset(parse_duration("-1ms").unwrap()),
            Some(
                unix_epoch
                    .offset(
                        parse_duration(&milliseconds_to_duration(i128::from(i64::MAX) - 1))
                            .unwrap()
                    )
                    .expect("valid datetime")
            )
        );
        assert!(date_time_min
            .offset(parse_duration("-1ms").unwrap())
            .is_none());
        assert_eq!(
            date_time_min.offset(parse_duration("1ms").unwrap()),
            Some(
                unix_epoch
                    .offset(
                        parse_duration(&milliseconds_to_duration(i128::from(i64::MIN) + 1))
                            .unwrap()
                    )
                    .expect("valid datetime")
            )
        );
        assert_eq!(
            unix_epoch.offset(parse_duration("1d").unwrap()),
            Some(parse_datetime("1970-01-02").unwrap().into())
        );
        assert_eq!(
            unix_epoch.offset(parse_duration("-1d").unwrap()),
            Some(parse_datetime("1969-12-31").unwrap().into())
        );
    }

    #[test]
    fn test_duration_since() {
        let unix_epoch = DateTime { epoch: 0 };
        let today: DateTime = parse_datetime("2024-10-24").unwrap().into();
        assert_eq!(
            today.duration_since(unix_epoch),
            Some(parse_duration("20020d").unwrap())
        );
        let yesterday: DateTime = parse_datetime("2024-10-23").unwrap().into();
        assert_eq!(
            yesterday.duration_since(today),
            Some(parse_duration("-1d").unwrap())
        );
        assert_eq!(
            today.duration_since(yesterday),
            Some(parse_duration("1d").unwrap())
        );

        let date_time_min = unix_epoch
            .offset(parse_duration(&milliseconds_to_duration(i64::MIN.into())).unwrap())
            .expect("valid datetime");
        assert!(today.duration_since(date_time_min).is_none());
    }

    #[test]
    fn test_to_date() {
        let unix_epoch = DateTime { epoch: 0 };
        let today: DateTime = parse_datetime("2024-10-24").unwrap().into();
        assert_eq!(
            today.duration_since(unix_epoch),
            Some(parse_duration("20020d").unwrap())
        );
        let yesterday: DateTime = parse_datetime("2024-10-23").unwrap().into();
        assert_eq!(
            yesterday.duration_since(today),
            Some(parse_duration("-1d").unwrap())
        );
        let some_day_before_unix_epoch: DateTime = parse_datetime("1900-01-01").unwrap().into();

        let max_day_offset = parse_duration("23h59m59s999ms").unwrap();
        let min_day_offset = parse_duration("-23h59m59s999ms").unwrap();

        for d in [today, yesterday, unix_epoch, some_day_before_unix_epoch] {
            assert_eq!(d.to_date().expect("should not overflow"), d);
            assert_eq!(
                d.offset(max_day_offset)
                    .unwrap()
                    .to_date()
                    .expect("should not overflow"),
                d
            );
            assert_eq!(
                d.offset(min_day_offset)
                    .unwrap()
                    .to_date()
                    .expect("should not overflow"),
                d.offset(parse_duration("-1d").unwrap()).unwrap()
            );
        }

        assert!(unix_epoch
            .offset(Duration { ms: i64::MIN })
            .expect("should be able to construct")
            .to_date()
            .is_none());
    }

    #[test]
    fn test_to_time() {
        let unix_epoch = DateTime { epoch: 0 };
        let today: DateTime = parse_datetime("2024-10-24").unwrap().into();
        assert_eq!(
            today.duration_since(unix_epoch),
            Some(parse_duration("20020d").unwrap())
        );
        let yesterday: DateTime = parse_datetime("2024-10-23").unwrap().into();
        assert_eq!(
            yesterday.duration_since(today),
            Some(parse_duration("-1d").unwrap())
        );
        let some_day_before_unix_epoch: DateTime = parse_datetime("1900-01-01").unwrap().into();

        let max_day_offset = parse_duration("23h59m59s999ms").unwrap();
        let min_day_offset = parse_duration("-23h59m59s999ms").unwrap();

        for d in [today, yesterday, unix_epoch, some_day_before_unix_epoch] {
            assert_eq!(d.offset(max_day_offset).unwrap().to_time(), max_day_offset);
            assert_eq!(
                d.offset(min_day_offset).unwrap().to_time(),
                parse_duration("1ms").unwrap(),
            );
        }
    }

    #[test]
    fn test_predicates() {
        let unix_epoch = DateTime { epoch: 0 };
        let today: DateTime = parse_datetime("2024-10-24").unwrap().into();
        let yesterday: DateTime = parse_datetime("2024-10-23").unwrap().into();
        let some_day_before_unix_epoch: DateTime = parse_datetime("1900-01-01").unwrap().into();
        assert!(unix_epoch <= unix_epoch);
        assert!(today == today);
        assert!(today != yesterday);
        assert!(unix_epoch < today);
        assert!(today > yesterday);
        assert!(some_day_before_unix_epoch <= unix_epoch);
        assert!(today >= some_day_before_unix_epoch);
        assert!(yesterday >= some_day_before_unix_epoch);
    }

    #[test]
    fn test_duration_methods() {
        let day_offset = parse_duration("10d23h59m58s999ms").unwrap();
        let day_offset_neg = parse_duration("-10d23h59m58s999ms").unwrap();
        for o in [day_offset, day_offset_neg] {
            assert_eq!(o.to_days().abs(), 10);
            assert_eq!(o.to_hours().abs(), 10 * 24 + 23);
            assert_eq!(o.to_minutes().abs(), (10 * 24 + 23) * 60 + 59);
            assert_eq!(o.to_seconds().abs(), ((10 * 24 + 23) * 60 + 59) * 60 + 58);
            assert_eq!(
                o.to_milliseconds().abs(),
                (((10 * 24 + 23) * 60 + 59) * 60 + 58) * 1000 + 999
            );
        }
    }

    fn dummy_entity() -> EntityUIDEntry {
        EntityUIDEntry::Known {
            euid: Arc::new(EntityUID::from_components(
                "A".parse().unwrap(),
                Eid::new(""),
                None,
            )),
            loc: None,
        }
    }

    #[test]
    fn test_interpretation_datetime() {
        let dummy_entity = dummy_entity();
        let entities = Entities::default();
        let eval = Evaluator::new(
            Request::new_unchecked(
                dummy_entity.clone(),
                dummy_entity.clone(),
                dummy_entity,
                None,
            ),
            &entities,
            Extensions::all_available(),
        );

        assert_matches!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                DATETIME_CONSTRUCTOR_NAME.clone(),
                vec![Value::from("2024-10-28").into()]
            )),
            Ok(Value {
                value: ValueKind::ExtensionValue(ext),
                ..
            }) => {
                assert!(ext.value().equals_extvalue(&DateTime {epoch: 1730073600000}));
            }
        );

        assert_matches!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                DATETIME_CONSTRUCTOR_NAME.clone(),
                vec![Value::from("2024-10-28T01:22:33.456Z").into()]
            )),
            Ok(Value {
                value: ValueKind::ExtensionValue(ext),
                ..
            }) => {
                assert!(ext.value().equals_extvalue(&DateTime {epoch: 1730078553456}));
            }
        );

        assert_matches!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                DATETIME_CONSTRUCTOR_NAME.clone(),
                vec![Value::from("2024-10-28T10:12:13.456-0700").into()]
            )),
            Ok(Value {
                value: ValueKind::ExtensionValue(ext),
                ..
            }) => {
                assert!(ext.value().equals_extvalue(&DateTime {epoch: 1730135533456}));
            }
        );

        assert_matches!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                DATETIME_CONSTRUCTOR_NAME.clone(),
                vec![Value::from("22024-30-28T10:12:13.456-0700").into()]
            )),
            Err(EvaluationError::FailedExtensionFunctionExecution(err)) => {
                assert_eq!(err.extension_name, *DATETIME_CONSTRUCTOR_NAME);
                assert_eq!(err.msg, "invalid date pattern".to_owned());
                // TODO: figure out why it's none given the help annotations
                assert_eq!(err.advice, None);
            }
        );

        // offset the offset component in a datetime specification
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"datetime("2024-10-28T10:12:13.456-0700").offset(duration("-7h"))"#)
                    .unwrap()
            )
            .unwrap(),
            eval.interpret_inline_policy(
                &parse_expr(r#"datetime("2024-10-28T10:12:13.456Z")"#).unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"datetime("2024-10-28T10:12:13.456+0700").offset(duration("7h"))"#)
                    .unwrap()
            )
            .unwrap(),
            eval.interpret_inline_policy(
                &parse_expr(r#"datetime("2024-10-28T10:12:13.456Z")"#).unwrap()
            )
            .unwrap()
        );

        assert_matches!(
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28T10:12:13.456+0700").offset("7h")"#).unwrap()),
            Err(EvaluationError::TypeError(err)) => {
                assert_eq!(err.expected, nonempty![Type::Extension { name: DURATION_CONSTRUCTOR_NAME.clone() }]);
                assert_eq!(err.actual, Type::String);
                assert_eq!(err.advice, Some("maybe you forgot to apply the `duration` constructor?".to_owned()));
            }
        );

        // .durationSince
        assert_eq!(
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28T10:12:13.456+0700").durationSince(datetime("2024-10-28T10:12:13.456Z"))"#).unwrap()).unwrap(),
            eval.interpret_inline_policy(&parse_expr(r#"duration("-7h")"#).unwrap()).unwrap()
        );

        assert_eq!(
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28T10:12:13.456-0700").durationSince(datetime("2024-10-28T10:12:13.456Z"))"#).unwrap()).unwrap(),
            eval.interpret_inline_policy(&parse_expr(r#"duration("7h")"#).unwrap()).unwrap()
        );

        assert_matches!(
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28T10:12:13.456+0700").durationSince("7h")"#).unwrap()),
            Err(EvaluationError::TypeError(err)) => {
                assert_eq!(err.expected, nonempty![Type::Extension { name: DATETIME_CONSTRUCTOR_NAME.clone() }]);
                assert_eq!(err.actual, Type::String);
                assert_eq!(err.advice, Some("maybe you forgot to apply the `datetime` constructor?".to_owned()));
            }
        );

        // .toDate
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"datetime("2024-10-28T10:12:13.456+0700").toDate()"#).unwrap()
            )
            .unwrap(),
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28")"#).unwrap())
                .unwrap()
        );

        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"datetime("2024-10-28T10:12:13.456-0700").toDate()"#).unwrap()
            )
            .unwrap(),
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28")"#).unwrap())
                .unwrap()
        );

        assert_matches!(
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28T10:12:13.456-0700").toDate(1)"#).unwrap()),
            Err(EvaluationError::WrongNumArguments(err)) => {
                assert_eq!(err.function_name, *TO_DATE_NAME);
                assert_eq!(err.actual, 2);
                assert_eq!(err.expected, 1);
            }
        );

        // .toTime
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"datetime("2024-10-28T10:12:13.456+0700").toTime()"#).unwrap()
            )
            .unwrap(),
            eval.interpret_inline_policy(&parse_expr(r#"duration("3h12m13s456ms")"#).unwrap())
                .unwrap()
        );

        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"datetime("2024-10-28T10:12:13.456-0700").toTime()"#).unwrap()
            )
            .unwrap(),
            eval.interpret_inline_policy(&parse_expr(r#"duration("17h12m13s456ms")"#).unwrap())
                .unwrap()
        );

        assert_matches!(
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28T10:12:13.456-0700").toTime(1)"#).unwrap()),
            Err(EvaluationError::WrongNumArguments(err)) => {
                assert_eq!(err.function_name, *TO_TIME_NAME);
                assert_eq!(err.actual, 2);
                assert_eq!(err.expected, 1);
            }
        );

        // comparisons
        assert_eq!(
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28T10:12:13.456-0700") > datetime("2024-10-28T10:12:13.456Z")"#).unwrap()).unwrap(),
            Value::from(true),
        );
        assert_eq!(
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28T10:12:13.456-0700") >= datetime("2024-10-28T10:12:13.456Z")"#).unwrap()).unwrap(),
            Value::from(true),
        );
        assert_eq!(
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28T10:12:13.456-0700") != datetime("2024-10-28T10:12:13.456Z")"#).unwrap()).unwrap(),
            Value::from(true),
        );
        assert_eq!(
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28T10:12:13.456-0700") == datetime("2024-10-28T17:12:13.456Z")"#).unwrap()).unwrap(),
            Value::from(true),
        );
        assert_eq!(
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28T10:12:13.456-0700") < datetime("2024-10-28T17:12:13.456-0800")"#).unwrap()).unwrap(),
            Value::from(true),
        );
        assert_eq!(
            eval.interpret_inline_policy(&parse_expr(r#"datetime("2024-10-28T10:12:13.456-0700") <= datetime("2024-10-28T17:12:13.456-0800")"#).unwrap()).unwrap(),
            Value::from(true),
        );
    }

    #[test]
    fn test_interpretation_duration() {
        let dummy_entity = dummy_entity();
        let entities = Entities::default();
        let eval = Evaluator::new(
            Request::new_unchecked(
                dummy_entity.clone(),
                dummy_entity.clone(),
                dummy_entity,
                None,
            ),
            &entities,
            Extensions::all_available(),
        );

        assert_matches!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                DURATION_CONSTRUCTOR_NAME.clone(),
                vec![Value::from("1d2h3m4s50ms").into()]
            )),
            Ok(Value {
                value: ValueKind::ExtensionValue(ext),
                ..
            }) => {
                assert!(ext.value().equals_extvalue(&Duration {ms: 93784050}));
            }
        );

        assert_matches!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                DURATION_CONSTRUCTOR_NAME.clone(),
                vec![Value::from("1dd2h3m4s50ms").into()]
            )),
            Err(EvaluationError::FailedExtensionFunctionExecution(err)) => {
                assert_eq!(err.extension_name, *DURATION_CONSTRUCTOR_NAME);
                assert_eq!(err.msg, "invalid duration pattern".to_owned());
                // TODO: figure out why it's none given the help annotations
                assert_eq!(err.advice, None);
            }
        );

        // .toMilliseconds
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("1d2h3m4s50ms").toMilliseconds()"#).unwrap()
            )
            .unwrap(),
            Value::from(93784050)
        );

        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("-1d2h3m4s50ms").toMilliseconds()"#).unwrap()
            )
            .unwrap(),
            Value::from(-93784050)
        );

        assert_matches!(
            eval.interpret_inline_policy(&parse_expr(r#"duration("-1d2h3m4s50ms").toMilliseconds(1)"#).unwrap()),
            Err(EvaluationError::WrongNumArguments(err)) => {
                assert_eq!(err.function_name, *TO_MILLISECONDS_NAME);
                assert_eq!(err.actual, 2);
                assert_eq!(err.expected, 1);
            }
        );

        // .toSeconds
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("1d2h3m4s50ms").toSeconds()"#).unwrap()
            )
            .unwrap(),
            Value::from(93784)
        );

        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("-1d2h3m4s50ms").toSeconds()"#).unwrap()
            )
            .unwrap(),
            Value::from(-93784)
        );

        assert_matches!(
            eval.interpret_inline_policy(&parse_expr(r#"duration("-1d2h3m4s50ms").toSeconds(1)"#).unwrap()),
            Err(EvaluationError::WrongNumArguments(err)) => {
                assert_eq!(err.function_name, *TO_SECONDS_NAME);
                assert_eq!(err.actual, 2);
                assert_eq!(err.expected, 1);
            }
        );

        // .toMinutes
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("1d2h3m4s50ms").toMinutes()"#).unwrap()
            )
            .unwrap(),
            Value::from(1563)
        );

        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("-1d2h3m4s50ms").toMinutes()"#).unwrap()
            )
            .unwrap(),
            Value::from(-1563)
        );

        assert_matches!(
            eval.interpret_inline_policy(&parse_expr(r#"duration("-1d2h3m4s50ms").toMinutes(1)"#).unwrap()),
            Err(EvaluationError::WrongNumArguments(err)) => {
                assert_eq!(err.function_name, *TO_MINUTES_NAME);
                assert_eq!(err.actual, 2);
                assert_eq!(err.expected, 1);
            }
        );

        // .toHours
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("1d2h3m4s50ms").toHours()"#).unwrap()
            )
            .unwrap(),
            Value::from(26)
        );

        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("-1d2h3m4s50ms").toHours()"#).unwrap()
            )
            .unwrap(),
            Value::from(-26)
        );

        assert_matches!(
            eval.interpret_inline_policy(&parse_expr(r#"duration("-1d2h3m4s50ms").toHours(1)"#).unwrap()),
            Err(EvaluationError::WrongNumArguments(err)) => {
                assert_eq!(err.function_name, *TO_HOURS_NAME);
                assert_eq!(err.actual, 2);
                assert_eq!(err.expected, 1);
            }
        );

        // .toDays
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("1d2h3m4s50ms").toDays()"#).unwrap()
            )
            .unwrap(),
            Value::from(1)
        );

        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("-1d2h3m4s50ms").toDays()"#).unwrap()
            )
            .unwrap(),
            Value::from(-1)
        );

        assert_matches!(
            eval.interpret_inline_policy(&parse_expr(r#"duration("-1d2h3m4s50ms").toDays(1)"#).unwrap()),
            Err(EvaluationError::WrongNumArguments(err)) => {
                assert_eq!(err.function_name, *TO_DAYS_NAME);
                assert_eq!(err.actual, 2);
                assert_eq!(err.expected, 1);
            }
        );

        // Python's datetime does this but is -2h shorter than 1h?
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("-2h") < duration("1h")"#).unwrap()
            )
            .unwrap(),
            Value::from(true),
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("-2h") <= duration("1h")"#).unwrap()
            )
            .unwrap(),
            Value::from(true),
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("-2h") != duration("1h")"#).unwrap()
            )
            .unwrap(),
            Value::from(true),
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("-3d") == duration("-72h")"#).unwrap()
            )
            .unwrap(),
            Value::from(true),
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("2h") > duration("1h")"#).unwrap()
            )
            .unwrap(),
            Value::from(true),
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"duration("2h") >= duration("1h")"#).unwrap()
            )
            .unwrap(),
            Value::from(true),
        );
    }
}
