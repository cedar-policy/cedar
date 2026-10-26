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

#[cfg(feature = "verus")]
use vstd::prelude::*;

use chrono::{NaiveDate, NaiveDateTime, NaiveTime, TimeDelta};
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

use crate::{
    ast::{
        CallStyle, Extension, ExtensionFunction, ExtensionOutputValue, ExtensionValue, Literal,
        Name, RepresentableExtensionValue, RestrictedExpr, Type, Value, ValueKind,
    },
    entities::SchemaType,
    evaluator::{self},
};

const DATETIME_EXTENSION_NAME: &str = "datetime";

/// Help text describing the valid datetime format, used as a fallback when a
/// specific parse error does not carry its own help text.
const VALID_DATETIME_HELP: &str = "valid datetime strings start with `YYYY-MM-DD` and may optionally include `THH:MM:SS` plus `Z`, `.SSSZ`, or an offset like `+0700`";

/// Help text describing the valid duration format, used as a fallback when a
/// specific parse error does not carry its own help text.
const VALID_DURATION_HELP: &str = "valid duration strings are concatenated quantity-unit pairs with an optional leading `-`, for example `1d2h3m4s50ms`";

#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "The `Name`s and `Regex` here are valid"
)]
pub(crate) mod constants {
    use regex::Regex;
    use std::sync::LazyLock;

    use crate::{ast::Name, extensions::datetime::DATETIME_EXTENSION_NAME};

    pub static DATETIME_CONSTRUCTOR_NAME: LazyLock<Name> = LazyLock::new(|| {
        Name::parse_unqualified_name(DATETIME_EXTENSION_NAME).expect("should be a valid identifier")
    });
    pub static DURATION_CONSTRUCTOR_NAME: LazyLock<Name> = LazyLock::new(|| {
        Name::parse_unqualified_name("duration").expect("should be a valid identifier")
    });
    pub static OFFSET_METHOD_NAME: LazyLock<Name> = LazyLock::new(|| {
        Name::parse_unqualified_name("offset").expect("should be a valid identifier")
    });
    pub static DURATION_SINCE_NAME: LazyLock<Name> = LazyLock::new(|| {
        Name::parse_unqualified_name("durationSince").expect("should be a valid identifier")
    });
    pub static TO_DATE_NAME: LazyLock<Name> = LazyLock::new(|| {
        Name::parse_unqualified_name("toDate").expect("should be a valid identifier")
    });
    pub static TO_TIME_NAME: LazyLock<Name> = LazyLock::new(|| {
        Name::parse_unqualified_name("toTime").expect("should be a valid identifier")
    });
    pub static TO_MILLISECONDS_NAME: LazyLock<Name> = LazyLock::new(|| {
        Name::parse_unqualified_name("toMilliseconds").expect("should be a valid identifier")
    });
    pub static TO_SECONDS_NAME: LazyLock<Name> = LazyLock::new(|| {
        Name::parse_unqualified_name("toSeconds").expect("should be a valid identifier")
    });
    pub static TO_MINUTES_NAME: LazyLock<Name> = LazyLock::new(|| {
        Name::parse_unqualified_name("toMinutes").expect("should be a valid identifier")
    });
    pub static TO_HOURS_NAME: LazyLock<Name> = LazyLock::new(|| {
        Name::parse_unqualified_name("toHours").expect("should be a valid identifier")
    });
    pub static TO_DAYS_NAME: LazyLock<Name> = LazyLock::new(|| {
        Name::parse_unqualified_name("toDays").expect("should be a valid identifier")
    });

    // Global regex, initialized at first use
    pub static DURATION_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        #[expect(clippy::unwrap_used, reason = "These are valid `Regex`")]
        Regex::new(r"^-?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?$").unwrap()
    });
    pub static DATE_PATTERN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})").unwrap());
    pub static HMS_PATTERN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^T([0-9]{2}):([0-9]{2}):([0-9]{2})").unwrap());
    pub static MS_AND_OFFSET_PATTERN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^(\.([0-9]{3}))?(Z|((\+|-)([0-9]{2})([0-9]{2})))$").unwrap());
}

// The `datetime` type, represented internally as an `i64`.
#[cfg_attr(feature = "verus", verus_verify(external_derive))]
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

/// Cedar function that constructs a `datetime` Cedar type from a
/// Cedar string
#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(r, crate::verification::model::ext::call(&crate::verification::model::ext::ExtFun::Datetime, &crate::verification::ext_abs::args1(*arg)))
))]
fn datetime_from_str(arg: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let s = arg.get_as_string()?;
    let ext_value = match parse_datetime(s.as_str()) {
        Ok(ndt) => DateTime::of_naive(ndt),
        Err(err) => return Err(datetime_parse_error(&err)),
    };
    Ok(datetime_value(ext_value, arg))
}

/// The evaluation error for a failed datetime parse
#[cfg_attr(feature = "verus", verus_verify(external_body))]
fn datetime_parse_error(err: &DateTimeParseError) -> evaluator::EvaluationError {
    extension_err(
        err.to_string(),
        &constants::DATETIME_CONSTRUCTOR_NAME,
        Some(
            err.help()
                .map(|v| v.to_string())
                .unwrap_or_else(|| VALID_DATETIME_HELP.to_string()),
        ),
    )
}

/// The `datetime` value `d`, constructed from the string `arg`
#[cfg_attr(feature = "verus", verus_verify(external_body))]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(Ok(r), Ok(crate::verification::model::ext::ExtRes::Ext(crate::verification::model::ext::Ext::Datetime(d.epoch))))
))]
fn datetime_value(d: DateTime, arg: &Value) -> ExtensionOutputValue {
    let arg_source_loc = arg.source_loc();
    let e = RepresentableExtensionValue::new(
        Arc::new(d),
        constants::DATETIME_CONSTRUCTOR_NAME.clone(),
        vec![arg.clone().into()],
    );
    Value {
        value: ValueKind::ExtensionValue(Arc::new(e)),
        loc: arg_source_loc.cloned(), // follow the same convention as the `decimal` extension
    }
    .into()
}

/// The `duration` value `d`, constructed from the string `arg`
#[cfg_attr(feature = "verus", verus_verify(external_body))]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(Ok(r), Ok(crate::verification::model::ext::ExtRes::Ext(crate::verification::model::ext::Ext::Duration(d.ms))))
))]
fn duration_value(d: Duration, arg: &Value) -> ExtensionOutputValue {
    let arg_source_loc = arg.source_loc();
    let e = RepresentableExtensionValue::new(
        Arc::new(d),
        constants::DURATION_CONSTRUCTOR_NAME.clone(),
        vec![arg.clone().into()],
    );
    Value {
        value: ValueKind::ExtensionValue(Arc::new(e)),
        loc: arg_source_loc.cloned(), // follow the same convention as the `decimal` extension
    }
    .into()
}

/// The `datetime` value `d`, computed by an extension function
#[cfg_attr(feature = "verus", verus_verify(external_body))]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(Ok(r), Ok(crate::verification::model::ext::ExtRes::Ext(crate::verification::model::ext::Ext::Datetime(d.epoch))))
))]
fn datetime_output(d: DateTime) -> ExtensionOutputValue {
    Value {
        value: ValueKind::ExtensionValue(Arc::new(d.into())),
        loc: None,
    }
    .into()
}

/// The `duration` value `d`, computed by an extension function
#[cfg_attr(feature = "verus", verus_verify(external_body))]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(Ok(r), Ok(crate::verification::model::ext::ExtRes::Ext(crate::verification::model::ext::Ext::Duration(d.ms))))
))]
fn duration_output(d: Duration) -> ExtensionOutputValue {
    Value {
        value: ValueKind::ExtensionValue(Arc::new(d.into())),
        loc: None,
    }
    .into()
}

#[cfg_attr(feature = "verus", verus_verify(external))]
fn as_ext<'a, Ext>(v: &'a Value, type_name: &'a Name) -> Result<&'a Ext, evaluator::EvaluationError>
where
    Ext: ExtensionValue + std::cmp::Ord + 'static,
{
    match &v.value {
        ValueKind::ExtensionValue(ev) if ev.typename() == *type_name => {
            #[expect(clippy::expect_used, reason = "Conditional above performs a typecheck")]
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
#[cfg_attr(feature = "verus", verus_verify(external_body))]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures
        match r {
            Ok(d) => crate::verification::ext_abs::ext_arg(*v) == crate::verification::model::value::Value::Ext(crate::verification::model::ext::Ext::Datetime(d.epoch)),
            Err(_) => !(crate::verification::ext_abs::ext_arg(*v) matches crate::verification::model::value::Value::Ext(crate::verification::model::ext::Ext::Datetime(_))),
        }
))]
fn as_datetime(v: &Value) -> Result<DateTime, evaluator::EvaluationError> {
    as_ext(v, &constants::DATETIME_CONSTRUCTOR_NAME).copied()
}

/// Check that `v` is a duration type and, if it is, return the wrapped value
#[cfg_attr(feature = "verus", verus_verify(external_body))]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures
        match r {
            Ok(d) => crate::verification::ext_abs::ext_arg(*v) == crate::verification::model::value::Value::Ext(crate::verification::model::ext::Ext::Duration(d.ms)),
            Err(_) => !(crate::verification::ext_abs::ext_arg(*v) matches crate::verification::model::value::Value::Ext(crate::verification::model::ext::Ext::Duration(_))),
        }
))]
fn as_duration(v: &Value) -> Result<Duration, evaluator::EvaluationError> {
    as_ext(v, &constants::DURATION_CONSTRUCTOR_NAME).copied()
}

#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(r, crate::verification::model::ext::call(&crate::verification::model::ext::ExtFun::Offset, &crate::verification::ext_abs::args2(*datetime, *duration)))
))]
fn offset(datetime: &Value, duration: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let datetime = as_datetime(datetime)?;
    let duration = as_duration(duration)?;
    let ret = match datetime.offset(duration) {
        Some(ret) => ret,
        None => return Err(offset_error(datetime, duration)),
    };
    Ok(datetime_output(ret))
}

#[cfg_attr(feature = "verus", verus_verify(external_body))]
fn offset_error(datetime: DateTime, duration: Duration) -> evaluator::EvaluationError {
    extension_err(
        format!(
            "overflows when adding an offset: {}+({})",
            RestrictedExpr::from(datetime),
            duration
        ),
        &constants::OFFSET_METHOD_NAME,
        None,
    )
}

#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(r, crate::verification::model::ext::call(&crate::verification::model::ext::ExtFun::DurationSince, &crate::verification::ext_abs::args2(*lhs, *rhs)))
))]
fn duration_since(lhs: &Value, rhs: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let lhs = as_datetime(lhs)?;
    let rhs = as_datetime(rhs)?;
    let ret = match lhs.duration_since(rhs) {
        Some(ret) => ret,
        None => return Err(duration_since_error(lhs, rhs)),
    };
    Ok(duration_output(ret))
}

#[cfg_attr(feature = "verus", verus_verify(external_body))]
fn duration_since_error(lhs: DateTime, rhs: DateTime) -> evaluator::EvaluationError {
    extension_err(
        format!(
            "overflows when computing the duration between {} and {}",
            RestrictedExpr::from(lhs),
            RestrictedExpr::from(rhs)
        ),
        &constants::DURATION_SINCE_NAME,
        None,
    )
}

#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(r, crate::verification::model::ext::call(&crate::verification::model::ext::ExtFun::ToDate, &crate::verification::ext_abs::args1(*value)))
))]
fn to_date(value: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let d = as_datetime(value)?;
    let ret = match d.to_date() {
        Some(ret) => ret,
        None => return Err(to_date_error(d)),
    };
    Ok(datetime_output(ret))
}

#[cfg_attr(feature = "verus", verus_verify(external_body))]
fn to_date_error(d: DateTime) -> evaluator::EvaluationError {
    extension_err(
        format!(
            "overflows when computing the date of {}",
            RestrictedExpr::from(d),
        ),
        &constants::TO_DATE_NAME,
        None,
    )
}

#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(r, crate::verification::model::ext::call(&crate::verification::model::ext::ExtFun::ToTime, &crate::verification::ext_abs::args1(*value)))
))]
fn to_time(value: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let d = as_datetime(value)?;
    let ret = d.to_time();
    Ok(duration_output(ret))
}

impl ExtensionValue for DateTime {
    fn typename(&self) -> crate::ast::Name {
        constants::DATETIME_CONSTRUCTOR_NAME.to_owned()
    }
    fn supports_operator_overloading(&self) -> bool {
        true
    }

    /// The canonical representation of a Cedar [`DateTime`] is the one returned by
    /// [`DateTime::as_ext_func_call`], i.e.
    /// `offset(datetime(<UNIX_EPOCH_STR>), duration("<Offset in MS>ms"))`
    fn canonical_repr(&self) -> (crate::ast::Name, Vec<crate::ast::RestrictedExpr>) {
        (*self).as_ext_func_call()
    }
}

#[cfg_attr(feature = "verus", verus_verify)]
impl DateTime {
    const DAY_IN_MILLISECONDS: i64 = 1000 * 3600 * 24;
    const UNIX_EPOCH_STR: &'static str = "1970-01-01";

    #[cfg_attr(feature = "verus", verus_spec(r =>
        ensures r matches Some(d) ==> crate::verification::model::ext::dt_offset(self.epoch, duration.ms) == Some(d.epoch),
            r is None ==> crate::verification::model::ext::dt_offset(self.epoch, duration.ms) is None
    ))]
    fn offset(self, duration: Duration) -> Option<Self> {
        self.epoch.checked_add(duration.ms).map(
            #[cfg_attr(feature = "verus", verus_spec(r: Self => ensures r.epoch == epoch))]
            |epoch| Self { epoch },
        )
    }

    #[cfg_attr(feature = "verus", verus_spec(r =>
        ensures r matches Some(d) ==> crate::verification::model::ext::dt_duration_since(self.epoch, other.epoch) == Some(d.ms),
            r is None ==> crate::verification::model::ext::dt_duration_since(self.epoch, other.epoch) is None
    ))]
    fn duration_since(self, other: DateTime) -> Option<Duration> {
        self.epoch.checked_sub(other.epoch).map(
            #[cfg_attr(feature = "verus", verus_spec(r: Duration => ensures r.ms == ms))]
            |ms| Duration { ms },
        )
    }

    #[cfg_attr(feature = "verus", verus_spec(r =>
        ensures r matches Some(d) ==> crate::verification::model::ext::dt_to_date(self.epoch) == Some(d.epoch),
            r is None ==> crate::verification::model::ext::dt_to_date(self.epoch) is None
    ))]
    fn to_date(self) -> Option<Self> {
        // `rem_euclid` has the desired property that
        // \forall a b, 0 <= a.rem_euclid(b) < b
        Some(Self {
            epoch: self
                .epoch
                .checked_sub(self.epoch.checked_rem_euclid(Self::DAY_IN_MILLISECONDS)?)?,
        })
    }

    #[cfg_attr(feature = "verus", verus_spec(r =>
        ensures r.ms == crate::verification::model::ext::dt_to_time(self.epoch)
    ))]
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

    #[cfg_attr(feature = "verus", verus_verify(external))]
    fn as_ext_func_call(self) -> (Name, Vec<RestrictedExpr>) {
        (
            constants::OFFSET_METHOD_NAME.clone(),
            vec![
                RestrictedExpr::call_extension_fn(
                    constants::DATETIME_CONSTRUCTOR_NAME.clone(),
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
        // Representation is derived from `canonical_repr` on demand.
        Self::new_lazy(Arc::new(value))
    }
}

impl From<NaiveDateTime> for DateTime {
    fn from(value: NaiveDateTime) -> Self {
        Self::of_naive(value)
    }
}

#[cfg_attr(feature = "verus", verus_verify)]
impl DateTime {
    /// `DateTime::from` (trusted: defines `ndt_ms` in `ext_trusted`)
    #[cfg_attr(feature = "verus", verus_verify(external_body))]
    #[cfg_attr(feature = "verus", verus_spec(r =>
        ensures r.epoch as int == crate::verification::ext_trusted::ndt_ms(value)
    ))]
    fn of_naive(value: NaiveDateTime) -> Self {
        let delta = chrono::DateTime::from_naive_utc_and_offset(value, chrono::Utc)
            - chrono::DateTime::UNIX_EPOCH;
        Self {
            epoch: delta.num_milliseconds(),
        }
    }
}

// The `duration` type
#[cfg_attr(feature = "verus", verus_verify(external_derive))]
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
        constants::DURATION_CONSTRUCTOR_NAME.to_owned()
    }
    fn supports_operator_overloading(&self) -> bool {
        true
    }
    /// The canonical representation of a Cedar [`Duration`] is the one returned by
    /// duration("<MILLISECONDS>ms")
    fn canonical_repr(&self) -> (crate::ast::Name, Vec<RestrictedExpr>) {
        (*self).as_ext_func_call()
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
        // Representation is derived from `canonical_repr` on demand.
        Self::new_lazy(Arc::new(value))
    }
}

/// Cedar function that constructs a `duration` Cedar type from a
/// Cedar string
#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(r, crate::verification::model::ext::call(&crate::verification::model::ext::ExtFun::Duration, &crate::verification::ext_abs::args1(*arg)))
))]
fn duration_from_str(arg: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let s = arg.get_as_string()?;
    let ext_value = match parse_duration(s.as_str()) {
        Ok(d) => d,
        Err(err) => return Err(duration_parse_error(&err)),
    };
    Ok(duration_value(ext_value, arg))
}

/// The evaluation error for a failed duration parse
#[cfg_attr(feature = "verus", verus_verify(external_body))]
fn duration_parse_error(err: &DurationParseError) -> evaluator::EvaluationError {
    extension_err(
        err.to_string(),
        &constants::DURATION_CONSTRUCTOR_NAME,
        Some(
            err.help()
                .map(|v| v.to_string())
                .unwrap_or_else(|| VALID_DURATION_HELP.to_string()),
        ),
    )
}

#[cfg_attr(feature = "verus", verus_verify)]
impl Duration {
    #[cfg_attr(feature = "verus", verus_spec(r => ensures r == self.ms))]
    fn to_milliseconds(self) -> i64 {
        self.ms
    }

    #[cfg_attr(feature = "verus", verus_spec(r => ensures r == crate::verification::model::ext::tdiv(self.ms, 1000)))]
    fn to_seconds(self) -> i64 {
        self.to_milliseconds() / 1000
    }

    #[cfg_attr(feature = "verus", verus_spec(r => ensures r == crate::verification::model::ext::tdiv(crate::verification::model::ext::tdiv(self.ms, 1000), 60)))]
    fn to_minutes(self) -> i64 {
        self.to_seconds() / 60
    }

    #[cfg_attr(feature = "verus", verus_spec(r => ensures r == crate::verification::model::ext::tdiv(crate::verification::model::ext::tdiv(crate::verification::model::ext::tdiv(self.ms, 1000), 60), 60)))]
    fn to_hours(self) -> i64 {
        self.to_minutes() / 60
    }

    #[cfg_attr(feature = "verus", verus_spec(r => ensures r == crate::verification::model::ext::tdiv(crate::verification::model::ext::tdiv(crate::verification::model::ext::tdiv(crate::verification::model::ext::tdiv(self.ms, 1000), 60), 60), 24)))]
    fn to_days(self) -> i64 {
        self.to_hours() / 24
    }

    #[cfg_attr(feature = "verus", verus_verify(external))]
    fn as_ext_func_call(self) -> (Name, Vec<RestrictedExpr>) {
        (
            constants::DURATION_CONSTRUCTOR_NAME.clone(),
            vec![Value::from(self.to_string()).into()],
        )
    }
}

/// Cedar function `to_milliseconds` on durations
#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(r, crate::verification::model::ext::call(&crate::verification::model::ext::ExtFun::ToMilliseconds, &crate::verification::ext_abs::args1(*value)))
))]
fn duration_to_milliseconds(value: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let d = as_duration(value)?;
    Ok(super::long_output(d.to_milliseconds()))
}

/// Cedar function `to_seconds` on durations
#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(r, crate::verification::model::ext::call(&crate::verification::model::ext::ExtFun::ToSeconds, &crate::verification::ext_abs::args1(*value)))
))]
fn duration_to_seconds(value: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let d = as_duration(value)?;
    Ok(super::long_output(d.to_seconds()))
}

/// Cedar function `to_minutes` on durations
#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(r, crate::verification::model::ext::call(&crate::verification::model::ext::ExtFun::ToMinutes, &crate::verification::ext_abs::args1(*value)))
))]
fn duration_to_minutes(value: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let d = as_duration(value)?;
    Ok(super::long_output(d.to_minutes()))
}

/// Cedar function `to_hours` on durations
#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(r, crate::verification::model::ext::call(&crate::verification::model::ext::ExtFun::ToHours, &crate::verification::ext_abs::args1(*value)))
))]
fn duration_to_hours(value: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let d = as_duration(value)?;
    Ok(super::long_output(d.to_hours()))
}

/// Cedar function `to_days` on durations
#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures crate::verification::ext_abs::ext_out_rel(r, crate::verification::model::ext::call(&crate::verification::model::ext::ExtFun::ToDays, &crate::verification::ext_abs::args1(*value)))
))]
fn duration_to_days(value: &Value) -> evaluator::Result<ExtensionOutputValue> {
    let d = as_duration(value)?;
    Ok(super::long_output(d.to_days()))
}

#[cfg_attr(feature = "verus", verus_verify(external_derive))]
#[derive(Debug, Clone, Error, Diagnostic)]
enum DurationParseError {
    #[error("invalid duration pattern")]
    #[help("A valid duration string is a concatenated sequence of quantity-unit pairs with an optional `-` at the beginning")]
    InvalidPattern,
    #[error("Duration overflows internal representation")]
    #[help("A duration in milliseconds must be representable by a signed 64 bit integer")]
    Overflow,
}

/// The digits of each unit of `s`, as matched by `DURATION_PATTERN`
#[cfg_attr(feature = "verus", verus_verify(external_body))]
#[cfg_attr(feature = "verus", verus_spec(r => ensures crate::verification::ext_trusted::duration_regex_spec(s, r)))]
fn duration_parts(s: &str) -> Option<[Option<&str>; 5]> {
    let captures = constants::DURATION_PATTERN.captures(s)?;
    Some([2, 4, 6, 8, 10].map(|idx| captures.get(idx).map(|m| m.as_str())))
}

/// The quantity of a unit (0 if absent)
#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures
        match r {
            Ok(n) => crate::verification::model::ext::dur_quantity(&crate::verification::ext_trusted::opt_str_list(m)) == Some(n),
            Err(_) => crate::verification::model::ext::dur_quantity(&crate::verification::ext_trusted::opt_str_list(m)) is None,
        }
))]
fn duration_number(m: Option<&str>) -> Result<u64, DurationParseError> {
    match m {
        None => Ok(0),
        Some(m) => match <u64 as std::str::FromStr>::from_str(m) {
            Ok(n) => Ok(n),
            Err(_) => Err(DurationParseError::Overflow),
        },
    }
}

/// `x ± y * mul`, checked
#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures
        match r {
            Ok(n) => crate::verification::model::ext::dur_step(x, y, mul, neg) == Some(n),
            Err(_) => crate::verification::model::ext::dur_step(x, y, mul, neg) is None,
        }
))]
fn duration_step(x: i64, y: u64, mul: i64, neg: bool) -> Result<i64, DurationParseError> {
    let y: i64 = match y.try_into() {
        Ok(y) => y,
        Err(_) => return Err(DurationParseError::Overflow),
    };
    let p = match i64::checked_mul(y, mul) {
        Some(p) => p,
        None => return Err(DurationParseError::Overflow),
    };
    let r = if neg {
        i64::checked_sub(x, p)
    } else {
        i64::checked_add(x, p)
    };
    match r {
        Some(r) => Ok(r),
        None => Err(DurationParseError::Overflow),
    }
}

#[cfg_attr(feature = "verus", verus_verify(spinoff_prover))]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures
        match r {
            Ok(d) => crate::verification::model::ext::parse_duration(&crate::verification::abs::seq_to_list(s@)) == Some(d.ms),
            Err(_) => crate::verification::model::ext::parse_duration(&crate::verification::abs::seq_to_list(s@)) is None,
        }
))]
fn parse_duration(s: &str) -> Result<Duration, DurationParseError> {
    proof! {
        broadcast use vstd::string::group_string_axioms;
        reveal_strlit("-");
        assert("-"@ =~= seq!['-']);
        crate::verification::ext_lemmas::lemma_is_empty(s@);
        crate::verification::ext_lemmas::lemma_is_char(s@, '-');
        crate::verification::ext_lemmas::lemma_starts_with(s@, '-');
    }
    if s.is_empty() || super::str_eq(s, "-") {
        return Err(DurationParseError::InvalidPattern);
    }
    let parts = match duration_parts(s) {
        Some(parts) => parts,
        None => return Err(DurationParseError::InvalidPattern),
    };
    let d: u64 = duration_number(parts[0])?;
    let h: u64 = duration_number(parts[1])?;
    let m: u64 = duration_number(parts[2])?;
    let sec: u64 = duration_number(parts[3])?;
    let ms: u64 = duration_number(parts[4])?;
    let neg = super::starts_with_char(s, '-');
    let mut ms = if neg {
        match i64::try_from(-i128::from(ms)) {
            Ok(ms) => ms,
            Err(_) => return Err(DurationParseError::Overflow),
        }
    } else {
        match i64::try_from(ms) {
            Ok(ms) => ms,
            Err(_) => return Err(DurationParseError::Overflow),
        }
    };
    ms = duration_step(ms, sec, 1000, neg)?;
    ms = duration_step(ms, m, 1000 * 60, neg)?;
    ms = duration_step(ms, h, 1000 * 60 * 60, neg)?;
    ms = duration_step(ms, d, 1000 * 60 * 60 * 24, neg)?;
    Ok(Duration { ms })
}

#[cfg_attr(feature = "verus", verus_verify(external_derive))]
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

#[cfg_attr(feature = "verus", verus_verify(external_derive))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct UTCOffset {
    positive: bool,
    hh: u32,
    mm: u32,
}

#[cfg_attr(feature = "verus", verus_verify)]
impl UTCOffset {
    const MAX_HH: u32 = 24;
    const MAX_MM: u32 = 60;

    #[cfg_attr(feature = "verus", verus_spec(r =>
        requires self.hh <= 9999, self.mm <= 9999,
        ensures r == if self.positive { (self.hh * 3600 + self.mm * 60) as int } else { -((self.hh * 3600 + self.mm * 60) as int) }
    ))]
    fn to_seconds(&self) -> i64 {
        let offset_in_seconds_unsigned = i64::from(self.hh * 3600 + self.mm * 60);
        if self.positive {
            offset_in_seconds_unsigned
        } else {
            -offset_in_seconds_unsigned
        }
    }

    #[cfg_attr(feature = "verus", verus_spec(r => ensures r == (self.hh < 24 && self.mm < 60)))]
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

/// The date matched by `DATE_PATTERN` at the start of `s` (the whole match,
/// the year, month and day, and the rest of `s`)
#[cfg_attr(feature = "verus", verus_verify(external_body))]
#[cfg_attr(feature = "verus", verus_spec(r => ensures crate::verification::ext_trusted::date_regex_spec(s, r)))]
fn date_parts(s: &str) -> Option<(&str, [&str; 3], &str)> {
    let (date_str, parts) = constants::DATE_PATTERN.captures(s)?.extract();
    #[expect(clippy::string_slice, reason = "`date_str` is a prefix of `s`")]
    Some((date_str, parts, &s[date_str.len()..]))
}

/// The time matched by `HMS_PATTERN` at the start of `s` (the whole match, the
/// hours, minutes and seconds, and the rest of `s`)
#[cfg_attr(feature = "verus", verus_verify(external_body))]
#[cfg_attr(feature = "verus", verus_spec(r => ensures crate::verification::ext_trusted::hms_regex_spec(s, r)))]
fn hms_parts(s: &str) -> Option<(&str, [&str; 3], &str)> {
    let (hms_str, parts) = constants::HMS_PATTERN.captures(s)?.extract();
    #[expect(clippy::string_slice, reason = "`hms_str` is a prefix of `s`")]
    Some((hms_str, parts, &s[hms_str.len()..]))
}

/// The milliseconds and the offset matched by `MS_AND_OFFSET_PATTERN` (the
/// offset is whether it is positive, its hours and its minutes)
#[cfg_attr(feature = "verus", verus_verify(external_body))]
#[cfg_attr(feature = "verus", verus_spec(r => ensures crate::verification::ext_trusted::ms_offset_regex_spec(s, r)))]
#[expect(clippy::type_complexity, reason = "the captures of the regex")]
fn ms_offset_parts(s: &str) -> Option<(Option<&str>, Option<(bool, &str, &str)>)> {
    let captures = constants::MS_AND_OFFSET_PATTERN.captures(s)?;
    let ms = captures.get(2).map(|m| m.as_str());
    let offset = if captures.get(4).is_some() {
        // captures 5, 6 and 7 are present when 4 is
        Some((
            captures.get(5)?.as_str() == "+",
            captures.get(6)?.as_str(),
            captures.get(7)?.as_str(),
        ))
    } else {
        None
    };
    Some((ms, offset))
}

/// The value of a string of 1 to 4 ASCII digits
#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    requires crate::verification::ext_trusted::small_digits(n@),
    ensures r as i64 == crate::verification::model::ext::small_nat(&crate::verification::abs::seq_to_list(n@))
))]
fn parse_small_u32(n: &str) -> u32 {
    #[expect(clippy::unwrap_used, reason = "at most 4 digits")]
    <u32 as std::str::FromStr>::from_str(n).unwrap()
}

/// The value of a string of 4 ASCII digits
#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    requires crate::verification::ext_trusted::small_digits(n@),
    ensures r as i64 == crate::verification::model::ext::small_nat(&crate::verification::abs::seq_to_list(n@))
))]
fn parse_small_i32(n: &str) -> i32 {
    #[expect(clippy::unwrap_used, reason = "at most 4 digits")]
    <i32 as std::str::FromStr>::from_str(n).unwrap()
}

/// The date `year-month-day`, if valid
#[cfg_attr(feature = "verus", verus_verify)]
#[cfg_attr(feature = "verus", verus_spec(r =>
    requires crate::verification::ext_trusted::small_digits(year@), crate::verification::ext_trusted::small_digits(month@), crate::verification::ext_trusted::small_digits(day@),
    ensures
        ({
            let y = crate::verification::model::ext::small_nat(&crate::verification::abs::seq_to_list(year@));
            let m = crate::verification::model::ext::small_nat(&crate::verification::abs::seq_to_list(month@));
            let d = crate::verification::model::ext::small_nat(&crate::verification::abs::seq_to_list(day@));
            match r {
                Ok(date) => crate::verification::model::ext::valid_date(y, m, d)
                    && crate::verification::ext_trusted::nd_days(date) == crate::verification::model::ext::days_from_civil(y, m, d) as int,
                Err(_) => !crate::verification::model::ext::valid_date(y, m, d),
            }
        })
))]
fn make_date(date_str: &str, year: &str, month: &str, day: &str) -> Result<NaiveDate, DateTimeParseError> {
    match NaiveDate::from_ymd_opt(parse_small_i32(year), parse_small_u32(month), parse_small_u32(day)) {
        Some(date) => Ok(date),
        None => Err(invalid_date(date_str)),
    }
}

#[cfg_attr(feature = "verus", verus_verify(external_body))]
fn invalid_date(date_str: &str) -> DateTimeParseError {
    DateTimeParseError::InvalidDate(date_str.into())
}

#[cfg_attr(feature = "verus", verus_verify(external_body))]
fn invalid_hms(hms_str: &str) -> DateTimeParseError {
    #[expect(clippy::string_slice, reason = "match for HMS_PATTERN must start with ASCII character `T`. Slicing `[1..]` skips this character.")]
    DateTimeParseError::InvalidHMS(hms_str[1..].into())
}

#[cfg_attr(feature = "verus", verus_verify(spinoff_prover, rlimit(40)))]
#[cfg_attr(feature = "verus", verus_spec(r =>
    ensures
        match r {
            Ok(ndt) => crate::verification::model::ext::parse_datetime(&crate::verification::abs::seq_to_list(s@)) == Some(ndt_ms_i64(ndt)),
            Err(_) => crate::verification::model::ext::parse_datetime(&crate::verification::abs::seq_to_list(s@)) is None,
        }
))]
fn parse_datetime(s: &str) -> Result<NaiveDateTime, DateTimeParseError> {
    // Get date first
    let (date_str, [year, month, day], rest) = match date_parts(s) {
        Some(parts) => parts,
        None => return Err(DateTimeParseError::InvalidDatePattern),
    };
    proof! {
        crate::verification::ext_lemmas::lemma_match_date(crate::verification::abs::seq_to_list(s@));
        let (ys, mos, ds, _) = crate::verification::model::ext::match_date(&crate::verification::abs::seq_to_list(s@)).unwrap();
        crate::verification::ext_lemmas::lemma_small_digits(ys, 4, year@);
        crate::verification::ext_lemmas::lemma_small_digits(mos, 2, month@);
        crate::verification::ext_lemmas::lemma_small_digits(ds, 2, day@);
        crate::verification::ext_lemmas::lemma_is_empty(rest@);
    }

    // A complete match; simply return
    if rest.is_empty() {
        let date = make_date(date_str, year, month, day)?;
        #[expect(
            clippy::unwrap_used,
            reason = "`0`s should be all valid given the limit on the number of digits."
        )]
        return Ok(NaiveDateTime::new(
            date,
            NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
        ));
    }

    // Get hour, minute, and second
    let rest_date = rest;
    let (hms_str, [h, m, sec], rest) = match hms_parts(rest_date) {
        Some(parts) => parts,
        None => return Err(DateTimeParseError::InvalidHMSPattern),
    };
    proof! {
        crate::verification::ext_lemmas::lemma_match_hms(crate::verification::abs::seq_to_list(rest_date@));
        let (hs, mis, ss, _) = crate::verification::model::ext::match_hms(&crate::verification::abs::seq_to_list(rest_date@)).unwrap();
        crate::verification::ext_lemmas::lemma_small_digits(hs, 2, h@);
        crate::verification::ext_lemmas::lemma_small_digits(mis, 2, m@);
        crate::verification::ext_lemmas::lemma_small_digits(ss, 2, sec@);
    }
    let (h, m, sec): (u32, u32, u32) = (parse_small_u32(h), parse_small_u32(m), parse_small_u32(sec));

    // Get millisecond and offset
    let (ms, offset) = match ms_offset_parts(rest) {
        Some(parts) => parts,
        None => return Err(DateTimeParseError::InvalidMSOffsetPattern),
    };
    proof! {
        crate::verification::ext_lemmas::lemma_match_ms_offset(crate::verification::abs::seq_to_list(rest@));
        let (mso, offo) = crate::verification::model::ext::match_ms_offset(&crate::verification::abs::seq_to_list(rest@)).unwrap();
        if let Some(msd) = mso {
            crate::verification::ext_lemmas::lemma_small_digits(msd, 3, ms.unwrap()@);
            crate::verification::ext_lemmas::lemma_small_nat_3(msd);
        }
        if let Some((_, hh, mm)) = offo {
            crate::verification::ext_lemmas::lemma_small_digits(hh, 2, offset.unwrap().1@);
            crate::verification::ext_lemmas::lemma_small_digits(mm, 2, offset.unwrap().2@);
        }
    }
    let ms: u32 = match ms {
        Some(ms) => parse_small_u32(ms),
        None => 0,
    };

    // Date validity is checked after the syntax, as `date_parts` delays it
    let date = make_date(date_str, year, month, day)?;
    let time = match NaiveTime::from_hms_milli_opt(h, m, sec, ms) {
        Some(time) => time,
        None => return Err(invalid_hms(hms_str)),
    };
    let offset: Result<TimeDelta, DateTimeParseError> = match offset {
        Some((positive, offset_hour, offset_min)) => {
            let (offset_hour, offset_min): (u32, u32) =
                (parse_small_u32(offset_hour), parse_small_u32(offset_min));
            let offset = UTCOffset {
                positive,
                hh: offset_hour,
                mm: offset_min,
            };
            if offset.is_valid() {
                let offset_in_secs = offset.to_seconds();
                #[expect(
                    clippy::unwrap_used,
                    reason = "should be valid because the limit on the values of offsets."
                )]
                Ok(TimeDelta::new(-offset_in_secs, 0).unwrap())
            } else {
                Err(DateTimeParseError::InvalidOffset((offset_hour, offset_min)))
            }
        }
        None => Ok(TimeDelta::default()),
    };
    Ok(add_delta(NaiveDateTime::new(date, time), offset?))
}

/// `a + d`
#[cfg_attr(feature = "verus", verus_verify(external_body))]
#[cfg_attr(feature = "verus", verus_spec(r =>
    requires
        -1_000_000_000_000_000_000 < crate::verification::ext_trusted::ndt_ms(a) < 1_000_000_000_000_000_000,
        -86_400_000 < crate::verification::ext_trusted::td_ms(d) < 86_400_000,
    ensures
        crate::verification::ext_trusted::ndt_ms(r) == crate::verification::ext_trusted::ndt_ms(a)
            + crate::verification::ext_trusted::td_ms(d),
))]
fn add_delta(a: NaiveDateTime, d: TimeDelta) -> NaiveDateTime {
    a + d
}

#[cfg(feature = "verus")]
verus! {
/// `ndt_ms` as an `i64`
pub(crate) open spec fn ndt_ms_i64(ndt: NaiveDateTime) -> i64 {
    crate::verification::ext_trusted::ndt_ms(ndt) as i64
}
}

/// Construct the extension
pub fn extension() -> Extension {
    let datetime_type = SchemaType::Extension {
        name: constants::DATETIME_CONSTRUCTOR_NAME.to_owned(),
    };
    let duration_type = SchemaType::Extension {
        name: constants::DURATION_CONSTRUCTOR_NAME.to_owned(),
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
                (datetime_type.clone(), datetime_type.clone()),
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
                Box::new(duration_to_milliseconds),
                SchemaType::Long,
                duration_type.clone(),
            ),
            ExtensionFunction::unary(
                constants::TO_SECONDS_NAME.clone(),
                CallStyle::MethodStyle,
                Box::new(duration_to_seconds),
                SchemaType::Long,
                duration_type.clone(),
            ),
            ExtensionFunction::unary(
                constants::TO_MINUTES_NAME.clone(),
                CallStyle::MethodStyle,
                Box::new(duration_to_minutes),
                SchemaType::Long,
                duration_type.clone(),
            ),
            ExtensionFunction::unary(
                constants::TO_HOURS_NAME.clone(),
                CallStyle::MethodStyle,
                Box::new(duration_to_hours),
                SchemaType::Long,
                duration_type.clone(),
            ),
            ExtensionFunction::unary(
                constants::TO_DAYS_NAME.clone(),
                CallStyle::MethodStyle,
                Box::new(duration_to_days),
                SchemaType::Long,
                duration_type,
            ),
        ],
        [
            constants::DATETIME_CONSTRUCTOR_NAME.clone(),
            constants::DURATION_CONSTRUCTOR_NAME.clone(),
        ],
    )
}

#[cfg(test)]
#[expect(clippy::cognitive_complexity, reason = "testing code")]
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
                assert_eq!(err.advice, Some("valid datetime strings start with `YYYY-MM-DD` and may optionally include `THH:MM:SS` plus `Z`, `.SSSZ`, or an offset like `+0700`".to_owned()));
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
                assert_eq!(err.advice, Some("valid duration strings are concatenated quantity-unit pairs with an optional leading `-`, for example `1d2h3m4s50ms`".to_owned()));
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
