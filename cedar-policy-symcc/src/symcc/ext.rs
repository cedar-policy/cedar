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

//! Extension values in SymCC.

use cedar_policy::EvaluationError;
use cedar_policy_core::ast::{Extension, Name, PartialValue, RestrictedExpr, Value, ValueKind};
use miette::Diagnostic;
use thiserror::Error;

use super::extension_types::datetime::{Datetime, Duration};
use super::extension_types::decimal::Decimal;

type IPAddr = super::extension_types::ipaddr::IPNet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ext {
    Decimal { d: Decimal },
    Ipaddr { ip: IPAddr },
    Datetime { dt: Datetime },
    Duration { d: Duration },
}

/// Errors in [`Ext`] conversions.
#[derive(Debug, Diagnostic, Error)]
pub enum ExtConvertError {
    /// Failed to convert from the given [`Value`].
    #[error("fail to convert value to an extension term: {0}")]
    FromValue(Value),
    /// Failed to convert from the given [`RestrictedExpr`].
    #[error("fail to convert expression to an extension term: {0}")]
    FromRestrictedExpr(RestrictedExpr),
    /// Evaluation error when converting to a value.
    #[error("evaluation error when converting to value")]
    EvaluationError(#[from] EvaluationError),
    /// Extension function not found.
    #[error("extension function `{0}` not found")]
    ExtensionFunctionNotFound(String),
    /// Extension value evaluates to a partial value.
    #[error("extension function returned a partial value")]
    UnsupportedPartialValue,
    /// Failed to parse extension function name.
    #[error("failed to parse extension function name")]
    ExtensionFunctionParseError,
}

impl Ext {
    #[allow(
        clippy::needless_pass_by_value,
        reason = "Pass by value expected by consumer"
    )]
    pub fn parse_decimal(str: String) -> Option<Ext> {
        super::extension_types::decimal::parse(&str).map(|d| Ext::Decimal { d })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "Pass by value expected by consumer"
    )]
    pub fn parse_datetime(str: String) -> Option<Ext> {
        super::extension_types::datetime::Datetime::parse(&str).map(|dt| Ext::Datetime { dt })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "Pass by value expected by consumer"
    )]
    pub fn parse_duration(str: String) -> Option<Ext> {
        super::extension_types::datetime::Duration::parse(&str).map(|d| Ext::Duration { d })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "Pass by value expected by consumer"
    )]
    pub fn parse_ip(str: String) -> Option<Ext> {
        super::extension_types::ipaddr::IPNet::parse(&str).map(|ip| Ext::Ipaddr { ip })
    }
}

impl Ext {
    /// Helper function to convert a [`RestrictedExpr`] to an [`Ext`].
    fn from_ext_value(rexp: &RestrictedExpr) -> Option<Self> {
        let (name, args) = rexp.as_extn_fn_call()?;
        let args = args.collect::<Vec<_>>();

        // Recover the string representation of supported extension values
        // and then convert them to corresponding `Term`s.
        match (name.as_ref().to_string().as_str(), args.as_slice()) {
            ("decimal", &[arg]) => Self::parse_decimal(arg.as_string()?.to_string()),
            ("duration", &[arg]) => Self::parse_duration(arg.as_string()?.to_string()),
            ("datetime", &[arg]) => Self::parse_datetime(arg.as_string()?.to_string()),
            // A `datetime` value is sometimes represented as `datetime(<epoch>).offset(<...>)`
            ("offset", &[arg1, arg2]) => {
                let (arg1_name, arg1_args) = arg1.as_extn_fn_call()?;
                let (arg2_name, arg2_args) = arg2.as_extn_fn_call()?;
                let arg1_args = arg1_args.collect::<Vec<_>>();
                let arg2_args = arg2_args.collect::<Vec<_>>();
                if arg1_name.as_ref().to_string() != "datetime"
                    || arg1_args.len() != 1
                    || arg2_name.as_ref().to_string() != "duration"
                    || arg2_args.len() != 1
                {
                    return None;
                }

                #[allow(
                    clippy::indexing_slicing,
                    reason = "arg1_args.len() == 1 thus indexing by 0 should not panic"
                )]
                let dt = super::extension_types::datetime::Datetime::parse(
                    arg1_args[0].as_string()?.as_str(),
                )?;
                #[allow(
                    clippy::indexing_slicing,
                    reason = "arg2_args.len() == 1 thus indexing by 0 should not panic"
                )]
                let d = super::extension_types::datetime::Duration::parse(
                    arg2_args[0].as_string()?.as_str(),
                )?;
                Some(Ext::Datetime { dt: dt.offset(&d)? }.into())
            }
            ("ip", &[arg]) => Self::parse_ip(arg.as_string()?.to_string()),
            _ => None,
        }
    }
}

/// Rust SymCC and Rust Cedar use different representations
/// of extension values (whereas the Lean model uses the same),
/// so we need these utility functions to convert between them.
impl TryFrom<&RestrictedExpr> for Ext {
    type Error = ExtConvertError;

    fn try_from(rexp: &RestrictedExpr) -> Result<Self, Self::Error> {
        Self::from_ext_value(rexp).ok_or_else(|| ExtConvertError::FromRestrictedExpr(rexp.clone()))
    }
}

impl TryFrom<&Value> for Ext {
    type Error = ExtConvertError;

    fn try_from(v: &Value) -> Result<Self, Self::Error> {
        let ValueKind::ExtensionValue(ext) = v.value_kind() else {
            return Err(ExtConvertError::FromValue(v.clone()));
        };
        let rexp = RestrictedExpr::from(ext.as_ref().clone());
        Self::from_ext_value(&rexp).ok_or_else(|| ExtConvertError::FromValue(v.clone()))
    }
}

/// A utility function to call an extension function
fn call_extension_func(
    ext: &Extension,
    name: &str,
    args: &[Value],
) -> Result<Value, ExtConvertError> {
    let name =
        Name::parse_unqualified_name(name).or(Err(ExtConvertError::ExtensionFunctionParseError))?;
    match ext
        .get_func(&name)
        .ok_or_else(|| ExtConvertError::ExtensionFunctionNotFound(name.to_string()))?
        .call(args)?
    {
        PartialValue::Value(v) => Ok(v),
        _ => Err(ExtConvertError::UnsupportedPartialValue),
    }
}

impl TryFrom<&Ext> for Value {
    type Error = ExtConvertError;

    fn try_from(ext: &Ext) -> Result<Self, Self::Error> {
        use cedar_policy_core::extensions::{datetime, decimal, ipaddr};
        match ext {
            Ext::Decimal { d } => {
                call_extension_func(&decimal::extension(), "decimal", &[format!("{}", d).into()])
            }
            Ext::Datetime { dt } => {
                // First construct `datetime("1970-01-01")`
                let epoch = call_extension_func(
                    &datetime::extension(),
                    "datetime",
                    &["1970-01-01".into()],
                )?;
                // Then construct the actual datetime as an offset duration
                let offset: i64 = dt.into();
                let offset = call_extension_func(
                    &datetime::extension(),
                    "duration",
                    &[format!("{}ms", offset).into()],
                )?;
                // Finally call the offset function to construct the right datetime value
                call_extension_func(&datetime::extension(), "offset", &[epoch, offset])
            }
            Ext::Duration { d } => {
                let offset: i64 = d.into();
                call_extension_func(
                    &datetime::extension(),
                    "duration",
                    &[format!("{}ms", offset).into()],
                )
            }
            Ext::Ipaddr { ip } => {
                call_extension_func(&ipaddr::extension(), "ip", &[format!("{}", ip).into()])
            }
        }
    }
}
