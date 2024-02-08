/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

//! This module contains the Cedar 'decimal' extension.

use crate::ast::{
    CallStyle, Extension, ExtensionFunction, ExtensionOutputValue, ExtensionValue,
    ExtensionValueWithArgs, Literal, Name, Type, Value, ValueKind,
};
use crate::entities::SchemaType;
use crate::evaluator;
use miette::Diagnostic;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;

/// Number of digits supported after the decimal
const NUM_DIGITS: u32 = 4;

/// Decimal value, represented internally as an integer.
/// `Decimal{value}` represents `value / 10^NUM_DIGITS`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
struct Decimal {
    value: i64,
}

// PANIC SAFETY The `Name`s and `Regex` here are valid
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod constants {
    use super::{Name, EXTENSION_NAME};
    use regex::Regex;

    // PANIC SAFETY all of the names here are valid names
    lazy_static::lazy_static! {
        pub static ref DECIMAL_FROM_STR_NAME : Name = Name::parse_unqualified_name(EXTENSION_NAME).expect("should be a valid identifier");
        pub static ref LESS_THAN : Name = Name::parse_unqualified_name("lessThan").expect("should be a valid identifier");
        pub static ref LESS_THAN_OR_EQUAL : Name = Name::parse_unqualified_name("lessThanOrEqual").expect("should be a valid identifier");
        pub static ref GREATER_THAN : Name = Name::parse_unqualified_name("greaterThan").expect("should be a valid identifier");
        pub static ref GREATER_THAN_OR_EQUAL : Name = Name::parse_unqualified_name("greaterThanOrEqual").expect("should be a valid identifier");
    }

    // Global regex, initialized at first use
    // PANIC SAFETY This is a valid `Regex`
    lazy_static::lazy_static! {
        pub static ref DECIMAL_REGEX : Regex = Regex::new(r"^(-?\d+)\.(\d+)$").unwrap();
    }
}

/// Help message to display when a String was provided where a decimal value was expected.
/// This error is likely due to confusion between "1.23" and decimal("1.23").
const ADVICE_MSG: &str = "maybe you forgot to apply the `decimal` constructor?";

/// Potential errors when working with decimal values. Note that these are
/// converted to evaluator::Err::ExtensionErr (which takes a string argument)
/// before being reported to users.
#[derive(Debug, Diagnostic, Error)]
enum Error {
    /// Error parsing the input string as a decimal value
    #[error("`{0}` is not a well-formed decimal value")]
    FailedParse(String),

    /// Too many digits after the decimal point
    #[error("too many digits after the decimal in `{0}`")]
    #[diagnostic(help("at most {NUM_DIGITS} digits are supported"))]
    TooManyDigits(String),

    /// Overflow occurred when converting to a decimal value
    #[error("overflow when converting to decimal")]
    Overflow,
}

/// Computes x * 10 ^ y while checking for overflows
fn checked_mul_pow(x: i64, y: u32) -> Result<i64, Error> {
    if let Some(z) = i64::checked_pow(10, y) {
        if let Some(w) = i64::checked_mul(x, z) {
            return Ok(w);
        }
    };
    Err(Error::Overflow)
}

impl Decimal {
    /// The Cedar typename of decimal values
    fn typename() -> Name {
        constants::DECIMAL_FROM_STR_NAME.clone()
    }

    /// Convert a string into a `Decimal` value.
    ///
    /// Matches against the regular expression `-?[0-9]+.[0-9]+`, which requires
    /// a decimal point and at least one digit before and after the decimal.
    /// We also enforce at most NUM_DIGITS digits after the decimal.
    ///
    /// Our representation stores the decimal number `d` as the 64-bit integer
    /// `d * 10 ^ NUM_DIGITS`; this function will error on overflow.
    fn from_str(str: impl AsRef<str>) -> Result<Self, Error> {
        // check that the string matches the regex
        if !constants::DECIMAL_REGEX.is_match(str.as_ref()) {
            return Err(Error::FailedParse(str.as_ref().to_owned()));
        }

        // pull out the components before and after the decimal point
        // (the check above should ensure that .captures() and .get() succeed,
        // but we include proper error handling for posterity)
        let caps = constants::DECIMAL_REGEX
            .captures(str.as_ref())
            .ok_or_else(|| Error::FailedParse(str.as_ref().to_owned()))?;
        let l = caps
            .get(1)
            .ok_or_else(|| Error::FailedParse(str.as_ref().to_owned()))?
            .as_str();
        let r = caps
            .get(2)
            .ok_or_else(|| Error::FailedParse(str.as_ref().to_owned()))?
            .as_str();

        // convert the left component to i64 and multiply by `10 ^ NUM_DIGITS`
        let l = i64::from_str(l).map_err(|_| Error::Overflow)?;
        let l = checked_mul_pow(l, NUM_DIGITS)?;

        // convert the right component to i64 and multiply by `10 ^ (NUM_DIGITS - len)`
        let len: u32 = r.len().try_into().map_err(|_| Error::Overflow)?;
        if NUM_DIGITS < len {
            return Err(Error::TooManyDigits(str.as_ref().to_string()));
        }
        let r = i64::from_str(r).map_err(|_| Error::Overflow)?;
        let r = checked_mul_pow(r, NUM_DIGITS - len)?;

        // compute the value
        if l >= 0 {
            l.checked_add(r)
        } else {
            l.checked_sub(r)
        }
        .map(|value| Self { value })
        .ok_or(Error::Overflow)
    }
}

impl std::fmt::Display for Decimal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}",
            self.value / i64::pow(10, NUM_DIGITS),
            (self.value % i64::pow(10, NUM_DIGITS)).abs()
        )
    }
}

impl ExtensionValue for Decimal {
    fn typename(&self) -> Name {
        Self::typename()
    }
}

const EXTENSION_NAME: &str = "decimal";

fn extension_err(msg: impl Into<String>) -> evaluator::EvaluationError {
    evaluator::EvaluationError::failed_extension_function_application(
        constants::DECIMAL_FROM_STR_NAME.clone(),
        msg.into(),
        None, // source loc will be added by the evaluator
    )
}

/// Cedar function that constructs a `decimal` Cedar type from a
/// Cedar string
fn decimal_from_str(arg: Value) -> evaluator::Result<ExtensionOutputValue> {
    let str = arg.get_as_string()?;
    let decimal = Decimal::from_str(str.as_str()).map_err(|e| extension_err(e.to_string()))?;
    let function_name = constants::DECIMAL_FROM_STR_NAME.clone();
    let arg_source_loc = arg.source_loc().cloned();
    let e = ExtensionValueWithArgs::new(Arc::new(decimal), function_name, vec![arg.into()]);
    Ok(Value {
        value: ValueKind::ExtensionValue(Arc::new(e)),
        loc: arg_source_loc, // this gives the loc of the arg. We could perhaps give instead the loc of the entire `decimal("x.yz")` call, but that is hard to do at this program point
    }
    .into())
}

/// Check that `v` is a decimal type and, if it is, return the wrapped value
fn as_decimal(v: &Value) -> Result<&Decimal, evaluator::EvaluationError> {
    match &v.value {
        ValueKind::ExtensionValue(ev) if ev.typename() == Decimal::typename() => {
            // PANIC SAFETY Conditional above performs a typecheck
            #[allow(clippy::expect_used)]
            let d = ev
                .value()
                .as_any()
                .downcast_ref::<Decimal>()
                .expect("already typechecked, so this downcast should succeed");
            Ok(d)
        }
        ValueKind::Lit(Literal::String(_)) => {
            Err(evaluator::EvaluationError::type_error_with_advice_single(
                Type::Extension {
                    name: Decimal::typename(),
                },
                v,
                ADVICE_MSG.into(),
            ))
        }
        _ => Err(evaluator::EvaluationError::type_error_single(
            Type::Extension {
                name: Decimal::typename(),
            },
            v,
        )),
    }
}

/// Cedar function that tests whether the first `decimal` Cedar type is
/// less than the second `decimal` Cedar type, returning a Cedar bool
fn decimal_lt(left: Value, right: Value) -> evaluator::Result<ExtensionOutputValue> {
    let left = as_decimal(&left)?;
    let right = as_decimal(&right)?;
    Ok(Value::from(left < right).into())
}

/// Cedar function that tests whether the first `decimal` Cedar type is
/// less than or equal to the second `decimal` Cedar type, returning a Cedar bool
fn decimal_le(left: Value, right: Value) -> evaluator::Result<ExtensionOutputValue> {
    let left = as_decimal(&left)?;
    let right = as_decimal(&right)?;
    Ok(Value::from(left <= right).into())
}

/// Cedar function that tests whether the first `decimal` Cedar type is
/// greater than the second `decimal` Cedar type, returning a Cedar bool
fn decimal_gt(left: Value, right: Value) -> evaluator::Result<ExtensionOutputValue> {
    let left = as_decimal(&left)?;
    let right = as_decimal(&right)?;
    Ok(Value::from(left > right).into())
}

/// Cedar function that tests whether the first `decimal` Cedar type is
/// greater than or equal to the second `decimal` Cedar type, returning a Cedar bool
fn decimal_ge(left: Value, right: Value) -> evaluator::Result<ExtensionOutputValue> {
    let left = as_decimal(&left)?;
    let right = as_decimal(&right)?;
    Ok(Value::from(left >= right).into())
}

/// Construct the extension
pub fn extension() -> Extension {
    let decimal_type = SchemaType::Extension {
        name: Decimal::typename(),
    };
    Extension::new(
        constants::DECIMAL_FROM_STR_NAME.clone(),
        vec![
            ExtensionFunction::unary(
                constants::DECIMAL_FROM_STR_NAME.clone(),
                CallStyle::FunctionStyle,
                Box::new(decimal_from_str),
                decimal_type.clone(),
                Some(SchemaType::String),
            ),
            ExtensionFunction::binary(
                constants::LESS_THAN.clone(),
                CallStyle::MethodStyle,
                Box::new(decimal_lt),
                SchemaType::Bool,
                (Some(decimal_type.clone()), Some(decimal_type.clone())),
            ),
            ExtensionFunction::binary(
                constants::LESS_THAN_OR_EQUAL.clone(),
                CallStyle::MethodStyle,
                Box::new(decimal_le),
                SchemaType::Bool,
                (Some(decimal_type.clone()), Some(decimal_type.clone())),
            ),
            ExtensionFunction::binary(
                constants::GREATER_THAN.clone(),
                CallStyle::MethodStyle,
                Box::new(decimal_gt),
                SchemaType::Bool,
                (Some(decimal_type.clone()), Some(decimal_type.clone())),
            ),
            ExtensionFunction::binary(
                constants::GREATER_THAN_OR_EQUAL.clone(),
                CallStyle::MethodStyle,
                Box::new(decimal_ge),
                SchemaType::Bool,
                (Some(decimal_type.clone()), Some(decimal_type)),
            ),
        ],
    )
}

#[cfg(test)]
// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::ast::{Expr, Type, Value};
    use crate::evaluator::test::{basic_entities, basic_request};
    use crate::evaluator::{EvaluationErrorKind, Evaluator};
    use crate::extensions::Extensions;
    use crate::parser::parse_expr;
    use cool_asserts::assert_matches;
    use nonempty::nonempty;

    /// Asserts that a `Result` is an `Err::ExtensionErr` with our extension name
    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_decimal_err<T: std::fmt::Debug>(res: evaluator::Result<T>) {
        assert_matches!(res, Err(e) => {
            assert_matches!(e.error_kind(), evaluator::EvaluationErrorKind::FailedExtensionFunctionApplication {
                extension_name,
                msg,
            } => {
                println!("{msg}");
                assert_eq!(
                    *extension_name,
                    Name::parse_unqualified_name("decimal")
                        .expect("should be a valid identifier")
                )
            });
        });
    }

    /// Asserts that a `Result` is a decimal value
    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_decimal_valid(res: evaluator::Result<Value>) {
        assert_matches!(res, Ok(Value { value: ValueKind::ExtensionValue(ev), .. }) => {
            assert_eq!(ev.typename(), Decimal::typename());
        });
    }

    /// this test just ensures that the right functions are marked constructors
    #[test]
    fn constructors() {
        let ext = extension();
        assert!(ext
            .get_func(
                &Name::parse_unqualified_name("decimal").expect("should be a valid identifier")
            )
            .expect("function should exist")
            .is_constructor());
        assert!(!ext
            .get_func(
                &Name::parse_unqualified_name("lessThan").expect("should be a valid identifier")
            )
            .expect("function should exist")
            .is_constructor());
        assert!(!ext
            .get_func(
                &Name::parse_unqualified_name("lessThanOrEqual")
                    .expect("should be a valid identifier")
            )
            .expect("function should exist")
            .is_constructor());
        assert!(!ext
            .get_func(
                &Name::parse_unqualified_name("greaterThan").expect("should be a valid identifier")
            )
            .expect("function should exist")
            .is_constructor());
        assert!(!ext
            .get_func(
                &Name::parse_unqualified_name("greaterThanOrEqual")
                    .expect("should be a valid identifier")
            )
            .expect("function should exist")
            .is_constructor(),);
    }

    #[test]
    fn decimal_creation() {
        let ext_array = [extension()];
        let exts = Extensions::specific_extensions(&ext_array);
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, &exts);

        // valid decimal strings
        assert_decimal_valid(
            eval.interpret_inline_policy(&parse_expr(r#"decimal("1.0")"#).expect("parsing error")),
        );
        assert_decimal_valid(
            eval.interpret_inline_policy(&parse_expr(r#"decimal("-1.0")"#).expect("parsing error")),
        );
        assert_decimal_valid(
            eval.interpret_inline_policy(
                &parse_expr(r#"decimal("123.456")"#).expect("parsing error"),
            ),
        );
        assert_decimal_valid(
            eval.interpret_inline_policy(
                &parse_expr(r#"decimal("0.1234")"#).expect("parsing error"),
            ),
        );
        assert_decimal_valid(
            eval.interpret_inline_policy(
                &parse_expr(r#"decimal("-0.0123")"#).expect("parsing error"),
            ),
        );
        assert_decimal_valid(
            eval.interpret_inline_policy(&parse_expr(r#"decimal("55.1")"#).expect("parsing error")),
        );
        assert_decimal_valid(eval.interpret_inline_policy(
            &parse_expr(r#"decimal("-922337203685477.5808")"#).expect("parsing error"),
        ));

        // weird, but ok
        assert_decimal_valid(
            eval.interpret_inline_policy(
                &parse_expr(r#"decimal("00.000")"#).expect("parsing error"),
            ),
        );

        // invalid decimal strings
        assert_decimal_err(
            eval.interpret_inline_policy(&parse_expr(r#"decimal("1234")"#).expect("parsing error")),
        );
        assert_decimal_err(
            eval.interpret_inline_policy(&parse_expr(r#"decimal("1.0.")"#).expect("parsing error")),
        );
        assert_decimal_err(
            eval.interpret_inline_policy(&parse_expr(r#"decimal("1.")"#).expect("parsing error")),
        );
        assert_decimal_err(
            eval.interpret_inline_policy(&parse_expr(r#"decimal(".1")"#).expect("parsing error")),
        );
        assert_decimal_err(
            eval.interpret_inline_policy(&parse_expr(r#"decimal("1.a")"#).expect("parsing error")),
        );
        assert_decimal_err(
            eval.interpret_inline_policy(&parse_expr(r#"decimal("-.")"#).expect("parsing error")),
        );

        // overflows
        assert_decimal_err(eval.interpret_inline_policy(
            &parse_expr(r#"decimal("1000000000000000.0")"#).expect("parsing error"),
        ));
        assert_decimal_err(eval.interpret_inline_policy(
            &parse_expr(r#"decimal("922337203685477.5808")"#).expect("parsing error"),
        ));
        assert_decimal_err(eval.interpret_inline_policy(
            &parse_expr(r#"decimal("-922337203685477.5809")"#).expect("parsing error"),
        ));
        assert_decimal_err(eval.interpret_inline_policy(
            &parse_expr(r#"decimal("-922337203685478.0")"#).expect("parsing error"),
        ));

        // too many digits after the decimal point
        assert_decimal_err(
            eval.interpret_inline_policy(
                &parse_expr(r#"decimal("0.12345")"#).expect("parsing error"),
            ),
        );

        // still an error, even if the extra digits are 0
        assert_decimal_err(
            eval.interpret_inline_policy(
                &parse_expr(r#"decimal("0.00000")"#).expect("parsing error"),
            ),
        );

        // bad use of `decimal` as method
        parse_expr(r#" "1.0".decimal() "#).expect_err("should fail");
    }

    #[test]
    fn decimal_equality() {
        let ext_array = [extension()];
        let exts = Extensions::specific_extensions(&ext_array);
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, &exts);

        let a = parse_expr(r#"decimal("123.0")"#).expect("parsing error");
        let b = parse_expr(r#"decimal("123.0000")"#).expect("parsing error");
        let c = parse_expr(r#"decimal("0123.0")"#).expect("parsing error");
        let d = parse_expr(r#"decimal("123.456")"#).expect("parsing error");
        let e = parse_expr(r#"decimal("1.23")"#).expect("parsing error");
        let f = parse_expr(r#"decimal("0.0")"#).expect("parsing error");
        let g = parse_expr(r#"decimal("-0.0")"#).expect("parsing error");

        // a, b, c are all equal
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(a.clone(), a.clone())),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(a.clone(), b.clone())),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(b.clone(), c.clone())),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(c, a.clone())),
            Ok(Value::from(true))
        );

        // d, e are distinct
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(b, d.clone())),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(a.clone(), e.clone())),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(d, e)),
            Ok(Value::from(false))
        );

        // f (0.0) and g (-0.0) are equal
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(f, g)),
            Ok(Value::from(true))
        );

        // other types are not equal
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(a.clone(), Expr::val("123.0"))),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(a, Expr::val(1))),
            Ok(Value::from(false))
        );
    }

    fn decimal_ops_helper(op: &str, tests: Vec<((Expr, Expr), bool)>) {
        let ext_array = [extension()];
        let exts = Extensions::specific_extensions(&ext_array);
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, &exts);

        for ((l, r), res) in tests {
            assert_eq!(
                eval.interpret_inline_policy(&Expr::call_extension_fn(
                    Name::parse_unqualified_name(op).expect("should be a valid identifier"),
                    vec![l, r]
                )),
                Ok(Value::from(res))
            );
        }
    }

    #[test]
    fn decimal_ops() {
        let a = parse_expr(r#"decimal("1.23")"#).expect("parsing error");
        let b = parse_expr(r#"decimal("1.24")"#).expect("parsing error");
        let c = parse_expr(r#"decimal("123.45")"#).expect("parsing error");
        let d = parse_expr(r#"decimal("-1.23")"#).expect("parsing error");
        let e = parse_expr(r#"decimal("-1.24")"#).expect("parsing error");

        // tests for lessThan
        let tests = vec![
            ((a.clone(), b.clone()), true),  // 1.23 < 1.24
            ((a.clone(), a.clone()), false), // 1.23 < 1.23
            ((c.clone(), a.clone()), false), // 123.45 < 1.23
            ((d.clone(), a.clone()), true),  // -1.23 < 1.23
            ((d.clone(), e.clone()), false), // -1.23 < -1.24
        ];
        decimal_ops_helper("lessThan", tests);

        // tests for lessThanOrEqual
        let tests = vec![
            ((a.clone(), b.clone()), true),  // 1.23 <= 1.24
            ((a.clone(), a.clone()), true),  // 1.23 <= 1.23
            ((c.clone(), a.clone()), false), // 123.45 <= 1.23
            ((d.clone(), a.clone()), true),  // -1.23 <= 1.23
            ((d.clone(), e.clone()), false), // -1.23 <= -1.24
        ];
        decimal_ops_helper("lessThanOrEqual", tests);

        // tests for greaterThan
        let tests = vec![
            ((a.clone(), b.clone()), false), // 1.23 > 1.24
            ((a.clone(), a.clone()), false), // 1.23 > 1.23
            ((c.clone(), a.clone()), true),  // 123.45 > 1.23
            ((d.clone(), a.clone()), false), // -1.23 > 1.23
            ((d.clone(), e.clone()), true),  // -1.23 > -1.24
        ];
        decimal_ops_helper("greaterThan", tests);

        // tests for greaterThanOrEqual
        let tests = vec![
            ((a.clone(), b), false),        // 1.23 >= 1.24
            ((a.clone(), a.clone()), true), // 1.23 >= 1.23
            ((c, a.clone()), true),         // 123.45 >= 1.23
            ((d.clone(), a), false),        // -1.23 >= 1.23
            ((d, e), true),                 // -1.23 >= -1.24
        ];
        decimal_ops_helper("greaterThanOrEqual", tests);

        // evaluation errors

        let ext_array = [extension()];
        let exts = Extensions::specific_extensions(&ext_array);
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, &exts);

        assert_matches!(
            eval.interpret_inline_policy(
                &parse_expr(r#"decimal("1.23") < decimal("1.24")"#).expect("parsing error")
            ),
            Err(e) => assert_eq!(e.error_kind(),
                &EvaluationErrorKind::TypeError {
                    expected: nonempty![Type::Long],
                    actual: Type::Extension {
                        name: Name::parse_unqualified_name("decimal")
                            .expect("should be a valid identifier")
                    },
                }
            )
        );
        assert_matches!(
            eval.interpret_inline_policy(
                &parse_expr(r#"decimal("-1.23").lessThan("1.23")"#).expect("parsing error")
            ),
            Err(e) => {
                assert_eq!(
                    e.error_kind(),
                    &EvaluationErrorKind::TypeError {
                        expected: nonempty![Type::Extension {
                            name: Name::parse_unqualified_name("decimal")
                                .expect("should be a valid identifier")
                        }],
                        actual: Type::String,
                    }
                );
                assert_eq!(e.advice(), Some(ADVICE_MSG));
            }
        );
        // bad use of `lessThan` as function
        parse_expr(r#"lessThan(decimal("-1.23"), decimal("1.23"))"#).expect_err("should fail");
    }

    fn check_round_trip(s: &str) {
        let d = Decimal::from_str(s).expect("should be a valid decimal");
        assert_eq!(s, d.to_string());
    }

    #[test]
    fn decimal_display() {
        // these strings will display the same after parsing
        check_round_trip("123.0");
        check_round_trip("1.2300");
        check_round_trip("123.4560");
        check_round_trip("-123.4560");
        check_round_trip("0.0");
    }
}
