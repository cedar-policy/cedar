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

use super::{Expr, Unknown, Value};
use crate::parser::Loc;
use itertools::Either;
use miette::Diagnostic;
use thiserror::Error;

/// Intermediate results of partial evaluation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartialValue {
    /// Fully evaluated values
    Value(Value),
    /// Residual expressions containing unknowns
    /// INVARIANT: A residual _must_ have an unknown contained within
    Residual(Expr),
}

impl PartialValue {
    /// Create a new `PartialValue` consisting of just this single `Unknown`
    pub fn unknown(u: Unknown) -> Self {
        Self::Residual(Expr::unknown(u))
    }

    /// Return the `PartialValue`, but with the given `Loc` (or `None`)
    pub fn with_maybe_source_loc(self, loc: Option<Loc>) -> Self {
        match self {
            Self::Value(v) => Self::Value(v.with_maybe_source_loc(loc)),
            Self::Residual(e) => Self::Residual(e.with_maybe_source_loc(loc)),
        }
    }
}

impl<V: Into<Value>> From<V> for PartialValue {
    fn from(into_v: V) -> Self {
        PartialValue::Value(into_v.into())
    }
}

impl From<Expr> for PartialValue {
    fn from(e: Expr) -> Self {
        debug_assert!(e.contains_unknown());
        PartialValue::Residual(e)
    }
}

/// Errors encountered when converting `PartialValue` to `Value`
// CAUTION: this type is publicly exported in `cedar-policy`.
#[derive(Debug, PartialEq, Diagnostic, Error)]
pub enum PartialValueToValueError {
    /// The `PartialValue` is a residual, i.e., contains an unknown
    #[diagnostic(transparent)]
    #[error(transparent)]
    ContainsUnknown(#[from] ContainsUnknown),
}

/// The `PartialValue` is a residual, i.e., contains an unknown
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, PartialEq, Diagnostic, Error)]
#[error("value contains a residual expression: `{residual}`")]
pub struct ContainsUnknown {
    /// Residual expression which contains an unknown
    residual: Expr,
}

impl TryFrom<PartialValue> for Value {
    type Error = PartialValueToValueError;

    fn try_from(value: PartialValue) -> Result<Self, Self::Error> {
        match value {
            PartialValue::Value(v) => Ok(v),
            PartialValue::Residual(e) => Err(ContainsUnknown { residual: e }.into()),
        }
    }
}

impl std::fmt::Display for PartialValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PartialValue::Value(v) => write!(f, "{v}"),
            PartialValue::Residual(r) => write!(f, "{r}"),
        }
    }
}

/// Collect an iterator of either residuals or values into one of the following
///  a) An iterator over values, if everything evaluated to values
///  b) An iterator over residuals expressions, if anything only evaluated to a residual
/// Order is preserved.
pub fn split<I>(i: I) -> Either<impl Iterator<Item = Value>, impl Iterator<Item = Expr>>
where
    I: IntoIterator<Item = PartialValue>,
{
    let mut values = vec![];
    let mut residuals = vec![];

    for item in i.into_iter() {
        match item {
            PartialValue::Value(a) => {
                if residuals.is_empty() {
                    values.push(a)
                } else {
                    residuals.push(a.into())
                }
            }
            PartialValue::Residual(r) => {
                residuals.push(r);
            }
        }
    }

    if residuals.is_empty() {
        Either::Left(values.into_iter())
    } else {
        let mut exprs: Vec<Expr> = values.into_iter().map(|x| x.into()).collect();
        exprs.append(&mut residuals);
        Either::Right(exprs.into_iter())
    }
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn split_values() {
        let vs = [
            PartialValue::Value(Value::from(1)),
            PartialValue::Value(Value::from(2)),
        ];
        match split(vs) {
            Either::Right(_) => panic!("expected values, got residuals"),
            Either::Left(vs) => {
                assert_eq!(vs.collect::<Vec<_>>(), vec![Value::from(1), Value::from(2)])
            }
        };
    }

    #[test]
    fn split_residuals() {
        let rs = [
            PartialValue::Value(Value::from(1)),
            PartialValue::Residual(Expr::val(2)),
            PartialValue::Value(Value::from(3)),
            PartialValue::Residual(Expr::val(4)),
        ];
        let expected = vec![Expr::val(1), Expr::val(2), Expr::val(3), Expr::val(4)];
        match split(rs) {
            Either::Left(_) => panic!("expected residuals, got values"),
            Either::Right(rs) => {
                assert_eq!(rs.collect::<Vec<_>>(), expected);
            }
        };
    }

    #[test]
    fn split_residuals2() {
        let rs = [
            PartialValue::Value(Value::from(1)),
            PartialValue::Value(Value::from(2)),
            PartialValue::Residual(Expr::val(3)),
            PartialValue::Residual(Expr::val(4)),
        ];
        let expected = vec![Expr::val(1), Expr::val(2), Expr::val(3), Expr::val(4)];
        match split(rs) {
            Either::Left(_) => panic!("expected residuals, got values"),
            Either::Right(rs) => {
                assert_eq!(rs.collect::<Vec<_>>(), expected);
            }
        };
    }

    #[test]
    fn split_residuals3() {
        let rs = [
            PartialValue::Residual(Expr::val(1)),
            PartialValue::Residual(Expr::val(2)),
            PartialValue::Value(Value::from(3)),
            PartialValue::Value(Value::from(4)),
        ];
        let expected = vec![Expr::val(1), Expr::val(2), Expr::val(3), Expr::val(4)];
        match split(rs) {
            Either::Left(_) => panic!("expected residuals, got values"),
            Either::Right(rs) => {
                assert_eq!(rs.collect::<Vec<_>>(), expected);
            }
        };
    }
}
