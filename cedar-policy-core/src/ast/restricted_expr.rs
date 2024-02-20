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

use super::{
    EntityUID, Expr, ExprConstructionError, ExprKind, Literal, Name, PartialValue, Unknown, Value,
    ValueKind,
};
use crate::entities::JsonSerializationError;
use crate::parser::err::ParseErrors;
use crate::parser::{self, Loc};
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::Arc;
use thiserror::Error;

/// A few places in Core use these "restricted expressions" (for lack of a
/// better term) which are in some sense the minimal subset of `Expr` required
/// to express all possible `Value`s.
///
/// Specifically, "restricted" expressions are
/// defined as expressions containing only the following:
///   - bool, int, and string literals
///   - literal EntityUIDs such as User::"alice"
///   - extension function calls, where the arguments must be other things
///       on this list
///   - set and record literals, where the values must be other things on
///       this list
///
/// That means the following are not allowed in "restricted" expressions:
///   - `principal`, `action`, `resource`, `context`
///   - builtin operators and functions, including `.`, `in`, `has`, `like`,
///       `.contains()`
///   - if-then-else expressions
///
/// These restrictions represent the expressions that are allowed to appear as
/// attribute values in `Slice` and `Context`.
#[derive(Deserialize, Serialize, Hash, Debug, Clone, PartialEq, Eq)]
#[serde(transparent)]
pub struct RestrictedExpr(Expr);

impl RestrictedExpr {
    /// Create a new `RestrictedExpr` from an `Expr`.
    ///
    /// This function is "safe" in the sense that it will verify that the
    /// provided `expr` does indeed qualify as a "restricted" expression,
    /// returning an error if not.
    ///
    /// Note this check requires recursively walking the AST. For a version of
    /// this function that doesn't perform this check, see `new_unchecked()`
    /// below.
    pub fn new(expr: Expr) -> Result<Self, RestrictedExprError> {
        is_restricted(&expr)?;
        Ok(Self(expr))
    }

    /// Create a new `RestrictedExpr` from an `Expr`, where the caller is
    /// responsible for ensuring that the `Expr` is a valid "restricted
    /// expression". If it is not, internal invariants will be violated, which
    /// may lead to other errors later, panics, or even incorrect results.
    ///
    /// For a "safer" version of this function that returns an error for invalid
    /// inputs, see `new()` above.
    pub fn new_unchecked(expr: Expr) -> Self {
        // in debug builds, this does the check anyway, panicking if it fails
        if cfg!(debug_assertions) {
            // PANIC SAFETY: We're in debug mode and panicking intentionally
            #[allow(clippy::unwrap_used)]
            Self::new(expr).unwrap()
        } else {
            Self(expr)
        }
    }

    /// Return the `RestrictedExpr`, but with the new `source_loc` (or `None`).
    pub fn with_maybe_source_loc(self, source_loc: Option<Loc>) -> Self {
        Self(self.0.with_maybe_source_loc(source_loc))
    }

    /// Create a `RestrictedExpr` that's just a single `Literal`.
    ///
    /// Note that you can pass this a `Literal`, an `Integer`, a `String`, etc.
    pub fn val(v: impl Into<Literal>) -> Self {
        // All literals are valid restricted-exprs
        Self::new_unchecked(Expr::val(v))
    }

    /// Create a `RestrictedExpr` that's just a single `Unknown`.
    pub fn unknown(u: Unknown) -> Self {
        // All unknowns are valid restricted-exprs
        Self::new_unchecked(Expr::unknown(u))
    }

    /// Create a `RestrictedExpr` which evaluates to a Set of the given `RestrictedExpr`s
    pub fn set(exprs: impl IntoIterator<Item = RestrictedExpr>) -> Self {
        // Set expressions are valid restricted-exprs if their elements are; and
        // we know the elements are because we require `RestrictedExpr`s in the
        // parameter
        Self::new_unchecked(Expr::set(exprs.into_iter().map(Into::into)))
    }

    /// Create a `RestrictedExpr` which evaluates to a Record with the given
    /// (key, value) pairs.
    ///
    /// Throws an error if any key occurs two or more times.
    pub fn record(
        pairs: impl IntoIterator<Item = (SmolStr, RestrictedExpr)>,
    ) -> Result<Self, ExprConstructionError> {
        // Record expressions are valid restricted-exprs if their elements are;
        // and we know the elements are because we require `RestrictedExpr`s in
        // the parameter
        Ok(Self::new_unchecked(Expr::record(
            pairs.into_iter().map(|(k, v)| (k, v.into())),
        )?))
    }

    /// Create a `RestrictedExpr` which calls the given extension function
    pub fn call_extension_fn(
        function_name: Name,
        args: impl IntoIterator<Item = RestrictedExpr>,
    ) -> Self {
        // Extension-function calls are valid restricted-exprs if their
        // arguments are; and we know the arguments are because we require
        // `RestrictedExpr`s in the parameter
        Self::new_unchecked(Expr::call_extension_fn(
            function_name,
            args.into_iter().map(Into::into).collect(),
        ))
    }

    /// Write a RestrictedExpr in "natural JSON" format.
    ///
    /// Used to output the context as a map from Strings to JSON Values
    pub fn to_natural_json(&self) -> Result<serde_json::Value, JsonSerializationError> {
        self.as_borrowed().to_natural_json()
    }

    /// Get the `bool` value of this `RestrictedExpr` if it's a boolean, or
    /// `None` if it is not a boolean
    pub fn as_bool(&self) -> Option<bool> {
        // the only way a `RestrictedExpr` can be a boolean is if it's a literal
        match self.expr_kind() {
            ExprKind::Lit(Literal::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    /// Get the `i64` value of this `RestrictedExpr` if it's a long, or `None`
    /// if it is not a long
    pub fn as_long(&self) -> Option<i64> {
        // the only way a `RestrictedExpr` can be a long is if it's a literal
        match self.expr_kind() {
            ExprKind::Lit(Literal::Long(i)) => Some(*i),
            _ => None,
        }
    }

    /// Get the `SmolStr` value of this `RestrictedExpr` if it's a string, or
    /// `None` if it is not a string
    pub fn as_string(&self) -> Option<&SmolStr> {
        // the only way a `RestrictedExpr` can be a string is if it's a literal
        match self.expr_kind() {
            ExprKind::Lit(Literal::String(s)) => Some(s),
            _ => None,
        }
    }

    /// Get the `EntityUID` value of this `RestrictedExpr` if it's an entity
    /// reference, or `None` if it is not an entity reference
    pub fn as_euid(&self) -> Option<&EntityUID> {
        // the only way a `RestrictedExpr` can be an entity reference is if it's
        // a literal
        match self.expr_kind() {
            ExprKind::Lit(Literal::EntityUID(e)) => Some(e),
            _ => None,
        }
    }

    /// Get `Unknown` value of this `RestrictedExpr` if it's an `Unknown`, or
    /// `None` if it is not an `Unknown`
    pub fn as_unknown(&self) -> Option<&Unknown> {
        match self.expr_kind() {
            ExprKind::Unknown(u) => Some(u),
            _ => None,
        }
    }

    /// Iterate over the elements of the set if this `RestrictedExpr` is a set,
    /// or `None` if it is not a set
    pub fn as_set_elements(&self) -> Option<impl Iterator<Item = BorrowedRestrictedExpr<'_>>> {
        match self.expr_kind() {
            ExprKind::Set(set) => Some(set.iter().map(BorrowedRestrictedExpr::new_unchecked)), // since the RestrictedExpr invariant holds for the input set, it will hold for each element as well
            _ => None,
        }
    }

    /// Iterate over the (key, value) pairs of the record if this
    /// `RestrictedExpr` is a record, or `None` if it is not a record
    pub fn as_record_pairs(
        &self,
    ) -> Option<impl Iterator<Item = (&SmolStr, BorrowedRestrictedExpr<'_>)>> {
        match self.expr_kind() {
            ExprKind::Record(map) => Some(
                map.iter()
                    .map(|(k, v)| (k, BorrowedRestrictedExpr::new_unchecked(v))),
            ), // since the RestrictedExpr invariant holds for the input record, it will hold for each attr value as well
            _ => None,
        }
    }

    /// Get the name and args of the called extension function if this
    /// `RestrictedExpr` is an extension function call, or `None` if it is not
    /// an extension function call
    pub fn as_extn_fn_call(
        &self,
    ) -> Option<(&Name, impl Iterator<Item = BorrowedRestrictedExpr<'_>>)> {
        match self.expr_kind() {
            ExprKind::ExtensionFunctionApp { fn_name, args } => Some((
                fn_name,
                args.iter().map(BorrowedRestrictedExpr::new_unchecked),
            )), // since the RestrictedExpr invariant holds for the input call, it will hold for each argument as well
            _ => None,
        }
    }
}

impl From<Value> for RestrictedExpr {
    fn from(value: Value) -> RestrictedExpr {
        RestrictedExpr::from(value.value).with_maybe_source_loc(value.loc)
    }
}

impl From<ValueKind> for RestrictedExpr {
    fn from(value: ValueKind) -> RestrictedExpr {
        match value {
            ValueKind::Lit(lit) => RestrictedExpr::val(lit),
            ValueKind::Set(set) => {
                RestrictedExpr::set(set.iter().map(|val| RestrictedExpr::from(val.clone())))
            }
            // PANIC SAFETY: cannot have duplicate key because the input was already a BTreeMap
            #[allow(clippy::expect_used)]
            ValueKind::Record(record) => RestrictedExpr::record(
                Arc::unwrap_or_clone(record)
                    .into_iter()
                    .map(|(k, v)| (k, RestrictedExpr::from(v))),
            )
            .expect("can't have duplicate keys, because the input `map` was already a BTreeMap"),
            ValueKind::ExtensionValue(ev) => {
                let ev = Arc::unwrap_or_clone(ev);
                RestrictedExpr::call_extension_fn(ev.constructor, ev.args)
            }
        }
    }
}

impl TryFrom<PartialValue> for RestrictedExpr {
    type Error = PartialValueToRestrictedExprError;
    fn try_from(pvalue: PartialValue) -> Result<RestrictedExpr, PartialValueToRestrictedExprError> {
        match pvalue {
            PartialValue::Value(v) => Ok(RestrictedExpr::from(v)),
            PartialValue::Residual(expr) => match RestrictedExpr::new(expr) {
                Ok(e) => Ok(e),
                Err(RestrictedExprError::InvalidRestrictedExpression { expr, .. }) => {
                    Err(PartialValueToRestrictedExprError::NontrivialResidual {
                        residual: Box::new(expr),
                    })
                }
            },
        }
    }
}

/// Errors when converting `PartialValue` to `RestrictedExpr`
#[derive(Debug, PartialEq, Diagnostic, Error)]
pub enum PartialValueToRestrictedExprError {
    /// The `PartialValue` contains a nontrivial residual that isn't a valid `RestrictedExpr`
    #[error("residual is not a valid restricted expression: `{residual}`")]
    NontrivialResidual {
        /// Residual that isn't a valid `RestrictedExpr`
        residual: Box<Expr>,
    },
}

impl std::str::FromStr for RestrictedExpr {
    type Err = RestrictedExprParseError;

    fn from_str(s: &str) -> Result<RestrictedExpr, Self::Err> {
        parser::parse_restrictedexpr(s)
    }
}

/// While `RestrictedExpr` wraps an _owned_ `Expr`, `BorrowedRestrictedExpr`
/// wraps a _borrowed_ `Expr`, with the same invariants.
///
/// We derive `Copy` for this type because it's just a single reference, and
/// `&T` is `Copy` for all `T`.
#[derive(Serialize, Hash, Debug, Clone, PartialEq, Eq, Copy)]
pub struct BorrowedRestrictedExpr<'a>(&'a Expr);

impl<'a> BorrowedRestrictedExpr<'a> {
    /// Create a new `BorrowedRestrictedExpr` from an `&Expr`.
    ///
    /// This function is "safe" in the sense that it will verify that the
    /// provided `expr` does indeed qualify as a "restricted" expression,
    /// returning an error if not.
    ///
    /// Note this check requires recursively walking the AST. For a version of
    /// this function that doesn't perform this check, see `new_unchecked()`
    /// below.
    pub fn new(expr: &'a Expr) -> Result<Self, RestrictedExprError> {
        is_restricted(expr)?;
        Ok(Self(expr))
    }

    /// Create a new `BorrowedRestrictedExpr` from an `&Expr`, where the caller
    /// is responsible for ensuring that the `Expr` is a valid "restricted
    /// expression". If it is not, internal invariants will be violated, which
    /// may lead to other errors later, panics, or even incorrect results.
    ///
    /// For a "safer" version of this function that returns an error for invalid
    /// inputs, see `new()` above.
    pub fn new_unchecked(expr: &'a Expr) -> Self {
        // in debug builds, this does the check anyway, panicking if it fails
        if cfg!(debug_assertions) {
            // PANIC SAFETY: We're in debug mode and panicking intentionally
            #[allow(clippy::unwrap_used)]
            Self::new(expr).unwrap()
        } else {
            Self(expr)
        }
    }

    /// Write a BorrowedRestrictedExpr in "natural JSON" format.
    ///
    /// Used to output the context as a map from Strings to JSON Values
    pub fn to_natural_json(self) -> Result<serde_json::Value, JsonSerializationError> {
        Ok(serde_json::to_value(
            crate::entities::CedarValueJson::from_expr(self)?,
        )?)
    }

    /// Convert `BorrowedRestrictedExpr` to `RestrictedExpr`.
    /// This has approximately the cost of cloning the `Expr`.
    pub fn to_owned(self) -> RestrictedExpr {
        RestrictedExpr::new_unchecked(self.0.clone())
    }

    /// Get the `bool` value of this `RestrictedExpr` if it's a boolean, or
    /// `None` if it is not a boolean
    pub fn as_bool(&self) -> Option<bool> {
        // the only way a `RestrictedExpr` can be a boolean is if it's a literal
        match self.expr_kind() {
            ExprKind::Lit(Literal::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    /// Get the `i64` value of this `RestrictedExpr` if it's a long, or `None`
    /// if it is not a long
    pub fn as_long(&self) -> Option<i64> {
        // the only way a `RestrictedExpr` can be a long is if it's a literal
        match self.expr_kind() {
            ExprKind::Lit(Literal::Long(i)) => Some(*i),
            _ => None,
        }
    }

    /// Get the `SmolStr` value of this `RestrictedExpr` if it's a string, or
    /// `None` if it is not a string
    pub fn as_string(&self) -> Option<&SmolStr> {
        // the only way a `RestrictedExpr` can be a string is if it's a literal
        match self.expr_kind() {
            ExprKind::Lit(Literal::String(s)) => Some(s),
            _ => None,
        }
    }

    /// Get the `EntityUID` value of this `RestrictedExpr` if it's an entity
    /// reference, or `None` if it is not an entity reference
    pub fn as_euid(&self) -> Option<&EntityUID> {
        // the only way a `RestrictedExpr` can be an entity reference is if it's
        // a literal
        match self.expr_kind() {
            ExprKind::Lit(Literal::EntityUID(e)) => Some(e),
            _ => None,
        }
    }

    /// Get `Unknown` value of this `RestrictedExpr` if it's an `Unknown`, or
    /// `None` if it is not an `Unknown`
    pub fn as_unknown(&self) -> Option<&Unknown> {
        match self.expr_kind() {
            ExprKind::Unknown(u) => Some(u),
            _ => None,
        }
    }

    /// Iterate over the elements of the set if this `RestrictedExpr` is a set,
    /// or `None` if it is not a set
    pub fn as_set_elements(&self) -> Option<impl Iterator<Item = BorrowedRestrictedExpr<'_>>> {
        match self.expr_kind() {
            ExprKind::Set(set) => Some(set.iter().map(BorrowedRestrictedExpr::new_unchecked)), // since the RestrictedExpr invariant holds for the input set, it will hold for each element as well
            _ => None,
        }
    }

    /// Iterate over the (key, value) pairs of the record if this
    /// `RestrictedExpr` is a record, or `None` if it is not a record
    pub fn as_record_pairs(
        &self,
    ) -> Option<impl Iterator<Item = (&'_ SmolStr, BorrowedRestrictedExpr<'_>)>> {
        match self.expr_kind() {
            ExprKind::Record(map) => Some(
                map.iter()
                    .map(|(k, v)| (k, BorrowedRestrictedExpr::new_unchecked(v))),
            ), // since the RestrictedExpr invariant holds for the input record, it will hold for each attr value as well
            _ => None,
        }
    }

    /// Get the name and args of the called extension function if this
    /// `RestrictedExpr` is an extension function call, or `None` if it is not
    /// an extension function call
    pub fn as_extn_fn_call(
        &self,
    ) -> Option<(&Name, impl Iterator<Item = BorrowedRestrictedExpr<'_>>)> {
        match self.expr_kind() {
            ExprKind::ExtensionFunctionApp { fn_name, args } => Some((
                fn_name,
                args.iter().map(BorrowedRestrictedExpr::new_unchecked),
            )), // since the RestrictedExpr invariant holds for the input call, it will hold for each argument as well
            _ => None,
        }
    }
}

/// Helper function: does the given `Expr` qualify as a "restricted" expression.
///
/// Returns `Ok(())` if yes, or a `RestrictedExpressionError` if no.
fn is_restricted(expr: &Expr) -> Result<(), RestrictedExprError> {
    match expr.expr_kind() {
        ExprKind::Lit(_) => Ok(()),
        ExprKind::Unknown(_) => Ok(()),
        ExprKind::Var(_) => Err(RestrictedExprError::InvalidRestrictedExpression {
            feature: "variables".into(),
            expr: expr.clone(),
        }),
        ExprKind::Slot(_) => Err(RestrictedExprError::InvalidRestrictedExpression {
            feature: "template slots".into(),
            expr: expr.clone(),
        }),
        ExprKind::If { .. } => Err(RestrictedExprError::InvalidRestrictedExpression {
            feature: "if-then-else".into(),
            expr: expr.clone(),
        }),
        ExprKind::And { .. } => Err(RestrictedExprError::InvalidRestrictedExpression {
            feature: "&&".into(),
            expr: expr.clone(),
        }),
        ExprKind::Or { .. } => Err(RestrictedExprError::InvalidRestrictedExpression {
            feature: "||".into(),
            expr: expr.clone(),
        }),
        ExprKind::UnaryApp { op, .. } => Err(RestrictedExprError::InvalidRestrictedExpression {
            feature: op.to_string().into(),
            expr: expr.clone(),
        }),
        ExprKind::BinaryApp { op, .. } => Err(RestrictedExprError::InvalidRestrictedExpression {
            feature: op.to_string().into(),
            expr: expr.clone(),
        }),
        ExprKind::MulByConst { .. } => Err(RestrictedExprError::InvalidRestrictedExpression {
            feature: "multiplication".into(),
            expr: expr.clone(),
        }),
        ExprKind::GetAttr { .. } => Err(RestrictedExprError::InvalidRestrictedExpression {
            feature: "attribute accesses".into(),
            expr: expr.clone(),
        }),
        ExprKind::HasAttr { .. } => Err(RestrictedExprError::InvalidRestrictedExpression {
            feature: "'has'".into(),
            expr: expr.clone(),
        }),
        ExprKind::Like { .. } => Err(RestrictedExprError::InvalidRestrictedExpression {
            feature: "'like'".into(),
            expr: expr.clone(),
        }),
        ExprKind::Is { .. } => Err(RestrictedExprError::InvalidRestrictedExpression {
            feature: "'is'".into(),
            expr: expr.clone(),
        }),
        ExprKind::ExtensionFunctionApp { args, .. } => args.iter().try_for_each(is_restricted),
        ExprKind::Set(exprs) => exprs.iter().try_for_each(is_restricted),
        ExprKind::Record(map) => map.values().try_for_each(is_restricted),
    }
}

// converting into Expr is always safe; restricted exprs are always valid Exprs
impl From<RestrictedExpr> for Expr {
    fn from(r: RestrictedExpr) -> Expr {
        r.0
    }
}

impl AsRef<Expr> for RestrictedExpr {
    fn as_ref(&self) -> &Expr {
        &self.0
    }
}

impl Deref for RestrictedExpr {
    type Target = Expr;
    fn deref(&self) -> &Expr {
        self.as_ref()
    }
}

impl std::fmt::Display for RestrictedExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

// converting into Expr is always safe; restricted exprs are always valid Exprs
impl<'a> From<BorrowedRestrictedExpr<'a>> for &'a Expr {
    fn from(r: BorrowedRestrictedExpr<'a>) -> &'a Expr {
        r.0
    }
}

impl<'a> AsRef<Expr> for BorrowedRestrictedExpr<'a> {
    fn as_ref(&self) -> &'a Expr {
        self.0
    }
}

impl RestrictedExpr {
    /// Turn an `&RestrictedExpr` into a `BorrowedRestrictedExpr`
    pub fn as_borrowed(&self) -> BorrowedRestrictedExpr<'_> {
        BorrowedRestrictedExpr::new_unchecked(self.as_ref())
    }
}

impl<'a> Deref for BorrowedRestrictedExpr<'a> {
    type Target = Expr;
    fn deref(&self) -> &'a Expr {
        self.0
    }
}

impl<'a> std::fmt::Display for BorrowedRestrictedExpr<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

/// Like `ExprShapeOnly`, but for restricted expressions.
///
/// A newtype wrapper around (borrowed) restricted expressions that provides
/// `Eq` and `Hash` implementations that ignore any source information or other
/// generic data used to annotate the expression.
#[derive(Eq, Debug, Clone)]
pub struct RestrictedExprShapeOnly<'a>(BorrowedRestrictedExpr<'a>);

impl<'a> RestrictedExprShapeOnly<'a> {
    /// Construct a `RestrictedExprShapeOnly` from a `BorrowedRestrictedExpr`.
    /// The `BorrowedRestrictedExpr` is not modified, but any comparisons on the
    /// resulting `RestrictedExprShapeOnly` will ignore source information and
    /// generic data.
    pub fn new(e: BorrowedRestrictedExpr<'a>) -> RestrictedExprShapeOnly<'a> {
        RestrictedExprShapeOnly(e)
    }
}

impl<'a> PartialEq for RestrictedExprShapeOnly<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_shape(&other.0)
    }
}

impl<'a> Hash for RestrictedExprShapeOnly<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash_shape(state);
    }
}

/// Error when constructing a restricted expression from unrestricted

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RestrictedExprError {
    /// An expression was expected to be a "restricted" expression, but contained
    /// a feature that is not allowed in restricted expressions. The `feature`
    /// argument is a string description of the feature that is not allowed.
    /// The `expr` argument is the expression that uses the disallowed feature.
    /// Note that it is potentially a sub-expression of a larger expression.
    #[error("not allowed to use {feature} in a restricted expression: `{expr}`")]
    InvalidRestrictedExpression {
        /// what disallowed feature appeared in the expression
        feature: SmolStr,
        /// the (sub-)expression that uses the disallowed feature
        expr: Expr,
    },
}

// custom impl of `Diagnostic`: take location info from the embedded subexpression
impl Diagnostic for RestrictedExprError {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        match self {
            Self::InvalidRestrictedExpression { expr, .. } => expr.source_loc().map(|loc| {
                Box::new(std::iter::once(miette::LabeledSpan::underline(loc.span)))
                    as Box<dyn Iterator<Item = _>>
            }),
        }
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        match self {
            Self::InvalidRestrictedExpression { expr, .. } => expr
                .source_loc()
                .map(|loc| &loc.src as &dyn miette::SourceCode),
        }
    }
}

/// Errors possible from `RestrictedExpr::from_str()`
#[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
pub enum RestrictedExprParseError {
    /// Failed to parse the expression entirely
    #[error("failed to parse restricted expression: {0}")]
    #[diagnostic(transparent)]
    Parse(#[from] ParseErrors),
    /// Parsed successfully as an expression, but failed to construct a
    /// restricted expression, for the reason indicated in the underlying error
    #[error(transparent)]
    #[diagnostic(transparent)]
    RestrictedExpr(#[from] RestrictedExprError),
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parser::err::{ParseError, ToASTError, ToASTErrorKind};
    use crate::parser::Loc;
    use std::str::FromStr;
    use std::sync::Arc;

    #[test]
    fn duplicate_key() {
        // duplicate key is an error when mapped to values of different types
        assert_eq!(
            RestrictedExpr::record([
                ("foo".into(), RestrictedExpr::val(37),),
                ("foo".into(), RestrictedExpr::val("hello"),),
            ]),
            Err(ExprConstructionError::DuplicateKeyInRecordLiteral { key: "foo".into() })
        );

        // duplicate key is an error when mapped to different values of same type
        assert_eq!(
            RestrictedExpr::record([
                ("foo".into(), RestrictedExpr::val(37),),
                ("foo".into(), RestrictedExpr::val(101),),
            ]),
            Err(ExprConstructionError::DuplicateKeyInRecordLiteral { key: "foo".into() })
        );

        // duplicate key is an error when mapped to the same value multiple times
        assert_eq!(
            RestrictedExpr::record([
                ("foo".into(), RestrictedExpr::val(37),),
                ("foo".into(), RestrictedExpr::val(37),),
            ]),
            Err(ExprConstructionError::DuplicateKeyInRecordLiteral { key: "foo".into() })
        );

        // duplicate key is an error even when other keys appear in between
        assert_eq!(
            RestrictedExpr::record([
                ("bar".into(), RestrictedExpr::val(-3),),
                ("foo".into(), RestrictedExpr::val(37),),
                ("spam".into(), RestrictedExpr::val("eggs"),),
                ("foo".into(), RestrictedExpr::val(37),),
                ("eggs".into(), RestrictedExpr::val("spam"),),
            ]),
            Err(ExprConstructionError::DuplicateKeyInRecordLiteral { key: "foo".into() })
        );

        // duplicate key is also an error when parsing from string
        let str = r#"{ foo: 37, bar: "hi", foo: 101 }"#;
        assert_eq!(
            RestrictedExpr::from_str(str),
            Err(RestrictedExprParseError::Parse(ParseErrors(vec![
                ParseError::ToAST(ToASTError::new(
                    ToASTErrorKind::DuplicateKeyInRecordLiteral { key: "foo".into() },
                    Loc::new(0..32, Arc::from(str))
                ))
            ]))),
        )
    }
}
