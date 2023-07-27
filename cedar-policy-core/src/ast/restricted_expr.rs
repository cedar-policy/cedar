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

use super::{Expr, ExprKind, Literal, Name};
use crate::entities::JsonSerializationError;
use crate::parser;
use crate::parser::err::ParseErrors;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
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

    /// Create a `RestrictedExpr` that's just a single `Literal`.
    ///
    /// Note that you can pass this a `Literal`, an `i64`, a `String`, etc.
    pub fn val(v: impl Into<Literal>) -> Self {
        // All literals are valid restricted-exprs
        Self::new_unchecked(Expr::val(v))
    }

    /// Create a `RestrictedExpr` which evaluates to a Set of the given `RestrictedExpr`s
    pub fn set(exprs: impl IntoIterator<Item = RestrictedExpr>) -> Self {
        // Set expressions are valid restricted-exprs if their elements are; and
        // we know the elements are because we require `RestrictedExpr`s in the
        // parameter
        Self::new_unchecked(Expr::set(exprs.into_iter().map(Into::into)))
    }

    /// Create a `RestrictedExpr` which evaluates to a Record with the given (key, value) pairs.
    pub fn record(pairs: impl IntoIterator<Item = (SmolStr, RestrictedExpr)>) -> Self {
        // Record expressions are valid restricted-exprs if their elements are;
        // and we know the elements are because we require `RestrictedExpr`s in
        // the parameter
        Self::new_unchecked(Expr::record(pairs.into_iter().map(|(k, v)| (k, v.into()))))
    }

    /// Create a `RestrictedExpr` which calls the given extension function
    pub fn call_extension_fn(function_name: Name, args: Vec<RestrictedExpr>) -> Self {
        // Extension-function calls are valid restricted-exprs if their
        // arguments are; and we know the arguments are because we require
        // `RestrictedExpr`s in the parameter
        Self::new_unchecked(Expr::call_extension_fn(
            function_name,
            args.into_iter().map(Into::into).collect(),
        ))
    }
}

impl std::str::FromStr for RestrictedExpr {
    type Err = RestrictedExprError;

    fn from_str(s: &str) -> Result<RestrictedExpr, Self::Err> {
        parser::parse_restrictedexpr(s)
    }
}

/// While `RestrictedExpr` wraps an _owned_ `Expr`, `BorrowedRestrictedExpr`
/// wraps a _borrowed_ `Expr`, with the same invariants.
#[derive(Serialize, Hash, Debug, Clone, PartialEq, Eq)]
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
            crate::entities::JSONValue::from_expr(self)?,
        )?)
    }
}

/// Helper function: does the given `Expr` qualify as a "restricted" expression.
///
/// Returns `Ok(())` if yes, or a `RestrictedExpressionError` if no.
fn is_restricted(expr: &Expr) -> Result<(), RestrictedExprError> {
    match expr.expr_kind() {
        ExprKind::Lit(_) => Ok(()),
        ExprKind::Unknown { .. } => Ok(()),
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
        ExprKind::ExtensionFunctionApp { args, .. } => args.iter().try_for_each(is_restricted),
        ExprKind::Set(exprs) => exprs.iter().try_for_each(is_restricted),
        ExprKind::Record { pairs } => pairs.iter().map(|(_, v)| v).try_for_each(is_restricted),
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
    fn as_ref(&self) -> &Expr {
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
    fn deref(&self) -> &Expr {
        self.as_ref()
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

/// Errors related to restricted expressions
#[derive(Debug, Clone, PartialEq, Error)]
pub enum RestrictedExprError {
    /// An expression was expected to be a "restricted" expression, but contained
    /// a feature that is not allowed in restricted expressions. The `feature`
    /// argument is a string description of the feature that is not allowed.
    /// The `expr` argument is the expression that uses the disallowed feature.
    /// Note that it is potentially a sub-expression of a larger expression.
    #[error("not allowed to use {feature} in a restricted expression: {expr}")]
    InvalidRestrictedExpression {
        /// what disallowed feature appeared in the expression
        feature: SmolStr,
        /// the (sub-)expression that uses the disallowed feature
        expr: Expr,
    },

    /// Failed to parse the expression that the restricted expression wraps.
    #[error("failed to parse restricted expression: {0}")]
    Parse(#[from] ParseErrors),
}
