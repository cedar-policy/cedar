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

//! Contains the trait [`ExprBuilder`], defining a generic interface for
//! building different expression data structures (e.g., AST and EST).

use smol_str::SmolStr;

use crate::{
    ast::{
        BinaryOp, EntityType, ExpressionConstructionError, Literal, Name, Pattern, SlotId, UnaryOp,
        Unknown, Var,
    },
    parser::{cst, Loc},
};

#[cfg(feature = "tolerant-ast")]
use crate::parser::err::ParseErrors;

/// Defines a generic interface for building different expression data
/// structures.
#[allow(clippy::wrong_self_convention)]
pub trait ExprBuilder: Clone {
    /// The type of expression constructed by this instance of `ExprBuilder`.
    type Expr: Clone + std::fmt::Display;

    /// Type for extra information stored on nodes of the expression AST. This
    /// can be `()` if no data is stored.
    type Data: Default;

    /// Type for what error we return if we cannot construct an error node
    ///
    ///  By default we fail on errors and this should be a ParseErrors
    ///  But when we run with error parsing enabled, can be Infallible
    #[cfg(feature = "tolerant-ast")]
    type ErrorType;

    /// Construct a new expression builder for an expression that will not carry any data.
    fn new() -> Self
    where
        Self: Sized,
    {
        Self::with_data(Self::Data::default())
    }

    /// Build an expression that failed to parse - can optionally include subexpressions that parsed successfully
    #[cfg(feature = "tolerant-ast")]
    fn error(self, parse_errors: ParseErrors) -> Result<Self::Expr, Self::ErrorType>;

    /// Build an expression storing this information
    fn with_data(data: Self::Data) -> Self;

    /// Build an expression located at `l`, if `l` is Some. An implementation
    /// may ignore this if it cannot store source information.
    fn with_maybe_source_loc(self, l: Option<&Loc>) -> Self;

    /// Build an expression located at `l`. An implementation may ignore this if
    /// it cannot store source information.
    fn with_source_loc(self, l: &Loc) -> Self
    where
        Self: Sized,
    {
        self.with_maybe_source_loc(Some(l))
    }

    /// Extract the location for this builder, if set. Used internally to
    /// provide utilities that construct multiple nodes which should all be
    /// reported as having the same source location.
    fn loc(&self) -> Option<&Loc>;

    /// Extract the data that will be stored on the constructed expression.
    /// Used internally to provide utilities that construct multiple nodes which
    /// will all have the same data.
    fn data(&self) -> &Self::Data;

    /// Create an expression that's just a single `Literal`.
    ///
    /// Note that you can pass this a `Literal`, an `Integer`, a `String`, etc.
    fn val(self, v: impl Into<Literal>) -> Self::Expr;

    /// Create an `Expr` that's just this literal `Var`
    fn var(self, v: Var) -> Self::Expr;

    /// Create an `Unknown` `Expr`
    fn unknown(self, u: Unknown) -> Self::Expr;

    /// Create an `Expr` that's just this `SlotId`
    fn slot(self, s: SlotId) -> Self::Expr;

    /// Create a ternary (if-then-else) `Expr`.
    fn ite(self, test_expr: Self::Expr, then_expr: Self::Expr, else_expr: Self::Expr)
        -> Self::Expr;

    /// Create a 'not' expression.
    fn not(self, e: Self::Expr) -> Self::Expr;

    /// Create a '==' expression
    fn is_eq(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr;

    /// Create an 'and' expression.
    fn and(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr;

    /// Create an 'or' expression.
    fn or(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr;

    /// Create a '<' expression.
    fn less(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr;

    /// Create a '<=' expression.
    fn lesseq(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr;

    /// Create an 'add' expression.
    fn add(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr;

    /// Create a 'sub' expression.
    fn sub(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr;

    /// Create a 'mul' expression.
    fn mul(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr;

    /// Create a 'neg' expression.
    fn neg(self, e: Self::Expr) -> Self::Expr;

    /// Create an 'in' expression. First argument must evaluate to Entity type.
    fn is_in(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr;

    /// Create a 'contains' expression.
    fn contains(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr;

    /// Create a 'contains_all' expression. Arguments must evaluate to Set type
    fn contains_all(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr;

    /// Create an 'contains_any' expression. Arguments must evaluate to Set type
    fn contains_any(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr;

    /// Create an 'is_empty' expression. Argument must evaluate to Set type
    fn is_empty(self, expr: Self::Expr) -> Self::Expr;

    /// Create a 'getTag' expression.
    fn get_tag(self, expr: Self::Expr, tag: Self::Expr) -> Self::Expr;

    /// Create a 'hasTag' expression.
    fn has_tag(self, expr: Self::Expr, tag: Self::Expr) -> Self::Expr;

    /// Create an `Expr` which evaluates to a Set of the given `Expr`s
    fn set(self, exprs: impl IntoIterator<Item = Self::Expr>) -> Self::Expr;

    /// Create an `Expr` which evaluates to a Record with the given (key, value) pairs.
    fn record(
        self,
        pairs: impl IntoIterator<Item = (SmolStr, Self::Expr)>,
    ) -> Result<Self::Expr, ExpressionConstructionError>;

    /// Create an `Expr` which calls the extension function with the given
    /// `Name` on `args`
    fn call_extension_fn(
        self,
        fn_name: Name,
        args: impl IntoIterator<Item = Self::Expr>,
    ) -> Self::Expr;

    /// Create an `Expr` which gets a given attribute of a given `Entity` or record.
    fn get_attr(self, expr: Self::Expr, attr: SmolStr) -> Self::Expr;

    /// Create an `Expr` which tests for the existence of a given
    /// attribute on a given `Entity` or record.
    fn has_attr(self, expr: Self::Expr, attr: SmolStr) -> Self::Expr;

    /// Create a 'like' expression.
    fn like(self, expr: Self::Expr, pattern: Pattern) -> Self::Expr;

    /// Create an 'is' expression.
    fn is_entity_type(self, expr: Self::Expr, entity_type: EntityType) -> Self::Expr;

    /// Create an `_ is _ in _`  expression
    fn is_in_entity_type(
        self,
        e1: Self::Expr,
        entity_type: EntityType,
        e2: Self::Expr,
    ) -> Self::Expr
    where
        Self: Sized,
    {
        self.clone().and(
            self.clone().is_entity_type(e1.clone(), entity_type),
            self.is_in(e1, e2),
        )
    }

    /// Create an application `Expr` which applies the given built-in unary
    /// operator to the given `arg`
    fn unary_app(self, op: impl Into<UnaryOp>, arg: Self::Expr) -> Self::Expr
    where
        Self: Sized,
    {
        match op.into() {
            UnaryOp::Not => self.not(arg),
            UnaryOp::Neg => self.neg(arg),
            UnaryOp::IsEmpty => self.is_empty(arg),
        }
    }

    /// Create an application `Expr` which applies the given built-in binary
    /// operator to `arg1` and `arg2`
    fn binary_app(self, op: impl Into<BinaryOp>, arg1: Self::Expr, arg2: Self::Expr) -> Self::Expr
    where
        Self: Sized,
    {
        match op.into() {
            BinaryOp::Eq => self.is_eq(arg1, arg2),
            BinaryOp::Less => self.less(arg1, arg2),
            BinaryOp::LessEq => self.lesseq(arg1, arg2),
            BinaryOp::Add => self.add(arg1, arg2),
            BinaryOp::Sub => self.sub(arg1, arg2),
            BinaryOp::Mul => self.mul(arg1, arg2),
            BinaryOp::In => self.is_in(arg1, arg2),
            BinaryOp::Contains => self.contains(arg1, arg2),
            BinaryOp::ContainsAll => self.contains_all(arg1, arg2),
            BinaryOp::ContainsAny => self.contains_any(arg1, arg2),
            BinaryOp::GetTag => self.get_tag(arg1, arg2),
            BinaryOp::HasTag => self.has_tag(arg1, arg2),
        }
    }

    /// Create a '!=' expression.
    fn noteq(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr
    where
        Self: Sized,
    {
        self.clone().not(self.is_eq(e1, e2))
    }

    /// Create a '>' expression.
    fn greater(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr
    where
        Self: Sized,
    {
        // e1 > e2 is defined as !(e1 <= e2)
        self.clone().not(self.lesseq(e1, e2))
    }

    /// Create a '>=' expression.
    fn greatereq(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr
    where
        Self: Sized,
    {
        // e1 >= e2 is defined as !(e1 < e2)
        self.clone().not(self.less(e1, e2))
    }

    /// Create an `and` expression that may have more than two subexpressions (A && B && C)
    /// or may have only one subexpression, in which case no `&&` is performed at all.
    /// Arguments must evaluate to Bool type.
    ///
    /// This may create multiple AST `&&` nodes. If it does, all the nodes will have the same
    /// source location and the same `T` data (taken from this builder) unless overridden, e.g.,
    /// with another call to `with_source_loc()`.
    fn and_nary(self, first: Self::Expr, others: impl IntoIterator<Item = Self::Expr>) -> Self::Expr
    where
        Self: Sized,
    {
        others
            .into_iter()
            .fold(first, |acc, next| self.clone().and(acc, next))
    }

    /// Create an `or` expression that may have more than two subexpressions (A || B || C)
    /// or may have only one subexpression, in which case no `||` is performed at all.
    /// Arguments must evaluate to Bool type.
    ///
    /// This may create multiple AST `||` nodes. If it does, all the nodes will have the same
    /// source location and the same `T` data (taken from this builder) unless overridden, e.g.,
    /// with another call to `with_source_loc()`.
    fn or_nary(self, first: Self::Expr, others: impl IntoIterator<Item = Self::Expr>) -> Self::Expr
    where
        Self: Sized,
    {
        others
            .into_iter()
            .fold(first, |acc, next| self.clone().or(acc, next))
    }

    /// Create expression containing addition and subtraction that may have more
    /// than two subexpressions (A + B - C) or may have only one subexpression,
    /// in which case no operations are performed at all.
    fn add_nary(
        self,
        first: Self::Expr,
        other: impl IntoIterator<Item = (cst::AddOp, Self::Expr)>,
    ) -> Self::Expr
    where
        Self: Sized,
    {
        other.into_iter().fold(first, |acc, (op, next)| match op {
            cst::AddOp::Plus => self.clone().add(acc, next),
            cst::AddOp::Minus => self.clone().sub(acc, next),
        })
    }

    /// Create expression containing multiplication that may have more than two
    /// subexpressions (A * B * C) or may have only one subexpression,
    /// in which case no operations are performed at all.
    fn mul_nary(self, first: Self::Expr, other: impl IntoIterator<Item = Self::Expr>) -> Self::Expr
    where
        Self: Sized,
    {
        other
            .into_iter()
            .fold(first, |acc, next| self.clone().mul(acc, next))
    }
}
