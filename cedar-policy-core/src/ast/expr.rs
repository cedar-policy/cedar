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

#[cfg(feature = "tolerant-ast")]
use {
    super::expr_allows_errors::AstExprErrorKind, crate::parser::err::ToASTError,
    crate::parser::err::ToASTErrorKind,
};

use crate::{
    ast::*,
    expr_builder::{self, ExprBuilder as _},
    extensions::Extensions,
    parser::{err::ParseErrors, AsLocRef, IntoMaybeLoc, Loc, MaybeLoc},
};
use educe::Educe;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::{
    borrow::Cow,
    collections::{btree_map, BTreeMap, HashMap},
    hash::{Hash, Hasher},
    mem,
    sync::Arc,
};
use thiserror::Error;

#[cfg(feature = "wasm")]
extern crate tsify;

/// Internal AST for expressions used by the policy evaluator.
/// This structure is a wrapper around an `ExprKind`, which is the expression
/// variant this object contains. It also contains source information about
/// where the expression was written in policy source code, and some generic
/// data which is stored on each node of the AST.
/// Cloning is O(1).
#[derive(Educe, Debug, Clone)]
#[educe(PartialEq, Eq, Hash)]
pub struct Expr<T = ()> {
    expr_kind: ExprKind<T>,
    #[educe(PartialEq(ignore))]
    #[educe(Hash(ignore))]
    source_loc: MaybeLoc,
    data: T,
}

/// The possible expression variants. This enum should be matched on by code
/// recursively traversing the AST.
#[derive(Hash, Debug, Clone, PartialEq, Eq)]
pub enum ExprKind<T = ()> {
    /// Literal value
    Lit(Literal),
    /// Variable
    Var(Var),
    /// Template Slots
    Slot(SlotId),
    /// Symbolic Unknown for partial-eval
    Unknown(Unknown),
    /// Ternary expression
    If {
        /// Condition for the ternary expression. Must evaluate to Bool type
        test_expr: Arc<Expr<T>>,
        /// Value if true
        then_expr: Arc<Expr<T>>,
        /// Value if false
        else_expr: Arc<Expr<T>>,
    },
    /// Boolean AND
    And {
        /// Left operand, which will be eagerly evaluated
        left: Arc<Expr<T>>,
        /// Right operand, which may not be evaluated due to short-circuiting
        right: Arc<Expr<T>>,
    },
    /// Boolean OR
    Or {
        /// Left operand, which will be eagerly evaluated
        left: Arc<Expr<T>>,
        /// Right operand, which may not be evaluated due to short-circuiting
        right: Arc<Expr<T>>,
    },
    /// Application of a built-in unary operator (single parameter)
    UnaryApp {
        /// Unary operator to apply
        op: UnaryOp,
        /// Argument to apply operator to
        arg: Arc<Expr<T>>,
    },
    /// Application of a built-in binary operator (two parameters)
    BinaryApp {
        /// Binary operator to apply
        op: BinaryOp,
        /// First arg
        arg1: Arc<Expr<T>>,
        /// Second arg
        arg2: Arc<Expr<T>>,
    },
    /// Application of an extension function to n arguments
    /// INVARIANT (MethodStyleArgs):
    ///   if op.style is MethodStyle then args _cannot_ be empty.
    ///     The first element of args refers to the subject of the method call
    /// Ideally, we find some way to make this non-representable.
    ExtensionFunctionApp {
        /// Extension function to apply
        fn_name: Name,
        /// Args to apply the function to
        args: Arc<Vec<Expr<T>>>,
    },
    /// Get an attribute of an entity, or a field of a record
    GetAttr {
        /// Expression to get an attribute/field of. Must evaluate to either
        /// Entity or Record type
        expr: Arc<Expr<T>>,
        /// Attribute or field to get
        attr: SmolStr,
    },
    /// Does the given `expr` have the given `attr`?
    HasAttr {
        /// Expression to test. Must evaluate to either Entity or Record type
        expr: Arc<Expr<T>>,
        /// Attribute or field to check for
        attr: SmolStr,
    },
    /// Regex-like string matching similar to IAM's `StringLike` operator.
    Like {
        /// Expression to test. Must evaluate to String type
        expr: Arc<Expr<T>>,
        /// Pattern to match on; can include the wildcard *, which matches any string.
        /// To match a literal `*` in the test expression, users can use `\*`.
        /// Be careful the backslash in `\*` must not be another escape sequence. For instance, `\\*` matches a backslash plus an arbitrary string.
        pattern: Pattern,
    },
    /// Entity type test. Does the first argument have the entity type
    /// specified by the second argument.
    Is {
        /// Expression to test. Must evaluate to an Entity.
        expr: Arc<Expr<T>>,
        /// The [`EntityType`] used for the type membership test.
        entity_type: EntityType,
    },
    /// Set (whose elements may be arbitrary expressions)
    //
    // This is backed by `Vec` (and not e.g. `HashSet`), because two `Expr`s
    // that are syntactically unequal, may actually be semantically equal --
    // i.e., we can't do the dedup of duplicates until all of the `Expr`s are
    // evaluated into `Value`s
    Set(Arc<Vec<Expr<T>>>),
    /// Anonymous record (whose elements may be arbitrary expressions)
    Record(Arc<BTreeMap<SmolStr, Expr<T>>>),
    #[cfg(feature = "tolerant-ast")]
    /// Error expression - allows us to continue parsing even when we have errors
    Error {
        /// Type of error that led to the failure
        error_kind: AstExprErrorKind,
    },
}

impl From<Value> for Expr {
    fn from(v: Value) -> Self {
        Expr::from(v.value).with_maybe_source_loc(v.loc)
    }
}

impl From<ValueKind> for Expr {
    fn from(v: ValueKind) -> Self {
        match v {
            ValueKind::Lit(lit) => Expr::val(lit),
            ValueKind::Set(set) => Expr::set(set.iter().map(|v| Expr::from(v.clone()))),
            // PANIC SAFETY: cannot have duplicate key because the input was already a BTreeMap
            #[allow(clippy::expect_used)]
            ValueKind::Record(record) => Expr::record(
                Arc::unwrap_or_clone(record)
                    .into_iter()
                    .map(|(k, v)| (k, Expr::from(v))),
            )
            .expect("cannot have duplicate key because the input was already a BTreeMap"),
            ValueKind::ExtensionValue(ev) => RestrictedExpr::from(ev.as_ref().clone()).into(),
        }
    }
}

impl From<PartialValue> for Expr {
    fn from(pv: PartialValue) -> Self {
        match pv {
            PartialValue::Value(v) => Expr::from(v),
            PartialValue::Residual(expr) => expr,
        }
    }
}

impl<T> Expr<T> {
    pub(crate) fn new(expr_kind: ExprKind<T>, source_loc: MaybeLoc, data: T) -> Self {
        Self {
            expr_kind,
            source_loc,
            data,
        }
    }

    /// Access the inner `ExprKind` for this `Expr`. The `ExprKind` is the
    /// `enum` which specifies the expression variant, so it must be accessed by
    /// any code matching and recursing on an expression.
    pub fn expr_kind(&self) -> &ExprKind<T> {
        &self.expr_kind
    }

    /// Access the inner `ExprKind`, taking ownership and consuming the `Expr`.
    pub fn into_expr_kind(self) -> ExprKind<T> {
        self.expr_kind
    }

    /// Access the data stored on the `Expr`.
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Access the data stored on the `Expr`, taking ownership and consuming the
    /// `Expr`.
    pub fn into_data(self) -> T {
        self.data
    }

    /// Consume the `Expr`, returning the `ExprKind`, `source_loc`, and stored
    /// data.
    pub fn into_parts(self) -> (ExprKind<T>, MaybeLoc, T) {
        (self.expr_kind, self.source_loc, self.data)
    }

    /// Access the `Loc` stored on the `Expr`.
    pub fn source_loc(&self) -> Option<&Loc> {
        self.source_loc.as_loc_ref()
    }

    /// Return the `Expr`, but with the new `source_loc` (or `None`).
    pub fn with_maybe_source_loc(self, source_loc: MaybeLoc) -> Self {
        Self { source_loc, ..self }
    }

    /// Update the data for this `Expr`. A convenient function used by the
    /// Validator in one place.
    pub fn set_data(&mut self, data: T) {
        self.data = data;
    }

    /// Check whether this expression is an entity reference
    ///
    /// This is used for policy scopes, where some syntax is
    /// required to be an entity reference.
    pub fn is_ref(&self) -> bool {
        match &self.expr_kind {
            ExprKind::Lit(lit) => lit.is_ref(),
            _ => false,
        }
    }

    /// Check whether this expression is a slot.
    pub fn is_slot(&self) -> bool {
        matches!(&self.expr_kind, ExprKind::Slot(_))
    }

    /// Check whether this expression is a set of entity references
    ///
    /// This is used for policy scopes, where some syntax is
    /// required to be an entity reference set.
    pub fn is_ref_set(&self) -> bool {
        match &self.expr_kind {
            ExprKind::Set(exprs) => exprs.iter().all(|e| e.is_ref()),
            _ => false,
        }
    }

    /// Iterate over all sub-expressions in this expression
    pub fn subexpressions(&self) -> impl Iterator<Item = &Self> {
        expr_iterator::ExprIterator::new(self)
    }

    /// Iterate over all of the slots in this policy AST
    pub fn slots(&self) -> impl Iterator<Item = Slot> + '_ {
        self.subexpressions()
            .filter_map(|exp| match &exp.expr_kind {
                ExprKind::Slot(slotid) => Some(Slot {
                    id: *slotid,
                    loc: exp.source_loc().into_maybe_loc(),
                }),
                _ => None,
            })
    }

    /// Determine if the expression is projectable under partial evaluation
    /// An expression is projectable if it's guaranteed to never error on evaluation
    /// This is true if the expression is entirely composed of values or unknowns
    pub fn is_projectable(&self) -> bool {
        self.subexpressions().all(|e| {
            matches!(
                e.expr_kind(),
                ExprKind::Lit(_)
                    | ExprKind::Unknown(_)
                    | ExprKind::Set(_)
                    | ExprKind::Var(_)
                    | ExprKind::Record(_)
            )
        })
    }

    /// Try to compute the runtime type of this expression. This operation may
    /// fail (returning `None`), for example, when asked to get the type of any
    /// variables, any attributes of entities or records, or an `unknown`
    /// without an explicitly annotated type.
    ///
    /// Also note that this is _not_ typechecking the expression. It does not
    /// check that the expression actually evaluates to a value (as opposed to
    /// erroring).
    ///
    /// Because of these limitations, this function should only be used to
    /// obtain a type for use in diagnostics such as error strings.
    pub fn try_type_of(&self, extensions: &Extensions<'_>) -> Option<Type> {
        match &self.expr_kind {
            ExprKind::Lit(l) => Some(l.type_of()),
            ExprKind::Var(_) => None,
            ExprKind::Slot(_) => None,
            ExprKind::Unknown(u) => u.type_annotation.clone(),
            ExprKind::If {
                then_expr,
                else_expr,
                ..
            } => {
                let type_of_then = then_expr.try_type_of(extensions);
                let type_of_else = else_expr.try_type_of(extensions);
                if type_of_then == type_of_else {
                    type_of_then
                } else {
                    None
                }
            }
            ExprKind::And { .. } => Some(Type::Bool),
            ExprKind::Or { .. } => Some(Type::Bool),
            ExprKind::UnaryApp {
                op: UnaryOp::Neg, ..
            } => Some(Type::Long),
            ExprKind::UnaryApp {
                op: UnaryOp::Not, ..
            } => Some(Type::Bool),
            ExprKind::UnaryApp {
                op: UnaryOp::IsEmpty,
                ..
            } => Some(Type::Bool),
            ExprKind::BinaryApp {
                op: BinaryOp::Add | BinaryOp::Mul | BinaryOp::Sub,
                ..
            } => Some(Type::Long),
            ExprKind::BinaryApp {
                op:
                    BinaryOp::Contains
                    | BinaryOp::ContainsAll
                    | BinaryOp::ContainsAny
                    | BinaryOp::Eq
                    | BinaryOp::In
                    | BinaryOp::Less
                    | BinaryOp::LessEq,
                ..
            } => Some(Type::Bool),
            ExprKind::BinaryApp {
                op: BinaryOp::HasTag,
                ..
            } => Some(Type::Bool),
            ExprKind::ExtensionFunctionApp { fn_name, .. } => extensions
                .func(fn_name)
                .ok()?
                .return_type()
                .map(|rty| rty.clone().into()),
            // We could try to be more complete here, but we can't do all that
            // much better without evaluating the argument. Even if we know it's
            // a record `Type::Record` tells us nothing about the type of the
            // attribute.
            ExprKind::GetAttr { .. } => None,
            // similarly to `GetAttr`
            ExprKind::BinaryApp {
                op: BinaryOp::GetTag,
                ..
            } => None,
            ExprKind::HasAttr { .. } => Some(Type::Bool),
            ExprKind::Like { .. } => Some(Type::Bool),
            ExprKind::Is { .. } => Some(Type::Bool),
            ExprKind::Set(_) => Some(Type::Set),
            ExprKind::Record(_) => Some(Type::Record),
            #[cfg(feature = "tolerant-ast")]
            ExprKind::Error { .. } => None,
        }
    }

    /// Converts an `Expr<V>` to `B::Expr` using the provided builder.
    ///
    /// Preserves source location information and recursively transforms each expression node.
    /// Note: Data may be cloned if the source expression is retained elsewhere.
    pub fn into_expr<B: expr_builder::ExprBuilder>(self) -> B::Expr
    where
        T: Clone,
    {
        let builder = B::new().with_maybe_source_loc(self.source_loc().as_deref());
        match self.into_expr_kind() {
            ExprKind::Lit(lit) => builder.val(lit),
            ExprKind::Var(var) => builder.var(var),
            ExprKind::Slot(slot) => builder.slot(slot),
            ExprKind::Unknown(u) => builder.unknown(u),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => builder.ite(
                Arc::unwrap_or_clone(test_expr).into_expr::<B>(),
                Arc::unwrap_or_clone(then_expr).into_expr::<B>(),
                Arc::unwrap_or_clone(else_expr).into_expr::<B>(),
            ),
            ExprKind::And { left, right } => builder.and(
                Arc::unwrap_or_clone(left).into_expr::<B>(),
                Arc::unwrap_or_clone(right).into_expr::<B>(),
            ),
            ExprKind::Or { left, right } => builder.or(
                Arc::unwrap_or_clone(left).into_expr::<B>(),
                Arc::unwrap_or_clone(right).into_expr::<B>(),
            ),
            ExprKind::UnaryApp { op, arg } => {
                let arg = Arc::unwrap_or_clone(arg).into_expr::<B>();
                builder.unary_app(op, arg)
            }
            ExprKind::BinaryApp { op, arg1, arg2 } => {
                let arg1 = Arc::unwrap_or_clone(arg1).into_expr::<B>();
                let arg2 = Arc::unwrap_or_clone(arg2).into_expr::<B>();
                builder.binary_app(op, arg1, arg2)
            }
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let args = Arc::unwrap_or_clone(args)
                    .into_iter()
                    .map(|e| e.into_expr::<B>());
                builder.call_extension_fn(fn_name, args)
            }
            ExprKind::GetAttr { expr, attr } => {
                builder.get_attr(Arc::unwrap_or_clone(expr).into_expr::<B>(), attr)
            }
            ExprKind::HasAttr { expr, attr } => {
                builder.has_attr(Arc::unwrap_or_clone(expr).into_expr::<B>(), attr)
            }
            ExprKind::Like { expr, pattern } => {
                builder.like(Arc::unwrap_or_clone(expr).into_expr::<B>(), pattern)
            }
            ExprKind::Is { expr, entity_type } => {
                builder.is_entity_type(Arc::unwrap_or_clone(expr).into_expr::<B>(), entity_type)
            }
            ExprKind::Set(set) => builder.set(
                Arc::unwrap_or_clone(set)
                    .into_iter()
                    .map(|e| e.into_expr::<B>()),
            ),
            // PANIC SAFETY: `map` is a map, so it will not have duplicates keys, so the `record` constructor cannot error.
            #[allow(clippy::unwrap_used)]
            ExprKind::Record(map) => builder
                .record(
                    Arc::unwrap_or_clone(map)
                        .into_iter()
                        .map(|(k, v)| (k, v.into_expr::<B>())),
                )
                .unwrap(),
            #[cfg(feature = "tolerant-ast")]
            // PANIC SAFETY: error type is Infallible so can never happen
            #[allow(clippy::unwrap_used)]
            ExprKind::Error { .. } => builder
                .error(ParseErrors::singleton(ToASTError::new(
                    ToASTErrorKind::ASTErrorNode,
                    Loc::new(0..1, "AST_ERROR_NODE".into()).into_maybe_loc(),
                )))
                .unwrap(),
        }
    }
}

#[allow(dead_code)] // some constructors are currently unused, or used only in tests, but provided for completeness
#[allow(clippy::should_implement_trait)] // the names of arithmetic constructors alias with those of certain trait methods such as `add` of `std::ops::Add`
impl Expr {
    /// Create an `Expr` that's just a single `Literal`.
    ///
    /// Note that you can pass this a `Literal`, an `Integer`, a `String`, etc.
    pub fn val(v: impl Into<Literal>) -> Self {
        ExprBuilder::new().val(v)
    }

    /// Create an `Expr` that's just a single `Unknown`.
    pub fn unknown(u: Unknown) -> Self {
        ExprBuilder::new().unknown(u)
    }

    /// Create an `Expr` that's just this literal `Var`
    pub fn var(v: Var) -> Self {
        ExprBuilder::new().var(v)
    }

    /// Create an `Expr` that's just this `SlotId`
    pub fn slot(s: SlotId) -> Self {
        ExprBuilder::new().slot(s)
    }

    /// Create a ternary (if-then-else) `Expr`.
    ///
    /// `test_expr` must evaluate to a Bool type
    pub fn ite(test_expr: Expr, then_expr: Expr, else_expr: Expr) -> Self {
        ExprBuilder::new().ite(test_expr, then_expr, else_expr)
    }

    /// Create a ternary (if-then-else) `Expr`.
    /// Takes `Arc`s instead of owned `Expr`s.
    /// `test_expr` must evaluate to a Bool type
    pub fn ite_arc(test_expr: Arc<Expr>, then_expr: Arc<Expr>, else_expr: Arc<Expr>) -> Self {
        ExprBuilder::new().ite_arc(test_expr, then_expr, else_expr)
    }

    /// Create a 'not' expression. `e` must evaluate to Bool type
    pub fn not(e: Expr) -> Self {
        ExprBuilder::new().not(e)
    }

    /// Create a '==' expression
    pub fn is_eq(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().is_eq(e1, e2)
    }

    /// Create a '!=' expression
    pub fn noteq(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().noteq(e1, e2)
    }

    /// Create an 'and' expression. Arguments must evaluate to Bool type
    pub fn and(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().and(e1, e2)
    }

    /// Create an 'or' expression. Arguments must evaluate to Bool type
    pub fn or(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().or(e1, e2)
    }

    /// Create a '<' expression. Arguments must evaluate to Long type
    pub fn less(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().less(e1, e2)
    }

    /// Create a '<=' expression. Arguments must evaluate to Long type
    pub fn lesseq(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().lesseq(e1, e2)
    }

    /// Create a '>' expression. Arguments must evaluate to Long type
    pub fn greater(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().greater(e1, e2)
    }

    /// Create a '>=' expression. Arguments must evaluate to Long type
    pub fn greatereq(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().greatereq(e1, e2)
    }

    /// Create an 'add' expression. Arguments must evaluate to Long type
    pub fn add(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().add(e1, e2)
    }

    /// Create a 'sub' expression. Arguments must evaluate to Long type
    pub fn sub(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().sub(e1, e2)
    }

    /// Create a 'mul' expression. Arguments must evaluate to Long type
    pub fn mul(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().mul(e1, e2)
    }

    /// Create a 'neg' expression. `e` must evaluate to Long type.
    pub fn neg(e: Expr) -> Self {
        ExprBuilder::new().neg(e)
    }

    /// Create an 'in' expression. First argument must evaluate to Entity type.
    /// Second argument must evaluate to either Entity type or Set type where
    /// all set elements have Entity type.
    pub fn is_in(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().is_in(e1, e2)
    }

    /// Create a `contains` expression.
    /// First argument must have Set type.
    pub fn contains(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().contains(e1, e2)
    }

    /// Create a `containsAll` expression. Arguments must evaluate to Set type
    pub fn contains_all(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().contains_all(e1, e2)
    }

    /// Create a `containsAny` expression. Arguments must evaluate to Set type
    pub fn contains_any(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().contains_any(e1, e2)
    }

    /// Create a `isEmpty` expression. Argument must evaluate to Set type
    pub fn is_empty(e: Expr) -> Self {
        ExprBuilder::new().is_empty(e)
    }

    /// Create a `getTag` expression.
    /// `expr` must evaluate to Entity type, `tag` must evaluate to String type.
    pub fn get_tag(expr: Expr, tag: Expr) -> Self {
        ExprBuilder::new().get_tag(expr, tag)
    }

    /// Create a `hasTag` expression.
    /// `expr` must evaluate to Entity type, `tag` must evaluate to String type.
    pub fn has_tag(expr: Expr, tag: Expr) -> Self {
        ExprBuilder::new().has_tag(expr, tag)
    }

    /// Create an `Expr` which evaluates to a Set of the given `Expr`s
    pub fn set(exprs: impl IntoIterator<Item = Expr>) -> Self {
        ExprBuilder::new().set(exprs)
    }

    /// Create an `Expr` which evaluates to a Record with the given (key, value) pairs.
    pub fn record(
        pairs: impl IntoIterator<Item = (SmolStr, Expr)>,
    ) -> Result<Self, ExpressionConstructionError> {
        ExprBuilder::new().record(pairs)
    }

    /// Create an `Expr` which evaluates to a Record with the given key-value mapping.
    ///
    /// If you have an iterator of pairs, generally prefer calling
    /// `Expr::record()` instead of `.collect()`-ing yourself and calling this,
    /// potentially for efficiency reasons but also because `Expr::record()`
    /// will properly handle duplicate keys but your own `.collect()` will not
    /// (by default).
    pub fn record_arc(map: Arc<BTreeMap<SmolStr, Expr>>) -> Self {
        ExprBuilder::new().record_arc(map)
    }

    /// Create an `Expr` which calls the extension function with the given
    /// `Name` on `args`
    pub fn call_extension_fn(fn_name: Name, args: Vec<Expr>) -> Self {
        ExprBuilder::new().call_extension_fn(fn_name, args)
    }

    /// Create an application `Expr` which applies the given built-in unary
    /// operator to the given `arg`
    pub fn unary_app(op: impl Into<UnaryOp>, arg: Expr) -> Self {
        ExprBuilder::new().unary_app(op, arg)
    }

    /// Create an application `Expr` which applies the given built-in binary
    /// operator to `arg1` and `arg2`
    pub fn binary_app(op: impl Into<BinaryOp>, arg1: Expr, arg2: Expr) -> Self {
        ExprBuilder::new().binary_app(op, arg1, arg2)
    }

    /// Create an `Expr` which gets a given attribute of a given `Entity` or record.
    ///
    /// `expr` must evaluate to either Entity or Record type
    pub fn get_attr(expr: Expr, attr: SmolStr) -> Self {
        ExprBuilder::new().get_attr(expr, attr)
    }

    /// Create an `Expr` which tests for the existence of a given
    /// attribute on a given `Entity` or record.
    ///
    /// `expr` must evaluate to either Entity or Record type
    pub fn has_attr(expr: Expr, attr: SmolStr) -> Self {
        ExprBuilder::new().has_attr(expr, attr)
    }

    /// Create a 'like' expression.
    ///
    /// `expr` must evaluate to a String type
    pub fn like(expr: Expr, pattern: Pattern) -> Self {
        ExprBuilder::new().like(expr, pattern)
    }

    /// Create an `is` expression.
    pub fn is_entity_type(expr: Expr, entity_type: EntityType) -> Self {
        ExprBuilder::new().is_entity_type(expr, entity_type)
    }

    /// Check if an expression contains any symbolic unknowns
    pub fn contains_unknown(&self) -> bool {
        self.subexpressions()
            .any(|e| matches!(e.expr_kind(), ExprKind::Unknown(_)))
    }

    /// Get all unknowns in an expression
    pub fn unknowns(&self) -> impl Iterator<Item = &Unknown> {
        self.subexpressions()
            .filter_map(|subexpr| match subexpr.expr_kind() {
                ExprKind::Unknown(u) => Some(u),
                _ => None,
            })
    }

    /// Substitute unknowns with concrete values.
    ///
    /// Ignores unmapped unknowns.
    /// Ignores type annotations on unknowns.
    /// Note that there might be "undiscovered unknowns" in the Expr, which
    /// this function does not notice if evaluation of this Expr did not
    /// traverse all entities and attributes during evaluation, leading to
    /// this function only substituting one unknown at a time.
    pub fn substitute(&self, definitions: &HashMap<SmolStr, Value>) -> Expr {
        match self.substitute_general::<UntypedSubstitution>(definitions) {
            Ok(e) => e,
            Err(empty) => match empty {},
        }
    }

    /// Substitute unknowns with concrete values.
    ///
    /// Ignores unmapped unknowns.
    /// Errors if the substituted value does not match the type annotation on the unknown.
    /// Note that there might be "undiscovered unknowns" in the Expr, which
    /// this function does not notice if evaluation of this Expr did not
    /// traverse all entities and attributes during evaluation, leading to
    /// this function only substituting one unknown at a time.
    pub fn substitute_typed(
        &self,
        definitions: &HashMap<SmolStr, Value>,
    ) -> Result<Expr, SubstitutionError> {
        self.substitute_general::<TypedSubstitution>(definitions)
    }

    /// Substitute unknowns with values
    ///
    /// Generic over the function implementing the substitution to allow for multiple error behaviors
    fn substitute_general<T: SubstitutionFunction>(
        &self,
        definitions: &HashMap<SmolStr, Value>,
    ) -> Result<Expr, T::Err> {
        match self.expr_kind() {
            ExprKind::Lit(_) => Ok(self.clone()),
            ExprKind::Unknown(u @ Unknown { name, .. }) => T::substitute(u, definitions.get(name)),
            ExprKind::Var(_) => Ok(self.clone()),
            ExprKind::Slot(_) => Ok(self.clone()),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => Ok(Expr::ite(
                test_expr.substitute_general::<T>(definitions)?,
                then_expr.substitute_general::<T>(definitions)?,
                else_expr.substitute_general::<T>(definitions)?,
            )),
            ExprKind::And { left, right } => Ok(Expr::and(
                left.substitute_general::<T>(definitions)?,
                right.substitute_general::<T>(definitions)?,
            )),
            ExprKind::Or { left, right } => Ok(Expr::or(
                left.substitute_general::<T>(definitions)?,
                right.substitute_general::<T>(definitions)?,
            )),
            ExprKind::UnaryApp { op, arg } => Ok(Expr::unary_app(
                *op,
                arg.substitute_general::<T>(definitions)?,
            )),
            ExprKind::BinaryApp { op, arg1, arg2 } => Ok(Expr::binary_app(
                *op,
                arg1.substitute_general::<T>(definitions)?,
                arg2.substitute_general::<T>(definitions)?,
            )),
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let args = args
                    .iter()
                    .map(|e| e.substitute_general::<T>(definitions))
                    .collect::<Result<Vec<Expr>, _>>()?;

                Ok(Expr::call_extension_fn(fn_name.clone(), args))
            }
            ExprKind::GetAttr { expr, attr } => Ok(Expr::get_attr(
                expr.substitute_general::<T>(definitions)?,
                attr.clone(),
            )),
            ExprKind::HasAttr { expr, attr } => Ok(Expr::has_attr(
                expr.substitute_general::<T>(definitions)?,
                attr.clone(),
            )),
            ExprKind::Like { expr, pattern } => Ok(Expr::like(
                expr.substitute_general::<T>(definitions)?,
                pattern.clone(),
            )),
            ExprKind::Set(members) => {
                let members = members
                    .iter()
                    .map(|e| e.substitute_general::<T>(definitions))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Expr::set(members))
            }
            ExprKind::Record(map) => {
                let map = map
                    .iter()
                    .map(|(name, e)| Ok((name.clone(), e.substitute_general::<T>(definitions)?)))
                    .collect::<Result<BTreeMap<_, _>, _>>()?;
                // PANIC SAFETY: cannot have a duplicate key because the input was already a BTreeMap
                #[allow(clippy::expect_used)]
                Ok(Expr::record(map)
                    .expect("cannot have a duplicate key because the input was already a BTreeMap"))
            }
            ExprKind::Is { expr, entity_type } => Ok(Expr::is_entity_type(
                expr.substitute_general::<T>(definitions)?,
                entity_type.clone(),
            )),
            #[cfg(feature = "tolerant-ast")]
            ExprKind::Error { .. } => Ok(self.clone()),
        }
    }
}

/// A trait for customizing the error behavior of substitution
trait SubstitutionFunction {
    /// The potential errors this substitution function can return
    type Err;
    /// The function for implementing the substitution.
    ///
    /// Takes the expression being substituted,
    /// The substitution from the map (if present)
    /// and the type annotation from the unknown (if present)
    fn substitute(value: &Unknown, substitute: Option<&Value>) -> Result<Expr, Self::Err>;
}

struct TypedSubstitution {}

impl SubstitutionFunction for TypedSubstitution {
    type Err = SubstitutionError;

    fn substitute(value: &Unknown, substitute: Option<&Value>) -> Result<Expr, Self::Err> {
        match (substitute, &value.type_annotation) {
            (None, _) => Ok(Expr::unknown(value.clone())),
            (Some(v), None) => Ok(v.clone().into()),
            (Some(v), Some(t)) => {
                if v.type_of() == *t {
                    Ok(v.clone().into())
                } else {
                    Err(SubstitutionError::TypeError {
                        expected: t.clone(),
                        actual: v.type_of(),
                    })
                }
            }
        }
    }
}

struct UntypedSubstitution {}

impl SubstitutionFunction for UntypedSubstitution {
    type Err = std::convert::Infallible;

    fn substitute(value: &Unknown, substitute: Option<&Value>) -> Result<Expr, Self::Err> {
        Ok(substitute
            .map(|v| v.clone().into())
            .unwrap_or_else(|| Expr::unknown(value.clone())))
    }
}

impl<T: Clone> std::fmt::Display for Expr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // To avoid code duplication between pretty-printers for AST Expr and EST Expr,
        // we just convert to EST and use the EST pretty-printer.
        // Note that converting AST->EST is lossless and infallible.
        write!(f, "{}", &self.clone().into_expr::<crate::est::Builder>())
    }
}

impl<T: Clone> BoundedDisplay for Expr<T> {
    fn fmt(&self, f: &mut impl std::fmt::Write, n: Option<usize>) -> std::fmt::Result {
        // Like the `std::fmt::Display` impl, we convert to EST and use the EST
        // pretty-printer. Note that converting AST->EST is lossless and infallible.
        BoundedDisplay::fmt(&self.clone().into_expr::<crate::est::Builder>(), f, n)
    }
}

impl std::str::FromStr for Expr {
    type Err = ParseErrors;

    fn from_str(s: &str) -> Result<Expr, Self::Err> {
        crate::parser::parse_expr(s)
    }
}

/// Enum for errors encountered during substitution
#[derive(Debug, Clone, Diagnostic, Error)]
pub enum SubstitutionError {
    /// The supplied value did not match the type annotation on the unknown.
    #[error("expected a value of type {expected}, got a value of type {actual}")]
    TypeError {
        /// The expected type, ie: the type the unknown was annotated with
        expected: Type,
        /// The type of the provided value
        actual: Type,
    },
}

/// Representation of a partial-evaluation Unknown at the AST level
#[derive(Hash, Debug, Clone, PartialEq, Eq)]
pub struct Unknown {
    /// The name of the unknown
    pub name: SmolStr,
    /// The type of the values that can be substituted in for the unknown.
    /// If `None`, we have no type annotation, and thus a value of any type can
    /// be substituted.
    pub type_annotation: Option<Type>,
}

impl Unknown {
    /// Create a new untyped `Unknown`
    pub fn new_untyped(name: impl Into<SmolStr>) -> Self {
        Self {
            name: name.into(),
            type_annotation: None,
        }
    }

    /// Create a new `Unknown` with type annotation. (Only values of the given
    /// type can be substituted.)
    pub fn new_with_type(name: impl Into<SmolStr>, ty: Type) -> Self {
        Self {
            name: name.into(),
            type_annotation: Some(ty),
        }
    }
}

impl std::fmt::Display for Unknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Like the Display impl for Expr, we delegate to the EST pretty-printer,
        // to avoid code duplication
        write!(
            f,
            "{}",
            Expr::unknown(self.clone()).into_expr::<crate::est::Builder>()
        )
    }
}

/// Builder for constructing `Expr` objects annotated with some `data`
/// (possibly taking default value) and optionally a `source_loc`.
#[derive(Clone, Debug)]
pub struct ExprBuilder<T> {
    source_loc: MaybeLoc,
    data: T,
}

impl<T: Default + Clone> expr_builder::ExprBuilder for ExprBuilder<T> {
    type Expr = Expr<T>;

    type Data = T;

    #[cfg(feature = "tolerant-ast")]
    type ErrorType = ParseErrors;

    fn loc(&self) -> Option<&Loc> {
        self.source_loc.as_loc_ref()
    }

    fn data(&self) -> &Self::Data {
        &self.data
    }

    fn with_data(data: T) -> Self {
        Self {
            source_loc: None,
            data,
        }
    }

    fn with_maybe_source_loc(mut self, maybe_source_loc: Option<&Loc>) -> Self {
        self.source_loc = maybe_source_loc.into_maybe_loc();
        self
    }

    /// Create an `Expr` that's just a single `Literal`.
    ///
    /// Note that you can pass this a `Literal`, an `Integer`, a `String`, etc.
    fn val(self, v: impl Into<Literal>) -> Expr<T> {
        self.with_expr_kind(ExprKind::Lit(v.into()))
    }

    /// Create an `Unknown` `Expr`
    fn unknown(self, u: Unknown) -> Expr<T> {
        self.with_expr_kind(ExprKind::Unknown(u))
    }

    /// Create an `Expr` that's just this literal `Var`
    fn var(self, v: Var) -> Expr<T> {
        self.with_expr_kind(ExprKind::Var(v))
    }

    /// Create an `Expr` that's just this `SlotId`
    fn slot(self, s: SlotId) -> Expr<T> {
        self.with_expr_kind(ExprKind::Slot(s))
    }

    /// Create a ternary (if-then-else) `Expr`.
    ///
    /// `test_expr` must evaluate to a Bool type
    fn ite(self, test_expr: Expr<T>, then_expr: Expr<T>, else_expr: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::If {
            test_expr: Arc::new(test_expr),
            then_expr: Arc::new(then_expr),
            else_expr: Arc::new(else_expr),
        })
    }

    /// Create a 'not' expression. `e` must evaluate to Bool type
    fn not(self, e: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::UnaryApp {
            op: UnaryOp::Not,
            arg: Arc::new(e),
        })
    }

    /// Create a '==' expression
    fn is_eq(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::Eq,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create an 'and' expression. Arguments must evaluate to Bool type
    fn and(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(match (&e1.expr_kind, &e2.expr_kind) {
            (ExprKind::Lit(Literal::Bool(b1)), ExprKind::Lit(Literal::Bool(b2))) => {
                ExprKind::Lit(Literal::Bool(*b1 && *b2))
            }
            _ => ExprKind::And {
                left: Arc::new(e1),
                right: Arc::new(e2),
            },
        })
    }

    /// Create an 'or' expression. Arguments must evaluate to Bool type
    fn or(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(match (&e1.expr_kind, &e2.expr_kind) {
            (ExprKind::Lit(Literal::Bool(b1)), ExprKind::Lit(Literal::Bool(b2))) => {
                ExprKind::Lit(Literal::Bool(*b1 || *b2))
            }

            _ => ExprKind::Or {
                left: Arc::new(e1),
                right: Arc::new(e2),
            },
        })
    }

    /// Create a '<' expression. Arguments must evaluate to Long type
    fn less(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::Less,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create a '<=' expression. Arguments must evaluate to Long type
    fn lesseq(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::LessEq,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create an 'add' expression. Arguments must evaluate to Long type
    fn add(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::Add,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create a 'sub' expression. Arguments must evaluate to Long type
    fn sub(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::Sub,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create a 'mul' expression. Arguments must evaluate to Long type
    fn mul(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::Mul,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create a 'neg' expression. `e` must evaluate to Long type.
    fn neg(self, e: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::UnaryApp {
            op: UnaryOp::Neg,
            arg: Arc::new(e),
        })
    }

    /// Create an 'in' expression. First argument must evaluate to Entity type.
    /// Second argument must evaluate to either Entity type or Set type where
    /// all set elements have Entity type.
    fn is_in(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::In,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create a 'contains' expression.
    /// First argument must have Set type.
    fn contains(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::Contains,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create a 'contains_all' expression. Arguments must evaluate to Set type
    fn contains_all(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::ContainsAll,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create an 'contains_any' expression. Arguments must evaluate to Set type
    fn contains_any(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::ContainsAny,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create an 'is_empty' expression. Argument must evaluate to Set type
    fn is_empty(self, expr: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::UnaryApp {
            op: UnaryOp::IsEmpty,
            arg: Arc::new(expr),
        })
    }

    /// Create a 'getTag' expression.
    /// `expr` must evaluate to Entity type, `tag` must evaluate to String type.
    fn get_tag(self, expr: Expr<T>, tag: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::GetTag,
            arg1: Arc::new(expr),
            arg2: Arc::new(tag),
        })
    }

    /// Create a 'hasTag' expression.
    /// `expr` must evaluate to Entity type, `tag` must evaluate to String type.
    fn has_tag(self, expr: Expr<T>, tag: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::HasTag,
            arg1: Arc::new(expr),
            arg2: Arc::new(tag),
        })
    }

    /// Create an `Expr` which evaluates to a Set of the given `Expr`s
    fn set(self, exprs: impl IntoIterator<Item = Expr<T>>) -> Expr<T> {
        self.with_expr_kind(ExprKind::Set(Arc::new(exprs.into_iter().collect())))
    }

    /// Create an `Expr` which evaluates to a Record with the given (key, value) pairs.
    fn record(
        self,
        pairs: impl IntoIterator<Item = (SmolStr, Expr<T>)>,
    ) -> Result<Expr<T>, ExpressionConstructionError> {
        let mut map = BTreeMap::new();
        for (k, v) in pairs {
            match map.entry(k) {
                btree_map::Entry::Occupied(oentry) => {
                    return Err(expression_construction_errors::DuplicateKeyError {
                        key: oentry.key().clone(),
                        context: "in record literal",
                    }
                    .into());
                }
                btree_map::Entry::Vacant(ventry) => {
                    ventry.insert(v);
                }
            }
        }
        Ok(self.with_expr_kind(ExprKind::Record(Arc::new(map))))
    }

    /// Create an `Expr` which calls the extension function with the given
    /// `Name` on `args`
    fn call_extension_fn(self, fn_name: Name, args: impl IntoIterator<Item = Expr<T>>) -> Expr<T> {
        self.with_expr_kind(ExprKind::ExtensionFunctionApp {
            fn_name,
            args: Arc::new(args.into_iter().collect()),
        })
    }

    /// Create an application `Expr` which applies the given built-in unary
    /// operator to the given `arg`
    fn unary_app(self, op: impl Into<UnaryOp>, arg: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::UnaryApp {
            op: op.into(),
            arg: Arc::new(arg),
        })
    }

    /// Create an application `Expr` which applies the given built-in binary
    /// operator to `arg1` and `arg2`
    fn binary_app(self, op: impl Into<BinaryOp>, arg1: Expr<T>, arg2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: op.into(),
            arg1: Arc::new(arg1),
            arg2: Arc::new(arg2),
        })
    }

    /// Create an `Expr` which gets a given attribute of a given `Entity` or record.
    ///
    /// `expr` must evaluate to either Entity or Record type
    fn get_attr(self, expr: Expr<T>, attr: SmolStr) -> Expr<T> {
        self.with_expr_kind(ExprKind::GetAttr {
            expr: Arc::new(expr),
            attr,
        })
    }

    /// Create an `Expr` which tests for the existence of a given
    /// attribute on a given `Entity` or record.
    ///
    /// `expr` must evaluate to either Entity or Record type
    fn has_attr(self, expr: Expr<T>, attr: SmolStr) -> Expr<T> {
        self.with_expr_kind(ExprKind::HasAttr {
            expr: Arc::new(expr),
            attr,
        })
    }

    /// Create a 'like' expression.
    ///
    /// `expr` must evaluate to a String type
    fn like(self, expr: Expr<T>, pattern: Pattern) -> Expr<T> {
        self.with_expr_kind(ExprKind::Like {
            expr: Arc::new(expr),
            pattern,
        })
    }

    /// Create an 'is' expression.
    fn is_entity_type(self, expr: Expr<T>, entity_type: EntityType) -> Expr<T> {
        self.with_expr_kind(ExprKind::Is {
            expr: Arc::new(expr),
            entity_type,
        })
    }

    /// Don't support AST Error nodes - return the error right back
    #[cfg(feature = "tolerant-ast")]
    fn error(self, parse_errors: ParseErrors) -> Result<Self::Expr, Self::ErrorType> {
        Err(parse_errors)
    }
}

impl<T> ExprBuilder<T> {
    /// Construct an `Expr` containing the `data` and `source_loc` in this
    /// `ExprBuilder` and the given `ExprKind`.
    pub fn with_expr_kind(self, expr_kind: ExprKind<T>) -> Expr<T> {
        Expr::new(expr_kind, self.source_loc, self.data)
    }

    /// Create a ternary (if-then-else) `Expr`.
    /// Takes `Arc`s instead of owned `Expr`s.
    /// `test_expr` must evaluate to a Bool type
    pub fn ite_arc(
        self,
        test_expr: Arc<Expr<T>>,
        then_expr: Arc<Expr<T>>,
        else_expr: Arc<Expr<T>>,
    ) -> Expr<T> {
        self.with_expr_kind(ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        })
    }

    /// Create an `Expr` which evaluates to a Record with the given key-value mapping.
    ///
    /// If you have an iterator of pairs, generally prefer calling `.record()`
    /// instead of `.collect()`-ing yourself and calling this, potentially for
    /// efficiency reasons but also because `.record()` will properly handle
    /// duplicate keys but your own `.collect()` will not (by default).
    pub fn record_arc(self, map: Arc<BTreeMap<SmolStr, Expr<T>>>) -> Expr<T> {
        self.with_expr_kind(ExprKind::Record(map))
    }
}

impl<T: Clone + Default> ExprBuilder<T> {
    /// Utility used the validator to get an expression with the same source
    /// location as an existing expression. This is done when reconstructing the
    /// `Expr` with type information.
    pub fn with_same_source_loc<U>(self, expr: &Expr<U>) -> Self {
        self.with_maybe_source_loc(expr.source_loc.as_loc_ref())
    }
}

/// Errors when constructing an expression
//
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, PartialEq, Eq, Clone, Diagnostic, Error)]
pub enum ExpressionConstructionError {
    /// The same key occurred two or more times
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateKey(#[from] expression_construction_errors::DuplicateKeyError),
}

/// Error subtypes for [`ExpressionConstructionError`]
pub mod expression_construction_errors {
    use miette::Diagnostic;
    use smol_str::SmolStr;
    use thiserror::Error;

    /// The same key occurred two or more times
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Diagnostic, Error)]
    #[error("duplicate key `{key}` {context}")]
    pub struct DuplicateKeyError {
        /// The key which occurred two or more times
        pub(crate) key: SmolStr,
        /// Information about where the duplicate key occurred (e.g., "in record literal")
        pub(crate) context: &'static str,
    }

    impl DuplicateKeyError {
        /// Get the key which occurred two or more times
        pub fn key(&self) -> &str {
            &self.key
        }

        /// Make a new error with an updated `context` field
        pub(crate) fn with_context(self, context: &'static str) -> Self {
            Self { context, ..self }
        }
    }
}

/// A new type wrapper around `Expr` that provides `Eq` and `Hash`
/// implementations that ignore any source information or other generic data
/// used to annotate the `Expr`.
#[derive(Eq, Debug, Clone)]
pub struct ExprShapeOnly<'a, T: Clone = ()>(Cow<'a, Expr<T>>);

impl<'a, T: Clone> ExprShapeOnly<'a, T> {
    /// Construct an `ExprShapeOnly` from a borrowed `Expr`. The `Expr` is not
    /// modified, but any comparisons on the resulting `ExprShapeOnly` will
    /// ignore source information and generic data.
    pub fn new_from_borrowed(e: &'a Expr<T>) -> ExprShapeOnly<'a, T> {
        ExprShapeOnly(Cow::Borrowed(e))
    }

    /// Construct an `ExprShapeOnly` from an owned `Expr`. The `Expr` is not
    /// modified, but any comparisons on the resulting `ExprShapeOnly` will
    /// ignore source information and generic data.
    pub fn new_from_owned(e: Expr<T>) -> ExprShapeOnly<'a, T> {
        ExprShapeOnly(Cow::Owned(e))
    }
}

impl<T: Clone> PartialEq for ExprShapeOnly<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_shape(&other.0)
    }
}

impl<T: Clone> Hash for ExprShapeOnly<'_, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash_shape(state);
    }
}

impl<T> Expr<T> {
    /// Return true if this expression (recursively) has the same expression
    /// kind as the argument expression. This accounts for the full recursive
    /// shape of the expression, but does not consider source information or any
    /// generic data annotated on expression. This should behave the same as the
    /// default implementation of `Eq` before source information and generic
    /// data were added.
    pub fn eq_shape<U>(&self, other: &Expr<U>) -> bool {
        use ExprKind::*;
        match (self.expr_kind(), other.expr_kind()) {
            (Lit(lit), Lit(lit1)) => lit == lit1,
            (Var(v), Var(v1)) => v == v1,
            (Slot(s), Slot(s1)) => s == s1,
            (
                Unknown(self::Unknown {
                    name: name1,
                    type_annotation: ta_1,
                }),
                Unknown(self::Unknown {
                    name: name2,
                    type_annotation: ta_2,
                }),
            ) => (name1 == name2) && (ta_1 == ta_2),
            (
                If {
                    test_expr,
                    then_expr,
                    else_expr,
                },
                If {
                    test_expr: test_expr1,
                    then_expr: then_expr1,
                    else_expr: else_expr1,
                },
            ) => {
                test_expr.eq_shape(test_expr1)
                    && then_expr.eq_shape(then_expr1)
                    && else_expr.eq_shape(else_expr1)
            }
            (
                And { left, right },
                And {
                    left: left1,
                    right: right1,
                },
            )
            | (
                Or { left, right },
                Or {
                    left: left1,
                    right: right1,
                },
            ) => left.eq_shape(left1) && right.eq_shape(right1),
            (UnaryApp { op, arg }, UnaryApp { op: op1, arg: arg1 }) => {
                op == op1 && arg.eq_shape(arg1)
            }
            (
                BinaryApp { op, arg1, arg2 },
                BinaryApp {
                    op: op1,
                    arg1: arg11,
                    arg2: arg21,
                },
            ) => op == op1 && arg1.eq_shape(arg11) && arg2.eq_shape(arg21),
            (
                ExtensionFunctionApp { fn_name, args },
                ExtensionFunctionApp {
                    fn_name: fn_name1,
                    args: args1,
                },
            ) => {
                fn_name == fn_name1
                    && args.len() == args1.len()
                    && args.iter().zip(args1.iter()).all(|(a, a1)| a.eq_shape(a1))
            }
            (
                GetAttr { expr, attr },
                GetAttr {
                    expr: expr1,
                    attr: attr1,
                },
            )
            | (
                HasAttr { expr, attr },
                HasAttr {
                    expr: expr1,
                    attr: attr1,
                },
            ) => attr == attr1 && expr.eq_shape(expr1),
            (
                Like { expr, pattern },
                Like {
                    expr: expr1,
                    pattern: pattern1,
                },
            ) => pattern == pattern1 && expr.eq_shape(expr1),
            (Set(elems), Set(elems1)) => {
                elems.len() == elems1.len()
                    && elems
                        .iter()
                        .zip(elems1.iter())
                        .all(|(e, e1)| e.eq_shape(e1))
            }
            (Record(map), Record(map1)) => {
                map.len() == map1.len()
                    && map
                        .iter()
                        .zip(map1.iter()) // relying on BTreeMap producing an iterator sorted by key
                        .all(|((a, e), (a1, e1))| a == a1 && e.eq_shape(e1))
            }
            (
                Is { expr, entity_type },
                Is {
                    expr: expr1,
                    entity_type: entity_type1,
                },
            ) => entity_type == entity_type1 && expr.eq_shape(expr1),
            _ => false,
        }
    }

    /// Implementation of hashing corresponding to equality as implemented by
    /// `eq_shape`. Must satisfy the usual relationship between equality and
    /// hashing.
    pub fn hash_shape<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        mem::discriminant(self).hash(state);
        match self.expr_kind() {
            ExprKind::Lit(lit) => lit.hash(state),
            ExprKind::Var(v) => v.hash(state),
            ExprKind::Slot(s) => s.hash(state),
            ExprKind::Unknown(u) => u.hash(state),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                test_expr.hash_shape(state);
                then_expr.hash_shape(state);
                else_expr.hash_shape(state);
            }
            ExprKind::And { left, right } => {
                left.hash_shape(state);
                right.hash_shape(state);
            }
            ExprKind::Or { left, right } => {
                left.hash_shape(state);
                right.hash_shape(state);
            }
            ExprKind::UnaryApp { op, arg } => {
                op.hash(state);
                arg.hash_shape(state);
            }
            ExprKind::BinaryApp { op, arg1, arg2 } => {
                op.hash(state);
                arg1.hash_shape(state);
                arg2.hash_shape(state);
            }
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                fn_name.hash(state);
                state.write_usize(args.len());
                args.iter().for_each(|a| {
                    a.hash_shape(state);
                });
            }
            ExprKind::GetAttr { expr, attr } => {
                expr.hash_shape(state);
                attr.hash(state);
            }
            ExprKind::HasAttr { expr, attr } => {
                expr.hash_shape(state);
                attr.hash(state);
            }
            ExprKind::Like { expr, pattern } => {
                expr.hash_shape(state);
                pattern.hash(state);
            }
            ExprKind::Set(elems) => {
                state.write_usize(elems.len());
                elems.iter().for_each(|e| {
                    e.hash_shape(state);
                })
            }
            ExprKind::Record(map) => {
                state.write_usize(map.len());
                map.iter().for_each(|(s, a)| {
                    s.hash(state);
                    a.hash_shape(state);
                });
            }
            ExprKind::Is { expr, entity_type } => {
                expr.hash_shape(state);
                entity_type.hash(state);
            }
            #[cfg(feature = "tolerant-ast")]
            ExprKind::Error { error_kind, .. } => error_kind.hash(state),
        }
    }
}

/// AST variables
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum Var {
    /// the Principal of the given request
    Principal,
    /// the Action of the given request
    Action,
    /// the Resource of the given request
    Resource,
    /// the Context of the given request
    Context,
}

impl From<PrincipalOrResource> for Var {
    fn from(v: PrincipalOrResource) -> Self {
        match v {
            PrincipalOrResource::Principal => Var::Principal,
            PrincipalOrResource::Resource => Var::Resource,
        }
    }
}

// PANIC SAFETY Tested by `test::all_vars_are_ids`. Never panics.
#[allow(clippy::fallible_impl_from)]
impl From<Var> for Id {
    fn from(var: Var) -> Self {
        // PANIC SAFETY: `Var` is a simple enum and all vars are formatted as valid `Id`. Tested by `test::all_vars_are_ids`
        #[allow(clippy::unwrap_used)]
        format!("{var}").parse().unwrap()
    }
}

// PANIC SAFETY Tested by `test::all_vars_are_ids`. Never panics.
#[allow(clippy::fallible_impl_from)]
impl From<Var> for UnreservedId {
    fn from(var: Var) -> Self {
        // PANIC SAFETY: `Var` is a simple enum and all vars are formatted as valid `UnreservedId`. Tested by `test::all_vars_are_ids`
        #[allow(clippy::unwrap_used)]
        Id::from(var).try_into().unwrap()
    }
}

impl std::fmt::Display for Var {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Principal => write!(f, "principal"),
            Self::Action => write!(f, "action"),
            Self::Resource => write!(f, "resource"),
            Self::Context => write!(f, "context"),
        }
    }
}

#[cfg(test)]
mod test {
    use cool_asserts::assert_matches;
    use itertools::Itertools;
    use smol_str::ToSmolStr;
    use std::collections::{hash_map::DefaultHasher, HashSet};

    use crate::expr_builder::ExprBuilder as _;

    use super::*;

    pub fn all_vars() -> impl Iterator<Item = Var> {
        [Var::Principal, Var::Action, Var::Resource, Var::Context].into_iter()
    }

    // Tests that Var::Into never panics
    #[test]
    fn all_vars_are_ids() {
        for var in all_vars() {
            let _id: Id = var.into();
            let _id: UnreservedId = var.into();
        }
    }

    #[test]
    fn exprs() {
        assert_eq!(
            Expr::val(33),
            Expr::new(ExprKind::Lit(Literal::Long(33)), None, ())
        );
        assert_eq!(
            Expr::val("hello"),
            Expr::new(ExprKind::Lit(Literal::from("hello")), None, ())
        );
        assert_eq!(
            Expr::val(EntityUID::with_eid("foo")),
            Expr::new(
                ExprKind::Lit(Literal::from(EntityUID::with_eid("foo"))),
                None,
                ()
            )
        );
        assert_eq!(
            Expr::var(Var::Principal),
            Expr::new(ExprKind::Var(Var::Principal), None, ())
        );
        assert_eq!(
            Expr::ite(Expr::val(true), Expr::val(88), Expr::val(-100)),
            Expr::new(
                ExprKind::If {
                    test_expr: Arc::new(Expr::new(ExprKind::Lit(Literal::Bool(true)), None, ())),
                    then_expr: Arc::new(Expr::new(ExprKind::Lit(Literal::Long(88)), None, ())),
                    else_expr: Arc::new(Expr::new(ExprKind::Lit(Literal::Long(-100)), None, ())),
                },
                None,
                ()
            )
        );
        assert_eq!(
            Expr::not(Expr::val(false)),
            Expr::new(
                ExprKind::UnaryApp {
                    op: UnaryOp::Not,
                    arg: Arc::new(Expr::new(ExprKind::Lit(Literal::Bool(false)), None, ())),
                },
                None,
                ()
            )
        );
        assert_eq!(
            Expr::get_attr(Expr::val(EntityUID::with_eid("foo")), "some_attr".into()),
            Expr::new(
                ExprKind::GetAttr {
                    expr: Arc::new(Expr::new(
                        ExprKind::Lit(Literal::from(EntityUID::with_eid("foo"))),
                        None,
                        ()
                    )),
                    attr: "some_attr".into()
                },
                None,
                ()
            )
        );
        assert_eq!(
            Expr::has_attr(Expr::val(EntityUID::with_eid("foo")), "some_attr".into()),
            Expr::new(
                ExprKind::HasAttr {
                    expr: Arc::new(Expr::new(
                        ExprKind::Lit(Literal::from(EntityUID::with_eid("foo"))),
                        None,
                        ()
                    )),
                    attr: "some_attr".into()
                },
                None,
                ()
            )
        );
        assert_eq!(
            Expr::is_entity_type(
                Expr::val(EntityUID::with_eid("foo")),
                "Type".parse().unwrap()
            ),
            Expr::new(
                ExprKind::Is {
                    expr: Arc::new(Expr::new(
                        ExprKind::Lit(Literal::from(EntityUID::with_eid("foo"))),
                        None,
                        ()
                    )),
                    entity_type: "Type".parse().unwrap()
                },
                None,
                ()
            ),
        );
    }

    #[test]
    fn like_display() {
        // `\0` escaped form is `\0`.
        let e = Expr::like(Expr::val("a"), Pattern::from(vec![PatternElem::Char('\0')]));
        assert_eq!(format!("{e}"), r#""a" like "\0""#);
        // `\`'s escaped form is `\\`
        let e = Expr::like(
            Expr::val("a"),
            Pattern::from(vec![PatternElem::Char('\\'), PatternElem::Char('0')]),
        );
        assert_eq!(format!("{e}"), r#""a" like "\\0""#);
        // `\`'s escaped form is `\\`
        let e = Expr::like(
            Expr::val("a"),
            Pattern::from(vec![PatternElem::Char('\\'), PatternElem::Wildcard]),
        );
        assert_eq!(format!("{e}"), r#""a" like "\\*""#);
        // literal star's escaped from is `\*`
        let e = Expr::like(
            Expr::val("a"),
            Pattern::from(vec![PatternElem::Char('\\'), PatternElem::Char('*')]),
        );
        assert_eq!(format!("{e}"), r#""a" like "\\\*""#);
    }

    #[test]
    fn has_display() {
        // `\0` escaped form is `\0`.
        let e = Expr::has_attr(Expr::val("a"), "\0".into());
        assert_eq!(format!("{e}"), r#""a" has "\0""#);
        // `\`'s escaped form is `\\`
        let e = Expr::has_attr(Expr::val("a"), r"\".into());
        assert_eq!(format!("{e}"), r#""a" has "\\""#);
    }

    #[test]
    fn slot_display() {
        let e = Expr::slot(SlotId::principal());
        assert_eq!(format!("{e}"), "?principal");
        let e = Expr::slot(SlotId::resource());
        assert_eq!(format!("{e}"), "?resource");
        let e = Expr::val(EntityUID::with_eid("eid"));
        assert_eq!(format!("{e}"), "test_entity_type::\"eid\"");
    }

    #[test]
    fn simple_slots() {
        let e = Expr::slot(SlotId::principal());
        let p = SlotId::principal();
        let r = SlotId::resource();
        let set: HashSet<SlotId> = HashSet::from_iter([p]);
        assert_eq!(set, e.slots().map(|slot| slot.id).collect::<HashSet<_>>());
        let e = Expr::or(
            Expr::slot(SlotId::principal()),
            Expr::ite(
                Expr::val(true),
                Expr::slot(SlotId::resource()),
                Expr::val(false),
            ),
        );
        let set: HashSet<SlotId> = HashSet::from_iter([p, r]);
        assert_eq!(set, e.slots().map(|slot| slot.id).collect::<HashSet<_>>());
    }

    #[test]
    fn unknowns() {
        let e = Expr::ite(
            Expr::not(Expr::unknown(Unknown::new_untyped("a"))),
            Expr::and(Expr::unknown(Unknown::new_untyped("b")), Expr::val(3)),
            Expr::unknown(Unknown::new_untyped("c")),
        );
        let unknowns = e.unknowns().collect_vec();
        assert_eq!(unknowns.len(), 3);
        assert!(unknowns.contains(&&Unknown::new_untyped("a")));
        assert!(unknowns.contains(&&Unknown::new_untyped("b")));
        assert!(unknowns.contains(&&Unknown::new_untyped("c")));
    }

    #[test]
    fn is_unknown() {
        let e = Expr::ite(
            Expr::not(Expr::unknown(Unknown::new_untyped("a"))),
            Expr::and(Expr::unknown(Unknown::new_untyped("b")), Expr::val(3)),
            Expr::unknown(Unknown::new_untyped("c")),
        );
        assert!(e.contains_unknown());
        let e = Expr::ite(
            Expr::not(Expr::val(true)),
            Expr::and(Expr::val(1), Expr::val(3)),
            Expr::val(1),
        );
        assert!(!e.contains_unknown());
    }

    #[test]
    fn expr_with_data() {
        let e = ExprBuilder::with_data("data").val(1);
        assert_eq!(e.into_data(), "data");
    }

    #[test]
    fn expr_shape_only_eq() {
        let temp = ExprBuilder::with_data(1).val(1);
        let exprs = &[
            (ExprBuilder::with_data(1).val(33), Expr::val(33)),
            (ExprBuilder::with_data(1).val(true), Expr::val(true)),
            (
                ExprBuilder::with_data(1).var(Var::Principal),
                Expr::var(Var::Principal),
            ),
            (
                ExprBuilder::with_data(1).slot(SlotId::principal()),
                Expr::slot(SlotId::principal()),
            ),
            (
                ExprBuilder::with_data(1).ite(temp.clone(), temp.clone(), temp.clone()),
                Expr::ite(Expr::val(1), Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).not(temp.clone()),
                Expr::not(Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).is_eq(temp.clone(), temp.clone()),
                Expr::is_eq(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).and(temp.clone(), temp.clone()),
                Expr::and(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).or(temp.clone(), temp.clone()),
                Expr::or(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).less(temp.clone(), temp.clone()),
                Expr::less(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).lesseq(temp.clone(), temp.clone()),
                Expr::lesseq(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).greater(temp.clone(), temp.clone()),
                Expr::greater(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).greatereq(temp.clone(), temp.clone()),
                Expr::greatereq(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).add(temp.clone(), temp.clone()),
                Expr::add(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).sub(temp.clone(), temp.clone()),
                Expr::sub(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).mul(temp.clone(), temp.clone()),
                Expr::mul(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).neg(temp.clone()),
                Expr::neg(Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).is_in(temp.clone(), temp.clone()),
                Expr::is_in(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).contains(temp.clone(), temp.clone()),
                Expr::contains(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).contains_all(temp.clone(), temp.clone()),
                Expr::contains_all(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).contains_any(temp.clone(), temp.clone()),
                Expr::contains_any(Expr::val(1), Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).is_empty(temp.clone()),
                Expr::is_empty(Expr::val(1)),
            ),
            (
                ExprBuilder::with_data(1).set([temp.clone()]),
                Expr::set([Expr::val(1)]),
            ),
            (
                ExprBuilder::with_data(1)
                    .record([("foo".into(), temp.clone())])
                    .unwrap(),
                Expr::record([("foo".into(), Expr::val(1))]).unwrap(),
            ),
            (
                ExprBuilder::with_data(1)
                    .call_extension_fn("foo".parse().unwrap(), vec![temp.clone()]),
                Expr::call_extension_fn("foo".parse().unwrap(), vec![Expr::val(1)]),
            ),
            (
                ExprBuilder::with_data(1).get_attr(temp.clone(), "foo".into()),
                Expr::get_attr(Expr::val(1), "foo".into()),
            ),
            (
                ExprBuilder::with_data(1).has_attr(temp.clone(), "foo".into()),
                Expr::has_attr(Expr::val(1), "foo".into()),
            ),
            (
                ExprBuilder::with_data(1)
                    .like(temp.clone(), Pattern::from(vec![PatternElem::Wildcard])),
                Expr::like(Expr::val(1), Pattern::from(vec![PatternElem::Wildcard])),
            ),
            (
                ExprBuilder::with_data(1).is_entity_type(temp, "T".parse().unwrap()),
                Expr::is_entity_type(Expr::val(1), "T".parse().unwrap()),
            ),
        ];

        for (e0, e1) in exprs {
            assert!(e0.eq_shape(e0));
            assert!(e1.eq_shape(e1));
            assert!(e0.eq_shape(e1));
            assert!(e1.eq_shape(e0));

            let mut hasher0 = DefaultHasher::new();
            e0.hash_shape(&mut hasher0);
            let hash0 = hasher0.finish();

            let mut hasher1 = DefaultHasher::new();
            e1.hash_shape(&mut hasher1);
            let hash1 = hasher1.finish();

            assert_eq!(hash0, hash1);
        }
    }

    #[test]
    fn expr_shape_only_not_eq() {
        let expr1 = ExprBuilder::with_data(1).val(1);
        let expr2 = ExprBuilder::with_data(1).val(2);
        assert_ne!(
            ExprShapeOnly::new_from_borrowed(&expr1),
            ExprShapeOnly::new_from_borrowed(&expr2)
        );
    }

    #[test]
    fn expr_shape_only_set_prefix_ne() {
        let e1 = ExprShapeOnly::new_from_owned(Expr::set([]));
        let e2 = ExprShapeOnly::new_from_owned(Expr::set([Expr::val(1)]));
        let e3 = ExprShapeOnly::new_from_owned(Expr::set([Expr::val(1), Expr::val(2)]));

        assert_ne!(e1, e2);
        assert_ne!(e1, e3);
        assert_ne!(e2, e1);
        assert_ne!(e2, e3);
        assert_ne!(e3, e1);
        assert_ne!(e2, e1);
    }

    #[test]
    fn expr_shape_only_ext_fn_arg_prefix_ne() {
        let e1 = ExprShapeOnly::new_from_owned(Expr::call_extension_fn(
            "decimal".parse().unwrap(),
            vec![],
        ));
        let e2 = ExprShapeOnly::new_from_owned(Expr::call_extension_fn(
            "decimal".parse().unwrap(),
            vec![Expr::val("0.0")],
        ));
        let e3 = ExprShapeOnly::new_from_owned(Expr::call_extension_fn(
            "decimal".parse().unwrap(),
            vec![Expr::val("0.0"), Expr::val("0.0")],
        ));

        assert_ne!(e1, e2);
        assert_ne!(e1, e3);
        assert_ne!(e2, e1);
        assert_ne!(e2, e3);
        assert_ne!(e3, e1);
        assert_ne!(e2, e1);
    }

    #[test]
    fn expr_shape_only_record_attr_prefix_ne() {
        let e1 = ExprShapeOnly::new_from_owned(Expr::record([]).unwrap());
        let e2 = ExprShapeOnly::new_from_owned(
            Expr::record([("a".to_smolstr(), Expr::val(1))]).unwrap(),
        );
        let e3 = ExprShapeOnly::new_from_owned(
            Expr::record([
                ("a".to_smolstr(), Expr::val(1)),
                ("b".to_smolstr(), Expr::val(2)),
            ])
            .unwrap(),
        );

        assert_ne!(e1, e2);
        assert_ne!(e1, e3);
        assert_ne!(e2, e1);
        assert_ne!(e2, e3);
        assert_ne!(e3, e1);
        assert_ne!(e2, e1);
    }

    #[test]
    fn untyped_subst_present() {
        let u = Unknown {
            name: "foo".into(),
            type_annotation: None,
        };
        let r = UntypedSubstitution::substitute(&u, Some(&Value::new(1, None)));
        match r {
            Ok(e) => assert_eq!(e, Expr::val(1)),
            Err(empty) => match empty {},
        }
    }

    #[test]
    fn untyped_subst_present_correct_type() {
        let u = Unknown {
            name: "foo".into(),
            type_annotation: Some(Type::Long),
        };
        let r = UntypedSubstitution::substitute(&u, Some(&Value::new(1, None)));
        match r {
            Ok(e) => assert_eq!(e, Expr::val(1)),
            Err(empty) => match empty {},
        }
    }

    #[test]
    fn untyped_subst_present_wrong_type() {
        let u = Unknown {
            name: "foo".into(),
            type_annotation: Some(Type::Bool),
        };
        let r = UntypedSubstitution::substitute(&u, Some(&Value::new(1, None)));
        match r {
            Ok(e) => assert_eq!(e, Expr::val(1)),
            Err(empty) => match empty {},
        }
    }

    #[test]
    fn untyped_subst_not_present() {
        let u = Unknown {
            name: "foo".into(),
            type_annotation: Some(Type::Bool),
        };
        let r = UntypedSubstitution::substitute(&u, None);
        match r {
            Ok(n) => assert_eq!(n, Expr::unknown(u)),
            Err(empty) => match empty {},
        }
    }

    #[test]
    fn typed_subst_present() {
        let u = Unknown {
            name: "foo".into(),
            type_annotation: None,
        };
        let e = TypedSubstitution::substitute(&u, Some(&Value::new(1, None))).unwrap();
        assert_eq!(e, Expr::val(1));
    }

    #[test]
    fn typed_subst_present_correct_type() {
        let u = Unknown {
            name: "foo".into(),
            type_annotation: Some(Type::Long),
        };
        let e = TypedSubstitution::substitute(&u, Some(&Value::new(1, None))).unwrap();
        assert_eq!(e, Expr::val(1));
    }

    #[test]
    fn typed_subst_present_wrong_type() {
        let u = Unknown {
            name: "foo".into(),
            type_annotation: Some(Type::Bool),
        };
        let r = TypedSubstitution::substitute(&u, Some(&Value::new(1, None))).unwrap_err();
        assert_matches!(
            r,
            SubstitutionError::TypeError {
                expected: Type::Bool,
                actual: Type::Long,
            }
        );
    }

    #[test]
    fn typed_subst_not_present() {
        let u = Unknown {
            name: "foo".into(),
            type_annotation: None,
        };
        let r = TypedSubstitution::substitute(&u, None).unwrap();
        assert_eq!(r, Expr::unknown(u));
    }
}
