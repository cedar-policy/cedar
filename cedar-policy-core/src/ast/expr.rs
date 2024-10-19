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

use crate::{
    ast::*,
    extensions::Extensions,
    parser::{err::ParseErrors, Loc},
};
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
#[derive(Serialize, Deserialize, Hash, Debug, Clone, PartialEq, Eq)]
pub struct Expr<T = ()> {
    expr_kind: ExprKind<T>,
    source_loc: Option<Loc>,
    data: T,
}

/// The possible expression variants. This enum should be matched on by code
/// recursively traversing the AST.
#[derive(Serialize, Deserialize, Hash, Debug, Clone, PartialEq, Eq)]
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
            ValueKind::ExtensionValue(ev) => Expr::from(ev.as_ref().clone()),
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

impl<T> ExprKind<T> {
    /// Describe this operator for error messages.
    pub fn operator_description(self: &ExprKind<T>) -> String {
        match self {
            ExprKind::Lit(_) => "literal".to_string(),
            ExprKind::Var(_) => "variable".to_string(),
            ExprKind::Slot(_) => "slot".to_string(),
            ExprKind::Unknown(_) => "unknown".to_string(),
            ExprKind::If { .. } => "if".to_string(),
            ExprKind::And { .. } => "&&".to_string(),
            ExprKind::Or { .. } => "||".to_string(),
            ExprKind::UnaryApp { op, .. } => op.to_string(),
            ExprKind::BinaryApp { op, .. } => op.to_string(),
            ExprKind::ExtensionFunctionApp { fn_name, .. } => fn_name.to_string(),
            ExprKind::GetAttr { .. } => "get attribute".to_string(),
            ExprKind::HasAttr { .. } => "has attribute".to_string(),
            ExprKind::Like { .. } => "like".to_string(),
            ExprKind::Is { .. } => "is".to_string(),
            ExprKind::Set(_) => "set".to_string(),
            ExprKind::Record(_) => "record".to_string(),
        }
    }
}

impl<T> Expr<T> {
    fn new(expr_kind: ExprKind<T>, source_loc: Option<Loc>, data: T) -> Self {
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

    /// Access the `Loc` stored on the `Expr`.
    pub fn source_loc(&self) -> Option<&Loc> {
        self.source_loc.as_ref()
    }

    /// Return the `Expr`, but with the new `source_loc` (or `None`).
    pub fn with_maybe_source_loc(self, source_loc: Option<Loc>) -> Self {
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
                    loc: exp.source_loc().cloned(),
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
    pub fn like(expr: Expr, pattern: impl IntoIterator<Item = PatternElem>) -> Self {
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
                pattern.iter().cloned(),
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
        write!(f, "{}", crate::est::Expr::from(self.clone()))
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
#[derive(Serialize, Deserialize, Hash, Debug, Clone, PartialEq, Eq)]
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
        write!(f, "{}", crate::est::Expr::from(Expr::unknown(self.clone())))
    }
}

#[cfg(feature = "protobufs")]
impl From<&proto::Expr> for Expr {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &proto::Expr) -> Self {
        let source_loc: Option<Loc> = v.source_loc.as_ref().map(Loc::from);
        let pdata = v
            .expr_kind
            .as_ref()
            .expect("as_ref() for field that will exist");
        let ety = pdata
            .data
            .as_ref()
            .expect("as_ref() for field that will exist");

        match ety {
            proto::expr::expr_kind::Data::Lit(lit) => {
                Expr::val(Literal::from(lit)).with_maybe_source_loc(source_loc)
            }

            proto::expr::expr_kind::Data::Var(var) => {
                let pvar =
                    proto::expr::Var::try_from(var.to_owned()).expect("decode should succeed");
                Expr::var(Var::from(&pvar)).with_maybe_source_loc(source_loc)
            }

            proto::expr::expr_kind::Data::Slot(slot) => {
                let pslot =
                    proto::SlotId::try_from(slot.to_owned()).expect("decode should succeed");
                Expr::slot(SlotId::from(&pslot)).with_maybe_source_loc(source_loc)
            }

            proto::expr::expr_kind::Data::If(msg) => {
                let test_expr = msg
                    .test_expr
                    .as_ref()
                    .expect("as_ref() for field that will exist")
                    .as_ref();
                let then_expr = msg
                    .then_expr
                    .as_ref()
                    .expect("as_ref() for field that will exist")
                    .as_ref();
                let else_expr = msg
                    .else_expr
                    .as_ref()
                    .expect("as_ref() for field that will exist")
                    .as_ref();
                Expr::ite(
                    Expr::from(test_expr),
                    Expr::from(then_expr),
                    Expr::from(else_expr),
                )
                .with_maybe_source_loc(source_loc)
            }

            proto::expr::expr_kind::Data::And(msg) => {
                let left = msg
                    .left
                    .as_ref()
                    .expect("as_ref() for field that will exist")
                    .as_ref();
                let right = msg
                    .right
                    .as_ref()
                    .expect("as_ref() for field that will exist")
                    .as_ref();
                Expr::and(Expr::from(left), Expr::from(right)).with_maybe_source_loc(source_loc)
            }

            proto::expr::expr_kind::Data::Or(msg) => {
                let left = msg
                    .left
                    .as_ref()
                    .expect("as_ref() for field that will exist")
                    .as_ref();
                let right = msg
                    .right
                    .as_ref()
                    .expect("as_ref() for field that will exist")
                    .as_ref();
                Expr::or(Expr::from(left), Expr::from(right)).with_maybe_source_loc(source_loc)
            }

            proto::expr::expr_kind::Data::UApp(msg) => {
                let arg = msg
                    .expr
                    .as_ref()
                    .expect("as_ref() for field that will exist")
                    .as_ref();
                let puop =
                    proto::expr::unary_app::Op::try_from(msg.op).expect("decode should succeed");
                Expr::unary_app(UnaryOp::from(&puop), Expr::from(arg))
                    .with_maybe_source_loc(source_loc)
            }

            proto::expr::expr_kind::Data::BApp(msg) => {
                let pbop =
                    proto::expr::binary_app::Op::try_from(msg.op).expect("decode should succeed");
                let left = msg
                    .left
                    .as_ref()
                    .expect("as_ref() for field that will exist");
                let right = msg
                    .right
                    .as_ref()
                    .expect("as_ref() for field that will exist");
                Expr::binary_app(
                    BinaryOp::from(&pbop),
                    Expr::from(left.as_ref()),
                    Expr::from(right.as_ref()),
                )
                .with_maybe_source_loc(source_loc)
            }

            proto::expr::expr_kind::Data::ExtApp(msg) => Expr::call_extension_fn(
                Name::from(
                    msg.fn_name
                        .as_ref()
                        .expect("as_ref() for field that will exist"),
                ),
                msg.args.iter().map(Expr::from).collect(),
            )
            .with_maybe_source_loc(source_loc),

            proto::expr::expr_kind::Data::GetAttr(msg) => {
                let arg = msg
                    .expr
                    .as_ref()
                    .expect("as_ref() for field that will exist")
                    .as_ref();
                Expr::get_attr(Expr::from(arg), msg.attr.clone().into())
                    .with_maybe_source_loc(source_loc)
            }

            proto::expr::expr_kind::Data::HasAttr(msg) => {
                let arg = msg
                    .expr
                    .as_ref()
                    .expect("as_ref() for field that will exist")
                    .as_ref();
                Expr::has_attr(Expr::from(arg), msg.attr.clone().into())
                    .with_maybe_source_loc(source_loc)
            }

            proto::expr::expr_kind::Data::Like(msg) => {
                let arg = msg
                    .expr
                    .as_ref()
                    .expect("as_ref() for field that will exist")
                    .as_ref();
                Expr::like(Expr::from(arg), msg.pattern.iter().map(PatternElem::from))
                    .with_maybe_source_loc(source_loc)
            }

            proto::expr::expr_kind::Data::Is(msg) => {
                let arg = msg
                    .expr
                    .as_ref()
                    .expect("as_ref() for field that will exist")
                    .as_ref();
                Expr::is_entity_type(
                    Expr::from(arg),
                    EntityType::from(
                        msg.entity_type
                            .as_ref()
                            .expect("as_ref() for field that will exist"),
                    ),
                )
                .with_maybe_source_loc(source_loc)
            }

            proto::expr::expr_kind::Data::Set(msg) => {
                Expr::set(msg.elements.iter().map(Expr::from)).with_maybe_source_loc(source_loc)
            }

            proto::expr::expr_kind::Data::Record(msg) => Expr::record(
                msg.items
                    .iter()
                    .map(|(key, value)| (key.into(), Expr::from(value))),
            )
            .expect("Expr should be valid")
            .with_maybe_source_loc(source_loc),
        }
    }
}

#[cfg(feature = "protobufs")]
impl From<&Expr> for proto::Expr {
    fn from(v: &Expr) -> Self {
        let source_loc: Option<proto::Loc> = v.source_loc.as_ref().map(proto::Loc::from);
        let expr_kind = match &v.expr_kind {
            ExprKind::Lit(l) => proto::expr::expr_kind::Data::Lit(proto::expr::Literal::from(l)),
            ExprKind::Var(v) => proto::expr::expr_kind::Data::Var(proto::expr::Var::from(v).into()),
            ExprKind::Slot(sid) => {
                proto::expr::expr_kind::Data::Slot(proto::SlotId::from(sid).into())
            }

            ExprKind::Unknown(_u) => {
                // PANIC SAFETY: experimental feature
                #[allow(clippy::unimplemented)]
                unimplemented!("Protobuffer interface does not support Unknown expressions")
            }
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => proto::expr::expr_kind::Data::If(Box::new(proto::expr::If {
                test_expr: Some(Box::new(proto::Expr::from(test_expr.as_ref()))),
                then_expr: Some(Box::new(proto::Expr::from(then_expr.as_ref()))),
                else_expr: Some(Box::new(proto::Expr::from(else_expr.as_ref()))),
            })),
            ExprKind::And { left, right } => {
                proto::expr::expr_kind::Data::And(Box::new(proto::expr::And {
                    left: Some(Box::new(proto::Expr::from(left.as_ref()))),
                    right: Some(Box::new(proto::Expr::from(right.as_ref()))),
                }))
            }
            ExprKind::Or { left, right } => {
                proto::expr::expr_kind::Data::Or(Box::new(proto::expr::Or {
                    left: Some(Box::new(proto::Expr::from(left.as_ref()))),
                    right: Some(Box::new(proto::Expr::from(right.as_ref()))),
                }))
            }
            ExprKind::UnaryApp { op, arg } => {
                proto::expr::expr_kind::Data::UApp(Box::new(proto::expr::UnaryApp {
                    op: proto::expr::unary_app::Op::from(op).into(),
                    expr: Some(Box::new(proto::Expr::from(arg.as_ref()))),
                }))
            }
            ExprKind::BinaryApp { op, arg1, arg2 } => {
                proto::expr::expr_kind::Data::BApp(Box::new(proto::expr::BinaryApp {
                    op: proto::expr::binary_app::Op::from(op).into(),
                    left: Some(Box::new(proto::Expr::from(arg1.as_ref()))),
                    right: Some(Box::new(proto::Expr::from(arg2.as_ref()))),
                }))
            }
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let mut pargs: Vec<proto::Expr> = Vec::with_capacity(args.as_ref().len());
                for value in args.as_ref() {
                    pargs.push(proto::Expr::from(value));
                }
                proto::expr::expr_kind::Data::ExtApp(proto::expr::ExtensionFunctionApp {
                    fn_name: Some(proto::Name::from(fn_name)),
                    args: pargs,
                })
            }
            ExprKind::GetAttr { expr, attr } => {
                proto::expr::expr_kind::Data::GetAttr(Box::new(proto::expr::GetAttr {
                    attr: attr.to_string(),
                    expr: Some(Box::new(proto::Expr::from(expr.as_ref()))),
                }))
            }
            ExprKind::HasAttr { expr, attr } => {
                proto::expr::expr_kind::Data::HasAttr(Box::new(proto::expr::HasAttr {
                    attr: attr.to_string(),
                    expr: Some(Box::new(proto::Expr::from(expr.as_ref()))),
                }))
            }
            ExprKind::Like { expr, pattern } => {
                let mut ppattern: Vec<proto::expr::like::PatternElem> =
                    Vec::with_capacity(pattern.len());
                for value in pattern.iter() {
                    ppattern.push(proto::expr::like::PatternElem::from(value));
                }
                proto::expr::expr_kind::Data::Like(Box::new(proto::expr::Like {
                    expr: Some(Box::new(proto::Expr::from(expr.as_ref()))),
                    pattern: ppattern,
                }))
            }
            ExprKind::Is { expr, entity_type } => {
                proto::expr::expr_kind::Data::Is(Box::new(proto::expr::Is {
                    expr: Some(Box::new(proto::Expr::from(expr.as_ref()))),
                    entity_type: Some(proto::EntityType::from(entity_type)),
                }))
            }
            ExprKind::Set(args) => {
                let mut pargs: Vec<proto::Expr> = Vec::with_capacity(args.as_ref().len());
                for arg in args.as_ref() {
                    pargs.push(proto::Expr::from(arg));
                }
                proto::expr::expr_kind::Data::Set(proto::expr::Set { elements: pargs })
            }
            ExprKind::Record(record) => {
                let precord = record
                    .as_ref()
                    .into_iter()
                    .map(|(key, value)| (key.to_string(), proto::Expr::from(value)))
                    .collect();
                proto::expr::expr_kind::Data::Record(proto::expr::Record { items: precord })
            }
        };
        Self {
            expr_kind: Some(Box::new(proto::expr::ExprKind {
                data: Some(expr_kind),
            })),
            source_loc: source_loc,
        }
    }
}

/// Builder for constructing `Expr` objects annotated with some `data`
/// (possibly taking default value) and optionally a `source_loc`.
#[derive(Debug)]
pub struct ExprBuilder<T> {
    source_loc: Option<Loc>,
    data: T,
}

impl<T> ExprBuilder<T>
where
    T: Default,
{
    /// Construct a new `ExprBuilder` where the data used for an expression
    /// takes a default value.
    pub fn new() -> Self {
        Self {
            source_loc: None,
            data: T::default(),
        }
    }

    /// Create a '!=' expression.
    /// Defined only for `T: Default` because the caller would otherwise need to
    /// provide a `data` for the intermediate `not` Expr node.
    pub fn noteq(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        match &self.source_loc {
            Some(source_loc) => ExprBuilder::new().with_source_loc(source_loc.clone()),
            None => ExprBuilder::new(),
        }
        .not(self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::Eq,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        }))
    }
}

impl<T: Default> Default for ExprBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ExprBuilder<T> {
    /// Construct a new `ExprBuild` where the specified data will be stored on
    /// the `Expr`. This constructor does not populate the `source_loc` field,
    /// so `with_source_loc` should be called if constructing an `Expr` where
    /// the source location is known.
    pub fn with_data(data: T) -> Self {
        Self {
            source_loc: None,
            data,
        }
    }

    /// Update the `ExprBuilder` to build an expression with some known location
    /// in policy source code.
    pub fn with_source_loc(self, source_loc: Loc) -> Self {
        self.with_maybe_source_loc(Some(source_loc))
    }

    /// Utility used the validator to get an expression with the same source
    /// location as an existing expression. This is done when reconstructing the
    /// `Expr` with type information.
    pub fn with_same_source_loc<U>(self, expr: &Expr<U>) -> Self {
        self.with_maybe_source_loc(expr.source_loc.clone())
    }

    /// internally used to update `.source_loc` to the given `Some` or `None`
    fn with_maybe_source_loc(mut self, maybe_source_loc: Option<Loc>) -> Self {
        self.source_loc = maybe_source_loc;
        self
    }

    /// Internally used by the following methods to construct an `Expr`
    /// containing the `data` and `source_loc` in this `ExprBuilder` with some
    /// inner `ExprKind`.
    fn with_expr_kind(self, expr_kind: ExprKind<T>) -> Expr<T> {
        Expr::new(expr_kind, self.source_loc, self.data)
    }

    /// Create an `Expr` that's just a single `Literal`.
    ///
    /// Note that you can pass this a `Literal`, an `Integer`, a `String`, etc.
    pub fn val(self, v: impl Into<Literal>) -> Expr<T> {
        self.with_expr_kind(ExprKind::Lit(v.into()))
    }

    /// Create an `Unknown` `Expr`
    pub fn unknown(self, u: Unknown) -> Expr<T> {
        self.with_expr_kind(ExprKind::Unknown(u))
    }

    /// Create an `Expr` that's just this literal `Var`
    pub fn var(self, v: Var) -> Expr<T> {
        self.with_expr_kind(ExprKind::Var(v))
    }

    /// Create an `Expr` that's just this `SlotId`
    pub fn slot(self, s: SlotId) -> Expr<T> {
        self.with_expr_kind(ExprKind::Slot(s))
    }

    /// Create a ternary (if-then-else) `Expr`.
    ///
    /// `test_expr` must evaluate to a Bool type
    pub fn ite(self, test_expr: Expr<T>, then_expr: Expr<T>, else_expr: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::If {
            test_expr: Arc::new(test_expr),
            then_expr: Arc::new(then_expr),
            else_expr: Arc::new(else_expr),
        })
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

    /// Create a 'not' expression. `e` must evaluate to Bool type
    pub fn not(self, e: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::UnaryApp {
            op: UnaryOp::Not,
            arg: Arc::new(e),
        })
    }

    /// Create a '==' expression
    pub fn is_eq(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::Eq,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create an 'and' expression. Arguments must evaluate to Bool type
    pub fn and(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
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
    pub fn or(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
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
    pub fn less(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::Less,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create a '<=' expression. Arguments must evaluate to Long type
    pub fn lesseq(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::LessEq,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create an 'add' expression. Arguments must evaluate to Long type
    pub fn add(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::Add,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create a 'sub' expression. Arguments must evaluate to Long type
    pub fn sub(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::Sub,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create a 'mul' expression. Arguments must evaluate to Long type
    pub fn mul(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::Mul,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create a 'neg' expression. `e` must evaluate to Long type.
    pub fn neg(self, e: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::UnaryApp {
            op: UnaryOp::Neg,
            arg: Arc::new(e),
        })
    }

    /// Create an 'in' expression. First argument must evaluate to Entity type.
    /// Second argument must evaluate to either Entity type or Set type where
    /// all set elements have Entity type.
    pub fn is_in(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::In,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create a 'contains' expression.
    /// First argument must have Set type.
    pub fn contains(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::Contains,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create a 'contains_all' expression. Arguments must evaluate to Set type
    pub fn contains_all(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::ContainsAll,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create an 'contains_any' expression. Arguments must evaluate to Set type
    pub fn contains_any(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::ContainsAny,
            arg1: Arc::new(e1),
            arg2: Arc::new(e2),
        })
    }

    /// Create a 'getTag' expression.
    /// `expr` must evaluate to Entity type, `tag` must evaluate to String type.
    pub fn get_tag(self, expr: Expr<T>, tag: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::GetTag,
            arg1: Arc::new(expr),
            arg2: Arc::new(tag),
        })
    }

    /// Create a 'hasTag' expression.
    /// `expr` must evaluate to Entity type, `tag` must evaluate to String type.
    pub fn has_tag(self, expr: Expr<T>, tag: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: BinaryOp::HasTag,
            arg1: Arc::new(expr),
            arg2: Arc::new(tag),
        })
    }

    /// Create an `Expr` which evaluates to a Set of the given `Expr`s
    pub fn set(self, exprs: impl IntoIterator<Item = Expr<T>>) -> Expr<T> {
        self.with_expr_kind(ExprKind::Set(Arc::new(exprs.into_iter().collect())))
    }

    /// Create an `Expr` which evaluates to a Record with the given (key, value) pairs.
    pub fn record(
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

    /// Create an `Expr` which evalutes to a Record with the given key-value mapping.
    ///
    /// If you have an iterator of pairs, generally prefer calling `.record()`
    /// instead of `.collect()`-ing yourself and calling this, potentially for
    /// efficiency reasons but also because `.record()` will properly handle
    /// duplicate keys but your own `.collect()` will not (by default).
    pub fn record_arc(self, map: Arc<BTreeMap<SmolStr, Expr<T>>>) -> Expr<T> {
        self.with_expr_kind(ExprKind::Record(map))
    }

    /// Create an `Expr` which calls the extension function with the given
    /// `Name` on `args`
    pub fn call_extension_fn(
        self,
        fn_name: Name,
        args: impl IntoIterator<Item = Expr<T>>,
    ) -> Expr<T> {
        self.with_expr_kind(ExprKind::ExtensionFunctionApp {
            fn_name,
            args: Arc::new(args.into_iter().collect()),
        })
    }

    /// Create an application `Expr` which applies the given built-in unary
    /// operator to the given `arg`
    pub fn unary_app(self, op: impl Into<UnaryOp>, arg: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::UnaryApp {
            op: op.into(),
            arg: Arc::new(arg),
        })
    }

    /// Create an application `Expr` which applies the given built-in binary
    /// operator to `arg1` and `arg2`
    pub fn binary_app(self, op: impl Into<BinaryOp>, arg1: Expr<T>, arg2: Expr<T>) -> Expr<T> {
        self.with_expr_kind(ExprKind::BinaryApp {
            op: op.into(),
            arg1: Arc::new(arg1),
            arg2: Arc::new(arg2),
        })
    }

    /// Create an `Expr` which gets a given attribute of a given `Entity` or record.
    ///
    /// `expr` must evaluate to either Entity or Record type
    pub fn get_attr(self, expr: Expr<T>, attr: SmolStr) -> Expr<T> {
        self.with_expr_kind(ExprKind::GetAttr {
            expr: Arc::new(expr),
            attr,
        })
    }

    /// Create an `Expr` which tests for the existence of a given
    /// attribute on a given `Entity` or record.
    ///
    /// `expr` must evaluate to either Entity or Record type
    pub fn has_attr(self, expr: Expr<T>, attr: SmolStr) -> Expr<T> {
        self.with_expr_kind(ExprKind::HasAttr {
            expr: Arc::new(expr),
            attr,
        })
    }

    /// Create a 'like' expression.
    ///
    /// `expr` must evaluate to a String type
    pub fn like(self, expr: Expr<T>, pattern: impl IntoIterator<Item = PatternElem>) -> Expr<T> {
        self.with_expr_kind(ExprKind::Like {
            expr: Arc::new(expr),
            pattern: Pattern::new(pattern),
        })
    }

    /// Create an 'is' expression.
    pub fn is_entity_type(self, expr: Expr<T>, entity_type: EntityType) -> Expr<T> {
        self.with_expr_kind(ExprKind::Is {
            expr: Arc::new(expr),
            entity_type,
        })
    }
}

impl<T: Clone> ExprBuilder<T> {
    /// Create an `and` expression that may have more than two subexpressions (A && B && C)
    /// or may have only one subexpression, in which case no `&&` is performed at all.
    /// Arguments must evaluate to Bool type.
    ///
    /// This may create multiple AST `&&` nodes. If it does, all the nodes will have the same
    /// source location and the same `T` data (taken from this builder) unless overridden, e.g.,
    /// with another call to `with_source_loc()`.
    pub fn and_nary(self, first: Expr<T>, others: impl IntoIterator<Item = Expr<T>>) -> Expr<T> {
        others.into_iter().fold(first, |acc, next| {
            Self::with_data(self.data.clone())
                .with_maybe_source_loc(self.source_loc.clone())
                .and(acc, next)
        })
    }

    /// Create an `or` expression that may have more than two subexpressions (A || B || C)
    /// or may have only one subexpression, in which case no `||` is performed at all.
    /// Arguments must evaluate to Bool type.
    ///
    /// This may create multiple AST `||` nodes. If it does, all the nodes will have the same
    /// source location and the same `T` data (taken from this builder) unless overridden, e.g.,
    /// with another call to `with_source_loc()`.
    pub fn or_nary(self, first: Expr<T>, others: impl IntoIterator<Item = Expr<T>>) -> Expr<T> {
        others.into_iter().fold(first, |acc, next| {
            Self::with_data(self.data.clone())
                .with_maybe_source_loc(self.source_loc.clone())
                .or(acc, next)
        })
    }

    /// Create a '>' expression. Arguments must evaluate to Long type
    pub fn greater(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        // e1 > e2 is defined as !(e1 <= e2)
        let leq = Self::with_data(self.data.clone())
            .with_maybe_source_loc(self.source_loc.clone())
            .lesseq(e1, e2);
        self.not(leq)
    }

    /// Create a '>=' expression. Arguments must evaluate to Long type
    pub fn greatereq(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        // e1 >= e2 is defined as !(e1 < e2)
        let leq = Self::with_data(self.data.clone())
            .with_maybe_source_loc(self.source_loc.clone())
            .less(e1, e2);
        self.not(leq)
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

impl<'a, T: Clone> PartialEq for ExprShapeOnly<'a, T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_shape(&other.0)
    }
}

impl<'a, T: Clone> Hash for ExprShapeOnly<'a, T> {
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
            ) => fn_name == fn_name1 && args.iter().zip(args1.iter()).all(|(a, a1)| a.eq_shape(a1)),
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
            (Set(elems), Set(elems1)) => elems
                .iter()
                .zip(elems1.iter())
                .all(|(e, e1)| e.eq_shape(e1)),
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

#[cfg(test)]
pub mod var_generator {
    use super::Var;
    #[cfg(test)]
    pub fn all_vars() -> impl Iterator<Item = Var> {
        [Var::Principal, Var::Action, Var::Resource, Var::Context].into_iter()
    }
}
// by default, Coverlay does not track coverage for lines after a line
// containing #[cfg(test)].
// we use the following sentinel to "turn back on" coverage tracking for
// remaining lines of this file, until the next #[cfg(test)]
// GRCOV_BEGIN_COVERAGE

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

#[cfg(feature = "protobufs")]
impl From<&proto::expr::Var> for Var {
    fn from(v: &proto::expr::Var) -> Self {
        match v {
            proto::expr::Var::Principal => Var::Principal,
            proto::expr::Var::Action => Var::Action,
            proto::expr::Var::Resource => Var::Resource,
            proto::expr::Var::Context => Var::Context,
        }
    }
}

#[cfg(feature = "protobufs")]
impl From<&Var> for proto::expr::Var {
    fn from(v: &Var) -> Self {
        match v {
            Var::Principal => proto::expr::Var::Principal,
            Var::Action => proto::expr::Var::Action,
            Var::Resource => proto::expr::Var::Resource,
            Var::Context => proto::expr::Var::Context,
        }
    }
}

#[cfg(test)]
mod test {
    use cool_asserts::assert_matches;
    use itertools::Itertools;
    use std::collections::{hash_map::DefaultHasher, HashSet};

    use super::{var_generator::all_vars, *};

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
        let e = Expr::like(Expr::val("a"), vec![PatternElem::Char('\0')]);
        assert_eq!(format!("{e}"), r#""a" like "\0""#);
        // `\`'s escaped form is `\\`
        let e = Expr::like(
            Expr::val("a"),
            vec![PatternElem::Char('\\'), PatternElem::Char('0')],
        );
        assert_eq!(format!("{e}"), r#""a" like "\\0""#);
        // `\`'s escaped form is `\\`
        let e = Expr::like(
            Expr::val("a"),
            vec![PatternElem::Char('\\'), PatternElem::Wildcard],
        );
        assert_eq!(format!("{e}"), r#""a" like "\\*""#);
        // literal star's escaped from is `\*`
        let e = Expr::like(
            Expr::val("a"),
            vec![PatternElem::Char('\\'), PatternElem::Char('*')],
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
                ExprBuilder::with_data(1).like(temp.clone(), vec![PatternElem::Wildcard]),
                Expr::like(Expr::val(1), vec![PatternElem::Wildcard]),
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

    #[cfg(feature = "protobufs")]
    #[test]
    fn protobuf_roundtrip() {
        let e1: Expr = Expr::val(33);
        assert_eq!(e1, Expr::from(&proto::Expr::from(&e1)));
        let e2: Expr = Expr::val("hello");
        assert_eq!(e2, Expr::from(&proto::Expr::from(&e2)));
        let e3: Expr = Expr::val(EntityUID::with_eid("foo"));
        assert_eq!(
            e3,
            Expr::from(&proto::Expr::from(&Expr::val(EntityUID::with_eid("foo"))))
        );
        let e4: Expr = Expr::var(Var::Principal);
        assert_eq!(e4, Expr::from(&proto::Expr::from(&e4)));
        let e5: Expr = Expr::ite(Expr::val(true), Expr::val(88), Expr::val(-100));
        assert_eq!(e5, Expr::from(&proto::Expr::from(&e5)));
        let e6: Expr = Expr::not(Expr::val(false));
        assert_eq!(e6, Expr::from(&proto::Expr::from(&e6)));
        let e7: Expr = Expr::get_attr(Expr::val(EntityUID::with_eid("foo")), "some_attr".into());
        assert_eq!(e7, Expr::from(&proto::Expr::from(&e7)));
        let e8: Expr = Expr::has_attr(Expr::val(EntityUID::with_eid("foo")), "some_attr".into());
        assert_eq!(e8, Expr::from(&proto::Expr::from(&e8)));
        let e9: Expr = Expr::is_entity_type(
            Expr::val(EntityUID::with_eid("foo")),
            "Type".parse().unwrap(),
        );
        assert_eq!(e9, Expr::from(&proto::Expr::from(&e9)));
    }
}
