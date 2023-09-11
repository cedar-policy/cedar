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

use crate::{
    ast::*,
    extensions::Extensions,
    parser::{err::ParseErrors, SourceInfo},
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::{
    collections::HashMap,
    collections::HashSet,
    hash::{Hash, Hasher},
    mem,
    sync::Arc,
};
use thiserror::Error;

/// Internal AST for expressions used by the policy evaluator.
/// This structure is a wrapper around an `ExprKind`, which is the expression
/// variant this object contains. It also contains source information about
/// where the expression was written in policy source code, and some generic
/// data which is stored on each node of the AST.
/// Cloning is O(1).
#[derive(Serialize, Deserialize, Hash, Debug, Clone, PartialEq, Eq)]
pub struct Expr<T = ()> {
    expr_kind: ExprKind<T>,
    source_info: Option<SourceInfo>,
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
    Unknown {
        /// The name of the unknown
        name: SmolStr,
        /// The type of the values that can be substituted in for the unknown
        /// If `None`, we have no type annotation, and thus a value of any type can be substituted.
        type_annotation: Option<Type>,
    },
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
    /// Multiplication by constant
    ///
    /// This isn't just a BinaryOp because its arguments aren't both expressions.
    /// (Similar to how `like` isn't a BinaryOp and has its own AST node as well.)
    MulByConst {
        /// first argument, which may be an arbitrary expression, but must
        /// evaluate to Long type
        arg: Arc<Expr<T>>,
        /// second argument, which must be an integer constant
        constant: i64,
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
    /// Set (whose elements may be arbitrary expressions)
    //
    // This is backed by `Vec` (and not e.g. `HashSet`), because two `Expr`s
    // that are syntactically unequal, may actually be semantically equal --
    // i.e., we can't do the dedup of duplicates until all of the `Expr`s are
    // evaluated into `Value`s
    Set(Arc<Vec<Expr<T>>>),
    /// Anonymous record (whose elements may be arbitrary expressions)
    /// This is a `Vec` for the same reason as above.
    Record {
        /// key/value pairs
        pairs: Arc<Vec<(SmolStr, Expr<T>)>>,
    },
}

impl From<Value> for Expr {
    fn from(v: Value) -> Self {
        match v {
            Value::Lit(l) => Expr::val(l),
            Value::Set(s) => Expr::set(s.iter().map(|v| Expr::from(v.clone()))),
            Value::Record(fields) => Expr::record(
                fields
                    .as_ref()
                    .clone()
                    .into_iter()
                    .map(|(k, v)| (k, Expr::from(v))),
            ),
            Value::ExtensionValue(ev) => ev.as_ref().clone().into(),
        }
    }
}

impl<T> Expr<T> {
    fn new(expr_kind: ExprKind<T>, source_info: Option<SourceInfo>, data: T) -> Self {
        Self {
            expr_kind,
            source_info,
            data,
        }
    }

    /// Access the inner `ExprKind` for this `Expr`. The `ExprKind` is the
    /// `enum` which specifies the expression variant, so it must be accessed by
    /// any code matching and recursing on an expression.
    pub fn expr_kind(&self) -> &ExprKind<T> {
        &self.expr_kind
    }

    /// Access the inner `ExprKind`, taking ownership.
    pub fn into_expr_kind(self) -> ExprKind<T> {
        self.expr_kind
    }

    /// Access the data stored on the `Expr`.
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Access the data stored on the `Expr`, taking ownership.
    pub fn into_data(self) -> T {
        self.data
    }

    /// Access the data stored on the `Expr`.
    pub fn source_info(&self) -> &Option<SourceInfo> {
        &self.source_info
    }

    /// Access the data stored on the `Expr`, taking ownership.
    pub fn into_source_info(self) -> Option<SourceInfo> {
        self.source_info
    }

    /// Update the data for this `Expr`. A convenient function used by the
    /// Validator in one place.
    pub fn set_data(&mut self, data: T) {
        self.data = data;
    }

    /// Check whether this expression is an entity reference
    ///
    /// This is used for policy headers, where some syntax is
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
    /// This is used for policy headers, where some syntax is
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
    pub fn slots(&self) -> impl Iterator<Item = &SlotId> {
        self.subexpressions()
            .filter_map(|exp| match &exp.expr_kind {
                ExprKind::Slot(slotid) => Some(slotid),
                _ => None,
            })
    }

    /// Determine if the expression is projectable under partial evaluation
    /// An expression is projectable if it's guaranteed to never error on evaluation
    /// This is true if the expression is entirely composed of values or unknowns
    pub fn is_projectable(&self) -> bool {
        self.subexpressions().all(|e| match e.expr_kind() {
            ExprKind::Lit(_) => true,
            ExprKind::Unknown { .. } => true,
            ExprKind::Set(_) => true,
            ExprKind::Var(_) => true,
            ExprKind::Record { pairs } => {
                // We need to ensure there are no duplicate keys in the expression
                let uniq_keys = pairs
                    .as_ref()
                    .iter()
                    .map(|(key, _)| key)
                    .collect::<HashSet<_>>();
                pairs.len() == uniq_keys.len()
            }
            _ => false,
        })
    }
}

#[allow(dead_code)] // some constructors are currently unused, or used only in tests, but provided for completeness
#[allow(clippy::should_implement_trait)] // the names of arithmetic constructors alias with those of certain trait methods such as `add` of `std::ops::Add`
impl Expr {
    /// Create an `Expr` that's just a single `Literal`.
    ///
    /// Note that you can pass this a `Literal`, an `i64`, a `String`, etc.
    pub fn val(v: impl Into<Literal>) -> Self {
        ExprBuilder::new().val(v)
    }

    /// Create an unknown value
    pub fn unknown(name: impl Into<SmolStr>) -> Self {
        Self::unknown_with_type(name, None)
    }

    /// Create an unknown value, with an optional type annotation
    pub fn unknown_with_type(name: impl Into<SmolStr>, t: Option<Type>) -> Self {
        ExprBuilder::new().unknown(name.into(), t)
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

    /// Create a 'mul' expression. First argument must evaluate to Long type.
    pub fn mul(e: Expr, c: i64) -> Self {
        ExprBuilder::new().mul(e, c)
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

    /// Create a 'contains' expression.
    /// First argument must have Set type.
    pub fn contains(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().contains(e1, e2)
    }

    /// Create a 'contains_all' expression. Arguments must evaluate to Set type
    pub fn contains_all(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().contains_all(e1, e2)
    }

    /// Create an 'contains_any' expression. Arguments must evaluate to Set type
    pub fn contains_any(e1: Expr, e2: Expr) -> Self {
        ExprBuilder::new().contains_any(e1, e2)
    }

    /// Create an `Expr` which evaluates to a Set of the given `Expr`s
    pub fn set(exprs: impl IntoIterator<Item = Expr>) -> Self {
        ExprBuilder::new().set(exprs)
    }

    /// Create an `Expr` which evaluates to a Record with the given (key, value) pairs.
    pub fn record(pairs: impl IntoIterator<Item = (SmolStr, Expr)>) -> Self {
        ExprBuilder::new().record(pairs)
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

    /// Create an `Expr` which gets the attribute of some `Entity` or the field
    /// of some record.
    ///
    /// `expr` must evaluate to either Entity or Record type
    pub fn get_attr(expr: Expr, attr: SmolStr) -> Self {
        ExprBuilder::new().get_attr(expr, attr)
    }

    /// Create an `Expr` which tests for the existence of a given
    /// attribute on a given `Entity`, or field on a given record.
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

    /// Check if an expression contains any symbolic unknowns
    pub fn is_unknown(&self) -> bool {
        self.subexpressions()
            .any(|e| matches!(e.expr_kind(), ExprKind::Unknown { .. }))
    }

    /// Get all unknowns in an expression
    pub fn unknowns(&self) -> impl Iterator<Item = &str> {
        self.subexpressions()
            .filter_map(|subexpr| match subexpr.expr_kind() {
                ExprKind::Unknown { name, .. } => Some(name.as_str()),
                _ => None,
            })
    }

    /// Substitute unknowns with values
    /// If a definition is missing, it will be left as an unknown,
    /// and can be filled in later.
    pub fn substitute(
        &self,
        definitions: &HashMap<SmolStr, Value>,
    ) -> Result<Expr, SubstitutionError> {
        match self.expr_kind() {
            ExprKind::Lit(_) => Ok(self.clone()),
            ExprKind::Unknown {
                name,
                type_annotation,
            } => match (definitions.get(name), type_annotation) {
                (None, _) => Ok(self.clone()),
                (Some(value), None) => Ok(value.clone().into()),
                (Some(value), Some(t)) => {
                    if &value.type_of() == t {
                        Ok(value.clone().into())
                    } else {
                        Err(SubstitutionError::TypeError {
                            expected: t.clone(),
                            actual: value.type_of(),
                        })
                    }
                }
            },
            ExprKind::Var(_) => Ok(self.clone()),
            ExprKind::Slot(_) => Ok(self.clone()),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => Ok(Expr::ite(
                test_expr.substitute(definitions)?,
                then_expr.substitute(definitions)?,
                else_expr.substitute(definitions)?,
            )),
            ExprKind::And { left, right } => Ok(Expr::and(
                left.substitute(definitions)?,
                right.substitute(definitions)?,
            )),
            ExprKind::Or { left, right } => Ok(Expr::or(
                left.substitute(definitions)?,
                right.substitute(definitions)?,
            )),
            ExprKind::UnaryApp { op, arg } => {
                Ok(Expr::unary_app(*op, arg.substitute(definitions)?))
            }
            ExprKind::BinaryApp { op, arg1, arg2 } => Ok(Expr::binary_app(
                *op,
                arg1.substitute(definitions)?,
                arg2.substitute(definitions)?,
            )),
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let args = args
                    .iter()
                    .map(|e| e.substitute(definitions))
                    .collect::<Result<Vec<Expr>, _>>()?;

                Ok(Expr::call_extension_fn(fn_name.clone(), args))
            }
            ExprKind::GetAttr { expr, attr } => {
                Ok(Expr::get_attr(expr.substitute(definitions)?, attr.clone()))
            }
            ExprKind::HasAttr { expr, attr } => {
                Ok(Expr::has_attr(expr.substitute(definitions)?, attr.clone()))
            }
            ExprKind::Like { expr, pattern } => Ok(Expr::like(
                expr.substitute(definitions)?,
                pattern.iter().cloned(),
            )),
            ExprKind::Set(members) => {
                let members = members
                    .iter()
                    .map(|e| e.substitute(definitions))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Expr::set(members))
            }
            ExprKind::Record { pairs } => {
                let pairs = pairs
                    .iter()
                    .map(|(name, e)| Ok((name.clone(), e.substitute(definitions)?)))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Expr::record(pairs))
            }
            ExprKind::MulByConst { arg, constant } => {
                Ok(Expr::mul(arg.substitute(definitions)?, *constant))
            }
        }
    }
}

impl std::fmt::Display for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.expr_kind {
            // Add parenthesis around negative numeric literals otherwise
            // round-tripping fuzzer fails for expressions like `(-1)["a"]`.
            ExprKind::Lit(Literal::Long(n)) if *n < 0 => write!(f, "({})", n),
            ExprKind::Lit(l) => write!(f, "{}", l),
            ExprKind::Var(v) => write!(f, "{}", v),
            ExprKind::Unknown {
                name,
                type_annotation,
            } => match type_annotation.as_ref() {
                Some(type_annotation) => write!(f, "unknown({name:?}:{type_annotation})"),
                None => write!(f, "unknown({name})"),
            },
            ExprKind::Slot(id) => write!(f, "{id}"),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => write!(
                f,
                "if {} then {} else {}",
                maybe_with_parens(test_expr),
                maybe_with_parens(then_expr),
                maybe_with_parens(else_expr)
            ),
            ExprKind::And { left, right } => write!(
                f,
                "{} && {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprKind::Or { left, right } => write!(
                f,
                "{} || {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprKind::UnaryApp { op, arg } => match op {
                UnaryOp::Not => write!(f, "!{}", maybe_with_parens(arg)),
                // Always add parentheses instead of calling
                // `maybe_with_parens`.
                // This makes sure that we always get a negation operation back
                // (as opposed to e.g., a negative number) when parsing the
                // printed form, thus preserving the round-tripping property.
                UnaryOp::Neg => write!(f, "-({})", arg),
            },
            ExprKind::BinaryApp { op, arg1, arg2 } => match op {
                BinaryOp::Eq => write!(
                    f,
                    "{} == {}",
                    maybe_with_parens(arg1),
                    maybe_with_parens(arg2),
                ),
                BinaryOp::Less => write!(
                    f,
                    "{} < {}",
                    maybe_with_parens(arg1),
                    maybe_with_parens(arg2),
                ),
                BinaryOp::LessEq => write!(
                    f,
                    "{} <= {}",
                    maybe_with_parens(arg1),
                    maybe_with_parens(arg2),
                ),
                BinaryOp::Add => write!(
                    f,
                    "{} + {}",
                    maybe_with_parens(arg1),
                    maybe_with_parens(arg2),
                ),
                BinaryOp::Sub => write!(
                    f,
                    "{} - {}",
                    maybe_with_parens(arg1),
                    maybe_with_parens(arg2),
                ),
                BinaryOp::In => write!(
                    f,
                    "{} in {}",
                    maybe_with_parens(arg1),
                    maybe_with_parens(arg2),
                ),
                BinaryOp::Contains => {
                    write!(f, "{}.contains({})", maybe_with_parens(arg1), &arg2)
                }
                BinaryOp::ContainsAll => {
                    write!(f, "{}.containsAll({})", maybe_with_parens(arg1), &arg2)
                }
                BinaryOp::ContainsAny => {
                    write!(f, "{}.containsAny({})", maybe_with_parens(arg1), &arg2)
                }
            },
            ExprKind::MulByConst { arg, constant } => {
                write!(f, "{} * {}", maybe_with_parens(arg), constant)
            }
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                // search for the name and callstyle
                let style = Extensions::all_available().all_funcs().find_map(|f| {
                    if f.name() == fn_name {
                        Some(f.style())
                    } else {
                        None
                    }
                });
                // PANIC SAFETY Args list must be non empty by INVARIANT (MethodStyleArgs)
                #[allow(clippy::indexing_slicing)]
                if matches!(style, Some(CallStyle::MethodStyle)) && !args.is_empty() {
                    write!(
                        f,
                        "{}.{}({})",
                        maybe_with_parens(&args[0]),
                        fn_name,
                        args[1..].iter().join(", ")
                    )
                } else {
                    // This case can only be reached for a manually constructed AST.
                    // In order to reach this case, either the function name `fn_name`
                    // is not in the list of available extension functions, or this
                    // is a method-style function call with zero arguments. Both of
                    // these cases can be displayed, but neither will parse. The
                    // resulting `ParseError` will be `NotAFunction`.
                    write!(f, "{}({})", fn_name, args.iter().join(", "))
                }
            }
            ExprKind::GetAttr { expr, attr } => write!(
                f,
                "{}[\"{}\"]",
                maybe_with_parens(expr),
                attr.escape_debug()
            ),
            ExprKind::HasAttr { expr, attr } => {
                write!(
                    f,
                    "{} has \"{}\"",
                    maybe_with_parens(expr),
                    attr.escape_debug()
                )
            }
            ExprKind::Like { expr, pattern } => {
                // during parsing we convert \* in the pattern into \u{0000},
                // so when printing we need to convert back
                write!(f, "{} like \"{}\"", maybe_with_parens(expr), pattern,)
            }
            ExprKind::Set(v) => write!(f, "[{}]", v.iter().join(", ")),
            ExprKind::Record { pairs } => write!(
                f,
                "{{{}}}",
                pairs
                    .iter()
                    .map(|(k, v)| format!("\"{}\": {}", k.escape_debug(), v))
                    .join(", ")
            ),
        }
    }
}

/// returns the `Display` representation of the Expr, adding parens around the
/// entire Expr if necessary.
/// E.g., won't add parens for constants or `principal` etc, but will for things
/// like `(2 < 5)`.
/// When in doubt, add the parens.
fn maybe_with_parens(expr: &Expr) -> String {
    match expr.expr_kind {
        ExprKind::Lit(_) => expr.to_string(),
        ExprKind::Var(_) => expr.to_string(),
        ExprKind::Unknown { .. } => expr.to_string(),
        ExprKind::Slot(_) => expr.to_string(),
        ExprKind::If { .. } => format!("({})", expr),
        ExprKind::And { .. } => format!("({})", expr),
        ExprKind::Or { .. } => format!("({})", expr),
        ExprKind::UnaryApp {
            op: UnaryOp::Not | UnaryOp::Neg,
            ..
        } => {
            // we want parens here because things like parse((!x).y)
            // would be printed into !x.y which has a different meaning,
            // albeit being semantically incorrect.
            format!("({})", expr)
        }
        ExprKind::BinaryApp { .. } => format!("({})", expr),
        ExprKind::MulByConst { .. } => format!("({})", expr),
        ExprKind::ExtensionFunctionApp { .. } => format!("({})", expr),
        ExprKind::GetAttr { .. } => format!("({})", expr),
        ExprKind::HasAttr { .. } => format!("({})", expr),
        ExprKind::Like { .. } => format!("({})", expr),
        ExprKind::Set { .. } => expr.to_string(),
        ExprKind::Record { .. } => expr.to_string(),
    }
}

impl std::str::FromStr for Expr {
    type Err = ParseErrors;

    fn from_str(s: &str) -> Result<Expr, Self::Err> {
        crate::parser::parse_expr(s)
    }
}

/// Enum for errors encountered during substitution
#[derive(Debug, Clone, Error)]
pub enum SubstitutionError {
    /// The supplied value did not match the type annotation on the unknown.
    #[error("Expected a value of type {expected}, got a value of type {actual}")]
    TypeError {
        /// The expected type, ie: the type the unknown was annotated with
        expected: Type,
        /// The type of the provided value
        actual: Type,
    },
}

/// Builder for constructing `Expr` objects annotated with some `data`
/// (possibly taking default value) and optional some `source_info`.
#[derive(Debug)]
pub struct ExprBuilder<T> {
    source_info: Option<SourceInfo>,
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
            source_info: None,
            data: T::default(),
        }
    }

    /// Create a '!=' expression.
    /// Defined only for `T: Default` because the caller would otherwise need to
    /// provide a `data` for the intermediate `not` Expr node.
    pub fn noteq(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        match &self.source_info {
            Some(source_info) => ExprBuilder::new().with_source_info(source_info.clone()),
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
    /// the `Expr`. This constructor does not populate the `source_info` field,
    /// so `with_source_info` should be called if constructing an `Expr` where
    /// the source location is known.
    pub fn with_data(data: T) -> Self {
        Self {
            source_info: None,
            data,
        }
    }

    /// Update the `ExprBuilder` to build an expression with some known location
    /// in policy source code.
    pub fn with_source_info(self, source_info: SourceInfo) -> Self {
        self.with_maybe_source_info(Some(source_info))
    }

    /// Utility used the validator to get an expression with the same source
    /// location as an existing expression. This is done when reconstructing the
    /// `Expr` with type information.
    pub fn with_same_source_info<U>(self, expr: &Expr<U>) -> Self {
        self.with_maybe_source_info(expr.source_info.clone())
    }

    /// internally used to update SourceInfo to the given `Some` or `None`
    fn with_maybe_source_info(mut self, maybe_source_info: Option<SourceInfo>) -> Self {
        self.source_info = maybe_source_info;
        self
    }

    /// Internally used by the following methods to construct an `Expr`
    /// containing the `data` and `source_info` in this `ExprBuilder` with some
    /// inner `ExprKind`.
    fn with_expr_kind(self, expr_kind: ExprKind<T>) -> Expr<T> {
        Expr::new(expr_kind, self.source_info, self.data)
    }

    /// Create an `Expr` that's just a single `Literal`.
    ///
    /// Note that you can pass this a `Literal`, an `i64`, a `String`, etc.
    pub fn val(self, v: impl Into<Literal>) -> Expr<T> {
        self.with_expr_kind(ExprKind::Lit(v.into()))
    }

    /// Create an `Unknown` `Expr`
    pub fn unknown(self, name: impl Into<SmolStr>, type_annotation: Option<Type>) -> Expr<T> {
        self.with_expr_kind(ExprKind::Unknown {
            name: name.into(),
            type_annotation,
        })
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

    /// Create a '>' expression. Arguments must evaluate to Long type
    pub fn greater(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.less(e2, e1)
    }

    /// Create a '>=' expression. Arguments must evaluate to Long type
    pub fn greatereq(self, e1: Expr<T>, e2: Expr<T>) -> Expr<T> {
        self.lesseq(e2, e1)
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

    /// Create a 'mul' expression. First argument must evaluate to Long type.
    pub fn mul(self, e: Expr<T>, c: i64) -> Expr<T> {
        self.with_expr_kind(ExprKind::MulByConst {
            arg: Arc::new(e),
            constant: c,
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

    /// Create an `Expr` which evaluates to a Set of the given `Expr`s
    pub fn set(self, exprs: impl IntoIterator<Item = Expr<T>>) -> Expr<T> {
        self.with_expr_kind(ExprKind::Set(Arc::new(exprs.into_iter().collect())))
    }

    /// Create an `Expr` which evaluates to a Record with the given (key, value) pairs.
    pub fn record(self, pairs: impl IntoIterator<Item = (SmolStr, Expr<T>)>) -> Expr<T> {
        self.with_expr_kind(ExprKind::Record {
            pairs: Arc::new(pairs.into_iter().collect()),
        })
    }

    /// Create an `Expr` which calls the extension function with the given
    /// `Name` on `args`
    pub fn call_extension_fn(self, fn_name: Name, args: Vec<Expr<T>>) -> Expr<T> {
        self.with_expr_kind(ExprKind::ExtensionFunctionApp {
            fn_name,
            args: Arc::new(args),
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

    /// Create an `Expr` which gets the attribute of some `Entity` or the field
    /// of some record.
    ///
    /// `expr` must evaluate to either Entity or Record type
    pub fn get_attr(self, expr: Expr<T>, attr: SmolStr) -> Expr<T> {
        self.with_expr_kind(ExprKind::GetAttr {
            expr: Arc::new(expr),
            attr,
        })
    }

    /// Create an `Expr` which tests for the existence of a given
    /// attribute on a given `Entity`, or field on a given record.
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
}

impl<T: Clone> ExprBuilder<T> {
    /// Create an `and` expression that may have more than two subexpressions (A && B && C)
    /// or may have only one subexpression, in which case no `&&` is performed at all.
    /// Arguments must evaluate to Bool type.
    ///
    /// This may create multiple AST `&&` nodes. If it does, all the nodes will have the same
    /// source location and the same `T` data (taken from this builder) unless overridden, e.g.,
    /// with another call to `with_source_info()`.
    pub fn and_nary(self, first: Expr<T>, others: impl IntoIterator<Item = Expr<T>>) -> Expr<T> {
        others.into_iter().fold(first, |acc, next| {
            Self::with_data(self.data.clone())
                .with_maybe_source_info(self.source_info.clone())
                .and(acc, next)
        })
    }

    /// Create an `or` expression that may have more than two subexpressions (A || B || C)
    /// or may have only one subexpression, in which case no `||` is performed at all.
    /// Arguments must evaluate to Bool type.
    ///
    /// This may create multiple AST `||` nodes. If it does, all the nodes will have the same
    /// source location and the same `T` data (taken from this builder) unless overridden, e.g.,
    /// with another call to `with_source_info()`.
    pub fn or_nary(self, first: Expr<T>, others: impl IntoIterator<Item = Expr<T>>) -> Expr<T> {
        others.into_iter().fold(first, |acc, next| {
            Self::with_data(self.data.clone())
                .with_maybe_source_info(self.source_info.clone())
                .or(acc, next)
        })
    }
}

/// A new type wrapper around `Expr` that provides `Eq` and `Hash`
/// implementations that ignore any source information or other generic data
/// used to annotate the `Expr`.
#[derive(Eq, Debug, Clone)]
pub struct ExprShapeOnly<'a, T = ()>(&'a Expr<T>);

impl<'a, T> ExprShapeOnly<'a, T> {
    /// Construct an `ExprShapeOnly` from an `Expr`. The `Expr` is not modified,
    /// but any comparisons on the resulting `ExprShapeOnly` will ignore source
    /// information and generic data.
    pub fn new(e: &'a Expr<T>) -> ExprShapeOnly<'a, T> {
        ExprShapeOnly(e)
    }
}

impl<'a, T> PartialEq for ExprShapeOnly<'a, T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_shape(other.0)
    }
}

impl<'a, T> Hash for ExprShapeOnly<'a, T> {
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
            (Lit(l), Lit(l1)) => l == l1,
            (Var(v), Var(v1)) => v == v1,
            (Slot(s), Slot(s1)) => s == s1,
            (
                Unknown {
                    name: name1,
                    type_annotation: ta_1,
                },
                Unknown {
                    name: name2,
                    type_annotation: ta_2,
                },
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
                MulByConst { arg, constant },
                MulByConst {
                    arg: arg1,
                    constant: constant1,
                },
            ) => constant == constant1 && arg.eq_shape(arg1),
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
            (Record { pairs }, Record { pairs: pairs1 }) => pairs
                .iter()
                .zip(pairs1.iter())
                .all(|((a, e), (a1, e1))| a == a1 && e.eq_shape(e1)),
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
            ExprKind::Lit(l) => l.hash(state),
            ExprKind::Var(v) => v.hash(state),
            ExprKind::Slot(s) => s.hash(state),
            ExprKind::Unknown {
                name,
                type_annotation,
            } => {
                name.hash(state);
                type_annotation.hash(state);
            }
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
            ExprKind::MulByConst { arg, constant } => {
                arg.hash_shape(state);
                constant.hash(state);
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
            ExprKind::Record { pairs } => {
                state.write_usize(pairs.len());
                pairs.iter().for_each(|(s, a)| {
                    s.hash(state);
                    a.hash_shape(state);
                });
            }
        }
    }
}

/// AST variables
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Var {
    /// the Principal of the given request
    #[serde(rename = "principal")]
    Principal,
    /// the Action of the given request
    #[serde(rename = "action")]
    Action,
    /// the Resource of the given request
    #[serde(rename = "resource")]
    Resource,
    /// the Context of the given request
    #[serde(rename = "context")]
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
    use std::{
        collections::{hash_map::DefaultHasher, HashSet},
        sync::Arc,
    };

    use super::{var_generator::all_vars, *};

    // Tests that Var::Into never panics
    #[test]
    fn all_vars_are_ids() {
        for var in all_vars() {
            let _id: Id = var.into();
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
        let set: HashSet<&SlotId> = [&p].into_iter().collect();
        assert_eq!(set, e.slots().collect::<HashSet<_>>());
        let e = Expr::or(
            Expr::slot(SlotId::principal()),
            Expr::ite(
                Expr::val(true),
                Expr::slot(SlotId::resource()),
                Expr::val(false),
            ),
        );
        let set: HashSet<&SlotId> = [&p, &r].into_iter().collect();
        assert_eq!(set, e.slots().collect::<HashSet<_>>());
    }

    #[test]
    fn unknowns() {
        let e = Expr::ite(
            Expr::not(Expr::unknown("a".to_string())),
            Expr::and(Expr::unknown("b".to_string()), Expr::val(3)),
            Expr::unknown("c".to_string()),
        );
        let unknowns = e.unknowns().collect_vec();
        assert_eq!(unknowns.len(), 3);
        assert!(unknowns.contains(&"a"));
        assert!(unknowns.contains(&"b"));
        assert!(unknowns.contains(&"c"));
    }

    #[test]
    fn is_unknown() {
        let e = Expr::ite(
            Expr::not(Expr::unknown("a".to_string())),
            Expr::and(Expr::unknown("b".to_string()), Expr::val(3)),
            Expr::unknown("c".to_string()),
        );
        assert!(e.is_unknown());
        let e = Expr::ite(
            Expr::not(Expr::val(true)),
            Expr::and(Expr::val(1), Expr::val(3)),
            Expr::val(1),
        );
        assert!(!e.is_unknown());
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
                ExprBuilder::with_data(1).mul(temp.clone(), 1),
                Expr::mul(Expr::val(1), 1),
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
                ExprBuilder::with_data(1).record([("foo".into(), temp.clone())]),
                Expr::record([("foo".into(), Expr::val(1))]),
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
                ExprBuilder::with_data(1).like(temp, vec![PatternElem::Wildcard]),
                Expr::like(Expr::val(1), vec![PatternElem::Wildcard]),
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
        assert_ne!(ExprShapeOnly::new(&expr1), ExprShapeOnly::new(&expr2));
    }
}
