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

//! This module contains the residual.

use std::collections::HashSet;
use std::{collections::BTreeMap, sync::Arc};

use crate::ast::{Annotations, Effect, EntityUID, Literal, Policy, PolicyID, ValueKind};
use crate::validator::types::Type;
use crate::{
    ast::{self, BinaryOp, EntityType, Expr, Name, Pattern, UnaryOp, Value, Var},
    expr_builder::ExprBuilder,
};
use smol_str::SmolStr;

/// The residual produced by TPE
#[derive(Debug, Clone)]
pub enum Residual {
    /// TPE produces a partial expression
    Partial {
        /// The kind of partial expression
        kind: ResidualKind,
        /// Type of the partial expression
        ty: Type,
    },
    /// TPE produces a concrete value
    Concrete {
        /// The concrete value
        value: Value,
        /// Type of the value
        ty: Type,
    },
    /// TPE produces a (typed) error
    /// Evaluating the residual of this variant always produces an evaluation
    /// error. The error kind does not matter for the sake of re-authorization.
    Error(Type),
}

impl Residual {
    /// Construct a residual policy
    pub fn to_policy(self, id: PolicyID, effect: Effect, annotations: Annotations) -> Policy {
        Policy::from_when_clause_annos(
            effect,
            Arc::new(self.into()),
            id,
            None,
            Arc::new(annotations),
        )
    }

    /// All literal uids referenced by this template
    pub fn all_literal_uids(&self) -> HashSet<EntityUID> {
        todo!()
    }

    /// Returns whether or not this residual is a concrete value
    pub fn is_concrete(&self) -> bool {
        todo!()
    }

    pub fn ty(&self) -> &Type {
        match self {
            Residual::Partial { ty, .. } => ty,
            Residual::Concrete { ty, .. } => ty,
            Residual::Error(ty) => ty,
        }
    }

    pub fn from_expr(value: &Expr<Option<Type>>) -> std::result::Result<Self, ()> {
        match value {
            _ => todo!(),
        }
    }
}

impl TryFrom<Residual> for Value {
    type Error = ();
    fn try_from(value: Residual) -> std::result::Result<Self, Self::Error> {
        match value {
            Residual::Concrete { value, .. } => Ok(value),
            _ => Err(()),
        }
    }
}

/// The kind of partial expression
#[derive(Debug, Clone)]
pub enum ResidualKind {
    /// Variable
    Var(Var),
    /// If-then-else expression
    If {
        /// Condition for the ternary expression. Must evaluate to Bool type
        test_expr: Arc<Residual>,
        /// Value if true
        then_expr: Arc<Residual>,
        /// Value if false
        else_expr: Arc<Residual>,
    },
    /// Boolean AND
    And {
        /// Left operand, which will be eagerly evaluated
        left: Arc<Residual>,
        /// Right operand, which may not be evaluated due to short-circuiting
        right: Arc<Residual>,
    },
    /// Boolean OR
    Or {
        /// Left operand, which will be eagerly evaluated
        left: Arc<Residual>,
        /// Right operand, which may not be evaluated due to short-circuiting
        right: Arc<Residual>,
    },
    /// Application of a built-in unary operator (single parameter)
    UnaryApp {
        /// Unary operator to apply
        op: UnaryOp,
        /// Argument to apply operator to
        arg: Arc<Residual>,
    },
    /// Application of a built-in binary operator (two parameters)
    BinaryApp {
        /// Binary operator to apply
        op: BinaryOp,
        /// First arg
        arg1: Arc<Residual>,
        /// Second arg
        arg2: Arc<Residual>,
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
        args: Arc<Vec<Residual>>,
    },
    /// Get an attribute of an entity, or a field of a record
    GetAttr {
        /// Expression to get an attribute/field of. Must evaluate to either
        /// Entity or Record type
        expr: Arc<Residual>,
        /// Attribute or field to get
        attr: SmolStr,
    },
    /// Does the given `expr` have the given `attr`?
    HasAttr {
        /// Expression to test. Must evaluate to either Entity or Record type
        expr: Arc<Residual>,
        /// Attribute or field to check for
        attr: SmolStr,
    },
    /// Regex-like string matching similar to IAM's `StringLike` operator.
    Like {
        /// Expression to test. Must evaluate to String type
        expr: Arc<Residual>,
        /// Pattern to match on; can include the wildcard *, which matches any string.
        /// To match a literal `*` in the test expression, users can use `\*`.
        /// Be careful the backslash in `\*` must not be another escape sequence. For instance, `\\*` matches a backslash plus an arbitrary string.
        pattern: Pattern,
    },
    /// Entity type test. Does the first argument have the entity type
    /// specified by the second argument.
    Is {
        /// Expression to test. Must evaluate to an Entity.
        expr: Arc<Residual>,
        /// The [`EntityType`] used for the type membership test.
        entity_type: EntityType,
    },
    /// Set (whose elements may be arbitrary expressions)
    //
    // This is backed by `Vec` (and not e.g. `HashSet`), because two `Expr`s
    // that are syntactically unequal, may actually be semantically equal --
    // i.e., we can't do the dedup of duplicates until all of the `Expr`s are
    // evaluated into `Value`s
    Set(Arc<Vec<Residual>>),
    /// Anonymous record (whose elements may be arbitrary expressions)
    Record(Arc<BTreeMap<SmolStr, Residual>>),
}

impl Residual {
    /// If a residual is trivially true
    pub fn is_true(&self) -> bool {
        matches!(
            self,
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        )
    }

    /// If a residual is trivially false
    pub fn is_false(&self) -> bool {
        matches!(
            self,
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(false)),
                    ..
                },
                ..
            }
        )
    }
}

/// Conversion from `Residual` to `Expr` so that we can use the concrete evaluator for re-authorization
// PANIC SAFETY: Residual to Expr conversion should always succeed
#[allow(clippy::fallible_impl_from)]
impl From<Residual> for Expr {
    fn from(value: Residual) -> Expr {
        match value {
            Residual::Partial { kind, .. } => {
                let builder: ast::ExprBuilder<()> = ExprBuilder::with_data(());
                match kind {
                    ResidualKind::And { left, right } => {
                        builder.and(left.as_ref().clone().into(), right.as_ref().clone().into())
                    }
                    ResidualKind::BinaryApp { op, arg1, arg2 } => builder.binary_app(
                        op,
                        arg1.as_ref().clone().into(),
                        arg2.as_ref().clone().into(),
                    ),
                    ResidualKind::ExtensionFunctionApp { fn_name, args } => builder
                        .call_extension_fn(
                            fn_name,
                            args.as_ref()
                                .clone()
                                .into_iter()
                                .map(|arg| arg.into())
                                .collect::<Vec<_>>(),
                        ),
                    ResidualKind::GetAttr { expr, attr } => {
                        builder.get_attr(expr.as_ref().clone().into(), attr)
                    }
                    ResidualKind::HasAttr { expr, attr } => {
                        builder.has_attr(expr.as_ref().clone().into(), attr)
                    }
                    ResidualKind::If {
                        test_expr,
                        then_expr,
                        else_expr,
                    } => builder.ite(
                        test_expr.as_ref().clone().into(),
                        then_expr.as_ref().clone().into(),
                        else_expr.as_ref().clone().into(),
                    ),
                    ResidualKind::Is { expr, entity_type } => {
                        builder.is_entity_type(expr.as_ref().clone().into(), entity_type)
                    }
                    ResidualKind::Like { expr, pattern } => {
                        builder.like(expr.as_ref().clone().into(), pattern)
                    }
                    ResidualKind::Or { left, right } => {
                        builder.or(left.as_ref().clone().into(), right.as_ref().clone().into())
                    }
                    // PANIC SAFETY: record construction should succeed
                    #[allow(clippy::expect_used)]
                    ResidualKind::Record(map) => builder
                        .record(map.as_ref().clone().into_iter().map(|(k, v)| (k, v.into())))
                        .expect("should succeed"),
                    ResidualKind::Set(set) => builder.set(
                        set.as_ref()
                            .clone()
                            .into_iter()
                            .map(|v| v.into())
                            .collect::<Vec<_>>(),
                    ),
                    ResidualKind::UnaryApp { op, arg } => {
                        builder.unary_app(op, arg.as_ref().clone().into())
                    }
                    ResidualKind::Var(v) => builder.var(v),
                }
            }
            Residual::Concrete { value, .. } => value.into(),
            Residual::Error(_) => {
                let builder: ast::ExprBuilder<()> = ExprBuilder::with_data(());
                // PANIC SAFETY: `error` is a valid `Name`
                #[allow(clippy::unwrap_used)]
                builder.call_extension_fn("error".parse().unwrap(), std::iter::empty())
            }
        }
    }
}
