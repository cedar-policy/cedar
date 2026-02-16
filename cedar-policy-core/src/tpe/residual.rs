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
use crate::evaluator::EvaluationError;
use crate::parser::Loc;
#[cfg(feature = "tolerant-ast")]
use crate::tpe::err::ErrorNotSupportedError;
use crate::tpe::err::{
    ExprToResidualError, MissingTypeAnnotationError, SlotNotSupportedError,
    UnknownNotSupportedError,
};
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
        /// The source location of the expression
        source_loc: Option<Loc>,
        /// Return type of the partial expression
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
    /// error. The TPE error should equal the error from concrete evaluation.
    Error {
        /// The error that occurred during TPE evaluation.
        err: EvaluationError,
        /// Return type of the partial expression before the error
        ty: Type,
    },
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

    /// All literal uids referenced by this residual
    pub fn all_literal_uids(&self) -> HashSet<EntityUID> {
        match self {
            Residual::Partial { kind, .. } => kind.all_literal_uids(),
            Residual::Concrete { value, .. } => value.all_literal_uids(),
            Residual::Error { .. } => HashSet::new(),
        }
    }

    /// Get the type of this residual
    pub fn ty(&self) -> &Type {
        match self {
            Residual::Partial { ty, .. } => ty,
            Residual::Concrete { ty, .. } => ty,
            Residual::Error { ty, .. } => ty,
        }
    }

    /// Whether this residual can result in a runtime error, assuming that self is well-formed, that is, has been validated against a schema.
    pub fn can_error_assuming_well_formed(&self) -> bool {
        match self {
            Residual::Concrete { .. } => false,
            Residual::Error { .. } => true,
            Residual::Partial { kind, .. } => match kind {
                // Keep the same order of cases here as in tpe::Evaluator::interpret
                ResidualKind::Var(_) => false,
                // The general rule here is that an expression can only error if any child expression can error.
                ResidualKind::And { left, right } => {
                    left.can_error_assuming_well_formed() || right.can_error_assuming_well_formed()
                }
                ResidualKind::Or { left, right } => {
                    left.can_error_assuming_well_formed() || right.can_error_assuming_well_formed()
                }
                ResidualKind::If {
                    test_expr,
                    then_expr,
                    else_expr,
                } => {
                    test_expr.can_error_assuming_well_formed()
                        || then_expr.can_error_assuming_well_formed()
                        || else_expr.can_error_assuming_well_formed()
                }
                ResidualKind::Is { expr, .. } => expr.can_error_assuming_well_formed(),
                ResidualKind::Like { expr, .. } => expr.can_error_assuming_well_formed(),

                ResidualKind::BinaryApp { op, arg1, arg2 } => match op {
                    // Arithmetic operations could error due to integer overflow
                    ast::BinaryOp::Add => true,
                    ast::BinaryOp::Mul => true,
                    ast::BinaryOp::Sub => true,

                    // <entityUID>.getTag possibly errors during reauthorization if <entityUID> does not exist in the entity store
                    ast::BinaryOp::GetTag => true,

                    // Other binary operations follow the general rule. They are all enumerated here for clarity, although
                    // a _ case could be used.
                    ast::BinaryOp::Contains
                    | ast::BinaryOp::ContainsAll
                    | ast::BinaryOp::ContainsAny
                    | ast::BinaryOp::Eq
                    | ast::BinaryOp::HasTag
                    | ast::BinaryOp::In
                    | ast::BinaryOp::Less
                    | ast::BinaryOp::LessEq => {
                        arg1.can_error_assuming_well_formed()
                            || arg2.can_error_assuming_well_formed()
                    }
                },

                // Extension function invocations can error at runtime.
                ResidualKind::ExtensionFunctionApp { .. } => true,
                // <entityUID>.<attr> possibly errors during reauthorization if <entityUID> does not exist in the entity store
                ResidualKind::GetAttr { .. } => true,

                ResidualKind::HasAttr { expr, .. } => expr.can_error_assuming_well_formed(),

                ResidualKind::UnaryApp { op, arg } => match op {
                    // Integer negation can error due to integer overflow
                    ast::UnaryOp::Neg => true,

                    // General rule for the rest of the unary operations.
                    ast::UnaryOp::IsEmpty | ast::UnaryOp::Not => {
                        arg.can_error_assuming_well_formed()
                    }
                },
                ResidualKind::Set(items) => items.iter().any(Self::can_error_assuming_well_formed),
                ResidualKind::Record(attrs) => attrs
                    .iter()
                    .any(|(_, e)| e.can_error_assuming_well_formed()),
            },
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

impl TryFrom<&Expr<Option<Type>>> for Residual {
    type Error = ExprToResidualError;
    fn try_from(expr: &Expr<Option<Type>>) -> std::result::Result<Self, ExprToResidualError> {
        let ty = expr.data().clone().ok_or(MissingTypeAnnotationError)?;

        // Otherwise, convert to a partial residual
        let kind = match expr.expr_kind() {
            ast::ExprKind::Var(var) => ResidualKind::Var(*var),
            ast::ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => ResidualKind::If {
                test_expr: Arc::new(Self::try_from(test_expr.as_ref())?),
                then_expr: Arc::new(Self::try_from(then_expr.as_ref())?),
                else_expr: Arc::new(Self::try_from(else_expr.as_ref())?),
            },
            ast::ExprKind::And { left, right } => ResidualKind::And {
                left: Arc::new(Self::try_from(left.as_ref())?),
                right: Arc::new(Self::try_from(right.as_ref())?),
            },
            ast::ExprKind::Or { left, right } => ResidualKind::Or {
                left: Arc::new(Self::try_from(left.as_ref())?),
                right: Arc::new(Self::try_from(right.as_ref())?),
            },
            ast::ExprKind::UnaryApp { op, arg } => ResidualKind::UnaryApp {
                op: *op,
                arg: Arc::new(Self::try_from(arg.as_ref())?),
            },
            ast::ExprKind::BinaryApp { op, arg1, arg2 } => ResidualKind::BinaryApp {
                op: *op,
                arg1: Arc::new(Self::try_from(arg1.as_ref())?),
                arg2: Arc::new(Self::try_from(arg2.as_ref())?),
            },
            ast::ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let residual_args: Result<Vec<_>, _> = args.iter().map(Self::try_from).collect();
                ResidualKind::ExtensionFunctionApp {
                    fn_name: fn_name.clone(),
                    args: Arc::new(residual_args?),
                }
            }
            ast::ExprKind::GetAttr { expr, attr } => ResidualKind::GetAttr {
                expr: Arc::new(Self::try_from(expr.as_ref())?),
                attr: attr.clone(),
            },
            ast::ExprKind::HasAttr { expr, attr } => ResidualKind::HasAttr {
                expr: Arc::new(Self::try_from(expr.as_ref())?),
                attr: attr.clone(),
            },
            ast::ExprKind::Like { expr, pattern } => ResidualKind::Like {
                expr: Arc::new(Self::try_from(expr.as_ref())?),
                pattern: pattern.clone(),
            },
            ast::ExprKind::Is { expr, entity_type } => ResidualKind::Is {
                expr: Arc::new(Self::try_from(expr.as_ref())?),
                entity_type: entity_type.clone(),
            },
            ast::ExprKind::Set(elements) => {
                let residual_elements: Result<Vec<_>, _> =
                    elements.iter().map(Self::try_from).collect();
                ResidualKind::Set(Arc::new(residual_elements?))
            }
            ast::ExprKind::Record(map) => {
                let residual_map: Result<BTreeMap<_, _>, ExprToResidualError> = map
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), Self::try_from(v)?)))
                    .collect();
                ResidualKind::Record(Arc::new(residual_map?))
            }
            // Literals should be converted to concrete values
            ast::ExprKind::Lit(lit) => {
                let value = Value::new(lit.clone(), None);
                return Ok(Residual::Concrete { value, ty });
            }
            // These are not supported in residuals
            ast::ExprKind::Slot(_) => return Err(SlotNotSupportedError.into()),
            ast::ExprKind::Unknown(_) => return Err(UnknownNotSupportedError.into()),
            #[cfg(feature = "tolerant-ast")]
            ast::ExprKind::Error { .. } => {
                return Err(ErrorNotSupportedError.into());
            }
        };

        Ok(Residual::Partial {
            kind,
            ty,
            source_loc: expr.source_loc().cloned(),
        })
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

impl ResidualKind {
    /// All literal uids referenced by this residual kind
    pub fn all_literal_uids(&self) -> HashSet<EntityUID> {
        match self {
            ResidualKind::Var(_) => HashSet::new(),
            ResidualKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                let mut uids = test_expr.all_literal_uids();
                uids.extend(then_expr.all_literal_uids());
                uids.extend(else_expr.all_literal_uids());
                uids
            }
            ResidualKind::And { left, right } | ResidualKind::Or { left, right } => {
                let mut uids = left.all_literal_uids();
                uids.extend(right.all_literal_uids());
                uids
            }
            ResidualKind::UnaryApp { arg, .. } => arg.all_literal_uids(),
            ResidualKind::BinaryApp { arg1, arg2, .. } => {
                let mut uids = arg1.all_literal_uids();
                uids.extend(arg2.all_literal_uids());
                uids
            }
            ResidualKind::ExtensionFunctionApp { args, .. } => {
                let mut uids = HashSet::new();
                for arg in args.as_ref() {
                    uids.extend(arg.all_literal_uids());
                }
                uids
            }
            ResidualKind::GetAttr { expr, .. }
            | ResidualKind::HasAttr { expr, .. }
            | ResidualKind::Like { expr, .. }
            | ResidualKind::Is { expr, .. } => expr.all_literal_uids(),
            ResidualKind::Set(elements) => {
                let mut uids = HashSet::new();
                for element in elements.as_ref() {
                    uids.extend(element.all_literal_uids());
                }
                uids
            }
            ResidualKind::Record(map) => {
                let mut uids = HashSet::new();
                for value in map.values() {
                    uids.extend(value.all_literal_uids());
                }
                uids
            }
        }
    }
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

    /// If a residual is an error
    pub fn is_error(&self) -> bool {
        matches!(self, Residual::Error { .. })
    }
}

/// Conversion from `Residual` to `Expr` so that we can use the concrete evaluator for re-authorization
#[expect(
    clippy::fallible_impl_from,
    reason = "Residual to Expr conversion should always succeed"
)]
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
                    #[expect(clippy::expect_used, reason = "record construction should succeed")]
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
            Residual::Error { .. } => {
                let builder: ast::ExprBuilder<()> = ExprBuilder::with_data(());
                #[expect(clippy::unwrap_used, reason = "`error` is a valid `Name`")]
                builder.call_extension_fn("error".parse().unwrap(), std::iter::empty())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::test_utils::parse_residual;
    use super::*;
    use crate::validator::types::BoolType;
    use similar_asserts::assert_eq;

    #[test]
    fn test_can_error_assuming_well_formed() {
        // Most common LHS, the policy header
        assert_eq!(
            parse_residual(
                r#"
                principal is User &&
                principal in Organization::"foo" && 
                action == Action::"get" && 
                resource is Document && 
                resource in Organization::"foo"
                "#
            )
            .can_error_assuming_well_formed(),
            false
        );
        assert_eq!(
            parse_residual(r#"User::"jane" in [User::"foo", User::"jane"]"#)
                .can_error_assuming_well_formed(),
            false
        );
        assert_eq!(
            parse_residual(r#"principal has foo || principal.hasTag("foo")"#)
                .can_error_assuming_well_formed(),
            false
        );
        assert_eq!(
            parse_residual(r#"principal == resource && !(principal in Organization::"foo")"#)
                .can_error_assuming_well_formed(),
            false
        );
        assert_eq!(
            parse_residual(
                r#"
                if principal.hasTag("foo") then 
                    principal in Organization::"foo" 
                else principal in Organization::"bar"
                "#
            )
            .can_error_assuming_well_formed(),
            false
        );
        assert_eq!(
            parse_residual(
                r#"
                1 == 2 || 
                !("a" == "b") && 
                ["a", "b"].contains("a") && 
                !["a", "b"].containsAll(["a"]) && 
                ["a", "b"].containsAny(["a"])
                "#
            )
            .can_error_assuming_well_formed(),
            false
        );
        assert_eq!(
            parse_residual(r#"{a: true, b: false}["a"] && false"#).can_error_assuming_well_formed(),
            true
        );
        assert_eq!(
            parse_residual(r#"User::"jane".str like "jane-*""#).can_error_assuming_well_formed(),
            true
        );
        assert_eq!(
            parse_residual(
                r#"if principal.num > 0 then User::"jane".num >= 100 else User::"foo".num == 1"#
            )
            .can_error_assuming_well_formed(),
            true
        );
        assert_eq!(
            parse_residual(r#"principal.hasTag("foo") && principal.getTag("foo") == "bar""#)
                .can_error_assuming_well_formed(),
            true
        );
        assert_eq!(
            parse_residual(
                r#"
                !principal.set.isEmpty() && (
                    principal.set.contains("foo") || 
                    principal.set.containsAll(["foo", "bar"]) || 
                    principal.set.containsAny(["foo", "bar"])
                )"#
            )
            .can_error_assuming_well_formed(),
            true
        );
        assert_eq!(
            parse_residual(r#"principal.num + 1 == 100 || true"#).can_error_assuming_well_formed(),
            true
        );
        assert_eq!(
            parse_residual(r#"if principal.foo then principal.num - 1 == 100 else true"#)
                .can_error_assuming_well_formed(),
            true
        );
        assert_eq!(
            parse_residual(r#"principal.foo && principal.num * 2 == 100"#)
                .can_error_assuming_well_formed(),
            true
        );
        assert_eq!(
            parse_residual(r#"principal.foo || -principal.num == 100"#)
                .can_error_assuming_well_formed(),
            true
        );
        assert_eq!(
            parse_residual(r#"principal.num == 1 && principal.period < (if principal.foo then duration("1d") else duration("2d"))"#).can_error_assuming_well_formed(),
            true
        );
        // in reality, this specific function could most likely never error
        // in the future, we might want to be more precise about exactly what functions could produce errors
        assert_eq!(
            parse_residual(r#"principal.period.toDays() == 365"#).can_error_assuming_well_formed(),
            true
        );
        assert_eq!(
            Residual::Error {
                err: EvaluationError::failed_extension_function_application(
                    "foo".parse().unwrap(),
                    "failed".into(),
                    None,
                    None
                ),
                ty: Type::Bool(BoolType::AnyBool),
            }
            .can_error_assuming_well_formed(),
            true
        );
    }

    mod literal_uids {
        use similar_asserts::assert_eq;
        use std::collections::HashSet;

        use super::parse_residual;

        #[test]
        fn var() {
            assert_eq!(
                parse_residual("principal.foo").all_literal_uids(),
                HashSet::new()
            );
        }

        #[test]
        fn r#if() {
            assert_eq!(
                parse_residual(
                    r#"if User::"alice".foo then User::"bob".foo else User::"jane".foo"#
                )
                .all_literal_uids(),
                HashSet::from([
                    r#"User::"alice""#.parse().unwrap(),
                    r#"User::"bob""#.parse().unwrap(),
                    r#"User::"jane""#.parse().unwrap(),
                ])
            );
        }

        #[test]
        fn and() {
            assert_eq!(
                parse_residual(r#"User::"alice".foo && User::"jane".foo"#).all_literal_uids(),
                HashSet::from([
                    r#"User::"alice""#.parse().unwrap(),
                    r#"User::"jane""#.parse().unwrap(),
                ])
            );
        }

        #[test]
        fn set() {
            assert_eq!(
                parse_residual(r#"principal in [User::"alice", User::"jane"]"#).all_literal_uids(),
                HashSet::from([
                    r#"User::"alice""#.parse().unwrap(),
                    r#"User::"jane""#.parse().unwrap(),
                ])
            );
        }

        #[test]
        fn record() {
            assert_eq!(
                parse_residual(r#"(if principal.foo then {a: User::"alice", b: true} else {a: User::"jane", b: false}).a.foo"#).all_literal_uids(),
                HashSet::from([
                    r#"User::"alice""#.parse().unwrap(),
                    r#"User::"jane""#.parse().unwrap(),
                ])
            );
        }
    }

    fn assert_eq_expr(expr_str: &str) {
        // The unconstrained
        let e: Expr = format!("true && (true && (true && ({})))", expr_str)
            .parse()
            .unwrap();
        let residual = parse_residual(expr_str);
        let e2 = Expr::from(residual);
        println!("e: {}", e);
        println!("e2: {}", e2);
        assert_eq!(e, e2);
    }

    #[test]
    fn to_expr() {
        assert_eq_expr(r#"User::"alice".foo && User::"jane".foo"#);
        assert_eq_expr(r#"User::"alice".foo || User::"jane".foo"#);
        assert_eq_expr(r#"[User::"jane".foo].contains(User::"jane".foo)"#);
        assert_eq_expr(r#"User::"alice" has foo"#);
        assert_eq_expr(r#"(if User::"alice".foo then User::"bob" else User::"jane").foo"#);
        assert_eq_expr(r#""foo" like "bar""#);
        assert_eq_expr(r#"principal in [User::"alice", User::"jane"]"#);
        assert_eq_expr(
            r#"(if principal.foo then {a: User::"alice", b: true} else {a: User::"jane", b: false}).a.foo"#,
        );
    }
}
