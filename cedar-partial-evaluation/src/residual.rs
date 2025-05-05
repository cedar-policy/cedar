use std::{collections::BTreeMap, fmt::Result, sync::Arc};

use cedar_policy_core::{
    ast::{self, BinaryOp, EntityType, Expr, Name, Pattern, UnaryOp, Value, Var},
    evaluator::{evaluation_errors::NonValueError, EvaluationError},
    expr_builder::ExprBuilder,
};
use cedar_policy_validator::types::Type;
use smol_str::SmolStr;

#[derive(Debug, Clone)]
pub enum Residual {
    Partial { kind: ResidualKind, ty: Type },
    Concrete { value: Value, ty: Type },
    Error(Type),
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

#[derive(Debug, Clone)]
pub enum ResidualKind {
    /// Variable
    Var(Var),
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

/// Conversion from `Residual` to `Expr` so that we can use the concrete evaluator for re-authorization
impl TryFrom<Residual> for Expr {
    type Error = ();

    fn try_from(value: Residual) -> std::result::Result<Expr, Self::Error> {
        match value {
            Residual::Partial { kind, .. } => {
                let builder: ast::ExprBuilder<()> = ExprBuilder::with_data(());
                match kind {
                    ResidualKind::And { left, right } => Ok(builder.and(
                        left.as_ref().clone().try_into()?,
                        right.as_ref().clone().try_into()?,
                    )),
                    ResidualKind::BinaryApp { op, arg1, arg2 } => Ok(builder.binary_app(
                        op,
                        arg1.as_ref().clone().try_into()?,
                        arg2.as_ref().clone().try_into()?,
                    )),
                    ResidualKind::ExtensionFunctionApp { fn_name, args } => Ok(builder
                        .call_extension_fn(
                            fn_name,
                            args.as_ref()
                                .clone()
                                .into_iter()
                                .map(|arg| arg.try_into())
                                .collect::<std::result::Result<Vec<_>, _>>()?,
                        )),
                    ResidualKind::GetAttr { expr, attr } => {
                        Ok(builder.get_attr(expr.as_ref().clone().try_into()?, attr))
                    }
                    ResidualKind::HasAttr { expr, attr } => {
                        Ok(builder.has_attr(expr.as_ref().clone().try_into()?, attr))
                    }
                    ResidualKind::If {
                        test_expr,
                        then_expr,
                        else_expr,
                    } => Ok(builder.ite(
                        test_expr.as_ref().clone().try_into()?,
                        then_expr.as_ref().clone().try_into()?,
                        else_expr.as_ref().clone().try_into()?,
                    )),
                    ResidualKind::Is { expr, entity_type } => {
                        Ok(builder.is_entity_type(expr.as_ref().clone().try_into()?, entity_type))
                    }
                    ResidualKind::Like { expr, pattern } => {
                        Ok(builder.like(expr.as_ref().clone().try_into()?, pattern))
                    }
                    ResidualKind::Or { left, right } => Ok(builder.or(
                        left.as_ref().clone().try_into()?,
                        right.as_ref().clone().try_into()?,
                    )),
                    ResidualKind::Record(map) => Ok(builder
                        .record(
                            map.as_ref()
                                .clone()
                                .into_iter()
                                .map(|(k, v)| Ok((k.clone(), v.try_into()?)))
                                .collect::<std::result::Result<Vec<(_, _)>, _>>()?,
                        )
                        .expect("should succeed")),
                    ResidualKind::Set(set) => Ok(builder.set(
                        set.as_ref()
                            .clone()
                            .into_iter()
                            .map(|v| v.try_into())
                            .collect::<std::result::Result<Vec<_>, _>>()?,
                    )),
                    ResidualKind::UnaryApp { op, arg } => {
                        Ok(builder.unary_app(op, arg.as_ref().clone().try_into()?))
                    }
                    ResidualKind::Var(v) => Ok(builder.var(v)),
                }
            }
            Residual::Concrete { value, .. } => Ok(value.into()),
            Residual::Error(_) => Err(()),
        }
    }
}
