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

//! Expression types for PST

use crate::ast::{EntityType, EntityUID, SlotId};
use crate::expr_builder::ExprBuilder;
use crate::parser::Loc;
use smol_str::{SmolStr, ToSmolStr};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Variables available in Cedar policies
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Var {
    /// The `principal` variable
    Principal,
    /// The `action` variable
    Action,
    /// The `resource` variable
    Resource,
    /// The `context` variable
    Context,
}

/// Binary operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOp {
    // Comparison
    /// Equality (`==`)
    Eq,
    /// Inequality (`!=`)
    NotEq,
    /// Less than (`<`)
    Less,
    /// Less than or equal (`<=`)
    LessEq,
    /// Greater than (`>`)
    Greater,
    /// Greater than or equal (`>=`)
    GreaterEq,
    // Logical
    /// Logical AND (`&&`)
    And,
    /// Logical OR (`||`)
    Or,
    // Arithmetic
    /// Addition (`+`)
    Add,
    /// Subtraction (`-`)
    Sub,
    /// Multiplication (`*`)
    Mul,
    // Set/hierarchy
    /// Hierarchy membership (`in`)
    In,
    /// Set contains element (`contains`)
    Contains,
    /// Set contains all elements (`containsAll`)
    ContainsAll,
    /// Set contains any element (`containsAny`)
    ContainsAny,
    // Tags (experimental)
    /// Get tag value (`getTag`)
    GetTag,
    /// Check tag existence (`hasTag`)
    HasTag,
}

impl From<BinaryOp> for crate::ast::BinaryOp {
    fn from(op: BinaryOp) -> Self {
        match op {
            BinaryOp::Eq => crate::ast::BinaryOp::Eq,
            BinaryOp::NotEq => panic!("NotEq should be converted to Not(Eq(...))"),
            BinaryOp::Less => crate::ast::BinaryOp::Less,
            BinaryOp::LessEq => crate::ast::BinaryOp::LessEq,
            BinaryOp::Greater => panic!("Greater should be converted to Not(LessEq(...))"),
            BinaryOp::GreaterEq => panic!("GreaterEq should be converted to Not(Less(...))"),
            BinaryOp::And => panic!("And should be converted to If-Then-Else"),
            BinaryOp::Or => panic!("Or should be converted to If-Then-Else"),
            BinaryOp::Add => crate::ast::BinaryOp::Add,
            BinaryOp::Sub => crate::ast::BinaryOp::Sub,
            BinaryOp::Mul => crate::ast::BinaryOp::Mul,
            BinaryOp::In => crate::ast::BinaryOp::In,
            BinaryOp::Contains => crate::ast::BinaryOp::Contains,
            BinaryOp::ContainsAll => crate::ast::BinaryOp::ContainsAll,
            BinaryOp::ContainsAny => crate::ast::BinaryOp::ContainsAny,
            BinaryOp::GetTag => crate::ast::BinaryOp::GetTag,
            BinaryOp::HasTag => crate::ast::BinaryOp::HasTag,
        }
    }
}

/// Literal values
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Literal {
    /// Boolean literal
    Bool(bool),
    /// Integer literal
    Long(i64),
    /// String literal
    String(String),
    /// Entity UID literal
    EntityUid(EntityUID),
}

/// Pattern element for `like` expressions
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PatternElem {
    /// A literal character
    Char(char),
    /// A wildcard (`*`)
    Wildcard,
}

/// PST Expression
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// Literal value
    Literal(Literal),
    /// Variable (principal, action, resource, context)
    Var(Var),
    /// Template slot
    Slot(SlotId),
    /// Logical not
    Not(Arc<Expr>),
    /// Arithmetic negation
    Neg(Arc<Expr>),
    /// Binary operation
    BinaryOp {
        /// The operator
        op: BinaryOp,
        /// Left operand
        left: Arc<Expr>,
        /// Right operand
        right: Arc<Expr>,
    },
    /// Attribute access (e.g., `principal.name`)
    GetAttr {
        /// Expression to get attribute from
        expr: Arc<Expr>,
        /// Attribute name
        attr: String,
    },
    /// Attribute existence check (e.g., `principal has name`)
    /// Can check nested attributes (e.g., `principal has address.street`)
    HasAttr {
        /// Expression to check for attribute
        expr: Arc<Expr>,
        /// Attribute path (non-empty)
        attrs: nonempty::NonEmpty<SmolStr>,
    },
    /// Pattern matching (e.g., `resource.name like "*.jpg"`)
    Like {
        /// Expression to match
        expr: Arc<Expr>,
        /// Pattern to match against
        pattern: Vec<PatternElem>,
    },
    /// Type test with optional hierarchy check
    /// `expr is Type` or `expr is Type in parent`
    Is {
        /// Expression to test
        expr: Arc<Expr>,
        /// Entity type to test for
        entity_type: EntityType,
        /// Optional hierarchy parent
        in_expr: Option<Arc<Expr>>,
    },
    /// Conditional expression
    IfThenElse {
        /// Condition
        cond: Arc<Expr>,
        /// Then branch
        then_expr: Arc<Expr>,
        /// Else branch
        else_expr: Arc<Expr>,
    },
    /// Set literal
    Set(Vec<Arc<Expr>>),
    /// Record literal
    Record(BTreeMap<String, Arc<Expr>>),
    /// Function call (builtin or extension). Syntactically, this can be either a function-style or
    /// method-style call depending on the extension.
    FuncCall {
        /// Function name
        name: SmolStr,
        /// Arguments
        args: Vec<Arc<Expr>>,
    },
    /// Check if set/record is empty
    IsEmpty(Arc<Expr>),
}

/// Builder to construct a PST [`Expr`] that implements the [`ExprBuilder`] interface. Unlike the
/// expression building functions, this does not perform any validation on the input and is meant
/// to be used internally.
#[derive(Clone, Debug)]
pub(crate) struct PstBuilder;

impl ExprBuilder for PstBuilder {
    type Expr = Expr;
    type Data = ();

    #[cfg(feature = "tolerant-ast")]
    type ErrorType = std::convert::Infallible;

    fn with_data(_data: Self::Data) -> Self {
        Self
    }

    fn with_maybe_source_loc(self, _: Option<&Loc>) -> Self {
        // PST doesn't store source locations
        self
    }

    fn loc(&self) -> Option<&Loc> {
        None
    }

    fn data(&self) -> &Self::Data {
        &()
    }

    fn val(self, lit: impl Into<crate::ast::Literal>) -> Expr {
        Expr::Literal(match lit.into() {
            crate::ast::Literal::Bool(b) => Literal::Bool(b),
            crate::ast::Literal::Long(i) => Literal::Long(i),
            crate::ast::Literal::String(s) => Literal::String(s.to_string()),
            crate::ast::Literal::EntityUID(e) => Literal::EntityUid(e.as_ref().clone()),
        })
    }

    fn var(self, var: crate::ast::Var) -> Expr {
        Expr::Var(match var {
            crate::ast::Var::Principal => Var::Principal,
            crate::ast::Var::Action => Var::Action,
            crate::ast::Var::Resource => Var::Resource,
            crate::ast::Var::Context => Var::Context,
        })
    }

    fn unknown(self, u: crate::ast::Unknown) -> Expr {
        // Represent unknown as a function call
        Expr::FuncCall {
            name: "unknown".into(),
            args: vec![Arc::new(Expr::Literal(Literal::String(u.name.to_string())))],
        }
    }

    fn slot(self, s: SlotId) -> Expr {
        Expr::Slot(s)
    }

    fn ite(self, test_expr: Expr, then_expr: Expr, else_expr: Expr) -> Expr {
        Expr::IfThenElse {
            cond: Arc::new(test_expr),
            then_expr: Arc::new(then_expr),
            else_expr: Arc::new(else_expr),
        }
    }

    fn not(self, e: Expr) -> Expr {
        Expr::Not(Arc::new(e))
    }

    fn is_eq(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Eq,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn and(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::And,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn or(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Or,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn less(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Less,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn lesseq(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::LessEq,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn add(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Add,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn sub(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Sub,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn mul(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Mul,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn neg(self, e: Expr) -> Expr {
        Expr::Neg(Arc::new(e))
    }

    fn is_in(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::In,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn contains(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Contains,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn contains_all(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::ContainsAll,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn contains_any(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::ContainsAny,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn is_empty(self, expr: Expr) -> Expr {
        Expr::IsEmpty(Arc::new(expr))
    }

    fn get_tag(self, expr: Expr, tag: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::GetTag,
            left: Arc::new(expr),
            right: Arc::new(tag),
        }
    }

    fn has_tag(self, expr: Expr, tag: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::HasTag,
            left: Arc::new(expr),
            right: Arc::new(tag),
        }
    }

    fn set(self, exprs: impl IntoIterator<Item = Expr>) -> Expr {
        Expr::Set(exprs.into_iter().map(Arc::new).collect())
    }

    fn record(
        self,
        pairs: impl IntoIterator<Item = (SmolStr, Expr)>,
    ) -> Result<Expr, crate::ast::ExpressionConstructionError> {
        let mut map = BTreeMap::new();
        for (k, v) in pairs {
            if map.insert(k.to_string(), Arc::new(v)).is_some() {
                return Err(
                    crate::ast::expression_construction_errors::DuplicateKeyError {
                        key: k,
                        context: "in record literal",
                    }
                    .into(),
                );
            }
        }
        Ok(Expr::Record(map))
    }

    fn call_extension_fn(
        self,
        fn_name: crate::ast::Name,
        args: impl IntoIterator<Item = Expr>,
    ) -> Expr {
        Expr::FuncCall {
            name: fn_name.to_smolstr(),
            args: args.into_iter().map(Arc::new).collect(),
        }
    }

    fn get_attr(self, expr: Expr, attr: SmolStr) -> Expr {
        Expr::GetAttr {
            expr: Arc::new(expr),
            attr: attr.to_string(),
        }
    }

    fn has_attr(self, expr: Expr, attr: SmolStr) -> Expr {
        Expr::HasAttr {
            expr: Arc::new(expr),
            attrs: nonempty::nonempty![attr],
        }
    }

    fn like(self, expr: Expr, pattern: crate::ast::Pattern) -> Expr {
        Expr::Like {
            expr: Arc::new(expr),
            pattern: pattern
                .iter()
                .map(|elem| match elem {
                    crate::ast::PatternElem::Char(c) => PatternElem::Char(*c),
                    crate::ast::PatternElem::Wildcard => PatternElem::Wildcard,
                })
                .collect(),
        }
    }

    fn is_entity_type(self, expr: Expr, entity_type: EntityType) -> Expr {
        Expr::Is {
            expr: Arc::new(expr),
            entity_type,
            in_expr: None,
        }
    }

    fn is_in_entity_type(self, e1: Expr, entity_type: EntityType, e2: Expr) -> Expr {
        Expr::Is {
            expr: Arc::new(e1),
            entity_type,
            in_expr: Some(Arc::new(e2)),
        }
    }

    #[cfg(feature = "tolerant-ast")]
    fn error(
        self,
        _parse_errors: crate::parser::err::ParseErrors,
    ) -> Result<Self::Expr, Self::ErrorType> {
        // PST doesn't support error nodes, so this is infallible
        // We could represent errors as a special variant, but for now we don't
        Ok(Expr::Literal(Literal::Bool(false)))
    }
}

impl From<crate::ast::Expr> for Expr {
    fn from(ast_expr: crate::ast::Expr) -> Self {
        use crate::expr_builder::ExprBuilder;
        let builder = PstBuilder;

        match ast_expr.into_expr_kind() {
            crate::ast::ExprKind::Lit(lit) => builder.val(lit),
            crate::ast::ExprKind::Var(v) => builder.var(v),
            crate::ast::ExprKind::Slot(s) => builder.slot(s),
            crate::ast::ExprKind::Unknown(u) => builder.unknown(u),
            crate::ast::ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => builder.ite(
                Arc::unwrap_or_clone(test_expr).into(),
                Arc::unwrap_or_clone(then_expr).into(),
                Arc::unwrap_or_clone(else_expr).into(),
            ),
            crate::ast::ExprKind::And { left, right } => builder.and(
                Arc::unwrap_or_clone(left).into(),
                Arc::unwrap_or_clone(right).into(),
            ),
            crate::ast::ExprKind::Or { left, right } => builder.or(
                Arc::unwrap_or_clone(left).into(),
                Arc::unwrap_or_clone(right).into(),
            ),
            crate::ast::ExprKind::UnaryApp { op, arg } => match op {
                crate::ast::UnaryOp::Not => builder.not(Arc::unwrap_or_clone(arg).into()),
                crate::ast::UnaryOp::Neg => builder.neg(Arc::unwrap_or_clone(arg).into()),
                crate::ast::UnaryOp::IsEmpty => builder.is_empty(Arc::unwrap_or_clone(arg).into()),
            },
            crate::ast::ExprKind::BinaryApp { op, arg1, arg2 } => match op {
                crate::ast::BinaryOp::Eq => builder.is_eq(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                crate::ast::BinaryOp::Less => builder.less(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                crate::ast::BinaryOp::LessEq => builder.lesseq(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                crate::ast::BinaryOp::Add => builder.add(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                crate::ast::BinaryOp::Sub => builder.sub(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                crate::ast::BinaryOp::Mul => builder.mul(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                crate::ast::BinaryOp::In => builder.is_in(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                crate::ast::BinaryOp::Contains => builder.contains(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                crate::ast::BinaryOp::ContainsAll => builder.contains_all(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                crate::ast::BinaryOp::ContainsAny => builder.contains_any(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                crate::ast::BinaryOp::GetTag => builder.get_tag(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                crate::ast::BinaryOp::HasTag => builder.has_tag(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
            },
            crate::ast::ExprKind::ExtensionFunctionApp { fn_name, args } => builder
                .call_extension_fn(
                    fn_name,
                    Arc::unwrap_or_clone(args).into_iter().map(|a| a.into()),
                ),
            crate::ast::ExprKind::GetAttr { expr, attr } => {
                builder.get_attr(Arc::unwrap_or_clone(expr).into(), attr.into())
            }
            crate::ast::ExprKind::HasAttr { expr, attr } => {
                builder.has_attr(Arc::unwrap_or_clone(expr).into(), attr.into())
            }
            crate::ast::ExprKind::Like { expr, pattern } => {
                builder.like(Arc::unwrap_or_clone(expr).into(), pattern)
            }
            crate::ast::ExprKind::Is { expr, entity_type } => {
                builder.is_entity_type(Arc::unwrap_or_clone(expr).into(), entity_type)
            }
            crate::ast::ExprKind::Set(elems) => {
                builder.set(Arc::unwrap_or_clone(elems).into_iter().map(|e| e.into()))
            }
            crate::ast::ExprKind::Record(map) => builder
                .record(
                    Arc::unwrap_or_clone(map)
                        .into_iter()
                        .map(|(k, v)| (k.into(), v.into())),
                )
                .unwrap(),
            #[cfg(feature = "tolerant-ast")]
            crate::ast::ExprKind::Error { .. } => panic!("Cannot convert EST error node to PST"),
        }
    }
}

impl std::fmt::Display for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Simple display implementation - can be improved later
        match self {
            Expr::Literal(lit) => write!(f, "{:?}", lit),
            Expr::Var(v) => write!(f, "{:?}", v),
            Expr::Slot(s) => write!(f, "{}", s),
            Expr::Not(e) => write!(f, "!{}", e),
            Expr::Neg(e) => write!(f, "-{}", e),
            Expr::BinaryOp { op, left, right } => write!(f, "({} {:?} {})", left, op, right),
            Expr::GetAttr { expr, attr } => write!(f, "{}.{}", expr, attr),
            Expr::HasAttr { expr, attrs } => {
                write!(
                    f,
                    "{} has {}",
                    expr,
                    attrs
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(".")
                )
            }
            Expr::Like { expr, pattern } => write!(f, "{} like {:?}", expr, pattern),
            Expr::Is {
                expr,
                entity_type,
                in_expr,
            } => {
                if let Some(in_e) = in_expr {
                    write!(f, "{} is {} in {}", expr, entity_type, in_e)
                } else {
                    write!(f, "{} is {}", expr, entity_type)
                }
            }
            Expr::IfThenElse {
                cond,
                then_expr,
                else_expr,
            } => {
                write!(f, "if {} then {} else {}", cond, then_expr, else_expr)
            }
            Expr::Set(exprs) => {
                write!(
                    f,
                    "[{}]",
                    exprs
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Expr::Record(map) => {
                write!(
                    f,
                    "{{{}}}",
                    map.iter()
                        .map(|(k, v)| format!("{}: {}", k, v))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Expr::FuncCall { name, args } => {
                write!(
                    f,
                    "{}({})",
                    name,
                    args.iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Expr::IsEmpty(e) => write!(f, "{}.isEmpty()", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_literal() {
        let expr = PstBuilder::new().val(true);
        assert!(matches!(expr, Expr::Literal(Literal::Bool(true))));

        let expr = PstBuilder::new().val(42i64);
        assert!(matches!(expr, Expr::Literal(Literal::Long(42))));
    }

    #[test]
    fn test_builder_var() {
        let expr = PstBuilder::new().var(crate::ast::Var::Principal);
        assert!(matches!(expr, Expr::Var(Var::Principal)));
    }

    #[test]
    fn test_builder_binary_ops() {
        let left = PstBuilder::new().val(1i64);
        let right = PstBuilder::new().val(2i64);

        let expr = PstBuilder::new().add(left.clone(), right.clone());
        assert!(matches!(
            expr,
            Expr::BinaryOp {
                op: BinaryOp::Add,
                ..
            }
        ));

        let expr = PstBuilder::new().and(left.clone(), right.clone());
        assert!(matches!(
            expr,
            Expr::BinaryOp {
                op: BinaryOp::And,
                ..
            }
        ));

        let expr = PstBuilder::new().is_eq(left, right);
        assert!(matches!(
            expr,
            Expr::BinaryOp {
                op: BinaryOp::Eq,
                ..
            }
        ));
    }

    #[test]
    fn test_builder_unary_ops() {
        let inner = PstBuilder::new().val(true);
        let expr = PstBuilder::new().not(inner);
        assert!(matches!(expr, Expr::Not(_)));

        let inner = PstBuilder::new().val(42i64);
        let expr = PstBuilder::new().neg(inner);
        assert!(matches!(expr, Expr::Neg(_)));
    }

    #[test]
    fn test_builder_ite() {
        let cond = PstBuilder::new().val(true);
        let then_expr = PstBuilder::new().val(1i64);
        let else_expr = PstBuilder::new().val(2i64);

        let expr = PstBuilder::new().ite(cond, then_expr, else_expr);
        assert!(matches!(expr, Expr::IfThenElse { .. }));
    }

    #[test]
    fn test_builder_set() {
        let exprs = vec![
            PstBuilder::new().val(1i64),
            PstBuilder::new().val(2i64),
            PstBuilder::new().val(3i64),
        ];

        let expr = PstBuilder::new().set(exprs);
        if let Expr::Set(elements) = expr {
            assert_eq!(elements.len(), 3);
        } else {
            panic!("Expected Set");
        }
    }

    #[test]
    fn test_builder_record() {
        let pairs = vec![
            ("a".into(), PstBuilder::new().val(1i64)),
            ("b".into(), PstBuilder::new().val(2i64)),
        ];

        let expr = PstBuilder::new().record(pairs).unwrap();
        if let Expr::Record(map) = expr {
            assert_eq!(map.len(), 2);
            assert!(map.contains_key("a"));
            assert!(map.contains_key("b"));
        } else {
            panic!("Expected Record");
        }
    }

    #[test]
    fn test_builder_get_attr() {
        let base = PstBuilder::new().var(crate::ast::Var::Principal);
        let expr = PstBuilder::new().get_attr(base, "name".into());

        if let Expr::GetAttr { attr, .. } = expr {
            assert_eq!(attr, "name");
        } else {
            panic!("Expected GetAttr");
        }
    }

    #[test]
    fn test_builder_has_attr() {
        let base = PstBuilder::new().var(crate::ast::Var::Principal);
        let expr = PstBuilder::new().has_attr(base, "name".into());

        if let Expr::HasAttr { attrs, .. } = expr {
            assert_eq!(attrs.len(), 1);
            assert_eq!(attrs.head, "name");
        } else {
            panic!("Expected HasAttr");
        }
    }

    #[test]
    fn test_builder_is_entity_type() {
        let base = PstBuilder::new().var(crate::ast::Var::Principal);
        let entity_type =
            EntityType::from(crate::ast::Name::parse_unqualified_name("User").unwrap());
        let expr = PstBuilder::new().is_entity_type(base, entity_type.clone());

        if let Expr::Is {
            entity_type: et,
            in_expr,
            ..
        } = expr
        {
            assert_eq!(et, entity_type);
            assert!(in_expr.is_none());
        } else {
            panic!("Expected Is");
        }
    }

    #[test]
    fn test_builder_func_call() {
        let args = vec![PstBuilder::new().val(1i64), PstBuilder::new().val(2i64)];
        let fn_name = crate::ast::Name::parse_unqualified_name("decimal").unwrap();
        let expr = PstBuilder::new().call_extension_fn(fn_name, args);

        if let Expr::FuncCall { name, args } = expr {
            assert_eq!(name, "decimal");
            assert_eq!(args.len(), 2);
        } else {
            panic!("Expected FuncCall");
        }
    }

    #[test]
    fn test_builder_display() {
        let expr = PstBuilder::new().val(42i64);
        let s = expr.to_string();
        assert!(s.contains("42"));
    }

    mod display_tests {
        use super::*;
        use nonempty::nonempty;

        #[test]
        fn test_literal_bool() {
            assert_eq!(Expr::Literal(Literal::Bool(true)).to_string(), "Bool(true)");
            assert_eq!(Expr::Literal(Literal::Bool(false)).to_string(), "Bool(false)");
        }

        #[test]
        fn test_literal_long() {
            assert_eq!(Expr::Literal(Literal::Long(42)).to_string(), "Long(42)");
            assert_eq!(Expr::Literal(Literal::Long(-123)).to_string(), "Long(-123)");
        }

        #[test]
        fn test_literal_string() {
            assert_eq!(
                Expr::Literal(Literal::String("hello".into())).to_string(),
                "String(\"hello\")"
            );
        }

        #[test]
        fn test_literal_entity_uid() {
            let uid = EntityUID::from_components(
                EntityType::from(crate::ast::Name::parse_unqualified_name("User").unwrap()),
                crate::ast::Eid::new("alice"),
                None,
            );
            let s = Expr::Literal(Literal::EntityUid(uid)).to_string();
            assert!(s.contains("User"));
            assert!(s.contains("alice"));
        }

        #[test]
        fn test_var() {
            assert_eq!(Expr::Var(Var::Principal).to_string(), "Principal");
            assert_eq!(Expr::Var(Var::Action).to_string(), "Action");
            assert_eq!(Expr::Var(Var::Resource).to_string(), "Resource");
            assert_eq!(Expr::Var(Var::Context).to_string(), "Context");
        }

        #[test]
        fn test_slot() {
            assert!(Expr::Slot(SlotId::principal()).to_string().contains("principal"));
        }

        #[test]
        fn test_not() {
            let expr = Expr::Not(Arc::new(Expr::Literal(Literal::Bool(true))));
            assert_eq!(expr.to_string(), "!Bool(true)");
        }

        #[test]
        fn test_neg() {
            let expr = Expr::Neg(Arc::new(Expr::Literal(Literal::Long(42))));
            assert_eq!(expr.to_string(), "-Long(42)");
        }

        #[test]
        fn test_binary_ops() {
            let left = Arc::new(Expr::Literal(Literal::Long(1)));
            let right = Arc::new(Expr::Literal(Literal::Long(2)));

            let cases = vec![
                (BinaryOp::Eq, "Eq"),
                (BinaryOp::NotEq, "NotEq"),
                (BinaryOp::Less, "Less"),
                (BinaryOp::LessEq, "LessEq"),
                (BinaryOp::Greater, "Greater"),
                (BinaryOp::GreaterEq, "GreaterEq"),
                (BinaryOp::And, "And"),
                (BinaryOp::Or, "Or"),
                (BinaryOp::Add, "Add"),
                (BinaryOp::Sub, "Sub"),
                (BinaryOp::Mul, "Mul"),
                (BinaryOp::In, "In"),
                (BinaryOp::Contains, "Contains"),
                (BinaryOp::ContainsAll, "ContainsAll"),
                (BinaryOp::ContainsAny, "ContainsAny"),
                (BinaryOp::GetTag, "GetTag"),
                (BinaryOp::HasTag, "HasTag"),
            ];

            for (op, name) in cases {
                let expr = Expr::BinaryOp {
                    op,
                    left: left.clone(),
                    right: right.clone(),
                };
                let s = expr.to_string();
                assert!(s.contains(name), "Expected {} in {}", name, s);
                assert!(s.starts_with('(') && s.ends_with(')'));
            }
        }

        #[test]
        fn test_get_attr() {
            let expr = Expr::GetAttr {
                expr: Arc::new(Expr::Var(Var::Principal)),
                attr: "name".into(),
            };
            assert_eq!(expr.to_string(), "Principal.name");
        }

        #[test]
        fn test_has_attr_single() {
            let expr = Expr::HasAttr {
                expr: Arc::new(Expr::Var(Var::Principal)),
                attrs: nonempty!["name".into()],
            };
            assert_eq!(expr.to_string(), "Principal has name");
        }

        #[test]
        fn test_has_attr_nested() {
            let expr = Expr::HasAttr {
                expr: Arc::new(Expr::Var(Var::Context)),
                attrs: nonempty!["user".into(), "email".into()],
            };
            assert_eq!(expr.to_string(), "Context has user.email");
        }

        #[test]
        fn test_like() {
            let expr = Expr::Like {
                expr: Arc::new(Expr::Var(Var::Principal)),
                pattern: vec![PatternElem::Char('a'), PatternElem::Wildcard],
            };
            assert!(expr.to_string().contains("Principal like"));
        }

        #[test]
        fn test_is_without_in() {
            let expr = Expr::Is {
                expr: Arc::new(Expr::Var(Var::Principal)),
                entity_type: EntityType::from(
                    crate::ast::Name::parse_unqualified_name("User").unwrap(),
                ),
                in_expr: None,
            };
            assert_eq!(expr.to_string(), "Principal is User");
        }

        #[test]
        fn test_is_with_in() {
            let expr = Expr::Is {
                expr: Arc::new(Expr::Var(Var::Principal)),
                entity_type: EntityType::from(
                    crate::ast::Name::parse_unqualified_name("User").unwrap(),
                ),
                in_expr: Some(Arc::new(Expr::Var(Var::Resource))),
            };
            assert_eq!(expr.to_string(), "Principal is User in Resource");
        }

        #[test]
        fn test_if_then_else() {
            let expr = Expr::IfThenElse {
                cond: Arc::new(Expr::Literal(Literal::Bool(true))),
                then_expr: Arc::new(Expr::Literal(Literal::Long(1))),
                else_expr: Arc::new(Expr::Literal(Literal::Long(2))),
            };
            assert_eq!(expr.to_string(), "if Bool(true) then Long(1) else Long(2)");
        }

        #[test]
        fn test_set() {
            assert_eq!(Expr::Set(vec![]).to_string(), "[]");
            assert_eq!(
                Expr::Set(vec![Arc::new(Expr::Literal(Literal::Long(42)))]).to_string(),
                "[Long(42)]"
            );
            assert_eq!(
                Expr::Set(vec![
                    Arc::new(Expr::Literal(Literal::Long(1))),
                    Arc::new(Expr::Literal(Literal::Long(2))),
                    Arc::new(Expr::Literal(Literal::Long(3))),
                ])
                .to_string(),
                "[Long(1), Long(2), Long(3)]"
            );
        }

        #[test]
        fn test_record() {
            assert_eq!(Expr::Record(BTreeMap::new()).to_string(), "{}");

            let mut map = BTreeMap::new();
            map.insert("a".into(), Arc::new(Expr::Literal(Literal::Long(1))));
            assert_eq!(Expr::Record(map).to_string(), "{a: Long(1)}");

            let mut map = BTreeMap::new();
            map.insert("a".into(), Arc::new(Expr::Literal(Literal::Long(1))));
            map.insert("b".into(), Arc::new(Expr::Literal(Literal::Long(2))));
            assert_eq!(Expr::Record(map).to_string(), "{a: Long(1), b: Long(2)}");
        }

        #[test]
        fn test_func_call() {
            assert_eq!(
                Expr::FuncCall {
                    name: "foo".into(),
                    args: vec![],
                }
                .to_string(),
                "foo()"
            );
            assert_eq!(
                Expr::FuncCall {
                    name: "decimal".into(),
                    args: vec![Arc::new(Expr::Literal(Literal::String("1.23".into())))],
                }
                .to_string(),
                "decimal(String(\"1.23\"))"
            );
            assert_eq!(
                Expr::FuncCall {
                    name: "foo".into(),
                    args: vec![
                        Arc::new(Expr::Literal(Literal::Long(1))),
                        Arc::new(Expr::Literal(Literal::Long(2))),
                    ],
                }
                .to_string(),
                "foo(Long(1), Long(2))"
            );
        }

        #[test]
        fn test_is_empty() {
            let expr = Expr::IsEmpty(Arc::new(Expr::Set(vec![])));
            assert_eq!(expr.to_string(), "[].isEmpty()");
        }

        #[test]
        fn test_nested() {
            let expr = Expr::BinaryOp {
                op: BinaryOp::Eq,
                left: Arc::new(Expr::BinaryOp {
                    op: BinaryOp::Add,
                    left: Arc::new(Expr::Literal(Literal::Long(1))),
                    right: Arc::new(Expr::Literal(Literal::Long(2))),
                }),
                right: Arc::new(Expr::Literal(Literal::Long(3))),
            };
            assert_eq!(expr.to_string(), "((Long(1) Add Long(2)) Eq Long(3))");
        }

        #[test]
        fn test_complex() {
            let expr = Expr::IfThenElse {
                cond: Arc::new(Expr::BinaryOp {
                    op: BinaryOp::Greater,
                    left: Arc::new(Expr::GetAttr {
                        expr: Arc::new(Expr::Var(Var::Principal)),
                        attr: "age".into(),
                    }),
                    right: Arc::new(Expr::Literal(Literal::Long(18))),
                }),
                then_expr: Arc::new(Expr::GetAttr {
                    expr: Arc::new(Expr::Var(Var::Principal)),
                    attr: "name".into(),
                }),
                else_expr: Arc::new(Expr::Literal(Literal::String("unknown".into()))),
            };
            assert_eq!(
                expr.to_string(),
                "if (Principal.age Greater Long(18)) then Principal.name else String(\"unknown\")"
            );
        }
    }
}
