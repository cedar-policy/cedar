use crate::{
    ast::*,
    expr_builder::{self},
    parser::{
        err::{ParseErrors, ToASTErrorKind},
        AsLocRef, IntoMaybeLoc, Loc, MaybeLoc,
    },
};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::{
    collections::{btree_map, BTreeMap},
    sync::Arc,
};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize, Hash, Clone, PartialEq, Eq)]
pub enum AstExprErrorKind {
    #[error("Invalid expression node: {0}")]
    InvalidExpr(String),
}

impl From<ToASTErrorKind> for AstExprErrorKind {
    fn from(value: ToASTErrorKind) -> Self {
        AstExprErrorKind::InvalidExpr(value.to_string())
    }
}

#[derive(Clone, Debug)]
pub struct ExprWithErrsBuilder<T = ()> {
    source_loc: MaybeLoc,
    data: T,
}

impl<T: Default + Clone> expr_builder::ExprBuilder for ExprWithErrsBuilder<T> {
    type Expr = Expr<T>;

    type Data = T;

    #[cfg(feature = "tolerant-ast")]
    type ErrorType = Infallible;

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

    #[cfg(feature = "tolerant-ast")]
    fn error(self, parse_errors: ParseErrors) -> Result<Expr<T>, Self::ErrorType> {
        Ok(self.with_expr_kind(ExprKind::Error {
            error_kind: AstExprErrorKind::InvalidExpr(parse_errors.to_string()),
        }))
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
        self.with_expr_kind(match (&e1.expr_kind(), &e2.expr_kind()) {
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
        self.with_expr_kind(match (&e1.expr_kind(), &e2.expr_kind()) {
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

    fn new() -> Self
    where
        Self: Sized,
    {
        Self::with_data(Self::Data::default())
    }

    fn with_source_loc(self, l: &Loc) -> Self
    where
        Self: Sized,
    {
        self.with_maybe_source_loc(Some(l))
    }

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

    fn noteq(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr
    where
        Self: Sized,
    {
        self.clone().not(self.is_eq(e1, e2))
    }

    fn greater(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr
    where
        Self: Sized,
    {
        // e1 > e2 is defined as !(e1 <= e2)
        self.clone().not(self.lesseq(e1, e2))
    }

    fn greatereq(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr
    where
        Self: Sized,
    {
        // e1 >= e2 is defined as !(e1 < e2)
        self.clone().not(self.less(e1, e2))
    }

    fn and_nary(self, first: Self::Expr, others: impl IntoIterator<Item = Self::Expr>) -> Self::Expr
    where
        Self: Sized,
    {
        others
            .into_iter()
            .fold(first, |acc, next| self.clone().and(acc, next))
    }

    fn or_nary(self, first: Self::Expr, others: impl IntoIterator<Item = Self::Expr>) -> Self::Expr
    where
        Self: Sized,
    {
        others
            .into_iter()
            .fold(first, |acc, next| self.clone().or(acc, next))
    }

    fn add_nary(
        self,
        first: Self::Expr,
        other: impl IntoIterator<Item = (crate::parser::cst::AddOp, Self::Expr)>,
    ) -> Self::Expr
    where
        Self: Sized,
    {
        other.into_iter().fold(first, |acc, (op, next)| match op {
            crate::parser::cst::AddOp::Plus => self.clone().add(acc, next),
            crate::parser::cst::AddOp::Minus => self.clone().sub(acc, next),
        })
    }

    fn mul_nary(self, first: Self::Expr, other: impl IntoIterator<Item = Self::Expr>) -> Self::Expr
    where
        Self: Sized,
    {
        other
            .into_iter()
            .fold(first, |acc, next| self.clone().mul(acc, next))
    }
}

impl<T> ExprWithErrsBuilder<T> {
    /// Construct an `Expr` containing the `data` and `source_loc` in this
    /// `ExprBuilder` and the given `ExprKind`.
    pub fn with_expr_kind(self, expr_kind: ExprKind<T>) -> Expr<T> {
        Expr::new(expr_kind, self.source_loc, self.data)
    }
}
