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

//! Public builder API for constructing PST expressions

use super::{BinaryOp, EntityType, EntityUID, Expr, Literal, PatternElem, SlotId, UnaryOp, Var};
use crate::ast;
use itertools::Itertools;
use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Errors that can occur when building PST expressions
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExprConstructionError {
    /// Empty attribute path in `has` expression
    #[error("attribute path cannot be empty")]
    EmptyAttributePath,
    /// Duplicate key in record literal
    #[error("duplicate key in record: {0}")]
    DuplicateRecordKey(String),
    /// Invalid attribute path
    #[error("invalid attribute path: {0}")]
    InvalidAttributePath(String),
}

impl Expr {
    /// Create a literal expression
    pub fn literal(lit: Literal) -> Self {
        Self::Literal(lit)
    }

    /// Create a boolean literal
    pub fn bool(b: bool) -> Self {
        Self::Literal(Literal::Bool(b))
    }

    /// Create an integer literal
    pub fn long(i: i64) -> Self {
        Self::Literal(Literal::Long(i))
    }

    /// Create a string literal
    pub fn string(s: impl Into<String>) -> Self {
        Self::Literal(Literal::String(s.into()))
    }

    /// Create an entity UID literal
    pub fn entity_uid(uid: EntityUID) -> Self {
        Self::Literal(Literal::EntityUID(uid))
    }

    /// Create a variable expression
    pub fn var(var: Var) -> Self {
        Self::Var(var)
    }

    /// Create a principal variable
    pub fn principal() -> Self {
        Self::Var(Var::Principal)
    }

    /// Create an action variable
    pub fn action() -> Self {
        Self::Var(Var::Action)
    }

    /// Create a resource variable
    pub fn resource() -> Self {
        Self::Var(Var::Resource)
    }

    /// Create a context variable
    pub fn context() -> Self {
        Self::Var(Var::Context)
    }

    /// Create a slot expression
    pub fn slot(slot: SlotId) -> Self {
        Self::Slot(slot)
    }

    /// Create a logical NOT expression
    pub fn not(expr: Self) -> Self {
        Self::UnaryOp {
            op: UnaryOp::Not,
            expr: Arc::new(expr),
        }
    }

    /// Create an arithmetic negation expression
    pub fn neg(expr: Self) -> Self {
        Self::UnaryOp {
            op: UnaryOp::Neg,
            expr: Arc::new(expr),
        }
    }

    /// Create a binary operation expression
    pub fn binary_op(op: BinaryOp, left: Self, right: Self) -> Self {
        Self::BinaryOp {
            op,
            left: Arc::new(left),
            right: Arc::new(right),
        }
    }

    /// Create an equality expression
    pub fn eq(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::Eq, left, right)
    }

    /// Create an inequality expression
    pub fn not_eq(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::NotEq, left, right)
    }

    /// Create a less-than expression
    pub fn less(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::Less, left, right)
    }

    /// Create a less-than-or-equal expression
    pub fn less_eq(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::LessEq, left, right)
    }

    /// Create a greater-than expression
    pub fn greater(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::Greater, left, right)
    }

    /// Create a greater-than-or-equal expression
    pub fn greater_eq(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::GreaterEq, left, right)
    }

    /// Create a logical AND expression
    pub fn and(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::And, left, right)
    }

    /// Create a logical OR expression
    pub fn or(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::Or, left, right)
    }

    /// Create an addition expression
    pub fn add(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::Add, left, right)
    }

    /// Create a subtraction expression
    pub fn sub(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::Sub, left, right)
    }

    /// Create a multiplication expression
    pub fn mul(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::Mul, left, right)
    }

    /// Create an `in` expression (hierarchy membership)
    pub fn in_expr(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::In, left, right)
    }

    /// Create a `contains` expression
    pub fn contains(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::Contains, left, right)
    }

    /// Create a `containsAll` expression
    pub fn contains_all(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::ContainsAll, left, right)
    }

    /// Create a `containsAny` expression
    pub fn contains_any(left: Self, right: Self) -> Self {
        Self::binary_op(BinaryOp::ContainsAny, left, right)
    }

    /// Create a `getTag` expression
    pub fn get_tag(expr: Self, tag: Self) -> Self {
        Self::binary_op(BinaryOp::GetTag, expr, tag)
    }

    /// Create a `hasTag` expression
    pub fn has_tag(expr: Self, tag: Self) -> Self {
        Self::binary_op(BinaryOp::HasTag, expr, tag)
    }

    /// Create an attribute access expression
    pub fn get_attr(expr: Self, attr: impl Into<SmolStr>) -> Self {
        Self::GetAttr {
            expr: Arc::new(expr),
            attr: attr.into(),
        }
    }

    /// Create a single attribute existence check expression
    pub fn has_attr(expr: Self, attr: SmolStr) -> Self {
        Self::HasAttr {
            expr: Arc::new(expr),
            attrs: nonempty::nonempty![attr],
        }
    }

    /// Create an attribute existence check expression
    ///
    /// # Errors
    /// Returns an error if the attribute path is empty
    pub fn has_attrs(
        expr: Self,
        attrs: impl IntoIterator<Item = impl Into<SmolStr>>,
    ) -> Result<Self, ExprConstructionError> {
        let attrs_vec: Vec<SmolStr> = attrs.into_iter().map(Into::into).collect();
        let attrs_nonempty = nonempty::NonEmpty::from_vec(attrs_vec)
            .ok_or(ExprConstructionError::EmptyAttributePath)?;
        if attrs_nonempty.len() > 1
            && attrs_nonempty
                .iter()
                .find(|attr| !ast::is_normalized_ident(attr))
                .is_some()
        {
            Err(ExprConstructionError::InvalidAttributePath(
                attrs_nonempty.iter().join("."),
            ))
        } else {
            Ok(Self::HasAttr {
                expr: Arc::new(expr),
                attrs: attrs_nonempty,
            })
        }
    }

    /// Create a pattern matching expression
    pub fn like(expr: Self, pattern: Vec<PatternElem>) -> Self {
        Self::Like {
            expr: Arc::new(expr),
            pattern,
        }
    }

    /// Create a type test expression
    pub fn is_type(expr: Self, entity_type: EntityType) -> Self {
        Self::Is {
            expr: Arc::new(expr),
            entity_type,
            in_expr: None,
        }
    }

    /// Create a type test with hierarchy check expression
    pub fn is_type_in(expr: Self, entity_type: EntityType, in_expr: Self) -> Self {
        Self::Is {
            expr: Arc::new(expr),
            entity_type,
            in_expr: Some(Arc::new(in_expr)),
        }
    }

    /// Create an if-then-else expression
    pub fn if_then_else(cond: Self, then_expr: Self, else_expr: Self) -> Self {
        Self::IfThenElse {
            cond: Arc::new(cond),
            then_expr: Arc::new(then_expr),
            else_expr: Arc::new(else_expr),
        }
    }

    /// Create a set expression
    pub fn set(elements: impl IntoIterator<Item = Self>) -> Self {
        Self::Set(elements.into_iter().map(Arc::new).collect())
    }

    /// Create a record expression
    ///
    /// # Errors
    /// Returns an error if there are duplicate keys
    pub fn record(
        pairs: impl IntoIterator<Item = (impl Into<String>, Self)>,
    ) -> Result<Self, ExprConstructionError> {
        let mut map = BTreeMap::new();
        for (k, v) in pairs {
            let key = k.into();
            if map.insert(key.clone(), Arc::new(v)).is_some() {
                return Err(ExprConstructionError::DuplicateRecordKey(key));
            }
        }
        Ok(Self::Record(map))
    }

    /// Create a binary operation expression
    pub fn bin_op(op: BinaryOp, left: Self, right: Self) -> Self {
        Self::BinaryOp {
            op,
            left: Arc::new(left),
            right: Arc::new(right),
        }
    }

    /// Create a unary operation expression
    pub fn un_op(op: UnaryOp, expr: Self) -> Self {
        Self::UnaryOp {
            op,
            expr: Arc::new(expr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cool_asserts::assert_matches;
    use nonempty::nonempty;

    #[test]
    fn test_expr_literals() {
        let expr = Expr::bool(true);
        assert!(matches!(expr, Expr::Literal(_)));

        let expr = Expr::long(42);
        assert!(matches!(expr, Expr::Literal(_)));

        let expr = Expr::string("hello");
        assert!(matches!(expr, Expr::Literal(_)));
    }

    #[test]
    fn test_expr_vars() {
        let expr = Expr::principal();
        assert!(matches!(expr, Expr::Var(_)));

        let expr = Expr::context();
        assert!(matches!(expr, Expr::Var(_)));
    }

    #[test]
    fn test_expr_binary_ops() {
        let left = Expr::long(1);
        let right = Expr::long(2);

        let expr = Expr::eq(left.clone(), right.clone());
        assert!(matches!(expr, Expr::BinaryOp { .. }));

        let expr = Expr::add(left, right);
        assert!(matches!(expr, Expr::BinaryOp { .. }));
    }

    #[test]
    fn test_expr_record() {
        let pairs = vec![("a", Expr::long(1)), ("b", Expr::long(2))];

        let expr = Expr::record(pairs).unwrap();
        assert!(matches!(expr, Expr::Record(_)));
    }

    #[test]
    fn test_expr_record_duplicate_key() {
        let pairs = vec![("a", Expr::long(1)), ("a", Expr::long(2))];

        let result = Expr::record(pairs);
        assert!(matches!(
            result,
            Err(ExprConstructionError::DuplicateRecordKey(_))
        ));
    }

    #[test]
    fn test_expr_has_attr_empty() {
        let expr = Expr::principal();
        let result = Expr::has_attrs(expr, Vec::<SmolStr>::new());
        assert!(matches!(
            result,
            Err(ExprConstructionError::EmptyAttributePath)
        ));
    }

    #[test]
    fn test_expr_has_attr_multi_nonident() {
        let expr = Expr::principal();
        let result = Expr::has_attrs(expr, nonempty!["ok", "oh snap®"]);
        assert!(matches!(
            result,
            Err(ExprConstructionError::InvalidAttributePath(_))
        ));
    }

    #[test]
    fn test_expr_has_attr_single_nonident() {
        let expr = Expr::principal();
        let result = Expr::has_attrs(expr, nonempty!["ok ∞ path"]).unwrap();
        assert_matches!(result, Expr::HasAttr { .. })
    }

    #[test]
    fn test_expr_complex() {
        // Build: if principal.age > 18 then true else false
        let age_attr = Expr::get_attr(Expr::principal(), "age");
        let eighteen = Expr::long(18);
        let cond = Expr::greater(age_attr, eighteen);
        let expr = Expr::if_then_else(cond, Expr::bool(true), Expr::bool(false));

        assert!(matches!(expr, Expr::IfThenElse { .. }));
    }
}
