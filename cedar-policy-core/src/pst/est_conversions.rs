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

//! Conversions between EST and PST representations.

use super::{EntityUID, Expr, UnaryOp};
use crate::pst::policy::PolicyID;
use crate::pst::Name;
use crate::{ast::is_normalized_ident, pst::EntityType};
use crate::{est, pst};
use itertools::Itertools;
use miette::Diagnostic;
use smol_str::SmolStr;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
pub enum ConversionError {
    #[error("action_constraint_cannot_have_slots")]
    ActionConstraintCannotHaveSlots,
    #[error("invalid entity uid {0}")]
    InvalidEntityUid(String),
    #[error("invalid entity type {0}")]
    InvalidEntityType(String),
    #[error("invalid record {0}")]
    InvalidRecord(String),
    #[error("invalid attribute path {0}")]
    InvalidAttributePath(String),
    #[error("invalid method call {0}")]
    InvalidMethodCall(SmolStr),
    #[error("unknown function {0}")]
    UnknownFunction(SmolStr),
}

impl TryFrom<est::Expr> for Expr {
    type Error = ConversionError;

    fn try_from(est_expr: est::Expr) -> Result<Self, ConversionError> {
        match est_expr {
            est::Expr::ExprNoExt(e) => e.try_into(),
            est::Expr::ExtFuncCall(e) => {
                let (fn_name, est_args) = e.into_components();
                let pst_args: Vec<Arc<Expr>> = est_args
                    .into_iter()
                    .map(|a: est::Expr| a.clone().try_into().map(Arc::new))
                    .try_collect()?;
                Expr::from_function_name_and_args(fn_name.clone(), &pst_args)
                    .map_err(|_| ConversionError::UnknownFunction(fn_name.clone()))
            }
        }
    }
}

impl TryFrom<est::ExprNoExt> for Expr {
    type Error = ConversionError;

    fn try_from(est_expr: est::ExprNoExt) -> Result<Self, ConversionError> {
        use est::ExprNoExt as E;
        // The conversion doesn't use the ExprBuilder's interface, which currently desugars some
        // expressions. We want the PST to be closed to the EST, so we avoid desugaring here.
        match est_expr {
            E::Value(v) => {
                // Convert CedarValueJson to AST Expr via RestrictedExpr, then to PST
                let ctx = || crate::entities::json::err::JsonDeserializationErrorContext::Context;
                let restricted_expr = v
                    .into_expr(&ctx)
                    .map_err(|e| ConversionError::InvalidEntityUid(e.to_string()))?;
                Ok(crate::ast::Expr::from(restricted_expr.as_ref().clone())
                    .try_into()
                    .unwrap())
            }
            E::Var(v) => Ok(Expr::var(v.try_into().unwrap())),
            E::Slot(s) => Ok(Expr::slot(s.into())),
            E::Not { arg } => Ok(Expr::not(Arc::unwrap_or_clone(arg).try_into()?)),
            E::Neg { arg } => Ok(Expr::neg(Arc::unwrap_or_clone(arg).try_into()?)),
            E::Eq { left, right } => Ok(Expr::eq(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::NotEq { left, right } => Ok(Expr::not_eq(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::In { left, right } => Ok(Expr::in_expr(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::Less { left, right } => Ok(Expr::less(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::LessEq { left, right } => Ok(Expr::less_eq(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::Greater { left, right } => Ok(Expr::greater(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::GreaterEq { left, right } => Ok(Expr::greater_eq(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::And { left, right } => Ok(Expr::and(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::Or { left, right } => Ok(Expr::or(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::Add { left, right } => Ok(Expr::add(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::Sub { left, right } => Ok(Expr::sub(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::Mul { left, right } => Ok(Expr::mul(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::Contains { left, right } => Ok(Expr::contains(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::ContainsAll { left, right } => Ok(Expr::contains_all(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::ContainsAny { left, right } => Ok(Expr::contains_any(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::IsEmpty { arg } => Ok(Expr::UnaryOp {
                op: UnaryOp::IsEmpty,
                expr: Arc::new(Arc::unwrap_or_clone(arg).try_into()?),
            }),
            E::GetTag { left, right } => Ok(Expr::get_tag(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::HasTag { left, right } => Ok(Expr::has_tag(
                Arc::unwrap_or_clone(left).try_into()?,
                Arc::unwrap_or_clone(right).try_into()?,
            )),
            E::GetAttr { left, attr } => {
                Ok(Expr::get_attr(Arc::unwrap_or_clone(left).try_into()?, attr))
            }
            E::HasAttr(repr) => match repr {
                est::HasAttrRepr::Simple { left, attr } => {
                    Ok(Expr::has_attr(Arc::unwrap_or_clone(left).try_into()?, attr))
                }
                est::HasAttrRepr::Extended { left, attr } => {
                    // Validate that if length of attr > 1, all elements are identifiers
                    if attr.len() > 1
                        && attr
                            .iter()
                            .find(|attr| !is_normalized_ident(attr))
                            .is_some()
                    {
                        Err(ConversionError::InvalidAttributePath(format!(
                            "attribute sequence .{} contains non-identifiers",
                            attr.iter().join(".")
                        )))
                    } else {
                        Expr::has_attrs(Arc::unwrap_or_clone(left).try_into()?, attr)
                            .map_err(|e| ConversionError::InvalidAttributePath(e.to_string()))
                    }
                }
            },
            E::Like { left, pattern } => {
                let pattern_elems: Vec<super::PatternElem> = pattern
                    .iter()
                    .flat_map(|e| match e {
                        est::PatternElem::Wildcard => vec![super::PatternElem::Wildcard],
                        est::PatternElem::Literal(s) => {
                            s.chars().map(super::PatternElem::Char).collect()
                        }
                    })
                    .collect();
                // We don't use the ExprBuilder trait here; avoids a conversion est -> ast,
                // instead we do directly est -> pst
                Ok(Self::like(
                    Arc::unwrap_or_clone(left).try_into()?,
                    pattern_elems,
                ))
            }
            E::Is {
                left,
                entity_type,
                in_expr,
            } => {
                let et_name = pst::Name::simple(entity_type);
                let et = EntityType::from_name(et_name);
                match in_expr {
                    None => Ok(Expr::is_type(Arc::unwrap_or_clone(left).try_into()?, et)),
                    Some(in_e) => Ok(Expr::is_type_in(
                        Arc::unwrap_or_clone(left).try_into()?,
                        et,
                        Arc::unwrap_or_clone(in_e).try_into()?,
                    )),
                }
            }
            E::If {
                cond_expr,
                then_expr,
                else_expr,
            } => Ok(Expr::if_then_else(
                Arc::unwrap_or_clone(cond_expr).try_into()?,
                Arc::unwrap_or_clone(then_expr).try_into()?,
                Arc::unwrap_or_clone(else_expr).try_into()?,
            )),
            E::Set(elems) => {
                let converted: Result<Vec<_>, _> =
                    elems.into_iter().map(|e| e.try_into()).collect();
                Ok(Expr::set(converted?))
            }
            E::Record(map) => {
                let converted: Result<Vec<_>, _> = map
                    .into_iter()
                    .map(|(k, v)| v.try_into().map(|v| (k, v)))
                    .collect();
                Expr::record(converted?).map_err(|e| ConversionError::InvalidRecord(e.to_string()))
            }
            #[cfg(feature = "tolerant-ast")]
            E::Error(_) => Err(ConversionError::InvalidEntityUid(
                "Cannot convert EST error node to PST".to_string(),
            )),
        }
    }
}

impl From<crate::ast::Var> for super::Var {
    fn from(v: crate::ast::Var) -> Self {
        match v {
            crate::ast::Var::Principal => super::Var::Principal,
            crate::ast::Var::Action => super::Var::Action,
            crate::ast::Var::Resource => super::Var::Resource,
            crate::ast::Var::Context => super::Var::Context,
        }
    }
}

impl TryFrom<est::Policy> for super::Policy {
    type Error = ConversionError;

    fn try_from(est_policy: est::Policy) -> Result<Self, Self::Error> {
        let clauses: Result<Vec<_>, _> = est_policy
            .conditions()
            .iter()
            .cloned()
            .map(|c| c.try_into())
            .collect();
        Ok(super::Policy {
            id: PolicyID("policy".into()),
            effect: match est_policy.effect() {
                crate::ast::Effect::Permit => super::Effect::Permit,
                crate::ast::Effect::Forbid => super::Effect::Forbid,
            },
            principal: est_policy.principal().clone().try_into()?,
            action: est_policy.action().clone().try_into()?,
            resource: est_policy.resource().clone().try_into()?,
            clauses: clauses?,
            annotations: est_policy
                .annotations()
                .0
                .iter()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        v.as_ref().map(|a| a.val.to_string()).unwrap_or_default(),
                    )
                })
                .collect(),
        })
    }
}

impl TryFrom<est::Clause> for super::Clause {
    type Error = ConversionError;

    fn try_from(clause: est::Clause) -> Result<Self, Self::Error> {
        match clause {
            est::Clause::When(expr) => Ok(super::Clause::When(Arc::new(expr.try_into()?))),
            est::Clause::Unless(expr) => Ok(super::Clause::Unless(Arc::new(expr.try_into()?))),
        }
    }
}

fn entity_from_entity_uid_json(
    entity: crate::entities::EntityUidJson,
) -> Result<EntityUID, ConversionError> {
    let ctx = || crate::entities::json::err::JsonDeserializationErrorContext::Context;
    entity
        .into_euid(&ctx)
        .map_err(|e| ConversionError::InvalidEntityUid(e.to_string()))
        .map(EntityUID::from)
}

impl TryFrom<est::PrincipalConstraint> for super::PrincipalConstraint {
    type Error = ConversionError;

    fn try_from(constraint: est::PrincipalConstraint) -> Result<Self, Self::Error> {
        use est::{EqConstraint, PrincipalConstraint as E, PrincipalOrResourceInConstraint};
        match constraint {
            E::All => Ok(super::PrincipalConstraint::Any),
            E::Eq(EqConstraint::Entity { entity }) => Ok(super::PrincipalConstraint::Eq(
                super::EntityOrSlot::Entity(entity_from_entity_uid_json(entity)?),
            )),
            E::Eq(EqConstraint::Slot { slot }) => Ok(super::PrincipalConstraint::Eq(
                super::EntityOrSlot::Slot(slot.into()),
            )),
            E::In(PrincipalOrResourceInConstraint::Entity { entity }) => {
                Ok(super::PrincipalConstraint::In(super::EntityOrSlot::Entity(
                    entity_from_entity_uid_json(entity)?,
                )))
            }
            E::In(PrincipalOrResourceInConstraint::Slot { slot }) => Ok(
                super::PrincipalConstraint::In(super::EntityOrSlot::Slot(slot.into())),
            ),
            E::Is(is_c) => {
                let (entity_type_ast, in_constraint) = is_c.into_components();
                let entity_type = EntityType::from_name(Name::simple(entity_type_ast));
                match in_constraint {
                    None => Ok(super::PrincipalConstraint::Is(entity_type)),
                    Some(PrincipalOrResourceInConstraint::Entity { entity }) => {
                        Ok(super::PrincipalConstraint::IsIn(
                            entity_type,
                            super::EntityOrSlot::Entity(entity_from_entity_uid_json(entity)?),
                        ))
                    }
                    Some(PrincipalOrResourceInConstraint::Slot { slot }) => {
                        Ok(super::PrincipalConstraint::IsIn(
                            entity_type,
                            super::EntityOrSlot::Slot(slot.into()),
                        ))
                    }
                }
            }
        }
    }
}

impl TryFrom<est::ResourceConstraint> for super::ResourceConstraint {
    type Error = ConversionError;

    fn try_from(constraint: est::ResourceConstraint) -> Result<Self, Self::Error> {
        use est::{EqConstraint, PrincipalOrResourceInConstraint, ResourceConstraint as E};
        match constraint {
            E::All => Ok(super::ResourceConstraint::Any),
            E::Eq(EqConstraint::Entity { entity }) => Ok(super::ResourceConstraint::Eq(
                super::EntityOrSlot::Entity(entity_from_entity_uid_json(entity)?),
            )),
            E::Eq(EqConstraint::Slot { slot }) => Ok(super::ResourceConstraint::Eq(
                super::EntityOrSlot::Slot(slot.into()),
            )),
            E::In(PrincipalOrResourceInConstraint::Entity { entity }) => {
                Ok(super::ResourceConstraint::In(super::EntityOrSlot::Entity(
                    entity_from_entity_uid_json(entity)?,
                )))
            }
            E::In(PrincipalOrResourceInConstraint::Slot { slot }) => Ok(
                super::ResourceConstraint::In(super::EntityOrSlot::Slot(slot.into())),
            ),
            E::Is(is_c) => {
                let (entity_type_ast, in_constraint) = is_c.into_components();
                let entity_type = EntityType::from_name(Name::simple(entity_type_ast));
                match in_constraint {
                    None => Ok(super::ResourceConstraint::Is(entity_type)),
                    Some(PrincipalOrResourceInConstraint::Entity { entity }) => {
                        Ok(super::ResourceConstraint::IsIn(
                            entity_type,
                            super::EntityOrSlot::Entity(entity_from_entity_uid_json(
                                entity.clone(),
                            )?),
                        ))
                    }
                    Some(PrincipalOrResourceInConstraint::Slot { slot }) => {
                        Ok(super::ResourceConstraint::IsIn(
                            entity_type,
                            super::EntityOrSlot::Slot(slot.into()),
                        ))
                    }
                }
            }
        }
    }
}

impl TryFrom<est::ActionConstraint> for super::ActionConstraint {
    type Error = ConversionError;

    fn try_from(constraint: est::ActionConstraint) -> Result<Self, Self::Error> {
        use est::{ActionConstraint as E, ActionInConstraint, EqConstraint};
        match constraint {
            E::All => Ok(super::ActionConstraint::Any),
            E::Eq(EqConstraint::Entity { entity }) => Ok(super::ActionConstraint::Eq(
                entity_from_entity_uid_json(entity)?,
            )),
            E::Eq(EqConstraint::Slot { .. }) => {
                Err(ConversionError::ActionConstraintCannotHaveSlots)
            }
            E::In(ActionInConstraint::Single { entity }) => Ok(super::ActionConstraint::In(vec![
                entity_from_entity_uid_json(entity)?,
            ])),
            E::In(ActionInConstraint::Set { entities }) => {
                let euids: Vec<EntityUID> = entities
                    .into_iter()
                    .map(entity_from_entity_uid_json)
                    .try_collect()?;
                Ok(super::ActionConstraint::In(euids))
            }
            #[cfg(feature = "tolerant-ast")]
            E::ErrorConstraint => Err(ConversionError::InvalidEntityUid(
                "Cannot convert EST error constraint to PST".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pst;

    #[test]
    fn test_est_expr_values() {
        let json = r#"{"Value": true}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Literal(_)));
    }

    #[test]
    fn test_est_expr_var() {
        let json = r#"{"Var": "principal"}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Var(pst::expr::Var::Principal)));
    }

    #[test]
    fn test_est_expr_slot() {
        let json = r#"{"Slot": "?principal"}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Slot(_)));
    }

    #[test]
    fn test_est_expr_not() {
        let json = r#"{"!": {"arg": {"Var": "principal"}}}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(
            pst_expr,
            Expr::UnaryOp {
                op: UnaryOp::Not,
                ..
            }
        ));
    }

    #[test]
    fn test_est_expr_neg() {
        let json = r#"{"neg": {"arg": {"Value": 5}}}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(
            pst_expr,
            Expr::UnaryOp {
                op: UnaryOp::Neg,
                ..
            }
        ));
    }

    #[test]
    fn test_est_expr_binary_ops() {
        // Test multiple binary operators: (a < b) && (c > d)
        let json = r#"{
            "&&": {
                "left": {"<": {"left": {"Var": "principal"}, "right": {"Var": "action"}}},
                "right": {">": {"left": {"Var": "resource"}, "right": {"Var": "context"}}}
            }
        }"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(
            pst_expr,
            Expr::BinaryOp {
                op: pst::expr::BinaryOp::And,
                ..
            }
        ));
    }

    #[test]
    fn test_est_expr_if_then_else() {
        let json = r#"{
            "if-then-else": {
                "if": {"Var": "principal"},
                "then": {"Value": true},
                "else": {"Value": false}
            }
        }"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::IfThenElse { .. }));
    }

    #[test]
    fn test_est_expr_set() {
        let json = r#"{"Set": [{"Var": "principal"}, {"Var": "action"}]}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        if let Expr::Set(elems) = pst_expr {
            assert_eq!(elems.len(), 2);
        } else {
            panic!("Expected Set");
        }
    }

    #[test]
    fn test_est_expr_record() {
        let json = r#"{"Record": {"foo": {"Var": "principal"}}}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Record(_)));
    }

    #[test]
    fn test_est_expr_get_attr() {
        let json = r#"{".": {"left": {"Var": "principal"}, "attr": "name"}}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::GetAttr { .. }));
    }

    #[test]
    fn test_est_expr_has_attr() {
        let json = r#"{"has": {"left": {"Var": "principal"}, "attr": "name"}}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::HasAttr { .. }));
        // Extended has attr
        let json2 = r#"{"has": {"left": {"Var": "principal"}, "attr": ["name", "nested"]}}"#;
        let est_expr2: est::Expr = serde_json::from_str(json2).unwrap();
        let pst_expr2: Expr = est_expr2.try_into().unwrap();
        assert!(matches!(pst_expr2, Expr::HasAttr { .. }));
    }

    #[test]
    fn test_est_expr_like() {
        let json = r#"{"like": {"left": {"Var": "principal"}, "pattern": [{"Wildcard": null}, {"Literal": "@example.com"}]}}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Like { .. }));
    }

    #[test]
    fn test_est_expr_is() {
        let json = r#"{"is": {
           "left": { "Var": "principal" },
            "entity_type": "User",
            "in": {"Value": {"__entity": { "type": "Folder", "id": "Public" }}}
    }}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Is { .. }));
    }

    #[test]
    fn test_est_to_pst_simple() {
        // Test simple value conversion
        let est_expr = est::ExprNoExt::Var(crate::ast::Var::Principal);
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Var(pst::expr::Var::Principal)));
    }

    #[test]
    fn test_est_to_pst_binary_ops() {
        let test_cases = vec![
            ("==", pst::expr::BinaryOp::Eq),
            ("!=", pst::expr::BinaryOp::NotEq),
            ("in", pst::expr::BinaryOp::In),
            ("<", pst::expr::BinaryOp::Less),
            ("<=", pst::expr::BinaryOp::LessEq),
            (">", pst::expr::BinaryOp::Greater),
            (">=", pst::expr::BinaryOp::GreaterEq),
            ("&&", pst::expr::BinaryOp::And),
            ("||", pst::expr::BinaryOp::Or),
            ("+", pst::expr::BinaryOp::Add),
            ("-", pst::expr::BinaryOp::Sub),
            ("*", pst::expr::BinaryOp::Mul),
            ("contains", pst::expr::BinaryOp::Contains),
            ("containsAll", pst::expr::BinaryOp::ContainsAll),
            ("containsAny", pst::expr::BinaryOp::ContainsAny),
            ("getTag", pst::expr::BinaryOp::GetTag),
            ("hasTag", pst::expr::BinaryOp::HasTag),
        ];

        for (op_str, expected_op) in test_cases {
            let json = format!(
                r#"{{"{}": {{"left": {{"Var": "principal"}}, "right": {{"Var": "resource"}}}}}}"#,
                op_str
            );
            let est_expr: est::Expr = serde_json::from_str(&json).unwrap();
            let pst_expr: Expr = est_expr.try_into().unwrap();
            if let Expr::BinaryOp { op, .. } = pst_expr {
                assert_eq!(op, expected_op, "Failed for operator {}", op_str);
            } else {
                panic!("Expected BinaryOp for {}", op_str);
            }
        }
    }

    #[test]
    fn test_est_to_pst_is_empty() {
        let arg = Arc::new(est::Expr::ExprNoExt(est::ExprNoExt::Var(
            crate::ast::Var::Principal,
        )));
        let est_expr = est::ExprNoExt::IsEmpty { arg };
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(
            pst_expr,
            Expr::UnaryOp {
                op: UnaryOp::IsEmpty,
                ..
            }
        ));
    }

    #[test]
    fn test_est_to_pst_get_attr() {
        let left = Arc::new(est::Expr::ExprNoExt(est::ExprNoExt::Var(
            crate::ast::Var::Principal,
        )));
        let est_expr = est::ExprNoExt::GetAttr {
            left,
            attr: "name".try_into().unwrap(),
        };
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::GetAttr { .. }));
    }

    #[test]
    fn test_est_to_pst_has_attr() {
        let left = Arc::new(est::Expr::ExprNoExt(est::ExprNoExt::Var(
            crate::ast::Var::Principal,
        )));
        let est_expr = est::ExprNoExt::HasAttr(est::HasAttrRepr::Simple {
            left,
            attr: "name".try_into().unwrap(),
        });
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::HasAttr { .. }));
    }

    #[test]
    fn test_est_to_pst_like() {
        let left = Arc::new(est::Expr::ExprNoExt(est::ExprNoExt::Var(
            crate::ast::Var::Principal,
        )));
        let pattern = vec![
            est::PatternElem::Wildcard,
            est::PatternElem::Literal("test".try_into().unwrap()),
        ];
        let est_expr = est::ExprNoExt::Like { left, pattern };
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Like { .. }));
    }

    #[test]
    fn test_est_to_pst_is() {
        let left = Arc::new(est::Expr::ExprNoExt(est::ExprNoExt::Var(
            crate::ast::Var::Principal,
        )));
        let est_expr = est::ExprNoExt::Is {
            left,
            entity_type: "User".try_into().unwrap(),
            in_expr: None,
        };
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Is { .. }));
    }

    #[test]
    fn test_est_to_pst_set() {
        // Test set conversion
        let est_expr = est::ExprNoExt::Set(vec![
            est::Expr::ExprNoExt(est::ExprNoExt::Var(crate::ast::Var::Principal)),
            est::Expr::ExprNoExt(est::ExprNoExt::Var(crate::ast::Var::Action)),
        ]);
        let pst_expr: Expr = est_expr.try_into().unwrap();
        if let Expr::Set(elems) = pst_expr {
            assert_eq!(elems.len(), 2);
        } else {
            panic!("Expected Set");
        }
    }

    #[test]
    fn test_est_policy_simple() {
        let json = r#"{
            "effect": "permit",
            "principal": {
                "op": "==",
                "entity": { "type": "User", "id": "alice" }
            },
            "action": {
                "op": "==",
                "entity": { "type": "Action", "id": "view" }
            },
            "resource": {
                "op": "All"
            },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        assert!(matches!(pst_policy.effect, pst::Effect::Permit));
    }

    #[test]
    fn test_est_policy_with_in_constraint() {
        let json = r#"{
            "effect": "forbid",
            "principal": {
                "op": "in",
                "entity": { "type": "Group", "id": "admins" }
            },
            "action": {
                "op": "All"
            },
            "resource": {
                "op": "in",
                "entity": { "type": "Folder", "id": "secrets" }
            },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        assert!(matches!(pst_policy.effect, pst::Effect::Forbid));
        assert!(matches!(
            pst_policy.principal,
            pst::PrincipalConstraint::In(_)
        ));
        assert!(matches!(
            pst_policy.resource,
            pst::ResourceConstraint::In(_)
        ));
    }

    #[test]
    fn test_est_policy_with_conditions() {
        let json = r#"{
            "effect": "permit",
            "principal": { "op": "All" },
            "action": { "op": "All" },
            "resource": { "op": "All" },
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "==": {
                            "left": { "Var": "principal" },
                            "right": { "Var": "resource" }
                        }
                    }
                }
            ]
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        assert_eq!(pst_policy.clauses.len(), 1);
        assert!(matches!(pst_policy.clauses[0], pst::Clause::When(..)));
    }

    #[test]
    fn test_est_policy_with_action_set() {
        let json = r#"{
            "effect": "permit",
            "principal": { "op": "All" },
            "action": {
                "op": "in",
                "entities": [
                    { "type": "Action", "id": "read" },
                    { "type": "Action", "id": "write" }
                ]
            },
            "resource": { "op": "All" },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        if let pst::ActionConstraint::In(actions) = pst_policy.action {
            assert_eq!(actions.len(), 2);
        } else {
            panic!("Expected ActionConstraint::In");
        }
    }

    #[test]
    fn test_est_resource_constraint_eq() {
        let json = r#"{
            "effect": "permit",
            "principal": { "op": "All" },
            "action": { "op": "All" },
            "resource": {
                "op": "==",
                "entity": { "type": "File", "id": "doc.txt" }
            },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        assert!(matches!(
            pst_policy.resource,
            pst::ResourceConstraint::Eq(_)
        ));
    }

    #[test]
    fn test_est_resource_constraint_is() {
        let json = r#"{
            "effect": "permit",
            "principal": { "op": "All" },
            "action": { "op": "All" },
            "resource": {
                "op": "is",
                "entity_type": "File"
            },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        assert!(matches!(
            pst_policy.resource,
            pst::ResourceConstraint::Is(_)
        ));
    }

    #[test]
    fn test_est_resource_constraint_is_in() {
        let json = r#"{
            "effect": "permit",
            "principal": { "op": "All" },
            "action": { "op": "All" },
            "resource": {
                "op": "is",
                "entity_type": "File",
                "in": { "entity": { "type": "Folder", "id": "docs" } }
            },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        assert!(matches!(
            pst_policy.resource,
            pst::ResourceConstraint::IsIn(..)
        ));
    }

    #[test]
    fn test_est_action_constraint_eq() {
        let json = r#"{
            "effect": "permit",
            "principal": { "op": "All" },
            "action": {
                "op": "==",
                "entity": { "type": "Action", "id": "view" }
            },
            "resource": { "op": "All" },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        assert!(matches!(pst_policy.action, pst::ActionConstraint::Eq(_)));
    }

    #[test]
    fn test_est_action_constraint_in_single() {
        let json = r#"{
            "effect": "permit",
            "principal": { "op": "All" },
            "action": {
                "op": "in",
                "entity": { "type": "Action", "id": "view" }
            },
            "resource": { "op": "All" },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        if let pst::ActionConstraint::In(actions) = pst_policy.action {
            assert_eq!(actions.len(), 1);
        } else {
            panic!("Expected ActionConstraint::In");
        }
    }

    #[test]
    fn test_est_action_constraint_slot_panics() {
        use crate::ast::SlotId;
        let constraint = est::ActionConstraint::Eq(est::EqConstraint::Slot {
            slot: SlotId::principal(),
        });
        let result: Result<pst::ActionConstraint, _> = constraint.try_into();
        assert!(matches!(
            result,
            Err(ConversionError::ActionConstraintCannotHaveSlots)
        ));
    }

    #[test]
    fn test_est_principal_constraint_eq() {
        let json = r#"{
            "effect": "permit",
            "principal": {
                "op": "==",
                "entity": { "type": "User", "id": "alice" }
            },
            "action": { "op": "All" },
            "resource": { "op": "All" },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        assert!(matches!(
            pst_policy.principal,
            pst::PrincipalConstraint::Eq(_)
        ));
    }

    #[test]
    fn test_est_principal_constraint_is() {
        let json = r#"{
            "effect": "permit",
            "principal": {
                "op": "is",
                "entity_type": "User"
            },
            "action": { "op": "All" },
            "resource": { "op": "All" },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        assert!(matches!(
            pst_policy.principal,
            pst::PrincipalConstraint::Is(_)
        ));
    }

    #[test]
    fn test_est_principal_constraint_is_in() {
        let json = r#"{
            "effect": "permit",
            "principal": {
                "op": "is",
                "entity_type": "User",
                "in": { "entity": { "type": "Group", "id": "admins" } }
            },
            "action": { "op": "All" },
            "resource": { "op": "All" },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        assert!(matches!(
            pst_policy.principal,
            pst::PrincipalConstraint::IsIn(..)
        ));
    }

    #[test]
    fn test_est_principal_constraint_slot() {
        let json = r#"{
            "effect": "permit",
            "principal": {
                "op": "==",
                "slot": "?principal"
            },
            "action": { "op": "All" },
            "resource": { "op": "All" },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        if let pst::PrincipalConstraint::Eq(pst::EntityOrSlot::Slot(_)) = pst_policy.principal {
            // Success
        } else {
            panic!("Expected PrincipalConstraint::Eq with Slot");
        }
    }

    #[test]
    fn test_est_resource_constraint_slot() {
        let json = r#"{
            "effect": "permit",
            "principal": { "op": "All" },
            "action": { "op": "All" },
            "resource": {
                "op": "in",
                "slot": "?resource"
            },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        if let pst::ResourceConstraint::In(pst::EntityOrSlot::Slot(_)) = pst_policy.resource {
            // Success
        } else {
            panic!("Expected ResourceConstraint::In with Slot");
        }
    }

    #[test]
    fn test_est_principal_constraint_is_in_slot() {
        let json = r#"{
            "effect": "permit",
            "principal": {
                "op": "is",
                "entity_type": "User",
                "in": { "slot": "?principal" }
            },
            "action": { "op": "All" },
            "resource": { "op": "All" },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        if let pst::PrincipalConstraint::IsIn(_, pst::EntityOrSlot::Slot(_)) = pst_policy.principal
        {
            // Success
        } else {
            panic!("Expected PrincipalConstraint::IsIn with Slot");
        }
    }

    #[test]
    fn test_est_resource_constraint_is_in_slot() {
        let json = r#"{
            "effect": "permit",
            "principal": { "op": "All" },
            "action": { "op": "All" },
            "resource": {
                "op": "is",
                "entity_type": "File",
                "in": { "slot": "?resource" }
            },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        if let pst::ResourceConstraint::IsIn(_, pst::EntityOrSlot::Slot(_)) = pst_policy.resource {
            // Success
        } else {
            panic!("Expected ResourceConstraint::IsIn with Slot");
        }
    }

    #[test]
    fn test_est_expr_func_call() {
        // Test unary function calls (single argument)
        let json = r#"{"decimal": [{"Value": "1.23"}]}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(
            pst_expr,
            Expr::UnaryOp {
                op: UnaryOp::Decimal,
                ..
            }
        ));

        let json = r#"{"datetime": [{"Value": "2025-10-10T10:01:10"}]}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(
            pst_expr,
            Expr::UnaryOp {
                op: UnaryOp::Datetime,
                ..
            }
        ));

        let json = r#"{"ip": [{"Value": "192.168.0.1"}]}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(
            pst_expr,
            Expr::UnaryOp {
                op: UnaryOp::Ip,
                ..
            }
        ));

        // Test binary function calls (two arguments)
        let json = r#"{"durationSince": [
          {"datetime": [{"Value": "2025-10-10T10:01:10"}]},
          {"datetime": [{"Value": "2025-09-10T10:01:10"}]}
         ]}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(
            pst_expr,
            Expr::BinaryOp {
                op: pst::expr::BinaryOp::DurationSince,
                ..
            }
        ));

        // Complex argument (expression)
        let json = r#"{"decimal": [{"&&": {"left": {"Value": true}, "right": {"Value": false}}}]}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        if let Expr::UnaryOp {
            op: UnaryOp::Decimal,
            expr,
        } = est_expr.try_into().unwrap()
        {
            assert!(matches!(
                *expr,
                Expr::BinaryOp {
                    op: pst::expr::BinaryOp::And,
                    ..
                }
            ));
        } else {
            panic!("Expected UnaryOp::Decimal with complex arg");
        }

        // Nested function call
        let json = r#"{"decimal": [{"ip": [{"Value": "192.168.0.1"}]}]}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        if let Expr::UnaryOp {
            op: UnaryOp::Decimal,
            expr,
        } = est_expr.try_into().unwrap()
        {
            assert!(matches!(
                *expr,
                Expr::UnaryOp {
                    op: UnaryOp::Ip,
                    ..
                }
            ));
        } else {
            panic!("Expected UnaryOp::Decimal with nested UnaryOp::Ip");
        }
    }

    #[test]
    fn test_valid_est_invalid_cedar_is_invalid_pst() {
        let json = r#"{"offset": []}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let result: Result<Expr, _> = est_expr.try_into();
        assert!(result.is_err());
        assert!(matches!(result, Err(ConversionError::InvalidMethodCall(_))));
    }
}
