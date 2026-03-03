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

use super::{
    ActionConstraint, Clause, Effect, EntityOrSlot, EntityType, EntityUID, Expr, Name, Policy,
    PolicyID, PrincipalConstraint, PstConstructionError, ResourceConstraint,
};
use crate::ast;
use crate::entities;
use crate::est;
use crate::pst::err::error_body::InvalidEntityUidError;
use itertools::Itertools;
use std::sync::Arc;

// ============================================================================
// EST → PST Conversions
// ============================================================================

impl TryFrom<est::Policy> for Policy {
    type Error = PstConstructionError;

    fn try_from(est_policy: est::Policy) -> Result<Self, Self::Error> {
        let clauses: Result<Vec<_>, _> = est_policy
            .conditions
            .into_iter()
            .map(|c| c.try_into())
            .collect();

        Ok(Policy {
            id: PolicyID("policy".into()),
            effect: match est_policy.effect {
                ast::Effect::Permit => Effect::Permit,
                ast::Effect::Forbid => Effect::Forbid,
            },
            principal: est_policy.principal.try_into()?,
            action: est_policy.action.try_into()?,
            resource: est_policy.resource.try_into()?,
            clauses: clauses?,
            annotations: est_policy
                .annotations
                .0
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.map(|a| a.val).unwrap_or_default()))
                .collect(),
        })
    }
}

impl TryFrom<est::Clause> for Clause {
    type Error = PstConstructionError;

    fn try_from(clause: est::Clause) -> Result<Self, Self::Error> {
        match clause {
            est::Clause::When(expr) => Ok(Clause::When(Arc::new(expr.try_into()?))),
            est::Clause::Unless(expr) => Ok(Clause::Unless(Arc::new(expr.try_into()?))),
        }
    }
}

impl TryFrom<entities::EntityUidJson> for EntityUID {
    type Error = PstConstructionError;

    fn try_from(entity: entities::EntityUidJson) -> Result<Self, Self::Error> {
        let ctx = || crate::entities::json::err::JsonDeserializationErrorContext::Context;
        entity
            .into_euid(&ctx)
            .map_err(|e| {
                InvalidEntityUidError {
                    description: e.to_string(),
                }
                .into()
            })
            .map(EntityUID::from)
    }
}

impl TryFrom<est::PrincipalConstraint> for PrincipalConstraint {
    type Error = PstConstructionError;

    fn try_from(constraint: est::PrincipalConstraint) -> Result<Self, Self::Error> {
        use est::{EqConstraint, PrincipalConstraint as E, PrincipalOrResourceInConstraint};
        match constraint {
            E::All => Ok(PrincipalConstraint::Any),
            E::Eq(EqConstraint::Entity { entity }) => Ok(PrincipalConstraint::Eq(
                EntityOrSlot::Entity(entity.try_into()?),
            )),
            E::Eq(EqConstraint::Slot { slot }) => {
                Ok(PrincipalConstraint::Eq(EntityOrSlot::Slot(slot.into())))
            }
            E::In(PrincipalOrResourceInConstraint::Entity { entity }) => Ok(
                PrincipalConstraint::In(EntityOrSlot::Entity(entity.try_into()?)),
            ),
            E::In(PrincipalOrResourceInConstraint::Slot { slot }) => {
                Ok(PrincipalConstraint::In(EntityOrSlot::Slot(slot.into())))
            }
            E::Is(is_c) => {
                let (entity_type_ast, in_constraint) = is_c.into_components();
                let entity_type = EntityType::from_name(Name::unqualified(entity_type_ast));
                match in_constraint {
                    None => Ok(PrincipalConstraint::Is(entity_type)),
                    Some(PrincipalOrResourceInConstraint::Entity { entity }) => {
                        Ok(PrincipalConstraint::IsIn(
                            entity_type,
                            EntityOrSlot::Entity(entity.try_into()?),
                        ))
                    }
                    Some(PrincipalOrResourceInConstraint::Slot { slot }) => Ok(
                        PrincipalConstraint::IsIn(entity_type, EntityOrSlot::Slot(slot.into())),
                    ),
                }
            }
        }
    }
}

impl TryFrom<est::ResourceConstraint> for ResourceConstraint {
    type Error = PstConstructionError;

    fn try_from(constraint: est::ResourceConstraint) -> Result<Self, Self::Error> {
        use est::{EqConstraint, PrincipalOrResourceInConstraint, ResourceConstraint as E};
        match constraint {
            E::All => Ok(ResourceConstraint::Any),
            E::Eq(EqConstraint::Entity { entity }) => Ok(ResourceConstraint::Eq(
                EntityOrSlot::Entity(entity.try_into()?),
            )),
            E::Eq(EqConstraint::Slot { slot }) => {
                Ok(ResourceConstraint::Eq(EntityOrSlot::Slot(slot.into())))
            }
            E::In(PrincipalOrResourceInConstraint::Entity { entity }) => Ok(
                ResourceConstraint::In(EntityOrSlot::Entity(entity.try_into()?)),
            ),
            E::In(PrincipalOrResourceInConstraint::Slot { slot }) => {
                Ok(ResourceConstraint::In(EntityOrSlot::Slot(slot.into())))
            }
            E::Is(is_c) => {
                let (entity_type_ast, in_constraint) = is_c.into_components();
                let entity_type = EntityType::from_name(Name::unqualified(entity_type_ast));
                match in_constraint {
                    None => Ok(ResourceConstraint::Is(entity_type)),
                    Some(PrincipalOrResourceInConstraint::Entity { entity }) => {
                        Ok(ResourceConstraint::IsIn(
                            entity_type,
                            EntityOrSlot::Entity(entity.try_into()?),
                        ))
                    }
                    Some(PrincipalOrResourceInConstraint::Slot { slot }) => Ok(
                        ResourceConstraint::IsIn(entity_type, EntityOrSlot::Slot(slot.into())),
                    ),
                }
            }
        }
    }
}

impl TryFrom<est::ActionConstraint> for ActionConstraint {
    type Error = PstConstructionError;

    fn try_from(constraint: est::ActionConstraint) -> Result<Self, Self::Error> {
        use est::{ActionConstraint as E, ActionInConstraint, EqConstraint};
        match constraint {
            E::All => Ok(ActionConstraint::Any),
            E::Eq(EqConstraint::Entity { entity }) => Ok(ActionConstraint::Eq(entity.try_into()?)),
            E::Eq(EqConstraint::Slot { .. }) => {
                Err(super::err::error_body::ActionConstraintCannotHaveSlotsError.into())
            }
            E::In(ActionInConstraint::Single { entity }) => {
                Ok(ActionConstraint::In(vec![entity.try_into()?]))
            }
            E::In(ActionInConstraint::Set { entities }) => {
                let euids: Vec<EntityUID> =
                    entities.into_iter().map(TryInto::try_into).try_collect()?;
                Ok(ActionConstraint::In(euids))
            }
            #[cfg(feature = "tolerant-ast")]
            E::ErrorConstraint => Err(InvalidEntityUidError {
                description: "Cannot convert EST error constraint to PST".to_string(),
            }
            .into()),
        }
    }
}

impl TryFrom<est::Expr> for Expr {
    type Error = PstConstructionError;

    fn try_from(est_expr: est::Expr) -> Result<Self, PstConstructionError> {
        est_expr.try_into_expr::<super::expr::PstBuilder>()
    }
}

// ============================================================================
// PST → EST Conversions
// ============================================================================

impl TryFrom<Expr> for est::Expr {
    type Error = PstConstructionError;

    fn try_from(expr: Expr) -> Result<Self, PstConstructionError> {
        expr.try_into_expr::<est::Builder>()
    }
}

impl TryFrom<Policy> for est::Policy {
    type Error = PstConstructionError;

    fn try_from(policy: Policy) -> Result<Self, Self::Error> {
        let mut annotations = est::Annotations::new();
        for (k, v) in policy.annotations.into_iter() {
            annotations.0.insert(
                ast::AnyId::new_unchecked(k),
                Some(ast::Annotation {
                    val: v.into(),
                    loc: None,
                }),
            );
        }
        Ok(est::Policy {
            effect: match policy.effect {
                Effect::Permit => ast::Effect::Permit,
                Effect::Forbid => ast::Effect::Forbid,
            },
            principal: policy.principal.into(),
            action: policy.action.into(),
            resource: policy.resource.into(),
            conditions: policy
                .clauses
                .into_iter()
                .map(|c| c.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            annotations,
        })
    }
}

impl TryFrom<Clause> for est::Clause {
    type Error = PstConstructionError;

    fn try_from(clause: Clause) -> Result<Self, Self::Error> {
        Ok(match clause {
            Clause::When(expr) => est::Clause::When(Arc::unwrap_or_clone(expr).try_into()?),
            Clause::Unless(expr) => est::Clause::Unless(Arc::unwrap_or_clone(expr).try_into()?),
        })
    }
}

impl From<PrincipalConstraint> for est::PrincipalConstraint {
    fn from(constraint: PrincipalConstraint) -> Self {
        match constraint {
            PrincipalConstraint::Any => est::PrincipalConstraint::All,
            PrincipalConstraint::Eq(eos) => match eos {
                EntityOrSlot::Entity(entity) => {
                    est::PrincipalConstraint::Eq(est::EqConstraint::Entity {
                        entity: entity.into(),
                    })
                }
                EntityOrSlot::Slot(slot) => {
                    est::PrincipalConstraint::Eq(est::EqConstraint::Slot { slot: slot.into() })
                }
            },
            PrincipalConstraint::In(eos) => match eos {
                EntityOrSlot::Entity(entity) => {
                    est::PrincipalConstraint::In(est::PrincipalOrResourceInConstraint::Entity {
                        entity: entity.into(),
                    })
                }
                EntityOrSlot::Slot(slot) => {
                    est::PrincipalConstraint::In(est::PrincipalOrResourceInConstraint::Slot {
                        slot: slot.into(),
                    })
                }
            },
            PrincipalConstraint::Is(entity_type) => {
                est::PrincipalConstraint::Is(est::PrincipalOrResourceIsConstraint {
                    entity_type: entity_type.to_string().into(),
                    in_entity: None,
                })
            }
            PrincipalConstraint::IsIn(entity_type, eos) => {
                let in_entity = match eos {
                    EntityOrSlot::Entity(entity) => est::PrincipalOrResourceInConstraint::Entity {
                        entity: entity.into(),
                    },
                    EntityOrSlot::Slot(slot) => {
                        est::PrincipalOrResourceInConstraint::Slot { slot: slot.into() }
                    }
                };
                est::PrincipalConstraint::Is(est::PrincipalOrResourceIsConstraint {
                    entity_type: entity_type.to_string().into(),
                    in_entity: Some(in_entity),
                })
            }
        }
    }
}

impl From<ResourceConstraint> for est::ResourceConstraint {
    fn from(constraint: ResourceConstraint) -> Self {
        match constraint {
            ResourceConstraint::Any => est::ResourceConstraint::All,
            ResourceConstraint::Eq(eos) => match eos {
                EntityOrSlot::Entity(entity) => {
                    est::ResourceConstraint::Eq(est::EqConstraint::Entity {
                        entity: entity.into(),
                    })
                }
                EntityOrSlot::Slot(slot) => {
                    est::ResourceConstraint::Eq(est::EqConstraint::Slot { slot: slot.into() })
                }
            },
            ResourceConstraint::In(eos) => match eos {
                EntityOrSlot::Entity(entity) => {
                    est::ResourceConstraint::In(est::PrincipalOrResourceInConstraint::Entity {
                        entity: entity.into(),
                    })
                }
                EntityOrSlot::Slot(slot) => {
                    est::ResourceConstraint::In(est::PrincipalOrResourceInConstraint::Slot {
                        slot: slot.into(),
                    })
                }
            },
            ResourceConstraint::Is(entity_type) => {
                est::ResourceConstraint::Is(est::PrincipalOrResourceIsConstraint {
                    entity_type: entity_type.to_string().into(),
                    in_entity: None,
                })
            }
            ResourceConstraint::IsIn(entity_type, eos) => {
                let in_entity = match eos {
                    EntityOrSlot::Entity(entity) => est::PrincipalOrResourceInConstraint::Entity {
                        entity: entity.into(),
                    },
                    EntityOrSlot::Slot(slot) => {
                        est::PrincipalOrResourceInConstraint::Slot { slot: slot.into() }
                    }
                };
                est::ResourceConstraint::Is(est::PrincipalOrResourceIsConstraint {
                    entity_type: entity_type.to_string().into(),
                    in_entity: Some(in_entity),
                })
            }
        }
    }
}

#[expect(
    clippy::fallible_impl_from,
    reason = "not faillible, as the unwrap cannot fail"
)]
impl From<ActionConstraint> for est::ActionConstraint {
    fn from(constraint: ActionConstraint) -> Self {
        match constraint {
            ActionConstraint::Any => est::ActionConstraint::All,
            ActionConstraint::Eq(entity) => est::ActionConstraint::Eq(est::EqConstraint::Entity {
                entity: entity.into(),
            }),
            ActionConstraint::In(entities) => {
                if entities.len() == 1 {
                    #[expect(
                        clippy::unwrap_used,
                        reason = "entities length checked to be 1 in this arm"
                    )]
                    est::ActionConstraint::In(est::ActionInConstraint::Single {
                        entity: entities.into_iter().next().unwrap().into(),
                    })
                } else {
                    est::ActionConstraint::In(est::ActionInConstraint::Set {
                        entities: entities.into_iter().map(Into::into).collect(),
                    })
                }
            }
        }
    }
}

impl From<EntityUID> for entities::EntityUidJson {
    fn from(uid: EntityUID) -> Self {
        entities::EntityUidJson::new(uid.ty.to_string(), uid.eid.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pst::{self, UnaryOp};

    fn roundtrips(e: Expr) {
        let est: est::Expr = e.clone().try_into().unwrap();
        let roundtrip_e: Expr = est.try_into().unwrap();
        assert!(roundtrip_e == e)
    }

    fn policy_roundtrips(p: Policy) {
        let est: est::Policy = p.clone().try_into().unwrap();
        let roundtrip_p: Policy = est.try_into().unwrap();
        assert!(roundtrip_p == p)
    }

    #[test]
    fn test_est_expr_values() {
        let json = r#"{"Value": true}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Literal(_)));
        roundtrips(pst_expr);
    }

    #[test]
    fn test_est_expr_var() {
        let json = r#"{"Var": "principal"}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Var(pst::expr::Var::Principal)));
        roundtrips(pst_expr);
    }

    #[test]
    fn test_est_expr_slot() {
        let json = r#"{"Slot": "?principal"}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Slot(_)));
        // Roundtrip is not supported for slots
        let result: Result<est::Expr, _> = pst_expr.try_into();
        assert!(matches!(
            result,
            Err(PstConstructionError::NotImplemented(..))
        ));
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
        roundtrips(pst_expr);
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
        roundtrips(pst_expr);
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
        roundtrips(pst_expr);
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
        roundtrips(pst_expr);
    }

    #[test]
    fn test_est_expr_set() {
        let json = r#"{"Set": [{"Var": "principal"}, {"Var": "action"}]}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        roundtrips(pst_expr.clone());
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
        roundtrips(pst_expr);
    }

    #[test]
    fn test_est_expr_get_attr() {
        let json = r#"{".": {"left": {"Var": "principal"}, "attr": "name"}}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::GetAttr { .. }));
        roundtrips(pst_expr);
    }

    #[test]
    fn test_est_expr_has_attr() {
        let json = r#"{"has": {"left": {"Var": "principal"}, "attr": "name"}}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::HasAttr { .. }));
        roundtrips(pst_expr);
        // Extended has attr — does not roundtrip because the EST builder desugars it
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
        roundtrips(pst_expr);
    }

    #[test]
    fn test_est_expr_is() {
        // Test simple is without in
        let json = r#"{"is": {
           "left": { "Var": "principal" },
            "entity_type": "User"
    }}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Is { in_expr: None, .. }));
        roundtrips(pst_expr);

        // Test is with in - now uses is_in_entity_type
        let json2 = r#"{"is": {
           "left": { "Var": "principal" },
            "entity_type": "User",
            "in": {"Value": {"__entity": { "type": "Folder", "id": "Public" }}}
    }}"#;
        let est_expr2: est::Expr = serde_json::from_str(json2).unwrap();
        let pst_expr2: Expr = est_expr2.try_into().unwrap();
        assert!(matches!(
            pst_expr2,
            Expr::Is {
                in_expr: Some(_),
                ..
            }
        ));
        roundtrips(pst_expr2);
    }

    #[test]
    fn test_est_to_pst_simple() {
        // Test simple value conversion
        let est_expr = est::Expr::ExprNoExt(est::ExprNoExt::Var(ast::Var::Principal));
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Var(pst::expr::Var::Principal)));
        roundtrips(pst_expr);
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
            roundtrips(pst_expr);
        }
    }

    #[test]
    fn test_est_to_pst_is_empty() {
        let arg = Arc::new(est::Expr::ExprNoExt(est::ExprNoExt::Var(
            ast::Var::Principal,
        )));
        let est_expr = est::Expr::ExprNoExt(est::ExprNoExt::IsEmpty { arg });
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(
            pst_expr,
            Expr::UnaryOp {
                op: UnaryOp::IsEmpty,
                ..
            }
        ));
        roundtrips(pst_expr);
    }

    #[test]
    fn test_est_to_pst_get_attr() {
        let left = Arc::new(est::Expr::ExprNoExt(est::ExprNoExt::Var(
            ast::Var::Principal,
        )));
        let est_expr = est::Expr::ExprNoExt(est::ExprNoExt::GetAttr {
            left,
            attr: "name".try_into().unwrap(),
        });
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::GetAttr { .. }));
        roundtrips(pst_expr);
    }

    #[test]
    fn test_est_to_pst_has_attr() {
        let left = Arc::new(est::Expr::ExprNoExt(est::ExprNoExt::Var(
            ast::Var::Principal,
        )));
        let est_expr = est::Expr::ExprNoExt(est::ExprNoExt::HasAttr(est::HasAttrRepr::Simple {
            left,
            attr: "name".try_into().unwrap(),
        }));
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::HasAttr { .. }));
        roundtrips(pst_expr);
    }

    #[test]
    fn test_est_to_pst_like() {
        let left = Arc::new(est::Expr::ExprNoExt(est::ExprNoExt::Var(
            ast::Var::Principal,
        )));
        let pattern = vec![
            est::PatternElem::Wildcard,
            est::PatternElem::Literal("test".try_into().unwrap()),
        ];
        let est_expr = est::Expr::ExprNoExt(est::ExprNoExt::Like { left, pattern });
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Like { .. }));
        roundtrips(pst_expr);
    }

    #[test]
    fn test_est_to_pst_is() {
        let left = Arc::new(est::Expr::ExprNoExt(est::ExprNoExt::Var(
            ast::Var::Principal,
        )));
        let est_expr = est::Expr::ExprNoExt(est::ExprNoExt::Is {
            left,
            entity_type: "User".try_into().unwrap(),
            in_expr: None,
        });
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Is { .. }));
        roundtrips(pst_expr);
    }

    #[test]
    fn test_est_to_pst_set() {
        // Test set conversion
        let est_expr = est::Expr::ExprNoExt(est::ExprNoExt::Set(vec![
            est::Expr::ExprNoExt(est::ExprNoExt::Var(ast::Var::Principal)),
            est::Expr::ExprNoExt(est::ExprNoExt::Var(ast::Var::Action)),
        ]));
        let pst_expr: Expr = est_expr.try_into().unwrap();
        roundtrips(pst_expr.clone());
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
        policy_roundtrips(pst_policy);
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
        policy_roundtrips(pst_policy);
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
        policy_roundtrips(pst_policy);
    }

    #[test]
    fn test_est_policy_with_annotations() {
        let json = r#"{
            "effect": "permit",
            "principal": { "op": "All" },
            "action": { "op": "All" },
            "resource": { "op": "All" },
            "conditions": [],
            "annotations": {
                "reason": "allow all access",
                "id": "policy_1"
            }
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: pst::Policy = est_policy.try_into().unwrap();
        assert_eq!(pst_policy.annotations.len(), 2);
        assert_eq!(pst_policy.annotations.get("reason").unwrap(), "allow all access");
        assert_eq!(pst_policy.annotations.get("id").unwrap(), "policy_1");
        policy_roundtrips(pst_policy);
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
        policy_roundtrips(pst_policy.clone());
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
        policy_roundtrips(pst_policy);
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
        policy_roundtrips(pst_policy);
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
        policy_roundtrips(pst_policy);
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
        policy_roundtrips(pst_policy);
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
        policy_roundtrips(pst_policy.clone());
        if let pst::ActionConstraint::In(actions) = pst_policy.action {
            assert_eq!(actions.len(), 1);
        } else {
            panic!("Expected ActionConstraint::In");
        }
    }

    #[test]
    fn test_est_action_constraint_slot_panics() {
        use ast::SlotId;
        let constraint = est::ActionConstraint::Eq(est::EqConstraint::Slot {
            slot: SlotId::principal(),
        });
        let result: Result<pst::ActionConstraint, _> = constraint.try_into();
        assert!(matches!(
            result,
            Err(PstConstructionError::ActionConstraintCannotHaveSlots(..))
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
        policy_roundtrips(pst_policy);
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
        policy_roundtrips(pst_policy);
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
        policy_roundtrips(pst_policy);
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
        policy_roundtrips(pst_policy);
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
        policy_roundtrips(pst_policy);
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
        policy_roundtrips(pst_policy);
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
        policy_roundtrips(pst_policy);
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
        roundtrips(pst_expr);

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
        roundtrips(pst_expr);

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
        roundtrips(pst_expr);

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
        roundtrips(pst_expr);

        // Complex argument (expression)
        let json = r#"{"decimal": [{"&&": {"left": {"Value": true}, "right": {"Value": false}}}]}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        roundtrips(pst_expr.clone());
        if let Expr::UnaryOp {
            op: UnaryOp::Decimal,
            expr,
        } = pst_expr
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
        let pst_expr: Expr = est_expr.try_into().unwrap();
        roundtrips(pst_expr.clone());
        if let Expr::UnaryOp {
            op: UnaryOp::Decimal,
            expr,
        } = pst_expr
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
        assert!(matches!(result, Err(PstConstructionError::WrongArity(..))));
    }
}
