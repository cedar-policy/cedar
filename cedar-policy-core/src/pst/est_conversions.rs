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
use crate::pst::err::error_body;
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
                error_body::InvalidEntityUidError {
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
            E::ErrorConstraint => Err((error_body::UnsupportedErrorNode {}).into()),
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
        for (k, val) in policy.annotations.into_iter() {
            let annotation = if val.is_empty() {
                None
            } else {
                Some(ast::Annotation { val, loc: None })
            };
            let id = k.parse::<ast::AnyId>().map_err(|p| {
                PstConstructionError::ParsingFailed(error_body::ParsingFailedError {
                    description: p.to_string(),
                })
            })?;
            annotations.0.insert(id, annotation);
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
            PrincipalConstraint::Is(entity_type) => est::PrincipalConstraint::Is(
                est::PrincipalOrResourceIsConstraint::new(entity_type.to_string().into(), None),
            ),
            PrincipalConstraint::IsIn(entity_type, eos) => {
                let in_entity = match eos {
                    EntityOrSlot::Entity(entity) => est::PrincipalOrResourceInConstraint::Entity {
                        entity: entity.into(),
                    },
                    EntityOrSlot::Slot(slot) => {
                        est::PrincipalOrResourceInConstraint::Slot { slot: slot.into() }
                    }
                };
                est::PrincipalConstraint::Is(est::PrincipalOrResourceIsConstraint::new(
                    entity_type.to_string().into(),
                    Some(in_entity),
                ))
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
            ResourceConstraint::Is(entity_type) => est::ResourceConstraint::Is(
                est::PrincipalOrResourceIsConstraint::new(entity_type.to_string().into(), None),
            ),
            ResourceConstraint::IsIn(entity_type, eos) => {
                let in_entity = match eos {
                    EntityOrSlot::Entity(entity) => est::PrincipalOrResourceInConstraint::Entity {
                        entity: entity.into(),
                    },
                    EntityOrSlot::Slot(slot) => {
                        est::PrincipalOrResourceInConstraint::Slot { slot: slot.into() }
                    }
                };
                est::ResourceConstraint::Is(est::PrincipalOrResourceIsConstraint::new(
                    entity_type.to_string().into(),
                    Some(in_entity),
                ))
            }
        }
    }
}

#[expect(
    clippy::fallible_impl_from,
    reason = "not fallible, as the unwrap cannot fail"
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
    use crate::pst::{self, BinaryOp, UnaryOp};
    use smol_str::SmolStr;
    use std::collections::BTreeMap;

    /// EST (JSON) → PST → EST → PST roundtrip for expressions.
    /// Parses `json` as an EST expression, converts to PST, asserts `check`,
    /// then roundtrips back through EST and verifies both representations are stable.
    fn est_expr_roundtrip(json: &str, check: &dyn Fn(&Expr) -> bool) {
        let est1: est::Expr = serde_json::from_str(json).unwrap();
        let pst1: Expr = est1.clone().try_into().unwrap();
        assert!(check(&pst1), "Pattern check failed for: {json}");
        let est2: est::Expr = pst1.clone().try_into().unwrap();
        let pst2: Expr = est2.clone().try_into().unwrap();
        assert_eq!(est1, est2, "EST mismatch for: {json}");
        assert_eq!(pst1, pst2, "PST mismatch for: {json}");
    }

    #[test]
    fn test_est_expr_roundtrips() {
        let cases: Vec<(&str, fn(&Expr) -> bool)> = vec![
            // Literals
            (r#"{ "Value": true }"#, |e| matches!(e, Expr::Literal(_))),
            // Variables
            (r#"{ "Var": "principal" }"#, |e| {
                matches!(e, Expr::Var(pst::expr::Var::Principal))
            }),
            // Slots
            (r#"{ "Slot": "?principal" }"#, |e| {
                matches!(e, Expr::Slot(_))
            }),
            // Unary: not
            (r#"{ "!": { "arg": { "Var": "principal" } } }"#, |e| {
                matches!(
                    e,
                    Expr::UnaryOp {
                        op: UnaryOp::Not,
                        ..
                    }
                )
            }),
            // Unary: neg
            (r#"{ "neg": { "arg": { "Value": 5 } } }"#, |e| {
                matches!(
                    e,
                    Expr::UnaryOp {
                        op: UnaryOp::Neg,
                        ..
                    }
                )
            }),
            // Unary: isEmpty
            (r#"{ "isEmpty": { "arg": { "Var": "principal" } } }"#, |e| {
                matches!(
                    e,
                    Expr::UnaryOp {
                        op: UnaryOp::IsEmpty,
                        ..
                    }
                )
            }),
            // Nested binary: (a < b) && (c > d)
            (
                r#"{
                    "&&": {
                        "left":  { "<": { "left": { "Var": "principal" }, "right": { "Var": "action" } } },
                        "right": { ">": { "left": { "Var": "resource" },  "right": { "Var": "context" } } }
                    }
                }"#,
                |e| {
                    matches!(
                        e,
                        Expr::BinaryOp {
                            op: BinaryOp::And,
                            ..
                        }
                    )
                },
            ),
            // If-then-else
            (
                r#"{
                    "if-then-else": {
                        "if":   { "Var": "principal" },
                        "then": { "Value": true },
                        "else": { "Value": false }
                    }
                }"#,
                |e| matches!(e, Expr::IfThenElse { .. }),
            ),
            // Set
            (
                r#"{ "Set": [{ "Var": "principal" }, { "Var": "action" }] }"#,
                |e| matches!(e, Expr::Set(elems) if elems.len() == 2),
            ),
            // Record
            (r#"{ "Record": { "foo": { "Var": "principal" } } }"#, |e| {
                matches!(e, Expr::Record(_))
            }),
            // GetAttr
            (
                r#"{ ".": { "left": { "Var": "principal" }, "attr": "name" } }"#,
                |e| matches!(e, Expr::GetAttr { .. }),
            ),
            // HasAttr
            (
                r#"{ "has": { "left": { "Var": "principal" }, "attr": "name" } }"#,
                |e| matches!(e, Expr::HasAttr { .. }),
            ),
            // Like (single-char literal; multi-char gets split by PST→EST)
            (
                r#"{
                    "like": {
                        "left": { "Var": "principal" },
                        "pattern": [{ "Wildcard": null }, { "Literal": "x" }]
                    }
                }"#,
                |e| matches!(e, Expr::Like { .. }),
            ),
            // Is (without in)
            (
                r#"{ "is": { "left": { "Var": "principal" }, "entity_type": "User" } }"#,
                |e| matches!(e, Expr::Is { in_expr: None, .. }),
            ),
            // Is (with in)
            (
                r#"{
                    "is": {
                        "left": { "Var": "principal" },
                        "entity_type": "User",
                        "in": { "Value": { "__entity": { "type": "Folder", "id": "Public" } } }
                    }
                }"#,
                |e| {
                    matches!(
                        e,
                        Expr::Is {
                            in_expr: Some(_),
                            ..
                        }
                    )
                },
            ),
            // Extension: decimal
            (r#"{ "decimal": [{ "Value": "1.23" }] }"#, |e| {
                matches!(
                    e,
                    Expr::UnaryOp {
                        op: UnaryOp::Decimal,
                        ..
                    }
                )
            }),
            // Extension: datetime
            (
                r#"{ "datetime": [{ "Value": "2025-10-10T10:01:10" }] }"#,
                |e| {
                    matches!(
                        e,
                        Expr::UnaryOp {
                            op: UnaryOp::Datetime,
                            ..
                        }
                    )
                },
            ),
            // Extension: ip
            (r#"{ "ip": [{ "Value": "192.168.0.1" }] }"#, |e| {
                matches!(
                    e,
                    Expr::UnaryOp {
                        op: UnaryOp::Ip,
                        ..
                    }
                )
            }),
            // Extension: durationSince (binary)
            (
                r#"{
                    "durationSince": [
                        { "datetime": [{ "Value": "2025-10-10T10:01:10" }] },
                        { "datetime": [{ "Value": "2025-09-10T10:01:10" }] }
                    ]
                }"#,
                |e| {
                    matches!(
                        e,
                        Expr::BinaryOp {
                            op: BinaryOp::DurationSince,
                            ..
                        }
                    )
                },
            ),
        ];
        for (json, check) in cases {
            est_expr_roundtrip(json, &check);
        }
    }

    #[test]
    fn test_est_expr_has_attr_extended() {
        // Extended has attr — does not roundtrip because the EST builder desugars it
        let json = r#"{"has": {"left": {"Var": "principal"}, "attr": ["name", "nested"]}}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::HasAttr { .. }));
    }

    /// Multi-char Like literals don't EST-roundtrip (PST splits them into individual chars),
    /// so we only check the PST shape here.
    #[test]
    fn test_est_expr_like_multichar_literal() {
        let json = r#"{"like": {"left": {"Var": "principal"}, "pattern": [{"Wildcard": null}, {"Literal": "@example.com"}]}}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        assert!(matches!(pst_expr, Expr::Like { .. }));
    }

    #[test]
    fn test_est_to_pst_binary_ops() {
        let test_cases = vec![
            ("==", BinaryOp::Eq),
            ("!=", BinaryOp::NotEq),
            ("in", BinaryOp::In),
            ("<", BinaryOp::Less),
            ("<=", BinaryOp::LessEq),
            (">", BinaryOp::Greater),
            (">=", BinaryOp::GreaterEq),
            ("&&", BinaryOp::And),
            ("||", BinaryOp::Or),
            ("+", BinaryOp::Add),
            ("-", BinaryOp::Sub),
            ("*", BinaryOp::Mul),
            ("contains", BinaryOp::Contains),
            ("containsAll", BinaryOp::ContainsAll),
            ("containsAny", BinaryOp::ContainsAny),
            ("getTag", BinaryOp::GetTag),
            ("hasTag", BinaryOp::HasTag),
        ];

        for (op_str, expected_op) in test_cases {
            let json = format!(
                r#"{{"{}": {{"left": {{"Var": "principal"}}, "right": {{"Var": "resource"}}}}}}"#,
                op_str
            );
            est_expr_roundtrip(
                &json,
                &|e| matches!(e, Expr::BinaryOp { op, .. } if *op == expected_op),
            );
        }
    }

    /// EST (JSON) → PST → EST → PST roundtrip for policies.
    fn est_policy_roundtrip(json: &str, check: &dyn Fn(&Policy) -> bool) {
        let est1: est::Policy =
            serde_json::from_str(json).expect(&format!("{} should parse", json));
        let pst1: Policy = est1.clone().try_into().unwrap();
        assert!(check(&pst1), "Pattern check failed for: {json}");
        let est2: est::Policy = pst1.clone().try_into().unwrap();
        let pst2: Policy = est2.clone().try_into().unwrap();
        assert_eq!(est1, est2, "EST mismatch for: {json}");
        assert_eq!(pst1, pst2, "PST mismatch for: {json}");
    }

    #[test]
    fn test_est_policy_roundtrips() {
        let cases: Vec<(&str, fn(&Policy) -> bool)> = vec![
            // Simple permit with principal == and action ==
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "==", "entity": { "type": "User", "id": "alice" } },
                    "action":    { "op": "==", "entity": { "type": "Action", "id": "view" } },
                    "resource":  { "op": "All" },
                    "conditions": []
                }"#,
                |p| matches!(p.effect, pst::Effect::Permit),
            ),
            // Forbid with principal in and resource in
            (
                r#"{
                    "effect": "forbid",
                    "principal": { "op": "in", "entity": { "type": "Group", "id": "admins" } },
                    "action":    { "op": "All" },
                    "resource":  { "op": "in", "entity": { "type": "Folder", "id": "secrets" } },
                    "conditions": []
                }"#,
                |p| {
                    matches!(p.effect, pst::Effect::Forbid)
                        && matches!(p.principal, pst::PrincipalConstraint::In(_))
                        && matches!(p.resource, pst::ResourceConstraint::In(_))
                },
            ),
            // With a when condition
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action":    { "op": "All" },
                    "resource":  { "op": "All" },
                    "conditions": [{
                        "kind": "when",
                        "body": { "==": { "left": { "Var": "principal" }, "right": { "Var": "resource" } } }
                    }]
                }"#,
                |p| p.clauses.len() == 1 && matches!(p.clauses[0], pst::Clause::When(..)),
            ),
            // With an unless condition
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action":    { "op": "All" },
                    "resource":  { "op": "All" },
                    "conditions": [{
                        "kind": "unless",
                        "body": { "has": { "left": { "Var": "principal" }, "attr": "attacker" } }
                    }]
                }"#,
                |p| p.clauses.len() == 1 && matches!(p.clauses[0], pst::Clause::Unless(..)),
            ),
            // With an unless and when condition
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action":    { "op": "All" },
                    "resource":  { "op": "All" },
                    "conditions": [{
                        "kind": "unless",
                        "body": { "has": { "left": { "Var": "principal" }, "attr": "attacker" } }
                    },
                    {
                        "kind": "when",
                        "body": { "==": { "left": { "Var": "principal" }, "right": { "Var": "resource" } } }
                    }]
                }"#,
                |p| {
                    p.clauses.len() == 2
                        && matches!(p.clauses[0], pst::Clause::Unless(..))
                        && matches!(p.clauses[1], pst::Clause::When(..))
                },
            ),
            // With annotations
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action":    { "op": "All" },
                    "resource":  { "op": "All" },
                    "conditions": [],
                    "annotations": { "reason": "allow all access", "id": "policy_1" }
                }"#,
                |p| {
                    p.annotations.len() == 2
                        && p.annotations
                            .get("reason")
                            .is_some_and(|v| v == "allow all access")
                        && p.annotations.get("id").is_some_and(|v| v == "policy_1")
                },
            ),
            // Action in set
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action":    { "op": "in", "entities": [{ "type": "Action", "id": "read" }, { "type": "Action", "id": "write" }] },
                    "resource":  { "op": "All" },
                    "conditions": []
                }"#,
                |p| matches!(&p.action, pst::ActionConstraint::In(a) if a.len() == 2),
            ),
            // Resource == slot
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action":    { "op": "All" },
                    "resource":  { "op": "==", "slot": "?resource" },
                    "conditions": []
                }"#,
                |p| matches!(p.resource, pst::ResourceConstraint::Eq(_)),
            ),
            // Resource ==
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action":    { "op": "All" },
                    "resource":  { "op": "==", "entity": { "type": "File", "id": "doc.txt" } },
                    "conditions": []
                }"#,
                |p| matches!(p.resource, pst::ResourceConstraint::Eq(_)),
            ),
            // Resource is
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action":    { "op": "All" },
                    "resource":  { "op": "is", "entity_type": "File" },
                    "conditions": []
                }"#,
                |p| matches!(p.resource, pst::ResourceConstraint::Is(_)),
            ),
            // Resource is in
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action":    { "op": "All" },
                    "resource":  { "op": "is", "entity_type": "File", "in": { "entity": { "type": "Folder", "id": "docs" } } },
                    "conditions": []
                }"#,
                |p| matches!(p.resource, pst::ResourceConstraint::IsIn(..)),
            ),
            // Action ==
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action":    { "op": "==", "entity": { "type": "Action", "id": "view" } },
                    "resource":  { "op": "All" },
                    "conditions": []
                }"#,
                |p| matches!(p.action, pst::ActionConstraint::Eq(_)),
            ),
            // Action in single
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action":    { "op": "in", "entity": { "type": "Action", "id": "view" } },
                    "resource":  { "op": "All" },
                    "conditions": []
                }"#,
                |p| matches!(&p.action, pst::ActionConstraint::In(a) if a.len() == 1),
            ),
            // Principal ==
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "==", "entity": { "type": "User", "id": "alice" } },
                    "action":    { "op": "All" },
                    "resource":  { "op": "All" },
                    "conditions": []
                }"#,
                |p| matches!(p.principal, pst::PrincipalConstraint::Eq(_)),
            ),
            // Principal is
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "is", "entity_type": "User" },
                    "action":    { "op": "All" },
                    "resource":  { "op": "All" },
                    "conditions": []
                }"#,
                |p| matches!(p.principal, pst::PrincipalConstraint::Is(_)),
            ),
            // Principal is in
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "is", "entity_type": "User", "in": { "entity": { "type": "Group", "id": "admins" } } },
                    "action":    { "op": "All" },
                    "resource":  { "op": "All" },
                    "conditions": []
                }"#,
                |p| matches!(p.principal, pst::PrincipalConstraint::IsIn(..)),
            ),
            // Principal in slot
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "in",  "slot": "?principal" },
                    "action":    { "op": "All" },
                    "resource":  { "op": "All" },
                    "conditions": []
                }"#,
                |p| matches!(p.principal, pst::PrincipalConstraint::In(..)),
            ),
            // Principal == slot
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "==", "slot": "?principal" },
                    "action":    { "op": "All" },
                    "resource":  { "op": "All" },
                    "conditions": []
                }"#,
                |p| {
                    matches!(
                        p.principal,
                        pst::PrincipalConstraint::Eq(pst::EntityOrSlot::Slot(_))
                    )
                },
            ),
            // Resource in slot
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action":    { "op": "All" },
                    "resource":  { "op": "in", "slot": "?resource" },
                    "conditions": []
                }"#,
                |p| {
                    matches!(
                        p.resource,
                        pst::ResourceConstraint::In(pst::EntityOrSlot::Slot(_))
                    )
                },
            ),
            // Principal is in slot
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "is", "entity_type": "User", "in": { "slot": "?principal" } },
                    "action":    { "op": "All" },
                    "resource":  { "op": "All" },
                    "conditions": []
                }"#,
                |p| {
                    matches!(
                        p.principal,
                        pst::PrincipalConstraint::IsIn(_, pst::EntityOrSlot::Slot(_))
                    )
                },
            ),
            // Resource is in slot
            (
                r#"{
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action":    { "op": "All" },
                    "resource":  { "op": "is", "entity_type": "File", "in": { "slot": "?resource" } },
                    "conditions": []
                }"#,
                |p| {
                    matches!(
                        p.resource,
                        pst::ResourceConstraint::IsIn(_, pst::EntityOrSlot::Slot(_))
                    )
                },
            ),
        ];
        for (json, check) in cases {
            est_policy_roundtrip(json, &check);
        }
    }

    /// Empty annotation values don't EST-roundtrip (`""` → PST → `None` in EST),
    /// so we only check the PST shape here.
    #[test]
    fn test_est_policy_annotation_empty_value() {
        let json = r#"{"annotations":{"ok":""},"effect":"permit","principal":{"op":"is","entity_type":"User","in":{"slot":"?principal"}},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[]}"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let pst_policy: Policy = est_policy.try_into().unwrap();
        assert_eq!(pst_policy.annotations.len(), 1);
    }

    #[test]
    fn test_est_action_constraint_slot_returns_err() {
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
    fn test_pst_to_est_annotation_empty_value_maps_to_none() {
        let mut annotations = BTreeMap::new();
        annotations.insert("empty".to_string(), SmolStr::default());
        annotations.insert("nonempty".to_string(), SmolStr::new("hello"));
        let policy = Policy {
            id: PolicyID("p0".into()),
            effect: Effect::Permit,
            principal: PrincipalConstraint::Any,
            action: ActionConstraint::Any,
            resource: ResourceConstraint::Any,
            clauses: vec![],
            annotations,
        };
        let est_policy: est::Policy = policy.try_into().unwrap();
        let empty_key = "empty".parse::<ast::AnyId>().unwrap();
        let nonempty_key = "nonempty".parse::<ast::AnyId>().unwrap();
        assert!(est_policy.annotations.0.get(&empty_key).unwrap().is_none());
        assert_eq!(
            est_policy
                .annotations
                .0
                .get(&nonempty_key)
                .unwrap()
                .as_ref()
                .unwrap()
                .val,
            "hello"
        );
    }

    #[test]
    fn test_pst_to_est_annotation_invalid_key() {
        let mut annotations = BTreeMap::new();
        annotations.insert("not valid!!".to_string(), SmolStr::new("v"));
        let policy = Policy {
            id: PolicyID("p0".into()),
            effect: Effect::Permit,
            principal: PrincipalConstraint::Any,
            action: ActionConstraint::Any,
            resource: ResourceConstraint::Any,
            clauses: vec![],
            annotations,
        };
        let result: Result<est::Policy, PstConstructionError> = policy.try_into();
        assert!(matches!(
            result,
            Err(PstConstructionError::ParsingFailed(..))
        ));
    }

    #[test]
    fn test_est_expr_func_call_nested() {
        // Complex argument (expression inside extension function)
        let json = r#"{"decimal": [{"&&": {"left": {"Value": true}, "right": {"Value": false}}}]}"#;
        let est_expr: est::Expr = serde_json::from_str(json).unwrap();
        let pst_expr: Expr = est_expr.try_into().unwrap();
        if let Expr::UnaryOp {
            op: UnaryOp::Decimal,
            expr,
        } = &pst_expr
        {
            assert!(matches!(
                **expr,
                Expr::BinaryOp {
                    op: BinaryOp::And,
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
        if let Expr::UnaryOp {
            op: UnaryOp::Decimal,
            expr,
        } = &pst_expr
        {
            assert!(matches!(
                **expr,
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

    #[test]
    fn test_est_policy_invalid_entity_uid() {
        let json = r#"{
            "effect": "permit",
            "principal": { "op": "==", "entity": 42 },
            "action":    { "op": "All" },
            "resource":  { "op": "All" },
            "conditions": []
        }"#;
        let est_policy: est::Policy = serde_json::from_str(json).unwrap();
        let result: Result<Policy, _> = est_policy.try_into();
        assert!(matches!(
            result,
            Err(PstConstructionError::InvalidEntityUid(..))
        ));
    }
}
