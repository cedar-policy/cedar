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

//! Conversions between PST and AST types

use super::{
    ActionConstraint, BinaryOp, Clause, Effect, EntityOrSlot, EntityType, EntityUID, Expr,
    LinkedPolicy, Literal, Name, PatternElem, Policy, PolicyID, PrincipalConstraint,
    PstConstructionError, ResourceConstraint, SlotId, StaticPolicy, Template, UnaryOp, Var,
};
use crate::ast::IsInfallible;
use crate::ast::{self, UnwrapInfallible};
use crate::expr_builder;
use crate::extensions;
use crate::pst::err::error_body::{
    PolicyMissingLinkIdError, UnsupportedErrorNode, WrongSlotPositionError,
};
use crate::pst::expr::{Id, PstBuilder};
use std::collections::HashMap;
use std::sync::Arc;

#[doc(hidden)]
impl TryFrom<Policy> for ast::Policy {
    type Error = PstConstructionError;

    fn try_from(policy: Policy) -> Result<Self, Self::Error> {
        match policy {
            Policy::Static(static_policy) => static_policy.try_into(),
            Policy::Linked(linked_policy) => linked_policy.try_into(),
        }
    }
}

impl TryFrom<StaticPolicy> for ast::Policy {
    type Error = PstConstructionError;

    fn try_from(policy: StaticPolicy) -> Result<Self, Self::Error> {
        Ok(ast::Policy::new(
            Arc::new(policy.body.try_into()?),
            Option::None,
            HashMap::new(),
        ))
    }
}

impl TryFrom<LinkedPolicy> for ast::Policy {
    type Error = PstConstructionError;

    fn try_from(policy: LinkedPolicy) -> Result<Self, Self::Error> {
        let ast_values: HashMap<ast::SlotId, ast::EntityUID> = policy
            .values
            .into_iter()
            .map(|(k, v)| (k.into(), ast::EntityUID::from(v)))
            .collect();
        Ok(ast::Policy::new(
            Arc::new(Arc::unwrap_or_clone(policy.body).try_into()?),
            Option::Some(policy.instance_id.into()),
            ast_values,
        ))
    }
}

#[doc(hidden)]
impl TryFrom<Template> for ast::Template {
    type Error = PstConstructionError;

    fn try_from(policy: Template) -> Result<Self, Self::Error> {
        use crate::expr_builder::ExprBuilder;
        // Convert clauses - fold them into a single expression (following EST pattern)
        let builder = ast::ExprBuilder::<()>::new();
        let mut conds_rev_iter = policy
            .clauses
            .into_iter()
            .map(|clause| match clause {
                Clause::When(expr) => Arc::unwrap_or_clone(expr).into(),
                Clause::Unless(expr) => builder.clone().not(Arc::unwrap_or_clone(expr).into()),
            })
            .rev()
            .collect::<Vec<ast::Expr>>()
            .into_iter();

        let conditions = conds_rev_iter.next().map(|last_expr| {
            conds_rev_iter.fold(last_expr, |acc, prev| builder.clone().and(prev, acc))
        });

        // Convert annotations
        let annotations: ast::Annotations = policy
            .annotations
            .into_iter()
            .map(|(key, val)| {
                let value = if val.is_empty() { None } else { Some(val) };
                (
                    ast::AnyId::new_unchecked(key),
                    ast::Annotation::with_optional_value(value, None),
                )
            })
            .collect();

        Ok(ast::Template::new(
            policy.id.into(),
            None,
            annotations,
            policy.effect.into(),
            policy.principal.try_into()?,
            policy.action.try_into()?,
            policy.resource.try_into()?,
            conditions,
        ))
    }
}

#[doc(hidden)]
impl TryFrom<PrincipalConstraint> for ast::PrincipalConstraint {
    type Error = PstConstructionError;

    fn try_from(constraint: PrincipalConstraint) -> Result<Self, Self::Error> {
        match constraint {
            PrincipalConstraint::Any => Ok(ast::PrincipalConstraint::any()),
            PrincipalConstraint::Eq(EntityOrSlot::Entity(eos)) => {
                Ok(ast::PrincipalConstraint::is_eq(Arc::new(eos.into())))
            }
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)) => {
                Ok(ast::PrincipalConstraint::is_eq_slot())
            }
            PrincipalConstraint::In(EntityOrSlot::Entity(eos)) => {
                Ok(ast::PrincipalConstraint::is_in(Arc::new(eos.into())))
            }
            PrincipalConstraint::In(EntityOrSlot::Slot(SlotId::Principal)) => {
                Ok(ast::PrincipalConstraint::is_in_slot())
            }
            PrincipalConstraint::Is(entity_type) => Ok(ast::PrincipalConstraint::is_entity_type(
                Arc::new(entity_type.into()),
            )),
            PrincipalConstraint::IsIn(entity_type, EntityOrSlot::Entity(eos)) => {
                Ok(ast::PrincipalConstraint::is_entity_type_in(
                    Arc::new(entity_type.into()),
                    Arc::new(eos.into()),
                ))
            }
            PrincipalConstraint::IsIn(entity_type, EntityOrSlot::Slot(SlotId::Principal)) => Ok(
                ast::PrincipalConstraint::is_entity_type_in_slot(Arc::new(entity_type.into())),
            ),
            // Wrong slot type (resource slot in principal position)
            PrincipalConstraint::Eq(EntityOrSlot::Slot(s))
            | PrincipalConstraint::In(EntityOrSlot::Slot(s))
            | PrincipalConstraint::IsIn(_, EntityOrSlot::Slot(s)) => {
                Err(WrongSlotPositionError::new(s, SlotId::Principal).into())
            }
        }
    }
}

#[doc(hidden)]
impl TryFrom<ResourceConstraint> for ast::ResourceConstraint {
    type Error = PstConstructionError;

    fn try_from(constraint: ResourceConstraint) -> Result<Self, Self::Error> {
        match constraint {
            ResourceConstraint::Any => Ok(ast::ResourceConstraint::any()),
            ResourceConstraint::Eq(EntityOrSlot::Entity(eos)) => {
                Ok(ast::ResourceConstraint::is_eq(Arc::new(eos.into())))
            }
            ResourceConstraint::Eq(EntityOrSlot::Slot(SlotId::Resource)) => {
                Ok(ast::ResourceConstraint::is_eq_slot())
            }
            ResourceConstraint::In(EntityOrSlot::Entity(eos)) => {
                Ok(ast::ResourceConstraint::is_in(Arc::new(eos.into())))
            }
            ResourceConstraint::In(EntityOrSlot::Slot(SlotId::Resource)) => {
                Ok(ast::ResourceConstraint::is_in_slot())
            }
            ResourceConstraint::Is(entity_type) => Ok(ast::ResourceConstraint::is_entity_type(
                Arc::new(entity_type.into()),
            )),
            ResourceConstraint::IsIn(entity_type, EntityOrSlot::Entity(eos)) => {
                Ok(ast::ResourceConstraint::is_entity_type_in(
                    Arc::new(entity_type.into()),
                    Arc::new(eos.into()),
                ))
            }
            ResourceConstraint::IsIn(entity_type, EntityOrSlot::Slot(SlotId::Resource)) => Ok(
                ast::ResourceConstraint::is_entity_type_in_slot(Arc::new(entity_type.into())),
            ),
            // Wrong slot type (principal slot in resource position)
            ResourceConstraint::Eq(EntityOrSlot::Slot(s))
            | ResourceConstraint::In(EntityOrSlot::Slot(s))
            | ResourceConstraint::IsIn(_, EntityOrSlot::Slot(s)) => {
                Err(WrongSlotPositionError::new(s, SlotId::Resource).into())
            }
        }
    }
}

#[doc(hidden)]
impl TryFrom<ActionConstraint> for ast::ActionConstraint {
    type Error = PstConstructionError;

    fn try_from(constraint: ActionConstraint) -> Result<Self, Self::Error> {
        match constraint {
            ActionConstraint::Any => Ok(ast::ActionConstraint::any()),
            ActionConstraint::Eq(uid) => Ok(ast::ActionConstraint::is_eq(uid.into())),
            ActionConstraint::In(uids) => {
                let ast_uids: Vec<_> = uids.into_iter().map(ast::EntityUID::from).collect();
                Ok(ast::ActionConstraint::is_in(ast_uids))
            }
        }
    }
}

fn elements_into_ast_pattern(elems: impl IntoIterator<Item = PatternElem>) -> ast::Pattern {
    let elems = elems.into_iter().map(|elem| match elem {
        PatternElem::Char(c) => ast::PatternElem::Char(c),
        PatternElem::Wildcard => ast::PatternElem::Wildcard,
    });
    ast::Pattern::from_iter(elems)
}

#[doc(hidden)]
impl From<Expr> for ast::Expr {
    fn from(expr: Expr) -> Self {
        expr.into_expr::<ast::ExprBuilder<()>>()
    }
}

#[doc(hidden)]
impl Expr {
    pub(crate) fn into_expr<B: expr_builder::ExprBuilder>(self) -> B::Expr
    where
        B::BuildError: IsInfallible, // we can change this as needed
    {
        let builder = B::new();
        match self {
            Expr::Literal(lit) => match lit {
                Literal::Bool(b) => builder.val(b),
                Literal::Long(i) => builder.val(i),
                Literal::String(s) => builder.val(s),
                Literal::EntityUID(uid) => {
                    let ast_uid: ast::EntityUID = uid.into();
                    builder.val(ast_uid)
                }
            },
            Expr::Var(v) => builder.var(v.into()),
            Expr::Slot(s) => builder.slot(s.into()),
            Expr::UnaryOp { op, expr } => {
                let inner = Arc::unwrap_or_clone(expr).into_expr::<B>();
                // Each variant is matched explicitly so the compiler enforces
                // that new variants are handled. Extension-function variants
                // mirror UnaryOp::to_name() but avoid the Option indirection.
                // This part of the conversion is infallible.
                match op {
                    UnaryOp::Not => builder.not(inner),
                    UnaryOp::Neg => builder.neg(inner),
                    UnaryOp::IsEmpty => builder.is_empty(inner),
                    UnaryOp::Decimal => builder
                        .call_extension_fn(
                            extensions::decimal::constants::DECIMAL_FROM_STR_NAME.clone(),
                            vec![inner],
                        )
                        .unwrap_infallible(),
                    UnaryOp::Datetime => builder
                        .call_extension_fn(
                            extensions::datetime::constants::DATETIME_CONSTRUCTOR_NAME.clone(),
                            vec![inner],
                        )
                        .unwrap_infallible(),
                    UnaryOp::Duration => builder
                        .call_extension_fn(
                            extensions::datetime::constants::DURATION_CONSTRUCTOR_NAME.clone(),
                            vec![inner],
                        )
                        .unwrap_infallible(),
                    UnaryOp::Ip => builder
                        .call_extension_fn(
                            extensions::ipaddr::names::IP_FROM_STR_NAME.clone(),
                            vec![inner],
                        )
                        .unwrap_infallible(),
                    UnaryOp::IsIPv4 => builder
                        .call_extension_fn(extensions::ipaddr::names::IS_IPV4.clone(), vec![inner])
                        .unwrap_infallible(),
                    UnaryOp::IsIPV6 => builder
                        .call_extension_fn(extensions::ipaddr::names::IS_IPV6.clone(), vec![inner])
                        .unwrap_infallible(),
                    UnaryOp::IsLoopback => builder
                        .call_extension_fn(
                            extensions::ipaddr::names::IS_LOOPBACK.clone(),
                            vec![inner],
                        )
                        .unwrap_infallible(),
                    UnaryOp::IsMulticast => builder
                        .call_extension_fn(
                            extensions::ipaddr::names::IS_MULTICAST.clone(),
                            vec![inner],
                        )
                        .unwrap_infallible(),
                    UnaryOp::ToDate => builder
                        .call_extension_fn(
                            extensions::datetime::constants::TO_DATE_NAME.clone(),
                            vec![inner],
                        )
                        .unwrap_infallible(),
                    UnaryOp::ToTime => builder
                        .call_extension_fn(
                            extensions::datetime::constants::TO_TIME_NAME.clone(),
                            vec![inner],
                        )
                        .unwrap_infallible(),
                    UnaryOp::ToMilliseconds => builder
                        .call_extension_fn(
                            extensions::datetime::constants::TO_MILLISECONDS_NAME.clone(),
                            vec![inner],
                        )
                        .unwrap_infallible(),
                    UnaryOp::ToSeconds => builder
                        .call_extension_fn(
                            extensions::datetime::constants::TO_SECONDS_NAME.clone(),
                            vec![inner],
                        )
                        .unwrap_infallible(),
                    UnaryOp::ToMinutes => builder
                        .call_extension_fn(
                            extensions::datetime::constants::TO_MINUTES_NAME.clone(),
                            vec![inner],
                        )
                        .unwrap_infallible(),
                    UnaryOp::ToHours => builder
                        .call_extension_fn(
                            extensions::datetime::constants::TO_HOURS_NAME.clone(),
                            vec![inner],
                        )
                        .unwrap_infallible(),
                    UnaryOp::ToDays => builder
                        .call_extension_fn(
                            extensions::datetime::constants::TO_DAYS_NAME.clone(),
                            vec![inner],
                        )
                        .unwrap_infallible(),
                }
            }
            Expr::BinaryOp { op, left, right } => {
                let left_ast = Arc::unwrap_or_clone(left).into_expr::<B>();
                let right_ast = Arc::unwrap_or_clone(right).into_expr::<B>();
                // Each variant is also matched explicitly here.
                match op {
                    BinaryOp::Eq => builder.is_eq(left_ast, right_ast),
                    BinaryOp::NotEq => builder.noteq(left_ast, right_ast),
                    BinaryOp::Less => builder.less(left_ast, right_ast),
                    BinaryOp::LessEq => builder.lesseq(left_ast, right_ast),
                    BinaryOp::Greater => builder.greater(left_ast, right_ast),
                    BinaryOp::GreaterEq => builder.greatereq(left_ast, right_ast),
                    BinaryOp::And => builder.and(left_ast, right_ast),
                    BinaryOp::Or => builder.or(left_ast, right_ast),
                    BinaryOp::Add => builder.add(left_ast, right_ast),
                    BinaryOp::Sub => builder.sub(left_ast, right_ast),
                    BinaryOp::Mul => builder.mul(left_ast, right_ast),
                    BinaryOp::In => builder.is_in(left_ast, right_ast),
                    BinaryOp::Contains => builder.contains(left_ast, right_ast),
                    BinaryOp::ContainsAll => builder.contains_all(left_ast, right_ast),
                    BinaryOp::ContainsAny => builder.contains_any(left_ast, right_ast),
                    BinaryOp::GetTag => builder.get_tag(left_ast, right_ast),
                    BinaryOp::HasTag => builder.has_tag(left_ast, right_ast),
                    // Extension-function variants: each maps directly to its
                    // extension name, mirroring BinaryOp::to_name() but without
                    // the Option indirection.
                    BinaryOp::IsInRange => builder
                        .call_extension_fn(
                            extensions::ipaddr::names::IS_IN_RANGE.clone(),
                            vec![left_ast, right_ast],
                        )
                        .unwrap_infallible(),
                    BinaryOp::Offset => builder
                        .call_extension_fn(
                            extensions::datetime::constants::OFFSET_METHOD_NAME.clone(),
                            vec![left_ast, right_ast],
                        )
                        .unwrap_infallible(),
                    BinaryOp::DurationSince => builder
                        .call_extension_fn(
                            extensions::datetime::constants::DURATION_SINCE_NAME.clone(),
                            vec![left_ast, right_ast],
                        )
                        .unwrap_infallible(),
                    BinaryOp::DecimalLessThan => builder
                        .call_extension_fn(
                            extensions::decimal::constants::LESS_THAN.clone(),
                            vec![left_ast, right_ast],
                        )
                        .unwrap_infallible(),
                    BinaryOp::DecimalLessEq => builder
                        .call_extension_fn(
                            extensions::decimal::constants::LESS_THAN_OR_EQUAL.clone(),
                            vec![left_ast, right_ast],
                        )
                        .unwrap_infallible(),
                    BinaryOp::DecimalGreater => builder
                        .call_extension_fn(
                            extensions::decimal::constants::GREATER_THAN.clone(),
                            vec![left_ast, right_ast],
                        )
                        .unwrap_infallible(),
                    BinaryOp::DecimalGreaterEq => builder
                        .call_extension_fn(
                            extensions::decimal::constants::GREATER_THAN_OR_EQUAL.clone(),
                            vec![left_ast, right_ast],
                        )
                        .unwrap_infallible(),
                }
            }
            Expr::Set(exprs) => {
                let ast_exprs: Vec<_> = exprs
                    .into_iter()
                    .map(|e| Arc::unwrap_or_clone(e).into_expr::<B>())
                    .collect();
                builder.set(ast_exprs)
            }
            Expr::IfThenElse {
                cond,
                then_expr,
                else_expr,
            } => builder.ite(
                Arc::unwrap_or_clone(cond).into_expr::<B>(),
                Arc::unwrap_or_clone(then_expr).into_expr::<B>(),
                Arc::unwrap_or_clone(else_expr).into_expr::<B>(),
            ),
            Expr::Is {
                expr,
                entity_type,
                in_expr: None,
            } => builder.is_entity_type(
                Arc::unwrap_or_clone(expr).into_expr::<B>(),
                entity_type.into(),
            ),
            Expr::Is {
                expr,
                entity_type,
                in_expr: Some(e),
            } => builder.is_in_entity_type(
                Arc::unwrap_or_clone(expr).into_expr::<B>(),
                entity_type.into(),
                Arc::unwrap_or_clone(e).into_expr::<B>(),
            ),
            Expr::GetAttr { expr, attr } => {
                builder.get_attr(Arc::unwrap_or_clone(expr).into_expr::<B>(), attr)
            }
            Expr::HasAttr { expr, attrs } => {
                builder.extended_has_attr(Arc::unwrap_or_clone(expr).into_expr::<B>(), attrs)
            }
            Expr::Like { expr, pattern } => builder.like(
                Arc::unwrap_or_clone(expr).into_expr::<B>(),
                elements_into_ast_pattern(pattern),
            ),
            Expr::Record(elems) =>
            {
                #[expect(
                    clippy::unwrap_used,
                    reason = "record is given a map, there cannot be duplicates"
                )]
                builder
                    .record(
                        elems
                            .into_iter()
                            .map(|(k, v)| (k.into(), Arc::unwrap_or_clone(v).into_expr::<B>())),
                    )
                    .unwrap()
            }
            Expr::Unknown { name } => builder.unknown(ast::Unknown {
                name,
                type_annotation: None,
            }),
        }
    }
}

#[doc(hidden)]
impl From<Effect> for ast::Effect {
    fn from(effect: Effect) -> Self {
        match effect {
            Effect::Permit => ast::Effect::Permit,
            Effect::Forbid => ast::Effect::Forbid,
        }
    }
}

/// Infallible: `pst::EntityUID` contains a validated `pst::EntityType`.
#[doc(hidden)]
impl From<EntityUID> for ast::EntityUID {
    fn from(value: EntityUID) -> Self {
        let ast_et: ast::EntityType = value.ty.into();
        let ast_eid = ast::Eid::new(value.eid);
        ast::EntityUID::from_components(ast_et, ast_eid, None)
    }
}

#[doc(hidden)]
impl From<ast::EntityType> for EntityType {
    fn from(et: ast::EntityType) -> Self {
        EntityType(et.into_name().into())
    }
}

/// Infallible: `pst::Name` components are already validated.
#[doc(hidden)]
impl From<EntityType> for ast::EntityType {
    fn from(et: EntityType) -> Self {
        ast::EntityType::EntityType(et.0.into())
    }
}

#[doc(hidden)]
impl From<ast::Var> for Var {
    fn from(v: ast::Var) -> Self {
        match v {
            ast::Var::Principal => Var::Principal,
            ast::Var::Action => Var::Action,
            ast::Var::Resource => Var::Resource,
            ast::Var::Context => Var::Context,
        }
    }
}

#[doc(hidden)]
impl From<Var> for ast::Var {
    fn from(v: Var) -> Self {
        match v {
            Var::Principal => ast::Var::Principal,
            Var::Action => ast::Var::Action,
            Var::Resource => ast::Var::Resource,
            Var::Context => ast::Var::Context,
        }
    }
}

#[doc(hidden)]
impl From<ast::Name> for Name {
    fn from(name: ast::Name) -> Self {
        let ast::Name {
            0: ast::InternalName { id, path, .. },
        } = name;
        Name {
            id: Id::from(id),
            namespace: Arc::new(
                Arc::unwrap_or_clone(path)
                    .into_iter()
                    .map(Id::from)
                    .collect(),
            ),
        }
    }
}

/// Infallible: `pst::Id` components are already validated.
#[doc(hidden)]
impl From<Name> for ast::Name {
    fn from(name: Name) -> Self {
        let basename = ast::Id::new_unchecked(name.id.into_smolstr());
        let path: Vec<ast::Id> = name
            .namespace
            .iter()
            .map(|id| ast::Id::new_unchecked(id.as_str()))
            .collect();
        ast::Name(ast::InternalName::new(basename, path, None))
    }
}

#[doc(hidden)]
impl From<ast::SlotId> for SlotId {
    fn from(slot: ast::SlotId) -> Self {
        match slot.0 {
            ast::ValidSlotId::Principal => SlotId::Principal,
            ast::ValidSlotId::Resource => SlotId::Resource,
        }
    }
}

#[doc(hidden)]
impl From<SlotId> for ast::SlotId {
    fn from(slot: SlotId) -> Self {
        match slot {
            SlotId::Principal => ast::SlotId::principal(),
            SlotId::Resource => ast::SlotId::resource(),
        }
    }
}

#[doc(hidden)]
impl From<ast::Pattern> for Vec<PatternElem> {
    fn from(pattern: ast::Pattern) -> Self {
        pattern
            .iter()
            .map(|elem| match elem {
                ast::PatternElem::Char(c) => PatternElem::Char(*c),
                ast::PatternElem::Wildcard => PatternElem::Wildcard,
            })
            .collect()
    }
}

#[doc(hidden)]
impl From<ast::Literal> for Literal {
    fn from(value: ast::Literal) -> Self {
        match value {
            ast::Literal::Bool(b) => Literal::Bool(b),
            ast::Literal::Long(i) => Literal::Long(i),
            ast::Literal::String(s) => Literal::String(s),
            ast::Literal::EntityUID(uid) => Literal::EntityUID(Arc::unwrap_or_clone(uid).into()),
        }
    }
}

#[doc(hidden)]
impl From<ast::EntityUID> for EntityUID {
    fn from(uid: ast::EntityUID) -> Self {
        let (ty, eid) = uid.components();
        EntityUID {
            ty: ty.into(),
            eid: eid.into_smolstr(),
        }
    }
}

#[doc(hidden)]
impl TryFrom<ast::Expr> for Expr {
    type Error = PstConstructionError;
    fn try_from(ast_expr: ast::Expr) -> Result<Self, PstConstructionError> {
        ast::Expr::try_into_expr::<PstBuilder>(ast_expr)
    }
}

#[doc(hidden)]
impl From<ast::Effect> for Effect {
    fn from(effect: ast::Effect) -> Self {
        match effect {
            ast::Effect::Permit => Effect::Permit,
            ast::Effect::Forbid => Effect::Forbid,
        }
    }
}

fn entity_ref_to_entity_or_slot(er: ast::EntityReference, slot: SlotId) -> EntityOrSlot {
    match er {
        ast::EntityReference::EUID(uid) => EntityOrSlot::Entity(Arc::unwrap_or_clone(uid).into()),
        ast::EntityReference::Slot(_) => EntityOrSlot::Slot(slot),
    }
}

#[doc(hidden)]
impl From<ast::PrincipalConstraint> for PrincipalConstraint {
    fn from(c: ast::PrincipalConstraint) -> Self {
        match c.into_inner() {
            ast::PrincipalOrResourceConstraint::Any => PrincipalConstraint::Any,
            ast::PrincipalOrResourceConstraint::Eq(er) => {
                PrincipalConstraint::Eq(entity_ref_to_entity_or_slot(er, SlotId::Principal))
            }
            ast::PrincipalOrResourceConstraint::In(er) => {
                PrincipalConstraint::In(entity_ref_to_entity_or_slot(er, SlotId::Principal))
            }
            ast::PrincipalOrResourceConstraint::Is(et) => {
                PrincipalConstraint::Is(Arc::unwrap_or_clone(et).into())
            }
            ast::PrincipalOrResourceConstraint::IsIn(et, er) => PrincipalConstraint::IsIn(
                Arc::unwrap_or_clone(et).into(),
                entity_ref_to_entity_or_slot(er, SlotId::Principal),
            ),
        }
    }
}

#[doc(hidden)]
impl From<ast::ResourceConstraint> for ResourceConstraint {
    fn from(c: ast::ResourceConstraint) -> Self {
        match c.into_inner() {
            ast::PrincipalOrResourceConstraint::Any => ResourceConstraint::Any,
            ast::PrincipalOrResourceConstraint::Eq(er) => {
                ResourceConstraint::Eq(entity_ref_to_entity_or_slot(er, SlotId::Resource))
            }
            ast::PrincipalOrResourceConstraint::In(er) => {
                ResourceConstraint::In(entity_ref_to_entity_or_slot(er, SlotId::Resource))
            }
            ast::PrincipalOrResourceConstraint::Is(et) => {
                ResourceConstraint::Is(Arc::unwrap_or_clone(et).into())
            }
            ast::PrincipalOrResourceConstraint::IsIn(et, er) => ResourceConstraint::IsIn(
                Arc::unwrap_or_clone(et).into(),
                entity_ref_to_entity_or_slot(er, SlotId::Resource),
            ),
        }
    }
}

#[doc(hidden)]
impl TryFrom<ast::ActionConstraint> for ActionConstraint {
    type Error = PstConstructionError;
    fn try_from(c: ast::ActionConstraint) -> Result<Self, PstConstructionError> {
        match c {
            ast::ActionConstraint::Any => Ok(ActionConstraint::Any),
            ast::ActionConstraint::Eq(uid) => {
                Ok(ActionConstraint::Eq(Arc::unwrap_or_clone(uid).into()))
            }
            ast::ActionConstraint::In(uids) => Ok(ActionConstraint::In(
                uids.into_iter()
                    .map(|uid| Arc::unwrap_or_clone(uid).into())
                    .collect(),
            )),
            #[cfg(feature = "tolerant-ast")]
            ast::ActionConstraint::ErrorConstraint => {
                Err(UnsupportedErrorNode::new("error action constraint").into())
            }
        }
    }
}

#[doc(hidden)]
impl TryFrom<ast::Template> for Template {
    type Error = PstConstructionError;

    fn try_from(template: ast::Template) -> Result<Self, PstConstructionError> {
        let (
            id,
            annot,
            effect,
            principal_constraint,
            action_constraint,
            resource_constraint,
            clause,
        ) = template
            .into_template_components_opt()
            .ok_or_else(|| UnsupportedErrorNode::new("template parsed with errors"))?;
        let id = PolicyID(id.into_smolstr());
        let effect = effect.into();
        let principal = principal_constraint.into();
        let action = action_constraint.try_into()?;
        let resource = resource_constraint.into();

        let clauses = match clause {
            Some(expr) => vec![Clause::When(Arc::new(
                Arc::unwrap_or_clone(expr).try_into()?,
            ))],
            None => vec![],
        };

        let annotations = Arc::unwrap_or_clone(annot)
            .into_iter()
            .map(|(key, ann)| (key.to_string(), ann.val))
            .collect();

        Template::new(id, effect, principal, action, resource)
            .with_annotations(annotations)
            .try_with_clauses(clauses)
    }
}

#[doc(hidden)]
impl TryFrom<ast::Policy> for Policy {
    type Error = PstConstructionError;

    fn try_from(policy: ast::Policy) -> Result<Self, PstConstructionError> {
        let (template, id, values) = policy.into_components();
        let pst_template: Template = Arc::unwrap_or_clone(template).try_into()?;
        if pst_template.is_static() {
            Ok(Policy::Static(pst_template.try_into()?))
        } else {
            let values = values
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect();
            if let Some(ast_id) = id {
                Ok(Policy::Linked(LinkedPolicy {
                    body: Arc::new(pst_template),
                    values,
                    instance_id: ast_id.into(),
                }))
            } else {
                // We shouldn't get there if the invariant on ast policies hold
                Err(PolicyMissingLinkIdError.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    /// Helper to create AST expressions from Cedar text
    fn parse_expr(s: &str) -> ast::Expr {
        parser::parse_expr(s).expect("parse failed")
    }

    /// Test roundtrip: ast::Expr -> pst::Expr -> ast::Expr
    fn assert_expr_roundtrip(ast_expr: ast::Expr) {
        let pst_expr: Expr = ast_expr
            .clone()
            .try_into()
            .expect("ast -> pst onversion failed.");
        let ast_expr2: ast::Expr = pst_expr.try_into().expect("pst -> ast conversion failed");
        assert_eq!(ast_expr, ast_expr2, "roundtrip failed");
    }

    #[test]
    fn test_literal_roundtrips() {
        let cases = ["true", "false", "42", r#""hello""#];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_variable_roundtrips() {
        let cases = ["principal", "action", "resource", "context"];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_unary_op_roundtrips() {
        let cases = ["!true", "-42", "[].isEmpty()"];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    /// Test the binary operators that roundtrip -- not all do
    fn test_binary_op_roundtrips() {
        let cases = [
            "1 + 2",
            "5 - 3",
            "2 * 3",
            "1 == 2",
            "1 != 2",
            "1 < 2",
            "1 <= 2",
            "1 > 2",
            "1 >= 2",
            "true && false",
            "true || false",
            r#""a" in "abc""#,
            r#"User::"alice" in Group::"admins""#,
            r#"[1, 2, 3].contains(2)"#,
            r#"[1, 2].containsAll([1])"#,
            r#"[1, 2].containsAny([2, 3])"#,
            r#"User::"alice".getTag("role")"#,
            r#"User::"alice".hasTag("role")"#,
        ];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_if_then_else_roundtrip() {
        let expr = parse_expr("if true then 1 else 2");
        assert_expr_roundtrip(expr);
    }

    #[test]
    fn test_set_roundtrips() {
        let cases = ["[]", "[1]", "[1, 2, 3]"];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_record_roundtrips() {
        let cases = [
            "{}",
            r#"{"a": 1}"#,
            r#"{"a": 1, "b": 2}"#,
            r#"{"nested": {"x": 1}}"#,
            r#"{"if": 1}"#,
            r#"{"a-b": 1}"#,
        ];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_entity_uid_roundtrip() {
        let cases = [r#"User::"alice""#, r#"MyApp::User::"alice""#];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_get_attr_roundtrips() {
        let cases = [r#"principal.name"#, r#"resource.owner.id"#];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_has_attr_roundtrip() {
        let expr = parse_expr(r#"principal has name"#);
        assert_expr_roundtrip(expr);
    }

    #[test]
    fn test_like_roundtrip() {
        let cases = [
            r#"principal.name like "a*b""#,
            r#""test" like "*""#,
            r#""test" like "*est""#,
            r#""test" like "test*""#,
        ];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_is_roundtrip() {
        let cases = [
            r#"principal is User"#,
            r#"principal is MyApp::User"#,
            r#"principal is User in Group::"admins""#,
            r#"principal is User in Group::"admins" || principal is User in Group::"users""#,
        ];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_function_call_roundtrips() {
        let cases = [
            r#"decimal("1.23")"#,
            r#"ip("127.0.0.1")"#,
            r#"datetime("2024-01-01")"#,
            r#"ip("127.0.0.1").isIpv4()"#,
            r#"ip("127.0.0.1").isInRange(ip("127.0.0.0/24"))"#,
        ];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    /// Test that extension methods that normalize to operators convert correctly
    /// These don't roundtrip to identical AST, but should convert without error
    #[test]
    fn test_extension_method_normalization() {
        let cases = [
            (
                r#"decimal("1.23").lessThan(decimal("2.0"))"#,
                "decimal lessThan -> <",
            ),
            (
                r#"decimal("1.23").lessThanOrEqual(decimal("2.0"))"#,
                "decimal lessThanOrEqual -> <=",
            ),
            (
                r#"decimal("1.23").greaterThan(decimal("2.0"))"#,
                "decimal greaterThan -> >",
            ),
            (
                r#"decimal("1.23").greaterThanOrEqual(decimal("2.0"))"#,
                "decimal greaterThanOrEqual -> >=",
            ),
        ];

        for (expr_str, desc) in cases {
            let ast_expr = parse_expr(expr_str);
            // Convert to PST
            let pst_expr: Expr = ast_expr.try_into().unwrap();
            // Convert back to AST - should succeed even if structure differs
            let _ast_expr2: ast::Expr = pst_expr.try_into().expect(desc);
        }
    }

    #[test]
    fn test_complex_nested_expression() {
        let cases = [
            r#"if principal.age >= 18 && resource.public == true then
                    [1, 2, 3].contains(action.level)
                else
                    false"#,
            r#"((1 + 2) * 3) - 4"#,
            r#"!(!true)"#,
            r#"true && (false || true)"#,
            r#"principal has name && principal has age"#,
        ];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_unknown_expr() {
        // Unknown is created programmatically, not parsed
        use crate::ast;
        let unknown = ast::Unknown::new_untyped("test");
        let ast_expr = ast::Expr::unknown(unknown);
        let pst_expr: Expr = ast_expr.clone().try_into().unwrap();
        let ast_expr2: ast::Expr = pst_expr.try_into().expect("conversion failed");
        assert_eq!(ast_expr, ast_expr2);
    }

    /// Helper to normalize whitespace for policy string comparison
    fn normalize(s: &str) -> String {
        s.replace('\n', " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Test roundtrip: parse Cedar text -> ast::Policy -> pst::Policy -> ast::Policy
    /// and verify the string representation is preserved.
    fn assert_static_policy_roundtrip(cedar_text: &str) {
        let ast_policy: ast::Policy = parser::parse_policy(None, cedar_text)
            .expect("parse failed")
            .into();
        let pst_policy: Policy = ast_policy.clone().try_into().expect("ast->pst failed");
        let ast_policy2: ast::Policy = pst_policy.try_into().expect("pst->ast failed");
        assert_eq!(
            normalize(&ast_policy.to_string()),
            normalize(&ast_policy2.to_string()),
            "roundtrip failed for: {}",
            cedar_text
        );
    }

    /// Test roundtrip: parse Cedar text -> ast::Template -> pst::Policy -> ast::Template
    /// and verify the string representation is preserved.
    fn assert_template_roundtrip(cedar_text: &str) {
        let ast_template =
            parser::parse_template(Some(ast::PolicyID::from_string("id\n")), cedar_text)
                .expect("parse failed");
        let pst_policy: Template = ast_template.clone().try_into().expect("ast->pst failed");
        let ast_template2: ast::Template = pst_policy.try_into().expect("pst->ast failed");
        assert_eq!(ast_template.id(), ast_template2.id());
        assert_eq!(
            normalize(&ast_template.to_string()),
            normalize(&ast_template2.to_string()),
            "template roundtrip failed for: {}",
            cedar_text
        );
    }

    /// Test ast::Policy -> pst::Policy -> ast::Policy roundtrip for static policies
    #[test]
    fn test_static_policy_roundtrip() {
        let cases = [
            r#"permit(principal, action, resource);"#,
            r#"forbid(principal, action, resource);"#,
            r#"permit(principal, action, resource) when { true };"#,
            r#"permit(principal, action, resource) when { !false };"#,
            r#"@id("test") permit(principal, action, resource);"#,
            r#"permit(principal == User::"alice", action, resource);"#,
            r#"permit(principal in User::"alice", action, resource);"#,
            r#"permit(principal is User, action, resource);"#,
            r#"permit(principal is User in User::"alice", action, resource);"#,
            r#"permit(principal, action == Action::"view", resource);"#,
            r#"permit(principal, action in [Action::"view"], resource);"#,
            r#"permit(principal, action, resource == Photo::"vacation");"#,
            r#"permit(principal, action, resource in Album::"trips");"#,
            r#"permit(principal, action, resource is Photo);"#,
            r#"permit(principal, action, resource is Photo in Album::"trips");"#,
            r#"permit(principal == User::"alice", action == Action::"view", resource in Album::"trips") when { resource.public };"#,
        ];
        for cedar_text in cases {
            assert_static_policy_roundtrip(cedar_text);
        }
    }

    /// Test ast::Template -> pst::Policy -> ast::Template roundtrip for templates with slots
    #[test]
    fn test_template_policy_roundtrip() {
        let cases = [
            r#"permit(principal == ?principal, action, resource);"#,
            r#"permit(principal in ?principal, action, resource);"#,
            r#"permit(principal is User in ?principal, action, resource);"#,
            r#"permit(principal, action, resource == ?resource);"#,
            r#"permit(principal, action, resource in ?resource);"#,
            r#"permit(principal, action, resource is Photo in ?resource);"#,
            r#"permit(principal == ?principal, action, resource == ?resource);"#,
            r#"permit(principal == ?principal, action, resource in ?resource) when { resource.public };"#,
        ];
        for cedar_text in cases {
            assert_template_roundtrip(cedar_text);
        }
    }

    /// Test ast::Policy roundtrip for a linked template (slots filled via env)
    #[test]
    fn test_linked_policy_roundtrip() {
        let template = parser::parse_template(
            None,
            r#"permit(principal == ?principal, action, resource in ?resource);"#,
        )
        .expect("parse failed");
        let mut pset = ast::PolicySet::new();
        let template_id = template.id().clone();
        pset.add_template(template).expect("add template failed");

        let mut env = std::collections::HashMap::new();
        env.insert(
            ast::SlotId::principal(),
            parser::parse_euid(r#"User::"alice""#).unwrap(),
        );
        env.insert(
            ast::SlotId::resource(),
            parser::parse_euid(r#"Album::"trips""#).unwrap(),
        );
        let link_id = ast::PolicyID::from_string("link0");
        pset.link(template_id, link_id.clone(), env)
            .expect("link failed");

        let ast_policy = pset.get(&link_id).expect("policy not found").clone();
        let pst_policy: Policy = ast_policy.clone().try_into().expect("ast->pst failed");

        let Policy::Linked(ref linked) = pst_policy else {
            panic!("Expected Linked policy");
        };

        // Linked policy should use the link ID, not the template ID
        assert_eq!(linked.instance_id, PolicyID("link0".into()));

        // The body still has slots; values hold the bindings
        assert!(linked.body.principal.has_slot() || linked.body.resource.has_slot());
        assert!(linked.values.contains_key(&SlotId::Principal));
        assert!(linked.values.contains_key(&SlotId::Resource));

        // Should convert back to a linked AST policy
        let ast_policy2: ast::Policy = pst_policy.try_into().expect("pst->ast failed");
        let expected =
            normalize(r#"permit( principal == ?principal, action, resource in ?resource );"#);
        assert_eq!(normalize(&ast_policy2.template().to_string()), expected);
    }

    /// Test expressions that get desugared/normalized during AST conversion
    #[test]
    fn test_expression_desugaring() {
        let cases = [
            ("1 != 2", "!(1 == 2)", "!= desugars to !(==)"),
            ("1 > 2", "!(1 <= 2)", "> desugars to !(<=)"),
            ("1 >= 2", "!(1 < 2)", ">= desugars to !(<)"),
        ];

        for (input, expected_output, desc) in cases {
            let ast_expr = parse_expr(input);
            let pst_expr: Expr = ast_expr.try_into().unwrap();
            let ast_expr2: ast::Expr = pst_expr.try_into().expect("conversion failed");

            // Normalize both for comparison
            let actual = ast_expr2
                .to_string()
                .replace('\n', " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let expected = expected_output
                .replace('\n', " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");

            assert_eq!(actual, expected, "failed: {}", desc);
        }
    }

    #[test]
    fn test_wrong_slot_position() {
        // Resource slot in principal position
        let result: Result<ast::PrincipalConstraint, _> =
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Resource)).try_into();
        assert!(matches!(
            result,
            Err(PstConstructionError::WrongSlotPosition(..))
        ));
        assert!(result.unwrap_err().to_string().contains(
            "slot `?resource` cannot be used in this position (expected slot `?principal`)"
        ));

        // Principal slot in resource position
        let result: Result<ast::ResourceConstraint, _> =
            ResourceConstraint::In(EntityOrSlot::Slot(SlotId::Principal)).try_into();
        assert!(matches!(
            result,
            Err(PstConstructionError::WrongSlotPosition(..))
        ));

        assert!(result.unwrap_err().to_string().contains(
            "slot `?principal` cannot be used in this position (expected slot `?resource`)"
        ));
    }

    #[test]
    fn test_invalid_entity_type_rejected_at_construction() {
        let result = Name::unqualified(":::bad");
        assert!(matches!(
            result,
            Err(PstConstructionError::ParsingFailed(..))
        ));
    }
}
