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

use smol_str::ToSmolStr;

use super::{
    ActionConstraint, BinaryOp, Clause, Effect, EntityOrSlot, EntityType, EntityUID, Expr, Literal,
    Name, PatternElem, Policy, PolicyID, PrincipalConstraint, PstConstructionError,
    ResourceConstraint, SlotId, UnaryOp, Var,
};
use crate::ast;
use crate::expr_builder;
use crate::pst::err::error_body::{
    InvalidConversionError, InvalidExpressionError, ParsingFailedError,
};
use crate::pst::expr::{ErrorNode, PstBuilder};
use itertools::Itertools;
use std::str::FromStr;
use std::sync::Arc;

impl TryFrom<Policy> for ast::Policy {
    type Error = PstConstructionError;

    fn try_from(policy: Policy) -> Result<Self, Self::Error> {
        // Convert to Template first, then to Policy (following EST pattern)
        let template: ast::Template = policy.try_into()?;
        ast::StaticPolicy::try_from(template)
            .map(Into::into)
            .map_err(|e| {
                InvalidConversionError::new(format!(
                    "Failed to convert template to static policy: {:?}",
                    e
                ))
                .into()
            })
    }
}

impl TryFrom<Policy> for ast::Template {
    type Error = PstConstructionError;

    fn try_from(policy: Policy) -> Result<Self, Self::Error> {
        use crate::expr_builder::ExprBuilder;
        // Convert clauses - fold them into a single expression (following EST pattern)
        let builder = ast::ExprBuilder::<()>::new();
        let mut conds_rev_iter = policy
            .clauses
            .into_iter()
            .map(|clause| match clause {
                Clause::When(expr) => Arc::unwrap_or_clone(expr).try_into(),
                Clause::Unless(expr) => Arc::unwrap_or_clone(expr)
                    .try_into()
                    .map(|x| builder.clone().not(x)),
            })
            .rev()
            .collect::<Result<Vec<_>, _>>()?
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

impl TryFrom<PrincipalConstraint> for ast::PrincipalConstraint {
    type Error = PstConstructionError;

    fn try_from(constraint: PrincipalConstraint) -> Result<Self, Self::Error> {
        match constraint {
            PrincipalConstraint::Any => Ok(ast::PrincipalConstraint::any()),
            PrincipalConstraint::Eq(EntityOrSlot::Entity(eos)) => {
                Ok(ast::PrincipalConstraint::is_eq(Arc::new(eos.try_into()?)))
            }
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)) => {
                Ok(ast::PrincipalConstraint::is_eq_slot())
            }
            PrincipalConstraint::In(EntityOrSlot::Entity(eos)) => {
                Ok(ast::PrincipalConstraint::is_in(Arc::new(eos.try_into()?)))
            }
            PrincipalConstraint::In(EntityOrSlot::Slot(SlotId::Principal)) => {
                Ok(ast::PrincipalConstraint::is_in_slot())
            }
            PrincipalConstraint::Is(entity_type) => Ok(ast::PrincipalConstraint::is_entity_type(
                Arc::new(entity_type.try_into()?),
            )),
            PrincipalConstraint::IsIn(entity_type, EntityOrSlot::Entity(eos)) => {
                Ok(ast::PrincipalConstraint::is_entity_type_in(
                    Arc::new(entity_type.try_into()?),
                    Arc::new(eos.try_into()?),
                ))
            }
            PrincipalConstraint::IsIn(entity_type, EntityOrSlot::Slot(SlotId::Principal)) => Ok(
                ast::PrincipalConstraint::is_entity_type_in_slot(Arc::new(entity_type.try_into()?)),
            ),
            // Wrong slot type (resource slot in principal position)
            PrincipalConstraint::Eq(EntityOrSlot::Slot(s))
            | PrincipalConstraint::In(EntityOrSlot::Slot(s))
            | PrincipalConstraint::IsIn(_, EntityOrSlot::Slot(s)) => Err(
                InvalidConversionError::new(format!("principal constraint cannot use slot `{s}`"))
                    .into(),
            ),
        }
    }
}

impl TryFrom<ResourceConstraint> for ast::ResourceConstraint {
    type Error = PstConstructionError;

    fn try_from(constraint: ResourceConstraint) -> Result<Self, Self::Error> {
        match constraint {
            ResourceConstraint::Any => Ok(ast::ResourceConstraint::any()),
            ResourceConstraint::Eq(EntityOrSlot::Entity(eos)) => {
                Ok(ast::ResourceConstraint::is_eq(Arc::new(eos.try_into()?)))
            }
            ResourceConstraint::Eq(EntityOrSlot::Slot(SlotId::Resource)) => {
                Ok(ast::ResourceConstraint::is_eq_slot())
            }
            ResourceConstraint::In(EntityOrSlot::Entity(eos)) => {
                Ok(ast::ResourceConstraint::is_in(Arc::new(eos.try_into()?)))
            }
            ResourceConstraint::In(EntityOrSlot::Slot(SlotId::Resource)) => {
                Ok(ast::ResourceConstraint::is_in_slot())
            }
            ResourceConstraint::Is(entity_type) => Ok(ast::ResourceConstraint::is_entity_type(
                Arc::new(entity_type.try_into()?),
            )),
            ResourceConstraint::IsIn(entity_type, EntityOrSlot::Entity(eos)) => {
                Ok(ast::ResourceConstraint::is_entity_type_in(
                    Arc::new(entity_type.try_into()?),
                    Arc::new(eos.try_into()?),
                ))
            }
            ResourceConstraint::IsIn(entity_type, EntityOrSlot::Slot(SlotId::Resource)) => Ok(
                ast::ResourceConstraint::is_entity_type_in_slot(Arc::new(entity_type.try_into()?)),
            ),
            // Wrong slot type (principal slot in resource position)
            ResourceConstraint::Eq(EntityOrSlot::Slot(s))
            | ResourceConstraint::In(EntityOrSlot::Slot(s))
            | ResourceConstraint::IsIn(_, EntityOrSlot::Slot(s)) => Err(
                InvalidConversionError::new(format!("resource constraint cannot use slot `{s}`"))
                    .into(),
            ),
        }
    }
}

impl TryFrom<ActionConstraint> for ast::ActionConstraint {
    type Error = PstConstructionError;

    fn try_from(constraint: ActionConstraint) -> Result<Self, Self::Error> {
        match constraint {
            ActionConstraint::Any => Ok(ast::ActionConstraint::any()),
            ActionConstraint::Eq(uid) => Ok(ast::ActionConstraint::is_eq(uid.try_into()?)),
            ActionConstraint::In(uids) => {
                let ast_uids: Result<Vec<_>, _> =
                    uids.into_iter().map(|uid| uid.try_into()).collect();
                Ok(ast::ActionConstraint::is_in(ast_uids?))
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

impl TryFrom<Expr> for ast::Expr {
    type Error = PstConstructionError;

    fn try_from(expr: Expr) -> Result<Self, PstConstructionError> {
        expr.try_into_expr::<ast::ExprBuilder<()>>()
    }
}

impl Expr {
    pub(crate) fn try_into_expr<B: expr_builder::ExprBuilder>(
        self,
    ) -> Result<B::Expr, PstConstructionError> {
        let builder = B::new();
        match self {
            Expr::Literal(lit) => match lit {
                Literal::Bool(b) => Ok(builder.val(b)),
                Literal::Long(i) => Ok(builder.val(i)),
                Literal::String(s) => Ok(builder.val(s)),
                Literal::EntityUID(uid) => {
                    let ast_et: ast::EntityType = uid.ty.try_into()?;
                    let ast_eid = ast::Eid::new(uid.eid.as_str());
                    let ast_uid = ast::EntityUID::from_components(ast_et, ast_eid, None);
                    Ok(builder.val(ast_uid))
                }
            },
            Expr::Var(v) => Ok(builder.var(v.into())),
            Expr::Slot(s) => Ok(builder.slot(s.into())),
            Expr::UnaryOp { op, expr } => {
                let inner = Arc::unwrap_or_clone(expr).try_into_expr::<B>()?;
                Ok(match op {
                    UnaryOp::Not => builder.not(inner),
                    UnaryOp::Neg => builder.neg(inner),
                    UnaryOp::IsEmpty => builder.is_empty(inner),
                    // The other unary operators are extension functions.
                    _ => match op.to_name() {
                        Some(fn_name) => builder.call_extension_fn(fn_name.clone(), vec![inner]),
                        // This should never occur!
                        None => Err(PstConstructionError::from(InvalidExpressionError::new(
                            format!("unknown unary operator: {}", op),
                        )))?,
                    },
                })
            }
            Expr::BinaryOp { op, left, right } => {
                let left_ast = Arc::unwrap_or_clone(left).try_into_expr::<B>()?;
                let right_ast = Arc::unwrap_or_clone(right).try_into_expr::<B>()?;

                Ok(match op {
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
                    // The other binary operators are extensions
                    _ => match op.to_name() {
                        Some(fn_name) => {
                            builder.call_extension_fn(fn_name.clone(), vec![left_ast, right_ast])
                        }
                        // This should never occur!
                        None => Err(PstConstructionError::from(InvalidExpressionError::new(
                            format!("unknown binary operator: {}", op),
                        )))?,
                    },
                })
            }
            Expr::Set(exprs) => {
                let ast_exprs: Result<Vec<_>, _> = exprs
                    .into_iter()
                    .map(|e| Arc::unwrap_or_clone(e).try_into_expr::<B>())
                    .collect();
                Ok(builder.set(ast_exprs?))
            }
            Expr::IfThenElse {
                cond,
                then_expr,
                else_expr,
            } => Ok(builder.ite(
                Arc::unwrap_or_clone(cond).try_into_expr::<B>()?,
                Arc::unwrap_or_clone(then_expr).try_into_expr::<B>()?,
                Arc::unwrap_or_clone(else_expr).try_into_expr::<B>()?,
            )),
            Expr::Is {
                expr,
                entity_type,
                in_expr: None,
            } => Ok(builder.is_entity_type(
                Arc::unwrap_or_clone(expr).try_into_expr::<B>()?,
                entity_type.try_into()?,
            )),
            Expr::Is {
                expr,
                entity_type,
                in_expr: Some(e),
            } => Ok(builder.is_in_entity_type(
                Arc::unwrap_or_clone(expr).try_into_expr::<B>()?,
                entity_type.try_into()?,
                Arc::unwrap_or_clone(e).try_into_expr::<B>()?,
            )),
            Expr::GetAttr { expr, attr } => {
                Ok(builder.get_attr(Arc::unwrap_or_clone(expr).try_into_expr::<B>()?, attr))
            }
            Expr::HasAttr { expr, attrs } => {
                Ok(builder
                    .extended_has_attr(Arc::unwrap_or_clone(expr).try_into_expr::<B>()?, attrs))
            }
            Expr::Like { expr, pattern } => Ok(builder.like(
                Arc::unwrap_or_clone(expr).try_into_expr::<B>()?,
                elements_into_ast_pattern(pattern),
            )),
            Expr::Record(elems) => builder
                .record(
                    elems
                        .into_iter()
                        .map(|(k, v)| Ok((k.into(), Arc::unwrap_or_clone(v).try_into_expr::<B>()?)))
                        .collect::<Result<Vec<_>, PstConstructionError>>()?,
                )
                .map_err(|cstr_err: ast::ExpressionConstructionError| {
                    InvalidConversionError::new(cstr_err.to_string()).into()
                }),
            Expr::Unknown { name } => Ok(builder.unknown(ast::Unknown {
                name,
                type_annotation: None,
            })),
            Expr::Error(ErrorNode { error }) => Err(error),
        }
    }
}

impl From<Effect> for ast::Effect {
    fn from(effect: Effect) -> Self {
        match effect {
            Effect::Permit => ast::Effect::Permit,
            Effect::Forbid => ast::Effect::Forbid,
        }
    }
}

impl TryFrom<EntityUID> for ast::EntityUID {
    type Error = PstConstructionError;

    fn try_from(value: EntityUID) -> Result<Self, PstConstructionError> {
        let ast_et: ast::EntityType = value.ty.try_into()?;
        let ast_eid = ast::Eid::new(value.eid.as_str());
        Ok(ast::EntityUID::from_components(ast_et, ast_eid, None))
    }
}

impl From<ast::EntityType> for EntityType {
    fn from(et: ast::EntityType) -> Self {
        EntityType(et.into_name().into())
    }
}

impl TryFrom<EntityType> for ast::EntityType {
    type Error = PstConstructionError;

    fn try_from(et: EntityType) -> Result<Self, Self::Error> {
        let name: ast::Name = et.0.try_into()?;
        Ok(ast::EntityType::EntityType(name))
    }
}

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

impl From<ast::Name> for Name {
    fn from(name: ast::Name) -> Self {
        let ast::Name {
            0: ast::InternalName { id, path, .. },
        } = name;
        Name {
            id: id.into_smolstr(),
            namespace: Arc::new(
                Arc::unwrap_or_clone(path)
                    .into_iter()
                    .map(|id| id.to_smolstr())
                    .collect(),
            ),
        }
    }
}

impl TryFrom<Name> for ast::Name {
    type Error = PstConstructionError;

    fn try_from(name: Name) -> Result<Self, Self::Error> {
        let basename = ast::Id::from_str(&name.id).map_err(ParsingFailedError::from)?;
        let path: Vec<ast::Id> = name
            .namespace
            .iter()
            .map(|s| ast::Id::from_str(s.as_str()))
            .try_collect()
            .map_err(ParsingFailedError::from)?;
        Ok(ast::Name(ast::InternalName::new(basename, path, None)))
    }
}

impl From<ast::SlotId> for SlotId {
    fn from(slot: ast::SlotId) -> Self {
        match slot.0 {
            ast::ValidSlotId::Principal => SlotId::Principal,
            ast::ValidSlotId::Resource => SlotId::Resource,
        }
    }
}

impl From<SlotId> for ast::SlotId {
    fn from(slot: SlotId) -> Self {
        match slot {
            SlotId::Principal => ast::SlotId::principal(),
            SlotId::Resource => ast::SlotId::resource(),
        }
    }
}

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

impl From<ast::EntityUID> for EntityUID {
    fn from(uid: ast::EntityUID) -> Self {
        let (ty, eid) = uid.components();
        EntityUID {
            ty: ty.into(),
            eid: eid.into_smolstr(),
        }
    }
}

impl From<ast::Expr> for Expr {
    fn from(ast_expr: ast::Expr) -> Self {
        ast::Expr::into_expr::<PstBuilder>(ast_expr)
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
impl From<ast::ActionConstraint> for ActionConstraint {
    fn from(c: ast::ActionConstraint) -> Self {
        match c {
            ast::ActionConstraint::Any => ActionConstraint::Any,
            ast::ActionConstraint::Eq(uid) => {
                ActionConstraint::Eq(Arc::unwrap_or_clone(uid).into())
            }
            ast::ActionConstraint::In(uids) => ActionConstraint::In(
                uids.into_iter()
                    .map(|uid| Arc::unwrap_or_clone(uid).into())
                    .collect(),
            ),
            #[cfg(feature = "tolerant-ast")]
            ast::ActionConstraint::ErrorConstraint => ActionConstraint::Any,
        }
    }
}

#[doc(hidden)]
impl TryFrom<ast::Template> for Policy {
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
            .ok_or_else(|| InvalidConversionError::new("template contained errors".to_string()))?;
        let id = PolicyID(id.to_smolstr());
        let effect = effect.into();
        let principal = principal_constraint.into();
        let action = action_constraint.into();
        let resource = resource_constraint.into();

        let clauses = match clause {
            Some(expr) => vec![Clause::When(Arc::new(Arc::unwrap_or_clone(expr).into()))],
            None => vec![],
        };

        let annotations = Arc::unwrap_or_clone(annot)
            .into_iter()
            .map(|(key, ann)| (key.to_string(), ann.val))
            .collect();

        Ok(Policy {
            id,
            effect,
            principal,
            action,
            resource,
            clauses,
            annotations,
        })
    }
}

#[doc(hidden)]
impl TryFrom<ast::Policy> for Policy {
    type Error = PstConstructionError;

    fn try_from(policy: ast::Policy) -> Result<Self, PstConstructionError> {
        let (template, link_id, env) = policy.into_components();
        let mut policy: Policy = Arc::unwrap_or_clone(template).try_into()?;
        if let Some(id) = link_id {
            policy.id = PolicyID(id.to_smolstr());
        }
        let env = env
            .into_iter()
            .map(|(k, v)| (SlotId::from(k), EntityUID::from(v)))
            .collect();
        Ok(policy.link(&env)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;
    use itertools::Itertools;
    use smol_str::SmolStr;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn parse_expr(s: &str) -> ast::Expr {
        parser::parse_expr(s).expect("parse failed")
    }

    fn norm(s: String) -> String {
        s.split_whitespace().join(" ")
    }

    /// AST → PST → AST → PST: verifies both representations are stable.
    fn assert_expr_roundtrip(cedar: &str) {
        let ast1 = parse_expr(cedar);
        let pst1: Expr = ast1.clone().into();
        let ast2: ast::Expr = pst1.clone().try_into().expect("pst->ast failed");
        let pst2: Expr = ast2.clone().into();
        assert_eq!(ast1, ast2, "AST mismatch for: {cedar}");
        assert_eq!(pst1, pst2, "PST mismatch for: {cedar}");
    }

    /// parse → ast::Policy → pst::Policy → ast::Policy → pst::Policy: verifies both stable.
    fn assert_static_policy_roundtrip(cedar: &str) {
        let ast1: ast::Policy = parser::parse_policy(None, cedar)
            .expect("parse failed")
            .into();
        let pst1: Policy = ast1.clone().try_into().expect("ast->pst failed");
        let ast2: ast::Policy = pst1.clone().try_into().expect("pst->ast failed");
        let pst2: Policy = ast2.clone().try_into().expect("ast->pst 2 failed");
        assert_eq!(
            norm(ast1.to_string()),
            norm(ast2.to_string()),
            "AST mismatch for: {cedar}"
        );
        assert_eq!(pst1, pst2, "PST mismatch for: {cedar}");
    }

    /// parse → ast::Template → pst::Policy → ast::Template → pst::Policy: verifies both stable.
    fn assert_template_roundtrip(cedar: &str) {
        let ast1 = parser::parse_template(None, cedar).expect("parse failed");
        let pst1: Policy = ast1.clone().try_into().expect("ast->pst failed");
        let ast2: ast::Template = pst1.clone().try_into().expect("pst->ast failed");
        let pst2: Policy = ast2.clone().try_into().expect("ast->pst 2 failed");
        assert_eq!(
            norm(ast1.to_string()),
            norm(ast2.to_string()),
            "AST mismatch for: {cedar}"
        );
        assert_eq!(pst1, pst2, "PST mismatch for: {cedar}");
    }

    #[test]
    fn test_expr_roundtrips() {
        let cases = [
            // Literals
            "true",
            "false",
            "42",
            r#""hello""#,
            // Variables
            "principal",
            "action",
            "resource",
            "context",
            // Unary ops
            "!true",
            "-42",
            "[].isEmpty()",
            // Binary ops
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
            r#"context.products.containsAny(["apples","oranges"])"#,
            r#"[1, 2].containsAny([2, 3])"#,
            r#"User::"alice".getTag("role")"#,
            r#"User::"alice".hasTag("role")"#,
            // If-then-else
            "if true then 1 else 2",
            // Sets
            "[]",
            "[1]",
            "[1, 2, 3]",
            // Records (including reserved-word and hyphenated keys)
            "{}",
            r#"{"a": 1}"#,
            r#"{"a": 1, "b": 2}"#,
            r#"{"nested": {"x": 1}}"#,
            r#"{"if": 1}"#,
            r#"{"a-b": 1}"#,
            // Entity UIDs (simple and namespaced)
            r#"User::"alice""#,
            r#"MyApp::User::"alice""#,
            // Attribute access and has
            r#"principal.name"#,
            r#"resource.owner.id"#,
            r#"principal has name"#,
            // Like patterns
            r#"principal.name like "a*b""#,
            r#""test" like "*""#,
            r#""test" like "*est""#,
            r#""test" like "test*""#,
            // Is / is-in (simple and namespaced)
            r#"principal is User"#,
            r#"principal is MyApp::User"#,
            r#"principal is User in Group::"admins""#,
            r#"principal is User in Group::"admins" || principal is User in Group::"users""#,
            // Extension functions
            r#"decimal("1.23")"#,
            r#"ip("127.0.0.1")"#,
            r#"datetime("2024-01-01")"#,
            r#"ip("127.0.0.1").isIpv4()"#,
            r#"ip("127.0.0.1").isInRange(ip("127.0.0.0/24"))"#,
            // Complex / nested
            r#"if principal.age >= 18 && resource.public == true then [1, 2, 3].contains(action.level) else false"#,
            r#"((1 + 2) * 3) - 4"#,
            r#"!(!true)"#,
            r#"true && (false || true)"#,
            r#"principal has name && principal has age"#,
        ];
        for cedar in cases {
            assert_expr_roundtrip(cedar);
        }
    }

    /// Extension methods like `lessThan` normalize to operators during AST→PST conversion,
    /// so they don't produce identical AST on roundtrip, but conversion must succeed.
    #[test]
    fn test_extension_method_normalization() {
        for cedar in [
            r#"decimal("1.23").lessThan(decimal("2.0"))"#,
            r#"decimal("1.23").lessThanOrEqual(decimal("2.0"))"#,
            r#"decimal("1.23").greaterThan(decimal("2.0"))"#,
            r#"decimal("1.23").greaterThanOrEqual(decimal("2.0"))"#,
        ] {
            let pst: Expr = parse_expr(cedar).into();
            let _: ast::Expr = pst.try_into().expect(cedar);
        }
    }

    #[test]
    fn test_unknown_expr() {
        // Unknown is created programmatically, not parsed
        use crate::ast;
        let unknown = ast::Unknown::new_untyped("test");
        let ast_expr = ast::Expr::unknown(unknown);
        let pst_expr: Expr = ast_expr.clone().into();
        let ast_expr2: ast::Expr = pst_expr.try_into().expect("conversion failed");
        assert_eq!(ast_expr, ast_expr2);
    }

    #[test]
    fn test_static_policy_roundtrips() {
        for cedar in [
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
            r#"permit(principal is User, action, resource is Photo in Album::"trips");"#,
        ] {
            assert_static_policy_roundtrip(cedar);
        }
    }

    #[test]
    fn test_template_roundtrips() {
        for cedar in [
            r#"permit(principal == ?principal, action, resource);"#,
            r#"permit(principal in ?principal, action, resource);"#,
            r#"permit(principal is User in ?principal, action, resource);"#,
            r#"permit(principal, action, resource == ?resource);"#,
            r#"permit(principal, action, resource in ?resource);"#,
            r#"permit(principal, action, resource is Photo in ?resource);"#,
            r#"permit(principal == ?principal, action, resource == ?resource);"#,
            r#"permit(principal == ?principal, action, resource in ?resource) when { resource.public };"#,
            r#"permit(principal in ?principal, action, resource in ?resource);"#,
            r#"permit(principal is User in ?principal, action, resource == ?resource) when { resource.public };"#,
        ] {
            assert_template_roundtrip(cedar);
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
        let pst_policy: Policy = ast_policy.try_into().expect("ast->pst failed");

        // Linked policy should use the link ID, not the template ID
        assert_eq!(pst_policy.id, PolicyID("link0".into()));

        // Linked policy should have no slots — entities are filled in
        assert!(matches!(
            pst_policy.principal,
            PrincipalConstraint::Eq(EntityOrSlot::Entity(_))
        ));
        assert!(matches!(
            pst_policy.resource,
            ResourceConstraint::In(EntityOrSlot::Entity(_))
        ));

        // Should convert back to a static AST policy
        let ast_policy2: ast::Policy = pst_policy.try_into().expect("pst->ast failed");
        let expected = norm(
            r#"permit( principal == User::"alice", action, resource in Album::"trips" );"#
                .to_string(),
        );
        assert_eq!(norm(ast_policy2.to_string()), expected);
    }

    /// The Cedar parser desugars `!=`, `>`, `>=` into negated forms in the AST.
    /// Verify the string output of the roundtripped expression matches the desugared form.
    #[test]
    fn test_expression_desugaring() {
        for (input, expected) in [
            ("1 != 2", "!(1 == 2)"),
            ("1 > 2", "!(1 <= 2)"),
            ("1 >= 2", "!(1 < 2)"),
        ] {
            let ast2: ast::Expr = Into::<Expr>::into(parse_expr(input)).try_into().unwrap();
            assert_eq!(
                norm(ast2.to_string()),
                norm(expected.to_string()),
                "desugaring: {input}"
            );
        }
    }

    /// ErrorNode in PST must produce a conversion error, not silently succeed.
    #[test]
    fn test_error_node_conversion() {
        use crate::pst::expr::ErrorNode;

        let error_expr = Expr::Error(ErrorNode {
            error: InvalidExpressionError::new("test error".into()).into(),
        });

        let result: Result<ast::Expr, PstConstructionError> = error_expr.try_into();
        assert!(result.is_err(), "ErrorNode should fail conversion");

        match result {
            Err(PstConstructionError::InvalidExpression(err)) => {
                assert_eq!(err.description, "test error");
            }
            Err(e) => panic!("Expected InvalidExpression error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    // ===== Programmatic construction =====

    #[test]
    fn test_programmatic_construction() {
        // Static policy with principal constraint and when clause
        let policy = Policy {
            id: PolicyID("policy0".into()),
            effect: Effect::Permit,
            principal: PrincipalConstraint::Eq(EntityOrSlot::Entity(EntityUID {
                ty: EntityType::from_name(Name::unqualified("User")),
                eid: "alice".into(),
            })),
            action: ActionConstraint::Any,
            resource: ResourceConstraint::Any,
            clauses: vec![Clause::When(Arc::new(Expr::Literal(Literal::Bool(true))))],
            annotations: BTreeMap::new(),
        };
        let ast_policy: ast::Policy = policy.try_into().expect("static policy");
        let text = norm(ast_policy.to_string());
        assert!(
            text.contains("permit")
                && text.contains("User::\"alice\"")
                && text.contains("when { true }")
        );

        // Template with two slots
        let tmpl = Policy {
            id: PolicyID("tmpl0".into()),
            effect: Effect::Forbid,
            principal: PrincipalConstraint::In(EntityOrSlot::Slot(SlotId::Principal)),
            action: ActionConstraint::Any,
            resource: ResourceConstraint::Eq(EntityOrSlot::Slot(SlotId::Resource)),
            clauses: vec![],
            annotations: BTreeMap::new(),
        };
        let ast_tmpl: ast::Template = tmpl.try_into().expect("template");
        assert_eq!(ast_tmpl.slots().count(), 2);

        // Programmatic expr: if (principal.age >= 18) then true else false
        let expr = Expr::IfThenElse {
            cond: Arc::new(Expr::BinaryOp {
                op: BinaryOp::GreaterEq,
                left: Arc::new(Expr::GetAttr {
                    expr: Arc::new(Expr::Var(Var::Principal)),
                    attr: "age".into(),
                }),
                right: Arc::new(Expr::Literal(Literal::Long(18))),
            }),
            then_expr: Arc::new(Expr::Literal(Literal::Bool(true))),
            else_expr: Arc::new(Expr::Literal(Literal::Bool(false))),
        };
        let _: ast::Expr = expr.try_into().expect("expr");

        // Annotations
        let mut annotations = BTreeMap::new();
        annotations.insert("reason".to_string(), SmolStr::new("test"));
        let annotated = Policy {
            id: PolicyID("p0".into()),
            effect: Effect::Permit,
            principal: PrincipalConstraint::Any,
            action: ActionConstraint::Any,
            resource: ResourceConstraint::Any,
            clauses: vec![],
            annotations,
        };
        let ast_annotated: ast::Template = annotated.try_into().expect("annotated");
        assert!(ast_annotated.to_string().contains("@reason(\"test\")"));
    }

    // ===== Edge cases =====

    /// PST-level structural edge cases: empty/nested collections, deep nesting.
    #[test]
    fn test_pst_expr_roundtrips() {
        // Empty set
        let empty_set = Expr::Set(vec![]);
        let back: Expr = TryInto::<ast::Expr>::try_into(empty_set.clone())
            .unwrap()
            .into();
        assert_eq!(empty_set, back);

        // Empty record
        let empty_rec = Expr::Record(BTreeMap::new());
        let back: Expr = TryInto::<ast::Expr>::try_into(empty_rec.clone())
            .unwrap()
            .into();
        assert_eq!(empty_rec, back);

        // Deeply nested: !(!(!(!(true))))
        let mut deep = Expr::Literal(Literal::Bool(true));
        for _ in 0..4 {
            deep = Expr::UnaryOp {
                op: UnaryOp::Not,
                expr: Arc::new(deep),
            };
        }
        let back: Expr = TryInto::<ast::Expr>::try_into(deep.clone()).unwrap().into();
        assert_eq!(deep, back);

        // Nested set inside record
        let nested = Expr::Record(BTreeMap::from([
            (
                "items".to_string(),
                Arc::new(Expr::Set(vec![
                    Arc::new(Expr::Literal(Literal::Long(1))),
                    Arc::new(Expr::Set(vec![])),
                ])),
            ),
            ("empty".to_string(), Arc::new(Expr::Record(BTreeMap::new()))),
        ]));
        let back: Expr = TryInto::<ast::Expr>::try_into(nested.clone())
            .unwrap()
            .into();
        assert_eq!(nested, back);
    }

    /// Multiple when/unless clauses get merged by AST into a single conjunction.
    #[test]
    fn test_multiple_clauses_merge() {
        let policy = Policy {
            id: PolicyID("p0".into()),
            effect: Effect::Permit,
            principal: PrincipalConstraint::Any,
            action: ActionConstraint::Any,
            resource: ResourceConstraint::Any,
            clauses: vec![
                Clause::When(Arc::new(Expr::Literal(Literal::Bool(true)))),
                Clause::Unless(Arc::new(Expr::Literal(Literal::Bool(false)))),
                Clause::When(Arc::new(Expr::BinaryOp {
                    op: BinaryOp::Eq,
                    left: Arc::new(Expr::Var(Var::Principal)),
                    right: Arc::new(Expr::Var(Var::Resource)),
                })),
            ],
            annotations: BTreeMap::new(),
        };
        let ast_t: ast::Template = policy.clone().try_into().expect("conversion failed");
        let pst_back: Policy = ast_t.try_into().expect("back conversion failed");
        assert_eq!(policy.effect, pst_back.effect);
        assert_eq!(policy.principal, pst_back.principal);
        assert!(!pst_back.clauses.is_empty());
    }

    /// All principal, resource, and action constraint variants roundtrip correctly,
    /// including namespaced entity types.
    #[test]
    fn test_all_constraint_variants() {
        let uid = EntityUID {
            ty: EntityType::from_name(Name::unqualified("User")),
            eid: "alice".into(),
        };
        let et = EntityType::from_name(Name::unqualified("User"));

        let make_policy = |principal, action, resource| Policy {
            id: PolicyID("p0".into()),
            effect: Effect::Permit,
            principal,
            action,
            resource,
            clauses: vec![],
            annotations: BTreeMap::new(),
        };

        for principal in [
            PrincipalConstraint::Any,
            PrincipalConstraint::Eq(EntityOrSlot::Entity(uid.clone())),
            PrincipalConstraint::In(EntityOrSlot::Entity(uid.clone())),
            PrincipalConstraint::Is(et.clone()),
            PrincipalConstraint::IsIn(et.clone(), EntityOrSlot::Entity(uid.clone())),
            // Namespaced entity type
            PrincipalConstraint::Is(EntityType::from_name(Name::qualified(
                ["MyApp", "Auth"],
                "User",
            ))),
        ] {
            let p = make_policy(
                principal.clone(),
                ActionConstraint::Any,
                ResourceConstraint::Any,
            );
            let back: Policy = TryInto::<ast::Template>::try_into(p)
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(principal, back.principal);
        }

        for resource in [
            ResourceConstraint::Any,
            ResourceConstraint::Eq(EntityOrSlot::Entity(uid.clone())),
            ResourceConstraint::In(EntityOrSlot::Entity(uid.clone())),
            ResourceConstraint::Is(et.clone()),
            ResourceConstraint::IsIn(et.clone(), EntityOrSlot::Entity(uid.clone())),
        ] {
            let p = make_policy(
                PrincipalConstraint::Any,
                ActionConstraint::Any,
                resource.clone(),
            );
            let back: Policy = TryInto::<ast::Template>::try_into(p)
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(resource, back.resource);
        }

        for action in [
            ActionConstraint::Any,
            ActionConstraint::Eq(uid.clone()),
            ActionConstraint::In(vec![uid.clone()]),
            ActionConstraint::In(vec![
                uid.clone(),
                EntityUID {
                    ty: EntityType::from_name(Name::unqualified("Action")),
                    eid: "write".into(),
                },
            ]),
        ] {
            let p = make_policy(
                PrincipalConstraint::Any,
                action.clone(),
                ResourceConstraint::Any,
            );
            let back: Policy = TryInto::<ast::Template>::try_into(p)
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(action, back.action);
        }
    }

    /// A PST policy with slots must not convert to a static ast::Policy.
    #[test]
    fn test_slot_in_constraint_rejects_static_conversion() {
        let policy = Policy {
            id: PolicyID("p0".into()),
            effect: Effect::Permit,
            principal: PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)),
            action: ActionConstraint::Any,
            resource: ResourceConstraint::Any,
            clauses: vec![],
            annotations: BTreeMap::new(),
        };
        assert!(TryInto::<ast::Policy>::try_into(policy).is_err());
    }

    /// A resource slot in a principal constraint (and vice versa) must be rejected.
    #[test]
    fn test_wrong_slot_type_in_constraint_fails() {
        // Resource slot in principal position
        for principal in [
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Resource)),
            PrincipalConstraint::In(EntityOrSlot::Slot(SlotId::Resource)),
            PrincipalConstraint::IsIn(
                EntityType::from_name(Name::unqualified("User")),
                EntityOrSlot::Slot(SlotId::Resource),
            ),
        ] {
            let result: Result<ast::Template, _> = Policy {
                id: PolicyID("p0".into()),
                effect: Effect::Permit,
                principal,
                action: ActionConstraint::Any,
                resource: ResourceConstraint::Any,
                clauses: vec![],
                annotations: BTreeMap::new(),
            }
            .try_into();
            assert!(
                matches!(result, Err(PstConstructionError::InvalidConversion(_))),
                "expected error for resource slot in principal"
            );
        }

        // Principal slot in resource position
        for resource in [
            ResourceConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)),
            ResourceConstraint::In(EntityOrSlot::Slot(SlotId::Principal)),
            ResourceConstraint::IsIn(
                EntityType::from_name(Name::unqualified("Photo")),
                EntityOrSlot::Slot(SlotId::Principal),
            ),
        ] {
            let result: Result<ast::Template, _> = Policy {
                id: PolicyID("p0".into()),
                effect: Effect::Permit,
                principal: PrincipalConstraint::Any,
                action: ActionConstraint::Any,
                resource,
                clauses: vec![],
                annotations: BTreeMap::new(),
            }
            .try_into();
            assert!(
                matches!(result, Err(PstConstructionError::InvalidConversion(_))),
                "expected error for principal slot in resource"
            );
        }
    }
}
