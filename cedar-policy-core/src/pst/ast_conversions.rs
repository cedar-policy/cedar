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
    Name, PatternElem, Policy, PrincipalConstraint, PstConstructionError, ResourceConstraint,
    SlotId, UnaryOp, Var,
};
use crate::ast;
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
                PstConstructionError::InvalidConversion(format!(
                    "Failed to convert template to static policy: {:?}",
                    e
                ))
            })
    }
}

impl TryFrom<Policy> for ast::Template {
    type Error = PstConstructionError;

    fn try_from(policy: Policy) -> Result<Self, Self::Error> {
        use crate::expr_builder::ExprBuilder;
        let id = policy.id.into();
        let effect: ast::Effect = policy.effect.into();
        let principal: ast::PrincipalConstraint = policy.principal.try_into()?;
        let action: ast::ActionConstraint = policy.action.try_into()?;
        let resource: ast::ResourceConstraint = policy.resource.try_into()?;
        // Convert clauses - fold them into a single expression (following EST pattern)
        let builder = ast::ExprBuilder::<()>::new();
        let mut conds_rev_iter = policy
            .clauses
            .into_iter()
            .map(|clause| match clause {
                Clause::When(expr) => (*expr).clone().try_into(),
                Clause::Unless(expr) => (*expr).clone().try_into().map(|x| builder.clone().not(x)),
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
                let value = if val.is_empty() {
                    None
                } else {
                    Some(val.to_smolstr())
                };
                (
                    ast::AnyId::new_unchecked(key),
                    ast::Annotation::with_optional_value(value, None),
                )
            })
            .collect();

        Ok(ast::Template::new(
            id,
            None,
            annotations,
            effect,
            principal,
            action,
            resource,
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
            PrincipalConstraint::In(EntityOrSlot::Entity(eos)) => {
                Ok(ast::PrincipalConstraint::is_in(Arc::new(eos.try_into()?)))
            }
            PrincipalConstraint::Is(entity_type) => {
                let ast_et: ast::EntityType = entity_type.try_into().map_err(|e| {
                    PstConstructionError::InvalidConversion(format!("Invalid entity type: {:?}", e))
                })?;
                Ok(ast::PrincipalConstraint::is_entity_type(Arc::new(ast_et)))
            }
            PrincipalConstraint::IsIn(entity_type, EntityOrSlot::Entity(eos)) => {
                let ast_et: ast::EntityType = entity_type.try_into().map_err(|e| {
                    PstConstructionError::InvalidConversion(format!("Invalid entity type: {:?}", e))
                })?;
                Ok(ast::PrincipalConstraint::is_entity_type_in(
                    Arc::new(ast_et),
                    Arc::new(eos.try_into()?),
                ))
            }
            _ => Err(PstConstructionError::NotImplemented("templates".into())),
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
            ResourceConstraint::In(EntityOrSlot::Entity(eos)) => {
                Ok(ast::ResourceConstraint::is_in(Arc::new(eos.try_into()?)))
            }
            ResourceConstraint::Is(entity_type) => {
                let ast_et: ast::EntityType = entity_type.try_into().map_err(|e| {
                    PstConstructionError::InvalidConversion(format!("Invalid entity type: {:?}", e))
                })?;
                Ok(ast::ResourceConstraint::is_entity_type(Arc::new(ast_et)))
            }
            ResourceConstraint::IsIn(entity_type, EntityOrSlot::Entity(eos)) => {
                let ast_et: ast::EntityType = entity_type.try_into().map_err(|e| {
                    PstConstructionError::InvalidConversion(format!("Invalid entity type: {:?}", e))
                })?;
                Ok(ast::ResourceConstraint::is_entity_type_in(
                    Arc::new(ast_et),
                    Arc::new(eos.try_into()?),
                ))
            }
            _ => Err(PstConstructionError::NotImplemented("templates".into())),
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
        expr_to_ast(expr).map_err(|e| {
            PstConstructionError::InvalidConversion(format!("Failed to convert expr: {:?}", e))
        })
    }
}

// Helper to convert PST Expr to AST Expr using the AST builder
fn expr_to_ast(expr: Expr) -> Result<ast::Expr, PstConstructionError> {
    use crate::expr_builder::ExprBuilder;
    let builder = ast::ExprBuilder::<()>::new();

    match expr {
        Expr::Literal(lit) => match lit {
            Literal::Bool(b) => Ok(builder.val(b)),
            Literal::Long(i) => Ok(builder.val(i)),
            Literal::String(s) => Ok(builder.val(s)),
            Literal::EntityUID(uid) => {
                // Convert PST EntityUID to AST EntityUID using existing TryFrom impl
                let ast_et: ast::EntityType = uid.ty.try_into().map_err(|e| {
                    PstConstructionError::InvalidConversion(format!("Invalid entity type: {:?}", e))
                })?;
                let ast_eid = ast::Eid::new(uid.eid.as_str());
                let ast_uid = ast::EntityUID::from_components(ast_et, ast_eid, None);
                Ok(builder.val(ast_uid))
            }
        },
        Expr::Var(v) => Ok(builder.var(v.into())),
        Expr::Slot(_) => Err(PstConstructionError::NotImplemented("slots".to_string())),
        Expr::UnaryOp { op, expr } => {
            let inner = expr_to_ast(Arc::unwrap_or_clone(expr))?;
            Ok(match op {
                UnaryOp::Not => builder.not(inner),
                UnaryOp::Neg => builder.neg(inner),
                UnaryOp::IsEmpty => builder.is_empty(inner),
                // The other unary operators are extension functions.
                _ => match op.to_name() {
                    Some(fn_name) => builder.call_extension_fn(fn_name.clone(), vec![inner]),
                    None => Err(PstConstructionError::InvalidConversion(format!(
                        "unknown unary operator: {:?}",
                        op
                    )))?,
                },
            })
        }
        Expr::BinaryOp { op, left, right } => {
            let left_ast = expr_to_ast(Arc::unwrap_or_clone(left))?;
            let right_ast = expr_to_ast(Arc::unwrap_or_clone(right))?;

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
                    None => Err(PstConstructionError::InvalidConversion(format!(
                        "unknown binary operator: {:?}",
                        op
                    )))?,
                },
            })
        }
        Expr::Set(exprs) => {
            let ast_exprs: Result<Vec<_>, _> = exprs
                .into_iter()
                .map(|e| expr_to_ast(Arc::unwrap_or_clone(e)))
                .collect();
            Ok(builder.set(ast_exprs?))
        }
        Expr::IfThenElse {
            cond,
            then_expr,
            else_expr,
        } => Ok(builder.ite(
            expr_to_ast(Arc::unwrap_or_clone(cond))?,
            expr_to_ast(Arc::unwrap_or_clone(then_expr))?,
            expr_to_ast(Arc::unwrap_or_clone(else_expr))?,
        )),
        Expr::Is {
            expr,
            entity_type,
            in_expr: None,
        } => Ok(builder.is_entity_type(
            expr_to_ast(Arc::unwrap_or_clone(expr))?,
            entity_type
                .try_into()
                .map_err(|p| PstConstructionError::InvalidConversion(format!("{:?}", p)))?,
        )),
        Expr::Is {
            expr,
            entity_type,
            in_expr: Some(e),
        } => Ok(builder.is_in_entity_type(
            expr_to_ast(Arc::unwrap_or_clone(expr))?,
            entity_type
                .try_into()
                .map_err(|p| PstConstructionError::InvalidConversion(format!("{:?}", p)))?,
            expr_to_ast(Arc::unwrap_or_clone(e))?,
        )),
        Expr::GetAttr { expr, attr } => {
            Ok(builder.get_attr(expr_to_ast(Arc::unwrap_or_clone(expr))?, attr))
        }
        Expr::HasAttr { expr, attrs } => {
            Ok(builder.extended_has_attr(expr_to_ast(Arc::unwrap_or_clone(expr))?, &attrs))
        }
        Expr::Like { expr, pattern } => Ok(builder.like(
            expr_to_ast(Arc::unwrap_or_clone(expr))?,
            elements_into_ast_pattern(pattern),
        )),
        Expr::Record(elems) => builder
            .record(
                elems
                    .into_iter()
                    .map(|(k, v)| Ok((k.into(), expr_to_ast(Arc::unwrap_or_clone(v))?)))
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .map_err(|cstr_err| PstConstructionError::InvalidConversion(format!("{:?}", cstr_err))),
        Expr::Unknown { name } => Ok(builder.unknown(ast::Unknown {
            name,
            type_annotation: None,
        })),
        Expr::Error(ErrorNode { error: e }) => Err(PstConstructionError::ErrorNode(e.to_string())),
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
        let ast_et: ast::EntityType = value.ty.try_into().map_err(|e| {
            PstConstructionError::InvalidConversion(format!("Invalid entity type: {:?}", e))
        })?;
        let ast_eid = ast::Eid::new(value.eid.as_str());
        Ok(ast::EntityUID::from_components(ast_et, ast_eid, None))
    }
}

impl TryFrom<EntityOrSlot> for ast::EntityReference {
    type Error = PstConstructionError;

    fn try_from(eos: EntityOrSlot) -> Result<Self, Self::Error> {
        match eos {
            EntityOrSlot::Entity(uid) => Ok(ast::EntityReference::euid(Arc::new(uid.try_into()?))),
            EntityOrSlot::Slot(_) => Err(PstConstructionError::NotImplemented(
                "templates".to_string(),
            )),
        }
    }
}

impl From<ast::EntityType> for EntityType {
    fn from(et: ast::EntityType) -> Self {
        EntityType(et.into_name().into())
    }
}

impl TryFrom<EntityType> for ast::EntityType {
    type Error = crate::parser::err::ParseErrors;

    fn try_from(et: EntityType) -> Result<Self, Self::Error> {
        Ok(ast::EntityType::EntityType(et.0.try_into()?))
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
                Arc::try_unwrap(path)
                    .unwrap_or_else(|arc| (*arc).clone())
                    .into_iter()
                    .map(|id| id.to_smolstr())
                    .collect(),
            ),
        }
    }
}

impl TryFrom<Name> for ast::Name {
    type Error = crate::parser::err::ParseErrors;

    fn try_from(name: Name) -> Result<Self, Self::Error> {
        let basename = ast::Id::from_str(&name.id)?;
        let path: Vec<ast::Id> = name
            .namespace
            .iter()
            .map(|s| ast::Id::from_str(s.as_str()))
            .try_collect()?;
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

impl From<PatternElem> for ast::PatternElem {
    fn from(elem: PatternElem) -> Self {
        match elem {
            PatternElem::Char(c) => ast::PatternElem::Char(c),
            PatternElem::Wildcard => ast::PatternElem::Wildcard,
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

#[expect(clippy::fallible_impl_from, reason = "the unwrap cannot fail")]
impl From<ast::Expr> for Expr {
    fn from(ast_expr: ast::Expr) -> Self {
        use crate::expr_builder::ExprBuilder;
        let builder = PstBuilder::new();
        match ast_expr.into_expr_kind() {
            ast::ExprKind::Lit(lit) => builder.val(lit),
            ast::ExprKind::Var(v) => builder.var(v.into()),
            ast::ExprKind::Slot(s) => builder.slot(s),
            ast::ExprKind::Unknown(u) => builder.unknown(u),
            ast::ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => builder.ite(
                Arc::unwrap_or_clone(test_expr).into(),
                Arc::unwrap_or_clone(then_expr).into(),
                Arc::unwrap_or_clone(else_expr).into(),
            ),
            ast::ExprKind::And { left, right } => builder.and(
                Arc::unwrap_or_clone(left).into(),
                Arc::unwrap_or_clone(right).into(),
            ),
            ast::ExprKind::Or { left, right } => builder.or(
                Arc::unwrap_or_clone(left).into(),
                Arc::unwrap_or_clone(right).into(),
            ),
            ast::ExprKind::UnaryApp { op, arg } => match op {
                ast::UnaryOp::Not => builder.not(Arc::unwrap_or_clone(arg).into()),
                ast::UnaryOp::Neg => builder.neg(Arc::unwrap_or_clone(arg).into()),
                ast::UnaryOp::IsEmpty => builder.is_empty(Arc::unwrap_or_clone(arg).into()),
            },
            ast::ExprKind::BinaryApp { op, arg1, arg2 } => match op {
                ast::BinaryOp::Eq => builder.is_eq(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                ast::BinaryOp::Less => builder.less(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                ast::BinaryOp::LessEq => builder.lesseq(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                ast::BinaryOp::Add => builder.add(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                ast::BinaryOp::Sub => builder.sub(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                ast::BinaryOp::Mul => builder.mul(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                ast::BinaryOp::In => builder.is_in(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                ast::BinaryOp::Contains => builder.contains(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                ast::BinaryOp::ContainsAll => builder.contains_all(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                ast::BinaryOp::ContainsAny => builder.contains_any(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                ast::BinaryOp::GetTag => builder.get_tag(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
                ast::BinaryOp::HasTag => builder.has_tag(
                    Arc::unwrap_or_clone(arg1).into(),
                    Arc::unwrap_or_clone(arg2).into(),
                ),
            },
            ast::ExprKind::ExtensionFunctionApp { fn_name, args } => builder.call_extension_fn(
                fn_name,
                Arc::unwrap_or_clone(args).into_iter().map(|a| a.into()),
            ),
            ast::ExprKind::GetAttr { expr, attr } => {
                builder.get_attr(Arc::unwrap_or_clone(expr).into(), attr)
            }
            ast::ExprKind::HasAttr { expr, attr } => {
                builder.has_attr(Arc::unwrap_or_clone(expr).into(), attr)
            }
            ast::ExprKind::Like { expr, pattern } => {
                builder.like(Arc::unwrap_or_clone(expr).into(), pattern)
            }
            ast::ExprKind::Is { expr, entity_type } => {
                builder.is_entity_type(Arc::unwrap_or_clone(expr).into(), entity_type)
            }
            ast::ExprKind::Set(elems) => {
                builder.set(Arc::unwrap_or_clone(elems).into_iter().map(|e| e.into()))
            }
            ast::ExprKind::Record(map) =>
            {
                #[expect(
                    clippy::unwrap_used,
                    reason = "cannot have duplicate keys in this conversion"
                )]
                builder
                    .record(
                        Arc::unwrap_or_clone(map)
                            .into_iter()
                            .map(|(k, v)| (k, v.into())),
                    )
                    .unwrap()
            }
            #[cfg(feature = "tolerant-ast")]
            ast::ExprKind::Error {
                error_kind: ast::expr_allows_errors::AstExprErrorKind::InvalidExpr(e_str),
            } => Expr::Error(ErrorNode {
                error: PstConstructionError::InvalidExpression(e_str),
            }),
        }
    }
}
