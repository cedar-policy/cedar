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

use super::constraints::{ActionConstraint, EntityOrSlot, PrincipalConstraint, ResourceConstraint};
use super::expr::{BinaryOp, EntityUID, Expr, Literal, PatternElem, UnaryOp, Var};
use super::policy::{Clause, Effect, Policy};
use crate::ast;
use std::sync::Arc;

/// Error type for PST to AST conversions
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConversionError {
    /// Invalid conversion with description
    #[error("Invalid conversion: {0}")]
    InvalidConversion(String),
    /// Conversion steps not yet implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

fn elements_into_ast_pattern(elems: impl IntoIterator<Item = PatternElem>) -> ast::Pattern {
    let elems = elems.into_iter().map(|elem| match elem {
        PatternElem::Char(c) => ast::PatternElem::Char(c),
        PatternElem::Wildcard => ast::PatternElem::Wildcard,
    });
    ast::Pattern::from_iter(elems)
}

// Helper to convert PST Expr to AST Expr using the AST builder
fn expr_to_ast(expr: impl AsRef<Expr>) -> Result<ast::Expr, ConversionError> {
    use crate::expr_builder::ExprBuilder;
    let builder = ast::ExprBuilder::<()>::new();

    match expr.as_ref() {
        Expr::Literal(lit) => match lit {
            Literal::Bool(b) => Ok(builder.val(*b)),
            Literal::Long(i) => Ok(builder.val(*i)),
            Literal::String(s) => Ok(builder.val(s.as_str())),
            Literal::EntityUID(uid) => {
                // Convert PST EntityUID to AST EntityUID using existing TryFrom impl
                let ast_et: ast::EntityType = uid.ty.clone().try_into().map_err(|e| {
                    ConversionError::InvalidConversion(format!("Invalid entity type: {:?}", e))
                })?;
                let ast_eid = ast::Eid::new(uid.eid.as_str());
                let ast_uid = ast::EntityUID::from_components(ast_et, ast_eid, None);
                Ok(builder.val(ast_uid))
            }
        },
        Expr::Var(v) => {
            let ast_var = match v {
                Var::Principal => ast::Var::Principal,
                Var::Action => ast::Var::Action,
                Var::Resource => ast::Var::Resource,
                Var::Context => ast::Var::Context,
            };
            Ok(builder.var(ast_var))
        }
        Expr::Slot(_) => Err(ConversionError::NotImplemented("slots".to_string())),
        Expr::UnaryOp { op, expr } => {
            let inner = expr_to_ast(expr.clone())?;
            Ok(match op {
                UnaryOp::Not => builder.not(inner),
                UnaryOp::Neg => builder.neg(inner),
                UnaryOp::IsEmpty => builder.is_empty(inner),
                _ => builder.call_extension_fn(op.to_name().clone(), vec![inner]),
            })
        }
        Expr::BinaryOp { op, left, right } => {
            let left_ast = expr_to_ast(left.clone())?;
            let right_ast = expr_to_ast(right.clone())?;

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
                _ => builder.call_extension_fn(op.to_name().clone(), vec![left_ast, right_ast]),
            })
        }
        Expr::Set(exprs) => {
            let ast_exprs: Result<Vec<_>, _> =
                exprs.into_iter().map(|e| expr_to_ast(e.clone())).collect();
            Ok(builder.set(ast_exprs?))
        }
        Expr::IfThenElse {
            cond,
            then_expr,
            else_expr,
        } => Ok(builder.ite(
            expr_to_ast(cond.clone())?,
            expr_to_ast(then_expr.clone())?,
            expr_to_ast(else_expr.clone())?,
        )),
        Expr::Is {
            expr,
            entity_type,
            in_expr: None,
        } => Ok(builder.is_entity_type(
            expr_to_ast(expr.clone())?,
            entity_type
                .clone()
                .try_into()
                .map_err(|p| ConversionError::InvalidConversion(format!("{:?}", p)))?,
        )),
        Expr::Is {
            expr,
            entity_type,
            in_expr: Some(e),
        } => Ok(builder.is_in_entity_type(
            expr_to_ast(expr.clone())?,
            entity_type
                .clone()
                .try_into()
                .map_err(|p| ConversionError::InvalidConversion(format!("{:?}", p)))?,
            expr_to_ast(e.clone())?,
        )),
        Expr::GetAttr { expr, attr } => {
            Ok(builder.get_attr(expr_to_ast(expr.clone())?, attr.clone()))
        }
        Expr::HasAttr { expr, attrs } => {
            Ok(builder.extended_has_attr(expr_to_ast(expr.clone())?, attrs))
        }
        Expr::Like { expr, pattern } => Ok(builder.like(
            expr_to_ast(expr.clone())?,
            elements_into_ast_pattern(pattern.clone()),
        )),
        Expr::Record(elems) => builder
            .record(
                elems
                    .into_iter()
                    .map(|(k, v)| Ok((k.into(), expr_to_ast(v)?)))
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .map_err(|cstr_err| ConversionError::InvalidConversion(format!("{:?}", cstr_err))),
        Expr::Unknown { name } => Ok(builder.unknown(ast::Unknown {
            name: name.clone(),
            type_annotation: None,
        })),
        Expr::Error(_) => todo!(),
    }
}

impl TryFrom<Effect> for ast::Effect {
    type Error = ConversionError;

    fn try_from(effect: Effect) -> Result<Self, Self::Error> {
        match effect {
            Effect::Permit => Ok(ast::Effect::Permit),
            Effect::Forbid => Ok(ast::Effect::Forbid),
        }
    }
}

impl TryFrom<EntityUID> for ast::EntityUID {
    type Error = ConversionError;

    fn try_from(value: EntityUID) -> Result<Self, ConversionError> {
        let ast_et: ast::EntityType = value.ty.try_into().map_err(|e| {
            ConversionError::InvalidConversion(format!("Invalid entity type: {:?}", e))
        })?;
        let ast_eid = ast::Eid::new(value.eid.as_str());
        Ok(ast::EntityUID::from_components(ast_et, ast_eid, None))
    }
}

impl TryFrom<EntityOrSlot> for ast::EntityReference {
    type Error = ConversionError;

    fn try_from(eos: EntityOrSlot) -> Result<Self, Self::Error> {
        match eos {
            EntityOrSlot::Entity(uid) => Ok(ast::EntityReference::euid(Arc::new(uid.try_into()?))),
            EntityOrSlot::Slot(_) => Err(ConversionError::NotImplemented("templates".to_string())),
        }
    }
}

impl TryFrom<PrincipalConstraint> for ast::PrincipalConstraint {
    type Error = ConversionError;

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
                    ConversionError::InvalidConversion(format!("Invalid entity type: {:?}", e))
                })?;
                Ok(ast::PrincipalConstraint::is_entity_type(Arc::new(ast_et)))
            }
            PrincipalConstraint::IsIn(entity_type, EntityOrSlot::Entity(eos)) => {
                let ast_et: ast::EntityType = entity_type.try_into().map_err(|e| {
                    ConversionError::InvalidConversion(format!("Invalid entity type: {:?}", e))
                })?;
                Ok(ast::PrincipalConstraint::is_entity_type_in(
                    Arc::new(ast_et),
                    Arc::new(eos.try_into()?),
                ))
            }
            _ => Err(ConversionError::NotImplemented("templates".into())),
        }
    }
}

impl TryFrom<ResourceConstraint> for ast::ResourceConstraint {
    type Error = ConversionError;

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
                    ConversionError::InvalidConversion(format!("Invalid entity type: {:?}", e))
                })?;
                Ok(ast::ResourceConstraint::is_entity_type(Arc::new(ast_et)))
            }
            ResourceConstraint::IsIn(entity_type, EntityOrSlot::Entity(eos)) => {
                let ast_et: ast::EntityType = entity_type.try_into().map_err(|e| {
                    ConversionError::InvalidConversion(format!("Invalid entity type: {:?}", e))
                })?;
                Ok(ast::ResourceConstraint::is_entity_type_in(
                    Arc::new(ast_et),
                    Arc::new(eos.try_into()?),
                ))
            }
            _ => Err(ConversionError::NotImplemented("templates".into())),
        }
    }
}

impl TryFrom<ActionConstraint> for ast::ActionConstraint {
    type Error = ConversionError;

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

impl TryFrom<Policy> for ast::Policy {
    type Error = ConversionError;

    fn try_from(policy: Policy) -> Result<Self, Self::Error> {
        // Convert to Template first, then to Policy (following EST pattern)
        let template: ast::Template = policy.try_into()?;
        ast::StaticPolicy::try_from(template)
            .map(Into::into)
            .map_err(|e| {
                ConversionError::InvalidConversion(format!(
                    "Failed to convert template to static policy: {:?}",
                    e
                ))
            })
    }
}

impl TryFrom<Policy> for ast::Template {
    type Error = ConversionError;

    fn try_from(policy: Policy) -> Result<Self, Self::Error> {
        use crate::expr_builder::ExprBuilder;
        let id = policy.id.into();
        let effect: ast::Effect = policy.effect.try_into()?;
        let principal: ast::PrincipalConstraint = policy.principal.try_into()?;
        let action: ast::ActionConstraint = policy.action.try_into()?;
        let resource: ast::ResourceConstraint = policy.resource.try_into()?;
        // Convert clauses - fold them into a single expression (following EST pattern)
        let builder = ast::ExprBuilder::<()>::new();
        let mut conds_rev_iter = policy
            .clauses
            .into_iter()
            .map(|clause| match clause {
                Clause::When(expr) => expr_to_ast(expr.clone()),
                Clause::Unless(expr) => Ok(builder.clone().not(expr_to_ast(expr.clone())?)),
            })
            .rev()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter();

        let conditions = if let Some(last_expr) = conds_rev_iter.next() {
            Some(conds_rev_iter.fold(last_expr, |acc, prev| builder.clone().and(prev, acc)))
        } else {
            None
        };

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
