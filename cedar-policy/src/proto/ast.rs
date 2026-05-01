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

#![allow(clippy::use_self, reason = "readability")]

use super::models;
use cedar_policy_core::{
    ast, evaluator::RestrictedEvaluator, extensions::Extensions, FromNormalizedStr,
};
use smol_str::ToSmolStr;
use std::{collections::HashSet, sync::Arc};

/// Error converting a protobuf model type into an AST type.
///
/// This indicates the protobuf message was well-formed at the wire level but
/// contained semantically invalid data (e.g. missing required fields, invalid
/// identifiers, unsupported features).
#[derive(Debug, thiserror::Error)]
#[error("error converting protobuf to AST: {0}")]
pub struct ProtoToAstError(pub(crate) String);

impl ProtoToAstError {
    pub(crate) fn missing(field: &str) -> Self {
        Self(format!("missing required field: `{field}`"))
    }
}

impl TryFrom<models::Name> for ast::InternalName {
    type Error = ProtoToAstError;
    fn try_from(v: models::Name) -> Result<Self, Self::Error> {
        let basename = ast::Id::from_normalized_str(&v.id)
            .map_err(|e| ProtoToAstError(format!("invalid basename `{}`: {e}", v.id)))?;
        let path = v
            .path
            .into_iter()
            .map(|id| {
                ast::Id::from_normalized_str(&id)
                    .map_err(|e| ProtoToAstError(format!("invalid path component `{id}`: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ast::InternalName::new(basename, path, None))
    }
}

impl TryFrom<models::Name> for ast::Name {
    type Error = ProtoToAstError;
    fn try_from(v: models::Name) -> Result<Self, Self::Error> {
        ast::Name::try_from(ast::InternalName::try_from(v)?)
            .map_err(|e| ProtoToAstError(format!("invalid name: {e}")))
    }
}

impl TryFrom<models::Name> for ast::EntityType {
    type Error = ProtoToAstError;
    fn try_from(v: models::Name) -> Result<Self, Self::Error> {
        Ok(ast::EntityType::from(ast::Name::try_from(v)?))
    }
}

impl From<&ast::InternalName> for models::Name {
    fn from(v: &ast::InternalName) -> Self {
        Self {
            id: v.basename().to_string(),
            path: v
                .namespace_components()
                .map(|id| String::from(id.as_ref()))
                .collect(),
        }
    }
}

impl From<&ast::Name> for models::Name {
    fn from(v: &ast::Name) -> Self {
        Self::from(v.as_ref())
    }
}

impl From<&ast::EntityType> for models::Name {
    fn from(v: &ast::EntityType) -> Self {
        Self::from(v.as_ref())
    }
}

impl TryFrom<models::EntityUid> for ast::EntityUID {
    type Error = ProtoToAstError;
    fn try_from(v: models::EntityUid) -> Result<Self, ProtoToAstError> {
        Ok(Self::from_components(
            ast::EntityType::try_from(v.ty.ok_or_else(|| ProtoToAstError::missing("ty"))?)?,
            ast::Eid::new(v.eid),
            None,
        ))
    }
}

impl From<&ast::EntityUID> for models::EntityUid {
    fn from(v: &ast::EntityUID) -> Self {
        Self {
            ty: Some(models::Name::from(v.entity_type())),
            eid: <ast::Eid as AsRef<str>>::as_ref(v.eid()).into(),
        }
    }
}

impl TryFrom<models::EntityUid> for ast::EntityUIDEntry {
    type Error = ProtoToAstError;
    fn try_from(v: models::EntityUid) -> Result<Self, Self::Error> {
        Ok(ast::EntityUIDEntry::known(
            ast::EntityUID::try_from(v)?,
            None,
        ))
    }
}

impl From<&ast::EntityUIDEntry> for models::EntityUid {
    #[expect(clippy::unimplemented, reason = "experimental feature")]
    fn from(v: &ast::EntityUIDEntry) -> Self {
        match v {
            ast::EntityUIDEntry::Unknown { .. } => {
                unimplemented!(
                    "Unknown EntityUID is not currently supported by the Protobuf interface"
                );
            }
            ast::EntityUIDEntry::Known { euid, .. } => models::EntityUid::from(euid.as_ref()),
        }
    }
}

impl TryFrom<models::Entity> for ast::Entity {
    type Error = ProtoToAstError;
    fn try_from(v: models::Entity) -> Result<Self, Self::Error> {
        let eval = RestrictedEvaluator::new(Extensions::none());

        let attrs = v
            .attrs
            .into_iter()
            .map(|(key, value)| {
                let expr = ast::Expr::try_from(value)?;
                let restricted = ast::BorrowedRestrictedExpr::new(&expr).map_err(|e| {
                    ProtoToAstError(format!("invalid restricted expr in attr `{key}`: {e}"))
                })?;
                let pval = eval.partial_interpret(restricted).map_err(|e| {
                    ProtoToAstError(format!("error interpreting attr `{key}`: {e}"))
                })?;
                Ok((key.into(), pval))
            })
            .collect::<Result<Vec<_>, ProtoToAstError>>()?;

        let ancestors = v
            .ancestors
            .into_iter()
            .map(ast::EntityUID::try_from)
            .collect::<Result<HashSet<_>, _>>()?;

        let tags = v
            .tags
            .into_iter()
            .map(|(key, value)| {
                let expr = ast::Expr::try_from(value)?;
                let restricted = ast::BorrowedRestrictedExpr::new(&expr).map_err(|e| {
                    ProtoToAstError(format!("invalid restricted expr in tag `{key}`: {e}"))
                })?;
                let pval = eval
                    .partial_interpret(restricted)
                    .map_err(|e| ProtoToAstError(format!("error interpreting tag `{key}`: {e}")))?;
                Ok((key.into(), pval))
            })
            .collect::<Result<Vec<_>, ProtoToAstError>>()?;

        Ok(Self::new_with_attr_partial_value(
            ast::EntityUID::try_from(v.uid.ok_or_else(|| ProtoToAstError::missing("uid"))?)?,
            attrs,
            HashSet::new(),
            ancestors,
            tags,
        ))
    }
}

impl From<&ast::Entity> for models::Entity {
    fn from(v: &ast::Entity) -> Self {
        Self {
            uid: Some(models::EntityUid::from(v.uid())),
            attrs: v
                .attrs()
                .map(|(key, value)| {
                    (
                        key.to_string(),
                        models::Expr::from(&ast::Expr::from(value.clone())),
                    )
                })
                .collect(),
            ancestors: v.ancestors().map(models::EntityUid::from).collect(),
            tags: v
                .tags()
                .map(|(key, value)| {
                    (
                        key.to_string(),
                        models::Expr::from(&ast::Expr::from(value.clone())),
                    )
                })
                .collect(),
        }
    }
}

impl From<&Arc<ast::Entity>> for models::Entity {
    fn from(v: &Arc<ast::Entity>) -> Self {
        Self::from(v.as_ref())
    }
}

impl TryFrom<models::Expr> for ast::Expr {
    type Error = ProtoToAstError;
    fn try_from(v: models::Expr) -> Result<Self, Self::Error> {
        let kind = v
            .expr_kind
            .ok_or_else(|| ProtoToAstError::missing("expr_kind"))?;

        match kind {
            models::expr::ExprKind::Lit(lit) => Ok(ast::Expr::val(ast::Literal::try_from(lit)?)),

            models::expr::ExprKind::Var(var) => {
                let pvar = models::expr::Var::try_from(var)
                    .map_err(|e| ProtoToAstError(format!("invalid var: {e}")))?;
                Ok(ast::Expr::var(ast::Var::from(pvar)))
            }

            models::expr::ExprKind::Slot(slot) => {
                let pslot = models::SlotId::try_from(slot)
                    .map_err(|e| ProtoToAstError(format!("invalid slot: {e}")))?;
                Ok(ast::Expr::slot(ast::SlotId::from(pslot)))
            }

            models::expr::ExprKind::If(msg) => {
                let test_expr = *msg
                    .test_expr
                    .ok_or_else(|| ProtoToAstError::missing("test_expr"))?;
                let then_expr = *msg
                    .then_expr
                    .ok_or_else(|| ProtoToAstError::missing("then_expr"))?;
                let else_expr = *msg
                    .else_expr
                    .ok_or_else(|| ProtoToAstError::missing("else_expr"))?;
                Ok(ast::Expr::ite(
                    ast::Expr::try_from(test_expr)?,
                    ast::Expr::try_from(then_expr)?,
                    ast::Expr::try_from(else_expr)?,
                ))
            }

            models::expr::ExprKind::And(msg) => {
                let left = *msg.left.ok_or_else(|| ProtoToAstError::missing("left"))?;
                let right = *msg.right.ok_or_else(|| ProtoToAstError::missing("right"))?;
                Ok(ast::Expr::and(
                    ast::Expr::try_from(left)?,
                    ast::Expr::try_from(right)?,
                ))
            }

            models::expr::ExprKind::Or(msg) => {
                let left = *msg.left.ok_or_else(|| ProtoToAstError::missing("left"))?;
                let right = *msg.right.ok_or_else(|| ProtoToAstError::missing("right"))?;
                Ok(ast::Expr::or(
                    ast::Expr::try_from(left)?,
                    ast::Expr::try_from(right)?,
                ))
            }

            models::expr::ExprKind::UApp(msg) => {
                let arg = *msg.expr.ok_or_else(|| ProtoToAstError::missing("expr"))?;
                let puop = models::expr::unary_app::Op::try_from(msg.op)
                    .map_err(|e| ProtoToAstError(format!("invalid unary op: {e}")))?;
                Ok(ast::Expr::unary_app(
                    ast::UnaryOp::from(puop),
                    ast::Expr::try_from(arg)?,
                ))
            }

            models::expr::ExprKind::BApp(msg) => {
                let pbop = models::expr::binary_app::Op::try_from(msg.op)
                    .map_err(|e| ProtoToAstError(format!("invalid binary op: {e}")))?;
                let left = *msg.left.ok_or_else(|| ProtoToAstError::missing("left"))?;
                let right = *msg.right.ok_or_else(|| ProtoToAstError::missing("right"))?;
                Ok(ast::Expr::binary_app(
                    ast::BinaryOp::from(pbop),
                    ast::Expr::try_from(left)?,
                    ast::Expr::try_from(right)?,
                ))
            }

            models::expr::ExprKind::ExtApp(msg) => Ok(ast::Expr::call_extension_fn(
                ast::Name::try_from(
                    msg.fn_name
                        .ok_or_else(|| ProtoToAstError::missing("fn_name"))?,
                )?,
                msg.args
                    .into_iter()
                    .map(ast::Expr::try_from)
                    .collect::<Result<_, _>>()?,
            )),

            models::expr::ExprKind::GetAttr(msg) => {
                let arg = *msg.expr.ok_or_else(|| ProtoToAstError::missing("expr"))?;
                Ok(ast::Expr::get_attr(
                    ast::Expr::try_from(arg)?,
                    msg.attr.into(),
                ))
            }

            models::expr::ExprKind::HasAttr(msg) => {
                let arg = *msg.expr.ok_or_else(|| ProtoToAstError::missing("expr"))?;
                Ok(ast::Expr::has_attr(
                    ast::Expr::try_from(arg)?,
                    msg.attr.into(),
                ))
            }

            models::expr::ExprKind::Like(msg) => {
                let arg = *msg.expr.ok_or_else(|| ProtoToAstError::missing("expr"))?;
                Ok(ast::Expr::like(
                    ast::Expr::try_from(arg)?,
                    msg.pattern
                        .into_iter()
                        .map(ast::PatternElem::try_from)
                        .collect::<Result<_, _>>()?,
                ))
            }

            models::expr::ExprKind::Is(msg) => {
                let arg = *msg.expr.ok_or_else(|| ProtoToAstError::missing("expr"))?;
                Ok(ast::Expr::is_entity_type(
                    ast::Expr::try_from(arg)?,
                    ast::EntityType::try_from(
                        msg.entity_type
                            .ok_or_else(|| ProtoToAstError::missing("entity_type"))?,
                    )?,
                ))
            }

            models::expr::ExprKind::Set(msg) => Ok(ast::Expr::set(
                msg.elements
                    .into_iter()
                    .map(ast::Expr::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            )),

            models::expr::ExprKind::Record(msg) => {
                let items = msg
                    .items
                    .into_iter()
                    .map(|(key, value)| Ok((key.into(), ast::Expr::try_from(value)?)))
                    .collect::<Result<Vec<_>, ProtoToAstError>>()?;
                ast::Expr::record(items)
                    .map_err(|e| ProtoToAstError(format!("invalid record: {e}")))
            }
        }
    }
}

impl From<&ast::Expr> for models::Expr {
    #[expect(
        clippy::unimplemented,
        clippy::too_many_lines,
        reason = "experimental feature"
    )]
    fn from(v: &ast::Expr) -> Self {
        let expr_kind = match v.expr_kind() {
            ast::ExprKind::Lit(l) => {
                models::expr::ExprKind::Lit(models::expr::Literal::from(l))
            }
            ast::ExprKind::Var(v) => {
                models::expr::ExprKind::Var(models::expr::Var::from(v).into())
            }
            ast::ExprKind::Slot(sid) => {
                models::expr::ExprKind::Slot(models::SlotId::from(sid).into())
            }

            ast::ExprKind::Unknown(_u) => {
                unimplemented!("Protobuffer interface does not support Unknown expressions")
            }
            ast::ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => models::expr::ExprKind::If(Box::new(models::expr::If {
                test_expr: Some(Box::new(models::Expr::from(test_expr.as_ref()))),
                then_expr: Some(Box::new(models::Expr::from(then_expr.as_ref()))),
                else_expr: Some(Box::new(models::Expr::from(else_expr.as_ref()))),
            })),
            ast::ExprKind::And { left, right } => {
                models::expr::ExprKind::And(Box::new(models::expr::And {
                    left: Some(Box::new(models::Expr::from(left.as_ref()))),
                    right: Some(Box::new(models::Expr::from(right.as_ref()))),
                }))
            }
            ast::ExprKind::Or { left, right } => {
                models::expr::ExprKind::Or(Box::new(models::expr::Or {
                    left: Some(Box::new(models::Expr::from(left.as_ref()))),
                    right: Some(Box::new(models::Expr::from(right.as_ref()))),
                }))
            }
            ast::ExprKind::UnaryApp { op, arg } => {
                models::expr::ExprKind::UApp(Box::new(models::expr::UnaryApp {
                    op: models::expr::unary_app::Op::from(op).into(),
                    expr: Some(Box::new(models::Expr::from(arg.as_ref()))),
                }))
            }
            ast::ExprKind::BinaryApp { op, arg1, arg2 } => {
                models::expr::ExprKind::BApp(Box::new(models::expr::BinaryApp {
                    op: models::expr::binary_app::Op::from(op).into(),
                    left: Some(Box::new(models::Expr::from(arg1.as_ref()))),
                    right: Some(Box::new(models::Expr::from(arg2.as_ref()))),
                }))
            }
            ast::ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let pargs: Vec<models::Expr> = args.iter().map(models::Expr::from).collect();
                models::expr::ExprKind::ExtApp(models::expr::ExtensionFunctionApp {
                    fn_name: Some(models::Name::from(fn_name)),
                    args: pargs,
                })
            }
            ast::ExprKind::GetAttr { expr, attr } => {
                models::expr::ExprKind::GetAttr(Box::new(models::expr::GetAttr {
                    attr: attr.to_string(),
                    expr: Some(Box::new(models::Expr::from(expr.as_ref()))),
                }))
            }
            ast::ExprKind::HasAttr { expr, attr } => {
                models::expr::ExprKind::HasAttr(Box::new(models::expr::HasAttr {
                    attr: attr.to_string(),
                    expr: Some(Box::new(models::Expr::from(expr.as_ref()))),
                }))
            }
            ast::ExprKind::Like { expr, pattern } => {
                let mut ppattern: Vec<models::expr::like::PatternElem> =
                    Vec::with_capacity(pattern.len());
                for value in pattern.iter() {
                    ppattern.push(models::expr::like::PatternElem::from(value));
                }
                models::expr::ExprKind::Like(Box::new(models::expr::Like {
                    expr: Some(Box::new(models::Expr::from(expr.as_ref()))),
                    pattern: ppattern,
                }))
            }
            ast::ExprKind::Is { expr, entity_type } => {
                models::expr::ExprKind::Is(Box::new(models::expr::Is {
                    expr: Some(Box::new(models::Expr::from(expr.as_ref()))),
                    entity_type: Some(models::Name::from(entity_type)),
                }))
            }
            ast::ExprKind::Set(args) => {
                let mut pargs: Vec<models::Expr> = Vec::with_capacity(args.as_ref().len());
                for arg in args.as_ref() {
                    pargs.push(models::Expr::from(arg));
                }
                models::expr::ExprKind::Set(models::expr::Set { elements: pargs })
            }
            ast::ExprKind::Record(record) => {
                let precord = record
                    .as_ref()
                    .iter()
                    .map(|(key, value)| (key.to_string(), models::Expr::from(value)))
                    .collect();
                models::expr::ExprKind::Record(models::expr::Record { items: precord })
            },
            #[cfg(feature="tolerant-ast")]
            ast::ExprKind::Error { .. } => unimplemented!("Protobufs feature not compatible with ASTs that contain error nodes - this should never happen"),
        };
        Self {
            expr_kind: Some(expr_kind),
        }
    }
}

impl From<&ast::Value> for models::Expr {
    fn from(v: &ast::Value) -> Self {
        (&ast::Expr::from(v.clone())).into()
    }
}

impl From<models::expr::Var> for ast::Var {
    fn from(v: models::expr::Var) -> Self {
        match v {
            models::expr::Var::Principal => ast::Var::Principal,
            models::expr::Var::Action => ast::Var::Action,
            models::expr::Var::Resource => ast::Var::Resource,
            models::expr::Var::Context => ast::Var::Context,
        }
    }
}

impl From<&ast::Var> for models::expr::Var {
    fn from(v: &ast::Var) -> Self {
        match v {
            ast::Var::Principal => models::expr::Var::Principal,
            ast::Var::Action => models::expr::Var::Action,
            ast::Var::Resource => models::expr::Var::Resource,
            ast::Var::Context => models::expr::Var::Context,
        }
    }
}

impl TryFrom<models::expr::Literal> for ast::Literal {
    type Error = ProtoToAstError;
    fn try_from(v: models::expr::Literal) -> Result<Self, Self::Error> {
        match v.lit.ok_or_else(|| ProtoToAstError::missing("lit"))? {
            models::expr::literal::Lit::B(b) => Ok(ast::Literal::Bool(b)),
            models::expr::literal::Lit::I(l) => Ok(ast::Literal::Long(l)),
            models::expr::literal::Lit::S(s) => Ok(ast::Literal::String(s.into())),
            models::expr::literal::Lit::Euid(e) => {
                Ok(ast::Literal::EntityUID(ast::EntityUID::try_from(e)?.into()))
            }
        }
    }
}

impl From<&ast::Literal> for models::expr::Literal {
    fn from(v: &ast::Literal) -> Self {
        match v {
            ast::Literal::Bool(b) => Self {
                lit: Some(models::expr::literal::Lit::B(*b)),
            },
            ast::Literal::Long(l) => Self {
                lit: Some(models::expr::literal::Lit::I(*l)),
            },
            ast::Literal::String(s) => Self {
                lit: Some(models::expr::literal::Lit::S(s.to_string())),
            },
            ast::Literal::EntityUID(euid) => Self {
                lit: Some(models::expr::literal::Lit::Euid(models::EntityUid::from(
                    euid.as_ref(),
                ))),
            },
        }
    }
}

impl From<models::SlotId> for ast::SlotId {
    fn from(v: models::SlotId) -> Self {
        match v {
            models::SlotId::Principal => ast::SlotId::principal(),
            models::SlotId::Resource => ast::SlotId::resource(),
        }
    }
}

#[expect(clippy::fallible_impl_from, reason = "experimental feature")]
impl From<&ast::SlotId> for models::SlotId {
    #[expect(clippy::panic, reason = "experimental feature")]
    fn from(v: &ast::SlotId) -> Self {
        if v.is_principal() {
            models::SlotId::Principal
        } else if v.is_resource() {
            models::SlotId::Resource
        } else {
            panic!("Slot other than principal or resource")
        }
    }
}

impl From<models::expr::unary_app::Op> for ast::UnaryOp {
    fn from(v: models::expr::unary_app::Op) -> Self {
        match v {
            models::expr::unary_app::Op::Not => ast::UnaryOp::Not,
            models::expr::unary_app::Op::Neg => ast::UnaryOp::Neg,
            models::expr::unary_app::Op::IsEmpty => ast::UnaryOp::IsEmpty,
        }
    }
}

impl From<&ast::UnaryOp> for models::expr::unary_app::Op {
    fn from(v: &ast::UnaryOp) -> Self {
        match v {
            ast::UnaryOp::Not => models::expr::unary_app::Op::Not,
            ast::UnaryOp::Neg => models::expr::unary_app::Op::Neg,
            ast::UnaryOp::IsEmpty => models::expr::unary_app::Op::IsEmpty,
        }
    }
}

impl From<models::expr::binary_app::Op> for ast::BinaryOp {
    fn from(v: models::expr::binary_app::Op) -> Self {
        match v {
            models::expr::binary_app::Op::Eq => ast::BinaryOp::Eq,
            models::expr::binary_app::Op::Less => ast::BinaryOp::Less,
            models::expr::binary_app::Op::LessEq => ast::BinaryOp::LessEq,
            models::expr::binary_app::Op::Add => ast::BinaryOp::Add,
            models::expr::binary_app::Op::Sub => ast::BinaryOp::Sub,
            models::expr::binary_app::Op::Mul => ast::BinaryOp::Mul,
            models::expr::binary_app::Op::In => ast::BinaryOp::In,
            models::expr::binary_app::Op::Contains => ast::BinaryOp::Contains,
            models::expr::binary_app::Op::ContainsAll => ast::BinaryOp::ContainsAll,
            models::expr::binary_app::Op::ContainsAny => ast::BinaryOp::ContainsAny,
            models::expr::binary_app::Op::GetTag => ast::BinaryOp::GetTag,
            models::expr::binary_app::Op::HasTag => ast::BinaryOp::HasTag,
        }
    }
}

impl From<&ast::BinaryOp> for models::expr::binary_app::Op {
    fn from(v: &ast::BinaryOp) -> Self {
        match v {
            ast::BinaryOp::Eq => models::expr::binary_app::Op::Eq,
            ast::BinaryOp::Less => models::expr::binary_app::Op::Less,
            ast::BinaryOp::LessEq => models::expr::binary_app::Op::LessEq,
            ast::BinaryOp::Add => models::expr::binary_app::Op::Add,
            ast::BinaryOp::Sub => models::expr::binary_app::Op::Sub,
            ast::BinaryOp::Mul => models::expr::binary_app::Op::Mul,
            ast::BinaryOp::In => models::expr::binary_app::Op::In,
            ast::BinaryOp::Contains => models::expr::binary_app::Op::Contains,
            ast::BinaryOp::ContainsAll => models::expr::binary_app::Op::ContainsAll,
            ast::BinaryOp::ContainsAny => models::expr::binary_app::Op::ContainsAny,
            ast::BinaryOp::GetTag => models::expr::binary_app::Op::GetTag,
            ast::BinaryOp::HasTag => models::expr::binary_app::Op::HasTag,
        }
    }
}

impl TryFrom<models::expr::like::PatternElem> for ast::PatternElem {
    type Error = ProtoToAstError;
    fn try_from(v: models::expr::like::PatternElem) -> Result<Self, Self::Error> {
        match v.data.ok_or_else(|| ProtoToAstError::missing("data"))? {
            models::expr::like::pattern_elem::Data::C(c) => {
                Ok(ast::PatternElem::Char(c.chars().next().ok_or_else(
                    || ProtoToAstError("empty char in pattern element".to_string()),
                )?))
            }
            models::expr::like::pattern_elem::Data::Wildcard(unit) => {
                match models::expr::like::pattern_elem::Wildcard::try_from(unit)
                    .map_err(|e| ProtoToAstError(format!("invalid wildcard: {e}")))?
                {
                    models::expr::like::pattern_elem::Wildcard::Unit => {
                        Ok(ast::PatternElem::Wildcard)
                    }
                }
            }
        }
    }
}

impl From<&ast::PatternElem> for models::expr::like::PatternElem {
    fn from(v: &ast::PatternElem) -> Self {
        match v {
            ast::PatternElem::Char(c) => Self {
                data: Some(models::expr::like::pattern_elem::Data::C(c.to_string())),
            },
            ast::PatternElem::Wildcard => Self {
                data: Some(models::expr::like::pattern_elem::Data::Wildcard(
                    models::expr::like::pattern_elem::Wildcard::Unit.into(),
                )),
            },
        }
    }
}

impl TryFrom<models::Request> for ast::Request {
    type Error = ProtoToAstError;
    fn try_from(v: models::Request) -> Result<Self, Self::Error> {
        Ok(ast::Request::new_unchecked(
            ast::EntityUIDEntry::try_from(
                v.principal
                    .ok_or_else(|| ProtoToAstError::missing("principal"))?,
            )?,
            ast::EntityUIDEntry::try_from(
                v.action.ok_or_else(|| ProtoToAstError::missing("action"))?,
            )?,
            ast::EntityUIDEntry::try_from(
                v.resource
                    .ok_or_else(|| ProtoToAstError::missing("resource"))?,
            )?,
            Some(
                ast::Context::from_pairs(
                    v.context
                        .into_iter()
                        .map(|(k, v)| {
                            let expr = ast::Expr::try_from(v)?;
                            let restricted = ast::RestrictedExpr::new(expr).map_err(|e| {
                                ProtoToAstError(format!(
                                    "invalid restricted expr in context key `{k}`: {e}"
                                ))
                            })?;
                            Ok((k.to_smolstr(), restricted))
                        })
                        .collect::<Result<Vec<_>, ProtoToAstError>>()?,
                    Extensions::all_available(),
                )
                .map_err(|e| ProtoToAstError(format!("invalid context: {e}")))?,
            ),
        ))
    }
}

impl From<&ast::Request> for models::Request {
    #[expect(clippy::expect_used, reason = "experimental feature")]
    fn from(v: &ast::Request) -> Self {
        Self {
            principal: Some(models::EntityUid::from(v.principal())),
            action: Some(models::EntityUid::from(v.action())),
            resource: Some(models::EntityUid::from(v.resource())),
            context: {
                let ctx = v.context().expect(
                    "Requests with unknown context currently cannot be modeled in protobuf",
                );
                match ctx {
                    ast::Context::Value(map) => map
                        .iter()
                        .map(|(k, v)| (k.to_string(), models::Expr::from(v)))
                        .collect(),
                    ast::Context::RestrictedResidual(map) => map
                        .iter()
                        .map(|(k, v)| (k.to_string(), models::Expr::from(v)))
                        .collect(),
                }
            },
        }
    }
}

impl TryFrom<models::Expr> for ast::Context {
    type Error = ProtoToAstError;
    fn try_from(v: models::Expr) -> Result<Self, Self::Error> {
        let expr = ast::Expr::try_from(v)?;
        let restricted = ast::BorrowedRestrictedExpr::new(&expr)
            .map_err(|e| ProtoToAstError(format!("invalid restricted expr in context: {e}")))?;
        ast::Context::from_expr(restricted, Extensions::none())
            .map_err(|e| ProtoToAstError(format!("invalid context: {e}")))
    }
}

impl From<&ast::Context> for models::Expr {
    fn from(v: &ast::Context) -> Self {
        models::Expr::from(&ast::Expr::from(ast::PartialValue::from(v.to_owned())))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn name_and_slot_roundtrip() {
        let orig_name = ast::Name::from_normalized_str("B::C::D").unwrap();
        assert_eq!(
            orig_name,
            ast::Name::try_from(models::Name::from(&orig_name)).unwrap()
        );

        let orig_slot1 = ast::SlotId::principal();
        assert_eq!(
            orig_slot1,
            ast::SlotId::from(models::SlotId::from(&orig_slot1))
        );

        let orig_slot2 = ast::SlotId::resource();
        assert_eq!(
            orig_slot2,
            ast::SlotId::from(models::SlotId::from(&orig_slot2))
        );
    }

    #[test]
    fn entity_roundtrip() {
        let name = ast::Name::from_normalized_str("B::C::D").unwrap();
        let ety_specified = ast::EntityType::from(name);
        assert_eq!(
            ety_specified,
            ast::EntityType::try_from(models::Name::from(&ety_specified)).unwrap()
        );

        let euid1 = ast::EntityUID::with_eid_and_type("A", "foo").unwrap();
        assert_eq!(
            euid1,
            ast::EntityUID::try_from(models::EntityUid::from(&euid1)).unwrap()
        );

        let euid2 = ast::EntityUID::from_normalized_str("Foo::Action::\"view\"").unwrap();
        assert_eq!(
            euid2,
            ast::EntityUID::try_from(models::EntityUid::from(&euid2)).unwrap()
        );

        let euid3 = ast::EntityUID::from_components(
            ast::EntityType::from_normalized_str("A").unwrap(),
            ast::Eid::new("\0\n \' \"+-$^!"),
            None,
        );
        assert_eq!(
            euid3,
            ast::EntityUID::try_from(models::EntityUid::from(&euid3)).unwrap()
        );

        let attrs = (1..=7).map(|id| (format!("{id}").into(), ast::RestrictedExpr::val(true)));
        let parent = ast::EntityUID::with_eid_and_type("Folder", "shared").unwrap();
        let entity = ast::Entity::new(
            r#"Foo::"bar""#.parse().unwrap(),
            attrs,
            HashSet::from([parent.clone()]),
            HashSet::new(),
            [],
            Extensions::none(),
        )
        .unwrap();
        assert_eq!(
            entity,
            ast::Entity::try_from(models::Entity::from(&entity)).unwrap()
        );
        assert!(ast::Entity::try_from(models::Entity::from(&entity))
            .unwrap()
            .is_child_of(&parent));
    }

    #[test]
    fn entity_tags_roundtrip() {
        let tags = [
            ("foo".into(), ast::RestrictedExpr::val(1)),
            ("bar".into(), ast::RestrictedExpr::val("baz")),
        ];
        let entity = ast::Entity::new(
            r#"Foo::"bar""#.parse().unwrap(),
            [],
            HashSet::new(),
            HashSet::new(),
            tags,
            Extensions::none(),
        )
        .unwrap();
        assert_eq!(
            entity,
            ast::Entity::try_from(models::Entity::from(&entity)).unwrap()
        );
    }

    #[test]
    fn expr_roundtrip() {
        let e1 = ast::Expr::val(33);
        assert_eq!(e1, ast::Expr::try_from(models::Expr::from(&e1)).unwrap());
        let e2 = ast::Expr::val("hello");
        assert_eq!(e2, ast::Expr::try_from(models::Expr::from(&e2)).unwrap());
        let e3 = ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "foo").unwrap());
        assert_eq!(e3, ast::Expr::try_from(models::Expr::from(&e3)).unwrap());
        let e4 = ast::Expr::var(ast::Var::Principal);
        assert_eq!(e4, ast::Expr::try_from(models::Expr::from(&e4)).unwrap());
        let e4 = ast::Expr::var(ast::Var::Action);
        assert_eq!(e4, ast::Expr::try_from(models::Expr::from(&e4)).unwrap());
        let e4 = ast::Expr::var(ast::Var::Resource);
        assert_eq!(e4, ast::Expr::try_from(models::Expr::from(&e4)).unwrap());
        let e4 = ast::Expr::var(ast::Var::Context);
        assert_eq!(e4, ast::Expr::try_from(models::Expr::from(&e4)).unwrap());
        let e5 = ast::Expr::ite(
            ast::Expr::val(true),
            ast::Expr::val(88),
            ast::Expr::val(-100),
        );
        assert_eq!(e5, ast::Expr::try_from(models::Expr::from(&e5)).unwrap());
        let e6 = ast::Expr::not(ast::Expr::val(false));
        assert_eq!(e6, ast::Expr::try_from(models::Expr::from(&e6)).unwrap());
        let e7 = ast::Expr::get_attr(
            ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "foo").unwrap()),
            "some_attr".into(),
        );
        assert_eq!(e7, ast::Expr::try_from(models::Expr::from(&e7)).unwrap());
        let e8 = ast::Expr::has_attr(
            ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "foo").unwrap()),
            "some_attr".into(),
        );
        assert_eq!(e8, ast::Expr::try_from(models::Expr::from(&e8)).unwrap());
        let e9 = ast::Expr::is_entity_type(
            ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "foo").unwrap()),
            "Type".parse().unwrap(),
        );
        assert_eq!(e9, ast::Expr::try_from(models::Expr::from(&e9)).unwrap());
        let e10 = ast::Expr::slot(ast::SlotId::principal());
        assert_eq!(e10, ast::Expr::try_from(models::Expr::from(&e10)).unwrap());
        let e11 = ast::Expr::slot(ast::SlotId::resource());
        assert_eq!(e11, ast::Expr::try_from(models::Expr::from(&e11)).unwrap());
        let e12 = ast::Expr::and(ast::Expr::val(false), ast::Expr::not(ast::Expr::val(true)));
        assert_eq!(e12, ast::Expr::try_from(models::Expr::from(&e12)).unwrap());
        let e13 = ast::Expr::or(
            ast::Expr::ite(
                ast::Expr::get_attr(ast::Expr::var(ast::Var::Context), "a".into()),
                ast::Expr::val(false),
                ast::Expr::not(ast::Expr::val(true)),
            ),
            ast::Expr::greater(ast::Expr::val(33), ast::Expr::val(-33)),
        );
        assert_eq!(e13, ast::Expr::try_from(models::Expr::from(&e13)).unwrap());
        let e14 = ast::Expr::contains(
            ast::Expr::set([ast::Expr::val("beans"), ast::Expr::val("carrots")]),
            ast::Expr::val("peas"),
        );
        assert_eq!(e14, ast::Expr::try_from(models::Expr::from(&e14)).unwrap());
        let e: ast::Expr = r#"ip("0.0.0.0").isInRange(ip("0.0.0.0"))"#.parse().unwrap();
        assert_eq!(e, ast::Expr::try_from(models::Expr::from(&e)).unwrap());
        let e: ast::Expr = r#"principal.foo like "bar*""#.parse().unwrap();
        assert_eq!(e, ast::Expr::try_from(models::Expr::from(&e)).unwrap());
        let e: ast::Expr = r#"principal.foo.isEmpty()"#.parse().unwrap();
        assert_eq!(e, ast::Expr::try_from(models::Expr::from(&e)).unwrap());
        let e: ast::Expr = r#"- principal.foo"#.parse().unwrap();
        assert_eq!(e, ast::Expr::try_from(models::Expr::from(&e)).unwrap());
    }

    #[test]
    fn literal_roundtrip() {
        let bool_literal_f = ast::Literal::from(false);
        assert_eq!(
            bool_literal_f,
            ast::Literal::try_from(models::expr::Literal::from(&bool_literal_f)).unwrap()
        );

        let bool_literal_t = ast::Literal::from(true);
        assert_eq!(
            bool_literal_t,
            ast::Literal::try_from(models::expr::Literal::from(&bool_literal_t)).unwrap()
        );

        let long_literal0 = ast::Literal::from(0);
        assert_eq!(
            long_literal0,
            ast::Literal::try_from(models::expr::Literal::from(&long_literal0)).unwrap()
        );

        let long_literal1 = ast::Literal::from(1);
        assert_eq!(
            long_literal1,
            ast::Literal::try_from(models::expr::Literal::from(&long_literal1)).unwrap()
        );

        let str_literal0 = ast::Literal::from("");
        assert_eq!(
            str_literal0,
            ast::Literal::try_from(models::expr::Literal::from(&str_literal0)).unwrap()
        );

        let str_literal1 = ast::Literal::from("foo");
        assert_eq!(
            str_literal1,
            ast::Literal::try_from(models::expr::Literal::from(&str_literal1)).unwrap()
        );

        let euid_literal =
            ast::Literal::from(ast::EntityUID::with_eid_and_type("A", "foo").unwrap());
        assert_eq!(
            euid_literal,
            ast::Literal::try_from(models::expr::Literal::from(&euid_literal)).unwrap()
        );
    }

    #[test]
    fn request_roundtrip() {
        let context = ast::Context::from_expr(
            ast::RestrictedExpr::record([("foo".into(), ast::RestrictedExpr::val(37))])
                .expect("Error creating restricted record.")
                .as_borrowed(),
            Extensions::none(),
        )
        .expect("Error creating context");
        let request = ast::Request::new_unchecked(
            ast::EntityUIDEntry::Known {
                euid: Arc::new(ast::EntityUID::with_eid_and_type("User", "andrew").unwrap()),
                loc: None,
            },
            ast::EntityUIDEntry::Known {
                euid: Arc::new(ast::EntityUID::with_eid_and_type("Action", "read").unwrap()),
                loc: None,
            },
            ast::EntityUIDEntry::Known {
                euid: Arc::new(
                    ast::EntityUID::with_eid_and_type("Book", "tale of two cities").unwrap(),
                ),
                loc: None,
            },
            Some(context.clone()),
        );
        let request_rt = ast::Request::try_from(models::Request::from(&request)).unwrap();
        assert_eq!(
            context,
            ast::Context::try_from(models::Expr::from(&context)).unwrap()
        );
        assert_eq!(request.principal().uid(), request_rt.principal().uid());
        assert_eq!(request.action().uid(), request_rt.action().uid());
        assert_eq!(request.resource().uid(), request_rt.resource().uid());
    }
}
