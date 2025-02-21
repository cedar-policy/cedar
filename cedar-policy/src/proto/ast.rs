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

#![allow(clippy::use_self)]

use super::models;
use cedar_policy_core::{
    ast, evaluator::RestrictedEvaluator, extensions::Extensions, FromNormalizedStr,
};
use smol_str::SmolStr;
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

impl From<&models::Annotation> for ast::Annotation {
    fn from(v: &models::Annotation) -> Self {
        Self {
            val: v.val.clone().into(),
            loc: None,
        }
    }
}

impl From<&ast::Annotation> for models::Annotation {
    fn from(v: &ast::Annotation) -> Self {
        Self {
            val: v.val.to_string(),
        }
    }
}

// PANIC SAFETY: experimental feature
#[allow(clippy::fallible_impl_from)]
impl From<&models::Name> for ast::InternalName {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::unwrap_used)]
    fn from(v: &models::Name) -> Self {
        let basename = ast::Id::from_normalized_str(&v.id).unwrap();
        let path = v
            .path
            .iter()
            .map(|id| ast::Id::from_normalized_str(id).unwrap());
        ast::InternalName::new(basename, path, None)
    }
}

// PANIC SAFETY: experimental feature
#[allow(clippy::fallible_impl_from)]
impl From<&models::Name> for ast::Name {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::unwrap_used)]
    fn from(v: &models::Name) -> Self {
        ast::Name::try_from(ast::InternalName::from(v)).unwrap()
    }
}

impl From<&models::Name> for ast::EntityType {
    fn from(v: &models::Name) -> Self {
        ast::EntityType::from(ast::Name::from(v))
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

impl From<&models::EntityType> for ast::Name {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used, clippy::fallible_impl_from)]
    fn from(v: &models::EntityType) -> Self {
        Self::from(v.name.as_ref().expect("name field should exist"))
    }
}

impl From<&models::EntityType> for ast::EntityType {
    fn from(v: &models::EntityType) -> Self {
        Self::from(ast::Name::from(v))
    }
}

impl From<&ast::EntityType> for models::EntityType {
    fn from(v: &ast::EntityType) -> Self {
        Self {
            name: Some(models::Name::from(v.name())),
        }
    }
}

impl From<&models::EntityUid> for ast::EntityUID {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::EntityUid) -> Self {
        Self::from_components(
            ast::EntityType::from(v.ty.as_ref().expect("ty field should exist")),
            ast::Eid::new(v.eid.clone()),
            None,
        )
    }
}

impl From<&ast::EntityUID> for models::EntityUid {
    fn from(v: &ast::EntityUID) -> Self {
        Self {
            ty: Some(models::EntityType::from(v.entity_type())),
            eid: <ast::Eid as AsRef<str>>::as_ref(v.eid()).into(),
        }
    }
}

impl From<&models::EntityUidEntry> for ast::EntityUIDEntry {
    fn from(v: &models::EntityUidEntry) -> Self {
        // PANIC SAFETY: experimental feature
        #[allow(clippy::expect_used)]
        ast::EntityUIDEntry::known(
            ast::EntityUID::from(v.euid.as_ref().expect("euid field should exist")),
            None,
        )
    }
}

impl From<&ast::EntityUIDEntry> for models::EntityUidEntry {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::unimplemented)]
    fn from(v: &ast::EntityUIDEntry) -> Self {
        match v {
            ast::EntityUIDEntry::Unknown { .. } => {
                unimplemented!(
                    "Unknown EntityUID is not currently supported by the Protobuf interface"
                );
            }
            ast::EntityUIDEntry::Known { euid, .. } => Self {
                euid: Some(models::EntityUid::from(euid.as_ref())),
            },
        }
    }
}

impl From<&models::Entity> for ast::Entity {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn from(v: &models::Entity) -> Self {
        let eval = RestrictedEvaluator::new(Extensions::none());

        let attrs: BTreeMap<SmolStr, ast::PartialValueSerializedAsExpr> = v
            .attrs
            .iter()
            .map(|(key, value)| {
                let pval = eval
                    .partial_interpret(
                        ast::BorrowedRestrictedExpr::new(&ast::Expr::from(value)).unwrap(),
                    )
                    .expect("interpret on RestrictedExpr");
                (key.into(), pval.into())
            })
            .collect();

        let ancestors: HashSet<ast::EntityUID> =
            v.ancestors.iter().map(ast::EntityUID::from).collect();

        let tags: BTreeMap<SmolStr, ast::PartialValueSerializedAsExpr> = v
            .tags
            .iter()
            .map(|(key, value)| {
                let pval = eval
                    .partial_interpret(
                        ast::BorrowedRestrictedExpr::new(&ast::Expr::from(value))
                            .expect("RestrictedExpr"),
                    )
                    .expect("interpret on RestrictedExpr");
                (key.into(), pval.into())
            })
            .collect();

        Self::new_with_attr_partial_value_serialized_as_expr(
            ast::EntityUID::from(v.uid.as_ref().expect("uid field should exist")),
            attrs,
            ancestors,
            HashSet::new(),
            tags,
        )
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

impl From<&models::Expr> for ast::Expr {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used, clippy::too_many_lines)]
    fn from(v: &models::Expr) -> Self {
        let pdata = v.expr_kind.as_ref().expect("expr_kind field should exist");
        let ety = pdata.data.as_ref().expect("data field should exist");

        match ety {
            models::expr::expr_kind::Data::Lit(lit) => ast::Expr::val(ast::Literal::from(lit)),

            models::expr::expr_kind::Data::Var(var) => {
                let pvar =
                    models::expr::Var::try_from(var.to_owned()).expect("decode should succeed");
                ast::Expr::var(ast::Var::from(&pvar))
            }

            models::expr::expr_kind::Data::Slot(slot) => {
                let pslot =
                    models::SlotId::try_from(slot.to_owned()).expect("decode should succeed");
                ast::Expr::slot(ast::SlotId::from(&pslot))
            }

            models::expr::expr_kind::Data::If(msg) => {
                let test_expr = msg
                    .test_expr
                    .as_ref()
                    .expect("test_expr field should exist")
                    .as_ref();
                let then_expr = msg
                    .then_expr
                    .as_ref()
                    .expect("then_expr field should exist")
                    .as_ref();
                let else_expr = msg
                    .else_expr
                    .as_ref()
                    .expect("else_expr field should exist")
                    .as_ref();
                ast::Expr::ite(
                    ast::Expr::from(test_expr),
                    ast::Expr::from(then_expr),
                    ast::Expr::from(else_expr),
                )
            }

            models::expr::expr_kind::Data::And(msg) => {
                let left = msg.left.as_ref().expect("left field should exist").as_ref();
                let right = msg
                    .right
                    .as_ref()
                    .expect("right field should exist")
                    .as_ref();
                ast::Expr::and(ast::Expr::from(left), ast::Expr::from(right))
            }

            models::expr::expr_kind::Data::Or(msg) => {
                let left = msg.left.as_ref().expect("left field should exist").as_ref();
                let right = msg
                    .right
                    .as_ref()
                    .expect("right field should exist")
                    .as_ref();
                ast::Expr::or(ast::Expr::from(left), ast::Expr::from(right))
            }

            models::expr::expr_kind::Data::UApp(msg) => {
                let arg = msg.expr.as_ref().expect("expr field should exist").as_ref();
                let puop =
                    models::expr::unary_app::Op::try_from(msg.op).expect("decode should succeed");
                ast::Expr::unary_app(ast::UnaryOp::from(&puop), ast::Expr::from(arg))
            }

            models::expr::expr_kind::Data::BApp(msg) => {
                let pbop =
                    models::expr::binary_app::Op::try_from(msg.op).expect("decode should succeed");
                let left = msg.left.as_ref().expect("left field should exist");
                let right = msg.right.as_ref().expect("right field should exist");
                ast::Expr::binary_app(
                    ast::BinaryOp::from(&pbop),
                    ast::Expr::from(left.as_ref()),
                    ast::Expr::from(right.as_ref()),
                )
            }

            models::expr::expr_kind::Data::ExtApp(msg) => ast::Expr::call_extension_fn(
                ast::Name::from(msg.fn_name.as_ref().expect("fn_name field should exist")),
                msg.args.iter().map(ast::Expr::from).collect(),
            ),

            models::expr::expr_kind::Data::GetAttr(msg) => {
                let arg = msg.expr.as_ref().expect("expr field should exist").as_ref();
                ast::Expr::get_attr(ast::Expr::from(arg), msg.attr.clone().into())
            }

            models::expr::expr_kind::Data::HasAttr(msg) => {
                let arg = msg.expr.as_ref().expect("expr field should exist").as_ref();
                ast::Expr::has_attr(ast::Expr::from(arg), msg.attr.clone().into())
            }

            models::expr::expr_kind::Data::Like(msg) => {
                let arg = msg.expr.as_ref().expect("expr field should exist").as_ref();
                ast::Expr::like(
                    ast::Expr::from(arg),
                    msg.pattern.iter().map(ast::PatternElem::from).collect(),
                )
            }

            models::expr::expr_kind::Data::Is(msg) => {
                let arg = msg.expr.as_ref().expect("expr field should exist").as_ref();
                ast::Expr::is_entity_type(
                    ast::Expr::from(arg),
                    ast::EntityType::from(
                        msg.entity_type
                            .as_ref()
                            .expect("entity_type field should exist"),
                    ),
                )
            }

            models::expr::expr_kind::Data::Set(msg) => {
                ast::Expr::set(msg.elements.iter().map(ast::Expr::from))
            }

            models::expr::expr_kind::Data::Record(msg) => ast::Expr::record(
                msg.items
                    .iter()
                    .map(|(key, value)| (key.into(), ast::Expr::from(value))),
            )
            .expect("Expr should be valid"),
        }
    }
}

impl From<&ast::Expr> for models::Expr {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::unimplemented, clippy::too_many_lines)]
    fn from(v: &ast::Expr) -> Self {
        let expr_kind = match v.expr_kind() {
            ast::ExprKind::Lit(l) => {
                models::expr::expr_kind::Data::Lit(models::expr::Literal::from(l))
            }
            ast::ExprKind::Var(v) => {
                models::expr::expr_kind::Data::Var(models::expr::Var::from(v).into())
            }
            ast::ExprKind::Slot(sid) => {
                models::expr::expr_kind::Data::Slot(models::SlotId::from(sid).into())
            }

            ast::ExprKind::Unknown(_u) => {
                unimplemented!("Protobuffer interface does not support Unknown expressions")
            }
            ast::ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => models::expr::expr_kind::Data::If(Box::new(models::expr::If {
                test_expr: Some(Box::new(models::Expr::from(test_expr.as_ref()))),
                then_expr: Some(Box::new(models::Expr::from(then_expr.as_ref()))),
                else_expr: Some(Box::new(models::Expr::from(else_expr.as_ref()))),
            })),
            ast::ExprKind::And { left, right } => {
                models::expr::expr_kind::Data::And(Box::new(models::expr::And {
                    left: Some(Box::new(models::Expr::from(left.as_ref()))),
                    right: Some(Box::new(models::Expr::from(right.as_ref()))),
                }))
            }
            ast::ExprKind::Or { left, right } => {
                models::expr::expr_kind::Data::Or(Box::new(models::expr::Or {
                    left: Some(Box::new(models::Expr::from(left.as_ref()))),
                    right: Some(Box::new(models::Expr::from(right.as_ref()))),
                }))
            }
            ast::ExprKind::UnaryApp { op, arg } => {
                models::expr::expr_kind::Data::UApp(Box::new(models::expr::UnaryApp {
                    op: models::expr::unary_app::Op::from(op).into(),
                    expr: Some(Box::new(models::Expr::from(arg.as_ref()))),
                }))
            }
            ast::ExprKind::BinaryApp { op, arg1, arg2 } => {
                models::expr::expr_kind::Data::BApp(Box::new(models::expr::BinaryApp {
                    op: models::expr::binary_app::Op::from(op).into(),
                    left: Some(Box::new(models::Expr::from(arg1.as_ref()))),
                    right: Some(Box::new(models::Expr::from(arg2.as_ref()))),
                }))
            }
            ast::ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let pargs: Vec<models::Expr> = args.iter().map(models::Expr::from).collect();
                models::expr::expr_kind::Data::ExtApp(models::expr::ExtensionFunctionApp {
                    fn_name: Some(models::Name::from(fn_name)),
                    args: pargs,
                })
            }
            ast::ExprKind::GetAttr { expr, attr } => {
                models::expr::expr_kind::Data::GetAttr(Box::new(models::expr::GetAttr {
                    attr: attr.to_string(),
                    expr: Some(Box::new(models::Expr::from(expr.as_ref()))),
                }))
            }
            ast::ExprKind::HasAttr { expr, attr } => {
                models::expr::expr_kind::Data::HasAttr(Box::new(models::expr::HasAttr {
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
                models::expr::expr_kind::Data::Like(Box::new(models::expr::Like {
                    expr: Some(Box::new(models::Expr::from(expr.as_ref()))),
                    pattern: ppattern,
                }))
            }
            ast::ExprKind::Is { expr, entity_type } => {
                models::expr::expr_kind::Data::Is(Box::new(models::expr::Is {
                    expr: Some(Box::new(models::Expr::from(expr.as_ref()))),
                    entity_type: Some(models::EntityType::from(entity_type)),
                }))
            }
            ast::ExprKind::Set(args) => {
                let mut pargs: Vec<models::Expr> = Vec::with_capacity(args.as_ref().len());
                for arg in args.as_ref() {
                    pargs.push(models::Expr::from(arg));
                }
                models::expr::expr_kind::Data::Set(models::expr::Set { elements: pargs })
            }
            ast::ExprKind::Record(record) => {
                let precord = record
                    .as_ref()
                    .iter()
                    .map(|(key, value)| (key.to_string(), models::Expr::from(value)))
                    .collect();
                models::expr::expr_kind::Data::Record(models::expr::Record { items: precord })
            },
            #[cfg(feature="tolerant-ast")]
            ast::ExprKind::Error { .. } => unimplemented!("Protobufs feature not compatible with ASTs that contain error nodes - this should never happen"),
        };
        Self {
            expr_kind: Some(Box::new(models::expr::ExprKind {
                data: Some(expr_kind),
            })),
        }
    }
}

impl From<&models::expr::Var> for ast::Var {
    fn from(v: &models::expr::Var) -> Self {
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

impl From<&models::expr::Literal> for ast::Literal {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::expr::Literal) -> Self {
        match v.lit.as_ref().expect("lit field should exist") {
            models::expr::literal::Lit::B(b) => ast::Literal::Bool(*b),
            models::expr::literal::Lit::I(l) => ast::Literal::Long(*l),
            models::expr::literal::Lit::S(s) => ast::Literal::String(s.clone().into()),
            models::expr::literal::Lit::Euid(e) => {
                ast::Literal::EntityUID(ast::EntityUID::from(e).into())
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

impl From<&models::SlotId> for ast::SlotId {
    fn from(v: &models::SlotId) -> Self {
        match v {
            models::SlotId::Principal => ast::SlotId::principal(),
            models::SlotId::Resource => ast::SlotId::resource(),
        }
    }
}

// PANIC SAFETY: experimental feature
#[allow(clippy::fallible_impl_from)]
impl From<&ast::SlotId> for models::SlotId {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::panic)]
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

impl From<&models::expr::unary_app::Op> for ast::UnaryOp {
    fn from(v: &models::expr::unary_app::Op) -> Self {
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

impl From<&models::expr::binary_app::Op> for ast::BinaryOp {
    fn from(v: &models::expr::binary_app::Op) -> Self {
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

impl From<&models::expr::like::PatternElem> for ast::PatternElem {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::expr::like::PatternElem) -> Self {
        match v.data.as_ref().expect("data field should exist") {
            models::expr::like::pattern_elem::Data::C(c) => {
                ast::PatternElem::Char(c.chars().next().expect("c is non-empty"))
            }

            models::expr::like::pattern_elem::Data::Ty(ty) => {
                match models::expr::like::pattern_elem::Ty::try_from(ty.to_owned())
                    .expect("decode should succeed")
                {
                    models::expr::like::pattern_elem::Ty::Wildcard => ast::PatternElem::Wildcard,
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
                data: Some(models::expr::like::pattern_elem::Data::Ty(
                    models::expr::like::pattern_elem::Ty::Wildcard.into(),
                )),
            },
        }
    }
}

impl From<&models::Request> for ast::Request {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::Request) -> Self {
        ast::Request::new_unchecked(
            ast::EntityUIDEntry::from(v.principal.as_ref().expect("principal.as_ref()")),
            ast::EntityUIDEntry::from(v.action.as_ref().expect("action.as_ref()")),
            ast::EntityUIDEntry::from(v.resource.as_ref().expect("resource.as_ref()")),
            v.context.as_ref().map(ast::Context::from),
        )
    }
}

impl From<&ast::Request> for models::Request {
    fn from(v: &ast::Request) -> Self {
        Self {
            principal: Some(models::EntityUidEntry::from(v.principal())),
            action: Some(models::EntityUidEntry::from(v.action())),
            resource: Some(models::EntityUidEntry::from(v.resource())),
            context: v.context().map(models::Context::from),
        }
    }
}

impl From<&models::Context> for ast::Context {
    fn from(v: &models::Context) -> Self {
        // PANIC SAFETY: experimental feature
        #[allow(clippy::expect_used)]
        ast::Context::from_expr(
            ast::BorrowedRestrictedExpr::new(&ast::Expr::from(
                v.context.as_ref().expect("context.as_ref()"),
            ))
            .expect("Expr::from"),
            Extensions::none(),
        )
        .expect("Context::from_expr")
    }
}

impl From<&ast::Context> for models::Context {
    fn from(v: &ast::Context) -> Self {
        Self {
            context: Some(models::Expr::from(&ast::Expr::from(
                ast::PartialValue::from(v.to_owned()),
            ))),
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn entity_roundtrip() {
        let name = ast::Name::from_normalized_str("B::C::D").unwrap();
        let ety_specified = ast::EntityType::from(name);
        assert_eq!(
            ety_specified,
            ast::EntityType::from(&models::EntityType::from(&ety_specified))
        );

        let euid1 = ast::EntityUID::with_eid_and_type("A", "foo").unwrap();
        assert_eq!(
            euid1,
            ast::EntityUID::from(&models::EntityUid::from(&euid1))
        );

        let euid2 = ast::EntityUID::from_normalized_str("Foo::Action::\"view\"").unwrap();
        assert_eq!(
            euid2,
            ast::EntityUID::from(&models::EntityUid::from(&euid2))
        );

        let euid3 = ast::EntityUID::from_components(
            ast::EntityType::from_normalized_str("A").unwrap(),
            ast::Eid::new("\0\n \' \"+-$^!"),
            None,
        );
        assert_eq!(
            euid3,
            ast::EntityUID::from(&models::EntityUid::from(&euid3))
        );

        let attrs = (1..=7)
            .map(|id| (format!("{id}").into(), ast::RestrictedExpr::val(true)))
            .collect::<HashMap<SmolStr, _>>();
        let entity = ast::Entity::new(
            r#"Foo::"bar""#.parse().unwrap(),
            attrs,
            HashSet::new(),
            HashSet::new(),
            BTreeMap::new(),
            Extensions::none(),
        )
        .unwrap();
        assert_eq!(entity, ast::Entity::from(&models::Entity::from(&entity)));
    }

    #[test]
    fn expr_roundtrip() {
        let e1 = ast::Expr::val(33);
        assert_eq!(e1, ast::Expr::from(&models::Expr::from(&e1)));
        let e2 = ast::Expr::val("hello");
        assert_eq!(e2, ast::Expr::from(&models::Expr::from(&e2)));
        let e3 = ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "foo").unwrap());
        assert_eq!(e3, ast::Expr::from(&models::Expr::from(&e3)));
        let e4 = ast::Expr::var(ast::Var::Principal);
        assert_eq!(e4, ast::Expr::from(&models::Expr::from(&e4)));
        let e5 = ast::Expr::ite(
            ast::Expr::val(true),
            ast::Expr::val(88),
            ast::Expr::val(-100),
        );
        assert_eq!(e5, ast::Expr::from(&models::Expr::from(&e5)));
        let e6 = ast::Expr::not(ast::Expr::val(false));
        assert_eq!(e6, ast::Expr::from(&models::Expr::from(&e6)));
        let e7 = ast::Expr::get_attr(
            ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "foo").unwrap()),
            "some_attr".into(),
        );
        assert_eq!(e7, ast::Expr::from(&models::Expr::from(&e7)));
        let e8 = ast::Expr::has_attr(
            ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "foo").unwrap()),
            "some_attr".into(),
        );
        assert_eq!(e8, ast::Expr::from(&models::Expr::from(&e8)));
        let e9 = ast::Expr::is_entity_type(
            ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "foo").unwrap()),
            "Type".parse().unwrap(),
        );
        assert_eq!(e9, ast::Expr::from(&models::Expr::from(&e9)));
    }

    #[test]
    fn literal_roundtrip() {
        let bool_literal_f = ast::Literal::from(false);
        assert_eq!(
            bool_literal_f,
            ast::Literal::from(&models::expr::Literal::from(&bool_literal_f))
        );

        let bool_literal_t = ast::Literal::from(true);
        assert_eq!(
            bool_literal_t,
            ast::Literal::from(&models::expr::Literal::from(&bool_literal_t))
        );

        let long_literal0 = ast::Literal::from(0);
        assert_eq!(
            long_literal0,
            ast::Literal::from(&models::expr::Literal::from(&long_literal0))
        );

        let long_literal1 = ast::Literal::from(1);
        assert_eq!(
            long_literal1,
            ast::Literal::from(&models::expr::Literal::from(&long_literal1))
        );

        let str_literal0 = ast::Literal::from("");
        assert_eq!(
            str_literal0,
            ast::Literal::from(&models::expr::Literal::from(&str_literal0))
        );

        let str_literal1 = ast::Literal::from("foo");
        assert_eq!(
            str_literal1,
            ast::Literal::from(&models::expr::Literal::from(&str_literal1))
        );

        let euid_literal =
            ast::Literal::from(ast::EntityUID::with_eid_and_type("A", "foo").unwrap());
        assert_eq!(
            euid_literal,
            ast::Literal::from(&models::expr::Literal::from(&euid_literal))
        );
    }

    #[test]
    fn name_and_slot_roundtrip() {
        let orig_name = ast::Name::from_normalized_str("B::C::D").unwrap();
        assert_eq!(orig_name, ast::Name::from(&models::Name::from(&orig_name)));

        let orig_slot1 = ast::SlotId::principal();
        assert_eq!(
            orig_slot1,
            ast::SlotId::from(&models::SlotId::from(&orig_slot1))
        );

        let orig_slot2 = ast::SlotId::resource();
        assert_eq!(
            orig_slot2,
            ast::SlotId::from(&models::SlotId::from(&orig_slot2))
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
        let request_rt = ast::Request::from(&models::Request::from(&request));
        assert_eq!(
            context,
            ast::Context::from(&models::Context::from(&context))
        );
        assert_eq!(request.principal().uid(), request_rt.principal().uid());
        assert_eq!(request.action().uid(), request_rt.action().uid());
        assert_eq!(request.resource().uid(), request_rt.resource().uid());
    }
}
