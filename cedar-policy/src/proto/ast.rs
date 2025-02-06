use super::*;
use cedar_policy_core::{
    ast, evaluator::RestrictedEvaluator, extensions::Extensions, FromNormalizedStr,
};
use smol_str::SmolStr;
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

impl From<&Annotation> for ast::Annotation {
    fn from(v: &Annotation) -> Self {
        Self {
            val: v.val.clone().into(),
            loc: None,
        }
    }
}

impl From<&ast::Annotation> for Annotation {
    fn from(v: &ast::Annotation) -> Self {
        Self {
            val: v.val.to_string(),
        }
    }
}

impl From<&Name> for ast::InternalName {
    fn from(v: &Name) -> Self {
        let basename = ast::Id::from_normalized_str(&v.id).unwrap();
        let path = v
            .path
            .iter()
            .map(|id| ast::Id::from_normalized_str(id).unwrap());
        ast::InternalName::new(basename, path, None)
    }
}

impl From<&Name> for ast::Name {
    fn from(v: &Name) -> Self {
        ast::Name::try_from(ast::InternalName::from(v)).unwrap()
    }
}

impl From<&ast::Name> for Name {
    fn from(v: &ast::Name) -> Self {
        Self {
            id: v.basename().to_string(),
            path: v
                .as_ref()
                .namespace_components()
                .map(|id| String::from(id.as_ref()))
                .collect(),
        }
    }
}

impl From<&EntityType> for ast::Name {
    fn from(v: &EntityType) -> Self {
        Self::from(v.name.as_ref().expect("name field should exist"))
    }
}

impl From<&EntityType> for ast::EntityType {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &EntityType) -> Self {
        Self::from(ast::Name::from(v))
    }
}

impl From<&ast::EntityType> for EntityType {
    fn from(v: &ast::EntityType) -> Self {
        Self {
            name: Some(Name::from(v.name())),
        }
    }
}

impl From<&EntityUid> for ast::EntityUID {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &EntityUid) -> Self {
        Self::from_components(
            ast::EntityType::from(v.ty.as_ref().expect("ty field should exist")),
            ast::Eid::new(v.eid.clone()),
            None,
        )
    }
}

impl From<&ast::EntityUID> for EntityUid {
    fn from(v: &ast::EntityUID) -> Self {
        Self {
            ty: Some(EntityType::from(v.entity_type())),
            eid: v.eid().escaped().into(),
        }
    }
}

impl From<&EntityUidEntry> for ast::EntityUIDEntry {
    fn from(v: &EntityUidEntry) -> Self {
        // PANIC SAFETY: experimental feature
        #[allow(clippy::expect_used)]
        ast::EntityUIDEntry::known(
            ast::EntityUID::from(v.euid.as_ref().expect("euid field should exist")),
            None,
        )
    }
}

impl From<&ast::EntityUIDEntry> for EntityUidEntry {
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
                euid: Some(EntityUid::from(euid.as_ref())),
            },
        }
    }
}

impl From<&Entity> for ast::Entity {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &Entity) -> Self {
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
            tags,
        )
    }
}

impl From<&ast::Entity> for Entity {
    fn from(v: &ast::Entity) -> Self {
        Self {
            uid: Some(EntityUid::from(v.uid())),
            attrs: v
                .attrs()
                .map(|(key, value)| (key.to_string(), Expr::from(&ast::Expr::from(value.clone()))))
                .collect(),
            ancestors: v.ancestors().map(EntityUid::from).collect(),
            tags: v
                .tags()
                .map(|(key, value)| {
                    (
                        key.to_string(),
                        Expr::from(&ast::Expr::from(ast::PartialValue::from(value.clone()))),
                    )
                })
                .collect(),
        }
    }
}

impl From<&Arc<ast::Entity>> for Entity {
    fn from(v: &Arc<ast::Entity>) -> Self {
        Self::from(v.as_ref())
    }
}

impl From<&Expr> for ast::Expr {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &Expr) -> Self {
        let pdata = v.expr_kind.as_ref().expect("expr_kind field should exist");
        let ety = pdata.data.as_ref().expect("data field should exist");

        match ety {
            expr::expr_kind::Data::Lit(lit) => ast::Expr::val(ast::Literal::from(lit)),

            expr::expr_kind::Data::Var(var) => {
                let pvar = expr::Var::try_from(var.to_owned()).expect("decode should succeed");
                ast::Expr::var(ast::Var::from(&pvar))
            }

            expr::expr_kind::Data::Slot(slot) => {
                let pslot = SlotId::try_from(slot.to_owned()).expect("decode should succeed");
                ast::Expr::slot(ast::SlotId::from(&pslot))
            }

            expr::expr_kind::Data::If(msg) => {
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

            expr::expr_kind::Data::And(msg) => {
                let left = msg.left.as_ref().expect("left field should exist").as_ref();
                let right = msg
                    .right
                    .as_ref()
                    .expect("right field should exist")
                    .as_ref();
                ast::Expr::and(ast::Expr::from(left), ast::Expr::from(right))
            }

            expr::expr_kind::Data::Or(msg) => {
                let left = msg.left.as_ref().expect("left field should exist").as_ref();
                let right = msg
                    .right
                    .as_ref()
                    .expect("right field should exist")
                    .as_ref();
                ast::Expr::or(ast::Expr::from(left), ast::Expr::from(right))
            }

            expr::expr_kind::Data::UApp(msg) => {
                let arg = msg.expr.as_ref().expect("expr field should exist").as_ref();
                let puop = expr::unary_app::Op::try_from(msg.op).expect("decode should succeed");
                ast::Expr::unary_app(ast::UnaryOp::from(&puop), ast::Expr::from(arg))
            }

            expr::expr_kind::Data::BApp(msg) => {
                let pbop = expr::binary_app::Op::try_from(msg.op).expect("decode should succeed");
                let left = msg.left.as_ref().expect("left field should exist");
                let right = msg.right.as_ref().expect("right field should exist");
                ast::Expr::binary_app(
                    ast::BinaryOp::from(&pbop),
                    ast::Expr::from(left.as_ref()),
                    ast::Expr::from(right.as_ref()),
                )
            }

            expr::expr_kind::Data::ExtApp(msg) => ast::Expr::call_extension_fn(
                ast::Name::from(msg.fn_name.as_ref().expect("fn_name field should exist")),
                msg.args.iter().map(ast::Expr::from).collect(),
            ),

            expr::expr_kind::Data::GetAttr(msg) => {
                let arg = msg.expr.as_ref().expect("expr field should exist").as_ref();
                ast::Expr::get_attr(ast::Expr::from(arg), msg.attr.clone().into())
            }

            expr::expr_kind::Data::HasAttr(msg) => {
                let arg = msg.expr.as_ref().expect("expr field should exist").as_ref();
                ast::Expr::has_attr(ast::Expr::from(arg), msg.attr.clone().into())
            }

            expr::expr_kind::Data::Like(msg) => {
                let arg = msg.expr.as_ref().expect("expr field should exist").as_ref();
                ast::Expr::like(
                    ast::Expr::from(arg),
                    msg.pattern.iter().map(ast::PatternElem::from).collect(),
                )
            }

            expr::expr_kind::Data::Is(msg) => {
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

            expr::expr_kind::Data::Set(msg) => {
                ast::Expr::set(msg.elements.iter().map(ast::Expr::from))
            }

            expr::expr_kind::Data::Record(msg) => ast::Expr::record(
                msg.items
                    .iter()
                    .map(|(key, value)| (key.into(), ast::Expr::from(value))),
            )
            .expect("Expr should be valid"),
        }
    }
}

impl From<&ast::Expr> for Expr {
    // PANIC SAFETY: experimental feature
    fn from(v: &ast::Expr) -> Self {
        let expr_kind = match v.expr_kind() {
            ast::ExprKind::Lit(l) => expr::expr_kind::Data::Lit(expr::Literal::from(l)),
            ast::ExprKind::Var(v) => expr::expr_kind::Data::Var(expr::Var::from(v).into()),
            ast::ExprKind::Slot(sid) => expr::expr_kind::Data::Slot(SlotId::from(sid).into()),

            ast::ExprKind::Unknown(_u) => {
                unimplemented!("Protobuffer interface does not support Unknown expressions")
            }
            ast::ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => expr::expr_kind::Data::If(Box::new(expr::If {
                test_expr: Some(Box::new(Expr::from(test_expr.as_ref()))),
                then_expr: Some(Box::new(Expr::from(then_expr.as_ref()))),
                else_expr: Some(Box::new(Expr::from(else_expr.as_ref()))),
            })),
            ast::ExprKind::And { left, right } => expr::expr_kind::Data::And(Box::new(expr::And {
                left: Some(Box::new(Expr::from(left.as_ref()))),
                right: Some(Box::new(Expr::from(right.as_ref()))),
            })),
            ast::ExprKind::Or { left, right } => expr::expr_kind::Data::Or(Box::new(expr::Or {
                left: Some(Box::new(Expr::from(left.as_ref()))),
                right: Some(Box::new(Expr::from(right.as_ref()))),
            })),
            ast::ExprKind::UnaryApp { op, arg } => {
                expr::expr_kind::Data::UApp(Box::new(expr::UnaryApp {
                    op: expr::unary_app::Op::from(op).into(),
                    expr: Some(Box::new(Expr::from(arg.as_ref()))),
                }))
            }
            ast::ExprKind::BinaryApp { op, arg1, arg2 } => {
                expr::expr_kind::Data::BApp(Box::new(expr::BinaryApp {
                    op: expr::binary_app::Op::from(op).into(),
                    left: Some(Box::new(Expr::from(arg1.as_ref()))),
                    right: Some(Box::new(Expr::from(arg2.as_ref()))),
                }))
            }
            ast::ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let pargs: Vec<Expr> = args.iter().map(Expr::from).collect();
                expr::expr_kind::Data::ExtApp(expr::ExtensionFunctionApp {
                    fn_name: Some(Name::from(fn_name)),
                    args: pargs,
                })
            }
            ast::ExprKind::GetAttr { expr, attr } => {
                expr::expr_kind::Data::GetAttr(Box::new(expr::GetAttr {
                    attr: attr.to_string(),
                    expr: Some(Box::new(Expr::from(expr.as_ref()))),
                }))
            }
            ast::ExprKind::HasAttr { expr, attr } => {
                expr::expr_kind::Data::HasAttr(Box::new(expr::HasAttr {
                    attr: attr.to_string(),
                    expr: Some(Box::new(Expr::from(expr.as_ref()))),
                }))
            }
            ast::ExprKind::Like { expr, pattern } => {
                let mut ppattern: Vec<expr::like::PatternElem> = Vec::with_capacity(pattern.len());
                for value in pattern.iter() {
                    ppattern.push(expr::like::PatternElem::from(value));
                }
                expr::expr_kind::Data::Like(Box::new(expr::Like {
                    expr: Some(Box::new(Expr::from(expr.as_ref()))),
                    pattern: ppattern,
                }))
            }
            ast::ExprKind::Is { expr, entity_type } => {
                expr::expr_kind::Data::Is(Box::new(expr::Is {
                    expr: Some(Box::new(Expr::from(expr.as_ref()))),
                    entity_type: Some(EntityType::from(entity_type)),
                }))
            }
            ast::ExprKind::Set(args) => {
                let mut pargs: Vec<Expr> = Vec::with_capacity(args.as_ref().len());
                for arg in args.as_ref() {
                    pargs.push(Expr::from(arg));
                }
                expr::expr_kind::Data::Set(expr::Set { elements: pargs })
            }
            ast::ExprKind::Record(record) => {
                let precord = record
                    .as_ref()
                    .iter()
                    .map(|(key, value)| (key.to_string(), Expr::from(value)))
                    .collect();
                expr::expr_kind::Data::Record(expr::Record { items: precord })
            }
        };
        Self {
            expr_kind: Some(Box::new(expr::ExprKind {
                data: Some(expr_kind),
            })),
        }
    }
}

impl From<&expr::Var> for ast::Var {
    fn from(v: &expr::Var) -> Self {
        match v {
            expr::Var::Principal => ast::Var::Principal,
            expr::Var::Action => ast::Var::Action,
            expr::Var::Resource => ast::Var::Resource,
            expr::Var::Context => ast::Var::Context,
        }
    }
}

impl From<&ast::Var> for expr::Var {
    fn from(v: &ast::Var) -> Self {
        match v {
            ast::Var::Principal => expr::Var::Principal,
            ast::Var::Action => expr::Var::Action,
            ast::Var::Resource => expr::Var::Resource,
            ast::Var::Context => expr::Var::Context,
        }
    }
}

impl From<&expr::Literal> for ast::Literal {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &expr::Literal) -> Self {
        match v.lit.as_ref().expect("lit field should exist") {
            expr::literal::Lit::B(b) => ast::Literal::Bool(*b),
            expr::literal::Lit::I(l) => ast::Literal::Long(*l),
            expr::literal::Lit::S(s) => ast::Literal::String(s.clone().into()),
            expr::literal::Lit::Euid(e) => ast::Literal::EntityUID(ast::EntityUID::from(e).into()),
        }
    }
}

impl From<&ast::Literal> for expr::Literal {
    fn from(v: &ast::Literal) -> Self {
        match v {
            ast::Literal::Bool(b) => Self {
                lit: Some(expr::literal::Lit::B(*b)),
            },
            ast::Literal::Long(l) => Self {
                lit: Some(expr::literal::Lit::I(*l)),
            },
            ast::Literal::String(s) => Self {
                lit: Some(expr::literal::Lit::S(s.to_string())),
            },
            ast::Literal::EntityUID(euid) => Self {
                lit: Some(expr::literal::Lit::Euid(EntityUid::from(euid.as_ref()))),
            },
        }
    }
}

impl From<&SlotId> for ast::SlotId {
    fn from(v: &SlotId) -> Self {
        match v {
            SlotId::Principal => ast::SlotId::principal(),
            SlotId::Resource => ast::SlotId::resource(),
        }
    }
}

impl From<&ast::SlotId> for SlotId {
    fn from(v: &ast::SlotId) -> Self {
        if v.is_principal() {
            SlotId::Principal
        } else if v.is_resource() {
            SlotId::Resource
        } else {
            panic!("Slot other than principal or resource")
        }
    }
}

impl From<&expr::unary_app::Op> for ast::UnaryOp {
    fn from(v: &expr::unary_app::Op) -> Self {
        match v {
            expr::unary_app::Op::Not => ast::UnaryOp::Not,
            expr::unary_app::Op::Neg => ast::UnaryOp::Neg,
            expr::unary_app::Op::IsEmpty => ast::UnaryOp::IsEmpty,
        }
    }
}

impl From<&ast::UnaryOp> for expr::unary_app::Op {
    fn from(v: &ast::UnaryOp) -> Self {
        match v {
            ast::UnaryOp::Not => expr::unary_app::Op::Not,
            ast::UnaryOp::Neg => expr::unary_app::Op::Neg,
            ast::UnaryOp::IsEmpty => expr::unary_app::Op::IsEmpty,
        }
    }
}

impl From<&expr::binary_app::Op> for ast::BinaryOp {
    fn from(v: &expr::binary_app::Op) -> Self {
        match v {
            expr::binary_app::Op::Eq => ast::BinaryOp::Eq,
            expr::binary_app::Op::Less => ast::BinaryOp::Less,
            expr::binary_app::Op::LessEq => ast::BinaryOp::LessEq,
            expr::binary_app::Op::Add => ast::BinaryOp::Add,
            expr::binary_app::Op::Sub => ast::BinaryOp::Sub,
            expr::binary_app::Op::Mul => ast::BinaryOp::Mul,
            expr::binary_app::Op::In => ast::BinaryOp::In,
            expr::binary_app::Op::Contains => ast::BinaryOp::Contains,
            expr::binary_app::Op::ContainsAll => ast::BinaryOp::ContainsAll,
            expr::binary_app::Op::ContainsAny => ast::BinaryOp::ContainsAny,
            expr::binary_app::Op::GetTag => ast::BinaryOp::GetTag,
            expr::binary_app::Op::HasTag => ast::BinaryOp::HasTag,
        }
    }
}

impl From<&ast::BinaryOp> for expr::binary_app::Op {
    fn from(v: &ast::BinaryOp) -> Self {
        match v {
            ast::BinaryOp::Eq => expr::binary_app::Op::Eq,
            ast::BinaryOp::Less => expr::binary_app::Op::Less,
            ast::BinaryOp::LessEq => expr::binary_app::Op::LessEq,
            ast::BinaryOp::Add => expr::binary_app::Op::Add,
            ast::BinaryOp::Sub => expr::binary_app::Op::Sub,
            ast::BinaryOp::Mul => expr::binary_app::Op::Mul,
            ast::BinaryOp::In => expr::binary_app::Op::In,
            ast::BinaryOp::Contains => expr::binary_app::Op::Contains,
            ast::BinaryOp::ContainsAll => expr::binary_app::Op::ContainsAll,
            ast::BinaryOp::ContainsAny => expr::binary_app::Op::ContainsAny,
            ast::BinaryOp::GetTag => expr::binary_app::Op::GetTag,
            ast::BinaryOp::HasTag => expr::binary_app::Op::HasTag,
        }
    }
}

impl From<&expr::like::PatternElem> for ast::PatternElem {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &expr::like::PatternElem) -> Self {
        match v.data.as_ref().expect("data field should exist") {
            expr::like::pattern_elem::Data::C(c) => {
                ast::PatternElem::Char(c.chars().next().expect("c is non-empty"))
            }

            expr::like::pattern_elem::Data::Ty(ty) => {
                match expr::like::pattern_elem::Ty::try_from(ty.to_owned())
                    .expect("decode should succeed")
                {
                    expr::like::pattern_elem::Ty::Wildcard => ast::PatternElem::Wildcard,
                }
            }
        }
    }
}

impl From<&ast::PatternElem> for expr::like::PatternElem {
    fn from(v: &ast::PatternElem) -> Self {
        match v {
            ast::PatternElem::Char(c) => Self {
                data: Some(expr::like::pattern_elem::Data::C(c.to_string())),
            },
            ast::PatternElem::Wildcard => Self {
                data: Some(expr::like::pattern_elem::Data::Ty(
                    expr::like::pattern_elem::Ty::Wildcard.into(),
                )),
            },
        }
    }
}

impl From<&Request> for ast::Request {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &Request) -> Self {
        ast::Request::new_unchecked(
            ast::EntityUIDEntry::from(v.principal.as_ref().expect("principal.as_ref()")),
            ast::EntityUIDEntry::from(v.action.as_ref().expect("action.as_ref()")),
            ast::EntityUIDEntry::from(v.resource.as_ref().expect("resource.as_ref()")),
            v.context.as_ref().map(ast::Context::from),
        )
    }
}

impl From<&ast::Request> for Request {
    fn from(v: &ast::Request) -> Self {
        Self {
            principal: Some(EntityUidEntry::from(v.principal())),
            action: Some(EntityUidEntry::from(v.action())),
            resource: Some(EntityUidEntry::from(v.resource())),
            context: v.context().map(Context::from),
        }
    }
}

impl From<&Context> for ast::Context {
    fn from(v: &Context) -> Self {
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

impl From<&ast::Context> for Context {
    fn from(v: &ast::Context) -> Self {
        Self {
            context: Some(Expr::from(&ast::Expr::from(ast::PartialValue::from(
                v.to_owned(),
            )))),
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
            ast::EntityType::from(&EntityType::from(&ety_specified))
        );

        let euid1 = ast::EntityUID::with_eid_and_type("A", "foo").unwrap();
        assert_eq!(euid1, ast::EntityUID::from(&EntityUid::from(&euid1)));

        let euid2 = ast::EntityUID::from_normalized_str("Foo::Action::\"view\"").unwrap();
        assert_eq!(euid2, ast::EntityUID::from(&EntityUid::from(&euid2)));

        let attrs = (1..=7)
            .map(|id| (format!("{id}").into(), ast::RestrictedExpr::val(true)))
            .collect::<HashMap<SmolStr, _>>();
        let entity = ast::Entity::new(
            r#"Foo::"bar""#.parse().unwrap(),
            attrs,
            HashSet::new(),
            BTreeMap::new(),
            Extensions::none(),
        )
        .unwrap();
        assert_eq!(entity, ast::Entity::from(&Entity::from(&entity)));
    }

    #[test]
    fn expr_roundtrip() {
        let e1 = ast::Expr::val(33);
        assert_eq!(e1, ast::Expr::from(&Expr::from(&e1)));
        let e2 = ast::Expr::val("hello");
        assert_eq!(e2, ast::Expr::from(&Expr::from(&e2)));
        let e3 = ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "foo").unwrap());
        assert_eq!(e3, ast::Expr::from(&Expr::from(&e3)));
        let e4 = ast::Expr::var(ast::Var::Principal);
        assert_eq!(e4, ast::Expr::from(&Expr::from(&e4)));
        let e5 = ast::Expr::ite(
            ast::Expr::val(true),
            ast::Expr::val(88),
            ast::Expr::val(-100),
        );
        assert_eq!(e5, ast::Expr::from(&Expr::from(&e5)));
        let e6 = ast::Expr::not(ast::Expr::val(false));
        assert_eq!(e6, ast::Expr::from(&Expr::from(&e6)));
        let e7 = ast::Expr::get_attr(
            ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "foo").unwrap()),
            "some_attr".into(),
        );
        assert_eq!(e7, ast::Expr::from(&Expr::from(&e7)));
        let e8 = ast::Expr::has_attr(
            ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "foo").unwrap()),
            "some_attr".into(),
        );
        assert_eq!(e8, ast::Expr::from(&Expr::from(&e8)));
        let e9 = ast::Expr::is_entity_type(
            ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "foo").unwrap()),
            "Type".parse().unwrap(),
        );
        assert_eq!(e9, ast::Expr::from(&Expr::from(&e9)));
    }

    #[test]
    fn literal_roundtrip() {
        let bool_literal_f = ast::Literal::from(false);
        assert_eq!(
            bool_literal_f,
            ast::Literal::from(&expr::Literal::from(&bool_literal_f))
        );

        let bool_literal_t = ast::Literal::from(true);
        assert_eq!(
            bool_literal_t,
            ast::Literal::from(&expr::Literal::from(&bool_literal_t))
        );

        let long_literal0 = ast::Literal::from(0);
        assert_eq!(
            long_literal0,
            ast::Literal::from(&expr::Literal::from(&long_literal0))
        );

        let long_literal1 = ast::Literal::from(1);
        assert_eq!(
            long_literal1,
            ast::Literal::from(&expr::Literal::from(&long_literal1))
        );

        let str_literal0 = ast::Literal::from("");
        assert_eq!(
            str_literal0,
            ast::Literal::from(&expr::Literal::from(&str_literal0))
        );

        let str_literal1 = ast::Literal::from("foo");
        assert_eq!(
            str_literal1,
            ast::Literal::from(&expr::Literal::from(&str_literal1))
        );

        let euid_literal =
            ast::Literal::from(ast::EntityUID::with_eid_and_type("A", "foo").unwrap());
        assert_eq!(
            euid_literal,
            ast::Literal::from(&expr::Literal::from(&euid_literal))
        );
    }

    #[test]
    fn name_and_slot_roundtrip() {
        let orig_name = ast::Name::from_normalized_str("B::C::D").unwrap();
        assert_eq!(orig_name, ast::Name::from(&Name::from(&orig_name)));

        let orig_slot1 = ast::SlotId::principal();
        assert_eq!(orig_slot1, ast::SlotId::from(&SlotId::from(&orig_slot1)));

        let orig_slot2 = ast::SlotId::resource();
        assert_eq!(orig_slot2, ast::SlotId::from(&SlotId::from(&orig_slot2)));
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
        let request_rt = ast::Request::from(&Request::from(&request));
        assert_eq!(context, ast::Context::from(&Context::from(&context)));
        assert_eq!(request.principal().uid(), request_rt.principal().uid());
        assert_eq!(request.action().uid(), request_rt.action().uid());
        assert_eq!(request.resource().uid(), request_rt.resource().uid());
    }
}
