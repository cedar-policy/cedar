use std::{collections::BTreeMap, sync::Arc};

use cedar_policy_core::{
    ast::{self, BinaryOp, Expr, ExprKind, PartialValue, Set, Value, ValueKind, Var},
    extensions::Extensions,
};
use cedar_policy_validator::types::Type;

use crate::{
    entities::PartialEntities,
    request::PartialRequest,
    residual::{Residual, ResidualKind},
};

#[derive(Debug)]
pub struct Evaluator<'e> {
    request: PartialRequest,
    entities: &'e PartialEntities,
    extensions: &'e Extensions<'e>,
}

impl<'e> Evaluator<'e> {
    pub fn interpret(&self, e: &Expr<Type>) -> Residual {
        let ty = e.data().clone();
        match e.expr_kind() {
            ExprKind::Lit(l) => Residual::Concrete {
                value: l.clone().into(),
                ty,
            },
            ExprKind::Var(Var::Action) => Residual::Concrete {
                value: self.request.action.clone().into(),
                ty,
            },
            ExprKind::Var(Var::Principal) => {
                if let Some(principal) = &self.request.principal {
                    Residual::Concrete {
                        value: principal.clone().into(),
                        ty,
                    }
                } else {
                    Residual::Partial {
                        kind: ResidualKind::Var(Var::Principal),
                        ty,
                    }
                }
            }
            ExprKind::Var(Var::Resource) => {
                if let Some(resource) = &self.request.resource {
                    Residual::Concrete {
                        value: resource.clone().into(),
                        ty,
                    }
                } else {
                    Residual::Partial {
                        kind: ResidualKind::Var(Var::Resource),
                        ty,
                    }
                }
            }
            ExprKind::Var(Var::Context) => {
                if let Some(context) = &self.request.context {
                    Residual::Concrete {
                        value: Value::record_arc(context.clone(), None),
                        ty,
                    }
                } else {
                    Residual::Partial {
                        kind: ResidualKind::Var(Var::Context),
                        ty,
                    }
                }
            }
            ExprKind::And { left, right } => {
                let left = self.interpret(left);
                match &left {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::Bool(false)),
                                ..
                            },
                        ..
                    } => Residual::Concrete {
                        value: false.into(),
                        ty,
                    },
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::Bool(true)),
                                ..
                            },
                        ..
                    } => self.interpret(right),
                    Residual::Concrete { ty, .. } => Residual::Error(ty.clone()),
                    Residual::Partial { .. } => Residual::Partial {
                        kind: ResidualKind::And {
                            left: Arc::new(left),
                            right: Arc::new(self.interpret(right)),
                        },
                        ty,
                    },
                    Residual::Error(_) => Residual::Error(ty),
                }
            }
            ExprKind::Or { left, right } => {
                let left = self.interpret(left);
                match &left {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::Bool(true)),
                                ..
                            },
                        ..
                    } => Residual::Concrete {
                        value: true.into(),
                        ty,
                    },
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::Bool(false)),
                                ..
                            },
                        ..
                    } => self.interpret(right),
                    Residual::Concrete { ty, .. } => Residual::Error(ty.clone()),
                    Residual::Partial { .. } => Residual::Partial {
                        kind: ResidualKind::Or {
                            left: Arc::new(left),
                            right: Arc::new(self.interpret(right)),
                        },
                        ty,
                    },
                    Residual::Error(_) => Residual::Error(ty),
                }
            }
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                let cond = self.interpret(test_expr);
                match &cond {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::Bool(b)),
                                ..
                            },
                        ..
                    } => {
                        if *b {
                            self.interpret(then_expr)
                        } else {
                            self.interpret(else_expr)
                        }
                    }
                    Residual::Concrete { ty, .. } => Residual::Error(ty.clone()),
                    Residual::Partial { .. } => Residual::Partial {
                        kind: ResidualKind::If {
                            test_expr: Arc::new(cond),
                            then_expr: Arc::new(self.interpret(then_expr)),
                            else_expr: Arc::new(self.interpret(else_expr)),
                        },
                        ty,
                    },
                    Residual::Error(_) => Residual::Error(ty),
                }
            }
            ExprKind::Is { expr, entity_type } => {
                let r = self.interpret(expr);
                match &r {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::EntityUID(uid)),
                                ..
                            },
                        ..
                    } => Residual::Concrete {
                        value: (uid.entity_type() == entity_type).into(),
                        ty,
                    },
                    Residual::Concrete { ty, .. } => Residual::Error(ty.clone()),
                    Residual::Partial { .. } => Residual::Partial {
                        kind: ResidualKind::Is {
                            expr: Arc::new(r),
                            entity_type: entity_type.clone(),
                        },
                        ty,
                    },
                    Residual::Error(_) => Residual::Error(ty),
                }
            }
            ExprKind::Like { expr, pattern } => {
                let r = self.interpret(expr);
                match &r {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::String(s)),
                                ..
                            },
                        ..
                    } => Residual::Concrete {
                        value: pattern.wildcard_match(&s).into(),
                        ty,
                    },
                    Residual::Concrete { ty, .. } => Residual::Error(ty.clone()),
                    Residual::Partial { .. } => Residual::Partial {
                        kind: ResidualKind::Like {
                            expr: Arc::new(r),
                            pattern: pattern.clone(),
                        },
                        ty,
                    },
                    Residual::Error(_) => Residual::Error(ty),
                }
            }
            ExprKind::BinaryApp { op, arg1, arg2 } => {
                let arg1 = self.interpret(arg1);
                let arg2 = self.interpret(arg2);
                match (&arg1, &arg2) {
                    (
                        Residual::Concrete { value: v1, .. },
                        Residual::Concrete { value: v2, .. },
                    ) => match op {
                        BinaryOp::Eq | BinaryOp::Less | BinaryOp::LessEq => {
                            if let Ok(v) = cedar_policy_core::evaluator::binary_relation(
                                *op,
                                v1.clone(),
                                v2.clone(),
                                self.extensions,
                            ) {
                                Residual::Concrete {
                                    value: v.into(),
                                    ty,
                                }
                            } else {
                                Residual::Error(ty.clone())
                            }
                        }
                        BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => {
                            if let Ok(v) = cedar_policy_core::evaluator::binary_arith(
                                *op,
                                v1.clone(),
                                v2.clone(),
                                None,
                            ) {
                                Residual::Concrete {
                                    value: v.into(),
                                    ty,
                                }
                            } else {
                                Residual::Error(ty.clone())
                            }
                        }
                        BinaryOp::In => {
                            if let Ok(uid1) = v1.get_as_entity() {
                                if let Ok(uid2) = v2.get_as_entity() {
                                    if uid1 == uid2 {
                                        Residual::Concrete {
                                            value: true.into(),
                                            ty,
                                        }
                                    } else {
                                        if let Some(entity) = self.entities.entities.get(uid1) {
                                            if let Some(ancestors) = &entity.ancestors {
                                                Residual::Concrete {
                                                    value: ancestors.contains(uid2).into(),
                                                    ty,
                                                }
                                            } else {
                                                Residual::Partial {
                                                    kind: ResidualKind::BinaryApp {
                                                        op: *op,
                                                        arg1: Arc::new(arg1),
                                                        arg2: Arc::new(arg2),
                                                    },
                                                    ty,
                                                }
                                            }
                                        } else {
                                            Residual::Partial {
                                                kind: ResidualKind::BinaryApp {
                                                    op: *op,
                                                    arg1: Arc::new(arg1),
                                                    arg2: Arc::new(arg2),
                                                },
                                                ty,
                                            }
                                        }
                                    }
                                } else if let Ok(s) = v2.get_as_set() {
                                    if let Ok(uids) = s
                                        .iter()
                                        .map(Value::get_as_entity)
                                        .collect::<std::result::Result<Vec<_>, _>>()
                                    {
                                        for uid2 in uids {
                                            if uid1 == uid2 {
                                                return Residual::Concrete {
                                                    value: true.into(),
                                                    ty,
                                                };
                                            } else {
                                                if let Some(entity) =
                                                    self.entities.entities.get(uid1)
                                                {
                                                    if let Some(ancestors) = &entity.ancestors {
                                                        if ancestors.contains(uid2) {
                                                            return Residual::Concrete {
                                                                value: true.into(),
                                                                ty,
                                                            };
                                                        }
                                                    } else {
                                                        return Residual::Partial {
                                                            kind: ResidualKind::BinaryApp {
                                                                op: *op,
                                                                arg1: Arc::new(arg1),
                                                                arg2: Arc::new(arg2),
                                                            },
                                                            ty,
                                                        };
                                                    }
                                                } else {
                                                    return Residual::Partial {
                                                        kind: ResidualKind::BinaryApp {
                                                            op: *op,
                                                            arg1: Arc::new(arg1),
                                                            arg2: Arc::new(arg2),
                                                        },
                                                        ty,
                                                    };
                                                }
                                            }
                                        }
                                        Residual::Concrete {
                                            value: false.into(),
                                            ty,
                                        }
                                    } else {
                                        Residual::Error(ty.clone())
                                    }
                                } else {
                                    Residual::Error(ty.clone())
                                }
                            } else {
                                Residual::Error(ty.clone())
                            }
                        }
                        BinaryOp::GetTag => {
                            if let Ok(uid) = v1.get_as_entity() {
                                if let Ok(tag) = v2.get_as_string() {
                                    if let Some(entity) = self.entities.entities.get(uid) {
                                        if let Some(tags) = &entity.tags {
                                            if let Some(v) = tags.get(tag) {
                                                Residual::Concrete {
                                                    value: v.clone(),
                                                    ty,
                                                }
                                            } else {
                                                Residual::Error(ty.clone())
                                            }
                                        } else {
                                            Residual::Partial {
                                                kind: ResidualKind::BinaryApp {
                                                    op: *op,
                                                    arg1: Arc::new(arg1),
                                                    arg2: Arc::new(arg2),
                                                },
                                                ty,
                                            }
                                        }
                                    } else {
                                        Residual::Partial {
                                            kind: ResidualKind::BinaryApp {
                                                op: *op,
                                                arg1: Arc::new(arg1),
                                                arg2: Arc::new(arg2),
                                            },
                                            ty,
                                        }
                                    }
                                } else {
                                    Residual::Error(ty.clone())
                                }
                            } else {
                                Residual::Error(ty.clone())
                            }
                        }
                        BinaryOp::HasTag => {
                            if let Ok(uid) = v1.get_as_entity() {
                                if let Ok(tag) = v2.get_as_string() {
                                    if let Some(entity) = self.entities.entities.get(uid) {
                                        if let Some(tags) = &entity.tags {
                                            Residual::Concrete {
                                                value: tags.contains_key(tag).into(),
                                                ty,
                                            }
                                        } else {
                                            Residual::Partial {
                                                kind: ResidualKind::BinaryApp {
                                                    op: *op,
                                                    arg1: Arc::new(arg1),
                                                    arg2: Arc::new(arg2),
                                                },
                                                ty,
                                            }
                                        }
                                    } else {
                                        Residual::Partial {
                                            kind: ResidualKind::BinaryApp {
                                                op: *op,
                                                arg1: Arc::new(arg1),
                                                arg2: Arc::new(arg2),
                                            },
                                            ty,
                                        }
                                    }
                                } else {
                                    Residual::Error(ty.clone())
                                }
                            } else {
                                Residual::Error(ty.clone())
                            }
                        }
                        BinaryOp::Contains => match &v1.value {
                            ValueKind::Set(Set { fast: Some(h), .. }) => Residual::Concrete {
                                value: match v2.try_as_lit() {
                                    Some(lit) => (h.contains(lit)).into(),
                                    None => false.into(),
                                },
                                ty,
                            },
                            ValueKind::Set(Set {
                                fast: None,
                                authoritative,
                            }) => Residual::Concrete {
                                value: (authoritative.contains(v2)).into(),
                                ty,
                            },
                            _ => Residual::Error(ty.clone()),
                        },
                        BinaryOp::ContainsAll | BinaryOp::ContainsAny => {
                            match (v1.get_as_set(), v2.get_as_set()) {
                                (Ok(arg1_set), Ok(arg2_set)) => {
                                    match (&arg1_set.fast, &arg2_set.fast) {
                                        (Some(arg1_set), Some(arg2_set)) => {
                                            // both sets are in fast form, ie, they only contain literals.
                                            // Fast hashset-based implementation.
                                            match op {
                                                BinaryOp::ContainsAll => {
                                                    Residual::Concrete { value: (arg2_set.is_subset(arg1_set)).into(), ty}
                                                }
                                                BinaryOp::ContainsAny => {
                                                    Residual::Concrete { value: (!arg1_set.is_disjoint(arg2_set)).into(), ty}
                                                }
                                                // PANIC SAFETY `op` is checked to be one of these two above
                                                #[allow(clippy::unreachable)]
                                                _ => unreachable!(
                                                    "Should have already checked that op was one of these"
                                                ),
                                            }
                                        }
                                        (_, _) => {
                                            // one or both sets are in slow form, ie, contain a non-literal.
                                            // Fallback to slow implementation.
                                            match op {
                                                BinaryOp::ContainsAll => {
                                                    let is_subset = arg2_set
                                                        .authoritative
                                                        .iter()
                                                        .all(|item| arg1_set.authoritative.contains(item));
                                                    Residual::Concrete {value: is_subset.into(), ty}
                                                }
                                                BinaryOp::ContainsAny => {
                                                    let not_disjoint = arg1_set
                                                        .authoritative
                                                        .iter()
                                                        .any(|item| arg2_set.authoritative.contains(item));
                                                    Residual::Concrete {value: not_disjoint.into(), ty}
                                                }
                                                // PANIC SAFETY `op` is checked to be one of these two above
                                                #[allow(clippy::unreachable)]
                                                _ => unreachable!(
                                                    "Should have already checked that op was one of these"
                                                ),
                                            }
                                        }
                                    }
                                }
                                _ => Residual::Error(ty),
                            }
                        }
                    },
                    (Residual::Error(_), _) => Residual::Error(ty),
                    (_, Residual::Error(_)) => Residual::Error(ty),
                    (_, _) => Residual::Partial {
                        kind: ResidualKind::BinaryApp {
                            op: op.clone(),
                            arg1: Arc::new(arg1),
                            arg2: Arc::new(arg2),
                        },
                        ty,
                    },
                }
            }
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let args = args.iter().map(|a| self.interpret(a)).collect::<Vec<_>>();
                if let Ok(vals) = args
                    .iter()
                    .map(|a| Value::try_from(a.clone()))
                    .collect::<std::result::Result<Vec<_>, _>>()
                {
                    if let Ok(ext_fn) = self.extensions.func(fn_name) {
                        if let Ok(PartialValue::Value(value)) = ext_fn.call(&vals) {
                            return Residual::Concrete { value, ty };
                        }
                    }
                    return Residual::Error(ty.clone());
                } else {
                    Residual::Partial {
                        kind: ResidualKind::ExtensionFunctionApp {
                            fn_name: fn_name.clone(),
                            args: Arc::new(args),
                        },
                        ty: ty.clone(),
                    }
                }
            }
            ExprKind::GetAttr { expr, attr } => {
                let r = self.interpret(expr);
                match &r {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Record(r),
                                ..
                            },
                        ..
                    } => {
                        if let Some(val) = r.as_ref().get(attr) {
                            Residual::Concrete {
                                value: val.clone(),
                                ty,
                            }
                        } else {
                            Residual::Error(ty.clone())
                        }
                    }
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::EntityUID(uid)),
                                ..
                            },
                        ..
                    } => {
                        if let Some(entity) = self.entities.entities.get(uid.as_ref()) {
                            if let Some(attrs) = &entity.as_ref().attrs {
                                if let Some(val) = attrs.get(attr) {
                                    return Residual::Concrete {
                                        value: val.clone(),
                                        ty,
                                    };
                                } else {
                                    return Residual::Error(ty.clone());
                                }
                            }
                        }
                        Residual::Partial {
                            kind: ResidualKind::GetAttr {
                                expr: Arc::new(r),
                                attr: attr.clone(),
                            },
                            ty,
                        }
                    }
                    Residual::Concrete { .. } => Residual::Error(ty),
                    Residual::Partial { .. } => Residual::Partial {
                        kind: ResidualKind::GetAttr {
                            expr: Arc::new(r),
                            attr: attr.clone(),
                        },
                        ty,
                    },
                    Residual::Error(_) => Residual::Error(ty),
                }
            }
            ExprKind::HasAttr { expr, attr } => {
                let r = self.interpret(expr);
                match &r {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Record(r),
                                ..
                            },
                        ..
                    } => Residual::Concrete {
                        value: r.as_ref().contains_key(attr).into(),
                        ty,
                    },
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::EntityUID(uid)),
                                ..
                            },
                        ..
                    } => {
                        if let Some(entity) = self.entities.entities.get(uid.as_ref()) {
                            if let Some(attrs) = &entity.as_ref().attrs {
                                return Residual::Concrete {
                                    value: attrs.contains_key(attr).into(),
                                    ty,
                                };
                            }
                        }
                        Residual::Partial {
                            kind: ResidualKind::HasAttr {
                                expr: Arc::new(r),
                                attr: attr.clone(),
                            },
                            ty,
                        }
                    }
                    Residual::Concrete { .. } => Residual::Error(ty),
                    Residual::Partial { .. } => Residual::Partial {
                        kind: ResidualKind::HasAttr {
                            expr: Arc::new(r),
                            attr: attr.clone(),
                        },
                        ty,
                    },
                    Residual::Error(_) => Residual::Error(ty),
                }
            }
            ExprKind::Unknown { .. } => unreachable!("we should not unexpect unknowns"),
            ExprKind::Slot(_) => unimplemented!("we should not unexpect slot for now"),
            ExprKind::UnaryApp { op, arg } => {
                let arg = self.interpret(arg);
                match &arg {
                    Residual::Concrete { value, .. } => {
                        if let Ok(v) =
                            cedar_policy_core::evaluator::unary_app(*op, value.clone(), None)
                        {
                            Residual::Concrete { value: v, ty }
                        } else {
                            Residual::Error(ty.clone())
                        }
                    }
                    Residual::Partial { .. } => Residual::Partial {
                        kind: ResidualKind::UnaryApp {
                            op: op.clone(),
                            arg: Arc::new(arg),
                        },
                        ty,
                    },
                    Residual::Error(_) => Residual::Error(ty),
                }
            }
            ExprKind::Set(es) => {
                let rs = es.iter().map(|a| self.interpret(a)).collect::<Vec<_>>();
                if let Ok(vals) = rs
                    .iter()
                    .map(|a| Value::try_from(a.clone()))
                    .collect::<std::result::Result<Vec<_>, _>>()
                {
                    Residual::Concrete {
                        value: Value {
                            value: ValueKind::Set(Set::new(vals)),
                            loc: None,
                        },
                        ty,
                    }
                } else {
                    Residual::Partial {
                        kind: ResidualKind::Set(Arc::new(rs)),
                        ty,
                    }
                }
            }
            ExprKind::Record(m) => {
                let record = m
                    .as_ref()
                    .iter()
                    .map(|(a, e)| (a.clone(), self.interpret(e)));
                if let Ok(m) = record
                    .clone()
                    .map(|(a, r)| Ok((a, Value::try_from(r)?)))
                    .collect::<std::result::Result<BTreeMap<_, _>, ()>>()
                {
                    Residual::Concrete {
                        value: Value {
                            value: ValueKind::Record(Arc::new(m)),
                            loc: None,
                        },
                        ty,
                    }
                } else {
                    Residual::Partial {
                        kind: ResidualKind::Record(Arc::new(record.collect())),
                        ty,
                    }
                }
            }
        }
    }
}
