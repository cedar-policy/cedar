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

//! This module contains the type-aware partial evaluator.

use std::{collections::BTreeMap, sync::Arc};

use crate::validator::types::Type;
use crate::{
    ast::{self, BinaryOp, EntityUID, Expr, ExprKind, PartialValue, Set, Value, ValueKind, Var},
    extensions::Extensions,
};

use crate::{
    tpe::entities::PartialEntities,
    tpe::request::PartialRequest,
    tpe::residual::{Residual, ResidualKind},
};

/// The partial evaluator
#[derive(Debug)]
pub struct Evaluator<'e> {
    pub(crate) request: PartialRequest,
    pub(crate) entities: &'e PartialEntities,
    pub(crate) extensions: &'e Extensions<'e>,
}

impl Evaluator<'_> {
    /// Interpret a typed expression into a residual
    /// This function always succeeds because it wraps an error encountered
    /// into a `ResidualKind::Error`
    pub fn interpret(&self, e: &Expr<Option<Type>>) -> Residual {
        // PANIC SAFETY: the validator should produce expressions with types
        #[allow(clippy::expect_used)]
        let ty = e
            .data()
            .clone()
            .expect("type checked should provide a type");
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
                if let Ok(principal) = EntityUID::try_from(self.request.principal.clone()) {
                    Residual::Concrete {
                        value: principal.into(),
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
                if let Ok(resource) = EntityUID::try_from(self.request.resource.clone()) {
                    Residual::Concrete {
                        value: resource.into(),
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
                    Residual::Partial { .. } => match &self.interpret(&right) {
                        Residual::Concrete {
                            value:
                                Value {
                                    value: ValueKind::Lit(ast::Literal::Bool(true)),
                                    ..
                                },
                            ..
                        } => left,
                        right => Residual::Partial {
                            kind: ResidualKind::And {
                                left: Arc::new(left),
                                right: Arc::new(right.clone()),
                            },
                            ty,
                        },
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
                    Residual::Partial { .. } => match &self.interpret(&right) {
                        Residual::Concrete {
                            value:
                                Value {
                                    value: ValueKind::Lit(ast::Literal::Bool(false)),
                                    ..
                                },
                            ..
                        } => left,
                        right => Residual::Partial {
                            kind: ResidualKind::Or {
                                left: Arc::new(left),
                                right: Arc::new(right.clone()),
                            },
                            ty,
                        },
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
                    Residual::Partial {
                        kind: ResidualKind::Var(Var::Principal),
                        ..
                    } => Residual::Concrete {
                        value: (entity_type == &self.request.principal.ty).into(),
                        ty,
                    },
                    Residual::Partial {
                        kind: ResidualKind::Var(Var::Resource),
                        ..
                    } => Residual::Concrete {
                        value: (entity_type == &self.request.resource.ty).into(),
                        ty,
                    },
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
                        value: pattern.wildcard_match(s).into(),
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
                let residual = |arg1, arg2, ty| Residual::Partial {
                    kind: ResidualKind::BinaryApp {
                        op: *op,
                        arg1: Arc::new(arg1),
                        arg2: Arc::new(arg2),
                    },
                    ty,
                };
                match (&arg1, &arg2) {
                    (
                        Residual::Concrete { value: v1, .. },
                        Residual::Concrete { value: v2, .. },
                    ) => match op {
                        BinaryOp::Eq | BinaryOp::Less | BinaryOp::LessEq => {
                            if let Ok(v) =
                                crate::evaluator::binary_relation(*op, v1, v2, self.extensions)
                            {
                                Residual::Concrete { value: v, ty }
                            } else {
                                Residual::Error(ty)
                            }
                        }
                        BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => {
                            if let Ok(v) =
                                crate::evaluator::binary_arith(*op, v1.clone(), v2.clone(), None)
                            {
                                Residual::Concrete { value: v, ty }
                            } else {
                                Residual::Error(ty)
                            }
                        }
                        BinaryOp::In => {
                            if let Ok(uid1) = v1.get_as_entity() {
                                if let Ok(uid2) = v2.get_as_entity() {
                                    if uid1 == uid2 {
                                        return Residual::Concrete {
                                            value: true.into(),
                                            ty,
                                        };
                                    } else if let Some(entity) = self.entities.entities.get(uid1) {
                                        if let Some(ancestors) = &entity.ancestors {
                                            return Residual::Concrete {
                                                value: ancestors.contains(uid2).into(),
                                                ty,
                                            };
                                        }
                                    }
                                    residual(arg1, arg2, ty)
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
                                            } else if let Some(entity) =
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
                                                    return residual(arg1, arg2, ty);
                                                }
                                            } else {
                                                return residual(arg1, arg2, ty);
                                            }
                                        }
                                        Residual::Concrete {
                                            value: false.into(),
                                            ty,
                                        }
                                    } else {
                                        Residual::Error(ty)
                                    }
                                } else {
                                    Residual::Error(ty)
                                }
                            } else {
                                Residual::Error(ty)
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
                                                Residual::Error(ty)
                                            }
                                        } else {
                                            residual(arg1, arg2, ty)
                                        }
                                    } else {
                                        residual(arg1, arg2, ty)
                                    }
                                } else {
                                    Residual::Error(ty)
                                }
                            } else {
                                Residual::Error(ty)
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
                                            residual(arg1, arg2, ty)
                                        }
                                    } else {
                                        residual(arg1, arg2, ty)
                                    }
                                } else {
                                    Residual::Error(ty)
                                }
                            } else {
                                Residual::Error(ty)
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
                            _ => Residual::Error(ty),
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
                    (_, _) => residual(arg1, arg2, ty),
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
                    Residual::Error(ty)
                } else {
                    if args.iter().any(|r| matches!(r, Residual::Error(_))) {
                        Residual::Error(ty)
                    } else {
                        Residual::Partial {
                            kind: ResidualKind::ExtensionFunctionApp {
                                fn_name: fn_name.clone(),
                                args: Arc::new(args),
                            },
                            ty,
                        }
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
                            Residual::Error(ty)
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
                            if let Some(attrs) = &entity.attrs {
                                if let Some(val) = attrs.get(attr) {
                                    return Residual::Concrete {
                                        value: val.clone(),
                                        ty,
                                    };
                                } else {
                                    return Residual::Error(ty);
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
                            if let Some(attrs) = &entity.attrs {
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
            // PANIC SAFETY: TPE does not expect explicit unknowns in policies
            #[allow(clippy::unreachable)]
            ExprKind::Unknown { .. } => unreachable!("we should not unexpect unknowns"),
            // PANIC SAFETY: TPE currently only works on static policies
            #[allow(clippy::unreachable)]
            ExprKind::Slot(_) => unreachable!("we should not unexpect slot for now"),
            #[cfg(feature = "tolerant-ast")]
            ExprKind::Error { .. } => Residual::Error(ty),
            ExprKind::UnaryApp { op, arg } => {
                let arg = self.interpret(arg);
                match &arg {
                    Residual::Concrete { value, .. } => {
                        if let Ok(v) = crate::evaluator::unary_app(*op, value.clone(), None) {
                            Residual::Concrete { value: v, ty }
                        } else {
                            Residual::Error(ty)
                        }
                    }
                    Residual::Partial { .. } => Residual::Partial {
                        kind: ResidualKind::UnaryApp {
                            op: *op,
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
                    if rs.iter().any(|r| matches!(r, Residual::Error(_))) {
                        Residual::Error(ty)
                    } else {
                        Residual::Partial {
                            kind: ResidualKind::Set(Arc::new(rs)),
                            ty,
                        }
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
                    let mut m = BTreeMap::new();
                    for (a, r) in record {
                        if matches!(r, Residual::Error(_)) {
                            return Residual::Error(ty);
                        } else {
                            m.insert(a, r);
                        }
                    }
                    Residual::Partial {
                        kind: ResidualKind::Record(Arc::new(m)),
                        ty,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        i64,
    };

    use crate::validator::{types::Type, ValidatorSchema};
    use crate::{
        ast::{
            BinaryOp, EntityUID, ExprBuilder, Literal, Pattern, PatternElem, UnaryOp, Value,
            ValueKind, Var,
        },
        expr_builder::ExprBuilder as _,
        extensions::Extensions,
        FromNormalizedStr,
    };
    use cool_asserts::assert_matches;

    use crate::{
        tpe::entities::{PartialEntities, PartialEntity},
        tpe::request::{PartialEntityUID, PartialRequest},
        tpe::residual::{Residual, ResidualKind},
    };

    use super::Evaluator;

    #[allow(unused)]
    #[track_caller]
    fn simple_schema() -> ValidatorSchema {
        let src = r#"
            entity E { s? : String, l? : Long };
            action a {
              principal: E,
              resource: E,
            };
        "#;
        ValidatorSchema::from_cedarschema_str(src, Extensions::all_available())
            .unwrap()
            .0
    }

    #[track_caller]
    fn action() -> EntityUID {
        r#"Action::"a""#.parse().unwrap()
    }

    #[track_caller]
    fn dummy_uid() -> EntityUID {
        r#"E::"""#.parse().unwrap()
    }

    #[allow(unused)]
    #[track_caller]
    fn dummy_entity() -> PartialEntity {
        PartialEntity {
            uid: dummy_uid(),
            attrs: None,
            ancestors: None,
            tags: None,
        }
    }

    #[track_caller]
    fn dummy_entities() -> PartialEntities {
        PartialEntities {
            entities: HashMap::new(),
        }
    }

    #[test]
    fn test_var() {
        let req = PartialRequest::new_unchecked(
            PartialEntityUID {
                ty: "E".parse().unwrap(),
                eid: None,
            },
            dummy_uid().into(),
            action(),
            None,
        );
        let eval = Evaluator {
            request: req,
            entities: &dummy_entities(),
            extensions: Extensions::all_available(),
        };
        // principal -> principal because its eid is unknown
        assert_matches!(
            eval.interpret(&builder().var(Var::Principal)),
            Residual::Partial {
                kind: ResidualKind::Var(Var::Principal),
                ..
            }
        );
        // resource -> E::""
        assert_matches!(
            eval.interpret(&builder().var(Var::Resource)),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::EntityUID(uid)),
                    ..
                },
                ..
            } => {
                assert_eq!(uid.as_ref(), &dummy_uid());
            }
        );
        // action is always known
        assert_matches!(
            eval.interpret(&builder().var(Var::Action)),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::EntityUID(uid)),
                    ..
                },
                ..
            } => {
                assert_eq!(uid.as_ref(), &action());
            }
        );
        // context is always unknown
        assert_matches!(
            eval.interpret(&builder().var(Var::Context)),
            Residual::Partial {
                kind: ResidualKind::Var(Var::Context),
                ..
            }
        );
    }

    #[track_caller]
    fn builder() -> ExprBuilder<Option<Type>> {
        ExprBuilder::with_data(Some(Type::Never))
    }

    #[test]
    fn test_and() {
        let req = PartialRequest::new_unchecked(
            PartialEntityUID {
                ty: "E".parse().unwrap(),
                eid: None,
            },
            dummy_uid().into(),
            action(),
            None,
        );
        let eval = Evaluator {
            request: req,
            entities: &dummy_entities(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret(&builder().and(
                builder().noteq(builder().var(Var::Resource), builder().var(Var::Resource)),
                builder().val(42)
            )),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(false)),
                    ..
                },
                ..
            }
        );
        // Note that this expression is not an invalid input
        // The evaluator does not perform any validation
        assert_matches!(
            eval.interpret(&builder().and(
                builder().var(Var::Principal),
                builder().val(true)
            )),
            Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. }
        );
        assert_matches!(
            eval.interpret(&builder().and(
                builder().noteq(
                    builder().mul(builder().val(i64::MAX), builder().val(2)),
                    builder().val(0)
                ),
                builder().val(42)
            )),
            Residual::Error(_),
        );
        // resource == resource && 42 => 42
        // Note that this expression is not an invalid input
        // The evaluator does not perform any validation
        assert_matches!(
            eval.interpret(&builder().and(
                builder().binary_app(
                    BinaryOp::Eq,
                    builder().var(Var::Resource),
                    builder().var(Var::Resource)
                ),
                builder().val(42)
            )),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Long(42)),
                    ..
                },
                ..
            }
        );
    }

    #[test]
    fn test_or() {
        let req = PartialRequest::new_unchecked(
            PartialEntityUID {
                ty: "E".parse().unwrap(),
                eid: None,
            },
            dummy_uid().into(),
            action(),
            None,
        );
        let eval = Evaluator {
            request: req,
            entities: &dummy_entities(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret(&builder().or(
                builder().binary_app(
                    BinaryOp::Eq,
                    builder().var(Var::Resource),
                    builder().var(Var::Resource)
                ),
                builder().val(42)
            )),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );
        // Note that this expression is not an invalid input
        // The evaluator does not perform any validation
        assert_matches!(
            eval.interpret(&builder().or(
                builder().var(Var::Principal),
                builder().val(false)
            )),
            Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. }
        );
        assert_matches!(
            eval.interpret(&builder().or(
                builder().noteq(
                    builder().mul(builder().val(i64::MAX), builder().val(2)),
                    builder().val(0)
                ),
                builder().val(42)
            )),
            Residual::Error(_),
        );
        // resource != resource || 42 => 42
        // Note that this expression is not an invalid input
        // The evaluator does not perform any validation
        assert_matches!(
            eval.interpret(&builder().or(
                builder().noteq(builder().var(Var::Resource), builder().var(Var::Resource)),
                builder().val(42)
            )),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Long(42)),
                    ..
                },
                ..
            }
        );
    }

    #[test]
    fn test_ite() {
        let req = PartialRequest::new_unchecked(
            PartialEntityUID {
                ty: "E".parse().unwrap(),
                eid: None,
            },
            dummy_uid().into(),
            action(),
            None,
        );
        let eval = Evaluator {
            request: req,
            entities: &dummy_entities(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret(&builder().ite(
                builder().is_eq(builder().var(Var::Action), builder().var(Var::Action)),
                builder().var(Var::Principal),
                builder().val(2)
            )),
            Residual::Partial {
                kind: ResidualKind::Var(Var::Principal),
                ..
            }
        );
        assert_matches!(
            eval.interpret(&builder().ite(
                builder().is_eq(builder().var(Var::Principal), builder().var(Var::Principal)),
                builder().var(Var::Principal),
                builder().val(2)
            )),
            Residual::Partial {
                kind: ResidualKind::If { test_expr, then_expr, else_expr },
                ..
            } => {
                assert_matches!(test_expr.as_ref(), Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::Eq, .. }, .. });
                assert_matches!(then_expr.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
                assert_matches!(else_expr.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::Long(2)), .. }, .. });
            }
        );
    }

    #[test]
    fn test_is() {
        let req = PartialRequest::new_unchecked(
            PartialEntityUID {
                ty: "E".parse().unwrap(),
                eid: None,
            },
            dummy_uid().into(),
            action(),
            None,
        );
        let eval = Evaluator {
            request: req,
            entities: &dummy_entities(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret(&builder().is_entity_type(
                builder().var(Var::Resource),
                dummy_uid().entity_type().clone()
            )),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );
        // Note that the Lean model evaluates it to `principal is E`
        assert_matches!(
            eval.interpret(&builder().is_entity_type(
                builder().var(Var::Principal),
                dummy_uid().entity_type().clone()
            )),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );
    }

    #[test]
    fn test_like() {
        let req = PartialRequest::new_unchecked(
            PartialEntityUID {
                ty: "E".parse().unwrap(),
                eid: None,
            },
            dummy_uid().into(),
            action(),
            None,
        );
        let eval = Evaluator {
            request: req,
            entities: &dummy_entities(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret(&builder().like(
                builder().val("aaa"),
                Pattern::from(vec![PatternElem::Char('a'), PatternElem::Wildcard])
            )),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );
        // Note that this expression is not valid input
        assert_matches!(
            eval.interpret(&builder().like(builder().var(Var::Principal), Pattern::from(vec![PatternElem::Char('a'), PatternElem::Wildcard]))),
           Residual::Partial { kind: ResidualKind::Like { expr, .. }, .. } => {
                assert_matches!(expr.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
            }
        );
    }

    #[test]
    fn test_unary_app() {
        let req = PartialRequest::new_unchecked(
            PartialEntityUID {
                ty: "E".parse().unwrap(),
                eid: None,
            },
            dummy_uid().into(),
            action(),
            None,
        );
        let eval = Evaluator {
            request: req,
            entities: &dummy_entities(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret(&builder().unary_app(UnaryOp::Neg, builder().val(42))),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Long(-42)),
                    ..
                },
                ..
            }
        );
        // This is not a valid input
        assert_matches!(
            eval.interpret(&builder().unary_app(UnaryOp::Neg, builder().var(Var::Principal))),
            Residual::Partial { kind: ResidualKind::UnaryApp { op: UnaryOp::Neg, arg }, .. } => {
                assert_matches!(arg.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
            }
        );
        assert_matches!(
            eval.interpret(&builder().unary_app(UnaryOp::Neg, builder().val(i64::MIN))),
            Residual::Error(_),
        );
    }

    #[test]
    fn test_get_attr() {
        let req = PartialRequest::new_unchecked(
            PartialEntityUID {
                ty: "E".parse().unwrap(),
                eid: None,
            },
            dummy_uid().into(),
            action(),
            None,
        );
        let entities = PartialEntities {
            entities: HashMap::from_iter([
                (
                    dummy_uid(),
                    PartialEntity {
                        uid: dummy_uid(),
                        attrs: Some(BTreeMap::from_iter([(
                            "s".parse().unwrap(),
                            Value::from("bar"),
                        )])),
                        ancestors: None,
                        tags: None,
                    },
                ),
                (
                    r#"E::"e""#.parse().unwrap(),
                    PartialEntity {
                        uid: r#"E::"e""#.parse().unwrap(),
                        attrs: None,
                        ancestors: None,
                        tags: None,
                    },
                ),
            ]),
        };
        let eval = Evaluator {
            request: req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret(&builder().get_attr(builder().var(Var::Resource), "s".parse().unwrap())),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::String(s)),
                    ..
                },
                ..
            } => {
                assert_eq!(s, "bar");
            }
        );

        // When LHS is unknown, the entire expression is
        assert_matches!(
            eval.interpret(&builder().get_attr(
                builder().var(Var::Principal),
                "s".parse().unwrap()
            )),
            Residual::Partial { kind: ResidualKind::GetAttr { expr, .. }, .. } => {
                assert_matches!(expr.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
            }
        );
        // When LHS is not in the entities, the entire expression is unknown
        assert_matches!(
            eval.interpret(&builder().get_attr(
                builder().val(EntityUID::from_normalized_str(r#"E::"f""#).unwrap()),
                "s".parse().unwrap()
            )),
            Residual::Partial { kind: ResidualKind::GetAttr { expr, .. }, .. } => {
                assert_matches!(expr.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );
        // When LHS is in the entities, but its attributes are `None`, the
        // entire expression is unknown
        assert_matches!(
            eval.interpret(&builder().get_attr(
                builder().val(EntityUID::from_normalized_str(r#"E::"e""#).unwrap()),
                "s".parse().unwrap()
            )),
            Residual::Partial { kind: ResidualKind::GetAttr { expr, .. }, .. } => {
                assert_matches!(expr.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );
        assert_matches!(
            eval.interpret(
                &builder().get_attr(builder().var(Var::Resource), "baz".parse().unwrap())
            ),
            Residual::Error(_),
        );
    }

    #[test]
    fn test_has_attr() {
        let req = PartialRequest::new_unchecked(
            PartialEntityUID {
                ty: "E".parse().unwrap(),
                eid: None,
            },
            dummy_uid().into(),
            action(),
            None,
        );
        let entities = PartialEntities {
            entities: HashMap::from_iter([
                (
                    dummy_uid(),
                    PartialEntity {
                        uid: dummy_uid(),
                        attrs: Some(BTreeMap::from_iter([(
                            "s".parse().unwrap(),
                            Value::from("bar"),
                        )])),
                        ancestors: None,
                        tags: None,
                    },
                ),
                (
                    r#"E::"e""#.parse().unwrap(),
                    PartialEntity {
                        uid: r#"E::"e""#.parse().unwrap(),
                        attrs: None,
                        ancestors: None,
                        tags: None,
                    },
                ),
            ]),
        };
        let eval = Evaluator {
            request: req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret(&builder().has_attr(builder().var(Var::Resource), "s".parse().unwrap())),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );
        assert_matches!(
            eval.interpret(&builder().has_attr(builder().var(Var::Principal), "s".parse().unwrap())),
            Residual::Partial {
                kind: ResidualKind::HasAttr { expr, .. },
                ..
            } => {
                assert_matches!(expr.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
            }
        );
        // When LHS is not in the entities, the entire expression is unknown
        assert_matches!(
            eval.interpret(&builder().has_attr(
                builder().val(EntityUID::from_normalized_str(r#"E::"f""#).unwrap()),
                "s".parse().unwrap()
            )),
            Residual::Partial { kind: ResidualKind::HasAttr { expr, .. }, .. } => {
                assert_matches!(expr.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );
        // When LHS is in the entities, but its attributes are `None`, the
        // entire expression is unknown
        assert_matches!(
            eval.interpret(&builder().has_attr(
                builder().val(EntityUID::from_normalized_str(r#"E::"e""#).unwrap()),
                "s".parse().unwrap()
            )),
            Residual::Partial { kind: ResidualKind::HasAttr { expr, .. }, .. } => {
                assert_matches!(expr.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );
    }

    #[test]
    fn test_set() {
        let req = PartialRequest::new_unchecked(
            PartialEntityUID {
                ty: "E".parse().unwrap(),
                eid: None,
            },
            dummy_uid().into(),
            action(),
            None,
        );
        let eval = Evaluator {
            request: req,
            entities: &dummy_entities(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret(&builder().set(
                [builder().var(Var::Resource)]
            )),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Set(s),
                    ..
                },
                ..
            } => {
                assert_eq!(Vec::from_iter(s.iter().cloned()), vec![Value::from(dummy_uid())]);
            }
        );
        assert_matches!(
            eval.interpret(&builder().set(
                [builder().var(Var::Principal),
                builder().var(Var::Resource),]
            )),
            Residual::Partial {
                kind: ResidualKind::Set(s),
                ..
            } => {
                assert_matches!(s.as_ref().as_slice(), [Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. }, Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. }]);
            }
        );

        // Error is propagated
        assert_matches!(
            eval.interpret(&builder().set([
                builder().neg(builder().val(i64::MIN)),
                builder().var(Var::Resource),
            ])),
            Residual::Error(_)
        )
    }

    #[test]
    fn test_record() {
        let req = PartialRequest::new_unchecked(
            PartialEntityUID {
                ty: "E".parse().unwrap(),
                eid: None,
            },
            dummy_uid().into(),
            action(),
            None,
        );
        let eval = Evaluator {
            request: req,
            entities: &dummy_entities(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret(&builder().record(
                [(
                    "s".into(),
                    builder().var(Var::Resource),
                )]
            ).unwrap()),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Record(m),
                    ..
                },
                ..
            } => {
                assert_eq!(m.get("s"), Some(&Value::from(dummy_uid())));
            }
        );
        assert_matches!(
            eval.interpret(&builder().record(
                [(
                    "s".into(),
                    builder().var(Var::Principal),
                )]
            ).unwrap()),
            Residual::Partial {
                kind: ResidualKind::Record(m),
                ..
            } => {
                assert_matches!(m.as_ref().get("s"), Some(Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. }));
            }
        );

        // Error is propagated
        assert_matches!(
            eval.interpret(
                &builder()
                    .record([
                        ("s".into(), builder().neg(builder().val(i64::MIN)),),
                        ("".into(), builder().var(Var::Resource),)
                    ])
                    .unwrap()
            ),
            Residual::Error(_)
        )
    }

    #[test]
    fn test_call() {
        let req = PartialRequest::new_unchecked(
            PartialEntityUID {
                ty: "E".parse().unwrap(),
                eid: None,
            },
            dummy_uid().into(),
            action(),
            None,
        );
        let eval = Evaluator {
            request: req,
            entities: &dummy_entities(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret(
                &builder().call_extension_fn("decimal".parse().unwrap(), [builder().val("0.0")])
            ),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::ExtensionValue(_),
                    ..
                },
                ..
            }
        );
        // not a valid input
        assert_matches!(
            eval.interpret(&builder().call_extension_fn(
                "decimal".parse().unwrap(),
                [builder().var(Var::Principal)]
            )),
            Residual::Partial {
                kind: ResidualKind::ExtensionFunctionApp { fn_name, args, .. },
                ..
            } => {
                assert_eq!(fn_name.to_string(), "decimal");
                assert_matches!(args.as_ref().as_slice(), [Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. }]);
            }
        );

        // Error is propagated
        assert_matches!(
            eval.interpret(&builder().call_extension_fn(
                "decimal".parse().unwrap(),
                [builder().neg(builder().val(i64::MIN))]
            )),
            Residual::Error(_)
        )
    }

    #[test]
    fn test_binary_app() {
        let req = PartialRequest::new_unchecked(
            PartialEntityUID {
                ty: "E".parse().unwrap(),
                eid: None,
            },
            dummy_uid().into(),
            action(),
            None,
        );
        // not valid entities
        let entities = PartialEntities {
            entities: HashMap::from_iter([
                (
                    dummy_uid(),
                    PartialEntity {
                        uid: dummy_uid(),
                        attrs: None,
                        ancestors: Some(HashSet::from_iter([r#"E::"e""#.parse().unwrap()])),
                        tags: Some(BTreeMap::from_iter([(
                            "s".parse().unwrap(),
                            Value::from("bar"),
                        )])),
                    },
                ),
                (
                    r#"E::"e""#.parse().unwrap(),
                    PartialEntity {
                        uid: r#"E::"e""#.parse().unwrap(),
                        attrs: None,
                        ancestors: Some(HashSet::default()),
                        tags: None,
                    },
                ),
            ]),
        };
        let eval = Evaluator {
            request: req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };

        assert_matches!(
            eval.interpret(&builder().binary_app(
                BinaryOp::Eq,
                builder().var(Var::Resource),
                builder().val(dummy_uid())
            )),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );

        assert_matches!(
            eval.interpret(&builder().binary_app(
                BinaryOp::Eq,
                builder().var(Var::Principal),
                builder().val(dummy_uid())
            )),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::Eq, arg1, .. }, .. } => {
                assert_matches!(arg1.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
            }
        );

        assert_matches!(
            eval.interpret(&builder().binary_app(
                BinaryOp::Add,
                builder().val(i64::MAX),
                builder().val(i64::MAX)
            )),
            Residual::Error(_)
        );

        assert_matches!(
            eval.interpret(&builder().binary_app(
                BinaryOp::Contains,
                builder().set([builder().val(dummy_uid())]),
                builder().var(Var::Resource)
            )),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );

        assert_matches!(
            eval.interpret(&builder().binary_app(
                BinaryOp::Contains,
                builder().set([builder().val(dummy_uid())]),
                builder().var(Var::Principal)
            )),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::Contains, arg2, .. }, .. } => {
                assert_matches!(arg2.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
            }
        );

        assert_matches!(
            eval.interpret(&builder().binary_app(
                BinaryOp::In,
                builder().val(EntityUID::from_normalized_str(r#"E::"e""#).unwrap()),
                builder().var(Var::Resource)
            )),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(false)),
                    ..
                },
                ..
            }
        );

        // LHS of `in` has unknown ancestors
        assert_matches!(
            eval.interpret(&builder().binary_app(
                BinaryOp::In,
                builder().val(EntityUID::from_normalized_str(r#"E::"f""#).unwrap()),
                builder().var(Var::Resource)
            )),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::In, arg1, arg2 }, .. } => {
                assert_matches!(arg1.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
                assert_matches!(arg2.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );

        // LHS of `in` is not in the entities
        assert_matches!(
            eval.interpret(&builder().binary_app(
                BinaryOp::In,
                builder().val(EntityUID::from_normalized_str(r#"E::"a""#).unwrap()),
                builder().var(Var::Resource)
            )),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::In, arg1, arg2 }, .. } => {
                assert_matches!(arg1.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
                assert_matches!(arg2.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );

        assert_matches!(
            eval.interpret(&builder().binary_app(
                BinaryOp::HasTag,
                builder().var(Var::Resource),
                builder().val("s")
            )),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );

        assert_matches!(
            eval.interpret(&builder().binary_app(
                BinaryOp::GetTag,
                builder().var(Var::Resource),
                builder().val("s")
            )),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::String(s)),
                    ..
                },
                ..
            } => {
                assert_eq!(s, "bar");
            }
        );

        // LHS of hasTag/getTag has unknown tags
        assert_matches!(
            eval.interpret(&builder().binary_app(
                BinaryOp::HasTag,
                builder().val(EntityUID::from_normalized_str(r#"E::"e""#).unwrap()),
                builder().val("s")
            )),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::HasTag, arg1, .. }, .. } => {
                assert_matches!(arg1.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );

        // LHS of hasTag/getTag is not in the entities
        assert_matches!(
            eval.interpret(&builder().binary_app(
                BinaryOp::HasTag,
                builder().val(EntityUID::from_normalized_str(r#"E::"a""#).unwrap()),
                builder().val("s")
            )),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::HasTag, arg1, .. }, .. } => {
                assert_matches!(arg1.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );
    }
}
