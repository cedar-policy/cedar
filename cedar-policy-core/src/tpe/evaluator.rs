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

use crate::{
    ast::{self, BinaryOp, EntityUID, PartialValue, Set, Value, ValueKind, Var},
    evaluator::stack_size_check,
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
    pub(crate) request: &'e PartialRequest,
    pub(crate) entities: &'e PartialEntities,
    pub(crate) extensions: &'e Extensions<'e>,
}

impl Evaluator<'_> {
    /// Interpret a typed expression into a residual
    /// This function always succeeds because it wraps an error encountered
    /// into a `ResidualKind::Error`
    #[expect(clippy::cognitive_complexity, reason = "experimental feature")]
    pub fn interpret(&self, r: &Residual) -> Residual {
        let kind = match r {
            Residual::Concrete { .. } => {
                return r.clone();
            }
            Residual::Error(_) => {
                return r.clone();
            }
            Residual::Partial { kind, .. } => kind,
        };
        // Do not define a ty variable in this scope, to avoid ambiguity, but instead propagate the ty in the return value,
        // the type does not change during evaluation.
        let mk_error = || Residual::Error(r.ty().clone());
        let mk_residual = |kind: ResidualKind| Residual::Partial {
            kind,
            ty: r.ty().clone(),
        };
        let mk_concrete = |v: Value| Residual::Concrete {
            value: v,
            ty: r.ty().clone(),
        };

        // Guard against stack overflows (just like the concrete evaluator), given the recursive nature of interpret
        match stack_size_check() {
            Ok(_) => (),
            Err(_) => return mk_error(),
        }

        match kind {
            ResidualKind::Var(Var::Action) => mk_concrete(self.request.action.clone().into()),
            ResidualKind::Var(Var::Principal) => {
                if let Ok(principal) = EntityUID::try_from(self.request.principal.clone()) {
                    mk_concrete(principal.into())
                } else {
                    mk_residual(ResidualKind::Var(Var::Principal))
                }
            }
            ResidualKind::Var(Var::Resource) => {
                if let Ok(resource) = EntityUID::try_from(self.request.resource.clone()) {
                    mk_concrete(resource.into())
                } else {
                    mk_residual(ResidualKind::Var(Var::Resource))
                }
            }
            ResidualKind::Var(Var::Context) => {
                if let Some(context) = &self.request.context {
                    mk_concrete(Value::record_arc(context.clone(), None))
                } else {
                    mk_residual(ResidualKind::Var(Var::Context))
                }
            }
            ResidualKind::And { left, right } => {
                let left = self.interpret(left);
                match &left {
                    Residual::Concrete { value, .. } => match value.get_as_bool() {
                        Ok(false) => mk_concrete(false.into()), // false && <right> => false
                        Ok(true) => self.interpret(right),      // true && <right> => <right>
                        Err(_) => mk_error(),                   // <error> && <right> => <error>
                    },
                    Residual::Partial { .. } => {
                        let right = self.interpret(right);
                        match &right {
                            Residual::Concrete {
                                value:
                                    Value {
                                        value: ValueKind::Lit(ast::Literal::Bool(true)),
                                        ..
                                    },
                                ..
                            } => left, // <left-residual> && true => <left-residual>
                            Residual::Concrete {
                                value:
                                    Value {
                                        value: ValueKind::Lit(ast::Literal::Bool(false)),
                                        ..
                                    },
                                ..
                            } => {
                                if !left.can_error_assuming_well_formed() {
                                    // simplify <error-free> && false == false
                                    mk_concrete(false.into())
                                } else {
                                    // cannot simplify <non-error-free> && false
                                    mk_residual(ResidualKind::And {
                                        left: Arc::new(left),
                                        right: Arc::new(mk_concrete(false.into())),
                                    })
                                }
                            }
                            _ => mk_residual(ResidualKind::And {
                                left: Arc::new(left),
                                right: Arc::new(right),
                            }),
                        }
                    }
                    Residual::Error(_) => mk_error(),
                }
            }
            ResidualKind::Or { left, right } => {
                let left = self.interpret(left);
                match &left {
                    Residual::Concrete { value, .. } => match value.get_as_bool() {
                        Ok(true) => mk_concrete(true.into()), // true || <right> => true
                        Ok(false) => self.interpret(right),   // false || <right> => <right>
                        Err(_) => mk_error(),                 // <error> || <right> => <error>
                    },
                    Residual::Partial { .. } => {
                        let right = self.interpret(right);
                        match &right {
                            Residual::Concrete {
                                value:
                                    Value {
                                        value: ValueKind::Lit(ast::Literal::Bool(false)),
                                        ..
                                    },
                                ..
                            } => left, // <left-residual> || false == <left-residual>
                            Residual::Concrete {
                                value:
                                    Value {
                                        value: ValueKind::Lit(ast::Literal::Bool(true)),
                                        ..
                                    },
                                ..
                            } => {
                                if !left.can_error_assuming_well_formed() {
                                    // simplify <error-free> || true == true
                                    mk_concrete(true.into())
                                } else {
                                    // cannot simplify <non-error-free> || true
                                    mk_residual(ResidualKind::Or {
                                        left: Arc::new(left),
                                        right: Arc::new(mk_concrete(true.into())),
                                    })
                                }
                            }
                            _ => mk_residual(ResidualKind::Or {
                                left: Arc::new(left),
                                right: Arc::new(right),
                            }),
                        }
                    }
                    Residual::Error(_) => mk_error(),
                }
            }
            ResidualKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                let test_expr = self.interpret(test_expr);
                match &test_expr {
                    Residual::Concrete { value, .. } => match value.get_as_bool() {
                        Ok(true) => self.interpret(then_expr), // (if true then <then> else <else>) => <then>
                        Ok(false) => self.interpret(else_expr), // (if false then <then> else <else>) => <else>
                        Err(_) => mk_error(), // (if <error> then <then> else <else>) => <error>
                    },
                    Residual::Partial { .. } => mk_residual(ResidualKind::If {
                        test_expr: Arc::new(test_expr),
                        then_expr: Arc::new(self.interpret(then_expr)),
                        else_expr: Arc::new(self.interpret(else_expr)),
                    }),
                    Residual::Error(_) => mk_error(),
                }
            }
            ResidualKind::Is { expr, entity_type } => {
                let expr = self.interpret(expr);
                match &expr {
                    Residual::Concrete { value, .. } => match value.get_as_entity() {
                        Ok(uid) => mk_concrete((uid.entity_type() == entity_type).into()),
                        Err(_) => mk_error(), // <error> is <entity_type> => <error>
                    },
                    Residual::Partial {
                        kind: ResidualKind::Var(Var::Principal),
                        ..
                    } => mk_concrete((entity_type == &self.request.principal.ty).into()),
                    Residual::Partial {
                        kind: ResidualKind::Var(Var::Resource),
                        ..
                    } => mk_concrete((entity_type == &self.request.resource.ty).into()),
                    Residual::Partial { .. } => mk_residual(ResidualKind::Is {
                        expr: Arc::new(expr),
                        entity_type: entity_type.clone(),
                    }),
                    Residual::Error(_) => mk_error(),
                }
            }
            ResidualKind::Like { expr, pattern } => {
                let expr = self.interpret(expr);
                match &expr {
                    Residual::Concrete { value, .. } => match value.get_as_string() {
                        Ok(s) => mk_concrete(pattern.wildcard_match(s).into()),
                        Err(_) => mk_error(), // <error> like <pattern> => <error>
                    },
                    Residual::Partial { .. } => mk_residual(ResidualKind::Like {
                        expr: Arc::new(expr),
                        pattern: pattern.clone(),
                    }),
                    Residual::Error(_) => mk_error(),
                }
            }
            ResidualKind::BinaryApp { op, arg1, arg2 } => {
                let arg1 = self.interpret(arg1);
                let arg2 = self.interpret(arg2);
                let binapp_residual = |arg1, arg2| {
                    mk_residual(ResidualKind::BinaryApp {
                        op: *op,
                        arg1: Arc::new(arg1),
                        arg2: Arc::new(arg2),
                    })
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
                                mk_concrete(v)
                            } else {
                                mk_error()
                            }
                        }
                        BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => {
                            if let Ok(v) =
                                crate::evaluator::binary_arith(*op, v1.clone(), v2.clone(), None)
                            {
                                mk_concrete(v)
                            } else {
                                mk_error()
                            }
                        }
                        BinaryOp::In => {
                            if let Ok(uid1) = v1.get_as_entity() {
                                if let Ok(uid2) = v2.get_as_entity() {
                                    if uid1 == uid2 {
                                        return mk_concrete(true.into());
                                    } else if let Some(entity) = self.entities.get(uid1) {
                                        if let Some(ancestors) = &entity.ancestors {
                                            return mk_concrete(ancestors.contains(uid2).into());
                                        }
                                    }
                                    binapp_residual(arg1, arg2)
                                } else if let Ok(s) = v2.get_as_set() {
                                    if let Ok(uids) = s
                                        .iter()
                                        .map(Value::get_as_entity)
                                        .collect::<std::result::Result<Vec<_>, _>>()
                                    {
                                        for uid2 in uids {
                                            if uid1 == uid2 {
                                                return mk_concrete(true.into());
                                            } else if let Some(entity) = self.entities.get(uid1) {
                                                if let Some(ancestors) = &entity.ancestors {
                                                    if ancestors.contains(uid2) {
                                                        return mk_concrete(true.into());
                                                    }
                                                } else {
                                                    return binapp_residual(arg1, arg2);
                                                }
                                            } else {
                                                return binapp_residual(arg1, arg2);
                                            }
                                        }
                                        mk_concrete(false.into())
                                    } else {
                                        mk_error()
                                    }
                                } else {
                                    mk_error()
                                }
                            } else {
                                mk_error()
                            }
                        }
                        BinaryOp::GetTag => {
                            if let Ok(uid) = v1.get_as_entity() {
                                if let Ok(tag) = v2.get_as_string() {
                                    if let Some(entity) = self.entities.get(uid) {
                                        if let Some(tags) = &entity.tags {
                                            if let Some(v) = tags.get(tag) {
                                                mk_concrete(v.clone())
                                            } else {
                                                mk_error()
                                            }
                                        } else {
                                            binapp_residual(arg1, arg2)
                                        }
                                    } else {
                                        binapp_residual(arg1, arg2)
                                    }
                                } else {
                                    mk_error()
                                }
                            } else {
                                mk_error()
                            }
                        }
                        BinaryOp::HasTag => {
                            if let Ok(uid) = v1.get_as_entity() {
                                if let Ok(tag) = v2.get_as_string() {
                                    if let Some(entity) = self.entities.get(uid) {
                                        if let Some(tags) = &entity.tags {
                                            mk_concrete(tags.contains_key(tag).into())
                                        } else {
                                            binapp_residual(arg1, arg2)
                                        }
                                    } else {
                                        binapp_residual(arg1, arg2)
                                    }
                                } else {
                                    mk_error()
                                }
                            } else {
                                mk_error()
                            }
                        }
                        BinaryOp::Contains => match &v1.value {
                            ValueKind::Set(s) => mk_concrete(s.contains(v2).into()),
                            _ => mk_error(),
                        },
                        BinaryOp::ContainsAll => match (v1.get_as_set(), v2.get_as_set()) {
                            (Ok(arg1_set), Ok(arg2_set)) => {
                                mk_concrete(arg2_set.is_subset(arg1_set).into())
                            }
                            _ => mk_error(),
                        },
                        BinaryOp::ContainsAny => match (v1.get_as_set(), v2.get_as_set()) {
                            (Ok(arg1_set), Ok(arg2_set)) => {
                                mk_concrete((!arg1_set.is_disjoint(arg2_set)).into())
                            }
                            _ => mk_error(),
                        },
                    },
                    (Residual::Error(_), _) => mk_error(),
                    (_, Residual::Error(_)) => mk_error(),
                    (_, _) => binapp_residual(arg1, arg2),
                }
            }
            ResidualKind::ExtensionFunctionApp { fn_name, args } => {
                let args = args.iter().map(|a| self.interpret(a)).collect::<Vec<_>>();
                // If the arguments are all concrete values, we proceed to
                // evaluate the function call
                if let Ok(vals) = args
                    .iter()
                    .map(|a| Value::try_from(a.clone()))
                    .collect::<std::result::Result<Vec<_>, _>>()
                {
                    // Attempt to look up the extension function and apply it
                    // Failed lookup or application errors both lead to
                    // `Residual::Error` of appropriate types
                    if let Ok(ext_fn) = self.extensions.func(fn_name) {
                        if let Ok(PartialValue::Value(value)) = ext_fn.call(&vals) {
                            return mk_concrete(normalize_ext_value(value));
                        }
                    }
                    mk_error()
                } else if args.iter().any(|r| matches!(r, Residual::Error(_))) {
                    mk_error()
                } else {
                    mk_residual(ResidualKind::ExtensionFunctionApp {
                        fn_name: fn_name.clone(),
                        args: Arc::new(args),
                    })
                }
            }
            ResidualKind::GetAttr { expr, attr } => {
                let expr = self.interpret(expr);
                match &expr {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Record(r),
                                ..
                            },
                        ..
                    } => {
                        if let Some(val) = r.as_ref().get(attr) {
                            mk_concrete(val.clone())
                        } else {
                            mk_error()
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
                        if let Some(entity) = self.entities.get(uid.as_ref()) {
                            if let Some(attrs) = &entity.attrs {
                                if let Some(val) = attrs.get(attr) {
                                    return mk_concrete(val.clone());
                                } else {
                                    return mk_error();
                                }
                            }
                        }
                        mk_residual(ResidualKind::GetAttr {
                            expr: Arc::new(expr),
                            attr: attr.clone(),
                        })
                    }
                    Residual::Concrete { .. } => mk_error(),
                    Residual::Partial { .. } => mk_residual(ResidualKind::GetAttr {
                        expr: Arc::new(expr),
                        attr: attr.clone(),
                    }),
                    Residual::Error(_) => mk_error(),
                }
            }
            ResidualKind::HasAttr { expr, attr } => {
                let expr = self.interpret(expr);
                match &expr {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Record(r),
                                ..
                            },
                        ..
                    } => mk_concrete(r.as_ref().contains_key(attr).into()),
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::EntityUID(uid)),
                                ..
                            },
                        ..
                    } => {
                        if let Some(entity) = self.entities.get(uid.as_ref()) {
                            if let Some(attrs) = &entity.attrs {
                                return mk_concrete(attrs.contains_key(attr).into());
                            }
                        }
                        mk_residual(ResidualKind::HasAttr {
                            expr: Arc::new(expr),
                            attr: attr.clone(),
                        })
                    }
                    Residual::Concrete { .. } => mk_error(),
                    Residual::Partial { .. } => mk_residual(ResidualKind::HasAttr {
                        expr: Arc::new(expr),
                        attr: attr.clone(),
                    }),
                    Residual::Error(_) => mk_error(),
                }
            }
            ResidualKind::UnaryApp { op, arg } => {
                let arg = self.interpret(arg);
                match arg {
                    Residual::Concrete { value, .. } => {
                        if let Ok(v) = crate::evaluator::unary_app(*op, value, None) {
                            mk_concrete(v)
                        } else {
                            mk_error()
                        }
                    }
                    Residual::Partial { .. } => mk_residual(ResidualKind::UnaryApp {
                        op: *op,
                        arg: Arc::new(arg),
                    }),
                    Residual::Error(_) => mk_error(),
                }
            }
            ResidualKind::Set(es) => {
                let es = es.iter().map(|a| self.interpret(a)).collect::<Vec<_>>();
                if let Ok(vals) = es
                    .iter()
                    .map(|a| Value::try_from(a.clone()))
                    .collect::<std::result::Result<Vec<_>, _>>()
                {
                    mk_concrete(Value {
                        value: ValueKind::Set(Set::new(vals)),
                        loc: None,
                    })
                } else if es.iter().any(|r| matches!(r, Residual::Error(_))) {
                    mk_error()
                } else {
                    mk_residual(ResidualKind::Set(Arc::new(es)))
                }
            }
            ResidualKind::Record(m) => {
                let record = m
                    .as_ref()
                    .iter()
                    .map(|(a, e)| (a.clone(), self.interpret(e)));
                if let Ok(m) = record
                    .clone()
                    .map(|(a, r)| Ok((a, Value::try_from(r)?)))
                    .collect::<std::result::Result<BTreeMap<_, _>, ()>>()
                {
                    mk_concrete(Value {
                        value: ValueKind::Record(Arc::new(m)),
                        loc: None,
                    })
                } else {
                    let mut m = BTreeMap::new();
                    for (a, r) in record {
                        if matches!(r, Residual::Error(_)) {
                            return mk_error();
                        } else {
                            m.insert(a, r);
                        }
                    }
                    mk_residual(ResidualKind::Record(Arc::new(m)))
                }
            }
        }
    }
}

/// If the value is an extension value whose type provides a [`canonical_repr`],
/// rebuild the [`RepresentableExtensionValue`] so that the stored `func`/`args`
/// match the canonical form.  This ensures TPE residuals are deterministic
/// regardless of which constructor originally created the value.
fn normalize_ext_value(value: Value) -> Value {
    match &value.value {
        ValueKind::ExtensionValue(ev) => {
            if let Some((func, args)) = ev.value().canonical_repr() {
                Value {
                    value: ValueKind::ExtensionValue(Arc::new(
                        ast::RepresentableExtensionValue::new(ev.value.clone(), func, args),
                    )),
                    loc: value.loc,
                }
            } else {
                value
            }
        }
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};

    use crate::ast::{Expr, SlotEnv, UnwrapInfallible};
    use crate::tpe::err::ExprToResidualError;
    use crate::validator::types::Type;
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
    use itertools::Itertools;

    use crate::{
        tpe::entities::{PartialEntities, PartialEntity},
        tpe::request::{PartialEntityUID, PartialRequest},
        tpe::residual::{Residual, ResidualKind},
    };

    use super::Evaluator;

    #[track_caller]
    fn action() -> EntityUID {
        r#"Action::"a""#.parse().unwrap()
    }

    #[track_caller]
    fn dummy_uid() -> EntityUID {
        r#"E::"""#.parse().unwrap()
    }

    impl Evaluator<'_> {
        /// Interpret a typed expression by converting to a [`Residual`] with an empty slot environment.
        ///
        /// This is a test-only utility because other callers should generally
        /// be interpreting a residual with slots bounds appropriately by
        /// `policy_residual_map` or else explicitly bindings slots (with an
        /// empty environment or otherwise).
        fn interpret_expr(&self, e: &Expr<Option<Type>>) -> Result<Residual, ExprToResidualError> {
            Ok(self.interpret(&Residual::try_from_typed_expr(e, &SlotEnv::new())?))
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        // principal -> principal because its eid is unknown
        assert_matches!(
            eval.interpret_expr(&builder().var(Var::Principal)).unwrap(),
            Residual::Partial {
                kind: ResidualKind::Var(Var::Principal),
                ..
            }
        );
        // resource -> E::""
        assert_matches!(
            eval.interpret_expr(&builder().var(Var::Resource)).unwrap(),
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
            eval.interpret_expr(&builder().var(Var::Action)).unwrap(),
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
            eval.interpret_expr(&builder().var(Var::Context)).unwrap(),
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret_expr(&builder().and(
                builder().noteq(builder().var(Var::Resource), builder().var(Var::Resource)),
                builder().val(42)
            ))
            .unwrap(),
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
            eval.interpret_expr(&builder().and(builder().var(Var::Principal), builder().val(true)))
                .unwrap(),
            Residual::Partial {
                kind: ResidualKind::Var(Var::Principal),
                ..
            }
        );
        assert_matches!(
            eval.interpret_expr(&builder().and(
                builder().noteq(
                    builder().mul(builder().val(i64::MAX), builder().val(2)),
                    builder().val(0)
                ),
                builder().val(42)
            ))
            .unwrap(),
            Residual::Error(_),
        );
        // resource == resource && 42 => 42
        // Note that this expression is not an invalid input
        // The evaluator does not perform any validation
        assert_matches!(
            eval.interpret_expr(&builder().and(
                builder().binary_app(
                    BinaryOp::Eq,
                    builder().var(Var::Resource),
                    builder().var(Var::Resource)
                ),
                builder().val(42)
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Long(42)),
                    ..
                },
                ..
            }
        );
        // <error-free> && false => false
        // principal in Organization::"foo" && 41 == 42 => false
        assert_matches!(
            eval.interpret_expr(&builder().and(
                builder().is_in(
                    builder().var(Var::Principal),
                    builder().val(EntityUID::with_eid_and_type("Organization", "foo").unwrap())
                ),
                builder().is_eq(builder().val(41), builder().val(42))
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(false)),
                    ..
                },
                ..
            },
        );
        // <non-error-free> && false cannot be simplified, e.g.
        // principal.foo + 1 == 100 && 41 == 42
        assert_matches!(
            eval.interpret_expr(&builder().and(
                builder().is_eq(
                    builder().add(
                        builder().get_attr(builder().var(Var::Principal), "foo".parse().unwrap()),
                        builder().val(1)
                    ),
                    builder().val(100)
                ),
                builder().is_eq(builder().val(41), builder().val(42))
            ))
            .unwrap(),
            // cannot match against the full residual, because of the Arc in the And enum variant,
            // and due to Residual not implementing the Eq trait, but this shows that the evaluator
            // kept the residual partial and with an And clause.
            Residual::Partial {
                kind: ResidualKind::And { .. },
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret_expr(&builder().or(
                builder().binary_app(
                    BinaryOp::Eq,
                    builder().var(Var::Resource),
                    builder().var(Var::Resource)
                ),
                builder().val(42)
            ))
            .unwrap(),
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
            eval.interpret_expr(&builder().or(builder().var(Var::Principal), builder().val(false)))
                .unwrap(),
            Residual::Partial {
                kind: ResidualKind::Var(Var::Principal),
                ..
            }
        );
        assert_matches!(
            eval.interpret_expr(&builder().or(
                builder().noteq(
                    builder().mul(builder().val(i64::MAX), builder().val(2)),
                    builder().val(0)
                ),
                builder().val(42)
            ))
            .unwrap(),
            Residual::Error(_),
        );
        // resource != resource || 42 => 42
        // Note that this expression is not an invalid input
        // The evaluator does not perform any validation
        assert_matches!(
            eval.interpret_expr(&builder().or(
                builder().noteq(builder().var(Var::Resource), builder().var(Var::Resource)),
                builder().val(42)
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Long(42)),
                    ..
                },
                ..
            }
        );
        // <error-free> || true => true
        // principal || 42 == 42 => true
        assert_matches!(
            eval.interpret_expr(&builder().or(
                builder().has_attr(builder().var(Var::Principal), "foo".into()),
                builder().is_eq(builder().val(42), builder().val(42))
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            },
        );
        // <non-error-free> || true cannot be simplified, e.g.
        // principal.foo + 1 == 100 || 42 == 42
        assert_matches!(
            eval.interpret_expr(&builder().or(
                builder().is_eq(
                    builder().add(
                        builder().get_attr(builder().var(Var::Principal), "foo".parse().unwrap()),
                        builder().val(1)
                    ),
                    builder().val(100)
                ),
                builder().is_eq(builder().val(42), builder().val(42))
            ))
            .unwrap(),
            // cannot match against the full residual, because of the Arc in the Or enum variant,
            // and due to Residual not implementing the Eq trait, but this shows that the evaluator
            // kept the residual partial and with an Or clause.
            Residual::Partial {
                kind: ResidualKind::Or { .. },
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret_expr(&builder().ite(
                builder().is_eq(builder().var(Var::Action), builder().var(Var::Action)),
                builder().var(Var::Principal),
                builder().val(2)
            ))
            .unwrap(),
            Residual::Partial {
                kind: ResidualKind::Var(Var::Principal),
                ..
            }
        );
        assert_matches!(
            eval.interpret_expr(&builder().ite(
                builder().is_eq(builder().var(Var::Principal), builder().var(Var::Principal)),
                builder().var(Var::Principal),
                builder().val(2)
            )).unwrap(),
            Residual::Partial {
                kind: ResidualKind::If { test_expr, then_expr, else_expr },
                ..
            } => {
                assert_matches!(test_expr.as_ref(), Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::Eq, .. }, .. });
                assert_matches!(then_expr.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
                assert_matches!(else_expr.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::Long(2)), .. }, .. });
            }
        );
        assert_matches!(
            eval.interpret_expr(&builder().ite(
                builder().val(false),
                builder().var(Var::Principal),
                builder().val(2)
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Long(2)),
                    ..
                },
                ..
            }
        );
        assert_matches!(
            eval.interpret_expr(&builder().ite(
                builder().is_eq(
                    builder().mul(builder().val(i64::MAX), builder().val(2)),
                    builder().val(0)
                ),
                builder().var(Var::Principal),
                builder().val(2)
            ))
            .unwrap(),
            Residual::Error(_),
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret_expr(&builder().is_entity_type(
                builder().var(Var::Resource),
                dummy_uid().entity_type().clone()
            ))
            .unwrap(),
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
            eval.interpret_expr(&builder().is_entity_type(
                builder().var(Var::Principal),
                dummy_uid().entity_type().clone()
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );
        assert_matches!(
            eval.interpret_expr(&builder().is_entity_type(
                builder().get_attr(builder().var(Var::Resource), "baz".parse().unwrap()),
                dummy_uid().entity_type().clone()
            ))
            .unwrap(),
            Residual::Partial {
                kind: ResidualKind::Is { expr, entity_type } ,
                ..
            } => {
                assert_matches!(expr.as_ref(), Residual::Partial { kind: ResidualKind::GetAttr { .. }, .. });
                assert_eq!(&entity_type, dummy_uid().entity_type());
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret_expr(&builder().like(
                builder().val("aaa"),
                Pattern::from(vec![PatternElem::Char('a'), PatternElem::Wildcard])
            ))
            .unwrap(),
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
            eval.interpret_expr(&builder().like(builder().var(Var::Principal), Pattern::from(vec![PatternElem::Char('a'), PatternElem::Wildcard]))).unwrap(),
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret_expr(&builder().unary_app(UnaryOp::Neg, builder().val(42)))
                .unwrap(),
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
            eval.interpret_expr(&builder().unary_app(UnaryOp::Neg, builder().var(Var::Principal))).unwrap(),
            Residual::Partial { kind: ResidualKind::UnaryApp { op: UnaryOp::Neg, arg }, .. } => {
                assert_matches!(arg.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
            }
        );
        assert_matches!(
            eval.interpret_expr(&builder().unary_app(UnaryOp::Neg, builder().val(i64::MIN)))
                .unwrap(),
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
        let entities = PartialEntities::from_entities_unchecked(
            [
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
            ]
            .into_iter(),
        );
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret_expr(&builder().get_attr(builder().var(Var::Resource), "s".parse().unwrap())).unwrap(),
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
            eval.interpret_expr(&builder().get_attr(
                builder().var(Var::Principal),
                "s".parse().unwrap()
            )).unwrap(),
            Residual::Partial { kind: ResidualKind::GetAttr { expr, .. }, .. } => {
                assert_matches!(expr.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
            }
        );
        // When LHS is not in the entities, the entire expression is unknown
        assert_matches!(
            eval.interpret_expr(&builder().get_attr(
                builder().val(EntityUID::from_normalized_str(r#"E::"f""#).unwrap()),
                "s".parse().unwrap()
            )).unwrap(),
            Residual::Partial { kind: ResidualKind::GetAttr { expr, .. }, .. } => {
                assert_matches!(expr.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );
        // When LHS is in the entities, but its attributes are `None`, the
        // entire expression is unknown
        assert_matches!(
            eval.interpret_expr(&builder().get_attr(
                builder().val(EntityUID::from_normalized_str(r#"E::"e""#).unwrap()),
                "s".parse().unwrap()
            )).unwrap(),
            Residual::Partial { kind: ResidualKind::GetAttr { expr, .. }, .. } => {
                assert_matches!(expr.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );
        assert_matches!(
            eval.interpret_expr(
                &builder().get_attr(builder().var(Var::Resource), "baz".parse().unwrap())
            )
            .unwrap(),
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
        let entities = PartialEntities::from_entities_unchecked(
            [
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
            ]
            .into_iter(),
        );
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret_expr(
                &builder().has_attr(builder().var(Var::Resource), "s".parse().unwrap())
            )
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );
        assert_matches!(
            eval.interpret_expr(&builder().has_attr(builder().var(Var::Principal), "s".parse().unwrap())).unwrap(),
            Residual::Partial {
                kind: ResidualKind::HasAttr { expr, .. },
                ..
            } => {
                assert_matches!(expr.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
            }
        );
        // When LHS is not in the entities, the entire expression is unknown
        assert_matches!(
            eval.interpret_expr(&builder().has_attr(
                builder().val(EntityUID::from_normalized_str(r#"E::"f""#).unwrap()),
                "s".parse().unwrap()
            )).unwrap(),
            Residual::Partial { kind: ResidualKind::HasAttr { expr, .. }, .. } => {
                assert_matches!(expr.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );
        // When LHS is in the entities, but its attributes are `None`, the
        // entire expression is unknown
        assert_matches!(
            eval.interpret_expr(&builder().has_attr(
                builder().val(EntityUID::from_normalized_str(r#"E::"e""#).unwrap()),
                "s".parse().unwrap()
            )).unwrap(),
            Residual::Partial { kind: ResidualKind::HasAttr { expr, .. }, .. } => {
                assert_matches!(expr.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );

        assert_matches!(
            eval.interpret_expr(&builder().has_attr(
                builder().record([("s".into(), builder().val(0))]).unwrap(),
                "s".parse().unwrap()
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );
        assert_matches!(
            eval.interpret_expr(&builder().has_attr(
                builder().record([("s".into(), builder().val(0))]).unwrap(),
                "t".parse().unwrap()
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(false)),
                    ..
                },
                ..
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret_expr(&builder().set(
                [builder().var(Var::Resource)]
            )).unwrap(),
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
            eval.interpret_expr(&builder().set(
                [builder().var(Var::Principal),
                builder().var(Var::Resource),]
            )).unwrap(),
            Residual::Partial {
                kind: ResidualKind::Set(s),
                ..
            } => {
                assert_matches!(s.as_ref().as_slice(), [Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. }, Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. }]);
            }
        );

        // Error is propagated
        assert_matches!(
            eval.interpret_expr(&builder().set([
                builder().neg(builder().val(i64::MIN)),
                builder().var(Var::Resource),
            ]))
            .unwrap(),
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret_expr(&builder().record(
                [(
                    "s".into(),
                    builder().var(Var::Resource),
                )]
            ).unwrap()).unwrap(),
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
            eval.interpret_expr(&builder().record(
                [(
                    "s".into(),
                    builder().var(Var::Principal),
                )]
            ).unwrap()).unwrap(),
            Residual::Partial {
                kind: ResidualKind::Record(m),
                ..
            } => {
                assert_matches!(m.as_ref().get("s"), Some(Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. }));
            }
        );

        // Error is propagated
        assert_matches!(
            eval.interpret_expr(
                &builder()
                    .record([
                        ("s".into(), builder().neg(builder().val(i64::MIN)),),
                        ("".into(), builder().var(Var::Resource),)
                    ])
                    .unwrap()
            )
            .unwrap(),
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        assert_matches!(
            eval.interpret_expr(
                &builder()
                    .call_extension_fn("decimal".parse().unwrap(), [builder().val("0.0")])
                    .unwrap_infallible()
            )
            .unwrap(),
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
            eval.interpret_expr(&builder().call_extension_fn(
                "decimal".parse().unwrap(),
                [builder().var(Var::Principal)]
            ).unwrap_infallible()).unwrap(),
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
            eval.interpret_expr(
                &builder()
                    .call_extension_fn(
                        "decimal".parse().unwrap(),
                        [builder().neg(builder().val(i64::MIN))]
                    )
                    .unwrap_infallible()
            )
            .unwrap(),
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
        let entities = PartialEntities::from_entities_unchecked(
            [
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
            ]
            .into_iter(),
        );
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };

        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::Eq,
                builder().var(Var::Resource),
                builder().val(dummy_uid())
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );

        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::Eq,
                builder().var(Var::Principal),
                builder().val(dummy_uid())
            )).unwrap(),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::Eq, arg1, .. }, .. } => {
                assert_matches!(arg1.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
            }
        );

        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::Add,
                builder().val(i64::MAX),
                builder().val(i64::MAX)
            ))
            .unwrap(),
            Residual::Error(_)
        );

        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::Add,
                builder().val(1),
                builder().val(1)
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Long(2)),
                    ..
                },
                ..
            }
        );

        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::Contains,
                builder().set([builder().val(dummy_uid())]),
                builder().var(Var::Resource)
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );

        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::Contains,
                builder().set([builder().val(dummy_uid())]),
                builder().var(Var::Principal)
            )).unwrap(),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::Contains, arg2, .. }, .. } => {
                assert_matches!(arg2.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
            }
        );

        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::In,
                builder().val(EntityUID::from_normalized_str(r#"E::"e""#).unwrap()),
                builder().var(Var::Resource)
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(false)),
                    ..
                },
                ..
            }
        );

        assert_matches!(
            eval.interpret_expr(
                &builder().binary_app(
                    BinaryOp::In,
                    builder().val(EntityUID::from_normalized_str(r#"E::"""#).unwrap()),
                    builder().set([
                        builder().val(EntityUID::from_normalized_str(r#"E::"e""#).unwrap()),
                    ])
                )
            )
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );

        // LHS of `in` has unknown ancestors
        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::In,
                builder().val(EntityUID::from_normalized_str(r#"E::"f""#).unwrap()),
                builder().var(Var::Resource)
            )).unwrap(),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::In, arg1, arg2 }, .. } => {
                assert_matches!(arg1.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
                assert_matches!(arg2.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );

        // LHS of `in` is not in the entities
        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::In,
                builder().val(EntityUID::from_normalized_str(r#"E::"a""#).unwrap()),
                builder().var(Var::Resource)
            )).unwrap(),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::In, arg1, arg2 }, .. } => {
                assert_matches!(arg1.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
                assert_matches!(arg2.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );

        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::HasTag,
                builder().var(Var::Resource),
                builder().val("s")
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );

        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::GetTag,
                builder().var(Var::Resource),
                builder().val("s")
            )).unwrap(),
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
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::HasTag,
                builder().val(EntityUID::from_normalized_str(r#"E::"e""#).unwrap()),
                builder().val("s")
            )).unwrap(),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::HasTag, arg1, .. }, .. } => {
                assert_matches!(arg1.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );

        // LHS of hasTag/getTag is not in the entities
        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::HasTag,
                builder().val(EntityUID::from_normalized_str(r#"E::"a""#).unwrap()),
                builder().val("s")
            )).unwrap(),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::HasTag, arg1, .. }, .. } => {
                assert_matches!(arg1.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
            }
        );
    }

    // Test containsAll/containsAny operations
    #[test]
    fn test_set_ops() {
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };

        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::ContainsAll,
                builder().set([builder().val(true), builder().val(false)]),
                builder().set([builder().val(true), builder().val(true)])
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );

        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::ContainsAll,
                builder().set([builder().val(true), builder().binary_app(BinaryOp::Eq, builder().var(Var::Principal), builder().var(Var::Resource))]),
                builder().set([builder().val(true), builder().val(true)])
            )).unwrap(),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::ContainsAll, arg1, arg2 }, .. } => {
                assert_matches!(arg1.as_ref(), Residual::Partial { kind: ResidualKind::Set(s), ..} => {
                    assert_matches!(s.as_slice(), [Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::Bool(true)), .. }, .. }, Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::Eq, arg1, arg2 }, .. }] => {
                        assert_matches!(arg2.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
                        assert_matches!(arg1.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
                    })
                } );
                assert_matches!(arg2.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Set(s), .. }, .. } => {
                    assert_eq!(s.iter().collect_vec(), [&Value::from(true)]);
                });
            }
        );

        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::ContainsAny,
                builder().set([builder().val(true), builder().val(false)]),
                builder().set([builder().val(true), builder().val(true)])
            ))
            .unwrap(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(true)),
                    ..
                },
                ..
            }
        );

        assert_matches!(
            eval.interpret_expr(&builder().binary_app(
                BinaryOp::ContainsAny,
                builder().set([builder().val(true), builder().binary_app(BinaryOp::Eq, builder().var(Var::Principal), builder().var(Var::Resource))]),
                builder().set([builder().val(true), builder().val(true)])
            )).unwrap(),
            Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::ContainsAny, arg1, arg2 }, .. } => {
                assert_matches!(arg1.as_ref(), Residual::Partial { kind: ResidualKind::Set(s), ..} => {
                    assert_matches!(s.as_slice(), [Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::Bool(true)), .. }, .. }, Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::Eq, arg1, arg2 }, .. }] => {
                        assert_matches!(arg2.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. }, .. });
                        assert_matches!(arg1.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Principal), .. });
                    })
                } );
                assert_matches!(arg2.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Set(s), .. }, .. } => {
                    assert_eq!(s.iter().collect_vec(), [&Value::from(true)]);
                });
            }
        );
    }

    #[test]
    fn test_datetime_residual_normalization() {
        // When the TPE evaluator evaluates datetime("6640-02-11") with all
        // concrete args, the resulting residual should use the canonical
        // offset(datetime("1970-01-01"), duration("Nms")) form — not the
        // original datetime("6640-02-11") string.
        // The Lean side will for now always produce the offset(datetime("1970-01-01"), _) repr,
        // while the Rust side representation without canonicalization can be either the
        // direct datetime or the offset from the Unix Epoch, depending on where the term
        // originated from.
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let residual = eval
            .interpret_expr(
                &builder()
                    .call_extension_fn("datetime".parse().unwrap(), [builder().val("6640-02-11")])
                    .unwrap_infallible(),
            )
            .unwrap();
        // Convert to Expr and check the top-level function is "offset"
        let expr: crate::ast::Expr = residual.into();
        assert_matches!(expr.expr_kind(), crate::ast::ExprKind::ExtensionFunctionApp { fn_name, .. } => {
            assert_eq!(fn_name.to_string(), "offset");
        });
        // String representation
        assert_eq!(
            expr.to_string(),
            r#"(datetime("1970-01-01")).offset(duration("147374467200000ms"))"#
        );
    }

    #[test]
    fn test_decimal_residual_normalization() {
        // decimal("0.0") should be normalized to decimal("0.0000") (4-digit padded)
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let residual = eval
            .interpret_expr(
                &builder()
                    .call_extension_fn("decimal".parse().unwrap(), [builder().val("0.0")])
                    .unwrap_infallible(),
            )
            .unwrap();
        let expr: crate::ast::Expr = residual.into();
        assert_eq!(expr.to_string(), r#"decimal("0.0000")"#);
    }

    #[test]
    fn test_ip_residual_normalization() {
        // ip("::1") should be normalized to include the prefix: ip("::1/128")
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let residual = eval
            .interpret_expr(
                &builder()
                    .call_extension_fn("ip".parse().unwrap(), [builder().val("::1")])
                    .unwrap_infallible(),
            )
            .unwrap();
        let expr: crate::ast::Expr = residual.into();
        assert_eq!(expr.to_string(), r#"ip("::1/128")"#);
    }

    #[test]
    fn test_duration_residual_normalization() {
        // duration("1d") should be normalized to duration("86400000ms")
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
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let residual = eval
            .interpret_expr(
                &builder()
                    .call_extension_fn("duration".parse().unwrap(), [builder().val("1d")])
                    .unwrap_infallible(),
            )
            .unwrap();
        let expr: crate::ast::Expr = residual.into();
        assert_eq!(expr.to_string(), r#"duration("86400000ms")"#);
    }
}
