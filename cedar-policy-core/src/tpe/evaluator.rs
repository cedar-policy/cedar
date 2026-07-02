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
        // Do not define a ty variable in this scope, to avoid ambiguity, but instead propagate
        // the ty in the return value, the type does not change during evaluation.
        let mk_error = || Residual::Error(r.ty().clone());
        let mk_residual = |kind: ResidualKind| Residual::Partial {
            kind,
            ty: r.ty().clone(),
        };
        let mk_concrete = |v: Value| Residual::Concrete {
            value: normalize_ext_value(v),
            ty: r.ty().clone(),
        };

        // Guard against stack overflows (just like the concrete evaluator), given the recursive
        // nature of interpret.
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
                            Residual::Concrete { value, .. } => match value.get_as_bool() {
                                // <left-residual> && true => <left-residual>
                                Ok(true) => left,
                                Ok(false) => {
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
                                // "<left-residual> && <nonbool>" => "<left-residual> && <error>"
                                // TODO(luxas): Introduce a Residual::PartialError variant that says "the expression definitely errors, but with an unknown error"
                                Err(_) => mk_residual(ResidualKind::And {
                                    left: Arc::new(left),
                                    right: Arc::new(mk_error()),
                                }),
                            },
                            // Cannot simplify "<left-residual> && <right-residual>" or "<left-residual> && <error>"
                            // The latter expression could become a Residual::PartialError later.
                            Residual::Partial { .. } | Residual::Error(_) => {
                                mk_residual(ResidualKind::And {
                                    left: Arc::new(left),
                                    right: Arc::new(right),
                                })
                            }
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
                            Residual::Concrete { value, .. } => match value.get_as_bool() {
                                // <left-residual> || false == <left-residual>
                                Ok(false) => left,
                                Ok(true) => {
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
                                // "<left-residual> || <nonbool>" => "<left-residual> || <error>"
                                // Note that this is not necessarily a Residual::PartialError, as "<left-residual>" might evaluate to true,
                                // in which case the whole expression is true, regardless of the RHS error.
                                Err(_) => mk_residual(ResidualKind::Or {
                                    left: Arc::new(left),
                                    right: Arc::new(mk_error()),
                                }),
                            },
                            // Cannot simplify "<left-residual> || <right-residual>" or "<left-residual> || <error>"
                            Residual::Partial { .. } | Residual::Error(_) => {
                                mk_residual(ResidualKind::Or {
                                    left: Arc::new(left),
                                    right: Arc::new(right),
                                })
                            }
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
    normalize_ext_value_inner(&value).unwrap_or(value)
}

/// Returns `Some(normalized)` if the value needed normalization, `None` if it was already fine.
fn normalize_ext_value_inner(value: &Value) -> Option<Value> {
    match &value.value {
        ValueKind::Lit(_) => None,
        ValueKind::ExtensionValue(ev) => {
            let (func, args) = ev.value().canonical_repr()?;
            Some(Value {
                value: ValueKind::ExtensionValue(Arc::new(ast::RepresentableExtensionValue::new(
                    ev.value.clone(),
                    func,
                    args,
                ))),
                loc: value.loc.clone(),
            })
        }
        ValueKind::Set(s) if s.fast.is_some() => {
            // due to invariant on set, this means all elements are literals, hence nothing to norm
            None
        }

        // The Set and Record normalization attempt to avoid cloning by scanning whether
        // normalization is needed. Cloning to get the normalization only happens when it is
        // actually required.
        ValueKind::Set(s) => {
            // Find the first element that needs normalization or return None.
            let (idx, normalized) = s
                .iter()
                .enumerate()
                .find_map(|(i, x)| normalize_ext_value_inner(x).map(|n| (i, n)))?;
            // Clone elements before `idx` as-is, insert the normalized one,
            // then normalize the rest.
            let vals: Vec<Value> = s
                .iter()
                .take(idx)
                .cloned()
                .chain(std::iter::once(normalized))
                .chain(
                    s.iter()
                        .skip(idx + 1)
                        .map(|v| normalize_ext_value_inner(v).unwrap_or_else(|| v.clone())),
                )
                .collect();
            Some(Value {
                value: ValueKind::Set(Set::new(vals)),
                loc: value.loc.clone(),
            })
        }
        ValueKind::Record(r) => {
            let mut iter = r.iter().enumerate();
            let (idx, key, normalized) = loop {
                let (i, (k, v)) = iter.next()?;
                if let Some(n) = normalize_ext_value_inner(v) {
                    break (i, k.clone(), n);
                }
            };
            let map: BTreeMap<_, _> = r
                .iter()
                .take(idx)
                .map(|(k, v)| (k.clone(), v.clone()))
                .chain(std::iter::once((key, normalized)))
                .chain(r.iter().skip(idx + 1).map(|(k, v)| {
                    (
                        k.clone(),
                        normalize_ext_value_inner(v).unwrap_or_else(|| v.clone()),
                    )
                }))
                .collect();
            Some(Value {
                value: ValueKind::Record(Arc::new(map)),
                loc: value.loc.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};
    use std::str::FromStr;
    use std::sync::Arc;

    use crate::ast::{Expr, SlotEnv};
    use crate::parser::parse_expr;
    use crate::tpe::err::ExprToResidualError;
    use crate::validator::typecheck::Typechecker;
    use crate::validator::types::Type;
    use crate::validator::{ValidationMode, ValidatorSchema};
    use crate::{
        ast::{Context, EntityUID, ExprBuilder, Value, Var},
        expr_builder::ExprBuilder as _,
        extensions::Extensions,
    };
    use insta::assert_snapshot;

    use crate::{
        ast,
        tpe::entities::PartialEntities,
        tpe::request::{PartialEntityUID, PartialRequest},
        tpe::residual::Residual,
    };

    use super::Evaluator;

    #[track_caller]
    fn parse_schema(src: &str) -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(src, &Extensions::all_available())
            .unwrap()
            .0
    }

    fn schema() -> ValidatorSchema {
        parse_schema(
            r#"
            entity User in Organization { foo: Bool, str: String, num: Long, period: __cedar::duration, set: Set<String> } tags String;
            entity Organization;
            entity Document in Organization;
            action get appliesTo { principal: [User], resource: [Document] };"#,
        )
    }

    fn concrete_user_req() -> PartialRequest {
        PartialRequest::new(
            concrete_euid(r#"User::"foo""#),
            r#"Action::"get""#.parse().unwrap(),
            unknown_euid("Document"),
            None,
            &schema(),
        )
        .unwrap()
    }

    #[track_caller]
    fn parse_typed_expr(
        expr_str: &str,
        request: &PartialRequest,
        schema: &ValidatorSchema,
    ) -> Expr<Option<Type>> {
        let expr = parse_expr(expr_str).unwrap();
        let policy_id = crate::ast::PolicyID::from_string("test");

        let env = request
            .find_request_env(&schema)
            .unwrap()
            .link_slot_env(&SlotEnv::new());

        let mut type_errors = HashSet::new();
        let typechecker = Typechecker::new(schema, ValidationMode::Strict);
        let ans =
            typechecker.typecheck_expr_with_request_env(&env, &expr, &policy_id, &mut type_errors);
        if !type_errors.is_empty() {
            println!("got {} type errors", type_errors.len());
            for e in type_errors {
                println!("{:?}", miette::Report::new(e));
            }
            panic!("unexpected type error in expression")
        }
        ans.into_typed_expr()
            .expect("expected typechecking to produce a typed expression")
    }

    fn concrete_euid(euid: &str) -> PartialEntityUID {
        EntityUID::from_str(euid).unwrap().into()
    }

    fn unknown_euid(ty: &str) -> PartialEntityUID {
        PartialEntityUID {
            ty: ty.parse().unwrap(),
            eid: None,
        }
    }

    #[track_caller]
    fn interpret_typed_str_to_str(
        evaluator: &Evaluator<'_>,
        expr_str: &str,
        schema: &ValidatorSchema,
    ) -> String {
        let expr = parse_typed_expr(expr_str, evaluator.request, schema);
        interpret_expr_to_str(evaluator, &expr)
    }

    #[track_caller]
    fn interpret_expr_to_str(evaluator: &Evaluator<'_>, expr: &Expr<Option<Type>>) -> String {
        let evaluated: ast::Expr = evaluator.interpret_expr(&expr).unwrap().try_into().unwrap();
        evaluated.to_string()
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
        let eval = Evaluator {
            request: &concrete_user_req(),
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema());
        // principal -> principal because its eid is unknown
        assert_snapshot!(
            interpret_typed_str_to_str("principal"),
            @r#"User::"foo""#
        );
        // resource -> E::""
        assert_snapshot!(
            interpret_typed_str_to_str("resource"),
            @"resource"
        );
        // action is always known
        assert_snapshot!(
            interpret_typed_str_to_str("action"),
            @r#"Action::"get""#
        );
        // context is always unknown
        assert_snapshot!(
            interpret_typed_str_to_str("context"),
            @"context"
        );
    }

    #[test]
    fn test_known_context() {
        let schema = parse_schema(
            r#"entity E; action a appliesTo {principal: E, resource: E, context: {l: Long}};"#,
        );
        let eval = Evaluator {
            request: &PartialRequest::new(
                unknown_euid(r#"E"#),
                r#"Action::"a""#.parse().unwrap(),
                unknown_euid("E"),
                Some(Arc::new(BTreeMap::from([(
                    "l".parse().unwrap(),
                    Value::from(0),
                )]))),
                &schema,
            )
            .unwrap(),
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);
        assert_snapshot!(
            interpret_typed_str_to_str("context"),
            @"{l: 0}"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("context.l"),
            @"0"
        );
    }

    #[track_caller]
    fn builder() -> ExprBuilder<Option<Type>> {
        ExprBuilder::with_data(Some(Type::Never))
    }

    #[test]
    fn test_and() {
        let eval = Evaluator {
            request: &concrete_user_req(),
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema());
        // Note: The test expressions are in the same order as the match statements

        // "false && <any>" => "false"
        assert_snapshot!(
            // Note: principal is concrete, and thus can the residual be simplified.
            interpret_typed_str_to_str("principal != principal && principal.foo"),
            @r#"false"#
        );
        // "true && <any>" => "<any>"
        assert_snapshot!(
            interpret_typed_str_to_str("principal == principal && principal.foo"),
            @r#"User::"foo".foo"#
        );
        // "<error> && <residual>" => "<error>"
        assert_snapshot!(
            interpret_typed_str_to_str("(9223372036854775807 * 2 == 0) && principal.foo"),
            @r#"error()"#
        );
        // "<residual> && true" => "<residual>"
        assert_snapshot!(
            interpret_typed_str_to_str("principal.foo && true"),
            @r#"User::"foo".foo"#
        );
        // "<error-free> && false" => "false"
        assert_snapshot!(
            interpret_typed_str_to_str("resource == resource && 41 == 42"),
            @r#"false"#
        );
        // note: resource is unknown, and we haven't (yet) implemented a simplifying algorithm for this,
        // so it yields an error-free residual, hence the previous test makes sense
        assert_snapshot!(
            interpret_typed_str_to_str("resource == resource"),
            @r#"resource == resource"#
        );
        // "<non-error-free> && false" cannot be fully simplified
        assert_snapshot!(
            interpret_typed_str_to_str("principal.num + 1 == 100 && 41 == 42"),
            @r#"(((User::"foo".num) + 1) == 100) && false"#
        );
        // "<residual> && <nonbool>" => "<residual> && <error>"
        assert_snapshot!(
            interpret_expr_to_str(&eval, &builder().and(
                builder().get_attr(builder().var(Var::Principal), "foo".into()),
                builder().val(42),
            )),
            @r#"(User::"foo".foo) && (error())"#
        );
        // The "<residual> && <residual>" case cannot be simplified
        assert_snapshot!(
            interpret_typed_str_to_str("principal.foo && principal.num == 100"),
            @r#"(User::"foo".foo) && ((User::"foo".num) == 100)"#
        );
        // "<residual> && <error>" cannot be simplified
        assert_snapshot!(
            interpret_typed_str_to_str("principal.foo && (9223372036854775807 * 2 == 0)"),
            @r#"(User::"foo".foo) && (error())"#
        );
        // "<error> && <any>" => "<error>"
        assert_snapshot!(
            interpret_typed_str_to_str("(9223372036854775807 * 2 == 0) && false"),
            @"error()"
        );
    }

    #[test]
    fn test_or() {
        let eval = Evaluator {
            request: &concrete_user_req(),
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema());
        // Note: The test expressions are in the same order as the match statements

        // "true || <any>" => "true"
        assert_snapshot!(
            // Note: principal is concrete, and thus can the residual be simplified.
            interpret_typed_str_to_str("principal == principal || principal.foo"),
            @r#"true"#
        );
        // "false || <any>" => "<any>"
        assert_snapshot!(
            interpret_typed_str_to_str("principal != principal || principal.foo"),
            @r#"User::"foo".foo"#
        );
        // "<error> || <residual>" => "<error>"
        assert_snapshot!(
            interpret_typed_str_to_str("(9223372036854775807 * 2 == 0) || principal.foo"),
            @r#"error()"#
        );
        // "<residual> || false" => "<residual>"
        assert_snapshot!(
            interpret_typed_str_to_str("principal.foo || false"),
            @r#"User::"foo".foo"#
        );
        // "<error-free> || true" => "true"
        assert_snapshot!(
            interpret_typed_str_to_str("resource == resource || 42 == 42"),
            @r#"true"#
        );
        // note: resource is unknown, and we haven't (yet) implemented a simplifying algorithm for this,
        // so it yields an error-free residual, hence the previous test makes sense
        assert_snapshot!(
            interpret_typed_str_to_str("resource == resource"),
            @r#"resource == resource"#
        );
        // "<non-error-free> || true" cannot be fully simplified
        assert_snapshot!(
            interpret_typed_str_to_str("principal.num + 1 == 100 || 42 == 42"),
            @r#"(((User::"foo".num) + 1) == 100) || true"#
        );
        // "<residual> || <nonbool>" => "<residual> || <error>"
        assert_snapshot!(
            interpret_expr_to_str(&eval, &builder().or(
                builder().get_attr(builder().var(Var::Principal), "foo".into()),
                builder().val(42),
            )),
            @r#"(User::"foo".foo) || (error())"#
        );
        // The "<residual> || <residual>" case cannot be simplified
        assert_snapshot!(
            interpret_typed_str_to_str("principal.foo || principal.num == 100"),
            @r#"(User::"foo".foo) || ((User::"foo".num) == 100)"#
        );
        // "<residual> || <error>" cannot be simplified
        assert_snapshot!(
            interpret_typed_str_to_str("principal.foo || (9223372036854775807 * 2 == 0)"),
            @r#"(User::"foo".foo) || (error())"#
        );
        // "<error> || <any>" => "<error>"
        assert_snapshot!(
            interpret_typed_str_to_str("(9223372036854775807 * 2 == 0) || true"),
            @"error()"
        );
    }

    #[test]
    fn test_ite() {
        let eval = Evaluator {
            request: &concrete_user_req(),
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema());
        assert_snapshot!(
            interpret_typed_str_to_str("if true then resource else 2"),
            @"resource"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("if false then resource else 2"),
            @"2"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"if (resource == User::"alice") then Document::"A" else Document::"B""#),
            @r#"if (resource == User::"alice") then Document::"B" else Document::"B""#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(&r#"if (9223372036854775807 * 2) == 0 then resource else Document::"A""#),
            @"error()"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("if true then (9223372036854775807 * 2) else 0"),
            @"error()"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("if false then (9223372036854775807 * 2) else 0"),
            @"0"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("if true then 0 else (9223372036854775807 * 2)"),
            @"0"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("if false then 0 else (9223372036854775807 * 2)"),
            @"error()"
        );
    }

    #[test]
    fn test_is() {
        let schema = parse_schema(
            r#"entity E, User { baz : E }; action a appliesTo {principal: User, resource: E};"#,
        );
        let req = PartialRequest::new(
            unknown_euid("User"),
            r#"Action::"a""#.parse().unwrap(),
            concrete_euid(r#"E::"""#),
            None,
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);

        assert_snapshot!(
            interpret_typed_str_to_str("resource is User"),
            @"false"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("resource is E"),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("principal is User"),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("principal is E"),
            @"false"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("principal.baz is E"),
            @"(principal.baz) is E"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("principal.baz is Document"),
            @"(principal.baz) is Document"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("User::\"alice\" is User"),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("User::\"alice\" is E"),
            @"false"
        );
        assert_snapshot!(
            interpret_typed_str_to_str("(if (9223372036854775807 * 2 == 0) then User::\"alice\" else principal) is E"),
            @"error()"
        );
    }

    #[test]
    fn test_like() {
        let schema = parse_schema(
            r#"entity E { s : String }; action a appliesTo {principal: E, resource: E};"#,
        );
        let req = PartialRequest::new(
            unknown_euid("E"),
            r#"Action::"a""#.parse().unwrap(),
            unknown_euid("E"),
            None,
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);

        assert_snapshot!(
            interpret_typed_str_to_str(r#""aaa" like "a*""#),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#""aaa" like "b*""#),
            @"false"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal.s like "*""#),
            @r#"(principal.s) like "*""#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal.s like "b*""#),
            @r#"(principal.s) like "b*""#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"(if (9223372036854775807 * 2 == 0) then "a" else "b") like "b*""#),
            @"error()"
        );
    }

    #[test]
    fn test_negation() {
        let schema = parse_schema(
            r#"entity E { l : Long , b: Bool }; action a appliesTo {principal: E, resource: E};"#,
        );
        let req = PartialRequest::new(
            unknown_euid("E"),
            r#"Action::"a""#.parse().unwrap(),
            concrete_euid(r#"E::"""#),
            None,
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);
        assert_snapshot!(
            interpret_typed_str_to_str(r#"-(42)"#),
            @"(-42)"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"-(-9223372036854775808)"#),
            @"error()"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"-(principal.l)"#),
            @"-(principal.l)"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"--(principal.l)"#),
            @"-(-(principal.l))"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"!(false)"#),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"!(principal.b)"#),
            @"!(principal.b)"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"!!(principal.b)"#),
            @"!(!(principal.b))"
        );
    }

    #[test]
    fn test_get_attr_simple() {
        let schema = parse_schema(
            r#"entity E { s: String }; action get appliesTo {principal: E, resource: E};"#,
        );
        let entities = PartialEntities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "E", "id": "" },
                    "attrs": { "s": "bar" },
                },
                {
                    "uid": { "type": "E", "id": "e" },
                },
            ]),
            &schema,
        )
        .unwrap();
        let req = PartialRequest::new(
            concrete_euid(r#"E::"""#),
            r#"Action::"get""#.parse().unwrap(),
            unknown_euid("E"),
            None,
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);
        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal.s"#),
            @r#""bar""#
        );
        // When LHS is unknown, the entire expression is
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource.s"#),
            @"resource.s"
        );
        // When LHS is not in the entities, the entire expression is unknown
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"f".s"#),
            @r#"E::"f".s"#
        );
        // When LHS is in the entities, but its attributes are `None`, the
        // entire expression is unknown
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"e".s"#),
            @r#"E::"e".s"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"(if (9223372036854775807 * 2 == 0) then E::"alice" else E::"bob").s"#),
            @"error()"
        );
    }

    #[test]
    fn test_get_attr_chained() {
        let schema = parse_schema(
            r#"entity E { s: String, e: E }; action get appliesTo {principal: E, resource: E};"#,
        );
        // `E::"loop".e` points back at itself, so chained access through it
        // always terminates at `E::"loop"`.
        let entities = PartialEntities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "E", "id": "" },
                    "attrs": {
                        "s": "bar",
                        "e": { "__entity": { "type": "E", "id": "x" } },
                    },
                },
                {
                    "uid": { "type": "E", "id": "loop" },
                    "attrs": {
                        "s": "loop_str",
                        "e": { "__entity": { "type": "E", "id": "loop" } },
                    },
                },
            ]),
            &schema,
        )
        .unwrap();
        let req = PartialRequest::new(
            concrete_euid(r#"E::"""#),
            r#"Action::"get""#.parse().unwrap(),
            unknown_euid("E"),
            None,
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);
        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal.e.s"#),
            @r#"E::"x".s"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal.e.e.e.s"#),
            @r#"((E::"x".e).e).s"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource.e.s"#),
            @"(resource.e).s"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"loop".e"#),
            @r#"E::"loop""#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"loop".e.e.e.e"#),
            @r#"E::"loop""#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"loop".e.e.e.e.s"#),
            @r#""loop_str""#
        );
    }

    #[test]
    fn test_has_attr() {
        let schema = parse_schema(
            r#"entity E { s: String }; entity User { s: String }; action get appliesTo {principal: E, resource: User};"#,
        );
        // `User::""` has known attributes while `E::"e"` omits `attrs`, marking
        // them unknown.
        let entities = PartialEntities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "User", "id": "" },
                    "attrs": { "s": "bar" },
                },
                {
                    "uid": { "type": "E", "id": "e" },
                },
            ]),
            &schema,
        )
        .unwrap();
        let req = PartialRequest::new(
            unknown_euid("E"),
            r#"Action::"get""#.parse().unwrap(),
            concrete_euid(r#"User::"""#),
            None,
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource has s"#),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource has other"#),
            @"false"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal has s"#),
            @"principal has s"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal has other"#),
            @"principal has other"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"f" has s"#),
            @r#"E::"f" has s"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"e" has s"#),
            @r#"E::"e" has s"#
        );

        assert_snapshot!(
            interpret_typed_str_to_str(r#"{s: 0} has s"#),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"{s: 0} has t"#),
            @"false"
        );
    }

    #[test]
    fn test_set() {
        let eval = Evaluator {
            request: &concrete_user_req(),
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };

        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema());
        assert_snapshot!(
            interpret_typed_str_to_str(r#"[resource]"#),
            @"[resource]"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"[principal]"#),
            @r#"[User::"foo"]"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"[principal, User::"alice"]"#),
            @r#"[User::"alice", User::"foo"]"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"[0, -(-9223372036854775808)]"#),
            @"error()"
        );
    }

    #[test]
    fn test_record() {
        let eval = Evaluator {
            request: &concrete_user_req(),
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema());
        assert_snapshot!(
            interpret_typed_str_to_str(r#"{s: resource}"#),
            @"{s: resource}"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"{s: principal}"#),
            @r#"{s: User::"foo"}"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"{s: -(-9223372036854775808), "": resource}"#),
            @"error()"
        );
    }

    #[test]
    fn test_get_attr_record() {
        let schema = parse_schema(
            r#"entity E { rec: { s: String, inner: { n: Long } } }; entity User; action get appliesTo {principal: User, resource: E, context: {c: {n: Long}}};"#,
        );

        // Entity `E::""` has a `rec` attribute that is a nested record.
        let entities = PartialEntities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "E", "id": "" },
                    "attrs": { "rec": { "s": "bar", "inner": { "n": 1 } } },
                },
                {
                    "uid": { "type": "E", "id": "unk_attrs" },
                }
            ]),
            &schema,
        )
        .unwrap();

        // A context record with a nested record field.
        let Ok(Context::Value(context)) =
            Context::from_json_value(serde_json::json!({ "c": { "n": 2 } }))
        else {
            panic!("expected concrete context")
        };

        let req = PartialRequest::new(
            unknown_euid("User"),
            r#"Action::"get""#.parse().unwrap(),
            concrete_euid(r#"E::"""#),
            Some(context),
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);

        // Nested records read from an entity attribute.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource.rec.s"#),
            @r#""bar""#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource.rec.inner.n"#),
            @"1"
        );

        // Nested records read from the context.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"context.c"#),
            @"{n: 2}"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"context.c.n"#),
            @"2"
        );

        // Attribute access on record literals.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"{s: "lit"}.s"#),
            @r#""lit""#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"{inner: {n: 3}}.inner.n"#),
            @"3"
        );

        assert_snapshot!(
            interpret_typed_str_to_str(r#"{e: E::"unk"}.e.rec"#),
            @r#"E::"unk".rec"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"{e: E::"unk_attrs"}.e.rec"#),
            @r#"E::"unk_attrs".rec"#
        );

        // Residuals inside record literals prevent reduction to preserve error semantics
        // cases to preserve semantics, should often be possible.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"{e: if principal == User::"alice" then 9223372036854775807*2 else 0, l: 0}.l"#),
            @r#"{e: if (principal == User::"alice") then (error()) else 0, l: 0}.l"#
        );
        // But it should be possible in other cases
        assert_snapshot!(
            interpret_typed_str_to_str(r#"{p: principal}.p"#),
            @"{p: principal}.p"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"{p: principal, l: 0}.l"#),
            @"{l: 0, p: principal}.l"
        );
    }

    #[test]
    fn test_get_attr_intermediate_entities_emulate_unknown_attrs() {
        let schema = parse_schema(
            r#"
            entity E0 { metadata: { m0: M0, m1: M1 } };
            entity M0 { data: Long };
            entity M1 { data: Long };
            entity User;
            action get appliesTo { principal: User, resource: E0 };"#,
        );

        let entities = PartialEntities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "E0", "id": "e" },
                    "attrs": {
                        "metadata": {
                            "m0": { "__entity": { "type": "M0", "id": "m0" } },
                            "m1": { "__entity": { "type": "M1", "id": "m1" } },
                        }
                    },
                },
                {
                    "uid": { "type": "M0", "id": "m0" },
                    "attrs": { "data": 42 },
                },
                {
                    "uid": { "type": "M1", "id": "m1" },
                },
            ]),
            &schema,
        )
        .unwrap();

        let req = PartialRequest::new(
            unknown_euid("User"),
            r#"Action::"get""#.parse().unwrap(),
            concrete_euid(r#"E0::"e""#),
            None,
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);

        // The referenced entity uids are always known.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource.metadata.m0"#),
            @r#"M0::"m0""#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource.metadata.m1"#),
            @r#"M1::"m1""#
        );

        // `m0`'s attributes are known, so `data` reduces to a concrete value.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource.metadata.m0.data"#),
            @"42"
        );
        // `m1`'s attributes are unknown, so `data` stays a residual: this is how
        // the intermediate entity emulates an unknown attribute.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource.metadata.m1.data"#),
            @r#"M1::"m1".data"#
        );
        // Mixing a known and an unknown attribute leaves a partial residual.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource.metadata.m0.data + resource.metadata.m1.data"#),
            @r#"42 + (M1::"m1".data)"#
        );
    }

    #[test]
    fn test_call() {
        let eval = Evaluator {
            request: &concrete_user_req(),
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema());
        assert_snapshot!(
            interpret_typed_str_to_str(r#"ip("192.168.0.1").isInRange(ip("192.168.0.0/16"))"#),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"(if principal == User::"alice" then ip("127.0.0.1") else ip("192.168.0.1")).isInRange(ip("192.168.0.0/16"))"#),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"(if (9223372036854775807 * 2 == 0) then ip("127.0.0.1") else ip("192.168.0.1")).isInRange(ip("192.168.0.0/16"))"#),
            @"error()"
        );
    }

    #[test]
    fn test_binary_app_eq() {
        let schema = parse_schema(
            r#"entity E; entity User; action get appliesTo {principal: User, resource: E};"#,
        );
        let req = PartialRequest::new(
            unknown_euid("User"),
            r#"Action::"get""#.parse().unwrap(),
            concrete_euid(r#"E::"""#),
            None,
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource == E::"""#),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource == User::"""#),
            @"false"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal == User::"""#),
            @r#"principal == User::"""#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal == E::"""#),
            @r#"principal == E::"""#
        );

        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal == (if (9223372036854775807 * 2 == 0) then User::"alice" else User::"bob")"#),
            @"error()"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"(if (9223372036854775807 * 2 == 0) then User::"alice" else User::"bob") == principal"#),
            @"error()"
        );
    }

    #[test]
    fn test_binary_app_arith() {
        let schema = parse_schema(
            r#"entity E; entity User; action get appliesTo {principal: User, resource: E};"#,
        );
        let req = {
            let schema: &ValidatorSchema = &schema;
            PartialRequest::new(
                unknown_euid("User"),
                r#"Action::"get""#.parse().unwrap(),
                concrete_euid(r#"E::"""#),
                None,
                schema,
            )
            .unwrap()
        };
        let eval = Evaluator {
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);
        assert_snapshot!(
            interpret_typed_str_to_str(r#"9223372036854775807 + 9223372036854775807"#),
            @"error()"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"1 + 1"#),
            @"2"
        );
    }

    #[test]
    fn test_binary_app_contains() {
        let schema = parse_schema(
            r#"entity E; entity User; action get appliesTo {principal: User, resource: E};"#,
        );
        let req = PartialRequest::new(
            unknown_euid("User"),
            r#"Action::"get""#.parse().unwrap(),
            concrete_euid(r#"E::"""#),
            None,
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);
        assert_snapshot!(
            interpret_typed_str_to_str(r#"[E::""].contains(resource)"#),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"[User::""].contains(principal)"#),
            @r#"[User::""].contains(principal)"#
        );
    }

    #[test]
    fn test_binary_app_in() {
        let schema = parse_schema(
            r#"entity E in E; entity User in E; action get appliesTo {principal: User, resource: E, context: {e: E}};"#,
        );
        let req = PartialRequest::new(
            unknown_euid("User"),
            r#"Action::"get""#.parse().unwrap(),
            concrete_euid(r#"E::"resource""#),
            None,
            &schema,
        )
        .unwrap();
        // `E::"e"` has known (empty) ancestors; `E::"child"` has a declared
        // parent `E::""`. The other referenced entities are absent, so their
        // ancestors are unknown and `in` stays a residual.
        let entities = PartialEntities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "E", "id": "no_parents" },
                    "parents": [],
                },
                {
                    "uid": { "type": "E", "id": "resource_child" },
                    "parents": [ { "type": "E", "id": "" } ],
                },
                {
                    "uid": { "type": "E", "id": "parents_none" },
                },
            ]),
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"no_parents" in resource"#),
            @"false"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"resource" in E::"resource""#),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"resource_child" in resource"#),
            @"false"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"resource_child" in E::"not_parent""#),
            @"false"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"resource_child" in [E::"not_parent", resource]"#),
            @"false"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"resource_child" in context.e"#),
            @r#"E::"resource_child" in (context.e)"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"resource_child" in [context.e]"#),
            @r#"E::"resource_child" in [context.e]"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"context.e in E::"resource""#),
            @r#"(context.e) in E::"resource""#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"undefined" in resource"#),
            @r#"E::"undefined" in E::"resource""#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"parents_none" in resource"#),
            @r#"E::"parents_none" in E::"resource""#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"undefined" in [resource]"#),
            @r#"E::"undefined" in [E::"resource"]"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"parents_none" in [resource]"#),
            @r#"E::"parents_none" in [E::"resource"]"#
        );
    }

    fn binary_app_tags_env() -> (ValidatorSchema, PartialEntities, PartialRequest) {
        let schema = parse_schema(
            r#"entity E; entity User tags String; action get appliesTo {principal: User, resource: E, context: {tag: String}};"#,
        );
        let req = PartialRequest::new(
            unknown_euid("User"),
            r#"Action::"get""#.parse().unwrap(),
            concrete_euid(r#"E::"resource""#),
            None,
            &schema,
        )
        .unwrap();
        let entities = PartialEntities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "User", "id": "some_tags" },
                    "tags": { "s": "bar" },
                },
                {
                    "uid": { "type": "User", "id": "none_tags" },
                },
                {
                    "uid": { "type": "E", "id": "none_tags" },
                },
                {
                    "uid": { "type": "E", "id": "empty_tags" },
                    "tags": {},
                },
            ]),
            &schema,
        )
        .unwrap();
        (schema, entities, req)
    }

    #[test]
    fn test_binary_app_has_tag() {
        let (schema, entities, req) = binary_app_tags_env();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);

        // Known tags: `hasTag` resolves to a concrete bool.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"User::"some_tags".hasTag("s")"#),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"User::"some_tags".hasTag("bogus")"#),
            @"false"
        );
        // Unknown entity uid, unknown tags, or absent entity: `hasTag` stays a residual.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal.hasTag("s")"#),
            @r#"principal.hasTag("s")"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"User::"none_tags".hasTag("s")"#),
            @r#"User::"none_tags".hasTag("s")"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"User::"undefined".hasTag("s")"#),
            @r#"User::"undefined".hasTag("s")"#
        );
    }

    #[test]
    fn test_binary_app_get_tag() {
        let (schema, entities, req) = binary_app_tags_env();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);

        // Known tags: resolves to a concrete bool.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"User::"some_tags".hasTag("s") && User::"some_tags".getTag("s") == "bar" "#),
            @"true"
        );
        // Known tags, missing key: `hasTag` is false and short-circuits.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"User::"some_tags".hasTag("bogus") && User::"some_tags".getTag("bogus") == "bar" "#),
            @"false"
        );
        // Unknown cases
        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal.hasTag("s") && principal.getTag("s") == "bar" "#),
            @r#"(principal.hasTag("s")) && ((principal.getTag("s")) == "bar")"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"User::"none_tags".hasTag("s") && User::"none_tags".getTag("s") == "bar" "#),
            @r#"(User::"none_tags".hasTag("s")) && ((User::"none_tags".getTag("s")) == "bar")"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"User::"undefined".hasTag("s") && User::"undefined".getTag("s") == "bar" "#),
            @r#"(User::"undefined".hasTag("s")) && ((User::"undefined".getTag("s")) == "bar")"#
        );

        // `E` entities can't have tags, but `hasTag` is still well-typed. These could all reduce to
        // `false`, but only the explicit empty tag case does atm.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"empty_tags".hasTag("s") && E::"empty_tags".getTag("s") == "bar" "#),
            @"false"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"none_tags".hasTag("s") && E::"none_tags".getTag("s") == "bar" "#),
            @r#"E::"none_tags".hasTag("s")"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"undefined_tags".hasTag("s") && E::"undefined_tags".getTag("s") == "bar" "#),
            @r#"E::"undefined_tags".hasTag("s")"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"undefined".hasTag("s") && E::"undefined".getTag("s") == "bar" "#),
            @r#"E::"undefined".hasTag("s")"#
        );
    }

    #[test]
    fn test_binary_app_tag_unknown_key() {
        let (schema, entities, req) = binary_app_tags_env();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);

        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal.hasTag(context.tag) && principal.getTag(context.tag) == "bar" "#),
            @r#"(principal.hasTag(context.tag)) && ((principal.getTag(context.tag)) == "bar")"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"User::"some_tags".hasTag(context.tag) && User::"some_tags".getTag(context.tag) == "bar" "#),
            @r#"(User::"some_tags".hasTag(context.tag)) && ((User::"some_tags".getTag(context.tag)) == "bar")"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"empty_tags".hasTag(context.tag) && E::"empty_tags".getTag(context.tag) == "bar" "#),
            @r#"E::"empty_tags".hasTag(context.tag)"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"E::"none_tags".hasTag(context.tag) && E::"none_tags".getTag(context.tag) == "bar" "#),
            @r#"E::"none_tags".hasTag(context.tag)"#
        );
    }

    #[test]
    fn test_binary_app_get_tag_record() {
        let schema = parse_schema(
            r#"entity E; entity User tags { s: String, inner: { n: Long } }; action get appliesTo {principal: User, resource: E};"#,
        );
        let req = PartialRequest::new(
            unknown_euid("User"),
            r#"Action::"get""#.parse().unwrap(),
            concrete_euid(r#"E::"""#),
            None,
            &schema,
        )
        .unwrap();
        // `User::"rec"` has a known tag `k` holding a nested record.
        let entities = PartialEntities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "User", "id": "rec" },
                    "tags": { "k": { "s": "bar", "inner": { "n": 1 } } },
                },
            ]),
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);

        assert_snapshot!(
            interpret_typed_str_to_str(r#"User::"rec".hasTag("k") && User::"other".hasTag("k") && User::"rec".getTag("k") == User::"other".getTag("k")"#),
            @r#"(User::"other".hasTag("k")) && ({inner: {n: 1}, s: "bar"} == (User::"other".getTag("k")))"#
        );
    }

    #[test]
    fn test_binary_app_get_tag_entity() {
        let schema = parse_schema(
            r#"entity E { data: Long }; entity User tags E; action get appliesTo {principal: User, resource: E};"#,
        );
        let req = PartialRequest::new(
            unknown_euid("User"),
            r#"Action::"get""#.parse().unwrap(),
            unknown_euid("E"),
            None,
            &schema,
        )
        .unwrap();
        let entities = PartialEntities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "User", "id": "ent" },
                    "tags": {
                        "k": { "__entity": { "type": "E", "id": "target" } },
                        "unk": { "__entity": { "type": "E", "id": "unk" } },
                    },
                },
                {
                    "uid": { "type": "E", "id": "target" },
                    "attrs": { "data": 42 },
                },
            ]),
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);

        assert_snapshot!(
            interpret_typed_str_to_str(r#"User::"ent".hasTag("k") && User::"ent".getTag("k").data == 42"#),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"User::"ent".hasTag("k") && User::"ent".getTag("k") == resource"#),
            @r#"E::"target" == resource"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"User::"ent".hasTag("unk") && User::"ent".getTag("unk").data == 42"#),
            @r#"(E::"unk".data) == 42"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"principal.hasTag("k") && principal.getTag("k").data == 42"#),
            @r#"(principal.hasTag("k")) && (((principal.getTag("k")).data) == 42)"#
        );
    }

    // Test containsAll/containsAny operations
    #[test]
    fn test_set_ops() {
        let eval = Evaluator {
            request: &concrete_user_req(),
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema());
        assert_snapshot!(
            interpret_typed_str_to_str(r#"[true, false].containsAll([false, true])"#),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"[true, false].containsAll([false, resource == Document::"mine"])"#),
            @r#"[false, true].containsAll([false, resource == Document::"mine"])"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"[true, false].containsAny([false])"#),
            @"true"
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"[true].containsAny([resource == Document::"alice"])"#),
            @r#"[true].containsAny([resource == Document::"alice"])"#
        );
    }

    #[test]
    fn test_ext_normalization() {
        let eval = Evaluator {
            request: &concrete_user_req(),
            entities: &PartialEntities::new(),
            extensions: Extensions::all_available(),
        };
        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema());
        // When the TPE evaluator evaluates datetime("6640-02-11") with all
        // concrete args, the resulting residual should use the canonical
        // offset(datetime("1970-01-01"), duration("Nms")) form — not the
        // original datetime("6640-02-11") string.
        // The Lean side will for now always produce the offset(datetime("1970-01-01"), _) repr,
        // while the Rust side representation without canonicalization can be either the
        // direct datetime or the offset from the Unix Epoch, depending on where the term
        // originated from.
        assert_snapshot!(
            interpret_typed_str_to_str(r#"datetime("6640-02-11")"#),
            @r#"(datetime("1970-01-01")).offset(duration("147374467200000ms"))"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"decimal("0.0")"#),
            @r#"decimal("0.0000")"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"ip("::1")"#),
            @r#"ip("::1/128")"#
        );
        assert_snapshot!(
            interpret_typed_str_to_str(r#"duration("1d")"#),
            @r#"duration("86400000ms")"#
        );
    }

    #[test]
    fn test_datetime_attr_from_entity_is_normalized() {
        let schema = parse_schema(
            r#"entity E { dt: datetime }; entity User; action get appliesTo {principal: User, resource: E};"#,
        );

        // Create an entity whose attribute "dt" holds a non-canonical datetime
        // (constructed via `datetime(..)` rather than the canonical
        // `datetime(..).offset(..)` form).
        let entities = PartialEntities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "E", "id": "" },
                    "attrs": {
                        "dt": { "__extn": { "fn": "datetime", "arg": "2026-10-01" } },
                    },
                },
            ]),
            &schema,
        )
        .unwrap();

        // Principal is unknown so that the overall expression stays partial,
        // making the datetime value appear in the residual.
        let req = PartialRequest::new(
            unknown_euid("User"),
            r#"Action::"get""#.parse().unwrap(),
            concrete_euid(r#"E::"""#),
            None,
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };

        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource.dt"#),
            @r#"(datetime("1970-01-01")).offset(duration("1790812800000ms"))"#
        );
    }

    #[test]
    fn test_datetime_in_record_attr_from_entity_is_normalized() {
        let schema = parse_schema(
            r#"entity E { rec: { dt: datetime } }; entity User; action get appliesTo {principal: User, resource: E};"#,
        );

        // Entity attribute "rec" is a record containing the non-canonical datetime.
        let entities = PartialEntities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "E", "id": "" },
                    "attrs": {
                        "rec": {
                            "dt": { "__extn": { "fn": "datetime", "arg": "2026-10-01" } },
                        },
                    },
                },
            ]),
            &schema,
        )
        .unwrap();

        let req = PartialRequest::new(
            unknown_euid("User"),
            r#"Action::"get""#.parse().unwrap(),
            concrete_euid(r#"E::"""#),
            None,
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };

        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource.rec"#),
            @r#"{dt: (datetime("1970-01-01")).offset(duration("1790812800000ms"))}"#
        );
    }

    #[test]
    fn test_datetime_in_set_attr_from_entity_is_normalized() {
        let schema = parse_schema(
            r#"entity E { s: Set<datetime> }; entity User; action get appliesTo {principal: User, resource: E};"#,
        );

        let entities = PartialEntities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "E", "id": "" },
                    "attrs": {
                        "s": [
                            { "__extn": { "fn": "datetime", "arg": "1970-01-02" } },
                            { "__extn": { "fn": "datetime", "arg": "2026-10-01" } },
                        ],
                    },
                },
            ]),
            &schema,
        )
        .unwrap();

        let req = PartialRequest::new(
            unknown_euid("User"),
            r#"Action::"get""#.parse().unwrap(),
            concrete_euid(r#"E::"""#),
            None,
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };

        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource.s"#),
            @r#"[(datetime("1970-01-01")).offset(duration("86400000ms")), (datetime("1970-01-01")).offset(duration("1790812800000ms"))]"#
        );
    }

    #[test]
    fn test_datetime_in_multi_field_record_is_normalized() {
        let schema = parse_schema(
            r#"entity E { rec: { a: Long, dt: datetime, z: Long } }; entity User; action get appliesTo {principal: User, resource: E};"#,
        );

        // Record with "a" before "dt" and "z" after, so the skip(idx+1) path is exercised.
        let entities = PartialEntities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "E", "id": "" },
                    "attrs": {
                        "rec": {
                            "a": 1,
                            "dt": { "__extn": { "fn": "datetime", "arg": "2026-10-01" } },
                            "z": 2,
                        },
                    },
                },
            ]),
            &schema,
        )
        .unwrap();

        let req = PartialRequest::new(
            unknown_euid("User"),
            r#"Action::"get""#.parse().unwrap(),
            concrete_euid(r#"E::"""#),
            None,
            &schema,
        )
        .unwrap();
        let eval = Evaluator {
            request: &req,
            entities: &entities,
            extensions: Extensions::all_available(),
        };

        let interpret_typed_str_to_str = |e| interpret_typed_str_to_str(&eval, e, &schema);
        assert_snapshot!(
            interpret_typed_str_to_str(r#"resource.rec"#),
            @r#"{a: 1, dt: (datetime("1970-01-01")).offset(duration("1790812800000ms")), z: 2}"#
        );
    }
}
