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

//! This module defines the Cedar symbolic compiler.
//!
//! The symbolic compiler takes as input a Cedar expression and a symbolic
//! environment. Given these inputs, it produces a Term encoding of the expression.
//!
//! If the compiler returns a Term, this Term represents a sound and complete
//! encoding of the input expression's semantics with respect to the given
//! environment: using this reduction for verification will neither miss bugs
//! (soundness) nor produce false positives (completeness).

use cedar_policy_core::ast::Var;
use cedar_policy_core::ast::{BinaryOp, Expr, ExprKind, UnaryOp};

use super::bitvec::BitVec;
use super::env::{SymEntities, SymEnv, SymRequest};
use super::ext::Ext;
use super::extfun;
use super::factory::{
    self, if_all_some, if_some, is_some, ite, option_get, record_get, record_of, some_of,
};
use super::function::UnaryFunction;
use super::result::Error;
use super::tags::SymTags;
use super::term::{Term, TermPrim};
use super::term_type::TermType;
use super::type_abbrevs::*;

//Utilities
type Result<T> = std::result::Result<T, Error>;

fn compile_prim(p: &Prim, es: &SymEntities) -> Result<Term> {
    match p {
        Prim::Bool(b) => Ok(some_of((*b).into())),
        Prim::Long(i) => Ok(some_of(BitVec::of_int(64, i128::from(*i)).into())),
        Prim::String(s) => Ok(some_of(s.clone().into())),
        Prim::EntityUID(uid) => {
            let uid = core_uid_into_uid(uid);
            if es.is_valid_entity_uid(uid) {
                Ok(some_of(uid.clone().into()))
            } else {
                Err(Error::TypeError)
            }
        }
    }
}

fn compile_var(v: &Var, req: &SymRequest) -> Result<Term> {
    match v {
        Var::Principal => {
            if req.principal.type_of().is_entity_type() {
                Ok(some_of(req.principal.clone()))
            } else {
                Err(Error::TypeError)
            }
        }
        Var::Action => {
            if req.action.type_of().is_entity_type() {
                Ok(some_of(req.action.clone()))
            } else {
                Err(Error::TypeError)
            }
        }
        Var::Resource => {
            if req.resource.type_of().is_entity_type() {
                Ok(some_of(req.resource.clone()))
            } else {
                Err(Error::TypeError)
            }
        }
        Var::Context => {
            if req.context.type_of().is_record_type() {
                Ok(some_of(req.context.clone()))
            } else {
                Err(Error::TypeError)
            }
        }
    }
}

fn compile_app1(op1: &UnaryOp, t: Term) -> Result<Term> {
    match (op1, t.type_of()) {
        (UnaryOp::Not, TermType::Bool) => Ok(some_of(factory::not(t))),
        (UnaryOp::Neg, TermType::Bitvec { n: 64 }) => Ok(factory::if_false(
            factory::bvnego(t.clone()),
            factory::bvneg(t),
        )),
        (UnaryOp::IsEmpty, TermType::Set { .. }) => Ok(some_of(factory::set_is_empty(t))),
        // No `like` or `is` cases here, because in Rust those are not
        // `UnaryOp`s, so we can't fully match the Lean.
        // In Rust we handle those in `compile_like()` and `compile_is()`.
        (_, _) => Err(Error::TypeError),
    }
}

/// In Lean, `compileApp₁` handles this case, but in Rust, `Like` is a separate
/// `Expr` variant and not part of `UnaryApp`.
fn compile_like(t: Term, pat: OrdPattern) -> Result<Term> {
    match t.type_of() {
        TermType::String => Ok(some_of(factory::string_like(t, pat))),
        _ => Err(Error::TypeError),
    }
}

/// In Lean, `compileApp₁` handles this case, but in Rust, `Is` is a separate
/// `Expr` variant and not part of `UnaryApp`.
fn compile_is(t: &Term, ety1: &EntityType) -> Result<Term> {
    match t.type_of() {
        TermType::Entity { ety: ety2 } => Ok(some_of((ety1 == &ety2).into())),
        _ => Err(Error::TypeError),
    }
}

/// Returns true if terms of type ty₁ = ty₂, so terms of types ty₁ / ty₂ can be
/// compared using the homogeneous equality operator `eq`. Returns false if ty₁ ≠
/// ty₂ but it can be soundly decided, from types alone, that terms of type ty₁ and
/// ty₂ can never be equal.  For now, we make this determination only for primitive
/// types, to match validator behavior.  We can make this determination more often
/// if needed. In general, we cannot decide if two terms of different set types are
/// never equal because they could both evaluate to the empty set and would be
/// considered equal under Cedar's dynamic semantics. Returns a type error if we
/// types are unequal and not known to be always unequal.
fn reducible_eq(ty1: &TermType, ty2: &TermType) -> Result<bool> {
    if ty1 == ty2 {
        Ok(true)
    } else if ty1.is_prim_type() && ty2.is_prim_type() {
        Ok(false)
    } else {
        Err(Error::TypeError)
    }
}

pub fn compile_in_ent(t1: Term, t2: Term, ancs: Option<UnaryFunction>) -> Term {
    let is_eq = if t1.type_of() == t2.type_of() {
        factory::eq(t1.clone(), t2.clone())
    } else {
        false.into()
    };
    let is_in = match ancs {
        Some(ancs) => factory::set_member(t2, factory::app(ancs, t1)),
        None => false.into(),
    };
    factory::or(is_eq, is_in)
}

pub fn compile_in_set(t: Term, ts: Term, ancs: Option<UnaryFunction>) -> Term {
    let is_in1 = if (ts.type_of()
        == TermType::Set {
            ty: Box::new(t.type_of()),
        }) {
        factory::set_member(t.clone(), ts.clone())
    } else {
        false.into()
    };
    let is_in2 = match ancs {
        Some(ancs) => factory::set_intersects(ts, factory::app(ancs, t)),
        None => false.into(),
    };
    factory::or(is_in1, is_in2)
}

pub fn compile_has_tag(entity: Term, tag: Term, tags: Option<&Option<SymTags>>) -> Result<Term> {
    match tags {
        None => Err(Error::NoSuchEntityType),
        Some(None) => Ok(some_of(false.into())),
        Some(Some(tags)) => Ok(some_of(tags.has_tag(entity, tag))),
    }
}

pub fn compile_get_tag(entity: Term, tag: Term, tags: Option<&Option<SymTags>>) -> Result<Term> {
    match tags {
        None => Err(Error::NoSuchEntityType),
        Some(None) => Err(Error::TypeError), // no tags declared
        Some(Some(tags)) => Ok(tags.get_tag(entity, tag)),
    }
}

pub fn compile_app2(op2: &BinaryOp, t1: Term, t2: Term, es: &SymEntities) -> Result<Term> {
    use BinaryOp::*;
    use ExtType::*;
    use TermType::*;
    match (op2, t1.type_of(), t2.type_of()) {
        (Eq, ty1, ty2) => {
            if reducible_eq(&ty1, &ty2)? {
                Ok(some_of(factory::eq(t1, t2)))
            } else {
                Ok(some_of(false.into()))
            }
        }
        (Less, Bitvec { n: 64 }, Bitvec { n: 64 }) => Ok(some_of(factory::bvslt(t1, t2))),
        (Less, Ext { xty: Duration }, Ext { xty: Duration }) => Ok(some_of(factory::bvslt(
            factory::ext_duration_val(t1),
            factory::ext_duration_val(t2),
        ))),
        (LessEq, Bitvec { n: 64 }, Bitvec { n: 64 }) => Ok(some_of(factory::bvsle(t1, t2))),
        (LessEq, Ext { xty: Duration }, Ext { xty: Duration }) => Ok(some_of(factory::bvsle(
            factory::ext_duration_val(t1),
            factory::ext_duration_val(t2),
        ))),
        (Add, Bitvec { n: 64 }, Bitvec { n: 64 }) => Ok(factory::if_false(
            factory::bvsaddo(t1.clone(), t2.clone()),
            factory::bvadd(t1, t2),
        )),
        (Sub, Bitvec { n: 64 }, Bitvec { n: 64 }) => Ok(factory::if_false(
            factory::bvssubo(t1.clone(), t2.clone()),
            factory::bvsub(t1, t2),
        )),
        (Mul, Bitvec { n: 64 }, Bitvec { n: 64 }) => Ok(factory::if_false(
            factory::bvsmulo(t1.clone(), t2.clone()),
            factory::bvmul(t1, t2),
        )),
        (Contains, Set { ty: ty1 }, ty2) => {
            if *ty1 == ty2 {
                Ok(some_of(factory::set_member(t2, t1)))
            } else {
                Err(Error::TypeError)
            }
        }
        (ContainsAll, Set { ty: ty1 }, Set { ty: ty2 }) => {
            if *ty1 == *ty2 {
                Ok(some_of(factory::set_subset(t2, t1)))
            } else {
                Err(Error::TypeError)
            }
        }
        (ContainsAny, Set { ty: ty1 }, Set { ty: ty2 }) => {
            if *ty1 == *ty2 {
                Ok(some_of(factory::set_intersects(t1, t2)))
            } else {
                Err(Error::TypeError)
            }
        }
        (In, Entity { ety: ety1 }, Entity { ety: ety2 }) => Ok(some_of(compile_in_ent(
            t1,
            t2,
            es.ancestors_of_type(&ety1, &ety2).cloned(),
        ))),
        (In, Entity { ety: ety1 }, Set { ty }) if matches!(*ty, Entity { .. }) => match *ty {
            Entity { ety: ety2 } => Ok(some_of(compile_in_set(
                t1,
                t2,
                es.ancestors_of_type(&ety1, &ety2).cloned(),
            ))),
            // PANIC SAFETY
            #[allow(
                clippy::unreachable,
                reason = "Code is unreachable due to above match that type must be an Entity"
            )]
            _ => unreachable!("We just matched with entity type above"),
        },
        (HasTag, Entity { ety }, String) => compile_has_tag(t1, t2, es.tags(&ety)),
        (GetTag, Entity { ety }, String) => compile_get_tag(t1, t2, es.tags(&ety)),
        (_, _, _) => Err(Error::TypeError),
    }
}

pub fn compile_attrs_of(t: Term, es: &SymEntities) -> Result<Term> {
    match t.type_of() {
        TermType::Entity { ety } => match es.attrs(&ety) {
            Some(attrs) => Ok(factory::app(attrs.clone(), t)),
            None => Err(Error::NoSuchEntityType),
        },
        TermType::Record { .. } => Ok(t),
        _ => Err(Error::TypeError),
    }
}

pub fn compile_has_attr(t: Term, a: &Attr, es: &SymEntities) -> Result<Term> {
    let attrs = compile_attrs_of(t, es)?;
    match attrs.type_of() {
        TermType::Record { rty } => match rty.get(a) {
            Some(ty) if ty.is_option_type() => Ok(some_of(is_some(record_get(attrs, a)))),
            Some(_) => Ok(true.into()),
            None => Ok(false.into()),
        },
        _ => Err(Error::TypeError),
    }
}

pub fn compile_get_attr(t: Term, a: &Attr, es: &SymEntities) -> Result<Term> {
    let attrs = compile_attrs_of(t, es)?;
    match attrs.type_of() {
        TermType::Record { rty } => match rty.get(a) {
            Some(ty) if ty.is_option_type() => Ok(record_get(attrs, a)),
            Some(_) => Ok(some_of(record_get(attrs, a))),
            None => Err(Error::NoSuchAttribute),
        },
        _ => Err(Error::TypeError),
    }
}

pub fn compile_if(t1: Term, r2: Result<Term>, r3: Result<Term>) -> Result<Term> {
    match (&t1, t1.type_of()) {
        (Term::Some(it), _) if matches!(**it, Term::Prim(TermPrim::Bool(true))) => r2,
        (Term::Some(it), _) if matches!(**it, Term::Prim(TermPrim::Bool(false))) => r3,
        (_, TermType::Option { ty }) if matches!(*ty, TermType::Bool) => {
            let t2 = r2?;
            let t3 = r3?;
            if t2.type_of() == t3.type_of() {
                Ok(factory::if_some(
                    t1.clone(),
                    factory::ite(factory::option_get(t1), t2, t3),
                ))
            } else {
                Err(Error::TypeError)
            }
        }
        (_, _) => Err(Error::TypeError),
    }
}

pub fn compile_and(t1: Term, r2: Result<Term>) -> Result<Term> {
    match (&t1, t1.type_of()) {
        (Term::Some(it), _) if matches!(**it, Term::Prim(TermPrim::Bool(false))) => Ok(t1),
        (_, TermType::Option { ty: ity }) if matches!(*ity, TermType::Bool) => {
            let t2 = r2?;
            if matches!(t2.type_of(), TermType::Option { ty } if matches!(*ty, TermType::Bool)) {
                Ok(if_some(
                    t1.clone(),
                    ite(option_get(t1), t2, some_of(false.into())),
                ))
            } else {
                Err(Error::TypeError)
            }
        }
        (_, _) => Err(Error::TypeError),
    }
}

pub fn compile_or(t1: Term, r2: Result<Term>) -> Result<Term> {
    match (&t1, t1.type_of()) {
        (Term::Some(it), _) if matches!(**it, Term::Prim(TermPrim::Bool(true))) => Ok(t1),
        (_, TermType::Option { ty: ity }) if matches!(*ity, TermType::Bool) => {
            let t2 = r2?;
            if matches!(t2.type_of(), TermType::Option { ty } if matches!(*ty, TermType::Bool)) {
                Ok(if_some(
                    t1.clone(),
                    ite(option_get(t1), some_of(true.into()), t2),
                ))
            } else {
                Err(Error::TypeError)
            }
        }
        (_, _) => Err(Error::TypeError),
    }
}

pub fn compile_set(ts: Vec<Term>) -> Result<Term> {
    if ts.is_empty() {
        Err(Error::UnsupportedError) // Reject empty set literals
    } else {
        // PANIC SAFETY
        #[allow(
            clippy::indexing_slicing,
            reason = "ts must be non-empty and thus indexing by 0 should not panic"
        )]
        match ts[0].type_of() {
            ref ty @ TermType::Option { ty: ref ity } => {
                if ts.iter().all(|it| &it.type_of() == ty) {
                    Ok(if_all_some(
                        ts.clone(),
                        some_of(factory::set_of(
                            ts.into_iter().map(option_get),
                            TermType::clone(ity),
                        )),
                    ))
                } else {
                    Err(Error::TypeError)
                }
            }
            _ => Err(Error::TypeError),
        }
    }
}

pub fn compile_record(ats: Vec<(Attr, Term)>) -> Result<Term> {
    #[allow(
        clippy::needless_collect,
        reason = "collect allows ats to be moved in the following line"
    )]
    Ok(if_all_some(
        ats.iter().map(|(_, t)| t.clone()).collect::<Vec<_>>(),
        some_of(record_of(ats.into_iter().map(|(a, t)| (a, option_get(t))))),
    ))
}

pub fn compile_call0(mk: impl Fn(String) -> Option<Ext>, arg: Term) -> Result<Term> {
    match arg {
        Term::Some(t) => match *t {
            Term::Prim(TermPrim::String(s)) => match mk(s) {
                Some(v) => Ok(some_of(v.into())),
                None => Err(Error::TypeError),
            },
            _ => Err(Error::TypeError),
        },
        _ => Err(Error::TypeError),
    }
}

pub fn compile_call1(xty: ExtType, enc: impl Fn(Term) -> Term, t1: Term) -> Result<Term> {
    if t1.type_of()
        == (TermType::Option {
            ty: Box::new(TermType::Ext { xty }),
        })
    {
        Ok(if_some(t1.clone(), some_of(enc(option_get(t1)))))
    } else {
        Err(Error::TypeError)
    }
}

pub fn compile_call2(
    xty: ExtType,
    enc: impl Fn(Term, Term) -> Term,
    t1: Term,
    t2: Term,
) -> Result<Term> {
    let ty = TermType::Option {
        ty: Box::new(TermType::Ext { xty }),
    };
    if t1.type_of() == ty && t2.type_of() == ty {
        Ok(if_some(
            t1.clone(),
            if_some(t2.clone(), some_of(enc(option_get(t1), option_get(t2)))),
        ))
    } else {
        Err(Error::TypeError)
    }
}

/// Extract the first item from a `Vec`, consuming the `Vec`.
/// Panics if there is less than one element.
fn extract_first<T>(v: Vec<T>) -> T {
    // PANIC SAFETY
    #[allow(
        clippy::unwrap_used,
        reason = "This function is only called from contexts where v has length >= 1"
    )]
    v.into_iter().next().unwrap()
}

/// Extract the first two items from a `Vec`, consuming the `Vec`.
/// Panics if there are less than two elements.
fn extract_first2<T>(v: Vec<T>) -> (T, T) {
    let mut it = v.into_iter();
    // PANIC SAFETY
    #[allow(
        clippy::unwrap_used,
        reason = "This function is only called from contexts where v has length >= 2"
    )]
    (it.next().unwrap(), it.next().unwrap())
}

pub fn compile_call(xfn: &cedar_policy_core::ast::Name, ts: Vec<Term>) -> Result<Term> {
    match (xfn.to_string().as_str(), ts.len()) {
        ("decimal", 1) => {
            let t1 = extract_first(ts);
            compile_call0(Ext::parse_decimal, t1)
        }
        ("lessThan", 2) => {
            let (t1, t2) = extract_first2(ts);
            compile_call2(ExtType::Decimal, extfun::less_than, t1, t2)
        }
        ("lessThanOrEqual", 2) => {
            let (t1, t2) = extract_first2(ts);
            compile_call2(ExtType::Decimal, extfun::less_than_or_equal, t1, t2)
        }
        ("greaterThan", 2) => {
            let (t1, t2) = extract_first2(ts);
            compile_call2(ExtType::Decimal, extfun::greater_than, t1, t2)
        }
        ("greaterThanOrEqual", 2) => {
            let (t1, t2) = extract_first2(ts);
            compile_call2(ExtType::Decimal, extfun::greater_than_or_equal, t1, t2)
        }
        ("ip", 1) => Err(Error::UnsupportedError),
        ("isIpv4", 1) => {
            let t1 = extract_first(ts);
            compile_call1(ExtType::IpAddr, extfun::is_ipv4, t1)
        }
        ("isIpv6", 1) => {
            let t1 = extract_first(ts);
            compile_call1(ExtType::IpAddr, extfun::is_ipv6, t1)
        }
        ("isLoopback", 1) => {
            let t1 = extract_first(ts);
            compile_call1(ExtType::IpAddr, extfun::is_loopback, t1)
        }
        ("isMulticast", 1) => {
            let t1 = extract_first(ts);
            compile_call1(ExtType::IpAddr, extfun::is_multicast, t1)
        }
        ("isInRange", 2) => {
            let (t1, t2) = extract_first2(ts);
            compile_call2(ExtType::IpAddr, extfun::is_in_range, t1, t2)
        }
        ("duration", 1) => Err(Error::UnsupportedError),
        ("toMilliseconds", 1) => {
            let t1 = extract_first(ts);
            compile_call1(ExtType::Duration, extfun::to_milliseconds, t1)
        }
        ("toSeconds", 1) => {
            let t1 = extract_first(ts);
            compile_call1(ExtType::Duration, extfun::to_seconds, t1)
        }
        ("toMinutes", 1) => {
            let t1 = extract_first(ts);
            compile_call1(ExtType::Duration, extfun::to_minutes, t1)
        }
        ("toHours", 1) => {
            let t1 = extract_first(ts);
            compile_call1(ExtType::Duration, extfun::to_hours, t1)
        }
        ("toDays", 1) => {
            let t1 = extract_first(ts);
            compile_call1(ExtType::Duration, extfun::to_days, t1)
        }
        (_, _) => Err(Error::TypeError),
    }
}

/// Given an expression `x` that has type `τ` with respect to a type environment
/// `Γ`, and given a well-formed symbolic environment `env` that conforms to `Γ`,
/// `compile x env` succeeds and produces a well-formed term of type `.option τ.toTermType`.
pub fn compile(x: &Expr, env: &SymEnv) -> Result<Term> {
    match x.expr_kind() {
        ExprKind::Lit(l) => compile_prim(l, &env.entities),
        ExprKind::Var(v) => compile_var(v, &env.request),
        ExprKind::Slot(_) => Err(Error::UnsupportedError), // analyzing templates is not supported
        ExprKind::Unknown(_) => Err(Error::UnsupportedError), // analyzing partial expressions is not supported
        ExprKind::If {
            test_expr: x1,
            then_expr: x2,
            else_expr: x3,
        } => compile_if(compile(x1, env)?, compile(x2, env), compile(x3, env)),
        ExprKind::And {
            left: x1,
            right: x2,
        } => compile_and(compile(x1, env)?, compile(x2, env)),
        ExprKind::Or {
            left: x1,
            right: x2,
        } => compile_or(compile(x1, env)?, compile(x2, env)),
        ExprKind::UnaryApp { op, arg } => {
            let t1 = compile(arg, env)?;
            Ok(if_some(t1.clone(), compile_app1(op, option_get(t1))?))
        }
        ExprKind::BinaryApp { op, arg1, arg2 } => {
            let t1 = compile(arg1, env)?;
            let t2 = compile(arg2, env)?;
            Ok(if_some(
                t1.clone(),
                if_some(
                    t2.clone(),
                    compile_app2(op, option_get(t1), option_get(t2), &env.entities)?,
                ),
            ))
        }
        ExprKind::HasAttr { expr, attr } => {
            let t = compile(expr, env)?;
            Ok(if_some(
                t.clone(),
                compile_has_attr(option_get(t), attr, &env.entities)?,
            ))
        }
        ExprKind::GetAttr { expr, attr } => {
            let t = compile(expr, env)?;
            Ok(if_some(
                t.clone(),
                compile_get_attr(option_get(t), attr, &env.entities)?,
            ))
        }
        ExprKind::Like { expr, pattern } => {
            let t1 = compile(expr, env)?;
            Ok(if_some(
                t1.clone(),
                compile_like(option_get(t1), pattern.clone().into())?,
            ))
        }
        ExprKind::Is { expr, entity_type } => {
            let t1 = compile(expr, env)?;
            Ok(if_some(
                t1.clone(),
                compile_is(
                    &option_get(t1),
                    core_entity_type_into_entity_type(entity_type),
                )?,
            ))
        }
        ExprKind::Set(xs) => {
            let ts = xs
                .iter()
                .map(|x1| compile(x1, env))
                .collect::<Result<Vec<_>>>()?;
            compile_set(ts)
        }
        ExprKind::Record(axs) => {
            let ats = axs
                .iter()
                .map(|(a1, x1)| Ok((a1.clone(), compile(x1, env)?)))
                .collect::<Result<Vec<_>>>()?;
            compile_record(ats)
        }
        ExprKind::ExtensionFunctionApp { fn_name, args } => {
            let ts = args
                .iter()
                .map(|x1| compile(x1, env))
                .collect::<Result<Vec<_>>>()?;
            compile_call(fn_name, ts)
        }
    }
}

#[cfg(test)]
mod tests {

    use cedar_policy_core::ast::Name;

    use cedar_policy::{RequestEnv, Schema};

    use crate::symcc::{extension_types::decimal::Decimal, result::Error};

    use super::*;

    #[track_caller]
    pub fn pretty_panic<T>(e: impl miette::Diagnostic + Send + Sync + 'static) -> T {
        panic!("{:?}", miette::Report::new(e))
    }

    fn dec_lit(str: &str) -> Expr {
        dec_expr(Expr::val(str))
    }

    fn dec_expr(expr: Expr) -> Expr {
        Expr::call_extension_fn(
            Name::parse_unqualified_name("decimal")
                .expect("Could not parse decimal ext constructor."),
            vec![expr],
        )
    }

    fn decimal_schema() -> Schema {
        let schema = r#"
            entity Thing;
            entity User;
            action View appliesTo {
                principal: [User],
                resource: [Thing],
                context: {
                    x: decimal,
                    y: decimal,
                    z: decimal,
                    s: String,
                }
            };
        "#;
        Schema::from_cedarschema_str(schema)
            .unwrap_or_else(pretty_panic)
            .0
    }

    fn request_env() -> RequestEnv {
        RequestEnv::new(
            "User".parse().unwrap(),
            "Action::\"View\"".parse().unwrap(),
            "Thing".parse().unwrap(),
        )
    }

    fn sym_env() -> SymEnv {
        SymEnv::new(&decimal_schema(), &request_env()).expect("Malformed sym env.")
    }

    #[track_caller]
    fn test_valid(str: &str, rep: i64) {
        assert_eq!(
            compile(&dec_lit(str), &sym_env()),
            Ok(Term::Some(Box::new(Term::Prim(TermPrim::Ext(
                Ext::Decimal { d: Decimal(rep) }
            ))))),
            "{str}"
        );
    }

    #[track_caller]
    fn test_invalid(str: &str, msg: &str) {
        let sym_env = SymEnv::new(&decimal_schema(), &request_env()).expect("Malformed sym env.");
        assert_eq!(
            compile(&dec_lit(str), &sym_env),
            Err(Error::TypeError),
            "{msg}"
        );
    }

    #[test]
    fn test_decimal() {
        test_valid("0.0", 0);
        test_valid("0.0000", 0);
        test_valid("12.34", 123400);
        test_valid("1.2345", 12345);
        test_valid("-1.0", -10000);
        test_valid("-4.2", -42000);
        test_valid("-9.876", -98760);
        test_valid("-922337203685477.5808", -9223372036854775808);
        test_valid("922337203685477.5807", 9223372036854775807);
        test_invalid("1.x", "invalid characters");
        test_invalid("1.-2", "invalid use of -");
        test_invalid("12", "no decimal point");
        test_invalid(".12", "no integer part");
        test_invalid("-.12", "no integer part");
        test_invalid("12.", "no fractional part");
        test_invalid("1.23456", "too many fractional digits");
        test_invalid("922337203685477.5808", "overflow");
        test_invalid("-922337203685477.5809", "overflow");
        let s = Expr::get_attr(Expr::var(Var::Context), "s".into());
        assert_eq!(
            compile(&dec_expr(s), &sym_env()),
            Err(Error::TypeError),
            "Error: applying decimal constructor to a non-literal"
        );
    }
}
