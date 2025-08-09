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

use std::sync::Arc;

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
use super::result::CompileError;
use super::tags::SymTags;
use super::term::{Term, TermPrim};
use super::term_type::TermType;
use super::type_abbrevs::*;

type Result<T> = std::result::Result<T, CompileError>;

fn compile_prim(p: &Prim, es: &SymEntities) -> Result<Term> {
    match p {
        Prim::Bool(b) => Ok(some_of((*b).into())),
        Prim::Long(i) => Ok(some_of(BitVec::of_i128(64, i128::from(*i))?.into())),
        Prim::String(s) => Ok(some_of(s.clone().into())),
        Prim::EntityUID(uid) => {
            let uid = core_uid_into_uid(uid);
            if es.is_valid_entity_uid(uid) {
                Ok(some_of(uid.clone().into()))
            } else {
                Err(CompileError::TypeError)
            }
        }
    }
}

fn compile_var(v: Var, req: &SymRequest) -> Result<Term> {
    match v {
        Var::Principal => {
            if req.principal.type_of().is_entity_type() {
                Ok(some_of(req.principal.clone()))
            } else {
                Err(CompileError::TypeError)
            }
        }
        Var::Action => {
            if req.action.type_of().is_entity_type() {
                Ok(some_of(req.action.clone()))
            } else {
                Err(CompileError::TypeError)
            }
        }
        Var::Resource => {
            if req.resource.type_of().is_entity_type() {
                Ok(some_of(req.resource.clone()))
            } else {
                Err(CompileError::TypeError)
            }
        }
        Var::Context => {
            if req.context.type_of().is_record_type() {
                Ok(some_of(req.context.clone()))
            } else {
                Err(CompileError::TypeError)
            }
        }
    }
}

fn compile_app1(op1: UnaryOp, t: Term) -> Result<Term> {
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
        (_, _) => Err(CompileError::TypeError),
    }
}

/// In Lean, `compileApp₁` handles this case, but in Rust, `Like` is a separate
/// `Expr` variant and not part of `UnaryApp`.
fn compile_like(t: Term, pat: OrdPattern) -> Result<Term> {
    match t.type_of() {
        TermType::String => Ok(some_of(factory::string_like(t, pat))),
        _ => Err(CompileError::TypeError),
    }
}

/// In Lean, `compileApp₁` handles this case, but in Rust, `Is` is a separate
/// `Expr` variant and not part of `UnaryApp`.
fn compile_is(t: &Term, ety1: &EntityType) -> Result<Term> {
    match t.type_of() {
        TermType::Entity { ety: ety2 } => Ok(some_of((ety1 == &ety2).into())),
        _ => Err(CompileError::TypeError),
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
        Err(CompileError::TypeError)
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
            ty: Arc::new(t.type_of()),
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

pub fn compile_has_tag(
    entity: Term,
    tag: Term,
    tags: Option<&Option<SymTags>>,
    ety: &EntityType,
) -> Result<Term> {
    match tags {
        None => Err(CompileError::NoSuchEntityType(ety.clone())),
        Some(None) => Ok(some_of(false.into())),
        Some(Some(tags)) => Ok(some_of(tags.has_tag(entity, tag))),
    }
}

pub fn compile_get_tag(
    entity: Term,
    tag: Term,
    tags: Option<&Option<SymTags>>,
    ety: &EntityType,
) -> Result<Term> {
    match tags {
        None => Err(CompileError::NoSuchEntityType(ety.clone())),
        Some(None) => Err(CompileError::TypeError), // no tags declared
        Some(Some(tags)) => Ok(tags.get_tag(entity, tag)),
    }
}

pub fn compile_app2(op2: BinaryOp, t1: Term, t2: Term, es: &SymEntities) -> Result<Term> {
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
        (Less, Ext { xty: DateTime }, Ext { xty: DateTime }) => Ok(some_of(factory::bvslt(
            factory::ext_datetime_val(t1),
            factory::ext_datetime_val(t2),
        ))),
        (Less, Ext { xty: Duration }, Ext { xty: Duration }) => Ok(some_of(factory::bvslt(
            factory::ext_duration_val(t1),
            factory::ext_duration_val(t2),
        ))),
        (LessEq, Bitvec { n: 64 }, Bitvec { n: 64 }) => Ok(some_of(factory::bvsle(t1, t2))),
        (LessEq, Ext { xty: DateTime }, Ext { xty: DateTime }) => Ok(some_of(factory::bvsle(
            factory::ext_datetime_val(t1),
            factory::ext_datetime_val(t2),
        ))),
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
                Err(CompileError::TypeError)
            }
        }
        (ContainsAll, Set { ty: ty1 }, Set { ty: ty2 }) => {
            if *ty1 == *ty2 {
                Ok(some_of(factory::set_subset(t2, t1)))
            } else {
                Err(CompileError::TypeError)
            }
        }
        (ContainsAny, Set { ty: ty1 }, Set { ty: ty2 }) => {
            if *ty1 == *ty2 {
                Ok(some_of(factory::set_intersects(t1, t2)))
            } else {
                Err(CompileError::TypeError)
            }
        }
        (In, Entity { ety: ety1 }, Entity { ety: ety2 }) => Ok(some_of(compile_in_ent(
            t1,
            t2,
            es.ancestors_of_type(&ety1, &ety2).cloned(),
        ))),
        (In, Entity { ety: ety1 }, Set { ty }) if matches!(*ty, Entity { .. }) => {
            match Arc::unwrap_or_clone(ty) {
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
            }
        }
        (HasTag, Entity { ety }, String) => compile_has_tag(t1, t2, es.tags(&ety), &ety),
        (GetTag, Entity { ety }, String) => compile_get_tag(t1, t2, es.tags(&ety), &ety),
        (_, _, _) => Err(CompileError::TypeError),
    }
}

pub fn compile_attrs_of(t: Term, es: &SymEntities) -> Result<Term> {
    match t.type_of() {
        TermType::Entity { ety } => match es.attrs(&ety) {
            Some(attrs) => Ok(factory::app(attrs.clone(), t)),
            None => Err(CompileError::NoSuchEntityType(ety)),
        },
        TermType::Record { .. } => Ok(t),
        _ => Err(CompileError::TypeError),
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
        _ => Err(CompileError::TypeError),
    }
}

pub fn compile_get_attr(t: Term, a: &Attr, es: &SymEntities) -> Result<Term> {
    let attrs = compile_attrs_of(t, es)?;
    match attrs.type_of() {
        TermType::Record { rty } => match rty.get(a) {
            Some(ty) if ty.is_option_type() => Ok(record_get(attrs, a)),
            Some(_) => Ok(some_of(record_get(attrs, a))),
            None => Err(CompileError::NoSuchAttribute(a.to_string())),
        },
        _ => Err(CompileError::TypeError),
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
                Err(CompileError::TypeError)
            }
        }
        (_, _) => Err(CompileError::TypeError),
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
                Err(CompileError::TypeError)
            }
        }
        (_, _) => Err(CompileError::TypeError),
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
                Err(CompileError::TypeError)
            }
        }
        (_, _) => Err(CompileError::TypeError),
    }
}

pub fn compile_set(ts: Vec<Term>) -> Result<Term> {
    if ts.is_empty() {
        Err(CompileError::UnsupportedFeature(
            "empty set literals are not supported".to_string(),
        ))
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
                    Err(CompileError::TypeError)
                }
            }
            _ => Err(CompileError::TypeError),
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
        Term::Some(t) => match Arc::unwrap_or_clone(t) {
            Term::Prim(TermPrim::String(s)) => match mk(s) {
                Some(v) => Ok(some_of(v.into())),
                None => Err(CompileError::TypeError),
            },
            _ => Err(CompileError::TypeError),
        },
        _ => Err(CompileError::TypeError),
    }
}

// Use directly for encoding calls that can error
pub fn compile_call1_error(xty: ExtType, enc: impl Fn(Term) -> Term, t1: Term) -> Result<Term> {
    let ty = TermType::Option {
        ty: Arc::new(TermType::Ext { xty }),
    };
    if t1.type_of() == ty {
        Ok(if_some(t1.clone(), enc(option_get(t1))))
    } else {
        Err(CompileError::TypeError)
    }
}

// Use directly for encoding calls that cannot error
pub fn compile_call1(xty: ExtType, enc: impl Fn(Term) -> Term, t1: Term) -> Result<Term> {
    let enc = |t1: Term| -> Term { some_of(enc(t1)) };
    compile_call1_error(xty, enc, t1)
}

// Use directly for encoding calls that can error
pub fn compile_call2_error(
    xty1: ExtType,
    xty2: ExtType,
    enc: impl Fn(Term, Term) -> Term,
    t1: Term,
    t2: Term,
) -> Result<Term> {
    let ty1 = TermType::Option {
        ty: Arc::new(TermType::Ext { xty: xty1 }),
    };
    let ty2 = TermType::Option {
        ty: Arc::new(TermType::Ext { xty: xty2 }),
    };
    if t1.type_of() == ty1 && t2.type_of() == ty2 {
        Ok(if_some(
            t1.clone(),
            if_some(t2.clone(), enc(option_get(t1), option_get(t2))),
        ))
    } else {
        Err(CompileError::TypeError)
    }
}

// Use directly for encoding calls that cannot error
pub fn compile_call2(
    xty: ExtType,
    enc: impl Fn(Term, Term) -> Term,
    t1: Term,
    t2: Term,
) -> Result<Term> {
    let enc = |t1: Term, t2: Term| -> Term { some_of(enc(t1, t2)) };
    compile_call2_error(xty.clone(), xty, enc, t1, t2)
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
        ("ip", 1) => {
            let t1 = extract_first(ts);
            compile_call0(Ext::parse_ip, t1)
        }
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
        ("datetime", 1) => {
            let t1 = extract_first(ts);
            compile_call0(Ext::parse_datetime, t1)
        }
        ("duration", 1) => {
            let t1 = extract_first(ts);
            compile_call0(Ext::parse_duration, t1)
        }
        ("offset", 2) => {
            let (t1, t2) = extract_first2(ts);
            compile_call2_error(ExtType::DateTime, ExtType::Duration, extfun::offset, t1, t2)
        }
        ("durationSince", 2) => {
            let (t1, t2) = extract_first2(ts);
            compile_call2_error(
                ExtType::DateTime,
                ExtType::DateTime,
                extfun::duration_since,
                t1,
                t2,
            )
        }
        ("toDate", 1) => {
            let t1 = extract_first(ts);
            compile_call1_error(ExtType::DateTime, extfun::to_date, t1)
        }
        ("toTime", 1) => {
            let t1 = extract_first(ts);
            compile_call1(ExtType::DateTime, extfun::to_time, t1)
        }
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
        (_, _) => Err(CompileError::TypeError),
    }
}

/// Given an expression `x` that has type `τ` with respect to a type environment
/// `Γ`, and given a well-formed symbolic environment `env` that conforms to `Γ`,
/// `compile x env` succeeds and produces a well-formed term of type `.option τ.toTermType`.
pub fn compile(x: &Expr, env: &SymEnv) -> Result<Term> {
    match x.expr_kind() {
        ExprKind::Lit(l) => compile_prim(l, &env.entities),
        ExprKind::Var(v) => compile_var(*v, &env.request),
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
            Ok(if_some(t1.clone(), compile_app1(*op, option_get(t1))?))
        }
        ExprKind::BinaryApp { op, arg1, arg2 } => {
            let t1 = compile(arg1, env)?;
            let t2 = compile(arg2, env)?;
            Ok(if_some(
                t1.clone(),
                if_some(
                    t2.clone(),
                    compile_app2(*op, option_get(t1), option_get(t2), &env.entities)?,
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
        ExprKind::Slot(_) => Err(CompileError::UnsupportedFeature(
            "templates/slots are not supported".to_string(),
        )),
        ExprKind::Unknown(_) => Err(CompileError::UnsupportedFeature(
            "partial evaluation is not supported".to_string(),
        )),
        #[allow(unreachable_patterns)]
        _ => Err(CompileError::UnsupportedFeature(format!(
            "symbolic compilation of `{}` is not supported",
            x
        ))),
    }
}

#[cfg(test)]
mod decimal_tests {

    use cedar_policy_core::ast::Name;

    use cedar_policy::{RequestEnv, Schema};

    use crate::symcc::{extension_types::decimal::Decimal, result::CompileError};

    use std::str::FromStr;

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
            compile(&dec_lit(str), &sym_env()).unwrap(),
            Term::Some(Arc::new(Term::Prim(TermPrim::Ext(Ext::Decimal {
                d: Decimal(rep)
            })))),
            "{str}"
        );
    }

    #[track_caller]
    fn test_invalid(str: &str, msg: &str) {
        let sym_env = SymEnv::new(&decimal_schema(), &request_env()).expect("Malformed sym env.");
        assert!(
            matches!(
                compile(&dec_lit(str), &sym_env),
                Err(CompileError::TypeError),
            ),
            "{msg}"
        );
    }

    fn parse_expr(str: &str) -> Expr {
        Expr::from_str(str).expect(format!("Could not parse expression: {str}").as_str())
    }

    fn test_valid_bool_simpl_expr(str: &str, res: bool) {
        assert_eq!(
            compile(&parse_expr(str), &sym_env()).unwrap(),
            Term::Some(Arc::new(Term::Prim(TermPrim::Bool(res)))),
            "{str}"
        )
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
        assert!(
            matches!(
                compile(&dec_expr(s), &sym_env()),
                Err(CompileError::TypeError),
            ),
            "Error: applying decimal constructor to a non-literal"
        );
    }

    #[test]
    // Test expressions for decimal comparisons that evaluates to a constant bool
    fn test_decimal_simpl_comp_expr() {
        test_valid_bool_simpl_expr(r#"decimal("0.0") == decimal("0.1")"#, false);
        test_valid_bool_simpl_expr(r#"decimal("0.0") == decimal("0.00")"#, true);
        test_valid_bool_simpl_expr(r#"decimal("0.0") != decimal("0.0001")"#, true);
        test_valid_bool_simpl_expr(r#"decimal("0.0") != decimal("0.00")"#, false);
        test_valid_bool_simpl_expr(r#"decimal("0.0").lessThan(decimal("0.0001"))"#, true);
        test_valid_bool_simpl_expr(r#"decimal("0.0").greaterThan(decimal("0.0001"))"#, false);
        test_valid_bool_simpl_expr(
            r#"decimal("0.0010").lessThanOrEqual(decimal("0.001"))"#,
            true,
        );
        test_valid_bool_simpl_expr(
            r#"decimal("0.0010").greaterThanOrEqual(decimal("0.001"))"#,
            true,
        );
    }
}

#[cfg(test)]
mod datetime_tests {
    use cedar_policy_core::ast::Name;

    use cedar_policy::{RequestEnv, Schema};

    use crate::symcc::{
        extension_types::datetime::{Datetime, Duration},
        result::CompileError,
    };

    use super::*;

    use std::str::FromStr;

    #[track_caller]
    pub fn pretty_panic<T>(e: impl miette::Diagnostic + Send + Sync + 'static) -> T {
        panic!("{:?}", miette::Report::new(e))
    }

    fn datetime_lit(str: &str) -> Expr {
        Expr::call_extension_fn(
            Name::parse_unqualified_name("datetime")
                .expect("Could not parse datetime ext constructor."),
            vec![Expr::val(str)],
        )
    }

    fn duration_lit(str: &str) -> Expr {
        Expr::call_extension_fn(
            Name::parse_unqualified_name("duration")
                .expect("Could not parse datetime ext constructor."),
            vec![Expr::val(str)],
        )
    }

    fn datetime_schema() -> Schema {
        let schema = r#"
            entity Thing;
            entity User;
            action View appliesTo {
                principal: [User],
                resource: [Thing],
                context: {
                    x: datetime,
                    y: datetime,
                    z: datetime,
                    s: String,
                }
            };
        "#;
        Schema::from_cedarschema_str(schema)
            .unwrap_or_else(pretty_panic)
            .0
    }

    fn duration_schema() -> Schema {
        let schema = r#"
            entity Thing;
            entity User;
            action View appliesTo {
                principal: [User],
                resource: [Thing],
                context: {
                    x: duration,
                    y: duration,
                    z: duration,
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

    fn datetime_sym_env() -> SymEnv {
        SymEnv::new(&datetime_schema(), &request_env()).expect("Malformed sym env.")
    }

    fn duration_sym_env() -> SymEnv {
        SymEnv::new(&duration_schema(), &request_env()).expect("Malformed sym env.")
    }

    #[track_caller]
    fn test_valid_datetime_constructor(str: &str, rep: i64) {
        assert_eq!(
            compile(&datetime_lit(str), &datetime_sym_env()).unwrap(),
            Term::Some(Arc::new(Term::Prim(TermPrim::Ext(Ext::Datetime {
                dt: Datetime::from(rep)
            })))),
            "{str}"
        );
    }

    #[track_caller]
    fn test_invalid_datetime_constructor(str: &str, msg: &str) {
        let sym_env = SymEnv::new(&datetime_schema(), &request_env()).expect("Malformed sym env.");
        assert!(
            matches!(
                compile(&datetime_lit(str), &sym_env),
                Err(CompileError::TypeError),
            ),
            "{msg}"
        );
    }

    #[track_caller]
    fn test_valid_duration_constructor(str: &str, rep: i64) {
        assert_eq!(
            compile(&duration_lit(str), &duration_sym_env()).unwrap(),
            Term::Some(Arc::new(Term::Prim(TermPrim::Ext(Ext::Duration {
                d: Duration::from(rep)
            })))),
            "{str}"
        );
    }

    #[track_caller]
    fn test_invalid_duration_constructor(str: &str, msg: &str) {
        let sym_env = SymEnv::new(&duration_schema(), &request_env()).expect("Malformed sym env.");
        assert!(
            matches!(
                compile(&duration_lit(str), &sym_env),
                Err(CompileError::TypeError),
            ),
            "{msg}"
        );
    }

    #[test]
    fn test_datetime() {
        test_valid_datetime_constructor("2022-10-10", 1665360000000);
        test_valid_datetime_constructor("1969-12-31", -86400000);
        test_valid_datetime_constructor("1969-12-31T23:59:59Z", -1000);
        test_valid_datetime_constructor("1969-12-31T23:59:59.001Z", -999);
        test_valid_datetime_constructor("1969-12-31T23:59:59.999Z", -1);
        test_valid_datetime_constructor("2024-10-15", 1728950400000);
        test_valid_datetime_constructor("2024-10-15T11:38:02Z", 1728992282000);
        test_valid_datetime_constructor("2024-10-15T11:38:02.101Z", 1728992282101);
        test_valid_datetime_constructor("2024-10-15T11:38:02.101-1134", 1729033922101);
        test_valid_datetime_constructor("2024-10-15T11:38:02.101+1134", 1728950642101);
        test_valid_datetime_constructor("2024-10-15T11:38:02+1134", 1728950642000);
        test_valid_datetime_constructor("2024-10-15T11:38:02-1134", 1729033922000);
        test_invalid_datetime_constructor("", "empty string");
        test_invalid_datetime_constructor("a", "string is letter");
        test_invalid_datetime_constructor("-", "string is character");
        test_invalid_datetime_constructor("-1", "string is integer");
        test_invalid_datetime_constructor(" 2022-10-10", "leading space");
        test_invalid_datetime_constructor("2022-10-10 ", "trailing space");
        test_invalid_datetime_constructor("2022-10- 10", "interior space");
        test_invalid_datetime_constructor("11-12-13", "two digits for year");
        test_invalid_datetime_constructor("011-12-13", "three digits for year");
        test_invalid_datetime_constructor("00011-12-13", "five digits for year");
        test_invalid_datetime_constructor("0001-2-13", "one digit for month");
        test_invalid_datetime_constructor("0001-012-13", "three digits for month");
        test_invalid_datetime_constructor("0001-02-3", "one digit for day");
        test_invalid_datetime_constructor("0001-02-003", "three digits for day");
        test_invalid_datetime_constructor("0001-01-01T1:01:01Z", "one digit for hour");
        test_invalid_datetime_constructor("0001-01-01T001:01:01Z", "three digits for hour");
        test_invalid_datetime_constructor("0001-01-01T01:1:01Z", "one digit for minutes");
        test_invalid_datetime_constructor("0001-01-01T01:001:01Z", "three digits for minutes");
        test_invalid_datetime_constructor("0001-01-01T01:01:1Z", "one digit for seconds");
        test_invalid_datetime_constructor("0001-01-01T01:01:001Z", "three digits for seconds");
        test_invalid_datetime_constructor("0001-01-01T01:01:01.01Z", "two digits for ms");
        test_invalid_datetime_constructor("0001-01-01T01:01:01.0001Z", "four digits for ms");
        test_invalid_datetime_constructor("0001-01-01T01:01:01.001+01", "two digits for offset");
        test_invalid_datetime_constructor("0001-01-01T01:01:01.001+001", "three digits for offset");
        test_invalid_datetime_constructor(
            "0001-01-01T01:01:01.001+000001",
            "six digits for offset",
        );
        test_invalid_datetime_constructor("0001-01-01T01:01:01.001+00:01", "offset with colon");
        test_invalid_datetime_constructor(
            "0001-01-01T01:01:01.001+00:00:01",
            "six offset with colon",
        );
        test_invalid_datetime_constructor("-0001-01-01", "negative year");
        test_invalid_datetime_constructor("1111-1x-20", "invalid month");
        test_invalid_datetime_constructor("1111-Jul-20", "abbreviated month");
        test_invalid_datetime_constructor("1111-July-20", "full month");
        test_invalid_datetime_constructor("1111-J-20", "single letter month");
        test_invalid_datetime_constructor("2024-10-15Z", "Zulu code invalid for date");
        test_invalid_datetime_constructor("2024-10-15T11:38:02ZZ", "double Zulu code");
        test_invalid_datetime_constructor("2024-01-01T", "separator not needed");
        test_invalid_datetime_constructor("2024-01-01Ta", "unexpected character 'a'");
        test_invalid_datetime_constructor("2024-01-01T01:", "only hours");
        test_invalid_datetime_constructor("2024-01-01T01:02", "no seconds");
        test_invalid_datetime_constructor("2024-01-01T01:02:0b", "unexpected character 'b'");
        test_invalid_datetime_constructor("2024-01-01T01::02:03", "double colon");
        test_invalid_datetime_constructor("2024-01-01T01::02::03", "double colons");
        test_invalid_datetime_constructor("2024-01-01T31:02:03Z", "invalid hour range");
        test_invalid_datetime_constructor("2024-01-01T01:60:03Z", "invalid minute range");
        test_invalid_datetime_constructor("2016-12-31T23:59:60Z", "leap second");
        test_invalid_datetime_constructor("2016-12-31T23:59:61Z", "invalid second range");
        test_invalid_datetime_constructor("2024-01-01T00:00:00", "timezone not specified");
        test_invalid_datetime_constructor("2024-01-01T00:00:00T", "separator is not timezone");
        test_invalid_datetime_constructor("2024-01-01T00:00:00ZZ", "double Zulu code");
        test_invalid_datetime_constructor(
            "2024-01-01T00:00:00x001Z",
            "typo in milliseconds separator",
        );
        test_invalid_datetime_constructor(
            "2024-01-01T00:00:00.001ZZ",
            "double Zulu code w/ millis",
        );
        test_invalid_datetime_constructor("2016-12-31T23:59:60.000Z", "leap second (millis/UTC)");
        test_invalid_datetime_constructor(
            "2016-12-31T23:59:60.000+0200",
            "leap second (millis/offset)",
        );
        test_invalid_datetime_constructor("2024-01-01T00:00:00➕0000", "sign `+` is an emoji");
        test_invalid_datetime_constructor("2024-01-01T00:00:00➖0000", "sign `-` is an emoji");
        test_invalid_datetime_constructor(
            "2024-01-01T00:00:00.0001Z",
            "fraction of seconds is 4 digits",
        );
        test_invalid_datetime_constructor("2024-01-01T00:00:00.001➖0000", "sign `+` is an emoji");
        test_invalid_datetime_constructor("2024-01-01T00:00:00.001➕0000", "sign `-` is an emoji");
        test_invalid_datetime_constructor("2024-01-01T00:00:00.001+00000", "offset is 5 digits");
        test_invalid_datetime_constructor("2024-01-01T00:00:00.001-00000", "offset is 5 digits");
        test_invalid_datetime_constructor("2016-01-01T00:00:00+2400", "invalid offset hour range");
        test_invalid_datetime_constructor(
            "2016-01-01T00:00:00+0060",
            "invalid offset minute range",
        );
        test_invalid_datetime_constructor(
            "2016-01-01T00:00:00+9999",
            "invalid offset hour and minute range",
        );
        test_invalid_datetime_constructor(
            "context.s",
            "Error: applying datetime constructor to a non-literal",
        );
    }

    #[test]
    fn test_duration() {
        test_valid_duration_constructor("0ms", 0);
        test_valid_duration_constructor("0d0s", 0);
        test_valid_duration_constructor("1ms", 1);
        test_valid_duration_constructor("1s", 1000);
        test_valid_duration_constructor("1m", 60000);
        test_valid_duration_constructor("1h", 3600000);
        test_valid_duration_constructor("1d", 86400000);
        test_valid_duration_constructor("12s340ms", 12340);
        test_valid_duration_constructor("1s234ms", 1234);
        test_valid_duration_constructor("-1ms", -1);
        test_valid_duration_constructor("-1s", -1000);
        test_valid_duration_constructor("-4s200ms", -4200);
        test_valid_duration_constructor("-9s876ms", -9876);
        test_valid_duration_constructor("106751d23h47m16s854ms", 9223372036854);
        test_valid_duration_constructor("-106751d23h47m16s854ms", -9223372036854);
        test_valid_duration_constructor("-9223372036854775808ms", i64::MIN);
        test_valid_duration_constructor("9223372036854775807ms", i64::MAX);
        test_valid_duration_constructor("1d2h3m4s5ms", 93784005);
        test_valid_duration_constructor("2d12h", 216000000);
        test_valid_duration_constructor("3m30s", 210000);
        test_valid_duration_constructor("1h30m45s", 5445000);
        test_valid_duration_constructor("2d5h20m", 192000000);
        test_valid_duration_constructor("-1d12h", -129600000);
        test_valid_duration_constructor("-3h45m", -13500000);
        test_valid_duration_constructor("1d1ms", 86400001);
        test_valid_duration_constructor("59m59s999ms", 3599999);
        test_valid_duration_constructor("23h59m59s999ms", 86399999);
        test_valid_duration_constructor("0d0h0m0s0ms", 0);
        test_invalid_duration_constructor("", "empty string");
        test_invalid_duration_constructor("d", "unit but no amount");
        test_invalid_duration_constructor("1d-1s", "invalid use of -");
        test_invalid_duration_constructor("1d2h3m4s5ms6", "trailing amount");
        test_invalid_duration_constructor("1x2m3s", "invalid unit");
        test_invalid_duration_constructor("1.23s", "amounts must be integral");
        test_invalid_duration_constructor("1s1d", "invalid order");
        test_invalid_duration_constructor("1s1s", "repeated units");
        test_invalid_duration_constructor("1d2h3m4s5ms ", "trailing space");
        test_invalid_duration_constructor(" 1d2h3m4s5ms", "leading space");
        test_invalid_duration_constructor("1d9223372036854775807ms", "overflow");
        test_invalid_duration_constructor("1d92233720368547758071ms", "overflow ms");
        test_invalid_duration_constructor("9223372036854776s1ms", "overflow s");
        test_invalid_duration_constructor(
            "context.s",
            "Error: applying duration constructor to a non-literal",
        );
    }

    fn parse_expr(str: &str) -> Expr {
        Expr::from_str(str).expect(format!("Could not parse expression: {str}").as_str())
    }

    // Test that the str compiles and simplifies to a Datetime literal matching rep
    fn test_valid_datetime_simpl_expr(str: &str, rep: i64) {
        assert_eq!(
            compile(&parse_expr(str), &datetime_sym_env()).unwrap(),
            Term::Some(Arc::new(Term::Prim(TermPrim::Ext(Ext::Datetime {
                dt: Datetime::from(rep)
            })))),
            "{str}"
        )
    }

    // Test that the str compiles and simplifies to a Duration literal matching rep
    fn test_valid_duration_simpl_expr(str: &str, rep: i64) {
        assert_eq!(
            compile(&parse_expr(str), &duration_sym_env()).unwrap(),
            Term::Some(Arc::new(Term::Prim(TermPrim::Ext(Ext::Duration {
                d: Duration::from(rep)
            })))),
            "{str}"
        )
    }

    fn test_valid_bool_simpl_expr(str: &str, res: bool) {
        assert_eq!(
            compile(&parse_expr(str), &datetime_sym_env()).unwrap(),
            Term::Some(Arc::new(Term::Prim(TermPrim::Bool(res)))),
            "{str}"
        )
    }

    #[test]
    fn test_datetime_simpl_expr() {
        test_valid_datetime_simpl_expr(
            r#"datetime("1970-01-01").offset(duration("365d"))"#,
            31536000000,
        );
        test_valid_datetime_simpl_expr(
            r#"
            datetime("1970-01-01")
            .offset(
                datetime("1971-01-01")
                .durationSince(datetime("1970-01-01"))
            )"#,
            31536000000,
        );
        // Tests with toDate will not work until BitVec::srem is implemented
        test_valid_datetime_simpl_expr(r#"datetime("1970-01-01T09:30:00Z").toDate()"#, 0);
        test_valid_datetime_simpl_expr(
            r#"datetime("1970-01-02T10:30:00.001Z").toDate()"#,
            86400000,
        );
        test_valid_datetime_simpl_expr(
            r#"datetime("1969-12-31T10:30:00.001Z").toDate()"#,
            -86400000,
        );
        test_valid_datetime_simpl_expr(
            r#"
            datetime("1969-12-31T10:30:00.001Z")
            .offset(duration("2d1h29m59s999ms"))
            .toDate()
            "#,
            86400000,
        );
    }

    #[test]
    fn test_duration_simpl_expr() {
        // Tests with toTime will not work until BitVec::srem is implemented
        test_valid_duration_simpl_expr(r#"datetime("1970-01-01").toTime()"#, 0);
        test_valid_duration_simpl_expr(r#"datetime("1969-12-31T00:01:00Z").toTime()"#, 60000);
        test_valid_duration_simpl_expr(
            r#"
            datetime("1973-01-02T01:23:19Z")
            .durationSince(
                datetime("1973-01-02T01:23:19Z")
            )"#,
            0,
        );
        test_valid_duration_simpl_expr(
            r#"
            datetime("1973-01-02")
            .durationSince(
                datetime("2000-01-02")
            )"#,
            -851990400000,
        );
        test_valid_duration_simpl_expr(
            r#"
            datetime("2000-01-02")
            .durationSince(
                datetime("1973-01-02")
            )"#,
            851990400000,
        );
        test_valid_duration_simpl_expr(
            r#"
            datetime("1969-12-31")
            .durationSince(
                datetime("1969-12-31T23:59:00+2359")
            )"#,
            0,
        );
    }

    #[test]
    fn test_datetime_simpl_comp_expr() {
        test_valid_bool_simpl_expr(r#"datetime("2025-01-01") == datetime("2025-01-01")"#, true);
        test_valid_bool_simpl_expr(
            r#"datetime("2025-01-01") == datetime("2025-01-01T00:00:00.001Z")"#,
            false,
        );
        test_valid_bool_simpl_expr(r#"datetime("2025-01-01") != datetime("2025-01-01")"#, false);
        test_valid_bool_simpl_expr(
            r#"datetime("2025-01-01") != datetime("2025-01-01T00:00:00.001Z")"#,
            true,
        );
        test_valid_bool_simpl_expr(r#"datetime("2025-01-01") <= datetime("2025-01-01")"#, true);
        test_valid_bool_simpl_expr(r#"datetime("2025-01-01") <= datetime("2025-01-02")"#, true);
        test_valid_bool_simpl_expr(r#"datetime("2024-01-01") <= datetime("2025-01-01")"#, true);
        test_valid_bool_simpl_expr(r#"datetime("2024-01-01") < datetime("2025-01-01")"#, true);
        test_valid_bool_simpl_expr(r#"datetime("2025-01-01") < datetime("2025-01-01")"#, false);
        test_valid_bool_simpl_expr(r#"datetime("2025-01-01") < datetime("2025-01-02")"#, true);
        test_valid_bool_simpl_expr(r#"datetime("2025-01-01") < datetime("2024-01-01")"#, false);
        test_valid_bool_simpl_expr(r#"datetime("2025-01-02") <= datetime("2025-01-01")"#, false);
    }

    #[test]
    fn test_duration_simpl_comp_expr() {
        test_valid_bool_simpl_expr(r#"duration("-39d") == duration("-3369600000ms")"#, true);
        test_valid_bool_simpl_expr(r#"duration("-32d") == duration("-3369600000s")"#, false);
        test_valid_bool_simpl_expr(r#"duration("-39d") != duration("-3369600000ms")"#, false);
        test_valid_bool_simpl_expr(r#"duration("-32d") != duration("-3369600000s")"#, true);
        test_valid_bool_simpl_expr(r#"duration("-32d") <= duration("-986986712ms")"#, true);
        test_valid_bool_simpl_expr(r#"duration("0ms") <= duration("1d")"#, true);
        test_valid_bool_simpl_expr(r#"duration("986986712ms") <= duration("32d")"#, true);
        test_valid_bool_simpl_expr(r#"duration("90s") < duration("1m31s")"#, true);
        test_valid_bool_simpl_expr(r#"duration("1m31s") < duration("91s")"#, false);
        test_valid_bool_simpl_expr(r#"duration("4s") < duration("4001ms")"#, true);
        test_valid_bool_simpl_expr(r#"duration("-1ms") < duration("-2ms")"#, false);
        test_valid_bool_simpl_expr(r#"duration("8d") <= duration("80109s")"#, false);
    }

    #[test]
    fn test_ipaddr_simpl_comp_expr() {
        test_valid_bool_simpl_expr(r#"ip("192.168.0.1").isInRange(ip("192.168.0.1/24"))"#, true);
        test_valid_bool_simpl_expr(r#"ip("192.168.0.1").isInRange(ip("192.168.0.1/28"))"#, true);
        test_valid_bool_simpl_expr(
            r#"ip("192.168.0.75").isInRange(ip("192.168.0.1/24"))"#,
            true,
        );
        test_valid_bool_simpl_expr(
            r#"ip("192.168.0.75").isInRange(ip("192.168.0.1/28"))"#,
            false,
        );
        test_valid_bool_simpl_expr(r#"ip("1:2:3:4::").isInRange(ip("1:2:3:4::/48"))"#, true);
        test_valid_bool_simpl_expr(r#"ip("192.168.0.1").isInRange(ip("1:2:3:4::"))"#, false);
        test_valid_bool_simpl_expr(
            r#"ip("192.168.1.1").isInRange(ip("192.168.0.1/24"))"#,
            false,
        );
        test_valid_bool_simpl_expr(r#"ip("127.0.0.1").isMulticast()"#, false);
        test_valid_bool_simpl_expr(r#"ip("ff00::2").isMulticast()"#, true);
        test_valid_bool_simpl_expr(r#"ip("127.0.0.2").isLoopback()"#, true);
        test_valid_bool_simpl_expr(r#"ip("::1").isLoopback()"#, true);
        test_valid_bool_simpl_expr(r#"ip("::2").isLoopback()"#, false);
        test_valid_bool_simpl_expr(r#"ip("127.0.0.1/24").isIpv6()"#, false);
        test_valid_bool_simpl_expr(r#"ip("ffee::/64").isIpv6()"#, true);
        test_valid_bool_simpl_expr(r#"ip("::1").isIpv6()"#, true);
        test_valid_bool_simpl_expr(r#"ip("127.0.0.1").isIpv4()"#, true);
        test_valid_bool_simpl_expr(r#"ip("::1").isIpv4()"#, false);
        test_valid_bool_simpl_expr(r#"ip("127.0.0.1/24").isIpv4()"#, true);
    }
}
