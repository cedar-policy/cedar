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

//! This file defines the algorithm for emitting well-formedness assumptions about
//! Cedar hierarchies. A valid Cedar hierarchy graph is the irreflexive transitive
//! closure of a DAG.  (Note that the `in` operator is reflexive, but this is
//! enforced separately by the semantics, and it's not needed in the hierarchy.)
//!
//! The generated assumptions are expressed as Terms that enforce the acyclicty and
//! transitivity constraints on the symbolic store, for a given Cedar expression.
//!
//! For more technical details, see comments in SymCC/Enforcer.lean.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use cedar_policy_core::ast::{Expr, ExprKind};

use super::{
    compiler::compile,
    env::{SymEntities, SymEnv},
    factory::{and, app, implies, is_some, not, option_get, set_is_empty, set_member, set_subset},
    function::UnaryFunction,
    term::Term,
    term_type::{TermType, TermTypeInner},
    type_abbrevs::EntityType,
};
use hashconsing::{HConsign, HashConsign};

/// Helper function used by `footprint()`.
/// In Lean this is defined inline inside `footprint()`, but in Rust, you can't
/// define closures that take generic arguments (like `impl IntoIterator`), so
/// we define it as a standalone function.

/// Returns the terms corresponding to subexpressions of `x` of the following form:
///
///   * A variable term with an entity type
///   * An entity reference literal
///   * An attribute access expression with an entity type
///   * A binary (`getTag`) expression with an entity type
///
/// These are the only basic expressions in Cedar that may evaluate to an entity.
/// All other expressions that evaluate to an entity are build up from the above
/// basic expressions.
///
/// All returned terms are of type `TermType.option .entity`.
//
// TODO: this essentially calls `compile()` on every subexpression, which is
// redundant by itself, and also potentially redundant with other `compile()`
// calls in verifier.rs
pub(crate) fn footprint(x: &Expr, env: &SymEnv, h: &mut HConsign<TermTypeInner>) -> Vec<Term> {
    let of_entity = |x: &Expr, h: &mut HConsign<TermTypeInner>| -> Vec<Term> {
        match compile(x, env, h) {
            Ok(t) => {
                if t.type_of(h).is_option_entity_type() {
                    vec![t]
                } else {
                    vec![]
                }
            }
            Err(_) => vec![],
        }
    };
    let of_branch = |x1: &Expr,
                     ft1: Vec<Term>,
                     ft2: Vec<Term>,
                     ft3: Vec<Term>,
                     h: &mut HConsign<TermTypeInner>|
     -> Vec<Term> {
        match compile(x1, env, h) {
            Ok(Term::Some(t)) if *t == true.into() => ft2,
            Ok(Term::Some(t)) if *t == false.into() => ft3,
            Ok(_) => ft1.into_iter().chain(ft2).chain(ft3).collect(),
            Err(_) => vec![],
        }
    };
    // PANIC SAFETY
    #[allow(clippy::unimplemented, reason = "Should fail at an earlier stage")]
    match x.expr_kind() {
        ExprKind::Lit(_) | ExprKind::Var(_) => of_entity(x, h),
        ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => of_branch(
            test_expr,
            footprint(test_expr, env, h),
            footprint(then_expr, env, h),
            footprint(else_expr, env, h),
            h,
        ),
        ExprKind::And { left, right } => of_branch(
            left,
            footprint(left, env, h),
            footprint(right, env, h),
            vec![],
            h,
        ),
        ExprKind::Or { left, right } => of_branch(
            left,
            footprint(left, env, h),
            vec![],
            footprint(right, env, h),
            h,
        ),
        ExprKind::BinaryApp { arg1, arg2, .. } => {
            let mut result = of_entity(x, h);
            result.extend(footprint(arg1, env, h));
            result.extend(footprint(arg2, env, h));
            result
        }
        ExprKind::GetAttr { expr, .. } => {
            let mut result = of_entity(x, h);
            result.extend(footprint(expr, env, h));
            result
        }
        ExprKind::HasAttr { expr, .. }
        | ExprKind::UnaryApp { arg: expr, .. }
        | ExprKind::Like { expr, .. }
        | ExprKind::Is { expr, .. } => footprint(expr, env, h),
        ExprKind::ExtensionFunctionApp { args: exprs, .. } | ExprKind::Set(exprs) => {
            exprs.iter().flat_map(|x| footprint(x, env, h)).collect()
        }
        ExprKind::Record(axs) => axs.iter().flat_map(|(_, x)| footprint(x, env, h)).collect(),
        ExprKind::Slot(_) => unimplemented!("analyzing templates is not currently supported"),
        ExprKind::Unknown(_) => {
            unimplemented!("analyzing partial expressions is not currently supported")
        }
        #[allow(unreachable_patterns)]
        _ => unimplemented!("analyzing `{}` is not currently supported", x),
    }
}

/// Returns the set of Terms corresponding to the footprints of `exprs`.
/// Returning a `BTreeSet` ensures there are no duplicates.
fn footprints<'a>(
    exprs: impl IntoIterator<Item = &'a Expr>,
    env: &SymEnv,
    h: &mut HConsign<TermTypeInner>,
) -> BTreeSet<Term> {
    exprs
        .into_iter()
        .flat_map(|x| footprint(x, env, h).into_iter())
        .collect()
}

/// Returns the acyclicity constraint for the given term
fn acyclicity(t: &Term, es: &SymEntities, h: &mut HConsign<TermTypeInner>) -> Term {
    match t.type_of(h).inner.get() {
        TermTypeInner::Option { ty } if matches!(ty.inner.get(), TermTypeInner::Entity { .. }) => {
            match ty.inner.get() {
                TermTypeInner::Entity { ety } => match es.ancestors_of_type(ety, ety) {
                    Some(f) => {
                        let t_unwrapped = option_get(t.clone(), h);
                        implies(
                            is_some(t.clone(), h),
                            not(
                                set_member(t_unwrapped.clone(), app(f.clone(), t_unwrapped, h), h),
                                h,
                            ),
                            h,
                        )
                    }
                    None => true.into(),
                },
                // PANIC SAFETY
                #[allow(
                    clippy::unreachable,
                    reason = "Code already checks that matches entity_type"
                )]
                _ => unreachable!("already checked it matches TermType::Entity above"),
            }
        }
        _ => true.into(),
    }
}

/// Returns the transitivity constraint for the given term
fn transitivity(t1: &Term, t2: &Term, es: &SymEntities, h: &mut HConsign<TermTypeInner>) -> Term {
    let is_ancestor = |t2_unwrapped: Term,
                       t1_unwrapped: Term,
                       f12: UnaryFunction,
                       h: &mut HConsign<TermTypeInner>|
     -> Term {
        and(
            and(is_some(t1.clone(), h), is_some(t2.clone(), h), h),
            set_member(t2_unwrapped, app(f12, t1_unwrapped, h), h),
            h,
        )
    };
    let are_ancestors = |t2_unwrapped: &Term,
                         anc2: &BTreeMap<EntityType, UnaryFunction>,
                         t1_unwrapped: &Term,
                         ety1,
                         h: &mut HConsign<TermTypeInner>|
     -> Term {
        anc2.iter().fold(true.into(), |acc, (ety3, f23)| {
            // inlining Lean's `areAncestorsOfType` here
            let are_ancestors_of_type = match es.ancestors_of_type(ety1, ety3) {
                Some(f13) => set_subset(
                    app(f23.clone(), t2_unwrapped.clone(), h),
                    app(f13.clone(), t1_unwrapped.clone(), h),
                    h,
                ),
                None => set_is_empty(app(f23.clone(), t2_unwrapped.clone(), h), h),
            };
            and(acc, are_ancestors_of_type, h)
        })
    };

    if t1 == t2 {
        true.into()
    } else {
        match (t1.type_of(h).inner.get(), t2.type_of(h).inner.get()) {
            (TermTypeInner::Option { ty: ty1 }, TermTypeInner::Option { ty: ty2 }) => {
                match (ty1.inner.get(), ty2.inner.get()) {
                    (TermTypeInner::Entity { ety: ety1 }, TermTypeInner::Entity { ety: ety2 }) => {
                        match (es.ancestors_of_type(ety1, ety2), es.ancestors(ety2)) {
                            (Some(f12), Some(anc2)) => {
                                let t1_unwrapped = option_get(t1.clone(), h);
                                let t2_unwrapped = option_get(t2.clone(), h);
                                implies(
                                    is_ancestor(
                                        t2_unwrapped.clone(),
                                        t1_unwrapped.clone(),
                                        f12.clone(),
                                        h,
                                    ),
                                    are_ancestors(&t2_unwrapped, anc2, &t1_unwrapped, ety1, h),
                                    h,
                                )
                            }
                            (_, _) => true.into(),
                        }
                    }
                    (_, _) => true.into(),
                }
            }
            (_, _) => true.into(),
        }
    }
}

/// Returns the ground acyclicity and transitivity assumptions for xs and env
pub fn enforce<'a>(
    xs: impl IntoIterator<Item = &'a Expr>,
    env: &SymEnv,
    h: &mut HConsign<TermTypeInner>,
) -> BTreeSet<Term> {
    let ts = footprints(xs, env, h);
    let mut result = BTreeSet::new();
    for t in &ts {
        result.insert(acyclicity(t, &env.entities, h));
    }
    for t in &ts {
        for t2 in &ts {
            result.insert(transitivity(t, t2, &env.entities, h));
        }
    }
    result
}
