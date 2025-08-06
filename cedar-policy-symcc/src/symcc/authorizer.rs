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
use cedar_policy::Effect;
use cedar_policy_core::ast::{Policy, PolicySet};

use crate::symcc::{
    compiler::compile,
    env::SymEnv,
    factory::{and, eq, not, or, some_of},
    result::CompileError,
    term::Term,
};

pub fn satisfied_with_effect(
    effect: Effect,
    policy: &Policy,
    env: &SymEnv,
) -> Result<Option<Term>, CompileError> {
    if policy.effect() == effect {
        Ok(Some(compile(&policy.condition(), env)?))
    } else {
        Ok(None)
    }
}

pub fn any_satisfied(terms: impl Iterator<Item = Term>) -> Term {
    let satisfied = |t: Term| eq(t, some_of(Term::from(true)));
    terms.fold(Term::from(false), |acc, t| or(acc, satisfied(t)))
}

pub fn satisfied_policies(
    effect: Effect,
    policies: &PolicySet,
    env: &SymEnv,
) -> Result<Term, CompileError> {
    let terms = policies
        .policies()
        .filter_map(|p| satisfied_with_effect(effect, p, env).transpose())
        .collect::<Result<Vec<Term>, CompileError>>()?
        .into_iter();
    Ok(any_satisfied(terms))
}

pub fn is_authorized(policies: &PolicySet, env: &SymEnv) -> Result<Term, CompileError> {
    let forbids = satisfied_policies(Effect::Forbid, policies, env)?;
    let permits = satisfied_policies(Effect::Permit, policies, env)?;
    Ok(and(permits, not(forbids)))
}
