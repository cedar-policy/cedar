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
    term_type::TermTypeInner,
};
use hashconsing::{HConsign, HashConsign};

pub fn satisfied_with_effect(
    effect: Effect,
    policy: &Policy,
    env: &SymEnv,
    h: &mut HConsign<TermTypeInner>,
) -> Result<Option<Term>, CompileError> {
    if policy.effect() == effect {
        Ok(Some(compile(&policy.condition(), env, h)?))
    } else {
        Ok(None)
    }
}

pub fn any_satisfied(terms: impl Iterator<Item = Term>, h: &mut HConsign<TermTypeInner>) -> Term {
    let mut result = Term::from(false);
    for t in terms {
        let satisfied = eq(t, some_of(Term::from(true)), h);
        result = or(result, satisfied, h);
    }
    result
}

pub fn satisfied_policies(
    effect: Effect,
    policies: &PolicySet,
    env: &SymEnv,
    h: &mut HConsign<TermTypeInner>,
) -> Result<Term, CompileError> {
    let terms = policies
        .policies()
        .filter_map(|p| satisfied_with_effect(effect, p, env, h).transpose())
        .collect::<Result<Vec<Term>, CompileError>>()?
        .into_iter();
    Ok(any_satisfied(terms, h))
}

pub fn is_authorized(
    policies: &PolicySet,
    env: &SymEnv,
    h: &mut HConsign<TermTypeInner>,
) -> Result<Term, CompileError> {
    let forbids = satisfied_policies(Effect::Forbid, policies, env, h)?;
    let permits = satisfied_policies(Effect::Permit, policies, env, h)?;
    Ok(and(permits, not(forbids, h), h))
}
