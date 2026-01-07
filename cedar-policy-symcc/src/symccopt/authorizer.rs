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

use super::compiler::{compile, CompileResult, Footprint, Result};
use crate::{
    term_factory::{and, any_true, eq, not, some_of},
    SymEnv,
};

pub fn compile_with_effect(
    effect: Effect,
    policy: &Policy,
    symenv: &SymEnv,
) -> Result<Option<CompileResult>> {
    if policy.effect() == effect {
        Ok(Some(compile(&policy.condition(), symenv)?))
    } else {
        Ok(None)
    }
}

pub fn satisfied_policies(
    effect: Effect,
    policies: &PolicySet,
    env: &SymEnv,
) -> Result<CompileResult> {
    let ress = policies
        .policies()
        .filter_map(|p| compile_with_effect(effect, p, env).transpose())
        .collect::<Result<Vec<CompileResult>>>()?;
    Ok(CompileResult {
        term: any_true(
            |term| eq(term, some_of(true.into())),
            ress.iter().map(|res| res.term.clone()),
        ),
        footprint: Footprint::from_iter(ress.into_iter().flat_map(|res| res.footprint)),
    })
}

pub fn is_authorized(policies: &PolicySet, env: &SymEnv) -> Result<CompileResult> {
    let forbids = satisfied_policies(Effect::Forbid, policies, env)?;
    let permits = satisfied_policies(Effect::Permit, policies, env)?;
    Ok(CompileResult {
        term: and(permits.term, not(forbids.term)),
        footprint: Footprint::from_iter(permits.footprint.chain(forbids.footprint)),
    })
}
