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

//! This file defines the function `extract_opt`, which turns interpretations
//! into concrete, strongly well-formed counterexamples to verification queries.
//!
//! See notes on the unoptimized version, `SymEnv::extract()` in `symcc/extractor.rs`.
//!
//! This module is as straightforward a translation as possible of
//! <https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/Cedar/SymCCOpt/Extractor.lean>.

use cedar_policy_core::ast::Policy;

use super::{CompiledPolicies, CompiledPolicy};
use crate::{err::ConcretizeError, Env, Interpretation};

impl CompiledPolicies {
    /// Caller guarantees that all of the `CompiledPolicies` were compiled for the same `env`.
    pub fn extract_opt<'a>(
        cps: impl IntoIterator<Item = &'a Self> + Clone,
        interp: &Interpretation<'_>,
    ) -> Result<Env, ConcretizeError> {
        let mut cps2 = cps.clone().into_iter().peekable();
        match cps2.peek() {
            None => Err(ConcretizeError::NoPolicies),
            Some(Self { symenv, .. }) => {
                let ps = cps2.flat_map(|cps| cps.policies.policies().map(Policy::condition));
                let footprint = cps.into_iter().flat_map(|cps| cps.footprint.iter());
                symenv
                    .interpret(&interp.repair_as_counterexample(footprint))
                    .concretize(ps)
            }
        }
    }
}

impl CompiledPolicy {
    /// Like `CompiledPolicies::extract_opt()`, but takes a list of `CompiledPolicy` rather than `CompiledPolicies`.
    ///
    /// Caller guarantees that all of the `CompiledPolicy`s were compiled for the same `env`.
    pub fn extract_opt<'a>(
        cps: impl IntoIterator<Item = &'a Self> + Clone,
        interp: &Interpretation<'_>,
    ) -> Result<Env, ConcretizeError> {
        let mut cps2 = cps.clone().into_iter().peekable();
        match cps2.peek() {
            None => Err(ConcretizeError::NoPolicies),
            Some(Self { symenv, .. }) => {
                let ps = cps2.map(|cp| cp.policy.condition());
                let footprint = cps.into_iter().flat_map(|cps| cps.footprint.iter());
                symenv
                    .interpret(&interp.repair_as_counterexample(footprint))
                    .concretize(ps)
            }
        }
    }
}
