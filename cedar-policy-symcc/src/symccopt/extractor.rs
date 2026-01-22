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

use super::CompiledPolicies;
use crate::{err::ConcretizeError, Env, Interpretation};

/// Optimized version of `SymEnv::extract()`.
///
/// Caller guarantees that all of the `CompiledPolicies` were compiled for the same `symenv`.
pub fn extract_opt<'a>(
    cpss: impl IntoIterator<Item = &'a CompiledPolicies<'a>> + Clone,
    interp: &Interpretation<'_>,
) -> Result<Env, ConcretizeError> {
    match cpss.clone().into_iter().next() {
        None => Err(ConcretizeError::NoPolicies),
        Some(cps) => {
            let ps = cpss.clone().into_iter().flat_map(|cps| cps.all_policies());
            let footprint = cpss.into_iter().flat_map(|cps| cps.footprint().iter());
            cps.symenv()
                .interpret(&interp.repair_as_counterexample(footprint))
                .concretize(ps.map(Policy::condition))
        }
    }
}
