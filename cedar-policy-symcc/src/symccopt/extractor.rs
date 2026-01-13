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

use super::CompiledPolicys;
use crate::{err::ConcretizeError, Env, Interpretation};

/// Optimized version of `SymEnv::extract()`.
///
/// Caller guarantees that all of the `CompiledPolicys` were compiled for the same `symenv`.
pub fn extract_opt<'a>(
    cps: impl Iterator<Item = &'a CompiledPolicys<'a>> + Clone,
    interp: &Interpretation<'_>,
) -> Result<Env, ConcretizeError> {
    match cps.clone().peekable().peek() {
        None => Err(ConcretizeError::NoPolicies),
        Some(cp_s) => {
            let ps = cps.clone().flat_map(|cp_s| cp_s.all_policies());
            let footprint = cps.flat_map(|cp_s| cp_s.footprint().iter());
            cp_s.symenv()
                .interpret(&interp.repair_as_counterexample(footprint))
                .concretize(ps.map(Policy::condition))
        }
    }
}
