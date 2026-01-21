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

//! This module is as straightforward a translation as possible of
//! <https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/Cedar/SymCCOpt.lean>.

mod authorizer;
mod compiled_policies;
pub use compiled_policies::{CompiledPolicies, CompiledPolicy, CompiledPolicySet};
mod compiler;
mod enforcer;
mod extractor;
mod verifier;

use crate::err::{Error, Result};
use crate::symcc::{concretizer::Env, solver::Solver, SymCompiler};
use crate::Asserts;
use extractor::extract_opt;
pub use verifier::{
    verify_always_allows_opt, verify_always_denies_opt, verify_always_matches_opt,
    verify_disjoint_opt, verify_equivalent_opt, verify_implies_opt, verify_matches_disjoint_opt,
    verify_matches_equivalent_opt, verify_matches_implies_opt, verify_never_errors_opt,
    verify_never_matches_opt,
};

impl<S: Solver> SymCompiler<S> {
    /// Optimized version of `sat_asserts()`.
    ///
    /// Corresponds to `satAssertsOpt?` in the Lean.
    pub async fn sat_asserts_opt<'a>(
        &mut self,
        asserts: &Asserts,
        cpss: impl IntoIterator<Item = &'a CompiledPolicies<'a>> + Clone,
    ) -> Result<Option<Env>> {
        match cpss.clone().into_iter().next() {
            None => Err(Error::NoPolicies),
            Some(cps) => match self.check_sat_asserts(asserts, cps.symenv()).await? {
                None => Ok(None),
                Some(interp) => Ok(Some(extract_opt(cpss, &interp)?)),
            },
        }
    }

    /// Optimized version of `check_never_errors()`.
    ///
    /// Corresponds to `checkNeverErrorsOpt` in the Lean.
    pub async fn check_never_errors_opt(&mut self, policy: &CompiledPolicy) -> Result<bool> {
        self.check_unsat_asserts(&verify_never_errors_opt(policy), &policy.symenv)
            .await
    }

    /// Optimized version of `check_never_errors_with_counterexample()`.
    ///
    /// Corresponds to `neverErrorsOpt?` in the Lean.
    pub async fn check_never_errors_with_counterexample_opt(
        &mut self,
        policy: &CompiledPolicy,
    ) -> Result<Option<Env>> {
        self.sat_asserts_opt(
            &verify_never_errors_opt(policy),
            std::iter::once(&CompiledPolicies::Policy(policy)),
        )
        .await
    }

    /// Optimized version of `check_always_matches()`.
    ///
    /// Corresponds to `checkAlwaysMatchesOpt` in the Lean.
    pub async fn check_always_matches_opt(&mut self, policy: &CompiledPolicy) -> Result<bool> {
        self.check_unsat_asserts(&verify_always_matches_opt(policy), &policy.symenv)
            .await
    }

    /// Optimized version of `check_always_matches_with_counterexample()`.
    ///
    /// Corresponds to `alwaysMatchesOpt?` in the Lean.
    pub async fn check_always_matches_with_counterexample_opt(
        &mut self,
        policy: &CompiledPolicy,
    ) -> Result<Option<Env>> {
        self.sat_asserts_opt(
            &verify_always_matches_opt(policy),
            std::iter::once(&CompiledPolicies::Policy(policy)),
        )
        .await
    }

    /// Optimized version of `check_never_matches()`.
    ///
    /// Corresponds to `checkNeverMatchesOpt` in the Lean.
    pub async fn check_never_matches_opt(&mut self, policy: &CompiledPolicy) -> Result<bool> {
        self.check_unsat_asserts(&verify_never_matches_opt(policy), &policy.symenv)
            .await
    }

    /// Optimized version of `check_never_matches_with_counterexample()`.
    ///
    /// Corresponds to `neverMatchesOpt?` in the Lean.
    pub async fn check_never_matches_with_counterexample_opt(
        &mut self,
        policy: &CompiledPolicy,
    ) -> Result<Option<Env>> {
        self.sat_asserts_opt(
            &verify_never_matches_opt(policy),
            std::iter::once(&CompiledPolicies::Policy(policy)),
        )
        .await
    }

    /// Optimized version of `check_matches_equivalent()`.
    ///
    /// Corresponds to `checkMatchesEquivalentOpt` in the Lean.
    pub async fn check_matches_equivalent_opt(
        &mut self,
        policy1: &CompiledPolicy,
        policy2: &CompiledPolicy,
    ) -> Result<bool> {
        self.check_unsat_asserts(
            &verify_matches_equivalent_opt(policy1, policy2),
            &policy1.symenv,
        )
        .await
    }

    /// Optimized version of `check_matches_equivalent_with_counterexample()`.
    ///
    /// Corresponds to `matchesEquivalentOpt?` in the Lean.
    pub async fn check_matches_equivalent_with_counterexample_opt(
        &mut self,
        policy1: &CompiledPolicy,
        policy2: &CompiledPolicy,
    ) -> Result<Option<Env>> {
        self.sat_asserts_opt(
            &verify_matches_equivalent_opt(policy1, policy2),
            [
                &CompiledPolicies::Policy(policy1),
                &CompiledPolicies::Policy(policy2),
            ],
        )
        .await
    }

    /// Optimized version of `check_matches_implies()`.
    ///
    /// Corresponds to `checkMatchesImpliesOpt` in the Lean.
    pub async fn check_matches_implies_opt(
        &mut self,
        policy1: &CompiledPolicy,
        policy2: &CompiledPolicy,
    ) -> Result<bool> {
        self.check_unsat_asserts(
            &verify_matches_implies_opt(policy1, policy2),
            &policy1.symenv,
        )
        .await
    }

    /// Optimized version of `check_matches_implies_with_counterexample()`.
    ///
    /// Corresponds to `matchesImpliesOpt?` in the Lean.
    pub async fn check_matches_implies_with_counterexample_opt(
        &mut self,
        policy1: &CompiledPolicy,
        policy2: &CompiledPolicy,
    ) -> Result<Option<Env>> {
        self.sat_asserts_opt(
            &verify_matches_implies_opt(policy1, policy2),
            [
                &CompiledPolicies::Policy(policy1),
                &CompiledPolicies::Policy(policy2),
            ],
        )
        .await
    }

    /// Optimized version of `check_matches_disjoint()`.
    ///
    /// Corresponds to `checkMatchesDisjointOpt` in the Lean.
    pub async fn check_matches_disjoint_opt(
        &mut self,
        policy1: &CompiledPolicy,
        policy2: &CompiledPolicy,
    ) -> Result<bool> {
        self.check_unsat_asserts(
            &verify_matches_disjoint_opt(policy1, policy2),
            &policy1.symenv,
        )
        .await
    }

    /// Optimized version of `check_matches_disjoint_with_counterexample()`.
    ///
    /// Corresponds to `matchesDisjointOpt?` in the Lean.
    pub async fn check_matches_disjoint_with_counterexample_opt(
        &mut self,
        policy1: &CompiledPolicy,
        policy2: &CompiledPolicy,
    ) -> Result<Option<Env>> {
        self.sat_asserts_opt(
            &verify_matches_disjoint_opt(policy1, policy2),
            [
                &CompiledPolicies::Policy(policy1),
                &CompiledPolicies::Policy(policy2),
            ],
        )
        .await
    }

    /// Optimized version of `check_implies()`.
    ///
    /// Corresponds to `checkImpliesOpt` in the Lean.
    pub async fn check_implies_opt(
        &mut self,
        policies1: &CompiledPolicySet,
        policies2: &CompiledPolicySet,
    ) -> Result<bool> {
        self.check_unsat_asserts(&verify_implies_opt(policies1, policies2), &policies1.symenv)
            .await
    }

    /// Optimized version of `check_implies_with_counterexample()`.
    ///
    /// Corresponds to `impliesOpt?` in the Lean.
    pub async fn check_implies_with_counterexample_opt(
        &mut self,
        policies1: &CompiledPolicySet,
        policies2: &CompiledPolicySet,
    ) -> Result<Option<Env>> {
        self.sat_asserts_opt(
            &verify_implies_opt(policies1, policies2),
            [
                &CompiledPolicies::PolicySet(policies1),
                &CompiledPolicies::PolicySet(policies2),
            ],
        )
        .await
    }

    /// Optimized version of `check_always_allows()`.
    ///
    /// Corresponds to `checkAlwaysAllowsOpt` in the Lean.
    pub async fn check_always_allows_opt(&mut self, policies: &CompiledPolicySet) -> Result<bool> {
        self.check_unsat_asserts(&verify_always_allows_opt(policies), &policies.symenv)
            .await
    }

    /// Optimized version of `check_always_allows_with_counterexample()`.
    ///
    /// Corresponds to `alwaysAllowsOpt?` in the Lean.
    pub async fn check_always_allows_with_counterexample_opt(
        &mut self,
        policies: &CompiledPolicySet,
    ) -> Result<Option<Env>> {
        self.sat_asserts_opt(
            &verify_always_allows_opt(policies),
            std::iter::once(&CompiledPolicies::PolicySet(policies)),
        )
        .await
    }

    /// Optimized version of `check_always_denies()`.
    ///
    /// Corresponds to `checkAlwaysDeniesOpt` in the Lean.
    pub async fn check_always_denies_opt(&mut self, policies: &CompiledPolicySet) -> Result<bool> {
        self.check_unsat_asserts(&verify_always_denies_opt(policies), &policies.symenv)
            .await
    }

    /// Optimized version of `check_always_denies_with_counterexample()`.
    ///
    /// Corresponds to `alwaysDeniesOpt?` in the Lean.
    pub async fn check_always_denies_with_counterexample_opt(
        &mut self,
        policies: &CompiledPolicySet,
    ) -> Result<Option<Env>> {
        self.sat_asserts_opt(
            &verify_always_denies_opt(policies),
            std::iter::once(&CompiledPolicies::PolicySet(policies)),
        )
        .await
    }

    /// Optimized version of `check_equivalent()`.
    ///
    /// Corresponds to `checkEquivalentOpt` in the Lean.
    pub async fn check_equivalent_opt(
        &mut self,
        policies1: &CompiledPolicySet,
        policies2: &CompiledPolicySet,
    ) -> Result<bool> {
        self.check_unsat_asserts(
            &verify_equivalent_opt(policies1, policies2),
            &policies1.symenv,
        )
        .await
    }

    /// Optimized version of `check_equivalent_with_counterexample()`.
    ///
    /// Corresponds to `equivalentOpt?` in the Lean.
    pub async fn check_equivalent_with_counterexample_opt(
        &mut self,
        policies1: &CompiledPolicySet,
        policies2: &CompiledPolicySet,
    ) -> Result<Option<Env>> {
        self.sat_asserts_opt(
            &verify_equivalent_opt(policies1, policies2),
            [
                &CompiledPolicies::PolicySet(policies1),
                &CompiledPolicies::PolicySet(policies2),
            ],
        )
        .await
    }

    /// Optimized version of `check_disjoint()`.
    ///
    /// Corresponds to `checkDisjointOpt` in the Lean.
    pub async fn check_disjoint_opt(
        &mut self,
        policies1: &CompiledPolicySet,
        policies2: &CompiledPolicySet,
    ) -> Result<bool> {
        self.check_unsat_asserts(
            &verify_disjoint_opt(policies1, policies2),
            &policies1.symenv,
        )
        .await
    }

    /// Optimized version of `check_disjoint_with_counterexample()`.
    ///
    /// Corresponds to `disjointOpt?` in the Lean.
    pub async fn check_disjoint_with_counterexample_opt(
        &mut self,
        policies1: &CompiledPolicySet,
        policies2: &CompiledPolicySet,
    ) -> Result<Option<Env>> {
        self.sat_asserts_opt(
            &verify_disjoint_opt(policies1, policies2),
            [
                &CompiledPolicies::PolicySet(policies1),
                &CompiledPolicies::PolicySet(policies2),
            ],
        )
        .await
    }
}
