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

mod compiled_policies;
pub use compiled_policies::{CompiledPolicies, CompiledPolicy};
mod enforcer;
mod verifier;

use crate::err::Result;
use crate::symcc::{concretizer::Env, solver::Solver, SymCompiler};
use crate::symccopt::verifier::{
    verify_always_allows_opt, verify_always_denies_opt, verify_always_matches_opt,
    verify_disjoint_opt, verify_equivalent_opt, verify_implies_opt, verify_matches_disjoint_opt,
    verify_matches_equivalent_opt, verify_matches_implies_opt, verify_never_errors_opt,
    verify_never_matches_opt,
};

use cedar_policy_core::ast::Policy;

impl<S: Solver> SymCompiler<S> {
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
        self.check_sat_asserts(
            &verify_never_errors_opt(policy),
            &policy.symenv,
            std::iter::once(policy.policy.condition()),
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
        self.check_sat_asserts(
            &verify_always_matches_opt(policy),
            &policy.symenv,
            std::iter::once(policy.policy.condition()),
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
        self.check_sat_asserts(
            &verify_never_matches_opt(policy),
            &policy.symenv,
            std::iter::once(policy.policy.condition()),
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
        self.check_sat_asserts(
            &verify_matches_equivalent_opt(policy1, policy2),
            &policy1.symenv,
            [policy1.policy.condition(), policy2.policy.condition()],
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
        self.check_sat_asserts(
            &verify_matches_implies_opt(policy1, policy2),
            &policy1.symenv,
            [policy1.policy.condition(), policy2.policy.condition()],
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
        self.check_sat_asserts(
            &verify_matches_disjoint_opt(policy1, policy2),
            &policy1.symenv,
            [policy1.policy.condition(), policy2.policy.condition()],
        )
        .await
    }

    /// Optimized version of `check_implies()`.
    ///
    /// Corresponds to `checkImpliesOpt` in the Lean.
    pub async fn check_implies_opt(
        &mut self,
        policies1: &CompiledPolicies,
        policies2: &CompiledPolicies,
    ) -> Result<bool> {
        self.check_unsat_asserts(&verify_implies_opt(policies1, policies2), &policies1.symenv)
            .await
    }

    /// Optimized version of `check_implies_with_counterexample()`.
    ///
    /// Corresponds to `impliesOpt?` in the Lean.
    pub async fn check_implies_with_counterexample_opt(
        &mut self,
        policies1: &CompiledPolicies,
        policies2: &CompiledPolicies,
    ) -> Result<Option<Env>> {
        self.check_sat_asserts(
            &verify_implies_opt(policies1, policies2),
            &policies1.symenv,
            policies1
                .policies
                .policies()
                .chain(policies2.policies.policies())
                .map(Policy::condition),
        )
        .await
    }

    /// Optimized version of `check_always_allows()`.
    ///
    /// Corresponds to `checkAlwaysAllowsOpt` in the Lean.
    pub async fn check_always_allows_opt(&mut self, policies: &CompiledPolicies) -> Result<bool> {
        self.check_unsat_asserts(&verify_always_allows_opt(policies), &policies.symenv)
            .await
    }

    /// Optimized version of `check_always_allows_with_counterexample()`.
    ///
    /// Corresponds to `alwaysAllowsOpt?` in the Lean.
    pub async fn check_always_allows_with_counterexample_opt(
        &mut self,
        policies: &CompiledPolicies,
    ) -> Result<Option<Env>> {
        self.check_sat_asserts(
            &verify_always_allows_opt(policies),
            &policies.symenv,
            policies.policies.policies().map(Policy::condition),
        )
        .await
    }

    /// Optimized version of `check_always_denies()`.
    ///
    /// Corresponds to `checkAlwaysDeniesOpt` in the Lean.
    pub async fn check_always_denies_opt(&mut self, policies: &CompiledPolicies) -> Result<bool> {
        self.check_unsat_asserts(&verify_always_denies_opt(policies), &policies.symenv)
            .await
    }

    /// Optimized version of `check_always_denies_with_counterexample()`.
    ///
    /// Corresponds to `alwaysDeniesOpt?` in the Lean.
    pub async fn check_always_denies_with_counterexample_opt(
        &mut self,
        policies: &CompiledPolicies,
    ) -> Result<Option<Env>> {
        self.check_sat_asserts(
            &verify_always_denies_opt(policies),
            &policies.symenv,
            policies.policies.policies().map(Policy::condition),
        )
        .await
    }

    /// Optimized version of `check_equivalent()`.
    ///
    /// Corresponds to `checkEquivalentOpt` in the Lean.
    pub async fn check_equivalent_opt(
        &mut self,
        policies1: &CompiledPolicies,
        policies2: &CompiledPolicies,
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
        policies1: &CompiledPolicies,
        policies2: &CompiledPolicies,
    ) -> Result<Option<Env>> {
        self.check_sat_asserts(
            &verify_equivalent_opt(policies1, policies2),
            &policies1.symenv,
            policies1
                .policies
                .policies()
                .chain(policies2.policies.policies())
                .map(Policy::condition),
        )
        .await
    }

    /// Optimized version of `check_disjoint()`.
    ///
    /// Corresponds to `checkDisjointOpt` in the Lean.
    pub async fn check_disjoint_opt(
        &mut self,
        policies1: &CompiledPolicies,
        policies2: &CompiledPolicies,
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
        policies1: &CompiledPolicies,
        policies2: &CompiledPolicies,
    ) -> Result<Option<Env>> {
        self.check_sat_asserts(
            &verify_disjoint_opt(policies1, policies2),
            &policies1.symenv,
            policies1
                .policies
                .policies()
                .chain(policies2.policies.policies())
                .map(Policy::condition),
        )
        .await
    }
}
