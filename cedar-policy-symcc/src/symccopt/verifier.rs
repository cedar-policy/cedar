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
//! <https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/Cedar/SymCCOpt/Verifier.lean>.

use super::{
    enforcer::{enforce_compiled_policy, enforce_pair_compiled_policies},
    CompiledPolicies, CompiledPolicy,
};
use crate::symcc::{factory, term::Term, verifier::Asserts};
use std::sync::Arc;

/// Returns asserts that are unsatisfiable iff the evaluation of `policy`,
/// represented as a `Term` of type .option .bool, satisfies `phi` on all inputs
/// drawn from the `symenv` that `policy` was compiled for.
///
/// See also `verify_never_errors_opt()`.
pub fn verify_evaluate_opt(phi: impl FnOnce(&Term) -> Term, policy: &CompiledPolicy) -> Asserts {
    Arc::new(
        enforce_compiled_policy(policy)
            .into_iter()
            .chain(std::iter::once(factory::not(phi(&policy.term))))
            .collect(),
    )
}

/// Returns asserts that are unsatisfiable iff the authorization decisions
/// produced by `policies1` and `policies2`, represented as `Term`s of type
/// .bool, satisfy `phi` on all inputs drawn from the `SymEnv` that the
/// policysets were compiled for.
/// (Caller guarantees that `policies1` and `policies2` were compiled for the
/// same `SymEnv`.)
///
/// See also `verify_always_allows_opt()`, `verify_always_denies_opt()`,
/// `verify_implies_opt()`, `verify_equivalent_opt()`, and
/// `verify_disjoint_opt()`.
pub fn verify_is_authorized_opt(
    phi: impl FnOnce(&Term, &Term) -> Term,
    policies1: &CompiledPolicies,
    policies2: &CompiledPolicies,
) -> Asserts {
    assert_eq!(&policies1.symenv, &policies2.symenv);
    Arc::new(
        enforce_pair_compiled_policies(policies1, policies2)
            .into_iter()
            .chain(std::iter::once(factory::not(phi(
                &policies1.term,
                &policies2.term,
            ))))
            .collect(),
    )
}

/// Returns asserts that are unsatisfiable iff `policy` does not error on any
/// input in the `SymEnv` it was compiled for. If the asserts are satisfiable,
/// then there is some input in the `SymEnv` on which `policy` errors.
pub fn verify_never_errors_opt(policy: &CompiledPolicy) -> Asserts {
    verify_evaluate_opt(|term| factory::is_some(term.clone()), policy)
}

/// Returns asserts that are unsatisfiable iff `policy` matches all inputs in
/// the `SymEnv` it was compiled for. If the asserts are satisfiable, then there
/// is some input in the `SymEnv` which `policy` doesn't match.
pub fn verify_always_matches_opt(policy: &CompiledPolicy) -> Asserts {
    verify_evaluate_opt(
        |term| factory::eq(term.clone(), factory::some_of(true.into())),
        policy,
    )
}

/// Returns asserts that are unsatisfiable iff `policy` matches no inputs in the
/// `SymEnv` it was compiled for.
/// If the asserts are satisfiable, then there is some input in the `SymEnv`
/// which `policy` does match.
pub fn verify_never_matches_opt(policy: &CompiledPolicy) -> Asserts {
    verify_evaluate_opt(
        |term| factory::not(factory::eq(term.clone(), factory::some_of(true.into()))),
        policy,
    )
}

/// Returns asserts that are unsatisfiable iff the authorization decision of
/// `policies1` implies that of `policies2` for every input in the `SymEnv` that
/// the policysets were compiled for.
/// (Caller guarantees that `policies1` and `policies2` were compiled for the same `SymEnv`.)
/// In other words, every input allowed by `policies1` is allowed by `policies2`.
pub fn verify_implies_opt(policies1: &CompiledPolicies, policies2: &CompiledPolicies) -> Asserts {
    verify_is_authorized_opt(
        |term1, term2| factory::implies(term1.clone(), term2.clone()),
        policies1,
        policies2,
    )
}

/// Returns asserts that are unsatisfiable iff `policies` allows all inputs in
/// the `SymEnv` it was compiled for.
pub fn verify_always_allows_opt(policies: &CompiledPolicies) -> Asserts {
    verify_implies_opt(
        &CompiledPolicies::allow_all(policies.symenv.clone()),
        policies,
    )
}

/// Returns asserts that are unsatisfiable iff `policies` denies all inputs in
/// the `SymEnv` it was compiled for.
pub fn verify_always_denies_opt(policies: &CompiledPolicies) -> Asserts {
    verify_implies_opt(
        policies,
        &CompiledPolicies::deny_all(policies.symenv.clone()),
    )
}

/// Returns asserts that are unsatisfiable iff `policies1` and `policies2`
/// produce the same authorization decisions on all inputs in the `SymEnv` that
/// the policysets were compiled for.
/// (Caller guarantees that `policies1` and `policies2` were compiled for the same `SymEnv`.)
pub fn verify_equivalent_opt(
    policies1: &CompiledPolicies,
    policies2: &CompiledPolicies,
) -> Asserts {
    verify_is_authorized_opt(
        |term1, term2| factory::eq(term1.clone(), term2.clone()),
        policies1,
        policies2,
    )
}

/// Returns asserts that are unsatisfiable iff there is no input in the `SymEnv`
/// that is allowed by both `policies1` and `policies2`.
/// (Caller guarantees that `policies1` and `policies2` were compiled for the same `SymEnv`.)
/// This checks that the authorization semantics of `policies1` and `policies2`
/// are disjoint.  If this query is satisfiable, then there is at least one
/// input in this `SymEnv` that is allowed by both `policies1` and `policies2`.
pub fn verify_disjoint_opt(policies1: &CompiledPolicies, policies2: &CompiledPolicies) -> Asserts {
    let disjoint = |t1: &Term, t2: &Term| factory::not(factory::and(t1.clone(), t2.clone()));
    verify_is_authorized_opt(disjoint, policies1, policies2)
}
