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

//! This module contains `verify*()` functions that use the Cedar symbolic compiler,
//! authorizer, and hierarchy enforcer to generate a list of `Asserts`. These are
//! boolean terms whose conjunction is unsatisfiable if and only if the verified
//! property holds.

use std::sync::Arc;

use crate::symcc::authorizer::is_authorized;
use crate::symcc::compiler::compile;
use crate::symcc::enforcer::enforce;
use crate::symcc::env::SymEnv;
use crate::symcc::factory::{and, eq, implies, is_some, not};
use crate::symcc::result;
use crate::symcc::term::Term;

use cedar_policy::Effect;
use cedar_policy_core::ast::{Expr, Policy, PolicyID, PolicySet, Value};

pub type Asserts = Arc<Vec<Term>>;
type Result<T> = std::result::Result<T, result::Error>;

/// Returns asserts that are unsatisfiable iff the evaluation of `policy`, represented as
/// a Term of type .option .bool, satisfies `phi` on all inputs drawn from `env`.  See also
/// `verify_never_errors`.
pub fn verify_evaluate(
    phi: impl Fn(Term) -> Term,
    policy: &Policy,
    env: &SymEnv,
) -> Result<Asserts> {
    let policy_expr = policy.condition();
    let term = compile(&policy_expr, env)?;
    Ok(Arc::new(
        enforce([&policy_expr], env)
            .into_iter()
            .chain([not(phi(term))])
            .collect(),
    ))
}

/// Returns asserts that are unsatisfiable iff the authorization decisions produced
/// by `policies1` and `policies2`, represented as Terms of type .bool, satisfy `phi` on all
/// inputs drawn from `env`. See also `verify_always_allows`, `verify_always_denies`,
/// `verify_implies`, `verify_equivalent`, and `verify_disjoint`.
pub fn verify_is_authorized(
    phi: impl Fn(Term, Term) -> Term,
    policies1: &PolicySet,
    policies2: &PolicySet,
    env: &SymEnv,
) -> Result<Asserts> {
    let term1 = is_authorized(policies1, env)?;
    let term2 = is_authorized(policies2, env)?;
    let xs: Vec<Expr> = policies1
        .policies()
        .chain(policies2.policies())
        .map(|p| p.condition())
        .collect();
    Ok(Arc::new(
        enforce(xs.iter(), env)
            .into_iter()
            .chain([not(phi(term1, term2))])
            .collect(),
    ))
}

/// Returns asserts that are unsatisfiable iff `policy` does not error on any input in
/// `env`. If the asserts are satisfiable, then there is some input in `env` on
/// which `policy` errors.
pub fn verify_never_errors(policy: &Policy, env: &SymEnv) -> Result<Asserts> {
    verify_evaluate(is_some, policy, env)
}

/// Returns asserts that are unsatisfiable iff the authorization decision of `policies1`
/// implies that of `policies2` for every input in `env`. In other words, every input
/// allowed by `policies1` is allowed by `policies2`.
pub fn verify_implies(
    policies1: &PolicySet,
    policies2: &PolicySet,
    env: &SymEnv,
) -> Result<Asserts> {
    verify_is_authorized(implies, policies1, policies2, env)
}

/// Returns asserts that are unsatisfiable iff `policies` allows all inputs in `env`.
pub fn verify_always_allows(policies: &PolicySet, env: &SymEnv) -> Result<Asserts> {
    let allow_all = Policy::from_when_clause(
        Effect::Permit,
        Expr::from(Value::from(true)),
        PolicyID::from_string("allowAll"),
        None,
    );
    let mut allow_all_ps = PolicySet::new();
    // PANIC SAFETY
    #[allow(
        clippy::expect_used,
        reason = "Adding allow_all to a `PolicySet` should not error"
    )]
    allow_all_ps
        .add(allow_all)
        .expect("Could not add policy to policy set.");
    verify_implies(&allow_all_ps, policies, env)
}

/// Returns asserts that are unsatisfiable iff `policies` denies all inputs in `env`.
pub fn verify_always_denies(policies: &PolicySet, env: &SymEnv) -> Result<Asserts> {
    verify_implies(policies, &PolicySet::new(), env)
}

/// Returns asserts that are unsatisfiable iff `policies1` and `policies2` produce the same
/// authorization decision on all inputs in `env`.
pub fn verify_equivalent(
    policies1: &PolicySet,
    policies2: &PolicySet,
    env: &SymEnv,
) -> Result<Asserts> {
    verify_is_authorized(eq, policies1, policies2, env)
}

/// Returns asserts that are unsatisfiable iff there is no input in `env` that is
/// allowed by both `policies1` and `policies2`. This checks that the authorization semantics
/// of `policies1` and `policies2` are disjoint. If this query is satisfiable, then there is at
/// least one input that is allowed by both `policies1` and `policies2`.
pub fn verify_disjoint(
    policies1: &PolicySet,
    policies2: &PolicySet,
    env: &SymEnv,
) -> Result<Asserts> {
    let disjoint = |t1: Term, t2: Term| not(and(t1, t2));
    verify_is_authorized(disjoint, policies1, policies2, env)
}
