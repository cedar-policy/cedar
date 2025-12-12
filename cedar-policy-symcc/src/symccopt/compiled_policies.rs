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
//! <https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/Cedar/SymCCOpt/CompiledPolicies.lean>.

use std::collections::BTreeSet;

use cedar_policy::{Effect, RequestEnv, Schema};
use cedar_policy_core::ast::{Policy, PolicySet};

use crate::symcc::{self, factory, term::Term, SymEnv};
use crate::Result;

// Unlike the Lean version, here in the Rust version we don't define our own
// error type for this module, we just reuse `crate::Result`

/// Represents a symbolically compiled policy. This can be fed into the various
/// functions in symccopt.rs for efficient solver queries (that don't have to
/// repeat symbolic compilation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    /// typechecked policy compiled to a `Term` of type Option<bool>
    pub(super) term: Term,
    /// `SymEnv` representing the environment this policy was compiled for
    pub(super) symenv: symcc::SymEnv,
    /// typechecked policy
    pub(super) policy: Policy,
    /// footprint of the policy
    pub(super) footprint: BTreeSet<Term>,
    /// acyclicity constraints for this policy
    pub(super) acyclicity: BTreeSet<Term>,
}

impl CompiledPolicy {
    /// Compile a policy for the given `RequestEnv`.
    ///
    /// This function calls the Cedar typechecker to obtain a policy that is
    /// semantically equivalent to `policy` and well-typed with respect to
    /// `env`.  Then, it runs the symbolic compiler to produce a compiled
    /// policy.
    ///
    /// This function ensures well-typedness for you. You need not (and should
    /// not) call `well_typed_policy()` or `WellTypedPolicy::from_policy()`
    /// prior to calling this.
    pub fn compile(policy: &Policy, env: &RequestEnv, schema: &Schema) -> Result<Self> {
        let policy = symcc::well_typed_policy(policy, env, schema)?;
        let env = symcc::SymEnv::new(schema, env)?;
        let term = symcc::compiler::compile(&policy.condition(), &env)?;
        let footprint: BTreeSet<Term> =
            symcc::enforcer::footprint(&policy.condition(), &env).collect();
        let acyclicity = footprint
            .iter()
            .map(|term| symcc::enforcer::acyclicity(term, &env.entities))
            .collect();
        Ok(Self {
            term,
            symenv: env,
            policy,
            footprint,
            acyclicity,
        })
    }

    /// Convert a `CompiledPolicy` to a `CompiledPolicies` representing a
    /// singleton policyset with just that policy.
    ///
    /// This function is intended to be much more efficient than re-compiling
    /// with `CompiledPolicies::compile()`.
    pub fn into_compiled_policies(self) -> CompiledPolicies {
        CompiledPolicies {
            term: match self.policy.effect() {
                Effect::Forbid => {
                    // a singleton pset with only a forbid policy, always denies everything
                    false.into()
                }
                Effect::Permit => {
                    // a singleton pset with only a permit policy, allows iff that policy evaluates to some(true)
                    factory::eq(self.term, factory::some_of(true.into()))
                }
            },
            symenv: self.symenv,
            #[expect(
                clippy::expect_used,
                reason = "Constructing a singleton policyset should not fail. For more future-proof (in case somehow in the future it becomes possible for constructing a singleton policyset to fail), we should add a `PolicySet::singleton()` function to cedar-policy-core and use that here."
            )]
            policies: PolicySet::try_from_iter([self.policy])
                .expect("constructing a singleton policyset should not fail"),
            footprint: self.footprint, // the footprint of a singleton policyset is the same as the footprint of the policy
            acyclicity: self.acyclicity, // the acyclicity constraints for a singleton policyset are the same as the acyclicity constraints for the policy
        }
    }
}

/// Represents a symbolically compiled policyset. This can be fed into the
/// various functions in symccopt.rs for efficient solver queries (that don't
/// have to repeat symbolic compilation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicies {
    /// typechecked policies compiled to a single `Term` of type bool
    /// representing the authorization decision
    pub(super) term: Term,
    /// `SymEnv` representing the environment these policies were compiled for
    pub(super) symenv: symcc::SymEnv,
    /// typechecked policies
    pub(super) policies: PolicySet,
    /// footprint of the policies
    pub(super) footprint: BTreeSet<Term>,
    /// acyclicity constraints for these policies
    pub(super) acyclicity: BTreeSet<Term>,
}

impl CompiledPolicies {
    /// Compile a set of policies for the given `RequestEnv`.
    ///
    /// This function calls the Cedar typechecker on each policy to obtain a
    /// policy that is semantically equivalent to the original policy and
    /// well-typed with respect to `env`. Then, it runs the symbolic compiler to
    /// produce a compiled policy.
    ///
    /// This function ensures well-typedness for you. You need not (and should
    /// not) call `well_typed_policies()` or `WellTypedPolicies::from_policies()`
    /// prior to calling this.
    pub fn compile(pset: &PolicySet, env: &RequestEnv, schema: &Schema) -> Result<Self> {
        let policies = symcc::well_typed_policies(pset, env, schema)?;
        let env = symcc::SymEnv::new(schema, env)?;
        let term = symcc::authorizer::is_authorized(&policies, &env)?;
        let footprint = {
            let conditions: Vec<_> = policies.policies().map(Policy::condition).collect();
            symcc::enforcer::footprints(conditions.iter(), &env)
        };
        let acyclicity = footprint
            .iter()
            .map(|term| symcc::enforcer::acyclicity(term, &env.entities))
            .collect();
        Ok(Self {
            term,
            symenv: env,
            policies,
            footprint,
            acyclicity,
        })
    }

    /// A `CompiledPolicies` that represents the policyset that allows all
    /// requests in the `SymEnv`.
    pub fn allow_all(symenv: SymEnv) -> Self {
        let footprint: BTreeSet<Term> =
            symcc::enforcer::footprint(&symcc::verifier::allow_all().condition(), &symenv)
                .collect();
        Self {
            term: Term::from(true),
            policies: symcc::verifier::allow_all_pset(),
            acyclicity: footprint
                .iter()
                .map(|term| symcc::enforcer::acyclicity(term, &symenv.entities))
                .collect(),
            symenv,
            footprint,
        }
    }

    /// A `CompiledPolicies` that represents the policyset that denies all
    /// requests in the `SymEnv`.
    pub fn deny_all(symenv: SymEnv) -> Self {
        Self {
            term: Term::from(false),
            symenv,
            policies: PolicySet::new(),
            footprint: BTreeSet::new(),
            acyclicity: BTreeSet::new(),
        }
    }
}
