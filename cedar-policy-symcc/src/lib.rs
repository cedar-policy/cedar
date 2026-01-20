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

#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod err;
mod symcc;
mod symccopt;

use cedar_policy::{Effect, Policy, PolicySet, RequestEnv, Schema};
use nonempty::{nonempty, NonEmpty};
use std::fmt;

use err::{Error, Result};
use solver::Solver;
use symcc::{well_typed_policies, well_typed_policy, Environment, SymCompiler};
use symccopt::{
    verify_always_allows_opt, verify_always_denies_opt, verify_always_matches_opt,
    verify_disjoint_opt, verify_equivalent_opt, verify_implies_opt, verify_matches_disjoint_opt,
    verify_matches_equivalent_opt, verify_matches_implies_opt, verify_never_errors_opt,
    verify_never_matches_opt,
};

pub use symcc::bitvec;
pub use symcc::ext;
pub use symcc::extension_types;
pub use symcc::factory as term_factory;
pub use symcc::op;
pub use symcc::solver;
pub use symcc::term;
pub use symcc::term_type;
pub use symcc::type_abbrevs;
pub use symcc::verifier::Asserts;
pub use symcc::Interpretation;
pub use symcc::{Env, SmtLibScript, SymEnv};

use crate::symccopt::CompiledPolicys;

impl SymEnv {
    /// Constructs a new [`SymEnv`] from the given [`Schema`] and [`RequestEnv`].
    pub fn new(schema: &Schema, req_env: &RequestEnv) -> Result<Self> {
        let env = Environment::from_request_env(req_env, schema.as_ref())
            .ok_or_else(|| Error::ActionNotInSchema(req_env.action().to_string()))?;
        Ok(Self::of_env(&env)?)
    }
}

/// Validated and well-typed policy.
#[derive(Clone, Debug)]
pub struct WellTypedPolicy {
    policy: cedar_policy_core::ast::Policy,
}

impl WellTypedPolicy {
    /// Returns a reference to the underlying policy.
    pub fn policy(&self) -> &cedar_policy_core::ast::Policy {
        &self.policy
    }

    /// Creates a well-typed policy with respect to the given request environment and schema.
    /// This ensures that the policy satisfies the well-typedness constraints required by the
    /// symbolic compiler, by applying Cedar's typechecker transformations.
    pub fn from_policy(
        policy: &Policy,
        env: &RequestEnv,
        schema: &Schema,
    ) -> Result<WellTypedPolicy> {
        well_typed_policy(policy.as_ref(), env, schema).map(|p| WellTypedPolicy { policy: p })
    }

    /// Converts a [`Policy`] to a [`WellTypedPolicy`] without type checking.
    /// Note that SymCC may fail on the policy produced by this function.
    pub fn from_policy_unchecked(policy: &Policy) -> Self {
        WellTypedPolicy {
            policy: policy.as_ref().clone(),
        }
    }
}

impl fmt::Display for WellTypedPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.policy)
    }
}

/// Validated and well-typed policy set.
/// Similar to [`WellTypedPolicy`] but for policy sets.
#[derive(Clone, Debug)]
pub struct WellTypedPolicies {
    policies: cedar_policy_core::ast::PolicySet,
}

impl WellTypedPolicies {
    /// Returns a reference to the underlying policy set
    pub fn policy_set(&self) -> &cedar_policy_core::ast::PolicySet {
        &self.policies
    }

    /// Creates a well-typed policy set with respect to the given request environment and schema.
    /// This ensures that the policies satisfy the `WellTyped` constraints required by the
    /// symbolic compiler, by applying Cedar's typechecker transformations.
    pub fn from_policies(
        ps: &PolicySet,
        env: &RequestEnv,
        schema: &Schema,
    ) -> Result<WellTypedPolicies> {
        well_typed_policies(ps.as_ref(), env, schema).map(|ps| WellTypedPolicies { policies: ps })
    }

    /// Converts a [`PolicySet`] to a [`WellTypedPolicies`] without type checking.
    /// Note that SymCC may fail on the policy set produced by this function.
    pub fn from_policies_unchecked(ps: &PolicySet) -> Self {
        WellTypedPolicies {
            policies: ps.as_ref().clone(),
        }
    }
}

impl fmt::Display for WellTypedPolicies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.policies)
    }
}

/// Represents a symbolically compiled policy. This can be fed into various
/// functions on [`CedarSymCompiler`] for efficient solver queries (that don't
/// have to repeat symbolic compilation).
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    policy: symccopt::CompiledPolicy,
}

impl CompiledPolicy {
    /// Compile a policy for the given `RequestEnv`.
    ///
    /// This does all the validating and well-typing that you need; you need not
    /// (and should not) call `WellTypedPolicy::from_policy()` prior to calling
    /// this.
    pub fn compile(policy: &Policy, env: &RequestEnv, schema: &Schema) -> Result<Self> {
        Ok(Self {
            policy: symccopt::CompiledPolicy::compile(policy.as_ref(), env, schema)?,
        })
    }

    /// Compile a policy for the given `RequestEnv`, using a custom `SymEnv`
    /// rather than the one that would naturally be derived from this
    /// `RequestEnv`.
    ///
    /// Most often, you want `compile()` instead.
    /// `compile_with_custom_symenv()` is generally used to compile with
    /// `SymEnv`s that are more concrete than the default `SymEnv`s, with
    /// constraints/concretizations of the entity hierarchy or request
    /// variables.
    ///
    /// Caller is responsible for some currently-undocumented invariants about
    /// the relationship between the `RequestEnv` and the `SymEnv`.
    /// This function has no analogue in the Lean (as of this writing).
    /// Use at your own risk.
    pub fn compile_with_custom_symenv(
        policy: &Policy,
        env: &RequestEnv,
        schema: &Schema,
        symenv: SymEnv,
    ) -> Result<Self> {
        Ok(Self {
            policy: symccopt::CompiledPolicy::compile_with_custom_symenv(
                policy.as_ref(),
                env,
                schema,
                symenv,
            )?,
        })
    }

    /// Get the `Effect` of this `CompiledPolicy`
    pub fn effect(&self) -> Effect {
        self.policy.effect()
    }

    /// Convert a `CompiledPolicy` to a `CompiledPolicies` representing a
    /// singleton policyset with just that policy.
    ///
    /// This function is intended to be much more efficient than re-compiling
    /// with `CompiledPolicies::compile()`.
    pub fn into_compiled_policies(self) -> CompiledPolicies {
        CompiledPolicies {
            policies: self.policy.into_compiled_policies(),
        }
    }
}

/// Represents a symbolically compiled policyset. This can be fed into various
/// functions on [`CedarSymCompiler`] for efficient solver queries (that don't
/// have to repeat symbolic compilation).
#[derive(Debug, Clone)]
pub struct CompiledPolicies {
    policies: symccopt::CompiledPolicies,
}

impl CompiledPolicies {
    /// Compile a policyset for the given `RequestEnv`.
    ///
    /// This does all the validating and well-typing that you need; you need not
    /// (and should not) call `WellTypedPolicies::from_policies()` prior to
    /// calling this.
    pub fn compile(pset: &PolicySet, env: &RequestEnv, schema: &Schema) -> Result<Self> {
        Ok(Self {
            policies: symccopt::CompiledPolicies::compile(pset.as_ref(), env, schema)?,
        })
    }

    /// Compile a set of policies for the given `RequestEnv`, using a custom
    /// `SymEnv` rather than the one that would naturally be derived from this
    /// `RequestEnv`.
    ///
    /// Most often, you want `compile()` instead.
    /// `compile_with_custom_symenv()` is generally used to compile with
    /// `SymEnv`s that are more concrete than the default `SymEnv`s, with
    /// constraints/concretizations of the entity hierarchy or request
    /// variables.
    ///
    /// Caller is responsible for some currently-undocumented invariants about
    /// the relationship between the `RequestEnv` and the `SymEnv`.
    /// This function has no analogue in the Lean (as of this writing).
    /// Use at your own risk.
    pub fn compile_with_custom_symenv(
        pset: &PolicySet,
        env: &RequestEnv,
        schema: &Schema,
        symenv: SymEnv,
    ) -> Result<Self> {
        Ok(Self {
            policies: symccopt::CompiledPolicies::compile_with_custom_symenv(
                pset.as_ref(),
                env,
                schema,
                symenv,
            )?,
        })
    }
}

/// Cedar symbolic compiler, which takes your policies and schemas
/// and converts them to SMT queries to perform various verification
/// tasks such as checking if a policy set always allows/denies,
/// if two policy sets are equivalent, etc.
#[derive(Clone, Debug)]
pub struct CedarSymCompiler<S: Solver> {
    /// SymCompiler
    symcc: SymCompiler<S>,
}

impl<S: Solver> CedarSymCompiler<S> {
    /// Constructs a new [`CedarSymCompiler`] with the given [`Solver`] instance.
    pub fn new(solver: S) -> Result<Self> {
        Ok(Self {
            symcc: SymCompiler::new(solver),
        })
    }

    /// Returns a reference to the [`Solver`] instance used to construct this [`CedarSymCompiler`]
    pub fn solver(&self) -> &S {
        self.symcc.solver()
    }

    /// Returns a mutable reference to the [`Solver`] instance used to construct this [`CedarSymCompiler`]
    pub fn solver_mut(&mut self) -> &mut S {
        self.symcc.solver_mut()
    }

    /// Calls the underlying solver to check if the given `asserts` are unsatisfiable.
    /// Returns `true` iff the asserts are unsatisfiable.
    ///
    /// NOTE: This API is an experimental feature that may break or change in the future.
    pub async fn check_unsat(&mut self, asserts: &WellFormedAsserts<'_>) -> Result<bool> {
        self.symcc
            .check_unsat(|_| Ok(asserts.asserts().clone()), asserts.symenv())
            .await
    }

    /// Calls the underlying solver with given raw `Asserts` and corresponding `SymEnv`,
    /// returning `true` iff the asserts are unsatisfiable.
    ///
    /// Caller is responsible for ensuring that the `Asserts` and `SymEnv` are
    /// well-formed and valid with respect to each other.
    ///
    /// NOTE: This API is an experimental feature that may break or change in the future.
    pub async fn check_unsat_raw(&mut self, asserts: Asserts, symenv: &SymEnv) -> Result<bool> {
        self.symcc.check_unsat(|_| Ok(asserts), symenv).await
    }

    /// Calls the underlying solver to check if the given `asserts` are unsatisfiable.
    /// Returns some counterexample to the given symbolic assertions iff they are satisfiable.
    ///
    /// NOTE: This API is an experimental feature that may break or change in the future.
    pub async fn check_sat(&mut self, asserts: &WellFormedAsserts<'_>) -> Result<Option<Env>> {
        // since `asserts.policies()` doesn't itself produce a clone-able
        // iterator, we create this iterator which is indeed (cheaply)
        // clone-able
        let policies: Vec<&CompiledPolicys<'_>> = asserts.policies().collect();
        let policies_iter = policies.iter().copied();

        self.symcc
            .sat_asserts_opt(asserts.asserts(), policies_iter)
            .await
    }

    /// Returns true iff [`WellTypedPolicy`] does not error on any well-formed
    /// input in the given symbolic environment.
    ///
    /// Consider using the optimized version `check_never_errors_opt()` instead,
    /// which will allow you to reuse a `CompiledPolicy` across many queries.
    #[deprecated(since = "0.3.0", note = "use `check_never_errors_opt()` instead")]
    pub async fn check_never_errors(
        &mut self,
        policy: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc.check_never_errors(&policy.policy, symenv).await
    }

    /// Returns true iff the [`CompiledPolicy`] does not error on any
    /// well-formed input in the `RequestEnv` it was compiled for.
    pub async fn check_never_errors_opt(&mut self, policy: &CompiledPolicy) -> Result<bool> {
        self.symcc.check_never_errors_opt(&policy.policy).await
    }

    /// Similar to [`Self::check_never_errors`], but returns a counterexample
    /// if the policy could error on well-formed input.
    ///
    /// Consider using the optimized version `check_never_errors_with_counterexample_opt()`
    /// instead, which will allow you to reuse a `CompiledPolicy` across many
    /// queries.
    #[deprecated(
        since = "0.3.0",
        note = "use `check_never_errors_with_counterexample_opt()` instead"
    )]
    pub async fn check_never_errors_with_counterexample(
        &mut self,
        policy: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_never_errors_with_counterexample(&policy.policy, symenv)
            .await
    }

    /// Similar to [`Self::check_never_errors_opt`], but returns a counterexample
    /// if the policy could error on well-formed input.
    pub async fn check_never_errors_with_counterexample_opt(
        &mut self,
        policy: &CompiledPolicy,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_never_errors_with_counterexample_opt(&policy.policy)
            .await
    }

    /// Returns true iff [`WellTypedPolicy`] matches all well-formed inputs in
    /// the given symbolic environment. That is, if `policy` is a `permit`
    /// policy, it allows all inputs in the `symenv`, or if `policy` is a
    /// `forbid` policy, it denies all inputs in the `symenv`.
    ///
    /// Consider using the optimized version `check_always_matches_opt()` instead,
    /// which will allow you to reuse a `CompiledPolicy` across many queries.
    #[deprecated(since = "0.3.0", note = "use `check_always_matches_opt()` instead")]
    pub async fn check_always_matches(
        &mut self,
        policy: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc
            .check_always_matches(&policy.policy, symenv)
            .await
    }

    /// Returns true iff the [`CompiledPolicy`] matches all well-formed inputs
    /// in the `RequestEnv` it was compiled for.
    pub async fn check_always_matches_opt(&mut self, policy: &CompiledPolicy) -> Result<bool> {
        self.symcc.check_always_matches_opt(&policy.policy).await
    }

    /// Similar to [`Self::check_always_matches`], but returns a counterexample
    /// if the policy does not match some well-formed input.
    ///
    /// Consider using the optimized version `check_always_matches_with_counterexample_opt()`
    /// instead, which will allow you to reuse a `CompiledPolicy` across many
    /// queries.
    #[deprecated(
        since = "0.3.0",
        note = "use `check_always_matches_with_counterexample_opt()` instead"
    )]
    pub async fn check_always_matches_with_counterexample(
        &mut self,
        policy: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_always_matches_with_counterexample(&policy.policy, symenv)
            .await
    }

    /// Similar to [`Self::check_always_matches_opt`], but returns a counterexample
    /// if the policy does not match some well-formed input.
    pub async fn check_always_matches_with_counterexample_opt(
        &mut self,
        policy: &CompiledPolicy,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_always_matches_with_counterexample_opt(&policy.policy)
            .await
    }

    /// Returns true iff [`WellTypedPolicy`] matches no well-formed inputs in
    /// the given symbolic environment.
    ///
    /// Consider using the optimized version `check_never_matches_opt()` instead,
    /// which will allow you to reuse a `CompiledPolicy` across many queries.
    #[deprecated(since = "0.3.0", note = "use `check_never_matches_opt()` instead")]
    pub async fn check_never_matches(
        &mut self,
        policy: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc.check_never_matches(&policy.policy, symenv).await
    }

    /// Returns true iff the [`CompiledPolicy`] matches no well-formed inputs
    /// in the `RequestEnv` it was compiled for.
    pub async fn check_never_matches_opt(&mut self, policy: &CompiledPolicy) -> Result<bool> {
        self.symcc.check_never_matches_opt(&policy.policy).await
    }

    /// Similar to [`Self::check_never_matches`], but returns a counterexample
    /// if the policy matches some well-formed input.
    ///
    /// Consider using the optimized version `check_never_matches_with_counterexample_opt()`
    /// instead, which will allow you to reuse a `CompiledPolicy` across many
    /// queries.
    #[deprecated(
        since = "0.3.0",
        note = "use `check_never_matches_with_counterexample_opt()` instead"
    )]
    pub async fn check_never_matches_with_counterexample(
        &mut self,
        policy: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_never_matches_with_counterexample(&policy.policy, symenv)
            .await
    }

    /// Similar to [`Self::check_never_matches_opt`], but returns a counterexample
    /// if the policy matches some well-formed input.
    pub async fn check_never_matches_with_counterexample_opt(
        &mut self,
        policy: &CompiledPolicy,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_never_matches_with_counterexample_opt(&policy.policy)
            .await
    }

    /// Returns true iff `policy1` and `policy2` match exactly the same set of
    /// well-formed inputs in the given symbolic environment.
    ///
    /// Compare with `check_equivalent`, which takes two policysets (which could consist
    /// of a single policy, or more) and determines whether the _authorization behavior_
    /// of those policysets is equivalent for well-formed inputs in the `symenv`. This
    /// function differs from `check_equivalent` on singleton policysets in how it treats
    /// `forbid` policies -- while `check_equivalent` trivially holds for any pair of
    /// `forbid` policies (as they both always-deny), `check_matches_equivalent` only
    /// holds if the two policies match exactly the same set of inputs. Also, a nonempty
    /// `permit` and nonempty `forbid` policy can be `check_matches_equivalent`, but can
    /// never be `check_equivalent`. (By "nonempty" we mean, matches at least one request
    /// in the given symbolic environment.)
    ///
    /// Consider using the optimized version `check_matches_equivalent_opt()` instead,
    /// which will allow you to reuse a `CompiledPolicy` across many queries.
    #[deprecated(since = "0.3.0", note = "use `check_matches_equivalent_opt()` instead")]
    pub async fn check_matches_equivalent(
        &mut self,
        policy1: &WellTypedPolicy,
        policy2: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc
            .check_matches_equivalent(&policy1.policy, &policy2.policy, symenv)
            .await
    }

    /// Returns true iff the [`CompiledPolicy`] `policy1` and `policy2` match exactly
    /// the same set of well-formed inputs in the `RequestEnv` they were compiled for.
    /// (Caller guarantees that both policies were compiled for the same `RequestEnv`.)
    ///
    /// Compare with `check_equivalent_opt`, which takes two compiled policysets and
    /// determines whether the _authorization behavior_ of those policysets is equivalent
    /// for well-formed inputs in the `RequestEnv`. This function differs from
    /// `check_equivalent_opt` on singleton policysets in how it treats `forbid` policies --
    /// while `check_equivalent_opt` trivially holds for any pair of `forbid` policies
    /// (as they both always-deny), `check_matches_equivalent_opt` only holds if the two
    /// policies match exactly the same set of inputs. Also, a nonempty `permit` and
    /// nonempty `forbid` policy can be `check_matches_equivalent_opt`, but can never
    /// be `check_equivalent_opt`. (By "nonempty" we mean, matches as least one request
    /// in the `RequestEnv` they were compiled for.)
    ///
    /// Corresponds to `checkMatchesEquivalentOpt` in the Lean.
    pub async fn check_matches_equivalent_opt(
        &mut self,
        policy1: &CompiledPolicy,
        policy2: &CompiledPolicy,
    ) -> Result<bool> {
        self.symcc
            .check_matches_equivalent_opt(&policy1.policy, &policy2.policy)
            .await
    }

    /// Similar to [`Self::check_matches_equivalent`], but returns a counterexample
    /// on which the matching behavior of `policy1` and `policy2` differ.
    ///
    /// Corresponds to `matchesEquivalent?` in the Lean.
    ///
    /// Consider using the optimized version `check_matches_equivalent_with_counterexample_opt()`
    /// instead, which will allow you to reuse a `CompiledPolicy` across many queries.
    #[deprecated(
        since = "0.3.0",
        note = "use `check_matches_equivalent_with_counterexample_opt()` instead"
    )]
    pub async fn check_matches_equivalent_with_counterexample(
        &mut self,
        policy1: &WellTypedPolicy,
        policy2: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_matches_equivalent_with_counterexample(&policy1.policy, &policy2.policy, symenv)
            .await
    }

    /// Similar to [`Self::check_matches_equivalent_opt`], but returns a counterexample
    /// on which the matching behavior of `policy1` and `policy2` differ.
    ///
    /// Corresponds to `matchesEquivalentOpt?` in the Lean.
    pub async fn check_matches_equivalent_with_counterexample_opt(
        &mut self,
        policy1: &CompiledPolicy,
        policy2: &CompiledPolicy,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_matches_equivalent_with_counterexample_opt(&policy1.policy, &policy2.policy)
            .await
    }

    /// Returns true iff `policy1` matching implies that `policy2` matches, for every
    /// well-formed input in the `symenv`. That is, for every request where `policy1`
    /// matches, `policy2` also matches.
    ///
    /// Compare with `check_implies`, which takes two policysets (which could consist of
    /// a single policy, or more) and determines whether the _authorization decision_ of
    /// the first implies that of the second. This function differs from `check_implies`
    /// on singleton policysets in how it treats `forbid` policies -- while for
    /// `check_implies`, any `forbid` policy trivially implies any `permit` policy (as
    /// always-deny always implies any policy), for `check_matches_implies`, a `forbid`
    /// policy may or may not imply a `permit` policy, and a `permit` policy may or may
    /// not imply a `forbid` policy.
    ///
    /// Consider using the optimized version `check_matches_implies_opt()` instead,
    /// which will allow you to reuse a `CompiledPolicy` across many queries.
    #[deprecated(since = "0.3.0", note = "use `check_matches_implies_opt()` instead")]
    pub async fn check_matches_implies(
        &mut self,
        policy1: &WellTypedPolicy,
        policy2: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc
            .check_matches_implies(&policy1.policy, &policy2.policy, symenv)
            .await
    }

    /// Returns true iff the [`CompiledPolicy`] `policy1` matching implies that `policy2`
    /// matches, for every well-formed input in the `RequestEnv` they were compiled for.
    /// (Caller guarantees that both policies were compiled for the same `RequestEnv`.)
    ///
    /// Compare with `check_implies_opt`, which takes two compiled policysets and
    /// determines whether the _authorization decision_ of the first implies that of the
    /// second. This function differs from `check_implies_opt` on singleton policysets
    /// in how it treats `forbid` policies -- while for `check_implies_opt`, any `forbid`
    /// policy trivially implies any `permit` policy (as always-deny always implies any
    /// policy), for `check_matches_implies_opt`, a `forbid` policy may or may not imply
    /// a `permit` policy, and a `permit` policy may or may not imply a `forbid` policy.
    ///
    /// Corresponds to `checkMatchesImpliesOpt` in the Lean.
    pub async fn check_matches_implies_opt(
        &mut self,
        policy1: &CompiledPolicy,
        policy2: &CompiledPolicy,
    ) -> Result<bool> {
        self.symcc
            .check_matches_implies_opt(&policy1.policy, &policy2.policy)
            .await
    }

    /// Similar to [`Self::check_matches_implies`], but returns a counterexample
    /// that is matched by `policy1` but not by `policy2` if it exists.
    ///
    /// Corresponds to `matchesImplies?` in the Lean.
    ///
    /// Consider using the optimized version `check_matches_implies_with_counterexample_opt()`
    /// instead, which will allow you to reuse a `CompiledPolicy` across many queries.
    #[deprecated(
        since = "0.3.0",
        note = "use `check_matches_implies_with_counterexample_opt()` instead"
    )]
    pub async fn check_matches_implies_with_counterexample(
        &mut self,
        policy1: &WellTypedPolicy,
        policy2: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_matches_implies_with_counterexample(&policy1.policy, &policy2.policy, symenv)
            .await
    }

    /// Similar to [`Self::check_matches_implies_opt`], but returns a counterexample
    /// that is matched by `policy1` but not by `policy2` if it exists.
    ///
    /// Corresponds to `matchesImpliesOpt?` in the Lean.
    pub async fn check_matches_implies_with_counterexample_opt(
        &mut self,
        policy1: &CompiledPolicy,
        policy2: &CompiledPolicy,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_matches_implies_with_counterexample_opt(&policy1.policy, &policy2.policy)
            .await
    }

    /// Returns true iff there is no well-formed input in the `symenv` that is matched
    /// by both `policy1` and `policy2`. This checks that the sets of inputs matched by
    /// `policy1` and `policy2` are disjoint.
    ///
    /// Compare with `check_disjoint`, which takes two policysets (which could consist
    /// of a single policy, or more) and determines whether the _authorization behavior_
    /// of those policysets are disjoint. This function differs from `check_disjoint` on
    /// singleton policysets in how it treats `forbid` policies -- while for
    /// `check_disjoint`, any `forbid` policy is trivially disjoint from any other policy
    /// (as it allows nothing), `check_matches_disjoint` considers whether the `forbid`
    /// policy may _match_ (rather than _allow_) any input that is matched by the other
    /// policy.
    ///
    /// Consider using the optimized version `check_matches_disjoint_opt()` instead,
    /// which will allow you to reuse a `CompiledPolicy` across many queries.
    #[deprecated(since = "0.3.0", note = "use `check_matches_disjoint_opt()` instead")]
    pub async fn check_matches_disjoint(
        &mut self,
        policy1: &WellTypedPolicy,
        policy2: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc
            .check_matches_disjoint(&policy1.policy, &policy2.policy, symenv)
            .await
    }

    /// Returns true iff there is no well-formed input in the `RequestEnv` that is
    /// matched by both [`CompiledPolicy`] `policy1` and `policy2`.
    /// (Caller guarantees that both policies were compiled for the same `RequestEnv`.)
    ///
    /// Compare with `check_disjoint_opt`, which takes two compiled policysets and
    /// determines whether the _authorization behavior_ of those policysets are disjoint.
    /// This function differs from `check_disjoint_opt` on singleton policysets in how it
    /// treats `forbid` policies -- while for `check_disjoint_opt`, any `forbid` policy
    /// is trivially disjoint from any other policy (as it allows nothing),
    /// `check_matches_disjoint_opt` considers whether the `forbid` policy may _match_
    /// (rather than _allow_) any input that is matched by the other policy.
    ///
    /// Corresponds to `checkMatchesDisjointOpt` in the Lean.
    pub async fn check_matches_disjoint_opt(
        &mut self,
        policy1: &CompiledPolicy,
        policy2: &CompiledPolicy,
    ) -> Result<bool> {
        self.symcc
            .check_matches_disjoint_opt(&policy1.policy, &policy2.policy)
            .await
    }

    /// Similar to [`Self::check_matches_disjoint`], but returns a counterexample
    /// that is matched by both `policy1` and `policy2` if it exists.
    ///
    /// Corresponds to `matchesDisjoint?` in the Lean.
    ///
    /// Consider using the optimized version `check_matches_disjoint_with_counterexample_opt()`
    /// instead, which will allow you to reuse a `CompiledPolicy` across many queries.
    #[deprecated(
        since = "0.3.0",
        note = "use `check_matches_disjoint_with_counterexample_opt()` instead"
    )]
    pub async fn check_matches_disjoint_with_counterexample(
        &mut self,
        policy1: &WellTypedPolicy,
        policy2: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_matches_disjoint_with_counterexample(&policy1.policy, &policy2.policy, symenv)
            .await
    }

    /// Similar to [`Self::check_matches_disjoint_opt`], but returns a counterexample
    /// that is matched by both `policy1` and `policy2` if it exists.
    ///
    /// Corresponds to `matchesDisjointOpt?` in the Lean.
    pub async fn check_matches_disjoint_with_counterexample_opt(
        &mut self,
        policy1: &CompiledPolicy,
        policy2: &CompiledPolicy,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_matches_disjoint_with_counterexample_opt(&policy1.policy, &policy2.policy)
            .await
    }

    /// Returns true iff the authorization decision of `pset1` implies that of
    /// `pset2` for every well-formed input in the `symenv`. That is, every
    /// input allowed by `pset1` is allowed by `pset2`; `pset2` is either more
    /// permissive than, or equivalent to, `pset1`.
    ///
    /// Consider using the optimized version `check_implies_opt()` instead,
    /// which will allow you to reuse a `CompiledPolicies` across many queries.
    #[deprecated(since = "0.3.0", note = "use `check_implies_opt()` instead")]
    pub async fn check_implies(
        &mut self,
        pset1: &WellTypedPolicies,
        pset2: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc
            .check_implies(&pset1.policies, &pset2.policies, symenv)
            .await
    }

    /// Returns true iff the authorization decision of `pset1` implies that of
    /// `pset2` for every well-formed input in the `RequestEnv` which both
    /// policysets were compiled for. (Caller guarantees that both policysets
    /// were compiled for the same `RequestEnv`.) That is, every input allowed
    /// by `pset1` is allowed by `pset2`; `pset2` is either more permissive
    /// than, or equivalent to, `pset1`.
    pub async fn check_implies_opt(
        &mut self,
        pset1: &CompiledPolicies,
        pset2: &CompiledPolicies,
    ) -> Result<bool> {
        self.symcc
            .check_implies_opt(&pset1.policies, &pset2.policies)
            .await
    }

    /// Similar to [`Self::check_implies`], but returns a counterexample
    /// that is allowed by `pset1` but not by `pset2` if it exists.
    ///
    /// Consider using the optimized version `check_implies_with_counterexample_opt()`
    /// instead, which will allow you to reuse a `CompiledPolicies` across many
    /// queries.
    #[deprecated(
        since = "0.3.0",
        note = "use `check_implies_with_counterexample_opt()` instead"
    )]
    pub async fn check_implies_with_counterexample(
        &mut self,
        pset1: &WellTypedPolicies,
        pset2: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_implies_with_counterexample(&pset1.policies, &pset2.policies, symenv)
            .await
    }

    /// Similar to [`Self::check_implies_opt`], but returns a counterexample
    /// that is allowed by `pset1` but not by `pset2` if it exists.
    pub async fn check_implies_with_counterexample_opt(
        &mut self,
        pset1: &CompiledPolicies,
        pset2: &CompiledPolicies,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_implies_with_counterexample_opt(&pset1.policies, &pset2.policies)
            .await
    }

    /// Returns true iff `pset` allows all well-formed inputs in the `symenv`.
    ///
    /// Consider using the optimized version `check_always_allows_opt()` instead,
    /// which will allow you to reuse a `CompiledPolicies` across many queries.
    #[deprecated(since = "0.3.0", note = "use `check_always_allows_opt()` instead")]
    pub async fn check_always_allows(
        &mut self,
        pset: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc.check_always_allows(&pset.policies, symenv).await
    }

    /// Returns true iff `pset` allows all well-formed inputs in the
    /// `RequestEnv` which it was compiled for.
    pub async fn check_always_allows_opt(&mut self, pset: &CompiledPolicies) -> Result<bool> {
        self.symcc.check_always_allows_opt(&pset.policies).await
    }

    /// Similar to [`Self::check_always_allows`], but returns a counterexample
    /// that is denied by `pset` if it exists.
    ///
    /// Consider using the optimized version `check_always_allows_with_counterexample_opt()`
    /// instead, which will allow you to reuse a `CompiledPolicies` across many
    /// queries.
    #[deprecated(
        since = "0.3.0",
        note = "use `check_always_allows_with_counterexample_opt()` instead"
    )]
    pub async fn check_always_allows_with_counterexample(
        &mut self,
        pset: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_always_allows_with_counterexample(&pset.policies, symenv)
            .await
    }

    /// Similar to [`Self::check_always_allows_opt`], but returns a counterexample
    /// that is denied by `pset` if it exists.
    pub async fn check_always_allows_with_counterexample_opt(
        &mut self,
        pset: &CompiledPolicies,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_always_allows_with_counterexample_opt(&pset.policies)
            .await
    }

    /// Returns true iff `pset` denies all well-formed inputs in the `symenv`.
    ///
    /// Consider using the optimized version `check_always_denies_opt()` instead,
    /// which will allow you to reuse a `CompiledPolicies` across many queries.
    #[deprecated(since = "0.3.0", note = "use `check_always_denies_opt()` instead")]
    pub async fn check_always_denies(
        &mut self,
        pset: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc.check_always_denies(&pset.policies, symenv).await
    }

    /// Returns true iff `pset` denies all well-formed inputs in the
    /// `RequestEnv` which it was compiled for.
    pub async fn check_always_denies_opt(&mut self, pset: &CompiledPolicies) -> Result<bool> {
        self.symcc.check_always_denies_opt(&pset.policies).await
    }

    /// Similar to [`Self::check_always_denies`], but returns a counterexample
    /// that is allowed by `pset` if it exists.
    ///
    /// Consider using the optimized version `check_always_denies_with_counterexample_opt()`
    /// instead, which will allow you to reuse a `CompiledPolicies` across many
    /// queries.
    #[deprecated(
        since = "0.3.0",
        note = "use `check_always_denies_with_counterexample_opt()` instead"
    )]
    pub async fn check_always_denies_with_counterexample(
        &mut self,
        pset: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_always_denies_with_counterexample(&pset.policies, symenv)
            .await
    }

    /// Similar to [`Self::check_always_denies_opt`], but returns a counterexample
    /// that is denied by `pset` if it exists.
    pub async fn check_always_denies_with_counterexample_opt(
        &mut self,
        pset: &CompiledPolicies,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_always_denies_with_counterexample_opt(&pset.policies)
            .await
    }

    /// Returns true iff `pset1` and `pset2` produce the same authorization
    /// decision on all well-formed inputs in the `symenv`.
    ///
    /// Consider using the optimized version `check_equivalent_opt()` instead,
    /// which will allow you to reuse a `CompiledPolicies` across many queries.
    #[deprecated(since = "0.3.0", note = "use `check_equivalent_opt()` instead")]
    pub async fn check_equivalent(
        &mut self,
        pset1: &WellTypedPolicies,
        pset2: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc
            .check_equivalent(&pset1.policies, &pset2.policies, symenv)
            .await
    }

    /// Returns true iff `pset1` and `pset2` produce the same authorization
    /// decision on all well-formed inputs in the `RequestEnv` which both
    /// policysets were compiled for. (Caller guarantees that both policysets
    /// were compiled for the same `RequestEnv`.)
    pub async fn check_equivalent_opt(
        &mut self,
        pset1: &CompiledPolicies,
        pset2: &CompiledPolicies,
    ) -> Result<bool> {
        self.symcc
            .check_equivalent_opt(&pset1.policies, &pset2.policies)
            .await
    }

    /// Similar to [`Self::check_equivalent`], but returns a counterexample
    /// on which the authorization decisions of `pset1` and `pset2` differ.
    ///
    /// Consider using the optimized version `check_equivalent_with_counterexample_opt()`
    /// instead, which will allow you to reuse a `CompiledPolicies` across many
    /// queries.
    #[deprecated(
        since = "0.3.0",
        note = "use `check_equivalent_with_counterexample_opt()` instead"
    )]
    pub async fn check_equivalent_with_counterexample(
        &mut self,
        pset1: &WellTypedPolicies,
        pset2: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_equivalent_with_counterexample(&pset1.policies, &pset2.policies, symenv)
            .await
    }

    /// Similar to [`Self::check_equivalent_opt`], but returns a counterexample
    /// on which the authorization decisions of `pset1` and `pset2` differ.
    pub async fn check_equivalent_with_counterexample_opt(
        &mut self,
        pset1: &CompiledPolicies,
        pset2: &CompiledPolicies,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_equivalent_with_counterexample_opt(&pset1.policies, &pset2.policies)
            .await
    }

    /// Returns true iff there is no well-formed input in the `symenv` that is
    /// allowed by both `pset1` and `pset2`. If this returns `false`, then there
    /// is at least one well-formed input that is allowed by both `pset1` and
    /// `pset2`.
    ///
    /// Consider using the optimized version `check_disjoint_opt()` instead,
    /// which will allow you to reuse a `CompiledPolicies` across many queries.
    #[deprecated(since = "0.3.0", note = "use `check_disjoint_opt()` instead")]
    pub async fn check_disjoint(
        &mut self,
        pset1: &WellTypedPolicies,
        pset2: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc
            .check_disjoint(&pset1.policies, &pset2.policies, symenv)
            .await
    }

    /// Returns true iff there is no well-formed input in the `RequestEnv` that
    /// is allowed by both `pset1` and `pset2`.
    /// (Caller guarantees that `policies1` and `policies2` were compiled for
    /// the same `RequestEnv`.)
    pub async fn check_disjoint_opt(
        &mut self,
        pset1: &CompiledPolicies,
        pset2: &CompiledPolicies,
    ) -> Result<bool> {
        self.symcc
            .check_disjoint_opt(&pset1.policies, &pset2.policies)
            .await
    }

    /// Similar to [`Self::check_disjoint`], but returns a counterexample
    /// that is allowed by both `pset1` and `pset2`.
    ///
    /// Consider using the optimized version `check_disjoint_with_counterexample_opt()`
    /// instead, which will allow you to reuse a `CompiledPolicies` across many
    /// queries.
    #[deprecated(
        since = "0.3.0",
        note = "use `check_disjoint_with_counterexample_opt()` instead"
    )]
    pub async fn check_disjoint_with_counterexample(
        &mut self,
        pset1: &WellTypedPolicies,
        pset2: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_disjoint_with_counterexample(&pset1.policies, &pset2.policies, symenv)
            .await
    }

    /// Similar to [`Self::check_disjoint_opt`], but returns a counterexample
    /// that is allowed by both `pset1` and `pset2`.
    pub async fn check_disjoint_with_counterexample_opt(
        &mut self,
        pset1: &CompiledPolicies,
        pset2: &CompiledPolicies,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_disjoint_with_counterexample_opt(&pset1.policies, &pset2.policies)
            .await
    }
}

/// Well-formed assertions generated by the symbolic compiler.
#[derive(Clone, Debug)]
pub struct WellFormedAsserts<'a> {
    asserts: Asserts,
    /// All `CompiledPolicy`s or `CompiledPolicies` that were used to generate the asserts.
    ///
    /// INVARIANT: All of these are for the same `symenv`.
    policies: NonEmpty<CompiledPolicys<'a>>,
}

impl<'a> WellFormedAsserts<'a> {
    /// Returns the symbolic environment these asserts were generated in.
    pub fn symenv(&self) -> &SymEnv {
        // Relying on the INVARIANT that all the items in `self.policies` have
        // the same `symenv`
        self.policies.first().symenv()
    }

    /// Returns the underlying raw [`Asserts`].
    pub fn asserts(&self) -> &Asserts {
        &self.asserts
    }

    /// Returns the `CompiledPolicys` that were used to generate the asserts
    fn policies(&self) -> impl Iterator<Item = &CompiledPolicys<'a>> {
        self.policies.iter()
    }
}

/// Generate the [`WellFormedAsserts`] for the `check_never_errors()`
/// operation, without actually calling a solver.
///
/// That is, the result of
/// ```no_compile
/// compiler.check_unsat(never_errors_asserts(policy))
/// ```
/// should be the same as `compiler.check_never_errors_opt(policy)`.
///
/// Likewise, the result of
/// ```no_compile
/// compiler.check_sat(asserts_for_never_errors(policy))
/// ```
/// should be the same as `compiler.check_never_errors_with_counterexample_opt(policy)`.
///
/// NOTE: This API is an experimental feature, and the API may change
/// or break in the future.
pub fn never_errors_asserts<'a>(policy: &'a CompiledPolicy) -> WellFormedAsserts<'a> {
    WellFormedAsserts {
        asserts: verify_never_errors_opt(&policy.policy),
        policies: nonempty![CompiledPolicys::Policy(&policy.policy)],
    }
}

/// Generate the [`WellFormedAsserts`] for the `check_always_matches()`
/// operation, without actually calling a solver.
///
/// That is, the result of
/// ```no_compile
/// compiler.check_unsat(always_matches_asserts(policy))
/// ```
/// should be the same as `compiler.check_always_matches_opt(policy)`.
///
/// Likewise, the result of
/// ```no_compile
/// compiler.check_sat(always_matches_asserts(policy))
/// ```
/// should be the same as `compiler.check_always_matches_opt(policy)`.
///
/// NOTE: This API is an experimental feature, and the API may change
/// or break in the future.
pub fn always_matches_asserts<'a>(policy: &'a CompiledPolicy) -> WellFormedAsserts<'a> {
    WellFormedAsserts {
        asserts: verify_always_matches_opt(&policy.policy),
        policies: nonempty![CompiledPolicys::Policy(&policy.policy)],
    }
}

/// Generate the [`WellFormedAsserts`] for the `check_never_matches()`
/// operation, without actually calling a solver.
///
/// That is, the result of
/// ```no_compile
/// compiler.check_unsat(never_matches_asserts(policy))
/// ```
/// should be the same as `compiler.check_never_matches_opt(policy)`.
///
/// Likewise, the result of
/// ```no_compile
/// compiler.check_sat(never_matches_asserts(policy))
/// ```
/// should be the same as `compiler.check_never_matches_opt(policy)`.
///
/// NOTE: This API is an experimental feature, and the API may change
/// or break in the future.
pub fn never_matches_asserts<'a>(policy: &'a CompiledPolicy) -> WellFormedAsserts<'a> {
    WellFormedAsserts {
        asserts: verify_never_matches_opt(&policy.policy),
        policies: nonempty![CompiledPolicys::Policy(&policy.policy)],
    }
}

/// Generate the [`WellFormedAsserts`] for the `check_matches_equivalent()`
/// operation, without actually calling a solver.
///
/// That is, the result of
/// ```no_compile
/// compiler.check_unsat(matches_equivalent_asserts(policy1, policy2))
/// ```
/// should be the same as `compiler.check_matches_equivalent(policy1, policy2)`.
///
/// Likewise, the result of
/// ```no_compile
/// compiler.check_sat(matches_equivalent_asserts(policy1, policy2))
/// ```
/// should be the same as `compiler.check_matches_equivalent_opt(policy1, policy2)`.
///
/// NOTE: This API is an experimental feature, and the API may change
/// or break in the future.
pub fn matches_equivalent_asserts<'a>(
    policy1: &'a CompiledPolicy,
    policy2: &'a CompiledPolicy,
) -> WellFormedAsserts<'a> {
    WellFormedAsserts {
        asserts: verify_matches_equivalent_opt(&policy1.policy, &policy2.policy),
        policies: nonempty![
            CompiledPolicys::Policy(&policy1.policy),
            CompiledPolicys::Policy(&policy2.policy)
        ],
    }
}

/// Generate the [`WellFormedAsserts`] for the `check_matches_implies()`
/// operation, without actually calling a solver.
///
/// That is, the result of
/// ```no_compile
/// compiler.check_unsat(matches_implies_asserts(policy1, policy2))
/// ```
/// should be the same as `compiler.check_matches_implies(policy1, policy2)`.
///
/// Likewise, the result of
/// ```no_compile
/// compiler.check_sat(matches_implies_asserts(policy1, policy2))
/// ```
/// should be the same as `compiler.check_matches_implies_opt(policy1, policy2)`.
///
/// NOTE: This API is an experimental feature, and the API may change
/// or break in the future.
pub fn matches_implies_asserts<'a>(
    policy1: &'a CompiledPolicy,
    policy2: &'a CompiledPolicy,
) -> WellFormedAsserts<'a> {
    WellFormedAsserts {
        asserts: verify_matches_implies_opt(&policy1.policy, &policy2.policy),
        #[expect(
            clippy::expect_used,
            reason = "NonEmpty::collect() will not fail on a nonempty iterator"
        )]
        policies: nonempty![
            CompiledPolicys::Policy(&policy1.policy),
            CompiledPolicys::Policy(&policy2.policy)
        ],
    }
}

/// Generate the [`WellFormedAsserts`] for the `check_matches_disjoint()`
/// operation, without actually calling a solver.
///
/// That is, the result of
/// ```no_compile
/// compiler.check_unsat(matches_disjoint_asserts(policy1, policy2))
/// ```
/// should be the same as `compiler.check_matches_disjoint(policy1, policy2)`.
///
/// Likewise, the result of
/// ```no_compile
/// compiler.check_sat(matches_disjoint_asserts(policy1, policy2))
/// ```
/// should be the same as `compiler.check_matches_disjoint_opt(policy1, policy2)`.
///
/// NOTE: This API is an experimental feature, and the API may change
/// or break in the future.
pub fn matches_disjoint_asserts<'a>(
    policy1: &'a CompiledPolicy,
    policy2: &'a CompiledPolicy,
) -> WellFormedAsserts<'a> {
    WellFormedAsserts {
        asserts: verify_matches_disjoint_opt(&policy1.policy, &policy2.policy),
        #[expect(
            clippy::expect_used,
            reason = "NonEmpty::collect() will not fail on a nonempty iterator"
        )]
        policies: nonempty![
            CompiledPolicys::Policy(&policy1.policy),
            CompiledPolicys::Policy(&policy2.policy)
        ],
    }
}

/// Generate the [`WellFormedAsserts`] for the `check_always_allows()`
/// operation, without actually calling a solver.
///
/// That is, the result of
/// ```no_compile
/// compiler.check_unsat(always_allows_asserts(policies))
/// ```
/// should be the same as `compiler.check_always_allows(policies)`.
///
/// Likewise, the result of
/// ```no_compile
/// compiler.check_sat(always_allows_asserts(policies))
/// ```
/// should be the same as `compiler.check_always_allows_opt(policies)`.
///
/// NOTE: This API is an experimental feature, and the API may change
/// or break in the future.
pub fn always_allows_asserts<'a>(policies: &'a CompiledPolicies) -> WellFormedAsserts<'a> {
    WellFormedAsserts {
        asserts: verify_always_allows_opt(&policies.policies),
        policies: nonempty![CompiledPolicys::Policies(&policies.policies)],
    }
}

/// Generate the [`WellFormedAsserts`] for the `check_always_denies()`
/// operation, without actually calling a solver.
///
/// That is, the result of
/// ```no_compile
/// compiler.check_unsat(always_denies_asserts(policies))
/// ```
/// should be the same as `compiler.check_always_denies(policies)`.
///
/// Likewise, the result of
/// ```no_compile
/// compiler.check_sat(always_denies_asserts(policies))
/// ```
/// should be the same as `compiler.check_always_denies_opt(policies)`.
///
/// NOTE: This API is an experimental feature, and the API may change
/// or break in the future.
pub fn always_denies_asserts<'a>(policies: &'a CompiledPolicies) -> WellFormedAsserts<'a> {
    WellFormedAsserts {
        asserts: verify_always_denies_opt(&policies.policies),
        policies: nonempty![CompiledPolicys::Policies(&policies.policies)],
    }
}

/// Generate the [`WellFormedAsserts`] for the `check_implies()`
/// operation, without actually calling a solver.
///
/// That is, the result of
/// ```no_compile
/// compiler.check_unsat(implies_asserts(policies1, policies2))
/// ```
/// should be the same as `compiler.check_implies(policies1, policies2)`.
///
/// Likewise, the result of
/// ```no_compile
/// compiler.check_sat(implies_asserts(policies1, policies2))
/// ```
/// should be the same as `compiler.check_implies_opt(policies1, policies2)`.
///
/// NOTE: This API is an experimental feature, and the API may change
/// or break in the future.
pub fn implies_asserts<'a>(
    policies1: &'a CompiledPolicies,
    policies2: &'a CompiledPolicies,
) -> WellFormedAsserts<'a> {
    WellFormedAsserts {
        asserts: verify_implies_opt(&policies1.policies, &policies2.policies),
        #[expect(
            clippy::expect_used,
            reason = "NonEmpty::collect() will not fail on a nonempty iterator"
        )]
        policies: nonempty![
            CompiledPolicys::Policies(&policies1.policies),
            CompiledPolicys::Policies(&policies2.policies)
        ],
    }
}

/// Generate the [`WellFormedAsserts`] for the `check_equivalent()`
/// operation, without actually calling a solver.
///
/// That is, the result of
/// ```no_compile
/// compiler.check_unsat(equivalent_asserts(policies1, policies2))
/// ```
/// should be the same as `compiler.check_equivalent(policies1, policies2)`.
///
/// Likewise, the result of
/// ```no_compile
/// compiler.check_sat(equivalent_asserts(policies1, policies2))
/// ```
/// should be the same as `compiler.check_equivalent_opt(policies1, policies2)`.
///
/// NOTE: This API is an experimental feature, and the API may change
/// or break in the future.
pub fn equivalent_asserts<'a>(
    policies1: &'a CompiledPolicies,
    policies2: &'a CompiledPolicies,
) -> WellFormedAsserts<'a> {
    WellFormedAsserts {
        asserts: verify_equivalent_opt(&policies1.policies, &policies2.policies),
        #[expect(
            clippy::expect_used,
            reason = "NonEmpty::collect() will not fail on a nonempty iterator"
        )]
        policies: nonempty![
            CompiledPolicys::Policies(&policies1.policies),
            CompiledPolicys::Policies(&policies2.policies)
        ],
    }
}

/// Generate the [`WellFormedAsserts`] for the `check_disjoint()`
/// operation, without actually calling a solver.
///
/// That is, the result of
/// ```no_compile
/// compiler.check_unsat(disjoint_asserts(policies1, policies2))
/// ```
/// should be the same as `compiler.check_disjoint(policies1, policies2)`.
///
/// Likewise, the result of
/// ```no_compile
/// compiler.check_sat(disjoint_asserts(policies1, policies2))
/// ```
/// should be the same as `compiler.check_disjoint_opt(policies1, policies2)`.
///
/// NOTE: This API is an experimental feature, and the API may change
/// or break in the future.
pub fn disjoint_asserts<'a>(
    policies1: &'a CompiledPolicies,
    policies2: &'a CompiledPolicies,
) -> WellFormedAsserts<'a> {
    WellFormedAsserts {
        asserts: verify_disjoint_opt(&policies1.policies, &policies2.policies),
        #[expect(
            clippy::expect_used,
            reason = "NonEmpty::collect() will not fail on a nonempty iterator"
        )]
        policies: nonempty![
            CompiledPolicys::Policies(&policies1.policies),
            CompiledPolicys::Policies(&policies2.policies)
        ],
    }
}
