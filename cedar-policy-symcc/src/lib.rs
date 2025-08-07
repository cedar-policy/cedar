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

mod err;
mod symcc;

use cedar_policy::{Policy, PolicySet, RequestEnv, Schema};
use std::fmt;

use solver::Solver;
use symcc::SymCompiler;
use symcc::{
    verify_always_allows, verify_always_denies, verify_disjoint, verify_equivalent, verify_implies,
    verify_never_errors, well_typed_policies, well_typed_policy,
};

pub use symcc::factory as term;
pub use symcc::{
    bitvec::BitVec,
    ext::Ext,
    extension_types,
    op::{ExtOp, Op, Uuf},
    term::Term,
    term::TermPrim,
    term::TermVar,
    term_type::TermType,
    type_abbrevs::*,
    type_abbrevs::{ExtType, OrdPattern},
    verifier::Asserts,
};
/// Public exports.
pub use symcc::{solver, Env, Environment, Interpretation, SmtLibScript, SymEnv};

/// Export various error types.
pub use err::*;

/// Cedar symbolic compiler, which takes your policies and schemas
/// and converts them to SMT queries to perform various verification
/// tasks such as checking if a policy set always allows/denies,
/// if two policy sets are equivalent, etc.
#[derive(Clone, Debug)]
pub struct CedarSymCompiler<S: Solver> {
    /// SymCompiler
    symcc: SymCompiler<S>,
}

impl SymEnv {
    /// Constructs a new [`SymEnv`] from the given [`Schema`] and [`RequestEnv`].
    pub fn new(schema: &Schema, req_env: &RequestEnv) -> Result<Self> {
        let env = Environment::from_request_env(req_env, schema.as_ref())
            .ok_or_else(|| Error::ActionNotInSchema(req_env.action().to_string()))?;
        Ok(Self::of_env(&env)?)
    }
}

/// Validated and well-typed policy.
#[derive(Debug)]
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
#[derive(Debug)]
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

    /// Returns true iff [`WellTypedPolicy`] does not error on any well-formed
    /// input in the given symbolic environment.
    pub async fn check_never_errors(
        &mut self,
        policy: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc.check_never_errors(&policy.policy, symenv).await
    }

    /// Similar to [`Self::check_never_errors`], but returns a counterexample
    /// if the policy could error on well-formed input.
    pub async fn check_never_errors_with_counterexample(
        &mut self,
        policy: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_never_errors_with_counterexample(&policy.policy, symenv)
            .await
    }

    /// Returns true iff the authorization decision of `pset1` implies that of
    /// `pset2` for every well-formed input in the `symenv`. That is, every
    /// input allowed by `pset1` is allowed by `pset2`; `pset2` is either more
    /// permissive than, or equivalent to, `pset1`.
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

    /// Similar to [`Self::check_implies`], but returns a counterexample
    /// that is allowed by `pset1` but not by `pset2` if it exists.
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

    /// Returns true iff `pset` allows all well-formed inputs in the `symenv`.
    pub async fn check_always_allows(
        &mut self,
        pset: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc.check_always_allows(&pset.policies, symenv).await
    }

    /// Similar to [`Self::check_always_allows`], but returns a counterexample
    /// that is denied by `pset` if it exists.
    pub async fn check_always_allows_with_counterexample(
        &mut self,
        pset: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_always_allows_with_counterexample(&pset.policies, symenv)
            .await
    }

    /// Returns true iff `pset` denies all well-formed inputs in the `symenv`.
    pub async fn check_always_denies(
        &mut self,
        pset: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<bool> {
        self.symcc.check_always_denies(&pset.policies, symenv).await
    }

    /// Similar to [`Self::check_always_denies`], but returns a counterexample
    /// that is allowed by `pset` if it exists.
    pub async fn check_always_denies_with_counterexample(
        &mut self,
        pset: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        self.symcc
            .check_always_denies_with_counterexample(&pset.policies, symenv)
            .await
    }

    /// Returns true iff `pset1` and `pset2` produce the same authorization
    /// decision on all well-formed inputs in the `symenv`.
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

    /// Similar to [`Self::check_equivalent`], but returns a counterexample
    /// on which the authorization decisions of `pset1` and `pset2` differ.
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

    /// Returns true iff there is no well-formed input in the `symenv` that is
    /// allowed by both `pset1` and `pset2`. If this returns `false`, then there
    /// is at least one well-formed input that is allowed by both `pset1` and
    /// `pset2`.
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

    /// Similar to [`Self::check_disjoint`], but returns a counterexample
    /// that is allowed by both `pset1` and `pset2`.
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
}

/// Well-formed assertions generated by the symbolic compiler.
#[derive(Debug, Clone)]
pub struct WellFormedAsserts<'a> {
    symenv: &'a SymEnv,
    asserts: Asserts,
    /// All [`cedar_policy_core::ast::Expr`]s that have been compiled when generating the asserts.
    footprint: Vec<cedar_policy_core::ast::Expr>,
}

impl<'a> WellFormedAsserts<'a> {
    /// Returns the symbolic environment these asserts were generated in.
    pub fn symenv(&self) -> &SymEnv {
        self.symenv
    }

    /// Returns the underlying raw [`Asserts`].
    pub fn asserts(&self) -> &Asserts {
        &self.asserts
    }

    /// Creates a new [`WellFormedAsserts`] from the given [`Asserts`]
    /// without checking if it is well-formed.
    ///
    /// NOTE: This is an experimental feature that allows manipulating/customizing
    /// the underlying raw [`Asserts`] directly.
    ///
    /// The inputs should satisfy the following conditions for the query to be sound:
    /// - `asserts` should be well-formed with respect to the `symenv`, in the
    ///   sense of the definition in the Lean model:
    ///   https://github.com/cedar-policy/cedar-spec/blob/7650a698e2a796b8c5b4118ac93d9e2874bc0807/cedar-lean/Cedar/Thm/SymCC/Data/Basic.lean#L463
    ///   For example, if the variable `principal` is used in `asserts`,
    ///   it should have the same type as `symenv.request.principal`.
    /// - `policies` should include all policies ever compiled in the `asserts`,
    ///   otherwise if a counterexample is generated from the query, it may not
    ///   be well-formed (in particular, having an acyclic and transitive
    ///   entity hierarchy).
    pub fn from_asserts_unchecked<'b>(
        symenv: &'a SymEnv,
        asserts: Asserts,
        policies: impl Iterator<Item = &'b cedar_policy_core::ast::Policy>,
    ) -> Self {
        WellFormedAsserts {
            symenv,
            asserts,
            footprint: policies.map(|p| p.condition()).collect(),
        }
    }
}

impl<S: Solver> CedarSymCompiler<S> {
    /// Calls the underlying solver to check if the given `asserts` are unsatisfiable.
    /// Returns `true` iff the asserts are unsatisfiable.
    ///
    /// NOTE: This is an experimental feature that may break or change in the future.
    pub async fn check_unsat(&mut self, asserts: &WellFormedAsserts<'_>) -> Result<bool> {
        self.symcc
            .check_unsat(|_| Ok(asserts.asserts().clone()), asserts.symenv())
            .await
    }

    /// Calls the underlying solver to check if the given `asserts` are unsatisfiable.
    /// Returns some counterexample to the given symbolic assertions iff they are satisfiable.
    ///
    /// NOTE: This is an experimental feature that may break or change in the future.
    pub async fn check_sat(&mut self, asserts: &WellFormedAsserts<'_>) -> Result<Option<Env>> {
        self.symcc
            .check_sat(
                |_| Ok(asserts.asserts().clone()),
                asserts.symenv(),
                asserts.footprint.iter(),
            )
            .await
    }
}

/// Compiles the verification task of [`CedarSymCompiler::check_never_errors`] to
/// the unsatisfiability of the returned [`WellFormedAsserts`]  without actually
/// calling an SMT solver.
///
/// For any `compiler: CedarSymCompiler` and `symenv: &SymvEnv`, the result of
/// ```no_compile
/// compiler.check_unsat(compiler.compile_never_errors(policy, symenv))
/// ```
/// should be the same as `compiler.check_never_errors(policy, symenv)`.
///
/// Similarly, the result of
/// ```no_compile
/// compiler.check_sat(compiler.compile_never_errors(policy, symenv))
/// ```
/// should be the same as `compiler.check_never_errors_with_counterexample(policy, symenv)`.
///
/// NOTE: This is an experimental feature that may break or change in the future.
pub fn compile_never_errors<'a>(
    policy: &WellTypedPolicy,
    symenv: &'a SymEnv,
) -> Result<WellFormedAsserts<'a>> {
    Ok(WellFormedAsserts::from_asserts_unchecked(
        symenv,
        verify_never_errors(policy.policy(), symenv)?,
        std::iter::once(policy.policy()),
    ))
}

/// Similar to [`compile_never_errors`], but compiles the verification task of
/// [`CedarSymCompiler::check_implies`] to the unsatisfiability of the returned
/// [`WellFormedAsserts`] without actually calling an SMT solver.
///
/// NOTE: This is an experimental feature that may break or change in the future.
pub fn compile_implies<'a>(
    pset1: &WellTypedPolicies,
    pset2: &WellTypedPolicies,
    symenv: &'a SymEnv,
) -> Result<WellFormedAsserts<'a>> {
    Ok(WellFormedAsserts::from_asserts_unchecked(
        symenv,
        verify_implies(pset1.policy_set(), pset2.policy_set(), symenv)?,
        pset1
            .policy_set()
            .policies()
            .chain(pset2.policy_set().policies()),
    ))
}

/// Similar to [`compile_never_errors`], but compiles the verification task of
/// [`CedarSymCompiler::check_always_allows`] to the unsatisfiability of the returned
/// [`WellFormedAsserts`] without actually calling an SMT solver.
///
/// NOTE: This is an experimental feature that may break or change in the future.
pub fn compile_always_allows<'a>(
    pset: &WellTypedPolicies,
    symenv: &'a SymEnv,
) -> Result<WellFormedAsserts<'a>> {
    Ok(WellFormedAsserts::from_asserts_unchecked(
        symenv,
        verify_always_allows(pset.policy_set(), symenv)?,
        pset.policy_set().policies(),
    ))
}

/// Similar to [`compile_never_errors`], but compiles the verification task of
/// [`CedarSymCompiler::check_always_denies`] to the unsatisfiability of the returned
/// [`WellFormedAsserts`] without actually calling an SMT solver.
///
/// NOTE: This is an experimental feature that may break or change in the future.
pub fn compile_always_denies<'a>(
    pset: &WellTypedPolicies,
    symenv: &'a SymEnv,
) -> Result<WellFormedAsserts<'a>> {
    Ok(WellFormedAsserts::from_asserts_unchecked(
        symenv,
        verify_always_denies(pset.policy_set(), symenv)?,
        pset.policy_set().policies(),
    ))
}

/// Similar to [`compile_never_errors`], but compiles the verification task of
/// [`CedarSymCompiler::check_equivalent`] to the unsatisfiability of the returned
/// [`WellFormedAsserts`] without actually calling an SMT solver.
///
/// NOTE: This is an experimental feature that may break or change in the future.
pub fn compile_equivalent<'a>(
    pset1: &WellTypedPolicies,
    pset2: &WellTypedPolicies,
    symenv: &'a SymEnv,
) -> Result<WellFormedAsserts<'a>> {
    Ok(WellFormedAsserts::from_asserts_unchecked(
        symenv,
        verify_equivalent(pset1.policy_set(), pset2.policy_set(), symenv)?,
        pset1
            .policy_set()
            .policies()
            .chain(pset2.policy_set().policies()),
    ))
}

/// Similar to [`compile_never_errors`], but compiles the verification task of
/// [`CedarSymCompiler::check_disjoint`] to the unsatisfiability of the returned
/// [`WellFormedAsserts`] without actually calling an SMT solver.
///
/// NOTE: This is an experimental feature that may break or change in the future.
pub fn compile_disjoint<'a>(
    pset1: &WellTypedPolicies,
    pset2: &WellTypedPolicies,
    symenv: &'a SymEnv,
) -> Result<WellFormedAsserts<'a>> {
    Ok(WellFormedAsserts::from_asserts_unchecked(
        symenv,
        verify_disjoint(pset1.policy_set(), pset2.policy_set(), symenv)?,
        pset1
            .policy_set()
            .policies()
            .chain(pset2.policy_set().policies()),
    ))
}
