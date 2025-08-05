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

pub use err::{Error, Result};
mod symcc;
use solver::Solver;
use symcc::SymCompiler;
pub use symcc::{solver, Env, Environment, Interpretation, SmtLibScript, SymEnv};
use symcc::{well_typed_policies, well_typed_policy};

use cedar_policy::{Policy, PolicySet, RequestEnv, Schema};

/// Cedar Symbolic Compiler paramatized by a solver `S`.
#[derive(Clone, Debug)]
pub struct CedarSymCompiler<S: Solver> {
    /// SymCompiler
    symcc: SymCompiler<S>,
}

impl SymEnv {
    /// Construct a new `SymEnv` from the given `schema` and `req_env`
    pub fn new(schema: &Schema, req_env: &RequestEnv) -> Result<Self> {
        let env = Environment::from_request_env(req_env, schema.as_ref()).ok_or_else(|| {
            Error::Symcc(symcc::Error::ActionNotInSchema {
                action: req_env.action().to_string(),
            })
        })?;
        Self::of_env(&env).map_err(|e| Error::Symcc(symcc::Error::SymCC(e)))
    }
}
use std::fmt;

#[derive(Debug)]
pub struct WellTypedPolicy {
    policy: cedar_policy_core::ast::Policy,
}

impl WellTypedPolicy {
    /// Returns a reference to the underlying policy
    pub fn policy(&self) -> &cedar_policy_core::ast::Policy {
        &self.policy
    }

    /// Creates a well-typed policy with respect to the given request environment and schema.
    /// This ensures that the policy satisfies the `WellTyped` constraints required by the
    /// symbolic compiler, by applying Cedar's typechecker transformations.
    pub fn from_policy(
        policy: &Policy,
        env: &RequestEnv,
        schema: &Schema,
    ) -> Result<WellTypedPolicy> {
        well_typed_policy(policy.as_ref(), env, schema)
            .map(|p| WellTypedPolicy { policy: p })
            .map_err(Error::Symcc)
    }

    /// Convers a [`Policy`] to a [`WellTypedPolicy`] unchecked.
    /// Note that SymCC may fail on the policy produced by this function
    /// even if it is validated.
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

/// The type of well-typed policies which ensures that the Cedar Symbolic Compiler is
/// not applied to any ill-formed policies. I.e., on only the output of successful validation
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
        well_typed_policies(ps.as_ref(), env, schema)
            .map(|ps| WellTypedPolicies { policies: ps })
            .map_err(Error::Symcc)
    }

    /// Converts a [`PolicySet`] to a [`WellTypedPolicies`] unchecked.
    /// Note that SymCC may fail on the policy set produced by this function
    /// even if it is validated.
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
    /// Construct a new `CedarSymCompiler` with the given `solver`
    pub fn new(solver: S) -> Result<Self> {
        Ok(Self {
            symcc: SymCompiler::new(solver),
        })
    }

    /// Returns a reference to the `Solver` instance used to construct this `CedarSymCompiler`
    pub fn solver(&self) -> &S {
        self.symcc.solver()
    }

    /// Returns a mutable reference to the `Solver` instance used to construct this `CedarSymCompiler`
    pub fn solver_mut(&mut self) -> &mut S {
        self.symcc.solver_mut()
    }

    /// Returns true iff `policy` does not error on any well-formed input in the
    /// `symenv`.
    ///
    /// Like `SymCompiler::check_never_errors()`, but takes `cedar-policy`
    /// types instead of internal types.
    pub async fn check_never_errors(
        &mut self,
        policy: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<bool> {
        Ok(self
            .symcc
            .check_never_errors(&policy.policy, symenv)
            .await?)
    }

    /// Similar to [`Self::check_never_errors`], but returns a counterexample
    /// where the policy does error.
    pub async fn check_never_errors_with_counterexample(
        &mut self,
        policy: &WellTypedPolicy,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        Ok(self
            .symcc
            .check_never_errors_with_counterexample(&policy.policy, symenv)
            .await?)
    }

    /// Returns true iff the authorization decision of `pset1` implies that of
    /// `pset2` for every well-formed input in the `symenv`. That is, every
    /// input allowed by `pset1` is allowed by `pset2`; `pset2` is either more
    /// permissive than, or equivalent to, `pset1`.
    ///
    /// Like `SymCompiler::check_implies()`, but takes `cedar-policy` types
    /// instead of internal types.
    pub async fn check_implies(
        &mut self,
        pset1: &WellTypedPolicies,
        pset2: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<bool> {
        Ok(self
            .symcc
            .check_implies(&pset1.policies, &pset2.policies, symenv)
            .await?)
    }

    /// Similar to [`Self::check_implies`], but returns a counterexample
    /// that is allowed by `pset1` but not by `pset2`.
    pub async fn check_implies_with_counterexample(
        &mut self,
        pset1: &WellTypedPolicies,
        pset2: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        Ok(self
            .symcc
            .check_implies_with_counterexample(&pset1.policies, &pset2.policies, symenv)
            .await?)
    }

    /// Returns true iff `pset` allows all well-formed inputs in the `symenv`.
    ///
    /// Like `SymCompiler::check_always_allows()`, but takes `cedar-policy`
    /// types instead of internal types.
    pub async fn check_always_allows(
        &mut self,
        pset: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<bool> {
        Ok(self
            .symcc
            .check_always_allows(&pset.policies, symenv)
            .await?)
    }

    /// Similar to [`Self::check_always_allows`], but returns a counterexample
    /// that is denied by `pset`.
    pub async fn check_always_allows_with_counterexample(
        &mut self,
        pset: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        Ok(self
            .symcc
            .check_always_allows_with_counterexample(&pset.policies, symenv)
            .await?)
    }

    /// Returns true iff `pset` denies all well-formed inputs in the `symenv`.
    ///
    /// Like `SymCompiler::check_always_denies()`, but takes `cedar-policy`
    /// types instead of internal types.
    pub async fn check_always_denies(
        &mut self,
        pset: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<bool> {
        Ok(self
            .symcc
            .check_always_denies(&pset.policies, symenv)
            .await?)
    }

    /// Similar to [`Self::check_always_denies`], but returns a counterexample
    /// that is allowed by `pset`.
    pub async fn check_always_denies_with_counterexample(
        &mut self,
        pset: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        Ok(self
            .symcc
            .check_always_denies_with_counterexample(&pset.policies, symenv)
            .await?)
    }

    /// Returns true iff `pset1` and `pset2` produce the same authorization
    /// decision on all well-formed inputs in the `symenv`.
    ///
    /// Like `SymCompiler::check_equivalent()`, but takes `cedar-policy` types
    /// instead of internal types.
    pub async fn check_equivalent(
        &mut self,
        pset1: &WellTypedPolicies,
        pset2: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<bool> {
        Ok(self
            .symcc
            .check_equivalent(&pset1.policies, &pset2.policies, symenv)
            .await?)
    }

    /// Similar to [`Self::check_equivalent`], but returns a counterexample
    /// on which the authorization decisions of `pset1` and `pset2` differ.
    pub async fn check_equivalent_with_counterexample(
        &mut self,
        pset1: &WellTypedPolicies,
        pset2: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        Ok(self
            .symcc
            .check_equivalent_with_counterexample(&pset1.policies, &pset2.policies, symenv)
            .await?)
    }

    /// Returns true iff there is no well-formed input in the `symenv` that is
    /// allowed by both `pset1` and `pset2`. If this returns `false`, then there
    /// is at least one well-formed input that is allowed by both `pset1` and
    /// `pset2`.
    ///
    /// Like `SymCompiler::check_disjoint()`, but takes `cedar-policy` types
    /// instead of internal types.
    pub async fn check_disjoint(
        &mut self,
        pset1: &WellTypedPolicies,
        pset2: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<bool> {
        Ok(self
            .symcc
            .check_disjoint(&pset1.policies, &pset2.policies, symenv)
            .await?)
    }

    /// Similar to [`Self::check_disjoint`], but returns a counterexample
    /// that is allowed by both `pset1` and `pset2`.
    pub async fn check_disjoint_with_counterexample(
        &mut self,
        pset1: &WellTypedPolicies,
        pset2: &WellTypedPolicies,
        symenv: &SymEnv,
    ) -> Result<Option<Env>> {
        Ok(self
            .symcc
            .check_disjoint_with_counterexample(&pset1.policies, &pset2.policies, symenv)
            .await?)
    }
}

/// Experimental features to compile various verification tasks to [`Term`] and [`Asserts`] directly.
#[cfg(feature = "term")]
mod term_feature {
    use super::*;

    pub use super::symcc::{
        bitvec::BitVec,
        ext::Ext,
        extension_types,
        op::{ExtOp, Op, Uuf},
        type_abbrevs::{ExtType, OrdPattern},
        Asserts, Term, TermPrim, TermType, TermVar,
    };
    pub use symcc::factory as term;
    pub use symcc::{
        verify_always_allows, verify_always_denies, verify_disjoint, verify_equivalent,
        verify_implies, verify_never_errors,
    };

    impl<S: Solver> CedarSymCompiler<S> {
        /// Calls the underlying solver to check if the given `asserts` are unsatisfiable.
        /// Returns `true` iff the asserts are unsatisfiable.
        ///
        /// NOTE: This is an experimental feature that may break or change in the future.
        pub async fn check_unsat(&mut self, asserts: Asserts, symenv: &SymEnv) -> Result<bool> {
            Ok(self.symcc.check_unsat(|_| Ok(asserts), symenv).await?)
        }

        /// Calls the underlying solver to check if the given `asserts` are unsatisfiable.
        /// Returns some counterexample to the given symbolic assertions iff they are satisfiable.
        ///
        /// For soundness, all policies ever evaluated in the given `asserts` must be included in `policies`.
        ///
        /// NOTE: This is an experimental feature that may break or change in the future.
        pub async fn check_sat(
            &mut self,
            asserts: Asserts,
            symenv: &SymEnv,
            policies: impl Iterator<Item = &cedar_policy_core::ast::Policy>,
        ) -> Result<Option<Env>> {
            Ok(self
                .symcc
                .check_sat(|_| Ok(asserts), symenv, policies)
                .await?)
        }

        /// Compiles the verification task of [`Self::check_never_errors`] to the unsatisfiability
        /// of the returned [`Asserts`]  without actually calling an SMT solver.
        ///
        /// For any `compiler: CedarSymCompiler` and `symenv: &SymvEnv`, the result of
        /// ```no_compile
        /// compiler.check_unsat(compiler.compile_never_errors(policy, symenv), symenv)
        /// ```
        /// should be the same as `compiler.check_never_errors(policy, symenv)`.
        ///
        /// Similarly, the result of
        /// ```no_compile
        /// compiler.check_sat(
        ///     compiler.compile_never_errors(policy, symenv),
        ///     symenv,
        ///     std::iter::once(policy.policy()))
        /// ```
        /// should be the same as `compiler.check_never_errors_with_counterexample(policy, symenv)`.
        ///
        /// NOTE: This is an experimental feature that may break or change in the future.
        pub fn compile_never_errors(
            &self,
            policy: &WellTypedPolicy,
            symenv: &SymEnv,
        ) -> Result<Asserts> {
            Ok(verify_never_errors(policy.policy(), symenv)?)
        }

        /// Similar to [`Self::compile_never_errors`], but compiles the verification task of
        /// [`Self::check_implies`] to the unsatisfiability of the returned [`Asserts`]
        /// without actually calling an SMT solver.
        ///
        /// NOTE: This is an experimental feature that may break or change in the future.
        pub fn compile_implies(
            &self,
            pset1: &WellTypedPolicies,
            pset2: &WellTypedPolicies,
            symenv: &SymEnv,
        ) -> Result<Asserts> {
            Ok(verify_implies(
                pset1.policy_set(),
                pset2.policy_set(),
                symenv,
            )?)
        }

        /// Similar to [`Self::compile_never_errors`], but compiles the verification task of
        /// [`Self::check_always_allows`] to the unsatisfiability of the returned [`Asserts`]
        /// without actually calling an SMT solver.
        ///
        /// NOTE: This is an experimental feature that may break or change in the future.
        pub fn compile_always_allows(
            &self,
            pset: &WellTypedPolicies,
            symenv: &SymEnv,
        ) -> Result<Asserts> {
            Ok(verify_always_allows(pset.policy_set(), symenv)?)
        }

        /// Similar to [`Self::compile_never_errors`], but compiles the verification task of
        /// [`Self::check_always_denies`] to the unsatisfiability of the returned [`Asserts`]
        /// without actually calling an SMT solver.
        ///
        /// NOTE: This is an experimental feature that may break or change in the future.
        pub fn compile_always_denies(
            &self,
            pset: &WellTypedPolicies,
            symenv: &SymEnv,
        ) -> Result<Asserts> {
            Ok(verify_always_denies(pset.policy_set(), symenv)?)
        }

        /// Similar to [`Self::compile_never_errors`], but compiles the verification task of
        /// [`Self::check_equivalent`] to the unsatisfiability of the returned [`Asserts`]
        /// without actually calling an SMT solver.
        ///
        /// NOTE: This is an experimental feature that may break or change in the future.
        pub fn compile_equivalent(
            &self,
            pset1: &WellTypedPolicies,
            pset2: &WellTypedPolicies,
            symenv: &SymEnv,
        ) -> Result<Asserts> {
            Ok(verify_equivalent(
                pset1.policy_set(),
                pset2.policy_set(),
                symenv,
            )?)
        }

        /// Similar to [`Self::compile_never_errors`], but compiles the verification task of
        /// [`Self::check_disjoint`] to the unsatisfiability of the returned [`Asserts`]
        /// without actually calling an SMT solver.
        ///
        /// NOTE: This is an experimental feature that may break or change in the future.
        pub fn compile_disjoint(
            &self,
            pset1: &WellTypedPolicies,
            pset2: &WellTypedPolicies,
            symenv: &SymEnv,
        ) -> Result<Asserts> {
            Ok(verify_disjoint(
                pset1.policy_set(),
                pset2.policy_set(),
                symenv,
            )?)
        }
    }
}

#[cfg(feature = "term")]
pub use term_feature::*;
