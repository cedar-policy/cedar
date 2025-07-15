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
pub use symcc::{solver, Environment, Interpretation, SmtLibScript, SymCompiler, SymEnv};
use symcc::{verify_sat, well_typed_policies, well_typed_policy};

use cedar_policy::{Entities, Policy, PolicySet, Request, RequestEnv, Schema};

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

    /// Returns [`Some`] iff there is any well-formed pair of
    /// concrete [`Request`] and [`Entities`] in the symbolic
    /// environment that is allowed by `pset`.
    pub async fn check_sat(
        &mut self,
        pset: &PolicySet,
        symenv: &SymEnv,
    ) -> Result<Option<(Request, Entities)>> {
        Ok(self
            .symcc
            .check_sat(
                |symenv| verify_sat(pset.as_ref(), symenv),
                symenv,
                pset.as_ref(),
            )
            .await?)
    }
}
