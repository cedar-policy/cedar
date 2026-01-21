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

#![expect(
    dead_code,
    reason = "not actually dead, but cargo issues warnings per test file"
)]
#![expect(clippy::panic, clippy::unwrap_used, reason = "unit test code")]
#![expect(
    deprecated,
    reason = "this file intentionally tests deprecated functions (along with undeprecated ones)"
)]

//! Utilities shared by various tests throughout the package

use std::{fmt::Debug, str::FromStr};

use cedar_policy::{
    Authorizer, Decision, Entities, Policy, PolicyId, PolicySet, RequestEnv, Schema,
    ValidationMode, Validator,
};
use cedar_policy_core::{ast::RequestSchema, extensions::Extensions};
use cedar_policy_symcc::{
    always_allows_asserts, always_denies_asserts, always_matches_asserts, disjoint_asserts,
    equivalent_asserts, implies_asserts, matches_disjoint_asserts, matches_equivalent_asserts,
    matches_implies_asserts, never_errors_asserts, never_matches_asserts, solver::Solver,
    CedarSymCompiler, CompiledPolicy, CompiledPolicySet, Env, Interpretation, SymEnv,
    WellTypedPolicies, WellTypedPolicy,
};

#[track_caller]
pub fn pretty_panic<T>(e: impl miette::Diagnostic + Send + Sync + 'static) -> T {
    panic!("{:?}", miette::Report::new(e))
}

/// Parse a policy from text, panicking if it fails to parse or validate
#[track_caller]
pub fn policy_from_text(id: &str, text: &str, validator: &Validator) -> Policy {
    let p = Policy::parse(Some(PolicyId::new(id)), text).unwrap_or_else(pretty_panic);
    let res = validator.validate(
        &PolicySet::from_policies([p.clone()]).unwrap_or_else(pretty_panic),
        ValidationMode::Strict,
    );
    if res.validation_passed() {
        p
    } else {
        pretty_panic(res)
    }
}

/// Parse a policy set from text, panicking if it fails to parse or validate
#[track_caller]
pub fn pset_from_text(text: &str, validator: &Validator) -> PolicySet {
    let pset = PolicySet::from_str(text).unwrap_or_else(pretty_panic);
    let res = validator.validate(&pset, ValidationMode::Strict);
    if res.validation_passed() {
        pset
    } else {
        pretty_panic(res)
    }
}

/// Parse a schema from Cedar syntax, panicking if it fails to parse
#[track_caller]
pub fn schema_from_cedarstr(str: &str) -> Schema {
    Schema::from_cedarschema_str(str)
        .unwrap_or_else(pretty_panic)
        .0
}

/// Parse a request env from text, panicking if it fails to parse
#[track_caller]
pub fn req_env_from_strs(principal_ty: &str, action: &str, resource_ty: &str) -> RequestEnv {
    RequestEnv::new(
        principal_ty.parse().unwrap(),
        action.parse().unwrap(),
        resource_ty.parse().unwrap(),
    )
}

#[derive(Debug)]
pub struct Environments<'a> {
    pub schema: &'a Schema,
    pub req_env: RequestEnv,
    pub symenv: SymEnv,
    has_custom_symenv: bool,
}

impl<'a> Environments<'a> {
    /// Create a new `Environments` instance from a schema and principal, action, and resource strings
    ///
    /// Uses the default `SymEnv`, which is the stable/default behavior
    #[track_caller]
    pub fn new(schema: &'a Schema, principal_ty: &str, action: &str, resource_ty: &str) -> Self {
        let req_env = req_env_from_strs(principal_ty, action, resource_ty);
        let symenv = SymEnv::new(schema, &req_env).unwrap();
        Self {
            schema,
            req_env,
            symenv,
            has_custom_symenv: false,
        }
    }

    /// Create a new `Environments` instance from a schema and principal, action, and resource strings,
    /// along with a custom `SymEnv` to use instead of the default. See warnings on `CompiledPolicy::compile_with_custom_symenv()`.
    #[track_caller]
    pub fn new_with_custom_symenv(
        schema: &'a Schema,
        principal_ty: &str,
        action: &str,
        resource_ty: &str,
        symenv: SymEnv,
    ) -> Self {
        let req_env = req_env_from_strs(principal_ty, action, resource_ty);
        Self {
            schema,
            req_env,
            symenv,
            has_custom_symenv: true,
        }
    }

    /// Gets all possible `Environments` from a schema (with default symenvs).
    pub fn get_all_from_schema(schema: &'a Schema) -> Vec<Self> {
        schema
            .request_envs()
            .map(|req_env| {
                let symenv = SymEnv::new(schema, &req_env).unwrap();
                Self {
                    schema,
                    req_env,
                    symenv,
                    has_custom_symenv: false,
                }
            })
            .collect()
    }

    #[track_caller]
    pub fn compile_policy(&self, policy: &Policy) -> CompiledPolicy {
        if self.has_custom_symenv {
            CompiledPolicy::compile_with_custom_symenv(
                policy,
                &self.req_env,
                self.schema,
                self.symenv.clone(),
            )
            .unwrap()
        } else {
            // in the common case, where the symenv wasn't created custom, test the standard `CompiledPolicy::compile()` API
            CompiledPolicy::compile(policy, &self.req_env, self.schema).unwrap()
        }
    }

    #[track_caller]
    pub fn compile_policies(&self, pset: &PolicySet) -> CompiledPolicySet {
        if self.has_custom_symenv {
            CompiledPolicySet::compile_with_custom_symenv(
                pset,
                &self.req_env,
                self.schema,
                self.symenv.clone(),
            )
            .unwrap()
        } else {
            // in the common case, where the symenv wasn't created custom, test the standard `CompiledPolicySet::compile()` API
            CompiledPolicySet::compile(pset, &self.req_env, self.schema).unwrap()
        }
    }
}

/// Checks that the counterexample validates against the schema.
fn assert_cex_valid(schema: &Schema, cex: &Env) {
    schema
        .as_ref()
        .validate_request(cex.request.as_ref(), Extensions::all_available())
        .unwrap_or_else(|e| panic!("{e:?}", e = miette::Report::new(e)));
    Entities::from_entities(cex.entities.clone(), Some(schema))
        .unwrap_or_else(|e| panic!("{e:?}", e = miette::Report::new(e)));
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Pathway {
    /// Use only the unoptimized pathway; still run the optimized one, but just check that it doesn't error
    UnoptOnly,
    /// Use only the optimized pathway; still run the unoptimized one, but just check that it doesn't error
    OptOnly,
    /// Test both pathways and assert that they return identical results
    #[default]
    Both,
}

impl Pathway {
    /// Given the unoptimized and optimized results, apply the `Pathway` operation (see notes on `Pathway`)
    fn resolve<T: PartialEq + Debug>(self, unopt: T, opt: T) -> T {
        match self {
            Self::UnoptOnly => unopt,
            Self::OptOnly => opt,
            Self::Both => {
                assert_eq!(unopt, opt);
                unopt
            }
        }
    }
}

/// Returns `true` if the policy never-errors in the `req_env`.
///
/// Panics if any call fails or if other invariants are violated.
pub async fn assert_never_errors_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
    pathway: Pathway,
) -> bool {
    let typed_policy = WellTypedPolicy::from_policy(policy, &envs.req_env, envs.schema).unwrap();
    let compiled_policy = envs.compile_policy(policy);
    let res = {
        let unopt_res = compiler
            .check_never_errors(&typed_policy, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_never_errors_opt(&compiled_policy)
            .await
            .unwrap();
        pathway.resolve(unopt_res, opt_res)
    };
    let cex = {
        let unopt_cex = compiler
            .check_never_errors_with_counterexample(&typed_policy, &envs.symenv)
            .await
            .unwrap();
        let opt_cex = compiler
            .check_never_errors_with_counterexample_opt(&compiled_policy)
            .await
            .unwrap();
        pathway.resolve(unopt_cex, opt_cex)
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let pset = PolicySet::from_policies(std::iter::once(policy.clone())).unwrap();
        let resp = Authorizer::new().is_authorized(&cex.request, &pset, &cex.entities);
        assert!(
            resp.diagnostics().errors().next().is_some(),
            "check_never_errors_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let custom_compiled = CompiledPolicy::compile_with_custom_symenv(
            policy,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = never_errors_asserts(&custom_compiled);
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let custom_compiled = CompiledPolicy::compile_with_custom_symenv(
            policy,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = never_errors_asserts(&custom_compiled);
        // There should be some literal false in the assertions
        assert!(asserts.asserts().iter().all(|t| t.is_literal()));
        assert!(asserts.asserts().iter().any(|t| t == &false.into()));
    }

    res
}

pub async fn assert_never_errors<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
) {
    assert!(
        assert_never_errors_ok(compiler, policy, envs, Pathway::default()).await,
        "assert_never_errors failed for:\n{policy}"
    );
}

/// Returns `true` if the policy always-matches in the `req_env`.
///
/// Panics if any call fails or if other invariants are violated.
pub async fn assert_always_matches_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
    pathway: Pathway,
) -> bool {
    let typed_policy = WellTypedPolicy::from_policy(policy, &envs.req_env, envs.schema).unwrap();
    let compiled_policy = envs.compile_policy(policy);
    let res = {
        let unopt_res = compiler
            .check_always_matches(&typed_policy, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_always_matches_opt(&compiled_policy)
            .await
            .unwrap();
        pathway.resolve(unopt_res, opt_res)
    };
    let cex = {
        let unopt_cex = compiler
            .check_always_matches_with_counterexample(&typed_policy, &envs.symenv)
            .await
            .unwrap();
        let opt_cex = compiler
            .check_always_matches_with_counterexample_opt(&compiled_policy)
            .await
            .unwrap();
        pathway.resolve(unopt_cex, opt_cex)
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let pset = PolicySet::from_policies(std::iter::once(policy.clone())).unwrap();
        let resp = Authorizer::new().is_authorized(&cex.request, &pset, &cex.entities);
        // For a permit policy, always_matches means it always allows, so counterexample should deny
        // For a forbid policy, always_matches means it always denies, so counterexample should allow
        let expected_decision = if policy.effect() == cedar_policy_core::ast::Effect::Permit {
            Decision::Deny
        } else {
            Decision::Allow
        };
        assert_eq!(
            resp.decision(),
            expected_decision,
            "check_always_matches_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let custom_compiled = CompiledPolicy::compile_with_custom_symenv(
            policy,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = always_matches_asserts(&custom_compiled);
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let custom_compiled = CompiledPolicy::compile_with_custom_symenv(
            policy,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = always_matches_asserts(&custom_compiled);
        // There should be some literal false in the assertions
        assert!(asserts.asserts().iter().all(|t| t.is_literal()));
        assert!(asserts.asserts().iter().any(|t| t == &false.into()));
    }

    res
}

pub async fn assert_always_matches<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
) {
    assert!(
        assert_always_matches_ok(compiler, policy, envs, Pathway::default()).await,
        "assert_always_matches failed for:\n{policy}"
    );
}

pub async fn assert_does_not_always_match<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_always_matches_ok(compiler, policy, envs, Pathway::default()).await,
        "assert_does_not_always_match failed for:\n{policy}"
    );
}

/// Returns `true` if the policy never-matches in the `req_env`.
///
/// Panics if any call fails or if other invariants are violated.
pub async fn assert_never_matches_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
    pathway: Pathway,
) -> bool {
    let typed_policy = WellTypedPolicy::from_policy(policy, &envs.req_env, envs.schema).unwrap();
    let compiled_policy = envs.compile_policy(policy);
    let res = {
        let unopt_res = compiler
            .check_never_matches(&typed_policy, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_never_matches_opt(&compiled_policy)
            .await
            .unwrap();
        pathway.resolve(unopt_res, opt_res)
    };
    let cex = {
        let unopt_cex = compiler
            .check_never_matches_with_counterexample(&typed_policy, &envs.symenv)
            .await
            .unwrap();
        let opt_cex = compiler
            .check_never_matches_with_counterexample_opt(&compiled_policy)
            .await
            .unwrap();
        pathway.resolve(unopt_cex, opt_cex)
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let pset = PolicySet::from_policies(std::iter::once(policy.clone())).unwrap();
        let resp = Authorizer::new().is_authorized(&cex.request, &pset, &cex.entities);
        // For a permit policy, never_matches means it never allows, so counterexample should allow
        // For a forbid policy, never_matches means it never denies, so counterexample should deny
        let expected_decision = if policy.effect() == cedar_policy_core::ast::Effect::Permit {
            Decision::Allow
        } else {
            Decision::Deny
        };
        assert_eq!(
            resp.decision(),
            expected_decision,
            "check_never_matches_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let custom_compiled = CompiledPolicy::compile_with_custom_symenv(
            policy,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = never_matches_asserts(&custom_compiled);
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let custom_compiled = CompiledPolicy::compile_with_custom_symenv(
            policy,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = never_matches_asserts(&custom_compiled);
        // There should be some literal false in the assertions
        assert!(asserts.asserts().iter().all(|t| t.is_literal()));
        assert!(asserts.asserts().iter().any(|t| t == &false.into()));
    }

    res
}

pub async fn assert_never_matches<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
) {
    assert!(
        assert_never_matches_ok(compiler, policy, envs, Pathway::default()).await,
        "assert_never_matches failed for:\n{policy}"
    );
}

pub async fn assert_does_not_never_match<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_never_matches_ok(compiler, policy, envs, Pathway::default()).await,
        "assert_does_not_never_match failed for:\n{policy}"
    );
}

/// Returns `true` if the policies matches-equivalent in the `req_env`.
///
/// Panics if any call fails or if other invariants are violated.
pub async fn assert_matches_equivalent_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy1: &Policy,
    policy2: &Policy,
    envs: &Environments<'_>,
    pathway: Pathway,
) -> bool {
    let typed_policy1 = WellTypedPolicy::from_policy(policy1, &envs.req_env, envs.schema).unwrap();
    let typed_policy2 = WellTypedPolicy::from_policy(policy2, &envs.req_env, envs.schema).unwrap();
    let compiled_policy1 = envs.compile_policy(policy1);
    let compiled_policy2 = envs.compile_policy(policy2);
    let res = {
        let unopt_res = compiler
            .check_matches_equivalent(&typed_policy1, &typed_policy2, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_matches_equivalent_opt(&compiled_policy1, &compiled_policy2)
            .await
            .unwrap();
        pathway.resolve(unopt_res, opt_res)
    };
    let cex = {
        let unopt_cex = compiler
            .check_matches_equivalent_with_counterexample(
                &typed_policy1,
                &typed_policy2,
                &envs.symenv,
            )
            .await
            .unwrap();
        let opt_cex = compiler
            .check_matches_equivalent_with_counterexample_opt(&compiled_policy1, &compiled_policy2)
            .await
            .unwrap();
        pathway.resolve(unopt_cex, opt_cex)
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let pset1 = PolicySet::from_policies(std::iter::once(policy1.clone())).unwrap();
        let pset2 = PolicySet::from_policies(std::iter::once(policy2.clone())).unwrap();
        let resp1 = Authorizer::new().is_authorized(&cex.request, &pset1, &cex.entities);
        let resp2 = Authorizer::new().is_authorized(&cex.request, &pset2, &cex.entities);
        let policy1_matches = resp1.diagnostics().reason().next().is_some();
        let policy2_matches = resp2.diagnostics().reason().next().is_some();
        assert_ne!(
            policy1_matches, policy2_matches,
            "check_matches_equivalent_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let custom_compiled_1 = CompiledPolicy::compile_with_custom_symenv(
            policy1,
            &envs.req_env,
            envs.schema,
            literal_symenv.clone(),
        )
        .unwrap();
        let custom_compiled_2 = CompiledPolicy::compile_with_custom_symenv(
            policy2,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = matches_equivalent_asserts(&custom_compiled_1, &custom_compiled_2);
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let custom_compiled_1 = CompiledPolicy::compile_with_custom_symenv(
            policy1,
            &envs.req_env,
            envs.schema,
            literal_symenv.clone(),
        )
        .unwrap();
        let custom_compiled_2 = CompiledPolicy::compile_with_custom_symenv(
            policy2,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = matches_equivalent_asserts(&custom_compiled_1, &custom_compiled_2);
        // There should be some literal false in the assertions
        assert!(asserts.asserts().iter().all(|t| t.is_literal()));
        assert!(asserts.asserts().iter().any(|t| t == &false.into()));
    }

    res
}

pub async fn assert_matches_equivalent<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy1: &Policy,
    policy2: &Policy,
    envs: &Environments<'_>,
) {
    assert!(
        assert_matches_equivalent_ok(compiler, policy1, policy2, envs, Pathway::default()).await,
        "assert_matches_equivalent failed for:\n{policy1}\n{policy2}"
    );
}

pub async fn assert_not_matches_equivalent<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy1: &Policy,
    policy2: &Policy,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_matches_equivalent_ok(compiler, policy1, policy2, envs, Pathway::default()).await,
        "assert_not_matches_equivalent failed for:\n{policy1}\n{policy2}"
    );
}

/// Returns `true` if the policies matches-implies in the `req_env`.
///
/// Panics if any call fails or if other invariants are violated.
pub async fn assert_matches_implies_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy1: &Policy,
    policy2: &Policy,
    envs: &Environments<'_>,
    pathway: Pathway,
) -> bool {
    let typed_policy1 = WellTypedPolicy::from_policy(policy1, &envs.req_env, envs.schema).unwrap();
    let typed_policy2 = WellTypedPolicy::from_policy(policy2, &envs.req_env, envs.schema).unwrap();
    let compiled_policy1 = envs.compile_policy(policy1);
    let compiled_policy2 = envs.compile_policy(policy2);
    let res = {
        let unopt_res = compiler
            .check_matches_implies(&typed_policy1, &typed_policy2, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_matches_implies_opt(&compiled_policy1, &compiled_policy2)
            .await
            .unwrap();
        pathway.resolve(unopt_res, opt_res)
    };
    let cex = {
        let unopt_cex = compiler
            .check_matches_implies_with_counterexample(&typed_policy1, &typed_policy2, &envs.symenv)
            .await
            .unwrap();
        let opt_cex = compiler
            .check_matches_implies_with_counterexample_opt(&compiled_policy1, &compiled_policy2)
            .await
            .unwrap();
        pathway.resolve(unopt_cex, opt_cex)
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let pset1 = PolicySet::from_policies(std::iter::once(policy1.clone())).unwrap();
        let pset2 = PolicySet::from_policies(std::iter::once(policy2.clone())).unwrap();
        let resp1 = Authorizer::new().is_authorized(&cex.request, &pset1, &cex.entities);
        let resp2 = Authorizer::new().is_authorized(&cex.request, &pset2, &cex.entities);
        let policy1_matches = resp1.diagnostics().reason().next().is_some();
        let policy2_matches = resp2.diagnostics().reason().next().is_some();
        assert!(
            policy1_matches && !policy2_matches,
            "check_matches_implies_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let custom_compiled_1 = CompiledPolicy::compile_with_custom_symenv(
            policy1,
            &envs.req_env,
            envs.schema,
            literal_symenv.clone(),
        )
        .unwrap();
        let custom_compiled_2 = CompiledPolicy::compile_with_custom_symenv(
            policy2,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = matches_implies_asserts(&custom_compiled_1, &custom_compiled_2);
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let custom_compiled_1 = CompiledPolicy::compile_with_custom_symenv(
            policy1,
            &envs.req_env,
            envs.schema,
            literal_symenv.clone(),
        )
        .unwrap();
        let custom_compiled_2 = CompiledPolicy::compile_with_custom_symenv(
            policy2,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = matches_implies_asserts(&custom_compiled_1, &custom_compiled_2);
        // There should be some literal false in the assertions
        assert!(asserts.asserts().iter().all(|t| t.is_literal()));
        assert!(asserts.asserts().iter().any(|t| t == &false.into()));
    }

    res
}

pub async fn assert_matches_implies<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy1: &Policy,
    policy2: &Policy,
    envs: &Environments<'_>,
) {
    assert!(
        assert_matches_implies_ok(compiler, policy1, policy2, envs, Pathway::default()).await,
        "assert_matches_implies failed for:\n{policy1}\n{policy2}"
    );
}

pub async fn assert_does_not_matches_imply<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy1: &Policy,
    policy2: &Policy,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_matches_implies_ok(compiler, policy1, policy2, envs, Pathway::default()).await,
        "assert_does_not_matches_imply failed for:\n{policy1}\n{policy2}"
    );
}

/// Returns `true` if the policies matches-disjoint in the `req_env`.
///
/// Panics if any call fails or if other invariants are violated.
pub async fn assert_matches_disjoint_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy1: &Policy,
    policy2: &Policy,
    envs: &Environments<'_>,
    pathway: Pathway,
) -> bool {
    let typed_policy1 = WellTypedPolicy::from_policy(policy1, &envs.req_env, envs.schema).unwrap();
    let typed_policy2 = WellTypedPolicy::from_policy(policy2, &envs.req_env, envs.schema).unwrap();
    let compiled_policy1 = envs.compile_policy(policy1);
    let compiled_policy2 = envs.compile_policy(policy2);
    let res = {
        let unopt_res = compiler
            .check_matches_disjoint(&typed_policy1, &typed_policy2, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_matches_disjoint_opt(&compiled_policy1, &compiled_policy2)
            .await
            .unwrap();
        pathway.resolve(unopt_res, opt_res)
    };
    let cex = {
        let unopt_cex = compiler
            .check_matches_disjoint_with_counterexample(
                &typed_policy1,
                &typed_policy2,
                &envs.symenv,
            )
            .await
            .unwrap();
        let opt_cex = compiler
            .check_matches_disjoint_with_counterexample_opt(&compiled_policy1, &compiled_policy2)
            .await
            .unwrap();
        pathway.resolve(unopt_cex, opt_cex)
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let pset1 = PolicySet::from_policies(std::iter::once(policy1.clone())).unwrap();
        let pset2 = PolicySet::from_policies(std::iter::once(policy2.clone())).unwrap();
        let resp1 = Authorizer::new().is_authorized(&cex.request, &pset1, &cex.entities);
        let resp2 = Authorizer::new().is_authorized(&cex.request, &pset2, &cex.entities);
        let policy1_matches = resp1.diagnostics().reason().next().is_some();
        let policy2_matches = resp2.diagnostics().reason().next().is_some();
        assert!(
            policy1_matches && policy2_matches,
            "check_matches_disjoint_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let custom_compiled_1 = CompiledPolicy::compile_with_custom_symenv(
            policy1,
            &envs.req_env,
            envs.schema,
            literal_symenv.clone(),
        )
        .unwrap();
        let custom_compiled_2 = CompiledPolicy::compile_with_custom_symenv(
            policy2,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = matches_disjoint_asserts(&custom_compiled_1, &custom_compiled_2);
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let custom_compiled_1 = CompiledPolicy::compile_with_custom_symenv(
            policy1,
            &envs.req_env,
            envs.schema,
            literal_symenv.clone(),
        )
        .unwrap();
        let custom_compiled_2 = CompiledPolicy::compile_with_custom_symenv(
            policy2,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = matches_disjoint_asserts(&custom_compiled_1, &custom_compiled_2);
        // There should be some literal false in the assertions
        assert!(asserts.asserts().iter().all(|t| t.is_literal()));
        assert!(asserts.asserts().iter().any(|t| t == &false.into()));
    }

    res
}

pub async fn assert_matches_disjoint<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy1: &Policy,
    policy2: &Policy,
    envs: &Environments<'_>,
) {
    assert!(
        assert_matches_disjoint_ok(compiler, policy1, policy2, envs, Pathway::default()).await,
        "assert_matches_disjoint failed for:\n{policy1}\n{policy2}"
    );
}

pub async fn assert_not_matches_disjoint<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy1: &Policy,
    policy2: &Policy,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_matches_disjoint_ok(compiler, policy1, policy2, envs, Pathway::default()).await,
        "assert_not_matches_disjoint failed for:\n{policy1}\n{policy2}"
    );
}

/// Returns `true` if the policyset always-allows in the `req_env`.
///
/// Panics if any call fails or if other invariants are violated.
pub async fn assert_always_allows_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
    pathway: Pathway,
) -> bool {
    let typed_pset = WellTypedPolicies::from_policies(pset, &envs.req_env, envs.schema).unwrap();
    let compiled_pset = envs.compile_policies(pset);
    let res = {
        let unopt_res = compiler
            .check_always_allows(&typed_pset, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_always_allows_opt(&compiled_pset)
            .await
            .unwrap();
        pathway.resolve(unopt_res, opt_res)
    };
    let cex = {
        let unopt_cex = compiler
            .check_always_allows_with_counterexample(&typed_pset, &envs.symenv)
            .await
            .unwrap();
        let opt_cex = compiler
            .check_always_allows_with_counterexample_opt(&compiled_pset)
            .await
            .unwrap();
        pathway.resolve(unopt_cex, opt_cex)
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let resp = Authorizer::new().is_authorized(&cex.request, pset, &cex.entities);
        assert_eq!(
            resp.decision(),
            Decision::Deny,
            "check_always_allows_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let custom_compiled = CompiledPolicySet::compile_with_custom_symenv(
            pset,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = always_allows_asserts(&custom_compiled);
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let custom_compiled = CompiledPolicySet::compile_with_custom_symenv(
            pset,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = always_allows_asserts(&custom_compiled);
        // There should be some literal false in the assertions
        assert!(asserts.asserts().iter().all(|t| t.is_literal()));
        assert!(asserts.asserts().iter().any(|t| t == &false.into()));
    }

    res
}

pub async fn assert_always_allows<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    assert!(
        assert_always_allows_ok(compiler, pset, envs, Pathway::default()).await,
        "assert_always_allows failed for:\n{pset}"
    );
}

pub async fn assert_does_not_always_allow<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_always_allows_ok(compiler, pset, envs, Pathway::default()).await,
        "assert_does_not_always_allow failed for:\n{pset}"
    );
}

/// Returns `true` if the policyset always-denies in the `req_env`.
///
/// Panics if any call fails or if other invariants are violated.
pub async fn assert_always_denies_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
    pathway: Pathway,
) -> bool {
    let typed_pset = WellTypedPolicies::from_policies(pset, &envs.req_env, envs.schema).unwrap();
    let compiled_pset = envs.compile_policies(pset);
    let res = {
        let unopt_res = compiler
            .check_always_denies(&typed_pset, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_always_denies_opt(&compiled_pset)
            .await
            .unwrap();
        pathway.resolve(unopt_res, opt_res)
    };
    let cex = {
        let unopt_cex = compiler
            .check_always_denies_with_counterexample(&typed_pset, &envs.symenv)
            .await
            .unwrap();
        let opt_cex = compiler
            .check_always_denies_with_counterexample_opt(&compiled_pset)
            .await
            .unwrap();
        pathway.resolve(unopt_cex, opt_cex)
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let resp = Authorizer::new().is_authorized(&cex.request, pset, &cex.entities);
        assert_eq!(
            resp.decision(),
            Decision::Allow,
            "check_always_denies_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let custom_compiled = CompiledPolicySet::compile_with_custom_symenv(
            pset,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = always_denies_asserts(&custom_compiled);
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let custom_compiled = CompiledPolicySet::compile_with_custom_symenv(
            pset,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = always_denies_asserts(&custom_compiled);
        // There should be some literal false in the assertions
        assert!(asserts.asserts().iter().all(|t| t.is_literal()));
        assert!(asserts.asserts().iter().any(|t| t == &false.into()));
    }

    res
}

pub async fn assert_always_denies<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    assert!(
        assert_always_denies_ok(compiler, pset, envs, Pathway::default()).await,
        "assert_always_denies failed for:\n{pset}"
    );
}

pub async fn assert_does_not_always_deny<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_always_denies_ok(compiler, pset, envs, Pathway::default()).await,
        "assert_does_not_always_deny failed for:\n{pset}"
    );
}

/// Returns `true` if the policysets are equivalent in the `req_env`.
///
/// Panics if any call fails or if other invariants are violated.
pub async fn assert_equivalent_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
    pathway: Pathway,
) -> bool {
    let typed_pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let typed_pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    let compiled_pset1 = envs.compile_policies(pset1);
    let compiled_pset2 = envs.compile_policies(pset2);
    let res = {
        let unopt_res = compiler
            .check_equivalent(&typed_pset1, &typed_pset2, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_equivalent_opt(&compiled_pset1, &compiled_pset2)
            .await
            .unwrap();
        pathway.resolve(unopt_res, opt_res)
    };
    let cex = {
        let unopt_cex = compiler
            .check_equivalent_with_counterexample(&typed_pset1, &typed_pset2, &envs.symenv)
            .await
            .unwrap();
        let opt_cex = compiler
            .check_equivalent_with_counterexample_opt(&compiled_pset1, &compiled_pset2)
            .await
            .unwrap();
        pathway.resolve(unopt_cex, opt_cex)
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let resp1 = Authorizer::new().is_authorized(&cex.request, pset1, &cex.entities);
        let resp2 = Authorizer::new().is_authorized(&cex.request, pset2, &cex.entities);
        assert_ne!(
            resp1.decision(),
            resp2.decision(),
            "check_equivalent_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let custom_compiled_1 = CompiledPolicySet::compile_with_custom_symenv(
            pset1,
            &envs.req_env,
            envs.schema,
            literal_symenv.clone(),
        )
        .unwrap();
        let custom_compiled_2 = CompiledPolicySet::compile_with_custom_symenv(
            pset2,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = equivalent_asserts(&custom_compiled_1, &custom_compiled_2);
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let custom_compiled_1 = CompiledPolicySet::compile_with_custom_symenv(
            pset1,
            &envs.req_env,
            envs.schema,
            literal_symenv.clone(),
        )
        .unwrap();
        let custom_compiled_2 = CompiledPolicySet::compile_with_custom_symenv(
            pset2,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = equivalent_asserts(&custom_compiled_1, &custom_compiled_2);
        // There should be some literal false in the assertions
        assert!(asserts.asserts().iter().all(|t| t.is_literal()));
        assert!(asserts.asserts().iter().any(|t| t == &false.into()));
    }

    res
}

pub async fn assert_equivalent<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    assert!(
        assert_equivalent_ok(compiler, pset1, pset2, envs, Pathway::default()).await,
        "assert_equivalent failed for:\n{pset1}\n{pset2}"
    );
}

pub async fn assert_not_equivalent<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_equivalent_ok(compiler, pset1, pset2, envs, Pathway::default()).await,
        "assert_not_equivalent failed for:\n{pset1}\n{pset2}"
    );
}

/// Returns `true` if `pset1` implies `pset2` in the `req_env`.
///
/// Panics if any call fails or if other invariants are violated.
pub async fn assert_implies_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
    pathway: Pathway,
) -> bool {
    let typed_pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let typed_pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    let compiled_pset1 = envs.compile_policies(pset1);
    let compiled_pset2 = envs.compile_policies(pset2);
    let res = {
        let unopt_res = compiler
            .check_implies(&typed_pset1, &typed_pset2, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_implies_opt(&compiled_pset1, &compiled_pset2)
            .await
            .unwrap();
        pathway.resolve(unopt_res, opt_res)
    };
    let cex = {
        let unopt_cex = compiler
            .check_implies_with_counterexample(&typed_pset1, &typed_pset2, &envs.symenv)
            .await
            .unwrap();
        let opt_cex = compiler
            .check_implies_with_counterexample_opt(&compiled_pset1, &compiled_pset2)
            .await
            .unwrap();
        pathway.resolve(unopt_cex, opt_cex)
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let resp1 = Authorizer::new().is_authorized(&cex.request, pset1, &cex.entities);
        let resp2 = Authorizer::new().is_authorized(&cex.request, pset2, &cex.entities);
        assert!(
            resp1.decision() == Decision::Allow && resp2.decision() == Decision::Deny,
            "check_implies_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let custom_compiled_1 = CompiledPolicySet::compile_with_custom_symenv(
            pset1,
            &envs.req_env,
            envs.schema,
            literal_symenv.clone(),
        )
        .unwrap();
        let custom_compiled_2 = CompiledPolicySet::compile_with_custom_symenv(
            pset2,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = implies_asserts(&custom_compiled_1, &custom_compiled_2);
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let custom_compiled_1 = CompiledPolicySet::compile_with_custom_symenv(
            pset1,
            &envs.req_env,
            envs.schema,
            literal_symenv.clone(),
        )
        .unwrap();
        let custom_compiled_2 = CompiledPolicySet::compile_with_custom_symenv(
            pset2,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = implies_asserts(&custom_compiled_1, &custom_compiled_2);
        // There should be some literal false in the assertions
        assert!(asserts.asserts().iter().all(|t| t.is_literal()));
        assert!(asserts.asserts().iter().any(|t| t == &false.into()));
    }

    res
}

pub async fn assert_implies<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    assert!(
        assert_implies_ok(compiler, pset1, pset2, envs, Pathway::default()).await,
        "assert_implies failed for:\n{pset1}\n{pset2}"
    );
}

pub async fn assert_does_not_imply<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_implies_ok(compiler, pset1, pset2, envs, Pathway::default()).await,
        "assert_does_not_imply failed for:\n{pset1}\n{pset2}"
    );
}

/// Returns `true` if the psets are disjoint in the `req_env`.
///
/// Panics if any call fails or if other invariants are violated.
pub async fn assert_disjoint_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
    pathway: Pathway,
) -> bool {
    let typed_pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let typed_pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    let compiled_pset1 = envs.compile_policies(pset1);
    let compiled_pset2 = envs.compile_policies(pset2);
    let res = {
        let unopt_res = compiler
            .check_disjoint(&typed_pset1, &typed_pset2, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_disjoint_opt(&compiled_pset1, &compiled_pset2)
            .await
            .unwrap();
        pathway.resolve(unopt_res, opt_res)
    };
    let cex = {
        let unopt_cex = compiler
            .check_disjoint_with_counterexample(&typed_pset1, &typed_pset2, &envs.symenv)
            .await
            .unwrap();
        let opt_cex = compiler
            .check_disjoint_with_counterexample_opt(&compiled_pset1, &compiled_pset2)
            .await
            .unwrap();
        pathway.resolve(unopt_cex, opt_cex)
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let resp1 = Authorizer::new().is_authorized(&cex.request, pset1, &cex.entities);
        let resp2 = Authorizer::new().is_authorized(&cex.request, pset2, &cex.entities);
        assert!(
            resp1.decision() == Decision::Allow && resp2.decision() == Decision::Allow,
            "check_disjoint_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let custom_compiled_1 = CompiledPolicySet::compile_with_custom_symenv(
            pset1,
            &envs.req_env,
            envs.schema,
            literal_symenv.clone(),
        )
        .unwrap();
        let custom_compiled_2 = CompiledPolicySet::compile_with_custom_symenv(
            pset2,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = disjoint_asserts(&custom_compiled_1, &custom_compiled_2);
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let custom_compiled_1 = CompiledPolicySet::compile_with_custom_symenv(
            pset1,
            &envs.req_env,
            envs.schema,
            literal_symenv.clone(),
        )
        .unwrap();
        let custom_compiled_2 = CompiledPolicySet::compile_with_custom_symenv(
            pset2,
            &envs.req_env,
            envs.schema,
            literal_symenv,
        )
        .unwrap();
        let asserts = disjoint_asserts(&custom_compiled_1, &custom_compiled_2);
        // There should be some literal false in the assertions
        assert!(asserts.asserts().iter().all(|t| t.is_literal()));
        assert!(asserts.asserts().iter().any(|t| t == &false.into()));
    }

    res
}

pub async fn assert_disjoint<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    assert!(
        assert_disjoint_ok(compiler, pset1, pset2, envs, Pathway::default()).await,
        "assert_disjoint failed for:\n{pset1}\n{pset2}"
    );
}

pub async fn assert_not_disjoint<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_disjoint_ok(compiler, pset1, pset2, envs, Pathway::default()).await,
        "assert_not_disjoint failed for:\n{pset1}\n{pset2}"
    );
}
