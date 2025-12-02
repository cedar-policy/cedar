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

#![allow(
    dead_code,
    reason = "not actually dead, but cargo issues warnings per test file"
)]

//! Utilities shared by various tests throughout the package
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Decision, Entities, Policy, PolicyId, PolicySet, RequestEnv, Schema,
    ValidationMode, Validator,
};
use cedar_policy_core::{ast::RequestSchema, extensions::Extensions};
use cedar_policy_symcc::{
    compile_always_allows, compile_always_denies, compile_always_matches, compile_disjoint,
    compile_equivalent, compile_implies, compile_never_errors, compile_never_matches,
    solver::Solver, CedarSymCompiler, CompiledPolicies, CompiledPolicy, Env, Interpretation,
    SymEnv, WellTypedPolicies, WellTypedPolicy,
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
}

impl<'a> Environments<'a> {
    /// Create a new Environments instance from a schema and principal, action, and resource strings
    #[track_caller]
    pub fn new(schema: &'a Schema, principal_ty: &str, action: &str, resource_ty: &str) -> Self {
        let req_env = req_env_from_strs(principal_ty, action, resource_ty);
        let symenv = SymEnv::new(schema, &req_env).unwrap();
        Self {
            schema,
            req_env,
            symenv,
        }
    }

    /// Gets all possible request environments from a schema.
    pub fn get_all_from_schema(schema: &'a Schema) -> Vec<Self> {
        schema
            .request_envs()
            .map(|req_env| {
                let symenv = SymEnv::new(schema, &req_env).unwrap();
                Self {
                    schema,
                    req_env,
                    symenv,
                }
            })
            .collect()
    }
}

/// Checks that the counterexample validates against the schema.
fn assert_cex_valid(schema: &Schema, cex: &Env) {
    schema
        .as_ref()
        .validate_request(cex.request.as_ref(), Extensions::all_available())
        .unwrap();
    Entities::from_entities(cex.entities.clone(), Some(schema)).unwrap();
}

pub async fn assert_never_errors_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
) -> bool {
    let typed_policy = WellTypedPolicy::from_policy(policy, &envs.req_env, envs.schema).unwrap();
    let compiled_policy = CompiledPolicy::compile(policy, &envs.req_env, envs.schema).unwrap();
    let res = {
        let unopt_res = compiler
            .check_never_errors(&typed_policy, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_never_errors_opt(&compiled_policy)
            .await
            .unwrap();
        assert_eq!(unopt_res, opt_res);
        unopt_res
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
        assert_eq!(unopt_cex, opt_cex);
        unopt_cex
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
        let asserts = compile_never_errors(&typed_policy, &literal_symenv).unwrap();
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let asserts = compile_never_errors(&typed_policy, &literal_symenv).unwrap();
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
        assert_never_errors_ok(compiler, policy, envs).await,
        "assert_never_errors failed for:\n{policy}"
    );
}

pub async fn assert_always_matches_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
) -> bool {
    let typed_policy = WellTypedPolicy::from_policy(policy, &envs.req_env, envs.schema).unwrap();
    let compiled_policy = CompiledPolicy::compile(policy, &envs.req_env, envs.schema).unwrap();
    let res = {
        let unopt_res = compiler
            .check_always_matches(&typed_policy, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_always_matches_opt(&compiled_policy)
            .await
            .unwrap();
        assert_eq!(unopt_res, opt_res);
        unopt_res
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
        assert_eq!(unopt_cex, opt_cex);
        unopt_cex
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
        assert!(
            resp.decision() == expected_decision,
            "check_always_matches_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let asserts = compile_always_matches(&typed_policy, &literal_symenv).unwrap();
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let asserts = compile_always_matches(&typed_policy, &literal_symenv).unwrap();
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
        assert_always_matches_ok(compiler, policy, envs).await,
        "assert_always_matches failed for:\n{policy}"
    );
}

pub async fn assert_does_not_always_match<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_always_matches_ok(compiler, policy, envs).await,
        "assert_does_not_always_match failed for:\n{policy}"
    );
}

pub async fn assert_never_matches_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
) -> bool {
    let typed_policy = WellTypedPolicy::from_policy(policy, &envs.req_env, envs.schema).unwrap();
    let compiled_policy = CompiledPolicy::compile(policy, &envs.req_env, envs.schema).unwrap();
    let res = {
        let unopt_res = compiler
            .check_never_matches(&typed_policy, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_never_matches_opt(&compiled_policy)
            .await
            .unwrap();
        assert_eq!(unopt_res, opt_res);
        unopt_res
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
        assert_eq!(unopt_cex, opt_cex);
        unopt_cex
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
        assert!(
            resp.decision() == expected_decision,
            "check_never_matches_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let asserts = compile_never_matches(&typed_policy, &literal_symenv).unwrap();
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let asserts = compile_never_matches(&typed_policy, &literal_symenv).unwrap();
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
        assert_never_matches_ok(compiler, policy, envs).await,
        "assert_never_matches failed for:\n{policy}"
    );
}

pub async fn assert_does_not_never_match<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_never_matches_ok(compiler, policy, envs).await,
        "assert_does_not_never_match failed for:\n{policy}"
    );
}

pub async fn assert_always_allows_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) -> bool {
    let typed_pset = WellTypedPolicies::from_policies(pset, &envs.req_env, envs.schema).unwrap();
    let compiled_pset = CompiledPolicies::compile(pset, &envs.req_env, envs.schema).unwrap();
    let res = {
        let unopt_res = compiler
            .check_always_allows(&typed_pset, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_always_allows_opt(&compiled_pset)
            .await
            .unwrap();
        assert_eq!(unopt_res, opt_res);
        unopt_res
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
        assert_eq!(unopt_cex, opt_cex);
        unopt_cex
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let resp = Authorizer::new().is_authorized(&cex.request, pset, &cex.entities);
        assert!(
            resp.decision() == Decision::Deny,
            "check_always_allows_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let asserts = compile_always_allows(&typed_pset, &literal_symenv).unwrap();
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let asserts = compile_always_allows(&typed_pset, &literal_symenv).unwrap();
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
        assert_always_allows_ok(compiler, pset, envs).await,
        "assert_always_allows failed for:\n{pset}"
    );
}

pub async fn assert_does_not_always_allow<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_always_allows_ok(compiler, pset, envs).await,
        "assert_does_not_always_allow failed for:\n{pset}"
    );
}

pub async fn assert_always_denies_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) -> bool {
    let typed_pset = WellTypedPolicies::from_policies(pset, &envs.req_env, envs.schema).unwrap();
    let compiled_pset = CompiledPolicies::compile(pset, &envs.req_env, envs.schema).unwrap();
    let res = {
        let unopt_res = compiler
            .check_always_denies(&typed_pset, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_always_denies_opt(&compiled_pset)
            .await
            .unwrap();
        assert_eq!(unopt_res, opt_res);
        unopt_res
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
        assert_eq!(unopt_cex, opt_cex);
        unopt_cex
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let resp = Authorizer::new().is_authorized(&cex.request, pset, &cex.entities);
        assert!(
            resp.decision() == Decision::Allow,
            "check_always_denies_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let asserts = compile_always_denies(&typed_pset, &literal_symenv).unwrap();
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let asserts = compile_always_denies(&typed_pset, &literal_symenv).unwrap();
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
        assert_always_denies_ok(compiler, pset, envs).await,
        "assert_always_denies failed for:\n{pset}"
    );
}

pub async fn assert_does_not_always_deny<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    assert!(
        !assert_always_denies_ok(compiler, pset, envs).await,
        "assert_does_not_always_deny failed for:\n{pset}"
    );
}

pub async fn assert_equivalent_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) -> bool {
    let typed_pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let typed_pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    let compiled_pset1 = CompiledPolicies::compile(pset1, &envs.req_env, envs.schema).unwrap();
    let compiled_pset2 = CompiledPolicies::compile(pset2, &envs.req_env, envs.schema).unwrap();
    let res = {
        let unopt_res = compiler
            .check_equivalent(&typed_pset1, &typed_pset2, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_equivalent_opt(&compiled_pset1, &compiled_pset2)
            .await
            .unwrap();
        assert_eq!(unopt_res, opt_res);
        unopt_res
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
        assert_eq!(unopt_cex, opt_cex);
        unopt_cex
    };
    assert_eq!(res, cex.is_none());

    if let Some(cex) = cex {
        assert_cex_valid(envs.schema, &cex);
        let resp1 = Authorizer::new().is_authorized(&cex.request, pset1, &cex.entities);
        let resp2 = Authorizer::new().is_authorized(&cex.request, pset2, &cex.entities);
        assert!(
            resp1.decision() != resp2.decision(),
            "check_equivalent_with_counterexample returned an invalid counterexample"
        );
        // Re-perform the check with a symbolized concrete `Env`
        let literal_symenv = SymEnv::from_concrete_env(&envs.req_env, envs.schema, &cex).unwrap();
        assert!(literal_symenv.is_literal());
        let asserts = compile_equivalent(&typed_pset1, &typed_pset2, &literal_symenv).unwrap();
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let asserts = compile_equivalent(&typed_pset1, &typed_pset2, &literal_symenv).unwrap();
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
        assert_equivalent_ok(compiler, pset1, pset2, envs).await,
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
        !assert_equivalent_ok(compiler, pset1, pset2, envs).await,
        "assert_not_equivalent failed for:\n{pset1}\n{pset2}"
    );
}

pub async fn assert_implies_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) -> bool {
    let typed_pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let typed_pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    let compiled_pset1 = CompiledPolicies::compile(pset1, &envs.req_env, envs.schema).unwrap();
    let compiled_pset2 = CompiledPolicies::compile(pset2, &envs.req_env, envs.schema).unwrap();
    let res = {
        let unopt_res = compiler
            .check_implies(&typed_pset1, &typed_pset2, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_implies_opt(&compiled_pset1, &compiled_pset2)
            .await
            .unwrap();
        assert_eq!(unopt_res, opt_res);
        unopt_res
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
        assert_eq!(unopt_cex, opt_cex);
        unopt_cex
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
        let asserts = compile_implies(&typed_pset1, &typed_pset2, &literal_symenv).unwrap();
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let asserts = compile_implies(&typed_pset1, &typed_pset2, &literal_symenv).unwrap();
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
        assert_implies_ok(compiler, pset1, pset2, envs).await,
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
        !assert_implies_ok(compiler, pset1, pset2, envs).await,
        "assert_does_not_imply failed for:\n{pset1}\n{pset2}"
    );
}

pub async fn assert_disjoint_ok<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) -> bool {
    let typed_pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let typed_pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    let compiled_pset1 = CompiledPolicies::compile(pset1, &envs.req_env, envs.schema).unwrap();
    let compiled_pset2 = CompiledPolicies::compile(pset2, &envs.req_env, envs.schema).unwrap();
    let res = {
        let unopt_res = compiler
            .check_disjoint(&typed_pset1, &typed_pset2, &envs.symenv)
            .await
            .unwrap();
        let opt_res = compiler
            .check_disjoint_opt(&compiled_pset1, &compiled_pset2)
            .await
            .unwrap();
        assert_eq!(unopt_res, opt_res);
        unopt_res
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
        assert_eq!(unopt_cex, opt_cex);
        unopt_cex
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
        let asserts = compile_disjoint(&typed_pset1, &typed_pset2, &literal_symenv).unwrap();
        // All asserts should be simplified to literal true's
        assert!(asserts.asserts().iter().all(|t| t == &true.into()));
    } else {
        // Test that the default interpretation does satisfy the property
        let interp = Interpretation::default(&envs.symenv);
        let literal_symenv = envs.symenv.interpret(&interp);
        assert!(literal_symenv.is_literal());
        let asserts = compile_disjoint(&typed_pset1, &typed_pset2, &literal_symenv).unwrap();
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
        assert_disjoint_ok(compiler, pset1, pset2, envs).await,
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
        !assert_disjoint_ok(compiler, pset1, pset2, envs).await,
        "assert_not_disjoint failed for:\n{pset1}\n{pset2}"
    );
}
