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
    solver::Solver, CedarSymCompiler, Env, SymEnv, WellTypedPolicies, WellTypedPolicy,
    WellTypedTemplates,
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

/// Parse a request env with slots from text, panicking if it fails to parse
#[track_caller]
pub fn req_env_with_slots_from_strs(
    principal_ty: &str,
    action: &str,
    resource_ty: &str,
    principal_slot_ty: Option<&str>,
    resource_slot_ty: Option<&str>,
) -> RequestEnv {
    RequestEnv::new_request_env_with_slots(
        principal_ty.parse().unwrap(),
        action.parse().unwrap(),
        resource_ty.parse().unwrap(),
        principal_slot_ty.map(|ty| ty.parse().unwrap()),
        resource_slot_ty.map(|ty| ty.parse().unwrap()),
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

    /// Create a new Environments instance from a schema and principal, action, resource, principal_slot, and resource_slot strings
    #[track_caller]
    pub fn new_with_slots(
        schema: &'a Schema,
        principal_ty: &str,
        action: &str,
        resource_ty: &str,
        principal_slot_ty: Option<&str>,
        resource_slot_ty: Option<&str>,
    ) -> Self {
        let req_env = req_env_with_slots_from_strs(
            principal_ty,
            action,
            resource_ty,
            principal_slot_ty,
            resource_slot_ty,
        );
        let symenv = SymEnv::new(schema, &req_env).unwrap();
        Self {
            schema,
            req_env,
            symenv,
        }
    }
}

pub async fn assert_never_errors<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
) {
    let policy = WellTypedPolicy::from_policy(policy, &envs.req_env, envs.schema).unwrap();
    match compiler.check_never_errors(&policy, &envs.symenv).await {
        Ok(true) => (),
        Ok(false) => panic!("assert_never_errors failed for:\n{policy}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler.check_never_errors_with_counterexample(&policy, &envs.symenv).await.unwrap().is_none(),
        "check_never_errors is true, but check_never_errors_with_counterexample returned a counterexample",
    );
}

pub async fn assert_always_allows<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset = WellTypedPolicies::from_policies(pset, &envs.req_env, envs.schema).unwrap();
    match compiler.check_always_allows(&pset, &envs.symenv).await {
        Ok(true) => (),
        Ok(false) => panic!("assert_always_allows failed for:\n{pset}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler.check_always_allows_with_counterexample(&pset, &envs.symenv).await.unwrap().is_none(),
        "check_always_allows is true, but check_always_allows_with_counterexample returned a counterexample",
    );
}

pub async fn assert_does_not_always_allow<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    let typed_pset = WellTypedPolicies::from_policies(pset, &envs.req_env, envs.schema).unwrap();
    match compiler
        .check_always_allows(&typed_pset, &envs.symenv)
        .await
    {
        Ok(true) => panic!("assert_does_not_always_allow failed for:\n{pset}"),
        Ok(false) => (),
        Err(e) => panic!("{e}"),
    }
    match compiler.check_always_allows_with_counterexample(&typed_pset, &envs.symenv).await.unwrap() {
        Some(Env { request, entities }) => {
            // Check that the request/entities pass validation
            envs.schema.as_ref().validate_request(request.as_ref(), Extensions::all_available()).unwrap();
            Entities::from_entities(entities.clone(), Some(envs.schema)).unwrap();
            // Check that the counterexample is correct
            let resp1 = Authorizer::new().is_authorized(&request, pset, &entities);
            assert!(resp1.decision() == Decision::Deny,
                "check_always_allows_with_counterexample returned an invalid counterexample");
        }
        _ => panic!("check_always_allows is false, but check_always_allows_with_counterexample returned no counterexample"),
    }
}

pub async fn assert_always_denies<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset = WellTypedPolicies::from_policies(pset, &envs.req_env, envs.schema).unwrap();
    match compiler.check_always_denies(&pset, &envs.symenv).await {
        Ok(true) => (),
        Ok(false) => panic!("assert_always_denies failed for:\n{pset}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler.check_always_denies_with_counterexample(&pset, &envs.symenv).await.unwrap().is_none(),
        "check_always_denies is true, but check_always_denies_with_counterexample returned a counterexample",
    );
}

pub async fn assert_does_not_always_deny<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    let typed_pset = WellTypedPolicies::from_policies(pset, &envs.req_env, envs.schema).unwrap();
    match compiler
        .check_always_denies(&typed_pset, &envs.symenv)
        .await
    {
        Ok(true) => panic!("assert_does_not_always_deny failed for:\n{pset}"),
        Ok(false) => (),
        Err(e) => panic!("{e}"),
    }
    match compiler.check_always_denies_with_counterexample(&typed_pset, &envs.symenv).await.unwrap() {
        Some(Env { request, entities }) => {
            // Check that the request/entities pass validation
            envs.schema.as_ref().validate_request(request.as_ref(), Extensions::all_available()).unwrap();
            Entities::from_entities(entities.clone(), Some(envs.schema)).unwrap();
            // Check that the counterexample is correct
            let resp1 = Authorizer::new().is_authorized(&request, pset, &entities);
            assert!(resp1.decision() == Decision::Allow,
                "check_always_denies_with_counterexample returned an invalid counterexample");
        }
        _ => panic!("check_always_denies is false, but check_always_denies_with_counterexample returned no counterexample"),
    }
}

pub async fn assert_equivalent<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler
        .check_equivalent(&pset1, &pset2, &envs.symenv)
        .await
    {
        Ok(true) => (),
        Ok(false) => panic!("assert_equivalent failed for:\n{pset1}\n{pset2}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler.check_equivalent_with_counterexample(&pset1, &pset2, &envs.symenv).await.unwrap().is_none(),
        "check_equivalent is true, but check_equivalent_with_counterexample returned a counterexample",
    );
}

pub async fn assert_not_equivalent<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let typed_pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let typed_pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler
        .check_equivalent(&typed_pset1, &typed_pset2, &envs.symenv)
        .await
    {
        Ok(true) => panic!("assert_not_equivalent failed for:\n{pset1}\n{pset2}"),
        Ok(false) => (),
        Err(e) => panic!("{e}"),
    }
    match compiler.check_equivalent_with_counterexample(&typed_pset1, &typed_pset2, &envs.symenv).await.unwrap() {
        Some(Env { request, entities }) => {
            // Check that the request/entities pass validation
            envs.schema.as_ref().validate_request(request.as_ref(), Extensions::all_available()).unwrap();
            Entities::from_entities(entities.clone(), Some(envs.schema)).unwrap();
            // Check that the counterexample is correct
            let resp1 = Authorizer::new().is_authorized(&request, pset1, &entities);
            let resp2 = Authorizer::new().is_authorized(&request, pset2, &entities);
            assert!(resp1.decision() != resp2.decision(),
                "check_equivalent_with_counterexample returned an invalid counterexample");
        }
        _ => panic!("check_equivalent is false, but check_equivalent_with_counterexample returned no counterexample"),
    }
}

pub async fn assert_implies<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler.check_implies(&pset1, &pset2, &envs.symenv).await {
        Ok(true) => (),
        Ok(false) => panic!("assert_implies failed for:\n{pset1}\n{pset2}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler
            .check_implies_with_counterexample(&pset1, &pset2, &envs.symenv)
            .await
            .unwrap()
            .is_none(),
        "check_implies is true, but check_implies_with_counterexample returned a counterexample",
    );
}

pub async fn assert_does_not_imply<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let typed_pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let typed_pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler
        .check_implies(&typed_pset1, &typed_pset2, &envs.symenv)
        .await
    {
        Ok(true) => panic!("assert_does_not_imply failed for:\n{pset1}\n{pset2}"),
        Ok(false) => (),
        Err(e) => panic!("{e}"),
    }
    match compiler.check_implies_with_counterexample(&typed_pset1, &typed_pset2, &envs.symenv).await.unwrap() {
        Some(Env { request, entities }) => {
            // Check that the request/entities pass validation
            envs.schema.as_ref().validate_request(request.as_ref(), Extensions::all_available()).unwrap();
            Entities::from_entities(entities.clone(), Some(envs.schema)).unwrap();
            // Check that the counterexample is correct
            let resp1 = Authorizer::new().is_authorized(&request, pset1, &entities);
            let resp2 = Authorizer::new().is_authorized(&request, pset2, &entities);
            assert!(resp1.decision() == Decision::Allow && resp2.decision() == Decision::Deny,
                "check_implies_with_counterexample returned an invalid counterexample");
        }
        _ => panic!("check_implies is false, but check_implies_with_counterexample returned no counterexample"),
    }
}

pub async fn assert_disjoint<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler.check_disjoint(&pset1, &pset2, &envs.symenv).await {
        Ok(true) => (),
        Ok(false) => panic!("assert_disjoint failed for:\n{pset1}\n{pset2}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler
            .check_disjoint_with_counterexample(&pset1, &pset2, &envs.symenv)
            .await
            .unwrap()
            .is_none(),
        "check_disjoint is true, but check_disjoint_with_counterexample returned a counterexample",
    );
}

pub async fn assert_not_disjoint<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let typed_pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let typed_pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler
        .check_disjoint(&typed_pset1, &typed_pset2, &envs.symenv)
        .await
    {
        Ok(true) => panic!("assert_not_disjoint failed for:\n{pset1}\n{pset2}"),
        Ok(false) => (),
        Err(e) => panic!("{e}"),
    }
    match compiler.check_disjoint_with_counterexample(&typed_pset1, &typed_pset2, &envs.symenv).await.unwrap() {
        Some(Env { request, entities }) => {
            // Check that the request/entities pass validation
            envs.schema.as_ref().validate_request(request.as_ref(), Extensions::all_available()).unwrap();
            Entities::from_entities(entities.clone(), Some(envs.schema)).unwrap();
            // Check that the counterexample is correct
            let resp1 = Authorizer::new().is_authorized(&request, pset1, &entities);
            let resp2 = Authorizer::new().is_authorized(&request, pset2, &entities);
            assert!(resp1.decision() == Decision::Allow && resp2.decision() == Decision::Allow,
                "check_disjoint_with_counterexample returned an invalid counterexample");
        }
        _ => panic!("check_disjoint is false, but check_disjoint_with_counterexample returned no counterexample"),
    }
}

pub async fn assert_implies_templates<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset1 = WellTypedTemplates::from_templates(pset1, &envs.req_env, envs.schema).unwrap();
    let pset2 = WellTypedTemplates::from_templates(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler
        .check_implies_templates(&pset1, &pset2, &envs.symenv)
        .await
    {
        Ok(true) => (),
        Ok(false) => panic!("assert_implies failed for:\n{pset1}\n{pset2}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler
            .check_implies_with_counterexample_templates(&pset1, &pset2, &envs.symenv)
            .await
            .unwrap()
            .is_none(),
        "check_implies_templates is true, but check_implies_with_counterexample_templates returned a counterexample",
    );
}

pub async fn assert_always_denies_templates<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset = WellTypedTemplates::from_templates(pset, &envs.req_env, envs.schema).unwrap();
    match compiler
        .check_always_denies_templates(&pset, &envs.symenv)
        .await
    {
        Ok(true) => (),
        Ok(false) => panic!("assert_always_denies failed for:\n{pset}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler.check_always_denies_with_counterexample_templates(&pset, &envs.symenv).await.unwrap().is_none(),
        "check_always_denies_templates is true, but check_always_denies_with_counterexample_templates returned a counterexample",
    );
}

pub async fn assert_equivalent_templates<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset1 = WellTypedTemplates::from_templates(pset1, &envs.req_env, envs.schema).unwrap();
    let pset2 = WellTypedTemplates::from_templates(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler
        .check_equivalent_templates(&pset1, &pset2, &envs.symenv)
        .await
    {
        Ok(true) => (),
        Ok(false) => panic!("assert_equivalent failed for:\n{pset1}\n{pset2}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler.check_equivalent_with_counterexample_templates(&pset1, &pset2, &envs.symenv).await.unwrap().is_none(),
        "check_equivalent is true, but check_equivalent_with_counterexample_templates returned a counterexample",
    );
}

pub async fn assert_disjoint_templates<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset1 = WellTypedTemplates::from_templates(pset1, &envs.req_env, envs.schema).unwrap();
    let pset2 = WellTypedTemplates::from_templates(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler
        .check_disjoint_templates(&pset1, &pset2, &envs.symenv)
        .await
    {
        Ok(true) => (),
        Ok(false) => panic!("assert_disjoint failed for:\n{pset1}\n{pset2}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler
            .check_disjoint_with_counterexample_templates(&pset1, &pset2, &envs.symenv)
            .await
            .unwrap()
            .is_none(),
        "check_disjoint is true, but check_disjoint_with_counterexample_templates returned a counterexample",
    );
}

pub async fn assert_possible_template_instantiation_satisfies_request<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    request: &cedar_policy::Request,
    envs: &Environments<'_>,
) {
    let pset = WellTypedTemplates::from_templates(pset, &envs.req_env, envs.schema).unwrap();
    match compiler
        .check_possible_template_instantiation_satisfies_request(&pset, &envs.symenv, request)
        .await
    {
        Ok(Some(_)) => (),
        Ok(None) => panic!("assert_possible_template_instantiation_satisfies_request failed for:\n{pset}\n{request}"),
        Err(e) => panic!("{e}"),
    }
}
