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

//! Utilities shared by various tests throughout the package
#![cfg(test)]

use std::str::FromStr;

use cedar_policy::{Policy, PolicyId, PolicySet, RequestEnv, Schema, ValidationMode, Validator};
use cedar_symcc::SymEnv;

#[track_caller]
pub fn pretty_panic<T>(e: impl miette::Diagnostic + Send + Sync + 'static) -> T {
    panic!("{:?}", miette::Report::new(e))
}

/// Parse a policy from text, panicking if it fails to parse or validate
#[allow(
    dead_code,
    reason = "supress unused warning as this is used within the integration_tests"
)]
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
#[allow(
    dead_code,
    reason = "supress unused warning as this is used within the integration_tests"
)]
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
#[allow(
    dead_code,
    reason = "supress unused warning as this is used within the integration_tests"
)]
#[track_caller]
pub fn schema_from_cedarstr(str: &str) -> Schema {
    Schema::from_cedarschema_str(str)
        .unwrap_or_else(pretty_panic)
        .0
}

/// Parse a request env from text, panicking if it fails to parse
#[allow(
    dead_code,
    reason = "supress unused warning as this is used within the integration_tests"
)]
#[track_caller]
pub fn req_env_from_strs(principal_ty: &str, action: &str, resource_ty: &str) -> RequestEnv {
    RequestEnv::new(
        principal_ty.parse().unwrap(),
        action.parse().unwrap(),
        resource_ty.parse().unwrap(),
    )
}

#[allow(
    dead_code,
    reason = "supress unused warning as this is used within the integration_tests"
)]
#[derive(Debug)]
pub struct Environments<'a> {
    pub schema: &'a Schema,
    pub req_env: RequestEnv,
    pub symenv: SymEnv,
}

#[allow(
    dead_code,
    reason = "supress unused warning as this is used within the integration_tests"
)]
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
}
