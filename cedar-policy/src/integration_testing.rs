/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

//! Helper code to run Cedar integration tests

// This is test code that is under `src/` only so that it can be shared between
// packages, so it's appropriate to exclude it from coverage.
//
// GRCOV_STOP_COVERAGE

// PANIC SAFETY: This module is used only for testing.
#![allow(clippy::unwrap_used)]
// PANIC SAFETY: This module is used only for testing.
#![allow(clippy::expect_used)]

use crate::{
    frontend::is_authorized::InterfaceResponse, AuthorizationError, Authorizer, Context, Decision,
    Entities, EntityUid, PolicyId, PolicySet, Request, Schema, ValidationMode, Validator,
};
use cedar_policy_core::jsonvalue::JsonValueWithNoDuplicateKeys;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    env,
    path::{Path, PathBuf},
    str::FromStr,
};

/// JSON representation of our integration test file format
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JsonTest {
    /// Filename of the policies to use (in pure Cedar syntax)
    pub policies: String,
    /// Filename of a JSON file representing the entity hierarchy
    pub entities: String,
    /// Filename of a JSON file containing the schema.
    pub schema: String,
    /// Whether the given policies are expected to pass the validator with this
    /// schema, or not
    pub should_validate: bool,
    /// Requests to perform on that data, along with their expected results
    /// Alias for backwards compatibility
    #[serde(alias = "queries")]
    pub requests: Vec<JsonRequest>,
}

/// JSON representation of a single request, along with its expected result,
/// in our integration test file format
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRequest {
    /// Description for the request
    pub desc: String,
    /// Principal for the request, in either explicit or implicit `__entity` form
    ///
    /// Examples:
    /// * `{ "__entity": { "type": "User", "id": "123abc" } }`
    /// * `{ "type": "User", "id": "123abc" }`
    #[serde(default)]
    pub principal: Option<JsonValueWithNoDuplicateKeys>,
    /// Action for the request, in either explicit or implicit `__entity` form
    ///
    /// Examples:
    /// * `{ "__entity": { "type": "Action", "id": "view" } }`
    /// * `{ "type": "Action", "id": "view" }`
    #[serde(default)]
    pub action: Option<JsonValueWithNoDuplicateKeys>,
    /// Resource for the request, in either explicit or implicit `__entity` form
    ///
    /// Examples:
    /// * `{ "__entity": { "type": "User", "id": "123abc" } }`
    /// * `{ "type": "User", "id": "123abc" }`
    #[serde(default)]
    pub resource: Option<JsonValueWithNoDuplicateKeys>,
    /// Context for the request. This should be a JSON object, not any other kind
    /// of JSON value
    pub context: JsonValueWithNoDuplicateKeys,
    /// Whether to enable request validation for this request
    #[serde(default = "constant_true")]
    pub enable_request_validation: bool,
    /// Expected decision for the request
    pub decision: Decision,
    /// Expected policies that led to the decision
    #[serde(alias = "reasons")]
    pub reason: Vec<PolicyId>,
    /// Expected policies that resulted in errors
    pub errors: Vec<PolicyId>,
}

fn constant_true() -> bool {
    true
}

/// For relative paths, return the absolute path, assuming that the path
/// is relative to the root of the `CedarIntegrationTests` repo.
/// For absolute paths, return them unchanged.
///
/// # Panics
///
/// Panics if the environment variable `CARGO_MANIFEST_DIR` is not set,
/// and `CEDAR_INTEGRATION_TESTS_PATH` is not set.
/// `CARGO_MANIFEST_DIR` should be set by Cargo at build-time, but
/// `CEDAR_INTEGRATION_TESTS_PATH` overrides `CARGO_MANIFEST_DIR`.
pub fn resolve_integration_test_path(path: impl AsRef<Path>) -> PathBuf {
    if path.as_ref().is_relative() {
        if let Ok(integration_tests_env_var) = env::var("CEDAR_INTEGRATION_TESTS_PATH") {
            return PathBuf::from(integration_tests_env_var);
        }
        let manifest_dir = env::var("CARGO_MANIFEST_DIR")
            .expect("`CARGO_MANIFEST_DIR` should be set by Cargo at build-time.");
        let mut full_path = PathBuf::from(manifest_dir.clone());
        full_path.push("..");
        // We run `cargo test` for cedar-drt. In that case, CARGO_MANIFEST_DIR will be
        // `cedar-spec/cedar-drt` and we want `../cedar/cedar-integration-tests`
        if manifest_dir.ends_with("cedar-drt") {
            full_path.push("cedar");
        }
        full_path.push("cedar-integration-tests");
        full_path.push(path.as_ref());
        full_path
    } else {
        path.as_ref().into()
    }
}

/// Data structure for the validation result of an integration test. Unlike a
/// definitional authorization response, a definitional validation result isn't
/// feasible to convert to its production analogue, so instead, we define a
/// simple data structure to which both can be converted that is sufficient for
/// the checks we want to perform.
#[derive(Debug)]
pub struct IntegrationTestValidationResult {
    /// Whether the test inputs passed validation.
    pub validation_passed: bool,
    /// Information about validation errors that may be shown to the user for
    /// diagnostic purposes. As the name suggests, it's customary to use the
    /// `Debug` representation of the original data structure.
    pub validation_errors_debug: String,
}

/// A custom Cedar implementation (authorizer + validator) on which to run
/// integration tests instead of the `Cedar` API.
pub trait CustomCedarImpl {
    /// Custom authorizer entry point.
    fn is_authorized(
        &self,
        q: &cedar_policy_core::ast::Request,
        p: &cedar_policy_core::ast::PolicySet,
        e: &cedar_policy_core::entities::Entities,
    ) -> InterfaceResponse;

    /// Custom validator entry point.
    ///
    /// The fact that this API takes ownership of `schema` is a quirk that
    /// parallels the equivalent production code pattern, in which construction
    /// of the `Validator` would take ownership of the schema. Indeed, the only
    /// current implementation of this method is based on
    /// `DefinitionalValidator::validate`, which seems to have replicated this
    /// quirk even though it has no apparent implementation need to take
    /// ownership of the schema.
    fn validate(
        &self,
        schema: cedar_policy_validator::ValidatorSchema,
        policies: &cedar_policy_core::ast::PolicySet,
    ) -> IntegrationTestValidationResult;
}

/// Given a `JsonTest`, parse the provided policies file.
/// # Panics
/// On failure to load or parse policies file.
// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
pub fn parse_policies_from_test(test: &JsonTest) -> PolicySet {
    let policy_file = resolve_integration_test_path(&test.policies);
    let policies_text = std::fs::read_to_string(policy_file)
        .unwrap_or_else(|e| panic!("error loading policy file {}: {e}", test.policies));
    PolicySet::from_str(&policies_text)
        .unwrap_or_else(|e| panic!("error parsing policy in file {}: {e}", &test.policies))
}

/// Same as `parse_policies_from_test`, but returns `cedar_policy_core::ast::PolicySet`
pub fn parse_policies_from_test_internal(test: &JsonTest) -> cedar_policy_core::ast::PolicySet {
    parse_policies_from_test(test).ast
}

/// Given a `JsonTest`, parse the provided schema file.
/// # Panics
/// On failure to load or parse schema file.
// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
pub fn parse_schema_from_test(test: &JsonTest) -> Schema {
    let schema_file = resolve_integration_test_path(&test.schema);
    let schema_text = std::fs::read_to_string(schema_file)
        .unwrap_or_else(|e| panic!("error loading schema file {}: {e}", &test.schema));
    Schema::from_str(&schema_text)
        .unwrap_or_else(|e| panic!("error parsing schema in {}: {e}", &test.schema))
}

/// Same as `parse_schema_from_test`, but returns `cedar_policy_validator::ValidatorSchema`
pub fn parse_schema_from_test_internal(test: &JsonTest) -> cedar_policy_validator::ValidatorSchema {
    parse_schema_from_test(test).0
}

/// Given a `JsonTest`, parse (and validate) the provided entities file.
/// # Panics
/// On failure to load or parse entities file.
// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
pub fn parse_entities_from_test(test: &JsonTest, schema: &Schema) -> Entities {
    let entity_file = resolve_integration_test_path(&test.entities);
    let entities_json = std::fs::OpenOptions::new()
        .read(true)
        .open(entity_file)
        .unwrap_or_else(|e| panic!("error opening entity file {}: {e}", &test.entities));
    Entities::from_json_file(&entities_json, Some(schema))
        .unwrap_or_else(|e| panic!("error parsing entities in {}: {e}", &test.entities))
}

/// Same as `parse_entities_from_test`, but returns `cedar_policy_core::entities::Entities`
pub fn parse_entities_from_test_internal(
    test: &JsonTest,
    schema: &Schema,
) -> cedar_policy_core::entities::Entities {
    parse_entities_from_test(test, schema).0
}

/// Given a `JsonRequest`, parse (and optionally validate) the provided request.
/// # Panics
/// On failure to parse or validate request.
// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
pub fn parse_request_from_test(
    json_request: &JsonRequest,
    schema: &Schema,
    test_name: &str,
) -> Request {
    let principal = json_request.principal.clone().map(|json| {
        EntityUid::from_json(json.into()).unwrap_or_else(|e| {
            panic!(
                "Failed to parse principal for request \"{}\" in {}: {e}",
                json_request.desc, test_name
            )
        })
    });
    let action = json_request.action.clone().map(|json| {
        EntityUid::from_json(json.into()).unwrap_or_else(|e| {
            panic!(
                "Failed to parse action for request \"{}\" in {}: {e}",
                json_request.desc, test_name
            )
        })
    });
    let resource = json_request.resource.clone().map(|json| {
        EntityUid::from_json(json.into()).unwrap_or_else(|e| {
            panic!(
                "Failed to parse resource for request \"{}\" in {}: {e}",
                json_request.desc, test_name
            )
        })
    });
    let context_schema = action.as_ref().map(|a| (schema, a));
    let context = Context::from_json_value(json_request.context.clone().into(), context_schema)
        .unwrap_or_else(|e| {
            panic!(
                "error parsing context for request \"{}\" in {}: {e}",
                json_request.desc, test_name
            )
        });
    Request::new(
        principal,
        action,
        resource,
        context,
        if json_request.enable_request_validation {
            Some(schema)
        } else {
            None
        },
    )
    .unwrap_or_else(|e| {
        panic!(
            "error validating request \"{}\" in {}: {e}",
            json_request.desc, test_name
        )
    })
}

/// Same as `parse_request_from_test`, but returns `cedar_policy_core::ast::Request`
pub fn parse_request_from_test_internal(
    request: &JsonRequest,
    schema: &Schema,
    test_name: &str,
) -> cedar_policy_core::ast::Request {
    parse_request_from_test(request, schema, test_name).0
}

/// Given the filename of a JSON file describing an integration test, perform
/// the test. If a custom Cedar implementation is provided, then use it for the
/// test, otherwise perform the test on the `Cedar` API.
///
/// Relative paths are assumed to be relative to the root of the
/// cedar-integration-tests folder.
/// Absolute paths are handled without modification.
/// # Panics
/// When integration test data cannot be found or the test otherwise fails.
#[allow(clippy::too_many_lines)]
// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
pub fn perform_integration_test_from_json_custom(
    jsonfile: impl AsRef<Path>,
    custom_impl_opt: Option<&dyn CustomCedarImpl>,
) {
    let jsonfile = resolve_integration_test_path(jsonfile);
    eprintln!("File path: {jsonfile:?}");
    let test_name: String = jsonfile.display().to_string();
    let jsonstr = std::fs::read_to_string(jsonfile.as_path())
        .unwrap_or_else(|e| panic!("error reading from file {test_name}: {e}"));
    let test: JsonTest =
        serde_json::from_str(&jsonstr).unwrap_or_else(|e| panic!("error parsing {test_name}: {e}"));
    let policies = parse_policies_from_test(&test);
    let schema = parse_schema_from_test(&test);
    let entities = parse_entities_from_test(&test, &schema);

    let validation_result = if let Some(custom_impl) = custom_impl_opt {
        custom_impl.validate(schema.0.clone(), &policies.ast)
    } else {
        let validator = Validator::new(schema.clone());
        let api_result = validator.validate(&policies, ValidationMode::default());
        IntegrationTestValidationResult {
            validation_passed: api_result.validation_passed(),
            validation_errors_debug: format!(
                "{:?}",
                api_result.validation_errors().collect::<Vec<_>>()
            ),
        }
    };
    if test.should_validate {
        assert!(
            validation_result.validation_passed,
            "Unexpected validation errors in {test_name}: {}",
            validation_result.validation_errors_debug
        );
    } else {
        assert!(
            !validation_result.validation_passed,
            "Expected that validation would fail in {test_name}, but it did not.",
        );
    }

    for json_request in test.requests {
        let request = parse_request_from_test(&json_request, &schema, &test_name);
        if let Some(custom_impl) = custom_impl_opt {
            let response = custom_impl.is_authorized(&request.0, &policies.ast, &entities.0);
            // check decision
            assert_eq!(
                response.decision(),
                json_request.decision,
                "test {test_name} failed for request \"{}\": unexpected decision",
                &json_request.desc
            );
            // check reasons
            let reasons: HashSet<PolicyId> = response.diagnostics().reason().cloned().collect();
            assert_eq!(
                reasons,
                json_request.reason.into_iter().collect(),
                "test {test_name} failed for request \"{}\": unexpected reasons",
                &json_request.desc
            );
            // ignore errors (#586)
        } else {
            let response = Authorizer::new().is_authorized(&request, &policies, &entities);
            // check decision
            assert_eq!(
                response.decision(),
                json_request.decision,
                "test {test_name} failed for request \"{}\": unexpected decision",
                &json_request.desc
            );
            // check reasons
            let reasons: HashSet<PolicyId> = response.diagnostics().reason().cloned().collect();
            assert_eq!(
                reasons,
                json_request.reason.into_iter().collect(),
                "test {test_name} failed for request \"{}\": unexpected reasons",
                &json_request.desc
            );
            // check errors
            let errors: HashSet<PolicyId> = response
                .diagnostics()
                .errors()
                .map(AuthorizationError::id)
                .cloned()
                .collect();
            assert_eq!(
                errors,
                json_request.errors.into_iter().collect(),
                "test {test_name} failed for request \"{}\": unexpected errors",
                &json_request.desc
            );
        };
    }
}

/// Specialization of `perform_integration_test_from_json_custom` that performs
/// an integration test on the `cedar-policy` API.
pub fn perform_integration_test_from_json(jsonfile: impl AsRef<Path>) {
    perform_integration_test_from_json_custom(jsonfile, None);
}
