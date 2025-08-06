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

//! Helper code to run Cedar integration tests

// PANIC SAFETY: This module is used only for testing.
#![allow(clippy::unwrap_used)]
// PANIC SAFETY: This module is used only for testing.
#![allow(clippy::expect_used)]

use crate::cedar_test_impl::*;
#[cfg(feature = "entity-manifest")]
use cedar_policy::{compute_entity_manifest, Validator};
use cedar_policy::{
    Context, Decision, Entities, EntityUid, PolicyId, PolicySet, Request, Schema, ValidationMode,
};
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
#[serde(rename_all = "camelCase")]
pub struct JsonTest {
    /// Filename of the policy set (in Cedar syntax)
    pub policies: String,
    /// Filename of a JSON file representing the entity hierarchy
    pub entities: String,
    /// Filename of the schema (in Cedar syntax)
    pub schema: String,
    /// Whether the given policies are expected to pass the validator with this
    /// schema, or not
    pub should_validate: bool,
    /// Requests to perform on that data, along with their expected results
    /// Alias for backwards compatibility
    pub requests: Vec<JsonRequest>,
}

/// JSON representation of a single request, along with its expected result,
/// in our integration test file format
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct JsonRequest {
    /// Description for the request
    pub description: String,
    /// Principal for the request, in either explicit or implicit `__entity` form
    ///
    /// Examples:
    /// * `{ "__entity": { "type": "User", "id": "123abc" } }`
    /// * `{ "type": "User", "id": "123abc" }`
    pub principal: serde_json::Value,
    /// Action for the request, in either explicit or implicit `__entity` form
    ///
    /// Examples:
    /// * `{ "__entity": { "type": "Action", "id": "view" } }`
    /// * `{ "type": "Action", "id": "view" }`
    pub action: serde_json::Value,
    /// Resource for the request, in either explicit or implicit `__entity` form
    ///
    /// Examples:
    /// * `{ "__entity": { "type": "User", "id": "123abc" } }`
    /// * `{ "type": "User", "id": "123abc" }`
    pub resource: serde_json::Value,
    /// Context for the request. This should be a JSON object, not any other kind
    /// of JSON value
    pub context: serde_json::Value,
    /// Whether to enable request validation for this request
    #[serde(default = "constant_true")]
    pub validate_request: bool,
    /// Expected decision for the request
    pub decision: Decision,
    /// Expected policies that led to the decision
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
        .unwrap_or_else(|e| panic!("error parsing policy file {}: {e}", &test.policies))
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
    Schema::from_cedarschema_str(&schema_text)
        .unwrap_or_else(|e| panic!("error parsing schema in {}: {e}", &test.schema))
        .0
}

/// Given a `JsonTest`, parse (and validate) the provided entities file.
/// # Panics
/// On failure to load or parse entities file.
// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
pub fn parse_entities_from_test(test: &JsonTest, schema: &Schema) -> Entities {
    let entity_file = resolve_integration_test_path(&test.entities);
    let json = std::fs::OpenOptions::new()
        .read(true)
        .open(entity_file)
        .unwrap_or_else(|e| panic!("error opening entity file {}: {e}", &test.entities));

    Entities::from_json_file(json, Some(schema))
        .unwrap_or_else(|e| panic!("error parsing entities in {}: {e}", &test.entities))
}

// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
fn parse_entity_uid(json: serde_json::Value, error_string: &str) -> EntityUid {
    EntityUid::from_json(json).unwrap_or_else(|e| panic!("{error_string}: {e}"))
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
    let error_string = format!(
        "Failed to parse principal for request \"{}\" in {}",
        json_request.description, test_name
    );
    let principal = parse_entity_uid(json_request.principal.clone(), &error_string);
    let error_string = format!(
        "Failed to parse action for request \"{}\" in {}",
        json_request.description, test_name
    );
    let action = parse_entity_uid(json_request.action.clone(), &error_string);
    let error_string = format!(
        "Failed to parse resource for request \"{}\" in {}",
        json_request.description, test_name
    );
    let resource = parse_entity_uid(json_request.resource.clone(), &error_string);

    let context = Context::from_json_value(json_request.context.clone(), Some((schema, &action)))
        .unwrap_or_else(|e| {
            panic!(
                "Failed to parse context for request \"{}\" in {}: {e}",
                json_request.description, test_name
            )
        });
    Request::new(
        principal,
        action,
        resource,
        context,
        if json_request.validate_request {
            Some(schema)
        } else {
            None
        },
    )
    .unwrap_or_else(|e| {
        panic!(
            "error validating request \"{}\" in {}: {e}",
            json_request.description, test_name
        )
    })
}

/// Asserts that the test response matches the json request,
/// including errors when the error comparison mode is enabled.
fn check_matches_json(
    response: &TestResponse,
    json_request: &JsonRequest,
    error_comparison_mode: &ErrorComparisonMode,
    test_name: &str,
) {
    // check decision
    assert_eq!(
        response.response.decision(),
        json_request.decision,
        "test {test_name} failed for request \"{}\": unexpected decision",
        &json_request.description
    );
    // check reason
    let reason: HashSet<PolicyId> = response.response.diagnostics().reason().cloned().collect();
    assert_eq!(
        reason,
        json_request.reason.iter().cloned().collect(),
        "test {test_name} failed for request \"{}\": unexpected reason",
        &json_request.description
    );
    // check errors, if applicable
    // for now, the integration tests only support the `PolicyIds` comparison mode
    if matches!(error_comparison_mode, ErrorComparisonMode::PolicyIds) {
        let errors: HashSet<PolicyId> = response
            .response
            .diagnostics()
            .errors()
            .map(|err| err.policy_id.clone())
            .collect();
        assert_eq!(
            errors,
            json_request.errors.iter().cloned().collect(),
            "test {test_name} failed for request \"{}\": unexpected errors",
            &json_request.description
        );
    }
}

/// Run an integration test starting from a pre-parsed `JsonTest`.
///
/// # Panics
/// When the integration test fails.
#[allow(clippy::too_many_lines)]
// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
pub fn perform_integration_test(
    policies: &PolicySet,
    entities: &Entities,
    schema: &Schema,
    should_validate: bool,
    requests: Vec<JsonRequest>,
    test_name: &str,
    test_impl: &impl CedarTestImplementation,
) {
    let validation_result = test_impl
        .validate(schema, policies, ValidationMode::default())
        .expect("Validation failed");
    if should_validate {
        assert!(
            validation_result.validation_passed(),
            "Unexpected validation errors in {test_name}: {:?}",
            validation_result.errors
        );
    } else {
        match test_impl.validation_comparison_mode() {
            ValidationComparisonMode::AgreeOnAll => {
                assert!(
                    !validation_result.validation_passed(),
                    "Expected that validation would fail in {test_name}, but it did not.",
                );
            }
            ValidationComparisonMode::AgreeOnValid => {} // ignore
        }
    }

    for json_request in requests {
        let request = parse_request_from_test(&json_request, schema, test_name);
        let response = test_impl
            .is_authorized(&request, policies, entities)
            .expect("Authorization failed");
        check_matches_json(
            &response,
            &json_request,
            &test_impl.error_comparison_mode(),
            test_name,
        );

        // now check that entity slicing arrives at the same decision
        #[cfg(feature = "entity-manifest")]
        if should_validate {
            let entity_manifest =
                compute_entity_manifest(&Validator::new(schema.clone()), policies)
                    .expect("test failed");
            let entity_slice = entity_manifest
                .slice_entities(entities.as_ref(), request.as_ref())
                .expect("test failed");
            let slice_response = test_impl
                .is_authorized(&request, policies, &entity_slice.into())
                .expect("Authorization failed");
            check_matches_json(
                &slice_response,
                &json_request,
                &test_impl.error_comparison_mode(),
                test_name,
            );
        }
    }
}

/// Given the filename of a JSON file describing an integration test, perform
/// the test.
///
/// Relative paths are assumed to be relative to the root of the
/// cedar-integration-tests folder.
/// Absolute paths are handled without modification.
/// # Panics
/// When integration test data cannot be found.
#[allow(clippy::too_many_lines)]
// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
pub fn perform_integration_test_from_json_custom(
    jsonfile: impl AsRef<Path>,
    test_impl: &impl CedarTestImplementation,
) {
    let jsonfile = resolve_integration_test_path(jsonfile);
    eprintln!("Running test: {jsonfile:?}");
    let test_name: String = jsonfile.display().to_string();
    let jsonstr = std::fs::read_to_string(jsonfile.as_path())
        .unwrap_or_else(|e| panic!("error reading from file {test_name}: {e}"));
    let test: JsonTest =
        serde_json::from_str(&jsonstr).unwrap_or_else(|e| panic!("error parsing {test_name}: {e}"));
    let policies = parse_policies_from_test(&test);
    let schema = parse_schema_from_test(&test);
    let entities = parse_entities_from_test(&test, &schema);
    perform_integration_test(
        &policies,
        &entities,
        &schema,
        test.should_validate,
        test.requests,
        test_name.as_ref(),
        test_impl,
    );
}

/// Specialization of `perform_integration_test_from_json_custom` that performs
/// an integration test on the `cedar-policy` API.
pub fn perform_integration_test_from_json(jsonfile: impl AsRef<Path>) {
    let rust_impl = RustEngine::new();
    perform_integration_test_from_json_custom(jsonfile, &rust_impl);
}
