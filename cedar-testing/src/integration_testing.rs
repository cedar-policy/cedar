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

use crate::cedar_test_impl::*;
use cedar_policy::{extensions::Extensions, Decision, PolicyId, ValidationMode};
use cedar_policy_core::ast::{Eid, EntityUID, PolicySet, Request};
use cedar_policy_core::entities::{self, Entities, JsonDeserializationErrorContext};
use cedar_policy_core::{jsonvalue::JsonValueWithNoDuplicateKeys, parser};
use cedar_policy_validator::ValidatorSchema;
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

/// Given a `JsonTest`, parse the provided policies file.
/// # Panics
/// On failure to load or parse policies file.
// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
pub fn parse_policies_from_test(test: &JsonTest) -> PolicySet {
    let policy_file = resolve_integration_test_path(&test.policies);
    let policies_text = std::fs::read_to_string(policy_file)
        .unwrap_or_else(|e| panic!("error loading policy file {}: {e}", test.policies));
    parser::parse_policyset(&policies_text)
        .unwrap_or_else(|e| panic!("error parsing policy in file {}: {e}", &test.policies))
}

/// Given a `JsonTest`, parse the provided schema file.
/// # Panics
/// On failure to load or parse schema file.
// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
pub fn parse_schema_from_test(test: &JsonTest) -> ValidatorSchema {
    let schema_file = resolve_integration_test_path(&test.schema);
    let schema_text = std::fs::read_to_string(schema_file)
        .unwrap_or_else(|e| panic!("error loading schema file {}: {e}", &test.schema));
    ValidatorSchema::from_str(&schema_text)
        .unwrap_or_else(|e| panic!("error parsing schema in {}: {e}", &test.schema))
}

/// Given a `JsonTest`, parse (and validate) the provided entities file.
/// # Panics
/// On failure to load or parse entities file.
// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
pub fn parse_entities_from_test(test: &JsonTest, schema: &ValidatorSchema) -> Entities {
    let entity_file = resolve_integration_test_path(&test.entities);
    let json = std::fs::OpenOptions::new()
        .read(true)
        .open(entity_file)
        .unwrap_or_else(|e| panic!("error opening entity file {}: {e}", &test.entities));

    let schema = cedar_policy_validator::CoreSchema::new(schema);
    let eparser = entities::EntityJsonParser::new(
        Some(&schema),
        Extensions::all_available(),
        entities::TCComputation::ComputeNow,
    );
    eparser
        .from_json_file(json)
        .unwrap_or_else(|e| panic!("error parsing entities in {}: {e}", &test.entities))
}

// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
fn parse_entity_uid(json: JsonValueWithNoDuplicateKeys, error_string: String) -> EntityUID {
    let parsed: entities::EntityUidJson =
        serde_json::from_value(json.into()).unwrap_or_else(|e| panic!("{}: {e}", error_string));
    parsed
        .into_euid(|| JsonDeserializationErrorContext::EntityUid)
        .unwrap_or_else(|e| panic!("{}: {e}", error_string))
}

/// Given a `JsonRequest`, parse (and optionally validate) the provided request.
/// # Panics
/// On failure to parse or validate request.
// PANIC SAFETY this is testing code
#[allow(clippy::panic)]
pub fn parse_request_from_test(
    json_request: &JsonRequest,
    schema: &ValidatorSchema,
    test_name: &str,
) -> Request {
    let principal = json_request
        .principal
        .clone()
        .map(|json| {
            let error_string = format!(
                "Failed to parse principal for request \"{}\" in {}",
                json_request.desc, test_name
            );
            parse_entity_uid(json, error_string)
        })
        .unwrap_or(EntityUID::unspecified_from_eid(Eid::new("principal")));
    let action = json_request
        .action
        .clone()
        .map(|json| {
            let error_string = format!(
                "Failed to parse action for request \"{}\" in {}",
                json_request.desc, test_name
            );
            parse_entity_uid(json, error_string)
        })
        .unwrap_or(EntityUID::unspecified_from_eid(Eid::new("action")));
    let resource = json_request
        .resource
        .clone()
        .map(|json| {
            let error_string = format!(
                "Failed to parse resource for request \"{}\" in {}",
                json_request.desc, test_name
            );
            parse_entity_uid(json, error_string)
        })
        .unwrap_or(EntityUID::unspecified_from_eid(Eid::new("resource")));
    let context_schema = cedar_policy_validator::context_schema_for_action(schema, &action)
        .unwrap_or_else(|| {
            panic!(
                "Unknown action {} for request \"{}\" in {}",
                action, json_request.desc, test_name
            )
        });
    let context =
        entities::ContextJsonParser::new(Some(&context_schema), Extensions::all_available())
            .from_json_value(json_request.context.clone().into())
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to parse context for request \"{}\" in {}: {e}",
                    json_request.desc, test_name
                )
            });
    Request::new(
        (principal, None),
        (action, None),
        (resource, None),
        context,
        if json_request.enable_request_validation {
            Some(schema)
        } else {
            None
        },
        Extensions::all_available(),
    )
    .unwrap_or_else(|e| {
        panic!(
            "error validating request \"{}\" in {}: {e}",
            json_request.desc, test_name
        )
    })
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
    test_impl: &impl CedarTestImplementation,
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

    let validation_result = test_impl
        .validate(&schema, &policies, ValidationMode::default().into())
        .expect("Validation failed");
    if test.should_validate {
        assert!(
            validation_result.validation_passed(),
            "Unexpected validation errors in {test_name}: {:?}",
            validation_result.errors
        );
    } else {
        assert!(
            !validation_result.validation_passed(),
            "Expected that validation would fail in {test_name}, but it did not.",
        );
    }

    for json_request in test.requests {
        let request = parse_request_from_test(&json_request, &schema, &test_name);
        let response = test_impl
            .is_authorized(&request, &policies, &entities)
            .expect("Authorization failed");
        // check decision
        assert_eq!(
            response.response.decision(),
            json_request.decision,
            "test {test_name} failed for request \"{}\": unexpected decision",
            &json_request.desc
        );
        // check reason
        let reason: HashSet<PolicyId> = response.response.diagnostics().reason().cloned().collect();
        assert_eq!(
            reason,
            json_request.reason.into_iter().collect(),
            "test {test_name} failed for request \"{}\": unexpected reason",
            &json_request.desc
        );
        // check errors, if applicable
        // for now, the integration tests only support the `PolicyIds` comparison mode
        if matches!(
            test_impl.error_comparison_mode(),
            ErrorComparisonMode::PolicyIds
        ) {
            let errors: HashSet<PolicyId> = response
                .response
                .diagnostics()
                .errors()
                .map(|err| PolicyId::from_str(err).unwrap())
                .collect();
            assert_eq!(
                errors,
                json_request.errors.into_iter().collect(),
                "test {test_name} failed for request \"{}\": unexpected errors",
                &json_request.desc
            );
        }
    }
}

/// Specialization of `perform_integration_test_from_json_custom` that performs
/// an integration test on the `cedar-policy` API.
pub fn perform_integration_test_from_json(jsonfile: impl AsRef<Path>) {
    let rust_impl = RustEngine::new();
    perform_integration_test_from_json_custom(jsonfile, &rust_impl);
}
