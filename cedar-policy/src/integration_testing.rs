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
//!
//! Cedar integration tests are shared among multiple interfaces. The files for
//! the tests can be found in the `CedarIntegrationTests` package. The helper
//! code in this file is used for two of those interfaces: the API in this
//! `Cedar` package, and a special integration test in the `CedarDRT` package
//! that uses the definitional implementation via `CustomCedarImpl`.

// This is test code that is under `src/` only so that it can be shared between
// packages, so it's appropriate to exclude it from coverage.
//
// GRCOV_STOP_COVERAGE

// PANIC SAFETY: This module is used only for testing.
#![allow(clippy::unwrap_used)]
// PANIC SAFETY: This module is used only for testing.
#![allow(clippy::expect_used)]

use crate::{
    Authorizer, Context, Decision, Entities, EntityUid, EvaluationError, Policy, PolicyId,
    PolicySet, Request, Response, Schema, ValidationMode, Validator,
};
use serde::Deserialize;
use std::{
    env,
    path::{Path, PathBuf},
    str::FromStr,
};

/// JSON representation of our integration test file format
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonTest {
    /// Filename of the policies to use (in pure Cedar syntax)
    policies: String,
    /// Filename of a JSON file representing the entity hierarchy
    entities: String,
    /// Filename of a JSON file containing the schema.
    schema: String,
    /// Whether the given policies are expected to pass the validator with this
    /// schema, or not
    should_validate: bool,
    /// Requests to perform on that data, along with their expected results
    /// Alias for backwards compatibility
    #[serde(alias = "queries")]
    requests: Vec<JsonRequest>,
}

/// JSON representation of a single request, along with its expected result,
/// in our integration test file format
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRequest {
    /// Description for the request
    desc: String,
    /// Principal for the request, in either explicit or implicit `__entity` form
    ///
    /// Examples:
    /// * `{ "__entity": { "type": "User", "id": "123abc" } }`
    /// * `{ "type": "User", "id": "123abc" }`
    #[serde(default)]
    principal: Option<serde_json::Value>,
    /// Action for the request, in either explicit or implicit `__entity` form
    ///
    /// Examples:
    /// * `{ "__entity": { "type": "Action", "id": "view" } }`
    /// * `{ "type": "Action", "id": "view" }`
    #[serde(default)]
    action: Option<serde_json::Value>,
    /// Resource for the request, in either explicit or implicit `__entity` form
    ///
    /// Examples:
    /// * `{ "__entity": { "type": "User", "id": "123abc" } }`
    /// * `{ "type": "User", "id": "123abc" }`
    #[serde(default)]
    resource: Option<serde_json::Value>,
    /// Context for the request. This should be a JSON object, not any other kind
    /// of JSON value
    context: serde_json::Value,
    /// Expected decision for the request
    decision: Decision,
    /// Expected "reasons" for the request
    reasons: Vec<String>,
    /// Expected error/warning messages for the request
    errors: Vec<String>,
}

/// For relative paths, return the absolute path, assuming that the path
/// is relative to the root of the `CedarIntegrationTests` repo.
/// For absolute paths, return them unchanged.
pub fn resolve_integration_test_path(path: impl AsRef<Path>) -> PathBuf {
    if path.as_ref().is_relative() {
        let mut full_path = PathBuf::new();
        let manifest_dir = env::var("CARGO_MANIFEST_DIR")
            .expect("`CARGO_MANIFEST_DIR` should be set by Cargo at build-time.");
        full_path.push(manifest_dir.clone());
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
    ) -> Response;

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

/// Given the filename of a JSON file describing an integration test, perform
/// the test. If a custom Cedar implementation is provided, then use it for the
/// test, otherwise perform the test on the `Cedar` API.
///
/// Relative paths are assumed to be relative to the root of the
/// `CedarIntegrationTests` repo.
/// Absolute paths are handled without modification.
/// # Panics
/// When integration test data cannot be found
#[allow(clippy::too_many_lines)]
pub fn perform_integration_test_from_json_custom(
    jsonfile: impl AsRef<Path>,
    custom_impl_opt: Option<&dyn CustomCedarImpl>,
) {
    let jsonfile = resolve_integration_test_path(jsonfile);
    eprintln!("File path: {jsonfile:?}");
    let jsonstr = std::fs::read_to_string(jsonfile.as_path())
        .unwrap_or_else(|e| panic!("error reading from file {}: {e}", jsonfile.display()));
    let test: JsonTest = serde_json::from_str(&jsonstr)
        .unwrap_or_else(|e| panic!("error parsing {}: {e}", jsonfile.display()));
    let policy_file = resolve_integration_test_path(&test.policies);
    let policies_text = std::fs::read_to_string(policy_file)
        .unwrap_or_else(|e| panic!("error loading policy file {}: {e}", &test.policies));
    //If parsing fails we don't want to quit immediately. Instead we want to check that the parse error corresponds to the original error when running the fuzzer
    let policies_res = PolicySet::from_str(&policies_text);
    if policies_res.is_err() {
        //we may see a failure to parse instead of the orginal error: (see comment at ast/exprs.rs:500)
        //If an expected response is for an error due to a non-existent function call or if e.g.,
        // "isInRange" is used as a function instead of a method
        //(Maybe due to null principal?)
        for json_request in test.requests {
            assert_eq!(
                json_request.decision,
                Decision::Deny,
                "test {} failed for request \"{}\" \n Parse errors should only occur for deny",
                jsonfile.display(),
                &json_request.desc
            );
        }
        return;
    }
    let policies = policies_res
        .unwrap_or_else(|e| panic!("error parsing policy in file {}: {e}", &test.policies));
    let schema_file = resolve_integration_test_path(&test.schema);
    let schema_text = std::fs::read_to_string(schema_file)
        .unwrap_or_else(|e| panic!("error loading schema file {}: {e}", &test.schema));
    let schema = Schema::from_str(&schema_text)
        .unwrap_or_else(|e| panic!("error parsing schema in {}: {e}", &test.schema));
    let entity_file = resolve_integration_test_path(&test.entities);
    let entities_json = std::fs::OpenOptions::new()
        .read(true)
        .open(entity_file)
        .unwrap_or_else(|e| panic!("error opening entity file {}: {e}", &test.entities));
    let entities = Entities::from_json_file(&entities_json, Some(&schema))
        .unwrap_or_else(|e| panic!("error parsing entities in {}: {e}", &test.entities));

    let validation_result = if let Some(custom_impl) = custom_impl_opt {
        custom_impl.validate(schema.clone().0, &policies.ast)
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
            "Unexpected validation errors in {}: {}",
            jsonfile.display(),
            validation_result.validation_errors_debug
        );
    } else {
        assert!(
            !validation_result.validation_passed,
            "Expected that validation would fail in {}, but it did not.",
            jsonfile.display(),
        );
    }

    for json_request in test.requests {
        let principal = json_request.principal.map(|json| {
            EntityUid::from_json(json).unwrap_or_else(|e| {
                panic!(
                    "Failed to parse principal for request \"{}\" in {}: {e}",
                    json_request.desc,
                    jsonfile.display()
                )
            })
        });
        let action = json_request.action.map(|json| {
            EntityUid::from_json(json).unwrap_or_else(|e| {
                panic!(
                    "Failed to parse action for request \"{}\" in {}: {e}",
                    json_request.desc,
                    jsonfile.display()
                )
            })
        });
        let resource = json_request.resource.map(|json| {
            EntityUid::from_json(json).unwrap_or_else(|e| {
                panic!(
                    "Failed to parse resource for request \"{}\" in {}: {e}",
                    json_request.desc,
                    jsonfile.display()
                )
            })
        });
        let context_schema = action.as_ref().map(|a| (&schema, a));
        let context = Context::from_json_value(json_request.context, context_schema)
            .unwrap_or_else(|e| {
                panic!(
                    "error parsing context for request \"{}\" in {}: {e}",
                    json_request.desc,
                    jsonfile.display()
                )
            });
        let request = Request::new(principal, action, resource, context);
        let response = if let Some(custom_impl) = custom_impl_opt {
            custom_impl.is_authorized(&request.0, &policies.ast, &entities.0)
        } else {
            Authorizer::new().is_authorized(&request, &policies, &entities)
        };
        let expected_response = Response::new(
            json_request.decision,
            json_request
                .reasons
                .into_iter()
                .map(|s| PolicyId::from_str(&s).unwrap())
                .collect(),
            json_request.errors.into_iter().collect(),
        );

        //If an expected response is for an error due to a non-existent function call, we may
        //see a failure to parse instead: (see comment at ast/exprs.rs:500)
        let mut parsing_fn_name: Option<String> = None;
        for e in response.diagnostics().errors() {
            let EvaluationError::StringMessage(msg) = e;
            if msg.contains("poorly formed: invalid syntax, expected function, found") {
                parsing_fn_name = Some(msg.split_whitespace().last().unwrap().to_string());
                break;
            }
        }
        if parsing_fn_name.is_some() {
            //For these tests we must have the same decision and the undefined function when running the fuzzer should be the same when parsing
            assert_eq!(
                response.decision(),
                expected_response.decision(),
                "test {} failed for request \"{}\"",
                jsonfile.display(),
                &json_request.desc
            );

            let mut found_matching_non_existent_fn_fuzzing = false;
            for e in expected_response.diagnostics().errors() {
                let EvaluationError::StringMessage(msg) = e;
                if msg.contains(
                    "error occurred while evaluating policy `policy0`: function does not exist:",
                ) {
                    let fuzzing_fn_name = Some(msg.split_whitespace().last().unwrap().to_string());
                    if parsing_fn_name == fuzzing_fn_name {
                        found_matching_non_existent_fn_fuzzing = true;
                        break;
                    }
                }
            }

            assert!(
                found_matching_non_existent_fn_fuzzing,
                "test {} failed for request \"{}\" \n Non existent function names did not match.",
                jsonfile.display(),
                &json_request.desc
            );
        } else {
            assert_eq!(
                response,
                expected_response,
                "test {} failed for request \"{}\"",
                jsonfile.display(),
                &json_request.desc
            );
        }

        // test that EST roundtrip works for this policy set
        // we can't test that the roundtrip produces the same policies exactly
        // (because the roundtrip is lossy), but we can at least test that it
        // roundtrips without errors
        let ests = policies
            .policies()
            .map(|p| p.to_json().expect("should convert to JSON successfully"));

        PolicySet::from_policies(ests.enumerate().map(|(i, est)| {
            let id = PolicyId::from_str(&format!("policy{i}")).expect("id should be valid");
            Policy::from_json(Some(id), est.clone()).unwrap_or_else(|e| {
                panic!("in test {}, failed to build policy from JSON successfully: {e}\n\ntext policy was:\n{}\n\nJSON policy was: {}\n",
                jsonfile.display(), policies.policies().nth(i).unwrap(), serde_json::to_string_pretty(&est).unwrap())
            })
        }))
        .expect("should convert to PolicySet successfully");
    }
}

/// Specialization of `perform_integration_test_from_json_custom` that performs
/// an integration test on the `Cedar` API.
pub fn perform_integration_test_from_json(jsonfile: impl AsRef<Path>) {
    perform_integration_test_from_json_custom(jsonfile, None);
}
