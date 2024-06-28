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

//! Helper code to run Cedar integration tests through the CLI

#![cfg(feature = "integration-testing")]
// PANIC SAFETY tests
#![allow(clippy::expect_used)]
// PANIC SAFETY tests
#![allow(clippy::panic)]

mod corpus_tests;
#[cfg(feature = "decimal")]
mod decimal;
mod example_use_cases;
#[cfg(feature = "ipaddr")]
mod ip;
mod multi;

use cedar_policy::Decision;
use cedar_policy::EntityUid;
use cedar_testing::integration_testing::JsonTest;
use std::env;
use std::path::{Path, PathBuf};

fn value_to_euid_string(v: serde_json::Value) -> Result<String, impl miette::Diagnostic> {
    EntityUid::from_json(v).map(|euid| euid.to_string())
}

/// For relative paths, return the absolute path, assuming that the path
/// is relative to the root of the CedarIntegrationTests repo.
/// For absolute paths, return them unchanged.
// PANIC SAFETY: this is all test code
#[allow(clippy::expect_used)]
fn resolve_integration_test_path(path: impl AsRef<Path>) -> PathBuf {
    if path.as_ref().is_relative() {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR")
            .expect("`CARGO_MANIFEST_DIR` should be set by Cargo at build-time");
        let mut full_path: PathBuf = [&manifest_dir, "..", "cedar-integration-tests"]
            .iter()
            .collect();
        full_path.push(path);
        full_path
    } else {
        path.as_ref().into()
    }
}

/// Given the filename of a JSON file describing an integration test, perform
/// the test.
///
/// Relative paths are assumed to be relative to the root of the
/// cedar-integration-tests folder.
/// Absolute paths are handled without modification.
// PANIC SAFETY: this is all test code
#[allow(clippy::unwrap_used)]
// PANIC SAFETY: this is all test code
#[allow(clippy::expect_used)]
fn perform_integration_test_from_json(jsonfile: impl AsRef<Path>) {
    let jsonfile = resolve_integration_test_path(jsonfile);
    let jsonstr = std::fs::read_to_string(&jsonfile)
        .unwrap_or_else(|e| panic!("error reading from file {}: {}", jsonfile.display(), e));
    let test: JsonTest = serde_json::from_str(&jsonstr)
        .unwrap_or_else(|e| panic!("error parsing {}: {e}", jsonfile.display()));
    let policy_file = resolve_integration_test_path(&test.policies);
    let entity_file = resolve_integration_test_path(&test.entities);
    let schema_file = resolve_integration_test_path(&test.schema);

    for json_request in test.requests.into_iter() {
        let validation_cmd = assert_cmd::Command::cargo_bin("cedar")
            .expect("bin exists")
            .arg("validate")
            .arg("--schema")
            .arg(&schema_file)
            .arg("--policies")
            .arg(&policy_file)
            .arg("--schema-format")
            .arg("human")
            .assert()
            .append_context("validation", json_request.description.clone());

        if test.should_validate {
            validation_cmd.success(); // assert it succeeded
        } else {
            validation_cmd.code(3); // assert that validation failed
        }

        // Integration test format provides context JSON object
        let mut ctx_file = tempfile::NamedTempFile::new().expect("failed to create tempfile");

        serde_json::to_writer_pretty(&mut ctx_file, &json_request.context)
            .expect("failed to write to tempfile");

        let mut entity_args = Vec::new();
        entity_args.push("--principal".to_string());
        entity_args.push(value_to_euid_string(json_request.principal.into()).unwrap());
        entity_args.push("--resource".to_string());
        entity_args.push(value_to_euid_string(json_request.resource.into()).unwrap());
        entity_args.push("--action".to_string());
        entity_args.push(value_to_euid_string(json_request.action.into()).unwrap());
        if !json_request.validate_request {
            entity_args.push("--request-validation=false".to_string());
        }

        let authorize_cmd = assert_cmd::Command::cargo_bin("cedar")
            .expect("bin exists")
            .arg("authorize")
            .args(entity_args)
            .arg("--context")
            .arg(ctx_file.path())
            .arg("--policies")
            .arg(&policy_file)
            .arg("--entities")
            .arg(&entity_file)
            .arg("--schema")
            .arg(&schema_file)
            .arg("--schema-format")
            .arg("human")
            .arg("--verbose") // so that reasons are displayed
            .assert()
            .append_context("authorization", json_request.description.clone());

        let authorize_cmd = match json_request.decision {
            Decision::Deny => authorize_cmd.code(2),
            Decision::Allow => authorize_cmd.success(),
        };

        let output = String::from_utf8(authorize_cmd.get_output().stdout.clone())
            .expect("output should be valid UTF-8");

        for error in json_request.errors {
            assert!(
                output.contains(&error.to_string()),
                "test {} failed for request \"{}\": output does not contain expected error {error:?}.\noutput was: {output}\nstderr was: {}",
                jsonfile.display(),
                &json_request.description,
                String::from_utf8(authorize_cmd.get_output().stderr.clone()).expect("stderr should be valid UTF-8"),
            );
        }

        if json_request.reason.is_empty() {
            assert!(
                output.contains("no policies applied to this request"),
                "test {} failed for request \"{}\": output does not contain the string \"no policies applied to this request\", as expected.\noutput was: {output}\nstderr was: {}",
                jsonfile.display(),
                &json_request.description,
                String::from_utf8(authorize_cmd.get_output().stderr.clone()).expect("stderr should be valid UTF-8"),
            );
        } else {
            assert!(output.contains("this decision was due to the following policies"));
            for reason in &json_request.reason {
                assert!(
                    output.contains(&reason.to_string()),
                    "test {} failed for request \"{}\": output does not contain the reason string {reason:?}.\noutput was: {output}\nstderr was: {}",
                    jsonfile.display(),
                    &json_request.description,
                    String::from_utf8(authorize_cmd.get_output().stderr.clone()).expect("stderr should be valid UTF-8"),
                );
            }
        };
    }
}
