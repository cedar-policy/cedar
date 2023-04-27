//! Cedar integration tests are stored in the `CedarIntegrationTests`
//! package, and shared among multiple interfaces (Rust bindings, Java bindings,
//! CLI [here], etc).

mod corpus_tests;
mod decimal;
mod example_use_cases_doc;
mod ip;
mod multi;

use cedar_policy::Decision;
use cedar_policy::PolicySet;
use serde::Deserialize;
use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// JSON representation of our integration test file format
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonTest {
    /// Filename of the policies to use (in pure Cedar syntax)
    policies: String,
    /// Filename of a JSON file representing the entity hierarchy
    entities: String,
    /// Filename of a JSON file containing the schema.
    schema: String,
    /// Whether the given policies are expected to pass the validator with this
    /// schema, or not
    should_validate: bool,
    /// Queries to perform on that data, along with their expected results
    queries: Vec<JsonRequest>,
}

/// JSON representation of a single request, along with its expected result,
/// in our integration test file format
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRequest {
    /// Description for the request
    desc: String,
    /// Principal for the request
    #[serde(default)]
    principal: Option<String>,
    /// Action for the request
    #[serde(default)]
    action: Option<String>,
    /// Resource for the request
    #[serde(default)]
    resource: Option<String>,
    /// Context for the request
    context: serde_json::Value,
    /// Expected decision for the request
    decision: Decision,
    /// Expected "reasons" for the request
    reasons: Vec<String>,
    /// Expected error/warning messages for the request
    errors: Vec<String>,
}

/// For relative paths, return the absolute path, assuming that the path
/// is relative to the root of the CedarIntegrationTests repo.
/// For absolute paths, return them unchanged.
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
/// CedarIntegrationTests repo.
/// Absolute paths are handled without modification.
fn perform_integration_test_from_json(jsonfile: impl AsRef<Path>) {
    let jsonfile = resolve_integration_test_path(jsonfile);
    let jsonstr = std::fs::read_to_string(&jsonfile)
        .unwrap_or_else(|e| panic!("error reading from file {}: {}", jsonfile.display(), e));
    let test: JsonTest = serde_json::from_str(&jsonstr)
        .unwrap_or_else(|e| panic!("error parsing {}: {e}", jsonfile.display()));
    let policy_file = resolve_integration_test_path(&test.policies);
    let entity_file = resolve_integration_test_path(&test.entities);
    let schema_file = resolve_integration_test_path(&test.schema);

    for json_request in test.queries.into_iter() {
        //Need to skip over policies that will fail to parse:
        let policies_text = std::fs::read_to_string(policy_file.clone())
            .unwrap_or_else(|e| panic!("error loading policy file {}: {e}", &test.policies));
        let policies_res = PolicySet::from_str(&policies_text);

        if let Err(parse_errs) = policies_res {
            //we may see a failure to parse instead of the original error: (see comment at ast/exprs.rs:500)
            //If an expected answer is for an error due to a non-existent function call or if e.g.,
            // "isInRange" is used as a function instead of a method
            //(Maybe due to null principal?)
            assert_eq!(
             json_request.decision,
             Decision::Deny,
             "test {} failed for request \"{}\" \n Failed to parse policy \n Parse errors should only occur for deny",
             jsonfile.display(),
             &json_request.desc
         );
            let mut error_for_nonexist_fn = false;
            for err_msg in parse_errs.errors_as_strings() {
                if err_msg.contains("poorly formed: invalid syntax, expected function, found") {
                    error_for_nonexist_fn = true;
                    break;
                }
            }
            assert!(
                     error_for_nonexist_fn,
                     "test {} failed for request \"{}\" \n Failed to parse policy \n Parse errors should only occur for undefined functions",
                     jsonfile.display(),
                     &json_request.desc
                 );
            continue;
        };
        let validation_cmd = assert_cmd::Command::cargo_bin("cedar")
            .expect("bin exists")
            .arg("validate")
            .arg("--schema")
            .arg(&schema_file)
            .arg("--policies")
            .arg(&policy_file)
            .assert()
            .append_context("validation", json_request.desc.clone());

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
        if let Some(s) = json_request.principal {
            entity_args.push("--principal".to_string());
            entity_args.push(s);
        }
        if let Some(s) = json_request.resource {
            entity_args.push("--resource".to_string());
            entity_args.push(s);
        }
        if let Some(s) = json_request.action {
            entity_args.push("--action".to_string());
            entity_args.push(s);
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
            .arg("--verbose") // so that reasons are displayed
            .assert()
            .append_context("authorization", json_request.desc.clone());

        let authorize_cmd = match json_request.decision {
            Decision::Deny => authorize_cmd.code(2),
            Decision::Allow => authorize_cmd.success(),
        };

        let output = String::from_utf8(authorize_cmd.get_output().stdout.clone())
            .expect("output should be valid UTF-8");

        for error in &json_request.errors {
            assert!(output.contains(error));
        }

        if json_request.reasons.is_empty() {
            assert!(output.contains("no policies applied to this request"));
        } else {
            assert!(output.contains("this decision was due to the following policies"));
            for reason in &json_request.reasons {
                assert!(output.contains(&reason.escape_debug().to_string()));
            }
        };
    }
}
