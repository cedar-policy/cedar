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

use clap::Args;
use miette::{miette, IntoDiagnostic, Report, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::de::{DeserializeSeed, IntoDeserializer};
use serde::{Deserialize, Deserializer};
use std::collections::BTreeSet;
use std::io::{BufReader, Write};
use std::path::Path;

use cedar_policy::*;

use crate::{CedarExitCode, OptionalSchemaArgs, PoliciesArgs, RequestJSON};

#[derive(Args, Debug)]
pub struct RunTestsArgs {
    /// Policies args (incorporated by reference)
    #[command(flatten)]
    pub policies: PoliciesArgs,
    /// Tests in JSON format
    #[arg(long, value_name = "FILE")]
    pub tests: String,
    #[command(flatten)]
    pub schema: OptionalSchemaArgs,
}

#[derive(Clone, Debug)]
enum TestResult {
    Pass,
    Fail(String),
}

/// Compare the test's expected decision against the actual decision
fn compare_test_decisions(test: &TestCase, ans: &Response) -> TestResult {
    if ans.decision() == test.decision.into() {
        let mut errors = Vec::new();
        let reason = ans.diagnostics().reason().collect::<BTreeSet<_>>();

        // Check that the declared reason is a subset of the actual reason
        let missing_reason = test
            .reason
            .iter()
            .filter(|r| !reason.contains(&PolicyId::new(r)))
            .collect::<Vec<_>>();

        if !missing_reason.is_empty() {
            errors.push(format!(
                "missing reason(s): {}",
                missing_reason
                    .into_iter()
                    .map(|r| format!("`{r}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        // Check that evaluation errors are expected
        let num_errors = ans.diagnostics().errors().count();
        if num_errors != test.num_errors {
            errors.push(format!(
                "expected {} error(s), but got {} runtime error(s){}",
                test.num_errors,
                num_errors,
                if num_errors == 0 {
                    "".to_string()
                } else {
                    format!(
                        ": {}",
                        ans.diagnostics()
                            .errors()
                            .map(|e| e.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                },
            ));
        }

        if errors.is_empty() {
            TestResult::Pass
        } else {
            TestResult::Fail(errors.join("; "))
        }
    } else {
        TestResult::Fail(format!(
            "expected {:?}, got {:?}",
            test.decision,
            ans.decision()
        ))
    }
}

/// Parse the test, validate against schema,
/// and then check the authorization decision
fn run_one_test(
    policies: &PolicySet,
    test: &serde_json::Value,
    validator: Option<&Validator>,
) -> Result<TestResult> {
    let test = CheckedTestCaseSeed(validator.map(Validator::schema))
        .deserialize(test.into_deserializer())
        .into_diagnostic()?;
    if let Some(validator) = validator {
        let val_res = validator.validate(policies, cedar_policy::ValidationMode::Strict);
        if !val_res.validation_passed_without_warnings() {
            return Err(Report::new(val_res).wrap_err("policy set validation failed"));
        }
    }
    let ans = Authorizer::new().is_authorized(&test.request, policies, &test.entities);
    Ok(compare_test_decisions(&test, &ans))
}

fn run_tests_inner(args: &RunTestsArgs) -> Result<CedarExitCode> {
    let policies = args.policies.get_policy_set()?;
    let tests = load_partial_tests(&args.tests)?;
    let validator = args.schema.get_schema()?.map(Validator::new);

    let mut total_fails: usize = 0;

    println!("running {} test(s)", tests.len());
    for test in tests.iter() {
        if let Some(name) = test["name"].as_str() {
            print!("  test {name} ... ");
        } else {
            print!("  test (unnamed) ... ");
        }
        std::io::stdout().flush().into_diagnostic()?;
        match run_one_test(&policies, test, validator.as_ref()) {
            Ok(TestResult::Pass) => {
                println!(
                    "{}",
                    "ok".if_supports_color(owo_colors::Stream::Stdout, |s| s.green())
                );
            }
            Ok(TestResult::Fail(reason)) => {
                total_fails += 1;
                println!(
                    "{}: {}",
                    "fail".if_supports_color(owo_colors::Stream::Stdout, |s| s.red()),
                    reason
                );
            }
            Err(e) => {
                total_fails += 1;
                println!(
                    "{}:\n  {:?}",
                    "error".if_supports_color(owo_colors::Stream::Stdout, |s| s.red()),
                    e
                );
            }
        }
    }

    println!(
        "results: {} {}, {} {}",
        tests.len() - total_fails,
        if total_fails == 0 {
            "passed"
                .if_supports_color(owo_colors::Stream::Stdout, |s| s.green())
                .to_string()
        } else {
            "passed".to_string()
        },
        total_fails,
        if total_fails != 0 {
            "failed"
                .if_supports_color(owo_colors::Stream::Stdout, |s| s.red())
                .to_string()
        } else {
            "failed".to_string()
        },
    );

    Ok(if total_fails != 0 {
        CedarExitCode::Failure
    } else {
        CedarExitCode::Success
    })
}

pub fn run_tests(args: &RunTestsArgs) -> CedarExitCode {
    run_tests_inner(args).unwrap_or_else(|e| {
        println!("{e:?}");
        CedarExitCode::Failure
    })
}

#[derive(Copy, Clone, Debug, Deserialize)]
enum ExpectedDecision {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "deny")]
    Deny,
}

impl From<ExpectedDecision> for Decision {
    fn from(value: ExpectedDecision) -> Self {
        match value {
            ExpectedDecision::Allow => Decision::Allow,
            ExpectedDecision::Deny => Decision::Deny,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct UncheckedTestCase {
    request: RequestJSON,
    entities: serde_json::Value,
    decision: ExpectedDecision,
    reason: Vec<String>,
    num_errors: usize,
}

#[derive(Clone, Debug)]
struct TestCase {
    request: Request,
    entities: Entities,
    decision: ExpectedDecision,
    reason: Vec<String>,
    num_errors: usize,
}

struct CheckedTestCaseSeed<'a>(Option<&'a Schema>);

impl<'de, 'a> DeserializeSeed<'de> for CheckedTestCaseSeed<'a> {
    type Value = TestCase;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let UncheckedTestCase {
            request,
            entities,
            decision,
            reason,
            num_errors,
        } = UncheckedTestCase::deserialize(deserializer)?;

        let principal = request.principal.parse().map_err(|e| {
            serde::de::Error::custom(format!(
                "failed to parse principal `{}`: {}",
                request.principal, e
            ))
        })?;

        let action = request.action.parse().map_err(|e| {
            serde::de::Error::custom(format!(
                "failed to parse action `{}`: {}",
                request.action, e
            ))
        })?;

        let resource = request.resource.parse().map_err(|e| {
            serde::de::Error::custom(format!(
                "failed to parse resource `{}`: {}",
                request.resource, e
            ))
        })?;

        let context = Context::from_json_value(request.context.clone(), None).map_err(|e| {
            serde::de::Error::custom(format!(
                "failed to parse context `{}`: {}",
                request.context, e
            ))
        })?;

        let request = Request::new(principal, action, resource, context, self.0)
            .map_err(|e| serde::de::Error::custom(format!("failed to create request: {e}")))?;

        let entities = Entities::from_json_value(entities, self.0)
            .map_err(|e| serde::de::Error::custom(format!("failed to parse entities: {e}")))?;

        Ok(TestCase {
            request,
            entities,
            decision,
            reason,
            num_errors,
        })
    }
}

/// Load partially parsed tests from a JSON file
/// (as JSON values first without parsing to TestCase)
fn load_partial_tests(tests_filename: impl AsRef<Path>) -> Result<Vec<serde_json::Value>> {
    match std::fs::OpenOptions::new()
        .read(true)
        .open(tests_filename.as_ref())
    {
        Ok(f) => {
            let reader = BufReader::new(f);
            serde_json::from_reader(reader).map_err(|e| {
                miette!(
                    "failed to parse tests from file {}: {e}",
                    tests_filename.as_ref().display()
                )
            })
        }
        Err(e) => Err(e).into_diagnostic().wrap_err_with(|| {
            format!(
                "failed to open test file {}",
                tests_filename.as_ref().display()
            )
        }),
    }
}
