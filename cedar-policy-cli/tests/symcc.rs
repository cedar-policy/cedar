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

//! Integration tests for the `cedar symcc` subcommands.
//!
//! These tests require CVC5 to be available (via `CVC5` env var or in PATH)
//! and the `analyze` feature to be enabled.
//!
//! Test data is inspired by `cedar-policy-symcc/tests/integration_tests.rs`.

#![cfg(feature = "analyze")]
#![allow(clippy::expect_used, reason = "tests")]
#![allow(clippy::unwrap_used, reason = "tests")]

use assert_cmd::cargo;
use predicates::prelude::PredicateBooleanExt;
use std::io::Write;
use tempfile::NamedTempFile;

const SAMPLE_SCHEMA: &str = r#"
entity Account;
entity Identity {
    account: Account
};
entity Thing in Account {
    owner: Identity,
    description: String,
    private: Bool
};
action view appliesTo {
    principal: [Identity],
    resource: [Thing],
    context: {
        n1: String
    }
};
"#;

const PERMIT_ALL: &str = "permit(principal, action, resource);";

const NEVER_MATCHES_POLICY: &str = r#"permit(principal, action, resource) when { 1 > 2 };"#;

/// Helper: write content to a temp file and return it (keeps file alive).
fn write_temp(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

// ---- Single-policy primitives ----

#[test]
fn test_never_errors_permit_all() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("never-errors")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_always_matches_permit_all() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("always-matches")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_never_matches_impossible_policy() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(NEVER_MATCHES_POLICY);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("never-matches")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_single_policy_rejects_multi_policy() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let multi = write_temp(
        "permit(principal, action, resource);\npermit(principal, action, resource) when { true };",
    );

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("never-errors")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(multi.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains("Expected exactly one policy"));
}

// ---- Two-policy comparison primitives ----

#[test]
fn test_matches_equivalent_same_policy() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let p1 = write_temp(PERMIT_ALL);
    let p2 = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("matches-equivalent")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policy1")
        .arg(p1.path())
        .arg("--policy2")
        .arg(p2.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_matches_implies_permit_all_implies_permit_all() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let p1 = write_temp(PERMIT_ALL);
    let p2 = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("matches-implies")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policy1")
        .arg(p1.path())
        .arg("--policy2")
        .arg(p2.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_matches_disjoint_permit_all_vs_never_matches() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let p1 = write_temp(PERMIT_ALL);
    let p2 = write_temp(NEVER_MATCHES_POLICY);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("matches-disjoint")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policy1")
        .arg(p1.path())
        .arg("--policy2")
        .arg(p2.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

// ---- Policy-set primitives ----

#[test]
fn test_always_allows_permit_all() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("always-allows")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_always_denies_empty_set() {
    let schema = write_temp(SAMPLE_SCHEMA);
    // An empty policy set (no policies) should always deny
    let policy = write_temp("");

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("always-denies")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_equivalent_same_policy_set() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let ps1 = write_temp(PERMIT_ALL);
    let ps2 = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("equivalent")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies1")
        .arg(ps1.path())
        .arg("--policies2")
        .arg(ps2.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_implies_permit_all_implies_itself() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let ps1 = write_temp(PERMIT_ALL);
    let ps2 = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("implies")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies1")
        .arg(ps1.path())
        .arg("--policies2")
        .arg(ps2.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_implies_never_matches_implies_permit_all() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let ps1 = write_temp(NEVER_MATCHES_POLICY);
    let ps2 = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("implies")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies1")
        .arg(ps1.path())
        .arg("--policies2")
        .arg(ps2.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_disjoint_permit_vs_empty() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let ps1 = write_temp(PERMIT_ALL);
    // Empty policy set denies everything, so it's disjoint from permit-all
    let ps2 = write_temp("");

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("disjoint")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies1")
        .arg(ps1.path())
        .arg("--policies2")
        .arg(ps2.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_nonexistent_cvc5_path_error() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("never-errors")
        .arg("--cvc5-path")
        .arg("/nonexistent/path/to/cvc5")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "CVC5 solver not found or failed to start at '/nonexistent/path/to/cvc5'",
        ));
}

// ---- Error condition tests ----

const TWO_POLICIES: &str =
    "permit(principal, action, resource);\npermit(principal, action, resource) when { true };";

#[test]
fn test_always_matches_rejects_multi_policy() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let multi = write_temp(TWO_POLICIES);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("always-matches")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(multi.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains("Expected exactly one policy"));
}

#[test]
fn test_never_matches_rejects_multi_policy() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let multi = write_temp(TWO_POLICIES);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("never-matches")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(multi.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains("Expected exactly one policy"));
}

#[test]
fn test_never_errors_rejects_empty_policy() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let empty = write_temp("");

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("never-errors")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(empty.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Expected exactly one policy in --policies, found 0",
        ));
}

#[test]
fn test_matches_equivalent_rejects_multi_policy_in_policy1() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let multi = write_temp(TWO_POLICIES);
    let single = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("matches-equivalent")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policy1")
        .arg(multi.path())
        .arg("--policy2")
        .arg(single.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Expected exactly one policy in --policy1",
        ));
}

#[test]
fn test_matches_implies_rejects_multi_policy_in_policy2() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let single = write_temp(PERMIT_ALL);
    let multi = write_temp(TWO_POLICIES);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("matches-implies")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policy1")
        .arg(single.path())
        .arg("--policy2")
        .arg(multi.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Expected exactly one policy in --policy2",
        ));
}

#[test]
fn test_matches_disjoint_rejects_multi_policy_in_both() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let multi = write_temp(TWO_POLICIES);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("matches-disjoint")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policy1")
        .arg(multi.path())
        .arg("--policy2")
        .arg(multi.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Expected exactly one policy in --policy1",
        ));
}

// ---- Tests with --no-counterexample (exercises the bool-only code path) ----

#[test]
fn test_never_errors_no_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("never-errors")
        .arg("--no-counterexample")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_always_matches_no_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("always-matches")
        .arg("--no-counterexample")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_never_matches_no_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(NEVER_MATCHES_POLICY);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("never-matches")
        .arg("--no-counterexample")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_matches_equivalent_no_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("matches-equivalent")
        .arg("--no-counterexample")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policy1")
        .arg(policy.path())
        .arg("--policy2")
        .arg(policy.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_always_allows_no_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("always-allows")
        .arg("--no-counterexample")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

#[test]
fn test_equivalent_no_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("equivalent")
        .arg("--no-counterexample")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies1")
        .arg(policy.path())
        .arg("--policies2")
        .arg(policy.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}

// ---- DOES NOT HOLD tests (with counterexample, the default) ----

#[test]
fn test_always_matches_does_not_hold_with_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    // A policy that doesn't always match
    let policy = write_temp(NEVER_MATCHES_POLICY);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("always-matches")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .code(5)
        .stdout(predicates::str::contains("DOES NOT HOLD"))
        .stdout(predicates::str::contains("Counterexample found"));
}

#[test]
fn test_never_matches_does_not_hold_with_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    // permit(principal, action, resource) always matches, so "never matches" does not hold
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("never-matches")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .code(5)
        .stdout(predicates::str::contains("DOES NOT HOLD"))
        .stdout(predicates::str::contains("Counterexample found"));
}

#[test]
fn test_always_denies_does_not_hold_with_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    // A permit-all policy set clearly doesn't always deny
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("always-denies")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .code(5)
        .stdout(predicates::str::contains("DOES NOT HOLD"))
        .stdout(predicates::str::contains("Counterexample found"));
}

#[test]
fn test_matches_equivalent_does_not_hold_with_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy1 = write_temp(PERMIT_ALL);
    let policy2 = write_temp(NEVER_MATCHES_POLICY);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("matches-equivalent")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policy1")
        .arg(policy1.path())
        .arg("--policy2")
        .arg(policy2.path())
        .assert()
        .code(5)
        .stdout(predicates::str::contains("DOES NOT HOLD"))
        .stdout(predicates::str::contains("Counterexample found"));
}

// ---- DOES NOT HOLD tests (without counterexample) ----

#[test]
fn test_always_matches_does_not_hold_no_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(NEVER_MATCHES_POLICY);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("always-matches")
        .arg("--no-counterexample")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .code(5)
        .stdout(predicates::str::contains("DOES NOT HOLD"))
        .stdout(predicates::str::contains("Counterexample found").not());
}

#[test]
fn test_never_matches_does_not_hold_no_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("never-matches")
        .arg("--no-counterexample")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .code(5)
        .stdout(predicates::str::contains("DOES NOT HOLD"))
        .stdout(predicates::str::contains("Counterexample found").not());
}

#[test]
fn test_always_denies_does_not_hold_no_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("always-denies")
        .arg("--no-counterexample")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .code(5)
        .stdout(predicates::str::contains("DOES NOT HOLD"))
        .stdout(predicates::str::contains("Counterexample found").not());
}

#[test]
fn test_warn_if_contains_templates_single_policy_set() {
    let schema = write_temp(SAMPLE_SCHEMA);
    // A policy set with one template (uses ?principal slot) and one static policy
    let policy = write_temp(
        r#"
        permit(principal, action, resource);
        forbid(principal == ?principal, action, resource);
        "#,
    );

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("always-allows")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .success()
        .stderr(predicates::str::contains(
            "policy set contains 1 policy template(s)",
        ));
}

#[test]
fn test_no_template_warning_without_templates() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("always-allows")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .assert()
        .success()
        .stderr(predicates::str::contains("will be ignored by analysis").not());
}

#[test]
fn test_error_if_contains_templates_single_policy() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(
        r#"
        permit(principal, action, resource);
        forbid(principal == ?principal, action, resource);
        "#,
    );

    let output = cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("always-matches")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .output()
        .expect("failed to run cedar");

    assert!(!output.status.success(), "expected non-zero exit code");
    insta::assert_snapshot!(String::from_utf8_lossy(&output.stderr), @"
    × Analysis failed
    ╰─▶ Expected exactly one static policy in --policies, found 1 policy
        template(s)
    ");
}

#[test]
fn test_warn_if_contains_templates_two_policy_sets() {
    let schema = write_temp(SAMPLE_SCHEMA);
    // First policy set has a template
    let ps1 = write_temp(
        r#"
        permit(principal, action, resource);
        permit(principal == ?principal, action, resource);
        "#,
    );
    // Second policy set has no templates
    let ps2 = write_temp(PERMIT_ALL);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("equivalent")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies1")
        .arg(ps1.path())
        .arg("--policies2")
        .arg(ps2.path())
        .assert()
        .success()
        .stderr(predicates::str::contains(
            "first policy set contains 1 policy template(s)",
        ));
}

#[test]
fn test_equivalent_does_not_hold_no_counterexample() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy1 = write_temp(PERMIT_ALL);
    let policy2 = write_temp(NEVER_MATCHES_POLICY);

    cargo::cargo_bin_cmd!("cedar")
        .arg("symcc")
        .arg("equivalent")
        .arg("--no-counterexample")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies1")
        .arg(policy1.path())
        .arg("--policies2")
        .arg(policy2.path())
        .assert()
        .code(5)
        .stdout(predicates::str::contains("DOES NOT HOLD"))
        .stdout(predicates::str::contains("Counterexample found").not());
}

#[test]
fn validation_error_pretty_print() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp("permit(principal, action, resource) when { resource.nonexistent };");

    let output = cargo::cargo_bin_cmd!("cedar")
        .env("NO_COLOR", "1")
        .arg("symcc")
        .arg("never-errors")
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--schema")
        .arg(schema.path())
        .arg("--schema-format")
        .arg("cedar")
        .arg("--policies")
        .arg(policy.path())
        .output()
        .expect("failed to run cedar");

    assert!(!output.status.success(), "expected non-zero exit code");
    insta::assert_snapshot!(String::from_utf8_lossy(&output.stderr), @"
      × Analysis failed
      ├─▶ Failed to compile policy
      ╰─▶ input policy (set) is not well typed with respect to the schema

    Error: 
      × for policy `policy0`, attribute `nonexistent` on entity type `Thing` not
      │ found
       ╭────
     1 │ permit(principal, action, resource) when { resource.nonexistent };
       ·                                            ────────────────────
       ╰────
      help: did you mean `description`?
    ");
}

#[test]
fn test_cvc5_not_found_error() {
    let schema = write_temp(SAMPLE_SCHEMA);
    let policy = write_temp(PERMIT_ALL);

    // No --cvc5-path, no CVC5 env var, and a PATH with no cvc5 on it.
    let output = cargo::cargo_bin_cmd!("cedar")
        .env("NO_COLOR", "1")
        .env_remove("CVC5")
        .env("PATH", "/nonexistent")
        .arg("symcc")
        .arg("never-errors")
        .arg("--schema")
        .arg(schema.path())
        .arg("--principal-type")
        .arg("Identity")
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource-type")
        .arg("Thing")
        .arg("--policies")
        .arg(policy.path())
        .output()
        .expect("failed to run cedar");

    assert_eq!(output.status.code(), Some(1));
    insta::assert_snapshot!(String::from_utf8_lossy(&output.stderr), @"
    × Analysis failed
    ├─▶ CVC5 solver not found or failed to start
    ├─▶ IO error during a solver operation
    ╰─▶ No such file or directory (os error 2)
    help: install cvc5 <https://github.com/cvc5/cvc5> and make it available via
          --cvc5-path, the CVC5 environment variable, or `cvc5` on your PATH
    ");
}
