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
        .arg("never-errors")
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
        .arg("always-matches")
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
        .arg("never-matches")
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
        .arg("never-errors")
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
        .arg("matches-equivalent")
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
        .arg("matches-implies")
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
        .arg("matches-disjoint")
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
        .arg("always-allows")
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
        .arg("always-denies")
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
        .arg("equivalent")
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
        .arg("implies")
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
        .arg("implies")
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
        .arg("disjoint")
        .arg("--policies1")
        .arg(ps1.path())
        .arg("--policies2")
        .arg(ps2.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("VERIFIED"));
}
