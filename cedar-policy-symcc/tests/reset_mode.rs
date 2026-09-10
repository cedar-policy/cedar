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

#![expect(clippy::unwrap_used, reason = "unit test code")]

//! Tests for `ResetMode`.

use cedar_policy::{PolicySet, Schema, Validator};
use cedar_policy_symcc::{
    err::Error, solver::WriterSolver, CedarSymCompiler, CompiledPolicySet, ResetMode,
};
use cool_asserts::assert_matches;

mod utils;
use utils::Environments;

const SCHEMA: &str = r#"
entity User;
entity Photo;
action view appliesTo {
    principal: [User],
    resource: [Photo],
    context: { admin: Bool },
};
"#;

/// Always-allows is nontrivial for this policyset, so we actually encode a
/// query and call the solver
const POLICIES: &str = r#"permit(principal, action, resource) when { context.admin };"#;

fn setup(schema: &Schema) -> (Environments<'_>, PolicySet) {
    let envs = Environments::new(schema, "User", "Action::\"view\"", "Photo");
    let pset = utils::pset_from_text(POLICIES, &Validator::new(schema.clone()));
    (envs, pset)
}

/// Runs `check_always_allows_opt()` (which goes through `check_unsat_asserts()`)
/// against a `WriterSolver` and returns the SMTLib script it produced.
///
/// `WriterSolver` always answers `Unknown`, so the query errors with
/// `SolverUnknown`; only the script matters here.
async fn script_for_check_unsat(reset_mode: ResetMode) -> String {
    let schema = utils::schema_from_cedarstr(SCHEMA);
    let (envs, pset) = setup(&schema);
    let compiled = CompiledPolicySet::compile(&pset, &envs.req_env, &schema).unwrap();
    let mut compiler = CedarSymCompiler::new(WriterSolver { w: Vec::new() })
        .unwrap()
        .with_reset_mode(reset_mode);
    assert_eq!(compiler.reset_mode(), reset_mode);
    assert_matches!(
        compiler.check_always_allows_opt(&compiled).await,
        Err(Error::SolverUnknown)
    );
    String::from_utf8(std::mem::take(&mut compiler.solver_mut().w)).unwrap()
}

/// Like `script_for_check_unsat()`, but for the counterexample path, which goes
/// through `check_sat_asserts()`
async fn script_for_check_sat(reset_mode: ResetMode) -> String {
    let schema = utils::schema_from_cedarstr(SCHEMA);
    let (envs, pset) = setup(&schema);
    let compiled = CompiledPolicySet::compile(&pset, &envs.req_env, &schema).unwrap();
    let mut compiler = CedarSymCompiler::new(WriterSolver { w: Vec::new() })
        .unwrap()
        .with_reset_mode(reset_mode);
    assert_matches!(
        compiler
            .check_always_allows_with_counterexample_opt(&compiled)
            .await,
        Err(Error::SolverUnknown)
    );
    String::from_utf8(std::mem::take(&mut compiler.solver_mut().w)).unwrap()
}

/// `(reset)` is the first line, and is a command
#[track_caller]
fn assert_starts_with_reset_command(script: &str) {
    assert_eq!(script.lines().next(), Some("(reset)"), "script:\n{script}");
}

/// `(reset)` is the first line, and appears only as a comment
#[track_caller]
fn assert_starts_with_reset_comment(script: &str) {
    assert_eq!(
        script.lines().next(),
        Some("; (reset)"),
        "script:\n{script}"
    );
    assert!(
        !script.lines().any(|line| line.trim() == "(reset)"),
        "expected no `(reset)` command, script:\n{script}"
    );
}

/// `new()` alone, without `with_reset_mode()`, emits the `(reset)` command
#[tokio::test]
async fn check_unsat_default_emits_reset_command() {
    let schema = utils::schema_from_cedarstr(SCHEMA);
    let (envs, pset) = setup(&schema);
    let compiled = CompiledPolicySet::compile(&pset, &envs.req_env, &schema).unwrap();
    let mut compiler = CedarSymCompiler::new(WriterSolver { w: Vec::new() }).unwrap();
    assert_eq!(compiler.reset_mode(), ResetMode::Emit);
    assert_matches!(
        compiler.check_always_allows_opt(&compiled).await,
        Err(Error::SolverUnknown)
    );
    let script = String::from_utf8(std::mem::take(&mut compiler.solver_mut().w)).unwrap();
    assert_starts_with_reset_command(&script);
}

#[tokio::test]
async fn check_unsat_emit_mode() {
    assert_starts_with_reset_command(&script_for_check_unsat(ResetMode::Emit).await);
}

#[tokio::test]
async fn check_unsat_comment_mode() {
    assert_starts_with_reset_comment(&script_for_check_unsat(ResetMode::Comment).await);
}

#[tokio::test]
async fn check_sat_emit_mode() {
    assert_starts_with_reset_command(&script_for_check_sat(ResetMode::Emit).await);
}

#[tokio::test]
async fn check_sat_comment_mode() {
    assert_starts_with_reset_comment(&script_for_check_sat(ResetMode::Comment).await);
}

/// The reset mode must not affect the rest of the script
#[tokio::test]
async fn comment_mode_changes_only_the_reset_line() {
    for (emit, comment) in [
        (
            script_for_check_unsat(ResetMode::Emit).await,
            script_for_check_unsat(ResetMode::Comment).await,
        ),
        (
            script_for_check_sat(ResetMode::Emit).await,
            script_for_check_sat(ResetMode::Comment).await,
        ),
    ] {
        assert_eq!(
            emit.replacen("(reset)", "; (reset)", 1),
            comment,
            "scripts differ in more than the `(reset)` line"
        );
    }
}
