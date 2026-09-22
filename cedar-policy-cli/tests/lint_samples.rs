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

//! Snapshot tests that run the lints over a few sample policy sets and schemas, so
//! a change to any lint's output — or a new lint firing on real policies — shows up
//! as a reviewable diff.
//!
//! The samples are listed explicitly rather than globbed over all of
//! `sample-data/`. What the snapshots detect is a *change in a lint's output*, and a
//! handful of varied inputs detects that as well as thirty near-duplicates do,
//! while keeping one lint's tweak from rewriting scores of files and burying the
//! part of the diff worth reading. The list below covers the distinct code paths:
//! with and without a schema, and the schema linter.
//!
//! Two snapshots per sample:
//!
//! * `default` — the lints that run out of the box, i.e. the default user
//!   experience; and
//! * `additional` — the lints that are *off* by default (all lints minus the
//!   default set), so the opt-in lints are covered too without burying the
//!   default view.
//!
//! A sample with no findings for one of those sets leaves no snapshot on disk, so
//! the absence of a file is itself the expectation — see [`check`].
//!
//! Findings are rendered through miette's no-color graphical handler (the same one
//! the CLI's own error snapshots use) rather than by shelling out to the binary,
//! so the output is deterministic regardless of terminal color detection.
//!
//! Runs only with the `tpe` feature, so the snapshots reflect the full lint set —
//! including the TPE-based lints that [`Linter::lint_with_schema`] runs only when
//! `tpe` is enabled. One snapshot set, always generated with `tpe`.

#![cfg(feature = "tpe")]
#![allow(clippy::expect_used, reason = "tests")]
#![allow(clippy::unwrap_used, reason = "tests")]

use std::path::{Path, PathBuf};
use std::str::FromStr;

use cedar_policy::{Lint, Linter, PolicySet, Schema, SchemaFragment, SchemaLinter};
use miette::{Diagnostic, GraphicalReportHandler, GraphicalTheme};

/// The sample policy sets to lint, relative to `sample-data/`. Between them they
/// cover a policy set linted with a schema (which unlocks the schema-informed and
/// TPE lints), one linted without a schema, and one written to exercise partial
/// evaluation.
const POLICY_SAMPLES: &[&str] = &[
    // A schema-backed set, so `lint_with_schema` and the TPE lints run.
    "sandbox_b/policies_5.cedar",
    // The TPE RFC's policies, which exercise the partial-evaluation lints.
    "tpe_rfc/policies.cedar",
    // No sibling schema, so only the schema-free lints run.
    "tiny_sandboxes/format/unformatted.cedar",
];

/// The sample schemas to lint with the [`SchemaLinter`].
const SCHEMA_SAMPLES: &[&str] = &["sandbox_b/schema.cedarschema"];

/// Render one diagnostic with the no-color graphical handler.
fn render(diag: &dyn Diagnostic) -> String {
    let mut buf = String::new();
    GraphicalReportHandler::new_themed(GraphicalTheme::unicode_nocolor())
        .render_report(&mut buf, diag)
        .expect("failed to render");
    buf
}

/// Join rendered findings into one snapshot body, or `None` when there are none —
/// in which case no snapshot is written, so a file with no findings leaves no
/// snapshot on disk.
fn body(mut findings: Vec<String>) -> Option<String> {
    if findings.is_empty() {
        return None;
    }
    findings.sort();
    Some(findings.join("\n"))
}

/// The absolute path of the sample at `rel` under `sample-data/`.
fn sample_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("sample-data")
        .join(rel)
}

/// The snapshot name for one run: `{set}@{rel}`, with `/` replaced by `__` so the
/// name is a single path component. Insta stores it as
/// `tests/snapshots/lint_samples__{set}@{rel}.snap`.
fn snapshot_name(set: &str, rel: &str) -> String {
    format!("{set}@{}", rel.replace('/', "__"))
}

/// Where insta stores the snapshot named by [`snapshot_name`].
fn snapshot_path(set: &str, rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(format!("lint_samples__{}.snap", snapshot_name(set, rel)))
}

/// Handle one lint run: snapshot the findings when there are any, and *fail* when
/// there are none but a stored snapshot still exists.
///
/// Presence of a snapshot file means "we expect findings here". Insta already
/// fails the other mismatch — findings with no stored snapshot is a new,
/// unreviewed snapshot — so together the two directions are both errors:
///
/// * expected findings (snapshot on disk), found none → this function panics;
/// * found findings, none expected (no snapshot) → insta fails on the new snapshot.
#[track_caller]
fn check(set: &str, rel: &str, findings: Option<String>) {
    match findings {
        Some(rendered) => insta::assert_snapshot!(snapshot_name(set, rel), rendered),
        None => assert!(
            !snapshot_path(set, rel).exists(),
            "no `{set}` lint findings for {rel}, but a snapshot exists at {}; \
             the lints changed — delete the stale snapshot if that is intended",
            snapshot_path(set, rel).display(),
        ),
    }
}

/// The lints that are on by default — the default user experience.
fn default_lints() -> Vec<Lint> {
    Lint::all().filter(|l| l.is_default()).collect()
}

/// The lints that are *off* by default (every lint minus the default set), so the
/// opt-in lints are snapshotted separately from the default view.
fn additional_lints() -> Vec<Lint> {
    Lint::all().filter(|l| !l.is_default()).collect()
}

/// The `schema.cedarschema` sitting next to a policy file, if any.
fn sibling_schema(policy_path: &Path) -> Option<Schema> {
    let candidate = policy_path.with_file_name("schema.cedarschema");
    let src = std::fs::read_to_string(candidate).ok()?;
    Schema::from_cedarschema_str(&src).ok().map(|(s, _)| s)
}

/// Two snapshots per sample policy set — `default` lints and the `additional`
/// (off-by-default) lints — each run with the sibling schema when one exists, so
/// the schema-informed lints run too. A parse failure is rendered rather than
/// panicking, so a sample that stops parsing is a visible diff, not a hard error.
#[test]
fn lint_sample_policies() {
    for rel in POLICY_SAMPLES {
        let path = sample_path(rel);
        let src = std::fs::read_to_string(&path).expect("read policy");
        let pset = match PolicySet::from_str(&src) {
            Ok(p) => p,
            Err(e) => {
                let rendered = format!("(did not parse) {e}");
                check("default", rel, Some(rendered.clone()));
                check("additional", rel, Some(rendered));
                continue;
            }
        };
        let schema = sibling_schema(&path);
        let run = |lints: Vec<Lint>| {
            let linter = Linter::new(lints);
            let result = match &schema {
                Some(schema) => linter.lint_with_schema(&pset, schema),
                None => linter.lint(&pset),
            };
            body(result.findings().map(|f| render(f)).collect())
        };
        check("default", rel, run(default_lints()));
        check("additional", rel, run(additional_lints()));
    }
}

/// Two snapshots per sample schema — `default` schema lints and the `additional`
/// (off-by-default) ones. (Every schema lint is on by default today, so
/// `additional` is empty; kept for symmetry and to catch a future off-by-default
/// schema lint.)
#[test]
fn lint_sample_schemas() {
    for rel in SCHEMA_SAMPLES {
        let src = std::fs::read_to_string(sample_path(rel)).expect("read schema");
        let fragment = match SchemaFragment::from_cedarschema_str(&src) {
            Ok((f, _)) => f,
            Err(e) => {
                let rendered = format!("(did not parse) {e}");
                check("default", rel, Some(rendered.clone()));
                check("additional", rel, Some(rendered));
                continue;
            }
        };
        let run = |lints: Vec<Lint>| {
            let findings = SchemaLinter::new(lints).lint(&fragment);
            body(findings.iter().map(|f| render(f)).collect())
        };
        check("default", rel, run(default_lints()));
        check("additional", rel, run(additional_lints()));
    }
}
