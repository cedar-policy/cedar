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

use crate::{CedarExitCode, OptionalSchemaArgs, PoliciesArgs};
use cedar_policy::{Lint, LintGroup, Linter, SchemaLinter};
use clap::Args;
use miette::Report;
use std::str::FromStr;

#[derive(Args, Debug)]
pub struct LintArgs {
    /// Policies args (incorporated by reference)
    #[command(flatten)]
    pub policies: PoliciesArgs,
    /// Schema args (optional). A schema is not required, but providing one
    /// unlocks the schema-informed lints (e.g. `typed-constant-condition`) and
    /// enables the schema lints on the schema itself.
    #[command(flatten)]
    pub schema: OptionalSchemaArgs,
    /// Run only this lint (repeatable). Give a lint by its name, e.g.
    /// `--lint constant-condition`. If neither `--lint` nor `--group` is given,
    /// the default set of lints runs.
    #[arg(long = "lint", value_name = "NAME")]
    pub lints: Vec<String>,
    /// Run every lint in this group (repeatable), e.g. `--group correctness`.
    #[arg(long = "group", value_name = "GROUP")]
    pub groups: Vec<String>,
    /// Run every lint, including those off by default. Overrides `--lint`/`--group`.
    #[arg(long)]
    pub all: bool,
    /// Also lint the schema itself (requires `--schema`).
    #[arg(long)]
    pub lint_schema: bool,
    /// The maximum attribute/tag access depth allowed by the
    /// `bounded-attribute-depth` lint (only meaningful when that lint runs).
    #[arg(long, value_name = "N")]
    pub max_attribute_depth: Option<usize>,
    /// Exit with a failure code if any lint finding is reported. Without this, a
    /// finding is printed but the command still succeeds.
    #[arg(long)]
    pub deny_warnings: bool,
}

/// Build the [`Linter`] the arguments select: `--all`, or the union of `--lint`
/// and `--group`, or the default set when neither is given.
fn build_linter(args: &LintArgs) -> Result<Linter, CedarExitCode> {
    let mut linter = if args.all {
        Linter::all_lints()
    } else if args.lints.is_empty() && args.groups.is_empty() {
        Linter::default_lints()
    } else {
        let mut l = Linter::new(std::iter::empty::<Lint>());
        for name in &args.lints {
            match Lint::from_str(name) {
                Ok(lint) => l = l.with(lint),
                Err(e) => {
                    println!("{:?}", Report::new(e));
                    return Err(CedarExitCode::Failure);
                }
            }
        }
        for name in &args.groups {
            match LintGroup::from_str(name) {
                Ok(group) => l = l.with_group(group),
                Err(e) => {
                    println!("{:?}", Report::new(e));
                    return Err(CedarExitCode::Failure);
                }
            }
        }
        l
    };
    if let Some(bound) = args.max_attribute_depth {
        linter = linter.with_attribute_depth_bound(bound);
    }
    Ok(linter)
}

pub fn lint(args: &LintArgs) -> CedarExitCode {
    let linter = match build_linter(args) {
        Ok(l) => l,
        Err(code) => return code,
    };

    let pset = match args.policies.get_policy_set() {
        Ok(pset) => pset,
        Err(e) => {
            println!("{e:?}");
            return CedarExitCode::Failure;
        }
    };

    let schema = match args.schema.get_schema() {
        Ok(schema) => schema,
        Err(e) => {
            println!("{e:?}");
            return CedarExitCode::Failure;
        }
    };

    // With a schema, run the schema-informed policy lints too; without one, the
    // schema-free lints only.
    let result = match &schema {
        Some(schema) => linter.lint_with_schema(&pset, schema),
        None => linter.lint(&pset),
    };

    let mut any_finding = false;
    for finding in result.findings() {
        any_finding = true;
        println!("{:?}", Report::new(finding.clone()));
    }

    // Schema linting, if requested. Needs the schema *fragment* (the schema as
    // written), which is read separately from the resolved `Schema` above.
    if args.lint_schema {
        match schema_findings(args) {
            Ok(reported) => any_finding |= reported,
            Err(code) => return code,
        }
    }

    if !any_finding {
        println!("no lint findings");
        CedarExitCode::Success
    } else if args.deny_warnings {
        CedarExitCode::ValidationFailure
    } else {
        CedarExitCode::Success
    }
}

/// Run the schema lints and print any findings. Returns whether any were reported,
/// or an exit code on error (no schema given, or the schema fails to parse as a
/// fragment).
fn schema_findings(args: &LintArgs) -> Result<bool, CedarExitCode> {
    let Some(schema_file) = &args.schema.schema_file else {
        println!("error: `--lint-schema` requires `--schema`");
        return Err(CedarExitCode::Failure);
    };
    let fragment = match crate::read_schema_fragment(schema_file, args.schema.schema_format) {
        Ok(f) => f,
        Err(e) => {
            println!("{e:?}");
            return Err(CedarExitCode::Failure);
        }
    };
    let findings = SchemaLinter::all().lint(&fragment);
    let mut any = false;
    for finding in findings {
        any = true;
        println!("{:?}", Report::new(finding));
    }
    Ok(any)
}
