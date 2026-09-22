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

//! The TPE-based lints: type-aware partial evaluation of the whole policy set on a
//! fully-unknown request in each request environment the schema admits.
//!
//! Each lint has its own submodule; [`shared`] holds the environment-iteration
//! driver ([`shared::for_each_env`]) and the scope-matching predicates more than
//! one of them uses. This whole module is gated on the `tpe` feature.

mod shared;

mod folded_constant_condition;
mod policy_always_errors;
mod trivial_decision;
mod vacuous_policy;

pub(crate) use policy_always_errors::lint as lint_errors;
pub(crate) use trivial_decision::lint;
pub(crate) use vacuous_policy::lint as lint_vacuous;

use crate::{
    ast::PolicySet,
    linter::{findings::LintFinding, Lint},
    validator::ValidatorSchema,
};

/// Which TPE lints to run, mirroring [`Linter`](crate::linter::Linter)'s selection.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Enabled {
    pub trivial_decision: bool,
    pub policy_always_errors: bool,
    pub vacuous_policy: bool,
    pub folded_constant: bool,
}

impl Enabled {
    /// Read the enabled TPE lints off a linter.
    pub(crate) fn from_linter(linter: &crate::linter::Linter) -> Self {
        Self {
            trivial_decision: linter.runs(Lint::TrivialDecision),
            policy_always_errors: linter.runs(Lint::PolicyAlwaysErrors),
            vacuous_policy: linter.runs(Lint::VacuousPolicy),
            folded_constant: linter.runs(Lint::FoldedConstantCondition),
        }
    }

    fn any(self) -> bool {
        self.trivial_decision
            || self.policy_always_errors
            || self.vacuous_policy
            || self.folded_constant
    }
}

/// Run the enabled TPE lints and return their findings as [`LintFinding`]s, so they
/// fold into the ordinary [`LintResult`](crate::linter::LintResult) alongside the
/// schema-free and schema-informed lints.
///
/// Most TPE findings are policy-scoped and carry their policy's ID; the
/// decision-level [`trivial_decision`] findings are scoped to a request environment
/// and carry none ([`LintFinding::untagged`]).
pub(crate) fn lint_all(
    policies: &PolicySet,
    schema: &ValidatorSchema,
    enabled: Enabled,
) -> Vec<LintFinding> {
    if !enabled.any() {
        return Vec::new();
    }
    let mut out = Vec::new();
    if enabled.trivial_decision {
        // Decision-scoped: no single policy owns these.
        out.extend(
            trivial_decision::lint(policies, schema)
                .into_iter()
                .map(|f| LintFinding::untagged(f.into())),
        );
    }
    if enabled.policy_always_errors {
        for f in policy_always_errors::lint(policies, schema) {
            let id = crate::ast::PolicyID::from_string(&f.policy_id);
            out.extend(LintFinding::tag_all([f.into()], &id));
        }
    }
    if enabled.vacuous_policy {
        for (id, f) in vacuous_policy::lint_tagged(policies, schema) {
            out.extend(LintFinding::tag_all([f.into()], &id));
        }
    }
    if enabled.folded_constant {
        for (id, f) in folded_constant_condition::lint(policies, schema) {
            out.extend(LintFinding::tag_all([f.into()], &id));
        }
    }
    out
}
