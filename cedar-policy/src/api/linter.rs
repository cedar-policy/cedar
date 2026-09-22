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

//! Public API for the Cedar policy and schema linter.
//!
//! The linter reports *lints* — policies or schemas that parse and validate but
//! are likely wrong, oddly written, or use a construct a caller may want to rule
//! out. Unlike the [`Validator`](crate::Validator) it makes no soundness claim and
//! needs no schema (though a schema unlocks more lints).
//!
//! ```
//! # use cedar_policy::{Linter, PolicySet};
//! # use std::str::FromStr;
//! let policies = PolicySet::from_str(
//!     "permit(principal, action, resource) when { 1 > 2 };",
//! )
//! .unwrap();
//! let result = Linter::default_lints().lint(&policies);
//! for finding in result.findings() {
//!     println!("{:?}: {}", finding.policy_id(), finding.finding());
//! }
//! ```
//!
//! The [`Lint`], [`LintGroup`], [`LintResult`], [`LintFinding`], [`Finding`], and
//! [`SchemaFinding`] types are re-exported unchanged from the core linter: they
//! are located by policy ID / entity type name rather than by any internal type,
//! so no API wrapper is needed. Only the entry points — [`Linter`] and
//! [`SchemaLinter`] — are wrapped, to take this crate's [`PolicySet`],
//! [`Schema`](crate::Schema), and [`SchemaFragment`](crate::SchemaFragment).

use crate::{PolicySet, Schema, SchemaFragment};

use cedar_policy_core::linter as core;

// These types are re-exported from the core linter unchanged: they carry no
// internal types on their public surface, so they are part of this crate's public
// API as-is. Any breaking change to them in `cedar-policy-core` is therefore a
// breaking change to this crate's API too (see the notes on their definitions).
#[cfg(feature = "tpe")]
pub use cedar_policy_core::linter::{AlwaysErrors, TrivialDecision, TrivialOutcome, VacuousPolicy};
pub use cedar_policy_core::linter::{
    Finding, Lint, LintFinding, LintGroup, LintResult, SchemaFinding, UnknownLintGroupName,
    UnknownLintName,
};

/// Runs a selected set of [`Lint`]s over a [`PolicySet`], optionally with a
/// [`Schema`](crate::Schema).
///
/// Construct one with [`Linter::default_lints`] (the recommended starting point),
/// [`Linter::all_lints`], or [`Linter::new`] with a chosen set, then call
/// [`lint`](Linter::lint) or [`lint_with_schema`](Linter::lint_with_schema).
#[derive(Debug, Clone)]
pub struct Linter(core::Linter);

impl Linter {
    /// A linter that runs exactly `lints`.
    pub fn new(lints: impl IntoIterator<Item = Lint>) -> Self {
        Self(core::Linter::new(lints))
    }

    /// A linter that runs the lints that are on by default. Recommended starting
    /// point; lints that are off by default flag things that are often deliberate.
    pub fn default_lints() -> Self {
        Self(core::Linter::default_lints())
    }

    /// A linter that runs every lint, including those off by default.
    pub fn all_lints() -> Self {
        Self(core::Linter::all_lints())
    }

    /// Add `lint` to the set this linter runs.
    #[must_use]
    pub fn with(self, lint: Lint) -> Self {
        Self(self.0.with(lint))
    }

    /// Add every lint in `group` to the set this linter runs.
    #[must_use]
    pub fn with_group(self, group: LintGroup) -> Self {
        Self(self.0.with_group(group))
    }

    /// Remove `lint` from the set this linter runs.
    #[must_use]
    pub fn without(self, lint: Lint) -> Self {
        Self(self.0.without(lint))
    }

    /// Remove every lint in `group` from the set this linter runs.
    #[must_use]
    pub fn without_group(self, group: LintGroup) -> Self {
        Self(self.0.without_group(group))
    }

    /// Set the bound for [`Lint::BoundedAttributeDepth`]: an attribute/tag access
    /// chain deeper than `bound` is reported. Has no effect unless that lint runs.
    #[must_use]
    pub fn with_attribute_depth_bound(self, bound: usize) -> Self {
        Self(self.0.with_attribute_depth_bound(bound))
    }

    /// Will this linter run `lint`?
    pub fn runs(&self, lint: Lint) -> bool {
        self.0.runs(lint)
    }

    /// The lints this linter runs.
    pub fn lints(&self) -> impl Iterator<Item = Lint> + '_ {
        self.0.lints()
    }

    /// Run the selected lints over `policy_set`, without a schema.
    ///
    /// This runs every schema-free lint. Schema-informed lints are only run by
    /// [`lint_with_schema`](Linter::lint_with_schema).
    pub fn lint(&self, policy_set: &PolicySet) -> LintResult {
        self.0.lint(&policy_set.ast)
    }

    /// Run the selected lints over `policy_set` using `schema`, which additionally
    /// runs the schema-informed lints (e.g. [`Lint::TypedConstantCondition`]).
    pub fn lint_with_schema(&self, policy_set: &PolicySet, schema: &Schema) -> LintResult {
        self.0.lint_with_schema(&policy_set.ast, schema.as_ref())
    }

    /// The [`Lint::TrivialDecision`] findings for `policy_set` under `schema`:
    /// request environments whose authorization decision is fixed regardless of
    /// request data.
    ///
    /// A separate method because these findings are scoped to request environments
    /// rather than to a policy, so they carry no policy ID. Empty unless this
    /// linter runs [`Lint::TrivialDecision`].
    #[cfg(feature = "tpe")]
    pub fn trivial_decisions(
        &self,
        policy_set: &PolicySet,
        schema: &Schema,
    ) -> Vec<TrivialDecision> {
        self.0.trivial_decisions(&policy_set.ast, schema.as_ref())
    }

    /// The [`Lint::PolicyAlwaysErrors`] findings for `policy_set` under `schema`:
    /// policies that error for every request in some reachable request
    /// environment. Empty unless this linter runs [`Lint::PolicyAlwaysErrors`].
    #[cfg(feature = "tpe")]
    pub fn erroring_policies(&self, policy_set: &PolicySet, schema: &Schema) -> Vec<AlwaysErrors> {
        self.0.erroring_policies(&policy_set.ast, schema.as_ref())
    }

    /// The [`Lint::VacuousPolicy`] findings for `policy_set` under `schema`:
    /// policies whose condition is fixed — always applies or never applies —
    /// across every request environment. Empty unless this linter runs
    /// [`Lint::VacuousPolicy`].
    #[cfg(feature = "tpe")]
    pub fn vacuous_policies(&self, policy_set: &PolicySet, schema: &Schema) -> Vec<VacuousPolicy> {
        self.0.vacuous_policies(&policy_set.ast, schema.as_ref())
    }
}

/// Runs the schema lints over a [`SchemaFragment`](crate::SchemaFragment).
///
/// Where [`Linter`] flags policies, this flags schemas — declarations that parse
/// and validate but are probably not what the author meant (an unused entity
/// type, a duplicated `memberOf` entry, and so on).
#[derive(Debug, Clone)]
pub struct SchemaLinter(core::SchemaLinter);

impl SchemaLinter {
    /// A linter running the given schema lints. Non-schema lints are ignored.
    pub fn new(lints: impl IntoIterator<Item = Lint>) -> Self {
        Self(core::SchemaLinter::new(lints))
    }

    /// A linter running every schema lint.
    pub fn all() -> Self {
        Self(core::SchemaLinter::all())
    }

    /// Lint `fragment`, returning every finding.
    ///
    /// Takes a [`SchemaFragment`](crate::SchemaFragment) — the schema as written,
    /// before name resolution — so the lints see the author's spelling.
    pub fn lint(&self, fragment: &SchemaFragment) -> Vec<SchemaFinding> {
        // `lossless` is the fragment as written (`RawName`, pre-resolution), which
        // is exactly what the core schema linter wants. It is a private field, but
        // this module is a descendant of `api`, where it is declared.
        self.0.lint(&fragment.lossless)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn lints_a_policy_set() {
        let policies =
            PolicySet::from_str("permit(principal, action, resource) when { 1 > 2 };").unwrap();
        let result = Linter::default_lints().lint(&policies);
        assert!(!result.is_empty());
        assert!(result
            .findings()
            .any(|f| f.lint() == Lint::ConstantCondition));
    }

    #[test]
    fn selecting_lints_by_group() {
        let policies =
            PolicySet::from_str("permit(principal, action, resource) when { [] == [] };").unwrap();
        // Only the strict-migration group: the empty-set lint fires, the type lint
        // (a different group) does not.
        let linter = Linter::new(LintGroup::StrictMigration.lints());
        let result = linter.lint(&policies);
        assert!(result.findings().any(|f| f.lint() == Lint::EmptySet));
        assert!(!result.findings().any(|f| f.lint() == Lint::Types));
    }

    #[test]
    fn schema_informed_lint_needs_schema() {
        let schema = Schema::from_str(
            "entity User; entity Photo; action view appliesTo { principal: [User], resource: [Photo] };",
        )
        .unwrap();
        let policies = PolicySet::from_str(
            r#"permit(principal, action == Action::"view", resource) when { principal is User };"#,
        )
        .unwrap();
        // `principal is User` is a typed constant here, only detectable with a
        // schema.
        let linter = Linter::new([Lint::TypedConstantCondition]);
        assert!(linter.lint(&policies).is_empty());
        let with_schema = linter.lint_with_schema(&policies, &schema);
        assert!(with_schema
            .findings()
            .any(|f| f.lint() == Lint::TypedConstantCondition));
    }

    #[test]
    fn schema_linter() {
        let (fragment, _) = SchemaFragment::from_cedarschema_str(
            "entity Used; entity Unused; action view appliesTo { principal: [Used], resource: [Used] };",
        )
        .unwrap();
        let findings = SchemaLinter::all().lint(&fragment);
        assert!(findings.iter().any(|f| f.lint() == Lint::UnusedEntityType));
    }

    #[test]
    fn lint_name_round_trips() {
        for lint in Lint::all() {
            assert_eq!(Lint::from_str(lint.name()).unwrap(), lint);
        }
    }
}
