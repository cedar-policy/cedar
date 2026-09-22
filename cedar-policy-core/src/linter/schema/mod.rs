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

//! Lints for Cedar *schemas*, as opposed to policies.
//!
//! Where the policy linter flags suspect policies, this flags suspect schemas —
//! things a schema author can write that parse and validate but are probably not
//! what they wanted. Like the policy linter, it does not re-check what schema
//! construction already rejects (duplicate declarations, cycles in the action or
//! common-type hierarchy, unknown extension or undeclared type references); those
//! are hard errors, not lints.
//!
//! It operates on a parsed [`json_schema::Fragment`](crate::validator::json_schema::Fragment),
//! which is what both schema syntaxes (JSON and the Cedar schema format) parse
//! into. That means it runs before name resolution, on the schema as written.
//!
//! Each lint lives in its own submodule with a `lint(namespace, def, findings)`
//! entry point; the [`SchemaLinter`] here selects and runs them. Helpers used by
//! more than one lint are in [`shared`].

use crate::{
    linter::{findings::SchemaFinding, Lint},
    validator::{json_schema::Fragment, RawName},
};

mod shared;

mod attribute_should_be_tags;
mod conflicting_applies_to_attr;
mod conflicting_tag_type;
mod duplicate_enum_choice;
mod duplicate_member_of;
mod shared_attributes;
mod shared_prefix_namespace;
mod unused_action;
mod unused_common_type;
mod unused_entity_type;

/// Runs the schema lints over a parsed schema fragment.
///
/// Takes the fragment as written (`RawName`, pre-resolution), so it sees the
/// author's spelling of type references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaLinter {
    lints: std::collections::BTreeSet<Lint>,
}

impl SchemaLinter {
    /// A linter running the given schema lints. Non-schema lints are ignored.
    pub fn new(lints: impl IntoIterator<Item = Lint>) -> Self {
        Self {
            lints: lints.into_iter().collect(),
        }
    }

    /// A linter running every schema lint.
    pub fn all() -> Self {
        Self::new([
            Lint::AttributeShouldBeTags,
            Lint::SharedPrefixNamespace,
            Lint::UnusedEntityType,
            Lint::UnusedCommonType,
            Lint::UnusedAction,
            Lint::DuplicateMemberOf,
            Lint::DuplicateEnumChoice,
            Lint::SharedAttributes,
            Lint::ConflictingAppliesToAttr,
            Lint::ConflictingContextAttr,
            Lint::ConflictingTagType,
        ])
    }

    fn runs(&self, lint: Lint) -> bool {
        self.lints.contains(&lint)
    }

    /// Lint `fragment`, returning every finding.
    pub fn lint(&self, fragment: &Fragment<RawName>) -> Vec<SchemaFinding> {
        let mut findings = Vec::new();
        for (ns, def) in &fragment.0 {
            let ns = ns.as_ref();
            // Each enabled lint's per-namespace pass. One `Lint => module::lint`
            // per line keeps the dispatch flat and every lint in its own file.
            for (lint, run) in [
                (
                    Lint::AttributeShouldBeTags,
                    attribute_should_be_tags::lint as LintFn,
                ),
                (Lint::SharedPrefixNamespace, shared_prefix_namespace::lint),
                (Lint::UnusedEntityType, unused_entity_type::lint),
                (Lint::UnusedCommonType, unused_common_type::lint),
                (Lint::UnusedAction, unused_action::lint),
                (Lint::DuplicateMemberOf, duplicate_member_of::lint),
                (Lint::DuplicateEnumChoice, duplicate_enum_choice::lint),
                (Lint::SharedAttributes, shared_attributes::lint),
                (
                    Lint::ConflictingAppliesToAttr,
                    conflicting_applies_to_attr::lint_applies_to_attr,
                ),
                (
                    Lint::ConflictingContextAttr,
                    conflicting_applies_to_attr::lint_context_attr,
                ),
                (Lint::ConflictingTagType, conflicting_tag_type::lint),
            ] {
                if self.runs(lint) {
                    run(ns, def, &mut findings);
                }
            }
        }
        findings
    }
}

/// The shape every schema lint's entry point has: given a namespace and its
/// definition, push any findings.
type LintFn = fn(
    Option<&crate::ast::Name>,
    &crate::validator::json_schema::NamespaceDefinition<RawName>,
    &mut Vec<SchemaFinding>,
);

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::LintGroup;

    /// `all()` must list exactly the lints in the `Schema` group. This catches a
    /// new schema lint being declared but forgotten here (so it never runs under
    /// `all()`), or a non-schema lint sneaking in.
    #[test]
    fn all_matches_schema_group() {
        let declared: std::collections::BTreeSet<Lint> = Lint::all()
            .filter(|l| l.group() == LintGroup::Schema)
            .collect();
        assert_eq!(SchemaLinter::all().lints, declared);
    }
}
