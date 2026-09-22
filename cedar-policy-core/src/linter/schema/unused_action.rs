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

//! Flags actions that are neither a parent of another action nor applicable to
//! any request.

use std::collections::BTreeSet;

use crate::{
    ast::Name,
    linter::findings::{SchemaFinding, UnusedAction},
    validator::{json_schema::NamespaceDefinition, RawName},
};

/// This is deliberately conservative, because the schema linter **cannot see
/// policies**: any action may be named by `action == Action::"x"` in a policy it
/// never sees. So "unused" here does not mean "no policy uses it" — that is not
/// schema-decidable. It means the action is inert *within the schema*: it groups
/// no other action (`memberOf` names it from nowhere) and has no `appliesTo`, so
/// it can never be the action of a valid request and organizes nothing. Such an
/// action is almost always a stub.
pub(super) fn lint(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    // Names that appear as some action's parent.
    let mut parents: BTreeSet<String> = BTreeSet::new();
    for action in def.actions.values() {
        if let Some(members) = &action.member_of {
            for m in members {
                parents.insert(m.id.to_string());
            }
        }
    }
    for (name, action) in &def.actions {
        let is_parent = parents.contains(name.as_str());
        // `appliesTo: None` means the action applies to nothing; an empty
        // principal or resource list likewise makes it inapplicable.
        let is_applicable = action
            .applies_to
            .as_ref()
            .is_some_and(|a| !a.principal_types.is_empty() && !a.resource_types.is_empty());
        if !is_parent && !is_applicable {
            findings.push(
                UnusedAction {
                    loc: None,
                    action: match namespace {
                        Some(ns) => format!(r#"{ns}::Action::"{name}""#),
                        None => format!(r#"Action::"{name}""#),
                    },
                }
                .into(),
            );
        }
    }
}

#[cfg(test)]
mod test {
    use crate::linter::schema::shared::test_support::report;
    use crate::linter::Lint;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        report(Lint::UnusedAction, src)
    }

    /// An action that groups nothing and applies to nothing is inert.
    #[test]
    fn unused_action() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User;
            action stub;
            action view appliesTo { principal: [User], resource: [User] };
        "#), @r#"
        ⚠ action `Action::"stub"` is declared but never used
        help: no policy scope can name it usefully and no action groups it; remove it or add it to a group
        "#);
    }

    /// An action that applies to a request is used.
    #[test]
    fn applicable_action_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User;
            action view appliesTo { principal: [User], resource: [User] };
        "#), @"");
    }

    /// An action that groups another (is a parent) is used, even with no
    /// `appliesTo` of its own.
    #[test]
    fn action_group_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User;
            action readOnly;
            action view in [readOnly] appliesTo { principal: [User], resource: [User] };
        "#), @"");
    }
}
