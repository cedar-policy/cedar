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

//! Flags `memberOf`/`in` lists that name the same parent more than once.

use crate::{
    ast::Name,
    linter::{
        findings::{DuplicateMemberOf, SchemaFinding},
        schema::shared::{duplicates, qualified},
    },
    validator::{
        json_schema::{EntityTypeKind, NamespaceDefinition},
        RawName,
    },
};

/// Membership is a set, so a repeat is inert. Checks both entity `memberOfTypes`
/// and action `memberOf`; reports each distinct repeated parent once per member.
pub(super) fn lint(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    for (name, entity) in &def.entity_types {
        if let EntityTypeKind::Standard(std) = &entity.kind {
            let seen = duplicates(std.member_of_types.iter().map(ToString::to_string));
            for parent in seen {
                findings.push(
                    DuplicateMemberOf {
                        loc: None,
                        member: qualified(namespace, name.as_ref()),
                        parent,
                    }
                    .into(),
                );
            }
        }
    }
    for (name, action) in &def.actions {
        if let Some(members) = &action.member_of {
            let seen = duplicates(members.iter().map(|m| m.id.to_string()));
            for parent in seen {
                findings.push(
                    DuplicateMemberOf {
                        loc: None,
                        member: match namespace {
                            Some(ns) => format!(r#"{ns}::Action::"{name}""#),
                            None => format!(r#"Action::"{name}""#),
                        },
                        parent: format!(r#"Action::"{parent}""#),
                    }
                    .into(),
                );
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::linter::schema::shared::test_support::report;
    use crate::linter::Lint;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        report(Lint::DuplicateMemberOf, src)
    }

    #[test]
    fn duplicate_entity_member_of() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity Group;
            entity User in [Group, Group];
        "#), @"
        ⚠ `Group` is listed more than once in the membership of `User`
        help: membership is a set, so the repeat has no effect; list each parent once
        ");
    }

    #[test]
    fn duplicate_action_member_of() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User;
            action readOnly;
            action view in [readOnly, readOnly] appliesTo { principal: [User], resource: [User] };
        "#), @r#"
        ⚠ `Action::"readOnly"` is listed more than once in the membership of `Action::"view"`
        help: membership is a set, so the repeat has no effect; list each parent once
        "#);
    }

    #[test]
    fn distinct_member_of_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity A;
            entity B;
            entity User in [A, B];
        "#), @"");
    }
}
