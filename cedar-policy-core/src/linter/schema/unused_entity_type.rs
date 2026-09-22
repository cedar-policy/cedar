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

//! Flags entity types that no action applies to and nothing else references.

use crate::{
    ast::Name,
    linter::{
        findings::{SchemaFinding, UnusedEntityType},
        schema::shared::{qualified, referenced_type_names},
    },
    validator::{json_schema::NamespaceDefinition, RawName},
};

/// An entity type earns its place by being reachable in a request: either an
/// action's `appliesTo` names it (as principal or resource), or another type
/// references it (a parent-of relationship, or an attribute/tag of that type). A
/// type that is neither can never appear in any request the schema describes.
///
/// This is sound within the namespace as written. It does not chase references
/// *across* namespaces, so a type used only by another namespace is conservatively
/// still reported here — noted in the help so a cross-namespace user can suppress.
pub(super) fn lint(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    let referenced = referenced_type_names(def);
    for name in def.entity_types.keys() {
        let name = name.as_ref();
        if !referenced.contains(name) {
            findings.push(
                UnusedEntityType {
                    loc: None,
                    entity_type: qualified(namespace, name),
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
        report(Lint::UnusedEntityType, src)
    }

    /// An entity type no action applies to and nothing references.
    #[test]
    fn unused_entity_type() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User;
            entity Orphan;
            action view appliesTo { principal: [User], resource: [User] };
        "#), @"
        ⚠ entity type `Orphan` is declared but never used
        help: no action's `appliesTo` names it and no other type references it, so no request can involve it; remove it or wire it up
        ");
    }

    /// A type an action applies to is used.
    #[test]
    fn entity_used_by_action_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User;
            entity Photo;
            action view appliesTo { principal: [User], resource: [Photo] };
        "#), @"");
    }

    /// A type referenced as a parent, an attribute, or a tag is used.
    #[test]
    fn entity_referenced_by_another_type_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity Group;
            entity User in [Group] { manager: User } tags Group;
            action view appliesTo { principal: [User], resource: [User] };
        "#), @"");
    }
}
