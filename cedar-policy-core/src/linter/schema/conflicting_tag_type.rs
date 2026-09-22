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

//! The `conflicting-tag-type` lint — the tag-side of the union-type footgun.
//!
//! Two entity types applicable in the *same* scope position (principal or
//! resource) for one action declare tags of *different* types: one `tags String`,
//! the other `tags Long`. A policy scoped to that action calling
//! `principal.getTag(k)` (or `resource.getTag(k)`) gets a different type depending
//! on which entity is supplied — exactly the
//! [`conflicting-applies-to-attr`](super::conflicting_applies_to_attr) footgun,
//! one accessor over.
//!
//! Comparison is on the same entity-erased [`type_signature`], so `tags Dog` vs
//! `tags Cat` (both "an entity") does *not* conflict — only a difference surviving
//! erasure of entity-type names does.
//!
//! A tags-vs-no-tags split is deliberately *not* flagged: reaching a tag requires
//! a `getTag`, which only type-checks behind a `hasTag` guard, so the guard the
//! author must already write prevents the error a missing tag would cause.
//!
//! Like the attribute lint, this runs pre-resolution and only sees *locally*
//! declared applicable types; a cross-namespace (qualified) reference is skipped,
//! since its tag declaration is not visible here.

use std::collections::BTreeMap;

use crate::{
    ast::Name,
    linter::{
        findings::{ConflictingTagType, SchemaFinding},
        schema::shared::{entity_tags, order, qualified, qualified_action, type_signature},
    },
    validator::{json_schema::NamespaceDefinition, RawName},
};

/// The `conflicting-tag-type` lint entry point.
pub(super) fn lint(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    // Each *locally* declared entity type's tag signature, by declared name, for
    // the types that declare tags. A type without tags is simply absent, and a
    // qualified applies-to reference into another namespace will not be a key and
    // is skipped.
    let tags_by_type: BTreeMap<String, String> = def
        .entity_types
        .iter()
        .filter_map(|(name, entity)| Some((name.to_string(), type_signature(entity_tags(entity)?))))
        .collect();

    for (action_name, action) in &def.actions {
        let Some(applies) = &action.applies_to else {
            continue;
        };
        for (position, types) in [
            ("principal", &applies.principal_types),
            ("resource", &applies.resource_types),
        ] {
            // The applicable local types that carry tags, with their signature,
            // sorted by name so a reported pair is deterministic.
            let mut sources: Vec<(&str, &str)> = types
                .iter()
                .filter_map(|t| {
                    let name = t.to_string();
                    tags_by_type
                        .get_key_value(&name)
                        .map(|(n, sig)| (n.as_str(), sig.as_str()))
                })
                .collect();
            sources.sort_by(|a, b| a.0.cmp(b.0));

            // The first tagged source fixes the expected signature; any later
            // tagged source with a different one is a conflict, reported against it
            // (as in the attribute lint).
            let mut expected: Option<(&str, &str)> = None;
            for (owner, sig) in sources {
                match expected {
                    None => expected = Some((owner, sig)),
                    Some((other_owner, other_sig)) if other_sig != sig => {
                        let (a, b) = order(other_owner, owner);
                        findings.push(
                            ConflictingTagType {
                                loc: None,
                                action: qualified_action(namespace, action_name),
                                position,
                                type_a: qualified(namespace, a),
                                type_b: qualified(namespace, b),
                            }
                            .into(),
                        );
                    }
                    Some(_) => {} // same signature: compatible up to entity types
                }
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
        report(Lint::ConflictingTagType, src)
    }

    /// Two applicable principals with tags of different primitive types conflict.
    #[test]
    fn primitive_tag_conflict() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User { name: String } tags Long;
            entity Admin { name: String } tags String;
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @r#"
        ⚠ `principal` types `Admin` and `User` of action `Action::"view"` carry tags of different types
        help: a policy for `Action::"view"` that calls `principal.getTag(..)` gets a different type depending on which entity is the principal; give the tags one type across both
        "#);
    }

    /// Tags of different *entity* types are fine — `getTag` yields "an entity"
    /// either way.
    #[test]
    fn entity_typed_tags_are_compatible() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity Dog;
            entity Cat;
            entity User tags Dog;
            entity Admin tags Cat;
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @"");
    }

    /// The erasure recurses into sets: `Set<Long>` vs `Set<String>` conflicts.
    #[test]
    fn set_tag_conflict() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User tags Set<Long>;
            entity Admin tags Set<String>;
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @r#"
        ⚠ `principal` types `Admin` and `User` of action `Action::"view"` carry tags of different types
        help: a policy for `Action::"view"` that calls `principal.getTag(..)` gets a different type depending on which entity is the principal; give the tags one type across both
        "#);
    }

    /// Same tag type across the applicable types is fine.
    #[test]
    fn same_tag_type_is_compatible() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User tags Long;
            entity Admin tags Long;
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @"");
    }

    /// A tags-vs-no-tags split is not flagged: the required `hasTag` guard prevents
    /// the error a missing tag would cause.
    #[test]
    fn presence_split_is_not_flagged() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User tags Long;
            entity Admin;
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @"");
    }

    /// Neither type having tags is fine.
    #[test]
    fn no_tags_anywhere_is_fine() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User;
            entity Admin;
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @"");
    }

    /// Types applicable in *different* positions do not conflict.
    #[test]
    fn different_positions_do_not_conflict() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User tags Long;
            entity Admin tags String;
            action view appliesTo { principal: [User], resource: [Admin] };
        "#), @"");
    }

    /// Types applicable to *different* actions do not conflict.
    #[test]
    fn different_actions_do_not_conflict() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User tags Long;
            entity Admin tags String;
            action view appliesTo { principal: [User], resource: [User] };
            action edit appliesTo { principal: [Admin], resource: [Admin] };
        "#), @"");
    }

    /// The conflict is found across three tagged types, reported per colliding pair
    /// against the first-seen signature.
    #[test]
    fn conflict_is_pairwise_against_first() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity Admin tags Long;
            entity Guest tags String;
            entity User tags String;
            action view appliesTo { principal: [Admin, Guest, User], resource: [User] };
        "#), @r#"
        ⚠ `principal` types `Admin` and `Guest` of action `Action::"view"` carry tags of different types
        help: a policy for `Action::"view"` that calls `principal.getTag(..)` gets a different type depending on which entity is the principal; give the tags one type across both

        ⚠ `principal` types `Admin` and `User` of action `Action::"view"` carry tags of different types
        help: a policy for `Action::"view"` that calls `principal.getTag(..)` gets a different type depending on which entity is the principal; give the tags one type across both
        "#);
    }
}
