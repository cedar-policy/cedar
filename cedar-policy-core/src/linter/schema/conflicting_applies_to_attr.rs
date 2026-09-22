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

//! Two lints for the schema-side of the union-type footgun — an attribute whose
//! type is ambiguous because the entity in a scope position, or the action, is not
//! pinned:
//!
//! * `conflicting-applies-to-attr`: two entity types applicable in the *same*
//!   scope position (principal or resource) for one action declare an attribute of
//!   the same name with *incompatible* types. A policy scoped to that action can
//!   read `principal.attr`/`resource.attr` without knowing which entity is there.
//! * `conflicting-context-attr`: two *actions* declare a `context` attribute of the
//!   same name with incompatible types. A policy not scoped to a single action
//!   reads `context.attr` without knowing which action's context is in play.
//!
//! Both compare on the same entity-erased type signature (below) and live here
//! because they share it.
//!
//! # "Incompatible" is up to entity types
//!
//! Differing *entity* types do not conflict: `User { pet: Dog }` and
//! `Admin { pet: Cat }` both give `principal.pet` "some entity", which a policy
//! treats uniformly (an entity comparison, a `.getTag`, etc.). Only a difference
//! that survives erasing entity-type names is a real conflict — `String` vs `Long`,
//! `Set<Long>` vs `Set<String>`, or a record whose fields differ up to entity
//! types. So the comparison is on a structural *signature* that maps every entity
//! reference to one token, keeps primitives and extension types distinct, and
//! recurses through `Set` and `Record`.
//!
//! Because the pass runs pre-resolution it cannot see through a common-type
//! reference; such a reference is treated as an opaque entity-like token, which
//! keeps the lint conservative (it may miss a conflict a common type would reveal,
//! but does not invent one).

use std::collections::BTreeMap;

use smol_str::SmolStr;

use crate::{
    ast::Name,
    linter::{
        findings::{ConflictingAppliesToAttr, ConflictingContextAttr, SchemaFinding},
        schema::shared::{
            entity_attributes, order, qualified, qualified_action, shape_variant, type_signature,
        },
    },
    validator::{
        json_schema::{NamespaceDefinition, RecordType, TypeVariant},
        RawName,
    },
};

/// One source of attributes to compare: its display name plus its attributes'
/// `(name -> type signature)`.
struct Source {
    /// Display name of the owner (an entity type, or an action id).
    owner: String,
    /// Each attribute's name and its entity-erased type signature.
    attrs: Vec<(SmolStr, String)>,
}

/// The `conflicting-applies-to-attr` lint: conflicts among the entity types
/// applicable in one scope position of an action.
pub(super) fn lint_applies_to_attr(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    lint_applies_to(namespace, def, findings);
}

/// The `conflicting-context-attr` lint: conflicts among the `context` records of
/// different actions.
pub(super) fn lint_context_attr(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    lint_contexts(namespace, def, findings);
}

/// For each action and each scope position, compare the attribute types of the
/// entity types applicable there and report same-name / different-signature
/// conflicts.
fn lint_applies_to(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    // The attribute signatures of each *local* standard entity type, by its
    // declared name. A cross-namespace applies-to reference (qualified) will not
    // match a key here and is skipped — its attributes are not visible here.
    let attrs_by_type: BTreeMap<String, Vec<(SmolStr, String)>> = def
        .entity_types
        .iter()
        .filter_map(|(name, entity)| {
            let attrs = entity_attributes(entity)?;
            Some((name.to_string(), signatures(attrs)))
        })
        .collect();

    for (action_name, action) in &def.actions {
        let Some(applies) = &action.applies_to else {
            continue;
        };
        for (position, types) in [
            ("principal", &applies.principal_types),
            ("resource", &applies.resource_types),
        ] {
            // The applicable types whose attributes we can see, sorted by name so a
            // reported pair is deterministic.
            let mut sources: Vec<Source> = types
                .iter()
                .filter_map(|t| {
                    let name = t.to_string();
                    attrs_by_type.get(&name).map(|attrs| Source {
                        owner: name,
                        attrs: attrs.clone(),
                    })
                })
                .collect();
            sources.sort_by(|a, b| a.owner.cmp(&b.owner));

            for c in conflicts(&sources) {
                findings.push(
                    ConflictingAppliesToAttr {
                        loc: None,
                        action: qualified_action(namespace, action_name),
                        position,
                        type_a: qualified(namespace, &c.owner_a),
                        type_b: qualified(namespace, &c.owner_b),
                        attribute: c.attribute,
                    }
                    .into(),
                );
            }
        }
    }
}

/// Compare the `context` records of every action pairwise and report same-name /
/// different-signature attribute conflicts across actions.
fn lint_contexts(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    // Each action's context attributes, by action id, sorted for determinism. A
    // context that is not a record (e.g. an unresolved common-type ref) yields no
    // attributes here.
    let mut sources: Vec<Source> = def
        .actions
        .iter()
        .filter_map(|(name, action)| {
            let applies = action.applies_to.as_ref()?;
            let TypeVariant::Record(RecordType { attributes, .. }) =
                shape_variant(&applies.context.0)
            else {
                return None;
            };
            Some(Source {
                owner: name.to_string(),
                attrs: signatures(attributes),
            })
        })
        .collect();
    sources.sort_by(|a, b| a.owner.cmp(&b.owner));

    for c in conflicts(&sources) {
        findings.push(
            ConflictingContextAttr {
                loc: None,
                action_a: qualified_action(namespace, &c.owner_a),
                action_b: qualified_action(namespace, &c.owner_b),
                attribute: c.attribute,
            }
            .into(),
        );
    }
}

/// A same-name / different-signature attribute conflict between two sources.
struct Conflict {
    owner_a: String,
    owner_b: String,
    attribute: SmolStr,
}

/// The attribute conflicts across `sources` (assumed sorted by owner): for each
/// attribute name, the first source that declares it fixes the expected
/// signature, and any later source with a different signature is a conflict.
fn conflicts(sources: &[Source]) -> Vec<Conflict> {
    let mut first_seen: BTreeMap<&SmolStr, (&str, &str)> = BTreeMap::new();
    let mut out = Vec::new();
    for source in sources {
        for (attr, sig) in &source.attrs {
            match first_seen.get(attr) {
                None => {
                    first_seen.insert(attr, (&source.owner, sig));
                }
                Some((other_owner, other_sig)) if *other_sig != sig.as_str() => {
                    let (a, b) = order(other_owner, &source.owner);
                    out.push(Conflict {
                        owner_a: a.to_string(),
                        owner_b: b.to_string(),
                        attribute: attr.clone(),
                    });
                }
                Some(_) => {} // same signature: compatible up to entity types
            }
        }
    }
    out
}

/// The `(name, signature)` of each attribute in `attrs`.
fn signatures(
    attrs: &BTreeMap<SmolStr, crate::validator::json_schema::TypeOfAttribute<RawName>>,
) -> Vec<(SmolStr, String)> {
    attrs
        .iter()
        .map(|(n, a)| (n.clone(), type_signature(&a.ty)))
        .collect()
}

#[cfg(test)]
mod test {
    use crate::linter::schema::shared::test_support::report;
    use crate::linter::Lint;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        report(Lint::ConflictingAppliesToAttr, src)
    }

    #[track_caller]
    fn context_report(src: &str) -> String {
        report(Lint::ConflictingContextAttr, src)
    }

    /// Same attribute name, different primitive types, both applicable as the
    /// principal of one action: a conflict.
    #[test]
    fn primitive_conflict() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User { level: Long };
            entity Admin { level: String };
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @r#"
        ⚠ `principal` types `Admin` and `User` of action `Action::"view"` both declare attribute `level` with different types
        help: a policy for `Action::"view"` that reads `principal.level` gets a different type depending on which entity is the principal; give the attribute one type across both, or rename one
        "#);
    }

    /// Same attribute name but different *entity* types is fine — `principal.pet`
    /// is "an entity" either way.
    #[test]
    fn entity_typed_attribute_is_compatible() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity Dog;
            entity Cat;
            entity User { pet: Dog };
            entity Admin { pet: Cat };
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @"");
    }

    /// The erasure recurses: `Set<Dog>` and `Set<Cat>` are compatible.
    #[test]
    fn set_of_entities_is_compatible() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity Dog;
            entity Cat;
            entity User { pets: Set<Dog> };
            entity Admin { pets: Set<Cat> };
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @"");
    }

    /// But `Set<Long>` vs `Set<String>` differ under the erasure: a conflict.
    #[test]
    fn set_of_primitives_conflict() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User { tags: Set<Long> };
            entity Admin { tags: Set<String> };
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @r#"
        ⚠ `principal` types `Admin` and `User` of action `Action::"view"` both declare attribute `tags` with different types
        help: a policy for `Action::"view"` that reads `principal.tags` gets a different type depending on which entity is the principal; give the attribute one type across both, or rename one
        "#);
    }

    /// Records recurse too: differing entity fields are fine, differing primitive
    /// fields conflict.
    #[test]
    fn record_field_up_to_entity_is_compatible() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity Dog;
            entity Cat;
            entity User { info: { owner: Dog, n: Long } };
            entity Admin { info: { owner: Cat, n: Long } };
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @"");
    }

    #[test]
    fn record_field_primitive_conflict() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User { info: { n: Long } };
            entity Admin { info: { n: String } };
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @r#"
        ⚠ `principal` types `Admin` and `User` of action `Action::"view"` both declare attribute `info` with different types
        help: a policy for `Action::"view"` that reads `principal.info` gets a different type depending on which entity is the principal; give the attribute one type across both, or rename one
        "#);
    }

    /// Types applicable in *different* positions do not conflict: a policy sees
    /// `principal.x` and `resource.x` as separate accesses.
    #[test]
    fn different_positions_do_not_conflict() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User { x: Long };
            entity Admin { x: String };
            action view appliesTo { principal: [User], resource: [Admin] };
        "#), @"");
    }

    /// Types applicable to *different* actions do not conflict.
    #[test]
    fn different_actions_do_not_conflict() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User { x: Long };
            entity Admin { x: String };
            action view appliesTo { principal: [User], resource: [User] };
            action edit appliesTo { principal: [Admin], resource: [Admin] };
        "#), @"");
    }

    /// A shared attribute with the *same* type is fine.
    #[test]
    fn same_type_is_compatible() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User { level: Long };
            entity Admin { level: Long };
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @"");
    }

    /// A disjoint attribute (present on only one type) is not a conflict.
    #[test]
    fn disjoint_attributes_are_fine() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User { a: Long };
            entity Admin { b: String };
            action view appliesTo { principal: [User, Admin], resource: [User] };
        "#), @"");
    }

    // --- context conflicts across actions ---

    /// Two actions declare `context.n` at different primitive types: a conflict.
    #[test]
    fn context_primitive_conflict() {
        insta::assert_snapshot!(context_report(
            r#"
            entity User;
            action view appliesTo { principal: [User], resource: [User], context: { n: Long } };
            action edit appliesTo { principal: [User], resource: [User], context: { n: String } };
        "#), @r#"
        ⚠ actions `Action::"edit"` and `Action::"view"` declare context attribute `n` with different types
        help: a policy that reads `context.n` without pinning the action gets a different type depending on which action is in play; give the attribute one type across both, or rename one
        "#);
    }

    /// Context attributes at different *entity* types are fine.
    #[test]
    fn context_entity_typed_is_compatible() {
        insta::assert_snapshot!(context_report(
            r#"
            entity User;
            entity Dog;
            entity Cat;
            action view appliesTo { principal: [User], resource: [User], context: { who: Dog } };
            action edit appliesTo { principal: [User], resource: [User], context: { who: Cat } };
        "#), @"");
    }

    /// Same context type across actions is fine.
    #[test]
    fn context_same_type_is_compatible() {
        insta::assert_snapshot!(context_report(
            r#"
            entity User;
            action view appliesTo { principal: [User], resource: [User], context: { n: Long } };
            action edit appliesTo { principal: [User], resource: [User], context: { n: Long } };
        "#), @"");
    }

    /// Distinct context attribute names across actions do not conflict.
    #[test]
    fn context_disjoint_attributes_are_fine() {
        insta::assert_snapshot!(context_report(
            r#"
            entity User;
            action view appliesTo { principal: [User], resource: [User], context: { a: Long } };
            action edit appliesTo { principal: [User], resource: [User], context: { b: String } };
        "#), @"");
    }

    /// The conflict is found across three actions, reported per colliding pair.
    #[test]
    fn context_conflict_is_pairwise() {
        insta::assert_snapshot!(context_report(
            r#"
            entity User;
            action a appliesTo { principal: [User], resource: [User], context: { n: Long } };
            action b appliesTo { principal: [User], resource: [User], context: { n: String } };
        "#), @r#"
        ⚠ actions `Action::"a"` and `Action::"b"` declare context attribute `n` with different types
        help: a policy that reads `context.n` without pinning the action gets a different type depending on which action is in play; give the attribute one type across both, or rename one
        "#);
    }
}
