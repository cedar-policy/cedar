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

//! Flags entity types referenced *only* as the type of an attribute — never a
//! principal/resource, never a hierarchy member, never otherwise referenced. Such
//! a type could be a common-type record instead of a separate entity.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ast::Name,
    linter::{
        findings::{EntityAttrShouldBeCommonType, SchemaFinding},
        schema::shared::{collect_type_refs, qualified, shape_variant},
    },
    validator::{
        json_schema::{EntityTypeKind, NamespaceDefinition, RecordType, TypeVariant},
        RawName,
    },
};

/// Where in a namespace a type name is referenced, split into attribute-type uses
/// and every other use.
#[derive(Default)]
struct RefKinds {
    /// Type names referenced as the type of some entity attribute or tag, with a
    /// human description of one such place (``attribute `address` on `User` ``).
    as_attribute: BTreeMap<String, String>,
    /// Type names referenced anywhere that is *not* an attribute type: a
    /// `memberOf` parent, an action `appliesTo` principal/resource, an action
    /// context, or a common-type body.
    elsewhere: BTreeSet<String>,
}

/// Classify every type reference in `def` as an attribute-type use or an other
/// use.
///
/// A common-type body counts as "elsewhere": a type reached through a common type
/// is not a plain owned sub-structure of one entity, so the record-inlining
/// suggestion does not apply cleanly.
fn classify_references(def: &NamespaceDefinition<RawName>) -> RefKinds {
    let mut kinds = RefKinds::default();
    for (owner, entity) in &def.entity_types {
        if let EntityTypeKind::Standard(std) = &entity.kind {
            // memberOf parents are structural, not attribute uses.
            for parent in &std.member_of_types {
                kinds.elsewhere.insert(parent.to_string());
            }
            // Each attribute's type is an attribute use.
            if let TypeVariant::Record(RecordType { attributes, .. }) = shape_variant(&std.shape.0)
            {
                for (attr, attr_ty) in attributes {
                    let mut refs = BTreeSet::new();
                    collect_type_refs(&attr_ty.ty, &mut refs);
                    for name in refs {
                        kinds
                            .as_attribute
                            .entry(name)
                            .or_insert_with(|| format!("attribute `{attr}` on `{owner}`"));
                    }
                }
            }
            // Tags are a store-backed, per-entity map — closer to an attribute, but
            // still a distinct mechanism; count them as an "elsewhere" use so a
            // tag-typed entity is not suggested for inlining into a record.
            if let Some(tags) = &std.tags {
                collect_type_refs(tags, &mut kinds.elsewhere);
            }
        }
    }
    for action in def.actions.values() {
        if let Some(applies) = &action.applies_to {
            for p in &applies.principal_types {
                kinds.elsewhere.insert(p.to_string());
            }
            for r in &applies.resource_types {
                kinds.elsewhere.insert(r.to_string());
            }
            collect_type_refs(&applies.context.0, &mut kinds.elsewhere);
        }
    }
    for common in def.common_types.values() {
        collect_type_refs(&common.ty, &mut kinds.elsewhere);
    }
    kinds
}

/// Such a type exists only to give structure to that attribute, which a
/// common-type record expresses inline without a separate entity to store or
/// dereference. Not applicable when the entity is meant to be shared by reference
/// across owners or when a policy tests its existence, so this is a `Style`
/// suggestion and its help names both escape hatches.
///
/// Conservative on two fronts: it does not chase references across namespaces (a
/// type used only from another namespace is still reported here), and an entity
/// used as an attribute on more than one owner is treated as plausibly shared and
/// left alone.
pub(super) fn lint(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    let kinds = classify_references(def);
    // How many distinct attribute owners reference each type, to spot a type that
    // is shared across owners (a hint it is meant to be referenced, not inlined).
    let mut owners_of: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (owner, entity) in &def.entity_types {
        if let EntityTypeKind::Standard(std) = &entity.kind {
            if let TypeVariant::Record(RecordType { attributes, .. }) = shape_variant(&std.shape.0)
            {
                for attr_ty in attributes.values() {
                    let mut refs = BTreeSet::new();
                    collect_type_refs(&attr_ty.ty, &mut refs);
                    for name in refs {
                        owners_of.entry(name).or_default().insert(owner.to_string());
                    }
                }
            }
        }
    }

    for (name, entity) in &def.entity_types {
        let name = name.as_ref();
        // Only standard entity types can be inlined into a record; enums cannot.
        if !matches!(entity.kind, EntityTypeKind::Standard(_)) {
            continue;
        }
        let Some(used_at) = kinds.as_attribute.get(name) else {
            continue; // not used as an attribute type at all
        };
        // Referenced elsewhere → not *only* an attribute type.
        if kinds.elsewhere.contains(name) {
            continue;
        }
        // Shared across more than one owner → plausibly meant to be referenced.
        if owners_of.get(name).map(BTreeSet::len).unwrap_or(0) > 1 {
            continue;
        }
        findings.push(
            EntityAttrShouldBeCommonType {
                loc: None,
                entity_type: qualified(namespace, name),
                used_at: used_at.clone(),
            }
            .into(),
        );
    }
}

#[cfg(test)]
mod test {
    use crate::linter::schema::shared::test_support::report;
    use crate::linter::Lint;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        report(Lint::EntityAttrShouldBeCommonType, src)
    }

    /// `Address` is used only as the type of `User.address`; suggest a common type.
    #[test]
    fn entity_used_only_as_attribute() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity Address { street: String, zip: String };
            entity User { address: Address };
            action view appliesTo { principal: [User], resource: [User] };
        "#), @"
        ⚠ entity type `Address` is used only as an attribute type
        help: it appears only as attribute `address` on `User`; a common-type record inlines that structure with no separate entity to store or dereference. This does not apply if the same entity is meant
              to be shared by reference across owners, or if a policy needs to test the entity's existence
        ");
    }

    /// A type used as a principal/resource is reachable in a request, not merely an
    /// attribute type.
    #[test]
    fn entity_used_as_principal_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User { address: User };
            action view appliesTo { principal: [User], resource: [User] };
        "#), @"");
    }

    /// A type used as an attribute on two different owners is plausibly shared by
    /// reference, so it is left alone.
    #[test]
    fn entity_shared_across_owners_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity Address { street: String };
            entity User { address: Address };
            entity Company { address: Address };
            action view appliesTo { principal: [User], resource: [Company] };
        "#), @"");
    }

    /// A type that is also a hierarchy member is referenced structurally, not only
    /// as an attribute.
    #[test]
    fn entity_used_as_member_parent_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity Org { name: String };
            entity User in [Org] { org: Org };
            action view appliesTo { principal: [User], resource: [User] };
        "#), @"");
    }
}
