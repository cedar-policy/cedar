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

//! Helpers shared by more than one schema lint: reading a shape's attributes,
//! collecting the type names a declaration references, and rendering a qualified
//! name. Each individual schema lint lives in its own sibling module.

use std::collections::{BTreeMap, BTreeSet};

use smol_str::SmolStr;

use crate::{
    ast::Name,
    validator::{
        json_schema::{
            EntityType, EntityTypeKind, NamespaceDefinition, RecordType, Type, TypeOfAttribute,
            TypeVariant,
        },
        RawName,
    },
};

/// The `TypeVariant` of a shape's record, if the shape is a record at all.
///
/// A shape is always a record in practice, but the type does not guarantee it, so
/// this returns the variant to match on.
pub(super) fn shape_variant<'a>(shape: &'a Type<RawName>) -> &'a TypeVariant<RawName> {
    static EMPTY: TypeVariant<RawName> = TypeVariant::Boolean;
    match shape {
        Type::Type { ty, .. } => ty,
        // A shape given as a common-type reference: we cannot see through it here
        // (that needs resolution), so treat it as not-a-record.
        Type::CommonTypeRef { .. } => &EMPTY,
    }
}

/// The standard entity type's attributes, if it is a standard record-shaped type.
pub(super) fn entity_attributes(
    entity: &EntityType<RawName>,
) -> Option<&BTreeMap<SmolStr, TypeOfAttribute<RawName>>> {
    let EntityTypeKind::Standard(std) = &entity.kind else {
        return None;
    };
    match shape_variant(&std.shape.0) {
        TypeVariant::Record(RecordType { attributes, .. }) => Some(attributes),
        _ => None,
    }
}

/// The standard entity type's tag type, if it is a standard type that declares
/// tags. `None` covers both a non-standard type and a standard type without tags;
/// callers that must distinguish those should match the kind themselves.
pub(super) fn entity_tags(entity: &EntityType<RawName>) -> Option<&Type<RawName>> {
    let EntityTypeKind::Standard(std) = &entity.kind else {
        return None;
    };
    std.tags.as_ref()
}

/// Collect every unqualified type name referenced by `ty`, recursively.
///
/// "Unqualified" because this compares against the names *declared* in the same
/// namespace, which are unqualified in the fragment as written. A reference into
/// another namespace is qualified and so simply won't match a local declaration —
/// which is correct, since the reference is to the other namespace's type.
///
/// This runs pre-resolution, so it cannot tell an entity reference from a common
/// one; it collects the name either way, which is what "is this name used?" needs.
pub(super) fn collect_type_refs(ty: &Type<RawName>, out: &mut BTreeSet<String>) {
    match ty {
        Type::CommonTypeRef { type_name, .. } => {
            out.insert(type_name.to_string());
        }
        Type::Type { ty, .. } => match ty {
            TypeVariant::Entity { name } => {
                out.insert(name.to_string());
            }
            TypeVariant::EntityOrCommon { type_name } => {
                out.insert(type_name.to_string());
            }
            TypeVariant::Set { element } => collect_type_refs(element, out),
            TypeVariant::Record(RecordType { attributes, .. }) => {
                for attr in attributes.values() {
                    collect_type_refs(&attr.ty, out);
                }
            }
            // Primitives and extensions name no declared type.
            TypeVariant::String
            | TypeVariant::Long
            | TypeVariant::Boolean
            | TypeVariant::Extension { .. } => {}
        },
    }
}

/// Every type name referenced anywhere in a namespace: entity `memberOfTypes`,
/// entity attributes and tags, action `appliesTo` (principal/resource/context),
/// and common-type bodies.
pub(super) fn referenced_type_names(def: &NamespaceDefinition<RawName>) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    for entity in def.entity_types.values() {
        if let EntityTypeKind::Standard(std) = &entity.kind {
            for parent in &std.member_of_types {
                refs.insert(parent.to_string());
            }
            collect_type_refs(&std.shape.0, &mut refs);
            if let Some(tags) = &std.tags {
                collect_type_refs(tags, &mut refs);
            }
        }
    }
    for action in def.actions.values() {
        if let Some(applies) = &action.applies_to {
            for p in &applies.principal_types {
                refs.insert(p.to_string());
            }
            for r in &applies.resource_types {
                refs.insert(r.to_string());
            }
            collect_type_refs(&applies.context.0, &mut refs);
        }
    }
    for common in def.common_types.values() {
        collect_type_refs(&common.ty, &mut refs);
    }
    refs
}

/// The distinct values that appear more than once in `items`, in first-seen order.
pub(super) fn duplicates(items: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut reported = BTreeSet::new();
    let mut out = Vec::new();
    for item in items {
        if !seen.insert(item.clone()) && reported.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

/// Render an entity type name qualified with its namespace, for a message.
pub(super) fn qualified(namespace: Option<&Name>, name: &str) -> String {
    match namespace {
        Some(ns) => format!("{ns}::{name}"),
        None => name.to_string(),
    }
}

/// Render an action's fully-qualified id, e.g. ``Action::"view"``.
pub(super) fn qualified_action(namespace: Option<&Name>, action: &str) -> String {
    match namespace {
        Some(ns) => format!(r#"{ns}::Action::"{action}""#),
        None => format!(r#"Action::"{action}""#),
    }
}

/// The two names in sorted order — for reporting a conflicting pair deterministically.
pub(super) fn order<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// A structural signature of a type that erases entity-type names (every entity
/// reference maps to one token) but keeps primitives and extension types distinct
/// and recurses through `Set` and `Record`. Two types with the same signature are
/// "the same up to entity types".
///
/// Used wherever a lint compares two schema types for a conflict that a policy
/// accessor (`.attr`, `.getTag`) would surface: differing *entity* types are
/// invisible to such an accessor, so they must not count as a conflict.
///
/// Runs pre-resolution, so a common-type reference is opaque and treated as an
/// entity-like token — conservative: it may miss a conflict resolution would
/// reveal, but never invents one.
pub(super) fn type_signature(ty: &Type<RawName>) -> String {
    match ty {
        Type::CommonTypeRef { .. } => "entity".to_string(),
        Type::Type { ty, .. } => match ty {
            TypeVariant::String => "String".to_string(),
            TypeVariant::Long => "Long".to_string(),
            TypeVariant::Boolean => "Bool".to_string(),
            TypeVariant::Extension { name } => format!("ext({name})"),
            TypeVariant::Set { element } => format!("set({})", type_signature(element)),
            TypeVariant::Record(RecordType { attributes, .. }) => {
                // Fields sorted by name (the map is already sorted), each with its
                // required-ness and recursively-normalized type.
                let fields = attributes
                    .iter()
                    .map(|(n, a)| {
                        format!(
                            "{n}{}:{}",
                            if a.required { "" } else { "?" },
                            type_signature(&a.ty)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!("record({fields})")
            }
            // A must-be-entity reference: erased to the shared token.
            TypeVariant::Entity { .. } => "entity".to_string(),
            // Ambiguous pre-resolution: a primitive spelled in Cedar syntax, an
            // entity, or a common type. Map the primitive spellings to the
            // primitive; otherwise treat as entity-like.
            TypeVariant::EntityOrCommon { type_name } => {
                if type_name.is_unqualified() {
                    match type_name.to_string().as_str() {
                        "String" => return "String".to_string(),
                        "Long" => return "Long".to_string(),
                        "Bool" => return "Bool".to_string(),
                        _ => {}
                    }
                }
                "entity".to_string()
            }
        },
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use crate::extensions::Extensions;
    use crate::linter::test_util::render;
    use crate::linter::{schema::SchemaLinter, Lint};
    use crate::validator::{json_schema::Fragment, RawName};

    /// Parse `src` as a Cedar-format schema, run a `SchemaLinter` restricted to
    /// `lint`, and return the pretty miette rendering of all findings.
    #[track_caller]
    pub(crate) fn report(lint: Lint, src: &str) -> String {
        let (fragment, _) =
            Fragment::<RawName>::from_cedarschema_str(src, Extensions::all_available())
                .expect("failed to parse schema");
        render(&SchemaLinter::new([lint]).lint(&fragment))
    }
}
