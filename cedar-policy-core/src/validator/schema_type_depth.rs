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

//! Effective depth computation for schema types, resolving common type references.

use std::collections::{HashMap, HashSet};

use crate::ast::InternalName;

use super::json_schema::{EntityTypeKind, Fragment, NamespaceDefinition, Type, TypeVariant};
use super::topo_sort::topo_sort;

/// Compute the maximum effective type depth across all types in a schema fragment,
/// resolving common type references to account for depth introduced through
/// chains of reference. This is the depth the types will have after common type
/// references are inlined.
///
/// Requires a `Fragment<InternalName>` where all type references are fully
/// qualified. Use [`Fragment::to_internal_name_fragment_with_resolved_types`] to obtain one.
///
/// Returns `None` if there are cycles (reported separately by the validator).
pub(crate) fn fragment_effective_depth(fragment: &Fragment<InternalName>) -> Option<usize> {
    let common_type_depths = resolve_all_common_type_depths(fragment)?;

    let max_depth = fragment
        .0
        .values()
        .map(|ns_def| namespace_depth(ns_def, &common_type_depths))
        .chain(common_type_depths.values().copied())
        .max()
        .unwrap_or(0);

    Some(max_depth)
}

/// Compute the maximum effective depth across all types declared in a
/// namespace. Does not account for common types declared in the namespace but
/// used elsewhere. All common type depths are checked together in
/// `fragment_effective_depth`.
fn namespace_depth(
    ns_def: &NamespaceDefinition<InternalName>,
    common_type_depths: &HashMap<InternalName, usize>,
) -> usize {
    let entity_depths = ns_def.entity_types.values().filter_map(|ety| {
        if let EntityTypeKind::Standard(standard) = &ety.kind {
            let shape = type_depth(&standard.shape.0, common_type_depths);
            let tags = standard
                .tags
                .as_ref()
                .map(|t| type_depth(t, common_type_depths))
                .unwrap_or(0);
            Some(shape.max(tags))
        } else {
            None
        }
    });
    let action_depths = ns_def
        .actions
        .values()
        .filter_map(|a| a.applies_to.as_ref())
        .map(|applies_to| type_depth(&applies_to.context.0, common_type_depths));
    entity_depths.chain(action_depths).max().unwrap_or(0)
}

/// Build a lookup map from fully-qualified [`InternalName`] to the common type definition.
fn build_common_type_map(
    fragment: &Fragment<InternalName>,
) -> HashMap<InternalName, &Type<InternalName>> {
    fragment
        .0
        .iter()
        .flat_map(|(ns_name, ns_def)| {
            ns_def.common_types.iter().map(move |(ct_id, ct)| {
                let key = InternalName::unqualified_name(ct_id.as_ref().clone().into(), None)
                    .qualify_with_name(ns_name.as_ref());
                (key, &ct.ty)
            })
        })
        .collect()
}

/// Resolve depths of all common types using topological sort.
/// Returns `None` if there is a cycle.
fn resolve_all_common_type_depths(
    fragment: &Fragment<InternalName>,
) -> Option<HashMap<InternalName, usize>> {
    let common_types = build_common_type_map(fragment);
    let graph: HashMap<&InternalName, HashSet<&InternalName>> = common_types
        .iter()
        .map(|(key, ty)| {
            let deps = ty
                .common_type_references()
                .filter(|name| common_types.contains_key(*name))
                .collect();
            (key, deps)
        })
        .collect();

    let sorted = topo_sort(&graph).ok()?;

    let mut common_type_depths: HashMap<InternalName, usize> = HashMap::new();
    for &key in &sorted {
        #[expect(
            clippy::unwrap_used,
            reason = "topo_sort only returns keys that exist in the input graph, which was built from common_types"
        )]
        let ty = common_types.get(key).unwrap();
        let depth = type_depth(ty, &common_type_depths);
        common_type_depths.insert(key.clone(), depth);
    }
    Some(common_type_depths)
}

/// Compute the structural depth of a type, substituting resolved depths for
/// common type references. We can directly recurse on `ty` because we assume we
/// have already checked its direct depth and we do not follow common type
/// references, instead looking them up in `common_type_defs`.
fn type_depth(ty: &Type<InternalName>, common_type_defs: &HashMap<InternalName, usize>) -> usize {
    match ty {
        Type::Type { ty: variant, .. } => match variant {
            TypeVariant::String
            | TypeVariant::Long
            | TypeVariant::Boolean
            | TypeVariant::Entity { .. }
            | TypeVariant::Extension { .. } => 0,
            TypeVariant::Set { element } => 1 + type_depth(element, common_type_defs),
            TypeVariant::Record(record) => {
                record
                    .attributes
                    .values()
                    .map(|attr| type_depth(&attr.ty, common_type_defs))
                    .max()
                    // If empty, the depth of a record is 0.  If non-empty, the
                    // depth is one more than the deepest member.
                    .map(|d| 1 + d)
                    .unwrap_or(0)
            }
            TypeVariant::EntityOrCommon { type_name } => {
                common_type_defs.get(type_name).copied().unwrap_or(0)
            }
        },
        Type::CommonTypeRef { type_name, .. } => {
            common_type_defs.get(type_name).copied().unwrap_or(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::Extensions;
    use crate::validator::cedar_schema::parser::parse_cedar_schema_fragment;
    use rstest::rstest;

    fn effective_depth_of_cedar(src: &str) -> Option<usize> {
        let extensions = Extensions::all_available();
        let (fragment, _warnings) = parse_cedar_schema_fragment(src, &extensions).unwrap();
        let resolved = fragment
            .to_internal_name_fragment_with_resolved_types()
            .unwrap();
        fragment_effective_depth(&resolved)
    }

    #[rstest]
    #[case::flat_entity("entity Foo;", 0)]
    #[case::entity_with_attr("entity Foo = { bar: Long };", 1)]
    #[case::set_of_long_attr("entity Foo = { bar: Set<Long> };", 2)]
    #[case::common_type_no_extra_depth("type T = Long; entity Foo = { bar: T };", 1)]
    #[case::common_type_chain(
        "type T1 = Set<Long>; type T2 = Set<T1>; entity Foo = { bar: T2 };",
        3
    )]
    #[case::long_typedef_chain("type T1 = Set<Long>; type T2 = Set<T1>; type T3 = Set<T2>;", 3)]
    #[case::record_with_typedef("type T = { inner: Long }; entity Foo = { bar: T };", 2)]
    #[case::entity_type_reference("entity Bar; entity Foo = { bar: Bar };", 1)]
    #[case::action_context_with_typedef(
        "type Deep = Set<Set<Long>>; entity User; entity File; action Read appliesTo { principal: User, resource: File, context: { x: Deep } };",
        3
    )]
    #[case::tags_with_typedef("type Deep = Set<Set<Long>>; entity Foo tags Deep;", 2)]
    fn effective_depth(#[case] src: &str, #[case] expected: usize) {
        assert_eq!(effective_depth_of_cedar(src), Some(expected));
    }
}
