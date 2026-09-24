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

//! Convert entity data AST to internal Entities representation

use std::collections::{BTreeMap, HashSet};

use smol_str::SmolStr;

use crate::ast::{
    expression_construction_errors::DuplicateKeyError, Eid, Entity, EntityType, EntityUID,
    ExpressionConstructionError, Name, RestrictedExpr,
};
use crate::extensions::Extensions;
use crate::from_normalized_str::FromNormalizedStr;
use crate::parser::{Loc, Node};

use super::ast::*;
use super::err::{conversion_errors, ConversionError, ConversionErrors};

/// Build a single `Loc` spanning a sequence of nodes (e.g. the `::`-separated
/// segments of a type path or extension-function name), from the start of the
/// first located node to the end of the last. Returns `None` if no node in the
/// slice carries a location.
fn combined_loc(nodes: &[Node<SmolStr>]) -> Option<Loc> {
    let mut located = nodes.iter().filter_map(|n| n.loc.as_ref());
    let first = located.next()?;
    let start = first.start();
    // The end is the end of the last located node (fall back to the first).
    let end = located.next_back().map_or_else(|| first.end(), Loc::end);
    Some(first.span(start..end))
}

/// Convert parsed entity data AST into a Vec of internal [`Entity`] values.
///
/// The resulting entities can then be passed to [`crate::entities::Entities::from_entities`]
/// for transitive closure computation and schema validation.
pub fn cedar_entities_to_entities(
    ast: EntityDataAst,
    extensions: &Extensions<'_>,
) -> Result<Vec<Entity>, ConversionErrors> {
    // Pass 1: collect the set of all declared entity types across all
    // namespaces. This lets an unqualified reference inside a namespace fall back
    // to the root/empty namespace when the current-namespace candidate isn't
    // declared (see `resolve_ref_type`).
    let declared_types = collect_declared_types(&ast);

    let mut entities = Vec::new();
    let mut errors = Vec::new();

    // Pass 2: convert each instance, consuming the AST.
    for annotated_ns in ast {
        let namespace_prefix: Option<Vec<SmolStr>> = annotated_ns
            .data
            .name
            .as_ref()
            .map(|p| p.node.iter().map(|s| s.node.clone()).collect());

        for annotated_inst in &annotated_ns.data.instances {
            match convert_instance(
                &annotated_inst.data.node,
                namespace_prefix.as_deref(),
                &declared_types,
                extensions,
            ) {
                Ok(entity) => entities.push(entity),
                Err(e) => errors.push(e),
            }
        }
    }

    if errors.is_empty() {
        Ok(entities)
    } else {
        Err(ConversionErrors::new(errors))
    }
}

/// Pass 1: gather the fully-qualified type of every declared instance.
///
/// A declaration always defines a name in its lexical namespace, so its own
/// type is resolved unconditionally (via [`resolve_decl_type`]) — no
/// current-vs-root ambiguity. Resolution failures are ignored here; they will
/// be reported when the instance is actually converted in pass 2.
fn collect_declared_types(ast: &EntityDataAst) -> HashSet<EntityType> {
    let mut declared = HashSet::new();
    for annotated_ns in ast {
        let namespace_prefix: Option<Vec<SmolStr>> = annotated_ns
            .data
            .name
            .as_ref()
            .map(|p| p.node.iter().map(|s| s.node.clone()).collect());
        for annotated_inst in &annotated_ns.data.instances {
            if let Ok(ty) = resolve_decl_type(
                &annotated_inst.data.node.entity_ref.node.type_path,
                namespace_prefix.as_deref(),
            ) {
                declared.insert(ty);
            }
        }
    }
    declared
}

/// Convert a single EntityInstance AST node to an Entity
fn convert_instance(
    inst: &EntityInstance,
    namespace_prefix: Option<&[SmolStr]>,
    declared_types: &HashSet<EntityType>,
    extensions: &Extensions<'_>,
) -> Result<Entity, ConversionError> {
    // 1. Resolve UID — the instance's own type is a *declaration*, so it is
    //    qualified unconditionally with the current namespace.
    let uid = resolve_decl_ref(&inst.entity_ref.node, namespace_prefix)?;

    // 2. Convert parents (transitive closure computed by Entities::from_entities)
    let parents: HashSet<EntityUID> = inst
        .parents
        .iter()
        .map(|p| resolve_ref(&p.node, namespace_prefix, declared_types))
        .collect::<Result<_, _>>()?;

    // 3. Convert attributes (rejecting duplicate keys)
    let attrs = match &inst.attrs {
        Some(record) => convert_record(&record.node, namespace_prefix, declared_types)?,
        None => Vec::new(),
    };

    // 4. Convert tags (rejecting duplicate keys)
    let tags = match &inst.tags {
        Some(record) => convert_record(&record.node, namespace_prefix, declared_types)?,
        None => Vec::new(),
    };

    // 5. Build Entity. `Entity::new` evaluates attribute/tag values, which is
    //    where unknown extension functions and wrong argument counts are caught;
    //    its `EntityAttrEvaluationError` is preserved (not flattened to a string)
    //    to keep the entity/attribute context and diagnostic.
    Entity::new(uid, attrs, HashSet::new(), parents, tags, extensions)
        .map_err(ConversionError::EntityAttributeEvaluation)
}

/// Convert a record's entries to validated `(key, value)` pairs, rejecting
/// duplicate keys.
///
/// Values are recursively converted and accumulated into a `BTreeMap`, so a
/// repeated key is detected on insertion (and reported with the offending key's
/// source location, reusing the shared [`DuplicateKeyError`]). The map is
/// returned as a `Vec` of pairs. Using a `BTreeMap` also gives deterministic
/// key order, matching how `Entity::new` stores attributes/tags.
fn convert_record(
    record: &[(Node<SmolStr>, Node<EntityValue>)],
    namespace_prefix: Option<&[SmolStr]>,
    declared_types: &HashSet<EntityType>,
) -> Result<Vec<(SmolStr, RestrictedExpr)>, ConversionError> {
    let mut map: BTreeMap<SmolStr, RestrictedExpr> = BTreeMap::new();
    for (k, v) in record {
        let val = convert_value(&v.node, namespace_prefix, declared_types)?;
        if map.insert(k.node.clone(), val).is_some() {
            return Err(dup_key_conversion_error(k));
        }
    }
    Ok(map.into_iter().collect())
}

/// Build a [`ConversionError`] for a duplicate record key `k`, reusing the
/// shared [`DuplicateKeyError`] (so the key and message stay consistent with
/// record construction elsewhere) and attaching the key's source location.
fn dup_key_conversion_error(k: &Node<SmolStr>) -> ConversionError {
    let err = DuplicateKeyError {
        key: k.node.clone(),
        context: "in record literal",
    };
    conversion_errors::DuplicateRecordKeyError {
        err,
        loc: k.loc.clone(),
    }
    .into()
}

/// Resolve an EntityReference in *declaration* position (the instance's own
/// type) to an EntityUID. A declaration always binds a name in its lexical
/// namespace, so the type is qualified unconditionally.
fn resolve_decl_ref(
    eref: &EntityReference,
    namespace_prefix: Option<&[SmolStr]>,
) -> Result<EntityUID, ConversionError> {
    let entity_type = resolve_decl_type(&eref.type_path, namespace_prefix)?;
    Ok(EntityUID::from_components(
        entity_type,
        Eid::new(eref.id.clone()),
        None,
    ))
}

/// Resolve an EntityReference in *reference* position (a parent or an entity-ref
/// value) to an EntityUID, using conditional (current-ns-then-root) resolution.
fn resolve_ref(
    eref: &EntityReference,
    namespace_prefix: Option<&[SmolStr]>,
    declared_types: &HashSet<EntityType>,
) -> Result<EntityUID, ConversionError> {
    let entity_type = resolve_ref_type(&eref.type_path, namespace_prefix, declared_types)?;
    Ok(EntityUID::from_components(
        entity_type,
        Eid::new(eref.id.clone()),
        None,
    ))
}

/// Build an [`EntityType`] from already-resolved path segments.
fn make_entity_type(segments: &[&str], loc: Option<Loc>) -> Result<EntityType, ConversionError> {
    let type_name = segments.join("::");
    let name = Name::from_normalized_str(&type_name).map_err(|_| {
        ConversionError::from(conversion_errors::UnresolvedTypeError {
            name: type_name,
            loc,
        })
    })?;
    Ok(EntityType::from(name))
}

/// Resolve an entity type in *declaration* position.
/// - Single-segment path (e.g., "User") → qualify with current namespace → "PhotoApp::User"
/// - Multi-segment path (e.g., "OtherApp::User") → use as-is (already qualified)
fn resolve_decl_type(
    type_path: &[Node<SmolStr>],
    namespace_prefix: Option<&[SmolStr]>,
) -> Result<EntityType, ConversionError> {
    let full_path: Vec<&str> = match type_path {
        // Single-segment (unqualified) — qualify with the current namespace.
        [single] => match namespace_prefix {
            Some(ns) => ns
                .iter()
                .map(|s| s.as_str())
                .chain(std::iter::once(single.node.as_str()))
                .collect(),
            None => vec![single.node.as_str()],
        },
        // Multi-segment (already qualified) — use as-is.
        segments => segments.iter().map(|s| s.node.as_str()).collect(),
    };
    make_entity_type(&full_path, combined_loc(type_path))
}

/// Resolve an entity type in *reference* position:
/// - Multi-segment path → already qualified, use as-is.
/// - Single-segment path inside namespace `NS` → resolve in priority order
///   `[NS::Name, Name]`, picking the first that is actually declared. If neither
///   is declared, default to the highest-priority candidate `NS::Name`.
/// - Single-segment path at the top level → the bare name.
///
/// See also `RawName::conditionally_qualify_with` in `validator/schema/raw_name.rs`
/// which implements the same resolution strategy for schema names.
fn resolve_ref_type(
    type_path: &[Node<SmolStr>],
    namespace_prefix: Option<&[SmolStr]>,
    declared_types: &HashSet<EntityType>,
) -> Result<EntityType, ConversionError> {
    match type_path {
        // Single-segment (unqualified): resolve current-namespace-then-root.
        [single] => {
            let name = single.node.as_str();
            let loc = single.loc.clone();
            match namespace_prefix {
                Some(ns) => {
                    // Candidate 1 (highest priority): current namespace.
                    let qualified_segments: Vec<&str> = ns
                        .iter()
                        .map(|s| s.as_str())
                        .chain(std::iter::once(name))
                        .collect();
                    let qualified = make_entity_type(&qualified_segments, loc.clone())?;
                    // Candidate 2: root / empty namespace.
                    let bare = make_entity_type(&[name], loc)?;

                    if declared_types.contains(&qualified) {
                        Ok(qualified)
                    } else if declared_types.contains(&bare) {
                        Ok(bare)
                    } else {
                        // Neither declared: default to current namespace (highest priority).
                        Ok(qualified)
                    }
                }
                None => make_entity_type(&[name], loc),
            }
        }
        // Multi-segment (already qualified) — use as-is.
        segments => {
            let full_path: Vec<&str> = segments.iter().map(|s| s.node.as_str()).collect();
            make_entity_type(&full_path, combined_loc(type_path))
        }
    }
}

/// Convert an EntityValue AST node to a RestrictedExpr
fn convert_value(
    value: &EntityValue,
    namespace_prefix: Option<&[SmolStr]>,
    declared_types: &HashSet<EntityType>,
) -> Result<RestrictedExpr, ConversionError> {
    match value {
        EntityValue::Long(n) => Ok(RestrictedExpr::val(*n)),
        EntityValue::String(s) => Ok(RestrictedExpr::val(s.clone())),
        EntityValue::Bool(b) => Ok(RestrictedExpr::val(*b)),
        EntityValue::EntityRef(eref) => {
            // Entity-ref values are *references*, so use conditional resolution.
            let uid = resolve_ref(&eref.node, namespace_prefix, declared_types)?;
            Ok(RestrictedExpr::val(uid))
        }
        EntityValue::Set(items) => {
            let exprs: Vec<RestrictedExpr> = items
                .iter()
                .map(|v| convert_value(&v.node, namespace_prefix, declared_types))
                .collect::<Result<_, _>>()?;
            Ok(RestrictedExpr::set(exprs))
        }
        EntityValue::Record(entries) => {
            let pairs = convert_record(entries, namespace_prefix, declared_types)?;
            RestrictedExpr::record(pairs).map_err(|e| match e {
                ExpressionConstructionError::DuplicateKey(err) => {
                    conversion_errors::DuplicateRecordKeyError { err, loc: None }.into()
                }
            })
        }
        EntityValue::ExtensionCall { fn_name, args } => {
            let name = Name::from_normalized_str(fn_name.node.as_str()).map_err(|_| {
                ConversionError::from(conversion_errors::UnknownExtensionFunctionError {
                    name: fn_name.node.to_string(),
                    loc: fn_name.loc.clone(),
                })
            })?;

            // Convert arguments
            let arg_exprs: Vec<RestrictedExpr> = args
                .iter()
                .map(|a| convert_value(&a.node, namespace_prefix, declared_types))
                .collect::<Result<_, _>>()?;

            Ok(RestrictedExpr::call_extension_fn(name, arg_exprs))
        }
    }
}
