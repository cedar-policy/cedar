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

//! Entity Loader API implementation
//! Loads entities based on the entity manifest.

use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use cedar_policy_core::{
    ast::{Context, Entity, EntityUID, Literal, PartialValue, Request, Value, ValueKind, Var},
    entities::{Entities, NoEntitiesSchema, TCComputation},
    extensions::Extensions,
};
use smol_str::SmolStr;

use crate::entity_manifest::{
    slicing::{
        EntitySliceError, PartialContextError, PartialEntityError, WrongNumberOfEntitiesError,
    },
    AccessTrie, EntityManifest, EntityRoot, PartialRequestError, RootAccessTrie,
};

/// A request that an entity be loaded.
/// Optionally, instead of loading the full entity the `access_trie`
/// may be used to load only some fields of the entity.
#[derive(Debug)]
pub(crate) struct EntityRequest {
    /// The id of the entity requested
    pub(crate) entity_id: EntityUID,
    /// The fieds of the entity requested
    pub(crate) access_trie: AccessTrie,
}

/// An entity request may be an entity or `None` when
/// the entity is not present.
pub(crate) type EntityAnswer = Option<Entity>;

/// The entity request before sub-entitity tries have been
/// pruned using `prune_child_entity_dereferences`.
pub(crate) struct EntityRequestRef<'a> {
    entity_id: EntityUID,
    access_trie: &'a AccessTrie,
}

impl EntityRequestRef<'_> {
    fn to_request(&self) -> EntityRequest {
        EntityRequest {
            entity_id: self.entity_id.clone(),
            access_trie: self.access_trie.prune_child_entity_dereferences(),
        }
    }
}

/// A request that the ancestors of an entity be loaded.
/// Optionally, the `ancestors` set may be used to just load ancestors in the set.
#[derive(Debug)]
pub(crate) struct AncestorsRequest {
    /// The id of the entity whose ancestors are requested
    pub(crate) entity_id: EntityUID,
    /// The ancestors that are requested, if present
    pub(crate) ancestors: HashSet<EntityUID>,
}

/// Implement [`EntityLoader`] to easily load entities using their ids
/// into a Cedar [`Entities`] store.
/// The most basic implementation loads full entities (including all ancestors) in the `load_entities` method and loads the context in the `load_context` method.
/// More advanced implementations make use of the [`AccessTrie`]s provided to load partial entities and context, as well as the `load_ancestors` method to load particular ancestors.
///
/// Warning: `load_entities` is called multiple times. If database
/// consistency is required, this API should not be used. Instead, use the entity manifest directly.
pub(crate) trait EntityLoader {
    /// `load_entities` is called multiple times to load entities based on their ids.
    /// For each entity request in the `to_load` vector, expects one loaded entity in the resulting vector.
    /// Each [`EntityRequest`] comes with an [`AccessTrie`], which can optionally be used.
    /// Only fields mentioned in the entity's [`AccessTrie`] are needed, but it is sound to provide other fields as well.
    /// Note that the same entity may be requested multiple times, with different [`AccessTrie`]s.
    ///
    /// Either `load_entities` must load all the ancestors of each entity, unless `load_ancestors` is implemented.
    fn load_entities(
        &mut self,
        to_load: &[EntityRequest],
    ) -> Result<Vec<EntityAnswer>, EntitySliceError>;

    /// Optionally, `load_entities` can forgo loading ancestors in the entity hierarchy.
    /// Instead, `load_ancestors` implements loading them.
    /// For each entity, `load_ancestors` produces a set of ancestors entities in the resulting vector.
    ///
    /// Each [`AncestorsRequest`] should result in one set of ancestors in the resulting vector.
    /// Only ancestors in the request are required, but it is sound to provide other ancestors as well.
    fn load_ancestors(
        &mut self,
        entities: &[AncestorsRequest],
    ) -> Result<Vec<HashSet<EntityUID>>, EntitySliceError>;
}

fn initial_entities_to_load<'a>(
    root_access_trie: &'a RootAccessTrie,
    context: &Context,
    request: &Request,
    required_ancestors: &mut HashSet<EntityUID>,
) -> Result<Vec<EntityRequestRef<'a>>, EntitySliceError> {
    let Context::Value(context_value) = &context else {
        return Err(PartialContextError {}.into());
    };

    let mut to_load = match root_access_trie.trie.get(&EntityRoot::Var(Var::Context)) {
        Some(access_trie) => {
            find_remaining_entities_context(context_value, access_trie, required_ancestors)?
        }
        _ => vec![],
    };

    for (key, access_trie) in &root_access_trie.trie {
        to_load.push(EntityRequestRef {
            entity_id: match key {
                EntityRoot::Var(Var::Principal) => request
                    .principal()
                    .uid()
                    .ok_or(PartialRequestError {})?
                    .clone(),
                EntityRoot::Var(Var::Action) => request
                    .action()
                    .uid()
                    .ok_or(PartialRequestError {})?
                    .clone(),
                EntityRoot::Var(Var::Resource) => request
                    .resource()
                    .uid()
                    .ok_or(PartialRequestError {})?
                    .clone(),
                EntityRoot::Literal(lit) => lit.clone(),
                EntityRoot::Var(Var::Context) => continue,
            },
            access_trie,
        });
    }

    Ok(to_load)
}

impl AccessTrie {
    /// Removes any entity dereferences in the children of this trie,
    /// recursively.
    /// These can be included in [`EntityRequest`]s, which don't include
    /// referenced entities.
    pub(crate) fn prune_child_entity_dereferences(&self) -> AccessTrie {
        let children = self
            .children
            .iter()
            .map(|(k, v)| (k.clone(), Box::new(v.prune_entity_dereferences())))
            .collect();

        AccessTrie {
            children,
            ancestors_trie: self.ancestors_trie.clone(),
            is_ancestor: self.is_ancestor,
            node_type: self.node_type.clone(),
        }
    }

    pub(crate) fn prune_entity_dereferences(&self) -> AccessTrie {
        // PANIC SAFETY: Node types should always be present on entity manifests after creation.
        #[allow(clippy::unwrap_used)]
        let children = if self.node_type.as_ref().unwrap().is_entity_type() {
            HashMap::new()
        } else {
            self.children
                .iter()
                .map(|(k, v)| (k.clone(), Box::new(v.prune_entity_dereferences())))
                .collect()
        };

        AccessTrie {
            children,
            ancestors_trie: self.ancestors_trie.clone(),
            is_ancestor: self.is_ancestor,
            node_type: self.node_type.clone(),
        }
    }
}

/// Loads entities based on the entity manifest, request, and
/// the implemented [`EntityLoader`].
pub(crate) fn load_entities(
    manifest: &EntityManifest,
    request: &Request,
    loader: &mut dyn EntityLoader,
) -> Result<Entities, EntitySliceError> {
    let Some(root_access_trie) = manifest
        .per_action
        .get(&request.to_request_type().ok_or(PartialRequestError {})?)
    else {
        match Entities::from_entities(
            vec![],
            None::<&NoEntitiesSchema>,
            TCComputation::AssumeAlreadyComputed,
            Extensions::all_available(),
        ) {
            Ok(entities) => return Ok(entities),
            Err(err) => return Err(err.into()),
        };
    };

    let context = request.context().ok_or(PartialRequestError {})?;

    let mut entities: HashMap<EntityUID, Entity> = Default::default();
    // entity requests in progress
    let mut to_load: Vec<EntityRequestRef<'_>> =
        initial_entities_to_load(root_access_trie, context, request, &mut Default::default())?;
    // later, find the ancestors of these entities using their ancestor tries
    let mut to_find_ancestors = vec![];

    // Main loop of loading entities, one batch at a time
    while !to_load.is_empty() {
        // first, record the entities in `to_find_ancestors`
        for entity_request in &to_load {
            to_find_ancestors.push((
                entity_request.entity_id.clone(),
                &entity_request.access_trie.ancestors_trie,
            ));
        }

        let new_entities = loader.load_entities(
            &to_load
                .iter()
                .map(|entity_ref| entity_ref.to_request())
                .collect::<Vec<_>>(),
        )?;
        if new_entities.len() != to_load.len() {
            return Err(WrongNumberOfEntitiesError {
                expected: to_load.len(),
                got: new_entities.len(),
            }
            .into());
        }

        let mut next_to_load = vec![];
        for (entity_request, loaded_maybe) in to_load.into_iter().zip(new_entities) {
            if let Some(loaded) = loaded_maybe {
                next_to_load.extend(find_remaining_entities(
                    &loaded,
                    entity_request.access_trie,
                    &mut Default::default(),
                )?);
                match entities.entry(entity_request.entity_id) {
                    hash_map::Entry::Occupied(o) => {
                        // If the entity is already present in the slice, then
                        // we need to be careful not to clobber its existing
                        // attributes.  This can happen when an entity is
                        // referenced by both an entity literal and a variable.
                        let (k, v) = o.remove_entry();
                        let merged = merge_entities(v, loaded);
                        entities.insert(k, merged);
                    }
                    hash_map::Entry::Vacant(v) => {
                        v.insert(loaded);
                    }
                }
            }
        }

        to_load = next_to_load;
    }

    // now that all the entities are loaded
    // we need to load their ancestors
    let mut ancestors_requests = vec![];
    for (entity_id, ancestors_trie) in to_find_ancestors {
        ancestors_requests.push(compute_ancestors_request(
            entity_id,
            ancestors_trie,
            &entities,
            context,
            request,
        )?);
    }

    let loaded_ancestors = loader.load_ancestors(&ancestors_requests)?;
    for (request, ancestors) in ancestors_requests.into_iter().zip(loaded_ancestors) {
        if let Some(entity) = entities.get_mut(&request.entity_id) {
            ancestors
                .into_iter()
                .for_each(|ancestor| entity.add_parent(ancestor));
        }
    }

    // finally, convert the loaded entities into a Cedar Entities store
    match Entities::from_entities(
        entities.into_values(),
        None::<&NoEntitiesSchema>,
        TCComputation::AssumeAlreadyComputed,
        Extensions::all_available(),
    ) {
        Ok(entities) => Ok(entities),
        Err(e) => Err(e.into()),
    }
}

/// Merge the contents of two entities in the slice. Combines the attributes
/// records for both entities, recursively merging any attribute that exist in
/// both. If one entity is referenced by multiple entity roots in the slice,
/// then we need to be sure that we don't clobber the attribute for the first
/// when inserting the second into the slice.
// INVARIANT: `e1` and `e2` must be the result of slicing the same original
// entity using the same entity manifest and request. I.e., they may differ only in
// what attributes they contain. When an attribute exists in both, the
// attributes may differ only if they are records, and then only in what nested
// attributes they contain.
fn merge_entities(e1: Entity, e2: Entity) -> Entity {
    let (uid1, mut attrs1, ancestors1, parents1, tags1) = e1.into_inner();
    let (uid2, attrs2, ancestors2, parents2, tags2) = e2.into_inner();

    assert_eq!(
        uid1, uid2,
        "attempting to merge entities with different uids!"
    );
    assert_eq!(
        ancestors1, ancestors2,
        "attempting to merge entities with different ancestors!"
    );
    assert_eq!(
        parents1, parents2,
        "attempting to merge entities with different parents!"
    );
    assert!(
        tags1.is_empty() && tags2.is_empty(),
        "attempting to merge entities with tags!"
    );

    for (k, v2) in attrs2 {
        match attrs1.entry(k) {
            hash_map::Entry::Occupied(occupied) => {
                let (k, v1) = occupied.remove_entry();
                match (v1, v2) {
                    (PartialValue::Value(v1), PartialValue::Value(v2)) => {
                        let merged_v = merge_values(v1, v2);
                        attrs1.insert(k, PartialValue::Value(merged_v));
                    }
                    (PartialValue::Residual(e1), PartialValue::Residual(e2)) => {
                        assert_eq!(e1, e2, "attempting to merge different residuals!");
                        attrs1.insert(k, PartialValue::Residual(e1));
                    }
                    // PANIC SAFETY: We're merging sliced copies of the same entity, so the attribute must be the same
                    #[allow(clippy::panic)]
                    (PartialValue::Value(_), PartialValue::Residual(_))
                    | (PartialValue::Residual(_), PartialValue::Value(_)) => {
                        panic!("attempting to merge a value with a residual")
                    }
                };
            }
            hash_map::Entry::Vacant(vacant) => {
                vacant.insert(v2);
            }
        }
    }

    Entity::new_with_attr_partial_value(uid1, attrs1, ancestors1, parents1, [])
}

/// Merge two value for corresponding attributes in the slice.
// INVARIANT: `v1` and `v2` must be the result of slicing the same original
// value using the same entity manifest and request. I.e., they must be
// identical, except for the attributes they contain when the values are a
// records. When an attribute exists in both records, the attributes must be
// recursively identical, with the same exception.
fn merge_values(v1: Value, v2: Value) -> Value {
    match (v1.value, v2.value) {
        (ValueKind::Record(r1), ValueKind::Record(r2)) => {
            let mut r1 = Arc::unwrap_or_clone(r1);
            for (k, v2) in Arc::unwrap_or_clone(r2) {
                match r1.entry(k) {
                    btree_map::Entry::Occupied(occupied) => {
                        let (k, v1) = occupied.remove_entry();
                        let merged_v = merge_values(v1, v2);
                        r1.insert(k, merged_v);
                    }
                    btree_map::Entry::Vacant(vacant) => {
                        vacant.insert(v2);
                    }
                }
            }
            Value::new(ValueKind::Record(Arc::new(r1)), v1.loc)
        }
        (ValueKind::Lit(l1), ValueKind::Lit(l2)) => {
            assert_eq!(l1, l2, "attempting to merge different literals!");
            Value::new(l1, v1.loc)
        }
        (vk1 @ ValueKind::ExtensionValue(_), vk2 @ ValueKind::ExtensionValue(_))
        | (vk1 @ ValueKind::Set(_), vk2 @ ValueKind::Set(_)) => {
            // It might seem that we should recur into the sets and extensions
            // values, but `AccessTrie::slice_val` doesn't, so the merge
            // function can stop here too.
            assert_eq!(
                vk1, vk2,
                "attempting to merge different sets or extensions!"
            );
            Value::new(vk1, v1.loc)
        }
        // PANIC SAFETY: We're merging sliced copies of the same entity, so the attribute must be the same
        #[allow(clippy::panic)]
        _ => {
            panic!("attempting to merge values of different kinds!")
        }
    }
}

/// Given a context value and an access trie, find all of the remaining
/// entities in the context.
/// Also keep track of required ancestors when encountering the `is_ancestor` flag.
fn find_remaining_entities_context<'a>(
    context_value: &Arc<BTreeMap<SmolStr, Value>>,
    fields: &'a AccessTrie,
    required_ancestors: &mut HashSet<EntityUID>,
) -> Result<Vec<EntityRequestRef<'a>>, EntitySliceError> {
    let mut remaining = vec![];
    for (field, slice) in &fields.children {
        if let Some(value) = context_value.get(field) {
            find_remaining_entities_value(&mut remaining, value, slice, required_ancestors)?;
        }
        // the attribute may not be present, since the schema can define
        // attributes that are optional
    }
    Ok(remaining)
}

/// This helper function finds all entity references that need to be
/// loaded given an already-loaded [`Entity`] and corresponding [`Fields`].
/// Returns pairs of entity and slices that need to be loaded.
/// Also, any sets marked `is_ancestor` are added to the `required_ancestors` set.
fn find_remaining_entities<'a>(
    entity: &Entity,
    fields: &'a AccessTrie,
    required_ancestors: &mut HashSet<EntityUID>,
) -> Result<Vec<EntityRequestRef<'a>>, EntitySliceError> {
    let mut remaining = vec![];
    for (field, slice) in &fields.children {
        if let Some(pvalue) = entity.get(field) {
            let PartialValue::Value(value) = pvalue else {
                return Err(PartialEntityError {}.into());
            };
            find_remaining_entities_value(&mut remaining, value, slice, required_ancestors)?;
        }
        // the attribute may not be present, since the schema can define
        // attributes that are optional
    }

    Ok(remaining)
}

/// Like `find_remaining_entities`, but for values.
/// Any sets that are marked `is_ancestor` are added to the `required_ancestors` set.
fn find_remaining_entities_value<'a>(
    remaining: &mut Vec<EntityRequestRef<'a>>,
    value: &Value,
    trie: &'a AccessTrie,
    required_ancestors: &mut HashSet<EntityUID>,
) -> Result<(), EntitySliceError> {
    // unless this is an entity id, ancestors should not be required
    assert!(
        trie.ancestors_trie == Default::default()
            || matches!(value.value_kind(), ValueKind::Lit(Literal::EntityUID(_)))
    );

    // unless this is an entity id or set, it should not be an
    // ancestor
    assert!(
        !trie.is_ancestor
            || matches!(
                value.value_kind(),
                ValueKind::Lit(Literal::EntityUID(_)) | ValueKind::Set(_)
            )
    );

    match value.value_kind() {
        ValueKind::Lit(literal) => {
            if let Literal::EntityUID(entity_id) = literal {
                // no need to add to ancestors set here because
                // we are creating an entity request.

                remaining.push(EntityRequestRef {
                    entity_id: (**entity_id).clone(),
                    access_trie: trie,
                });
            }
        }
        ValueKind::Set(set) => {
            // when this is an ancestor, request all of the entities
            // in this set
            if trie.is_ancestor {
                for val in set.iter() {
                    match val.value_kind() {
                        ValueKind::Lit(Literal::EntityUID(id)) => {
                            required_ancestors.insert((**id).clone());
                        }
                        // PANIC SAFETY: see assert above- ancestor annotation is only valid on sets of entities or entities
                        #[allow(clippy::panic)]
                        _ => {
                            panic!(
                                "Found is_ancestor on set of non-entity-type {}",
                                val.value_kind()
                            );
                        }
                    }
                }
            }
        }
        ValueKind::ExtensionValue(_) => (),
        ValueKind::Record(record) => {
            for (field, child_slice) in &trie.children {
                // only need to slice if field is present
                if let Some(value) = record.get(field) {
                    find_remaining_entities_value(
                        remaining,
                        value,
                        child_slice,
                        required_ancestors,
                    )?;
                }
            }
        }
    };
    Ok(())
}

/// Traverse the already-loaded entities using the ancestors trie
/// to find the entity ids that are required.
fn compute_ancestors_request(
    entity_id: EntityUID,
    ancestors_trie: &RootAccessTrie,
    entities: &HashMap<EntityUID, Entity>,
    context: &Context,
    request: &Request,
) -> Result<AncestorsRequest, EntitySliceError> {
    // similar to load_entities, we traverse the access trie
    // this time using the already-loaded entities and looking for
    // is_ancestor tags.
    let mut ancestors = HashSet::new();

    let mut to_visit = initial_entities_to_load(ancestors_trie, context, request, &mut ancestors)?;

    while !to_visit.is_empty() {
        let mut next_to_visit = vec![];
        for entity_request in to_visit {
            // check the is_ancestor flag for entities
            // the is_ancestor flag on sets of entities is handled by find_remaining_entities
            if entity_request.access_trie.is_ancestor {
                ancestors.insert(entity_request.entity_id.clone());
            }

            if let Some(entity) = entities.get(&entity_request.entity_id) {
                next_to_visit.extend(find_remaining_entities(
                    entity,
                    entity_request.access_trie,
                    &mut ancestors,
                )?);
            }
        }
        to_visit = next_to_visit;
    }

    Ok(AncestorsRequest {
        entity_id,
        ancestors,
    })
}

#[cfg(test)]
mod test {
    use cedar_policy_core::ast::Value;
    use smol_str::ToSmolStr;

    use super::merge_values;

    #[test]
    fn test_merge_values() {
        assert_eq!(
            merge_values(Value::new(1, None), Value::new(1, None)),
            Value::new(1, None),
        );
        assert_eq!(
            merge_values(
                Value::set([Value::new(1, None), Value::new(2, None)], None),
                Value::set([Value::new(1, None), Value::new(2, None)], None),
            ),
            Value::set([Value::new(1, None), Value::new(2, None)], None),
        );
        assert_eq!(
            merge_values(
                Value::record([("a".to_smolstr(), Value::new(1, None))], None),
                Value::record([("a".to_smolstr(), Value::new(1, None))], None),
            ),
            Value::record([("a".to_smolstr(), Value::new(1, None))], None),
        );
        assert_eq!(
            merge_values(
                Value::empty_record(None),
                Value::record([("a".to_smolstr(), Value::new(1, None))], None),
            ),
            Value::record([("a".to_smolstr(), Value::new(1, None))], None),
        );
        assert_eq!(
            merge_values(
                Value::record([("a".to_smolstr(), Value::new(1, None))], None),
                Value::empty_record(None),
            ),
            Value::record([("a".to_smolstr(), Value::new(1, None))], None),
        );
        assert_eq!(
            merge_values(
                Value::record([("a".to_smolstr(), Value::new(1, None))], None),
                Value::record([("b".to_smolstr(), Value::new(2, None))], None),
            ),
            Value::record(
                [
                    ("a".to_smolstr(), Value::new(1, None)),
                    ("b".to_smolstr(), Value::new(2, None))
                ],
                None
            ),
        );
    }
}
