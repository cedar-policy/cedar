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
    collections::{btree_map, hash_map, HashMap, HashSet},
    sync::Arc,
};

use crate::{
    ast::{Entity, EntityUID, Literal, PartialValue, Request, Value, ValueKind, Var},
    entities::{Entities, NoEntitiesSchema, TCComputation},
    extensions::Extensions,
    validator::entity_manifest::{
        errors::{ExpectedEntityOrEntitySetError, ExpectedEntityTypeError},
        manifest_helpers::AccessTrie,
        AccessPath, AccessPathVariant, EntityManifest, PathsForRequestType,
    },
};

use crate::validator::entity_manifest::errors::{
    EntitySliceError, PartialRequestError, WrongNumberOfEntitiesError,
};

/// A request that an entity be loaded.
/// Optionally, instead of loading the full entity the `access_trie`
/// may be used to load only some fields of the entity.
#[derive(Debug)]
pub(crate) struct EntityRequest {
    /// The id of the entity requested
    pub(crate) entity_id: EntityUID,
    /// The access path that resulted in this entity
    pub(crate) access_path: AccessPath,
    /// The requested tags for the entity TODO set these during loading
    pub(crate) tags: HashSet<String>,
    /// A trie containing the access paths needed for this entity
    pub(crate) access_trie: AccessTrie,
}

/// An entity request may be an entity or `None` when
/// the entity is not present.
pub(crate) type EntityAnswer = Option<Entity>;

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
/// More advanced implementations make use of the [`AccessPaths`]s provided to load partial entities and context, as well as the `load_ancestors` method to load particular ancestors.
///
/// Warning: `load_entities` is called multiple times. If database
/// consistency is required, this API should not be used. Instead, use the entity manifest directly.
pub(crate) trait EntityLoader {
    /// `load_entities` is called multiple times to load entities based on their ids.
    /// For each entity request in the `to_load` vector, expects one loaded entity in the resulting vector.
    /// Each [`EntityRequest`] comes with [`AccessTrie`], which can optionally be used.
    /// Only fields mentioned in the entity's [`AccessTrie`] are needed, but it is sound to provide other fields as well.
    /// Note that the same entity may be requested multiple times, with different [`AccessTrie`]s.
    ///
    /// `load_entities` must load all the ancestors of each entity unless `load_ancestors` is implemented.
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

/// Helper function to determine the initial entities to load based on the access tries
fn initial_entities_to_load(
    access_tries: &HashMap<AccessPath, AccessTrie>,
    for_request: &PathsForRequestType,
    request: &Request,
) -> Vec<EntityRequest> {
    let mut to_load = Vec::new();

    for (access_path, trie) in access_tries.iter() {
        if let Ok(variant) = access_path.get_variant(&for_request.dag) {
            let entity_id = match variant {
                AccessPathVariant::Var(Var::Principal) => request.principal().uid().cloned(),
                AccessPathVariant::Var(Var::Action) => request.action().uid().cloned(),
                AccessPathVariant::Var(Var::Resource) => request.resource().uid().cloned(),
                AccessPathVariant::Literal(euid) => Some(euid.clone()),
                _ => None,
            };

            if let Some(entity_id) = entity_id {
                to_load.push(EntityRequest {
                    entity_id,
                    tags: HashSet::new(), // No tags for now
                    access_trie: trie.clone(),
                    access_path: access_path.clone(),
                });
            }
        }
    }

    to_load
}

/// Loads entities based on the entity manifest, request, and
/// the implemented [`EntityLoader`].
pub(crate) fn load_entities(
    manifest: &EntityManifest,
    request: &Request,
    loader: &mut dyn EntityLoader,
) -> Result<Entities, EntitySliceError> {
    // Get the PathsForRequestType for this request type
    let Some(for_request) = manifest
        .per_action
        .get(&request.to_request_type().ok_or(PartialRequestError {})?)
    else {
        // If there's no entry for this request type, return empty entities
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

    // Compute the access tries for all entities
    let access_tries = for_request.compute_access_tries();

    // Build a map of entity paths to their dependent entities
    let reachable_paths = for_request.reachable_paths();
    let dependents_map = for_request.build_dependents_map(&reachable_paths);
    let dependent_entities_map = for_request.build_dependent_entities_map(&dependents_map);

    // Get initial entities to load and track processed entities
    let mut to_load = initial_entities_to_load(&access_tries, for_request, request);
    let mut entities_map: HashMap<EntityUID, Entity> = HashMap::new();
    let mut visited_paths = HashSet::new();

    // Main loop of loading entities, one batch at a time
    while !to_load.is_empty() {
        eprintln!("to load: {:?}", to_load);
        // Load the current batch of entities
        let loaded_entities = loader.load_entities(&to_load)?;
        eprintln!("loaded entities: {:?}", loaded_entities);

        if loaded_entities.len() != to_load.len() {
            return Err(WrongNumberOfEntitiesError {
                expected: to_load.len(),
                got: loaded_entities.len(),
            }
            .into());
        }

        for entity in loaded_entities.into_iter().flatten() {
            // Add or merge the entity into our map
            match entities_map.entry(entity.uid().clone()) {
                hash_map::Entry::Occupied(o) => {
                    // If the entity is already present, merge it
                    let (k, v) = o.remove_entry();
                    let merged = merge_entities(v, entity.clone());
                    entities_map.insert(k, merged);
                }
                hash_map::Entry::Vacant(v) => {
                    v.insert(entity.clone());
                }
            }
        }

        // Process loaded entities and prepare next batch to load
        let mut next_to_load = Vec::new();

        for entity_request in to_load.into_iter() {
            let entity_path = entity_request.access_path;

            // Find dependent entities for this entity path
            let dependent_entities = dependent_entities_map
                .get(&entity_path)
                .unwrap_or(&vec![])
                .clone();

            // Add dependent entities to the next batch if they haven't been processed yet
            for dependent_path in dependent_entities {
                if !visited_paths.insert(dependent_path.clone()) {
                    continue;
                }

                // get the id of the dependent path using the entity store
                let dependent_val =
                    dependent_path.compute_value(&entities_map, &for_request.dag, request)?;

                let dependent_id = match dependent_val.value_kind() {
                    ValueKind::Lit(Literal::EntityUID(euid)) => (**euid).clone(),
                    _ => {
                        return Err(ExpectedEntityTypeError {
                            found_value: dependent_val.clone(),
                        }
                        .into())
                    }
                };

                // Get the access trie for this dependent entity if any
                if let Some(dependent_trie) = access_tries.get(&dependent_path) {
                    next_to_load.push(EntityRequest {
                        entity_id: dependent_id.clone(),
                        tags: HashSet::new(),
                        access_trie: dependent_trie.clone(),
                        access_path: dependent_path.clone(),
                    });
                }
            }
        }

        // Update to_load for the next iteration
        to_load = next_to_load;
    }

    // Load ancestors for all entities
    let mut ancestors_requests = HashMap::new();

    // compute ancestors requests by finding all AccessPathVariant::Ancestor variants
    // look up the entity ids in the Entities store using the paths
    // then create an ancestor request
    for path in reachable_paths.iter() {
        if let Ok(AccessPathVariant::Ancestor { of, ancestor }) = path.get_variant(&for_request.dag)
        {
            // Extract EntityUID from the Value
            let of_val_result = of.compute_value(&entities_map, &for_request.dag, request)?;
            let ancestor_val_result =
                ancestor.compute_value(&entities_map, &for_request.dag, request)?;

            // Extract the EntityUID from the Value
            let of_val = match of_val_result.value_kind() {
                ValueKind::Lit(Literal::EntityUID(euid)) => (**euid).clone(),
                _ => {
                    return Err(ExpectedEntityTypeError {
                        found_value: of_val_result.clone(),
                    }
                    .into())
                }
            };

            // ancestor value can be a UID or a set of UIDs
            let ancestors_to_request = match ancestor_val_result.value_kind() {
                ValueKind::Lit(Literal::EntityUID(euid)) => {
                    vec![(**euid).clone()].into_iter().collect()
                }
                ValueKind::Set(set) => {
                    // make a set of EntityUIDs from the set
                    let mut resulting_set = HashSet::new();
                    for val in set.iter() {
                        if let ValueKind::Lit(Literal::EntityUID(euid)) = val.value_kind() {
                            resulting_set.insert((**euid).clone());
                        } else {
                            return Err(ExpectedEntityTypeError {
                                found_value: val.clone(),
                            }
                            .into());
                        }
                    }
                    resulting_set
                }
                _ => {
                    return Err(ExpectedEntityOrEntitySetError {
                        found_value: ancestor_val_result.clone(),
                    }
                    .into());
                }
            };

            // if there is an existing ancestor request, add to it
            // otherwise make a new one
            let ancestor_request =
                ancestors_requests
                    .entry(of_val.clone())
                    .or_insert_with(|| AncestorsRequest {
                        entity_id: of_val.clone(),
                        ancestors: HashSet::new(),
                    });
            ancestor_request.ancestors.extend(ancestors_to_request);
        }
    }

    eprintln!("ancestors requests: {:?}", ancestors_requests);

    if !ancestors_requests.is_empty() {
        // Convert HashMap to Vec for the loader API
        let ancestors_requests_vec: Vec<AncestorsRequest> =
            ancestors_requests.into_values().collect();

        let loaded_ancestors = loader.load_ancestors(&ancestors_requests_vec)?;

        // Add ancestors to entities
        for (request, ancestors) in ancestors_requests_vec.into_iter().zip(loaded_ancestors) {
            if let Some(entity) = entities_map.get_mut(&request.entity_id) {
                for ancestor in ancestors {
                    entity.add_parent(ancestor);
                }
            } else {
                // otherwise, we need to create the entity if ancestors is not empty
                if !ancestors.is_empty() {
                    let entity = Entity::new_with_attr_partial_value(
                        request.entity_id.clone(),
                        HashMap::new(),
                        HashSet::new(),
                        ancestors,
                        [], // TODO: entity slicing does not yet support tags
                    );
                    entities_map.insert(request.entity_id.clone(), entity);
                }
            }
        }
    }

    // Convert the loaded entities into a Cedar Entities store
    match Entities::from_entities(
        entities_map.into_values(),
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
