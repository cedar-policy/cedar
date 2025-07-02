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
    ast::{Entity, EntityUID, PartialValue, Request, Value, ValueKind, Var},
    entities::{Entities, NoEntitiesSchema, TCComputation},
    extensions::Extensions,
    validator::entity_manifest::{AccessPath, AccessPathVariant, AccessPaths},
};

use crate::validator::entity_manifest::{
    slicing::{
        EntitySliceError, PartialContextError, PartialEntityError, WrongNumberOfEntitiesError,
    },
    AccessDag, EntityManifest, EntityRoot, PartialRequestError,
};

/// A request that an entity be loaded.
/// Optionally, instead of loading the full entity the `access_trie`
/// may be used to load only some fields of the entity.
#[derive(Debug)]
pub(crate) struct EntityRequest {
    /// The id of the entity requested
    pub(crate) entity_id: EntityUID,
    /// The fields of the entity requested, a set of paths
    /// each with root `entity_id`.
    pub(crate) access_paths: AccessPaths,
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
    /// Each [`EntityRequest`] comes with [`AccessPaths`], which can optionally be used.
    /// Only fields mentioned in the entity's [`AccessPaths`] are needed, but it is sound to provide other fields as well.
    /// Note that the same entity may be requested multiple times, with different [`AccessPaths`]s.
    ///
    /// `load_entities` must load all the ancestors of each entity unless `load_ancestors` is implemented.
    fn load_entities(
        &mut self,
        to_load: &[EntityRequest],
        store: AccessDag,
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

// fn initial_entities_to_load<'a>(
//     root_access_trie: &'a AccessDag,
//     context: &Context,
//     request: &Request,
//     required_ancestors: &mut HashSet<EntityUID>,
// ) -> Result<Vec<EntityRequestRef<'a>>, EntitySliceError> {
//     let Context::Value(context_value) = &context else {
//         return Err(PartialContextError {}.into());
//     };

//     let mut to_load = match root_access_trie.trie.get(&EntityRoot::Var(Var::Context)) {
//         Some(access_trie) => {
//             find_remaining_entities_context(context_value, access_trie, required_ancestors)?
//         }
//         _ => vec![],
//     };

//     for (key, access_trie) in &root_access_trie.trie {
//         to_load.push(EntityRequestRef {
//             entity_id: match key {
//                 EntityRoot::Var(Var::Principal) => request
//                     .principal()
//                     .uid()
//                     .ok_or(PartialRequestError {})?
//                     .clone(),
//                 EntityRoot::Var(Var::Action) => request
//                     .action()
//                     .uid()
//                     .ok_or(PartialRequestError {})?
//                     .clone(),
//                 EntityRoot::Var(Var::Resource) => request
//                     .resource()
//                     .uid()
//                     .ok_or(PartialRequestError {})?
//                     .clone(),
//                 EntityRoot::Literal(lit) => lit.clone(),
//                 EntityRoot::Var(Var::Context) => continue,
//             },
//             access_trie,
//         });
//     }

//     Ok(to_load)
// }

/// Loads entities based on the entity manifest, request, and
/// the implemented [`EntityLoader`].
pub(crate) fn load_entities(
    manifest: &EntityManifest,
    request: &Request,
    loader: &mut dyn EntityLoader,
) -> Result<Entities, EntitySliceError> {
    let Some(for_request) = manifest
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

    let mut reachable_access_paths = AccessPaths::default();
    for path in for_request.access_paths.paths() {
        reachable_access_paths.extend(path.subpaths(&for_request.dag));
    }

    let context = request.context().ok_or(PartialRequestError {})?;

    let mut entities: HashMap<EntityUID, Entity> = Default::default();
    
    // Step 1: Identify all leaf nodes in the reachable_access_paths
    // A leaf node is a path that doesn't appear as a parent in any other path
    let mut leaf_paths = HashSet::new();
    let mut parent_paths = HashSet::new();
    
    // First, collect all paths that are parents
    for path in &reachable_access_paths.paths {
        match path.get_variant(&for_request.dag) {
            Ok(variant) => match variant {
                AccessPathVariant::Attribute { of, .. } => {
                    parent_paths.insert(of.clone());
                }
                AccessPathVariant::Tag { of, tag } => {
                    parent_paths.insert(of.clone());
                    parent_paths.insert(tag.clone());
                }
                AccessPathVariant::Ancestor { of, ancestor } => {
                    parent_paths.insert(of.clone());
                    parent_paths.insert(ancestor.clone());
                }
                _ => {}
            },
            Err(_) => continue, // Skip paths that can't be found in the DAG
        }
    }
    
    // Then, identify leaf paths (paths that are not parents)
    for path in &reachable_access_paths.paths {
        if !parent_paths.contains(path) {
            leaf_paths.insert(path.clone());
        }
    }
    
    // Step 2: Process paths in layers, starting from leaf nodes and moving up
    let mut processed_paths = HashSet::new();
    let mut to_process = leaf_paths;
    let mut entity_requests = Vec::new();
    let mut entity_id_map: HashMap<AccessPath, EntityUID> = HashMap::new();
    
    // Process each layer until no more paths are left to process
    while !to_process.is_empty() {
        let current_layer = to_process;
        to_process = HashSet::new();
        let mut next_layer_paths = HashSet::new();
        
        // Group paths by entity ID for batch loading
        let mut path_groups: HashMap<EntityUID, AccessPaths> = HashMap::new();
        
        // Process current layer paths
        for path in current_layer {
            if processed_paths.contains(&path) {
                continue;
            }
            
            processed_paths.insert(path.clone());
            
            // Determine the entity ID for this path
            let entity_id = match path.get_variant(&for_request.dag) {
                Ok(variant) => match variant {
                    AccessPathVariant::Literal(euid) => euid.clone(),
                    AccessPathVariant::Var(var) => match var {
                        Var::Principal => request.principal().uid().ok_or(PartialRequestError {})?.clone(),
                        Var::Action => request.action().uid().ok_or(PartialRequestError {})?.clone(),
                        Var::Resource => request.resource().uid().ok_or(PartialRequestError {})?.clone(),
                        Var::Context => continue, // Context is handled separately
                    },
                    AccessPathVariant::Attribute { of, .. } => {
                        // If we have the entity ID for the parent path, use it
                        if let Some(parent_id) = entity_id_map.get(of) {
                            // Add the parent path to the next layer if not processed
                            if !processed_paths.contains(of) {
                                next_layer_paths.insert(of.clone());
                            }
                            parent_id.clone()
                        } else {
                            // Otherwise, add the parent path to the next layer
                            next_layer_paths.insert(of.clone());
                            continue; // Skip this path for now
                        }
                    },
                    AccessPathVariant::Tag { of, .. } => {
                        // Similar to attribute, we need the parent entity ID
                        if let Some(parent_id) = entity_id_map.get(of) {
                            if !processed_paths.contains(of) {
                                next_layer_paths.insert(of.clone());
                            }
                            parent_id.clone()
                        } else {
                            next_layer_paths.insert(of.clone());
                            continue;
                        }
                    },
                    AccessPathVariant::Ancestor { of, .. } => {
                        // For ancestors, we need the entity whose ancestors we're checking
                        if let Some(entity_id) = entity_id_map.get(of) {
                            if !processed_paths.contains(of) {
                                next_layer_paths.insert(of.clone());
                            }
                            entity_id.clone()
                        } else {
                            next_layer_paths.insert(of.clone());
                            continue;
                        }
                    },
                    AccessPathVariant::String(_) => continue, // String literals don't need entity loading
                },
                Err(_) => continue, // Skip paths that can't be found in the DAG
            };
            
            // Map this path to its entity ID for future reference
            entity_id_map.insert(path.clone(), entity_id.clone());
            
            // Group paths by entity ID
            path_groups
                .entry(entity_id)
                .or_insert_with(AccessPaths::default)
                .insert(path);
        }
        
        // Create entity requests for this layer
        for (entity_id, access_paths) in path_groups {
            entity_requests.push(EntityRequest {
                entity_id,
                access_paths,
            });
        }
        
        // If we have entity requests, load them
        if !entity_requests.is_empty() {
            let loaded_entities = loader.load_entities(&entity_requests, for_request.dag.clone())?;
            
            if loaded_entities.len() != entity_requests.len() {
                return Err(WrongNumberOfEntitiesError {
                    expected: entity_requests.len(),
                    got: loaded_entities.len(),
                }
                .into());
            }
            
            // Process loaded entities
            for (request, entity_option) in entity_requests.iter().zip(loaded_entities) {
                if let Some(entity) = entity_option {
                    // Merge with existing entity if it exists
                    match entities.entry(request.entity_id.clone()) {
                        hash_map::Entry::Occupied(o) => {
                            let (k, v) = o.remove_entry();
                            let merged = merge_entities(v, entity);
                            entities.insert(k, merged);
                        }
                        hash_map::Entry::Vacant(v) => {
                            v.insert(entity);
                        }
                    }
                }
            }
            
            // Clear entity requests for the next layer
            entity_requests.clear();
        }
        
        // Add next layer paths to process
        to_process = next_layer_paths;
    }
    
    // Step 3: Load ancestors for all entities
    let mut ancestors_requests = Vec::new();
    for (entity_id, _) in &entities {
        // Create an ancestors request for each entity
        ancestors_requests.push(AncestorsRequest {
            entity_id: entity_id.clone(),
            ancestors: HashSet::new(), // Load all ancestors
        });
    }
    
    if !ancestors_requests.is_empty() {
        let loaded_ancestors = loader.load_ancestors(&ancestors_requests)?;
        
        if loaded_ancestors.len() != ancestors_requests.len() {
            return Err(WrongNumberOfEntitiesError {
                expected: ancestors_requests.len(),
                got: loaded_ancestors.len(),
            }
            .into());
        }
        
        // Add ancestors to entities
        for (request, ancestors) in ancestors_requests.into_iter().zip(loaded_ancestors) {
            if let Some(entity) = entities.get_mut(&request.entity_id) {
                ancestors
                    .into_iter()
                    .for_each(|ancestor| entity.add_parent(ancestor));
            }
        }
    }
    
    // Finally, convert the loaded entities into a Cedar Entities store
    match Entities::from_entities(
        entities.into_values(),
        None::<&NoEntitiesSchema>,
        TCComputation::AssumeAlreadyComputed,
        Extensions::all_available(),
    ) {
        Ok(entities) => Ok(entities),
        Err(e) => Err(e.into()),
    }


    // Old code using trie
    // entity requests in progress
    // let mut to_load: Vec<EntityRequestRef<'_>> =
    //     initial_entities_to_load(root_access_trie, context, request, &mut Default::default())?;
    // // later, find the ancestors of these entities using their ancestor tries
    // let mut to_find_ancestors = vec![];

    // // Main loop of loading entities, one batch at a time
    // while !to_load.is_empty() {
    //     // first, record the entities in `to_find_ancestors`
    //     for entity_request in &to_load {
    //         to_find_ancestors.push((
    //             entity_request.entity_id.clone(),
    //             &entity_request.access_trie.ancestors_trie,
    //         ));
    //     }

    //     let new_entities = loader.load_entities(
    //         &to_load
    //             .iter()
    //             .map(|entity_ref| entity_ref.to_request())
    //             .collect::<Vec<_>>(),
    //     )?;
    //     if new_entities.len() != to_load.len() {
    //         return Err(WrongNumberOfEntitiesError {
    //             expected: to_load.len(),
    //             got: new_entities.len(),
    //         }
    //         .into());
    //     }

    //     let mut next_to_load = vec![];
    //     for (entity_request, loaded_maybe) in to_load.into_iter().zip(new_entities) {
    //         if let Some(loaded) = loaded_maybe {
    //             next_to_load.extend(find_remaining_entities(
    //                 &loaded,
    //                 entity_request.access_trie,
    //                 &mut Default::default(),
    //             )?);
    //             match entities.entry(entity_request.entity_id) {
    //                 hash_map::Entry::Occupied(o) => {
    //                     // If the entity is already present in the slice, then
    //                     // we need to be careful not to clobber its existing
    //                     // attributes.  This can happen when an entity is
    //                     // referenced by both an entity literal and a variable.
    //                     let (k, v) = o.remove_entry();
    //                     let merged = merge_entities(v, loaded);
    //                     entities.insert(k, merged);
    //                 }
    //                 hash_map::Entry::Vacant(v) => {
    //                     v.insert(loaded);
    //                 }
    //             }
    //         }
    //     }

    //     to_load = next_to_load;
    // }

    // // now that all the entities are loaded
    // // we need to load their ancestors
    // let mut ancestors_requests = vec![];
    // for (entity_id, ancestors_trie) in to_find_ancestors {
    //     ancestors_requests.push(compute_ancestors_request(
    //         entity_id,
    //         ancestors_trie,
    //         &entities,
    //         context,
    //         request,
    //     )?);
    // }

    // let loaded_ancestors = loader.load_ancestors(&ancestors_requests)?;
    // for (request, ancestors) in ancestors_requests.into_iter().zip(loaded_ancestors) {
    //     if let Some(entity) = entities.get_mut(&request.entity_id) {
    //         ancestors
    //             .into_iter()
    //             .for_each(|ancestor| entity.add_parent(ancestor));
    //     }
    // }

    // // finally, convert the loaded entities into a Cedar Entities store
    // match Entities::from_entities(
    //     entities.into_values(),
    //     None::<&NoEntitiesSchema>,
    //     TCComputation::AssumeAlreadyComputed,
    //     Extensions::all_available(),
    // ) {
    //     Ok(entities) => Ok(entities),
    //     Err(e) => Err(e.into()),
    // }
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
