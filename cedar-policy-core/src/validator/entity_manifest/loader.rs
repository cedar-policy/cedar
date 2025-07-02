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

use smol_str::SmolStr;

use crate::{
    ast::{Entity, EntityUID, PartialValue, Request, Value, ValueKind, Var},
    entities::{Entities, NoEntitiesSchema, TCComputation},
    extensions::Extensions,
    validator::entity_manifest::{AccessPath, AccessPathVariant, AccessPaths, PathsForRequestType},
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
    /// The requested tags for the entity
    pub(crate) tags: HashSet<String>,
    /// A trie containing the access paths needed for this entity
    pub(crate) access_trie: AccessTrie,
}

/// A trie containing what attributes of an entity or record
/// are requested.
/// Children [`AccessTrie`] describe what fields of child records are requested.
/// These don't recur into other entities.
#[derive(Debug, Clone)]
pub(crate) struct AccessTrie {
    pub(crate) fields: HashMap<SmolStr, Box<AccessTrie>>,
}

impl AccessTrie {
    /// Creates a new empty AccessTrie
    pub(crate) fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    /// Gets or creates a field in this AccessTrie
    pub(crate) fn get_or_create_field(&mut self, field: &SmolStr) -> &mut Box<AccessTrie> {
        self.fields
            .entry(field.clone())
            .or_insert_with(|| Box::new(AccessTrie::new()))
    }
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

impl PathsForRequestType {
    /// Build a hashmap of parent paths for all reachable paths
    fn build_parents_map(
        &self,
        reachable_paths: &HashSet<AccessPath>,
    ) -> HashMap<AccessPath, Vec<AccessPath>> {
        let mut parents_map = HashMap::new();

        // Initialize the map with empty vectors for all paths
        for path in reachable_paths {
            parents_map.insert(path.clone(), Vec::new());
        }

        // Populate the map with parent-child relationships
        for path in reachable_paths {
            // Get all children of this path
            let children = path.children(&self.dag);

            for child in children {
                // Add this path as a parent of the child
                if let Some(child_parents) = parents_map.get_mut(&child) {
                    child_parents.push(path.clone());
                }
            }
        }

        parents_map
    }

    /// Helper function to get the manifest dependent entity paths of an access path
    /// A manifest dependent entity for node A is a node B such that A ->* B points to B
    /// with a path such that no intermediate nodes are entity typed
    fn get_manifest_dependent_entities(
        &self,
        path: &AccessPath,
        parents_map: &HashMap<AccessPath, Vec<AccessPath>>,
    ) -> Vec<AccessPath> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = Vec::new();

        // Start with the current path
        queue.push(path.clone());
        visited.insert(path.clone());

        while let Some(current) = queue.pop() {
            // Skip the starting node when checking if it's an entity
            if &current != path && self.is_entity_path(&current) {
                // Found an entity parent
                result.push(current);
                // Don't explore beyond this entity
                continue;
            }

            // Get the parents of the current path
            if let Some(parents) = parents_map.get(&current) {
                for parent in parents {
                    if !visited.contains(parent) {
                        visited.insert(parent.clone());
                        queue.push(parent.clone());
                    }
                }
            }
        }

        result
    }

    /// For each reachable [`AccessPath`] in the path with
    /// an entity type, computes the [`AccessTrie`] needed
    /// for that entity.
    ///
    /// This is a helper which computes the access tries needed during
    /// entity loading with the [`EntityLoader`] API.
    fn compute_access_tries(&self) -> HashMap<AccessPath, AccessTrie> {
        // First, compute all reachable paths
        let reachable_paths = self.reachable_paths();

        // Build a parents map for efficient parent lookup
        let parents_map = self.build_parents_map(&reachable_paths);

        // Find all entity paths among the reachable paths
        let entity_paths = self.get_entity_paths(&reachable_paths);

        // Build the AccessTrie for each entity path
        let mut result = HashMap::new();
        for entity_path in entity_paths {
            let trie =
                self.build_access_trie_for_entity(&entity_path, &reachable_paths, &parents_map);
            if !trie.fields.is_empty() {
                result.insert(entity_path, trie);
            }
        }

        result
    }

    /// Helper function to determine if a path has an entity type
    fn is_entity_path(&self, path: &AccessPath) -> bool {
        // Check if we have type information
        if let Some(types) = &self.dag.types {
            if path.id < types.len() {
                // Check if the type is an entity type
                use crate::validator::types::EntityRecordKind;
                match &types[path.id] {
                    crate::validator::types::Type::EntityOrRecord(kind) => {
                        matches!(
                            kind,
                            EntityRecordKind::Entity(_) | EntityRecordKind::AnyEntity
                        )
                    }
                    _ => false,
                }
            } else {
                false
            }
        } else {
            // Without type information, check if it's a root path (Literal or Var)
            if let Ok(variant) = path.get_variant(&self.dag) {
                matches!(
                    variant,
                    AccessPathVariant::Literal(_) | AccessPathVariant::Var(_)
                )
            } else {
                false
            }
        }
    }

    /// Helper function to get all entity paths among the reachable paths
    fn get_entity_paths(&self, reachable_paths: &HashSet<AccessPath>) -> HashSet<AccessPath> {
        reachable_paths
            .iter()
            .filter(|path| self.is_entity_path(path))
            .cloned()
            .collect()
    }

    /// Recursively build the AccessTrie for an entity path
    fn build_access_trie_for_entity(
        &self,
        entity_path: &AccessPath,
        reachable_paths: &HashSet<AccessPath>,
        parents_map: &HashMap<AccessPath, Vec<AccessPath>>,
    ) -> AccessTrie {
        let mut trie = AccessTrie::new();

        // Get all direct children (attributes) of this entity path
        for child in entity_path.children(&self.dag) {
            // Get the attribute name if this is an attribute relationship
            let attr = if let Ok(variant) = child.get_variant(&self.dag) {
                if let AccessPathVariant::Attribute { attr, .. } = variant {
                    attr.clone()
                } else {
                    continue; // Skip non-attribute relationships
                }
            } else {
                continue; // Skip if we can't get the variant
            };

            // Use child as the child_path
            let child_path = child;
            // Skip if the child path is also an entity (don't recur into sub-entities)
            if self.is_entity_path(&child_path) {
                continue;
            }

            // Get the manifest dependent entities of this child path
            let dependent_entities = self.get_manifest_dependent_entities(&child_path, parents_map);

            // Skip if this child has other dependent entities besides the current entity
            // This ensures we don't include fields that belong to other entities
            if dependent_entities.iter().any(|p| p != entity_path) {
                continue;
            }

            // Get or create the field in the trie
            let field_trie = trie.get_or_create_field(&attr);

            // Recursively build the trie for this field's children
            let child_trie =
                self.build_access_trie_for_entity(&child_path, reachable_paths, parents_map);

            // Merge the child trie into the field trie
            if !child_trie.fields.is_empty() {
                *field_trie = Box::new(child_trie);
            }
        }

        trie
    }

    /// Computes all reachable paths.
    /// Currently inefficient in the presense of sharing between paths
    /// because it uses the subpaths method.
    fn reachable_paths(&self) -> HashSet<AccessPath> {
        let mut result = HashSet::new();

        // Iterate through all access paths in the PathsForRequestType
        for path in &self.access_paths.paths {
            // For each path, get all its subpaths (including itself)
            // and add them to the result set
            let subpaths = path.subpaths(&self.dag);
            result.extend(subpaths.paths().clone());
        }

        result
    }
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
    let parents_map = for_request.build_parents_map(&reachable_paths);

    // Create a map to track which entities we've already processed
    let mut processed_entities = HashSet::new();

    // Create initial entity requests for entities that need to be loaded
    let mut to_load = Vec::new();
    let mut entities_map = HashMap::new();
    let mut to_find_ancestors = Vec::new();

    // Add requests for principal, action, and resource if they have access tries
    if let Some(principal_uid) = request.principal().uid() {
        for (entity_path, trie) in &access_tries {
            if let Ok(variant) = entity_path.get_variant(&for_request.dag) {
                if let AccessPathVariant::Var(Var::Principal) = variant {
                    to_load.push(EntityRequest {
                        entity_id: principal_uid.clone(),
                        tags: HashSet::new(), // No tags for now
                        access_trie: (*trie).clone(),
                    });
                    processed_entities.insert(principal_uid.clone());
                    break;
                }
            }
        }
    }

    if let Some(action_uid) = request.action().uid() {
        for (entity_path, trie) in &access_tries {
            if let Ok(variant) = entity_path.get_variant(&for_request.dag) {
                if let AccessPathVariant::Var(Var::Action) = variant {
                    to_load.push(EntityRequest {
                        entity_id: action_uid.clone(),
                        tags: HashSet::new(), // No tags for now
                        access_trie: (*trie).clone(),
                    });
                    processed_entities.insert(action_uid.clone());
                    break;
                }
            }
        }
    }

    if let Some(resource_uid) = request.resource().uid() {
        for (entity_path, trie) in &access_tries {
            if let Ok(variant) = entity_path.get_variant(&for_request.dag) {
                if let AccessPathVariant::Var(Var::Resource) = variant {
                    to_load.push(EntityRequest {
                        entity_id: resource_uid.clone(),
                        tags: HashSet::new(), // No tags for now
                        access_trie: (*trie).clone(),
                    });
                    processed_entities.insert(resource_uid.clone());
                    break;
                }
            }
        }
    }

    // Add requests for literal entities
    for (entity_path, trie) in &access_tries {
        if let Ok(variant) = entity_path.get_variant(&for_request.dag) {
            if let AccessPathVariant::Literal(euid) = variant {
                if !processed_entities.contains(euid) {
                    to_load.push(EntityRequest {
                        entity_id: euid.clone(),
                        tags: HashSet::new(), // No tags for now
                        access_trie: (*trie).clone(),
                    });
                    processed_entities.insert(euid.clone());
                }
            }
        }
    }

    // If there's nothing to load, return empty entities
    if to_load.is_empty() {
        match Entities::from_entities(
            vec![],
            None::<&NoEntitiesSchema>,
            TCComputation::AssumeAlreadyComputed,
            Extensions::all_available(),
        ) {
            Ok(entities) => return Ok(entities),
            Err(err) => return Err(err.into()),
        };
    }

    // Main loop of loading entities, one batch at a time
    while !to_load.is_empty() {
        // Record entities for ancestor loading later
        for entity_request in &to_load {
            to_find_ancestors.push(entity_request.entity_id.clone());
        }

        // Load the current batch of entities
        let loaded_entities = loader.load_entities(&to_load, for_request.dag.clone())?;

        if loaded_entities.len() != to_load.len() {
            return Err(WrongNumberOfEntitiesError {
                expected: to_load.len(),
                got: loaded_entities.len(),
            }
            .into());
        }

        // Process loaded entities and prepare next batch to load
        let mut next_to_load = Vec::new();

        for (entity_request, entity_maybe) in to_load.into_iter().zip(loaded_entities) {
            if let Some(entity) = entity_maybe {
                // Find entity paths that correspond to this entity
                for (entity_path, trie) in &access_tries {
                    if let Ok(variant) = entity_path.get_variant(&for_request.dag) {
                        let matches = match variant {
                            AccessPathVariant::Literal(euid) => euid == &entity_request.entity_id,
                            AccessPathVariant::Var(Var::Principal) => {
                                request.principal().uid() == Some(&entity_request.entity_id)
                            }
                            AccessPathVariant::Var(Var::Resource) => {
                                request.resource().uid() == Some(&entity_request.entity_id)
                            }
                            AccessPathVariant::Var(Var::Action) => {
                                request.action().uid() == Some(&entity_request.entity_id)
                            }
                            _ => false,
                        };

                        if matches {
                            // Find dependent entities for this entity path
                            let dependent_entities = for_request
                                .get_manifest_dependent_entities(entity_path, &parents_map);

                            // Add dependent entities to the next batch if they haven't been processed yet
                            for dependent_path in dependent_entities {
                                if let Ok(dependent_variant) =
                                    dependent_path.get_variant(&for_request.dag)
                                {
                                    if let Some(dependent_euid) = match dependent_variant {
                                        AccessPathVariant::Literal(euid) => Some(euid.clone()),
                                        AccessPathVariant::Var(Var::Principal) => {
                                            request.principal().uid().cloned()
                                        }
                                        AccessPathVariant::Var(Var::Resource) => {
                                            request.resource().uid().cloned()
                                        }
                                        AccessPathVariant::Var(Var::Action) => {
                                            request.action().uid().cloned()
                                        }
                                        _ => None,
                                    } {
                                        if !processed_entities.contains(&dependent_euid) {
                                            // Get the access trie for this dependent entity
                                            let dependent_trie = access_tries
                                                .get(&dependent_path)
                                                .map(|t| (*t).clone())
                                                .unwrap_or_else(AccessTrie::new);

                                            next_to_load.push(EntityRequest {
                                                entity_id: dependent_euid.clone(),
                                                tags: HashSet::new(),
                                                access_trie: dependent_trie,
                                            });
                                            processed_entities.insert(dependent_euid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Add or merge the entity into our map
                match entities_map.entry(entity_request.entity_id) {
                    hash_map::Entry::Occupied(o) => {
                        // If the entity is already present, merge it
                        let (k, v) = o.remove_entry();
                        let merged = merge_entities(v, entity);
                        entities_map.insert(k, merged);
                    }
                    hash_map::Entry::Vacant(v) => {
                        v.insert(entity);
                    }
                }
            }
        }

        // Update to_load for the next iteration
        to_load = next_to_load;
    }

    // Load ancestors for all entities
    let mut ancestors_requests = Vec::new();

    for entity_id in to_find_ancestors {
        // For now, we don't have specific ancestor requirements
        // so we just request all ancestors
        ancestors_requests.push(AncestorsRequest {
            entity_id,
            ancestors: HashSet::new(), // Empty set means all ancestors
        });
    }

    if !ancestors_requests.is_empty() {
        let loaded_ancestors = loader.load_ancestors(&ancestors_requests)?;

        // Add ancestors to entities
        for (request, ancestors) in ancestors_requests.into_iter().zip(loaded_ancestors) {
            if let Some(entity) = entities_map.get_mut(&request.entity_id) {
                for ancestor in ancestors {
                    entity.add_parent(ancestor);
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
