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
    iter::IntoIterator,
    sync::Arc,
};

use smol_str::SmolStr;

use crate::{
    ast::{Entity, EntityUID, Literal, PartialValue, Request, Value, ValueKind},
    entities::{Entities, NoEntitiesSchema, TCComputation},
    extensions::Extensions,
    validator::entity_manifest::{
        errors::{
            ConflictingEntityDataError, ExpectedEntityOrEntitySetError, ExpectedEntityTypeError,
            ExpectedStringTypeError,
        },
        manifest_helpers::{AccessTrie, EntityRequestContext},
        AccessTermVariant, EntityManifest,
    },
};

use crate::validator::entity_manifest::errors::{
    EntitySliceError, PartialRequestError, ResidualEncounteredError,
};


/// A request that an entity be loaded.
/// Entities this entity references need not be loaded, as they will be requested separately.
///
/// Optionally, instead of loading the full entity the `access_trie`
/// may be used to load only some fields of the entity and the `tags` field
/// can be used to load only specific tags.
#[derive(Debug)]
pub(crate) struct EntityRequest {
    /// The id of the entity requested
    pub(crate) entity_id: EntityUID,
    /// The requested tags for the entity, if any
    /// Each tag's value can be loaded completely or (in the case of records) partially using the associated `AccessTrie`.
    pub(crate) tags: HashMap<SmolStr, AccessTrie>,
    /// A trie containing the access paths needed for this entity
    pub(crate) access_trie: AccessTrie,
}

/// A collection of entity requests, indexed by entity ID.
/// When multiple requests are added for the same entity, they are unioned together.
#[derive(Debug, Default)]
pub(crate) struct EntityRequests {
    /// Map from entity ID to entity request
    requests: HashMap<EntityUID, EntityRequest>,
}

impl EntityRequests {
    /// Creates a new empty collection of entity requests.
    pub(crate) fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    /// Adds an entity request to the collection.
    /// If a request for the same entity already exists, the requests are unioned.
    /// Empty requests (with no fields or tags) are not added.
    pub(crate) fn add(&mut self, request: EntityRequest) {
        // Skip empty requests
        if request.is_empty() {
            return;
        }

        match self.requests.entry(request.entity_id.clone()) {
            hash_map::Entry::Occupied(mut entry) => {
                // If a request for this entity already exists, union the requests
                entry.get_mut().union_with(&request);
            }
            hash_map::Entry::Vacant(entry) => {
                // If no request for this entity exists, add it
                entry.insert(request);
            }
        }
    }

    /// Clears all entity requests from the collection.
    pub(crate) fn clear(&mut self) {
        self.requests.clear();
    }
}

impl IntoIterator for EntityRequests {
    type Item = EntityRequest;
    type IntoIter = std::collections::hash_map::IntoValues<EntityUID, EntityRequest>;

    fn into_iter(self) -> Self::IntoIter {
        self.requests.into_values()
    }
}

impl<'a> IntoIterator for &'a EntityRequests {
    type Item = &'a EntityRequest;
    type IntoIter = std::collections::hash_map::Values<'a, EntityUID, EntityRequest>;

    fn into_iter(self) -> Self::IntoIter {
        self.requests.values()
    }
}

impl EntityRequest {
    /// Returns true if this request is empty (has no fields or tags to load).
    pub(crate) fn is_empty(&self) -> bool {
        self.access_trie.is_empty() && self.tags.is_empty()
    }

    /// Unions this [`EntityRequest`] with another, modifying this request in place.
    /// After this operation, this request will contain all fields and tags from both requests.
    /// If both requests have the same tag, the tag tries are recursively unioned.
    pub(crate) fn union_with(&mut self, other: &EntityRequest) {
        // Union the access tries
        self.access_trie.union_with(&other.access_trie);

        // Union the tags
        for (tag_name, tag_trie) in &other.tags {
            match self.tags.entry(tag_name.clone()) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    // If both requests have the same tag, recursively union the tag tries
                    entry.get_mut().union_with(tag_trie);
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    // If only the other request has this tag, clone it into this request
                    entry.insert(tag_trie.clone());
                }
            }
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

/// A collection of ancestor requests, indexed by entity ID.
#[derive(Debug, Default)]
pub(crate) struct AncestorRequests {
    /// Map from entity ID to ancestor request
    requests: HashMap<EntityUID, AncestorsRequest>,
}

impl AncestorRequests {
    /// Creates a new empty collection of ancestor requests.
    pub(crate) fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    /// Computes ancestor requests from the given request type terms, entities map, and request.
    pub(crate) fn compute_from_request<'a>(
        for_request: &'a crate::validator::entity_manifest::RequestTypeTerms,
        entities_map: &HashMap<EntityUID, Entity>,
        request: &'a Request,
    ) -> Result<Self, EntitySliceError> {
        let mut ancestor_requests = Self::new();

        // Compute ancestors requests by finding all AccessTermVariant::Ancestor variants
        // Look up the entity ids in the Entities store using the terms
        // Then create an ancestor request
        let reachable_terms = for_request.reachable_terms();
        for term in reachable_terms.iter() {
            if let Ok(AccessTermVariant::Ancestor { of, ancestor }) =
                term.get_variant(&for_request.dag)
            {
                // Extract EntityUID from the Value
                let of_val_result = of.compute_value(entities_map, &for_request.dag, request)?;
                let ancestor_val_result =
                    ancestor.compute_value(entities_map, &for_request.dag, request)?;

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

                // Ancestor value can be a UID or a set of UIDs
                let ancestors_to_request = match ancestor_val_result.value_kind() {
                    ValueKind::Lit(Literal::EntityUID(euid)) => {
                        vec![(**euid).clone()].into_iter().collect()
                    }
                    ValueKind::Set(set) => {
                        // Make a set of EntityUIDs from the set
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

                // If there is an existing ancestor request, add to it
                // Otherwise make a new one
                let ancestor_request = ancestor_requests
                    .requests
                    .entry(of_val.clone())
                    .or_insert_with(|| AncestorsRequest {
                        entity_id: of_val,
                        ancestors: HashSet::new(),
                    });
                ancestor_request.ancestors.extend(ancestors_to_request);
            }
        }

        Ok(ancestor_requests)
    }

    /// Loads ancestors for all entities in the collection and adds them to the entities map.
    pub(crate) fn load_ancestors(
        self,
        loader: &mut dyn EntityLoader,
        entities_map: &mut HashMap<EntityUID, Entity>,
    ) -> Result<(), EntitySliceError> {
        if self.requests.is_empty() {
            return Ok(());
        }

        // Convert HashMap to Vec for the loader API
        let ancestors_requests_vec: Vec<AncestorsRequest> = self.requests.into_values().collect();

        let loaded_ancestors = loader.load_ancestors(&ancestors_requests_vec)?;

        // Add ancestors to entities
        for (request, ancestors) in ancestors_requests_vec.into_iter().zip(loaded_ancestors) {
            if let Some(entity) = entities_map.get_mut(&request.entity_id) {
                for ancestor in ancestors {
                    entity.add_parent(ancestor);
                }
            } else {
                // Otherwise, we need to create the entity if ancestors is not empty
                if !ancestors.is_empty() {
                    let entity_id = request.entity_id.clone();
                    let entity = Entity::new_with_attr_partial_value(
                        entity_id.clone(),
                        HashMap::new(),
                        HashSet::new(),
                        ancestors,
                        [],
                    );
                    entities_map.insert(entity_id, entity);
                }
            }
        }

        Ok(())
    }
}

/// Implement [`EntityLoader`] to easily load entities using their ids
/// into a Cedar [`Entities`] store.
/// The most basic implementation loads full entities (including all ancestors) in the `load_entities` method and loads the context in the `load_context` method.
/// More advanced implementations make use of the [`AccessTerms`]s provided to load partial entities and context, as well as the `load_ancestors` method to load particular ancestors.
///
/// Warning: `load_entities` is called multiple times. If database
/// consistency is required, this API should not be used. Instead, use the entity manifest directly.
pub(crate) trait EntityLoader {
    /// `load_entities` is called multiple times to load entities based on their ids.
    /// If an entity does not exist, it should be skipped.
    /// Each [`EntityRequest`] comes with [`AccessTrie`], which can optionally be used.
    /// Only fields mentioned in the entity's [`AccessTrie`] are needed, but it is sound to provide other fields as well.
    /// Note that the same entity may be requested multiple times, with different [`AccessTrie`]s.
    ///
    /// `load_entities` must load all the ancestors of each entity unless `load_ancestors` is implemented.
    fn load_entities(&mut self, to_load: &EntityRequests) -> Result<Vec<Entity>, EntitySliceError>;

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

/// Loads entities based on the entity manifest, request, and
/// the implemented [`EntityLoader`].
pub(crate) fn load_entities(
    manifest: &EntityManifest,
    request: &Request,
    loader: &mut dyn EntityLoader,
) -> Result<Entities, EntitySliceError> {
    // Get the RequestTypeTerms for this request type
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

    // Create the entity request context
    let mut context = EntityRequestContext::new(for_request, request);

    // Get initial entities to load and track processed entities
    let mut next_critical_terms = context.initial_critical_terms();
    // Collection of entity requests
    let mut entity_requests = EntityRequests::new();
    let mut visited_terms = HashSet::new();

    eprintln!("next_critical_terms: {next_critical_terms:?}");

    // Main loop of loading entities, one batch at a time
    while !next_critical_terms.is_empty() {
        // Prepare entity requests from the current batch of critical terms
        context.prepare_entity_requests_from_terms(
            &mut next_critical_terms,
            &mut visited_terms,
            &mut entity_requests,
        )?;

        // Load and merge entities for the current batch
        context.load_and_merge_entities(loader, &mut entity_requests)?;
    }

    // Compute and load ancestor requests
    let ancestor_requests =
        AncestorRequests::compute_from_request(for_request, context.entities_map(), request)?;
    ancestor_requests.load_ancestors(loader, context.entities_map_mut())?;

    // Convert the loaded entities into a Cedar Entities store
    match Entities::from_entities(
        context.entities_map().clone().into_values(),
        None::<&NoEntitiesSchema>,
        TCComputation::AssumeAlreadyComputed,
        Extensions::all_available(),
    ) {
        Ok(entities) => Ok(entities),
        Err(e) => Err(e.into()),
    }
}

