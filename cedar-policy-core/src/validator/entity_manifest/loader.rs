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
        manifest_helpers::AccessTrie,
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

    let reachable_terms = for_request.reachable_terms();
    // Map from term to dependents
    let dependents_map = for_request.build_dependents_map(&reachable_terms);
    // Map from a critical term to critical dependents
    let dependent_critical = for_request.build_dependent_critical_terms(&dependents_map);
    // Access tries for each critical term
    let access_tries = for_request.compute_access_tries(&dependent_critical, &dependents_map);

    // Get initial entities to load and track processed entities
    let mut next_critical_terms = for_request.initial_critical_terms(&access_tries);
    // Collection of entity requests
    let mut entity_requests = EntityRequests::new();
    let mut entities_map: HashMap<EntityUID, Entity> = HashMap::new();
    let mut visited_terms = HashSet::new();

    eprintln!("next_critical_terms: {next_critical_terms:?}");

    // Main loop of loading entities, one batch at a time
    while !next_critical_terms.is_empty() {
        // Prepare entity requests from the current batch of critical terms
        prepare_entity_requests_from_terms(
            &mut next_critical_terms,
            &mut visited_terms,
            &dependent_critical,
            &access_tries,
            for_request,
            &entities_map,
            request,
            &mut entity_requests,
        )?;

        // Load and merge entities for the current batch
        load_and_merge_entities(loader, &mut entity_requests, &mut entities_map)?;
    }

    // Load ancestors for all entities
    let mut ancestors_requests = HashMap::new();

    // compute ancestors requests by finding all AccessTermVariant::Ancestor variants
    // look up the entity ids in the Entities store using the terms
    // then create an ancestor request
    for term in reachable_terms.iter() {
        if let Ok(AccessTermVariant::Ancestor { of, ancestor }) = term.get_variant(&for_request.dag)
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
fn merge_entities(e1: Entity, e2: Entity) -> Result<Entity, EntitySliceError> {
    let (uid1, mut attrs1, ancestors1, parents1, tags1) = e1.into_inner();
    let (uid2, attrs2, ancestors2, parents2, tags2) = e2.into_inner();

    if uid1 != uid2 {
        return Err(ConflictingEntityDataError {
            entity_id: uid1.clone(),
            old_value: Value::new(ValueKind::Lit(Literal::EntityUID(Arc::new(uid1))), None),
            new_value: Value::new(ValueKind::Lit(Literal::EntityUID(Arc::new(uid2))), None),
        }
        .into());
    }

    // Merge ancestors
    let mut merged_ancestors = ancestors1;
    merged_ancestors.extend(ancestors2);

    // Merge parents
    let mut merged_parents = parents1;
    merged_parents.extend(parents2);

    // Merge tags
    let mut merged_tags = tags1;
    for (k, v2) in tags2 {
        match merged_tags.entry(k) {
            hash_map::Entry::Occupied(occupied) => {
                let (k, v1) = occupied.remove_entry();
                match (v1, v2) {
                    (PartialValue::Value(v1), PartialValue::Value(v2)) => {
                        let merged_v = merge_values(v1, v2, &uid1)?;
                        merged_tags.insert(k, PartialValue::Value(merged_v));
                    }
                    (PartialValue::Residual(_), PartialValue::Residual(_)) => {
                        return Err(ResidualEncounteredError { entity_id: uid1 }.into());
                    }
                    (PartialValue::Value(_), PartialValue::Residual(_))
                    | (PartialValue::Residual(_), PartialValue::Value(_)) => {
                        return Err(ResidualEncounteredError { entity_id: uid1 }.into());
                    }
                };
            }
            hash_map::Entry::Vacant(vacant) => {
                vacant.insert(v2);
            }
        }
    }

    for (k, v2) in attrs2 {
        match attrs1.entry(k) {
            hash_map::Entry::Occupied(occupied) => {
                let (k, v1) = occupied.remove_entry();
                match (v1, v2) {
                    (PartialValue::Value(v1), PartialValue::Value(v2)) => {
                        let merged_v = merge_values(v1, v2, &uid1)?;
                        attrs1.insert(k, PartialValue::Value(merged_v));
                    }
                    (PartialValue::Residual(_), PartialValue::Residual(_)) => {
                        return Err(ResidualEncounteredError { entity_id: uid1 }.into());
                    }
                    (PartialValue::Value(_), PartialValue::Residual(_))
                    | (PartialValue::Residual(_), PartialValue::Value(_)) => {
                        return Err(ResidualEncounteredError { entity_id: uid1 }.into());
                    }
                };
            }
            hash_map::Entry::Vacant(vacant) => {
                vacant.insert(v2);
            }
        }
    }

    Ok(Entity::new_with_attr_partial_value(
        uid1,
        attrs1,
        merged_ancestors,
        merged_parents,
        merged_tags,
    ))
}

/// Prepare entity requests from a batch of critical terms.
///
/// This function:
/// 1. Takes critical terms from `next_critical_terms`
/// 2. Adds their dependent terms to `next_critical_terms` for the next batch
/// 3. Processes entity-typed terms and tag terms, adding appropriate entity requests
fn prepare_entity_requests_from_terms(
    next_critical_terms: &mut Vec<crate::validator::entity_manifest::AccessTerm>,
    visited_terms: &mut HashSet<crate::validator::entity_manifest::AccessTerm>,
    dependent_critical: &HashMap<
        crate::validator::entity_manifest::AccessTerm,
        Vec<crate::validator::entity_manifest::AccessTerm>,
    >,
    access_tries: &HashMap<crate::validator::entity_manifest::AccessTerm, AccessTrie>,
    for_request: &crate::validator::entity_manifest::RequestTypeTerms,
    entities_map: &HashMap<EntityUID, Entity>,
    request: &Request,
    entity_requests: &mut EntityRequests,
) -> Result<(), EntitySliceError> {
    // Process each critical term in the current batch
    for critical_term in std::mem::take(next_critical_terms).into_iter() {
        // If we have already visited this term, skip it
        if !visited_terms.insert(critical_term.clone()) {
            continue;
        }

        // Add dependent critical terms to the next batch
        // PANIC SAFETY: Every critical term has an entry in dependent_critical
        #[allow(clippy::panic)]
        let Some(dependent_critical_terms) = dependent_critical.get(&critical_term) else {
            panic!(
                "Expected dependent term {:?} to have an entry in dependent_critical",
                critical_term
            );
        };
        next_critical_terms.extend(dependent_critical_terms.iter().cloned());

        // Get the access trie for this critical term if any
        if let Some(dependent_trie) = access_tries.get(&critical_term) {
            // Case split on entities or tag access terms
            if for_request.is_entity_typed_term(&critical_term) {
                add_entity_request_from_term(
                    &critical_term,
                    dependent_trie,
                    for_request,
                    entities_map,
                    request,
                    entity_requests,
                )?;
            } else {
                add_tag_request_from_term(
                    &critical_term,
                    dependent_trie,
                    for_request,
                    entities_map,
                    request,
                    entity_requests,
                )?;
            }
        }
    }

    Ok(())
}

/// Add an entity request for an entity-typed term.
fn add_entity_request_from_term(
    critical_term: &crate::validator::entity_manifest::AccessTerm,
    dependent_trie: &AccessTrie,
    for_request: &crate::validator::entity_manifest::RequestTypeTerms,
    entities_map: &HashMap<EntityUID, Entity>,
    request: &Request,
    entity_requests: &mut EntityRequests,
) -> Result<(), EntitySliceError> {
    // Get the id of the entity term using the entity store
    let dependent_val = critical_term.compute_value(entities_map, &for_request.dag, request)?;

    let dependent_id = match dependent_val.value_kind() {
        ValueKind::Lit(Literal::EntityUID(euid)) => (**euid).clone(),
        _ => {
            return Err(ExpectedEntityTypeError {
                found_value: dependent_val.clone(),
            }
            .into())
        }
    };

    // Add entity request to the collection
    entity_requests.add(EntityRequest {
        entity_id: dependent_id.clone(),
        tags: HashMap::new(),
        access_trie: dependent_trie.clone(),
    });

    Ok(())
}

/// Add an entity request with a tag for a tag term.
fn add_tag_request_from_term(
    critical_term: &crate::validator::entity_manifest::AccessTerm,
    dependent_trie: &AccessTrie,
    for_request: &crate::validator::entity_manifest::RequestTypeTerms,
    entities_map: &HashMap<EntityUID, Entity>,
    request: &Request,
    entity_requests: &mut EntityRequests,
) -> Result<(), EntitySliceError> {
    eprintln!(
        "Loading tag term: {:?} with access trie: {:?}",
        critical_term, dependent_trie
    );

    // PANIC SAFETY: Critical terms are either entity typed or tag terms.
    #[allow(clippy::panic)]
    let AccessTermVariant::Tag { of, tag } = critical_term.get_variant_internal(&for_request.dag) else {
        panic!(
            "Expected a tag term variant, but got {:?}",
            critical_term.get_variant_internal(&for_request.dag)
        );
    };

    // For tag terms, generate an entity request with the tag and access trie
    let of_val_result = of.compute_value(entities_map, &for_request.dag, request)?;
    let tag_val_result = tag.compute_value(entities_map, &for_request.dag, request)?;

    // Extract the entity ID
    let of_val = match of_val_result.value_kind() {
        ValueKind::Lit(Literal::EntityUID(euid)) => (**euid).clone(),
        _ => {
            return Err(ExpectedEntityTypeError {
                found_value: of_val_result.clone(),
            }
            .into())
        }
    };

    // Tag value is always a string
    let tag_val = match tag_val_result.value_kind() {
        ValueKind::Lit(Literal::String(s)) => s.clone(),
        _ => {
            return Err(ExpectedStringTypeError {
                found_value: tag_val_result.clone(),
            }
            .into());
        }
    };

    // Add the tag to the request
    let mut tags = HashMap::new();
    tags.insert(tag_val, dependent_trie.clone());

    // Add entity request with tags to the collection
    entity_requests.add(EntityRequest {
        entity_id: of_val.clone(),
        tags,
        access_trie: AccessTrie::new(),
    });

    Ok(())
}

/// Load entities for the current batch of requests and merge them into the entities map.
fn load_and_merge_entities(
    loader: &mut dyn EntityLoader,
    entity_requests: &mut EntityRequests,
    entities_map: &mut HashMap<EntityUID, Entity>,
) -> Result<(), EntitySliceError> {
    eprintln!("Loading entities for requests: {:?}", entity_requests);

    // Load the current batch of entities
    let loaded_entities = loader.load_entities(entity_requests)?;

    // Reset entity_requests for the next batch
    entity_requests.clear();

    for entity in loaded_entities.into_iter() {
        // Add or merge the entity into our map
        match entities_map.entry(entity.uid().clone()) {
            hash_map::Entry::Occupied(o) => {
                // If the entity is already present, merge it
                let (k, v) = o.remove_entry();
                let merged = merge_entities(v, entity.clone())?;
                entities_map.insert(k, merged);
            }
            hash_map::Entry::Vacant(v) => {
                v.insert(entity.clone());
            }
        }
    }

    Ok(())
}

/// Merge two value for corresponding attributes in the slice.
// INVARIANT: `v1` and `v2` must be the result of slicing the same original
// value using the same entity manifest and request. I.e., they must be
// identical, except for the attributes they contain when the values are a
// records. When an attribute exists in both records, the attributes must be
// recursively identical, with the same exception.
fn merge_values(v1: Value, v2: Value, entity_id: &EntityUID) -> Result<Value, EntitySliceError> {
    // Clone the values before the match to avoid borrow issues
    let v1_clone = v1.clone();
    let v2_clone = v2.clone();
    let v1_loc = v1.loc;

    match (v1.value, v2.value) {
        (ValueKind::Record(r1), ValueKind::Record(r2)) => {
            let mut r1 = Arc::unwrap_or_clone(r1);
            for (k, v2) in Arc::unwrap_or_clone(r2) {
                match r1.entry(k) {
                    btree_map::Entry::Occupied(occupied) => {
                        let (k, v1) = occupied.remove_entry();
                        let merged_v = merge_values(v1, v2, entity_id)?;
                        r1.insert(k, merged_v);
                    }
                    btree_map::Entry::Vacant(vacant) => {
                        vacant.insert(v2);
                    }
                }
            }
            Ok(Value::new(ValueKind::Record(Arc::new(r1)), v1_loc))
        }
        (ValueKind::Lit(l1), ValueKind::Lit(l2)) => {
            if l1 != l2 {
                return Err(ConflictingEntityDataError {
                    entity_id: entity_id.clone(),
                    old_value: v1_clone,
                    new_value: v2_clone,
                }
                .into());
            }
            Ok(Value::new(l1, v1_loc))
        }
        (vk1 @ ValueKind::ExtensionValue(_), vk2 @ ValueKind::ExtensionValue(_))
        | (vk1 @ ValueKind::Set(_), vk2 @ ValueKind::Set(_)) => {
            // It might seem that we should recur into the sets and extensions
            // values, but `AccessTrie::slice_val` doesn't, so the merge
            // function can stop here too.
            if vk1 != vk2 {
                return Err(ConflictingEntityDataError {
                    entity_id: entity_id.clone(),
                    old_value: v1_clone,
                    new_value: v2_clone,
                }
                .into());
            }
            Ok(Value::new(vk1, v1_loc))
        }
        _ => Err(ConflictingEntityDataError {
            entity_id: entity_id.clone(),
            old_value: v1_clone,
            new_value: v2_clone,
        }
        .into()),
    }
}
