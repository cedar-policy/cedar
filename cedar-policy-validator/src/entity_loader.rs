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
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use cedar_policy_core::{
    ast::{Context, Entity, EntityUID, Literal, PartialValue, Request, Value, ValueKind, Var},
    entities::{Entities, NoEntitiesSchema, TCComputation},
    extensions::Extensions,
};
use smol_str::SmolStr;

use crate::{
    entity_manifest::{
        AccessTrie, EntityManifest, EntityRoot, PartialRequestError, RootAccessTrie,
    },
    entity_slicing::{
        EntitySliceError, PartialContextError, PartialEntityError, WrongNumberOfEntitiesError,
    },
};

/// A request that an entity be loaded.
/// Optionally, instead of loading the full entity the `access_trie`
/// may be used to load only some fields of the entity.
#[derive(Debug)]
pub struct EntityRequest<'a> {
    /// The id of the entity requested
    entity_id: EntityUID,
    /// The fieds of the entity requested
    access_trie: &'a AccessTrie,
}

/// A request that the ancestors of an entity be loaded.
/// Optionally, the `ancestors` set may be used to just load ancestors in the set.
#[derive(Debug)]
pub struct AncestorsRequest {
    /// The id of the entity whose ancestors are requested
    entity_id: EntityUID,
    /// The ancestors that are requested, if present
    ancestors: HashSet<EntityUID>,
}

/// Implement [`EntityLoader`] to easily load entities using their ids
/// into a Cedar [`Entities`] store.
/// The most basic implementation loads full entities (including all ancestors) in the `load_entities` method and loads the context in the `load_context` method.
/// More advanced implementations make use of the [`AccessTrie`]s provided to load partial entities and context, as well as the `load_ancestors` method to load particular ancestors.
pub trait EntityLoader {
    /// Loads the concrete context based on the request.
    /// Only context attributes mentioned in the `access_trie` are required.
    fn load_context(&mut self, access_trie: AccessTrie) -> Context;

    /// `load_entities` is called multiple times to load entities based on their ids.
    /// For each entity request in the `to_load` vector, expects one loaded entity in the resulting vector.
    /// Each [`EntityRequest`] comes with an [`AccessTrie`], which can optionally be used.
    /// Only fields mentioned in the entity's [`AccessTrie`] are needed, but it is sound to provide other fields as well.
    /// Note that the same entity may be requested multiple times, with different [`AccessTrie`]s.
    ///
    /// Either `load_entities` must load all the ancestors of each entity, unless `load_ancestors` is implemented.
    fn load_entities(&mut self, to_load: &[EntityRequest<'_>]) -> Vec<Entity>;

    /// Optionally, `load_entities` can forgo loading ancestors in the entity hierarchy.
    /// Instead, `load_ancestors` implements loading them.
    /// For each entity, `load_ancestors` produces a set of ancestors entities in the resulting vector.
    ///
    /// Each [`AncestorsRequest`] should result in one set of ancestors in the resulting vector.
    /// Only ancestors in the request are required, but it is sound to provide other ancestors as well.
    fn load_ancestors(&mut self, entities: &Vec<AncestorsRequest>) -> Vec<HashSet<EntityUID>>;
}

fn initial_entities_to_load<'a>(
    root_access_trie: &'a RootAccessTrie,
    context: &Context,
    request: &Request,
) -> Result<Vec<EntityRequest<'a>>, EntitySliceError> {
    let Context::Value(context_value) = &context else {
        return Err(PartialContextError {}.into());
    };

    let mut to_load = match root_access_trie.trie.get(&EntityRoot::Var(Var::Context)) {
        Some(access_trie) => find_remaining_entities_context(context_value, access_trie)?,
        _ => vec![],
    };

    for (key, access_trie) in &root_access_trie.trie {
        to_load.push(EntityRequest {
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

/// Loads entities based on the entity manifest, request, and
/// the implemented [`EntityLoader`].
/// Returns both the new entity store and the loaded context.
pub fn load_entities(
    manifest: &EntityManifest,
    request: &Request,
    loader: &mut dyn EntityLoader,
) -> Result<(Context, Entities), EntitySliceError> {
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
            Ok(entities) => return Ok((Context::empty(), entities)),
            Err(err) => return Err(err.into()),
        };
    };

    let context = match root_access_trie.trie.get(&EntityRoot::Var(Var::Context)) {
        Some(access_trie) => loader.load_context(access_trie.clone()),
        _ => Context::empty(),
    };

    let mut entities: HashMap<EntityUID, Entity> = Default::default();
    // entity requests in progress
    let mut to_load: Vec<EntityRequest<'_>> =
        initial_entities_to_load(&root_access_trie, &context, &request)?;
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

        let new_entities = loader.load_entities(&to_load);
        if new_entities.len() != to_load.len() {
            return Err(WrongNumberOfEntitiesError {
                expected: to_load.len(),
                got: new_entities.len(),
            }
            .into());
        }

        let mut next_to_load = vec![];
        for (entity_request, loaded) in to_load.drain(..).zip(new_entities) {
            next_to_load.extend(find_remaining_entities(
                &loaded,
                entity_request.access_trie,
            )?);
            entities.insert(entity_request.entity_id, loaded);
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
            &context,
            request,
        )?);
    }

    let loaded_ancestors = loader.load_ancestors(&ancestors_requests);
    for (request, ancestors) in ancestors_requests.into_iter().zip(loaded_ancestors) {
        // PANIC SAFETY: ancestor requests are only created for entities already loaded in the entities map
        #[allow(clippy::unwrap_used)]
        entities
            .get_mut(&request.entity_id)
            .unwrap()
            .add_ancestors(ancestors);
    }

    // finally, convert the loaded entities into a Cedar Entities store

    match Entities::from_entities(
        entities.values().cloned(),
        None::<&NoEntitiesSchema>,
        TCComputation::AssumeAlreadyComputed,
        Extensions::all_available(),
    ) {
        Ok(entities) => Ok((context, entities)),
        Err(e) => Err(e.into()),
    }
}

fn find_remaining_entities_context<'a>(
    context_value: &Arc<BTreeMap<SmolStr, Value>>,
    fields: &'a AccessTrie,
) -> Result<Vec<EntityRequest<'a>>, EntitySliceError> {
    let mut remaining = vec![];
    for (field, slice) in &fields.children {
        if let Some(value) = context_value.get(field) {
            find_remaining_entities_value(&mut remaining, value, slice)?;
        }
        // the attribute may not be present, since the schema can define
        // attributes that are optional
    }
    Ok(remaining)
}

/// This helper function finds all entity references that need to be
/// loaded given an already-loaded [`Entity`] and corresponding [`Fields`].
/// Returns pairs of entity and slices that need to be loaded.
fn find_remaining_entities<'a>(
    entity: &Entity,
    fields: &'a AccessTrie,
) -> Result<Vec<EntityRequest<'a>>, EntitySliceError> {
    let mut remaining = vec![];
    for (field, slice) in &fields.children {
        if let Some(pvalue) = entity.get(field) {
            let PartialValue::Value(value) = pvalue else {
                return Err(PartialEntityError {}.into());
            };
            find_remaining_entities_value(&mut remaining, value, slice)?;
        }
        // the attribute may not be present, since the schema can define
        // attributes that are optional
    }

    Ok(remaining)
}

fn find_remaining_entities_value<'a>(
    remaining: &mut Vec<EntityRequest<'a>>,
    value: &Value,
    trie: &'a AccessTrie,
) -> Result<(), EntitySliceError> {
    match value.value_kind() {
        ValueKind::Lit(literal) => {
            if let Literal::EntityUID(entity_id) = literal {
                remaining.push(EntityRequest {
                    entity_id: (**entity_id).clone(),
                    access_trie: trie,
                });
            }
        }
        ValueKind::Set(_) => (),
        ValueKind::ExtensionValue(_) => (),
        ValueKind::Record(record) => {
            for (field, child_slice) in &trie.children {
                // only need to slice if field is present
                if let Some(value) = record.get(field) {
                    find_remaining_entities_value(remaining, value, child_slice)?;
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

    let mut to_visit = initial_entities_to_load(ancestors_trie, context, request)?;

    while !to_visit.is_empty() {
        let mut next_to_visit = vec![];
        for entity_request in to_visit.drain(..) {
            if entity_request.access_trie.is_ancestor {
                ancestors.insert(entity_request.entity_id.clone());
            }
            if let Some(entity) = entities.get(&entity_request.entity_id) {
                next_to_visit.extend(find_remaining_entities(entity, entity_request.access_trie)?);
            }
        }
        to_visit = next_to_visit;
    }

    Ok(AncestorsRequest {
        ancestors,
        entity_id,
    })
}
