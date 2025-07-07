//! Helper types and functions for using the entity manifest with the [`SimpleEntityLoader`]
//!
//! These helpers are packaged as a [`EntityLoadingContext`], which stores information about the entity DAG to enable efficient loading.

use std::{
    collections::{btree_map, hash_map, HashMap, HashSet},
    sync::Arc,
};

use smol_str::SmolStr;

use crate::{
    ast::EntityUID,
    validator::entity_manifest::{
        errors::{EntitySliceError, ResidualEncounteredError},
        loader::{EntityLoader, EntityRequest, EntityRequests},
        AccessTerm, AccessTermVariant, RequestTypeTerms,
    },
};
use crate::{
    ast::{Entity, Literal, PartialValue, Request, Value, ValueKind},
    validator::entity_manifest::errors::{
        ConflictingEntityDataError, ExpectedEntityTypeError, ExpectedStringTypeError,
    },
};

impl RequestTypeTerms {
    /// Given a set of access tries, determines which are leaf nodes.
    ///
    /// Used by [`EntityLoadingContext::initial_critical_terms`] to find the starting points
    /// for entity loading.
    pub(crate) fn initial_critical_terms(
        &self,
        access_tries: &HashMap<AccessTerm, AccessTrie>,
    ) -> Vec<AccessTerm> {
        access_tries
            .keys()
            .filter(|term| term.is_leaf(&self.dag))
            .copied()
            .collect()
    }

    /// Returns a map from terms to all their dependent terms.
    /// A dependent term for term B is a term A such that B is a child of A.
    /// So A has a direct data dependency on B.
    /// Only includes terms in `reachable_terms`.
    pub(crate) fn build_dependents_map(
        &self,
        reachable_terms: &HashSet<AccessTerm>,
    ) -> HashMap<AccessTerm, Vec<AccessTerm>> {
        let mut dependents_map = HashMap::new();

        // Initialize the map with empty vectors for all terms
        for term in reachable_terms {
            dependents_map.insert(*term, Vec::new());
        }

        // Populate the map with parent-child relationships
        for term in reachable_terms {
            // Get all children of this term
            let children = term.children(&self.dag);

            for child in children {
                // Add this term as a parent of the child
                if let Some(child_dependents) = dependents_map.get_mut(&child) {
                    child_dependents.push(term.clone());
                }
            }
        }

        dependents_map
    }

    /// Builds a map from a critical term to other critical terms that depend on it.
    /// Only considers terms which are keys in `dependents_map`.
    pub(crate) fn build_dependent_critical_terms(
        &self,
        dependents_map: &HashMap<AccessTerm, Vec<AccessTerm>>,
    ) -> HashMap<AccessTerm, Vec<AccessTerm>> {
        let mut dependent_entities_map = HashMap::new();

        for term in dependents_map.keys() {
            if self.is_critical_term(term) {
                let dependent_entities =
                    self.get_manifest_dependent_critical_terms(*term, dependents_map);
                dependent_entities_map.insert(term.clone(), dependent_entities);
            }
        }

        dependent_entities_map
    }

    /// Builds a map from a critical term to other critical terms it depends on.
    /// This is the inverse of `build_dependent_critical_terms`.
    /// A dependee critical term for term B is a term A such that A ->* B (B is a subterm of A)
    /// and no intermediate terms in the term from A to B are critical terms.
    pub(crate) fn build_dependee_critical_terms(
        &self,
        dependent_critical: &HashMap<AccessTerm, Vec<AccessTerm>>,
    ) -> HashMap<AccessTerm, Vec<AccessTerm>> {
        let mut dependee_critical = HashMap::new();

        // Initialize the map with empty vectors for all critical terms
        for term in dependent_critical.keys() {
            dependee_critical.insert(*term, Vec::new());
        }

        // For each critical term and its dependents
        for (term, dependents) in dependent_critical {
            // For each dependent, add the current term as a dependee
            for dependent in dependents {
                if let Some(dependees) = dependee_critical.get_mut(dependent) {
                    dependees.push(*term);
                }
            }
        }

        dependee_critical
    }

    /// Helper function to get the manifest dependent critical terms
    fn get_manifest_dependent_critical_terms(
        &self,
        term: AccessTerm,
        dependents_map: &HashMap<AccessTerm, Vec<AccessTerm>>,
    ) -> Vec<AccessTerm> {
        let mut result = HashSet::new();
        let mut visited = HashSet::new();
        let mut queue = Vec::new();

        // Start with the current term
        queue.push(term.clone());

        while let Some(current) = queue.pop() {
            // Get the dependents of the current term
            if let Some(dependents) = dependents_map.get(&current) {
                for dependent in dependents {
                    if visited.insert(dependent) {
                        // if it has an entity type, add it to the result
                        if self.is_critical_term(dependent) {
                            result.insert(dependent.clone());
                        } else {
                            // otherwise add to the queue
                            queue.push(dependent.clone());
                        }
                    }
                }
            }
        }

        result.into_iter().collect()
    }

    /// For each reachable critical [`AccessTerm`]
    /// computes the [`AccessTrie`] needed
    /// for that term.
    /// This trie either corresponds to an entity or a tag.
    /// See the documentation for [`RequestTypeTerms::is_critical_term`]
    /// for more information on what a critical term is.
    ///
    /// Used by [`EntityLoadingContext`] during initialization to prepare access tries
    /// for entity loading.
    pub(crate) fn compute_access_tries(
        &self,
        dependent_critical: &HashMap<AccessTerm, Vec<AccessTerm>>,
        dependents_map: &HashMap<AccessTerm, Vec<AccessTerm>>,
    ) -> HashMap<AccessTerm, AccessTrie> {
        dependent_critical
            .keys()
            .map(|term| {
                // For each critical term, we need to build an AccessTrie
                (
                    *term,
                    self.build_access_trie_for_critical(term, dependents_map),
                )
            })
            .collect()
    }

    fn is_critical_term(&self, term: &AccessTerm) -> bool {
        self.is_entity_typed_term(term) || self.is_tag_term(term)
    }

    pub(crate) fn is_tag_term(&self, term: &AccessTerm) -> bool {
        let variant = term.get_variant_internal(&self.dag);
        // Check if the term is a tag term
        matches!(variant, AccessTermVariant::Tag { .. })
    }

    pub(crate) fn is_entity_typed_term(&self, term: &AccessTerm) -> bool {
        // Check if we have type information
        if term.id < self.dag.types.len() {
            // Check if the type is an entity type
            // PANIC SAFETY: types should exist for every term in the dag
            #[allow(clippy::unwrap_used)]
            match self.dag.types.get(term.id).unwrap() {
                Some(ty) => ty.is_entity_type(),
                _ => false,
            }
        } else {
            false
        }
    }

    /// Recursively build the `AccessTrie` for an entity term
    fn build_access_trie_for_critical(
        &self,
        entity_term: &AccessTerm,
        dependents_map: &HashMap<AccessTerm, Vec<AccessTerm>>,
    ) -> AccessTrie {
        // Create a new trie for this entity
        let mut trie = AccessTrie::new();

        // Use a recursive helper to build the trie
        self.build_trie_recursive(entity_term, &mut trie, dependents_map, &mut HashSet::new());

        trie
    }

    /// Recursive helper function to build the `AccessTrie`
    /// Traverses the dependents map starting from the entity term
    fn build_trie_recursive(
        &self,
        term: &AccessTerm,
        trie: &mut AccessTrie,
        dependents_map: &HashMap<AccessTerm, Vec<AccessTerm>>,
        visited: &mut HashSet<AccessTerm>,
    ) {
        // Mark this term as visited to avoid cycles
        visited.insert(term.clone());

        // Get all dependents of this term
        if let Some(dependents) = dependents_map.get(term) {
            for dependent in dependents {
                // Skip if we've already visited this term
                if visited.contains(dependent) {
                    continue;
                }

                // Check if this is an attribute term
                if let Ok(AccessTermVariant::Attribute { attr, .. }) =
                    dependent.get_variant(&self.dag)
                {
                    // Get or create the field in the trie
                    let field_trie = trie.get_or_create_field(attr);

                    // If this is an entity, don't continue building the trie
                    if !self.is_critical_term(dependent) {
                        self.build_trie_recursive(dependent, field_trie, dependents_map, visited);
                    }
                }
            }
        }
    }

    /// Computes all reachable terms.
    /// Currently inefficient in the presense of sharing between terms
    /// because it uses the subterms method.
    pub(crate) fn reachable_terms(&self) -> HashSet<AccessTerm> {
        let mut result = HashSet::new();

        // Iterate through all access terms in the RequestTypeTerms
        for term in &self.access_terms.terms {
            // For each term, get all its subterms (including itself)
            // and add them to the result set
            let subterms = term.subterms(&self.dag);
            result.extend(subterms.terms().clone());
        }

        result
    }
}
/// A trie containing what attributes of an entity or record
/// are requested.
/// Children [`AccessTrie`] describe what fields of child records are requested.
/// These don't recur into other entities.
///
/// Used extensively by [`EntityLoadingContext`] to track which attributes need to be loaded
/// for each entity.
#[derive(Debug, Clone)]
pub(crate) struct AccessTrie {
    pub(crate) fields: HashMap<SmolStr, Box<AccessTrie>>,
}

impl AccessTrie {
    pub(crate) fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Creates a new empty `AccessTrie`
    pub(crate) fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    /// Gets or creates a field in this `AccessTrie`
    pub(crate) fn get_or_create_field(&mut self, field: &SmolStr) -> &mut Box<AccessTrie> {
        self.fields
            .entry(field.clone())
            .or_insert_with(|| Box::new(AccessTrie::new()))
    }

    /// Unions this [`AccessTrie`] with another, modifying this trie in place.
    /// After this operation, this trie will contain all fields from both tries.
    /// If both tries have the same field, the field tries are recursively unioned.
    pub(crate) fn union_with(&mut self, other: &AccessTrie) {
        for (field, other_trie) in &other.fields {
            match self.fields.entry(field.clone()) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    // If both tries have the same field, recursively union the field tries
                    entry.get_mut().union_with(other_trie);
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    // If only the other trie has this field, clone it into this trie
                    entry.insert(other_trie.clone());
                }
            }
        }
    }
}

/// A context for loading entities using the [`SimpleEntityLoader`] API.
/// This struct encapsulates all the data needed for the entity loading process.
#[derive(Debug)]
pub(crate) struct EntityLoadingContext<'a> {
    /// A "critical term" is a term whose dependents need to be explicitly loaded
    /// by the [`EntityLoader`] API.
    /// These include two kinds of terms:
    ///     1) terms that have an entity type, since the [`EntityLoader`] API
    ///     doesn't load entities recursively.
    ///     2) terms that are [`AccessTermVariant::Tag`]s because they are computed based on multiple
    ///     other values- not a single term starting from an entity.
    ///
    /// This field maps critical terms to critical terms that depend on them.
    ///
    /// A dependent critical term for term A is a term B such that A ->* B (B is a subterm of A)
    /// and no intermediate terms in the term from A to B are critical terms.
    dependent_critical: HashMap<
        crate::validator::entity_manifest::AccessTerm,
        Vec<crate::validator::entity_manifest::AccessTerm>,
    >,
    /// This map is the inverse of `dependent_critical`.
    /// It stores, for each term, terms which it directly depends on.
    dependee_critical: HashMap<
        crate::validator::entity_manifest::AccessTerm,
        Vec<crate::validator::entity_manifest::AccessTerm>,
    >,
    /// Access tries for each critical term.
    access_tries: HashMap<crate::validator::entity_manifest::AccessTerm, AccessTrie>,
    /// The request type terms.
    for_request: &'a crate::validator::entity_manifest::RequestTypeTerms,
    /// Map of already loaded entities.
    entities_map: HashMap<EntityUID, Entity>,
    /// The request.
    request: &'a Request,
}

impl<'a> EntityLoadingContext<'a> {
    /// Creates a new entity request context.
    pub(crate) fn new(
        for_request: &'a crate::validator::entity_manifest::RequestTypeTerms,
        request: &'a Request,
    ) -> Self {
        let reachable_terms = for_request.reachable_terms();
        // Map from term to dependents
        let dependents_map = for_request.build_dependents_map(&reachable_terms);
        // Map from a critical term to critical dependents
        let dependent_critical = for_request.build_dependent_critical_terms(&dependents_map);
        // Map from a critical term to critical dependees (inverse of dependent_critical)
        let dependee_critical = for_request.build_dependee_critical_terms(&dependent_critical);
        // Access tries for each critical term
        let access_tries = for_request.compute_access_tries(&dependent_critical, &dependents_map);

        Self {
            dependent_critical,
            dependee_critical,
            access_tries,
            for_request,
            entities_map: HashMap::new(),
            request,
        }
    }

    /// Gets the initial critical terms to process.
    pub(crate) fn initial_critical_terms(
        &self,
    ) -> Vec<crate::validator::entity_manifest::AccessTerm> {
        self.for_request.initial_critical_terms(&self.access_tries)
    }

    /// Gets the entities map.
    pub(crate) fn entities_map(&self) -> &HashMap<EntityUID, Entity> {
        &self.entities_map
    }

    /// Gets a mutable reference to the entities map.
    pub(crate) fn entities_map_mut(&mut self) -> &mut HashMap<EntityUID, Entity> {
        &mut self.entities_map
    }

    /// Prepare entity requests from a batch of critical terms.
    ///
    /// This function:
    /// 1. Takes critical terms from `next_critical_terms`
    /// 2. Adds their dependent terms to `next_critical_terms` for the next batch
    /// 3. Processes entity-typed terms and tag terms, adding appropriate entity requests
    pub(crate) fn prepare_entity_requests_from_terms(
        &self,
        critical_terms: &Vec<crate::validator::entity_manifest::AccessTerm>,
        computed_critical_terms: &HashSet<crate::validator::entity_manifest::AccessTerm>,
        entity_requests: &mut EntityRequests,
    ) -> Result<Vec<AccessTerm>, EntitySliceError> {
        let mut next_critical_terms = vec![];
        let mut visited_critical_terms: HashSet<AccessTerm> = HashSet::new();
        // Process each critical term in the current batch
        for critical_term in critical_terms {
            if computed_critical_terms.contains(critical_term) {
                continue;
            }

            // ensure that this term's critical dependees have been visited
            // PANIC SAFETY: dependee_critical should have one entry per critical term
            #[allow(clippy::unwrap_used)]
            if !self
                .dependee_critical
                .get(critical_term)
                .unwrap()
                .iter()
                .all(|dependee| computed_critical_terms.contains(dependee))
            {
                continue;
            }

            // If we have already visited this term, skip it
            if !visited_critical_terms.insert(*critical_term) {
                continue;
            }

            // Add dependent critical terms to the next batch
            // PANIC SAFETY: Every critical term has an entry in dependent_critical
            #[allow(clippy::panic)]
            let Some(dependent_critical_terms) = self.dependent_critical.get(critical_term) else {
                panic!(
                    "Expected dependent term {critical_term:?} to have an entry in dependent_critical",
                );
            };
            next_critical_terms.extend(dependent_critical_terms.iter().cloned());

            // Get the access trie for this critical term
            // PANIC SAFETY: access_tries has one entry per critical term
            #[allow(clippy::unwrap_used)]
            let access_trie = self.access_tries.get(critical_term).unwrap();
            // Case split on entities or tag access terms
            if self.for_request.is_tag_term(critical_term) {
                self.add_tag_request_from_term(critical_term, access_trie, entity_requests)?;
            } else {
                self.add_entity_request_from_term(*critical_term, access_trie, entity_requests)?;
            }
            eprintln!("done");
        }

        Ok(next_critical_terms)
    }

    /// Add an entity request for an entity-typed term.
    fn add_entity_request_from_term(
        &self,
        critical_term: AccessTerm,
        dependent_trie: &AccessTrie,
        entity_requests: &mut EntityRequests,
    ) -> Result<(), EntitySliceError> {
        // Get the id of the entity term using the entity store
        let dependent_val =
            critical_term.compute_value(&self.entities_map, &self.for_request.dag, self.request)?;

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
            entity_id: dependent_id,
            tags: HashMap::new(),
            access_trie: dependent_trie.clone(),
        });

        Ok(())
    }

    /// Add an entity request with a tag for a tag term.
    fn add_tag_request_from_term(
        &self,
        critical_term: &crate::validator::entity_manifest::AccessTerm,
        dependent_trie: &AccessTrie,
        entity_requests: &mut EntityRequests,
    ) -> Result<(), EntitySliceError> {
        eprintln!("Adding tag request for term: {critical_term:?}");
        // PANIC SAFETY: Critical terms are either entity typed or tag terms.
        #[allow(clippy::panic)]
        let AccessTermVariant::Tag { of, tag } =
            critical_term.get_variant_internal(&self.for_request.dag)
        else {
            panic!(
                "Expected a tag term variant, but got {:?}",
                critical_term.get_variant_internal(&self.for_request.dag)
            );
        };

        // For tag terms, generate an entity request with the tag and access trie
        eprintln!("computing of");
        let of_val_result =
            of.compute_value(&self.entities_map, &self.for_request.dag, self.request)?;
        eprintln!("computing tag");
        let tag_val_result =
            tag.compute_value(&self.entities_map, &self.for_request.dag, self.request)?;

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
            entity_id: of_val,
            tags,
            access_trie: AccessTrie::new(),
        });

        Ok(())
    }

    /// Load entities for the current batch of requests and merge them into the entities map.
    pub(crate) fn load_and_merge_entities(
        &mut self,
        loader: &mut dyn EntityLoader,
        entity_requests: &mut EntityRequests,
    ) -> Result<(), EntitySliceError> {
        eprintln!("Loading entities for batch: {:?}...", entity_requests);
        // Load the current batch of entities
        let loaded_entities = loader.load_entities(entity_requests)?;

        // Reset entity_requests for the next batch
        entity_requests.clear();

        for entity in loaded_entities.into_iter() {
            // Add or merge the entity into our map
            match self.entities_map.entry(entity.uid().clone()) {
                hash_map::Entry::Occupied(o) => {
                    // If the entity is already present, merge it
                    let (k, v) = o.remove_entry();
                    let merged = merge_entities(v, entity)?;
                    self.entities_map.insert(k, merged);
                }
                hash_map::Entry::Vacant(v) => {
                    v.insert(entity);
                }
            }
        }

        Ok(())
    }
}

/// Merge the contents of two entities in the slice. Combines the attributes
/// records for both entities, recursively merging any attribute that exist in
/// both. If one entity is referenced by multiple entity roots in the slice,
/// then we need to be sure that we don't clobber the attribute for the first
/// when inserting the second into the slice.
///
/// Called by [`EntityLoadingContext::load_and_merge_entities`] when the same entity
/// is loaded multiple times with different attributes.
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

/// Merge two values for corresponding attributes in the slice.
///
/// Used by [`merge_entities`] when merging entity attributes in the [`EntityLoadingContext`].
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
