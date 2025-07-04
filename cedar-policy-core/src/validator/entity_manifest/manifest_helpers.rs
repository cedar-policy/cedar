use std::collections::{HashMap, HashSet};

use smol_str::SmolStr;

use crate::validator::entity_manifest::{AccessTerm, AccessTermVariant, RequestTypeTerms};

impl RequestTypeTerms {
    /// Given a set of access tries, determines which are leaf nodes
    pub(crate) fn initial_critical_terms(
        &self,
        access_tries: &HashMap<AccessTerm, AccessTrie>,
    ) -> Vec<AccessTerm> {
        access_tries
            .keys()
            .filter(|term| term.is_leaf(&self.dag))
            .cloned()
            .collect()
    }

    /// Build a hashmap of dependent terms for all reachable terms
    pub(crate) fn build_dependents_map(
        &self,
        reachable_terms: &HashSet<AccessTerm>,
    ) -> HashMap<AccessTerm, Vec<AccessTerm>> {
        let mut dependents_map = HashMap::new();

        // Initialize the map with empty vectors for all terms
        for term in reachable_terms {
            dependents_map.insert(term.clone(), Vec::new());
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

    pub(crate) fn build_dependent_critical_terms(
        &self,
        dependents_map: &HashMap<AccessTerm, Vec<AccessTerm>>,
    ) -> HashMap<AccessTerm, Vec<AccessTerm>> {
        let mut dependent_entities_map = HashMap::new();

        for term in dependents_map.keys() {
            let dependent_entities =
                self.get_manifest_dependent_critical_terms(term, dependents_map);
            dependent_entities_map.insert(term.clone(), dependent_entities);
        }

        dependent_entities_map
    }

    /// Helper function to get the manifest dependent entity terms of an access term
    /// A manifest dependent critical term for term A is a term B such that A ->* B (B is a subterm of A)
    /// and no intermediate terms in the term from A to B are critical terms.
    fn get_manifest_dependent_critical_terms(
        &self,
        term: &AccessTerm,
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

    /// A "critical term" is a term whose dependents need to be explicitly loaded
    /// by the [`EntityLoader`] API.
    /// These include two kinds of terms:
    ///     1) terms that have an entity type, since the [`EntityLoader`] API
    ///     doesn't load entities recursively.
    ///     2) terms that are [`AccessTermVariant::Tag`]s because they are computed based on multiple
    ///     other values- not a single term starting from an entity.
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
            use crate::validator::types::EntityRecordKind;
            match self.dag.types.get(term.id) {
                Some(Some(crate::validator::types::Type::EntityOrRecord(kind))) => {
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
    }

    /// Gets critical terms (see [`RequestTypeTerms::is_critical_term`])
    fn get_critical_terms(
        &self,
        dependent_map: &HashMap<AccessTerm, Vec<AccessTerm>>,
    ) -> HashSet<AccessTerm> {
        dependent_map
            .keys()
            .filter(|term| self.is_critical_term(term))
            .cloned()
            .collect()
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
                if let Ok(variant) = dependent.get_variant(&self.dag) {
                    if let AccessTermVariant::Attribute { attr, .. } = variant {
                        // Get or create the field in the trie
                        let field_trie = trie.get_or_create_field(attr);

                        // If this is an entity, don't continue building the trie
                        if !self.is_critical_term(dependent) {
                            self.build_trie_recursive(
                                dependent,
                                field_trie,
                                dependents_map,
                                visited,
                            );
                        }
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
}
