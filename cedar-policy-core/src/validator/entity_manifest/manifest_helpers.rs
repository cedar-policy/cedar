use std::collections::{HashMap, HashSet};

use smol_str::SmolStr;

use crate::validator::entity_manifest::{AccessTerm, AccessTermVariant, RequestTypePaths};

impl RequestTypePaths {
    /// Build a hashmap of dependent paths for all reachable paths
    pub(crate) fn build_dependents_map(
        &self,
        reachable_paths: &HashSet<AccessTerm>,
    ) -> HashMap<AccessTerm, Vec<AccessTerm>> {
        let mut dependents_map = HashMap::new();

        // Initialize the map with empty vectors for all paths
        for path in reachable_paths {
            dependents_map.insert(path.clone(), Vec::new());
        }

        // Populate the map with parent-child relationships
        for path in reachable_paths {
            // Get all children of this path
            let children = path.children(&self.dag);

            for child in children {
                // Add this path as a parent of the child
                if let Some(child_dependents) = dependents_map.get_mut(&child) {
                    child_dependents.push(path.clone());
                }
            }
        }

        dependents_map
    }

    pub(crate) fn build_dependent_entities_map(
        &self,
        dependents_map: &HashMap<AccessTerm, Vec<AccessTerm>>,
    ) -> HashMap<AccessTerm, Vec<AccessTerm>> {
        let mut dependent_entities_map = HashMap::new();

        for path in dependents_map.keys() {
            let dependent_entities =
                self.get_manifest_dependent_critical_paths(path, dependents_map);
            dependent_entities_map.insert(path.clone(), dependent_entities);
        }

        dependent_entities_map
    }

    /// Helper function to get the manifest dependent entity paths of an access path
    /// A manifest dependent critical term for term A is a term B such that A ->* B (B is a subterm of A)
    /// and no intermediate terms in the path from A to B are critical terms.
    fn get_manifest_dependent_critical_paths(
        &self,
        path: &AccessTerm,
        dependents_map: &HashMap<AccessTerm, Vec<AccessTerm>>,
    ) -> Vec<AccessTerm> {
        let mut result = HashSet::new();
        let mut visited = HashSet::new();
        let mut queue = Vec::new();

        // Start with the current path
        queue.push(path.clone());

        while let Some(current) = queue.pop() {
            // Get the dependents of the current path
            if let Some(dependents) = dependents_map.get(&current) {
                for dependent in dependents {
                    if visited.insert(dependent) {
                        // if it has an entity type, add it to the result
                        if self.is_critical_path(dependent) {
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
    /// See the documentation for [`RequestTypePaths::is_critical_path`]
    /// for more information on what a critical path is.
    pub(crate) fn compute_access_tries(
        &self,
        dependents_map: &HashMap<AccessTerm, Vec<AccessTerm>>,
    ) -> HashMap<AccessTerm, AccessTrie> {
        // Find all entity paths among the reachable paths
        let entity_paths = self.get_critical_paths(&dependents_map);

        // Build the AccessTrie for each entity path
        let mut result = HashMap::new();
        for entity_path in entity_paths {
            let trie = self.build_access_trie_for_critical(&entity_path, dependents_map);

            if !trie.fields.is_empty() {
                result.insert(entity_path, trie);
            }
        }

        result
    }

    /// A "critical path" is a path whose dependents need to be explicitly loaded
    /// by the [`EntityLoader`] API.
    /// These include two kinds of paths:
    ///     1) paths that have an entity type, since the [`EntityLoader`] API
    ///     doesn't load entities recursively.
    ///     2) paths that are [`AccessTermVariant::Tag`]s because they are computed based on multiple
    ///     other values- not a single path starting from an entity.
    fn is_critical_path(&self, path: &AccessTerm) -> bool {
        self.is_entity_typed_path(path) || self.is_tag_path(path)
    }

    pub(crate) fn is_tag_path(&self, path: &AccessTerm) -> bool {
        let variant = path.get_variant_internal(&self.dag);
        // Check if the path is a tag path
        matches!(variant, AccessTermVariant::Tag { .. })
    }

    pub(crate) fn is_entity_typed_path(&self, path: &AccessTerm) -> bool {
        // Check if we have type information
        if path.id < self.dag.types.len() {
            // Check if the type is an entity type
            use crate::validator::types::EntityRecordKind;
            match self.dag.types.get(path.id) {
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

    /// Gets critical paths (see [`RequestTypePaths::is_critical_path`])
    fn get_critical_paths(
        &self,
        dependent_map: &HashMap<AccessTerm, Vec<AccessTerm>>,
    ) -> HashSet<AccessTerm> {
        dependent_map
            .keys()
            .filter(|path| self.is_critical_path(path))
            .cloned()
            .collect()
    }

    /// Recursively build the `AccessTrie` for an entity path
    fn build_access_trie_for_critical(
        &self,
        entity_path: &AccessTerm,
        dependents_map: &HashMap<AccessTerm, Vec<AccessTerm>>,
    ) -> AccessTrie {
        // Create a new trie for this entity
        let mut trie = AccessTrie::new();

        // Use a recursive helper to build the trie
        self.build_trie_recursive(entity_path, &mut trie, dependents_map, &mut HashSet::new());

        trie
    }

    /// Recursive helper function to build the `AccessTrie`
    /// Traverses the dependents map starting from the entity path
    fn build_trie_recursive(
        &self,
        path: &AccessTerm,
        trie: &mut AccessTrie,
        dependents_map: &HashMap<AccessTerm, Vec<AccessTerm>>,
        visited: &mut HashSet<AccessTerm>,
    ) {
        // Mark this path as visited to avoid cycles
        visited.insert(path.clone());

        // Get all dependents of this path
        if let Some(dependents) = dependents_map.get(path) {
            for dependent in dependents {
                // Skip if we've already visited this path
                if visited.contains(dependent) {
                    continue;
                }

                // Check if this is an attribute path
                if let Ok(variant) = dependent.get_variant(&self.dag) {
                    if let AccessTermVariant::Attribute { attr, .. } = variant {
                        // Get or create the field in the trie
                        let field_trie = trie.get_or_create_field(attr);

                        // If this is an entity, don't continue building the trie
                        if !self.is_critical_path(dependent) {
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

    /// Computes all reachable paths.
    /// Currently inefficient in the presense of sharing between paths
    /// because it uses the subpaths method.
    pub(crate) fn reachable_paths(&self) -> HashSet<AccessTerm> {
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
