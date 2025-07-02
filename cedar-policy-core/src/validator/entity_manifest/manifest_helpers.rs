use std::{
    collections::{btree_map, hash_map, HashMap, HashSet},
    sync::Arc,
};

use smol_str::SmolStr;

use crate::{
    ast::{Entity, EntityUID, Literal, PartialValue, Request, Value, ValueKind, Var},
    entities::{Entities, NoEntitiesSchema, TCComputation},
    extensions::Extensions,
    validator::entity_manifest::{AccessPath, AccessPathVariant, AccessPaths, PathsForRequestType},
};

impl PathsForRequestType {
    /// Build a hashmap of dependent paths for all reachable paths
    pub(crate) fn build_dependents_map(
        &self,
        reachable_paths: &HashSet<AccessPath>,
    ) -> HashMap<AccessPath, Vec<AccessPath>> {
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
        dependents_map: &HashMap<AccessPath, Vec<AccessPath>>,
    ) -> HashMap<AccessPath, Vec<AccessPath>> {
        let mut dependent_entities_map = HashMap::new();

        for (path, _dependents) in dependents_map {
            let dependent_entities = self.get_manifest_dependent_entities(path, dependents_map);
            dependent_entities_map.insert(path.clone(), dependent_entities);
        }

        dependent_entities_map
    }

    /// Helper function to get the manifest dependent entity paths of an access path
    /// A manifest dependent entity for node A is a node B such that A ->* B points to B
    /// with a path such that no intermediate nodes are entity typed
    fn get_manifest_dependent_entities(
        &self,
        path: &AccessPath,
        dependents_map: &HashMap<AccessPath, Vec<AccessPath>>,
    ) -> Vec<AccessPath> {
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
                        if self.is_entity_path(dependent) {
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

    /// For each reachable [`AccessPath`] in the path with
    /// an entity type, computes the [`AccessTrie`] needed
    /// for that entity.
    ///
    /// This is a helper which computes the access tries needed during
    /// entity loading with the [`EntityLoader`] API.
    ///
    /// TODO we already have reachable paths and dependent map when we call this
    pub(crate) fn compute_access_tries(&self) -> HashMap<AccessPath, AccessTrie> {
        // First, compute all reachable paths
        let reachable_paths = self.reachable_paths();

        // Build a dependents map for efficient dependent lookup
        let dependents_map = self.build_dependents_map(&reachable_paths);

        // Find all entity paths among the reachable paths
        let entity_paths = self.get_entity_paths(&reachable_paths);

        // Build the AccessTrie for each entity path
        let mut result = HashMap::new();
        for entity_path in entity_paths {
            let trie = self.build_access_trie_for_entity(&entity_path, &dependents_map);

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
                // PANIC SAFETY: types are computed for all paths in the manifest
                #[allow(clippy::unwrap_used)]
                match types.get(path.id).unwrap() {
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
            // PANIC SAFETY: all manifests are typed after their creation.
            panic!("Entity manifest lacked types after its creation");
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
        dependents_map: &HashMap<AccessPath, Vec<AccessPath>>,
    ) -> AccessTrie {
        // Create a new trie for this entity
        let mut trie = AccessTrie::new();

        // Use a recursive helper to build the trie
        self.build_trie_recursive(entity_path, &mut trie, dependents_map, &mut HashSet::new());

        trie
    }

    /// Recursive helper function to build the AccessTrie
    /// Traverses the dependents map starting from the entity path
    fn build_trie_recursive(
        &self,
        path: &AccessPath,
        trie: &mut AccessTrie,
        dependents_map: &HashMap<AccessPath, Vec<AccessPath>>,
        visited: &mut HashSet<AccessPath>,
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
                    if let AccessPathVariant::Attribute { attr, .. } = variant {
                        // Get or create the field in the trie
                        let field_trie = trie.get_or_create_field(attr);

                        // If this is an entity, don't continue building the trie
                        if !self.is_entity_path(dependent) {
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
    pub(crate) fn reachable_paths(&self) -> HashSet<AccessPath> {
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
