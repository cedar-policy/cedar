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

//! Entity Manifest definition and static analysis.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};

use crate::ast::{EntityUID, PolicySet, RequestType, Var};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;

pub(crate) mod analysis;
#[cfg(test)]
mod entity_manifest_tests;
#[cfg(test)]
mod entity_slice_tests;
mod errors;
mod human_format;
mod loader;
pub(crate) mod manifest_helpers;
pub mod slicing;
mod type_annotations;

// Import errors directly
pub use crate::validator::entity_manifest::errors::{
    AccessPathNotFoundError, ConversionError, EntityManifestError, EntityManifestFromJsonError,
    MismatchedEntityManifestError, MismatchedMissingEntityError, MismatchedNotStrictSchemaError,
    PartialExpressionError, PartialRequestError, PathExpressionParseError,
    UnsupportedCedarFeatureError,
};

use crate::validator::entity_manifest::analysis::analyze_expr_access_paths;
// Re-export types from human_format module
use crate::validator::Validator;
use crate::validator::{
    typecheck::{PolicyCheck, Typechecker},
    types::Type,
    ValidationMode, ValidatorSchema,
};

/// Stores paths for a specific request type, including the request type,
/// access dag, and access paths.
#[doc = include_str!("../../experimental_warning.md")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathsForRequestType {
    /// The request type
    pub(crate) request_type: RequestType,
    /// The backing store for the paths, a directed acyclic graph
    pub(crate) dag: AccessDag,
    /// The set of access paths required for this request type
    pub(crate) access_paths: AccessPaths,
}

impl PathsForRequestType {
    /// Create a new [`PathsForRequestType`]
    pub fn new(request_type: RequestType) -> Self {
        Self {
            request_type,
            dag: AccessDag::default(),
            access_paths: AccessPaths::default(),
        }
    }

    /// Get the request type
    pub fn request_type(&self) -> &RequestType {
        &self.request_type
    }

    /// Get the access dag
    pub(crate) fn dag(&self) -> &AccessDag {
        &self.dag
    }

    /// Get mutable access to the access dag
    pub(crate) fn dag_mut(&mut self) -> &mut AccessDag {
        &mut self.dag
    }

    /// Get the access paths
    pub fn access_paths(&self) -> &AccessPaths {
        &self.access_paths
    }

    /// Get mutable access to the access paths
    pub fn access_paths_mut(&mut self) -> &mut AccessPaths {
        &mut self.access_paths
    }

    /// Add all paths from `other` to `self`
    /// Don't make this public! Doesn't restore type information.
    fn union_with(&mut self, other: &Self) -> PathMapping {
        let mut path_mapping = PathMapping::new();
        // First, add all paths from the other manifest to this manifest
        // and build a mapping from paths in the other manifest to paths in this manifest
        for i in 0..other.dag.manifest_store.len() {
            // PANIC SAFETY: Iterating over length of vector and not mutating it
            #[allow(clippy::unwrap_used)]
            let variant = &other.dag.manifest_store.get(i).unwrap();
            let mapped_variant = self.map_variant(variant, &mut path_mapping);
            let new_path = self.dag.add_path(mapped_variant);
            path_mapping.path_map.insert(i, new_path.id);
        }

        // Map each path from the other manifest to this manifest
        for path in &other.access_paths.paths {
            if let Some(mapped_path) = path_mapping.map_path(path) {
                self.access_paths.insert(mapped_path);
            }
        }

        path_mapping
    }

    /// Leaf nodes like variables and literal ids don't need to be loaded.
    /// Variables are included in the request.
    /// We prune these from the set of access paths required.
    fn prune_leafs(&mut self) {
        let mut to_remove = Vec::new();
        for path in &self.access_paths.paths {
            if path.is_leaf(&self.dag) {
                to_remove.push(path.clone());
            }
        }
        for path in to_remove {
            self.access_paths.remove(&path);
        }
    }
}

/// Data structure storing what data is needed based on the the [`RequestType`].
///
/// For each request type, the [`EntityManifest`] stores
/// a [`PathsForRequestType`] containing the data paths needed for that request type.
///
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[doc = include_str!("../../experimental_warning.md")]
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityManifest {
    /// A map from request types to PathsForRequestType.
    /// For each request, stores what access paths are required.
    #[serde_as(as = "Vec<(_, _)>")]
    pub(crate) per_action: HashMap<RequestType, PathsForRequestType>,
}

/// A backing store for a set of access paths
/// stored as a directed acyclic graph.
///
/// Edges in the graph denote a data dependency.
/// For example, an attribute may depend on the principal entity
/// or a record in another entity.
///
/// After construction, the dag is annotated with the types of all of the access paths.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessDag {
    /// A map from [`AccessPathInternal`] to the [`AccessPath`], which
    /// indexes the `manifest_store`.
    /// This allows us to de-duplicate equivalent access paths using the "hash cons"
    /// programming trick.
    #[serde_as(as = "Vec<(_, _)>")]
    pub(crate) manifest_hash_cons: HashMap<AccessPathVariant, AccessPath>,
    /// The backing store of access paths in the entity manifest.
    /// Each entry is the variant for the corresponding AccessPath with the same ID.
    pub(crate) manifest_store: Vec<AccessPathVariant>,
    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    pub(crate) types: Option<Vec<Type>>,
}

/// Stores a set of access paths.
#[doc = include_str!("../../experimental_warning.md")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccessPaths {
    /// The set of access paths
    paths: HashSet<AccessPath>,
}

/// Represents a path of data involving a sequence of
/// attribute or tag accesses, ending in a cedar variable or literal.
/// Internally represented as a single integer into a backing store
/// (a directed acyclic graph).
/// Hashing an [`AccessPath`] is extremely cheap, so resulting data can be cached.
#[doc = include_str!("../../experimental_warning.md")]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccessPath {
    /// The unique identifier for this path in the [`AccessDag`].
    id: usize,
}

/// Turn an [`AccessPath`] into a [`AccessPathVariant`] in order to perform pattern matching.
/// Stores the access path's constructor and children.
#[doc = include_str!("../../experimental_warning.md")]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessPathVariant {
    /// Literal entity ids
    Literal(EntityUID),
    /// A Cedar variable
    Var(Var),
    /// A literal Cedar string
    String(SmolStr),
    /// A record or entity attribute
    Attribute {
        /// The entity whose attribute is being requested
        of: AccessPath,
        /// The requested attribute
        attr: SmolStr,
    },
    /// An entity tag access
    Tag {
        /// The entity whose tag is requested
        of: AccessPath,
        /// The accesspath computing the requested tag (may be a literal string)
        tag: AccessPath,
    },
    /// Whether this entity has a particular ancestor is requested
    Ancestor {
        /// The entity whose ancestor is requested
        of: AccessPath,
        /// The ancestor whose presence is requested
        ancestor: AccessPath,
    },
}

/// The root of a data path or [`RootAccessTrie`].
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[doc = include_str!("../../experimental_warning.md")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub enum EntityRoot {
    /// Literal entity ids
    Literal(EntityUID),
    /// A Cedar variable
    Var(Var),
}

impl Display for EntityRoot {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityRoot::Literal(l) => write!(f, "{l}"),
            EntityRoot::Var(v) => write!(f, "{v}"),
        }
    }
}

impl AccessPath {
    /// Get the variant for this path
    ///
    /// Returns an error if the path is not found in the entity manifest,
    /// which may indicate that you are using the wrong entity manifest with this path.
    pub fn get_variant<'a>(
        &self,
        store: &'a AccessDag,
    ) -> Result<&'a AccessPathVariant, AccessPathNotFoundError> {
        store
            .manifest_store
            .get(self.id)
            .ok_or_else(|| AccessPathNotFoundError { path_id: self.id })
    }
}

impl AccessDag {
    pub(crate) fn add_path(&mut self, variant: AccessPathVariant) -> AccessPath {
        // Check if the variant already exists in the hash_cons map
        if let Some(path) = self.manifest_hash_cons.get(&variant) {
            // If it does, return the existing AccessPath
            return path.clone();
        }

        // If it doesn't exist, create a new AccessPath with the next available ID
        let id = self.manifest_store.len();
        let path = AccessPath { id };

        // Add the variant to the hash_cons map
        self.manifest_hash_cons
            .insert(variant.clone(), path.clone());

        // Add the variant to the manifest_store
        self.manifest_store.push(variant);

        // Return the new AccessPath
        path
    }
}

/// A mapping from paths in one manifest to paths in another manifest
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMapping {
    /// Maps from source path IDs to target path IDs
    pub(crate) path_map: HashMap<usize, usize>,
}

impl PathMapping {
    /// Create a new empty path mapping
    pub fn new() -> Self {
        Self {
            path_map: HashMap::new(),
        }
    }

    /// Map a path from the source manifest to the target manifest
    pub fn map_path(&self, path: &AccessPath) -> Option<AccessPath> {
        self.path_map.get(&path.id).map(|&id| AccessPath { id })
    }
}

impl PartialEq for EntityManifest {
    fn eq(&self, other: &Self) -> bool {
        // Check if self is a subset of other and other is a subset of self
        self.is_subset_of(other) && other.is_subset_of(self)
    }
}

impl Eq for EntityManifest {}

impl PathsForRequestType {
    /// Map a variant from the source manifest to the target manifest
    ///
    /// This method recursively maps a variant and its children from the source manifest
    /// to the target manifest, creating new paths in the target manifest as needed.
    fn map_variant(
        &mut self,
        variant: &AccessPathVariant,
        path_mapping: &mut PathMapping,
    ) -> AccessPathVariant {
        match variant {
            AccessPathVariant::Literal(euid) => AccessPathVariant::Literal(euid.clone()),
            AccessPathVariant::Var(var) => AccessPathVariant::Var(*var),
            AccessPathVariant::String(s) => AccessPathVariant::String(s.clone()),
            AccessPathVariant::Attribute { of, attr } => {
                // Recursively map the 'of' path
                let mapped_of = self.map_path_or_create(of, path_mapping);

                AccessPathVariant::Attribute {
                    of: mapped_of,
                    attr: attr.clone(),
                }
            }
            AccessPathVariant::Tag { of, tag } => {
                // Recursively map both paths
                let mapped_of = self.map_path_or_create(of, path_mapping);
                let mapped_tag = self.map_path_or_create(tag, path_mapping);

                AccessPathVariant::Tag {
                    of: mapped_of,
                    tag: mapped_tag,
                }
            }
            AccessPathVariant::Ancestor { of, ancestor } => {
                // Recursively map both paths
                let mapped_of = self.map_path_or_create(of, path_mapping);
                let mapped_ancestor = self.map_path_or_create(ancestor, path_mapping);

                AccessPathVariant::Ancestor {
                    of: mapped_of,
                    ancestor: mapped_ancestor,
                }
            }
        }
    }

    /// Helper method to map a path or create a new one if it doesn't exist in the mapping
    fn map_path_or_create(
        &mut self,
        path: &AccessPath,
        path_mapping: &mut PathMapping,
    ) -> AccessPath {
        // Check if the path is already mapped
        if let Some(mapped_path) = path_mapping.map_path(path) {
            return mapped_path;
        }

        // If not, get the variant for this path from the source manifest
        // and recursively map it to create a new path in the target manifest
        if let Ok(variant) = path.get_variant(&self.dag).clone() {
            let variant = variant.clone();
            let mapped_variant = self.map_variant(&variant, path_mapping);
            let new_path = self.dag.add_path(mapped_variant);
            path_mapping.path_map.insert(path.id, new_path.id);
            new_path
        } else {
            // If we can't find the variant, create a safe default
            // This should rarely happen in practice
            let default_variant = AccessPathVariant::Var(Var::Principal);
            self.dag.add_path(default_variant)
        }
    }
}

impl EntityManifest {
    /// Create a new empty [`EntityManifest`].
    pub(crate) fn new() -> Self {
        Self {
            per_action: HashMap::new(),
        }
    }

    /// Check if this manifest is a subset of another manifest
    ///
    /// A manifest is a subset of another if all access paths from one are reachable from the other.
    fn is_subset_of(&self, other: &Self) -> bool {
        // For each request type, check that the other is a subset
        for (request_type, my_paths) in &self.per_action {
            let Some(other_paths) = other.per_action.get(request_type) else {
                return false;
            };
            let mut other_clone = other_paths.clone();

            let mapping = other_clone.union_with(my_paths);

            // now find all the reachable paths in other
            let mut reachable = HashSet::new();
            for path in other_paths.access_paths.paths() {
                let subpaths = path.subpaths(&other_paths.dag);
                reachable.extend(subpaths.paths().clone());
            }

            // now check that all paths in self are in reachable
            for path in my_paths.access_paths.paths() {
                let Some(mapped) = mapping.map_path(path) else {
                    return false;
                };
                if !reachable.contains(&mapped) {
                    return false;
                }
            }
        }

        return true;
    }

    /// Union this entity manifest with another entity manifest
    ///
    /// This adds all paths from the other manifest to this manifest,
    /// and updates the `per_action` map to include the paths from the other manifest.
    ///
    /// Returns a mapping from paths in the other manifest to paths in this manifest.
    /// 
    /// Not public! Doesn't restore type information.
    pub(crate) fn union_with(&mut self, other: &EntityManifest) {
        // Update the `per_action` map to include the paths from the other manifest
        for (request_type, other_paths_for_request_type) in &other.per_action {
            let my_path_for_request_type = self
                .per_action
                .entry(request_type.clone())
                .or_insert_with(|| PathsForRequestType::new(request_type.clone()));

            my_path_for_request_type.union_with(other_paths_for_request_type);
        }
    }

    /// Get the contents of the entity manifest
    /// indexed by the type of the request.
    pub fn per_action(&self) -> &HashMap<RequestType, PathsForRequestType> {
        &self.per_action
    }

    /// Convert a json string to an [`EntityManifest`].
    /// Requires the schema in order to add type annotations.
    pub fn from_json_str(
        json: &str,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntityManifestFromJsonError> {
        match serde_json::from_str::<EntityManifest>(json) {
            Ok(manifest) => manifest.add_types(schema).map_err(|e| e.into()),
            Err(e) => Err(e.into()),
        }
    }

    /// Convert a json value to an [`EntityManifest`].
    /// Requires the schema in order to add type annotations.
    #[allow(dead_code)]
    pub fn from_json_value(
        value: serde_json::Value,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntityManifestFromJsonError> {
        match serde_json::from_value::<EntityManifest>(value) {
            Ok(manifest) => manifest.add_types(schema).map_err(|e| e.into()),
            Err(e) => Err(e.into()),
        }
    }
}

impl AccessPath {
    /// If there are no children, this is a leaf node
    pub fn is_leaf(&self, store: &AccessDag) -> bool {
        self.children(store).is_empty()
    }

    /// Get the immediate children of this path
    pub fn children(&self, store: &AccessDag) -> Vec<AccessPath> {
        // Get the variant for this path
        if let Some(variant) = store.manifest_hash_cons.iter().find_map(|(variant, path)| {
            if path.id == self.id {
                Some(variant)
            } else {
                None
            }
        }) {
            // Return children based on the variant
            match variant {
                AccessPathVariant::Attribute { of, .. } => {
                    vec![of.clone()]
                }
                AccessPathVariant::Tag { of, tag } => {
                    vec![of.clone(), tag.clone()]
                }
                AccessPathVariant::Ancestor { of, ancestor } => {
                    vec![of.clone(), ancestor.clone()]
                }
                // Literal, Var, and String variants don't have children
                _ => vec![],
            }
        } else {
            vec![]
        }
    }

    /// Helper method to collect all subpaths into the provided set
    /// This is more efficient than creating new AccessPaths objects and extending them
    pub fn collect_subpaths_into(&self, store: &AccessDag, paths: &mut HashSet<AccessPath>) {
        // Add self to the paths
        paths.insert(self.clone());

        // Get immediate children
        let children = self.children(store);

        // Recursively collect subpaths for each child
        for child in children {
            child.collect_subpaths_into(store, paths);
        }
    }

    /// Get all subpaths of this path, including itself.
    pub fn subpaths(&self, store: &AccessDag) -> AccessPaths {
        let mut paths = HashSet::new();
        self.collect_subpaths_into(store, &mut paths);
        AccessPaths { paths }
    }
}

impl AccessPaths {
    /// Add all the access paths from another [`AccessPaths`]
    /// to this one, mutably.
    pub fn extend(&mut self, other: Self) {
        self.paths.extend(other.paths)
    }

    /// Owned version of extend.
    pub fn extend_owned(mut self, other: Self) -> Self {
        self.extend(other);
        self
    }

    /// Add a path to the set.
    pub fn insert(&mut self, path: AccessPath) {
        self.paths.insert(path);
    }

    /// A set with a single element.
    pub fn from_path(path: AccessPath) -> Self {
        let mut paths = HashSet::new();
        paths.insert(path);
        Self { paths }
    }

    /// Get a reference to the paths.
    pub fn paths(&self) -> &HashSet<AccessPath> {
        &self.paths
    }

    /// Remove a path
    pub fn remove(&mut self, path: &AccessPath) {
        self.paths.remove(path);
    }
}

/// Computes an [`EntityManifest`] from the schema and policies.
/// The policies must validate against the schema in strict mode,
/// otherwise an error is returned.
pub fn compute_entity_manifest(
    validator: &Validator,
    policies: &PolicySet,
) -> Result<EntityManifest, EntityManifestError> {
    // first, run strict validation to ensure there are no errors
    let validation_res = validator.validate(policies, ValidationMode::Strict);
    if !validation_res.validation_passed() {
        return Err(EntityManifestError::Validation(validation_res));
    }

    let mut manifest = EntityManifest::new();

    let typechecker = Typechecker::new(validator.schema(), ValidationMode::Strict);
    // now, for each policy we add the data it requires to the manifest
    for policy in policies.policies() {
        // typecheck the policy and get all the request environments
        let request_envs = typechecker.typecheck_by_request_env(policy.template());
        for (request_env, policy_check) in request_envs {
            let request_type = request_env
                .to_request_type()
                .ok_or(PartialRequestError {})?;

            let mut per_request = match manifest.per_action.entry(request_type.clone()) {
                Entry::Occupied(mut occupied) => occupied.remove(),
                Entry::Vacant(_) => PathsForRequestType::new(request_type.clone()),
            };

            match policy_check {
                PolicyCheck::Success(typechecked_expr) => {
                    // compute the access paths from the typechecked expr
                    // using static analysis
                    let res = analyze_expr_access_paths(&typechecked_expr, &mut per_request.dag)?;
                    // add the result to the per_request
                    per_request.access_paths.extend(res.all_access_paths());
                }
                PolicyCheck::Irrelevant(_, _) => {}

                // PANIC SAFETY: policy check should not fail after full strict validation above.
                #[allow(clippy::panic)]
                PolicyCheck::Fail(_errors) => {
                    panic!("Policy check failed after validation succeeded")
                }
            };

            // prune leafs, which are included in the request and don't need to be loaded
            per_request.prune_leafs();

            // add the per action entry back
            manifest.per_action.insert(request_type, per_request);
        }
    }

    // PANIC SAFETY: entity manifest cannot be out of date, since it was computed from the schema given
    #[allow(clippy::unwrap_used)]
    Ok(manifest.add_types(validator.schema()).unwrap())
}
