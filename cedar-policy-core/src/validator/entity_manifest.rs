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

use std::collections::{HashMap, HashSet};

use crate::ast::{EntityUID, PolicySet, RequestType, Var};
use crate::validator::entity_manifest::err::{
    AccessTermNotFoundError, EntityManifestError, EntityManifestFromJsonError, PartialRequestError,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;

pub(crate) mod analysis;
#[cfg(test)]
mod entity_manifest_tests;
#[cfg(test)]
mod entity_slice_tests;
pub mod err;
#[cfg(test)]
mod human_format;
mod loader;
pub(crate) mod manifest_helpers;
pub mod slicing;
mod type_annotations;

use crate::validator::entity_manifest::analysis::analyze_expr_access_paths as analyze_expr_access_terms;
use crate::validator::Validator;
use crate::validator::{
    typecheck::{PolicyCheck, Typechecker},
    types::Type,
    ValidationMode, ValidatorSchema,
};

/// For a given request type, stores information about what
/// data is required.
/// It stores the request type, access dag, and access terms.
///
/// Each access term stores a data path, starting from a cedar variable or literal.
/// Access paths include requests for entity attributes, tags, and ancestors.
/// Data not mentioned by [`AccessPaths`] can be omitted, including fields of records or entity attributes.
/// See [`AccessPath`] for more details.
///
/// This can be used to load data only necessary data
/// from a backing store into an [`Entities`] object.
/// Suggested usage options
///   - load each [`AccessTerm`] from [`AccessTerms`] separately,
///   - take advantage or shared sub-terms and load all the access terms at once
///   - load data in batches, traversing the access terms bottom-up
///   - avoid using this directly and instead use the [`EntityLoader`] API.
///
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[doc = include_str!("../../experimental_warning.md")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestTypeTerms {
    /// The request type
    pub(crate) request_type: RequestType,
    /// The backing store for the terms, a directed acyclic graph
    pub(crate) dag: AccessDag,
    /// The set of access terms required for this request type
    pub(crate) access_terms: AccessTerms,
}

impl RequestTypeTerms {
    /// Create a new [`RequestTypeTerms`]
    pub fn new(request_type: RequestType) -> Self {
        Self {
            request_type,
            dag: AccessDag::default(),
            access_terms: AccessTerms::default(),
        }
    }

    /// Get the request type
    pub fn request_type(&self) -> &RequestType {
        &self.request_type
    }

    /// Get the access dag
    pub fn dag(&self) -> &AccessDag {
        &self.dag
    }

    /// Get the access terms
    pub fn access_terms(&self) -> &AccessTerms {
        &self.access_terms
    }

    /// Add all terms from `other` to `self`
    /// Don't make this public! Doesn't restore type information.
    fn union_with(&mut self, other: &Self) -> TermMapping {
        let mut term_mapping = TermMapping::new();
        // First, add all terms from the other manifest to this manifest
        // and build a mapping from terms in the other manifest to terms in this manifest
        for (i, variant) in other.dag.manifest_store.iter().enumerate() {
            let mapped_variant = self.map_variant(variant, &mut term_mapping);
            let new_term = self.dag.add_term(mapped_variant);
            term_mapping.term_map.insert(i, new_term.id);
        }

        // Map each term from the other manifest to this manifest
        for term in &other.access_terms.terms {
            // PANIC SAFETY: all terms are mapped in the previous loop
            #[allow(clippy::unwrap_used)]
            self.access_terms
                .insert(term_mapping.map_term(*term).unwrap());
        }

        term_mapping
    }

    /// Leaf nodes like variables and literal ids don't need to be loaded.
    /// Variables are included in the request.
    /// We prune these from the set of access terms required.
    fn prune_leafs(&mut self) {
        let terms = std::mem::take(&mut self.access_terms.terms);
        self.access_terms.terms = terms
            .into_iter()
            .filter(|term| !term.is_leaf(&self.dag))
            .collect();
    }

    /// Map a variant from the source manifest to the target manifest
    ///
    /// This method recursively maps a variant and its children from the source manifest
    /// to the target manifest, creating new terms in the target manifest as needed.
    fn map_variant(
        &mut self,
        variant: &AccessTermVariant,
        term_mapping: &mut TermMapping,
    ) -> AccessTermVariant {
        match variant {
            AccessTermVariant::Literal(euid) => AccessTermVariant::Literal(euid.clone()),
            AccessTermVariant::Var(var) => AccessTermVariant::Var(*var),
            AccessTermVariant::String(s) => AccessTermVariant::String(s.clone()),
            AccessTermVariant::Attribute { of, attr } => {
                // Recursively map the 'of' term
                let mapped_of = self.map_term_or_create(*of, term_mapping);

                AccessTermVariant::Attribute {
                    of: mapped_of,
                    attr: attr.clone(),
                }
            }
            AccessTermVariant::Tag { of, tag } => {
                // Recursively map both terms
                let mapped_of = self.map_term_or_create(*of, term_mapping);
                let mapped_tag = self.map_term_or_create(*tag, term_mapping);

                AccessTermVariant::Tag {
                    of: mapped_of,
                    tag: mapped_tag,
                }
            }
            AccessTermVariant::Ancestor { of, ancestor } => {
                // Recursively map both terms
                let mapped_of = self.map_term_or_create(*of, term_mapping);
                let mapped_ancestor = self.map_term_or_create(*ancestor, term_mapping);

                AccessTermVariant::Ancestor {
                    of: mapped_of,
                    ancestor: mapped_ancestor,
                }
            }
        }
    }

    /// Helper method to map a term or create a new one if it doesn't exist in the mapping
    fn map_term_or_create(
        &mut self,
        term: AccessTerm,
        term_mapping: &mut TermMapping,
    ) -> AccessTerm {
        // Check if the term is already mapped
        if let Some(mapped_term) = term_mapping.map_term(term) {
            return mapped_term;
        }

        // If not, get the variant for this term from the source manifest
        // and recursively map it to create a new term in the target manifest
        // PANIC SAFETY: Only internal cedar functions add terms, and these correspond to the same manifest.
        #[allow(clippy::expect_used)]
        let variant = term
            .get_variant(&self.dag)
            .expect("Entity manifest with terms belonging to a different manifest")
            .clone();
        let mapped_variant = self.map_variant(&variant, term_mapping);
        let new_term = self.dag.add_term(mapped_variant);
        term_mapping.term_map.insert(term.id, new_term.id);
        new_term
    }
}

/// Data structure storing what data is needed based on the the [`RequestType`].
///
/// For each request type, the [`EntityManifest`] stores
/// a [`RequestTypeTerms`] containing the data terms needed for that request type.
///
/// The [`EntityManifest`] can be used redirectly to load data,
/// or be used with the (unreleased) [`EntityLoader`] API.
///
/// See [`RequestTypeTerms`] for more details.
///
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[doc = include_str!("../../experimental_warning.md")]
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityManifest {
    /// A map from request types to RequestTypeTerms.
    /// For each request, stores what access terms are required.
    #[serde_as(as = "Vec<(_, _)>")]
    pub(crate) per_action: HashMap<RequestType, RequestTypeTerms>,
}

/// A backing store for a set of access terms
/// stored as a directed acyclic graph.
///
/// Edges in the graph denote a data dependency.
/// For example, an attribute may depend on the principal entity
/// or a record in another entity.
///
/// After construction, the dag is annotated with the types of all of the access terms.
#[doc = include_str!("../../experimental_warning.md")]
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AccessDag {
    /// A map from [`AccessTermInternal`] to the [`AccessTerm`], which
    /// indexes the `manifest_store`.
    /// This allows us to de-duplicate equivalent access terms using the "hash cons"
    /// programming trick.
    #[serde_as(as = "Vec<(_, _)>")]
    pub(crate) manifest_hash_cons: HashMap<AccessTermVariant, AccessTerm>,
    /// The backing store of access terms in the entity manifest.
    /// Each entry is the variant for the corresponding AccessTerm with the same ID.
    pub(crate) manifest_store: Vec<AccessTermVariant>,
    /// The types of each access term in the manifest store.
    /// This is populated when the manifest is created, and operations preserve the types (by recomputation).
    /// Each type is an option because some terms may not have a type if they don't appear in the schema.
    /// This happens for example with `has` operations on entities without the attribute.
    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    pub(crate) types: Vec<Option<Type>>,
}

/// Stores a set of access terms.
///
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[doc = include_str!("../../experimental_warning.md")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccessTerms {
    /// The set of access terms
    terms: HashSet<AccessTerm>,
}

impl IntoIterator for AccessTerms {
    type Item = AccessTerm;
    type IntoIter = std::collections::hash_set::IntoIter<AccessTerm>;

    fn into_iter(self) -> Self::IntoIter {
        self.terms.into_iter()
    }
}

/// Represents a piece of requested data involving a sequence of
/// attribute or tag accesses, ending in a cedar variable or literal.
/// All subpaths must also be included in the entity store.
///
///
/// Internally represented as a single integer into a backing store
/// (a directed acyclic graph).
/// Hashing an [`AccessTerm`] is extremely cheap, so resulting data can be cached.
///
/// To match on this [`AccessTerm`], turn it into a [`AccessTermVariant`] with the [`AccessTerm::get_variant`] method.
///
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[doc = include_str!("../../experimental_warning.md")]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Copy)]
pub struct AccessTerm {
    /// The unique identifier for this term in the [`AccessDag`].
    id: usize,
}

/// Stores the access term's constructor and children.
///
/// Includes leaf nodes (literals, variables, and strings)
/// as well as attribute accesses, tag accesses, and ancestor accesses.
///
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[doc = include_str!("../../experimental_warning.md")]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessTermVariant {
    /// Literal entity ids
    Literal(EntityUID),
    /// A Cedar variable
    Var(Var),
    /// A literal Cedar string
    String(SmolStr),
    /// A record or entity attribute
    Attribute {
        /// The entity whose attribute is being requested
        of: AccessTerm,
        /// The requested attribute
        attr: SmolStr,
    },
    /// An entity tag access
    Tag {
        /// The entity whose tag is requested
        of: AccessTerm,
        /// The [`AccessTerm`] computing the requested tag (may be a literal string)
        tag: AccessTerm,
    },
    /// Whether this entity has a particular ancestor is requested
    Ancestor {
        /// The entity whose ancestor is requested
        of: AccessTerm,
        /// The ancestor whose presence is requested
        ancestor: AccessTerm,
    },
}

impl AccessTerm {
    /// Get the variant for this term
    ///
    /// Returns an error if the term is not found in the entity manifest,
    /// which may indicate that you are using the wrong entity manifest with this term.
    pub fn get_variant<'a>(
        &self,
        store: &'a AccessDag,
    ) -> Result<&'a AccessTermVariant, AccessTermNotFoundError> {
        store
            .manifest_store
            .get(self.id)
            .ok_or(AccessTermNotFoundError { path_id: self.id })
    }

    /// Like `get_variant`, but asserts that the term is in the store.
    /// We use this internally because we know terms that come from the same
    /// [`RequestTypeTerms`] are guaranteed to be in the store.
    pub(crate) fn get_variant_internal(self, store: &AccessDag) -> &AccessTermVariant {
        // PANIC SAFETY: This function is only called on terms that are in the store.
        #[allow(clippy::unwrap_used)]
        self.get_variant(store).unwrap()
    }
}

impl AccessDag {
    pub(crate) fn add_term(&mut self, variant: AccessTermVariant) -> AccessTerm {
        // Check if the variant already exists in the hash_cons map
        if let Some(term) = self.manifest_hash_cons.get(&variant) {
            // If it does, return the existing AccessTerm
            return *term;
        }

        // If it doesn't exist, create a new AccessTerm with the next available ID
        let id = self.manifest_store.len();
        let term = AccessTerm { id };

        // Add the variant to the hash_cons map
        self.manifest_hash_cons.insert(variant.clone(), term);

        // Add the variant to the manifest_store
        self.manifest_store.push(variant);

        // Return the new AccessTerm
        term
    }
}

/// A mapping from terms in one manifest to terms in another manifest
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TermMapping {
    /// Maps from source term IDs to target term IDs
    pub(crate) term_map: HashMap<usize, usize>,
}

impl Default for TermMapping {
    fn default() -> Self {
        Self::new()
    }
}

impl TermMapping {
    /// Create a new empty term mapping
    pub(crate) fn new() -> Self {
        Self {
            term_map: HashMap::new(),
        }
    }

    /// Map a term from the source manifest to the target manifest
    pub(crate) fn map_term(&self, term: AccessTerm) -> Option<AccessTerm> {
        self.term_map.get(&term.id).map(|&id| AccessTerm { id })
    }
}

impl PartialEq for EntityManifest {
    fn eq(&self, other: &Self) -> bool {
        // Check if self is a subset of other and other is a subset of self
        self.is_subset_of(other) && other.is_subset_of(self)
    }
}

impl Eq for EntityManifest {}

impl EntityManifest {
    /// Create a new empty [`EntityManifest`].
    pub(crate) fn new() -> Self {
        Self {
            per_action: HashMap::new(),
        }
    }

    /// Check if this manifest is a subset of another manifest
    ///
    /// A manifest is a subset of another if all access terms from one are reachable from the other.
    fn is_subset_of(&self, other: &Self) -> bool {
        // For each request type, check that the other is a subset
        for (request_type, my_terms) in &self.per_action {
            let Some(other_terms) = other.per_action.get(request_type) else {
                return false;
            };
            let mut other_clone = other_terms.clone();

            // Call `union_with` to get a mapping from terms in self to terms in other.
            // Terms not present in `other` will also have a mapping to `other_clone`, but will be missing in `other`.
            let mapping = other_clone.union_with(my_terms);

            // Find all reachable terms in `other`
            let reachable = other_terms
                .access_terms
                .terms()
                .iter()
                .flat_map(|term| term.subterms(&other_terms.dag).into_iter())
                .collect::<HashSet<_>>();

            // now check that all terms in self are in reachable in `other`
            // using the mapping
            for term in my_terms.access_terms.terms() {
                let Some(mapped) = mapping.map_term(*term) else {
                    return false;
                };
                if !reachable.contains(&mapped) {
                    return false;
                }
            }
        }

        true
    }

    /// Get the contents of the entity manifest
    /// indexed by the type of the request.
    pub fn per_action(&self) -> &HashMap<RequestType, RequestTypeTerms> {
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

impl AccessTerm {
    /// If there are no children, this is a leaf node
    pub(crate) fn is_leaf(&self, store: &AccessDag) -> bool {
        self.children(store).is_empty()
    }

    /// Get the immediate children of this term
    pub(crate) fn children(&self, store: &AccessDag) -> Vec<AccessTerm> {
        // PANIC SAFETY: This function is only called on terms that are in the store.
        #[allow(clippy::unwrap_used)]
        let variant = self.get_variant(store).unwrap();
        // Return children based on the variant
        match variant {
            AccessTermVariant::Attribute { of, .. } => {
                vec![of.clone()]
            }
            AccessTermVariant::Tag { of, tag } => {
                vec![of.clone(), tag.clone()]
            }
            AccessTermVariant::Ancestor { of, ancestor } => {
                vec![of.clone(), ancestor.clone()]
            }
            AccessTermVariant::Literal(_) => vec![],
            AccessTermVariant::Var(_) => vec![],
            AccessTermVariant::String(_) => vec![],
        }
    }

    /// Helper method to collect all subterms into the provided set
    /// This is more efficient than creating new [`AccessTerms`] objects and extending them
    pub fn collect_subterms_into(&self, store: &AccessDag, terms: &mut HashSet<AccessTerm>) {
        // Add self to the terms
        terms.insert(*self);

        // Get immediate children
        let children = self.children(store);

        // Recursively collect subterms for each child
        for child in children {
            child.collect_subterms_into(store, terms);
        }
    }

    /// Get all subterms of this term, including itself.
    pub fn subterms(&self, store: &AccessDag) -> AccessTerms {
        let mut terms = HashSet::new();
        self.collect_subterms_into(store, &mut terms);
        AccessTerms { terms }
    }
}

impl AccessTerms {
    /// Add all the access terms from another [`AccessTerms`]
    /// to this one, mutably.
    pub fn extend(&mut self, other: Self) {
        self.terms.extend(other.terms)
    }

    /// Owned version of extend.
    pub fn extend_owned(mut self, other: Self) -> Self {
        self.extend(other);
        self
    }

    /// Add a term to the set.
    pub fn insert(&mut self, term: AccessTerm) {
        self.terms.insert(term);
    }

    /// A set with a single element.
    pub fn from_term(term: AccessTerm) -> Self {
        let mut terms = HashSet::new();
        terms.insert(term);
        Self { terms }
    }

    /// Get a reference to the terms.
    pub fn terms(&self) -> &HashSet<AccessTerm> {
        &self.terms
    }

    /// Remove a term
    pub fn remove(&mut self, term: AccessTerm) {
        self.terms.remove(&term);
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

            let mut per_request = manifest
                .per_action
                .remove(&request_type)
                .unwrap_or(RequestTypeTerms::new(request_type.clone()));

            match policy_check {
                PolicyCheck::Success(typechecked_expr) => {
                    // compute the access terms from the typechecked expr
                    // using static analysis
                    let res = analyze_expr_access_terms(&typechecked_expr, &mut per_request.dag)?;
                    // add the result to the per_request
                    per_request.access_terms.extend(res.all_access_paths());
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
