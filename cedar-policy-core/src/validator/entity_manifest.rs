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

use crate::ast::{
    BinaryOp, EntityUID, Expr, ExprKind, Literal, PolicySet, RequestType, UnaryOp, Var,
};
use crate::entities::err::EntitiesError;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;
use thiserror::Error;

mod analysis;
mod loader;
pub mod slicing;
mod type_annotations;

use crate::validator::entity_manifest::analysis::{
    EntityManifestAnalysisResult, WrappedAccessPaths,
};
use crate::validator::{
    typecheck::{PolicyCheck, Typechecker},
    types::Type,
    ValidationMode, ValidatorSchema,
};
use crate::validator::{ValidationResult, Validator};

/// Data structure storing what data is needed based on the the [`RequestType`].
///
/// For each request type, the [`EntityManifest`] stores
/// a [`RootAccessTrie`] of data to retrieve.
///
/// `T` represents an optional type annotation on each
/// node in the [`AccessTrie`].
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[doc = include_str!("../../experimental_warning.md")]
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityManifest {
    /// The backing store for the entity manifest,
    /// a directed acyclic graph storing a set of paths
    pub(crate) dag: AccessPathDag,
    /// A map from request types to sets of [`AccessPath`].
    /// For each request, stores what access paths are required.
    #[serde_as(as = "Vec<(_, _)>")]
    pub(crate) per_action: HashMap<RequestType, AccessPaths>,
}

/// A backing store for a set of access paths
/// stored as a directed acyclic graph.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessPathDag {
    /// A map from [`AccessPathInternal`] to the [`AccessPath`], which
    /// indexes the `manifest_store`.
    /// This allows us to de-duplicate equivalent access paths using the "hash cons"
    /// programming trick.
    #[serde_as(as = "Vec<(_, _)>")]
    pub(crate) manifest_hash_cons: HashMap<AccessPathVariant, AccessPath>,
    /// The backing store of access paths in the entity manifest.
    pub(crate) manifest_store: Vec<AccessPath>,
}

/// Stores a set of access paths.
#[doc = include_str!("../../experimental_warning.md")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessPaths {
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
    Attribute { of: AccessPath, attr: SmolStr },
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

/// Error when expressions are partial during entity
/// manifest computation
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("entity slicing requires fully concrete policies. Got a policy with an unknown expression")]
pub struct PartialExpressionError {}

impl Diagnostic for PartialExpressionError {}

/// Error when the request is partial during entity
/// manifest computation
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("entity slicing requires a fully concrete request. Got a partial request")]
pub struct PartialRequestError {}
impl Diagnostic for PartialRequestError {}

/// An error generated by entity slicing.
#[derive(Debug, Error)]
pub enum EntityManifestError {
    /// A validation error was encountered
    // TODO (#1158) impl Error for ValidationResult (it already is implemented for api::ValidationResult)
    #[error("a validation error occurred")]
    Validation(ValidationResult),
    /// A entities error was encountered
    #[error(transparent)]
    Entities(#[from] EntitiesError),

    /// The request was partial
    #[error(transparent)]
    PartialRequest(#[from] PartialRequestError),
    /// A policy was partial
    #[error(transparent)]
    PartialExpression(#[from] PartialExpressionError),
    /// Unsupported feature
    #[error(transparent)]
    UnsupportedCedarFeature(#[from] UnsupportedCedarFeatureError),
}

/// Error when entity manifest analysis cannot handle a Cedar feature
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Diagnostic)]
#[error("entity manifest analysis currently doesn't support Cedar feature: {feature}")]
pub struct UnsupportedCedarFeatureError {
    pub(crate) feature: SmolStr,
}

/// Error when the manifest has an entity the schema lacks.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("entity manifest doesn't match schema. Schema is missing entity {entity}. Either you wrote an entity manifest by hand (not recommended) or you are using an out-of-date entity manifest with respect to the schema")]
pub struct MismatchedMissingEntityError {
    pub(crate) entity: EntityUID,
}

/// Error when the schema isn't valid in strict mode.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("entity manifests are only compatible with schemas that validate in strict mode. Tried to use an invalid schema with an entity manifest")]
pub struct MismatchedNotStrictSchemaError {}

/// An error generated by entity manifest parsing. These happen
/// when the entity manifest doesn't conform to the schema.
/// Either the user wrote an entity manifest by hand (not reccomended)
/// or they used an out-of-date entity manifest (after updating the schema).
/// Warning: This error is not guaranteed to happen, even when an entity
/// manifest is out-of-date with respect to a schema! Users must ensure
/// that entity manifests are in-sync with the schema and policies.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
pub enum MismatchedEntityManifestError {
    /// Mismatch between entity in manifest and schema
    #[error(transparent)]
    MismatchedMissingEntity(#[from] MismatchedMissingEntityError),
    /// Found a schema that isn't valid in strict mode
    #[error(transparent)]
    MismatchedNotStrictSchema(#[from] MismatchedNotStrictSchemaError),
}

/// An error generated when parsing entity manifests from json
#[derive(Debug, Error)]
pub enum EntityManifestFromJsonError {
    /// A Serde error happened
    #[error(transparent)]
    SerdeJsonParseError(#[from] serde_json::Error),
    /// A mismatched entity manifest error
    #[error(transparent)]
    MismatchedEntityManifest(#[from] MismatchedEntityManifestError),
}

impl AccessPathDag {
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
        self.manifest_hash_cons.insert(variant, path.clone());

        // Add the new AccessPath to the manifest_store
        self.manifest_store.push(path.clone());

        // Return the new AccessPath
        path
    }
}

impl EntityManifest {
    pub fn new() -> Self {
        Self {
            manifest_hash_cons: HashMap::new(),
            manifest_store: Vec::new(),
            per_action: HashMap::new(),
        }
    }

    /// Get the contents of the entity manifest
    /// indexed by the type of the request.
    pub fn per_action(&self) -> &HashMap<RequestType, AccessPaths> {
        &self.per_action
    }

    /// Convert a json string to an [`EntityManifest`].
    /// Requires the schema in order to add type annotations.
    pub fn from_json_str(
        json: &str,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntityManifestFromJsonError> {
        match serde_json::from_str::<EntityManifest>(json) {
            Ok(manifest) => manifest.to_typed(schema).map_err(|e| e.into()),
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
            Ok(manifest) => manifest.to_typed(schema).map_err(|e| e.into()),
            Err(e) => Err(e.into()),
        }
    }
}

impl AccessPaths {
    /// Add all the access paths from another [`AccessPaths`]
    /// to this one, mutably.
    pub fn add_paths(&mut self, other: Self) {
        self.paths.extend(other.paths)
    }

    /// Add a path to the set.
    pub fn insert(&mut self, path: AccessPath) {
        self.paths.insert(path)
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
            let new_primary_slice = match policy_check {
                PolicyCheck::Success(typechecked_expr) => {
                    // compute the trie from the typechecked expr
                    // using static analysis
                    entity_manifest_from_expr(&typechecked_expr).map(|val| val.global_trie)
                }
                PolicyCheck::Irrelevant(_, _) => {
                    // this policy is irrelevant, so we need no data
                    Ok(AccessDag::new())
                }

                // PANIC SAFETY: policy check should not fail after full strict validation above.
                #[allow(clippy::panic)]
                PolicyCheck::Fail(_errors) => {
                    panic!("Policy check failed after validation succeeded")
                }
            }?;

            let request_type = request_env
                .to_request_type()
                .ok_or(PartialRequestError {})?;
            match manifest.entry(request_type) {
                Entry::Occupied(mut occupied) => {
                    occupied.get_mut().union_mut(new_primary_slice);
                }
                Entry::Vacant(vacant) => {
                    vacant.insert(new_primary_slice);
                }
            }
        }
    }

    // PANIC SAFETY: entity manifest cannot be out of date, since it was computed from the schema given
    #[allow(clippy::unwrap_used)]
    Ok(EntityManifest {
        per_action: manifest,
    }
    .to_typed(validator.schema())
    .unwrap())
}

/// A static analysis on type-annotated cedar expressions.
/// Computes the [`RootAccessTrie`] representing all the data required
/// to evaluate the expression.
fn entity_manifest_from_expr(
    expr: &Expr<Option<Type>>,
) -> Result<EntityManifestAnalysisResult, EntityManifestError> {
    match expr.expr_kind() {
        ExprKind::Slot(slot_id) => {
            if slot_id.is_principal() {
                Ok(EntityManifestAnalysisResult::from_root(EntityRoot::Var(
                    Var::Principal,
                )))
            } else {
                assert!(slot_id.is_resource());
                Ok(EntityManifestAnalysisResult::from_root(EntityRoot::Var(
                    Var::Resource,
                )))
            }
        }
        ExprKind::Var(var) => Ok(EntityManifestAnalysisResult::from_root(EntityRoot::Var(
            *var,
        ))),
        ExprKind::Lit(Literal::EntityUID(literal)) => Ok(EntityManifestAnalysisResult::from_root(
            EntityRoot::Literal((**literal).clone()),
        )),
        ExprKind::Unknown(_) => Err(PartialExpressionError {})?,

        // Non-entity literals need no fields to be loaded.
        ExprKind::Lit(_) => Ok(EntityManifestAnalysisResult::default()),
        ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => Ok(entity_manifest_from_expr(test_expr)?
            .empty_paths()
            .union(entity_manifest_from_expr(then_expr)?)
            .union(entity_manifest_from_expr(else_expr)?)),
        ExprKind::And { left, right }
        | ExprKind::Or { left, right }
        | ExprKind::BinaryApp {
            op: BinaryOp::Less | BinaryOp::LessEq | BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul,
            arg1: left,
            arg2: right,
        } => Ok(entity_manifest_from_expr(left)?
            .empty_paths()
            .union(entity_manifest_from_expr(right)?.empty_paths())),
        ExprKind::UnaryApp { op, arg } => {
            match op {
                // these unary ops are on primitive types, so they are simple
                UnaryOp::Not | UnaryOp::Neg => Ok(entity_manifest_from_expr(arg)?.empty_paths()),
                UnaryOp::IsEmpty => {
                    // PANIC SAFETY: Typechecking succeeded, so type annotations are present.
                    #[allow(clippy::expect_used)]
                    let ty = arg
                        .data()
                        .as_ref()
                        .expect("Expected annotated types after typechecking");
                    Ok(entity_manifest_from_expr(arg)?
                        .full_type_required(ty)
                        .empty_paths())
                }
            }
        }
        ExprKind::BinaryApp {
            op:
                op @ (BinaryOp::Eq
                | BinaryOp::In
                | BinaryOp::Contains
                | BinaryOp::ContainsAll
                | BinaryOp::ContainsAny),
            arg1,
            arg2,
        } => {
            // First, find the data paths for each argument
            let mut arg1_res = entity_manifest_from_expr(arg1)?;
            let arg2_res = entity_manifest_from_expr(arg2)?;

            // PANIC SAFETY: Typechecking succeeded, so type annotations are present.
            #[allow(clippy::expect_used)]
            let ty1 = arg1
                .data()
                .as_ref()
                .expect("Expected annotated types after typechecking");
            // PANIC SAFETY: Typechecking succeeded, so type annotations are present.
            #[allow(clippy::expect_used)]
            let ty2 = arg2
                .data()
                .as_ref()
                .expect("Expected annotated types after typechecking");

            // For the `in` operator, we need the ancestors of entities.
            if matches!(op, BinaryOp::In) {
                arg1_res = arg1_res.with_ancestors_required(&arg2_res.resulting_paths);
            }

            // Load all fields using `full_type_required`, since
            // these operations do equality checks.
            Ok(arg1_res
                .full_type_required(ty1)
                .union(arg2_res.full_type_required(ty2))
                .empty_paths())
        }
        ExprKind::BinaryApp {
            op: BinaryOp::GetTag | BinaryOp::HasTag,
            arg1: _,
            arg2: _,
        } => Err(UnsupportedCedarFeatureError {
            feature: "entity tags".into(),
        }
        .into()),
        ExprKind::ExtensionFunctionApp { fn_name: _, args } => {
            // WARNING: this code assumes that extension functions
            // all take primitives as inputs and produce
            // primitives as outputs.
            // If not, we would need to use logic similar to the Eq binary operator.

            let mut res = EntityManifestAnalysisResult::default();

            for arg in args.iter() {
                res = res.union(entity_manifest_from_expr(arg)?);
            }
            Ok(res)
        }
        ExprKind::Like { expr, pattern: _ }
        | ExprKind::Is {
            expr,
            entity_type: _,
        } => {
            // drop paths since boolean returned
            Ok(entity_manifest_from_expr(expr)?.empty_paths())
        }
        ExprKind::Set(contents) => {
            let mut res = EntityManifestAnalysisResult::default();

            // take union of all of the contents
            for expr in &**contents {
                let content = entity_manifest_from_expr(expr)?;

                res = res.union(content);
            }

            // now, wrap result in a set
            res.resulting_paths = WrappedAccessPaths::SetLiteral(Box::new(res.resulting_paths));

            Ok(res)
        }
        ExprKind::Record(content) => {
            let mut record_contents = HashMap::new();
            let mut global_trie = AccessDag::default();

            for (key, child_expr) in content.iter() {
                let res = entity_manifest_from_expr(child_expr)?;
                record_contents.insert(key.clone(), Box::new(res.resulting_paths));

                global_trie = global_trie.union(res.global_trie);
            }

            Ok(EntityManifestAnalysisResult {
                resulting_paths: WrappedAccessPaths::RecordLiteral(record_contents),
                global_trie,
            })
        }
        ExprKind::GetAttr { expr, attr } => {
            Ok(entity_manifest_from_expr(expr)?.get_or_has_attr(attr))
        }
        ExprKind::HasAttr { expr, attr } => Ok(entity_manifest_from_expr(expr)?
            .get_or_has_attr(attr)
            .empty_paths()),
        #[cfg(feature = "tolerant-ast")]
        ExprKind::Error { .. } => Err(EntityManifestError::UnsupportedCedarFeature(
            UnsupportedCedarFeatureError {
                feature: "No support for AST error nodes".into(),
            },
        )),
    }
}

#[cfg(test)]
mod entity_slice_tests {
    use crate::{ast::PolicyID, extensions::Extensions, parser::parse_policy};

    use super::*;

    // Schema for testing in this module
    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            "
entity User = {
  name: String,
};

entity Document;

action Read appliesTo {
  principal: [User],
  resource: [Document]
};
    ",
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    fn document_fields_schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            "
entity User = {
name: String,
};

entity Document = {
owner: User,
viewer: User,
};

action Read appliesTo {
principal: [User],
resource: [Document]
};
",
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    #[test]
    fn test_simple_entity_manifest() {
        let mut pset = PolicySet::new();
        let policy = parse_policy(
            None,
            r#"permit(principal, action, resource)
when {
    principal.name == "John"
};"#,
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let validator = Validator::new(schema());

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected_rust = EntityManifest {
            per_action: HashMap::from([(
                RequestType {
                    principal: "User".parse().unwrap(),
                    resource: "Document".parse().unwrap(),
                    action: r#"Action::"Read""#.parse().unwrap(),
                },
                AccessDag {
                    trie: HashMap::from([(
                        EntityRoot::Var(Var::Principal),
                        AccessTrie {
                            children: HashMap::from([(
                                SmolStr::new_static("name"),
                                Box::new(AccessTrie {
                                    children: HashMap::new(),
                                    ancestors_trie: AccessDag::new(),
                                    is_ancestor: false,
                                    node_type: Some(Type::primitive_string()),
                                }),
                            )]),
                            ancestors_trie: AccessDag::new(),
                            is_ancestor: false,
                            node_type: Some(Type::named_entity_reference("User".parse().unwrap())),
                        },
                    )]),
                },
            )]),
        };
        let expected = serde_json::json! ({
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "name",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
        });
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
        assert_eq!(entity_manifest, expected_rust);
    }

    #[test]
    fn test_empty_entity_manifest() {
        let mut pset = PolicySet::new();
        let policy =
            parse_policy(None, "permit(principal, action, resource);").expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let validator = Validator::new(schema());

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json!(
        {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                ]
              }
            ]
          ]
        });
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_ancestors_required() {
        let mut pset = PolicySet::new();
        let policy = parse_policy(
            None,
            "permit(principal, action, resource)
when {
    principal in resource || principal.manager in resource
};",
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = ValidatorSchema::from_cedarschema_str(
            "
entity User in [Document] = {
  name: String,
  manager: User
};
entity Document;
action Read appliesTo {
  principal: [User],
  resource: [Document]
};
  ",
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let validator = Validator::new(schema);

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json!(
        {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "manager",
                          {
                            "children": [],
                            "ancestorsTrie": {
                              "trie": [
                                [
                                  {
                                    "var": "resource",
                                  },
                                  {
                                    "children": [],
                                    "isAncestor": true,
                                    "ancestorsTrie": { "trie": [] }
                                  }
                                ]
                              ]
                            },
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": {
                              "trie": [
                                [
                                  {
                                    "var": "resource",
                                  },
                                  {
                                    "children": [],
                                    "isAncestor": true,
                                    "ancestorsTrie": { "trie": [] }
                                  }
                                ]
                              ]
                            },
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
        });
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_multiple_types() {
        let mut pset = PolicySet::new();
        let policy = parse_policy(
            None,
            r#"permit(principal, action, resource)
when {
    principal.name == "John"
};"#,
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = ValidatorSchema::from_cedarschema_str(
            "
entity User = {
  name: String,
};

entity OtherUserType = {
  name: String,
  irrelevant: String,
};

entity Document;

action Read appliesTo {
  principal: [User, OtherUserType],
  resource: [Document]
};
        ",
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let validator = Validator::new(schema);

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json!(
        {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "name",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ],
            [
              {
                "principal": "OtherUserType",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "name",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
            });
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_multiple_branches() {
        let mut pset = PolicySet::new();
        let policy1 = parse_policy(
            None,
            r#"
permit(
  principal,
  action == Action::"Read",
  resource
)
when
{
  resource.readers.contains(principal)
};"#,
        )
        .unwrap();
        let policy2 = parse_policy(
            Some(PolicyID::from_string("Policy2")),
            r#"permit(
  principal,
  action == Action::"Read",
  resource
)
when
{
  resource.metadata.owner == principal
};"#,
        )
        .unwrap();
        pset.add(policy1.into()).expect("should succeed");
        pset.add(policy2.into()).expect("should succeed");

        let schema = ValidatorSchema::from_cedarschema_str(
            "
entity User;

entity Metadata = {
   owner: User,
   time: String,
};

entity Document = {
  metadata: Metadata,
  readers: Set<User>,
};

action Read appliesTo {
  principal: [User],
  resource: [Document]
};
        ",
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let validator = Validator::new(schema);

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json!(
        {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "resource"
                    },
                    {
                      "children": [
                        [
                          "metadata",
                          {
                            "children": [
                              [
                                "owner",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ]
                            ],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ],
                        [
                          "readers",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ],
                ]
              }
            ]
          ]
        });
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_struct_equality() {
        let mut pset = PolicySet::new();
        // we need to load all of the metadata, not just nickname
        // no need to load actual name
        let policy = parse_policy(
            None,
            r#"permit(principal, action, resource)
when {
    principal.metadata.nickname == "timmy" && principal.metadata == {
        "friends": [ "oliver" ],
        "nickname": "timmy"
    }
};"#,
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = ValidatorSchema::from_cedarschema_str(
            "
entity User = {
  name: String,
  metadata: {
    friends: Set<String>,
    nickname: String,
  },
};

entity Document;

action BeSad appliesTo {
  principal: [User],
  resource: [Document]
};
        ",
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let validator = Validator::new(schema);

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json!(
        {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "BeSad"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "metadata",
                          {
                            "children": [
                              [
                                "nickname",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ],
                              [
                                "friends",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ]
                            ],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
        });
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_struct_equality_left_right_different() {
        let mut pset = PolicySet::new();
        // we need to load all of the metadata, not just nickname
        // no need to load actual name
        let policy = parse_policy(
            None,
            r#"permit(principal, action, resource)
when {
    principal.metadata == resource.metadata
};"#,
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = ValidatorSchema::from_cedarschema_str(
            "
entity User = {
  name: String,
  metadata: {
    friends: Set<String>,
    nickname: String,
  },
};

entity Document;

action Hello appliesTo {
  principal: [User],
  resource: [User]
};
        ",
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let validator = Validator::new(schema);

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json!(
        {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Hello"
                },
                "resource": "User"
              },
              {
                "trie": [
                  [
                    {
                      "var": "resource"
                    },
                    {
                      "children": [
                        [
                          "metadata",
                          {
                            "children": [
                              [
                                "friends",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ],
                              [
                                "nickname",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ]
                            ],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                    }
                  ],
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "metadata",
                          {
                            "children": [
                              [
                                "nickname",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ],
                              [
                                "friends",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ]
                            ],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
        });
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_with_if() {
        let mut pset = PolicySet::new();

        let validator = Validator::new(document_fields_schema());

        let policy = parse_policy(
            None,
            r#"permit(principal, action, resource)
when {
    if principal.name == "John"
    then resource.owner.name == User::"oliver".name
    else resource.viewer == User::"oliver"
};"#,
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json! ( {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "name",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                    }
                  ],
                  [
                    {
                      "literal": {
                        "ty": "User",
                        "eid": "oliver"
                      }
                    },
                    {
                      "children": [
                        [
                          "name",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                    }
                  ],
                  [
                    {
                      "var": "resource"
                    },
                    {
                      "children": [
                        [
                          "viewer",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ],
                        [
                          "owner",
                          {
                            "children": [
                              [
                                "name",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                                }
                              ]
                            ],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
        }
        );
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_if_literal_record() {
        let mut pset = PolicySet::new();

        let validator = Validator::new(document_fields_schema());

        let policy = parse_policy(
            None,
            r#"permit(principal, action, resource)
when {
    {
      "myfield":
          {
            "secondfield":
            if principal.name == "yihong"
            then principal
            else resource.owner,
            "ignored but still important due to errors":
            resource.viewer
          }
    }["myfield"]["secondfield"].name == "pavel"
};"#,
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json! ( {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "name",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                    }
                  ],
                  [
                    {
                      "var": "resource"
                    },
                    {
                      "children": [
                        [
                          "viewer",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ],
                        [
                          "owner",
                          {
                            "children": [
                              [
                                "name",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ]
                            ],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
        }
        );
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }
}
