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

use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use cedar_policy_core::ast::{
    BinaryOp, EntityUID, Expr, ExprKind, Literal, PolicySet, RequestType, UnaryOp, Var,
};
use cedar_policy_core::entities::err::EntitiesError;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;
use thiserror::Error;

use crate::entity_manifest_analysis::{EntityManifestAnalysisResult, WrappedAccessPaths};
use crate::{
    typecheck::{PolicyCheck, Typechecker},
    types::Type,
    ValidationMode, ValidatorSchema,
};
use crate::{ValidationResult, Validator};

/// Data structure storing what data is needed
/// based on the the [`RequestType`].
/// For each request type, the [`EntityManifest`] stores
/// a [`RootAccessTrie`] of data to retrieve.
///
/// `T` represents an optional type annotation on each
/// node in the [`AccessTrie`].
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[doc = include_str!("../../cedar-policy/experimental_warning.md")]
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityManifest<T = ()>
where
    T: Clone,
{
    /// A map from request types to [`RootAccessTrie`]s.
    #[serde_as(as = "Vec<(_, _)>")]
    #[serde(bound(deserialize = "T: Default"))]
    pub(crate) per_action: HashMap<RequestType, RootAccessTrie<T>>,
}

/// A map of data fields to [`AccessTrie`]s.
/// The keys to this map form the edges in the access trie,
/// pointing to sub-tries.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[doc = include_str!("../../cedar-policy/experimental_warning.md")]
pub type Fields<T> = HashMap<SmolStr, Box<AccessTrie<T>>>;

/// The root of a data path or [`RootAccessTrie`].
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[doc = include_str!("../../cedar-policy/experimental_warning.md")]
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

/// A [`RootAccessTrie`] is a trie describing a set of
/// data paths to retrieve. Each edge in the trie
/// is either a record or entity dereference.
///
/// If an entity or record field does not exist in the backing store,
/// it is safe to stop loading data at that point.
///
/// `T` represents an optional type annotation on each
/// node in the [`AccessTrie`].
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[doc = include_str!("../../cedar-policy/experimental_warning.md")]
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootAccessTrie<T = ()>
where
    T: Clone,
{
    /// The data that needs to be loaded, organized by root.
    #[serde_as(as = "Vec<(_, _)>")]
    #[serde(bound(deserialize = "T: Default"))]
    pub(crate) trie: HashMap<EntityRoot, AccessTrie<T>>,
}

/// A Trie representing a set of data paths to load,
/// starting implicitly from a Cedar value.
///
/// `T` represents an optional type annotation on each
/// node in the [`AccessTrie`].
///
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[doc = include_str!("../../cedar-policy/experimental_warning.md")]
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTrie<T = ()> {
    /// Child data of this entity slice.
    /// The keys are edges in the trie pointing to sub-trie values.
    #[serde_as(as = "Vec<(_, _)>")]
    pub(crate) children: Fields<T>,
    /// `ancestors_trie` is another [`RootAccessTrie`] representing
    /// all of the ancestors of this entity that are required.
    /// See the [`RootAccessTrie::is_ancestor`] annotation.
    pub(crate) ancestors_trie: RootAccessTrie,
    /// When ancestors are required, each node marked `is_ancestor`
    /// represents an ancestor or set of ancestors that are required.
    pub(crate) is_ancestor: bool,
    /// Optional data annotation, usually used for type information.
    #[serde(skip_serializing, skip_deserializing)]
    #[serde(bound(deserialize = "T: Default"))]
    pub(crate) data: T,
}

/// An access path represents path of fields, starting with an [`EntityRoot`].
/// Fields may be record fields or entity fields.
/// If an access path ends with an entity type, it may also require the ancestors of the entity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct AccessPath {
    /// The root variable that begins the data path
    pub root: EntityRoot,
    /// The path of fields of entities or structs
    pub path: Vec<SmolStr>,
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
}

impl<T: Clone> EntityManifest<T> {
    /// Get the contents of the entity manifest
    /// indexed by the type of the request.
    pub fn per_action(&self) -> &HashMap<RequestType, RootAccessTrie<T>> {
        &self.per_action
    }
}

/// Union two tries by combining the fields.
fn union_fields<T: Clone>(first: &Fields<T>, second: &Fields<T>) -> Fields<T> {
    let mut res = first.clone();
    for (key, value) in second {
        res.entry(key.clone())
            .and_modify(|existing| existing.union_mut(value))
            .or_insert(value.clone());
    }
    res
}

impl AccessPath {
    /// Convert a [`AccessPath`] into corresponding [`RootAccessTrie`].
    pub fn to_root_access_trie(&self) -> RootAccessTrie {
        self.to_root_access_trie_with_leaf(AccessTrie::default())
    }

    /// Convert an [`AccessPath`] to a [`RootAccessTrie`], and also
    /// add a full trie as the leaf at the end.
    pub(crate) fn to_root_access_trie_with_leaf(&self, leaf_trie: AccessTrie) -> RootAccessTrie {
        let mut current = leaf_trie;

        // reverse the path, visiting the last access first
        for field in self.path.iter().rev() {
            let mut fields = HashMap::new();
            fields.insert(field.clone(), Box::new(current));

            // the first time we build an access trie is the leaf
            // of the path, so set the `ancestors_required` flag
            current = AccessTrie {
                ancestors_trie: Default::default(),
                is_ancestor: false,
                children: fields,
                data: (),
            };
        }

        let mut primary_map = HashMap::new();

        // special case: if the path is completely empty,
        // no need to insert anything
        if current != AccessTrie::new() {
            primary_map.insert(self.root.clone(), current);
        }
        RootAccessTrie { trie: primary_map }
    }
}

impl<T: Clone> RootAccessTrie<T> {
    /// Get the trie as a hash map from [`EntityRoot`]
    /// to sub-[`AccessTrie`]s.
    pub fn trie(&self) -> &HashMap<EntityRoot, AccessTrie<T>> {
        &self.trie
    }
}

impl RootAccessTrie {
    /// Create an empty [`RootAccessTrie`] that requests nothing.
    pub fn new() -> Self {
        Self {
            trie: Default::default(),
        }
    }
}

impl<T: Clone> RootAccessTrie<T> {
    /// Union two [`RootAccessTrie`]s together.
    /// The new trie requests the data from both of the original.
    pub fn union(mut self, other: &Self) -> Self {
        self.union_mut(other);
        self
    }

    /// Like [`RootAccessTrie::union`], but modifies the current trie.
    pub fn union_mut(&mut self, other: &Self) {
        for (key, value) in &other.trie {
            self.trie
                .entry(key.clone())
                .and_modify(|existing| existing.union_mut(value))
                .or_insert(value.clone());
        }
    }
}

impl Default for RootAccessTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> AccessTrie<T> {
    /// Union two [`AccessTrie`]s together.
    /// The new trie requests the data from both of the original.
    pub fn union(mut self, other: &Self) -> Self {
        self.union_mut(other);
        self
    }

    /// Like [`AccessTrie::union`], but modifies the current trie.
    pub fn union_mut(&mut self, other: &Self) {
        self.children = union_fields(&self.children, &other.children);
        self.ancestors_trie.union_mut(&other.ancestors_trie);
        self.is_ancestor = self.is_ancestor || other.is_ancestor;
    }

    /// Get the children of this [`AccessTrie`].
    pub fn children(&self) -> &Fields<T> {
        &self.children
    }

    /// Get a boolean which is true if this trie
    /// requires all ancestors of the entity to be loaded.
    pub fn ancestors_required(&self) -> &RootAccessTrie {
        &self.ancestors_trie
    }

    /// Get the data associated with this [`AccessTrie`].
    /// This is usually `()` unless it is annotated by a type.
    pub fn data(&self) -> &T {
        &self.data
    }
}

impl AccessTrie {
    /// A new trie that requests no data.
    pub fn new() -> Self {
        Self {
            children: Default::default(),
            ancestors_trie: Default::default(),
            is_ancestor: false,
            data: (),
        }
    }
}

impl Default for AccessTrie {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes an [`EntityManifest`] from the schema and policies.
/// The policies must validate against the schema in strict mode,
/// otherwise an error is returned.
pub fn compute_entity_manifest(
    schema: &ValidatorSchema,
    policies: &PolicySet,
) -> Result<EntityManifest, EntityManifestError> {
    // first, run strict validation to ensure there are no errors
    let validator = Validator::new(schema.clone());
    let validation_res = validator.validate(policies, ValidationMode::Strict);
    if !validation_res.validation_passed() {
        return Err(EntityManifestError::Validation(validation_res));
    }

    let mut manifest: HashMap<RequestType, RootAccessTrie> = HashMap::new();

    // now, for each policy we add the data it requires to the manifest
    for policy in policies.policies() {
        // typecheck the policy and get all the request environments
        let typechecker = Typechecker::new(schema, ValidationMode::Strict, policy.id().clone());
        let request_envs = typechecker.typecheck_by_request_env(policy.template());
        for (request_env, policy_check) in request_envs {
            let new_primary_slice = match policy_check {
                PolicyCheck::Success(typechecked_expr) => {
                    // compute the trie from the typechecked expr
                    // using static analysis
                    entity_manifest_from_expr(&typechecked_expr).map(|val| val.global_trie)
                }
                PolicyCheck::Irrelevant(_) => {
                    // this policy is irrelevant, so we need no data
                    Ok(RootAccessTrie::new())
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
            manifest
                .entry(request_type)
                .and_modify(|existing| existing.union_mut(&new_primary_slice))
                .or_insert(new_primary_slice);
        }
    }

    Ok(EntityManifest {
        per_action: manifest,
    })
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
            .union(&entity_manifest_from_expr(then_expr)?)
            .union(&entity_manifest_from_expr(else_expr)?)),
        ExprKind::And { left, right }
        | ExprKind::Or { left, right }
        | ExprKind::BinaryApp {
            op: BinaryOp::Less | BinaryOp::LessEq | BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul,
            arg1: left,
            arg2: right,
        } => Ok(entity_manifest_from_expr(left)?
            .empty_paths()
            .union(&entity_manifest_from_expr(right)?.empty_paths())),
        ExprKind::UnaryApp { op, arg } => {
            match op {
                // both unary ops are on booleans, so they are simple
                UnaryOp::Not | UnaryOp::Neg => Ok(entity_manifest_from_expr(arg)?.empty_paths()),
            }
        }
        ExprKind::BinaryApp {
            op:
                BinaryOp::Eq
                | BinaryOp::In
                | BinaryOp::Contains
                | BinaryOp::ContainsAll
                | BinaryOp::ContainsAny,
            arg1,
            arg2,
        } => {
            // TODO Is there more elegant way to bind op using rust pattern matching?
            // PANIC SAFETY: Matched a binary app above, so expr must still be a binary app.
            #[allow(clippy::panic)]
            let ExprKind::BinaryApp { op, .. } = expr.expr_kind() else {
                panic!("Matched above");
            };

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
            if let BinaryOp::In = op {
                arg1_res = arg1_res
                    .with_ancestors_required(&arg2_res.resulting_paths.to_ancestor_access_trie());
            }

            // Load all fields using `full_type_required`, since
            // these operations do equality checks.
            Ok(arg1_res
                .full_type_required(ty1)
                .union(&arg2_res.full_type_required(ty2))
                .empty_paths())
        }
        ExprKind::ExtensionFunctionApp { fn_name: _, args } => {
            // WARNING: this code assumes that extension functions
            // all take primitives as inputs and produce
            // primitives as outputs.
            // If not, we would need to use logic similar to the Eq binary operator.

            let mut res = EntityManifestAnalysisResult::default();

            for arg in args.iter() {
                res = res.union(&entity_manifest_from_expr(arg)?);
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

                res = res.union(&content);
            }

            // now, wrap result in a set
            res.resulting_paths = WrappedAccessPaths::SetLiteral(Box::new(res.resulting_paths));

            Ok(res)
        }
        ExprKind::Record(content) => {
            let mut record_contents = HashMap::new();
            let mut global_trie = RootAccessTrie::default();

            for (key, child_expr) in content.iter() {
                let res = entity_manifest_from_expr(child_expr)?;
                record_contents.insert(key.clone(), Box::new(res.resulting_paths));

                global_trie = global_trie.union(&res.global_trie);
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
    }
}

#[cfg(test)]
mod entity_slice_tests {
    use cedar_policy_core::{ast::PolicyID, extensions::Extensions, parser::parse_policy};

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
            "permit(principal, action, resource)
when {
    principal.name == \"John\"
};",
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = schema();

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");
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
        let expected_manifest = serde_json::from_value(expected).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_empty_entity_manifest() {
        let mut pset = PolicySet::new();
        let policy =
            parse_policy(None, "permit(principal, action, resource);").expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = schema();

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");
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
        let expected_manifest = serde_json::from_value(expected).unwrap();
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

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");
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
        let expected_manifest = serde_json::from_value(expected).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_multiple_types() {
        let mut pset = PolicySet::new();
        let policy = parse_policy(
            None,
            "permit(principal, action, resource)
when {
    principal.name == \"John\"
};",
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

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");
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
        let expected_manifest = serde_json::from_value(expected).unwrap();
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

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");
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
        let expected_manifest = serde_json::from_value(expected).unwrap();
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

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");
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
        let expected_manifest = serde_json::from_value(expected).unwrap();
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

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");
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
        let expected_manifest = serde_json::from_value(expected).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_with_if() {
        let mut pset = PolicySet::new();

        let schema = document_fields_schema();

        let policy = parse_policy(
            None,
            "permit(principal, action, resource)
when {
    if principal.name == \"John\"
    then resource.owner.name == User::\"oliver\".name
    else resource.viewer == User::\"oliver\"
};",
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");
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
        let expected_manifest = serde_json::from_value(expected).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_if_literal_record() {
        let mut pset = PolicySet::new();

        let schema = document_fields_schema();

        let policy = parse_policy(
            None,
            "permit(principal, action, resource)
when {
    {
      \"myfield\":
          {
            \"secondfield\":
            if principal.name == \"yihong\"
            then principal
            else resource.owner,
            \"ignored but still important due to errors\":
            resource.viewer
          }
    }[\"myfield\"][\"secondfield\"].name == \"pavel\"
};",
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");
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
        let expected_manifest = serde_json::from_value(expected).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }
}
