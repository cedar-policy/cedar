//! Entity Manifest definition and static analysis.

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

use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use cedar_policy_core::ast::{
    BinaryOp, EntityUID, Expr, ExprKind, Literal, PolicyID, PolicySet, RequestType, UnaryOp, Var,
};
use cedar_policy_core::entities::err::EntitiesError;
use cedar_policy_core::impl_diagnostic_from_source_loc_field;
use cedar_policy_core::parser::Loc;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;
use thiserror::Error;

use crate::ValidationError;
use crate::{
    typecheck::{PolicyCheck, Typechecker},
    types::{EntityRecordKind, Type},
    ValidationMode, ValidatorSchema,
};

/// Data structure storing what data is needed
/// based on the the [`RequestType`].
/// For each request type, the [`EntityManifest`] stores
/// a [`RootAccessTrie`] of data to retrieve.
#[doc = include_str!("../../cedar-policy/experimental_warning.md")]
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityManifest<T = ()>
where
    T: Clone,
{
    /// A map from request types to [`RootAccessTrie`]s.
    #[serde_as(as = "Vec<(_, _)>")]
    #[serde(bound(deserialize = "T: Default"))]
    pub per_action: HashMap<RequestType, RootAccessTrie<T>>,
}

/// A map of data fields to [`AccessTrie`]s.
/// The keys to this map form the edges in the access trie,
/// pointing to sub-tries.
#[doc = include_str!("../../cedar-policy/experimental_warning.md")]
pub type Fields<T> = HashMap<SmolStr, Box<AccessTrie<T>>>;

/// The root of an entity slice.
#[doc = include_str!("../../cedar-policy/experimental_warning.md")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
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

/// A [`RootAccessTrie`] is a trie describing
/// data paths to retrieve. Each edge in the trie
/// is either a record or entity dereference.
///
/// If an entity or record field does not exist in the backing store,
/// it is safe to stop loading data at that point.
#[doc = include_str!("../../cedar-policy/experimental_warning.md")]
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootAccessTrie<T = ()>
where
    T: Clone,
{
    #[serde_as(as = "Vec<(_, _)>")]
    #[serde(bound(deserialize = "T: Default"))]
    /// The data that needs to be loaded, organized by root.
    pub trie: HashMap<EntityRoot, AccessTrie<T>>,
}

/// An entity slice- tells users a tree of data to load
#[doc = include_str!("../../cedar-policy/experimental_warning.md")]
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTrie<T = ()> {
    /// Child data of this entity slice.
    /// The keys are edges in the trie pointing to sub-trie values.
    #[serde_as(as = "Vec<(_, _)>")]
    pub children: Fields<T>,
    /// For entity types, this boolean may be `true`
    /// to signal that all the parents in the entity hierarchy
    /// are required (transitively).
    pub parents_required: bool,
    /// Optional data annotation, usually used for type information.
    #[serde(skip_serializing, skip_deserializing)]
    #[serde(bound(deserialize = "T: Default"))]
    pub data: T,
}

/// A data path that may end with requesting the parents of
/// an entity.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AccessPath {
    /// The root variable that begins the data path
    pub root: EntityRoot,
    /// The path of fields of entities or structs
    pub path: Vec<SmolStr>,
    /// Request all the parents in the entity hierarchy of this entity.
    pub parents_required: bool,
}

/// Entity manifest computation does not handle the full
/// cedar language. In particular, the policies must follow the
/// following grammar:
/// ```text
/// <expr> = <datapath-expr>
///          <datapath-expr> in <expr>
///          <expr> + <expr>
///          if <expr> { <expr> } { <expr> }
///          ... all other cedar operators not mentioned by datapath-expr

/// <datapath-expr> = <datapath-expr>.<field>
///                   <datapath-expr> has <field>
///                   <variable>
///                   <entity literal>
/// ```
/// The `get_expr_path` function handles `datapath-expr` expressions.
/// This error message tells the user not to use certain operators
/// before accessing record or entity attributes, breaking this grammar.
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("For policy `{policy_id}`, failed to analyze expression while computing entity manifest.`")]
pub struct FailedAnalysisError {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// The kind of the expression that was unexpected
    pub expr_kind: ExprKind<Option<Type>>,
}

impl Diagnostic for FailedAnalysisError {
    impl_diagnostic_from_source_loc_field!();

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(format!(
            "failed to compute entity manifest: {} operators are not allowed before accessing record or entity attributes",
            self.expr_kind.operator_description()
        )))
    }
}

/// An error generated by entity slicing.
/// See [`FailedAnalysisError`] for details on the fragment
/// of Cedar handled by entity slicing.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum EntityManifestError {
    /// A validation error was encountered
    #[error(transparent)]
    #[diagnostic(transparent)]
    ValidationError(#[from] ValidationError),
    /// A entities error was encountered
    #[error(transparent)]
    #[diagnostic(transparent)]
    EntitiesError(#[from] EntitiesError),

    /// The request was partial
    #[error("Entity slicing requires a fully concrete request. Got a partial request.")]
    PartialRequestError,
    /// A policy was partial
    #[error(
        "Entity slicing requires fully concrete policies. Got a policy with an unknown expression."
    )]
    PartialExpressionError,

    /// A policy was not analyzable because it used unsupported operators
    /// before a [`ExprKind::GetAttr`]
    /// See [`FailedAnalysisError`] for more details.
    #[error(transparent)]
    #[diagnostic(transparent)]
    FailedAnalysis(#[from] FailedAnalysisError),
}

/// Union two tries by combining the fields.
fn union_fields<T: Clone>(first: &Fields<T>, second: &Fields<T>) -> Fields<T> {
    let mut res = first.clone();
    for (key, value) in second {
        if let Some(existing) = res.get(key) {
            res.insert(key.clone(), Box::new((*existing).union(value)));
        } else {
            res.insert(key.clone(), value.clone());
        }
    }
    res
}

impl AccessPath {
    /// Convert a [`AccessPath`] into corresponding [`RootAccessTrie`].
    fn to_primary_slice(&self) -> RootAccessTrie {
        self.to_primary_slice_with_leaf(AccessTrie {
            parents_required: true,
            children: Default::default(),
            data: (),
        })
    }

    /// Convert an [`AccessPath`] to a [`RootAccessTrie`], and also
    /// add a full trie as the leaf at the end.
    fn to_primary_slice_with_leaf(&self, leaf_trie: AccessTrie) -> RootAccessTrie {
        let mut current = leaf_trie;
        // reverse the path, visiting the last access first
        for field in self.path.iter().rev() {
            let mut fields = HashMap::new();
            fields.insert(field.clone(), Box::new(current));
            current = AccessTrie {
                parents_required: false,
                children: fields,
                data: (),
            };
        }

        let mut primary_map = HashMap::new();
        primary_map.insert(self.root.clone(), current);
        RootAccessTrie { trie: primary_map }
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
    fn union(&self, other: &Self) -> Self {
        let mut res = self.clone();
        for (key, value) in &other.trie {
            if let Some(existing) = res.trie.get(key) {
                res.trie.insert(key.clone(), (*existing).union(value));
            } else {
                res.trie.insert(key.clone(), value.clone());
            }
        }
        res
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
    fn union(&self, other: &Self) -> Self {
        Self {
            children: union_fields(&self.children, &other.children),
            parents_required: self.parents_required || other.parents_required,
            data: self.data.clone(),
        }
    }
}

impl AccessTrie {
    /// A new trie that requests no data.
    fn new() -> Self {
        Self {
            children: Default::default(),
            parents_required: false,
            data: (),
        }
    }
}

/// Computes an [`EntityManifest`] from the schema and policies.
/// The policies must validate against the schema in strict mode,
/// otherwise an error is returned.
pub fn compute_entity_manifest(
    schema: &ValidatorSchema,
    policies: &PolicySet,
) -> Result<EntityManifest, EntityManifestError> {
    let mut manifest: HashMap<RequestType, RootAccessTrie> = HashMap::new();

    // now, for each policy we add the data it requires to the manifest
    for policy in policies.policies() {
        // typecheck the policy and get all the request environments
        let typechecker = Typechecker::new(schema, ValidationMode::Strict, policy.id().clone());
        let request_envs = typechecker.typecheck_by_request_env(policy.template());
        for (request_env, policy_check) in request_envs {
            // match on the typechecking answer
            let new_primary_slice = match policy_check {
                PolicyCheck::Success(typechecked_expr) => {
                    // compute the trie from the typechecked expr
                    // using static analysis
                    compute_root_trie(&typechecked_expr, policy.id())
                }
                PolicyCheck::Irrelevant(_) => {
                    // this policy is irrelevant, so we need no data
                    Ok(RootAccessTrie::new())
                }

                // TODO is returning the first error correct?
                // Also, should we run full validation instead of just
                // typechecking? Validation does a little more right?
                PolicyCheck::Fail(errors) => {
                    // PANIC SAFETY: policy check fail should be a non-empty vector.
                    #[allow(clippy::expect_used)]
                    Err(errors
                        .first()
                        .expect("Policy check failed without an error")
                        .clone()
                        .into())
                }
            }?;

            let request_type = request_env
                .to_request_type()
                .ok_or(EntityManifestError::PartialRequestError)?;
            // Add to the manifest based on the request type.
            if let Some(existing) = manifest.get_mut(&request_type) {
                *existing = existing.union(&new_primary_slice);
            } else {
                manifest.insert(request_type, new_primary_slice);
            }
        }
    }

    Ok(EntityManifest {
        per_action: manifest,
    })
}

/// A static analysis on type-annotated cedar expressions.
/// Computes the [`RootAccessTrie`] representing all the data required
/// to evaluate the expression.
fn compute_root_trie(
    expr: &Expr<Option<Type>>,
    policy_id: &PolicyID,
) -> Result<RootAccessTrie, EntityManifestError> {
    let mut primary_slice = RootAccessTrie::new();
    add_to_root_trie(&mut primary_slice, expr, policy_id, false)?;
    Ok(primary_slice)
}

/// Add the expression's requested data to the [`RootAccessTrie`].
/// This handles <expr>s from the grammar (see [`FailedAnalysisError`])
/// while [`get_expr_path`] handles the <datapath-expr>s.
fn add_to_root_trie(
    root_trie: &mut RootAccessTrie,
    expr: &Expr<Option<Type>>,
    policy_id: &PolicyID,
    should_load_all: bool,
) -> Result<(), EntityManifestError> {
    match expr.expr_kind() {
        // Literals, variables, and unkonwns without any GetAttr operations
        // on them are okay, since no fields need to be loaded.
        ExprKind::Lit(_) => (),
        ExprKind::Var(_) => (),
        ExprKind::Slot(_) => (),
        ExprKind::Unknown(_) => return Err(EntityManifestError::PartialExpressionError),
        ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => {
            add_to_root_trie(root_trie, test_expr, policy_id, should_load_all)?;
            add_to_root_trie(root_trie, then_expr, policy_id, should_load_all)?;
            add_to_root_trie(root_trie, else_expr, policy_id, should_load_all)?;
        }
        ExprKind::And { left, right } => {
            add_to_root_trie(root_trie, left, policy_id, should_load_all)?;
            add_to_root_trie(root_trie, right, policy_id, should_load_all)?;
        }
        ExprKind::Or { left, right } => {
            add_to_root_trie(root_trie, left, policy_id, should_load_all)?;
            add_to_root_trie(root_trie, right, policy_id, should_load_all)?;
        }
        ExprKind::UnaryApp { op, arg } => match op {
            UnaryOp::Not => add_to_root_trie(root_trie, arg, policy_id, should_load_all)?,
            UnaryOp::Neg => add_to_root_trie(root_trie, arg, policy_id, should_load_all)?,
        },
        ExprKind::BinaryApp { op, arg1, arg2 } => match op {
            // Special case! Equality between records requires
            // that we load all fields.
            // This could be made more precise if we check the type.
            BinaryOp::Eq => {
                add_to_root_trie(root_trie, arg1, policy_id, true)?;
                add_to_root_trie(root_trie, arg1, policy_id, true)?;
            }
            BinaryOp::In => {
                // Recur normally on the rhs
                add_to_root_trie(root_trie, arg2, policy_id, should_load_all)?;

                // The lhs should be a datapath expression.
                let mut flat_slice = get_expr_path(arg1, policy_id)?;
                flat_slice.parents_required = true;
                *root_trie = root_trie.union(&flat_slice.to_primary_slice());
            }
            BinaryOp::Contains | BinaryOp::ContainsAll | BinaryOp::ContainsAny => {
                // Like equality, another special case for records.
                add_to_root_trie(root_trie, arg1, policy_id, true)?;
                add_to_root_trie(root_trie, arg2, policy_id, true)?;
            }
            BinaryOp::Less | BinaryOp::LessEq | BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => {
                // These operators work on values, so no special
                // case is needed.
                add_to_root_trie(root_trie, arg1, policy_id, should_load_all)?;
                add_to_root_trie(root_trie, arg2, policy_id, should_load_all)?;
            }
        },
        ExprKind::ExtensionFunctionApp { fn_name: _, args } => {
            // WARNING: this code assumes that extension functions
            // don't take full structs as inputs.
            // If they did, we would need to use logic similar to the Eq binary operator.
            for arg in args.iter() {
                add_to_root_trie(root_trie, arg, policy_id, should_load_all)?;
            }
        }
        ExprKind::Like { expr, pattern: _ } => {
            add_to_root_trie(root_trie, expr, policy_id, should_load_all)?;
        }
        ExprKind::Is {
            expr,
            entity_type: _,
        } => {
            add_to_root_trie(root_trie, expr, policy_id, should_load_all)?;
        }
        ExprKind::Set(contents) => {
            for expr in &**contents {
                add_to_root_trie(root_trie, expr, policy_id, should_load_all)?;
            }
        }
        ExprKind::Record(content) => {
            for expr in content.values() {
                add_to_root_trie(root_trie, expr, policy_id, should_load_all)?;
            }
        }
        ExprKind::HasAttr { expr, attr } => {
            let mut flat_slice = get_expr_path(expr, policy_id)?;
            flat_slice.path.push(attr.clone());
            *root_trie = root_trie.union(&flat_slice.to_primary_slice());
        }
        ExprKind::GetAttr { .. } => {
            let flat_slice = get_expr_path(expr, policy_id)?;

            // PANIC SAFETY: Successfuly typechecked expressions should always have annotated types.
            #[allow(clippy::expect_used)]
            let leaf_field = if should_load_all {
                type_to_access_trie(
                    expr.data()
                        .as_ref()
                        .expect("Typechecked expression missing type"),
                )
            } else {
                AccessTrie::new()
            };

            *root_trie = flat_slice.to_primary_slice_with_leaf(leaf_field);
        }
    };

    Ok(())
}

/// Compute the full [`AccessTrie`] required for the type.
fn type_to_access_trie(ty: &Type) -> AccessTrie {
    match ty {
        // if it's not an entity or record, slice ends here
        Type::ExtensionType { .. }
        | Type::Never
        | Type::True
        | Type::False
        | Type::Primitive { .. }
        | Type::Set { .. } => AccessTrie::new(),
        Type::EntityOrRecord(record_type) => entity_or_record_to_access_trie(record_type),
    }
}

/// Compute the full [`AccessTrie`] for the given entity or record type.
fn entity_or_record_to_access_trie(ty: &EntityRecordKind) -> AccessTrie {
    match ty {
        EntityRecordKind::ActionEntity { name: _, attrs }
        | EntityRecordKind::Record {
            attrs,
            open_attributes: _,
        } => {
            let mut fields = HashMap::new();
            for (attr_name, attr_type) in attrs.iter() {
                fields.insert(
                    attr_name.clone(),
                    Box::new(type_to_access_trie(&attr_type.attr_type)),
                );
            }
            AccessTrie {
                children: fields,
                parents_required: false,
                data: (),
            }
        }

        EntityRecordKind::Entity(_) | EntityRecordKind::AnyEntity => {
            // no need to load data for entities, which are compared
            // using ids
            AccessTrie::new()
        }
    }
}

/// Given an expression, get the corresponding data path
/// starting with a variable.
/// If the expression is not a `<datapath-expr>`, return an error.
/// See [`FailedAnalysisError`] for more information.
fn get_expr_path(
    expr: &Expr<Option<Type>>,
    policy_id: &PolicyID,
) -> Result<AccessPath, EntityManifestError> {
    Ok(match expr.expr_kind() {
        ExprKind::Slot(slot_id) => {
            if slot_id.is_principal() {
                AccessPath {
                    root: EntityRoot::Var(Var::Principal),
                    path: vec![],
                    parents_required: false,
                }
            } else {
                assert!(slot_id.is_resource());
                AccessPath {
                    root: EntityRoot::Var(Var::Resource),
                    path: vec![],
                    parents_required: false,
                }
            }
        }
        ExprKind::Var(var) => AccessPath {
            root: EntityRoot::Var(*var),
            path: vec![],
            parents_required: false,
        },
        ExprKind::GetAttr { expr, attr } => {
            let mut slice = get_expr_path(expr, policy_id)?;
            slice.path.push(attr.clone());
            slice
        }
        ExprKind::Lit(Literal::EntityUID(literal)) => AccessPath {
            root: EntityRoot::Literal((**literal).clone()),
            path: vec![],
            parents_required: false,
        },
        ExprKind::Unknown(_) => Err(EntityManifestError::PartialExpressionError)?,
        // all other variants of expressions result in failure to analyze.
        _ => Err(EntityManifestError::FailedAnalysis(FailedAnalysisError {
            source_loc: expr.source_loc().cloned(),
            policy_id: policy_id.clone(),
            expr_kind: expr.expr_kind().clone(),
        }))?,
    })
}

#[cfg(test)]
mod entity_slice_tests {
    use cedar_policy_core::{ast::PolicyID, extensions::Extensions, parser::parse_policy};

    use super::*;

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

        let schema = ValidatorSchema::from_str_natural(
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
        .0;

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");
        let expected = r#"
{
  "per_action": [
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
              "Var": "principal"
            },
            {
              "children": [
                [
                  "name",
                  {
                    "children": [],
                    "parents_required": false
                  }
                ]
              ],
              "parents_required": false
            }
          ]
        ]
      }
    ]
  ]
}"#;
        let expected_manifest = serde_json::from_str(expected).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_empty_entity_manifest() {
        let mut pset = PolicySet::new();
        let policy =
            parse_policy(None, "permit(principal, action, resource);").expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = ValidatorSchema::from_str_natural(
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
        .0;

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");
        let expected = r#"
{
  "per_action": [
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
}"#;
        let expected_manifest = serde_json::from_str(expected).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_parents_required() {
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

        let schema = ValidatorSchema::from_str_natural(
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
        let expected = r#"
{
  "per_action": [
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
              "Var": "principal"
            },
            {
              "children": [
                [
                  "manager",
                  {
                    "children": [],
                    "parents_required": true
                  }
                ]
              ],
              "parents_required": true
            }
          ]
        ]
      }
    ]
  ]
}"#;
        let expected_manifest = serde_json::from_str(expected).unwrap();
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

        let schema = ValidatorSchema::from_str_natural(
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
        let expected = r#"
{
  "per_action": [
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
              "Var": "principal"
            },
            {
              "children": [
                [
                  "name",
                  {
                    "children": [],
                    "parents_required": false
                  }
                ]
              ],
              "parents_required": false
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
              "Var": "principal"
            },
            {
              "children": [
                [
                  "name",
                  {
                    "children": [],
                    "parents_required": false
                  }
                ]
              ],
              "parents_required": false
            }
          ]
        ]
      }
    ]
  ]
}"#;
        let expected_manifest = serde_json::from_str(expected).unwrap();
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

        let schema = ValidatorSchema::from_str_natural(
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
        let expected = r#"
{
  "per_action": [
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
              "Var": "resource"
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
                          "parents_required": false
                        }
                      ]
                    ],
                    "parents_required": false
                  }
                ],
                [
                  "readers",
                  {
                    "children": [],
                    "parents_required": false
                  }
                ]
              ],
              "parents_required": false
            }
          ]
        ]
      }
    ]
  ]
}"#;
        let expected_manifest = serde_json::from_str(expected).unwrap();
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

        let schema = ValidatorSchema::from_str_natural(
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
        let expected = r#"
{
  "per_action": [
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
              "Var": "principal"
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
                          "parents_required": false
                        }
                      ],
                      [
                        "friends",
                        {
                          "children": [],
                          "parents_required": false
                        }
                      ]
                    ],
                    "parents_required": false
                  }
                ]
              ],
              "parents_required": false
            }
          ]
        ]
      }
    ]
  ]
}"#;
        let expected_manifest = serde_json::from_str(expected).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }
}
