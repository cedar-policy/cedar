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

//! This module contains the type-aware partial evaluator.

pub mod entities;
pub mod err;
pub mod evaluator;
pub mod request;
pub mod residual;
pub mod response;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::ast::{Entity, EntityUID, EntityUIDEntry, Expr, PolicyID, Request};
use crate::entities::TCComputation;
use crate::tpe::entities::PartialEntity;
use crate::tpe::err::{BatchedEvalError, NonstaticPolicyError, PartialRequestError, TPEError};
use crate::tpe::request::PartialEntityUID;
use crate::tpe::response::{ResidualPolicy, Response};
use crate::validator::types::Type;
use crate::validator::{
    typecheck::{PolicyCheck, Typechecker},
    ValidatorSchema,
};
use crate::{ast::PolicySet, extensions::Extensions};

use crate::tpe::{entities::PartialEntities, evaluator::Evaluator, request::PartialRequest};

fn policy_expr_map<'a>(
    request: &'a PartialRequest,
    ps: &'a PolicySet,
    schema: &ValidatorSchema,
) -> std::result::Result<HashMap<&'a PolicyID, Expr<Option<Type>>>, TPEError> {
    let mut exprs = HashMap::new();
    let tc = Typechecker::new(schema, crate::validator::ValidationMode::Strict);
    let env = request.find_request_env(schema)?;
    for p in ps.policies() {
        if !p.is_static() {
            return Err(NonstaticPolicyError.into());
        }
        let t = p.template();
        match tc.typecheck_by_single_request_env(t, &env) {
            PolicyCheck::Success(expr) => {
                exprs.insert(p.id(), expr);
            }
            PolicyCheck::Fail(errs) => {
                return Err(TPEError::Validation(errs));
            }
            PolicyCheck::Irrelevant(errs, expr) => {
                if errs.is_empty() {
                    exprs.insert(p.id(), expr);
                } else {
                    return Err(TPEError::Validation(errs));
                }
            }
        }
    }
    Ok(exprs)
}

/// Type-aware partial-evaluation on a `PolicySet`.
/// Both `request` and `entities` should be valid and hence be constructed
/// using their safe constructors.
/// Policies must be static.
pub fn is_authorized<'a>(
    ps: &PolicySet,
    request: &'a PartialRequest,
    entities: &'a PartialEntities,
    schema: &'a ValidatorSchema,
) -> std::result::Result<Response<'a>, TPEError> {
    let exprs = policy_expr_map(request, ps, schema)?;
    let evaluator = Evaluator {
        request,
        entities,
        extensions: Extensions::all_available(),
    };
    let residuals: Result<Vec<_>, TPEError> = exprs
        .into_iter()
        .map(|(id, expr)| {
            let residual = evaluator
                .interpret_expr(&expr)
                .map_err(TPEError::ExprToResidual)?;
            // PANIC SAFETY: exprs and policy set contain the same policy ids
            #[allow(clippy::unwrap_used)]
            Ok(ResidualPolicy::new(
                Arc::new(residual),
                Arc::new(ps.get(id).unwrap().clone()),
            ))
        })
        .collect();

    // PANIC SAFETY: `id` should exist in the policy set
    #[allow(clippy::unwrap_used)]
    Ok(Response::new(
        residuals?.into_iter(),
        Some(request),
        Some(entities),
        schema,
    ))
}

/// Internal version of [`EntityLoader`]
pub trait EntityLoaderInternal {
    /// Load all entities for the given set of entity UIDs.
    /// Returns a map from [`EntityUID`] to Option<Entity>, where `None` indicates
    /// the entity does not exist.
    fn load_entities(
        &mut self,
        uids: &std::collections::HashSet<EntityUID>,
    ) -> std::collections::HashMap<EntityUID, Option<Entity>>;
}

fn concrete_request_to_partial(
    request: &Request,
    schema: &ValidatorSchema,
) -> Result<PartialRequest, BatchedEvalError> {
    // Convert principal EntityUIDEntry to PartialEntityUID
    let principal = match &request.principal {
        EntityUIDEntry::Known { euid, .. } => PartialEntityUID::from(euid.as_ref().clone()),
        EntityUIDEntry::Unknown { .. } => return Err(PartialRequestError {}.into()),
    };

    // Convert action EntityUIDEntry to EntityUID (must be concrete)
    let action = match &request.action {
        EntityUIDEntry::Known { euid, .. } => euid.as_ref().clone(),
        EntityUIDEntry::Unknown { .. } => return Err(PartialRequestError {}.into()),
    };

    // Convert resource EntityUIDEntry to PartialEntityUID
    let resource = match &request.resource {
        EntityUIDEntry::Known { euid, .. } => PartialEntityUID::from(euid.as_ref().clone()),
        EntityUIDEntry::Unknown { .. } => return Err(PartialRequestError {}.into()),
    };

    // Convert context
    let context = match &request.context {
        Some(crate::ast::Context::Value(attrs)) => Some(attrs.clone()),
        Some(crate::ast::Context::RestrictedResidual(_)) => {
            return Err(PartialRequestError {}.into())
        }
        None => None,
    };

    Ok(PartialRequest::new(
        principal, action, resource, context, schema,
    )?)
}

/// Perform authorization using loader function instead
/// of an [`Entities`] store.
pub fn is_authorized_batched<'a>(
    request: &Request,
    ps: &PolicySet,
    schema: &'a ValidatorSchema,
    loader: &mut dyn EntityLoaderInternal,
    max_iters: u32,
) -> Result<Response<'a>, BatchedEvalError> {
    let request = concrete_request_to_partial(request, schema)?;
    let exprs = policy_expr_map(&request, ps, schema)?;
    let mut entities = PartialEntities::default();
    let initial_evaluator = Evaluator {
        request: &request,
        entities: &entities,
        extensions: Extensions::all_available(),
    };
    let residuals_res: Result<Vec<ResidualPolicy>, BatchedEvalError> = exprs
        .into_iter()
        .map(|(id, expr)| {
            let residual = initial_evaluator
                .interpret_expr(&expr)
                .map_err(BatchedEvalError::from)?;
            // PANIC SAFETY: exprs and policy set contain the same policy ids
            #[allow(clippy::unwrap_used)]
            Ok(ResidualPolicy::new(
                Arc::new(residual),
                Arc::new(ps.get(id).unwrap().clone()),
            ))
        })
        .collect();
    let mut residuals = residuals_res?;

    // PANIC SAFETY: residuals and policy set contain the same policy ids
    #[allow(clippy::unwrap_used)]
    for _i in 0..max_iters {
        let ids = residuals.iter().flat_map(|r| r.all_literal_uids());
        let mut to_load = HashSet::new();
        // filter to_load for already loaded entities
        for uid in ids {
            if !entities.entities.contains_key(&uid) {
                to_load.insert(uid);
            }
        }
        // Subtle: missing entities are equivalent empty entities in both normal and partial evaluation.
        let loaded_entities = loader.load_entities(&to_load);

        // check that all requested entities were loaded and return error otherwise

        let mut loaded_partial = vec![];
        for (id, e_option) in loaded_entities {
            let partial_entity = match e_option {
                Some(e) => PartialEntity::try_from(e)?,
                None => PartialEntity::try_from(Entity::with_uid(id.clone()))?,
            };
            loaded_partial.push((id, partial_entity));
        }

        entities.add_entities(
            loaded_partial.into_iter(),
            schema,
            TCComputation::AssumeAlreadyComputed,
        )?;

        let evaluator = Evaluator {
            request: &request,
            entities: &entities,
            extensions: Extensions::all_available(),
        };
        // perform partial evaluation again
        residuals = residuals
            .into_iter()
            .map(|residual| {
                ResidualPolicy::new(
                    Arc::new(evaluator.interpret(&residual.get_residual())),
                    Arc::new(ps.get(&residual.get_policy_id()).unwrap().clone()),
                )
            })
            .collect();

        // if all the residuals are done exit
        if residuals.iter().all(|r| r.get_residual().is_concrete()) {
            break;
        }
    }
    Ok(Response::new(residuals.into_iter(), None, None, schema))
}

#[cfg(test)]
mod tests {
    use cool_asserts::assert_matches;

    use crate::ast::{Annotation, AnyId, BinaryOp, Literal, Value, ValueKind, Var};
    use crate::tpe::residual::{Residual, ResidualKind};
    use crate::validator::ValidatorSchema;
    use crate::{
        ast::{Eid, EntityUID, PolicySet},
        extensions::Extensions,
        parser::parse_policyset,
    };
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        sync::Arc,
    };

    use crate::tpe::{
        entities::{PartialEntities, PartialEntity},
        request::{PartialEntityUID, PartialRequest},
    };

    use super::is_authorized;

    fn rfc_policies() -> PolicySet {
        parse_policyset(
            r#"
        // Users can view public documents.
@id("0")
permit (
  principal,
  action == Action::"View",
  resource
) when {
  resource.isPublic
};

@id("1")
// Users can view owned documents if they are mfa-authenticated.
permit (
  principal,
  action == Action::"View",
  resource
) when {
  context.hasMFA &&
  resource.owner == principal
};

@id("2")
// Users can delete owned documents if they are mfa-authenticated
// and on the company network.
permit (
  principal,
  action == Action::"Delete",
  resource
) when {
  context.hasMFA &&
  resource.owner == principal &&
  context.srcIP.isInRange(ip("1.1.1.0/24"))
};
        "#,
        )
        .unwrap()
    }

    fn rfc_schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
        entity User;

entity Document  = {
  "isPublic": Bool,
  "owner": User
};

action View appliesTo {
  principal: [User],
  resource: [Document],
  context: {
    "hasMFA": Bool,
  }
};

action Delete appliesTo {
  principal: [User],
  resource: [Document],
  context: {
    "hasMFA": Bool,
    "srcIP": ipaddr
  }
};
        "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    fn rfc_request() -> PartialRequest {
        PartialRequest {
            principal: PartialEntityUID {
                ty: "User".parse().unwrap(),
                eid: Some(Eid::new("Alice")),
            },
            action: EntityUID::from_components("Action".parse().unwrap(), Eid::new("View"), None),
            resource: PartialEntityUID {
                ty: "Document".parse().unwrap(),
                eid: None,
            },
            context: Some(Arc::new(BTreeMap::from_iter(std::iter::once((
                "hasMFA".into(),
                true.into(),
            ))))),
        }
    }

    fn rfc_entities() -> PartialEntities {
        let uid = EntityUID::from_components("User".parse().unwrap(), Eid::new("Alice"), None);
        PartialEntities {
            entities: HashMap::from_iter([(
                uid.clone(),
                PartialEntity {
                    uid,
                    attrs: Some(BTreeMap::new()),
                    ancestors: Some(HashSet::new()),
                    tags: None,
                },
            )]),
        }
    }
    #[test]
    fn rfc_example() {
        let policies = rfc_policies();
        let schema = rfc_schema();
        let request = rfc_request();
        let entities = rfc_entities();
        let residuals = is_authorized(&policies, &request, &entities, &schema).unwrap();
        let id = AnyId::new_unchecked("id");
        let policy0 = policies
            .static_policies()
            .find(|p| matches!(p.annotation(&id), Some(Annotation {val, ..}) if val == "0"))
            .unwrap();
        let policy1 = policies
            .static_policies()
            .find(|p| matches!(p.annotation(&id), Some(Annotation {val, ..}) if val == "1"))
            .unwrap();
        let policy2 = policies
            .static_policies()
            .find(|p| matches!(p.annotation(&id), Some(Annotation {val, ..}) if val == "2"))
            .unwrap();
        // resource["isPublic"]
        assert_matches!(residuals.get_residual(policy0.id()), Some(Residual::Partial{kind: ResidualKind::GetAttr { expr, attr }, ..}) => {
            assert_matches!(expr.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Resource), .. });
            assert_eq!(attr, "isPublic");
        });
        // (resource["owner"]) == User::"Alice"
        assert_matches!(residuals.get_residual(policy1.id()), Some(Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::Eq, arg1, arg2 }, .. }) => {
            assert_matches!(arg1.as_ref(), Residual::Partial { kind: ResidualKind::GetAttr { expr, attr }, .. } => {
                assert_matches!(expr.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Resource), .. });
                assert_eq!(attr, "owner");
            });
            assert_matches!(arg2.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(uid)), ..}, .. } => {
                assert_eq!(uid.as_ref(), &EntityUID::from_components("User".parse().unwrap(), Eid::new("Alice"), None));
            });
        });
        // false
        assert_matches!(
            residuals.get_residual(policy2.id()),
            Some(Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(false)),
                    ..
                },
                ..
            })
        );
    }
}

#[cfg(test)]
mod tinytodo {
    use std::collections::HashSet;
    use std::{collections::BTreeMap, sync::Arc};

    use crate::ast::{
        Annotation, AnyId, BinaryOp, EntityUID, Literal, PolicyID, Value, ValueKind, Var,
    };
    use crate::tpe::residual::{Residual, ResidualKind};
    use crate::validator::ValidatorSchema;
    use crate::{
        ast::{Eid, PolicySet},
        extensions::Extensions,
        parser::parse_policyset,
    };
    use cool_asserts::assert_matches;
    use serde_json::json;

    use crate::tpe::{
        entities::PartialEntities,
        request::{PartialEntityUID, PartialRequest},
    };

    use super::is_authorized;

    #[track_caller]
    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"type Task = {
    "id": Long,
    "name": String,
    "state": String,
};

type Tasks = Set<Task>;
entity List in [Application] = {
  "editors": Team,
  "name": String,
  "owner": User,
  "readers": Team,
  "tasks": Tasks,
};
entity Application enum ["TinyTodo"];
entity User in [Team, Application] = {
  "joblevel": Long,
  "location": String,
};
entity Team in [Team, Application];

action DeleteList, GetList, UpdateList appliesTo {
  principal: [User],
  resource: [List]
};
action CreateList, GetLists appliesTo {
  principal: [User],
  resource: [Application]
};
action CreateTask, UpdateTask, DeleteTask appliesTo {
  principal: [User],
  resource: [List]
};
action EditShare appliesTo {
  principal: [User],
  resource: [List]
};"#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    #[track_caller]
    fn policies() -> PolicySet {
        parse_policyset(
            r#"
        // Policy 0: Any User can create a list and see what lists they own
@id("0")
permit (
    principal,
    action in [Action::"CreateList", Action::"GetLists"],
    resource == Application::"TinyTodo"
);

// Policy 1: A User can perform any action on a List they own
@id("1")
permit (
  principal,
  action,
  resource is List
)
when { resource.owner == principal };

// Policy 2: A User can see a List if they are either a reader or editor
@id("2")
permit (
    principal,
    action == Action::"GetList",
    resource
)
when { principal in resource.readers || principal in resource.editors };

@id("3")
// Policy 3: A User can update a List and its tasks if they are an editor
permit (
    principal,
    action in
        [Action::"UpdateList",
         Action::"CreateTask",
         Action::"UpdateTask",
         Action::"DeleteTask"],
    resource
)
when { principal in resource.editors };
        "#,
        )
        .unwrap()
    }

    #[track_caller]
    fn partial_request() -> PartialRequest {
        PartialRequest {
            principal: PartialEntityUID {
                ty: "User".parse().unwrap(),
                eid: Some(Eid::new("aaron")),
            },
            action: r#"Action::"GetList""#.parse().unwrap(),
            resource: PartialEntityUID {
                ty: "List".parse().unwrap(),
                eid: None,
            },
            context: Some(Arc::new(BTreeMap::new())),
        }
    }

    #[track_caller]
    fn partial_entities() -> PartialEntities {
        PartialEntities::from_json_value(
            json!([
                {
                    "uid" : {
                        "type" : "User",
                        "id" : "aaron"
                    },
                    "parents" : [{"type": "Application", "id": "TinyTodo"}],
                },
            ]),
            &schema(),
        )
        .unwrap()
    }

    #[test]
    fn run() {
        let policies = policies();
        let schema = schema();
        let request = partial_request();
        let entities = partial_entities();
        let residuals = is_authorized(&policies, &request, &entities, &schema).unwrap();
        let id = AnyId::new_unchecked("id");
        let policy0 = policies
            .static_policies()
            .find(|p| matches!(p.annotation(&id), Some(Annotation {val, ..}) if val == "0"))
            .unwrap();
        let policy1 = policies
            .static_policies()
            .find(|p| matches!(p.annotation(&id), Some(Annotation {val, ..}) if val == "1"))
            .unwrap();
        let policy2 = policies
            .static_policies()
            .find(|p| matches!(p.annotation(&id), Some(Annotation {val, ..}) if val == "2"))
            .unwrap();
        let policy3 = policies
            .static_policies()
            .find(|p| matches!(p.annotation(&id), Some(Annotation {val, ..}) if val == "3"))
            .unwrap();
        let false_permits: HashSet<&PolicyID> = residuals.false_permits().collect();
        assert!(false_permits.len() == 2);
        assert!(false_permits.contains(policy0.id()));
        assert!(false_permits.contains(policy3.id()));
        let false_forbids: HashSet<&PolicyID> = residuals.false_forbids().collect();
        assert!(false_forbids.is_empty());
        let true_permits: HashSet<&PolicyID> = residuals.satisfied_permits().collect();
        assert!(true_permits.is_empty());
        let true_forbids: HashSet<&PolicyID> = residuals.satisfied_forbids().collect();
        assert!(true_forbids.is_empty());
        let non_trivial_permits: HashSet<&PolicyID> = residuals.non_trival_permits().collect();
        assert!(non_trivial_permits.len() == 2);
        assert!(non_trivial_permits.contains(policy1.id()));
        assert!(non_trivial_permits.contains(policy2.id()));
        let non_trivial_forbids: HashSet<&PolicyID> = residuals.non_trival_forbids().collect();
        assert!(non_trivial_forbids.is_empty());
        assert_matches!(residuals.decision(), None);
        // (resource["owner"]) == User::"aaron"
        assert_matches!(residuals.get_residual(policy1.id()), Some(Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::Eq, arg1, arg2 }, .. }) => {
            assert_matches!(arg1.as_ref(), Residual::Partial { kind: ResidualKind::GetAttr { expr, attr }, .. } => {
                assert_matches!(expr.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Resource), .. });
                assert_eq!(attr, "owner");
            });
            assert_matches!(arg2.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(uid)), ..}, .. } => {
                assert_eq!(uid.as_ref(), &EntityUID::from_components("User".parse().unwrap(), Eid::new("aaron"), None));
            });
        });
        // (User::"aaron" in (resource["readers"])) || (User::"aaron" in (resource["editors"]))
        assert_matches!(residuals.get_residual(policy2.id()), Some(Residual::Partial { kind: ResidualKind::Or{ left, right }, .. }) => {
                    assert_matches!(left.as_ref(), Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::In, arg1, arg2 }, .. } => {
        assert_matches!(arg1.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(uid)), ..}, .. } => {
                        assert_eq!(uid.as_ref(), &EntityUID::from_components("User".parse().unwrap(), Eid::new("aaron"), None));
                    });
                        assert_matches!(arg2.as_ref(), Residual::Partial { kind: ResidualKind::GetAttr { expr, attr }, .. } => {
                            assert_matches!(expr.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Resource), .. });
                            assert_eq!(attr, "readers");
                        });
                    });
                    assert_matches!(right.as_ref(), Residual::Partial { kind: ResidualKind::BinaryApp { op: BinaryOp::In, arg1, arg2 }, .. } => {
                       assert_matches!(arg1.as_ref(), Residual::Concrete { value: Value { value: ValueKind::Lit(Literal::EntityUID(uid)), ..}, .. } => {
                        assert_eq!(uid.as_ref(), &EntityUID::from_components("User".parse().unwrap(), Eid::new("aaron"), None));
                    });
                        assert_matches!(arg2.as_ref(), Residual::Partial { kind: ResidualKind::GetAttr { expr, attr }, .. } => {
                            assert_matches!(expr.as_ref(), Residual::Partial { kind: ResidualKind::Var(Var::Resource), .. });
                            assert_eq!(attr, "editors");
                        });
                    });
                });
    }
}
