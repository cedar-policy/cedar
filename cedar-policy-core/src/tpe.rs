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

#[cfg(test)]
pub(crate) mod test_utils;

use std::{collections::HashMap, sync::Arc};

use crate::ast::PolicyID;
use crate::tpe::err::{PolicyValidationError, TpeError};
use crate::tpe::residual::Residual;
use crate::tpe::response::{ResidualPolicy, Response};
use crate::validator::Validator;
use crate::validator::{typecheck::PolicyCheck, typecheck::Typechecker, ValidatorSchema};
use crate::{ast::PolicySet, extensions::Extensions};

use crate::tpe::{entities::PartialEntities, evaluator::Evaluator, request::PartialRequest};

pub(crate) fn policy_residual_map<'a>(
    request: &'a PartialRequest,
    ps: &'a PolicySet,
    schema: &ValidatorSchema,
) -> std::result::Result<HashMap<&'a PolicyID, Residual>, TpeError> {
    let mut residuals = HashMap::new();
    let tc = Typechecker::new(schema, crate::validator::ValidationMode::Strict);
    let env = request.find_request_env(schema)?;
    for p in ps.policies() {
        let t = p.template();

        let errs: Vec<_> = Validator::validate_entity_types_and_literals(schema, t).collect();
        if !errs.is_empty() {
            return Err(PolicyValidationError::new(errs).into());
        }

        // Get an environment using the actual types of the entities linked with
        // this template. If static, the slot env is empty and this is a no-op.
        let env = env.clone().link_slot_env(p.env());
        match tc.typecheck_by_single_request_env(t, &env) {
            PolicyCheck::Success(expr) => {
                residuals.insert(p.id(), Residual::try_from_typed_expr(&expr, p.env())?);
            }
            PolicyCheck::Fail(errs) => {
                return Err(PolicyValidationError::new(errs).into());
            }
            PolicyCheck::Irrelevant(errs, expr) => {
                if errs.is_empty() {
                    residuals.insert(p.id(), Residual::try_from_typed_expr(&expr, p.env())?);
                } else {
                    return Err(PolicyValidationError::new(errs).into());
                }
            }
        }
    }
    Ok(residuals)
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
) -> std::result::Result<Response<'a>, TpeError> {
    let evaluator = Evaluator {
        request,
        entities,
        extensions: Extensions::all_available(),
    };
    let residuals = policy_residual_map(request, ps, schema)?
        .into_iter()
        .map(|(id, residual)| {
            let residual = evaluator.interpret(&residual);
            #[expect(
                clippy::unwrap_used,
                reason = "exprs and policy set contain the same policy ids"
            )]
            ResidualPolicy::new(Arc::new(residual), Arc::new(ps.get(id).unwrap().clone()))
        });

    Ok(Response::new(residuals, request, entities, schema))
}

#[cfg(test)]
mod tests {
    use cool_asserts::assert_matches;

    use crate::ast::{Annotation, AnyId, BinaryOp, Literal, PolicyID, Value, ValueKind, Var};
    use crate::tpe::residual::{Residual, ResidualKind};
    use crate::validator::ValidatorSchema;
    use crate::{
        ast::{EntityUID, PolicySet},
        extensions::Extensions,
        parser::parse_policyset,
    };
    use std::{
        collections::{BTreeMap, HashSet},
        sync::Arc,
    };

    use crate::tpe::{
        entities::{PartialEntities, PartialEntity},
        request::{PartialEntityUID, PartialRequest},
    };

    use super::is_authorized;

    pub(super) fn collect_policy_ids<'a>(
        iter: impl Iterator<Item = &'a super::response::ResidualPolicy>,
    ) -> HashSet<&'a PolicyID> {
        iter.map(|p| p.get_policy_id()).collect()
    }

    #[track_caller]
    pub(super) fn get_policy_by_annotation_id<'a>(
        ps: &'a PolicySet,
        annotation_id: &str,
    ) -> &'a crate::ast::Policy {
        let id_key = AnyId::new_unchecked("id");
        ps.static_policies()
            .find(|p| {
                matches!(p.annotation(&id_key), Some(Annotation { val, .. }) if val == annotation_id)
            })
            .unwrap()
    }

    #[track_caller]
    pub(super) fn assert_resource_get_attr(residual: &Residual, expected_attr: &str) {
        assert_matches!(
            residual,
            Residual::Partial {
                kind: ResidualKind::GetAttr { expr, attr },
                ..
            } => {
                assert_matches!(
                    expr.as_ref(),
                    Residual::Partial { kind: ResidualKind::Var(Var::Resource), .. }
                );
                assert_eq!(attr, expected_attr);
            }
        );
    }

    #[track_caller]
    pub(super) fn assert_in_resource_attr(
        residual: &Residual,
        expected_uid: &EntityUID,
        expected_attr: &str,
    ) {
        assert_matches!(
            residual,
            Residual::Partial {
                kind: ResidualKind::BinaryApp { op: BinaryOp::In, arg1, arg2 },
                ..
            } => {
                assert_entity_uid_literal(arg1.as_ref(), expected_uid);
                assert_resource_get_attr(arg2.as_ref(), expected_attr);
            }
        );
    }

    #[track_caller]
    pub(super) fn assert_entity_uid_literal(residual: &Residual, expected_uid: &EntityUID) {
        assert_matches!(
            residual,
            Residual::Concrete {
                value: Value { value: ValueKind::Lit(Literal::EntityUID(uid)), .. },
                ..
            } => {
                assert_eq!(uid.as_ref(), expected_uid);
            }
        );
    }

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
            principal: r#"User::"Alice""#.parse::<EntityUID>().unwrap().into(),
            action: r#"Action::"View""#.parse().unwrap(),
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
        let uid: EntityUID = r#"User::"Alice""#.parse().unwrap();
        PartialEntities::from_entities_unchecked(
            [(
                uid.clone(),
                PartialEntity {
                    uid,
                    attrs: Some(BTreeMap::new()),
                    ancestors: Some(HashSet::new()),
                    tags: None,
                },
            )]
            .into_iter(),
        )
    }
    #[test]
    fn rfc_example() {
        let policies = rfc_policies();
        let schema = rfc_schema();
        let request = rfc_request();
        let entities = rfc_entities();
        let residuals = is_authorized(&policies, &request, &entities, &schema).unwrap();

        let policy0 = get_policy_by_annotation_id(&policies, "0");
        let policy1 = get_policy_by_annotation_id(&policies, "1");
        let policy2 = get_policy_by_annotation_id(&policies, "2");

        // Policy 0: resource["isPublic"]
        let r0 = residuals
            .get_residual_policy(policy0.id())
            .unwrap()
            .get_residual();
        assert_resource_get_attr(r0.as_ref(), "isPublic");

        // Policy 1: resource["owner"] == User::"Alice"
        let r1 = residuals
            .get_residual_policy(policy1.id())
            .unwrap()
            .get_residual();
        let alice: EntityUID = r#"User::"Alice""#.parse().unwrap();
        assert_matches!(
            r1.as_ref(),
            Residual::Partial {
                kind: ResidualKind::BinaryApp { op: BinaryOp::Eq, arg1, arg2 },
                ..
            } => {
                assert_resource_get_attr(arg1.as_ref(), "owner");
                assert_entity_uid_literal(arg2.as_ref(), &alice);
            }
        );

        // Policy 2: false (action doesn't match)
        let r2 = residuals
            .get_residual_policy(policy2.id())
            .unwrap()
            .get_residual();
        assert_matches!(
            r2.as_ref(),
            Residual::Concrete {
                value: Value {
                    value: ValueKind::Lit(Literal::Bool(false)),
                    ..
                },
                ..
            }
        );
    }
}

#[cfg(test)]
mod tinytodo {
    use std::collections::HashSet;
    use std::{collections::BTreeMap, sync::Arc};

    use crate::ast::{BinaryOp, EntityUID};
    use crate::tpe::residual::{Residual, ResidualKind};
    use crate::validator::ValidatorSchema;
    use crate::{ast::PolicySet, extensions::Extensions, parser::parse_policyset};
    use cool_asserts::assert_matches;
    use serde_json::json;

    use crate::tpe::{
        entities::PartialEntities,
        request::{PartialEntityUID, PartialRequest},
    };

    use super::is_authorized;
    use super::tests::{
        assert_entity_uid_literal, assert_in_resource_attr, assert_resource_get_attr,
        collect_policy_ids, get_policy_by_annotation_id,
    };

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
            principal: r#"User::"aaron""#.parse::<EntityUID>().unwrap().into(),
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

        let policy0 = get_policy_by_annotation_id(&policies, "0");
        let policy1 = get_policy_by_annotation_id(&policies, "1");
        let policy2 = get_policy_by_annotation_id(&policies, "2");
        let policy3 = get_policy_by_annotation_id(&policies, "3");

        // Check response categorization
        let false_permits = collect_policy_ids(residuals.false_permits());
        assert_eq!(false_permits, HashSet::from([policy0.id(), policy3.id()]));
        assert!(collect_policy_ids(residuals.false_forbids()).is_empty());
        assert!(collect_policy_ids(residuals.true_permits()).is_empty());
        assert!(collect_policy_ids(residuals.true_forbids()).is_empty());

        let residual_permits = collect_policy_ids(residuals.residual_permits());
        assert_eq!(
            residual_permits,
            HashSet::from([policy1.id(), policy2.id()])
        );
        assert!(collect_policy_ids(residuals.residual_forbids()).is_empty());
        assert_matches!(residuals.decision(), None);

        // Policy 1: resource["owner"] == User::"aaron"
        let aaron: EntityUID = r#"User::"aaron""#.parse().unwrap();
        let r1 = residuals
            .get_residual_policy(policy1.id())
            .unwrap()
            .get_residual();
        assert_matches!(
            r1.as_ref(),
            Residual::Partial {
                kind: ResidualKind::BinaryApp { op: BinaryOp::Eq, arg1, arg2 },
                ..
            } => {
                assert_resource_get_attr(arg1.as_ref(), "owner");
                assert_entity_uid_literal(arg2.as_ref(), &aaron);
            }
        );

        // Policy 2: (User::"aaron" in resource["readers"]) || (User::"aaron" in resource["editors"])
        let r2 = residuals
            .get_residual_policy(policy2.id())
            .unwrap()
            .get_residual();
        assert_matches!(
            r2.as_ref(),
            Residual::Partial {
                kind: ResidualKind::Or { left, right },
                ..
            } => {
                assert_in_resource_attr(left.as_ref(), &aaron, "readers");
                assert_in_resource_attr(right.as_ref(), &aaron, "editors");
            }
        );
    }
}
