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
pub mod evaluator;
pub mod request;
pub mod residual;

use thiserror::Error;

use crate::{ast::PolicySet, extensions::Extensions};
use crate::{
    tpe::errors::{NoMatchingReqEnvError, NonstaticPolicyError},
    validator::{
        typecheck::{PolicyCheck, Typechecker},
        ValidationError, ValidatorSchema,
    },
};

use crate::tpe::{
    entities::PartialEntities, evaluator::Evaluator, request::PartialRequest, residual::Residual,
};

/// Errors for TPE
#[derive(Debug, Error)]
pub enum TPEError {
    /// Error thrown when there is no matching request environment according to
    /// a schema
    #[error(transparent)]
    NoMatchingReqEnv(#[from] NoMatchingReqEnvError),
    /// Error thrown when TPE is applied to a non-static policy
    #[error(transparent)]
    NonstaticPolicy(#[from] NonstaticPolicyError),
    /// Error thrown when the typechecker fails to typecheck a policy
    #[error("Failed validation: {:#?}", .0)]
    Validation(Vec<ValidationError>),
}

mod errors {
    use thiserror::Error;

    #[derive(Debug, Error)]
    #[error("Can't find a matching request environment")]
    pub struct NoMatchingReqEnvError;

    #[derive(Debug, Error)]
    #[error("Found a non-static policy")]
    pub struct NonstaticPolicyError;
}

/// Type-aware partial-evaluation on a `PolicySet`.
/// Both `request` and `entities` should be valid and hence be constructed
/// using their safe constructors.
/// Polices must be static.
pub fn tpe_policies(
    ps: &PolicySet,
    request: &PartialRequest,
    entities: &PartialEntities,
    schema: &ValidatorSchema,
) -> std::result::Result<Vec<Residual>, TPEError> {
    let env = request
        .find_request_env(schema)
        .ok_or(NoMatchingReqEnvError)?;
    let tc = Typechecker::new(schema, crate::validator::ValidationMode::Strict);
    let mut exprs = Vec::new();
    for p in ps.policies() {
        if !p.is_static() {
            return Err(NonstaticPolicyError.into());
        }
        let t = p.template();
        match tc.typecheck_by_single_request_env(t, &env) {
            PolicyCheck::Success(expr) => {
                exprs.push(expr);
            }
            PolicyCheck::Fail(errs) => {
                return Err(TPEError::Validation(errs));
            }
            PolicyCheck::Irrelevant(errs, expr) => {
                if errs.is_empty() {
                    exprs.push(expr);
                } else {
                    return Err(TPEError::Validation(errs));
                }
            }
        }
    }
    let evaluator = Evaluator {
        request: request.clone(),
        entities,
        extensions: Extensions::all_available(),
    };
    Ok(exprs.iter().map(|expr| evaluator.interpret(expr)).collect())
}

#[cfg(test)]
mod tests {
    use crate::validator::ValidatorSchema;
    use crate::{
        ast::{Eid, EntityUID, Expr, PolicySet},
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
        residual::Residual,
    };

    use super::tpe_policies;

    fn rfc_policies() -> PolicySet {
        parse_policyset(
            r#"
        // Users can view public documents.
permit (
  principal,
  action == Action::"View",
  resource
) when {
  resource.isPublic
};

// Users can view owned documents if they are mfa-authenticated.
permit (
  principal,
  action == Action::"View",
  resource
) when {
  context.hasMFA &&
  resource.owner == principal
};

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
        let residuals: Vec<Residual> =
            tpe_policies(&policies, &request, &entities, &schema).unwrap();
        for residual in residuals {
            println!("{}", Expr::try_from(residual).unwrap());
        }
    }
}

#[cfg(test)]
mod tinytodo {
    use std::{collections::BTreeMap, sync::Arc};

    use crate::validator::ValidatorSchema;
    use crate::{
        ast::{Eid, Expr, PolicySet},
        extensions::Extensions,
        parser::parse_policyset,
    };
    use serde_json::json;

    use crate::tpe::{
        entities::PartialEntities,
        request::{PartialEntityUID, PartialRequest},
        residual::Residual,
    };

    use super::tpe_policies;

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
permit (
    principal,
    action in [Action::"CreateList", Action::"GetLists"],
    resource == Application::"TinyTodo"
);

// Policy 1: A User can perform any action on a List they own
permit (
  principal,
  action,
  resource is List
)
when { resource.owner == principal };

// Policy 2: A User can see a List if they are either a reader or editor
permit (
    principal,
    action == Action::"GetList",
    resource
)
when { principal in resource.readers || principal in resource.editors };

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

// Policy 4: Admins can perform any action on any resource
// @id("admin-omnipotence")
// permit (
//    principal in Team::"admin",
//    action,
//    resource in Application::"TinyTodo"
// );
// 
// Policy 5: Interns may not create new task lists
// forbid (
//     principal in Team::"interns",
//     action == Action::"CreateList",
//     resource == Application::"TinyTodo"
// );
//
// Policy 6: No access if not high rank and at location DEF, 
// or at resource's owner's location
// forbid(
//     principal,
//     action,
//     resource is List
// ) unless {
//     principal.joblevel > 6 && principal.location like "DEF*" ||
//     principal.location == resource.owner.location
// };
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
        let residuals: Vec<Residual> =
            tpe_policies(&policies, &request, &entities, &schema).unwrap();
        for residual in residuals {
            println!("{}", Expr::try_from(residual).unwrap());
        }
    }
}
