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

//! This module contains the batched evaluator implementation and the (internal) definition of [`EntityLoader`]

pub mod err;

use std::collections::{HashMap, HashSet};
use std::iter;
use std::sync::Arc;

use crate::ast::{Entity, EntityUID, EntityUIDEntry, Request};
use crate::authorizer::Decision;
use crate::batched_evaluator::err::{BatchedEvalError, InsufficientIterationsError};
use crate::entities::TCComputation;
use crate::tpe::entities::PartialEntity;
use crate::tpe::err::PartialRequestError;
use crate::tpe::policy_residual_map;
use crate::tpe::request::{PartialEntityUID, PartialRequest};
use crate::tpe::response::{decision_from_residuals, ResidualPolicy, Response};
use crate::validator::ValidatorSchema;
use crate::{ast::PolicySet, extensions::Extensions};

use crate::tpe::{entities::PartialEntities, evaluator::Evaluator};

/// Loads entities based on their EntityUID.
/// See the public version in `api.rs`
pub trait EntityLoader {
    /// Load all entities for the given set of entity UIDs.
    /// Returns a map from [`EntityUID`] to `Option<Entity>`, where `None` indicates
    /// the entity does not exist.
    fn load_entities(&mut self, uids: &HashSet<EntityUID>) -> HashMap<EntityUID, Option<Entity>>;
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
/// of an [`crate::entities::Entities`] store.
pub fn is_authorized_batched(
    request: &Request,
    ps: &PolicySet,
    schema: &ValidatorSchema,
    loader: &mut dyn EntityLoader,
    max_iters: u32,
) -> Result<Decision, BatchedEvalError> {
    let request = concrete_request_to_partial(request, schema)?;
    // Actions comes from the schema, so batched eval can start with them
    let mut entities = PartialEntities::from_entities(iter::empty(), schema)?;
    let initial_evaluator = Evaluator {
        request: &request,
        entities: &entities,
        extensions: Extensions::all_available(),
    };
    let mut residuals: Vec<ResidualPolicy> = policy_residual_map(&request, ps, schema)?
        .into_iter()
        .map(|(id, expr)| {
            let residual = initial_evaluator.interpret(&expr);
            #[expect(
                clippy::unwrap_used,
                reason = "exprs and policy set contain the same policy ids"
            )]
            ResidualPolicy::new(Arc::new(residual), Arc::new(ps.get(id).unwrap().clone()))
        })
        .collect();

    for _i in 0..max_iters {
        if decision_from_residuals(&residuals).is_some() {
            // Exit before `max_iters` if we reach a decision
            break;
        }

        let ids = residuals.iter().flat_map(|r| r.all_literal_uids());
        let mut to_load = HashSet::new();
        // filter to_load for already loaded entities
        for uid in ids {
            if !entities.contains_entity(&uid) {
                to_load.insert(uid);
            }
        }
        // Subtle: missing entities are equivalent empty entities in both normal and partial evaluation.
        let loaded_entities = loader.load_entities(&to_load);

        // check that all requested entities were loaded and return error otherwise

        for (id, e_option) in loaded_entities {
            match e_option {
                Some(e) => {
                    entities.add_entities(
                        iter::once((id, PartialEntity::try_from(e)?)),
                        schema,
                        TCComputation::AssumeAlreadyComputed,
                    )?;
                }
                None => {
                    entities.add_entity_trusted(
                        id.clone(),
                        PartialEntity::try_from(Entity::with_uid(id))?,
                    )?;
                }
            }
        }

        let evaluator = Evaluator {
            request: &request,
            entities: &entities,
            extensions: Extensions::all_available(),
        };

        // perform partial evaluation again
        residuals = residuals
            .into_iter()
            .map(|residual| {
                #[expect(
                    clippy::unwrap_used,
                    reason = "residuals and policy set contain the same policy ids"
                )]
                ResidualPolicy::new(
                    Arc::new(evaluator.interpret(&residual.get_residual())),
                    Arc::new(ps.get(residual.get_policy_id()).unwrap().clone()),
                )
            })
            .collect();
    }

    let response = Response::new(residuals.into_iter(), &request, &entities, schema);

    match response.decision() {
        Some(decision) => Ok(decision),
        None => Err(InsufficientIterationsError {}.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Context, RequestSchemaAllPass};
    use crate::extensions::Extensions;
    use crate::parser::parse_policyset;

    struct Loader {
        requested: Vec<EntityUID>,
    }

    impl EntityLoader for Loader {
        fn load_entities(
            &mut self,
            uids: &HashSet<EntityUID>,
        ) -> HashMap<EntityUID, Option<Entity>> {
            self.requested.extend(uids.iter().cloned());
            uids.iter().map(|u| (u.clone(), None)).collect()
        }
    }

    #[track_caller]
    fn run(policies: &str) -> (Decision, Loader) {
        let schema = ValidatorSchema::from_cedarschema_str(
            r#"
            entity User { level: Long };
            entity Document;
            action all;
            action read in [all] appliesTo { principal: [User], resource: [Document] };
            "#,
            Extensions::all_available(),
        )
        .expect("schema should parse")
        .0;
        let request = Request::new(
            (r#"User::"alice""#.parse().expect("uid should parse"), None),
            (r#"Action::"read""#.parse().expect("uid should parse"), None),
            (
                r#"Document::"doc""#.parse().expect("uid should parse"),
                None,
            ),
            Context::empty(),
            Some(&RequestSchemaAllPass {}),
            Extensions::all_available(),
        )
        .expect("request should be valid");
        let ps = parse_policyset(policies).expect("policies should parse");
        let mut loader = Loader {
            requested: Vec::new(),
        };
        let decision = is_authorized_batched(&request, &ps, &schema, &mut loader, 3)
            .expect("should reach a decision");
        (decision, loader)
    }

    #[test]
    fn actions_are_seeded_from_the_schema() {
        let (decision, loader) = run(r#"permit(principal, action in Action::"all", resource);"#);
        assert_eq!(decision, Decision::Allow);
        assert_eq!(loader.requested, vec![]);
    }

    #[test]
    fn nothing_is_loaded_once_the_decision_is_determined() {
        let (decision, loader) = run(r#"
            forbid(principal, action, resource);
            permit(principal, action, resource) when { principal.level > 5 };
            "#);
        assert_eq!(decision, Decision::Deny);
        assert_eq!(loader.requested, vec![]);
    }
}
