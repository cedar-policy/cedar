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

use std::collections::{HashMap, HashSet};
use std::iter;
use std::sync::Arc;

use crate::ast::{Entity, EntityUID, EntityUIDEntry, Expr, PolicyID, Request};
use crate::authorizer::Decision;
use crate::entities::TCComputation;
use crate::tpe::entities::PartialEntity;
use crate::tpe::err::{
    BatchedEvalError, InsufficientIterationsError, NonstaticPolicyError, PartialRequestError,
    TPEError,
};
use crate::tpe::request::{PartialEntityUID, PartialRequest};
use crate::tpe::residual::Residual;
use crate::tpe::response::{ResidualPolicy, Response};
use crate::validator::typecheck::{PolicyCheck, Typechecker};
use crate::validator::types::Type;
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

pub(crate) fn policy_expr_map<'a>(
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
    loader: &mut dyn EntityLoader,
    max_iters: u32,
) -> Result<Decision, BatchedEvalError> {
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
                .map_err(TPEError::from)?;
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
                ResidualPolicy::new(
                    Arc::new(evaluator.interpret(&residual.get_residual())),
                    Arc::new(ps.get(&residual.get_policy_id()).unwrap().clone()),
                )
            })
            .collect();

        // if all the residuals are done, exit
        if residuals
            .iter()
            .all(|r| !matches!(*(r.get_residual()), Residual::Partial { .. }))
        {
            break;
        }
    }

    let response = Response::new(residuals.into_iter(), &request, &entities, schema);

    match response.decision() {
        Some(decision) => Ok(decision),
        None => Err(InsufficientIterationsError {}.into()),
    }
}
