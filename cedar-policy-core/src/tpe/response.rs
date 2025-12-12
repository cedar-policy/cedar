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

//! This module contains the result of partial authorization.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    ast::{Effect, EntityUID, Expr, Policy, PolicyID, PolicySet, Request, RequestSchema},
    authorizer::{Authorizer, Decision},
    entities::{conformance::EntitySchemaConformanceChecker, Entities},
    extensions::Extensions,
    tpe::{
        entities::PartialEntities, err::ReauthorizationError, request::PartialRequest,
        residual::Residual,
    },
    validator::{CoreSchema, ValidatorSchema},
};

/// Represent a residual policy
#[derive(Debug, Clone)]
pub struct ResidualPolicy {
    residual: Arc<Residual>,
    policy: Arc<Policy>,
}

impl ResidualPolicy {
    /// Construct a [`ResidualPolicy`]
    pub fn new(residual: Arc<Residual>, policy: Arc<Policy>) -> Self {
        Self { residual, policy }
    }

    /// Get the [`Effect`]
    pub fn get_effect(&self) -> Effect {
        self.policy.effect()
    }

    /// Get the [`Residual`]
    pub fn get_residual(&self) -> Arc<Residual> {
        self.residual.clone()
    }

    /// Get the [`PolicyID`]
    pub fn get_policy_id(&self) -> PolicyID {
        self.policy.id().clone()
    }

    /// All literal uids referenced by this residual
    pub fn all_literal_uids(&self) -> HashSet<EntityUID> {
        self.residual.all_literal_uids()
    }
}

impl From<ResidualPolicy> for Policy {
    fn from(value: ResidualPolicy) -> Self {
        Self::from_when_clause_annos(
            value.policy.effect(),
            Arc::new(Expr::from(value.residual.as_ref().clone())),
            value.policy.id().clone(),
            None,
            value.policy.annotations_arc().clone(),
        )
    }
}

/// The result of partial authorization.
// This struct is akin is to PE's `PartialResponse`
#[derive(Debug, Clone)]
pub struct Response<'a> {
    decision: Option<Decision>,
    residuals: HashMap<PolicyID, ResidualPolicy>,
    // All of the [`Effect::Permit`] policies that were satisfied
    satisfied_permits: HashSet<PolicyID>,
    // All of the [`Effect::Permit`] policies that were not satisfied
    false_permits: HashSet<PolicyID>,
    // All of the [`Effect::Permit`] policies that evaluated to a residual
    residual_permits: HashSet<PolicyID>,
    // All of the [`Effect::Forbid`] policies that were satisfied
    satisfied_forbids: HashSet<PolicyID>,
    // All of the [`Effect::Forbid`] policies that were not satisfied
    false_forbids: HashSet<PolicyID>,
    // All of the [`Effect::Forbid`] policies that evaluated to a residual
    residual_forbids: HashSet<PolicyID>,
    // request used for this partial evaluation
    request: &'a PartialRequest,
    // entities used for this partial evaluation
    entities: &'a PartialEntities,
    // schema
    schema: &'a ValidatorSchema,
}

impl<'a> Response<'a> {
    /// Construct a [`Response`] from an iterator of [`ResidualPolicy`]s.
    /// Guaranteed to arrive at a [`Decision`] if all the residuals are not [`Residual::Partial`]
    pub fn new(
        residuals: impl Iterator<Item = ResidualPolicy>,
        request: &'a PartialRequest,
        entities: &'a PartialEntities,
        schema: &'a ValidatorSchema,
    ) -> Self {
        let mut residual_map = HashMap::new();
        let mut satisfied_permits = HashSet::new();
        let mut false_permits = HashSet::new();
        let mut residual_permits = HashSet::new();
        let mut satisfied_forbids = HashSet::new();
        let mut false_forbids = HashSet::new();
        let mut residual_forbids = HashSet::new();
        for rp in residuals {
            let r = rp.get_residual();
            let id = rp.get_policy_id();
            residual_map.insert(id.clone(), rp.clone());
            match rp.get_effect() {
                Effect::Forbid => {
                    if r.is_true() {
                        satisfied_forbids.insert(id);
                    } else if r.is_false() || r.is_error() {
                        false_forbids.insert(id);
                    } else {
                        residual_forbids.insert(id);
                    }
                }
                Effect::Permit => {
                    if r.is_true() {
                        satisfied_permits.insert(id);
                    } else if r.is_false() || r.is_error() {
                        false_permits.insert(id);
                    } else {
                        residual_permits.insert(id);
                    }
                }
            }
        }

        let decision = match (
            !satisfied_forbids.is_empty(),
            !satisfied_permits.is_empty(),
            !residual_permits.is_empty(),
            !residual_forbids.is_empty(),
        ) {
            // Any true forbids means we will deny
            (true, _, _, _) => Some(Decision::Deny),
            // No potentially or trivially true permits, means we default deny
            (_, false, false, _) => Some(Decision::Deny),
            // Potentially true forbids, means we can't know (as that forbid may evaluate to true, overriding any permits)
            (false, _, _, true) => None,
            // No true permits, but some potentially true permits + no true/potentially true forbids means we don't know
            (false, false, true, false) => None,
            // At least one trivially true permit, and no trivially or possible true forbids, means we allow
            (false, true, _, false) => Some(Decision::Allow),
        };

        Self {
            decision,
            residuals: residual_map,
            satisfied_permits,
            false_permits,
            residual_permits,
            satisfied_forbids,
            false_forbids,
            residual_forbids,
            request,
            entities,
            schema,
        }
    }

    /// Get satisfied permit residual policies
    pub fn satisfied_permits(&self) -> impl Iterator<Item = &ResidualPolicy> {
        #[expect(
            clippy::unwrap_used,
            reason = "we know that the policy ids are in the residuals map"
        )]
        self.satisfied_permits
            .iter()
            .map(|id| self.residuals.get(id).unwrap())
    }

    /// Get satisfied forbid residual policies
    pub fn satisfied_forbids(&self) -> impl Iterator<Item = &ResidualPolicy> {
        #[expect(
            clippy::unwrap_used,
            reason = "we know that the policy ids are in the residuals map"
        )]
        self.satisfied_forbids
            .iter()
            .map(|id| self.residuals.get(id).unwrap())
    }

    /// Get trivially false permit residual policies
    pub fn false_permits(&self) -> impl Iterator<Item = &ResidualPolicy> {
        #[expect(
            clippy::unwrap_used,
            reason = "we know that the policy ids are in the residuals map"
        )]
        self.false_permits
            .iter()
            .map(|id| self.residuals.get(id).unwrap())
    }

    /// Get trivially false forbid residual policies
    pub fn false_forbids(&self) -> impl Iterator<Item = &ResidualPolicy> {
        #[expect(
            clippy::unwrap_used,
            reason = "we know that the policy ids are in the residuals map"
        )]
        self.false_forbids
            .iter()
            .map(|id| self.residuals.get(id).unwrap())
    }

    /// Get non-trivial permit residual policies
    pub fn residual_permits(&self) -> impl Iterator<Item = &ResidualPolicy> {
        #[expect(
            clippy::unwrap_used,
            reason = "we know that the policy ids are in the residuals map"
        )]
        self.residual_permits
            .iter()
            .map(|id| self.residuals.get(id).unwrap())
    }

    /// Get non-trivial forbid residual policies
    pub fn residual_forbids(&self) -> impl Iterator<Item = &ResidualPolicy> {
        #[expect(
            clippy::unwrap_used,
            reason = "we know that the policy ids are in the residuals map"
        )]
        self.residual_forbids
            .iter()
            .map(|id| self.residuals.get(id).unwrap())
    }

    /// Look up the [`Residual`] by [`PolicyID`]
    pub fn get_residual(&self, id: &PolicyID) -> Option<&Residual> {
        self.residuals.get(id).map(|rp| rp.residual.as_ref())
    }

    /// Attempt to get the authorization decision
    pub fn decision(&self) -> Option<Decision> {
        self.decision
    }

    /// Perform reauthorization
    pub fn reauthorize(
        &self,
        request: &Request,
        entities: &Entities,
    ) -> Result<crate::authorizer::Response, ReauthorizationError> {
        self.schema
            .validate_request(request, Extensions::all_available())?;
        let core_schema = CoreSchema::new(self.schema);
        let entities_checker =
            EntitySchemaConformanceChecker::new(&core_schema, Extensions::all_available());
        for entity in entities.iter() {
            entities_checker.validate_entity(entity)?;
        }
        self.entities.check_consistency(entities)?;
        self.request.check_consistency(request)?;

        let authorizer = Authorizer::new();
        #[expect(clippy::unwrap_used, reason = "policy ids should not clash")]
        Ok(authorizer.is_authorized(
            request.clone(),
            &PolicySet::try_from_iter(self.residuals.values().map(|rp| rp.clone().into())).unwrap(),
            entities,
        ))
    }

    /// Get residual policies
    pub fn residual_policies(&self) -> impl Iterator<Item = &ResidualPolicy> {
        self.residuals.values()
    }
}
