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
    ast::{Effect, Expr, Policy, PolicyID, PolicySet, Request, RequestSchema},
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
    decison: Option<Decision>,
    residuals: HashMap<PolicyID, ResidualPolicy>,
    // All of the [`Effect::Permit`] policies that were satisfied
    satisfied_permits: HashSet<PolicyID>,
    // All of the [`Effect::Permit`] policies that were not satisfied
    false_permits: HashSet<PolicyID>,
    // All of the [`Effect::Permit`] policies that evaluated to a residual
    non_trivial_permits: HashSet<PolicyID>,
    // All of the [`Effect::Forbid`] policies that were satisfied
    satisfied_forbids: HashSet<PolicyID>,
    // All of the [`Effect::Forbid`] policies that were not satisfied
    false_forbids: HashSet<PolicyID>,
    // All of the [`Effect::Forbid`] policies that evaluated to a residual
    non_trivial_forbids: HashSet<PolicyID>,
    // request
    request: &'a PartialRequest,
    // entities
    entities: &'a PartialEntities,
    // schema
    schema: &'a ValidatorSchema,
}

impl<'a> Response<'a> {
    /// Construct a [`Response`] from an iterator of [`ResidualPolicy`]s
    pub fn new(
        residuals: impl Iterator<Item = ResidualPolicy>,
        request: &'a PartialRequest,
        entities: &'a PartialEntities,
        schema: &'a ValidatorSchema,
    ) -> Self {
        let mut residual_map = HashMap::new();
        let mut satisfied_permits = HashSet::new();
        let mut false_permits = HashSet::new();
        let mut non_trivial_permits = HashSet::new();
        let mut satisfied_forbids = HashSet::new();
        let mut false_forbids = HashSet::new();
        let mut non_trivial_forbids = HashSet::new();
        for rp in residuals {
            let r = rp.get_residual();
            let id = rp.get_policy_id();
            residual_map.insert(id.clone(), rp.clone());
            match rp.get_effect() {
                Effect::Forbid => {
                    if r.is_true() {
                        satisfied_forbids.insert(id);
                    } else if r.is_false() {
                        false_forbids.insert(id);
                    } else {
                        non_trivial_forbids.insert(id);
                    }
                }
                Effect::Permit => {
                    if r.is_true() {
                        satisfied_permits.insert(id);
                    } else if r.is_false() {
                        false_permits.insert(id);
                    } else {
                        non_trivial_permits.insert(id);
                    }
                }
            }
        }
        let decison = if !satisfied_forbids.is_empty() {
            // there are satsified forbid policies, the decision must be a deny
            Some(Decision::Deny)
        } else if !non_trivial_forbids.is_empty() {
            // satisfied_forbids.is_empty && !non_trivial_forbids.is_empty()
            // there are residual forbid policies, we can't make any conclusive
            // authorization answer
            None
        } else if !satisfied_permits.is_empty() {
            // satisfied_forbids.is_empty && non_trivial_forbids.is_empty() && !satisfied_permits.is_empty()
            // all forbid policies are unsatisified, as long as there's one
            // permit policy, we can give an allow decision
            Some(Decision::Allow)
        } else if non_trivial_permits.is_empty() {
            // satisfied_forbids.is_empty && non_trivial_forbids.is_empty() && satisfied_permits.is_empty() && non_trivial_permits.is_empty()
            // there's no satisifed permit and no permit residual, in other
            // words, all permit residual policies are false, we can give a deny
            // decision
            Some(Decision::Deny)
        } else {
            // fallback option
            None
        };
        Self {
            decison,
            residuals: residual_map,
            satisfied_permits,
            false_permits,
            non_trivial_permits,
            satisfied_forbids,
            false_forbids,
            non_trivial_forbids,
            request,
            entities,
            schema,
        }
    }

    /// Get policy ids of satisified permit residual policies
    pub fn get_satisfied_permits(&self) -> impl Iterator<Item = &PolicyID> {
        self.satisfied_permits.iter()
    }

    /// Get policy ids of satisified forbid residual policies
    pub fn get_satisfied_forbids(&self) -> impl Iterator<Item = &PolicyID> {
        self.satisfied_forbids.iter()
    }

    /// Get policy ids of trivially false permit residual policies
    pub fn get_false_permits(&self) -> impl Iterator<Item = &PolicyID> {
        self.false_permits.iter()
    }

    /// Get policy ids of trivially false forbid residual policies
    pub fn get_false_forbids(&self) -> impl Iterator<Item = &PolicyID> {
        self.false_forbids.iter()
    }

    /// Get policy ids of non-trivial permit residual policies
    pub fn get_non_trival_permits(&self) -> impl Iterator<Item = &PolicyID> {
        self.non_trivial_permits.iter()
    }

    /// Get policy ids of non-trivial forbid residual policies
    pub fn get_non_trival_forbids(&self) -> impl Iterator<Item = &PolicyID> {
        self.non_trivial_forbids.iter()
    }

    /// Look up the [`Residual`] by [`PolicyID`]
    pub fn get_residual(&self, id: &PolicyID) -> Option<&Residual> {
        self.residuals.get(id).map(|rp| rp.residual.as_ref())
    }

    /// Attempt to get the authorization decision
    pub fn decision(&self) -> Option<Decision> {
        self.decison.clone()
    }

    /// Perform reauthorization
    pub fn reauthorize(
        &self,
        request: &Request,
        entities: &Entities,
    ) -> Result<crate::authorizer::Response, ReauthorizationError> {
        let _ = self
            .schema
            .validate_request(request, Extensions::all_available())?;
        let core_schema = CoreSchema::new(&self.schema);
        let entities_checker =
            EntitySchemaConformanceChecker::new(&core_schema, Extensions::all_available());
        for entity in entities.iter() {
            entities_checker.validate_entity(&entity)?;
        }
        let _ = self.entities.check_consistency(entities)?;
        let _ = self.request.check_consistency(request)?;
        let authorizer = Authorizer::new();
        // PANIC SAFETY: policy ids should not clash
        #[allow(clippy::unwrap_used)]
        Ok(authorizer.is_authorized(
            request.clone(),
            &PolicySet::try_from_iter(self.residuals.values().map(|rp| rp.clone().into())).unwrap(),
            entities,
        ))
    }
}
