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
    /// The residual expression remaining after partial evaluation.
    residual: Arc<Residual>,
    /// The original policy prior to partial evaluation.
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
    pub fn get_policy_id(&self) -> &PolicyID {
        self.policy.id()
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
    // All of the [`Effect::Permit`] policies that were true
    true_permits: HashSet<PolicyID>,
    // All of the [`Effect::Permit`] policies that were false
    false_permits: HashSet<PolicyID>,
    // All of the [`Effect::Permit`] policies that errored
    error_permits: HashSet<PolicyID>,
    // All of the [`Effect::Permit`] policies that evaluated to a residual
    residual_permits: HashSet<PolicyID>,
    // All of the [`Effect::Forbid`] policies that were true
    true_forbids: HashSet<PolicyID>,
    // All of the [`Effect::Forbid`] policies that were false
    false_forbids: HashSet<PolicyID>,
    // All of the [`Effect::Forbid`] policies that errored
    error_forbids: HashSet<PolicyID>,
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
        let mut true_permits = HashSet::new();
        let mut false_permits = HashSet::new();
        let mut error_permits = HashSet::new();
        let mut residual_permits = HashSet::new();
        let mut true_forbids = HashSet::new();
        let mut false_forbids = HashSet::new();
        let mut error_forbids = HashSet::new();
        let mut residual_forbids = HashSet::new();
        for rp in residuals {
            let r = rp.get_residual();
            let id = rp.get_policy_id();
            residual_map.insert(id.clone(), rp.clone());
            match rp.get_effect() {
                Effect::Forbid => {
                    if r.is_true() {
                        true_forbids.insert(id.clone());
                    } else if r.is_false() {
                        false_forbids.insert(id.clone());
                    } else if r.is_error() {
                        error_forbids.insert(id.clone());
                    } else {
                        residual_forbids.insert(id.clone());
                    }
                }
                Effect::Permit => {
                    if r.is_true() {
                        true_permits.insert(id.clone());
                    } else if r.is_false() {
                        false_permits.insert(id.clone());
                    } else if r.is_error() {
                        error_permits.insert(id.clone());
                    } else {
                        residual_permits.insert(id.clone());
                    }
                }
            }
        }

        let decision = match (
            !true_forbids.is_empty(),
            !true_permits.is_empty(),
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
            true_permits,
            false_permits,
            error_permits,
            residual_permits,
            true_forbids,
            false_forbids,
            error_forbids,
            residual_forbids,
            request,
            entities,
            schema,
        }
    }

    /// Get satisfied permit residual policies
    pub fn true_permits(&self) -> impl Iterator<Item = &ResidualPolicy> {
        #[expect(
            clippy::unwrap_used,
            reason = "we know that the policy ids are in the residuals map"
        )]
        self.true_permits
            .iter()
            .map(|id| self.residuals.get(id).unwrap())
    }

    /// Get satisfied forbid residual policies
    pub fn true_forbids(&self) -> impl Iterator<Item = &ResidualPolicy> {
        #[expect(
            clippy::unwrap_used,
            reason = "we know that the policy ids are in the residuals map"
        )]
        self.true_forbids
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

    /// Get trivially erroring permit residual policies
    pub fn error_permits(&self) -> impl Iterator<Item = &ResidualPolicy> {
        #[expect(
            clippy::unwrap_used,
            reason = "we know that the policy ids are in the residuals map"
        )]
        self.error_permits
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

    /// Get trivially erroring forbid residual policies
    pub fn error_forbids(&self) -> impl Iterator<Item = &ResidualPolicy> {
        #[expect(
            clippy::unwrap_used,
            reason = "we know that the policy ids are in the residuals map"
        )]
        self.error_forbids
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

    /// Look up the [`ResidualPolicy`] by [`PolicyID`]
    pub fn get_residual_policy(&self, id: &PolicyID) -> Option<&ResidualPolicy> {
        self.residuals.get(id)
    }

    /// Attempt to get the authorization decision
    pub fn decision(&self) -> Option<Decision> {
        self.decision
    }

    /// Get the determining policies for the authorization decision
    pub fn reason(&self) -> Option<impl Iterator<Item = &PolicyID>> {
        match self.decision? {
            Decision::Allow => Some(self.true_permits.iter()),
            Decision::Deny => Some(self.true_forbids.iter()),
        }
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
        Ok(authorizer.is_authorized(request.clone(), &self.policy_set(), entities))
    }

    /// Get all policies (including concrete true/false/error residuals)
    pub fn policies(&self) -> impl Iterator<Item = &ResidualPolicy> {
        self.residuals.values()
    }

    /// Get all policies (including concrete true/false/error residuals) as a `PolicySet`
    pub fn policy_set(&self) -> PolicySet {
        let mut ps = PolicySet::new();
        for p in self.policies() {
            #[expect(
                clippy::unwrap_used,
                reason = "`PolicySet::add` only fails on duplicate ids, but all residual policies will have unique ids"
            )]
            ps.add(p.clone().into()).unwrap()
        }
        ps
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};
    use std::sync::Arc;

    use crate::ast::{
        ActionConstraint, EntityUID, Policy, PolicySet, PrincipalConstraint, ResourceConstraint,
    };
    use crate::extensions::Extensions;
    use crate::parser::parse_policyset;
    use crate::tpe::entities::{PartialEntities, PartialEntity};
    use crate::tpe::is_authorized;
    use crate::tpe::request::{PartialEntityUID, PartialRequest};
    use crate::validator::ValidatorSchema;

    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
            namespace Auth {
              entity Group {};
              entity Role {};
              entity User in [Group] {};
              action "AssumeRole" appliesTo {
                principal: [Auth::User],
                resource: Auth::Role,
              };
            }
            "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    fn policies() -> PolicySet {
        parse_policyset(
            r#"
            @id("permit")
            permit(principal == Auth::User::"1", action == Auth::Action::"AssumeRole", resource);
            @id("forbid")
            forbid(principal, action == Auth::Action::"AssumeRole", resource == Auth::Role::"2");
            "#,
        )
        .unwrap()
    }

    fn request() -> PartialRequest {
        PartialRequest::new(
            r#"Auth::User::"1""#.parse::<EntityUID>().unwrap().into(),
            r#"Auth::Action::"AssumeRole""#.parse().unwrap(),
            // Unknown resource of type `Auth::Role`.
            PartialEntityUID {
                ty: "Auth::Role".parse().unwrap(),
                eid: None,
            },
            Some(Arc::new(BTreeMap::new())),
            &schema(),
        )
        .unwrap()
    }

    fn entities() -> PartialEntities {
        let schema = schema();
        PartialEntities::from_entities(
            [PartialEntity::new(
                r#"Auth::User::"1""#.parse().unwrap(),
                Some(BTreeMap::new()),
                Some(HashSet::new()),
                None,
                &schema,
            )
            .unwrap()]
            .into_iter(),
            &schema,
        )
        .unwrap()
    }

    #[track_caller]
    fn assert_scopes_unconstrained(policy: &Policy) {
        let t = policy.template();
        assert_eq!(
            t.principal_constraint(),
            &PrincipalConstraint::any(),
            "residual policy `{}` should have an unconstrained principal scope",
            policy.id()
        );
        assert_eq!(
            t.action_constraint(),
            &ActionConstraint::any(),
            "residual policy `{}` should have an unconstrained action scope",
            policy.id()
        );
        assert_eq!(
            t.resource_constraint(),
            &ResourceConstraint::any(),
            "residual policy `{}` should have an unconstrained resource scope",
            policy.id()
        );
    }

    #[test]
    fn policy_set_returns_residuals_not_originals() {
        let policies = policies();
        let schema = schema();
        let request = request();
        let entities = entities();

        let res = is_authorized(&policies, &request, &entities, &schema).unwrap();
        // With a concrete principal and an unknown resource, we can't decide.
        assert_eq!(res.decision(), None);

        let policy_set = res.policy_set();
        assert_eq!(policy_set.policies().count(), 2);

        for p in policy_set.policies() {
            assert_scopes_unconstrained(p);
        }
    }

    #[test]
    fn policy_set_matches_policies() {
        let policies = policies();
        let schema = schema();
        let request = request();
        let entities = entities();

        let res = is_authorized(&policies, &request, &entities, &schema).unwrap();

        let policy_set = res.policy_set();

        let mut expected = PolicySet::new();
        for p in res.policies() {
            expected.add(p.clone().into()).unwrap();
        }

        assert_eq!(policy_set.policies().count(), expected.policies().count());
        for expected_policy in expected.policies() {
            let actual = policy_set
                .get(expected_policy.id())
                .unwrap_or_else(|| panic!("missing policy `{}`", expected_policy.id()));
            assert_eq!(actual.effect(), expected_policy.effect());
            assert_eq!(
                actual.template().principal_constraint(),
                expected_policy.template().principal_constraint()
            );
            assert_eq!(
                actual.template().action_constraint(),
                expected_policy.template().action_constraint()
            );
            assert_eq!(
                actual.template().resource_constraint(),
                expected_policy.template().resource_constraint()
            );
            assert_eq!(actual.condition(), expected_policy.condition());
        }
    }
}
