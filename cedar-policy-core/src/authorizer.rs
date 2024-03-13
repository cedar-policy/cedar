/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

//! This module contains the Cedar "authorizer", which implements the actual
//! authorization logic.
//!
//! Together with the parser, evaluator, and other components, this comprises
//! the "authorization engine".

use crate::ast::*;
use crate::entities::Entities;
use crate::evaluator::{EvaluationError, Evaluator};
use crate::extensions::Extensions;
use itertools::Either;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::iter::once;

#[cfg(feature = "wasm")]
extern crate tsify;

mod err;
pub use err::AuthorizationError;

/// Authorizer
pub struct Authorizer {
    /// Cedar `Extension`s which will be used during requests to this `Authorizer`
    extensions: Extensions<'static>,
    /// Error-handling behavior of this `Authorizer`
    error_handling: ErrorHandling,
}

/// Describes the possible Cedar error-handling modes. Note that modes other than
/// `SkipOnError` are vestigial: the only official behavior is `SkipOnError`.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorHandling {
    /// Deny the entire request if _any_ policy encounters an evaluation error
    Deny,
    /// If a permit policy errors, skip it (implicit deny).  If a forbid policy
    /// errors, enforce it (explicit deny).
    Forbid,
    /// If a policy encounters an evaluation error, skip it.  The decision will
    /// be as if the erroring policy did not exist.
    Skip,
}

/// A potentially partial response from the authorizer
#[derive(Debug, Clone)]
pub enum ResponseKind {
    /// A fully evaluated response
    FullyEvaluated(Response),
    /// A response that has some residuals
    Partial(PartialResponse),
}

impl ResponseKind {
    /// The decision reached, if a decision could be reached
    pub fn decision(&self) -> Option<Decision> {
        match self {
            ResponseKind::FullyEvaluated(a) => Some(a.decision),
            ResponseKind::Partial(_) => None,
        }
    }
}

impl Default for ErrorHandling {
    fn default() -> Self {
        Self::Skip
    }
}

impl Authorizer {
    /// Create a new `Authorizer`
    pub fn new() -> Self {
        Self {
            extensions: Extensions::all_available(), // set at compile time
            error_handling: Default::default(),
        }
    }

    /// Returns an authorization response for `q` with respect to the given `Slice`.
    ///
    /// The language spec and formal model give a precise definition of how this is
    /// computed.
    pub fn is_authorized(&self, q: Request, pset: &PolicySet, entities: &Entities) -> Response {
        match self.is_authorized_core(q, pset, entities) {
            ResponseKind::FullyEvaluated(response) => response,
            ResponseKind::Partial(partial) => {
                // If we get a residual, we have to treat every residual policy as an error, and obey the error semantics.
                // This can result in an Accept in one case:
                // `error_handling` is `SkipOnerror`, no forbids evaluated to a concrete response, and some permits evaluated to `true`
                let mut errors = partial.diagnostics.errors;
                errors.extend(partial.residuals.policies().map(|p| {
                    AuthorizationError::PolicyEvaluationError {
                        id: p.id().clone(),
                        error: EvaluationError::non_value(p.condition()),
                    }
                }));

                let idset = partial.residuals.policies().map(|p| p.id().clone());

                match self.error_handling {
                    ErrorHandling::Deny => Response::new(
                        Decision::Deny,
                        idset.chain(partial.diagnostics.reason).collect(),
                        errors,
                    ),
                    ErrorHandling::Forbid => Response::new(
                        Decision::Deny,
                        idset.chain(partial.diagnostics.reason).collect(),
                        errors,
                    ),
                    ErrorHandling::Skip => {
                        // If there were satisfied permits in the residual, then skipping errors means returning `Allow`
                        // This is tricky logic, but it's correct as follows:
                        //  If any permit policy is in the diagnostics, it means it evaluated to a concrete `true` and was not overridden by a `forbid` policy
                        //  That means that all forbid policies evaluated to one of:
                        //    concrete `false`
                        //    concrete error
                        //    a residual (effectively concrete error).
                        // Thus all residuals should be `skipped`
                        // However, if all of the policies are `forbid`, then we still have to return `Deny`, likewise if the set is empty.

                        // PANIC SAFETY: every policy in the diagnostics had to come from the policy set
                        #[allow(clippy::unwrap_used)]
                        if partial
                            .diagnostics
                            .reason
                            .iter()
                            .any(|pid| pset.get(pid).unwrap().effect() == Effect::Permit)
                        {
                            Response::new(Decision::Allow, partial.diagnostics.reason, errors)
                        } else {
                            Response::new(
                                Decision::Deny,
                                idset.chain(partial.diagnostics.reason).collect(),
                                errors,
                            )
                        }
                    }
                }
            }
        }
    }

    /// Returns an authorization response for `q` with respect to the given `Slice`.
    /// Partial Evaluation of is_authorized
    ///
    /// The language spec and formal model give a precise definition of how this is
    /// computed.
    pub fn is_authorized_core(
        &self,
        q: Request,
        pset: &PolicySet,
        entities: &Entities,
    ) -> ResponseKind {
        let results = self.evaluate_policies_core(pset, q, entities);

        let errors = results
            .errors
            .into_iter()
            .map(|(pid, err)| AuthorizationError::PolicyEvaluationError {
                id: pid,
                error: err,
            })
            .collect();

        if !results.global_deny_policies.is_empty() {
            return ResponseKind::FullyEvaluated(Response::new(
                Decision::Deny,
                results.global_deny_policies,
                errors,
            ));
        }
        // Semantics ask for the set C_I^+ of all satisfied Permit policies
        // which override all satisfied Forbid policies. We call this set
        // `satisfied_permits`.
        // Notice that this currently differs from the semantics stated in the Language Spec,
        // which no longer consider overrides. The implementation is however equivalent,
        // since forbids always trump permits.
        let mut satisfied_permits = results
            .satisfied_permits
            .into_iter()
            .filter(|permit_p| {
                results
                    .satisfied_forbids
                    .iter()
                    .all(|forbid_p| Self::overrides(permit_p, forbid_p))
            })
            .peekable();

        match (
            satisfied_permits.peek().is_some(),
            !results.permit_residuals.is_empty(),
            !results.forbid_residuals.is_empty(),
        ) {
            // If we have a satisfied permit and _no_ residual forbids, we can return Allow (this is true regardless of residual permits)
            (true, false | true, false) => {
                let idset = satisfied_permits.map(|p| p.id().clone()).collect();
                ResponseKind::FullyEvaluated(Response::new(Decision::Allow, idset, errors))
            }
            // If we have a satisfied permit, and there are residual forbids, we must return a residual response. (this is true regardless of residual permits)
            (true, false | true, true) => {
                // `idset` is non-empty as `satisified_permits.peek().is_some()` is `true`
                let idset = satisfied_permits
                    .map(|p| p.id().clone())
                    .collect::<HashSet<_>>();
                // The residual will consist of all of the residual forbids, and one trivially true `permit`.
                // We will re-use one of the satisfied permits policy IDs to ensure uniqueness
                // PANIC SAFETY This `unwrap` is safe as `idset` is non-empty
                #[allow(clippy::unwrap_used)]
                let id = idset.iter().next().unwrap().clone(); // This unwrap is safe as we know there are satisfied permits
                let trivial_true = Policy::from_when_clause(Effect::Permit, Expr::val(true), id);
                // PANIC SAFETY Since all of the ids in the original policy set were unique by construction, a subset will still be unique
                #[allow(clippy::unwrap_used)]
                let policy_set = PolicySet::try_from_iter(
                    results
                        .forbid_residuals
                        .into_iter()
                        .chain(once(trivial_true)),
                )
                .unwrap();
                ResponseKind::Partial(PartialResponse::new(policy_set, idset, errors))
            }
            // If there are no satisfied permits, and no residual permits, then the request cannot succeed
            (false, false, false | true) => {
                let idset = results
                    .satisfied_forbids
                    .into_iter()
                    .map(|p| p.id().clone())
                    .collect();
                ResponseKind::FullyEvaluated(Response::new(Decision::Deny, idset, errors))
            }
            // If there are no satisfied permits, but residual permits, then request may still succeed. Return residual
            // Add in the forbid_residuals if any
            (false, true, false | true) => {
                // The request will definitely fail if there are satisfied forbids, check those
                if !results.satisfied_forbids.is_empty() {
                    let idset = results
                        .satisfied_forbids
                        .into_iter()
                        .map(|p| p.id().clone())
                        .collect();
                    ResponseKind::FullyEvaluated(Response::new(Decision::Deny, idset, errors))
                } else {
                    // No satisfied forbids
                    // PANIC SAFETY all policy IDs in the original policy are unique by construction
                    #[allow(clippy::unwrap_used)]
                    let all_residuals = PolicySet::try_from_iter(
                        [results.forbid_residuals, results.permit_residuals].concat(),
                    )
                    .unwrap();
                    ResponseKind::Partial(PartialResponse::new(
                        all_residuals,
                        HashSet::new(),
                        errors,
                    ))
                }
            }
        }
    }

    /// Returns a policy evaluation response for `q`.
    pub fn evaluate_policies(
        &self,
        pset: &PolicySet,
        q: Request,
        entities: &Entities,
    ) -> EvaluationResponse {
        let EvaluationResults {
            satisfied_permits,
            satisfied_forbids,
            global_deny_policies: _,
            errors,
            permit_residuals,
            forbid_residuals,
        } = self.evaluate_policies_core(pset, q, entities);

        let errors = errors
            .into_iter()
            .map(|(pid, err)| AuthorizationError::PolicyEvaluationError {
                id: pid,
                error: err,
            })
            .collect();

        let satisfied_permits = satisfied_permits.iter().map(|p| p.id().clone()).collect();
        let satisfied_forbids = satisfied_forbids.iter().map(|p| p.id().clone()).collect();

        // PANIC SAFETY all policy IDs in the original policy are unique by construction
        #[allow(clippy::unwrap_used)]
        let permit_residuals = PolicySet::try_from_iter(permit_residuals).unwrap();
        // PANIC SAFETY all policy IDs in the original policy are unique by construction
        #[allow(clippy::unwrap_used)]
        let forbid_residuals = PolicySet::try_from_iter(forbid_residuals).unwrap();

        EvaluationResponse {
            satisfied_permits,
            satisfied_forbids,
            errors,
            permit_residuals,
            forbid_residuals,
        }
    }

    fn evaluate_policies_core<'a>(
        &'a self,
        pset: &'a PolicySet,
        q: Request,
        entities: &Entities,
    ) -> EvaluationResults<'a> {
        let eval = Evaluator::new(q, entities, &self.extensions);
        let mut results = EvaluationResults::default();
        let mut satisfied_policies = vec![];

        for p in pset.policies() {
            match eval.partial_evaluate(p) {
                Ok(Either::Left(response)) => {
                    if response {
                        satisfied_policies.push(p)
                    }
                }
                Ok(Either::Right(residual)) => match p.effect() {
                    Effect::Permit => results.permit_residuals.push(Policy::from_when_clause(
                        p.effect(),
                        residual,
                        p.id().clone(),
                    )),
                    Effect::Forbid => results.forbid_residuals.push(Policy::from_when_clause(
                        p.effect(),
                        residual,
                        p.id().clone(),
                    )),
                },
                Err(e) => {
                    results.errors.push((p.id().clone(), e));
                    let satisfied = match self.error_handling {
                        ErrorHandling::Deny => {
                            results.global_deny_policies.insert(p.id().clone());
                            true
                        }
                        ErrorHandling::Forbid => match p.effect() {
                            Effect::Permit => false,
                            Effect::Forbid => true,
                        },
                        ErrorHandling::Skip => false,
                    };
                    if satisfied {
                        satisfied_policies.push(p);
                    }
                }
            };
        }

        let (satisfied_permits, satisfied_forbids) = satisfied_policies
            .iter()
            .partition(|p| p.effect() == Effect::Permit);

        results.satisfied_forbids = satisfied_forbids;
        results.satisfied_permits = satisfied_permits;

        results
    }

    /// Private helper function which determines if policy `p1` overrides policy
    /// `p2`.
    ///
    /// INVARIANT: p1 and p2 must have differing effects.
    /// This only makes sense to call with one `Permit` and one `Forbid` policy.
    /// If you call this with two `Permit`s or two `Forbid`s, this will panic.
    fn overrides(p1: &Policy, p2: &Policy) -> bool {
        // For now, we only support the default:
        // all Forbid policies override all Permit policies.
        // PANIC SAFETY p1 and p2s effect cannot be equal by invariant
        #[allow(clippy::unreachable)]
        match (p1.effect(), p2.effect()) {
            (Effect::Forbid, Effect::Permit) => true,
            (Effect::Permit, Effect::Forbid) => false,
            (Effect::Permit, Effect::Permit) => {
                unreachable!("Shouldn't call overrides() with two Permits")
            }
            (Effect::Forbid, Effect::Forbid) => {
                unreachable!("Shouldn't call overrides() with two Forbids")
            }
        }
    }
}

impl Default for Authorizer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
struct EvaluationResults<'a> {
    satisfied_permits: Vec<&'a Policy>,
    satisfied_forbids: Vec<&'a Policy>,
    global_deny_policies: HashSet<PolicyID>,
    errors: Vec<(PolicyID, EvaluationError)>,
    permit_residuals: Vec<Policy>,
    forbid_residuals: Vec<Policy>,
}

impl std::fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.extensions.ext_names().next().is_none() {
            write!(f, "<Authorizer with no extensions>")
        } else {
            write!(
                f,
                "<Authorizer with the following extensions: {:?}>",
                self.extensions.ext_names().collect::<Vec<_>>()
            )
        }
    }
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;
    use crate::ast::{Annotations, RequestSchemaAllPass};
    use crate::parser;

    /// Sanity unit test case for is_authorized.
    /// More robust testing is accomplished through the integration tests.
    #[test]
    fn authorizer_sanity_check_empty() {
        let a = Authorizer::new();
        let q = Request::new(
            (EntityUID::with_eid("p"), None),
            (EntityUID::with_eid("a"), None),
            (EntityUID::with_eid("r"), None),
            Context::empty(),
            None::<&RequestSchemaAllPass>,
            Extensions::none(),
        )
        .unwrap();
        let pset = PolicySet::new();
        let entities = Entities::new();
        let ans = a.is_authorized(q, &pset, &entities);
        assert_eq!(ans.decision, Decision::Deny);
    }

    /// Simple tests of skip-on-error semantics
    #[test]
    fn skip_on_error_tests() {
        let a = Authorizer::new();
        let q = Request::new(
            (EntityUID::with_eid("p"), None),
            (EntityUID::with_eid("a"), None),
            (EntityUID::with_eid("r"), None),
            Context::empty(),
            None::<&RequestSchemaAllPass>,
            Extensions::none(),
        )
        .unwrap();
        let mut pset = PolicySet::new();
        let entities = Entities::new();

        let p1_src = r#"
        permit(principal, action, resource);
        "#;

        let p2_src = r#"
        permit(principal, action, resource) when { context.bad == 2 };
        "#;

        let p3_src = r#"
        forbid(principal, action, resource) when { context.bad == 2 };
        "#;
        let p4_src = r#"
        forbid(principal, action, resource);
        "#;

        let p1 = parser::parse_policy(Some("1".into()), p1_src).unwrap();
        pset.add_static(p1).unwrap();

        let ans = a.is_authorized(q.clone(), &pset, &entities);
        assert_eq!(ans.decision, Decision::Allow);

        pset.add_static(parser::parse_policy(Some("2".into()), p2_src).unwrap())
            .unwrap();

        let ans = a.is_authorized(q.clone(), &pset, &entities);
        assert_eq!(ans.decision, Decision::Allow);

        pset.add_static(parser::parse_policy(Some("3".into()), p3_src).unwrap())
            .unwrap();

        let ans = a.is_authorized(q.clone(), &pset, &entities);
        assert_eq!(ans.decision, Decision::Allow);

        pset.add_static(parser::parse_policy(Some("4".into()), p4_src).unwrap())
            .unwrap();

        let ans = a.is_authorized(q, &pset, &entities);
        assert_eq!(ans.decision, Decision::Deny);
    }

    fn true_policy(id: &str, e: Effect) -> StaticPolicy {
        let pid = PolicyID::from_string(id);
        StaticPolicy::new(
            pid,
            Annotations::new(),
            e,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Expr::val(true),
        )
        .expect("Policy Creation Failed")
    }

    fn context_pol(id: &str, effect: Effect) -> StaticPolicy {
        let pid = PolicyID::from_string(id);
        StaticPolicy::new(
            pid,
            Annotations::new(),
            effect,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Expr::get_attr(Expr::var(Var::Context), "test".into()),
        )
        .expect("Policy Creation Failed")
    }

    #[test]
    fn authorizer_sanity_check_allow() {
        let a = Authorizer::new();
        let q = Request::new(
            (EntityUID::with_eid("p"), None),
            (EntityUID::with_eid("a"), None),
            (EntityUID::with_eid("r"), None),
            Context::empty(),
            None::<&RequestSchemaAllPass>,
            Extensions::none(),
        )
        .unwrap();
        let mut pset = PolicySet::new();
        pset.add_static(true_policy("0", Effect::Permit))
            .expect("Policy ID already in PolicySet");
        let entities = Entities::new();
        let ans = a.is_authorized(q, &pset, &entities);
        assert!(ans.decision == Decision::Allow);
    }

    #[test]
    fn authorizer_sanity_check_partial_deny() {
        let context = Context::from_expr(
            RestrictedExpr::record([(
                "test".into(),
                RestrictedExpr::unknown(Unknown::new_untyped("name")),
            )])
            .unwrap()
            .as_borrowed(),
            Extensions::none(),
        )
        .unwrap();
        let a = Authorizer::new();
        let q = Request::new(
            (EntityUID::with_eid("p"), None),
            (EntityUID::with_eid("a"), None),
            (EntityUID::with_eid("r"), None),
            context,
            None::<&RequestSchemaAllPass>,
            Extensions::none(),
        )
        .unwrap();
        let mut pset = PolicySet::new();
        pset.add_static(true_policy("0", Effect::Permit))
            .expect("Policy ID already in PolicySet");
        let entities = Entities::new();
        let ans = a.is_authorized(q.clone(), &pset, &entities);
        assert_eq!(ans.decision, Decision::Allow);
        pset.add_static(context_pol("1", Effect::Forbid))
            .expect("Policy ID overlap");
        let ans = a.is_authorized(q.clone(), &pset, &entities);
        assert_eq!(ans.decision, Decision::Allow);

        let mut pset = PolicySet::new();
        let entities = Entities::new();
        pset.add_static(context_pol("1", Effect::Forbid))
            .expect("Policy ID overlap");
        let ans = a.is_authorized(q.clone(), &pset, &entities);
        assert_eq!(ans.decision, Decision::Deny);

        let mut pset = PolicySet::new();
        let entities = Entities::new();
        pset.add_static(context_pol("1", Effect::Permit))
            .expect("Policy ID overlap");
        let ans = a.is_authorized(q, &pset, &entities);
        assert_eq!(ans.decision, Decision::Deny);
    }

    #[test]
    fn authorizer_sanity_check_deny() {
        let a = Authorizer::new();
        let q = Request::new(
            (EntityUID::with_eid("p"), None),
            (EntityUID::with_eid("a"), None),
            (EntityUID::with_eid("r"), None),
            Context::empty(),
            None::<&RequestSchemaAllPass>,
            Extensions::none(),
        )
        .unwrap();
        let mut pset = PolicySet::new();
        pset.add_static(true_policy("0", Effect::Permit))
            .expect("Policy ID already in PolicySet");
        pset.add_static(true_policy("1", Effect::Forbid))
            .expect("Policy ID already in PolicySet");
        let entities = Entities::new();
        let ans = a.is_authorized(q, &pset, &entities);
        assert!(ans.decision == Decision::Deny);
    }

    #[test]
    fn satisfied_permit_no_forbids() {
        let q = Request::new(
            (EntityUID::with_eid("p"), None),
            (EntityUID::with_eid("a"), None),
            (EntityUID::with_eid("r"), None),
            Context::empty(),
            None::<&RequestSchemaAllPass>,
            Extensions::none(),
        )
        .unwrap();
        let a = Authorizer::new();
        let mut pset = PolicySet::new();
        let es = Entities::new();

        let src1 = r#"
        permit(principal == test_entity_type::"p",action,resource);
        "#;
        let src2 = r#"
        forbid(principal == test_entity_type::"p",action,resource) when {
            false
        };
        "#;
        let src3 = r#"
        permit(principal == test_entity_type::"p",action,resource) when {
            unknown("test")
        };
        "#;

        pset.add_static(parser::parse_policy(Some("1".to_string()), src1).unwrap())
            .unwrap();
        pset.add_static(parser::parse_policy(Some("2".to_string()), src2).unwrap())
            .unwrap();

        let r = a.is_authorized_core(q.clone(), &pset, &es).decision();
        assert_eq!(r, Some(Decision::Allow));

        pset.add_static(parser::parse_policy(Some("3".to_string()), src3).unwrap())
            .unwrap();

        let r = a.is_authorized_core(q.clone(), &pset, &es).decision();
        assert_eq!(r, Some(Decision::Allow));

        let r = a.evaluate_policies(&pset, q, &es);
        assert!(r.satisfied_permits.contains(&PolicyID::from_string("1")));
        assert!(r.satisfied_forbids.is_empty());
        assert!(r
            .permit_residuals
            .get(&PolicyID::from_string("3"))
            .is_some());
        assert!(r.forbid_residuals.is_empty());
        assert!(r.errors.is_empty());
    }

    #[test]
    fn satisfied_permit_residual_forbid() {
        let q = Request::new(
            (EntityUID::with_eid("p"), None),
            (EntityUID::with_eid("a"), None),
            (EntityUID::with_eid("r"), None),
            Context::empty(),
            None::<&RequestSchemaAllPass>,
            Extensions::none(),
        )
        .unwrap();
        let a = Authorizer::new();
        let mut pset = PolicySet::new();
        let es = Entities::new();

        let src1 = r#"
        permit(principal,action,resource);
        "#;
        let src2 = r#"
        forbid(principal,action,resource) when {
            unknown("test")
        };
        "#;
        pset.add_static(parser::parse_policy(Some("1".to_string()), src1).unwrap())
            .unwrap();
        pset.add_static(parser::parse_policy(Some("2".to_string()), src2).unwrap())
            .unwrap();

        let r = a.is_authorized_core(q.clone(), &pset, &es);
        match r {
            ResponseKind::FullyEvaluated(_) => {
                panic!("Reached response, should have gotten residual.")
            }
            ResponseKind::Partial(p) => {
                let map = [("test".into(), Value::from(false))].into_iter().collect();
                let new = p.residuals.policies().map(|p| {
                    Policy::from_when_clause(
                        p.effect(),
                        p.condition().substitute(&map).unwrap(),
                        p.id().clone(),
                    )
                });
                let pset = PolicySet::try_from_iter(new).unwrap();
                let r = a.is_authorized(q.clone(), &pset, &es);
                assert_eq!(r.decision, Decision::Allow);

                let map = [("test".into(), Value::from(true))].into_iter().collect();
                let new = p.residuals.policies().map(|p| {
                    Policy::from_when_clause(
                        p.effect(),
                        p.condition().substitute(&map).unwrap(),
                        p.id().clone(),
                    )
                });
                let pset = PolicySet::try_from_iter(new).unwrap();
                let r = a.is_authorized(q.clone(), &pset, &es);
                assert_eq!(r.decision, Decision::Deny);
            }
        }

        let r = a.evaluate_policies(&pset, q, &es);
        assert!(r.satisfied_permits.contains(&PolicyID::from_string("1")));
        assert!(r.satisfied_forbids.is_empty());
        assert!(r.errors.is_empty());
        assert!(r.permit_residuals.is_empty());
        assert!(r
            .forbid_residuals
            .get(&PolicyID::from_string("2"))
            .is_some());
    }

    #[test]
    fn no_permits() {
        let q = Request::new(
            (EntityUID::with_eid("p"), None),
            (EntityUID::with_eid("a"), None),
            (EntityUID::with_eid("r"), None),
            Context::empty(),
            None::<&RequestSchemaAllPass>,
            Extensions::none(),
        )
        .unwrap();
        let a = Authorizer::new();
        let mut pset = PolicySet::new();
        let es = Entities::new();

        let r = a.is_authorized_core(q.clone(), &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));

        let src1 = r#"
        permit(principal, action, resource) when { false };
        "#;

        pset.add_static(parser::parse_policy(Some("1".into()), src1).unwrap())
            .unwrap();
        let r = a.is_authorized_core(q.clone(), &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));

        let src2 = r#"
        forbid(principal, action, resource) when { unknown("a") };
        "#;

        pset.add_static(parser::parse_policy(Some("2".into()), src2).unwrap())
            .unwrap();
        let r = a.is_authorized_core(q.clone(), &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));

        let src3 = r#"
        forbid(principal, action, resource) when { true };
        "#;
        let src4 = r#"
        permit(principal, action, resource) when { true };
        "#;

        pset.add_static(parser::parse_policy(Some("3".into()), src3).unwrap())
            .unwrap();
        pset.add_static(parser::parse_policy(Some("4".into()), src4).unwrap())
            .unwrap();
        let r = a.is_authorized_core(q.clone(), &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));

        let r = a.evaluate_policies(&pset, q, &es);
        assert!(r.satisfied_permits.contains(&PolicyID::from_string("4")));
        assert!(r.satisfied_forbids.contains(&PolicyID::from_string("3")));
        assert!(r.errors.is_empty());
        assert!(r.permit_residuals.is_empty());
        assert!(r
            .forbid_residuals
            .get(&PolicyID::from_string("2"))
            .is_some());
    }

    #[test]
    fn residual_permits() {
        let q = Request::new(
            (EntityUID::with_eid("p"), None),
            (EntityUID::with_eid("a"), None),
            (EntityUID::with_eid("r"), None),
            Context::empty(),
            None::<&RequestSchemaAllPass>,
            Extensions::none(),
        )
        .unwrap();
        let a = Authorizer::new();
        let mut pset = PolicySet::new();
        let es = Entities::new();

        let src1 = r#"
        permit(principal, action, resource) when { false };
        "#;
        let src2 = r#"
        permit(principal, action, resource) when { unknown("a") };
        "#;
        let src3 = r#"
        forbid(principal, action, resource) when { true };
        "#;

        pset.add_static(parser::parse_policy(Some("1".into()), src1).unwrap())
            .unwrap();
        pset.add_static(parser::parse_policy(Some("2".into()), src2).unwrap())
            .unwrap();

        let r = a.is_authorized_core(q.clone(), &pset, &es);
        match r {
            ResponseKind::FullyEvaluated(_) => {
                panic!("Reached response, should have gotten residual.")
            }
            ResponseKind::Partial(p) => {
                let map = [("a".into(), Value::from(false))].into_iter().collect();
                let new = p.residuals.policies().map(|p| {
                    Policy::from_when_clause(
                        p.effect(),
                        p.condition().substitute(&map).unwrap(),
                        p.id().clone(),
                    )
                });
                let pset = PolicySet::try_from_iter(new).unwrap();
                let r = a.is_authorized(q.clone(), &pset, &es);
                assert_eq!(r.decision, Decision::Deny);

                let map = [("a".into(), Value::from(true))].into_iter().collect();
                let new = p.residuals.policies().map(|p| {
                    Policy::from_when_clause(
                        p.effect(),
                        p.condition().substitute(&map).unwrap(),
                        p.id().clone(),
                    )
                });
                let pset = PolicySet::try_from_iter(new).unwrap();
                let r = a.is_authorized(q.clone(), &pset, &es);
                assert_eq!(r.decision, Decision::Allow);
            }
        }

        pset.add_static(parser::parse_policy(Some("3".into()), src3).unwrap())
            .unwrap();
        let r = a.is_authorized_core(q.clone(), &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));

        let r = a.evaluate_policies(&pset, q, &es);
        assert!(r.satisfied_permits.is_empty());
        assert!(r.satisfied_forbids.contains(&PolicyID::from_string("3")));
        assert!(r.errors.is_empty());
        assert!(r
            .permit_residuals
            .get(&PolicyID::from_string("2"))
            .is_some());
        assert!(r.forbid_residuals.is_empty());
    }
}
// by default, Coverlay does not track coverage for lines after a line
// containing #[cfg(test)].
// we use the following sentinel to "turn back on" coverage tracking for
// remaining lines of this file, until the next #[cfg(test)]
// GRCOV_BEGIN_COVERAGE

/// Authorization response returned from the `Authorizer`
#[derive(Debug, PartialEq, Clone)]
pub struct Response {
    /// Authorization decision
    pub decision: Decision,
    /// Diagnostics providing more information on how this decision was reached
    pub diagnostics: Diagnostics,
}

/// Response that may contain a residual.
#[derive(Debug, PartialEq, Clone)]
pub struct PartialResponse {
    /// Residual policies
    pub residuals: PolicySet,
    /// Diagnostics providing info
    pub diagnostics: Diagnostics,
}

impl PartialResponse {
    /// Create a partial response with a residual PolicySet
    pub fn new(
        pset: PolicySet,
        reason: HashSet<PolicyID>,
        errors: Vec<AuthorizationError>,
    ) -> Self {
        PartialResponse {
            residuals: pset,
            diagnostics: Diagnostics { reason, errors },
        }
    }
}

/// Policy evaluation response returned from the `Authorizer`.
#[derive(Debug, PartialEq, Clone)]
pub struct EvaluationResponse {
    /// `PolicyID`s of the fully evaluated policies with a permit [`Effect`].
    pub satisfied_permits: HashSet<PolicyID>,
    /// `PolicyID`s of the fully evaluated policies with a forbid [`Effect`].
    pub satisfied_forbids: HashSet<PolicyID>,
    /// List of errors that occurred
    pub errors: Vec<AuthorizationError>,
    /// Residual policies with a permit [`Effect`].
    pub permit_residuals: PolicySet,
    /// Residual policies with a forbid [`Effect`].
    pub forbid_residuals: PolicySet,
}

/// Diagnostics providing more information on how a `Decision` was reached
#[derive(Debug, PartialEq, Clone)]
pub struct Diagnostics {
    /// `PolicyID`s of the policies that contributed to the decision. If no
    /// policies applied to the request, this set will be empty.
    pub reason: HashSet<PolicyID>,
    /// List of errors that occurred
    pub errors: Vec<AuthorizationError>,
}

impl Response {
    /// Create a new `Response`
    pub fn new(
        decision: Decision,
        reason: HashSet<PolicyID>,
        errors: Vec<AuthorizationError>,
    ) -> Self {
        Response {
            decision,
            diagnostics: Diagnostics { reason, errors },
        }
    }
}

/// Decision returned from the `Authorizer`
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum Decision {
    /// The `Authorizer` determined that the request should be allowed
    Allow,
    /// The `Authorizer` determined that the request should be denied.
    /// This is also returned if sufficiently fatal errors are encountered such
    /// that no decision could be safely reached; for example, errors parsing
    /// the policies.
    Deny,
}
