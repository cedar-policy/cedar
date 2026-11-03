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

//! This module contains the Cedar "authorizer", which implements the actual
//! authorization logic.
//!
//! Together with the parser, evaluator, and other components, this comprises
//! the "authorization engine".

use crate::ast::*;
use crate::entities::Entities;
use crate::evaluator::Evaluator;
use crate::extensions::Extensions;
use itertools::{Either, Itertools};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

#[cfg(feature = "wasm")]
extern crate tsify;

mod err;
mod partial_response;
pub use err::{AuthorizationError, ConcretizationError, ReauthorizationError};

pub use partial_response::ErrorState;
pub use partial_response::PartialResponse;

/// Authorizer
#[derive(Clone)] // `Debug` implemented manually below
pub struct Authorizer {
    /// Cedar `Extension`s which will be used during requests to this `Authorizer`
    extensions: &'static Extensions<'static>,
    /// Error-handling behavior of this `Authorizer`
    error_handling: ErrorHandling,
}

/// Describes the possible Cedar error-handling modes.
/// We currently only have one mode: [`ErrorHandling::Skip`].
/// Other modes were debated during development, so this is here as an easy
/// way to add modes if the future if we so decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ErrorHandling {
    /// If a policy encounters an evaluation error, skip it.  The decision will
    /// be as if the erroring policy did not exist.
    #[default]
    Skip,
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
        let eval = Evaluator::new(q.clone(), entities, self.extensions);
        match self.is_authorized_concrete(&eval, pset) {
            Some(response) => response,
            // Some policy evaluated to a residual. `PartialResponse` defines
            // the response in that case, so evaluate the whole request again
            // on that path.
            None => self
                .is_authorized_core_internal(&eval, q, pset)
                .concretize(),
        }
    }

    /// Compute the [`Response`] for the request in `eval` without building a
    /// [`PartialResponse`]: only the satisfied policies and the evaluation
    /// errors are recorded, and nothing is recorded for a policy that
    /// evaluates to `false`.
    ///
    /// Returns `None` if any policy evaluates to a residual. Otherwise the
    /// result is equal to concretizing the [`PartialResponse`] for the same
    /// request. In particular, the errors are in the order of
    /// [`PolicySet::policies`], which is the order in which
    /// [`Authorizer::is_authorized_core`] collects them.
    fn is_authorized_concrete(&self, eval: &Evaluator<'_>, pset: &PolicySet) -> Option<Response> {
        let mut satisfied_permits = vec![];
        let mut satisfied_forbids = vec![];
        let mut errors = vec![];

        for p in pset.policies() {
            match eval.partial_evaluate(p) {
                Ok(Either::Left(true)) => match p.effect() {
                    Effect::Permit => satisfied_permits.push(p.id()),
                    Effect::Forbid => satisfied_forbids.push(p.id()),
                },
                Ok(Either::Left(false)) => {}
                Ok(Either::Right(_)) => return None,
                Err(error) => {
                    errors.push(AuthorizationError::PolicyEvaluationError {
                        id: p.id().clone(),
                        error,
                    });
                    match self.error_handling {
                        // the erroring policy is not satisfied
                        ErrorHandling::Skip => {}
                    }
                }
            }
        }

        // A satisfied forbid overrides every permit, and then the forbids are
        // the reason for the decision. With no satisfied policy the request
        // is denied for no reason.
        let (decision, reason) = if !satisfied_forbids.is_empty() {
            (Decision::Deny, satisfied_forbids)
        } else if satisfied_permits.is_empty() {
            (Decision::Deny, vec![])
        } else {
            (Decision::Allow, satisfied_permits)
        };
        Some(Response::new(
            decision,
            reason.into_iter().cloned().collect(),
            errors,
        ))
    }

    /// Returns an authorization response for `q` with respect to the given `Slice`.
    /// Partial Evaluation of is_authorized
    ///
    pub fn is_authorized_core(
        &self,
        q: Request,
        pset: &PolicySet,
        entities: &Entities,
    ) -> PartialResponse {
        let eval = Evaluator::new(q.clone(), entities, self.extensions);
        self.is_authorized_core_internal(&eval, q, pset)
    }

    /// The same as is_authorized_core, but for any Evaluator.
    /// A PartialResponse caller constructs its own evaluator, with an unknown mapper function.
    pub(crate) fn is_authorized_core_internal(
        &self,
        eval: &Evaluator<'_>,
        q: Request,
        pset: &PolicySet,
    ) -> PartialResponse {
        let mut true_permits = vec![];
        let mut true_forbids = vec![];
        let mut false_permits = vec![];
        let mut false_forbids = vec![];
        let mut residual_permits = vec![];
        let mut residual_forbids = vec![];
        let mut errors = vec![];

        for p in pset.policies() {
            let (id, annotations) = (p.id().clone(), p.annotations_arc().clone());
            match eval.partial_evaluate(p) {
                Ok(Either::Left(satisfied)) => match (satisfied, p.effect()) {
                    (true, Effect::Permit) => true_permits.push((id, annotations)),
                    (true, Effect::Forbid) => true_forbids.push((id, annotations)),
                    (false, Effect::Permit) => {
                        false_permits.push((id, (ErrorState::NoError, annotations)))
                    }
                    (false, Effect::Forbid) => {
                        false_forbids.push((id, (ErrorState::NoError, annotations)))
                    }
                },
                Ok(Either::Right(residual)) => match p.effect() {
                    Effect::Permit => {
                        residual_permits.push((id, (Arc::new(residual), annotations)))
                    }
                    Effect::Forbid => {
                        residual_forbids.push((id, (Arc::new(residual), annotations)))
                    }
                },
                Err(e) => {
                    errors.push(AuthorizationError::PolicyEvaluationError {
                        id: id.clone(),
                        error: e,
                    });
                    let satisfied = match self.error_handling {
                        ErrorHandling::Skip => false,
                    };
                    match (satisfied, p.effect()) {
                        (true, Effect::Permit) => true_permits.push((id, annotations)),
                        (true, Effect::Forbid) => true_forbids.push((id, annotations)),
                        (false, Effect::Permit) => {
                            false_permits.push((id, (ErrorState::Error, annotations)))
                        }
                        (false, Effect::Forbid) => {
                            false_forbids.push((id, (ErrorState::Error, annotations)))
                        }
                    }
                }
            };
        }

        PartialResponse::new(
            true_permits,
            false_permits,
            residual_permits,
            true_forbids,
            false_forbids,
            residual_forbids,
            errors,
            Arc::new(q),
        )
    }
}

impl Default for Authorizer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.extensions.ext_names().next().is_none() {
            write!(f, "<Authorizer with no extensions>")
        } else {
            write!(
                f,
                "<Authorizer with the following extensions: [{}]>",
                self.extensions.ext_names().join(", ")
            )
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ast::Annotations;
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

        let p1 = parser::parse_policy(Some(PolicyID::from_string("1")), p1_src).unwrap();
        pset.add_static(p1).unwrap();

        let ans = a.is_authorized(q.clone(), &pset, &entities);
        assert_eq!(ans.decision, Decision::Allow);

        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("2")), p2_src).unwrap())
            .unwrap();

        let ans = a.is_authorized(q.clone(), &pset, &entities);
        assert_eq!(ans.decision, Decision::Allow);

        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("3")), p3_src).unwrap())
            .unwrap();

        let ans = a.is_authorized(q.clone(), &pset, &entities);
        assert_eq!(ans.decision, Decision::Allow);

        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("4")), p4_src).unwrap())
            .unwrap();

        let ans = a.is_authorized(q, &pset, &entities);
        assert_eq!(ans.decision, Decision::Deny);
    }

    fn true_policy(id: &str, e: Effect) -> StaticPolicy {
        let pid = PolicyID::from_string(id);
        StaticPolicy::new(
            pid,
            None,
            Annotations::new(),
            e,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            None,
        )
        .expect("Policy Creation Failed")
    }

    #[cfg(feature = "partial-eval")]
    fn context_pol(id: &str, effect: Effect) -> StaticPolicy {
        let pid = PolicyID::from_string(id);
        StaticPolicy::new(
            pid,
            None,
            Annotations::new(),
            effect,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Some(Expr::get_attr(Expr::var(Var::Context), "test".into())),
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
    #[cfg(feature = "partial-eval")]
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

        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("1")), src1).unwrap())
            .unwrap();
        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("2")), src2).unwrap())
            .unwrap();

        let r = a.is_authorized_core(q, &pset, &es).decision();
        assert_eq!(r, Some(Decision::Allow));
    }

    #[test]
    #[cfg(feature = "partial-eval")]
    fn satisfied_permit_no_forbids_unknown() {
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

        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("1")), src1).unwrap())
            .unwrap();
        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("2")), src2).unwrap())
            .unwrap();

        let r = a.is_authorized_core(q.clone(), &pset, &es).decision();
        assert_eq!(r, Some(Decision::Allow));

        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("3")), src3).unwrap())
            .unwrap();

        let r = a.is_authorized_core(q.clone(), &pset, &es).decision();
        assert_eq!(r, Some(Decision::Allow));

        let r = a.is_authorized_core(q, &pset, &es);
        assert!(r
            .satisfied_permits
            .contains_key(&PolicyID::from_string("1")));
        assert!(r.satisfied_forbids.is_empty());
        assert!(r.residual_permits.contains_key(&PolicyID::from_string("3")));
        assert!(r.residual_forbids.is_empty());
        assert!(r.errors.is_empty());
    }

    #[test]
    #[cfg(feature = "partial-eval")]
    fn satisfied_permit_residual_forbid() {
        use std::collections::HashMap;

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
        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("1")), src1).unwrap())
            .unwrap();
        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("2")), src2).unwrap())
            .unwrap();

        let r = a.is_authorized_core(q.clone(), &pset, &es);
        let map = HashMap::from([("test".into(), Value::from(false))]);
        let r2: Response = r.reauthorize(&map, &a, &es).unwrap().into();
        assert_eq!(r2.decision, Decision::Allow);
        drop(r2);

        let map = HashMap::from([("test".into(), Value::from(true))]);
        let r2: Response = r.reauthorize(&map, &a, &es).unwrap().into();
        assert_eq!(r2.decision, Decision::Deny);

        let r = a.is_authorized_core(q, &pset, &es);
        assert!(r
            .satisfied_permits
            .contains_key(&PolicyID::from_string("1")));
        assert!(r.satisfied_forbids.is_empty());
        assert!(r.errors.is_empty());
        assert!(r.residual_permits.is_empty());
        assert!(r.residual_forbids.contains_key(&PolicyID::from_string("2")));
    }

    #[test]
    #[cfg(feature = "partial-eval")]
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

        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("1")), src1).unwrap())
            .unwrap();
        let r = a.is_authorized_core(q.clone(), &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));

        let src2 = r#"
        forbid(principal, action, resource) when { unknown("a") };
        "#;

        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("2")), src2).unwrap())
            .unwrap();
        let r = a.is_authorized_core(q.clone(), &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));

        let src3 = r#"
        forbid(principal, action, resource) when { true };
        "#;
        let src4 = r#"
        permit(principal, action, resource) when { true };
        "#;

        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("3")), src3).unwrap())
            .unwrap();
        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("4")), src4).unwrap())
            .unwrap();
        let r = a.is_authorized_core(q.clone(), &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));

        let r = a.is_authorized_core(q, &pset, &es);
        assert!(r
            .satisfied_permits
            .contains_key(&PolicyID::from_string("4")));
        assert!(r
            .satisfied_forbids
            .contains_key(&PolicyID::from_string("3")));
        assert!(r.errors.is_empty());
        assert!(r.residual_permits.is_empty());
        assert!(r.residual_forbids.contains_key(&PolicyID::from_string("2")));
    }

    #[test]
    #[cfg(feature = "partial-eval")]
    fn residual_permits() {
        use std::collections::HashMap;

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

        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("1")), src1).unwrap())
            .unwrap();
        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("2")), src2).unwrap())
            .unwrap();

        let r = a.is_authorized_core(q.clone(), &pset, &es);
        let map = HashMap::from([("a".into(), Value::from(false))]);
        let r2: Response = r.reauthorize(&map, &a, &es).unwrap().into();
        assert_eq!(r2.decision, Decision::Deny);

        let map = HashMap::from([("a".into(), Value::from(true))]);
        let r2: Response = r.reauthorize(&map, &a, &es).unwrap().into();
        assert_eq!(r2.decision, Decision::Allow);

        pset.add_static(parser::parse_policy(Some(PolicyID::from_string("3")), src3).unwrap())
            .unwrap();
        let r = a.is_authorized_core(q.clone(), &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));

        let r = a.is_authorized_core(q, &pset, &es);
        assert!(r.satisfied_permits.is_empty());
        assert!(r
            .satisfied_forbids
            .contains_key(&PolicyID::from_string("3")));
        assert!(r.errors.is_empty());
        assert!(r.residual_permits.contains_key(&PolicyID::from_string("2")));
        assert!(r.residual_forbids.is_empty());
    }
}

/// Authorization response returned from the `Authorizer`
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Response {
    /// Authorization decision
    pub decision: Decision,
    /// Diagnostics providing more information on how this decision was reached
    pub diagnostics: Diagnostics,
}

/// Policy evaluation response returned from the `Authorizer`.
#[derive(Debug, PartialEq, Eq, Clone)]
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
#[derive(Debug, PartialEq, Eq, Clone)]
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
#[serde(rename_all = "camelCase")]
pub enum Decision {
    /// The `Authorizer` determined that the request should be allowed
    Allow,
    /// The `Authorizer` determined that the request should be denied.
    /// This is also returned if sufficiently fatal errors are encountered such
    /// that no decision could be safely reached; for example, errors parsing
    /// the policies.
    Deny,
}

/// Tests that [`Authorizer::is_authorized`] returns exactly the [`Response`]
/// that concretizing the [`PartialResponse`] for the same request returns.
#[cfg(test)]
mod differential_tests {
    use super::*;
    use crate::entities::{EntityJsonParser, NoEntitiesSchema, TCComputation};
    use crate::parser;
    use cool_asserts::assert_matches;
    use std::collections::HashMap;

    /// Policies with every kind of scope constraint, each matching some of
    /// the requests of [`requests`] and not others; forbids; policies whose
    /// `when` clause errors; and three templates.
    const POLICIES: &str = r#"
        permit(principal, action, resource);
        permit(principal == User::"alice", action, resource);
        permit(principal == User::"bob", action, resource);
        permit(principal in Group::"admins", action, resource);
        permit(principal in Group::"staff", action, resource);
        permit(principal in User::"ghost", action, resource);
        permit(principal is User, action, resource);
        permit(principal is Service, action, resource);
        permit(principal is User in Group::"admins", action, resource);
        permit(principal is Service in Group::"admins", action, resource);
        permit(principal, action == Action::"view", resource);
        permit(principal, action == Action::"edit", resource);
        permit(principal, action in [Action::"view", Action::"edit"], resource);
        permit(principal, action in [Action::"readOnly"], resource);
        permit(principal, action in Action::"readOnly", resource);
        permit(principal, action in [], resource);
        permit(principal, action == Action::"absent", resource);
        permit(principal, action in [Action::"absent"], resource);
        permit(principal, action, resource == Doc::"d1");
        permit(principal, action, resource in Folder::"f1");
        permit(principal, action, resource in Folder::"f2");
        permit(principal, action, resource is Doc);
        permit(principal, action, resource is Doc in Folder::"f2");
        permit(principal == User::"alice", action == Action::"view", resource == Doc::"d1");
        permit(principal == User::"alice", action == Action::"edit", resource == Doc::"d2")
            when { context.missing };
        forbid(principal, action == Action::"delete", resource);
        forbid(principal == User::"mallory", action, resource);
        forbid(principal, action, resource) when { resource.locked };
        forbid(principal, action == Action::"edit", resource) unless { context.mfa };
        permit(principal, action, resource is Folder) when { context.missing == 1 };
        permit(principal == User::"bob", action, resource) when { 1 + "a" == 2 };
        permit(principal, action == Action::"edit", resource) when { principal.level > 3 };
        permit(principal == ?principal, action, resource in ?resource);
        forbid(principal in ?principal, action == Action::"edit", resource == ?resource);
        permit(principal == ?principal, action in [Action::"readOnly"], resource)
            when { resource.locked };
    "#;

    /// `User::"ghost"`, `Action::"absent"` and `Doc::"absent"` are used in
    /// requests but are not in the store. `Action::"view"` is in
    /// `Action::"readOnly"`.
    const ENTITIES: &str = r#"[
        {"uid": {"type": "User", "id": "alice"}, "attrs": {"level": 5},
         "parents": [{"type": "Group", "id": "admins"}]},
        {"uid": {"type": "User", "id": "bob"}, "attrs": {"level": 1},
         "parents": [{"type": "Group", "id": "staff"}]},
        {"uid": {"type": "User", "id": "mallory"}, "attrs": {}, "parents": []},
        {"uid": {"type": "Service", "id": "svc"}, "attrs": {},
         "parents": [{"type": "Group", "id": "admins"}]},
        {"uid": {"type": "Group", "id": "admins"}, "attrs": {},
         "parents": [{"type": "Group", "id": "staff"}]},
        {"uid": {"type": "Group", "id": "staff"}, "attrs": {}, "parents": []},
        {"uid": {"type": "Doc", "id": "d1"}, "attrs": {"locked": false},
         "parents": [{"type": "Folder", "id": "f1"}]},
        {"uid": {"type": "Doc", "id": "d2"}, "attrs": {"locked": true},
         "parents": [{"type": "Folder", "id": "f2"}]},
        {"uid": {"type": "Doc", "id": "d3"}, "attrs": {}, "parents": []},
        {"uid": {"type": "Folder", "id": "f1"}, "attrs": {"locked": false},
         "parents": [{"type": "Folder", "id": "f2"}]},
        {"uid": {"type": "Folder", "id": "f2"}, "attrs": {"locked": false}, "parents": []},
        {"uid": {"type": "Action", "id": "view"}, "attrs": {},
         "parents": [{"type": "Action", "id": "readOnly"}]},
        {"uid": {"type": "Action", "id": "edit"}, "attrs": {}, "parents": []},
        {"uid": {"type": "Action", "id": "delete"}, "attrs": {}, "parents": []},
        {"uid": {"type": "Action", "id": "readOnly"}, "attrs": {}, "parents": []}
    ]"#;

    fn uid(ty: &str, eid: &str) -> EntityUID {
        EntityUID::with_eid_and_type(ty, eid).expect("valid entity type")
    }

    /// The policies of [`POLICIES`], with each of the three templates linked
    /// four times, to different principals and resources.
    fn policy_set() -> PolicySet {
        let mut pset = parser::parse_policyset(POLICIES).expect("policies parse");
        let templates: Vec<(PolicyID, Vec<SlotId>)> = pset
            .templates()
            .map(|t| (t.id().clone(), t.slots().map(|slot| slot.id).collect()))
            .collect();
        assert_eq!(templates.len(), 3);
        let bindings = [
            (uid("User", "alice"), uid("Folder", "f2")),
            (uid("User", "bob"), uid("Folder", "f1")),
            (uid("Group", "staff"), uid("Doc", "d1")),
            (uid("Group", "admins"), uid("Doc", "d3")),
        ];
        for (t, (id, slots)) in templates.iter().enumerate() {
            for (l, (principal, resource)) in bindings.iter().enumerate() {
                let values: HashMap<SlotId, EntityUID> = slots
                    .iter()
                    .map(|slot| {
                        if slot.is_principal() {
                            (*slot, principal.clone())
                        } else {
                            (*slot, resource.clone())
                        }
                    })
                    .collect();
                pset.link(
                    id.clone(),
                    PolicyID::from_string(format!("link-{t}-{l}")),
                    values,
                )
                .expect("linking succeeds");
            }
        }
        pset
    }

    fn entities() -> Entities {
        EntityJsonParser::new(
            None::<&NoEntitiesSchema>,
            Extensions::all_available(),
            TCComputation::ComputeNow,
        )
        .from_json_str(ENTITIES)
        .expect("entities parse")
    }

    /// Every combination of six principals, five actions, six resources and
    /// three contexts.
    fn requests() -> Vec<Request> {
        let principals = [
            uid("User", "alice"),
            uid("User", "bob"),
            uid("User", "mallory"),
            uid("User", "ghost"),
            uid("Service", "svc"),
            uid("Group", "admins"),
        ];
        let actions = [
            uid("Action", "view"),
            uid("Action", "edit"),
            uid("Action", "delete"),
            uid("Action", "readOnly"),
            uid("Action", "absent"),
        ];
        let resources = [
            uid("Doc", "d1"),
            uid("Doc", "d2"),
            uid("Doc", "d3"),
            uid("Doc", "absent"),
            uid("Folder", "f1"),
            uid("Folder", "f2"),
        ];
        let contexts = [r#"{"mfa": true}"#, r#"{"mfa": false}"#, "{}"];
        let mut requests = vec![];
        for principal in &principals {
            for action in &actions {
                for resource in &resources {
                    for context in contexts {
                        requests.push(
                            Request::new(
                                (principal.clone(), None),
                                (action.clone(), None),
                                (resource.clone(), None),
                                Context::from_json_str(context).expect("context parses"),
                                None::<&RequestSchemaAllPass>,
                                Extensions::all_available(),
                            )
                            .expect("request is valid"),
                        );
                    }
                }
            }
        }
        requests
    }

    /// Assert that `is_authorized` returns what concretizing the
    /// `PartialResponse` returns for `q`, and return that response.
    #[track_caller]
    fn assert_agrees(q: &Request, pset: &PolicySet, entities: &Entities) -> Response {
        let a = Authorizer::new();
        let direct = a.is_authorized(q.clone(), pset, entities);
        let reference = a.is_authorized_core(q.clone(), pset, entities).concretize();
        assert_eq!(direct, reference, "responses differ for {q}");
        direct
    }

    #[test]
    fn agrees_with_partial_response() {
        let pset = policy_set();
        let entities = entities();
        let (mut allows, mut forbidden, mut with_errors) = (0, 0, 0);
        let mut most_errors = 0;
        for q in requests() {
            let response = assert_agrees(&q, &pset, &entities);
            match response.decision {
                Decision::Allow => allows += 1,
                Decision::Deny => {
                    assert!(
                        !response.diagnostics.reason.is_empty(),
                        "the first policy permits every request, so only a forbid denies {q}"
                    );
                    forbidden += 1;
                }
            }
            with_errors += usize::from(!response.diagnostics.errors.is_empty());
            most_errors = most_errors.max(response.diagnostics.errors.len());
        }
        // the requests exercise each kind of response
        assert!(allows > 0 && forbidden > 0 && with_errors > 0);
        assert!(
            most_errors >= 3,
            "some request has several erroring policies"
        );
    }

    #[test]
    fn agrees_when_no_policy_is_satisfied() {
        let pset = parser::parse_policyset(
            r#"
            permit(principal == User::"alice", action == Action::"view", resource);
            permit(principal, action, resource) when { context.missing };
            forbid(principal, action, resource) when { resource.locked };
        "#,
        )
        .expect("policies parse");
        let entities = entities();
        let mut default_denies = 0;
        for q in requests() {
            let response = assert_agrees(&q, &pset, &entities);
            default_denies += usize::from(
                response.decision == Decision::Deny && response.diagnostics.reason.is_empty(),
            );
        }
        assert!(default_denies > 0);

        let q = requests().swap_remove(0);
        let response = assert_agrees(&q, &PolicySet::new(), &entities);
        assert_eq!(response.decision, Decision::Deny);
    }

    #[test]
    fn errors_are_in_policy_order() {
        let pset = parser::parse_policyset(
            r#"
            permit(principal, action, resource) when { context.a };
            forbid(principal, action, resource) when { context.b };
            permit(principal, action, resource);
            forbid(principal, action, resource) when { context.c };
            permit(principal, action, resource) when { context.d };
        "#,
        )
        .expect("policies parse");
        let q = requests().swap_remove(0);
        let response = assert_agrees(&q, &pset, &entities());
        assert_eq!(response.decision, Decision::Allow);
        assert_matches!(
            response.diagnostics.errors.as_slice(),
            [
                AuthorizationError::PolicyEvaluationError { id: id0, .. },
                AuthorizationError::PolicyEvaluationError { id: id1, .. },
                AuthorizationError::PolicyEvaluationError { id: id3, .. },
                AuthorizationError::PolicyEvaluationError { id: id4, .. },
            ] => {
                assert_eq!(id0, &PolicyID::from_string("policy0"));
                assert_eq!(id1, &PolicyID::from_string("policy1"));
                assert_eq!(id3, &PolicyID::from_string("policy3"));
                assert_eq!(id4, &PolicyID::from_string("policy4"));
            }
        );
    }

    /// A policy that evaluates to a residual sends the whole request to the
    /// `PartialResponse` path. That path reports the errors of residual
    /// policies in the iteration order of a `HashMap`, which changes from one
    /// call to the next, so this test compares the errors in policy ID order.
    #[cfg(feature = "partial-eval")]
    #[test]
    fn agrees_on_residuals() {
        #[track_caller]
        fn assert_agrees_in_any_error_order(q: &Request, pset: &PolicySet, entities: &Entities) {
            let sorted = |mut response: Response| {
                response.diagnostics.errors.sort_by_key(
                    |AuthorizationError::PolicyEvaluationError { id, .. }| id.to_string(),
                );
                response
            };
            let a = Authorizer::new();
            let direct = a.is_authorized(q.clone(), pset, entities);
            let reference = a.is_authorized_core(q.clone(), pset, entities).concretize();
            assert_eq!(
                sorted(direct),
                sorted(reference),
                "responses differ for {q}"
            );
        }

        let pset = policy_set();
        let concrete = entities();
        let partial = entities().partial();
        let unknown_context = Context::from_expr(
            RestrictedExpr::record([(
                "mfa".into(),
                RestrictedExpr::unknown(Unknown::new_untyped("mfa")),
            )])
            .expect("no duplicate keys")
            .as_borrowed(),
            Extensions::all_available(),
        )
        .expect("context is a record");
        for q in requests().into_iter().step_by(7) {
            // an entity that a partial store does not have is unknown
            assert_agrees_in_any_error_order(&q, &pset, &partial);
            // unknown context attribute
            let q_context = Request::new_unchecked(
                q.principal().clone(),
                q.action().clone(),
                q.resource().clone(),
                Some(unknown_context.clone()),
            );
            assert_agrees_in_any_error_order(&q_context, &pset, &concrete);
            assert_agrees_in_any_error_order(&q_context, &pset, &partial);
            // unknown principal and unknown context
            let q_unknown = Request::new_unchecked(
                EntityUIDEntry::unknown(),
                q.action().clone(),
                q.resource().clone(),
                None,
            );
            assert_agrees_in_any_error_order(&q_unknown, &pset, &concrete);
        }
    }
}
