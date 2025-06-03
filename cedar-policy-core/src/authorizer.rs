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

use crate::spec::{spec_ast, spec_authorizer, spec_evaluator};
use crate::verus_utils::*;
use vstd::{prelude::*, seq_lib::*, std_specs::hash::*};

verus! {

/// Authorizer
#[derive(Clone)] // `Debug` implemented manually below
#[verifier::external_derive]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorHandling {
    /// If a policy encounters an evaluation error, skip it.  The decision will
    /// be as if the erroring policy did not exist.
    Skip,
}

impl Default for ErrorHandling {
    fn default() -> Self {
        Self::Skip
    }
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

    verus! {

    /// Rewrite of original `Authorizer::is_authorized`, simplified to avoid partial evaluation and inline
    /// all of the processing logic from `is_authorized_core_internal` and `PartialResponse::concretize`,
    /// to make verification with Verus more feasible
    /// -----
    /// Returns an authorization response for `q` with respect to the given `Slice`.
    ///
    /// The language spec and formal model give a precise definition of how this is
    /// computed.
    pub fn is_authorized(&self, q: Request, pset: &PolicySet, entities: &Entities) -> (response: Response)
        ensures
            //response@ == spec_authorizer::is_authorized(q@, entities@, pset@)
            response@.decision == spec_authorizer::is_authorized(q@, entities@, pset.view_as_seq()).decision // ignoring determining_policies for now
    {
        let eval = Evaluator::new(q.clone(), entities, self.extensions);

        // logic from `Authorizer::is_authorized_core_internal()`
        let mut satisfied_permits = vec![];
        let mut satisfied_forbids = vec![];
        // let mut errors = vec![];

        proof {
            pset.lemma_view_is_finite();
        }

        // Verus well-formedness assumptions for HashMap
        proof { assume(obeys_key_model::<PolicyID>() && builds_valid_hashers::<std::hash::RandomState>()) }
        let policies_iter = pset.policies_iter();
        for p in policies_ghost_iter: policies_iter
            invariant
                eval@.request == q@,
                eval@.entities == entities@,
                ({
                    let (policies_idx, policies_seq) = policies_iter@;
                    policies_ghost_iter@ == policies_seq.take(policies_ghost_iter.pos)
                }),
                // TODO: use a quantifier here somehow?
                satisfied_permits@.map_values(|p:PolicyID| p@).to_set()
                    == spec_authorizer::satisfied_policies(spec_ast::Effect::Permit, policies_ghost_iter@.map_values(|p:Policy| p@), q@, entities@),
                satisfied_forbids@.map_values(|p:PolicyID| p@).to_set()
                    == spec_authorizer::satisfied_policies(spec_ast::Effect::Forbid, policies_ghost_iter@.map_values(|p:Policy| p@), q@, entities@),
        {
            let id = p.id().clone();
            assert(id@ == p@.id);
            match eval.evaluate_verus(p) {
                Ok(satisfied) => match (satisfied, p.effect()) {
                    (true, Effect::Permit) => {
                        assert(spec_authorizer::satisfied(p@, q@, entities@)) by { reveal(spec_authorizer::satisfied) };
                        assert(spec_authorizer::satisfied_with_effect(spec_ast::Effect::Permit, p@, q@, entities@) matches Some(spec_id) && spec_id == p@.id )
                            by { reveal(spec_authorizer::satisfied_with_effect) };
                        satisfied_permits.push(id)
                    },
                    (true, Effect::Forbid) => {
                        assert(spec_authorizer::satisfied(p@, q@, entities@)) by { reveal(spec_authorizer::satisfied) };
                        assert(spec_authorizer::satisfied_with_effect(spec_ast::Effect::Forbid, p@, q@, entities@) matches Some(spec_id) && spec_id == p@.id )
                            by { reveal(spec_authorizer::satisfied_with_effect) };
                        satisfied_forbids.push(id)
                    },
                    _ => {},
                    // (false, Effect::Permit) => {
                    //     false_permits.push((id, (ErrorState::NoError, annotations)))
                    // }
                    // (false, Effect::Forbid) => {
                    //     false_forbids.push((id, (ErrorState::NoError, annotations)))
                    // }
                },
                Err(e) => {
                    // TODO add back errors when we can handle them
                    // errors.push(AuthorizationError::PolicyEvaluationError {
                    //     id: id.clone(),
                    //     error: e,
                    // });

                    // // Since Cedar currently only supports `ErrorHandling::Skip`, we never push to `satisfied_permits`
                    // // or `satisfied_forbids` in this error case; so we can just
                    // let satisfied = match self.error_handling {
                    //     ErrorHandling::Skip => false,
                    // };
                    // match (satisfied, p.effect()) {
                    //     (true, Effect::Permit) => satisfied_permits.push(id),
                    //     (true, Effect::Forbid) => satisfied_forbids.push(id),
                    //     _ => {},
                    //     (false, Effect::Permit) => {
                    //         false_permits.push((id, (ErrorState::Error, annotations)))
                    //     }
                    //     (false, Effect::Forbid) => {
                    //         false_forbids.push((id, (ErrorState::Error, annotations)))
                    //     }
                    // }
                }
            };
        }


        if !vec_is_empty(&satisfied_permits) && vec_is_empty(&satisfied_forbids) {
            proof {
                reveal(spec_authorizer::satisfied_policies);
                reveal(spec_authorizer::is_authorized);
                satisfied_permits@.map_values(|p:PolicyID| p@).lemma_cardinality_of_empty_set_is_0();
                satisfied_forbids@.map_values(|p:PolicyID| p@).lemma_cardinality_of_empty_set_is_0();
                spec_authorizer::lemma_satisfied_policies_from_set(spec_ast::Effect::Permit, pset.view(), q@, entities@);
                spec_authorizer::lemma_satisfied_policies_from_set(spec_ast::Effect::Forbid, pset.view(), q@, entities@);
                assert(!spec_authorizer::satisfied_policies(spec_ast::Effect::Permit, pset.view_as_seq(), q@, entities@).is_empty());
                assert(spec_authorizer::satisfied_policies(spec_ast::Effect::Forbid, pset.view_as_seq(), q@, entities@).is_empty());
            }
            Response::new_no_errors(
                Decision::Allow,
                hash_set_from_vec(satisfied_permits),
                // errors
            )
        } else {
            proof {
                reveal(spec_authorizer::satisfied_policies);
                reveal(spec_authorizer::is_authorized);
                spec_authorizer::lemma_satisfied_policies_from_set(spec_ast::Effect::Permit, pset.view(), q@, entities@);
                spec_authorizer::lemma_satisfied_policies_from_set(spec_ast::Effect::Forbid, pset.view(), q@, entities@);
                assert({
                    ||| spec_authorizer::satisfied_policies(spec_ast::Effect::Permit, pset.view_as_seq(), q@, entities@).is_empty()
                    ||| !spec_authorizer::satisfied_policies(spec_ast::Effect::Forbid, pset.view_as_seq(), q@, entities@).is_empty()
                });
            }
            Response::new_no_errors(
                Decision::Deny,
                hash_set_from_vec(satisfied_forbids),
                // errors
            )
        }
    }

    } // verus!

    // /// Returns an authorization response for `q` with respect to the given `Slice`.
    // ///
    // /// The language spec and formal model give a precise definition of how this is
    // /// computed.
    // pub fn is_authorized(&self, q: Request, pset: &PolicySet, entities: &Entities) -> Response {
    //     self.is_authorized_core(q, pset, entities).concretize()
    // }

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

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
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
            Expr::val(true),
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

verus! {

/// Authorization response returned from the `Authorizer`
#[derive(Debug, PartialEq, Eq, Clone)]
#[verifier::external_derive]
pub struct Response {
    /// Authorization decision
    pub decision: Decision,
    /// Diagnostics providing more information on how this decision was reached
    pub diagnostics: Diagnostics,
}

impl View for Response {
    type V = spec_ast::Response;
    open spec fn view(&self) -> spec_ast::Response {
        spec_ast::Response {
            decision: self.decision.view(),
            determining_policies: self.spec_get_reason(),
            // TODO: Verus can't handle AuthorizationError at the moment
            erroring_policies: set![], // self.diagnostics.errors.view().to_set().map(|e: AuthorizationError| e.id.view())
        }
    }
}

clone_spec_for!(Response);


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

verus! {

/// Diagnostics providing more information on how a `Decision` was reached
#[derive(Debug, PartialEq, Eq, Clone)]
#[verifier::external_derive]
#[verifier::external_body]
pub struct Diagnostics {
    /// `PolicyID`s of the policies that contributed to the decision. If no
    /// policies applied to the request, this set will be empty.
    pub reason: HashSet<PolicyID>,
    /// List of errors that occurred
    pub errors: Vec<AuthorizationError>,
}

} // verus!
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

    verus! {

    /// Create a new `Response`
    #[verifier::external_body]
    pub fn new_no_errors(
        decision: Decision,
        reason: HashSet<PolicyID>,
    ) -> (r: Self)
        ensures
            r@ == (spec_ast::Response {
                decision: decision@,
                determining_policies: reason@.map(|p: PolicyID| p.view()),
                erroring_policies: set![],
            }),
            r.spec_get_reason() == reason@.map(|p: PolicyID| p.view()),
    {
        Response {
            decision,
            diagnostics: Diagnostics { reason, errors: vec![] },
        }
    }

    #[verifier::external_body]
    pub closed spec fn spec_get_reason(&self) -> vstd::set::Set<spec_ast::PolicyID> {
        self.diagnostics.reason.view().map(|p: PolicyID| p.view())
    }

    }
}

verus! {

/// Decision returned from the `Authorizer`
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
#[verifier::external_derive]
pub enum Decision {
    /// The `Authorizer` determined that the request should be allowed
    Allow,
    /// The `Authorizer` determined that the request should be denied.
    /// This is also returned if sufficiently fatal errors are encountered such
    /// that no decision could be safely reached; for example, errors parsing
    /// the policies.
    Deny,
}

impl View for Decision {
    type V = spec_ast::Decision;
    open spec fn view(&self) -> spec_ast::Decision {
        match self {
            Decision::Allow => spec_ast::Decision::Allow,
            Decision::Deny => spec_ast::Decision::Deny,
        }
    }
}

clone_spec_for!(Decision);

} // verus!
