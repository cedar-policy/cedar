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
use crate::evaluator::concrete::Evaluator as ConcreteEvaluator;
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

use crate::spec::{spec_ast, spec_authorizer};
use crate::verus_utils::*;
use vstd::pervasive::ForLoopGhostIteratorNew;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::hash::*;

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
            response@ == spec_authorizer::is_authorized(q@, entities@, pset@.to_seq())
    {
        proof {
            // Assumptions and basic setup for the proof

            // Assumption: PolicySet contains only finitely many policies
            pset.lemma_view_is_finite();

            // Assumption: Verus well-formedness assumptions for HashMap
            // these are uninterpreted in vstd and need to be assumed
            assume(obeys_key_model::<PolicyID>() && builds_valid_hashers::<std::hash::RandomState>());

            // To make the proof easier, we prove the code correct against `spec_authorizer::is_authorized_from_set`, which
            // operates on a Set<Policy> (like this function), not a Seq<Policy> (like the Lean model).
            // This lemma proves that the two versions are equivalent for the case that we start with a Set<Policy>
            // (as we do here since `pset@` is a Set<Policy>)
            spec_authorizer::lemma_is_authorized_from_set(q@, entities@, pset@);
        }

        // TODO: figure out how to avoid the panic
        let eval_opt = ConcreteEvaluator::new(q.clone(), entities, self.extensions);
        proof { assume(eval_opt is Some) }
        let eval = eval_opt.expect("Got an invalid request context");

        // logic from `Authorizer::is_authorized_core_internal()`
        let mut satisfied_permits = vec![];
        let mut satisfied_forbids = vec![];
        let mut errors = vec![];

        // Main loop iterating over the policy set and evaluating each policy. Explaining the various iterators:
        //    - `policies_iter` has type `hash_map::Values<'_,PolicyID,Policy>`, Rust exec iterator over `Policy`
        //    - `policies_iter@` has type `(int, Seq<Policy>)`; the `Seq<Policy>` contains *all* policies to iterate over
        //    - `policies_ghost_iter` has type `vstd::std_specs::ValuesGhostIterator<PolicyID,Policy>`, containing:
        //         - `pos: int`, the current index into the sequence of policies
        //    - `policies_ghost_iter@` has type `Seq<Policy>`, containing policies 0..policies_ghost_iter.pos (those already iterated over)
        // There are two groups of invariants:
        //    - *Structural invariants:* establishing that we iterate correctly through the policy set. Essentially, we show that:
        //          "the policies we've examined already" union "the policies we have yet to examine"        == "all policies in the policy set"
        //          `policies_ghost_iter@`                union `policies_seq.skip(policies_ghost_iter.pos)` == `pset@`
        //      At the end of the loop, we have therefore examined all of the policies in `pset@`.
        //    - *Semantic invariants:* establishing that `satisfied_permits` and `satisfied_forbids` contain exactly
        //      the satisfied permits and satisfied forbids (respectively) from the policies we have examined so far (`policies_ghost_iter@`),
        //      and `errors` contains exactly the erroring policies that we have examined so far

        let policies_iter = pset.policies_iter();
        proof {
            // Establish that loop invariants hold before the loop starts
            let ghost policies_ghost_iter = policies_iter.ghost_iter();
            let (policies_idx, policies_seq) = policies_iter@;

            // Establishing structural invariants before loop
            assert(policies_seq.map_values(|p: Policy| p@).to_set() == pset@);
            assert(policies_ghost_iter@ == policies_seq.take(policies_ghost_iter.pos));
            assert(policies_ghost_iter@ + policies_seq.skip(policies_ghost_iter.pos) == policies_seq);
            assert(policies_ghost_iter@.map_values(|p:Policy| p@) + policies_seq.skip(policies_ghost_iter.pos).map_values(|p:Policy| p@)
                    == (policies_ghost_iter@ + policies_seq.skip(policies_ghost_iter.pos)).map_values(|p:Policy| p@));
            assert(policies_ghost_iter@.map_values(|p:Policy| p@).to_set()
                    .union(policies_seq.skip(policies_ghost_iter.pos).map_values(|p:Policy| p@).to_set())
                    == pset@);

            // Establishing semantic invariants about `satisfied_permits`/`satisfied_forbids/errors` before loop
            assert(policies_ghost_iter@.map_values(|p:Policy| p@).to_set().is_empty());
            assert(satisfied_permits@.map_values(|p:PolicyID| p@).to_set().is_empty());
            assert(satisfied_forbids@.map_values(|p:PolicyID| p@).to_set().is_empty());
            assert(errors@.map_values(|a:AuthorizationError| a.spec_get_policy_id()).to_set().is_empty());
            spec_authorizer::lemma_satisfied_policies_from_set_empty(spec_ast::Effect::Permit, q@, entities@);
            spec_authorizer::lemma_satisfied_policies_from_set_empty(spec_ast::Effect::Forbid, q@, entities@);
            spec_authorizer::lemma_error_policies_from_set_empty(q@, entities@);
        }
        for p in policies_ghost_iter: policies_iter
            invariant
                eval@.request == q@,
                eval@.entities == entities@,
                // "Structural" invariants about how the loop iteration proceeds
                ({
                    let (policies_idx, policies_seq) = policies_iter@;
                    &&& policies_seq.map_values(|p: Policy| p@).to_set() == pset@
                    &&& policies_ghost_iter@ == policies_seq.take(policies_ghost_iter.pos)
                    &&& policies_ghost_iter@.map_values(|p:Policy| p@).to_set()
                            .union(policies_seq.skip(policies_ghost_iter.pos).map_values(|p:Policy| p@).to_set())
                            == pset@
                }),

                // "Semantic" invariants about `satisfied_permits`/`satisfied_forbids`
                satisfied_permits@.map_values(|p:PolicyID| p@).to_set()
                    == spec_authorizer::satisfied_policies_from_set(spec_ast::Effect::Permit, policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@),
                satisfied_forbids@.map_values(|p:PolicyID| p@).to_set()
                    == spec_authorizer::satisfied_policies_from_set(spec_ast::Effect::Forbid, policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@),
                errors@.map_values(|a:AuthorizationError| a.spec_get_policy_id()).to_set()
                    == spec_authorizer::error_policies_from_set(policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@),
        {
            let id = p.id().clone();
            assert(id@ == p@.template.id);
            proof {
                // Establish that `p` is correctly being processed, to prove we update `satisfied_permits`/`satisfied_forbids` correctly
                let (policies_idx, policies_seq) = policies_iter@;
                assert(policies_seq.map_values(|p:Policy| p@)[policies_ghost_iter.pos] == p@);
                lemma_seq_take_distributes_over_map_values(policies_seq, policies_ghost_iter.pos, |p:Policy| p@);
                lemma_seq_take_distributes_over_map_values(policies_seq, policies_ghost_iter.pos + 1, |p:Policy| p@);
                lemma_seq_take_push_to_set_insert(policies_seq.map_values(|p:Policy| p@), policies_ghost_iter.pos);
                assert(policies_seq.take(policies_ghost_iter.pos + 1).map_values(|p:Policy| p@).to_set()
                        == policies_seq.take(policies_ghost_iter.pos).map_values(|p:Policy| p@).to_set().insert(p@));
            }
            match eval.evaluate(p) {
                Ok(satisfied) => match (satisfied, p.effect()) {
                    (true, Effect::Permit) => {
                        proof {
                            // Establish that `p@` is a satisfied permit and not a satisfied forbid
                            assert(spec_authorizer::satisfied(p@, q@, entities@)) by { reveal(spec_authorizer::satisfied) };
                            assert(spec_authorizer::satisfied_with_effect(spec_ast::Effect::Permit, p@, q@, entities@) matches Some(spec_id) && spec_id == p@.template.id )
                                by { reveal(spec_authorizer::satisfied_with_effect) };
                            assert(spec_authorizer::satisfied_with_effect(spec_ast::Effect::Forbid, p@, q@, entities@) is None)
                                by { reveal(spec_authorizer::satisfied_with_effect); reveal(spec_authorizer::satisfied) };
                            assert(spec_authorizer::errored(p@, q@, entities@) is None)
                                by { reveal(spec_authorizer::errored); reveal(spec_authorizer::has_error) };

                            // Establish that `p@` should go into `satisfied_permits` and not `satisfied_forbids`
                            spec_authorizer::lemma_satisfied_policies_from_set_insert_some(
                                spec_ast::Effect::Permit, policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@, p@, id@
                            );
                            spec_authorizer::lemma_satisfied_policies_from_set_insert_none(
                                spec_ast::Effect::Forbid, policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@, p@
                            );
                            spec_authorizer::lemma_error_policies_from_set_insert_none(
                                policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@, p@
                            );

                            // Boring proof that pushing to `satisfied_permits` results in the correct set of `spec_ast::PolicyID`s
                            lemma_seq_push_to_set_insert(satisfied_permits@.map_values(|p:PolicyID| p@), id@);
                            lemma_seq_map_values_distributes_over_push(satisfied_permits@, |p:PolicyID| p@, id);
                            // assert(satisfied_permits@.push(id).map_values(|p:PolicyID| p@).to_set() == satisfied_permits@.map_values(|p:PolicyID| p@).to_set().insert(id@));
                        }
                        satisfied_permits.push(id);
                    },
                    (true, Effect::Forbid) => {
                        proof {
                            // Establish that `p@` is a satisfied forbid and not a satisfied permit
                            assert(spec_authorizer::satisfied(p@, q@, entities@)) by { reveal(spec_authorizer::satisfied) };
                            assert(spec_authorizer::satisfied_with_effect(spec_ast::Effect::Permit, p@, q@, entities@) is None)
                                by { reveal(spec_authorizer::satisfied_with_effect); reveal(spec_authorizer::satisfied) };
                            assert(spec_authorizer::satisfied_with_effect(spec_ast::Effect::Forbid, p@, q@, entities@) matches Some(spec_id) && spec_id == p@.template.id )
                                by { reveal(spec_authorizer::satisfied_with_effect) };
                            assert(spec_authorizer::errored(p@, q@, entities@) is None)
                                by { reveal(spec_authorizer::errored); reveal(spec_authorizer::has_error) };

                            // Establish that `p@` should go into `satisfied_forbids` and not `satisfied_permits`
                            spec_authorizer::lemma_satisfied_policies_from_set_insert_none(
                                spec_ast::Effect::Permit, policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@, p@
                            );
                            spec_authorizer::lemma_satisfied_policies_from_set_insert_some(
                                spec_ast::Effect::Forbid, policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@, p@, id@
                            );
                            spec_authorizer::lemma_error_policies_from_set_insert_none(
                                policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@, p@
                            );

                            // Boring proof that pushing to `satisfied_forbids` results in the correct set of `spec_ast::PolicyID`s
                            lemma_seq_push_to_set_insert(satisfied_forbids@.map_values(|p:PolicyID| p@), id@);
                            lemma_seq_map_values_distributes_over_push(satisfied_forbids@, |p:PolicyID| p@, id);
                            // assert(satisfied_forbids@.push(id).map_values(|p:PolicyID| p@).to_set() == satisfied_forbids@.map_values(|p:PolicyID| p@).to_set().insert(id@));
                        }
                        satisfied_forbids.push(id)
                    },
                    _ => {
                        proof {
                            // Establish that `p@` is neither a satisfied permit nor a satisfied forbid
                            assert(spec_authorizer::satisfied_with_effect(spec_ast::Effect::Permit, p@, q@, entities@) is None)
                                by { reveal(spec_authorizer::satisfied_with_effect); reveal(spec_authorizer::satisfied) };
                            assert(spec_authorizer::satisfied_with_effect(spec_ast::Effect::Forbid, p@, q@, entities@) is None)
                                by { reveal(spec_authorizer::satisfied_with_effect); reveal(spec_authorizer::satisfied) };
                            assert(spec_authorizer::errored(p@, q@, entities@) is None)
                                by { reveal(spec_authorizer::errored); reveal(spec_authorizer::has_error) };

                            // Establish that `p@` should go into neither `satisfied_permits` nor `satisfied_forbids`
                            spec_authorizer::lemma_satisfied_policies_from_set_insert_none(
                                spec_ast::Effect::Permit, policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@, p@
                            );
                            spec_authorizer::lemma_satisfied_policies_from_set_insert_none(
                                spec_ast::Effect::Forbid, policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@, p@
                            );
                            spec_authorizer::lemma_error_policies_from_set_insert_none(
                                policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@, p@
                            );
                        }
                    },
                    // (false, Effect::Permit) => {
                    //     false_permits.push((id, (ErrorState::NoError, annotations)))
                    // }
                    // (false, Effect::Forbid) => {
                    //     false_forbids.push((id, (ErrorState::NoError, annotations)))
                    // }
                },
                Err(e) => {
                    proof {
                        // Establish that `p@` is and error, and neither a satisfied permit nor a satisfied forbid
                        assert(spec_authorizer::has_error(p@, q@, entities@)) by { reveal(spec_authorizer::has_error); reveal(spec_authorizer::satisfied) };
                        spec_authorizer::lemma_erroring_policy_cannot_be_satisfied(p@, q@, entities@);
                        assert(spec_authorizer::satisfied_with_effect(spec_ast::Effect::Permit, p@, q@, entities@) is None);
                        assert(spec_authorizer::satisfied_with_effect(spec_ast::Effect::Forbid, p@, q@, entities@) is None);
                        assert(spec_authorizer::errored(p@, q@, entities@) matches Some(spec_id) && spec_id == p@.template.id)
                            by { reveal(spec_authorizer::errored) };

                        // Establish that `p@` should go into `errors` and neither `satisfied_permits` nor `satisfied_forbids`
                        spec_authorizer::lemma_satisfied_policies_from_set_insert_none(
                            spec_ast::Effect::Permit, policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@, p@
                        );
                        spec_authorizer::lemma_satisfied_policies_from_set_insert_none(
                            spec_ast::Effect::Forbid, policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@, p@
                        );
                        spec_authorizer::lemma_error_policies_from_set_insert_some(
                            policies_ghost_iter@.map_values(|p:Policy| p@).to_set(), q@, entities@, p@, id@,
                        );
                    }
                    let auth_error = AuthorizationError::PolicyEvaluationError {
                        id: id.clone(),
                        error: e,
                    };
                    proof {
                        // Boring proof that pushing to `errors` results in the correct set of `spec_ast::PolicyID`s
                        lemma_seq_push_to_set_insert(errors@.map_values(|a: AuthorizationError| a.spec_get_policy_id()), id@);
                        lemma_seq_map_values_distributes_over_push(errors@, |a: AuthorizationError| a.spec_get_policy_id(), auth_error);
                    }
                    errors.push(auth_error);

                    // // Since Cedar currently only supports `ErrorHandling::Skip`, we never push to `satisfied_permits`
                    // // or `satisfied_forbids` in this error case; so we can just skip it
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

            proof {
                // Prove structural invariants for next iteration of the loop
                // i.e., on the next iteration, we will have already examined the first `policies_ghost_iter.pos + 1` policies

                let (policies_idx, policies_seq) = policies_iter@;
                lemma_seq_take_skip_add(policies_seq, policies_ghost_iter.pos + 1);
                lemma_seq_map_values_distributes_over_add(
                    policies_seq.take(policies_ghost_iter.pos + 1),
                    policies_seq.skip(policies_ghost_iter.pos + 1),
                    |p:Policy| p@
                );
                lemma_seq_to_set_distributes_over_add(
                    policies_seq.take(policies_ghost_iter.pos + 1).map_values(|p:Policy| p@),
                    policies_seq.skip(policies_ghost_iter.pos + 1).map_values(|p:Policy| p@)
                );
            }
        }

        if !vec_is_empty(&satisfied_permits) && vec_is_empty(&satisfied_forbids) {
            proof {
                // Establish that decision is correct
                reveal(spec_authorizer::satisfied_policies_from_set);
                reveal(spec_authorizer::is_authorized_from_set);
                satisfied_permits@.map_values(|p:PolicyID| p@).lemma_cardinality_of_empty_set_is_0();
                satisfied_forbids@.map_values(|p:PolicyID| p@).lemma_cardinality_of_empty_set_is_0();
                assert(!spec_authorizer::satisfied_policies_from_set(spec_ast::Effect::Permit, pset@, q@, entities@).is_empty());
                assert(spec_authorizer::satisfied_policies_from_set(spec_ast::Effect::Forbid, pset@, q@, entities@).is_empty());

                // Establish that determining_policies is correct
                // (need to commute `.map(...).to_set()` from loop invariant to `.to_set().map(f)` from spec of `Response::new_no_errors`)
                satisfied_permits@.lemma_to_set_map_commutes(|p:PolicyID| p@);
            }
            Response::new(
                Decision::Allow,
                hash_set_from_vec(satisfied_permits),
                errors,
            )
        } else {
            proof {
                // Establish that decision is correct
                reveal(spec_authorizer::satisfied_policies_from_set);
                reveal(spec_authorizer::is_authorized_from_set);
                satisfied_permits@.map_values(|p:PolicyID| p@).lemma_cardinality_of_empty_set_is_0();
                satisfied_forbids@.map_values(|p:PolicyID| p@).lemma_cardinality_of_empty_set_is_0();
                assert({
                    ||| spec_authorizer::satisfied_policies_from_set(spec_ast::Effect::Permit, pset@, q@, entities@).is_empty()
                    ||| !spec_authorizer::satisfied_policies_from_set(spec_ast::Effect::Forbid, pset@, q@, entities@).is_empty()
                });

                // Establish that determining_policies is correct
                // (need to commute `.map(...).to_set()` from loop invariant to `.to_set().map(f)` from spec of `Response::new_no_errors`)
                // lemma_seq_to_set_commutes_with_map(satisfied_forbids@, |p:PolicyID| p@);
                satisfied_forbids@.lemma_to_set_map_commutes(|p:PolicyID| p@);
            }
            Response::new(
                Decision::Deny,
                hash_set_from_vec(satisfied_forbids),
                errors,
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
            erroring_policies: self.diagnostics.errors.view().map_values(|e: AuthorizationError| e.spec_get_policy_id()).to_set(),
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
//#[verifier::external_body]
pub struct Diagnostics {
    /// `PolicyID`s of the policies that contributed to the decision. If no
    /// policies applied to the request, this set will be empty.
    pub reason: HashSet<PolicyID>,
    /// List of errors that occurred
    pub errors: Vec<AuthorizationError>,
}

} // verus!
impl Response {
    verus! {

    /// Create a new `Response`
    pub fn new(
        decision: Decision,
        reason: HashSet<PolicyID>,
        errors: Vec<AuthorizationError>,
    ) -> (r: Self)
        ensures
            r@ == (spec_ast::Response {
                decision: decision@,
                determining_policies: reason@.map(|p: PolicyID| p.view()),
                erroring_policies: errors@.map_values(|a: AuthorizationError| a.spec_get_policy_id()).to_set(),
            }),
            r.spec_get_reason() == reason@.map(|p: PolicyID| p.view()),
    {
        Response {
            decision,
            diagnostics: Diagnostics { reason, errors },
        }
    }

    // /// Create a new `Response`
    // #[verifier::external_body]
    // pub fn new_no_errors(
    //     decision: Decision,
    //     reason: HashSet<PolicyID>,
    // ) -> (r: Self)
    //     ensures
    //         r@ == (spec_ast::Response {
    //             decision: decision@,
    //             determining_policies: reason@.map(|p: PolicyID| p.view()),
    //             erroring_policies: set![],
    //         }),
    //         r.spec_get_reason() == reason@.map(|p: PolicyID| p.view()),
    // {
    //     Response {
    //         decision,
    //         diagnostics: Diagnostics { reason, errors: vec![] },
    //     }
    // }

    // #[verifier::external_body]
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
