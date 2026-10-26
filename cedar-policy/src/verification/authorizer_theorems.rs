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

//! The authorization theorems about the public `Authorizer::is_authorized`,
//! lifted from those of the core one (`th`) via `abs::is_authorized_lift`.
//! They are stated with the core predicates on the core (`spec_ast`) arguments.
#![allow(unused_imports)]

use vstd::prelude::*;

use super::abs::*;
use crate::api::*;
use cedar_policy_core::ast;
use cedar_policy_core::authorizer;
use cedar_policy_core::verification::policy_abs::{policy_effect, policy_id};
use cedar_policy_core::verification::authorizer_theorems as th;
use cedar_policy_core::verification::trusted as ct;
use vstd::set::Set;

verus! {

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

/// `r` is the response of the public `Authorizer::is_authorized`, under its preconditions.
pub open spec fn api_authorized(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response) -> bool {
    &&& call_ensures(Authorizer::is_authorized, (&a, &q, &ps, &es), r)
    &&& authorization_hyps(a, q, ps, es)
}

/// The (core) IDs of the determining policies of a public response
pub open spec fn determining_ids(r: Response) -> Set<ast::PolicyID> {
    r.spec_reason().map(|id: PolicyId| id.spec_ast())
}

/// The (core) IDs of the erroring policies of a public response
pub open spec fn erroring_ids(r: Response) -> Set<ast::PolicyID> {
    r.spec_errors().map_values(|e: AuthorizationError| e.spec_policy_id()).to_set()
}

/// Same decision, determining policies and erroring policies
pub open spec fn same_response(r1: Response, r2: Response) -> bool {
    &&& r1.spec_decision() == r2.spec_decision()
    &&& determining_ids(r1) == determining_ids(r2)
    &&& erroring_ids(r1) == erroring_ids(r2)
}

pub open spec fn has_satisfied_effect(eff: ast::Effect, q: Request, es: Entities, ps: PolicySet) -> bool {
    th::has_satisfied_effect(eff, q.spec_ast(), es.spec_ast(), ps.spec_ast())
}

pub open spec fn is_explicitly_forbidden(q: Request, es: Entities, ps: PolicySet) -> bool {
    th::is_explicitly_forbidden(q.spec_ast(), es.spec_ast(), ps.spec_ast())
}

pub open spec fn is_explicitly_permitted(q: Request, es: Entities, ps: PolicySet) -> bool {
    th::is_explicitly_permitted(q.spec_ast(), es.spec_ast(), ps.spec_ast())
}

pub open spec fn policy_satisfied(p: ast::Policy, q: Request, es: Entities) -> bool {
    th::policy_satisfied(p, q.spec_ast(), es.spec_ast())
}

pub open spec fn policy_errors(p: ast::Policy, q: Request, es: Entities) -> bool {
    th::policy_errors(p, q.spec_ast(), es.spec_ast())
}

// ---------------------------------------------------------------------------
// Lemmas
// ---------------------------------------------------------------------------

/// The core response that `r` lifts
pub proof fn lemma_api_authorized(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response) -> (r0: authorizer::Response)
    requires
        api_authorized(a, q, ps, es, r),
    ensures
        th::authorized(a.spec_ast(), q.spec_ast(), ps.spec_ast(), es.spec_ast(), r0),
        response_lift(r, r0),
        determining_ids(r) == r0.diagnostics.reason@,
        erroring_ids(r) == th::erroring_ids(r0),
{
    choose|r0: authorizer::Response| #[trigger] th::authorized(a.spec_ast(), q.spec_ast(), ps.spec_ast(), es.spec_ast(), r0)
        && response_lift(r, r0)
}

proof fn lemma_same_response(r1: Response, r2: Response, r01: authorizer::Response, r02: authorizer::Response)
    requires
        response_lift(r1, r01),
        response_lift(r2, r02),
        th::same_response(r01, r02),
    ensures
        same_response(r1, r2),
{
}

// ---------------------------------------------------------------------------
// Theorems: each lifts the `th` theorem of the same name
// (Lean: `Cedar/Thm/Authorization.lean`, `Cedar/Thm/PolicySlice.lean`)
// ---------------------------------------------------------------------------

pub proof fn thm_forbid_trumps_permit(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        api_authorized(a, q, ps, es, r),
        is_explicitly_forbidden(q, es, ps),
    ensures
        r.spec_decision() is Deny,
{
    let r0 = lemma_api_authorized(a, q, ps, es, r);
    th::thm_forbid_trumps_permit(a.spec_ast(), q.spec_ast(), ps.spec_ast(), es.spec_ast(), r0);
}

pub proof fn thm_allowed_only_if_explicitly_permitted(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        api_authorized(a, q, ps, es, r),
        r.spec_decision() is Allow,
    ensures
        is_explicitly_permitted(q, es, ps),
{
    let r0 = lemma_api_authorized(a, q, ps, es, r);
    th::thm_allowed_only_if_explicitly_permitted(a.spec_ast(), q.spec_ast(), ps.spec_ast(), es.spec_ast(), r0);
}

pub proof fn thm_default_deny(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        api_authorized(a, q, ps, es, r),
        !is_explicitly_permitted(q, es, ps),
    ensures
        r.spec_decision() is Deny,
{
    let r0 = lemma_api_authorized(a, q, ps, es, r);
    th::thm_default_deny(a.spec_ast(), q.spec_ast(), ps.spec_ast(), es.spec_ast(), r0);
}

pub proof fn thm_allowed_iff_explicitly_permitted_and_not_denied(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        api_authorized(a, q, ps, es, r),
    ensures
        (is_explicitly_permitted(q, es, ps) && !is_explicitly_forbidden(q, es, ps)) <==> r.spec_decision() is Allow,
{
    let r0 = lemma_api_authorized(a, q, ps, es, r);
    th::thm_allowed_iff_explicitly_permitted_and_not_denied(a.spec_ast(), q.spec_ast(), ps.spec_ast(), es.spec_ast(), r0);
}

pub proof fn thm_denied_iff_explicitly_denied_or_not_permitted(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        api_authorized(a, q, ps, es, r),
    ensures
        (is_explicitly_forbidden(q, es, ps) || !is_explicitly_permitted(q, es, ps)) <==> r.spec_decision() is Deny,
{
    let r0 = lemma_api_authorized(a, q, ps, es, r);
    th::thm_denied_iff_explicitly_denied_or_not_permitted(a.spec_ast(), q.spec_ast(), ps.spec_ast(), es.spec_ast(), r0);
}

pub proof fn thm_order_and_dup_independent(
    a1: Authorizer,
    a2: Authorizer,
    q: Request,
    ps1: PolicySet,
    ps2: PolicySet,
    es: Entities,
    r1: Response,
    r2: Response,
)
    requires
        api_authorized(a1, q, ps1, es, r1),
        api_authorized(a2, q, ps2, es, r2),
        forall|p: ast::Policy| ct::pset_policies(ps1.spec_ast()).contains(p) <==> ct::pset_policies(ps2.spec_ast()).contains(p),
    ensures
        same_response(r1, r2),
{
    let r01 = lemma_api_authorized(a1, q, ps1, es, r1);
    let r02 = lemma_api_authorized(a2, q, ps2, es, r2);
    th::thm_order_and_dup_independent(a1.spec_ast(), a2.spec_ast(), q.spec_ast(), ps1.spec_ast(), ps2.spec_ast(), es.spec_ast(), r01, r02);
    lemma_same_response(r1, r2, r01, r02);
}

pub proof fn thm_unchanged_allow_when_add_permit(
    a1: Authorizer,
    a2: Authorizer,
    q: Request,
    ps1: PolicySet,
    ps2: PolicySet,
    p: ast::Policy,
    es: Entities,
    r1: Response,
    r2: Response,
)
    requires
        api_authorized(a1, q, ps1, es, r1),
        api_authorized(a2, q, ps2, es, r2),
        th::pset_with(ps2.spec_ast(), ps1.spec_ast(), p),
        policy_effect(p) is Permit,
        r1.spec_decision() is Allow,
    ensures
        r2.spec_decision() is Allow,
{
    let r01 = lemma_api_authorized(a1, q, ps1, es, r1);
    let r02 = lemma_api_authorized(a2, q, ps2, es, r2);
    th::thm_unchanged_allow_when_add_permit(a1.spec_ast(), a2.spec_ast(), q.spec_ast(), ps1.spec_ast(), ps2.spec_ast(), p, es.spec_ast(), r01, r02);
}

pub proof fn thm_unchanged_deny_when_add_forbid(
    a1: Authorizer,
    a2: Authorizer,
    q: Request,
    ps1: PolicySet,
    ps2: PolicySet,
    p: ast::Policy,
    es: Entities,
    r1: Response,
    r2: Response,
)
    requires
        api_authorized(a1, q, ps1, es, r1),
        api_authorized(a2, q, ps2, es, r2),
        th::pset_with(ps2.spec_ast(), ps1.spec_ast(), p),
        policy_effect(p) is Forbid,
        r1.spec_decision() is Deny,
    ensures
        r2.spec_decision() is Deny,
{
    let r01 = lemma_api_authorized(a1, q, ps1, es, r1);
    let r02 = lemma_api_authorized(a2, q, ps2, es, r2);
    th::thm_unchanged_deny_when_add_forbid(a1.spec_ast(), a2.spec_ast(), q.spec_ast(), ps1.spec_ast(), ps2.spec_ast(), p, es.spec_ast(), r01, r02);
}

/// Policy slicing soundness
pub proof fn thm_is_authorized_eq_for_sound_policy_slice(
    a1: Authorizer,
    a2: Authorizer,
    q: Request,
    slice: PolicySet,
    ps: PolicySet,
    es: Entities,
    r1: Response,
    r2: Response,
)
    requires
        api_authorized(a1, q, slice, es, r1),
        api_authorized(a2, q, ps, es, r2),
        th::is_sound_policy_slice(q.spec_ast(), es.spec_ast(), slice.spec_ast(), ps.spec_ast()),
    ensures
        same_response(r1, r2),
{
    let r01 = lemma_api_authorized(a1, q, slice, es, r1);
    let r02 = lemma_api_authorized(a2, q, ps, es, r2);
    th::thm_is_authorized_eq_for_sound_policy_slice(a1.spec_ast(), a2.spec_ast(), q.spec_ast(), slice.spec_ast(), ps.spec_ast(), es.spec_ast(), r01, r02);
    lemma_same_response(r1, r2, r01, r02);
}

pub proof fn thm_determining_policies_of(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        api_authorized(a, q, ps, es, r),
    ensures
        forall|id: ast::PolicyID| #[trigger] determining_ids(r).contains(id)
            <==> exists|p: ast::Policy| #[trigger] ct::pset_policies(ps.spec_ast()).contains(p) && policy_id(p) == id
                && policy_effect(p) == th::decision_effect(r.spec_decision()) && policy_satisfied(p, q, es),
{
    let r0 = lemma_api_authorized(a, q, ps, es, r);
    th::thm_determining_policies_of(a.spec_ast(), q.spec_ast(), ps.spec_ast(), es.spec_ast(), r0);
}

pub proof fn thm_erroring_policies_of(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        api_authorized(a, q, ps, es, r),
    ensures
        forall|id: ast::PolicyID| #[trigger] erroring_ids(r).contains(id)
            <==> exists|p: ast::Policy| #[trigger] ct::pset_policies(ps.spec_ast()).contains(p) && policy_id(p) == id && policy_errors(p, q, es),
{
    let r0 = lemma_api_authorized(a, q, ps, es, r);
    th::thm_erroring_policies_of(a.spec_ast(), q.spec_ast(), ps.spec_ast(), es.spec_ast(), r0);
}

pub proof fn thm_determining_erroring_disjoint_when_unique_ids(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        api_authorized(a, q, ps, es, r),
        forall|p1: ast::Policy, p2: ast::Policy| #[trigger] ct::pset_policies(ps.spec_ast()).contains(p1) && #[trigger] ct::pset_policies(ps.spec_ast()).contains(p2)
            && policy_id(p1) == policy_id(p2) ==> p1 == p2,
    ensures
        forall|id: ast::PolicyID| !(#[trigger] determining_ids(r).contains(id) && erroring_ids(r).contains(id)),
{
    let r0 = lemma_api_authorized(a, q, ps, es, r);
    th::thm_determining_erroring_disjoint_when_unique_ids(a.spec_ast(), q.spec_ast(), ps.spec_ast(), es.spec_ast(), r0);
}

} // verus!
