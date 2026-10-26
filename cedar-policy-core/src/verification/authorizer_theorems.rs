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

//! The authorization theorems about production `Authorizer::is_authorized`,
//! each proved from the Lean theorem of the same name (`authorizer_lean_theorems`)
//! and the verified contract of `is_authorized`.

use vstd::prelude::*;

use super::abs::*;
use super::authorizer_lean_theorems as lt;
use super::model as m;
use super::model::policy as mp;
use super::policy_abs::{abs_linked_policy, policy_effect, policy_id, policy_modeled};
use super::trusted::*;
use super::value_abs::*;
use super::expr_abs::*;
use super::map_entries::*;
use crate::ast::*;
use crate::authorizer::{Authorizer, Decision, Response};
use crate::entities::Entities;
use crate::evaluator::Evaluator;

verus! {

broadcast use super::trusted::group_trusted, super::model_lemmas::group_model_eq;

// ---------------------------------------------------------------------------
// Production-level predicates
// ---------------------------------------------------------------------------

/// The production evaluator returns `Ok(true)` on the policy (`lemma_evaluate_policy`).
pub open spec fn policy_satisfied(p: Policy, q: Request, es: Entities) -> bool {
    m::authorizer::satisfied(&abs_policy(p), &abs_request(q), &abs_entities(es))
}

/// The production evaluator returns `Err` on the policy (`lemma_evaluate_policy`).
pub open spec fn policy_errors(p: Policy, q: Request, es: Entities) -> bool {
    m::authorizer::has_error(&abs_policy(p), &abs_request(q), &abs_entities(es))
}

pub open spec fn has_satisfied_effect(eff: Effect, q: Request, es: Entities, ps: PolicySet) -> bool {
    exists|p: Policy| #[trigger] pset_policies(ps).contains(p) && policy_effect(p) == eff && policy_satisfied(p, q, es)
}

pub open spec fn is_explicitly_forbidden(q: Request, es: Entities, ps: PolicySet) -> bool {
    has_satisfied_effect(Effect::Forbid, q, es, ps)
}

pub open spec fn is_explicitly_permitted(q: Request, es: Entities, ps: PolicySet) -> bool {
    has_satisfied_effect(Effect::Permit, q, es, ps)
}

/// `r` is the result of `Authorizer::is_authorized`, under its preconditions.
pub open spec fn authorized(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response) -> bool {
    &&& call_ensures(Authorizer::is_authorized, (&a, q, &ps, &es), r)
    &&& authorization_hyps(a, q, ps, es)
}

/// The preconditions of `Authorizer::is_authorized` other than `!stack_exhausted()`
pub open spec fn authorization_hyps(a: Authorizer, q: Request, ps: PolicySet, es: Entities) -> bool {
    &&& request_wf(q)
    &&& entities_wf(es)
    &&& policy_set_modeled(ps, a.spec_ext_ok())
}

pub open spec fn decision_effect(d: Decision) -> Effect {
    match d {
        Decision::Allow => Effect::Permit,
        Decision::Deny => Effect::Forbid,
    }
}

pub open spec fn erroring_ids(r: Response) -> vstd::set::Set<PolicyID> {
    error_ids(r.diagnostics.errors@)
}

// ---------------------------------------------------------------------------
// Lemmas
// ---------------------------------------------------------------------------

/// The model policies of a policy set are the abstractions of its policies.
pub proof fn lemma_abs_policy_set(ps: PolicySet)
    ensures
        list_view(abs_policy_set(ps)) == pset_policies(ps).map_values(|p: Policy| abs_policy(p)),
        forall|mp: m::authorizer::Policy| #[trigger] list_view(abs_policy_set(ps)).contains(mp)
            <==> exists|p: Policy| #[trigger] pset_policies(ps).contains(p) && abs_policy(p) == mp,
{
    let s = pset_policies(ps).map_values(|p: Policy| abs_policy(p));
    super::model_lemmas::lemma_list_view_seq_to_list(s);
    assert forall|mp: m::authorizer::Policy| #[trigger] list_view(abs_policy_set(ps)).contains(mp)
        <==> exists|p: Policy| #[trigger] pset_policies(ps).contains(p) && abs_policy(p) == mp by {
        if list_view(abs_policy_set(ps)).contains(mp) {
            let i = choose|i: int| 0 <= i < s.len() && s[i] == mp;
            assert(pset_policies(ps).contains(pset_policies(ps)[i]));
        }
        if exists|p: Policy| #[trigger] pset_policies(ps).contains(p) && abs_policy(p) == mp {
            let p = choose|p: Policy| #[trigger] pset_policies(ps).contains(p) && abs_policy(p) == mp;
            let i = choose|i: int| 0 <= i < pset_policies(ps).len() && pset_policies(ps)[i] == p;
            assert(s[i] == mp);
        }
    }
}

/// The model policy of a production policy is that of a linked policy.
pub proof fn lemma_is_linked(p: Policy)
    ensures
        lt::is_linked(abs_policy(p)),
{
    assert(mp::to_policy(&abs_linked_policy(p)) == abs_policy(p));
}

/// The model policies of a policy set are those of linked policies.
pub proof fn lemma_linked(ps: PolicySet)
    ensures
        lt::linked(abs_policy_set(ps)),
{
    lemma_abs_policy_set(ps);
    assert forall|mp: m::authorizer::Policy| #[trigger] list_view(abs_policy_set(ps)).contains(mp) implies lt::is_linked(mp) by {
        let p = choose|p: Policy| #[trigger] pset_policies(ps).contains(p) && abs_policy(p) == mp;
        lemma_is_linked(p);
    }
}

pub proof fn lemma_seq_to_list_inj<T>(a: Seq<T>, b: Seq<T>)
    requires
        seq_to_list(a) == seq_to_list(b),
    ensures
        a == b,
{
    super::model_lemmas::lemma_list_view_seq_to_list(a);
    super::model_lemmas::lemma_list_view_seq_to_list(b);
}

/// Policy IDs are determined by their model strings.
pub proof fn lemma_abs_policy_id_inj(a: PolicyID, b: PolicyID)
    requires
        abs_policy_id(a) == abs_policy_id(b),
    ensures
        a == b,
{
    lemma_seq_to_list_inj(smol_view(policy_id_str(a)), smol_view(policy_id_str(b)));
    lemma_policy_id_str_injective(a, b);
}

/// A production set of IDs equals another if their model strings do.
pub proof fn lemma_ids_inj(a: vstd::set::Set<PolicyID>, b: vstd::set::Set<PolicyID>)
    requires
        a.map(|id: PolicyID| abs_policy_id(id)) == b.map(|id: PolicyID| abs_policy_id(id)),
    ensures
        a == b,
{
    assert forall|id: PolicyID| a.contains(id) implies b.contains(id) by {
        assert(a.map(|id: PolicyID| abs_policy_id(id)).contains(abs_policy_id(id)));
        let id2 = choose|id2: PolicyID| b.contains(id2) && abs_policy_id(id2) == abs_policy_id(id);
        lemma_abs_policy_id_inj(id, id2);
    }
    assert forall|id: PolicyID| b.contains(id) implies a.contains(id) by {
        assert(b.map(|id: PolicyID| abs_policy_id(id)).contains(abs_policy_id(id)));
        let id2 = choose|id2: PolicyID| a.contains(id2) && abs_policy_id(id2) == abs_policy_id(id);
        lemma_abs_policy_id_inj(id, id2);
    }
    assert(a =~= b);
}

/// The production response of `is_authorized` is the model's.
pub proof fn lemma_authorized(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        authorized(a, q, ps, es, r),
    ensures
        response_rel(r, m::authorizer::is_authorized(&abs_request(q), &abs_entities(es), &abs_policy_set(ps))),
        lt::linked(abs_policy_set(ps)),
{
    lemma_linked(ps);
}

pub proof fn lemma_has_satisfied_effect(eff: Effect, q: Request, es: Entities, ps: PolicySet)
    ensures
        has_satisfied_effect(eff, q, es, ps)
            == lt::has_satisfied_effect(abs_effect(eff), abs_request(q), abs_entities(es), abs_policy_set(ps)),
{
    lemma_abs_policy_set(ps);
    if has_satisfied_effect(eff, q, es, ps) {
        let p = choose|p: Policy| #[trigger] pset_policies(ps).contains(p) && policy_effect(p) == eff && policy_satisfied(p, q, es);
        assert(list_view(abs_policy_set(ps)).contains(abs_policy(p)));
    }
    if lt::has_satisfied_effect(abs_effect(eff), abs_request(q), abs_entities(es), abs_policy_set(ps)) {
        let mp = choose|mp: m::authorizer::Policy| #[trigger] list_view(abs_policy_set(ps)).contains(mp) && mp.effect == abs_effect(eff)
            && m::authorizer::satisfied(&mp, &abs_request(q), &abs_entities(es));
        let p = choose|p: Policy| #[trigger] pset_policies(ps).contains(p) && abs_policy(p) == mp;
        assert(policy_effect(p) == eff);
    }
}

pub proof fn lemma_decision(r: Response, mr: m::authorizer::Response)
    requires
        response_rel(r, mr),
    ensures
        (r.decision is Deny) == (mr.decision is Deny),
        (r.decision is Allow) == (mr.decision is Allow),
{
}

// ---------------------------------------------------------------------------
// The evaluator on a policy
// ---------------------------------------------------------------------------

pub proof fn lemma_evaluate_policy(eval: Evaluator, q: Request, es: Entities, p: Policy, r: crate::evaluator::Result<bool>)
    requires
        call_ensures(Evaluator::evaluate, (&eval, &p), r),
        eval.spec_request() == abs_request(q),
        eval.spec_entities() == abs_entities(es),
        policy_modeled(p, eval.spec_ext_ok()),
    ensures
        (r == Ok::<bool, crate::evaluator::EvaluationError>(true)) == policy_satisfied(p, q, es),
        (r is Err) == policy_errors(p, q, es),
{
    super::authorizer_lemmas::lemma_policy_eval_bool(p, abs_request(q), abs_entities(es));
}

// ---------------------------------------------------------------------------
// Authorization theorems: each from the `lt` axiom of the same name
// ---------------------------------------------------------------------------

pub proof fn thm_forbid_trumps_permit(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        authorized(a, q, ps, es, r),
        is_explicitly_forbidden(q, es, ps),
    ensures
        r.decision is Deny,
{
    lemma_authorized(a, q, ps, es, r);
    lemma_has_satisfied_effect(Effect::Forbid, q, es, ps);
    lt::forbid_trumps_permit(abs_request(q), abs_entities(es), abs_policy_set(ps));
}

pub proof fn thm_allowed_only_if_explicitly_permitted(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        authorized(a, q, ps, es, r),
        r.decision is Allow,
    ensures
        is_explicitly_permitted(q, es, ps),
{
    lemma_authorized(a, q, ps, es, r);
    lemma_has_satisfied_effect(Effect::Permit, q, es, ps);
    lt::allowed_only_if_explicitly_permitted(abs_request(q), abs_entities(es), abs_policy_set(ps));
}

pub proof fn thm_default_deny(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        authorized(a, q, ps, es, r),
        !is_explicitly_permitted(q, es, ps),
    ensures
        r.decision is Deny,
{
    lemma_authorized(a, q, ps, es, r);
    lemma_has_satisfied_effect(Effect::Permit, q, es, ps);
    lt::default_deny(abs_request(q), abs_entities(es), abs_policy_set(ps));
}

pub proof fn thm_allowed_iff_explicitly_permitted_and_not_denied(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        authorized(a, q, ps, es, r),
    ensures
        (is_explicitly_permitted(q, es, ps) && !is_explicitly_forbidden(q, es, ps)) <==> r.decision is Allow,
{
    lemma_authorized(a, q, ps, es, r);
    lemma_has_satisfied_effect(Effect::Permit, q, es, ps);
    lemma_has_satisfied_effect(Effect::Forbid, q, es, ps);
    lt::allowed_iff_explicitly_permitted_and_not_denied(abs_request(q), abs_entities(es), abs_policy_set(ps));
}

pub proof fn thm_denied_iff_explicitly_denied_or_not_permitted(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        authorized(a, q, ps, es, r),
    ensures
        (is_explicitly_forbidden(q, es, ps) || !is_explicitly_permitted(q, es, ps)) <==> r.decision is Deny,
{
    lemma_authorized(a, q, ps, es, r);
    lemma_has_satisfied_effect(Effect::Permit, q, es, ps);
    lemma_has_satisfied_effect(Effect::Forbid, q, es, ps);
    lt::denied_iff_explicitly_denied_or_not_permitted(abs_request(q), abs_entities(es), abs_policy_set(ps));
}

/// Same decision, determining policies and erroring policies
pub open spec fn same_response(r1: Response, r2: Response) -> bool {
    &&& r1.decision == r2.decision
    &&& r1.diagnostics.reason@ == r2.diagnostics.reason@
    &&& erroring_ids(r1) == erroring_ids(r2)
}

pub proof fn lemma_same_response(r1: Response, r2: Response, mr: m::authorizer::Response)
    requires
        response_rel(r1, mr),
        response_rel(r2, mr),
    ensures
        same_response(r1, r2),
{
    lemma_ids_inj(r1.diagnostics.reason@, r2.diagnostics.reason@);
    lemma_ids_inj(erroring_ids(r1), erroring_ids(r2));
    assert(r1.decision == r2.decision) by {
        match r1.decision { Decision::Allow => {}, Decision::Deny => {} }
        match r2.decision { Decision::Allow => {}, Decision::Deny => {} }
    }
}

pub proof fn thm_order_and_dup_independent(
    a1: Authorizer, a2: Authorizer, q: Request, ps1: PolicySet, ps2: PolicySet, es: Entities, r1: Response, r2: Response,
)
    requires
        authorized(a1, q, ps1, es, r1),
        authorized(a2, q, ps2, es, r2),
        forall|p: Policy| pset_policies(ps1).contains(p) <==> pset_policies(ps2).contains(p),
    ensures
        same_response(r1, r2),
{
    lemma_authorized(a1, q, ps1, es, r1);
    lemma_authorized(a2, q, ps2, es, r2);
    lemma_abs_policy_set(ps1);
    lemma_abs_policy_set(ps2);
    let l1 = abs_policy_set(ps1);
    let l2 = abs_policy_set(ps2);
    assert forall|mp: m::authorizer::Policy| list_view(l1).contains(mp) <==> list_view(l2).contains(mp) by {
        if list_view(l1).contains(mp) {
            let p = choose|p: Policy| #[trigger] pset_policies(ps1).contains(p) && abs_policy(p) == mp;
            assert(pset_policies(ps2).contains(p));
        }
        if list_view(l2).contains(mp) {
            let p = choose|p: Policy| #[trigger] pset_policies(ps2).contains(p) && abs_policy(p) == mp;
            assert(pset_policies(ps1).contains(p));
        }
    }
    lt::order_and_dup_independent(abs_request(q), abs_entities(es), l1, l2);
    lemma_same_response(r1, r2, m::authorizer::is_authorized(&abs_request(q), &abs_entities(es), &l1));
}

/// `ps2` is `ps1` with `p` added.
pub open spec fn pset_with(ps2: PolicySet, ps1: PolicySet, p: Policy) -> bool {
    forall|x: Policy| #[trigger] pset_policies(ps2).contains(x) <==> (x == p || pset_policies(ps1).contains(x))
}

/// The model of `ps2 = ps1 + p` is (up to order) `Cons(p, ps1)`.
pub proof fn lemma_pset_with(q: Request, es: Entities, ps2: PolicySet, ps1: PolicySet, p: Policy)
    requires
        pset_with(ps2, ps1, p),
    ensures
        lt::linked(abs_policy_set(ps1)),
        lt::is_linked(abs_policy(p)),
        m::authorizer::is_authorized(&abs_request(q), &abs_entities(es), &abs_policy_set(ps2))
            == m::authorizer::is_authorized(&abs_request(q), &abs_entities(es), &m::value::List::Cons(abs_policy(p), Box::new(abs_policy_set(ps1)))),
{
    lemma_linked(ps1);
    lemma_linked(ps2);
    lemma_is_linked(p);
    lemma_abs_policy_set(ps1);
    lemma_abs_policy_set(ps2);
    let l1 = abs_policy_set(ps1);
    let l2 = abs_policy_set(ps2);
    let l3 = m::value::List::Cons(abs_policy(p), Box::new(l1));
    assert(list_view(l3) == seq![abs_policy(p)] + list_view(l1));
    assert forall|mp: m::authorizer::Policy| #[trigger] list_view(l3).contains(mp) implies lt::is_linked(mp) by {
        if mp != abs_policy(p) {
            assert(list_view(l1).contains(mp)) by {
                let k = choose|k: int| 0 <= k < list_view(l3).len() && list_view(l3)[k] == mp;
                assert(list_view(l1)[k - 1] == mp);
            }
        }
    }
    assert forall|mp: m::authorizer::Policy| list_view(l2).contains(mp) <==> list_view(l3).contains(mp) by {
        if list_view(l2).contains(mp) {
            let x = choose|x: Policy| #[trigger] pset_policies(ps2).contains(x) && abs_policy(x) == mp;
            if x == p {
                assert(list_view(l3)[0] == mp);
            } else {
                assert(pset_policies(ps1).contains(x));
                assert(list_view(l1).contains(mp));
                let k = choose|k: int| 0 <= k < list_view(l1).len() && list_view(l1)[k] == mp;
                assert(list_view(l3)[k + 1] == mp);
            }
        }
        if list_view(l3).contains(mp) {
            let k = choose|k: int| 0 <= k < list_view(l3).len() && list_view(l3)[k] == mp;
            if k == 0 {
                assert(pset_policies(ps2).contains(p));
            } else {
                assert(list_view(l1)[k - 1] == mp);
                assert(list_view(l1).contains(mp));
                let x = choose|x: Policy| #[trigger] pset_policies(ps1).contains(x) && abs_policy(x) == mp;
                assert(pset_policies(ps2).contains(x));
            }
        }
    }
    lt::order_and_dup_independent(abs_request(q), abs_entities(es), l2, l3);
}

pub proof fn thm_unchanged_allow_when_add_permit(
    a1: Authorizer, a2: Authorizer, q: Request, ps1: PolicySet, ps2: PolicySet, p: Policy, es: Entities, r1: Response, r2: Response,
)
    requires
        authorized(a1, q, ps1, es, r1),
        authorized(a2, q, ps2, es, r2),
        pset_with(ps2, ps1, p),
        policy_effect(p) is Permit,
        r1.decision is Allow,
    ensures
        r2.decision is Allow,
{
    lemma_pset_with(q, es, ps2, ps1, p);
    lt::unchanged_allow_when_add_permit(abs_request(q), abs_entities(es), abs_policy_set(ps1), abs_policy(p));
}

pub proof fn thm_unchanged_deny_when_add_forbid(
    a1: Authorizer, a2: Authorizer, q: Request, ps1: PolicySet, ps2: PolicySet, p: Policy, es: Entities, r1: Response, r2: Response,
)
    requires
        authorized(a1, q, ps1, es, r1),
        authorized(a2, q, ps2, es, r2),
        pset_with(ps2, ps1, p),
        policy_effect(p) is Forbid,
        r1.decision is Deny,
    ensures
        r2.decision is Deny,
{
    lemma_pset_with(q, es, ps2, ps1, p);
    lt::unchanged_deny_when_add_forbid(abs_request(q), abs_entities(es), abs_policy_set(ps1), abs_policy(p));
}

/// `slice` is a subset of `ps` that only leaves out policies that are neither
/// satisfied nor erroring.
pub open spec fn is_sound_policy_slice(q: Request, es: Entities, slice: PolicySet, ps: PolicySet) -> bool {
    &&& forall|p: Policy| #[trigger] pset_policies(slice).contains(p) ==> pset_policies(ps).contains(p)
    &&& forall|p: Policy| #[trigger] pset_policies(ps).contains(p) && !pset_policies(slice).contains(p) ==>
            !policy_satisfied(p, q, es) && !policy_errors(p, q, es)
}

pub proof fn thm_is_authorized_eq_for_sound_policy_slice(
    a1: Authorizer, a2: Authorizer, q: Request, slice: PolicySet, ps: PolicySet, es: Entities, r1: Response, r2: Response,
)
    requires
        authorized(a1, q, slice, es, r1),
        authorized(a2, q, ps, es, r2),
        is_sound_policy_slice(q, es, slice, ps),
    ensures
        same_response(r1, r2),
{
    lemma_authorized(a2, q, ps, es, r2);
    lemma_abs_policy_set(slice);
    lemma_abs_policy_set(ps);
    let ls = abs_policy_set(slice);
    let lp = abs_policy_set(ps);
    let mq = abs_request(q);
    let mes = abs_entities(es);
    assert forall|mp: m::authorizer::Policy| #[trigger] list_view(ls).contains(mp) implies list_view(lp).contains(mp) by {
        let p = choose|p: Policy| #[trigger] pset_policies(slice).contains(p) && abs_policy(p) == mp;
        assert(pset_policies(ps).contains(p));
    }
    assert forall|mp: m::authorizer::Policy| #[trigger] list_view(lp).contains(mp) && !list_view(ls).contains(mp) implies
        !m::authorizer::satisfied(&mp, &mq, &mes) && !m::authorizer::has_error(&mp, &mq, &mes) by {
        let p = choose|p: Policy| #[trigger] pset_policies(ps).contains(p) && abs_policy(p) == mp;
        if pset_policies(slice).contains(p) {
            assert(list_view(ls).contains(mp));
        }
    }
    lt::is_authorized_eq_for_sound_policy_slice(mq, mes, ls, lp);
    lemma_same_response(r1, r2, m::authorizer::is_authorized(&mq, &mes, &lp));
}

pub proof fn thm_determining_policies_of(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        authorized(a, q, ps, es, r),
    ensures
        forall|id: PolicyID| #[trigger] r.diagnostics.reason@.contains(id)
            <==> exists|p: Policy| #[trigger] pset_policies(ps).contains(p) && policy_id(p) == id
                && policy_effect(p) == decision_effect(r.decision) && policy_satisfied(p, q, es),
{
    lemma_authorized(a, q, ps, es, r);
    lemma_abs_policy_set(ps);
    let mq = abs_request(q);
    let mes = abs_entities(es);
    let l = abs_policy_set(ps);
    let mr = m::authorizer::is_authorized(&mq, &mes, &l);
    lt::determining_policies_of(mq, mes, l);
    assert(abs_effect(decision_effect(r.decision)) == lt::decision_effect(mr.decision));
    assert forall|id: PolicyID| #[trigger] r.diagnostics.reason@.contains(id)
        <==> exists|p: Policy| #[trigger] pset_policies(ps).contains(p) && policy_id(p) == id
            && policy_effect(p) == decision_effect(r.decision) && policy_satisfied(p, q, es) by {
        let sid = abs_policy_id(id);
        if r.diagnostics.reason@.contains(id) {
            assert(r.diagnostics.reason@.map(|id: PolicyID| abs_policy_id(id)).contains(sid));
            assert(list_view(mr.determining_policies).contains(sid));
            let mp = choose|mp: m::authorizer::Policy| #[trigger] list_view(l).contains(mp) && mp.id == sid
                && mp.effect == lt::decision_effect(mr.decision) && m::authorizer::satisfied(&mp, &mq, &mes);
            let p = choose|p: Policy| #[trigger] pset_policies(ps).contains(p) && abs_policy(p) == mp;
            lemma_abs_policy_id_inj(policy_id(p), id);
            assert(policy_effect(p) == decision_effect(r.decision));
        }
        if exists|p: Policy| #[trigger] pset_policies(ps).contains(p) && policy_id(p) == id
            && policy_effect(p) == decision_effect(r.decision) && policy_satisfied(p, q, es) {
            let p = choose|p: Policy| #[trigger] pset_policies(ps).contains(p) && policy_id(p) == id
                && policy_effect(p) == decision_effect(r.decision) && policy_satisfied(p, q, es);
            assert(list_view(l).contains(abs_policy(p)));
            assert(list_view(mr.determining_policies).contains(sid));
            assert(list_view(mr.determining_policies).to_set().contains(sid));
            let id2 = choose|id2: PolicyID| r.diagnostics.reason@.contains(id2) && abs_policy_id(id2) == sid;
            lemma_abs_policy_id_inj(id2, id);
        }
    }
}

pub proof fn thm_erroring_policies_of(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        authorized(a, q, ps, es, r),
    ensures
        forall|id: PolicyID| #[trigger] erroring_ids(r).contains(id)
            <==> exists|p: Policy| #[trigger] pset_policies(ps).contains(p) && policy_id(p) == id && policy_errors(p, q, es),
{
    lemma_authorized(a, q, ps, es, r);
    lemma_abs_policy_set(ps);
    let mq = abs_request(q);
    let mes = abs_entities(es);
    let l = abs_policy_set(ps);
    let mr = m::authorizer::is_authorized(&mq, &mes, &l);
    lt::erroring_policies_of(mq, mes, l);
    assert forall|id: PolicyID| #[trigger] erroring_ids(r).contains(id)
        <==> exists|p: Policy| #[trigger] pset_policies(ps).contains(p) && policy_id(p) == id && policy_errors(p, q, es) by {
        let sid = abs_policy_id(id);
        if erroring_ids(r).contains(id) {
            assert(erroring_ids(r).map(|id: PolicyID| abs_policy_id(id)).contains(sid));
            assert(list_view(mr.erroring_policies).contains(sid));
            let mp = choose|mp: m::authorizer::Policy| #[trigger] list_view(l).contains(mp) && mp.id == sid && m::authorizer::has_error(&mp, &mq, &mes);
            let p = choose|p: Policy| #[trigger] pset_policies(ps).contains(p) && abs_policy(p) == mp;
            lemma_abs_policy_id_inj(policy_id(p), id);
        }
        if exists|p: Policy| #[trigger] pset_policies(ps).contains(p) && policy_id(p) == id && policy_errors(p, q, es) {
            let p = choose|p: Policy| #[trigger] pset_policies(ps).contains(p) && policy_id(p) == id && policy_errors(p, q, es);
            assert(list_view(l).contains(abs_policy(p)));
            assert(list_view(mr.erroring_policies).contains(sid));
            assert(list_view(mr.erroring_policies).to_set().contains(sid));
            let id2 = choose|id2: PolicyID| erroring_ids(r).contains(id2) && abs_policy_id(id2) == sid;
            lemma_abs_policy_id_inj(id2, id);
        }
    }
}

/// Proved from the previous two theorems rather than transcribed from Lean.
pub proof fn thm_determining_erroring_disjoint_when_unique_ids(a: Authorizer, q: Request, ps: PolicySet, es: Entities, r: Response)
    requires
        authorized(a, q, ps, es, r),
        forall|p1: Policy, p2: Policy| #[trigger] pset_policies(ps).contains(p1) && #[trigger] pset_policies(ps).contains(p2)
            && policy_id(p1) == policy_id(p2) ==> p1 == p2,
    ensures
        forall|id: PolicyID| !(#[trigger] r.diagnostics.reason@.contains(id) && erroring_ids(r).contains(id)),
{
    thm_determining_policies_of(a, q, ps, es, r);
    thm_erroring_policies_of(a, q, ps, es, r);
    assert forall|id: PolicyID| !(#[trigger] r.diagnostics.reason@.contains(id) && erroring_ids(r).contains(id)) by {
        if r.diagnostics.reason@.contains(id) && erroring_ids(r).contains(id) {
            let p1 = choose|p: Policy| #[trigger] pset_policies(ps).contains(p) && policy_id(p) == id
                && policy_effect(p) == decision_effect(r.decision) && policy_satisfied(p, q, es);
            let p2 = choose|p: Policy| #[trigger] pset_policies(ps).contains(p) && policy_id(p) == id && policy_errors(p, q, es);
            assert(p1 == p2);
        }
    }
}

} // verus!
