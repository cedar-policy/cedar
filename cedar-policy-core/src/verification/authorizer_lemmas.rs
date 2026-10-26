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

//! Specifications and lemmas for the authorizer.

use vstd::prelude::*;

use super::abs::*;
use super::model as m;
use super::model_lemmas::*;
use super::trusted::*;
use super::value_abs::*;
use super::expr_abs::*;
use super::map_entries::*;
use super::policy_abs::{policy_id, policy_env};
use crate::ast::*;
use crate::authorizer::{AuthorizationError, PartialResponse, Response};
use vstd::iset::ISet;

verus! {

broadcast use super::trusted::group_trusted, super::model_lemmas::group_model_eq;

pub enum Category {
    SatisfiedPermit,
    SatisfiedForbid,
    Error,
}

/// Does policy `p` belong to the category (in the model)?
pub open spec fn in_category(p: Policy, cat: Category, req: m::request::Request, es: m::entities::Entities) -> bool {
    match cat {
        Category::SatisfiedPermit => super::policy_abs::policy_effect(p) is Permit && m::authorizer::satisfied(&abs_policy(p), &req, &es),
        Category::SatisfiedForbid => super::policy_abs::policy_effect(p) is Forbid && m::authorizer::satisfied(&abs_policy(p), &req, &es),
        Category::Error => m::authorizer::has_error(&abs_policy(p), &req, &es),
    }
}

/// The IDs of the policies among the first `n` of `ps` that are in the category
pub open spec fn categorized(ps: Seq<Policy>, n: int, cat: Category, req: m::request::Request, es: m::entities::Entities) -> ISet<
    PolicyID,
> {
    ISet::new(|id: PolicyID| exists|j: int| 0 <= j < n && policy_id(ps[j]) == id && #[trigger] in_category(ps[j], cat, req, es))
}

/// A partial response correctly categorizes the policies `ps`.
pub open spec fn partial_response_rel(r: PartialResponse, ps: Seq<Policy>, req: m::request::Request, es: m::entities::Entities) -> bool {
    &&& r.spec_satisfied_permits().to_iset() == categorized(ps, ps.len() as int, Category::SatisfiedPermit, req, es)
    &&& r.spec_satisfied_forbids().to_iset() == categorized(ps, ps.len() as int, Category::SatisfiedForbid, req, es)
    &&& r.spec_residual_permits().is_empty()
    &&& r.spec_residual_forbids().is_empty()
    &&& error_ids(r.spec_errors()).to_iset() == categorized(
        ps,
        ps.len() as int,
        Category::Error,
        req,
        es,
    )
}

pub proof fn lemma_categorized_step(ps: Seq<Policy>, n: int, cat: Category, req: m::request::Request, es: m::entities::Entities)
    requires
        0 <= n < ps.len(),
    ensures
        categorized(ps, n + 1, cat, req, es) == if in_category(ps[n], cat, req, es) {
            categorized(ps, n, cat, req, es).insert(policy_id(ps[n]))
        } else {
            categorized(ps, n, cat, req, es)
        },
{
    let a = categorized(ps, n + 1, cat, req, es);
    let b = categorized(ps, n, cat, req, es);
    if in_category(ps[n], cat, req, es) {
        assert forall|id: PolicyID| a.contains(id) <==> b.insert(policy_id(ps[n])).contains(id) by {
            if a.contains(id) {
                let j = choose|j: int| 0 <= j < n + 1 && policy_id(ps[j]) == id && #[trigger] in_category(ps[j], cat, req, es);
                if j < n {
                    assert(b.contains(id));
                }
            }
            if b.contains(id) {
                let j = choose|j: int| 0 <= j < n && policy_id(ps[j]) == id && #[trigger] in_category(ps[j], cat, req, es);
                assert(0 <= j < n + 1);
            }
        }
        assert(a =~= b.insert(policy_id(ps[n])));
    } else {
        assert forall|id: PolicyID| a.contains(id) <==> b.contains(id) by {
            if a.contains(id) {
                let j = choose|j: int| 0 <= j < n + 1 && policy_id(ps[j]) == id && #[trigger] in_category(ps[j], cat, req, es);
                assert(j != n);
            }
            if b.contains(id) {
                let j = choose|j: int| 0 <= j < n && policy_id(ps[j]) == id && #[trigger] in_category(ps[j], cat, req, es);
                assert(0 <= j < n + 1);
            }
        }
        assert(a =~= b);
    }
}

pub broadcast proof fn lemma_ids_of_push<A>(v: Seq<(PolicyID, A)>, x: (PolicyID, A))
    ensures
        #[trigger] ids_of(v.push(x)).to_iset() == ids_of(v).to_iset().insert(x.0),
{
    assert(v.push(x).map_values(|y: (PolicyID, A)| y.0) =~= v.map_values(|y: (PolicyID, A)| y.0).push(x.0));
    v.map_values(|y: (PolicyID, A)| y.0).lemma_push_to_set_commute(x.0);
    assert(ids_of(v.push(x)).to_iset() =~= ids_of(v).to_iset().insert(x.0));
}

pub broadcast proof fn lemma_error_ids_push(v: Seq<AuthorizationError>, x: AuthorizationError)
    ensures
        #[trigger] error_ids(v.push(x)).to_iset() == error_ids(v).to_iset().insert(error_policy_id(x)),
{
    let f = |e: AuthorizationError| error_policy_id(e);
    assert(v.push(x).map_values(f) =~= v.map_values(f).push(error_policy_id(x)));
    v.map_values(f).lemma_push_to_set_commute(error_policy_id(x));
    assert(error_ids(v.push(x)).to_iset() =~= error_ids(v).to_iset().insert(error_policy_id(x)));
}

pub broadcast group group_authorizer_lemmas {
    lemma_ids_of_push,
    lemma_error_ids_push,
}

pub open spec fn cat_of(permit: bool) -> Category {
    if permit { Category::SatisfiedPermit } else { Category::SatisfiedForbid }
}

pub proof fn lemma_list_view_cons<T>(x: T, rest: m::value::List<T>, y: T)
    ensures
        list_view(m::value::List::Cons(x, Box::new(rest))).contains(y) == (x == y || list_view(rest).contains(y)),
{
    let l = list_view(m::value::List::Cons(x, Box::new(rest)));
    let r = list_view(rest);
    assert(l == seq![x] + r);
    if l.contains(y) {
        let i = choose|i: int| 0 <= i < l.len() && l[i] == y;
        if i > 0 {
            assert(r[i - 1] == y);
        }
    }
    if r.contains(y) {
        let i = choose|i: int| 0 <= i < r.len() && r[i] == y;
        assert(l[i + 1] == y);
    }
    if x == y {
        assert(l[0] == y);
    }
}

pub proof fn lemma_seq_to_list_map_cons(s: Seq<Policy>)
    requires
        s.len() > 0,
    ensures
        seq_to_list(s.map_values(|p: Policy| abs_policy(p))) == m::value::List::Cons(
            abs_policy(s[0]),
            Box::new(seq_to_list(s.subrange(1, s.len() as int).map_values(|p: Policy| abs_policy(p)))),
        ),
{
    let t = s.map_values(|p: Policy| abs_policy(p));
    assert(t.subrange(1, t.len() as int) =~= s.subrange(1, s.len() as int).map_values(|p: Policy| abs_policy(p)));
}

/// The model's satisfied policies are the satisfied policies of the right effect.
pub proof fn lemma_satisfied_policies_contents(permit: bool, s: Seq<Policy>, req: m::request::Request, es: m::entities::Entities, x: m::value::Str)
    ensures
        list_view(m::authorizer::satisfied_policies(permit, &seq_to_list(s.map_values(|p: Policy| abs_policy(p))), &req, &es)).contains(x)
            <==> exists|j: int| 0 <= j < s.len() && abs_policy_id(policy_id(s[j])) == x && #[trigger] in_category(s[j], cat_of(permit), req, es),
    decreases s.len(),
{
    if s.len() == 0 {
        assert(seq_to_list(s.map_values(|p: Policy| abs_policy(p))) == m::value::List::<m::authorizer::Policy>::Nil);
    } else {
        let rest = s.subrange(1, s.len() as int);
        lemma_seq_to_list_map_cons(s);
        lemma_satisfied_policies_contents(permit, rest, req, es, x);
        let rest_ids = m::authorizer::satisfied_policies(permit, &seq_to_list(rest.map_values(|p: Policy| abs_policy(p))), &req, &es);
        let p = abs_policy(s[0]);
        assert((m::authorizer::is_permit(&p.effect) == permit && m::authorizer::satisfied(&p, &req, &es)) == in_category(s[0], cat_of(permit), req, es));
        assert(m::value::clone_str(&p.id) == abs_policy_id(policy_id(s[0])));
        if m::authorizer::is_permit(&p.effect) == permit && m::authorizer::satisfied(&p, &req, &es) {
            lemma_list_view_cons(m::value::clone_str(&p.id), rest_ids, x);
            if x == abs_policy_id(policy_id(s[0])) {
                assert(in_category(s[0], cat_of(permit), req, es));
            }
        }
        if exists|j: int| 0 <= j < s.len() && abs_policy_id(policy_id(s[j])) == x && #[trigger] in_category(s[j], cat_of(permit), req, es) {
            let j = choose|j: int| 0 <= j < s.len() && abs_policy_id(policy_id(s[j])) == x && #[trigger] in_category(s[j], cat_of(permit), req, es);
            if j > 0 {
                assert(rest[j - 1] == s[j]);
                assert(in_category(rest[j - 1], cat_of(permit), req, es));
            }
        }
        if exists|j: int| 0 <= j < rest.len() && abs_policy_id(policy_id(rest[j])) == x && #[trigger] in_category(rest[j], cat_of(permit), req, es) {
            let j = choose|j: int| 0 <= j < rest.len() && abs_policy_id(policy_id(rest[j])) == x && #[trigger] in_category(rest[j], cat_of(permit), req, es);
            assert(s[j + 1] == rest[j]);
            assert(in_category(s[j + 1], cat_of(permit), req, es));
        }
    }
}

/// The model's erroring policies are the policies that produce an error.
#[verifier::spinoff_prover]
#[verifier::rlimit(100)]
pub proof fn lemma_error_policies_contents(s: Seq<Policy>, req: m::request::Request, es: m::entities::Entities, x: m::value::Str)
    ensures
        list_view(m::authorizer::error_policies(&seq_to_list(s.map_values(|p: Policy| abs_policy(p))), &req, &es)).contains(x)
            <==> exists|j: int| 0 <= j < s.len() && abs_policy_id(policy_id(s[j])) == x && #[trigger] in_category(s[j], Category::Error, req, es),
    decreases s.len(),
{
    if s.len() == 0 {
        assert(seq_to_list(s.map_values(|p: Policy| abs_policy(p))) == m::value::List::<m::authorizer::Policy>::Nil);
    } else {
        let rest = s.subrange(1, s.len() as int);
        lemma_seq_to_list_map_cons(s);
        lemma_error_policies_contents(rest, req, es, x);
        let rest_ids = m::authorizer::error_policies(&seq_to_list(rest.map_values(|p: Policy| abs_policy(p))), &req, &es);
        let p = abs_policy(s[0]);
        assert(m::authorizer::has_error(&p, &req, &es) == in_category(s[0], Category::Error, req, es));
        assert(m::value::clone_str(&p.id) == abs_policy_id(policy_id(s[0])));
        if m::authorizer::has_error(&p, &req, &es) {
            lemma_list_view_cons(m::value::clone_str(&p.id), rest_ids, x);
            if x == abs_policy_id(policy_id(s[0])) {
                assert(in_category(s[0], Category::Error, req, es));
            }
        }
        if exists|j: int| 0 <= j < s.len() && abs_policy_id(policy_id(s[j])) == x && #[trigger] in_category(s[j], Category::Error, req, es) {
            let j = choose|j: int| 0 <= j < s.len() && abs_policy_id(policy_id(s[j])) == x && #[trigger] in_category(s[j], Category::Error, req, es);
            if j > 0 {
                assert(rest[j - 1] == s[j]);
                assert(in_category(rest[j - 1], Category::Error, req, es));
            }
        }
        if exists|j: int| 0 <= j < rest.len() && abs_policy_id(policy_id(rest[j])) == x && #[trigger] in_category(rest[j], Category::Error, req, es) {
            let j = choose|j: int| 0 <= j < rest.len() && abs_policy_id(policy_id(rest[j])) == x && #[trigger] in_category(rest[j], Category::Error, req, es);
            assert(s[j + 1] == rest[j]);
            assert(in_category(s[j + 1], Category::Error, req, es));
        }
    }
}

/// The abstraction of a set of IDs that is `categorized`
pub proof fn lemma_abs_categorized(
    ids: vstd::set::Set<PolicyID>,
    ps: Seq<Policy>,
    cat: Category,
    req: m::request::Request,
    es: m::entities::Entities,
    x: m::value::Str,
)
    requires
        ids.to_iset() == categorized(ps, ps.len() as int, cat, req, es),
    ensures
        ids.map(|id: PolicyID| abs_policy_id(id)).contains(x) <==> exists|j: int|
            0 <= j < ps.len() && abs_policy_id(policy_id(ps[j])) == x && #[trigger] in_category(ps[j], cat, req, es),
{
    if ids.map(|id: PolicyID| abs_policy_id(id)).contains(x) {
        let id = choose|id: PolicyID| ids.contains(id) && abs_policy_id(id) == x;
        assert(categorized(ps, ps.len() as int, cat, req, es).contains(id));
    }
    if exists|j: int| 0 <= j < ps.len() && abs_policy_id(policy_id(ps[j])) == x && #[trigger] in_category(ps[j], cat, req, es) {
        let j = choose|j: int| 0 <= j < ps.len() && abs_policy_id(policy_id(ps[j])) == x && #[trigger] in_category(ps[j], cat, req, es);
        assert(categorized(ps, ps.len() as int, cat, req, es).contains(policy_id(ps[j])));
        assert(ids.contains(policy_id(ps[j])));
    }
}

pub proof fn lemma_categorized_empty(ps: Seq<Policy>, cat: Category, req: m::request::Request, es: m::entities::Entities)
    ensures
        categorized(ps, 0, cat, req, es) == ISet::<PolicyID>::empty(),
{
    assert(categorized(ps, 0, cat, req, es) =~= ISet::<PolicyID>::empty());
}

/// A policy condition evaluates to a boolean or an error.
pub proof fn lemma_policy_eval_bool(p: Policy, req: m::request::Request, es: m::entities::Entities)
    ensures
        m::evaluator::evaluate(&abs_policy(p).condition, &req, &es) matches Ok(m::value::Value::Prim(m::value::Prim::Bool(_)))
            || m::evaluator::evaluate(&abs_policy(p).condition, &req, &es) is Err,
{
    let x = super::model::policy::policy_to_expr(&super::policy_abs::abs_linked_policy(p));
    assert(abs_policy(p).condition == x);
    assert(x is And || x matches m::expr::Expr::Lit(m::value::Prim::Bool(_)));
}

} // verus!

verus! {

/// `r` is the concretization of the partial response `p`
pub open spec fn concretized(p: PartialResponse, r: Response) -> bool {
    &&& (r.decision is Allow) == (!p.spec_satisfied_permits().is_empty() && p.spec_satisfied_forbids().is_empty())
    &&& r.diagnostics.reason@ == if p.spec_satisfied_forbids().is_empty() && p.spec_residual_forbids().is_empty() {
        p.spec_satisfied_permits()
    } else {
        p.spec_satisfied_forbids()
    }
    &&& error_ids(r.diagnostics.errors@) == p.spec_residual_forbids() + p.spec_residual_permits() + error_ids(p.spec_errors())
}

/// The keys of a sequence of entries
pub open spec fn entry_keys<K, V>(es: Seq<(K, V)>) -> Seq<K> {
    es.map_values(|e: (K, V)| e.0)
}

/// The keys of the entries of a map of policies
pub proof fn lemma_entry_keys<V>(m: std::collections::HashMap<PolicyID, V>, es: Seq<(PolicyID, V)>)
    requires
        es.to_set() == m@.kv_pairs(),
    ensures
        entry_keys(es).to_set() == m@.dom(),
        entry_keys(es).len() == es.len(),
        forall|i: int| 0 <= i < es.len() ==> #[trigger] entry_keys(es)[i] == es[i].0,
{
    let ks = entry_keys(es);
    assert forall|k: PolicyID| ks.to_set().contains(k) <==> m@.dom().contains(k) by {
        if m@.dom().contains(k) {
            assert(m@.kv_pairs().contains((k, m@[k])));
            let i = choose|i: int| 0 <= i < es.len() && es[i] == (k, m@[k]);
            assert(ks[i] == k);
        }
        if ks.to_set().contains(k) {
            let i = choose|i: int| 0 <= i < ks.len() && ks[i] == k;
            assert(es.to_set().contains(es[i]));
        }
    }
    assert(ks.to_set() =~= m@.dom());
}

/// Adding the next element of a sequence to the set of the elements before
/// it (and the last one gives the set of all the elements)
pub proof fn lemma_take_push_set<T>(s: Seq<T>, i: int)
    requires
        0 <= i < s.len(),
    ensures
        s.take(i + 1).to_set() == s.take(i).to_set().insert(s[i]),
        i + 1 == s.len() ==> s.take(i + 1) == s,
{
    assert(s.take(i + 1) =~= s.take(i).push(s[i]));
    s.take(i).lemma_push_to_set_commute(s[i]);
    if i + 1 == s.len() {
        assert(s.take(i + 1) =~= s);
    }
}

/// The erroring policies of errors pushed one by one, or appended
pub proof fn lemma_error_ids_push_set(v: Seq<AuthorizationError>, e: AuthorizationError)
    ensures
        error_ids(v.push(e)) == error_ids(v).insert(error_policy_id(e)),
{
    assert(v.push(e).map_values(|e: AuthorizationError| error_policy_id(e))
        =~= v.map_values(|e: AuthorizationError| error_policy_id(e)).push(error_policy_id(e)));
    (v.map_values(|e: AuthorizationError| error_policy_id(e))).lemma_push_to_set_commute(error_policy_id(e));
}

pub proof fn lemma_error_ids_append(a: Seq<AuthorizationError>, b: Seq<AuthorizationError>)
    ensures
        error_ids(a + b) == error_ids(a) + error_ids(b),
{
    assert((a + b).map_values(|e: AuthorizationError| error_policy_id(e))
        =~= a.map_values(|e: AuthorizationError| error_policy_id(e)) + b.map_values(|e: AuthorizationError| error_policy_id(e)));
    vstd::seq_lib::seq_to_set_distributes_over_add(a.map_values(|e: AuthorizationError| error_policy_id(e)), b.map_values(|e: AuthorizationError| error_policy_id(e)));
}

pub proof fn lemma_list_view_empty<T>(l: m::value::List<T>)
    ensures
        (l is Nil) == list_view(l).to_set().is_empty(),
{
    match l {
        m::value::List::Nil => {
            assert(list_view(l).to_set() =~= vstd::set::Set::<T>::empty());
        },
        m::value::List::Cons(x, rest) => {
            lemma_list_view_cons(x, *rest, x);
            assert(list_view(l).to_set().contains(x));
        },
    }
}

/// Concretizing a correctly categorized partial response gives the model's
/// response.
pub proof fn lemma_response(pr: PartialResponse, r: Response, ps: Seq<Policy>, req: m::request::Request, es: m::entities::Entities)
    requires
        partial_response_rel(pr, ps, req, es),
        (r.decision is Allow) == (!pr.spec_satisfied_permits().is_empty() && pr.spec_satisfied_forbids().is_empty()),
        r.diagnostics.reason@ == if pr.spec_satisfied_forbids().is_empty() && pr.spec_residual_forbids().is_empty() {
            pr.spec_satisfied_permits()
        } else {
            pr.spec_satisfied_forbids()
        },
        error_ids(r.diagnostics.errors@) == pr.spec_residual_forbids() + pr.spec_residual_permits() + error_ids(pr.spec_errors()),
    ensures
        response_rel(r, m::authorizer::is_authorized(&req, &es, &seq_to_list(ps.map_values(|p: Policy| abs_policy(p))))),
{
    let mps = seq_to_list(ps.map_values(|p: Policy| abs_policy(p)));
    let permits0 = m::authorizer::satisfied_policies(true, &mps, &req, &es);
    let forbids0 = m::authorizer::satisfied_policies(false, &mps, &req, &es);
    let errs0 = m::authorizer::error_policies(&mps, &req, &es);
    let permits = m::value::strs_canonicalize(permits0);
    let forbids = m::value::strs_canonicalize(forbids0);
    let errs = m::value::strs_canonicalize(errs0);
    lemma_strs_canonicalize_set(permits0);
    lemma_strs_canonicalize_set(forbids0);
    lemma_strs_canonicalize_set(errs0);
    let sp = pr.spec_satisfied_permits().map(|id: PolicyID| abs_policy_id(id));
    let sf = pr.spec_satisfied_forbids().map(|id: PolicyID| abs_policy_id(id));
    let se = error_ids(pr.spec_errors()).map(|id: PolicyID| abs_policy_id(id));
    assert forall|x: m::value::Str| sp.contains(x) == list_view(permits).to_set().contains(x) by {
        lemma_abs_categorized(pr.spec_satisfied_permits(), ps, Category::SatisfiedPermit, req, es, x);
        lemma_satisfied_policies_contents(true, ps, req, es, x);
    }
    assert forall|x: m::value::Str| sf.contains(x) == list_view(forbids).to_set().contains(x) by {
        lemma_abs_categorized(pr.spec_satisfied_forbids(), ps, Category::SatisfiedForbid, req, es, x);
        lemma_satisfied_policies_contents(false, ps, req, es, x);
    }
    assert(error_ids(pr.spec_errors()).to_iset() == categorized(ps, ps.len() as int, Category::Error, req, es));
    assert forall|x: m::value::Str| se.contains(x) == list_view(errs).to_set().contains(x) by {
        lemma_abs_categorized(error_ids(pr.spec_errors()), ps, Category::Error, req, es, x);
        lemma_error_policies_contents(ps, req, es, x);
    }
    assert(sp =~= list_view(permits).to_set());
    assert(sf =~= list_view(forbids).to_set());
    assert(se =~= list_view(errs).to_set());
    lemma_list_view_empty(permits);
    lemma_list_view_empty(forbids);
    assert(pr.spec_satisfied_permits().is_empty() == sp.is_empty()) by {
        if !pr.spec_satisfied_permits().is_empty() {
            let id = pr.spec_satisfied_permits().choose();
            assert(sp.contains(abs_policy_id(id)));
        }
    }
    assert(pr.spec_satisfied_forbids().is_empty() == sf.is_empty()) by {
        if !pr.spec_satisfied_forbids().is_empty() {
            let id = pr.spec_satisfied_forbids().choose();
            assert(sf.contains(abs_policy_id(id)));
        }
    }
    assert(pr.spec_residual_forbids() =~= vstd::set::Set::<PolicyID>::empty());
    assert(pr.spec_residual_permits() =~= vstd::set::Set::<PolicyID>::empty());
    assert(error_ids(r.diagnostics.errors@) =~= error_ids(pr.spec_errors()));
    if sp.is_empty() && sf.is_empty() {
        assert(r.diagnostics.reason@.map(|id: PolicyID| abs_policy_id(id)) =~= list_view(forbids).to_set());
    }
}

} // verus!
