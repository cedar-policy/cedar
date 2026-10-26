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

//! Lemmas about the abstraction functions.

use vstd::prelude::*;

use super::abs::*;
use super::model as m;
use super::trusted::*;
use super::value_abs::*;
use super::expr_abs::*;
use super::map_entries::*;
use crate::ast::*;
use crate::ast::{Integer, Set};
use smol_str::SmolStr;

verus! {

/// The abstraction of a set, element by element
pub broadcast proof fn lemma_abs_set_index(s: Set, i: int)
    requires
        0 <= i < set_elems(s).len(),
    ensures
        list_view(abs_set(s)).len() == set_elems(s).len(),
        list_view(abs_set(s))[i] == abs_value(#[trigger] set_elems(s)[i]),
{
    broadcast use super::value_abs::lemma_abs_set_elems;
}

// ---------------------------------------------------------------------------
// Sequences sorted by (`SmolStr`) key
// ---------------------------------------------------------------------------

/// `lex_cmp` is asymmetric.
pub proof fn lemma_lex_cmp_asym(a: Seq<char>, b: Seq<char>)
    ensures
        lex_cmp(a, b) is Less ==> lex_cmp(b, a) is Greater,
    decreases a.len(),
{
    if a.len() > 0 && b.len() > 0 && (a[0] as u32) == (b[0] as u32) {
        lemma_lex_cmp_asym(a.subrange(1, a.len() as int), b.subrange(1, b.len() as int));
    }
}

/// Keys of a key-sorted sequence are strictly ordered, hence distinct.
pub proof fn lemma_sorted_by_key<V>(s: Seq<(SmolStr, V)>, i: int, j: int)
    requires
        sorted_by_key(s),
        0 <= i < j < s.len(),
    ensures
        lex_cmp(smol_view(s[i].0), smol_view(s[j].0)) is Less,
        !(lex_cmp(smol_view(s[j].0), smol_view(s[i].0)) is Less),
        s[i].0 != s[j].0,
{
    lemma_lex_cmp_asym(smol_view(s[i].0), smol_view(s[j].0));
    lemma_lex_cmp_asym(smol_view(s[j].0), smol_view(s[i].0));
}

/// A `vstd` `increasing_seq` of `SmolStr`s is increasing in the order of `str`.
pub proof fn lemma_increasing_seq_smol(t: Seq<SmolStr>)
    requires
        vstd::std_specs::btree::increasing_seq(t),
    ensures
        forall|i: int, j: int|
            #![trigger t[i], t[j]]
            0 <= i < j < t.len() ==> lex_cmp(smol_view(t[i]), smol_view(t[j])) is Less,
{
    broadcast use axiom_smol_str_obeys_cmp, vstd::std_specs::btree::axiom_increasing_seq_meaning;
    assert forall|i: int, j: int|
        #![trigger t[i], t[j]]
        0 <= i < j < t.len() implies lex_cmp(smol_view(t[i]), smol_view(t[j])) is Less by {
        assert(vstd::std_specs::cmp::OrdSpec::cmp_spec(&t[i], &t[j]) is Less);
        axiom_smol_str_cmp(t[i], t[j]);
    }
}

proof fn lemma_sorted_unique_prefix<V>(s1: Seq<(SmolStr, V)>, s2: Seq<(SmolStr, V)>, n: int)
    requires
        s1.to_set() == s2.to_set(),
        sorted_by_key(s1),
        sorted_by_key(s2),
        0 <= n <= s1.len(),
        n <= s2.len(),
    ensures
        forall|i: int| 0 <= i < n ==> s1[i] == s2[i],
    decreases n,
{
    if n > 0 {
        let m = n - 1;
        lemma_sorted_unique_prefix(s1, s2, m);
        // s1[m] occurs in s2 at some index j, and s2[m] in s1 at some index k.
        assert(s2.to_set().contains(s1[m]));
        let j = choose|j: int| 0 <= j < s2.len() && s2[j] == s1[m];
        assert(s1.to_set().contains(s2[m]));
        let k = choose|k: int| 0 <= k < s1.len() && s1[k] == s2[m];
        if j < m {
            assert(s1[j] == s2[j]);
            lemma_sorted_by_key(s1, j, m);
        } else if k < m {
            assert(s1[k] == s2[k]);
            lemma_sorted_by_key(s2, k, m);
        } else if j > m && k > m {
            lemma_sorted_by_key(s2, m, j);
            lemma_sorted_by_key(s1, m, k);
        }
    }
}

/// A key-sorted sequence is determined by its set of entries.
pub proof fn lemma_sorted_entries_unique<V>(s1: Seq<(SmolStr, V)>, s2: Seq<(SmolStr, V)>)
    requires
        s1.to_set() == s2.to_set(),
        sorted_by_key(s1),
        sorted_by_key(s2),
    ensures
        s1 == s2,
{
    if s1.len() <= s2.len() {
        lemma_sorted_unique_prefix(s1, s2, s1.len() as int);
        if s1.len() < s2.len() {
            let m = s1.len() as int;
            assert(s1.to_set().contains(s2[m]));
            let k = choose|k: int| 0 <= k < s1.len() && s1[k] == s2[m];
            assert(s2[k] == s1[k]);
            lemma_sorted_by_key(s2, k, m);
        }
    } else {
        lemma_sorted_unique_prefix(s1, s2, s2.len() as int);
        let m = s2.len() as int;
        assert(s2.to_set().contains(s1[m]));
        let k = choose|k: int| 0 <= k < s2.len() && s2[k] == s1[m];
        assert(s2[k] == s1[k]);
        lemma_sorted_by_key(s1, k, m);
    }
    assert(s1 =~= s2);
}

/// `expr_entries(r)` is the unique key-sorted sequence of `r`'s entries, so it
/// is `r`'s iteration order.
pub proof fn lemma_expr_entries_unique(r: std::collections::BTreeMap<SmolStr, Expr>, s: Seq<(SmolStr, Expr)>)
    requires
        s.to_set() == r@.kv_pairs(),
        sorted_by_key(s),
    ensures
        s == expr_entries(r),
{
    lemma_expr_entries(r);
    lemma_sorted_entries_unique(s, expr_entries(r));
}

// ---------------------------------------------------------------------------
// Evaluating set and record literals element by element
// ---------------------------------------------------------------------------

/// The production values `vals` are the (modeled) results of evaluating the
/// first `vals.len()` expressions of `xs` in the model.
pub closed spec fn evaluated_prefix(xs: m::value::List<m::expr::Expr>, req: m::request::Request, es: m::entities::Entities, vals: Seq<Value>) -> bool {
    &&& vals.len() <= list_view(xs).len()
    &&& forall|j: int| 0 <= j < vals.len() ==> modeled(#[trigger] vals[j]) && m::evaluator::evaluate(
        &list_view(xs)[j],
        &req,
        &es,
    ) == Ok::<m::value::Value, m::value::Error>(abs_value(vals[j]))
}

pub proof fn lemma_evaluated_prefix_empty(xs: m::value::List<m::expr::Expr>, req: m::request::Request, es: m::entities::Entities)
    ensures
        evaluated_prefix(xs, req, es, Seq::empty()),
{
}

/// Evaluating the next expression `x`: if it fails, then so does
/// `evaluate_list`.
pub proof fn lemma_evaluated_prefix_err(xs: m::value::List<m::expr::Expr>, req: m::request::Request, es: m::entities::Entities, vals: Seq<Value>, x: m::expr::Expr)
    requires
        evaluated_prefix(xs, req, es, vals),
        vals.len() < list_view(xs).len(),
        list_view(xs)[vals.len() as int] == x,
    ensures
        m::evaluator::evaluate(&x, &req, &es) is Err ==> m::evaluator::evaluate_list(&xs, &req, &es) is Err,
{
    super::model_lemmas::lemma_evaluate_list(xs, req, es);
    if m::evaluator::evaluate(&x, &req, &es) is Err {
        assert(!(m::evaluator::evaluate(&list_view(xs)[vals.len() as int], &req, &es) is Ok));
    }
}

/// Evaluating the next expression `x`, if it succeeds with `v`
pub proof fn lemma_evaluated_prefix_push(xs: m::value::List<m::expr::Expr>, req: m::request::Request, es: m::entities::Entities, vals: Seq<Value>, x: m::expr::Expr, v: Value)
    requires
        evaluated_prefix(xs, req, es, vals),
        vals.len() < list_view(xs).len(),
        list_view(xs)[vals.len() as int] == x,
        modeled(v),
        m::evaluator::evaluate(&x, &req, &es) == Ok::<m::value::Value, m::value::Error>(abs_value(v)),
    ensures
        evaluated_prefix(xs, req, es, vals.push(v)),
{
    assert forall|j: int| 0 <= j < vals.push(v).len() implies modeled(#[trigger] vals.push(v)[j]) && m::evaluator::evaluate(
        &list_view(xs)[j],
        &req,
        &es,
    ) == Ok::<m::value::Value, m::value::Error>(abs_value(vals.push(v)[j])) by {
        if j < vals.len() {
            assert(vals.push(v)[j] == vals[j]);
        }
    }
}

/// All expressions evaluated successfully
pub proof fn lemma_evaluated_prefix_full(xs: m::value::List<m::expr::Expr>, req: m::request::Request, es: m::entities::Entities, vals: Seq<Value>)
    requires
        evaluated_prefix(xs, req, es, vals),
        vals.len() == list_view(xs).len(),
    ensures
        (forall|j: int| 0 <= j < vals.len() ==> #[trigger] modeled(vals[j])),
        m::evaluator::evaluate_list(&xs, &req, &es) == Ok::<m::value::List<m::value::Value>, m::value::Error>(
            seq_to_list(vals.map_values(|v: Value| abs_value(v))),
        ),
{
    super::model_lemmas::lemma_evaluate_list(xs, req, es);
    assert forall|j: int| 0 <= j < list_view(xs).len() implies #[trigger] m::evaluator::evaluate(&list_view(xs)[j], &req, &es) is Ok by {
        assert(modeled(vals[j]));
    }
    let vs = m::evaluator::evaluate_list(&xs, &req, &es)->Ok_0;
    assert forall|j: int| 0 <= j < vals.len() implies #[trigger] list_view(vs)[j] == abs_value(vals[j]) by {
        assert(modeled(vals[j]));
        assert(m::evaluator::evaluate(&list_view(xs)[j], &req, &es) == Ok::<m::value::Value, m::value::Error>(list_view(vs)[j]));
    }
    assert(list_view(vs) =~= vals.map_values(|v: Value| abs_value(v)));
    super::model_lemmas::lemma_seq_to_list_list_view(vs);
}

/// The production pairs `pairs` are the (modeled) results of evaluating the
/// first `pairs.len()` attributes of `axs` in the model.
pub closed spec fn evaluated_attrs_prefix(
    axs: m::value::List<(m::value::Str, m::expr::Expr)>,
    req: m::request::Request,
    es: m::entities::Entities,
    pairs: Seq<(SmolStr, Value)>,
) -> bool {
    &&& pairs.len() <= list_view(axs).len()
    &&& forall|j: int| 0 <= j < pairs.len() ==> {
        &&& modeled((#[trigger] pairs[j]).1)
        &&& abs_str(pairs[j].0) == list_view(axs)[j].0
        &&& m::evaluator::evaluate(&list_view(axs)[j].1, &req, &es) == Ok::<m::value::Value, m::value::Error>(abs_value(pairs[j].1))
    }
}

pub proof fn lemma_evaluated_attrs_prefix_empty(axs: m::value::List<(m::value::Str, m::expr::Expr)>, req: m::request::Request, es: m::entities::Entities)
    ensures
        evaluated_attrs_prefix(axs, req, es, Seq::empty()),
{
}

/// Evaluating the next attribute `x`: if it fails, then so does
/// `evaluate_attrs`.
pub proof fn lemma_evaluated_attrs_prefix_err(
    axs: m::value::List<(m::value::Str, m::expr::Expr)>,
    req: m::request::Request,
    es: m::entities::Entities,
    pairs: Seq<(SmolStr, Value)>,
    x: m::expr::Expr,
)
    requires
        evaluated_attrs_prefix(axs, req, es, pairs),
        pairs.len() < list_view(axs).len(),
        list_view(axs)[pairs.len() as int].1 == x,
    ensures
        m::evaluator::evaluate(&x, &req, &es) is Err ==> m::evaluator::evaluate_attrs(&axs, &req, &es) is Err,
{
    super::model_lemmas::lemma_evaluate_attrs(axs, req, es);
    if m::evaluator::evaluate(&x, &req, &es) is Err {
        assert(!(m::evaluator::evaluate(&list_view(axs)[pairs.len() as int].1, &req, &es) is Ok));
    }
}

/// Evaluating the next attribute `(k, x)`, if it succeeds with `v`
pub proof fn lemma_evaluated_attrs_prefix_push(
    axs: m::value::List<(m::value::Str, m::expr::Expr)>,
    req: m::request::Request,
    es: m::entities::Entities,
    pairs: Seq<(SmolStr, Value)>,
    k: SmolStr,
    x: m::expr::Expr,
    v: Value,
)
    requires
        evaluated_attrs_prefix(axs, req, es, pairs),
        pairs.len() < list_view(axs).len(),
        list_view(axs)[pairs.len() as int] == (abs_str(k), x),
        modeled(v),
        m::evaluator::evaluate(&x, &req, &es) == Ok::<m::value::Value, m::value::Error>(abs_value(v)),
    ensures
        evaluated_attrs_prefix(axs, req, es, pairs.push((k, v))),
{
    let p = pairs.push((k, v));
    assert forall|j: int| 0 <= j < p.len() implies {
        &&& modeled((#[trigger] p[j]).1)
        &&& abs_str(p[j].0) == list_view(axs)[j].0
        &&& m::evaluator::evaluate(&list_view(axs)[j].1, &req, &es) == Ok::<m::value::Value, m::value::Error>(abs_value(p[j].1))
    } by {
        if j < pairs.len() {
            assert(p[j] == pairs[j]);
        }
    }
}

/// All attributes evaluated successfully
pub proof fn lemma_evaluated_attrs_prefix_full(
    axs: m::value::List<(m::value::Str, m::expr::Expr)>,
    req: m::request::Request,
    es: m::entities::Entities,
    pairs: Seq<(SmolStr, Value)>,
)
    requires
        evaluated_attrs_prefix(axs, req, es, pairs),
        pairs.len() == list_view(axs).len(),
    ensures
        (forall|j: int| 0 <= j < pairs.len() ==> #[trigger] modeled(pairs[j].1)),
        m::evaluator::evaluate_attrs(&axs, &req, &es) == Ok::<m::value::Attrs, m::value::Error>(
            seq_to_list(pairs.map_values(|e: (SmolStr, Value)| (abs_str(e.0), abs_value(e.1)))),
        ),
{
    super::model_lemmas::lemma_evaluate_attrs(axs, req, es);
    assert forall|j: int| 0 <= j < pairs.len() implies #[trigger] modeled(pairs[j].1) by {
        assert(modeled(pairs[j].1));
    }
    assert forall|j: int| 0 <= j < list_view(axs).len() implies #[trigger] m::evaluator::evaluate(&list_view(axs)[j].1, &req, &es) is Ok by {
        assert(modeled(pairs[j].1));
    }
    let avs = m::evaluator::evaluate_attrs(&axs, &req, &es)->Ok_0;
    assert forall|j: int| 0 <= j < pairs.len() implies #[trigger] list_view(avs)[j] == (abs_str(pairs[j].0), abs_value(pairs[j].1)) by {
        assert(modeled(pairs[j].1));
        assert(m::evaluator::evaluate(&list_view(axs)[j].1, &req, &es) == Ok::<m::value::Value, m::value::Error>(list_view(avs)[j].1));
    }
    assert(list_view(avs) =~= pairs.map_values(|e: (SmolStr, Value)| (abs_str(e.0), abs_value(e.1))));
    super::model_lemmas::lemma_seq_to_list_list_view(avs);
}

pub broadcast group group_lemmas {
    lemma_abs_set_index,
}

} // verus!
