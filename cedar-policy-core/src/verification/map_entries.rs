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

//! Entries of a `SmolStr`-keyed map sorted by key (`BTreeMap` iteration order).

use vstd::prelude::*;
use vstd::relations::*;

use super::trusted::*;
use smol_str::SmolStr;

verus! {

// ---------------------------------------------------------------------------
// The order of `str`
// ---------------------------------------------------------------------------

pub proof fn lemma_lex_cmp_refl(a: Seq<char>)
    ensures
        lex_cmp(a, a) is Equal,
    decreases a.len(),
{
    if a.len() > 0 {
        lemma_lex_cmp_refl(a.subrange(1, a.len() as int));
    }
}

/// `lex_cmp` is antisymmetric (`Less` one way is `Greater` the other way).
pub proof fn lemma_lex_cmp_flip(a: Seq<char>, b: Seq<char>)
    ensures
        lex_cmp(a, b) is Less <==> lex_cmp(b, a) is Greater,
        lex_cmp(a, b) is Equal <==> lex_cmp(b, a) is Equal,
    decreases a.len(),
{
    if a.len() > 0 && b.len() > 0 && (a[0] as u32) == (b[0] as u32) {
        lemma_lex_cmp_flip(a.subrange(1, a.len() as int), b.subrange(1, b.len() as int));
    }
}

/// `lex_cmp` is `Equal` only on equal sequences.
pub proof fn lemma_lex_cmp_eq(a: Seq<char>, b: Seq<char>)
    requires
        lex_cmp(a, b) is Equal,
    ensures
        a == b,
    decreases a.len(),
{
    if a.len() > 0 && b.len() > 0 {
        let a1 = a.subrange(1, a.len() as int);
        let b1 = b.subrange(1, b.len() as int);
        lemma_lex_cmp_eq(a1, b1);
        assert(a[0] == b[0]);
        assert(a =~= seq![a[0]] + a1);
        assert(b =~= seq![b[0]] + b1);
    } else {
        assert(a =~= b);
    }
}

/// `lex_cmp` is transitive.
pub proof fn lemma_lex_cmp_trans(a: Seq<char>, b: Seq<char>, c: Seq<char>)
    requires
        !(lex_cmp(a, b) is Greater),
        !(lex_cmp(b, c) is Greater),
    ensures
        !(lex_cmp(a, c) is Greater),
        lex_cmp(a, b) is Less || lex_cmp(b, c) is Less ==> lex_cmp(a, c) is Less,
    decreases a.len(),
{
    if a.len() > 0 && b.len() > 0 && c.len() > 0 && (a[0] as u32) == (b[0] as u32) && (b[0] as u32) == (c[0] as u32) {
        lemma_lex_cmp_trans(
            a.subrange(1, a.len() as int),
            b.subrange(1, b.len() as int),
            c.subrange(1, c.len() as int),
        );
    }
}

/// The order of `str` on `SmolStr`s
pub open spec fn smol_leq(a: SmolStr, b: SmolStr) -> bool {
    !(lex_cmp(smol_view(a), smol_view(b)) is Greater)
}

pub proof fn lemma_smol_leq_total()
    ensures
        total_ordering(|a: SmolStr, b: SmolStr| smol_leq(a, b)),
{
    let leq = |a: SmolStr, b: SmolStr| smol_leq(a, b);
    assert forall|a: SmolStr| #[trigger] leq(a, a) by {
        lemma_lex_cmp_refl(smol_view(a));
    }
    assert forall|a: SmolStr, b: SmolStr| #[trigger] leq(a, b) && #[trigger] leq(b, a) implies a == b by {
        lemma_lex_cmp_flip(smol_view(a), smol_view(b));
        lemma_lex_cmp_eq(smol_view(a), smol_view(b));
        axiom_smol_view_injective(a);
        axiom_smol_view_injective(b);
    }
    assert forall|a: SmolStr, b: SmolStr, c: SmolStr| #[trigger] leq(a, b) && #[trigger] leq(b, c) implies leq(a, c) by {
        lemma_lex_cmp_trans(smol_view(a), smol_view(b), smol_view(c));
    }
    assert forall|a: SmolStr, b: SmolStr| #[trigger] leq(a, b) || leq(b, a) by {
        lemma_lex_cmp_flip(smol_view(a), smol_view(b));
    }
    assert(reflexive(leq));
    assert(antisymmetric(leq));
    assert(transitive(leq));
    assert(strongly_connected(leq));
}

// ---------------------------------------------------------------------------
// Sorted entries
// ---------------------------------------------------------------------------

/// Is `s` strictly increasing by key (in the order of `str`)?
pub open spec fn sorted_by_key<V>(s: Seq<(SmolStr, V)>) -> bool {
    forall|i: int, j: int|
        #![trigger s[i], s[j]]
        0 <= i < j < s.len() ==> lex_cmp(smol_view(s[i].0), smol_view(s[j].0)) is Less
}

/// The keys of a map, sorted
pub open spec fn sorted_keys<V>(m: Map<SmolStr, V>) -> Seq<SmolStr> {
    m.dom().to_sorted_seq(|a: SmolStr, b: SmolStr| smol_leq(a, b))
}

/// The entries of a map, sorted by key
pub open spec fn sorted_entries<V>(m: Map<SmolStr, V>) -> Seq<(SmolStr, V)> {
    sorted_keys(m).map_values(|k: SmolStr| (k, m[k]))
}

pub proof fn lemma_sorted_keys<V>(m: Map<SmolStr, V>)
    ensures
        sorted_keys(m).to_set() == m.dom(),
        sorted_keys(m).no_duplicates(),
        sorted_keys(m).len() == m.dom().len(),
        forall|i: int, j: int|
            #![trigger sorted_keys(m)[i], sorted_keys(m)[j]]
            0 <= i < j < sorted_keys(m).len() ==> lex_cmp(smol_view(sorted_keys(m)[i]), smol_view(sorted_keys(m)[j])) is Less,
{
    broadcast use vstd::seq_lib::group_to_multiset_ensures;

    let leq = |a: SmolStr, b: SmolStr| smol_leq(a, b);
    lemma_smol_leq_total();
    let s0 = m.dom().to_seq();
    m.dom().lemma_to_seq_to_set_id();
    m.dom().lemma_to_seq_no_duplicates();
    m.dom().lemma_to_seq_len();
    s0.lemma_sort_by_ensures(leq);
    let s = s0.sort_by(leq);
    assert(s == sorted_keys(m));
    assert(s.len() == s0.len()) by {
        s.to_multiset_ensures();
        s0.to_multiset_ensures();
    }
    assert(s.to_multiset() == s0.to_multiset());
    assert forall|x: SmolStr| s.contains(x) <==> s0.contains(x) by {
        s.to_multiset_ensures();
        s0.to_multiset_ensures();
        assert(s.to_multiset().count(x) == s0.to_multiset().count(x));
    }
    assert(s.to_set() =~= s0.to_set());
    assert(s.no_duplicates()) by {
        s0.lemma_multiset_has_no_duplicates();
        s.lemma_multiset_has_no_duplicates_conv();
    }
    assert forall|i: int, j: int|
        #![trigger s[i], s[j]]
        0 <= i < j < s.len() implies lex_cmp(smol_view(s[i]), smol_view(s[j])) is Less by {
        assert(leq(s[i], s[j]));
        if lex_cmp(smol_view(s[i]), smol_view(s[j])) is Equal {
            lemma_lex_cmp_eq(smol_view(s[i]), smol_view(s[j]));
            axiom_smol_view_injective(s[i]);
            axiom_smol_view_injective(s[j]);
        }
    }
}

/// The sorted entries of a map are its entries, sorted by key.
pub proof fn lemma_sorted_entries<V>(m: Map<SmolStr, V>)
    ensures
        sorted_entries(m).to_set() == m.kv_pairs(),
        sorted_by_key(sorted_entries(m)),
        sorted_entries(m).len() == m.dom().len(),
        forall|i: int| 0 <= i < sorted_entries(m).len() ==> {
            &&& m.dom().contains(#[trigger] sorted_entries(m)[i].0)
            &&& sorted_entries(m)[i].1 == m[sorted_entries(m)[i].0]
        },
{
    lemma_sorted_keys(m);
    let ks = sorted_keys(m);
    let s = sorted_entries(m);
    assert forall|i: int| 0 <= i < s.len() implies m.dom().contains(#[trigger] s[i].0) && s[i].1 == m[s[i].0] by {
        assert(ks.to_set().contains(ks[i]));
    }
    assert forall|e: (SmolStr, V)| s.to_set().contains(e) <==> m.kv_pairs().contains(e) by {
        if s.to_set().contains(e) {
            let i = choose|i: int| 0 <= i < s.len() && s[i] == e;
            assert(m.dom().contains(s[i].0));
        }
        if m.kv_pairs().contains(e) {
            assert(ks.to_set().contains(e.0));
            let i = choose|i: int| 0 <= i < ks.len() && ks[i] == e.0;
            assert(s[i] == e);
        }
    }
    assert(s.to_set() =~= m.kv_pairs());
}

} // verus!
