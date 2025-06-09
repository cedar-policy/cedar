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

//! Extra utilties for Verus verification

#![allow(missing_debug_implementations)] // vstd types Seq/Set/Map don't impl Debug
#![allow(missing_docs)] // don't want docs on `assume_specification` etc

use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::hash::Hash;
#[cfg(verus_keep_ghost)]
#[allow(unused_imports)]
use vstd::std_specs::hash::*;
use vstd::{assert_seqs_equal, assert_sets_equal, calc, prelude::*};

// Specification macros

#[allow(unused_macros)]
macro_rules! clone_spec_for {
    ($type:ty) => {
        verus! {
            pub assume_specification[ <$type as Clone>::clone ](this: &$type) -> (other: $type)
                ensures this@ == other@;
        }
    };
}
#[allow(unused_imports)]
pub(crate) use clone_spec_for;

#[allow(unused_macros)]
macro_rules! empty_clone_spec_for {
    ($type:ty) => {
        verus! {
            pub assume_specification[ <$type as Clone>::clone ](this: &$type) -> (other: $type);
        }
    };
}
#[allow(unused_imports)]
pub(crate) use empty_clone_spec_for;

// Specifications for external types

verus! {

// SmolStr

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExSmolStr(SmolStr);

clone_spec_for!(SmolStr);

/// Like `impl View for SmolStr`, but we can't write that explicitly due to trait orphan rules
pub trait SmolStrView {
    type V;
    spec fn view(&self) -> Self::V;
}

impl SmolStrView for SmolStr {
    type V = Seq<char>;
    uninterp spec fn view(&self) -> Self::V;
}



// BTreeMap

#[verifier::external_type_specification]
#[verifier::external_body]
#[verifier::accept_recursive_types(K)]
#[verifier::accept_recursive_types(V)]
#[verifier::reject_recursive_types(A)]
pub struct ExBTreeMap<K, V, A: std::alloc::Allocator + Clone>(BTreeMap<K,V,A>);

// pub assume_specification<K: Clone, V: Clone, A: std::alloc::Allocator + Clone>
//     [ <BTreeMap::<K, V, A> as Clone>:: clone ](this: &BTreeMap<K, V, A>) -> (other: BTreeMap<K, V, A>)
//     ensures other.view() == this.view();


/// Like `impl<K:View, V:View> View for BTreeMap<K,V>`,
/// but we can't write that explicitly due to trait orphan rules
pub trait BTreeMapView {
    type V;
    spec fn view(&self) -> Self::V;
}

// Doesn't work for BTreeMap<SmolStr, V> because SmolStr doesn't implement View, but SmolStrView;
// so we just manually implement BTreeMapView for each map type we want
// impl<K:View, V:View> BTreeMapView for BTreeMap<K, V> {
//     type V = Map<K::V, V::V>;
//     uninterp spec fn view(&self) -> Self::V; // plan to just axiomatize it for now
// }

} // verus!

// Helper data structures (should be in vstd)

verus! {

/// A statically finite set (backed internally by a `Seq`)
/// needed due to https://verus-lang.zulipchat.com/#narrow/channel/399078-help/topic/Recursive.20structure.20with.20vstd.20.60Set.60/with/518139335
/// should eventually be replaced with the vstd finite set from https://github.com/verus-lang/verus/tree/jonh/sets-typed-finite
/// but that branch doesn't build yet
#[verifier::accept_recursive_types(T)]
pub struct FiniteSet<T> {
    s: Seq<T>,
}


impl<T> FiniteSet<T> {
    #[verifier::type_invariant]
    pub closed spec fn no_duplicates(self) -> bool {
        self.s.no_duplicates()
    }

}


}

// Helper functions (should be in vstd)

verus! {

#[verifier::external_body]
pub fn hash_set_from_vec<T: Eq + Hash>(vec: Vec<T>) -> (hset: HashSet<T>)
{
    HashSet::from_iter(vec)
}

#[verifier::external_body]
pub fn vec_is_empty<T>(v: &Vec<T>) -> (res: bool)
    ensures
        res <==> v@.len() == 0
{
    v.is_empty()
}

// #[cfg(verus_keep_ghost)]
// pub assume_specification<T, A: std::alloc::Allocator>[ Vec::<T>::is_empty ](
//     v: &Vec<T, A>,
// ) -> (res: bool)
//     ensures
//         res <==> v@.len() == 0,
// ;

// Analogous to Lean's `List.filterMap` (https://lean-lang.org/doc/reference/latest//Basic-Types/Linked-Lists/#List___filterMap)
pub open spec fn seq_filter_map_option<A, B>(s: Seq<A>, f: spec_fn(A) -> Option<B>) -> Seq<B> {
    s.map_values(f)
     .filter(|x: Option<B>| x is Some)
     .map_values(|x: Option<B>| x.unwrap())
}

// Like `seq_filter_map_option` but operating on Sets instead
pub open spec fn set_filter_map_option<A, B>(s: Set<A>, f: spec_fn(A) -> Option<B>) -> Set<B> {
    s.map(f)
     .filter(|x: Option<B>| x is Some)
     .map(|x: Option<B>| x.unwrap())
}


} // verus!

// Helper lemmas (should be in vstd)

verus! {

pub proof fn lemma_set_map_finite_stays_finite<A,B>(s: Set<A>, f: spec_fn(A)->B)
    requires s.finite(),
    ensures s.map(f).finite(),
{
    admit();
}

pub proof fn lemma_set_to_seq_to_set<T>(set: Set<T>)
    requires set.finite()
    ensures set.to_seq().to_set() == set,
    decreases set.len(),
{
    if set.len() == 0 {
        assert(set == Set::<T>::empty());
        assert(set.to_seq() == Seq::<T>::empty());
        assert(set.to_seq().to_set() == Set::<T>::empty());
    } else {
        let x = set.choose();
        lemma_set_to_seq_to_set(set.remove(x));
        assert(Seq::<T>::empty().push(x).to_set() == Set::<T>::empty().insert(x)) by {
            vstd::seq_lib::lemma_seq_contains_after_push(Seq::<T>::empty(), x, x);
            vstd::assert_sets_equal!(Seq::<T>::empty().push(x).to_set() == set![x]);
        }
        assert(set.to_seq().to_set() == (Seq::<T>::empty().push(x) + set.remove(x).to_seq()).to_set());
        assert(set == (Set::<T>::empty().insert(x)).union(set.remove(x).to_seq().to_set()));
        vstd::assert_sets_equal!(
            (Seq::<T>::empty().push(x) + set.remove(x).to_seq()).to_set()
            ==
            (Seq::<T>::empty().push(x).to_set()).union(set.remove(x).to_seq().to_set()),
            elem => {
                if elem == x {
                    vstd::seq_lib::lemma_seq_concat_contains_all_elements(Seq::<T>::empty().push(x), set.remove(x).to_seq(), elem);
                } else {
                    if ((Seq::<T>::empty().push(x) + set.remove(x).to_seq()).to_set().contains(elem)) {
                        assert((Seq::<T>::empty().push(x).to_set()).union(set.remove(x).to_seq().to_set()).contains(elem));
                    };
                    if ((Seq::<T>::empty().push(x).to_set()).union(set.remove(x).to_seq().to_set()).contains(elem)) {
                        vstd::seq_lib::lemma_seq_concat_contains_all_elements(Seq::<T>::empty().push(x), set.remove(x).to_seq(), elem);
                    };
                }
            }
        );
    }
}

pub proof fn lemma_seq_set_map<A,B>(st: Set<A>, sq: Seq<A>, f: spec_fn(A) -> B)
    requires
        st.finite(),
        st == sq.to_set(),
    ensures
        st.map(f) == sq.map_values(f).to_set(),
    decreases st.len()
{
    admit()
}

pub proof fn lemma_seq_set_filter<A>(st: Set<A>, sq: Seq<A>, f: spec_fn(A) -> bool)
    requires
        st.finite(),
        st == sq.to_set(),
    ensures
        st.filter(f) == sq.filter(f).to_set(),
{
    admit()
}


pub proof fn lemma_set_seq_filter_map_option<A, B>(st: Set<A>, f: spec_fn(A) -> Option<B>)
    requires
        st.finite(),
    ensures
        set_filter_map_option(st,f) == seq_filter_map_option(st.to_seq(), f).to_set(),
    decreases st.len(),
{
    let sq = st.to_seq();
    assert(st == sq.to_set()) by { lemma_set_to_seq_to_set(st) };
    lemma_seq_set_map(st, sq, f);
    let st_map = st.map(f);
    let sq_map = sq.map_values(f);
    lemma_seq_set_filter(st_map, sq_map, |x: Option<B>| x is Some);
    let st_map_filter = st_map.filter(|x: Option<B>| x is Some);
    let sq_map_filter = sq_map.filter(|x: Option<B>| x is Some);
    lemma_seq_set_map(st_map_filter, sq_map_filter, |x: Option<B>| x.unwrap());
}

pub proof fn lemma_seq_filter_map_option_add<A,B>(s: Seq<A>, f: spec_fn(A) -> Option<B>, a: A)
    requires f(a) is Some,
    ensures
        seq_filter_map_option(s.push(a), f) == seq_filter_map_option(s, f).push(f(a).unwrap()),
    decreases s.len(),
{
    calc! { (==)
        seq_filter_map_option(s.push(a), f); {}
        (s.push(a)).map_values(f).filter(|x: Option<B>| x is Some).map_values(|x: Option<B>| x.unwrap());
            { lemma_seq_map_values_append(s, f, a) }
        (s.map_values(f).push(f(a))).filter(|x: Option<B>| x is Some).map_values(|x: Option<B>| x.unwrap());
            { lemma_seq_filter_values_append(s.map_values(f), |x: Option<B>| x is Some, f(a)) }
        (s.map_values(f).filter(|x: Option<B>| x is Some)).push(f(a)).map_values(|x: Option<B>| x.unwrap());
            { lemma_seq_map_values_append(s.map_values(f).filter(|x: Option<B>| x is Some), |x: Option<B>| x.unwrap(), f(a)) }
        (s.map_values(f).filter(|x: Option<B>| x is Some).map_values(|x: Option<B>| x.unwrap())).push(f(a).unwrap()); {}
        seq_filter_map_option(s, f).push(f(a).unwrap());
    }
}

pub proof fn lemma_seq_map_values_append<A,B>(s: Seq<A>, f: spec_fn(A) -> B, a: A)
    ensures
        (s.push(a)).map_values(f) == s.map_values(f).push(f(a)),
    decreases s.len(),
{
    let s_push_a = s.push(a);
    assert(s_push_a.map_values(f) == Seq::new(s_push_a.len(), |i: int| f(s_push_a[i])));
    assert_seqs_equal!(s_push_a.map_values(f) == s.map_values(f).push(f(a)), i => {
        if 0 <= i < s.len() {
            assert(s_push_a.map_values(f)[i] == f(s_push_a[i]));
            assert(s.map_values(f).push(f(a))[i] == f(s_push_a[i]));
        } else {
            assert(s_push_a.map_values(f)[i] == f(a));
            assert(s.map_values(f).push(f(a))[i] == f(a));
        }
    });
}

pub proof fn lemma_seq_filter_values_append<A>(s: Seq<A>, f: spec_fn(A) -> bool, a: A)
    requires f(a) == true
    ensures
        (s.push(a)).filter(f) == s.filter(f).push(a),
{
    reveal_with_fuel(Seq::filter, 1);
    let s_push_a = s.push(a);
    assert(s_push_a.last() == a);
    assert(s_push_a.drop_last() == s);
    assert(s_push_a.drop_last().filter(f) == s.filter(f));
    assert(s_push_a.drop_last().filter(f).push(s_push_a.last()) == s.filter(f).push(a));
    assert(s_push_a.filter(f) == s_push_a.drop_last().filter(f).push(s_push_a.last()));
}

pub proof fn lemma_seq_take_skip_add<A>(s: Seq<A>, n: int)
    requires 0 <= n <= s.len(),
    ensures s == s.take(n) + s.skip(n)
{
    assert_seqs_equal!(s.take(n) + s.skip(n) == s);
}

pub broadcast proof fn lemma_seq_map_values_distributes_over_add<A,B>(s1: Seq<A>, s2: Seq<A>, f: spec_fn(A) -> B)
    ensures #[trigger] (s1.map_values(f) + s2.map_values(f)) == #[trigger] (s1 + s2).map_values(f)
{
    assert_seqs_equal!(s1.map_values(f) + s2.map_values(f) == (s1 + s2).map_values(f));
}

pub proof fn lemma_seq_to_set_commutes_with_map<A,B>(s: Seq<A>, f: spec_fn(A) -> B)
    ensures s.to_set().map(f) == s.map_values(f).to_set()
{
    assert forall |a: A| #[trigger] s.contains(a) implies s.map_values(f).contains(f(a)) by {
        assert(exists |i| 0 <= i < s.len() && s[i] == a);
        let i = choose |i| 0 <= i < s.len() && s[i] == a;
        assert(s.map_values(f)[i] == f(a));
    };
    assert forall |a: A| #[trigger] s.contains(a) implies s.to_set().map(f).contains(f(a)) by {
        assert(s.to_set().contains(a));
    };
    assert forall |a: A| #[trigger] s.contains(a) implies s.map_values(f).to_set().contains(f(a)) by {
        assert(s.map_values(f).contains(f(a)));
    };
    assert forall |a: A| #[trigger] s.map_values(f).contains(f(a)) implies s.to_set().map(f).contains(f(a)) by {
        assert(exists |i| 0 <= i < s.len() && s.map_values(f)[i] == f(a));
        let i = choose |i| 0 <= i < s.len() && s.map_values(f)[i] == f(a);
        assert(s.to_set().contains(s[i]));
        assert(s.to_set().map(f).contains(f(s[i])));
    };
    assert_sets_equal!(s.to_set().map(f) == s.map_values(f).to_set());
}


} // verus!
