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

use nonempty::NonEmpty;
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::hash::Hash;
use std::sync::Arc;
#[cfg(verus_keep_ghost)]
#[allow(unused_imports)]
use vstd::std_specs::hash::*;
use vstd::{assert_seqs_equal, assert_sets_equal, calc, prelude::*, relations::*, seq_lib};

// Specification macros

#[allow(unused_macros)]
macro_rules! clone_spec_for {
    ($type:ty) => {
        verus! {
            pub assume_specification[ <$type as Clone>::clone ](this: &$type) -> (other: $type)
                ensures this@ == other@;
        }
    };
    ($type:ty, $($generic:ident $(: $bound:path)?),*) => {
        verus! {
            pub assume_specification<$($generic $(: $bound)?)*>[ <$type as Clone>::clone ](this: &$type) -> (other: $type)
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

#[allow(unused_imports)]
macro_rules! eq_spec_for {
    ($type_name:ty) => {
        verus! {
        pub assume_specification[<$type_name as PartialEq>::eq](s1: &$type_name, s2: &$type_name) -> (res: bool)
            ensures
                res == (s1@ == s2@);
        }
    };
}
#[allow(unused_imports)]
pub(crate) use eq_spec_for;

// Axioms

verus! {

pub broadcast proof fn axiom_map_map_values_finite<K,V,U>(m: Map<K,V>, f: spec_fn(V) -> U)
    requires m.dom().finite(),
    ensures #[trigger] m.map_values(f).dom().finite()
{
    admit()
}

}

// Arithmetic

verus! {

#[verifier::inline]
pub open spec fn i64_of_int_checked(x: int) -> Option<i64> {
    if i64::MIN <= x && x <= i64::MAX {
        Some(x as i64)
    } else {
        None
    }
}

#[verifier::inline]
pub open spec fn checked_add(i1: i64, i2: i64) -> Option<i64> {
    i64_of_int_checked(i1 as int + i2 as int)
}

#[verifier::inline]
pub open spec fn checked_sub(i1: i64, i2: i64) -> Option<i64> {
    i64_of_int_checked(i1 as int - i2 as int)
}

#[verifier::inline]
pub open spec fn checked_mul(i1: i64, i2: i64) -> Option<i64> {
    i64_of_int_checked(i1 as int * i2 as int)
}

#[verifier::inline]
pub open spec fn checked_neg(i: i64) -> Option<i64> {
    i64_of_int_checked(-(i as int))
}

#[verifier::external_body]
pub fn i64_checked_neg_verus(i: &i64) -> (neg: Option<i64>)
    ensures neg == checked_neg(*i)
{
    i.checked_neg()
}

} // verus!

// Specifications for external types

verus! {

// Misc stdlib stuff

#[cfg(verus_keep_ghost)]
pub assume_specification<T: Clone, A: std::alloc::Allocator>[Arc::unwrap_or_clone](arc: Arc<T, A>) -> (inner: T)
    ensures inner == arc;

#[cfg(verus_keep_ghost)]
pub assume_specification<T: ?Sized, A: std::alloc::Allocator>[Arc::as_ref](arc: &Arc<T, A>) -> (a_ref: &T)
    ensures a_ref == arc;

#[cfg(verus_keep_ghost)]
pub assume_specification<T>[<T as From<T>>::from](t: T) -> (new_t: T)
    ensures new_t == t;

// We don't actually need the spec on this
pub assume_specification<T: Clone>[Option::<&T>::cloned](opt: Option<&T>) -> (cloned_opt: Option<T>);

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

pub proof fn smol_str_view_injective()
    ensures injective(|s: SmolStr| s.view())
{
    admit()
}

pub proof fn smol_str_ref_view_injective()
    ensures injective(|s: &SmolStr| s.view())
{
    admit()
}


pub assume_specification[SmolStr::as_str](this: &SmolStr) -> (s: &str)
    ensures this@ == s@;

// NonEmpty

#[verifier::external_type_specification]
#[verifier::external_body]
#[verifier::reject_recursive_types(T)] // TODO: can be relaxed maybe
pub struct ExNonEmpty<T>(NonEmpty<T>);

// BTreeMap

#[cfg(verus_keep_ghost)]
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
    broadcast proof fn axiom_btree_map_view_decreases(&self)
        ensures decreases_to!(self => #[trigger] self.view())
    {
        admit()
    }
}

// BTreeSet

#[cfg(verus_keep_ghost)]
#[verifier::external_type_specification]
#[verifier::external_body]
#[verifier::accept_recursive_types(T)]
#[verifier::reject_recursive_types(A)]
pub struct ExBTreeSet<T, A: std::alloc::Allocator + Clone>(BTreeSet<T, A>);


/// Like `impl<V:View> View for BTreeSet<V>`,
/// but we can't write that explicitly due to trait orphan rules
pub trait BTreeSetView {
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

    pub open spec fn is_empty(self) -> bool {
        self.len() == 0
    }

    pub closed spec fn len(&self) -> nat {
        self.s.len()
    }

    pub open spec fn all(&self, pred: spec_fn(T) -> bool) -> bool {
        forall |x: T| self.contains(x) ==> pred(x)
    }

    pub open spec fn any(&self, pred: spec_fn(T) -> bool) -> bool {
        exists |x: T| self.contains(x) && pred(x)
    }

    pub closed spec fn map<B>(self, f: spec_fn(T) -> B) -> FiniteSet<B> {
        FiniteSet { s: self.s.map_values(f).remove_duplicates(seq![]) }
    }

    pub closed spec fn contains(self, t: T) -> bool {
        self.s.contains(t)
    }

    pub open spec fn subset_of(self, s2: FiniteSet<T>) -> bool {
        forall |x: T| self.contains(x) ==> s2.contains(x)
    }

    pub closed spec fn intersect(self, s2: FiniteSet<T>) -> FiniteSet<T> {
        FiniteSet { s: self.s.filter(|x: T| s2.contains(x)) } // neither has duplicates
    }

    pub closed spec fn from_seq(s: Seq<T>) -> FiniteSet<T> {
        FiniteSet { s: s.remove_duplicates(seq![]) }
    }

    pub closed spec fn from_set(set: Set<T>) -> FiniteSet<T> {
        FiniteSet { s: set.to_seq() } // no duplicates
    }

    pub broadcast proof fn lemma_finiteset_from_seq_contains_spec(s: Seq<T>, t: T)
        ensures s.contains(t) <==> #[trigger] Self::from_seq(s).contains(t)
    {
        assert(s + seq![] =~= s);
        s.lemma_remove_duplicates_properties(seq![]);
    }

    pub broadcast proof fn lemma_finiteset_from_set_contains_spec(s: Set<T>, t: T)
        requires s.finite()
        ensures s.contains(t) <==> #[trigger] Self::from_set(s).contains(t)
    {
        lemma_set_to_seq_contains(s, t);
    }

    pub broadcast proof fn lemma_finiteset_map_contains_spec<B>(self, f: spec_fn(T) -> B, t: T)
        ensures self.contains(t) ==> #[trigger] self.map(f).contains(f(t))
    {
        if self.contains(t) {
            let i = choose |i:int| 0 <= i < self.s.len() && self.s[i] == t;
            assert(self.s.map_values(f)[i] == f(t));
            self.s.map_values(f).lemma_remove_duplicates_properties(seq![]);
        }
    }

    pub broadcast proof fn lemma_finiteset_map_contains_spec_rev<B>(self, f: spec_fn(T) -> B, b: B)
        ensures #[trigger] self.map(f).contains(b) ==> (exists |t: T| self.contains(t) && f(t) == b)
    {
        if self.map(f).contains(b) {
            self.s.map_values(f).lemma_remove_duplicates_properties(seq![]);
            assert(self.s.map_values(f).contains(b));
            let i = choose |i:int| 0 <= i < self.s.map_values(f).len() && self.s.map_values(f)[i] == b;
            assert(f(self.s[i]) == b);
            assert(self.contains(self.s[i]));
        }
    }

    pub broadcast proof fn lemma_finiteset_intersect_contains_spec(self, other: FiniteSet<T>, t: T)
        ensures #[trigger] self.intersect(other).contains(t) <==> self.contains(t) && other.contains(t)
    {
        if self.intersect(other).contains(t) {
            self.s.lemma_filter_contains_rev(|x: T| other.contains(x), t);
        }
    }

    pub broadcast proof fn lemma_empty_not_contains(self)
        requires #[trigger] self.is_empty()
        ensures forall |t:T| !(#[trigger] self.contains(t))
    {
        assert(self.s =~= seq![]);
    }

    pub broadcast proof fn lemma_not_empty_contains(self)
        requires !(#[trigger] self.is_empty())
        ensures exists |t:T| #[trigger] self.contains(t)
    {
        assert(self.s.len() > 0);
        assert(self.contains(self.s[0]));
    }

    pub broadcast proof fn lemma_empty_intersect(self, other: FiniteSet<T>)
        requires #[trigger] self.intersect(other).is_empty()
        ensures
            forall |t:T| #[trigger] self.contains(t) ==> !other.contains(t),
            forall |t:T| #[trigger] other.contains(t) ==> !self.contains(t),
    {
        self.intersect(other).lemma_empty_not_contains();
        assert forall |t:T| #[trigger] self.contains(t) implies !other.contains(t) by {
            self.lemma_finiteset_intersect_contains_spec(other, t);
        };
        assert forall |t:T| #[trigger] other.contains(t) implies !self.contains(t) by {
            self.lemma_finiteset_intersect_contains_spec(other, t);
        };
    }

    pub broadcast group group_finiteset_properties {
        FiniteSet::lemma_finiteset_from_seq_contains_spec,
        FiniteSet::lemma_finiteset_from_set_contains_spec,
        FiniteSet::lemma_finiteset_map_contains_spec,
        FiniteSet::lemma_finiteset_map_contains_spec_rev,
        FiniteSet::lemma_finiteset_intersect_contains_spec,
        FiniteSet::lemma_empty_not_contains,
        FiniteSet::lemma_not_empty_contains,
        FiniteSet::lemma_empty_intersect,
    }
}


}

// Helper functions (should be in vstd)

verus! {

#[verifier::external_body]
pub fn hash_set_from_vec<T: Eq + Hash>(vec: Vec<T>) -> (hset: HashSet<T>)
    ensures hset@ == vec@.to_set()
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

pub open spec fn seq_filter_map_aux<A, B>(s: Seq<A>, f: spec_fn(A) -> Option<B>) -> Seq<B> {
    s.map_values(f)
     .filter(|x: Option<B>| x is Some)
     .map_values(|x: Option<B>| x.unwrap())
}

pub open spec fn set_filter_map_aux<A, B>(s: Set<A>, f: spec_fn(A) -> Option<B>) -> Set<B> {
    s.map(f)
     .filter(|x: Option<B>| x is Some)
     .map(|x: Option<B>| x.unwrap())
}

// Map f over elements of s, returning the first Err found, otherwise unwrapping the Ok values
pub open spec fn seq_map_result_all<A, B, E>(s: Seq<A>, f: spec_fn(A) -> Result<B,E>) -> Result<Seq<B>, E> {
    let f = |rsb: Result<Seq<B>,E>, a: A| match rsb {
        Ok(sb) => match f(a) {
            Ok(b) => Ok(sb.push(b)),
            Err(err) => Err(err),
        },
        Err(err) => Err(err),
    };
    s.fold_left_alt(Ok(seq![]), f)
}

pub open spec fn assoc_list_as_map<K,V>(assoc_list: Seq<(K,V)>) -> Map<K,V>
    decreases assoc_list.len()
{
    if assoc_list.len() == 0 {
        map![]
    } else {
        let (last_k, last_v) = assoc_list.last();
        let rest_map = assoc_list_as_map(assoc_list.drop_last());
        rest_map.insert(last_k, last_v)
    }
}

pub open spec fn assoc_list_no_dups<K,V>(assoc_list: Seq<(K,V)>) -> bool {
    forall |i:int, j:int| 0 <= i < assoc_list.len() && 0 <= j < assoc_list.len() ==> ((#[trigger] assoc_list[i]).0 == (#[trigger] assoc_list[j]).0 ==> i == j)
}

pub open spec fn assoc_list_dom<K,V>(assoc_list: Seq<(K,V)>) -> Set<K> {
    assoc_list.map_values(|kv: (K,V)| kv.0).to_set()
}

pub proof fn assoc_list_insert_spec<K,V>(assoc_list: Seq<(K,V)>, k: K, v: V)
    ensures assoc_list_as_map(assoc_list.push((k,v))) == assoc_list_as_map(assoc_list).insert(k, v)
{
    reveal_with_fuel(assoc_list_as_map, 1);
    assert(assoc_list.push((k,v)).drop_last() =~= assoc_list);
}


} // verus!

// Helper lemmas (should be in vstd)

verus! {

pub proof fn lemma_set_to_seq_contains<A>(s: Set<A>, t: A)
    requires s.finite()
    ensures s.contains(t) <==> #[trigger] s.to_seq().contains(t)
    decreases s.len()
{
    broadcast use vstd::set_lib::group_set_properties;
    broadcast use vstd::seq_lib::group_seq_properties;
    reveal_with_fuel(Set::to_seq, 1);
    if s.len() > 0 {
        assert(s.to_seq().len() > 0);
        let x = s.choose();
        assert(s.to_seq().contains(x));
        if x != t {
            lemma_set_to_seq_contains(s.remove(x), t);
            if s.contains(t) {
                assert(s.remove(x).contains(t));
            } else {
                assert(!s.remove(x).contains(t));
            }
        }
    }
}


pub proof fn lemma_map_insert_map_values<K,V,U>(m: Map<K,V>, k: K, v: V, f: spec_fn(V) -> U)
    ensures
        m.insert(k, v).map_values(f) == m.map_values(f).insert(k, f(v))
{
    assert(m.insert(k, v).map_values(f) =~= m.map_values(f).insert(k, f(v)));
}

pub proof fn lemma_map_map_values_only_on_dom<K,V,U>(m: Map<K,V>, f: spec_fn(V) -> U)
    requires m.dom().finite()
    ensures ({
        let map_values_f = m.map_values(f);
        let map_values_check_contains_f = m.map_values(|v: V| {
            if m.dom().finite() && m.contains_value(v) {
                f(v)
            } else {
                arbitrary()
            }
        });
        map_values_f == map_values_check_contains_f
    })
{
    let map_values_f = m.map_values(f);
    let map_values_check_contains_f = m.map_values(|v: V| {
        if m.dom().finite() && m.contains_value(v) {
            f(v)
        } else {
            arbitrary()
        }
    });
    assert(map_values_f =~= map_values_check_contains_f);
}


pub proof fn lemma_set_filter_map_aux_equiv<A,B>(st: Set<A>, f: spec_fn(A) -> Option<B>)
    requires
        st.finite() // so we can use recursion
    ensures
        st.map(f).filter(|x: Option<B>| x is Some).map(|x: Option<B>| x.unwrap()) == st.filter_map(f)
    decreases st.len()
{
    if st.is_empty() {
        assert(st.filter_map(f).is_empty());
        assert(st.map(f).is_empty());
        assert(st.map(f).filter(|x: Option<B>| x is Some).is_empty());
        assert(st.map(f).filter(|x: Option<B>| x is Some).map(|x: Option<B>| x.unwrap()).is_empty());
    } else {
        let a = choose |a:A| st.contains(a);
        let st_without_a = st.remove(a);
        assert(st_without_a.insert(a) == st);
        lemma_set_filter_map_aux_equiv(st_without_a, f);
        vstd::set::Set::lemma_filter_map_insert(st_without_a, f, a);
        match f(a) {
            Some(res) => {
                assert(st_without_a.insert(a).filter_map(f) == st_without_a.filter_map(f).insert(res));
                assert(st_without_a.insert(a).filter_map(f) == st_without_a.map(f).filter(|x: Option<B>| x is Some).map(|x: Option<B>| x.unwrap()).insert(res));
                calc! { (==)
                    st_without_a.insert(a).map(f).filter(|x: Option<B>| x is Some).map(|x: Option<B>| x.unwrap());
                        {lemma_set_map_insert(st_without_a, f, a)}
                    st_without_a.map(f).insert(f(a)).filter(|x: Option<B>| x is Some).map(|x: Option<B>| x.unwrap());
                        {lemma_set_filter_insert_true(st_without_a.map(f), |x: Option<B>| x is Some, f(a))}
                    st_without_a.map(f).filter(|x: Option<B>| x is Some).insert(f(a)).map(|x: Option<B>| x.unwrap());
                        {lemma_set_map_insert(st_without_a.map(f).filter(|x: Option<B>| x is Some), |x: Option<B>| x.unwrap(), f(a))}
                    st_without_a.map(f).filter(|x: Option<B>| x is Some).map(|x: Option<B>| x.unwrap()).insert(res);
                }
            },
            None => {
                assert(st_without_a.insert(a).filter_map(f) == st_without_a.filter_map(f));
                assert(st_without_a.insert(a).filter_map(f) == st_without_a.map(f).filter(|x: Option<B>| x is Some).map(|x: Option<B>| x.unwrap()));
                calc! { (==)
                    st_without_a.insert(a).map(f).filter(|x: Option<B>| x is Some).map(|x: Option<B>| x.unwrap());
                        {lemma_set_map_insert(st_without_a, f, a)}
                    st_without_a.map(f).insert(f(a)).filter(|x: Option<B>| x is Some).map(|x: Option<B>| x.unwrap());
                        {lemma_set_filter_insert_false(st_without_a.map(f), |x: Option<B>| x is Some, f(a))}
                    st_without_a.map(f).filter(|x: Option<B>| x is Some).map(|x: Option<B>| x.unwrap());
                }
            },
        }

    }
}

pub proof fn lemma_seq_filter_map_aux_equiv<A,B>(sq: Seq<A>, f: spec_fn(A) -> Option<B>)
    ensures
        sq.map_values(f).filter(|x: Option<B>| x is Some).map_values(|x: Option<B>| x.unwrap()) == sq.filter_map(f)
    decreases sq.len()
{
    if sq.len() == 0 {
        assert(sq.filter_map(f) =~= Seq::empty());
        assert(sq.map_values(f).filter(|x: Option<B>| x is Some).map_values(|x: Option<B>| x.unwrap()) =~= Seq::empty());
    } else {
        reveal_with_fuel(Seq::filter_map, 2);
        let rest = sq.drop_last();
        let last = sq.last();
        assert(sq == rest.push(last));
        lemma_seq_filter_map_aux_equiv(rest, f);
        match f(last) {
            Some(res) => {
                assert(sq.filter_map(f) == rest.filter_map(f).push(res));
                assert(sq.filter_map(f) == rest.map_values(f).filter(|x: Option<B>| x is Some).map_values(|x: Option<B>| x.unwrap()).push(res));
                calc! { (==)
                    rest.push(last).map_values(f).filter(|x: Option<B>| x is Some).map_values(|x: Option<B>| x.unwrap());
                        {lemma_seq_map_values_append(rest, f, last)}
                    rest.map_values(f).push(f(last)).filter(|x: Option<B>| x is Some).map_values(|x: Option<B>| x.unwrap());
                        {lemma_seq_filter_values_append_true(rest.map_values(f), |x: Option<B>| x is Some, f(last))}
                    rest.map_values(f).filter(|x: Option<B>| x is Some).push(f(last)).map_values(|x: Option<B>| x.unwrap());
                        {lemma_seq_map_values_append(rest.map_values(f).filter(|x: Option<B>| x is Some), |x: Option<B>| x.unwrap(), f(last))}
                    rest.map_values(f).filter(|x: Option<B>| x is Some).map_values(|x: Option<B>| x.unwrap()).push(res);
                }
            },
            None => {
                assert(sq.filter_map(f) == rest.filter_map(f));
                assert(sq.filter_map(f) == rest.map_values(f).filter(|x: Option<B>| x is Some).map_values(|x: Option<B>| x.unwrap()));
                calc! { (==)
                    rest.push(last).map_values(f).filter(|x: Option<B>| x is Some).map_values(|x: Option<B>| x.unwrap());
                        {lemma_seq_map_values_append(rest, f, last)}
                    rest.map_values(f).push(f(last)).filter(|x: Option<B>| x is Some).map_values(|x: Option<B>| x.unwrap());
                        { lemma_seq_filter_values_append_false(rest.map_values(f), |x: Option<B>| x is Some, f(last)); }
                    rest.map_values(f).filter(|x: Option<B>| x is Some).map_values(|x: Option<B>| x.unwrap());
                }
            },
        }
    }
}

pub proof fn lemma_set_filter_insert_true<A>(s: Set<A>, f: spec_fn(A) -> bool, a: A)
    requires
        f(a),
    ensures
        s.filter(f).insert(a) == s.insert(a).filter(f),
{
    assert_sets_equal!(s.filter(f).insert(a) == s.insert(a).filter(f));
}

pub proof fn lemma_set_filter_insert_false<A>(s: Set<A>, f: spec_fn(A) -> bool, a: A)
    requires
        !f(a),
    ensures
        s.filter(f) == s.insert(a).filter(f),
{
    assert_sets_equal!(s.filter(f) == s.insert(a).filter(f));
}


pub proof fn lemma_set_map_insert<A,B>(s: Set<A>, f: spec_fn(A) -> B, a: A)
    ensures
        s.map(f).insert(f(a)) == s.insert(a).map(f),
{
    assert forall |b: B| s.map(f).insert(f(a)).contains(b) implies s.insert(a).map(f).contains(b) by {
        if (exists |a0: A| s.contains(a0) && f(a0) == b) {
            let a0 = choose |a0: A| s.contains(a0) && f(a0) == b;
            assert(s.insert(a).contains(a0));
            assert(s.insert(a).map(f).contains(f(a0)));
        } else if f(a) == b {
            assert(s.insert(a).contains(a));
            assert(s.insert(a).map(f).contains(f(a)));
        }
    };
    assert_sets_equal!(s.map(f).insert(f(a)) == s.insert(a).map(f));
}


pub proof fn lemma_set_seq_filter_map<A, B>(st: Set<A>, f: spec_fn(A) -> Option<B>)
    requires
        st.finite(),
    ensures
        st.filter_map(f) == st.to_seq().filter_map(f).to_set(),
    decreases st.len(),
{
    let sq = st.to_seq();
    assert(st == sq.to_set()) by { st.lemma_to_seq_to_set_id(); };
    sq.lemma_to_set_map_commutes(f);
    let st_map = st.map(f);
    let sq_map = sq.map_values(f);
    lemma_seq_to_set_commutes_with_filter(sq_map, |x: Option<B>| x is Some);
    let st_map_filter = st_map.filter(|x: Option<B>| x is Some);
    let sq_map_filter = sq_map.filter(|x: Option<B>| x is Some);
    sq_map_filter.lemma_to_set_map_commutes(|x: Option<B>| x.unwrap());
    lemma_set_filter_map_aux_equiv(st, f);
    lemma_seq_filter_map_aux_equiv(sq, f);
}

pub proof fn lemma_seq_filter_map_add<A,B>(s: Seq<A>, f: spec_fn(A) -> Option<B>, a: A)
    requires f(a) is Some,
    ensures
        s.push(a).filter_map(f) == s.filter_map(f).push(f(a).unwrap()),
    decreases s.len(),
{
    reveal_with_fuel(Seq::filter_map, 1);
    assert(s.push(a).last() == a);
    assert(s.push(a).drop_last() == s);
    assert(s.push(a).filter_map(f) == s.push(a).drop_last().filter_map(f) + seq![f(a).unwrap()]);
    if s.len() == 0 {
    } else {
        assert_seqs_equal!(s.push(a) == s + seq![a]);
        assert(s.push(a).filter_map(f) == s.filter_map(f) + seq![f(a).unwrap()]);
        assert_seqs_equal!(s.filter_map(f) + seq![f(a).unwrap()] == s.filter_map(f).push(f(a).unwrap()));
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

pub proof fn lemma_seq_filter_values_append_true<A>(s: Seq<A>, f: spec_fn(A) -> bool, a: A)
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

pub proof fn lemma_seq_filter_values_append_false<A>(s: Seq<A>, f: spec_fn(A) -> bool, a: A)
    requires f(a) == false
    ensures
        (s.push(a)).filter(f) == s.filter(f),
{
    reveal_with_fuel(Seq::filter, 1);
    let s_push_a = s.push(a);
    assert(s_push_a.last() == a);
    assert(s_push_a.drop_last() == s);
    assert(s_push_a.drop_last().filter(f) == s.filter(f));
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


pub proof fn lemma_seq_to_set_commutes_with_filter<A>(s: Seq<A>, f: spec_fn(A) -> bool)
    ensures s.to_set().filter(f) == s.filter(f).to_set()
{
    broadcast use vstd::seq_lib::group_filter_ensures;
    assert forall |a:A| s.filter(f).to_set().contains(a) implies s.to_set().filter(f).contains(a) by {
        assert(s.filter(f).contains(a));
        lemma_seq_filter_contains_rev(s, f, a);
        assert(s.to_set().contains(a));
    };

    assert_sets_equal!(s.to_set().filter(f) == s.filter(f).to_set());
}

pub proof fn lemma_seq_filter_contains_rev<A>(s: Seq<A>, f: spec_fn(A) -> bool, a: A)
    requires s.filter(f).contains(a)
    ensures s.contains(a)
    decreases s.len()
{
    reveal_with_fuel(Seq::filter, 1);
    broadcast use vstd::seq_lib::group_filter_ensures;
    assert(f(a));
    if a == s.last() {
        assert(a == s.filter(f).last());
    } else {
        lemma_seq_filter_contains_rev(s.drop_last(), f, a);
    }
}


pub proof fn lemma_seq_to_set_distributes_over_add<A>(s1: Seq<A>, s2: Seq<A>)
    ensures (s1 + s2).to_set() == s1.to_set().union(s2.to_set())
{
    assert forall |a: A| #[trigger] s1.to_set().union(s2.to_set()).contains(a) implies (s1 + s2).to_set().contains(a) by {
        seq_lib::lemma_seq_concat_contains_all_elements(s1, s2, a);
        if (s1.to_set().contains(a)) {
            assert(s1.contains(a));
            assert((s1 + s2).contains(a));
        } else {
            assert(s2.to_set().contains(a));
            assert(s2.contains(a));
            assert((s1 + s2).contains(a));
        }
    };
    assert_sets_equal!((s1 + s2).to_set() == s1.to_set().union(s2.to_set()));
}

pub proof fn lemma_seq_take_distributes_over_map_values<A,B>(s: Seq<A>, n: int, f: spec_fn(A) -> B)
    requires 0 <= n <= s.len(),
    ensures (s.take(n)).map_values(f) == s.map_values(f).take(n)
{
    assert_seqs_equal!((s.take(n)).map_values(f) == s.map_values(f).take(n));
}

pub proof fn lemma_seq_push_to_set_insert<A>(s: Seq<A>, a: A)
    ensures s.push(a).to_set() == s.to_set().insert(a)
{
    lemma_seq_to_set_distributes_over_add(s, seq![a]);
    assert((s + seq![a]).to_set() == s.to_set().union(seq![a].to_set()));
    lemma_seq_singleton_to_set(a);
    assert_sets_equal!(s.to_set().insert(a) == s.to_set().union(set![a]));
    assert(s.to_set().insert(a) =~= (s + seq![a]).to_set());
    assert_seqs_equal!(s + seq![a] == s.push(a));
}

pub proof fn lemma_seq_take_push_to_set_insert<A>(s: Seq<A>, n: int)
    requires 0 <= n < s.len(),
    ensures s.take(n).to_set().insert(s[n]) == s.take(n+1).to_set()
{
    let s_take_n = s.take(n);
    let s_n = s[n];
    assert(s.take(n+1) == s_take_n.push(s_n));
    lemma_seq_push_to_set_insert(s_take_n, s_n);
}

pub proof fn lemma_seq_singleton_to_set<A>(x: A)
    ensures seq![x].to_set() == set![x]
{
    assert forall |a: A| #[trigger] set![x].contains(a) implies seq![x].to_set().contains(a) by {
        assert(a == x);
        assert(seq![x][0] == a); // need to manually instantiate the existential quantifier on `contains`
        assert(seq![x].contains(a));
    };
    assert_sets_equal!(seq![x].to_set() == set![x]);
}

pub proof fn lemma_seq_map_values_distributes_over_push<A,B>(s: Seq<A>, f: spec_fn(A) -> B, a: A)
    ensures (s.push(a)).map_values(f) == s.map_values(f).push(f(a))
{
    assert_seqs_equal!((s.push(a)).map_values(f) == s.map_values(f).push(f(a)));
}

} // verus!
