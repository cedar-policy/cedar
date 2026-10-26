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

//! Abstraction of production values to model values (`abs_value`). Sets are
//! abstracted in iteration order, records in key order.

use vstd::prelude::*;

use super::abs::*;
use super::map_entries::*;
use super::model as m;
use super::trusted::*;
use crate::ast::*;
use crate::ast::Set;
use smol_str::SmolStr;
use std::collections::BTreeMap;

verus! {

broadcast use vstd::std_specs::btree::axiom_btree_set_decreases, vstd::std_specs::btree::axiom_btree_map_decreases,
    vstd::map::axiom_map_index_decreases, vstd::set::axiom_set_decreases_to_member;

/// The entries of a record in key order (= `BTreeMap` iteration order)
pub open spec fn record_entries(r: BTreeMap<SmolStr, Value>) -> Seq<(SmolStr, Value)> {
    sorted_entries(r@)
}

/// The elements of a set value
pub open spec fn elems_of(v: ValueKind) -> Seq<Value> {
    match v {
        ValueKind::Set(s) => set_elems(s),
        _ => Seq::empty(),
    }
}

/// The entries of a record value
pub open spec fn entries_of(v: ValueKind) -> Seq<(SmolStr, Value)> {
    match v {
        ValueKind::Record(r) => record_entries(*r),
        _ => Seq::empty(),
    }
}

proof fn lemma_parts_decrease(v: ValueKind)
    ensures
        forall|i: int| 0 <= i < elems_of(v).len() ==> decreases_to!(v => (#[trigger] elems_of(v)[i]).value),
        forall|i: int| 0 <= i < entries_of(v).len() ==> decreases_to!(v => (#[trigger] entries_of(v)[i]).1.value),
{
    match v {
        ValueKind::Set(s) => {
            axiom_set_elems(s);
            assert forall|i: int| 0 <= i < elems_of(v).len() implies decreases_to!(v => (#[trigger] elems_of(v)[i]).value) by {
                assert((*s.authoritative)@.contains(set_elems(s)[i]));
                assert(decreases_to!(v => set_elems(s)[i]));
            }
        },
        ValueKind::Record(r) => {
            lemma_sorted_entries((*r)@);
            assert forall|i: int| 0 <= i < entries_of(v).len() implies decreases_to!(v => (#[trigger] entries_of(v)[i]).1.value) by {
                assert((*r)@.dom().contains(entries_of(v)[i].0));
                assert(decreases_to!(v => entries_of(v)[i].1));
            }
        },
        _ => {},
    }
}

/// Abstraction of production values (source locations are ignored)
pub open spec fn abs_value(v: Value) -> m::value::Value {
    abs_value_kind(v.value)
}

pub open spec fn abs_value_kind(v: ValueKind) -> m::value::Value
    decreases v, 1nat, 0nat,
{
    match v {
        ValueKind::Lit(l) => m::value::Value::Prim(abs_lit(l)),
        ValueKind::Set(s) => m::value::Value::Set(Box::new(abs_elems(v, 0))),
        ValueKind::Record(r) => m::value::Value::Record(Box::new(abs_entries(v, 0))),
        ValueKind::ExtensionValue(ev) => m::value::Value::Ext(super::ext_trusted::ext_of(*ev)),
    }
}

/// The abstractions of the elements of a set value, from the `i`-th
pub open spec fn abs_elems(v: ValueKind, i: nat) -> m::value::List<m::value::Value>
    decreases v, 0nat, elems_of(v).len() - i via abs_elems_decreases
{
    if i < elems_of(v).len() {
        m::value::List::Cons(abs_value_kind(elems_of(v)[i as int].value), Box::new(abs_elems(v, i + 1)))
    } else {
        m::value::List::Nil
    }
}

/// The abstractions of the entries of a record value, from the `i`-th
pub open spec fn abs_entries(v: ValueKind, i: nat) -> m::value::Attrs
    decreases v, 0nat, entries_of(v).len() - i via abs_entries_decreases
{
    if i < entries_of(v).len() {
        m::value::List::Cons(
            (abs_str(entries_of(v)[i as int].0), abs_value_kind(entries_of(v)[i as int].1.value)),
            Box::new(abs_entries(v, i + 1)),
        )
    } else {
        m::value::List::Nil
    }
}

#[via_fn]
proof fn abs_elems_decreases(v: ValueKind, i: nat) {
    lemma_parts_decrease(v);
}

#[via_fn]
proof fn abs_entries_decreases(v: ValueKind, i: nat) {
    lemma_parts_decrease(v);
}

/// Abstraction of the elements of a set (in iteration order)
pub open spec fn abs_set(s: Set) -> m::value::List<m::value::Value> {
    seq_to_list(set_elems(s).map_values(|x: Value| abs_value(x)))
}

/// Abstraction of the entries of a record (in key order)
pub open spec fn abs_record(r: BTreeMap<SmolStr, Value>) -> m::value::Attrs {
    seq_to_list(record_entries(r).map_values(|e: (SmolStr, Value)| (abs_str(e.0), abs_value(e.1))))
}

/// Every value is modeled; kept as a predicate for the evaluator's specs,
/// which also handle residuals.
pub open spec fn modeled(v: Value) -> bool {
    true
}

pub open spec fn modeled_kind(v: ValueKind) -> bool {
    true
}

// ---------------------------------------------------------------------------
// The definitions, one level at a time
// ---------------------------------------------------------------------------

proof fn lemma_abs_elems(v: ValueKind, i: nat)
    requires
        i <= elems_of(v).len(),
    ensures
        abs_elems(v, i) == seq_to_list(elems_of(v).subrange(i as int, elems_of(v).len() as int).map_values(
            |x: Value| abs_value(x),
        )),
    decreases elems_of(v).len() - i,
{
    let s = elems_of(v).subrange(i as int, elems_of(v).len() as int).map_values(|x: Value| abs_value(x));
    if i < elems_of(v).len() {
        lemma_abs_elems(v, i + 1);
        assert(s.subrange(1, s.len() as int) =~= elems_of(v).subrange(i + 1 as int, elems_of(v).len() as int).map_values(
            |x: Value| abs_value(x),
        ));
    } else {
        assert(s =~= Seq::empty());
    }
}

proof fn lemma_abs_entries(v: ValueKind, i: nat)
    requires
        i <= entries_of(v).len(),
    ensures
        abs_entries(v, i) == seq_to_list(entries_of(v).subrange(i as int, entries_of(v).len() as int).map_values(
            |e: (SmolStr, Value)| (abs_str(e.0), abs_value(e.1)),
        )),
    decreases entries_of(v).len() - i,
{
    let s = entries_of(v).subrange(i as int, entries_of(v).len() as int).map_values(
        |e: (SmolStr, Value)| (abs_str(e.0), abs_value(e.1)),
    );
    if i < entries_of(v).len() {
        lemma_abs_entries(v, i + 1);
        assert(s.subrange(1, s.len() as int) =~= entries_of(v).subrange(i + 1 as int, entries_of(v).len() as int).map_values(
            |e: (SmolStr, Value)| (abs_str(e.0), abs_value(e.1)),
        ));
    } else {
        assert(s =~= Seq::empty());
    }
}

/// Unfolds `abs_value_kind` one level
pub broadcast proof fn lemma_abs_value(v: ValueKind)
    ensures
        #[trigger] abs_value_kind(v) == match v {
            ValueKind::Lit(l) => m::value::Value::Prim(abs_lit(l)),
            ValueKind::Set(s) => m::value::Value::Set(Box::new(abs_set(s))),
            ValueKind::Record(r) => m::value::Value::Record(Box::new(abs_record(*r))),
            ValueKind::ExtensionValue(ev) => m::value::Value::Ext(super::ext_trusted::ext_of(*ev)),
        },
{
    match v {
        ValueKind::Set(s) => {
            lemma_abs_elems(v, 0);
            assert(elems_of(v).subrange(0, elems_of(v).len() as int) =~= set_elems(s));
        },
        ValueKind::Record(r) => {
            lemma_abs_entries(v, 0);
            assert(entries_of(v).subrange(0, entries_of(v).len() as int) =~= record_entries(*r));
        },
        _ => {},
    }
}

pub broadcast proof fn lemma_abs_set_elems(s: Set)
    ensures
        list_view(#[trigger] abs_set(s)) == set_elems(s).map_values(|x: Value| abs_value(x)),
{
    super::model_lemmas::lemma_list_view_seq_to_list(set_elems(s).map_values(|x: Value| abs_value(x)));
}

pub broadcast proof fn lemma_abs_record_entries(r: BTreeMap<SmolStr, Value>)
    ensures
        list_view(#[trigger] abs_record(r)) == record_entries(r).map_values(
            |e: (SmolStr, Value)| (abs_str(e.0), abs_value(e.1)),
        ),
{
    super::model_lemmas::lemma_list_view_seq_to_list(
        record_entries(r).map_values(|e: (SmolStr, Value)| (abs_str(e.0), abs_value(e.1))),
    );
}

/// The entries of a record are sorted by key.
pub proof fn lemma_record_entries(r: BTreeMap<SmolStr, Value>)
    ensures
        record_entries(r).to_set() == r@.kv_pairs(),
        sorted_by_key(record_entries(r)),
        forall|i: int| 0 <= i < record_entries(r).len() ==> {
            &&& r@.dom().contains(#[trigger] record_entries(r)[i].0)
            &&& record_entries(r)[i].1 == r@[record_entries(r)[i].0]
        },
{
    lemma_sorted_entries(r@);
}

// ---------------------------------------------------------------------------
// Well-formedness of abstracted IP networks
// ---------------------------------------------------------------------------

proof fn lemma_abs_value_kind_wf(v: ValueKind)
    ensures
        super::model_lemmas::value_wf(abs_value_kind(v)),
    decreases v, 1nat, 0nat,
{
    broadcast use super::ext_trusted::axiom_ext_of_wf;

    match v {
        ValueKind::Set(_) => lemma_abs_elems_wf(v, 0),
        ValueKind::Record(_) => lemma_abs_entries_wf(v, 0),
        _ => {},
    }
}

proof fn lemma_abs_elems_wf(v: ValueKind, i: nat)
    ensures
        super::model_lemmas::values_wf(abs_elems(v, i)),
    decreases v, 0nat, elems_of(v).len() - i,
{
    if i < elems_of(v).len() {
        lemma_parts_decrease(v);
        lemma_abs_value_kind_wf(elems_of(v)[i as int].value);
        lemma_abs_elems_wf(v, i + 1);
    }
}

proof fn lemma_abs_entries_wf(v: ValueKind, i: nat)
    ensures
        super::model_lemmas::attrs_wf(abs_entries(v, i)),
    decreases v, 0nat, entries_of(v).len() - i,
{
    if i < entries_of(v).len() {
        lemma_parts_decrease(v);
        lemma_abs_value_kind_wf(entries_of(v)[i as int].1.value);
        lemma_abs_entries_wf(v, i + 1);
    }
}

pub broadcast proof fn lemma_abs_value_wf(v: ValueKind)
    ensures
        super::model_lemmas::value_wf(#[trigger] abs_value_kind(v)),
{
    lemma_abs_value_kind_wf(v);
}

pub broadcast proof fn lemma_abs_set_wf(s: Set)
    ensures
        super::model_lemmas::values_wf(#[trigger] abs_set(s)),
{
    lemma_abs_value_kind_wf(ValueKind::Set(s));
    lemma_abs_value(ValueKind::Set(s));
}

pub broadcast proof fn lemma_abs_record_wf(r: BTreeMap<SmolStr, Value>)
    ensures
        super::model_lemmas::attrs_wf(#[trigger] abs_record(r)),
{
    let v = ValueKind::Record(std::sync::Arc::new(r));
    lemma_abs_value_kind_wf(v);
    lemma_abs_value(v);
}

// ---------------------------------------------------------------------------
// Lookups in records
// ---------------------------------------------------------------------------

/// `abs_str` is injective.
pub proof fn lemma_abs_str_inj(a: SmolStr, b: SmolStr)
    requires
        abs_str(a) == abs_str(b),
    ensures
        a == b,
{
    super::model_lemmas::lemma_list_view_seq_to_list(smol_view(a));
    super::model_lemmas::lemma_list_view_seq_to_list(smol_view(b));
    axiom_smol_view_injective(a);
    axiom_smol_view_injective(b);
}

proof fn lemma_attrs_find_entries(s: Seq<(SmolStr, Value)>, k: SmolStr)
    requires
        forall|i: int, j: int| #![trigger s[i], s[j]] 0 <= i < j < s.len() ==> s[i].0 != s[j].0,
    ensures
        m::value::attrs_find(&seq_to_list(s.map_values(|e: (SmolStr, Value)| (abs_str(e.0), abs_value(e.1)))), &abs_str(k))
            == if exists|i: int| 0 <= i < s.len() && #[trigger] s[i].0 == k {
                Some(&abs_value(s[choose|i: int| 0 <= i < s.len() && #[trigger] s[i].0 == k].1))
            } else {
                None::<&m::value::Value>
            },
    decreases s.len(),
{
    broadcast use super::model_lemmas::lemma_str_eq;

    let f = |e: (SmolStr, Value)| (abs_str(e.0), abs_value(e.1));
    if s.len() > 0 {
        let s1 = s.subrange(1, s.len() as int);
        assert forall|i: int, j: int| #![trigger s1[i], s1[j]] 0 <= i < j < s1.len() implies s1[i].0 != s1[j].0 by {
            assert(s[i + 1] == s1[i] && s[j + 1] == s1[j]);
        }
        lemma_attrs_find_entries(s1, k);
        assert(s.map_values(f).subrange(1, s.len() as int) =~= s1.map_values(f));
        if s[0].0 == k {
            let i = choose|i: int| 0 <= i < s.len() && #[trigger] s[i].0 == k;
            if i != 0 {
                assert(s[0].0 == s[i].0);
            }
        } else {
            if abs_str(s[0].0) == abs_str(k) {
                lemma_abs_str_inj(s[0].0, k);
            }
            if exists|i: int| 0 <= i < s.len() && #[trigger] s[i].0 == k {
                let i = choose|i: int| 0 <= i < s.len() && #[trigger] s[i].0 == k;
                assert(s1[i - 1].0 == k);
                let i1 = choose|i: int| 0 <= i < s1.len() && #[trigger] s1[i].0 == k;
                assert(s[i1 + 1].0 == k);
                if i != i1 + 1 {
                    if i < i1 + 1 {
                        assert(s[i].0 != s[i1 + 1].0);
                    } else {
                        assert(s[i1 + 1].0 != s[i].0);
                    }
                }
            }
            if exists|i: int| 0 <= i < s1.len() && #[trigger] s1[i].0 == k {
                let i1 = choose|i: int| 0 <= i < s1.len() && #[trigger] s1[i].0 == k;
                assert(s[i1 + 1].0 == k);
            }
        }
    }
}

pub broadcast proof fn lemma_abs_record_find(r: BTreeMap<SmolStr, Value>, k: SmolStr)
    ensures
        #[trigger] m::value::attrs_find(&abs_record(r), &abs_str(k)) == if r@.contains_key(k) {
            Some(&abs_value(r@[k]))
        } else {
            None
        },
{
    let s = record_entries(r);
    lemma_record_entries(r);
    assert forall|i: int, j: int| #![trigger s[i], s[j]] 0 <= i < j < s.len() implies s[i].0 != s[j].0 by {
        super::lemmas::lemma_sorted_by_key(s, i, j);
    }
    lemma_attrs_find_entries(s, k);
    if r@.contains_key(k) {
        assert(r@.kv_pairs().contains((k, r@[k])));
        assert(s.to_set().contains((k, r@[k])));
        let j = choose|j: int| 0 <= j < s.len() && s[j] == (k, r@[k]);
        assert(s[j].0 == k);
    } else {
        if exists|i: int| 0 <= i < s.len() && #[trigger] s[i].0 == k {
            let i = choose|i: int| 0 <= i < s.len() && #[trigger] s[i].0 == k;
            assert(r@.dom().contains(s[i].0));
        }
    }
}

pub broadcast group group_value_abs {
    lemma_abs_value,
    lemma_abs_value_wf,
    lemma_abs_set_wf,
    lemma_abs_record_wf,
    lemma_abs_record_find,
    lemma_abs_set_elems,
    lemma_abs_record_entries,
}

} // verus!
