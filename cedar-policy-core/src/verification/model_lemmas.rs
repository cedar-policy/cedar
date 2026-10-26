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

//! Lemmas about the model.

use vstd::prelude::*;

use super::model as m;
use super::model::{authorizer::*, entities::*, evaluator::*, expr::*, request::*, value::*};

verus! {

// ---------------------------------------------------------------------------
// The copying functions return their input.
// ---------------------------------------------------------------------------

pub broadcast proof fn lemma_clone_str(s: m::value::Str)
    ensures
        #[trigger] clone_str(&s) == s,
    decreases s,
{
    match s {
        List::Cons(_, rest) => lemma_clone_str(*rest),
        _ => {},
    }
}

pub broadcast proof fn lemma_clone_strs(ss: m::value::List<m::value::Str>)
    ensures
        #[trigger] clone_strs(&ss) == ss,
    decreases ss,
{
    match ss {
        List::Cons(s, rest) => {
            lemma_clone_str(s);
            lemma_clone_strs(*rest);
        },
        _ => {},
    }
}

pub broadcast proof fn lemma_clone_name(n: m::value::Name)
    ensures
        #[trigger] clone_name(&n) == n,
{
    lemma_clone_str(n.id);
    lemma_clone_strs(n.path);
}

pub broadcast proof fn lemma_clone_uid(u: m::value::EntityUID)
    ensures
        #[trigger] clone_uid(&u) == u,
{
    lemma_clone_name(u.ty);
    lemma_clone_str(u.eid);
}

pub broadcast proof fn lemma_clone_prim(p: m::value::Prim)
    ensures
        #[trigger] clone_prim(&p) == p,
{
    match p {
        Prim::String(s) => lemma_clone_str(s),
        Prim::EntityUID(u) => lemma_clone_uid(u),
        _ => {},
    }
}

pub broadcast proof fn lemma_clone_value(v: m::value::Value)
    ensures
        #[trigger] clone_value(&v) == v,
    decreases v,
{
    match v {
        Value::Prim(p) => lemma_clone_prim(p),
        Value::Set(vs) => lemma_clone_values(*vs),
        Value::Record(avs) => lemma_clone_attrs(*avs),
        Value::Ext(e) => lemma_clone_ext(e),
    }
}

pub broadcast proof fn lemma_clone_ext(e: super::model::ext::Ext)
    ensures
        #[trigger] super::model::ext::clone_ext(&e) == e,
{
    match e {
        super::model::ext::Ext::IPAddr(super::model::ext::IPNet::V4(_, _)) => {},
        super::model::ext::Ext::IPAddr(super::model::ext::IPNet::V6(_, _)) => {},
        _ => {},
    }
}

pub broadcast proof fn lemma_clone_extfun(f: super::model::ext::ExtFun)
    ensures
        #[trigger] super::model::ext::clone_extfun(&f) == f,
{
}

/// IP prefixes in `v` are at most the address width. Needed because the
/// model's equality is `==` only on such values (as in Lean, an IPv4 prefix
/// above 32 equals 32); abstracted production values satisfy it.
pub open spec fn value_wf(v: m::value::Value) -> bool
    decreases v,
{
    match v {
        Value::Prim(_) => true,
        Value::Set(vs) => values_wf(*vs),
        Value::Record(avs) => attrs_wf(*avs),
        Value::Ext(e) => super::model::ext::ext_wf(&e),
    }
}

pub open spec fn values_wf(vs: m::value::List<m::value::Value>) -> bool
    decreases vs,
{
    match vs {
        List::Nil => true,
        List::Cons(v, rest) => value_wf(v) && values_wf(*rest),
    }
}

pub open spec fn attrs_wf(avs: m::value::Attrs) -> bool
    decreases avs,
{
    match avs {
        List::Nil => true,
        List::Cons((_, v), rest) => value_wf(v) && attrs_wf(*rest),
    }
}

pub broadcast proof fn lemma_clone_values(vs: m::value::List<m::value::Value>)
    ensures
        #[trigger] clone_values(&vs) == vs,
    decreases vs,
{
    match vs {
        List::Cons(v, rest) => {
            lemma_clone_value(v);
            lemma_clone_values(*rest);
        },
        _ => {},
    }
}

pub broadcast proof fn lemma_clone_attrs(avs: m::value::Attrs)
    ensures
        #[trigger] clone_attrs(&avs) == avs,
    decreases avs,
{
    match avs {
        List::Cons((a, v), rest) => {
            lemma_clone_str(a);
            lemma_clone_value(v);
            lemma_clone_attrs(*rest);
        },
        _ => {},
    }
}

// ---------------------------------------------------------------------------
// The equality functions are (spec) equality.
// ---------------------------------------------------------------------------

pub broadcast proof fn lemma_str_eq(a: m::value::Str, b: m::value::Str)
    ensures
        #[trigger] str_eq(&a, &b) == (a == b),
    decreases a,
{
    match (a, b) {
        (List::Cons(_, a1), List::Cons(_, b1)) => lemma_str_eq(*a1, *b1),
        _ => {},
    }
}

pub broadcast proof fn lemma_strs_eq(a: m::value::List<m::value::Str>, b: m::value::List<m::value::Str>)
    ensures
        #[trigger] strs_eq(&a, &b) == (a == b),
    decreases a,
{
    match (a, b) {
        (List::Cons(s, a1), List::Cons(t, b1)) => {
            lemma_str_eq(s, t);
            lemma_strs_eq(*a1, *b1);
        },
        _ => {},
    }
}

pub broadcast proof fn lemma_name_eq(a: m::value::Name, b: m::value::Name)
    ensures
        #[trigger] name_eq(&a, &b) == (a == b),
{
    lemma_str_eq(a.id, b.id);
    lemma_strs_eq(a.path, b.path);
}

pub broadcast proof fn lemma_uid_eq(a: m::value::EntityUID, b: m::value::EntityUID)
    ensures
        #[trigger] uid_eq(&a, &b) == (a == b),
{
    lemma_name_eq(a.ty, b.ty);
    lemma_str_eq(a.eid, b.eid);
}

pub broadcast proof fn lemma_prim_eq(a: m::value::Prim, b: m::value::Prim)
    ensures
        #[trigger] prim_eq(&a, &b) == (a == b),
{
    match (a, b) {
        (Prim::String(x), Prim::String(y)) => lemma_str_eq(x, y),
        (Prim::EntityUID(x), Prim::EntityUID(y)) => lemma_uid_eq(x, y),
        _ => {},
    }
}

pub broadcast proof fn lemma_value_eq(a: m::value::Value, b: m::value::Value)
    requires
        value_wf(a),
        value_wf(b),
    ensures
        #[trigger] value_eq(&a, &b) == (a == b),
    decreases a,
{
    match (a, b) {
        (Value::Prim(x), Value::Prim(y)) => lemma_prim_eq(x, y),
        (Value::Set(xs), Value::Set(ys)) => lemma_values_eq(*xs, *ys),
        (Value::Record(xs), Value::Record(ys)) => lemma_attrs_eq(*xs, *ys),
        (Value::Ext(x), Value::Ext(y)) => lemma_ext_eq(x, y),
        _ => {},
    }
}

/// On well-formed extension values, `ext_eq` is `==`.
pub proof fn lemma_ext_eq(a: super::model::ext::Ext, b: super::model::ext::Ext)
    requires
        super::model::ext::ext_wf(&a),
        super::model::ext::ext_wf(&b),
    ensures
        super::model::ext::ext_eq(&a, &b) == (a == b),
{
    use super::model::ext::{Ext, IPNet};
    match (a, b) {
        (Ext::IPAddr(IPNet::V4(x, p)), Ext::IPAddr(IPNet::V4(y, q))) => {},
        (Ext::IPAddr(IPNet::V6(x, p)), Ext::IPAddr(IPNet::V6(y, q))) => {},
        _ => {},
    }
}

pub broadcast proof fn lemma_values_eq(a: m::value::List<m::value::Value>, b: m::value::List<m::value::Value>)
    requires
        values_wf(a),
        values_wf(b),
    ensures
        #[trigger] values_eq(&a, &b) == (a == b),
    decreases a,
{
    match (a, b) {
        (List::Cons(x, a1), List::Cons(y, b1)) => {
            lemma_value_eq(x, y);
            lemma_values_eq(*a1, *b1);
        },
        _ => {},
    }
}

pub broadcast proof fn lemma_attrs_eq(a: m::value::Attrs, b: m::value::Attrs)
    requires
        attrs_wf(a),
        attrs_wf(b),
    ensures
        #[trigger] attrs_eq(&a, &b) == (a == b),
    decreases a,
{
    match (a, b) {
        (List::Cons((k, x), a1), List::Cons((l, y), b1)) => {
            lemma_str_eq(k, l);
            lemma_value_eq(x, y);
            lemma_attrs_eq(*a1, *b1);
        },
        _ => {},
    }
}

// ---------------------------------------------------------------------------
// Entity membership
// ---------------------------------------------------------------------------

/// The entity in a value of the form `Prim(EntityUID(u))`.
pub open spec fn value_uid(v: m::value::Value) -> m::value::EntityUID {
    match v {
        Value::Prim(Prim::EntityUID(u)) => u,
        _ => arbitrary(),
    }
}

pub open spec fn is_uid_value(v: m::value::Value) -> bool {
    v matches Value::Prim(Prim::EntityUID(_))
}

/// `in_s` errors unless every element is an entity; else: is `u` in some element?
pub broadcast proof fn lemma_in_s(u: m::value::EntityUID, vs: m::value::List<m::value::Value>, es: m::entities::Entities)
    ensures
        #[trigger] in_s(&u, &vs, &es) == if forall|i: int|
            0 <= i < super::abs::list_view(vs).len() ==> is_uid_value(#[trigger] super::abs::list_view(vs)[i]) {
            Ok::<bool, m::value::Error>(exists|i: int|
                0 <= i < super::abs::list_view(vs).len() && #[trigger] in_e(
                    &u,
                    &value_uid(super::abs::list_view(vs)[i]),
                    &es,
                ))
        } else {
            Err::<bool, m::value::Error>(m::value::Error::TypeError)
        },
    decreases vs,
{
    match vs {
        List::Nil => {},
        List::Cons(v, rest) => {
            lemma_in_s(u, *rest, es);
            let l = super::abs::list_view(vs);
            let lr = super::abs::list_view(*rest);
            assert(l == seq![v] + lr);
            assert(forall|i: int| 0 <= i < lr.len() ==> l[i + 1] == lr[i]);
            if is_uid_value(v) {
                if forall|i: int| 0 <= i < lr.len() ==> is_uid_value(#[trigger] lr[i]) {
                    assert(forall|i: int| 0 <= i < l.len() ==> is_uid_value(#[trigger] l[i])) by {
                        assert forall|i: int| 0 <= i < l.len() implies is_uid_value(#[trigger] l[i]) by {
                            if i > 0 {
                                assert(l[i] == lr[i - 1]);
                            }
                        }
                    }
                    if in_e(&u, &value_uid(v), &es) {
                        assert(in_e(&u, &value_uid(l[0]), &es));
                    } else if exists|i: int| 0 <= i < lr.len() && #[trigger] in_e(&u, &value_uid(lr[i]), &es) {
                        let i = choose|i: int| 0 <= i < lr.len() && #[trigger] in_e(&u, &value_uid(lr[i]), &es);
                        assert(in_e(&u, &value_uid(l[i + 1]), &es));
                    } else {
                        assert forall|i: int| 0 <= i < l.len() implies !#[trigger] in_e(&u, &value_uid(l[i]), &es) by {
                            if i > 0 {
                                assert(l[i] == lr[i - 1]);
                            }
                        }
                    }
                } else {
                    let i = choose|i: int| 0 <= i < lr.len() && !is_uid_value(#[trigger] lr[i]);
                    assert(!is_uid_value(l[i + 1]));
                }
            } else {
                assert(!is_uid_value(l[0]));
            }
        },
    }
}

// ---------------------------------------------------------------------------
// One step of `has_attrs` (`x has a.rest`).
// ---------------------------------------------------------------------------

pub proof fn lemma_has_attrs_nil(v: Value, es: Entities)
    ensures
        has_attrs(&v, &List::Nil, &es) == Ok::<Value, Error>(bool_val(true)),
{
}

pub proof fn lemma_has_attrs_record(avs: Attrs, a: Str, rest: List<Str>, es: Entities)
    ensures
        has_attrs(&Value::Record(Box::new(avs)), &List::Cons(a, Box::new(rest)), &es)
            == match attrs_find(&avs, &a) {
            Some(v) => has_attrs(v, &rest, &es),
            None => Ok(bool_val(false)),
        },
{
}

pub proof fn lemma_has_attrs_entity(u: EntityUID, a: Str, rest: List<Str>, es: Entities)
    ensures
        has_attrs(&Value::Prim(Prim::EntityUID(u)), &List::Cons(a, Box::new(rest)), &es)
            == match entities_find(&es, &u) {
            Some(d) => match attrs_find(&d.attrs, &a) {
                Some(v) => has_attrs(v, &rest, &es),
                None => Ok(bool_val(false)),
            },
            None => Ok(bool_val(false)),
        },
{
    assert(has_attrs(&Value::Prim(Prim::EntityUID(u)), &List::Cons(a, Box::new(rest)), &es)
        == entity_has_attrs(&es, &u, &a, &rest));
    if let Some(d) = entities_find(&es, &u) {
        assert(entity_has_attrs(&es, &u, &a, &rest) == attrs_has_attrs(&d.attrs, &a, &rest, &es));
    }
}

pub proof fn lemma_has_attrs_type_error(v: Value, a: Str, rest: List<Str>, es: Entities)
    requires
        !(v is Record),
        !(v matches Value::Prim(Prim::EntityUID(_))),
    ensures
        has_attrs(&v, &List::Cons(a, Box::new(rest)), &es) is Err,
{
}

// ---------------------------------------------------------------------------
// Sets of strings
// ---------------------------------------------------------------------------

pub proof fn lemma_list_view_cons_set<T>(x: T, rest: m::value::List<T>)
    ensures
        super::abs::list_view(List::Cons(x, Box::new(rest))).to_set()
            == super::abs::list_view(rest).to_set().insert(x),
{
    let l = super::abs::list_view(List::Cons(x, Box::new(rest)));
    let r = super::abs::list_view(rest);
    assert(l == seq![x] + r);
    assert forall|y: T| l.to_set().contains(y) <==> r.to_set().insert(x).contains(y) by {
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
        if y == x {
            assert(l[0] == y);
        }
    }
    assert(l.to_set() =~= r.to_set().insert(x));
}

pub proof fn lemma_char_lt_trichotomy(c: char, d: char)
    ensures
        char_lt(c, d) || char_lt(d, c) || c == d,
{
    if (c as u32) == (d as u32) {
        assert(c == d);
    }
}

pub proof fn lemma_str_lt_trichotomy(a: m::value::Str, b: m::value::Str)
    ensures
        str_lt(&a, &b) || str_lt(&b, &a) || a == b,
    decreases a,
{
    match (a, b) {
        (List::Cons(c, a1), List::Cons(d, b1)) => {
            lemma_char_lt_trichotomy(c, d);
            lemma_str_lt_trichotomy(*a1, *b1);
        },
        _ => {},
    }
}

pub proof fn lemma_strs_insert_set(x: m::value::Str, xs: m::value::List<m::value::Str>)
    ensures
        super::abs::list_view(strs_insert(x, xs)).to_set() == super::abs::list_view(xs).to_set().insert(x),
    decreases xs,
{
    match xs {
        List::Nil => {
            lemma_list_view_cons_set(x, List::<m::value::Str>::Nil);
            assert(super::abs::list_view(List::<m::value::Str>::Nil).to_set() =~= vstd::set::Set::<m::value::Str>::empty());
        },
        List::Cons(hd, tl) => {
            lemma_str_lt_trichotomy(x, hd);
            lemma_list_view_cons_set(hd, *tl);
            if str_lt(&x, &hd) {
                lemma_list_view_cons_set(x, xs);
            } else if str_lt(&hd, &x) {
                lemma_strs_insert_set(x, *tl);
                lemma_list_view_cons_set(hd, strs_insert(x, *tl));
                assert(super::abs::list_view(strs_insert(x, xs)).to_set()
                    =~= super::abs::list_view(xs).to_set().insert(x));
            } else {
                lemma_list_view_cons_set(x, *tl);
                assert(super::abs::list_view(strs_insert(x, xs)).to_set()
                    =~= super::abs::list_view(xs).to_set().insert(x));
            }
        },
    }
}

pub proof fn lemma_strs_canonicalize_set(xs: m::value::List<m::value::Str>)
    ensures
        super::abs::list_view(strs_canonicalize(xs)).to_set() == super::abs::list_view(xs).to_set(),
    decreases xs,
{
    match xs {
        List::Nil => {},
        List::Cons(hd, tl) => {
            lemma_strs_canonicalize_set(*tl);
            lemma_strs_insert_set(hd, strs_canonicalize(*tl));
            lemma_list_view_cons_set(hd, *tl);
        },
    }
}

// ---------------------------------------------------------------------------
// Lists and evaluation of list/record literals
// ---------------------------------------------------------------------------

/// A list is determined by its elements.
pub proof fn lemma_list_view_seq_to_list<T>(s: Seq<T>)
    ensures
        super::abs::list_view(super::abs::seq_to_list(s)) == s,
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_list_view_seq_to_list(s.subrange(1, s.len() as int));
        assert(s =~= seq![s[0]] + s.subrange(1, s.len() as int));
    } else {
        assert(s =~= Seq::<T>::empty());
    }
}

pub proof fn lemma_seq_to_list_list_view<T>(l: List<T>)
    ensures
        super::abs::seq_to_list(super::abs::list_view(l)) == l,
    decreases l,
{
    match l {
        List::Nil => {},
        List::Cons(x, rest) => {
            lemma_seq_to_list_list_view(*rest);
            let s = super::abs::list_view(l);
            assert(s.subrange(1, s.len() as int) =~= super::abs::list_view(*rest));
        },
    }
}

/// `evaluate_list` succeeds iff every element does, returning their values.
pub proof fn lemma_evaluate_list(xs: List<Expr>, req: Request, es: Entities)
    ensures
        (evaluate_list(&xs, &req, &es) is Ok) == (forall|j: int|
            0 <= j < super::abs::list_view(xs).len() ==> #[trigger] evaluate(&super::abs::list_view(xs)[j], &req, &es) is Ok),
        evaluate_list(&xs, &req, &es) matches Ok(vs) ==> {
            &&& super::abs::list_view(vs).len() == super::abs::list_view(xs).len()
            &&& forall|j: int| 0 <= j < super::abs::list_view(xs).len() ==> #[trigger] evaluate(
                &super::abs::list_view(xs)[j],
                &req,
                &es,
            ) == Ok::<Value, Error>(super::abs::list_view(vs)[j])
        },
    decreases xs,
{
    match xs {
        List::Nil => {},
        List::Cons(x, rest) => {
            lemma_evaluate_list(*rest, req, es);
            let l = super::abs::list_view(xs);
            let lr = super::abs::list_view(*rest);
            assert(l == seq![x] + lr);
            assert(l[0] == x);
            assert(forall|j: int| 0 <= j < lr.len() ==> l[j + 1] == lr[j]);
            match evaluate(&x, &req, &es) {
                Ok(v) => {
                    if forall|j: int| 0 <= j < lr.len() ==> #[trigger] evaluate(&lr[j], &req, &es) is Ok {
                        assert forall|j: int| 0 <= j < l.len() implies #[trigger] evaluate(&l[j], &req, &es) is Ok by {
                            if j > 0 {
                                assert(l[j] == lr[j - 1]);
                            }
                        }
                        let vs = evaluate_list(&xs, &req, &es)->Ok_0;
                        let vsr = evaluate_list(&*rest, &req, &es)->Ok_0;
                        assert(super::abs::list_view(vs) == seq![v] + super::abs::list_view(vsr));
                        assert forall|j: int| 0 <= j < l.len() implies #[trigger] evaluate(&l[j], &req, &es)
                            == Ok::<Value, Error>(super::abs::list_view(vs)[j]) by {
                            if j > 0 {
                                assert(l[j] == lr[j - 1]);
                            }
                        }
                    } else {
                        let j = choose|j: int| 0 <= j < lr.len() && !(#[trigger] evaluate(&lr[j], &req, &es) is Ok);
                        assert(!(evaluate(&l[j + 1], &req, &es) is Ok));
                    }
                },
                Err(_) => {
                    assert(!(evaluate(&l[0], &req, &es) is Ok));
                },
            }
        },
    }
}

/// `evaluate_attrs` succeeds iff every attribute does, returning their values.
pub proof fn lemma_evaluate_attrs(axs: List<(Str, Expr)>, req: Request, es: Entities)
    ensures
        (evaluate_attrs(&axs, &req, &es) is Ok) == (forall|j: int|
            0 <= j < super::abs::list_view(axs).len() ==> #[trigger] evaluate(&super::abs::list_view(axs)[j].1, &req, &es) is Ok),
        evaluate_attrs(&axs, &req, &es) matches Ok(avs) ==> {
            &&& super::abs::list_view(avs).len() == super::abs::list_view(axs).len()
            &&& forall|j: int| 0 <= j < super::abs::list_view(axs).len() ==> {
                &&& #[trigger] evaluate(&super::abs::list_view(axs)[j].1, &req, &es)
                    == Ok::<Value, Error>(super::abs::list_view(avs)[j].1)
                &&& super::abs::list_view(avs)[j].0 == super::abs::list_view(axs)[j].0
            }
        },
    decreases axs,
{
    broadcast use lemma_clone_str;
    match axs {
        List::Nil => {},
        List::Cons((a, x), rest) => {
            lemma_evaluate_attrs(*rest, req, es);
            let l = super::abs::list_view(axs);
            let lr = super::abs::list_view(*rest);
            assert(l == seq![(a, x)] + lr);
            assert(l[0] == (a, x));
            assert(forall|j: int| 0 <= j < lr.len() ==> l[j + 1] == lr[j]);
            match evaluate(&x, &req, &es) {
                Ok(v) => {
                    if forall|j: int| 0 <= j < lr.len() ==> #[trigger] evaluate(&lr[j].1, &req, &es) is Ok {
                        assert forall|j: int| 0 <= j < l.len() implies #[trigger] evaluate(&l[j].1, &req, &es) is Ok by {
                            if j > 0 {
                                assert(l[j] == lr[j - 1]);
                            }
                        }
                        let avs = evaluate_attrs(&axs, &req, &es)->Ok_0;
                        let avsr = evaluate_attrs(&*rest, &req, &es)->Ok_0;
                        assert(super::abs::list_view(avs) == seq![(a, v)] + super::abs::list_view(avsr));
                        assert forall|j: int| 0 <= j < l.len() implies {
                            &&& #[trigger] evaluate(&l[j].1, &req, &es) == Ok::<Value, Error>(super::abs::list_view(avs)[j].1)
                            &&& super::abs::list_view(avs)[j].0 == l[j].0
                        } by {
                            if j > 0 {
                                assert(l[j] == lr[j - 1]);
                            }
                        }
                    } else {
                        let j = choose|j: int| 0 <= j < lr.len() && !(#[trigger] evaluate(&lr[j].1, &req, &es) is Ok);
                        assert(!(evaluate(&l[j + 1].1, &req, &es) is Ok));
                    }
                },
                Err(_) => {
                    assert(!(evaluate(&l[0].1, &req, &es) is Ok));
                },
            }
        },
    }
}

pub broadcast group group_model_eq {
    lemma_clone_str,
    lemma_clone_strs,
    lemma_clone_name,
    lemma_clone_uid,
    lemma_clone_prim,
    lemma_clone_value,
    lemma_clone_values,
    lemma_clone_attrs,
    lemma_str_eq,
    lemma_strs_eq,
    lemma_name_eq,
    lemma_uid_eq,
    lemma_prim_eq,
    lemma_value_eq,
    lemma_values_eq,
    lemma_attrs_eq,
    lemma_in_s,
    lemma_clone_ext,
    lemma_clone_extfun,
}

} // verus!
