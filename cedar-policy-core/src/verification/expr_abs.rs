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

//! Abstraction of production expressions (`abs_expr`) and which expressions
//! are modeled (`expr_modeled`). Children are recursed over by index; the
//! lemmas below restate the definitions with children as sequences.

use vstd::prelude::*;

use super::abs::*;
use super::map_entries::*;
use super::model as m;
use super::trusted::*;
use super::value_abs::*;
use crate::ast::*;
use smol_str::SmolStr;
use std::collections::BTreeMap;

verus! {

broadcast use vstd::std_specs::btree::axiom_btree_map_decreases, vstd::map::axiom_map_index_decreases,
    vstd::std_specs::vec::axiom_vec_index_decreases;

/// The entries of a record literal in key order (= `BTreeMap` iteration order)
pub open spec fn expr_entries(r: BTreeMap<SmolStr, Expr>) -> Seq<(SmolStr, Expr)> {
    sorted_entries(r@)
}

/// The children of a set literal or of an extension call
pub open spec fn kids(e: Expr) -> Seq<Expr> {
    match e.spec_kind() {
        ExprKind::Set(xs) => (*xs)@,
        ExprKind::ExtensionFunctionApp { fn_name, args } => (*args)@,
        _ => Seq::empty(),
    }
}

/// The entries of a record literal
pub open spec fn kid_entries(e: Expr) -> Seq<(SmolStr, Expr)> {
    match e.spec_kind() {
        ExprKind::Record(r) => expr_entries(*r),
        _ => Seq::empty(),
    }
}

pub proof fn lemma_kids_decrease(e: Expr)
    ensures
        forall|i: int| 0 <= i < kids(e).len() ==> decreases_to!(e => #[trigger] kids(e)[i]),
        forall|i: int| 0 <= i < kid_entries(e).len() ==> decreases_to!(e => #[trigger] kid_entries(e)[i].1),
{
    e.lemma_kind_decreases();
    match e.spec_kind() {
        ExprKind::Set(xs) => {
            assert forall|i: int| 0 <= i < kids(e).len() implies decreases_to!(e => #[trigger] kids(e)[i]) by {
                assert(decreases_to!(*xs => (*xs)[i]));
            }
        },
        ExprKind::ExtensionFunctionApp { fn_name, args } => {
            assert forall|i: int| 0 <= i < kids(e).len() implies decreases_to!(e => #[trigger] kids(e)[i]) by {
                assert(decreases_to!(*args => (*args)[i]));
            }
        },
        ExprKind::Record(r) => {
            lemma_sorted_entries((*r)@);
            assert forall|i: int| 0 <= i < kid_entries(e).len() implies decreases_to!(e => #[trigger] kid_entries(e)[i].1) by {
                let k = kid_entries(e)[i].0;
                assert((*r)@.dom().contains(k));
                assert(decreases_to!((*r)@ => (*r)@[k]));
            }
        },
        _ => {},
    }
}

// ---------------------------------------------------------------------------
// Abstraction
// ---------------------------------------------------------------------------

/// Abstraction of production expressions, with slots filled from `slots`.
/// Only meaningful for `expr_modeled` expressions.
pub open spec fn abs_expr(e: Expr, slots: SlotEnv) -> m::expr::Expr
    decreases e, 1nat, 0nat via abs_expr_decreases
{
    match e.spec_kind() {
        ExprKind::Lit(l) => m::expr::Expr::Lit(abs_lit(l)),
        ExprKind::Var(v) => m::expr::Expr::Var(abs_var(v)),
        ExprKind::Slot(id) => m::expr::Expr::Lit(m::value::Prim::EntityUID(abs_uid(slots@[id]))),
        ExprKind::If { test_expr, then_expr, else_expr } => m::expr::Expr::Ite(
            Box::new(abs_expr(*test_expr, slots)),
            Box::new(abs_expr(*then_expr, slots)),
            Box::new(abs_expr(*else_expr, slots)),
        ),
        ExprKind::And { left, right } => m::expr::Expr::And(
            Box::new(abs_expr(*left, slots)),
            Box::new(abs_expr(*right, slots)),
        ),
        ExprKind::Or { left, right } => m::expr::Expr::Or(
            Box::new(abs_expr(*left, slots)),
            Box::new(abs_expr(*right, slots)),
        ),
        ExprKind::UnaryApp { op, arg } => m::expr::Expr::UnaryApp(
            abs_unary_op(op).unwrap(),
            Box::new(abs_expr(*arg, slots)),
        ),
        ExprKind::BinaryApp { op, arg1, arg2 } => m::expr::Expr::BinaryApp(
            abs_binary_op(op),
            Box::new(abs_expr(*arg1, slots)),
            Box::new(abs_expr(*arg2, slots)),
        ),
        ExprKind::GetAttr { expr, attr } => m::expr::Expr::GetAttr(Box::new(abs_expr(*expr, slots)), abs_str(attr)),
        ExprKind::HasAttr { expr, attr } => m::expr::Expr::HasAttr(Box::new(abs_expr(*expr, slots)), abs_str(attr)),
        ExprKind::ExtHasAttr { expr, attrs } => m::expr::Expr::ExtHasAttr(
            Box::new(abs_expr(*expr, slots)),
            abs_str(attrs.head),
            seq_to_list(attrs.tail@.map_values(|a: SmolStr| abs_str(a))),
        ),
        ExprKind::Like { expr, pattern } => m::expr::Expr::UnaryApp(
            m::expr::UnaryOp::Like(abs_pattern(pattern)),
            Box::new(abs_expr(*expr, slots)),
        ),
        ExprKind::Is { expr, entity_type } => m::expr::Expr::UnaryApp(
            m::expr::UnaryOp::Is(abs_entity_type(entity_type)),
            Box::new(abs_expr(*expr, slots)),
        ),
        ExprKind::Set(xs) => m::expr::Expr::Set(Box::new(abs_kids(e, slots, 0))),
        ExprKind::Record(r) => m::expr::Expr::Record(Box::new(abs_kid_entries(e, slots, 0))),
        ExprKind::ExtensionFunctionApp { fn_name, args } => match super::ext_abs::ext_fun_of_name(fn_name) {
            Some(f) => m::expr::Expr::Call(f, Box::new(abs_kids(e, slots, 0))),
            None => m::expr::Expr::Lit(m::value::Prim::Bool(false)),
        },
        _ => m::expr::Expr::Lit(m::value::Prim::Bool(false)),
    }
}

/// The abstractions of the children of `e`, from the `i`-th
pub open spec fn abs_kids(e: Expr, slots: SlotEnv, i: nat) -> m::value::List<m::expr::Expr>
    decreases e, 0nat, kids(e).len() - i via abs_kids_decreases
{
    if i < kids(e).len() {
        m::value::List::Cons(abs_expr(kids(e)[i as int], slots), Box::new(abs_kids(e, slots, i + 1)))
    } else {
        m::value::List::Nil
    }
}

/// The abstractions of the entries of `e`, from the `i`-th
pub open spec fn abs_kid_entries(e: Expr, slots: SlotEnv, i: nat) -> m::value::List<(m::value::Str, m::expr::Expr)>
    decreases e, 0nat, kid_entries(e).len() - i via abs_kid_entries_decreases
{
    if i < kid_entries(e).len() {
        m::value::List::Cons(
            (abs_str(kid_entries(e)[i as int].0), abs_expr(kid_entries(e)[i as int].1, slots)),
            Box::new(abs_kid_entries(e, slots, i + 1)),
        )
    } else {
        m::value::List::Nil
    }
}

/// Abstraction of a sequence of expressions
pub open spec fn abs_exprs(es: Vec<Expr>, slots: SlotEnv) -> m::value::List<m::expr::Expr> {
    seq_to_list(es@.map_values(|x: Expr| abs_expr(x, slots)))
}

/// Abstraction of the entries of a record literal
pub open spec fn abs_expr_record(r: BTreeMap<SmolStr, Expr>, slots: SlotEnv) -> m::value::List<(m::value::Str, m::expr::Expr)> {
    seq_to_list(expr_entries(r).map_values(|e: (SmolStr, Expr)| (abs_str(e.0), abs_expr(e.1, slots))))
}

// ---------------------------------------------------------------------------
// Modeled expressions
// ---------------------------------------------------------------------------

/// `e` has no unknowns, only slots bound in `slots`, and extension calls only
/// if `calls` (the evaluator passes `Evaluator::spec_ext_ok`).
pub open spec fn expr_modeled(e: Expr, slots: SlotEnv, calls: bool) -> bool
    decreases e, 1nat, 0nat via expr_modeled_decreases
{
    match e.spec_kind() {
        ExprKind::Lit(l) => true,
        ExprKind::Var(v) => true,
        ExprKind::Slot(id) => slots@.contains_key(id),
        ExprKind::If { test_expr, then_expr, else_expr } => expr_modeled(*test_expr, slots, calls)
            && expr_modeled(*then_expr, slots, calls) && expr_modeled(*else_expr, slots, calls),
        ExprKind::And { left, right } => expr_modeled(*left, slots, calls) && expr_modeled(*right, slots, calls),
        ExprKind::Or { left, right } => expr_modeled(*left, slots, calls) && expr_modeled(*right, slots, calls),
        ExprKind::UnaryApp { op, arg } => expr_modeled(*arg, slots, calls),
        ExprKind::BinaryApp { op, arg1, arg2 } => expr_modeled(*arg1, slots, calls) && expr_modeled(*arg2, slots, calls),
        ExprKind::GetAttr { expr, attr } => expr_modeled(*expr, slots, calls),
        ExprKind::HasAttr { expr, attr } => expr_modeled(*expr, slots, calls),
        ExprKind::ExtHasAttr { expr, attrs } => expr_modeled(*expr, slots, calls),
        ExprKind::Like { expr, pattern } => expr_modeled(*expr, slots, calls),
        ExprKind::Is { expr, entity_type } => expr_modeled(*expr, slots, calls),
        ExprKind::Set(xs) => kids_modeled(e, slots, calls, 0),
        ExprKind::Record(r) => kid_entries_modeled(e, slots, calls, 0),
        ExprKind::ExtensionFunctionApp { fn_name, args } => calls
            && super::ext_abs::ext_fun_of_name(fn_name) is Some
            && kids_modeled(e, slots, calls, 0),
        _ => false,
    }
}

/// The children of `e` are modeled, from the `i`-th
pub open spec fn kids_modeled(e: Expr, slots: SlotEnv, calls: bool, i: nat) -> bool
    decreases e, 0nat, kids(e).len() - i via kids_modeled_decreases
{
    i < kids(e).len() ==> expr_modeled(kids(e)[i as int], slots, calls) && kids_modeled(e, slots, calls, i + 1)
}

/// The entries of `e` are modeled, from the `i`-th
pub open spec fn kid_entries_modeled(e: Expr, slots: SlotEnv, calls: bool, i: nat) -> bool
    decreases e, 0nat, kid_entries(e).len() - i via kid_entries_modeled_decreases
{
    i < kid_entries(e).len() ==> expr_modeled(kid_entries(e)[i as int].1, slots, calls)
        && kid_entries_modeled(e, slots, calls, i + 1)
}

// Termination proofs for the definitions above

#[via_fn]
proof fn abs_expr_decreases(e: Expr, slots: SlotEnv) {
    e.lemma_kind_decreases();
}

#[via_fn]
proof fn abs_kids_decreases(e: Expr, slots: SlotEnv, i: nat) {
    lemma_kids_decrease(e);
}

#[via_fn]
proof fn abs_kid_entries_decreases(e: Expr, slots: SlotEnv, i: nat) {
    lemma_kids_decrease(e);
}

#[via_fn]
proof fn expr_modeled_decreases(e: Expr, slots: SlotEnv, calls: bool) {
    e.lemma_kind_decreases();
}

#[via_fn]
proof fn kids_modeled_decreases(e: Expr, slots: SlotEnv, calls: bool, i: nat) {
    lemma_kids_decrease(e);
}

#[via_fn]
proof fn kid_entries_modeled_decreases(e: Expr, slots: SlotEnv, calls: bool, i: nat) {
    lemma_kids_decrease(e);
}

// ---------------------------------------------------------------------------
// The definitions, one level at a time
// ---------------------------------------------------------------------------

proof fn lemma_abs_kids(e: Expr, slots: SlotEnv, i: nat)
    requires
        i <= kids(e).len(),
    ensures
        abs_kids(e, slots, i) == seq_to_list(kids(e).subrange(i as int, kids(e).len() as int).map_values(
            |x: Expr| abs_expr(x, slots),
        )),
    decreases kids(e).len() - i,
{
    let s = kids(e).subrange(i as int, kids(e).len() as int).map_values(|x: Expr| abs_expr(x, slots));
    if i < kids(e).len() {
        lemma_abs_kids(e, slots, i + 1);
        assert(s.subrange(1, s.len() as int) =~= kids(e).subrange(i + 1 as int, kids(e).len() as int).map_values(
            |x: Expr| abs_expr(x, slots),
        ));
    } else {
        assert(s =~= Seq::empty());
    }
}

proof fn lemma_abs_kid_entries(e: Expr, slots: SlotEnv, i: nat)
    requires
        i <= kid_entries(e).len(),
    ensures
        abs_kid_entries(e, slots, i) == seq_to_list(kid_entries(e).subrange(i as int, kid_entries(e).len() as int).map_values(
            |x: (SmolStr, Expr)| (abs_str(x.0), abs_expr(x.1, slots)),
        )),
    decreases kid_entries(e).len() - i,
{
    let s = kid_entries(e).subrange(i as int, kid_entries(e).len() as int).map_values(
        |x: (SmolStr, Expr)| (abs_str(x.0), abs_expr(x.1, slots)),
    );
    if i < kid_entries(e).len() {
        lemma_abs_kid_entries(e, slots, i + 1);
        assert(s.subrange(1, s.len() as int) =~= kid_entries(e).subrange(i + 1 as int, kid_entries(e).len() as int).map_values(
            |x: (SmolStr, Expr)| (abs_str(x.0), abs_expr(x.1, slots)),
        ));
    } else {
        assert(s =~= Seq::empty());
    }
}

proof fn lemma_kids_modeled(e: Expr, slots: SlotEnv, calls: bool, i: nat)
    requires
        i <= kids(e).len(),
    ensures
        kids_modeled(e, slots, calls, i) == forall|j: int| i <= j < kids(e).len() ==> #[trigger] expr_modeled(kids(e)[j], slots, calls),
    decreases kids(e).len() - i,
{
    if i < kids(e).len() {
        lemma_kids_modeled(e, slots, calls, i + 1);
        if kids_modeled(e, slots, calls, i) {
            assert forall|j: int| i <= j < kids(e).len() implies #[trigger] expr_modeled(kids(e)[j], slots, calls) by {
                if j > i {
                    assert(i + 1 <= j);
                }
            }
        }
        if forall|j: int| i <= j < kids(e).len() ==> #[trigger] expr_modeled(kids(e)[j], slots, calls) {
            assert(expr_modeled(kids(e)[i as int], slots, calls));
        }
    }
}

proof fn lemma_kid_entries_modeled(e: Expr, slots: SlotEnv, calls: bool, i: nat)
    requires
        i <= kid_entries(e).len(),
    ensures
        kid_entries_modeled(e, slots, calls, i) == forall|j: int|
            i <= j < kid_entries(e).len() ==> #[trigger] expr_modeled(kid_entries(e)[j].1, slots, calls),
    decreases kid_entries(e).len() - i,
{
    if i < kid_entries(e).len() {
        lemma_kid_entries_modeled(e, slots, calls, i + 1);
        if kid_entries_modeled(e, slots, calls, i) {
            assert forall|j: int| i <= j < kid_entries(e).len() implies #[trigger] expr_modeled(kid_entries(e)[j].1, slots, calls) by {
                if j > i {
                    assert(i + 1 <= j);
                }
            }
        }
        if forall|j: int| i <= j < kid_entries(e).len() ==> #[trigger] expr_modeled(kid_entries(e)[j].1, slots, calls) {
            assert(expr_modeled(kid_entries(e)[i as int].1, slots, calls));
        }
    }
}

/// Unfolds `abs_expr` one level. Not `broadcast`, to avoid matching loops.
pub proof fn lemma_abs_expr(e: Expr, slots: SlotEnv)
    ensures
        abs_expr(e, slots) == match e.spec_kind() {
            ExprKind::Lit(l) => m::expr::Expr::Lit(abs_lit(l)),
            ExprKind::Var(v) => m::expr::Expr::Var(abs_var(v)),
            ExprKind::Slot(id) => m::expr::Expr::Lit(m::value::Prim::EntityUID(abs_uid(slots@[id]))),
            ExprKind::If { test_expr, then_expr, else_expr } => m::expr::Expr::Ite(
                Box::new(abs_expr(*test_expr, slots)),
                Box::new(abs_expr(*then_expr, slots)),
                Box::new(abs_expr(*else_expr, slots)),
            ),
            ExprKind::And { left, right } => m::expr::Expr::And(
                Box::new(abs_expr(*left, slots)),
                Box::new(abs_expr(*right, slots)),
            ),
            ExprKind::Or { left, right } => m::expr::Expr::Or(
                Box::new(abs_expr(*left, slots)),
                Box::new(abs_expr(*right, slots)),
            ),
            ExprKind::UnaryApp { op, arg } => m::expr::Expr::UnaryApp(
                abs_unary_op(op).unwrap(),
                Box::new(abs_expr(*arg, slots)),
            ),
            ExprKind::BinaryApp { op, arg1, arg2 } => m::expr::Expr::BinaryApp(
                abs_binary_op(op),
                Box::new(abs_expr(*arg1, slots)),
                Box::new(abs_expr(*arg2, slots)),
            ),
            ExprKind::GetAttr { expr, attr } => m::expr::Expr::GetAttr(Box::new(abs_expr(*expr, slots)), abs_str(attr)),
            ExprKind::HasAttr { expr, attr } => m::expr::Expr::HasAttr(Box::new(abs_expr(*expr, slots)), abs_str(attr)),
            ExprKind::ExtHasAttr { expr, attrs } => m::expr::Expr::ExtHasAttr(
                Box::new(abs_expr(*expr, slots)),
                abs_str(attrs.head),
                seq_to_list(attrs.tail@.map_values(|a: SmolStr| abs_str(a))),
            ),
            ExprKind::Like { expr, pattern } => m::expr::Expr::UnaryApp(
                m::expr::UnaryOp::Like(abs_pattern(pattern)),
                Box::new(abs_expr(*expr, slots)),
            ),
            ExprKind::Is { expr, entity_type } => m::expr::Expr::UnaryApp(
                m::expr::UnaryOp::Is(abs_entity_type(entity_type)),
                Box::new(abs_expr(*expr, slots)),
            ),
            ExprKind::Set(xs) => m::expr::Expr::Set(Box::new(abs_exprs(*xs, slots))),
            ExprKind::Record(r) => m::expr::Expr::Record(Box::new(abs_expr_record(*r, slots))),
            ExprKind::ExtensionFunctionApp { fn_name, args } => match super::ext_abs::ext_fun_of_name(fn_name) {
                Some(f) => m::expr::Expr::Call(f, Box::new(abs_exprs(*args, slots))),
                None => m::expr::Expr::Lit(m::value::Prim::Bool(false)),
            },
            _ => m::expr::Expr::Lit(m::value::Prim::Bool(false)),
        },
{
    match e.spec_kind() {
        ExprKind::Set(xs) => {
            lemma_abs_kids(e, slots, 0);
            assert(kids(e).subrange(0, kids(e).len() as int) =~= (*xs)@);
        },
        ExprKind::ExtensionFunctionApp { fn_name, args } => {
            lemma_abs_kids(e, slots, 0);
            assert(kids(e).subrange(0, kids(e).len() as int) =~= (*args)@);
        },
        ExprKind::Record(r) => {
            lemma_abs_kid_entries(e, slots, 0);
            assert(kid_entries(e).subrange(0, kid_entries(e).len() as int) =~= expr_entries(*r));
        },
        _ => {},
    }
}

/// Unfolds `expr_modeled` one level (not `broadcast`; see above)
pub proof fn lemma_expr_modeled(e: Expr, slots: SlotEnv, calls: bool)
    ensures
        expr_modeled(e, slots, calls) == match e.spec_kind() {
            ExprKind::Lit(l) => true,
            ExprKind::Var(v) => true,
            ExprKind::Slot(id) => slots@.contains_key(id),
            ExprKind::If { test_expr, then_expr, else_expr } => expr_modeled(*test_expr, slots, calls)
                && expr_modeled(*then_expr, slots, calls) && expr_modeled(*else_expr, slots, calls),
            ExprKind::And { left, right } => expr_modeled(*left, slots, calls) && expr_modeled(*right, slots, calls),
            ExprKind::Or { left, right } => expr_modeled(*left, slots, calls) && expr_modeled(*right, slots, calls),
            ExprKind::UnaryApp { op, arg } => expr_modeled(*arg, slots, calls),
            ExprKind::BinaryApp { op, arg1, arg2 } => expr_modeled(*arg1, slots, calls) && expr_modeled(*arg2, slots, calls),
            ExprKind::GetAttr { expr, attr } => expr_modeled(*expr, slots, calls),
            ExprKind::HasAttr { expr, attr } => expr_modeled(*expr, slots, calls),
            ExprKind::ExtHasAttr { expr, attrs } => expr_modeled(*expr, slots, calls),
            ExprKind::Like { expr, pattern } => expr_modeled(*expr, slots, calls),
            ExprKind::Is { expr, entity_type } => expr_modeled(*expr, slots, calls),
            ExprKind::Set(xs) => forall|i: int| 0 <= i < xs@.len() ==> #[trigger] expr_modeled(xs@[i], slots, calls),
            ExprKind::Record(r) => forall|i: int|
                0 <= i < expr_entries(*r).len() ==> #[trigger] expr_modeled(expr_entries(*r)[i].1, slots, calls),
            ExprKind::ExtensionFunctionApp { fn_name, args } => calls
                && super::ext_abs::ext_fun_of_name(fn_name) is Some
                && forall|i: int| 0 <= i < args@.len() ==> #[trigger] expr_modeled(args@[i], slots, calls),
            _ => false,
        },
{
    match e.spec_kind() {
        ExprKind::Set(xs) => lemma_kids_modeled(e, slots, calls, 0),
        ExprKind::ExtensionFunctionApp { fn_name, args } => lemma_kids_modeled(e, slots, calls, 0),
        ExprKind::Record(r) => lemma_kid_entries_modeled(e, slots, calls, 0),
        _ => {},
    }
}

pub broadcast proof fn lemma_abs_exprs(es: Vec<Expr>, slots: SlotEnv)
    ensures
        list_view(#[trigger] abs_exprs(es, slots)) == es@.map_values(|x: Expr| abs_expr(x, slots)),
{
    super::model_lemmas::lemma_list_view_seq_to_list(es@.map_values(|x: Expr| abs_expr(x, slots)));
}

pub broadcast proof fn lemma_abs_expr_record(r: BTreeMap<SmolStr, Expr>, slots: SlotEnv)
    ensures
        list_view(#[trigger] abs_expr_record(r, slots)) == expr_entries(r).map_values(
            |e: (SmolStr, Expr)| (abs_str(e.0), abs_expr(e.1, slots)),
        ),
{
    super::model_lemmas::lemma_list_view_seq_to_list(
        expr_entries(r).map_values(|e: (SmolStr, Expr)| (abs_str(e.0), abs_expr(e.1, slots))),
    );
}

/// The entries of a record literal, sorted by key
pub proof fn lemma_expr_entries(r: BTreeMap<SmolStr, Expr>)
    ensures
        expr_entries(r).to_set() == r@.kv_pairs(),
        sorted_by_key(expr_entries(r)),
{
    lemma_sorted_entries(r@);
}

pub broadcast group group_expr_abs {
    lemma_abs_exprs,
    lemma_abs_expr_record,
}

} // verus!
