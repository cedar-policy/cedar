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

//! This module contains a spec of the Cedar evaluator, translated to Verus spec code
//! from the Lean spec in cedar-spec/cedar-lean/Cedar/Spec/Evaluator.lean.

#![allow(missing_debug_implementations)] // vstd types Seq/Set/Map don't impl Debug
#![allow(missing_docs)] // just for now
#![allow(unused_imports)]

use core::prelude::v1;

pub use crate::spec::spec_ast::*;
pub use crate::verus_utils::*;
use regex::escape;
#[cfg(verus_keep_ghost)]
pub use vstd::{map::*, prelude::*, seq::*, set::*};

verus! {

// Spec symbol representing the check that we have enough stack space
pub uninterp spec fn enough_stack_space() -> bool;


#[verifier::inline]
pub open spec fn int_or_err(x: Option<i64>) -> SpecResult<Value> {
    match x {
        Some(i) => Ok(Value::int(i)),
        None => Err(Error::ArithBoundsError)
    }
}

pub open spec fn apply_1(u: UnaryOp, v: Value) -> SpecResult<Value> {
    match (u, v) {
        (UnaryOp::Not, Value::Prim { p: Prim::Bool { b }}) => Ok(Value::bool(!b)),
        (UnaryOp::Neg, Value::Prim { p: Prim::Int { i }}) => int_or_err(checked_neg(i)),
        (UnaryOp::IsEmpty, Value::Set { s }) => Ok(Value::bool(s.is_empty())),
        // TODO: patterns
        // (UnaryOp::Like { p }, Value::Prim { p: Prim::String { s }}) => Ok(Value::prim(Prim::pbool(wildcard_match(s, p))))
        (UnaryOp::Is { ety }, Value::Prim { p: Prim::EntityUID { uid }}) => Ok(Value::bool(ety == uid.ty)),
        (_, _) => Err(Error::TypeError)
    }
}

pub open spec fn in_e(uid1: EntityUID, uid2: EntityUID, es: Entities) -> bool {
    uid1 == uid2 || entities_ancestors_or_empty(es, uid1).contains(uid2)
}

pub open spec fn in_s(uid: EntityUID, vs: FiniteSet<Value>, es: Entities) -> SpecResult<Value> {
    let uids_r = valueset_as_entity_uid(vs);
    match uids_r {
        Ok(uids) => {
            let b = uids.any(|u: EntityUID| in_e(uid, u, es));
            Ok(Value::bool(b))
        },
        Err(err) => Err(err)
    }
}

pub open spec fn has_tag(uid: EntityUID, tag: Tag, es: Entities) -> SpecResult<Value> {
    Ok(Value::bool(entities_tags_or_empty(es, uid).contains_key(tag)))
}

pub open spec fn get_tag(uid: EntityUID, tag: Tag, es: Entities) -> SpecResult<Value> {
    let tags_r = entities_tags(es, uid);
    match tags_r {
        Ok(tags) => {
            tags.get(tag).ok_or(Error::TagDoesNotExist)
        },
        Err(err) => Err(err)
    }
}

pub open spec fn apply_2(op2: BinaryOp, v1: Value, v2: Value, es: Entities) -> SpecResult<Value> {
    match (op2, v1, v2) {
        (BinaryOp::Eq, _, _) => Ok(Value::bool(v1 == v2)),
        (BinaryOp::Less, Value::Prim { p: Prim::Int { i } }, Value::Prim { p: Prim::Int { i: j } }) =>
            Ok(Value::bool(i < j)),
        // TODO: datetime and duration cases for BinaryOp::Less
        // (BinaryOp::Less, Value::Ext { e: Ext::Datetime { d: d1 } }, Value::Ext { e: Ext::Datetime { d: d2 } }) =>
        //     Ok(Value::bool(d1 < d2)),
        // (BinaryOp::Less, Value::Ext { e: Ext::Duration { d: d1 } }, Value::Ext { e: Ext::Duration { d: d2 } }) =>
        //     Ok(Value::bool(d1 < d2)),
        (BinaryOp::LessEq, Value::Prim { p: Prim::Int { i } }, Value::Prim { p: Prim::Int { i: j } }) =>
            Ok(Value::bool(i <= j)),
        // TODO: datetime and duration cases for BinaryOp::LessEq
        // (BinaryOp::LessEq, Value::Ext { e: Ext::Datetime { d: d1 } }, Value::Ext { e: Ext::Datetime { d: d2 } }) =>
        //     Ok(Value::bool(d1 <= d2)),
        // (BinaryOp::LessEq, Value::Ext { e: Ext::Duration { d: d1 } }, Value::Ext { e: Ext::Duration { d: d2 } }) =>
        //     Ok(Value::bool(d1 <= d2)),
        (BinaryOp::Add, Value::Prim { p: Prim::Int { i } }, Value::Prim { p: Prim::Int { i: j } }) =>
            int_or_err(checked_add(i, j)),
        (BinaryOp::Sub, Value::Prim { p: Prim::Int { i } }, Value::Prim { p: Prim::Int { i: j } }) =>
            int_or_err(checked_sub(i, j)),
        (BinaryOp::Mul, Value::Prim { p: Prim::Int { i } }, Value::Prim { p: Prim::Int { i: j } }) =>
            int_or_err(checked_mul(i, j)),
        (BinaryOp::Contains, Value::Set { s: vs1 }, v2) =>
            Ok(Value::bool(vs1.contains(v2))),
        (BinaryOp::ContainsAll, Value::Set { s: vs1 }, Value::Set { s: vs2 }) =>
            Ok(Value::bool(vs2.subset_of(vs1))),
        (BinaryOp::ContainsAny, Value::Set { s: vs1 }, Value::Set { s: vs2 }) =>
            Ok(Value::bool(!vs1.intersect(vs2).is_empty())),
        (BinaryOp::Mem, Value::Prim { p: Prim::EntityUID { uid: uid1 } }, Value::Prim { p: Prim::EntityUID { uid: uid2 } }) =>
            Ok(Value::bool(in_e(uid1, uid2, es))),
        (BinaryOp::Mem, Value::Prim { p: Prim::EntityUID { uid: uid1 } }, Value::Set { s: vs }) =>
            in_s(uid1, vs, es),
        (BinaryOp::HasTag, Value::Prim { p: Prim::EntityUID { uid: uid1 } }, Value::Prim { p: Prim::String { s: tag } }) =>
            has_tag(uid1, tag, es),
        (BinaryOp::GetTag, Value::Prim { p: Prim::EntityUID { uid: uid1 } }, Value::Prim { p: Prim::String { s: tag } }) =>
            get_tag(uid1, tag, es),
        (_, _, _) => Err(Error::TypeError)
    }
}

pub open spec fn attrs_of(v: Value, lookup: spec_fn(EntityUID) -> SpecResult<Map<Attr,Value>>) -> SpecResult<Map<Attr,Value>> {
    match v {
        Value::Record { m: r } => Ok(r),
        Value::Prim { p: Prim::EntityUID { uid } } => lookup(uid),
        _ => Err(Error::TypeError)
    }
}

pub open spec fn has_attr(v: Value, a: Attr, es: Entities) -> SpecResult<Value> {
    match attrs_of(v, |uid: EntityUID| Ok(entities_attrs_or_empty(es, uid))) {
        Ok(m) => Ok(Value::bool(m.contains_key(a))),
        Err(err) => Err(err)
    }
}

pub open spec fn get_attr(v: Value, a: Attr, es: Entities) -> SpecResult<Value> {
    match attrs_of(v, |uid: EntityUID| entities_attrs(es, uid)) {
        Ok(m) => match m.get(a) {
                Some(v) => Ok(v),
                None => Err(Error::AttrDoesNotExist)
        },
        Err(err) => Err(err)
    }
}

pub open spec fn evaluate(x: Expr, req: Request, es: Entities, slot_env: SlotEnv) -> SpecResult<Value>
    decreases x via evaluate_decreases
{
    match x {
        Expr::Lit { p } => Ok(Value::Prim { p }),
        Expr::Var { v } => match v {
            Var::Principal => Ok(Value::entity_uid(req.principal)),
            Var::Action => Ok(Value::entity_uid(req.action)),
            Var::Resource => Ok(Value::entity_uid(req.resource)),
            Var::Context => Ok(Value::Record { m: req.context }),
        },
        Expr::Slot { s } => {
            match slot_env.get(s) {
                Some(euid) => Ok(Value::entity_uid(euid)),
                None => Err(Error::UnlinkedSlot)
            }
        }
        Expr::Ite { cond, then_expr, else_expr } => {
            match evaluate(*cond, req, es, slot_env) {
                Ok(cond_result) => match cond_result {
                    Value::Prim { p: Prim::Bool { b } } => {
                        if b {
                            evaluate(*then_expr, req, es, slot_env)
                        } else {
                            evaluate(*else_expr, req, es, slot_env)
                        }
                    },
                    _ => Err(Error::TypeError),
                },
                Err(err) => Err(err),
            }
        },
        Expr::And { a, b } => {
            match evaluate(*a, req, es, slot_env) {
                Ok(a_result) => match a_result {
                    Value::Prim { p: Prim::Bool { b: bool_a } } => {
                        if !bool_a {
                            Ok(Value::bool(bool_a))
                        } else {
                            match evaluate(*b, req, es, slot_env) {
                                Ok(b_result) => match b_result {
                                    Value::Prim { p: Prim::Bool { b: bool_b } } => Ok(Value::bool(bool_b)),
                                    _ => Err(Error::TypeError),
                                },
                                Err(err) => Err(err),
                            }
                        }
                    },
                    _ => Err(Error::TypeError),
                },
                Err(err) => Err(err),
            }
        },
        Expr::Or { a, b } => {
            match evaluate(*a, req, es, slot_env) {
                Ok(a_result) => match a_result {
                    Value::Prim { p: Prim::Bool { b: bool_a } } => {
                        if bool_a {
                            Ok(Value::bool(bool_a))
                        } else {
                            match evaluate(*b, req, es, slot_env) {
                                Ok(b_result) => match b_result {
                                    Value::Prim { p: Prim::Bool { b: bool_b } } => Ok(Value::bool(bool_b)),
                                    _ => Err(Error::TypeError),
                                },
                                Err(e) => Err(e),
                            }
                        }
                    },
                    _ => Err(Error::TypeError),
                },
                Err(err) => Err(err),
            }
        },
        Expr::UnaryApp { uop, expr } => {
            match evaluate(*expr, req, es, slot_env) {
                Ok(v) => apply_1(uop, v),
                Err(err) => Err(err),
            }
        },
        Expr::BinaryApp { bop, a, b } => {
            match evaluate(*a, req, es, slot_env) {
                Ok(v1) => match evaluate(*b, req, es, slot_env) {
                    Ok(v2) => apply_2(bop, v1, v2, es),
                    Err(err) => Err(err),
                },
                Err(err) => Err(err),
            }
        },
        Expr::HasAttr { expr, attr } => {
            match evaluate(*expr, req, es, slot_env) {
                Ok(v1) => has_attr(v1, attr, es),
                Err(err) => Err(err),
            }
        },
        Expr::GetAttr { expr, attr } => {
            match evaluate(*expr, req, es, slot_env) {
                Ok(v1) => get_attr(v1, attr, es),
                Err(err) => Err(err),
            }
        },
        Expr::Set { ls } => {
            let vs_r = evaluate_expr_seq(ls, req, es, slot_env);
            match vs_r {
                Ok(vs) => Ok(Value::Set { s: FiniteSet::from_seq(vs) }),
                Err(err) => Err(err)
            }
        },
        Expr::Record { map } => {
            // TODO: this doesn't guarantee which map entry's error will be returned, but does guarantee
            // that if any element in the map results in error, then some error will be returned.
            // This is analogous to the property checked by DRT, but may not be strong enough to verify the impl
            let entries_evaluated_rs = map.map_values(|mx: Expr| {
                // Needed to prove termination
                if map.dom().finite() && map.contains_value(mx) {
                    evaluate(mx, req, es, slot_env)
                } else {
                    arbitrary()
                }
            });
            if entries_evaluated_rs.values().any(|vr: SpecResult<Value>| vr is Err) {
                // return one of the errors in the set
                entries_evaluated_rs.values().filter(|vr: SpecResult<Value>| vr is Err).choose()
            } else {
                let entries_evaluated =
                    entries_evaluated_rs.map_values(|x: SpecResult<Value>| x->Ok_0);
                Ok(Value::Record { m: entries_evaluated })
            }
        },
        // TODO: case for ExtFun call
    }
}

#[via_fn]
proof fn evaluate_decreases(x: Expr, req: Request, es: Entities, slot_env: SlotEnv) {
    match x {
        Expr::Record { map } => {
            assert(forall |mx: Expr| map.dom().finite() && map.contains_value(mx) ==> decreases_to!(map => mx));
        },
        _ => {}
    };
}

// Short-circuiting evaluation of a sequence of `Expr`s, implemented recursively
pub open spec fn evaluate_expr_seq(exprs: Seq<Expr>, req: Request, es: Entities, slot_env: SlotEnv) -> SpecResult<Seq<Value>>
    decreases exprs
{
    if exprs.len() == 0 {
        Ok(seq![])
    } else {
        let last = exprs.last();
        match evaluate_expr_seq(exprs.drop_last(), req, es, slot_env) {
            Ok(front_seq) => match evaluate(last, req, es, slot_env) {
                Ok(last_val) => Ok(front_seq.push(last_val)),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        }
    }
}

}

///////////////////////////////////////////////////////
// Helper definitions and lemmas about the evaluator //
///////////////////////////////////////////////////////

verus! {

// if evaluate_expr_seq(exprs1, ...) is Err, then evaluate_expr_seq(exprs1 + exprs2, ...) is Err
pub proof fn evaluate_expr_seq_err_short_circuit_auto(exprs1: Seq<Expr>, req: Request, es: Entities, slot_env: SlotEnv)
    requires evaluate_expr_seq(exprs1, req, es, slot_env) is Err
    ensures forall |exprs2: Seq<Expr>| #[trigger] evaluate_expr_seq(#[trigger] (exprs1 + exprs2), req, es, slot_env) is Err
    decreases exprs1
{
    assert forall |exprs2: Seq<Expr>| #[trigger] evaluate_expr_seq(#[trigger] (exprs1 + exprs2), req, es, slot_env) is Err by {
        evaluate_expr_seq_err_short_circuit(exprs1, exprs2, req, es, slot_env)
    }
}

// if evaluate_expr_seq(exprs1, ...) is Err, then evaluate_expr_seq(exprs1 + exprs2, ...) is Err
pub proof fn evaluate_expr_seq_err_short_circuit(exprs1: Seq<Expr>, exprs2: Seq<Expr>, req: Request, es: Entities, slot_env: SlotEnv)
    requires evaluate_expr_seq(exprs1, req, es, slot_env) is Err
    ensures evaluate_expr_seq(exprs1 + exprs2, req, es, slot_env) is Err
    decreases exprs2
{
    if exprs2.len() >= 1 {
        assert(exprs1 + exprs2 =~= (exprs1.push(exprs2[0])) + exprs2.subrange(1, exprs2.len() as int));
        evaluate_expr_seq_err_short_circuit_aux(exprs1, exprs2[0], req, es, slot_env);
        evaluate_expr_seq_err_short_circuit(exprs1.push(exprs2[0]), exprs2.subrange(1, exprs2.len() as int), req, es, slot_env);
    }
}

// if evaluate_expr_seq(exprs1, ...) is Err, then evaluate_expr_seq(exprs1.push(expr2), ...) is Err
pub proof fn evaluate_expr_seq_err_short_circuit_aux(exprs1: Seq<Expr>, expr2: Expr, req: Request, es: Entities, slot_env: SlotEnv)
    requires evaluate_expr_seq(exprs1, req, es, slot_env) is Err
    ensures evaluate_expr_seq(exprs1.push(expr2), req, es, slot_env) is Err
{
    assert(exprs1.push(expr2).drop_last() =~= exprs1);
    if exprs1.len() > 0 {
        let last = exprs1.last();
        match evaluate_expr_seq(exprs1.drop_last(), req, es, slot_env) {
            Ok(front_seq) => match evaluate(last, req, es, slot_env) {
                Ok(last_val) => assert(false),
                Err(err) => {
                    assert(evaluate_expr_seq(exprs1, req, es, slot_env) is Err) by { reveal_with_fuel(evaluate_expr_seq, 1) };
                    assert(evaluate_expr_seq(exprs1.push(expr2), req, es, slot_env) is Err) by { reveal_with_fuel(evaluate_expr_seq, 1) };
                },
            },
            Err(err) => {
                assert(evaluate_expr_seq(exprs1, req, es, slot_env) is Err) by { reveal_with_fuel(evaluate_expr_seq, 1) };
                assert(evaluate_expr_seq(exprs1.push(expr2), req, es, slot_env) is Err) by { reveal_with_fuel(evaluate_expr_seq, 1) };
            },
        }
    }
}

// if evaluate_expr_seq(exprs1, ...) is Ok(vs1), and evaluate(expr2, ...) is Ok(v2), then evaluate_expr_seq(exprs1.push(expr2), ...) is Ok(vs1.push(v2))
pub proof fn evaluate_expr_seq_ok_push(exprs1: Seq<Expr>, expr2: Expr, req: Request, es: Entities, slot_env: SlotEnv)
    requires
        evaluate_expr_seq(exprs1, req, es, slot_env) is Ok,
        evaluate(expr2, req, es, slot_env) is Ok
    ensures ({
        &&& evaluate_expr_seq(exprs1.push(expr2), req, es, slot_env) matches Ok(vs)
        &&& vs == (evaluate_expr_seq(exprs1, req, es, slot_env)->Ok_0).push(evaluate(expr2, req, es, slot_env)->Ok_0)
    })
{
    assert(exprs1.push(expr2).drop_last() =~= exprs1);
    if exprs1.len() > 0 {
        let last = exprs1.last();
        match evaluate_expr_seq(exprs1.drop_last(), req, es, slot_env) {
            Ok(front_seq) => match evaluate(last, req, es, slot_env) {
                Ok(last_val) => {
                    reveal_with_fuel(evaluate_expr_seq, 2);
                },
                Err(err) => {
                    assert(false);
                },
            },
            Err(err) => {
                assert(false);
            },
        }
    }
}


// The concrete evaluator separates out the relation operations into a function that doesn't take `es: Entities` as argument;
// to simplify the proof, we provide this spec which we prove matches `apply_2` above on the arithmetic cases
pub open spec fn apply_2_relation(op2: BinaryOp, v1: Value, v2: Value) -> SpecResult<Value>
    recommends (op2 is Eq || op2 is Less || op2 is LessEq)
{
    if op2 is Eq || op2 is Less || op2 is LessEq {
        match (op2, v1, v2) {
            (BinaryOp::Eq, _, _) => Ok(Value::bool(v1 == v2)),
            (BinaryOp::Less, Value::Prim { p: Prim::Int { i } }, Value::Prim { p: Prim::Int { i: j } }) =>
                Ok(Value::bool(i < j)),
            // TODO: datetime and duration cases for BinaryOp::Less
            // (BinaryOp::Less, Value::Ext { e: Ext::Datetime { d: d1 } }, Value::Ext { e: Ext::Datetime { d: d2 } }) =>
            //     Ok(Value::bool(d1 < d2)),
            // (BinaryOp::Less, Value::Ext { e: Ext::Duration { d: d1 } }, Value::Ext { e: Ext::Duration { d: d2 } }) =>
            //     Ok(Value::bool(d1 < d2)),
            (BinaryOp::LessEq, Value::Prim { p: Prim::Int { i } }, Value::Prim { p: Prim::Int { i: j } }) =>
                Ok(Value::bool(i <= j)),
            // TODO: datetime and duration cases for BinaryOp::LessEq
            // (BinaryOp::LessEq, Value::Ext { e: Ext::Datetime { d: d1 } }, Value::Ext { e: Ext::Datetime { d: d2 } }) =>
            //     Ok(Value::bool(d1 <= d2)),
            // (BinaryOp::LessEq, Value::Ext { e: Ext::Duration { d: d1 } }, Value::Ext { e: Ext::Duration { d: d2 } }) =>
            //     Ok(Value::bool(d1 <= d2)),
            _ => Err(Error::TypeError)
        }
    } else {
        arbitrary()
    }
}

// Proof for `apply_2_relation`
pub proof fn lemma_apply_2_relation_correct(op2: BinaryOp, v1: Value, v2: Value, es: Entities)
    requires (op2 is Eq || op2 is Less || op2 is LessEq)
    ensures apply_2_relation(op2, v1, v2) == apply_2(op2, v1, v2, es)
{}


// The concrete evaluator separates out the arithmetic operations into a function that doesn't take `es: Entities` as argument;
// to simplify the proof, we provide this spec which we prove matches `apply_2` above on the arithmetic cases
pub open spec fn apply_2_arith(op2: BinaryOp, v1: Value, v2: Value) -> SpecResult<Value>
    recommends (op2 is Add || op2 is Sub || op2 is Mul)
{
    if op2 is Add || op2 is Sub || op2 is Mul {
        match (op2, v1, v2) {
            (BinaryOp::Add, Value::Prim { p: Prim::Int { i } }, Value::Prim { p: Prim::Int { i: j } }) =>
                int_or_err(checked_add(i, j)),
            (BinaryOp::Sub, Value::Prim { p: Prim::Int { i } }, Value::Prim { p: Prim::Int { i: j } }) =>
                int_or_err(checked_sub(i, j)),
            (BinaryOp::Mul, Value::Prim { p: Prim::Int { i } }, Value::Prim { p: Prim::Int { i: j } }) =>
                int_or_err(checked_mul(i, j)),
            _ => Err(Error::TypeError)
        }
    } else {
        arbitrary()
    }
}

// Proof for `apply_2_arith`
pub proof fn lemma_apply_2_arith_correct(op2: BinaryOp, v1: Value, v2: Value, es: Entities)
    requires (op2 is Add || op2 is Sub || op2 is Mul)
    ensures apply_2_arith(op2, v1, v2) == apply_2(op2, v1, v2, es)
{}



pub proof fn lemma_eval_and_spec(a: Expr, b: Expr, req: Request, es: Entities, slot_env: SlotEnv)
    ensures ({
        let a_result = evaluate(a, req, es, slot_env);
        let b_result = evaluate(b, req, es, slot_env);
        match (evaluate(a, req, es, slot_env), evaluate(b, req, es, slot_env)) {
            (Ok(Value::Prim { p: Prim::Bool { b: bool_a } }), Ok(Value::Prim { p: Prim::Bool { b: bool_b } })) =>
                evaluate(Expr::and(a, b), req, es, slot_env) matches Ok(Value::Prim { p: Prim::Bool { b } }) && b == (bool_a && bool_b),
            (Ok(Value::Prim { p: Prim::Bool { b: bool_a } }), _) => !bool_a ==>
                (evaluate(Expr::and(a, b), req, es, slot_env) matches Ok(Value::Prim { p: Prim::Bool { b } }) && b == false),
            (_, _) => evaluate(Expr::and(a, b), req, es, slot_env) is Err
        }
    })
{
    reveal_with_fuel(evaluate, 1);
}

pub proof fn lemma_eval_and_assoc(a: Expr, b: Expr, c: Expr, req: Request, es: Entities, slot_env: SlotEnv)
    ensures
        evaluate(Expr::and(a, Expr::and(b, c)), req, es, slot_env) matches Ok(v1) ==>
                evaluate(Expr::and(Expr::and(a, b), c), req, es, slot_env) matches Ok(v2) && v1 == v2,
        evaluate(Expr::and(a, Expr::and(b, c)), req, es, slot_env) is Err ==>
                evaluate(Expr::and(Expr::and(a, b), c), req, es, slot_env) is Err
{
    reveal_with_fuel(evaluate, 1);
    lemma_eval_and_spec(a, Expr::and(b, c), req, es, slot_env);
    lemma_eval_and_spec(Expr::and(a, b), c, req, es, slot_env);
}

pub proof fn lemma_evaluate_to_expr_left_assoc_equal(p: Policy, req: Request, entities: Entities)
    ensures
        evaluate(p.to_expr(), req, entities, p.slot_env) matches Ok(v) ==>
                evaluate(p.to_expr_left_assoc(), req, entities, p.slot_env) matches Ok(v_left) && v == v_left,
        evaluate(p.to_expr(), req, entities, p.slot_env) is Err ==>
                evaluate(p.to_expr_left_assoc(), req, entities, p.slot_env) is Err
{
    reveal(Policy::to_expr);
    reveal(Policy::to_expr_left_assoc);
    reveal(Template::to_expr);
    reveal(Template::to_expr_left_assoc);
    let p_scope_expr = p.template.principal_scope.to_expr();
    let a_scope_expr = p.template.action_scope.to_expr();
    let r_scope_expr = p.template.resource_scope.to_expr();
    let c_expr = p.template.condition;
    // (p, (a, (r, c))) == ((p, a), (r, c))
    lemma_eval_and_assoc(p_scope_expr, a_scope_expr, Expr::and(r_scope_expr, c_expr), req, entities, p.slot_env);
    // ((p, a), (r, c)) == (((p, a), r), c)
    lemma_eval_and_assoc(Expr::and(p_scope_expr, a_scope_expr), r_scope_expr, c_expr, req, entities, p.slot_env);
}

pub proof fn lemma_eval_and_bool_or_err(a: Expr, b: Expr, req: Request, es: Entities, slot_env: SlotEnv)
    ensures ({
        ||| evaluate(Expr::and(a, b), req, es, slot_env) matches Ok(v) && v is Prim && v->p is Bool
        ||| evaluate(Expr::and(a, b), req, es, slot_env) is Err
    })
{
    lemma_eval_and_spec(a, b, req, es, slot_env);
}

pub proof fn lemma_evaluate_to_expr_bool_or_err(p: Policy, req: Request, entities: Entities)
    ensures ({
        ||| evaluate(p.to_expr(), req, entities, p.slot_env) matches Ok(v) && v is Prim && v->p is Bool
        ||| evaluate(p.to_expr(), req, entities, p.slot_env) is Err
    })
{
    reveal(Policy::to_expr);
    reveal(Policy::to_expr_left_assoc);
    reveal(Template::to_expr);
    reveal(Template::to_expr_left_assoc);
    let p_scope_expr = p.template.principal_scope.to_expr();
    let a_scope_expr = p.template.action_scope.to_expr();
    let r_scope_expr = p.template.resource_scope.to_expr();
    let c_expr = p.template.condition;
    lemma_eval_and_spec(p_scope_expr, Expr::and(a_scope_expr, Expr::and(r_scope_expr, c_expr)), req, entities, p.slot_env);
}

pub open spec fn in_e_with_entity(uid1: EntityUID, entity1: Option<EntityData>, uid2: EntityUID) -> bool {
    uid1 == uid2 || (match entity1 {
        Some(e1) => e1.ancestors.contains(uid2),
        None => false,
    })
}

pub open spec fn in_s_with_entity(uid: EntityUID, entity1: Option<EntityData>, vs: FiniteSet<Value>) -> SpecResult<Value> {
    let uids_r = valueset_as_entity_uid(vs);
    match uids_r {
        Ok(uids) => {
            let b = uids.any(|u: EntityUID| in_e_with_entity(uid, entity1, u));
            Ok(Value::bool(b))
        },
        Err(err) => Err(err)
    }
}

// The concrete evaluator separates out the arithmetic operations into a function that takes a single entity, rather than
// the whole entities map; to simplify the proof, we provide this spec. Verus seems to be able to prove equivalence at the call site
pub open spec fn apply_2_mem_with_entity(uid1: EntityUID, entity1: Option<EntityData>, v2: Value) -> SpecResult<Value> {
    match v2 {
        (Value::Prim { p: Prim::EntityUID { uid: uid2 } }) =>
            Ok(Value::bool(in_e_with_entity(uid1, entity1, uid2))),
        (Value::Set { s: vs }) =>
            in_s_with_entity(uid1, entity1, vs),
        _ => Err(Error::TypeError)
    }
}




}
