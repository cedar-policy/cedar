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

pub use crate::spec::spec_ast::*;
pub use crate::verus_utils::*;
#[cfg(verus_keep_ghost)]
pub use vstd::{map::*, prelude::*, seq::*, set::*};

verus! {

#[verifier::inline]
pub open spec fn int_or_err(x: Option<i64>) -> SpecResult<Value> {
    match x {
        Some(i) => Ok(Value::int(i)),
        None => Err(Error::ArithBoundsError)
    }
}

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

pub open spec fn evaluate(x: Expr, req: Request, es: Entities) -> SpecResult<Value>
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
        Expr::Ite { cond, then_expr, else_expr } => {
            match evaluate(*cond, req, es) {
                Ok(cond_result) => match cond_result {
                    Value::Prim { p: Prim::Bool { b } } => {
                        if b {
                            evaluate(*then_expr, req, es)
                        } else {
                            evaluate(*else_expr, req, es)
                        }
                    },
                    _ => Err(Error::TypeError),
                },
                Err(err) => Err(err),
            }
        },
        Expr::And { a, b } => {
            match evaluate(*a, req, es) {
                Ok(a_result) => match a_result {
                    Value::Prim { p: Prim::Bool { b: bool_a } } => {
                        if !bool_a {
                            Ok(Value::bool(bool_a))
                        } else {
                            match evaluate(*b, req, es) {
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
            match evaluate(*a, req, es) {
                Ok(a_result) => match a_result {
                    Value::Prim { p: Prim::Bool { b: bool_a } } => {
                        if bool_a {
                            Ok(Value::bool(bool_a))
                        } else {
                            match evaluate(*b, req, es) {
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
            match evaluate(*expr, req, es) {
                Ok(v) => apply_1(uop, v),
                Err(err) => Err(err),
            }
        },
        Expr::BinaryApp { bop, a, b } => {
            match evaluate(*a, req, es) {
                Ok(v1) => match evaluate(*b, req, es) {
                    Ok(v2) => apply_2(bop, v1, v2, es),
                    Err(err) => Err(err),
                },
                Err(err) => Err(err),
            }
        },
        Expr::HasAttr { expr, attr } => {
            match evaluate(*expr, req, es) {
                Ok(v1) => has_attr(v1, attr, es),
                Err(err) => Err(err),
            }
        },
        Expr::GetAttr { expr, attr } => {
            match evaluate(*expr, req, es) {
                Ok(v1) => get_attr(v1, attr, es),
                Err(err) => Err(err),
            }
        },
        Expr::Set { ls } => {
            let vs_r = seq_map_result_all(ls, |lx: Expr| {
                // Needed to prove termination
                if ls.contains(lx) {
                    evaluate(lx, req, es)
                } else {
                    arbitrary()
                }
            });
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
                    evaluate(mx, req, es)
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
proof fn evaluate_decreases(x: Expr, req: Request, es: Entities) {
    match x {
        Expr::Set { ls } => {
            assert(forall |lx: Expr| ls.contains(lx) ==> decreases_to!(ls => lx));
        }
        Expr::Record { map } => {
            assert(forall |mx: Expr| map.dom().finite() && map.contains_value(mx) ==> decreases_to!(map => mx));
        },
        _ => {}
    };
}

}
