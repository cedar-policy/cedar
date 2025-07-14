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

use super::bitvec::{self, BitVec};
use super::entity_tag::EntityTag;
use super::ext::Ext;
use super::extension_types::ipaddr::IPNet;
use super::function::UnaryFunction;
use super::op::{ExtOp, Op};
use super::term::{Term, TermPrim};
use super::term_type::TermType;
use super::type_abbrevs::*;
use std::collections::BTreeSet;

// ---------- Checked term constructors ----------

pub fn none_of(ty: TermType) -> Term {
    Term::None(ty)
}

pub fn some_of(t: Term) -> Term {
    Term::Some(Box::new(t))
}

pub fn set_of(ts: impl IntoIterator<Item = Term>, elts_ty: TermType) -> Term {
    Term::Set {
        elts: ts.into_iter().collect(),
        elts_ty,
    }
}

pub fn record_of(ats: impl IntoIterator<Item = (Attr, Term)>) -> Term {
    Term::Record(ats.into_iter().collect())
}

pub fn tag_of(entity: Term, tag: Term) -> Term {
    Term::Record(EntityTag::mk(entity, tag).0)
}

// ---------- SMTLib core theory of equality with uninterpreted functions (`UF`) ----------

pub fn not(t: Term) -> Term {
    match t {
        Term::Prim(TermPrim::Bool(b)) => (!b).into(),
        Term::App {
            op: Op::Not, args, ..
        } if args.len() == 1 => args.into_iter().next().unwrap(),
        t => Term::App {
            op: Op::Not,
            args: vec![t],
            ret_ty: TermType::Bool,
        },
    }
}

pub fn opposites(t1: &Term, t2: &Term) -> bool {
    match (t1, t2) {
        (
            t1,
            Term::App {
                op: Op::Not, args, ..
            },
        ) if args.len() == 1 => t1 == &args[0],
        (
            Term::App {
                op: Op::Not, args, ..
            },
            t2,
        ) if args.len() == 1 => &args[0] == t2,
        (_, _) => false,
    }
}

pub fn and(t1: Term, t2: Term) -> Term {
    if t1 == t2 || t2 == true.into() {
        t1
    } else if t1 == true.into() {
        t2
    } else if t1 == false.into() || t2 == false.into() || opposites(&t1, &t2) {
        false.into()
    } else {
        Term::App {
            op: Op::And,
            args: vec![t1, t2],
            ret_ty: TermType::Bool,
        }
    }
}

pub fn or(t1: Term, t2: Term) -> Term {
    if t1 == t2 || t2 == false.into() {
        t1
    } else if t1 == false.into() {
        t2
    } else if t1 == true.into() || t2 == true.into() || opposites(&t1, &t2) {
        true.into()
    } else {
        Term::App {
            op: Op::Or,
            args: vec![t1, t2],
            ret_ty: TermType::Bool,
        }
    }
}

pub fn implies(t1: Term, t2: Term) -> Term {
    or(not(t1), t2)
}

pub fn eq(t1: Term, t2: Term) -> Term {
    let simplify = |t1: Term, t2: Term| -> Term {
        if t1 == t2 {
            true.into()
        } else if t1.is_literal() && t2.is_literal() {
            false.into()
        } else if t1 == true.into() && t2.type_of() == TermType::Bool {
            t2
        } else if t2 == true.into() && t1.type_of() == TermType::Bool {
            t1
        } else if t1 == false.into() && t2.type_of() == TermType::Bool {
            not(t2)
        } else if t2 == false.into() && t1.type_of() == TermType::Bool {
            not(t1)
        } else {
            Term::App {
                op: Op::Eq,
                args: vec![t1, t2],
                ret_ty: TermType::Bool,
            }
        }
    };
    match (t1, t2) {
        (Term::Some(t1), Term::Some(t2)) => simplify(*t1, *t2),
        (Term::Some(_), Term::None(_)) | (Term::None(_), Term::Some(_)) => false.into(),
        (t1, t2) => simplify(t1, t2),
    }
}

pub fn ite(t1: Term, t2: Term, t3: Term) -> Term {
    let simplify = |t2: Term, t3: Term| -> Term {
        if t1 == true.into() || t2 == t3 {
            t2
        } else if t1 == false.into() {
            t3
        } else {
            match (t2, t3) {
                (Term::Prim(TermPrim::Bool(true)), Term::Prim(TermPrim::Bool(false))) => t1,
                (Term::Prim(TermPrim::Bool(false)), Term::Prim(TermPrim::Bool(true))) => not(t1),
                (t2, Term::Prim(TermPrim::Bool(false))) => and(t1, t2),
                (Term::Prim(TermPrim::Bool(true)), t3) => or(t1, t3),
                (t2, t3) => {
                    let ret_ty = t2.type_of();
                    Term::App {
                        op: Op::Ite,
                        args: vec![t1, t2, t3],
                        ret_ty,
                    }
                }
            }
        }
    };
    match (t2, t3) {
        (Term::Some(t2), Term::Some(t3)) => Term::Some(Box::new(simplify(*t2, *t3))),
        (t2, t3) => simplify(t2, t3),
    }
}

/// Returns the result of applying a UUF or a UDF to a term. UDFs can be applied to
/// both literals and non-literal terms. The latter will result in the creation of a
/// chained `ite` expression that encodes the semantics of table lookup on an
/// unknown value.
pub fn app(f: UnaryFunction, t: Term) -> Term {
    match f {
        UnaryFunction::Uuf(f) => {
            let ret_ty = f.out.clone();
            Term::App {
                op: Op::Uuf(f),
                args: vec![t],
                ret_ty,
            }
        }
        UnaryFunction::Udf(f) => {
            if t.is_literal() {
                match f.table.get(&t) {
                    Some(v) => v.clone(),
                    None => f.default,
                }
            } else {
                f.table.iter().rfold(f.default, |acc, (t1, t2)| {
                    ite(eq(t.clone(), t1.clone()), t2.clone(), acc)
                })
            }
        }
    }
}

// // ---------- SMTLib theory of finite bitvectors (`BV`) ----------

// We are doing very weak partial evaluation for bitvectors: just constant
// propagation. If more rewrites are needed, we can add them later.  This simple
// approach is sufficient for the strong PE property we care about:  if given a
// fully concrete input, the symbolic compiler returns a fully concrete output.

pub fn bvneg(t: Term) -> Term {
    match t {
        Term::Prim(TermPrim::Bitvec(b)) => b.neg().into(),
        // this optimization is not present in the Lean
        Term::App {
            op: Op::Bvneg,
            args,
            ..
        } if args.len() == 1 => args.into_iter().next().unwrap(),
        t => {
            let ret_ty = t.type_of();
            Term::App {
                op: Op::Bvneg,
                args: vec![t],
                ret_ty,
            }
        }
    }
}

type Comparator = dyn Fn(&BitVec, &BitVec) -> bool;
type BVOp = dyn Fn(&BitVec, &BitVec) -> BitVec;

pub fn bvapp(op: Op, f: &BVOp, t1: Term, t2: Term) -> Term {
    match (t1, t2) {
        (Term::Prim(TermPrim::Bitvec(b1)), Term::Prim(TermPrim::Bitvec(b2))) => f(&b1, &b2).into(),
        (t1, t2) => {
            let ret_ty = t1.type_of();
            Term::App {
                op,
                args: vec![t1, t2],
                ret_ty,
            }
        }
    }
}

pub fn bvadd(t1: Term, t2: Term) -> Term {
    bvapp(Op::Bvadd, &BitVec::add, t1, t2)
}

pub fn bvsub(t1: Term, t2: Term) -> Term {
    bvapp(Op::Bvsub, &BitVec::sub, t1, t2)
}

pub fn bvmul(t1: Term, t2: Term) -> Term {
    bvapp(Op::Bvmul, &BitVec::mul, t1, t2)
}

pub fn bvsdiv(t1: Term, t2: Term) -> Term {
    bvapp(Op::Bvsdiv, &BitVec::sdiv, t1, t2)
}

pub fn bvudiv(t1: Term, t2: Term) -> Term {
    bvapp(Op::Bvudiv, &BitVec::udiv, t1, t2)
}

pub fn bvshl(t1: Term, t2: Term) -> Term {
    bvapp(Op::Bvshl, &BitVec::shl, t1, t2)
}

pub fn bvlshr(t1: Term, t2: Term) -> Term {
    bvapp(Op::Bvlshr, &BitVec::lshr, t1, t2)
}

fn bvcmp(op: Op, comp: &Comparator, t1: Term, t2: Term) -> Term {
    match (t1, t2) {
        (Term::Prim(TermPrim::Bitvec(bv1)), Term::Prim(TermPrim::Bitvec(bv2))) => {
            comp(&bv1, &bv2).into()
        }
        (t1, t2) => Term::App {
            op,
            args: vec![t1, t2],
            ret_ty: TermType::Bool,
        },
    }
}

pub fn bvslt(t1: Term, t2: Term) -> Term {
    bvcmp(Op::Bvslt, &BitVec::slt, t1, t2)
}

pub fn bvsle(t1: Term, t2: Term) -> Term {
    bvcmp(Op::Bvsle, &BitVec::sle, t1, t2)
}

pub fn bvult(t1: Term, t2: Term) -> Term {
    bvcmp(Op::Bvult, &BitVec::ult, t1, t2)
}

pub fn bvule(t1: Term, t2: Term) -> Term {
    bvcmp(Op::Bvule, &BitVec::ule, t1, t2)
}

/// Does negation overflow
pub fn bvnego(t: Term) -> Term {
    match t {
        Term::Prim(TermPrim::Bitvec(bv)) => bitvec::overflows(bv.width(), -bv.v).into(),
        t => Term::App {
            op: Op::Bvnego,
            args: vec![t],
            ret_ty: TermType::Bool,
        },
    }
}

pub fn bvso(op: Op, f: &BVOp, t1: Term, t2: Term) -> Term {
    match (t1, t2) {
        (Term::Prim(TermPrim::Bitvec(bv1)), Term::Prim(TermPrim::Bitvec(bv2))) => {
            assert!(bv1.width() == bv2.width());
            bitvec::overflows(bv1.width(), f(&bv1, &bv2).v).into()
        }
        (t1, t2) => Term::App {
            op,
            args: vec![t1, t2],
            ret_ty: TermType::Bool,
        },
    }
}

pub fn bvsaddo(t1: Term, t2: Term) -> Term {
    bvso(Op::Bvsaddo, &BitVec::add, t1, t2)
}

pub fn bvssubo(t1: Term, t2: Term) -> Term {
    bvso(Op::Bvssubo, &BitVec::sub, t1, t2)
}

pub fn bvsmulo(t1: Term, t2: Term) -> Term {
    bvso(Op::Bvsmulo, &BitVec::mul, t1, t2)
}

/// Note that Lean's Std.BitVec defines zero_extend differently from SMTLib,
/// so we compensate for the difference in partial evaluation.
///
/// This function adds `n` to the existing width. It does not pad the width to `n`.
pub fn zero_extend(n: Nat, t: Term) -> Term {
    match t {
        Term::Prim(TermPrim::Bitvec(BitVec { width, v })) => BitVec {
            width: n + width,
            v,
        }
        .into(),
        t => {
            match t.type_of() {
                TermType::Bitvec { n: cur_width } => Term::App {
                    op: Op::ZeroExtend(n),
                    args: vec![t],
                    ret_ty: TermType::Bitvec { n: cur_width + n },
                },
                _ => t, // should be ruled out by callers
            }
        }
    }
}

// // ---------- CVC theory of finite sets (`FS`) ----------

pub fn set_member(t: Term, ts: Term) -> Term {
    match ts {
        Term::Set { elts, .. } if elts.is_empty() => false.into(),
        Term::Set { elts, .. } if t.is_literal() && ts.is_literal() => elts.contains(&t).into(),
        ts => Term::App {
            op: Op::SetMember,
            args: vec![t, ts],
            ret_ty: TermType::Bool,
        },
    }
}

pub fn set_subset(sub: Term, sup: Term) -> Term {
    if sub == sup {
        true.into()
    } else {
        match (&sub, &sup) {
            (Term::Set { elts, .. }, _) if elts.is_empty() => true.into(),
            (sub @ Term::Set { elts: sub_elts, .. }, sup @ Term::Set { elts: sup_elts, .. })
                if sub.is_literal() && sup.is_literal() =>
            {
                sub_elts.is_subset(sup_elts).into()
            }
            (_, _) => Term::App {
                op: Op::SetSubset,
                args: vec![sub, sup],
                ret_ty: TermType::Bool,
            },
        }
    }
}

pub fn set_inter(ts1: Term, ts2: Term) -> Term {
    if ts1 == ts2 {
        ts1
    } else {
        match (&ts1, &ts2) {
            (Term::Set { ref elts, .. }, _) if elts.is_empty() => ts1,
            (_, Term::Set { ref elts, .. }) if elts.is_empty() => ts2,
            (
                Term::Set {
                    elts: elts1,
                    elts_ty,
                },
                Term::Set { elts: elts2, .. },
            ) if ts1.is_literal() && ts2.is_literal() => Term::Set {
                elts: elts1.intersection(elts2).cloned().collect(),
                elts_ty: elts_ty.clone(),
            },
            (_, _) => {
                let ret_ty = ts1.type_of();
                Term::App {
                    op: Op::SetInter,
                    args: vec![ts1, ts2],
                    ret_ty,
                }
            }
        }
    }
}

pub fn set_is_empty(t: Term) -> Term {
    match t {
        Term::Set { elts, .. } if elts.is_empty() => true.into(),
        Term::Set { elts, .. } if !elts.is_empty() => false.into(),
        ts => match ts.type_of() {
            TermType::Set { ty } => eq(
                ts,
                Term::Set {
                    elts: BTreeSet::new(),
                    elts_ty: *ty,
                },
            ),
            _ => false.into(),
        },
    }
}

/// Term to test if intersection is empty
pub fn set_intersects(ts1: Term, ts2: Term) -> Term {
    not(set_is_empty(set_inter(ts1, ts2)))
}

// // ---------- Core ADT operators with a trusted mapping to SMT ----------

pub fn option_get(t: Term) -> Term {
    match t {
        Term::Some(t) => *t,
        t => match t.type_of() {
            TermType::Option { ty } => Term::App {
                op: Op::OptionGet,
                args: vec![t],
                ret_ty: *ty,
            },
            _ => t,
        },
    }
}

pub fn record_get(t: Term, a: &Attr) -> Term {
    match &t {
        Term::Record(r) => match r.get(a) {
            Some(ta) => ta.clone(),
            None => t,
        },
        _ => match t.type_of() {
            TermType::Record { rty } => match rty.get(a) {
                Some(ty) => Term::App {
                    op: Op::RecordGet(a.clone()),
                    args: vec![t],
                    ret_ty: ty.clone(),
                },
                None => t,
            },
            _ => t,
        },
    }
}

pub fn string_like(t: Term, p: OrdPattern) -> Term {
    match t {
        Term::Prim(TermPrim::String(s)) => p.wildcard_match(&s).into(),
        _ => Term::App {
            op: Op::StringLike(p),
            args: vec![t],
            ret_ty: TermType::Bool,
        },
    }
}

// // ---------- Extension ADT operators with a trusted mapping to SMT ----------

pub fn ext_decimal_val(t: Term) -> Term {
    match t {
        Term::Prim(TermPrim::Ext(Ext::Decimal { d })) => Term::Prim(TermPrim::Bitvec(BitVec {
            width: 64,
            v: d.0.into(),
        })),
        t => Term::App {
            op: Op::Ext(ExtOp::DecimalVal),
            args: vec![t],
            ret_ty: TermType::Bitvec { n: 64 },
        },
    }
}

pub fn ext_ipaddr_is_v4(t: Term) -> Term {
    match t {
        Term::Prim(TermPrim::Ext(Ext::Ipaddr { ip })) => ip.is_v4().into(),
        t => Term::App {
            op: Op::Ext(ExtOp::IpaddrIsV4),
            args: vec![t],
            ret_ty: TermType::Bool,
        },
    }
}

pub fn ext_ipaddr_addr_v4(t: Term) -> Term {
    match t {
        Term::Prim(TermPrim::Ext(Ext::Ipaddr { ip })) => Ext::Ipaddr { ip }.into(),
        t => Term::App {
            op: Op::Ext(ExtOp::IpaddrAddrV4),
            args: vec![t],
            ret_ty: TermType::Bitvec { n: 32 },
        },
    }
}

pub fn ext_ipaddr_prefix_v4(t: Term) -> Term {
    match t {
        Term::Prim(TermPrim::Ext(Ext::Ipaddr { ip: IPNet::V4(v4) })) => match v4.prefix {
            None => Term::None(TermType::Bitvec { n: 5 }),
            Some(p) => some_of(
                BitVec {
                    width: 5,
                    v: p.v as i128,
                }
                .into(),
            ),
        },
        t => Term::App {
            op: Op::Ext(ExtOp::IpaddrPrefixV4),
            args: vec![t],
            ret_ty: TermType::Option {
                ty: Box::new(TermType::Bitvec { n: 5 }),
            },
        },
    }
}

pub fn ext_ipaddr_addr_v6(t: Term) -> Term {
    match t {
        Term::Prim(TermPrim::Ext(Ext::Ipaddr { ip })) => Ext::Ipaddr { ip }.into(),
        t => Term::App {
            op: Op::Ext(ExtOp::IpaddrAddrV6),
            args: vec![t],
            ret_ty: TermType::Bitvec { n: 128 },
        },
    }
}

pub fn ext_ipaddr_prefix_v6(t: Term) -> Term {
    match t {
        Term::Prim(TermPrim::Ext(Ext::Ipaddr { ip: IPNet::V6(v6) })) => match v6.prefix {
            None => Term::None(TermType::Bitvec { n: 7 }),
            Some(p) => some_of(
                BitVec {
                    width: 7,
                    v: p.v as i128,
                }
                .into(),
            ),
        },
        t => Term::App {
            op: Op::Ext(ExtOp::IpaddrPrefixV6),
            args: vec![t],
            ret_ty: TermType::Option {
                ty: Box::new(TermType::Bitvec { n: 7 }),
            },
        },
    }
}

pub fn ext_duration_val(t: Term) -> Term {
    match t {
        Term::Prim(TermPrim::Ext(Ext::Duration { d })) => Ext::Duration { d }.into(),
        t => Term::App {
            op: Op::Ext(ExtOp::DurationVal),
            args: vec![t],
            ret_ty: TermType::Bitvec { n: 64 },
        },
    }
}

// ---------- Helper functions for constructing compound terms ----------

pub fn is_none(t: Term) -> Term {
    match &t {
        Term::None(_) => true.into(),
        Term::Some(_) => false.into(),
        Term::App {
            op: Op::Ite, args, ..
        } => {
            assert!(args.len() == 3);
            match (&args[0], &args[1], &args[2]) {
                (_, Term::Some(_), Term::Some(_)) => false.into(),
                (g, Term::Some(_), Term::None(_)) => not(g.clone()),
                (g, Term::None(_), Term::Some(_)) => g.clone(),
                _ => match t.type_of() {
                    TermType::Option { ty } => eq(t, Term::None(*ty)),
                    _ => false.into(),
                },
            }
        }
        _ => match t.type_of() {
            TermType::Option { ty } => eq(t, Term::None(*ty)),
            _ => false.into(),
        },
    }
}

pub fn is_some(t: Term) -> Term {
    not(is_none(t))
}

pub fn if_false(g: Term, t: Term) -> Term {
    ite(g, none_of(t.type_of()), some_of(t))
}

pub fn if_true(g: Term, t: Term) -> Term {
    let t_ty = t.type_of();
    ite(g, some_of(t), none_of(t_ty))
}

pub fn if_some(g: Term, t: Term) -> Term {
    match t.type_of() {
        TermType::Option { ty } => ite(is_none(g), none_of(*ty), t),
        _ => if_false(is_none(g), t),
    }
}

pub fn any_none(gs: impl IntoIterator<Item = Term>) -> Term {
    gs.into_iter()
        .fold(false.into(), |acc, g| or(is_none(g), acc))
}

pub fn if_all_some(gs: impl IntoIterator<Item = Term>, t: Term) -> Term {
    let g = any_none(gs);
    match t.type_of() {
        TermType::Option { ty } => ite(g, none_of(*ty), t),
        _ => if_false(g, t),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn create_terms() {
        let my_term = Term::Prim(TermPrim::Bool(true));
        let not_my_term = not(my_term.clone());

        assert_ne!(my_term.clone(), not_my_term.clone());

        let not_not_my_term = not(not_my_term.clone());

        assert_eq!(my_term, not_not_my_term);
    }
}
