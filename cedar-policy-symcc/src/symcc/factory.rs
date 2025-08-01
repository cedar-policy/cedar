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

use crate::symcc::term::TermX;

use super::bitvec::BitVec;
use super::entity_tag::EntityTag;
use super::ext::Ext;
use super::extension_types::{
    datetime::{Datetime, Duration},
    ipaddr::IPNet,
};
use super::function::UnaryFunction;
use super::op::{ExtOp, Op};
use super::term::{Term, TermPrim};
use super::term_type::TermType;
use super::type_abbrevs::*;
use num_traits::ToPrimitive;
use std::collections::BTreeSet;
use std::sync::Arc;

// ---------- Checked term constructors ----------

pub fn none_of(ty: TermType) -> Term {
    Term::new(TermX::None(ty))
}

pub fn some_of(t: Term) -> Term {
    Term::new(TermX::Some(t))
}

pub fn set_of(ts: impl IntoIterator<Item = Term>, elts_ty: TermType) -> Term {
    Term::new(TermX::Set {
        elts: ts.into_iter().collect(),
        elts_ty,
    })
}

pub fn record_of(ats: impl IntoIterator<Item = (Attr, Term)>) -> Term {
    Term::new(TermX::Record(ats.into_iter().collect()))
}

pub fn tag_of(entity: Term, tag: Term) -> Term {
    Term::new(TermX::Record(EntityTag::mk(entity, tag).0))
}

// ---------- SMTLib core theory of equality with uninterpreted functions (`UF`) ----------

pub fn not(t: Term) -> Term {
    match t.to_owned() {
        TermX::Prim(TermPrim::Bool(b)) => (!b).into(),
        // PANIC SAFETY
        #[allow(
            clippy::unwrap_used,
            reason = "List of length 1 should not panic when unwrapping first element"
        )]
        TermX::App {
            op: Op::Not, args, ..
        } if args.len() == 1 => args.into_iter().next().unwrap(),
        t => Term::new(TermX::App {
            op: Op::Not,
            args: vec![Term::new(t)],
            ret_ty: TermType::Bool,
        }),
    }
}

pub fn opposites(t1: &Term, t2: &Term) -> bool {
    match (t1.as_ref(), t2.as_ref()) {
        // PANIC SAFETY: List of length 1 should not error when indexed by 0
        #[allow(clippy::indexing_slicing)]
        (
            t1,
            TermX::App {
                op: Op::Not, args, ..
            },
        ) if args.len() == 1 => t1 == args[0].as_ref(),
        // PANIC SAFETY: List of length 2 should not error when indexed by 0 or 1
        #[allow(clippy::indexing_slicing)]
        (
            TermX::App {
                op: Op::Not, args, ..
            },
            t2,
        ) if args.len() == 1 => args[0].as_ref() == t2,
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
        Term::new(TermX::App {
            op: Op::And,
            args: vec![t1, t2],
            ret_ty: TermType::Bool,
        })
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
        Term::new(TermX::App {
            op: Op::Or,
            args: vec![t1, t2],
            ret_ty: TermType::Bool,
        })
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
            Term::new(TermX::App {
                op: Op::Eq,
                args: vec![t1, t2],
                ret_ty: TermType::Bool,
            })
        }
    };
    match (t1.to_owned(), t2.to_owned()) {
        (TermX::Some(t1), TermX::Some(t2)) => {
            simplify(t1, t2)
        }
        (TermX::Some(_), TermX::None(_)) | (TermX::None(_), TermX::Some(_)) => false.into(),
        (t1, t2) => simplify(t1.into(), t2.into()),
    }
}

pub fn ite(t1: Term, t2: Term, t3: Term) -> Term {
    let simplify = |t2: Term, t3: Term| -> Term {
        if t1 == true.into() || t2 == t3 {
            t2
        } else if t1 == false.into() {
            t3
        } else {
            match (t2.to_owned(), t3.to_owned()) {
                (TermX::Prim(TermPrim::Bool(true)), TermX::Prim(TermPrim::Bool(false))) => t1,
                (TermX::Prim(TermPrim::Bool(false)), TermX::Prim(TermPrim::Bool(true))) => not(t1),
                (t2, TermX::Prim(TermPrim::Bool(false))) => and(t1, t2.into()),
                (TermX::Prim(TermPrim::Bool(true)), t3) => or(t1, t3.into()),
                (t2, t3) => {
                    let ret_ty = t2.type_of();
                    Term::new(TermX::App {
                        op: Op::Ite,
                        args: vec![t1, t2.into(), t3.into()],
                        ret_ty,
                    })
                }
            }
        }
    };
    match (t2.to_owned(), t3.to_owned()) {
        (TermX::Some(t2), TermX::Some(t3)) => Term::new(TermX::Some(simplify(t2, t3))),
        (t2, t3) => simplify(t2.into(), t3.into()),
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
            Term::new(TermX::App {
                op: Op::Uuf(f),
                args: vec![t],
                ret_ty,
            })
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
    match t.to_owned() {
        #[allow(clippy::unwrap_used, reason = "BitVec::neg cannot return error.")]
        TermX::Prim(TermPrim::Bitvec(b)) => b.neg().unwrap().into(),
        // this optimization is not present in the Lean
        // PANIC SAFETY
        #[allow(
            clippy::unwrap_used,
            reason = "List of length 1 should not panic when unwrapping first element"
        )]
        TermX::App {
            op: Op::Bvneg,
            args,
            ..
        } if args.len() == 1 => args.into_iter().next().unwrap(),
        t => {
            let ret_ty = t.type_of();
            Term::new(TermX::App {
                op: Op::Bvneg,
                args: vec![t.into()],
                ret_ty,
            })
        }
    }
}

type Comparator = dyn Fn(&BitVec, &BitVec) -> Result<bool, super::result::Error>;
type BVOp = dyn Fn(&BitVec, &BitVec) -> Result<BitVec, super::result::Error>;

pub fn bvapp(op: Op, f: &BVOp, t1: Term, t2: Term) -> Term {
    match (t1.to_owned(), t2.to_owned()) {
        #[allow(
            clippy::unwrap_used,
            reason = "Assume the bit-vectors have the same width by construction for now."
        )]
        (TermX::Prim(TermPrim::Bitvec(b1)), TermX::Prim(TermPrim::Bitvec(b2))) => {
            (f(&b1, &b2)).unwrap().into()
        }
        (t1, t2) => {
            let ret_ty = t1.type_of();
            Term::new(TermX::App {
                op,
                args: vec![t1.into(), t2.into()],
                ret_ty,
            })
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

pub fn bvsrem(t1: Term, t2: Term) -> Term {
    bvapp(Op::Bvsrem, &BitVec::srem, t1, t2)
}

#[allow(unused, reason = "Added for completeness")]
pub fn bvsmod(t1: Term, t2: Term) -> Term {
    bvapp(Op::Bvsmod, &BitVec::smod, t1, t2)
}

#[allow(unused, reason = "Added for completeness")]
pub fn bvurem(t1: Term, t2: Term) -> Term {
    bvapp(Op::Bvumod, &BitVec::urem, t1, t2)
}

pub fn bvshl(t1: Term, t2: Term) -> Term {
    bvapp(Op::Bvshl, &BitVec::shl, t1, t2)
}

pub fn bvlshr(t1: Term, t2: Term) -> Term {
    bvapp(Op::Bvlshr, &BitVec::lshr, t1, t2)
}

fn bvcmp(op: Op, comp: &Comparator, t1: Term, t2: Term) -> Term {
    match (t1.to_owned(), t2.to_owned()) {
        #[allow(
            clippy::unwrap_used,
            reason = "Assume the bit-vectors have the same width by construction for now."
        )]
        (TermX::Prim(TermPrim::Bitvec(bv1)), TermX::Prim(TermPrim::Bitvec(bv2))) => {
            comp(&bv1, &bv2).unwrap().into()
        }
        (t1, t2) => Term::new(TermX::App {
            op,
            args: vec![t1.into(), t2.into()],
            ret_ty: TermType::Bool,
        }),
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
    match t.to_owned() {
        TermX::Prim(TermPrim::Bitvec(bv)) =>
        {
            #[allow(
                clippy::unwrap_used,
                reason = "By construction bit-vectors have non-zero width."
            )]
            BitVec::overflows(bv.width(), -bv.to_int()).unwrap().into()
        }
        t => Term::new(TermX::App {
            op: Op::Bvnego,
            args: vec![t.into()],
            ret_ty: TermType::Bool,
        }),
    }
}

pub fn bvso(op: Op, f: &BVOp, t1: Term, t2: Term) -> Term {
    match (t1.to_owned(), t2.to_owned()) {
        (TermX::Prim(TermPrim::Bitvec(bv1)), TermX::Prim(TermPrim::Bitvec(bv2))) => {
            assert!(bv1.width() == bv2.width());
            #[allow(
                clippy::unwrap_used,
                reason = "Assert above guarantees same bit-vector width."
            )]
            BitVec::overflows(bv1.width(), f(&bv1, &bv2).unwrap().to_int())
                .unwrap()
                .into()
        }
        (t1, t2) => Term::new(TermX::App {
            op,
            args: vec![t1.into(), t2.into()],
            ret_ty: TermType::Bool,
        }),
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
pub fn zero_extend(n: Width, t: Term) -> Term {
    match t.to_owned() {
        TermX::Prim(TermPrim::Bitvec(bv)) =>
        {
            #[allow(
                clippy::unwrap_used,
                reason = "By construction bit-vectors have non-zero width."
            )]
            BitVec::zero_extend(&bv, n + bv.width()).unwrap().into()
        }
        t => {
            match t.type_of() {
                TermType::Bitvec { n: cur_width } => Term::new(TermX::App {
                    op: Op::ZeroExtend(n),
                    args: vec![t.into()],
                    ret_ty: TermType::Bitvec { n: cur_width + n },
                }),
                _ => t.into(), // should be ruled out by callers
            }
        }
    }
}

// // ---------- CVC theory of finite sets (`FS`) ----------

pub fn set_member(t: Term, ts: Term) -> Term {
    match ts.as_ref() {
        TermX::Set { elts, .. } if elts.is_empty() => false.into(),
        TermX::Set { elts, .. } if t.is_literal() && ts.is_literal() => elts.contains(&t).into(),
        _ => Term::new(TermX::App {
            op: Op::SetMember,
            args: vec![t, ts],
            ret_ty: TermType::Bool,
        }),
    }
}

pub fn set_subset(sub: Term, sup: Term) -> Term {
    if sub == sup {
        true.into()
    } else {
        match (sub.as_ref(), sup.as_ref()) {
            (TermX::Set { elts, .. }, _) if elts.is_empty() => true.into(),
            (sub @ TermX::Set { elts: sub_elts, .. }, sup @ TermX::Set { elts: sup_elts, .. })
                if sub.is_literal() && sup.is_literal() =>
            {
                sub_elts.is_subset(&sup_elts).into()
            }
            (_, _) => Term::new(TermX::App {
                op: Op::SetSubset,
                args: vec![sub, sup],
                ret_ty: TermType::Bool,
            }),
        }
    }
}

pub fn set_inter(ts1: Term, ts2: Term) -> Term {
    if ts1 == ts2 {
        ts1
    } else {
        match (ts1.as_ref(), ts2.as_ref()) {
            (TermX::Set { elts, .. }, _) if elts.is_empty() => ts1,
            (_, TermX::Set { elts, .. }) if elts.is_empty() => ts2,
            (
                TermX::Set {
                    elts: elts1,
                    elts_ty,
                },
                TermX::Set { elts: elts2, .. },
            ) if ts1.is_literal() && ts2.is_literal() => Term::new(TermX::Set {
                elts: elts1.intersection(&elts2).cloned().collect(),
                elts_ty: elts_ty.clone(),
            }),
            (_, _) => {
                let ret_ty = ts1.type_of();
                Term::new(TermX::App {
                    op: Op::SetInter,
                    args: vec![ts1, ts2],
                    ret_ty,
                })
            }
        }
    }
}

pub fn set_is_empty(t: Term) -> Term {
    match t.to_owned() {
        TermX::Set { elts, .. } if elts.is_empty() => true.into(),
        TermX::Set { elts, .. } if !elts.is_empty() => false.into(),
        ts => match ts.type_of() {
            TermType::Set { ty } => eq(
                ts.into(),
                Term::new(TermX::Set {
                    elts: BTreeSet::new(),
                    elts_ty: Arc::unwrap_or_clone(ty),
                }),
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
    match t.to_owned() {
        TermX::Some(t) => t,
        t => match t.type_of() {
            TermType::Option { ty } => Term::new(TermX::App {
                op: Op::OptionGet,
                args: vec![t.into()],
                ret_ty: Arc::unwrap_or_clone(ty),
            }),
            _ => t.into(),
        },
    }
}

pub fn record_get(t: Term, a: &Attr) -> Term {
    match t.as_ref() {
        TermX::Record(r) => match r.get(a) {
            Some(ta) => ta.clone(),
            None => t,
        },
        _ => match t.type_of() {
            TermType::Record { rty } => match rty.get(a) {
                Some(ty) => Term::new(TermX::App {
                    op: Op::RecordGet(a.clone()),
                    args: vec![t],
                    ret_ty: ty.clone(),
                }),
                None => t,
            },
            _ => t,
        },
    }
}

pub fn string_like(t: Term, p: OrdPattern) -> Term {
    match t.as_ref() {
        TermX::Prim(TermPrim::String(s)) => p.wildcard_match(&s).into(),
        _ => Term::new(TermX::App {
            op: Op::StringLike(p),
            args: vec![t],
            ret_ty: TermType::Bool,
        }),
    }
}

// // ---------- Extension ADT operators with a trusted mapping to SMT ----------

pub fn ext_decimal_val(t: Term) -> Term {
    match t.to_owned() {
        TermX::Prim(TermPrim::Ext(Ext::Decimal { d })) =>
        {
            #[allow(
                clippy::unwrap_used,
                reason = "Cannot panic because bitwidth is guaranteed to be non-zero."
            )]
            Term::new(TermX::Prim(TermPrim::Bitvec(BitVec::of_int(64, d.0.into()).unwrap())))
        }
        t => Term::new(TermX::App {
            op: Op::Ext(ExtOp::DecimalVal),
            args: vec![t.into()],
            ret_ty: TermType::Bitvec { n: 64 },
        }),
    }
}

pub fn ext_ipaddr_is_v4(t: Term) -> Term {
    match t.to_owned() {
        TermX::Prim(TermPrim::Ext(Ext::Ipaddr { ip })) => ip.is_v4().into(),
        t => Term::new(TermX::App {
            op: Op::Ext(ExtOp::IpaddrIsV4),
            args: vec![t.into()],
            ret_ty: TermType::Bool,
        }),
    }
}

pub fn ext_ipaddr_addr_v4(t: Term) -> Term {
    match t.to_owned() {
        TermX::Prim(TermPrim::Ext(Ext::Ipaddr { ip: IPNet::V4(v4) })) => v4.addr.val.into(),
        t => Term::new(TermX::App {
            op: Op::Ext(ExtOp::IpaddrAddrV4),
            args: vec![t.into()],
            ret_ty: TermType::Bitvec { n: 32 },
        }),
    }
}

pub fn ext_ipaddr_prefix_v4(t: Term) -> Term {
    match t.to_owned() {
        TermX::Prim(TermPrim::Ext(Ext::Ipaddr { ip: IPNet::V4(v4) })) => match v4.prefix.val {
            None => Term::new(TermX::None(TermType::Bitvec { n: 5 })),
            Some(p) => some_of(p.into()),
        },
        t => Term::new(TermX::App {
            op: Op::Ext(ExtOp::IpaddrPrefixV4),
            args: vec![t.into()],
            ret_ty: TermType::Option {
                ty: Arc::new(TermType::Bitvec { n: 5 }),
            },
        }),
    }
}

pub fn ext_ipaddr_addr_v6(t: Term) -> Term {
    match t.to_owned() {
        TermX::Prim(TermPrim::Ext(Ext::Ipaddr { ip: IPNet::V6(v6) })) => v6.addr.val.into(),
        t => Term::new(TermX::App {
            op: Op::Ext(ExtOp::IpaddrAddrV6),
            args: vec![t.into()],
            ret_ty: TermType::Bitvec { n: 128 },
        }),
    }
}

pub fn ext_ipaddr_prefix_v6(t: Term) -> Term {
    match t.to_owned() {
        TermX::Prim(TermPrim::Ext(Ext::Ipaddr { ip: IPNet::V6(v6) })) => match v6.prefix.val {
            None => Term::new(TermX::None(TermType::Bitvec { n: 7 })),
            Some(p) => some_of(p.into()),
        },
        t => Term::new(TermX::App {
            op: Op::Ext(ExtOp::IpaddrPrefixV6),
            args: vec![t.into()],
            ret_ty: TermType::Option {
                ty: Arc::new(TermType::Bitvec { n: 7 }),
            },
        }),
    }
}

pub fn ext_datetime_val(t: Term) -> Term {
    match t.to_owned() {
        TermX::Prim(TermPrim::Ext(Ext::Datetime { dt })) =>
        {
            #[allow(
                clippy::unwrap_used,
                reason = "Cannot panic because bitwidth is guaranteed to be non-zero."
            )]
            Term::new(TermX::Prim(TermPrim::Bitvec(BitVec::of_i128(64, dt.into()).unwrap())))
        }
        t => Term::new(TermX::App {
            op: Op::Ext(ExtOp::DatetimeVal),
            args: vec![t.into()],
            ret_ty: TermType::Bitvec { n: 64 },
        }),
    }
}

pub fn ext_datetime_of_bitvec(t: Term) -> Term {
    match t.to_owned() {
        TermX::Prim(TermPrim::Bitvec(bv)) if bv.width() == 64 => {
            // PANIC SAFETY: If condition ensures the value will fit in 128 bits.
            #[allow(clippy::unwrap_used)]
            Term::new(TermX::Prim(TermPrim::Ext(Ext::Datetime {
                dt: Datetime::from(bv.to_int().to_i128().unwrap()),
            })))
        }
        t => Term::new(TermX::App {
            op: Op::Ext(ExtOp::DatetimeOfBitVec),
            args: vec![t.into()],
            ret_ty: TermType::Ext {
                xty: ExtType::DateTime,
            },
        }),
    }
}

pub fn ext_duration_val(t: Term) -> Term {
    match t.to_owned() {
        #[allow(
            clippy::unwrap_used,
            reason = "Cannot panic because bitwidth is guaranteed to be non-zero."
        )]
        TermX::Prim(TermPrim::Ext(Ext::Duration { d })) => Term::new(TermX::Prim(TermPrim::Bitvec(
            BitVec::of_i128(64, d.to_milliseconds().into()).unwrap(),
        ))),
        t => Term::new(TermX::App {
            op: Op::Ext(ExtOp::DurationVal),
            args: vec![t.into()],
            ret_ty: TermType::Bitvec { n: 64 },
        }),
    }
}

pub fn ext_duration_of_bitvec(t: Term) -> Term {
    match t.to_owned() {
        TermX::Prim(TermPrim::Bitvec(bv)) if bv.width() == 64 => {
            // PANIC SAFETY: If condition ensures the value will fit in 128 bits.
            #[allow(clippy::unwrap_used)]
            Term::new(TermX::Prim(TermPrim::Ext(Ext::Duration {
                d: Duration::from(bv.to_int().to_i128().unwrap()),
            })))
        }
        t => Term::new(TermX::App {
            op: Op::Ext(ExtOp::DurationOfBitVec),
            args: vec![t.into()],
            ret_ty: TermType::Ext {
                xty: ExtType::Duration,
            },
        }),
    }
}

// ---------- Helper functions for constructing compound terms ----------

pub fn is_none(t: Term) -> Term {
    match t.as_ref() {
        TermX::None(_) => true.into(),
        TermX::Some(_) => false.into(),
        TermX::App {
            op: Op::Ite, args, ..
        } => {
            #[cfg(test)]
            assert!(args.len() == 3);
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "Ite should have 3 args. Since term is constructed it should have 3 args"
            )]
            match (args[1].as_ref(), args[2].as_ref()) {
                (TermX::Some(_), TermX::Some(_)) => false.into(),
                (TermX::Some(_), TermX::None(_)) => not(args[0].clone()),
                (TermX::None(_), TermX::Some(_)) => args[0].clone(),
                _ => match t.type_of() {
                    TermType::Option { ty } => eq(t, TermX::None(Arc::unwrap_or_clone(ty)).into()),
                    _ => false.into(),
                },
            }
        }
        _ => match t.type_of() {
            TermType::Option { ty } => eq(t, TermX::None(Arc::unwrap_or_clone(ty)).into()),
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
        TermType::Option { ty } => ite(is_none(g), none_of(Arc::unwrap_or_clone(ty)), t),
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
        TermType::Option { ty } => ite(g, none_of(Arc::unwrap_or_clone(ty)), t),
        _ => if_false(g, t),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn create_terms() {
        let my_term = Term::new(TermX::Prim(TermPrim::Bool(true)));
        let not_my_term = not(my_term.clone());

        assert_ne!(my_term, not_my_term);

        let not_not_my_term = not(not_my_term);

        assert_eq!(my_term, not_not_my_term);
    }
}
