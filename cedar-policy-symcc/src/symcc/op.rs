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

//! Various [`super::term::Term`] operations allowed in [`super::term::Term::App`].

use std::sync::Arc;

use smol_str::SmolStr;

use super::term_type::{TermType, TermTypeInner};
use super::type_abbrevs::*;
use hashconsing::{HConsign, HashConsign};

/// Uninterpreted unary function.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct Uuf {
    /// A unique identifier of the unary function.
    pub id: SmolStr,
    /// Argument type.
    pub arg: TermType,
    /// Output type.
    pub out: TermType,
}

/// Extension ADT operators.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[allow(missing_docs)]
pub enum ExtOp {
    DecimalVal,
    IpaddrIsV4,
    IpaddrAddrV4,
    IpaddrPrefixV4,
    IpaddrAddrV6,
    IpaddrPrefixV6,
    DatetimeVal,
    DatetimeOfBitVec,
    DurationVal,
    DurationOfBitVec,
}

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[allow(missing_docs)]
pub enum Op {
    //   ---------- SMTLib core theory of equality with uninterpreted functions (`UF`) ----------
    Not,
    And,
    Or,
    Eq,
    Ite,
    Uuf(Arc<Uuf>),
    //   ---------- SMTLib theory of finite bitvectors (`BV`) ----------
    Bvneg,
    Bvadd,
    Bvsub,
    Bvmul,
    /// Signed bit-vector division.
    Bvsdiv,
    /// Unsigned bit-vector division.
    Bvudiv,
    /// Signed remainder (remainder of division rounded towards zero) (copies sign from dividend).
    Bvsrem,
    /// Signed modulus (remainder of division rounded towards negative infinity) (copies sign from divisor).
    Bvsmod,
    /// Unsigned modulus.
    Bvumod,
    Bvshl,
    Bvlshr,
    Bvslt,
    Bvsle,
    Bvult,
    Bvule,
    /// Bit-vector negation overflow predicate.
    Bvnego,
    /// Bit-vector signed addition overflow predicate.
    Bvsaddo,
    /// Bit-vector signed subtraction overflow predicate.
    Bvssubo,
    /// Bit-vector signed multiplication overflow predicate.
    Bvsmulo,
    ZeroExtend(Width),
    //   ---------- CVC theory of finite sets (`FS`) ----------
    SetMember,
    SetSubset,
    SetInter,
    //   ---------- Core ADT operators with a trusted mapping to SMT ----------
    OptionGet,
    RecordGet(Attr),
    StringLike(OrdPattern),
    //   ---------- Extension ADT operators with a trusted mapping to SMT ----------
    Ext(ExtOp),
}

impl ExtOp {
    /// Returns the name of an extension operator.
    ///
    /// Corresponds to `ExtOp.mkName` in the Lean model.
    pub fn mk_name(&self) -> &'static str {
        match self {
            ExtOp::DecimalVal => "decimal.val",
            ExtOp::IpaddrIsV4 => "ipaddr.isV4",
            ExtOp::IpaddrAddrV4 => "ipaddr.addrV4",
            ExtOp::IpaddrPrefixV4 => "ipaddr.prefixV4",
            ExtOp::IpaddrAddrV6 => "ipaddr.addrV6",
            ExtOp::IpaddrPrefixV6 => "ipaddr.prefixV6",
            ExtOp::DatetimeVal => "datetime.val",
            ExtOp::DatetimeOfBitVec => "datetime.ofBitVec",
            ExtOp::DurationVal => "duration.val",
            ExtOp::DurationOfBitVec => "duration.ofBitVec",
        }
    }

    /// Returns the output type of an extension operator when applied
    /// to terms of the given types.
    #[allow(clippy::needless_pass_by_value)]
    pub fn type_of(self, l: Vec<TermType>, h: &mut HConsign<TermTypeInner>) -> Option<TermType> {
        let ext_decimal = TermType {
            inner: h.mk(TermTypeInner::Ext {
                xty: ExtType::Decimal,
            }),
        };
        let ext_ipaddr = TermType {
            inner: h.mk(TermTypeInner::Ext {
                xty: ExtType::IpAddr,
            }),
        };
        let ext_datetime = TermType {
            inner: h.mk(TermTypeInner::Ext {
                xty: ExtType::DateTime,
            }),
        };
        let ext_duration = TermType {
            inner: h.mk(TermTypeInner::Ext {
                xty: ExtType::Duration,
            }),
        };
        let bv64 = TermType {
            inner: h.mk(TermTypeInner::Bitvec { n: 64 }),
        };

        match self {
            ExtOp::DecimalVal if l == vec![ext_decimal] => Some(TermType {
                inner: h.mk(TermTypeInner::Bitvec { n: 64 }),
            }),
            ExtOp::IpaddrIsV4 if l == vec![ext_ipaddr.clone()] => Some(TermType {
                inner: h.mk(TermTypeInner::Bool),
            }),
            ExtOp::IpaddrAddrV4 if l == vec![ext_ipaddr.clone()] => Some(TermType {
                inner: h.mk(TermTypeInner::Bitvec { n: 32 }),
            }),
            ExtOp::IpaddrPrefixV4 if l == vec![ext_ipaddr.clone()] => {
                let inner_ty = TermType {
                    inner: h.mk(TermTypeInner::Bitvec { n: 5 }),
                };
                Some(TermType {
                    inner: h.mk(TermTypeInner::Option {
                        ty: Arc::new(inner_ty),
                    }),
                })
            }
            ExtOp::IpaddrAddrV6 if l == vec![ext_ipaddr] => Some(TermType {
                inner: h.mk(TermTypeInner::Bitvec { n: 128 }),
            }),
            ExtOp::DatetimeVal if l == vec![ext_datetime.clone()] => Some(TermType {
                inner: h.mk(TermTypeInner::Bitvec { n: 64 }),
            }),
            ExtOp::DatetimeOfBitVec if l == vec![bv64.clone()] => Some(ext_datetime),
            ExtOp::DurationVal if l == vec![ext_duration.clone()] => Some(TermType {
                inner: h.mk(TermTypeInner::Bitvec { n: 64 }),
            }),
            ExtOp::DurationOfBitVec if l == vec![bv64] => Some(ext_duration),
            _ => None,
        }
    }
}

impl Op {
    /// Returns the output type of an operator when applied
    /// to terms of the given types.
    #[allow(clippy::cognitive_complexity)]
    pub fn type_of(self, l: Vec<TermType>, h: &mut HConsign<TermTypeInner>) -> Option<TermType> {
        use super::term_type::TermTypeInner::{Bitvec, Bool};
        let bool_ty = TermType {
            inner: h.mk(TermTypeInner::Bool),
        };
        match self {
            Op::Not if l == vec![bool_ty.clone()] => Some(bool_ty.clone()),
            Op::And if l == vec![bool_ty.clone(), bool_ty.clone()] => Some(bool_ty.clone()),
            Op::Or if l == vec![bool_ty.clone(), bool_ty.clone()] => Some(bool_ty.clone()),
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 2 should not error when indexed by 0 or 1"
            )]
            Op::Eq if l.len() == 2 => {
                if l[0] == l[1] {
                    Some(bool_ty.clone())
                } else {
                    None
                }
            }
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 3 should not error when indexed by 0, 1, or 2"
            )]
            Op::Ite if l.len() == 3 && l[0].inner.get() == &Bool => {
                if l[1] == l[2] {
                    Some(l[1].clone())
                } else {
                    None
                }
            }
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 1 should not error when indexed by 0"
            )]
            Op::Uuf(f) if l.len() == 1 => {
                if f.arg == l[0] {
                    Some(Arc::unwrap_or_clone(f).out)
                } else {
                    None
                }
            }
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 1 should not error when indexed by 0"
            )]
            Op::Bvneg if l.len() == 1 => match l[0].inner.get() {
                Bitvec { n } => Some(TermType {
                    inner: h.mk(TermTypeInner::Bitvec { n: *n }),
                }),
                _ => None,
            },
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 2 should not error when indexed by 0 or 1"
            )]
            Op::Bvadd
            | Op::Bvsub
            | Op::Bvmul
            | Op::Bvshl
            | Op::Bvlshr
            | Op::Bvsdiv
            | Op::Bvudiv
            | Op::Bvsrem
            | Op::Bvsmod
            | Op::Bvumod
                if l.len() == 2 =>
            {
                match (l[0].inner.get(), l[1].inner.get()) {
                    (Bitvec { n }, Bitvec { n: m }) if n == m => Some(TermType {
                        inner: h.mk(TermTypeInner::Bitvec { n: *n }),
                    }),
                    _ => None,
                }
            }
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 1 should not error when indexed by 0"
            )]
            Op::Bvnego if l.len() == 1 && matches!(l[0].inner.get(), Bitvec { .. }) => {
                Some(bool_ty.clone())
            }
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 2 should not error when indexed by 0 or 1"
            )]
            Op::Bvsaddo
            | Op::Bvssubo
            | Op::Bvsmulo
            | Op::Bvslt
            | Op::Bvsle
            | Op::Bvult
            | Op::Bvule
                if l.len() == 2 =>
            {
                match (l[0].inner.get(), l[1].inner.get()) {
                    (Bitvec { n }, Bitvec { n: m }) if n == m => Some(bool_ty.clone()),
                    _ => None,
                }
            }
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 1 should not error when indexed by 0"
            )]
            Op::ZeroExtend(m) if l.len() == 1 => match l[0].inner.get() {
                Bitvec { n } => Some(TermType {
                    inner: h.mk(TermTypeInner::Bitvec { n: (n + m) }),
                }),
                _ => None,
            },
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 2 should not error when indexed by 0 or 1"
            )]
            Op::SetMember if l.len() == 2 => match (l[0].clone(), l[1].inner.get()) {
                (ty1, TermTypeInner::Set { ty: ty2 }) if ty1 == **ty2 => Some(bool_ty.clone()),
                (_, _) => None,
            },
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 2 should not error when indexed by 0 or 1"
            )]
            Op::SetSubset | Op::SetInter if l.len() == 2 => {
                match (l[0].inner.get(), l[1].inner.get()) {
                    (TermTypeInner::Set { ty: ty1 }, TermTypeInner::Set { ty: ty2 })
                        if ty1 == ty2 =>
                    {
                        Some(bool_ty.clone())
                    }
                    (_, _) => None,
                }
            }
            // PANIC SAFETY
            #[allow(
                clippy::unwrap_used,
                reason = "List of length 1 should not error on first call to next()"
            )]
            Op::OptionGet if l.len() == 1 => match l.into_iter().next().unwrap().inner.get() {
                TermTypeInner::Option { ty } => Some((**ty).clone()),
                _ => None,
            },
            // PANIC SAFETY
            #[allow(
                clippy::unwrap_used,
                reason = "List of length 1 should not error on first call to next()"
            )]
            Op::RecordGet(a) if l.len() == 1 => match l.into_iter().next().unwrap().inner.get() {
                TermTypeInner::Record { rty } => rty.get(&a).cloned(),
                _ => None,
            },
            Op::StringLike(_)
                if l == vec![TermType {
                    inner: h.mk(TermTypeInner::String),
                }] =>
            {
                Some(bool_ty)
            }
            Op::Ext(xop) => xop.type_of(l, h),
            _ => None,
        }
    }

    /// Returns the name of the operator.
    ///
    /// Corresponds to `Op.mkName` in the Lean model.
    pub fn mk_name(&self) -> &'static str {
        match self {
            Op::Not => "not",
            Op::And => "and",
            Op::Or => "or",
            Op::Eq => "eq",
            Op::Ite => "ite",
            Op::Uuf(_) => "uuf",
            Op::Bvneg => "bvneg",
            Op::Bvadd => "bvadd",
            Op::Bvsub => "bvsub",
            Op::Bvmul => "bvmul",
            Op::Bvsdiv => "bvsdiv",
            Op::Bvudiv => "bvudiv",
            Op::Bvsrem => "bvsrem",
            Op::Bvsmod => "bvsmod",
            Op::Bvumod => "bvurem",
            Op::Bvshl => "bvshl",
            Op::Bvlshr => "bvlshr",
            Op::Bvslt => "bvslt",
            Op::Bvsle => "bvsle",
            Op::Bvult => "bvult",
            Op::Bvule => "bvule",
            Op::Bvnego => "bvnego",
            Op::Bvsaddo => "bvsaddo",
            Op::Bvssubo => "bvssubo",
            Op::Bvsmulo => "bvsmulo",
            Op::ZeroExtend(_) => "zero_extend",
            Op::SetMember => "set.member",
            Op::SetSubset => "set.subset",
            Op::SetInter => "set.inter",
            Op::OptionGet => "option.get",
            Op::RecordGet(_) => "record.get",
            Op::StringLike(_) => "string.like",
            Op::Ext(_) => "ext",
        }
    }
}
