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

use super::term_type::TermType;
use super::type_abbrevs::*;

/// Uninterpreted unary function
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct Uuf {
    pub id: String,
    pub arg: TermType,
    pub out: TermType,
}

/// Extension ADT operators
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
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
pub enum Op {
    //   ---------- SMTLib core theory of equality with uninterpreted functions (`UF`) ----------
    Not,
    And,
    Or,
    Eq,
    Ite,
    Uuf(Uuf),
    //   ---------- SMTLib theory of finite bitvectors (`BV`) ----------
    Bvneg,
    Bvadd,
    Bvsub,
    Bvmul,
    Bvsdiv, // signed bit-vector division
    Bvudiv, // unsigned bit-vector division
    Bvsrem, // signed remainder (remainder of division rounded towards zero) (copies sign from dividend)
    Bvsmod, // signed modulus (remainder of division rounded towards negative infinity) (copies sign from divisor)
    Bvumod, // unsigned modulus
    Bvshl,
    Bvlshr,
    Bvslt,
    Bvsle,
    Bvult,
    Bvule,
    /// bit-vector negation overflow predicate
    Bvnego,
    /// bit-vector signed addition overflow predicate
    Bvsaddo,
    /// bit-vector signed subtraction overflow predicate
    Bvssubo,
    /// bit-vector signed multiplication overflow predicate
    Bvsmulo,
    ZeroExtend(Nat),
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

    #[allow(clippy::needless_pass_by_value)]
    pub fn type_of(self, l: Vec<TermType>) -> Option<TermType> {
        match self {
            ExtOp::DecimalVal
                if l == vec![TermType::Ext {
                    xty: ExtType::Decimal,
                }] =>
            {
                Some(TermType::Bitvec { n: 64 })
            }
            ExtOp::IpaddrIsV4
                if l == vec![TermType::Ext {
                    xty: ExtType::IpAddr,
                }] =>
            {
                Some(TermType::Bool)
            }
            ExtOp::IpaddrAddrV4
                if l == vec![TermType::Ext {
                    xty: ExtType::IpAddr,
                }] =>
            {
                Some(TermType::Bitvec { n: 32 })
            }
            ExtOp::IpaddrPrefixV4
                if l == vec![TermType::Ext {
                    xty: ExtType::IpAddr,
                }] =>
            {
                Some(TermType::Option {
                    ty: Box::new(TermType::Bitvec { n: 5 }),
                })
            }
            ExtOp::IpaddrAddrV6
                if l == vec![TermType::Ext {
                    xty: ExtType::IpAddr,
                }] =>
            {
                Some(TermType::Bitvec { n: 128 })
            }
            ExtOp::DatetimeVal
                if l == vec![TermType::Ext {
                    xty: ExtType::DateTime,
                }] =>
            {
                Some(TermType::Bitvec { n: 64 })
            }
            ExtOp::DatetimeOfBitVec if l == vec![TermType::Bitvec { n: 64 }] => {
                Some(TermType::Ext {
                    xty: ExtType::DateTime,
                })
            }
            ExtOp::DurationVal
                if l == vec![TermType::Ext {
                    xty: ExtType::Duration,
                }] =>
            {
                Some(TermType::Bitvec { n: 64 })
            }
            ExtOp::DurationOfBitVec if l == vec![TermType::Bitvec { n: 64 }] => {
                Some(TermType::Ext {
                    xty: ExtType::Duration,
                })
            }
            _ => None,
        }
    }
}

impl Op {
    #[allow(clippy::cognitive_complexity)]
    pub fn type_of(self, l: Vec<TermType>) -> Option<TermType> {
        use TermType::{Bitvec, Bool};
        match self {
            Op::Not if l == vec![TermType::Bool] => Some(TermType::Bool),
            Op::And if l == vec![TermType::Bool, TermType::Bool] => Some(TermType::Bool),
            Op::Or if l == vec![TermType::Bool, TermType::Bool] => Some(TermType::Bool),
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 2 should not error when indexed by 0 or 1"
            )]
            Op::Eq if l.len() == 2 => {
                if l[0] == l[1] {
                    Some(TermType::Bool)
                } else {
                    None
                }
            }
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 3 should not error when indexed by 0, 1, or 2"
            )]
            Op::Ite if l.len() == 3 && l[0] == Bool => {
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
                    Some(f.out)
                } else {
                    None
                }
            }
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 1 should not error when indexed by 0"
            )]
            Op::Bvneg if l.len() == 1 => match l[0] {
                Bitvec { n } => Some(Bitvec { n }),
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
                match (l[0].clone(), l[1].clone()) {
                    (Bitvec { n }, Bitvec { n: m }) if n == m => Some(Bitvec { n }),
                    _ => None,
                }
            }
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 1 should not error when indexed by 0"
            )]
            Op::Bvnego if l.len() == 1 && matches!(l[0].clone(), Bitvec { .. }) => Some(Bool),
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
                match (l[0].clone(), l[1].clone()) {
                    (Bitvec { n }, Bitvec { n: m }) if n == m => Some(Bool),
                    _ => None,
                }
            }
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 1 should not error when indexed by 0"
            )]
            Op::ZeroExtend(m) if l.len() == 1 => match l[0].clone() {
                Bitvec { n } => Some(Bitvec { n: (n + m) }),
                _ => None,
            },
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 2 should not error when indexed by 0 or 1"
            )]
            Op::SetMember if l.len() == 2 => match (l[0].clone(), l[1].clone()) {
                (ty1, TermType::Set { ty: ty2 }) if ty1 == *ty2 => Some(Bool),
                (_, _) => None,
            },
            // PANIC SAFETY
            #[allow(
                clippy::indexing_slicing,
                reason = "List of length 2 should not error when indexed by 0 or 1"
            )]
            Op::SetSubset | Op::SetInter if l.len() == 2 => match (l[0].clone(), l[1].clone()) {
                (TermType::Set { ty: ty1 }, TermType::Set { ty: ty2 }) if *ty1 == *ty2 => {
                    Some(Bool)
                }
                (_, _) => None,
            },
            // PANIC SAFETY
            #[allow(
                clippy::unwrap_used,
                reason = "List of length 1 should not error on first call to next()"
            )]
            Op::OptionGet if l.len() == 1 => match l.into_iter().next().unwrap() {
                TermType::Option { ty } => Some(*ty),
                _ => None,
            },
            // PANIC SAFETY
            #[allow(
                clippy::unwrap_used,
                reason = "List of length 1 should not error on first call to next()"
            )]
            Op::RecordGet(a) if l.len() == 1 => match l.into_iter().next().unwrap() {
                TermType::Record { rty } => rty.get(&a).cloned(),
                _ => None,
            },
            Op::StringLike(_) if l == vec![TermType::String] => Some(Bool),
            Op::Ext(xop) => xop.type_of(l),
            _ => None,
        }
    }

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
            Op::Bvumod => "Bvurem",
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
