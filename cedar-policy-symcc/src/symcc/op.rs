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

use super::term_type::TermType;
use super::type_abbrevs::*;

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
#[expect(missing_docs, reason = "self-explanatory")]
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
#[expect(missing_docs, reason = "existing code")]
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
}

impl Op {
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
