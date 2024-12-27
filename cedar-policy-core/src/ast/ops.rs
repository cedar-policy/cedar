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

use serde::{Deserialize, Serialize};

#[cfg(feature = "protobufs")]
use crate::ast::proto;

/// Built-in operators with exactly one argument
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum UnaryOp {
    /// Logical negation
    ///
    /// Argument must have Bool type
    Not,
    /// Integer negation
    ///
    /// Argument must have Long type
    Neg,
    /// isEmpty test for sets
    ///
    /// Argument must have Set type
    IsEmpty,
}

impl std::fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnaryOp::Not => write!(f, "!"),
            UnaryOp::Neg => write!(f, "-"),
            UnaryOp::IsEmpty => write!(f, "isEmpty"),
        }
    }
}

#[cfg(feature = "protobufs")]
impl From<&proto::expr::unary_app::Op> for UnaryOp {
    fn from(v: &proto::expr::unary_app::Op) -> Self {
        match v {
            proto::expr::unary_app::Op::Not => UnaryOp::Not,
            proto::expr::unary_app::Op::Neg => UnaryOp::Neg,
            proto::expr::unary_app::Op::IsEmpty => UnaryOp::IsEmpty,
        }
    }
}

#[cfg(feature = "protobufs")]
impl From<&UnaryOp> for proto::expr::unary_app::Op {
    fn from(v: &UnaryOp) -> Self {
        match v {
            UnaryOp::Not => proto::expr::unary_app::Op::Not,
            UnaryOp::Neg => proto::expr::unary_app::Op::Neg,
            UnaryOp::IsEmpty => proto::expr::unary_app::Op::IsEmpty,
        }
    }
}

/// Binary order relations
///
/// Arguments must have Long type or certain extension type
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum BinaryOrd {
    /// <
    Less,
    /// <=
    LessEq,
}

/// Binary arithmetic operations
///
/// Arguments must have Long type
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum BinaryArithmetic {
    /// Integer addition
    Add,
    /// Integer subtraction
    Sub,
    /// Integer multiplication
    Mul,
}

/// Binary set relations
///
/// Arguments must have Set type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum BinarySetRelation {
    /// ContainsAll test for sets. Specifically, if the first set contains the second arg.
    ContainsAll,
    /// ContainsAny test for sets (is the intersection empty?)
    ContainsAny,
}

/// Built-in operators with exactly two arguments
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[serde(untagged)]
pub enum BinaryOp {
    /// Equality
    ///
    /// Works on arguments of any type, ie "total equality". If you compare
    /// things of different types, `Eq` will return `false`, rather than error.
    Eq,
    /// Binary order relations
    Ord(BinaryOrd),
    /// Binary arithmetic operations
    /// Arguments must have Long type
    Arithmetic(BinaryArithmetic),
    /// Hierarchy membership. Specifically, is the first arg a member of the
    /// second.
    ///
    /// First argument must have Entity type.
    /// Second argument must either have Entity type, or Set type where the
    /// set elements all have Entity type. If it's a set, the semantics is
    /// "is the first argument `in` any element of the given set"
    In,

    /// Set membership.
    ///
    /// First argument must have Set type.
    Contains,

    /// Binary set relations
    SetRelation(BinarySetRelation),

    /// Get a tag of an entity.
    ///
    /// First argument must have Entity type, second argument must have String type.
    GetTag,

    /// Does the given `expr` have the given `tag`?
    ///
    /// First argument must have Entity type, second argument must have String type.
    HasTag,
}

impl std::fmt::Display for BinaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryOp::Eq => write!(f, "=="),
            BinaryOp::Ord(BinaryOrd::Less) => write!(f, "<"),
            BinaryOp::Ord(BinaryOrd::LessEq) => write!(f, "<="),
            BinaryOp::Arithmetic(BinaryArithmetic::Add) => write!(f, "+"),
            BinaryOp::Arithmetic(BinaryArithmetic::Sub) => write!(f, "-"),
            BinaryOp::Arithmetic(BinaryArithmetic::Mul) => write!(f, "*"),
            BinaryOp::In => write!(f, "in"),
            BinaryOp::Contains => write!(f, "contains"),
            BinaryOp::SetRelation(BinarySetRelation::ContainsAll) => write!(f, "containsAll"),
            BinaryOp::SetRelation(BinarySetRelation::ContainsAny) => write!(f, "containsAny"),
            BinaryOp::GetTag => write!(f, "getTag"),
            BinaryOp::HasTag => write!(f, "hasTag"),
        }
    }
}

#[cfg(feature = "protobufs")]
impl From<&proto::expr::binary_app::Op> for BinaryOp {
    fn from(v: &proto::expr::binary_app::Op) -> Self {
        match v {
            proto::expr::binary_app::Op::Eq => BinaryOp::Eq,
            proto::expr::binary_app::Op::Less => BinaryOp::Ord(BinaryOrd::Less),
            proto::expr::binary_app::Op::LessEq => BinaryOp::Ord(BinaryOrd::LessEq),
            proto::expr::binary_app::Op::Add => BinaryOp::Arithmetic(BinaryArithmetic::Add),
            proto::expr::binary_app::Op::Sub => BinaryOp::Arithmetic(BinaryArithmetic::Sub),
            proto::expr::binary_app::Op::Mul => BinaryOp::Arithmetic(BinaryArithmetic::Mul),
            proto::expr::binary_app::Op::In => BinaryOp::In,
            proto::expr::binary_app::Op::Contains => BinaryOp::Contains,
            proto::expr::binary_app::Op::ContainsAll => {
                BinaryOp::SetRelation(BinarySetRelation::ContainsAll)
            }
            proto::expr::binary_app::Op::ContainsAny => {
                BinaryOp::SetRelation(BinarySetRelation::ContainsAny)
            }
            proto::expr::binary_app::Op::GetTag => BinaryOp::GetTag,
            proto::expr::binary_app::Op::HasTag => BinaryOp::HasTag,
        }
    }
}

#[cfg(feature = "protobufs")]
impl From<&BinaryOp> for proto::expr::binary_app::Op {
    fn from(v: &BinaryOp) -> Self {
        match v {
            BinaryOp::Eq => proto::expr::binary_app::Op::Eq,
            BinaryOp::Ord(BinaryOrd::Less) => proto::expr::binary_app::Op::Less,
            BinaryOp::Ord(BinaryOrd::LessEq) => proto::expr::binary_app::Op::LessEq,
            BinaryOp::Arithmetic(BinaryArithmetic::Add) => proto::expr::binary_app::Op::Add,
            BinaryOp::Arithmetic(BinaryArithmetic::Sub) => proto::expr::binary_app::Op::Sub,
            BinaryOp::Arithmetic(BinaryArithmetic::Mul) => proto::expr::binary_app::Op::Mul,
            BinaryOp::In => proto::expr::binary_app::Op::In,
            BinaryOp::Contains => proto::expr::binary_app::Op::Contains,
            BinaryOp::SetRelation(BinarySetRelation::ContainsAll) => {
                proto::expr::binary_app::Op::ContainsAll
            }
            BinaryOp::SetRelation(BinarySetRelation::ContainsAny) => {
                proto::expr::binary_app::Op::ContainsAny
            }
            BinaryOp::GetTag => proto::expr::binary_app::Op::GetTag,
            BinaryOp::HasTag => proto::expr::binary_app::Op::HasTag,
        }
    }
}
