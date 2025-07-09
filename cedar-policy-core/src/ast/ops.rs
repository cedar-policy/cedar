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

use crate::spec::*;
use crate::verus_utils::*;
use vstd::prelude::*;

verus! {

/// Built-in operators with exactly one argument
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[verifier::external_derive]
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

clone_spec_for!(UnaryOp);

impl View for UnaryOp {
    type V = spec_ast::UnaryOp;

    #[verifier::inline]
    open spec fn view(&self) -> spec_ast::UnaryOp {
        match self {
            UnaryOp::Not => spec_ast::UnaryOp::Not,
            UnaryOp::Neg => spec_ast::UnaryOp::Neg,
            UnaryOp::IsEmpty => spec_ast::UnaryOp::IsEmpty,
        }
    }
}

} // verus!

impl std::fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnaryOp::Not => write!(f, "!"),
            UnaryOp::Neg => write!(f, "-"),
            UnaryOp::IsEmpty => write!(f, "isEmpty"),
        }
    }
}

verus! {

/// Built-in operators with exactly two arguments
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[verifier::external_derive]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum BinaryOp {
    /// Equality
    ///
    /// Works on arguments of any type, ie "total equality". If you compare
    /// things of different types, `Eq` will return `false`, rather than error.
    Eq,

    /// <
    ///
    /// Arguments must have Long type
    Less,

    /// <=
    ///
    /// Arguments must have Long type
    LessEq,

    /// Integer addition
    ///
    /// Arguments must have Long type
    Add,

    /// Integer subtraction
    ///
    /// Arguments must have Long type
    Sub,

    /// Integer multiplication
    ///
    /// Arguments must have Long type
    Mul,

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

    /// ContainsAll test for sets. Specifically, if the first set contains the second arg.
    ///
    /// Arguments must have Set type
    ContainsAll,

    /// ContainsAny test for sets (is the intersection empty?)
    ///
    /// Arguments must have Set type
    ContainsAny,

    /// Get a tag of an entity.
    ///
    /// First argument must have Entity type, second argument must have String type.
    GetTag,

    /// Does the given `expr` have the given `tag`?
    ///
    /// First argument must have Entity type, second argument must have String type.
    HasTag,
}

clone_spec_for!(BinaryOp);

impl View for BinaryOp {
    type V = spec_ast::BinaryOp;

    #[verifier::inline]
    open spec fn view(&self) -> spec_ast::BinaryOp {
        match self {
            BinaryOp::Eq => spec_ast::BinaryOp::Eq,
            BinaryOp::Less => spec_ast::BinaryOp::Less,
            BinaryOp::LessEq => spec_ast::BinaryOp::LessEq,
            BinaryOp::Add => spec_ast::BinaryOp::Add,
            BinaryOp::Sub => spec_ast::BinaryOp::Sub,
            BinaryOp::Mul => spec_ast::BinaryOp::Mul,
            BinaryOp::In => spec_ast::BinaryOp::Mem,
            BinaryOp::Contains => spec_ast::BinaryOp::Contains,
            BinaryOp::ContainsAll => spec_ast::BinaryOp::ContainsAll,
            BinaryOp::ContainsAny => spec_ast::BinaryOp::ContainsAny,
            BinaryOp::GetTag => spec_ast::BinaryOp::GetTag,
            BinaryOp::HasTag => spec_ast::BinaryOp::HasTag,
        }
    }

}

} // verus!

impl std::fmt::Display for BinaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryOp::Eq => write!(f, "=="),
            BinaryOp::Less => write!(f, "<"),
            BinaryOp::LessEq => write!(f, "<="),
            BinaryOp::Add => write!(f, "+"),
            BinaryOp::Sub => write!(f, "-"),
            BinaryOp::Mul => write!(f, "*"),
            BinaryOp::In => write!(f, "in"),
            BinaryOp::Contains => write!(f, "contains"),
            BinaryOp::ContainsAll => write!(f, "containsAll"),
            BinaryOp::ContainsAny => write!(f, "containsAny"),
            BinaryOp::GetTag => write!(f, "getTag"),
            BinaryOp::HasTag => write!(f, "hasTag"),
        }
    }
}
