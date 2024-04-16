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

use crate::ast::CallStyle;
use serde::{Deserialize, Serialize};

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
}

/// Built-in operators with exactly two arguments
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Hash)]
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
}

impl std::fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnaryOp::Not => write!(f, "!_"),
            UnaryOp::Neg => write!(f, "-_"),
        }
    }
}

impl std::fmt::Display for BinaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryOp::Eq => write!(f, "_==_"),
            BinaryOp::Less => write!(f, "_<_"),
            BinaryOp::LessEq => write!(f, "_<=_"),
            BinaryOp::Add => write!(f, "_+_"),
            BinaryOp::Sub => write!(f, "_-_"),
            BinaryOp::Mul => write!(f, "_*_"),
            BinaryOp::In => write!(f, "_in_"),
            BinaryOp::Contains => write!(f, "contains"),
            BinaryOp::ContainsAll => write!(f, "containsAll"),
            BinaryOp::ContainsAny => write!(f, "containsAny"),
        }
    }
}

impl std::fmt::Display for CallStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FunctionStyle => write!(f, "function-style"),
            Self::MethodStyle => write!(f, "method-style"),
        }
    }
}
