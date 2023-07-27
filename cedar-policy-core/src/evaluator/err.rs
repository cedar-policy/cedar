/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

use crate::ast::*;
use smol_str::SmolStr;
use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur during evaluation
#[derive(Debug, PartialEq, Clone, Error)]
pub enum EvaluationError {
    /// Tried to lookup this entity UID, but it didn't exist in the provided
    /// entities
    #[error("entity does not exist: {0}")]
    EntityDoesNotExist(Arc<EntityUID>),

    /// Tried to get this attribute, but the specified entity didn't
    /// have that attribute
    #[error("`{}` does not have the attribute: {}", &.entity, &.attr)]
    EntityAttrDoesNotExist {
        /// Entity that didn't have the attribute
        entity: Arc<EntityUID>,
        /// Name of the attribute it didn't have
        attr: SmolStr,
    },

    /// Tried to access an attribute of an unspecified entity
    #[error("cannot access attribute of unspecified entity: {0}")]
    UnspecifiedEntityAccess(SmolStr),

    /// Tried to get an attribute of a (non-entity) record, but that record
    /// didn't have that attribute
    #[error("record does not have the attribute: {0}. Available attributes: {1:?}")]
    RecordAttrDoesNotExist(SmolStr, Vec<SmolStr>),

    /// An error occurred when looking up an extension function
    #[error(transparent)]
    FailedExtensionFunctionLookup(#[from] crate::extensions::ExtensionFunctionLookupError),

    /// Tried to evaluate an operation on values with incorrect types for that
    /// operation
    // INVARIANT `expected` must be non-empty
    #[error("{}", pretty_type_error(expected, actual))]
    TypeError {
        /// Expected (one of) these types
        expected: Vec<Type>,
        /// Encountered this type instead
        actual: Type,
    },

    /// Wrong number of arguments provided to an extension function
    #[error("wrong number of arguments provided to extension function {function_name}: expected {expected}, got {actual}")]
    WrongNumArguments {
        /// arguments to this function
        function_name: Name,
        /// expected number of arguments
        expected: usize,
        /// actual number of arguments
        actual: usize,
    },

    /// Overflow during an integer operation
    #[error(transparent)]
    IntegerOverflow(#[from] IntegerOverflowError),

    /// Error with the use of "restricted" expressions
    #[error(transparent)]
    InvalidRestrictedExpression(#[from] RestrictedExprError),

    /// Thrown when a policy is evaluated with a slot that is not linked to an
    /// [`EntityUID`]
    #[error("template slot `{0}` was not linked")]
    UnlinkedSlot(SlotId),

    /// Evaluation error thrown by an extension function
    #[error("error while evaluating {extension_name} extension function: {msg}")]
    FailedExtensionFunctionApplication {
        /// Name of the extension throwing the error
        extension_name: Name,
        /// Error message from the extension
        msg: String,
    },

    /// This error is raised if an expression contains unknowns and cannot be
    /// reduced to a [`Value`]. In order to return partial results, use the
    /// partial evaluation APIs instead.
    #[error("the expression contains unknown(s) (consider using the partial evaluation API): {0}")]
    NonValue(Expr),

    /// Maximum recursion limit reached for expression evaluation
    #[error("recursion limit reached")]
    RecursionLimit,
}

/// helper function for pretty-printing type errors
/// INVARIANT: `expected` must have at least one value
fn pretty_type_error(expected: &[Type], actual: &Type) -> String {
    match expected.len() {
        // PANIC SAFETY, `expected` is non-empty by invariant
        #[allow(clippy::unreachable)]
        0 => unreachable!("should expect at least one type"),
        // PANIC SAFETY. `len` is 1 in this branch
        #[allow(clippy::indexing_slicing)]
        1 => format!("type error: expected {}, got {}", expected[0], actual),
        _ => {
            use itertools::Itertools;
            format!(
                "type error: expected one of [{}], got {actual}",
                expected.iter().join(", ")
            )
        }
    }
}

#[derive(Debug, PartialEq, Clone, Error)]
pub enum IntegerOverflowError {
    /// Overflow during a binary operation
    #[error("integer overflow while attempting to {} the values `{arg1}` and `{arg2}`", match .op { BinaryOp::Add => "add", BinaryOp::Sub => "subtract", _ => "perform an operation on" })]
    BinaryOp {
        /// overflow while evaluating this operator
        op: BinaryOp,
        /// first argument to that operator
        arg1: Value,
        /// second argument to that operator
        arg2: Value,
    },

    /// Overflow during multiplication
    #[error("integer overflow while attempting to multiply `{arg}` by `{constant}`")]
    Multiplication {
        /// first argument, which wasn't necessarily a constant in the policy
        arg: Value,
        /// second argument, which was a constant in the policy
        constant: i64,
    },

    /// Overflow during a unary operation
    #[error("integer overflow while attempting to {} the value `{arg}`", match .op { UnaryOp::Neg => "negate", _ => "perform an operation on" })]
    UnaryOp {
        /// overflow while evaluating this operator
        op: UnaryOp,
        /// argument to that operator
        arg: Value,
    },
}

/// Type alias for convenience
pub type Result<T> = std::result::Result<T, EvaluationError>;
