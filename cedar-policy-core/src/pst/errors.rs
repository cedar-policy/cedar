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

//! Error types for PST (Public Syntax Tree) construction and conversion.
//!
//! This module defines errors that can occur when:
//! - Programmatically constructing PST expressions, policies, and constraints
//! - Converting between PST and other representations (EST, AST)
//! - Validating PST structure and semantics

use crate::extensions::ExtensionFunctionLookupError;
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

/// Errors that can occur during PST construction or conversion.
#[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
pub enum PstConstructionError {
    /// Action constraints cannot contain template slots
    #[error("action constraint cannot have slots")]
    ActionConstraintCannotHaveSlots,

    /// Duplicate key found in a record literal
    #[error("duplicate record key: {0}")]
    DuplicateRecordKey(String),

    /// Failed to parse a Cedar name (e.g., entity type, attribute name)
    #[error("invalid name: {0}")]
    InvalidName(SmolStr),

    /// Invalid entity UID format or structure
    #[error("invalid entity UID: {0}")]
    InvalidEntityUid(String),

    /// Invalid entity type name
    #[error("invalid entity type: {0}")]
    InvalidEntityType(String),

    /// Invalid attribute path format or structure
    #[error("invalid attribute path: {0}")]
    InvalidAttributePath(String),

    /// Attempted to construct a `has` expression with an empty attribute path
    #[error("attribute path cannot be empty")]
    EmptyAttributePath,

    /// Invalid record structure (e.g., malformed key-value pairs)
    #[error("invalid record: {0}")]
    InvalidRecord(String),

    /// A generic invalid expression error with a description
    #[error("invalid expression: {0}")]
    InvalidExpression(String),

    /// Unknown function name (not a built-in or registered extension function)
    #[error("unknown function: {0}")]
    UnknownFunction(SmolStr),

    /// Function called with wrong number of arguments
    #[error("function {name} expects {expected} argument(s), got {got}")]
    WrongArity {
        /// The name of the function with the wrong number of arguments
        name: String,
        /// The expected number of arguments
        expected: usize,
        /// The actual number of arguments
        got: usize,
    },

    /// Extension function lookup failed (function not found or invalid)
    #[error(transparent)]
    FunctionLookupError(ExtensionFunctionLookupError),

    /// Invalid conversion between representations with description
    #[error("conversion failed: {0}")]
    InvalidConversion(String),

    /// Error nodes from parsing are not supported in PST conversion
    #[error("error nodes not supported in conversion: {0}")]
    ErrorNode(String),

    /// Conversion functionality not yet implemented
    #[error("not implemented: {0}")]
    NotImplemented(String),

    /// A parsing error occurred, usually in names
    #[error("parse error: {0}")]
    ParseError(String),
}

impl From<crate::parser::err::ParseErrors> for PstConstructionError {
    fn from(value: crate::parser::err::ParseErrors) -> Self {
        PstConstructionError::ParseError(format!("{value:?}"))
    }
}
