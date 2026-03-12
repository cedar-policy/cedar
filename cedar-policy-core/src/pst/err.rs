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

use miette::Diagnostic;
use smol_str::ToSmolStr;
use thiserror::Error;

use crate::est;

/// Errors that can occur during PST construction or conversion
#[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
#[non_exhaustive]
pub enum PstConstructionError {
    /// Action constraints cannot contain template slots
    #[error(transparent)]
    #[diagnostic(transparent)]
    ActionConstraintCannotHaveSlots(#[from] error_body::ActionConstraintCannotHaveSlotsError),

    /// Duplicate key found in a record literal
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateRecordKey(#[from] error_body::DuplicateRecordKeyError),

    /// Failed to parse a Cedar name (e.g., entity type, attribute name)
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidName(#[from] error_body::InvalidNameError),

    /// Invalid entity UID format or structure
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidEntityUid(#[from] error_body::InvalidEntityUidError),

    /// Invalid entity type name
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidEntityType(#[from] error_body::InvalidEntityTypeError),

    /// Invalid attribute path format or structure
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidAttributePath(#[from] error_body::InvalidAttributePathError),

    /// Attempted to construct a `has` expression with an empty attribute path
    #[error(transparent)]
    #[diagnostic(transparent)]
    EmptyAttributePath(#[from] error_body::EmptyAttributePathError),

    /// Invalid record structure (e.g., malformed key-value pairs)
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidRecord(#[from] error_body::InvalidRecordError),

    /// A generic invalid expression error with a description
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidExpression(#[from] error_body::InvalidExpressionError),

    /// Unknown function name (not a built-in or registered extension function)
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnknownFunction(#[from] error_body::UnknownFunctionError),

    /// Function called with wrong number of arguments
    #[error(transparent)]
    #[diagnostic(transparent)]
    WrongArity(#[from] error_body::WrongArityError),

    /// Extension function lookup failed (function not found or invalid)
    #[error(transparent)]
    #[diagnostic(transparent)]
    FunctionLookup(#[from] error_body::FunctionLookupError),

    /// Invalid conversion between representations with description
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidConversion(#[from] error_body::InvalidConversionError),

    /// Error nodes from parsing are not supported in PST conversion
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnsupportedErrorNode(#[from] error_body::UnsupportedErrorNode),

    /// Conversion functionality not yet implemented
    #[error(transparent)]
    #[diagnostic(transparent)]
    NotImplemented(#[from] error_body::NotImplementedError),

    /// A parsing error occurred, usually in names
    #[error(transparent)]
    #[diagnostic(transparent)]
    ParsingFailed(#[from] error_body::ParsingFailedError),

    /// A linking error occurred.
    #[error(transparent)]
    #[diagnostic(transparent)]
    LinkingFailed(#[from] error_body::LinkingError),
}

#[doc(hidden)]
impl From<est::FromJsonError> for PstConstructionError {
    fn from(err: est::FromJsonError) -> Self {
        match err {
            est::FromJsonError::UnknownExtensionFunction(e) => {
                PstConstructionError::UnknownFunction(error_body::UnknownFunctionError::new(
                    e.to_smolstr(),
                ))
            }
            est::FromJsonError::InvalidEntityType(e) => {
                PstConstructionError::InvalidEntityType(error_body::InvalidEntityTypeError {
                    description: e.to_string(),
                })
            }
            est::FromJsonError::UnescapeError(e) => PstConstructionError::ParsingFailed(
                // Show just first error in main error message, like original err
                error_body::ParsingFailedError::new(e.head.to_string()),
            ),
            #[cfg(feature = "tolerant-ast")]
            est::FromJsonError::ASTErrorNode => {
                PstConstructionError::UnsupportedErrorNode(error_body::UnsupportedErrorNode {})
            }
            _ => PstConstructionError::InvalidConversion(error_body::InvalidConversionError::new(
                err.to_string(),
            )),
        }
    }
}

/// Error subtypes for [`PstConstructionError`]
pub mod error_body {
    use crate::extensions::ExtensionFunctionLookupError;
    use miette::Diagnostic;
    use smol_str::SmolStr;
    use thiserror::Error;

    /// Action constraints cannot contain template slots
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("action constraint cannot have slots")]
    pub struct ActionConstraintCannotHaveSlotsError;

    /// Duplicate key found in a record literal
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("duplicate record key: `{key}`")]
    pub struct DuplicateRecordKeyError {
        pub(crate) key: String,
    }

    impl DuplicateRecordKeyError {
        /// The duplicate key
        pub fn key(&self) -> &str {
            &self.key
        }
    }

    /// Failed to parse a Cedar name
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("invalid name: `{name}`")]
    pub struct InvalidNameError {
        pub(crate) name: SmolStr,
    }

    impl InvalidNameError {
        /// The invalid name
        pub fn name(&self) -> &str {
            &self.name
        }
    }

    /// Invalid entity UID format or structure
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("invalid entity UID: {description}")]
    pub struct InvalidEntityUidError {
        pub(crate) description: String,
    }

    /// Invalid entity type error (often failure to parse the name)
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("invalid entity type: `{description}`")]
    pub struct InvalidEntityTypeError {
        pub(crate) description: String,
    }

    /// Invalid attribute path format or structure
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("invalid attribute path: {description}")]
    pub struct InvalidAttributePathError {
        pub(crate) description: String,
    }

    /// Attempted to construct a `has` expression with an empty attribute path
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("attribute path cannot be empty")]
    pub struct EmptyAttributePathError;

    /// Invalid record structure
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("invalid record: {description}")]
    pub struct InvalidRecordError {
        pub(crate) description: String,
    }

    /// A generic invalid expression error with a description
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("invalid expression: {description}")]
    pub struct InvalidExpressionError {
        pub(crate) description: String,
    }

    impl InvalidExpressionError {
        pub(crate) fn new(description: String) -> Self {
            Self { description }
        }
    }

    /// Unknown function name
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("unknown function: `{name}`")]
    pub struct UnknownFunctionError {
        pub(crate) name: SmolStr,
    }

    impl UnknownFunctionError {
        pub(crate) fn new(name: SmolStr) -> Self {
            Self { name }
        }

        /// The unknown function name
        pub fn name(&self) -> &str {
            &self.name
        }
    }

    /// Function called with wrong number of arguments
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("function `{name}` expects {expected} argument(s), got {got}")]
    pub struct WrongArityError {
        pub(crate) name: String,
        pub(crate) expected: usize,
        pub(crate) got: usize,
    }

    impl WrongArityError {
        pub(crate) fn new(name: String, expected: usize, got: usize) -> Self {
            Self {
                name,
                expected,
                got,
            }
        }

        /// The function name
        pub fn name(&self) -> &str {
            &self.name
        }

        /// The expected number of arguments
        pub fn expected(&self) -> usize {
            self.expected
        }

        /// The actual number of arguments provided
        pub fn got(&self) -> usize {
            self.got
        }
    }

    /// Extension function lookup failed
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error(transparent)]
    pub struct FunctionLookupError(pub(crate) ExtensionFunctionLookupError);

    impl From<ExtensionFunctionLookupError> for FunctionLookupError {
        fn from(err: ExtensionFunctionLookupError) -> Self {
            Self(err)
        }
    }

    /// Invalid conversion between representations
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("conversion failed: {description}")]
    pub struct InvalidConversionError {
        pub(crate) description: String,
    }

    impl InvalidConversionError {
        pub(crate) fn new(description: String) -> Self {
            Self { description }
        }
    }

    /// Error nodes from parsing are not supported in PST conversion
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("error nodes not supported in conversion")]
    pub struct UnsupportedErrorNode {}

    /// Conversion functionality not yet implemented
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("not implemented: {description}")]
    pub struct NotImplementedError {
        pub(crate) description: String,
    }

    /// A parsing error occurred
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("parse error: {description}")]
    pub struct ParsingFailedError {
        pub(crate) description: String,
    }

    impl ParsingFailedError {
        pub(crate) fn new(description: String) -> Self {
            Self { description }
        }
    }

    impl From<crate::parser::err::ParseErrors> for ParsingFailedError {
        fn from(value: crate::parser::err::ParseErrors) -> Self {
            Self::new(format!("{value:?}"))
        }
    }

    /// Errors that can occur when linking a template policy
    #[derive(Debug, PartialEq, Eq, Diagnostic, Error, Clone)]
    pub enum LinkingError {
        /// Template contains this slot, but a value wasn't provided for it
        #[error("failed to link template: no value provided for `{slot}`")]
        MissedSlot {
            /// Slot which didn't have a value provided for it
            slot: crate::pst::SlotId,
        },
    }
}
