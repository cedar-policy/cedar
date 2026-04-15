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

use std::collections::HashSet;

use crate::extensions::ExtensionFunctionLookupError;
use crate::pst;
use miette::Diagnostic;
use smol_str::ToSmolStr;
use thiserror::Error;

use crate::ast;
use crate::est;

/// Errors that can occur during PST construction or conversion
#[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
#[non_exhaustive]
pub enum PstConstructionError {
    /// A policy is a linked policy but no link id has been provided
    #[error(transparent)]
    #[diagnostic(transparent)]
    PolicyMissingLinkId(#[from] error_body::PolicyMissingLinkIdError),

    /// Action constraints cannot contain template slots
    #[error(transparent)]
    #[diagnostic(transparent)]
    ActionConstraintCannotHaveSlots(#[from] error_body::ActionConstraintCannotHaveSlotsError),

    /// Expected a template with slots, but found a static policy
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExpectedTemplateWithSlots(#[from] error_body::ExpectedTemplateWithSlotsError),

    /// Slot occurs in the wrong position (e.g., principal slot in resource)
    #[error(transparent)]
    #[diagnostic(transparent)]
    WrongSlotPosition(#[from] error_body::WrongSlotPositionError),

    /// Duplicate key found in a record literal
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateRecordKey(#[from] error_body::DuplicateRecordKeyError),

    /// Invalid annotation in a policy or template
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidAnnotation(#[from] error_body::InvalidAnnotationError),

    /// Invalid entity UID format or structure
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidEntityUid(#[from] error_body::InvalidEntityUidError),

    /// Invalid entity type name
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidEntityType(#[from] error_body::InvalidEntityTypeError),

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

    /// Error nodes from parsing are not supported in PST conversion
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnsupportedErrorNode(#[from] error_body::UnsupportedErrorNode),

    /// A parsing error occurred, usually in names
    #[error(transparent)]
    #[diagnostic(transparent)]
    ParsingFailed(#[from] error_body::ParsingFailedError),

    /// A linking error occurred.
    #[error(transparent)]
    #[diagnostic(transparent)]
    LinkingFailed(#[from] error_body::LinkingError),

    /// Contains unexpected slots
    #[error(transparent)]
    #[diagnostic(transparent)]
    ContainsSlots(#[from] error_body::ContainsSlotError),
}

#[doc(hidden)]
impl From<est::FromJsonError> for PstConstructionError {
    fn from(err: est::FromJsonError) -> Self {
        match err {
            est::FromJsonError::UnknownExtensionFunction(e) => {
                error_body::UnknownFunctionError::new(e.to_smolstr()).into()
            }
            est::FromJsonError::InvalidEntityType(e) => error_body::InvalidEntityTypeError {
                description: e.to_string(),
            }
            .into(),
            est::FromJsonError::JsonDeserializationError(e) => {
                // An error while deserializing JSON can occur only in small transformations; this
                // is likely a parsing error on a literal.
                error_body::ParsingFailedError::new(e.to_string()).into()
            }
            est::FromJsonError::UnescapeError(e) => {
                // Show just first error in main error message, like original err
                error_body::ParsingFailedError::new(e.head.to_string()).into()
            }

            // Errors below should not occur in normal expression conversion paths, but we still
            // map them to the closest PST error for completeness.
            est::FromJsonError::ActionSlot => {
                error_body::ActionConstraintCannotHaveSlotsError.into()
            }
            est::FromJsonError::InvalidActionType(e) => error_body::InvalidEntityTypeError {
                description: e.to_string(),
            }
            .into(),
            est::FromJsonError::InvalidSlotName => {
                error_body::ParsingFailedError::new(err.to_string()).into()
            }
            est::FromJsonError::TemplateToPolicy(e) => {
                let mut slots: HashSet<pst::SlotId, _> = HashSet::new();
                slots.insert(e.slot.id.into());
                error_body::ContainsSlotError { slots }.into()
            }
            est::FromJsonError::PolicyToTemplate(_) => {
                error_body::ExpectedTemplateWithSlotsError.into()
            }
            est::FromJsonError::SlotsInConditionClause(e) => error_body::ContainsSlotError {
                slots: std::iter::once(e.slot.id.into()).collect(),
            }
            .into(),
            est::FromJsonError::MissingOperator | est::FromJsonError::MultipleOperators { .. } => {
                error_body::InvalidExpressionError::new(err.to_string()).into()
            }
            #[cfg(feature = "tolerant-ast")]
            est::FromJsonError::ASTErrorNode => {
                error_body::UnsupportedErrorNode::new("AST contains an error node").into()
            }
        }
    }
}

#[doc(hidden)]
impl From<ast::ExpressionConstructionError> for PstConstructionError {
    fn from(err: ast::ExpressionConstructionError) -> Self {
        let ast::ExpressionConstructionError::DuplicateKey(k) = err;
        error_body::DuplicateRecordKeyError { key: k.key }.into()
    }
}

#[doc(hidden)]
impl From<crate::parser::err::ParseErrors> for PstConstructionError {
    fn from(value: crate::parser::err::ParseErrors) -> Self {
        error_body::ParsingFailedError::from(value).into()
    }
}

// Extension function lookup failed

#[doc(hidden)]
impl From<ExtensionFunctionLookupError> for PstConstructionError {
    fn from(err: ExtensionFunctionLookupError) -> Self {
        let ExtensionFunctionLookupError::FuncDoesNotExist(body) = err;
        error_body::UnknownFunctionError::new(body.name.to_smolstr()).into()
    }
}

/// Error subtypes for [`PstConstructionError`]
pub mod error_body {
    use miette::Diagnostic;
    use smol_str::SmolStr;
    use std::collections::HashSet;
    use thiserror::Error;

    use crate::est;
    use crate::pst;

    /// A policy is a linked policy but no link id has been provided
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("linked policy is missing an instance id")]
    pub struct PolicyMissingLinkIdError;

    /// Action constraints cannot contain template slots
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("action constraint cannot have slots")]
    pub struct ActionConstraintCannotHaveSlotsError;

    /// Expected a template with slots, but found a static policy
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("expected a template with slots, but found a static policy")]
    pub struct ExpectedTemplateWithSlotsError;

    /// Slot occurs in the wrong position (e.g., principal slot in resource)
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("slot `{found}` cannot be used in this position (expected slot `{expected}`)")]
    pub struct WrongSlotPositionError {
        found: pst::SlotId,
        expected: pst::SlotId,
    }

    impl WrongSlotPositionError {
        pub(crate) fn new(found: pst::SlotId, expected: pst::SlotId) -> Self {
            Self { found, expected }
        }
    }

    /// Duplicate key found in a record literal
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("duplicate record key: `{key}`")]
    pub struct DuplicateRecordKeyError {
        pub(crate) key: SmolStr,
    }

    impl DuplicateRecordKeyError {
        /// The duplicate key
        pub fn key(&self) -> &str {
            &self.key
        }
    }

    /// Invalid annotation in a policy or template
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("invalid annotation: {description}")]
    pub struct InvalidAnnotationError {
        description: String,
    }

    impl InvalidAnnotationError {
        pub(crate) fn new(description: impl Into<String>) -> Self {
            Self {
                description: description.into(),
            }
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

    /// Error nodes from parsing are not supported in PST conversion
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("error nodes not supported in conversion: {description}")]
    pub struct UnsupportedErrorNode {
        /// Information about where this error node might come from
        description: &'static str,
    }

    impl UnsupportedErrorNode {
        pub(crate) fn new(description: &'static str) -> Self {
            Self { description }
        }
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
            Self::new(format!("{value}"))
        }
    }

    /// Errors that can occur when linking a template policy
    #[derive(Debug, PartialEq, Eq, Diagnostic, Error, Clone)]
    pub enum LinkingError {
        /// Template contains this slot, but a value wasn't provided for it
        #[error("failed to link template: no value provided for `{slot}`")]
        MissedSlot {
            /// Slot which didn't have a value provided for it
            slot: pst::SlotId,
        },
    }

    impl From<LinkingError> for est::LinkingError {
        fn from(err: LinkingError) -> Self {
            match err {
                LinkingError::MissedSlot { slot } => Self::MissedSlot { slot: slot.into() },
            }
        }
    }

    /// The policy or an expression contains slots
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("policy or expression contains slots: {slots:?}")]
    pub struct ContainsSlotError {
        pub(crate) slots: HashSet<crate::pst::SlotId>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cool_asserts::assert_matches;

    #[test]
    fn from_json_error_conversions() {
        use crate::est::FromJsonError;

        // This is a set of rather shallow tests to cover the different cases in FromJsonError.
        // We don't actually expect those to happen, cause you need a valid EST/AST to then convert
        // to the PST, so those FromJsonError would already have happened. However, we want to
        // cover nicely the conversion just in case. The real error cases should be covered in
        // unit tests in the conversions.

        // JsonDeserializationError
        let serde_err = serde_json::from_str::<String>("bad").unwrap_err();
        let json_deser_err: crate::entities::json::err::JsonDeserializationError = serde_err.into();
        let err: PstConstructionError =
            FromJsonError::JsonDeserializationError(json_deser_err).into();
        assert_matches!(err, PstConstructionError::ParsingFailed(..));

        // ActionSlot
        let err: PstConstructionError = FromJsonError::ActionSlot.into();
        assert!(matches!(
            err,
            PstConstructionError::ActionConstraintCannotHaveSlots(..)
        ));

        // InvalidActionType
        let euid = ast::EntityUID::with_eid_and_type("Bad", "act").unwrap();
        let err: PstConstructionError =
            FromJsonError::InvalidActionType(crate::parser::err::parse_errors::InvalidActionType {
                euids: nonempty::nonempty![std::sync::Arc::new(euid)],
            })
            .into();
        assert_matches!(err, PstConstructionError::InvalidEntityType(..));

        // InvalidSlotName
        let err: PstConstructionError = FromJsonError::InvalidSlotName.into();
        assert_matches!(err, PstConstructionError::ParsingFailed(..));

        // TemplateToPolicy
        let err: PstConstructionError = FromJsonError::TemplateToPolicy(
            crate::parser::err::parse_errors::ExpectedStaticPolicy {
                slot: ast::Slot {
                    id: ast::SlotId::principal(),
                    loc: None,
                },
            },
        )
        .into();
        assert_matches!(err, PstConstructionError::ContainsSlots(..));

        // PolicyToTemplate
        let err: PstConstructionError = FromJsonError::PolicyToTemplate(
            crate::parser::err::parse_errors::ExpectedTemplate::new(),
        )
        .into();
        assert!(matches!(
            err,
            PstConstructionError::ExpectedTemplateWithSlots(..)
        ));

        // SlotsInConditionClause
        let err: PstConstructionError = FromJsonError::SlotsInConditionClause(
            crate::parser::err::parse_errors::SlotsInConditionClause {
                slot: ast::Slot {
                    id: ast::SlotId::resource(),
                    loc: None,
                },
                clause_type: "when",
            },
        )
        .into();
        assert_matches!(err, PstConstructionError::ContainsSlots(..));

        // MissingOperator
        let err: PstConstructionError = FromJsonError::MissingOperator.into();
        assert_matches!(err, PstConstructionError::InvalidExpression(..));

        // MultipleOperators
        let err: PstConstructionError = FromJsonError::MultipleOperators {
            ops: vec!["a".into(), "b".into()],
        }
        .into();
        assert_matches!(err, PstConstructionError::InvalidExpression(..));
    }

    #[test]
    fn from_expression_construction_error() {
        let err: PstConstructionError = ast::ExpressionConstructionError::DuplicateKey(
            ast::expression_construction_errors::DuplicateKeyError {
                key: "k".into(),
                context: "in record literal",
            },
        )
        .into();
        assert_matches!(err, PstConstructionError::DuplicateRecordKey(..));
    }

    #[test]
    fn from_extension_function_lookup_error() {
        use crate::extensions::ExtensionFunctionLookupError;
        let err: PstConstructionError = ExtensionFunctionLookupError::FuncDoesNotExist(
            crate::extensions::extension_function_lookup_errors::FuncDoesNotExistError {
                name: "bogus".parse().unwrap(),
                source_loc: None,
            },
        )
        .into();
        assert_matches!(err, PstConstructionError::UnknownFunction(..));
    }
}
