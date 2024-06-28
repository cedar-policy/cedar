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

use crate::ast::*;
use crate::parser::Loc;
use miette::Diagnostic;
use nonempty::{nonempty, NonEmpty};
use smol_str::SmolStr;
use std::sync::Arc;
use thiserror::Error;

// How many attrs will we store in an error before cutting off for performance reason
const TOO_MANY_ATTRS: usize = 5;

/// Enumeration of the possible errors that can occur during evaluation
//
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution when
// adding public methods.
#[derive(Debug, PartialEq, Eq, Clone, Diagnostic, Error)]
pub enum EvaluationError {
    /// Tried to lookup an entity UID, but it didn't exist in the provided
    /// entities
    #[error(transparent)]
    #[diagnostic(transparent)]
    EntityDoesNotExist(#[from] evaluation_errors::EntityDoesNotExistError),

    /// Tried to get an attribute, but the specified entity didn't
    /// have that attribute
    #[error(transparent)]
    #[diagnostic(transparent)]
    EntityAttrDoesNotExist(#[from] evaluation_errors::EntityAttrDoesNotExistError),

    /// Tried to get an attribute of a (non-entity) record, but that record
    /// didn't have that attribute
    #[error(transparent)]
    #[diagnostic(transparent)]
    RecordAttrDoesNotExist(#[from] evaluation_errors::RecordAttrDoesNotExistError),

    /// An error occurred when looking up an extension function
    #[error(transparent)]
    #[diagnostic(transparent)]
    FailedExtensionFunctionLookup(#[from] crate::extensions::ExtensionFunctionLookupError),

    /// Tried to evaluate an operation on values with incorrect types for that
    /// operation
    #[error(transparent)]
    #[diagnostic(transparent)]
    TypeError(#[from] evaluation_errors::TypeError),

    /// Wrong number of arguments provided to an extension function
    #[error(transparent)]
    #[diagnostic(transparent)]
    WrongNumArguments(#[from] evaluation_errors::WrongNumArgumentsError),

    /// Overflow during an integer operation
    #[error(transparent)]
    #[diagnostic(transparent)]
    IntegerOverflow(#[from] evaluation_errors::IntegerOverflowError),

    /// Not all template slots were linked
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnlinkedSlot(#[from] evaluation_errors::UnlinkedSlotError),

    /// Evaluation error thrown by an extension function
    #[error(transparent)]
    #[diagnostic(transparent)]
    FailedExtensionFunctionExecution(#[from] evaluation_errors::ExtensionFunctionExecutionError),

    /// This error is raised if an expression contains unknowns and cannot be
    /// reduced to a [`Value`]. In order to return partial results, use the
    /// partial evaluation APIs instead.
    #[error(transparent)]
    #[diagnostic(transparent)]
    NonValue(#[from] evaluation_errors::NonValueError),

    /// Maximum recursion limit reached for expression evaluation
    #[error(transparent)]
    #[diagnostic(transparent)]
    RecursionLimit(#[from] evaluation_errors::RecursionLimitError),
}

impl EvaluationError {
    /// Extract the source location of the error, if one is attached
    pub(crate) fn source_loc(&self) -> Option<&Loc> {
        match self {
            Self::EntityDoesNotExist(e) => e.source_loc.as_ref(),
            Self::EntityAttrDoesNotExist(e) => e.source_loc.as_ref(),
            Self::RecordAttrDoesNotExist(e) => e.source_loc.as_ref(),
            Self::FailedExtensionFunctionLookup(e) => e.source_loc(),
            Self::TypeError(e) => e.source_loc.as_ref(),
            Self::WrongNumArguments(e) => e.source_loc.as_ref(),
            Self::IntegerOverflow(e) => e.source_loc(),
            Self::UnlinkedSlot(e) => e.source_loc.as_ref(),
            Self::FailedExtensionFunctionExecution(e) => e.source_loc.as_ref(),
            Self::NonValue(e) => e.source_loc.as_ref(),
            Self::RecursionLimit(e) => e.source_loc.as_ref(),
        }
    }

    /// Return the `EvaluationError`, but with the new `source_loc` (or `None`).
    pub(crate) fn with_maybe_source_loc(self, source_loc: Option<Loc>) -> Self {
        match self {
            Self::EntityDoesNotExist(e) => {
                Self::EntityDoesNotExist(evaluation_errors::EntityDoesNotExistError {
                    source_loc,
                    ..e
                })
            }
            Self::EntityAttrDoesNotExist(e) => {
                Self::EntityAttrDoesNotExist(evaluation_errors::EntityAttrDoesNotExistError {
                    source_loc,
                    ..e
                })
            }
            Self::RecordAttrDoesNotExist(e) => {
                Self::RecordAttrDoesNotExist(evaluation_errors::RecordAttrDoesNotExistError {
                    source_loc,
                    ..e
                })
            }
            Self::FailedExtensionFunctionLookup(e) => {
                Self::FailedExtensionFunctionLookup(e.with_maybe_source_loc(source_loc))
            }
            Self::TypeError(e) => Self::TypeError(evaluation_errors::TypeError { source_loc, ..e }),
            Self::WrongNumArguments(e) => {
                Self::WrongNumArguments(evaluation_errors::WrongNumArgumentsError {
                    source_loc,
                    ..e
                })
            }
            Self::IntegerOverflow(e) => Self::IntegerOverflow(e.with_maybe_source_loc(source_loc)),
            Self::UnlinkedSlot(e) => {
                Self::UnlinkedSlot(evaluation_errors::UnlinkedSlotError { source_loc, ..e })
            }
            Self::FailedExtensionFunctionExecution(e) => Self::FailedExtensionFunctionExecution(
                evaluation_errors::ExtensionFunctionExecutionError { source_loc, ..e },
            ),
            Self::NonValue(e) => {
                Self::NonValue(evaluation_errors::NonValueError { source_loc, ..e })
            }
            Self::RecursionLimit(e) => {
                Self::RecursionLimit(evaluation_errors::RecursionLimitError { source_loc, ..e })
            }
        }
    }

    /// Construct a [`EntityDoesNotExist`] error
    pub(crate) fn entity_does_not_exist(uid: Arc<EntityUID>, source_loc: Option<Loc>) -> Self {
        evaluation_errors::EntityDoesNotExistError { uid, source_loc }.into()
    }

    /// Construct a [`EntityAttrDoesNotExist`] error
    pub(crate) fn entity_attr_does_not_exist<'a>(
        entity: Arc<EntityUID>,
        attr: SmolStr,
        available_attrs: impl IntoIterator<Item = &'a SmolStr>,
        total_attrs: usize,
        source_loc: Option<Loc>,
    ) -> Self {
        evaluation_errors::EntityAttrDoesNotExistError {
            entity,
            attr,
            available_attrs: available_attrs
                .into_iter()
                .take(TOO_MANY_ATTRS)
                .cloned()
                .collect::<Vec<_>>(),
            total_attrs,
            source_loc,
        }
        .into()
    }

    /// Construct a [`RecordAttrDoesNotExist`] error
    pub(crate) fn record_attr_does_not_exist<'a>(
        attr: SmolStr,
        available_attrs: impl IntoIterator<Item = &'a SmolStr>,
        total_attrs: usize,
        source_loc: Option<Loc>,
    ) -> Self {
        evaluation_errors::RecordAttrDoesNotExistError {
            attr,
            available_attrs: available_attrs
                .into_iter()
                .take(TOO_MANY_ATTRS)
                .cloned()
                .collect(),
            total_attrs,
            source_loc,
        }
        .into()
    }

    /// Construct a [`TypeError`] error
    pub(crate) fn type_error(expected: NonEmpty<Type>, actual: &Value) -> Self {
        evaluation_errors::TypeError {
            expected,
            actual: actual.type_of(),
            advice: None,
            source_loc: actual.source_loc().cloned(),
        }
        .into()
    }

    pub(crate) fn type_error_single(expected: Type, actual: &Value) -> Self {
        Self::type_error(nonempty![expected], actual)
    }

    /// Construct a [`TypeError`] error with the advice field set
    pub(crate) fn type_error_with_advice(
        expected: NonEmpty<Type>,
        actual: &Value,
        advice: String,
    ) -> Self {
        evaluation_errors::TypeError {
            expected,
            actual: actual.type_of(),
            advice: Some(advice),
            source_loc: actual.source_loc().cloned(),
        }
        .into()
    }

    pub(crate) fn type_error_with_advice_single(
        expected: Type,
        actual: &Value,
        advice: String,
    ) -> Self {
        Self::type_error_with_advice(nonempty![expected], actual, advice)
    }

    /// Construct a [`WrongNumArguments`] error
    pub(crate) fn wrong_num_arguments(
        function_name: Name,
        expected: usize,
        actual: usize,
        source_loc: Option<Loc>,
    ) -> Self {
        evaluation_errors::WrongNumArgumentsError {
            function_name,
            expected,
            actual,
            source_loc,
        }
        .into()
    }

    /// Construct a [`UnlinkedSlot`] error
    pub(crate) fn unlinked_slot(slot: SlotId, source_loc: Option<Loc>) -> Self {
        evaluation_errors::UnlinkedSlotError { slot, source_loc }.into()
    }

    /// Construct a [`FailedExtensionFunctionApplication`] error
    pub(crate) fn failed_extension_function_application(
        extension_name: Name,
        msg: String,
        source_loc: Option<Loc>,
    ) -> Self {
        evaluation_errors::ExtensionFunctionExecutionError {
            extension_name,
            msg,
            source_loc,
        }
        .into()
    }

    /// Construct a [`NonValue`] error
    pub(crate) fn non_value(expr: Expr) -> Self {
        let source_loc = expr.source_loc().cloned();
        evaluation_errors::NonValueError { expr, source_loc }.into()
    }

    /// Construct a [`RecursionLimit`] error
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn recursion_limit(source_loc: Option<Loc>) -> Self {
        evaluation_errors::RecursionLimitError { source_loc }.into()
    }
}

/// Error subtypes for [`EvaluationError`]
pub mod evaluation_errors {
    use crate::ast::{BinaryOp, EntityUID, Expr, Name, SlotId, Type, UnaryOp, Value};
    use crate::parser::Loc;
    use itertools::Itertools;
    use miette::Diagnostic;
    use nonempty::NonEmpty;
    use smol_str::SmolStr;
    use std::sync::Arc;
    use thiserror::Error;

    /// Tried to lookup an entity UID, but it didn't exist in the provided entities
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error("entity `{uid}` does not exist")]
    pub struct EntityDoesNotExistError {
        /// Entity UID which didn't exist in the provided entities
        pub(crate) uid: Arc<EntityUID>,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    // This and similar `Diagnostic` impls could just be derived with
    //
    // #[source_code]
    // #[label]
    // source_loc: Option<Loc>,
    //
    // if [miette#377](https://github.com/zkat/miette/issues/377) gets fixed.
    // Or, we could have separate fields for source code and label instead of
    // combining them into `Loc`, which would work around the issue.
    impl Diagnostic for EntityDoesNotExistError {
        impl_diagnostic_from_source_loc_field!();

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
    }

    /// Tried to get an attribute, but the specified entity didn't have that
    /// attribute
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error("`{entity}` does not have the attribute `{attr}`")]
    pub struct EntityAttrDoesNotExistError {
        /// Entity that didn't have the attribute
        pub(crate) entity: Arc<EntityUID>,
        /// Name of the attribute it didn't have
        pub(crate) attr: SmolStr,
        /// (First five) Available attributes on the entity
        pub(crate) available_attrs: Vec<SmolStr>,
        /// Total number of attributes on the entity
        pub(crate) total_attrs: usize,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl Diagnostic for EntityAttrDoesNotExistError {
        impl_diagnostic_from_source_loc_field!();

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            if self.available_attrs.is_empty() {
                Some(Box::new("entity does not have any attributes"))
            } else if self.available_attrs.len() == self.total_attrs {
                Some(Box::new(format!(
                    "Available attributes: {:?}",
                    self.available_attrs
                )))
            } else {
                Some(Box::new(format!(
                    "available attributes: [{}, ... ({} more attributes) ]",
                    self.available_attrs.iter().join(","),
                    self.total_attrs - self.available_attrs.len()
                )))
            }
        }

        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
    }

    /// Tried to get an attribute of a (non-entity) record, but that record didn't
    /// have that attribute
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error("record does not have the attribute `{attr}`")]
    pub struct RecordAttrDoesNotExistError {
        /// Name of the attribute we tried to access
        pub(crate) attr: SmolStr,
        /// (First five) Available attributes on the record
        pub(crate) available_attrs: Vec<SmolStr>,
        /// The total number of attrs this record has
        pub(crate) total_attrs: usize,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl Diagnostic for RecordAttrDoesNotExistError {
        impl_diagnostic_from_source_loc_field!();

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            if self.available_attrs.is_empty() {
                Some(Box::new("record does not have any attributes"))
            } else if self.available_attrs.len() == self.total_attrs {
                Some(Box::new(format!(
                    "available attributes: {:?}",
                    self.available_attrs
                )))
            } else {
                Some(Box::new(format!(
                    "available attributes: [{}, ... ({} more attributes) ]",
                    self.available_attrs.iter().join(","),
                    self.total_attrs - self.available_attrs.len()
                )))
            }
        }
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
    }

    /// Tried to evaluate an operation on values with incorrect types for that
    /// operation
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    pub struct TypeError {
        /// Expected one of these types
        pub(crate) expected: NonEmpty<Type>,
        /// Encountered this type instead
        pub(crate) actual: Type,
        /// Optional advice for how to fix this error
        pub(crate) advice: Option<String>,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl Diagnostic for TypeError {
        impl_diagnostic_from_source_loc_field!();

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            self.advice.as_ref().map(|advice| Box::new(advice) as _)
        }
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
    }

    impl std::fmt::Display for TypeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if self.expected.len() == 1 {
                write!(
                    f,
                    "type error: expected {}, got {}",
                    self.expected.first(),
                    self.actual
                )
            } else {
                write!(
                    f,
                    "type error: expected one of [{}], got {}",
                    self.expected.iter().join(", "),
                    self.actual
                )
            }
        }
    }

    /// Wrong number of arguments provided to an extension function
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error("wrong number of arguments provided to extension function `{function_name}`: expected {expected}, got {actual}")]
    pub struct WrongNumArgumentsError {
        /// arguments to this function
        pub(crate) function_name: Name,
        /// expected number of arguments
        pub(crate) expected: usize,
        /// actual number of arguments
        pub(crate) actual: usize,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl Diagnostic for WrongNumArgumentsError {
        impl_diagnostic_from_source_loc_field!();

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
    }

    /// Overflow during an integer operation
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Diagnostic, Error)]
    pub enum IntegerOverflowError {
        /// Overflow during a binary operation
        #[error(transparent)]
        #[diagnostic(transparent)]
        BinaryOp(#[from] BinaryOpOverflowError),

        /// Overflow during a unary operation
        #[error(transparent)]
        #[diagnostic(transparent)]
        UnaryOp(#[from] UnaryOpOverflowError),
    }

    impl IntegerOverflowError {
        pub(crate) fn source_loc(&self) -> Option<&Loc> {
            match self {
                Self::BinaryOp(e) => e.source_loc.as_ref(),
                Self::UnaryOp(e) => e.source_loc.as_ref(),
            }
        }

        pub(crate) fn with_maybe_source_loc(self, source_loc: Option<Loc>) -> Self {
            match self {
                Self::BinaryOp(e) => Self::BinaryOp(BinaryOpOverflowError { source_loc, ..e }),
                Self::UnaryOp(e) => Self::UnaryOp(UnaryOpOverflowError { source_loc, ..e }),
            }
        }
    }

    /// Overflow during a binary operation
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error("integer overflow while attempting to {} the values `{arg1}` and `{arg2}`", match .op { BinaryOp::Add => "add", BinaryOp::Sub => "subtract", BinaryOp::Mul => "multiply", _ => "perform an operation on" })]
    pub struct BinaryOpOverflowError {
        /// overflow while evaluating this operator
        pub(crate) op: BinaryOp,
        /// first argument to that operator
        pub(crate) arg1: Value,
        /// second argument to that operator
        pub(crate) arg2: Value,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl Diagnostic for BinaryOpOverflowError {
        impl_diagnostic_from_source_loc_field!();

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
    }

    /// Overflow during a unary operation
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error("integer overflow while attempting to {} the value `{arg}`", match .op { UnaryOp::Neg => "negate", _ => "perform an operation on" })]
    pub struct UnaryOpOverflowError {
        /// overflow while evaluating this operator
        pub(crate) op: UnaryOp,
        /// argument to that operator
        pub(crate) arg: Value,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl Diagnostic for UnaryOpOverflowError {
        impl_diagnostic_from_source_loc_field!();

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
    }

    /// Not all template slots were linked
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error("template slot `{slot}` was not linked")]
    pub struct UnlinkedSlotError {
        /// Slot which was not linked
        pub(crate) slot: SlotId,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl Diagnostic for UnlinkedSlotError {
        impl_diagnostic_from_source_loc_field!();

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
    }

    /// Evaluation error thrown by an extension function
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error("error while evaluating `{extension_name}` extension function: {msg}")]
    pub struct ExtensionFunctionExecutionError {
        /// Name of the extension throwing the error
        pub(crate) extension_name: Name,
        /// Error message from the extension
        pub(crate) msg: String,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl Diagnostic for ExtensionFunctionExecutionError {
        impl_diagnostic_from_source_loc_field!();

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
    }

    impl ExtensionFunctionExecutionError {
        /// Get the name of the extension that threw this error
        pub fn extension_name(&self) -> String {
            self.extension_name.to_string()
        }
    }

    /// This error is raised if an expression contains unknowns and cannot be
    /// reduced to a [`Value`]. In order to return partial results, use the
    /// partial evaluation APIs instead.
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error("the expression contains unknown(s): `{expr}`")]
    pub struct NonValueError {
        /// Expression that contained unknown(s)
        pub(crate) expr: Expr,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl Diagnostic for NonValueError {
        impl_diagnostic_from_source_loc_field!();

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            Some(Box::new("consider using the partial evaluation APIs"))
        }
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
    }

    /// Maximum recursion limit reached for expression evaluation
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error("recursion limit reached")]
    pub struct RecursionLimitError {
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl Diagnostic for RecursionLimitError {
        impl_diagnostic_from_source_loc_field!();

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
    }
}

/// Type alias for convenience
pub type Result<T> = std::result::Result<T, EvaluationError>;
