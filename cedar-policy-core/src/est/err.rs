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

use crate::ast;
use crate::entities::json::err::JsonDeserializationError;
use crate::parser::err::{parse_errors, ParseErrors};
use crate::parser::unescape;
use miette::Diagnostic;
use nonempty::NonEmpty;
use smol_str::SmolStr;
use thiserror::Error;

/// Errors arising while converting a policy from its JSON representation (aka EST) into an AST
//
// This is NOT a publicly exported error type.
#[derive(Debug, Diagnostic, Error)]
pub enum FromJsonError {
    /// Error while deserializing JSON
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonDeserializationError(#[from] JsonDeserializationError),
    /// Tried to convert an EST representing a template to an AST representing a static policy
    #[error(transparent)]
    #[diagnostic(transparent)]
    TemplateToPolicy(#[from] parse_errors::ExpectedStaticPolicy),
    /// Tried to convert an EST representing a static policy to an AST representing a template
    #[error(transparent)]
    #[diagnostic(transparent)]
    PolicyToTemplate(#[from] parse_errors::ExpectedTemplate),
    /// Slot name was not valid for the position it was used in. (Currently, principal slots must
    /// be named `?principal`, and resource slots must be named `?resource`.)
    #[error("invalid slot name or slot used in wrong position")]
    #[diagnostic(help(
        "principal slots must be named `?principal` and resource slots must be named `?resource`"
    ))]
    InvalidSlotName,
    /// EST contained a template slot for `action`. This is not currently allowed
    #[error("slots are not allowed for actions")]
    ActionSlot,
    /// EST contained a template slot in policy condition
    #[error(transparent)]
    #[diagnostic(transparent)]
    SlotsNotInScopeInConditionClause(#[from] parse_errors::SlotsNotInScopeInConditionClause),
    /// EST contained the empty JSON object `{}` where a key (operator) was expected
    #[error("missing operator, found empty object")]
    MissingOperator,
    /// EST contained an object with multiple keys (operators) where a single operator was expected
    #[error("found multiple operators where one was expected: {ops:?}")]
    MultipleOperators {
        /// the multiple operators that were found where one was expected
        ops: Vec<SmolStr>,
    },
    /// Error thrown while processing string escapes
    // show just the first error in the main error message, like in [`ParseErrors`]; see #326 and discussion on #477
    #[error("{}", .0.first())]
    UnescapeError(#[related] NonEmpty<unescape::UnescapeError>),
    /// Error reported when the entity type tested by an `is` expression cannot be parsed.
    #[error("invalid entity type: {0}")]
    #[diagnostic(transparent)]
    InvalidEntityType(ParseErrors),
    /// Error reported when the extension function name is unknown. Note that
    /// unlike the Cedar policy format, the JSON format has no way to distinguish
    /// between function-style and method-style calls.
    #[error("invalid extension function: `{0}`")]
    UnknownExtensionFunction(ast::Name),
    /// Returned when an entity uid used as an action does not have the type `Action`
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidActionType(#[from] parse_errors::InvalidActionType),
    /// Returned when we have an error node in an AST - this is not supported
    #[cfg(feature = "tolerant-ast")]
    #[error("AST error node")]
    ASTErrorNode,
}

/// Errors arising while converting a policy set from its JSON representation (aka EST) into an AST
#[derive(Debug, Diagnostic, Error)]
pub enum PolicySetFromJsonError {
    /// Error reported when a policy set has duplicate ids
    #[error(transparent)]
    #[diagnostic(transparent)]
    PolicySet(#[from] ast::PolicySetError),
    /// Error reported when attempting to create a template-link
    #[error(transparent)]
    #[diagnostic(transparent)]
    Linking(#[from] ast::LinkingError),
    /// Error reported when converting an EST policy or template to an AST
    #[error(transparent)]
    #[diagnostic(transparent)]
    FromJsonError(#[from] FromJsonError),
}

/// Errors while linking a policy
#[derive(Debug, PartialEq, Eq, Diagnostic, Error)]
pub enum LinkingError {
    /// Template contains this slot, but a value wasn't provided for it
    #[error("failed to link template: no value provided for `{slot}`")]
    MissedSlot {
        /// Slot which didn't have a value provided for it
        slot: ast::SlotId,
    },
}

impl From<ast::UnexpectedSlotError> for FromJsonError {
    fn from(err: ast::UnexpectedSlotError) -> Self {
        Self::TemplateToPolicy(err.into())
    }
}
