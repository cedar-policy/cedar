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

use crate::ast::{self, SlotId};
use crate::entities::JsonDeserializationError;
use crate::parser::err::ParseErrors;
use crate::parser::unescape;
use miette::Diagnostic;
use nonempty::NonEmpty;
use smol_str::SmolStr;
use thiserror::Error;

/// Errors arising while converting a policy from its JSON representation (aka EST) into an AST
#[derive(Debug, Diagnostic, Error)]
pub enum FromJsonError {
    /// Error while deserializing JSON
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonDeserializationError(#[from] JsonDeserializationError),
    /// Tried to convert an EST representing a template to an AST representing a static policy
    #[error("tried to convert JSON representing a template to a static policy: {0}")]
    #[diagnostic(transparent)]
    TemplateToPolicy(#[from] ast::UnexpectedSlotError),
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
    #[error("found template slot {slot} in a `{clausetype}` clause")]
    #[diagnostic(help("slots are currently unsupported in `{clausetype}` clauses"))]
    SlotsInConditionClause {
        /// Slot that was found in a when/unless clause
        slot: SlotId,
        /// Clause type, e.g. "when" or "unless"
        clausetype: &'static str,
    },
    /// EST contained the empty JSON object `{}` where a key (operator) was expected
    #[error("missing operator, found empty object")]
    MissingOperator,
    /// EST contained an object with multiple keys (operators) where a single operator was expected
    #[error("found multiple operators where one was expected: {ops:?}")]
    MultipleOperators {
        /// the multiple operators that were found where one was expected
        ops: Vec<SmolStr>,
    },
    /// At most one of the operands in `a * b * c * d * ...` can be a non-{constant int}
    #[error(
        "multiplication must be by a constant int: neither `{arg1}` nor `{arg2}` is a constant"
    )]
    MultiplicationByNonConstant {
        /// First non-constant argument
        arg1: ast::Expr,
        /// Second non-constant argument
        arg2: ast::Expr,
    },
    /// Error thrown while processing string escapes
    // show just the first error in the main error message, like in [`ParseErrors`]; see #326 and discussion on #477
    #[error("{}", .0.first())]
    UnescapeError(#[related] NonEmpty<unescape::UnescapeError>),
    /// Error reported when the entity type tested by an `is` expression cannot be parsed.
    #[error("invalid entity type: {0}")]
    #[diagnostic(transparent)]
    InvalidEntityType(ParseErrors),
}

/// Errors while instantiating a policy
#[derive(Debug, PartialEq, Diagnostic, Error)]
pub enum InstantiationError {
    /// Template contains this slot, but a value wasn't provided for it
    #[error("failed to instantiate template: no value provided for `{slot}`")]
    MissedSlot {
        /// Slot which didn't have a value provided for it
        slot: ast::SlotId,
    },
}
