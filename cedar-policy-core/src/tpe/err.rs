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

//! This module contains possible errors thrown by various components of the
//! type-aware partial evaluator.

use thiserror::Error;

use crate::{
    ast::EntityUID, entities::conformance::err::EntitySchemaConformanceError,
    evaluator::EvaluationError,
};

/// Error thrown when encountered an action
#[derive(Debug, Error)]
#[error("Unexpected action: `{}`", .action)]
pub struct UnexpectedActionError {
    pub(super) action: EntityUID,
}

/// Error thrown when deserializing a [`PartialEntity`]
#[derive(Debug, Error)]
pub enum JsonDeserializationError {
    /// Error thrown when deserializing concrete components
    #[error(transparent)]
    Concrete(#[from] crate::entities::json::err::JsonDeserializationError),
    /// Error thrown when encountered an action
    /// Actions are automatically inserted from a schema
    #[error(transparent)]
    UnexpectedAction(#[from] UnexpectedActionError),
    /// Error thrown when a restricted expression does not evaluate to a value
    #[error(transparent)]
    RestrictedExprEvaluation(#[from] EvaluationError),
}

/// Error thrown when validating a [`PartialEntity`]
#[derive(Debug, Error)]
pub enum EntityValidationError {
    /// Error thrown when validating concrete components
    #[error(transparent)]
    Concrete(#[from] EntitySchemaConformanceError),
    /// Error thrown when an action component is unknown
    #[error(transparent)]
    UnknownActionComponent(#[from] UnknownActionComponentError),
    /// Error thrown when an action's ancestors do not match the schema
    #[error(transparent)]
    MismatchedActionAncestors(#[from] MismatchedActionAncestorsError),
}

/// Error thrown when an action has unknown ancestors/attrs/tags
#[derive(Debug, Error)]
#[error("action `{}` has unknown ancestors/attrs/tags", .action)]
pub struct UnknownActionComponentError {
    pub(super) action: EntityUID,
}

/// Error thrown when an action's ancestors do not match the schema
#[derive(Debug, Error)]
#[error("action `{}`'s ancestors do not match the schema", .action)]
pub struct MismatchedActionAncestorsError {
    pub(super) action: EntityUID,
}

/// Error thrown when an ancestor of an ancestor is unknown
#[derive(Debug, Error)]
#[error("`{}`'s ancestor `{}` has unknown ancestors", .uid, .ancestor)]
pub struct AncestorValidationError {
    pub(crate) uid: EntityUID,
    pub(crate) ancestor: EntityUID,
}
