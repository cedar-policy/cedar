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
    ast::{EntityType, EntityUID},
    entities::conformance::err::{EntitySchemaConformanceError, InvalidEnumEntityError},
    evaluator::EvaluationError,
    validator::{RequestValidationError, ValidationError},
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

/// Errors for TPE
#[derive(Debug, Error)]
pub enum TPEError {
    /// Error thrown when there is no matching request environment according to
    /// a schema
    #[error(transparent)]
    NoMatchingReqEnv(#[from] NoMatchingReqEnvError),
    /// Error thrown when TPE is applied to a non-static policy
    #[error(transparent)]
    NonstaticPolicy(#[from] NonstaticPolicyError),
    /// Error thrown when the typechecker fails to typecheck a policy
    #[error("Failed validation: {:#?}", .0)]
    Validation(Vec<ValidationError>),
}

/// Error thrown when there is no matching request environment according to a
/// schema
#[derive(Debug, Error)]
#[error("Can't find a matching request environment")]
pub struct NoMatchingReqEnvError;

/// Error thrown when TPE is applied to a non-static policy
#[derive(Debug, Error)]
#[error("Found a non-static policy")]
pub struct NonstaticPolicyError;

/// Error thrown when using a [`RequestBuilder`]
#[derive(Debug, Error)]
pub enum RequestBuilderError {
    /// Error thrown when the request cannot be validated
    #[error(transparent)]
    Validation(#[from] RequestValidationError),
    /// Error thrown when attempting to add a principal when one exists
    #[error(transparent)]
    ExistingPrincipal(#[from] ExistingPrincipalError),
    /// Error thrown when attempting to add a resource when one exists
    #[error(transparent)]
    ExistingResource(#[from] ExistingResourceError),
    /// Error thrown when attempting to add a context when one exists
    #[error("Context already exists")]
    ExistingContext,
    /// Error thrown when attempting to add a principal with an incorrect
    /// entity type
    #[error(transparent)]
    IncorrectPrincipalEntityType(#[from] IncorrectPrincipalEntityTypeError),
    /// Error thrown when attempting to add a resource with an incorrect
    /// entity type
    #[error(transparent)]
    IncorrectResourceEntityType(#[from] IncorrectResourceEntityTypeError),
    /// Error thrown when the principal candidate is invalid
    #[error("invalid principal candidate: {}", .0)]
    InvalidPrincipalCandidate(InvalidEnumEntityError),
    /// Error thrown when the resource candidate is invalid
    #[error("invalid resource candidate: {}", .0)]
    InvalidResourceCandidate(InvalidEnumEntityError),
    /// Error thrown when the context candidate is invalid
    #[error("context candidate doesn't validate: {}", .0)]
    IllTypedContextCandidate(RequestValidationError),
    /// Error thrown when the context candidate contains unknowns
    #[error("context candidate contains unknowns")]
    UnknownContextCandidate,
}

/// Error thrown when attempting to add a principal with an incorrect
/// entity type
#[derive(Debug, Error)]
#[error("Principal `{}` already exists", .principal)]
pub struct ExistingPrincipalError {
    pub(super) principal: EntityUID,
}

/// Error thrown when attempting to add a resource with an incorrect
/// entity type
#[derive(Debug, Error)]
#[error("Resource `{}` already exists", .resource)]
pub struct ExistingResourceError {
    pub(super) resource: EntityUID,
}

/// Error thrown when attempting to add a principal with an incorrect
/// entity type
#[derive(Debug, Error)]
#[error("Principal type `{}` is inconsistent with the partial request's `{}`", .ty, .expected)]
pub struct IncorrectPrincipalEntityTypeError {
    pub(super) ty: EntityType,
    pub(super) expected: EntityType,
}

/// Error thrown when attempting to add a resource with an incorrect
/// entity type
#[derive(Debug, Error)]
#[error("Resource type `{}` is inconsistent with the partial request's `{}`", .ty, .expected)]
pub struct IncorrectResourceEntityTypeError {
    pub(super) ty: EntityType,
    pub(super) expected: EntityType,
}
