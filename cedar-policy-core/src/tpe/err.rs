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

use std::fmt::Display;

use smol_str::SmolStr;
use thiserror::Error;

use crate::{
    ast::{Eid, EntityType, EntityUID, PartialValueToValueError},
    entities::{
        conformance::err::{EntitySchemaConformanceError, InvalidEnumEntityError},
        err::Duplicate,
    },
    evaluator::EvaluationError,
    transitive_closure::TcError,
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
    /// Error when an expression is not supported by batched evaluation
    #[error(transparent)]
    ExprToResidualError(#[from] ExprToResidualError),
}

/// Residuals require fully typed expressions without
/// unknowns or parse errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExprToResidualError {
    /// Expression is missing type annotation
    #[error(transparent)]
    MissingTypeAnnotation(#[from] MissingTypeAnnotationError),
    /// Expression contains a slot which is not supported in residuals
    #[error(transparent)]
    SlotNotSupported(#[from] SlotNotSupportedError),
    /// Expression contains an unknown which is not supported in residuals
    #[error(transparent)]
    UnknownNotSupported(#[from] UnknownNotSupportedError),
    /// Expression contains an error which is not supported in residuals
    #[error(transparent)]
    ErrorNotSupported(#[from] ErrorNotSupportedError),
}

/// Error thrown when expression is missing type annotation
#[derive(Debug, Error)]
#[error("Expression is missing type annotation")]
pub struct MissingTypeAnnotationError;

/// Error thrown when expression contains a slot which is not supported in residuals
#[derive(Debug, Error)]
#[error("Expression contains a slot which is not supported in residuals")]
pub struct SlotNotSupportedError;

/// Error thrown when expression contains an unknown which is not supported in residuals
#[derive(Debug, Error)]
#[error("Expression contains an unknown which is not supported in residuals")]
pub struct UnknownNotSupportedError;

/// Error thrown when expression contains an error which is not supported in residuals
#[derive(Debug, Error)]
#[error("Expression contains an error which is not supported in residuals")]
pub struct ErrorNotSupportedError;

/// Error when a request was expected to be concrete
#[derive(Debug, Error)]
#[error("Found a partial request when a concrete request was expected")]
pub struct PartialRequestError {}

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

/// Error thrown when constructing [`PartialEntities`]
#[derive(Debug, Error)]
pub enum EntitiesError {
    /// Error thrown when validating concrete components
    #[error(transparent)]
    Deserialization(#[from] JsonDeserializationError),
    /// Error thrown when validating a [`PartialEntity`]
    #[error(transparent)]
    Validation(#[from] EntityValidationError),
    /// Error thrown when validating the ancestors of a [`PartialEntity`]
    #[error(transparent)]
    AncestorValidation(#[from] AncestorValidationError),
    /// Error thrown when computing TC
    #[error(transparent)]
    TCComputation(#[from] TcError<EntityUID>),
    /// Error constructing the Entities collection due to encountering two
    /// different entities with the same Entity UID
    #[error(transparent)]
    Duplicate(#[from] Duplicate),
    /// Errors encountered when converting `PartialValue` to `Value`
    #[error(transparent)]
    PartialValueToValue(#[from] PartialValueToValueError),
}

/// Error thrown when checking the consistency between [`PartialEntities`] and
/// [`Entities`]
#[derive(Debug, Error)]
pub enum EntitiesConsistencyError {
    /// Error thrown when there is an entity missing in the concrete entities
    #[error(transparent)]
    MissingEntity(#[from] MissingEntityError),
    /// Error thrown when concrete entities contain unknown entities
    #[error(transparent)]
    UnknownEntity(#[from] UnknownEntityError),
    /// Error thrown when a concrete entity and a partial entity are
    /// inconsistent
    #[error(transparent)]
    InconsistentEntity(#[from] EntityConsistencyError),
}

/// Error thrown when checking the consistency between [`PartialEntity`] and
/// [`Entity`]
#[derive(Debug, Error)]
pub enum EntityConsistencyError {
    /// Error thrown when the concrete entity contains unknown attribute
    #[error(transparent)]
    UnknownAttribute(#[from] UnknownAttributeError),
    /// Error thrown when attributes mismatch
    #[error(transparent)]
    MismatchedAttribute(#[from] MismatchedAttributeError),
    /// Error thrown when ancestors do not match
    #[error(transparent)]
    MismatchedAncestor(#[from] MismatchedAncestorError),
    /// Error thrown when the concrete entity contains unknown tag
    #[error(transparent)]
    UnknownTag(#[from] UnknownTagError),
    /// Error thrown when tags mismatch
    #[error(transparent)]
    MismatchedTag(#[from] MismatchedTagError),
}

/// Error thrown when the concrete entity contains unknown attribute
#[derive(Debug, Error)]
#[error("Concrete entity `{uid}` contains unknown attribute `{attr}`")]
pub struct UnknownAttributeError {
    pub(super) uid: EntityUID,
    pub(super) attr: SmolStr,
}

/// Error thrown when attributes mismatch
#[derive(Debug, Error)]
#[error("Entity `{uid}`'s attributes do not match")]
pub struct MismatchedAttributeError {
    pub(super) uid: EntityUID,
}

/// Error thrown when the concrete entity contains unknown tag
#[derive(Debug, Error)]
#[error("Concrete entity `{uid}` contains unknown tag `{tag}`")]
pub struct UnknownTagError {
    pub(super) uid: EntityUID,
    pub(super) tag: SmolStr,
}

/// Error thrown when tags mismatch
#[derive(Debug, Error)]
#[error("Entity `{uid}`'s tags do not match")]
pub struct MismatchedTagError {
    pub(super) uid: EntityUID,
}

/// Error thrown when ancestors do not match
#[derive(Debug, Error)]
#[error("Entity `{uid}`'s ancestors do not match")]
pub struct MismatchedAncestorError {
    pub(super) uid: EntityUID,
}

/// Error thrown when when there is an entity missing in the concrete entities
#[derive(Debug, Error)]
#[error("Concrete entities does not include `{uid}`")]
pub struct MissingEntityError {
    pub(super) uid: EntityUID,
}

/// Error thrown when concrete entities contain unknown entities
#[derive(Debug, Error)]
#[error("Concrete entities contains unknown entity `{uid}`")]
pub struct UnknownEntityError {
    pub(super) uid: EntityUID,
}

/// Error thrown when some requested entities were not loaded
#[derive(Debug, Error)]
pub struct MissingEntitiesError {
    pub(super) missing_entities: Vec<EntityUID>,
}

impl MissingEntitiesError {
    /// Construct a new [`MissingEntitiesError`]
    pub fn new(missing_entities: Vec<EntityUID>) -> Self {
        Self { missing_entities }
    }
}

impl Display for MissingEntitiesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Failed to load entities: {}",
            self.missing_entities
                .iter()
                .map(|uid| uid.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// Error thrown when a [`PartialRequest`] is consistent with a [`Request`]
#[derive(Debug, Error)]
pub enum RequestConsistencyError {
    /// Error thrown when the concrete principal is unknown
    #[error("Concrete principal is unknown")]
    UnknownPrincipal,
    /// Error thrown when the concrete resource is unknown
    #[error("Concrete resource is unknown")]
    UnknownResource,
    /// Error thrown when the concrete action is unknown
    #[error("Concrete action is unknown")]
    UnknownAction,
    /// Error thrown when the concrete context is unknown
    #[error("Concrete context is unknown")]
    UnknownContext,
    /// Error thrown when principal types are inconsistent
    #[error(transparent)]
    InconsistentPrincipalType(#[from] InconsistentPrincipalTypeError),
    /// Error thrown when principal eids are inconsistent
    #[error(transparent)]
    InconsistentPrincipalEid(#[from] InconsistentPrincipalEidError),
    /// Error thrown when resource types are inconsistent
    #[error(transparent)]
    InconsistentResourceType(#[from] InconsistentResourceTypeError),
    /// Error thrown when resource eids are inconsistent
    #[error(transparent)]
    InconsistentResourceEid(#[from] InconsistentResourceEidError),
    /// Error thrown when actions are inconsistent
    #[error(transparent)]
    InconsistentAction(#[from] InconsistentActionError),
    /// Error thrown when contexts are inconsistent
    #[error("Contexts are inconsistent")]
    InconsistentContext,
    /// Error thrown when the concrete context contains unknowns
    #[error("Concrete context contains unknowns")]
    ConcreteContextContainsUnknowns,
}

/// Error thrown when principal types are inconsistent
#[derive(Debug, Error)]
#[error("Principal types `{partial}` and `{concrete}` do not match")]
pub struct InconsistentPrincipalTypeError {
    pub(super) partial: EntityType,
    pub(super) concrete: EntityType,
}

/// Error thrown when principal eids are inconsistent
#[derive(Debug, Error)]
#[error("Principal eid `{}` and `{}` do not match", .partial.escaped(), .concrete.escaped())]
pub struct InconsistentPrincipalEidError {
    pub(super) partial: Eid,
    pub(super) concrete: Eid,
}

/// Error thrown when resource types are inconsistent
#[derive(Debug, Error)]
#[error("Resource types `{partial}` and `{concrete}` do not match")]
pub struct InconsistentResourceTypeError {
    pub(super) partial: EntityType,
    pub(super) concrete: EntityType,
}

/// Error thrown when resource eids are inconsistent
#[derive(Debug, Error)]
#[error("Resource eid `{}` and `{}` do not match", .partial.escaped(), .concrete.escaped())]
pub struct InconsistentResourceEidError {
    pub(super) partial: Eid,
    pub(super) concrete: Eid,
}

/// Error thrown when actions are inconsistent
#[derive(Debug, Error)]
#[error("Actions `{}` and `{}` do not match", .partial, .concrete)]
pub struct InconsistentActionError {
    pub(super) partial: EntityUID,
    pub(super) concrete: EntityUID,
}

/// Error thrown during reauthorization
#[derive(Debug, Error)]
pub enum ReauthorizationError {
    /// Error thrown when request validation fails
    #[error(transparent)]
    RequestValidation(#[from] RequestValidationError),
    /// Error thrown when entity validation fails
    #[error(transparent)]
    EntityValidation(#[from] EntitySchemaConformanceError),
    /// Error thrown when entities and partial entities are inconsistent
    #[error(transparent)]
    EntitiesConsistentcy(#[from] EntitiesConsistencyError),
    /// Error thrown when request and partial request are inconsistent
    #[error(transparent)]
    RequestConsistentcy(#[from] RequestConsistencyError),
}
