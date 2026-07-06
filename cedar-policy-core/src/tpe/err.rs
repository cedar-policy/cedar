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

use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

use crate::{
    ast::{Eid, EntityType, EntityUID, PartialValueToValueError},
    entities::{conformance::err::EntitySchemaConformanceError, err::Duplicate},
    evaluator::{evaluation_errors::UnlinkedSlotError, EvaluationError},
    transitive_closure::TcError,
    validator::{RequestValidationError, ValidationError},
};

/// Error thrown when encountered an action
#[derive(Debug, Error, Diagnostic)]
#[error("Unexpected action: `{}`", .action)]
pub struct UnexpectedActionError {
    pub(super) action: EntityUID,
}

/// Error thrown when deserializing a [`crate::tpe::entities::PartialEntity`]
#[derive(Debug, Error, Diagnostic)]
pub enum JsonDeserializationError {
    /// Error thrown when deserializing concrete components
    #[error(transparent)]
    #[diagnostic(transparent)]
    Concrete(#[from] crate::entities::json::err::JsonDeserializationError),
    /// Error thrown when encountered an action
    /// Actions are automatically inserted from a schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnexpectedAction(#[from] UnexpectedActionError),
    /// Error thrown when a restricted expression does not evaluate to a value
    #[error(transparent)]
    #[diagnostic(transparent)]
    RestrictedExprEvaluation(#[from] EvaluationError),
}

/// Error thrown when validating a [`crate::tpe::entities::PartialEntity`]
#[derive(Debug, Error, Diagnostic)]
pub enum EntityValidationError {
    /// Error thrown when validating concrete components
    #[error(transparent)]
    #[diagnostic(transparent)]
    Concrete(#[from] EntitySchemaConformanceError),
    /// Error thrown when an action component is unknown
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnknownActionComponent(#[from] UnknownActionComponentError),
    /// Error thrown when an action's ancestors do not match the schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    MismatchedActionAncestors(#[from] MismatchedActionAncestorsError),
}

/// Error thrown when an action has unknown ancestors/attrs/tags
#[derive(Debug, Error, Diagnostic)]
#[error("action `{}` has unknown ancestors/attrs/tags", .action)]
pub struct UnknownActionComponentError {
    pub(super) action: EntityUID,
}

/// Error thrown when an action's ancestors do not match the schema
#[derive(Debug, Error, Diagnostic)]
#[error("action `{}`'s ancestors do not match the schema", .action)]
pub struct MismatchedActionAncestorsError {
    pub(super) action: EntityUID,
}

/// Error thrown when an ancestor of an ancestor is unknown
#[derive(Debug, Error, Diagnostic)]
#[error("ancestor `{ancestor}` of `{uid}` has unknown ancestors")]
#[diagnostic(help(
    "an entity with known ancestors cannot have an ancestor whose own ancestors are unknown"
))]
pub struct AncestorValidationError {
    pub(crate) uid: EntityUID,
    pub(crate) ancestor: EntityUID,
}

/// Errors for TPE
#[derive(Debug, Error, Diagnostic)]
pub enum TpeError {
    /// Error thrown when there is no matching request environment according to
    /// a schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    NoMatchingReqEnv(#[from] NoMatchingReqEnvError),
    /// Error thrown when the policy does not typecheck against the schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    Validation(#[from] PolicyValidationError),
    /// Error when an expression is not supported by batched evaluation
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExprToResidualError(#[from] ExprToResidualError),
}

/// Error thrown when a policy fails to typecheck against the schema during
/// type-aware partial evaluation
#[derive(Debug, Error)]
#[error("policy failed to validate against the schema")]
pub struct PolicyValidationError {
    pub(super) errors: Vec<ValidationError>,
}

impl PolicyValidationError {
    /// Construct a new [`PolicyValidationError`] from the validation errors
    /// that were encountered
    pub(crate) fn new(errors: Vec<ValidationError>) -> Self {
        Self { errors }
    }

    /// The underlying validation errors
    pub fn errors(&self) -> impl Iterator<Item = &ValidationError> {
        self.errors.iter()
    }
}

impl Diagnostic for PolicyValidationError {
    fn related(&self) -> Option<Box<dyn Iterator<Item = &dyn Diagnostic> + '_>> {
        Some(Box::new(self.errors.iter().map(|e| e as &dyn Diagnostic)))
    }
}

/// Residuals require fully typed expressions without
/// unknowns or parse errors.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum ExprToResidualError {
    /// Expression is missing type annotation
    #[error(transparent)]
    #[diagnostic(transparent)]
    MissingTypeAnnotation(#[from] MissingTypeAnnotationError),
    /// Expression contains a slot which is not supported in residuals
    #[error(transparent)]
    UnlinkedSlotError(#[from] UnlinkedSlotError),
    /// Expression contains an unknown which is not supported in residuals
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnknownNotSupported(#[from] UnknownNotSupportedError),
    /// Expression contains an error which is not supported in residuals
    #[error(transparent)]
    #[diagnostic(transparent)]
    ErrorNotSupported(#[from] ErrorNotSupportedError),
}

/// Error thrown when expression is missing type annotation
#[derive(Debug, Error, Diagnostic)]
#[error("expression is missing a type annotation")]
#[diagnostic(help(
    "expressions must be typechecked by the policy validator before partial evaluation"
))]
pub struct MissingTypeAnnotationError;

/// Error thrown when expression contains an unknown which is not supported in residuals
#[derive(Debug, Error, Diagnostic)]
#[error("expression contains an unknown, which is not supported in residuals")]
pub struct UnknownNotSupportedError;

/// Error thrown when expression contains an error which is not supported in residuals
#[derive(Debug, Error, Diagnostic)]
#[error("expression contains an error node, which is not supported in residuals")]
pub struct ErrorNotSupportedError;

/// Error when a request was expected to be concrete
#[derive(Debug, Error, Diagnostic)]
#[error("expected a concrete request, but found a partial request")]
pub struct PartialRequestError {}

/// Error thrown when there is no matching request environment according to a
/// schema
#[derive(Debug, Error, Diagnostic)]
#[error("no request environment in the schema matches the given request")]
pub struct NoMatchingReqEnvError;

/// Error thrown when using a [`crate::tpe::request::RequestBuilder`]
#[derive(Debug, Error, Diagnostic)]
pub enum RequestBuilderError {
    /// Error thrown when the request cannot be validated
    #[error(transparent)]
    #[diagnostic(transparent)]
    Validation(#[from] RequestValidationError),
    /// Error thrown when attempting to add a principal when one exists
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExistingPrincipal(#[from] ExistingPrincipalError),
    /// Error thrown when attempting to add a resource when one exists
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExistingResource(#[from] ExistingResourceError),
    /// Error thrown when attempting to add a context when one exists
    #[error("a context has already been set on this request")]
    ExistingContext,
    /// Error thrown when attempting to add a principal with an incorrect
    /// entity type
    #[error(transparent)]
    #[diagnostic(transparent)]
    IncorrectPrincipalEntityType(#[from] IncorrectPrincipalEntityTypeError),
    /// Error thrown when attempting to add a resource with an incorrect
    /// entity type
    #[error(transparent)]
    #[diagnostic(transparent)]
    IncorrectResourceEntityType(#[from] IncorrectResourceEntityTypeError),
    /// Error thrown when the context candidate contains unknowns
    #[error("context candidate contains unknowns")]
    UnknownContextCandidate,
}

/// Error thrown when attempting to add a principal when one already exists
#[derive(Debug, Error, Diagnostic)]
#[error("a principal (`{principal}`) has already been set on this request")]
pub struct ExistingPrincipalError {
    pub(super) principal: EntityUID,
}

/// Error thrown when attempting to add a resource when one already exists
#[derive(Debug, Error, Diagnostic)]
#[error("a resource (`{resource}`) has already been set on this request")]
pub struct ExistingResourceError {
    pub(super) resource: EntityUID,
}

/// Error thrown when attempting to add a principal with an incorrect
/// entity type
#[derive(Debug, Error, Diagnostic)]
#[error("principal type `{ty}` does not match the partial request's principal type `{expected}`")]
pub struct IncorrectPrincipalEntityTypeError {
    pub(super) ty: EntityType,
    pub(super) expected: EntityType,
}

/// Error thrown when attempting to add a resource with an incorrect
/// entity type
#[derive(Debug, Error, Diagnostic)]
#[error("resource type `{ty}` does not match the partial request's resource type `{expected}`")]
pub struct IncorrectResourceEntityTypeError {
    pub(super) ty: EntityType,
    pub(super) expected: EntityType,
}

/// Error thrown when constructing [`crate::tpe::entities::PartialEntities`]
#[derive(Debug, Error, Diagnostic)]
pub enum EntitiesError {
    /// Error thrown when validating concrete components
    #[error(transparent)]
    #[diagnostic(transparent)]
    Deserialization(#[from] JsonDeserializationError),
    /// Error thrown when validating a [`crate::tpe::entities::PartialEntity`]
    #[error(transparent)]
    #[diagnostic(transparent)]
    Validation(#[from] EntityValidationError),
    /// Error thrown when validating the ancestors of a [`crate::tpe::entities::PartialEntity`]
    #[error(transparent)]
    #[diagnostic(transparent)]
    AncestorValidation(#[from] AncestorValidationError),
    /// Error thrown when computing TC
    #[error(transparent)]
    #[diagnostic(transparent)]
    TCComputation(#[from] TcError<EntityUID>),
    /// Error constructing the Entities collection due to encountering two
    /// different entities with the same Entity UID
    #[error(transparent)]
    #[diagnostic(transparent)]
    Duplicate(#[from] Duplicate),
    /// Errors encountered when converting `PartialValue` to `Value`
    #[error(transparent)]
    #[diagnostic(transparent)]
    PartialValueToValue(#[from] PartialValueToValueError),
}

/// Error thrown when checking the consistency between [`crate::tpe::entities::PartialEntities`] and
/// [`crate::entities::Entities`]
#[derive(Debug, Error, Diagnostic)]
pub enum EntitiesConsistencyError {
    /// Error thrown when there is an entity missing in the concrete entities
    #[error(transparent)]
    #[diagnostic(transparent)]
    MissingEntity(#[from] MissingEntityError),
    /// Error thrown when concrete entities contain unknown entities
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnknownEntity(#[from] UnknownEntityError),
    /// Error thrown when a concrete entity and a partial entity are
    /// inconsistent
    #[error(transparent)]
    #[diagnostic(transparent)]
    InconsistentEntity(#[from] EntityConsistencyError),
}

/// Error thrown when checking the consistency between [`crate::tpe::entities::PartialEntity`] and
/// [`crate::ast::Entity`]
#[derive(Debug, Error, Diagnostic)]
pub enum EntityConsistencyError {
    /// Error thrown when the concrete entity contains unknown attribute
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnknownAttribute(#[from] UnknownAttributeError),
    /// Error thrown when attributes mismatch
    #[error(transparent)]
    #[diagnostic(transparent)]
    MismatchedAttribute(#[from] MismatchedAttributeError),
    /// Error thrown when ancestors do not match
    #[error(transparent)]
    #[diagnostic(transparent)]
    MismatchedAncestor(#[from] MismatchedAncestorError),
    /// Error thrown when the concrete entity contains unknown tag
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnknownTag(#[from] UnknownTagError),
    /// Error thrown when tags mismatch
    #[error(transparent)]
    #[diagnostic(transparent)]
    MismatchedTag(#[from] MismatchedTagError),
}

/// Error thrown when the concrete entity contains unknown attribute
#[derive(Debug, Error, Diagnostic)]
#[error("concrete entity `{uid}` has an unknown value for attribute `{attr}`")]
pub struct UnknownAttributeError {
    pub(super) uid: EntityUID,
    pub(super) attr: SmolStr,
}

/// Error thrown when attributes mismatch
#[derive(Debug, Error, Diagnostic)]
#[error("attributes of entity `{uid}` do not match")]
pub struct MismatchedAttributeError {
    pub(super) uid: EntityUID,
}

/// Error thrown when the concrete entity contains unknown tag
#[derive(Debug, Error, Diagnostic)]
#[error("concrete entity `{uid}` has an unknown value for tag `{tag}`")]
pub struct UnknownTagError {
    pub(super) uid: EntityUID,
    pub(super) tag: SmolStr,
}

/// Error thrown when tags mismatch
#[derive(Debug, Error, Diagnostic)]
#[error("tags of entity `{uid}` do not match")]
pub struct MismatchedTagError {
    pub(super) uid: EntityUID,
}

/// Error thrown when ancestors do not match
#[derive(Debug, Error, Diagnostic)]
#[error("ancestors of entity `{uid}` do not match")]
pub struct MismatchedAncestorError {
    pub(super) uid: EntityUID,
}

/// Error thrown when when there is an entity missing in the concrete entities
#[derive(Debug, Error, Diagnostic)]
#[error("entity `{uid}` is missing from the concrete entities")]
pub struct MissingEntityError {
    pub(super) uid: EntityUID,
}

/// Error thrown when concrete entities contain unknown entities
#[derive(Debug, Error, Diagnostic)]
#[error("concrete entities contain an unknown entity `{uid}`")]
pub struct UnknownEntityError {
    pub(super) uid: EntityUID,
}

/// Error thrown when some requested entities were not loaded
#[derive(Debug, Error, Diagnostic)]
#[error("Failed to load entities: {}", .missing_entities.iter().map(|uid| uid.to_string()).collect::<Vec<_>>().join(", "))]
pub struct MissingEntitiesError {
    pub(super) missing_entities: Vec<EntityUID>,
}

impl MissingEntitiesError {
    /// Construct a new [`MissingEntitiesError`]
    pub fn new(missing_entities: Vec<EntityUID>) -> Self {
        Self { missing_entities }
    }
}

/// Error thrown when a [`crate::tpe::request::PartialRequest`] is inconsistent with a [`crate::ast::Request`]
#[derive(Debug, Error, Diagnostic)]
pub enum RequestConsistencyError {
    /// Error thrown when the concrete principal is unknown
    #[error("the concrete request's principal is unknown")]
    UnknownPrincipal,
    /// Error thrown when the concrete resource is unknown
    #[error("the concrete request's resource is unknown")]
    UnknownResource,
    /// Error thrown when the concrete action is unknown
    #[error("the concrete request's action is unknown")]
    UnknownAction,
    /// Error thrown when the concrete context is unknown
    #[error("the concrete request's context is unknown")]
    UnknownContext,
    /// Error thrown when principal types are inconsistent
    #[error(transparent)]
    #[diagnostic(transparent)]
    InconsistentPrincipalType(#[from] InconsistentPrincipalTypeError),
    /// Error thrown when principal eids are inconsistent
    #[error(transparent)]
    #[diagnostic(transparent)]
    InconsistentPrincipalEid(#[from] InconsistentPrincipalEidError),
    /// Error thrown when resource types are inconsistent
    #[error(transparent)]
    #[diagnostic(transparent)]
    InconsistentResourceType(#[from] InconsistentResourceTypeError),
    /// Error thrown when resource eids are inconsistent
    #[error(transparent)]
    #[diagnostic(transparent)]
    InconsistentResourceEid(#[from] InconsistentResourceEidError),
    /// Error thrown when actions are inconsistent
    #[error(transparent)]
    #[diagnostic(transparent)]
    InconsistentAction(#[from] InconsistentActionError),
    /// Error thrown when contexts are inconsistent
    #[error("the partial and concrete request contexts do not match")]
    InconsistentContext,
    /// Error thrown when the concrete context contains unknowns
    #[error("the concrete request's context contains unknowns")]
    ConcreteContextContainsUnknowns,
}

/// Error thrown when principal types are inconsistent
#[derive(Debug, Error, Diagnostic)]
#[error("partial request principal type `{partial}` does not match concrete request principal type `{concrete}`")]
pub struct InconsistentPrincipalTypeError {
    pub(super) partial: EntityType,
    pub(super) concrete: EntityType,
}

/// Error thrown when principal eids are inconsistent
#[derive(Debug, Error, Diagnostic)]
#[error("partial request principal id `{}` does not match concrete request principal id `{}`", .partial.escaped(), .concrete.escaped())]
pub struct InconsistentPrincipalEidError {
    pub(super) partial: Eid,
    pub(super) concrete: Eid,
}

/// Error thrown when resource types are inconsistent
#[derive(Debug, Error, Diagnostic)]
#[error("partial request resource type `{partial}` does not match concrete request resource type `{concrete}`")]
pub struct InconsistentResourceTypeError {
    pub(super) partial: EntityType,
    pub(super) concrete: EntityType,
}

/// Error thrown when resource eids are inconsistent
#[derive(Debug, Error, Diagnostic)]
#[error("partial request resource id `{}` does not match concrete request resource id `{}`", .partial.escaped(), .concrete.escaped())]
pub struct InconsistentResourceEidError {
    pub(super) partial: Eid,
    pub(super) concrete: Eid,
}

/// Error thrown when actions are inconsistent
#[derive(Debug, Error, Diagnostic)]
#[error("partial request action `{partial}` does not match concrete request action `{concrete}`")]
pub struct InconsistentActionError {
    pub(super) partial: EntityUID,
    pub(super) concrete: EntityUID,
}

/// Error thrown during reauthorization
#[derive(Debug, Error, Diagnostic)]
pub enum ReauthorizationError {
    /// Error thrown when request validation fails
    #[error(transparent)]
    #[diagnostic(transparent)]
    RequestValidation(#[from] RequestValidationError),
    /// Error thrown when entity validation fails
    #[error(transparent)]
    #[diagnostic(transparent)]
    EntityValidation(#[from] EntitySchemaConformanceError),
    /// Error thrown when entities and partial entities are inconsistent
    #[error(transparent)]
    #[diagnostic(transparent)]
    EntitiesConsistency(#[from] EntitiesConsistencyError),
    /// Error thrown when request and partial request are inconsistent
    #[error(transparent)]
    #[diagnostic(transparent)]
    RequestConsistency(#[from] RequestConsistencyError),
}
