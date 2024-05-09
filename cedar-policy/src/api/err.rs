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

//! This module defines the publicly exported error types.

use crate::EntityTypeName;
use crate::EntityUid;
use crate::PolicyId;
use cedar_policy_core::ast;
use cedar_policy_core::ast::Name;
use cedar_policy_core::authorizer;
use cedar_policy_core::est;
pub use cedar_policy_core::evaluator::{EvaluationError, EvaluationErrorKind};
use cedar_policy_core::parser;
pub use cedar_policy_core::parser::err::ParseErrors;
pub use cedar_policy_validator::human_schema::SchemaWarning;
pub use cedar_policy_validator::{
    TypeErrorKind, UnsupportedFeature, ValidationErrorKind, ValidationWarningKind,
};
use miette::Diagnostic;
use ref_cast::RefCast;
use smol_str::SmolStr;
use std::collections::HashSet;
use thiserror::Error;

/// Errors that can occur during authorization
#[derive(Debug, Diagnostic, PartialEq, Eq, Error, Clone)]
pub enum AuthorizationError {
    /// An error occurred when evaluating a policy.
    #[error(transparent)]
    #[diagnostic(transparent)]
    PolicyEvaluationError(#[from] PolicyEvaluationError),
}

impl AuthorizationError {
    /// Get the id of the erroring policy
    pub fn id(&self) -> &PolicyId {
        match self {
            Self::PolicyEvaluationError(e) => e.id(),
        }
    }
}

/// An error occurred when evaluating a policy
#[derive(Debug, Diagnostic, PartialEq, Eq, Error, Clone)]
#[error("while evaluating policy `{id}`: {error}")]
pub struct PolicyEvaluationError {
    /// Id of the policy with an error
    id: ast::PolicyID,
    /// Underlying evaluation error
    #[diagnostic(transparent)]
    error: EvaluationError,
}

impl PolicyEvaluationError {
    /// Get the [`PolicyId`] of the erroring policy
    pub fn id(&self) -> &PolicyId {
        PolicyId::ref_cast(&self.id)
    }

    /// Get the underlying [`EvaluationError`]
    pub fn inner(&self) -> &EvaluationError {
        &self.error
    }

    /// Consume this error, producing the underlying [`EvaluationError`]
    pub fn into_inner(self) -> EvaluationError {
        self.error
    }
}

#[doc(hidden)]
impl From<authorizer::AuthorizationError> for AuthorizationError {
    fn from(value: authorizer::AuthorizationError) -> Self {
        match value {
            authorizer::AuthorizationError::PolicyEvaluationError { id, error } => {
                Self::PolicyEvaluationError(PolicyEvaluationError { id, error })
            }
        }
    }
}

/// Errors that can be encountered when re-evaluating a partial response
#[derive(Debug, Error)]
pub enum ReAuthorizeError {
    /// An evaluation error was encountered
    #[error("{err}")]
    Evaluation {
        /// The evaluation error
        #[from]
        err: EvaluationError,
    },
    /// A policy id conflict was found
    #[error("{err}")]
    PolicySet {
        /// The conflicting ids
        #[from]
        err: cedar_policy_core::ast::PolicySetError,
    },
}

/// Errors encountered during construction of a Validation Schema
#[derive(Debug, Diagnostic, Error)]
pub enum SchemaError {
    /// Error thrown by the `serde_json` crate during deserialization
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonDeserialization(#[from] cedar_policy_validator::JsonDeserializationError),
    /// Error thrown by the `serde_json` crate during serialization
    #[error(transparent)]
    JsonSerialization(serde_json::Error), // no #[from], because if you just have a serde_json::Error you should choose between JsonDeserialization and JsonSerialization appropriately
    /// Errors occurring while computing or enforcing transitive closure on
    /// action hierarchy.
    #[error("transitive closure computation/enforcement error on action hierarchy: {0}")]
    ActionTransitiveClosure(String),
    /// Errors occurring while computing or enforcing transitive closure on
    /// entity type hierarchy.
    #[error("transitive closure computation/enforcement error on entity type hierarchy: {0}")]
    EntityTypeTransitiveClosure(String),
    /// Error generated when processing a schema file that uses unsupported features
    #[error("unsupported feature used in schema: {0}")]
    UnsupportedFeature(String),
    /// Undeclared entity type(s) used in the `memberOf` field of an entity
    /// type, the `appliesTo` fields of an action, or an attribute type in a
    /// context or entity attribute record. Entity types in the error message
    /// are fully qualified, including any implicit or explicit namespaces.
    #[error("undeclared entity type(s): {0:?}")]
    UndeclaredEntityTypes(HashSet<String>),
    /// Undeclared action(s) used in the `memberOf` field of an action.
    #[error("undeclared action(s): {0:?}")]
    UndeclaredActions(HashSet<String>),
    /// Undeclared common type(s) used in entity or context attributes.
    #[error("undeclared common type(s): {0:?}")]
    UndeclaredCommonTypes(HashSet<String>),
    /// Duplicate specifications for an entity type. Argument is the name of
    /// the duplicate entity type.
    #[error("duplicate entity type `{0}`")]
    DuplicateEntityType(String),
    /// Duplicate specifications for an action. Argument is the name of the
    /// duplicate action.
    #[error("duplicate action `{0}`")]
    DuplicateAction(String),
    /// Duplicate specification for a reusable type declaration.
    #[error("duplicate common type `{0}`")]
    DuplicateCommonType(String),
    /// Cycle in the schema's action hierarchy.
    #[error("cycle in action hierarchy containing `{0}`")]
    CycleInActionHierarchy(EntityUid),
    /// Cycle in the schema's common type declarations.
    #[error("cycle in common type references containing `{0}`")]
    CycleInCommonTypeReferences(Name),
    /// The schema file included an entity type `Action` in the entity type
    /// list. The `Action` entity type is always implicitly declared, and it
    /// cannot currently have attributes or be in any groups, so there is no
    /// purposes in adding an explicit entry.
    #[error("entity type `Action` declared in `entityTypes` list")]
    ActionEntityTypeDeclared,
    /// `context` or `shape` fields are not records
    #[error("{0} is declared with a type other than `Record`")]
    ContextOrShapeNotRecord(ContextOrShape),
    /// An action entity (transitively) has an attribute that is an empty set.
    /// The validator cannot assign a type to an empty set.
    /// This error variant should only be used when `PermitAttributes` is enabled.
    #[error("action `{0}` has an attribute that is an empty set")]
    ActionAttributesContainEmptySet(EntityUid),
    /// An action entity (transitively) has an attribute of unsupported type (`ExprEscape`, `EntityEscape` or `ExtnEscape`).
    /// This error variant should only be used when `PermitAttributes` is enabled.
    #[error("action `{0}` has an attribute with unsupported JSON representation: {1}")]
    UnsupportedActionAttribute(EntityUid, String),
    /// Error when evaluating an action attribute
    #[error(transparent)]
    #[diagnostic(transparent)]
    ActionAttrEval(EntityAttrEvaluationError),
    /// Error thrown when the schema contains the `__expr` escape.
    /// Support for this escape form has been dropped.
    #[error("schema contained the non-supported `__expr` escape")]
    ExprEscapeUsed,
}

/// Errors serializing Schemas to the natural syntax
#[derive(Debug, Error, Diagnostic)]
pub enum ToHumanSyntaxError {
    /// Duplicate names were found in the schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    NameCollisions(#[from] to_human_syntax_errors::NameCollisionsError),
}

/// Error subtypes for [`ToHumanSyntaxError`]
pub mod to_human_syntax_errors {
    use itertools::Itertools;
    use miette::Diagnostic;
    use nonempty::NonEmpty;
    use smol_str::SmolStr;
    use thiserror::Error;

    /// Duplicate names were found in the schema
    #[derive(Debug, Error, Diagnostic)]
    #[error("There are name collisions: [{}]", .names.iter().join(", "))]
    pub struct NameCollisionsError {
        /// Names that had collisions
        names: NonEmpty<SmolStr>,
    }

    impl NameCollisionsError {
        /// Construct a new [`NameCollisionsError`]
        pub(crate) fn new(names: NonEmpty<SmolStr>) -> Self {
            Self { names }
        }

        /// Get the names that had collisions
        pub fn names(&self) -> impl Iterator<Item = &str> {
            self.names.iter().map(|n| n.as_str())
        }
    }
}

#[doc(hidden)]
impl From<cedar_policy_validator::human_schema::ToHumanSchemaStrError> for ToHumanSyntaxError {
    fn from(value: cedar_policy_validator::human_schema::ToHumanSchemaStrError) -> Self {
        match value {
            cedar_policy_validator::human_schema::ToHumanSchemaStrError::NameCollisions(
                collisions,
            ) => Self::NameCollisions(to_human_syntax_errors::NameCollisionsError::new(collisions)),
        }
    }
}

/// Errors when parsing schemas
#[derive(Debug, Diagnostic, Error)]
pub enum HumanSchemaError {
    /// Error parsing a schema in natural syntax
    #[error(transparent)]
    #[diagnostic(transparent)]
    ParseError(#[from] cedar_policy_validator::HumanSyntaxParseError),
    /// Errors combining fragments into full schemas
    #[error(transparent)]
    #[diagnostic(transparent)]
    Core(#[from] SchemaError),
    /// IO errors while parsing
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

#[doc(hidden)]
impl From<cedar_policy_validator::HumanSchemaError> for HumanSchemaError {
    fn from(value: cedar_policy_validator::HumanSchemaError) -> Self {
        match value {
            cedar_policy_validator::HumanSchemaError::Core(core) => Self::Core(core.into()),
            cedar_policy_validator::HumanSchemaError::IO(io_err) => Self::Io(io_err),
            cedar_policy_validator::HumanSchemaError::Parsing(e) => Self::ParseError(e),
        }
    }
}

#[doc(hidden)]
impl From<cedar_policy_validator::SchemaError> for HumanSchemaError {
    fn from(value: cedar_policy_validator::SchemaError) -> Self {
        Self::Core(value.into())
    }
}

/// Error when evaluating an entity attribute
#[derive(Debug, Diagnostic, Error)]
#[error("in attribute `{attr}` of `{uid}`: {err}")]
pub struct EntityAttrEvaluationError {
    /// Action that had the attribute with the error
    uid: EntityUid,
    /// Attribute that had the error
    attr: SmolStr,
    /// Underlying evaluation error
    #[diagnostic(transparent)]
    err: EvaluationError,
}

impl EntityAttrEvaluationError {
    /// Get the [`EntityUid`] of the action that had the attribute with the error
    pub fn action(&self) -> &EntityUid {
        &self.uid
    }

    /// Get the name of the attribute that had the error
    pub fn attr(&self) -> &SmolStr {
        &self.attr
    }

    /// Get the underlying evaluation error
    pub fn inner(&self) -> &EvaluationError {
        &self.err
    }
}

#[doc(hidden)]
impl From<ast::EntityAttrEvaluationError> for EntityAttrEvaluationError {
    fn from(err: ast::EntityAttrEvaluationError) -> Self {
        Self {
            uid: EntityUid::new(err.uid),
            attr: err.attr,
            err: err.err,
        }
    }
}

/// Describes in what action context or entity type shape a schema parsing error
/// occurred.
#[derive(Debug)]
pub enum ContextOrShape {
    /// An error occurred when parsing the context for the action with this
    /// `EntityUid`.
    ActionContext(EntityUid),
    /// An error occurred when parsing the shape for the entity type with this
    /// `EntityTypeName`.
    EntityTypeShape(EntityTypeName),
}

impl std::fmt::Display for ContextOrShape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActionContext(action) => write!(f, "Context for action {action}"),
            Self::EntityTypeShape(entity_type) => {
                write!(f, "Shape for entity type {entity_type}")
            }
        }
    }
}

#[doc(hidden)]
impl From<cedar_policy_validator::ContextOrShape> for ContextOrShape {
    fn from(value: cedar_policy_validator::ContextOrShape) -> Self {
        match value {
            cedar_policy_validator::ContextOrShape::ActionContext(euid) => {
                Self::ActionContext(EntityUid::new(euid))
            }
            cedar_policy_validator::ContextOrShape::EntityTypeShape(name) => {
                Self::EntityTypeShape(EntityTypeName::new(name))
            }
        }
    }
}

#[doc(hidden)]
impl From<cedar_policy_validator::SchemaError> for SchemaError {
    fn from(value: cedar_policy_validator::SchemaError) -> Self {
        match value {
            cedar_policy_validator::SchemaError::JsonDeserialization(e) => {
                Self::JsonDeserialization(e)
            }
            cedar_policy_validator::SchemaError::ActionTransitiveClosure(e) => {
                Self::ActionTransitiveClosure(e.to_string())
            }
            cedar_policy_validator::SchemaError::EntityTypeTransitiveClosure(e) => {
                Self::EntityTypeTransitiveClosure(e.to_string())
            }
            cedar_policy_validator::SchemaError::UnsupportedFeature(e) => {
                Self::UnsupportedFeature(e.to_string())
            }
            cedar_policy_validator::SchemaError::UndeclaredEntityTypes(e) => {
                Self::UndeclaredEntityTypes(e)
            }
            cedar_policy_validator::SchemaError::UndeclaredActions(e) => Self::UndeclaredActions(e),
            cedar_policy_validator::SchemaError::UndeclaredCommonTypes(c) => {
                Self::UndeclaredCommonTypes(c)
            }
            cedar_policy_validator::SchemaError::DuplicateEntityType(e) => {
                Self::DuplicateEntityType(e)
            }
            cedar_policy_validator::SchemaError::DuplicateAction(e) => Self::DuplicateAction(e),
            cedar_policy_validator::SchemaError::DuplicateCommonType(c) => {
                Self::DuplicateCommonType(c)
            }
            cedar_policy_validator::SchemaError::CycleInActionHierarchy(e) => {
                Self::CycleInActionHierarchy(EntityUid::new(e))
            }
            cedar_policy_validator::SchemaError::CycleInCommonTypeReferences(n) => {
                Self::CycleInCommonTypeReferences(n)
            }
            cedar_policy_validator::SchemaError::ActionEntityTypeDeclared => {
                Self::ActionEntityTypeDeclared
            }
            cedar_policy_validator::SchemaError::ContextOrShapeNotRecord(context_or_shape) => {
                Self::ContextOrShapeNotRecord(context_or_shape.into())
            }
            cedar_policy_validator::SchemaError::ActionAttributesContainEmptySet(uid) => {
                Self::ActionAttributesContainEmptySet(EntityUid::new(uid))
            }
            cedar_policy_validator::SchemaError::UnsupportedActionAttribute(uid, escape_type) => {
                Self::UnsupportedActionAttribute(EntityUid::new(uid), escape_type)
            }
            cedar_policy_validator::SchemaError::ActionAttrEval(err) => {
                Self::ActionAttrEval(err.into())
            }
            cedar_policy_validator::SchemaError::ExprEscapeUsed => Self::ExprEscapeUsed,
        }
    }
}

/// An error generated by the validator when it finds a potential problem in a
/// policy. The error contains a enumeration that specifies the kind of problem,
/// and provides details specific to that kind of problem. The error also records
/// where the problem was encountered.
#[derive(Debug, Clone, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub struct ValidationError {
    error: cedar_policy_validator::ValidationError,
}

impl ValidationError {
    /// Extract details about the exact issue detected by the validator.
    pub fn error_kind(&self) -> &ValidationErrorKind {
        self.error.error_kind()
    }

    /// Extract the location where the validator found the issue.
    pub fn location(&self) -> &SourceLocation {
        SourceLocation::ref_cast(self.error.location())
    }
}

#[doc(hidden)]
impl From<cedar_policy_validator::ValidationError> for ValidationError {
    fn from(error: cedar_policy_validator::ValidationError) -> Self {
        Self { error }
    }
}

/// Represents a location in Cedar policy source.
#[derive(Debug, Clone, Eq, PartialEq, RefCast)]
#[repr(transparent)]
pub struct SourceLocation(cedar_policy_validator::SourceLocation);

impl SourceLocation {
    /// Get the `PolicyId` for the policy at this source location.
    pub fn policy_id(&self) -> &PolicyId {
        PolicyId::ref_cast(self.0.policy_id())
    }

    /// Get the start of the location. Returns `None` if this location does not
    /// have a range.
    pub fn range_start(&self) -> Option<usize> {
        self.0.source_loc().map(parser::Loc::start)
    }

    /// Get the end of the location. Returns `None` if this location does not
    /// have a range.
    pub fn range_end(&self) -> Option<usize> {
        self.0.source_loc().map(parser::Loc::end)
    }

    /// Returns a tuple of (start, end) of the location.
    /// Returns `None` if this location does not have a range.
    pub fn range_start_and_end(&self) -> Option<(usize, usize)> {
        self.0
            .source_loc()
            .as_ref()
            .map(|loc| (loc.start(), loc.end()))
    }
}

impl std::fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "policy `{}`", self.0.policy_id())?;
        if let Some(loc) = self.0.source_loc() {
            write!(f, " at offset {}-{}", loc.start(), loc.end())?;
        }
        Ok(())
    }
}

#[doc(hidden)]
impl From<&cedar_policy_validator::SourceLocation> for SourceLocation {
    fn from(loc: &cedar_policy_validator::SourceLocation) -> Self {
        Self(loc.clone())
    }
}

#[derive(Debug, Clone, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
/// Warnings found in Cedar policies
pub struct ValidationWarning {
    warning: cedar_policy_validator::ValidationWarning,
}

impl ValidationWarning {
    /// Extract details about the exact issue detected by the validator.
    pub fn warning_kind(&self) -> &ValidationWarningKind {
        self.warning.kind()
    }

    /// Extract the location where the validator found the issue.
    pub fn location(&self) -> &SourceLocation {
        SourceLocation::ref_cast(self.warning.location())
    }
}

#[doc(hidden)]
impl From<cedar_policy_validator::ValidationWarning> for ValidationWarning {
    fn from(warning: cedar_policy_validator::ValidationWarning) -> Self {
        Self { warning }
    }
}

/// Potential errors when adding to a `PolicySet`.
#[derive(Debug, Diagnostic, Error)]
#[non_exhaustive]
pub enum PolicySetError {
    /// There was a duplicate [`PolicyId`] encountered in either the set of
    /// templates or the set of policies.
    #[error("duplicate template or policy id `{id}`")]
    AlreadyDefined {
        /// [`PolicyId`] that was duplicate
        id: PolicyId,
    },
    /// Error when linking a template
    #[error("unable to link template: {0}")]
    #[diagnostic(transparent)]
    LinkingError(#[from] ast::LinkingError),
    /// Expected a static policy, but a template-linked policy was provided
    #[error("expected a static policy, but a template-linked policy was provided")]
    ExpectedStatic,
    /// Expected a template, but a static policy was provided.
    #[error("expected a template, but a static policy was provided")]
    ExpectedTemplate,
    /// Error when removing a static policy
    #[error("unable to remove static policy `{0}` because it does not exist")]
    PolicyNonexistentError(PolicyId),
    /// Error when removing a template that doesn't exist
    #[error("unable to remove policy template `{0}` because it does not exist")]
    TemplateNonexistentError(PolicyId),
    /// Error when removing a template with active links
    #[error("unable to remove policy template `{0}` because it has active links")]
    RemoveTemplateWithActiveLinksError(PolicyId),
    /// Error when removing a template that is not a template
    #[error("unable to remove policy template `{0}` because it is not a template")]
    RemoveTemplateNotTemplateError(PolicyId),
    /// Error when unlinking a template
    #[error("unable to unlink policy template `{0}` because it does not exist")]
    LinkNonexistentError(PolicyId),
    /// Error when removing a link that is not a link
    #[error("unable to unlink `{0}` because it is not a link")]
    UnlinkLinkNotLinkError(PolicyId),
    /// Error when converting from EST
    #[error("Error deserializing a policy/template from JSON: {0}")]
    #[diagnostic(transparent)]
    FromJson(#[from] cedar_policy_core::est::FromJsonError),
    /// Error when converting to EST
    #[error("Error serializing a policy to JSON: {0}")]
    #[diagnostic(transparent)]
    ToJson(#[from] PolicyToJsonError),
    /// Errors encountered in JSON ser/de
    #[error("Error serializing or deserializing from JSON: {0})")]
    Json(#[from] serde_json::Error),
}

#[doc(hidden)]
impl From<ast::PolicySetError> for PolicySetError {
    fn from(e: ast::PolicySetError) -> Self {
        match e {
            ast::PolicySetError::Occupied { id } => Self::AlreadyDefined {
                id: PolicyId::new(id),
            },
        }
    }
}

#[doc(hidden)]
impl From<ast::UnexpectedSlotError> for PolicySetError {
    fn from(_: ast::UnexpectedSlotError) -> Self {
        Self::ExpectedStatic
    }
}

/// Errors that can happen when getting the JSON representation of a policy
#[derive(Debug, Diagnostic, Error)]
pub enum PolicyToJsonError {
    /// Parse error in the policy text
    #[error(transparent)]
    #[diagnostic(transparent)]
    Parse(#[from] ParseErrors),
    /// For linked policies, error linking the JSON representation
    #[error(transparent)]
    #[diagnostic(transparent)]
    Link(#[from] json_errors::JsonLinkError),
    /// Error in the JSON serialization
    #[error(transparent)]
    JsonSerialization(#[from] json_errors::PolicyJsonSerializationError),
}

#[doc(hidden)]
impl From<est::LinkingError> for PolicyToJsonError {
    fn from(e: est::LinkingError) -> Self {
        json_errors::JsonLinkError::from(e).into()
    }
}

impl From<serde_json::Error> for PolicyToJsonError {
    fn from(e: serde_json::Error) -> Self {
        json_errors::PolicyJsonSerializationError::from(e).into()
    }
}

/// Error types related to JSON processing
pub mod json_errors {
    use cedar_policy_core::est;
    use miette::Diagnostic;
    use thiserror::Error;

    /// Error linking the JSON representation of a linked policy
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    #[diagnostic(transparent)]
    pub struct JsonLinkError {
        /// Underlying error
        #[from]
        err: est::LinkingError,
    }

    /// Error serializing a policy as JSON
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    pub struct PolicyJsonSerializationError {
        /// Underlying error
        #[from]
        err: serde_json::Error,
    }
}

/// Error type for parsing `Context` from JSON
#[derive(Debug, Diagnostic, Error)]
pub enum ContextJsonError {
    /// Error deserializing the JSON into a Context
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonDeserialization(#[from] context_json_errors::ContextJsonDeserializationError),
    /// The supplied action doesn't exist in the supplied schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    MissingAction(#[from] context_json_errors::MissingActionError),
}

impl ContextJsonError {
    /// Construct a `ContextJsonError::MissingAction`
    pub(crate) fn missing_action(action: EntityUid) -> Self {
        Self::MissingAction(context_json_errors::MissingActionError { action })
    }
}

#[doc(hidden)]
impl From<cedar_policy_core::entities::json::ContextJsonDeserializationError> for ContextJsonError {
    fn from(error: cedar_policy_core::entities::json::ContextJsonDeserializationError) -> Self {
        context_json_errors::ContextJsonDeserializationError::from(error).into()
    }
}

/// Error subtypes for [`ContextJsonError`]
pub mod context_json_errors {
    use super::EntityUid;
    use miette::Diagnostic;
    use thiserror::Error;

    /// Error deserializing the JSON into a Context
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    pub struct ContextJsonDeserializationError {
        #[diagnostic(transparent)]
        #[from]
        error: cedar_policy_core::entities::json::ContextJsonDeserializationError,
    }

    /// The supplied action doesn't exist in the supplied schema
    #[derive(Debug, Diagnostic, Error)]
    #[error("action `{action}` does not exist in the supplied schema")]
    pub struct MissingActionError {
        /// UID of the action which doesn't exist
        pub(super) action: EntityUid,
    }

    impl MissingActionError {
        /// Get the [`EntityUid`] of the action which doesn't exist
        pub fn action(&self) -> &EntityUid {
            &self.action
        }
    }
}
