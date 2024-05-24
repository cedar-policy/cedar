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

use crate::EntityUid;
use crate::PolicyId;
use cedar_policy_core::ast;
pub use cedar_policy_core::ast::RestrictedExpressionParseError;
use cedar_policy_core::authorizer;
use cedar_policy_core::est;
pub use cedar_policy_core::evaluator::{evaluation_errors, EvaluationError};
pub use cedar_policy_core::extensions::{
    extension_function_lookup_errors, ExtensionFunctionLookupError,
};
pub use cedar_policy_core::parser::err::{ParseError, ParseErrors};
pub use cedar_policy_validator::human_schema::SchemaWarning;
pub use cedar_policy_validator::schema_error;
pub use cedar_policy_validator::{ValidationErrorKind, ValidationWarningKind};
use miette::Diagnostic;
use ref_cast::RefCast;
use smol_str::SmolStr;
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

mod human_schema_error {
    use crate::schema_error::SchemaError;
    use miette::Diagnostic;
    use thiserror::Error;

    /// Parsing errors for human-readable schemas
    #[derive(Debug, Error, Diagnostic)]
    #[error(transparent)]
    #[diagnostic(transparent)]
    pub struct ParseError(#[from] pub(super) cedar_policy_validator::HumanSyntaxParseError);

    /// Errors when converting parsed human-readable schemas into full schemas
    #[derive(Debug, Error, Diagnostic)]
    #[error(transparent)]
    #[diagnostic(transparent)]
    pub struct CoreError(#[from] pub(super) SchemaError);

    /// IO errors when parsing human-readable schemas
    #[derive(Debug, Error, Diagnostic)]
    #[error(transparent)]
    pub struct IoError(#[from] pub(super) std::io::Error);
}

/// Errors when parsing schemas
#[derive(Debug, Diagnostic, Error)]
pub enum HumanSchemaError {
    /// Error parsing a schema in natural syntax
    #[error(transparent)]
    #[diagnostic(transparent)]
    Parse(#[from] human_schema_error::ParseError),
    /// Errors combining fragments into full schemas
    #[error(transparent)]
    #[diagnostic(transparent)]
    Core(#[from] human_schema_error::CoreError),
    /// IO errors while parsing
    #[error(transparent)]
    #[diagnostic(transparent)]
    Io(#[from] human_schema_error::IoError),
}

#[doc(hidden)]
impl From<cedar_policy_validator::HumanSchemaError> for HumanSchemaError {
    fn from(value: cedar_policy_validator::HumanSchemaError) -> Self {
        match value {
            cedar_policy_validator::HumanSchemaError::Core(core) => {
                human_schema_error::CoreError(core).into()
            }
            cedar_policy_validator::HumanSchemaError::IO(io_err) => {
                human_schema_error::IoError(io_err).into()
            }
            cedar_policy_validator::HumanSchemaError::Parsing(e) => {
                human_schema_error::ParseError(e).into()
            }
        }
    }
}

#[doc(hidden)]
impl From<crate::schema_error::SchemaError> for HumanSchemaError {
    fn from(value: crate::schema_error::SchemaError) -> Self {
        human_schema_error::CoreError(value).into()
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
        self.error.kind()
    }

    /// Extract the policy id of the policy where the validator found the issue.
    pub fn policy_id(&self) -> &PolicyId {
        PolicyId::ref_cast(self.error.policy_id())
    }
}

#[doc(hidden)]
impl From<cedar_policy_validator::ValidationError> for ValidationError {
    fn from(error: cedar_policy_validator::ValidationError) -> Self {
        Self { error }
    }
}

/// Structures containing details for validation errors
pub mod validation_errors {
    pub use cedar_policy_validator::validation_errors::{
        EmptySetForbidden, FunctionArgumentValidation, HierarchyNotRespected, IncompatibleTypes,
        InvalidActionApplication, MultiplyDefinedFunction, NonLitExtConstructor, TypeError,
        UndefinedFunction, UnexpectedType, UnrecognizedActionId, UnrecognizedEntityType,
        UnsafeAttributeAccess, UnsafeOptionalAttributeAccess, UnspecifiedEntity,
        ValidationErrorKind, WrongCallStyle, WrongNumberArguments,
    };
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

    /// Extract the policy id of the policy where the validator found the issue.
    pub fn policy_id(&self) -> &PolicyId {
        PolicyId::ref_cast(self.warning.policy_id())
    }
}

#[doc(hidden)]
impl From<cedar_policy_validator::ValidationWarning> for ValidationWarning {
    fn from(warning: cedar_policy_validator::ValidationWarning) -> Self {
        Self { warning }
    }
}

/// Structures containing details for validation warnings
pub mod validation_warnings {
    pub use cedar_policy_validator::validation_warnings::{
        BidiCharsInIdentifier, BidiCharsInString, ConfusableIdentifier, ImpossiblePolicy,
        MixedScriptIdentifier, MixedScriptString,
    };
}

/// Error structs for the variants of `PolicySetError`
pub mod policy_set_error_structs {
    use super::Error;
    use crate::PolicyId;
    use miette::Diagnostic;

    /// There was a duplicate [`PolicyId`] encountered in either the set of
    /// templates or the set of policies.
    #[derive(Debug, Diagnostic, Error)]
    #[error("duplicate template or policy id `{id}`")]
    pub struct AlreadyDefined {
        pub(crate) id: PolicyId,
    }

    /// Expected a static policy, but a template-linked policy was provided
    #[derive(Debug, Diagnostic, Error)]
    #[error("expected a static policy, but a template-linked policy was provided")]
    pub struct ExpectedStatic {}

    /// Expected a template, but a static policy was provided.
    #[derive(Debug, Diagnostic, Error)]
    #[error("expected a template, but a static policy was provided")]
    pub struct ExpectedTemplate {}

    /// Error when removing a static policy that doesn't exist
    #[derive(Debug, Diagnostic, Error)]
    #[error("unable to remove static policy `{policy_id}` because it does not exist")]
    pub struct PolicyNonexistentError {
        pub(crate) policy_id: PolicyId,
    }

    /// Error when removing a static policy that doesn't exist
    #[derive(Debug, Diagnostic, Error)]
    #[error("unable to remove template `{template_id}` because it does not exist")]
    pub struct TemplateNonexistentError {
        pub(crate) template_id: PolicyId,
    }

    /// Error when removing a template with active links
    #[derive(Debug, Diagnostic, Error)]
    #[error("unable to remove policy template `{template_id}` because it has active links")]
    pub struct RemoveTemplateWithActiveLinksError {
        pub(crate) template_id: PolicyId,
    }

    /// Error when removing a template that is not a template
    #[derive(Debug, Diagnostic, Error)]
    #[error("unable to remove policy template `{template_id}` because it is not a template")]
    pub struct RemoveTemplateNotTemplateError {
        pub(crate) template_id: PolicyId,
    }

    /// Error when unlinking a template
    #[derive(Debug, Diagnostic, Error)]
    #[error("unable to unlink policy `{policy_id}` because it does not exist")]
    pub struct LinkNonexistentError {
        pub(crate) policy_id: PolicyId,
    }

    /// Error when removing a link that is not a link
    #[derive(Debug, Diagnostic, Error)]
    #[error("unable to unlink `{policy_id}` because it is not a link")]
    pub struct UnlinkLinkNotLinkError {
        pub(crate) policy_id: PolicyId,
    }
}

/// Potential errors when adding to a `PolicySet`.
#[derive(Debug, Diagnostic, Error)]
#[non_exhaustive]
pub enum PolicySetError {
    /// There was a duplicate [`PolicyId`] encountered in either the set of
    /// templates or the set of policies.
    #[error(transparent)]
    #[diagnostic(transparent)]
    AlreadyDefined(#[from] policy_set_error_structs::AlreadyDefined),
    /// Error when linking a template
    #[error("unable to link template: {0}")]
    #[diagnostic(transparent)]
    LinkingError(#[from] ast::LinkingError),
    /// Expected a static policy, but a template-linked policy was provided
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExpectedStatic(#[from] policy_set_error_structs::ExpectedStatic),
    /// Expected a template, but a static policy was provided.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExpectedTemplate(#[from] policy_set_error_structs::ExpectedTemplate),
    /// Error when removing a static policy that doesn't exist
    #[error(transparent)]
    #[diagnostic(transparent)]
    PolicyNonexistentError(#[from] policy_set_error_structs::PolicyNonexistentError),
    /// Error when removing a template that doesn't exist
    #[error(transparent)]
    #[diagnostic(transparent)]
    TemplateNonexistentError(#[from] policy_set_error_structs::TemplateNonexistentError),
    /// Error when removing a template with active links
    #[error(transparent)]
    #[diagnostic(transparent)]
    RemoveTemplateWithActiveLinksError(
        #[from] policy_set_error_structs::RemoveTemplateWithActiveLinksError,
    ),
    /// Error when removing a template that is not a template
    #[error(transparent)]
    #[diagnostic(transparent)]
    RemoveTemplateNotTemplateError(
        #[from] policy_set_error_structs::RemoveTemplateNotTemplateError,
    ),
    /// Error when unlinking a linked policy
    #[error(transparent)]
    #[diagnostic(transparent)]
    LinkNonexistentError(#[from] policy_set_error_structs::LinkNonexistentError),
    /// Error when removing a link that is not a link
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnlinkLinkNotLinkError(#[from] policy_set_error_structs::UnlinkLinkNotLinkError),
    /// Error when converting from EST
    #[error("Error deserializing a policy/template from JSON: {0}")]
    #[diagnostic(transparent)]
    FromJson(#[from] cedar_policy_core::est::FromJsonError),
    /// Error when converting to EST
    #[error("Error serializing a policy to JSON: {0}")]
    #[diagnostic(transparent)]
    ToJson(#[from] PolicyToJsonError),
    /// Errors encountered in JSON ser/de of the policy set (as opposed to individual policies)
    #[error("Error serializing / deserializing PolicySet to / from JSON: {0})")]
    Json(#[from] serde_json::Error),
}

#[doc(hidden)]
impl From<ast::PolicySetError> for PolicySetError {
    fn from(e: ast::PolicySetError) -> Self {
        match e {
            ast::PolicySetError::Occupied { id } => {
                Self::AlreadyDefined(policy_set_error_structs::AlreadyDefined {
                    id: PolicyId::new(id),
                })
            }
        }
    }
}

#[doc(hidden)]
impl From<ast::UnexpectedSlotError> for PolicySetError {
    fn from(_: ast::UnexpectedSlotError) -> Self {
        Self::ExpectedStatic(policy_set_error_structs::ExpectedStatic {})
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
