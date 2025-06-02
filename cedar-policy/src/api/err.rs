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

use crate::{EntityUid, PolicyId};
pub use cedar_policy_core::ast::{
    expression_construction_errors, restricted_expr_errors, ContainsUnknown,
    ExpressionConstructionError, PartialValueToValueError, RestrictedExpressionError,
};
#[cfg(feature = "entity-manifest")]
use cedar_policy_core::entities::err::EntitiesError;
pub use cedar_policy_core::evaluator::{evaluation_errors, EvaluationError};
pub use cedar_policy_core::extensions::{
    extension_function_lookup_errors, ExtensionFunctionLookupError,
};
pub use cedar_policy_core::validator::cedar_schema::{schema_warnings, SchemaWarning};
#[cfg(feature = "entity-manifest")]
pub use cedar_policy_core::validator::entity_manifest::slicing::EntitySliceError;
#[cfg(feature = "entity-manifest")]
use cedar_policy_core::validator::entity_manifest::{
    self, PartialExpressionError, PartialRequestError, UnsupportedCedarFeatureError,
};
pub use cedar_policy_core::validator::{schema_errors, SchemaError};
use cedar_policy_core::{ast, authorizer, est};
use miette::Diagnostic;
use ref_cast::RefCast;
use smol_str::SmolStr;
use thiserror::Error;
use to_cedar_syntax_errors::NameCollisionsError;

#[cfg(feature = "entity-manifest")]
use super::ValidationResult;

/// Errors related to [`crate::Entities`]
pub mod entities_errors {
    pub use cedar_policy_core::entities::err::{Duplicate, EntitiesError, TransitiveClosureError};
}

/// Errors related to serializing/deserializing entities or contexts to/from JSON
pub mod entities_json_errors {
    pub use cedar_policy_core::entities::json::err::{
        ActionParentIsNotAction, DuplicateKey, ExpectedExtnValue, ExpectedLiteralEntityRef,
        ExtnCall0Arguments, ExtnCall2OrMoreArguments, JsonDeserializationError, JsonError,
        JsonSerializationError, MissingImpliedConstructor, MissingRequiredRecordAttr, ParseEscape,
        ReservedKey, Residual, TypeMismatch, UnexpectedRecordAttr, UnexpectedRestrictedExprKind,
    };
}

/// Errors related to schema conformance checking for entities
pub mod conformance_errors {
    pub use cedar_policy_core::entities::conformance::err::{
        ActionDeclarationMismatch, EntitySchemaConformanceError, ExtensionFunctionLookup,
        InvalidAncestorType, MissingRequiredEntityAttr, TypeMismatch, UndeclaredAction,
        UnexpectedEntityAttr, UnexpectedEntityTag, UnexpectedEntityTypeError,
    };
}

/// Errors that can occur during authorization
#[derive(Debug, Diagnostic, PartialEq, Eq, Error, Clone)]
pub enum AuthorizationError {
    /// An error occurred when evaluating a policy.
    #[error(transparent)]
    #[diagnostic(transparent)]
    PolicyEvaluationError(#[from] authorization_errors::PolicyEvaluationError),
}

/// Error subtypes for [`AuthorizationError`]
pub mod authorization_errors {
    use crate::{EvaluationError, PolicyId};
    use cedar_policy_core::{ast, authorizer};
    use miette::Diagnostic;
    use ref_cast::RefCast;
    use thiserror::Error;

    /// An error occurred when evaluating a policy
    #[derive(Debug, Diagnostic, PartialEq, Eq, Error, Clone)]
    #[error("error while evaluating policy `{id}`: {error}")]
    pub struct PolicyEvaluationError {
        /// Id of the policy with an error
        id: ast::PolicyID,
        /// Underlying evaluation error
        #[diagnostic(transparent)]
        error: EvaluationError,
    }

    impl PolicyEvaluationError {
        /// Get the [`PolicyId`] of the erroring policy
        pub fn policy_id(&self) -> &PolicyId {
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
    impl From<authorizer::AuthorizationError> for PolicyEvaluationError {
        fn from(e: authorizer::AuthorizationError) -> Self {
            match e {
                authorizer::AuthorizationError::PolicyEvaluationError { id, error } => {
                    Self { id, error }
                }
            }
        }
    }
}

#[doc(hidden)]
impl From<authorizer::AuthorizationError> for AuthorizationError {
    fn from(value: authorizer::AuthorizationError) -> Self {
        Self::PolicyEvaluationError(value.into())
    }
}

/// Errors that occur during concretizing a partial request
#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[diagnostic(transparent)]
pub struct ConcretizationError(pub(crate) cedar_policy_core::authorizer::ConcretizationError);

/// Errors that can be encountered when re-evaluating a partial response
#[derive(Debug, Diagnostic, Error)]
pub enum ReauthorizationError {
    /// An evaluation error was encountered
    #[error(transparent)]
    #[diagnostic(transparent)]
    Evaluation(#[from] EvaluationError),
    /// A policy set error was encountered
    #[error(transparent)]
    #[diagnostic(transparent)]
    PolicySet(#[from] PolicySetError),
    /// A request concretization error was encountered
    #[error(transparent)]
    #[diagnostic(transparent)]
    Concretization(#[from] ConcretizationError),
}

#[doc(hidden)]
impl From<cedar_policy_core::authorizer::ReauthorizationError> for ReauthorizationError {
    fn from(e: cedar_policy_core::authorizer::ReauthorizationError) -> Self {
        match e {
            cedar_policy_core::authorizer::ReauthorizationError::PolicySetError(err) => {
                Self::PolicySet(err.into())
            }
            cedar_policy_core::authorizer::ReauthorizationError::ConcretizationError(err) => {
                Self::Concretization(ConcretizationError(err))
            }
        }
    }
}

/// Errors serializing Schemas to the Cedar syntax
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum ToCedarSchemaError {
    /// Duplicate names were found in the schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    NameCollisions(#[from] to_cedar_syntax_errors::NameCollisionsError),
}

/// Error subtypes for [`ToCedarSchemaError`]
pub mod to_cedar_syntax_errors {
    use miette::Diagnostic;
    use thiserror::Error;

    /// Duplicate names were found in the schema
    #[derive(Debug, Error, Diagnostic)]
    #[error("{err}")]
    pub struct NameCollisionsError {
        #[diagnostic(transparent)]
        pub(super) err: cedar_policy_core::validator::cedar_schema::fmt::NameCollisionsError,
        // because `.names()` needs to return borrowed `&str`, we need somewhere to borrow from, hence here
        pub(super) names_as_strings: Vec<String>,
    }

    impl NameCollisionsError {
        /// Get the names that had collisions
        pub fn names(&self) -> impl Iterator<Item = &str> {
            self.names_as_strings
                .iter()
                .map(std::string::String::as_str)
        }
    }
}

#[doc(hidden)]
impl From<cedar_policy_core::validator::cedar_schema::fmt::ToCedarSchemaSyntaxError>
    for ToCedarSchemaError
{
    fn from(
        value: cedar_policy_core::validator::cedar_schema::fmt::ToCedarSchemaSyntaxError,
    ) -> Self {
        match value {
            cedar_policy_core::validator::cedar_schema::fmt::ToCedarSchemaSyntaxError::NameCollisions(
                name_collision_err,
            ) => NameCollisionsError {
                names_as_strings: name_collision_err
                    .names()
                    .map(ToString::to_string)
                    .collect(),
                err: name_collision_err,
            }
            .into(),
        }
    }
}

/// Error subtypes for [`CedarSchemaError`]
pub mod cedar_schema_errors {
    use miette::Diagnostic;
    use thiserror::Error;

    pub use cedar_policy_core::validator::CedarSchemaParseError as ParseError;

    /// IO error while parsing a Cedar schema
    #[derive(Debug, Error, Diagnostic)]
    #[error(transparent)]
    pub struct IoError(#[from] pub(super) std::io::Error);
}

/// Errors when parsing schemas
#[derive(Debug, Diagnostic, Error)]
#[non_exhaustive]
pub enum CedarSchemaError {
    /// Error parsing a schema in the Cedar syntax
    #[error(transparent)]
    #[diagnostic(transparent)]
    Parse(#[from] cedar_schema_errors::ParseError),
    /// IO error while parsing a Cedar schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    Io(#[from] cedar_schema_errors::IoError),
    /// Encountered a `SchemaError` while parsing a Cedar schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    Schema(#[from] SchemaError),
}

#[doc(hidden)]
impl From<cedar_policy_core::validator::CedarSchemaError> for CedarSchemaError {
    fn from(value: cedar_policy_core::validator::CedarSchemaError) -> Self {
        match value {
            cedar_policy_core::validator::CedarSchemaError::Schema(e) => e.into(),
            cedar_policy_core::validator::CedarSchemaError::IO(e) => {
                cedar_schema_errors::IoError(e).into()
            }
            cedar_policy_core::validator::CedarSchemaError::Parsing(e) => e.into(),
        }
    }
}

/// Error when evaluating an entity attribute or tag
#[derive(Debug, Diagnostic, Error)]
#[error("in {} `{attr_or_tag}` of `{uid}`: {err}", if *.was_attr { "attribute" } else { "tag" })]
pub struct EntityAttrEvaluationError {
    /// Action that had the attribute or tag with the error
    uid: EntityUid,
    /// Attribute or tag that had the error
    attr_or_tag: SmolStr,
    /// Is `attr_or_tag` an attribute (`true`) or a tag (`false`)
    was_attr: bool,
    /// Underlying evaluation error
    #[diagnostic(transparent)]
    err: EvaluationError,
}

impl EntityAttrEvaluationError {
    /// Get the [`EntityUid`] of the action that had the attribute with the error
    pub fn action(&self) -> &EntityUid {
        &self.uid
    }

    /// Get the name of the attribute or tag that had the error
    //
    // Method is named `.attr()` and not `.attr_or_tag()` for historical / backwards-compatibility reasons
    pub fn attr(&self) -> &SmolStr {
        &self.attr_or_tag
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
            uid: err.uid.into(),
            attr_or_tag: err.attr_or_tag,
            was_attr: err.was_attr,
            err: err.err,
        }
    }
}

/// Errors while trying to create a `Context`
#[derive(Debug, Diagnostic, Error)]
pub enum ContextCreationError {
    /// Tried to create a `Context` out of something other than a record
    #[error(transparent)]
    #[diagnostic(transparent)]
    NotARecord(context_creation_errors::NotARecord),
    /// Error evaluating the expression given for the `Context`
    #[error(transparent)]
    #[diagnostic(transparent)]
    Evaluation(#[from] EvaluationError),
    /// Error constructing the expression given for the `Context`.
    /// Only returned by `Context::from_pairs()`
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExpressionConstruction(#[from] ExpressionConstructionError),
}

#[doc(hidden)]
impl From<ast::ContextCreationError> for ContextCreationError {
    fn from(e: ast::ContextCreationError) -> Self {
        match e {
            ast::ContextCreationError::NotARecord(nre) => Self::NotARecord(nre),
            ast::ContextCreationError::Evaluation(e) => Self::Evaluation(e),
            ast::ContextCreationError::ExpressionConstruction(ece) => {
                Self::ExpressionConstruction(ece)
            }
        }
    }
}

/// Error subtypes for [`ContextCreationError`]
mod context_creation_errors {
    pub use cedar_policy_core::ast::context_creation_errors::NotARecord;
}

/// Error subtypes for [`ValidationError`].
///
/// Errors are primarily documented on their variants in [`ValidationError`].
pub mod validation_errors;

/// An error generated by the validator when it finds a potential problem in a
/// policy.
#[derive(Debug, Clone, Error, Diagnostic)]
#[non_exhaustive]
pub enum ValidationError {
    /// A policy contains an entity type that is not declared in the schema.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnrecognizedEntityType(#[from] validation_errors::UnrecognizedEntityType),
    /// A policy contains an action that is not declared in the schema.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnrecognizedActionId(#[from] validation_errors::UnrecognizedActionId),
    /// There is no action satisfying the action scope constraint that can be
    /// applied to a principal and resources that both satisfy their respective
    /// scope conditions.
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidActionApplication(#[from] validation_errors::InvalidActionApplication),
    /// The typechecker expected to see a subtype of one of the types in
    /// `expected`, but saw `actual`.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnexpectedType(#[from] validation_errors::UnexpectedType),
    /// The typechecker could not compute a least upper bound for `types`.
    #[error(transparent)]
    #[diagnostic(transparent)]
    IncompatibleTypes(#[from] validation_errors::IncompatibleTypes),
    /// The typechecker detected an access to a record or entity attribute
    /// that it could not statically guarantee would be present.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnsafeAttributeAccess(#[from] validation_errors::UnsafeAttributeAccess),
    /// The typechecker could not conclude that an access to an optional
    /// attribute was safe.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnsafeOptionalAttributeAccess(#[from] validation_errors::UnsafeOptionalAttributeAccess),
    /// The typechecker could not conclude that an access to a tag was safe.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnsafeTagAccess(#[from] validation_errors::UnsafeTagAccess),
    /// `.getTag()` on an entity type which cannot have tags according to the schema.
    #[error(transparent)]
    #[diagnostic(transparent)]
    NoTagsAllowed(#[from] validation_errors::NoTagsAllowed),
    /// Undefined extension function.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UndefinedFunction(#[from] validation_errors::UndefinedFunction),
    /// Incorrect number of arguments in an extension function application.
    #[error(transparent)]
    #[diagnostic(transparent)]
    WrongNumberArguments(#[from] validation_errors::WrongNumberArguments),
    /// Error returned by custom extension function argument validation
    #[diagnostic(transparent)]
    #[error(transparent)]
    FunctionArgumentValidation(#[from] validation_errors::FunctionArgumentValidation),
    /// Error returned when an empty set literal is found in a policy.
    #[diagnostic(transparent)]
    #[error(transparent)]
    EmptySetForbidden(#[from] validation_errors::EmptySetForbidden),
    /// Error returned when an extension constructor is applied to an non-literal expression.
    #[diagnostic(transparent)]
    #[error(transparent)]
    NonLitExtConstructor(#[from] validation_errors::NonLitExtConstructor),
    /// This error type is no longer ever returned, but remains here for
    /// backwards-compatibility (removing the variant entirely would be a
    /// breaking change).
    #[error(transparent)]
    #[diagnostic(transparent)]
    HierarchyNotRespected(#[from] validation_errors::HierarchyNotRespected),
    /// Returned when an internal invariant is violated (should not happen; if
    /// this is ever returned, please file an issue)
    #[error(transparent)]
    #[diagnostic(transparent)]
    InternalInvariantViolation(#[from] validation_errors::InternalInvariantViolation),
    /// Entity level violation
    #[error(transparent)]
    #[diagnostic(transparent)]
    EntityDerefLevelViolation(#[from] validation_errors::EntityDerefLevelViolation),
    /// Returned when an entity is of an enumerated entity type but has invalid EID
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidEnumEntity(#[from] validation_errors::InvalidEnumEntity),
}

impl ValidationError {
    /// Extract the policy id of the policy where the validator found the issue.
    pub fn policy_id(&self) -> &crate::PolicyId {
        match self {
            Self::UnrecognizedEntityType(e) => e.policy_id(),
            Self::UnrecognizedActionId(e) => e.policy_id(),
            Self::InvalidActionApplication(e) => e.policy_id(),
            Self::UnexpectedType(e) => e.policy_id(),
            Self::IncompatibleTypes(e) => e.policy_id(),
            Self::UnsafeAttributeAccess(e) => e.policy_id(),
            Self::UnsafeOptionalAttributeAccess(e) => e.policy_id(),
            Self::UnsafeTagAccess(e) => e.policy_id(),
            Self::NoTagsAllowed(e) => e.policy_id(),
            Self::UndefinedFunction(e) => e.policy_id(),
            Self::WrongNumberArguments(e) => e.policy_id(),
            Self::FunctionArgumentValidation(e) => e.policy_id(),
            Self::EmptySetForbidden(e) => e.policy_id(),
            Self::NonLitExtConstructor(e) => e.policy_id(),
            Self::HierarchyNotRespected(e) => e.policy_id(),
            Self::InternalInvariantViolation(e) => e.policy_id(),
            Self::EntityDerefLevelViolation(e) => e.policy_id(),
            Self::InvalidEnumEntity(e) => e.policy_id(),
        }
    }
}

#[doc(hidden)]
impl From<cedar_policy_core::validator::ValidationError> for ValidationError {
    fn from(error: cedar_policy_core::validator::ValidationError) -> Self {
        match error {
            cedar_policy_core::validator::ValidationError::UnrecognizedEntityType(e) => {
                Self::UnrecognizedEntityType(e.into())
            }
            cedar_policy_core::validator::ValidationError::UnrecognizedActionId(e) => {
                Self::UnrecognizedActionId(e.into())
            }
            cedar_policy_core::validator::ValidationError::InvalidActionApplication(e) => {
                Self::InvalidActionApplication(e.into())
            }
            cedar_policy_core::validator::ValidationError::UnexpectedType(e) => {
                Self::UnexpectedType(e.into())
            }
            cedar_policy_core::validator::ValidationError::IncompatibleTypes(e) => {
                Self::IncompatibleTypes(e.into())
            }
            cedar_policy_core::validator::ValidationError::UnsafeAttributeAccess(e) => {
                Self::UnsafeAttributeAccess(e.into())
            }
            cedar_policy_core::validator::ValidationError::UnsafeOptionalAttributeAccess(e) => {
                Self::UnsafeOptionalAttributeAccess(e.into())
            }
            cedar_policy_core::validator::ValidationError::UnsafeTagAccess(e) => {
                Self::UnsafeTagAccess(e.into())
            }
            cedar_policy_core::validator::ValidationError::NoTagsAllowed(e) => {
                Self::NoTagsAllowed(e.into())
            }
            cedar_policy_core::validator::ValidationError::UndefinedFunction(e) => {
                Self::UndefinedFunction(e.into())
            }
            cedar_policy_core::validator::ValidationError::WrongNumberArguments(e) => {
                Self::WrongNumberArguments(e.into())
            }
            cedar_policy_core::validator::ValidationError::FunctionArgumentValidation(e) => {
                Self::FunctionArgumentValidation(e.into())
            }
            cedar_policy_core::validator::ValidationError::EmptySetForbidden(e) => {
                Self::EmptySetForbidden(e.into())
            }
            cedar_policy_core::validator::ValidationError::NonLitExtConstructor(e) => {
                Self::NonLitExtConstructor(e.into())
            }
            cedar_policy_core::validator::ValidationError::InternalInvariantViolation(e) => {
                Self::InternalInvariantViolation(e.into())
            }
            cedar_policy_core::validator::ValidationError::InvalidEnumEntity(e) => {
                Self::InvalidEnumEntity(e.into())
            }
            cedar_policy_core::validator::ValidationError::EntityDerefLevelViolation(e) => {
                Self::EntityDerefLevelViolation(e.into())
            }
        }
    }
}

/// Error subtypes for [`ValidationWarning`].
///
/// Validation warnings are primarily documented on their variants in [`ValidationWarning`].
pub mod validation_warnings;

/// Represents the different kinds of validation warnings and information
/// specific to that warning.
///
/// Marked as `non_exhaustive` to allow adding additional warnings in the future
/// as a non-breaking change.
#[derive(Debug, Clone, Error, Diagnostic)]
#[non_exhaustive]
pub enum ValidationWarning {
    /// A string contains a mix of characters for different scripts (e.g., latin
    /// and cyrillic alphabets). Different scripts can contain visually similar
    /// characters which may be confused for each other.
    #[diagnostic(transparent)]
    #[error(transparent)]
    MixedScriptString(#[from] validation_warnings::MixedScriptString),
    /// A string contains bidirectional text control characters. These can be used to create crafted pieces of code that obfuscate true control flow.
    #[diagnostic(transparent)]
    #[error(transparent)]
    BidiCharsInString(#[from] validation_warnings::BidiCharsInString),
    /// An id contains bidirectional text control characters. These can be used to create crafted pieces of code that obfuscate true control flow.
    #[diagnostic(transparent)]
    #[error(transparent)]
    BidiCharsInIdentifier(#[from] validation_warnings::BidiCharsInIdentifier),
    /// An id contains a mix of characters for different scripts (e.g., latin and
    /// cyrillic alphabets). Different scripts can contain visually similar
    /// characters which may be confused for each other.
    #[diagnostic(transparent)]
    #[error(transparent)]
    MixedScriptIdentifier(#[from] validation_warnings::MixedScriptIdentifier),
    /// An id contains characters that is not a [graphical ASCII character](https://doc.rust-lang.org/std/primitive.char.html#method.is_ascii_graphic),
    /// not the space character (`U+0020`), and falls outside of the General
    /// Security Profile for Identifiers. We recommend adhering to this if
    /// possible. See [Unicode® Technical Standard #39](https://unicode.org/reports/tr39/#General_Security_Profile) for more information.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ConfusableIdentifier(#[from] validation_warnings::ConfusableIdentifier),
    /// The typechecker found that a policy condition will always evaluate to false.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ImpossiblePolicy(#[from] validation_warnings::ImpossiblePolicy),
}

impl ValidationWarning {
    /// Extract the policy id of the policy where the validator found the issue.
    pub fn policy_id(&self) -> &PolicyId {
        match self {
            Self::MixedScriptString(w) => w.policy_id(),
            Self::BidiCharsInString(w) => w.policy_id(),
            Self::BidiCharsInIdentifier(w) => w.policy_id(),
            Self::MixedScriptIdentifier(w) => w.policy_id(),
            Self::ConfusableIdentifier(w) => w.policy_id(),
            Self::ImpossiblePolicy(w) => w.policy_id(),
        }
    }
}

#[doc(hidden)]
impl From<cedar_policy_core::validator::ValidationWarning> for ValidationWarning {
    fn from(warning: cedar_policy_core::validator::ValidationWarning) -> Self {
        match warning {
            cedar_policy_core::validator::ValidationWarning::MixedScriptString(w) => {
                Self::MixedScriptString(w.into())
            }
            cedar_policy_core::validator::ValidationWarning::BidiCharsInString(w) => {
                Self::BidiCharsInString(w.into())
            }
            cedar_policy_core::validator::ValidationWarning::BidiCharsInIdentifier(w) => {
                Self::BidiCharsInIdentifier(w.into())
            }
            cedar_policy_core::validator::ValidationWarning::MixedScriptIdentifier(w) => {
                Self::MixedScriptIdentifier(w.into())
            }
            cedar_policy_core::validator::ValidationWarning::ConfusableIdentifier(w) => {
                Self::ConfusableIdentifier(w.into())
            }
            cedar_policy_core::validator::ValidationWarning::ImpossiblePolicy(w) => {
                Self::ImpossiblePolicy(w.into())
            }
        }
    }
}

/// Error subtypes for [`PolicySetError`]
pub mod policy_set_errors {
    use super::Error;
    use crate::PolicyId;
    use cedar_policy_core::ast;
    use miette::Diagnostic;

    /// There was a duplicate [`PolicyId`] encountered in either the set of
    /// templates or the set of policies.
    #[derive(Debug, Diagnostic, Error)]
    #[error("duplicate template or policy id `{id}`")]
    pub struct AlreadyDefined {
        pub(crate) id: PolicyId,
    }

    impl AlreadyDefined {
        /// Get the [`PolicyId`] for which there was a duplicate
        pub fn duplicate_id(&self) -> &PolicyId {
            &self.id
        }
    }

    /// Error when linking a template
    #[derive(Debug, Diagnostic, Error)]
    #[error("unable to link template")]
    pub struct LinkingError {
        #[from]
        #[diagnostic(transparent)]
        pub(crate) inner: ast::LinkingError,
    }

    /// Expected a static policy, but a template-linked policy was provided
    #[derive(Debug, Diagnostic, Error)]
    #[error("expected a static policy, but a template-linked policy was provided")]
    pub struct ExpectedStatic {
        /// A private field, just so the public interface notes this as a
        /// private-fields struct and not a empty-fields struct for semver
        /// purposes (e.g., consumers cannot construct this type with
        /// `ExpectedStatic {}`)
        _dummy: (),
    }

    impl ExpectedStatic {
        pub(crate) fn new() -> Self {
            Self { _dummy: () }
        }
    }

    /// Expected a template, but a static policy was provided.
    #[derive(Debug, Diagnostic, Error)]
    #[error("expected a template, but a static policy was provided")]
    pub struct ExpectedTemplate {
        /// A private field, just so the public interface notes this as a
        /// private-fields struct and not a empty-fields struct for semver
        /// purposes (e.g., consumers cannot construct this type with
        /// `ExpectedTemplate {}`)
        _dummy: (),
    }

    impl ExpectedTemplate {
        pub(crate) fn new() -> Self {
            Self { _dummy: () }
        }
    }

    /// Error when removing a static policy that doesn't exist
    #[derive(Debug, Diagnostic, Error)]
    #[error("unable to remove static policy `{policy_id}` because it does not exist")]
    pub struct PolicyNonexistentError {
        pub(crate) policy_id: PolicyId,
    }

    impl PolicyNonexistentError {
        /// Get the [`PolicyId`] of the policy which didn't exist
        pub fn policy_id(&self) -> &PolicyId {
            &self.policy_id
        }
    }

    /// Error when removing a template that doesn't exist
    #[derive(Debug, Diagnostic, Error)]
    #[error("unable to remove template `{template_id}` because it does not exist")]
    pub struct TemplateNonexistentError {
        pub(crate) template_id: PolicyId,
    }

    impl TemplateNonexistentError {
        /// Get the [`PolicyId`] of the template which didn't exist
        pub fn template_id(&self) -> &PolicyId {
            &self.template_id
        }
    }

    /// Error when removing a template with active links
    #[derive(Debug, Diagnostic, Error)]
    #[error("unable to remove policy template `{template_id}` because it has active links")]
    pub struct RemoveTemplateWithActiveLinksError {
        pub(crate) template_id: PolicyId,
    }

    impl RemoveTemplateWithActiveLinksError {
        /// Get the [`PolicyId`] of the template which had active links
        pub fn template_id(&self) -> &PolicyId {
            &self.template_id
        }
    }

    /// Error when removing a template that is not a template
    #[derive(Debug, Diagnostic, Error)]
    #[error("unable to remove policy template `{template_id}` because it is not a template")]
    pub struct RemoveTemplateNotTemplateError {
        pub(crate) template_id: PolicyId,
    }

    impl RemoveTemplateNotTemplateError {
        /// Get the [`PolicyId`] of the template which is not a template
        pub fn template_id(&self) -> &PolicyId {
            &self.template_id
        }
    }

    /// Error when unlinking a template-linked policy
    #[derive(Debug, Diagnostic, Error)]
    #[error("unable to unlink policy `{policy_id}` because it does not exist")]
    pub struct LinkNonexistentError {
        pub(crate) policy_id: PolicyId,
    }

    impl LinkNonexistentError {
        /// Get the [`PolicyId`] of the link which does not exist
        pub fn policy_id(&self) -> &PolicyId {
            &self.policy_id
        }
    }

    /// Error when removing a link that is not a link
    #[derive(Debug, Diagnostic, Error)]
    #[error("unable to unlink `{policy_id}` because it is not a link")]
    pub struct UnlinkLinkNotLinkError {
        pub(crate) policy_id: PolicyId,
    }

    impl UnlinkLinkNotLinkError {
        /// Get the [`PolicyId`] of the link which is not a link
        pub fn policy_id(&self) -> &PolicyId {
            &self.policy_id
        }
    }

    /// Error during JSON ser/de of the policy set (as opposed to individual policies)
    #[derive(Debug, Diagnostic, Error)]
    #[error("error serializing/deserializing policy set to/from JSON")]
    pub struct JsonPolicySetError {
        #[from]
        pub(crate) inner: serde_json::Error,
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
    AlreadyDefined(#[from] policy_set_errors::AlreadyDefined),
    /// Error when linking a template
    #[error(transparent)]
    #[diagnostic(transparent)]
    Linking(#[from] policy_set_errors::LinkingError),
    /// Expected a static policy, but a template-linked policy was provided
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExpectedStatic(#[from] policy_set_errors::ExpectedStatic),
    /// Expected a template, but a static policy was provided.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExpectedTemplate(#[from] policy_set_errors::ExpectedTemplate),
    /// Error when removing a static policy that doesn't exist
    #[error(transparent)]
    #[diagnostic(transparent)]
    PolicyNonexistent(#[from] policy_set_errors::PolicyNonexistentError),
    /// Error when removing a template that doesn't exist
    #[error(transparent)]
    #[diagnostic(transparent)]
    TemplateNonexistent(#[from] policy_set_errors::TemplateNonexistentError),
    /// Error when removing a template with active links
    #[error(transparent)]
    #[diagnostic(transparent)]
    RemoveTemplateWithActiveLinks(#[from] policy_set_errors::RemoveTemplateWithActiveLinksError),
    /// Error when removing a template that is not a template
    #[error(transparent)]
    #[diagnostic(transparent)]
    RemoveTemplateNotTemplate(#[from] policy_set_errors::RemoveTemplateNotTemplateError),
    /// Error when unlinking a linked policy
    #[error(transparent)]
    #[diagnostic(transparent)]
    LinkNonexistent(#[from] policy_set_errors::LinkNonexistentError),
    /// Error when removing a link that is not a link
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnlinkLinkNotLink(#[from] policy_set_errors::UnlinkLinkNotLinkError),
    /// Error when converting a policy/template from JSON format
    #[error(transparent)]
    #[diagnostic(transparent)]
    FromJson(#[from] PolicyFromJsonError),
    /// Error when converting a policy/template to JSON format
    #[error("Error serializing a policy/template to JSON")]
    #[diagnostic(transparent)]
    ToJson(#[from] PolicyToJsonError),
    /// Error during JSON ser/de of the policy set (as opposed to individual policies)
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonPolicySet(#[from] policy_set_errors::JsonPolicySetError),
}

#[doc(hidden)]
impl From<ast::PolicySetError> for PolicySetError {
    fn from(e: ast::PolicySetError) -> Self {
        match e {
            ast::PolicySetError::Occupied { id } => {
                Self::AlreadyDefined(policy_set_errors::AlreadyDefined {
                    id: PolicyId::new(id),
                })
            }
        }
    }
}

#[doc(hidden)]
impl From<ast::LinkingError> for PolicySetError {
    fn from(e: ast::LinkingError) -> Self {
        Self::Linking(e.into())
    }
}

#[doc(hidden)]
impl From<ast::UnexpectedSlotError> for PolicySetError {
    fn from(_: ast::UnexpectedSlotError) -> Self {
        Self::ExpectedStatic(policy_set_errors::ExpectedStatic::new())
    }
}

#[doc(hidden)]
impl From<est::PolicySetFromJsonError> for PolicySetError {
    fn from(e: est::PolicySetFromJsonError) -> Self {
        match e {
            est::PolicySetFromJsonError::PolicySet(e) => e.into(),
            est::PolicySetFromJsonError::Linking(e) => e.into(),
            est::PolicySetFromJsonError::FromJsonError(e) => Self::FromJson(e.into()),
        }
    }
}

/// Represents one or more [`ParseError`]s encountered when parsing a policy or
/// expression.
///
/// By default, the `Diagnostic` and `Error` implementations will only print the
/// first error. If you want to see all errors, use `.iter()` or `.into_iter()`.
#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[diagnostic(transparent)]
pub struct ParseErrors(#[from] cedar_policy_core::parser::err::ParseErrors);

impl ParseErrors {
    /// Get every [`ParseError`] associated with this [`ParseErrors`] object.
    /// The returned iterator is guaranteed to be nonempty.
    pub fn iter(&self) -> impl Iterator<Item = &ParseError> {
        self.0.iter().map(ParseError::ref_cast)
    }
}

/// Errors that can occur when parsing policies or expressions.
///
/// Marked as `non_exhaustive` to support adding additional error information
/// in the future without a major version bump.
#[derive(Debug, Diagnostic, Error, RefCast)]
#[repr(transparent)]
#[error(transparent)]
#[diagnostic(transparent)]
#[non_exhaustive]
pub struct ParseError {
    #[from]
    inner: cedar_policy_core::parser::err::ParseError,
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
    Link(#[from] policy_to_json_errors::JsonLinkError),
    /// Error in the JSON serialization
    #[error(transparent)]
    JsonSerialization(#[from] policy_to_json_errors::PolicyJsonSerializationError),
}

#[doc(hidden)]
impl From<est::LinkingError> for PolicyToJsonError {
    fn from(e: est::LinkingError) -> Self {
        policy_to_json_errors::JsonLinkError::from(e).into()
    }
}

impl From<serde_json::Error> for PolicyToJsonError {
    fn from(e: serde_json::Error) -> Self {
        policy_to_json_errors::PolicyJsonSerializationError::from(e).into()
    }
}

/// Error subtypes for [`PolicyToJsonError`]
pub mod policy_to_json_errors {
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

/// Error when converting a policy or template from JSON format
#[derive(Debug, Diagnostic, Error)]
#[error("error deserializing a policy/template from JSON")]
#[diagnostic(transparent)]
pub struct PolicyFromJsonError {
    #[from]
    pub(crate) inner: cedar_policy_core::est::FromJsonError,
}

/// Error type for parsing `Context` from JSON
#[derive(Debug, Diagnostic, Error)]
pub enum ContextJsonError {
    /// Error deserializing the JSON into a [`crate::Context`]
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonDeserialization(#[from] entities_json_errors::JsonDeserializationError),
    /// Error constructing the [`crate::Context`] itself
    #[error(transparent)]
    #[diagnostic(transparent)]
    ContextCreation(#[from] ContextCreationError),
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
    fn from(e: cedar_policy_core::entities::json::ContextJsonDeserializationError) -> Self {
        match e {
            cedar_policy_core::entities::json::ContextJsonDeserializationError::JsonDeserialization(e) => Self::JsonDeserialization(e),
            cedar_policy_core::entities::json::ContextJsonDeserializationError::ContextCreation(e) => Self::ContextCreation(e.into())
        }
    }
}

/// Error subtypes for [`ContextJsonError`]
pub mod context_json_errors {
    use super::EntityUid;
    use miette::Diagnostic;
    use thiserror::Error;

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

/// Error type for parsing a `RestrictedExpression`
#[derive(Debug, Diagnostic, Error)]
#[non_exhaustive]
pub enum RestrictedExpressionParseError {
    /// Failed to parse the expression
    #[error(transparent)]
    #[diagnostic(transparent)]
    Parse(#[from] ParseErrors),
    /// Parsed successfully as an expression, but failed to construct a
    /// restricted expression, for the reason indicated in the underlying error
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidRestrictedExpression(#[from] RestrictedExpressionError),
}

#[doc(hidden)]
impl From<cedar_policy_core::ast::RestrictedExpressionParseError>
    for RestrictedExpressionParseError
{
    fn from(e: cedar_policy_core::ast::RestrictedExpressionParseError) -> Self {
        match e {
            cedar_policy_core::ast::RestrictedExpressionParseError::Parse(e) => {
                Self::Parse(e.into())
            }
            cedar_policy_core::ast::RestrictedExpressionParseError::InvalidRestrictedExpression(
                e,
            ) => e.into(),
        }
    }
}

/// The request does not conform to the schema
#[derive(Debug, Diagnostic, Error)]
#[non_exhaustive]
pub enum RequestValidationError {
    /// Request action is not declared in the schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    UndeclaredAction(#[from] request_validation_errors::UndeclaredActionError),
    /// Request principal is of a type not declared in the schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    UndeclaredPrincipalType(#[from] request_validation_errors::UndeclaredPrincipalTypeError),
    /// Request resource is of a type not declared in the schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    UndeclaredResourceType(#[from] request_validation_errors::UndeclaredResourceTypeError),
    /// Request principal is of a type that is declared in the schema, but is
    /// not valid for the request action
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidPrincipalType(#[from] request_validation_errors::InvalidPrincipalTypeError),
    /// Request resource is of a type that is declared in the schema, but is
    /// not valid for the request action
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidResourceType(#[from] request_validation_errors::InvalidResourceTypeError),
    /// Context does not comply with the shape specified for the request action
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidContext(#[from] request_validation_errors::InvalidContextError),
    /// Error computing the type of the `Context`
    #[error(transparent)]
    #[diagnostic(transparent)]
    TypeOfContext(#[from] request_validation_errors::TypeOfContextError),
    /// Error when a principal or resource entity is of an enumerated entity
    /// type but has an invalid EID
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidEnumEntity(#[from] request_validation_errors::InvalidEnumEntityError),
}

#[doc(hidden)]
impl From<cedar_policy_core::validator::RequestValidationError> for RequestValidationError {
    fn from(e: cedar_policy_core::validator::RequestValidationError) -> Self {
        match e {
            cedar_policy_core::validator::RequestValidationError::UndeclaredAction(e) => {
                Self::UndeclaredAction(e.into())
            }
            cedar_policy_core::validator::RequestValidationError::UndeclaredPrincipalType(e) => {
                Self::UndeclaredPrincipalType(e.into())
            }
            cedar_policy_core::validator::RequestValidationError::UndeclaredResourceType(e) => {
                Self::UndeclaredResourceType(e.into())
            }
            cedar_policy_core::validator::RequestValidationError::InvalidPrincipalType(e) => {
                Self::InvalidPrincipalType(e.into())
            }
            cedar_policy_core::validator::RequestValidationError::InvalidResourceType(e) => {
                Self::InvalidResourceType(e.into())
            }
            cedar_policy_core::validator::RequestValidationError::InvalidContext(e) => {
                Self::InvalidContext(e.into())
            }
            cedar_policy_core::validator::RequestValidationError::TypeOfContext(e) => {
                Self::TypeOfContext(e.into())
            }
            cedar_policy_core::validator::RequestValidationError::InvalidEnumEntity(e) => {
                Self::InvalidEnumEntity(e.into())
            }
        }
    }
}

/// Error subtypes for [`RequestValidationError`]
pub mod request_validation_errors {
    use cedar_policy_core::extensions::ExtensionFunctionLookupError;
    use miette::Diagnostic;
    use ref_cast::RefCast;
    use thiserror::Error;

    use crate::{Context, EntityTypeName, EntityUid};

    /// Request action is not declared in the schema
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    #[diagnostic(transparent)]
    pub struct UndeclaredActionError(
        #[from] cedar_policy_core::validator::request_validation_errors::UndeclaredActionError,
    );

    impl UndeclaredActionError {
        /// The action which was not declared in the schema
        pub fn action(&self) -> &EntityUid {
            RefCast::ref_cast(self.0.action())
        }
    }

    /// Request principal is of a type not declared in the schema
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    #[diagnostic(transparent)]
    pub struct UndeclaredPrincipalTypeError(
        #[from]
        cedar_policy_core::validator::request_validation_errors::UndeclaredPrincipalTypeError,
    );

    impl UndeclaredPrincipalTypeError {
        /// The principal type which was not declared in the schema
        pub fn principal_ty(&self) -> &EntityTypeName {
            RefCast::ref_cast(self.0.principal_ty())
        }
    }

    /// Request resource is of a type not declared in the schema
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    #[diagnostic(transparent)]
    pub struct UndeclaredResourceTypeError(
        #[from]
        cedar_policy_core::validator::request_validation_errors::UndeclaredResourceTypeError,
    );

    impl UndeclaredResourceTypeError {
        /// The resource type which was not declared in the schema
        pub fn resource_ty(&self) -> &EntityTypeName {
            RefCast::ref_cast(self.0.resource_ty())
        }
    }

    /// Request principal is of a type that is declared in the schema, but is
    /// not valid for the request action
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    #[diagnostic(transparent)]
    pub struct InvalidPrincipalTypeError(
        #[from] cedar_policy_core::validator::request_validation_errors::InvalidPrincipalTypeError,
    );

    impl InvalidPrincipalTypeError {
        /// The principal type which is not valid
        pub fn principal_ty(&self) -> &EntityTypeName {
            RefCast::ref_cast(self.0.principal_ty())
        }

        /// The action which it is not valid for
        pub fn action(&self) -> &EntityUid {
            RefCast::ref_cast(self.0.action())
        }
    }

    /// Request resource is of a type that is declared in the schema, but is
    /// not valid for the request action
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    #[diagnostic(transparent)]
    pub struct InvalidResourceTypeError(
        #[from] cedar_policy_core::validator::request_validation_errors::InvalidResourceTypeError,
    );

    impl InvalidResourceTypeError {
        /// The resource type which is not valid
        pub fn resource_ty(&self) -> &EntityTypeName {
            RefCast::ref_cast(self.0.resource_ty())
        }

        /// The action which it is not valid for
        pub fn action(&self) -> &EntityUid {
            RefCast::ref_cast(self.0.action())
        }
    }

    /// Context does not comply with the shape specified for the request action
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    #[diagnostic(transparent)]
    pub struct InvalidContextError(
        #[from] cedar_policy_core::validator::request_validation_errors::InvalidContextError,
    );

    impl InvalidContextError {
        /// The context which is not valid
        pub fn context(&self) -> &Context {
            RefCast::ref_cast(self.0.context())
        }

        /// The action which it is not valid for
        pub fn action(&self) -> &EntityUid {
            RefCast::ref_cast(self.0.action())
        }
    }

    /// Error computing the type of the `Context`
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    #[diagnostic(transparent)]
    pub struct TypeOfContextError(#[from] ExtensionFunctionLookupError);

    /// Error when a principal or resource entity is of an enumerated entity
    /// type but has an invalid EID
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    #[diagnostic(transparent)]
    pub struct InvalidEnumEntityError(
        #[from] cedar_policy_core::entities::conformance::err::InvalidEnumEntityError,
    );
}

/// An error generated by entity slicing.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
#[cfg(feature = "entity-manifest")]
pub enum EntityManifestError {
    /// A validation error was encountered
    #[error(transparent)]
    #[diagnostic(transparent)]
    Validation(#[from] ValidationResult),
    /// A entities error was encountered
    #[error(transparent)]
    #[diagnostic(transparent)]
    Entities(#[from] EntitiesError),

    /// The request was partial
    #[error(transparent)]
    #[diagnostic(transparent)]
    PartialRequest(#[from] PartialRequestError),
    /// A policy was partial
    #[error(transparent)]
    #[diagnostic(transparent)]
    PartialExpression(#[from] PartialExpressionError),
    /// Encounters unsupported Cedar feature
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnsupportedCedarFeature(#[from] UnsupportedCedarFeatureError),
}

#[cfg(feature = "entity-manifest")]
impl From<entity_manifest::EntityManifestError> for EntityManifestError {
    fn from(e: entity_manifest::EntityManifestError) -> Self {
        match e {
            entity_manifest::EntityManifestError::Validation(e) => Self::Validation(e.into()),
            entity_manifest::EntityManifestError::Entities(e) => Self::Entities(e),
            entity_manifest::EntityManifestError::PartialRequest(e) => Self::PartialRequest(e),
            entity_manifest::EntityManifestError::PartialExpression(e) => {
                Self::PartialExpression(e)
            }
            entity_manifest::EntityManifestError::UnsupportedCedarFeature(e) => {
                Self::UnsupportedCedarFeature(e)
            }
        }
    }
}
