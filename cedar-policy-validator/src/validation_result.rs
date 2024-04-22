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

use cedar_policy_core::ast::PolicyID;
use cedar_policy_core::parser::Loc;
use miette::Diagnostic;
use thiserror::Error;

use crate::TypeErrorKind;

/// Contains the result of policy validation. The result includes the list of
/// issues found by validation and whether validation succeeds or fails.
/// Validation succeeds if there are no fatal errors. There may still be
/// non-fatal warnings present when validation passes.
#[derive(Debug)]
pub struct ValidationResult {
    validation_errors: Vec<ValidationError>,
    validation_warnings: Vec<ValidationWarning>,
}

impl ValidationResult {
    pub fn new(
        errors: impl IntoIterator<Item = ValidationError>,
        warnings: impl IntoIterator<Item = ValidationWarning>,
    ) -> Self {
        Self {
            validation_errors: errors.into_iter().collect(),
            validation_warnings: warnings.into_iter().collect(),
        }
    }

    /// True when validation passes. There are no errors, but there may be
    /// non-fatal warnings.
    pub fn validation_passed(&self) -> bool {
        self.validation_errors.is_empty()
    }

    /// Get an iterator over the errors found by the validator.
    pub fn validation_errors(&self) -> impl Iterator<Item = &ValidationError> {
        self.validation_errors.iter()
    }

    /// Get an iterator over the warnings found by the validator.
    pub fn validation_warnings(&self) -> impl Iterator<Item = &ValidationWarning> {
        self.validation_warnings.iter()
    }

    /// Get an iterator over the errors and warnings found by the validator.
    pub fn into_errors_and_warnings(
        self,
    ) -> (
        impl Iterator<Item = ValidationError>,
        impl Iterator<Item = ValidationWarning>,
    ) {
        (
            self.validation_errors.into_iter(),
            self.validation_warnings.into_iter(),
        )
    }
}

/// An error generated by the validator when it finds a potential problem in a
/// policy. The error contains a enumeration that specifies the kind of problem,
/// and provides details specific to that kind of problem. The error also records
/// where the problem was encountered.
#[derive(Clone, Debug, Error)]
#[error("{error_kind}")]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct ValidationError {
    location: SourceLocation,
    error_kind: ValidationErrorKind,
}

// custom impl of `Diagnostic`: source location and source code are from
// .location, everything else forwarded to .error_kind
impl Diagnostic for ValidationError {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        let label = miette::LabeledSpan::underline(self.location.source_loc.as_ref()?.span);
        Some(Box::new(std::iter::once(label)))
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.location.source_loc.as_ref()?.src)
    }

    fn code(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        self.error_kind.code()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.error_kind.severity()
    }

    fn url(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        self.error_kind.url()
    }

    fn help(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        self.error_kind.help()
    }

    fn related(&self) -> Option<Box<dyn Iterator<Item = &dyn Diagnostic> + '_>> {
        self.error_kind.related()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.error_kind.diagnostic_source()
    }
}

impl ValidationError {
    pub(crate) fn with_policy_id(
        id: PolicyID,
        source_loc: Option<Loc>,
        error_kind: ValidationErrorKind,
    ) -> Self {
        Self {
            error_kind,
            location: SourceLocation::new(id, source_loc),
        }
    }

    /// Deconstruct this into its component source location and error kind.
    pub fn into_location_and_error_kind(self) -> (SourceLocation, ValidationErrorKind) {
        (self.location, self.error_kind)
    }

    /// Extract details about the exact issue detected by the validator.
    pub fn error_kind(&self) -> &ValidationErrorKind {
        &self.error_kind
    }

    /// Extract the location where the validator found the issue.
    pub fn location(&self) -> &SourceLocation {
        &self.location
    }
}

/// Represents a location in Cedar policy source.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SourceLocation {
    policy_id: PolicyID,
    source_loc: Option<Loc>,
}

impl SourceLocation {
    pub(crate) fn new(policy_id: PolicyID, source_loc: Option<Loc>) -> Self {
        Self {
            policy_id,
            source_loc,
        }
    }

    /// Get the `PolicyId` for the policy at this source location.
    pub fn policy_id(&self) -> &PolicyID {
        &self.policy_id
    }

    pub fn source_loc(&self) -> Option<&Loc> {
        self.source_loc.as_ref()
    }
}

/// Enumeration of the possible diagnostic error that could be found by the
/// verification steps.
#[derive(Debug, Clone, Diagnostic, Error)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[non_exhaustive]
pub enum ValidationErrorKind {
    /// A policy contains an entity type that is not declared in the schema.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnrecognizedEntityType(#[from] UnrecognizedEntityType),
    /// A policy contains an action that is not declared in the schema.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnrecognizedActionId(#[from] UnrecognizedActionId),
    /// There is no action satisfying the action head constraint that can be
    /// applied to a principal and resources that both satisfy their respective
    /// head conditions.
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidActionApplication(#[from] InvalidActionApplication),
    /// The type checker found an error.
    #[error(transparent)]
    #[diagnostic(transparent)]
    TypeError(#[from] TypeErrorKind),
    /// An unspecified entity was used in a policy. This should be impossible,
    /// assuming that the policy was constructed by the parser.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnspecifiedEntity(#[from] UnspecifiedEntityError),
}

impl ValidationErrorKind {
    pub(crate) fn unrecognized_entity_type(
        actual_entity_type: String,
        suggested_entity_type: Option<String>,
    ) -> ValidationErrorKind {
        UnrecognizedEntityType {
            actual_entity_type,
            suggested_entity_type,
        }
        .into()
    }

    pub(crate) fn unrecognized_action_id(
        actual_action_id: String,
        suggested_action_id: Option<String>,
    ) -> ValidationErrorKind {
        UnrecognizedActionId {
            actual_action_id,
            suggested_action_id,
        }
        .into()
    }

    pub(crate) fn invalid_action_application(
        would_in_fix_principal: bool,
        would_in_fix_resource: bool,
    ) -> ValidationErrorKind {
        InvalidActionApplication {
            would_in_fix_principal,
            would_in_fix_resource,
        }
        .into()
    }

    pub(crate) fn type_error(type_error: TypeErrorKind) -> ValidationErrorKind {
        type_error.into()
    }

    pub(crate) fn unspecified_entity(entity_id: String) -> ValidationErrorKind {
        UnspecifiedEntityError { entity_id }.into()
    }
}

/// Structure containing details about an unrecognized entity type error.
#[derive(Debug, Clone, Error)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[error("unrecognized entity type `{actual_entity_type}`")]
pub struct UnrecognizedEntityType {
    /// The entity type seen in the policy.
    pub(crate) actual_entity_type: String,
    /// An entity type from the schema that the user might reasonably have
    /// intended to write.
    pub(crate) suggested_entity_type: Option<String>,
}

impl Diagnostic for UnrecognizedEntityType {
    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        match &self.suggested_entity_type {
            Some(s) => Some(Box::new(format!("did you mean `{s}`?"))),
            None => None,
        }
    }
}

/// Structure containing details about an unrecognized action id error.
#[derive(Debug, Clone, Error)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[error("unrecognized action `{actual_action_id}`")]
pub struct UnrecognizedActionId {
    /// Action Id seen in the policy.
    pub(crate) actual_action_id: String,
    /// An action id from the schema that the user might reasonably have
    /// intended to write.
    pub(crate) suggested_action_id: Option<String>,
}

impl Diagnostic for UnrecognizedActionId {
    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        match &self.suggested_action_id {
            Some(s) => Some(Box::new(format!("did you mean `{s}`?"))),
            None => None,
        }
    }
}

/// Structure containing details about an invalid action application error.
#[derive(Debug, Clone, Error)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[error("unable to find an applicable action given the policy head constraints")]
pub struct InvalidActionApplication {
    pub(crate) would_in_fix_principal: bool,
    pub(crate) would_in_fix_resource: bool,
}

impl Diagnostic for InvalidActionApplication {
    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        match (self.would_in_fix_principal, self.would_in_fix_resource) {
            (true, false) => Some(Box::new(
                "try replacing `==` with `in` in the principal clause",
            )),
            (false, true) => Some(Box::new(
                "try replacing `==` with `in` in the resource clause",
            )),
            (true, true) => Some(Box::new(
                "try replacing `==` with `in` in the principal clause and the resource clause",
            )),
            (false, false) => None,
        }
    }
}

/// Structure containing details about an unspecified entity error.
#[derive(Debug, Clone, Diagnostic, Error)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[error("unspecified entity with id `{entity_id}`")]
#[diagnostic(help("unspecified entities cannot be used in policies"))]
pub struct UnspecifiedEntityError {
    /// EID of the unspecified entity.
    pub(crate) entity_id: String,
}

/// The structure for validation warnings.
#[derive(Hash, Eq, PartialEq, Error, Debug, Clone)]
pub struct ValidationWarning {
    pub(crate) location: SourceLocation,
    pub(crate) kind: ValidationWarningKind,
}

impl ValidationWarning {
    pub(crate) fn with_policy_id(
        id: PolicyID,
        source_loc: Option<Loc>,
        warning_kind: ValidationWarningKind,
    ) -> Self {
        Self {
            kind: warning_kind,
            location: SourceLocation::new(id, source_loc),
        }
    }

    pub fn location(&self) -> &SourceLocation {
        &self.location
    }

    pub fn kind(&self) -> &ValidationWarningKind {
        &self.kind
    }

    pub fn to_kind_and_location(self) -> (SourceLocation, ValidationWarningKind) {
        (self.location, self.kind)
    }
}

impl std::fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "validation warning on policy `{}`: {}",
            self.location.policy_id(),
            self.kind
        )
    }
}

// custom impl of `Diagnostic`: source location and source code are from
// .location, everything else forwarded to .kind
impl Diagnostic for ValidationWarning {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        let label = miette::LabeledSpan::underline(self.location.source_loc.as_ref()?.span);
        Some(Box::new(std::iter::once(label)))
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.location.source_loc.as_ref()?.src)
    }

    fn code(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        self.kind.code()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.kind.severity()
    }

    fn url(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        self.kind.url()
    }

    fn help(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        self.kind.help()
    }

    fn related(&self) -> Option<Box<dyn Iterator<Item = &dyn Diagnostic> + '_>> {
        self.kind.related()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.kind.diagnostic_source()
    }
}

/// Represents the different kinds of validation warnings and information
/// specific to that warning. Marked as `non_exhaustive` to allow adding
/// additional warnings in the future as a non-breaking change.
#[derive(Debug, Clone, PartialEq, Diagnostic, Error, Eq, Hash)]
#[non_exhaustive]
#[diagnostic(severity(Warning))]
pub enum ValidationWarningKind {
    /// A string contains mixed scripts. Different scripts can contain visually similar characters which may be confused for each other.
    #[error("string `\"{0}\"` contains mixed scripts")]
    MixedScriptString(String),
    /// A string contains BIDI control characters. These can be used to create crafted pieces of code that obfuscate true control flow.
    #[error("string `\"{0}\"` contains BIDI control characters")]
    BidiCharsInString(String),
    /// An id contains BIDI control characters. These can be used to create crafted pieces of code that obfuscate true control flow.
    #[error("identifier `{0}` contains BIDI control characters")]
    BidiCharsInIdentifier(String),
    /// An id contains mixed scripts. This can cause characters to be confused for each other.
    #[error("identifier `{0}` contains mixed scripts")]
    MixedScriptIdentifier(String),
    /// An id contains characters that fall outside of the General Security Profile for Identifiers. We recommend adhering to this if possible. See Unicode® Technical Standard #39 for more info.
    #[error("identifier `{0}` contains characters that fall outside of the General Security Profile for Identifiers")]
    ConfusableIdentifier(String),
    /// The typechecker found that a policy condition will always evaluate to false.
    #[error(
        "policy is impossible: the policy expression evaluates to false for all valid requests"
    )]
    ImpossiblePolicy,
}
