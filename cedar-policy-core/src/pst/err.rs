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

//! Error types for PST (Public Syntax Tree) construction and conversion.
//!
//! This module defines errors that can occur when:
//! - Programmatically constructing PST expressions, policies, and constraints
//! - Converting between PST and other representations (EST, AST)
//! - Validating PST structure and semantics

use crate::extensions::ExtensionFunctionLookupError;
use miette::Diagnostic;
use smol_str::ToSmolStr;
use thiserror::Error;

use crate::ast;
use crate::est;

/// Errors that can occur during PST construction or conversion
#[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
#[non_exhaustive]
pub enum PstConstructionError {
    /// Trying to construct a policy from an empty representation of another type.
    /// A toplevel `Policy` was constructed without any text, EST or PST representation.
    #[error(transparent)]
    #[diagnostic(transparent)]
    PolicyFromEmptyRepresentation(#[from] error_body::PolicyFromEmptyRepresentationError),

    /// A policy is a linked policy but no link id has been provided
    #[error(transparent)]
    #[diagnostic(transparent)]
    PolicyMissingLinkId(#[from] error_body::PolicyMissingLinkIdError),

    /// A template was expected, but instead a static policy without slots was received
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExpectedTemplate(#[from] crate::parser::err::parse_errors::ExpectedTemplate),

    /// Action constraints cannot contain template slots
    #[error(transparent)]
    #[diagnostic(transparent)]
    ActionConstraintCannotHaveSlots(#[from] error_body::ActionConstraintCannotHaveSlotsError),

    /// Slot occurs in the wrong position (e.g., principal slot in resource)
    #[error(transparent)]
    #[diagnostic(transparent)]
    WrongSlotPosition(#[from] error_body::WrongSlotPositionError),

    /// Duplicate key found in a record literal
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateRecordKey(#[from] error_body::DuplicateRecordKeyError),

    /// Invalid annotation in a policy or template
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidAnnotation(#[from] error_body::InvalidAnnotationError),

    /// Invalid entity UID format or structure
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidEntityUid(#[from] error_body::InvalidEntityUidError),

    /// Invalid entity type name
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidEntityType(#[from] error_body::InvalidEntityTypeError),

    /// Invalid attribute path format or structure
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidAttributePath(#[from] error_body::InvalidAttributePathError),

    /// Attempted to construct a `has` expression with an empty attribute path
    #[error(transparent)]
    #[diagnostic(transparent)]
    EmptyAttributePath(#[from] error_body::EmptyAttributePathError),

    /// Invalid record structure (e.g., malformed key-value pairs)
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidRecord(#[from] error_body::InvalidRecordError),

    /// A generic invalid expression error with a description
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidExpression(#[from] error_body::InvalidExpressionError),

    /// Unknown function name (not a built-in or registered extension function)
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnknownFunction(#[from] error_body::UnknownFunctionError),

    /// Function called with wrong number of arguments
    #[error(transparent)]
    #[diagnostic(transparent)]
    WrongArity(#[from] error_body::WrongArityError),

    /// Error nodes from parsing are not supported in PST conversion
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnsupportedErrorNode(#[from] error_body::UnsupportedErrorNode),

    /// A parsing error occurred, usually in names
    #[error(transparent)]
    #[diagnostic(transparent)]
    ParsingFailed(#[from] error_body::ParsingFailedError),

    /// A linking error occurred.
    #[error(transparent)]
    #[diagnostic(transparent)]
    LinkingFailed(#[from] error_body::LinkingError),

    /// Contains unexpected slots
    #[error(transparent)]
    #[diagnostic(transparent)]
    ContainsSlots(#[from] error_body::ContainsSlotError),
}

impl PstConstructionError {
    /// Create an `ExpectedTemplate` error.
    pub fn expected_template() -> PstConstructionError {
        PstConstructionError::ExpectedTemplate(
            crate::parser::err::parse_errors::ExpectedTemplate::new(),
        )
    }
}

#[doc(hidden)]
impl From<est::FromJsonError> for PstConstructionError {
    fn from(err: est::FromJsonError) -> Self {
        match err {
            est::FromJsonError::UnknownExtensionFunction(e) => {
                PstConstructionError::UnknownFunction(error_body::UnknownFunctionError::new(
                    e.to_smolstr(),
                ))
            }
            est::FromJsonError::InvalidEntityType(e) => {
                PstConstructionError::InvalidEntityType(error_body::InvalidEntityTypeError {
                    description: e.to_string(),
                })
            }
            est::FromJsonError::JsonDeserializationError(e) => {
                // An error while deserializing JSON can occur only in small transformations; this
                // is likely a parsing error on a literal.
                error_body::ParsingFailedError::new(e.to_string()).into()
            }
            est::FromJsonError::UnescapeError(e) => PstConstructionError::ParsingFailed(
                // Show just first error in main error message, like original err
                error_body::ParsingFailedError::new(e.head.to_string()),
            ),
            est::FromJsonError::ActionSlot => {
                error_body::ActionConstraintCannotHaveSlotsError.into()
            }
            #[cfg(feature = "tolerant-ast")]
            est::FromJsonError::ASTErrorNode => {
                error_body::UnsupportedErrorNode::new("AST contains an error node").into()
            }
            _ => PstConstructionError::UnknownFunction(error_body::UnknownFunctionError::new(
                err.to_string().to_smolstr(),
            )), // TODO:
        }
    }
}

#[doc(hidden)]
impl From<ast::ExpressionConstructionError> for PstConstructionError {
    fn from(err: ast::ExpressionConstructionError) -> Self {
        let ast::ExpressionConstructionError::DuplicateKey(k) = err;
        error_body::DuplicateRecordKeyError { key: k.key }.into()
    }
}

#[doc(hidden)]
impl From<crate::parser::err::ParseErrors> for PstConstructionError {
    fn from(value: crate::parser::err::ParseErrors) -> Self {
        error_body::ParsingFailedError::from(value).into()
    }
}

/// Extension function lookup failed

#[doc(hidden)]
impl From<ExtensionFunctionLookupError> for PstConstructionError {
    fn from(err: ExtensionFunctionLookupError) -> Self {
        let ExtensionFunctionLookupError::FuncDoesNotExist(body) = err;
        error_body::UnknownFunctionError::new(body.name.to_smolstr()).into()
    }
}

/// Error subtypes for [`PstConstructionError`]
pub mod error_body {
    use crate::pst::SlotId;
    use miette::Diagnostic;
    use smol_str::SmolStr;
    use std::collections::HashSet;
    use thiserror::Error;

    use crate::est;
    use crate::pst;

    /// Trying to construct a policy from an empty representation of another type
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("cannot construct policy from empty representation")]
    pub struct PolicyFromEmptyRepresentationError;

    /// A policy is a linked policy but no link id has been provided
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("action constraint cannot have slots")]
    pub struct PolicyMissingLinkIdError;

    /// Action constraints cannot contain template slots
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("action constraint cannot have slots")]
    pub struct ActionConstraintCannotHaveSlotsError;

    /// Slot occurs in the wrong position (e.g., principal slot in resource)
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("slot `{found}` cannot be used in this position (expected slot `{expected}`)")]
    pub struct WrongSlotPositionError {
        found: pst::SlotId,
        expected: pst::SlotId,
    }

    impl WrongSlotPositionError {
        pub(crate) fn new(found: pst::SlotId, expected: pst::SlotId) -> Self {
            Self { found, expected }
        }
    }

    /// Duplicate key found in a record literal
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("duplicate record key: `{key}`")]
    pub struct DuplicateRecordKeyError {
        pub(crate) key: SmolStr,
    }

    impl DuplicateRecordKeyError {
        /// The duplicate key
        pub fn key(&self) -> &str {
            &self.key
        }
    }

    /// Invalid annotation in a policy or template
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("invalid annotation: {description}")]
    pub struct InvalidAnnotationError {
        description: String,
    }

    impl InvalidAnnotationError {
        pub(crate) fn new(description: impl Into<String>) -> Self {
            Self {
                description: description.into(),
            }
        }
    }

    /// Invalid entity UID format or structure
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("invalid entity UID: {description}")]
    pub struct InvalidEntityUidError {
        pub(crate) description: String,
    }

    /// Invalid entity type error (often failure to parse the name)
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("invalid entity type: `{description}`")]
    pub struct InvalidEntityTypeError {
        pub(crate) description: String,
    }

    /// Invalid attribute path format or structure
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("invalid attribute path: {description}")]
    pub struct InvalidAttributePathError {
        pub(crate) description: String,
    }

    /// Attempted to construct a `has` expression with an empty attribute path
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("attribute path cannot be empty")]
    pub struct EmptyAttributePathError;

    /// Invalid record structure
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("invalid record: {description}")]
    pub struct InvalidRecordError {
        pub(crate) description: String,
    }

    /// A generic invalid expression error with a description
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("invalid expression: {description}")]
    pub struct InvalidExpressionError {
        pub(crate) description: String,
    }

    impl InvalidExpressionError {
        pub(crate) fn new(description: String) -> Self {
            Self { description }
        }
    }

    /// Unknown function name
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("unknown function: `{name}`")]
    pub struct UnknownFunctionError {
        pub(crate) name: SmolStr,
    }

    impl UnknownFunctionError {
        pub(crate) fn new(name: SmolStr) -> Self {
            Self { name }
        }

        /// The unknown function name
        pub fn name(&self) -> &str {
            &self.name
        }
    }

    /// Function called with wrong number of arguments
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("function `{name}` expects {expected} argument(s), got {got}")]
    pub struct WrongArityError {
        pub(crate) name: String,
        pub(crate) expected: usize,
        pub(crate) got: usize,
    }

    impl WrongArityError {
        pub(crate) fn new(name: String, expected: usize, got: usize) -> Self {
            Self {
                name,
                expected,
                got,
            }
        }

        /// The function name
        pub fn name(&self) -> &str {
            &self.name
        }

        /// The expected number of arguments
        pub fn expected(&self) -> usize {
            self.expected
        }

        /// The actual number of arguments provided
        pub fn got(&self) -> usize {
            self.got
        }
    }

    /// Error nodes from parsing are not supported in PST conversion
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("error nodes not supported in conversion: {description}")]
    pub struct UnsupportedErrorNode {
        /// Information about where this error node might come from
        description: String,
    }

    impl UnsupportedErrorNode {
        pub(crate) fn new(description: impl Into<String>) -> Self {
            Self {
                description: description.into(),
            }
        }
    }

    /// A parsing error occurred
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("parse error: {description}")]
    pub struct ParsingFailedError {
        pub(crate) description: String,
    }

    impl ParsingFailedError {
        pub(crate) fn new(description: String) -> Self {
            Self { description }
        }
    }

    impl From<crate::parser::err::ParseErrors> for ParsingFailedError {
        fn from(value: crate::parser::err::ParseErrors) -> Self {
            Self::new(format!("{value:?}"))
        }
    }

    /// Errors that can occur when linking a template policy
    #[derive(Debug, PartialEq, Eq, Diagnostic, Error, Clone)]
    pub enum LinkingError {
        /// Template contains this slot, but a value wasn't provided for it
        #[error("failed to link template: no value provided for `{slot}`")]
        MissedSlot {
            /// Slot which didn't have a value provided for it
            slot: SlotId,
        },
    }

    impl From<LinkingError> for est::LinkingError {
        fn from(err: LinkingError) -> Self {
            match err {
                LinkingError::MissedSlot { slot } => Self::MissedSlot { slot: slot.into() },
            }
        }
    }

    /// The policy or an expression contains slots
    #[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
    #[error("policy or expression contains slots: {slots:?}")]
    pub struct ContainsSlotError {
        pub(crate) slots: HashSet<crate::pst::SlotId>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast;
    use crate::est;
    use crate::expr_builder::ExprBuilder;
    use crate::pst;
    use crate::pst::constraints::*;
    use crate::pst::expr::{Expr, Literal, PstBuilder, SlotId};
    use smol_str::SmolStr;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// From<est::FromJsonError> conversion covers all branches
    #[test]
    fn from_est_json_error_branches() {
        // UnknownExtensionFunction — not reachable via try_into_expr, but the From impl exists
        let name = ast::Name::parse_unqualified_name("nonexistent").unwrap();
        let err = PstConstructionError::from(est::FromJsonError::UnknownExtensionFunction(name));
        assert!(matches!(err, PstConstructionError::UnknownFunction(_)));

        // JsonDeserializationError
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{{").unwrap_err();
        let err =
            PstConstructionError::from(est::FromJsonError::JsonDeserializationError(json_err.into()));
        assert!(matches!(err, PstConstructionError::ParsingFailed(_)));

        // UnescapeError
        let unescape_errs = crate::parser::unescape::to_unescaped_string(r"\q").unwrap_err();
        let err = PstConstructionError::from(est::FromJsonError::UnescapeError(unescape_errs));
        assert!(matches!(err, PstConstructionError::ParsingFailed(_)));

        // MissingOperator (fallback branch)
        let err = PstConstructionError::from(est::FromJsonError::MissingOperator);
        assert!(matches!(err, PstConstructionError::UnknownFunction(_)));

        // ActionSlot
        let err = PstConstructionError::from(est::FromJsonError::ActionSlot);
        assert!(matches!(
            err,
            PstConstructionError::ActionConstraintCannotHaveSlots(_)
        ));
    }

    /// PST with ?resource slot in principal position → WrongSlotPosition on PST→AST conversion
    #[test]
    fn pst_wrong_slot_position() {
        let template = pst::Template::new(
            "t",
            pst::Effect::Permit,
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Resource)), // wrong!
            pst::ActionConstraint::Any,
            pst::ResourceConstraint::Any,
        );
        let err = ast::Template::try_from(template).unwrap_err();
        assert!(matches!(err, PstConstructionError::WrongSlotPosition(_)));
    }

    /// Linking a template with a missing slot → LinkingFailed, then convert to EST
    #[test]
    fn link_missing_slot_converts_to_est() {
        let template = pst::Template::new(
            "t",
            pst::Effect::Permit,
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)),
            pst::ActionConstraint::Any,
            pst::ResourceConstraint::Any,
        );
        let err = template.link(&HashMap::new()).unwrap_err();
        assert!(matches!(err, PstConstructionError::LinkingFailed(_)));
        if let PstConstructionError::LinkingFailed(linking_err) = err {
            let est_err: est::LinkingError = linking_err.into();
            assert!(matches!(est_err, est::LinkingError::MissedSlot { .. }));
        }
    }

    /// Adding a clause with slots to a template → ContainsSlots
    #[test]
    fn clause_with_slots_rejected() {
        let template = pst::Template::new(
            "t",
            pst::Effect::Permit,
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)),
            pst::ActionConstraint::Any,
            pst::ResourceConstraint::Any,
        );
        let err = template
            .try_with_clauses(vec![pst::Clause::When(Arc::new(Expr::Slot(
                SlotId::Principal,
            )))])
            .unwrap_err();
        assert!(matches!(err, PstConstructionError::ContainsSlots(_)));
        assert!(err.to_string().contains("slots"));
    }

    /// PST record with duplicate keys → DuplicateRecordKey with accessor
    #[test]
    fn pst_record_duplicate_keys() {
        let pairs = vec![
            (SmolStr::new("k"), PstBuilder.val(1i64)),
            (SmolStr::new("k"), PstBuilder.val(2i64)),
        ];
        let err = PstBuilder.record(pairs).unwrap_err();
        let pst_err = PstConstructionError::from(err);
        assert!(matches!(pst_err, PstConstructionError::DuplicateRecordKey(_)));
        if let PstConstructionError::DuplicateRecordKey(e) = &pst_err {
            assert_eq!(e.key(), "k");
        }
    }

    /// PST annotation with invalid key → InvalidAnnotation via EST conversion
    #[test]
    fn pst_invalid_annotation_key() {
        use std::collections::BTreeMap;
        let mut annotations = BTreeMap::new();
        annotations.insert("not valid!!".to_string(), "v".into());
        let policy = pst::Template::new(
            "p",
            pst::Effect::Permit,
            PrincipalConstraint::Any,
            pst::ActionConstraint::Any,
            pst::ResourceConstraint::Any,
        )
        .with_annotations(annotations);
        let err: Result<est::Policy, PstConstructionError> = policy.try_into();
        assert!(matches!(
            err,
            Err(PstConstructionError::InvalidAnnotation(..))
        ));
    }

    /// Unknown function via Expr builder → UnknownFunction with accessor
    #[test]
    fn pst_unknown_function() {
        let name = ast::Name::parse_unqualified_name("nonexistentFunc").unwrap();
        let args = vec![Arc::new(Expr::Literal(Literal::Long(1)))];
        let err = Expr::from_function_ast_name_and_args(&name, args).unwrap_err();
        assert!(matches!(err, PstConstructionError::UnknownFunction(_)));
        if let PstConstructionError::UnknownFunction(e) = &err {
            assert!(e.name().contains("nonexistent"));
        }
    }

    /// Wrong arity via Expr builder → WrongArity with accessors
    #[test]
    fn pst_wrong_arity() {
        let name = ast::Name::parse_unqualified_name("decimal").unwrap();
        let args = vec![
            Arc::new(Expr::Literal(Literal::Long(1))),
            Arc::new(Expr::Literal(Literal::Long(2))),
        ];
        let err = Expr::from_function_ast_name_and_args(&name, args).unwrap_err();
        if let PstConstructionError::WrongArity(e) = &err {
            assert_eq!(e.name(), "decimal");
            assert_eq!(e.expected(), 1);
            assert_eq!(e.got(), 2);
        } else {
            panic!("expected WrongArity, got: {err}");
        }
    }

    /// Invalid Cedar text → ParseErrors → PstConstructionError::ParsingFailed
    #[test]
    fn parse_errors_to_pst_error() {
        let parse_errs: crate::parser::err::ParseErrors =
            "bad!!!".parse::<ast::Expr>().unwrap_err();
        let pst_err = PstConstructionError::from(parse_errs);
        assert!(matches!(pst_err, PstConstructionError::ParsingFailed(_)));
    }
}
