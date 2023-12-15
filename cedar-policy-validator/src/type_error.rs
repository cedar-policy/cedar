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

//! Defines the structure for type errors returned by the typechecker.

use std::{collections::BTreeSet, fmt::Display};

use cedar_policy_core::ast::{CallStyle, EntityUID, Expr, ExprKind, Name, Var};

use crate::types::{EntityLUB, EntityRecordKind, RequestEnv};

use super::types::Type;

use itertools::Itertools;
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

/// The structure for type errors. A type errors knows the expression that
/// triggered the type error, as well as additional information for specific
/// kinds of type errors.
#[derive(Debug, Hash, PartialEq, Eq, Error)]
#[error("{kind}")]
pub struct TypeError {
    // This struct has both `on_expr` and `source_location` because many tests
    // were written to check that an error was raised on a particular expression
    // rather than at a source location. This is redundant (particularly since
    // an `Expr` already has a source location embedded in it).
    // For greater efficiency, we could remove `on_expr` and rewrite the affected
    // tests to only check for the correct `source_location`.
    pub(crate) on_expr: Option<Expr>,
    pub(crate) source_location: Option<miette::SourceSpan>,
    pub(crate) kind: TypeErrorKind,
}

// custom impl of `Diagnostic`: source location is from .source_span(),
// everything else forwarded to .kind
impl Diagnostic for TypeError {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        self.source_span().as_ref().map(|info| {
            let label = miette::LabeledSpan::underline(*info);
            let ret: Box<dyn Iterator<Item = miette::LabeledSpan>> =
                Box::new(std::iter::once(label));
            ret
        })
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.kind.source_code()
    }

    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.kind.code()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.kind.help()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.kind.severity()
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.kind.url()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.kind.diagnostic_source()
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        self.kind.related()
    }
}

impl TypeError {
    /// Extract the type error kind for this type error.
    pub fn type_error_kind(self) -> TypeErrorKind {
        self.kind
    }

    /// Extract the source location (span) of this type error.
    pub fn source_span(&self) -> Option<miette::SourceSpan> {
        match self.source_location {
            Some(_) => self.source_location,
            None => self.on_expr.as_ref().and_then(|e| e.source_span()),
        }
    }

    /// Deconstruct the type error into its kind and location.
    pub fn kind_and_location(self) -> (TypeErrorKind, Option<miette::SourceSpan>) {
        let span = self.source_span();
        (self.kind, span)
    }

    /// Construct a type error for when an unexpected type occurs in an expression.
    pub(crate) fn expected_one_of_types(
        on_expr: Expr,
        expected: impl IntoIterator<Item = Type>,
        actual: Type,
        help: Option<UnexpectedTypeHelp>,
    ) -> Self {
        Self {
            on_expr: Some(on_expr),
            source_location: None,
            kind: TypeErrorKind::UnexpectedType(UnexpectedType {
                expected: expected.into_iter().collect::<BTreeSet<_>>(),
                actual,
                help,
            }),
        }
    }

    /// Construct a type error for when a least upper bound cannot be found for
    /// a collection of types.
    pub(crate) fn incompatible_types(on_expr: Expr, types: impl IntoIterator<Item = Type>) -> Self {
        Self {
            on_expr: Some(on_expr),
            source_location: None,
            kind: TypeErrorKind::IncompatibleTypes(IncompatibleTypes {
                types: types.into_iter().collect::<BTreeSet<_>>(),
            }),
        }
    }

    pub(crate) fn unsafe_attribute_access(
        on_expr: Expr,
        attribute_access: AttributeAccess,
        suggestion: Option<String>,
        may_exist: bool,
    ) -> Self {
        Self {
            on_expr: Some(on_expr),
            source_location: None,
            kind: TypeErrorKind::UnsafeAttributeAccess(UnsafeAttributeAccess {
                attribute_access,
                suggestion,
                may_exist,
            }),
        }
    }

    pub(crate) fn unsafe_optional_attribute_access(
        on_expr: Expr,
        attribute_access: AttributeAccess,
    ) -> Self {
        Self {
            on_expr: Some(on_expr),
            source_location: None,
            kind: TypeErrorKind::UnsafeOptionalAttributeAccess(UnsafeOptionalAttributeAccess {
                attribute_access,
            }),
        }
    }

    pub(crate) fn impossible_policy(on_expr: Expr) -> Self {
        Self {
            on_expr: Some(on_expr),
            source_location: None,
            kind: TypeErrorKind::ImpossiblePolicy,
        }
    }

    pub(crate) fn undefined_extension(on_expr: Expr, name: String) -> Self {
        Self {
            on_expr: Some(on_expr),
            source_location: None,
            kind: TypeErrorKind::UndefinedFunction(UndefinedFunction { name }),
        }
    }

    pub(crate) fn multiply_defined_extension(on_expr: Expr, name: String) -> Self {
        Self {
            on_expr: Some(on_expr),
            source_location: None,
            kind: TypeErrorKind::MultiplyDefinedFunction(MultiplyDefinedFunction { name }),
        }
    }

    pub(crate) fn wrong_number_args(on_expr: Expr, expected: usize, actual: usize) -> Self {
        Self {
            on_expr: Some(on_expr),
            source_location: None,
            kind: TypeErrorKind::WrongNumberArguments(WrongNumberArguments { expected, actual }),
        }
    }

    pub(crate) fn arg_validation_error(on_expr: Expr, msg: String) -> Self {
        Self {
            on_expr: Some(on_expr),
            source_location: None,
            kind: TypeErrorKind::FunctionArgumentValidationError(FunctionArgumentValidationError {
                msg,
            }),
        }
    }

    pub(crate) fn empty_set_forbidden<T>(on_expr: Expr<T>) -> Self {
        Self {
            on_expr: None,
            source_location: on_expr.source_span(),
            kind: TypeErrorKind::EmptySetForbidden,
        }
    }

    pub(crate) fn non_lit_ext_constructor<T>(on_expr: Expr<T>) -> Self {
        Self {
            on_expr: None,
            source_location: on_expr.source_span(),
            kind: TypeErrorKind::NonLitExtConstructor,
        }
    }

    pub(crate) fn hierarchy_not_respected<T>(
        on_expr: Expr<T>,
        in_lhs: Option<Name>,
        in_rhs: Option<Name>,
    ) -> Self {
        Self {
            on_expr: None,
            source_location: on_expr.source_span(),
            kind: TypeErrorKind::HierarchyNotRespected(HierarchyNotRespected { in_lhs, in_rhs }),
        }
    }
}

/// Represents the different kinds of type errors and contains information
/// specific to that type error kind.
#[derive(Debug, Diagnostic, Error, Hash, Eq, PartialEq)]
#[non_exhaustive]
pub enum TypeErrorKind {
    /// The typechecker expected to see a subtype of one of the types in
    /// `expected`, but saw `actual`.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnexpectedType(UnexpectedType),
    /// The typechecker could not compute a least upper bound for `types`.
    #[error("unable to find upper bound for types: [{}]", .0.types.iter().join(","))]
    IncompatibleTypes(IncompatibleTypes),
    /// The typechecker detected an access to a record or entity attribute
    /// that it could not statically guarantee would be present.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnsafeAttributeAccess(UnsafeAttributeAccess),
    /// The typechecker could not conclude that an access to an optional
    /// attribute was safe.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnsafeOptionalAttributeAccess(UnsafeOptionalAttributeAccess),
    /// The typechecker found that a policy condition will always evaluate to false.
    #[error(
        "policy is impossible: the policy expression evaluates to false for all valid requests"
    )]
    ImpossiblePolicy,
    /// Undefined extension function.
    #[error("undefined extension function: {}", .0.name)]
    UndefinedFunction(UndefinedFunction),
    /// Multiply defined extension function.
    #[error("extension function defined multiple times: {}", .0.name)]
    MultiplyDefinedFunction(MultiplyDefinedFunction),
    /// Incorrect number of arguments in an extension function application.
    #[error("wrong number of arguments in extension function application. Expected {}, got {}", .0.expected, .0.actual)]
    WrongNumberArguments(WrongNumberArguments),
    /// Incorrect call style in an extension function application.
    #[error("wrong call style in extension function application. Expected {}, got {}", .0.expected, .0.actual)]
    WrongCallStyle(WrongCallStyle),
    /// Error returned by custom extension function argument validation
    #[error("error during extension function argument validation: {0}")]
    #[diagnostic(transparent)]
    FunctionArgumentValidationError(FunctionArgumentValidationError),
    #[error("empty set literals are forbidden in policies")]
    EmptySetForbidden,
    #[error("extension constructors may not be called with non-literal expressions")]
    NonLitExtConstructor,
    /// To pass strict validation a policy cannot contain an `in` expression
    /// where the entity type on the left might not be able to be a member of
    /// the entity type on the right.
    #[error(transparent)]
    #[diagnostic(transparent)]
    HierarchyNotRespected(HierarchyNotRespected),
}

/// Structure containing details about an unexpected type error.
#[derive(Diagnostic, Error, Debug, Hash, Eq, PartialEq)]
#[error("unexpected type: expected {} but saw {}",
    match .expected.iter().next() {
        Some(single) if .expected.len() == 1 => format!("{}", single),
        _ => .expected.iter().join(", or ")
    },
    .actual
)]
pub struct UnexpectedType {
    expected: BTreeSet<Type>,
    actual: Type,
    #[help]
    help: Option<UnexpectedTypeHelp>,
}

#[derive(Error, Debug, Hash, Eq, PartialEq)]
pub(crate) enum UnexpectedTypeHelp {
    #[error("try using `like` to examine the contents of a string")]
    TryUsingLike,
    #[error(
        "try using `contains`, `containsAny`, or `containsAll` to examine the contents of a set"
    )]
    TryUsingContains,
    #[error("try using `contains` to test if a single element is in a set")]
    TryUsingSingleContains,
    #[error("try using `has` to test for an attribute")]
    TryUsingHas,
    #[error("try using `is` to test for an entity type")]
    TryUsingIs,
    #[error("try using `in` for entity hierarchy membership")]
    TryUsingIn,
    #[error("Cedar only supports run time type tests for entities")]
    TypeTestNotSupported,
    #[error("Cedar does not support string concatenation")]
    ConcatenationNotSupported,
    #[error("Cedar does not support computing the union, intersection, or difference of sets")]
    SetOperationsNotSupported,
}

/// Structure containing details about an incompatible type error.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct IncompatibleTypes {
    pub(crate) types: BTreeSet<Type>,
}

/// Structure containing details about a missing attribute error.
#[derive(Debug, Hash, Eq, PartialEq, Error)]
#[error("attribute {attribute_access} not found")]
pub struct UnsafeAttributeAccess {
    attribute_access: AttributeAccess,
    suggestion: Option<String>,
    /// When this is true, the attribute might still exist, but the validator
    /// cannot guarantee that it will.
    may_exist: bool,
}

impl Diagnostic for UnsafeAttributeAccess {
    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        match (&self.suggestion, self.may_exist) {
            (Some(suggestion), false) => Some(Box::new(format!("did you mean `{suggestion}`?"))),
            (None, true) => Some(Box::new("there may be additional attributes that the validator is not able to reason about".to_string())),
            (Some(suggestion), true) => Some(Box::new(format!("did you mean `{suggestion}`? (there may also be additional attributes that the validator is not able to reason about)"))),
            (None, false) => None,
        }
    }
}

/// Structure containing details about an unsafe optional attribute error.
#[derive(Error, Diagnostic, Debug, Hash, Eq, PartialEq)]
#[error("unable to guarantee safety of access to optional attribute {attribute_access}")]
#[diagnostic(help("try testing for the attribute with `{} && ..`", attribute_access.suggested_has_guard()))]
pub struct UnsafeOptionalAttributeAccess {
    attribute_access: AttributeAccess,
}

/// Structure containing details about an undefined function error.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct UndefinedFunction {
    name: String,
}

/// Structure containing details about a multiply defined function error.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct MultiplyDefinedFunction {
    name: String,
}

/// Structure containing details about a wrong number of arguments error.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct WrongNumberArguments {
    expected: usize,
    actual: usize,
}

/// Structure containing details about a wrong call style error.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct WrongCallStyle {
    expected: CallStyle,
    actual: CallStyle,
}

/// Structure containing details about a function argument validation error.
#[derive(Debug, Hash, Eq, PartialEq, Diagnostic, Error)]
#[error("{msg}")]
pub struct FunctionArgumentValidationError {
    msg: String,
}

/// Structure containing details about a hierarchy not respected error
#[derive(Debug, Hash, Eq, PartialEq, Error)]
#[error("operands to `in` do not respect the entity hierarchy")]
pub struct HierarchyNotRespected {
    in_lhs: Option<Name>,
    in_rhs: Option<Name>,
}

impl Diagnostic for HierarchyNotRespected {
    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        match (&self.in_lhs, &self.in_rhs) {
            (Some(in_lhs), Some(in_rhs)) => Some(Box::new(format!(
                "`{in_lhs}` cannot be a descendant of `{in_rhs}`"
            ))),
            _ => None,
        }
    }
}

/// Contains more detailed information about an attribute access when it occurs
/// on an entity type expression or on the `context` variable. Track a `Vec` of
/// attributes rather than a single attribute so that on `principal.foo.bar` can
/// report that the record attribute `foo` of an entity type (e.g., `User`)
/// needs attributes `bar` instead of giving up when the immediate target of the
/// attribute access is not a entity.
#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) enum AttributeAccess {
    /// The attribute access is some sequence of attributes accesses eventually
    /// targeting an EntityLUB.
    EntityLUB(EntityLUB, Vec<SmolStr>),
    /// The attribute access is some sequence of attributes accesses eventually
    /// targeting the context variable. The context being accessed is identified
    /// by the `EntityUID` for the associated action.
    Context(EntityUID, Vec<SmolStr>),
    /// Other cases where we do not attempt to give more information about the
    /// access. This includes any access on the `AnyEntity` type and on record
    /// types other than the `context` variable.
    Other(Vec<SmolStr>),
}

impl AttributeAccess {
    pub(crate) fn from_expr(
        req_env: &RequestEnv,
        mut expr: &Expr<Option<Type>>,
    ) -> AttributeAccess {
        let mut attrs: Vec<SmolStr> = Vec::new();
        loop {
            if let Some(Type::EntityOrRecord(EntityRecordKind::Entity(lub))) = expr.data() {
                return AttributeAccess::EntityLUB(lub.clone(), attrs);
            } else if let ExprKind::Var(Var::Context) = expr.expr_kind() {
                return match req_env.action_entity_uid() {
                    Some(action) => AttributeAccess::Context(action.clone(), attrs),
                    None => AttributeAccess::Other(attrs),
                };
            } else if let ExprKind::GetAttr {
                expr: sub_expr,
                attr,
            } = expr.expr_kind()
            {
                expr = sub_expr;
                attrs.push(attr.clone());
            } else {
                return AttributeAccess::Other(attrs);
            }
        }
    }

    pub(crate) fn attrs(&self) -> &Vec<SmolStr> {
        match self {
            AttributeAccess::EntityLUB(_, attrs) => attrs,
            AttributeAccess::Context(_, attrs) => attrs,
            AttributeAccess::Other(attrs) => attrs,
        }
    }

    /// Construct a `has` expression that we can use to suggest a fix after an
    /// unsafe optional attribute access.
    pub(crate) fn suggested_has_guard(&self) -> String {
        // We know if this is an access directly on `context`, so we can suggest
        // specifically `context has ..`. Otherwise, we just use a generic `e`.
        let base_expr = match self {
            AttributeAccess::Context(_, _) => "context".into(),
            _ => "e".into(),
        };

        let (safe_attrs, err_attr) = match self.attrs().split_first() {
            Some((first, rest)) => (rest, first.clone()),
            // We should always have a least one attribute stored, so this
            // shouldn't be possible. If it does happen, just use a placeholder
            // attribute name `f` since we'd rather avoid panicking.
            None => (&[] as &[SmolStr], "f".into()),
        };

        let full_expr = std::iter::once(&base_expr)
            .chain(safe_attrs.iter().rev())
            .join(".");
        format!("{full_expr} has {err_attr}")
    }
}

impl Display for AttributeAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let attrs_str = self.attrs().iter().rev().join(".");
        match self {
            AttributeAccess::EntityLUB(lub, _) => write!(
                f,
                "`{attrs_str}` for entity type{}",
                match lub.get_single_entity() {
                    Some(single) => format!(" {}", single),
                    _ => format!("s {}", lub.iter().join(", ")),
                },
            ),
            AttributeAccess::Context(action, _) => {
                write!(f, "`{attrs_str}` in context for {action}",)
            }
            AttributeAccess::Other(_) => write!(f, "`{attrs_str}`"),
        }
    }
}
