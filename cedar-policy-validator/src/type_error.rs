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

use cedar_policy_core::{
    ast::{CallStyle, EntityUID, Expr, ExprKind, Name, Var},
    parser::SourceInfo,
};

use crate::types::{EntityLUB, EntityRecordKind, RequestEnv};

use super::types::Type;

use itertools::Itertools;
use smol_str::SmolStr;
use thiserror::Error;

/// The structure for type errors. A type errors knows the expression that
/// triggered the type error, as well as additional information for specific
/// kinds of type errors.
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct TypeError {
    // This struct has `on_expr` and `source_location` because many tests were
    // written to check that an error was raised on a particular expression
    // rather than at a source location. We can eliminate an AST clone by
    // dropping `on_expr` and rewriting test to check for the correct source
    // location.
    pub(crate) on_expr: Option<Expr>,
    pub(crate) source_location: Option<SourceInfo>,
    pub(crate) kind: TypeErrorKind,
}

impl TypeError {
    /// Extract the type error kind for this type error.
    pub fn type_error_kind(self) -> TypeErrorKind {
        self.kind_and_location().0
    }

    /// Extract the location of this type error.
    pub fn source_location(self) -> Option<SourceInfo> {
        self.kind_and_location().1
    }

    /// Deconstruct the type error into its kind and location.
    pub fn kind_and_location(self) -> (TypeErrorKind, Option<SourceInfo>) {
        (
            self.kind,
            match self.source_location {
                Some(_) => self.source_location,
                None => self.on_expr.and_then(|e| e.into_source_info()),
            },
        )
    }

    /// Construct a type error for when an unexpected type occurs in an expression.
    pub(crate) fn expected_one_of_types(
        on_expr: Expr,
        expected: impl IntoIterator<Item = Type>,
        actual: Type,
    ) -> Self {
        Self {
            on_expr: Some(on_expr),
            source_location: None,
            kind: TypeErrorKind::UnexpectedType(UnexpectedType {
                expected: expected.into_iter().collect::<BTreeSet<_>>(),
                actual,
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
            source_location: on_expr.into_source_info(),
            kind: TypeErrorKind::EmptySetForbidden,
        }
    }

    pub(crate) fn non_lit_ext_constructor<T>(on_expr: Expr<T>) -> Self {
        Self {
            on_expr: None,
            source_location: on_expr.into_source_info(),
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
            source_location: on_expr.into_source_info(),
            kind: TypeErrorKind::HierarchyNotRespected(HierarchyNotRespected { in_lhs, in_rhs }),
        }
    }
}

impl Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::error::Error for TypeError {}

/// Represents the different kinds of type errors and contains information
/// specific to that type error kind.
#[derive(Debug, Error, Hash, Eq, PartialEq)]
#[non_exhaustive]
pub enum TypeErrorKind {
    /// The typechecker expected to see a subtype of one of the types in
    /// `expected`, but saw `actual`.
    #[error("Unexpected type. Expected {} but saw {}",
        match .0.expected.iter().next() {
            Some(single) if .0.expected.len() == 1 => format!("{}", single),
            _ => .0.expected.iter().join(", or ")
        },
        .0.actual
    )]
    UnexpectedType(UnexpectedType),
    /// The typechecker could not compute a least upper bound for `types`.
    #[error("Unable to find upper bound for types: [{}]", .0.types.iter().join(","))]
    IncompatibleTypes(IncompatibleTypes),
    /// The typechecker detected an access to a record or entity attribute
    /// that it could not statically guarantee would be present.
    #[error(
        "attribute {} not found{}{}",
        .0.attribute_access,
        match &.0.suggestion {
            Some(suggestion) => format!(", did you mean `{suggestion}`"),
            None => "".to_string(),
        },
        if .0.may_exist {
            ". There may be additional attributes that the validator is not able to reason about."
        } else {
            ""
        }
    )]
    UnsafeAttributeAccess(UnsafeAttributeAccess),
    /// The typechecker could not conclude that an access to an optional
    /// attribute was safe.
    #[error("unable to guarantee safety of access to optional attribute {}", .0.attribute_access)]
    UnsafeOptionalAttributeAccess(UnsafeOptionalAttributeAccess),
    /// The typechecker found that a policy condition will always evaluate to false.
    #[error(
        "Policy is impossible. The policy expression evaluates to false for all valid requests"
    )]
    ImpossiblePolicy,
    /// Undefined extension function.
    #[error("Undefined extension function: {}", .0.name)]
    UndefinedFunction(UndefinedFunction),
    /// Multiply defined extension function.
    #[error("Extension function defined multiple times: {}", .0.name)]
    MultiplyDefinedFunction(MultiplyDefinedFunction),
    /// Incorrect number of arguments in an extension function application.
    #[error("Wrong number of arguments in extension function application. Expected {}, got {}", .0.expected, .0.actual)]
    WrongNumberArguments(WrongNumberArguments),
    /// Incorrect call style in an extension function application.
    #[error("Wrong call style in extension function application. Expected {}, got {}", .0.expected, .0.actual)]
    WrongCallStyle(WrongCallStyle),
    /// Error returned by custom extension function argument validation
    #[error("Error during extension function argument validation: {}", .0.msg)]
    FunctionArgumentValidationError(FunctionArgumentValidationError),
    #[error("empty set literals are forbidden in policies")]
    EmptySetForbidden,
    #[error("extension constructors may not be called with non-literal expressions")]
    NonLitExtConstructor,
    /// To pass strict validation a policy cannot contain an `in` expression
    /// where the entity type on the left might not be able to be a member of
    /// the entity type on the right.
    #[error("operands to `in` do not respect the entity hierarchy{}",
        match (&.0.in_lhs, &.0.in_rhs) {
            (Some(in_lhs), Some(in_rhs)) => format!(". `{}` is not a descendant of `{}`", in_lhs, in_rhs),
            _ => "".to_string(),
        })]
    HierarchyNotRespected(HierarchyNotRespected),
}

/// Structure containing details about an unexpected type error.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct UnexpectedType {
    expected: BTreeSet<Type>,
    actual: Type,
}

/// Structure containing details about an incompatible type error.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct IncompatibleTypes {
    pub(crate) types: BTreeSet<Type>,
}

/// Structure containing details about a missing attribute error.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct UnsafeAttributeAccess {
    attribute_access: AttributeAccess,
    suggestion: Option<String>,
    /// When this is true, the attribute might still exist, but the validator
    /// cannot guarantee that it will.
    may_exist: bool,
}

/// Structure containing details about an unsafe optional attribute error.
#[derive(Debug, Hash, Eq, PartialEq)]
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
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct FunctionArgumentValidationError {
    msg: String,
}

/// Structure containing details about a hierarchy not respected error
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct HierarchyNotRespected {
    in_lhs: Option<Name>,
    in_rhs: Option<Name>,
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
                return AttributeAccess::Context(req_env.action.clone(), attrs);
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
}

impl Display for AttributeAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttributeAccess::EntityLUB(lub, attrs) => write!(
                f,
                "`{}` for entity type{}",
                attrs.iter().rev().join("."),
                match lub.get_single_entity() {
                    Some(single) => format!(" {}", single),
                    _ => format!("s {}", lub.iter().join(", ")),
                },
            ),
            AttributeAccess::Context(action, attrs) => write!(
                f,
                "`{}` in context for {}",
                attrs.iter().rev().join("."),
                action
            ),
            AttributeAccess::Other(attrs) => write!(f, "`{}`", attrs.iter().rev().join(".")),
        }
    }
}
