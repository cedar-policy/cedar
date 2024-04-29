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

//! Contains utility functions for testing that expression typecheck or fail to
//! typecheck correctly.
#![cfg(test)]
// GRCOV_STOP_COVERAGE

// PANIC SAFETY unit tests
#![allow(clippy::panic)]
// PANIC SAFETY unit tests
#![allow(clippy::indexing_slicing)]

use cool_asserts::assert_matches;
use std::{collections::HashSet, sync::Arc};

use cedar_policy_core::ast::{EntityType, EntityUID, Expr, ExprShapeOnly, StaticPolicy, Template};

use super::{TypecheckAnswer, Typechecker};
use crate::{
    schema::ACTION_ENTITY_TYPE,
    type_error::TypeError,
    types::{EffectSet, OpenTag, RequestEnv, Type},
    NamespaceDefinition, UnexpectedTypeHelp, ValidationMode, ValidationWarning,
    ValidationWarningKind, ValidatorSchema,
};

impl TypeError {
    /// Testing utility for an unexpected type error when exactly one type was
    /// expected.
    #[cfg(test)]
    pub(crate) fn expected_type(
        on_expr: Expr,
        expected: Type,
        actual: Type,
        help: Option<UnexpectedTypeHelp>,
    ) -> Self {
        TypeError::expected_one_of_types(on_expr, vec![expected], actual, help)
    }
}

impl Type {
    /// Construct a named entity reference type using the `Name` resulting from
    /// parsing the `name` string. This function will panic on a parse error.
    pub(crate) fn named_entity_reference_from_str(name: &str) -> Type {
        Type::named_entity_reference(name.parse().unwrap_or_else(|_| {
            panic!("Expected that {} would be a valid entity type name.", name)
        }))
    }
}

impl Typechecker<'_> {
    /// Typecheck an expression outside the context of a policy. This is
    /// currently only used for testing.
    pub(crate) fn typecheck_expr<'a>(
        &self,
        e: &'a Expr,
        unique_type_errors: &mut HashSet<TypeError>,
    ) -> TypecheckAnswer<'a> {
        // Using bogus entity type names here for testing. They'll be treated as
        // having empty attribute records, so tests will behave as expected.
        let request_env = RequestEnv::DeclaredAction {
            principal: &EntityType::Specified(
                "Principal"
                    .parse()
                    .expect("Placeholder type \"Principal\" failed to parse as valid type name."),
            ),
            action: &EntityUID::with_eid_and_type(ACTION_ENTITY_TYPE, "action")
                .expect("ACTION_ENTITY_TYPE failed to parse as type name."),
            resource: &EntityType::Specified(
                "Resource"
                    .parse()
                    .expect("Placeholder type \"Resource\" failed to parse as valid type name."),
            ),
            context: &Type::record_with_attributes(None, OpenTag::ClosedAttributes),
            principal_slot: None,
            resource_slot: None,
        };
        let mut type_errors = Vec::new();
        let ans = self.typecheck(&request_env, &EffectSet::new(), e, &mut type_errors);
        unique_type_errors.extend(type_errors);
        ans
    }
}

/// Utility to execute a closure using a typechecker instance constructed
/// with a specific schema. A closure is used instead of returning the
/// typechecker because the typechecker structure needs a reference to a
/// schema, which is local to this function.
pub(crate) fn with_typechecker_from_schema<F>(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    fun: F,
) where
    F: FnOnce(Typechecker<'_>),
{
    let schema = schema.try_into().expect("Failed to construct schema.");
    let typechecker = Typechecker::new(&schema, ValidationMode::default());
    fun(typechecker);
}

/// Assert expected == actual by by asserting expected <: actual && actual <: expected.
/// In the future it might better to only assert actual <: expected to allow
/// improvement to the typechecker to return more specific types.
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_types_eq(schema: &ValidatorSchema, expected: &Type, actual: &Type) {
    assert!(
            Type::is_subtype(schema, expected, actual, ValidationMode::Permissive),
            "Type equality assertion failed: the expected type is not a subtype of the actual type.\nexpected: {:#?}\nactual: {:#?}", expected, actual);
    assert!(
            Type::is_subtype(schema, actual, expected, ValidationMode::Permissive),
             "Type equality assertion failed: the actual type is not a subtype of the expected type.\nexpected: {:#?}\nactual: {:#?}", expected, actual);
}

/// Assert that every TypeError in the expected list of type errors appears
/// in the expected list of type errors, and that the expected number of
/// type errors were generated. Equality of types in TypeErrors is
/// determined in the same way as in `assert_types_eq`.
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_expected_type_errors(expected: &Vec<TypeError>, actual: &HashSet<TypeError>) {
    expected.iter().for_each(|expected| {
            assert!(
                actual.iter().any(|actual| {
                     expected.kind == actual.kind && expected.on_expr.as_ref().map(ExprShapeOnly::new) == actual.on_expr.as_ref().map(ExprShapeOnly::new)
                }),
                "Expected generated type errors to contain {:#?}, but error was not found. The following errors were generated: {:#?}",
                expected,
                actual
            );
        });
    assert_eq!(
        expected.len(),
        actual.len(),
        "Unexpected type errors generated. Expected {:#?}, saw {:#?}.",
        expected,
        actual,
    );
}

/// Assert that every `ValidationWarningKind` in the expected list of warnings
/// appears in the expected list of warnings, and that the expected number of
/// warnings were generated.
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_expected_warnings(
    expected: &Vec<ValidationWarningKind>,
    actual: &HashSet<ValidationWarning>,
) {
    expected.iter().for_each(|expected| {
            assert!(
                actual.iter().any(|w| w.kind() == expected),
                "Expected generated warnings to contain {:#?}, but warning was not found. The following warnings were generated: {:#?}",
                expected,
                actual
            );
        });
    assert_eq!(
        expected.len(),
        actual.len(),
        "Unexpected warnings generated. Expected {:#?}, saw {:#?}.",
        expected,
        actual,
    );
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_policy_typechecks(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    policy: impl Into<Arc<Template>>,
) {
    assert_policy_typechecks_for_mode(schema, policy, ValidationMode::Strict)
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_policy_typechecks_for_mode(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    policy: impl Into<Arc<Template>>,
    mode: ValidationMode,
) {
    with_typechecker_from_schema(schema, |mut typechecker| {
        let policy: Arc<Template> = policy.into();
        typechecker.mode = mode;
        let mut type_errors: HashSet<TypeError> = HashSet::new();
        let mut warnings: HashSet<ValidationWarning> = HashSet::new();
        let typechecked = typechecker.typecheck_policy(&policy, &mut type_errors, &mut warnings);
        assert_eq!(type_errors, HashSet::new(), "Did not expect any errors.");
        assert!(typechecked, "Expected that policy would typecheck.");

        // Ensure that partial schema validation doesn't cause any policy that
        // should validate with a complete schema to no longer validate with the
        // same complete schema.
        typechecker.mode = ValidationMode::Permissive;
        let typechecked = typechecker.typecheck_policy(&policy, &mut type_errors, &mut warnings);
        assert_eq!(
            type_errors,
            HashSet::new(),
            "Did not expect any errors under partial schema validation."
        );
        assert!(
            typechecked,
            "Expected that policy would typecheck under partial schema validation."
        );
    });
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_policy_typecheck_fails(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    policy: impl Into<Arc<Template>>,
    expected_type_errors: Vec<TypeError>,
) {
    assert_policy_typecheck_fails_for_mode(
        schema,
        policy,
        expected_type_errors,
        ValidationMode::Strict,
    )
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_policy_typecheck_warns(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    policy: impl Into<Arc<Template>>,
    expected_warnings: Vec<ValidationWarningKind>,
) {
    assert_policy_typecheck_warns_for_mode(
        schema,
        policy,
        expected_warnings,
        ValidationMode::Strict,
    )
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_policy_typecheck_fails_for_mode(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    policy: impl Into<Arc<Template>>,
    expected_type_errors: Vec<TypeError>,
    mode: ValidationMode,
) {
    with_typechecker_from_schema(schema, |mut typechecker| {
        typechecker.mode = mode;
        let mut type_errors: HashSet<TypeError> = HashSet::new();
        let mut warnings: HashSet<ValidationWarning> = HashSet::new();
        let typechecked =
            typechecker.typecheck_policy(&policy.into(), &mut type_errors, &mut warnings);
        assert_expected_type_errors(&expected_type_errors, &type_errors);
        assert!(!typechecked, "Expected that policy would not typecheck.");
    });
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_policy_typecheck_warns_for_mode(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    policy: impl Into<Arc<Template>>,
    expected_warnings: Vec<ValidationWarningKind>,
    mode: ValidationMode,
) {
    with_typechecker_from_schema(schema, |mut typechecker| {
        typechecker.mode = mode;
        let mut type_errors: HashSet<TypeError> = HashSet::new();
        let mut warnings: HashSet<ValidationWarning> = HashSet::new();
        let policy = policy.into();
        let typechecked = typechecker.typecheck_policy(&policy, &mut type_errors, &mut warnings);
        assert_expected_warnings(&expected_warnings, &warnings);
        assert!(
            typechecked,
            "Expected that policy would typecheck (with warnings)."
        );
    });
}

/// Assert that expr type checks successfully with a particular type, and
/// that it does not generate any type errors.
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typechecks(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    expr: Expr,
    expected: Type,
) {
    assert_typechecks_for_mode(schema, expr, expected, ValidationMode::Strict);
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typechecks_for_mode(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    expr: Expr,
    expected: Type,
    mode: ValidationMode,
) {
    with_typechecker_from_schema(schema, |mut typechecker| {
        typechecker.mode = mode;
        let mut type_errors = HashSet::new();
        let actual = typechecker.typecheck_expr(&expr, &mut type_errors);
        assert_matches!(actual, TypecheckAnswer::TypecheckSuccess { expr_type, .. } => {
            assert_types_eq(typechecker.schema, &expected, &expr_type.into_data().expect("Typechecked expression must have type"));
        });
        assert_eq!(
            type_errors,
            HashSet::new(),
            "Did not expect any errors, saw {:#?}.",
            type_errors
        );
    });
}

/// Assert that typechecking fails, generating some `TypeErrors` for the
/// expressions. Failed type checking will still return a type that is used
/// to continue typechecking, so the `expected` type must match the returned
/// type for this to pass.
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typecheck_fails(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    expr: Expr,
    expected_ty: Option<Type>,
    expected_type_errors: Vec<TypeError>,
) {
    assert_typecheck_fails_for_mode(
        schema,
        expr,
        expected_ty,
        expected_type_errors,
        ValidationMode::Strict,
    )
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typecheck_fails_for_mode(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    expr: Expr,
    expected_ty: Option<Type>,
    expected_type_errors: Vec<TypeError>,
    mode: ValidationMode,
) {
    with_typechecker_from_schema(schema, |mut typechecker| {
        typechecker.mode = mode;
        let mut type_errors = HashSet::new();
        let actual = typechecker.typecheck_expr(&expr, &mut type_errors);
        assert_matches!(actual, TypecheckAnswer::TypecheckFail { expr_recovery_type } => {
            match (expected_ty.as_ref(), expr_recovery_type.data()) {
                (None, None) => (),
                (Some(expected_ty), Some(actual_ty)) => {
                    assert_types_eq(typechecker.schema, expected_ty, actual_ty);
                }
                _ => panic!("Expected that actual type would be defined iff expected type is defined."),
            }
            assert_expected_type_errors(&expected_type_errors, &type_errors);
        });
    });
}

pub(crate) fn static_to_template(p: StaticPolicy) -> Arc<Template> {
    let (t, _) = Template::link_static_policy(p);
    t
}

pub(crate) fn empty_schema_file() -> NamespaceDefinition {
    NamespaceDefinition::new([], [])
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typechecks_empty_schema(expr: Expr, expected: Type) {
    assert_typechecks(empty_schema_file(), expr, expected)
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typechecks_empty_schema_permissive(expr: Expr, expected: Type) {
    assert_typechecks_for_mode(
        empty_schema_file(),
        expr,
        expected,
        ValidationMode::Permissive,
    )
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typecheck_fails_empty_schema(
    expr: Expr,
    expected: Type,
    type_errors: Vec<TypeError>,
) {
    assert_typecheck_fails(empty_schema_file(), expr, Some(expected), type_errors);
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typecheck_fails_empty_schema_without_type(
    expr: Expr,
    type_errors: Vec<TypeError>,
) {
    assert_typecheck_fails(empty_schema_file(), expr, None, type_errors);
}
