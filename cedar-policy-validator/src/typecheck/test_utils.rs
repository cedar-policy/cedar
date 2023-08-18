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

//! Contains utility functions for testing that expression typecheck or fail to
//! typecheck correctly.
#![cfg(test)]
// GRCOV_STOP_COVERAGE

use std::{collections::HashSet, sync::Arc};

use cedar_policy_core::ast::{EntityType, EntityUID, Expr, ExprShapeOnly, StaticPolicy, Template};

use crate::{
    schema::ACTION_ENTITY_TYPE,
    type_error::TypeError,
    types::{Attributes, EffectSet, RequestEnv, Type},
    NamespaceDefinition, ValidationMode, ValidatorSchema,
};

use super::{TypecheckAnswer, Typechecker};

impl TypeError {
    /// Testing utility for an unexpected type error when exactly one type was
    /// expected.
    #[cfg(test)]
    pub(crate) fn expected_type(on_expr: Expr, expected: Type, actual: Type) -> Self {
        TypeError::expected_one_of_types(on_expr, vec![expected], actual)
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
        let request_env = RequestEnv {
            principal: &EntityType::Concrete(
                "Principal"
                    .parse()
                    .expect("Placeholder type \"Principal\" failed to parse as valid type name."),
            ),
            action: &EntityUID::with_eid_and_type(ACTION_ENTITY_TYPE, "action")
                .expect("ACTION_ENTITY_TYPE failed to parse as type name."),
            resource: &EntityType::Concrete(
                "Resource"
                    .parse()
                    .expect("Placeholder type \"Resource\" failed to parse as valid type name."),
            ),
            context: &Attributes::with_attributes(None),
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
pub(crate) fn assert_types_eq(schema: &ValidatorSchema, expected: &Type, actual: &Type) {
    assert!(
            Type::is_subtype(schema, expected, actual),
            "Type equality assertion failed: the expected type is not a subtype of the actual type.\nexpected: {:#?}\nactual: {:#?}", expected, actual);
    assert!(
            Type::is_subtype(schema, actual, expected),
             "Type equality assertion failed: the actual type is not a subtype of the expected type.\nexpected: {:#?}\nactual: {:#?}", expected, actual);
}

/// Assert that every TypeError in the expected list of type errors appears
/// in the expected list of type errors, and that the expected number of
/// type errors were generated. Equality of types in TypeErrors is
/// determined in the same way as in `assert_types_eq`.
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

pub(crate) fn assert_policy_typechecks(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    policy: impl Into<Arc<Template>>,
) {
    with_typechecker_from_schema(schema, |typechecker| {
        let mut type_errors: HashSet<TypeError> = HashSet::new();
        let typechecked = typechecker.typecheck_policy(&policy.into(), &mut type_errors);
        assert_eq!(type_errors, HashSet::new(), "Did not expect any errors.");
        assert!(typechecked, "Expected that policy would typecheck.");
    });
}

pub(crate) fn assert_policy_typecheck_fails(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    policy: impl Into<Arc<Template>>,
    expected_type_errors: Vec<TypeError>,
) {
    with_typechecker_from_schema(schema, |typechecker| {
        let mut type_errors: HashSet<TypeError> = HashSet::new();
        let typechecked = typechecker.typecheck_policy(&policy.into(), &mut type_errors);
        assert_expected_type_errors(&expected_type_errors, &type_errors);
        assert!(!typechecked, "Expected that policy would not typecheck.");
    });
}

/// Assert that expr type checks successfully with a particular type, and
/// that it does not generate any type errors.
pub(crate) fn assert_typechecks(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    expr: Expr,
    expected: Type,
) {
    with_typechecker_from_schema(schema, |typechecker| {
        let mut type_errors = HashSet::new();
        let actual = typechecker.typecheck_expr(&expr, &mut type_errors);
        assert_types_eq(
            typechecker.schema,
            &expected,
            &match actual {
                TypecheckAnswer::TypecheckSuccess { expr_type, .. } => expr_type
                    .into_data()
                    .expect("Typechecked expression must have type."),
                TypecheckAnswer::TypecheckFail { .. } => {
                    panic!(
                        "Expected that expression would typecheck. Errors: {}",
                        type_errors
                            .iter()
                            .map(|e| format!("{:#?}", e))
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                }
                TypecheckAnswer::RecursionLimit => panic!("Should not have hit recursion limit"),
            },
        );
        assert!(
            type_errors.is_empty(),
            "Did not expect any errors, saw {:#?}.",
            type_errors
        );
    });
}

/// Assert that typechecking fails, generating some `TypeErrors` for the
/// expressions. Failed type checking will still return a type that is used
/// to continue typechecking, so the `expected` type must match the returned
/// type for this to pass.
pub(crate) fn assert_typecheck_fails(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    expr: Expr,
    expected_ty: Option<Type>,
    expected_type_errors: Vec<TypeError>,
) {
    with_typechecker_from_schema(schema, |typechecker| {
        let mut type_errors = HashSet::new();
        let actual = typechecker.typecheck_expr(&expr, &mut type_errors);
        let actual_ty = match actual {
            TypecheckAnswer::TypecheckSuccess { .. } => {
                panic!("Expected that expression would not typecheck.")
            }
            TypecheckAnswer::TypecheckFail { expr_recovery_type } => expr_recovery_type,
            TypecheckAnswer::RecursionLimit => panic!("Should not have hit recursion limit"),
        };
        match (expected_ty.as_ref(), actual_ty.data()) {
            (None, None) => (),
            (Some(expected_ty), Some(actual_ty)) => {
                assert_types_eq(typechecker.schema, expected_ty, actual_ty)
            }
            _ => panic!("Expected that actual type would be defined iff expected type is defined."),
        }
        assert_expected_type_errors(&expected_type_errors, &type_errors);
    });
}

pub(crate) fn static_to_template(p: StaticPolicy) -> Arc<Template> {
    let (t, _) = Template::link_static_policy(p);
    t
}

pub(crate) fn empty_schema_file() -> NamespaceDefinition {
    NamespaceDefinition::new([], [])
}

pub(crate) fn assert_typechecks_empty_schema(expr: Expr, expected: Type) {
    assert_typechecks(empty_schema_file(), expr, expected)
}

pub(crate) fn assert_typecheck_fails_empty_schema(
    expr: Expr,
    expected: Type,
    type_errors: Vec<TypeError>,
) {
    assert_typecheck_fails(empty_schema_file(), expr, Some(expected), type_errors);
}

pub(crate) fn assert_typecheck_fails_empty_schema_without_type(
    expr: Expr,
    type_errors: Vec<TypeError>,
) {
    assert_typecheck_fails(empty_schema_file(), expr, None, type_errors);
}
