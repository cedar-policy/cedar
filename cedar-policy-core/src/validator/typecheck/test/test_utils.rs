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

use cool_asserts::assert_matches;
use itertools::Itertools;
use std::{collections::HashSet, hash::Hash, sync::Arc};

use crate::ast::{EntityUID, Expr, PolicyID, Template, ACTION_ENTITY_TYPE};
use crate::extensions::Extensions;
use crate::parser::Loc;

use crate::validator::{
    json_schema,
    typecheck::{SingleEnvTypechecker, TypecheckAnswer, Typechecker},
    types::{CapabilitySet, OpenTag, RequestEnv, Type},
    validation_errors::UnexpectedTypeHelp,
    NamespaceDefinitionWithActionAttributes, RawName, ValidationError, ValidationMode,
    ValidationWarning, ValidatorSchema,
};

use similar_asserts::assert_eq;

// Placeholder policy id for use when typechecking an expression directly.
pub fn expr_id_placeholder() -> PolicyID {
    PolicyID::from_string("expr")
}

/// Get `Loc` corresponding to `snippet` in `src`. Returns an option because we
/// always want an `Option<Loc>` instead of a `Loc`. Panics if `snippet` is not
/// in `src` to fail fast in tests.
#[track_caller]
pub fn get_loc(src: impl AsRef<str>, snippet: impl AsRef<str>) -> Option<Loc> {
    let start = src
        .as_ref()
        .find(snippet.as_ref())
        .expect("Snippet does not exist in source!");
    let end = start + snippet.as_ref().len();
    Some(Loc::new(start..end, src.as_ref().into()))
}

impl ValidationError {
    /// Testing utility for an unexpected type error when exactly one type was
    /// expected.
    pub(crate) fn expected_type(
        source_loc: Option<Loc>,
        policy_id: PolicyID,
        expected: Type,
        actual: Type,
        help: Option<UnexpectedTypeHelp>,
    ) -> Self {
        ValidationError::expected_one_of_types(source_loc, policy_id, vec![expected], actual, help)
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
    ///
    /// `policy_id`: Policy ID to associate with this `Expr`, for the purposes
    /// of reporting the policy ID in validation errors
    pub(crate) fn typecheck_expr<'a>(
        &self,
        e: &'a Expr,
        policy_id: &'a PolicyID,
        unique_type_errors: &mut HashSet<ValidationError>,
    ) -> TypecheckAnswer<'a> {
        // Using bogus entity type names here for testing. They'll be treated as
        // having empty attribute records, so tests will behave as expected.
        let request_env = RequestEnv::DeclaredAction {
            principal: &"Principal"
                .parse()
                .expect("Placeholder type \"Principal\" failed to parse as valid type name."),
            action: &EntityUID::with_eid_and_type(ACTION_ENTITY_TYPE, "action")
                .expect("ACTION_ENTITY_TYPE failed to parse as type name."),
            resource: &"Resource"
                .parse()
                .expect("Placeholder type \"Resource\" failed to parse as valid type name."),
            context: &Type::record_with_attributes(None, OpenTag::ClosedAttributes),
            principal_slot: None,
            resource_slot: None,
        };
        let typechecker = SingleEnvTypechecker {
            schema: self.schema,
            extensions: self.extensions,
            mode: self.mode,
            policy_id,
            request_env: &request_env,
        };
        let mut type_errors = Vec::new();
        let ans = typechecker.typecheck(&CapabilitySet::new(), e, &mut type_errors);
        unique_type_errors.extend(type_errors);
        ans
    }
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

/// Assert that every `T` in `actual` appears in `expected`, and vice versa.
#[track_caller]
pub(crate) fn assert_sets_equal<T: Hash + Eq + std::fmt::Debug>(
    expected: impl IntoIterator<Item = T>,
    actual: impl IntoIterator<Item = T>,
) {
    assert_eq!(
        expected.into_iter().collect::<HashSet<_>>(),
        actual.into_iter().collect::<HashSet<_>>(),
    );
}

/// Unifies a bunch of different ways we specify schemas in tests
pub(crate) trait SchemaProvider {
    /// Produce the schema, panicking (with a nice error message as appropriate) if it is not a valid schema.
    fn schema(self) -> ValidatorSchema;
}

impl SchemaProvider for ValidatorSchema {
    fn schema(self) -> ValidatorSchema {
        self
    }
}

impl SchemaProvider for json_schema::Fragment<RawName> {
    fn schema(self) -> ValidatorSchema {
        self.try_into()
            .unwrap_or_else(|e| panic!("failed to construct schema: {:?}", miette::Report::new(e)))
    }
}

impl SchemaProvider for json_schema::NamespaceDefinition<RawName> {
    fn schema(self) -> ValidatorSchema {
        self.try_into()
            .unwrap_or_else(|e| panic!("failed to construct schema: {:?}", miette::Report::new(e)))
    }
}

impl SchemaProvider for NamespaceDefinitionWithActionAttributes<RawName> {
    fn schema(self) -> ValidatorSchema {
        self.try_into()
            .unwrap_or_else(|e| panic!("failed to construct schema: {:?}", miette::Report::new(e)))
    }
}

impl SchemaProvider for &str {
    fn schema(self) -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(self, Extensions::all_available())
            .unwrap_or_else(|e| panic!("failed to construct schema: {:?}", miette::Report::new(e)))
            .0
    }
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_policy_typechecks(
    schema: impl SchemaProvider,
    policy: impl Into<Arc<Template>>,
) {
    assert_policy_typechecks_for_mode(schema, policy, ValidationMode::Strict)
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_policy_typechecks_for_mode(
    schema: impl SchemaProvider,
    policy: impl Into<Arc<Template>>,
    mode: ValidationMode,
) {
    let policy = policy.into();
    let schema = schema.schema();
    let mut typechecker = Typechecker::new(&schema, mode);
    let mut type_errors: HashSet<ValidationError> = HashSet::new();
    let mut warnings: HashSet<ValidationWarning> = HashSet::new();
    let typechecked = typechecker.typecheck_policy(&policy, &mut type_errors, &mut warnings);
    if !type_errors.is_empty() {
        let mut pretty_type_errors = type_errors
            .into_iter()
            .map(|e| format!("{:?}", miette::Report::new(e)));
        panic!(
            "typechecking failed with mode {:?}:\n\n{}",
            typechecker.mode,
            pretty_type_errors.join("\n\n")
        );
    }
    assert!(
        typechecked,
        "Unexpected failure with mode {:?}: no errors, but typechecker reported failure",
        typechecker.mode
    );

    // Ensure that partial schema validation doesn't cause any policy that
    // should validate with a complete schema to no longer validate with the
    // same complete schema.
    typechecker.mode = ValidationMode::Permissive;
    let typechecked = typechecker.typecheck_policy(&policy, &mut type_errors, &mut warnings);
    if !type_errors.is_empty() {
        let mut pretty_type_errors = type_errors
            .into_iter()
            .map(|e| format!("{:?}", miette::Report::new(e)));
        panic!(
            "typechecking failed with mode {:?}:\n\n{}",
            typechecker.mode,
            pretty_type_errors.join("\n\n")
        );
    }
    assert!(
        typechecked,
        "Unexpected failure with mode {:?}: no errors, but typechecker reported failure",
        typechecker.mode
    );
}

/// Assert that the policy fails to typecheck, and return a `HashSet` of the validation errors encountered
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_policy_typecheck_fails(
    schema: impl SchemaProvider,
    policy: impl Into<Arc<Template>>,
) -> HashSet<ValidationError> {
    assert_policy_typecheck_fails_for_mode(schema, policy, ValidationMode::Strict)
}

/// Assert that the policy typechecks successfully, but returns warnings.
/// Returns a `HashSet` of the validation warnings encountered (which will not be empty)
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_policy_typecheck_warns(
    schema: impl SchemaProvider,
    policy: impl Into<Arc<Template>>,
) -> HashSet<ValidationWarning> {
    assert_policy_typecheck_warns_for_mode(schema, policy, ValidationMode::Strict)
}

/// Assert that the policy fails to typecheck, and return a `HashSet` of the validation errors encountered
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_policy_typecheck_fails_for_mode(
    schema: impl SchemaProvider,
    policy: impl Into<Arc<Template>>,
    mode: ValidationMode,
) -> HashSet<ValidationError> {
    let policy = policy.into();
    let schema = schema.schema();
    let typechecker = Typechecker::new(&schema, mode);
    let mut type_errors: HashSet<ValidationError> = HashSet::new();
    let mut warnings: HashSet<ValidationWarning> = HashSet::new();
    let typechecked = typechecker.typecheck_policy(&policy, &mut type_errors, &mut warnings);
    assert!(!typechecked, "Expected that policy would not typecheck.");
    type_errors
}

/// Assert that the policy typechecks successfully, but returns warnings.
/// Returns a `HashSet` of the validation warnings encountered (which will not be empty)
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_policy_typecheck_warns_for_mode(
    schema: impl SchemaProvider,
    policy: impl Into<Arc<Template>>,
    mode: ValidationMode,
) -> HashSet<ValidationWarning> {
    let policy = policy.into();
    let schema = schema.schema();
    let typechecker = Typechecker::new(&schema, mode);
    let mut type_errors: HashSet<ValidationError> = HashSet::new();
    let mut warnings: HashSet<ValidationWarning> = HashSet::new();
    let typechecked = typechecker.typecheck_policy(&policy, &mut type_errors, &mut warnings);
    assert!(
        typechecked,
        "Expected that policy would typecheck (with warnings)."
    );
    assert!(
        !warnings.is_empty(),
        "Expected that policy would produce a warning, but found none"
    );
    warnings
}

/// Assert that expr type checks successfully with a particular type, and
/// that it does not generate any type errors.
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typechecks(schema: impl SchemaProvider, expr: &Expr, expected: &Type) {
    assert_typechecks_for_mode(schema, expr, expected, ValidationMode::Strict);
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typechecks_for_mode(
    schema: impl SchemaProvider,
    expr: &Expr,
    expected: &Type,
    mode: ValidationMode,
) {
    let schema = schema.schema();
    let typechecker = Typechecker::new(&schema, mode);
    let mut type_errors = HashSet::new();
    let pid = expr_id_placeholder();
    let actual = typechecker.typecheck_expr(expr, &pid, &mut type_errors);
    assert_matches!(actual, TypecheckAnswer::TypecheckSuccess { expr_type, .. } => {
        assert_types_eq(typechecker.schema, expected, &expr_type.into_data().expect("Typechecked expression must have type"));
    });
    assert_eq!(
        type_errors,
        HashSet::new(),
        "Did not expect any errors, saw {:#?}.",
        type_errors
    );
}

/// Assert that typechecking fails for the given `Expr`, and return a `HashSet`
/// of the `ValidationErrors` encountered.
///
/// Failed typechecking still returns a type that is used to continue
/// typechecking; this method also checks that this returned type matches
/// `expected_ty`.
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typecheck_fails(
    schema: impl SchemaProvider,
    expr: &Expr,
    expected_ty: Option<&Type>,
) -> HashSet<ValidationError> {
    assert_typecheck_fails_for_mode(schema, expr, expected_ty, ValidationMode::Strict)
}

/// Assert that typechecking fails for the given `Expr`, and return a `HashSet`
/// of the `ValidationErrors` encountered.
///
/// Failed typechecking still returns a type that is used to continue
/// typechecking; this method also checks that this returned type matches
/// `expected_ty`.
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typecheck_fails_for_mode(
    schema: impl SchemaProvider,
    expr: &Expr,
    expected_ty: Option<&Type>,
    mode: ValidationMode,
) -> HashSet<ValidationError> {
    let schema = schema.schema();
    let typechecker = Typechecker::new(&schema, mode);
    let mut type_errors = HashSet::new();
    let pid = expr_id_placeholder();
    let actual = typechecker.typecheck_expr(expr, &pid, &mut type_errors);
    assert_matches!(actual, TypecheckAnswer::TypecheckFail { expr_recovery_type } => {
        match (expected_ty.as_ref(), expr_recovery_type.data()) {
            (None, None) => (),
            (Some(expected_ty), Some(actual_ty)) => {
                assert_types_eq(typechecker.schema, expected_ty, actual_ty);
            }
            _ => panic!("Expected that actual type would be defined iff expected type is defined."),
        }
    });
    type_errors
}

pub(crate) fn empty_schema_file() -> json_schema::NamespaceDefinition<RawName> {
    json_schema::NamespaceDefinition::new([], [])
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typechecks_empty_schema(expr: &Expr, expected: &Type) {
    assert_typechecks(empty_schema_file(), expr, expected)
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typechecks_empty_schema_permissive(expr: &Expr, expected: &Type) {
    assert_typechecks_for_mode(
        empty_schema_file(),
        expr,
        expected,
        ValidationMode::Permissive,
    )
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typecheck_fails_empty_schema(
    expr: &Expr,
    expected: &Type,
) -> HashSet<ValidationError> {
    assert_typecheck_fails(empty_schema_file(), expr, Some(expected))
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typecheck_fails_empty_schema_without_type(
    expr: &Expr,
) -> HashSet<ValidationError> {
    assert_typecheck_fails(empty_schema_file(), expr, None)
}

/// Assert that the given `HashSet` has exactly one `Diagnostic`. Return it.
/// If there are more than one, panic and display all the `Diagnostic`s in pretty format.
#[track_caller]
pub(crate) fn assert_exactly_one_diagnostic<T: miette::Diagnostic + Send + Sync + 'static>(
    set: HashSet<T>,
) -> T {
    match set.len() {
        0 => panic!("expected exactly one error, but got no errors"),
        1 => set.into_iter().next().unwrap(),
        2.. => panic!(
            "expected exactly one error, but got {}:\n\n{}",
            set.len(),
            set.into_iter()
                .map(|e| format!("{:?}", &miette::Report::new(e)))
                .join("\n\n")
        ),
    }
}
