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

//! Contains test for typechecking with partial schema files.

use std::collections::HashSet;

use cedar_policy_core::ast::{PolicyID, StaticPolicy, Template};
use cedar_policy_core::parser::parse_policy;

use super::test_utils::{assert_sets_equal, empty_schema_file, get_loc};
use crate::json_schema;
use crate::typecheck::Typechecker;
use crate::types::{EntityLUB, Type};
use crate::validation_errors::{AttributeAccess, UnexpectedTypeHelp};
use crate::{RawName, ValidationError, ValidationMode, ValidationWarning, ValidatorSchema};

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_partial_typecheck(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    policy: StaticPolicy,
) {
    let schema = schema.try_into().expect("Failed to construct schema.");
    let typechecker = Typechecker::new(&schema, ValidationMode::Partial);
    let mut errors: HashSet<ValidationError> = HashSet::new();
    let mut warnings: HashSet<ValidationWarning> = HashSet::new();
    let typechecked = typechecker.typecheck_policy(
        &Template::link_static_policy(policy).0,
        &mut errors,
        &mut warnings,
    );
    assert_eq!(errors, HashSet::new(), "Did not expect any errors.");
    assert!(typechecked, "Expected that policy would typecheck.");
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_partial_typecheck_fails(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    policy: StaticPolicy,
    expected_errors: impl IntoIterator<Item = ValidationError>,
) {
    let schema = schema.try_into().expect("Failed to construct schema.");
    let typechecker = Typechecker::new(&schema, ValidationMode::Partial);
    let mut errors: HashSet<ValidationError> = HashSet::new();
    let mut warnings: HashSet<ValidationWarning> = HashSet::new();
    let typechecked = typechecker.typecheck_policy(
        &Template::link_static_policy(policy).0,
        &mut errors,
        &mut warnings,
    );
    assert_sets_equal(expected_errors, errors);
    assert!(!typechecked, "Expected that policy would not typecheck.");
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_partial_typecheck_warns(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    policy: StaticPolicy,
    expected_warnings: impl IntoIterator<Item = ValidationWarning>,
) {
    let schema = schema.try_into().expect("Failed to construct schema.");
    let typechecker = Typechecker::new(&schema, ValidationMode::Partial);
    let mut errors: HashSet<ValidationError> = HashSet::new();
    let mut warnings: HashSet<ValidationWarning> = HashSet::new();
    let typechecked = typechecker.typecheck_policy(
        &Template::link_static_policy(policy).0,
        &mut errors,
        &mut warnings,
    );
    assert_sets_equal(warnings, expected_warnings);
    assert!(
        typechecked,
        "Expected that policy would typecheck (with warnings)."
    );
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typechecks_empty_schema(policy: StaticPolicy) {
    assert_partial_typecheck(empty_schema_file(), policy)
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typecheck_fails_empty_schema(
    policy: StaticPolicy,
    expected_type_errors: impl IntoIterator<Item = ValidationError>,
) {
    assert_partial_typecheck_fails(empty_schema_file(), policy, expected_type_errors)
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typecheck_warns_empty_schema(
    policy: StaticPolicy,
    expected_warnings: impl IntoIterator<Item = ValidationWarning>,
) {
    assert_partial_typecheck_warns(empty_schema_file(), policy, expected_warnings)
}

mod passes_empty_schema {

    use super::*;

    #[test]
    fn principal_attr() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { principal.is_admin };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn action_attr() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) unless { action.is_restricted };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn resource_attr() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { resource.is_public };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn literal_attr() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { User::"alice".is_admin };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn get_nested_attr() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { resource.foo.bar.baz.buz };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn principal_has_attr() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { principal has is_admin };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn action_has_attr() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) unless { action has is_restricted };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn resource_has_attr() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { resource has is_public };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn literal_has_attr() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { User::"alice" has is_admin };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn has_nested_attr() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { resource.foo has bar };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn principal_eq() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal == User::"alice", action, resource);"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn action_eq() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action == Action::"view", resource);"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn resource_eq() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource == Photo::"vacation.jpg");"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn principal_in() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal in User::"alice", action, resource);"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn action_in() {
        // Test case with `in` are  interesting because, for an undeclared
        // entity type or action we don't know what should be `in` it, so the
        // expression has type boolean (not known to be true or false).
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action in Action::"view", resource);"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn resource_in() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource in Photo::"vacation.jpg");"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn principal_in_set() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when {  principal in [User::"alice", Admin::"bob"] };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn action_in_set() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action in [Action::"view", Action::"edit"], resource);"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn in_attr() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { principal in resource.owner };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn attr_in() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { resource.owner in principal };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn resource_in_set() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { resource in [Photo::"vacation.jpg", Album::"vacation_photos"] } ;"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn if_both_branches_undefined() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { if principal.foo then action.bar else resource.bar };"#
            )
            .unwrap(),
        );
    }

    #[test]
    fn if_one_branch_undefined() {
        assert_typechecks_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { 0 < (if principal.foo then action.bar else 1) };"#
            )
            .unwrap(),
        );
    }

    #[test]
    fn context_attr() {
        let p = parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { context.foo };"#,
        )
        .expect("Policy should parse.");
        assert_typechecks_partial_schema(p);
        let p = parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { context.foo.bar };"#,
        )
        .expect("Policy should parse.");
        assert_typechecks_partial_schema(p);
    }
}

mod fails_empty_schema {
    use cedar_policy_core::{ast::PolicyID, extensions::Extensions};

    use crate::types::Type;

    use super::*;

    #[test]
    fn operator_type_error() {
        // We expect to see a type error for the incorrect literal argument to
        // various operators. No error should be generated for missing
        // attributes or the type of the attributes.
        let extensions = Extensions::all_available();
        let src = r#"permit(principal, action, resource) when { principal.foo > "a" };"#;
        assert_typecheck_fails_empty_schema(
            parse_policy(None, src).unwrap(),
            [ValidationError::expected_one_of_types(
                get_loc(src, r#""a""#),
                PolicyID::from_string("policy0"),
                extensions
                    .types_with_operator_overloading()
                    .cloned()
                    .map(Type::extension)
                    .chain(std::iter::once(Type::primitive_long()))
                    .collect(),
                Type::primitive_string(),
                None,
            )],
        );

        let src = r#"permit(principal, action, resource) when { 1.contains(principal.foo) };"#;
        assert_typecheck_fails_empty_schema(
            parse_policy(None, src).unwrap(),
            [ValidationError::expected_type(
                get_loc(src, "1"),
                PolicyID::from_string("policy0"),
                Type::any_set(),
                Type::primitive_long(),
                None,
            )],
        );

        let src = r#"permit(principal, action, resource) when { principal.foo.containsAll(1) };"#;
        assert_typecheck_fails_empty_schema(
            parse_policy(None, src).unwrap(),
            [ValidationError::expected_type(
                get_loc(src, "1"),
                PolicyID::from_string("policy0"),
                Type::any_set(),
                Type::primitive_long(),
                Some(UnexpectedTypeHelp::TryUsingSingleContains),
            )],
        );
    }

    #[test]
    fn top_level_type_error() {
        let src = r#"permit(principal, action, resource) when { principal.foo + 1 };"#;
        assert_typecheck_fails_empty_schema(
            parse_policy(None, src).unwrap(),
            [ValidationError::expected_type(
                get_loc(src, "principal.foo + 1"),
                PolicyID::from_string("policy0"),
                Type::primitive_boolean(),
                Type::primitive_long(),
                None,
            )],
        )
    }

    #[test]
    fn impossible_policy() {
        let src = r#"permit(principal, action, resource) when { resource.bar && false };"#;
        let p = parse_policy(None, src).unwrap();
        assert_typecheck_warns_empty_schema(
            p,
            [ValidationWarning::impossible_policy(
                get_loc(src, src),
                PolicyID::from_string("policy0"),
            )],
        )
    }

    #[test]
    fn record_lit_bad_attr() {
        let src = r#"permit(principal, action, resource) when { {foo: 1}.bar };"#;
        let p = parse_policy(None, src).unwrap();
        assert_typecheck_fails_empty_schema(
            p,
            [ValidationError::unsafe_attribute_access(
                get_loc(src, "{foo: 1}.bar"),
                PolicyID::from_string("policy0"),
                AttributeAccess::Other(vec!["bar".into()]),
                Some("foo".into()),
                false,
            )],
        )
    }
}

fn partial_schema_file() -> json_schema::NamespaceDefinition<RawName> {
    serde_json::from_value(serde_json::json!(
        {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Group" ],
                    "shape": {
                        "type": "Record",
                        "additionalAttributes": true,
                        "attributes": {
                            "name": { "type": "String", "required": true},
                            "age": { "type": "Long", "required": true},
                            "favorite": { "type": "Entity", "name": "Photo", "required": true}
                        }
                    }
                },
                "Group": {
                    "shape": {
                        "type": "Record",
                        "additionalAttributes": false,
                        "attributes": {}
                    }
                },
                "Photo": {
                    "shape": {
                        "type": "Record",
                        "additionalAttributes": true,
                        "attributes": {}
                    }
                }
            },
            "actions": {
                "view_photo": {
                    "appliesTo": {
                        "principalTypes": ["User", "Group"],
                        "resourceTypes": ["Photo"],
                        "context": {
                            "type": "Record",
                            "additionalAttributes": true,
                            "attributes": {}
                        }
                    }
                }
            }
        }
    ))
    .expect("Expected valid schema")
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typechecks_partial_schema(policy: StaticPolicy) {
    assert_partial_typecheck(partial_schema_file(), policy)
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_typecheck_fails_partial_schema(
    policy: StaticPolicy,
    expected_type_errors: impl IntoIterator<Item = ValidationError>,
) {
    assert_partial_typecheck_fails(partial_schema_file(), policy, expected_type_errors)
}

mod passes_partial_schema {
    use super::*;

    #[test]
    fn unknown_attr_on_declared_entity_type() {
        assert_typechecks_partial_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { User::"alice".unknown };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn has_unknown_attr_on_declared_entity_type() {
        assert_typechecks_partial_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { User::"alice" has unknown };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn undeclared_entity_type_in_declared_entity_type() {
        assert_typechecks_partial_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { Admin::"alice" in User::"alice" };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn undeclared_action_in_declared_action() {
        assert_typechecks_partial_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { Action::"undeclared" in Action::"view" };"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn principal_wrong_for_known_actions() {
        // `resource` can't be a `Group` for the defined actions, but there
        // might be an undefined action where that's OK.
        assert_typechecks_partial_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource == Group::"owners");"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn policy_in_set_action_and_other() {
        let p = parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { User::"alice" in [action, User::"alice"] };"#,
        ).expect("Policy should parse.");
        assert_typechecks_partial_schema(p);
    }

    #[test]
    fn policy_action_in_set_action_and_other() {
        let p = parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { action in [action, User::"alice"] };"#,
        )
        .expect("Policy should parse.");
        assert_typechecks_partial_schema(p);
    }

    #[test]
    fn context_attr() {
        let p = parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action == Action::"view_photo", resource) when { context.foo };"#,
        )
        .expect("Policy should parse.");
        assert_typechecks_partial_schema(p);
    }
}

mod fail_partial_schema {
    use cedar_policy_core::{ast::PolicyID, extensions::Extensions};

    use super::*;
    use crate::validation_errors::{LubContext, LubHelp};

    #[test]
    fn error_on_declared_attr() {
        let extensions = Extensions::all_available();
        // `name` is declared as a `String` in the partial schema, so we can
        // error even though `principal.unknown` is not declared.
        let src = r#"permit(principal == User::"alice", action, resource) when { principal.name > principal.unknown };"#;
        assert_typecheck_fails_partial_schema(
            parse_policy(None, src).unwrap(),
            [ValidationError::expected_one_of_types(
                get_loc(src, "principal.name"),
                PolicyID::from_string("policy0"),
                extensions
                    .types_with_operator_overloading()
                    .cloned()
                    .map(Type::extension)
                    .chain(std::iter::once(Type::primitive_long()))
                    .collect(),
                Type::primitive_string(),
                None,
            )],
        );
    }

    #[test]
    fn incompatible_attrs() {
        // `age` and `name` are defined with incompatible types, while
        // `unknown` is not defined. The conflict is noticed and an error is
        // raised.
        let src = r#"
            permit(principal == User::"alice", action, resource) when {
                (if resource.foo then principal.age else (if resource.bar then principal.name else principal.unknown)) == "alice"
            };"#;
        assert_typecheck_fails_partial_schema(
            parse_policy(
                None,
                src,
            )
            .unwrap(),
            [ValidationError::incompatible_types(
                get_loc(src, "if resource.foo then principal.age else (if resource.bar then principal.name else principal.unknown)"),
                PolicyID::from_string("policy0"),
                vec![Type::primitive_long(), Type::primitive_string()],
                LubHelp::None,
                LubContext::Conditional,
            )],
        );
    }

    #[test]
    fn unknown_attr_on_closed_entity_type() {
        let src = r#"permit(principal, action, resource) when { principal.is_foo };"#;
        assert_typecheck_fails_partial_schema(
            parse_policy(None, src).unwrap(),
            [ValidationError::unsafe_attribute_access(
                get_loc(src, "principal.is_foo"),
                PolicyID::from_string("policy0"),
                AttributeAccess::EntityLUB(
                    EntityLUB::single_entity("Group".parse().unwrap()),
                    vec!["is_foo".into()],
                ),
                None,
                false,
            )],
        );
    }
}
