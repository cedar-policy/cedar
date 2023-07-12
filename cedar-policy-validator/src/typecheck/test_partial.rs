//! Contains test for typechecking with partial schema files.
#![cfg(test)]
#![cfg(feature = "partial_schema")]
// GRCOV_STOP_COVERAGE

use std::collections::HashSet;

use cedar_policy_core::ast::{Expr, Template, Var};
use cedar_policy_core::{ast::StaticPolicy, parser::parse_policy};

use crate::typecheck::test_utils::assert_expected_type_errors;
use crate::typecheck::Typechecker;
use crate::types::Type;
use crate::{NamespaceDefinition, TypeError, ValidationMode, ValidatorSchema};

use super::test_utils::empty_schema_file;

pub(crate) fn assert_partial_typecheck(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    policy: StaticPolicy,
) {
    let schema = schema.try_into().expect("Failed to construct schema.");
    let typechecker = Typechecker::new(&schema, ValidationMode::Partial);
    let mut type_errors: HashSet<TypeError> = HashSet::new();
    let typechecked = typechecker.typecheck_policy(
        &Template::link_static_policy(policy.clone()).0,
        &mut type_errors,
    );
    assert_eq!(type_errors, HashSet::new(), "Did not expect any errors.");
    assert!(typechecked, "Expected that policy would typecheck.");
}

pub(crate) fn assert_partial_typecheck_fail(
    schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
    policy: StaticPolicy,
    expected_type_errors: Vec<TypeError>,
) {
    let schema = schema.try_into().expect("Failed to construct schema.");
    let typechecker = Typechecker::new(&schema, ValidationMode::Partial);
    let mut type_errors: HashSet<TypeError> = HashSet::new();
    let typechecked = typechecker.typecheck_policy(
        &Template::link_static_policy(policy.clone()).0,
        &mut type_errors,
    );
    assert_expected_type_errors(&expected_type_errors, &type_errors);
    assert!(!typechecked, "Expected that policy would not typecheck.");
}

pub(crate) fn assert_typechecks_empty_schema(policy: StaticPolicy) {
    assert_partial_typecheck(empty_schema_file(), policy)
}

pub(crate) fn assert_typecheck_fails_empty_schema(
    policy: StaticPolicy,
    expected_type_errors: Vec<TypeError>,
) {
    assert_partial_typecheck_fail(empty_schema_file(), policy, expected_type_errors)
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
}

mod fails_empty_schema {
    use std::str::FromStr;

    use cedar_policy_core::ast::Expr;

    use crate::types::Type;

    use super::*;

    #[test]
    fn operator_type_error() {
        // We expect to see a type error for the incorrect literal argument to
        // various operators. No error should be generated for missing
        // attributes or the type of the attributes.
        assert_typecheck_fails_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { principal.foo > "a" };"#,
            )
            .unwrap(),
            vec![TypeError::expected_type(
                Expr::val("a"),
                Type::primitive_long(),
                Type::primitive_string(),
            )],
        );
        assert_typecheck_fails_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { 1.contains(principal.foo) };"#,
            )
            .unwrap(),
            vec![TypeError::expected_type(
                Expr::val(1),
                Type::any_set(),
                Type::primitive_long(),
            )],
        );
        assert_typecheck_fails_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { principal.foo.containsAll(1) };"#,
            )
            .unwrap(),
            vec![TypeError::expected_type(
                Expr::val(1),
                Type::any_set(),
                Type::primitive_long(),
            )],
        );
    }

    #[test]
    fn top_level_type_error() {
        assert_typecheck_fails_empty_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { principal.foo + 1 };"#,
            )
            .unwrap(),
            vec![TypeError::expected_type(
                Expr::from_str("principal.foo + 1").unwrap(),
                Type::primitive_boolean(),
                Type::primitive_long(),
            )],
        )
    }

    #[test]
    fn impossible_policy() {
        let p = parse_policy(
            None,
            r#"permit(principal, action, resource) when { resource.bar && false };"#,
        )
        .unwrap();
        assert_typecheck_fails_empty_schema(
            p.clone(),
            vec![TypeError::impossible_policy(p.condition())],
        )
    }

    #[test]
    fn record_lit_bad_attr() {
        let p = parse_policy(
            None,
            r#"permit(principal, action, resource) when { {foo: 1}.bar };"#,
        )
        .unwrap();
        assert_typecheck_fails_empty_schema(
            p.clone(),
            vec![TypeError::unsafe_attribute_access(
                Expr::from_str("{foo: 1}.bar").unwrap(),
                "bar".into(),
                Some("foo".into()),
                false,
            )],
        )
    }
}

fn partial_schema_file() -> NamespaceDefinition {
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
                        "resourceTypes": ["Photo"]
                    }
                }
            }
        }
    ))
    .expect("Expected valid schema")
}

pub(crate) fn assert_typechecks_partial_schema(policy: StaticPolicy) {
    assert_partial_typecheck(partial_schema_file(), policy)
}

pub(crate) fn assert_typecheck_fails_partial_schema(
    policy: StaticPolicy,
    expected_type_errors: Vec<TypeError>,
) {
    assert_partial_typecheck_fail(partial_schema_file(), policy, expected_type_errors)
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
            Some("0".to_string()),
            r#"permit(principal, action, resource) when { User::"alice" in [action, User::"alice"] };"#,
        ).expect("Policy should parse.");
        assert_typechecks_partial_schema(p);
    }

    #[test]
    fn policy_action_in_set_action_and_other() {
        let p = parse_policy(
            Some("0".to_string()),
            r#"permit(principal, action, resource) when { action in [action, User::"alice"] };"#,
        )
        .expect("Policy should parse.");
        assert_typechecks_partial_schema(p);
    }
}

mod fail_partial_schema {

    use std::str::FromStr;

    use super::*;

    #[test]
    fn error_on_declared_attr() {
        // `name` is declared as a `String` in the partial schema, so we can
        // error even though `principal.unknown` is not declared.
        assert_typecheck_fails_partial_schema(
            parse_policy(
                None,
                r#"permit(principal == User::"alice", action, resource) when { principal.name > principal.unknown };"#,
            )
            .unwrap(),
            vec![TypeError::expected_type(
                Expr::get_attr(Expr::var(Var::Principal), "name".into()),
                Type::primitive_long(),
                Type::primitive_string(),
            )],
        );
    }

    #[test]
    fn incompatible_attrs() {
        assert_typecheck_fails_partial_schema(
            // `age` and `name` are defined with incompatible types, while
            // `unknown` is not defined. The conflict is noticed and an error is
            // raised.
            parse_policy(
                None,
                r#"permit(principal == User::"alice", action, resource) when {
                        (if resource.foo then
                            principal.age
                        else (if resource.bar then
                            principal.name
                        else
                            principal.unknown
                        )) == "alice"};"#,
            )
            .unwrap(),
            vec![TypeError::incompatible_types(
                Expr::from_str("if resource.foo then principal.age else (if resource.bar then principal.name else principal.unknown)").unwrap(),
                vec![Type::primitive_long(), Type::primitive_string()],
            )],
        );
    }

    #[test]
    fn unknown_attr_on_closed_entity_type() {
        assert_typecheck_fails_partial_schema(
            parse_policy(
                None,
                r#"permit(principal, action, resource) when { principal.is_foo };"#,
            )
            .unwrap(),
            vec![TypeError::unsafe_attribute_access(
                Expr::from_str("principal.is_foo").unwrap(),
                "is_foo".into(),
                None,
                false,
            )],
        );
    }
}

mod open_member_of {

    use super::*;

    fn schema_file() -> NamespaceDefinition {
        serde_json::from_value(serde_json::json!(
            {
                "entityTypes": {
                    "Group": {
                        "memberOfTypesIncomplete": true
                    },
                    "User": {
                        "memberOfTypes": [ "Group" ],
                    },
                },
                "actions": {
                    "view": {
                        "memberOfIncomplete": true,
                    },
                    "view_photo": {
                        "memberOf": [{"id": "view"}],
                    }
                }
            }
        ))
        .expect("Expected valid schema")
    }

    pub(crate) fn assert_typechecks_partial_schema(policy: StaticPolicy) {
        assert_partial_typecheck(schema_file(), policy)
    }

    #[test]
    fn in_open_member_of() {
        let p = parse_policy(
            None,
            r#"permit(principal, action, resource) when { Action::"view" in Action::"bogus"};"#,
        )
        .expect("Policy should parse.");
        assert_typechecks_partial_schema(p)
    }

    #[test]
    fn in_transitive_open_member_of() {
        let p = parse_policy(
            None,
            r#"permit(principal, action, resource) when { Action::"view_photo" in Action::"fake"};"#,
        )
        .expect("Policy should parse.");
        assert_typechecks_partial_schema(p)
    }

    #[test]
    fn in_open_member_of_types() {
        let p = parse_policy(
            None,
            r#"permit(principal, action, resource) when { Group::"alice_friends" in Fake::"bogus"};"#,
        )
        .expect("Policy should parse.");
        assert_typechecks_partial_schema(p)
    }

    #[test]
    fn in_transitive_open_member_of_types() {
        let p = parse_policy(
            None,
            r#"permit(principal, action, resource) when { User::"alice" in Bogus::"fake"};"#,
        )
        .expect("Policy should parse.");
        assert_typechecks_partial_schema(p)
    }
}
