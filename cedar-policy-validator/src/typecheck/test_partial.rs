//! Contains test for typechecking with partial schema files.
#![cfg(test)]
#![cfg(feature = "partial-validate")]
// GRCOV_STOP_COVERAGE

use std::collections::HashSet;

use cedar_policy_core::ast::{Expr, Template, Var};
use cedar_policy_core::{ast::StaticPolicy, parser::parse_policy};

use crate::typecheck::test_utils::assert_expected_type_errors;
use crate::typecheck::Typechecker;
use crate::types::{EntityLUB, Type};
use crate::{AttributeAccess, NamespaceDefinition, TypeError, ValidationMode, ValidatorSchema};

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

    #[test]
    fn context_attr() {
        let p = parse_policy(
            Some("0".to_string()),
            r#"permit(principal, action == Action::"view_photo", resource) when { context.foo };"#,
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
