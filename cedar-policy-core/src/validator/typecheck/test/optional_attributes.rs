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

//! Contains tests for defining optional attributes and typechecking their
//! access using the ability added by capabilities.

use crate::{
    ast::{PolicyID, StaticPolicy},
    parser::parse_policy,
};

use crate::validator::{
    diagnostics::ValidationError, json_schema, types::EntityLUB,
    validation_errors::AttributeAccess, NamespaceDefinitionWithActionAttributes, RawName,
    ValidationWarning,
};

use super::test_utils::{
    assert_exactly_one_diagnostic, assert_policy_typecheck_fails, assert_policy_typecheck_warns,
    assert_policy_typechecks, assert_sets_equal, get_loc,
};

fn schema_with_optionals() -> json_schema::NamespaceDefinition<RawName> {
    serde_json::from_str::<json_schema::NamespaceDefinition<RawName>>(
        r#"
{
    "entityTypes": {
        "User": {
            "shape": {
                "type": "Record",
                "attributes": {
                    "name": { "type": "String", "required": false},
                    "age": { "type": "Long", "required": false}
                }
            }
        }
    },
    "actions": {
        "view_photo": {
            "appliesTo": {
                "principalTypes": ["User"],
                "resourceTypes": ["User"]
            }
        }
    }
}
    "#,
    )
    .expect("Expected valid schema.")
}

#[test]
fn simple_and_guard_principal() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal has name && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn simple_and_guard_resource() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { resource has name && resource.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn principal_and_resource_in_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { resource has name && principal has age && resource.name == "foo" && principal.age == 1};"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn and_branches_union() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { (principal has name && principal has age) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn and_rhs_true_has_lhs_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { (principal has name && true) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn and_lhs_true_has_rhs_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { (true && principal has name) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn and_branches_use_prior_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { (principal has name) && (principal.name == "foo" && principal.name == "foo") };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn and_short_circuit_without_error() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal has age || (false && principal.name == "foo") };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn or_branches_intersect() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { (principal has name || principal has name) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn or_lhs_false_has_rhs_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { (false || principal has name) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn or_rhs_false_has_lhs_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { (principal has name || false) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn or_branches_use_prior_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { (principal has name) && (principal.name == "foo" || principal.name == "foo") };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn then_guarded_access_by_test() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { if principal has name then principal.name == "foo" else false };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn then_guarded_access_by_prior_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal has name && (if principal has age then principal.name == "foo" else false) };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn else_guarded_access_by_prior_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal has name && (if principal has age then false else principal.name == "foo") };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn if_true_short_circuit_without_error() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal has name && (if true then principal.name == "foo" else principal.age == 1)};"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn if_false_short_circuit_without_error() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal has name && (if false then principal.age == 1 else principal.name == "foo")};"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn if_then_else_then_else_same() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"
        permit(principal, action, resource)
        when {
            if
                if (principal has age)
                then (principal has name)
                else (principal has name)
            then principal.name == "foo"
            else false
        };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn if_then_else_can_use_guard_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"
        permit(principal, action, resource)
        when {
            if
                if (principal has name)
                then (principal has age)
                else (principal has name)
            then principal.name == "foo"
            else false
        };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn if_then_else_guard_union_then_equal_else() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"
        permit(principal, action, resource)
        when {
            (
                if (principal has name)
                then (principal has age)
                else (principal has name && principal has age)
            ) && principal.name == "hi" && principal.age == 2
        };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[test]
fn guarded_has_true_short_circuits() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"
        permit(principal, action, resource)
        when {
            principal has name && (if principal has name then principal.name == "foo" else principal.age == 3)
        };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema_with_optionals(), policy);
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
fn assert_name_access_fails(policy: StaticPolicy) {
    let id = policy.id().clone();

    let loc = get_loc(policy.loc().unwrap().src.clone(), "principal.name");
    let errors = assert_policy_typecheck_fails(schema_with_optionals(), policy);
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::unsafe_optional_attribute_access(
            loc,
            id,
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("User".parse().unwrap()),
                vec!["name".into()],
            ),
        )
    );
}

#[test]
fn unguarded_access_fails() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn else_access_fails() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { if principal has name then false else principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn or_rhs_access_fails() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal has name || principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn or_lhs_access_fails() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal.name == "foo" || principal has name };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn or_branches_empty_intersect_fails() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { (principal has name || principal has age) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn and_lhs_access_fails() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal.name == "foo" && principal has name };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn if_then_else_else_access_fails() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"
        permit(principal, action, resource)
        when {
            if principal has name
            then principal["name"] == "foo"
            else principal.name == "bar"
        };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn if_then_else_as_guard_empty_intersect_fails() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"
        permit(principal, action, resource)
        when {
            if
                if (principal has age)
                then (principal has age)
                else (principal has name)
            then principal.name == "foo"
            else false
        };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn resource_capability_access_principal_fails() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { resource has name && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn not_no_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { !(principal has name) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn true_no_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { true && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn set_contains_no_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { [principal has name].contains(principal has name) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn contains_all_no_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { [principal has name].containsAll([principal has name]) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn contains_any_no_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { [principal has name].containsAny([principal has name]) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn like_no_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { "foo" like "bar" && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn record_attr_no_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { {name: true}.name && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn record_attr_has_no_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { {name: true} has name && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn in_no_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal in resource && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn in_list_no_capability() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal in [resource] && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn record_optional_attrs() {
    let schema = serde_json::from_str::<json_schema::NamespaceDefinition<RawName>>(
        r#"
{
    "entityTypes": {
        "User": {
            "shape": {
                "type": "Record",
                "attributes": {
                    "name": { "type": "String", "required": false},
                    "record": {
                        "type": "Record",
                        "attributes": {
                            "name": { "type": "String", "required": false},
                            "other": { "type": "String", "required": true}
                        }
                    }
                }
            }
        }
    },
    "actions": {
        "view_photo": {
            "appliesTo": {
                "principalTypes": ["User"],
                "resourceTypes": ["User"]
            }
        }
    }
}
    "#,
    )
    .expect("Expected valid schema.");

    let passing_policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal.record has name && principal.record.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema.clone(), passing_policy);

    let src = r#"permit(principal, action, resource) when { principal.record has other && principal.record.name == "foo" };"#;
    let failing_policy =
        parse_policy(Some(PolicyID::from_string("0")), src).expect("Policy should parse.");
    let errors = assert_policy_typecheck_fails(schema.clone(), failing_policy);
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::unsafe_optional_attribute_access(
            get_loc(src, "principal.record.name"),
            PolicyID::from_string("0"),
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("User".parse().unwrap()),
                vec!["name".into(), "record".into()],
            ),
        )
    );

    let src = r#"permit(principal, action, resource) when { principal.record has name && principal.name == "foo" };"#;
    let failing_policy2 =
        parse_policy(Some(PolicyID::from_string("0")), src).expect("Policy should parse.");
    let errors = assert_policy_typecheck_fails(schema, failing_policy2);
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::unsafe_optional_attribute_access(
            get_loc(src, "principal.name"),
            PolicyID::from_string("0"),
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("User".parse().unwrap()),
                vec!["name".into()],
            ),
        )
    );
}

#[test]
fn action_attrs_passing() {
    let schema = serde_json::from_str::<NamespaceDefinitionWithActionAttributes<RawName>>(
        r#"
        {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "name": { "type": "String", "required": false},
                            "record": {
                                "type": "Record",
                                "attributes": {
                                    "name": { "type": "String", "required": false}
                                }
                            },
                            "isReadOnly": {"type": "Boolean", "required": true}
                        }
                    }
                }
            },
            "actions": {
                "view": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["User"]
                    },
                    "attributes": {
                        "isReadOnly": true,
                        "canUndo": false
                    }
                },
                "edit": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["User"]
                    },
                    "attributes": {
                        "isReadOnly": false,
                        "canUndo": true
                    }
                }
            }
        }
    "#,
    )
    .expect("Expected valid schema.");

    let passing_policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action in [Action::"view", Action::"edit"], resource) when { action.isReadOnly };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema.clone(), passing_policy);

    let passing_policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action == Action::"edit", resource) when { action.canUndo };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema.clone(), passing_policy);

    //This doesn't work when the UB of two ActionEntities is AnyEntity

    // let passing_policy = parse_policy(
    //     Some(PolicyID::from_string("0")),
    //     r#"
    //     permit(
    //         principal == User::"bob",
    //         action == Action::"view",
    //         resource
    //     )
    //     when {
    //       [Action::"view", Action::"edit"].contains(action)
    //     };
    //     "#,
    // )
    // .expect("Policy should parse.");
    // assert_policy_typechecks(schema.clone(), passing_policy);

    let passing_policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"
        permit(
            principal == User::"bob",
            action == Action::"view",
            resource
        )
        when {
          Action::"view".isReadOnly
        };
        "#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema, passing_policy);
}

#[test]
fn action_attrs_failing() {
    let schema = serde_json::from_str::<NamespaceDefinitionWithActionAttributes<RawName>>(
        r#"
        {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "name": { "type": "String", "required": false},
                            "record": {
                                "type": "Record",
                                "attributes": {
                                    "name": { "type": "String", "required": false}
                                }
                            },
                            "isReadOnly": {"type": "Boolean", "required": true}
                        }
                    }
                }
            },
            "actions": {
                "view": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["User"]
                    },
                    "attributes": {
                        "isReadOnly": true
                    }
                },
                "edit": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["User"]
                    },
                    "attributes": {
                        "isReadOnly": false,
                        "canUndo": true
                    }
                }
            }
        }
    "#,
    )
    .expect("Expected valid schema.");

    let src = r#"permit(principal, action == Action::"view", resource) when { action.canUndo };"#;
    let failing_policy =
        parse_policy(Some(PolicyID::from_string("0")), src).expect("Policy should parse.");
    let errors = assert_policy_typecheck_fails(schema.clone(), failing_policy);
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::unsafe_attribute_access(
            get_loc(src, "action.canUndo"),
            PolicyID::from_string("0"),
            AttributeAccess::Other(vec!["canUndo".into()]),
            Some("isReadOnly".to_string()),
            false,
        )
    );

    // No error is returned, but the typechecker identifies that `action has ""`
    // is always false.
    let failing_policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action == Action::"view", resource) when { action has "" };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(schema.clone(), failing_policy.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(
            failing_policy.loc().cloned(),
            PolicyID::from_string("0"),
        )
    );

    // Fails because OtherNamespace::Action::"view" is not defined in the schema.
    // However, this will be detected by a different pass, so no error is reported.
    let failing_policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"
        permit(
            principal,
            action,
            resource
        )
        when {
            OtherNamespace::Action::"view".isReadOnly
        };
        "#,
    )
    .expect("Policy should parse.");
    let errors = assert_policy_typecheck_fails(schema, failing_policy);
    assert_sets_equal(errors, []);
}
