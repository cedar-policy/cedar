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

//! Contains tests for defining optional attributes and typechecking their
//! access using the ability added by contextual effects.
#![cfg(test)]
// GRCOV_STOP_COVERAGE

use cedar_policy_core::{
    ast::{BinaryOp, EntityUID, Expr, StaticPolicy, Var},
    parser::parse_policy,
};
use smol_str::SmolStr;

use crate::{
    type_error::TypeError, types::EntityLUB, AttributeAccess, NamespaceDefinition,
    NamespaceDefinitionWithActionAttributes,
};

use super::test_utils::{assert_policy_typecheck_fails, assert_policy_typechecks};

fn schema_with_optionals() -> NamespaceDefinition {
    serde_json::from_str::<NamespaceDefinition>(
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

fn assert_policy_typechecks_optional_schema(p: StaticPolicy) {
    assert_policy_typechecks(schema_with_optionals(), p);
}

fn assert_policy_typecheck_fails_optional_schema(
    p: StaticPolicy,
    expected_type_errors: Vec<TypeError>,
) {
    assert_policy_typecheck_fails(schema_with_optionals(), p, expected_type_errors);
}

#[test]
fn simple_and_guard_principal() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal has name && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn simple_and_guard_resource() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { resource has name && resource.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn principal_and_resource_in_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { resource has name && principal has age && resource.name == "foo" && principal.age == 1};"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn and_branches_union() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { (principal has name && principal has age) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn and_rhs_true_has_lhs_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { (principal has name && true) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn and_lhs_true_has_rhs_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { (true && principal has name) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn and_branches_use_prior_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { (principal has name) && (principal.name == "foo" && principal.name == "foo") };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn and_short_circuit_without_error() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal has age || (false && principal.name == "foo") };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn or_branches_intersect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { (principal has name || principal has name) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn or_lhs_false_has_rhs_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { (false || principal has name) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn or_rhs_false_has_lhs_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { (principal has name || false) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn or_branches_use_prior_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { (principal has name) && (principal.name == "foo" || principal.name == "foo") };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn then_guarded_access_by_test() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { if principal has name then principal.name == "foo" else false };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn then_guarded_access_by_prior_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal has name && (if principal has age then principal.name == "foo" else false) };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn else_guarded_access_by_prior_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal has name && (if principal has age then false else principal.name == "foo") };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn if_true_short_circuit_without_error() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal has name && (if true then principal.name == "foo" else principal.age == 1)};"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn if_false_short_circuit_without_error() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal has name && (if false then principal.age == 1 else principal.name == "foo")};"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn if_then_else_then_else_same() {
    let policy = parse_policy(
        Some("0".to_string()),
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
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn if_then_else_can_use_guard_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
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
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn if_then_else_guard_union_then_equal_else() {
    let policy = parse_policy(
        Some("0".to_string()),
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
    assert_policy_typechecks_optional_schema(policy);
}

#[test]
fn guarded_has_true_short_circuits() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"
        permit(principal, action, resource)
        when {
            principal has name && (if principal has name then principal.name == "foo" else principal.age == 3)
        };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks_optional_schema(policy);
}

fn assert_name_access_fails(policy: StaticPolicy) {
    let optional_attr: SmolStr = "name".into();
    assert_policy_typecheck_fails_optional_schema(
        policy,
        vec![TypeError::unsafe_optional_attribute_access(
            Expr::get_attr(Expr::var(Var::Principal), optional_attr.clone()),
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("User".parse().unwrap()),
                vec![optional_attr],
            ),
        )],
    );
}

#[test]
fn unguarded_access_fails() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn else_access_fails() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { if principal has name then false else principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn or_rhs_access_fails() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal has name || principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn or_lhs_access_fails() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal.name == "foo" || principal has name };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn or_branches_empty_intersect_fails() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { (principal has name || principal has age) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn and_lhs_access_fails() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal.name == "foo" && principal has name };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn if_then_else_else_access_fails() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"
        permit(principal, action, resource)
        when {
            if principal has name
            then principal.name == "foo"
            else principal.name == "bar"
        };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn if_then_else_as_guard_empty_intersect_fails() {
    let policy = parse_policy(
        Some("0".to_string()),
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
fn resource_effect_access_principal_fails() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { resource has name && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn not_no_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { !(principal has name) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn true_no_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { true && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn set_contains_no_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { [principal has name].contains(principal has name) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn contains_all_no_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { [principal has name].containsAll([principal has name]) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn contains_any_no_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { [principal has name].containsAny([principal has name]) && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn like_no_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { "foo" like "bar" && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn record_attr_no_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { {name: true}.name && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn record_attr_has_no_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { {name: true} has name && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn in_no_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal in resource && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn in_list_no_effect() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal in [resource] && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_name_access_fails(policy);
}

#[test]
fn record_optional_attrs() {
    let schema = serde_json::from_str::<NamespaceDefinition>(
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
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal.record has name && principal.record.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema.clone(), passing_policy);

    let failing_policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal.record has other && principal.record.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typecheck_fails(
        schema.clone(),
        failing_policy,
        vec![TypeError::unsafe_optional_attribute_access(
            Expr::get_attr(
                Expr::get_attr(Expr::var(Var::Principal), "record".into()),
                "name".into(),
            ),
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("User".parse().unwrap()),
                vec!["name".into(), "record".into()],
            ),
        )],
    );

    let failing_policy2 = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action, resource) when { principal.record has name && principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typecheck_fails(
        schema,
        failing_policy2,
        vec![TypeError::unsafe_optional_attribute_access(
            Expr::get_attr(Expr::var(Var::Principal), "name".into()),
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("User".parse().unwrap()),
                vec!["name".into()],
            ),
        )],
    );
}

#[test]
fn action_attrs_passing() {
    let schema = serde_json::from_str::<NamespaceDefinitionWithActionAttributes>(
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
        Some("0".to_string()),
        r#"permit(principal, action in [Action::"view", Action::"edit"], resource) when { action.isReadOnly };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema.clone(), passing_policy);

    let passing_policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action == Action::"edit", resource) when { action.canUndo };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(schema.clone(), passing_policy);

    //This doesn't work when the UB of two ActionEntities is AnyEntity

    // let passing_policy = parse_policy(
    //     Some("0".to_string()),
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
        Some("0".to_string()),
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
    let schema = serde_json::from_str::<NamespaceDefinitionWithActionAttributes>(
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

    let failing_policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action == Action::"view", resource) when { action.canUndo };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typecheck_fails(
        schema.clone(),
        failing_policy,
        vec![TypeError::unsafe_attribute_access(
            Expr::get_attr(Expr::var(Var::Action), "canUndo".into()),
            AttributeAccess::Other(vec!["canUndo".into()]),
            Some("isReadOnly".to_string()),
            false,
        )],
    );

    // Doesn't fail do to imprecision in ActionEntity LUB computation requiring `may_have_attr` to return true for ActionEntity types

    let failing_policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action == Action::"view", resource) when { action has "" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typecheck_fails(
        schema.clone(),
        failing_policy,
        vec![TypeError::impossible_policy(Expr::and(
            Expr::and(
                Expr::and(
                    Expr::val(true),
                    Expr::binary_app(
                        BinaryOp::Eq,
                        Expr::var(Var::Action),
                        Expr::val(EntityUID::with_eid_and_type("Action", "view").unwrap()),
                    ),
                ),
                Expr::val(true),
            ),
            Expr::has_attr(Expr::var(Var::Action), "".into()),
        ))],
    );

    let failing_policy = parse_policy(
        Some("0".to_string()),
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
    assert_policy_typecheck_fails(schema, failing_policy, vec![]); //fails because OtherNamespace::Action::"view" doesn't have defined attributes
}
