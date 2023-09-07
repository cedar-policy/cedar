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

#![cfg(test)]
// GRCOV_STOP_COVERAGE

use cedar_policy_core::{
    ast::{Expr, StaticPolicy, Var},
    parser::parse_policy,
};

use crate::{type_error::TypeError, AttributeAccess, NamespaceDefinition};

use super::test_utils;

fn schema_with_unspecified() -> NamespaceDefinition {
    serde_json::from_str::<NamespaceDefinition>(
        r#"
{
    "entityTypes": {
        "Entity": {
            "shape": {
                "type": "Record",
                "attributes": {
                    "name": { "type": "String" }
                }
            }
        }
    },
    "actions": {
        "act1": {
            "appliesTo": {
                "principalTypes": ["Entity"],
                "resourceTypes": null
            }
        },
        "act2": {
            "appliesTo": {
                "principalTypes": null,
                "resourceTypes": ["Entity"]
            }
        },
        "act3": {
            "appliesTo": null
        }
    }
}
    "#,
    )
    .expect("Expected valid schema.")
}

fn assert_policy_typechecks(p: StaticPolicy) {
    test_utils::assert_policy_typechecks(schema_with_unspecified(), p);
}

fn assert_policy_typecheck_fails(p: StaticPolicy, expected_type_errors: Vec<TypeError>) {
    test_utils::assert_policy_typecheck_fails(schema_with_unspecified(), p, expected_type_errors);
}

#[test]
fn spec_principal_unspec_resource() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action == Action::"act1", resource) when { principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(policy);

    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action == Action::"act1", resource) when { resource.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typecheck_fails(
        policy,
        vec![TypeError::unsafe_attribute_access(
            Expr::get_attr(Expr::var(Var::Resource), "name".into()),
            AttributeAccess::Other(vec!["name".into()]),
            None,
            true,
        )],
    );
}

#[test]
fn spec_resource_unspec_principal() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action == Action::"act2", resource) when { principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typecheck_fails(
        policy,
        vec![TypeError::unsafe_attribute_access(
            Expr::get_attr(Expr::var(Var::Principal), "name".into()),
            AttributeAccess::Other(vec!["name".into()]),
            None,
            true,
        )],
    );

    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action == Action::"act2", resource) when { resource.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typechecks(policy);
}

#[test]
fn unspec_resource_unspec_principal() {
    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action == Action::"act3", resource) when { principal.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typecheck_fails(
        policy,
        vec![TypeError::unsafe_attribute_access(
            Expr::get_attr(Expr::var(Var::Principal), "name".into()),
            AttributeAccess::Other(vec!["name".into()]),
            None,
            true,
        )],
    );

    let policy = parse_policy(
        Some("0".to_string()),
        r#"permit(principal, action == Action::"act3", resource) when { resource.name == "foo" };"#,
    )
    .expect("Policy should parse.");
    assert_policy_typecheck_fails(
        policy,
        vec![TypeError::unsafe_attribute_access(
            Expr::get_attr(Expr::var(Var::Resource), "name".into()),
            AttributeAccess::Other(vec!["name".into()]),
            None,
            true,
        )],
    );
}
