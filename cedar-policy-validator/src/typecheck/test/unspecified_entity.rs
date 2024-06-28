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

// GRCOV_STOP_COVERAGE

use cool_asserts::assert_matches;

use crate::{NamespaceDefinition, RawName};

fn schema_with_unspecified() -> &'static str {
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
    "#
}

#[test]
fn unspecified_does_not_parse() {
    assert_matches!(
        serde_json::from_str::<NamespaceDefinition<RawName>>(schema_with_unspecified()),
        Err(_)
    );
}

#[cfg(feature = "rfc55_backwards_compatible")]
mod backwards_compat_tests {
    use crate::{
        compat, schema_file_format,
        schema_file_format::DEFAULT_CEDAR_TYPE,
        typecheck::{test::test_utils, AttributeAccess},
        types::EntityLUB,
        RawName, ValidationError,
    };
    use cedar_policy_core::{
        ast::{Expr, PolicyID, StaticPolicy, Var},
        parser::parse_policy,
    };

    use super::*;

    fn parsed_schema_with_unspecified() -> schema_file_format::NamespaceDefinition<RawName> {
        let temp: compat::schema_file_format::NamespaceDefinition<RawName> =
            serde_json::from_str(schema_with_unspecified()).unwrap();
        temp.into()
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_policy_typechecks(p: StaticPolicy) {
        test_utils::assert_policy_typechecks(parsed_schema_with_unspecified(), p);
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_policy_typecheck_fails(p: StaticPolicy, expected_type_errors: Vec<ValidationError>) {
        test_utils::assert_policy_typecheck_fails(
            parsed_schema_with_unspecified(),
            p,
            expected_type_errors,
        );
    }

    fn default_access() -> AttributeAccess {
        AttributeAccess::EntityLUB(
            EntityLUB::single_entity(DEFAULT_CEDAR_TYPE.clone().into()),
            vec!["name".into()],
        )
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
            vec![ValidationError::unsafe_attribute_access(
                Expr::get_attr(Expr::var(Var::Resource), "name".into()),
                PolicyID::from_string("0"),
                default_access(),
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
            vec![ValidationError::unsafe_attribute_access(
                Expr::get_attr(Expr::var(Var::Principal), "name".into()),
                PolicyID::from_string("0"),
                default_access(),
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
            vec![ValidationError::unsafe_attribute_access(
                Expr::get_attr(Expr::var(Var::Principal), "name".into()),
                PolicyID::from_string("0"),
                default_access(),
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
            vec![ValidationError::unsafe_attribute_access(
                Expr::get_attr(Expr::var(Var::Resource), "name".into()),
                PolicyID::from_string("0"),
                default_access(),
                None,
                true,
            )],
        );
    }
}
