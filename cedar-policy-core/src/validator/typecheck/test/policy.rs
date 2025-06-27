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

//! Contains test for typechecking complete Cedar policies with schema
//! files.

use std::sync::Arc;

use crate::{
    ast::{EntityUID, Expr, PolicyID, Template},
    extensions::Extensions,
    parser::{parse_policy, parse_policy_or_template},
};

use super::test_utils::{
    assert_exactly_one_diagnostic, assert_policy_typecheck_fails,
    assert_policy_typecheck_fails_for_mode, assert_policy_typecheck_warns,
    assert_policy_typecheck_warns_for_mode, assert_policy_typechecks,
    assert_policy_typechecks_for_mode, assert_typechecks, get_loc,
};
use crate::validator::{
    diagnostics::ValidationError,
    json_schema,
    typecheck::{PolicyCheck, Typechecker},
    types::{EntityLUB, Type},
    validation_errors::{AttributeAccess, LubContext, LubHelp},
    RawName, ValidationMode, ValidationWarning, ValidatorSchema,
};

fn simple_schema_file() -> json_schema::NamespaceDefinition<RawName> {
    serde_json::from_value(serde_json::json!(
        {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Group" ],
                    "shape": {
                        "type": "Record",
                        "additionalAttributes": false,
                        "attributes": {
                            "name": { "type": "String", "required": true},
                            "age": { "type": "Long", "required": true},
                            "favorite": { "type": "Entity", "name": "Photo", "required": true}
                        }
                    }
                },
                "Group": {
                    "memberOfTypes": [],
                    "shape": {
                        "type": "Record",
                        "additionalAttributes": false,
                        "attributes": {
                            "name": { "type": "String", "required": true}
                        }
                    }
                },
                "Photo": {
                    "memberOfTypes": [ "Album" ],
                    "shape": {
                        "type": "Record",
                        "additionalAttributes": false,
                        "attributes": {
                            "file_type": { "type": "String", "required": true},
                            "owner": { "type": "Entity", "name": "User", "required": true}
                        }
                    }
                },
                "Album": {
                    "memberOfTypes": [],
                    "shape": {
                        "type": "Record",
                        "additionalAttributes": false,
                        "attributes": { }
                    }
                }
            },
            "actions": {
                "view_photo": {
                    "memberOf": [],
                    "appliesTo": {
                        "principalTypes": ["User", "Group"],
                        "resourceTypes": ["Photo"]
                    }
                },
                "delete_group": {
                    "memberOf": [],
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Group"]
                    }
                }
            }
        }
    ))
    .expect("Expected valid schema")
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
fn assert_policy_typechecks_permissive_simple_schema(p: impl Into<Arc<Template>>) {
    assert_policy_typechecks_for_mode(simple_schema_file(), p, ValidationMode::Permissive)
}

#[test]
fn entity_literal_typechecks() {
    assert_typechecks(
        simple_schema_file(),
        &Expr::val(
            EntityUID::with_eid_and_type("Group", "friends")
                .expect("EUID component failed to parse."),
        ),
        &Type::named_entity_reference_from_str("Group"),
    )
}

#[test]
fn policy_checked_in_multiple_envs() {
    let t = parse_policy_or_template(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action == Action::"view_photo", resource) when { resource.file_type == "jpg" };"#
    ).expect("Policy should parse.");

    let schema = simple_schema_file()
        .try_into()
        .expect("Failed to construct schema.");
    let typechecker = Typechecker::new(&schema, ValidationMode::default());
    let env_checks = typechecker.typecheck_by_request_env(&t);
    // There are 3 possible envs in schema:
    // - User, "view_photo", Photo
    // - Group, "view_photo", Photo
    // - User, "delete_group", Group
    assert!(env_checks.len() == 3);
    // Policy is always false for "delete_group"
    assert!(
        env_checks
            .iter()
            .filter(|(_, check)| { matches!(check, PolicyCheck::Irrelevant(_, _)) })
            .count()
            == 1
    );

    let t = parse_policy_or_template(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action == Action::"delete_group", resource) when { resource.file_type == "jpg" };"#
    ).expect("Policy should parse.");
    let schema = simple_schema_file()
        .try_into()
        .expect("Failed to construct schema.");
    let typechecker = Typechecker::new(&schema, ValidationMode::default());
    let env_checks = typechecker.typecheck_by_request_env(&t);
    // With the new action, policy is always false for the other two
    assert!(
        env_checks
            .iter()
            .filter(|(_, check)| { matches!(check, PolicyCheck::Irrelevant(_, _)) })
            .count()
            == 2
    );
    // and fails by not updating usage of resource
    assert!(
        env_checks
            .iter()
            .filter(|(_, check)| { matches!(check, PolicyCheck::Fail(_)) })
            .count()
            == 1
    );
}

#[test]
fn policy_single_action_attribute_access() {
    assert_policy_typechecks(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action == Action::"view_photo", resource) when { resource.file_type == "jpg" };"#
        ).expect("Policy should parse."));
}

#[test]
fn policy_principal_action_attribute_access() {
    // The principal for Action::"view_photo" is ordinarily User or Group, but the
    // principal condition refines this to User, so we can access the age
    // attribute.
    assert_policy_typechecks(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal == User::"alice", action == Action::"view_photo", resource) when { principal.age > 21 };"#
        ).expect("Policy should parse."));
}

#[test]
fn policy_action_multiple_principal_attribute_access() {
    // The attribute name is defined for User and Group.
    assert_policy_typechecks(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action == Action::"view_photo", resource) when { principal.name == "alice" };"#
        ).expect("Policy should parse."));
}

#[test]
fn policy_no_conditions_attribute_access() {
    // Both actions in the schema apply to principals with the attribute name,
    // so the action condition isn't required either.
    assert_policy_typechecks(
        simple_schema_file(),
        parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { principal.name == "alice" };"#,
        )
        .expect("Policy should parse."),
    );
}

#[test]
fn policy_resource_narrows_principal() {
    // The resource condition doesn't match the resource applies_to set for
    // "view_photo", so we know the action is "delete_group", which only
    // accepts User as the principal.
    assert_policy_typechecks(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource == Group::"jane_friends") when { principal.age > 22};"#
        ).expect("Policy should parse."));
}

#[test]
fn policy_action_in() {
    assert_policy_typechecks(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action in [Action::"delete_group", Action::"view_photo"], resource in Album::"vacation_photos") when { resource.file_type == "png" };"#
        ).expect("Policy should parse."));
}

#[test]
fn policy_invalid_attribute() {
    let src = r#"permit(principal, action in [Action::"delete_group", Action::"view_photo"], resource) when { resource.file_type == "jpg" };"#;
    let errors = assert_policy_typecheck_fails(
        simple_schema_file(),
        parse_policy(Some(PolicyID::from_string("0")), src).expect("Policy should parse."),
    );
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::unsafe_attribute_access(
            get_loc(src, "resource.file_type"),
            PolicyID::from_string("0"),
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("Group".parse().unwrap()),
                vec!["file_type".into()],
            ),
            Some("name".into()),
            false,
        )
    );
}

#[test]
fn policy_invalid_attribute_2() {
    let src = r#"permit(principal, action == Action::"view_photo", resource) when { principal.age > 21 };"#;
    let errors = assert_policy_typecheck_fails(
        simple_schema_file(),
        parse_policy(Some(PolicyID::from_string("0")), src).expect("Policy should parse."),
    );
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::unsafe_attribute_access(
            get_loc(src, "principal.age"),
            PolicyID::from_string("0"),
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("Group".parse().unwrap()),
                vec!["age".into()],
            ),
            Some("name".into()),
            false,
        )
    );
}

#[test]
fn policy_context_invalid_attribute() {
    let src =
        r#"permit(principal, action == Action::"view_photo", resource) when { context.fake };"#;
    let errors = assert_policy_typecheck_fails(
        simple_schema_file(),
        parse_policy(Some(PolicyID::from_string("0")), src).expect("Policy should parse."),
    );
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::unsafe_attribute_access(
            get_loc(src, "context.fake"),
            PolicyID::from_string("0"),
            AttributeAccess::Context(
                r#"Action::"view_photo""#.parse().unwrap(),
                vec!["fake".into()],
            ),
            None,
            false,
        )
    );
}

#[test]
fn policy_entity_type_attr() {
    assert_policy_typechecks(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action == Action::"view_photo", resource) when { resource.owner.age > 0 };"#
        ).expect("Policy should parse."));
}

#[test]
fn policy_entity_type_action_in() {
    assert_policy_typechecks(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action in Action::"view_photo", resource) when { resource.owner.age > 0 };"#
        ).expect("Policy should parse."));
}

#[test]
fn policy_entity_type_action_in_body() {
    assert_policy_typechecks(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { action in Action::"view_photo" && resource.owner.age > 0 };"#
        ).expect("Policy should parse."));
}

#[test]
fn policy_entity_type_action_in_set() {
    assert_policy_typechecks(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action in [Action::"view_photo"], resource) when { resource.owner.age > 0 };"#
        ).expect("Policy should parse."));
}

#[test]
fn policy_entity_type_principal_in_set() {
    assert_policy_typechecks_for_mode(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { principal in [User::"admin", Group::"admin"] || true};"#
        ).expect("Policy should parse."), ValidationMode::Permissive);
}

#[test]
fn policy_entity_type_principal_in_set_user_only() {
    assert_policy_typechecks(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { principal in [User::"admin"] && principal.age == 0};"#
        ).expect("Policy should parse."));
}

#[test]
fn policy_lub_entity_type_attr() {
    assert_policy_typechecks(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action == Action::"view_photo", resource) when { resource.owner.favorite.file_type == "png" };"#
        ).expect("Policy should parse."));
}

#[test]
fn policy_impossible_scope() {
    let p = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal == Group::"foo", action == Action::"delete_group", resource);"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(simple_schema_file(), p.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("0"),)
    );
}

#[test]
fn policy_impossible_literal_euids() {
    let p = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { Group::"foo" in User::"bar" };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(simple_schema_file(), p.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("0"),)
    );
}

#[test]
fn policy_impossible_not_has() {
    let p = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { ! ({name: "alice"} has name)};"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(simple_schema_file(), p.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("0"),)
    );
}

#[test]
fn policy_if_entities_lub() {
    assert_policy_typechecks(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { (if principal.name == "foo" then User::"alice" else User::"bob").age > 21};"#
        ).expect("Policy should parse."));
}

#[test]
fn policy_in_action_impossible() {
    let p = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { User::"alice" in [action] };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(simple_schema_file(), p.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("0"),)
    );

    let p = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { User::"alice" in [Action::"view_photo"] };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(simple_schema_file(), p.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("0"),)
    );

    let p = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal in [action] };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(simple_schema_file(), p.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("0"),)
    );

    let p = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal in action };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(simple_schema_file(), p.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("0"),)
    );

    let p = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal in Action::"view_photo" };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(simple_schema_file(), p.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("0"),)
    );

    let p = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal in [Action::"view_photo", Action::"delete_group"] };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(simple_schema_file(), p.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("0"),)
    );

    let p = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { principal in [Action::"view_photo", Photo::"bar"] };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns_for_mode(
        simple_schema_file(),
        p.clone(),
        ValidationMode::Permissive,
    );
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("0"),)
    );
}

#[test]
fn policy_action_in_impossible() {
    let p = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { action in [User::"alice"] };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(simple_schema_file(), p.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("0"),)
    );
}

#[test]
fn policy_entity_has_then_get() {
    assert_policy_typechecks(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { principal has age && principal.age > 0};"#,
        ).expect("Policy should parse."));
}

#[test]
fn policy_entity_top_has() {
    assert_policy_typechecks_for_mode(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { (if principal.name == "foo" then principal else resource) has name || true };"#,
        ).expect("Policy should parse."), ValidationMode::Permissive);
}

#[test]
fn entity_lub_access_attribute() {
    assert_policy_typechecks_for_mode(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { (if 1 > 0 then User::"alice" else Group::"alice_friends").name like "foo"};"#
        ).expect("Policy should parse."), ValidationMode::Permissive);
}

#[test]
fn entity_lub_no_common_attributes_is_entity() {
    assert_policy_typechecks_for_mode(simple_schema_file(), parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { principal in (if 1 > 0 then User::"alice" else Photo::"vacation.jpg")};"#
        ).expect("Policy should parse."), ValidationMode::Permissive);
}

#[test]
fn entity_lub_cant_access_attribute_not_shared() {
    let src = r#"permit(principal, action, resource == Group::"foo") when { (if 1 > 0 then User::"alice" else Photo::"vacation.jpg").name == "bob"};"#;
    let p = parse_policy(Some(PolicyID::from_string("0")), src).expect("Policy should parse.");
    let errors =
        assert_policy_typecheck_fails_for_mode(simple_schema_file(), p, ValidationMode::Permissive);
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::unsafe_attribute_access(
            get_loc(
                src,
                r#"(if 1 > 0 then User::"alice" else Photo::"vacation.jpg").name"#,
            ),
            PolicyID::from_string("0"),
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("User".parse().unwrap())
                    .least_upper_bound(&EntityLUB::single_entity("Photo".parse().unwrap())),
                vec!["name".into()],
            ),
            None,
            true,
        )
    );
}

#[test]
fn entity_attribute_recommendation() {
    let src = r#"permit(principal, action == Action::"view_photo", resource) when {resource.filetype like "*jpg" }; "#;
    let p = parse_policy(Some(PolicyID::from_string("0")), src).expect("Policy should parse");
    let errors = assert_policy_typecheck_fails(simple_schema_file(), p);
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::unsafe_attribute_access(
            get_loc(src, "resource.filetype"),
            PolicyID::from_string("0"),
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("Photo".parse().unwrap()),
                Vec::from(["filetype".into()]),
            ),
            Some("file_type".into()),
            false,
        )
    );
}

#[test]
fn entity_lub_no_common_attributes_might_have_declared_attribute() {
    assert_policy_typechecks_permissive_simple_schema(parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource) when { (if 1 > 0 then User::"alice" else Photo::"vacation.jpg") has age || true };"#
        ).expect("Policy should parse."));
}

#[test]
fn entity_lub_cant_have_undeclared_attribute() {
    let p = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { (if 1 > 0 then User::"alice" else Photo::"vacation.jpg") has foo};"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns_for_mode(
        simple_schema_file(),
        p.clone(),
        ValidationMode::Permissive,
    );
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("0"),)
    );
}

#[test]
fn is_typechecks_singleton() {
    assert_policy_typechecks(
        simple_schema_file(),
        parse_policy(None, r#"permit(principal is User, action, resource);"#).unwrap(),
    );
    assert_policy_typechecks(
        simple_schema_file(),
        parse_policy(None, r#"permit(principal is Group, action, resource);"#).unwrap(),
    );
    assert_policy_typechecks(
        simple_schema_file(),
        parse_policy(None, r#"permit(principal, action, resource is Photo);"#).unwrap(),
    );
    assert_policy_typechecks(
        simple_schema_file(),
        parse_policy(None, r#"permit(principal, action, resource is Group);"#).unwrap(),
    );
}

#[test]
fn is_impossible() {
    let p = parse_policy(None, r#"permit(principal is Photo, action, resource);"#).unwrap();
    let warnings = assert_policy_typecheck_warns(simple_schema_file(), p.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("policy0"),)
    );
    let p = parse_policy(None, r#"permit(principal, action, resource is User);"#).unwrap();
    let warnings = assert_policy_typecheck_warns(simple_schema_file(), p.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("policy0"),)
    );
}

#[test]
fn is_entity_lub() {
    assert_policy_typechecks_permissive_simple_schema(
        parse_policy(
            None,
            r#"
            permit(principal, action, resource) when {
                (if principal.name == "foo" then principal else resource) is User
            };
        "#,
        )
        .unwrap(),
    );
    let p = parse_policy(
        None,
        r#"
            permit(principal, action, resource) when {
                (if principal.name == "foo" then principal else resource) is Album
            };
        "#,
    )
    .unwrap();
    let warnings = assert_policy_typecheck_warns_for_mode(
        simple_schema_file(),
        p.clone(),
        ValidationMode::Permissive,
    );
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("policy0"),)
    );
}

#[test]
fn is_action() {
    assert_policy_typechecks(
        simple_schema_file(),
        parse_policy(
            None,
            r#"
            permit(principal, action, resource) when { action is Action };
        "#,
        )
        .unwrap(),
    );
    let p = parse_policy(
        None,
        r#"
            permit(principal, action, resource) when { action is User};
        "#,
    )
    .unwrap();
    let warnings = assert_policy_typecheck_warns(simple_schema_file(), p.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(p.loc().cloned(), PolicyID::from_string("policy0"),)
    );
}

#[test]
fn entity_record_lub_is_none() {
    let src = r#"permit(principal, action, resource) when { (if 1 > 0 then User::"alice" else {name: "bob"}).name == "jane" };"#;
    let errors = assert_policy_typecheck_fails(
        simple_schema_file(),
        parse_policy(Some(PolicyID::from_string("0")), src).expect("Policy should parse."),
    );
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::incompatible_types(
            get_loc(src, r#"if 1 > 0 then User::"alice" else {name: "bob"}"#),
            PolicyID::from_string("0"),
            [
                Type::closed_record_with_required_attributes([(
                    "name".into(),
                    Type::primitive_string(),
                )]),
                Type::named_entity_reference_from_str("User"),
            ],
            LubHelp::EntityRecord,
            LubContext::Conditional,
        )
    );
}

#[test]
fn optional_attr_fail() {
    let schema: json_schema::NamespaceDefinition<RawName> = serde_json::from_str(
        r#"
        {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ ],
                    "shape": {
                        "type": "Record",
                        "additionalAttributes": false,
                        "attributes": {
                            "name": { "type": "String", "required": false}
                        }
                    }
                }
            },
            "actions": {
                "view_photo": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["User"],
                        "context": {
                            "type": "Record",
                            "additionalAttributes": false,
                            "attributes": { }
                        }
                    }
                }
            }
        }"#,
    )
    .expect("Expected valid schema");

    let src = r#"permit(principal, action, resource) when { principal.name == "foo" };"#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).expect("Policy should parse.");
    let errors = assert_policy_typecheck_fails(schema, policy);
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
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
fn type_error_is_not_reported_for_every_cross_product_element() {
    let schema: json_schema::NamespaceDefinition<RawName> = serde_json::from_str(
        r#"
        {
            "entityTypes": {
                "Foo": {},
                "Bar": {},
                "Baz": {},
                "Buz": {}
            },
            "actions": { "act": {
                "appliesTo" : {
                    "principalTypes" : ["Foo", "Bar", "Baz", "Buz"],
                    "resourceTypes" : ["Foo", "Bar", "Baz", "Buz"]
                }
            }
            }
        }"#,
    )
    .expect("Expected valid schema");

    let src = r#"permit(principal, action, resource) when { 1 > true };"#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).expect("Policy should parse.");
    let errors = assert_policy_typecheck_fails(schema, policy);
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_one_of_types(
            get_loc(src, "true"),
            PolicyID::from_string("0"),
            vec![Type::primitive_long()],
            Type::True,
            None,
        )
    );
}

#[test]
fn action_groups() {
    let schema: json_schema::NamespaceDefinition<RawName> = serde_json::from_str(
        r#"
        {
            "entityTypes": { "Entity": {} },
            "actions": {
                "group": { },
                "act": {
                    "memberOf": [ {"id": "group"} ]
                }
            }
        }"#,
    )
    .expect("Expected valid schema");

    // Two good cases for `action in`.
    assert_policy_typechecks(
        schema.clone(),
        parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action in Action::"group", resource);"#,
        )
        .expect("Policy should parse."),
    );

    assert_policy_typechecks(
        schema.clone(),
        parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action in Action::"act", resource);"#,
        )
        .expect("Policy should parse."),
    );

    // Four test cases that I think might have failed before namespaces were
    // added to the schema. Prior to that change, actions were identified only
    // by their Uid without considering the type, so `Entity::"group"` might
    // have been treated the same as `Action::"group"` in some cases.
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { action in Entity::"group" };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(schema.clone(), policy.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(policy.loc().cloned(), PolicyID::from_string("0"),)
    );

    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { action in Entity::"act" };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(schema.clone(), policy.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(policy.loc().cloned(), PolicyID::from_string("0"),)
    );

    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { Entity::"group" in action };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(schema.clone(), policy.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(policy.loc().cloned(), PolicyID::from_string("0"),)
    );

    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"permit(principal, action, resource) when { Entity::"act" in action };"#,
    )
    .expect("Policy should parse.");
    let warnings = assert_policy_typecheck_warns(schema, policy.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(policy.loc().cloned(), PolicyID::from_string("0"),)
    );
}

// Example demonstrating Non-terminating LUB computation
#[test]
fn record_entity_lub_non_term() {
    let schema: json_schema::NamespaceDefinition<RawName> =
        serde_json::from_value(serde_json::json!(
        {
            "entityTypes": {
                "E" : {
                    "shape" : {
                        "type" : "Record",
                        "attributes" : {}
                    },
                },
              "U": {
                "shape": {
                  "type": "Record",
                  "attributes": {
                    "foo": {
                      "type": "Record",
                      "attributes" : {
                        "foo" : { "type" : "Entity", "name" : "U" }
                      }
                    },
                    "bar": { "type": "Boolean" }
                  }
                }
              }
            },
            "actions": {
              "view": {
                "appliesTo": {
                  "principalTypes": ["U"],
                  "resourceTypes": ["E"]
                }
              }
            }
          }))
        .unwrap();

    let src = r#"permit(principal, action, resource) when {if principal.bar then principal.foo else U::"b"};"#;
    let policy = parse_policy(None, src).expect("Policy should parse.");
    let errors = assert_policy_typecheck_fails(schema, policy);
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::incompatible_types(
            get_loc(src, r#"if principal.bar then principal.foo else U::"b""#),
            PolicyID::from_string("policy0"),
            [
                Type::closed_record_with_required_attributes([(
                    "foo".into(),
                    Type::named_entity_reference_from_str("U"),
                )]),
                Type::named_entity_reference_from_str("U"),
            ],
            LubHelp::EntityRecord,
            LubContext::Conditional,
        )
    );
}

#[test]
fn validate_policy_with_common_type_schema() {
    let namespace_def: json_schema::NamespaceDefinition<RawName> =
        serde_json::from_value(serde_json::json!(
        {
            "commonTypes": {
                "SharedAttrs": {
                    "type": "Record",
                    "attributes": {
                        "flag": {"type": "Boolean"}
                    }
                }
            },
            "entityTypes": {
                "Entity": {
                    "shape": {
                        "type": "SharedAttrs",
                    }
                }
            },
            "actions": {
              "act": {
                "appliesTo": {
                  "principalTypes": ["Entity"],
                  "resourceTypes": ["Entity"]
                }
              }
            }
        }))
        .unwrap();

    assert_policy_typechecks(
        namespace_def,
        parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action == Action::"act", resource) when { principal.flag };"#,
        )
        .expect("Policy should parse."),
    );
}

#[test]
fn extended_has() {
    let schema_src = r#"
        entity A {
          x?: {
            y?: {
              z?: Long,
            }
          }
        };

        action "action" appliesTo {
          principal: A,
          resource: A,
        };
    "#;
    let (schema, _) =
        ValidatorSchema::from_cedarschema_str(schema_src, Extensions::none()).unwrap();

    let policy = parse_policy(
        None,
        r#"
    permit(principal, action == Action::"action", resource) when {
        principal has x.y.z && principal.x.y.z > 1
    };
    "#,
    )
    .unwrap();
    assert_policy_typechecks(schema.clone(), policy);
    let policy = parse_policy(
        None,
        r#"
    permit(principal, action == Action::"action", resource) when {
        principal has x.y && principal.x.y has z
    };
    "#,
    )
    .unwrap();
    assert_policy_typechecks(schema.clone(), policy);
    let policy = parse_policy(
        None,
        r#"
    permit(principal, action == Action::"action", resource) when {
        principal has x && principal.x has y.z
    };
    "#,
    )
    .unwrap();
    assert_policy_typechecks(schema.clone(), policy);

    let src = r#"
    permit(principal, action == Action::"action", resource) when {
        principal has x.y && principal.x.y.z > 1
    };
    "#;
    let policy = parse_policy(None, src).unwrap();
    let errors = assert_policy_typecheck_fails(schema.clone(), policy);
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::unsafe_optional_attribute_access(
            get_loc(src, "principal.x.y.z"),
            PolicyID::from_string("policy0"),
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("A".parse().unwrap()),
                vec!["z".into(), "y".into(), "x".into()],
            )
        )
    );

    let src = r#"
    permit(principal, action == Action::"action", resource) when {
        principal has x && principal.x.y has z
    };
    "#;
    let policy = parse_policy(None, src).unwrap();
    let errors = assert_policy_typecheck_fails(schema.clone(), policy);
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::unsafe_optional_attribute_access(
            get_loc(src, "principal.x.y"),
            PolicyID::from_string("policy0"),
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("A".parse().unwrap()),
                vec!["y".into(), "x".into()],
            )
        )
    );

    let src = r#"
    permit(principal, action == Action::"action", resource) when {
        principal has x.y.z && principal.x.y.a > 1
    };
    "#;
    let policy = parse_policy(None, src).unwrap();
    let errors = assert_policy_typecheck_fails(schema, policy);
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::unsafe_attribute_access(
            get_loc(src, "principal.x.y.a"),
            PolicyID::from_string("policy0"),
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("A".parse().unwrap()),
                vec!["a".into(), "y".into(), "x".into(),],
            ),
            Some("z".into()),
            false
        )
    );
}

mod templates {
    use super::*;

    #[test]
    fn principal_eq_slot() {
        assert_policy_typechecks(
            simple_schema_file(),
            parse_policy_or_template(
                None,
                r#"permit(principal == ?principal, action, resource);"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn resource_eq_slot() {
        assert_policy_typechecks(
            simple_schema_file(),
            parse_policy_or_template(None, r#"permit(principal, action, resource == ?resource);"#)
                .unwrap(),
        );
    }

    #[test]
    fn principal_resource_eq_slot() {
        assert_policy_typechecks(
            simple_schema_file(),
            parse_policy_or_template(
                None,
                r#"permit(principal == ?principal, action, resource == ?resource);"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn principal_in_slot() {
        assert_policy_typechecks(
            simple_schema_file(),
            parse_policy_or_template(
                None,
                r#"permit(principal in ?principal, action, resource);"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn resource_in_slot() {
        assert_policy_typechecks(
            simple_schema_file(),
            parse_policy_or_template(None, r#"permit(principal, action, resource in ?resource);"#)
                .unwrap(),
        );
    }

    #[test]
    fn principal_resource_in_slot() {
        assert_policy_typechecks(
            simple_schema_file(),
            parse_policy_or_template(
                None,
                r#"permit(principal in ?principal, action, resource in ?resource);"#,
            )
            .unwrap(),
        );
    }

    #[test]
    fn resource_slot_safe_body() {
        assert_policy_typechecks(
            simple_schema_file(),
            parse_policy_or_template(
                None,
                r#"permit(principal, action, resource in ?resource) when { resource in Group::"Friends" && resource.name like "*" };"#,
            )
            .unwrap()
        );
    }

    #[test]
    fn resource_slot_error_body() {
        let src = r#"permit(principal, action, resource in ?resource) when { resource in Group::"Friends" && resource.bogus };"#;
        let errors = assert_policy_typecheck_fails(
            simple_schema_file(),
            parse_policy_or_template(None, src).unwrap(),
        );
        let error = assert_exactly_one_diagnostic(errors);
        assert_eq!(
            error,
            ValidationError::unsafe_attribute_access(
                get_loc(src, "resource.bogus"),
                PolicyID::from_string("policy0"),
                AttributeAccess::EntityLUB(
                    EntityLUB::single_entity("Group".parse().unwrap()),
                    vec!["bogus".into()],
                ),
                Some("name".to_string()),
                false,
            )
        );
    }

    #[test]
    fn principal_slot_safe_body() {
        assert_policy_typechecks(
            simple_schema_file(),
            parse_policy_or_template(
                None,
                r#"permit(principal == ?principal, action, resource in ?resource) when { principal has age && principal.age > 0};"#,
            )
            .unwrap()
        );
    }

    #[test]
    fn principal_slot_error_body() {
        let src = r#"permit(principal == ?principal, action, resource) when { principal has age && principal.bogus > 0 };"#;
        let errors = assert_policy_typecheck_fails(
            simple_schema_file(),
            parse_policy_or_template(None, src).unwrap(),
        );
        let error = assert_exactly_one_diagnostic(errors);
        assert_eq!(
            error,
            ValidationError::unsafe_attribute_access(
                get_loc(src, "principal.bogus"),
                PolicyID::from_string("policy0"),
                AttributeAccess::EntityLUB(
                    EntityLUB::single_entity("User".parse().unwrap()),
                    vec!["bogus".into()],
                ),
                Some("age".to_string()),
                false,
            )
        );
    }

    #[test]
    fn template_all_false() {
        let template = parse_policy_or_template(
            None,
            r#"permit(principal == ?principal, action, resource) when { false };"#,
        )
        .unwrap();
        let warnings = assert_policy_typecheck_warns(simple_schema_file(), template.clone());
        let warning = assert_exactly_one_diagnostic(warnings);
        assert_eq!(
            warning,
            ValidationWarning::impossible_policy(
                template.loc().cloned(),
                PolicyID::from_string("policy0"),
            )
        );
    }
}
