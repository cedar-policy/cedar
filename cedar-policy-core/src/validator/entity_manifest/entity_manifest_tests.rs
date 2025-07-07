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

//! Tests generating entity manifests (without doing any slicing)

use crate::validator::entity_manifest::human_format::HumanEntityManifest;
use crate::validator::entity_manifest::{compute_entity_manifest, EntityManifest};
use crate::{
    ast::PolicyID, extensions::Extensions, parser::parse_policy, validator::ValidatorSchema,
};
use std::fmt::Write;

use std::fmt::Write as FmtWrite;

use crate::ast::PolicySet;

use crate::validator::{ValidationResult, Validator};

/// Assert that two entity manifests are equal, and if not, print them in human format
fn assert_manifests_equal(actual: &EntityManifest, expected: &EntityManifest) {
    if actual != expected {
        let actual_human = actual.to_human_format();
        let expected_human = expected.to_human_format();

        let mut error_message = String::new();
        writeln!(&mut error_message, "Entity manifests are not equal!").unwrap();
        writeln!(&mut error_message, "Actual manifest (human format):").unwrap();
        writeln!(
            &mut error_message,
            "{}",
            actual_human.to_json_string().unwrap()
        )
        .unwrap();
        writeln!(&mut error_message, "Expected manifest (human format):").unwrap();
        writeln!(
            &mut error_message,
            "{}",
            expected_human.to_json_string().unwrap()
        )
        .unwrap();

        assert_eq!(actual, expected, "{}", error_message);
    }
}

// Schema for testing in this module
fn schema() -> ValidatorSchema {
    ValidatorSchema::from_cedarschema_str(
        "
entity User = {
  name: String,
} tags String;
 

entity Document tags String;

action Read appliesTo {
  principal: [User],
  resource: [Document]
};
    ",
        Extensions::all_available(),
    )
    .unwrap()
    .0
}

fn document_fields_schema() -> ValidatorSchema {
    ValidatorSchema::from_cedarschema_str(
        "
entity User = {
name: String,
} tags String;

entity Document = {
owner: User,
viewer: User,
} tags String;

action Read appliesTo {
principal: [User],
resource: [Document]
};
",
        Extensions::all_available(),
    )
    .unwrap()
    .0
}

/// Helper function to create an expected manifest from a JSON value
fn create_expected_manifest(
    human_json: serde_json::Value,
    validator: &Validator,
) -> EntityManifest {
    let human_manifest: HumanEntityManifest = serde_json::from_value(human_json).unwrap();
    human_manifest
        .to_entity_manifest(validator.schema())
        .unwrap()
}

/// Helper function to test entity manifest generation with a single policy
fn test_entity_manifest_with_policy(
    policy_str: &str,
    policy_id: Option<PolicyID>,
    validator: Validator,
    expected_json: serde_json::Value,
) {
    let mut pset = PolicySet::new();
    let policy = parse_policy(policy_id, policy_str).expect("should succeed");
    pset.add(policy.into()).expect("should succeed");

    let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
    let expected_manifest = create_expected_manifest(expected_json, &validator);

    assert_manifests_equal(&entity_manifest, &expected_manifest);
}

/// Helper function to test entity manifest generation with multiple policies
fn test_entity_manifest_with_policies(
    policies: Vec<(&str, Option<PolicyID>)>,
    validator: Validator,
    expected_json: serde_json::Value,
) {
    let mut pset = PolicySet::new();
    for (policy_str, policy_id) in policies {
        let policy = parse_policy(policy_id, policy_str).expect("should succeed");
        pset.add(policy.into()).expect("should succeed");
    }

    let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
    let expected_manifest = create_expected_manifest(expected_json, &validator);

    assert_manifests_equal(&entity_manifest, &expected_manifest);
}

#[test]
fn test_simple_entity_manifest() {
    test_entity_manifest_with_policy(
        r#"permit(principal, action, resource)
when {
    principal.name == "John"
};"#,
        None,
        Validator::new(schema()),
        serde_json::json!({
            "perAction": [[
                {
                    "principal": "User",
                    "action": {
                        "ty": "Action",
                        "eid": "Read"
                    },
                    "resource": "Document"
                },
                ["principal.name"]
            ]]
        }),
    );
}

#[test]
fn test_empty_entity_manifest() {
    test_entity_manifest_with_policy(
        "permit(principal, action, resource);",
        None,
        Validator::new(schema()),
        serde_json::json!({
            "perAction": [[
                {
                    "principal": "User",
                    "action": {
                        "ty": "Action",
                        "eid": "Read"
                    },
                    "resource": "Document"
                },
                []
            ]]
        }),
    );
}

#[test]
fn test_entity_manifest_ancestors_required() {
    let schema = ValidatorSchema::from_cedarschema_str(
        "
entity User in [Document] = {
  name: String,
  manager: User
};
entity Document;
action Read appliesTo {
  principal: [User],
  resource: [Document]
};
  ",
        Extensions::all_available(),
    )
    .unwrap()
    .0;

    test_entity_manifest_with_policy(
        "permit(principal, action, resource)
when {
    principal in resource || principal.manager in resource
};",
        None,
        Validator::new(schema),
        serde_json::json!({
            "perAction": [[
                {
                    "principal": "User",
                    "action": {
                        "ty": "Action",
                        "eid": "Read"
                    },
                    "resource": "Document"
                },
                ["principal in resource", "principal.manager in resource"]
            ]]
        }),
    );
}

#[test]
fn test_entity_manifest_multiple_types() {
    let schema = ValidatorSchema::from_cedarschema_str(
        "
entity User = {
  name: String,
};

entity OtherUserType = {
  name: String,
  irrelevant: String,
};

entity Document;

action Read appliesTo {
  principal: [User, OtherUserType],
  resource: [Document]
};
        ",
        Extensions::all_available(),
    )
    .unwrap()
    .0;

    test_entity_manifest_with_policy(
        r#"permit(principal, action, resource)
when {
    principal.name == "John"
};"#,
        None,
        Validator::new(schema),
        serde_json::json!({
            "perAction": [
                [
                    {
                        "principal": "User",
                        "action": {
                            "ty": "Action",
                            "eid": "Read"
                        },
                        "resource": "Document"
                    },
                    ["principal.name"]
                ],
                [
                    {
                        "principal": "OtherUserType",
                        "action": {
                            "ty": "Action",
                            "eid": "Read"
                        },
                        "resource": "Document"
                    },
                    ["principal.name"]
                ]
            ]
        }),
    );
}

#[test]
fn test_entity_manifest_multiple_branches() {
    let schema = ValidatorSchema::from_cedarschema_str(
        "
entity User;

entity Metadata = {
   owner: User,
   time: String,
};

entity Document = {
  metadata: Metadata,
  readers: Set<User>,
};

action Read appliesTo {
  principal: [User],
  resource: [Document]
};
        ",
        Extensions::all_available(),
    )
    .unwrap()
    .0;

    test_entity_manifest_with_policies(
        vec![
            (
                r#"
permit(
  principal,
  action == Action::"Read",
  resource
)
when
{
  resource.readers.contains(principal)
};"#,
                None,
            ),
            (
                r#"permit(
  principal,
  action == Action::"Read",
  resource
)
when
{
  resource.metadata.owner == principal
};"#,
                Some(PolicyID::from_string("Policy2")),
            ),
        ],
        Validator::new(schema),
        serde_json::json!({
            "perAction": [[
                {
                    "principal": "User",
                    "action": {
                        "ty": "Action",
                        "eid": "Read"
                    },
                    "resource": "Document"
                },
                ["resource.readers", "resource.metadata.owner"]
            ]]
        }),
    );
}

#[test]
fn test_entity_manifest_struct_equality() {
    let schema = ValidatorSchema::from_cedarschema_str(
        "
entity User = {
  name: String,
  metadata: {
    friends: Set<String>,
    nickname: String,
  },
};

entity Document;

action BeSad appliesTo {
  principal: [User],
  resource: [Document]
};
        ",
        Extensions::all_available(),
    )
    .unwrap()
    .0;

    test_entity_manifest_with_policy(
        r#"permit(principal, action, resource)
when {
    principal.metadata.nickname == "timmy" && principal.metadata == {
        "friends": [ "oliver" ],
        "nickname": "timmy"
    }
};"#,
        None,
        Validator::new(schema),
        serde_json::json!({
            "perAction": [[
                {
                    "principal": "User",
                    "action": {
                        "ty": "Action",
                        "eid": "BeSad"
                    },
                    "resource": "Document"
                },
                ["principal.metadata.nickname", "principal.metadata.friends"]
            ]]
        }),
    );
}

#[test]
fn test_entity_manifest_struct_equality_left_right_different() {
    let schema = ValidatorSchema::from_cedarschema_str(
        "
entity User = {
  name: String,
  metadata: {
    friends: Set<String>,
    nickname: String,
  },
};

entity Document;

action Hello appliesTo {
  principal: [User],
  resource: [User]
};
        ",
        Extensions::all_available(),
    )
    .unwrap()
    .0;

    test_entity_manifest_with_policy(
        r#"permit(principal, action, resource)
when {
    principal.metadata == resource.metadata
};"#,
        None,
        Validator::new(schema),
        serde_json::json!({
            "perAction": [[
                {
                    "principal": "User",
                    "action": {
                        "ty": "Action",
                        "eid": "Hello"
                    },
                    "resource": "User"
                },
                [
                    "principal.metadata.nickname",
                    "principal.metadata.friends",
                    "resource.metadata.nickname",
                    "resource.metadata.friends"
                ]
            ]]
        }),
    );
}

#[test]
fn test_entity_manifest_with_if() {
    test_entity_manifest_with_policy(
        r#"permit(principal, action, resource)
when {
    if principal.name == "John"
    then resource.owner.name == User::"oliver".name
    else resource.viewer == User::"oliver"
};"#,
        None,
        Validator::new(document_fields_schema()),
        serde_json::json!({
            "perAction": [[
                {
                    "principal": "User",
                    "action": {
                        "ty": "Action",
                        "eid": "Read"
                    },
                    "resource": "Document"
                },
                [
                    "principal.name",
                    "User::\"oliver\".name",
                    "resource.owner.name",
                    "resource.viewer"
                ]
            ]]
        }),
    );
}

#[test]
fn test_entity_manifest_if_literal_record() {
    test_entity_manifest_with_policy(
        r#"permit(principal, action, resource)
when {
    {
      "myfield":
          {
            "secondfield":
            if principal.name == "yihong"
            then principal
            else resource.owner,
            "ignored but still important due to errors":
            resource.viewer
          }
    }["myfield"]["secondfield"].name == "pavel"
};"#,
        None,
        Validator::new(document_fields_schema()),
        serde_json::json!({
            "perAction": [[
                {
                    "principal": "User",
                    "action": {
                        "ty": "Action",
                        "eid": "Read"
                    },
                    "resource": "Document"
                },
                [
                    "principal.name",
                    "resource.viewer",
                    "resource.owner.name"
                ]
            ]]
        }),
    );
}

#[test]
fn test_has_tag_simple() {
    test_entity_manifest_with_policy(
        r#"permit(principal, action, resource)
when {
    principal.hasTag("mytag")
};"#,
        None,
        Validator::new(schema()),
        serde_json::json!({
            "perAction": [[
                {
                    "principal": "User",
                    "action": {
                        "ty": "Action",
                        "eid": "Read"
                    },
                    "resource": "Document"
                },
                ["principal.getTag(\"mytag\")"]
            ]]
        }),
    );
}

#[test]
fn test_has_tag_computed() {
    test_entity_manifest_with_policy(
        r#"permit(principal, action, resource)
when {
    principal.hasTag(resource.owner.name)
};"#,
        None,
        Validator::new(document_fields_schema()),
        serde_json::json!({
            "perAction": [[
                {
                    "principal": "User",
                    "action": {
                        "ty": "Action",
                        "eid": "Read"
                    },
                    "resource": "Document"
                },
                ["principal.getTag(resource.owner.name)"]
            ]]
        }),
    );
}

#[test]
fn test_multiple_possible_tags_and_possible_entities() {
    test_entity_manifest_with_policy(
        r#"permit(principal, action, resource)
when {
        (if 
            resource.owner.name == "oliver"
            then resource.owner
            else resource.viewer
        ).hasTag(if principal.name == "yihong"
            then "yihong"
            else resource.owner.name)
};"#,
        None,
        Validator::new(document_fields_schema()),
        serde_json::json!({
            "perAction": [[
                {
                    "principal": "User",
                    "action": {
                        "ty": "Action",
                        "eid": "Read"
                    },
                    "resource": "Document"
                },
                [
                    "resource.owner.getTag(\"yihong\")",
                    "resource.owner.getTag(resource.owner.name)",
                    "resource.viewer.getTag(\"yihong\")",
                    "resource.viewer.getTag(resource.owner.name)",
                    "principal.name"
                ]
            ]]
        }),
    );
}
