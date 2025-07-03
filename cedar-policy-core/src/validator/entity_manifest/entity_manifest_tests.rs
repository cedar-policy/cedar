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

use std::fmt::{Display, Formatter, Write as FmtWrite};

use crate::ast::{
    self, BinaryOp, EntityUID, Expr, ExprKind, Literal, PolicySet, RequestType, UnaryOp, Var,
};

use crate::validator::entity_manifest::analysis::WrappedAccessPaths;
use crate::validator::{
    typecheck::{PolicyCheck, Typechecker},
    types::Type,
    ValidationMode,
};
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
    .0
}

fn document_fields_schema() -> ValidatorSchema {
    ValidatorSchema::from_cedarschema_str(
        "
entity User = {
name: String,
};

entity Document = {
owner: User,
viewer: User,
};

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

#[test]
fn test_simple_entity_manifest() {
    let mut pset = PolicySet::new();
    let policy = parse_policy(
        None,
        r#"permit(principal, action, resource)
when {
    principal.name == "John"
};"#,
    )
    .expect("should succeed");
    pset.add(policy.into()).expect("should succeed");

    let validator = Validator::new(schema());

    let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");

    // Define the human manifest using the json! macro
    let human_json = serde_json::json!({
        "perAction":
              [[
              {
            "principal": "User",
            "action": {
              "ty": "Action",
              "eid": "Read"
            },
            "resource": "Document"
          },
              ["principal.name"]
              ]],
    });

    // Convert the JSON value to a HumanEntityManifest
    let human_manifest: HumanEntityManifest = serde_json::from_value(human_json).unwrap();

    // Convert the human manifest to an EntityManifest
    let expected_manifest = human_manifest
        .to_entity_manifest(validator.schema())
        .unwrap();

    assert_manifests_equal(&entity_manifest, &expected_manifest);
}

#[test]
fn test_empty_entity_manifest() {
    let mut pset = PolicySet::new();
    let policy =
        parse_policy(None, "permit(principal, action, resource);").expect("should succeed");
    pset.add(policy.into()).expect("should succeed");

    let validator = Validator::new(schema());

    let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");

    // Define the human manifest using the json! macro
    let human_json = serde_json::json!({
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
    });

    // Convert the JSON value to a HumanEntityManifest
    let human_manifest: HumanEntityManifest = serde_json::from_value(human_json).unwrap();

    // Convert the human manifest to an EntityManifest
    let expected_manifest = human_manifest
        .to_entity_manifest(validator.schema())
        .unwrap();

    // Compare the computed manifest with the expected manifest
    assert_manifests_equal(&entity_manifest, &expected_manifest);
}

#[test]
fn test_entity_manifest_ancestors_required() {
    let mut pset = PolicySet::new();
    let policy = parse_policy(
        None,
        "permit(principal, action, resource)
when {
    principal in resource || principal.manager in resource
};",
    )
    .expect("should succeed");
    pset.add(policy.into()).expect("should succeed");

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
    let validator = Validator::new(schema);

    let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
    let human_computed = entity_manifest.to_human_format();
    eprintln!("{}", human_computed.to_json_string().unwrap());

    // Define the human manifest using the json! macro
    let human_json = serde_json::json!({
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
    });

    // Convert the JSON value to a HumanEntityManifest
    let human_manifest: HumanEntityManifest = serde_json::from_value(human_json).unwrap();

    // Convert the human manifest to an EntityManifest
    let expected_manifest = human_manifest
        .to_entity_manifest(validator.schema())
        .unwrap();

    assert_manifests_equal(&entity_manifest, &expected_manifest);
}

#[test]
fn test_entity_manifest_multiple_types() {
    let mut pset = PolicySet::new();
    let policy = parse_policy(
        None,
        r#"permit(principal, action, resource)
when {
    principal.name == "John"
};"#,
    )
    .expect("should succeed");
    pset.add(policy.into()).expect("should succeed");

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
    let validator = Validator::new(schema);

    let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");

    // Define the human manifest using the json! macro
    let human_json = serde_json::json!({
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
    });

    // Convert the JSON value to a HumanEntityManifest
    let human_manifest: HumanEntityManifest = serde_json::from_value(human_json).unwrap();

    // Convert the human manifest to an EntityManifest
    let expected_manifest = human_manifest
        .to_entity_manifest(validator.schema())
        .unwrap();

    assert_manifests_equal(&entity_manifest, &expected_manifest);
}

#[test]
fn test_entity_manifest_multiple_branches() {
    let mut pset = PolicySet::new();
    let policy1 = parse_policy(
        None,
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
    )
    .unwrap();
    let policy2 = parse_policy(
        Some(PolicyID::from_string("Policy2")),
        r#"permit(
  principal,
  action == Action::"Read",
  resource
)
when
{
  resource.metadata.owner == principal
};"#,
    )
    .unwrap();
    pset.add(policy1.into()).expect("should succeed");
    pset.add(policy2.into()).expect("should succeed");

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
    let validator = Validator::new(schema);

    let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");

    // Define the human manifest using the json! macro
    let human_json = serde_json::json!({
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
    });

    // Convert the JSON value to a HumanEntityManifest
    let human_manifest: HumanEntityManifest = serde_json::from_value(human_json).unwrap();

    // Convert the human manifest to an EntityManifest
    let expected_manifest = human_manifest
        .to_entity_manifest(validator.schema())
        .unwrap();

    assert_manifests_equal(&entity_manifest, &expected_manifest);
}

#[test]
fn test_entity_manifest_struct_equality() {
    let mut pset = PolicySet::new();
    // we need to load all of the metadata, not just nickname
    // no need to load actual name
    let policy = parse_policy(
        None,
        r#"permit(principal, action, resource)
when {
    principal.metadata.nickname == "timmy" && principal.metadata == {
        "friends": [ "oliver" ],
        "nickname": "timmy"
    }
};"#,
    )
    .expect("should succeed");
    pset.add(policy.into()).expect("should succeed");

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
    let validator = Validator::new(schema);

    let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");

    // Define the human manifest using the json! macro
    let human_json = serde_json::json!({
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
    });

    // Convert the JSON value to a HumanEntityManifest
    let human_manifest: HumanEntityManifest = serde_json::from_value(human_json).unwrap();

    // Convert the human manifest to an EntityManifest
    let expected_manifest = human_manifest
        .to_entity_manifest(validator.schema())
        .unwrap();

    assert_manifests_equal(&entity_manifest, &expected_manifest);
}

#[test]
fn test_entity_manifest_struct_equality_left_right_different() {
    let mut pset = PolicySet::new();
    // we need to load all of the metadata, not just nickname
    // no need to load actual name
    let policy = parse_policy(
        None,
        r#"permit(principal, action, resource)
when {
    principal.metadata == resource.metadata
};"#,
    )
    .expect("should succeed");
    pset.add(policy.into()).expect("should succeed");

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
    let validator = Validator::new(schema);

    let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");

    // Define the human manifest using the json! macro
    let human_json = serde_json::json!({
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
    });

    // Convert the JSON value to a HumanEntityManifest
    let human_manifest: HumanEntityManifest = serde_json::from_value(human_json).unwrap();

    // Convert the human manifest to an EntityManifest
    let expected_manifest = human_manifest
        .to_entity_manifest(validator.schema())
        .unwrap();

    assert_manifests_equal(&entity_manifest, &expected_manifest);
}

#[test]
fn test_entity_manifest_with_if() {
    let mut pset = PolicySet::new();

    let validator = Validator::new(document_fields_schema());

    let policy = parse_policy(
        None,
        r#"permit(principal, action, resource)
when {
    if principal.name == "John"
    then resource.owner.name == User::"oliver".name
    else resource.viewer == User::"oliver"
};"#,
    )
    .expect("should succeed");
    pset.add(policy.into()).expect("should succeed");

    let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");

    // Define the human manifest using the json! macro
    let human_json = serde_json::json!({
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
    });

    // Convert the JSON value to a HumanEntityManifest
    let human_manifest: HumanEntityManifest = serde_json::from_value(human_json).unwrap();

    // Convert the human manifest to an EntityManifest
    let expected_manifest = human_manifest
        .to_entity_manifest(validator.schema())
        .unwrap();

    assert_manifests_equal(&entity_manifest, &expected_manifest);
}

#[test]
fn test_entity_manifest_if_literal_record() {
    let mut pset = PolicySet::new();

    let validator = Validator::new(document_fields_schema());

    let policy = parse_policy(
        None,
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
    )
    .expect("should succeed");
    pset.add(policy.into()).expect("should succeed");

    let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");

    // Define the human manifest using the json! macro
    let human_json = serde_json::json!({
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
    });

    // Convert the JSON value to a HumanEntityManifest
    let human_manifest: HumanEntityManifest = serde_json::from_value(human_json).unwrap();

    // Convert the human manifest to an EntityManifest
    let expected_manifest = human_manifest
        .to_entity_manifest(validator.schema())
        .unwrap();

    assert_manifests_equal(&entity_manifest, &expected_manifest);
}
