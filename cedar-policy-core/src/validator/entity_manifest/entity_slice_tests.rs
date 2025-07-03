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

//! Tests using an entity manifest to reduce the size of the entity store.

use similar_asserts::assert_eq;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ast::{Context, Entity, EntityUID, PolicyID, PolicySet, Request},
    entities::{Dereference, Entities, EntityJsonParser, TCComputation},
    extensions::Extensions,
    parser::{self, parse_policy},
    validator::entity_manifest::EntityManifest,
};

use crate::validator::{
    entity_manifest::compute_entity_manifest, CoreSchema, Validator, ValidatorSchema,
};

/// The implementation of [`Eq`] and [`PartialEq`] for
/// entities just compares entity ids.
/// This implementation does a more traditional, deep equality
/// check comparing attributes, ancestors, and the id.
fn entity_deep_equal(this: &Entity, other: &Entity) -> bool {
    this.uid() == other.uid()
        && BTreeMap::from_iter(this.attrs()) == BTreeMap::from_iter(other.attrs())
        && BTreeSet::from_iter(this.ancestors()) == BTreeSet::from_iter(other.ancestors())
}

/// The implementation of [`Eq`] and [`PartialEq`] on [`Entities`]
/// only checks equality by id for entities in the store.
/// This method checks that the entities are equal deeply,
/// using `[Entity::deep_equal]` to check equality.
/// Note that it ignores mode
fn entities_deep_equal(this: &Entities, other: &Entities) -> bool {
    for this_entity in this.iter() {
        let key = this_entity.uid();
        if let Dereference::Data(other_value) = other.entity(key) {
            if !entity_deep_equal(this_entity, other_value) {
                return false;
            }
        } else {
            return false;
        }
    }

    for key in other.iter() {
        if !matches!(this.entity(key.uid()), Dereference::Data(_)) {
            return false;
        }
    }

    true
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

fn schema_with_hierarchy() -> ValidatorSchema {
    ValidatorSchema::from_cedarschema_str(
        "
entity User in [Document] = {
  name: String,
  manager: User,
  personaldoc: Document,
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

#[track_caller]
fn expect_entity_slice_to(
    original: serde_json::Value,
    expected: serde_json::Value,
    schema: &ValidatorSchema,
    manifest: &EntityManifest,
) {
    let request = Request::new(
        (
            EntityUID::with_eid_and_type("User", "oliver").unwrap(),
            None,
        ),
        (
            EntityUID::with_eid_and_type("Action", "Read").unwrap(),
            None,
        ),
        (
            EntityUID::with_eid_and_type("Document", "dummy").unwrap(),
            None,
        ),
        Context::empty(),
        Some(schema),
        Extensions::all_available(),
    )
    .unwrap();

    let schema = CoreSchema::new(schema);
    let parser: EntityJsonParser<'_, '_, CoreSchema<'_>> = EntityJsonParser::new(
        Some(&schema),
        Extensions::all_available(),
        TCComputation::AssumeAlreadyComputed,
    );
    let original_entities = parser.from_json_value(original).unwrap();

    // Entity slicing results in invalid entity stores
    // since attributes may be missing.
    let parser_without_validation: EntityJsonParser<'_, '_> = EntityJsonParser::new(
        None,
        Extensions::all_available(),
        TCComputation::AssumeAlreadyComputed,
    );
    let expected_entities = parser_without_validation.from_json_value(expected).unwrap();

    let sliced_entities = manifest
        .slice_entities(&original_entities, &request)
        .unwrap();

    // PANIC SAFETY: panic in testing when test fails
    #[allow(clippy::panic)]
    if !entities_deep_equal(&sliced_entities, &expected_entities) {
        // pretty print differing json values
        let expected_json =
            serde_json::to_string_pretty(&expected_entities.to_json_value().unwrap())
                .expect("should serialize expected entities to JSON");
        let sliced_json = serde_json::to_string_pretty(&sliced_entities.to_json_value().unwrap())
            .expect("should serialize sliced entities to JSON");
        panic!(
            "Sliced entities differed from expected.\nExpected:\n{}\nGot:\n{}",
            expected_json, sliced_json
        );
    }
}

/// Helper function to test entity slicing with a single policy
fn test_entity_slice_with_policy(
    policy_str: &str,
    policy_id: Option<PolicyID>,
    schema: ValidatorSchema,
    original_json: serde_json::Value,
    expected_json: serde_json::Value,
) {
    let mut pset = PolicySet::new();
    let policy = parse_policy(policy_id, policy_str).expect("should succeed");
    pset.add(policy.into()).expect("should succeed");

    let validator = Validator::new(schema);
    let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");

    expect_entity_slice_to(
        original_json,
        expected_json,
        validator.schema(),
        &entity_manifest,
    );
}

/// Helper function to test entity slicing with multiple policies
fn test_entity_slice_with_policies(
    policies: Vec<(&str, Option<PolicyID>)>,
    schema: ValidatorSchema,
    original_json: serde_json::Value,
    expected_json: serde_json::Value,
) {
    let mut pset = PolicySet::new();
    for (policy_str, policy_id) in policies {
        let policy = parse_policy(policy_id, policy_str).expect("should succeed");
        pset.add(policy.into()).expect("should succeed");
    }

    let validator = Validator::new(schema);
    let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");

    expect_entity_slice_to(
        original_json,
        expected_json,
        validator.schema(),
        &entity_manifest,
    );
}

#[test]
fn test_simple_entity_manifest() {
    test_entity_slice_with_policy(
        r#"permit(principal, action, resource)
when {
    principal.name == "John"
};"#,
        None,
        schema(),
        serde_json::json!([
            {
                "uid" : { "type" : "User", "id" : "oliver"},
                "attrs" : {
                    "name" : "Oliver"
                },
                "parents" : []
            },
            {
                "uid" : { "type" : "User", "id" : "oliver2"},
                "attrs" : {
                    "name" : "Oliver2"
                },
                "parents" : []
            },
        ]),
        serde_json::json!([
            {
                "uid" : { "type" : "User", "id" : "oliver"},
                "attrs" : {
                    "name" : "Oliver"
                },
                "parents" : []
            },
        ]),
    );
}

#[test]
#[should_panic(expected = "Sliced entities differed")]
fn sanity_test_empty_entity_manifest() {
    test_entity_slice_with_policy(
        "permit(principal, action, resource);",
        None,
        schema(),
        serde_json::json!([
            {
                "uid" : { "type" : "User", "id" : "oliver"},
                "attrs" : {
                    "name" : "Oliver"
                },
                "parents" : []
            },
            {
                "uid" : { "type" : "User", "id" : "oliver2"},
                "attrs" : {
                    "name" : "Oliver2"
                },
                "parents" : []
            },
        ]),
        serde_json::json!([
            {
                "uid" : { "type" : "User", "id" : "oliver"},
                "attrs" : {
                    "name" : "Oliver"
                },
                "parents" : []
            },
            {
                "uid" : { "type" : "User", "id" : "oliver2"},
                "attrs" : {
                    "name" : "Oliver2"
                },
                "parents" : []
            },
        ]),
    );
}

#[test]
fn test_empty_entity_manifest() {
    test_entity_slice_with_policy(
        "permit(principal, action, resource);",
        None,
        schema(),
        serde_json::json!([
            {
                "uid" : { "type" : "User", "id" : "oliver"},
                "attrs" : {
                    "name" : "Oliver"
                },
                "parents" : []
            },
            {
                "uid" : { "type" : "User", "id" : "oliver2"},
                "attrs" : {
                    "name" : "Oliver2"
                },
                "parents" : []
            },
        ]),
        serde_json::json!([]),
    );
}

#[test]
fn test_entity_manifest_ancestors_skipped() {
    test_entity_slice_with_policy(
        "permit(principal, action, resource)
when {
    principal in resource || principal.manager in resource
};",
        None,
        schema_with_hierarchy(),
        serde_json::json!([
            {
                "uid" : { "type" : "User", "id" : "oliver"},
                "attrs" : {
                    "name" : "Oliver",
                    "manager": { "type" : "User", "id" : "george"},
                    "personaldoc": { "type" : "Document", "id" : "oliverdocument"}
                },
                "parents" : [
                    { "type" : "Document", "id" : "oliverdocument"},
                    { "type" : "Document", "id" : "dummy"}
                ]
            },
            {
                "uid" : { "type" : "User", "id" : "george"},
                "attrs" : {
                    "name" : "George",
                    "manager": { "type" : "User", "id" : "george"},
                    "personaldoc": { "type" : "Document", "id" : "georgedocument"}
                },
                "parents" : [
                ]
            },
        ]),
        serde_json::json!([
            {
                "uid" : { "type" : "User", "id" : "oliver"},
                "attrs" : {
                    "manager": { "__entity": { "type" : "User", "id" : "george"} }
                },
                "parents" : [
                    { "type" : "Document", "id" : "dummy"}
                ]
            },
        ]),
    );
}

#[test]
fn test_entity_manifest_possible_ancestors() {
    test_entity_slice_with_policy(
        r#"permit(principal, action, resource)
when {
    principal in (if 2 > 3
                  then Document::"dummy"
                  else principal.personaldoc)
};"#,
        None,
        schema_with_hierarchy(),
        serde_json::json!([
            {
                "uid" : { "type" : "User", "id" : "oliver"},
                "attrs" : {
                    "name" : "Oliver",
                    "manager": { "type" : "User", "id" : "george"},
                    "personaldoc": { "type" : "Document", "id" : "oliverdocument"}
                },
                "parents" : [
                    { "type" : "Document", "id" : "oliverdocument"},
                    { "type" : "Document", "id" : "georgedocument"},
                    { "type" : "Document", "id" : "dummy"}
                ]
            },
        ]),
        serde_json::json!([
            {
                "uid" : { "type" : "User", "id" : "oliver"},
                "attrs" : {
                    "personaldoc":{"__entity":{"type":"Document","id":"oliverdocument"}},
                },
                "parents" : [
                    { "type" : "Document", "id" : "dummy"},
                    { "type" : "Document", "id" : "oliverdocument"}
                ]
            }
        ]),
    );
}

#[test]
fn test_entity_manifest_set_of_ancestors() {
    let schema = ValidatorSchema::from_cedarschema_str(
        "
entity User in [User] = {
  name: String,
  managers: Set<User>
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

    test_entity_slice_with_policy(
        "permit(principal, action, resource)
when {
    principal in principal.managers
};",
        None,
        schema,
        serde_json::json!([
            {
                "uid" : { "type" : "User", "id" : "oliver"},
                "attrs" : {
                    "name" : "Oliver",
                    "managers": [
                        { "type" : "User", "id" : "george"},
                        { "type" : "User", "id" : "yihong"},
                        { "type" : "User", "id" : "ignored"},
                    ]
                },
                "parents" : [
                    { "type" : "User", "id" : "dummy"},
                    { "type" : "User", "id" : "george"},
                    { "type" : "User", "id" : "yihong"},
                ]
            },
        ]),
        serde_json::json!([
            {
                "uid" : { "type" : "User", "id" : "oliver"},
                "attrs" : {
                    "managers": [
                        { "__entity": { "type" : "User", "id" : "george"}},
                        { "__entity": { "type" : "User", "id" : "yihong"}},
                        { "__entity": { "type" : "User", "id" : "ignored"}},
                    ]
                },
                "parents" : [
                    { "type" : "User", "id" : "george"},
                    { "type" : "User", "id" : "yihong"},
                ]
            },
        ]),
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

    test_entity_slice_with_policies(
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
        schema,
        serde_json::json!([
            {
                "uid" : { "type" : "User", "id" : "oliver"},
                "attrs" : {
                },
                "parents" : [
                ]
            },
            {
                "uid": { "type": "Document", "id": "dummy"},
                "attrs": {
                    "metadata": { "type": "Metadata", "id": "olivermetadata"},
                    "readers": [{"type": "User", "id": "oliver"}]
                },
                "parents": [],
            },
            {
                "uid": { "type": "Metadata", "id": "olivermetadata"},
                "attrs": {
                    "owner": { "type": "User", "id": "oliver"},
                    "time": "now"
                },
                "parents": [],
            },
        ]),
        serde_json::json!([
            {
                "uid": { "type": "Document", "id": "dummy"},
                "attrs": {
                    "metadata": {"__entity": { "type": "Metadata", "id": "olivermetadata"}},
                    "readers": [{ "__entity": {"type": "User", "id": "oliver"}}]
                },
                "parents": [],
            },
            {
                "uid": { "type": "Metadata", "id": "olivermetadata"},
                "attrs": {
                    "owner": {"__entity": { "type": "User", "id": "oliver"}},
                },
                "parents": [],
            },
        ]),
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

    let validator = Validator::new(schema);
    let entity_manifest =
        compute_entity_manifest(&validator, &PolicySet::new()).expect("Should succeed");
    assert_eq!(entity_manifest, entity_manifest);
}

#[test]
fn test_slice_with_entity_alias() {
    let entities_json = serde_json::json!([{
        "uid" : { "type" : "User", "id" : "oliver"},
        "parents": [],
        "attrs": { "name": "oliver" }
    }]);

    // Only lit is accessed
    test_entity_slice_with_policy(
        r#"permit(principal in User::"oliver", action, resource) when { User::"oliver".name == "oliver" };"#,
        None,
        schema(),
        entities_json.clone(),
        entities_json.clone(),
    );

    // Only var is accessed
    test_entity_slice_with_policy(
        r#"permit(principal in User::"oliver", action, resource) when { principal.name == "oliver" };"#,
        None,
        schema(),
        entities_json.clone(),
        entities_json.clone(),
    );

    // Both are accessed
    test_entity_slice_with_policy(
        r#"permit(principal in User::"oliver", action, resource) when { principal.name == User::"oliver".name };"#,
        None,
        schema(),
        entities_json.clone(),
        entities_json,
    );
}

#[test]
fn test_slice_in_const_true_guard() {
    let schema = ValidatorSchema::from_cedarschema_str(
        "
entity User = {
  foo: String,
  bar: String,
  baz: String,
};

entity Document;

action Read appliesTo {
  principal: [User],
  resource: [Document]
};",
        Extensions::all_available(),
    )
    .unwrap()
    .0;

    test_entity_slice_with_policy(
        r#"permit(principal, action, resource) when {
                if (principal.foo == "foo") || true then
                    principal.bar == "bar"
                else
                    principal.baz == "baz"
            };"#,
        None,
        schema,
        serde_json::json!([{
            "uid" : { "type" : "User", "id" : "oliver"},
            "parents": [],
            "attrs": {
                "foo": "foo",
                "bar": "bar",
                "baz": "baz",
            }
        }]),
        serde_json::json!([{
            "uid" : { "type" : "User", "id" : "oliver"},
            "parents": [],
            "attrs": {
                "foo": "foo",
                "bar": "bar",
            }
        }]),
    );
}

#[test]
fn test_slice_with_entity_alias_with_two_attrs() {
    let schema = ValidatorSchema::from_cedarschema_str(
        "
entity User = {
  foo: String,
  bar: String,
};

entity Document;

action Read appliesTo {
  principal: [User],
  resource: [Document]
};",
        Extensions::all_available(),
    )
    .unwrap()
    .0;

    let entities_json = serde_json::json!([{
        "uid" : { "type" : "User", "id" : "oliver"},
        "parents": [],
        "attrs": {
            "foo": "1",
            "bar": "1",
        }
    }]);

    test_entity_slice_with_policy(
        r#"permit(principal in User::"oliver", action, resource) when { principal.foo == User::"oliver".bar };"#,
        None,
        schema,
        entities_json.clone(),
        entities_json,
    );
}

#[test]
fn test_slice_with_entity_alias_with_nested_record() {
    let schema = ValidatorSchema::from_cedarschema_str(
        "
entity User = {
  foo: {
    bar: String,
    baz: String,
  },
};

entity Document;

action Read appliesTo {
  principal: [User],
  resource: [Document]
};",
        Extensions::all_available(),
    )
    .unwrap()
    .0;

    let entities_json = serde_json::json!([{
        "uid" : { "type" : "User", "id" : "oliver"},
        "parents": [],
        "attrs": { "foo": {
            "bar": "1",
            "baz": "1",
        }}
    }]);

    test_entity_slice_with_policy(
        r#"permit(principal in User::"oliver", action, resource) when { principal.foo.bar == User::"oliver".foo.baz };"#,
        None,
        schema,
        entities_json.clone(),
        entities_json,
    );
}

#[test]
fn test_slice_with_entity_alias_ancestors() {
    let schema = ValidatorSchema::from_cedarschema_str(
        "
entity User in Group = {
  name: String
};

entity Group;

entity Document;

action Read appliesTo {
  principal: [User],
  resource: [Document]
};",
        Extensions::all_available(),
    )
    .unwrap()
    .0;
    let entities_json = serde_json::json!([{
        "uid" : { "type" : "User", "id" : "oliver"},
        "parents": [ { "type" : "Group", "id" : "oliver"}, ],
        "attrs": { "name": "oliver" }
    }]);

    // The `principal` alias needs to load ancestors, but the lit alias does not. Slicing still needs to load ancestors
    test_entity_slice_with_policy(
        r#"permit(principal in Group::"oliver", action, resource) when {User::"oliver".name == "oliver"};"#,
        None,
        schema.clone(),
        entities_json.clone(),
        entities_json.clone(),
    );

    // Lit wants ancestors, `principal` does not
    test_entity_slice_with_policy(
        r#"permit(principal, action, resource) when { User::"oliver" in Group::"oliver" && principal.name == "oliver"};"#,
        None,
        schema.clone(),
        entities_json.clone(),
        entities_json.clone(),
    );

    // Both need ancestors
    test_entity_slice_with_policy(
        r#"permit(principal, action, resource) when { User::"oliver" in Group::"oliver" && principal in Group::"oliver" };"#,
        None,
        schema,
        entities_json,
        serde_json::json!([{
            "uid" : { "type" : "User", "id" : "oliver"},
            "parents": [ { "type" : "Group", "id" : "oliver"}, ],
            "attrs": {}
        }]),
    );
}
