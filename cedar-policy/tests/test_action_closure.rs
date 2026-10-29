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

//! End-to-end tests for `Schema::action_closure_for`.
//!
//! A schema is sliced into one partial schema per action holding that action's
//! transitive closure. Each slice is stored as text and parsed back on its own,
//! which is the fast path an authorizer takes. Parsed alone, a slice must give
//! the same action entities as the full schema for the action and its
//! ancestors, and must accept and reject the same requests for the action.
//!
//! An entity type registry (every entity type, no actions) is what entity
//! validation needs. Linking it with a slice is also checked, where the slice
//! defines no enumerated type.

#![allow(clippy::unwrap_used, clippy::panic, reason = "tests")]

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema, SchemaFragment,
    ValidationMode, Validator,
};
use cedar_policy_core::validator::ValidatorSchema;
use serde_json::json;
use std::collections::BTreeSet;
use std::str::FromStr;

const LARGE: &str = include_str!("../benches/fixtures/large_action_hierarchy.cedarschema");

fn parse(label: &str, src: &str) -> Schema {
    Schema::from_str(src).unwrap_or_else(|e| panic!("{label} should parse: {e:?}"))
}

fn uid(src: &str) -> EntityUid {
    EntityUid::from_str(src).unwrap()
}

fn action(id: &str) -> EntityUid {
    uid(&format!(r#"Action::"{id}""#))
}

fn names<'a, T: ToString + 'a>(iter: impl Iterator<Item = &'a T>) -> BTreeSet<String> {
    iter.map(ToString::to_string).collect()
}

fn closure(full: &Schema, uid: &EntityUid) -> SchemaFragment {
    full.action_closure_for(uid)
        .unwrap()
        .unwrap_or_else(|| panic!("{uid} is declared"))
}

/// Slice `uid`, store the slice as Cedar schema text, and parse it back.
fn stored_closure(full: &Schema, uid: &EntityUid) -> Schema {
    let text = closure(full, uid).to_cedarschema().unwrap();
    parse("stored closure", &text)
}

/// Every entity type of `schema`, and no actions.
fn registry(schema: &Schema) -> Schema {
    ValidatorSchema::new(schema.as_ref().entity_types().cloned(), []).into()
}

/// The action entities of `slice` are exactly those of `full` for the uids
/// in `closure`.
#[track_caller]
fn assert_action_entities_agree(full: &Entities, slice: &Entities, closure: &[EntityUid]) {
    assert_eq!(
        slice.len(),
        closure.len(),
        "one action entity per closure member"
    );
    for uid in closure {
        assert_eq!(
            slice.get(uid),
            full.get(uid),
            "action entity {uid} differs from the full schema's"
        );
    }
}

/// Whether `schema` accepts the request.
fn accepts(
    schema: &Schema,
    principal: &str,
    action: &EntityUid,
    resource: &str,
    context: &serde_json::Value,
) -> bool {
    let context = Context::from_json_value(context.clone(), None).unwrap();
    Request::new(
        uid(principal),
        action.clone(),
        uid(resource),
        context,
        Some(schema),
    )
    .is_ok()
}

/// `slice` accepts exactly the requests `full` accepts, for each case.
#[track_caller]
fn assert_same_request_validation(
    full: &Schema,
    slice: &Schema,
    action: &EntityUid,
    cases: &[(&str, &str, serde_json::Value)],
) {
    for (principal, resource, context) in cases {
        assert_eq!(
            accepts(slice, principal, action, resource, context),
            accepts(full, principal, action, resource, context),
            "request ({principal}, {action}, {resource}, {context}) is validated differently"
        );
    }
}

#[test]
fn the_fixture_has_the_described_shape() {
    let full = parse("fixture", LARGE);
    assert!(full.is_complete());
    assert_eq!(
        names(full.entity_types()),
        BTreeSet::from(["Agent".into(), "Document".into(), "User".into()])
    );
    assert_eq!(full.actions().count(), 2022);
    let entities = full.action_entities().unwrap();
    let ancestors =
        |id: &str| -> BTreeSet<String> { names(entities.ancestors(&action(id)).unwrap()) };
    let groups = |p: &str| -> BTreeSet<String> {
        [r#"Action::"g""#, r#"Action::"m""#, p]
            .into_iter()
            .map(String::from)
            .collect()
    };
    assert_eq!(ancestors("a0000"), groups(r#"Action::"p00""#));
    assert_eq!(ancestors("a0099"), groups(r#"Action::"p00""#));
    assert_eq!(ancestors("a0100"), groups(r#"Action::"p01""#));
    assert_eq!(ancestors("a1999"), groups(r#"Action::"p19""#));
    assert_eq!(ancestors("p07"), BTreeSet::new());
}

#[test]
fn every_leaf_action_closure_alone_gives_its_action_entities() {
    let full = parse("fixture", LARGE);
    let full_entities = full.action_entities().unwrap();
    let stored_registry = registry(&full).as_ref().to_cedar_schema().unwrap();
    for n in 0..2000 {
        let id = format!("a{n:04}");
        let leaf = action(&id);
        let members = [
            leaf.clone(),
            action("g"),
            action("m"),
            action(&format!("p{:02}", n / 100)),
        ];

        let slice = stored_closure(&full, &leaf);
        assert!(!slice.is_complete(), "{id}: the slice is partial");
        assert_eq!(
            names(slice.actions()),
            names(members.iter()),
            "{id}: slice actions"
        );
        assert_eq!(
            slice.external_actions().count(),
            0,
            "{id}: no external actions"
        );
        assert_eq!(
            names(slice.external_entity_types()),
            BTreeSet::from(["Agent".into(), "Document".into(), "User".into()]),
            "{id}: appliesTo types are external"
        );
        assert_eq!(
            slice.defined_entity_types().count(),
            0,
            "{id}: no defined types"
        );
        assert_action_entities_agree(&full_entities, &slice.action_entities().unwrap(), &members);

        // With no enumerated type in the slice, it also links with the
        // registry into a complete schema.
        let linked =
            Schema::schema_link_complete([parse("stored registry", &stored_registry), slice])
                .unwrap_or_else(|e| panic!("{id}: registry and slice should link: {e:?}"));
        assert_action_entities_agree(&full_entities, &linked.action_entities().unwrap(), &members);
    }
}

#[test]
fn a_closure_alone_validates_requests_as_the_full_schema_does() {
    let full = parse("fixture", LARGE);
    let leaf = action("a1234");
    let slice = stored_closure(&full, &leaf);
    let context = json!({
        "a": "x", "b": "y", "c": "z",
        "d": { "__extn": { "fn": "decimal", "arg": "1.5" } },
        "e": ["q"]
    });
    let mut missing_attr = context.clone();
    missing_attr.as_object_mut().unwrap().remove("e");
    let mut wrong_type = context.clone();
    wrong_type["d"] = json!("1.5");
    let cases = [
        (r#"User::"u""#, r#"Document::"d""#, context.clone()),
        (r#"Agent::"a""#, r#"Document::"d""#, context.clone()),
        (r#"Document::"d""#, r#"Document::"d""#, context.clone()),
        (r#"User::"u""#, r#"User::"u""#, context),
        (r#"User::"u""#, r#"Document::"d""#, missing_attr),
        (r#"User::"u""#, r#"Document::"d""#, wrong_type),
        (r#"User::"u""#, r#"Document::"d""#, json!({})),
    ];
    assert!(accepts(&full, cases[0].0, &leaf, cases[0].1, &cases[0].2));
    assert_same_request_validation(&full, &slice, &leaf, &cases);
}

#[test]
fn a_closure_round_trips_through_json() {
    let full = parse("fixture", LARGE);
    let leaf = action("a1234");
    let fragment = closure(&full, &leaf);
    let from_json = Schema::from_json_str(&fragment.to_json_string().unwrap()).unwrap();
    let from_cedar = parse("cedar closure", &fragment.to_cedarschema().unwrap());
    for schema in [&from_json, &from_cedar] {
        assert_eq!(
            names(schema.external_entity_types()),
            BTreeSet::from(["Agent".into(), "Document".into(), "User".into()])
        );
    }
    let entities = |s: &Schema| s.action_entities().unwrap();
    assert_eq!(entities(&from_json).get(&leaf), entities(&full).get(&leaf));
    assert_eq!(entities(&from_cedar).get(&leaf), entities(&full).get(&leaf));
}

#[test]
fn an_undeclared_action_has_no_closure() {
    let full = parse("fixture", LARGE);
    assert!(full.action_closure_for(&action("a2000")).unwrap().is_none());
}

/// A deeper hierarchy, an entity hierarchy, and a context that mentions
/// entity types.
const NESTED: &str = r#"
entity Team;
entity User in Team { team: Team };
entity Doc;
entity Folder;
entity Unused;
action root;
action mid in root;
action leaf in mid appliesTo {
  principal: User,
  resource: Doc,
  context: { owner: User, folder?: Folder, tags: Set<{ by: Team }> }
};
action other in root appliesTo { principal: User, resource: Folder };
"#;

#[test]
fn a_closure_keeps_the_hierarchy_and_the_types_it_mentions() {
    let full = parse("nested", NESTED);
    let slice = stored_closure(&full, &action("leaf"));
    let members = [action("leaf"), action("mid"), action("root")];
    assert_eq!(names(slice.actions()), names(members.iter()));
    // `Team` is reached only through the context's nested record; `Unused`
    // and `other` are not reachable from `leaf` at all.
    assert_eq!(
        names(slice.external_entity_types()),
        BTreeSet::from(["Doc".into(), "Folder".into(), "Team".into(), "User".into()])
    );
    let full_entities = full.action_entities().unwrap();
    assert_action_entities_agree(&full_entities, &slice.action_entities().unwrap(), &members);

    let context = json!({
        "owner": { "__entity": { "type": "User", "id": "o" } },
        "tags": [{ "by": { "__entity": { "type": "Team", "id": "t" } } }]
    });
    let cases = [
        (r#"User::"u""#, r#"Doc::"d""#, context.clone()),
        (r#"User::"u""#, r#"Folder::"f""#, context),
        (
            r#"User::"u""#,
            r#"Doc::"d""#,
            json!({ "owner": "o", "tags": [] }),
        ),
    ];
    assert_same_request_validation(&full, &slice, &action("leaf"), &cases);

    // Linked with the registry, the slice validates a policy on `leaf` as the
    // full schema does, and the registry supplies the entity hierarchy.
    let linked = Schema::schema_link_complete([registry(&full), slice]).unwrap();
    assert_action_entities_agree(&full_entities, &linked.action_entities().unwrap(), &members);
    assert_eq!(
        names(linked.ancestors(&"User".parse().unwrap()).unwrap()),
        BTreeSet::from(["Team".into()])
    );
    let policies = PolicySet::from_str(
        r#"permit(principal, action in Action::"mid", resource)
           when { context.owner in principal.team };"#,
    )
    .unwrap();
    for schema in [&full, &linked] {
        let result = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        assert!(result.validation_passed(), "{result}");
    }
}

/// `Color` is enumerated and used both as a resource type and in a context.
const ENUMS: &str = r#"
entity User;
entity Group;
entity Color enum ["red", "blue"];
entity Size enum ["s", "m"];
action paint appliesTo { principal: User, resource: Color, context: { size: Size } };
action label appliesTo { principal: User, resource: Group, context: { color: Color } };
"#;

#[test]
fn a_closure_defines_the_enumerated_types_it_mentions() {
    let full = parse("enums", ENUMS);
    let full_entities = full.action_entities().unwrap();

    let paint = stored_closure(&full, &action("paint"));
    assert_eq!(
        names(paint.defined_entity_types()),
        BTreeSet::from(["Color".into(), "Size".into()])
    );
    assert_eq!(
        names(paint.external_entity_types()),
        BTreeSet::from(["User".into()])
    );
    assert_action_entities_agree(
        &full_entities,
        &paint.action_entities().unwrap(),
        &[action("paint")],
    );
    let size = |s: &str| json!({ "size": { "__entity": { "type": "Size", "id": s } } });
    assert_same_request_validation(
        &full,
        &paint,
        &action("paint"),
        &[
            (r#"User::"u""#, r#"Color::"red""#, size("s")),
            (r#"User::"u""#, r#"Color::"green""#, size("s")),
            (r#"User::"u""#, r#"Color::"red""#, size("xl")),
        ],
    );

    let label = stored_closure(&full, &action("label"));
    assert_eq!(
        names(label.defined_entity_types()),
        BTreeSet::from(["Color".into()])
    );
    let color = |c: &str| json!({ "color": { "__entity": { "type": "Color", "id": c } } });
    assert_same_request_validation(
        &full,
        &label,
        &action("label"),
        &[
            (r#"User::"u""#, r#"Group::"g""#, color("red")),
            (r#"User::"u""#, r#"Group::"g""#, color("green")),
        ],
    );

    // The registry defines `Color` too, so the two do not link.
    assert!(Schema::schema_link([registry(&full), label]).is_err());
}

/// An action-typed context attribute lets a condition reach an action outside
/// the closure, so the closure is not a substitute for the full schema. The
/// Lean proof rules this out with `Schema.noActionTypedAttrs`; the Rust schema
/// parser accepts such a schema. This pins the divergence.
#[test]
fn an_action_typed_context_is_outside_the_guarantee() {
    let full = parse(
        "action-typed context",
        r#"
        entity User;
        entity Doc;
        action y;
        action x in y;
        action view appliesTo { principal: User, resource: Doc, context: { a: Action, b: Action } };
        "#,
    );
    let view = action("view");
    let slice = stored_closure(&full, &view);
    let policies =
        PolicySet::from_str("permit(principal, action, resource) when { context.a in context.b };")
            .unwrap();
    let context = json!({
        "a": { "__entity": { "type": "Action", "id": "x" } },
        "b": { "__entity": { "type": "Action", "id": "y" } }
    });
    let request = Request::new(
        uid(r#"User::"u""#),
        view.clone(),
        uid(r#"Doc::"d""#),
        Context::from_json_value(context.clone(), None).unwrap(),
        None,
    )
    .unwrap();
    let decide = |schema: &Schema| {
        Authorizer::new()
            .is_authorized(&request, &policies, &schema.action_entities().unwrap())
            .decision()
    };
    assert_eq!(decide(&full), Decision::Allow);
    assert_eq!(decide(&slice), Decision::Deny);
    // Request validation diverges too: the closure does not declare `x`.
    assert!(accepts(
        &full,
        r#"User::"u""#,
        &view,
        r#"Doc::"d""#,
        &context
    ));
    assert!(!accepts(
        &slice,
        r#"User::"u""#,
        &view,
        r#"Doc::"d""#,
        &context
    ));
}
