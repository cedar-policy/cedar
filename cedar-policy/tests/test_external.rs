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

//! End-to-end tests for RFC 116, `external` entity type and action
//! declarations, exercised through the public API only.
//!
//! An `external` declaration makes a name known without defining it, so a
//! schema that carries one is *partial*. Entity validation and request
//! validation are what RFC 116 exists to enable, and they accept a partial
//! schema; every other feature refuses one.
//!
//! Every schema here is written twice, once in the Cedar schema syntax and
//! once in JSON, and every case runs against both, so that the two syntaxes
//! are pinned to the same behavior and not just to the same parse.

use cedar_policy::{
    Context, Entities, EntityUid, Policy, PolicySet, Request, RequestValidationError, Schema,
    Validator,
};
use serde_json::json;
use std::str::FromStr;

/// The partial schema `S`.
///
/// `B` and `D` are external entity types, `g`, `w` and `x` are external
/// actions, and `act` is defined. `A` refers to `B` in its ancestors, its
/// attributes and its tags; `R` holds an action-valued attribute.
const S_CEDAR: &str = r#"
external entity B;
external entity D;
entity A in B { b: B } tags B;
entity R { act: Action };
external action g;
external action w in g;
external action x in w;
action act in g appliesTo {
  principal: B,
  resource: A,
  context: {
    reviewer?: B,
    delegate?: Action,
  },
};
"#;

/// `S` again, in JSON. Keep in step with `S_CEDAR`.
fn s_json() -> serde_json::Value {
    json!({
        "": {
            "entityTypes": {
                "B": { "external": true },
                "D": { "external": true },
                "A": {
                    "memberOfTypes": ["B"],
                    "shape": {
                        "type": "Record",
                        "attributes": { "b": { "type": "EntityOrCommon", "name": "B" } }
                    },
                    "tags": { "type": "EntityOrCommon", "name": "B" }
                },
                "R": {
                    "shape": {
                        "type": "Record",
                        "attributes": { "act": { "type": "EntityOrCommon", "name": "Action" } }
                    }
                }
            },
            "actions": {
                "g": { "external": true },
                "w": { "external": true, "memberOf": [{ "id": "g" }] },
                "x": { "external": true, "memberOf": [{ "id": "w" }] },
                "act": {
                    "memberOf": [{ "id": "g" }],
                    "appliesTo": {
                        "principalTypes": ["B"],
                        "resourceTypes": ["A"],
                        "context": {
                            "type": "Record",
                            "attributes": {
                                "reviewer": { "type": "EntityOrCommon", "name": "B", "required": false },
                                "delegate": { "type": "EntityOrCommon", "name": "Action", "required": false }
                            }
                        }
                    }
                }
            }
        }
    })
}

/// `S₀` is `S` without the definition of `act`, so every action it holds is
/// external and its validation view has no request environments at all.
const S0_CEDAR: &str = r#"
external entity B;
external entity D;
entity A in B { b: B } tags B;
entity R { act: Action };
external action g;
external action w in g;
external action x in w;
"#;

/// `S₀` again, in JSON. Keep in step with `S0_CEDAR`.
fn s0_json() -> serde_json::Value {
    let mut json = s_json();
    json[""]["actions"]
        .as_object_mut()
        .expect("actions is an object")
        .remove("act")
        .expect("`act` is there to remove");
    json
}

/// `S` parsed from each syntax, labelled so a failure says which one broke.
fn s() -> [(&'static str, Schema); 2] {
    [
        (
            "Cedar syntax",
            Schema::from_str(S_CEDAR).expect("`S_CEDAR` should parse"),
        ),
        (
            "JSON syntax",
            Schema::from_json_value(s_json()).expect("`s_json` should parse"),
        ),
    ]
}

/// `S₀` parsed from each syntax.
fn s0() -> [(&'static str, Schema); 2] {
    [
        (
            "Cedar syntax",
            Schema::from_str(S0_CEDAR).expect("`S0_CEDAR` should parse"),
        ),
        (
            "JSON syntax",
            Schema::from_json_value(s0_json()).expect("`s0_json` should parse"),
        ),
    ]
}

/// What a case expects. An `Invalid` carries a fragment of the rendered error
/// chain, so a case that fails for an unrelated reason does not pass.
enum Expect {
    Valid,
    Invalid(&'static str),
}

use Expect::{Invalid, Valid};

/// Render an error together with its `source` chain.
fn chain(e: &dyn std::error::Error) -> String {
    use std::fmt::Write as _;
    let mut msg = e.to_string();
    let mut source = e.source();
    while let Some(e) = source {
        let _ = write!(msg, ": {e}");
        source = e.source();
    }
    msg
}

#[track_caller]
fn check(outcome: Result<(), Box<dyn std::error::Error>>, expect: &Expect, case: &str) {
    match (outcome, expect) {
        (Ok(()), Valid) => (),
        (Err(e), Valid) => panic!("{case}: expected valid, got `{}`", chain(e.as_ref())),
        (Ok(()), Invalid(want)) => {
            panic!("{case}: expected an error containing `{want}`, got valid")
        }
        (Err(e), Invalid(want)) => {
            let got = chain(e.as_ref());
            assert!(
                got.contains(want),
                "{case}: expected an error containing `{want}`, got `{got}`"
            );
        }
    }
}

/// An entity UID as it appears inside an attribute or tag value.
fn euid(ty: &str, id: &str) -> serde_json::Value {
    json!({ "__entity": { "type": ty, "id": id } })
}

// ---------------------------------------------------------------------------
// The schema itself
// ---------------------------------------------------------------------------

/// A schema that still holds `external` declarations is accepted, in both
/// syntaxes.
#[test]
fn a_partial_schema_is_accepted() {
    for (syntax, schema) in s() {
        // `action_entities` hands out the defined actions only.
        let action_entities = schema
            .action_entities()
            .unwrap_or_else(|e| panic!("{syntax}: {}", chain(&e)));
        let uid = |id: &str| -> cedar_policy::EntityUid {
            format!("Action::\"{id}\"").parse().expect("a valid UID")
        };
        assert!(
            action_entities.get(&uid("act")).is_some(),
            "{syntax}: expected the defined `act` in the schema's action entities"
        );
        for id in ["g", "w", "x"] {
            assert!(
                action_entities.get(&uid(id)).is_none(),
                "{syntax}: expected the external `Action::\"{id}\"` to be excluded"
            );
        }
        // An entity store built with the schema still materializes an
        // external action's entity.
        let store = Entities::from_json_value(json!([]), Some(&schema))
            .unwrap_or_else(|e| panic!("{syntax}: {}", chain(&e)));
        assert!(
            store.get(&uid("g")).is_some(),
            "{syntax}: expected the external `Action::\"g\"` in a store built with the schema"
        );
        // An external entity type is a known principal/resource type: `act`
        // applies to `B`.
        assert!(
            schema.principals().any(|ty| ty.to_string() == "B"),
            "{syntax}: expected `B` among the schema's principal types"
        );
    }
}

/// One schema written both ways, parsed and labelled.
#[track_caller]
fn both(cedar: &str, json: serde_json::Value) -> [(&'static str, Schema); 2] {
    [
        (
            "Cedar syntax",
            Schema::from_str(cedar)
                .unwrap_or_else(|e| panic!("the Cedar schema should parse: {}", chain(&e))),
        ),
        (
            "JSON syntax",
            Schema::from_json_value(json)
                .unwrap_or_else(|e| panic!("the JSON schema should parse: {}", chain(&e))),
        ),
    ]
}

/// Validate `store` against `schema`, as a single `check`-able outcome.
#[track_caller]
fn validate_entities(store: serde_json::Value, schema: &Schema, expect: &Expect, case: &str) {
    let outcome = Entities::from_json_value(store, Some(schema))
        .map(|_| ())
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
    check(outcome, expect, case);
}

/// Parse `cedar` as Cedar syntax and `json` as JSON, and check both against
/// `expect`. `json` is `None` for the one case JSON cannot express.
#[track_caller]
fn check_both_syntaxes(name: &str, cedar: &str, json: Option<serde_json::Value>, expect: &Expect) {
    let outcome = Schema::from_str(cedar)
        .map(|_| ())
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
    check(outcome, expect, &format!("Cedar syntax, {name}"));

    if let Some(json) = json {
        let outcome = Schema::from_json_value(json)
            .map(|_| ())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
        check(outcome, expect, &format!("JSON syntax, {name}"));
    }
}

// ---------------------------------------------------------------------------
// Well-formed partial schemas
// ---------------------------------------------------------------------------

/// A partial schema must declare every entity type and action it refers to,
/// either as a definition or as an external. An `external` declaration makes
/// a name usable everywhere a definition would be, but it does not excuse the
/// names *it* refers to.
#[test]
fn well_formed_partial_schemas() {
    check_both_syntaxes(
        "an external entity type used as an attribute type",
        "external entity B; entity A { b: B };",
        Some(json!({ "": {
            "entityTypes": {
                "B": { "external": true },
                "A": { "shape": { "type": "Record", "attributes": {
                    "b": { "type": "EntityOrCommon", "name": "B" }
                } } }
            },
            "actions": {}
        } })),
        &Valid,
    );

    check_both_syntaxes(
        "an external entity type with an external parent",
        "external entity G; external entity F in G; entity A in F;",
        Some(json!({ "": {
            "entityTypes": {
                "G": { "external": true },
                "F": { "external": true, "memberOfTypes": ["G"] },
                "A": { "memberOfTypes": ["F"] }
            },
            "actions": {}
        } })),
        &Valid,
    );

    check_both_syntaxes(
        "an external action as a parent, and an external entity type in `appliesTo`",
        r#"
        external entity User;
        external action g;
        action a in g appliesTo { principal: User, resource: User };
        "#,
        Some(json!({ "": {
            "entityTypes": { "User": { "external": true } },
            "actions": {
                "g": { "external": true },
                "a": {
                    "memberOf": [{ "id": "g" }],
                    "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["User"] }
                }
            }
        } })),
        &Valid,
    );

    check_both_syntaxes(
        "a cycle through an external action",
        "external action b in a; action a in b;",
        Some(json!({ "": {
            "entityTypes": {},
            "actions": {
                "b": { "external": true, "memberOf": [{ "id": "a" }] },
                "a": { "memberOf": [{ "id": "b" }] }
            }
        } })),
        &Invalid("cycle in action hierarchy"),
    );

    check_both_syntaxes(
        "an external entity type that refers to an undeclared name",
        "external entity A in [Undeclared];",
        Some(json!({ "": {
            "entityTypes": { "A": { "external": true, "memberOfTypes": ["Undeclared"] } },
            "actions": {}
        } })),
        &Invalid("failed to resolve type: Undeclared"),
    );

    // A name cannot be both declared and defined in one schema. JSON cannot
    // express this at all, since a namespace holds one entry per name.
    check_both_syntaxes(
        "a name both declared and defined",
        "external entity A; entity A;",
        None,
        &Invalid("`A` is declared twice"),
    );
}

// ---------------------------------------------------------------------------
// Name shadowing
// ---------------------------------------------------------------------------

/// A declaration participates in name resolution exactly as a definition
/// does, so the existing shadowing rules apply to it unchanged.
#[test]
fn shadowing() {
    // A common type outranks an entity type of the same name, declared or
    // defined. `A`'s attribute `b` is the common type `String`.
    check_both_syntaxes(
        "a common type shadows an external entity type",
        "external entity B; type B = String; entity A { b: B };",
        Some(json!({ "": {
            "entityTypes": {
                "B": { "external": true },
                "A": { "shape": { "type": "Record", "attributes": {
                    "b": { "type": "EntityOrCommon", "name": "B" }
                } } }
            },
            "commonTypes": { "B": { "type": "String" } },
            "actions": {}
        } })),
        &Valid,
    );

    // A declaration shadows a built-in the same way a definition does: `A`'s
    // attribute `s` is the entity `String`, not the primitive.
    check_both_syntaxes(
        "an external entity type shadows a built-in",
        "external entity String; entity A { s: String };",
        Some(json!({ "": {
            "entityTypes": {
                "String": { "external": true },
                "A": { "shape": { "type": "Record", "attributes": {
                    "s": { "type": "EntityOrCommon", "name": "String" }
                } } }
            },
            "actions": {}
        } })),
        &Valid,
    );

    // A qualified name may not shadow an empty-namespace name, whichever side
    // is the declaration.
    check_both_syntaxes(
        "a namespaced external entity type shadows an empty-namespace one",
        "entity Foo; namespace N { external entity Foo; }",
        Some(json!({
            "": { "entityTypes": { "Foo": {} }, "actions": {} },
            "N": { "entityTypes": { "Foo": { "external": true } }, "actions": {} }
        })),
        &Invalid("illegally shadows the existing definition of `Foo`"),
    );

    check_both_syntaxes(
        "a namespaced external action shadows an empty-namespace one",
        "action a; namespace N { external action a; }",
        Some(json!({
            "": { "entityTypes": {}, "actions": { "a": {} } },
            "N": { "entityTypes": {}, "actions": { "a": { "external": true } } }
        })),
        &Invalid(r#"illegally shadows the existing definition of `Action::"a"`"#),
    );
}

/// The two shadowing cases above that resolve rather than fail, observed
/// through entity validation.
#[test]
fn shadowing_resolves_the_same_way_in_both_syntaxes() {
    // `type B = String` wins over `external entity B`, so `b` holds a string.
    for (syntax, schema) in both(
        "external entity B; type B = String; entity A { b: B };",
        json!({ "": {
            "entityTypes": {
                "B": { "external": true },
                "A": { "shape": { "type": "Record", "attributes": {
                    "b": { "type": "EntityOrCommon", "name": "B" }
                } } }
            },
            "commonTypes": { "B": { "type": "String" } },
            "actions": {}
        } }),
    ) {
        validate_entities(
            json!([{ "uid": { "type": "A", "id": "a" }, "attrs": { "b": "x" }, "parents": [] }]),
            &schema,
            &Valid,
            &format!("{syntax}, `b` is the common type `String`"),
        );
        validate_entities(
            json!([{ "uid": { "type": "A", "id": "a" }, "attrs": { "b": euid("B", "x") }, "parents": [] }]),
            &schema,
            &Invalid("value was expected to have type string"),
            &format!("{syntax}, `b` is not the entity type `B`"),
        );
    }

    // `external entity String` wins over the primitive, so `s` holds a UID.
    for (syntax, schema) in both(
        "external entity String; entity A { s: String };",
        json!({ "": {
            "entityTypes": {
                "String": { "external": true },
                "A": { "shape": { "type": "Record", "attributes": {
                    "s": { "type": "EntityOrCommon", "name": "String" }
                } } }
            },
            "actions": {}
        } }),
    ) {
        validate_entities(
            json!([{ "uid": { "type": "A", "id": "a" }, "attrs": { "s": euid("String", "x") }, "parents": [] }]),
            &schema,
            &Valid,
            &format!("{syntax}, `s` is the entity type `String`"),
        );
        validate_entities(
            json!([{ "uid": { "type": "A", "id": "a" }, "attrs": { "s": "x" }, "parents": [] }]),
            &schema,
            &Invalid("expected a literal entity reference"),
            &format!("{syntax}, `s` is not the primitive `String`"),
        );
    }
}

// ---------------------------------------------------------------------------
// The RFC's own examples
// ---------------------------------------------------------------------------

/// RFC 116, ["Basic example"]: a `Document` can be validated against a schema
/// that only declares `User`, because the `owner` attribute needs nothing
/// from `User` beyond its name.
///
/// ["Basic example"]: https://github.com/cedar-policy/rfcs/blob/rfc-validating-entities/text/0116-entity-validation-schema-fragments.md#basic-example
#[test]
fn rfc_basic_example() {
    for (syntax, schema) in both(
        r#"
        external entity User;
        entity Document {
          owner: User
        };
        "#,
        json!({ "": {
            "entityTypes": {
                "User": { "external": true },
                "Document": { "shape": { "type": "Record", "attributes": {
                    "owner": { "type": "EntityOrCommon", "name": "User" }
                } } }
            },
            "actions": {}
        } }),
    ) {
        validate_entities(
            json!([{
                "uid": { "type": "Document", "id": "file.txt" },
                "attrs": { "owner": euid("User", "alice") },
                "parents": []
            }]),
            &schema,
            &Valid,
            &format!("{syntax}, an `owner` of entity type `User`"),
        );
        validate_entities(
            json!([{
                "uid": { "type": "Document", "id": "report.pdf" },
                "attrs": { "owner": euid("Account", "123") },
                "parents": []
            }]),
            &schema,
            &Invalid("type mismatch: value was expected to have type `User`"),
            &format!("{syntax}, an `owner` of some other entity type"),
        );
    }
}

/// An external declaration cannot say which values of an enum ancestor are
/// allowed, so a schema that gives an external entity type an enum ancestor is
/// refused when it is constructed. The ancestor may be reached transitively,
/// so the check runs on the closed hierarchy.
#[test]
fn an_external_entity_type_may_not_have_an_enum_ancestor() {
    check_both_syntaxes(
        "an enum as the direct ancestor of an external entity type",
        r#"entity F enum ["x"]; external entity E in [F];"#,
        Some(json!({ "": {
            "entityTypes": {
                "F": { "enum": ["x"] },
                "E": { "external": true, "memberOfTypes": ["F"] }
            },
            "actions": {}
        } })),
        &Invalid("cannot have the enum entity type `F` as an ancestor"),
    );
    check_both_syntaxes(
        "an enum as a transitive ancestor of an external entity type",
        r#"entity F enum ["x"]; entity M in [F]; external entity E in [M];"#,
        Some(json!({ "": {
            "entityTypes": {
                "F": { "enum": ["x"] },
                "M": { "memberOfTypes": ["F"] },
                "E": { "external": true, "memberOfTypes": ["M"] }
            },
            "actions": {}
        } })),
        &Invalid("cannot have the enum entity type `F` as an ancestor"),
    );
    check_both_syntaxes(
        "an enum ancestor of a defined entity type is still accepted",
        r#"entity F enum ["x"]; entity M in [F];"#,
        Some(json!({ "": {
            "entityTypes": {
                "F": { "enum": ["x"] },
                "M": { "memberOfTypes": ["F"] }
            },
            "actions": {}
        } })),
        &Valid,
    );
}

/// RFC 116, ["External ancestor types"]: an external entity type used as an
/// ancestor type is the one case where its definition matters, because its
/// own parents transitively determine the valid ancestor types. Declaring
/// them is what makes the ancestor checkable.
///
/// ["External ancestor types"]: https://github.com/cedar-policy/rfcs/blob/rfc-validating-entities/text/0116-entity-validation-schema-fragments.md#external-ancestor-types
#[test]
fn rfc_external_ancestor_types() {
    // `Folder`'s parents are not declared, so they are conservatively treated
    // as none. A `Document` in a `Folder` is checkable; a `Document` in an
    // `Application` is not -- and that must be an error, not a warning.
    for (syntax, schema) in both(
        r#"
        external entity Folder;
        entity Document in Folder;
        "#,
        json!({ "": {
            "entityTypes": {
                "Folder": { "external": true },
                "Document": { "memberOfTypes": ["Folder"] }
            },
            "actions": {}
        } }),
    ) {
        validate_entities(
            json!([{
                "uid": { "type": "Document", "id": "file.txt" },
                "attrs": {},
                "parents": [{ "type": "Folder", "id": "home" }]
            }]),
            &schema,
            &Valid,
            &format!("{syntax}, a `Folder` ancestor, which the schema allows"),
        );
        validate_entities(
            json!([{
                "uid": { "type": "Document", "id": "file.txt" },
                "attrs": {},
                "parents": [{ "type": "Application", "id": "app" }]
            }]),
            &schema,
            &Invalid("is not allowed to have an ancestor of type `Application`"),
            &format!("{syntax}, an `Application` ancestor, with `Folder`'s parents unknown"),
        );
    }

    // The same store, against a schema that declares `Folder in Application`.
    // The declared parent types feed the transitive closure, so the ancestor
    // is checkable and valid.
    for (syntax, schema) in both(
        r#"
        external entity Application;
        external entity Folder in Application;
        entity Document in Folder;
        "#,
        json!({ "": {
            "entityTypes": {
                "Application": { "external": true },
                "Folder": { "external": true, "memberOfTypes": ["Application"] },
                "Document": { "memberOfTypes": ["Folder"] }
            },
            "actions": {}
        } }),
    ) {
        validate_entities(
            json!([{
                "uid": { "type": "Document", "id": "file.txt" },
                "attrs": {},
                "parents": [{ "type": "Application", "id": "app" }]
            }]),
            &schema,
            &Valid,
            &format!("{syntax}, an `Application` ancestor, with `Folder in Application` declared"),
        );
    }
}

// ---------------------------------------------------------------------------
// Entity validation
// ---------------------------------------------------------------------------

/// Entity validation against `S`.
///
/// An entity of a defined type may refer to externals in its attributes, tags
/// and ancestors. An entity of an external type cannot be validated at all,
/// because its attributes, tags and ancestors are unknown. An external
/// *action*'s entity can be, because its declaration fixes its ancestors and
/// action entities have no attributes or tags.
#[test]
fn entity_validation() {
    let cases: Vec<(&str, serde_json::Value, Expect)> = vec![
        (
            "the empty store",
            json!([]),
            // Validation checks only supplied entries, so the declared action
            // entities need not be present.
            Valid,
        ),
        (
            "an attribute of an external entity type",
            json!([{ "uid": { "type": "A", "id": "a" }, "attrs": { "b": euid("B", "x") }, "parents": [] }]),
            // The attribute only needs a UID of that type; the `B` entity
            // itself need not be in the store.
            Valid,
        ),
        (
            "a tag of an external entity type",
            json!([{
                "uid": { "type": "A", "id": "a" },
                "attrs": { "b": euid("B", "x") },
                "parents": [],
                "tags": { "owner": euid("B", "owner") }
            }]),
            Valid,
        ),
        (
            "an ancestor of an external entity type the schema allows",
            json!([{
                "uid": { "type": "A", "id": "a" },
                "attrs": { "b": euid("B", "x") },
                "parents": [{ "type": "B", "id": "y" }]
            }]),
            // `S` says `A in B`, even though `B` is external.
            Valid,
        ),
        (
            "an ancestor of an external entity type the schema does not allow",
            json!([{
                "uid": { "type": "A", "id": "a" },
                "attrs": { "b": euid("B", "x") },
                "parents": [{ "type": "D", "id": "d" }]
            }]),
            // `D` is declared, but `S` does not say that `A` can be in `D`.
            Invalid("is not allowed to have an ancestor of type `D`"),
        ),
        (
            "an entity of an external entity type",
            json!([{ "uid": { "type": "B", "id": "x" }, "attrs": {}, "parents": [] }]),
            Invalid("has type `B` which is declared `external` in the schema"),
        ),
        (
            "an attribute holding an external action's UID",
            json!([{ "uid": { "type": "R", "id": "r" }, "attrs": { "act": euid("Action", "g") }, "parents": [] }]),
            // `Action::"g"` is an exact action UID declared by `S`.
            Valid,
        ),
        (
            "an attribute holding an undeclared action's UID",
            json!([{ "uid": { "type": "R", "id": "r" }, "attrs": { "act": euid("Action", "missing") }, "parents": [] }]),
            Invalid("it was not declared as an action in the schema"),
        ),
        (
            "a defined action entity with an external parent",
            json!([{ "uid": { "type": "Action", "id": "act" }, "attrs": {}, "parents": [{ "type": "Action", "id": "g" }] }]),
            // The parent is external, but `act`'s ancestors are known.
            Valid,
        ),
        (
            "an external action entity with no parents, as declared",
            json!([{ "uid": { "type": "Action", "id": "g" }, "attrs": {}, "parents": [] }]),
            Valid,
        ),
        (
            "an external action entity with the parent it declares",
            json!([{ "uid": { "type": "Action", "id": "w" }, "attrs": {}, "parents": [{ "type": "Action", "id": "g" }] }]),
            Valid,
        ),
        (
            "an external action entity missing the parent it declares",
            json!([{ "uid": { "type": "Action", "id": "w" }, "attrs": {}, "parents": [] }]),
            Invalid("does not match its schema declaration"),
        ),
        (
            "an external action entity with its full ancestor set",
            json!([{
                "uid": { "type": "Action", "id": "x" },
                "attrs": {},
                "parents": [{ "type": "Action", "id": "w" }, { "type": "Action", "id": "g" }]
            }]),
            Valid,
        ),
        (
            "an external action entity missing a transitive ancestor",
            json!([{
                "uid": { "type": "Action", "id": "x" },
                "attrs": {},
                "parents": [{ "type": "Action", "id": "w" }]
            }]),
            // `x`'s closed ancestor set is `{w, g}`. The store supplies only
            // `w`, and transitive closure cannot add `g`, because `w` is not in
            // the store to close through.
            Invalid("does not match its schema declaration"),
        ),
        (
            "an action entity with attributes",
            json!([{ "uid": { "type": "Action", "id": "g" }, "attrs": { "x": 1 }, "parents": [] }]),
            // As for any action entity, declared or defined.
            Invalid("does not match its schema declaration"),
        ),
    ];

    for (syntax, schema) in s() {
        for (name, store, expect) in &cases {
            let outcome = Entities::from_json_value(store.clone(), Some(&schema))
                .map(|_| ())
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
            check(outcome, expect, &format!("{syntax}, {name}"));
        }
    }
}

/// Entity validation against `S₀`, whose actions are all external.
///
/// `S₀` has no request environments at all. Entity validation scans the
/// supplied store directly, so there is still something to check.
#[test]
fn entity_validation_without_request_environments() {
    let cases: Vec<(&str, serde_json::Value, Expect)> = vec![
        (
            "a required attribute missing",
            json!([{ "uid": { "type": "A", "id": "a" }, "attrs": {}, "parents": [] }]),
            Invalid(r#"expected entity `A::"a"` to have attribute `b`, but it does not"#),
        ),
        (
            "an attribute of the wrong type",
            json!([{ "uid": { "type": "A", "id": "a" }, "attrs": { "b": 1 }, "parents": [] }]),
            Invalid(r#"in attribute `b` on `A::"a"`, expected a literal entity reference"#),
        ),
        (
            "an entity of an external entity type, as against `S`",
            json!([{ "uid": { "type": "B", "id": "x" }, "attrs": {}, "parents": [] }]),
            Invalid("has type `B` which is declared `external` in the schema"),
        ),
        (
            "a well-formed entity",
            json!([{ "uid": { "type": "A", "id": "a" }, "attrs": { "b": euid("B", "x") }, "parents": [] }]),
            Valid,
        ),
    ];

    for (syntax, schema) in s0() {
        for (name, store, expect) in &cases {
            let outcome = Entities::from_json_value(store.clone(), Some(&schema))
                .map(|_| ())
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
            check(outcome, expect, &format!("{syntax}, {name}"));
        }
    }
}

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------

/// Request validation against `S`.
///
/// An external entity type is a declared name, so a defined action may apply
/// to it and a request may name it. An external action is different: nothing
/// is known about what it applies to, so no request for it can be valid.
#[test]
fn request_validation() {
    // (case, principal, action, resource, context, expectation)
    let cases: Vec<(&str, &str, &str, &str, serde_json::Value, Expect)> = vec![
        (
            "a principal of an external entity type, listed in `appliesTo`",
            r#"B::"x""#,
            r#"Action::"act""#,
            r#"A::"a""#,
            json!({}),
            // The optional context fields may be omitted.
            Valid,
        ),
        (
            "a context value of an external entity type",
            r#"B::"x""#,
            r#"Action::"act""#,
            r#"A::"a""#,
            json!({ "reviewer": euid("B", "reviewer") }),
            Valid,
        ),
        (
            "a context value holding an external action",
            r#"B::"x""#,
            r#"Action::"act""#,
            r#"A::"a""#,
            json!({ "delegate": euid("Action", "g") }),
            // `g` may appear as a context value even though it cannot be the
            // request action.
            Valid,
        ),
        (
            "a context value of the wrong external entity type",
            r#"B::"x""#,
            r#"Action::"act""#,
            r#"A::"a""#,
            json!({ "reviewer": euid("D", "reviewer") }),
            // `D` is declared, but `reviewer` requires exactly `B`.
            Invalid(r#"context `{reviewer: D::"reviewer"}` is not valid for `Action::"act"`"#),
        ),
        (
            "a principal whose type is only an ancestor of one in `appliesTo`",
            r#"A::"a""#,
            r#"Action::"act""#,
            r#"A::"a""#,
            json!({}),
            // `A` has ancestor type `B`, but request validation requires the
            // listed type exactly.
            Invalid("principal type `A` is not valid for"),
        ),
        (
            "an external action",
            r#"B::"x""#,
            r#"Action::"g""#,
            r#"A::"a""#,
            json!({}),
            Invalid(r#"request's action `Action::"g"` is declared `external` in the schema"#),
        ),
    ];

    for (syntax, schema) in s() {
        for (name, principal, action, resource, context, expect) in &cases {
            let context = cedar_policy::Context::from_json_value(context.clone(), None)
                .expect("the context should be well-formed JSON");
            let outcome = Request::new(
                principal.parse().expect("a valid principal UID"),
                action.parse().expect("a valid action UID"),
                resource.parse().expect("a valid resource UID"),
                context,
                Some(&schema),
            )
            .map(|_| ())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
            check(outcome, expect, &format!("{syntax}, {name}"));
        }
    }
}

/// The error for an external action names the action and says why no request
/// can be valid for it, rather than reporting it as undeclared.
#[test]
fn an_external_action_is_not_reported_as_undeclared() {
    for (syntax, schema) in s() {
        let err = Request::new(
            r#"B::"x""#.parse().expect("a valid principal UID"),
            r#"Action::"g""#.parse().expect("a valid action UID"),
            r#"A::"a""#.parse().expect("a valid resource UID"),
            cedar_policy::Context::empty(),
            Some(&schema),
        )
        .expect_err("an external action should be refused");
        assert!(
            matches!(err, RequestValidationError::ExternalAction(_)),
            "{syntax}: expected `ExternalAction`, got `{err:?}`"
        );
    }
}

// ---------------------------------------------------------------------------
// Policy validation
// ---------------------------------------------------------------------------

/// Policy validation refuses a partial schema, once per policy. It cannot
/// report anything sound about a policy whose types are not all known.
#[test]
fn policy_validation_refuses_a_partial_schema() {
    let mut policies = PolicySet::new();
    for (id, src) in [
        ("p0", r#"permit(principal, action, resource);"#),
        (
            "p1",
            r#"permit(principal, action == Action::"act", resource);"#,
        ),
    ] {
        policies
            .add(
                Policy::parse(Some(id.parse().expect("a valid policy id")), src)
                    .expect("the policy should parse"),
            )
            .expect("the policy id should be fresh");
    }

    for (syntax, schema) in s() {
        let result =
            Validator::new(schema).validate(&policies, cedar_policy::ValidationMode::Strict);
        assert!(
            !result.validation_passed(),
            "{syntax}: a partial schema should not validate"
        );
        let mut reported: Vec<String> = result
            .validation_errors()
            .map(|e| e.policy_id().to_string())
            .collect();
        reported.sort();
        assert_eq!(
            reported,
            ["p0", "p1"],
            "{syntax}: expected one error per policy"
        );
        for e in result.validation_errors() {
            let msg = e.to_string();
            assert!(
                msg.contains("schema is incomplete"),
                "{syntax}: expected an incomplete-schema error, got `{msg}`"
            );
        }
    }
}

/// The same policies against the same schema, with every declaration
/// defined.
#[test]
fn policy_validation_accepts_the_same_schema_once_defined() {
    let defined = r#"
    entity B;
    entity D;
    entity A in B { b: B } tags B;
    entity R { act: Action };
    action g;
    action w in g;
    action x in w;
    action act in g appliesTo {
      principal: B,
      resource: A,
      context: {
        reviewer?: B,
        delegate?: Action,
      },
    };
    "#;
    let schema = Schema::from_str(defined).expect("the defined schema should parse");
    let policies = PolicySet::from_str(r#"permit(principal, action, resource);"#)
        .expect("the policy should parse");
    let result = Validator::new(schema).validate(&policies, cedar_policy::ValidationMode::Strict);
    assert!(
        result.validation_passed(),
        "expected the defined schema to validate, got {:?}",
        result.validation_errors().collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// The completeness API
// ---------------------------------------------------------------------------

/// The partial schema `S₁`: one external entity type and one external
/// action, each with a definition that refers to it.
const S1_CEDAR: &str = r#"
external entity User;
external action audit;
entity Document { owner: User };
action view appliesTo { principal: [Document], resource: [Document] };
"#;

/// `S₁` again, in JSON. Keep in step with `S1_CEDAR`.
fn s1_json() -> serde_json::Value {
    json!({
        "": {
            "entityTypes": {
                "User": { "external": true },
                "Document": { "shape": { "type": "Record", "attributes": {
                    "owner": { "type": "EntityOrCommon", "name": "User" }
                } } }
            },
            "actions": {
                "audit": { "external": true },
                "view": { "appliesTo": {
                    "principalTypes": ["Document"],
                    "resourceTypes": ["Document"]
                } }
            }
        }
    })
}

/// `S₁` parsed from each syntax.
fn s1() -> [(&'static str, Schema); 2] {
    both(S1_CEDAR, s1_json())
}

/// Sorted display forms, so an assertion reads as a list of names.
fn names<'a, T: ToString + 'a>(iter: impl Iterator<Item = &'a T>) -> Vec<String> {
    let mut v: Vec<String> = iter.map(ToString::to_string).collect();
    v.sort();
    v
}

/// Each accessor answers for `S₁`, and each external/defined pair partitions
/// the corresponding catch-all.
#[test]
fn completeness_api_partitions_the_schema() {
    for (syntax, schema) in s1() {
        assert!(!schema.is_complete(), "{syntax}: `S` is partial");

        assert_eq!(names(schema.external_entity_types()), ["User"], "{syntax}");
        assert_eq!(
            names(schema.defined_entity_types()),
            ["Document"],
            "{syntax}"
        );
        assert_eq!(
            names(schema.external_actions()),
            [r#"Action::"audit""#],
            "{syntax}"
        );
        assert_eq!(
            names(schema.defined_actions()),
            [r#"Action::"view""#],
            "{syntax}"
        );

        // Each pair partitions the corresponding catch-all.
        assert_eq!(
            names(schema.entity_types()),
            ["Document", "User"],
            "{syntax}"
        );
        assert_eq!(
            names(schema.actions()),
            [r#"Action::"audit""#, r#"Action::"view""#],
            "{syntax}"
        );
    }
}

/// The smallest partial schemas: one external entity type with a defined
/// child, and one external action with a defined child.
#[test]
fn completeness_api_on_a_single_declaration() {
    // An external entity type.
    for (syntax, schema) in both(
        "external entity Folder; entity Document in Folder;",
        json!({ "": {
            "entityTypes": {
                "Folder": { "external": true },
                "Document": { "memberOfTypes": ["Folder"] }
            },
            "actions": {}
        } }),
    ) {
        assert!(!schema.is_complete(), "{syntax}");
        assert_eq!(
            names(schema.external_entity_types()),
            ["Folder"],
            "{syntax}"
        );
        assert_eq!(
            names(schema.defined_entity_types()),
            ["Document"],
            "{syntax}"
        );
        assert_eq!(schema.external_actions().count(), 0, "{syntax}");
        assert_eq!(schema.defined_actions().count(), 0, "{syntax}");
    }

    // An external action.
    for (syntax, schema) in both(
        "external action WriteActions; action DeleteFile in WriteActions;",
        json!({ "": {
            "entityTypes": {},
            "actions": {
                "WriteActions": { "external": true },
                "DeleteFile": { "memberOf": [{ "id": "WriteActions" }] }
            }
        } }),
    ) {
        assert!(!schema.is_complete(), "{syntax}");
        assert_eq!(
            names(schema.external_actions()),
            [r#"Action::"WriteActions""#],
            "{syntax}"
        );
        assert_eq!(
            names(schema.defined_actions()),
            [r#"Action::"DeleteFile""#],
            "{syntax}"
        );
        assert_eq!(schema.external_entity_types().count(), 0, "{syntax}");
    }
}

/// A complete schema answers the other way, and an enumerated entity type is
/// a definition rather than a declaration.
#[test]
fn completeness_api_on_a_complete_schema() {
    for (syntax, schema) in both(
        r#"entity Color enum ["red"]; entity User in Color;
           action view appliesTo { principal: [User], resource: [User] };"#,
        json!({ "": {
            "entityTypes": {
                "Color": { "enum": ["red"] },
                "User": { "memberOfTypes": ["Color"] }
            },
            "actions": { "view": { "appliesTo": {
                "principalTypes": ["User"], "resourceTypes": ["User"]
            } } }
        } }),
    ) {
        assert!(schema.is_complete(), "{syntax}");
        assert_eq!(schema.external_entity_types().count(), 0, "{syntax}");
        assert_eq!(schema.external_actions().count(), 0, "{syntax}");
        assert_eq!(
            names(schema.defined_entity_types()),
            names(schema.entity_types()),
            "{syntax}: an enum is a definition"
        );
        assert_eq!(
            names(schema.defined_actions()),
            names(schema.actions()),
            "{syntax}"
        );
    }
}

/// The accessors against `S`, whose declarations include an external action
/// that another external action declares as a parent. Such an action is
/// external and an action group at once.
#[test]
fn completeness_api_on_chained_external_actions() {
    for (syntax, schema) in s() {
        assert!(!schema.is_complete(), "{syntax}");
        assert_eq!(
            names(schema.external_entity_types()),
            ["B", "D"],
            "{syntax}"
        );
        assert_eq!(names(schema.defined_entity_types()), ["A", "R"], "{syntax}");
        assert_eq!(
            names(schema.external_actions()),
            [r#"Action::"g""#, r#"Action::"w""#, r#"Action::"x""#],
            "{syntax}"
        );
        assert_eq!(
            names(schema.defined_actions()),
            [r#"Action::"act""#],
            "{syntax}"
        );
        // `g` is external and a group, because `w` and `act` are in it.
        assert!(
            names(schema.action_groups()).contains(&r#"Action::"g""#.to_string()),
            "{syntax}: an external action can be an action group"
        );
    }
}

// ---------------------------------------------------------------------------
// Existing API, on declarations
// ---------------------------------------------------------------------------

/// `principals_for_action` and `resources_for_action` find an external
/// action, so they answer `Some` with an empty iterator rather than `None`,
/// and it contributes no request environment.
#[test]
fn an_external_action_is_found_but_applies_to_nothing() {
    for (syntax, schema) in s1() {
        let audit: EntityUid = r#"Action::"audit""#.parse().expect("a valid UID");
        let view: EntityUid = r#"Action::"view""#.parse().expect("a valid UID");
        let absent: EntityUid = r#"Action::"absent""#.parse().expect("a valid UID");

        for (name, got) in [
            (
                "principals_for_action",
                schema.principals_for_action(&audit).map(Iterator::count),
            ),
            (
                "resources_for_action",
                schema.resources_for_action(&audit).map(Iterator::count),
            ),
        ] {
            assert_eq!(got, Some(0), "{syntax}: {name} on an external action");
        }
        assert_eq!(
            schema.principals_for_action(&absent).map(Iterator::count),
            None,
            "{syntax}: an absent action is still `None`"
        );
        assert_eq!(
            schema.principals_for_action(&view).map(Iterator::count),
            Some(1),
            "{syntax}: a defined action is unaffected"
        );

        // Only the defined action yields a request environment.
        assert_eq!(
            names(
                schema
                    .request_envs()
                    .map(|env| env.action().to_string())
                    .collect::<Vec<_>>()
                    .iter()
            ),
            [r#"Action::"view""#],
            "{syntax}"
        );
    }
}

/// An external entity type takes part in the hierarchy through its declared
/// parents, so `ancestors` answers for a declaration as for a definition.
#[test]
fn ancestors_answers_for_declarations() {
    for (syntax, schema) in both(
        "external entity Application; external entity Folder in Application; entity Document in Folder;",
        json!({ "": {
            "entityTypes": {
                "Application": { "external": true },
                "Folder": { "external": true, "memberOfTypes": ["Application"] },
                "Document": { "memberOfTypes": ["Folder"] }
            },
            "actions": {}
        } }),
    ) {
        let ancestors = |ty: &str| {
            names(
                schema
                    .ancestors(&ty.parse().expect("a valid type name"))
                    .unwrap_or_else(|| panic!("{syntax}: `{ty}` should be in the schema"))
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .iter(),
            )
        };
        // `Document in Folder in Application`, closed.
        assert_eq!(ancestors("Document"), ["Application", "Folder"], "{syntax}");
        // A declaration's own ancestors are its declared parents.
        assert_eq!(ancestors("Folder"), ["Application"], "{syntax}");
        assert!(ancestors("Application").is_empty(), "{syntax}");
        assert!(
            schema
                .ancestors(&"Absent".parse().expect("a valid type name"))
                .is_none(),
            "{syntax}: an absent type is `None`"
        );
    }
}

// ---------------------------------------------------------------------------
// The rendered messages
// ---------------------------------------------------------------------------

/// The refusal names every declaration, entity types before actions, and
/// policy validation reports it once per policy. No policy is typechecked, so
/// the type error the second policy would otherwise draw is not reported, and
/// an empty policy set passes.
#[test]
fn policy_validation_names_every_declaration() {
    const EXPECTED: [&str; 2] = [
        r#"for policy `policy0`, schema is incomplete: `User` and `Action::"audit"` are declared `external` but not defined"#,
        r#"for policy `policy1`, schema is incomplete: `User` and `Action::"audit"` are declared `external` but not defined"#,
    ];

    let mut policies = PolicySet::new();
    for (id, src) in [
        (
            "policy0",
            r#"permit(principal, action == Action::"audit", resource);"#,
        ),
        (
            "policy1",
            r#"permit(principal, action, resource) when { principal.owner.nope };"#,
        ),
    ] {
        policies
            .add(
                Policy::parse(Some(id.parse().expect("a valid policy id")), src)
                    .expect("the policy should parse"),
            )
            .expect("the policy id should be fresh");
    }

    for (syntax, schema) in s1() {
        let result = Validator::new(schema.clone())
            .validate(&policies, cedar_policy::ValidationMode::Strict);
        assert!(!result.validation_passed(), "{syntax}");

        // Once per policy, naming each policy.
        let mut reported: Vec<String> = result
            .validation_errors()
            .map(ToString::to_string)
            .collect();
        reported.sort();
        assert_eq!(reported, EXPECTED, "{syntax}");

        let mut ids: Vec<String> = result
            .validation_errors()
            .map(|e| e.policy_id().to_string())
            .collect();
        ids.sort();
        assert_eq!(
            ids,
            ["policy0", "policy1"],
            "{syntax}: one error per policy"
        );

        // Neither policy is typechecked, so `nope` is never reported.
        assert!(
            !reported.iter().any(|m| m.contains("nope")),
            "{syntax}: no policy should be typechecked"
        );

        // An empty policy set has nothing to report against.
        assert!(
            Validator::new(schema)
                .validate(&PolicySet::new(), cedar_policy::ValidationMode::Strict)
                .validation_passed(),
            "{syntax}"
        );
    }
}

/// Entity and request validation name the one item they reject, rather than
/// the schema.
#[test]
fn validation_of_one_item_names_that_item() {
    for (syntax, schema) in s1() {
        // An entity of an external type.
        validate_entities(
            json!([{ "uid": { "type": "User", "id": "alice" }, "attrs": {}, "parents": [] }]),
            &schema,
            &Invalid(
                r#"entity `User::"alice"` has type `User` which is declared `external` in the schema"#,
            ),
            &format!("{syntax}, an entity of an external type"),
        );

        // A request for an external action.
        let err = Request::new(
            r#"Document::"d""#.parse().expect("a valid principal UID"),
            r#"Action::"audit""#.parse().expect("a valid action UID"),
            r#"Document::"d""#.parse().expect("a valid resource UID"),
            Context::empty(),
            Some(&schema),
        )
        .expect_err("an external action should be refused");
        assert_eq!(
            err.to_string(),
            r#"request's action `Action::"audit"` is declared `external` in the schema"#,
            "{syntax}, a request for an external action"
        );

        // The defined action is unaffected, and `Document` may hold a `User`.
        Request::new(
            r#"Document::"d""#.parse().expect("a valid principal UID"),
            r#"Action::"view""#.parse().expect("a valid action UID"),
            r#"Document::"d""#.parse().expect("a valid resource UID"),
            Context::empty(),
            Some(&schema),
        )
        .unwrap_or_else(|e| panic!("{syntax}: the defined action should be valid: {e}"));
        validate_entities(
            json!([{
                "uid": { "type": "Document", "id": "d" },
                "attrs": { "owner": euid("User", "alice") },
                "parents": []
            }]),
            &schema,
            &Valid,
            &format!("{syntax}, a defined entity referring to an external type"),
        );
    }
}

/// `Context::from_json_value` cannot distinguish an external action from an
/// absent one, and its message is true of both.
#[test]
fn context_reports_an_external_action_as_not_defined() {
    for (syntax, schema) in s1() {
        for id in ["audit", "absent"] {
            let uid: EntityUid = format!("Action::\"{id}\"").parse().expect("a valid UID");
            let err = Context::from_json_value(json!({}), Some((&schema, &uid)))
                .expect_err("neither action has a context type");
            assert_eq!(
                err.to_string(),
                format!("action `Action::\"{id}\"` is not defined in the supplied schema"),
                "{syntax}, {id}"
            );
        }
        // `Context::validate` reports the external case accurately.
        let err = Context::empty()
            .validate(&schema, &r#"Action::"audit""#.parse().expect("a valid UID"))
            .expect_err("an external action should be refused");
        assert!(
            matches!(err, RequestValidationError::ExternalAction(_)),
            "{syntax}: expected `ExternalAction`, got `{err:?}`"
        );
    }
}

// ---------------------------------------------------------------------------
// The JSON interface
// ---------------------------------------------------------------------------

/// Each case pairs a JSON entry with the Cedar declaration it denotes, and
/// the two must describe the same schema. Each supplies whatever extra
/// declaration the entry refers to, the same on both sides.
#[test]
fn a_json_entry_and_its_cedar_declaration_agree() {
    // (case, JSON entity types, JSON actions, Cedar)
    let cases: [(&str, serde_json::Value, serde_json::Value, &str); 8] = [
        (
            "an entity type with a parent",
            json!({
                "Folder": { "external": true, "memberOfTypes": ["Application"] },
                "Application": { "external": true }
            }),
            json!({}),
            "external entity Folder in Application; external entity Application;",
        ),
        (
            "an action with a parent",
            json!({}),
            json!({
                "DeleteActions": { "external": true, "memberOf": [{ "id": "WriteActions" }] },
                "WriteActions": { "external": true }
            }),
            "external action DeleteActions in WriteActions; external action WriteActions;",
        ),
        (
            "an explicit `external: false`",
            json!({}),
            json!({
                "DeleteActions": { "external": false, "memberOf": [{ "id": "WriteActions" }] },
                "WriteActions": { "external": true }
            }),
            "action DeleteActions in WriteActions; external action WriteActions;",
        ),
        (
            "an absent `external`",
            json!({}),
            json!({
                "DeleteActions": { "memberOf": [{ "id": "WriteActions" }] },
                "WriteActions": { "external": true }
            }),
            "action DeleteActions in WriteActions; external action WriteActions;",
        ),
        (
            "an entity type with no parents",
            json!({ "Folder": { "external": true } }),
            json!({}),
            "external entity Folder;",
        ),
        (
            "an action with no parents",
            json!({}),
            json!({ "WriteActions": { "external": true } }),
            "external action WriteActions;",
        ),
        (
            "a definition with an empty shape",
            json!({ "User": { "shape": { "type": "Record", "attributes": {} } } }),
            json!({}),
            "entity User {};",
        ),
        (
            "a null `appliesTo` on an action",
            json!({}),
            json!({ "WriteActions": { "external": true, "appliesTo": null } }),
            "external action WriteActions;",
        ),
    ];

    for (case, entity_types, actions, cedar) in cases {
        let from_json = Schema::from_json_value(json!({
            "": { "entityTypes": entity_types, "actions": actions }
        }))
        .unwrap_or_else(|e| panic!("{case}: the JSON should parse: {}", chain(&e)));
        let from_cedar = Schema::from_str(cedar)
            .unwrap_or_else(|e| panic!("{case}: the Cedar should parse: {}", chain(&e)));

        for (what, a, b) in [
            (
                "external entity types",
                names(from_json.external_entity_types()),
                names(from_cedar.external_entity_types()),
            ),
            (
                "defined entity types",
                names(from_json.defined_entity_types()),
                names(from_cedar.defined_entity_types()),
            ),
            (
                "external actions",
                names(from_json.external_actions()),
                names(from_cedar.external_actions()),
            ),
            (
                "defined actions",
                names(from_json.defined_actions()),
                names(from_cedar.defined_actions()),
            ),
        ] {
            assert_eq!(a, b, "{case}: the two sides disagree on {what}");
        }
        assert_eq!(
            from_json.is_complete(),
            from_cedar.is_complete(),
            "{case}: the two sides disagree on completeness"
        );
    }
}

/// A declaration carrying a field that only a definition may have, each
/// rejected by the presence of that field. These have no Cedar column,
/// because the grammar cannot express them.
#[test]
fn json_rejects_a_definition_field_on_a_declaration() {
    let cases: [(&str, serde_json::Value, serde_json::Value, &str); 6] = [
        (
            "a null `external` on an entity type",
            json!({ "Folder": { "external": null } }),
            json!({}),
            "invalid type: null, expected a boolean",
        ),
        (
            "a `shape` on a declaration",
            json!({ "Folder": { "external": true, "shape": {
                "type": "Record", "attributes": { "x": { "type": "String" } }
            } } }),
            json!({}),
            "unexpected field on an external entity type: shape",
        ),
        (
            "`tags` on a declaration",
            json!({ "Folder": { "external": true, "tags": { "type": "String" } } }),
            json!({}),
            "unexpected field on an external entity type: tags",
        ),
        (
            "an `enum` on a declaration",
            json!({ "Folder": { "external": true, "enum": ["x"] } }),
            json!({}),
            "unexpected field on an external entity type: enum",
        ),
        (
            "an `appliesTo` on a declaration",
            json!({}),
            json!({ "WriteActions": { "external": true, "appliesTo": {
                "principalTypes": ["User"], "resourceTypes": ["Folder"]
            } } }),
            "unexpected field on an external action: appliesTo",
        ),
        (
            "`attributes` on a declaration",
            json!({}),
            json!({ "WriteActions": { "external": true, "attributes": {} } }),
            "unexpected field on an external action: attributes",
        ),
    ];

    for (case, entity_types, actions, want) in cases {
        let err = match Schema::from_json_value(json!({
            "": { "entityTypes": entity_types, "actions": actions }
        })) {
            Err(e) => e,
            Ok(_) => panic!("{case}: should be rejected"),
        };
        let got = chain(&err);
        assert!(
            got.to_lowercase().contains(&want.to_lowercase()),
            "{case}: expected an error containing `{want}`, got `{got}`"
        );
    }

    // On an action, `null` is accepted and reads as absent, unlike on an
    // entity type.
    let schema = Schema::from_json_value(json!({
        "": {
            "entityTypes": {},
            "actions": { "WriteActions": { "external": null } }
        }
    }))
    .expect("`external: null` is accepted on an action");
    assert_eq!(
        names(schema.defined_actions()),
        [r#"Action::"WriteActions""#],
        "`null` reads as absent, so the action is defined"
    );
    assert_eq!(schema.external_actions().count(), 0);
}
