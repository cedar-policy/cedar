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

//! End-to-end tests for schema linking (RFC 116), exercised through the
//! public API only.
//!
//! Linking resolves a name declared `external` in one schema against a
//! definition of the same name in another. Each test encodes one case of the
//! specification: two input schemas `p` and `c`, and either the schema they
//! link to or the fact that linking refuses them.
//!
//! The linker mirrors `Cedar/Validation/Linker.lean` and adds two checks the
//! Lean model abstracts away: the linked schema is held to the RFC 70
//! shadowing rules, and a link may not introduce a declaration that shadows a
//! primitive or extension type. A common type is inlined where it is used, so
//! a link cannot observe one and the cases that turn on a `type` declaration
//! are accepted.
//!
//! A successful link is checked against the expected schema written as Cedar
//! text, compared on everything the public API can observe: which entity types
//! and actions exist, which of them are still `external`, each entity type's
//! closed ancestors, and whether the result is complete. `Schema` has no
//! `PartialEq`, so there is no stronger comparison available. Attribute types
//! are not compared; `accepts_entity` probes one where a case turns on it.
//!
//! A refusal is checked only for being a refusal. The specification names a
//! distinct error for each case, recorded in the `spec_error` argument.

use cedar_policy::{Entities, Schema};
use serde_json::json;
use std::str::FromStr;

/// Sorted display forms, so an assertion reads as a list of names.
fn names<'a, T: ToString + 'a>(iter: impl Iterator<Item = &'a T>) -> Vec<String> {
    let mut v: Vec<String> = iter.map(ToString::to_string).collect();
    v.sort();
    v
}

fn parse(label: &str, src: &str) -> Schema {
    Schema::from_str(src).unwrap_or_else(|e| panic!("{label} should parse: {e}"))
}

/// Compare everything the public API can observe about two schemas.
#[track_caller]
fn assert_same_schema(case: &str, got: &Schema, want: &Schema) {
    assert_eq!(
        names(got.entity_types()),
        names(want.entity_types()),
        "{case}: entity types"
    );
    assert_eq!(
        names(got.actions()),
        names(want.actions()),
        "{case}: actions"
    );
    assert_eq!(
        names(got.external_entity_types()),
        names(want.external_entity_types()),
        "{case}: which entity types are still external"
    );
    assert_eq!(
        names(got.external_actions()),
        names(want.external_actions()),
        "{case}: which actions are still external"
    );
    assert_eq!(
        got.is_complete(),
        want.is_complete(),
        "{case}: completeness"
    );
    for ty in want.entity_types() {
        let ancestors = |s: &Schema| {
            s.ancestors(ty)
                .map(|it| names(it.collect::<Vec<_>>().iter()))
        };
        assert_eq!(
            ancestors(got),
            ancestors(want),
            "{case}: closed ancestors of `{ty}`"
        );
    }
}

/// `p` and `c` link to `expected`.
#[track_caller]
fn link_ok(case: &str, p: &str, c: &str, expected: &str) -> Schema {
    let linked = Schema::schema_link([parse("p", p), parse("c", c)])
        .unwrap_or_else(|e| panic!("{case}: linking should succeed: {e}"));
    assert_same_schema(case, &linked, &parse("the expected schema", expected));
    linked
}

/// Linking `p` and `c` is refused. `spec_error` is the name the specification
/// gives the refusal; see the module comment for why it is not asserted.
#[track_caller]
fn link_err(case: &str, p: &str, c: &str, spec_error: &str) {
    let got = Schema::schema_link([parse("p", p), parse("c", c)]);
    assert!(
        got.is_err(),
        "{case}: linking should be refused with `{spec_error}`"
    );
}

/// An entity UID as it appears inside an attribute value.
fn euid(ty: &str, id: &str) -> serde_json::Value {
    json!({ "__entity": { "type": ty, "id": id } })
}

/// Validate a one-entity store, as a way to observe an attribute's type.
#[track_caller]
fn accepts_entity(schema: &Schema, store: serde_json::Value) -> bool {
    Entities::from_json_value(store, Some(schema)).is_ok()
}

/// Entity: partial + complete = complete.
#[test]
fn an_entity_definition_replaces_an_external() {
    link_ok(
        "an_entity_definition_replaces_an_external",
        r#"
external entity B;
entity A { b: B };
"#,
        r#"
entity B;
"#,
        r#"
entity A { b: B };
entity B;
"#,
    );
}

/// Action: an external action links to a definition with an appliesTo.
#[test]
fn an_external_action_links_to_a_definition_with_applies_to() {
    link_ok(
        "an_external_action_links_to_a_definition_with_applies_to",
        r#"
entity User;
entity Doc;
external action write;
"#,
        r#"
external entity User;
external entity Doc;
action write
  appliesTo {
    principal: User,
    resource: Doc,
  };
"#,
        r#"
entity User;
entity Doc;
action write
  appliesTo {
    principal: User,
    resource: Doc,
  };
"#,
    );
}

/// Partial + partial = partial.
#[test]
fn an_unresolved_external_remains_external() {
    link_ok(
        "an_unresolved_external_remains_external",
        r#"
external entity B;
entity A { b: B };
"#,
        r#"
external entity B;
entity D { b: B };
"#,
        r#"
external entity B;
entity A { b: B };
entity D { b: B };
"#,
    );
}

/// Mutual externals: partial + partial = complete.
#[test]
fn mutual_externals_resolve() {
    link_ok(
        "mutual_externals_resolve",
        r#"
external entity B;
entity A { b: B };
"#,
        r#"
external entity A;
entity B { a: A };
"#,
        r#"
entity A { b: B };
entity B { a: A };
"#,
    );
}

/// Ancestors through an external.
#[test]
fn a_definition_preserves_closed_ancestors_through_an_external() {
    link_ok(
        "a_definition_preserves_closed_ancestors_through_an_external",
        r#"
external entity G;
external entity F in G;
entity A in F;
"#,
        r#"
entity G;
entity F in G;
"#,
        r#"
entity G;
entity F in G;
entity A in F;
"#,
    );
}

/// Repeated externals combine their declared parents.
#[test]
fn repeated_external_ancestors_are_combined() {
    link_ok(
        "repeated_external_ancestors_are_combined",
        r#"
external entity G;
external entity F in G;
"#,
        r#"
external entity H;
external entity F in H;
"#,
        r#"
external entity G;
external entity H;
external entity F in [G, H];
"#,
    );
}

/// A definition may add parents.
#[test]
fn an_entity_definition_may_contain_more_closed_ancestors() {
    link_ok(
        "an_entity_definition_may_contain_more_closed_ancestors",
        r#"
external entity G;
external entity F in G;
"#,
        r#"
entity G;
entity H;
entity F in [G, H];
"#,
        r#"
entity G;
entity H;
entity F in [G, H];
"#,
    );
}

/// Error: a cross-schema cycle would enlarge defined ancestors.
#[test]
fn a_cross_schema_cycle_would_enlarge_defined_ancestors() {
    link_err(
        "a_cross_schema_cycle_would_enlarge_defined_ancestors",
        r#"
external entity B;
entity A in B;
"#,
        r#"
external entity A;
entity B in A;
"#,
        "definedEntityAncestorsChanged",
    );
}

/// A transitive ancestor satisfies an external declaration.
#[test]
fn a_transitive_ancestor_satisfies_an_external_declaration() {
    link_ok(
        "a_transitive_ancestor_satisfies_an_external_declaration",
        r#"
external entity G;
external entity F in G;
"#,
        r#"
entity G;
entity X in G;
entity F in X;
"#,
        r#"
entity G;
entity X in G;
entity F in X;
"#,
    );
}

/// Error: action parents must match exactly.
#[test]
fn action_ancestors_must_match_exactly() {
    link_err(
        "action_ancestors_must_match_exactly",
        r#"
external action g;
external action w in g;
"#,
        r#"
action g;
action r;
action w in [g, r];
"#,
        "externalActionParentsMismatch",
    );
}

/// Error: an external can't be an enumerated type.
#[test]
fn an_external_entity_cannot_resolve_to_an_enum() {
    link_err(
        "an_external_entity_cannot_resolve_to_an_enum",
        r#"
external entity E;
entity A { e: E };
"#,
        r#"
entity E enum ["x"];
"#,
        "externalIsEnum",
    );
}

/// Error: two definitions of the same name.
#[test]
fn duplicate_entity_definitions_are_rejected() {
    link_err(
        "duplicate_entity_definitions_are_rejected",
        r#"
entity A;
"#,
        r#"
entity A;
"#,
        "duplicateEntityType",
    );
}

/// Error: an external cannot add an ancestor to a definition.
#[test]
fn an_external_cannot_add_an_ancestor_to_a_definition() {
    link_err(
        "an_external_cannot_add_an_ancestor_to_a_definition",
        r#"
external entity X;
entity E in X;
"#,
        r#"
external entity G;
external entity E in G;
"#,
        "externalAncestorsNotInDefinition",
    );
}

/// Error: linking cannot enlarge a defined entity's closed ancestors.
#[test]
fn linking_cannot_enlarge_a_defined_entitys_closed_ancestors() {
    link_err(
        "linking_cannot_enlarge_a_defined_entitys_closed_ancestors",
        r#"
external entity X;
entity E in X;
"#,
        r#"
external entity G;
external entity X in G;
"#,
        "definedEntityAncestorsChanged",
    );
}

/// An external entity's closed ancestors can grow.
#[test]
fn an_external_entitys_closed_ancestors_can_grow() {
    link_ok(
        "an_external_entitys_closed_ancestors_can_grow",
        r#"
external entity X;
external entity E in X;
"#,
        r#"
external entity G;
external entity X in G;
"#,
        r#"
external entity G;
external entity X in G;
external entity E in [X, G];
"#,
    );
}

/// A link may introduce a common type that shadows an entity type: the
/// definition is inlined where it is used, so the link does not see it.
#[test]
fn a_link_may_shadow_a_declared_entity() {
    link_ok(
        "a_link_may_shadow_a_declared_entity",
        r#"
external entity B;
entity A { b: B };
"#,
        r#"
type B = String;
"#,
        r#"
external entity B;
entity A { b: B };
"#,
    );
}

/// A parent resolves only to an entity type, so a common type cannot
/// capture it.
#[test]
fn a_link_may_shadow_a_declared_parent() {
    link_ok(
        "a_link_may_shadow_a_declared_parent",
        r#"
external entity B;
entity A in B;
"#,
        r#"
type B = String;
"#,
        r#"
external entity B;
entity A in B;
"#,
    );
}

/// Link defines the shadowed entity.
#[test]
fn a_link_may_define_a_shadowed_entity() {
    let linked = link_ok(
        "a_link_may_define_a_shadowed_entity",
        r#"
external entity B;
type B = String;
entity A { b: B };
"#,
        r#"
entity B;
"#,
        r#"
entity B;
type B = String;
entity A { b: B };
"#,
    );
    assert!(
        accepts_entity(
            &linked,
            json!([{ "uid": { "type": "A", "id": "a" },
            "attrs": { "b": "x" }, "parents": [] }])
        ),
        "`b` should still be the common type `String`"
    );
    assert!(
        !accepts_entity(
            &linked,
            json!([{ "uid": { "type": "A", "id": "a" },
            "attrs": { "b": euid("B", "x") }, "parents": [] }])
        ),
        "`b` should not be the entity type `B`"
    );
}

/// Link defines the declared child.
#[test]
fn a_link_may_define_a_declared_child() {
    link_ok(
        "a_link_may_define_a_declared_child",
        r#"
entity G;
type G = Long;
external entity F in G;
"#,
        r#"
external entity G;
entity F in G;
"#,
        r#"
entity G;
type G = Long;
entity F in G;
"#,
    );
}

/// As for a declared entity type.
#[test]
fn a_link_may_shadow_a_defined_entity() {
    link_ok(
        "a_link_may_shadow_a_defined_entity",
        r#"
entity B;
entity A { b: B };
"#,
        r#"
type B = String;
"#,
        r#"
entity B;
entity A { b: B };
"#,
    );
}

/// One input already carries the shadowing. The link resolves the external
/// against the definition and the common type plays no part.
#[test]
fn shadowing_that_arrives_already_formed_is_accepted() {
    link_ok(
        "shadowing_that_arrives_already_formed_is_accepted",
        r#"
external entity B;
entity A { b: B };
"#,
        r#"
entity B;
type B = String;
"#,
        r#"
entity B;
entity A { b: B };
"#,
    );
}

/// Link adds a namespaced declaration.
#[test]
fn a_link_may_not_add_a_namespaced_declaration() {
    link_err(
        "a_link_may_not_add_a_namespaced_declaration",
        r#"
entity Foo;
namespace N {
  entity A { f: Foo };
}
"#,
        r#"
namespace N {
  external entity Foo;
}
"#,
        "TypeShadowing",
    );
}

/// Link shadows a primitive.
#[test]
fn a_link_may_not_shadow_a_primitive() {
    link_err(
        "a_link_may_not_shadow_a_primitive",
        r#"
entity A { s: String };
"#,
        r#"
external entity String;
"#,
        "shadowsBuiltinType",
    );
}

/// Link repeats existing shadowing.
#[test]
fn a_link_may_repeat_existing_shadowing() {
    let linked = link_ok(
        "a_link_may_repeat_existing_shadowing",
        r#"
entity String;
entity A { s: String };
"#,
        r#"
external entity String;
"#,
        r#"
entity String;
entity A { s: String };
"#,
    );
    assert!(
        accepts_entity(
            &linked,
            json!([{ "uid": { "type": "A", "id": "a" },
            "attrs": { "s": euid("String", "x") }, "parents": [] }])
        ),
        "`s` should still be the entity type `String`"
    );
    assert!(
        !accepts_entity(
            &linked,
            json!([{ "uid": { "type": "A", "id": "a" },
            "attrs": { "s": "x" }, "parents": [] }])
        ),
        "`s` should not be the primitive `String`"
    );
}

/// Link does not repeat the shadowing. The exemption needs every input to
/// declare the name, so a schema that shadows a primitive on its own links
/// with nothing that does not shadow it too.
#[test]
fn a_link_that_does_not_repeat_the_shadowing_is_refused() {
    link_err(
        "a_link_that_does_not_repeat_the_shadowing_is_refused",
        r#"
external entity String;
"#,
        r#"
entity Z;
"#,
        "shadowsBuiltinType",
    );
}

/// A link keeps the resolution each input already had. `R.act` resolves to
/// the empty-namespace `Action` in `p` and stays there, although `c` makes
/// `N::Action` exist. Writing the same declarations as one schema would
/// resolve `act` to `N::Action` instead.
#[test]
fn a_link_may_declare_a_namespaced_action() {
    link_ok(
        "a_link_may_declare_a_namespaced_action",
        r#"
action a;
namespace N {
  entity R { act: Action };
}
"#,
        r#"
namespace N {
  action b;
}
"#,
        r#"
action a;
namespace N { entity R { act: Action }; action b; }
"#,
    );
}

/// Common types are inlined, so a second definition reaches no reference.
/// `A.x` keeps the definition from `p`.
#[test]
fn a_link_may_add_a_conflicting_common_type() {
    link_ok(
        "a_link_may_add_a_conflicting_common_type",
        r#"
type T = String;
entity A { x: T };
"#,
        r#"
type T = Long;
"#,
        r#"
type T = String;
entity A { x: T };
"#,
    );
}

/// As for a conflicting definition.
#[test]
fn a_link_may_repeat_an_identical_common_type() {
    link_ok(
        "a_link_may_repeat_an_identical_common_type",
        r#"
type T = String;
entity A { x: T };
"#,
        r#"
type T = String;
"#,
        r#"
type T = String;
entity A { x: T };
"#,
    );
}

/// Both sides use a conflicting definition. Each use keeps its own side's,
/// so one name reaches the result as two types.
#[test]
fn a_link_may_use_a_conflicting_common_type_on_both_sides() {
    let linked = link_ok(
        "a_link_may_use_a_conflicting_common_type_on_both_sides",
        r#"
type T = String;
entity A { x: T };
"#,
        r#"
type T = Long;
entity B { x: T };
"#,
        r#"
entity A { x: String };
entity B { x: Long };
"#,
    );
    assert!(
        accepts_entity(
            &linked,
            json!([{ "uid": { "type": "A", "id": "a" }, "attrs": { "x": "s" }, "parents": [] },
                   { "uid": { "type": "B", "id": "b" }, "attrs": { "x": 1 }, "parents": [] }])
        ),
        "`A.x` should be a string and `B.x` a long"
    );
    assert!(
        !accepts_entity(
            &linked,
            json!([{ "uid": { "type": "A", "id": "a" }, "attrs": { "x": 1 }, "parents": [] }])
        ),
        "`A.x` should not be a long"
    );
    assert!(
        !accepts_entity(
            &linked,
            json!([{ "uid": { "type": "B", "id": "b" }, "attrs": { "x": "s" }, "parents": [] }])
        ),
        "`B.x` should not be a string"
    );
}

/// Both sides use an identical definition, as for a conflicting one.
#[test]
fn a_link_may_use_an_identical_common_type_on_both_sides() {
    let linked = link_ok(
        "a_link_may_use_an_identical_common_type_on_both_sides",
        r#"
type T = String;
entity A { x: T };
"#,
        r#"
type T = String;
entity B { x: T };
"#,
        r#"
entity A { x: String };
entity B { x: String };
"#,
    );
    assert!(
        accepts_entity(
            &linked,
            json!([{ "uid": { "type": "A", "id": "a" }, "attrs": { "x": "s" }, "parents": [] },
                   { "uid": { "type": "B", "id": "b" }, "attrs": { "x": "s" }, "parents": [] }])
        ),
        "both `x` should be a string"
    );
}

/// Link resolves to an enum.
#[test]
fn an_external_may_not_resolve_to_an_enum_across_a_link() {
    link_err(
        "an_external_may_not_resolve_to_an_enum_across_a_link",
        r#"
external entity E;
entity A in E;
"#,
        r#"
entity E enum ["x"];
"#,
        "externalIsEnum",
    );
}

/// Link shadows an extension type.
#[test]
fn a_link_may_not_shadow_an_extension_type() {
    link_err(
        "a_link_may_not_shadow_an_extension_type",
        r#"
entity A { d: decimal };
"#,
        r#"
entity decimal;
"#,
        "shadowsBuiltinType",
    );
}

/// Neither input has the forbidden shape on its own: `p` declares nothing
/// `external` and `c` declares no enum. Linking them would give the external
/// `E` the enum `F` as an ancestor, which no schema may hold.
#[test]
fn a_link_may_not_give_an_external_an_enum_ancestor() {
    link_err(
        "a_link_may_not_give_an_external_an_enum_ancestor",
        r#"
entity F enum ["x"];
entity M in [F];
"#,
        r#"
external entity M;
external entity E in [M];
entity Leaf { e: E };
"#,
        "externalWithEnumAncestor",
    );
}

/// Link with the extensions active. They are an argument to the link rather
/// than a property of either input, so a name no input declares stays the
/// extension type.
#[test]
fn a_link_keeps_an_extension_type_no_input_declares() {
    let linked = link_ok(
        "a_link_keeps_an_extension_type_no_input_declares",
        r#"
entity A { d: decimal };
"#,
        r#"
entity B;
"#,
        r#"
entity A { d: decimal };
entity B;
"#,
    );
    assert!(
        accepts_entity(
            &linked,
            json!([{ "uid": { "type": "A", "id": "a" },
            "attrs": { "d": { "__extn": { "fn": "decimal", "arg": "1.0" } } }, "parents": [] }])
        ),
        "`d` should still be the extension type `decimal`"
    );
}

/// Both sides carry one key.
#[test]
fn annotations_on_one_key_merge_from_both_sides() {
    link_ok(
        "annotations_on_one_key_merge_from_both_sides",
        r#"
@doc("declared here")
external entity B;
"#,
        r#"
@doc("defined here")
entity B;
"#,
        r#"
@doc("declared here\ndefined here")
entity B;
"#,
    );
}

/// Each side carries its own key.
#[test]
fn annotations_on_separate_keys_are_both_kept() {
    link_ok(
        "annotations_on_separate_keys_are_both_kept",
        r#"
@doc("declared here")
external entity B;
"#,
        r#"
@owner("team")
entity B;
"#,
        r#"
@doc("declared here")
@owner("team")
entity B;
"#,
    );
}
