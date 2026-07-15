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

//! Tests for the Cedar entity data syntax parser

use super::ast::*;
use super::parser::parse_entities;

#[test]
fn empty_input() {
    assert!(parse_entities("").unwrap().is_empty());
}

#[test]
fn single_bare_instance() {
    let ast = parse_entities(r#"instance User::"alice";"#).unwrap();
    assert_eq!(ast.len(), 1);
    let ns = &ast[0].data;
    assert!(ns.name.is_none()); // bare (no namespace)
    assert_eq!(ns.instances.len(), 1);
    let inst = &ns.instances[0].data.node;
    assert_eq!(inst.entity_ref.node.type_path.len(), 1);
    assert_eq!(inst.entity_ref.node.type_path[0].node.as_str(), "User");
    assert_eq!(inst.entity_ref.node.id.as_str(), "alice");
    assert!(inst.parents.is_empty());
    assert!(inst.attrs.is_none());
    assert!(inst.tags.is_none());
}

#[test]
fn instance_with_attrs() {
    let input = r#"instance User::"alice" = { name: "Alice", age: 30 };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    assert_eq!(attrs.node.len(), 2);
    assert_eq!(attrs.node[0].0.node.as_str(), "name");
    assert_eq!(attrs.node[1].0.node.as_str(), "age");
}

#[test]
fn instance_with_attrs_no_equals() {
    // The `=` before `{` is optional
    let input = r#"instance User::"alice" { name: "Alice" };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    assert!(inst.attrs.is_some());
}

#[test]
fn instance_with_parents_single() {
    let input = r#"instance User::"alice" in Group::"admins";"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    assert_eq!(inst.parents.len(), 1);
    assert_eq!(inst.parents[0].node.type_path[0].node.as_str(), "Group");
    assert_eq!(inst.parents[0].node.id.as_str(), "admins");
}

#[test]
fn instance_with_parents_multiple() {
    let input = r#"instance User::"alice" in [Group::"admins", Group::"users"];"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    assert_eq!(inst.parents.len(), 2);
    assert_eq!(inst.parents[0].node.id.as_str(), "admins");
    assert_eq!(inst.parents[1].node.id.as_str(), "users");
}

#[test]
fn instance_with_tags() {
    let input = r#"instance User::"alice" tags { role: "admin" };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    assert!(inst.tags.is_some());
    let tags = inst.tags.as_ref().unwrap();
    assert_eq!(tags.node.len(), 1);
    assert_eq!(tags.node[0].0.node.as_str(), "role");
}

#[test]
fn instance_with_attrs_and_tags() {
    let input = r#"instance User::"alice" = { name: "Alice" } tags { role: "admin" };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    assert!(inst.attrs.is_some());
    assert!(inst.tags.is_some());
}

#[test]
fn namespace_block() {
    let input = r#"
        namespace PhotoApp {
            instance User::"alice";
            instance User::"bob";
        }
    "#;
    let ast = parse_entities(input).unwrap();
    assert_eq!(ast.len(), 1);
    let ns = &ast[0].data;
    assert!(ns.name.is_some());
    let path = ns.name.as_ref().unwrap();
    assert_eq!(path.node.len(), 1);
    assert_eq!(path.node[0].node.as_str(), "PhotoApp");
    assert_eq!(ns.instances.len(), 2);
}

#[test]
fn nested_namespace_path() {
    let input = r#"
        namespace AWS::IAM {
            instance User::"alice";
        }
    "#;
    let ast = parse_entities(input).unwrap();
    let ns = &ast[0].data;
    let path = ns.name.as_ref().unwrap();
    assert_eq!(path.node.len(), 2);
    assert_eq!(path.node[0].node.as_str(), "AWS");
    assert_eq!(path.node[1].node.as_str(), "IAM");
}

#[test]
fn value_integer() {
    let input = r#"instance U::"1" = { x: 42 };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    assert!(matches!(attrs.node[0].1.node, EntityValue::Long(42)));
}

#[test]
fn value_negative_integer() {
    let input = r#"instance U::"1" = { x: -5 };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    assert!(matches!(attrs.node[0].1.node, EntityValue::Long(-5)));
}

#[test]
fn value_string() {
    let input = r#"instance U::"1" = { x: "hello" };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    match &attrs.node[0].1.node {
        EntityValue::String(s) => assert_eq!(s.as_str(), "hello"),
        _ => panic!("expected string value"),
    }
}

#[test]
fn value_string_escapes() {
    let input = r#"instance U::"1" = { x: "hello\nworld" };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    match &attrs.node[0].1.node {
        EntityValue::String(s) => assert_eq!(s.as_str(), "hello\nworld"),
        _ => panic!("expected string value"),
    }
}

#[test]
fn value_bool() {
    for (src, expected) in [("true", true), ("false", false)] {
        let input = format!(r#"instance U::"1" = {{ x: {src} }};"#);
        let ast = parse_entities(&input).unwrap();
        let inst = &ast[0].data.instances[0].data.node;
        let attrs = inst.attrs.as_ref().unwrap();
        assert_eq!(attrs.node[0].1.node, EntityValue::Bool(expected));
    }
}

#[test]
fn value_entity_ref() {
    let input = r#"instance U::"1" = { x: Other::"foo" };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    match &attrs.node[0].1.node {
        EntityValue::EntityRef(eref) => {
            assert_eq!(eref.node.type_path[0].node.as_str(), "Other");
            assert_eq!(eref.node.id.as_str(), "foo");
        }
        _ => panic!("expected entity ref value"),
    }
}

#[test]
fn value_namespaced_entity_ref() {
    let input = r#"instance U::"1" = { x: NS::Other::"foo" };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    match &attrs.node[0].1.node {
        EntityValue::EntityRef(eref) => {
            assert_eq!(eref.node.type_path.len(), 2);
            assert_eq!(eref.node.type_path[0].node.as_str(), "NS");
            assert_eq!(eref.node.type_path[1].node.as_str(), "Other");
            assert_eq!(eref.node.id.as_str(), "foo");
        }
        _ => panic!("expected entity ref value"),
    }
}

#[test]
fn value_set() {
    let input = r#"instance U::"1" = { x: [1, 2, 3] };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    match &attrs.node[0].1.node {
        EntityValue::Set(items) => assert_eq!(items.len(), 3),
        _ => panic!("expected set value"),
    }
}

#[test]
fn value_empty_set() {
    let input = r#"instance U::"1" = { x: [] };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    match &attrs.node[0].1.node {
        EntityValue::Set(items) => assert!(items.is_empty()),
        _ => panic!("expected set value"),
    }
}

#[test]
fn value_record() {
    let input = r#"instance U::"1" = { x: { a: 1, b: "two" } };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    match &attrs.node[0].1.node {
        EntityValue::Record(kvs) => {
            assert_eq!(kvs.len(), 2);
            assert_eq!(kvs[0].0.node.as_str(), "a");
            assert_eq!(kvs[1].0.node.as_str(), "b");
        }
        _ => panic!("expected record value"),
    }
}

#[test]
fn value_nested_record() {
    let input = r#"instance U::"1" = { x: { inner: { deep: true } } };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    match &attrs.node[0].1.node {
        EntityValue::Record(kvs) => {
            assert_eq!(kvs[0].0.node.as_str(), "inner");
            match &kvs[0].1.node {
                EntityValue::Record(inner_kvs) => {
                    assert_eq!(inner_kvs[0].0.node.as_str(), "deep");
                }
                _ => panic!("expected nested record"),
            }
        }
        _ => panic!("expected record value"),
    }
}

#[test]
fn value_extension_call() {
    let input = r#"instance U::"1" = { x: ip("192.168.1.1") };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    match &attrs.node[0].1.node {
        EntityValue::ExtensionCall { fn_name, args } => {
            assert_eq!(fn_name.len(), 1);
            assert_eq!(fn_name[0].node.as_str(), "ip");
            assert_eq!(args.len(), 1);
        }
        _ => panic!("expected extension call value"),
    }
}

#[test]
fn value_extension_call_multi_arg() {
    let input = r#"instance U::"1" = { x: offset(datetime("2024-01-01"), duration("1h")) };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    match &attrs.node[0].1.node {
        EntityValue::ExtensionCall { fn_name, args } => {
            assert_eq!(fn_name[0].node.as_str(), "offset");
            assert_eq!(args.len(), 2);
        }
        _ => panic!("expected extension call value"),
    }
}

#[test]
fn trailing_comma_record() {
    let input = r#"instance U::"1" = { x: 1, y: 2, };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    assert_eq!(attrs.node.len(), 2);
}

#[test]
fn trailing_comma_set() {
    let input = r#"instance U::"1" = { x: [1, 2, 3,] };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    match &attrs.node[0].1.node {
        EntityValue::Set(items) => assert_eq!(items.len(), 3),
        _ => panic!("expected set value"),
    }
}

#[test]
fn comments_ignored() {
    let input = r#"
        // This is a comment
        instance User::"alice"; // inline comment
        // Another comment
    "#;
    assert_eq!(parse_entities(input).unwrap().len(), 1);
}

#[test]
fn annotations_parsed() {
    let input = r#"@doc("test entity") instance User::"alice";"#;
    let ast = parse_entities(input).unwrap();
    // Annotations are on the namespace wrapper for bare instances
    let inst_annotations = &ast[0].data.instances[0].annotations;
    let doc_key = "doc".parse().unwrap();
    let doc = inst_annotations.get(&doc_key);
    assert!(doc.is_some());
}

#[test]
fn multiple_instances() {
    let input = r#"
        instance User::"alice";
        instance User::"bob";
        instance Photo::"pic1";
    "#;
    let ast = parse_entities(input).unwrap();
    // Each bare instance becomes its own namespace wrapper
    assert_eq!(ast.len(), 3);
}

#[test]
fn mixed_bare_and_namespace() {
    let input = r#"
        instance User::"standalone";
        namespace App {
            instance User::"inside";
        }
    "#;
    let ast = parse_entities(input).unwrap();
    assert_eq!(ast.len(), 2);
    // First is bare
    assert!(ast[0].data.name.is_none());
    // Second is namespaced
    assert!(ast[1].data.name.is_some());
}

#[test]
fn keyword_as_record_key() {
    let input = r#"instance U::"1" = { in: true, tags: "hello", namespace: 42 };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    assert_eq!(attrs.node[0].0.node.as_str(), "in");
    assert_eq!(attrs.node[1].0.node.as_str(), "tags");
    assert_eq!(attrs.node[2].0.node.as_str(), "namespace");
}

#[test]
fn empty_record() {
    let input = r#"instance U::"1" = {};"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    assert!(attrs.node.is_empty());
}

#[test]
fn string_key_in_record() {
    let input = r#"instance U::"1" = { "special key": true };"#;
    let ast = parse_entities(input).unwrap();
    let inst = &ast[0].data.instances[0].data.node;
    let attrs = inst.attrs.as_ref().unwrap();
    assert_eq!(attrs.node[0].0.node.as_str(), "special key");
}

mod conversion_tests {
    use crate::entities::cedar_syntax::parser::parse_entities;
    use crate::entities::cedar_syntax::to_entities::cedar_entities_to_entities;
    use crate::entities::{Entities, NoEntitiesSchema, TCComputation};
    use crate::extensions::Extensions;

    /// Helper: parse cedar text and convert to Entities
    fn parse_and_convert(input: &str) -> Entities {
        let ast = parse_entities(input).unwrap_or_else(|e| panic!("Parse failed: {e}"));
        let entity_vec = cedar_entities_to_entities(ast, Extensions::all_available())
            .unwrap_or_else(|e| panic!("Conversion failed: {e}"));
        Entities::from_entities(
            entity_vec,
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::all_available(),
        )
        .unwrap_or_else(|e| panic!("Entity construction failed: {e}"))
    }

    #[test]
    fn basic_entity_conversion() {
        let input = r#"instance User::"alice";"#;
        let entities = parse_and_convert(input);
        assert_eq!(entities.iter().count(), 1);
        let uid = r#"User::"alice""#.parse().unwrap();
        let entity = entities.entity(&uid).unwrap();
        assert_eq!(entity.uid(), &uid);
    }

    #[test]
    fn entity_with_parents() {
        let input = r#"
            instance User::"alice" in [Group::"admins", Group::"users"];
            instance Group::"admins";
            instance Group::"users";
        "#;
        let entities = parse_and_convert(input);
        assert_eq!(entities.iter().count(), 3);
        let alice_uid = r#"User::"alice""#.parse().unwrap();
        let alice = entities.entity(&alice_uid).unwrap();
        assert!(alice.is_descendant_of(&r#"Group::"admins""#.parse().unwrap()));
        assert!(alice.is_descendant_of(&r#"Group::"users""#.parse().unwrap()));
    }

    #[test]
    fn entity_with_attrs() {
        let input = r#"instance User::"alice" = { name: "Alice", age: 30, active: true };"#;
        let entities = parse_and_convert(input);
        let uid = r#"User::"alice""#.parse().unwrap();
        let entity = entities.entity(&uid).unwrap();
        assert_eq!(
            entity.get("name"),
            Some(&crate::ast::PartialValue::from("Alice"))
        );
        assert_eq!(entity.get("age"), Some(&crate::ast::PartialValue::from(30)));
        assert_eq!(
            entity.get("active"),
            Some(&crate::ast::PartialValue::from(true))
        );
    }

    #[test]
    fn namespace_resolution() {
        let input = r#"
            namespace PhotoApp {
                instance User::"alice";
                instance Photo::"pic1";
            }
        "#;
        let entities = parse_and_convert(input);
        assert_eq!(entities.iter().count(), 2);
        // Types should be fully qualified
        let uid = r#"PhotoApp::User::"alice""#.parse().unwrap();
        assert!(matches!(
            entities.entity(&uid),
            crate::entities::Dereference::Data(_)
        ));
        let uid2 = r#"PhotoApp::Photo::"pic1""#.parse().unwrap();
        assert!(matches!(
            entities.entity(&uid2),
            crate::entities::Dereference::Data(_)
        ));
    }

    #[test]
    fn cross_namespace_ref() {
        // When a type path has multiple segments, it's already qualified
        let input = r#"
            namespace App {
                instance User::"alice" = { manager: Other::Manager::"bob" };
            }
        "#;
        let entities = parse_and_convert(input);
        let uid = r#"App::User::"alice""#.parse().unwrap();
        let entity = entities.entity(&uid).unwrap();
        // The manager attribute should reference Other::Manager::"bob"
        let manager_val = entity.get("manager").unwrap();
        let expected_uid: crate::ast::EntityUID = r#"Other::Manager::"bob""#.parse().unwrap();
        assert_eq!(manager_val, &crate::ast::PartialValue::from(expected_uid));
    }

    #[cfg(feature = "ipaddr")]
    #[test]
    fn extension_function_ip() {
        let input = r#"instance Host::"web1" = { addr: ip("192.168.1.1") };"#;
        let entities = parse_and_convert(input);
        let uid = r#"Host::"web1""#.parse().unwrap();
        let entity = entities.entity(&uid).unwrap();
        // The ip() extension function should have been evaluated
        assert!(entity.get("addr").is_some());
    }

    #[cfg(feature = "decimal")]
    #[test]
    fn extension_function_decimal() {
        let input = r#"instance User::"alice" = { score: decimal("3.14") };"#;
        let entities = parse_and_convert(input);
        let uid = r#"User::"alice""#.parse().unwrap();
        let entity = entities.entity(&uid).unwrap();
        assert!(entity.get("score").is_some());
    }

    #[test]
    fn entity_with_set_attr() {
        let input = r#"instance User::"alice" = { scores: [95, 88, 72] };"#;
        let entities = parse_and_convert(input);
        let uid = r#"User::"alice""#.parse().unwrap();
        let entity = entities.entity(&uid).unwrap();
        let scores = entity.get("scores").unwrap();
        // It should be a set of 3 elements
        match scores {
            crate::ast::PartialValue::Value(v) => match &v.value {
                crate::ast::ValueKind::Set(s) => assert_eq!(s.len(), 3),
                _ => panic!("expected set"),
            },
            _ => panic!("expected value"),
        }
    }

    #[test]
    fn entity_with_record_attr() {
        let input = r#"instance User::"alice" = { info: { city: "Seattle", zip: 98101 } };"#;
        let entities = parse_and_convert(input);
        let uid = r#"User::"alice""#.parse().unwrap();
        let entity = entities.entity(&uid).unwrap();
        assert!(entity.get("info").is_some());
    }

    #[test]
    fn entity_with_tags() {
        let input = r#"instance User::"alice" tags { role: "admin", level: 5 };"#;
        let entities = parse_and_convert(input);
        let uid = r#"User::"alice""#.parse().unwrap();
        let entity = entities.entity(&uid).unwrap();
        assert_eq!(
            entity.get_tag("role"),
            Some(&crate::ast::PartialValue::from("admin"))
        );
        assert_eq!(
            entity.get_tag("level"),
            Some(&crate::ast::PartialValue::from(5))
        );
    }
}

mod test_pairs {
    use crate::entities::cedar_syntax::parser::parse_entities;
    use crate::entities::cedar_syntax::to_entities::cedar_entities_to_entities;
    use crate::entities::json::EntityJsonParser;
    use crate::entities::{Entities, NoEntitiesSchema, TCComputation};
    use crate::extensions::Extensions;

    /// Core assertion: Cedar syntax and JSON produce equivalent entity sets
    fn assert_cedar_matches_json(cedar_src: &str, json_src: &str) {
        let extensions = Extensions::all_available();

        // Parse Cedar entity syntax
        let ast = parse_entities(cedar_src).unwrap_or_else(|e| panic!("Cedar parse failed:\n{e}"));
        let entity_vec = cedar_entities_to_entities(ast, extensions)
            .unwrap_or_else(|e| panic!("Cedar entity conversion failed:\n{e}"));
        let cedar_entities = Entities::from_entities(
            entity_vec,
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            extensions,
        )
        .unwrap_or_else(|e| panic!("Entities construction failed:\n{e}"));

        // Parse JSON entities
        let eparser = EntityJsonParser::new(
            None::<&NoEntitiesSchema>,
            extensions,
            TCComputation::ComputeNow,
        );
        let json_entities = eparser
            .from_json_str(json_src)
            .unwrap_or_else(|e| panic!("JSON parse failed:\n{e:?}"));

        assert_eq!(cedar_entities, json_entities);
    }

    macro_rules! test_pair {
        ($name:ident, $dir:literal) => {
            #[test]
            fn $name() {
                let cedar = include_str!(concat!("testfiles/", $dir, "/input.cedarentities"));
                let json = include_str!(concat!("testfiles/", $dir, "/expected.json"));
                assert_cedar_matches_json(cedar, json);
            }
        };
    }

    test_pair!(test_hierarchy, "hierarchy");
    test_pair!(test_refs_and_sets, "refs-and-sets");
    test_pair!(test_nested_records, "nested-records");
    test_pair!(test_extensions, "extensions");
    test_pair!(test_namespaces, "namespaces");
    test_pair!(test_tags, "tags");
    test_pair!(test_edge_cases, "edge-cases");
    test_pair!(test_healthcare_app, "healthcare-app");
}

mod error_tests {
    use crate::entities::cedar_syntax::parser::parse_entities;
    use crate::entities::cedar_syntax::to_entities::cedar_entities_to_entities;
    use crate::extensions::Extensions;
    use crate::test_utils::{expect_err, ExpectedErrorMessageBuilder};
    use cool_asserts::assert_matches;

    /// Assert that `input` fails to parse with an error matching `expected`, so a
    /// test cannot pass because parsing failed for an unrelated reason.
    #[track_caller]
    fn assert_parse_error(input: &str, expected: &crate::test_utils::ExpectedErrorMessage<'_>) {
        assert_matches!(parse_entities(input), Err(e) => {
            expect_err(input, &miette::Report::new(e), expected);
        });
    }

    #[test]
    fn error_missing_semicolon() {
        assert_parse_error(
            r#"instance User::"alice""#,
            &ExpectedErrorMessageBuilder::error("unexpected end of input")
                .exactly_one_underline_with_label("", "expected `;`, `=`, `{`, `in`, or `tags`")
                .build(),
        );
    }

    #[test]
    fn error_invalid_token() {
        assert_parse_error(
            r#"instance User::"alice" = { x: $ };"#,
            &ExpectedErrorMessageBuilder::error("invalid token")
                .exactly_one_underline("")
                .build(),
        );
    }

    #[test]
    fn error_method_call_not_parseable() {
        // Method calls have no `.` production, so the `.` is an invalid token.
        assert_parse_error(
            r#"instance H::"1" = { a: ip("127.0.0.1").isLoopback() };"#,
            &ExpectedErrorMessageBuilder::error("invalid token")
                .exactly_one_underline("")
                .build(),
        );
    }

    #[test]
    fn error_variable_not_parseable() {
        // A bare identifier is not a valid value: without `(...)` it is not an
        // extension call, and without `::"id"` it is not an entity reference, so
        // parsing reaches `}` still expecting `(` or `::`.
        assert_parse_error(
            r#"instance U::"1" = { a: principal };"#,
            &ExpectedErrorMessageBuilder::error("unexpected token `}`")
                .exactly_one_underline_with_label("}", "expected `(` or `::`")
                .build(),
        );
    }

    #[test]
    fn error_expression_not_parseable() {
        // `+` is not part of the value grammar.
        assert_parse_error(
            r#"instance U::"1" = { a: 1 + 2 };"#,
            &ExpectedErrorMessageBuilder::error("invalid token")
                .exactly_one_underline("")
                .build(),
        );
    }

    #[test]
    fn error_schema_wrong_api() {
        // Schema syntax uses `entity`, which is not a valid start token here.
        assert_parse_error(
            r#"entity User in [Group] { name: String };"#,
            &ExpectedErrorMessageBuilder::error("unexpected token `entity`")
                .exactly_one_underline_with_label(
                    "entity",
                    "expected `@`, `instance`, or `namespace`",
                )
                .build(),
        );
    }

    #[test]
    fn error_policy_wrong_api() {
        assert_parse_error(
            r#"permit(principal, action, resource);"#,
            &ExpectedErrorMessageBuilder::error("unexpected token `permit`")
                .exactly_one_underline_with_label(
                    "permit",
                    "expected `@`, `instance`, or `namespace`",
                )
                .build(),
        );
    }

    #[test]
    fn error_integer_overflow() {
        assert_parse_error(
            r#"instance U::"1" = { a: 99999999999999999999 };"#,
            &ExpectedErrorMessageBuilder::error(
                "integer literal `99999999999999999999` is too large",
            )
            .exactly_one_underline("99999999999999999999")
            .build(),
        );
    }

    #[test]
    fn error_negative_integer_overflow() {
        assert_parse_error(
            r#"instance U::"1" = { a: -99999999999999999999 };"#,
            &ExpectedErrorMessageBuilder::error(
                "integer literal `-99999999999999999999` is too large",
            )
            .exactly_one_underline("-99999999999999999999")
            .build(),
        );
    }

    #[test]
    fn error_missing_entity_id() {
        // `instance User;` has no `::"id"`, so the `;` appears where the id must be.
        assert_parse_error(
            r#"instance User;"#,
            &ExpectedErrorMessageBuilder::error("unexpected token `;`")
                .exactly_one_underline_with_label(";", "expected `::`")
                .build(),
        );
    }

    #[test]
    fn error_duplicate_entity() {
        // Two instances declare the same UID.
        let input = r#"
            instance User::"alice" = { name: "Alice" };
            instance User::"alice" = { name: "Bob" };
        "#;
        let ast = parse_entities(input).unwrap();
        let entity_vec = cedar_entities_to_entities(ast, Extensions::all_available()).unwrap();
        let result = crate::entities::Entities::from_entities(
            entity_vec,
            None::<&crate::entities::NoEntitiesSchema>,
            crate::entities::TCComputation::ComputeNow,
            Extensions::all_available(),
        );
        assert_matches!(
            result,
            Err(crate::entities::err::EntitiesError::Duplicate(_))
        );
    }

    /// A duplicate key in a top-level attribute record is rejected, matching the
    /// behavior for duplicate keys in a nested record.
    #[test]
    fn error_duplicate_toplevel_attr() {
        let input = r#"instance U::"1" = { a: 1, a: 2 };"#;
        let ast = parse_entities(input).unwrap();
        let result = cedar_entities_to_entities(ast, Extensions::all_available());
        assert!(
            result.is_err(),
            "duplicate top-level attribute key should be rejected"
        );
    }

    /// A duplicate key in a top-level tags record is rejected.
    #[test]
    fn error_duplicate_toplevel_tag() {
        let input = r#"instance U::"1" tags { a: 1, a: 2 };"#;
        let ast = parse_entities(input).unwrap();
        let result = cedar_entities_to_entities(ast, Extensions::all_available());
        assert!(
            result.is_err(),
            "duplicate top-level tag key should be rejected"
        );
    }

    /// An unknown extension function is rejected, and the error names the function
    /// and describes the problem rather than being flattened into an opaque
    /// message.
    #[test]
    fn error_unknown_extension_function_variant() {
        use crate::entities::cedar_syntax::err::ConversionError;
        let input = r#"instance U::"1" = { a: nonexistent("arg") };"#;
        let ast = parse_entities(input).unwrap();
        let err = cedar_entities_to_entities(ast, Extensions::all_available())
            .expect_err("unknown extension function should be rejected");
        assert!(
            err.iter()
                .any(|e| matches!(e, ConversionError::EntityAttributeEvaluation(_))),
            "expected EntityAttributeEvaluation, got: {err}"
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains("nonexistent") && rendered.contains("does not exist"),
            "error should name the missing function; got: {rendered}"
        );
        assert!(
            !rendered.contains("conversion failed with"),
            "error should surface the underlying cause, not a count; got: {rendered}"
        );
    }

    /// Calling a known extension function with the wrong number of arguments is
    /// rejected with a message describing the arity mismatch.
    #[cfg(feature = "ipaddr")]
    #[test]
    fn error_wrong_arg_count_variant() {
        use crate::entities::cedar_syntax::err::ConversionError;
        let input = r#"instance U::"1" = { a: ip("1.2.3.4", "extra") };"#;
        let ast = parse_entities(input).unwrap();
        let err = cedar_entities_to_entities(ast, Extensions::all_available())
            .expect_err("wrong extension-function arg count should be rejected");
        assert!(
            err.iter()
                .any(|e| matches!(e, ConversionError::EntityAttributeEvaluation(_))),
            "expected EntityAttributeEvaluation, got: {err}"
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains("ip") && rendered.contains("argument"),
            "error should describe the arg-count problem for `ip`; got: {rendered}"
        );
    }
}

mod roundtrip_tests {
    use crate::entities::cedar_syntax::fmt::format_entities;
    use crate::entities::cedar_syntax::parser::parse_entities;
    use crate::entities::cedar_syntax::to_entities::cedar_entities_to_entities;
    use crate::entities::json::EntityJsonParser;
    use crate::entities::{Entities, NoEntitiesSchema, TCComputation};
    use crate::extensions::Extensions;

    /// Round-trip: JSON → Entities → Cedar text → parse → Entities → compare count
    fn assert_roundtrip(json_src: &str, name: &str) {
        let extensions = Extensions::all_available();

        // Parse JSON → Entities
        let json_parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, extensions, TCComputation::ComputeNow);
        let original = json_parser
            .from_json_str(json_src)
            .unwrap_or_else(|e| panic!("JSON parse failed for {name}: {e:?}"));

        // Format to Cedar text
        let cedar_text =
            format_entities(&original).unwrap_or_else(|e| panic!("Format failed for {name}: {e}"));

        // Re-parse Cedar text → Entities
        let ast = parse_entities(&cedar_text).unwrap_or_else(|e| {
            panic!("Re-parse failed for {name}:\n{e}\n\nCedar text:\n{cedar_text}")
        });
        let entity_vec = cedar_entities_to_entities(ast, extensions)
            .unwrap_or_else(|e| panic!("Re-conversion failed for {name}: {e}"));
        let reparsed = Entities::from_entities(
            entity_vec,
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            extensions,
        )
        .unwrap_or_else(|e| panic!("Entity construction failed for {name}: {e}"));

        // Compare entity counts
        let orig_count = original.iter().count();
        let reparse_count = reparsed.iter().count();
        assert_eq!(
            orig_count, reparse_count,
            "Round-trip entity count mismatch for {name}: original={orig_count}, reparsed={reparse_count}\n\nCedar text:\n{cedar_text}"
        );

        // Compare each entity
        for orig_entity in original.iter() {
            let uid = orig_entity.uid();
            let reparsed_entity = match reparsed.entity(uid) {
                crate::entities::Dereference::Data(e) => e,
                _ => panic!("Entity {uid} missing after round-trip for {name}"),
            };

            // Compare attribute keys
            let orig_keys: std::collections::BTreeSet<_> = orig_entity.keys().collect();
            let new_keys: std::collections::BTreeSet<_> = reparsed_entity.keys().collect();
            assert_eq!(
                orig_keys, new_keys,
                "Attribute keys differ for {uid} in {name}"
            );

            // Compare attribute values
            for key in orig_keys.iter() {
                let orig_val = orig_entity.get(key).unwrap();
                let new_val = reparsed_entity.get(key).unwrap();
                assert_eq!(
                    orig_val, new_val,
                    "Attribute '{key}' differs for {uid} in {name}"
                );
            }
        }
    }

    macro_rules! roundtrip_test {
        ($name:ident, $dir:literal) => {
            #[test]
            fn $name() {
                let json = include_str!(concat!("testfiles/", $dir, "/expected.json"));
                assert_roundtrip(json, $dir);
            }
        };
    }

    roundtrip_test!(roundtrip_hierarchy, "hierarchy");
    roundtrip_test!(roundtrip_refs_and_sets, "refs-and-sets");
    roundtrip_test!(roundtrip_nested_records, "nested-records");
    roundtrip_test!(roundtrip_extensions, "extensions");
    roundtrip_test!(roundtrip_namespaces, "namespaces");
    roundtrip_test!(roundtrip_tags, "tags");
    roundtrip_test!(roundtrip_edge_cases, "edge-cases");
    roundtrip_test!(roundtrip_healthcare_app, "healthcare-app");

    /// A reference to a declared top-level entity type is preserved across a
    /// format/reparse round-trip when the referrer lives inside a namespace: the
    /// declared top-level `GlobalThing::"g"` must not be re-qualified to
    /// `NS::GlobalThing::"g"`.
    ///
    /// The input is built from JSON so the reference is genuinely top-level
    /// entering the pipeline; parsing it from Cedar syntax would resolve the
    /// reference before the formatter runs.
    #[test]
    fn roundtrip_namespaced_ref_to_toplevel_type() {
        let extensions = Extensions::all_available();
        let json = r#"[
            {"uid":{"type":"GlobalThing","id":"g"},"attrs":{},"parents":[]},
            {"uid":{"type":"NS::Bar","id":"1"},
             "attrs":{"ref":{"__entity":{"type":"GlobalThing","id":"g"}}},
             "parents":[]}
        ]"#;
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, extensions, TCComputation::ComputeNow);
        let original = parser.from_json_str(json).unwrap();

        let bar_uid: crate::ast::EntityUID = r#"NS::Bar::"1""#.parse().unwrap();
        let orig_ref = match original.entity(&bar_uid) {
            crate::entities::Dereference::Data(e) => e.get("ref").unwrap().clone(),
            _ => panic!("NS::Bar::\"1\" missing from source entities"),
        };

        // Format → reparse.
        let cedar_text =
            format_entities(&original).unwrap_or_else(|e| panic!("format failed: {e}"));
        let ast = parse_entities(&cedar_text)
            .unwrap_or_else(|e| panic!("reparse failed:\n{e}\n\ntext:\n{cedar_text}"));
        let entity_vec = cedar_entities_to_entities(ast, extensions)
            .unwrap_or_else(|e| panic!("reconversion failed: {e}"));
        let reparsed = Entities::from_entities(
            entity_vec,
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            extensions,
        )
        .unwrap_or_else(|e| panic!("entity construction failed: {e}"));

        let reparsed_ref = match reparsed.entity(&bar_uid) {
            crate::entities::Dereference::Data(e) => e.get("ref").unwrap().clone(),
            _ => panic!("NS::Bar::\"1\" missing after round-trip"),
        };

        assert_eq!(
            orig_ref, reparsed_ref,
            "round-trip changed the reference target (finding #1)\n\nCedar text:\n{cedar_text}"
        );
    }

    /// This is an interesting edgecase. In json definition, you can specify toplevel entity
    /// within an entity definition inside a namespace.  This cannot be done in current cedar entity
    /// syntax.  One option is to fail unless entities are defined.  Current implementation allows
    /// this internal definition like json but will force the internally define instance cannot be
    /// in top level namespace as no namespace will assume current namespace.
    #[test]
    fn characterize_undeclared_toplevel_ref_from_namespace() {
        let extensions = Extensions::all_available();
        // NS::User::"alice" references top-level Group::"admins" as a parent, but
        // Group is never declared as its own instance in this set.
        let json = r#"[
            {"uid":{"type":"NS::User","id":"alice"},"attrs":{},
             "parents":[{"type":"Group","id":"admins"}]}
        ]"#;
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, extensions, TCComputation::ComputeNow);
        let original = parser.from_json_str(json).unwrap();

        let alice_uid: crate::ast::EntityUID = r#"NS::User::"alice""#.parse().unwrap();
        let orig_parent = match original.entity(&alice_uid) {
            crate::entities::Dereference::Data(e) => e.ancestors().next().unwrap().clone(),
            _ => panic!("NS::User::\"alice\" missing"),
        };
        // Sanity: the source parent is genuinely top-level.
        assert_eq!(orig_parent.to_string(), r#"Group::"admins""#);

        // Format → reparse.
        let cedar_text = format_entities(&original).unwrap();
        let ast = parse_entities(&cedar_text).unwrap();
        let entity_vec = cedar_entities_to_entities(ast, extensions).unwrap();
        let reparsed = Entities::from_entities(
            entity_vec,
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            extensions,
        )
        .unwrap();
        let new_parent = match reparsed.entity(&alice_uid) {
            crate::entities::Dereference::Data(e) => e.ancestors().next().unwrap().clone(),
            _ => panic!("NS::User::\"alice\" missing after round-trip"),
        };

        // The undeclared top-level parent is re-qualified to the current
        // namespace on reparse.
        assert_eq!(
            new_parent.to_string(),
            r#"NS::Group::"admins""#,
            "undeclared top-level ref re-qualifies to the namespace\n\nCedar text:\n{cedar_text}"
        );
    }
}
