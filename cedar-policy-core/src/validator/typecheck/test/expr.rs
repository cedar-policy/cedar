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

//! Contains tests for typechecking Cedar expressions outside of a larger
//! policy and without a schema.

use std::{str::FromStr, vec};

use crate::{
    ast::{BinaryOp, EntityUID, Expr, Pattern, PatternElem, SlotId, Var},
    extensions::Extensions,
};
use itertools::Itertools;
use serde_json::json;
use smol_str::SmolStr;

use crate::validator::{
    diagnostics::ValidationError,
    json_schema,
    types::Type,
    validation_errors::{AttributeAccess, LubContext, LubHelp, UnexpectedTypeHelp},
    RawName, ValidationMode,
};

use super::test_utils::{
    assert_exactly_one_diagnostic, assert_sets_equal, assert_typecheck_fails,
    assert_typecheck_fails_empty_schema, assert_typecheck_fails_empty_schema_without_type,
    assert_typecheck_fails_for_mode, assert_typechecks, assert_typechecks_empty_schema,
    assert_typechecks_empty_schema_permissive, assert_typechecks_for_mode, empty_schema_file,
    expr_id_placeholder, get_loc,
};

#[test]
fn primitives_typecheck() {
    assert_typechecks_empty_schema(&Expr::val(true), &Type::singleton_boolean(true));
    assert_typechecks_empty_schema(&Expr::val(1), &Type::primitive_long());
    assert_typechecks_empty_schema(&Expr::val("foo"), &Type::primitive_string());
}

#[test]
fn slot_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::slot(SlotId::principal()),
        &Type::any_entity_reference(),
    );

    assert_typechecks_empty_schema(
        &Expr::slot(SlotId::resource()),
        &Type::any_entity_reference(),
    );
}

#[test]
fn slot_in_typechecks() {
    let etype = json_schema::StandardEntityType {
        member_of_types: vec![],
        shape: json_schema::AttributesOrContext::default(),
        tags: None,
    }
    .into();
    let schema = json_schema::NamespaceDefinition::new([("typename".parse().unwrap(), etype)], []);
    assert_typechecks_for_mode(
        schema.clone(),
        &Expr::binary_app(
            BinaryOp::In,
            Expr::val(EntityUID::with_eid_and_type("typename", "id").expect("Bad EUID")),
            Expr::slot(SlotId::principal()),
        ),
        &Type::primitive_boolean(),
        ValidationMode::Permissive,
    );
    assert_typechecks_for_mode(
        schema,
        &Expr::binary_app(
            BinaryOp::In,
            Expr::val(EntityUID::with_eid_and_type("typename", "id").expect("Bad EUID")),
            Expr::slot(SlotId::resource()),
        ),
        &Type::primitive_boolean(),
        ValidationMode::Permissive,
    );
}

#[test]
fn slot_equals_typechecks() {
    let etype = json_schema::StandardEntityType {
        member_of_types: vec![],
        shape: json_schema::AttributesOrContext::default(),
        tags: None,
    }
    .into();
    // These don't typecheck in strict mode because the test_util expression
    // typechecker doesn't have access to a schema, so it can't link
    // the template slots with appropriate types. Similar policies that pass
    // strict typechecking are in the test_policy file.
    let schema = json_schema::NamespaceDefinition::new([("typename".parse().unwrap(), etype)], []);
    assert_typechecks_for_mode(
        schema.clone(),
        &Expr::binary_app(
            BinaryOp::Eq,
            Expr::val(EntityUID::with_eid_and_type("typename", "edi").expect("EUID Failed")),
            Expr::slot(SlotId::principal()),
        ),
        &Type::primitive_boolean(),
        ValidationMode::Permissive,
    );
    assert_typechecks_for_mode(
        schema,
        &Expr::binary_app(
            BinaryOp::Eq,
            Expr::val(EntityUID::with_eid_and_type("typename", "edi").expect("EUID Failed")),
            Expr::slot(SlotId::resource()),
        ),
        &Type::primitive_boolean(),
        ValidationMode::Permissive,
    );
}

#[test]
fn slot_has_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::has_attr(Expr::slot(SlotId::principal()), "test".into()),
        &Type::primitive_boolean(),
    );
    assert_typechecks_empty_schema(
        &Expr::has_attr(Expr::slot(SlotId::resource()), "test".into()),
        &Type::primitive_boolean(),
    );
}

#[test]
fn set_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::set([Expr::val(true)]),
        &Type::set(Type::singleton_boolean(true)),
    );
}

#[test]
fn heterogeneous_set() {
    let src = "[true, 1]";
    let errors = assert_typecheck_fails_empty_schema_without_type(&src.parse().unwrap());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::incompatible_types(
            get_loc(src, src),
            expr_id_placeholder(),
            [Type::singleton_boolean(true), Type::primitive_long()],
            LubHelp::None,
            LubContext::Set,
        )
    );
}

#[test]
fn record_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::record([("foo".into(), Expr::val(1))]).unwrap(),
        &Type::closed_record_with_required_attributes([("foo".into(), Type::primitive_long())]),
    )
}

#[test]
fn and_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::and(Expr::val(true), Expr::val(false)),
        &Type::singleton_boolean(false),
    );
}

#[test]
fn and_typecheck_fails() {
    let src = "1 && true";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "1"),
            expr_id_placeholder(),
            Type::primitive_boolean(),
            Type::primitive_long(),
            None,
        )
    );

    let src = "(1 > 0) && 2";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "2"),
            expr_id_placeholder(),
            Type::primitive_boolean(),
            Type::primitive_long(),
            None,
        )
    );

    let src = "(1 > false) && true";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "false"),
            expr_id_placeholder(),
            Type::primitive_long(),
            Type::singleton_boolean(false),
            None,
        )
    );

    let src = "true && (1 > false)";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "false"),
            expr_id_placeholder(),
            Type::primitive_long(),
            Type::singleton_boolean(false),
            None,
        )
    );
}

#[test]
fn or_left_true_is_true() {
    assert_typechecks_empty_schema(
        &Expr::or(Expr::val(true), Expr::val(false)),
        &Type::singleton_boolean(true),
    );
}

#[test]
fn or_left_false_is_right() {
    assert_typechecks_empty_schema(
        &Expr::or(Expr::val(false), Expr::greater(Expr::val(1), Expr::val(0))),
        &Type::primitive_boolean(),
    );
}

#[test]
fn or_left_true_ignores_right() {
    assert_typechecks_empty_schema(
        &Expr::or(Expr::val(true), Expr::not(Expr::val(1))),
        &Type::singleton_boolean(true),
    );
}

#[test]
fn or_right_true_fails_left() {
    let src = "1 || true";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "1"),
            expr_id_placeholder(),
            Type::primitive_boolean(),
            Type::primitive_long(),
            None,
        )
    );
}

#[test]
fn or_right_true_is_true() {
    assert_typechecks_empty_schema(
        &Expr::or(Expr::greater(Expr::val(1), Expr::val(0)), Expr::val(true)),
        &Type::singleton_boolean(true),
    );
}

#[test]
fn or_right_false_is_left() {
    assert_typechecks_empty_schema(
        &Expr::or(Expr::greater(Expr::val(1), Expr::val(0)), Expr::val(false)),
        &Type::primitive_boolean(),
    );
}

#[test]
fn or_boolean() {
    assert_typechecks_empty_schema(
        &Expr::or(
            Expr::greater(Expr::val(1), Expr::val(0)),
            Expr::greater(Expr::val(1), Expr::val(0)),
        ),
        &Type::primitive_boolean(),
    );
}

#[test]
fn or_false() {
    assert_typechecks_empty_schema(
        &Expr::or(Expr::val(false), Expr::val(false)),
        &Type::singleton_boolean(false),
    );
}

#[test]
fn or_typecheck_fails() {
    let src = "1 || true";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "1"),
            expr_id_placeholder(),
            Type::primitive_boolean(),
            Type::primitive_long(),
            None,
        )
    );

    let src = "(2 > 0) || 1";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "1"),
            expr_id_placeholder(),
            Type::primitive_boolean(),
            Type::primitive_long(),
            None,
        )
    );

    let src = "(1 > true) || false";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "true"),
            expr_id_placeholder(),
            Type::primitive_long(),
            Type::singleton_boolean(true),
            None,
        )
    );

    let src = "(1 > false) || true";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::singleton_boolean(true));
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "false"),
            expr_id_placeholder(),
            Type::primitive_long(),
            Type::singleton_boolean(false),
            None,
        )
    );

    let src = "false || (1 > true)";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "true"),
            expr_id_placeholder(),
            Type::primitive_long(),
            Type::singleton_boolean(true),
            None,
        )
    );
}

#[test]
fn eq_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::is_eq(Expr::val(2), Expr::val(1)),
        &Type::primitive_boolean(),
    );
}

#[test]
fn entity_eq_is_false() {
    let schema: json_schema::NamespaceDefinition<RawName> = serde_json::from_str(
        r#"
    {
        "entityTypes": {
            "Foo": {},
            "Bar": {},
            "Baz": {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "foo": {
                            "type": "Entity",
                            "name": "Foo"
                        },
                        "bar": {
                            "type": "Entity",
                            "name": "Bar"
                        }
                    }
                }
            }
        },
        "actions": {}
    }"#,
    )
    .expect("Expected that schema would parse");
    assert_typechecks(
        schema,
        &Expr::is_eq(
            Expr::get_attr(
                Expr::val(
                    EntityUID::with_eid_and_type("Baz", "buz").expect("Expected EntityUID parse."),
                ),
                "foo".into(),
            ),
            Expr::get_attr(
                Expr::val(
                    EntityUID::with_eid_and_type("Baz", "buz").expect("Expected EntityUID parse."),
                ),
                "bar".into(),
            ),
        ),
        &Type::False,
    );
}

#[test]
fn set_eq_is_not_false() {
    let schema: json_schema::NamespaceDefinition<RawName> = serde_json::from_str(
        r#"
    {
        "entityTypes": {
            "some_type": {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "long_set": {
                            "type": "Set",
                            "element": {
                                "type": "Long"
                            }
                        },
                        "bool_set": {
                            "type": "Set",
                            "element": {
                                "type": "Boolean"
                            }
                        }
                    }
                }
            }
        },
        "actions": {}
    }"#,
    )
    .expect("Expected that schema would parse");
    assert_typechecks_for_mode(
        schema,
        &Expr::is_eq(
            Expr::get_attr(
                Expr::val(
                    EntityUID::with_eid_and_type("some_type", "a")
                        .expect("Expected EntityUID parse."),
                ),
                "long_set".into(),
            ),
            Expr::get_attr(
                Expr::val(
                    EntityUID::with_eid_and_type("some_type", "b")
                        .expect("Expected EntityUID parse."),
                ),
                "bool_set".into(),
            ),
        ),
        &Type::primitive_boolean(),
        ValidationMode::Permissive,
    );
}

#[test]
fn eq_typecheck_action_literals_false() {
    let schema: json_schema::NamespaceDefinition<RawName> = serde_json::from_str(
        r#"
    {
        "entityTypes": {},
        "actions": {
            "view_photo": {},
            "view_album": {}
        }
    }"#,
    )
    .expect("Expected that schema would parse");
    assert_typechecks(
        schema,
        &Expr::is_eq(
            Expr::val(
                EntityUID::with_eid_and_type("Action", "view_photo")
                    .expect("Expected EntityUID parse."),
            ),
            Expr::val(
                EntityUID::with_eid_and_type("Action", "view_album")
                    .expect("Expected EntityUID parse."),
            ),
        ),
        &Type::singleton_boolean(false),
    );
}

#[test]
fn eq_typecheck_entity_literals_false() {
    let schema: json_schema::NamespaceDefinition<RawName> = serde_json::from_str(
        r#"
    {
        "entityTypes": {
            "A": {},
            "B": {}
        },
        "actions": {}
    }"#,
    )
    .expect("Expected that schema would parse");
    assert_typechecks(
        schema,
        &Expr::is_eq(
            Expr::val(EntityUID::with_eid_and_type("A", "foo").expect("Expected EntityUID parse.")),
            Expr::val(EntityUID::with_eid_and_type("B", "foo").expect("Expected EntityUID parse.")),
        ),
        &Type::singleton_boolean(false),
    );
}

#[test]
fn entity_has_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::has_attr(Expr::var(Var::Principal), "attr".into()),
        &Type::primitive_boolean(),
    );
}

#[test]
fn record_has_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::has_attr(Expr::var(Var::Context), "attr".into()),
        &Type::singleton_boolean(false),
    );
    assert_typechecks_empty_schema(
        &Expr::has_attr(Expr::record([]).unwrap(), "attr".into()),
        &Type::singleton_boolean(false),
    );
    assert_typechecks_empty_schema(
        &Expr::from_str("{a: 1} has a").unwrap(),
        &Type::singleton_boolean(true),
    );
}

#[test]
fn record_lub_has_typechecks_strict() {
    assert_typechecks_empty_schema(
        &Expr::from_str("(if 1 > 0 then {a: 1} else {a: 2}) has a").unwrap(),
        &Type::singleton_boolean(true),
    );
    assert_typechecks_empty_schema(
        &Expr::from_str("(if 1 > 0 then {a: 1} else {a: 2}) has b").unwrap(),
        &Type::singleton_boolean(false),
    );
    assert_typechecks_empty_schema(
        &Expr::from_str("(if 1 > 0 then {a: true} else {a: false}) has b").unwrap(),
        &Type::singleton_boolean(false),
    );
    assert_typechecks_empty_schema(
        &Expr::from_str("(if 1 > 0 then {a: true} else {a: false}) has a").unwrap(),
        &Type::singleton_boolean(true),
    );
}

#[test]
fn record_lub_has_typechecks_permissive() {
    assert_typechecks_empty_schema_permissive(
        &Expr::from_str("(if 1 > 0 then {a: 1} else {a: 2, b: 3}) has a").unwrap(),
        &Type::singleton_boolean(true),
    );
    assert_typechecks_empty_schema_permissive(
        &Expr::from_str("(if 1 > 0 then {a: 1, b: 2} else {a: 1, c: 2}) has a").unwrap(),
        &Type::singleton_boolean(true),
    );
    assert_typechecks_empty_schema_permissive(
        &Expr::from_str("(if 1 > 0 then {a: 1} else {}) has a").unwrap(),
        &Type::primitive_boolean(),
    );
    assert_typechecks_empty_schema_permissive(
        &Expr::from_str("(if 1 > 0 then {a: 1, b: 2} else {a: 1, c: 2}) has b").unwrap(),
        &Type::primitive_boolean(),
    );
    assert_typechecks_empty_schema_permissive(
        &Expr::from_str("(if 1 > 0 then (if 1 > 0 then {a: 1} else {}) else {}) has a").unwrap(),
        &Type::primitive_boolean(),
    );

    // These cases are imprecise.
    assert_typechecks_empty_schema_permissive(
        &Expr::from_str("(if 1 > 0 then {a: 1} else {}) has c").unwrap(),
        &Type::primitive_boolean(),
    );
    assert_typechecks_empty_schema_permissive(
        &Expr::from_str("(if 1 > 0 then {a: 1} else {b: 2}) has c").unwrap(),
        &Type::primitive_boolean(),
    );
    assert_typechecks_empty_schema_permissive(
        &Expr::from_str("(if 1 > 0 then {a: 1} else {a : false}) has a").unwrap(),
        &Type::primitive_boolean(),
    );
}

#[test]
fn has_typecheck_fails() {
    let src = "true has attr";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_one_of_types(
            get_loc(src, "true"),
            expr_id_placeholder(),
            vec![Type::any_entity_reference(), Type::any_record()],
            Type::singleton_boolean(true),
            None,
        )
    );
}

#[test]
fn record_get_attr_typechecks() {
    let attr: SmolStr = "foo".into();
    assert_typechecks_empty_schema(
        &Expr::get_attr(Expr::record([(attr.clone(), Expr::val(1))]).unwrap(), attr),
        &Type::primitive_long(),
    );
}

#[test]
fn record_get_attr_incompatible() {
    let src = "(if (1 > 0) then {foo: true} else {foo: 1}).foo";
    let errors = assert_typecheck_fails_for_mode(
        empty_schema_file(),
        &src.parse().unwrap(),
        None,
        crate::validator::ValidationMode::Permissive,
    );
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::unsafe_attribute_access(
            get_loc(src, src),
            expr_id_placeholder(),
            AttributeAccess::Other(vec!["foo".into()]),
            None,
            true,
        )
    );
}

#[test]
fn record_get_attr_typecheck_fails() {
    let src = "2.foo";
    let errors = assert_typecheck_fails_empty_schema_without_type(&src.parse().unwrap());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_one_of_types(
            get_loc(src, "2"),
            expr_id_placeholder(),
            vec![Type::any_entity_reference(), Type::any_record()],
            Type::primitive_long(),
            None,
        )
    );
}

#[test]
fn record_get_attr_lub_typecheck_fails() {
    let src = "(if (0 < 1) then {foo: true} else 1).foo";
    let errors = assert_typecheck_fails_empty_schema_without_type(&src.parse().unwrap());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::incompatible_types(
            get_loc(src, "if (0 < 1) then {foo: true} else 1"),
            expr_id_placeholder(),
            [
                Type::closed_record_with_required_attributes([(
                    "foo".into(),
                    Type::singleton_boolean(true),
                )]),
                Type::primitive_long(),
            ],
            LubHelp::None,
            LubContext::Conditional,
        )
    );
}

#[test]
fn record_get_attr_does_not_exist() {
    let src = "{}.foo";
    let errors = assert_typecheck_fails_empty_schema_without_type(&src.parse().unwrap());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::unsafe_attribute_access(
            get_loc(src, src),
            expr_id_placeholder(),
            AttributeAccess::Other(vec!["foo".into()]),
            None,
            false,
        )
    );
}

#[test]
fn record_get_attr_lub_does_not_exist() {
    let src = "(if true then {} else {foo: 1}).foo";
    let errors = assert_typecheck_fails_empty_schema_without_type(&src.parse().unwrap());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::unsafe_attribute_access(
            get_loc(src, src),
            expr_id_placeholder(),
            AttributeAccess::Other(vec!["foo".into()]),
            None,
            false,
        )
    );
}

#[test]
fn in_typechecks_permissive() {
    assert_typechecks_empty_schema_permissive(
        &Expr::is_in(Expr::var(Var::Principal), Expr::var(Var::Resource)),
        &Type::primitive_boolean(),
    );
}

#[test]
fn in_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::is_in(Expr::var(Var::Principal), Expr::var(Var::Principal)),
        &Type::primitive_boolean(),
    );
}

#[test]
fn in_set_typechecks_permissive() {
    assert_typechecks_empty_schema_permissive(
        &Expr::is_in(
            Expr::var(Var::Principal),
            Expr::set([Expr::var(Var::Resource)]),
        ),
        &Type::primitive_boolean(),
    );
}

#[test]
fn in_set_typechecks_strict() {
    assert_typechecks_empty_schema(
        &Expr::is_in(
            Expr::var(Var::Principal),
            Expr::set([Expr::var(Var::Principal)]),
        ),
        &Type::primitive_boolean(),
    );
}

#[test]
fn in_typecheck_fails() {
    let src = "0 in true";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    assert_sets_equal(
        errors,
        [
            ValidationError::expected_type(
                get_loc(src, "0"),
                expr_id_placeholder(),
                Type::any_entity_reference(),
                Type::primitive_long(),
                Some(UnexpectedTypeHelp::TryUsingContains),
            ),
            ValidationError::expected_one_of_types(
                get_loc(src, "true"),
                expr_id_placeholder(),
                vec![
                    Type::set(Type::any_entity_reference()),
                    Type::any_entity_reference(),
                ],
                Type::singleton_boolean(true),
                None,
            ),
        ],
    );
}

#[test]
fn contains_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::contains(Expr::set([Expr::val(1)]), Expr::val(2)),
        &Type::primitive_boolean(),
    );
}

#[test]
fn contains_typecheck_fails() {
    use crate::validator::types::AttributeType;
    let src = r#""foo".contains("bar")"#;
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, r#""foo""#),
            expr_id_placeholder(),
            Type::any_set(),
            Type::primitive_string(),
            Some(UnexpectedTypeHelp::TryUsingLike),
        )
    );

    let src = r#"1.contains("bar")"#;
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "1"),
            expr_id_placeholder(),
            Type::any_set(),
            Type::primitive_long(),
            None,
        )
    );

    let src = r#"{foo: 1}.contains("foo")"#;
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "{foo: 1}"),
            expr_id_placeholder(),
            Type::any_set(),
            Type::closed_record_with_attributes([(
                "foo".into(),
                AttributeType::new(Type::primitive_long(), true),
            )]),
            Some(UnexpectedTypeHelp::TryUsingHas),
        )
    );
}

#[test]
fn contains_typecheck_literals_false() {
    let schema: json_schema::NamespaceDefinition<RawName> = serde_json::from_value(json!(
    {
        "entityTypes": {},
        "actions": {
            "view_photo": { },
            "view_album": { }
        }
    }))
    .expect("Expected that schema would parse");
    assert_typechecks(
        schema,
        &Expr::contains(
            Expr::set([Expr::val(
                EntityUID::with_eid_and_type("Action", "view_photo")
                    .expect("Expected EntityUID parse."),
            )]),
            Expr::val(
                EntityUID::with_eid_and_type("Action", "view_album")
                    .expect("Expected EntityUID parse."),
            ),
        ),
        // Previously had type `False`. This case might become false again if we
        // decide to restore some of the special cases for `contains`.
        &Type::primitive_boolean(),
    );
}

#[test]
fn contains_all_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::contains_all(Expr::set([Expr::val(1)]), Expr::set([Expr::val(1)])),
        &Type::primitive_boolean(),
    );
}

#[test]
fn contains_all_typecheck_fails() {
    let src = "1.containsAll(true)";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    assert_sets_equal(
        errors,
        [
            ValidationError::expected_type(
                get_loc(src, "1"),
                expr_id_placeholder(),
                Type::any_set(),
                Type::primitive_long(),
                None,
            ),
            ValidationError::expected_type(
                get_loc(src, "true"),
                expr_id_placeholder(),
                Type::any_set(),
                Type::singleton_boolean(true),
                Some(UnexpectedTypeHelp::TryUsingSingleContains),
            ),
        ],
    );
}

#[test]
fn contains_all_typecheck_literals_false() {
    let schema: json_schema::NamespaceDefinition<RawName> = serde_json::from_value(json!(
    {
        "entityTypes": {},
        "actions": {
            "view_photo": {},
            "view_album": {}
        }
    }))
    .expect("Expected that schema would parse");
    assert_typechecks(
        schema,
        &Expr::contains_all(
            Expr::set([Expr::val(
                EntityUID::with_eid_and_type("Action", "view_photo")
                    .expect("Expected EntityUID parse."),
            )]),
            Expr::set([Expr::val(
                EntityUID::with_eid_and_type("Action", "view_album")
                    .expect("Expected EntityUID parse."),
            )]),
        ),
        // Previously had type `False`. This case might become false again if we
        // decide to restore some of the special cases for `containsAll`.
        &Type::primitive_boolean(),
    );
}

#[test]
fn is_empty_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::is_empty(Expr::set([Expr::val(1)])),
        &Type::primitive_boolean(),
    );
}

#[test]
fn is_empty_typecheck_fails() {
    let src = "\"crab\".isEmpty()";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "\"crab\""),
            expr_id_placeholder(),
            Type::any_set(),
            Type::primitive_string(),
            Some(UnexpectedTypeHelp::TryUsingEqEmptyString),
        )
    )
}

#[test]
fn like_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::like(
            Expr::val("foo"),
            Pattern::from(vec![
                PatternElem::Char('b'),
                PatternElem::Char('a'),
                PatternElem::Char('r'),
            ]),
        ),
        &Type::primitive_boolean(),
    );
}

#[test]
fn like_typecheck_fails() {
    let src = r#"1 like "bar""#;
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "1"),
            expr_id_placeholder(),
            Type::primitive_string(),
            Type::primitive_long(),
            None,
        )
    );
}

#[test]
fn less_than_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::less(Expr::val(1), Expr::val(2)),
        &Type::primitive_boolean(),
    );
}

#[test]
fn less_than_typecheck_fails() {
    let extensions = Extensions::all_available();
    let expected_types = extensions
        .types_with_operator_overloading()
        .cloned()
        .map(Type::extension)
        .chain(std::iter::once(Type::primitive_long()))
        .collect_vec();
    let src = "true < false";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    assert_sets_equal(
        errors,
        [
            ValidationError::expected_one_of_types(
                get_loc(src, "true"),
                expr_id_placeholder(),
                expected_types.clone(),
                Type::singleton_boolean(true),
                None,
            ),
            ValidationError::expected_one_of_types(
                get_loc(src, "false"),
                expr_id_placeholder(),
                expected_types.clone(),
                Type::singleton_boolean(false),
                None,
            ),
        ],
    );

    let src = "true < \"\"";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    assert_sets_equal(
        errors,
        [
            ValidationError::expected_one_of_types(
                get_loc(src, "true"),
                expr_id_placeholder(),
                expected_types.clone(),
                Type::singleton_boolean(true),
                None,
            ),
            ValidationError::expected_one_of_types(
                get_loc(src, "\"\""),
                expr_id_placeholder(),
                expected_types,
                Type::primitive_string(),
                None,
            ),
        ],
    );

    let src = "true < 1";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    assert_sets_equal(
        errors,
        [ValidationError::expected_type(
            get_loc(src, "true"),
            expr_id_placeholder(),
            Type::primitive_long(),
            Type::singleton_boolean(true),
            None,
        )],
    );
}

#[test]
fn not_typechecks() {
    assert_typechecks_empty_schema(&Expr::not(Expr::val(true)), &Type::singleton_boolean(false));
    assert_typechecks_empty_schema(&Expr::not(Expr::val(false)), &Type::singleton_boolean(true));
}

#[test]
fn not_typecheck_fails() {
    let src = "!1";
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "1"),
            expr_id_placeholder(),
            Type::primitive_boolean(),
            Type::primitive_long(),
            None,
        )
    );
}

#[test]
fn if_typechecks() {
    assert_typechecks_empty_schema(
        &Expr::ite(Expr::val(true), Expr::val(1), Expr::val(22)),
        &Type::primitive_long(),
    );
}

#[test]
fn if_true_ignore_else() {
    assert_typechecks_empty_schema(
        &Expr::ite(Expr::val(true), Expr::val(1), Expr::not(Expr::val(22))),
        &Type::primitive_long(),
    );
}

#[test]
fn if_false_ignores_then() {
    assert_typechecks_empty_schema(
        &Expr::ite(Expr::val(false), Expr::not(Expr::val(1)), Expr::val(22)),
        &Type::primitive_long(),
    );
}

#[test]
fn if_no_lub_error() {
    let src = r#"if (1 < 2) then 1 else "test""#;
    let errors = assert_typecheck_fails_empty_schema_without_type(&src.parse().unwrap());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::incompatible_types(
            get_loc(src, src),
            expr_id_placeholder(),
            [Type::primitive_long(), Type::primitive_string()],
            LubHelp::None,
            LubContext::Conditional,
        )
    );
}

#[test]
fn if_typecheck_fails() {
    let src = r#"if "fail" then 1 else "test""#;
    let errors = assert_typecheck_fails_empty_schema_without_type(&src.parse().unwrap());
    assert_sets_equal(
        errors,
        [
            ValidationError::incompatible_types(
                get_loc(src, src),
                expr_id_placeholder(),
                [Type::primitive_long(), Type::primitive_string()],
                LubHelp::None,
                LubContext::Conditional,
            ),
            ValidationError::expected_type(
                get_loc(src, r#""fail""#),
                expr_id_placeholder(),
                Type::primitive_boolean(),
                Type::primitive_string(),
                None,
            ),
        ],
    );
}

#[test]
fn neg_typechecks() {
    let neg_expr = Expr::neg(Expr::val(1));
    assert_typechecks_empty_schema(&neg_expr, &Type::primitive_long());
}

#[test]
fn neg_typecheck_fails() {
    let src = r#"-"foo""#;
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_long());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, r#""foo""#),
            expr_id_placeholder(),
            Type::primitive_long(),
            Type::primitive_string(),
            None,
        )
    )
}

#[test]
fn mul_typechecks() {
    let neg_expr = Expr::mul(Expr::val(1), Expr::val(2));
    assert_typechecks_empty_schema(&neg_expr, &Type::primitive_long());
}

#[test]
fn mul_typecheck_fails() {
    let src = r#""foo" * 2"#;
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_long());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, r#""foo""#),
            expr_id_placeholder(),
            Type::primitive_long(),
            Type::primitive_string(),
            None,
        )
    )
}

#[test]
fn add_sub_typechecks() {
    let add_expr = Expr::add(Expr::val(1), Expr::val(2));
    assert_typechecks_empty_schema(&add_expr, &Type::primitive_long());
    let sub_expr = Expr::sub(Expr::val(1), Expr::val(2));
    assert_typechecks_empty_schema(&sub_expr, &Type::primitive_long());
}

#[test]
fn add_sub_typecheck_fails() {
    let src = r#"1 + "foo""#;
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_long());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, r#""foo""#),
            expr_id_placeholder(),
            Type::primitive_long(),
            Type::primitive_string(),
            Some(UnexpectedTypeHelp::ConcatenationNotSupported),
        )
    );

    let src = r#""bar" - 2"#;
    let errors =
        assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_long());
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, r#""bar""#),
            expr_id_placeholder(),
            Type::primitive_long(),
            Type::primitive_string(),
            None,
        )
    );
}

#[test]
fn is_typecheck_fails() {
    let schema: json_schema::NamespaceDefinition<RawName> =
        serde_json::from_value(json!({ "entityTypes": { "User": {}, }, "actions": {} })).unwrap();
    let src = r#"1 is User"#;
    let errors = assert_typecheck_fails(
        schema,
        &src.parse().unwrap(),
        Some(&Type::primitive_boolean()),
    );
    let error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        error,
        ValidationError::expected_type(
            get_loc(src, "1"),
            expr_id_placeholder(),
            Type::any_entity_reference(),
            Type::primitive_long(),
            Some(UnexpectedTypeHelp::TypeTestNotSupported),
        )
    );
}

#[test]
fn is_typechecks() {
    let schema = json_schema::Fragment::from_json_value(json!({
            "": { "entityTypes": { "User": {}, "Photo": {} }, "actions": {} },
            "N::S": { "entityTypes": { "Foo": {} }, "actions": {} }
    }))
    .unwrap();
    assert_typechecks(
        schema.clone(),
        &r#"User::"alice" is User"#.parse().unwrap(),
        &Type::singleton_boolean(true),
    );
    assert_typechecks(
        schema.clone(),
        &r#"User::"alice" is Photo"#.parse().unwrap(),
        &Type::singleton_boolean(false),
    );
    assert_typechecks(
        schema.clone(),
        &r#"N::S::Foo::"alice" is N::S::Foo"#.parse().unwrap(),
        &Type::singleton_boolean(true),
    );
    assert_typechecks(
        schema,
        &r#"N::S::Foo::"alice" is User"#.parse().unwrap(),
        &Type::singleton_boolean(false),
    );
}

mod datetime {
    use crate::{
        ast::{Expr, Name, Value},
        extensions::Extensions,
    };
    use itertools::Itertools;

    use crate::validator::{
        typecheck::test::test_utils::{expr_id_placeholder, get_loc},
        types::Type,
        ValidationError,
    };

    use super::{
        assert_sets_equal, assert_typecheck_fails_empty_schema, assert_typechecks_empty_schema,
    };

    #[inline]
    fn get_datetime_constructor_name() -> Name {
        "datetime".parse().unwrap()
    }

    #[inline]
    fn get_duration_constructor_name() -> Name {
        "duration".parse().unwrap()
    }

    #[test]
    fn less_than_typechecks() {
        assert_typechecks_empty_schema(
            &Expr::less(Expr::val(1), Expr::val(2)),
            &Type::primitive_boolean(),
        );
        assert_typechecks_empty_schema(
            &Expr::less(
                Expr::call_extension_fn(
                    get_datetime_constructor_name(),
                    vec![Value::from("1970-01-01").into()],
                ),
                Expr::call_extension_fn(
                    get_datetime_constructor_name(),
                    vec![Value::from("1970-01-02").into()],
                ),
            ),
            &Type::primitive_boolean(),
        );
        assert_typechecks_empty_schema(
            &Expr::lesseq(
                Expr::call_extension_fn(
                    get_datetime_constructor_name(),
                    vec![Value::from("1970-01-01").into()],
                ),
                Expr::call_extension_fn(
                    get_datetime_constructor_name(),
                    vec![Value::from("1970-01-02").into()],
                ),
            ),
            &Type::primitive_boolean(),
        );
        assert_typechecks_empty_schema(
            &Expr::less(
                Expr::call_extension_fn(
                    get_duration_constructor_name(),
                    vec![Value::from("1h").into()],
                ),
                Expr::call_extension_fn(
                    get_duration_constructor_name(),
                    vec![Value::from("2h").into()],
                ),
            ),
            &Type::primitive_boolean(),
        );
        assert_typechecks_empty_schema(
            &Expr::lesseq(
                Expr::call_extension_fn(
                    get_duration_constructor_name(),
                    vec![Value::from("1h").into()],
                ),
                Expr::call_extension_fn(
                    get_duration_constructor_name(),
                    vec![Value::from("2h").into()],
                ),
            ),
            &Type::primitive_boolean(),
        );
    }

    #[test]
    fn less_than_typecheck_fails() {
        let extensions = Extensions::all_available();
        let expected_types = extensions
            .types_with_operator_overloading()
            .cloned()
            .map(Type::extension)
            .chain(std::iter::once(Type::primitive_long()))
            .collect_vec();
        let src = "true < false";
        let errors =
            assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
        assert_sets_equal(
            errors,
            [
                ValidationError::expected_one_of_types(
                    get_loc(src, "true"),
                    expr_id_placeholder(),
                    expected_types.clone(),
                    Type::singleton_boolean(true),
                    None,
                ),
                ValidationError::expected_one_of_types(
                    get_loc(src, "false"),
                    expr_id_placeholder(),
                    expected_types.clone(),
                    Type::singleton_boolean(false),
                    None,
                ),
            ],
        );

        let src = "true < \"\"";
        let errors =
            assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
        assert_sets_equal(
            errors,
            [
                ValidationError::expected_one_of_types(
                    get_loc(src, "true"),
                    expr_id_placeholder(),
                    expected_types.clone(),
                    Type::singleton_boolean(true),
                    None,
                ),
                ValidationError::expected_one_of_types(
                    get_loc(src, "\"\""),
                    expr_id_placeholder(),
                    expected_types,
                    Type::primitive_string(),
                    None,
                ),
            ],
        );

        let src = "true < 1";
        let errors =
            assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
        assert_sets_equal(
            errors,
            [ValidationError::expected_type(
                get_loc(src, "true"),
                expr_id_placeholder(),
                Type::primitive_long(),
                Type::singleton_boolean(true),
                None,
            )],
        );

        let src = r#"true < duration("1h")"#;
        let errors =
            assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
        assert_sets_equal(
            errors,
            [ValidationError::expected_type(
                get_loc(src, "true"),
                expr_id_placeholder(),
                Type::ExtensionType {
                    name: get_duration_constructor_name(),
                },
                Type::singleton_boolean(true),
                None,
            )],
        );

        // Error reporting favors long
        let src = r#"duration("1d") < 1"#;
        let errors =
            assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
        assert_sets_equal(
            errors,
            [ValidationError::expected_type(
                get_loc(src, r#"duration("1d")"#),
                expr_id_placeholder(),
                Type::primitive_long(),
                Type::ExtensionType {
                    name: get_duration_constructor_name(),
                },
                None,
            )],
        );

        let src = r#"1 < duration("1d")"#;
        let errors =
            assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
        assert_sets_equal(
            errors,
            [ValidationError::expected_type(
                get_loc(src, r#"duration("1d")"#),
                expr_id_placeholder(),
                Type::primitive_long(),
                Type::ExtensionType {
                    name: get_duration_constructor_name(),
                },
                None,
            )],
        );

        let src = r#"datetime("1970-01-01") < duration("1d")"#;
        let errors =
            assert_typecheck_fails_empty_schema(&src.parse().unwrap(), &Type::primitive_boolean());
        assert_sets_equal(
            errors,
            [ValidationError::expected_type(
                get_loc(src, r#"duration("1d")"#),
                expr_id_placeholder(),
                Type::ExtensionType {
                    name: get_datetime_constructor_name(),
                },
                Type::ExtensionType {
                    name: get_duration_constructor_name(),
                },
                None,
            )],
        );
    }
}
