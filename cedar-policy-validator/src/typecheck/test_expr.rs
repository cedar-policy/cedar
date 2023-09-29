/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#![cfg(test)]
// GRCOV_STOP_COVERAGE

use std::str::FromStr;

use cedar_policy_core::ast::{BinaryOp, EntityUID, Expr, PatternElem, SlotId, Var};
use serde_json::json;
use smol_str::SmolStr;

use crate::{
    type_error::TypeError, types::Type, AttributeAccess, AttributesOrContext, EntityType,
    NamespaceDefinition, ValidationMode,
};

use super::test_utils::{
    assert_typecheck_fails_empty_schema, assert_typecheck_fails_empty_schema_without_type,
    assert_typecheck_fails_for_mode, assert_typechecks, assert_typechecks_empty_schema,
    assert_typechecks_empty_schema_permissive, assert_typechecks_for_mode, empty_schema_file,
};

#[test]
fn primitives_typecheck() {
    assert_typechecks_empty_schema(Expr::val(true), Type::singleton_boolean(true));
    assert_typechecks_empty_schema(Expr::val(1), Type::primitive_long());
    assert_typechecks_empty_schema(Expr::val("foo"), Type::primitive_string());
}

#[test]
fn slot_typechecks() {
    assert_typechecks_empty_schema(
        Expr::slot(SlotId::principal()),
        Type::any_entity_reference(),
    );

    assert_typechecks_empty_schema(Expr::slot(SlotId::resource()), Type::any_entity_reference());
}

#[test]
fn slot_in_typechecks() {
    let etype = EntityType {
        member_of_types: vec![],
        shape: AttributesOrContext::default(),
    };
    let schema = NamespaceDefinition::new([("typename".into(), etype)], []);
    assert_typechecks_for_mode(
        schema.clone(),
        Expr::binary_app(
            BinaryOp::In,
            Expr::val(EntityUID::with_eid_and_type("typename", "id").expect("Bad EUID")),
            Expr::slot(SlotId::principal()),
        ),
        Type::primitive_boolean(),
        ValidationMode::Permissive,
    );
    assert_typechecks_for_mode(
        schema,
        Expr::binary_app(
            BinaryOp::In,
            Expr::val(EntityUID::with_eid_and_type("typename", "id").expect("Bad EUID")),
            Expr::slot(SlotId::resource()),
        ),
        Type::primitive_boolean(),
        ValidationMode::Permissive,
    );
}

#[test]
fn slot_equals_typechecks() {
    let etype = EntityType {
        member_of_types: vec![],
        shape: AttributesOrContext::default(),
    };
    // These don't typecheck in strict mode because the test_util expression
    // typechecker doesn't have access to a schema, so it can't instantiate
    // the template slots with appropriate types. Similar policies that pass
    // strict typechecking are in the test_policy file.
    let schema = NamespaceDefinition::new([("typename".into(), etype)], []);
    assert_typechecks_for_mode(
        schema.clone(),
        Expr::binary_app(
            BinaryOp::Eq,
            Expr::val(EntityUID::with_eid_and_type("typename", "edi").expect("EUID Failed")),
            Expr::slot(SlotId::principal()),
        ),
        Type::primitive_boolean(),
        ValidationMode::Permissive,
    );
    assert_typechecks_for_mode(
        schema,
        Expr::binary_app(
            BinaryOp::Eq,
            Expr::val(EntityUID::with_eid_and_type("typename", "edi").expect("EUID Failed")),
            Expr::slot(SlotId::resource()),
        ),
        Type::primitive_boolean(),
        ValidationMode::Permissive,
    );
}

#[test]
fn slot_has_typechecks() {
    assert_typechecks_empty_schema(
        Expr::has_attr(Expr::slot(SlotId::principal()), "test".into()),
        Type::primitive_boolean(),
    );
    assert_typechecks_empty_schema(
        Expr::has_attr(Expr::slot(SlotId::resource()), "test".into()),
        Type::primitive_boolean(),
    );
}

#[test]
fn set_typechecks() {
    assert_typechecks_empty_schema(
        Expr::set([Expr::val(true)]),
        Type::set(Type::singleton_boolean(true)),
    );
}

#[test]
fn heterogeneous_set() {
    let set = Expr::set([Expr::val(true), Expr::val(1)]);
    assert_typecheck_fails_empty_schema_without_type(
        set.clone(),
        vec![TypeError::incompatible_types(
            set,
            vec![Type::singleton_boolean(true), Type::primitive_long()],
        )],
    );
}

#[test]
fn record_typechecks() {
    assert_typechecks_empty_schema(
        Expr::record([("foo".into(), Expr::val(1))]),
        Type::closed_record_with_required_attributes([("foo".into(), Type::primitive_long())]),
    )
}

#[test]
fn and_typechecks() {
    assert_typechecks_empty_schema(
        Expr::and(Expr::val(true), Expr::val(false)),
        Type::singleton_boolean(false),
    );
}

#[test]
fn and_typecheck_fails() {
    assert_typecheck_fails_empty_schema(
        Expr::and(Expr::val(1), Expr::val(true)),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(1),
            Type::primitive_boolean(),
            Type::primitive_long(),
        )],
    );
    assert_typecheck_fails_empty_schema(
        Expr::and(Expr::greater(Expr::val(1), Expr::val(0)), Expr::val(1)),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(1),
            Type::primitive_boolean(),
            Type::primitive_long(),
        )],
    );
    assert_typecheck_fails_empty_schema(
        Expr::and(
            Expr::greater(Expr::val(1), Expr::val(true)),
            Expr::val(true),
        ),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(true),
            Type::primitive_long(),
            Type::singleton_boolean(true),
        )],
    );
    assert_typecheck_fails_empty_schema(
        Expr::and(
            Expr::val(true),
            Expr::greater(Expr::val(1), Expr::val(true)),
        ),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(true),
            Type::primitive_long(),
            Type::singleton_boolean(true),
        )],
    );
}

#[test]
fn or_left_true_is_true() {
    assert_typechecks_empty_schema(
        Expr::or(Expr::val(true), Expr::val(false)),
        Type::singleton_boolean(true),
    );
}

#[test]
fn or_left_false_is_right() {
    assert_typechecks_empty_schema(
        Expr::or(Expr::val(false), Expr::greater(Expr::val(1), Expr::val(0))),
        Type::primitive_boolean(),
    );
}

#[test]
fn or_left_true_ignores_right() {
    assert_typechecks_empty_schema(
        Expr::or(Expr::val(true), Expr::not(Expr::val(1))),
        Type::singleton_boolean(true),
    );
}

#[test]
fn or_right_true_fails_left() {
    assert_typecheck_fails_empty_schema(
        Expr::or(Expr::val(1), Expr::val(true)),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(1),
            Type::primitive_boolean(),
            Type::primitive_long(),
        )],
    );
}

#[test]
fn or_right_true_is_true() {
    assert_typechecks_empty_schema(
        Expr::or(Expr::greater(Expr::val(1), Expr::val(0)), Expr::val(true)),
        Type::singleton_boolean(true),
    );
}

#[test]
fn or_right_false_is_left() {
    assert_typechecks_empty_schema(
        Expr::or(Expr::greater(Expr::val(1), Expr::val(0)), Expr::val(false)),
        Type::primitive_boolean(),
    );
}

#[test]
fn or_boolean() {
    assert_typechecks_empty_schema(
        Expr::or(
            Expr::greater(Expr::val(1), Expr::val(0)),
            Expr::greater(Expr::val(1), Expr::val(0)),
        ),
        Type::primitive_boolean(),
    );
}

#[test]
fn or_false() {
    assert_typechecks_empty_schema(
        Expr::or(Expr::val(false), Expr::val(false)),
        Type::singleton_boolean(false),
    );
}

#[test]
fn or_typecheck_fails() {
    assert_typecheck_fails_empty_schema(
        Expr::or(Expr::val(1), Expr::val(true)),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(1),
            Type::primitive_boolean(),
            Type::primitive_long(),
        )],
    );
    assert_typecheck_fails_empty_schema(
        Expr::or(Expr::greater(Expr::val(1), Expr::val(0)), Expr::val(1)),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(1),
            Type::primitive_boolean(),
            Type::primitive_long(),
        )],
    );
    assert_typecheck_fails_empty_schema(
        Expr::or(
            Expr::greater(Expr::val(1), Expr::val(true)),
            Expr::val(false),
        ),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(true),
            Type::primitive_long(),
            Type::singleton_boolean(true),
        )],
    );
    assert_typecheck_fails_empty_schema(
        Expr::or(
            Expr::greater(Expr::val(1), Expr::val(true)),
            Expr::val(true),
        ),
        Type::singleton_boolean(true),
        vec![TypeError::expected_type(
            Expr::val(true),
            Type::primitive_long(),
            Type::singleton_boolean(true),
        )],
    );
    assert_typecheck_fails_empty_schema(
        Expr::or(
            Expr::val(false),
            Expr::greater(Expr::val(1), Expr::val(true)),
        ),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(true),
            Type::primitive_long(),
            Type::singleton_boolean(true),
        )],
    );
}

#[test]
fn eq_typechecks() {
    assert_typechecks_empty_schema(
        Expr::is_eq(Expr::val(2), Expr::val(1)),
        Type::primitive_boolean(),
    );
}

#[test]
fn entity_eq_is_false() {
    let schema: NamespaceDefinition = serde_json::from_str(
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
        Expr::is_eq(
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
        Type::False,
    );
}

#[test]
fn set_eq_is_not_false() {
    let schema: NamespaceDefinition = serde_json::from_str(
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
        Expr::is_eq(
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
        Type::primitive_boolean(),
        ValidationMode::Permissive,
    );
}

#[test]
fn eq_typecheck_action_literals_false() {
    let schema: NamespaceDefinition = serde_json::from_str(
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
        Expr::is_eq(
            Expr::val(
                EntityUID::with_eid_and_type("Action", "view_photo")
                    .expect("Expected EntityUID parse."),
            ),
            Expr::val(
                EntityUID::with_eid_and_type("Action", "view_album")
                    .expect("Expected EntityUID parse."),
            ),
        ),
        Type::singleton_boolean(false),
    );
}

#[test]
fn eq_typecheck_entity_literals_false() {
    let schema: NamespaceDefinition = serde_json::from_str(
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
        Expr::is_eq(
            Expr::val(EntityUID::with_eid_and_type("A", "foo").expect("Expected EntityUID parse.")),
            Expr::val(EntityUID::with_eid_and_type("B", "foo").expect("Expected EntityUID parse.")),
        ),
        Type::singleton_boolean(false),
    );
}

#[test]
fn entity_has_typechecks() {
    assert_typechecks_empty_schema(
        Expr::has_attr(Expr::var(Var::Principal), "attr".into()),
        Type::singleton_boolean(false),
    );
}

#[test]
fn record_has_typechecks() {
    assert_typechecks_empty_schema(
        Expr::has_attr(Expr::var(Var::Context), "attr".into()),
        Type::singleton_boolean(false),
    );
    assert_typechecks_empty_schema(
        Expr::has_attr(Expr::record([]), "attr".into()),
        Type::singleton_boolean(false),
    );
    assert_typechecks_empty_schema(
        Expr::from_str("{a: 1} has a").unwrap(),
        Type::singleton_boolean(true),
    );
}

#[test]
fn record_lub_has_typechecks_strict() {
    assert_typechecks_empty_schema(
        Expr::from_str("(if 1 > 0 then {a: 1} else {a: 2}) has a").unwrap(),
        Type::singleton_boolean(true),
    );
    assert_typechecks_empty_schema(
        Expr::from_str("(if 1 > 0 then {a: 1} else {a: 2}) has b").unwrap(),
        Type::singleton_boolean(false),
    );
    assert_typechecks_empty_schema(
        Expr::from_str("(if 1 > 0 then {a: true} else {a: false}) has b").unwrap(),
        Type::singleton_boolean(false),
    );
    assert_typechecks_empty_schema(
        Expr::from_str("(if 1 > 0 then {a: true} else {a: false}) has a").unwrap(),
        Type::singleton_boolean(true),
    );
}

#[test]
fn record_lub_has_typechecks_permissive() {
    assert_typechecks_empty_schema_permissive(
        Expr::from_str("(if 1 > 0 then {a: 1} else {a: 2, b: 3}) has a").unwrap(),
        Type::singleton_boolean(true),
    );
    assert_typechecks_empty_schema_permissive(
        Expr::from_str("(if 1 > 0 then {a: 1, b: 2} else {a: 1, c: 2}) has a").unwrap(),
        Type::singleton_boolean(true),
    );
    assert_typechecks_empty_schema_permissive(
        Expr::from_str("(if 1 > 0 then {a: 1} else {}) has a").unwrap(),
        Type::primitive_boolean(),
    );
    assert_typechecks_empty_schema_permissive(
        Expr::from_str("(if 1 > 0 then {a: 1, b: 2} else {a: 1, c: 2}) has b").unwrap(),
        Type::primitive_boolean(),
    );
    assert_typechecks_empty_schema_permissive(
        Expr::from_str("(if 1 > 0 then (if 1 > 0 then {a: 1} else {}) else {}) has a").unwrap(),
        Type::primitive_boolean(),
    );

    // These cases are imprecise.
    assert_typechecks_empty_schema_permissive(
        Expr::from_str("(if 1 > 0 then {a: 1} else {}) has c").unwrap(),
        Type::primitive_boolean(),
    );
    assert_typechecks_empty_schema_permissive(
        Expr::from_str("(if 1 > 0 then {a: 1} else {b: 2}) has c").unwrap(),
        Type::primitive_boolean(),
    );
    assert_typechecks_empty_schema_permissive(
        Expr::from_str("(if 1 > 0 then {a: 1} else {a : false}) has a").unwrap(),
        Type::primitive_boolean(),
    );
}

#[test]
fn has_typecheck_fails() {
    assert_typecheck_fails_empty_schema(
        Expr::has_attr(Expr::val(true), "attr".into()),
        Type::primitive_boolean(),
        vec![TypeError::expected_one_of_types(
            Expr::val(true),
            vec![Type::any_entity_reference(), Type::any_record()],
            Type::singleton_boolean(true),
        )],
    );
}

#[test]
fn record_get_attr_typechecks() {
    let attr: SmolStr = "foo".into();
    assert_typechecks_empty_schema(
        Expr::get_attr(Expr::record([(attr.clone(), Expr::val(1))]), attr),
        Type::primitive_long(),
    );
}

#[test]
fn record_get_attr_incompatible() {
    let attr: SmolStr = "foo".into();
    let if_expr = Expr::ite(
        Expr::less(Expr::val(1), Expr::val(0)),
        Expr::record([(attr.clone(), Expr::val(true))]),
        Expr::record([(attr.clone(), Expr::val(1))]),
    );

    assert_typecheck_fails_for_mode(
        empty_schema_file(),
        Expr::get_attr(if_expr.clone(), attr.clone()),
        None,
        vec![TypeError::unsafe_attribute_access(
            Expr::get_attr(if_expr, attr.clone()),
            AttributeAccess::Other(vec![attr]),
            None,
            true,
        )],
        crate::ValidationMode::Permissive,
    );
}

#[test]
fn record_get_attr_typecheck_fails() {
    assert_typecheck_fails_empty_schema_without_type(
        Expr::get_attr(Expr::val(2), "foo".into()),
        vec![TypeError::expected_one_of_types(
            Expr::val(2),
            vec![Type::any_entity_reference(), Type::any_record()],
            Type::primitive_long(),
        )],
    );
}

#[test]
fn record_get_attr_lub_typecheck_fails() {
    let attr: SmolStr = "foo".into();
    let if_expr = Expr::ite(
        Expr::less(Expr::val(0), Expr::val(1)),
        Expr::record([(attr.clone(), Expr::val(true))]),
        Expr::val(1),
    );
    assert_typecheck_fails_empty_schema_without_type(
        Expr::get_attr(if_expr.clone(), attr.clone()),
        vec![TypeError::incompatible_types(
            if_expr,
            vec![
                Type::closed_record_with_required_attributes([(
                    attr,
                    Type::singleton_boolean(true),
                )]),
                Type::primitive_long(),
            ],
        )],
    );
}

#[test]
fn record_get_attr_does_not_exist() {
    let attr: SmolStr = "foo".into();
    assert_typecheck_fails_empty_schema_without_type(
        Expr::get_attr(Expr::record([]), attr.clone()),
        vec![TypeError::unsafe_attribute_access(
            Expr::get_attr(Expr::record([]), attr.clone()),
            AttributeAccess::Other(vec![attr]),
            None,
            false,
        )],
    );
}

#[test]
fn record_get_attr_lub_does_not_exist() {
    let attr: SmolStr = "foo".into();
    let if_expr = Expr::ite(
        Expr::val(true),
        Expr::record([]),
        Expr::record([(attr.clone(), Expr::val(1))]),
    );
    assert_typecheck_fails_empty_schema_without_type(
        Expr::get_attr(if_expr.clone(), attr.clone()),
        vec![TypeError::unsafe_attribute_access(
            Expr::get_attr(if_expr, attr.clone()),
            AttributeAccess::Other(vec![attr]),
            None,
            false,
        )],
    );
}

#[test]
fn in_typechecks_permissive() {
    assert_typechecks_empty_schema_permissive(
        Expr::is_in(Expr::var(Var::Principal), Expr::var(Var::Resource)),
        Type::primitive_boolean(),
    );
}

#[test]
fn in_typechecks() {
    assert_typechecks_empty_schema(
        Expr::is_in(Expr::var(Var::Principal), Expr::var(Var::Principal)),
        Type::primitive_boolean(),
    );
}

#[test]
fn in_set_typechecks_permissive() {
    assert_typechecks_empty_schema_permissive(
        Expr::is_in(
            Expr::var(Var::Principal),
            Expr::set([Expr::var(Var::Resource)]),
        ),
        Type::primitive_boolean(),
    );
}

#[test]
fn in_set_typechecks_strict() {
    assert_typechecks_empty_schema(
        Expr::is_in(
            Expr::var(Var::Principal),
            Expr::set([Expr::var(Var::Principal)]),
        ),
        Type::primitive_boolean(),
    );
}

#[test]
fn in_typecheck_fails() {
    assert_typecheck_fails_empty_schema(
        Expr::is_in(Expr::val(0), Expr::val(true)),
        Type::primitive_boolean(),
        vec![
            TypeError::expected_type(
                Expr::val(0),
                Type::any_entity_reference(),
                Type::primitive_long(),
            ),
            TypeError::expected_one_of_types(
                Expr::val(true),
                vec![
                    Type::set(Type::any_entity_reference()),
                    Type::any_entity_reference(),
                ],
                Type::singleton_boolean(true),
            ),
        ],
    );
}

#[test]
fn contains_typechecks() {
    assert_typechecks_empty_schema(
        Expr::contains(Expr::set([Expr::val(1)]), Expr::val(2)),
        Type::primitive_boolean(),
    );
}

#[test]
fn contains_typecheck_fails() {
    use crate::types::AttributeType;
    assert_typecheck_fails_empty_schema(
        Expr::contains(Expr::val("foo"), Expr::val("bar")),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val("foo"),
            Type::any_set(),
            Type::primitive_string(),
        )],
    );
    assert_typecheck_fails_empty_schema(
        Expr::contains(Expr::val(1), Expr::val("bar")),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(1),
            Type::any_set(),
            Type::primitive_long(),
        )],
    );
    assert_typecheck_fails_empty_schema(
        Expr::contains(
            Expr::record([("foo".into(), Expr::val(1))]),
            Expr::val("foo"),
        ),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::record([("foo".into(), Expr::val(1))]),
            Type::any_set(),
            Type::closed_record_with_attributes([(
                "foo".into(),
                AttributeType::new(Type::primitive_long(), true),
            )]),
        )],
    );
}

#[test]
fn contains_typecheck_literals_false() {
    let schema: NamespaceDefinition = serde_json::from_value(json!(
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
        Expr::contains(
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
        Type::primitive_boolean(),
    );
}

#[test]
fn contains_all_typechecks() {
    assert_typechecks_empty_schema(
        Expr::contains_all(Expr::set([Expr::val(1)]), Expr::set([Expr::val(1)])),
        Type::primitive_boolean(),
    );
}

#[test]
fn contains_all_typecheck_fails() {
    assert_typecheck_fails_empty_schema(
        Expr::contains_all(Expr::val(1), Expr::val(true)),
        Type::primitive_boolean(),
        vec![
            TypeError::expected_type(Expr::val(1), Type::any_set(), Type::primitive_long()),
            TypeError::expected_type(
                Expr::val(true),
                Type::any_set(),
                Type::singleton_boolean(true),
            ),
        ],
    );
}

#[test]
fn contains_all_typecheck_literals_false() {
    let schema: NamespaceDefinition = serde_json::from_value(json!(
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
        Expr::contains_all(
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
        Type::primitive_boolean(),
    );
}

#[test]
fn like_typechecks() {
    assert_typechecks_empty_schema(
        Expr::like(
            Expr::val("foo"),
            vec![
                PatternElem::Char('b'),
                PatternElem::Char('a'),
                PatternElem::Char('r'),
            ],
        ),
        Type::primitive_boolean(),
    );
}

#[test]
fn like_typecheck_fails() {
    assert_typecheck_fails_empty_schema(
        Expr::like(
            Expr::val(1),
            vec![
                PatternElem::Char('b'),
                PatternElem::Char('a'),
                PatternElem::Char('r'),
            ],
        ),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(1),
            Type::primitive_string(),
            Type::primitive_long(),
        )],
    );
}

#[test]
fn less_than_typechecks() {
    assert_typechecks_empty_schema(
        Expr::less(Expr::val(1), Expr::val(2)),
        Type::primitive_boolean(),
    )
}

#[test]
fn less_than_typecheck_fails() {
    assert_typecheck_fails_empty_schema(
        Expr::less(Expr::val(true), Expr::val(false)),
        Type::primitive_boolean(),
        vec![
            TypeError::expected_type(
                Expr::val(true),
                Type::primitive_long(),
                Type::singleton_boolean(true),
            ),
            TypeError::expected_type(
                Expr::val(false),
                Type::primitive_long(),
                Type::singleton_boolean(false),
            ),
        ],
    )
}

#[test]
fn not_typechecks() {
    assert_typechecks_empty_schema(Expr::not(Expr::val(true)), Type::singleton_boolean(false));
    assert_typechecks_empty_schema(Expr::not(Expr::val(false)), Type::singleton_boolean(true));
}

#[test]
fn not_typecheck_fails() {
    assert_typecheck_fails_empty_schema(
        Expr::not(Expr::val(1)),
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(1),
            Type::primitive_boolean(),
            Type::primitive_long(),
        )],
    );
}

#[test]
fn if_typechecks() {
    assert_typechecks_empty_schema(
        Expr::ite(Expr::val(true), Expr::val(1), Expr::val(22)),
        Type::primitive_long(),
    );
}

#[test]
fn if_true_ignore_else() {
    assert_typechecks_empty_schema(
        Expr::ite(Expr::val(true), Expr::val(1), Expr::not(Expr::val(22))),
        Type::primitive_long(),
    );
}

#[test]
fn if_false_ignores_then() {
    assert_typechecks_empty_schema(
        Expr::ite(Expr::val(false), Expr::not(Expr::val(1)), Expr::val(22)),
        Type::primitive_long(),
    );
}

#[test]
fn if_no_lub_error() {
    let if_expr = Expr::ite(
        Expr::less(Expr::val(1), Expr::val(2)),
        Expr::val(1),
        Expr::val("test"),
    );
    assert_typecheck_fails_empty_schema_without_type(
        if_expr.clone(),
        vec![TypeError::incompatible_types(
            if_expr,
            vec![Type::primitive_long(), Type::primitive_string()],
        )],
    );
}

#[test]
fn if_typecheck_fails() {
    let if_expr = Expr::ite(Expr::val("fail"), Expr::val(1), Expr::val("test"));
    assert_typecheck_fails_empty_schema_without_type(
        if_expr.clone(),
        vec![
            TypeError::incompatible_types(
                if_expr,
                vec![Type::primitive_long(), Type::primitive_string()],
            ),
            TypeError::expected_type(
                Expr::val("fail"),
                Type::primitive_boolean(),
                Type::primitive_string(),
            ),
        ],
    );
}

#[test]
fn neg_typechecks() {
    let neg_expr = Expr::neg(Expr::val(1));
    assert_typechecks_empty_schema(neg_expr, Type::primitive_long());
}

#[test]
fn neg_typecheck_fails() {
    let neg_expr = Expr::neg(Expr::val("foo"));
    assert_typecheck_fails_empty_schema(
        neg_expr,
        Type::primitive_long(),
        vec![TypeError::expected_type(
            Expr::val("foo"),
            Type::primitive_long(),
            Type::primitive_string(),
        )],
    )
}

#[test]
fn mul_typechecks() {
    let neg_expr = Expr::mul(Expr::val(1), 2);
    assert_typechecks_empty_schema(neg_expr, Type::primitive_long());
}

#[test]
fn mul_typecheck_fails() {
    let neg_expr = Expr::mul(Expr::val("foo"), 2);
    assert_typecheck_fails_empty_schema(
        neg_expr,
        Type::primitive_long(),
        vec![TypeError::expected_type(
            Expr::val("foo"),
            Type::primitive_long(),
            Type::primitive_string(),
        )],
    )
}

#[test]
fn add_sub_typechecks() {
    let add_expr = Expr::add(Expr::val(1), Expr::val(2));
    assert_typechecks_empty_schema(add_expr, Type::primitive_long());
    let sub_expr = Expr::sub(Expr::val(1), Expr::val(2));
    assert_typechecks_empty_schema(sub_expr, Type::primitive_long());
}

#[test]
fn add_sub_typecheck_fails() {
    let add_expr = Expr::add(Expr::val(1), Expr::val("foo"));
    assert_typecheck_fails_empty_schema(
        add_expr,
        Type::primitive_long(),
        vec![TypeError::expected_type(
            Expr::val("foo"),
            Type::primitive_long(),
            Type::primitive_string(),
        )],
    );

    let sub_expr = Expr::sub(Expr::val("bar"), Expr::val(2));
    assert_typecheck_fails_empty_schema(
        sub_expr,
        Type::primitive_long(),
        vec![TypeError::expected_type(
            Expr::val("bar"),
            Type::primitive_long(),
            Type::primitive_string(),
        )],
    );
}
