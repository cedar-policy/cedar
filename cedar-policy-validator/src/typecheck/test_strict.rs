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

//! Contains test for strict typechecking.
#![cfg(test)]
// GRCOV_STOP_COVERAGE

use serde_json::json;
use std::str::FromStr;

use cedar_policy_core::ast::{EntityType, EntityUID, Expr};

use crate::{
    types::{Attributes, EffectSet, RequestEnv, Type},
    IncompatibleTypes, SchemaFragment, TypeErrorKind, ValidationMode,
};

use super::test_utils::with_typechecker_from_schema;

fn assert_typechecks_strict(
    schema: SchemaFragment,
    env: &RequestEnv,
    e: Expr,
    e_strict: Expr,
    expected_type: Type,
) {
    with_typechecker_from_schema(schema, |mut typechecker| {
        typechecker.mode = ValidationMode::Strict;
        let mut errs = Vec::new();
        let answer = typechecker.expect_type(env, &EffectSet::new(), &e, expected_type, &mut errs);

        assert_eq!(errs, vec![], "Expression should not contain any errors.");
        match answer {
            crate::typecheck::TypecheckAnswer::TypecheckSuccess { expr_type, .. } => {
                assert!(expr_type.eq_shape(&e_strict), "Transformed expression does not have the expected shape. expected: {:?}, actual: {:?}", e_strict, expr_type)
            }
            crate::typecheck::TypecheckAnswer::TypecheckFail { .. } => {
                panic!("Typechecking should have succeeded for expression {:?}", e)
            }
            crate::typecheck::TypecheckAnswer::RecursionLimit => {
                panic!("Should not have hit recursion liimt for: {:?}", e)
            }
        }
    });
}

fn assert_strict_type_error(
    schema: SchemaFragment,
    env: &RequestEnv,
    e: Expr,
    e_strict: Expr,
    expected_type: Type,
    expected_error: TypeErrorKind,
) {
    with_typechecker_from_schema(schema, |mut typechecker| {
        typechecker.mode = ValidationMode::Strict;
        let mut errs = Vec::new();
        let answer = typechecker.expect_type(env, &EffectSet::new(), &e, expected_type, &mut errs);

        assert_eq!(
            errs.into_iter().map(|e| e.kind).collect::<Vec<_>>(),
            vec![expected_error]
        );

        match answer {
            crate::typecheck::TypecheckAnswer::TypecheckFail { expr_recovery_type } => {
                assert!(expr_recovery_type.eq_shape(&e_strict), "Transformed expression does not have the expected shape. expected: {:?}, actual: {:?}", e_strict, expr_recovery_type)
            }
            crate::typecheck::TypecheckAnswer::TypecheckSuccess { .. } => {
                panic!("Typechecking should have failed for expression {:?}", e)
            }
            crate::typecheck::TypecheckAnswer::RecursionLimit => {
                panic!("Should not have hit recursion limit for {:?}", e)
            }
        }
    });
}

fn assert_types_must_match(
    schema: SchemaFragment,
    env: &RequestEnv,
    e: Expr,
    e_strict: Expr,
    expected_type: Type,
    unequal_types: impl IntoIterator<Item = Type>,
) {
    assert_strict_type_error(
        schema,
        env,
        e,
        e_strict,
        expected_type,
        TypeErrorKind::IncompatibleTypes(IncompatibleTypes {
            types: unequal_types.into_iter().collect(),
        }),
    )
}

fn simple_schema_file() -> SchemaFragment {
    serde_json::from_value(json!(
    { "": {
      "entityTypes": {
        "User": {},
        "Photo": {}
      },
      "actions": {
        "view_photo": {
          "appliesTo": {
            "principalTypes": [ "User" ],
            "resourceTypes": [ "Photo" ]
          }
        },
        "delete_photo": {
          "appliesTo": {
            "principalTypes": [ "User" ],
            "resourceTypes": [ "Photo" ]
          }
        }
      }
    }
    }))
    .expect("Expected valid schema")
}

fn with_simple_schema_and_request<F>(f: F)
where
    F: FnOnce(SchemaFragment, RequestEnv),
{
    f(
        simple_schema_file(),
        RequestEnv {
            principal: &EntityType::Concrete("User".parse().unwrap()),
            action: &EntityUID::with_eid_and_type("Action", "view_photo").unwrap(),
            resource: &EntityType::Concrete("Photo".parse().unwrap()),
            context: &Attributes::with_attributes(None),
            principal_slot: None,
            resource_slot: None,
        },
    )
}

#[test]
fn strict_typecheck_catches_regular_type_error() {
    with_simple_schema_and_request(|s, q| {
        with_typechecker_from_schema(s, |mut typechecker| {
            let mut errs = Vec::new();
            typechecker.mode = ValidationMode::Strict;
            typechecker.expect_type(
                &q,
                &EffectSet::new(),
                &Expr::from_str("1 + false").unwrap(),
                Type::primitive_long(),
                &mut errs,
            );

            assert!(errs.len() == 1);
            assert!(matches!(
                errs.get(0).unwrap().kind,
                TypeErrorKind::UnexpectedType(_)
            ));
        })
    })
}

#[test]
fn false_eq_rewrites_to_false() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"principal == Photo::"image.jpg""#).unwrap(),
            Expr::from_str(r#"false"#).unwrap(),
            Type::primitive_boolean(),
        )
    })
}

#[test]
fn true_eq_rewrites_to_true() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"action == Action::"view_photo""#).unwrap(),
            Expr::from_str(r#"true"#).unwrap(),
            Type::primitive_boolean(),
        )
    })
}

#[test]
fn bool_eq_types_match() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"1 == 1"#).unwrap(),
            Expr::from_str(r#"1 == 1"#).unwrap(),
            Type::primitive_boolean(),
        )
    })
}

#[test]
fn eq_strict_types_mismatch() {
    with_simple_schema_and_request(|s, q| {
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"1 == "foo""#).unwrap(),
            Expr::from_str(r#"1 == "foo""#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_string(), Type::primitive_long()],
        )
    })
}

#[test]
fn contains_strict_types_mismatch() {
    with_simple_schema_and_request(|s, q| {
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"[1].contains("test")"#).unwrap(),
            Expr::from_str(r#"[1].contains("test")"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_long(), Type::primitive_string()],
        )
    })
}

#[test]
fn contains_any_strict_types_mismatch() {
    with_simple_schema_and_request(|s, q| {
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"[principal].containsAny([1])"#).unwrap(),
            Expr::from_str(r#"[principal].containsAny([1])"#).unwrap(),
            Type::primitive_boolean(),
            [
                Type::set(Type::named_entity_reference_from_str("User")),
                Type::set(Type::primitive_long()),
            ],
        )
    })
}

#[test]
fn contains_all_strict_types_mismatch() {
    with_simple_schema_and_request(|s, q| {
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"[principal].containsAll([1])"#).unwrap(),
            Expr::from_str(r#"[principal].containsAll([1])"#).unwrap(),
            Type::primitive_boolean(),
            [
                Type::set(Type::named_entity_reference_from_str("User")),
                Type::set(Type::primitive_long()),
            ],
        )
    })
}

#[test]
fn if_false_else_only() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"if resource == User::"alice" then 1 else "foo""#).unwrap(),
            Expr::from_str(r#""foo""#).unwrap(),
            Type::primitive_string(),
        )
    })
}

#[test]
fn if_true_then_only() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"if action == Action::"view_photo" then 1 else "foo""#).unwrap(),
            Expr::from_str(r#"1"#).unwrap(),
            Type::primitive_long(),
        )
    })
}

#[test]
fn if_bool_keeps_both() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"if principal == User::"alice" then 1 else 2"#).unwrap(),
            Expr::from_str(r#"if principal == User::"alice" then 1 else 2"#).unwrap(),
            Type::primitive_long(),
        )
    })
}

#[test]
fn if_bool_strict_type_mismatch() {
    with_simple_schema_and_request(|s, q| {
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(
                r#"if principal == User::"alice" then User::"alice" else Photo::"pie.jpg""#,
            )
            .unwrap(),
            Expr::from_str(
                r#"if principal == User::"alice" then User::"alice" else Photo::"pie.jpg""#,
            )
            .unwrap(),
            Type::any_entity_reference(),
            [
                Type::named_entity_reference_from_str("User"),
                Type::named_entity_reference_from_str("Photo"),
            ],
        )
    })
}

#[test]
fn set_strict_types_mismatch() {
    with_simple_schema_and_request(|s, q| {
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"[User::"alice", Photo::"foo.jpg"]"#).unwrap(),
            Expr::from_str(r#"[User::"alice", Photo::"foo.jpg"]"#).unwrap(),
            Type::set(Type::entity_lub(["User", "Photo"])),
            [
                Type::named_entity_reference_from_str("User"),
                Type::named_entity_reference_from_str("Photo"),
            ],
        )
    })
}

#[test]
fn empty_set_literal() {
    with_simple_schema_and_request(|s, q| {
        assert_strict_type_error(
            s,
            &q,
            Expr::from_str(r#"[]"#).unwrap(),
            Expr::from_str(r#"[]"#).unwrap(),
            Type::any_set(),
            TypeErrorKind::EmptySetForbidden,
        )
    })
}

#[cfg(feature = "ipaddr")]
#[test]
fn ext_struct_non_lit() {
    with_simple_schema_and_request(|s, q| {
        assert_strict_type_error(
            s,
            &q,
            Expr::from_str(r#"ip(if 1 > 0 then "a" else "b")"#).unwrap(),
            Expr::from_str(r#"ip(if 1 > 0 then "a" else "b")"#).unwrap(),
            Type::extension("ipaddr".parse().unwrap()),
            TypeErrorKind::NonLitExtConstructor,
        )
    });

    #[cfg(feature = "decimal")]
    with_simple_schema_and_request(|s, q| {
        assert_strict_type_error(
            s,
            &q,
            Expr::from_str(r#"decimal(if 1 > 0 then "0.1" else "1.0")"#).unwrap(),
            Expr::from_str(r#"decimal(if 1 > 0 then "0.1" else "1.0")"#).unwrap(),
            Type::extension("decimal".parse().unwrap()),
            TypeErrorKind::NonLitExtConstructor,
        )
    })
}

#[test]
fn entity_in_lub() {
    // This test demonstrates that the the type of an expression after strict
    // transformation may be an EntityLub if the expression failed to validate.
    // A previous revision panicked when this happened.
    with_simple_schema_and_request(|s, q| {
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(
                r#"User::"alice" in (if 1 > 0 then User::"alice" else Photo::"pie.jpg")"#,
            )
            .unwrap(),
            Expr::from_str(
                r#"User::"alice" in (if 1 > 0 then User::"alice" else Photo::"pie.jpg")"#,
            )
            .unwrap(),
            Type::primitive_boolean(),
            [
                Type::named_entity_reference_from_str("User"),
                Type::named_entity_reference_from_str("Photo"),
            ],
        )
    });
}

// The remaining are less interesting. They just check that the AST is
// reconstructed properly in cases where no changes are made and that strict
// typing errors are detected when nested inside all AST nodes.

#[test]
fn test_and() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s.clone(),
            &q,
            Expr::from_str(r#"1 == 2 && 2 == 3"#).unwrap(),
            Expr::from_str(r#"1 == 2 && 2 == 3"#).unwrap(),
            Type::primitive_boolean(),
        );
        assert_types_must_match(
            s.clone(),
            &q,
            Expr::from_str(r#"(1 == (2 > 0)) && true"#).unwrap(),
            Expr::from_str(r#"(1 == (2 > 0)) && true"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_long(), Type::primitive_boolean()],
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"true && (1 == (2 > 0))"#).unwrap(),
            Expr::from_str(r#"true && (1 == (2 > 0))"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_long(), Type::primitive_boolean()],
        );
    })
}

#[test]
fn test_or() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s.clone(),
            &q,
            Expr::from_str(r#"1 == 2 || 2 == 3"#).unwrap(),
            Expr::from_str(r#"1 == 2 || 2 == 3"#).unwrap(),
            Type::primitive_boolean(),
        );
        assert_types_must_match(
            s.clone(),
            &q,
            Expr::from_str(r#"(1 == (2 > 0)) || false"#).unwrap(),
            Expr::from_str(r#"(1 == (2 > 0)) || false"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_boolean(), Type::primitive_long()],
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"false || (1 == (2 > 0))"#).unwrap(),
            Expr::from_str(r#"false || (1 == (2 > 0))"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_boolean(), Type::primitive_long()],
        );
    })
}

#[test]
fn test_unary() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s.clone(),
            &q,
            Expr::from_str(r#"!(1 == 2)"#).unwrap(),
            Expr::from_str(r#"!(1 == 2)"#).unwrap(),
            Type::primitive_boolean(),
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"!(1 == "foo")"#).unwrap(),
            Expr::from_str(r#"!(1 == "foo")"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_long(), Type::primitive_string()],
        );
    })
}

#[test]
fn test_mul() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s.clone(),
            &q,
            Expr::from_str(r#"2*(if 1 == 2 then 3 else 4)"#).unwrap(),
            Expr::from_str(r#"2*(if 1 == 2 then 3 else 4)"#).unwrap(),
            Type::primitive_long(),
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"2*(if 1 == false then 3 else 4)"#).unwrap(),
            Expr::from_str(r#"2*(if 1 == false then 3 else 4)"#).unwrap(),
            Type::primitive_long(),
            [Type::primitive_long(), Type::singleton_boolean(false)],
        );
    })
}

#[test]
fn test_like() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s.clone(),
            &q,
            Expr::from_str(r#""a" like "a""#).unwrap(),
            Expr::from_str(r#""a" like "a""#).unwrap(),
            Type::primitive_boolean(),
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"(if 1 == false then "foo" else "bar") like "bar""#).unwrap(),
            Expr::from_str(r#"(if 1 == false then "foo" else "bar") like "bar""#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_long(), Type::singleton_boolean(false)],
        );
    })
}

#[test]
fn test_get_attr() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s.clone(),
            &q,
            Expr::from_str(r#"{name: "foo"}.name"#).unwrap(),
            Expr::from_str(r#"{name: "foo"}.name"#).unwrap(),
            Type::primitive_string(),
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"{name: 1 == "foo"}.name"#).unwrap(),
            Expr::from_str(r#"{name: 1 == "foo"}.name"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_long(), Type::primitive_string()],
        );
    })
}

#[test]
fn test_has_attr() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s.clone(),
            &q,
            Expr::from_str(r#"{name: "foo"} has bar"#).unwrap(),
            Expr::from_str(r#"{name: "foo"} has bar"#).unwrap(),
            Type::primitive_boolean(),
        );
        assert_typechecks_strict(
            s.clone(),
            &q,
            Expr::from_str(r#"{name: "foo"} has name"#).unwrap(),
            Expr::from_str(r#"{name: "foo"} has name"#).unwrap(),
            Type::primitive_boolean(),
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"(if 1 == 2 then {name: 1} else {bar: 2}) has bar"#).unwrap(),
            Expr::from_str(r#"(if 1 == 2 then {name: 1} else {bar: 2}) has bar"#).unwrap(),
            Type::primitive_boolean(),
            [
                Type::closed_record_with_required_attributes([(
                    "name".into(),
                    Type::primitive_long(),
                )]),
                Type::closed_record_with_required_attributes([(
                    "bar".into(),
                    Type::primitive_long(),
                )]),
            ],
        );
    })
}

#[test]
#[cfg(feature = "ipaddr")]
fn test_extension() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s.clone(),
            &q,
            Expr::from_str(r#"ip("127.0.0.1")"#).unwrap(),
            Expr::from_str(r#"ip("127.0.0.1")"#).unwrap(),
            Type::extension("ipaddr".parse().unwrap()),
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"ip("192.168.1.0/8").isInRange(if 1 == false then ip("127.0.0.1") else ip("192.168.1.1"))"#).unwrap(),
            Expr::from_str(r#"ip("192.168.1.0/8").isInRange(if 1 == false then ip("127.0.0.1") else ip("192.168.1.1"))"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_long(), Type::singleton_boolean(false)]
        );
    })
}

#[test]
fn true_false_equality() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"[false] == [true, true]"#).unwrap(),
            Expr::from_str(r#"[false] == [true, true]"#).unwrap(),
            Type::primitive_boolean(),
        )
    });
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"[true].contains(false)"#).unwrap(),
            Expr::from_str(r#"[true].contains(false)"#).unwrap(),
            Type::primitive_boolean(),
        )
    })
}

#[test]
fn true_false_set() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"[true, false]"#).unwrap(),
            Expr::from_str(r#"[true, false]"#).unwrap(),
            Type::set(Type::primitive_boolean()),
        )
    });
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"[[true], [false]]"#).unwrap(),
            Expr::from_str(r#"[[true], [false]]"#).unwrap(),
            Type::set(Type::set(Type::primitive_boolean())),
        )
    });
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"[[[true, false], [true, true]], [[false, false]]]"#).unwrap(),
            Expr::from_str(r#"[[[true, false], [true, true]], [[false, false]]]"#).unwrap(),
            Type::set(Type::set(Type::set(Type::primitive_boolean()))),
        )
    })
}
