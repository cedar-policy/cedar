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

//! Contains test for strict typechecking.
// GRCOV_STOP_COVERAGE

use cool_asserts::assert_matches;
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;

use cedar_policy_core::{
    ast::{EntityUID, Expr, PolicyID},
    extensions::Extensions,
    parser::{parse_policy_template, Loc},
};

use crate::{
    typecheck::Typechecker,
    types::{AttributeType, EffectSet, OpenTag, RequestEnv, Type},
    validation_errors::LubContext,
    validation_errors::LubHelp,
    RawName, SchemaFragment, ValidationError, ValidationMode,
};

use super::test_utils::{assert_policy_typecheck_fails, expr_id_placeholder};

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
fn assert_typechecks_strict(
    schema: SchemaFragment<RawName>,
    env: &RequestEnv<'_>,
    e: Expr,
    expected_type: Type,
) {
    let schema = schema.try_into().expect("Failed to construct schema.");
    let typechecker = Typechecker::new(&schema, ValidationMode::Strict, expr_id_placeholder());
    let mut errs = Vec::new();
    let answer =
        typechecker.expect_type(env, &EffectSet::new(), &e, expected_type, &mut errs, |_| {
            None
        });

    assert_eq!(errs, vec![], "Expression should not contain any errors.");
    assert_matches!(
        answer,
        crate::typecheck::TypecheckAnswer::TypecheckSuccess { .. }
    );
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
fn assert_strict_type_error(
    schema: SchemaFragment<RawName>,
    env: &RequestEnv<'_>,
    e: Expr,
    expected_type: Type,
    expected_error: ValidationError,
) {
    let schema = schema.try_into().expect("Failed to construct schema.");
    let typechecker = Typechecker::new(&schema, ValidationMode::Strict, expr_id_placeholder());
    let mut errs = Vec::new();
    let answer =
        typechecker.expect_type(env, &EffectSet::new(), &e, expected_type, &mut errs, |_| {
            None
        });

    assert_eq!(errs.into_iter().collect::<Vec<_>>(), vec![expected_error]);
    assert_matches!(
        answer,
        crate::typecheck::TypecheckAnswer::TypecheckFail { .. }
    );
}

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
fn assert_types_must_match(
    schema: SchemaFragment<RawName>,
    env: &RequestEnv<'_>,
    e: Expr,
    on_expr: Expr,
    expected_type: Type,
    unequal_types: impl IntoIterator<Item = Type>,
    hint: LubHelp,
    context: LubContext,
) {
    assert_strict_type_error(
        schema,
        env,
        e,
        expected_type,
        ValidationError::incompatible_types(
            on_expr,
            expr_id_placeholder(),
            unequal_types,
            hint,
            context,
        ),
    )
}

fn simple_schema_file() -> SchemaFragment<RawName> {
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
    F: FnOnce(SchemaFragment<RawName>, RequestEnv<'_>),
{
    f(
        simple_schema_file(),
        RequestEnv::DeclaredAction {
            principal: &"User".parse().unwrap(),
            action: &EntityUID::with_eid_and_type("Action", "view_photo").unwrap(),
            resource: &"Photo".parse().unwrap(),
            context: &Type::record_with_attributes(None, OpenTag::ClosedAttributes),
            principal_slot: None,
            resource_slot: None,
        },
    )
}

#[test]
fn strict_typecheck_catches_regular_type_error() {
    with_simple_schema_and_request(|s, q| {
        let schema = s.try_into().expect("Failed to construct schema.");
        let typechecker = Typechecker::new(&schema, ValidationMode::Strict, expr_id_placeholder());
        let mut errs = Vec::new();
        typechecker.expect_type(
            &q,
            &EffectSet::new(),
            &Expr::from_str("1 + false").unwrap(),
            Type::primitive_long(),
            &mut errs,
            |_| None,
        );

        assert!(errs.len() == 1);
        assert!(matches!(
            errs.first().unwrap(),
            ValidationError::UnexpectedType(_)
        ));
    })
}

#[test]
fn false_eq_rewrites_to_false() {
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"principal == Photo::"image.jpg""#).unwrap(),
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
            LubHelp::None,
            LubContext::Equality,
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
            LubHelp::None,
            LubContext::Contains,
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
            LubHelp::None,
            LubContext::ContainsAnyAll,
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
            LubHelp::None,
            LubContext::ContainsAnyAll,
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
            LubHelp::EntityType,
            LubContext::Conditional,
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
            LubHelp::EntityType,
            LubContext::Set,
        )
    })
}

#[test]
fn empty_set_literal() {
    with_simple_schema_and_request(|s, q| {
        let src = r#"[]"#;
        assert_strict_type_error(
            s,
            &q,
            Expr::from_str(src).unwrap(),
            Type::any_set(),
            ValidationError::empty_set_forbidden(
                Some(Loc::new(0..2, Arc::from(src))),
                expr_id_placeholder(),
            ),
        )
    })
}

#[cfg(feature = "ipaddr")]
#[test]
fn ext_struct_non_lit() {
    with_simple_schema_and_request(|s, q| {
        let src = r#"ip(if 1 > 0 then "a" else "b")"#;
        assert_strict_type_error(
            s,
            &q,
            Expr::from_str(src).unwrap(),
            Type::extension("ipaddr".parse().unwrap()),
            ValidationError::non_lit_ext_constructor(
                Some(Loc::new(0..30, Arc::from(src))),
                expr_id_placeholder(),
            ),
        )
    });

    #[cfg(feature = "decimal")]
    with_simple_schema_and_request(|s, q| {
        let src = r#"decimal(if 1 > 0 then "0.1" else "1.0")"#;
        assert_strict_type_error(
            s,
            &q,
            Expr::from_str(src).unwrap(),
            Type::extension("decimal".parse().unwrap()),
            ValidationError::non_lit_ext_constructor(
                Some(Loc::new(0..39, Arc::from(src))),
                expr_id_placeholder(),
            ),
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
            Expr::from_str(r#"if 1 > 0 then User::"alice" else Photo::"pie.jpg""#).unwrap(),
            Type::primitive_boolean(),
            [
                Type::named_entity_reference_from_str("User"),
                Type::named_entity_reference_from_str("Photo"),
            ],
            LubHelp::EntityType,
            LubContext::Conditional,
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
            Type::primitive_boolean(),
        );
        assert_types_must_match(
            s.clone(),
            &q,
            Expr::from_str(r#"(1 == (2 > 0)) && true"#).unwrap(),
            Expr::from_str(r#"1 == (2 > 0)"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_long(), Type::primitive_boolean()],
            LubHelp::None,
            LubContext::Equality,
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"true && (1 == (2 > 0))"#).unwrap(),
            Expr::from_str(r#"1 == (2 > 0)"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_long(), Type::primitive_boolean()],
            LubHelp::None,
            LubContext::Equality,
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
            Type::primitive_boolean(),
        );
        assert_types_must_match(
            s.clone(),
            &q,
            Expr::from_str(r#"(1 == (2 > 0)) || false"#).unwrap(),
            Expr::from_str(r#"1 == (2 > 0)"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_boolean(), Type::primitive_long()],
            LubHelp::None,
            LubContext::Equality,
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"false || (1 == (2 > 0))"#).unwrap(),
            Expr::from_str(r#"1 == (2 > 0)"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_boolean(), Type::primitive_long()],
            LubHelp::None,
            LubContext::Equality,
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
            Type::primitive_boolean(),
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"!(1 == "foo")"#).unwrap(),
            Expr::from_str(r#"1 == "foo""#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_long(), Type::primitive_string()],
            LubHelp::None,
            LubContext::Equality,
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
            Type::primitive_long(),
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"2*(if 1 == false then 3 else 4)"#).unwrap(),
            Expr::from_str(r#"1 == false"#).unwrap(),
            Type::primitive_long(),
            [Type::primitive_long(), Type::singleton_boolean(false)],
            LubHelp::None,
            LubContext::Equality,
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
            Type::primitive_boolean(),
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"(if 1 == false then "foo" else "bar") like "bar""#).unwrap(),
            Expr::from_str(r#"1 == false"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_long(), Type::singleton_boolean(false)],
            LubHelp::None,
            LubContext::Equality,
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
            Type::primitive_string(),
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"{name: 1 == "foo"}.name"#).unwrap(),
            Expr::from_str(r#"1 == "foo""#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_long(), Type::primitive_string()],
            LubHelp::None,
            LubContext::Equality,
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
            Type::primitive_boolean(),
        );
        assert_typechecks_strict(
            s.clone(),
            &q,
            Expr::from_str(r#"{name: "foo"} has name"#).unwrap(),
            Type::primitive_boolean(),
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"(if 1 == 2 then {name: 1} else {bar: 2}) has bar"#).unwrap(),
            Expr::from_str("if 1 == 2 then {name: 1} else {bar: 2}").unwrap(),
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
            LubHelp::RecordWidth,
            LubContext::Conditional,
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
            Type::extension("ipaddr".parse().unwrap()),
        );
        assert_types_must_match(
            s,
            &q,
            Expr::from_str(r#"ip("192.168.1.0/8").isInRange(if 1 == false then ip("127.0.0.1") else ip("192.168.1.1"))"#).unwrap(),
            Expr::from_str(r#"1 == false"#).unwrap(),
            Type::primitive_boolean(),
            [Type::primitive_long(), Type::singleton_boolean(false)],
            LubHelp::None,
            LubContext::Equality,
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
            Type::primitive_boolean(),
        )
    });
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
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
            Type::set(Type::primitive_boolean()),
        )
    });
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"[[true], [false]]"#).unwrap(),
            Type::set(Type::set(Type::primitive_boolean())),
        )
    });
    with_simple_schema_and_request(|s, q| {
        assert_typechecks_strict(
            s,
            &q,
            Expr::from_str(r#"[[[true, false], [true, true]], [[false, false]]]"#).unwrap(),
            Type::set(Type::set(Type::set(Type::primitive_boolean()))),
        )
    })
}

#[test]
fn qualified_record_attr() {
    let (schema, _) = SchemaFragment::from_str_natural(
        r#"
        entity Foo;
        action A appliesTo { context: {num_of_things?: Long }, principal : [Foo], resource : [Foo] };"#,
        Extensions::all_available(),
    )
    .unwrap();
    let p = parse_policy_template(
        None,
        "permit(principal, action, resource) when { context == {num_of_things: 1}};",
    )
    .unwrap();
    assert_policy_typecheck_fails(
        schema,
        p.clone(),
        vec![ValidationError::incompatible_types(
            "context == {num_of_things: 1}".parse().unwrap(),
            PolicyID::from_string("policy0"),
            [
                Type::record_with_attributes(
                    [(
                        "num_of_things".into(),
                        AttributeType::new(Type::primitive_long(), false),
                    )],
                    OpenTag::ClosedAttributes,
                ),
                Type::record_with_attributes(
                    [(
                        "num_of_things".into(),
                        AttributeType::new(Type::primitive_long(), true),
                    )],
                    OpenTag::ClosedAttributes,
                ),
            ],
            LubHelp::AttributeQualifier,
            LubContext::Equality,
        )],
    );
}
