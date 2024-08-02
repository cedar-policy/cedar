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

use cool_asserts::assert_matches;
use serde_json::json;
use std::collections::HashSet;

use cedar_policy_core::ast::{EntityUID, Expr, ExprBuilder, PolicyID};

use super::test_utils::{empty_schema_file, expr_id_placeholder};
use crate::{json_schema, typecheck::Typechecker, types::Type, ValidationMode};

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
fn assert_expr_has_annotated_ast(e: &Expr, annotated: &Expr<Option<Type>>) {
    let schema = empty_schema_file()
        .try_into()
        .expect("Failed to construct schema.");
    let typechecker = Typechecker::new(
        &schema,
        ValidationMode::default(),
        PolicyID::from_string("0"),
    );
    let mut errs = HashSet::new();
    assert_matches!(typechecker.typecheck_expr(e, &mut errs), crate::typecheck::TypecheckAnswer::TypecheckSuccess { expr_type, .. } => {
        assert_eq!(&expr_type, annotated);
    });
}

#[test]
fn expr_typechecks_with_correct_annotation() {
    assert_expr_has_annotated_ast(
        &Expr::val(1),
        &ExprBuilder::with_data(Some(Type::primitive_long())).val(1),
    );
    assert_expr_has_annotated_ast(
        &Expr::greater(Expr::val(1), Expr::val(0)),
        &ExprBuilder::with_data(Some(Type::primitive_boolean())).greater(
            ExprBuilder::with_data(Some(Type::primitive_long())).val(1),
            ExprBuilder::with_data(Some(Type::primitive_long())).val(0),
        ),
    );
    assert_expr_has_annotated_ast(
        &Expr::less(Expr::val(1), Expr::val(0)),
        &ExprBuilder::with_data(Some(Type::primitive_boolean())).less(
            ExprBuilder::with_data(Some(Type::primitive_long())).val(1),
            ExprBuilder::with_data(Some(Type::primitive_long())).val(0),
        ),
    );
    assert_expr_has_annotated_ast(
        &Expr::and(Expr::greater(Expr::val(1), Expr::val(1)), Expr::val(false)),
        &ExprBuilder::with_data(Some(Type::singleton_boolean(false))).and(
            ExprBuilder::with_data(Some(Type::primitive_boolean())).greater(
                ExprBuilder::with_data(Some(Type::primitive_long())).val(1),
                ExprBuilder::with_data(Some(Type::primitive_long())).val(1),
            ),
            ExprBuilder::with_data(Some(Type::singleton_boolean(false))).val(false),
        ),
    );
    assert_expr_has_annotated_ast(
        &Expr::or(Expr::greater(Expr::val(1), Expr::val(1)), Expr::val(true)),
        &ExprBuilder::with_data(Some(Type::singleton_boolean(true))).or(
            ExprBuilder::with_data(Some(Type::primitive_boolean())).greater(
                ExprBuilder::with_data(Some(Type::primitive_long())).val(1),
                ExprBuilder::with_data(Some(Type::primitive_long())).val(1),
            ),
            ExprBuilder::with_data(Some(Type::singleton_boolean(true))).val(true),
        ),
    );
    assert_expr_has_annotated_ast(
        &Expr::ite(
            Expr::less(Expr::val(1), Expr::val(0)),
            Expr::val("bar"),
            Expr::val("foo"),
        ),
        &ExprBuilder::with_data(Some(Type::primitive_string())).ite(
            ExprBuilder::with_data(Some(Type::primitive_boolean())).less(
                ExprBuilder::with_data(Some(Type::primitive_long())).val(1),
                ExprBuilder::with_data(Some(Type::primitive_long())).val(0),
            ),
            ExprBuilder::with_data(Some(Type::primitive_string())).val("bar"),
            ExprBuilder::with_data(Some(Type::primitive_string())).val("foo"),
        ),
    );
    assert_expr_has_annotated_ast(
        &Expr::not(Expr::val(false)),
        &ExprBuilder::with_data(Some(Type::singleton_boolean(true)))
            .not(ExprBuilder::with_data(Some(Type::singleton_boolean(false))).val(false)),
    );
    assert_expr_has_annotated_ast(
        &Expr::mul(Expr::val(3), Expr::val(4)),
        &ExprBuilder::with_data(Some(Type::primitive_long())).mul(
            ExprBuilder::with_data(Some(Type::primitive_long())).val(3),
            ExprBuilder::with_data(Some(Type::primitive_long())).val(4),
        ),
    );
    assert_expr_has_annotated_ast(
        &Expr::set([Expr::val(1), Expr::val(2), Expr::val(3)]),
        &ExprBuilder::with_data(Some(Type::set(Type::primitive_long()))).set([
            ExprBuilder::with_data(Some(Type::primitive_long())).val(1),
            ExprBuilder::with_data(Some(Type::primitive_long())).val(2),
            ExprBuilder::with_data(Some(Type::primitive_long())).val(3),
        ]),
    );
    assert_expr_has_annotated_ast(
        &Expr::record([
            ("foo".into(), Expr::val(1)),
            ("bar".into(), Expr::val(false)),
        ])
        .unwrap(),
        &ExprBuilder::with_data(Some(Type::closed_record_with_required_attributes([
            ("foo".into(), Type::primitive_long()),
            ("bar".into(), Type::singleton_boolean(false)),
        ])))
        .record([
            (
                "foo".into(),
                ExprBuilder::with_data(Some(Type::primitive_long())).val(1),
            ),
            (
                "bar".into(),
                ExprBuilder::with_data(Some(Type::singleton_boolean(false))).val(false),
            ),
        ])
        .unwrap(),
    );

    let schema = json_schema::Fragment::from_json_value(
        json!({"": { "entityTypes": { "Foo": {} }, "actions": {} }}),
    )
    .unwrap()
    .try_into()
    .expect("Failed to construct schema.");
    let tc = Typechecker::new(&schema, ValidationMode::default(), expr_id_placeholder());
    let mut errs = HashSet::new();
    let euid = EntityUID::with_eid_and_type("Foo", "bar").unwrap();
    match tc.typecheck_expr(&Expr::val(euid.clone()), &mut errs) {
        crate::typecheck::TypecheckAnswer::TypecheckSuccess { expr_type, .. } => {
            assert_eq!(
                &expr_type,
                &ExprBuilder::with_data(Some(Type::named_entity_reference_from_str("Foo")))
                    .val(euid)
            )
        }
        crate::typecheck::TypecheckAnswer::TypecheckFail { .. } => {
            panic!("Typechecking should succeed.")
        }
        crate::typecheck::TypecheckAnswer::RecursionLimit => {
            panic!("Should not have hit recursion limit")
        }
    }
}
