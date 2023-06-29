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

#![cfg(test)]

use std::collections::HashSet;

use cedar_policy_core::ast::{EntityUID, Expr, ExprBuilder};

use crate::{types::Type, SchemaFragment};

use serde_json::json;

use super::test_utils::{empty_schema_file, with_typechecker_from_schema};

fn assert_expr_has_annotated_ast(e: &Expr, annotated: &Expr<Option<Type>>) {
    with_typechecker_from_schema(empty_schema_file(), |tc| {
        let mut errs = HashSet::new();
        match tc.typecheck_expr(e, &mut errs) {
            super::TypecheckAnswer::TypecheckSuccess { expr_type, .. } => {
                assert_eq!(&expr_type, annotated)
            }
            super::TypecheckAnswer::TypecheckFail { .. } => panic!("Typechecking should succeed."),
            super::TypecheckAnswer::RecursionLimit => panic!("Should not have hit recursion limit"),
        }
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
        &Expr::mul(Expr::val(3), 4),
        &ExprBuilder::with_data(Some(Type::primitive_long())).mul(
            ExprBuilder::with_data(Some(Type::primitive_long())).val(3),
            4,
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
        ]),
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
        ]),
    );
    with_typechecker_from_schema(
        serde_json::from_value::<SchemaFragment>(
            json!({"": { "entityTypes": { "Foo": {} }, "actions": {} }}),
        )
        .unwrap(),
        |tc| {
            let mut errs = HashSet::new();
            let euid = EntityUID::with_eid_and_type("Foo", "bar").unwrap();
            match tc.typecheck_expr(&Expr::val(euid.clone()), &mut errs) {
                super::TypecheckAnswer::TypecheckSuccess { expr_type, .. } => {
                    assert_eq!(
                        &expr_type,
                        &ExprBuilder::with_data(Some(Type::named_entity_reference_from_str("Foo")))
                            .val(euid)
                    )
                }
                super::TypecheckAnswer::TypecheckFail { .. } => {
                    panic!("Typechecking should succeed.")
                }
                super::TypecheckAnswer::RecursionLimit => {
                    panic!("Should not have hit recursion limit")
                }
            }
        },
    );
}
