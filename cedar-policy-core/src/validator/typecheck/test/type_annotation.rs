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
use itertools::Itertools;
use serde_json::json;
use similar_asserts::assert_eq;
use std::{collections::HashSet, sync::Arc};

use crate::{
    ast::{EntityUID, Expr, ExprBuilder, Policy, PolicyID, Template},
    expr_builder::ExprBuilder as _,
    extensions::Extensions,
    parser::parse_policy,
    validator::{
        json_schema,
        typecheck::{PolicyCheck, TypecheckAnswer, Typechecker},
        types::Type,
        ValidationMode, ValidatorSchema,
    },
};

use super::test_utils::{empty_schema_file, expr_id_placeholder};

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
fn assert_expr_has_annotated_ast(e: &Expr, annotated: &Expr<Option<Type>>) {
    let schema = empty_schema_file()
        .try_into()
        .expect("Failed to construct schema.");
    let typechecker = Typechecker::new(&schema, ValidationMode::default());
    let mut errs = HashSet::new();
    assert_matches!(typechecker.typecheck_expr(e, &PolicyID::from_string("0"), &mut errs), TypecheckAnswer::TypecheckSuccess { expr_type, .. } => {
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
        &Expr::and(Expr::val(false), Expr::val(1)),
        &ExprBuilder::with_data(Some(Type::singleton_boolean(false))).and(
            ExprBuilder::with_data(Some(Type::singleton_boolean(false))).val(false),
            // Doesn't contain `1` because we didn't typecheck this side
            ExprBuilder::new().val(true),
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
        &Expr::or(Expr::val(true), Expr::val(1)),
        &ExprBuilder::with_data(Some(Type::singleton_boolean(true))).or(
            ExprBuilder::with_data(Some(Type::singleton_boolean(true))).val(true),
            // Doesn't contain `1` because we didn't typecheck this side
            ExprBuilder::new().val(true),
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
        &Expr::ite(Expr::val(true), Expr::val("bar"), Expr::val("foo")),
        &ExprBuilder::with_data(Some(Type::primitive_string())).ite(
            ExprBuilder::with_data(Some(Type::True)).val(true),
            ExprBuilder::with_data(Some(Type::primitive_string())).val("bar"),
            // Contains `bar` instead of `foo` because we didn't typecheck the `else` branch
            ExprBuilder::with_data(Some(Type::primitive_string())).val("bar"),
        ),
    );
    assert_expr_has_annotated_ast(
        &Expr::ite(Expr::val(false), Expr::val("bar"), Expr::val("foo")),
        &ExprBuilder::with_data(Some(Type::primitive_string())).ite(
            ExprBuilder::with_data(Some(Type::False)).val(false),
            // Contains `foo` instead of `bar` because we didn't typecheck the `else` branch
            ExprBuilder::with_data(Some(Type::primitive_string())).val("foo"),
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
        &ExprBuilder::with_data(Some(Type::set(Type::primitive_long().into()))).set([
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
            ("foo".into(), Type::primitive_long().into()),
            ("bar".into(), Type::singleton_boolean(false).into()),
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
    let tc = Typechecker::new(&schema, ValidationMode::default());
    let mut errs = HashSet::new();
    let euid = EntityUID::with_eid_and_type("Foo", "bar").unwrap();
    match tc.typecheck_expr(&Expr::val(euid.clone()), &expr_id_placeholder(), &mut errs) {
        crate::validator::typecheck::TypecheckAnswer::TypecheckSuccess { expr_type, .. } => {
            assert_eq!(
                &expr_type,
                &ExprBuilder::with_data(Some(Type::named_entity_reference_from_str("Foo")))
                    .val(euid)
            )
        }
        crate::validator::typecheck::TypecheckAnswer::TypecheckFail { .. } => {
            panic!("Typechecking should succeed.")
        }
        crate::validator::typecheck::TypecheckAnswer::RecursionLimit => {
            panic!("Should not have hit recursion limit")
        }
        #[cfg(feature = "tolerant-ast")]
        crate::validator::typecheck::TypecheckAnswer::ErrorAstNode => {
            panic!("Should not type check an AST with an error node")
        }
    }
}

// we discovered this input that is not idempotent when being typechecked twice
#[test]
fn non_idempotent() {
    let (schema, _) = ValidatorSchema::from_cedarschema_str(
        r#"
        entity a tags Set<__cedar::ipaddr>;

        action "action" appliesTo {
        principal: [a],
        resource: [a],
        context: {}
        };
    "#,
        Extensions::all_available(),
    )
    .unwrap();
    let policy = parse_policy(
        None,
        r#"
    permit(
        principal,
        action in [Action::"action"],
        resource is a
    ) when {
        ((true && (if (
            if (if true then true else true)
            then (if true then true else true)
            else (if true then false else true)
        )
            then (a::"".hasTag(if true then "" else ""))
            else (
                if (if true then true else true)
                then (if true then true else false)
                else false
            )
        )) && (
            if (a::"".hasTag(if true then "" else ")"))
            then (
                if (if true then true else true)
                then (if true then true else false)
                else true
            )
            else (principal in a::"")
        )) && (a::"".hasTag(""))
    };
    "#,
    )
    .unwrap();
    let typechecker = Typechecker::new(&schema, ValidationMode::Strict);
    let req_env = schema
        .unlinked_request_envs(ValidationMode::Strict)
        .exactly_one()
        .unwrap_or_else(|e| panic!("expected exactly one request env: {e}"));
    let template: Arc<Template> = policy.into();

    assert_matches!(typechecker.typecheck_by_single_request_env(&template, &req_env), PolicyCheck::Success(transformed) => {
        // after typechecking, the policy is transformed into this:
        assert_eq!(transformed.to_string(), r#"true && ((action in [Action::"action"]) && ((resource is a) && (((true && (if (if (if true then true else true) then (if true then true else true) else (if true then true else true)) then (a::"".hasTag(if true then "" else "")) else (a::"".hasTag(if true then "" else "")))) && (if (a::"".hasTag(if true then "" else "")) then (if (if true then true else true) then (if true then true else true) else (if true then true else true)) else (principal in a::""))) && (a::"".hasTag("")))))"#);
        // in particular, note that it still contains the `principal in a::""` term
        assert!(transformed.to_string().contains(r#"principal in a::"""#));

        // now we typecheck the transformed policy:
        let transformed = Policy::from_when_clause(
            template.effect(),
            transformed.into_expr::<ExprBuilder<()>>(),
            template.id().clone(),
            template.loc().cloned(),
        );
        assert_matches!(typechecker.typecheck_by_single_request_env(&transformed.template(), &req_env), PolicyCheck::Success(retransformed) => {
            // after re-typechecking, the policy is transformed into this:
            assert_eq!(retransformed.to_string(), r#"true && (true && (true && (true && ((action in [Action::"action"]) && ((resource is a) && (((true && (if (if (if true then true else true) then (if true then true else true) else (if true then true else true)) then (a::"".hasTag(if true then "" else "")) else (a::"".hasTag(if true then "" else "")))) && (if (a::"".hasTag(if true then "" else "")) then (if (if true then true else true) then (if true then true else true) else (if true then true else true)) else (if (if true then true else true) then (if true then true else true) else (if true then true else true)))) && (a::"".hasTag(""))))))))"#);
            // in particular, note that it no longer contains the `principal in a::""` term
            assert!(!retransformed.to_string().contains(r#"principal in a::"""#));
        });
    });
}
