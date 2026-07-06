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

//! Utilities for writing TPE test cases

use std::collections::HashSet;

use crate::{
    ast::{EntityUID, Expr, PolicyID, SlotEnv},
    parser::parse_expr,
    tpe::request::{PartialEntityUID, PartialRequest},
    validator::{typecheck::Typechecker, types::Type, ValidationMode, ValidatorSchema},
};

/// Parse a [`PartialEntityUID`] from a string.
///
/// Accepts either a bare entity type (e.g. `A`), yielding an unknown eid, or
/// a full entity uid (e.g. `A::"foo"`), yielding a concrete eid.
#[track_caller]
pub(crate) fn parse_partial_euid(s: &str) -> PartialEntityUID {
    if let Ok(euid) = s.parse::<EntityUID>() {
        PartialEntityUID::from(euid)
    } else {
        PartialEntityUID {
            ty: s.parse().expect("should parse as an entity type"),
            eid: None,
        }
    }
}

/// Given a expression as a Cedar source string, parse and typecheck it, giving
/// a type annotated expression.
#[track_caller]
pub(crate) fn parse_typed_expr(
    expr_str: &str,
    request: &PartialRequest,
    schema: &ValidatorSchema,
    slot_env: &SlotEnv,
) -> Expr<Option<Type>> {
    let env = request
        .find_request_env(&schema)
        .unwrap()
        .link_slot_env(slot_env);

    let expr = parse_expr(expr_str).unwrap();
    let mut type_errors = HashSet::new();
    let id = PolicyID::from_string("test");
    let ans = Typechecker::new(schema, ValidationMode::Strict).typecheck_expr_with_request_env(
        &env,
        &expr,
        &id,
        &mut type_errors,
    );
    if !type_errors.is_empty() {
        println!("got {} type errors", type_errors.len());
        for e in type_errors {
            println!("{:?}", miette::Report::new(e));
        }
        panic!("unexpected type error in expression")
    }
    ans.into_typed_expr()
        .expect("expected typechecking to produce a typed expression")
}
