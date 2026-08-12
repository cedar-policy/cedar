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
use std::sync::Arc;

use crate::{
    ast::{Eid, EntityUID, Expr, Literal, PolicyID, SlotEnv},
    parser::{parse_expr, parse_policyset},
    tpe::entities::{PartialEntities, PartialEntity},
    tpe::request::{PartialEntityUID, PartialRequest},
    tpe::residual::Residual,
    tpe::value::{PartialAttribute, PartialRecord, PartialValue},
    validator::{typecheck::Typechecker, types::Type, ValidationMode, ValidatorSchema},
};
use smol_str::SmolStr;

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

    let expr = match parse_expr(expr_str) {
        Ok(expr) => expr,
        Err(es) => {
            for e in es {
                println!("{:?}", miette::Report::new(e));
            }
            panic!("parse error on input expression");
        }
    };
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

/// Parse a Cedar-schema source string into a [`ValidatorSchema`], panicking on
/// error. Convenience for tests that only need the schema, not its warnings.
#[track_caller]
pub(crate) fn parse_schema(src: &str) -> ValidatorSchema {
    ValidatorSchema::from_cedarschema_str(src, crate::extensions::Extensions::all_available())
        .unwrap()
        .0
}

/// Build an [`EntityUID`] from a type and id.
pub(crate) fn uid(ty: &str, id: &str) -> EntityUID {
    EntityUID::from_components(ty.parse().unwrap(), Eid::new(id), None)
}

/// Build a [`PartialRequest`] with an empty concrete context, validated against
/// `schema`. `principal` and `resource` accept anything [`parse_partial_euid`] does.
#[track_caller]
pub(crate) fn request(
    principal: &str,
    action_id: &str,
    resource: &str,
    schema: &ValidatorSchema,
) -> PartialRequest {
    request_with_context(
        principal,
        action_id,
        resource,
        Some(PartialRecord::new()),
        schema,
    )
}

/// As [`request`], but with the given context.
#[track_caller]
pub(crate) fn request_with_context(
    principal: &str,
    action_id: &str,
    resource: &str,
    context: Option<PartialRecord>,
    schema: &ValidatorSchema,
) -> PartialRequest {
    PartialRequest::new(
        parse_partial_euid(principal),
        uid("Action", action_id),
        parse_partial_euid(resource),
        context,
        schema,
    )
    .expect("request should conform to the schema")
}

/// Build a [`PartialEntity`] with known (empty) ancestors.
pub(crate) fn entity(
    ty: &str,
    id: &str,
    attrs: Option<PartialRecord>,
    tags: Option<PartialRecord>,
) -> PartialEntity {
    PartialEntity {
        uid: uid(ty, id),
        attrs,
        ancestors: Some(HashSet::new()),
        tags,
    }
}

/// A [`PartialEntity`] with fully-known, empty attrs and tags.
pub(crate) fn empty_entity(ty: &str, id: &str) -> PartialEntity {
    entity(
        ty,
        id,
        Some(PartialRecord::new()),
        Some(PartialRecord::new()),
    )
}

fn to_cedar(r: &Residual) -> String {
    let expr: crate::ast::Expr = r.clone().into();
    expr.to_string()
}

/// Partially evaluate `policy` and pretty-print the residual as Cedar text.
#[track_caller]
pub(crate) fn eval_to_cedar(
    schema: &ValidatorSchema,
    req: &PartialRequest,
    entities: impl IntoIterator<Item = PartialEntity>,
    policy: &str,
) -> String {
    let policies = parse_policyset(policy).unwrap();
    let ents = PartialEntities::from_entities(entities.into_iter(), schema).unwrap();
    let response = crate::tpe::is_authorized(&policies, req, &ents, schema).unwrap();
    let id = policies.static_policies().next().unwrap().id().clone();
    to_cedar(
        response
            .get_residual_policy(&id)
            .unwrap()
            .get_residual()
            .as_ref(),
    )
}

/// Wrap a condition in a `permit` policy with id `p`.
pub(crate) fn permit_when(cond: &str) -> String {
    format!(r#"@id("p") permit(principal, action, resource) when {{ {cond} }};"#)
}

/// A known-value literal attribute (`PartialAttribute::Value`).
pub(crate) fn present(v: impl Into<Literal>) -> PartialAttribute {
    PartialAttribute::Value(PartialValue::Lit(v.into()))
}

/// A known-value entity-uid attribute (`PartialAttribute::Value`).
pub(crate) fn present_uid(ty: &str, id: &str) -> PartialAttribute {
    PartialAttribute::Value(PartialValue::Lit(Literal::EntityUID(Arc::new(uid(ty, id)))))
}

/// A known-value record attribute (`PartialAttribute::Value`).
pub(crate) fn record(
    fields: impl IntoIterator<Item = (impl Into<SmolStr>, PartialAttribute)>,
) -> PartialAttribute {
    PartialAttribute::Value(PartialValue::Record(rec(fields)))
}

/// A [`PartialRecord`] from (key, attribute) pairs.
pub(crate) fn rec(
    fields: impl IntoIterator<Item = (impl Into<SmolStr>, PartialAttribute)>,
) -> PartialRecord {
    PartialRecord::from_attrs(fields.into_iter().map(|(k, v)| (k.into(), v)))
}
