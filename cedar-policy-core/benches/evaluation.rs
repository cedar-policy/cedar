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

#![allow(clippy::unwrap_used, reason = "benchmarking")]

use cedar_policy_core::ast::{
    Context, Entity, EntityUID, Expr, RestrictedExpr, Request, RequestSchemaAllPass, Var,
};
use cedar_policy_core::entities::{Entities, NoEntitiesSchema, TCComputation};
use cedar_policy_core::evaluator::Evaluator;
use cedar_policy_core::extensions::Extensions;
use criterion::{criterion_group, criterion_main, Criterion};
use std::collections::{HashMap, HashSet};
use std::hint::black_box;

fn uid(ty: &str, eid: &str) -> EntityUID {
    EntityUID::with_eid_and_type(ty, eid).unwrap()
}

fn entities() -> Entities {
    let attrs: HashMap<_, RestrictedExpr> = [
        ("age".into(), RestrictedExpr::val(21)),
        ("name".into(), RestrictedExpr::val("alice")),
    ]
    .into_iter()
    .collect();
    let principal = Entity::new(
        uid("User", "alice"),
        attrs,
        HashSet::new(),
        HashSet::new(),
        HashMap::new(),
        Extensions::none(),
    )
    .unwrap();
    Entities::from_entities(
        std::iter::once(principal),
        None::<&NoEntitiesSchema>,
        TCComputation::ComputeNow,
        Extensions::none(),
    )
    .unwrap()
}

fn condition() -> Expr {
    let age = Expr::get_attr(Expr::var(Var::Principal), "age".into());
    let name = Expr::get_attr(Expr::var(Var::Principal), "name".into());
    Expr::and(
        Expr::and(
            Expr::less(age, Expr::val(150)),
            Expr::is_eq(Expr::var(Var::Action), Expr::val(uid("Action", "view"))),
        ),
        Expr::contains(
            Expr::set([Expr::val("alice"), Expr::val("bob")]),
            name,
        ),
    )
}

fn policy_condition(c: &mut Criterion) {
    let entities = entities();
    let request = Request::new(
        (uid("User", "alice"), None),
        (uid("Action", "view"), None),
        (uid("Album", "trip"), None),
        Context::empty(),
        None::<&RequestSchemaAllPass>,
        Extensions::none(),
    )
    .unwrap();
    let eval = Evaluator::new(request, &entities, Extensions::none());
    let slots = HashMap::new();
    let expr = condition();
    assert_eq!(
        eval.interpret(&expr, &slots).unwrap(),
        cedar_policy_core::ast::Value::from(true),
    );

    c.bench_function("eval/policy_condition", |b| {
        b.iter(|| black_box(eval.interpret(black_box(&expr), &slots).unwrap()))
    });
}

criterion_group!(benches, policy_condition);
criterion_main!(benches);
