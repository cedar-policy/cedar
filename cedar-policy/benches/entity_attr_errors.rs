// PANIC SAFETY: testing code
#![allow(clippy::unwrap_used)]
// PANIC SAFETY: testing code
#![allow(clippy::indexing_slicing)]

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityUid, PolicySet, Request, RestrictedExpression,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::iter::once;
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

const LARGE_SIZE: usize = 100_000;
const NUM_POLICIES: usize = 10;

fn create_policy_array(rng: &mut oorandom::Rand32) -> Vec<PolicySet> {
    let mut buf = vec![];
    for _ in 0..NUM_POLICIES {
        let attribute_number = rng.rand_range(1..((LARGE_SIZE - 1) as u32));
        let policy = PolicySet::from_str(&format!(
            r#"
        permit( principal, action, resource)
        when {{ Foo::"bar".a{attribute_number} }};
    "#,
        ))
        .unwrap();
        buf.push(policy);
    }
    buf
}

fn choose<'a>(policies: &'a [PolicySet], rng: &'a mut oorandom::Rand32) -> &'a PolicySet {
    let index = rng.rand_range(0..(policies.len() as u32)) as usize;
    &policies[index]
}

pub fn large_context_record(c: &mut Criterion) {
    let mut rng = oorandom::Rand32::new(4); // chosen by fair dice role
    let large_attr = (1..=LARGE_SIZE)
        .map(|i| (format!("a{i}"), RestrictedExpression::new_bool(true)))
        .collect::<HashMap<_, _>>();
    let large_entity =
        Entity::new(r#"Foo::"bar""#.parse().unwrap(), large_attr, HashSet::new()).unwrap();

    let small_attr = [
        ("a1".to_string(), RestrictedExpression::new_bool(true)),
        ("a2".to_string(), RestrictedExpression::new_bool(true)),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>();

    let small_entity =
        Entity::new(r#"Foo::"bar""#.parse().unwrap(), small_attr, HashSet::new()).unwrap();

    let euid: EntityUid = r#"Placeholder::"entity""#.parse().unwrap();
    let req = Request::new(
        euid.clone(),
        euid.clone(),
        euid.clone(),
        Context::empty(),
        None,
    )
    .unwrap();
    let large_entities = Entities::from_entities(once(large_entity), None).unwrap();
    let small_entities = Entities::from_entities(once(small_entity), None).unwrap();
    let auth = Authorizer::new();

    let mut group = c.benchmark_group("is_authorized large_entity_record");

    let policies = create_policy_array(&mut rng);

    group.bench_function("get-attr (large)", |b| {
        b.iter(|| {
            let policy = choose(&policies, &mut rng);
            auth.is_authorized(
                black_box(&req),
                black_box(policy),
                black_box(&large_entities),
            )
        })
    });

    group.bench_function("get-attr (small)", |b| {
        b.iter(|| {
            let policy = choose(&policies, &mut rng);
            auth.is_authorized(
                black_box(&req),
                black_box(policy),
                black_box(&small_entities),
            )
        })
    });

    let policy = PolicySet::from_str(
        r#"
        permit( principal, action, resource)
        when { Foo::"bar".other };
    "#,
    )
    .unwrap();
    group.bench_function("get-attr err (large)", |b| {
        b.iter(|| {
            auth.is_authorized(
                black_box(&req),
                black_box(&policy),
                black_box(&large_entities),
            )
        })
    });

    group.bench_function("get-attr err (small)", |b| {
        b.iter(|| {
            auth.is_authorized(
                black_box(&req),
                black_box(&policy),
                black_box(&small_entities),
            )
        })
    });

    group.finish();
}

criterion_group!(benches, large_context_record);
criterion_main!(benches);
