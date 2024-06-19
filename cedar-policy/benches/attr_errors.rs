// PANIC SAFETY: testing code
#![allow(clippy::unwrap_used)]
use cedar_policy::EntityUid;
use cedar_policy::{Authorizer, Context, Entities, PolicySet, Request, RestrictedExpression};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::str::FromStr;

const LARGE_SIZE: usize = 100_000;

pub fn large_context_record(c: &mut Criterion) {
    let large_context = Context::from_pairs(
        (1..=LARGE_SIZE)
            .map(|i| (format!("a{i}"), RestrictedExpression::new_bool(true)))
            .collect::<Vec<_>>(),
    )
    .unwrap();

    let small_context = Context::from_pairs([
        ("a1".to_string(), RestrictedExpression::new_bool(true)),
        ("a2".to_string(), RestrictedExpression::new_bool(true)),
    ])
    .unwrap();

    let euid: EntityUid = r#"Placeholder::"entity""#.parse().unwrap();
    let large_req = Request::new(
        euid.clone(),
        euid.clone(),
        euid.clone(),
        large_context,
        None,
    )
    .unwrap();
    let small_req = Request::new(
        euid.clone(),
        euid.clone(),
        euid.clone(),
        small_context,
        None,
    )
    .unwrap();
    let entities = Entities::empty();
    let auth = Authorizer::new();

    let mut group = c.benchmark_group("is_authorized large_context_record");

    let policy = PolicySet::from_str(
        r#"
        permit( principal, action, resource)
        when { context.a1 };
    "#,
    )
    .unwrap();
    group.bench_function("get-attr (large)", |b| {
        b.iter(|| {
            auth.is_authorized(
                black_box(&large_req),
                black_box(&policy),
                black_box(&entities),
            )
        })
    });

    group.bench_function("get-attr (small)", |b| {
        b.iter(|| {
            auth.is_authorized(
                black_box(&small_req),
                black_box(&policy),
                black_box(&entities),
            )
        })
    });

    let policy = PolicySet::from_str(
        r#"
        permit( principal, action, resource)
        when { context.other };
    "#,
    )
    .unwrap();
    group.bench_function("get-attr err (large)", |b| {
        b.iter(|| {
            auth.is_authorized(
                black_box(&large_req),
                black_box(&policy),
                black_box(&entities),
            )
        })
    });

    group.bench_function("get-attr err (small)", |b| {
        b.iter(|| {
            auth.is_authorized(
                black_box(&small_req),
                black_box(&policy),
                black_box(&entities),
            )
        })
    });

    group.finish();
}

criterion_group!(benches, large_context_record);
criterion_main!(benches);
