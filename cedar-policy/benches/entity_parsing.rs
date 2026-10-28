#![allow(clippy::unwrap_used, reason = "benchmarking")]

use std::{hint::black_box, str::FromStr};

use cedar_policy::{EntityTypeName, EntityUid};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn entity_type_name_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("EntityTypeName parsing");
    for name in [
        "foo",
        "foo::bar",
        "foo::bar::bar::bar::bar",
        "foo::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar",
        "foo::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar::bar",
    ]
    .iter()
    {
        group.bench_with_input(BenchmarkId::from_parameter(format!("Type Name size {}", name.len())), name, |b, name| {
            b.iter(|| EntityTypeName::from_str(black_box(name)).unwrap());
        });
    }
    group.finish();
}

fn entity_uid_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("EntityUid parsing");
    for (label, uid) in [
        ("unqualified", r#"User::"alice""#),
        ("one namespace", r#"Namespace::User::"alice""#),
        ("six namespaces", r#"A::B::C::D::E::F::User::"alice""#),
        ("uuid eid", r#"User::"01234567-89ab-cdef-0123-456789abcdef""#),
        (
            "long eid",
            r#"User::"alicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealice""#,
        ),
        // an eid that needs escaping takes the unoptimized path
        ("escaped eid", r#"User::"alice\nbob""#),
    ]
    .iter()
    {
        group.bench_with_input(BenchmarkId::from_parameter(label), uid, |b, uid| {
            b.iter(|| EntityUid::from_str(black_box(uid)).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, entity_type_name_parsing, entity_uid_parsing);
criterion_main!(benches);
