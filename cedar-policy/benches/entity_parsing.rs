// PANIC SAFETY: it's ok for benchmarking code to panic
#![allow(clippy::unwrap_used)]

use std::{hint::black_box, str::FromStr};

use cedar_policy::EntityTypeName;

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

criterion_group!(benches, entity_type_name_parsing);
criterion_main!(benches);
