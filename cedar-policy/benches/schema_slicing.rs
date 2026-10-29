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
#![allow(clippy::expect_used, reason = "benchmarking")]
#![allow(clippy::indexing_slicing, reason = "benchmarking")]

//! Getting the action entities for one request from a large schema.
//!
//! Compares parsing the whole schema against parsing only the request
//! action's transitive closure (`Schema::action_closure_for`), stored as Cedar
//! schema text. The closure alone gives the action entities for an
//! authorization request. Linking it with an entity type registry, which
//! entity validation needs, is measured too.

use std::{hint::black_box, str::FromStr};

use cedar_policy::{EntityUid, Schema};
use cedar_policy_core::validator::ValidatorSchema;
use criterion::{criterion_group, criterion_main, Criterion};

const LARGE: &str = include_str!("fixtures/large_action_hierarchy.cedarschema");
const LEAF_ACTIONS: u32 = 2000;

fn leaf(n: u32) -> EntityUid {
    EntityUid::from_str(&format!(r#"Action::"a{n:04}""#)).unwrap()
}

pub fn criterion_benchmark(c: &mut Criterion) {
    // What an admin step would compute and store once per schema version.
    let full = Schema::from_str(LARGE).unwrap();
    let registry = ValidatorSchema::new(full.as_ref().entity_types().cloned(), [])
        .to_cedar_schema()
        .unwrap();
    let slices: Vec<String> = (0..LEAF_ACTIONS)
        .map(|n| {
            full.action_closure_for(&leaf(n))
                .unwrap()
                .unwrap()
                .to_cedarschema()
                .unwrap()
        })
        .collect();
    eprintln!(
        "stored sizes: full schema {} bytes, registry {} bytes, one closure {} bytes",
        LARGE.len(),
        registry.len(),
        slices[0].len()
    );

    let mut group = c.benchmark_group("action_entities");

    // One full parse takes about 340 ms, so criterion's default 5 s is too
    // short for 100 samples. It asks for about 31 s; 40 s leaves headroom.
    group.measurement_time(std::time::Duration::from_secs(40));
    group.bench_function("parse full schema", |b| {
        b.iter(|| {
            let schema = Schema::from_str(black_box(LARGE)).unwrap();
            black_box(schema.action_entities().unwrap())
        })
    });
    // "full schema already parsed" (about 1.6 ms) needs about 8 s for 100
    // samples; the rest are fast enough either way.
    group.measurement_time(std::time::Duration::from_secs(10));

    group.bench_function("full schema already parsed", |b| {
        b.iter(|| black_box(black_box(&full).action_entities().unwrap()))
    });

    let mut rng = oorandom::Rand32::new(0x5eed);
    group.bench_function(
        "parse registry and one closure, link (validation path)",
        |b| {
            b.iter(|| {
                let slice = &slices[rng.rand_range(0..LEAF_ACTIONS) as usize];
                let registry = Schema::from_str(black_box(&registry)).unwrap();
                let slice = Schema::from_str(black_box(slice)).unwrap();
                let linked = Schema::schema_link_complete([registry, slice]).unwrap();
                black_box(linked.action_entities().unwrap())
            })
        },
    );

    let mut rng = oorandom::Rand32::new(0x5eed);
    group.bench_function("parse one closure only (isAuthorized path)", |b| {
        b.iter(|| {
            let slice = &slices[rng.rand_range(0..LEAF_ACTIONS) as usize];
            let slice = Schema::from_str(black_box(slice)).unwrap();
            black_box(slice.action_entities().unwrap())
        })
    });

    // The fixed cost of any schema parse, for scale.
    group.bench_function("parse a one-line schema", |b| {
        b.iter(|| black_box(Schema::from_str(black_box("entity User;")).unwrap()))
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
