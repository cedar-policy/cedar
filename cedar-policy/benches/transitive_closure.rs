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

//! `compute_tc` and `repair_tc` on entity maps, and `Entities::from_json_str`.
//! Run once as is and once with `--features cedar-policy-core/verified-core`.

use std::collections::{HashMap, HashSet};
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use cedar_policy::Entities;
use cedar_policy_core::ast::{Entity, EntityUID};
use cedar_policy_core::transitive_closure::{compute_tc, repair_tc};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

type Map = HashMap<EntityUID, Arc<Entity>>;

fn uid(ty: &str, i: usize) -> EntityUID {
    EntityUID::with_eid_and_type(ty, &i.to_string()).unwrap()
}

fn insert(m: &mut Map, e: Entity) {
    m.insert(e.uid().clone(), Arc::new(e));
}

fn entity(id: EntityUID, parents: impl IntoIterator<Item = EntityUID>) -> Entity {
    let mut e = Entity::with_uid(id);
    for p in parents {
        e.add_parent(p);
    }
    e
}

/// `users` users, each in 3 distinct groups out of `groups`; each group in 1 of `orgs` orgs
fn orgs(users: usize, groups: usize, orgs: usize) -> Map {
    let mut rng = oorandom::Rand32::new(7);
    let mut m = Map::new();
    for o in 0..orgs {
        insert(&mut m, entity(uid("Org", o), []));
    }
    for g in 0..groups {
        let o = rng.rand_range(0..orgs as u32) as usize;
        insert(&mut m, entity(uid("Group", g), [uid("Org", o)]));
    }
    for u in 0..users {
        insert(&mut m, user(&mut rng, u, groups));
    }
    m
}

fn user(rng: &mut oorandom::Rand32, u: usize, groups: usize) -> Entity {
    let mut gs = HashSet::new();
    while gs.len() < 3 {
        gs.insert(rng.rand_range(0..groups as u32) as usize);
    }
    entity(uid("User", u), gs.into_iter().map(|g| uid("Group", g)))
}

/// Complete binary tree with `2^depth - 1` nodes; node `i > 0` has parent `(i - 1) / 2`
fn tree(depth: u32) -> Map {
    let mut m = Map::new();
    for i in 0..(1usize << depth) - 1 {
        let p = (i > 0).then(|| uid("Node", (i - 1) / 2));
        insert(&mut m, entity(uid("Node", i), p));
    }
    m
}

/// Node `i > 0` has parent `i - 1`
fn chain(n: usize) -> Map {
    let mut m = Map::new();
    for i in 0..n {
        let p = (i > 0).then(|| uid("Node", i - 1));
        insert(&mut m, entity(uid("Node", i), p));
    }
    m
}

/// 32 actions, each in 1 or 2 of 8 groups; groups 0..4 in `read`, 4..8 in `write`; both in `all`
fn actions() -> Map {
    let a = |s: &str| EntityUID::with_eid_and_type("Action", s).unwrap();
    let mut m = Map::new();
    insert(&mut m, entity(a("all"), []));
    insert(&mut m, entity(a("read"), [a("all")]));
    insert(&mut m, entity(a("write"), [a("all")]));
    for g in 0..8 {
        let top = if g < 4 { "read" } else { "write" };
        insert(&mut m, entity(a(&format!("g{g}")), [a(top)]));
    }
    for i in 0..32 {
        let mut ps = vec![a(&format!("g{}", i % 8))];
        if i % 3 == 0 {
            ps.push(a(&format!("g{}", (i + 3) % 8)));
        }
        insert(&mut m, entity(a(&format!("a{i}")), ps));
    }
    m
}

/// Copy of `m` that shares no `Arc` with it, so `Arc::make_mut` does not clone
fn deep_clone(m: &Map) -> Map {
    m.iter()
        .map(|(k, v)| (k.clone(), Arc::new(Entity::clone(v))))
        .collect()
}

fn closed(mut m: Map) -> Map {
    compute_tc(&mut m, true).unwrap();
    m
}

fn config() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
}

fn bench_compute(c: &mut Criterion) {
    let mut group = c.benchmark_group("compute_tc");
    let workloads: [(&str, Map); 6] = [
        ("actions_43", actions()),
        ("orgs_10k", orgs(10_000, 100, 10)),
        ("orgs_100k", orgs(100_000, 1000, 10)),
        ("tree_d16", tree(16)),
        ("chain_500", chain(500)),
        ("chain_2000", chain(2000)),
    ];
    for (name, m) in &workloads {
        group.bench_with_input(BenchmarkId::from_parameter(name), m, |b, m| {
            b.iter_batched(
                || deep_clone(m),
                |mut m| {
                    compute_tc(&mut m, true).unwrap();
                    m
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_repair(c: &mut Criterion) {
    let mut group = c.benchmark_group("repair_tc");
    let base_orgs = closed(orgs(100_000, 1000, 10));
    let base_chain = closed(chain(2000));
    for k in [1, 10, 100] {
        // new users, each in 3 groups
        group.bench_with_input(BenchmarkId::new("orgs_100k", k), &k, |b, &k| {
            b.iter_batched(
                || {
                    let mut m = deep_clone(&base_orgs);
                    let mut rng = oorandom::Rand32::new(11);
                    let mut fix = HashSet::new();
                    for u in 0..k {
                        let e = user(&mut rng, 100_000 + u, 1000);
                        fix.insert(e.uid().clone());
                        insert(&mut m, e);
                    }
                    (m, fix)
                },
                |(mut m, fix)| {
                    repair_tc(&fix, &mut m, true).unwrap();
                    (m, fix)
                },
                BatchSize::PerIteration,
            );
        });
        // new leaves under the deepest node of the chain, which has 1999 ancestors
        group.bench_with_input(BenchmarkId::new("chain_2000_deep", k), &k, |b, &k| {
            b.iter_batched(
                || {
                    let mut m = deep_clone(&base_chain);
                    let mut fix = HashSet::new();
                    for i in 0..k {
                        let e = entity(uid("Leaf", i), [uid("Node", 1999)]);
                        fix.insert(e.uid().clone());
                        insert(&mut m, e);
                    }
                    (m, fix)
                },
                |(mut m, fix)| {
                    repair_tc(&fix, &mut m, true).unwrap();
                    (m, fix)
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn to_json(m: &Map) -> String {
    let es: Vec<serde_json::Value> = m
        .values()
        .map(|e| {
            let parents: Vec<_> = e
                .parents()
                .map(|p| serde_json::json!({ "type": p.entity_type().to_string(), "id": p.eid().escaped().to_string() }))
                .collect();
            serde_json::json!({
                "uid": { "type": e.uid().entity_type().to_string(), "id": e.uid().eid().escaped().to_string() },
                "attrs": {},
                "parents": parents,
            })
        })
        .collect();
    serde_json::to_string(&es).unwrap()
}

fn bench_entities_json(c: &mut Criterion) {
    let mut group = c.benchmark_group("entities_from_json");
    for (name, m) in [
        ("orgs_10k", orgs(10_000, 100, 10)),
        ("chain_1000", chain(1000)),
    ] {
        let json = to_json(&m);
        group.bench_with_input(BenchmarkId::from_parameter(name), &json, |b, json| {
            b.iter_with_large_drop(|| Entities::from_json_str(black_box(json), None).unwrap());
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = config();
    targets = bench_compute, bench_repair, bench_entities_json
}
criterion_main!(benches);
