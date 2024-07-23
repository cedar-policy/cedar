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
// PANIC SAFETY: benchmarking
#![allow(clippy::unwrap_used)]
// PANIC SAFETY: benchmarking
#![allow(clippy::expect_used)]

use cedar_policy::{Entities, Entity, EntityId, EntityTypeName, EntityUid};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use itertools::Itertools;
use std::iter;
use std::{collections::HashSet, str::FromStr};

struct RandBool {
    rng: oorandom::Rand32,
    current_u32: u32,
    bit_offset: u8,
}

impl RandBool {
    fn new(mut rng: oorandom::Rand32) -> Self {
        let current_u32 = rng.rand_u32();
        Self {
            rng,
            current_u32,
            bit_offset: 0,
        }
    }

    fn rand_bool(&mut self) -> bool {
        if self.bit_offset >= 32 {
            self.bit_offset = 0;
            self.current_u32 = self.rng.rand_u32();
        }
        let bit_mask = (1 as u32)
            .checked_shr(self.bit_offset as u32)
            .expect("`bit_offset` < 32");
        self.bit_offset += 1;
        (self.current_u32 & bit_mask) == bit_mask
    }
}

fn create_entity_array(num: usize, ety: EntityTypeName, rng: oorandom::Rand32) -> Vec<Entity> {
    let mut euids = Vec::with_capacity(num);
    for i in 0..num {
        euids.push(EntityUid::from_type_name_and_id(
            ety.clone(),
            EntityId::from_str(&format!("entity{i}")).unwrap(),
        ));
    }

    let mut rand_bool = RandBool::new(rng);
    let mut entities = Vec::with_capacity(num);
    while let Some(euid) = euids.pop() {
        let mut parents = HashSet::with_capacity(euids.len() / 2);
        for parent_euid in &euids {
            if rand_bool.rand_bool() {
                parents.insert(parent_euid.clone());
            }
        }
        entities.push(Entity::new_no_attrs(euid.clone(), parents));
    }
    entities
}

pub fn entity_transitive_closure(c: &mut Criterion) {
    const LONG : usize = 25;
    const SHORT : usize = 5;
    let qual_entity_type = EntityTypeName::from_str("T").unwrap();
    let entities = create_entity_array(SHORT, qual_entity_type, oorandom::Rand32::new(7));
    c.bench_function("baseline", |b| {
        b.iter(|| {
            Entities::from_entities(black_box(entities.clone()), None).unwrap();
        })
    });

    let qual_entity_type = EntityTypeName::from_str("T").unwrap();
    let entities = create_entity_array(LONG, qual_entity_type, oorandom::Rand32::new(7));
    c.bench_function("long_entities", |b| {
        b.iter(|| {
            Entities::from_entities(black_box(entities.clone()), None).unwrap();
        })
    });

    let qual_entity_type =
        EntityTypeName::from_str(&iter::repeat("NS").take(LONG).join("::")).unwrap();
    let entities = create_entity_array(SHORT, qual_entity_type, oorandom::Rand32::new(7));
    c.bench_function("long_name", |b| {
        b.iter(|| {
            Entities::from_entities(black_box(entities.clone()), None).unwrap();
        })
    });

    let qual_entity_type =
        EntityTypeName::from_str(&iter::repeat("NS").take(LONG).join("::")).unwrap();
    let entities = create_entity_array(LONG, qual_entity_type, oorandom::Rand32::new(7));
    c.bench_function("long_name_long_entities", |b| {
        b.iter(|| {
            Entities::from_entities(black_box(entities.clone()), None).unwrap();
        })
    });
}

criterion_group!(benches, entity_transitive_closure);
criterion_main!(benches);
