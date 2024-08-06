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

use std::str::FromStr;

use cedar_policy::{Policy, PolicySet, Schema, Validator};

use criterion::{black_box, criterion_group, criterion_main, Criterion};

// PANIC SAFETY: benchmarking
#[allow(clippy::unwrap_used)]
pub fn extension_fn_validation(c: &mut Criterion) {
    let (schema, _) = Schema::from_cedarschema_str(
        "entity E; action Act appliesTo { principal: E, resource: E, context: {}};",
    )
    .unwrap();
    let validator = Validator::new(schema);

    let policy_set = PolicySet::from_policies([Policy::from_str(
        r#"permit(principal, action, resource) when { ip("127.0.0.1") };"#,
    )
    .unwrap()])
    .unwrap();
    c.bench_function("ip", |b| {
        b.iter(|| {
            validator.validate(black_box(&policy_set), cedar_policy::ValidationMode::Strict);
        })
    });

    let policy_set = PolicySet::from_policies([Policy::from_str(
        r#"permit(principal, action, resource) when { decimal("12.34") };"#,
    )
    .unwrap()])
    .unwrap();
    c.bench_function("decimal", |b| {
        b.iter(|| {
            validator.validate(black_box(&policy_set), cedar_policy::ValidationMode::Strict);
        })
    });
}

criterion_group!(benches, extension_fn_validation);
criterion_main!(benches);
