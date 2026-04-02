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
//! Benchmarks comparing the old `LosslessPolicy::Text` path against the new
//! `LosslessPolicy::Empty` path used by `Policy::from_ast()`.
//!
//! Old path (Text): eagerly `ast.to_string()`, then lazily re-parse via
//! `parse_policy_or_template_to_est(text)`.
//!
//! New path (Empty): lazily reconstruct via `est::Policy::from(ast.clone())`
//! or `pst::Policy::try_from(ast.clone())`.
#![allow(clippy::unwrap_used, reason = "benchmarking")]

use std::sync::Arc;

use cedar_policy_core::ast;
use cedar_policy_core::est;
use cedar_policy_core::parser;
use cedar_policy_core::pst;
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

const SMALL_POLICY: &str = r#"permit(
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"vacation.jpg"
);"#;

const LARGE_POLICY: &str = r#"permit(
    principal == User::"alice",
    action == Action::"view",
    resource
) when {
    resource.owner == principal &&
    context.ip.isInRange(ip("192.168.0.0/16")) &&
    resource.tags.contains("public") &&
    principal.age > 0 &&
    principal.department == "engineering" &&
    resource.classification != "top-secret" &&
    context.time > 0 &&
    context.authenticated == true
};"#;

const IP_HEAVY_POLICY: &str = r#"forbid(
    principal,
    action == Action::"ssh",
    resource
) when {
    !context.source_ip.isInRange(ip("10.0.0.0/8")) &&
    !context.source_ip.isInRange(ip("172.16.0.0/12")) &&
    !context.source_ip.isInRange(ip("192.168.0.0/16")) &&
    !context.source_ip.isLoopback() &&
    !context.source_ip.isMulticast()
} unless {
    context.vpn_ip.isInRange(ip("10.200.0.0/16")) ||
    context.vpn_ip.isInRange(ip("10.201.0.0/16"))
};"#;

const DECIMAL_DATETIME_POLICY: &str = r#"permit(
    principal,
    action == Action::"purchase",
    resource
) when {
    decimal("0.00") <= context.price &&
    context.price <= decimal("1000.00") &&
    context.discount >= decimal("0.00") &&
    context.discount <= decimal("0.50") &&
    context.requested_at >= datetime("2025-01-01T00:00:00Z") &&
    context.requested_at < datetime("2026-01-01T00:00:00Z") &&
    context.requested_at.offset(duration("1h")) < datetime("2026-01-01T01:00:00Z") &&
    context.requested_at.durationSince(datetime("2025-01-01T00:00:00Z")) < duration("365d")
};"#;

fn bench_from_ast(c: &mut Criterion) {
    let cases: &[(&str, &str)] = &[
        ("small", SMALL_POLICY),
        ("large", LARGE_POLICY),
        ("ip_heavy", IP_HEAVY_POLICY),
        ("decimal_datetime", DECIMAL_DATETIME_POLICY),
    ];

    for &(label, policy_text) in cases {
        let static_policy = parser::parse_policy(None, policy_text).unwrap();
        let ast_template: Arc<ast::Template> = static_policy.clone().into();
        let ast_policy: ast::Policy = static_policy.clone().into();
        let text = ast_template.to_string();

        let mut group = c.benchmark_group(format!("from_ast/{label}"));

        // --- Old path components ---

        // Eager cost at from_ast() time
        group.bench_function("old/to_string", |b| {
            b.iter(|| black_box(&ast_template).to_string())
        });

        // Lazy cost at to_json()/to_pst() time
        group.bench_function("old/parse_to_est", |b| {
            b.iter(|| parser::parse_policy_or_template_to_est(black_box(&text)).unwrap())
        });

        // Combined old path total
        group.bench_function("old/total", |b| {
            b.iter(|| {
                let t = black_box(&ast_template).to_string();
                parser::parse_policy_or_template_to_est(&t).unwrap()
            })
        });

        // --- New path components ---

        // Lazy cost at to_json() time: AST → EST
        group.bench_function("new/ast_to_est", |b| {
            b.iter(|| est::Policy::from(black_box((*ast_template).clone())))
        });

        // Lazy cost at to_pst() time: AST → PST
        group.bench_function("new/ast_to_pst", |b| {
            b.iter(|| pst::Policy::try_from(black_box(ast_policy.clone())).unwrap())
        });

        group.finish();
    }
}

criterion_group!(benches, bench_from_ast);
criterion_main!(benches);
