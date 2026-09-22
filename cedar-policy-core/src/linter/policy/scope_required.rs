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

//! Flags a policy whose scope constrains *nothing* — all three of `principal`,
//! `action`, and `resource` are the bare, unconstrained form.
//!
//! ```cedar
//! permit(principal, action, resource) when { context.mfa };
//! ```
//!
//! The `no-unconstrained-scope` restriction asks every policy to anchor somewhere
//! in the request space via its scope — `principal is User`, `action ==
//! Action::"view"`, `resource in Album::"a"`, and so on. A fully-open scope pushes
//! all narrowing into the condition, where it is invisible to a reader skimming
//! scopes and to a policy store trying to slice on the request. A mistake in the
//! condition then silently leaves the policy spanning the entire request space.
//!
//! This is a `Restriction`, not a correctness finding: a fully-open scope is legal
//! and a deliberately global baseline `forbid` (e.g. "deny everything for a
//! disabled principal") wants exactly this shape. So it is off by default; enable
//! it when the auditability property is worth requiring an anchor on every policy.
//!
//! Only the scope is examined — the condition is irrelevant, since the point is
//! that the *scope* says nothing.

use crate::{
    ast::{ActionConstraint, Effect, PrincipalOrResourceConstraint as PrcConstraint, Template},
    linter::findings::{Finding, UnconstrainedScope},
};

/// Is a principal/resource scope constraint the unconstrained `Any`?
fn pr_is_any(c: &PrcConstraint) -> bool {
    matches!(c, PrcConstraint::Any)
}

/// Is an action scope constraint the unconstrained `Any`?
fn action_is_any(c: &ActionConstraint) -> bool {
    matches!(c, ActionConstraint::Any)
}

/// Lint `template`'s scope: report when principal, action, and resource are all
/// unconstrained.
pub(crate) fn lint(template: &Template) -> Vec<Finding> {
    let all_open = pr_is_any(template.principal_constraint().as_inner())
        && action_is_any(template.action_constraint())
        && pr_is_any(template.resource_constraint().as_inner());
    if !all_open {
        return Vec::new();
    }
    let effect = match template.effect() {
        Effect::Permit => "permit",
        Effect::Forbid => "forbid",
    };
    vec![UnconstrainedScope {
        loc: template.loc().cloned(),
        effect,
    }
    .into()]
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_policy_or_template;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        let template = parse_policy_or_template(None, src).expect("failed to parse");
        render(&lint(&template))
    }

    /// A fully-open scope, even with a condition, is reported.
    #[test]
    fn fully_open_scope() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.mfa };"#), @"
         ⚠ this permit constrains nothing in its scope
          ╭────
        1 │ permit(principal, action, resource) when { context.mfa };
          · ─────────────────────────────────────────────────────────
          ╰────
         help: constrain at least one of `principal`, `action`, or `resource` in the scope (with `==`, `in`, or `is`), so the policy's reach is visible without reading the condition and a policy store can
               slice on it; a deliberately global policy can suppress this
        ");
    }

    /// A constrained principal is enough to anchor the policy.
    #[test]
    fn constrained_principal_is_fine() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal == User::"alice", action, resource);"#), @"");
    }

    /// A constrained action is enough.
    #[test]
    fn constrained_action_is_fine() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"view", resource);"#), @"");
    }

    /// A constrained resource is enough.
    #[test]
    fn constrained_resource_is_fine() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource in Album::"a");"#), @"");
    }

    /// An `is` type constraint anchors too.
    #[test]
    fn is_constraint_is_fine() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal is User, action, resource);"#), @"");
    }

    /// A fully-open `forbid` is reported the same way, with its effect named.
    #[test]
    fn fully_open_forbid() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal.disabled };"#), @"
         ⚠ this forbid constrains nothing in its scope
          ╭────
        1 │ forbid(principal, action, resource) when { principal.disabled };
          · ────────────────────────────────────────────────────────────────
          ╰────
         help: constrain at least one of `principal`, `action`, or `resource` in the scope (with `==`, `in`, or `is`), so the policy's reach is visible without reading the condition and a policy store can
               slice on it; a deliberately global policy can suppress this
        ");
    }

    /// A template with a slot in scope is anchored (the slot is a constraint).
    #[test]
    fn slot_scope_is_fine() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal == ?principal, action, resource);"#), @"");
    }
}
