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

//! Flags attribute accesses that are not guarded by a corresponding `has` check.
//!
//! `principal.admin` errors when `principal` has no `admin` attribute, and a
//! policy whose condition errors is skipped (`ErrorHandling::Skip`), so it has no
//! effect on the decision. Which direction that fails depends on the effect, and
//! the two are reported separately so they can be enabled independently:
//!
//! * In a `forbid` it fails **open**: the policy meant to deny access is dropped,
//!   and if some `permit` matches, the request is allowed. Whoever controls the
//!   entity or context data can trigger that by simply omitting the attribute.
//! * In a `permit` it fails **closed**: the request is denied. Not a security
//!   problem, but the `permit` silently stops working, which is still a bug.
//!
//! Either way the fix is the same — guard the access, e.g.
//! `principal has admin && principal.admin`.
//!
//! # Why this is worth enabling even with a schema
//!
//! Strict validation already proves that a *declared* optional attribute is
//! guarded, so the obvious reading is that this lint only matters without a
//! schema. It isn't: a guard also covers the case the validator cannot rule out,
//! namely that the entity **does not exist in the store at all**.
//!
//! Cedar treats an entity absent from the store as one with no attributes, and
//! the schema says nothing about which entities the store actually contains. So
//! `principal.dept` errors for a `principal` that was never passed in, even
//! though the schema declares `dept` as required on that entity type and strict
//! validation accepts the policy. A `has` guard is what makes the condition
//! evaluate to `false` in that case instead of erroring. That makes this a
//! restriction worth adopting alongside validation, not just in place of it.
//!
//! # How it works
//!
//! This pass is the same capability analysis the validator does in
//! `validator/typecheck.rs`, minus the schema: it tracks which attributes a
//! `has` check has established at each point in the condition, and reports every
//! `GetAttr` whose attribute isn't among them. Without a schema it can't tell a
//! required attribute from an optional one — and per the above, it shouldn't want
//! to — so it asks for a guard on every access. That is a broad ask, which is why
//! both lints are off by default.
//!
//! # Capabilities
//!
//! The pass reuses the typechecker's [`Capability`] and [`CapabilitySet`], so the
//! two analyses share one notion of "this attribute is known to exist". Each
//! subexpression yields the set it establishes: the *positive* half holds when
//! that subexpression is true, the *negative* half when it is false.
//!
//! Carrying both halves is what lets a guard work through a negation —
//! [`CapabilitySet::negate`] swaps them — which is what makes the negative
//! pattern work:
//!
//! ```cedar
//! forbid(principal, action, resource) when { !(principal has admin) || principal.admin };
//! ```
//!
//! `!(principal has admin)` short-circuits the `||` when true, so the right
//! operand is only reached when it is false — which is exactly when
//! `principal.admin` exists.
//!
//! Each rule follows the short-circuiting, using
//! [`and`](CapabilitySet::and) and [`or`](CapabilitySet::or) to combine:
//!
//! | Expression | Right/branches linted under | Establishes |
//! | --- | --- | --- |
//! | `l && r` | `l`, since `r` is reached only when `l` was true | `l.and(r)` |
//! | `l \|\| r` | `!l`, since `r` is reached only when `l` was false | `l.or(r)` |
//! | `if t then a else b` | `t` for `a`, `!t` for `b` | `t.and(a).or(!t.and(b))` |
//! | `!e` | — | `e` negated |
//!
//! Everything else evaluates its operands eagerly, and establishes nothing.
//!
//! Note the analysis is purely syntactic: the guard must name the same target
//! expression, compared by shape, and the same attribute. `principal has x &&
//! principal.y` is reported, and so is a guard established through a construct
//! the pass doesn't reason about, e.g. `(principal has x) == true`.

use smol_str::SmolStr;

use crate::{
    ast::{Effect, Expr, ExprKind, Template},
    linter::{
        capability::walk_capabilities,
        findings::{Finding, UnguardedAttrInForbid, UnguardedAttrInPermit},
    },
    validator::types::{Capability, CapabilitySet},
};

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AttrGuardLinter {
    /// Which effect to lint. A policy of the other effect is skipped, so the two
    /// lints can be enabled independently.
    effect: Effect,
    errors: Vec<Finding>,
}

impl AttrGuardLinter {
    /// A linter that reports unguarded accesses in policies whose effect is
    /// `effect`, and ignores the rest.
    pub(crate) fn new(effect: Effect) -> Self {
        Self {
            effect,
            errors: Vec::new(),
        }
    }

    pub(crate) fn lint(&mut self, template: &Template) {
        if template.effect() != self.effect {
            return;
        }
        // The scope constraints contain no attribute access, so linting the
        // whole condition is the same as linting the `when`/`unless` clauses,
        // and it keeps the negation an `unless` introduces.
        let condition = template.condition();
        let effect = self.effect;
        let mut errors = std::mem::take(&mut self.errors);
        // The capability plumbing (`&&`/`||`/`if`/`!`) is shared; this only says
        // what each node establishes and checks. A `has` establishes its attribute;
        // a `GetAttr` not covered by an established capability is unguarded.
        walk_capabilities(&condition, &CapabilitySet::new(), &mut |expr, caps| {
            match expr.expr_kind() {
                ExprKind::HasAttr { expr: target, attr } => {
                    CapabilitySet::singleton(Capability::new_attribute(target, attr.clone()))
                }
                ExprKind::GetAttr { expr: target, attr } => {
                    // An attribute of a record literal that spells the attribute
                    // out cannot be missing.
                    let literally_present = match target.expr_kind() {
                        ExprKind::Record(attrs) => attrs.contains_key(attr),
                        _ => false,
                    };
                    if !literally_present
                        && !caps.contains(&Capability::new_attribute(target, attr.clone()))
                    {
                        errors.push(unguarded(effect, expr, target, attr));
                    }
                    CapabilitySet::new()
                }
                _ => CapabilitySet::new(),
            }
        });
        // `walk_capabilities` reports an access before the accesses nested inside
        // its target, and `&&` before `||` regardless of source order. Sort so
        // findings read in the order the policy does; the sort is stable, so
        // spans starting at the same offset keep innermost-first.
        errors.sort_by_key(|e| e.source_loc().map(|l| l.span.offset()));
        self.errors = errors;
    }

    /// Consume this linter, returning the findings it accumulated.
    pub(crate) fn into_findings(self) -> Vec<Finding> {
        self.errors
    }
}

/// The finding for an unguarded access, tagged by effect.
fn unguarded(effect: Effect, expr: &Expr, target: &Expr, attr: &SmolStr) -> Finding {
    let loc = expr.source_loc().cloned();
    let attr = attr.clone();
    let target = target.to_string();
    match effect {
        Effect::Forbid => UnguardedAttrInForbid { loc, attr, target }.into(),
        Effect::Permit => UnguardedAttrInPermit { loc, attr, target }.into(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_policy_or_template;

    /// Lint `src` for `effect` policies and return the pretty miette rendering of
    /// all findings, concatenated. Rendered without color so the snapshots stay
    /// readable.
    #[track_caller]
    fn lint_report_for(effect: Effect, src: &str) -> String {
        let template = parse_policy_or_template(None, src).expect("failed to parse");
        let mut linter = AttrGuardLinter::new(effect);
        linter.lint(&template);
        render(&linter.errors)
    }

    /// Lint `src`, which the tests below write as a `forbid`. The `permit` case
    /// runs the same analysis, so it is covered by `permit_reported_separately`
    /// rather than duplicated throughout.
    #[track_caller]
    fn lint_report(src: &str) -> String {
        lint_report_for(Effect::Forbid, src)
    }

    /// An access guarded by the corresponding `has` is fine.
    #[test]
    fn guarded_by_has() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal has admin && principal.admin };"#),
            @"");
    }

    #[test]
    fn unguarded() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal.admin };"#), @"
         ⚠ attribute `admin` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { principal.admin };
          ·                                            ───────────────
          ╰────
         help: if `admin` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has admin &&`
        ");
    }

    /// The negative pattern: the guard is reached by being *false*, so what it
    /// establishes has to survive the negation and the `||`.
    #[test]
    fn negative_capability_guards() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { !(principal has bar) || principal.bar };"#), @"");
        // The parens are load-bearing: `!` binds tighter than `has`, so without
        // them this is `(!principal) has bar`, which guards nothing about
        // `principal`. Reporting it is right, and is the more useful outcome —
        // the policy really is unguarded.
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { !principal has bar || principal.bar };"#), @"
         ⚠ attribute `bar` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { !principal has bar || principal.bar };
          ·                                                                  ─────────────
          ╰────
         help: if `bar` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has bar &&`
        ");
    }

    /// Only the negated form guards the right operand of `||`. A bare `has`
    /// there establishes nothing: the right side is reached exactly when the
    /// check was false, i.e. when the attribute is missing.
    #[test]
    fn plain_or_does_not_guard() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal has bar || principal.bar };"#), @"
         ⚠ attribute `bar` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { principal has bar || principal.bar };
          ·                                                                 ─────────────
          ╰────
         help: if `bar` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has bar &&`
        ");
    }

    /// Double negation cancels, so the guard is back to guarding the left.
    #[test]
    fn double_negation() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { !(!(principal has bar)) && principal.bar };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { !(!(principal has bar)) || principal.bar };"#), @"
         ⚠ attribute `bar` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { !(!(principal has bar)) || principal.bar };
          ·                                                                       ─────────────
          ╰────
         help: if `bar` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has bar &&`
        ");
    }

    /// A negated `has` also guards the right operand of `&&`'s negation, i.e.
    /// `unless`, which is how `unless` clauses are represented.
    #[test]
    fn unless_is_negated() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) unless { principal has admin && principal.admin };"#),
            @"");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) unless { principal.admin };"#), @"
         ⚠ attribute `admin` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) unless { principal.admin };
          ·                                              ───────────────
          ╰────
         help: if `admin` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has admin &&`
        ");
    }

    /// The guard must name the same attribute and the same target.
    #[test]
    fn guard_must_match() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal has admin && principal.owner };"#),
            @"
         ⚠ attribute `owner` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { principal has admin && principal.owner };
          ·                                                                   ───────────────
          ╰────
         help: if `owner` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has owner &&`
        ");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal has admin && resource.admin };"#),
            @"
         ⚠ attribute `admin` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { principal has admin && resource.admin };
          ·                                                                   ──────────────
          ╰────
         help: if `admin` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `resource has admin &&`
        ");
    }

    /// A `has` test guards the `then` branch of an `if`, and its negation
    /// guards the `else` branch.
    #[test]
    fn if_guards_both_branches() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { if principal has admin then principal.admin else false };"#),
            @"");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { if !(principal has admin) then false else principal.admin };"#),
            @"");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { if principal has admin then false else principal.admin };"#),
            @"
         ⚠ attribute `admin` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { if principal has admin then false else principal.admin };
          ·                                                                                   ───────────────
          ╰────
         help: if `admin` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has admin &&`
        ");
    }

    /// Guards accumulate along a chain of `&&`, and each access is checked.
    #[test]
    fn multiple_guards() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal has a && principal has b && principal.a == principal.b };"#),
            @"");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal has a && principal.a == principal.b };"#),
            @"
         ⚠ attribute `b` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { principal has a && principal.a == principal.b };
          ·                                                                              ───────────
          ╰────
         help: if `b` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has b &&`
        ");
    }

    /// A nested access needs a guard at each level, and each level is reported
    /// separately, innermost first.
    #[test]
    fn nested_access() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal has a && principal.a has b && principal.a.b };"#),
            @"");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal.a.b };"#), @"
         ⚠ attribute `a` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { principal.a.b };
          ·                                            ─────────────
          ╰────
         help: if `a` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has a &&`

         ⚠ attribute `b` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { principal.a.b };
          ·                                            ─────────────
          ╰────
         help: if `b` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal.a has b &&`
        ");
    }

    /// A guard on the outer access alone doesn't cover the inner one.
    #[test]
    fn nested_access_partially_guarded() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal.a has b && principal.a.b };"#), @"
         ⚠ attribute `a` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { principal.a has b && principal.a.b };
          ·                                            ───────────
          ╰────
         help: if `a` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has a &&`

         ⚠ attribute `a` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { principal.a has b && principal.a.b };
          ·                                                                 ─────────────
          ╰────
         help: if `a` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has a &&`
        ");
    }

    /// The `permit` case runs the same analysis but reports a distinct finding,
    /// since skipping a `permit` denies rather than allows.
    #[test]
    fn permit_gets_its_own_finding() {
        insta::assert_snapshot!(lint_report_for(
            Effect::Permit, r#"permit(principal, action, resource) when { principal.admin };"#), @"
         ⚠ attribute `admin` is accessed in a `permit` policy without a `has` guard
          ╭────
        1 │ permit(principal, action, resource) when { principal.admin };
          ·                                            ───────────────
          ╰────
         help: if `admin` is absent the condition errors and the `permit` is skipped, so the request may be denied; guard the access with `principal has admin &&`
        ");
        insta::assert_snapshot!(lint_report_for(
            Effect::Permit,
            r#"permit(principal, action, resource) when { principal has admin && principal.admin };"#),
            @"");
    }

    /// Each effect is linted only by its own lint, so the two can be enabled
    /// independently.
    #[test]
    fn effects_are_configured_separately() {
        let forbid = r#"forbid(principal, action, resource) when { principal.admin };"#;
        let permit = r#"permit(principal, action, resource) when { principal.admin };"#;
        // Linting for one effect ignores policies of the other.
        insta::assert_snapshot!(lint_report_for(Effect::Permit, forbid), @"");
        insta::assert_snapshot!(lint_report_for(Effect::Forbid, permit), @"");
        // And each does report its own.
        assert!(!lint_report_for(Effect::Forbid, forbid).is_empty());
        assert!(!lint_report_for(Effect::Permit, permit).is_empty());
    }

    /// Context attributes are the common case, and get no special treatment.
    #[test]
    fn context_access() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { context has mfa && !context.mfa };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { !context.mfa };"#), @"
         ⚠ attribute `mfa` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { !context.mfa };
          ·                                             ───────────
          ╰────
         help: if `mfa` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `context has mfa &&`
        ");
    }

    /// An attribute a record literal spells out cannot be missing.
    #[test]
    fn record_literal_attribute() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { {a: 1}.a > 0 };"#), @"");
    }

    /// Accesses inside sets, records, and extension calls are found too.
    #[test]
    fn access_in_nested_position() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { [principal.a].isEmpty() };"#), @"
         ⚠ attribute `a` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { [principal.a].isEmpty() };
          ·                                             ───────────
          ╰────
         help: if `a` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has a &&`
        ");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { {x: principal.a}.x > 0 };"#), @"
         ⚠ attribute `a` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { {x: principal.a}.x > 0 };
          ·                                                ───────────
          ╰────
         help: if `a` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has a &&`
        ");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { ip(principal.addr).isLoopback() };"#), @"
         ⚠ attribute `addr` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { ip(principal.addr).isLoopback() };
          ·                                               ──────────────
          ╰────
         help: if `addr` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has addr &&`
        ");
    }

    /// Both operands of a binary operator are evaluated eagerly, so a `has` in
    /// one does not guard the other.
    #[test]
    fn binary_operand_does_not_guard() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { (principal has a) == principal.a };"#), @"
         ⚠ attribute `a` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal, action, resource) when { (principal has a) == principal.a };
          ·                                                                 ───────────
          ╰────
         help: if `a` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has a &&`
        ");
    }

    /// A `forbid` with no attribute access at all is fine, as is one with no
    /// conditions.
    #[test]
    fn nothing_to_report() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource);"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal == User::"alice", action, resource) when { 1 > 0 };"#), @"");
    }

    /// Templates are linted the same as static policies, and a slot is an
    /// ordinary target expression.
    #[test]
    fn template() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal == ?principal, action, resource) when { principal has a && principal.a };"#),
            @"");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal == ?principal, action, resource) when { principal.a };"#), @"
         ⚠ attribute `a` is accessed in a `forbid` policy without a `has` guard
          ╭────
        1 │ forbid(principal == ?principal, action, resource) when { principal.a };
          ·                                                          ───────────
          ╰────
         help: if `a` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `principal has a &&`
        ");
    }
}
