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

//! Flags an attribute/tag access chain deeper than a configured bound.
//!
//! ```cedar
//! permit(principal, action, resource)
//! when { principal.manager.department.owner.email == "root@x.com" };
//! ```
//!
//! Each `.attr` / `getTag` step on an entity is a store lookup at evaluation time
//! and a dereference the analyzer must follow. Bounding chain depth caps
//! per-evaluation lookups and keeps a policy within a fixed reasoning horizon. This
//! is a `Restriction` — deep chains are legal and sometimes intended — off by
//! default and with a configurable bound.
//!
//! # Relationship to level validation (RFC 76), and why this is sound
//!
//! RFC 76 level validation counts *entity dereferences* — steps that read an
//! attribute/tag off an **entity** — from a request-variable root, and rejects a
//! policy that exceeds `max_deref_level`. Attribute access on a **record** is not a
//! dereference, and dereferencing an entity **literal** is forbidden outright.
//!
//! Without a schema this lint cannot tell an entity-attribute access from a
//! record-field access, so it *over-approximates*: it counts **every** `.attr` /
//! `getTag` step in a root-anchored chain as if it were an entity dereference.
//! Because the true entity-deref count is a subset of the steps counted here, the
//! lint's depth is an **upper bound** on the RFC 76 level. Therefore a policy this
//! lint accepts at bound `N` is guaranteed to pass level validation at
//! `max_deref_level = N`. It may be *stricter* (flagging a chain of record-field
//! accesses that costs zero entity derefs), which is acceptable for an opt-in
//! restriction and noted in the help.
//!
//! # What is measured
//!
//! The depth of a chain is the number of `.attr` (`GetAttr`) and `getTag`
//! (`BinaryOp::GetTag`) steps stacked on one another. `principal.a` is depth 1,
//! `principal.a.b.c` is depth 3, `resource.getTag("x").y` is depth 2. The chain
//! root is irrelevant to the count (a variable, a literal, a record — each is
//! depth 0), which keeps the count an upper bound without modelling the root's
//! type. The outermost node of each maximal chain over the bound is reported once;
//! a `getTag`'s key expression is linted as its own chain.

use crate::{
    ast::{BinaryOp, Expr, ExprKind, Template},
    linter::{
        findings::{AttributeTooDeep, Finding},
        util::direct_children,
    },
};

/// The number of stacked attribute/tag access steps at the top of the chain
/// rooted at `expr`. A non-access expression is depth 0.
fn access_depth(expr: &Expr) -> usize {
    match expr.expr_kind() {
        ExprKind::GetAttr { expr: target, .. } => 1 + access_depth(target),
        ExprKind::BinaryApp {
            op: BinaryOp::GetTag,
            arg1: target,
            ..
        } => 1 + access_depth(target),
        _ => 0,
    }
}

#[derive(Debug, Default)]
pub(crate) struct AttributeDepthLinter {
    bound: usize,
    findings: Vec<Finding>,
}

impl AttributeDepthLinter {
    /// A linter reporting chains deeper than `bound`.
    pub(crate) fn new(bound: usize) -> Self {
        Self {
            bound,
            findings: Vec::new(),
        }
    }

    /// Lint `template`'s whole condition (scope-derived accesses are only against
    /// the bare variables, so they never exceed a bound of 0 or more).
    pub(crate) fn lint(&mut self, template: &Template) {
        self.walk(&template.condition(), false);
        self.findings
            .sort_by_key(|f| f.source_loc().map(|l| l.span.offset()));
    }

    /// Consume this linter, returning the findings it accumulated.
    pub(crate) fn into_findings(self) -> Vec<Finding> {
        self.findings
    }

    /// Walk `expr`. `in_chain` is true when `expr` is the target-spine descendant
    /// of an access node already measured, so it is part of a chain whose top was
    /// already considered and must not be measured again. Branches *off* the spine
    /// (a `getTag` key, operator operands, set elements) are walked afresh.
    fn walk(&mut self, expr: &Expr, in_chain: bool) {
        match expr.expr_kind() {
            ExprKind::GetAttr { expr: target, .. } => {
                if !in_chain {
                    let depth = access_depth(expr);
                    if depth > self.bound {
                        self.report(expr, depth);
                    }
                }
                // The spine continues through the target.
                self.walk(target, true);
            }
            ExprKind::BinaryApp {
                op: BinaryOp::GetTag,
                arg1: target,
                arg2: key,
            } => {
                if !in_chain {
                    let depth = access_depth(expr);
                    if depth > self.bound {
                        self.report(expr, depth);
                    }
                }
                self.walk(target, true);
                // The tag key is its own expression, not part of this chain.
                self.walk(key, false);
            }
            // Any other node ends a chain: its children start fresh chains.
            _ => {
                for child in direct_children(expr) {
                    self.walk(child, false);
                }
            }
        }
    }

    fn report(&mut self, expr: &Expr, depth: usize) {
        self.findings.push(
            AttributeTooDeep {
                loc: expr.source_loc().cloned(),
                depth,
                bound: self.bound,
            }
            .into(),
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_policy_or_template;

    #[track_caller]
    fn lint_report(bound: usize, src: &str) -> String {
        let template = parse_policy_or_template(None, src).expect("failed to parse");
        let mut linter = AttributeDepthLinter::new(bound);
        linter.lint(&template);
        render(&linter.into_findings())
    }

    #[test]
    fn chain_over_bound() {
        insta::assert_snapshot!(lint_report(2,
            r#"permit(principal, action, resource) when { principal.manager.department.owner == resource.owner };"#), @"
         ⚠ access chain is 3 levels deep, over the bound of 2
          ╭────
        1 │ permit(principal, action, resource) when { principal.manager.department.owner == resource.owner };
          ·                                            ──────────────────────────────────
          ╰────
         help: each attribute or tag access on an entity is a store lookup at evaluation time and a dereference the analyzer must follow; a shallower chain (e.g. denormalizing the value onto a nearer
               entity) keeps evaluation and analysis within a fixed bound. This counts syntactic access depth, so it is an upper bound on the RFC 76 entity-dereference level
        ");
    }

    /// A chain exactly at the bound is fine.
    #[test]
    fn chain_at_bound_is_fine() {
        insta::assert_snapshot!(lint_report(2,
            r#"permit(principal, action, resource) when { principal.a.b == 1 };"#), @"");
    }

    /// `getTag` steps count too.
    #[test]
    fn tag_access_counts() {
        insta::assert_snapshot!(lint_report(1,
            r#"permit(principal, action, resource) when { principal.team.getTag("role") == "admin" };"#), @r#"
         ⚠ access chain is 2 levels deep, over the bound of 1
          ╭────
        1 │ permit(principal, action, resource) when { principal.team.getTag("role") == "admin" };
          ·                                            ─────────────────────────────
          ╰────
         help: each attribute or tag access on an entity is a store lookup at evaluation time and a dereference the analyzer must follow; a shallower chain (e.g. denormalizing the value onto a nearer
               entity) keeps evaluation and analysis within a fixed bound. This counts syntactic access depth, so it is an upper bound on the RFC 76 entity-dereference level
        "#);
    }

    /// Each independent chain over the bound is reported once; the outer chain is
    /// not double-counted with its inner sub-chains.
    #[test]
    fn two_chains() {
        insta::assert_snapshot!(lint_report(1,
            r#"permit(principal, action, resource) when { principal.a.b == resource.c.d };"#), @"
         ⚠ access chain is 2 levels deep, over the bound of 1
          ╭────
        1 │ permit(principal, action, resource) when { principal.a.b == resource.c.d };
          ·                                            ─────────────
          ╰────
         help: each attribute or tag access on an entity is a store lookup at evaluation time and a dereference the analyzer must follow; a shallower chain (e.g. denormalizing the value onto a nearer
               entity) keeps evaluation and analysis within a fixed bound. This counts syntactic access depth, so it is an upper bound on the RFC 76 entity-dereference level

         ⚠ access chain is 2 levels deep, over the bound of 1
          ╭────
        1 │ permit(principal, action, resource) when { principal.a.b == resource.c.d };
          ·                                                             ────────────
          ╰────
         help: each attribute or tag access on an entity is a store lookup at evaluation time and a dereference the analyzer must follow; a shallower chain (e.g. denormalizing the value onto a nearer
               entity) keeps evaluation and analysis within a fixed bound. This counts syntactic access depth, so it is an upper bound on the RFC 76 entity-dereference level
        ");
    }

    /// A shallow access is fine.
    #[test]
    fn shallow_is_fine() {
        insta::assert_snapshot!(lint_report(2,
            r#"permit(principal, action, resource) when { principal.name == "x" };"#), @"");
    }

    /// The `getTag` key is linted as its own chain, so a deep key is caught even
    /// when the outer chain is shallow.
    #[test]
    fn tag_key_is_its_own_chain() {
        insta::assert_snapshot!(lint_report(2,
            r#"permit(principal, action, resource) when { resource.getTag(principal.a.b.c) == "x" };"#), @r#"
         ⚠ access chain is 3 levels deep, over the bound of 2
          ╭────
        1 │ permit(principal, action, resource) when { resource.getTag(principal.a.b.c) == "x" };
          ·                                                            ───────────────
          ╰────
         help: each attribute or tag access on an entity is a store lookup at evaluation time and a dereference the analyzer must follow; a shallower chain (e.g. denormalizing the value onto a nearer
               entity) keeps evaluation and analysis within a fixed bound. This counts syntactic access depth, so it is an upper bound on the RFC 76 entity-dereference level
        "#);
    }
}
