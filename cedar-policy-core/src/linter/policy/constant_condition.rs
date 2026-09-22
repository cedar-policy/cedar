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

//! Flags a constant expression used where a condition is expected, e.g.
//! `when { 1 > 2 }`.
//!
//! A condition that does not depend on the request or the entity store has the
//! same value for every request, so it is not really a condition. Either it is
//! dead code left behind — `when { false }` makes the policy never apply,
//! `unless { true }` likewise — or it is a placeholder someone forgot to fill in.
//! Both are worth surfacing.
//!
//! This mirrors clippy's `absurd_extreme_comparisons` and Regal's
//! `constant-condition`.
//!
//! # Where a condition is expected
//!
//! The whole of a `when`/`unless` clause, and every boolean *position* nested
//! within it: the operands of `&&`, `||`, and `!`, and the test of an `if`. A
//! constant that is merely an *operand* of a comparison — the `2` in
//! `context.n > 2` — is not a condition and is not reported; only a constant that
//! stands where a boolean decision belongs.
//!
//! Reporting the outermost constant position and not descending into it avoids
//! double-reporting: in `when { 1 > 2 && false }`, the `&&` is not itself
//! constant (its left side isn't), so each constant operand is reported once.
//!
//! # Scope constraints are not conditions
//!
//! This reads the `when`/`unless` clauses via `non_scope_constraints`, never the
//! whole `condition()`. The scope compiles to `true` for an unconstrained policy,
//! and reporting that would flag `permit(principal, action, resource)` — the most
//! ordinary policy there is.

use crate::{
    ast::{Expr, ExprKind, UnaryOp},
    linter::{findings::ConstantCondition, findings::Finding, util::is_constant},
};

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct ConstantConditionLinter {
    findings: Vec<Finding>,
}

impl ConstantConditionLinter {
    /// Lint the `when`/`unless` clauses `conditions`.
    pub(crate) fn lint(&mut self, conditions: &Expr) {
        // The clause body is itself a boolean position.
        self.check(conditions);
    }

    /// Consume this linter, returning the findings it accumulated.
    pub(crate) fn into_findings(self) -> Vec<Finding> {
        self.findings
    }

    /// Check `expr`, which stands in a boolean position, then recurse into the
    /// boolean positions it contains.
    ///
    /// If `expr` is itself constant it is reported and *not* descended into: the
    /// whole thing is dead, so reporting a constant sub-part too would be noise.
    fn check(&mut self, expr: &Expr) {
        if is_constant(expr) {
            self.findings.push(
                ConstantCondition {
                    loc: expr.source_loc().cloned(),
                }
                .into(),
            );
            return;
        }
        // Not constant itself; recurse into the boolean positions within it.
        match expr.expr_kind() {
            ExprKind::And { left, right } | ExprKind::Or { left, right } => {
                self.check(left);
                self.check(right);
            }
            ExprKind::UnaryApp {
                op: UnaryOp::Not,
                arg,
            } => self.check(arg),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                // The test is a boolean position; the branches are boolean
                // positions when the `if` is itself used as one, which it is here.
                self.check(test_expr);
                self.check(then_expr);
                self.check(else_expr);
            }
            // Any other operator is a leaf as far as boolean structure goes: its
            // operands are values, not conditions. A constant operand there (the
            // `2` in `n > 2`) is not a dead condition.
            _ => {}
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_policy_or_template;

    /// Lint the conditions of `src` and return the pretty miette rendering of all
    /// findings. Rendered without color so the snapshots stay readable.
    #[track_caller]
    fn lint_report(src: &str) -> String {
        let template = parse_policy_or_template(None, src).expect("failed to parse");
        let mut linter = ConstantConditionLinter::default();
        if let Some(conditions) = template.non_scope_constraints() {
            linter.lint(conditions);
        }
        render(&linter.into_findings())
    }

    #[test]
    fn literal_true() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { true };"#), @"
         ⚠ this condition is constant
          ╭────
        1 │ permit(principal, action, resource) when { true };
          ·                                            ────
          ╰────
         help: it does not depend on the request, so it is the same for every one; remove it, or replace it with the intended condition
        ");
    }

    #[test]
    fn literal_false() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { false };"#), @"
         ⚠ this condition is constant
          ╭────
        1 │ permit(principal, action, resource) when { false };
          ·                                            ─────
          ╰────
         help: it does not depend on the request, so it is the same for every one; remove it, or replace it with the intended condition
        ");
    }

    #[test]
    fn constant_comparison() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { 1 > 2 };"#), @"
         ⚠ this condition is constant
          ╭────
        1 │ permit(principal, action, resource) when { 1 > 2 };
          ·                                            ─────
          ╰────
         help: it does not depend on the request, so it is the same for every one; remove it, or replace it with the intended condition
        ");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { "a" == "b" };"#), @r#"
         ⚠ this condition is constant
          ╭────
        1 │ permit(principal, action, resource) when { "a" == "b" };
          ·                                            ──────────
          ╰────
         help: it does not depend on the request, so it is the same for every one; remove it, or replace it with the intended condition
        "#);
    }

    /// A constant `unless` is dead in the other direction.
    #[test]
    fn constant_unless() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) unless { true };"#), @"
         ⚠ this condition is constant
          ╭────
        1 │ permit(principal, action, resource) unless { true };
          ·                                     ───────────────
          ╰────
         help: it does not depend on the request, so it is the same for every one; remove it, or replace it with the intended condition
        ");
    }

    /// A constant operand of a `&&` is reported; the whole `&&` is not constant
    /// because the other side varies.
    #[test]
    fn constant_operand_of_and() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { false && context.a };"#), @"
         ⚠ this condition is constant
          ╭────
        1 │ permit(principal, action, resource) when { false && context.a };
          ·                                            ─────
          ╰────
         help: it does not depend on the request, so it is the same for every one; remove it, or replace it with the intended condition
        ");
    }

    /// A constant `if` test.
    #[test]
    fn constant_if_test() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { if true then context.a else context.b };"#), @"
         ⚠ this condition is constant
          ╭────
        1 │ permit(principal, action, resource) when { if true then context.a else context.b };
          ·                                               ────
          ╰────
         help: it does not depend on the request, so it is the same for every one; remove it, or replace it with the intended condition
        ");
    }

    /// A whole constant condition is reported once, not once per constant part.
    #[test]
    fn whole_constant_reported_once() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { 1 > 2 && true };"#), @"
         ⚠ this condition is constant
          ╭────
        1 │ permit(principal, action, resource) when { 1 > 2 && true };
          ·                                            ─────────────
          ╰────
         help: it does not depend on the request, so it is the same for every one; remove it, or replace it with the intended condition
        ");
    }

    /// A constant that is merely an operand of a comparison is not a condition.
    #[test]
    fn constant_operand_is_not_a_condition() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.n > 2 };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.role == "admin" };"#), @"");
    }

    /// An unconstrained scope compiles to `true`, but that is not a condition the
    /// author wrote, so it is not reported.
    #[test]
    fn unconstrained_scope_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource);"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal == User::"alice", action, resource);"#), @"");
    }

    /// An ordinary condition that depends on the request is fine.
    #[test]
    fn ordinary_condition() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal.admin && context.mfa };"#), @"");
    }

    /// Each constant condition is reported, in source order.
    #[test]
    fn multiple() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { true && context.a && 1 > 2 };"#), @"
         ⚠ this condition is constant
          ╭────
        1 │ permit(principal, action, resource) when { true && context.a && 1 > 2 };
          ·                                            ────
          ╰────
         help: it does not depend on the request, so it is the same for every one; remove it, or replace it with the intended condition

         ⚠ this condition is constant
          ╭────
        1 │ permit(principal, action, resource) when { true && context.a && 1 > 2 };
          ·                                                                 ─────
          ╰────
         help: it does not depend on the request, so it is the same for every one; remove it, or replace it with the intended condition
        ");
    }
}
