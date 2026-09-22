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

//! Flags arithmetic negation applied twice, as in `- -x`.
//!
//! Negating twice computes the operand back again, so the expression says nothing
//! that `x` alone does not. That makes it very likely the author meant something
//! else — a subtraction whose left operand went missing (`a - -b` mistyped as
//! `- -b`), or a logical `!` rather than an arithmetic `-`.
//!
//! This is a correctness warning rather than a style one, for two reasons.
//!
//! First, it is not a redundancy that can simply be deleted. Cedar's negation is
//! checked, so `-i64::MIN` errors rather than wrapping. `- -x` therefore does *not*
//! evaluate to `x` for every input: at `x = i64::MIN` the inner negation errors,
//! the condition errors, and the policy is skipped — in a `forbid` that fails open.
//! So the doubled negation adds a failure mode while computing nothing, which is
//! strictly worse than writing `x`.
//!
//! Second, the shape itself signals a mistake. A single `-` is meaningful and a
//! `!` is meaningful, but nobody negates twice on purpose.
//!
//! # Relationship to other lints
//!
//! [`ErroringArithmetic`](crate::linter::Lint::ErroringArithmetic) also flags these
//! expressions, but for the generic reason that any negation can overflow, and only
//! when it is enabled — it is in the `Restriction` group and off by default,
//! because it rules out arithmetic in conditions wholesale. This lint is narrower
//! and on by default: it fires only on the doubled form, which has no legitimate
//! use, so it costs nothing to leave on.
//!
//! [`sugar`](super::sugar) reports repeated logical `!`, which is a genuine
//! rewrite (`!!x` really is `x` for every input, since `!` cannot error). The two
//! are separate findings because the advice differs: `!!x` should become `x`, while
//! `- -x` should be re-examined.

use crate::{
    ast::{Expr, ExprKind, Literal, UnaryOp},
    linter::findings::{DoubleNegation, Finding},
};

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct DoubleNegationLinter {
    findings: Vec<Finding>,
}

/// Is `expr` an arithmetic negation of something that is itself negative?
///
/// Two shapes reach here, because the parser folds a negated literal into a single
/// negative `Long`:
///
/// * `- -x` for a non-literal `x` is `Neg(Neg(x))`.
/// * `- -5` is `Neg(Lit(-5))`, since the inner `-5` became the literal.
///
/// A single negation of a positive literal (`-5`) is just a negative number and is
/// not reported.
fn is_double_negation(expr: &Expr) -> bool {
    let ExprKind::UnaryApp {
        op: UnaryOp::Neg,
        arg,
    } = expr.expr_kind()
    else {
        return false;
    };
    match arg.expr_kind() {
        ExprKind::UnaryApp {
            op: UnaryOp::Neg, ..
        } => true,
        ExprKind::Lit(Literal::Long(n)) => *n < 0,
        _ => false,
    }
}

impl DoubleNegationLinter {
    /// Lint `expr`, reporting every doubled arithmetic negation within it.
    pub(crate) fn lint(&mut self, expr: &Expr) {
        // Only the outermost negation of a run is reported. `- - -x` contains two
        // overlapping doubled pairs whose spans are identical, so reporting both
        // would print the same finding twice; one mention of the run is the useful
        // advice either way.
        let mut inner: Vec<*const Expr> = Vec::new();
        for e in expr.subexpressions() {
            if is_double_negation(e) {
                if let ExprKind::UnaryApp { arg, .. } = e.expr_kind() {
                    inner.push(std::ptr::from_ref::<Expr>(arg));
                }
            }
        }

        // `subexpressions` yields in reverse source order, so collect and sort to
        // report the way the policy reads.
        let mut found: Vec<&Expr> = expr
            .subexpressions()
            .filter(|e| is_double_negation(e))
            .filter(|e| !inner.contains(&std::ptr::from_ref::<Expr>(*e)))
            .collect();
        found.sort_by_key(|e| e.source_loc().map(|l| l.span.offset()));

        for e in found {
            self.findings.push(
                DoubleNegation {
                    loc: e.source_loc().cloned(),
                }
                .into(),
            );
        }
    }

    /// Consume this linter, returning the findings it accumulated.
    pub(crate) fn into_findings(self) -> Vec<Finding> {
        self.findings
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
        let mut linter = DoubleNegationLinter::default();
        if let Some(conditions) = template.non_scope_constraints() {
            linter.lint(conditions);
        }
        render(&linter.into_findings())
    }

    #[test]
    fn double_negation() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { - -context.a > 0 };"#), @"
         ⚠ negation applied twice
          ╭────
        1 │ permit(principal, action, resource) when { - -context.a > 0 };
          ·                                            ────────────
          ╰────
         help: negating twice computes the operand back again, and errors on `i64::MIN` where the operand alone would not; did you mean a subtraction, or the logical `!`?
        ");
    }

    /// Parenthesized, which parses to the same thing.
    #[test]
    fn parenthesized() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { -(-context.a) > 0 };"#), @"
         ⚠ negation applied twice
          ╭────
        1 │ permit(principal, action, resource) when { -(-context.a) > 0 };
          ·                                            ─────────────
          ╰────
         help: negating twice computes the operand back again, and errors on `i64::MIN` where the operand alone would not; did you mean a subtraction, or the logical `!`?
        ");
    }

    /// `- -5` is the literal case: the inner `-5` folds into a negative literal, so
    /// the outer `-` is still a doubled negation.
    #[test]
    fn double_negation_of_literal() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { - -5 > 0 };"#), @"
         ⚠ negation applied twice
          ╭────
        1 │ permit(principal, action, resource) when { - -5 > 0 };
          ·                                            ────
          ╰────
         help: negating twice computes the operand back again, and errors on `i64::MIN` where the operand alone would not; did you mean a subtraction, or the logical `!`?
        ");
    }

    /// Three negations contain two overlapping doubled pairs with identical spans,
    /// so the run is reported once rather than twice.
    #[test]
    fn triple_negation() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { - - -context.a > 0 };"#), @"
         ⚠ negation applied twice
          ╭────
        1 │ permit(principal, action, resource) when { - - -context.a > 0 };
          ·                                            ──────────────
          ╰────
         help: negating twice computes the operand back again, and errors on `i64::MIN` where the operand alone would not; did you mean a subtraction, or the logical `!`?
        ");
    }

    /// A single negation is ordinary arithmetic.
    #[test]
    fn single_negation_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { -context.a > 0 };"#), @"");
    }

    /// A negative literal is a number, not a doubled negation.
    #[test]
    fn negative_literal_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { -5 > 0 };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a > -5 };"#), @"");
    }

    /// Subtracting a negative is not a doubled negation: `a - -b` has a left
    /// operand and computes something the single-negation form does not.
    #[test]
    fn subtracting_a_negative_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a - -5 > 0 };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a + -5 > 0 };"#), @"");
    }

    /// Logical `!` is a different operator, reported by `sugar` instead.
    #[test]
    fn logical_negation_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !!context.a };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !context.a };"#), @"");
    }

    /// Found nested inside other expressions and in `unless` clauses.
    #[test]
    fn nested_and_in_unless() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.b && - -context.a > 0 };"#), @"
         ⚠ negation applied twice
          ╭────
        1 │ permit(principal, action, resource) when { context.b && - -context.a > 0 };
          ·                                                         ────────────
          ╰────
         help: negating twice computes the operand back again, and errors on `i64::MIN` where the operand alone would not; did you mean a subtraction, or the logical `!`?
        ");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) unless { - -context.a > 0 };"#), @"
         ⚠ negation applied twice
          ╭────
        1 │ permit(principal, action, resource) unless { - -context.a > 0 };
          ·                                              ────────────
          ╰────
         help: negating twice computes the operand back again, and errors on `i64::MIN` where the operand alone would not; did you mean a subtraction, or the logical `!`?
        ");
    }

    /// Each occurrence is reported, in source order.
    #[test]
    fn multiple() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { - -context.a > - -context.b };"#), @"
         ⚠ negation applied twice
          ╭────
        1 │ permit(principal, action, resource) when { - -context.a > - -context.b };
          ·                                            ────────────
          ╰────
         help: negating twice computes the operand back again, and errors on `i64::MIN` where the operand alone would not; did you mean a subtraction, or the logical `!`?

         ⚠ negation applied twice
          ╭────
        1 │ permit(principal, action, resource) when { - -context.a > - -context.b };
          ·                                                           ────────────
          ╰────
         help: negating twice computes the operand back again, and errors on `i64::MIN` where the operand alone would not; did you mean a subtraction, or the logical `!`?
        ");
    }

    #[test]
    fn nothing_to_report() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a - context.b > 0 };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource);"#), @"");
    }
}
