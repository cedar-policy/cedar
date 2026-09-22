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

//! Flags arithmetic in policy conditions, because arithmetic can error and a
//! policy whose condition errors is skipped.
//!
//! Cedar arithmetic is checked: `+`, `-`, and `*` all error on integer overflow
//! rather than wrapping. When a policy's condition errors, the authorizer
//! records the error but treats the policy as unsatisfied
//! (`ErrorHandling::Skip`), so the policy has no effect on the decision.
//!
//! For a `forbid` policy that is a security problem: the policy that was meant
//! to deny access is dropped, and if some `permit` matches, the request is
//! allowed. An attacker who controls the arithmetic operands may be able to
//! trigger the overflow deliberately.
//!
//! The same mechanism applies to `permit` policies, but skipping a `permit`
//! fails closed rather than open, so it is much less dangerous. Both are
//! reported as warnings, since neither is necessarily wrong: whether an overflow
//! is reachable depends on the data. The two are distinct findings so the
//! `forbid` case can be prioritized.
//!
//! Note this pass flags arithmetic that *could* error, not arithmetic that
//! definitely does. Proving an overflow impossible in general needs operand
//! ranges, which needs a schema.
//!
//! Fully constant arithmetic is excluded: its value is fixed, so it either
//! always overflows or never does, and either way no request can influence it.

use crate::{
    ast::{BinaryOp, Effect, Expr, ExprKind, Template, UnaryOp},
    linter::findings::{ArithmeticInForbid, ArithmeticInPermit, Finding},
    linter::util::is_constant_arithmetic,
};

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct ErroringForbidLinter {
    errors: Vec<Finding>,
}

/// Does this expression perform arithmetic that could error at evaluation time?
///
/// A fully constant expression is excluded: its value is fixed, so it either
/// always overflows or never does, and either way an attacker can't influence
/// it. A constant that does overflow is reported by a different lint.
fn is_fallible_arithmetic(expr: &Expr) -> bool {
    if is_constant_arithmetic(expr) {
        return false;
    }
    // The three arithmetic operators, plus negation, which overflows on
    // `i64::MIN`.
    matches!(
        expr.expr_kind(),
        ExprKind::BinaryApp {
            op: BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul,
            ..
        }
    ) || matches!(
        expr.expr_kind(),
        ExprKind::UnaryApp {
            op: UnaryOp::Neg,
            ..
        }
    )
}

impl ErroringForbidLinter {
    /// Consume this linter, returning the findings it accumulated.
    pub(crate) fn into_findings(self) -> Vec<Finding> {
        self.errors
    }
    pub(crate) fn lint(&mut self, template: &Template) {
        let condition = template.condition();
        // `subexpressions` yields subexpressions in reverse source order, so
        // sort to report findings the way the policy reads.
        let mut arith: Vec<&Expr> = condition
            .subexpressions()
            .filter(|e| is_fallible_arithmetic(e))
            .collect();
        arith.sort_by_key(|e| e.source_loc().map(|l| l.span.offset()));
        for e in arith {
            let loc = e.source_loc().cloned();
            self.errors.push(match template.effect() {
                Effect::Forbid => ArithmeticInForbid { loc }.into(),
                Effect::Permit => ArithmeticInPermit { loc }.into(),
            });
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_policy_or_template;

    /// Lint `src` and return the pretty miette rendering of all findings,
    /// concatenated. Rendered without color so the snapshots stay readable.
    #[track_caller]
    fn lint_report(src: &str) -> String {
        let template = parse_policy_or_template(None, src).expect("failed to parse");
        let mut linter = ErroringForbidLinter::default();
        linter.lint(&template);
        render(&linter.errors)
    }

    /// Arithmetic in a `forbid`: if it overflows the policy is skipped and the
    /// request may be permitted by some other policy.
    #[test]
    fn arithmetic_in_forbid() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { context.count + 1 > 10 };"#), @"
         ⚠ arithmetic in a `forbid` policy may cause the policy to be skipped
          ╭────
        1 │ forbid(principal, action, resource) when { context.count + 1 > 10 };
          ·                                            ─────────────────
          ╰────
         help: arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `forbid` may fail to deny a request; consider bounding the operands or moving the arithmetic into the
               data
        ");
    }

    /// The same construct in a `permit` fails closed, so it gets a distinct,
    /// lower-priority finding.
    #[test]
    fn arithmetic_in_permit() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.count + 1 > 10 };"#), @"
         ⚠ arithmetic in a `permit` policy may cause the policy to be skipped
          ╭────
        1 │ permit(principal, action, resource) when { context.count + 1 > 10 };
          ·                                            ─────────────────
          ╰────
         help: arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `permit` may fail to allow a request
        ");
    }

    /// All three arithmetic operators are flagged, as is negation, which
    /// overflows on `i64::MIN`.
    #[test]
    fn all_arithmetic_ops() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { context.a - context.b > 0 };"#), @"
         ⚠ arithmetic in a `forbid` policy may cause the policy to be skipped
          ╭────
        1 │ forbid(principal, action, resource) when { context.a - context.b > 0 };
          ·                                            ─────────────────────
          ╰────
         help: arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `forbid` may fail to deny a request; consider bounding the operands or moving the arithmetic into the
               data
        ");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { context.a * context.b > 0 };"#), @"
         ⚠ arithmetic in a `forbid` policy may cause the policy to be skipped
          ╭────
        1 │ forbid(principal, action, resource) when { context.a * context.b > 0 };
          ·                                            ─────────────────────
          ╰────
         help: arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `forbid` may fail to deny a request; consider bounding the operands or moving the arithmetic into the
               data
        ");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { -context.a > 0 };"#), @"
         ⚠ arithmetic in a `forbid` policy may cause the policy to be skipped
          ╭────
        1 │ forbid(principal, action, resource) when { -context.a > 0 };
          ·                                            ──────────
          ╰────
         help: arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `forbid` may fail to deny a request; consider bounding the operands or moving the arithmetic into the
               data
        ");
    }

    /// A policy with no arithmetic is fine.
    #[test]
    fn no_arithmetic() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { context.count > 10 };"#), @"");
        insta::assert_snapshot!(
            lint_report(r#"forbid(principal, action, resource);"#), @"");
    }

    /// Constant arithmetic isn't flagged: its value is fixed, so no request can
    /// influence whether it overflows.
    #[test]
    fn constant_arithmetic_not_flagged() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { 1 + 1 > 10 };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { -5 * (2 + 3) > 10 };"#), @"");
    }

    /// Only the non-constant part of a mixed expression is flagged.
    #[test]
    fn mixed_constant_and_non_constant() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { context.a + (1 + 2) > 10 };"#), @"
         ⚠ arithmetic in a `forbid` policy may cause the policy to be skipped
          ╭────
        1 │ forbid(principal, action, resource) when { context.a + (1 + 2) > 10 };
          ·                                            ───────────────────
          ╰────
         help: arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `forbid` may fail to deny a request; consider bounding the operands or moving the arithmetic into the
               data
        ");
    }

    /// Arithmetic anywhere in the condition is found, including in `unless`
    /// clauses and nested inside other expressions.
    #[test]
    fn arithmetic_in_unless() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) unless { context.a + 1 > 10 };"#), @"
         ⚠ arithmetic in a `forbid` policy may cause the policy to be skipped
          ╭────
        1 │ forbid(principal, action, resource) unless { context.a + 1 > 10 };
          ·                                              ─────────────
          ╰────
         help: arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `forbid` may fail to deny a request; consider bounding the operands or moving the arithmetic into the
               data
        ");
    }

    #[test]
    fn nested_arithmetic() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { {total: context.a + 1}.total > 0 };"#), @"
         ⚠ arithmetic in a `forbid` policy may cause the policy to be skipped
          ╭────
        1 │ forbid(principal, action, resource) when { {total: context.a + 1}.total > 0 };
          ·                                                    ─────────────
          ╰────
         help: arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `forbid` may fail to deny a request; consider bounding the operands or moving the arithmetic into the
               data
        ");
    }

    /// Each arithmetic operation is reported separately.
    #[test]
    fn multiple_arithmetic() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { context.a + 1 > context.b - 1 };"#), @"
         ⚠ arithmetic in a `forbid` policy may cause the policy to be skipped
          ╭────
        1 │ forbid(principal, action, resource) when { context.a + 1 > context.b - 1 };
          ·                                            ─────────────
          ╰────
         help: arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `forbid` may fail to deny a request; consider bounding the operands or moving the arithmetic into the
               data

         ⚠ arithmetic in a `forbid` policy may cause the policy to be skipped
          ╭────
        1 │ forbid(principal, action, resource) when { context.a + 1 > context.b - 1 };
          ·                                                            ─────────────
          ╰────
         help: arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `forbid` may fail to deny a request; consider bounding the operands or moving the arithmetic into the
               data
        ");
    }

    /// Templates are linted the same as static policies.
    #[test]
    fn template() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal == ?principal, action, resource) when { context.a + 1 > 0 };"#), @"
         ⚠ arithmetic in a `forbid` policy may cause the policy to be skipped
          ╭────
        1 │ forbid(principal == ?principal, action, resource) when { context.a + 1 > 0 };
          ·                                                          ─────────────
          ╰────
         help: arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `forbid` may fail to deny a request; consider bounding the operands or moving the arithmetic into the
               data
        ");
    }
}
