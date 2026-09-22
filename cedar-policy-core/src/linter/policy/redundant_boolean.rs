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

//! Flags boolean-valued expressions written the long way round.
//!
//! | Written | Prefer |
//! | --- | --- |
//! | `a == true` | `a` |
//! | `a == false` | `!a` |
//! | `if c then true else false` | `c` |
//! | `if c then false else true` | `!c` |
//!
//! Each is a pure rewrite: both forms evaluate identically for every input,
//! including when the operand errors.
//!
//! This pass reads the AST, unlike its sibling [`sugar`](super::sugar), which has
//! to read the CST. The distinction is whether the parser rewrites the construct:
//! it turns `a != b` into `!(a == b)`, so telling those apart needs the CST, but
//! it leaves `a == true` and `if c then true else false` exactly as written. Since
//! the AST is enough here, this pass uses it — it needs no new plumbing and gets
//! the desugaring of `!=` and `>` for free, so `a != true` is reported too.
//!
//! Note the `==` cases are rewrites rather than pure redundancies. `a == true` is
//! equivalent to `a` only when `a` is a boolean; if `a` is not, `a == true` is
//! `false` while `a` alone is a type error. The types lint reports that
//! separately, and the suggested rewrite is what the author meant either way.

use crate::{
    ast::{BinaryOp, Expr, ExprKind, Literal, UnaryOp},
    linter::findings::{Finding, RedundantBoolean},
};

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct RedundantBooleanLinter {
    findings: Vec<Finding>,
}

/// If `expr` is `x == <bool>` (either operand), that boolean.
///
/// `true == false` yields `None`: that is a constant expression, not a rewrite of
/// an operand, and belongs to a lint about constant conditions.
fn eq_against_bool(expr: &Expr) -> Option<bool> {
    let ExprKind::BinaryApp {
        op: BinaryOp::Eq,
        arg1,
        arg2,
    } = expr.expr_kind()
    else {
        return None;
    };
    match (bool_literal(arg1), bool_literal(arg2)) {
        (Some(_), Some(_)) | (None, None) => None,
        (Some(b), None) | (None, Some(b)) => Some(b),
    }
}

/// The value of `expr` if it is exactly a boolean literal.
fn bool_literal(expr: &Expr) -> Option<bool> {
    match expr.expr_kind() {
        ExprKind::Lit(Literal::Bool(b)) => Some(*b),
        _ => None,
    }
}

/// What a comparison against the boolean `b` should be replaced with, where
/// `negated` says whether an enclosing `!` applies.
///
/// `a == true` is `a` and `a == false` is `!a`; a `!` around either flips it.
fn suggestion_for(b: bool, negated: bool) -> (&'static str, &'static str) {
    let wrote = if negated {
        if b {
            "comparing against `true` under a `!`"
        } else {
            "comparing against `false` under a `!`"
        }
    } else if b {
        "comparing against `true`"
    } else {
        "comparing against `false`"
    };
    if b == !negated {
        (wrote, "the operand on its own")
    } else {
        (wrote, "`!` on the operand")
    }
}

impl RedundantBooleanLinter {
    /// Lint `expr`, reporting every redundant boolean construct within it.
    pub(crate) fn lint(&mut self, expr: &Expr) {
        let mut found = Vec::new();
        Self::walk(expr, &mut found);
        // Report the way the policy reads.
        found.sort_by_key(|(e, _, _): &(&Expr, _, _)| e.source_loc().map(|l| l.span.offset()));
        for (e, wrote, prefer) in found {
            self.findings.push(
                RedundantBoolean {
                    loc: e.source_loc().cloned(),
                    wrote: wrote.to_string(),
                    prefer: prefer.to_string(),
                }
                .into(),
            );
        }
    }

    /// Walk `expr`, collecting findings.
    ///
    /// A `!` has to be considered together with the comparison inside it, because
    /// it flips the advice: `a != true` desugars to `!(a == true)`, where the right
    /// rewrite is `!a`, not `a`. Reporting the inner `==` alone would print a span
    /// covering the whole `!=` beside advice for just its inside.
    ///
    /// So negated comparisons are reported on the outer `!` node, and the inner
    /// `==` is recorded as already handled rather than reported again.
    fn walk<'a>(expr: &'a Expr, out: &mut Vec<(&'a Expr, &'static str, &'static str)>) {
        // Comparisons that a `!` above them already accounted for, by pointer, so
        // that an identical comparison elsewhere is still reported.
        let mut handled: Vec<*const Expr> = Vec::new();

        for e in expr.subexpressions() {
            match e.expr_kind() {
                ExprKind::UnaryApp {
                    op: UnaryOp::Not,
                    arg,
                } => {
                    if let Some(b) = eq_against_bool(arg) {
                        let (wrote, prefer) = suggestion_for(b, true);
                        out.push((e, wrote, prefer));
                        handled.push(std::ptr::from_ref::<Expr>(arg));
                    }
                }
                ExprKind::BinaryApp { .. } => {
                    if handled.contains(&std::ptr::from_ref::<Expr>(e)) {
                        continue;
                    }
                    if let Some(b) = eq_against_bool(e) {
                        let (wrote, prefer) = suggestion_for(b, false);
                        out.push((e, wrote, prefer));
                    }
                }
                // `if c then true else false` is `c`, and the mirror is `!c`.
                ExprKind::If {
                    then_expr,
                    else_expr,
                    ..
                } => match (bool_literal(then_expr), bool_literal(else_expr)) {
                    (Some(true), Some(false)) => out.push((
                        e,
                        "`if .. then true else false`",
                        "the condition on its own",
                    )),
                    (Some(false), Some(true)) => {
                        out.push((e, "`if .. then false else true`", "`!` on the condition"))
                    }
                    _ => {}
                },
                _ => {}
            }
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
        let mut linter = RedundantBooleanLinter::default();
        if let Some(conditions) = template.non_scope_constraints() {
            linter.lint(conditions);
        }
        render(&linter.into_findings())
    }

    #[test]
    fn compare_to_true() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a == true };"#), @"
         ⚠ comparing against `true` is redundant
          ╭────
        1 │ permit(principal, action, resource) when { context.a == true };
          ·                                            ─────────────────
          ╰────
         help: write the operand on its own instead; the two are equivalent for every input
        ");
    }

    #[test]
    fn compare_to_false() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a == false };"#), @"
         ⚠ comparing against `false` is redundant
          ╭────
        1 │ permit(principal, action, resource) when { context.a == false };
          ·                                            ──────────────────
          ╰────
         help: write `!` on the operand instead; the two are equivalent for every input
        ");
    }

    /// The literal may be on either side.
    #[test]
    fn reversed() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { true == context.a };"#), @"
         ⚠ comparing against `true` is redundant
          ╭────
        1 │ permit(principal, action, resource) when { true == context.a };
          ·                                            ─────────────────
          ╰────
         help: write the operand on its own instead; the two are equivalent for every input
        ");
    }

    /// `a != true` desugars to `!(a == true)`, so the AST pass catches it for
    /// free — one of the reasons this lint doesn't need the CST.
    #[test]
    fn not_equal_to_bool() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a != true };"#), @"
         ⚠ comparing against `true` under a `!` is redundant
          ╭────
        1 │ permit(principal, action, resource) when { context.a != true };
          ·                                            ─────────────────
          ╰────
         help: write `!` on the operand instead; the two are equivalent for every input
        ");
    }

    #[test]
    fn if_returning_booleans() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { if context.a then true else false };"#), @"
         ⚠ `if .. then true else false` is redundant
          ╭────
        1 │ permit(principal, action, resource) when { if context.a then true else false };
          ·                                            ─────────────────────────────────
          ╰────
         help: write the condition on its own instead; the two are equivalent for every input
        ");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { if context.a then false else true };"#), @"
         ⚠ `if .. then false else true` is redundant
          ╭────
        1 │ permit(principal, action, resource) when { if context.a then false else true };
          ·                                            ─────────────────────────────────
          ╰────
         help: write `!` on the condition instead; the two are equivalent for every input
        ");
    }

    /// An `if` with a branch that does real work is left alone.
    #[test]
    fn ordinary_if() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { if context.a then context.b else false };"#),
            @"");
    }

    /// Comparing against a non-boolean literal is an ordinary comparison.
    #[test]
    fn non_boolean_literal() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a == 1 };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a == "x" };"#), @"");
    }

    /// Two boolean literals is a constant expression, not a rewrite of an
    /// operand, so this lint stays out of it.
    #[test]
    fn both_operands_literal() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { true == false };"#), @"");
    }

    /// Found nested inside other expressions and in `unless` clauses.
    #[test]
    fn nested_and_in_unless() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.b && context.a == true };"#), @"
         ⚠ comparing against `true` is redundant
          ╭────
        1 │ permit(principal, action, resource) when { context.b && context.a == true };
          ·                                                         ─────────────────
          ╰────
         help: write the operand on its own instead; the two are equivalent for every input
        ");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) unless { context.a == true };"#), @"
         ⚠ comparing against `true` under a `!` is redundant
          ╭────
        1 │ permit(principal, action, resource) unless { context.a == true };
          ·                                     ────────────────────────────
          ╰────
         help: write `!` on the operand instead; the two are equivalent for every input
        ");
    }

    /// Each occurrence is reported, in source order.
    #[test]
    fn multiple() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a == true && context.b == false };"#), @"
         ⚠ comparing against `true` is redundant
          ╭────
        1 │ permit(principal, action, resource) when { context.a == true && context.b == false };
          ·                                            ─────────────────
          ╰────
         help: write the operand on its own instead; the two are equivalent for every input

         ⚠ comparing against `false` is redundant
          ╭────
        1 │ permit(principal, action, resource) when { context.a == true && context.b == false };
          ·                                                                 ──────────────────
          ╰────
         help: write `!` on the operand instead; the two are equivalent for every input
        ");
    }

    #[test]
    fn nothing_to_report() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a && context.b > 2 };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource);"#), @"");
    }
}
