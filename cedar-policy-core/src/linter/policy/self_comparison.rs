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

//! Flags a comparison whose two operands are syntactically identical, e.g.
//! `principal == principal`.
//!
//! Comparing a value to itself is almost always a mistake — a mistyped operand,
//! or a copy-paste that was meant to be edited. What it *does* at runtime varies,
//! which is the point: this is a bug whatever the outcome.
//!
//! * `principal == principal` is always `true`.
//! * `context.a == context.a` **errors** if `a` is absent, so the policy is
//!   skipped rather than being trivially true.
//! * `principal <= principal` is a type error — entities are not ordered.
//!
//! Rather than try to say which, the finding reports the shape: the same
//! expression on both sides. This mirrors clippy's `eq_op`, which likewise flags
//! the syntactic redundancy rather than claiming a value.
//!
//! # What is covered
//!
//! The relational operators `==`, `<`, `<=`, and the hierarchy operator `in`. The
//! parser desugars `!=` to `!(==)`, `>` to `!(<=)`, and `>=` to `!(<)`, so
//! checking the three it keeps also covers those three. `a in a` is included: an
//! entity is always a member of itself, so it is always `true` and says nothing.
//!
//! The finding does not name the operator, precisely because of that desugaring:
//! `a > a` reaches the AST as `!(a <= a)`, so the operator seen here is `<=`, not
//! the `>` the author wrote. The span shows the real source, so the operator name
//! would add nothing and occasionally mislead.
//!
//! Logical `&&` and `||` with identical operands (`a && a`) are *not* here — that
//! is [`redundant_expr`](super::redundant_expr), which frames it as a
//! simplification rather than a comparison mistake.
//!
//! Operands are compared by shape via [`ExprShapeOnly`], so source locations do
//! not participate: `principal.a == principal.a` matches, but two textually
//! different expressions that happen to be equal at runtime do not.

use crate::{
    ast::{BinaryOp, Expr, ExprKind, ExprShapeOnly},
    linter::{
        findings::{Finding, SelfComparison},
        util::scan,
    },
};

/// Lint `expr`, reporting every self-comparison within it.
pub(crate) fn lint(expr: &Expr) -> Vec<Finding> {
    scan(expr, |e| {
        let ExprKind::BinaryApp {
            op: BinaryOp::Eq | BinaryOp::Less | BinaryOp::LessEq | BinaryOp::In,
            arg1,
            arg2,
        } = e.expr_kind()
        else {
            return None;
        };
        (ExprShapeOnly::new_from_borrowed(arg1) == ExprShapeOnly::new_from_borrowed(arg2)).then(
            || {
                SelfComparison {
                    loc: e.source_loc().cloned(),
                }
                .into()
            },
        )
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_expr;

    /// Lint `src` and return the pretty miette rendering of all findings.
    #[track_caller]
    fn lint_report(src: &str) -> String {
        let expr = parse_expr(src).expect("failed to parse");
        render(&lint(&expr))
    }

    #[test]
    fn equality_of_a_variable() {
        insta::assert_snapshot!(lint_report(r#"principal == principal"#), @"
         ⚠ both operands of this comparison are the same expression
          ╭────
        1 │ principal == principal
          · ──────────────────────
          ╰────
         help: comparing a value to itself is redundant; did you mean to compare it to something else?
        ");
    }

    #[test]
    fn equality_of_an_attribute() {
        insta::assert_snapshot!(lint_report(r#"principal.a == principal.a"#), @"
         ⚠ both operands of this comparison are the same expression
          ╭────
        1 │ principal.a == principal.a
          · ──────────────────────────
          ╰────
         help: comparing a value to itself is redundant; did you mean to compare it to something else?
        ");
    }

    #[test]
    fn ordering() {
        insta::assert_snapshot!(lint_report(r#"context.n <= context.n"#), @"
         ⚠ both operands of this comparison are the same expression
          ╭────
        1 │ context.n <= context.n
          · ──────────────────────
          ╰────
         help: comparing a value to itself is redundant; did you mean to compare it to something else?
        ");
        insta::assert_snapshot!(lint_report(r#"context.n < context.n"#), @"
         ⚠ both operands of this comparison are the same expression
          ╭────
        1 │ context.n < context.n
          · ─────────────────────
          ╰────
         help: comparing a value to itself is redundant; did you mean to compare it to something else?
        ");
    }

    #[test]
    fn membership() {
        insta::assert_snapshot!(lint_report(r#"principal in principal"#), @"
         ⚠ both operands of this comparison are the same expression
          ╭────
        1 │ principal in principal
          · ──────────────────────
          ╰────
         help: comparing a value to itself is redundant; did you mean to compare it to something else?
        ");
    }

    /// `!=`, `>`, `>=` desugar to a negation of one of the checked operators, so
    /// they are covered too.
    #[test]
    fn desugared_operators() {
        insta::assert_snapshot!(lint_report(r#"principal != principal"#), @"
         ⚠ both operands of this comparison are the same expression
          ╭────
        1 │ principal != principal
          · ──────────────────────
          ╰────
         help: comparing a value to itself is redundant; did you mean to compare it to something else?
        ");
        insta::assert_snapshot!(lint_report(r#"context.n > context.n"#), @"
         ⚠ both operands of this comparison are the same expression
          ╭────
        1 │ context.n > context.n
          · ─────────────────────
          ╰────
         help: comparing a value to itself is redundant; did you mean to compare it to something else?
        ");
        insta::assert_snapshot!(lint_report(r#"context.n >= context.n"#), @"
         ⚠ both operands of this comparison are the same expression
          ╭────
        1 │ context.n >= context.n
          · ──────────────────────
          ╰────
         help: comparing a value to itself is redundant; did you mean to compare it to something else?
        ");
    }

    /// Different operands are the normal case.
    #[test]
    fn different_operands_are_not_reported() {
        insta::assert_snapshot!(lint_report(r#"principal == resource"#), @"");
        insta::assert_snapshot!(lint_report(r#"principal.a == principal.b"#), @"");
        insta::assert_snapshot!(lint_report(r#"context.n < context.m"#), @"");
    }

    /// Equal *values* reached by different syntax are not a self-comparison: the
    /// check is syntactic.
    #[test]
    fn syntactically_different_is_not_reported() {
        insta::assert_snapshot!(lint_report(r#"principal.a == principal["a"]"#), @r#"
         ⚠ both operands of this comparison are the same expression
          ╭────
        1 │ principal.a == principal["a"]
          · ─────────────────────────────
          ╰────
         help: comparing a value to itself is redundant; did you mean to compare it to something else?
        "#);
    }

    /// Found nested inside a larger condition.
    #[test]
    fn nested() {
        insta::assert_snapshot!(lint_report(r#"context.ok && principal == principal"#), @"
         ⚠ both operands of this comparison are the same expression
          ╭────
        1 │ context.ok && principal == principal
          ·               ──────────────────────
          ╰────
         help: comparing a value to itself is redundant; did you mean to compare it to something else?
        ");
    }

    /// Each self-comparison is reported, in source order.
    #[test]
    fn multiple() {
        insta::assert_snapshot!(lint_report(r#"principal == principal && resource == resource"#), @"
         ⚠ both operands of this comparison are the same expression
          ╭────
        1 │ principal == principal && resource == resource
          · ──────────────────────
          ╰────
         help: comparing a value to itself is redundant; did you mean to compare it to something else?

         ⚠ both operands of this comparison are the same expression
          ╭────
        1 │ principal == principal && resource == resource
          ·                           ────────────────────
          ╰────
         help: comparing a value to itself is redundant; did you mean to compare it to something else?
        ");
    }

    #[test]
    fn nothing_to_report() {
        insta::assert_snapshot!(lint_report(r#"principal == User::"alice" && context.n > 2"#), @"");
    }
}
