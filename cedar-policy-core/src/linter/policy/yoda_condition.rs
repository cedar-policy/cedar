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

//! Flags a "Yoda condition" — a literal on the left of `==`, as in
//! `5 == context.n`, which reads more naturally as `context.n == 5`.
//!
//! The name is from the speech pattern: "five, the count is". Cedar has no
//! assignment-in-condition footgun for putting the constant first to guard
//! against (the way C does), so this is purely a readability lint — the two forms
//! are identical. It is the analogue of Regal's `yoda-condition`.
//!
//! # What is covered
//!
//! Only `==` with a *literal* on the left and a non-literal on the right. `!=`
//! desugars to `!(==)`, so it is covered too.
//!
//! Ordering operators are deliberately excluded. `5 < context.n` is a perfectly
//! ordinary way to say "n is greater than five", and range idioms like
//! `lo <= x && x <= hi` put a value on the left of the first comparison on
//! purpose; flagging those would be noise.
//!
//! A general constant like `1 + 1` on the left is also not flagged — only a bare
//! literal. Yoda conditions are about a written constant, and a computed one on
//! the left is rare enough that reporting it would more likely confuse.
//!
//! # Not overlapping with `scope-constraints`
//!
//! `entity-literal == scope-variable`, e.g. `User::"alice" == principal`, is a
//! Yoda condition, but [`scope_constraints`](super::scope_constraints) already
//! reports it with more actionable advice (move it into the scope). To avoid two
//! findings on one span, this lint skips a bare scope variable on the right —
//! that case belongs to the other lint.

use crate::{
    ast::{BinaryOp, Expr, ExprKind, Var},
    linter::{
        findings::{Finding, YodaCondition},
        util::scan,
    },
};

/// Is `expr` a bare literal — the thing that belongs on the *right* of a
/// comparison?
fn is_literal(expr: &Expr) -> bool {
    matches!(expr.expr_kind(), ExprKind::Lit(_))
}

/// Is `expr` a bare scope variable? `scope-constraints` owns comparisons of an
/// entity literal against one of these, so this lint yields that case to it.
fn is_scope_var(expr: &Expr) -> bool {
    matches!(
        expr.expr_kind(),
        ExprKind::Var(Var::Principal | Var::Action | Var::Resource)
    )
}

/// Lint `expr`, reporting every Yoda condition within it.
pub(crate) fn lint(expr: &Expr) -> Vec<Finding> {
    scan(expr, |e| {
        let ExprKind::BinaryApp {
            op: BinaryOp::Eq,
            arg1,
            arg2,
        } = e.expr_kind()
        else {
            return None;
        };
        // Literal on the left, non-literal on the right (so not `1 == 2`), and not
        // the scope-constraints shape.
        (is_literal(arg1) && !is_literal(arg2) && !is_scope_var(arg2)).then(|| {
            YodaCondition {
                loc: e.source_loc().cloned(),
            }
            .into()
        })
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
    fn literal_on_left() {
        insta::assert_snapshot!(lint_report(r#"5 == context.n"#), @"
         ⚠ literal on the left of `==`
          ╭────
        1 │ 5 == context.n
          · ──────────────
          ╰────
         help: put the variable first and the literal second, as in `x == 5`; the two are equivalent
        ");
    }

    #[test]
    fn string_literal_on_left() {
        insta::assert_snapshot!(lint_report(r#""admin" == principal.role"#), @r#"
         ⚠ literal on the left of `==`
          ╭────
        1 │ "admin" == principal.role
          · ─────────────────────────
          ╰────
         help: put the variable first and the literal second, as in `x == 5`; the two are equivalent
        "#);
    }

    /// `!=` desugars to `!(==)`, so it is covered.
    #[test]
    fn not_equal() {
        insta::assert_snapshot!(lint_report(r#"5 != context.n"#), @"
         ⚠ literal on the left of `==`
          ╭────
        1 │ 5 != context.n
          · ──────────────
          ╰────
         help: put the variable first and the literal second, as in `x == 5`; the two are equivalent
        ");
    }

    /// The natural order is not reported.
    #[test]
    fn literal_on_right_is_fine() {
        insta::assert_snapshot!(lint_report(r#"context.n == 5"#), @"");
        insta::assert_snapshot!(lint_report(r#"principal.role == "admin""#), @"");
    }

    /// Ordering operators are excluded: a value on the left is idiomatic there.
    #[test]
    fn ordering_is_not_reported() {
        insta::assert_snapshot!(lint_report(r#"5 < context.n"#), @"");
        insta::assert_snapshot!(lint_report(r#"5 <= context.n && context.n <= 10"#), @"");
    }

    /// Both sides literal is a constant, not a Yoda condition.
    #[test]
    fn constant_is_not_reported() {
        insta::assert_snapshot!(lint_report(r#"5 == 5"#), @"");
    }

    /// Neither side a literal is an ordinary comparison.
    #[test]
    fn two_non_literals_is_not_reported() {
        insta::assert_snapshot!(lint_report(r#"context.a == context.b"#), @"");
    }

    /// A computed constant on the left is not flagged — only a bare literal.
    #[test]
    fn computed_constant_is_not_reported() {
        insta::assert_snapshot!(lint_report(r#"1 + 1 == context.n"#), @"");
    }

    /// An entity literal against a bare scope variable belongs to
    /// `scope-constraints`, which gives better advice, so this lint yields it.
    #[test]
    fn scope_constraint_shape_is_yielded() {
        insta::assert_snapshot!(lint_report(r#"User::"alice" == principal"#), @"");
        insta::assert_snapshot!(lint_report(r#"Action::"view" == action"#), @"");
    }

    /// But an entity literal against a non-scope-variable is a plain Yoda
    /// condition, since `scope-constraints` does not cover it.
    #[test]
    fn entity_literal_against_attribute_is_reported() {
        insta::assert_snapshot!(lint_report(r#"User::"alice" == principal.manager"#), @r#"
         ⚠ literal on the left of `==`
          ╭────
        1 │ User::"alice" == principal.manager
          · ──────────────────────────────────
          ╰────
         help: put the variable first and the literal second, as in `x == 5`; the two are equivalent
        "#);
    }

    #[test]
    fn multiple() {
        insta::assert_snapshot!(lint_report(r#"5 == context.n && "x" == context.s"#), @r#"
         ⚠ literal on the left of `==`
          ╭────
        1 │ 5 == context.n && "x" == context.s
          · ──────────────
          ╰────
         help: put the variable first and the literal second, as in `x == 5`; the two are equivalent

         ⚠ literal on the left of `==`
          ╭────
        1 │ 5 == context.n && "x" == context.s
          ·                   ────────────────
          ╰────
         help: put the variable first and the literal second, as in `x == 5`; the two are equivalent
        "#);
    }
}
