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

//! Flags non-linear arithmetic, i.e. a multiplication where neither operand is
//! a constant.
//!
//! Cedar originally allowed only multiplication of an expression by a constant.
//! [RFC 57] lifted that restriction, so `principal.a * principal.b` is legal
//! today and evaluates fine. The concern is *analyzability*: symbolic analysis
//! (`cedar-policy-symcc`) compiles Cedar's `Long` to a fixed-width bitvector, so
//! this is decidable in principle — but a multiplication of two *variables*
//! bit-blasts to a multiplier circuit, which SAT/SMT solvers are notoriously slow
//! to reason through. Multiplication by a *constant* does not: it lowers to
//! shifts and adds, which the solver handles cheaply. So the "neither operand
//! constant" gate is exactly the line between the cheap case and the
//! solver-hostile one.
//!
//! (`*` is the only such operator: Cedar has no division or remainder — its
//! arithmetic is `+`, `-`, and `*` — so there is nothing more to flag here.)
//!
//! This pass reports a warning, since nothing is wrong with such a policy on its
//! own: it only matters if you want to analyze it.
//!
//! [RFC 57]: https://github.com/cedar-policy/rfcs/pull/57

use crate::ast::{BinaryOp, Expr, ExprKind};
use crate::linter::findings::{Finding, NonLinearArithmetic};
use crate::linter::util::{is_constant_arithmetic, scan};

/// Lint `expr`, reporting every multiplication where neither operand is a
/// constant.
pub(crate) fn lint(expr: &Expr) -> Vec<Finding> {
    scan(expr, |e| {
        matches!(
            e.expr_kind(),
            ExprKind::BinaryApp {
                op: BinaryOp::Mul,
                arg1,
                arg2,
            } if !is_constant_arithmetic(arg1) && !is_constant_arithmetic(arg2)
        )
        .then(|| {
            NonLinearArithmetic {
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
    fn both_operands_non_constant() {
        insta::assert_snapshot!(lint_report(r#"principal.a * principal.b"#), @"
         ⚠ multiplication of two non-constant expressions
          ╭────
        1 │ principal.a * principal.b
          · ─────────────────────────
          ╰────
         help: multiplying two variables bit-blasts to a multiplier circuit that automated reasoning tools solve slowly; multiplying by a constant avoids it
        ");
    }

    /// Multiplying by a constant is linear, on either side.
    #[test]
    fn constant_operand_is_linear() {
        insta::assert_snapshot!(lint_report(r#"principal.a * 2"#), @"");
        insta::assert_snapshot!(lint_report(r#"2 * principal.a"#), @"");
        insta::assert_snapshot!(lint_report(r#"principal.a * -2"#), @"");
    }

    /// A constant-folded operand still counts as constant.
    #[test]
    fn folded_constant_operand_is_linear() {
        insta::assert_snapshot!(lint_report(r#"principal.a * (2 * 3)"#), @"");
        insta::assert_snapshot!(lint_report(r#"principal.a * (2 + 3 - 1)"#), @"");
    }

    /// Multiplying two constants is trivially linear.
    #[test]
    fn all_constants() {
        insta::assert_snapshot!(lint_report(r#"2 * 3"#), @"");
    }

    /// Addition and subtraction are always linear, whatever their operands.
    #[test]
    fn add_and_sub_are_linear() {
        insta::assert_snapshot!(lint_report(r#"principal.a + principal.b"#), @"");
        insta::assert_snapshot!(lint_report(r#"principal.a - principal.b"#), @"");
    }

    /// Multiplication nested inside a larger expression is still found.
    #[test]
    fn nested() {
        insta::assert_snapshot!(lint_report(r#"(principal.a * resource.b) > 10"#), @"
         ⚠ multiplication of two non-constant expressions
          ╭────
        1 │ (principal.a * resource.b) > 10
          ·  ────────────────────────
          ╰────
         help: multiplying two variables bit-blasts to a multiplier circuit that automated reasoning tools solve slowly; multiplying by a constant avoids it
        ");
        insta::assert_snapshot!(lint_report(r#"{total: context.x * context.y}"#), @"
         ⚠ multiplication of two non-constant expressions
          ╭────
        1 │ {total: context.x * context.y}
          ·         ─────────────────────
          ╰────
         help: multiplying two variables bit-blasts to a multiplier circuit that automated reasoning tools solve slowly; multiplying by a constant avoids it
        ");
    }

    /// Each non-linear multiplication is reported separately.
    #[test]
    fn multiple() {
        insta::assert_snapshot!(
            lint_report(r#"(principal.a * principal.b) + (resource.c * resource.d)"#), @"
         ⚠ multiplication of two non-constant expressions
          ╭────
        1 │ (principal.a * principal.b) + (resource.c * resource.d)
          ·  ─────────────────────────
          ╰────
         help: multiplying two variables bit-blasts to a multiplier circuit that automated reasoning tools solve slowly; multiplying by a constant avoids it

         ⚠ multiplication of two non-constant expressions
          ╭────
        1 │ (principal.a * principal.b) + (resource.c * resource.d)
          ·                                ───────────────────────
          ╰────
         help: multiplying two variables bit-blasts to a multiplier circuit that automated reasoning tools solve slowly; multiplying by a constant avoids it
        ");
    }

    /// A squaring is non-linear even though both operands are the same.
    #[test]
    fn squaring() {
        insta::assert_snapshot!(lint_report(r#"principal.a * principal.a"#), @"
         ⚠ multiplication of two non-constant expressions
          ╭────
        1 │ principal.a * principal.a
          · ─────────────────────────
          ╰────
         help: multiplying two variables bit-blasts to a multiplier circuit that automated reasoning tools solve slowly; multiplying by a constant avoids it
        ");
    }
}
