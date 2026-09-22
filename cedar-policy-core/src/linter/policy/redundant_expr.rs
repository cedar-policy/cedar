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

//! Flags expressions with a part that carries no weight.
//!
//! | Written | Redundant part |
//! | --- | --- |
//! | `a && a`, `a \|\| a` | the repeated operand |
//! | `if c then X else X` | the choice: both branches are `X` |
//! | `[1, 2, 1]` | the duplicate element |
//!
//! Each is a likely mistake rather than a mere style nit — a repeated operand or
//! branch usually means one of the two was meant to be something else, and a
//! duplicate set element is often a typo. These are the analogues of clippy's
//! `eq_op` (for `&&`/`||`), `if_same_then_else`, and the duplicate-value checks in
//! other linters.
//!
//! # Soundness of the `&&`/`||` case
//!
//! `a && a` is reported as reducible to `a`, and `a || a` likewise. That holds
//! even when `a` errors: Cedar expressions are deterministic and side-effect free,
//! so both copies of `a` do the same thing, and `a && a` errors exactly when `a`
//! does. (Comparisons of identical operands — `a == a` — are a different lint,
//! [`self_comparison`](super::self_comparison), which frames them as a comparison
//! mistake rather than a simplification.)
//!
//! Operands and branches are compared by shape via [`ExprShapeOnly`], so `a` must
//! be written the same way on both sides; two expressions equal only at runtime do
//! not match.
//!
//! A duplicate set *element* is reported once per extra occurrence, at the
//! element. The set's own value is unchanged — `[1, 2, 1]` is `[1, 2]` — so this
//! is about the source, not the result.

use crate::{
    ast::{Expr, ExprKind, ExprShapeOnly},
    linter::{
        findings::{DuplicateSetElement, Finding, IdenticalIfBranches, RepeatedLogicalOperand},
        util::scan_many,
    },
};

/// Lint `expr`, reporting every redundant part within it: `a && a` / `a || a`,
/// an `if` with identical branches, and duplicated set-literal elements.
pub(crate) fn lint(expr: &Expr) -> Vec<Finding> {
    scan_many(expr, |e| match e.expr_kind() {
        ExprKind::And { left, right } | ExprKind::Or { left, right } => {
            if ExprShapeOnly::new_from_borrowed(left) == ExprShapeOnly::new_from_borrowed(right) {
                let is_and = matches!(e.expr_kind(), ExprKind::And { .. });
                vec![RepeatedLogicalOperand {
                    loc: e.source_loc().cloned(),
                    op: if is_and { "&&" } else { "||" },
                }
                .into()]
            } else {
                vec![]
            }
        }
        ExprKind::If {
            then_expr,
            else_expr,
            ..
        } => {
            if ExprShapeOnly::new_from_borrowed(then_expr)
                == ExprShapeOnly::new_from_borrowed(else_expr)
            {
                vec![IdenticalIfBranches {
                    loc: e.source_loc().cloned(),
                }
                .into()]
            } else {
                vec![]
            }
        }
        ExprKind::Set(elems) => {
            // Report each element that duplicates an earlier one, at the
            // duplicate, so the span points where the fix is.
            let mut seen: Vec<ExprShapeOnly<'_, ()>> = Vec::new();
            let mut out = Vec::new();
            for elem in elems.iter() {
                let shape = ExprShapeOnly::new_from_borrowed(elem);
                if seen.contains(&shape) {
                    out.push(
                        DuplicateSetElement {
                            loc: elem.source_loc().cloned(),
                        }
                        .into(),
                    );
                } else {
                    seen.push(shape);
                }
            }
            out
        }
        _ => vec![],
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

    // --- repeated logical operand ---

    #[test]
    fn repeated_and() {
        insta::assert_snapshot!(lint_report(r#"context.a && context.a"#), @"
         ⚠ both operands of `&&` are the same expression
          ╭────
        1 │ context.a && context.a
          · ──────────────────────
          ╰────
         help: this is equivalent to the operand on its own; did you mean a different operand on one side?
        ");
    }

    #[test]
    fn repeated_or() {
        insta::assert_snapshot!(lint_report(r#"principal.admin || principal.admin"#), @"
         ⚠ both operands of `||` are the same expression
          ╭────
        1 │ principal.admin || principal.admin
          · ──────────────────────────────────
          ╰────
         help: this is equivalent to the operand on its own; did you mean a different operand on one side?
        ");
    }

    /// Different operands are the normal case.
    #[test]
    fn different_operands_are_not_reported() {
        insta::assert_snapshot!(lint_report(r#"context.a && context.b"#), @"");
        insta::assert_snapshot!(lint_report(r#"principal.x || resource.y"#), @"");
    }

    // --- identical if branches ---

    #[test]
    fn identical_branches() {
        insta::assert_snapshot!(lint_report(r#"if context.c then context.x else context.x"#), @"
         ⚠ both branches of this `if` are the same expression
          ╭────
        1 │ if context.c then context.x else context.x
          · ──────────────────────────────────────────
          ╰────
         help: the condition has no effect since both branches are identical; use the branch expression directly
        ");
    }

    #[test]
    fn different_branches_are_not_reported() {
        insta::assert_snapshot!(lint_report(r#"if context.c then context.x else context.y"#), @"");
    }

    // --- duplicate set element ---

    #[test]
    fn duplicate_literal() {
        insta::assert_snapshot!(lint_report(r#"[1, 2, 1]"#), @"
         ⚠ this set element is a duplicate
          ╭────
        1 │ [1, 2, 1]
          ·        ─
          ╰────
         help: it already appears earlier in the set, so it has no effect; remove it
        ");
    }

    #[test]
    fn duplicate_entity() {
        insta::assert_snapshot!(lint_report(r#"[User::"a", User::"b", User::"a"]"#), @r#"
         ⚠ this set element is a duplicate
          ╭────
        1 │ [User::"a", User::"b", User::"a"]
          ·                        ─────────
          ╰────
         help: it already appears earlier in the set, so it has no effect; remove it
        "#);
    }

    /// Every extra occurrence is reported, so `[1, 1, 1]` gives two findings.
    #[test]
    fn triplicate() {
        insta::assert_snapshot!(lint_report(r#"[1, 1, 1]"#), @"
         ⚠ this set element is a duplicate
          ╭────
        1 │ [1, 1, 1]
          ·     ─
          ╰────
         help: it already appears earlier in the set, so it has no effect; remove it

         ⚠ this set element is a duplicate
          ╭────
        1 │ [1, 1, 1]
          ·        ─
          ╰────
         help: it already appears earlier in the set, so it has no effect; remove it
        ");
    }

    #[test]
    fn distinct_elements_are_not_reported() {
        insta::assert_snapshot!(lint_report(r#"[1, 2, 3]"#), @"");
        insta::assert_snapshot!(lint_report(r#"[]"#), @"");
    }

    /// The comparison is syntactic, matching the rest of the linter.
    #[test]
    fn syntactically_different_elements_are_not_reported() {
        insta::assert_snapshot!(lint_report(r#"[principal.a, principal["a"]]"#), @r#"
         ⚠ this set element is a duplicate
          ╭────
        1 │ [principal.a, principal["a"]]
          ·               ──────────────
          ╰────
         help: it already appears earlier in the set, so it has no effect; remove it
        "#);
    }

    // --- combinations ---

    /// Nested and mixed findings are all reported, in source order.
    #[test]
    fn multiple() {
        insta::assert_snapshot!(lint_report(r#"context.a && context.a && [1, 1] == resource.s"#), @"
         ⚠ both operands of `&&` are the same expression
          ╭────
        1 │ context.a && context.a && [1, 1] == resource.s
          · ──────────────────────────────────────────────
          ╰────
         help: this is equivalent to the operand on its own; did you mean a different operand on one side?

         ⚠ this set element is a duplicate
          ╭────
        1 │ context.a && context.a && [1, 1] == resource.s
          ·                               ─
          ╰────
         help: it already appears earlier in the set, so it has no effect; remove it
        ");
    }

    #[test]
    fn nothing_to_report() {
        insta::assert_snapshot!(lint_report(r#"principal.x && context.y > 2"#), @"");
    }
}
