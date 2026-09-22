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

//! Flags empty set literals.
//!
//! Empty set literals are legal Cedar and evaluate without error, so this pass
//! exists only to ease migration to strict validation, which rejects them: with
//! no elements there is nothing to infer an element type from. The finding is
//! reported as a warning rather than an error.

use crate::{
    ast::{Expr, ExprKind},
    linter::{
        findings::{EmptySet, Finding},
        util::scan,
    },
};

/// Lint `expr`, reporting every empty set literal within it (including a bare
/// `[]`, since `subexpressions` includes `expr` itself).
pub(crate) fn lint(expr: &Expr) -> Vec<Finding> {
    scan(expr, |e| {
        matches!(e.expr_kind(), ExprKind::Set(elems) if elems.is_empty()).then(|| {
            EmptySet {
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
    fn top_level_empty_set() {
        insta::assert_snapshot!(lint_report(r#"[]"#), @"
         ⚠ empty set literal
          ╭────
        1 │ []
          · ──
          ╰────
         help: strict validation forbids empty set literals because it cannot infer their element type
        ");
    }

    #[test]
    fn non_empty_set_is_fine() {
        insta::assert_snapshot!(lint_report(r#"[1, 2]"#), @"");
        insta::assert_snapshot!(lint_report(r#"[[1], [2]]"#), @"");
    }

    #[test]
    fn nested_empty_set() {
        insta::assert_snapshot!(lint_report(r#"principal.roles.containsAll([])"#), @"
         ⚠ empty set literal
          ╭────
        1 │ principal.roles.containsAll([])
          ·                             ──
          ╰────
         help: strict validation forbids empty set literals because it cannot infer their element type
        ");
        insta::assert_snapshot!(lint_report(r#"{a: []}"#), @"
         ⚠ empty set literal
          ╭────
        1 │ {a: []}
          ·     ──
          ╰────
         help: strict validation forbids empty set literals because it cannot infer their element type
        ");
    }

    /// Each empty set in an expression is reported separately.
    #[test]
    fn multiple_empty_sets() {
        insta::assert_snapshot!(lint_report(r#"[[], []]"#), @"
         ⚠ empty set literal
          ╭────
        1 │ [[], []]
          ·  ──
          ╰────
         help: strict validation forbids empty set literals because it cannot infer their element type

         ⚠ empty set literal
          ╭────
        1 │ [[], []]
          ·      ──
          ╰────
         help: strict validation forbids empty set literals because it cannot infer their element type
        ");
    }
}
