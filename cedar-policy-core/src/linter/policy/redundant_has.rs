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

//! Flags a `has` check on an attribute an earlier `has` in the same conjunction
//! already established, e.g. `principal has a && principal has a`.
//!
//! The second `has` is always true given the first, so it adds nothing. This is
//! purely syntactic — it needs no schema, and it holds whatever the attribute's
//! type or required-ness. It is the `has` analogue of
//! [`redundant_expr`](super::redundant_expr)'s repeated-operand check, specialized
//! so the message can name the attribute.
//!
//! # What "established" means
//!
//! Only along a conjunction. `a has x && (a has x)` repeats within one `&&` chain,
//! so the second is redundant. `a has x || a has x` does *not* count — the right
//! operand of `||` is reached only when the left was false, so the second `has` is
//! not established by the first. This mirrors how the capability analysis in
//! [`attr_guards`](super::attr_guards) treats `&&` versus `||`, but this lint only
//! needs the positive, short-circuiting `&&` direction, so it tracks the
//! established set directly rather than through the full capability machinery.
//!
//! The target is compared by shape via [`ExprShapeOnly`], so `principal.a has x`
//! and `principal["a"] has x` are the same target.

use std::collections::BTreeSet;

use smol_str::SmolStr;

use crate::{
    ast::{Expr, ExprKind, ExprShapeOnly},
    linter::{
        findings::{Finding, RedundantHas},
        util::direct_children,
    },
};

/// A `has` capability: `target has attr`, target compared by shape.
type HasKey<'a> = (ExprShapeOnly<'a, ()>, SmolStr);

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct RedundantHasLinter {
    findings: Vec<Finding>,
}

impl RedundantHasLinter {
    /// Lint `expr`, reporting every `has` redundant with an earlier one.
    pub(crate) fn lint(&mut self, expr: &Expr) {
        self.walk(expr, &mut BTreeSet::new());
        self.findings
            .sort_by_key(|f| f.source_loc().map(|l| l.span.offset()));
    }

    /// Consume this linter, returning the findings it accumulated.
    pub(crate) fn into_findings(self) -> Vec<Finding> {
        self.findings
    }

    /// Walk `expr`, with `established` the `has` capabilities known true here.
    ///
    /// `established` grows along a conjunction: the left operand of `&&` runs
    /// first, and whatever it establishes is known when the right operand runs.
    /// It does *not* cross `||`, `if`, or any other boundary — those reset to what
    /// was known before, since the sub-expression is not reached under the same
    /// guarantee.
    fn walk<'a>(&mut self, expr: &'a Expr, established: &mut BTreeSet<HasKey<'a>>) {
        match expr.expr_kind() {
            ExprKind::And { left, right } => {
                // Left, then right knowing what the left established. A single
                // shared set threaded left-to-right is exactly the accumulation
                // an `&&` chain gives.
                self.walk(left, established);
                self.walk(right, established);
            }
            ExprKind::HasAttr { expr: target, attr } => {
                // Descend into the target first, under the current knowledge.
                self.walk(target, established);
                let key = (ExprShapeOnly::new_from_borrowed(target), attr.clone());
                if established.contains(&key) {
                    self.findings.push(
                        RedundantHas {
                            loc: expr.source_loc().cloned(),
                            attr: attr.clone(),
                        }
                        .into(),
                    );
                } else {
                    established.insert(key);
                }
            }
            // Every other node is a boundary: its children are not reached under
            // this conjunction's guarantees, so lint each with a fresh set.
            _ => {
                for child in direct_children(expr) {
                    self.walk(child, &mut BTreeSet::new());
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_expr;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        let expr = parse_expr(src).expect("failed to parse");
        let mut linter = RedundantHasLinter::default();
        linter.lint(&expr);
        render(&linter.into_findings())
    }

    #[test]
    fn repeated_has() {
        insta::assert_snapshot!(lint_report(r#"principal has a && principal has a"#), @"
         ⚠ this `has` check is redundant
          ╭────
        1 │ principal has a && principal has a
          ·                    ───────────────
          ╰────
         help: `a` was already tested by an earlier `has` in this conjunction, so this repeat has no effect
        ");
    }

    /// Redundant even with other conjuncts between the two `has`.
    #[test]
    fn repeated_has_with_gap() {
        insta::assert_snapshot!(lint_report(
            r#"principal has a && context.ok && principal has a"#), @"
         ⚠ this `has` check is redundant
          ╭────
        1 │ principal has a && context.ok && principal has a
          ·                                  ───────────────
          ╰────
         help: `a` was already tested by an earlier `has` in this conjunction, so this repeat has no effect
        ");
    }

    /// A `has` followed by using the attribute is fine; only a repeated `has` is
    /// redundant.
    #[test]
    fn has_then_access_is_fine() {
        insta::assert_snapshot!(lint_report(r#"principal has a && principal.a == 1"#), @"");
    }

    /// Different attributes, or different targets, are not redundant.
    #[test]
    fn distinct_has_is_fine() {
        insta::assert_snapshot!(lint_report(r#"principal has a && principal has b"#), @"");
        insta::assert_snapshot!(lint_report(r#"principal has a && resource has a"#), @"");
    }

    /// `||` does not establish its left for its right, so a repeat across `||` is
    /// not redundant.
    #[test]
    fn across_or_is_not_redundant() {
        insta::assert_snapshot!(lint_report(r#"principal has a || principal has a"#), @"");
    }

    /// A nested access target is compared by shape.
    #[test]
    fn nested_target() {
        insta::assert_snapshot!(lint_report(
            r#"principal.org has a && principal.org has a"#), @"
         ⚠ this `has` check is redundant
          ╭────
        1 │ principal.org has a && principal.org has a
          ·                        ───────────────────
          ╰────
         help: `a` was already tested by an earlier `has` in this conjunction, so this repeat has no effect
        ");
    }

    #[test]
    fn nothing_to_report() {
        insta::assert_snapshot!(lint_report(r#"principal has a && context.b > 2"#), @"");
    }
}
