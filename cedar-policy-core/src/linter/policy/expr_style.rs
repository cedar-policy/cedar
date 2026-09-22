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

//! Flags expressions with a shorter equivalent form, where the AST is enough to
//! tell the two apart.
//!
//! | Written | Prefer |
//! | --- | --- |
//! | `x in [E]` | `x in E` |
//! | `a + -1` | `a - 1` |
//!
//! Both are pure rewrites. Unlike [`sugar`](super::sugar) and
//! [`syntax_style`](super::syntax_style), these constructs survive parsing
//! distinctly — `in [E]` really is a `Set` operand in the AST, and `+ -1` really is
//! an `Add` of a negation — so no CST is needed and they run in the ordinary
//! [`Linter::lint`](crate::linter::Linter::lint) path.
//!
//! # Why `- -x` is not here
//!
//! `- -x` looks like it belongs in this list, but it is not a rewrite: negation is
//! checked, and `-i64::MIN` overflows. So for `x = i64::MIN`, `- -x` errors while
//! `x` evaluates fine — the policy is *skipped* in one form and satisfied in the
//! other. Suggesting it as a simplification would change behavior in exactly the
//! case that matters.
//!
//! It is also not a style question at all: negating twice computes nothing and adds
//! a failure mode, so it signals a mistake rather than a preference. That makes it
//! a correctness warning, reported by
//! [`double_negation`](super::double_negation).
//!
//! The `+ -1` rewrite is safe by contrast: `a + (-n)` and `a - n` compute the same
//! value, so they overflow under exactly the same conditions. The single exception
//! is `a + -9223372036854775808`, whose magnitude has no `i64` representation and
//! so cannot be written as a subtraction at all; that one is not reported.

use crate::{
    ast::{BinaryOp, Expr, ExprKind, Literal},
    linter::findings::{Finding, PlusNegativeLiteral, SingletonSetIn},
};

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct ExprStyleLinter {
    findings: Vec<Finding>,
}

/// The sole element of `expr` if it is a one-element set literal.
fn singleton_set(expr: &Expr) -> Option<&Expr> {
    match expr.expr_kind() {
        ExprKind::Set(elems) => match &elems[..] {
            [only] => Some(only),
            _ => None,
        },
        _ => None,
    }
}

/// The magnitude of `expr` if it is a negative integer literal.
///
/// A written `-1` is folded by the parser into a single negative `Long`, not a
/// `Neg` applied to `1`, so this matches the literal rather than a negation.
///
/// `i64::MIN` returns `None`: its magnitude is not representable as an `i64`, and
/// `a - 9223372036854775808` is not writable, so there is no rewrite to suggest.
fn negative_literal(expr: &Expr) -> Option<i64> {
    match expr.expr_kind() {
        ExprKind::Lit(Literal::Long(n)) if *n < 0 => n.checked_neg(),
        _ => None,
    }
}

impl ExprStyleLinter {
    /// Lint `expr`, reporting every simplifiable construct within it.
    pub(crate) fn lint(&mut self, expr: &Expr) {
        // `subexpressions` yields in reverse source order, so collect and sort to
        // report the way the policy reads.
        let mut found: Vec<Finding> = Vec::new();
        let mut ordered: Vec<(&Expr, Finding)> = Vec::new();

        for e in expr.subexpressions() {
            match e.expr_kind() {
                // `x in [E]` is `x in E`: `eval_in` treats a one-element set and a
                // bare entity identically.
                ExprKind::BinaryApp {
                    op: BinaryOp::In,
                    arg2,
                    ..
                } => {
                    if singleton_set(arg2).is_some() {
                        ordered.push((
                            e,
                            SingletonSetIn {
                                loc: arg2.source_loc().cloned(),
                            }
                            .into(),
                        ));
                    }
                }
                // `a + -1` is `a - 1`.
                ExprKind::BinaryApp {
                    op: BinaryOp::Add,
                    arg2,
                    ..
                } => {
                    if let Some(n) = negative_literal(arg2) {
                        ordered.push((
                            e,
                            PlusNegativeLiteral {
                                loc: e.source_loc().cloned(),
                                magnitude: n.to_string(),
                            }
                            .into(),
                        ));
                    }
                }
                _ => {}
            }
        }

        ordered.sort_by_key(|(e, _)| e.source_loc().map(|l| l.span.offset()));
        found.extend(ordered.into_iter().map(|(_, f)| f));
        self.findings.extend(found);
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
        let mut linter = ExprStyleLinter::default();
        if let Some(conditions) = template.non_scope_constraints() {
            linter.lint(conditions);
        }
        render(&linter.into_findings())
    }

    // --- `in` with a singleton set ---

    #[test]
    fn singleton_set_in() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal in [Group::"g"] };"#), @r#"
         ⚠ `in` against a one-element set
          ╭────
        1 │ permit(principal, action, resource) when { principal in [Group::"g"] };
          ·                                                         ────────────
          ╰────
         help: `in` accepts a single entity directly, so the surrounding `[..]` can be dropped
        "#);
    }

    #[test]
    fn singleton_set_in_action_scope_style() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { action in [Action::"view"] };"#), @r#"
         ⚠ `in` against a one-element set
          ╭────
        1 │ permit(principal, action, resource) when { action in [Action::"view"] };
          ·                                                      ────────────────
          ╰────
         help: `in` accepts a single entity directly, so the surrounding `[..]` can be dropped
        "#);
    }

    /// More than one element is what a set operand is for.
    #[test]
    fn multi_element_set_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal in [Group::"a", Group::"b"] };"#),
            @"");
    }

    /// An empty set means "never in anything", which `in E` cannot express.
    #[test]
    fn empty_set_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal in [] };"#), @"");
    }

    /// The already-short form is not reported.
    #[test]
    fn bare_entity_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal in Group::"g" };"#), @"");
    }

    /// A non-literal operand is not a set literal, so there is nothing to unwrap.
    #[test]
    fn non_set_operand_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal in context.groups };"#), @"");
    }

    /// `contains` is a different operator and keeps its set.
    #[test]
    fn contains_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { [Group::"g"].contains(principal) };"#),
            @"");
    }

    // --- adding a negative literal ---

    #[test]
    fn plus_negative_literal() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a + -1 > 0 };"#), @"
         ⚠ adding a negative literal
          ╭────
        1 │ permit(principal, action, resource) when { context.a + -1 > 0 };
          ·                                            ──────────────
          ╰────
         help: write `- 1` instead; both compute the same value and overflow in the same cases
        ");
    }

    /// Subtraction is the form to prefer, so it is not reported.
    #[test]
    fn subtraction_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a - 1 > 0 };"#), @"");
    }

    /// Adding a positive literal is ordinary.
    #[test]
    fn plus_positive_literal_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a + 1 > 0 };"#), @"");
    }

    /// Only a literal: negating an expression may be what was meant, and `a - b`
    /// is not obviously clearer than `a + -b`.
    #[test]
    fn plus_negated_expression_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a + -context.b > 0 };"#), @"");
    }

    /// `i64::MIN` has no representable magnitude, so there is no subtraction to
    /// suggest and it is not reported.
    #[test]
    fn plus_i64_min_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a + -9223372036854775808 > 0 };"#),
            @"");
    }

    /// `- -x` is deliberately not reported here: it is not a safe rewrite, and it
    /// is a correctness problem rather than a style one, so
    /// [`double_negation`](super::double_negation) reports it instead.
    #[test]
    fn double_negation_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { - -context.a > 0 };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { - -5 > 0 };"#), @"");
    }

    // --- combinations ---

    /// Each finding is reported, in source order.
    #[test]
    fn multiple_findings() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal in [Group::"g"] && context.a + -1 > 0 };"#), @r#"
         ⚠ `in` against a one-element set
          ╭────
        1 │ permit(principal, action, resource) when { principal in [Group::"g"] && context.a + -1 > 0 };
          ·                                                         ────────────
          ╰────
         help: `in` accepts a single entity directly, so the surrounding `[..]` can be dropped

         ⚠ adding a negative literal
          ╭────
        1 │ permit(principal, action, resource) when { principal in [Group::"g"] && context.a + -1 > 0 };
          ·                                                                         ──────────────
          ╰────
         help: write `- 1` instead; both compute the same value and overflow in the same cases
        "#);
    }

    #[test]
    fn nothing_to_report() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal in Group::"g" && context.a - 1 > 0 };"#),
            @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource);"#), @"");
    }
}
