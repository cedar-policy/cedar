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

//! Flags negations written out by hand where Cedar has syntax for them.
//!
//! | Written | Prefer |
//! | --- | --- |
//! | `!(a == b)` | `a != b` |
//! | `!(a != b)` | `a == b` |
//! | `!(a <= b)` | `a > b` |
//! | `!(a < b)` | `a >= b` |
//! | `!(a >= b)` | `a < b` |
//! | `!(a > b)` | `a <= b` |
//! | `!!a` | `a` (any even number of `!`s) |
//! | `!!!a` | `!a` (any odd number above one) |
//!
//! Each is a pure rewrite: both forms evaluate identically for every input.
//!
//! # Why this pass reads the CST
//!
//! Unlike most lints, this one cannot use the AST. The parser desugars: `a != b`
//! becomes `!(a == b)`, `a > b` becomes `!(a <= b)`, and `a >= b` becomes
//! `!(a < b)` (`expr_builder.rs`). By the time a policy is an
//! [`Expr`](crate::ast::Expr) the hand-written and sugared spellings are the same
//! tree, so an AST pass would report every `!=` as "prefer `!=`".
//!
//! The CST keeps them apart: [`RelOp`] has its own `NotEq`, `Greater`, and
//! `GreaterEq`, and [`NegOp::Bang`] records how many `!`s were written. It also
//! carries a `Loc` on every node, so findings point at the offending expression
//! like every other lint.
//!
//! Constructs the parser leaves intact — `a == true`, `if c then true else false`
//! — do not need the CST and are handled on the AST by
//! [`redundant_boolean`](super::redundant_boolean) instead.
//!
//! `!(a in b)` and `!(a has b)` are not reported: Cedar has no negated spelling
//! for either, so the explicit `!` is already the only way to write them.

use crate::{
    ast::PolicyID,
    linter::{
        cst_visitor::{self, CstVisitor},
        findings::{Finding, LintFinding, PreferSugar},
    },
    parser::{
        cst::{And, Expr, ExprData, Member, NegOp, Or, Policies, Primary, RelOp, Relation, Unary},
        Node,
    },
};

/// The negated spelling of a relational operator, for the six that have one.
///
/// `in` is absent deliberately: Cedar has no `not in`, so `!(a in b)` is already
/// the only way to write it. (`has` is a separate CST variant and never reaches
/// here.)
fn negated_op(op: RelOp) -> Option<&'static str> {
    match op {
        RelOp::Eq => Some("!="),
        RelOp::NotEq => Some("=="),
        RelOp::LessEq => Some(">"),
        RelOp::Less => Some(">="),
        RelOp::GreaterEq => Some("<"),
        RelOp::Greater => Some("<="),
        RelOp::In | RelOp::InvalidSingleEq => None,
    }
}

/// How an operator reads in source, for the message.
fn op_str(op: RelOp) -> &'static str {
    match op {
        RelOp::Eq => "==",
        RelOp::NotEq => "!=",
        RelOp::Less => "<",
        RelOp::LessEq => "<=",
        RelOp::Greater => ">",
        RelOp::GreaterEq => ">=",
        RelOp::In => "in",
        RelOp::InvalidSingleEq => "=",
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct SugarLinter {
    findings: Vec<Finding>,
}

impl CstVisitor for SugarLinter {
    fn visit_unary(&mut self, unary: &Node<Option<Unary>>) {
        if let Some(Unary {
            op: Some(NegOp::Bang(bangs_count)),
            item,
        }) = unary.as_inner()
        {
            let n = *bangs_count;
            if n > 1 {
                // Repeated `!` collapses: an even count is the operand itself, an
                // odd count is a single `!`.
                let bangs = "!".repeat(usize::from(n));
                self.report(
                    unary,
                    format!("`{bangs}`"),
                    if n % 2 == 0 {
                        "no `!` at all"
                    } else {
                        "a single `!`"
                    },
                );
            } else if let Some(op) = negated_comparison(item) {
                // Only for a single `!`: with more than one, the collapse
                // reported above is the more useful advice, so don't
                // double-report the same span.
                if let Some(prefer) = negated_op(op) {
                    self.report(
                        unary,
                        format!("`!(.. {} ..)`", op_str(op)),
                        format!("`{prefer}`"),
                    );
                }
            }
        }
        cst_visitor::walk_unary(self, unary);
    }
}

impl SugarLinter {
    /// Lint every policy in `policies`, tagging findings with the policy ID the
    /// AST assigns.
    ///
    /// `cst_to_ast::with_generated_policyids` names policies positionally as
    /// `policyN` — the `@id` annotation is not consulted — so doing the same here
    /// keeps these findings' IDs consistent with every other lint's.
    pub(crate) fn lint_policies(policies: &Node<Option<Policies>>) -> Vec<LintFinding> {
        // Not `visit_policies`, which would pool every policy's findings: each
        // policy needs its own linter so its findings carry its own ID.
        let Some(Policies(list)) = policies.as_inner() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (i, policy) in list.iter().enumerate() {
            let mut linter = Self::default();
            linter.visit_policy(policy);
            if linter.findings.is_empty() {
                continue;
            }
            // The visitor descends outermost-first, so sort to read in source
            // order. Stable, so equal offsets keep outermost-first.
            linter
                .findings
                .sort_by_key(|f| f.source_loc().map(|l| l.span.offset()));
            out.extend(LintFinding::tag_all(
                linter.findings,
                &PolicyID::from_string(format!("policy{i}")),
            ));
        }
        out
    }

    fn report<T>(&mut self, at: &Node<T>, wrote: impl Into<String>, prefer: impl Into<String>) {
        self.findings.push(
            PreferSugar {
                loc: at.loc().cloned(),
                wrote: wrote.into(),
                prefer: prefer.into(),
            }
            .into(),
        );
    }
}

/// If `member` is a parenthesized single comparison, its operator.
///
/// The comparison has to be the whole parenthesized expression: `!(a == b && c)`
/// is not `a != b && c`, so a `||` or `&&` inside disqualifies it. A chain like
/// `!(a == b == c)` is likewise skipped — the CST permits it, Cedar rejects it,
/// and it has no single negated spelling.
fn negated_comparison(member: &Node<Option<Member>>) -> Option<RelOp> {
    let Member { item, access } = member.as_inner()?;
    // A method call or field access on the parenthesized group means the `!`
    // applies to the result of that, not to the comparison.
    if !access.is_empty() {
        return None;
    }
    let Primary::Expr(inner) = item.as_inner()? else {
        return None;
    };
    // `Expr` has a second variant only under `tolerant-ast`, so this match is
    // irrefutable without that feature.
    #[allow(irrefutable_let_patterns)]
    let Expr::Expr(inner) = inner.as_inner()?
    else {
        return None;
    };
    let ExprData::Or(or) = &*inner.expr else {
        return None;
    };
    let Or { initial, extended } = or.as_inner()?;
    if !extended.is_empty() {
        return None;
    }
    let And { initial, extended } = initial.as_inner()?;
    if !extended.is_empty() {
        return None;
    }
    let Relation::Common { extended, .. } = initial.as_inner()? else {
        return None;
    };
    match &extended[..] {
        [(op, _)] => Some(*op),
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::text_to_cst;

    /// Lint `src` and return the pretty miette rendering of all findings,
    /// concatenated. Rendered without color so the snapshots stay readable.
    #[track_caller]
    fn lint_report(src: &str) -> String {
        let cst = text_to_cst::parse_policy(src).expect("failed to parse");
        let mut linter = SugarLinter::default();
        linter.visit_policy(&cst);
        linter
            .findings
            .sort_by_key(|f| f.source_loc().map(|l| l.span.offset()));
        render(&linter.findings)
    }

    #[test]
    fn negated_equality() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !(context.a == 1) };"#), @"
         ⚠ `!(.. == ..)` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) when { !(context.a == 1) };
          ·                                            ─────────────────
          ╰────
         help: prefer `!=`; the two are equivalent for every input
        ");
    }

    #[test]
    fn negated_inequality() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !(context.a != 1) };"#), @"
         ⚠ `!(.. != ..)` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) when { !(context.a != 1) };
          ·                                            ─────────────────
          ╰────
         help: prefer `==`; the two are equivalent for every input
        ");
    }

    #[test]
    fn negated_less_eq() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !(context.a <= 1) };"#), @"
         ⚠ `!(.. <= ..)` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) when { !(context.a <= 1) };
          ·                                            ─────────────────
          ╰────
         help: prefer `>`; the two are equivalent for every input
        ");
    }

    #[test]
    fn negated_less() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !(context.a < 1) };"#), @"
         ⚠ `!(.. < ..)` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) when { !(context.a < 1) };
          ·                                            ────────────────
          ╰────
         help: prefer `>=`; the two are equivalent for every input
        ");
    }

    #[test]
    fn negated_greater_eq() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !(context.a >= 1) };"#), @"
         ⚠ `!(.. >= ..)` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) when { !(context.a >= 1) };
          ·                                            ─────────────────
          ╰────
         help: prefer `<`; the two are equivalent for every input
        ");
    }

    #[test]
    fn negated_greater() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !(context.a > 1) };"#), @"
         ⚠ `!(.. > ..)` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) when { !(context.a > 1) };
          ·                                            ────────────────
          ╰────
         help: prefer `<=`; the two are equivalent for every input
        ");
    }

    /// The sugared forms are what we want, so they are not reported. These are the
    /// cases that would fail if this pass ran on the AST, where `a != 1` and
    /// `!(a == 1)` are the same tree.
    #[test]
    fn sugared_forms_are_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a != 1 };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a > 1 };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a >= 1 };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a < 1 };"#), @"");
    }

    /// `in` and `has` have no negated spelling, so an explicit `!` stays.
    #[test]
    fn no_negated_spelling() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !(resource in Folder::"f") };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !(context has a) };"#), @"");
    }

    #[test]
    fn double_negation() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !!context.a };"#), @"
         ⚠ `!!` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) when { !!context.a };
          ·                                            ───────────
          ╰────
         help: prefer no `!` at all; the two are equivalent for every input
        ");
    }

    #[test]
    fn triple_negation() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !!!context.a };"#), @"
         ⚠ `!!!` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) when { !!!context.a };
          ·                                            ────────────
          ╰────
         help: prefer a single `!`; the two are equivalent for every input
        ");
    }

    /// A single `!` on something that isn't a comparison is fine.
    #[test]
    fn plain_negation_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !context.a };"#), @"");
    }

    /// `!(a == b && c)` is not `a != b && c`, so the parenthesized expression has
    /// to be exactly one comparison.
    #[test]
    fn negated_connective_is_not_rewritten() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !(context.a == 1 && context.b) };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !(context.a == 1 || context.b) };"#), @"");
    }

    /// Found nested inside other expressions, and in `unless` clauses.
    #[test]
    fn nested_and_in_unless() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.b && !(context.a == 1) };"#), @"
         ⚠ `!(.. == ..)` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) when { context.b && !(context.a == 1) };
          ·                                                         ─────────────────
          ╰────
         help: prefer `!=`; the two are equivalent for every input
        ");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) unless { !(context.a == 1) };"#), @"
         ⚠ `!(.. == ..)` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) unless { !(context.a == 1) };
          ·                                              ─────────────────
          ╰────
         help: prefer `!=`; the two are equivalent for every input
        ");
    }

    /// Reached inside a set, a record value, and a method argument — the places
    /// the visitor has to descend into.
    #[test]
    fn nested_in_containers() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { [!(context.a == 1)] == [] };"#), @"
         ⚠ `!(.. == ..)` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) when { [!(context.a == 1)] == [] };
          ·                                             ─────────────────
          ╰────
         help: prefer `!=`; the two are equivalent for every input
        ");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { {x: !(context.a == 1)}.x };"#), @"
         ⚠ `!(.. == ..)` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) when { {x: !(context.a == 1)}.x };
          ·                                                ─────────────────
          ╰────
         help: prefer `!=`; the two are equivalent for every input
        ");
    }

    /// Each occurrence is reported, in source order.
    #[test]
    fn multiple_findings() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !(context.a == 1) && !!context.b };"#), @"
         ⚠ `!(.. == ..)` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) when { !(context.a == 1) && !!context.b };
          ·                                            ─────────────────
          ╰────
         help: prefer `!=`; the two are equivalent for every input

         ⚠ `!!` can be written more directly
          ╭────
        1 │ permit(principal, action, resource) when { !(context.a == 1) && !!context.b };
          ·                                                                 ───────────
          ╰────
         help: prefer no `!` at all; the two are equivalent for every input
        ");
    }

    /// A policy with nothing to rewrite is silent, as is one with no conditions.
    #[test]
    fn nothing_to_report() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a && resource.b > 2 };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource);"#), @"");
    }
}
