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

//! Flags policies whose syntax is more roundabout than it needs to be.
//!
//! Four checks, all of which need the CST because the AST does not record the
//! distinction:
//!
//! | Written | Prefer | Why the AST can't see it |
//! | --- | --- | --- |
//! | `principal["foo"]` | `principal.foo` | both are `GetAttr` |
//! | `((expr))` | `(expr)` | parentheses are not a node |
//! | `unless { !expr }` | `when { expr }` | `unless` is folded into a `!` |
//! | `x is T && x in E` | `x is T in E` | the sugar expands to exactly that `&&` |
//!
//! The `unless` case is the clearest illustration. `unless { !x }` and `when { !!x }`
//! produce byte-identical ASTs (`!(!(x))`), so on the AST there is no way to tell
//! a double negative the author wrote from one the `unless` introduced — a lint
//! there would flag `unless { !x }` as "`!!` collapses", which is not the useful
//! advice. On the CST the `unless` keyword is right there, so the advice can be
//! the real one: drop both negations and use `when`.
//!
//! # Redundant parentheses
//!
//! Only parentheses that are *doubled* are reported: `((x))` has an inner pair
//! that cannot affect precedence no matter what `x` is, so removing it is always
//! safe and always an improvement.
//!
//! A single redundant pair is deliberately not reported. `(a == b) && c` parses
//! the same without the parens, but they document the precedence for a reader who
//! would otherwise have to recall whether `==` binds tighter than `&&`. Flagging
//! those would be a style opinion this lint does not hold; flagging a doubled pair
//! is not.

use crate::{
    ast::PolicyID,
    linter::{
        cst_visitor::{self, CstVisitor},
        findings::{
            Finding, IndexWithLiteralKey, LintFinding, RedundantParens, SeparateIsAndIn,
            UnlessWithNegation,
        },
    },
    parser::{
        cst::{
            And, Cond, Expr, ExprData, Literal, MemAccess, Member, NegOp, Policies, Primary, RelOp,
            Relation, Str,
        },
        parse_ident, Node,
    },
};

/// `__cedar` parses as an identifier but is reserved, so `x["__cedar"]` cannot be
/// rewritten as `x.__cedar`.
const RESERVED_ID: &str = "__cedar";

/// The attribute name in `expr["key"]`, if `key` could be written as `.key`.
///
/// Requires a string literal that is a legal, non-reserved Cedar identifier;
/// `x["with space"]`, `x["has"]`, and `x[expr]` all have to stay as they are.
fn rewritable_key(access: &MemAccess) -> Option<&str> {
    let MemAccess::Index(e) = access else {
        return None;
    };
    let key = string_literal(e)?;
    (parse_ident(key).is_ok() && key != RESERVED_ID).then_some(key)
}

/// The value of `e` if it is exactly a string literal.
///
/// Walks the precedence chain down to the literal, since even a bare `"foo"` is
/// wrapped in the full `Or`/`And`/.../`Primary` stack.
fn string_literal(e: &Node<Option<Expr>>) -> Option<&str> {
    let primary = sole_primary(e)?;
    let Primary::Literal(lit) = primary else {
        return None;
    };
    match lit.as_inner()? {
        // `Str::Invalid` is never produced by the parser today, but treat it as
        // not-rewritable rather than assuming its contents are usable.
        Literal::Str(s) => match s.as_inner()? {
            Str::String(s) => Some(s.as_str()),
            Str::Invalid(_) => None,
        },
        _ => None,
    }
}

/// The [`Primary`] of `e`, if `e` is a single operand with no operators applied.
///
/// Returns `None` the moment anything else appears — an operator at any level, a
/// `!`, a field access — since then `e` is not just a primary.
fn sole_primary(e: &Node<Option<Expr>>) -> Option<&Primary> {
    #[allow(irrefutable_let_patterns)]
    let Expr::Expr(inner) = e.as_inner()?
    else {
        return None;
    };
    let ExprData::Or(or) = &*inner.expr else {
        return None;
    };
    let or = or.as_inner()?;
    if !or.extended.is_empty() {
        return None;
    }
    let and = or.initial.as_inner()?;
    if !and.extended.is_empty() {
        return None;
    }
    let Relation::Common { initial, extended } = and.initial.as_inner()? else {
        return None;
    };
    if !extended.is_empty() {
        return None;
    }
    let add = initial.as_inner()?;
    if !add.extended.is_empty() {
        return None;
    }
    let mult = add.initial.as_inner()?;
    if !mult.extended.is_empty() {
        return None;
    }
    let unary = mult.initial.as_inner()?;
    if unary.op.is_some() {
        return None;
    }
    let Member { item, access } = unary.item.as_inner()?;
    if !access.is_empty() {
        return None;
    }
    item.as_inner()
}

/// If `p` is a parenthesized expression that is *itself* just a parenthesized
/// expression, i.e. `((..))`, the inner pair's node.
fn doubled_parens<'a>(p: &'a Primary) -> Option<&'a Node<Option<Expr>>> {
    let Primary::Expr(inner) = p else {
        return None;
    };
    match sole_primary(inner)? {
        Primary::Expr(_) => Some(inner),
        _ => None,
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct SyntaxStyleLinter {
    findings: Vec<Finding>,
}

impl CstVisitor for SyntaxStyleLinter {
    /// `x is T && x in E` is `x is T in E`.
    ///
    /// Both forms produce the same AST — the parser expands the sugar into exactly
    /// this conjunction — so only the CST can tell which was written.
    fn visit_and(&mut self, and: &Node<Option<And>>) {
        if let Some(And { initial, extended }) = and.as_inner() {
            // Adjacent pairs across the whole chain, since `a && x is T && x in E`
            // puts the two relations next to each other but not first.
            let relations: Vec<&Node<Option<Relation>>> =
                std::iter::once(initial).chain(extended).collect();
            for pair in relations.windows(2) {
                if let [left, right] = pair {
                    if let Some(loc) = separable_is_in(left, right) {
                        self.findings
                            .push(SeparateIsAndIn { loc: Some(loc) }.into());
                    }
                }
            }
        }
        cst_visitor::walk_and(self, and);
    }

    fn visit_cond(&mut self, cond: &Node<Option<Cond>>, is_when: bool) {
        // `unless { !x }` is a double negative: the clause negates, and so does
        // the `!`. Only for a leading `!` on the whole clause body — a `!` deeper
        // inside is doing real work.
        if !is_when {
            if let Some(Cond { expr: Some(e), .. }) = cond.as_inner() {
                if leading_negation(e) {
                    self.findings.push(
                        UnlessWithNegation {
                            loc: cond.loc().cloned(),
                        }
                        .into(),
                    );
                }
            }
        }
        cst_visitor::walk_cond(self, cond, is_when);
    }

    fn visit_member(&mut self, member: &Node<Option<Member>>) {
        if let Some(Member { access, .. }) = member.as_inner() {
            for a in access {
                if let Some(key) = a.as_inner().and_then(rewritable_key) {
                    self.findings.push(
                        IndexWithLiteralKey {
                            loc: a.loc().cloned(),
                            key: key.to_string(),
                        }
                        .into(),
                    );
                }
            }
        }
        cst_visitor::walk_member(self, member);
    }

    fn visit_primary(&mut self, primary: &Node<Option<Primary>>) {
        if let Some(p) = primary.as_inner() {
            if let Some(inner) = doubled_parens(p) {
                self.findings.push(
                    RedundantParens {
                        loc: inner.loc().cloned(),
                    }
                    .into(),
                );
            }
        }
        cst_visitor::walk_primary(self, primary);
    }
}

/// If `left` is `x is T` and `right` is `x in E` for the same `x`, the span
/// covering both, so the finding points at what would become `x is T in E`.
///
/// The `x`s are compared structurally: [`Node`]'s `PartialEq` ignores source
/// locations, so two occurrences of the same expression text match. That also
/// means the comparison is syntactic — `principal is User && principal.self in E`
/// is not reported even if the two denote the same entity.
fn separable_is_in(
    left: &Node<Option<Relation>>,
    right: &Node<Option<Relation>>,
) -> Option<crate::parser::Loc> {
    // `x is T` with no `in` of its own: `x is T in E && ..` is already sugared.
    let Relation::IsIn {
        target: is_target,
        in_entity: None,
        ..
    } = left.as_inner()?
    else {
        return None;
    };
    // `x in E`, which is a `Common` relation with a single `In` operator.
    let Relation::Common {
        initial: in_target,
        extended,
    } = right.as_inner()?
    else {
        return None;
    };
    let [(RelOp::In, _)] = &extended[..] else {
        return None;
    };
    if is_target != in_target {
        return None;
    }
    // Span both relations, since the fix rewrites the pair.
    let start = left.loc()?;
    let end = right.loc()?;
    let from = start.span.offset();
    let to = end.span.offset() + end.span.len();
    Some(start.span(miette::SourceSpan::from(from..to)))
}

/// Does `e` consist of a single `!` applied to something?
///
/// `!!x` is excluded: that is its own finding, reported by
/// [`sugar`](super::sugar), and `unless { !!x }` is better advised there.
fn leading_negation(e: &Node<Option<Expr>>) -> bool {
    #[allow(irrefutable_let_patterns)]
    let Some(Expr::Expr(inner)) = e.as_inner() else {
        return false;
    };
    let ExprData::Or(or) = &*inner.expr else {
        return false;
    };
    let Some(or) = or.as_inner() else {
        return false;
    };
    // A `!` on one operand of `||` doesn't negate the whole clause.
    if !or.extended.is_empty() {
        return false;
    }
    let Some(and) = or.initial.as_inner() else {
        return false;
    };
    if !and.extended.is_empty() {
        return false;
    }
    let Some(Relation::Common { initial, extended }) = and.initial.as_inner() else {
        return false;
    };
    if !extended.is_empty() {
        return false;
    }
    let Some(add) = initial.as_inner() else {
        return false;
    };
    if !add.extended.is_empty() {
        return false;
    }
    let Some(mult) = add.initial.as_inner() else {
        return false;
    };
    if !mult.extended.is_empty() {
        return false;
    }
    matches!(
        mult.initial.as_inner().and_then(|u| u.op),
        Some(NegOp::Bang(1))
    )
}

impl SyntaxStyleLinter {
    /// Lint every policy in `policies`, tagging findings with the policy ID the
    /// AST assigns.
    ///
    /// `cst_to_ast::with_generated_policyids` names policies positionally as
    /// `policyN`, so doing the same keeps these findings' IDs consistent with
    /// every other lint's.
    pub(crate) fn lint_policies(policies: &Node<Option<Policies>>) -> Vec<LintFinding> {
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
        let mut linter = SyntaxStyleLinter::default();
        linter.visit_policy(&cst);
        linter
            .findings
            .sort_by_key(|f| f.source_loc().map(|l| l.span.offset()));
        render(&linter.findings)
    }

    // --- index access ---

    #[test]
    fn index_with_identifier_key() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal["foo"] };"#), @r#"
         ⚠ `["foo"]` can be written as `.foo`
          ╭────
        1 │ permit(principal, action, resource) when { principal["foo"] };
          ·                                                     ───────
          ╰────
         help: `.foo` is the idiomatic form; the index form is needed only when the key is not a legal identifier
        "#);
    }

    #[test]
    fn index_in_a_chain() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal.a["b"].c };"#), @r#"
         ⚠ `["b"]` can be written as `.b`
          ╭────
        1 │ permit(principal, action, resource) when { principal.a["b"].c };
          ·                                                       ─────
          ╰────
         help: `.b` is the idiomatic form; the index form is needed only when the key is not a legal identifier
        "#);
    }

    /// A key that is not a legal identifier has to stay as an index.
    #[test]
    fn index_with_non_identifier_key() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal["with space"] };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal["1abc"] };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal[""] };"#), @"");
    }

    /// A Cedar keyword is not usable after `.`, so the index form is required.
    #[test]
    fn index_with_reserved_word_key() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal["has"] };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal["if"] };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal["true"] };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal["__cedar"] };"#), @"");
    }

    /// Only a literal key can be rewritten.
    #[test]
    fn index_with_non_literal_key() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal[context.k] };"#), @"");
    }

    /// The idiomatic form is not reported.
    #[test]
    fn field_access_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal.foo };"#), @"");
    }

    // --- redundant parentheses ---

    #[test]
    fn doubled_parens() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { ((principal.foo)) };"#), @"
         ⚠ redundant parentheses
          ╭────
        1 │ permit(principal, action, resource) when { ((principal.foo)) };
          ·                                             ───────────────
          ╰────
         help: this pair is already inside another, so it cannot change how the expression parses
        ");
    }

    #[test]
    fn doubled_parens_around_a_comparison() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { ((context.a == 1)) };"#), @"
         ⚠ redundant parentheses
          ╭────
        1 │ permit(principal, action, resource) when { ((context.a == 1)) };
          ·                                             ────────────────
          ╰────
         help: this pair is already inside another, so it cannot change how the expression parses
        ");
    }

    /// A single pair is left alone, even where it is strictly removable: it may be
    /// documenting precedence for the reader.
    #[test]
    fn single_parens_are_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { (principal.foo) };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { (context.a == 1) && context.b };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { (context.a && context.b) || context.c };"#),
            @"");
    }

    /// Parens whose contents are an operator expression are load-bearing at one
    /// level, so only a doubled pair is reported.
    #[test]
    fn nested_but_not_doubled() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { ((context.a) && context.b) };"#), @"");
    }

    // --- unless with a negation ---

    #[test]
    fn unless_with_negation() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) unless { !context.a };"#), @"
         ⚠ `unless` with a negated body is a double negative
          ╭────
        1 │ permit(principal, action, resource) unless { !context.a };
          ·                                     ─────────────────────
          ╰────
         help: `unless` already negates, so drop the `!` and use `when` instead
        ");
    }

    #[test]
    fn unless_with_negated_comparison() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) unless { !(context.a == 1) };"#), @"
         ⚠ `unless` with a negated body is a double negative
          ╭────
        1 │ permit(principal, action, resource) unless { !(context.a == 1) };
          ·                                     ────────────────────────────
          ╰────
         help: `unless` already negates, so drop the `!` and use `when` instead
        ");
    }

    /// An ordinary `unless` is the point of the keyword.
    #[test]
    fn plain_unless_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) unless { context.a };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) unless { context.a == 1 };"#), @"");
    }

    /// A `when` clause is not a negation, so a `!` in it is ordinary.
    #[test]
    fn when_with_negation_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { !context.a };"#), @"");
    }

    /// The `!` has to negate the whole clause: one operand of a connective is not
    /// the same thing.
    #[test]
    fn negation_of_one_operand_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) unless { !context.a && context.b };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) unless { !context.a || context.b };"#), @"");
    }

    /// `unless { !!x }` is a `!!` finding, which `sugar` reports; this lint stays
    /// out of it rather than giving competing advice for the same span.
    #[test]
    fn unless_with_double_negation_defers_to_sugar() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) unless { !!context.a };"#), @"");
    }

    // --- separate `is` and `in` ---

    #[test]
    fn separate_is_and_in() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal is User && principal in Group::"g" };"#), @r#"
         ⚠ `is` and `in` on the same operand can be combined
          ╭────
        1 │ permit(principal, action, resource) when { principal is User && principal in Group::"g" };
          ·                                            ────────────────────────────────────────────
          ╰────
         help: Cedar has an `is .. in ..` form that states both constraints at once
        "#);
    }

    /// Found when the pair is not at the start of the `&&` chain.
    #[test]
    fn separate_is_and_in_later_in_chain() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context.a && principal is User && principal in Group::"g" };"#), @r#"
         ⚠ `is` and `in` on the same operand can be combined
          ╭────
        1 │ permit(principal, action, resource) when { context.a && principal is User && principal in Group::"g" };
          ·                                                         ────────────────────────────────────────────
          ╰────
         help: Cedar has an `is .. in ..` form that states both constraints at once
        "#);
    }

    /// The combined form is what we want, so it is not reported. This is the case
    /// that would misfire on the AST, where both forms are the same tree.
    #[test]
    fn combined_is_in_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal is User in Group::"g" };"#), @"");
    }

    /// Different operands are two unrelated constraints.
    #[test]
    fn is_and_in_on_different_operands() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal is User && resource in Folder::"f" };"#),
            @"");
    }

    /// The comparison is syntactic, so an attribute access on one side does not
    /// match a bare variable on the other.
    #[test]
    fn is_and_in_on_syntactically_different_targets() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal is User && principal.self in Group::"g" };"#),
            @"");
    }

    /// Order matters: `x in E && x is T` is not the sugar's expansion.
    #[test]
    fn in_before_is_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal in Group::"g" && principal is User };"#),
            @"");
    }

    /// `is` alone, and `in` alone, are ordinary.
    #[test]
    fn is_or_in_alone_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal is User };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal in Group::"g" };"#), @"");
    }

    /// `||` does not combine, so the pair must be under `&&`.
    #[test]
    fn is_or_in_under_disjunction_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal is User || principal in Group::"g" };"#),
            @"");
    }

    // --- combinations ---

    /// Each finding is reported, in source order.
    #[test]
    fn multiple_findings() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) unless { !((principal["foo"])) };"#), @r#"
         ⚠ `unless` with a negated body is a double negative
          ╭────
        1 │ permit(principal, action, resource) unless { !((principal["foo"])) };
          ·                                     ────────────────────────────────
          ╰────
         help: `unless` already negates, so drop the `!` and use `when` instead

         ⚠ redundant parentheses
          ╭────
        1 │ permit(principal, action, resource) unless { !((principal["foo"])) };
          ·                                                ──────────────────
          ╰────
         help: this pair is already inside another, so it cannot change how the expression parses

         ⚠ `["foo"]` can be written as `.foo`
          ╭────
        1 │ permit(principal, action, resource) unless { !((principal["foo"])) };
          ·                                                          ───────
          ╰────
         help: `.foo` is the idiomatic form; the index form is needed only when the key is not a legal identifier
        "#);
    }

    #[test]
    fn nothing_to_report() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal.foo && resource.bar > 2 };"#),
            @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource);"#), @"");
    }
}
