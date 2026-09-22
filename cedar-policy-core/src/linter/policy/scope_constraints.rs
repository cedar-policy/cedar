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

//! Flags `==` and `in` comparisons between a scope variable and an entity
//! literal that appear in a policy's condition rather than in its scope.
//!
//! ```cedar
//! permit(principal, action, resource) when { principal == User::"alice" };
//! ```
//!
//! is equivalent to, and better written as:
//!
//! ```cedar
//! permit(principal == User::"alice", action, resource);
//! ```
//!
//! Both forms authorize the same requests, so this is a style finding, not a
//! correctness one. It is worth reporting because the scope is not merely the
//! conventional place for these constraints — it is the only place Cedar itself
//! can see them:
//!
//! * **Policy slicing.** The scope is what makes a policy indexable. A store can
//!   fetch just the policies whose scope could match a request; a constraint
//!   hidden in a condition forces the policy to be considered for every request.
//! * **Readability.** The scope is the summary of who a policy is about, so a
//!   reader who skims scopes should not be misled by `permit(principal, ...)` on
//!   a policy that in fact applies to one user.
//!
//! # What is reported
//!
//! Only a comparison that the scope could express verbatim:
//!
//! | Reported | Not reported | Why |
//! | --- | --- | --- |
//! | `principal == User::"alice"` | `context == ...` | `context` has no scope slot |
//! | `resource in Folder::"f"` | `principal.owner == User::"alice"` | not the bare variable |
//! | `action == Action::"view"` | `principal == 1` | not an entity literal; the types lint covers it |
//! | `User::"alice" == principal` | `principal == resource` | no literal to move |
//!
//! `action in [Action::"a", Action::"b"]` is also reported: the action scope
//! accepts a set of action literals, so it moves too.
//!
//! Only the `when`/`unless` clauses are examined, never the scope-derived part of
//! the condition — the latter is itself built from `==` and `in` against the
//! scope variables, so linting it would report every constrained policy.
//!
//! Note the comparison is reported wherever it appears in the condition,
//! including under an `||` or inside an `if`. Such a policy cannot always be
//! rewritten by moving the constraint into the scope, since the scope is a
//! conjunction; the finding still stands, but the fix may be to split the policy.

use crate::{
    ast::{BinaryOp, Expr, ExprKind, Literal, Template, Var},
    linter::findings::{Finding, ScopeConstraintInCondition},
};

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct ScopeConstraintLinter {
    errors: Vec<Finding>,
}

/// Is `expr` a bare scope variable that the scope can constrain, i.e. one of
/// `principal`, `action`, or `resource`?
///
/// `context` is excluded: it has no scope slot, so there is nowhere to move a
/// comparison against it.
fn as_scope_var(expr: &Expr) -> Option<Var> {
    match expr.expr_kind() {
        ExprKind::Var(var @ (Var::Principal | Var::Action | Var::Resource)) => Some(*var),
        _ => None,
    }
}

/// Is `expr` something the scope could hold on the right of `==` or `in`?
///
/// That means an entity literal, or — for `in`, and only for `action` — a set of
/// them. Non-entity literals are excluded: `principal == 1` is a type error, not
/// a misplaced scope constraint, and the types lint reports it.
fn is_scope_literal(expr: &Expr) -> bool {
    match expr.expr_kind() {
        ExprKind::Lit(Literal::EntityUID(_)) => true,
        ExprKind::Set(elems) => {
            !elems.is_empty()
                && elems
                    .iter()
                    .all(|e| matches!(e.expr_kind(), ExprKind::Lit(Literal::EntityUID(_))))
        }
        _ => false,
    }
}

impl ScopeConstraintLinter {
    /// Lint the `when`/`unless` clauses of `template`.
    ///
    /// Deliberately not `template.condition()`: that folds in the scope
    /// constraints, which are themselves `==`/`in` comparisons against the scope
    /// variables and would be reported on every constrained policy.
    pub(crate) fn lint(&mut self, template: &Template) {
        let Some(conditions) = template.non_scope_constraints() else {
            return;
        };
        // `subexpressions` yields subexpressions in reverse source order, so
        // sort to report findings the way the policy reads.
        let mut found: Vec<(&Expr, Var, BinaryOp)> = conditions
            .subexpressions()
            .filter_map(|e| Self::misplaced_constraint(e).map(|(var, op)| (e, var, op)))
            .collect();
        found.sort_by_key(|(e, _, _)| e.source_loc().map(|l| l.span.offset()));

        for (expr, var, op) in found {
            self.errors.push(
                ScopeConstraintInCondition {
                    loc: expr.source_loc().cloned(),
                    var,
                    op: match op {
                        BinaryOp::Eq => "==",
                        // The filter below admits only `Eq` and `In`.
                        _ => "in",
                    },
                }
                .into(),
            );
        }
    }

    /// If `expr` is a scope-expressible comparison, which variable and operator.
    ///
    /// Either operand may be the variable: `User::"alice" == principal` reads
    /// backwards but means the same thing. `in` is directional, though — the
    /// scope can express `resource in Folder::"f"` but not
    /// `Folder::"f" in resource` — so a reversed `in` is not reported.
    fn misplaced_constraint(expr: &Expr) -> Option<(Var, BinaryOp)> {
        let ExprKind::BinaryApp {
            op: op @ (BinaryOp::Eq | BinaryOp::In),
            arg1,
            arg2,
        } = expr.expr_kind()
        else {
            return None;
        };
        if let Some(var) = as_scope_var(arg1).filter(|_| is_scope_literal(arg2)) {
            return Some((var, *op));
        }
        // A set is only ever the right operand of `in`, so a reversed match is
        // limited to a single entity literal, and only for `==`.
        if *op == BinaryOp::Eq {
            if let Some(var) = as_scope_var(arg2).filter(|_| is_scope_literal(arg1)) {
                return Some((var, *op));
            }
        }
        None
    }

    /// Consume this linter, returning the findings it accumulated.
    pub(crate) fn into_findings(self) -> Vec<Finding> {
        self.errors
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_policy_or_template;

    /// Lint `src` and return the pretty miette rendering of all findings,
    /// concatenated. Rendered without color so the snapshots stay readable.
    #[track_caller]
    fn lint_report(src: &str) -> String {
        let template = parse_policy_or_template(None, src).expect("failed to parse");
        let mut linter = ScopeConstraintLinter::default();
        linter.lint(&template);
        render(&linter.errors)
    }

    #[test]
    fn principal_equality() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal == User::"alice" };"#), @r#"
          ⚠ `principal == ..` belongs in the policy scope, not in a condition
           ╭────
         1 │ permit(principal, action, resource) when { principal == User::"alice" };
           ·                                            ──────────────────────────
           ╰────
          help: write it as `principal == ..` in the scope instead; the scope is what lets a policy store slice on this constraint, and what a reader sees first
        "#);
    }

    #[test]
    fn resource_in() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { resource in Folder::"f" };"#), @r#"
          ⚠ `resource in ..` belongs in the policy scope, not in a condition
           ╭────
         1 │ permit(principal, action, resource) when { resource in Folder::"f" };
           ·                                            ───────────────────────
           ╰────
          help: write it as `resource in ..` in the scope instead; the scope is what lets a policy store slice on this constraint, and what a reader sees first
        "#);
    }

    #[test]
    fn action_equality() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { action == Action::"view" };"#), @r#"
          ⚠ `action == ..` belongs in the policy scope, not in a condition
           ╭────
         1 │ permit(principal, action, resource) when { action == Action::"view" };
           ·                                            ────────────────────────
           ╰────
          help: write it as `action == ..` in the scope instead; the scope is what lets a policy store slice on this constraint, and what a reader sees first
        "#);
    }

    /// The action scope accepts a set of action literals, so `in` a set moves too.
    #[test]
    fn action_in_set() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { action in [Action::"a", Action::"b"] };"#), @r#"
          ⚠ `action in ..` belongs in the policy scope, not in a condition
           ╭────
         1 │ permit(principal, action, resource) when { action in [Action::"a", Action::"b"] };
           ·                                            ────────────────────────────────────
           ╰────
          help: write it as `action in ..` in the scope instead; the scope is what lets a policy store slice on this constraint, and what a reader sees first
        "#);
    }

    /// Reversed `==` means the same thing, so it is reported too.
    #[test]
    fn reversed_equality() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { User::"alice" == principal };"#), @r#"
          ⚠ `principal == ..` belongs in the policy scope, not in a condition
           ╭────
         1 │ permit(principal, action, resource) when { User::"alice" == principal };
           ·                                            ──────────────────────────
           ╰────
          help: write it as `principal == ..` in the scope instead; the scope is what lets a policy store slice on this constraint, and what a reader sees first
        "#);
    }

    /// `in` is directional: the scope cannot express `Folder::"f" in resource`.
    #[test]
    fn reversed_in_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { Folder::"f" in resource };"#), @"");
    }

    /// The scope constraints are themselves `==`/`in` against the scope
    /// variables, so a constrained policy with no conditions reports nothing.
    #[test]
    fn scope_itself_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal == User::"alice", action == Action::"view", resource in Folder::"f");"#),
            @"");
    }

    /// A policy that already puts its constraints in the scope, and has an
    /// unrelated condition, is fine.
    #[test]
    fn well_written_policy() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal == User::"alice", action, resource) when { context.mfa };"#), @"");
    }

    /// `context` has no scope slot, so a comparison against it stays put.
    #[test]
    fn context_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { context == Ctx::"c" };"#), @"");
    }

    /// An attribute of a scope variable is not the variable, so there is nothing
    /// to move.
    #[test]
    fn attribute_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal.manager == User::"alice" };"#),
            @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { resource.parent in Folder::"f" };"#), @"");
    }

    /// Comparing two variables has no literal to move into the scope.
    #[test]
    fn variable_to_variable_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal == resource };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { resource in principal };"#), @"");
    }

    /// A non-entity literal is a type error rather than a misplaced constraint,
    /// and the types lint reports it.
    #[test]
    fn non_entity_literal_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal == 1 };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal == "alice" };"#), @"");
    }

    /// A set containing anything other than entity literals is not a scope
    /// constraint, and neither is an empty one.
    #[test]
    fn non_entity_set_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { action in [Action::"a", 1] };"#), @"");
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { action in [] };"#), @"");
    }

    /// Each misplaced constraint in a condition is reported, in source order.
    #[test]
    fn multiple_constraints() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal == User::"alice" && resource in Folder::"f" };"#), @r#"
          ⚠ `principal == ..` belongs in the policy scope, not in a condition
           ╭────
         1 │ permit(principal, action, resource) when { principal == User::"alice" && resource in Folder::"f" };
           ·                                            ──────────────────────────
           ╰────
          help: write it as `principal == ..` in the scope instead; the scope is what lets a policy store slice on this constraint, and what a reader sees first

          ⚠ `resource in ..` belongs in the policy scope, not in a condition
           ╭────
         1 │ permit(principal, action, resource) when { principal == User::"alice" && resource in Folder::"f" };
           ·                                                                          ───────────────────────
           ╰────
          help: write it as `resource in ..` in the scope instead; the scope is what lets a policy store slice on this constraint, and what a reader sees first
        "#);
    }

    /// Found in an `unless` clause too.
    #[test]
    fn in_unless() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) unless { principal == User::"bob" };"#), @r#"
          ⚠ `principal == ..` belongs in the policy scope, not in a condition
           ╭────
         1 │ permit(principal, action, resource) unless { principal == User::"bob" };
           ·                                              ────────────────────────
           ╰────
          help: write it as `principal == ..` in the scope instead; the scope is what lets a policy store slice on this constraint, and what a reader sees first
        "#);
    }

    /// Reported under an `||` as well, where moving it to the scope is not a
    /// sound rewrite on its own — the finding stands, but the fix differs.
    #[test]
    fn under_a_disjunction() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal == User::"a" || principal == User::"b" };"#), @r#"
          ⚠ `principal == ..` belongs in the policy scope, not in a condition
           ╭────
         1 │ permit(principal, action, resource) when { principal == User::"a" || principal == User::"b" };
           ·                                            ──────────────────────
           ╰────
          help: write it as `principal == ..` in the scope instead; the scope is what lets a policy store slice on this constraint, and what a reader sees first

          ⚠ `principal == ..` belongs in the policy scope, not in a condition
           ╭────
         1 │ permit(principal, action, resource) when { principal == User::"a" || principal == User::"b" };
           ·                                                                      ──────────────────────
           ╰────
          help: write it as `principal == ..` in the scope instead; the scope is what lets a policy store slice on this constraint, and what a reader sees first
        "#);
    }

    /// `forbid` policies have scopes too.
    #[test]
    fn forbid() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal == User::"alice" };"#), @r#"
          ⚠ `principal == ..` belongs in the policy scope, not in a condition
           ╭────
         1 │ forbid(principal, action, resource) when { principal == User::"alice" };
           ·                                            ──────────────────────────
           ╰────
          help: write it as `principal == ..` in the scope instead; the scope is what lets a policy store slice on this constraint, and what a reader sees first
        "#);
    }

    /// A policy with no conditions at all has nothing to examine.
    #[test]
    fn no_conditions() {
        insta::assert_snapshot!(lint_report(r#"permit(principal, action, resource);"#), @"");
    }
}
