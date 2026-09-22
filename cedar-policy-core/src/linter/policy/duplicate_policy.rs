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

//! Flags a policy that is a duplicate of an earlier one in the same set.
//!
//! Two policies are duplicates when they have the same effect (`permit`/`forbid`)
//! and the same condition — where "condition" is the whole compiled expression,
//! folding in the scope constraints and the `when`/`unless` clauses. A duplicate
//! is dead weight: it authorizes exactly what its twin already does, so it is
//! either a copy-paste that was meant to be edited, or a merge artifact.
//!
//! This is the analogue of Regal's `duplicate-rule`. Unlike the other lints, it
//! needs the whole [`PolicySet`], not a single policy — like the universal-policy
//! and forbid-without-permit checks it sits beside.
//!
//! # What counts as the same
//!
//! Policies are compared by the *shape* of their condition via [`ExprShapeOnly`],
//! so source locations and policy IDs do not participate — only the structure and
//! the values. This is syntactic, not semantic: two policies that are logically
//! equivalent but written differently (`a && b` vs `b && a`) are **not** reported.
//! Proving semantic equivalence is symcc's job (an unsat check on the symmetric
//! difference); this lint takes only the cheap, exact, always-correct case.
//!
//! Scope constraints are part of the comparison because they are part of the
//! condition: `permit(principal == User::"a", ...)` and
//! `permit(principal, ...) when { principal == User::"a" }` compile to conditions
//! of different shape and so are not reported as duplicates, even though they
//! match the same requests. (`scope-constraints` addresses that pairing
//! separately.)
//!
//! # Templates
//!
//! Two templates with the same effect and the same body shape are duplicates too;
//! the slots occupy the same positions, so the shapes match. A template and a
//! static policy never compare equal, since a slot and a concrete entity have
//! different shape.

use std::collections::HashMap;

use crate::{
    ast::{Effect, ExprShapeOnly, PolicyID, PolicySet},
    linter::findings::{DuplicatePolicy, LintFinding},
};

/// Lint for policies that duplicate an earlier one in the set.
///
/// Each policy is compared against those before it in iteration order; the first
/// occurrence is treated as the original and later matches are reported, so a set
/// of `n` identical policies yields `n - 1` findings, each naming the original.
pub(crate) fn lint_duplicate_policy(policy_set: &PolicySet) -> Vec<LintFinding> {
    // Key each policy by (effect, condition shape); the first policy seen with a
    // given key is the original.
    let mut seen: HashMap<(Effect, ExprShapeOnly<'static, ()>), PolicyID> = HashMap::new();
    let mut findings = Vec::new();

    for template in policy_set.all_templates() {
        // `condition()` returns an owned `Expr`, so the shape must own it too.
        let key = (
            template.effect(),
            ExprShapeOnly::new_from_owned(template.condition()),
        );
        match seen.get(&key) {
            Some(original) => {
                findings.extend(LintFinding::tag_all(
                    [DuplicatePolicy {
                        loc: template.loc().cloned(),
                        original: original.to_string(),
                    }
                    .into()],
                    template.id(),
                ));
            }
            None => {
                seen.insert(key, template.id().clone());
            }
        }
    }
    findings
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_policyset;

    /// Render `src`'s duplicate-policy findings as concatenated pretty miette
    /// output, without color so the snapshots stay readable.
    #[track_caller]
    fn lint_report(src: &str) -> String {
        let policies = parse_policyset(src).expect("failed to parse");
        render(&lint_duplicate_policy(&policies))
    }

    #[test]
    fn exact_duplicate() {
        insta::assert_snapshot!(lint_report(
            r#"
            permit(principal, action, resource) when { principal.admin };
            permit(principal, action, resource) when { principal.admin };
        "#), @"
         ⚠ for policy `policy1`, this policy is a duplicate of `policy0`
          ╭─[3:13]
        2 │             permit(principal, action, resource) when { principal.admin };
        3 │             permit(principal, action, resource) when { principal.admin };
          ·             ─────────────────────────────────────────────────────────────
        4 │         
          ╰────
         help: it has the same effect and condition as `policy0`, so it has no additional effect; remove one of them
        ");
    }

    /// The scope is part of the condition, so identical scopes duplicate too.
    #[test]
    fn duplicate_with_scope() {
        insta::assert_snapshot!(lint_report(
            r#"
            permit(principal == User::"alice", action, resource);
            permit(principal == User::"alice", action, resource);
        "#), @r#"
         ⚠ for policy `policy1`, this policy is a duplicate of `policy0`
          ╭─[3:13]
        2 │             permit(principal == User::"alice", action, resource);
        3 │             permit(principal == User::"alice", action, resource);
          ·             ─────────────────────────────────────────────────────
        4 │         
          ╰────
         help: it has the same effect and condition as `policy0`, so it has no additional effect; remove one of them
        "#);
    }

    /// Three copies give two findings, each naming the first.
    #[test]
    fn triplicate() {
        insta::assert_snapshot!(lint_report(
            r#"
            forbid(principal, action, resource) when { context.blocked };
            forbid(principal, action, resource) when { context.blocked };
            forbid(principal, action, resource) when { context.blocked };
        "#), @"
         ⚠ for policy `policy1`, this policy is a duplicate of `policy0`
          ╭─[3:13]
        2 │             forbid(principal, action, resource) when { context.blocked };
        3 │             forbid(principal, action, resource) when { context.blocked };
          ·             ─────────────────────────────────────────────────────────────
        4 │             forbid(principal, action, resource) when { context.blocked };
          ╰────
         help: it has the same effect and condition as `policy0`, so it has no additional effect; remove one of them

         ⚠ for policy `policy2`, this policy is a duplicate of `policy0`
          ╭─[4:13]
        3 │             forbid(principal, action, resource) when { context.blocked };
        4 │             forbid(principal, action, resource) when { context.blocked };
          ·             ─────────────────────────────────────────────────────────────
        5 │         
          ╰────
         help: it has the same effect and condition as `policy0`, so it has no additional effect; remove one of them
        ");
    }

    /// Same condition but different effect is not a duplicate.
    #[test]
    fn different_effect_is_not_a_duplicate() {
        insta::assert_snapshot!(lint_report(
            r#"
            permit(principal, action, resource) when { principal.admin };
            forbid(principal, action, resource) when { principal.admin };
        "#), @"");
    }

    /// Different conditions are not duplicates.
    #[test]
    fn different_conditions_are_not_duplicates() {
        insta::assert_snapshot!(lint_report(
            r#"
            permit(principal, action, resource) when { principal.admin };
            permit(principal, action, resource) when { principal.owner };
        "#), @"");
    }

    /// Different scopes are not duplicates, even with the same clause.
    #[test]
    fn different_scopes_are_not_duplicates() {
        insta::assert_snapshot!(lint_report(
            r#"
            permit(principal == User::"alice", action, resource);
            permit(principal == User::"bob", action, resource);
        "#), @"");
    }

    /// The comparison is syntactic: logically-equivalent but differently-written
    /// conditions are not reported (that is symcc's job).
    #[test]
    fn logically_equivalent_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"
            permit(principal, action, resource) when { principal.a && principal.b };
            permit(principal, action, resource) when { principal.b && principal.a };
        "#), @"");
    }

    /// A scope constraint and the equivalent condition compile to different
    /// shapes, so they are not reported as duplicates here.
    #[test]
    fn scope_versus_condition_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"
            permit(principal == User::"alice", action, resource);
            permit(principal, action, resource) when { principal == User::"alice" };
        "#), @"");
    }

    /// Identical templates are duplicates.
    #[test]
    fn duplicate_template() {
        insta::assert_snapshot!(lint_report(
            r#"
            permit(principal == ?principal, action, resource) when { principal.admin };
            permit(principal == ?principal, action, resource) when { principal.admin };
        "#), @"
         ⚠ for policy `policy1`, this policy is a duplicate of `policy0`
          ╭─[3:13]
        2 │             permit(principal == ?principal, action, resource) when { principal.admin };
        3 │             permit(principal == ?principal, action, resource) when { principal.admin };
          ·             ───────────────────────────────────────────────────────────────────────────
        4 │         
          ╰────
         help: it has the same effect and condition as `policy0`, so it has no additional effect; remove one of them
        ");
    }

    #[test]
    fn nothing_to_report() {
        insta::assert_snapshot!(lint_report(
            r#"
            permit(principal, action, resource) when { principal.admin };
            forbid(principal, action, resource) when { resource.locked };
        "#), @"");
        insta::assert_snapshot!(lint_report(""), @"");
    }
}
