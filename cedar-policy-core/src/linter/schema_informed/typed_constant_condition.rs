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

//! Flags a sub-expression whose type is a singleton boolean (`True`/`False`) with
//! the same value in every applicable request environment — a condition that is
//! constant *only* because of type information (`principal is User` when every
//! principal is a `User`).

use crate::validator::types::{BoolType, Type};

use super::super::findings::{Finding, TypedConstantCondition};
use super::PerEnv;

/// The singleton-boolean value of a type, if it is one.
fn singleton_bool(ty: &Option<Type>) -> Option<bool> {
    match ty {
        Some(Type::Bool(BoolType::True)) => Some(true),
        Some(Type::Bool(BoolType::False)) => Some(false),
        _ => None,
    }
}

/// Report each sub-expression position that is a singleton boolean with the same
/// value in every environment's typed AST.
pub(super) fn lint(per_env: &PerEnv<'_>, findings: &mut Vec<Finding>) {
    for i in 0..per_env.len() {
        let Some(sub) = per_env.source(i) else {
            continue;
        };
        // A *syntactically* constant sub-expression — a literal, or an operator
        // over constants like `1 > 2` — is the schema-free `constant-condition`
        // lint's job. This lint is for sub-expressions that are constant *only*
        // because of type information, so skip anything the syntactic predicate
        // already recognizes. The two lints are then exactly disjoint.
        if crate::linter::util::is_constant(sub) {
            continue;
        }
        // Same singleton value in every environment where it is evaluated.
        let Some(value) = [true, false]
            .into_iter()
            .find(|v| per_env.all_envs(i, |e| singleton_bool(e.data()) == Some(*v)))
        else {
            continue;
        };
        findings.push(
            TypedConstantCondition {
                loc: sub.source_loc().cloned(),
                value,
            }
            .into(),
        );
    }
}

#[cfg(test)]
mod test {
    use super::super::test_support::{report, report_with_schema};
    use crate::linter::Lint;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        report(Lint::TypedConstantCondition, src)
    }

    /// `edit` admits both `User` and `Photo` principals, so `principal is User`
    /// varies across `edit`'s environments.
    const MIXED_SCHEMA: &str = r#"
        entity User { name: String };
        entity Photo;
        action view appliesTo { principal: [User], resource: [Photo] };
        action edit appliesTo { principal: [User, Photo], resource: [Photo] };
    "#;

    #[track_caller]
    fn mixed_report(src: &str) -> String {
        report_with_schema(Lint::TypedConstantCondition, MIXED_SCHEMA, src)
    }

    /// A condition that is `false` in some environments (where the typechecker
    /// calls the policy `Irrelevant`) and `true` in the rest is not constant.
    /// Dropping the `false` environments used to report it as always `true`.
    #[test]
    fn false_in_some_envs_is_not_constant() {
        insta::assert_snapshot!(mixed_report(
            r#"permit(principal, action, resource) when { principal is User };"#), @"");
    }

    /// `has` on an attribute declared nowhere, as the whole condition: the policy
    /// is `false` in every environment, and the `has` is reported.
    #[test]
    fn has_undeclared_attr_whole_condition() {
        insta::assert_snapshot!(mixed_report(
            r#"permit(principal, action, resource) when { principal has bogus };"#), @r#"
         ⚠ for policy `policy0`, this sub-expression is always `false` given the schema
          ╭────
        1 │ permit(principal, action, resource) when { principal has bogus };
          ·                                            ───────────────────
          ╰────
         help: its type is a singleton in every request environment this policy applies to, so it has the same value for every request; remove it or replace it with the intended condition
        "#);
    }

    /// The same, as the left of a `&&` (which then short-circuits, so the right
    /// operand is never typed).
    #[test]
    fn has_undeclared_attr_short_circuits_and() {
        insta::assert_snapshot!(mixed_report(
            r#"permit(principal, action, resource) when { principal has bogus && principal.name == "x" };"#), @r#"
         ⚠ for policy `policy0`, this sub-expression is always `false` given the schema
          ╭────
        1 │ permit(principal, action, resource) when { principal has bogus && principal.name == "x" };
          ·                                            ────────────────────────────────────────────
          ╰────
         help: its type is a singleton in every request environment this policy applies to, so it has the same value for every request; remove it or replace it with the intended condition

         ⚠ for policy `policy0`, this sub-expression is always `false` given the schema
          ╭────
        1 │ permit(principal, action, resource) when { principal has bogus && principal.name == "x" };
          ·                                            ───────────────────
          ╰────
         help: its type is a singleton in every request environment this policy applies to, so it has the same value for every request; remove it or replace it with the intended condition
        "#);
    }

    /// `principal is User || principal has bogus`: the `has` is evaluated only
    /// for `Photo` principals (the `||` short-circuits for `User`s), and is
    /// `false` there. Neither the `||` nor the `is` is constant.
    #[test]
    fn has_undeclared_attr_behind_short_circuit_or() {
        insta::assert_snapshot!(mixed_report(
            r#"permit(principal, action, resource) when { principal is User || principal has bogus };"#), @r#"
         ⚠ for policy `policy0`, this sub-expression is always `false` given the schema
          ╭────
        1 │ permit(principal, action, resource) when { principal is User || principal has bogus };
          ·                                                                 ───────────────────
          ╰────
         help: its type is a singleton in every request environment this policy applies to, so it has the same value for every request; remove it or replace it with the intended condition
        "#);
    }

    /// The dead branch of an `if` with a constant guard is not evaluated, so it
    /// is not compared (the typechecker fills that slot with a copy of the live
    /// branch); the guard itself is reported.
    #[test]
    fn if_with_constant_guard() {
        insta::assert_snapshot!(mixed_report(
            r#"permit(principal, action == Action::"view", resource) when { if principal is User then principal.name == "a" else principal has bogus };"#), @r#"
         ⚠ for policy `policy0`, this sub-expression is always `true` given the schema
          ╭────
        1 │ permit(principal, action == Action::"view", resource) when { if principal is User then principal.name == "a" else principal has bogus };
          ·                                                                 ─────────────────
          ╰────
         help: its type is a singleton in every request environment this policy applies to, so it has the same value for every request; remove it or replace it with the intended condition
        "#);
    }

    /// `principal is User` is always true: every principal of `view` is a `User`.
    #[test]
    fn is_always_true() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"view", resource) when { principal is User };"#), @r#"
         ⚠ for policy `policy0`, this sub-expression is always `true` given the schema
          ╭────
        1 │ permit(principal, action == Action::"view", resource) when { principal is User };
          ·                                                              ─────────────────
          ╰────
         help: its type is a singleton in every request environment this policy applies to, so it has the same value for every request; remove it or replace it with the intended condition
        "#);
    }

    /// A real, varying condition is not constant.
    #[test]
    fn varying_condition_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal.name == "admin" };"#), @"");
    }

    /// A bare boolean literal is the syntactic constant-condition lint's job, not
    /// this one, so it is not reported here.
    #[test]
    fn bare_literal_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { true };"#), @"");
    }

    /// The sharpest case: a constant sub-expression *inside* an otherwise-live
    /// condition. `principal is User` is always true, but the policy overall
    /// varies (it depends on `name`), so only the dead conjunct is flagged — not
    /// the whole condition.
    #[test]
    fn constant_subexpr_in_live_condition() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"view", resource) when { principal is User && principal.name == "x" };"#), @r#"
         ⚠ for policy `policy0`, this sub-expression is always `true` given the schema
          ╭────
        1 │ permit(principal, action == Action::"view", resource) when { principal is User && principal.name == "x" };
          ·                                                              ─────────────────
          ╰────
         help: its type is a singleton in every request environment this policy applies to, so it has the same value for every request; remove it or replace it with the intended condition
        "#);
    }

    /// And a *syntactically* constant sub-expression inside a live condition is
    /// left to the schema-free `constant-condition` lint, not double-reported
    /// here: `1 > 2` is syntactically constant, so this lint stays silent on it.
    #[test]
    fn syntactic_constant_subexpr_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { 1 > 2 && principal.name == "x" };"#),
            @"");
    }
}
