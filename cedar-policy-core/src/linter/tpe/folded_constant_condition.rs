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

//! Flags a clause sub-expression that type-aware partial evaluation folds to the
//! *same* constant boolean in every request environment the policy applies to.
//!
//! This is the TPE-backed sibling of two syntactic/type-only lints, and is
//! deliberately disjoint from both:
//!
//! * `constant-condition` recognizes a *syntactic* constant — a literal, or an
//!   operator over literals like `1 > 2`. It stops at extension calls, because an
//!   extension constructor can *error* (`ip("bad")`), so it cannot tell a constant
//!   value from a constant error.
//! * `typed-constant-condition` reads a *singleton boolean type* the typechecker
//!   assigns (`principal is User` when every principal is a `User`).
//!
//! Neither catches `ip("10.0.0.0").isInRange(ip("10.0.0.0/8"))`: it is not
//! syntactically constant (it is an extension call) and its type is plain `Bool`,
//! not a singleton. TPE, however, actually evaluates it on a fully-unknown request
//! and folds it to `true`. That is what this lint reports.
//!
//! # Constant, not erroring
//!
//! A sub-expression that *errors* — `ip("bad")`, or arithmetic that overflows for
//! every input — folds to a TPE [`Residual::Error`], not a [`Residual::Concrete`]
//! value, and is **not** reported here. An always-erroring policy is
//! [`policy_always_errors`](super::policy_always_errors)' concern. So this lint
//! fires only on a sub-expression that reduces to a genuine constant `true`/`false`.
//!
//! # Why per-sub-expression, not the whole residual
//!
//! TPE simplifies a constant conjunct *out* of the whole condition (`x && true`
//! becomes `x`), and residuals carry no source locations, so the whole-policy
//! residual cannot point at the dead sub-expression. Instead this converts each
//! clause sub-expression independently to a residual and interprets it, keeping the
//! typed-AST node for its location. A position is reported only when it folds to the
//! same constant in *every* applicable environment — a sub-expression constant in
//! only some environments is doing real work in the rest — and no reported ancestor
//! already covers it.

use std::collections::BTreeSet;

use crate::{
    ast::{Expr, SlotEnv},
    extensions::Extensions,
    tpe::{
        entities::PartialEntities,
        evaluator::Evaluator,
        request::{PartialEntityUID, PartialRequest},
        residual::Residual,
    },
    validator::{
        typecheck::{PolicyCheck, Typechecker},
        types::Type,
        ValidationMode, ValidatorSchema,
    },
};

use crate::linter::findings::FoldedConstantCondition;

/// A `(policy_id, finding)` pair: this lint's findings are policy-scoped.
pub(crate) type Report = (crate::ast::PolicyID, FoldedConstantCondition);

/// Lint every template in `policies`, returning the folded-constant findings tagged
/// with the policy they were found in.
pub(crate) fn lint(policies: &crate::ast::PolicySet, schema: &ValidatorSchema) -> Vec<Report> {
    let typechecker = Typechecker::new(schema, ValidationMode::Strict);
    let extensions = Extensions::all_available();
    let mut out = Vec::new();
    for template in policies.all_templates() {
        for finding in lint_template(&typechecker, schema, extensions, template) {
            out.push((template.id().clone(), finding));
        }
    }
    out
}

/// The clause-body span of `template`, if it has `when`/`unless` clauses.
fn clause_span(template: &crate::ast::Template) -> Option<(usize, usize)> {
    template
        .non_scope_constraints()
        .and_then(|e| e.source_loc().map(|l| (l.span.offset(), l.span.len())))
}

/// The findings for one template: sub-expression positions that fold to the same
/// constant boolean in every environment the policy applies to.
fn lint_template(
    typechecker: &Typechecker<'_>,
    schema: &ValidatorSchema,
    extensions: &Extensions<'_>,
    template: &crate::ast::Template,
) -> Vec<FoldedConstantCondition> {
    let Some(clause_span) = clause_span(template) else {
        return Vec::new();
    };

    // Per applicable environment, the folded boolean value at each sub-expression
    // position of the typed clause. Position `i` is the same node in every
    // environment (the typed ASTs share the source structure), so we can ask whether
    // it folds to one value everywhere.
    //
    // The typed AST is owned per environment (the typechecker hands back an owned
    // `Expr`), so we cannot hold references across iterations; instead the first
    // successful environment records the owned per-position metadata each finding
    // needs (its location, and whether the other constant lints already cover it).
    let mut per_env: Vec<Vec<Option<bool>>> = Vec::new();
    let mut positions: Vec<PositionMeta> = Vec::new();

    for (env, check) in typechecker.typecheck_by_request_env(template) {
        let PolicyCheck::Success(typed) = check else {
            // `Irrelevant` (scope excludes this env) or `Fail`: not an environment
            // this policy applies to.
            continue;
        };
        let (Some(p), Some(a), Some(r)) = (
            env.principal_entity_type(),
            env.action_entity_uid(),
            env.resource_entity_type(),
        ) else {
            continue;
        };
        let Ok(request) = PartialRequest::new(
            PartialEntityUID {
                ty: p.clone(),
                eid: None,
            },
            a.clone(),
            PartialEntityUID {
                ty: r.clone(),
                eid: None,
            },
            None,
            schema,
        ) else {
            continue;
        };
        let entities = PartialEntities::new();
        let evaluator = Evaluator {
            request: &request,
            entities: &entities,
            extensions,
        };

        let subs: Vec<&Expr<Option<Type>>> = typed.subexpressions().collect();
        // The first successful environment fixes the position metadata (owned, so it
        // outlives this iteration's `typed`).
        if positions.is_empty() {
            positions = subs
                .iter()
                .map(|sub| PositionMeta {
                    loc: sub.source_loc().cloned(),
                    // Disjoint from the other "trivially fixed" lints:
                    // `constant-condition` (syntactic), `typed-constant-condition`
                    // (singleton type), and `self-comparison` (identical operands).
                    covered_by_other_lint: crate::linter::util::is_constant(sub)
                        || is_singleton_bool(sub)
                        || is_self_comparison(sub),
                })
                .collect();
        }
        per_env.push(
            subs.iter()
                .map(|sub| folded_bool(&evaluator, sub))
                .collect(),
        );
    }

    // No applicable environment: nothing sound to say.
    if per_env.is_empty() || positions.is_empty() {
        return Vec::new();
    }

    let mut reported_spans: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut findings = Vec::new();
    for (i, meta) in positions.iter().enumerate() {
        let Some(loc) = &meta.loc else {
            continue;
        };
        let span = (loc.span.offset(), loc.span.len());
        // Only the author's clause body, not scope-derived nodes.
        if !within(span, clause_span) {
            continue;
        }
        if meta.covered_by_other_lint {
            continue;
        }
        // The same constant boolean in every environment.
        let first = per_env[0].get(i).copied().flatten();
        let Some(value) = first else {
            continue;
        };
        if !per_env
            .iter()
            .all(|env| env.get(i).copied().flatten() == Some(value))
        {
            continue;
        }
        // Do not report inside an already-reported constant sub-expression: the
        // whole thing is constant, so a constant part of it is noise. Positions are
        // in preorder, so an ancestor is always seen before its descendants.
        if reported_spans
            .iter()
            .any(|&(s, l)| span.0 >= s && span.0 + span.1 <= s + l)
        {
            continue;
        }
        reported_spans.insert(span);
        findings.push(FoldedConstantCondition {
            loc: Some(loc.clone()),
            value,
        });
    }
    findings
}

/// Owned metadata for one sub-expression position, captured from the first
/// environment so it survives after that environment's typed AST is dropped.
struct PositionMeta {
    loc: Option<crate::parser::Loc>,
    /// Already reported by `constant-condition` (syntactic) or
    /// `typed-constant-condition` (singleton type); skip to keep the lints disjoint.
    covered_by_other_lint: bool,
}

/// The boolean `expr` folds to under `evaluator`, if it folds to a concrete
/// boolean. A residual (depends on the request) or an error (`ip("bad")`) yields
/// `None`.
fn folded_bool(evaluator: &Evaluator<'_>, expr: &Expr<Option<Type>>) -> Option<bool> {
    let residual = Residual::try_from_typed_expr(expr, &SlotEnv::new()).ok()?;
    let folded = evaluator.interpret(&residual);
    if folded.is_true() {
        Some(true)
    } else if folded.is_false() {
        Some(false)
    } else {
        None
    }
}

/// Is `expr`'s type a singleton boolean? Those are `typed-constant-condition`'s
/// job, so this lint leaves them alone to keep the two disjoint.
fn is_singleton_bool(expr: &Expr<Option<Type>>) -> bool {
    use crate::validator::types::BoolType;
    matches!(
        expr.data(),
        Some(Type::Bool(BoolType::True)) | Some(Type::Bool(BoolType::False))
    )
}

/// Is `expr` a comparison whose two operands have the same shape — a
/// `self-comparison`? That lint owns these (e.g. `ip(x) == ip(x)`), so this one
/// leaves them alone to avoid double-reporting the same span. Mirrors the predicate
/// in [`self_comparison`](crate::linter::policy::self_comparison).
fn is_self_comparison(expr: &Expr<Option<Type>>) -> bool {
    use crate::ast::{BinaryOp, ExprShapeOnly};
    matches!(
        expr.expr_kind(),
        crate::ast::ExprKind::BinaryApp {
            op: BinaryOp::Eq | BinaryOp::Less | BinaryOp::LessEq | BinaryOp::In,
            arg1,
            arg2,
        } if ExprShapeOnly::new_from_borrowed(arg1.as_ref())
            == ExprShapeOnly::new_from_borrowed(arg2.as_ref())
    )
}

/// Does `(offset, len)` fall within the `(start, len)` clause-body span?
fn within((offset, len): (usize, usize), (start, span_len): (usize, usize)) -> bool {
    offset >= start && offset + len <= start + span_len
}

#[cfg(test)]
mod test {
    use super::super::shared::test_support::schema;
    use super::lint;
    use crate::linter::test_util::render;
    use crate::parser::parse_policyset;

    /// Lint `src` and render the findings (dropping the policy IDs the driver adds).
    #[track_caller]
    fn lint_report(src: &str) -> String {
        let policies = parse_policyset(src).expect("policy parse");
        let mut findings: Vec<_> = lint(&policies, &schema())
            .into_iter()
            .map(|(_, f)| f)
            .collect();
        findings.sort_by_key(|f| f.loc.as_ref().map(|l| l.span.offset()));
        render(&findings)
    }

    /// An extension call over literals folds to a constant even though it is neither
    /// syntactically constant nor singleton-typed.
    #[test]
    fn ext_call_over_literals_folds() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"edit", resource)
               when { ip("10.0.0.0").isInRange(ip("10.0.0.0/8")) };"#), @r#"
         ⚠ this sub-expression is always `true`, whatever the request
          ╭─[2:23]
        1 │ permit(principal, action == Action::"edit", resource)
        2 │                when { ip("10.0.0.0").isInRange(ip("10.0.0.0/8")) };
          ·                       ──────────────────────────────────────────
          ╰────
         help: it evaluates to the same value for every request the policy applies to, so it is not really a condition; remove it or replace it with the intended condition
        "#);
    }

    /// The constant conjunct inside an otherwise-live condition is the one flagged,
    /// not the whole condition.
    #[test]
    fn constant_conjunct_in_live_condition() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"edit", resource)
               when { ip("10.0.0.0").isInRange(ip("10.0.0.0/8")) && context.n > 3 };"#), @r#"
         ⚠ this sub-expression is always `true`, whatever the request
          ╭─[2:23]
        1 │ permit(principal, action == Action::"edit", resource)
        2 │                when { ip("10.0.0.0").isInRange(ip("10.0.0.0/8")) && context.n > 3 };
          ·                       ──────────────────────────────────────────
          ╰────
         help: it evaluates to the same value for every request the policy applies to, so it is not really a condition; remove it or replace it with the intended condition
        "#);
    }

    /// A sub-expression that errors (`ip("bad")`) folds to a TPE error, not a
    /// constant, so it is not reported here.
    #[test]
    fn erroring_ext_call_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"edit", resource)
               when { ip("bad").isLoopback() };"#), @"");
    }

    /// A genuinely varying condition is not folded.
    #[test]
    fn varying_condition_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"edit", resource)
               when { context.n > 3 };"#), @"");
    }

    /// A syntactically constant sub-expression is `constant-condition`'s job, not
    /// this one.
    #[test]
    fn syntactic_constant_is_left_to_constant_condition() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"edit", resource) when { 1 > 2 };"#), @"");
    }

    /// A self-comparison (`ip(x) == ip(x)`) folds to `true`, but it is
    /// `self-comparison`'s job; this lint leaves it alone to avoid double-reporting
    /// the same span.
    #[test]
    fn self_comparison_is_left_to_self_comparison() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"edit", resource)
               when { ip("127.0.0.1") == ip("127.0.0.1") };"#), @"");
    }
}
