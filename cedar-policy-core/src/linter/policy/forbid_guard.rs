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

//! Flags a `forbid` that fails *open* when a guarded attribute is absent.
//!
//! ```cedar
//! forbid(principal, action, resource) when { principal has banned && principal.banned };
//! ```
//!
//! The guard `principal has banned` makes `principal.banned` safe to read, but in a
//! `forbid` that is the wrong default: with `banned` absent the condition is
//! `false`, the `forbid` does not fire, and some `permit` may allow the request.
//! The `forbid` fails **open**. The fail-*closed* form fires the forbid when the
//! attribute is missing, e.g. `!(e has banned) || e.banned`.
//!
//! This is a `Restriction`, off by default: the fail-closed rewrite denies every
//! entity that lacks the attribute, which may be more restrictive than intended.
//! It is the counterpart of [`attr_guards`](super::attr_guards)'s
//! `forbid-attr-guards`: that lint asks for a guard on every access; this one flags
//! the guard people then write and points at the fail-closed direction. Both are
//! schema-free.
//!
//! # Semantic, not a fixed syntactic shape
//!
//! The property reported is *behavioral*: with attribute `a` absent, the `forbid`'s
//! condition evaluates to `false`. That is checked by abstractly evaluating the
//! condition under the hypothesis "`a` is absent" over the four-valued lattice
//! {`True`, `False`, `Error`, `Unknown`}, following Cedar's short-circuiting `&&`,
//! `||`, and `if`, then reporting when the result is `False`.
//!
//! This subsumes every phrasing at once rather than matching idioms: `e has a &&
//! e.a`, `if e has a then e.a else false`, `e has a && e.a == true`, and
//! `e has a && (e.a || x)` all fold to `false` when `a` is absent and are all
//! reported; an unguarded `e.a` folds to `Error` (the `forbid-attr-guards` lint's
//! concern, not this one), and a fail-closed guard folds to `True` and is not
//! reported.
//!
//! # Which attributes are tested
//!
//! The candidates are the `(target, attr)` pairs the policy `has`-checks anywhere
//! in its condition — the attributes the author is guarding. For each, the
//! condition is evaluated with just that attribute hypothesised absent (all else
//! `Unknown`); a `false` result is a fail-open guard on it.

use std::collections::BTreeSet;

use smol_str::SmolStr;

use crate::{
    ast::{BinaryOp, Effect, Expr, ExprKind, ExprShapeOnly, Template, UnaryOp},
    linter::{
        findings::{Finding, ForbidGuardFailsOpen},
        util::direct_children,
    },
};

/// The four-valued result of abstractly evaluating a condition with one attribute
/// hypothesised absent. `Unknown` stands for "depends on data we did not model".
#[derive(Clone, Copy, PartialEq, Eq)]
enum AbstractVal {
    True,
    False,
    Error,
    Unknown,
}

use AbstractVal::{Error as AErr, False as AFalse, True as ATrue, Unknown as AUnknown};

/// A guarded attribute the policy tests: `(target shape, attr)`.
type AttrKey = (ExprShapeOnly<'static, ()>, SmolStr);

#[derive(Debug, Default)]
pub(crate) struct ForbidGuardLinter {
    findings: Vec<Finding>,
}

impl ForbidGuardLinter {
    /// Lint `template`. Only `forbid` policies are examined; a `permit` guarded by
    /// `has` fails closed, which is the safe direction and not this lint's concern.
    pub(crate) fn lint(&mut self, template: &Template) {
        if template.effect() != Effect::Forbid {
            return;
        }
        let Some(condition) = template.non_scope_constraints() else {
            return;
        };
        // Candidate attributes: everything the policy `has`-checks. These are the
        // attributes the author guards, and so the ones a missing value could make
        // the condition fail open on.
        let mut candidates: Vec<(AttrKey, SmolStr)> = Vec::new();
        collect_has_checks(condition, &mut candidates);

        // Report each candidate whose absence makes the whole condition `false`.
        // Sorted and de-duplicated by attribute name so one attribute reports once.
        let mut reported: BTreeSet<SmolStr> = BTreeSet::new();
        for ((target_shape, attr), attr_name) in candidates {
            if reported.contains(&attr_name) {
                continue;
            }
            if eval_absent(condition, &target_shape, &attr) == AFalse {
                reported.insert(attr_name.clone());
                self.findings.push(
                    ForbidGuardFailsOpen {
                        loc: condition.source_loc().cloned(),
                        attr: attr_name,
                    }
                    .into(),
                );
            }
        }
        self.findings
            .sort_by_key(|f| f.source_loc().map(|l| l.span.offset()));
    }

    /// Consume this linter, returning the findings it accumulated.
    pub(crate) fn into_findings(self) -> Vec<Finding> {
        self.findings
    }
}

/// Collect every `(target, attr)` the condition `has`-checks, keyed by target
/// shape, paired with the attribute name for the message.
fn collect_has_checks(expr: &Expr, out: &mut Vec<(AttrKey, SmolStr)>) {
    if let ExprKind::HasAttr { expr: target, attr } = expr.expr_kind() {
        let key = (
            ExprShapeOnly::new_from_owned((**target).clone()),
            attr.clone(),
        );
        out.push((key, attr.clone()));
    }
    for child in direct_children(expr) {
        collect_has_checks(child, out);
    }
}

/// Abstractly evaluate `expr` under the hypothesis that the attribute `(target,
/// attr)` is absent: `target has attr` is `False`, `target.attr` is `Error`, and
/// everything else that is not a boolean connective is `Unknown`. Booleans follow
/// Cedar's short-circuiting evaluation and error propagation.
fn eval_absent(expr: &Expr, target: &ExprShapeOnly<'static, ()>, attr: &SmolStr) -> AbstractVal {
    match expr.expr_kind() {
        ExprKind::Lit(crate::ast::Literal::Bool(b)) => {
            if *b {
                ATrue
            } else {
                AFalse
            }
        }
        ExprKind::HasAttr { expr: t, attr: a } => {
            if a == attr && shape_eq(t, target) {
                // The hypothesised-absent attribute: `has` is definitely false.
                AFalse
            } else {
                AUnknown
            }
        }
        ExprKind::GetAttr { expr: t, attr: a } => {
            if a == attr && shape_eq(t, target) {
                // Reading the absent attribute errors.
                AErr
            } else {
                AUnknown
            }
        }
        ExprKind::And { left, right } => {
            let l = eval_absent(left, target, attr);
            match l {
                // `&&` short-circuits on a false or erroring left.
                AFalse => AFalse,
                AErr => AErr,
                _ => {
                    let r = eval_absent(right, target, attr);
                    match (l, r) {
                        (_, AFalse) => AFalse,
                        (ATrue, ATrue) => ATrue,
                        (_, AErr) => AErr,
                        _ => AUnknown,
                    }
                }
            }
        }
        ExprKind::Or { left, right } => {
            let l = eval_absent(left, target, attr);
            match l {
                // `||` short-circuits to true on a true left, errors on an erroring
                // left (before the right is reached).
                ATrue => ATrue,
                AErr => AErr,
                _ => {
                    let r = eval_absent(right, target, attr);
                    match (l, r) {
                        (_, ATrue) => ATrue,
                        (AFalse, AFalse) => AFalse,
                        (_, AErr) => AErr,
                        _ => AUnknown,
                    }
                }
            }
        }
        ExprKind::UnaryApp {
            op: UnaryOp::Not,
            arg,
        } => match eval_absent(arg, target, attr) {
            ATrue => AFalse,
            AFalse => ATrue,
            AErr => AErr,
            AUnknown => AUnknown,
        },
        ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => match eval_absent(test_expr, target, attr) {
            ATrue => eval_absent(then_expr, target, attr),
            AFalse => eval_absent(else_expr, target, attr),
            AErr => AErr,
            AUnknown => {
                // Either branch could be taken; join their values.
                join(
                    eval_absent(then_expr, target, attr),
                    eval_absent(else_expr, target, attr),
                )
            }
        },
        // `==` against a boolean literal preserves the abstract value in the useful
        // cases: `x == true` is `x`, `x == false` is `!x`. Other binary ops over
        // the absent attribute could error, but we only need to recognise enough to
        // fold the common guard phrasings; anything else is `Unknown`, unless a
        // sub-expression errors, which propagates.
        ExprKind::BinaryApp {
            op: BinaryOp::Eq,
            arg1,
            arg2,
        } => {
            let a1 = eval_absent(arg1, target, attr);
            let a2 = eval_absent(arg2, target, attr);
            // An error in either operand propagates.
            if a1 == AErr || a2 == AErr {
                return AErr;
            }
            match (bool_lit(arg1), bool_lit(arg2)) {
                (Some(true), _) => a2,
                (_, Some(true)) => a1,
                (Some(false), _) => negate(a2),
                (_, Some(false)) => negate(a1),
                _ => AUnknown,
            }
        }
        // Any other operator evaluates its operands eagerly: if one errors on the
        // absent attribute, the whole expression errors; otherwise it is data we do
        // not model.
        _ => {
            if direct_children(expr).any(|c| eval_absent(c, target, attr) == AErr) {
                AErr
            } else {
                AUnknown
            }
        }
    }
}

/// The join (least-upper-bound) of two abstract values: equal values stay, anything
/// else is `Unknown`.
fn join(a: AbstractVal, b: AbstractVal) -> AbstractVal {
    if a == b {
        a
    } else {
        AUnknown
    }
}

/// Negate an abstract boolean, leaving `Error`/`Unknown` unchanged.
fn negate(a: AbstractVal) -> AbstractVal {
    match a {
        ATrue => AFalse,
        AFalse => ATrue,
        other => other,
    }
}

/// The boolean a literal expression names, if it is one.
fn bool_lit(expr: &Expr) -> Option<bool> {
    match expr.expr_kind() {
        ExprKind::Lit(crate::ast::Literal::Bool(b)) => Some(*b),
        _ => None,
    }
}

/// Is `expr`'s shape equal to the owned target shape?
fn shape_eq(expr: &Expr, target: &ExprShapeOnly<'static, ()>) -> bool {
    &ExprShapeOnly::new_from_owned(expr.clone()) == target
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_policy_or_template;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        let template = parse_policy_or_template(None, src).expect("failed to parse");
        let mut linter = ForbidGuardLinter::default();
        linter.lint(&template);
        render(&linter.into_findings())
    }

    #[test]
    fn guarded_forbid_fails_open() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal has banned && principal.banned };"#), @"
         ⚠ `forbid` fails open when `banned` is absent
          ╭────
        1 │ forbid(principal, action, resource) when { principal has banned && principal.banned };
          ·                                            ────────────────────────────────────────
          ╰────
         help: when `banned` is absent this condition is `false`, so the `forbid` does not fire and a missing attribute fails open; restructure so a missing `banned` makes the condition true (e.g. `!(e has
               banned) || <uses banned>`, or `if e has banned then <uses banned> else true`) to fire the `forbid` instead. Note this denies every entity lacking `banned`, which may be more restrictive than
               intended
        ");
    }

    /// Reported even with other conjuncts between the guard and the access.
    #[test]
    fn guard_and_access_with_gap() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal has banned && context.now > 0 && principal.banned };"#), @"
         ⚠ `forbid` fails open when `banned` is absent
          ╭────
        1 │ forbid(principal, action, resource) when { principal has banned && context.now > 0 && principal.banned };
          ·                                            ───────────────────────────────────────────────────────────
          ╰────
         help: when `banned` is absent this condition is `false`, so the `forbid` does not fire and a missing attribute fails open; restructure so a missing `banned` makes the condition true (e.g. `!(e has
               banned) || <uses banned>`, or `if e has banned then <uses banned> else true`) to fire the `forbid` instead. Note this denies every entity lacking `banned`, which may be more restrictive than
               intended
        ");
    }

    /// The semantic check catches a phrasing the old syntactic matcher missed:
    /// `has a && a == true` also folds to false when `a` is absent.
    #[test]
    fn guard_with_equality_still_fails_open() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal has banned && principal.banned == true };"#), @"
         ⚠ `forbid` fails open when `banned` is absent
          ╭────
        1 │ forbid(principal, action, resource) when { principal has banned && principal.banned == true };
          ·                                            ────────────────────────────────────────────────
          ╰────
         help: when `banned` is absent this condition is `false`, so the `forbid` does not fire and a missing attribute fails open; restructure so a missing `banned` makes the condition true (e.g. `!(e has
               banned) || <uses banned>`, or `if e has banned then <uses banned> else true`) to fire the `forbid` instead. Note this denies every entity lacking `banned`, which may be more restrictive than
               intended
        ");
    }

    /// And a disjunction inside the guarded conjunction: absent `banned` makes the
    /// left `false`, so the whole `&&` is false — still fail-open.
    #[test]
    fn guard_with_inner_disjunction_still_fails_open() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal has banned && (principal.banned || context.x) };"#), @"
         ⚠ `forbid` fails open when `banned` is absent
          ╭────
        1 │ forbid(principal, action, resource) when { principal has banned && (principal.banned || context.x) };
          ·                                            ───────────────────────────────────────────────────────
          ╰────
         help: when `banned` is absent this condition is `false`, so the `forbid` does not fire and a missing attribute fails open; restructure so a missing `banned` makes the condition true (e.g. `!(e has
               banned) || <uses banned>`, or `if e has banned then <uses banned> else true`) to fire the `forbid` instead. Note this denies every entity lacking `banned`, which may be more restrictive than
               intended
        ");
    }

    /// The `if e has a then e.a else false` shape folds to false too.
    #[test]
    fn if_then_else_false_fails_open() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { if principal has banned then principal.banned else false };"#), @"
         ⚠ `forbid` fails open when `banned` is absent
          ╭────
        1 │ forbid(principal, action, resource) when { if principal has banned then principal.banned else false };
          ·                                            ────────────────────────────────────────────────────────
          ╰────
         help: when `banned` is absent this condition is `false`, so the `forbid` does not fire and a missing attribute fails open; restructure so a missing `banned` makes the condition true (e.g. `!(e has
               banned) || <uses banned>`, or `if e has banned then <uses banned> else true`) to fire the `forbid` instead. Note this denies every entity lacking `banned`, which may be more restrictive than
               intended
        ");
    }

    /// `if e has a then e.a else true` fires when the attribute is absent
    /// (folds to true), so it is fail-closed and not reported.
    #[test]
    fn if_then_else_true_is_fail_closed() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { if principal has banned then principal.banned else true };"#), @"");
    }

    /// The fail-closed disjunction `!(e has a) || e.a` folds to true when `a` is
    /// absent, so it is not reported.
    #[test]
    fn fail_closed_disjunction_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { !(principal has banned) || principal.banned };"#), @"");
    }

    /// An unguarded access errors when the attribute is absent (not `false`), so
    /// it is the `forbid-attr-guards` lint's concern, not this one.
    #[test]
    fn unguarded_access_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal.banned };"#), @"");
    }

    /// A `permit` with the fail-open shape is not reported: skipping a permit
    /// denies, the safe direction.
    #[test]
    fn permit_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource) when { principal has banned && principal.banned };"#), @"");
    }

    /// A nested target is matched by shape.
    #[test]
    fn nested_target() {
        insta::assert_snapshot!(lint_report(
            r#"forbid(principal, action, resource) when { principal.org has locked && principal.org.locked };"#), @"
         ⚠ `forbid` fails open when `locked` is absent
          ╭────
        1 │ forbid(principal, action, resource) when { principal.org has locked && principal.org.locked };
          ·                                            ────────────────────────────────────────────────
          ╰────
         help: when `locked` is absent this condition is `false`, so the `forbid` does not fire and a missing attribute fails open; restructure so a missing `locked` makes the condition true (e.g. `!(e has
               locked) || <uses locked>`, or `if e has locked then <uses locked> else true`) to fire the `forbid` instead. Note this denies every entity lacking `locked`, which may be more restrictive than
               intended
        ");
    }
}
