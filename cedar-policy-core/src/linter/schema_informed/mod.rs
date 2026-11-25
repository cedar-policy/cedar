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

//! Policy lints that need a schema, run via [`Linter::lint_with_schema`].
//!
//! These use the typechecker as a *service*: they call
//! [`Typechecker::typecheck_by_request_env`] and inspect the typed AST it
//! returns. No analysis is added inside the typechecker itself.
//!
//! # Quantification over request environments
//!
//! A schema admits a set of request environments (`(principal-type, action,
//! resource-type)` triples) that a policy can apply to. A finding here about
//! *redundancy* — a sub-expression that is constant, a guard that is always true —
//! is only reported when it holds in **every** applicable environment. In one
//! environment it would be noise: the author wrote one general policy, and a
//! sub-expression that is constant in only some environments is doing real work in
//! the others.
//!
//! (Findings about a policy being *dead* or a decision being *fixed* have a
//! different, per-environment character; those are TPE's job, in
//! [`tpe`](super::tpe), not this module's.)
//!
//! # Structure
//!
//! The two lints share a driver: typecheck the policy in every request
//! environment, align each typed clause against the source clause (accounting for
//! the typechecker's short-circuiting), then compare the same source sub-expression
//! across environments. That shared machinery ([`Enabled`], [`lint`], [`align`]) lives here; each lint's per-position predicate is in its own
//! submodule ([`typed_constant_condition`], [`has_on_required_attr`]), operating
//! on the [`PerEnv`] view this driver hands it.

use std::collections::HashMap;

use crate::{
    ast::{Expr, ExprKind, Template},
    validator::{
        typecheck::{PolicyCheck, Typechecker},
        types::{BoolType, Type},
        ValidationMode, ValidatorSchema,
    },
};

use super::findings::{Finding, LintFinding};

mod has_on_required_attr;
mod typed_constant_condition;

/// Which schema-informed lints to run.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Enabled {
    pub typed_constant: bool,
    pub has_on_required: bool,
}

/// The author's clause body, aligned against its typed form in each request
/// environment the policy's scope admits.
///
/// Position `i` is the `i`-th node of the *source* clause (preorder). For each
/// environment, `per_env[env][i]` is the typed node for that source node, or
/// `None` if the node is not evaluated in that environment. The typechecker
/// short-circuits `&&`/`||` with a constant left operand (the operator node is
/// replaced by its left operand and the right operand is never typed) and `if`
/// with a constant guard (only the live branch is typed). So typed ASTs from
/// different environments do not have the same shape, and the only sound way to
/// compare "the same sub-expression" across them is through the source tree.
pub(super) struct PerEnv<'a> {
    /// Source clause nodes, in preorder.
    source: Vec<&'a Expr>,
    /// `per_env[env][i]` — the typed node for `source[i]` in `env`, if evaluated.
    per_env: Vec<Vec<Option<&'a Expr<Option<Type>>>>>,
}

impl<'a> PerEnv<'a> {
    /// The number of source sub-expression positions.
    fn len(&self) -> usize {
        self.source.len()
    }

    /// The source sub-expression at position `i`, which a lint inspects
    /// syntactically and anchors its finding at.
    fn source(&self, i: usize) -> Option<&'a Expr> {
        self.source.get(i).copied()
    }

    /// Does `pred` hold at position `i` in every environment where that position
    /// is evaluated (and is it evaluated in at least one)? A sub-expression that
    /// is short-circuited away in an environment never runs there, so it says
    /// nothing about that environment either way.
    fn all_envs(&self, i: usize, pred: impl Fn(&Expr<Option<Type>>) -> bool) -> bool {
        let mut evaluated = self
            .per_env
            .iter()
            .filter_map(|env| env.get(i).copied().flatten())
            .peekable();
        evaluated.peek().is_some() && evaluated.all(pred)
    }
}

/// Run the enabled schema-informed lints over every template in `policies`.
pub(crate) fn lint(
    policies: &crate::ast::PolicySet,
    schema: &ValidatorSchema,
    enabled: Enabled,
) -> Vec<LintFinding> {
    if !enabled.typed_constant && !enabled.has_on_required {
        return Vec::new();
    }
    let typechecker = Typechecker::new(schema, ValidationMode::Strict);
    let mut out = Vec::new();
    for template in policies.all_templates() {
        let findings = lint_template(&typechecker, schema, template, enabled);
        out.extend(LintFinding::tag_all(findings, template.id()));
    }
    out
}

fn lint_template(
    typechecker: &Typechecker<'_>,
    schema: &ValidatorSchema,
    template: &Template,
    enabled: Enabled,
) -> Vec<Finding> {
    // Only the author's `when`/`unless` body is linted: `condition()` also folds
    // in the scope constraints, which are constant by construction. A policy with
    // no clauses (or no source location for them) has nothing to lint.
    let Some(clause) = template.non_scope_constraints() else {
        return Vec::new();
    };
    let Some(clause_span) = span_of(clause) else {
        return Vec::new();
    };

    // Typecheck the policy in every request environment. A policy with a type
    // error in any environment gets no schema-informed findings: its typed ASTs
    // are not a sound basis for "always" claims.
    let mut typed: Vec<Expr<Option<Type>>> = Vec::new();
    for (_env, check) in typechecker.typecheck_by_request_env(template) {
        match check {
            PolicyCheck::Success(e) => typed.push(e),
            // `Irrelevant` means the whole condition is `false` in this
            // environment. That covers both "the scope excludes this environment"
            // and "the scope admits it but the `when`/`unless` body is always
            // false". The latter is exactly the kind of thing these lints are
            // about, so keep it; the former is filtered below, where the scope's
            // `&&` short-circuits and the clause is never typed.
            PolicyCheck::Irrelevant(errs, e) if errs.is_empty() => typed.push(e),
            PolicyCheck::Irrelevant(_, _) | PolicyCheck::Fail(_) => return Vec::new(),
        }
    }

    let source: Vec<&Expr> = clause.subexpressions().collect();
    let index: HashMap<*const Expr, usize> = source
        .iter()
        .enumerate()
        .map(|(i, e)| (std::ptr::from_ref(*e), i))
        .collect();

    let per_env = typed
        .iter()
        .filter_map(|root| {
            // The typed clause is the node carrying the clause's span. If the
            // scope excludes this environment, the scope's `&&` short-circuits
            // before the clause and no such node exists.
            let typed_clause = root
                .subexpressions()
                .find(|e| span_of(e) == Some(clause_span))?;
            let mut slots = vec![None; source.len()];
            align(clause, typed_clause, &index, &mut slots);
            Some(slots)
        })
        .collect();
    let per_env = PerEnv { source, per_env };

    let mut findings = Vec::new();
    if enabled.typed_constant {
        typed_constant_condition::lint(&per_env, &mut findings);
    }
    if enabled.has_on_required {
        has_on_required_attr::lint(&per_env, schema, &mut findings);
    }
    findings.sort_by_key(|f| f.source_loc().map(|l| l.span.offset()));
    findings
}

/// The `(offset, len)` span of `e`, if it has a source location.
fn span_of<T>(e: &Expr<T>) -> Option<(usize, usize)> {
    e.source_loc().map(|l| (l.span.offset(), l.span.len()))
}

/// Record in `slots` the typed node for `src` and, recursively, for each of its
/// sub-expressions that is evaluated, following the typechecker's
/// short-circuiting. Anything not reached stays `None`.
fn align<'a>(
    src: &'a Expr,
    ty: &'a Expr<Option<Type>>,
    index: &HashMap<*const Expr, usize>,
    slots: &mut [Option<&'a Expr<Option<Type>>>],
) {
    if let Some(slot) = index
        .get(&std::ptr::from_ref(src))
        .and_then(|&i| slots.get_mut(i))
    {
        *slot = Some(ty);
    }
    match (src.expr_kind(), ty.expr_kind()) {
        (
            ExprKind::And { left, right },
            ExprKind::And {
                left: tl,
                right: tr,
            },
        )
        | (
            ExprKind::Or { left, right },
            ExprKind::Or {
                left: tl,
                right: tr,
            },
        ) if span_of(tl.as_ref()) == span_of(left.as_ref()) => {
            align(left, tl, index, slots);
            align(right, tr, index, slots);
        }
        // A short-circuited `&&`/`||`: the typed node *is* the left operand
        // (relabeled with the operator's location), and the right operand is
        // never evaluated.
        (ExprKind::And { left, .. } | ExprKind::Or { left, .. }, _) => {
            align(left, ty, index, slots);
        }
        (
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            },
            ExprKind::If {
                test_expr: tt,
                then_expr: tthen,
                else_expr: telse,
            },
        ) => {
            align(test_expr, tt, index, slots);
            // With a constant guard the typechecker types only the live branch
            // (and puts a copy of it in the dead branch's slot).
            match tt.data() {
                Some(Type::Bool(BoolType::True)) => align(then_expr, tthen, index, slots),
                Some(Type::Bool(BoolType::False)) => align(else_expr, telse, index, slots),
                _ => {
                    align(then_expr, tthen, index, slots);
                    align(else_expr, telse, index, slots);
                }
            }
        }
        (ExprKind::Record(src_map), ExprKind::Record(ty_map)) => {
            for (k, v) in src_map.iter() {
                if let Some(tv) = ty_map.get(k) {
                    align(v, tv, index, slots);
                }
            }
        }
        _ => {
            // Every other form is typed structurally: same node kind, children
            // in the same order. If the shapes disagree, stop (conservatively
            // leaving the descendants unevaluated).
            let ((s_kind, sc), (t_kind, tc)) = (children(src), children(ty));
            if s_kind == t_kind && sc.len() == tc.len() {
                for (s, t) in sc.into_iter().zip(tc) {
                    align(s, t, index, slots);
                }
            }
        }
    }
}

/// A tag for the node kind of `e`, and its direct children in source order.
/// (`Record`, `And`, `Or`, and `If` are handled specially by [`align`].)
fn children<T>(e: &Expr<T>) -> (u8, Vec<&Expr<T>>) {
    match e.expr_kind() {
        ExprKind::UnaryApp { arg, .. } => (1, vec![arg]),
        ExprKind::BinaryApp { arg1, arg2, .. } => (2, vec![arg1, arg2]),
        ExprKind::GetAttr { expr, .. } => (3, vec![expr]),
        ExprKind::HasAttr { expr, .. } => (4, vec![expr]),
        ExprKind::ExtHasAttr { expr, .. } => (5, vec![expr]),
        ExprKind::Like { expr, .. } => (6, vec![expr]),
        ExprKind::Is { expr, .. } => (7, vec![expr]),
        ExprKind::ExtensionFunctionApp { args, .. } => (8, args.iter().collect()),
        ExprKind::Set(args) => (9, args.iter().collect()),
        _ => (0, Vec::new()),
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use crate::extensions::Extensions;
    use crate::linter::test_util::render;
    use crate::linter::Lint;
    use crate::parser::parse_policyset;
    use crate::validator::ValidatorSchema;

    /// The schema the schema-informed lint tests share.
    pub(crate) const SCHEMA: &str = r#"
        entity User { name: String, manager?: User };
        entity Photo;
        action view appliesTo { principal: [User], resource: [Photo] };
    "#;

    /// Parse `src`, run the schema-informed lints restricted to `lint` against
    /// [`SCHEMA`], and render the findings.
    #[track_caller]
    pub(crate) fn report(lint: Lint, src: &str) -> String {
        report_with_schema(lint, SCHEMA, src)
    }

    /// [`report`] against a caller-supplied schema.
    #[track_caller]
    pub(crate) fn report_with_schema(lint: Lint, schema: &str, src: &str) -> String {
        let schema = ValidatorSchema::from_cedarschema_str(schema, Extensions::all_available())
            .expect("schema parse")
            .0;
        let policies = parse_policyset(src).expect("policy parse");
        let enabled = super::Enabled {
            typed_constant: lint == Lint::TypedConstantCondition,
            has_on_required: lint == Lint::HasOnRequiredAttr,
        };
        render(&super::lint(&policies, &schema, enabled))
    }
}
