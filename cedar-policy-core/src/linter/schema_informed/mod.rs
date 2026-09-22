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
//! The two lints share a driver: typecheck the policy in every applicable request
//! environment, then compare the same sub-expression position across those typed
//! ASTs. That shared machinery ([`Enabled`], [`lint`], per-environment building,
//! [`within`]) lives here; each lint's per-position predicate is in its own
//! submodule ([`typed_constant_condition`], [`has_on_required_attr`]), operating
//! on the [`PerEnv`] view this driver hands it.

use crate::{
    ast::{Expr, Template},
    validator::{
        typecheck::{PolicyCheck, Typechecker},
        types::Type,
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

/// The same source policy typed in each applicable request environment, as the
/// per-environment lists of subexpressions. Because the typed ASTs share one
/// structure, index `i` names the same sub-expression position in every
/// environment — which is how a lint asks "is this position constant *everywhere*".
pub(super) struct PerEnv<'a> {
    /// `per_env[env][i]` — subexpressions of the typed AST for each environment.
    per_env: Vec<Vec<&'a Expr<Option<Type>>>>,
    /// The `(offset, len)` span of the author's `when`/`unless` clause body.
    clause_span: (usize, usize),
}

impl<'a> PerEnv<'a> {
    /// The number of sub-expression positions (shared across environments).
    fn len(&self) -> usize {
        self.per_env.first().map_or(0, Vec::len)
    }

    /// The sub-expression at position `i` in the first environment — the
    /// representative node a lint inspects and anchors its finding at.
    fn first(&self, i: usize) -> &'a Expr<Option<Type>> {
        self.per_env[0][i]
    }

    /// Is position `i` within the author's clause body? Positions outside it are
    /// scope-derived (folded in by `condition()`) and not linted.
    fn in_clause(&self, i: usize) -> bool {
        within(self.first(i).source_loc(), self.clause_span)
    }

    /// Does `pred` hold at position `i` in *every* environment? A lint uses this to
    /// require a property across all environments the policy applies to.
    fn all_envs(&self, i: usize, pred: impl Fn(&Expr<Option<Type>>) -> bool) -> bool {
        self.per_env
            .iter()
            .all(|env| env.get(i).is_some_and(|e| pred(e)))
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
    // Typecheck the policy in every applicable request environment, collecting
    // the typed condition expression for each. A policy the schema admits no
    // environment for yields nothing.
    let typed: Vec<Expr<Option<Type>>> = typechecker
        .typecheck_by_request_env(template)
        .into_iter()
        .filter_map(|(_env, check)| match check {
            // `Success` is the typed AST; `Irrelevant` means the policy cannot
            // apply in this environment (its scope excludes it), so it is not an
            // environment this policy "applies to" and is skipped.
            PolicyCheck::Success(e) => Some(e),
            PolicyCheck::Irrelevant(_, _) => None,
            PolicyCheck::Fail(_) => None,
        })
        .collect();

    // No applicable environment (or the policy fails to typecheck): nothing sound
    // to say.
    if typed.is_empty() {
        return Vec::new();
    }

    // `condition()` folds the scope constraints into the typed AST as a
    // `&&`-chain of scope-derived nodes (`true`s for an unconstrained scope, the
    // desugared `action == ..` for a constrained one). Those are constant by
    // construction and are not what the author wrote in a `when`/`unless` clause,
    // so restrict findings to the span of the actual clause body. A policy with no
    // clauses has nothing to lint.
    let Some(clause_span) = template
        .non_scope_constraints()
        .and_then(|e| e.source_loc().map(|l| (l.span.offset(), l.span.len())))
    else {
        return Vec::new();
    };

    let per_env = PerEnv {
        per_env: typed.iter().map(|e| e.subexpressions().collect()).collect(),
        clause_span,
    };

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

/// Does `loc` fall within the `(offset, len)` clause-body span?
fn within(loc: Option<&crate::parser::Loc>, (start, len): (usize, usize)) -> bool {
    loc.is_some_and(|l| l.span.offset() >= start && l.span.offset() + l.span.len() <= start + len)
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
        let schema = ValidatorSchema::from_cedarschema_str(SCHEMA, Extensions::all_available())
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
