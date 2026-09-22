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

//! Flags a policy whose condition folds to the *same* constant — always true or
//! always false — in every request environment its scope admits. A policy that
//! always applies has a vacuous `when`/`unless`; one that never applies is dead.

use std::collections::BTreeMap;

use crate::{
    ast::{EntityType, EntityUID, Policy, PolicyID, PolicySet},
    linter::findings::{VacuousKind, VacuousPolicy},
    validator::ValidatorSchema,
};

use super::shared::{action_matches, for_each_env, pr_admits};

/// How a single policy's residual evaluates in one request environment: the
/// condition is fixed true, fixed false, or neither (a residual, or unreachable).
#[derive(Clone, Copy, PartialEq, Eq)]
enum PolicyEnvState {
    /// The residual is `true`: the policy applies to every request in this env.
    True,
    /// The residual is `false`: the policy never applies in this env.
    False,
    /// A residual remains, or the policy is not applicable / errored — nothing
    /// uniform to say.
    Other,
}

/// This is a per-policy property, distinct from the decision-level
/// [`trivial_decision`](super::trivial_decision) (a permit can always apply yet be
/// overridden, a forbid can never apply while the decision stays default-deny). It
/// requires the constant to hold in *every* applicable environment, since a
/// condition constant in only some environments is doing real work in the rest.
pub(crate) fn lint(policies: &PolicySet, schema: &ValidatorSchema) -> Vec<VacuousPolicy> {
    lint_tagged(policies, schema)
        .into_iter()
        .map(|(_, f)| f)
        .collect()
}

/// As [`lint`], but each finding is paired with the ID of the policy it is about,
/// for callers that fold these into the policy-scoped [`LintResult`].
pub(crate) fn lint_tagged(
    policies: &PolicySet,
    schema: &ValidatorSchema,
) -> Vec<(crate::ast::PolicyID, VacuousPolicy)> {
    // Per policy, the states across the environments its scope reaches. A policy
    // whose scope excludes an environment simply is not observed there.
    let mut states: BTreeMap<PolicyID, Vec<PolicyEnvState>> = BTreeMap::new();
    for_each_env(policies, schema, |p, a, r, response| {
        for policy in policies.policies() {
            // A policy's residual folds in its *scope*: in an environment the scope
            // excludes, the residual is `false` for a reason that has nothing to do
            // with the `when`/`unless` clauses. Only environments the scope admits
            // say anything about whether the condition is vacuous, so skip the rest.
            if !scope_admits(policy, p, a, r) {
                continue;
            }
            let state = match response.get_residual_policy(policy.id()) {
                Some(rp) => {
                    let residual = rp.get_residual();
                    if residual.is_true() {
                        PolicyEnvState::True
                    } else if residual.is_false() {
                        PolicyEnvState::False
                    } else {
                        PolicyEnvState::Other
                    }
                }
                None => continue,
            };
            states.entry(policy.id().clone()).or_default().push(state);
        }
    });

    let mut out = Vec::new();
    for (id, seen) in &states {
        let Some(policy) = policies.get(id) else {
            continue;
        };
        // A syntactically constant condition (`when { false }`, `when { true }`)
        // is the schema-free `constant-condition` lint's job; leave those to it so
        // the two lints stay disjoint. This lint is for conditions that are only
        // constant once TPE evaluates them against typed-but-unknown request data.
        if policy
            .non_scope_constraints()
            .is_some_and(crate::linter::util::is_constant)
        {
            continue;
        }
        // No scope-admitted environment was observed (e.g. the scope is an `in`,
        // whose satisfaction is an entity-level residual we never resolve): nothing
        // to conclude. Guard explicitly — `all` on an empty slice is vacuously true
        // and would otherwise report every such policy as always-applies.
        if seen.is_empty() {
            continue;
        }
        let kind = if seen.iter().all(|s| *s == PolicyEnvState::True) {
            VacuousKind::AlwaysApplies
        } else if seen.iter().all(|s| *s == PolicyEnvState::False) {
            VacuousKind::NeverApplies
        } else {
            continue;
        };
        out.push((
            id.clone(),
            VacuousPolicy {
                effect: policy.effect(),
                kind,
                loc: policy.loc().cloned(),
            },
        ));
    }
    out
}

/// Does `policy`'s scope evaluate to *definitely true* — no residual — in the
/// environment `(principal, action, resource)`?
///
/// This needs the scope fully decided so that the policy's residual *is* its
/// `when`/`unless` condition, with no scope test folded in. The action is
/// concrete, so any action constraint resolves; a principal/resource constraint is
/// decided only when the entity's *type* settles it (see [`pr_admits`]).
fn scope_admits(
    policy: &Policy,
    principal: &EntityType,
    action: &EntityUID,
    resource: &EntityType,
) -> bool {
    action_matches(policy.action_constraint(), action)
        && pr_admits(policy.principal_constraint().as_inner(), principal)
        && pr_admits(policy.resource_constraint().as_inner(), resource)
}

#[cfg(test)]
mod test {
    use super::super::shared::test_support::schema;
    use super::lint;
    use crate::linter::test_util::render;
    use crate::parser::parse_policyset;

    #[track_caller]
    fn vacuous_report(src: &str) -> String {
        let policies = parse_policyset(src).expect("policy parse");
        let mut findings = lint(&policies, &schema());
        findings.sort_by_key(|f| f.to_string());
        render(&findings)
    }

    /// A permit whose condition is a type-level tautology (`principal is User`,
    /// when `edit` only admits `User` principals) always applies.
    #[test]
    fn permit_condition_always_true_is_vacuous() {
        insta::assert_snapshot!(vacuous_report(
            r#"permit(principal, action == Action::"edit", resource) when { principal is User };"#), @r#"
         ⚠ this permit's condition is always true, so it applies to every request its scope allows
          ╭────
        1 │ permit(principal, action == Action::"edit", resource) when { principal is User };
          · ─────────────────────────────────────────────────────────────────────────────────
          ╰────
         help: its `when`/`unless` clauses evaluate to true in every request environment, so they narrow nothing; drop them or write the intended condition
        "#);
    }

    /// A permit whose condition is a type-level contradiction (`principal is Admin`
    /// when `edit` only admits `User`) never applies: dead code.
    #[test]
    fn permit_condition_always_false_is_vacuous() {
        insta::assert_snapshot!(vacuous_report(
            r#"permit(principal, action == Action::"edit", resource) when { principal is Admin };"#), @r#"
         ⚠ this permit never applies to any request, so it has no effect
          ╭────
        1 │ permit(principal, action == Action::"edit", resource) when { principal is Admin };
          · ──────────────────────────────────────────────────────────────────────────────────
          ╰────
         help: its condition is unsatisfiable in every request environment, so this permit grants nothing; it is likely dead code
        "#);
    }

    /// A forbid whose clause is always true has a vacuous condition too.
    #[test]
    fn forbid_condition_always_true_is_vacuous() {
        insta::assert_snapshot!(vacuous_report(
            r#"forbid(principal, action == Action::"edit", resource) when { resource is Photo };"#), @r#"
         ⚠ this forbid's condition is always true, so it applies to every request its scope allows
          ╭────
        1 │ forbid(principal, action == Action::"edit", resource) when { resource is Photo };
          · ─────────────────────────────────────────────────────────────────────────────────
          ╰────
         help: its `when`/`unless` clauses evaluate to true in every request environment, so they narrow nothing; drop them or write the intended condition
        "#);
    }

    /// A genuinely varying condition is not vacuous in either direction.
    #[test]
    fn varying_condition_is_not_vacuous() {
        insta::assert_snapshot!(vacuous_report(
            r#"permit(principal, action == Action::"edit", resource) when { context.n > 3 };"#),
            @"");
    }

    /// A syntactically constant condition (`when { false }`) is the schema-free
    /// `constant-condition` lint's job, so this lint stays silent on it.
    #[test]
    fn syntactically_constant_condition_is_left_to_constant_condition() {
        insta::assert_snapshot!(vacuous_report(
            r#"permit(principal, action == Action::"edit", resource) when { false };"#),
            @"");
    }

    /// A condition constant in only *some* environments is doing real work in the
    /// rest, so it is not vacuous. `resource is Photo` is always true for `edit`
    /// (only `Photo`) but varies for `view` (`Photo` or `Album`).
    #[test]
    fn condition_constant_in_only_some_envs_is_not_vacuous() {
        insta::assert_snapshot!(vacuous_report(
            r#"permit(principal, action, resource) when { resource is Photo };"#),
            @"");
    }
}
