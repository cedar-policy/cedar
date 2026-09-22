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

//! Flags request environments whose authorization decision is fixed regardless of
//! any request data — a whole action, or a principal/resource type under an
//! action, that is *always allowed* or *always denied*.
//!
//! For each request environment the schema admits, this runs TPE on a fully
//! unknown request and asks whether the policy set already reaches a decision. A
//! finding is reported per *whole dimension* (action, principal type, or resource
//! type) that decides uniformly — never a `(principal, action)` pair, which is the
//! ordinary role-grant shape. See the individual functions for aggregation and
//! source-location attribution.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ast::{
        ActionConstraint, Effect, EntityReference, EntityType, EntityUID, Policy, PolicyID,
        PolicySet, PrincipalOrResourceConstraint,
    },
    authorizer::Decision,
    tpe::{
        entities::PartialEntities,
        is_authorized,
        request::{PartialEntityUID, PartialRequest},
    },
    validator::{ValidationMode, ValidatorSchema},
};

use super::shared::action_matches;
use crate::linter::findings::{TrivialDecision, TrivialOutcome};

/// The fixed decision for one request environment, with the policies responsible.
#[derive(Clone, PartialEq, Eq)]
enum EnvOutcome {
    /// Allowed, determined by these permit policies (`Response::reason`).
    Allow(BTreeSet<PolicyID>),
    /// Denied by a forbid always firing, determined by these forbid policies.
    ForbidDeny(BTreeSet<PolicyID>),
    /// Denied because no policy allows it — Cedar's default. Carries the permits
    /// whose scope *matches* this environment but which nonetheless didn't fire —
    /// the candidate culprits for the "why is this denied" explanation.
    DefaultDeny(BTreeSet<PolicyID>),
    /// TPE could not fix a decision: some request in this env decides differently.
    Varies,
}

/// The outcome plus responsible policies shared by a whole dimension, if its
/// environments all agree. This is what a dimension is aggregated by.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum DimVerdict {
    /// Allowed, by exactly this set of determining permits (union across envs).
    Allow(BTreeSet<PolicyID>),
    /// Denied by forbids, by exactly this set of determining forbids.
    ForbidDeny(BTreeSet<PolicyID>),
    /// Denied by default. Carries the scope-matching permits across the
    /// dimension's environments; when exactly one, it is the culprit whose scope
    /// reaches the dimension but which never fires.
    DefaultDeny(BTreeSet<PolicyID>),
}
/// Run the trivial-decision lint over `policies` given `schema`.
pub(crate) fn lint(policies: &PolicySet, schema: &ValidatorSchema) -> Vec<TrivialDecision> {
    let mut envs: Vec<((EntityType, EntityUID, EntityType), EnvOutcome)> = Vec::new();
    for env in schema.unlinked_request_envs(ValidationMode::Strict) {
        let (Some(p), Some(a), Some(r)) = (
            env.principal_entity_type(),
            env.action_entity_uid(),
            env.resource_entity_type(),
        ) else {
            continue;
        };
        let Some(outcome) = env_outcome(policies, schema, p, a, r) else {
            continue;
        };
        envs.push(((p.clone(), a.clone(), r.clone()), outcome));
    }
    report(policies, envs)
}
/// classify the outcome, recording the determining policies.
fn env_outcome(
    policies: &PolicySet,
    schema: &ValidatorSchema,
    principal: &EntityType,
    action: &EntityUID,
    resource: &EntityType,
) -> Option<EnvOutcome> {
    // Fully unknown principal/resource of the environment's types, and unknown
    // context (`None`): if the decision is fixed with all of this unknown, no
    // request in the environment can change it.
    let request = PartialRequest::new(
        PartialEntityUID {
            ty: principal.clone(),
            eid: None,
        },
        action.clone(),
        PartialEntityUID {
            ty: resource.clone(),
            eid: None,
        },
        None,
        schema,
    )
    .ok()?;
    let entities = PartialEntities::new();
    let response = is_authorized(policies, &request, &entities, schema).ok()?;

    Some(match response.decision() {
        None => EnvOutcome::Varies,
        Some(Decision::Allow) => {
            // The determining permits — `reason()` gives exactly the policies that
            // fix the decision.
            EnvOutcome::Allow(response.reason().into_iter().flatten().cloned().collect())
        }
        Some(Decision::Deny) => {
            // A deny with determining forbids is a blanket forbid firing; a deny
            // with no determining policy is Cedar's default (no permit allows it).
            // `reason()` distinguishes them cleanly: it is the true forbids for a
            // deny, empty when the deny is by default.
            let forbids: BTreeSet<PolicyID> =
                response.reason().into_iter().flatten().cloned().collect();
            if forbids.is_empty() {
                // Default deny: record the permits whose scope reaches this
                // environment but which did not fire — the candidate culprits.
                EnvOutcome::DefaultDeny(scope_matching_permits(
                    policies, principal, action, resource,
                ))
            } else {
                EnvOutcome::ForbidDeny(forbids)
            }
        }
    })
}
/// The permits whose scope is jointly satisfiable in the environment
/// `(principal, action, resource)` — the permits that *could* apply here.
///
/// "Could apply" is an existential over concrete entities, evaluated
/// conservatively: a constraint the analysis cannot rule out is treated as
/// satisfiable. So `In(..)` and slot constraints always match (a suitable entity
/// could exist), and only the checks decidable from types alone — the action
/// identity, and `Is`/`Eq` entity *types* — can exclude a permit. Over-matching is
/// the safe direction: the culprit is reported only when exactly one permit
/// matches, so an over-count suppresses the finding rather than misattributing it.
fn scope_matching_permits(
    policies: &PolicySet,
    principal: &EntityType,
    action: &EntityUID,
    resource: &EntityType,
) -> BTreeSet<PolicyID> {
    policies
        .policies()
        .filter(|p| p.effect() == Effect::Permit)
        .filter(|p| {
            action_matches(p.action_constraint(), action)
                && pr_matches(p.principal_constraint().as_inner(), principal)
                && pr_matches(p.resource_constraint().as_inner(), resource)
        })
        .map(|p| p.id().clone())
        .collect()
}
/// How specifically a permit's scope targets the request space — higher means
/// narrower. Used to pick, among several dead permits that all reach a
/// default-denied dimension, the one most plausibly *written for* it: the tightest
/// scope is the strongest "this was meant to grant it, but it is broken" signal.
///
/// Each of the three scope positions contributes: an exact `==`/`is`/`is in`
/// (targets one type or entity) counts more than an `in` (a subtree), which counts
/// more than an unconstrained `Any`.
fn scope_specificity(policy: &Policy) -> u32 {
    let action = match policy.action_constraint() {
        ActionConstraint::Eq(_) => 2,
        ActionConstraint::In(_) => 1,
        ActionConstraint::Any => 0,
        #[cfg(feature = "tolerant-ast")]
        ActionConstraint::ErrorConstraint => 0,
    };
    let pr = |c: &PrincipalOrResourceConstraint| {
        use PrincipalOrResourceConstraint as C;
        match c {
            C::Eq(_) | C::Is(_) | C::IsIn(_, _) => 2,
            C::In(_) => 1,
            C::Any => 0,
        }
    };
    action
        + pr(policy.principal_constraint().as_inner())
        + pr(policy.resource_constraint().as_inner())
}
/// Pick the single most plausible culprit from a set of candidate permits: the one
/// with the strictly highest [`scope_specificity`]. Returns `None` when the set is
/// empty or the top specificity is shared — a tie gives no clear one to blame, so
/// the finding stays unanchored.
fn most_specific_culprit(
    policies: &PolicySet,
    candidates: &BTreeSet<PolicyID>,
) -> Option<PolicyID> {
    let scored: Vec<(&PolicyID, u32)> = candidates
        .iter()
        .filter_map(|id| policies.get(id).map(|p| (id, scope_specificity(p))))
        .collect();
    let top = scored.iter().map(|(_, s)| *s).max()?;
    let mut best = scored.iter().filter(|(_, s)| *s == top);
    match (best.next(), best.next()) {
        // A unique strict maximum: blame it.
        (Some((id, _)), None) => Some((*id).clone()),
        // No candidate, or a tie at the top: no single one to blame.
        _ => None,
    }
}
/// The sole element of `set`, or `None` if it is empty or has more than one.
fn exactly_one(set: BTreeSet<PolicyID>) -> Option<PolicyID> {
    let mut it = set.into_iter();
    match (it.next(), it.next()) {
        (Some(id), None) => Some(id),
        _ => None,
    }
}
/// Could a principal/resource scope constraint be satisfied by *some* entity of
/// type `ty`?
///
/// Conservative: `Any`, `In`, and slots always could (a suitable entity may
/// exist); `Is`/`IsIn` match only their named type; `Eq(uid)` matches only when
/// `uid`'s type is `ty`.
fn pr_matches(constraint: &PrincipalOrResourceConstraint, ty: &EntityType) -> bool {
    use PrincipalOrResourceConstraint as C;
    match constraint {
        C::Any => true,
        C::Is(t) => t.as_ref() == ty,
        C::IsIn(t, _) => t.as_ref() == ty,
        C::Eq(EntityReference::EUID(uid)) => uid.entity_type() == ty,
        // A slot `==`, or any `in` (the entity of `ty` could be a descendant), or
        // an `in`/`==` slot: not excludable from types alone.
        C::Eq(EntityReference::Slot(_)) | C::In(_) => true,
    }
}
/// The verdict shared by every environment of a dimension, if they agree.
///
/// All environments must reach the same *kind* of outcome; for allow and
/// forbid-deny the responsible-policy sets are unioned across the environments.
/// A `Varies` in any environment, or a mix of kinds, means the dimension is not
/// uniform and yields `None`.
fn dimension_verdict<'a>(mut outcomes: impl Iterator<Item = &'a EnvOutcome>) -> Option<DimVerdict> {
    let first = outcomes.next()?;
    let mut verdict = match first {
        EnvOutcome::Allow(ps) => DimVerdict::Allow(ps.clone()),
        EnvOutcome::ForbidDeny(ps) => DimVerdict::ForbidDeny(ps.clone()),
        EnvOutcome::DefaultDeny(ps) => DimVerdict::DefaultDeny(ps.clone()),
        EnvOutcome::Varies => return None,
    };
    for o in outcomes {
        verdict = match (verdict, o) {
            (DimVerdict::Allow(mut acc), EnvOutcome::Allow(ps)) => {
                acc.extend(ps.iter().cloned());
                DimVerdict::Allow(acc)
            }
            (DimVerdict::ForbidDeny(mut acc), EnvOutcome::ForbidDeny(ps)) => {
                acc.extend(ps.iter().cloned());
                DimVerdict::ForbidDeny(acc)
            }
            (DimVerdict::DefaultDeny(mut acc), EnvOutcome::DefaultDeny(ps)) => {
                acc.extend(ps.iter().cloned());
                DimVerdict::DefaultDeny(acc)
            }
            // Mixed kinds, or a `Varies`: not uniform.
            _ => return None,
        };
    }
    Some(verdict)
}
/// A dimension of the request space, for describing a finding's scope.
enum Dimension {
    Action(EntityUID),
    Principal(EntityType),
    Resource(EntityType),
}

impl Dimension {
    fn describe(&self) -> String {
        match self {
            Dimension::Action(a) => format!("for action `{a}`"),
            Dimension::Principal(p) => format!("with any principal of type `{p}`"),
            Dimension::Resource(r) => format!("with any resource of type `{r}`"),
        }
    }
}
/// Aggregate uniform dimensions into findings, merging dimensions that share a
/// verdict (same outcome and same responsible-policy set) into one.
///
/// Only whole dimensions are considered — an action, a principal type, or a
/// resource type — never a `(principal, action)` pair, which is the ordinary
/// role-grant shape. Merging by verdict is what keeps a universal permit (which
/// makes every action, principal, and resource uniformly allowed by the same one
/// policy) to a single finding rather than one per dimension.
fn report(
    policies: &PolicySet,
    envs: Vec<((EntityType, EntityUID, EntityType), EnvOutcome)>,
) -> Vec<TrivialDecision> {
    let mut by_action: BTreeMap<&EntityUID, Vec<&EnvOutcome>> = BTreeMap::new();
    let mut by_principal: BTreeMap<&EntityType, Vec<&EnvOutcome>> = BTreeMap::new();
    let mut by_resource: BTreeMap<&EntityType, Vec<&EnvOutcome>> = BTreeMap::new();
    for ((p, a, r), o) in &envs {
        by_action.entry(a).or_default().push(o);
        by_principal.entry(p).or_default().push(o);
        by_resource.entry(r).or_default().push(o);
    }

    // Which actions are themselves uniform, and with what verdict. Used to
    // suppress a principal/resource-type finding that only restates the actions
    // it lives under.
    let uniform_actions: BTreeMap<&EntityUID, DimVerdict> = by_action
        .iter()
        .filter_map(|(a, os)| dimension_verdict(os.iter().copied()).map(|v| (*a, v)))
        .collect();

    // The actions each principal / resource type appears in, for that suppression
    // check.
    let mut principal_actions: BTreeMap<&EntityType, BTreeSet<&EntityUID>> = BTreeMap::new();
    let mut resource_actions: BTreeMap<&EntityType, BTreeSet<&EntityUID>> = BTreeMap::new();
    for ((p, a, r), _) in &envs {
        principal_actions.entry(p).or_default().insert(a);
        resource_actions.entry(r).or_default().insert(a);
    }

    // A principal/resource dimension is redundant when *every* action it occurs in
    // is itself a uniform finding with the same verdict: the action-level findings
    // already cover it, so reporting the type separately just restates them.
    let subsumed_by_actions = |actions: &BTreeSet<&EntityUID>, verdict: &DimVerdict| {
        actions
            .iter()
            .all(|a| uniform_actions.get(a) == Some(verdict))
    };

    // Collect (verdict, dimension) for every uniform dimension.
    let mut uniform: Vec<(DimVerdict, Dimension)> = Vec::new();
    for (a, v) in &uniform_actions {
        uniform.push((v.clone(), Dimension::Action((*a).clone())));
    }
    for (p, os) in &by_principal {
        if let Some(v) = dimension_verdict(os.iter().copied()) {
            if !subsumed_by_actions(&principal_actions[*p], &v) {
                uniform.push((v, Dimension::Principal((*p).clone())));
            }
        }
    }
    for (r, os) in &by_resource {
        if let Some(v) = dimension_verdict(os.iter().copied()) {
            if !subsumed_by_actions(&resource_actions[*r], &v) {
                uniform.push((v, Dimension::Resource((*r).clone())));
            }
        }
    }

    // The full set of actions: a finding covers "every request" when its
    // dimensions include every action (every environment has some action).
    let all_actions: BTreeSet<&EntityUID> = by_action.keys().copied().collect();

    // Merge dimensions sharing a verdict into one finding.
    let mut by_verdict: BTreeMap<DimVerdict, Vec<Dimension>> = BTreeMap::new();
    for (verdict, dim) in uniform {
        by_verdict.entry(verdict).or_default().push(dim);
    }

    by_verdict
        .into_iter()
        .map(|(verdict, dims)| finding_for(policies, &all_actions, verdict, dims))
        .collect()
}
/// Build one finding for a verdict and the dimensions it covers.
fn finding_for(
    policies: &PolicySet,
    all_actions: &BTreeSet<&EntityUID>,
    verdict: DimVerdict,
    mut dims: Vec<Dimension>,
) -> TrivialDecision {
    // A finding is "every request" when its action dimensions already cover every
    // action — every environment has an action, so covering them all is covering
    // the whole request space.
    let covered_actions: BTreeSet<&EntityUID> = dims
        .iter()
        .filter_map(|d| match d {
            Dimension::Action(a) => Some(a),
            _ => None,
        })
        .collect();
    let every_request = !all_actions.is_empty() && covered_actions == *all_actions;

    // Stable, readable order: actions, then principals, then resources.
    dims.sort_by_key(|d| match d {
        Dimension::Action(_) => 0,
        Dimension::Principal(_) => 1,
        Dimension::Resource(_) => 2,
    });
    let scope = dims
        .iter()
        .map(Dimension::describe)
        .collect::<Vec<_>>()
        .join(", and ");

    // The single policy to anchor at, if there is a clear one. For allow and
    // forbid-deny the determining set genuinely *all* fire, so we blame only when
    // there is exactly one — naming one of several would be misleading. For a
    // default deny the candidates are dead permits that merely *could* have applied;
    // none fires, so there is no "all of them" concern, and we can reasonably blame
    // the most specifically-scoped one — the permit most plausibly written for this
    // request space but broken (see `most_specific_culprit`).
    let (outcome, culprit): (TrivialOutcome, Option<PolicyID>) = match verdict {
        DimVerdict::Allow(ps) => (TrivialOutcome::Allow, exactly_one(ps)),
        DimVerdict::ForbidDeny(ps) => (TrivialOutcome::DenyByForbid, exactly_one(ps)),
        DimVerdict::DefaultDeny(culprits) => (
            TrivialOutcome::DenyByDefault,
            most_specific_culprit(policies, &culprits),
        ),
    };

    let (loc, policy_id) = match culprit {
        Some(id) => (
            policies.get(&id).and_then(|p| p.loc().cloned()),
            Some(id.to_string()),
        ),
        None => (None, None),
    };

    TrivialDecision {
        scope,
        outcome,
        every_request,
        loc,
        policy_id,
    }
}

#[cfg(test)]
mod test {
    use super::super::shared::test_support::schema;
    use super::lint;
    use crate::linter::test_util::render;
    use crate::parser::parse_policyset;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        let policies = parse_policyset(src).expect("policy parse");
        let mut findings = lint(&policies, &schema());
        // Deterministic order for the snapshot.
        findings.sort_by_key(|f| f.to_string());
        render(&findings)
    }

    /// An unconditional permit makes every environment of every action allowed.
    #[test]
    fn always_allow_all_actions() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource);"#), @"
         ⚠ every request is always allowed
          ╭────
        1 │ permit(principal, action, resource);
          · ────────────────────────────────────
          ╰────
         help: policy `policy0` allows this no matter the request data; if that is not intended, it is too permissive
        ");
    }

    /// A permit scoped to one action makes only that action always-allowed.
    #[test]
    fn always_allow_one_action() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"edit", resource);"#), @r#"
         ⚠ every request for action `Action::"edit"` is always allowed
          ╭────
        1 │ permit(principal, action == Action::"edit", resource);
          · ──────────────────────────────────────────────────────
          ╰────
         help: policy `policy0` allows this no matter the request data; if that is not intended, it is too permissive

         ⚠ every request for action `Action::"view"` is always denied
         help: no policy allows this, so it is denied by default; this is request space the policy set never grants
        "#);
    }

    /// A dead permit (condition always false) grants nothing, so every dimension
    /// is default-denied and grouped into a single "denied by default" finding —
    /// the dead permit is invisible to this lint, which reports the *resulting*
    /// coverage gap rather than the permit itself.
    #[test]
    fn dead_permit_yields_default_deny() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"edit", resource) when { false };"#), @r#"
         ⚠ every request for action `Action::"edit"`, and with any principal of type `User`, and with any resource of type `Photo` is always denied
          ╭────
        1 │ permit(principal, action == Action::"edit", resource) when { false };
          · ─────────────────────────────────────────────────────────────────────
          ╰────
         help: permit `policy0` is the permit that could most specifically allow this, but it never does; it may be dead or its condition unsatisfiable

         ⚠ every request for action `Action::"view"` is always denied
         help: no policy allows this, so it is denied by default; this is request space the policy set never grants
        "#);
    }

    /// A blanket forbid is an interesting deny.
    #[test]
    fn blanket_forbid_is_interesting_deny() {
        insta::assert_snapshot!(lint_report(
            r#"
            permit(principal, action, resource);
            forbid(principal, action == Action::"edit", resource);
        "#), @r#"
         ⚠ every request for action `Action::"edit"` is always denied
          ╭─[3:13]
        2 │             permit(principal, action, resource);
        3 │             forbid(principal, action == Action::"edit", resource);
          ·             ──────────────────────────────────────────────────────
        4 │         
          ╰────
         help: forbid `policy1` always fires here; it may be broader than intended

         ⚠ every request for action `Action::"view"` is always allowed
          ╭─[2:13]
        1 │ 
        2 │             permit(principal, action, resource);
          ·             ────────────────────────────────────
        3 │             forbid(principal, action == Action::"edit", resource);
          ╰────
         help: policy `policy0` allows this no matter the request data; if that is not intended, it is too permissive
        "#);
    }

    /// An empty policy set denies everything by default; that is grouped into one
    /// finding covering every dimension, per the always-report-default-deny rule.
    #[test]
    fn empty_policy_set_is_all_default_deny() {
        insta::assert_snapshot!(lint_report(""), @"
        ⚠ every request is always denied
        help: no policy allows this, so it is denied by default; this is request space the policy set never grants
        ");
    }

    /// A conditional permit does not fix `edit`'s decision (the condition may go
    /// either way), so `edit` is omitted; the dimensions the permit never reaches
    /// (`view`, `Admin`, `Album`) are default-denied and grouped. `edit`/`User`/
    /// `Photo` are not uniform, since `edit` varies, so they are absent.
    #[test]
    fn conditional_permit_leaves_edit_unfixed() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"edit", resource) when { resource == Photo::"p" };"#),
            @r#"
        ⚠ every request for action `Action::"view"` is always denied
        help: no policy allows this, so it is denied by default; this is request space the policy set never grants
        "#);
    }

    /// A permit for `Admin` doing `view`: the whole `Admin` principal dimension is
    /// allowed (it reaches only `view`), and the remaining dimensions — `edit`, and
    /// principal `User` — are default-denied and grouped into one finding. The
    /// `(Admin, view)` pair itself is never named as such; the finding is on the
    /// `Admin` dimension.
    #[test]
    fn principal_action_pair_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal is Admin, action == Action::"view", resource);"#), @r#"
         ⚠ every request for action `Action::"edit"`, and with any principal of type `User` is always denied
         help: no policy allows this, so it is denied by default; this is request space the policy set never grants

         ⚠ every request with any principal of type `Admin` is always allowed
          ╭────
        1 │ permit(principal is Admin, action == Action::"view", resource);
          · ───────────────────────────────────────────────────────────────
          ╰────
         help: policy `policy0` allows this no matter the request data; if that is not intended, it is too permissive
        "#);
    }

    /// A *whole principal type* always allowed — across every action and resource
    /// it can reach — is surprising and reported on the principal dimension.
    #[test]
    fn whole_principal_type_always_allowed() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal is Admin, action, resource);"#), @r#"
         ⚠ every request for action `Action::"edit"`, and with any principal of type `User` is always denied
         help: no policy allows this, so it is denied by default; this is request space the policy set never grants

         ⚠ every request with any principal of type `Admin` is always allowed
          ╭────
        1 │ permit(principal is Admin, action, resource);
          · ─────────────────────────────────────────────
          ╰────
         help: policy `policy0` allows this no matter the request data; if that is not intended, it is too permissive
        "#);
    }

    /// A whole resource type always allowed is reported on the resource dimension.
    #[test]
    fn whole_resource_type_always_allowed() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource is Album);"#), @r#"
         ⚠ every request for action `Action::"edit"`, and with any resource of type `Photo` is always denied
         help: no policy allows this, so it is denied by default; this is request space the policy set never grants

         ⚠ every request with any resource of type `Album` is always allowed
          ╭────
        1 │ permit(principal, action, resource is Album);
          · ─────────────────────────────────────────────
          ╰────
         help: policy `policy0` allows this no matter the request data; if that is not intended, it is too permissive
        "#);
    }

    /// Culprit attribution, tricky case 1: a dead permit scoped `principal is
    /// User, action, resource` must NOT be blamed for the default-deny of actions
    /// where `User` is not an allowed principal. `edit` and `view` both allow
    /// `User`, so here the permit *does* match both; the point of the test is that
    /// its scope-match is computed per env, and a `User`-scoped permit reaches only
    /// envs whose principal type is `User`.
    #[test]
    fn dead_broad_permit_blamed_only_where_scope_reaches() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal is User, action, resource) when { false };"#), @"
         ⚠ every request is always denied
          ╭────
        1 │ permit(principal is User, action, resource) when { false };
          · ───────────────────────────────────────────────────────────
          ╰────
         help: permit `policy0` is the permit that could most specifically allow this, but it never does; it may be dead or its condition unsatisfiable

         ⚠ every request with any principal of type `Admin` is always denied
         help: no policy allows this, so it is denied by default; this is request space the policy set never grants
        ");
    }

    /// Culprit attribution, tricky case 2: a dead permit that is the *only* policy
    /// applying to `view` is blamed for `view`'s default-deny.
    #[test]
    fn lone_dead_permit_for_action_is_the_culprit() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"view", resource) when { false };"#), @r#"
         ⚠ every request for action `Action::"edit"` is always denied
         help: no policy allows this, so it is denied by default; this is request space the policy set never grants

         ⚠ every request for action `Action::"view"`, and with any principal of type `User`, and with any resource of type `Photo` is always denied
          ╭────
        1 │ permit(principal, action == Action::"view", resource) when { false };
          · ─────────────────────────────────────────────────────────────────────
          ╰────
         help: permit `policy0` is the permit that could most specifically allow this, but it never does; it may be dead or its condition unsatisfiable
        "#);
    }

    /// Why-deny with *several* candidate permits: two dead permits both reach
    /// `edit`, but one is scoped precisely to `edit` while the other is a broad
    /// `action` permit. The specifically-scoped one is the more plausible "meant to
    /// grant this but broken" culprit, so it — not the broad one — is blamed.
    #[test]
    fn most_specific_dead_permit_is_blamed() {
        insta::assert_snapshot!(lint_report(
            r#"
            permit(principal, action, resource) when { false };
            permit(principal, action == Action::"edit", resource) when { false };
        "#), @r#"
         ⚠ every request for action `Action::"edit"`, and with any principal of type `User`, and with any resource of type `Photo` is always denied
          ╭─[3:13]
        2 │             permit(principal, action, resource) when { false };
        3 │             permit(principal, action == Action::"edit", resource) when { false };
          ·             ─────────────────────────────────────────────────────────────────────
        4 │         
          ╰────
         help: permit `policy1` is the permit that could most specifically allow this, but it never does; it may be dead or its condition unsatisfiable

         ⚠ every request for action `Action::"view"` is always denied
          ╭─[2:13]
        1 │ 
        2 │             permit(principal, action, resource) when { false };
          ·             ───────────────────────────────────────────────────
        3 │             permit(principal, action == Action::"edit", resource) when { false };
          ╰────
         help: permit `policy0` is the permit that could most specifically allow this, but it never does; it may be dead or its condition unsatisfiable
        "#);
    }

    /// A tie at the top specificity gives no clear culprit, so the default-deny
    /// finding stays unanchored rather than arbitrarily naming one of the two
    /// equally-scoped dead permits.
    #[test]
    fn tied_dead_permits_leave_finding_unanchored() {
        insta::assert_snapshot!(lint_report(
            r#"
            permit(principal is User, action == Action::"edit", resource) when { false };
            permit(principal, action == Action::"edit", resource is Photo) when { false };
        "#), @r#"
         ⚠ every request for action `Action::"edit"`, and with any principal of type `User`, and with any resource of type `Photo` is always denied
         help: no policy allows this, so it is denied by default; this is request space the policy set never grants

         ⚠ every request for action `Action::"view"` is always denied
         help: no policy allows this, so it is denied by default; this is request space the policy set never grants
        "#);
    }
}
