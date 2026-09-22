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

//! Flags a *universal* policy — one whose scope is fully unconstrained and which
//! has no `when`/`unless` clauses, so it applies to every request — that makes
//! other policies in the set redundant or unreachable.
//!
//! A universal policy is not in itself a problem: a policy set consisting of one
//! universal policy is simply open, or closed, by design, and is not reported.
//! What matters is how it interacts with the rest of the set:
//!
//! * A universal `permit` alongside other `permit`s makes those redundant.
//! * A universal `permit` in a set with no `forbid` means nothing can ever deny.
//! * A universal `forbid` denies everything, so (since `forbid` overrides `permit`)
//!   every other policy is dead.
//!
//! This needs the whole policy set, not a single policy.

use crate::{
    ast::{ActionConstraint, Effect, PolicySet, PrincipalOrResourceConstraint, Template},
    linter::findings::{
        Finding, ForbidAllSubsumesPolicies, LintFinding, PermitAllSubsumesPermits,
        PermitAllWithoutForbid,
    },
};

/// Does this policy apply to every request, i.e. is its scope fully unconstrained
/// and does it have no `when`/`unless` clauses?
fn is_universal(template: &Template) -> bool {
    matches!(
        template.principal_constraint().as_inner(),
        PrincipalOrResourceConstraint::Any
    ) && matches!(
        template.resource_constraint().as_inner(),
        PrincipalOrResourceConstraint::Any
    ) && matches!(template.action_constraint(), ActionConstraint::Any)
        && template.non_scope_constraints().is_none()
}

/// Report universal policies that make other policies in the set redundant or
/// unreachable.
pub(crate) fn lint(policy_set: &PolicySet) -> Vec<LintFinding> {
    let total = policy_set.all_templates().count();
    let permits = policy_set
        .all_templates()
        .filter(|t| t.effect() == Effect::Permit)
        .count();
    let forbids = policy_set
        .all_templates()
        .filter(|t| t.effect() == Effect::Forbid)
        .count();

    let mut findings = Vec::new();
    for template in policy_set.all_templates().filter(|t| is_universal(t)) {
        // A universal policy on its own is a deliberate choice, not a mistake.
        if total == 1 {
            continue;
        }
        let loc = || template.loc().cloned();
        let mut here: Vec<Finding> = Vec::new();
        match template.effect() {
            Effect::Permit => {
                // Other `permit`s are made redundant by this one.
                if permits > 1 {
                    here.push(PermitAllSubsumesPermits { loc: loc() }.into());
                }
                // Nothing in the set can deny a request. Note this can only
                // fire alongside the subsumption finding above: with more than
                // one policy and no `forbid`, every other policy is a `permit`.
                if forbids == 0 {
                    here.push(PermitAllWithoutForbid { loc: loc() }.into());
                }
            }
            // `forbid` overrides `permit`, so every other policy is dead,
            // whatever its effect.
            Effect::Forbid => here.push(ForbidAllSubsumesPolicies { loc: loc() }.into()),
        }
        findings.extend(LintFinding::tag_all(here, template.id()));
    }
    findings
}

#[cfg(test)]
mod test {
    use super::lint;
    use crate::linter::test_util::render;
    use crate::parser::parse_policyset;

    #[track_caller]
    fn universal_report(src: &str) -> String {
        let policies = parse_policyset(src).expect("failed to parse");
        render(&lint(&policies))
    }

    /// A universal policy on its own is a deliberate choice: an open policy set,
    /// or a closed one. Neither is reported.
    #[test]
    fn universal_alone_is_not_reported() {
        insta::assert_snapshot!(universal_report(r#"permit(principal, action, resource);"#), @"");
        insta::assert_snapshot!(universal_report(r#"forbid(principal, action, resource);"#), @"");
    }

    /// Both `permit` findings apply when a universal `permit` sits alongside
    /// another `permit` and there is no `forbid`: it subsumes the other `permit`
    /// *and* leaves nothing able to deny.
    #[test]
    fn permit_all_reports_both_findings() {
        insta::assert_snapshot!(universal_report(
            r#"
            permit(principal, action, resource);
            permit(principal == User::"alice", action, resource);
        "#), @r#"
         ⚠ for policy `policy0`, this `permit` applies to every request, making the other `permit` policies redundant
          ╭─[2:13]
        1 │ 
        2 │             permit(principal, action, resource);
          ·             ────────────────────────────────────
        3 │             permit(principal == User::"alice", action, resource);
          ╰────
         help: it allows everything the other, constrained `permit` policies were written to allow selectively

         ⚠ for policy `policy0`, this `permit` applies to every request, and no `forbid` policy can deny one
          ╭─[2:13]
        1 │ 
        2 │             permit(principal, action, resource);
          ·             ────────────────────────────────────
        3 │             permit(principal == User::"alice", action, resource);
          ╰────
         help: every request is allowed; add a `forbid` policy or constrain this one
        "#);
    }

    /// Only the subsumption finding applies when the set does have a `forbid`.
    #[test]
    fn permit_all_with_a_forbid_reports_only_subsumption() {
        insta::assert_snapshot!(universal_report(
            r#"
            permit(principal, action, resource);
            permit(principal == User::"alice", action, resource);
            forbid(principal == User::"bob", action, resource);
        "#), @r#"
         ⚠ for policy `policy0`, this `permit` applies to every request, making the other `permit` policies redundant
          ╭─[2:13]
        1 │ 
        2 │             permit(principal, action, resource);
          ·             ────────────────────────────────────
        3 │             permit(principal == User::"alice", action, resource);
          ╰────
         help: it allows everything the other, constrained `permit` policies were written to allow selectively
        "#);
    }

    /// A universal `forbid` makes every other policy dead, whatever its effect.
    #[test]
    fn forbid_all_subsumes_permits() {
        insta::assert_snapshot!(universal_report(
            r#"
            forbid(principal, action, resource);
            permit(principal == User::"alice", action, resource);
        "#), @r#"
         ⚠ for policy `policy0`, this `forbid` applies to every request, making every other policy unreachable
          ╭─[2:13]
        1 │ 
        2 │             forbid(principal, action, resource);
          ·             ────────────────────────────────────
        3 │             permit(principal == User::"alice", action, resource);
          ╰────
         help: `forbid` overrides every `permit`, so this denies all requests and the rest of the policy set has no effect
        "#);
    }

    #[test]
    fn forbid_all_subsumes_forbids() {
        insta::assert_snapshot!(universal_report(
            r#"
            forbid(principal, action, resource);
            forbid(principal == User::"alice", action, resource);
        "#), @r#"
         ⚠ for policy `policy0`, this `forbid` applies to every request, making every other policy unreachable
          ╭─[2:13]
        1 │ 
        2 │             forbid(principal, action, resource);
          ·             ────────────────────────────────────
        3 │             forbid(principal == User::"alice", action, resource);
          ╰────
         help: `forbid` overrides every `permit`, so this denies all requests and the rest of the policy set has no effect
        "#);
    }

    /// Constrained policies are never universal, so nothing is reported.
    #[test]
    fn constrained_policies_are_not_universal() {
        insta::assert_snapshot!(universal_report(
            r#"
            permit(principal == User::"alice", action, resource);
            permit(principal, action == Action::"view", resource);
            permit(principal, action, resource in Folder::"f");
            permit(principal is User, action, resource);
            permit(principal, action, resource) when { context.x > 1 };
            permit(principal, action, resource) unless { context.x > 1 };
        "#), @"");
    }

    /// A template with a slot is constrained, since the slot is filled on link.
    #[test]
    fn template_slot_is_a_constraint() {
        insta::assert_snapshot!(universal_report(
            r#"
            permit(principal == ?principal, action, resource);
            permit(principal == User::"alice", action, resource);
        "#), @"");
    }
}
