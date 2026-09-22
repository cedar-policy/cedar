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

//! Finding types produced by the TPE-based lints. They are variants of
//! [`Finding`](super::Finding) (under the `tpe` feature), so they flow through the
//! ordinary [`LintResult`](crate::linter::LintResult) like every other finding —
//! though the decision-scoped [`TrivialDecision`] carries no policy ID.

use miette::Diagnostic;
use thiserror::Error;

use crate::parser::Loc;

/// Why a [`TrivialDecision`]'s environments reach the decision they do.
///
/// PUBLIC API (under the `tpe` feature): re-exported unchanged from
/// `cedar-policy`; a breaking change here breaks that crate's API too.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TrivialOutcome {
    /// Allowed regardless of request data.
    Allow,
    /// Denied by a `forbid` that always fires.
    DenyByForbid,
    /// Denied by default: no policy allows it. A lone permit whose scope reaches
    /// these environments but never fires may be named as the culprit.
    DenyByDefault,
}

impl TrivialOutcome {
    /// The "allowed" / "denied" word for the headline message.
    fn word(self) -> &'static str {
        match self {
            TrivialOutcome::Allow => "allowed",
            TrivialOutcome::DenyByForbid | TrivialOutcome::DenyByDefault => "denied",
        }
    }
}

/// A group of request environments whose authorization decision is fixed
/// regardless of any request data. Merges every dimension (action, principal
/// type, resource type) that shares one verdict into a single finding, anchored at
/// the responsible policy when exactly one is.
///
/// PUBLIC API (under the `tpe` feature): re-exported unchanged from
/// `cedar-policy`; a breaking change here breaks that crate's API too.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("{}", headline(self))]
pub struct TrivialDecision {
    /// A human description of the fixed dimensions, e.g. ``for action
    /// `Action::"view"`` or ``with any principal of type `User`, and any resource
    /// of type `Photo``` when one policy fixes several dimensions at once.
    pub(crate) scope: String,
    pub(crate) outcome: TrivialOutcome,
    /// True when the finding covers *every* request environment — reported as
    /// "every request" rather than listing all the dimensions.
    pub(crate) every_request: bool,
    /// Source location of the single policy responsible, when exactly one is.
    pub(crate) loc: Option<Loc>,
    /// The ID of that responsible policy, if any, for the message.
    pub(crate) policy_id: Option<String>,
}

/// The headline message: "every request" when the finding spans all environments,
/// otherwise the listed scope.
fn headline(d: &TrivialDecision) -> String {
    let word = d.outcome.word();
    if d.every_request {
        format!("every request is always {word}")
    } else {
        format!("every request {} is always {word}", d.scope)
    }
}

impl Diagnostic for TrivialDecision {
    impl_diagnostic_from_source_loc_opt_field!(loc);

    fn severity(&self) -> Option<miette::Severity> {
        Some(miette::Severity::Warning)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(match (self.outcome, &self.policy_id) {
            (TrivialOutcome::Allow, Some(id)) => format!(
                "policy `{id}` allows this no matter the request data; if that is not intended, it is too permissive"
            ),
            (TrivialOutcome::Allow, None) => {
                "this is allowed no matter the request data; if that is not intended, the policies are too permissive here".to_string()
            }
            (TrivialOutcome::DenyByForbid, Some(id)) => format!(
                "forbid `{id}` always fires here; it may be broader than intended"
            ),
            (TrivialOutcome::DenyByForbid, None) => {
                "a forbid always fires here; it may be broader than intended".to_string()
            }
            (TrivialOutcome::DenyByDefault, Some(id)) => format!(
                "permit `{id}` is the permit that could most specifically allow this, but it never does; it may be dead or its condition unsatisfiable"
            ),
            (TrivialOutcome::DenyByDefault, None) => {
                "no policy allows this, so it is denied by default; this is request space the policy set never grants".to_string()
            }
        }))
    }
}

/// A policy that errors for *every* request in some reachable request
/// environment — its residual, with principal, resource, and context all unknown,
/// is already an error. Every request in that environment therefore errors, and an
/// erroring policy is skipped, so the policy silently has no effect there. In a
/// `forbid` that fails open.
///
/// Unlike [`TrivialDecision`], one environment is enough: an error reachable in
/// any environment is a real bug, not a redundancy that needs to hold everywhere.
///
/// PUBLIC API (under the `tpe` feature): re-exported unchanged from
/// `cedar-policy`; a breaking change here breaks that crate's API too.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("policy `{policy_id}` always errors {env}")]
pub struct AlwaysErrors {
    pub(crate) policy_id: String,
    /// The environment, e.g. ``for principal `User`, action `Action::"view"`,
    /// resource `Photo` ``.
    pub(crate) env: String,
}

impl Diagnostic for AlwaysErrors {
    fn severity(&self) -> Option<miette::Severity> {
        Some(miette::Severity::Warning)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "the policy errors for every request in this environment, so it is skipped there and has no effect; a skipped `forbid` fails open",
        ))
    }
}

/// Whether a [`VacuousPolicy`]'s condition is fixed true (always applies) or
/// fixed false (never applies).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VacuousKind {
    /// The condition is `true` in every applicable environment: the policy
    /// applies to every request its scope admits, so the `when`/`unless` clauses
    /// are doing nothing.
    AlwaysApplies,
    /// The condition is `false` in every applicable environment: the policy never
    /// applies to any request, so it is dead.
    NeverApplies,
}

/// A policy whose condition, after type-aware partial evaluation on a fully
/// unknown request, folds to the same constant in *every* request environment its
/// scope admits — so it either always applies or never does, regardless of request
/// data.
///
/// This is distinct from the decision-level [`TrivialDecision`]: a permit can
/// always apply yet be overridden by a `forbid` (the decision is not fixed), and a
/// forbid can never apply while the decision stays default-deny. It is also broader
/// than the syntactic `constant-condition` and the single-node
/// `typed-constant-condition`: partial evaluation collapses scope-and-condition
/// interactions that neither of those sees.
///
/// One environment is not enough — a condition constant in one environment is
/// doing real work in the others — so this requires the same constant across every
/// applicable environment, like the other redundancy findings.
///
/// PUBLIC API (under the `tpe` feature): re-exported unchanged from
/// `cedar-policy`; a breaking change here breaks that crate's API too.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("{}", vacuous_headline(self))]
pub struct VacuousPolicy {
    pub(crate) effect: crate::ast::Effect,
    pub(crate) kind: VacuousKind,
    pub(crate) loc: Option<Loc>,
}

fn vacuous_headline(d: &VacuousPolicy) -> String {
    let effect = match d.effect {
        crate::ast::Effect::Permit => "permit",
        crate::ast::Effect::Forbid => "forbid",
    };
    match d.kind {
        VacuousKind::AlwaysApplies => {
            format!("this {effect}'s condition is always true, so it applies to every request its scope allows")
        }
        VacuousKind::NeverApplies => {
            format!("this {effect} never applies to any request, so it has no effect")
        }
    }
}

impl Diagnostic for VacuousPolicy {
    impl_diagnostic_from_source_loc_opt_field!(loc);

    fn severity(&self) -> Option<miette::Severity> {
        Some(miette::Severity::Warning)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(match (self.effect, self.kind) {
            (_, VacuousKind::AlwaysApplies) => {
                "its `when`/`unless` clauses evaluate to true in every request environment, so they narrow nothing; drop them or write the intended condition"
            }
            (crate::ast::Effect::Permit, VacuousKind::NeverApplies) => {
                "its condition is unsatisfiable in every request environment, so this permit grants nothing; it is likely dead code"
            }
            (crate::ast::Effect::Forbid, VacuousKind::NeverApplies) => {
                "its condition is unsatisfiable in every request environment, so this forbid denies nothing; it is likely dead code"
            }
        }))
    }
}

/// A sub-expression that type-aware partial evaluation folds to the same constant
/// boolean in *every* request environment the policy applies to. Unlike the
/// syntactic `constant-condition` (which stops at literals and operators over
/// literals) and the type-only `typed-constant-condition` (which reads singleton
/// boolean *types*), this actually evaluates the sub-expression on a fully unknown
/// request, so it also catches an extension call over literals like
/// `ip("10.0.0.0").isInRange(ip("10.0.0.0/8"))`. A sub-expression that *errors*
/// (e.g. `ip("bad")`) folds to a TPE error, not a constant, and is not reported
/// here (that is `policy-always-errors`' concern).
///
/// PUBLIC API (under the `tpe` feature): re-exported unchanged from
/// `cedar-policy`; a breaking change here breaks that crate's API too.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("this sub-expression is always `{value}`, whatever the request")]
pub struct FoldedConstantCondition {
    pub(crate) loc: Option<Loc>,
    /// The constant boolean it folds to in every environment.
    pub(crate) value: bool,
}

impl Diagnostic for FoldedConstantCondition {
    impl_diagnostic_from_source_loc_opt_field!(loc);

    fn severity(&self) -> Option<miette::Severity> {
        Some(miette::Severity::Warning)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "it evaluates to the same value for every request the policy applies to, so it is not really a condition; remove it or replace it with the intended condition",
        ))
    }
}
