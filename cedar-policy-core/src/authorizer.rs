//! This module contains the Cedar "authorizer", which implements the actual
//! authorization logic.
//!
//! Together with the parser, evaluator, and other components, this comprises
//! the "authorization engine".

use crate::ast::*;
use crate::entities::Entities;
use crate::evaluator::{EvaluationError, Evaluator};
use crate::extensions::Extensions;
use itertools::Either;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::iter::once;

/// Authorizer
pub struct Authorizer {
    /// Cedar `Extension`s which will be used during requests to this `Authorizer`
    extensions: Extensions<'static>,
    /// Error-handling behavior of this `Authorizer`
    error_handling: ErrorHandling,
}

/// Describes the possible Cedar error-handling modes. Note that modes other than
/// `SkipOnError` are vestigial: the only official behavior is `SkipOnError`.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorHandling {
    /// Deny the entire request if _any_ policy encounters an evaluation error
    Deny,
    /// If a permit policy errors, skip it (implicit deny).  If a forbid policy
    /// errors, enforce it (explicit deny).
    Forbid,
    /// If a policy encounters an evaluation error, skip it.  The decision will
    /// be as if the erroring policy did not exist.
    Skip,
}

/// A potentially partial answer from the authorizer
#[derive(Debug, Clone)]
pub enum AnswerKind {
    /// A fully evaluated answer
    FullyEvaluated(Answer),
    /// An answer that has some residuals
    Partial(PartialAnswer),
}

impl AnswerKind {
    /// The decision reached, if a decision could be reached
    pub fn decision(&self) -> Option<Decision> {
        match self {
            AnswerKind::FullyEvaluated(a) => Some(a.decision),
            AnswerKind::Partial(_) => None,
        }
    }
}

impl Default for ErrorHandling {
    fn default() -> Self {
        Self::Skip
    }
}

impl Authorizer {
    /// Create a new `Authorizer`
    pub fn new() -> Self {
        Self {
            extensions: Extensions::all_available(), // set at compile time
            error_handling: Default::default(),
        }
    }

    /// Returns an authorization answer for `q` with respect to the given `Slice`.
    ///
    /// The language spec and Dafny model give a precise definition of how this is
    /// computed.
    pub fn is_authorized(&self, q: &Request, pset: &PolicySet, entities: &Entities) -> Answer {
        match self.is_authorized_core(q, pset, entities) {
            AnswerKind::FullyEvaluated(answer) => answer,
            AnswerKind::Partial(partial) => {
                // If we get a residual, we have to treat every residual policy as an error, and obey the error semantics.
                // This can result in an Accept in one case:
                // `error_handling` is `SkipOnerror`, no forbids evaluated to a concrete answer, and some permits evaluated to `true`
                let mut errors = partial.diagnostics.errors;
                errors.extend(partial.residuals.policies().map(|p| {
                    format!(
                        "while evaluating policy {}, encountered the following error: {}",
                        p.id(),
                        EvaluationError::NonValue(p.condition())
                    )
                }));

                let idset = partial.residuals.policies().map(|p| p.id().clone());

                match self.error_handling {
                    ErrorHandling::Deny => Answer::new(
                        Decision::Deny,
                        idset
                            .chain(partial.diagnostics.reason.into_iter())
                            .collect(),
                        errors,
                    ),
                    ErrorHandling::Forbid => Answer::new(
                        Decision::Deny,
                        idset
                            .chain(partial.diagnostics.reason.into_iter())
                            .collect(),
                        errors,
                    ),
                    ErrorHandling::Skip => {
                        // If there were satisfied permits in the residual, then skipping errors means returning `Allow`
                        // This is tricky logic, but it's correct as follows:
                        //  If any permit policy is in the diagnostics, it means it evaluated to a concrete `true` and was not overridden by a `forbid` policy
                        //  That means that all forbid policies evaluated to one of:
                        //    concrete `false`
                        //    concrete error
                        //    a residual (effectively concrete error).
                        // Thus all residuals should be `skipped`
                        // However, if all of the policies are `forbid`, then we still have to return `Deny`, likewise if the set is empty.

                        // This `unwrap` is safe as all policy ids in `diagnostics` are by definition in the policy set
                        if partial
                            .diagnostics
                            .reason
                            .iter()
                            .any(|pid| pset.get(pid).unwrap().effect() == Effect::Permit)
                        {
                            Answer::new(Decision::Allow, partial.diagnostics.reason, errors)
                        } else {
                            Answer::new(
                                Decision::Deny,
                                idset
                                    .chain(partial.diagnostics.reason.into_iter())
                                    .collect(),
                                errors,
                            )
                        }
                    }
                }
            }
        }
    }

    /// Returns an authorization answer for `q` with respect to the given `Slice`.
    /// Partial Evaluation of is_authorized
    ///
    /// The language spec and Dafny model give a precise definition of how this is
    /// computed.
    pub fn is_authorized_core(
        &self,
        q: &Request,
        pset: &PolicySet,
        entities: &Entities,
    ) -> AnswerKind {
        let eval = match Evaluator::new(q, entities, &self.extensions) {
            Ok(eval) => eval,
            Err(e) => {
                let msg = format!(
                    "while initializing the Evaluator, encountered the following error: {e}"
                );
                return AnswerKind::FullyEvaluated(Answer::new(
                    Decision::Deny,
                    HashSet::new(),
                    vec![msg],
                ));
            }
        };

        let results = self.evaluate_policies(pset, eval);

        if !results.global_deny_policies.is_empty() {
            return AnswerKind::FullyEvaluated(Answer::new(
                Decision::Deny,
                results.global_deny_policies,
                results.all_warnings,
            ));
        }
        // Semantics ask for the set C_I^+ of all satisfied Permit policies
        // which override all satisfied Forbid policies. We call this set
        // `satisfied_permits`.
        // Notice that this currently differs from the semantics stated in the Language Spec,
        // which no longer consider overrides. The implementation is however equivalent,
        // since forbids always trump permits.
        let mut satisfied_permits = results
            .satisfied_permits
            .into_iter()
            .filter(|permit_p| {
                results
                    .satisfied_forbids
                    .iter()
                    .all(|forbid_p| Self::overrides(permit_p, forbid_p))
            })
            .peekable();

        match (
            satisfied_permits.peek().is_some(),
            !results.permit_residuals.is_empty(),
            !results.forbid_residuals.is_empty(),
        ) {
            // If we have a satisfied permit and _no_ residual forbids, we can return Allow (this is true regardless of residual permits)
            (true, false | true, false) => {
                let idset = satisfied_permits.map(|p| p.id().clone()).collect();
                AnswerKind::FullyEvaluated(Answer::new(
                    Decision::Allow,
                    idset,
                    results.all_warnings,
                ))
            }
            // If we have a satisfied permit, and there are residual forbids, we must return a residual answer. (this is true regardless of residual permits)
            (true, false | true, true) => {
                let idset = satisfied_permits
                    .map(|p| p.id().clone())
                    .collect::<HashSet<_>>();
                // The residual will consist of all of the residual forbids, and one trivially true `permit`
                let id = idset.iter().next().unwrap().clone(); // This unwrap is safe as we know there are satisfied permits
                let trivial_true = Policy::from_when_clause(Effect::Permit, Expr::val(true), id);
                // This unwrap should be safe, all policy IDs should already be unique
                AnswerKind::Partial(PartialAnswer::new(
                    PolicySet::try_from_iter(
                        results
                            .forbid_residuals
                            .into_iter()
                            .chain(once(trivial_true)),
                    )
                    .unwrap(),
                    idset,
                    results.all_warnings,
                ))
            }
            // If there are no satisfied permits, and no residual permits, then the request cannot succeed
            (false, false, false | true) => {
                let idset = results
                    .satisfied_forbids
                    .into_iter()
                    .map(|p| p.id().clone())
                    .collect();
                AnswerKind::FullyEvaluated(Answer::new(Decision::Deny, idset, results.all_warnings))
            }
            // If there are no satisfied permits, but residual permits, then request may still succeed. Return residual
            // Add in the forbid_residuals if any
            (false, true, false | true) => {
                // The request will definitely fail if there are satisfied forbids, check those
                if !results.satisfied_forbids.is_empty() {
                    let idset = results
                        .satisfied_forbids
                        .into_iter()
                        .map(|p| p.id().clone())
                        .collect();
                    AnswerKind::FullyEvaluated(Answer::new(
                        Decision::Deny,
                        idset,
                        results.all_warnings,
                    ))
                } else {
                    // No satisfied forbids
                    // This unwrap should be safe, all policy IDs should already be unique
                    let all_residuals = PolicySet::try_from_iter(
                        [results.forbid_residuals, results.permit_residuals].concat(),
                    )
                    .unwrap();
                    AnswerKind::Partial(PartialAnswer::new(
                        all_residuals,
                        HashSet::new(),
                        results.all_warnings,
                    ))
                }
            }
        }
    }

    fn evaluate_policies<'a>(
        &'a self,
        pset: &'a PolicySet,
        eval: Evaluator<'_>,
    ) -> EvaluationResults<'a> {
        let mut results = EvaluationResults::default();
        let mut satisfied_policies = vec![];

        for p in pset.policies() {
            match eval.partial_evaluate(p) {
                Ok(Either::Left(answer)) => {
                    if answer {
                        satisfied_policies.push(p)
                    }
                }
                Ok(Either::Right(residual)) => match p.effect() {
                    Effect::Permit => results.permit_residuals.push(Policy::from_when_clause(
                        p.effect(),
                        residual,
                        p.id().clone(),
                    )),
                    Effect::Forbid => results.forbid_residuals.push(Policy::from_when_clause(
                        p.effect(),
                        residual,
                        p.id().clone(),
                    )),
                },
                Err(e) => {
                    results.all_warnings.push(format!(
                        "while evaluating policy {}, encountered the following error: {e}",
                        p.id()
                    ));
                    let satisfied = match self.error_handling {
                        ErrorHandling::Deny => {
                            results.global_deny_policies.insert(p.id().clone());
                            true
                        }
                        ErrorHandling::Forbid => match p.effect() {
                            Effect::Permit => false,
                            Effect::Forbid => true,
                        },
                        ErrorHandling::Skip => false,
                    };
                    if satisfied {
                        satisfied_policies.push(p);
                    }
                }
            };
        }

        let (satisfied_permits, satisfied_forbids) = satisfied_policies
            .iter()
            .partition(|p| p.effect() == Effect::Permit);

        results.satisfied_forbids = satisfied_forbids;
        results.satisfied_permits = satisfied_permits;

        results
    }

    /// Private helper function which determines if policy `p1` overrides policy
    /// `p2`.
    ///
    /// This only makes sense to call with one `Permit` and one `Forbid` policy.
    /// If you call this with two `Permit`s or two `Forbid`s, this will panic.
    fn overrides(p1: &Policy, p2: &Policy) -> bool {
        // For now, we only support the default:
        // all Forbid policies override all Permit policies.
        match (p1.effect(), p2.effect()) {
            (Effect::Forbid, Effect::Permit) => true,
            (Effect::Permit, Effect::Forbid) => false,
            (Effect::Permit, Effect::Permit) => {
                panic!("Shouldn't call overrides() with two Permits")
            }
            (Effect::Forbid, Effect::Forbid) => {
                panic!("Shouldn't call overrides() with two Forbids")
            }
        }
    }
}

impl Default for Authorizer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
struct EvaluationResults<'a> {
    satisfied_permits: Vec<&'a Policy>,
    satisfied_forbids: Vec<&'a Policy>,
    global_deny_policies: HashSet<PolicyID>,
    all_warnings: Vec<String>,
    permit_residuals: Vec<Policy>,
    forbid_residuals: Vec<Policy>,
}

impl std::fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.extensions.ext_names().next().is_none() {
            write!(f, "<Authorizer with no extensions>")
        } else {
            write!(
                f,
                "<Authorizer with the following extensions: {:?}>",
                self.extensions.ext_names().collect::<Vec<_>>()
            )
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use crate::parser;

    use super::*;

    /// Sanity unit test case for is_authorized.
    /// More robust testing is accomplished through the integration tests.
    #[test]
    fn authorizer_sanity_check_empty() {
        let a = Authorizer::new();
        let q = Request::new(
            EntityUID::with_eid("p"),
            EntityUID::with_eid("a"),
            EntityUID::with_eid("r"),
            Context::empty(),
        );
        let pset = PolicySet::new();
        let entities = Entities::new();
        let ans = a.is_authorized(&q, &pset, &entities);
        assert_eq!(ans.decision, Decision::Deny);
    }

    /// Simple tests of skip-on-error semantics
    #[test]
    fn skip_on_error_tests() {
        let a = Authorizer::new();
        let q = Request::new(
            EntityUID::with_eid("p"),
            EntityUID::with_eid("a"),
            EntityUID::with_eid("r"),
            Context::empty(),
        );
        let mut pset = PolicySet::new();
        let entities = Entities::new();

        let p1_src = r#"
        permit(principal, action, resource);
        "#;

        let p2_src = r#"
        permit(principal, action, resource) when { context.bad == 2 };
        "#;

        let p3_src = r#"
        forbid(principal, action, resource) when { context.bad == 2 };
        "#;
        let p4_src = r#"
        forbid(principal, action, resource);
        "#;

        let p1 = parser::parse_policy(Some("1".into()), p1_src).unwrap();
        pset.add_static(p1).unwrap();

        let ans = a.is_authorized(&q, &pset, &entities);
        assert_eq!(ans.decision, Decision::Allow);

        pset.add_static(parser::parse_policy(Some("2".into()), p2_src).unwrap())
            .unwrap();

        let ans = a.is_authorized(&q, &pset, &entities);
        assert_eq!(ans.decision, Decision::Allow);

        pset.add_static(parser::parse_policy(Some("3".into()), p3_src).unwrap())
            .unwrap();

        let ans = a.is_authorized(&q, &pset, &entities);
        assert_eq!(ans.decision, Decision::Allow);

        pset.add_static(parser::parse_policy(Some("4".into()), p4_src).unwrap())
            .unwrap();

        let ans = a.is_authorized(&q, &pset, &entities);
        assert_eq!(ans.decision, Decision::Deny);
    }

    fn true_policy(id: &str, e: Effect) -> StaticPolicy {
        let pid = PolicyID::from_string(id);
        StaticPolicy::new(
            pid,
            BTreeMap::new(),
            e,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Expr::val(true),
        )
        .expect("Policy Creation Failed")
    }

    fn context_pol(id: &str, effect: Effect) -> StaticPolicy {
        let pid = PolicyID::from_string(id);
        StaticPolicy::new(
            pid,
            BTreeMap::new(),
            effect,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Expr::get_attr(Expr::var(Var::Context), "test".into()),
        )
        .expect("Policy Creation Failed")
    }

    #[test]
    fn authorizer_sanity_check_allow() {
        let a = Authorizer::new();
        let q = Request::new(
            EntityUID::with_eid("p"),
            EntityUID::with_eid("a"),
            EntityUID::with_eid("r"),
            Context::empty(),
        );
        let mut pset = PolicySet::new();
        pset.add_static(true_policy("0", Effect::Permit))
            .expect("Policy ID already in PolicySet");
        let entities = Entities::new();
        let ans = a.is_authorized(&q, &pset, &entities);
        assert!(ans.decision == Decision::Allow);
    }

    #[test]
    fn authorizer_sanity_check_partial_deny() {
        let context = Context::from_expr(RestrictedExpr::record([(
            "test".into(),
            RestrictedExpr::new(Expr::unknown("name")).unwrap(),
        )]));
        let a = Authorizer::new();
        let q = Request::new(
            EntityUID::with_eid("p"),
            EntityUID::with_eid("a"),
            EntityUID::with_eid("r"),
            context,
        );
        let mut pset = PolicySet::new();
        pset.add_static(true_policy("0", Effect::Permit))
            .expect("Policy ID already in PolicySet");
        let entities = Entities::new();
        let ans = a.is_authorized(&q, &pset, &entities);
        assert_eq!(ans.decision, Decision::Allow);
        pset.add_static(context_pol("1", Effect::Forbid))
            .expect("Policy ID overlap");
        let ans = a.is_authorized(&q, &pset, &entities);
        assert_eq!(ans.decision, Decision::Allow);

        let mut pset = PolicySet::new();
        let entities = Entities::new();
        pset.add_static(context_pol("1", Effect::Forbid))
            .expect("Policy ID overlap");
        let ans = a.is_authorized(&q, &pset, &entities);
        assert_eq!(ans.decision, Decision::Deny);

        let mut pset = PolicySet::new();
        let entities = Entities::new();
        pset.add_static(context_pol("1", Effect::Permit))
            .expect("Policy ID overlap");
        let ans = a.is_authorized(&q, &pset, &entities);
        assert_eq!(ans.decision, Decision::Deny);
    }

    #[test]
    fn authorizer_sanity_check_deny() {
        let a = Authorizer::new();
        let q = Request::new(
            EntityUID::with_eid("p"),
            EntityUID::with_eid("a"),
            EntityUID::with_eid("r"),
            Context::empty(),
        );
        let mut pset = PolicySet::new();
        pset.add_static(true_policy("0", Effect::Permit))
            .expect("Policy ID already in PolicySet");
        pset.add_static(true_policy("1", Effect::Forbid))
            .expect("Policy ID already in PolicySet");
        let entities = Entities::new();
        let ans = a.is_authorized(&q, &pset, &entities);
        assert!(ans.decision == Decision::Deny);
    }

    #[test]
    fn satisfied_permit_no_forbids() {
        let q = Request::new(
            EntityUID::with_eid("p"),
            EntityUID::with_eid("a"),
            EntityUID::with_eid("r"),
            Context::empty(),
        );
        let a = Authorizer::new();
        let mut pset = PolicySet::new();
        let es = Entities::new();

        let src1 = r#"
        permit(principal == test_entity_type::"p",action,resource);
        "#;
        let src2 = r#"
        forbid(principal == test_entity_type::"p",action,resource) when {
            false
        };
        "#;
        let src3 = r#"
        permit(principal == test_entity_type::"p",action,resource) when {
            unknown("test")
        };
        "#;

        pset.add_static(parser::parse_policy(Some("1".to_string()), src1).unwrap())
            .unwrap();
        pset.add_static(parser::parse_policy(Some("2".to_string()), src2).unwrap())
            .unwrap();

        let r = a.is_authorized_core(&q, &pset, &es).decision();
        assert_eq!(r, Some(Decision::Allow));

        pset.add_static(parser::parse_policy(Some("3".to_string()), src3).unwrap())
            .unwrap();

        let r = a.is_authorized_core(&q, &pset, &es).decision();
        assert_eq!(r, Some(Decision::Allow));
    }

    #[test]
    fn satisfied_permit_residual_forbid() {
        let q = Request::new(
            EntityUID::with_eid("p"),
            EntityUID::with_eid("a"),
            EntityUID::with_eid("r"),
            Context::empty(),
        );
        let a = Authorizer::new();
        let mut pset = PolicySet::new();
        let es = Entities::new();

        let src1 = r#"
        permit(principal,action,resource);
        "#;
        let src2 = r#"
        forbid(principal,action,resource) when {
            unknown("test")
        };
        "#;
        pset.add_static(parser::parse_policy(Some("1".to_string()), src1).unwrap())
            .unwrap();
        pset.add_static(parser::parse_policy(Some("2".to_string()), src2).unwrap())
            .unwrap();

        let r = a.is_authorized_core(&q, &pset, &es);
        match r {
            AnswerKind::FullyEvaluated(_) => panic!("Reached answer, should have gotten residual."),
            AnswerKind::Partial(p) => {
                let map = [("test".into(), Value::Lit(false.into()))]
                    .into_iter()
                    .collect();
                let new = p.residuals.policies().map(|p| {
                    Policy::from_when_clause(
                        p.effect(),
                        p.condition().substitute(&map).unwrap(),
                        p.id().clone(),
                    )
                });
                let pset = PolicySet::try_from_iter(new).unwrap();
                let r = a.is_authorized(&q, &pset, &es);
                assert_eq!(r.decision, Decision::Allow);

                let map = [("test".into(), Value::Lit(true.into()))]
                    .into_iter()
                    .collect();
                let new = p.residuals.policies().map(|p| {
                    Policy::from_when_clause(
                        p.effect(),
                        p.condition().substitute(&map).unwrap(),
                        p.id().clone(),
                    )
                });
                let pset = PolicySet::try_from_iter(new).unwrap();
                let r = a.is_authorized(&q, &pset, &es);
                assert_eq!(r.decision, Decision::Deny);
            }
        }
    }

    #[test]
    fn no_permits() {
        let q = Request::new(
            EntityUID::with_eid("p"),
            EntityUID::with_eid("a"),
            EntityUID::with_eid("r"),
            Context::empty(),
        );
        let a = Authorizer::new();
        let mut pset = PolicySet::new();
        let es = Entities::new();

        let r = a.is_authorized_core(&q, &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));

        let src1 = r#"
        permit(principal, action, resource) when { false };
        "#;

        pset.add_static(parser::parse_policy(Some("1".into()), src1).unwrap())
            .unwrap();
        let r = a.is_authorized_core(&q, &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));

        let src2 = r#"
        forbid(principal, action, resource) when { unknown("a") };
        "#;

        pset.add_static(parser::parse_policy(Some("2".into()), src2).unwrap())
            .unwrap();
        let r = a.is_authorized_core(&q, &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));

        let src3 = r#"
        forbid(principal, action, resource) when { true };
        "#;
        let src4 = r#"
        permit(principal, action, resource) when { true };
        "#;

        pset.add_static(parser::parse_policy(Some("3".into()), src3).unwrap())
            .unwrap();
        pset.add_static(parser::parse_policy(Some("4".into()), src4).unwrap())
            .unwrap();
        let r = a.is_authorized_core(&q, &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));
    }

    #[test]
    fn residual_permits() {
        let q = Request::new(
            EntityUID::with_eid("p"),
            EntityUID::with_eid("a"),
            EntityUID::with_eid("r"),
            Context::empty(),
        );
        let a = Authorizer::new();
        let mut pset = PolicySet::new();
        let es = Entities::new();

        let src1 = r#"
        permit(principal, action, resource) when { false };
        "#;
        let src2 = r#"
        permit(principal, action, resource) when { unknown("a") };
        "#;
        let src3 = r#"
        forbid(principal, action, resource) when { true };
        "#;

        pset.add_static(parser::parse_policy(Some("1".into()), src1).unwrap())
            .unwrap();
        pset.add_static(parser::parse_policy(Some("2".into()), src2).unwrap())
            .unwrap();

        let r = a.is_authorized_core(&q, &pset, &es);
        match r {
            AnswerKind::FullyEvaluated(_) => panic!("Reached answer, should have gotten residual."),
            AnswerKind::Partial(p) => {
                let map = [("a".into(), Value::Lit(false.into()))]
                    .into_iter()
                    .collect();
                let new = p.residuals.policies().map(|p| {
                    Policy::from_when_clause(
                        p.effect(),
                        p.condition().substitute(&map).unwrap(),
                        p.id().clone(),
                    )
                });
                let pset = PolicySet::try_from_iter(new).unwrap();
                let r = a.is_authorized(&q, &pset, &es);
                assert_eq!(r.decision, Decision::Deny);

                let map = [("a".into(), Value::Lit(true.into()))]
                    .into_iter()
                    .collect();
                let new = p.residuals.policies().map(|p| {
                    Policy::from_when_clause(
                        p.effect(),
                        p.condition().substitute(&map).unwrap(),
                        p.id().clone(),
                    )
                });
                let pset = PolicySet::try_from_iter(new).unwrap();
                let r = a.is_authorized(&q, &pset, &es);
                assert_eq!(r.decision, Decision::Allow);
            }
        }

        pset.add_static(parser::parse_policy(Some("3".into()), src3).unwrap())
            .unwrap();
        let r = a.is_authorized_core(&q, &pset, &es);
        assert_eq!(r.decision(), Some(Decision::Deny));
    }
}
// by default, Coverlay does not track coverage for lines after a line
// containing #[cfg(test)].
// we use the following sentinel to "turn back on" coverage tracking for
// remaining lines of this file, until the next #[cfg(test)]
// GRCOV_BEGIN_COVERAGE

/// Authorization answer returned from the `Authorizer`
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Answer {
    /// Authorization decision
    pub decision: Decision,
    /// Diagnostics providing more information on how this decision was reached
    pub diagnostics: Diagnostics,
}

/// Answer that may contain a residual.
#[derive(Debug, PartialEq, Clone)]
pub struct PartialAnswer {
    /// Residual policies
    pub residuals: PolicySet,
    /// Diagnostics providing info
    pub diagnostics: Diagnostics,
}

impl PartialAnswer {
    /// Create a partial answer with a residual PolicySet
    pub fn new(pset: PolicySet, reason: HashSet<PolicyID>, errors: Vec<String>) -> Self {
        PartialAnswer {
            residuals: pset,
            diagnostics: Diagnostics { reason, errors },
        }
    }
}

/// Diagnostics providing more information on how a `Decision` was reached
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Diagnostics {
    /// `PolicyID`s of the policies that contributed to the decision. If no
    /// policies applied to the request, this set will be empty.
    pub reason: HashSet<PolicyID>,
    /// list of error messages which occurred
    pub errors: Vec<String>,
}

impl Answer {
    /// Create a new `Answer`
    pub fn new(decision: Decision, reason: HashSet<PolicyID>, errors: Vec<String>) -> Self {
        Answer {
            decision,
            diagnostics: Diagnostics { reason, errors },
        }
    }
}

/// Decision returned from the `Authorizer`
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Copy)]
pub enum Decision {
    /// The `Authorizer` determined that the request should be allowed
    Allow,
    /// The `Authorizer` determined that the request should be denied.
    /// This is also returned if sufficiently fatal errors are encountered such
    /// that no decision could be safely reached; for example, errors parsing
    /// the policies.
    Deny,
}
