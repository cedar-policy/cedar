use std::collections::HashMap;

use either::Either;
use smol_str::SmolStr;

use super::{
    Annotations, AuthorizationError, Authorizer, Decision, Effect, Expr, Policy, PolicySet,
    PolicySetError, Request, Response, Value,
};
use crate::{ast::PolicyID, entities::Entities, evaluator::EvaluationError};

/// Enum representing whether a policy is not satisfied due to
/// evaluating to `false`, or because it errored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorState {
    /// The policy did not error
    NoError,
    /// The policy did error
    Error,
}

/// A partially evaluated authorization response.
/// Splits the results into several categories: satisfied, false, and residual for each policy effect.
/// Also tracks all the errors that were encountered during evaluation.
/// This structure currently has to own all of the `PolicyID` objects due to the [`Self::reauthorize`]
/// method. If [`PolicySet`] could borrow its PolicyID/contents then this whole structured could be borrowed.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct PartialResponse {
    /// All of the [`Effect::Permit`] policies that were satisfied
    pub satisfied_permits: HashMap<PolicyID, Annotations>,
    /// All of the [`Effect::Permit`] policies that were not satisfied
    pub false_permits: HashMap<PolicyID, (ErrorState, Annotations)>,
    /// All of the [`Effect::Permit`] policies that evaluated to a residual
    pub residual_permits: HashMap<PolicyID, (Expr, Annotations)>,
    /// All of the [`Effect::Forbid`] policies that were satisfied
    pub satisfied_forbids: HashMap<PolicyID, Annotations>,
    /// All of the [`Effect::Forbid`] policies that were not satisfied
    pub false_forbids: HashMap<PolicyID, (ErrorState, Annotations)>,
    /// All of the [`Effect::Forbid`] policies that evaluated to a residual
    pub residual_forbids: HashMap<PolicyID, (Expr, Annotations)>,
    /// All of the policy errors encountered during evaluation
    pub errors: Vec<AuthorizationError>,
    /// The trivial `true` expression, used for materializing a residual for satisfied policies
    true_expr: Expr,
    /// The trivial `false` expression, used for materializing a residual for non-satisfied policies
    false_expr: Expr,
}

impl PartialResponse {
    /// Create a partial response from each of the policy result categories
    pub fn new(
        true_permits: impl IntoIterator<Item = (PolicyID, Annotations)>,
        false_permits: impl IntoIterator<Item = (PolicyID, (ErrorState, Annotations))>,
        residual_permits: impl IntoIterator<Item = (PolicyID, (Expr, Annotations))>,
        true_forbids: impl IntoIterator<Item = (PolicyID, Annotations)>,
        false_forbids: impl IntoIterator<Item = (PolicyID, (ErrorState, Annotations))>,
        residual_forbids: impl IntoIterator<Item = (PolicyID, (Expr, Annotations))>,
        errors: impl IntoIterator<Item = AuthorizationError>,
    ) -> Self {
        Self {
            satisfied_permits: true_permits.into_iter().collect(),
            false_permits: false_permits.into_iter().collect(),
            residual_permits: residual_permits.into_iter().collect(),
            satisfied_forbids: true_forbids.into_iter().collect(),
            false_forbids: false_forbids.into_iter().collect(),
            residual_forbids: residual_forbids.into_iter().collect(),
            errors: errors.into_iter().collect(),
            true_expr: Expr::val(true),
            false_expr: Expr::val(false),
        }
    }

    /// Convert this response into a concrete evaluation response.
    /// All residuals are treated as errors
    pub fn concretize(self) -> Response {
        self.into()
    }

    /// Attempt to reach a partial decision; the presence of residuals may result in returning [`None`],
    /// indicating that a decision could not be reached given the unknowns
    pub fn decision(&self) -> Option<Decision> {
        match (
            !self.satisfied_permits.is_empty(),
            !self.false_permits.is_empty(),
            !self.residual_permits.is_empty(),
            !self.satisfied_forbids.is_empty(),
            !self.false_forbids.is_empty(),
            !self.residual_forbids.is_empty(),
        ) {
            // Any true forbids means we will deny
            (_, _, _, true, _, _) => Some(Decision::Deny),
            // No potentially or trivially true permits, means we default deny
            (false, _, false, _, _, _) => Some(Decision::Deny),
            // Potentially true forbids, means we don't know
            (_, _, _, _, _, true) => None,
            // No true permits, but some potentially true permits + no true/potentially true forbids means we don't know
            (false, _, true, false, _, false) => None,
            // At least one trivially true permit, and no trivially or possible true forbids, means we allow
            (true, _, _, false, _, false) => Some(Decision::Allow),
        }
    }

    fn satisfied_permit_ids(&self) -> impl Iterator<Item = &PolicyID> {
        self.satisfied_permits.iter().map(first)
    }

    fn satisfied_forbid_ids(&self) -> impl Iterator<Item = &PolicyID> {
        self.satisfied_forbids.iter().map(first)
    }

    /// Returns the set of [`PolicyID`]s that were definitely satisfied
    pub fn definitely_satisfied(&self) -> impl Iterator<Item = &PolicyID> {
        self.satisfied_permit_ids()
            .chain(self.satisfied_forbid_ids())
    }

    /// Returns the set of [`PolicyID`]s that encountered errors
    pub fn definitely_errored(&self) -> impl Iterator<Item = &PolicyID> {
        self.false_permits
            .iter()
            .chain(self.false_forbids.iter())
            .filter_map(did_error)
    }

    /// Returns an over-approximation of the set of determining policies.
    ///
    /// This is all policies that may be determining for any substitution of the unknowns.
    pub fn may_be_determining(&self) -> impl Iterator<Item = &PolicyID> {
        if self.satisfied_forbids.is_empty() {
            // We have no definitely true forbids, so the over approx is everything that is true or potentially true
            Either::Left(
                self.satisfied_permit_ids()
                    .chain(self.residual_permits.keys())
                    .chain(self.residual_forbids.keys()),
            )
        } else {
            // We have definitely true forbids, so we know only things that can determine is
            // true forbids and potentially true forbids
            Either::Right(
                self.satisfied_forbid_ids()
                    .chain(self.residual_forbids.keys()),
            )
        }
    }

    /// Returns an under-approximation of the set of determining policies.
    ///
    /// This is all policies that must be determining for all possible substitutions of the unknowns.
    pub fn definitely_determining(&self) -> impl Iterator<Item = &PolicyID> {
        // If there are no true forbids or potentially true forbids,
        // the the under approximation is the true permits
        if self.satisfied_forbids.is_empty() && self.residual_forbids.is_empty() {
            Either::Left(self.satisfied_permit_ids())
        } else {
            // Otherwise it's the true forbids
            Either::Right(self.satisfied_forbid_ids())
        }
    }

    /// Returns the set of non-trivial (meaning more than just `true` or `false`) residuals expressions
    pub fn nontrivial_residuals(&self) -> impl Iterator<Item = &Expr> {
        self.residual_forbids
            .values()
            .chain(self.residual_permits.values())
            .map(|(r, _)| r)
    }

    /// Returns every policy as a residual expression
    pub fn all_residuals(&self) -> impl Iterator<Item = &Expr> {
        self.all_permit_residuals()
            .chain(self.all_forbid_residuals())
            .map(|(_, (residual, _))| residual)
    }

    /// Returns all residuals expressions that come from [`Effect::Permit`] policies
    fn all_permit_residuals(&self) -> impl Iterator<Item = (&PolicyID, (&Expr, &Annotations))> {
        let trues = self
            .satisfied_permits
            .iter()
            .map(|(id, a)| (id, (&self.true_expr, a)));
        let falses = self
            .false_permits
            .iter()
            .map(|(id, (_, a))| (id, (&self.false_expr, a)));
        let nontrivial = self
            .residual_permits
            .iter()
            .map(|(id, (r, a))| (id, (r, a)));
        trues.chain(falses).chain(nontrivial)
    }

    /// Returns all residuals expressions that come from [`Effect::Forbid`] policies
    fn all_forbid_residuals(&self) -> impl Iterator<Item = (&PolicyID, (&Expr, &Annotations))> {
        let trues = self
            .satisfied_forbids
            .iter()
            .map(|(id, a)| (id, (&self.true_expr, a)));
        let falses = self
            .false_forbids
            .iter()
            .map(|(id, (_, a))| (id, (&self.false_expr, a)));
        let nontrivial = self
            .residual_forbids
            .iter()
            .map(|(id, (r, a))| (id, (r, a)));
        trues.chain(falses).chain(nontrivial)
    }

    /// Return the residual for a given [`PolicyID`], if it exists in the response
    pub fn get(&self, id: &PolicyID) -> Option<&Expr> {
        self.get_true(id)
            .or_else(|| self.get_false(id).or_else(|| self.get_residual(id)))
    }

    fn get_true(&self, id: &PolicyID) -> Option<&Expr> {
        self.satisfied_permits
            .get(id)
            .or_else(|| self.satisfied_forbids.get(id))
            .map(|_| &self.true_expr)
    }

    fn get_false(&self, id: &PolicyID) -> Option<&Expr> {
        self.false_permits
            .get(id)
            .or_else(|| self.false_forbids.get(id))
            .map(|_| &self.false_expr)
    }

    fn get_residual(&self, id: &PolicyID) -> Option<&Expr> {
        self.residual_permits
            .get(id)
            .or_else(|| self.residual_forbids.get(id))
            .map(|(r, _)| r)
    }

    /// Attempt to re-authorize this response given a mapping from unknowns to values
    pub fn reauthorize(
        &self,
        mapping: &HashMap<SmolStr, Value>,
        auth: &Authorizer,
        r: Request,
        es: &Entities,
    ) -> Result<Self, PolicySetError> {
        let policyset = self.all_policies(mapping)?;
        Ok(auth.is_authorized_core(r, &policyset, es))
    }

    fn all_policies<'a>(
        &'a self,
        mapping: &'a HashMap<SmolStr, Value>,
    ) -> Result<PolicySet, PolicySetError> {
        PolicySet::try_from_iter(
            build_policies(Effect::Permit, self.all_permit_residuals(), mapping).chain(
                build_policies(Effect::Forbid, self.all_forbid_residuals(), mapping),
            ),
        )
    }

    fn errors(self) -> impl Iterator<Item = AuthorizationError> {
        self.residual_forbids
            .into_iter()
            .chain(self.residual_permits)
            .map(
                |(id, (expr, _))| AuthorizationError::PolicyEvaluationError {
                    id: id.clone(),
                    error: EvaluationError::non_value(expr),
                },
            )
            .chain(self.errors)
    }
}

impl From<PartialResponse> for Response {
    fn from(p: PartialResponse) -> Self {
        let decision = if !p.satisfied_permits.is_empty() && p.satisfied_forbids.is_empty() {
            Decision::Allow
        } else {
            Decision::Deny
        };
        Response::new(
            decision,
            p.definitely_determining().cloned().collect(),
            p.errors().collect(),
        )
    }
}

/// Builds a set of policies from a set of residuals.
/// `mapping` is used to replace unknowns in the residual with values
fn build_policies<'a>(
    effect: Effect,
    i: impl IntoIterator<Item = (&'a PolicyID, (&'a Expr, &'a Annotations))> + 'a,
    mapping: &'a HashMap<SmolStr, Value>,
) -> impl Iterator<Item = Policy> + 'a {
    i.into_iter().map(move |(id, (residual, annotations))| {
        let residual = residual.substitute(mapping);
        Policy::from_when_clause_annos(effect, residual, id.clone(), annotations.clone())
    })
}

fn did_error<'a>(
    (id, (state, _)): (&'a PolicyID, &'_ (ErrorState, Annotations)),
) -> Option<&'a PolicyID> {
    match *state {
        ErrorState::NoError => None,
        ErrorState::Error => Some(id),
    }
}

fn first<A, B>((x, _): (A, B)) -> A {
    x
}

#[cfg(test)]
// PANIC SAFETY testing
#[allow(clippy::indexing_slicing)]
mod test {
    use std::{
        collections::HashSet,
        iter::{empty, once},
    };

    use crate::authorizer::{ActionConstraint, PrincipalConstraint, ResourceConstraint};

    use super::*;

    #[test]
    fn sanity_check() {
        let a = once((PolicyID::from_string("a"), Annotations::default()));
        let bc = [
            (
                PolicyID::from_string("b"),
                (ErrorState::Error, Annotations::default()),
            ),
            (
                PolicyID::from_string("c"),
                (ErrorState::NoError, Annotations::default()),
            ),
        ];
        let d = once((
            PolicyID::from_string("d"),
            (
                Expr::add(Expr::val(1), Expr::val(2)),
                Annotations::default(),
            ),
        ));
        let e = once((PolicyID::from_string("e"), Annotations::default()));
        let fg = [
            (
                PolicyID::from_string("f"),
                (ErrorState::Error, Annotations::default()),
            ),
            (
                PolicyID::from_string("g"),
                (ErrorState::NoError, Annotations::default()),
            ),
        ];
        let h = once((
            PolicyID::from_string("h"),
            (
                Expr::add(Expr::val(1), Expr::val(2)),
                Annotations::default(),
            ),
        ));
        let errs = empty();
        let pr = PartialResponse::new(a, bc, d, e, fg, h, errs);
        assert_eq!(
            pr.satisfied_permit_ids().collect::<HashSet<_>>(),
            HashSet::from([&PolicyID::from_string("a")])
        );
        assert_eq!(
            pr.satisfied_forbid_ids().collect::<HashSet<_>>(),
            HashSet::from([&PolicyID::from_string("e")])
        );
        assert_eq!(
            pr.definitely_satisfied().collect::<HashSet<_>>(),
            HashSet::from([&PolicyID::from_string("a"), &PolicyID::from_string("e")])
        );
        assert_eq!(
            pr.definitely_errored().collect::<HashSet<_>>(),
            HashSet::from([&PolicyID::from_string("b"), &PolicyID::from_string("f")])
        );
        assert_eq!(
            pr.may_be_determining().collect::<HashSet<_>>(),
            HashSet::from([&PolicyID::from_string("e"), &PolicyID::from_string("h")])
        );
        assert_eq!(
            pr.definitely_determining().collect::<HashSet<_>>(),
            HashSet::from([&PolicyID::from_string("e")])
        );
        assert_eq!(pr.nontrivial_residuals().count(), 2);
        assert_eq!(
            pr.nontrivial_residuals().collect::<HashSet<_>>(),
            HashSet::from([&Expr::add(Expr::val(1), Expr::val(2))])
        );
        assert_eq!(pr.all_residuals().count(), 8);
        assert_eq!(
            pr.all_residuals().collect::<HashSet<_>>(),
            HashSet::from([
                &Expr::add(Expr::val(1), Expr::val(2)),
                &Expr::val(true),
                &Expr::val(false)
            ])
        );

        assert_eq!(pr.get(&PolicyID::from_string("a")), Some(&Expr::val(true)));
        assert_eq!(pr.get(&PolicyID::from_string("b")), Some(&Expr::val(false)));
        assert_eq!(pr.get(&PolicyID::from_string("c")), Some(&Expr::val(false)));
        assert_eq!(
            pr.get(&PolicyID::from_string("d")),
            Some(&Expr::add(Expr::val(1), Expr::val(2)))
        );
        assert_eq!(pr.get(&PolicyID::from_string("e")), Some(&Expr::val(true)));
        assert_eq!(pr.get(&PolicyID::from_string("f")), Some(&Expr::val(false)));
        assert_eq!(pr.get(&PolicyID::from_string("g")), Some(&Expr::val(false)));
        assert_eq!(
            pr.get(&PolicyID::from_string("h")),
            Some(&Expr::add(Expr::val(1), Expr::val(2)))
        );
    }

    #[test]
    fn build_policies_trivial_permit() {
        let e = Expr::add(Expr::val(1), Expr::val(2));
        let id = PolicyID::from_string("foo");
        let result = build_policies(
            Effect::Permit,
            once((&id, (&e, &Annotations::default()))),
            &HashMap::default(),
        )
        .collect::<Vec<_>>();
        assert_eq!(result.len(), 1);
        let p = &result[0];
        assert_eq!(p.effect(), Effect::Permit);
        assert!(p.annotations().next().is_none());
        assert_eq!(p.action_constraint(), &ActionConstraint::Any);
        assert_eq!(p.principal_constraint(), PrincipalConstraint::any());
        assert_eq!(p.resource_constraint(), ResourceConstraint::any());
        assert_eq!(p.id(), &id);
        assert_eq!(p.non_head_constraints(), &e);
    }

    #[test]
    fn build_policies_trivial_forbid() {
        let e = Expr::add(Expr::val(1), Expr::val(2));
        let id = PolicyID::from_string("foo");
        let result = build_policies(
            Effect::Forbid,
            once((&id, (&e, &Annotations::default()))),
            &HashMap::default(),
        )
        .collect::<Vec<_>>();
        assert_eq!(result.len(), 1);
        let p = &result[0];
        assert_eq!(p.effect(), Effect::Forbid);
        assert!(p.annotations().next().is_none());
        assert_eq!(p.action_constraint(), &ActionConstraint::Any);
        assert_eq!(p.principal_constraint(), PrincipalConstraint::any());
        assert_eq!(p.resource_constraint(), ResourceConstraint::any());
        assert_eq!(p.id(), &id);
        assert_eq!(p.non_head_constraints(), &e);
    }

    #[test]
    fn did_error_error() {
        assert_eq!(
            did_error((
                &PolicyID::from_string("foo"),
                &(ErrorState::Error, Annotations::default())
            )),
            Some(&PolicyID::from_string("foo"))
        );
    }

    #[test]
    fn did_error_noerror() {
        assert_eq!(
            did_error((
                &PolicyID::from_string("foo"),
                &(ErrorState::NoError, Annotations::default())
            )),
            None,
        );
    }
}
