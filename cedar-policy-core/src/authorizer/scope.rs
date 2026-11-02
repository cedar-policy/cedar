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

//! Test of a policy's scope against a concrete request, done on the scope
//! constraints as data, without building or interpreting the policy's
//! condition expression.
//!
//! [`Template::condition`](crate::ast::Template::condition) builds a policy's
//! condition as `principal_scope && (action_scope && (resource_scope &&
//! non_scope_constraints))`, which the interpreter evaluates left to right
//! with short-circuiting. A policy is excluded here only when the first scope
//! constraint that is not `true` is `false`, and every constraint before it
//! evaluates to `true` without an error or a residual. For such a policy the
//! interpreter returns `false`. This module depends on that nesting: if the
//! order of the scope constraints in the condition changes, the order in
//! [`RequestScope::excludes`] has to change with it.

use crate::ast::{
    ActionConstraint, Entity, EntityUID, Policy, PrincipalOrResourceConstraint, Request, SlotEnv,
    SlotId,
};
use crate::entities::{Dereference, Entities};
use crate::evaluator::stack_has_margin;

/// Upper bound, in bytes, on the stack that the interpreter uses between the
/// caller of [`RequestScope::new`] and its deepest stack check while it
/// evaluates the scope constraints of one policy. An unoptimized build uses
/// about half of this, and an optimized build about a twentieth.
const SCOPE_EVALUATION_STACK: usize = 512 * 1024;

/// What evaluating one scope constraint yields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeMatch {
    /// The constraint evaluates to `true`
    Yes,
    /// The constraint evaluates to `false`
    No,
    /// The constraint evaluates to an error or a residual, so the interpreter
    /// has to produce the result
    Undecided,
}

impl From<bool> for ScopeMatch {
    fn from(b: bool) -> Self {
        if b {
            Self::Yes
        } else {
            Self::No
        }
    }
}

/// What the entity store holds for a request variable.
#[derive(Debug, Clone, Copy)]
enum Stored<'a> {
    /// The store has the entity
    Present(&'a Entity),
    /// A concrete store does not have the entity
    Absent,
    /// A partial store does not have the entity, so `in` on it is a residual
    Unknown,
}

/// The UID of the principal, action, or resource of a request, with what the
/// entity store holds for it.
#[derive(Debug, Clone, Copy)]
struct RequestVar<'a> {
    uid: &'a EntityUID,
    stored: Stored<'a>,
}

impl<'a> RequestVar<'a> {
    fn new(uid: &'a EntityUID, entities: &'a Entities) -> Self {
        let stored = match entities.entity(uid) {
            Dereference::Data(entity) => Stored::Present(entity),
            Dereference::NoSuchEntity => Stored::Absent,
            Dereference::Residual(_) => Stored::Unknown,
        };
        Self { uid, stored }
    }

    /// Evaluate `var in target`.
    ///
    /// The interpreter dereferences `var` before it compares the UIDs, so an
    /// entity missing from a partial store gives a residual even when `var`
    /// is `target`.
    fn is_in(&self, target: &EntityUID) -> ScopeMatch {
        match self.stored {
            Stored::Present(entity) => {
                (self.uid == target || entity.is_descendant_of(target)).into()
            }
            Stored::Absent => (self.uid == target).into(),
            Stored::Unknown => ScopeMatch::Undecided,
        }
    }

    /// Evaluate a principal or resource scope constraint on this variable.
    /// `slot` is the slot the constraint may refer to, bound in `env`. A slot
    /// that `env` does not bind is an evaluation error.
    fn matches(
        &self,
        constraint: &PrincipalOrResourceConstraint,
        slot: SlotId,
        env: &SlotEnv,
    ) -> ScopeMatch {
        match constraint {
            PrincipalOrResourceConstraint::Any => ScopeMatch::Yes,
            PrincipalOrResourceConstraint::Eq(reference) => reference
                .resolve(slot, env)
                .map_or(ScopeMatch::Undecided, |uid| (self.uid == uid).into()),
            PrincipalOrResourceConstraint::In(reference) => reference
                .resolve(slot, env)
                .map_or(ScopeMatch::Undecided, |uid| self.is_in(uid)),
            PrincipalOrResourceConstraint::Is(entity_type) => {
                (self.uid.entity_type() == entity_type.as_ref()).into()
            }
            // `var is T && var in e`: `in` is evaluated only if `is` holds
            PrincipalOrResourceConstraint::IsIn(entity_type, reference) => {
                if self.uid.entity_type() == entity_type.as_ref() {
                    reference
                        .resolve(slot, env)
                        .map_or(ScopeMatch::Undecided, |uid| self.is_in(uid))
                } else {
                    ScopeMatch::No
                }
            }
        }
    }

    /// Evaluate an action scope constraint on this variable.
    fn matches_action(&self, constraint: &ActionConstraint) -> ScopeMatch {
        match constraint {
            ActionConstraint::Any => ScopeMatch::Yes,
            ActionConstraint::Eq(uid) => (self.uid == uid.as_ref()).into(),
            // `var in [e, ..]`: the interpreter dereferences `var` first, so
            // even `var in []` is a residual for an unknown entity
            ActionConstraint::In(uids) => match self.stored {
                Stored::Unknown => ScopeMatch::Undecided,
                Stored::Present(_) | Stored::Absent => uids
                    .iter()
                    .any(|uid| self.is_in(uid) == ScopeMatch::Yes)
                    .into(),
            },
            #[cfg(feature = "tolerant-ast")]
            ActionConstraint::ErrorConstraint => ScopeMatch::Undecided,
        }
    }
}

/// The principal, action, and resource of a concrete request, prepared for
/// testing policy scopes against them.
#[derive(Debug)]
pub(super) struct RequestScope<'a> {
    principal: RequestVar<'a>,
    action: RequestVar<'a>,
    resource: RequestVar<'a>,
}

impl<'a> RequestScope<'a> {
    /// Prepare `q` for scope tests against `entities`, which must be the
    /// entity store the request is evaluated with.
    ///
    /// Returns `None` if the principal, action, or resource of `q` is
    /// unknown.
    ///
    /// Also returns `None` unless the stack has room for the interpreter to
    /// evaluate the scope constraints of a policy without reaching its
    /// recursion limit. Closer to the limit, the interpreter reports a
    /// recursion-limit error for a policy whose scope is `false`, which a
    /// scope test would exclude without an error.
    pub(super) fn new(q: &'a Request, entities: &'a Entities) -> Option<Self> {
        if !stack_has_margin(SCOPE_EVALUATION_STACK) {
            return None;
        }
        Some(Self {
            principal: RequestVar::new(q.principal().uid()?, entities),
            action: RequestVar::new(q.action().uid()?, entities),
            resource: RequestVar::new(q.resource().uid()?, entities),
        })
    }

    /// Is `p`'s scope certain to evaluate to `false`, so that `p` is not
    /// satisfied and does not error?
    ///
    /// A policy that failed to parse (`tolerant-ast`) has an unconstrained
    /// scope, so it is never excluded and the interpreter reports its error.
    pub(super) fn excludes(&self, p: &Policy) -> bool {
        let template = p.template();
        let principal = self.principal.matches(
            template.principal_constraint().as_inner(),
            SlotId::principal(),
            p.env(),
        );
        if principal != ScopeMatch::Yes {
            return principal == ScopeMatch::No;
        }
        let action = self.action.matches_action(template.action_constraint());
        if action != ScopeMatch::Yes {
            return action == ScopeMatch::No;
        }
        self.resource.matches(
            template.resource_constraint().as_inner(),
            SlotId::resource(),
            p.env(),
        ) == ScopeMatch::No
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ast::{
        EntityType, EntityUIDEntry, Expr, Literal, PartialValue, PrincipalConstraint,
        ResourceConstraint, ValueKind,
    };
    #[cfg(feature = "partial-eval")]
    use crate::authorizer::differential_tests::uid;
    use crate::authorizer::differential_tests::{entities, policy_set, requests};
    use crate::evaluator::Evaluator;
    use crate::extensions::Extensions;
    use cool_asserts::assert_matches;
    use itertools::Either;
    use std::sync::Arc;

    /// A policy that the scope test excludes evaluates to `false`. For a
    /// policy with no `when` or `unless` clause and a concrete store, the
    /// converse holds too: a policy that evaluates to `false` is excluded.
    #[test]
    fn excludes_exactly_the_policies_with_false_scope() {
        let pset = policy_set();
        let entities = entities();
        let (mut excluded, mut kept) = (0, 0);
        for q in requests() {
            let eval = Evaluator::new(q.clone(), &entities, Extensions::all_available());
            let scope = RequestScope::new(&q, &entities).expect("request is concrete");
            for p in pset.policies() {
                let result = eval.partial_evaluate(p);
                if scope.excludes(p) {
                    assert_matches!(
                        result,
                        Ok(Either::Left(false)),
                        "policy {} is excluded for {q}",
                        p.id()
                    );
                    excluded += 1;
                } else {
                    if p.non_scope_constraints().is_none() {
                        assert_matches!(
                            result,
                            Ok(Either::Left(true)),
                            "policy {} is not excluded for {q}",
                            p.id()
                        );
                    }
                    kept += 1;
                }
            }
        }
        assert!(excluded > kept, "most scopes do not match most requests");
    }

    /// `in` on an entity that a partial store does not have is a residual,
    /// so the scope test leaves the policy to the interpreter, even when the
    /// entity is the one the constraint names.
    #[cfg(feature = "partial-eval")]
    #[test]
    fn leaves_unknown_entities_to_the_interpreter() {
        let pset = policy_set();
        let entities = entities().partial();
        let mut residuals = 0;
        for q in requests() {
            let eval = Evaluator::new(q.clone(), &entities, Extensions::all_available());
            let scope = RequestScope::new(&q, &entities).expect("request is concrete");
            for p in pset.policies() {
                let result = eval.partial_evaluate(p);
                if scope.excludes(p) {
                    assert_matches!(
                        result,
                        Ok(Either::Left(false)),
                        "policy {} is excluded for {q}",
                        p.id()
                    );
                }
                residuals += usize::from(matches!(result, Ok(Either::Right(_))));
            }
        }
        assert!(residuals > 0);

        let ghost = uid("User", "ghost");
        let var = RequestVar::new(&ghost, &entities);
        assert_eq!(var.is_in(&ghost), ScopeMatch::Undecided);
        assert_eq!(var.is_in(&uid("Group", "admins")), ScopeMatch::Undecided);
    }

    /// A slot that the slot environment does not bind is an evaluation
    /// error, so a constraint that reaches one is left to the interpreter.
    /// `is T in ?slot` reaches the slot only if the type test holds.
    #[test]
    fn leaves_unbound_slots_to_the_interpreter() {
        let entities = entities();
        // `User::"alice"`, `Action::"view"`, `Doc::"d1"`
        let q = requests().swap_remove(0);
        let eval = Evaluator::new(q.clone(), &entities, Extensions::all_available());
        let scope = RequestScope::new(&q, &entities).expect("request is concrete");
        let env = SlotEnv::new();
        let interpreted = |constraint: &Expr| match eval.partial_interpret(constraint, &env) {
            Ok(PartialValue::Value(v)) => match v.value_kind() {
                ValueKind::Lit(Literal::Bool(b)) => ScopeMatch::from(*b),
                _ => ScopeMatch::Undecided,
            },
            Ok(PartialValue::Residual(_)) | Err(_) => ScopeMatch::Undecided,
        };
        let entity_type =
            |ty: &str| -> Arc<EntityType> { Arc::new(ty.parse().expect("valid entity type")) };
        // the last two name the type of the request's principal and of its
        // resource, so each misses the type of one variable and reaches the
        // slot for the other
        let constraints = [
            (
                PrincipalOrResourceConstraint::is_eq_slot(),
                [ScopeMatch::Undecided; 2],
            ),
            (
                PrincipalOrResourceConstraint::is_in_slot(),
                [ScopeMatch::Undecided; 2],
            ),
            (
                PrincipalOrResourceConstraint::is_entity_type_in_slot(entity_type("User")),
                [ScopeMatch::Undecided, ScopeMatch::No],
            ),
            (
                PrincipalOrResourceConstraint::is_entity_type_in_slot(entity_type("Doc")),
                [ScopeMatch::No, ScopeMatch::Undecided],
            ),
        ];
        for (constraint, [on_principal, on_resource]) in constraints {
            let matched = scope
                .principal
                .matches(&constraint, SlotId::principal(), &env);
            assert_eq!(matched, on_principal, "principal {constraint:?}");
            let expr = PrincipalConstraint::new(constraint.clone()).as_expr();
            assert_eq!(matched, interpreted(&expr), "principal {constraint:?}");

            let matched = scope
                .resource
                .matches(&constraint, SlotId::resource(), &env);
            assert_eq!(matched, on_resource, "resource {constraint:?}");
            let expr = ResourceConstraint::new(constraint.clone()).as_expr();
            assert_eq!(matched, interpreted(&expr), "resource {constraint:?}");
        }
    }

    /// Scope tests are off on a stack too small for the interpreter to
    /// evaluate a scope without reaching its recursion limit.
    #[test]
    fn needs_stack_for_the_interpreter() {
        if stacker::remaining_stack().is_none() {
            // the stack cannot be measured here, so there is no limit to test
            return;
        }
        let entities = entities();
        let q = requests().swap_remove(0);
        assert!(RequestScope::new(&q, &entities).is_some());
        let on_small_stack = std::thread::scope(|s| {
            std::thread::Builder::new()
                .stack_size(SCOPE_EVALUATION_STACK / 2)
                .spawn_scoped(s, || RequestScope::new(&q, &entities).is_some())
                .expect("thread starts")
                .join()
                .expect("thread does not panic")
        });
        assert!(!on_small_stack);
    }

    /// On the smallest stack where scope tests are on, the interpreter still
    /// evaluates every excluded policy to `false`: it does not reach its
    /// recursion limit inside a scope constraint. This is what
    /// `SCOPE_EVALUATION_STACK` has to guarantee, for the build profile the
    /// test runs in.
    #[test]
    fn stack_bound_covers_the_interpreter() {
        if stacker::remaining_stack().is_none() {
            // the stack cannot be measured here, so there is no limit to test
            return;
        }
        let pset = policy_set();
        let entities = entities();
        let requests = requests();
        // `None` if scope tests are off on a stack of this size, otherwise
        // the number of excluded policies that were evaluated
        let excluded_on_stack_of = |size: usize| -> Option<usize> {
            std::thread::scope(|s| {
                std::thread::Builder::new()
                    .stack_size(size)
                    .spawn_scoped(s, || {
                        let mut excluded = 0;
                        for q in &requests {
                            let scope = RequestScope::new(q, &entities)?;
                            let eval =
                                Evaluator::new(q.clone(), &entities, Extensions::all_available());
                            for p in pset.policies().filter(|p| scope.excludes(p)) {
                                assert_matches!(
                                    eval.partial_evaluate(p),
                                    Ok(Either::Left(false)),
                                    "policy {} is excluded for {q}",
                                    p.id()
                                );
                                excluded += 1;
                            }
                        }
                        Some(excluded)
                    })
                    .expect("thread starts")
                    .join()
                    .expect("no excluded policy errors")
            })
        };
        let step = 16 * 1024;
        let excluded = (1..)
            .map(|steps| steps * step)
            .take_while(|size| *size <= 4 * SCOPE_EVALUATION_STACK)
            .find_map(excluded_on_stack_of)
            .expect("scope tests are on for a large enough stack");
        assert!(excluded > 0);
    }

    #[test]
    fn needs_a_concrete_request() {
        let entities = entities();
        let q = requests().swap_remove(0);
        let unknown = [
            Request::new_unchecked(
                EntityUIDEntry::unknown(),
                q.action().clone(),
                q.resource().clone(),
                q.context().cloned(),
            ),
            Request::new_unchecked(
                q.principal().clone(),
                EntityUIDEntry::unknown(),
                q.resource().clone(),
                q.context().cloned(),
            ),
            Request::new_unchecked(
                q.principal().clone(),
                q.action().clone(),
                EntityUIDEntry::unknown(),
                q.context().cloned(),
            ),
        ];
        for q in &unknown {
            assert!(RequestScope::new(q, &entities).is_none());
        }
        // an unknown context does not prevent scope tests
        let q = Request::new_unchecked(
            q.principal().clone(),
            q.action().clone(),
            q.resource().clone(),
            None,
        );
        assert!(RequestScope::new(&q, &entities).is_some());
    }
}
