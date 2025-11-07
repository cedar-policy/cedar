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

//! Implements typechecking for Cedar policies. Typechecking is done using
//! the `Typechecker` struct by calling the `typecheck_policy` method given a
//! policy.

pub(crate) mod test;

mod typecheck_answer;
use itertools::EitherOrBoth::{Both, Left, Right};
use itertools::Itertools;
pub(crate) use typecheck_answer::TypecheckAnswer;

use std::sync::Arc;
use std::{borrow::Cow, collections::HashSet};

use crate::validator::types::EntityLUB;
use crate::validator::{
    extension_schema::ExtensionFunctionType,
    extensions::ExtensionSchemas,
    schema::ValidatorSchema,
    types::{
        AttributeType, Capability, CapabilitySet, EntityRecordKind, OpenTag, Primitive, RequestEnv,
        Type,
    },
    validation_errors::{AttributeAccess, LubContext, UnexpectedTypeHelp},
    ValidationError, ValidationMode, ValidationWarning,
};

use crate::fuzzy_match::fuzzy_search;
use crate::{
    ast::{
        BinaryOp, EntityType, EntityUID, Expr, ExprBuilder, ExprKind, Literal, Name, PolicyID,
        PrincipalOrResourceConstraint, SlotId, Template, UnaryOp, Var,
    },
    expr_builder::ExprBuilder as _,
};

const REQUIRED_STACK_SPACE: usize = 1024 * 100;

/// Basic result for typechecking
#[derive(Debug)]
pub enum PolicyCheck {
    /// Policy will evaluate to a bool
    Success(Expr<Option<Type>>),
    /// Policy will always evaluate to false, and may have errors
    Irrelevant(Vec<ValidationError>, Expr<Option<Type>>),
    /// Policy will have errors
    Fail(Vec<ValidationError>),
}

/// This structure implements typechecking for Cedar policies through the
/// entry point `typecheck_policy`.
#[derive(Debug)]
pub struct Typechecker<'a> {
    schema: &'a ValidatorSchema,
    extensions: &'static ExtensionSchemas<'static>,
    mode: ValidationMode,
    /// List of valid (unlinked) `RequestEnv`s for this schema.
    /// Cached here so it can be computed once (during `Typechecker`
    /// construction) and potentially used for many typechecking operations.
    unlinked_envs: Vec<RequestEnv<'a>>,
}

impl<'a> Typechecker<'a> {
    /// Construct a new typechecker. All extensions are enabled by default.
    pub fn new(schema: &'a ValidatorSchema, mode: ValidationMode) -> Typechecker<'a> {
        Self {
            schema,
            extensions: ExtensionSchemas::all_available(),
            mode,
            unlinked_envs: schema.unlinked_request_envs(mode).collect(),
        }
    }

    /// The main entry point for typechecking policies. Checks that the policy
    /// expression has type boolean. If typechecking succeeds, then the method
    /// will return true, and no items will be added to the output list.
    /// Otherwise, the function returns false and the `type_errors` list is
    /// populated with any errors encountered while typechecking. Note that it
    /// is possible for _no_ errors to be added in this case because the
    /// relevant error is expected to be added by a different pass. Finally,
    /// warnings may be added to the `warnings` list, although these will not
    /// impact the boolean return value.
    pub fn typecheck_policy(
        &self,
        t: &Template,
        type_errors: &mut HashSet<ValidationError>,
        warnings: &mut HashSet<ValidationWarning>,
    ) -> bool {
        let typecheck_answers = self.typecheck_by_request_env(t);

        // consolidate the results from each query environment
        let (all_false, all_succ) = typecheck_answers.into_iter().fold(
            (true, true),
            |(all_false, all_succ), (_, check)| match check {
                PolicyCheck::Success(_) => (false, all_succ),
                PolicyCheck::Irrelevant(err, _) => {
                    let no_err = err.is_empty();
                    type_errors.extend(err);
                    (all_false, all_succ && no_err)
                }
                PolicyCheck::Fail(err) => {
                    type_errors.extend(err);
                    (false, false)
                }
            },
        );

        // If every policy typechecked with type false, then the policy cannot
        // possibly apply to any request.
        if all_false {
            warnings.insert(ValidationWarning::impossible_policy(
                t.loc().cloned(),
                t.id().clone(),
            ));
        }

        all_succ
    }

    /// Secondary entry point for typechecking requests. This method takes a policy and
    /// typechecks it under every schema-defined request environment. The result contains
    /// these environments and the individual typechecking response for each, in no
    /// particular order.
    ///
    /// Callers using this as the toplevel entry point, rather than
    /// `typecheck_policy()`, will not get `impossible_policy` validation
    /// warnings.
    pub fn typecheck_by_request_env<'b>(
        &'b self,
        t: &'b Template,
    ) -> Vec<(RequestEnv<'b>, PolicyCheck)> {
        self.apply_typecheck_fn_by_request_env(t, |request_env, policy_id, expr| {
            self.single_env_typechecking(request_env, policy_id, expr)
        })
    }

    fn single_env_typechecking(
        &self,
        request_env: &RequestEnv<'_>,
        policy_id: &PolicyID,
        expr: &Expr,
    ) -> PolicyCheck {
        let mut type_errors = Vec::new();
        let single_env_typechecker = SingleEnvTypechecker {
            schema: self.schema,
            extensions: self.extensions,
            mode: self.mode,
            policy_id,
            request_env,
        };
        let empty_prior_capability = CapabilitySet::new();
        let ans = single_env_typechecker.expect_type(
            &empty_prior_capability,
            expr,
            Type::primitive_boolean(),
            &mut type_errors,
            |_| None,
        );

        let is_false = ans.contains_type(&Type::singleton_boolean(false));
        match (is_false, ans.typechecked(), ans.into_typed_expr()) {
            (false, true, None) => PolicyCheck::Fail(type_errors),
            (false, true, Some(e)) => PolicyCheck::Success(e),
            (false, false, _) => PolicyCheck::Fail(type_errors),
            (true, _, Some(e)) => PolicyCheck::Irrelevant(type_errors, e),
            // PANIC SAFETY: `is_false` implies `e` has a type implies `Some(e)`.
            #[allow(clippy::unreachable)]
            (true, _, None) => unreachable!(),
        }
    }

    /// Type check a `Template` by a single request environment
    pub fn typecheck_by_single_request_env<'b>(
        &'b self,
        t: &'b Template,
        request_env: &RequestEnv<'b>,
    ) -> PolicyCheck {
        self.single_env_typechecking(request_env, t.id(), &t.condition())
    }

    /// Apply `typecheck_fn` to the given policy in every schema-defined request
    /// environment, and collect all the results.
    ///
    /// Results are returned in no particular order.
    fn apply_typecheck_fn_by_request_env<'b, F, C>(
        &'b self,
        t: &'b Template,
        typecheck_fn: F,
    ) -> Vec<(RequestEnv<'b>, C)>
    where
        F: Fn(&RequestEnv<'b>, &PolicyID, &Expr) -> C,
    {
        // compute `.condition()` just once, and cache it here
        let cond = t.condition();

        // Validate each (principal, resource) pair with the substituted policy
        // for the corresponding action.
        self.unlinked_envs
            .iter()
            .flat_map(|unlinked_e| {
                self.link_request_env(unlinked_e, t).map(|linked_e| {
                    let check = typecheck_fn(&linked_e, t.id(), &cond);
                    (linked_e, check)
                })
            })
            .collect()
    }

    /// Given a request environment and a template, return new environments
    /// formed by linking template slots with possible entity types.
    fn link_request_env<'b, 'c>(
        &'b self,
        env: &'c RequestEnv<'b>,
        t: &'b Template,
    ) -> Box<dyn Iterator<Item = RequestEnv<'b>> + 'c> {
        match env {
            RequestEnv::UndeclaredAction => Box::new(std::iter::once(RequestEnv::UndeclaredAction)),
            RequestEnv::DeclaredAction {
                principal,
                action,
                resource,
                context,
                ..
            } => Box::new(
                self.possible_slot_links(
                    t,
                    SlotId::principal(),
                    principal,
                    t.principal_constraint().as_inner(),
                )
                .flat_map(move |p_slot| {
                    self.possible_slot_links(
                        t,
                        SlotId::resource(),
                        resource,
                        t.resource_constraint().as_inner(),
                    )
                    .map(move |r_slot| RequestEnv::DeclaredAction {
                        principal,
                        action,
                        resource,
                        context,
                        principal_slot: p_slot.clone(),
                        resource_slot: r_slot,
                    })
                }),
            ),
        }
    }

    /// Get the entity types which could link the slot given in this
    /// template based on the policy scope constraints. We use this function to
    /// avoid typechecking with slot bindings that will always be false based
    /// only on the scope constraints.
    fn possible_slot_links(
        &self,
        t: &Template,
        slot_id: SlotId,
        var: &'a EntityType,
        constraint: &PrincipalOrResourceConstraint,
    ) -> Box<dyn Iterator<Item = Option<EntityType>> + 'a> {
        if t.slots().any(|t_slot| t_slot.id == slot_id) {
            let all_entity_types = self.schema.entity_types();
            match constraint {
                // The condition is `var = ?slot`, so the policy can only apply
                // if the slot has the same entity type as `var`.
                PrincipalOrResourceConstraint::Eq(_) => {
                    Box::new(std::iter::once(Some(var.clone())))
                }
                // The condition is `var in ?slot` or `var is type in ?slot`, so
                // the policy can only apply if the var is some descendant of
                // the slot. We ignore the `is type` portion because this
                // constrains the `var` and not the slot.
                PrincipalOrResourceConstraint::IsIn(_, _)
                | PrincipalOrResourceConstraint::In(_) => Box::new(
                    all_entity_types
                        .filter(|ety| ety.has_descendant_entity_type(var))
                        .map(|ety| Some(ety.name().clone()))
                        .chain(std::iter::once(Some(var.clone()))),
                ),
                // The template uses the slot, but without a scope constraint.
                // This can't happen for the moment because slots may only
                // appear in scope constraints, but if we ever see this, then the
                // only correct way to proceed is by returning all entity types
                // as possible links.
                PrincipalOrResourceConstraint::Is(_) | PrincipalOrResourceConstraint::Any => {
                    Box::new(all_entity_types.map(|ety| Some(ety.name().clone())))
                }
            }
        } else {
            // If the template does not contain this slot, then we don't need to
            // consider its links.
            Box::new(std::iter::once(None))
        }
    }
}

/// Struct which implements typechecking for policies within a single request
/// env.
struct SingleEnvTypechecker<'a> {
    schema: &'a ValidatorSchema,
    extensions: &'a ExtensionSchemas<'a>,
    mode: ValidationMode,
    /// ID of the policy we're typechecking; used for associating any validation
    /// errors with the correct policy ID
    policy_id: &'a PolicyID,
    /// The single env which we're performing typechecking for
    request_env: &'a RequestEnv<'a>,
}

impl<'a> SingleEnvTypechecker<'a> {
    /// This method handles the majority of the work. Given an expression, and
    /// the prior capability, return the result of typechecking the expression
    /// in the single env this typechecker was constructed for, and add any
    /// errors encountered into the `type_errors` list.
    fn typecheck<'b>(
        &self,
        prior_capability: &CapabilitySet<'b>,
        e: &'b Expr,
        type_errors: &mut Vec<ValidationError>,
    ) -> TypecheckAnswer<'b> {
        // We assume there's enough space if we cannot determine it with `remaining_stack`
        if stacker::remaining_stack().unwrap_or(REQUIRED_STACK_SPACE) < REQUIRED_STACK_SPACE {
            return TypecheckAnswer::RecursionLimit;
        }

        match e.expr_kind() {
            // Principal, resource, and context have types defined by
            // the request type.
            ExprKind::Var(Var::Principal) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(self.request_env.principal_type()))
                    .with_same_source_loc(e)
                    .var(Var::Principal),
            ),
            // While the EntityUID for Action is held in the request context,
            // entity types do not consider the id of the entity (only the
            // entity type), so the type of Action is only the entity type name
            // taken from the euid.
            ExprKind::Var(Var::Action) => {
                match self.request_env.action_type(self.schema) {
                    Some(ty) => TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(ty))
                            .with_same_source_loc(e)
                            .var(Var::Action),
                    ),
                    // `None` if the action entity is not defined in the schema.
                    // This will only show up if we're typechecking with a
                    // request environment that was not constructed from the
                    // schema cross product, which will not happen through our
                    // public entry points, but it can occur if calling
                    // `typecheck` directly which happens in our tests.
                    None => TypecheckAnswer::fail(
                        ExprBuilder::new().with_same_source_loc(e).var(Var::Action),
                    ),
                }
            }
            ExprKind::Var(Var::Resource) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(self.request_env.resource_type()))
                    .with_same_source_loc(e)
                    .var(Var::Resource),
            ),
            ExprKind::Var(Var::Context) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(self.request_env.context_type()))
                    .with_same_source_loc(e)
                    .var(Var::Context),
            ),
            ExprKind::Unknown(u) => {
                TypecheckAnswer::fail(ExprBuilder::with_data(None).unknown(u.clone()))
            }
            // Template Slots, always has to be an entity.
            ExprKind::Slot(slotid) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(if slotid.is_principal() {
                    self.request_env
                        .principal_slot()
                        .clone()
                        .map(Type::named_entity_reference)
                        .unwrap_or_else(Type::any_entity_reference)
                } else if slotid.is_resource() {
                    self.request_env
                        .resource_slot()
                        .clone()
                        .map(Type::named_entity_reference)
                        .unwrap_or_else(Type::any_entity_reference)
                } else {
                    Type::any_entity_reference()
                }))
                .with_same_source_loc(e)
                .slot(*slotid),
            ),

            // Literal booleans get singleton type according to their value.
            ExprKind::Lit(Literal::Bool(val)) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::singleton_boolean(*val)))
                    .with_same_source_loc(e)
                    .val(*val),
            ),
            // Other literal primitive values have the type of that primitive value.
            ExprKind::Lit(Literal::Long(val)) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::primitive_long()))
                    .with_same_source_loc(e)
                    .val(*val),
            ),
            ExprKind::Lit(Literal::String(val)) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::primitive_string()))
                    .with_same_source_loc(e)
                    .val(val.clone()),
            ),

            // Literal entity reference have a type based on the entity type
            // that can be looked up in the schema.
            ExprKind::Lit(Literal::EntityUID(euid)) => {
                // Unknown entity types/actions ids and unspecified entities will be
                // detected by a different part of the validator, so a ValidationError is
                // not generated here. We still return `TypecheckFail` so that
                // typechecking is not considered successful.
                match Type::euid_literal(euid.as_ref(), self.schema) {
                    // The entity type is undeclared, but that's OK for a
                    // partial schema. The attributes record will be empty if we
                    // try to access it later, so all attributes will have the
                    // bottom type.
                    None if self.mode.is_partial() => TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(Type::named_entity_reference(
                            euid.entity_type().clone(),
                        )))
                        .with_same_source_loc(e)
                        .val(euid.clone()),
                    ),
                    Some(ty) => TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(ty))
                            .with_same_source_loc(e)
                            .val(euid.clone()),
                    ),
                    None => TypecheckAnswer::fail(
                        ExprBuilder::new().with_same_source_loc(e).val(euid.clone()),
                    ),
                }
            }

            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                // The guard expression must be boolean.
                let ans_test = self.expect_type(
                    prior_capability,
                    test_expr,
                    Type::primitive_boolean(),
                    type_errors,
                    |_| None,
                );
                ans_test.then_typecheck(|typ_test, test_capability| {
                    // If the guard has type `true` or `false`, we short circuit,
                    // looking at only the relevant branch.
                    if typ_test.data() == &Some(Type::singleton_boolean(true)) {
                        // The `then` branch needs to be typechecked using the
                        // prior capability of the `if` and any new capability generated
                        // by `test`. This enables an attribute access
                        // `principal.foo` after a condition `principal has foo`.
                        let ans_then = self.typecheck(
                            &prior_capability.union(&test_capability),
                            then_expr,
                            type_errors,
                        );

                        ans_then.then_typecheck(|typ_then, then_capability| {
                            TypecheckAnswer::success_with_capability(
                                ExprBuilder::with_data(typ_then.data().clone())
                                    .with_same_source_loc(e)
                                    .ite(
                                        typ_test,
                                        typ_then.clone(),
                                        // The type of the test expression is `True`, so we know the `else` branch
                                        // will never be evaluated. We still need to put something here, so we use
                                        // a copy of the `then` branch.
                                        typ_then,
                                    ),
                                // The output capability of the whole `if` expression also
                                // needs to contain the capability of the condition.
                                then_capability.union(&test_capability),
                            )
                        })
                    } else if typ_test.data() == &Some(Type::singleton_boolean(false)) {
                        // The `else` branch cannot use the `test` capability since
                        // we know in the `else` branch that the condition
                        // evaluated to `false`. It still can use the original
                        // prior capability.
                        let ans_else = self.typecheck(prior_capability, else_expr, type_errors);

                        ans_else.then_typecheck(|typ_else, else_capability| {
                            TypecheckAnswer::success_with_capability(
                                ExprBuilder::with_data(typ_else.data().clone())
                                    .with_same_source_loc(e)
                                    .ite(
                                        typ_test,
                                        // The type of the test expression is `False`, so we know the `then` branch
                                        // will never be evaluated. We still need to put something here, so we use
                                        // a copy of the `else` branch.
                                        typ_else.clone(),
                                        typ_else,
                                    ),
                                else_capability,
                            )
                        })
                    } else {
                        // When we don't short circuit, the `then` and `else`
                        // branches are individually typechecked with the same
                        // prior capability are in their individual cases.
                        let ans_then = self
                            .typecheck(
                                &prior_capability.union(&test_capability),
                                then_expr,
                                type_errors,
                            )
                            .map_capability(|capability| capability.union(&test_capability));
                        let ans_else = self.typecheck(prior_capability, else_expr, type_errors);
                        // The type of the if expression is then the least
                        // upper bound of the types of the then and else
                        // branches.  If either of these fails to typecheck, the
                        // other is still be typechecked to detect errors that
                        // may exist in that branch. This failure, in addition
                        // to any failure that may have occurred in the test
                        // expression, will propagate to final TypecheckAnswer.
                        ans_then.then_typecheck(|typ_then, then_capability| {
                            ans_else.then_typecheck(|typ_else, else_capability| {
                                let lub_ty = self.least_upper_bound_or_error(
                                    e,
                                    vec![typ_then.data().clone(), typ_else.data().clone()],
                                    type_errors,
                                    LubContext::Conditional,
                                );
                                let has_lub = lub_ty.is_some();
                                let annot_expr = ExprBuilder::with_data(lub_ty)
                                    .with_same_source_loc(e)
                                    .ite(typ_test, typ_then, typ_else);
                                if has_lub {
                                    // Capabilities are not handled in the LUB computation,
                                    // so we need to compute the resulting capability here. When
                                    // the `||` evaluates to `true`, we know that
                                    // one operand evaluated to true, but we don't
                                    // know which. This is handled by returning a
                                    // capability set that is the intersection of the
                                    // operand capability sets.
                                    TypecheckAnswer::success_with_capability(
                                        annot_expr,
                                        else_capability.intersect(&then_capability),
                                    )
                                } else {
                                    TypecheckAnswer::fail(annot_expr)
                                }
                            })
                        })
                    }
                })
            }

            ExprKind::And { left, right } => {
                let ans_left = self.expect_type(
                    prior_capability,
                    left,
                    Type::primitive_boolean(),
                    type_errors,
                    |_| None,
                );
                ans_left.then_typecheck(|typ_left, capability_left| {
                    match typ_left.data() {
                        // LHS argument is false, so short circuit the `&&` to
                        // `False` _without_ typechecking the RHS.
                        Some(Type::False) => TypecheckAnswer::success(
                            typ_left.with_maybe_source_loc(e.source_loc().cloned()),
                        ),
                        _ => {
                            // Similar to the `then` branch of an `if`
                            // expression, the rhs of an `&&` is typechecked
                            // using an updated prior capability that includes
                            // the capability from the lhs to enable
                            // typechecking expressions like
                            // `principal has foo && principal.foo`. This is
                            // valid because `&&` short circuits at run time, so
                            // the right will only be evaluated after the left
                            // evaluated to `true`.
                            let ans_right = self.expect_type(
                                &prior_capability.union(&capability_left),
                                right,
                                Type::primitive_boolean(),
                                type_errors,
                                |_| None,
                            );
                            ans_right.then_typecheck(|typ_right, capability_right| {
                                match (typ_left.data(), typ_right.data()) {
                                    // The second argument is false, so the `&&`
                                    // is false. The capability is empty for the
                                    // same reason as when the first argument
                                    // was false.
                                    (Some(_), Some(Type::False)) => TypecheckAnswer::success(
                                        ExprBuilder::with_data(Some(Type::False))
                                            .with_same_source_loc(e)
                                            .and(typ_left, typ_right),
                                    ),

                                    // When either argument is true, the result type is
                                    // the type of the other argument. Here, and
                                    // in the remaining successful cases, the
                                    // capability of the `&&` is the union of the
                                    // lhs and rhs because both operands must be
                                    // true for the whole `&&` to be true.
                                    (Some(_), Some(Type::True)) => {
                                        TypecheckAnswer::success_with_capability(
                                            ExprBuilder::with_data(typ_left.data().clone())
                                                .with_same_source_loc(e)
                                                .and(typ_left, typ_right),
                                            capability_left.union(&capability_right),
                                        )
                                    }
                                    (Some(Type::True), Some(_)) => {
                                        TypecheckAnswer::success_with_capability(
                                            ExprBuilder::with_data(typ_right.data().clone())
                                                .with_same_source_loc(e)
                                                .and(typ_left, typ_right),
                                            capability_right.union(&capability_right),
                                        )
                                    }

                                    // Neither argument was true or false, so we only
                                    // know the result type is boolean.
                                    (Some(_), Some(_)) => TypecheckAnswer::success_with_capability(
                                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                            .with_same_source_loc(e)
                                            .and(typ_left, typ_right),
                                        capability_left.union(&capability_right),
                                    ),

                                    // One or both of the left and the right failed to
                                    // typecheck, so the `&&` expression also fails.
                                    _ => TypecheckAnswer::fail(
                                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                            .with_same_source_loc(e)
                                            .and(typ_left, typ_right),
                                    ),
                                }
                            })
                        }
                    }
                })
            }

            // `||` follows the same pattern as `&&`, but with short circuiting
            // capability propagation adjusted as necessary.
            ExprKind::Or { left, right } => {
                let ans_left = self.expect_type(
                    prior_capability,
                    left,
                    Type::primitive_boolean(),
                    type_errors,
                    |_| None,
                );
                ans_left.then_typecheck(|ty_expr_left, capability_left| match ty_expr_left.data() {
                    // LHS argument is true, so short circuit the `|| to `True`
                    // _without_ typechecking the RHS. Contrary to `&&`, we
                    // keep a capability  when short circuiting `||`.
                    Some(Type::True) => TypecheckAnswer::success_with_capability(
                        ty_expr_left.with_maybe_source_loc(e.source_loc().cloned()),
                        capability_left,
                    ),
                    _ => {
                        // The right operand of an `||` cannot be typechecked
                        // using the capability learned from the left because the
                        // left could have evaluated to either `true` or `false`
                        // when the left is evaluated.
                        let ans_right = self.expect_type(
                            prior_capability,
                            right,
                            Type::primitive_boolean(),
                            type_errors,
                            |_| None,
                        );
                        ans_right.then_typecheck(|ty_expr_right, capability_right| {
                            match (ty_expr_left.data(), ty_expr_right.data()) {
                                // Now the right operand is always `true`, so we can
                                // use its capability as the result capability. The left
                                // operand might have been `true` or `false`, but it
                                // does not affect the value of the `||` if the
                                // right is always `true`.
                                (Some(_), Some(Type::True)) => {
                                    TypecheckAnswer::success_with_capability(
                                        ExprBuilder::with_data(Some(Type::True))
                                            .with_same_source_loc(e)
                                            .or(ty_expr_left, ty_expr_right),
                                        capability_right,
                                    )
                                }
                                // If the right or left operand is always `false`,
                                // then the only way the `||` expression can be
                                // `true` is if the other operand is `true`. This
                                // lets us pass the capability of the other operand
                                // through to the capability of the `||`.
                                (Some(typ_left), Some(Type::False)) => {
                                    TypecheckAnswer::success_with_capability(
                                        ExprBuilder::with_data(Some(typ_left.clone()))
                                            .with_same_source_loc(e)
                                            .or(ty_expr_left, ty_expr_right),
                                        capability_left,
                                    )
                                }
                                (Some(Type::False), Some(typ_right)) => {
                                    TypecheckAnswer::success_with_capability(
                                        ExprBuilder::with_data(Some(typ_right.clone()))
                                            .with_same_source_loc(e)
                                            .or(ty_expr_left, ty_expr_right),
                                        capability_right,
                                    )
                                }
                                // When neither has a constant value, the `||`
                                // evaluates to true if one or both is `true`. This
                                // means we can only keep capabilities in the
                                // intersection of their capability sets.
                                (Some(_), Some(_)) => TypecheckAnswer::success_with_capability(
                                    ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                        .with_same_source_loc(e)
                                        .or(ty_expr_left, ty_expr_right),
                                    capability_right.intersect(&capability_left),
                                ),
                                _ => TypecheckAnswer::fail(
                                    ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                        .with_same_source_loc(e)
                                        .or(ty_expr_left, ty_expr_right),
                                ),
                            }
                        })
                    }
                })
            }

            ExprKind::UnaryApp { .. } => {
                // INVARIANT: typecheck_unary requires a `UnaryApp`, we've just ensured this
                self.typecheck_unary(prior_capability, e, type_errors)
            }
            ExprKind::BinaryApp { .. } => {
                // INVARIANT: typecheck_binary requires a `BinaryApp`, we've just ensured this
                self.typecheck_binary(prior_capability, e, type_errors)
            }
            ExprKind::ExtensionFunctionApp { .. } => {
                // INVARIANT: typecheck_extension requires a `ExtensionFunctionApp`, we've just ensured this
                self.typecheck_extension(prior_capability, e, type_errors)
            }

            ExprKind::GetAttr { expr, attr } => {
                // Accessing an attribute requires either an entity or a record
                // that has the attribute.
                let actual = self.expect_one_of_types(
                    prior_capability,
                    expr,
                    &[Type::any_entity_reference(), Type::any_record()],
                    type_errors,
                    |_| None,
                );

                actual.then_typecheck(|typ_expr_actual, _| match typ_expr_actual.data() {
                    Some(typ_actual) => {
                        let all_attrs = typ_actual.all_attributes(self.schema);
                        let attr_ty = Type::lookup_attribute_type(self.schema, typ_actual, attr);
                        let annot_expr = ExprBuilder::with_data(
                            attr_ty.clone().map(|attr_ty| attr_ty.attr_type),
                        )
                        .with_same_source_loc(e)
                        .get_attr(typ_expr_actual.clone(), attr.clone());
                        match attr_ty {
                            Some(ty) => {
                                // A safe access to an attribute requires either
                                // that the attribute is required (always
                                // present), or that the attribute is in the
                                // prior capability set (the current expression is
                                // guarded by a condition that will only
                                // evaluate to `true` when the attribute is
                                // present).
                                if ty.is_required
                                    || prior_capability
                                        .contains(&Capability::new_attribute(expr, attr.clone()))
                                {
                                    TypecheckAnswer::success(annot_expr)
                                } else {
                                    type_errors.push(
                                        ValidationError::unsafe_optional_attribute_access(
                                            e.source_loc().cloned(),
                                            self.policy_id.clone(),
                                            AttributeAccess::from_expr(
                                                self.request_env,
                                                &typ_expr_actual,
                                                attr.clone(),
                                            ),
                                        ),
                                    );
                                    TypecheckAnswer::fail(annot_expr)
                                }
                            }
                            // In partial schema validation, if we can't find
                            // the attribute but there may be additional
                            // attributes, we do not fail and instead return the
                            // bottom type (`Never`).
                            None if self.mode.is_partial()
                                && Type::may_have_attr(self.schema, typ_actual, attr) =>
                            {
                                TypecheckAnswer::success(
                                    ExprBuilder::with_data(Some(Type::Never))
                                        .with_same_source_loc(e)
                                        .get_attr(typ_expr_actual, attr.clone()),
                                )
                            }
                            None => {
                                let borrowed =
                                    all_attrs.iter().map(|s| s.as_str()).collect::<Vec<_>>();
                                let suggestion = fuzzy_search(attr, &borrowed);
                                type_errors.push(ValidationError::unsafe_attribute_access(
                                    e.source_loc().cloned(),
                                    self.policy_id.clone(),
                                    AttributeAccess::from_expr(
                                        self.request_env,
                                        &typ_expr_actual,
                                        attr.clone(),
                                    ),
                                    suggestion,
                                    Type::may_have_attr(self.schema, typ_actual, attr),
                                ));
                                TypecheckAnswer::fail(annot_expr)
                            }
                        }
                    }
                    None => TypecheckAnswer::fail(
                        ExprBuilder::new()
                            .with_same_source_loc(e)
                            .get_attr(typ_expr_actual, attr.clone()),
                    ),
                })
            }

            ExprKind::HasAttr { expr, attr } => {
                // `has` applies to an entity or a record
                let actual = self.expect_one_of_types(
                    prior_capability,
                    expr,
                    &[Type::any_entity_reference(), Type::any_record()],
                    type_errors,
                    |actual| match actual {
                        Type::Set { .. } => Some(UnexpectedTypeHelp::TryUsingContains),
                        Type::Primitive {
                            primitive_type: Primitive::String,
                        } => Some(UnexpectedTypeHelp::TryUsingLike),
                        _ => None,
                    },
                );
                actual.then_typecheck(|typ_expr_actual, _| match typ_expr_actual.data() {
                    Some(typ_actual) => {
                        match Type::lookup_attribute_type(self.schema, typ_actual, attr) {
                            Some(AttributeType {
                                is_required: true, ..
                            }) => {
                                // Since an entity doesn't always have to exist
                                // in the entity store, and `has` evaluates to
                                // `false` when this is the case, we can't
                                // conclude that `has` is true just because an
                                // attribute is required for an entity type.
                                let exists_in_store = matches!(
                                    typ_actual,
                                    Type::EntityOrRecord(EntityRecordKind::Record { .. })
                                );
                                // However, we can make an exception when the attribute
                                // access of the expression is already in the prior capability,
                                // which means the entity must exist.
                                let in_prior_capability = prior_capability
                                    .contains(&Capability::new_attribute(expr, attr.clone()));
                                let type_of_has = if exists_in_store || in_prior_capability {
                                    Type::singleton_boolean(true)
                                } else {
                                    Type::primitive_boolean()
                                };
                                TypecheckAnswer::success_with_capability(
                                    ExprBuilder::with_data(Some(type_of_has))
                                        .with_same_source_loc(e)
                                        .has_attr(typ_expr_actual, attr.clone()),
                                    CapabilitySet::singleton(Capability::new_attribute(
                                        expr,
                                        attr.clone(),
                                    )),
                                )
                            }
                            // This is where capability information is generated. If
                            // the `HasAttr` for an optional attribute evaluates
                            // to `true`, then we know that it is safe to access
                            // that attribute, so we add an entry to the capability
                            // set.
                            Some(AttributeType {
                                is_required: false, ..
                            }) => TypecheckAnswer::success_with_capability(
                                ExprBuilder::with_data(Some(
                                    // The optional attribute `HasAttr` can have
                                    // type `true` if it occurs after the attribute
                                    // access of the expression is already in the
                                    // prior capability.
                                    if prior_capability
                                        .contains(&Capability::new_attribute(expr, attr.clone()))
                                    {
                                        Type::singleton_boolean(true)
                                    } else {
                                        Type::primitive_boolean()
                                    },
                                ))
                                .with_same_source_loc(e)
                                .has_attr(typ_expr_actual, attr.clone()),
                                CapabilitySet::singleton(Capability::new_attribute(
                                    expr,
                                    attr.clone(),
                                )),
                            ),
                            None => TypecheckAnswer::success(
                                ExprBuilder::with_data(Some(
                                    if Type::may_have_attr(self.schema, typ_actual, attr) {
                                        // The type might have the attribute, but we
                                        // can not conclude one way or the other.
                                        // This applies to record types and least
                                        // upper bounds between entity reference
                                        // types where one member of the lub has the
                                        // attribute.
                                        Type::primitive_boolean()
                                    } else {
                                        // The type definitely does not have the
                                        // attribute. This applies to entity least
                                        // upper bounds where none of the members
                                        // have the attribute.
                                        Type::singleton_boolean(false)
                                    },
                                ))
                                .with_same_source_loc(e)
                                .has_attr(typ_expr_actual, attr.clone()),
                            ),
                        }
                    }
                    None => TypecheckAnswer::fail(
                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                            .with_same_source_loc(e)
                            .has_attr(typ_expr_actual, attr.clone()),
                    ),
                })
            }

            ExprKind::Like { expr, pattern } => {
                // `like` applies to a string
                let actual = self.expect_type(
                    prior_capability,
                    expr,
                    Type::primitive_string(),
                    type_errors,
                    |actual| match actual {
                        Type::EntityOrRecord(
                            EntityRecordKind::AnyEntity | EntityRecordKind::Entity(_),
                        ) => Some(UnexpectedTypeHelp::TryUsingIs),
                        _ => None,
                    },
                );
                actual.then_typecheck(|actual_expr_ty, _| {
                    TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                            .with_same_source_loc(e)
                            .like(actual_expr_ty, pattern.clone()),
                    )
                })
            }

            ExprKind::Is { expr, entity_type } => {
                self.expect_type(
                    prior_capability,
                    expr,
                    Type::any_entity_reference(),
                    type_errors,
                    |_| Some(UnexpectedTypeHelp::TypeTestNotSupported),
                )
                .then_typecheck(|expr_ty, _| {
                    match expr_ty.data() {
                        Some(Type::EntityOrRecord(EntityRecordKind::Entity(actual_lub))) => {
                            let type_of_is = if !actual_lub.contains_entity_type(entity_type) {
                                // The actual EntityLUB does not contain the entity type
                                // we're testing for, so the `is` will always be `false`
                                Type::singleton_boolean(false)
                            } else if actual_lub.get_single_entity() == Some(entity_type) {
                                // The actual EntityLUB is exactly the entity type we're
                                // testing for with `is`, so the expression is always `true`
                                Type::singleton_boolean(true)
                            } else {
                                // The actual EntityLUB contains the entity type, so
                                // the `is` could be `true`, but it may also be `false`
                                Type::primitive_boolean()
                            };

                            TypecheckAnswer::success(
                                ExprBuilder::with_data(Some(type_of_is))
                                    .with_same_source_loc(e)
                                    .is_entity_type(expr_ty, entity_type.clone()),
                            )
                        }
                        // For `AnyEntity` we don't know anything about what
                        // entity type it could be, so we just return `Bool`.
                        Some(Type::EntityOrRecord(EntityRecordKind::AnyEntity)) => {
                            TypecheckAnswer::success(
                                ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                    .with_same_source_loc(e)
                                    .is_entity_type(expr_ty, entity_type.clone()),
                            )
                        }
                        // Expression type is not an entity type or is `None`.
                        // In either case a type error was already reported.
                        _ => TypecheckAnswer::fail(
                            ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                .with_same_source_loc(e)
                                .is_entity_type(expr_ty, entity_type.clone()),
                        ),
                    }
                })
            }

            // Literal sets have a list type where the type of the set element
            // is the least upper bound of all the types of expression in the set.
            ExprKind::Set(exprs) => {
                let elem_types = exprs
                    .iter()
                    .map(|elem| self.typecheck(prior_capability, elem, type_errors))
                    .collect::<Vec<_>>();

                // If we cannot compute a least upper bound for the element
                // types, then a type error will be generated by
                // `least_upper_bound_or_error` and TypecheckFail will be
                // returned. It will also return TypecheckFail if any of the
                // individual element failed to typecheck (were TypecheckFail).
                TypecheckAnswer::sequence_all_then_typecheck(elem_types, |types_and_capabilities| {
                    let (elem_expr_types, _): (Vec<Expr<Option<Type>>>, Vec<_>) =
                        types_and_capabilities.into_iter().unzip();
                    let elem_lub = self.least_upper_bound_or_error(
                        e,
                        elem_expr_types.iter().map(|ety| ety.data().clone()),
                        type_errors,
                        LubContext::Set,
                    );
                    match elem_lub {
                        _ if self.mode.is_strict() && exprs.is_empty() => {
                            type_errors.push(ValidationError::empty_set_forbidden(
                                e.source_loc().cloned(),
                                self.policy_id.clone(),
                            ));
                            TypecheckAnswer::fail(
                                ExprBuilder::new()
                                    .with_same_source_loc(e)
                                    .set(elem_expr_types),
                            )
                        }
                        Some(elem_lub) => TypecheckAnswer::success(
                            ExprBuilder::with_data(Some(Type::set(elem_lub)))
                                .with_same_source_loc(e)
                                .set(elem_expr_types),
                        ),
                        None => TypecheckAnswer::fail(
                            ExprBuilder::new()
                                .with_same_source_loc(e)
                                .set(elem_expr_types),
                        ),
                    }
                })
            }

            // For records, each (attribute, value) pair in the initializer need
            // to be individually accounted for in the record type.
            ExprKind::Record(map) => {
                // Typecheck each attribute initializer expression individually.
                let record_attr_tys = map
                    .values()
                    .map(|value| self.typecheck(prior_capability, value, type_errors));
                // This will cause the return value to be `TypecheckFail` if any
                // of the attributes did not typecheck.
                TypecheckAnswer::sequence_all_then_typecheck(
                    record_attr_tys,
                    |record_attr_tys_and_capabilities| {
                        let (record_attr_expr_tys, _): (Vec<Expr<Option<Type>>>, Vec<_>) =
                            record_attr_tys_and_capabilities.into_iter().unzip();
                        // If any of the attributes could not be assigned a type
                        // (recall that a expression can fail to typecheck but still
                        // be assigned a type), then we cannot assign any type to
                        // this expression.
                        let record_attr_tys = record_attr_expr_tys
                            .iter()
                            .map(|e| e.data().clone())
                            .collect::<Option<Vec<_>>>();
                        let ty = record_attr_tys.map(|record_attr_tys| {
                            // Given the attribute types which we know know
                            // exist, we pair them with the corresponding
                            // attribute names to get a record type.
                            let record_attrs = map.keys().cloned();
                            let record_type_entries = std::iter::zip(record_attrs, record_attr_tys);
                            Type::record_with_required_attributes(
                                record_type_entries,
                                OpenTag::ClosedAttributes,
                            )
                        });
                        let is_success = ty.is_some();
                        // PANIC SAFETY: can't have duplicate keys because the keys are the same as those in `map` which was already a BTreeMap
                        #[allow(clippy::expect_used)]
                        let expr = ExprBuilder::with_data(ty)
                            .with_same_source_loc(e)
                            .record(map.keys().cloned().zip(record_attr_expr_tys))
                            .expect("this can't have duplicate keys because the keys are the same as those in `map` which was already a BTreeMap");
                        if is_success {
                            TypecheckAnswer::success(expr)
                        } else {
                            TypecheckAnswer::fail(expr)
                        }
                    },
                )
            }
            #[cfg(feature = "tolerant-ast")]
            ExprKind::Error { .. } => TypecheckAnswer::ErrorAstNode,
        }
    }

    // Return if `ty` is a valid comparison operator type
    // Currently, only primitive long and certain extension types are valid
    fn is_valid_comparison_op_type(&self, ty: &Type) -> bool {
        match ty {
            Type::Primitive {
                primitive_type: Primitive::Long,
            } => true,
            Type::ExtensionType { name } => {
                self.extensions.has_type_with_operator_overloading(name)
            }
            _ => false,
        }
    }

    // Get all valid types satisfying `is_valid_comparison_op_type`
    // Only used for error message construction
    fn expected_comparison_op_types(&self) -> Vec<Type> {
        let expected_types = self
            .extensions
            .types_with_operator_overloading()
            .cloned()
            .map(Type::extension)
            .chain(std::iter::once(Type::primitive_long()))
            .collect_vec();
        expected_types
    }

    /// A utility called by the main typecheck method to handle binary operator
    /// application.
    /// INVARIANT: `bin_expr` must be a `BinaryApp`
    fn typecheck_binary<'b>(
        &self,
        prior_capability: &CapabilitySet<'b>,
        bin_expr: &'b Expr,
        type_errors: &mut Vec<ValidationError>,
    ) -> TypecheckAnswer<'b> {
        // PANIC SAFETY: maintained by invariant on this function
        #[allow(clippy::panic)]
        let ExprKind::BinaryApp { op, arg1, arg2 } = bin_expr.expr_kind() else {
            panic!("`typecheck_binary` called with an expression kind other than `BinaryApp`");
        };
        let bin_expr_loc = bin_expr.source_loc().cloned();

        match op {
            // The arguments to `==` may typecheck with any type, but we will
            // return false if the types are disjoint.
            BinaryOp::Eq => {
                let lhs_ty = self.typecheck(prior_capability, arg1, type_errors);
                let rhs_ty = self.typecheck(prior_capability, arg2, type_errors);
                lhs_ty.then_typecheck(|lhs_ty, _| {
                    rhs_ty.then_typecheck(|rhs_ty, _| {
                        let type_of_eq = self.type_of_equality(
                            arg1,
                            lhs_ty.data().as_ref(),
                            arg2,
                            rhs_ty.data().as_ref(),
                        );

                        if self.mode.is_strict() {
                            let annotated_eq = ExprBuilder::with_data(Some(type_of_eq))
                                .with_same_source_loc(bin_expr)
                                .binary_app(*op, lhs_ty.clone(), rhs_ty.clone());
                            self.enforce_strict_equality(
                                bin_expr,
                                annotated_eq,
                                lhs_ty.data().as_ref(),
                                rhs_ty.data().as_ref(),
                                type_errors,
                                LubContext::Equality,
                            )
                        } else {
                            TypecheckAnswer::success(
                                ExprBuilder::with_data(Some(type_of_eq))
                                    .with_same_source_loc(bin_expr)
                                    .binary_app(*op, lhs_ty, rhs_ty),
                            )
                        }
                    })
                })
            }

            BinaryOp::Less | BinaryOp::LessEq => {
                let ans_arg1 = self.typecheck(prior_capability, arg1, type_errors);
                ans_arg1.then_typecheck(|expr_ty_arg1, _| {
                    let ans_arg2 = self.typecheck(prior_capability, arg2, type_errors);
                    ans_arg2.then_typecheck(|expr_ty_arg2, _| {
                        let expr = ExprBuilder::with_data(Some(Type::primitive_boolean()))
                            .with_same_source_loc(bin_expr)
                            .binary_app(*op, expr_ty_arg1.clone(), expr_ty_arg2.clone());
                        let t1 = expr_ty_arg1.data().as_ref();
                        let t2 = expr_ty_arg2.data().as_ref();
                        match (t1, t2) {
                            (Some(Type::Never), Some(Type::Never)) => TypecheckAnswer::fail(expr),
                            (Some(Type::Never), Some(other)) => {
                                if self.is_valid_comparison_op_type(other) {
                                    TypecheckAnswer::success(expr)
                                } else {
                                    type_errors.push(ValidationError::expected_one_of_types(
                                        expr_ty_arg2.source_loc().cloned(),
                                        self.policy_id.clone(),
                                        self.expected_comparison_op_types(),
                                        other.clone(),
                                        None,
                                    ));
                                    TypecheckAnswer::fail(expr)
                                }
                            }
                            (Some(other), Some(Type::Never)) => {
                                if self.is_valid_comparison_op_type(other) {
                                    TypecheckAnswer::success(expr)
                                } else {
                                    type_errors.push(ValidationError::expected_one_of_types(
                                        expr_ty_arg1.source_loc().cloned(),
                                        self.policy_id.clone(),
                                        self.expected_comparison_op_types(),
                                        other.clone(),
                                        None,
                                    ));
                                    TypecheckAnswer::fail(expr)
                                }
                            }
                            (Some(t1), Some(t2))
                                if t1 == t2 && self.is_valid_comparison_op_type(t1) =>
                            {
                                TypecheckAnswer::success(expr)
                            }
                            (
                                Some(Type::Primitive {
                                    primitive_type: Primitive::Long,
                                }),
                                Some(other),
                            ) => {
                                type_errors.push(ValidationError::expected_one_of_types(
                                    expr_ty_arg2.source_loc().cloned(),
                                    self.policy_id.clone(),
                                    vec![Type::primitive_long()],
                                    other.clone(),
                                    None,
                                ));
                                TypecheckAnswer::fail(expr)
                            }
                            (
                                Some(other),
                                Some(Type::Primitive {
                                    primitive_type: Primitive::Long,
                                }),
                            ) => {
                                type_errors.push(ValidationError::expected_one_of_types(
                                    expr_ty_arg1.source_loc().cloned(),
                                    self.policy_id.clone(),
                                    vec![Type::primitive_long()],
                                    other.clone(),
                                    None,
                                ));
                                TypecheckAnswer::fail(expr)
                            }
                            (Some(lhs), Some(rhs)) if self.is_valid_comparison_op_type(lhs) => {
                                type_errors.push(ValidationError::expected_one_of_types(
                                    expr_ty_arg2.source_loc().cloned(),
                                    self.policy_id.clone(),
                                    vec![lhs.clone()],
                                    rhs.clone(),
                                    None,
                                ));
                                TypecheckAnswer::fail(expr)
                            }
                            (Some(lhs), Some(rhs)) if self.is_valid_comparison_op_type(rhs) => {
                                type_errors.push(ValidationError::expected_one_of_types(
                                    expr_ty_arg1.source_loc().cloned(),
                                    self.policy_id.clone(),
                                    vec![rhs.clone()],
                                    lhs.clone(),
                                    None,
                                ));
                                TypecheckAnswer::fail(expr)
                            }
                            (Some(lhs), Some(rhs)) => {
                                let expected_types = self.expected_comparison_op_types();
                                type_errors.push(ValidationError::expected_one_of_types(
                                    expr_ty_arg1.source_loc().cloned(),
                                    self.policy_id.clone(),
                                    expected_types.clone(),
                                    lhs.clone(),
                                    None,
                                ));
                                type_errors.push(ValidationError::expected_one_of_types(
                                    expr_ty_arg2.source_loc().cloned(),
                                    self.policy_id.clone(),
                                    expected_types,
                                    rhs.clone(),
                                    None,
                                ));
                                TypecheckAnswer::fail(expr)
                            }
                            _ => TypecheckAnswer::fail(expr),
                        }
                    })
                })
            }

            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => {
                let help_builder = |actual: &Type| match (op, actual) {
                    (
                        BinaryOp::Add,
                        Type::Primitive {
                            primitive_type: Primitive::String,
                        },
                    ) => Some(UnexpectedTypeHelp::ConcatenationNotSupported),
                    (_, Type::Set { .. }) => Some(UnexpectedTypeHelp::SetOperationsNotSupported),
                    _ => None,
                };
                let ans_arg1 = self.expect_type(
                    prior_capability,
                    arg1,
                    Type::primitive_long(),
                    type_errors,
                    help_builder,
                );
                ans_arg1.then_typecheck(|expr_ty_arg1, _| {
                    let ans_arg2 = self.expect_type(
                        prior_capability,
                        arg2,
                        Type::primitive_long(),
                        type_errors,
                        help_builder,
                    );
                    ans_arg2.then_typecheck(|expr_ty_arg2, _| {
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(Some(Type::primitive_long()))
                                .with_same_source_loc(bin_expr)
                                .binary_app(*op, expr_ty_arg1, expr_ty_arg2),
                        )
                    })
                })
            }

            BinaryOp::In => self.typecheck_in(prior_capability, bin_expr, arg1, arg2, type_errors),

            BinaryOp::Contains => {
                // The first argument must be a set.
                self.expect_type(
                    prior_capability,
                    arg1,
                    Type::any_set(),
                    type_errors,
                    |actual| match actual {
                        Type::EntityOrRecord(
                            EntityRecordKind::AnyEntity | EntityRecordKind::Entity(_),
                        ) => Some(UnexpectedTypeHelp::TryUsingIn),
                        Type::EntityOrRecord(EntityRecordKind::Record { .. }) => {
                            Some(UnexpectedTypeHelp::TryUsingHas)
                        }
                        Type::Primitive {
                            primitive_type: Primitive::String,
                        } => Some(UnexpectedTypeHelp::TryUsingLike),
                        _ => None,
                    },
                )
                .then_typecheck(|expr_ty_arg1, _| {
                    // The second argument may be any type. We do not care if the element type cannot be in the set.
                    self.typecheck(prior_capability, arg2, type_errors)
                        .then_typecheck(|expr_ty_arg2, _| {
                            if self.mode.is_strict() {
                                let annotated_expr =
                                    ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                        .with_same_source_loc(bin_expr)
                                        .binary_app(
                                            *op,
                                            expr_ty_arg1.clone(),
                                            expr_ty_arg2.clone(),
                                        );
                                self.enforce_strict_equality(
                                    bin_expr,
                                    annotated_expr,
                                    match expr_ty_arg1.data() {
                                        Some(Type::Set {
                                            element_type: Some(ty),
                                        }) => Some(ty.as_ref()),
                                        _ => None,
                                    },
                                    expr_ty_arg2.data().as_ref(),
                                    type_errors,
                                    LubContext::Contains,
                                )
                            } else {
                                TypecheckAnswer::success(
                                    ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                        .with_same_source_loc(bin_expr)
                                        .binary_app(*op, expr_ty_arg1, expr_ty_arg2),
                                )
                            }
                        })
                })
            }

            BinaryOp::ContainsAll | BinaryOp::ContainsAny => {
                // Both arguments to a `containsAll` or `containsAny` must be sets.
                self.expect_type(
                    prior_capability,
                    arg1,
                    Type::any_set(),
                    type_errors,
                    |actual| match actual {
                        Type::EntityOrRecord(
                            EntityRecordKind::AnyEntity | EntityRecordKind::Entity(_),
                        ) => Some(UnexpectedTypeHelp::TryUsingIn),
                        Type::EntityOrRecord(EntityRecordKind::Record { .. }) => {
                            Some(UnexpectedTypeHelp::TryUsingHas)
                        }
                        Type::Primitive {
                            primitive_type: Primitive::String,
                        } => Some(UnexpectedTypeHelp::TryUsingLike),
                        _ => None,
                    },
                )
                .then_typecheck(|expr_ty_arg1, _| {
                    self.expect_type(prior_capability, arg2, Type::any_set(), type_errors, |_| {
                        Some(UnexpectedTypeHelp::TryUsingSingleContains)
                    })
                    .then_typecheck(|expr_ty_arg2, _| {
                        if self.mode.is_strict() {
                            let annotated_expr =
                                ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                    .with_same_source_loc(bin_expr)
                                    .binary_app(*op, expr_ty_arg1.clone(), expr_ty_arg2.clone());
                            self.enforce_strict_equality(
                                bin_expr,
                                annotated_expr,
                                expr_ty_arg1.data().as_ref(),
                                expr_ty_arg2.data().as_ref(),
                                type_errors,
                                LubContext::ContainsAnyAll,
                            )
                        } else {
                            TypecheckAnswer::success(
                                ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                    .with_same_source_loc(bin_expr)
                                    .binary_app(*op, expr_ty_arg1, expr_ty_arg2),
                            )
                        }
                    })
                })
            }

            BinaryOp::HasTag => self
                .expect_type(
                    prior_capability,
                    arg1,
                    Type::any_entity_reference(),
                    type_errors,
                    |_| None,
                )
                .then_typecheck(|expr_ty_arg1, _| {
                    self.expect_type(
                        prior_capability,
                        arg2,
                        Type::primitive_string(),
                        type_errors,
                        |_| None,
                    )
                    .then_typecheck(|expr_ty_arg2, _| {
                        let kind = match expr_ty_arg1.data() {
                            Some(Type::EntityOrRecord(kind)) => kind,
                            None => {
                                // should have already reported an error in this case.
                                // just return a failure.
                                return TypecheckAnswer::fail(
                                    ExprBuilder::new()
                                        .with_same_source_loc(bin_expr)
                                        .has_tag(expr_ty_arg1, expr_ty_arg2),
                                );
                            }
                            _ => {
                                // should be unreachable, as we already typechecked that this matches
                                // `Type::any_entity_reference()`
                                type_errors.push(ValidationError::internal_invariant_violation(
                                    bin_expr_loc.clone(),
                                    self.policy_id.clone(),
                                ));
                                return TypecheckAnswer::fail(
                                    ExprBuilder::new()
                                        .with_same_source_loc(bin_expr)
                                        .has_tag(expr_ty_arg1, expr_ty_arg2),
                                );
                            }
                        };
                        let type_of_has = match self.tag_types(kind) {
                            Ok(tag_types) if tag_types.is_empty() => {
                                // impossible for the type to have any tags, thus the `has` will always be `False`
                                Type::singleton_boolean(false)
                            }
                            Err(()) => {
                                // Not an entity type; should be unreachable, as we already typechecked
                                // that this matches `Type::any_entity_reference()`
                                type_errors.push(ValidationError::internal_invariant_violation(
                                    bin_expr_loc.clone(),
                                    self.policy_id.clone(),
                                ));
                                return TypecheckAnswer::fail(
                                    ExprBuilder::new()
                                        .with_same_source_loc(bin_expr)
                                        .has_tag(expr_ty_arg1, expr_ty_arg2),
                                );
                            }
                            _ => {
                                if prior_capability
                                    .contains(&Capability::new_borrowed_tag(arg1, arg2))
                                {
                                    // Prior capability tells us that we already checked for the tag, so `hasTag` is `True`
                                    Type::singleton_boolean(true)
                                } else {
                                    Type::primitive_boolean()
                                }
                            }
                        };
                        TypecheckAnswer::success_with_capability(
                            ExprBuilder::with_data(Some(type_of_has))
                                .with_same_source_loc(bin_expr)
                                .binary_app(BinaryOp::HasTag, expr_ty_arg1, expr_ty_arg2),
                            CapabilitySet::singleton(Capability::new_borrowed_tag(arg1, arg2)),
                        )
                    })
                }),

            BinaryOp::GetTag => {
                self.expect_type(
                    prior_capability,
                    arg1,
                    Type::any_entity_reference(),
                    type_errors,
                    |_actual| None,
                )
                .then_typecheck(|expr_ty_arg1, _| {
                    self.expect_type(
                        prior_capability,
                        arg2,
                        Type::primitive_string(),
                        type_errors,
                        |_| None,
                    )
                    .then_typecheck(|expr_ty_arg2, _| {
                        let kind = match expr_ty_arg1.data() {
                            Some(Type::EntityOrRecord(kind)) => kind,
                            None => {
                                // should have already reported an error in this case.
                                // just return a failure.
                                return TypecheckAnswer::fail(
                                    ExprBuilder::new()
                                        .with_same_source_loc(bin_expr)
                                        .get_tag(expr_ty_arg1, expr_ty_arg2),
                                );
                            }
                            _ => {
                                // should be unreachable, as we already typechecked that this matches
                                // `Type::any_entity_reference()`
                                type_errors.push(ValidationError::internal_invariant_violation(
                                    bin_expr_loc.clone(),
                                    self.policy_id.clone(),
                                ));
                                return TypecheckAnswer::fail(
                                    ExprBuilder::new()
                                        .with_same_source_loc(bin_expr)
                                        .get_tag(expr_ty_arg1, expr_ty_arg2),
                                );
                            }
                        };
                        if prior_capability.contains(&Capability::new_borrowed_tag(arg1, arg2)) {
                            // Determine the set of possible tag types for this access.
                            let tag_types = match self.tag_types(kind) {
                                Ok(tag_types) => tag_types,
                                Err(()) => {
                                    // `kind` was not an entity type.
                                    // should be unreachable, as we already typechecked that this matches
                                    // `Type::any_entity_reference()`
                                    type_errors.push(
                                        ValidationError::internal_invariant_violation(
                                            bin_expr_loc.clone(),
                                            self.policy_id.clone(),
                                        ),
                                    );
                                    return TypecheckAnswer::fail(
                                        ExprBuilder::new()
                                            .with_same_source_loc(bin_expr)
                                            .get_tag(expr_ty_arg1, expr_ty_arg2),
                                    );
                                }
                            };
                            if tag_types.is_empty() {
                                // no entities in the LUB are allowed to have tags.
                                // This is a somewhat weird case where we did do a `has` check (we
                                // already confirmed farther above that we have the capability for
                                // this tag), but the entity type(s) we're operating on just can't
                                // have tags.
                                let entity_ty = match kind {
                                    EntityRecordKind::Entity(lub) => lub.get_single_entity(),
                                    EntityRecordKind::AnyEntity => None,
                                    EntityRecordKind::Record { .. } => None,
                                };
                                type_errors.push(ValidationError::no_tags_allowed(
                                    bin_expr_loc.clone(),
                                    self.policy_id.clone(),
                                    entity_ty.cloned(),
                                ));
                                TypecheckAnswer::fail(
                                    ExprBuilder::new()
                                        .with_same_source_loc(bin_expr)
                                        .get_tag(expr_ty_arg1, expr_ty_arg2),
                                )
                            } else {
                                // one or more entities in the LUB are allowed to have tags.
                                // compute the LUB of all the relevant tag types, and assign that
                                // as the type.
                                let tag_type = match Type::reduce_to_least_upper_bound(
                                    self.schema,
                                    tag_types.clone(),
                                    self.mode,
                                ) {
                                    Ok(ty) => ty,
                                    Err(e) => {
                                        type_errors.push(ValidationError::incompatible_types(
                                            bin_expr_loc.clone(),
                                            self.policy_id.clone(),
                                            tag_types.into_iter().cloned(),
                                            e,
                                            LubContext::GetTag,
                                        ));
                                        return TypecheckAnswer::fail(
                                            ExprBuilder::new()
                                                .with_same_source_loc(bin_expr)
                                                .get_tag(expr_ty_arg1, expr_ty_arg2),
                                        );
                                    }
                                };
                                TypecheckAnswer::success(
                                    ExprBuilder::with_data(Some(tag_type))
                                        .with_same_source_loc(bin_expr)
                                        .get_tag(expr_ty_arg1, expr_ty_arg2),
                                )
                            }
                        } else {
                            type_errors.push(ValidationError::unsafe_tag_access(
                                bin_expr_loc.clone(),
                                self.policy_id.clone(),
                                match kind {
                                    EntityRecordKind::Entity(lub) => Some(lub.clone()),
                                    _ => None,
                                },
                                expr_ty_arg2.clone(),
                            ));
                            TypecheckAnswer::fail(
                                ExprBuilder::new()
                                    .with_same_source_loc(bin_expr)
                                    .get_tag(expr_ty_arg1, expr_ty_arg2),
                            )
                        }
                    })
                })
            }
        }
    }

    fn enforce_strict_equality<'b>(
        &self,
        unannotated_expr: &'b Expr,
        annotated_expr: Expr<Option<Type>>,
        lhs_ty: Option<&Type>,
        rhs_ty: Option<&Type>,
        type_errors: &mut Vec<ValidationError>,
        context: LubContext,
    ) -> TypecheckAnswer<'b> {
        match annotated_expr.data() {
            Some(Type::True | Type::False) => TypecheckAnswer::success(annotated_expr),
            _ => match (lhs_ty, rhs_ty) {
                (Some(lhs_ty), Some(rhs_ty)) => {
                    if let Err(lub_hint) =
                        Type::least_upper_bound(self.schema, lhs_ty, rhs_ty, self.mode)
                    {
                        type_errors.push(ValidationError::incompatible_types(
                            unannotated_expr.source_loc().cloned(),
                            self.policy_id.clone(),
                            [lhs_ty.clone(), rhs_ty.clone()],
                            lub_hint,
                            context,
                        ));
                        TypecheckAnswer::fail(annotated_expr)
                    } else {
                        // We had `Some` type for lhs and rhs and these types
                        // were compatible.
                        TypecheckAnswer::success(annotated_expr)
                    }
                }
                // We failed to compute a type for either lhs or rhs, meaning
                // we already failed typechecking for that expression.
                _ => TypecheckAnswer::success(annotated_expr),
            },
        }
    }

    /// Get the type for an `==` expression given the input types.
    fn type_of_equality<'b>(
        &self,
        lhs_expr: &'b Expr,
        lhs_ty: Option<&Type>,
        rhs_expr: &'b Expr,
        rhs_ty: Option<&Type>,
    ) -> Type {
        // If we know the types are disjoint, then we can return give the
        // expression type False. See `are_types_disjoint` definition for
        // explanation of why fewer types are disjoint than may be expected.
        let disjoint_types = match (lhs_ty, rhs_ty) {
            (Some(lhs_ty), Some(rhs_ty)) => Type::are_types_disjoint(lhs_ty, rhs_ty),
            _ => false,
        };
        if disjoint_types {
            Type::False
        } else {
            // The types are not disjoint. Check if we can decide the equality
            // from the actual expressions. If both expressions are literals,
            // then we evaluate the equality between literals and return that as
            // a singleton boolean.
            if let (ExprKind::Lit(lhs_lit), ExprKind::Lit(rhs_lit)) = (
                self.replace_action_var_with_euid(lhs_expr).expr_kind(),
                self.replace_action_var_with_euid(rhs_expr).expr_kind(),
            ) {
                Type::singleton_boolean(lhs_lit == rhs_lit)
            } else {
                // When the left and right expressions are not both literal
                // euids, the validator does not attempt to give a more specific
                // type than boolean.
                Type::primitive_boolean()
            }
        }
    }

    /// Get the set of types that are possible tag types for `kind`.
    ///
    /// If `kind` is not an entity type (e.g., a record type), this returns `Err`.
    /// If `kind` is an entity type without a `tags` declaration, this returns
    /// `Ok` with the empty set.
    ///
    /// If `kind` is a LUB containing some entity types that have tags and some
    /// that do not, this ignores the entity types that do not; we just assume
    /// the access is not on one of those entity types.
    fn tag_types<'s>(&'s self, kind: &EntityRecordKind) -> Result<HashSet<&'s Type>, ()> {
        use crate::validator::schema::ValidatorEntityType;
        match kind {
            EntityRecordKind::Entity(lub) => Ok(lub
                .iter()
                .filter_map(|ety| {
                    self.schema
                        .get_entity_type(ety)
                        .and_then(ValidatorEntityType::tag_type)
                })
                .collect()),
            EntityRecordKind::AnyEntity => Ok(self
                .schema
                .entity_types()
                .filter_map(ValidatorEntityType::tag_type)
                .collect()),
            EntityRecordKind::Record { .. } => Err(()),
        }
    }

    /// Checks if `lhs_ety` may be a descendant of `rhs_ety` in the action hierarchy.
    /// We assume that `lhs_ety` is an action entity type, but `rhs_ety` can be any entity type.
    /// Lean counterpart: <https://github.com/cedar-policy/cedar-spec/blob/7e231a68b0e0eb1b8ce1362e81de4568671a668a/cedar-lean/Cedar/Validation/Types.lean#L202>
    fn check_action_in_entity_type(&self, lhs_ety: &EntityType, rhs_ety: &EntityType) -> bool {
        lhs_ety == rhs_ety
            || self.schema.action_ids().any(|action| {
                action.name().entity_type() == rhs_ety
                    && action
                        .descendants()
                        .any(|desc| desc.entity_type() == lhs_ety)
            })
    }

    /// Check if an entity type in `lhs` may be a descendant of some entity type
    /// in rhs, either in the entity or action hierarchy. If this function
    /// returns `false`, then `lhs in rhs` cannot possibly evaluate to `true`,
    /// meaning that the expression can have type `False`.
    fn any_entity_type_decedent_of(&self, lhs: &EntityLUB, rhs: &EntityLUB) -> bool {
        lhs.iter().any(|lhs| {
            rhs.iter().any(|rhs| {
                self.schema.get_entity_types_in(rhs).contains(&lhs)
                    || self.check_action_in_entity_type(lhs, rhs)
            })
        })
    }

    /// Handles typechecking of `in` expressions. This is complicated because it
    /// requires searching the schema to determine if an `in` expression
    /// consisting of variables and literals can ever be true. When we find that
    /// an `in` expression is always false, this function returns the singleton
    /// type false, allowing for short circuiting in `if` and `and` expressions.
    fn typecheck_in<'b>(
        &self,
        prior_capability: &CapabilitySet<'b>,
        in_expr: &Expr,
        lhs: &'b Expr,
        rhs: &'b Expr,
        type_errors: &mut Vec<ValidationError>,
    ) -> TypecheckAnswer<'b> {
        // First, the basic typechecking rules for `in` that apply regardless of
        // the syntactic special cases that follow.
        let ty_lhs = self.expect_type(
            prior_capability,
            lhs,
            Type::any_entity_reference(),
            type_errors,
            |_| Some(UnexpectedTypeHelp::TryUsingContains),
        );
        let ty_rhs = self.expect_one_of_types(
            prior_capability,
            rhs,
            &[
                Type::set(Type::any_entity_reference()),
                Type::any_entity_reference(),
            ],
            type_errors,
            |actual| match actual {
                Type::Set { .. } => Some(UnexpectedTypeHelp::TryUsingContains),
                Type::Primitive {
                    primitive_type: Primitive::String,
                } => Some(UnexpectedTypeHelp::TryUsingLike),
                _ => None,
            },
        );

        let lhs_typechecked = ty_lhs.typechecked();
        let rhs_typechecked = ty_rhs.typechecked();

        ty_lhs.then_typecheck(|lhs_expr, _lhs_capabilities| {
            ty_rhs.then_typecheck(|rhs_expr, _rhs_capabilities| {
                // If either failed to typecheck, then the whole expression fails to
                // typecheck.
                if !lhs_typechecked || !rhs_typechecked {
                    return TypecheckAnswer::fail(
                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                            .with_same_source_loc(in_expr)
                            .is_in(lhs_expr, rhs_expr),
                    );
                }
                let lhs_as_euid_lit = self.euid_from_euid_literal_or_action(lhs);
                let rhs_as_euid_lits = self.euids_from_euid_literals_or_actions(rhs);
                match (lhs_as_euid_lit, rhs_as_euid_lits) {
                    // Syntactic special case for an action literal or variable
                    // `in` an entity literal or set of entity literal. By
                    // examining the action hierarchy in the schema, we'll be
                    // able to give this a singleton boolean type.
                    (Some(lhs_euid), Some(rhs_euids)) if lhs_euid.is_action() => self
                        .type_of_action_in_entity_literals(
                            &lhs_euid,
                            rhs_euids.iter().map(AsRef::as_ref),
                            in_expr,
                            lhs_expr,
                            rhs_expr,
                        ),
                    _ => {
                        let lhs_etys = match lhs_expr.data() {
                            Some(Type::EntityOrRecord(EntityRecordKind::Entity(lhs_etys))) => {
                                Some(lhs_etys)
                            }
                            _ => None,
                        };
                        let rhs_etys = match rhs_expr.data() {
                            Some(Type::EntityOrRecord(EntityRecordKind::Entity(rhs_etys))) => {
                                Some(rhs_etys)
                            }
                            Some(Type::Set {
                                element_type: Some(element_type),
                            }) => match element_type.as_ref() {
                                Type::EntityOrRecord(EntityRecordKind::Entity(rhs_etys)) => {
                                    Some(rhs_etys)
                                }
                                _ => None,
                            },
                            _ => None,
                        };
                        match (lhs_etys, rhs_etys) {
                            (Some(lhs_etys), Some(rhs_etys))
                                if !self.any_entity_type_decedent_of(lhs_etys, rhs_etys) =>
                            {
                                TypecheckAnswer::success(
                                    ExprBuilder::with_data(Some(Type::False))
                                        .with_same_source_loc(in_expr)
                                        .is_in(lhs_expr, rhs_expr),
                                )
                            }

                            // If none of the cases apply, then all we know is that `in` has
                            // type boolean. Importantly for partial schema
                            // validation, this case captures an `in` between entity
                            // literals where the LHS is not an action defined in
                            // the schema and does not have an entity type defined
                            // in the schema.
                            _ => TypecheckAnswer::success(
                                ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                    .with_same_source_loc(in_expr)
                                    .is_in(lhs_expr, rhs_expr),
                            ),
                        }
                    }
                }
                .then_typecheck(|type_of_in, _| TypecheckAnswer::success(type_of_in))
            })
        })
    }

    // Given an expression, if that expression is a literal or the `action`
    // variable, return it as an `EntityUID`. Return `None` otherwise.
    fn euid_from_euid_literal_or_action(&self, e: &Expr) -> Option<Arc<EntityUID>> {
        match self.replace_action_var_with_euid(e).expr_kind() {
            ExprKind::Lit(Literal::EntityUID(e)) => Some(e.clone()),
            _ => None,
        }
    }

    /// If the expression is a literal, the `action` variable, or a set of
    /// exclusively literals/actions, then return all the `EntityUID`s. Return
    /// `None` otherwise.
    fn euids_from_euid_literals_or_actions(&self, e: &Expr) -> Option<Vec<Arc<EntityUID>>> {
        if let Some(euid) = self.euid_from_euid_literal_or_action(e) {
            Some(vec![euid])
        } else if let ExprKind::Set(exprs) = e.expr_kind() {
            exprs
                .iter()
                .map(|e| self.euid_from_euid_literal_or_action(e))
                .collect::<Option<Vec<_>>>()
        } else {
            None
        }
    }

    // Get the type for `in` when it is applied to an action EUID literal on the
    // left and one or more EUID literals on the right, which may or may not be
    // actions.  If they're not actions, then we assume the LHS action can never
    // be in a non-action entity. If there is at least on RHS action entity,
    // then we can precisely evaluate the `in`, giving the expression a
    // singleton boolean type.
    fn type_of_action_in_entity_literals<'b, 'c>(
        &self,
        lhs_euid: &EntityUID,
        rhs_elems: impl IntoIterator<Item = &'b EntityUID>,
        in_expr: &Expr,
        lhs_expr: Expr<Option<Type>>,
        rhs_expr: Expr<Option<Type>>,
    ) -> TypecheckAnswer<'c> {
        debug_assert!(
            lhs_euid.is_action(),
            "We expect this function is called only when an action entity is on the LHS"
        );
        // If there's a at least on action on the right, check if that
        // action is an ancestor of the LHS action. We can ignore any
        // non-actions because we assume action cannot be `in` a non-action.
        let rhs_actions: Vec<_> = rhs_elems
            .into_iter()
            .filter(|e| e.entity_type().is_action())
            .collect();
        if !rhs_actions.is_empty() {
            self.type_of_action_in_actions(
                lhs_euid,
                rhs_actions.iter().copied(),
                in_expr,
                lhs_expr,
                rhs_expr,
            )
        } else {
            // There are no actions on the right, so the LHS action cannot
            // be `in` any of them.
            TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::False))
                    .with_same_source_loc(in_expr)
                    .is_in(lhs_expr, rhs_expr),
            )
        }
    }

    // Get the type for `in` when it is applied to an action EUID literal on the
    // left and one or more actions EUID literals on the right.  We can look up
    // the exact set of ancestors for the action in the schema, allowing us to
    // evalute the `in` to `true` or `false`, so the type will be `True` or
    // `False`  respectively.
    fn type_of_action_in_actions<'b>(
        &self,
        lhs: &EntityUID,
        rhs: impl IntoIterator<Item = &'a EntityUID> + 'a,
        in_expr: &Expr,
        lhs_expr: Expr<Option<Type>>,
        rhs_expr: Expr<Option<Type>>,
    ) -> TypecheckAnswer<'b> {
        if let Some(rhs_descendants) = self.schema.get_actions_in_set(rhs) {
            // We have literal actions on the LHS and RHS of the `in` so we can
            // precisely evaluate the expression by checking if the LHS action
            // is a decedent of anything on the RHS.
            let is_action_in_descendants = rhs_descendants.into_iter().any(|e| e == lhs);
            TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::singleton_boolean(is_action_in_descendants)))
                    .with_same_source_loc(in_expr)
                    .is_in(lhs_expr, rhs_expr),
            )
        } else {
            let annotated_expr = ExprBuilder::with_data(Some(Type::primitive_boolean()))
                .with_same_source_loc(in_expr)
                .is_in(lhs_expr, rhs_expr);
            if self.mode.is_partial() {
                TypecheckAnswer::success(annotated_expr)
            } else {
                TypecheckAnswer::fail(annotated_expr)
            }
        }
    }

    /// A utility called by the main typecheck method to handle unary operator
    /// application.
    /// INVARIANT: `unary_expr` must be of kind `UnaryApp`
    fn typecheck_unary<'b>(
        &self,
        prior_capability: &CapabilitySet<'b>,
        unary_expr: &'b Expr,
        type_errors: &mut Vec<ValidationError>,
    ) -> TypecheckAnswer<'b> {
        // PANIC SAFETY maintained by invariant on this function
        #[allow(clippy::panic)]
        let ExprKind::UnaryApp { op, arg } = unary_expr.expr_kind() else {
            panic!("`typecheck_unary` called with an expression kind other than `UnaryApp`");
        };
        match op {
            UnaryOp::Not => {
                let ans_arg = self.expect_type(
                    prior_capability,
                    arg,
                    Type::primitive_boolean(),
                    type_errors,
                    |_| None,
                );
                ans_arg.then_typecheck(|typ_expr_arg, _| match typ_expr_arg.data() {
                    Some(typ_arg) => {
                        TypecheckAnswer::success(if typ_arg == &Type::singleton_boolean(true) {
                            ExprBuilder::with_data(Some(Type::singleton_boolean(false)))
                                .with_same_source_loc(unary_expr)
                                .not(typ_expr_arg)
                        } else if typ_arg == &Type::singleton_boolean(false) {
                            ExprBuilder::with_data(Some(Type::singleton_boolean(true)))
                                .with_same_source_loc(unary_expr)
                                .not(typ_expr_arg)
                        } else {
                            ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                .with_same_source_loc(unary_expr)
                                .not(typ_expr_arg)
                        })
                    }
                    None => TypecheckAnswer::fail(
                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                            .with_same_source_loc(unary_expr)
                            .not(typ_expr_arg),
                    ),
                })
            }
            UnaryOp::Neg => {
                let ans_arg = self.expect_type(
                    prior_capability,
                    arg,
                    Type::primitive_long(),
                    type_errors,
                    |_| None,
                );
                ans_arg.then_typecheck(|typ_expr_arg, _| {
                    TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(Type::primitive_long()))
                            .with_same_source_loc(unary_expr)
                            .neg(typ_expr_arg),
                    )
                })
            }
            UnaryOp::IsEmpty => {
                let ans_arg = self.expect_type(
                    prior_capability,
                    arg,
                    Type::any_set(),
                    type_errors,
                    |actual| match actual {
                        Type::Primitive {
                            primitive_type: Primitive::String,
                        } => Some(UnexpectedTypeHelp::TryUsingEqEmptyString),
                        _ => None,
                    },
                );
                ans_arg.then_typecheck(|typ_expr_arg, _| {
                    TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                            .with_same_source_loc(unary_expr)
                            .is_empty(typ_expr_arg),
                    )
                })
            }
        }
    }

    /// Check that an expression has a type that is a subtype of one of the
    /// given types. If not, generate a type error and return `TypecheckFail`.
    /// Return `TypecheckSuccess` with the type otherwise.
    fn expect_one_of_types<'b, F>(
        &self,
        prior_capability: &CapabilitySet<'b>,
        expr: &'b Expr,
        expected: &[Type],
        type_errors: &mut Vec<ValidationError>,
        type_error_help: F,
    ) -> TypecheckAnswer<'b>
    where
        F: FnOnce(&Type) -> Option<UnexpectedTypeHelp>,
    {
        let actual = self.typecheck(prior_capability, expr, type_errors);
        actual.then_typecheck(|mut typ_actual, capability| match typ_actual.data() {
            Some(actual_ty) => {
                if !expected.iter().any(|expected_ty| {
                    // This check uses `ValidationMode::Permissive` even in
                    // strict typechecking because we use this function and
                    // `expect_type` to require that an operand is a record type
                    // or an entity type by calling this function with
                    // `AnyEntity` or `{}` as the expected type. In either case,
                    // we need to make the check using width subtyping to avoid
                    // reporting an error every time we see a `GetAttr` on a
                    // non-empty record.
                    Type::is_subtype(
                        self.schema,
                        actual_ty,
                        expected_ty,
                        ValidationMode::Permissive,
                    )
                }) {
                    type_errors.push(ValidationError::expected_one_of_types(
                        expr.source_loc().cloned(),
                        self.policy_id.clone(),
                        expected.to_vec(),
                        actual_ty.clone(),
                        type_error_help(actual_ty),
                    ));
                    // Some code (e.g., typechecking And) depends on
                    // `expect_type` not returning an expression with a type
                    // other than one of the expected types. At the same time,
                    // we need to return an Expr with the source location,
                    // children, and kind as the original expression. The
                    // easiest way to do this is to mutate `typ_actual`.
                    typ_actual.set_data(None);
                    TypecheckAnswer::fail(typ_actual)
                } else {
                    TypecheckAnswer::success_with_capability(typ_actual, capability)
                }
            }
            None => {
                typ_actual.set_data(None);
                TypecheckAnswer::fail(typ_actual)
            }
        })
    }

    /// Check that an expression has a type that is a subtype of a given type.
    /// If not, generate a type error and return None. Otherwise, return the
    /// type.
    fn expect_type<'b, F>(
        &self,
        prior_capability: &CapabilitySet<'b>,
        expr: &'b Expr,
        expected: Type,
        type_errors: &mut Vec<ValidationError>,
        type_error_help: F,
    ) -> TypecheckAnswer<'b>
    where
        F: FnOnce(&Type) -> Option<UnexpectedTypeHelp>,
    {
        self.expect_one_of_types(
            prior_capability,
            expr,
            &[expected],
            type_errors,
            type_error_help,
        )
    }

    /// Return the least upper bound of all types is the `types` vector. If
    /// there isn't a least upper bound, then a type error is reported and
    /// `TypecheckFail` is returned. Note that this function does not preserve the
    /// capabilities of the input [`TypecheckAnswers`].
    fn least_upper_bound_or_error(
        &self,
        expr: &Expr,
        answers: impl IntoIterator<Item = Option<Type>>,
        type_errors: &mut Vec<ValidationError>,
        context: LubContext,
    ) -> Option<Type> {
        answers
            .into_iter()
            // Inverting this to `Option<Vec<_>>` will cause this to fail to
            // find a least upper bound if any of the input types were not
            // defined.
            .collect::<Option<Vec<_>>>()
            .and_then(|typechecked_types| {
                let lub =
                    Type::reduce_to_least_upper_bound(self.schema, &typechecked_types, self.mode);
                match lub {
                    Err(lub_hint) => {
                        // A type error is generated if we could not find a least
                        // upper bound for the types. The computed least upper bound
                        // will be None, so this function will correctly report this
                        // as a failure.
                        type_errors.push(ValidationError::incompatible_types(
                            expr.source_loc().cloned(),
                            self.policy_id.clone(),
                            typechecked_types,
                            lub_hint,
                            context,
                        ));
                        None
                    }
                    Ok(lub) => Some(lub),
                }
            })
    }

    /// If the `maybe_action_var` expression is `Expr::Var(Var::Action)`, return
    /// a expression for the entity uid for the action variable in the request
    /// environment. Otherwise, return the expression unchanged.
    fn replace_action_var_with_euid(&self, maybe_action_var: &'a Expr) -> Cow<'a, Expr> {
        match maybe_action_var.expr_kind() {
            ExprKind::Var(Var::Action) => match self.request_env.action_entity_uid() {
                Some(action) => Cow::Owned(Expr::val(action.clone())),
                None => Cow::Borrowed(maybe_action_var),
            },
            _ => Cow::Borrowed(maybe_action_var),
        }
    }

    /// Lookup an extension function type by name.
    fn lookup_extension_function(
        &self,
        f: &Name,
        e: &Expr,
    ) -> Result<&ExtensionFunctionType, ValidationError> {
        self.extensions.func_type(f).ok_or_else(|| {
            ValidationError::undefined_extension(
                e.source_loc().cloned(),
                self.policy_id.clone(),
                f.to_string(),
            )
        })
    }

    /// Utility called by the main typecheck method to handle extension function
    /// application.
    /// INVARIANT `ext_expr` must be a `ExtensionFunctionApp`
    fn typecheck_extension<'b>(
        &self,
        prior_capability: &CapabilitySet<'b>,
        ext_expr: &'b Expr,
        type_errors: &mut Vec<ValidationError>,
    ) -> TypecheckAnswer<'b> {
        // PANIC SAFETY maintained by invariant on this function
        #[allow(clippy::panic)]
        let ExprKind::ExtensionFunctionApp { fn_name, args } = ext_expr.expr_kind() else {
            panic!("`typecheck_extension` called with an expression kind other than `ExtensionFunctionApp`");
        };

        let typed_arg_exprs = |type_errors: &mut Vec<ValidationError>| {
            args.iter()
                .map(|arg| {
                    self.typecheck(prior_capability, arg, type_errors)
                        .into_typed_expr()
                })
                .collect::<Option<Vec<_>>>()
        };

        match self.lookup_extension_function(fn_name, ext_expr) {
            Ok(efunc) => {
                let arg_tys = efunc.argument_types();
                let ret_ty = efunc.return_type();
                // since we mutate several times, I think readability is better if we keep a consistent pattern, rather than using Clippy's suggestion for the first block
                #[allow(clippy::useless_let_if_seq)]
                let mut failed = false;

                // variadic functions can take one or more arguments of the last argument type
                if efunc.is_variadic() && args.len() < arg_tys.len() {
                    type_errors.push(ValidationError::wrong_number_args(
                        ext_expr.source_loc().cloned(),
                        self.policy_id.clone(),
                        arg_tys.len(),
                        args.len(),
                    ));
                    failed = true;
                }

                // non-variadic functions must take the exact number of argument as the number of argument types
                if !efunc.is_variadic() && args.len() != arg_tys.len() {
                    type_errors.push(ValidationError::wrong_number_args(
                        ext_expr.source_loc().cloned(),
                        self.policy_id.clone(),
                        arg_tys.len(),
                        args.len(),
                    ));
                    failed = true;
                }
                if let Err(msg) = efunc.check_arguments(args) {
                    type_errors.push(ValidationError::function_argument_validation(
                        ext_expr.source_loc().cloned(),
                        self.policy_id.clone(),
                        msg,
                    ));
                    failed = true;
                }

                if self.mode.is_strict()
                    && efunc.has_argument_check()
                    && !args
                        .iter()
                        .all(|e| matches!(e.expr_kind(), ExprKind::Lit(_)))
                {
                    type_errors.push(ValidationError::non_lit_ext_constructor(
                        ext_expr.source_loc().cloned(),
                        self.policy_id.clone(),
                    ));
                    failed = true;
                }

                if failed {
                    match typed_arg_exprs(type_errors) {
                        Some(exprs) => TypecheckAnswer::fail(
                            ExprBuilder::with_data(Some(ret_ty.clone()))
                                .with_same_source_loc(ext_expr)
                                .call_extension_fn(fn_name.clone(), exprs),
                        ),
                        None => TypecheckAnswer::RecursionLimit,
                    }
                } else {
                    let typechecked_args = args
                        .as_ref()
                        .iter()
                        .zip_longest(arg_tys)
                        .map(|item| match item {
                            Both(arg, ty) => (arg, ty),
                            // PANIC SAFETY: only variadic functions can have more arguments than argument types, and by construction
                            // PANIC SAFETY: variadic functions have at least 2 argument types. See [`crate::crate::ast::ExtensionFunction::variadic`]
                            #[allow(clippy::unwrap_used)]
                            Left(arg) => (arg, arg_tys.last().unwrap()),
                            // PANIC SAFETY
                            #[allow(clippy::unreachable)]
                            Right(_ty) => {
                                unreachable!("Previous checks ensure args.len() >= arg_tys.len()")
                            }
                        })
                        .map(|(arg, ty)| {
                            self.expect_type(prior_capability, arg, ty.clone(), type_errors, |_| {
                                None
                            })
                        });
                    TypecheckAnswer::sequence_all_then_typecheck(
                        typechecked_args,
                        |arg_exprs_capabilities| {
                            let (typed_arg_exprs, _): (Vec<Expr<Option<Type>>>, Vec<_>) =
                                arg_exprs_capabilities.into_iter().unzip();
                            TypecheckAnswer::success(
                                ExprBuilder::with_data(Some(ret_ty.clone()))
                                    .with_same_source_loc(ext_expr)
                                    .call_extension_fn(fn_name.clone(), typed_arg_exprs),
                            )
                        },
                    )
                }
            }
            Err(typ_err) => {
                type_errors.push(typ_err);
                match typed_arg_exprs(type_errors) {
                    Some(typed_args) => TypecheckAnswer::fail(
                        ExprBuilder::with_data(None)
                            .with_same_source_loc(ext_expr)
                            .call_extension_fn(fn_name.clone(), typed_args),
                    ),
                    None => TypecheckAnswer::RecursionLimit,
                }
            }
        }
    }
}
