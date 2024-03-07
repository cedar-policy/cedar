/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

mod test_expr;
mod test_extensions;
mod test_namespace;
mod test_optional_attributes;
mod test_partial;
mod test_policy;
mod test_strict;
mod test_type_annotation;
mod test_unspecified_entity;
mod test_utils;

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    iter::zip,
};

use crate::{
    extension_schema::{ExtensionFunctionType, ExtensionSchema},
    extensions::all_available_extension_schemas,
    fuzzy_match::fuzzy_search,
    schema::{is_action_entity_type, ValidatorSchema},
    types::{
        AttributeType, Effect, EffectSet, EntityRecordKind, OpenTag, Primitive, RequestEnv, Type,
    },
    AttributeAccess, UnexpectedTypeHelp, ValidationMode,
};

use super::type_error::TypeError;

use cedar_policy_core::ast::{
    BinaryOp, EntityType, EntityUID, Expr, ExprBuilder, ExprKind, Literal, Name,
    PrincipalOrResourceConstraint, SlotId, Template, UnaryOp, Var,
};
use itertools::Itertools;

const REQUIRED_STACK_SPACE: usize = 1024 * 100;

/// TypecheckAnswer holds the result of typechecking an expression.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum TypecheckAnswer<'a> {
    /// Typechecking succeeded, and we know the type and a possibly empty effect
    /// set for the expression. The effect set is the set of
    /// (expression, attribute) pairs that are known as safe to access under the
    /// assumption that the expression evaluates to true.
    TypecheckSuccess {
        expr_type: Expr<Option<Type>>,
        expr_effect: EffectSet<'a>,
    },
    /// Typechecking failed. We might still be able to know the type of the
    /// overall expression, but not always. For instance, an `&&` expression
    /// will always have type `boolean`, so we populate `expr_recovery_type`
    /// with `Some(boolean)` even when there is a type error in the expression.
    TypecheckFail {
        expr_recovery_type: Expr<Option<Type>>,
    },

    /// RecursionLimit Reached
    RecursionLimit,
}

impl<'a> TypecheckAnswer<'a> {
    /// Construct a successful TypecheckAnswer with a type but with an empty
    /// effect set.
    pub fn success(expr_type: Expr<Option<Type>>) -> Self {
        Self::TypecheckSuccess {
            expr_type,
            expr_effect: EffectSet::new(),
        }
    }

    /// Construct a successful TypecheckAnswer with a type and an effect.
    pub fn success_with_effect(expr_type: Expr<Option<Type>>, expr_effect: EffectSet<'a>) -> Self {
        Self::TypecheckSuccess {
            expr_type,
            expr_effect,
        }
    }

    /// Construct a failing TypecheckAnswer with a type.
    pub fn fail(expr_type: Expr<Option<Type>>) -> Self {
        Self::TypecheckFail {
            expr_recovery_type: expr_type,
        }
    }

    /// Check if this TypecheckAnswer contains a particular type. It
    /// contains a type if the type annotated AST contains `Some`
    /// of the argument type at its root.
    pub fn contains_type(&self, ty: &Type) -> bool {
        match self {
            TypecheckAnswer::TypecheckSuccess { expr_type, .. } => Some(expr_type),
            TypecheckAnswer::TypecheckFail { expr_recovery_type } => Some(expr_recovery_type),
            TypecheckAnswer::RecursionLimit => None,
        }
        .and_then(|e| e.data().as_ref())
            == Some(ty)
    }

    pub fn into_typed_expr(self) -> Option<Expr<Option<Type>>> {
        match self {
            TypecheckAnswer::TypecheckSuccess { expr_type, .. } => Some(expr_type),
            TypecheckAnswer::TypecheckFail { expr_recovery_type } => Some(expr_recovery_type),
            TypecheckAnswer::RecursionLimit => None,
        }
    }

    /// Return true if this represents successful typechecking.
    pub fn typechecked(&self) -> bool {
        match self {
            TypecheckAnswer::TypecheckSuccess { .. } => true,
            TypecheckAnswer::TypecheckFail { .. } => false,
            TypecheckAnswer::RecursionLimit => false,
        }
    }

    /// Transform the effect of this TypecheckAnswer without modifying the
    /// success or type.
    pub fn map_effect<F>(self, f: F) -> Self
    where
        F: FnOnce(EffectSet<'a>) -> EffectSet<'a>,
    {
        match self {
            TypecheckAnswer::TypecheckSuccess {
                expr_type,
                expr_effect,
            } => TypecheckAnswer::TypecheckSuccess {
                expr_type,
                expr_effect: f(expr_effect),
            },
            TypecheckAnswer::TypecheckFail { .. } => self,
            TypecheckAnswer::RecursionLimit => self,
        }
    }

    /// Convert this TypecheckAnswer into an equivalent answer for an expression
    /// that has failed to typecheck. If this is already TypecheckFail, then no
    /// change is required, otherwise, a TypecheckFail is constructed containing
    /// `Some` of the `expr_type`.
    pub fn into_fail(self) -> Self {
        match self {
            TypecheckAnswer::TypecheckSuccess { expr_type, .. } => TypecheckAnswer::fail(expr_type),
            TypecheckAnswer::TypecheckFail { .. } => self,
            TypecheckAnswer::RecursionLimit => self,
        }
    }

    /// Sequence another typechecking operation after this answer. The result of
    /// the operation will be adjusted to be a TypecheckFail if this is a
    /// TypecheckFail, otherwise it will be returned unaltered.
    pub fn then_typecheck<F>(self, f: F) -> Self
    where
        F: FnOnce(Expr<Option<Type>>, EffectSet<'a>) -> TypecheckAnswer<'a>,
    {
        match self {
            TypecheckAnswer::TypecheckSuccess {
                expr_type,
                expr_effect,
            } => f(expr_type, expr_effect),
            TypecheckAnswer::TypecheckFail { expr_recovery_type } => {
                f(expr_recovery_type, EffectSet::new()).into_fail()
            }
            TypecheckAnswer::RecursionLimit => self,
        }
    }

    /// Sequence another typechecking operation after all of the typechecking
    /// answers in the argument. The result of the operation is adjusted in the
    /// same manner as in `then_typecheck`, but accounts for the all the
    /// TypecheckAnswers.
    pub fn sequence_all_then_typecheck<F>(
        answers: impl IntoIterator<Item = TypecheckAnswer<'a>>,
        f: F,
    ) -> TypecheckAnswer<'a>
    where
        F: FnOnce(Vec<(Expr<Option<Type>>, EffectSet<'a>)>) -> TypecheckAnswer<'a>,
    {
        let mut unwrapped = Vec::new();
        let mut any_failed = false;
        let mut recusion_limit_reached = false;
        for ans in answers {
            any_failed |= !ans.typechecked();
            unwrapped.push(match ans {
                TypecheckAnswer::TypecheckSuccess {
                    expr_type,
                    expr_effect,
                } => (expr_type, expr_effect),
                TypecheckAnswer::TypecheckFail { expr_recovery_type } => {
                    (expr_recovery_type, EffectSet::new())
                }
                TypecheckAnswer::RecursionLimit => {
                    recusion_limit_reached = true;
                    break;
                }
            });
        }

        let ans = f(unwrapped);
        if recusion_limit_reached {
            TypecheckAnswer::RecursionLimit
        } else if any_failed {
            ans.into_fail()
        } else {
            ans
        }
    }
}

/// Basic result for typechecking
#[derive(Debug)]
pub enum PolicyCheck {
    /// Policy will evaluate to a bool
    Success(Expr<Option<Type>>),
    /// Policy will always evaluate to false, and may have errors
    Irrelevant(Vec<TypeError>),
    /// Policy will have errors
    Fail(Vec<TypeError>),
}

/// This structure implements typechecking for Cedar policies through the
/// entry point `typecheck_policy`.
#[derive(Debug)]
pub struct Typechecker<'a> {
    schema: &'a ValidatorSchema,
    extensions: HashMap<Name, ExtensionSchema>,
    mode: ValidationMode,
}

impl<'a> Typechecker<'a> {
    /// Construct a new typechecker.
    pub fn new(schema: &'a ValidatorSchema, mode: ValidationMode) -> Typechecker<'a> {
        // Set the extensions using `all_available_extension_schemas`.
        let extensions = all_available_extension_schemas()
            .into_iter()
            .map(|ext| (ext.name().clone(), ext))
            .collect();
        Self {
            schema,
            extensions,
            mode,
        }
    }

    /// The main entry point for typechecking policies. This method takes a
    /// policy and a mutable `Vec` used to output type errors. Typechecking
    /// ensures that the policy expression has type boolean. If typechecking
    /// succeeds, then the method will return true, and no items will be
    /// added to the output list. Otherwise, the function returns false and the
    /// output list is populated with any errors encountered while typechecking.
    pub fn typecheck_policy(&self, t: &Template, type_errors: &mut HashSet<TypeError>) -> bool {
        let typecheck_answers = self.typecheck_by_request_env(t);

        // consolidate the results from each query environment
        let (all_false, all_succ) = typecheck_answers.into_iter().fold(
            (true, true),
            |(all_false, all_succ), (_, check)| match check {
                PolicyCheck::Success(_) => (false, all_succ),
                PolicyCheck::Irrelevant(err) => {
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
            type_errors.insert(TypeError::impossible_policy(t.condition()));
            false
        } else {
            all_succ
        }
    }

    /// Secondary entry point for typechecking requests. This method takes a policy and
    /// typechecks it under every schema-defined request environment. The result contains
    /// these environments and the individual typechecking response for each, in no
    /// particular order.
    pub fn typecheck_by_request_env<'b>(
        &'b self,
        t: &'b Template,
    ) -> Vec<(RequestEnv, PolicyCheck)> {
        self.apply_typecheck_fn_by_request_env(t, |request, expr| {
            let mut type_errors = Vec::new();
            let empty_prior_eff = EffectSet::new();
            let ty = self.expect_type(
                request,
                &empty_prior_eff,
                expr,
                Type::primitive_boolean(),
                &mut type_errors,
                |_| None,
            );

            let is_false = ty.contains_type(&Type::singleton_boolean(false));
            match (is_false, ty.typechecked(), ty.into_typed_expr()) {
                (false, true, None) => PolicyCheck::Fail(type_errors),
                (false, true, Some(e)) => PolicyCheck::Success(e),
                (false, false, _) => PolicyCheck::Fail(type_errors),
                (true, _, _) => PolicyCheck::Irrelevant(type_errors),
            }
        })
    }

    /// Utility abstracting the common logic for strict and regular typechecking
    /// by request environment.
    fn apply_typecheck_fn_by_request_env<'b, F, C>(
        &'b self,
        t: &'b Template,
        typecheck_fn: F,
    ) -> Vec<(RequestEnv, C)>
    where
        F: Fn(&RequestEnv, &Expr) -> C,
    {
        let mut result_checks = Vec::new();

        // Validate each (principal, resource) pair with the substituted policy
        // for the corresponding action. Implemented as for loop to make it
        // explicit that `expect_type` will be called for every element of
        // request_env without short circuiting.
        let policy_condition = &t.condition();
        for requeste in self
            .unlinked_request_envs()
            .flat_map(|env| self.link_request_env(env, t))
        {
            let check = typecheck_fn(&requeste, policy_condition);
            result_checks.push((requeste, check))
        }
        result_checks
    }

    /// Additional entry point for typechecking requests. This method takes a slice
    /// over policies and typechecks each under every schema-defined request environment.
    ///
    /// The result contains these environments in no particular order, but each list of
    /// policy checks will always match the original order.
    pub fn multi_typecheck_by_request_env(
        &self,
        policy_templates: &[&Template],
    ) -> Vec<(RequestEnv, Vec<PolicyCheck>)> {
        let mut env_checks = Vec::new();
        for request in self.unlinked_request_envs() {
            let mut policy_checks = Vec::new();
            for t in policy_templates.iter() {
                let condition_expr = t.condition();
                for linked_env in self.link_request_env(request.clone(), t) {
                    let mut type_errors = Vec::new();
                    let empty_prior_eff = EffectSet::new();
                    let ty = self.expect_type(
                        &linked_env,
                        &empty_prior_eff,
                        &condition_expr,
                        Type::primitive_boolean(),
                        &mut type_errors,
                        |_| None,
                    );

                    let is_false = ty.contains_type(&Type::singleton_boolean(false));
                    match (is_false, ty.typechecked(), ty.into_typed_expr()) {
                        (false, true, None) => policy_checks.push(PolicyCheck::Fail(type_errors)),
                        (false, true, Some(e)) => policy_checks.push(PolicyCheck::Success(e)),
                        (false, false, _) => policy_checks.push(PolicyCheck::Fail(type_errors)),
                        (true, _, _) => policy_checks.push(PolicyCheck::Irrelevant(type_errors)),
                    }
                }
            }
            env_checks.push((request, policy_checks));
        }
        env_checks
    }

    fn unlinked_request_envs(&self) -> impl Iterator<Item = RequestEnv> + '_ {
        // Gather all of the actions declared in the schema.
        let all_actions = self
            .schema
            .known_action_ids()
            .filter_map(|a| self.schema.get_action_id(a));

        // For every action compute the cross product of the principal and
        // resource applies_to sets.
        all_actions
            .flat_map(|action| {
                action
                    .applies_to
                    .applicable_principal_types()
                    .flat_map(|principal| {
                        action
                            .applies_to
                            .applicable_resource_types()
                            .map(|resource| RequestEnv::DeclaredAction {
                                principal,
                                action: &action.name,
                                resource,
                                context: &action.context,
                                principal_slot: None,
                                resource_slot: None,
                            })
                    })
            })
            .chain(if self.mode.is_partial() {
                // A partial schema might not list all actions, and may not
                // include all principal and resource types for the listed ones.
                // So we typecheck with a fully unknown request to handle these
                // missing cases.
                Some(RequestEnv::UndeclaredAction)
            } else {
                None
            })
    }

    /// Given a request environment and a template, return new environments
    /// formed by instantiating template slots with possible entity types.
    fn link_request_env<'b>(
        &'b self,
        env: RequestEnv<'b>,
        t: &'b Template,
    ) -> Box<dyn Iterator<Item = RequestEnv> + 'b> {
        match env {
            RequestEnv::UndeclaredAction => Box::new(std::iter::once(RequestEnv::UndeclaredAction)),
            RequestEnv::DeclaredAction {
                principal,
                action,
                resource,
                context,
                ..
            } => Box::new(
                self.possible_slot_instantiations(
                    t,
                    SlotId::principal(),
                    principal,
                    t.principal_constraint().as_inner(),
                )
                .flat_map(move |p_slot| {
                    self.possible_slot_instantiations(
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
                        resource_slot: r_slot.clone(),
                    })
                }),
            ),
        }
    }

    /// Get the entity types which could instantiate the slot given in this
    /// template based on the policy scope constraints. We use this function to
    /// avoid typechecking with slot bindings that will always be false based
    /// only on the scope constraints.
    fn possible_slot_instantiations(
        &self,
        t: &Template,
        slot_id: SlotId,
        var: &'a EntityType,
        constraint: &PrincipalOrResourceConstraint,
    ) -> Box<dyn Iterator<Item = Option<EntityType>> + 'a> {
        if t.slots().contains(&slot_id) {
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
                        .filter(|(_, ety)| ety.has_descendant_entity_type(var))
                        .map(|(name, _)| Some(EntityType::Specified(name.clone())))
                        .chain(std::iter::once(Some(var.clone()))),
                ),
                // The template uses the slot, but without a scope constraint.
                // This can't happen for the moment because slots may only
                // appear in scope constraints, but if we ever see this, then the
                // only correct way to proceed is by returning all entity types
                // as possible instantiations.
                PrincipalOrResourceConstraint::Is(_) | PrincipalOrResourceConstraint::Any => {
                    Box::new(
                        all_entity_types.map(|(name, _)| Some(EntityType::Specified(name.clone()))),
                    )
                }
            }
        } else {
            // If the template does not contain this slot, then we don't need to
            // consider its instantiations..
            Box::new(std::iter::once(None))
        }
    }

    /// This method handles the majority of the work. Given an expression,
    /// the type for the request, and the a prior effect context for the
    /// expression, return the result of typechecking the expression, and add
    /// any errors encountered into the type_errors list. The result of
    /// typechecking contains the type of the expression, any current effect of
    /// the expression, and a flag indicating whether the expression
    /// successfully typechecked.
    fn typecheck<'b>(
        &self,
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        e: &'b Expr,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
        #[cfg(not(target_arch = "wasm32"))]
        if stacker::remaining_stack().unwrap_or(0) < REQUIRED_STACK_SPACE {
            return TypecheckAnswer::RecursionLimit;
        }

        match e.expr_kind() {
            // Principal, resource, and context have types defined by
            // the request type.
            ExprKind::Var(Var::Principal) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(request_env.principal_type()))
                    .with_same_source_loc(e)
                    .var(Var::Principal),
            ),
            // While the EntityUID for Action is held in the request context,
            // entity types do not consider the id of the entity (only the
            // entity type), so the type of Action is only the entity type name
            // taken from the euid.
            ExprKind::Var(Var::Action) => {
                match request_env.action_type(self.schema) {
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
                ExprBuilder::with_data(Some(request_env.resource_type()))
                    .with_same_source_loc(e)
                    .var(Var::Resource),
            ),
            ExprKind::Var(Var::Context) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(request_env.context_type()))
                    .with_same_source_loc(e)
                    .var(Var::Context),
            ),
            ExprKind::Unknown(u) => {
                TypecheckAnswer::fail(ExprBuilder::with_data(None).unknown(u.clone()))
            }
            // Template Slots, always has to be an entity.
            ExprKind::Slot(slotid) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(if slotid.is_principal() {
                    request_env
                        .principal_slot()
                        .clone()
                        .map(Type::possibly_unspecified_entity_reference)
                        .unwrap_or(Type::any_entity_reference())
                } else if slotid.is_resource() {
                    request_env
                        .resource_slot()
                        .clone()
                        .map(Type::possibly_unspecified_entity_reference)
                        .unwrap_or(Type::any_entity_reference())
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
                // detected by a different part of the validator, so a TypeError is
                // not generated here. We still return `TypecheckFail` so that
                // typechecking is not considered successful.
                match Type::euid_literal((**euid).clone(), self.schema) {
                    // The entity type is undeclared, but that's OK for a
                    // partial schema. The attributes record will be empty if we
                    // try to access it later, so all attributes will have the
                    // bottom type.
                    None if self.mode.is_partial() => TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(Type::possibly_unspecified_entity_reference(
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
                    request_env,
                    prior_eff,
                    test_expr,
                    Type::primitive_boolean(),
                    type_errors,
                    |_| None,
                );
                ans_test.then_typecheck(|typ_test, eff_test| {
                    // If the guard has type `true` or `false`, we short circuit,
                    // looking at only the relevant branch.
                    if typ_test.data() == &Some(Type::singleton_boolean(true)) {
                        // The `then` branch needs to be typechecked using the
                        // prior effect of the `if` and any new effect generated
                        // by `test`. This enables an attribute access
                        // `principal.foo` after a condition `principal has foo`.
                        let ans_then = self.typecheck(
                            request_env,
                            &prior_eff.union(&eff_test),
                            then_expr,
                            type_errors,
                        );

                        ans_then.then_typecheck(|typ_then, eff_then| {
                            TypecheckAnswer::success_with_effect(
                                typ_then,
                                // The output effect of the whole `if` expression also
                                // needs to contain the effect of the condition.
                                eff_then.union(&eff_test),
                            )
                        })
                    } else if typ_test.data() == &Some(Type::singleton_boolean(false)) {
                        // The `else` branch cannot use the `test` effect since
                        // we know in the `else` branch that the condition
                        // evaluated to `false`. It still can use the original
                        // prior effect.
                        let ans_else =
                            self.typecheck(request_env, prior_eff, else_expr, type_errors);

                        ans_else.then_typecheck(|typ_else, eff_else| {
                            TypecheckAnswer::success_with_effect(typ_else, eff_else)
                        })
                    } else {
                        // When we don't short circuit, the `then` and `else`
                        // branches are individually typechecked with the same
                        // prior effects are in their individual cases.
                        let ans_then = self
                            .typecheck(
                                request_env,
                                &prior_eff.union(&eff_test),
                                then_expr,
                                type_errors,
                            )
                            .map_effect(|ef| ef.union(&eff_test));
                        let ans_else =
                            self.typecheck(request_env, prior_eff, else_expr, type_errors);
                        // The type of the if expression is then the least
                        // upper bound of the types of the then and else
                        // branches.  If either of these fails to typecheck, the
                        // other is still be typechecked to detect errors that
                        // may exist in that branch. This failure, in addition
                        // to any failure that may have occurred in the test
                        // expression, will propagate to final TypecheckAnswer.
                        ans_then.then_typecheck(|typ_then, eff_then| {
                            ans_else.then_typecheck(|typ_else, eff_else| {
                                let lub_ty = self.least_upper_bound_or_error(
                                    e,
                                    vec![typ_then.data().clone(), typ_else.data().clone()],
                                    type_errors,
                                );
                                let has_lub = lub_ty.is_some();
                                let annot_expr = ExprBuilder::with_data(lub_ty)
                                    .with_same_source_loc(e)
                                    .ite(typ_test, typ_then, typ_else);
                                if has_lub {
                                    // Effect is not handled in the LUB computation,
                                    // so we need to compute the effect here. When
                                    // the `||` evaluates to `true`, we know that
                                    // one operand evaluated to true, but we don't
                                    // know which. This is handled by returning an
                                    // effect set that is the intersection of the
                                    // operand effect sets.
                                    TypecheckAnswer::success_with_effect(
                                        annot_expr,
                                        eff_else.intersect(&eff_then),
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
                    request_env,
                    prior_eff,
                    left,
                    Type::primitive_boolean(),
                    type_errors,
                    |_| None,
                );
                ans_left.then_typecheck(|typ_left, eff_left| {
                    match typ_left.data() {
                        // First argument is false, so short circuit the `&&` to
                        // false _without_ typechecking the second argument.
                        // Since the type of the `&&` is `false`, it is known to
                        // always evaluate to `false` at run time. The `&&`
                        // expression typechecks with an empty effect rather
                        // than the effect of the lhs.
                        // The right operand is not typechecked, so it is not
                        // included in the type annotated AST.
                        Some(Type::False) => TypecheckAnswer::success(typ_left),
                        _ => {
                            // Similar to the `then` branch of an `if`
                            // expression, the rhs of an `&&` is typechecked
                            // using an updated prior effect that includes
                            // effect learned from the lhs to enable
                            // typechecking expressions like
                            // `principal has foo && principal.foo`. This is
                            // valid because `&&` short circuits at run time, so
                            // the right will only be evaluated after the left
                            // evaluated to `true`.
                            let ans_right = self.expect_type(
                                request_env,
                                &prior_eff.union(&eff_left),
                                right,
                                Type::primitive_boolean(),
                                type_errors,
                                |_| None,
                            );
                            ans_right.then_typecheck(|typ_right, eff_right| {
                                match (typ_left.data(), typ_right.data()) {
                                    // The second argument is false, so the `&&`
                                    // is false. The effect is empty for the
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
                                    // effect of the `&&` is the union of the
                                    // lhs and rhs because both operands must be
                                    // true for the whole `&&` to be true.
                                    (Some(_), Some(Type::True)) => {
                                        TypecheckAnswer::success_with_effect(
                                            ExprBuilder::with_data(typ_left.data().clone())
                                                .with_same_source_loc(e)
                                                .and(typ_left, typ_right),
                                            eff_left.union(&eff_right),
                                        )
                                    }
                                    (Some(Type::True), Some(_)) => {
                                        TypecheckAnswer::success_with_effect(
                                            ExprBuilder::with_data(typ_right.data().clone())
                                                .with_same_source_loc(e)
                                                .and(typ_left, typ_right),
                                            eff_right.union(&eff_right),
                                        )
                                    }

                                    // Neither argument was true or false, so we only
                                    // know the result type is boolean.
                                    (Some(_), Some(_)) => TypecheckAnswer::success_with_effect(
                                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                            .with_same_source_loc(e)
                                            .and(typ_left, typ_right),
                                        eff_left.union(&eff_right),
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
            // effect propagation adjusted as necessary.
            ExprKind::Or { left, right } => {
                let ans_left = self.expect_type(
                    request_env,
                    prior_eff,
                    left,
                    Type::primitive_boolean(),
                    type_errors,
                    |_| None,
                );
                ans_left.then_typecheck(|ty_expr_left, eff_left| match ty_expr_left.data() {
                    // Contrary to `&&` where short circuiting did not permit
                    // any effect, an effect can be maintained when short
                    // circuiting `||`. We know the left operand is `true`, so
                    // its effect is maintained. The right operand is not
                    // evaluated, so its effect does not need to be considered.
                    // The right operand is not typechecked, so it is not
                    // included in the type annotated AST.
                    Some(Type::True) => TypecheckAnswer::success(ty_expr_left),
                    _ => {
                        // The right operand of an `||` cannot be typechecked
                        // using the effect learned from the left because the
                        // left could have evaluated to either `true` or `false`
                        // when the left is evaluated.
                        let ans_right = self.expect_type(
                            request_env,
                            prior_eff,
                            right,
                            Type::primitive_boolean(),
                            type_errors,
                            |_| None,
                        );
                        ans_right.then_typecheck(|ty_expr_right, eff_right| {
                            match (ty_expr_left.data(), ty_expr_right.data()) {
                                // Now the right operand is always `true`, so we can
                                // use its effect as the result effect. The left
                                // operand might have been `true` of `false`, but it
                                // does not affect the value of the `||` if the
                                // right is always `true`.
                                (Some(_), Some(Type::True)) => {
                                    TypecheckAnswer::success_with_effect(
                                        ExprBuilder::with_data(Some(Type::True))
                                            .with_same_source_loc(e)
                                            .or(ty_expr_left, ty_expr_right),
                                        eff_right,
                                    )
                                }
                                // If the right or left operand is always `false`,
                                // then the only way the `||` expression can be
                                // `true` is if the other operand is `true`. This
                                // lets us pass the effect of the other operand
                                // through to the effect of the `||`.
                                (Some(typ_left), Some(Type::False)) => {
                                    TypecheckAnswer::success_with_effect(
                                        ExprBuilder::with_data(Some(typ_left.clone()))
                                            .with_same_source_loc(e)
                                            .or(ty_expr_left, ty_expr_right),
                                        eff_left,
                                    )
                                }
                                (Some(Type::False), Some(typ_right)) => {
                                    TypecheckAnswer::success_with_effect(
                                        ExprBuilder::with_data(Some(typ_right.clone()))
                                            .with_same_source_loc(e)
                                            .or(ty_expr_left, ty_expr_right),
                                        eff_right,
                                    )
                                }
                                // When neither has a constant value, the `||`
                                // evaluates to true if one or both is `true`. This
                                // means we can only keep effects in the
                                // intersection of their effect sets.
                                (Some(_), Some(_)) => TypecheckAnswer::success_with_effect(
                                    ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                        .with_same_source_loc(e)
                                        .or(ty_expr_left, ty_expr_right),
                                    eff_right.intersect(&eff_left),
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
                self.typecheck_unary(request_env, prior_eff, e, type_errors)
            }
            ExprKind::BinaryApp { .. } => {
                // INVARIANT: typecheck_binary requires a `BinaryApp`, we've just ensured this
                self.typecheck_binary(request_env, prior_eff, e, type_errors)
            }
            ExprKind::MulByConst { .. } => {
                // INVARIANT: typecheck_mul requires a `MulByConst`, we've just ensured this
                self.typecheck_mul(request_env, prior_eff, e, type_errors)
            }
            ExprKind::ExtensionFunctionApp { .. } => {
                // INVARIANT: typecheck_extension requires a `ExtensionFunctionApp`, we've just ensured this
                self.typecheck_extension(request_env, prior_eff, e, type_errors)
            }

            ExprKind::GetAttr { expr, attr } => {
                // Accessing an attribute requires either an entity or a record
                // that has the attribute.
                let actual = self.expect_one_of_types(
                    request_env,
                    prior_eff,
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
                                // prior effect set (the current expression is
                                // guarded by a condition that will only
                                // evaluate to `true` when the attribute is
                                // present).
                                if ty.is_required || prior_eff.contains(&Effect::new(expr, attr)) {
                                    TypecheckAnswer::success(annot_expr)
                                } else {
                                    type_errors.push(TypeError::unsafe_optional_attribute_access(
                                        e.clone(),
                                        AttributeAccess::from_expr(request_env, &annot_expr),
                                    ));
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
                                type_errors.push(TypeError::unsafe_attribute_access(
                                    e.clone(),
                                    AttributeAccess::from_expr(request_env, &annot_expr),
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
                    request_env,
                    prior_eff,
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
                                attr_type: _,
                                is_required: true,
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
                                // access of the expression is already in the prior effect,
                                // which means the entity must exist.
                                let in_prior_effs = prior_eff.contains(&Effect::new(expr, attr));
                                let type_of_has = if exists_in_store || in_prior_effs {
                                    Type::singleton_boolean(true)
                                } else {
                                    Type::primitive_boolean()
                                };
                                TypecheckAnswer::success_with_effect(
                                    ExprBuilder::with_data(Some(type_of_has))
                                        .with_same_source_loc(e)
                                        .has_attr(typ_expr_actual, attr.clone()),
                                    EffectSet::singleton(Effect::new(expr, attr)),
                                )
                            }
                            // This is where effect information is generated. If
                            // the `HasAttr` for an optional attribute evaluates
                            // to `true`, then we know that it is safe to access
                            // that attribute, so we add an entry to the effect
                            // set.
                            Some(AttributeType {
                                attr_type: _,
                                is_required: false,
                            }) => TypecheckAnswer::success_with_effect(
                                ExprBuilder::with_data(Some(
                                    // The optional attribute `HasAttr` can have
                                    // type `true` if it occurs after the attribute
                                    // access of the expression is already in the
                                    // prior effect.
                                    if prior_eff.contains(&Effect::new(expr, attr)) {
                                        Type::singleton_boolean(true)
                                    } else {
                                        Type::primitive_boolean()
                                    },
                                ))
                                .with_same_source_loc(e)
                                .has_attr(typ_expr_actual, attr.clone()),
                                EffectSet::singleton(Effect::new(expr, attr)),
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
                    request_env,
                    prior_eff,
                    expr,
                    Type::primitive_string(),
                    type_errors,
                    |actual| match actual {
                        Type::EntityOrRecord(
                            EntityRecordKind::AnyEntity
                            | EntityRecordKind::Entity(_)
                            | EntityRecordKind::ActionEntity { .. },
                        ) => Some(UnexpectedTypeHelp::TryUsingIs),
                        _ => None,
                    },
                );
                actual.then_typecheck(|actual_expr_ty, _| {
                    TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                            .with_same_source_loc(e)
                            // FIXME: `pattern` contains an `Arc<Vec<...>>` that
                            // could be cloned cheap, but this reallocated the
                            // pattern vec. Need a different constructor.
                            .like(actual_expr_ty, pattern.iter().cloned()),
                    )
                })
            }

            ExprKind::Is { expr, entity_type } => {
                self.expect_type(
                    request_env,
                    prior_eff,
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
                        Some(Type::EntityOrRecord(EntityRecordKind::ActionEntity {
                            name, ..
                        })) => {
                            let type_of_is = if name == entity_type {
                                // The actual action entity type is exactly the entity type we're
                                // testing for with `is`, so the expression is always `true`
                                Type::singleton_boolean(true)
                            } else {
                                // The actual action entity type is not the entity type
                                // we're testing for, so the `is` will always be `false`
                                Type::singleton_boolean(false)
                            };

                            TypecheckAnswer::success(
                                ExprBuilder::with_data(Some(type_of_is))
                                    .with_same_source_loc(e)
                                    .is_entity_type(expr_ty, entity_type.clone()),
                            )
                        }
                        // For `AnyEntity` we don't know anything about what
                        // entity type it could be, so we just return `Bool`.
                        Some(Type::EntityOrRecord(EntityRecordKind::AnyEntity { .. })) => {
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
                    .map(|elem| self.typecheck(request_env, prior_eff, elem, type_errors))
                    .collect::<Vec<_>>();

                // If we cannot compute a least upper bound for the element
                // types, then a type error will be generated by
                // `least_upper_bound_or_error` and TypecheckFail will be
                // returned. It will also return TypecheckFail if any of the
                // individual element failed to typecheck (were TypecheckFail).
                TypecheckAnswer::sequence_all_then_typecheck(elem_types, |elem_types_and_effects| {
                    let (elem_expr_types, _): (Vec<Expr<Option<Type>>>, Vec<_>) =
                        elem_types_and_effects.into_iter().unzip();
                    let elem_lub = self.least_upper_bound_or_error(
                        e,
                        elem_expr_types.iter().map(|ety| ety.data().clone()),
                        type_errors,
                    );
                    match elem_lub {
                        _ if self.mode.is_strict() && exprs.is_empty() => {
                            type_errors.push(TypeError::empty_set_forbidden(e.clone()));
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
                    .map(|value| self.typecheck(request_env, prior_eff, value, type_errors));
                // This will cause the return value to be `TypecheckFail` if any
                // of the attributes did not typecheck.
                TypecheckAnswer::sequence_all_then_typecheck(
                    record_attr_tys,
                    |record_attr_tys_and_effects| {
                        let (record_attr_expr_tys, _): (Vec<Expr<Option<Type>>>, Vec<_>) =
                            record_attr_tys_and_effects.into_iter().unzip();
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
        }
    }

    /// A utility called by the main typecheck method to handle binary operator
    /// application.
    /// INVARIANT: `bin_expr` must be a `BinaryApp`
    fn typecheck_binary<'b>(
        &self,
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        bin_expr: &'b Expr,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
        // PANIC SAFETY: maintained by invariant on this function
        #[allow(clippy::panic)]
        let ExprKind::BinaryApp { op, arg1, arg2 } = bin_expr.expr_kind() else {
            panic!("`typecheck_binary` called with an expression kind other than `BinaryApp`");
        };

        match op {
            // The arguments to `==` may typecheck with any type, but we will
            // return false if the types are disjoint.
            BinaryOp::Eq => {
                let lhs_ty = self.typecheck(request_env, prior_eff, arg1, type_errors);
                let rhs_ty = self.typecheck(request_env, prior_eff, arg2, type_errors);
                lhs_ty.then_typecheck(|lhs_ty, _| {
                    rhs_ty.then_typecheck(|rhs_ty, _| {
                        let type_of_eq = self.type_of_equality(
                            request_env,
                            arg1,
                            lhs_ty.data(),
                            arg2,
                            rhs_ty.data(),
                        );

                        if self.mode.is_strict() {
                            let annotated_eq = ExprBuilder::with_data(Some(type_of_eq))
                                .with_same_source_loc(bin_expr)
                                .binary_app(*op, lhs_ty.clone(), rhs_ty.clone());
                            self.enforce_strict_equality(
                                bin_expr,
                                annotated_eq,
                                lhs_ty.data(),
                                rhs_ty.data(),
                                type_errors,
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
                let ans_arg1 = self.expect_type(
                    request_env,
                    prior_eff,
                    arg1,
                    Type::primitive_long(),
                    type_errors,
                    |_| None,
                );
                ans_arg1.then_typecheck(|expr_ty_arg1, _| {
                    let ans_arg2 = self.expect_type(
                        request_env,
                        prior_eff,
                        arg2,
                        Type::primitive_long(),
                        type_errors,
                        |_| None,
                    );
                    ans_arg2.then_typecheck(|expr_ty_arg2, _| {
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                .with_same_source_loc(bin_expr)
                                .binary_app(*op, expr_ty_arg1, expr_ty_arg2),
                        )
                    })
                })
            }

            BinaryOp::Add | BinaryOp::Sub => {
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
                    request_env,
                    prior_eff,
                    arg1,
                    Type::primitive_long(),
                    type_errors,
                    help_builder,
                );
                ans_arg1.then_typecheck(|expr_ty_arg1, _| {
                    let ans_arg2 = self.expect_type(
                        request_env,
                        prior_eff,
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

            BinaryOp::In => {
                self.typecheck_in(request_env, prior_eff, bin_expr, arg1, arg2, type_errors)
            }

            BinaryOp::Contains => {
                // The first argument must be a set.
                self.expect_type(
                    request_env,
                    prior_eff,
                    arg1,
                    Type::any_set(),
                    type_errors,
                    |actual| match actual {
                        Type::EntityOrRecord(
                            EntityRecordKind::AnyEntity
                            | EntityRecordKind::Entity(_)
                            | EntityRecordKind::ActionEntity { .. },
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
                    self.typecheck(request_env, prior_eff, arg2, type_errors)
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
                                    &match expr_ty_arg1.data() {
                                        Some(Type::Set {
                                            element_type: Some(ty),
                                        }) => Some(*ty.clone()),
                                        _ => None,
                                    },
                                    expr_ty_arg2.data(),
                                    type_errors,
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
                    request_env,
                    prior_eff,
                    arg1,
                    Type::any_set(),
                    type_errors,
                    |actual| match actual {
                        Type::EntityOrRecord(
                            EntityRecordKind::AnyEntity
                            | EntityRecordKind::Entity(_)
                            | EntityRecordKind::ActionEntity { .. },
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
                    self.expect_type(
                        request_env,
                        prior_eff,
                        arg2,
                        Type::any_set(),
                        type_errors,
                        |_| Some(UnexpectedTypeHelp::TryUsingSingleContains),
                    )
                    .then_typecheck(|expr_ty_arg2, _| {
                        if self.mode.is_strict() {
                            let annotated_expr =
                                ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                    .with_same_source_loc(bin_expr)
                                    .binary_app(*op, expr_ty_arg1.clone(), expr_ty_arg2.clone());
                            self.enforce_strict_equality(
                                bin_expr,
                                annotated_expr,
                                expr_ty_arg1.data(),
                                expr_ty_arg2.data(),
                                type_errors,
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
        }
    }

    fn enforce_strict_equality<'b>(
        &self,
        unannotated_expr: &'b Expr,
        annotated_expr: Expr<Option<Type>>,
        lhs_ty: &Option<Type>,
        rhs_ty: &Option<Type>,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
        match annotated_expr.data() {
            Some(Type::False) => {
                TypecheckAnswer::success(ExprBuilder::with_data(Some(Type::False)).val(false))
            }
            Some(Type::True) => {
                TypecheckAnswer::success(ExprBuilder::with_data(Some(Type::True)).val(true))
            }
            _ => match (lhs_ty, rhs_ty) {
                (Some(lhs_ty), Some(rhs_ty))
                    if Type::least_upper_bound(self.schema, lhs_ty, rhs_ty, self.mode)
                        .is_none() =>
                {
                    type_errors.push(TypeError::incompatible_types(
                        unannotated_expr.clone(),
                        [lhs_ty.clone(), rhs_ty.clone()],
                    ));
                    TypecheckAnswer::fail(annotated_expr)
                }
                // Either we had `Some` type for lhs and rhs and these types
                // were compatible, or we failed to a compute a type for either
                // lhs or rhs, meaning we already failed typechecking for that
                // expression.
                _ => TypecheckAnswer::success(annotated_expr),
            },
        }
    }

    /// Like `typecheck_binary()`, but for multiplication, which isn't
    /// technically a `BinaryOp`
    /// INVARIANT: must be called `mul_expr` being a `MulByConst`
    fn typecheck_mul<'b>(
        &self,
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        mul_expr: &'b Expr,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
        // PANIC SAFETY: maintained by invariant on this function
        #[allow(clippy::panic)]
        let ExprKind::MulByConst { arg, constant } = mul_expr.expr_kind() else {
            panic!("`typecheck_mul` called with an expression kind other than `MulByConst`");
        };

        let ans_arg = self.expect_type(
            request_env,
            prior_eff,
            arg,
            Type::primitive_long(),
            type_errors,
            |_| None,
        );
        ans_arg.then_typecheck(|arg_expr_ty, _| {
            TypecheckAnswer::success({
                ExprBuilder::with_data(Some(Type::primitive_long()))
                    .with_same_source_loc(mul_expr)
                    .mul(arg_expr_ty, *constant)
            })
        })
    }

    /// Get the type for an `==` expression given the input types.
    fn type_of_equality<'b>(
        &self,
        request_env: &RequestEnv,
        lhs_expr: &'b Expr,
        lhs_ty: &Option<Type>,
        rhs_expr: &'b Expr,
        rhs_ty: &Option<Type>,
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
            // The types are not disjoint. Look at the actual
            // expressions to see if they are matching or disjoint entity
            // literals.  If both the lhs and rhs expression are literal euid or
            // the action variable (which is converted into a literal euid
            // according to the binding in the request environment), then we
            // compare the euids on either side.
            let lhs_euid = Typechecker::euid_from_euid_literal_or_action(request_env, lhs_expr);
            let rhs_euid = Typechecker::euid_from_euid_literal_or_action(request_env, rhs_expr);
            if let (Some(lhs_euid), Some(rhs_euid)) = (lhs_euid, rhs_euid) {
                if lhs_euid == rhs_euid {
                    // If lhs and rhs euid are the same, the equality has type `True`.
                    Type::singleton_boolean(true)
                } else {
                    // If lhs and rhs euid are different, the type is `False`.
                    Type::singleton_boolean(false)
                }
            } else {
                let left_is_unspecified = Typechecker::is_unspecified_entity(request_env, lhs_expr);
                let right_is_specified = rhs_ty
                    .as_ref()
                    .map(Type::must_be_specified_entity)
                    .unwrap_or(false);

                if left_is_unspecified && right_is_specified {
                    // Check we are comparing an unspecified entity to a
                    // specified entity. This is always false.
                    Type::singleton_boolean(false)
                } else {
                    // When the left and right expressions are not both literal
                    // euids, the validator does not attempt to give a more specific
                    // type than boolean.
                    Type::primitive_boolean()
                }
            }
        }
    }

    /// Handles typechecking of `in` expressions. This is complicated because it
    /// requires searching the schema to determine if an `in` expression
    /// consisting of variables and literals can ever be true. When we find that
    /// an `in` expression is always false, this function returns the singleton
    /// type false, allowing for short circuiting in `if` and `and` expressions.
    fn typecheck_in<'b>(
        &self,
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        in_expr: &Expr,
        lhs: &'b Expr,
        rhs: &'b Expr,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
        // First, the basic typechecking rules for `in` that apply regardless of
        // the syntactic special cases that follow.
        let ty_lhs = self.expect_type(
            request_env,
            prior_eff,
            lhs,
            Type::any_entity_reference(),
            type_errors,
            |_| Some(UnexpectedTypeHelp::TryUsingContains),
        );
        let ty_rhs = self.expect_one_of_types(
            request_env,
            prior_eff,
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

        ty_lhs.then_typecheck(|lhs_expr, _lhs_effects| {
            ty_rhs.then_typecheck(|rhs_expr, _rhs_effects| {
                // If either failed to typecheck, then the whole expression fails to
                // typecheck.
                if !lhs_typechecked || !rhs_typechecked {
                    return TypecheckAnswer::fail(
                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                            .with_same_source_loc(in_expr)
                            .is_in(lhs_expr, rhs_expr),
                    );
                }
                let left_is_unspecified = Typechecker::is_unspecified_entity(request_env, lhs);
                let right_is_specified = match rhs_expr.data() {
                    Some(Type::Set { element_type }) => element_type.as_ref().map(|t| t.as_ref()),
                    ty => ty.as_ref(),
                }
                .map(Type::must_be_specified_entity)
                .unwrap_or(false);
                if left_is_unspecified && right_is_specified {
                    return TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(Type::singleton_boolean(false)))
                            .with_same_source_loc(in_expr)
                            .is_in(lhs_expr, rhs_expr),
                    );
                }
                let lhs_ty = lhs_expr.data().clone();
                let rhs_ty = rhs_expr.data().clone();
                let lhs_as_euid_lit = Typechecker::replace_action_var_with_euid(request_env, lhs);
                let rhs_as_euid_lit = Typechecker::replace_action_var_with_euid(request_env, rhs);
                match (lhs_as_euid_lit.expr_kind(), rhs_as_euid_lit.expr_kind()) {
                    // var in EntityLiteral. Lookup the descendant types of the entity
                    // literals.  If the principal/resource type is not one of the
                    // descendants, than it can never be `in` the literals (return false).
                    // Otherwise, it could be (return boolean).
                    (
                        ExprKind::Var(var @ (Var::Principal | Var::Resource)),
                        ExprKind::Lit(Literal::EntityUID(_)),
                    ) => self.type_of_var_in_entity_literals(
                        request_env,
                        *var,
                        [rhs_as_euid_lit.as_ref()],
                        in_expr,
                        lhs_expr,
                        rhs_expr,
                    ),

                    // var in [EntityLiteral, ...]. As above, but now the
                    // principal/resource just needs to be in the descendants sets for
                    // any member of the set.
                    (
                        ExprKind::Var(var @ (Var::Principal | Var::Resource)),
                        ExprKind::Set(elems),
                    ) => self.type_of_var_in_entity_literals(
                        request_env,
                        *var,
                        elems.as_ref(),
                        in_expr,
                        lhs_expr,
                        rhs_expr,
                    ),

                    // EntityLiteral in EntityLiteral. Follows similar logic to the
                    // first case, but with the added complication that this case
                    // handles Action entities (including the action variable due to the
                    // action-var -> action-entity-literal substitution applied), whose
                    // hierarchy is based on EntityUids (type name + id) rather than
                    // entity type names.
                    (
                        ExprKind::Lit(Literal::EntityUID(euid0)),
                        ExprKind::Lit(Literal::EntityUID(_)),
                    ) => self.type_of_entity_literal_in_entity_literals(
                        request_env,
                        euid0,
                        [rhs_as_euid_lit.as_ref()],
                        in_expr,
                        lhs_expr,
                        rhs_expr,
                    ),

                    // As above, with the same complication, but applied to set of entities.
                    (ExprKind::Lit(Literal::EntityUID(euid)), ExprKind::Set(elems)) => self
                        .type_of_entity_literal_in_entity_literals(
                            request_env,
                            euid,
                            elems.as_ref(),
                            in_expr,
                            lhs_expr,
                            rhs_expr,
                        ),

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
                .then_typecheck(|type_of_in, _| {
                    if !self.mode.is_strict() {
                        TypecheckAnswer::success(type_of_in)
                    } else if matches!(type_of_in.data(), Some(Type::False)) {
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(Some(Type::False)).val(false),
                        )
                    } else if matches!(type_of_in.data(), Some(Type::True)) {
                        TypecheckAnswer::success(ExprBuilder::with_data(Some(Type::True)).val(true))
                    } else {
                        match (lhs_ty, rhs_ty) {
                            (Some(lhs_ty), Some(rhs_ty)) => {
                                match (
                                    Self::get_as_single_entity_type(lhs_ty),
                                    Self::get_as_single_entity_type(rhs_ty),
                                ) {
                                    (Some(lhs_name), Some(rhs_name)) => {
                                        let lhs_ty_in_rhs_ty = self
                                            .schema
                                            .get_entity_type(&rhs_name)
                                            .map(|ety| ety.descendants.contains(&lhs_name))
                                            .unwrap_or(false);
                                        // A schema may always declare that an action entity is a member of another action entity,
                                        // regardless of their exact types (i.e., their namespaces), so we shouldn't treat it as an error.
                                        let action_in_action = is_action_entity_type(&lhs_name)
                                            && is_action_entity_type(&rhs_name);
                                        if lhs_name == rhs_name
                                            || action_in_action
                                            || lhs_ty_in_rhs_ty
                                        {
                                            TypecheckAnswer::success(type_of_in)
                                        } else {
                                            // We could actually just return `Type::False`, but this is incurs a larger Dafny proof update.
                                            type_errors.push(TypeError::hierarchy_not_respected(
                                                in_expr.clone(),
                                                Some(lhs_name),
                                                Some(rhs_name),
                                            ));
                                            TypecheckAnswer::fail(type_of_in)
                                        }
                                    }
                                    _ => {
                                        type_errors.push(TypeError::hierarchy_not_respected(
                                            in_expr.clone(),
                                            None,
                                            None,
                                        ));
                                        TypecheckAnswer::fail(type_of_in)
                                    }
                                }
                            }
                            // An argument type is `None`, so one the arguments must have failed to typecheck already.
                            // There's no other interesting error to report in this case.
                            _ => TypecheckAnswer::fail(type_of_in),
                        }
                    }
                })
            })
        })
    }

    fn get_as_single_entity_type(ty: Type) -> Option<Name> {
        match ty {
            Type::EntityOrRecord(EntityRecordKind::Entity(lub)) => lub.into_single_entity(),
            Type::EntityOrRecord(EntityRecordKind::ActionEntity { name, .. }) => Some(name),
            Type::Set {
                element_type: Some(element_type),
            } => match *element_type {
                Type::EntityOrRecord(EntityRecordKind::Entity(lub)) => lub.into_single_entity(),
                Type::EntityOrRecord(EntityRecordKind::ActionEntity { name, .. }) => Some(name),
                _ => None,
            },
            _ => None,
        }
    }

    // Given an expression, if that expression is a literal or the `action`
    // variable, return it as an EntityUID. Return `None` otherwise.
    fn euid_from_euid_literal_or_action(request_env: &RequestEnv, e: &Expr) -> Option<EntityUID> {
        match Typechecker::replace_action_var_with_euid(request_env, e)
            .as_ref()
            .expr_kind()
        {
            ExprKind::Lit(Literal::EntityUID(e)) => Some((**e).clone()),
            _ => None,
        }
    }

    // Convert all expressions in the input to EntityUIDs if an EntityUID can be
    // extracted by `euid_from_uid_literal_or_action`. Return `None` if any
    // cannot be converted.
    fn euids_from_euid_literals_or_action<'b>(
        request_env: &RequestEnv,
        exprs: impl IntoIterator<Item = &'b Expr>,
    ) -> Option<Vec<EntityUID>> {
        exprs
            .into_iter()
            .map(|e| Self::euid_from_euid_literal_or_action(request_env, e))
            .collect::<Option<Vec<_>>>()
    }

    fn is_unspecified_entity(query_env: &RequestEnv, expr: &Expr) -> bool {
        match expr.expr_kind() {
            ExprKind::Var(Var::Principal) => matches!(
                query_env.principal_entity_type(),
                Some(EntityType::Unspecified)
            ),
            ExprKind::Var(Var::Resource) => matches!(
                query_env.resource_entity_type(),
                Some(EntityType::Unspecified)
            ),
            ExprKind::Var(Var::Action) => {
                matches!(
                    query_env.action_entity_uid().map(EntityUID::entity_type),
                    Some(EntityType::Unspecified)
                )
            }
            _ => false,
        }
    }

    /// Handles `in` expression where the `principal` or `resource` is `in` an
    /// entity literal or set of entity literals.
    fn type_of_var_in_entity_literals<'b, 'c>(
        &self,
        request_env: &RequestEnv,
        lhs_var: Var,
        rhs_elems: impl IntoIterator<Item = &'b Expr>,
        in_expr: &Expr,
        lhs_expr: Expr<Option<Type>>,
        rhs_expr: Expr<Option<Type>>,
    ) -> TypecheckAnswer<'c> {
        if let Some(rhs) = Typechecker::euids_from_euid_literals_or_action(request_env, rhs_elems) {
            let var_etype = if matches!(lhs_var, Var::Principal) {
                request_env.principal_entity_type()
            } else {
                request_env.resource_entity_type()
            };
            match var_etype {
                None => {
                    // We failed to get the principal/resource entity type because
                    // we are typechecking a request for some action which isn't
                    // declared in the schema.  We don't know if the euid would be
                    // in the descendants or not, so give it type boolean.
                    let in_expr = ExprBuilder::with_data(Some(Type::primitive_boolean()))
                        .with_same_source_loc(in_expr)
                        .is_in(lhs_expr, rhs_expr);
                    if self.mode.is_partial() {
                        TypecheckAnswer::success(in_expr)
                    } else {
                        // This should only happen when doing partial validation
                        // since we never construct the undeclared action
                        // request environment otherwise.
                        TypecheckAnswer::fail(in_expr)
                    }
                }
                Some(EntityType::Specified(var_name)) => {
                    let all_rhs_known = rhs
                        .iter()
                        .all(|e| self.schema.euid_has_known_entity_type(e));
                    if self.schema.is_known_entity_type(var_name) && all_rhs_known {
                        let descendants = self.schema.get_entity_types_in_set(rhs.iter());
                        Typechecker::entity_in_descendants(
                            var_name,
                            descendants,
                            in_expr,
                            lhs_expr,
                            rhs_expr,
                        )
                    } else {
                        let annotated_expr =
                            ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                .with_same_source_loc(in_expr)
                                .is_in(lhs_expr, rhs_expr);
                        if self.mode.is_partial() {
                            // In partial schema mode, undeclared entity types are
                            // expected.
                            TypecheckAnswer::success(annotated_expr)
                        } else {
                            TypecheckAnswer::fail(annotated_expr)
                        }
                    }
                }
                Some(EntityType::Unspecified) => {
                    // It's perfectly valid for `principal` or `resource` to be `EntityType::Unspecified`
                    if rhs
                        .iter()
                        .any(|euid| matches!(euid.entity_type(), EntityType::Unspecified))
                    {
                        // something on the RHS is unspecified, so we have to type `unspecified in RHS` as Bool,
                        // because two unspecified entities are equal (and thus `in`) if they have the same `Eid`.
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                .with_same_source_loc(in_expr)
                                .is_in(lhs_expr, rhs_expr),
                        )
                    } else {
                        // nothing on the RHS is unspecified, so `unspecified in RHS` is always false
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(Some(Type::singleton_boolean(false)))
                                .with_same_source_loc(in_expr)
                                .is_in(lhs_expr, rhs_expr),
                        )
                    }
                }
            }
        } else {
            // One or more of the elements on the right is not an entity
            // literal, so this does not apply. The `in` is still valid, so
            // typechecking succeeds with type Boolean.
            // Note that we could still return `False` in the specific case
            // where LHS is Unspecified and RHS cannot contain any Unspecified,
            // but in that case, we return `False` before ever reaching this
            // function, due to earlier checks.
            TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::primitive_boolean()))
                    .with_same_source_loc(in_expr)
                    .is_in(lhs_expr, rhs_expr),
            )
        }
    }

    fn type_of_entity_literal_in_entity_literals<'b, 'c>(
        &self,
        request_env: &RequestEnv,
        lhs_euid: &EntityUID,
        rhs_elems: impl IntoIterator<Item = &'b Expr>,
        in_expr: &Expr,
        lhs_expr: Expr<Option<Type>>,
        rhs_expr: Expr<Option<Type>>,
    ) -> TypecheckAnswer<'c> {
        if let Some(rhs) = Typechecker::euids_from_euid_literals_or_action(request_env, rhs_elems) {
            match lhs_euid.entity_type() {
                EntityType::Specified(name) => {
                    // We don't want to apply the action hierarchy check to
                    // non-action entities, but now we have a set of entities.
                    // We can apply the check as long as any are actions. The
                    // non-actions are omitted from the check, but they can
                    // never be an ancestor of `Action`.
                    let lhs_is_action = is_action_entity_type(name);
                    let (actions, non_actions): (Vec<_>, Vec<_>) =
                        rhs.into_iter().partition(|e| match e.entity_type() {
                            EntityType::Specified(e_name) => is_action_entity_type(e_name),
                            EntityType::Unspecified => false,
                        });
                    if lhs_is_action && !actions.is_empty() {
                        self.type_of_action_in_actions(
                            lhs_euid,
                            actions.iter(),
                            in_expr,
                            lhs_expr,
                            rhs_expr,
                        )
                    } else if !lhs_is_action && !non_actions.is_empty() {
                        self.type_of_non_action_in_entities(
                            lhs_euid,
                            &non_actions,
                            in_expr,
                            lhs_expr,
                            rhs_expr,
                        )
                    } else {
                        // This hard codes the assumption that `Action` can
                        // never be a member of any other entity type, and no
                        // other entity type can ever be a member of `Action`,
                        // and by extension any particular action entity.
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(Some(Type::False))
                                .with_same_source_loc(in_expr)
                                .is_in(lhs_expr, rhs_expr),
                        )
                    }
                }
                // This is a `TypecheckFail` because entity literals (`lhs_euid`
                // in this case) are not allowed to have `Unspecified` type.
                // Note that `Unspecified` entity literals will be detected by a
                // different part of the validator, so all we need to do here is
                // return `TypecheckFail`.
                EntityType::Unspecified => TypecheckAnswer::fail(
                    ExprBuilder::with_data(Some(Type::primitive_boolean()))
                        .with_same_source_loc(in_expr)
                        .is_in(lhs_expr, rhs_expr),
                ),
            }
        } else {
            // One or more of the elements on the right is not an entity
            // literal, so this does not apply. The `in` is still valid, so
            // typechecking succeeds with type Boolean.
            TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::primitive_boolean()))
                    .with_same_source_loc(in_expr)
                    .is_in(lhs_expr, rhs_expr),
            )
        }
    }

    // Get the type for `in` when it is applied to an action EUID literal and a
    // set of EUID literals. We can look up all ancestors of the action in the
    // schema, so the type will be `False` if the none of the rhs actions are an
    // ancestor of the lhs.
    fn type_of_action_in_actions<'b>(
        &self,
        lhs: &EntityUID,
        rhs: impl IntoIterator<Item = &'a EntityUID> + 'a,
        in_expr: &Expr,
        lhs_expr: Expr<Option<Type>>,
        rhs_expr: Expr<Option<Type>>,
    ) -> TypecheckAnswer<'b> {
        let rhs_descendants = self.schema.get_actions_in_set(rhs);
        if let Some(rhs_descendants) = rhs_descendants {
            Typechecker::entity_in_descendants(lhs, rhs_descendants, in_expr, lhs_expr, rhs_expr)
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

    // Get the type for `in` when it is applied to an non-action EUID literal
    // and a set of EUID literals. We can't conclude anything about membership
    // based on the precise EUIDs when they're not actions, so we only look at
    // entity types. The type will be `False` is none of the entities on the rhs
    // have a type which may be an ancestor of the rhs entity type.
    fn type_of_non_action_in_entities<'b>(
        &self,
        lhs: &EntityUID,
        rhs: &[EntityUID],
        in_expr: &Expr,
        lhs_expr: Expr<Option<Type>>,
        rhs_expr: Expr<Option<Type>>,
    ) -> TypecheckAnswer<'b> {
        match lhs.entity_type() {
            EntityType::Specified(lhs_ety) => {
                let all_rhs_known = rhs
                    .iter()
                    .all(|e| self.schema.euid_has_known_entity_type(e));
                if self.schema.is_known_entity_type(lhs_ety) && all_rhs_known {
                    let rhs_descendants = self.schema.get_entity_types_in_set(rhs.iter());
                    Typechecker::entity_in_descendants(
                        lhs_ety,
                        rhs_descendants,
                        in_expr,
                        lhs_expr,
                        rhs_expr,
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
            EntityType::Unspecified => {
                // Unspecified entities will be detected by a different part of the validator.
                // Still return `TypecheckFail` so that typechecking is not considered successful.
                TypecheckAnswer::fail(
                    ExprBuilder::with_data(Some(Type::primitive_boolean()))
                        .with_same_source_loc(in_expr)
                        .is_in(lhs_expr, rhs_expr),
                )
            }
        }
    }

    /// Check if the entity is in the list of descendants. Return the singleton
    /// type false if it is not, and boolean otherwise.
    fn entity_in_descendants<'b, K>(
        lhs_entity: &K,
        rhs_descendants: impl IntoIterator<Item = &'a K>,
        in_expr: &Expr,
        lhs_expr: Expr<Option<Type>>,
        rhs_expr: Expr<Option<Type>>,
    ) -> TypecheckAnswer<'b>
    where
        K: PartialEq + 'a,
    {
        let is_var_in_descendants = rhs_descendants.into_iter().any(|e| e == lhs_entity);
        TypecheckAnswer::success(
            ExprBuilder::with_data(Some(if is_var_in_descendants {
                Type::primitive_boolean()
            } else {
                Type::singleton_boolean(false)
            }))
            .with_same_source_loc(in_expr)
            .is_in(lhs_expr, rhs_expr),
        )
    }

    /// A utility called by the main typecheck method to handle unary operator
    /// application.
    /// INVARIANT: `unary_expr` must be of kind `UnaryApp`
    fn typecheck_unary<'b>(
        &self,
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        unary_expr: &'b Expr,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
        // PANIC SAFETY maintained by invariant on this function
        #[allow(clippy::panic)]
        let ExprKind::UnaryApp { op, arg } = unary_expr.expr_kind() else {
            panic!("`typecheck_unary` called with an expression kind other than `UnaryApp`");
        };
        match op {
            UnaryOp::Not => {
                let ans_arg = self.expect_type(
                    request_env,
                    prior_eff,
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
                    request_env,
                    prior_eff,
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
        }
    }

    /// Check that an expression has a type that is a subtype of one of the
    /// given types. If not, generate a type error and return TypecheckFail.
    /// Return the TypecheckSuccess with the type otherwise.
    fn expect_one_of_types<'b, F>(
        &self,
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        expr: &'b Expr,
        expected: &[Type],
        type_errors: &mut Vec<TypeError>,
        type_error_help: F,
    ) -> TypecheckAnswer<'b>
    where
        F: FnOnce(&Type) -> Option<UnexpectedTypeHelp>,
    {
        let actual = self.typecheck(request_env, prior_eff, expr, type_errors);
        actual.then_typecheck(|mut typ_actual, eff_actual| match typ_actual.data() {
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
                    type_errors.push(TypeError::expected_one_of_types(
                        expr.clone(),
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
                    TypecheckAnswer::success_with_effect(typ_actual, eff_actual)
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
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        expr: &'b Expr,
        expected: Type,
        type_errors: &mut Vec<TypeError>,
        type_error_help: F,
    ) -> TypecheckAnswer<'b>
    where
        F: FnOnce(&Type) -> Option<UnexpectedTypeHelp>,
    {
        self.expect_one_of_types(
            request_env,
            prior_eff,
            expr,
            &[expected],
            type_errors,
            type_error_help,
        )
    }

    /// Return the least upper bound of all types is the `types` vector. If
    /// there isn't a least upper bound, then a type error is reported and
    /// TypecheckFail is returned. Note that this function does not preserve the
    /// effects of the input TypecheckAnswers.
    fn least_upper_bound_or_error(
        &self,
        expr: &Expr,
        answers: impl IntoIterator<Item = Option<Type>>,
        type_errors: &mut Vec<TypeError>,
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
                if lub.is_none() {
                    // A type error is generated if we could not find a least
                    // upper bound for the types. The computed least upper bound
                    // will be None, so this function will correctly report this
                    // as a failure.
                    type_errors.push(TypeError::incompatible_types(
                        expr.clone(),
                        typechecked_types,
                    ));
                }
                lub
            })
    }

    /// If the `maybe_action_var` expression is `Expr::Var(Var::Action)`, return
    /// a expression for the entity uid for the action variable in the request
    /// environment. Otherwise, return the expression unchanged.
    fn replace_action_var_with_euid(
        request_env: &RequestEnv,
        maybe_action_var: &'a Expr,
    ) -> Cow<'a, Expr> {
        match maybe_action_var.expr_kind() {
            ExprKind::Var(Var::Action) => match request_env.action_entity_uid() {
                Some(action) => Cow::Owned(Expr::val(action.clone())),
                None => Cow::Borrowed(maybe_action_var),
            },
            _ => Cow::Borrowed(maybe_action_var),
        }
    }

    /// Lookup an extension function type by name. If the extension function
    /// does not exist or if multiple extension function with the same name are
    /// defined, instead return a closure that will construct an appropriate
    /// error.  A closure is returned rather than constructing the error in this
    /// function so that we can use the function in the strict typechecker where
    /// a different instantiation of the generic expression type is used.
    fn lookup_extension_function<'b>(
        &'b self,
        f: &'b Name,
    ) -> Result<&ExtensionFunctionType, impl FnOnce(Expr) -> TypeError + 'b> {
        let extension_funcs: Vec<&ExtensionFunctionType> = self
            .extensions
            .iter()
            .filter_map(|(_, ext)| ext.get_function_type(f))
            .collect();

        let fn_name_str = f.to_string();
        match extension_funcs.first() {
            Some(e) if extension_funcs.len() == 1 => Ok(e),
            _ => Err(move |e| {
                if extension_funcs.is_empty() {
                    TypeError::undefined_extension(e, fn_name_str)
                } else {
                    TypeError::multiply_defined_extension(e, fn_name_str)
                }
            }),
        }
    }

    /// Utility called by the main typecheck method to handle extension function
    /// application.
    /// INVARIANT `ext_expr` must be a `ExtensionFunctionApp`
    fn typecheck_extension<'b>(
        &self,
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        ext_expr: &'b Expr,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
        // PANIC SAFETY maintained by invariant on this function
        #[allow(clippy::panic)]
        let ExprKind::ExtensionFunctionApp { fn_name, args } = ext_expr.expr_kind() else {
            panic!("`typecheck_extension` called with an expression kind other than `ExtensionFunctionApp`");
        };

        let typed_arg_exprs = |type_errors: &mut Vec<TypeError>| {
            args.iter()
                .map(|arg| {
                    self.typecheck(request_env, prior_eff, arg, type_errors)
                        .into_typed_expr()
                })
                .collect::<Option<Vec<_>>>()
        };

        match self.lookup_extension_function(fn_name) {
            Ok(efunc) => {
                let arg_tys = efunc.argument_types();
                let ret_ty = efunc.return_type();
                let mut failed = false;
                if args.len() != arg_tys.len() {
                    type_errors.push(TypeError::wrong_number_args(
                        ext_expr.clone(),
                        arg_tys.len(),
                        args.len(),
                    ));
                    failed = true;
                }
                if let Err(msg) = efunc.check_arguments(args) {
                    type_errors.push(TypeError::arg_validation_error(ext_expr.clone(), msg));
                    failed = true;
                }

                if self.mode.is_strict()
                    && efunc.has_argument_check()
                    && !args
                        .iter()
                        .all(|e| matches!(e.expr_kind(), ExprKind::Lit(_)))
                {
                    type_errors.push(TypeError::non_lit_ext_constructor(ext_expr.clone()));
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
                    let typechecked_args = zip(args.as_ref(), arg_tys).map(|(arg, ty)| {
                        self.expect_type(
                            request_env,
                            prior_eff,
                            arg,
                            ty.clone(),
                            type_errors,
                            |_| None,
                        )
                    });
                    TypecheckAnswer::sequence_all_then_typecheck(
                        typechecked_args,
                        |arg_exprs_effects| {
                            let (typed_arg_exprs, _): (Vec<Expr<Option<Type>>>, Vec<_>) =
                                arg_exprs_effects.into_iter().unzip();
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
                type_errors.push(typ_err(ext_expr.clone()));
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
