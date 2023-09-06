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
    schema::{
        is_action_entity_type, ActionHeadVar, HeadVar, PrincipalOrResourceHeadVar, ValidatorSchema,
    },
    types::{
        AttributeType, Effect, EffectSet, EntityRecordKind, OpenTag, Primitive, RequestEnv, Type,
    },
    AttributeAccess, ValidationMode,
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

    pub fn typed_expr(&self) -> Option<&Expr<Option<Type>>> {
        match self {
            TypecheckAnswer::TypecheckSuccess { expr_type, .. } => Some(expr_type),
            TypecheckAnswer::TypecheckFail { expr_recovery_type } => Some(expr_recovery_type),
            TypecheckAnswer::RecursionLimit => None,
        }
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
        let typecheck_answers = if self.mode.is_strict() {
            self.typecheck_by_request_env_strict(t)
        } else {
            self.typecheck_by_request_env(t)
        };

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

    /// A strict variant of `typecheck_by_request_env` which is used by cedar policy
    /// analysis.
    pub fn typecheck_by_request_env_strict<'b>(
        &'b self,
        t: &'b Template,
    ) -> Vec<(RequestEnv, PolicyCheck)> {
        self.apply_typecheck_fn_by_request_env(t, move |request, expr| {
            let mut type_errors = Vec::new();
            let ty =
                self.typecheck_strict(request, expr, Type::primitive_boolean(), &mut type_errors);

            // Strict types don't include the True and False boolean singletons,
            // so we can't check for for type False. The strict transformation
            // includes a rewriting from any boolean singleton type expression
            // to the corresponding boolean literal, so we instead look for the
            // literal `false`.
            match ty.typed_expr() {
                Some(typed_expr) => {
                    let is_false = typed_expr.eq_shape(&Expr::val(false));
                    match (is_false, ty.typechecked()) {
                        (false, false) => PolicyCheck::Fail(type_errors),
                        (false, true) => PolicyCheck::Success(typed_expr.clone()),
                        (true, _) => PolicyCheck::Irrelevant(type_errors),
                    }
                }
                None => PolicyCheck::Fail(type_errors),
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

    /// Additional entry point for strict typechecking requests. This method takes a slice
    /// over policies and typechecks each under every schema-defined request environment.
    ///
    /// The result contains these environments in no particular order, but each list of
    /// policy checks will always match the original order.
    ///
    /// This function is currently only used in policy analysis where only the
    /// strict variant is needed.
    pub fn multi_typecheck_by_request_env_strict(
        &self,
        policy_templates: &[&Template],
    ) -> Vec<(RequestEnv, Vec<PolicyCheck>)> {
        let mut env_checks = Vec::new();
        for request in self.unlinked_request_envs() {
            let mut policy_checks = Vec::new();
            for t in policy_templates.iter() {
                for linked_env in self.link_request_env(request.clone(), t) {
                    let mut type_errors = Vec::new();
                    let policy_condition = &t.condition();
                    let ty = self.typecheck_strict(
                        &linked_env,
                        policy_condition,
                        Type::primitive_boolean(),
                        &mut type_errors,
                    );

                    // Again, look for the literal `false` instead of the type
                    // false.
                    match ty.typed_expr() {
                        Some(typed_expr) => {
                            let is_false = typed_expr.eq_shape(&Expr::val(false));
                            match (is_false, ty.typechecked()) {
                                (false, false) => {
                                    policy_checks.push(PolicyCheck::Fail(type_errors))
                                }
                                (false, true) => {
                                    policy_checks.push(PolicyCheck::Success(typed_expr.clone()));
                                }
                                (true, _) => {
                                    policy_checks.push(PolicyCheck::Irrelevant(type_errors))
                                }
                            }
                        }
                        None => policy_checks.push(PolicyCheck::Fail(type_errors)),
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
        all_actions.flat_map(move |action| {
            action
                .applies_to
                .applicable_principal_types()
                .flat_map(move |principal| {
                    action
                        .applies_to
                        .applicable_resource_types()
                        .map(move |resource| RequestEnv {
                            principal,
                            action: &action.name,
                            resource,
                            context: &action.context,
                            principal_slot: None,
                            resource_slot: None,
                        })
                })
        })
    }

    /// Given a request environment and a template, return new environments
    /// formed by instantiating template slots with possible entity types.
    fn link_request_env<'b>(
        &'b self,
        env: RequestEnv<'b>,
        t: &'b Template,
    ) -> impl Iterator<Item = RequestEnv> + 'b {
        self.possible_slot_instantiations(
            t,
            SlotId::principal(),
            env.principal,
            t.principal_constraint().as_inner(),
        )
        .flat_map(move |p_slot| {
            self.possible_slot_instantiations(
                t,
                SlotId::resource(),
                env.resource,
                t.resource_constraint().as_inner(),
            )
            .map(move |r_slot| RequestEnv {
                principal: env.principal,
                action: env.action,
                resource: env.resource,
                context: env.context,
                principal_slot: p_slot.clone(),
                resource_slot: r_slot.clone(),
            })
        })
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
                // The condition is `var in ?slot`, so the policy can only apply
                // if the var is some descendant of the slot.
                PrincipalOrResourceConstraint::In(_) => Box::new(
                    all_entity_types
                        .filter(|(_, ety)| ety.has_descendant_entity_type(var))
                        .map(|(name, _)| Some(EntityType::Concrete(name.clone())))
                        .chain(std::iter::once(Some(var.clone()))),
                ),
                // The template uses the slot, but without a scope constraint.
                // This can't happen for the moment because slots may only
                // appear in head constraints, but if we ever see this, then the
                // only correct way to proceed is by returning all entity types
                // as possible instantiations.
                PrincipalOrResourceConstraint::Any => Box::new(
                    all_entity_types.map(|(name, _)| Some(EntityType::Concrete(name.clone()))),
                ),
            }
        } else {
            // If the template does not contain this slot, then we don't need to
            // consider its instantiations..
            Box::new(std::iter::once(None))
        }
    }

    fn typecheck_strict<'b>(
        &self,
        request_env: &RequestEnv,
        e: &'b Expr,
        expected_type: Type,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
        let empty_prior_eff = EffectSet::new();
        let tc_ans = self.expect_type(request_env, &empty_prior_eff, e, expected_type, type_errors);

        tc_ans.then_typecheck(|annot_expr, _| self.strict_transform(&annot_expr, type_errors))
    }

    fn check_all_types_compat_acts(elems_types: &HashSet<&Option<Type>>) -> bool {
        let mut action_entity_namespace: Option<String> = None;
        return elems_types.iter().all(|ot| match ot {
            None => false,
            Some(t) => match t {
                Type::EntityOrRecord(EntityRecordKind::ActionEntity { .. }) => true,
                Type::EntityOrRecord(EntityRecordKind::Entity(lub)) => {
                    match lub.get_single_entity() {
                        Some(n) => {
                            if is_action_entity_type(n) {
                                match &action_entity_namespace {
                                    Some(ns) => n.namespace().eq(&ns.clone()),
                                    None => {
                                        action_entity_namespace = Some(n.namespace());
                                        true
                                    }
                                }
                            } else {
                                false
                            }
                        }
                        None => false,
                    }
                }
                _ => false,
            },
        });
    }

    fn strict_transform<'b>(
        &self,
        e: &Expr<Option<Type>>,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
        #[cfg(not(target_arch = "wasm32"))]
        if stacker::remaining_stack().unwrap_or(0) < REQUIRED_STACK_SPACE {
            return TypecheckAnswer::RecursionLimit;
        }
        match e.data() {
            // If the validator could conclude that an expression is always true
            // or always false (encoded as the singleton boolean types
            // `Type::True` and `Type::False`), then we return a constant
            // `true` or `false` expression. The type of the constant expression
            // is `Boolean` in either case because strictly typed expressions
            // may not use the singleton boolean types.
            Some(Type::True) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::primitive_boolean())).val(true),
            ),
            Some(Type::False) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::primitive_boolean())).val(false),
            ),
            _ => match e.expr_kind() {
                // These are leaves of the AST, so no further work is done.
                ExprKind::Lit(_)
                | ExprKind::Var(_)
                | ExprKind::Slot(_)
                | ExprKind::Unknown { .. } => TypecheckAnswer::success(e.clone()),

                ExprKind::If {
                    test_expr,
                    then_expr,
                    else_expr,
                } => {
                    match test_expr.data() {
                        // When the guard of an `if` expression always evaluates to
                        // the same constant boolean value, we can eliminate one of
                        // the branches without applying the strict transformation
                        // to it because it will never be evaluated. The guard is
                        // also eliminated.
                        Some(Type::True) => self.strict_transform(then_expr, type_errors),
                        Some(Type::False) => self.strict_transform(else_expr, type_errors),

                        // The guard is not `True` or `False`. Assuming that `e`
                        // passed the validator, we know it's `Boolean`, so either
                        // the `then` or `else` branches may be evaluated. Strict
                        // validation requires that their strict types are
                        // equivalent.
                        _ => {
                            let test_ans = self.strict_transform(test_expr, type_errors);
                            let then_ans = self.strict_transform(then_expr, type_errors);
                            let else_ans = self.strict_transform(else_expr, type_errors);
                            then_ans.then_typecheck(|then_strict, _| {
                                else_ans.then_typecheck(|else_strict, _| {
                                    test_ans.then_typecheck(|test_strict, _| {
                                        let strict_expr = ExprBuilder::with_data(e.data().clone())
                                            .ite(
                                                test_strict,
                                                then_strict.clone(),
                                                else_strict.clone(),
                                            );
                                        // If either branch was not assigned a type,
                                        // we do not conclude that they have different
                                        // types.  Note that we have already raised a
                                        // type error whenever a type is `None`, so there
                                        // are no soundness issues.
                                        match (then_strict.data(), else_strict.data()) {
                                            (Some(ty_then), Some(ty_else))
                                                if !Self::unify_strict_types(ty_then, ty_else) =>
                                            {
                                                // Only generate a new type error when the
                                                // types have a LUB. If the don't have a
                                                // lub, the first typechecking pass already
                                                // reported an error.
                                                let has_lub = Type::least_upper_bound(
                                                    self.schema,
                                                    ty_then,
                                                    ty_else,
                                                )
                                                .is_some();
                                                if has_lub {
                                                    type_errors.push(TypeError::types_must_match(
                                                        e.clone(),
                                                        [ty_then.clone(), ty_else.clone()],
                                                    ));
                                                }
                                                TypecheckAnswer::fail(strict_expr)
                                            }

                                            _ => TypecheckAnswer::success(strict_expr),
                                        }
                                    })
                                })
                            })
                        }
                    }
                }

                ExprKind::BinaryApp { .. } => self.strict_transform_binary(e, type_errors),

                // The elements of a set must share a single type. We
                // additionally require that they cannot be empty. This is not a
                // hard requirement for strict validation, but the current
                // validator can't assign a type to empty set literals, which is
                // required by the analyzer.
                ExprKind::Set(elems) => {
                    let elems_strict_answers = elems
                        .iter()
                        .map(|e| self.strict_transform(e, type_errors))
                        .collect::<Vec<_>>();
                    TypecheckAnswer::sequence_all_then_typecheck(
                        elems_strict_answers,
                        |elems_strict_unwrapped| {
                            let elems_strict_exprs: Vec<_> =
                                elems_strict_unwrapped.into_iter().map(|(e, _)| e).collect();
                            let strict_expr = ExprBuilder::with_data(e.data().clone())
                                .set(elems_strict_exprs.clone());

                            let elems_types = elems_strict_exprs
                                .iter()
                                .map(|e| e.data())
                                .collect::<HashSet<_>>();

                            let all_contained_types_are_compatable_actions =
                                Self::check_all_types_compat_acts(&elems_types);

                            // Check that the type of all elements of the set
                            // can unify. This ensures that the all have the
                            // same type up to the limited subtyping allowed
                            // between True/False/Boolean.
                            let mut elems_types_iter = elems_types.iter();
                            let representative_type =
                                elems_types_iter.next().and_then(|t| t.as_ref());
                            let types_unify = representative_type
                                .map(|representative_type| {
                                    elems_types_iter
                                        .filter_map(|ty| ty.as_ref())
                                        .all(|ty| Self::unify_strict_types(representative_type, ty))
                                })
                                .unwrap_or(true);

                            let contains_one_type =
                                types_unify || all_contained_types_are_compatable_actions;
                            let is_non_empty = elems.len() != 0;

                            if !contains_one_type {
                                type_errors.push(TypeError::types_must_match(
                                    e.clone(),
                                    elems_types.into_iter().flatten().cloned(),
                                ));
                            }
                            if !is_non_empty {
                                type_errors.push(TypeError::empty_set_forbidden(e.clone()));
                            }

                            if contains_one_type && is_non_empty {
                                TypecheckAnswer::success(strict_expr)
                            } else {
                                TypecheckAnswer::fail(strict_expr)
                            }
                        },
                    )
                }

                // Extension type constructor functions requiring string
                // parsing should only be callable with literals. The functions
                // have a `check_arguments` function defined which is used by
                // the standard validator to ensure that the string can be
                // parsed.  The standard validator, however, allows calling
                // these functions with non-literal expression that might not
                // parse, so we have a
                ExprKind::ExtensionFunctionApp { fn_name, args } => {
                    let args_strict_answers = args
                        .iter()
                        .map(|e| self.strict_transform(e, type_errors))
                        .collect::<Vec<_>>();

                    TypecheckAnswer::sequence_all_then_typecheck(
                        args_strict_answers,
                        |args_strict_unwrapped| {
                            let strict_expr = ExprBuilder::with_data(e.data().clone())
                                .call_extension_fn(
                                    fn_name.clone(),
                                    args_strict_unwrapped.into_iter().map(|a| a.0).collect(),
                                );
                            let fn_has_arg_check = match self.lookup_extension_function(fn_name) {
                                Ok(f) => f.has_argument_check(),
                                // The function is not defined or is defined
                                // multiple times. An error was already raised by
                                // the standard typechecker.
                                Err(_) => false,
                            };
                            let args_args_lit = args
                                .iter()
                                .all(|e| matches!(e.expr_kind(), ExprKind::Lit(_)));
                            if !fn_has_arg_check || args_args_lit {
                                TypecheckAnswer::success(strict_expr)
                            } else {
                                type_errors.push(TypeError::non_lit_ext_constructor(e.clone()));
                                TypecheckAnswer::fail(strict_expr)
                            }
                        },
                    )
                }

                // All other expressions are also processed recursively. Any
                // expressions that can have types `Type` and `False` are
                // handled by the constant boolean expression rules. This
                // applies to, for example, `And` and `Or` expressions which can
                // short circuit to `true` or `false`.
                ExprKind::And { left, right } => {
                    let left_strict = self.strict_transform(left, type_errors);
                    left_strict.then_typecheck(|left_strict, _| {
                        let right_strict = self.strict_transform(right, type_errors);
                        right_strict.then_typecheck(|right_strict, _| {
                            TypecheckAnswer::success(
                                ExprBuilder::with_data(e.data().clone())
                                    .and(left_strict, right_strict),
                            )
                        })
                    })
                }
                ExprKind::Or { left, right } => {
                    let left_strict = self.strict_transform(left, type_errors);
                    left_strict.then_typecheck(|left_strict, _| {
                        let right_strict = self.strict_transform(right, type_errors);
                        right_strict.then_typecheck(|right_strict, _| {
                            TypecheckAnswer::success(
                                ExprBuilder::with_data(e.data().clone())
                                    .or(left_strict, right_strict),
                            )
                        })
                    })
                }

                ExprKind::UnaryApp { op, arg } => self
                    .strict_transform(arg, type_errors)
                    .then_typecheck(|strict_arg, _| {
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(e.data().clone()).unary_app(*op, strict_arg),
                        )
                    }),
                ExprKind::MulByConst { arg, constant } => self
                    .strict_transform(arg, type_errors)
                    .then_typecheck(|strict_arg, _| {
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(e.data().clone()).mul(strict_arg, *constant),
                        )
                    }),

                ExprKind::GetAttr { expr, attr } => self
                    .strict_transform(expr, type_errors)
                    .then_typecheck(|strict_expr, _| {
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(e.data().clone())
                                .get_attr(strict_expr, attr.clone()),
                        )
                    }),
                ExprKind::HasAttr { expr, attr } => self
                    .strict_transform(expr, type_errors)
                    .then_typecheck(|strict_expr, _| {
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(e.data().clone())
                                .has_attr(strict_expr, attr.clone()),
                        )
                    }),
                ExprKind::Like { expr, pattern } => self
                    .strict_transform(expr, type_errors)
                    .then_typecheck(|strict_expr, _| {
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(e.data().clone())
                                .like(strict_expr, pattern.iter().cloned()),
                        )
                    }),
                ExprKind::Record { pairs } => {
                    let (attr_names, strict_attr_exprs): (Vec<_>, Vec<_>) = pairs
                        .iter()
                        .map(|(a, e)| (a.clone(), self.strict_transform(e, type_errors)))
                        .unzip();

                    TypecheckAnswer::sequence_all_then_typecheck(
                        strict_attr_exprs,
                        |strict_attr_exprs| {
                            TypecheckAnswer::success(
                                ExprBuilder::with_data(e.data().clone()).record(
                                    attr_names
                                        .into_iter()
                                        .zip(strict_attr_exprs.into_iter().map(|(e, _)| e)),
                                ),
                            )
                        },
                    )
                }
            },
        }
    }

    fn strict_transform_binary<'b>(
        &self,
        bin_expr: &Expr<Option<Type>>,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
        let ExprKind::BinaryApp { op, arg1, arg2 } = bin_expr.expr_kind() else {
            panic!(
                "`strict_transform_binary` called with an expression kind other than `BinaryApp`"
            );
        };

        // Binary operators `==`, `contains`, `containsAll`, and `containsAny`
        // are restricted to operating on operands of the same type (or sets of
        // that type as appropriate).
        let arg1_strict = self.strict_transform(arg1, type_errors);
        let arg2_strict = self.strict_transform(arg2, type_errors);
        arg1_strict.then_typecheck(|arg1_strict, _| {
            arg2_strict.then_typecheck(|arg2_strict, _| {
                // If either operand was not assigned a type, then we should not
                // conclude that they have different types, as this raises
                // spurious errors. Note that we have already raised a type
                // error whenever a type is `None`, so there are no soundness
                // issues.
                match (arg1_strict.data(), arg2_strict.data()) {
                    (None, _) | (_, None) => TypecheckAnswer::success(
                        ExprBuilder::with_data(bin_expr.data().clone()).binary_app(
                            *op,
                            arg1_strict,
                            arg2_strict,
                        ),
                    ),
                    (Some(ty1), Some(ty2)) => {
                        let operand_types_match = match (op, arg1_strict.data(), arg2_strict.data())
                        {
                            (BinaryOp::Eq, Some(ty1), Some(ty2)) => {
                                Self::unify_strict_types(ty1, ty2)
                            }
                            // Assume that LHS is a set. This is checked by the
                            // standard typechecker.
                            (
                                BinaryOp::Contains,
                                Some(Type::Set {
                                    // This pattern causes us to assume that the set is not the empty set.
                                    // The empty set was already rejected by the strict validator, but it
                                    // can still show up here because we continue typechecking after
                                    // failure. It's fine to fall through to the catch-all case at the
                                    // bottom where no additional error will be raised.
                                    element_type: Some(elem_ty),
                                }),
                                Some(ty2),
                            ) => Self::unify_strict_types(elem_ty.as_ref(), ty2),
                            // Both args must be sets, but this is checked by
                            // the typechecker. Their elements must then be the
                            // same type, but, they're both sets, so we can just
                            // check for equality directly.
                            (
                                BinaryOp::ContainsAll | BinaryOp::ContainsAny,
                                Some(ty1),
                                Some(ty2),
                            ) => Self::unify_strict_types(ty1, ty2),
                            (BinaryOp::In, Some(ty1), Some(ty2)) => {
                                let ty2 = match ty2 {
                                    // If `element_type` is None then the second operand to `in` was an empty
                                    // set. An error was raised for this already, so it can fall through to
                                    // the catch-all at the next `match`.
                                    Type::Set { element_type } => {
                                        element_type.as_ref().map(|t| t.as_ref())
                                    }
                                    _ => Some(ty2),
                                };
                                match (ty1, ty2) {
                                    (
                                        Type::EntityOrRecord(EntityRecordKind::Entity(lub1)),
                                        Some(Type::EntityOrRecord(EntityRecordKind::Entity(lub2))),
                                    ) => {
                                        match (lub1.get_single_entity(), lub2.get_single_entity()) {
                                            (Some(entity_type_name1), Some(entity_type_name2)) => {
                                                let entity_type2 =
                                                    self.schema.get_entity_type(entity_type_name2);

                                                // Strict validation does not permit an `in` between unrelated
                                                // entity types.
                                                let is_same_entity_type =
                                                    entity_type_name1 == entity_type_name2;
                                                let is_descendant = match entity_type2 {
                                                    Some(entity2) => entity2
                                                        .descendants
                                                        .contains(entity_type_name1),
                                                    // The entity type does not exist. Even though an error
                                                    // was raised for an unknown entity type, it still makes
                                                    // sense to raise an error noting that strict validation
                                                    // would fail even if the entity type was declared.
                                                    None => false,
                                                };
                                                is_same_entity_type || is_descendant
                                            }
                                            // One of the operands has a non-singleton entity LUB type. This
                                            // implies that it did not strictly typecheck.
                                            _ => true,
                                        }
                                    }
                                    // AnyEntity cannot appear on either side of the `in`. This would effect
                                    // slots and unspecified entities, but an `in` with unspecified entities
                                    // is always `False` after standard typechecking, and we explicitly permit
                                    // slots below.
                                    (
                                        Type::EntityOrRecord(
                                            EntityRecordKind::AnyEntity
                                            | EntityRecordKind::Entity(_),
                                        ),
                                        Some(Type::EntityOrRecord(
                                            EntityRecordKind::AnyEntity
                                            | EntityRecordKind::Entity(_)
                                            | EntityRecordKind::ActionEntity { .. },
                                        )),
                                    ) => false,
                                    // `in` is applied to a type that was either not an entity/set-of-entity or
                                    // was an empty set. The typechecker already raised an error for this, so
                                    // it doesn't make sense to also complain that the types don't match.
                                    _ => true,
                                }
                            }
                            // No extra checking is required for the remaining binary operators.
                            _ => true,
                        };

                        // Arg2 has type `AnyEntity` when it is a template slot.
                        // This would normally fail the strict check, but we
                        // want to let slots through so that templates are not
                        // always rejected by the strict validator. For every
                        // instantiation of the slots in a template, either that
                        // instantiation passes strict validation or we can
                        // conclude the instantiation evaluates to `false`.
                        let arg2_is_slot = matches!(arg2.expr_kind(), ExprKind::Slot(_));

                        if arg2_is_slot || operand_types_match {
                            TypecheckAnswer::success(
                                ExprBuilder::with_data(bin_expr.data().clone()).binary_app(
                                    *op,
                                    arg1_strict,
                                    arg2_strict,
                                ),
                            )
                        } else {
                            type_errors.push(TypeError::types_must_match(
                                bin_expr.clone(),
                                [ty1.clone(), ty2.clone()],
                            ));
                            TypecheckAnswer::fail(
                                ExprBuilder::with_data(bin_expr.data().clone()).binary_app(
                                    *op,
                                    arg1_strict,
                                    arg2_strict,
                                ),
                            )
                        }
                    }
                }
            })
        })
    }

    pub(crate) fn unify_strict_types(actual: &Type, expected: &Type) -> bool {
        match (actual, expected) {
            (
                Type::True
                | Type::False
                | Type::Primitive {
                    primitive_type: Primitive::Bool,
                },
                Type::True
                | Type::False
                | Type::Primitive {
                    primitive_type: Primitive::Bool,
                },
            ) => true,
            (
                Type::Set {
                    element_type: Some(ety1),
                },
                Type::Set {
                    element_type: Some(ety2),
                },
            ) => Self::unify_strict_types(ety1, ety2),
            (
                Type::EntityOrRecord(EntityRecordKind::Record {
                    attrs: attrs1,
                    open_attributes: open1,
                }),
                Type::EntityOrRecord(EntityRecordKind::Record {
                    attrs: attrs2,
                    open_attributes: open2,
                }),
            ) => {
                let keys1 = attrs1.attrs.keys().collect::<HashSet<_>>();
                let keys2 = attrs2.attrs.keys().collect::<HashSet<_>>();
                open1 == open2
                    && keys1 == keys2
                    && attrs1.iter().all(|(k, attr1)| {
                        // PANIC SAFETY: The attribute keys sets are equal. `k` is a key in `attr1`, so it must be a key in `attrs2`.
                        #[allow(clippy::expect_used)]
                        let attr2 = attrs2
                            .get_attr(k)
                            .expect("Guarded by `keys1` == `keys2`, and `k` is a key in `keys1`.");
                        attr2.is_required == attr1.is_required
                            && Self::unify_strict_types(&attr1.attr_type, &attr2.attr_type)
                    })
            }
            _ => actual == expected,
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
                ExprBuilder::with_data(Some(Type::possibly_unspecified_entity_reference(
                    request_env.principal.clone(),
                )))
                .with_same_source_info(e)
                .var(Var::Principal),
            ),
            // While the EntityUID for Action is held in the request context,
            // entity types do not consider the id of the entity (only the
            // entity type), so the type of Action is only the entity type name
            // taken from the euid.
            ExprKind::Var(Var::Action) => {
                let ty = if matches!(request_env.action.entity_type(), EntityType::Unspecified) {
                    // The action entity may be unspecified. In this case it has
                    // type AnyEntity
                    Some(Type::any_entity_reference())
                } else {
                    // This returns `None` if the action entity is not defined
                    // in the schema which will cause a typecheck fail in the
                    // match below.
                    Type::euid_literal(request_env.action.clone(), self.schema)
                };

                match ty {
                    Some(ty) => TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(ty))
                            .with_same_source_info(e)
                            .var(Var::Action),
                    ),
                    None => TypecheckAnswer::fail(
                        ExprBuilder::new().with_same_source_info(e).var(Var::Action),
                    ),
                }
            }
            ExprKind::Var(Var::Resource) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::possibly_unspecified_entity_reference(
                    request_env.resource.clone(),
                )))
                .with_same_source_info(e)
                .var(Var::Resource),
            ),
            ExprKind::Var(Var::Context) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::record_with_attributes(
                    request_env.context.clone(),
                    OpenTag::ClosedAttributes,
                )))
                .with_same_source_info(e)
                .var(Var::Context),
            ),
            ExprKind::Unknown {
                name,
                type_annotation,
            } => TypecheckAnswer::fail(
                ExprBuilder::with_data(None).unknown(name.clone(), type_annotation.clone()),
            ),
            // Template Slots, always has to be an entity.
            ExprKind::Slot(slotid) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(if slotid.is_principal() {
                    request_env
                        .principal_slot
                        .clone()
                        .map(Type::possibly_unspecified_entity_reference)
                        .unwrap_or(Type::any_entity_reference())
                } else if slotid.is_resource() {
                    request_env
                        .resource_slot
                        .clone()
                        .map(Type::possibly_unspecified_entity_reference)
                        .unwrap_or(Type::any_entity_reference())
                } else {
                    Type::any_entity_reference()
                }))
                .with_same_source_info(e)
                .slot(*slotid),
            ),

            // Literal booleans get singleton type according to their value.
            ExprKind::Lit(Literal::Bool(val)) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::singleton_boolean(*val)))
                    .with_same_source_info(e)
                    .val(*val),
            ),
            // Other literal primitive values have the type of that primitive value.
            ExprKind::Lit(Literal::Long(val)) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::primitive_long()))
                    .with_same_source_info(e)
                    .val(*val),
            ),
            ExprKind::Lit(Literal::String(val)) => TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::primitive_string()))
                    .with_same_source_info(e)
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
                    Some(ty) => TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(ty))
                            .with_same_source_info(e)
                            .val(euid.clone()),
                    ),
                    None => TypecheckAnswer::fail(
                        ExprBuilder::new()
                            .with_same_source_info(e)
                            .val(euid.clone()),
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
                        // We have to build a type annotated `else` branch for
                        // strict typechecking, but we want to throw away the
                        // errors. This could instead  ignore the `else` if we
                        // update our Dafny formalism to verify that this is
                        // correct.
                        let mut errs_else = Vec::new();
                        let ans_else =
                            self.typecheck(request_env, prior_eff, else_expr, &mut errs_else);

                        ans_then.then_typecheck(|typ_then, eff_then| {
                            match ans_else.into_typed_expr() {
                                Some(ety) => {
                                    TypecheckAnswer::success_with_effect(
                                        ExprBuilder::with_data(typ_then.data().clone())
                                            .with_same_source_info(e)
                                            .ite(typ_test, typ_then, ety),
                                        // The output effect of the whole `if` expression also
                                        // needs to contain the effect of the condition.
                                        eff_then.union(&eff_test),
                                    )
                                }
                                // We might have hit the recursion limit only on
                                // the `else` branch. Unfortunate since that
                                // shouldn't effect typechecking, but we still
                                // need to exit to avoid a crash.
                                None => TypecheckAnswer::RecursionLimit,
                            }
                        })
                    } else if typ_test.data() == &Some(Type::singleton_boolean(false)) {
                        // The `else` branch cannot use the `test` effect since
                        // we know in the `else` branch that the condition
                        // evaluated to `false`. It still can use the original
                        // prior effect.
                        let ans_else =
                            self.typecheck(request_env, prior_eff, else_expr, type_errors);

                        // Annotating types but ignoring errors in the `then` branch.
                        let mut errs_then = Vec::new();
                        let ans_then = self.typecheck(
                            request_env,
                            &prior_eff.union(&eff_test),
                            then_expr,
                            &mut errs_then,
                        );

                        ans_else.then_typecheck(|typ_else, eff_else| {
                            match ans_then.into_typed_expr() {
                                Some(ety) => TypecheckAnswer::success_with_effect(
                                    ExprBuilder::with_data(typ_else.data().clone())
                                        .with_same_source_info(e)
                                        .ite(typ_test, ety, typ_else),
                                    eff_else,
                                ),
                                // We might have hit the recursion limit only on
                                // the `then` branch.
                                None => TypecheckAnswer::RecursionLimit,
                            }
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
                                    .with_same_source_info(e)
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
                            );
                            ans_right.then_typecheck(|typ_right, eff_right| {
                                match (typ_left.data(), typ_right.data()) {
                                    // The second argument is false, so the `&&`
                                    // is false. The effect is empty for the
                                    // same reason as when the first argument
                                    // was false.
                                    (Some(_), Some(Type::False)) => TypecheckAnswer::success(
                                        ExprBuilder::with_data(Some(Type::False))
                                            .with_same_source_info(e)
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
                                                .with_same_source_info(e)
                                                .and(typ_left, typ_right),
                                            eff_left.union(&eff_right),
                                        )
                                    }
                                    (Some(Type::True), Some(_)) => {
                                        TypecheckAnswer::success_with_effect(
                                            ExprBuilder::with_data(typ_right.data().clone())
                                                .with_same_source_info(e)
                                                .and(typ_left, typ_right),
                                            eff_right.union(&eff_right),
                                        )
                                    }

                                    // Neither argument was true or false, so we only
                                    // know the result type is boolean.
                                    (Some(_), Some(_)) => TypecheckAnswer::success_with_effect(
                                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                            .with_same_source_info(e)
                                            .and(typ_left, typ_right),
                                        eff_left.union(&eff_right),
                                    ),

                                    // One or both of the left and the right failed to
                                    // typecheck, so the `&&` expression also fails.
                                    _ => TypecheckAnswer::fail(
                                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                            .with_same_source_info(e)
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
                                            .with_same_source_info(e)
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
                                            .with_same_source_info(e)
                                            .or(ty_expr_left, ty_expr_right),
                                        eff_left,
                                    )
                                }
                                (Some(Type::False), Some(typ_right)) => {
                                    TypecheckAnswer::success_with_effect(
                                        ExprBuilder::with_data(Some(typ_right.clone()))
                                            .with_same_source_info(e)
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
                                        .with_same_source_info(e)
                                        .or(ty_expr_left, ty_expr_right),
                                    eff_right.intersect(&eff_left),
                                ),
                                _ => TypecheckAnswer::fail(
                                    ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                        .with_same_source_info(e)
                                        .or(ty_expr_left, ty_expr_right),
                                ),
                            }
                        })
                    }
                })
            }

            ExprKind::UnaryApp { .. } => {
                self.typecheck_unary(request_env, prior_eff, e, type_errors)
            }
            ExprKind::BinaryApp { .. } => {
                self.typecheck_binary(request_env, prior_eff, e, type_errors)
            }
            ExprKind::MulByConst { .. } => {
                self.typecheck_mul(request_env, prior_eff, e, type_errors)
            }
            ExprKind::ExtensionFunctionApp { .. } => {
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
                );

                actual.then_typecheck(|typ_expr_actual, _| match typ_expr_actual.data() {
                    Some(typ_actual) => {
                        let all_attrs = typ_actual.all_attributes(self.schema);
                        let attr_ty = Type::lookup_attribute_type(self.schema, typ_actual, attr);
                        let annot_expr = ExprBuilder::with_data(
                            attr_ty.clone().map(|attr_ty| attr_ty.attr_type),
                        )
                        .with_same_source_info(e)
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
                            .with_same_source_info(e)
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
                                        .with_same_source_info(e)
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
                                .with_same_source_info(e)
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
                                .with_same_source_info(e)
                                .has_attr(typ_expr_actual, attr.clone()),
                            ),
                        }
                    }
                    None => TypecheckAnswer::fail(
                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                            .with_same_source_info(e)
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
                );
                actual.then_typecheck(|actual_expr_ty, _| {
                    TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                            .with_same_source_info(e)
                            // FIXME: `pattern` contains an `Arc<Vec<...>>` that
                            // could be cloned cheap, but this reallocated the
                            // pattern vec. Need a different constructor.
                            .like(actual_expr_ty, pattern.iter().cloned()),
                    )
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
                        Some(elem_lub) => TypecheckAnswer::success(
                            ExprBuilder::with_data(Some(Type::set(elem_lub)))
                                .with_same_source_info(e)
                                .set(elem_expr_types),
                        ),
                        None => TypecheckAnswer::fail(
                            ExprBuilder::new()
                                .with_same_source_info(e)
                                .set(elem_expr_types),
                        ),
                    }
                })
            }

            // For records, each (attribute, value) pair in the initializer need
            // to be individually accounted for in the record type.
            ExprKind::Record { pairs } => {
                // Typecheck each attribute initializer expression individually.
                let record_attr_tys = pairs
                    .iter()
                    .map(|(_, value)| self.typecheck(request_env, prior_eff, value, type_errors));
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
                        let t = pairs
                            .iter()
                            .map(|(attr, _)| attr.clone())
                            .zip(record_attr_expr_tys);
                        match record_attr_tys {
                            Some(record_attr_tys) => {
                                // Given the attribute types which we know know
                                // exist, we pair them with the corresponding
                                // attribute names to get a record type.
                                let record_attrs = pairs.iter().map(|(id, _)| id.clone());
                                let record_type_entries =
                                    std::iter::zip(record_attrs, record_attr_tys);
                                TypecheckAnswer::success(
                                    ExprBuilder::with_data(Some(
                                        Type::record_with_required_attributes(
                                            record_type_entries,
                                            OpenTag::ClosedAttributes,
                                        ),
                                    ))
                                    .with_same_source_info(e)
                                    .record(t),
                                )
                            }
                            None => TypecheckAnswer::fail(
                                ExprBuilder::with_data(None)
                                    .with_same_source_info(e)
                                    .record(t),
                            ),
                        }
                    },
                )
            }
        }
    }

    /// A utility called by the main typecheck method to handle binary operator
    /// application.
    fn typecheck_binary<'b>(
        &self,
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        bin_expr: &'b Expr,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
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
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(Some(self.type_of_equality(
                                request_env,
                                arg1,
                                lhs_ty.data().clone(),
                                arg2,
                                rhs_ty.data().clone(),
                            )))
                            .with_same_source_info(bin_expr)
                            .binary_app(*op, lhs_ty, rhs_ty),
                        )
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
                );
                ans_arg1.then_typecheck(|expr_ty_arg1, _| {
                    let ans_arg2 = self.expect_type(
                        request_env,
                        prior_eff,
                        arg2,
                        Type::primitive_long(),
                        type_errors,
                    );
                    ans_arg2.then_typecheck(|expr_ty_arg2, _| {
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                .with_same_source_info(bin_expr)
                                .binary_app(*op, expr_ty_arg1, expr_ty_arg2),
                        )
                    })
                })
            }

            BinaryOp::Add | BinaryOp::Sub => {
                let ans_arg1 = self.expect_type(
                    request_env,
                    prior_eff,
                    arg1,
                    Type::primitive_long(),
                    type_errors,
                );
                ans_arg1.then_typecheck(|expr_ty_arg1, _| {
                    let ans_arg2 = self.expect_type(
                        request_env,
                        prior_eff,
                        arg2,
                        Type::primitive_long(),
                        type_errors,
                    );
                    ans_arg2.then_typecheck(|expr_ty_arg2, _| {
                        TypecheckAnswer::success(
                            ExprBuilder::with_data(Some(Type::primitive_long()))
                                .with_same_source_info(bin_expr)
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
                self.expect_type(request_env, prior_eff, arg1, Type::any_set(), type_errors)
                    .then_typecheck(|expr_ty_arg1, _| {
                        // The second argument may be any type. We do not care if the element type cannot be in the set.
                        self.typecheck(request_env, prior_eff, arg2, type_errors)
                            .then_typecheck(|expr_ty_arg2, _| {
                                TypecheckAnswer::success(
                                    ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                        .with_same_source_info(bin_expr)
                                        .binary_app(*op, expr_ty_arg1, expr_ty_arg2),
                                )
                            })
                    })
            }

            BinaryOp::ContainsAll | BinaryOp::ContainsAny => {
                // Both arguments to a `containsAll` or `containsAny` must be sets.
                self.expect_type(request_env, prior_eff, arg1, Type::any_set(), type_errors)
                    .then_typecheck(|expr_ty_arg1, _| {
                        self.expect_type(request_env, prior_eff, arg2, Type::any_set(), type_errors)
                            .then_typecheck(|expr_ty_arg2, _| {
                                TypecheckAnswer::success(
                                    ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                        .with_same_source_info(bin_expr)
                                        .binary_app(*op, expr_ty_arg1, expr_ty_arg2),
                                )
                            })
                    })
            }
        }
    }

    /// Like `typecheck_binary()`, but for multiplication, which isn't
    /// technically a `BinaryOp`
    fn typecheck_mul<'b>(
        &self,
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        mul_expr: &'b Expr,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
        let ExprKind::MulByConst { arg, constant } = mul_expr.expr_kind() else {
            panic!("`typecheck_mul` called with an expression kind other than `MulByConst`");
        };

        let ans_arg = self.expect_type(
            request_env,
            prior_eff,
            arg,
            Type::primitive_long(),
            type_errors,
        );
        ans_arg.then_typecheck(|arg_expr_ty, _| {
            TypecheckAnswer::success({
                ExprBuilder::with_data(Some(Type::primitive_long()))
                    .with_same_source_info(mul_expr)
                    .mul(arg_expr_ty, *constant)
            })
        })
    }

    /// Get the type for an `==` expression given the input types.
    fn type_of_equality<'b>(
        &self,
        request_env: &RequestEnv,
        lhs_expr: &'b Expr,
        lhs_ty: Option<Type>,
        rhs_expr: &'b Expr,
        rhs_ty: Option<Type>,
    ) -> Type {
        // If we know the types are disjoint, then we can return give the
        // expression type False. See `are_types_disjoint` definition for
        // explanation of why fewer types are disjoint than may be expected.
        let disjoint_types = match (&lhs_ty, &rhs_ty) {
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
                    .map(|ty| Type::must_be_specified_entity(&ty))
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
        );

        let lhs_typechecked = ty_lhs.typechecked();
        let rhs_typechecked = ty_rhs.typechecked();

        ty_lhs.then_typecheck(|lhs_expr, _lhs_effects| {
            ty_rhs.then_typecheck(|rhs_expr, _rhs_effects| {
                let left_is_unspecified = Typechecker::is_unspecified_entity(request_env, lhs);
                let right_is_specified = match rhs_expr.data() {
                    Some(Type::Set { element_type }) => element_type.as_ref().map(|t| t.as_ref()),
                    ty => ty.as_ref(),
                }
                .map(Type::must_be_specified_entity)
                .unwrap_or(false);
                // If either failed to typecheck, then the whole expression fails to
                // typecheck.  Otherwise, proceed to special cases.
                if !lhs_typechecked || !rhs_typechecked {
                    TypecheckAnswer::fail(
                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                            .with_same_source_info(in_expr)
                            .is_in(lhs_expr, rhs_expr),
                    )
                } else if left_is_unspecified && right_is_specified {
                    TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(Type::singleton_boolean(false)))
                            .with_same_source_info(in_expr)
                            .is_in(lhs_expr, rhs_expr),
                    )
                } else {
                    let lhs_as_euid_lit =
                        Typechecker::replace_action_var_with_euid(request_env, lhs);
                    let rhs_as_euid_lit =
                        Typechecker::replace_action_var_with_euid(request_env, rhs);
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
                            (**euid0).clone(),
                            [rhs_as_euid_lit.as_ref()],
                            in_expr,
                            lhs_expr,
                            rhs_expr,
                        ),

                        // As above, with the same complication, but applied to set of entities.
                        (ExprKind::Lit(Literal::EntityUID(euid)), ExprKind::Set(elems)) => self
                            .type_of_entity_literal_in_entity_literals(
                                request_env,
                                (**euid).clone(),
                                elems.as_ref(),
                                in_expr,
                                lhs_expr,
                                rhs_expr,
                            ),

                        // If none of the cases apply, then all we know is that `in` has
                        // type boolean.
                        _ => TypecheckAnswer::success(
                            ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                .with_same_source_info(in_expr)
                                .is_in(lhs_expr, rhs_expr),
                        ),
                    }
                }
            })
        })
    }

    // Given an expression, if that expression is a literal or the `action` head
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
            ExprKind::Var(Var::Principal) => matches!(query_env.principal, EntityType::Unspecified),
            ExprKind::Var(Var::Resource) => matches!(query_env.resource, EntityType::Unspecified),
            ExprKind::Var(Var::Action) => {
                matches!(query_env.action.entity_type(), EntityType::Unspecified)
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
            let var_euid = if matches!(lhs_var, Var::Principal) {
                request_env.principal
            } else {
                request_env.resource
            };
            let descendants = self
                .schema
                .get_entities_in_set(PrincipalOrResourceHeadVar::PrincipalOrResource, rhs);
            match var_euid {
                EntityType::Concrete(var_name) => Typechecker::entity_in_descendants(
                    var_name,
                    descendants,
                    in_expr,
                    lhs_expr,
                    rhs_expr,
                ),
                // Unspecified entities will be detected by a different part of the validator.
                // Still return `TypecheckFail` so that typechecking is not considered successful.
                EntityType::Unspecified => TypecheckAnswer::fail(
                    ExprBuilder::with_data(Some(Type::primitive_boolean()))
                        .with_same_source_info(in_expr)
                        .is_in(lhs_expr, rhs_expr),
                ),
            }
        } else {
            // One or more of the elements on the right is not an entity
            // literal, so this does not apply. The `in` is still valid, so
            // typechecking succeeds with type Boolean.
            TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::primitive_boolean()))
                    .with_same_source_info(in_expr)
                    .is_in(lhs_expr, rhs_expr),
            )
        }
    }

    fn type_of_entity_literal_in_entity_literals<'b, 'c>(
        &self,
        request_env: &RequestEnv,
        lhs_euid: EntityUID,
        rhs_elems: impl IntoIterator<Item = &'b Expr>,
        in_expr: &Expr,
        lhs_expr: Expr<Option<Type>>,
        rhs_expr: Expr<Option<Type>>,
    ) -> TypecheckAnswer<'c> {
        if let Some(rhs) = Typechecker::euids_from_euid_literals_or_action(request_env, rhs_elems) {
            match lhs_euid.entity_type() {
                EntityType::Concrete(name) => {
                    // We don't want to apply the action hierarchy check to
                    // non-action entities.  We have a set of entities, so We
                    // can apply the check as long as any are actions. The
                    // non-actions are omitted from the check, but they can
                    // never be an ancestor of `Action`.
                    let lhs_is_action = is_action_entity_type(name);
                    let (actions, non_actions): (Vec<_>, Vec<_>) =
                        rhs.into_iter().partition(|e| match e.entity_type() {
                            EntityType::Concrete(e_name) => is_action_entity_type(e_name),
                            EntityType::Unspecified => false,
                        });
                    if lhs_is_action && !actions.is_empty() {
                        self.type_of_euid_in_euids(
                            lhs_euid,
                            actions,
                            ActionHeadVar::Action,
                            in_expr,
                            lhs_expr,
                            rhs_expr,
                        )
                    } else if !lhs_is_action && !non_actions.is_empty() {
                        self.type_of_euid_in_euids(
                            lhs_euid,
                            non_actions,
                            PrincipalOrResourceHeadVar::PrincipalOrResource,
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
                                .with_same_source_info(in_expr)
                                .is_in(lhs_expr, rhs_expr),
                        )
                    }
                }
                // Unspecified entities will be detected by a different part of the validator.
                // Still return `TypecheckFail` so that typechecking is not considered successful.
                EntityType::Unspecified => TypecheckAnswer::fail(
                    ExprBuilder::with_data(Some(Type::primitive_boolean()))
                        .with_same_source_info(in_expr)
                        .is_in(lhs_expr, rhs_expr),
                ),
            }
        } else {
            // One or more of the elements on the right is not an entity
            // literal, so this does not apply. The `in` is still valid, so
            // typechecking succeeds with type Boolean.
            TypecheckAnswer::success(
                ExprBuilder::with_data(Some(Type::primitive_boolean()))
                    .with_same_source_info(in_expr)
                    .is_in(lhs_expr, rhs_expr),
            )
        }
    }

    // Get the type for `in` when it is applied to an EUID literal and a set of
    // EUID literals. The type depends on if we know the LHS entity literal
    // cannot be in the RHS set.
    fn type_of_euid_in_euids<'b, K>(
        &self,
        lhs: EntityUID,
        rhs: impl IntoIterator<Item = EntityUID>,
        var: impl HeadVar<K>,
        in_expr: &Expr,
        lhs_expr: Expr<Option<Type>>,
        rhs_expr: Expr<Option<Type>>,
    ) -> TypecheckAnswer<'b>
    where
        K: Clone + PartialEq,
    {
        if let Some(lhs_entity) = self.schema.get_entity_eq(var, lhs) {
            let rhs_descendants = self.schema.get_entities_in_set(var, rhs);
            Typechecker::entity_in_descendants(
                &lhs_entity,
                rhs_descendants,
                in_expr,
                lhs_expr,
                rhs_expr,
            )
        } else {
            // Unspecified entities will be detected by a different part of the validator.
            // Still return `TypecheckFail` so that typechecking is not considered successful.
            TypecheckAnswer::fail(
                ExprBuilder::with_data(Some(Type::primitive_boolean()))
                    .with_same_source_info(in_expr)
                    .is_in(lhs_expr, rhs_expr),
            )
        }
    }

    /// Check if the entity is in the list of descendants. Return the singleton
    /// type false if it is not, and boolean otherwise.
    fn entity_in_descendants<'b, K>(
        lhs_entity: &K,
        rhs_descendants: impl IntoIterator<Item = K>,
        in_expr: &Expr,
        lhs_expr: Expr<Option<Type>>,
        rhs_expr: Expr<Option<Type>>,
    ) -> TypecheckAnswer<'b>
    where
        K: PartialEq,
    {
        let is_var_in_descendants = rhs_descendants.into_iter().any(|e| &e == lhs_entity);
        TypecheckAnswer::success(
            ExprBuilder::with_data(Some(if is_var_in_descendants {
                Type::primitive_boolean()
            } else {
                Type::singleton_boolean(false)
            }))
            .with_same_source_info(in_expr)
            .is_in(lhs_expr, rhs_expr),
        )
    }

    /// A utility called by the main typecheck method to handle unary operator
    /// application.
    fn typecheck_unary<'b>(
        &self,
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        unary_expr: &'b Expr,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
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
                );
                ans_arg.then_typecheck(|typ_expr_arg, _| match typ_expr_arg.data() {
                    Some(typ_arg) => {
                        TypecheckAnswer::success(if typ_arg == &Type::singleton_boolean(true) {
                            ExprBuilder::with_data(Some(Type::singleton_boolean(false)))
                                .with_same_source_info(unary_expr)
                                .not(typ_expr_arg)
                        } else if typ_arg == &Type::singleton_boolean(false) {
                            ExprBuilder::with_data(Some(Type::singleton_boolean(true)))
                                .with_same_source_info(unary_expr)
                                .not(typ_expr_arg)
                        } else {
                            ExprBuilder::with_data(Some(Type::primitive_boolean()))
                                .with_same_source_info(unary_expr)
                                .not(typ_expr_arg)
                        })
                    }
                    None => TypecheckAnswer::fail(
                        ExprBuilder::with_data(Some(Type::primitive_boolean()))
                            .with_same_source_info(unary_expr)
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
                );
                ans_arg.then_typecheck(|typ_expr_arg, _| {
                    TypecheckAnswer::success(
                        ExprBuilder::with_data(Some(Type::primitive_long()))
                            .with_same_source_info(unary_expr)
                            .neg(typ_expr_arg),
                    )
                })
            }
        }
    }

    /// Check that an expression has a type that is a subtype of one of the
    /// given types. If not, generate a type error and return TypecheckFail.
    /// Return the TypecheckSuccess with the type otherwise.
    fn expect_one_of_types<'b>(
        &self,
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        expr: &'b Expr,
        expected: &[Type],
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
        let actual = self.typecheck(request_env, prior_eff, expr, type_errors);
        actual.then_typecheck(|mut typ_actual, eff_actual| match typ_actual.data() {
            Some(actual_ty) => {
                if !expected
                    .iter()
                    .any(|expected_ty| Type::is_subtype(self.schema, actual_ty, expected_ty))
                {
                    type_errors.push(TypeError::expected_one_of_types(
                        expr.clone(),
                        expected.to_vec(),
                        actual_ty.clone(),
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
    fn expect_type<'b>(
        &self,
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        expr: &'b Expr,
        expected: Type,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
        self.expect_one_of_types(request_env, prior_eff, expr, &[expected], type_errors)
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
                let lub = Type::reduce_to_least_upper_bound(self.schema, &typechecked_types);
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
            ExprKind::Var(Var::Action) => Cow::Owned(Expr::val(request_env.action.clone())),
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
        match extension_funcs.get(0) {
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
    fn typecheck_extension<'b>(
        &self,
        request_env: &RequestEnv,
        prior_eff: &EffectSet<'b>,
        ext_expr: &'b Expr,
        type_errors: &mut Vec<TypeError>,
    ) -> TypecheckAnswer<'b> {
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
                if failed {
                    match typed_arg_exprs(type_errors) {
                        Some(exprs) => TypecheckAnswer::fail(
                            ExprBuilder::with_data(Some(ret_ty.clone()))
                                .with_same_source_info(ext_expr)
                                .call_extension_fn(fn_name.clone(), exprs),
                        ),
                        None => TypecheckAnswer::RecursionLimit,
                    }
                } else {
                    let typechecked_args = zip(args.as_ref(), arg_tys).map(|(arg, ty)| {
                        self.expect_type(request_env, prior_eff, arg, ty.clone(), type_errors)
                    });
                    TypecheckAnswer::sequence_all_then_typecheck(
                        typechecked_args,
                        |arg_exprs_effects| {
                            let (typed_arg_exprs, _): (Vec<Expr<Option<Type>>>, Vec<_>) =
                                arg_exprs_effects.into_iter().unzip();
                            TypecheckAnswer::success(
                                ExprBuilder::with_data(Some(ret_ty.clone()))
                                    .with_same_source_info(ext_expr)
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
                            .with_same_source_info(ext_expr)
                            .call_extension_fn(fn_name.clone(), typed_args),
                    ),
                    None => TypecheckAnswer::RecursionLimit,
                }
            }
        }
    }
}
