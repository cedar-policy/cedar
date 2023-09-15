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

//! This module contains the Cedar evaluator.

use crate::ast::*;
use crate::entities::{Dereference, Entities, EntityDataSource};
use crate::extensions::Extensions;
use std::sync::Arc;

mod err;
pub(crate) use err::*;
pub use err::{EvaluationError, EvaluationErrorKind};
use itertools::Either;
use smol_str::SmolStr;

const REQUIRED_STACK_SPACE: usize = 1024 * 100;

// PANIC SAFETY `Name`s in here are valid `Name`s
#[allow(clippy::expect_used)]
mod names {
    use super::Name;
    lazy_static::lazy_static! {
        pub static ref ANY_ENTITY_TYPE : Name = Name::parse_unqualified_name("any_entity_type").expect("valid identifier");
    }
}

/// Evaluator object.
///
/// Conceptually keeps the evaluation environment as part of its internal state,
/// because we will be repeatedly invoking the evaluator on every policy in a
/// Slice.
pub struct Evaluator<'e, T: EntityDataSource> {
    /// `Principal` for the current request
    principal: EntityUIDEntry,
    /// `Action` for the current request
    action: EntityUIDEntry,
    /// `Resource` for the current request
    resource: EntityUIDEntry,
    /// `Context` for the current request; this will be a Record type
    context: PartialValue,
    /// Entities which we use to resolve entity references.
    ///
    /// This is a reference, because the `Evaluator` doesn't need ownership of
    /// (or need to modify) the `Entities`. One advantage of this is that you
    /// could create multiple `Evaluator`s without copying the `Entities`.
    entities: &'e T,
    /// Extensions which are active for this evaluation
    extensions: &'e Extensions<'e>,
}

/// Evaluator for "restricted" expressions. See notes on `RestrictedExpr`.
#[derive(Debug)]
pub struct RestrictedEvaluator<'e> {
    /// Extensions which are active for this evaluation
    extensions: &'e Extensions<'e>,
}

impl<'e> RestrictedEvaluator<'e> {
    /// Create a fresh evaluator for evaluating "restricted" expressions
    pub fn new(extensions: &'e Extensions<'e>) -> Self {
        Self { extensions }
    }

    /// Interpret a `RestrictedExpr` into a `Value` in this evaluation environment.
    ///
    /// May return an error, for instance if an extension function returns an error
    pub fn interpret(&self, e: BorrowedRestrictedExpr<'_>) -> Result<Value> {
        match self.partial_interpret(e)? {
            PartialValue::Value(v) => Ok(v),
            PartialValue::Residual(r) => Err(EvaluationError::non_value(r)),
        }
    }

    /// Interpret a `RestrictedExpr` into a `Value` in this evaluation environment.
    ///
    /// May return an error, for instance if an extension function returns an error
    pub fn partial_interpret(&self, e: BorrowedRestrictedExpr<'_>) -> Result<PartialValue> {
        stack_size_check()?;

        match e.as_ref().expr_kind() {
            ExprKind::Lit(lit) => Ok(lit.clone().into()),
            ExprKind::Set(items) => {
                let vals = items
                    .iter()
                    .map(|item| self.partial_interpret(BorrowedRestrictedExpr::new_unchecked(item))) // assuming the invariant holds for `e`, it will hold here
                    .collect::<Result<Vec<_>>>()?;
                match split(vals) {
                    Either::Left(values) => Ok(Value::Set(values.collect()).into()),
                    Either::Right(residuals) => Ok(Expr::set(residuals).into()),
                }
            }
            ExprKind::Unknown{name, type_annotation} => Ok(PartialValue::Residual(Expr::unknown_with_type(name.clone(), type_annotation.clone()))),
            ExprKind::Record { pairs } => {
                let map = pairs
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.partial_interpret(BorrowedRestrictedExpr::new_unchecked(v))?))) // assuming the invariant holds for `e`, it will hold here
                    .collect::<Result<Vec<_>>>()?;
                let (names, attrs) : (Vec<_>, Vec<_>) = map.into_iter().unzip();
                match split(attrs) {
                    Either::Left(values) => Ok(Value::Record(Arc::new(names.into_iter().zip(values).collect())).into()),
                    Either::Right(residuals) => Ok(Expr::record(names.into_iter().zip(residuals)).into()),
                }
            }
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let args = args
                    .iter()
                    .map(|arg| self.partial_interpret(BorrowedRestrictedExpr::new_unchecked(arg))) // assuming the invariant holds for `e`, it will hold here
                    .collect::<Result<Vec<_>>>()?;
                match split(args) {
                    Either::Left(values) => {
                        let values : Vec<_> = values.collect();
                        let efunc = self.extensions.func(fn_name)?;
                        efunc.call(&values)
                    },
                    Either::Right(residuals) => Ok(Expr::call_extension_fn(fn_name.clone(), residuals.collect()).into()),
                }
            },
            // PANIC SAFETY Unreachable via invariant on restricted expressions
            #[allow(clippy::unreachable)]
            expr => unreachable!("internal invariant violation: BorrowedRestrictedExpr somehow contained this expr case: {expr:?}"),
        }
    }
}

impl Entity {
    /// Evaluate the attributes in the entity, using the given evaluator
    pub fn eval_attrs(self, eval: &RestrictedEvaluator<'_>) -> Result<Entity<PartialValue>> {
        self.map_attrs(|v| eval.partial_interpret(v.as_borrowed()))
    }
}

impl Entities {
    /// Evaluate all the attributes in the entities, using the given extensions, turning this into an
    /// `Entities<PartialValue>`.
    pub fn eval_attrs(self, extensions: &Extensions<'_>) -> Result<Entities<PartialValue>> {
        let eval = RestrictedEvaluator::new(extensions);
        self.map_attrs(|v| v.eval_attrs(&eval))
    }
}

impl<'q, 'e, T: EntityDataSource> Evaluator<'e, T> {
    /// Create a fresh `Evaluator` for the given `request`, which uses the given
    /// `Entities` to resolve entity references. Use the given `Extension`s when
    /// evaluating the request.
    ///
    /// (An `Entities` is the entity-hierarchy portion of a `Slice`, without the
    /// policies.)
    pub fn new(q: &'q Request, entities: &'e T, extensions: &'e Extensions<'e>) -> Result<Self> {
        Ok(Self {
            principal: q.principal().clone(),
            action: q.action().clone(),
            resource: q.resource().clone(),
            context: {
                // evaluate each of the context attributes in an evaluator
                // for "restricted" expressions.
                // This prohibits them from referring to the `request`,
                // ie, the variables `principal`, `resource`, etc.
                // For more, see notes on `RestrictedExpr`.
                let restricted_eval = RestrictedEvaluator::new(extensions);
                match &q.context {
                    None => PartialValue::Residual(Expr::unknown("context")),
                    Some(ctxt) => restricted_eval.partial_interpret(ctxt.as_ref().as_borrowed())?,
                }
            },
            entities,
            extensions,
        })
    }

    /// Evaluate the given `Policy`, returning either a bool or an error.
    /// The bool indicates whether the policy applies, ie, "is satisfied" for the
    /// current `request`.
    /// This is _different than_ "if the current `request` should be allowed" --
    /// it doesn't consider whether we're processing a `Permit` policy or a
    /// `Forbid` policy.
    pub fn evaluate(&self, p: &Policy) -> Result<bool> {
        self.interpret(&p.condition(), p.env())?.get_as_bool()
    }

    /// Partially evaluate the given `Policy`, returning one of:
    /// 1) A boolean, if complete evaluation was possible
    /// 2) An error, if the policy is guaranteed to error
    /// 3) A residual, if complete evaluation was impossible
    /// The bool indicates whether the policy applies, ie, "is satisfied" for the
    /// current `request`.
    /// This is _different than_ "if the current `request` should be allowed" --
    /// it doesn't consider whether we're processing a `Permit` policy or a
    /// `Forbid` policy.
    pub fn partial_evaluate(&self, p: &Policy) -> Result<Either<bool, Expr>> {
        match self.partial_interpret(&p.condition(), p.env())? {
            PartialValue::Value(v) => v.get_as_bool().map(Either::Left),
            PartialValue::Residual(e) => Ok(Either::Right(e)),
        }
    }

    /// Run an expression as far as possible.
    /// however, if an error is encountered, instead of error-ing, wrap the error
    /// in a call the `error` extension function.
    pub fn run_to_error(
        &self,
        e: &Expr,
        slots: &SlotEnv,
    ) -> (PartialValue, Option<EvaluationError>) {
        match self.partial_interpret(e, slots) {
            Ok(e) => (e, None),
            Err(err) => {
                let arg = Expr::val(format!("{err}"));
                // PANIC SAFETY: Input to `parse` is fully static and a valid extension function name
                #[allow(clippy::unwrap_used)]
                let fn_name = "error".parse().unwrap();
                (
                    PartialValue::Residual(Expr::call_extension_fn(fn_name, vec![arg])),
                    Some(err),
                )
            }
        }
    }

    /// Interpret an `Expr` into a `Value` in this evaluation environment.
    ///
    /// Ensures the result is not a residual.
    /// May return an error, for instance if the `Expr` tries to access an
    /// attribute that doesn't exist.
    pub fn interpret(&self, e: &Expr, slots: &SlotEnv) -> Result<Value> {
        match self.partial_interpret(e, slots)? {
            PartialValue::Value(v) => Ok(v),
            PartialValue::Residual(r) => Err(EvaluationError::non_value(r)),
        }
    }

    /// Interpret an `Expr` into a `Value` in this evaluation environment.
    ///
    /// May return a residual expression, if the input expression is symbolic.
    /// May return an error, for instance if the `Expr` tries to access an
    /// attribute that doesn't exist.
    pub fn partial_interpret(&self, e: &Expr, slots: &SlotEnv) -> Result<PartialValue> {
        stack_size_check()?;

        match e.expr_kind() {
            ExprKind::Lit(lit) => Ok(lit.clone().into()),
            ExprKind::Slot(id) => slots
                .get(id)
                .ok_or_else(|| err::EvaluationError::unlinked_slot(*id))
                .map(|euid| PartialValue::from(euid.clone())),
            ExprKind::Var(v) => match v {
                Var::Principal => Ok(self.principal.evaluate(*v)),
                Var::Action => Ok(self.action.evaluate(*v)),
                Var::Resource => Ok(self.resource.evaluate(*v)),
                Var::Context => Ok(self.context.clone()),
            },
            ExprKind::Unknown { .. } => Ok(PartialValue::Residual(e.clone())),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => self.eval_if(test_expr, then_expr, else_expr, slots),
            ExprKind::And { left, right } => {
                match self.partial_interpret(left, slots)? {
                    // PE Case
                    PartialValue::Residual(e) => Ok(PartialValue::Residual(Expr::and(
                        e,
                        self.run_to_error(right.as_ref(), slots).0.into(),
                    ))),
                    // Full eval case
                    PartialValue::Value(v) => {
                        if v.get_as_bool()? {
                            match self.partial_interpret(right, slots)? {
                                // you might think that `true && <residual>` can be optimized to `<residual>`, but this isn't true because
                                // <residual> must be boolean, or else it needs to type error. So return `true && <residual>` to ensure
                                // type check happens
                                PartialValue::Residual(right) => {
                                    Ok(PartialValue::Residual(Expr::and(Expr::val(true), right)))
                                }
                                // If it's an actual value, compute and
                                PartialValue::Value(v) => Ok(v.get_as_bool()?.into()),
                            }
                        } else {
                            // We can short circuit here
                            Ok(false.into())
                        }
                    }
                }
            }
            ExprKind::Or { left, right } => {
                match self.partial_interpret(left, slots)? {
                    // PE cases
                    PartialValue::Residual(r) => Ok(PartialValue::Residual(Expr::or(
                        r,
                        self.run_to_error(right, slots).0.into(),
                    ))),
                    // Full eval case
                    PartialValue::Value(lhs) => {
                        if lhs.get_as_bool()? {
                            // We can short circuit here
                            Ok(true.into())
                        } else {
                            match self.partial_interpret(right, slots)? {
                                PartialValue::Residual(rhs) =>
                                // you might think that `false || <residual>` can be optimized to `<residual>`, but this isn't true because
                                // <residual> must be boolean, or else it needs to type error. So return `false || <residual>` to ensure
                                // type check happens
                                {
                                    Ok(PartialValue::Residual(Expr::or(Expr::val(false), rhs)))
                                }
                                PartialValue::Value(v) => Ok(v.get_as_bool()?.into()),
                            }
                        }
                    }
                }
            }
            ExprKind::UnaryApp { op, arg } => match self.partial_interpret(arg, slots)? {
                PartialValue::Value(arg) => match op {
                    UnaryOp::Not => match arg.get_as_bool()? {
                        true => Ok(false.into()),
                        false => Ok(true.into()),
                    },
                    UnaryOp::Neg => {
                        let i = arg.get_as_long()?;
                        match i.checked_neg() {
                            Some(v) => Ok(v.into()),
                            None => Err(IntegerOverflowError::UnaryOp { op: *op, arg }.into()),
                        }
                    }
                },
                // NOTE, there was a bug here found during manual review. (I forgot to wrap in unary_app call)
                // Could be a nice target for fault injection
                PartialValue::Residual(r) => Ok(PartialValue::Residual(Expr::unary_app(*op, r))),
            },
            ExprKind::BinaryApp { op, arg1, arg2 } => {
                // NOTE: There are more precise partial eval opportunities here, esp w/ typed unknowns
                // Current limitations:
                //   Operators are not partially evaluated.
                let (arg1, arg2) = match (
                    self.partial_interpret(arg1, slots)?,
                    self.partial_interpret(arg2, slots)?,
                ) {
                    (PartialValue::Value(v1), PartialValue::Value(v2)) => (v1, v2),
                    (PartialValue::Value(v1), PartialValue::Residual(e2)) => {
                        return Ok(PartialValue::Residual(Expr::binary_app(*op, v1.into(), e2)))
                    }
                    (PartialValue::Residual(e1), PartialValue::Value(v2)) => {
                        return Ok(PartialValue::Residual(Expr::binary_app(*op, e1, v2.into())))
                    }
                    (PartialValue::Residual(e1), PartialValue::Residual(e2)) => {
                        return Ok(PartialValue::Residual(Expr::binary_app(*op, e1, e2)))
                    }
                };
                match op {
                    BinaryOp::Eq => Ok((arg1 == arg2).into()),
                    // comparison and arithmetic operators, which only work on Longs
                    BinaryOp::Less | BinaryOp::LessEq | BinaryOp::Add | BinaryOp::Sub => {
                        let i1 = arg1.get_as_long()?;
                        let i2 = arg2.get_as_long()?;
                        match op {
                            BinaryOp::Less => Ok((i1 < i2).into()),
                            BinaryOp::LessEq => Ok((i1 <= i2).into()),
                            BinaryOp::Add => match i1.checked_add(i2) {
                                Some(sum) => Ok(sum.into()),
                                None => Err(IntegerOverflowError::BinaryOp {
                                    op: *op,
                                    arg1,
                                    arg2,
                                }
                                .into()),
                            },
                            BinaryOp::Sub => match i1.checked_sub(i2) {
                                Some(diff) => Ok(diff.into()),
                                None => Err(IntegerOverflowError::BinaryOp {
                                    op: *op,
                                    arg1,
                                    arg2,
                                }
                                .into()),
                            },
                            // PANIC SAFETY `op` is checked to be one of the above
                            #[allow(clippy::unreachable)]
                            _ => {
                                unreachable!("Should have already checked that op was one of these")
                            }
                        }
                    }
                    // hierarchy membership operator; see note on `BinaryOp::In`
                    BinaryOp::In => {
                        let uid1 = arg1.get_as_entity().map_err(|mut e|
                            {
                                // If arg1 is not an entity and arg2 is a set, then possibly
                                // the user intended `arg2.contains(arg1)` rather than `arg1 in arg2`.
                                // If arg2 is a record, then possibly they intended `arg2 has arg1`.
                                if matches!(e.error_kind(), EvaluationErrorKind::TypeError { .. }) {
                                    match arg2 {
                                        Value::Set(_) => e.set_advice("`in` is for checking the entity hierarchy, use `.contains()` to test set membership".into()),
                                        Value::Record(_) =>  e.set_advice("`in` is for checking the entity hierarchy, use `has` to test if a record has a key".into()),
                                        _ => {}
                                    }
                                };
                                e
                            })?;
                        let rhs = self.eval_in_rhs_as_vec(&arg2)?;
                        if rhs.contains(uid1) {
                            Ok(true.into())
                        } else {
                            match self
                                .entities
                                .exists_entity_deref(uid1)
                                .map_err(EvaluationError::mk_request)?
                            {
                                Dereference::Residual(r) => Ok(PartialValue::Residual(
                                    Expr::binary_app(BinaryOp::In, r, arg2.into()),
                                )),
                                Dereference::NoSuchEntity => Ok(false.into()),
                                Dereference::Data(_) => self.eval_in(uid1, rhs),
                            }
                        }
                    }
                    // contains, which works on Sets
                    BinaryOp::Contains => match arg1 {
                        Value::Set(Set { fast: Some(h), .. }) => match arg2.try_as_lit() {
                            Some(lit) => Ok((h.contains(lit)).into()),
                            None => Ok(false.into()), // we know it doesn't contain a non-literal
                        },
                        Value::Set(Set { authoritative, .. }) => {
                            Ok((authoritative.contains(&arg2)).into())
                        }
                        _ => Err(EvaluationError::type_error(vec![Type::Set], arg1.type_of())),
                    },
                    // ContainsAll and ContainsAny, which work on Sets
                    BinaryOp::ContainsAll | BinaryOp::ContainsAny => {
                        let arg1_set = arg1.get_as_set()?;
                        let arg2_set = arg2.get_as_set()?;
                        match (&arg1_set.fast, &arg2_set.fast) {
                            (Some(arg1_set), Some(arg2_set)) => {
                                // both sets are in fast form, ie, they only contain literals.
                                // Fast hashset-based implementation.
                                match op {
                                    BinaryOp::ContainsAll => {
                                        Ok((arg2_set.is_subset(arg1_set)).into())
                                    }
                                    BinaryOp::ContainsAny => {
                                        Ok((!arg1_set.is_disjoint(arg2_set)).into())
                                    }
                                    // PANIC SAFETY `op` is checked to be one of these two above
                                    #[allow(clippy::unreachable)]
                                    _ => unreachable!(
                                        "Should have already checked that op was one of these"
                                    ),
                                }
                            }
                            (_, _) => {
                                // one or both sets are in slow form, ie, contain a non-literal.
                                // Fallback to slow implementation.
                                match op {
                                    BinaryOp::ContainsAll => {
                                        let is_subset = arg2_set
                                            .authoritative
                                            .iter()
                                            .all(|item| arg1_set.authoritative.contains(item));
                                        Ok(is_subset.into())
                                    }
                                    BinaryOp::ContainsAny => {
                                        let not_disjoint = arg1_set
                                            .authoritative
                                            .iter()
                                            .any(|item| arg2_set.authoritative.contains(item));
                                        Ok(not_disjoint.into())
                                    }
                                    // PANIC SAFETY `op` is checked to be one of these two above
                                    #[allow(clippy::unreachable)]
                                    _ => unreachable!(
                                        "Should have already checked that op was one of these"
                                    ),
                                }
                            }
                        }
                    }
                }
            }
            ExprKind::MulByConst { arg, constant } => match self.partial_interpret(arg, slots)? {
                PartialValue::Value(arg) => {
                    let i1 = arg.get_as_long()?;
                    match i1.checked_mul(*constant) {
                        Some(prod) => Ok(prod.into()),
                        None => Err(IntegerOverflowError::Multiplication {
                            arg,
                            constant: *constant,
                        }
                        .into()),
                    }
                }
                PartialValue::Residual(r) => Ok(PartialValue::Residual(Expr::mul(r, *constant))),
            },
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let args = args
                    .iter()
                    .map(|arg| self.partial_interpret(arg, slots))
                    .collect::<Result<Vec<_>>>()?;
                match split(args) {
                    Either::Left(vals) => {
                        let vals: Vec<_> = vals.collect();
                        let efunc = self.extensions.func(fn_name)?;
                        efunc.call(&vals)
                    }
                    Either::Right(residuals) => Ok(PartialValue::Residual(
                        Expr::call_extension_fn(fn_name.clone(), residuals.collect()),
                    )),
                }
            }
            ExprKind::GetAttr { expr, attr } => self.get_attr(expr.as_ref(), attr, slots),
            ExprKind::HasAttr { expr, attr } => match self.partial_interpret(expr, slots)? {
                PartialValue::Value(Value::Record(record)) => Ok(record.get(attr).is_some().into()),
                PartialValue::Value(Value::Lit(Literal::EntityUID(uid))) => {
                    match self
                        .entities
                        .handle_access_error(
                            &uid,
                            self.entities.entity_has_attr(&uid, attr.as_str()),
                        )
                        .map_err(EvaluationError::mk_request)?
                    {
                        Dereference::NoSuchEntity => Ok(false.into()),
                        Dereference::Residual(r) => {
                            Ok(PartialValue::Residual(Expr::has_attr(r, attr.clone())))
                        }
                        Dereference::Data(b) => Ok(b.into()),
                    }
                }
                PartialValue::Value(val) => Err(err::EvaluationError::type_error(
                    vec![
                        Type::Record,
                        Type::entity_type(names::ANY_ENTITY_TYPE.clone()),
                    ],
                    val.type_of(),
                )),
                PartialValue::Residual(r) => Ok(Expr::has_attr(r, attr.clone()).into()),
            },
            ExprKind::Like { expr, pattern } => {
                let v = self.partial_interpret(expr, slots)?;
                match v {
                    PartialValue::Value(v) => {
                        Ok((pattern.wildcard_match(v.get_as_string()?)).into())
                    }
                    PartialValue::Residual(r) => Ok(Expr::like(r, pattern.iter().cloned()).into()),
                }
            }
            ExprKind::Set(items) => {
                let vals = items
                    .iter()
                    .map(|item| self.partial_interpret(item, slots))
                    .collect::<Result<Vec<_>>>()?;
                match split(vals) {
                    Either::Left(vals) => Ok(Value::set(vals).into()),
                    Either::Right(r) => Ok(Expr::set(r).into()),
                }
            }
            ExprKind::Record { pairs } => {
                let map = pairs
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.partial_interpret(v, slots)?)))
                    .collect::<Result<Vec<_>>>()?;
                let (names, evalled): (Vec<SmolStr>, Vec<PartialValue>) = map.into_iter().unzip();
                match split(evalled) {
                    Either::Left(vals) => {
                        Ok(Value::Record(Arc::new(names.into_iter().zip(vals).collect())).into())
                    }
                    Either::Right(rs) => Ok(Expr::record(names.into_iter().zip(rs)).into()),
                }
            }
        }
    }

    fn eval_in_rhs_as_vec(&self, rhs: &Value) -> Result<Vec<EntityUID>> {
        // `rhs` is a list of all the UIDs for which we need to
        // check if `uid1` is a descendant of
        match rhs {
            Value::Lit(Literal::EntityUID(uid)) => Ok(vec![(**uid).clone()]),
            // we assume that iterating the `authoritative` BTreeSet is
            // approximately the same cost as iterating the `fast` HashSet
            Value::Set(Set { authoritative, .. }) => authoritative
                .iter()
                .map(|val| Ok(val.get_as_entity()?.clone()))
                .collect::<Result<Vec<EntityUID>>>(),
            _ => Err(EvaluationError::type_error(
                vec![Type::Set, Type::entity_type(names::ANY_ENTITY_TYPE.clone())],
                rhs.type_of(),
            )),
        }
    }

    fn eval_in(&self, uid1: &EntityUID, rhs: Vec<EntityUID>) -> Result<PartialValue> {
        for uid2 in rhs {
            if self
                .entities
                .entity_in(uid1, &uid2)
                .map_err(EvaluationError::mk_request)?
            {
                return Ok(true.into());
            }
        }
        // if we get here, `uid1` is not a descendant of (or equal to)
        // any UID in `rhs`
        Ok(false.into())
    }

    /// Evaluation of conditionals
    /// Must be sure to respect short-circuiting semantics
    fn eval_if(
        &self,
        guard: &Expr,
        consequent: &Expr,
        alternative: &Expr,
        slots: &SlotEnv,
    ) -> Result<PartialValue> {
        match self.partial_interpret(guard, slots)? {
            PartialValue::Value(v) => {
                if v.get_as_bool()? {
                    self.partial_interpret(consequent, slots)
                } else {
                    self.partial_interpret(alternative, slots)
                }
            }
            PartialValue::Residual(guard) => {
                let (consequent, consequent_errored) = self.run_to_error(consequent, slots);
                let (alternative, alternative_errored) = self.run_to_error(alternative, slots);
                // If both branches errored, the expression will always error
                match (consequent_errored, alternative_errored) {
                    (Some(e), Some(_)) => Err(e),
                    _ => Ok(Expr::ite(guard, consequent.into(), alternative.into()).into()),
                }
            }
        }
    }

    fn get_attr(&self, expr: &Expr, attr: &SmolStr, slots: &SlotEnv) -> Result<PartialValue> {
        match self.partial_interpret(expr, slots)? {
            // PE Cases
            PartialValue::Residual(e) => {
                match e.expr_kind() {
                    ExprKind::Record { pairs } => {
                        // If we have a residual record, we evaluate as follows:
                        // 1) If it's safe to project, we can project. We can evaluate to see if this attribute can become a value
                        // 2) If it's not safe to project, we can check to see if the requested key exists in the record
                        //    if it doens't, we can fail early
                        if e.is_projectable() {
                            pairs
                                .as_ref()
                                .iter()
                                .filter_map(|(k, v)| if k == attr { Some(v) } else { None })
                                .next()
                                .ok_or_else(|| {
                                    EvaluationError::record_attr_does_not_exist(
                                        attr.clone(),
                                        pairs.iter().map(|(f, _)| f.clone()).collect(),
                                    )
                                })
                                .and_then(|e| self.partial_interpret(e, slots))
                        } else if pairs.iter().any(|(k, _v)| k == attr) {
                            Ok(PartialValue::Residual(Expr::get_attr(
                                Expr::record(pairs.as_ref().clone()), // We should try to avoid this copy
                                attr.clone(),
                            )))
                        } else {
                            Err(EvaluationError::record_attr_does_not_exist(
                                attr.clone(),
                                pairs.iter().map(|(f, _)| f.clone()).collect(),
                            ))
                        }
                    }
                    // We got a residual, that is not a record at the top level
                    _ => Ok(PartialValue::Residual(Expr::get_attr(e, attr.clone()))),
                }
            }
            PartialValue::Value(Value::Record(attrs)) => attrs
                .as_ref()
                .get(attr)
                .ok_or_else(|| {
                    EvaluationError::record_attr_does_not_exist(
                        attr.clone(),
                        attrs.iter().map(|(f, _)| f.clone()).collect(),
                    )
                })
                .map(|v| PartialValue::Value(v.clone())),
            PartialValue::Value(Value::Lit(Literal::EntityUID(uid))) => {
                let attr_value = match self.entities.entity_attr(&uid, attr) {
                    Ok(v) => Ok(v),
                    Err(e) => Err(e.handle_attr(()).err().ok_or_else(|| {
                        EvaluationError::entity_attr_does_not_exist(uid.clone(), attr.clone())
                    })?),
                };
                match self
                    .entities
                    .handle_access_error(&uid, attr_value)
                    .map_err(EvaluationError::mk_request)?
                {
                    Dereference::NoSuchEntity => Err(match *uid.entity_type() {
                        EntityType::Unspecified => {
                            EvaluationError::unspecified_entity_access(attr.clone())
                        }
                        EntityType::Concrete(_) => {
                            EvaluationError::entity_does_not_exist(uid.clone())
                        }
                    }),
                    Dereference::Residual(r) => {
                        Ok(PartialValue::Residual(Expr::get_attr(r, attr.clone())))
                    }
                    Dereference::Data(v) => Ok(v),
                }
            }
            PartialValue::Value(v) => {
                // PANIC SAFETY Entity type name is fully static and a valid unqualified `Name`
                #[allow(clippy::unwrap_used)]
                Err(EvaluationError::type_error(
                    vec![
                        Type::Record,
                        Type::entity_type(Name::parse_unqualified_name("any_entity_type").unwrap()),
                    ],
                    v.type_of(),
                ))
            }
        }
    }

    #[cfg(test)]
    pub fn interpret_inline_policy(&self, e: &Expr) -> Result<Value> {
        use std::collections::HashMap;

        match self.partial_interpret(e, &HashMap::new())? {
            PartialValue::Value(v) => Ok(v),
            PartialValue::Residual(r) => Err(err::EvaluationError::non_value(r)),
        }
    }

    /// Evaluate an expression, potentially leaving a residual
    #[cfg(test)]
    pub fn partial_eval_expr(&self, p: &Expr) -> Result<Either<Value, Expr>> {
        let env = SlotEnv::new();
        match self.partial_interpret(p, &env)? {
            PartialValue::Value(v) => Ok(Either::Left(v)),
            PartialValue::Residual(r) => Ok(Either::Right(r)),
        }
    }
    // by default, Coverlay does not track coverage for lines after a line
    // containing #[cfg(test)].
    // we use the following sentinel to "turn back on" coverage tracking for
    // remaining lines of this file, until the next #[cfg(test)]
    // GRCOV_BEGIN_COVERAGE
}

impl<'e, T: EntityDataSource> std::fmt::Debug for Evaluator<'e, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<Evaluator with principal = {:?}, action = {:?}, resource = {:?}",
            &self.principal, &self.action, &self.resource
        )
    }
}

impl Value {
    /// Convert the `Value` to a boolean, or throw a type error if it's not a
    /// boolean.
    pub(crate) fn get_as_bool(&self) -> Result<bool> {
        match self {
            Value::Lit(Literal::Bool(b)) => Ok(*b),
            _ => Err(EvaluationError::type_error(
                vec![Type::Bool],
                self.type_of(),
            )),
        }
    }

    /// Convert the `Value` to a Long, or throw a type error if it's not a
    /// Long.
    pub(crate) fn get_as_long(&self) -> Result<i64> {
        match self {
            Value::Lit(Literal::Long(i)) => Ok(*i),
            _ => Err(EvaluationError::type_error(
                vec![Type::Long],
                self.type_of(),
            )),
        }
    }

    /// Convert the `Value` to a String, or throw a type error if it's not a
    /// String.
    pub(crate) fn get_as_string(&self) -> Result<&SmolStr> {
        match self {
            Value::Lit(Literal::String(s)) => Ok(s),
            _ => Err(EvaluationError::type_error(
                vec![Type::String],
                self.type_of(),
            )),
        }
    }

    /// Convert the `Value` to a Set, or throw a type error if it's not a Set.
    pub(crate) fn get_as_set(&self) -> Result<&Set> {
        match self {
            Value::Set(s) => Ok(s),
            _ => Err(EvaluationError::type_error(vec![Type::Set], self.type_of())),
        }
    }

    /// Convert the `Value` to an Entity, or throw a type error if it's not a
    /// Entity.
    pub(crate) fn get_as_entity(&self) -> Result<&EntityUID> {
        match self {
            Value::Lit(Literal::EntityUID(uid)) => Ok(uid.as_ref()),
            _ => Err(EvaluationError::type_error(
                vec![Type::entity_type(names::ANY_ENTITY_TYPE.clone())],
                self.type_of(),
            )),
        }
    }
}

#[inline(always)]
fn stack_size_check() -> Result<()> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        if stacker::remaining_stack().unwrap_or(0) < REQUIRED_STACK_SPACE {
            return Err(EvaluationError::recursion_limit());
        }
    }
    Ok(())
}

#[cfg(test)]
pub mod test {
    use std::collections::HashMap;
    use std::str::FromStr;

    use super::*;

    use crate::{
        entities::{EntityJsonParser, TCComputation},
        parser::{self, parse_policyset},
        parser::{parse_expr, parse_policy_template},
    };

    use cool_asserts::assert_matches;

    // Many of these tests use this Request
    pub fn basic_request() -> Request {
        Request::new(
            EntityUID::with_eid("test_principal"),
            EntityUID::with_eid("test_action"),
            EntityUID::with_eid("test_resource"),
            Context::from_pairs([
                ("cur_time".into(), RestrictedExpr::val("03:22:11")),
                (
                    "device_properties".into(),
                    RestrictedExpr::record(vec![
                        ("os_name".into(), RestrictedExpr::val("Windows")),
                        ("manufacturer".into(), RestrictedExpr::val("ACME Corp")),
                    ]),
                ),
            ]),
        )
    }

    // Many of these tests use this basic `Entities`
    pub fn basic_entities() -> Entities<PartialValue> {
        Entities::from_entities(
            vec![
                Entity::with_uid(EntityUID::with_eid("foo")),
                Entity::with_uid(EntityUID::with_eid("test_principal")),
                Entity::with_uid(EntityUID::with_eid("test_action")),
                Entity::with_uid(EntityUID::with_eid("test_resource")),
            ],
            TCComputation::ComputeNow,
        )
        .expect("failed to create basic entities")
    }

    // This `Entities` has richer Entities
    pub fn rich_entities() -> Entities<PartialValue> {
        let entity_no_attrs_no_parents =
            Entity::with_uid(EntityUID::with_eid("entity_no_attrs_no_parents"));
        let mut entity_with_attrs = Entity::with_uid(EntityUID::with_eid("entity_with_attrs"));
        entity_with_attrs.set_attr("spoon".into(), RestrictedExpr::val(787));
        entity_with_attrs.set_attr(
            "tags".into(),
            RestrictedExpr::set(vec![
                RestrictedExpr::val("fun"),
                RestrictedExpr::val("good"),
                RestrictedExpr::val("useful"),
            ]),
        );
        entity_with_attrs.set_attr(
            "address".into(),
            RestrictedExpr::record(vec![
                ("street".into(), RestrictedExpr::val("234 magnolia")),
                ("town".into(), RestrictedExpr::val("barmstadt")),
                ("country".into(), RestrictedExpr::val("amazonia")),
            ]),
        );
        let mut child = Entity::with_uid(EntityUID::with_eid("child"));
        let mut parent = Entity::with_uid(EntityUID::with_eid("parent"));
        let grandparent = Entity::with_uid(EntityUID::with_eid("grandparent"));
        let mut sibling = Entity::with_uid(EntityUID::with_eid("sibling"));
        let unrelated = Entity::with_uid(EntityUID::with_eid("unrelated"));
        child.add_ancestor(parent.uid());
        sibling.add_ancestor(parent.uid());
        parent.add_ancestor(grandparent.uid());
        let mut child_diff_type = Entity::with_uid(
            EntityUID::with_eid_and_type("other_type", "other_child")
                .expect("should be a valid identifier"),
        );
        child_diff_type.add_ancestor(parent.uid());
        child_diff_type.add_ancestor(grandparent.uid());
        Entities::from_entities(
            vec![
                entity_no_attrs_no_parents,
                entity_with_attrs,
                child,
                child_diff_type,
                parent,
                grandparent,
                sibling,
                unrelated,
            ],
            TCComputation::ComputeNow,
        )
        .expect("Failed to create rich entities")
        .eval_attrs(&Extensions::none())
        .expect("Failed to evaluated attributes")
    }

    #[cfg(feature = "partial-eval")]
    #[test]
    fn partial_entity_stores_in_set() {
        let q = basic_request();
        let entities = rich_entities().partial();
        let exts = Extensions::none();
        let child = EntityUID::with_eid("child");
        let second = EntityUID::with_eid("joseph");
        let missing = EntityUID::with_eid("non-present");
        let parent = EntityUID::with_eid("parent");
        let eval = Evaluator::new(&q, &entities, &exts).unwrap();

        let e = Expr::binary_app(
            BinaryOp::In,
            Expr::val(child),
            Expr::set([Expr::val(parent.clone()), Expr::val(second.clone())]),
        );
        let r = eval.partial_eval_expr(&e).unwrap();
        assert_eq!(r, Either::Left(true.into()));

        let e = Expr::binary_app(
            BinaryOp::In,
            Expr::val(missing.clone()),
            Expr::set([Expr::val(parent.clone()), Expr::val(second.clone())]),
        );
        let r = eval.partial_eval_expr(&e).unwrap();
        let expected_residual = Expr::binary_app(
            BinaryOp::In,
            Expr::unknown(format!("{missing}")),
            Expr::set([Expr::val(parent.clone()), Expr::val(second.clone())]),
        );
        let expected_residual2 = Expr::binary_app(
            BinaryOp::In,
            Expr::unknown(format!("{missing}")),
            Expr::set([Expr::val(second), Expr::val(parent)]),
        );

        // Either ordering is valid
        assert!(r == Either::Right(expected_residual) || r == Either::Right(expected_residual2));
    }

    #[cfg(feature = "partial-eval")]
    #[test]
    fn partial_entity_stores_in() {
        let q = basic_request();
        let entities = rich_entities().partial();
        let exts = Extensions::none();
        let child = EntityUID::with_eid("child");
        let missing = EntityUID::with_eid("non-present");
        let parent = EntityUID::with_eid("parent");
        let eval = Evaluator::new(&q, &entities, &exts).unwrap();

        let e = Expr::binary_app(BinaryOp::In, Expr::val(child), Expr::val(parent.clone()));
        let r = eval.partial_eval_expr(&e).unwrap();
        assert_eq!(r, Either::Left(true.into()));

        let e = Expr::binary_app(
            BinaryOp::In,
            Expr::val(missing.clone()),
            Expr::val(parent.clone()),
        );
        let r = eval.partial_eval_expr(&e).unwrap();
        let expected_residual = Expr::binary_app(
            BinaryOp::In,
            Expr::unknown(format!("{missing}")),
            Expr::val(parent),
        );
        assert_eq!(r, Either::Right(expected_residual));
    }

    #[cfg(feature = "partial-eval")]
    #[test]
    fn partial_entity_stores_hasattr() {
        let q = basic_request();
        let entities = rich_entities().partial();
        let exts = Extensions::none();
        let has_attr = EntityUID::with_eid("entity_with_attrs");
        let missing = EntityUID::with_eid("missing");
        let eval = Evaluator::new(&q, &entities, &exts).unwrap();

        let e = Expr::has_attr(Expr::val(has_attr), "spoon".into());
        let r = eval.partial_eval_expr(&e).unwrap();
        assert_eq!(r, Either::Left(true.into()));

        let e = Expr::has_attr(Expr::val(missing.clone()), "spoon".into());
        let r = eval.partial_eval_expr(&e).unwrap();
        let expected_residual = Expr::has_attr(Expr::unknown(format!("{missing}")), "spoon".into());
        assert_eq!(r, Either::Right(expected_residual));
    }

    #[cfg(feature = "partial-eval")]
    #[test]
    fn partial_entity_stores_getattr() {
        let q = basic_request();
        let entities = rich_entities().partial();
        let exts = Extensions::none();
        let has_attr = EntityUID::with_eid("entity_with_attrs");
        let missing = EntityUID::with_eid("missing");
        let eval = Evaluator::new(&q, &entities, &exts).unwrap();

        let e = Expr::get_attr(Expr::val(has_attr), "spoon".into());
        let r = eval.partial_eval_expr(&e).unwrap();
        assert_eq!(r, Either::Left(787.into()));

        let e = Expr::get_attr(Expr::val(missing.clone()), "spoon".into());
        let r = eval.partial_eval_expr(&e).unwrap();
        let expected_residual = Expr::get_attr(Expr::unknown(format!("{missing}")), "spoon".into());
        assert_eq!(r, Either::Right(expected_residual));
    }

    #[test]
    fn interpret_primitives() {
        let request = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val(false)),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val(true)),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val(57)),
            Ok(Value::Lit(Literal::Long(57)))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val(-3)),
            Ok(Value::Lit(Literal::Long(-3)))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val("")),
            Ok(Value::Lit(Literal::String("".into())))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val("Hello")),
            Ok(Value::Lit(Literal::String("Hello".into())))
        );
    }

    #[test]
    fn interpret_entities() {
        let request = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val(EntityUID::with_eid("foo"))),
            Ok(Value::Lit(Literal::EntityUID(Arc::new(
                EntityUID::with_eid("foo")
            ))))
        );
        // should be no error here even for entities that do not exist.
        // (for instance, A == B is allowed even when A and/or B do not exist.)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val(EntityUID::with_eid("doesnotexist"))),
            Ok(Value::Lit(Literal::EntityUID(Arc::new(
                EntityUID::with_eid("doesnotexist")
            ))))
        );
        // unspecified entities should not result in an error.
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val(EntityUID::unspecified_from_eid(Eid::new(
                "foo"
            )))),
            Ok(Value::Lit(Literal::EntityUID(Arc::new(
                EntityUID::unspecified_from_eid(Eid::new("foo"))
            ))))
        );
    }

    #[test]
    fn interpret_builtin_vars() {
        let request = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        assert_eq!(
            eval.interpret_inline_policy(&Expr::var(Var::Principal)),
            Ok(Value::Lit(Literal::EntityUID(Arc::new(
                EntityUID::with_eid("test_principal")
            ))))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::var(Var::Action)),
            Ok(Value::Lit(Literal::EntityUID(Arc::new(
                EntityUID::with_eid("test_action")
            ))))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::var(Var::Resource)),
            Ok(Value::Lit(Literal::EntityUID(Arc::new(
                EntityUID::with_eid("test_resource")
            ))))
        );
    }

    #[test]
    fn interpret_entity_attrs() {
        let request = basic_request();
        let entities = rich_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        // has_attr on an entity with no attrs
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::val(EntityUID::with_eid("entity_no_attrs_no_parents")),
                "doesnotexist".into()
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // has_attr on an entity that has attrs, but not that one
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::val(EntityUID::with_eid("entity_with_attrs")),
                "doesnotexist".into()
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // has_attr where the response is true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::val(EntityUID::with_eid("entity_with_attrs")),
                "tags".into()
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // get_attr on an attr which doesn't exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::val(EntityUID::with_eid("entity_with_attrs")),
                "doesnotexist".into()
            )),
            Err(EvaluationError::entity_attr_does_not_exist(
                Arc::new(EntityUID::with_eid("entity_with_attrs")),
                "doesnotexist".into()
            ))
        );
        // get_attr on an attr which does exist (and has integer type)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::val(EntityUID::with_eid("entity_with_attrs")),
                "spoon".into()
            )),
            Ok(Value::Lit(Literal::Long(787)))
        );
        // get_attr on an attr which does exist (and has Set type)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::get_attr(
                    Expr::val(EntityUID::with_eid("entity_with_attrs")),
                    "tags".into()
                ),
                Expr::val("useful")
            )),
            Ok(Value::from(true))
        );
        // has_attr on an entity which doesn't exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::val(EntityUID::with_eid("doesnotexist")),
                "foo".into()
            )),
            Ok(Value::from(false))
        );
        // get_attr on an entity which doesn't exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::val(EntityUID::with_eid("doesnotexist")),
                "foo".into()
            )),
            Err(EvaluationError::entity_does_not_exist(Arc::new(
                EntityUID::with_eid("doesnotexist")
            )))
        );
        // has_attr on an unspecified entity
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::val(EntityUID::unspecified_from_eid(Eid::new("foo"))),
                "foo".into()
            )),
            Ok(Value::from(false))
        );
        // get_attr on an unspecified entity
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::val(EntityUID::unspecified_from_eid(Eid::new("foo"))),
                "bar".into()
            )),
            Err(EvaluationError::unspecified_entity_access("bar".into()))
        );
    }

    #[test]
    fn interpret_ternaries() {
        let request = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        // if true then 3 else 8
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(Expr::val(true), Expr::val(3), Expr::val(8))),
            Ok(Value::Lit(Literal::Long(3)))
        );
        // if false then 3 else 8
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(Expr::val(false), Expr::val(3), Expr::val(8))),
            Ok(Value::Lit(Literal::Long(8)))
        );
        // if false then false else true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::val(false),
                Expr::val(true)
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // if false then principal else resource
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::var(Var::Principal),
                Expr::var(Var::Resource)
            )),
            Ok(Value::from(EntityUID::with_eid("test_resource")))
        );
        // if "hello" then 3 else 8
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val("hello"),
                Expr::val(3),
                Expr::val(8)
            )),
            Err(EvaluationError::type_error(vec![Type::Bool], Type::String))
        );
        // if principal then 3 else 8
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::var(Var::Principal),
                Expr::val(3),
                Expr::val(8)
            )),
            Err(EvaluationError::type_error(
                vec![Type::Bool],
                Type::Entity {
                    ty: EntityUID::test_entity_type(),
                },
            ))
        );
        // if true then "hello" else 2
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::val("hello"),
                Expr::val(2)
            )),
            Ok(Value::from("hello"))
        );
        // if false then "hello" else 2
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::val("hello"),
                Expr::val(2)
            )),
            Ok(Value::Lit(Literal::Long(2)))
        );
        // if true then (if true then 3 else 8) else -10
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::ite(Expr::val(true), Expr::val(3), Expr::val(8)),
                Expr::val(-10)
            )),
            Ok(Value::Lit(Literal::Long(3)))
        );
        // if true then (if false then 3 else 8) else -10
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::ite(Expr::val(false), Expr::val(3), Expr::val(8)),
                Expr::val(-10)
            )),
            Ok(Value::Lit(Literal::Long(8)))
        );
        // if false then (if false then 3 else 8) else -10
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::ite(Expr::val(false), Expr::val(3), Expr::val(8)),
                Expr::val(-10)
            )),
            Ok(Value::Lit(Literal::Long(-10)))
        );
        // if false then (if "hello" then 3 else 8) else -10
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::ite(Expr::val("hello"), Expr::val(3), Expr::val(8)),
                Expr::val(-10)
            )),
            Ok(Value::Lit(Literal::Long(-10)))
        );
        // if true then 3 else (if true then 8 else -10)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::val(3),
                Expr::ite(Expr::val(true), Expr::val(8), Expr::val(-10))
            )),
            Ok(Value::Lit(Literal::Long(3)))
        );
        // if (if true then false else true) then 3 else 8
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::ite(Expr::val(true), Expr::val(false), Expr::val(true)),
                Expr::val(3),
                Expr::val(8)
            )),
            Ok(Value::Lit(Literal::Long(8)))
        );
        // if true then 3 else <err>
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::val(3),
                Expr::get_attr(Expr::record(vec![]), "foo".into()),
            )),
            Ok(Value::Lit(Literal::Long(3)))
        );
        // if false then 3 else <err>
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::val(3),
                Expr::get_attr(Expr::record(vec![]), "foo".into()),
            )),
            Err(EvaluationError::record_attr_does_not_exist(
                "foo".into(),
                vec![]
            ))
        );
        // if true then <err> else 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::get_attr(Expr::record(vec![]), "foo".into()),
                Expr::val(3),
            )),
            Err(EvaluationError::record_attr_does_not_exist(
                "foo".into(),
                vec![]
            ))
        );
        // if false then <err> else 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::get_attr(Expr::record(vec![]), "foo".into()),
                Expr::val(3),
            )),
            Ok(Value::Lit(Literal::Long(3)))
        );
    }

    #[test]
    fn interpret_sets() {
        let request = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        // set(8)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::set(vec![Expr::val(8)])),
            Ok(Value::set(vec![Value::Lit(Literal::Long(8))]))
        );
        // set(8, 2, 101)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::set(vec![
                Expr::val(8),
                Expr::val(2),
                Expr::val(101)
            ])),
            Ok(Value::set(vec![
                Value::Lit(Literal::Long(8)),
                Value::Lit(Literal::Long(2)),
                Value::Lit(Literal::Long(101))
            ]))
        );
        // empty set
        assert_eq!(
            eval.interpret_inline_policy(&Expr::set(vec![])),
            Ok(Value::empty_set())
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::set(vec![])),
            Ok(Value::empty_set())
        );
        // set(8)["hello"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::set(vec![Expr::val(8)]),
                "hello".into()
            )),
            Err(EvaluationError::type_error(
                vec![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ],
                Type::Set,
            ))
        );
        // indexing into empty set
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(Expr::set(vec![]), "hello".into())),
            Err(EvaluationError::type_error(
                vec![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ],
                Type::Set,
            ))
        );
        // set("hello", 2, true, <entity foo>)
        let mixed_set = Expr::set(vec![
            Expr::val("hello"),
            Expr::val(2),
            Expr::val(true),
            Expr::val(EntityUID::with_eid("foo")),
        ]);
        assert_eq!(
            eval.interpret_inline_policy(&mixed_set),
            Ok(Value::set(vec![
                Value::Lit(Literal::String("hello".into())),
                Value::Lit(Literal::Long(2)),
                Value::Lit(Literal::Bool(true)),
                Value::Lit(Literal::EntityUID(Arc::new(EntityUID::with_eid("foo")))),
            ]))
        );
        // set("hello", 2, true, <entity foo>)["hello"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(mixed_set, "hello".into())),
            Err(EvaluationError::type_error(
                vec![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ],
                Type::Set,
            ))
        );
        // set(set(8, 2), set(13, 702), set(3))
        let set_of_sets = Expr::set(vec![
            Expr::set(vec![Expr::val(8), Expr::val(2)]),
            Expr::set(vec![Expr::val(13), Expr::val(702)]),
            Expr::set(vec![Expr::val(3)]),
        ]);
        assert_eq!(
            eval.interpret_inline_policy(&set_of_sets),
            Ok(Value::set(vec![
                Value::set(vec![
                    Value::Lit(Literal::Long(8)),
                    Value::Lit(Literal::Long(2))
                ]),
                Value::set(vec![
                    Value::Lit(Literal::Long(13)),
                    Value::Lit(Literal::Long(702))
                ]),
                Value::set(vec![Value::Lit(Literal::Long(3))]),
            ]))
        );
        // set(set(8, 2), set(13, 702), set(3))["hello"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(set_of_sets.clone(), "hello".into())),
            Err(EvaluationError::type_error(
                vec![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ],
                Type::Set,
            ))
        );
        // set(set(8, 2), set(13, 702), set(3))["ham"]["eggs"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::get_attr(set_of_sets, "ham".into()),
                "eggs".into()
            )),
            Err(EvaluationError::type_error(
                vec![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ],
                Type::Set,
            ))
        );
    }

    #[test]
    fn interpret_records() {
        let request = basic_request();
        let entities = rich_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        // {"key": 3}["key"] or {"key": 3}.key
        let string_key = Expr::record(vec![("key".into(), Expr::val(3))]);
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(string_key, "key".into())),
            Ok(Value::Lit(Literal::Long(3)))
        );
        // {"ham": 3, "eggs": 7}["ham"] or {"ham": 3, "eggs": 7}.ham
        let ham_and_eggs = Expr::record(vec![
            ("ham".into(), Expr::val(3)),
            ("eggs".into(), Expr::val(7)),
        ]);
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(ham_and_eggs.clone(), "ham".into())),
            Ok(Value::Lit(Literal::Long(3)))
        );
        // {"ham": 3, "eggs": 7}["eggs"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(ham_and_eggs.clone(), "eggs".into())),
            Ok(Value::Lit(Literal::Long(7)))
        );
        // {"ham": 3, "eggs": 7}["what"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(ham_and_eggs, "what".into())),
            Err(EvaluationError::record_attr_does_not_exist(
                "what".into(),
                vec!["eggs".into(), "ham".into()]
            ))
        );

        // {"ham": 3, "eggs": "why"}["ham"]
        let ham_and_eggs_2 = Expr::record(vec![
            ("ham".into(), Expr::val(3)),
            ("eggs".into(), Expr::val("why")),
        ]);
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(ham_and_eggs_2.clone(), "ham".into())),
            Ok(Value::Lit(Literal::Long(3)))
        );
        // {"ham": 3, "eggs": "why"}["eggs"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(ham_and_eggs_2, "eggs".into())),
            Ok(Value::from("why"))
        );
        // {"ham": 3, "eggs": "why", "else": <entity foo>}["else"]
        let ham_and_eggs_3 = Expr::record(vec![
            ("ham".into(), Expr::val(3)),
            ("eggs".into(), Expr::val("why")),
            ("else".into(), Expr::val(EntityUID::with_eid("foo"))),
        ]);
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(ham_and_eggs_3, "else".into())),
            Ok(Value::from(EntityUID::with_eid("foo")))
        );
        // {"hams": {"some": 1, "more": 2}, "eggs": "why"}["hams"]["more"]
        let hams_and_eggs = Expr::record(vec![
            (
                "hams".into(),
                Expr::record(vec![
                    ("some".into(), Expr::val(1)),
                    ("more".into(), Expr::val(2)),
                ]),
            ),
            ("eggs".into(), Expr::val("why")),
        ]);
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::get_attr(hams_and_eggs, "hams".into()),
                "more".into()
            )),
            Ok(Value::Lit(Literal::Long(2)))
        );
        // {"this is a valid map key+.-_%() ": 7}["this is a valid map key+.-_%() "]
        let weird_key = Expr::record(vec![(
            "this is a valid map key+.-_%() ".into(),
            Expr::val(7),
        )]);
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                weird_key,
                "this is a valid map key+.-_%() ".into()
            )),
            Ok(Value::Lit(Literal::Long(7)))
        );
        // { foo: 2, bar: [3, 33, 333] }.bar
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::record(vec![
                    ("foo".into(), Expr::val(2)),
                    (
                        "bar".into(),
                        Expr::set(vec!(Expr::val(3), Expr::val(33), Expr::val(333)))
                    )
                ]),
                "bar".into()
            )),
            Ok(Value::set(vec![
                Value::from(3),
                Value::from(33),
                Value::from(333)
            ]))
        );
        // { foo: 2, bar: {"a+b": 5, "jkl;": 10} }.bar["a+b"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::get_attr(
                    Expr::record(vec![
                        ("foo".into(), Expr::val(2)),
                        (
                            "bar".into(),
                            Expr::record(vec![
                                ("a+b".into(), Expr::val(5)),
                                ("jkl;".into(), Expr::val(10)),
                            ])
                        ),
                    ]),
                    "bar".into()
                ),
                "a+b".into()
            )),
            Ok(Value::Lit(Literal::Long(5)))
        );
        // { foo: 2, bar: { foo: 4, cake: 77 } }.bar.foo
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::get_attr(
                    Expr::record(vec![
                        ("foo".into(), Expr::val(2)),
                        (
                            "bar".into(),
                            Expr::record(vec![
                                ("foo".into(), Expr::val(4)),
                                ("cake".into(), Expr::val(77)),
                            ])
                        ),
                    ]),
                    "bar".into(),
                ),
                "foo".into(),
            )),
            Ok(Value::Lit(Literal::Long(4)))
        );
        // entity_with_attrs.address.street
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::get_attr(
                    Expr::val(EntityUID::with_eid("entity_with_attrs")),
                    "address".into()
                ),
                "street".into()
            )),
            Ok(Value::Lit(Literal::String("234 magnolia".into())))
        );
        // context.cur_time
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::var(Var::Context),
                "cur_time".into()
            )),
            Ok(Value::Lit(Literal::String("03:22:11".into())))
        );
        // context.device_properties.os_name
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::get_attr(Expr::var(Var::Context), "device_properties".into()),
                "os_name".into()
            )),
            Ok(Value::Lit(Literal::String("Windows".into())))
        );
        // using has() to test for existence of a record field (which does exist)
        // has({"foo": 77, "bar" : "pancakes"}.foo)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::record(vec![
                    ("foo".into(), Expr::val(77)),
                    ("bar".into(), Expr::val("pancakes")),
                ]),
                "foo".into()
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // using has() to test for existence of a record field (which doesn't exist)
        // has({"foo": 77, "bar" : "pancakes"}.pancakes)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::record(vec![
                    ("foo".into(), Expr::val(77)),
                    ("bar".into(), Expr::val("pancakes")),
                ]),
                "pancakes".into()
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // has({"2": "ham"}["2"])
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::record(vec![("2".into(), Expr::val("ham"))]),
                "2".into()
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // has({"ham": 17, "eggs": if has(foo.spaghetti) then 3 else 7}.ham)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::record(vec![
                    ("ham".into(), Expr::val(17)),
                    (
                        "eggs".into(),
                        Expr::ite(
                            Expr::has_attr(
                                Expr::val(EntityUID::with_eid("foo")),
                                "spaghetti".into()
                            ),
                            Expr::val(3),
                            Expr::val(7)
                        )
                    ),
                ]),
                "ham".into()
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // indexing into something that's not a record, 1010122["hello"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(Expr::val(1010122), "hello".into())),
            Err(EvaluationError::type_error(
                vec![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ],
                Type::Long,
            ))
        );
        // indexing into something that's not a record, "hello"["eggs"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(Expr::val("hello"), "eggs".into())),
            Err(EvaluationError::type_error(
                vec![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ],
                Type::String,
            ))
        );
        // has_attr on something that's not a record, has(1010122.hello)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(Expr::val(1010122), "hello".into())),
            Err(EvaluationError::type_error(
                vec![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ],
                Type::Long,
            ))
        );
        // has_attr on something that's not a record, has("hello".eggs)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(Expr::val("hello"), "eggs".into())),
            Err(EvaluationError::type_error(
                vec![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ],
                Type::String,
            ))
        );
    }

    #[test]
    fn interpret_nots() {
        let request = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        // not(true)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::not(Expr::val(true))),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // not(false)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::not(Expr::val(false))),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // not(8)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::not(Expr::val(8))),
            Err(EvaluationError::type_error(vec![Type::Bool], Type::Long))
        );
        // not(action)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::not(Expr::var(Var::Action))),
            Err(EvaluationError::type_error(
                vec![Type::Bool],
                Type::Entity {
                    ty: EntityUID::test_entity_type(),
                },
            ))
        );
        // not(not(true))
        assert_eq!(
            eval.interpret_inline_policy(&Expr::not(Expr::not(Expr::val(true)))),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // not(if true then false else true)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::not(Expr::ite(
                Expr::val(true),
                Expr::val(false),
                Expr::val(true)
            ))),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // if not(true) then "hello" else "goodbye"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::not(Expr::val(true)),
                Expr::val("hello"),
                Expr::val("goodbye")
            )),
            Ok(Value::from("goodbye"))
        );
    }

    #[test]
    fn interpret_negs() {
        let request = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        // neg(101)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::neg(Expr::val(101))),
            Ok(Value::Lit(Literal::Long(-101)))
        );
        // neg(-101)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::neg(Expr::val(-101))),
            Ok(Value::Lit(Literal::Long(101)))
        );
        // neg(0)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::neg(Expr::val(0))),
            Ok(Value::Lit(Literal::Long(0)))
        );
        // neg(neg(7))
        assert_eq!(
            eval.interpret_inline_policy(&Expr::neg(Expr::neg(Expr::val(7)))),
            Ok(Value::Lit(Literal::Long(7)))
        );
        // if true then neg(8) else neg(1)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::neg(Expr::val(8)),
                Expr::neg(Expr::val(1))
            )),
            Ok(Value::Lit(Literal::Long(-8)))
        );
        // overflow
        assert_eq!(
            eval.interpret_inline_policy(&Expr::neg(Expr::val(std::i64::MIN))),
            Err(IntegerOverflowError::UnaryOp {
                op: UnaryOp::Neg,
                arg: Value::from(std::i64::MIN)
            }
            .into()),
        );
        // neg(false)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::neg(Expr::val(false))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::Bool))
        );
        // neg([1, 2, 3])
        assert_eq!(
            eval.interpret_inline_policy(&Expr::neg(Expr::set([
                Expr::val(1),
                Expr::val(2),
                Expr::val(3)
            ]))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::Set))
        );
    }

    #[test]
    fn interpret_eqs() {
        let request = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        // eq(33, 33)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(Expr::val(33), Expr::val(33))),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // eq(33, -12)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(Expr::val(33), Expr::val(-12))),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // if eq("foo", "foo") then 12 else 97
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::is_eq(Expr::val("foo"), Expr::val("foo")),
                Expr::val(12),
                Expr::val(97),
            )),
            Ok(Value::Lit(Literal::Long(12)))
        );
        // if eq([1, -33, 707], [1, -33]) then 12 else 97
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::is_eq(
                    Expr::set(vec![Expr::val(1), Expr::val(-33), Expr::val(707)]),
                    Expr::set(vec![Expr::val(1), Expr::val(-33)])
                ),
                Expr::val(12),
                Expr::val(97),
            )),
            Ok(Value::Lit(Literal::Long(97)))
        );
        // eq(2>0, 0>(-2))
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::greater(Expr::val(2), Expr::val(0)),
                Expr::greater(Expr::val(0), Expr::val(-2))
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // eq(12+33, 50-5)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::add(Expr::val(12), Expr::val(33)),
                Expr::sub(Expr::val(50), Expr::val(5)),
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // eq([1, 2, 40], [1, 2, 40])
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::set(vec![Expr::val(1), Expr::val(2), Expr::val(40)]),
                Expr::set(vec![Expr::val(1), Expr::val(2), Expr::val(40)])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // eq([1, 2, 40], [1, 40, 2])
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::set(vec![Expr::val(1), Expr::val(2), Expr::val(40)]),
                Expr::set(vec![Expr::val(1), Expr::val(40), Expr::val(2)])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // eq([1, -2, 40], [1, 40])
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::set(vec![Expr::val(1), Expr::val(-2), Expr::val(40)]),
                Expr::set(vec![Expr::val(1), Expr::val(40)])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // eq([1, 1, 1, 2, 40], [40, 1, 2])
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::set(vec![
                    Expr::val(1),
                    Expr::val(1),
                    Expr::val(1),
                    Expr::val(2),
                    Expr::val(40)
                ]),
                Expr::set(vec![Expr::val(40), Expr::val(1), Expr::val(2)])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // eq([1, 1, 2, 1, 40, 2, 1, 2, 40, 1], [1, 40, 1, 2])
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::set(vec![
                    Expr::val(1),
                    Expr::val(1),
                    Expr::val(2),
                    Expr::val(1),
                    Expr::val(40),
                    Expr::val(2),
                    Expr::val(1),
                    Expr::val(2),
                    Expr::val(40),
                    Expr::val(1)
                ]),
                Expr::set(vec![
                    Expr::val(1),
                    Expr::val(40),
                    Expr::val(1),
                    Expr::val(2)
                ])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // eq(context.device_properties, { appropriate record literal })
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::get_attr(Expr::var(Var::Context), "device_properties".into()),
                Expr::record(vec![
                    ("os_name".into(), Expr::val("Windows")),
                    ("manufacturer".into(), Expr::val("ACME Corp")),
                ])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // eq(context.device_properties, { record literal missing one field })
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::get_attr(Expr::var(Var::Context), "device_properties".into()),
                Expr::record(vec![("os_name".into(), Expr::val("Windows")),])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // eq(context.device_properties, { record literal with an extra field })
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::get_attr(Expr::var(Var::Context), "device_properties".into()),
                Expr::record(vec![
                    ("os_name".into(), Expr::val("Windows")),
                    ("manufacturer".into(), Expr::val("ACME Corp")),
                    ("extrafield".into(), Expr::val(true)),
                ])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // eq(context.device_properties, { record literal with the same keys/values })
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::get_attr(Expr::var(Var::Context), "device_properties".into()),
                Expr::record(vec![
                    ("os_name".into(), Expr::val("Windows")),
                    ("manufacturer".into(), Expr::val("ACME Corp")),
                ])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // eq(A, A) where A is an Entity
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val(EntityUID::with_eid("foo")),
                Expr::val(EntityUID::with_eid("foo")),
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // eq(A, A) where A is an Entity that doesn't exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val(EntityUID::with_eid("doesnotexist")),
                Expr::val(EntityUID::with_eid("doesnotexist")),
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // eq(A, B) where A and B are entities of the same type
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val(EntityUID::with_eid("foo")),
                Expr::val(EntityUID::with_eid("bar")),
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // eq(A, B) where A and B are entities of different types
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val(
                    EntityUID::with_eid_and_type("type1", "foo")
                        .expect("should be a valid identifier")
                ),
                Expr::val(
                    EntityUID::with_eid_and_type("type2", "bar")
                        .expect("should be a valid identifier")
                ),
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // eq(A, B) where A and B are entities of different types but happen to
        // have the same name
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val(
                    EntityUID::with_eid_and_type("type1", "foo")
                        .expect("should be a valid identifier")
                ),
                Expr::val(
                    EntityUID::with_eid_and_type("type2", "foo")
                        .expect("should be a valid identifier")
                ),
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // eq(A, B) where A exists but B does not
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val(EntityUID::with_eid("foo")),
                Expr::val(EntityUID::with_eid("doesnotexist")),
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // eq("foo", <entity foo>)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val("foo"),
                Expr::val(EntityUID::with_eid("foo"))
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
    }

    #[test]
    fn interpret_compares() {
        let request = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        // 3 < 303
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(3), Expr::val(303))),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // 3 < -303
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(3), Expr::val(-303))),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // -303 < -1
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(-303), Expr::val(-1))),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // 3 < 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(3), Expr::val(3))),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // -33 <= 0
        assert_eq!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val(-33), Expr::val(0))),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // 3 <= 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val(3), Expr::val(3))),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // 7 > 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greater(Expr::val(7), Expr::val(3))),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // 7 > -3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greater(Expr::val(7), Expr::val(-3))),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // 7 > 7
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greater(Expr::val(7), Expr::val(7))),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // 0 >= -7
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(0), Expr::val(-7))),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // -1 >= 7
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(-1), Expr::val(7))),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // 7 >= 7
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(7), Expr::val(7))),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // false < true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(false), Expr::val(true))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::Bool))
        );
        // false < false
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(false), Expr::val(false))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::Bool))
        );
        // true <= false
        assert_eq!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val(true), Expr::val(false))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::Bool))
        );
        // false <= false
        assert_eq!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val(false), Expr::val(false))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::Bool))
        );
        // false > true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greater(Expr::val(false), Expr::val(true))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::Bool))
        );
        // true > true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greater(Expr::val(true), Expr::val(true))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::Bool))
        );
        // true >= false
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(true), Expr::val(false))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::Bool))
        );
        // true >= true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(true), Expr::val(true))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::Bool))
        );
        // bc < zzz
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("bc"), Expr::val("zzz"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // banana < zzz
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("banana"), Expr::val("zzz"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // "" < zzz
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(""), Expr::val("zzz"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // a < 1
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("a"), Expr::val("1"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // a < A
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("a"), Expr::val("A"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // A < A
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("A"), Expr::val("A"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // zebra < zebras
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("zebra"), Expr::val("zebras"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // zebra <= zebras
        assert_eq!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val("zebra"), Expr::val("zebras"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // zebras <= zebras
        assert_eq!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val("zebras"), Expr::val("zebras"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // zebras <= Zebras
        assert_eq!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val("zebras"), Expr::val("Zebras"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // 123 > 78
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greater(Expr::val("123"), Expr::val("78"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // <space>zebras >= zebras
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greatereq(
                Expr::val(" zebras"),
                Expr::val("zebras")
            )),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // "" >= ""
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(""), Expr::val(""))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // "" >= _hi
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(""), Expr::val("_hi"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // 🦀 >= _hi
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val("🦀"), Expr::val("_hi"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // 2 < "4"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(2), Expr::val("4"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // "4" < 2
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("4"), Expr::val(2))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // false < 1
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(false), Expr::val(1))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::Bool))
        );
        // 1 < false
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(1), Expr::val(false))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::Bool))
        );
        // [1, 2] < [47, 0]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(
                Expr::set(vec![Expr::val(1), Expr::val(2)]),
                Expr::set(vec![Expr::val(47), Expr::val(0)])
            )),
            Err(EvaluationError::type_error(vec![Type::Long], Type::Set))
        );
    }

    #[test]
    fn interpret_arithmetic() {
        let request = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        // 11 + 22
        assert_eq!(
            eval.interpret_inline_policy(&Expr::add(Expr::val(11), Expr::val(22))),
            Ok(Value::Lit(Literal::Long(33)))
        );
        // 11 + 0
        assert_eq!(
            eval.interpret_inline_policy(&Expr::add(Expr::val(11), Expr::val(0))),
            Ok(Value::Lit(Literal::Long(11)))
        );
        // -1 + 1
        assert_eq!(
            eval.interpret_inline_policy(&Expr::add(Expr::val(-1), Expr::val(1))),
            Ok(Value::Lit(Literal::Long(0)))
        );
        // overflow
        assert_eq!(
            eval.interpret_inline_policy(&Expr::add(Expr::val(std::i64::MAX), Expr::val(1))),
            Err(IntegerOverflowError::BinaryOp {
                op: BinaryOp::Add,
                arg1: Value::from(std::i64::MAX),
                arg2: Value::from(1),
            }
            .into())
        );
        // 7 + "3"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::add(Expr::val(7), Expr::val("3"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // 44 - 31
        assert_eq!(
            eval.interpret_inline_policy(&Expr::sub(Expr::val(44), Expr::val(31))),
            Ok(Value::Lit(Literal::Long(13)))
        );
        // 5 - (-3)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::sub(Expr::val(5), Expr::val(-3))),
            Ok(Value::Lit(Literal::Long(8)))
        );
        // overflow
        assert_eq!(
            eval.interpret_inline_policy(&Expr::sub(Expr::val(std::i64::MIN + 2), Expr::val(3))),
            Err(IntegerOverflowError::BinaryOp {
                op: BinaryOp::Sub,
                arg1: Value::from(std::i64::MIN + 2),
                arg2: Value::from(3),
            }
            .into())
        );
        // "ham" - "ha"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::sub(Expr::val("ham"), Expr::val("ha"))),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // 5 * (-3)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::mul(Expr::val(5), -3)),
            Ok(Value::Lit(Literal::Long(-15)))
        );
        // 5 * 0
        assert_eq!(
            eval.interpret_inline_policy(&Expr::mul(Expr::val(5), 0)),
            Ok(Value::Lit(Literal::Long(0)))
        );
        // "5" * 0
        assert_eq!(
            eval.interpret_inline_policy(&Expr::mul(Expr::val("5"), 0)),
            Err(EvaluationError::type_error(vec![Type::Long], Type::String))
        );
        // overflow
        assert_eq!(
            eval.interpret_inline_policy(&Expr::mul(Expr::val(std::i64::MAX - 1), 3)),
            Err(IntegerOverflowError::Multiplication {
                arg: Value::from(std::i64::MAX - 1),
                constant: 3,
            }
            .into())
        );
    }

    #[test]
    fn interpret_set_and_map_membership() {
        let request = basic_request();
        let entities = rich_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");

        // [2, 3, 4] contains 2
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![Expr::val(2), Expr::val(3), Expr::val(4)]),
                Expr::val(2)
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // [34, 2, -7] contains 2
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![Expr::val(34), Expr::val(2), Expr::val(-7)]),
                Expr::val(2)
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // [34, 2, -7] contains 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![Expr::val(34), Expr::val(2), Expr::val(-7)]),
                Expr::val(3)
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // [] contains 7
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(Expr::set(vec![]), Expr::val(7))),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // ["some", "useful", "tags"] contains "foo"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::val("some"),
                    Expr::val("useful"),
                    Expr::val("tags")
                ]),
                Expr::val("foo")
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // ["some", "useful", "tags"] contains "useful"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::val("some"),
                    Expr::val("useful"),
                    Expr::val("tags")
                ]),
                Expr::val("useful")
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // [<entity child>, <entity sibling>] contains <entity child>
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("child")),
                    Expr::val(EntityUID::with_eid("sibling"))
                ]),
                Expr::val(EntityUID::with_eid("child"))
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // [<entity parent>, <entity sibling>] contains <entity child>
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("parent")),
                    Expr::val(EntityUID::with_eid("sibling"))
                ]),
                Expr::val(EntityUID::with_eid("child"))
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // ["foo", "bar"] contains 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![Expr::val("foo"), Expr::val("bar")]),
                Expr::val(3)
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // ["foo", "bar"] contains [3]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![Expr::val("foo"), Expr::val("bar")]),
                Expr::set(vec![Expr::val(3)])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // [[7], "eggs", [3]] contains [3]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::set(vec![Expr::val(7)]),
                    Expr::val("eggs"),
                    Expr::set(vec![Expr::val(3)])
                ]),
                Expr::set(vec![Expr::val(3)])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );

        // ["2", 20, true, <entity foo>] contains 2
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::val("2"),
                    Expr::val(20),
                    Expr::val(true),
                    Expr::val(EntityUID::with_eid("foo")),
                ]),
                Expr::val(2)
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // ["ham", entity_with_attrs.address.town, -1] contains "barmstadt"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::val("ham"),
                    Expr::get_attr(
                        Expr::get_attr(
                            Expr::val(EntityUID::with_eid("entity_with_attrs")),
                            "address".into()
                        ),
                        "town".into()
                    ),
                    Expr::val(-1),
                ]),
                Expr::val("barmstadt")
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // 3 contains 7
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(Expr::val(3), Expr::val(7))),
            Err(EvaluationError::type_error(vec![Type::Set], Type::Long))
        );
        // { ham: "eggs" } contains "ham"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::record(vec![("ham".into(), Expr::val("eggs"))]),
                Expr::val("ham")
            )),
            Err(EvaluationError::type_error(vec![Type::Set], Type::Record))
        );
        // wrong argument order
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::val(3),
                Expr::set(vec![Expr::val(1), Expr::val(3), Expr::val(7)])
            )),
            Err(EvaluationError::type_error(vec![Type::Set], Type::Long))
        );
    }

    #[test]
    fn interpret_hierarchy_membership() {
        let request = basic_request();
        let entities = rich_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        // A in B, where A and B are unrelated (but same type)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::val(EntityUID::with_eid("unrelated"))
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // A in B, where A and B are the same type and it's true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::val(EntityUID::with_eid("parent"))
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // A in B, where A and B are different types and it's true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(
                    EntityUID::with_eid_and_type("other_type", "other_child")
                        .expect("should be a valid identifier")
                ),
                Expr::val(EntityUID::with_eid("parent"))
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // A in B, where A and B are unrelated _and_ different types
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(
                    EntityUID::with_eid_and_type("other_type", "other_child")
                        .expect("should be a valid identifier")
                ),
                Expr::val(EntityUID::with_eid("unrelated"))
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // A in B, where A and B are siblings
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::val(EntityUID::with_eid("sibling"))
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // A in A, where A exists
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("parent")),
                Expr::val(EntityUID::with_eid("parent"))
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // A in A, where A does not exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("doesnotexist")),
                Expr::val(EntityUID::with_eid("doesnotexist")),
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // A in A, where A is unspecified
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::unspecified_from_eid(Eid::new("foo"))),
                Expr::val(EntityUID::unspecified_from_eid(Eid::new("foo"))),
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // A in B, where actually B in A
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("parent")),
                Expr::val(EntityUID::with_eid("child"))
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // A in B, where actually A is a grandchild of B
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::val(EntityUID::with_eid("grandparent"))
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // A in B, where A doesn't exist but B does
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("doesnotexist")),
                Expr::val(EntityUID::with_eid("parent"))
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // A in B, where B doesn't exist but A does
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("parent")),
                Expr::val(EntityUID::with_eid("doesnotexist"))
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // A in B, where A is unspecified but B exists
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::unspecified_from_eid(Eid::new("foo"))),
                Expr::val(EntityUID::with_eid("parent"))
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // A in B, where A exists but B is unspecified
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("parent")),
                Expr::val(EntityUID::unspecified_from_eid(Eid::new("foo")))
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // A in [B, C] where A in B but not A in C
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("grandparent")),
                    Expr::val(EntityUID::with_eid("sibling")),
                ])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // A in [B, C] where A in C but not A in B
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("sibling")),
                    Expr::val(EntityUID::with_eid("grandparent")),
                ])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // A in [B, C] where A is in neither B nor C
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("sibling")),
                    Expr::val(EntityUID::with_eid("unrelated")),
                ])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // A in [A, B] where B is unrelated
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("unrelated")),
                    Expr::val(EntityUID::with_eid("child")),
                ])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // A in [B, A] where B is unrelated
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("child")),
                    Expr::val(EntityUID::with_eid("unrelated")),
                ])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // A in [A, true]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("child")),
                    Expr::val(true),
                ])
            )),
            Err(EvaluationError::type_error(
                vec![Type::entity_type(
                    Name::parse_unqualified_name("any_entity_type")
                        .expect("should be a valid identifier")
                )],
                Type::Bool,
            ))
        );
        // A in [A, B] where A and B do not exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("doesnotexistA")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("doesnotexistA")),
                    Expr::val(EntityUID::with_eid("doesnotexistB")),
                ])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // A in [B, C] where none of A, B, or C exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("doesnotexistA")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("doesnotexistB")),
                    Expr::val(EntityUID::with_eid("doesnotexistC")),
                ])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // A in [B, C] where B and C do not exist but A does
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("doesnotexistB")),
                    Expr::val(EntityUID::with_eid("doesnotexistC")),
                ])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // A in [B, C] where B and C exist but A does not
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("doesnotexistA")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("child")),
                    Expr::val(EntityUID::with_eid("grandparent")),
                ])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // "foo" in "foobar"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(Expr::val("foo"), Expr::val("foobar"))),
            Err(EvaluationError::type_error(
                vec![Type::entity_type(
                    Name::parse_unqualified_name("any_entity_type")
                        .expect("should be a valid identifier")
                )],
                Type::String,
            ))
        );
        // "spoon" in A (where has(A.spoon))
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val("spoon"),
                Expr::val(EntityUID::with_eid("entity_with_attrs"))
            )),
            Err(EvaluationError::type_error(
                vec![Type::entity_type(
                    Name::parse_unqualified_name("any_entity_type")
                        .expect("should be a valid identifier")
                )],
                Type::String,
            ))
        );
        // 3 in [34, -2, 7]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(3),
                Expr::set(vec![Expr::val(34), Expr::val(-2), Expr::val(7)])
            )),
            Err(EvaluationError::type_error_with_advice(
                vec![Type::entity_type(
                    Name::parse_unqualified_name("any_entity_type")
                        .expect("should be a valid identifier")
                )],
                Type::Long,
                "`in` is for checking the entity hierarchy, use `.contains()` to test set membership".into(),
            ))
        );
        // "foo" in { "foo": 2, "bar": true }
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val("foo"),
                Expr::record(vec![
                    ("foo".into(), Expr::val(2)),
                    ("bar".into(), Expr::val(true)),
                ])
            )),
            Err(EvaluationError::type_error_with_advice(
                vec![Type::entity_type(
                    Name::parse_unqualified_name("any_entity_type")
                        .expect("should be a valid identifier")
                )],
                Type::String,
                "`in` is for checking the entity hierarchy, use `has` to test if a record has a key".into(),
            ))
        );
        // A in { "foo": 2, "bar": true }
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::record(vec![
                    ("foo".into(), Expr::val(2)),
                    ("bar".into(), Expr::val(true)),
                ])
            )),
            Err(EvaluationError::type_error(
                vec![
                    Type::Set,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    )
                ],
                Type::Record,
            ))
        );
    }

    #[test]
    fn interpret_hierarchy_membership_slice() {
        // User::"Alice" in Group::"Friends".
        // Slice.attributes = {Alice},
        // Slice.hierarchy = {Alice, Group::Friends}
        // Should be allow under new semantics for "in"

        let request = Request::new(
            EntityUID::with_eid("Alice"),
            EntityUID::with_eid("test_action"),
            EntityUID::with_eid("test_resource"),
            Context::empty(),
        );
        //Alice has parent "Friends" but we don't add "Friends" to the slice
        let mut alice = Entity::with_uid(EntityUID::with_eid("Alice"));
        let parent: Entity<RestrictedExpr> = Entity::with_uid(EntityUID::with_eid("Friends"));
        alice.add_ancestor(parent.uid());
        let entities = Entities::from_entities(vec![alice], TCComputation::AssumeAlreadyComputed)
            .expect("failed to create basic entities");
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("Alice")),
                Expr::val(EntityUID::with_eid("Friends"))
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("Bob")),
                Expr::val(EntityUID::with_eid("Friends"))
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("Alice")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("Friends")),
                    Expr::val(EntityUID::with_eid("Bob"))
                ])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("Bob")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("Friends")),
                    Expr::val(EntityUID::with_eid("Alice"))
                ])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
    }

    #[test]
    fn interpret_string_like() {
        let request = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        // "eggs" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs" like "*ham*""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // "ham and eggs" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham and eggs" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham and eggs" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham and eggs" like "*ham*""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham and eggs" like "*h*a*m*""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // "eggs and ham" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs and ham" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs and ham" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // "eggs, ham, and spinach" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs, ham, and spinach" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs, ham, and spinach" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs, ham, and spinach" like "*ham*""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // "Gotham" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""Gotham" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""Gotham" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // "ham" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham" like "ham""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham" like "*h*a*m*""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // "ham and ham" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham and ham" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham and ham" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // "ham" vs "ham and eggs"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham" like "*ham and eggs*""#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // type error
        assert_eq!(
            eval.interpret_inline_policy(&Expr::like(Expr::val(354), vec![])),
            Err(EvaluationError::type_error(vec![Type::String], Type::Long))
        );
        // 'contains' is not allowed on strings
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::val("ham and ham"),
                Expr::val("ham")
            )),
            Err(EvaluationError::type_error(vec![Type::Set], Type::String))
        );
        // '\0' should not match '*'
        assert_eq!(
            eval.interpret_inline_policy(&Expr::like(
                Expr::val("*"),
                vec![PatternElem::Char('\u{0000}')]
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );

        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"   "\\afterslash" like "\\*"   "#).expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
    }

    #[test]
    fn interpret_string_like_escaped_chars() {
        let request = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        // testing like wth escaped characters -- similar tests are also in parser/convert.rs
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""string\\with\\backslashes" like "string\\with\\backslashes""#)
                    .expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(
                    r#""string\\with\\backslashes" like "string\u{0000}with\u{0000}backslashe""#
                )
                .expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""string\\with\\backslashes" like "string*with*backslashes""#)
                    .expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""string*with*stars" like "string\*with\*stars""#)
                    .expect("parsing error")
            ),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        assert_eq!(eval.interpret_inline_policy(&parse_expr(r#""string\\*with\\*backslashes\\*and\\*stars" like "string\\*with\\*backslashes\\*and\\*stars""#).expect("parsing error")), Ok(Value::Lit(Literal::Bool(true))));
    }

    #[test]
    fn interpret_contains_all_and_contains_any() -> Result<()> {
        let request = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&request, &entities, &exts).expect("failed to create evaluator");
        //  [1, -22, 34] containsall of [1, -22]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)]),
                Expr::set(vec![Expr::val(1), Expr::val(-22)])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // [1, -22, 34] containsall [-22, 1]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)]),
                Expr::set(vec![Expr::val(-22), Expr::val(1)])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // [1, -22, 34] containsall [-22]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)]),
                Expr::set(vec![Expr::val(-22)])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // [43, 34] containsall [34, 43]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(43), Expr::val(34)]),
                Expr::set(vec![Expr::val(34), Expr::val(43)])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // [1, -2, 34] containsall [1, -22]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(1), Expr::val(-2), Expr::val(34)]),
                Expr::set(vec![Expr::val(1), Expr::val(-22)])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // [1, 34] containsall [1, 101, 34]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(1), Expr::val(34)]),
                Expr::set(vec![Expr::val(1), Expr::val(101), Expr::val(34)])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // [1, 34, 102] containsall [1, 101, 34]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(1), Expr::val(34), Expr::val(102)]),
                Expr::set(vec![Expr::val(1), Expr::val(101), Expr::val(34)])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // [2, -7, 387] containsall [1, 101, 34]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(2), Expr::val(-7), Expr::val(387)]),
                Expr::set(vec![Expr::val(1), Expr::val(101), Expr::val(34)])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // [2, 43] containsall []?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(2), Expr::val(43)]),
                Expr::set(vec![])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // [] containsall [2, 43]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![]),
                Expr::set(vec![Expr::val(2), Expr::val(43)])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // [<entity bar>, <entity foo>] containsall [<entity foo>]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("bar")),
                    Expr::val(EntityUID::with_eid("foo"))
                ]),
                Expr::set(vec![Expr::val(EntityUID::with_eid("foo"))])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // [false, 3, [47, 0], {"2": "ham"}] containsall [3, {"2": "ham"}]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![
                    Expr::val(false),
                    Expr::val(3),
                    Expr::set(vec![Expr::val(47), Expr::val(0)]),
                    Expr::record(vec![("2".into(), Expr::val("ham"))])
                ]),
                Expr::set(vec![
                    Expr::val(3),
                    Expr::record(vec![("2".into(), Expr::val("ham"))])
                ])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        //  "ham and eggs" containsall "ham"?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::val("ham"),
                Expr::val("ham and eggs")
            )),
            Err(EvaluationError::type_error(vec![Type::Set], Type::String))
        );
        // {"2": "ham", "3": "eggs"} containsall {"2": "ham"} ?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::record(vec![("2".into(), Expr::val("ham"))]),
                Expr::record(vec![
                    ("2".into(), Expr::val("ham")),
                    ("3".into(), Expr::val("eggs"))
                ])
            )),
            Err(EvaluationError::type_error(vec![Type::Set], Type::Record))
        );
        // test for [1, -22] contains_any of [1, -22, 34]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![Expr::val(1), Expr::val(-22)]),
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // test for [1, -22, 34] contains_any of [1, -22]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)]),
                Expr::set(vec![Expr::val(1), Expr::val(-22)])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // test for [-22] contains_any of [1, -22, 34]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![Expr::val(-22)]),
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // test for [1, 101] contains_any of [1, -22, 34]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![Expr::val(1), Expr::val(101)]),
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // test for [1, 101] contains_any of [-22, 34]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![Expr::val(1), Expr::val(101)]),
                Expr::set(vec![Expr::val(-22), Expr::val(34)])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // test for [] contains_any of [-22, 34]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![]),
                Expr::set(vec![Expr::val(-22), Expr::val(34)])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // test for [-22, 34] contains_any of []
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![Expr::val(-22), Expr::val(34)]),
                Expr::set(vec![])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // test for [<entity foo>, <entity bar>] contains_any of [<entity ham>, <entity eggs>]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("foo")),
                    Expr::val(EntityUID::with_eid("bar"))
                ]),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("ham")),
                    Expr::val(EntityUID::with_eid("eggs"))
                ])
            )),
            Ok(Value::Lit(Literal::Bool(false)))
        );
        // test for [3, {"2": "ham", "1": "eggs"}] contains_any of [7, false, [-22, true], {"1": "eggs", "2": "ham"}]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![
                    Expr::val(3),
                    Expr::record(vec![
                        ("2".into(), Expr::val("ham")),
                        ("1".into(), Expr::val("eggs"))
                    ])
                ]),
                Expr::set(vec![
                    Expr::val(7),
                    Expr::val(false),
                    Expr::set(vec![Expr::val(-22), Expr::val(true)]),
                    Expr::record(vec![
                        ("1".into(), Expr::val("eggs")),
                        ("2".into(), Expr::val("ham"))
                    ])
                ])
            )),
            Ok(Value::Lit(Literal::Bool(true)))
        );
        // test for "ham" contains_any of "ham and eggs"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::val("ham"),
                Expr::val("ham and eggs")
            )),
            Err(EvaluationError::type_error(vec![Type::Set], Type::String))
        );
        // test for {"2": "ham"} contains_any of {"2": "ham", "3": "eggs"}
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::record(vec![("2".into(), Expr::val("ham"))]),
                Expr::record(vec![
                    ("2".into(), Expr::val("ham")),
                    ("3".into(), Expr::val("eggs"))
                ])
            )),
            Err(EvaluationError::type_error(vec![Type::Set], Type::Record))
        );
        Ok(())
    }

    #[test]
    fn eval_and_or() -> Result<()> {
        use crate::parser;
        let request = basic_request();
        let eparser: EntityJsonParser<'_> =
            EntityJsonParser::new(None, Extensions::none(), TCComputation::ComputeNow);
        let entities = eparser
            .from_json_str("[]")
            .expect("empty slice")
            .eval_attrs(&Extensions::none())
            .expect("empty slice");
        let exts = Extensions::none();
        let evaluator = Evaluator::new(&request, &entities, &exts).expect("empty slice");

        // short-circuit allows these to pass without error
        let raw_expr = "(false && 3)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_ok());

        let raw_expr = "(true || 3)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_ok());

        // short-circuit plus total equality allows these to pass without error
        let raw_expr = "(false && 3) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_ok());

        let raw_expr = "(true || 3) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_ok());

        let raw_expr = "(false && 3 && true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_ok());

        let raw_expr = "(true || 3 || true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_ok());

        // These must error
        let raw_expr = "(true && 3)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        let t = evaluator.interpret_inline_policy(&expr);
        println!("EXPR={:?}", t);
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(3 && true)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(3 && false)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(3 || true)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(3 || false)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(false || 3)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(true && 3) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(3 && true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(3 && false) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(3 || true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(3 || false) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(false || 3) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(true && 3 && true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(3 && true && true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(3 && false && true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(3 || true || true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(3 || false || true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        let raw_expr = "(false || 3 || true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert!(evaluator.interpret_inline_policy(&expr).is_err());

        Ok(())
    }

    #[test]
    fn template_env_tests() {
        let request = basic_request();
        let eparser: EntityJsonParser<'_> =
            EntityJsonParser::new(None, Extensions::none(), TCComputation::ComputeNow);
        let entities = eparser
            .from_json_str("[]")
            .expect("empty slice")
            .eval_attrs(&Extensions::none())
            .expect("empty slice");
        let exts = Extensions::none();
        let evaluator = Evaluator::new(&request, &entities, &exts).expect("empty slice");
        let e = Expr::slot(SlotId::principal());

        let slots = HashMap::new();
        let r = evaluator.partial_interpret(&e, &slots);
        match r {
            Err(e) => match e.error_kind() {
                EvaluationErrorKind::UnlinkedSlot(slotid) => {
                    assert_eq!(*slotid, SlotId::principal())
                }
                _ => panic!("Got wrong error: {e}"),
            },
            Ok(v) => panic!("Got wrong response: {v}"),
        };

        let mut slots = HashMap::new();
        slots.insert(SlotId::principal(), EntityUID::with_eid("eid"));
        let r = evaluator.partial_interpret(&e, &slots);
        match r {
            Ok(e) => assert_eq!(
                e,
                PartialValue::Value(Value::Lit(Literal::EntityUID(Arc::new(
                    EntityUID::with_eid("eid")
                ))))
            ),
            Err(e) => panic!("Got unexpected error {e}"),
        };
    }

    #[test]
    fn template_interp() {
        let t = parse_policy_template(
            Some("template".to_string()),
            r#"permit(principal == ?principal, action, resource);"#,
        )
        .expect("Parse Error");
        let mut pset = PolicySet::new();
        pset.add_template(t)
            .expect("Template already present in PolicySet");
        let mut values = HashMap::new();
        values.insert(SlotId::principal(), EntityUID::with_eid("p"));
        pset.link(
            PolicyID::from_string("template"),
            PolicyID::from_string("instance"),
            values,
        )
        .expect("Instantiation failed!");
        let q = Request::new(
            EntityUID::with_eid("p"),
            EntityUID::with_eid("a"),
            EntityUID::with_eid("r"),
            Context::empty(),
        );
        let eparser: EntityJsonParser<'_> =
            EntityJsonParser::new(None, Extensions::none(), TCComputation::ComputeNow);
        let entities = eparser
            .from_json_str("[]")
            .expect("empty slice")
            .eval_attrs(&Extensions::none())
            .expect("empty slice");
        let exts = Extensions::none();
        let eval = Evaluator::new(&q, &entities, &exts).expect("Failed to start evaluator");

        let ir = pset.policies().next().expect("No linked policies");
        assert!(
            match eval.partial_evaluate(ir).expect("evaluation_failed") {
                Either::Left(b) => b,
                Either::Right(_) => false,
            },
            "Should be enforced"
        );
    }

    fn assert_restricted_expression_error(v: Result<PartialValue>) {
        match v {
            Err(e) => assert_matches!(
                e.error_kind(),
                EvaluationErrorKind::InvalidRestrictedExpression { .. }
            ),
            Ok(v) => panic!("Got wrong response: {v}"),
        }
    }

    #[test]
    fn restricted_expressions() {
        let exts = Extensions::all_available();
        let evaluator = RestrictedEvaluator::new(&exts);

        // simple expressions
        assert_eq!(
            BorrowedRestrictedExpr::new(&Expr::val(true))
                .map_err(Into::into)
                .and_then(|e| evaluator.partial_interpret(e)),
            Ok(Value::from(true).into())
        );
        assert_eq!(
            BorrowedRestrictedExpr::new(&Expr::val(-2))
                .map_err(Into::into)
                .and_then(|e| evaluator.partial_interpret(e)),
            Ok(Value::from(-2).into())
        );
        assert_eq!(
            BorrowedRestrictedExpr::new(&Expr::val("hello world"))
                .map_err(Into::into)
                .and_then(|e| evaluator.partial_interpret(e)),
            Ok(Value::from("hello world").into())
        );
        assert_eq!(
            BorrowedRestrictedExpr::new(&Expr::val(EntityUID::with_eid("alice")))
                .map_err(Into::into)
                .and_then(|e| evaluator.partial_interpret(e)),
            Ok(Value::from(EntityUID::with_eid("alice")).into())
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::var(Var::Principal))
                .map_err(Into::into)
                .and_then(|e| evaluator.partial_interpret(e)),
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::var(Var::Action))
                .map_err(Into::into)
                .and_then(|e| evaluator.partial_interpret(e)),
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::var(Var::Resource))
                .map_err(Into::into)
                .and_then(|e| evaluator.partial_interpret(e)),
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::var(Var::Context))
                .map_err(Into::into)
                .and_then(|e| evaluator.partial_interpret(e)),
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::ite(Expr::val(true), Expr::val(7), Expr::val(12)))
                .map_err(Into::into)
                .and_then(|e| evaluator.partial_interpret(e)),
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::and(Expr::val("bogus"), Expr::val(true)))
                .map_err(Into::into)
                .and_then(|e| evaluator.partial_interpret(e)),
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::or(Expr::val("bogus"), Expr::val(true)))
                .map_err(Into::into)
                .and_then(|e| evaluator.partial_interpret(e)),
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::not(Expr::val(true)))
                .map_err(Into::into)
                .and_then(|e| evaluator.partial_interpret(e)),
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::is_in(
                Expr::val(EntityUID::with_eid("alice")),
                Expr::val(EntityUID::with_eid("some_group")),
            ))
            .map_err(Into::into)
            .and_then(|e| evaluator.partial_interpret(e)),
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::is_eq(
                Expr::val(EntityUID::with_eid("alice")),
                Expr::val(EntityUID::with_eid("some_group")),
            ))
            .map_err(Into::into)
            .and_then(|e| evaluator.partial_interpret(e)),
        );
        #[cfg(feature = "ipaddr")]
        assert_matches!(
            BorrowedRestrictedExpr::new(&Expr::call_extension_fn(
                "ip".parse().expect("should be a valid Name"),
                vec![Expr::val("222.222.222.222")]
            ))
            .map_err(Into::into)
            .and_then(|e| evaluator.partial_interpret(e)),
            Ok(PartialValue::Value(Value::ExtensionValue(_)))
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::get_attr(
                Expr::val(EntityUID::with_eid("alice")),
                "pancakes".into(),
            ))
            .map_err(Into::into)
            .and_then(|e| evaluator.partial_interpret(e)),
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::has_attr(
                Expr::val(EntityUID::with_eid("alice")),
                "pancakes".into(),
            ))
            .map_err(Into::into)
            .and_then(|e| evaluator.partial_interpret(e)),
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::like(
                Expr::val("abcdefg12"),
                vec![
                    PatternElem::Char('a'),
                    PatternElem::Char('b'),
                    PatternElem::Char('c'),
                    PatternElem::Wildcard,
                ],
            ))
            .map_err(Into::into)
            .and_then(|e| evaluator.partial_interpret(e)),
        );
        assert_matches!(
            BorrowedRestrictedExpr::new(&Expr::set([Expr::val("hi"), Expr::val("there")]))
                .map_err(Into::into)
                .and_then(|e| evaluator.partial_interpret(e)),
            Ok(PartialValue::Value(Value::Set(_)))
        );
        assert_matches!(
            BorrowedRestrictedExpr::new(&Expr::record([
                ("hi".into(), Expr::val(1001)),
                ("foo".into(), Expr::val("bar"))
            ]),)
            .map_err(Into::into)
            .and_then(|e| evaluator.partial_interpret(e)),
            Ok(PartialValue::Value(Value::Record(_)))
        );

        // complex expressions -- for instance, violation not at top level
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::set([
                Expr::val("hi"),
                Expr::and(Expr::val("bogus"), Expr::val(false)),
            ]))
            .map_err(Into::into)
            .and_then(|e| evaluator.partial_interpret(e)),
        );
        assert_restricted_expression_error(
            BorrowedRestrictedExpr::new(&Expr::call_extension_fn(
                "ip".parse().expect("should be a valid Name"),
                vec![Expr::var(Var::Principal)],
            ))
            .map_err(Into::into)
            .and_then(|e| evaluator.partial_interpret(e)),
        );
    }

    #[test]
    fn simple_partial() {
        let pset = parse_policyset(
            r#"
            permit(principal == Principal::"alice", action, resource);
            "#,
        )
        .expect("Failed to parse");
        let euid =
            Arc::new(EntityUID::from_str(r#"Principal::"alice""#).expect("EUID failed to parse"));
        let p = pset
            .get(&PolicyID::from_string("policy0"))
            .expect("No such policy");
        let q = Request::new_with_unknowns(
            EntityUIDEntry::Unknown,
            EntityUIDEntry::Unknown,
            EntityUIDEntry::Unknown,
            Some(Context::empty()),
        );
        let es = Entities::new();
        let exts = Extensions::none();
        let e = Evaluator::new(&q, &es, &exts).expect("failed to create evaluator");
        match e.partial_evaluate(p).expect("eval error") {
            Either::Left(_) => panic!("Evalled to a value"),
            Either::Right(expr) => {
                println!("{expr}");
                assert!(expr.is_unknown());
                let m: HashMap<_, _> = [("principal".into(), Value::Lit(Literal::EntityUID(euid)))]
                    .into_iter()
                    .collect();
                let new_expr = expr.substitute(&m).unwrap();
                assert_eq!(
                    e.partial_interpret(&new_expr, &HashMap::new())
                        .expect("Failed to eval"),
                    PartialValue::Value(true.into())
                );
            }
        }
    }

    fn partial_context_test(context_expr: Expr, e: Expr) -> Either<Value, Expr> {
        let euid: EntityUID = r#"Test::"test""#.parse().unwrap();
        let rexpr = RestrictedExpr::new(context_expr)
            .expect("Context Expression was not a restricted expression");
        let context = Context::from_expr(rexpr);
        let q = Request::new(euid.clone(), euid.clone(), euid, context);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&q, &es, &exts).expect("Failed to instantiate evaluator");
        eval.partial_eval_expr(&e).unwrap()
    }

    #[test]
    fn partial_contexts1() {
        // { "cell" : <unknown> }
        let c_expr = Expr::record([("cell".into(), Expr::unknown("cell"))]);
        let expr = Expr::binary_app(
            BinaryOp::Eq,
            Expr::get_attr(Expr::var(Var::Context), "cell".into()),
            Expr::val(2),
        );
        let expected = Expr::binary_app(
            BinaryOp::Eq,
            Expr::unknown("cell".to_string()),
            Expr::val(2),
        );

        let r = partial_context_test(c_expr, expr);

        assert_eq!(r, Either::Right(expected));
    }

    #[test]
    fn partial_contexts2() {
        // { "loc" : "test", "cell" : <unknown> }
        let c_expr = Expr::record([
            ("loc".into(), Expr::val("test")),
            ("cell".into(), Expr::unknown("cell")),
        ]);
        // context["cell"] == 2
        let expr = Expr::binary_app(
            BinaryOp::Eq,
            Expr::get_attr(Expr::var(Var::Context), "cell".into()),
            Expr::val(2),
        );
        let r = partial_context_test(c_expr.clone(), expr);
        let expected = Expr::binary_app(
            BinaryOp::Eq,
            Expr::unknown("cell".to_string()),
            Expr::val(2),
        );
        assert_eq!(r, Either::Right(expected));

        // context["loc"] == 2
        let expr = Expr::binary_app(
            BinaryOp::Eq,
            Expr::get_attr(Expr::var(Var::Context), "loc".into()),
            Expr::val(2),
        );
        let r = partial_context_test(c_expr, expr);
        assert_eq!(r, Either::Left(false.into()));
    }

    #[test]
    fn partial_contexts3() {
        // { "loc" : "test", "cell" : { "row" : <unknown> } }
        let row = Expr::record([("row".into(), Expr::unknown("row"))]);
        //assert!(row.is_partially_projectable());
        let c_expr = Expr::record([("loc".into(), Expr::val("test")), ("cell".into(), row)]);
        //assert!(c_expr.is_partially_projectable());
        // context["cell"]["row"] == 2
        let expr = Expr::binary_app(
            BinaryOp::Eq,
            Expr::get_attr(
                Expr::get_attr(Expr::var(Var::Context), "cell".into()),
                "row".into(),
            ),
            Expr::val(2),
        );
        let r = partial_context_test(c_expr, expr);
        let expected =
            Expr::binary_app(BinaryOp::Eq, Expr::unknown("row".to_string()), Expr::val(2));
        assert_eq!(r, Either::Right(expected));
    }

    #[test]
    fn partial_contexts4() {
        // { "loc" : "test", "cell" : { "row" : <unknown>, "col" : <unknown> } }
        let row = Expr::record([
            ("row".into(), Expr::unknown("row")),
            ("col".into(), Expr::unknown("col")),
        ]);
        //assert!(row.is_partially_projectable());
        let c_expr = Expr::record([("loc".into(), Expr::val("test")), ("cell".into(), row)]);
        //assert!(c_expr.is_partially_projectable());
        // context["cell"]["row"] == 2
        let expr = Expr::binary_app(
            BinaryOp::Eq,
            Expr::get_attr(
                Expr::get_attr(Expr::var(Var::Context), "cell".into()),
                "row".into(),
            ),
            Expr::val(2),
        );
        let r = partial_context_test(c_expr.clone(), expr);
        let expected = Expr::binary_app(BinaryOp::Eq, Expr::unknown("row"), Expr::val(2));
        assert_eq!(r, Either::Right(expected));
        // context["cell"]["col"] == 2
        let expr = Expr::binary_app(
            BinaryOp::Eq,
            Expr::get_attr(
                Expr::get_attr(Expr::var(Var::Context), "cell".into()),
                "col".into(),
            ),
            Expr::val(2),
        );
        let r = partial_context_test(c_expr, expr);
        let expected =
            Expr::binary_app(BinaryOp::Eq, Expr::unknown("col".to_string()), Expr::val(2));
        assert_eq!(r, Either::Right(expected));
    }

    #[test]
    fn partial_context_fail() {
        let context = Context::from_expr(RestrictedExpr::new_unchecked(Expr::record([
            ("a".into(), Expr::val(3)),
            ("b".into(), Expr::unknown("b".to_string())),
        ])));
        let euid: EntityUID = r#"Test::"test""#.parse().unwrap();
        let q = Request::new(euid.clone(), euid.clone(), euid, context);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&q, &es, &exts).expect("Failed to instantiate evaluator");
        let e = Expr::get_attr(Expr::var(Var::Context), "foo".into());
        assert!(eval.partial_eval_expr(&e).is_err())
    }

    #[test]
    fn mikes_test() {
        let policyset = parse_policyset(
            r#"
            permit(
                principal == Principal::"p",
                action == Action::"a",
                resource == Table::"t"
            ) when {
                context.cell.row > 5 && context.cell.col < 2
            };
        "#,
        )
        .expect("Failed to parse");
        let policy = policyset
            .get(&PolicyID::from_string("policy0"))
            .expect("No such policy");

        let es = Entities::new();

        let p: EntityUID = r#"Principal::"p""#.parse().expect("Failed to parse");
        let a: EntityUID = r#"Action::"a""#.parse().expect("Failed to parse");
        let r: EntityUID = r#"Table::"t""#.parse().expect("Failed to parse");

        let c_expr = RestrictedExpr::new(Expr::record([(
            "cell".into(),
            Expr::unknown("cell".to_string()),
        )]))
        .expect("should qualify as restricted");
        let context = Context::from_expr(c_expr);

        let q = Request::new(p, a, r, context);
        let exts = Extensions::none();
        let eval = Evaluator::new(&q, &es, &exts).expect("Could not create evaluator");

        let result = eval.partial_evaluate(policy).expect("Eval error");
        match result {
            Either::Left(_) => panic!("Got a value"),
            Either::Right(r) => {
                println!("{r}");
            }
        }
    }

    fn empty_request() -> Request {
        let p: EntityUID = r#"p::"Principal""#.parse().unwrap();
        let a: EntityUID = r#"a::"Action""#.parse().unwrap();
        let r: EntityUID = r#"r::"Resource""#.parse().unwrap();
        let c = Context::empty();
        Request::new(p, a, r, c)
    }

    #[test]
    fn if_semantics_residual_guard() {
        let a = Expr::unknown("guard".to_string());
        let b = Expr::and(Expr::val(1), Expr::val(2));
        let c = Expr::val(true);

        let e = Expr::ite(a, b, c);

        let es = Entities::new();

        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(
            r,
            PartialValue::Residual(Expr::ite(
                Expr::unknown("guard".to_string()),
                Expr::call_extension_fn(
                    "error".parse().unwrap(),
                    vec![Expr::val("type error: expected bool, got long")]
                ),
                Expr::val(true)
            ))
        )
    }

    #[test]
    fn if_semantics_residual_reduce() {
        let a = Expr::binary_app(
            BinaryOp::Eq,
            Expr::get_attr(Expr::var(Var::Context), "condition".into()),
            Expr::val("value"),
        );
        let b = Expr::val("true branch");
        let c = Expr::val("false branch");

        let e = Expr::ite(a, b.clone(), c.clone());

        let es = Entities::new();

        let exts = Extensions::none();
        let q = Request::new(
            EntityUID::with_eid("p"),
            EntityUID::with_eid("a"),
            EntityUID::with_eid("r"),
            Context::from_expr(RestrictedExpr::new_unchecked(Expr::record([(
                "condition".into(),
                Expr::unknown("unknown_condition"),
            )]))),
        );
        let eval = Evaluator::new(&q, &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(
            r,
            PartialValue::Residual(Expr::ite(
                Expr::binary_app(
                    BinaryOp::Eq,
                    Expr::unknown("unknown_condition".to_string()),
                    Expr::val("value"),
                ),
                b,
                c
            ))
        );
    }

    #[test]
    fn if_semantics_both_err() {
        let a = Expr::unknown("guard".to_string());
        let b = Expr::and(Expr::val(1), Expr::val(2));
        let c = Expr::or(Expr::val(1), Expr::val(3));

        let e = Expr::ite(a, b, c);

        let es = Entities::new();

        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        assert!(eval.partial_interpret(&e, &HashMap::new()).is_err());
    }

    #[test]
    fn and_semantics1() {
        // Left-hand-side evaluates to `false`, should short-circuit to value
        let e = Expr::and(
            Expr::binary_app(BinaryOp::Eq, Expr::val(1), Expr::val(2)),
            Expr::and(Expr::unknown("a".to_string()), Expr::val(false)),
        );

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Value(Value::Lit(Literal::Bool(false))));
    }

    #[test]
    fn and_semantics2() {
        // Left hand sides evaluates to `true`, can't drop it due to dynamic types
        let e = Expr::and(
            Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(2)),
            Expr::and(Expr::unknown("a".to_string()), Expr::val(false)),
        );

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(
            r,
            PartialValue::Residual(Expr::and(
                Expr::val(true),
                Expr::and(Expr::unknown("a".to_string()), Expr::val(false))
            ))
        );
    }

    #[test]
    fn and_semantics3() {
        // Errors on left hand side should propagate
        let e = Expr::and(
            Expr::binary_app(BinaryOp::Add, Expr::val("hello"), Expr::val(2)),
            Expr::and(Expr::unknown("a".to_string()), Expr::val(false)),
        );

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        assert!(eval.partial_interpret(&e, &HashMap::new()).is_err());
    }

    #[test]
    fn and_semantics4() {
        // Left hand is residual, errors on right hand side should _not_ propagate
        let e = Expr::and(
            Expr::binary_app(BinaryOp::Eq, Expr::unknown("a".to_string()), Expr::val(2)),
            Expr::and(Expr::val("hello"), Expr::val("bye")),
        );

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        assert!(eval.partial_interpret(&e, &HashMap::new()).is_ok());
    }

    #[test]
    fn or_semantics1() {
        // Left-hand-side evaluates to `true`, should short-circuit to value

        let e = Expr::or(
            Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(2)),
            Expr::and(Expr::unknown("a".to_string()), Expr::val(false)),
        );

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Value(Value::Lit(Literal::Bool(true))));
    }

    #[test]
    fn or_semantics2() {
        // Left hand sides evaluates to `false`, can't drop it due to dynamic types
        let e = Expr::or(
            Expr::binary_app(BinaryOp::Eq, Expr::val(1), Expr::val(2)),
            Expr::and(Expr::unknown("a".to_string()), Expr::val(false)),
        );

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(
            r,
            PartialValue::Residual(Expr::or(
                Expr::val(false),
                Expr::and(Expr::unknown("a".to_string()), Expr::val(false))
            ))
        );
    }

    #[test]
    fn or_semantics3() {
        // Errors on left hand side should propagate
        let e = Expr::or(
            Expr::binary_app(BinaryOp::Add, Expr::val("hello"), Expr::val(2)),
            Expr::and(Expr::unknown("a".to_string()), Expr::val(false)),
        );

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        assert!(eval.partial_interpret(&e, &HashMap::new()).is_err());
    }

    #[test]
    fn or_semantics4() {
        // Left hand is residual, errors on right hand side should _not_ propagate
        let e = Expr::or(
            Expr::binary_app(BinaryOp::Eq, Expr::unknown("a".to_string()), Expr::val(2)),
            Expr::and(Expr::val("hello"), Expr::val("bye")),
        );

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        assert!(eval.partial_interpret(&e, &HashMap::new()).is_ok());
    }

    #[test]
    fn record_semantics_err() {
        let a = Expr::get_attr(
            Expr::record([("value".into(), Expr::unknown("test".to_string()))]),
            "notpresent".into(),
        );

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        assert!(eval.partial_interpret(&a, &HashMap::new()).is_err());
    }

    #[test]
    fn record_semantics_key_present() {
        let a = Expr::get_attr(
            Expr::record([("value".into(), Expr::unknown("test".to_string()))]),
            "value".into(),
        );

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&a, &HashMap::new()).unwrap();

        let expected = PartialValue::Residual(Expr::unknown("test"));

        assert_eq!(r, expected);
    }

    #[test]
    fn record_semantics_missing_attr() {
        let a = Expr::get_attr(
            Expr::record([
                ("a".into(), Expr::unknown("a")),
                ("b".into(), Expr::unknown("c")),
            ]),
            "c".into(),
        );

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        assert!(eval.partial_interpret(&a, &HashMap::new()).is_err());
    }

    #[test]
    fn record_semantics_mult_unknowns() {
        let a = Expr::get_attr(
            Expr::record([
                ("a".into(), Expr::unknown("a")),
                ("b".into(), Expr::unknown("b")),
            ]),
            "b".into(),
        );

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&a, &HashMap::new()).unwrap();

        let expected = PartialValue::Residual(Expr::unknown("b"));

        assert_eq!(r, expected);
    }

    #[test]
    fn parital_if_noerrors() {
        let guard = Expr::get_attr(Expr::unknown("a"), "field".into());
        let cons = Expr::val(1);
        let alt = Expr::val(2);
        let e = Expr::ite(guard.clone(), cons, alt);

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::ite(guard, Expr::val(1), Expr::val(2));

        assert_eq!(r, PartialValue::Residual(expected));
    }

    #[test]
    fn parital_if_cons_error() {
        let guard = Expr::get_attr(Expr::unknown("a"), "field".into());
        let cons = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val(true));
        let alt = Expr::val(2);
        let e = Expr::ite(guard.clone(), cons, alt);

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::ite(
            guard,
            Expr::call_extension_fn(
                "error".parse().unwrap(),
                vec![Expr::val("type error: expected long, got bool")],
            ),
            Expr::val(2),
        );

        assert_eq!(r, PartialValue::Residual(expected));
    }

    #[test]
    fn parital_if_alt_error() {
        let guard = Expr::get_attr(Expr::unknown("a"), "field".into());
        let cons = Expr::val(2);
        let alt = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val(true));
        let e = Expr::ite(guard.clone(), cons, alt);

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::ite(
            guard,
            Expr::val(2),
            Expr::call_extension_fn(
                "error".parse().unwrap(),
                vec![Expr::val("type error: expected long, got bool")],
            ),
        );
        assert_eq!(r, PartialValue::Residual(expected));
    }

    #[test]
    fn parital_if_both_error() {
        let guard = Expr::get_attr(Expr::unknown("a"), "field".into());
        let cons = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val(true));
        let alt = Expr::less(Expr::val("hello"), Expr::val("bye"));
        let e = Expr::ite(guard, cons, alt);

        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        assert!(eval.partial_interpret(&e, &HashMap::new()).is_err());
    }

    // err && res -> err
    #[test]
    fn partial_and_err_res() {
        let lhs = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val("test"));
        let rhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let e = Expr::and(lhs, rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        assert!(eval.partial_interpret(&e, &HashMap::new()).is_err());
    }

    // err || res -> err
    #[test]
    fn partial_or_err_res() {
        let lhs = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val("test"));
        let rhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let e = Expr::or(lhs, rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        assert!(eval.partial_interpret(&e, &HashMap::new()).is_err());
    }

    // true && res -> true && res
    #[test]
    fn partial_and_true_res() {
        let lhs = Expr::binary_app(BinaryOp::Eq, Expr::val(1), Expr::val(1));
        let rhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let e = Expr::and(lhs, rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::and(
            Expr::val(true),
            Expr::get_attr(Expr::unknown("test"), "field".into()),
        );
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // false && res -> false
    #[test]
    fn partial_and_false_res() {
        let lhs = Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(1));
        let rhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let e = Expr::and(lhs, rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Value(Value::Lit(false.into())));
    }

    // res && true -> res && true
    #[test]
    fn partial_and_res_true() {
        let lhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let rhs = Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(2));
        let e = Expr::and(lhs.clone(), rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        let expected = Expr::and(lhs, Expr::val(true));
        assert_eq!(r, PartialValue::Residual(expected));
    }

    #[test]
    fn partial_and_res_false() {
        let lhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let rhs = Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(1));
        let e = Expr::and(lhs.clone(), rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        let expected = Expr::and(lhs, Expr::val(false));
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // res && res -> res && res
    #[test]
    fn partial_and_res_res() {
        let lhs = Expr::unknown("b");
        let rhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let e = Expr::and(lhs, rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::and(
            Expr::unknown("b"),
            Expr::get_attr(Expr::unknown("test"), "field".into()),
        );
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // res && err -> res && err
    #[test]
    fn partial_and_res_err() {
        let lhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let rhs = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val("oops"));
        let e = Expr::and(lhs, rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::and(
            Expr::get_attr(Expr::unknown("test"), "field".into()),
            Expr::call_extension_fn(
                "error".parse().unwrap(),
                vec![Expr::val("type error: expected long, got string")],
            ),
        );
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // true || res -> true
    #[test]
    fn partial_or_true_res() {
        let lhs = Expr::binary_app(BinaryOp::Eq, Expr::val(1), Expr::val(1));
        let rhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let e = Expr::or(lhs, rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Value(Value::Lit(true.into())));
    }

    // false || res -> false || res
    #[test]
    fn partial_or_false_res() {
        let lhs = Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(1));
        let rhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let e = Expr::or(lhs, rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        let expected = Expr::or(
            Expr::val(false),
            Expr::get_attr(Expr::unknown("test"), "field".into()),
        );
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // res || true -> res || true
    #[test]
    fn partial_or_res_true() {
        let lhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let rhs = Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(2));
        let e = Expr::or(lhs.clone(), rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        let expected = Expr::or(lhs, Expr::val(true));
        assert_eq!(r, PartialValue::Residual(expected));
    }

    #[test]
    fn partial_or_res_false() {
        let lhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let rhs = Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(1));
        let e = Expr::or(lhs.clone(), rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        let expected = Expr::or(lhs, Expr::val(false));
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // res || res -> res || res
    #[test]
    fn partial_or_res_res() {
        let lhs = Expr::unknown("b");
        let rhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let e = Expr::or(lhs, rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::or(
            Expr::unknown("b"),
            Expr::get_attr(Expr::unknown("test"), "field".into()),
        );
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // res || err -> res || err
    #[test]
    fn partial_or_res_err() {
        let lhs = Expr::get_attr(Expr::unknown("test"), "field".into());
        let rhs = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val("oops"));
        let e = Expr::or(lhs, rhs);
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::or(
            Expr::get_attr(Expr::unknown("test"), "field".into()),
            Expr::call_extension_fn(
                "error".parse().unwrap(),
                vec![Expr::val("type error: expected long, got string")],
            ),
        );
        assert_eq!(r, PartialValue::Residual(expected));
    }

    #[test]
    fn partial_unop() {
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let e = Expr::unary_app(UnaryOp::Neg, Expr::unknown("a"));
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Residual(e));

        let e = Expr::unary_app(UnaryOp::Not, Expr::unknown("a"));
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Residual(e));
    }

    #[test]
    fn partial_binop() {
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let binops = [
            BinaryOp::Add,
            BinaryOp::Contains,
            BinaryOp::ContainsAll,
            BinaryOp::ContainsAny,
            BinaryOp::Eq,
            BinaryOp::In,
            BinaryOp::Less,
            BinaryOp::LessEq,
            BinaryOp::Sub,
        ];

        for binop in binops {
            // ensure PE evaluates left side
            let e = Expr::binary_app(
                binop,
                Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val(2)),
                Expr::unknown("a"),
            );
            let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
            let expected = Expr::binary_app(binop, Expr::val(3), Expr::unknown("a"));
            assert_eq!(r, PartialValue::Residual(expected));
            // ensure PE propagates left side errors
            let e = Expr::binary_app(
                binop,
                Expr::binary_app(BinaryOp::Add, Expr::val("hello"), Expr::val(2)),
                Expr::unknown("a"),
            );
            assert!(eval.partial_interpret(&e, &HashMap::new()).is_err());
            // ensure PE evaluates right side
            let e = Expr::binary_app(
                binop,
                Expr::unknown("a"),
                Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val(2)),
            );
            let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
            let expected = Expr::binary_app(binop, Expr::unknown("a"), Expr::val(3));
            assert_eq!(r, PartialValue::Residual(expected));
            // ensure PE propagates right side errors
            let e = Expr::binary_app(
                binop,
                Expr::unknown("a"),
                Expr::binary_app(BinaryOp::Add, Expr::val("hello"), Expr::val(2)),
            );
            assert!(eval.partial_interpret(&e, &HashMap::new()).is_err());
            // Both left and right residuals
            let e = Expr::binary_app(binop, Expr::unknown("a"), Expr::unknown("b"));
            let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
            let expected = Expr::binary_app(binop, Expr::unknown("a"), Expr::unknown("b"));
            assert_eq!(r, PartialValue::Residual(expected));
        }
    }

    #[test]
    fn partial_mul() {
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let e = Expr::mul(Expr::unknown("a"), 32);
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Residual(e));
    }

    #[test]
    fn partial_ext_constructors() {
        let es = Entities::new();
        let exts = Extensions::all_available();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let e = Expr::call_extension_fn("ip".parse().unwrap(), vec![Expr::unknown("a")]);

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Residual(e));
    }

    #[cfg(feature = "ipaddr")]
    #[test]
    fn partial_ext_unfold() {
        let es = Entities::new();
        let exts = Extensions::all_available();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let a = Expr::call_extension_fn("ip".parse().unwrap(), vec![Expr::val("127.0.0.1")]);
        let b = Expr::unknown("a");
        let e = Expr::call_extension_fn("isInRange".parse().unwrap(), vec![a, b]);

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Residual(e));

        let b = Expr::call_extension_fn("ip".parse().unwrap(), vec![Expr::val("127.0.0.1")]);
        let a = Expr::unknown("a");
        let e = Expr::call_extension_fn("isInRange".parse().unwrap(), vec![a, b]);

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Residual(e));

        let b = Expr::call_extension_fn("ip".parse().unwrap(), vec![Expr::val("invalid")]);
        let a = Expr::unknown("a");
        let e = Expr::call_extension_fn("isInRange".parse().unwrap(), vec![a, b]);

        assert!(eval.partial_interpret(&e, &HashMap::new()).is_err());
    }

    #[test]
    fn partial_like() {
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let e = Expr::like(Expr::unknown("a"), []);

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Residual(e));
    }

    #[test]
    fn partial_hasattr() {
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let e = Expr::has_attr(Expr::unknown("a"), "test".into());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Residual(e));
    }

    #[test]
    fn partial_set() {
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let e = Expr::set([Expr::val(1), Expr::unknown("a"), Expr::val(2)]);
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Residual(e));

        let e = Expr::set([
            Expr::val(1),
            Expr::unknown("a"),
            Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val(2)),
        ]);
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(
            r,
            PartialValue::Residual(Expr::set([Expr::val(1), Expr::unknown("a"), Expr::val(3)]))
        );

        let e = Expr::set([
            Expr::val(1),
            Expr::unknown("a"),
            Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val("a")),
        ]);
        assert!(eval.partial_interpret(&e, &HashMap::new()).is_err());
    }

    #[test]
    fn partial_record() {
        let es = Entities::new();
        let exts = Extensions::none();
        let eval = Evaluator::new(&empty_request(), &es, &exts).unwrap();

        let e = Expr::record([
            ("a".into(), Expr::val(1)),
            ("b".into(), Expr::unknown("a")),
            ("c".into(), Expr::val(2)),
        ]);
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Residual(e));

        let e = Expr::record([("a".into(), Expr::val(1)), ("a".into(), Expr::unknown("a"))]);
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(
            r,
            PartialValue::Residual(Expr::record([
                ("a".into(), Expr::val(1)),
                ("a".into(), Expr::unknown("a"))
            ]))
        );

        let e = Expr::record([("a".into(), Expr::unknown("a")), ("a".into(), Expr::val(1))]);
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(
            r,
            PartialValue::Residual(Expr::record([
                ("a".into(), Expr::unknown("a")),
                ("a".into(), Expr::val(1))
            ]))
        );

        let e = Expr::record([
            ("a".into(), Expr::val(1)),
            ("b".into(), Expr::unknown("a")),
            (
                "c".into(),
                Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val(2)),
            ),
        ]);
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(
            r,
            PartialValue::Residual(Expr::record([
                ("a".into(), Expr::val(1)),
                ("b".into(), Expr::unknown("a")),
                ("c".into(), Expr::val(3))
            ]))
        );

        let e = Expr::record([
            ("a".into(), Expr::val(1)),
            ("b".into(), Expr::unknown("a")),
            (
                "c".into(),
                Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val("hello")),
            ),
        ]);
        assert!(eval.partial_interpret(&e, &HashMap::new()).is_err());
    }

    #[test]
    fn small() {
        let e = parser::parse_expr("[[1]]").unwrap();
        let re = RestrictedExpr::new(e).unwrap();
        let exts = Extensions::none();
        let eval = RestrictedEvaluator::new(&exts);
        let r = eval.partial_interpret(re.as_borrowed()).unwrap();
        match r {
            PartialValue::Value(Value::Set(s)) => assert_eq!(s.len(), 1),
            PartialValue::Value(_) => panic!("wrong value"),
            PartialValue::Residual(_) => panic!("Wrong residual"),
        }
    }

    #[test]
    fn unprojectable_residual() {
        let q = basic_request();
        let entities = basic_entities();
        let exts = Extensions::none();
        let eval = Evaluator::new(&q, &entities, &exts).unwrap();

        let e = Expr::get_attr(
            Expr::record([
                (
                    "a".into(),
                    Expr::binary_app(BinaryOp::Add, Expr::unknown("a"), Expr::val(3)),
                ),
                ("b".into(), Expr::val(83)),
            ]),
            "b".into(),
        );
        let r = eval.partial_eval_expr(&e).unwrap();
        assert_eq!(r, Either::Right(e));

        let e = Expr::get_attr(
            Expr::record([(
                "a".into(),
                Expr::binary_app(BinaryOp::Add, Expr::unknown("a"), Expr::val(3)),
            )]),
            "b".into(),
        );
        assert!(eval.partial_eval_expr(&e).is_err());
    }
}
