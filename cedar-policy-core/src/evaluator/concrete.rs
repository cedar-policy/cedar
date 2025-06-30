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

//! This module contains the Cedar concrete evaluator.

use crate::ast::*;
use crate::entities::{Dereference, Entities};
use crate::extensions::Extensions;
use crate::parser::Loc;
use std::sync::Arc;

use super::err::evaluation_errors;
use super::err::EvaluationError;
#[cfg(feature = "tolerant-ast")]
use super::err::EvaluationError::ASTErrorExpr;
use super::err::*;
use evaluation_errors::*;
use itertools::{Either, Itertools};
use nonempty::nonempty;
use smol_str::SmolStr;

// Temporary, until more refactoring can be done
use crate::evaluator::*;

#[derive(Debug)]
pub struct Evaluator<'e> {
    /// `Principal` for the current request
    principal: EntityUIDEntry,
    /// `Action` for the current request
    action: EntityUIDEntry,
    /// `Resource` for the current request
    resource: EntityUIDEntry,
    /// `Context` for the current request; this will be a Record type
    context: Value,
    /// Entities which we use to resolve entity references.
    ///
    /// This is a reference, because the `Evaluator` doesn't need ownership of
    /// (or need to modify) the `Entities`. One advantage of this is that you
    /// could create multiple `Evaluator`s without copying the `Entities`.
    entities: &'e Entities,
    /// Extensions which are active for this evaluation
    extensions: &'e Extensions<'e>,
}

impl<'e> Evaluator<'e> {
    /// Create a fresh `Evaluator` for the given `request`, which uses the given
    /// `Entities` to resolve entity references. Use the given `Extension`s when
    /// evaluating.
    pub fn new(q: Request, entities: &'e Entities, extensions: &'e Extensions<'e>) -> Self {
        Self {
            principal: q.principal,
            action: q.action,
            resource: q.resource,
            context: {
                match q.context {
                    None => todo!("concrete::Evaluator::new with None context"),
                    Some(ctx) => todo!("concrete::Evaluator::new with Some context"), // ctx.into(),
                }
            },
            entities,
            extensions,
        }
    }

    // verus! {

    // /// Duplicate of `evaluate()` with a Verus spec.
    // /// Evaluate the given `Policy`, returning either a bool or an error.
    // /// The bool indicates whether the policy applies, ie, "is satisfied" for the
    // /// current `request`.
    // /// This is _different than_ "if the current `request` should be allowed" --
    // /// it doesn't consider whether we're processing a `Permit` policy or a
    // /// `Forbid` policy.
    // #[verifier::external_body]
    // pub fn evaluate_verus(&self, p: &Policy) -> (res: Result<bool>)
    //     ensures ({
    //         &&& res matches Ok(res_b) ==> {
    //             &&& spec_evaluator::evaluate(p@.to_expr(), self@.request, self@.entities) matches Ok(v)
    //             &&& v is Prim &&& v->p is Bool &&& v->p->b == res_b
    //         }
    //         &&& res is Err ==> {
    //             &&& spec_evaluator::evaluate(p@.to_expr(), self@.request, self@.entities) is Err
    //         }
    //     })
    // {
    //     self.evaluate(p)
    // }

    // } // verus!

    /// Evaluate the given `Policy`, returning either a bool or an error.
    /// The bool indicates whether the policy applies, ie, "is satisfied" for the
    /// current `request`.
    /// This is _different than_ "if the current `request` should be allowed" --
    /// it doesn't consider whether we're processing a `Permit` policy or a
    /// `Forbid` policy.
    pub fn evaluate(&self, p: &Policy) -> Result<bool> {
        self.interpret(&p.condition(), p.env())?.get_as_bool()
    }

    /// Interpret an `Expr` into a `Value` in this evaluation environment.
    ///
    /// Ensures the result is not a residual.
    /// May return an error, for instance if the `Expr` tries to access an
    /// attribute that doesn't exist.
    pub fn interpret(&self, expr: &Expr, slots: &SlotEnv) -> Result<Value> {
        stack_size_check()?;

        let res = self.interpret_internal(expr, slots);

        // set the returned value's source location to the same source location
        // as the input expression had.
        // we do this here so that we don't have to set/propagate the source
        // location in every arm of the big `match` in `partial_interpret_internal()`.
        // also, if there is an error, set its source location to the source
        // location of the input expression as well, unless it already had a
        // more specific location
        res.map(|pval| pval.with_maybe_source_loc(expr.source_loc().cloned()))
            .map_err(|err| match err.source_loc() {
                None => err.with_maybe_source_loc(expr.source_loc().cloned()),
                Some(_) => err,
            })
    }

    /// Internal function to interpret an `Expr`. (External callers, use
    /// `interpret()` or `partial_interpret()`.)
    ///
    /// Part of the reason this exists, instead of inlining this into
    /// `partial_interpret()`, is so that we can use `?` inside this function
    /// without immediately shortcircuiting into a return from
    /// `partial_interpret()` -- ie, so we can make sure the source locations of
    /// all errors are set properly before returning them from
    /// `partial_interpret()`.
    #[allow(clippy::cognitive_complexity)]
    fn interpret_internal(&self, expr: &Expr, slots: &SlotEnv) -> Result<Value> {
        let loc = expr.source_loc(); // the `loc` describing the location of the entire expression
        match expr.expr_kind() {
            ExprKind::Lit(lit) => Ok(lit.clone().into()),
            ExprKind::Slot(id) => slots
                .get(id)
                .ok_or_else(|| err::EvaluationError::unlinked_slot(*id, loc.cloned()))
                .map(|euid| Value::from(euid.clone())),
            ExprKind::Var(v) => match v {
                Var::Principal => self
                    .principal
                    .evaluate_concrete(*v)
                    .ok_or(err::EvaluationError::non_value(expr.clone())),
                Var::Action => self
                    .action
                    .evaluate_concrete(*v)
                    .ok_or(err::EvaluationError::non_value(expr.clone())),
                Var::Resource => self
                    .resource
                    .evaluate_concrete(*v)
                    .ok_or(err::EvaluationError::non_value(expr.clone())),
                Var::Context => Ok(self.context.clone()),
            },
            ExprKind::Unknown(u) => Err(err::EvaluationError::non_value(expr.clone())),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => self.eval_if(test_expr, then_expr, else_expr, slots),
            ExprKind::And { left, right } => {
                let v = self.interpret(left, slots)?;
                if v.get_as_bool()? {
                    let v = self.interpret(right, slots)?;
                    Ok(v.get_as_bool()?.into())
                } else {
                    // short-circuit
                    Ok(false.into())
                }
            }
            ExprKind::Or { left, right } => {
                let lhs = self.interpret(left, slots)?;
                if lhs.get_as_bool()? {
                    // short-circuit
                    Ok(true.into())
                } else {
                    let v = self.interpret(right, slots)?;
                    Ok(v.get_as_bool()?.into())
                }
            }
            ExprKind::UnaryApp { op, arg } => {
                let arg = self.interpret(arg, slots)?;
                unary_app(*op, arg, loc)
            }
            ExprKind::BinaryApp { op, arg1, arg2 } => {
                let (arg1, arg2) = (self.interpret(arg1, slots)?, self.interpret(arg2, slots)?);
                match op {
                    BinaryOp::Eq | BinaryOp::Less | BinaryOp::LessEq => {
                        binary_relation(*op, arg1, arg2, self.extensions).map(Into::into)
                    }
                    BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => {
                        binary_arith(*op, arg1, arg2, loc).map(Into::into)
                    }
                    // hierarchy membership operator; see note on `BinaryOp::In`
                    BinaryOp::In => {
                        let uid1 = arg1.get_as_entity().map_err(|mut e|
                            {
                                // If arg1 is not an entity and arg2 is a set, then possibly
                                // the user intended `arg2.contains(arg1)` rather than `arg1 in arg2`.
                                // If arg2 is a record, then possibly they intended `arg2 has arg1`.
                                if let EvaluationError::TypeError(TypeError { advice, .. }) = &mut e {
                                    match arg2.type_of() {
                                        Type::Set => *advice = Some("`in` is for checking the entity hierarchy; use `.contains()` to test set membership".into()),
                                        Type::Record => *advice = Some("`in` is for checking the entity hierarchy; use `has` to test if a record has a key".into()),
                                        _ => {}
                                    }
                                };
                                e
                            })?;
                        match self.entities.entity(uid1) {
                            Dereference::Residual(r) => {
                                Err(err::EvaluationError::non_value(expr.clone()))
                            }
                            Dereference::NoSuchEntity => self.eval_in(uid1, None, arg2),
                            Dereference::Data(entity1) => self.eval_in(uid1, Some(entity1), arg2),
                        }
                    }
                    // contains, which works on Sets
                    BinaryOp::Contains => match arg1.value {
                        ValueKind::Set(Set { fast: Some(h), .. }) => match arg2.try_as_lit() {
                            Some(lit) => Ok((h.contains(lit)).into()),
                            None => Ok(false.into()), // we know it doesn't contain a non-literal
                        },
                        ValueKind::Set(Set {
                            fast: None,
                            authoritative,
                        }) => Ok((authoritative.contains(&arg2)).into()),
                        _ => Err(EvaluationError::type_error_single(Type::Set, &arg1)),
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
                    // GetTag and HasTag, which require an Entity on the left and a String on the right
                    BinaryOp::GetTag | BinaryOp::HasTag => {
                        let uid = arg1.get_as_entity()?;
                        let tag = arg2.get_as_string()?;
                        match op {
                            BinaryOp::GetTag => {
                                match self.entities.entity(uid) {
                                    Dereference::NoSuchEntity => {
                                        // intentionally using the location of the euid (the LHS) and not the entire GetTag expression
                                        Err(EvaluationError::entity_does_not_exist(
                                            Arc::new(uid.clone()),
                                            arg1.source_loc().cloned(),
                                        ))
                                    }
                                    Dereference::Residual(r) => {
                                        Err(err::EvaluationError::non_value(expr.clone()))
                                    }
                                    Dereference::Data(entity) => match entity.get_tag(tag) {
                                        Some(PartialValue::Value(v)) => Ok(v.clone()),
                                        Some(PartialValue::Residual(_)) => {
                                            Err(err::EvaluationError::non_value(expr.clone()))
                                        }
                                        None => {
                                            Err(EvaluationError::entity_tag_does_not_exist(
                                                Arc::new(uid.clone()),
                                                tag.clone(),
                                                entity.tag_keys(),
                                                entity.get(tag).is_some(),
                                                entity.tags_len(),
                                                loc.cloned(), // intentionally using the location of the entire `GetTag` expression
                                            ))
                                        }
                                    },
                                }
                            }
                            BinaryOp::HasTag => match self.entities.entity(uid) {
                                Dereference::NoSuchEntity => Ok(false.into()),
                                Dereference::Residual(r) => {
                                    Err(err::EvaluationError::non_value(expr.clone()))
                                }
                                Dereference::Data(entity) => {
                                    Ok(entity.get_tag(tag).is_some().into())
                                }
                            },
                            // PANIC SAFETY `op` is checked to be one of these two above
                            #[allow(clippy::unreachable)]
                            _ => {
                                unreachable!("Should have already checked that op was one of these")
                            }
                        }
                    }
                }
            }
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let args = args
                    .iter()
                    .map(|arg| self.interpret(arg, slots))
                    .collect::<Result<Vec<_>>>()?;
                let efunc = self.extensions.func(fn_name)?;
                // TODO need to change extension functions internally?
                match efunc.call(&args)? {
                    PartialValue::Value(v) => Ok(v),
                    PartialValue::Residual(_) => Err(err::EvaluationError::non_value(expr.clone())),
                }
            }
            ExprKind::GetAttr { expr, attr } => self.get_attr(expr.as_ref(), attr, slots, loc),
            ExprKind::HasAttr {
                expr: expr_inner,
                attr,
            } => match self.interpret(expr_inner, slots)? {
                Value {
                    value: ValueKind::Record(record),
                    ..
                } => Ok(record.get(attr).is_some().into()),
                Value {
                    value: ValueKind::Lit(Literal::EntityUID(uid)),
                    ..
                } => match self.entities.entity(&uid) {
                    Dereference::NoSuchEntity => Ok(false.into()),
                    Dereference::Residual(r) => Err(err::EvaluationError::non_value(expr.clone())),
                    Dereference::Data(e) => Ok(e.get(attr).is_some().into()),
                },
                val => Err(err::EvaluationError::type_error(
                    nonempty![
                        Type::Record,
                        Type::entity_type(names::ANY_ENTITY_TYPE.clone())
                    ],
                    &val,
                )),
            },
            ExprKind::Like { expr, pattern } => {
                let v = self.interpret(expr, slots)?;
                Ok((pattern.wildcard_match(v.get_as_string()?)).into())
            }
            ExprKind::Is { expr, entity_type } => {
                let v = self.interpret(expr, slots)?;
                Ok((v.get_as_entity()?.entity_type() == entity_type).into())
            }
            ExprKind::Set(items) => {
                let vals = items
                    .iter()
                    .map(|item| self.interpret(item, slots))
                    .collect::<Result<Vec<_>>>()?;
                Ok(Value::set(vals, loc.cloned()).into())
            }
            ExprKind::Record(map) => {
                let map = map
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.interpret(v, slots)?)))
                    .collect::<Result<Vec<_>>>()?;
                let (names, vals): (Vec<SmolStr>, Vec<Value>) = map.into_iter().unzip();
                Ok(Value::record(names.into_iter().zip(vals), loc.cloned()).into())
            }
            #[cfg(feature = "tolerant-ast")]
            ExprKind::Error { .. } => Err(ASTErrorExpr(ASTErrorExprError {
                source_loc: loc.cloned(),
            })),
        }
    }

    // // Never map unknowns when feature flag is not set
    // #[cfg(not(feature = "partial-eval"))]
    // #[inline(always)]
    // fn unknown_to_partialvalue(&self, u: &Unknown) -> Result<PartialValue> {
    //     Ok(PartialValue::Residual(Expr::unknown(u.clone())))
    // }

    // // Try resolving a named Unknown into a Value
    // #[cfg(feature = "partial-eval")]
    // fn unknown_to_partialvalue(&self, u: &Unknown) -> Result<PartialValue> {
    //     match (self.unknowns_mapper.as_ref()(&u.name), &u.type_annotation) {
    //         // The mapper might not recognize the unknown
    //         (None, _) => Ok(PartialValue::Residual(Expr::unknown(u.clone()))),
    //         // Replace the unknown value with the concrete one found
    //         (Some(v), None) => Ok(PartialValue::Value(v)),
    //         (Some(v), Some(t)) => {
    //             if v.type_of() == *t {
    //                 Ok(PartialValue::Value(v))
    //             } else {
    //                 Err(EvaluationError::type_error_single(t.clone(), &v))
    //             }
    //         }
    //     }
    // }

    fn eval_in(&self, uid1: &EntityUID, entity1: Option<&Entity>, arg2: Value) -> Result<Value> {
        // `rhs` is a list of all the UIDs for which we need to
        // check if `uid1` is a descendant of
        let rhs = match arg2.value {
            ValueKind::Lit(Literal::EntityUID(uid)) => vec![Arc::unwrap_or_clone(uid)],
            // we assume that iterating the `authoritative` BTreeSet is
            // approximately the same cost as iterating the `fast` HashSet
            ValueKind::Set(Set { authoritative, .. }) => authoritative
                .iter()
                .map(|val| Ok(val.get_as_entity()?.clone()))
                .collect::<Result<Vec<EntityUID>>>()?,
            _ => {
                return Err(EvaluationError::type_error(
                    nonempty![Type::Set, Type::entity_type(names::ANY_ENTITY_TYPE.clone())],
                    &arg2,
                ))
            }
        };
        for uid2 in rhs {
            if uid1 == &uid2
                || entity1
                    .map(|e1| e1.is_descendant_of(&uid2))
                    .unwrap_or(false)
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
        consequent: &Arc<Expr>,
        alternative: &Arc<Expr>,
        slots: &SlotEnv,
    ) -> Result<Value> {
        let v = self.interpret(guard, slots)?;
        if v.get_as_bool()? {
            self.interpret(consequent, slots)
        } else {
            self.interpret(alternative, slots)
        }
    }

    /// We don't use the `source_loc()` on `expr` because that's only the loc
    /// for the LHS of the GetAttr. `source_loc` argument should be the loc for
    /// the entire GetAttr expression
    fn get_attr(
        &self,
        expr: &Expr,
        attr: &SmolStr,
        slots: &SlotEnv,
        source_loc: Option<&Loc>,
    ) -> Result<Value> {
        match self.interpret(expr, slots)? {
            Value {
                value: ValueKind::Record(record),
                ..
            } => record
                .as_ref()
                .get(attr)
                .ok_or_else(|| {
                    EvaluationError::record_attr_does_not_exist(
                        attr.clone(),
                        record.keys(),
                        record.len(),
                        source_loc.cloned(),
                    )
                })
                .map(|v| v.clone()),
            Value {
                value: ValueKind::Lit(Literal::EntityUID(uid)),
                loc,
            } => match self.entities.entity(uid.as_ref()) {
                Dereference::NoSuchEntity => {
                    // intentionally using the location of the euid (the LHS) and not the entire GetAttr expression
                    Err(EvaluationError::entity_does_not_exist(uid.clone(), loc))
                }
                Dereference::Residual(r) => Err(EvaluationError::non_value(Expr::get_attr(
                    expr.clone(),
                    attr.clone(),
                ))),
                Dereference::Data(entity) => match entity.get(attr) {
                    Some(PartialValue::Value(v)) => Ok(v.clone()),
                    Some(PartialValue::Residual(e)) => Err(EvaluationError::non_value(
                        Expr::get_attr(expr.clone(), attr.clone()),
                    )),
                    None => Err(EvaluationError::entity_attr_does_not_exist(
                        uid,
                        attr.clone(),
                        entity.keys(),
                        entity.get_tag(attr).is_some(),
                        entity.attrs_len(),
                        source_loc.cloned(),
                    )),
                },
            },
            v => {
                // PANIC SAFETY Entity type name is fully static and a valid unqualified `Name`
                #[allow(clippy::unwrap_used)]
                Err(EvaluationError::type_error(
                    nonempty![
                        Type::Record,
                        Type::entity_type(names::ANY_ENTITY_TYPE.clone()),
                    ],
                    &v,
                ))
            }
        }
    }

    /// Evaluate a binary operation between a residual expression (left) and a value (right). If despite the unknown contained in the residual, concrete result
    /// can be obtained (using the type annotation on the residual), it is returned.
    fn short_circuit_residual_and_value(
        &self,
        e1: &Expr,
        v2: &Value,
        op: BinaryOp,
    ) -> Option<PartialValue> {
        match op {
            // Since these operators are commutative, we can use just one order, and have one implementation of the actual logic
            BinaryOp::Add | BinaryOp::Eq | BinaryOp::Mul | BinaryOp::ContainsAny => {
                self.short_circuit_value_and_residual(v2, e1, op)
            }
            _ => None,
        }
    }

    /// Evaluate a binary operation between a value (left) and a residual expression (right). If despite the unknown contained in the residual, concrete result
    /// can be obtained (using the type annotation on the residual), it is returned.
    fn short_circuit_value_and_residual(
        &self,
        v1: &Value,
        e2: &Expr,
        op: BinaryOp,
    ) -> Option<PartialValue> {
        match (op, v1.value_kind(), e2.expr_kind()) {
            // We detect comparing a typed unknown entity id to a literal entity id, and short-circuit to false if the literal is not the same type
            (
                BinaryOp::Eq,
                ValueKind::Lit(Literal::EntityUID(uid1)),
                ExprKind::Unknown(Unknown {
                    type_annotation:
                        Some(Type::Entity {
                            ty: type_of_unknown,
                        }),
                    ..
                }),
            ) => {
                if uid1.entity_type() != type_of_unknown {
                    Some(false.into())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn short_circuit_two_typed_residuals(
        &self,
        e1: &Expr,
        e2: &Expr,
        op: BinaryOp,
    ) -> Option<PartialValue> {
        match (op, e1.expr_kind(), e2.expr_kind()) {
            // We detect comparing two typed unknown entities, and return false if they don't have the same type.
            (
                BinaryOp::Eq,
                ExprKind::Unknown(Unknown {
                    type_annotation: Some(Type::Entity { ty: t1 }),
                    ..
                }),
                ExprKind::Unknown(Unknown {
                    type_annotation: Some(Type::Entity { ty: t2 }),
                    ..
                }),
            ) => {
                if t1 != t2 {
                    Some(false.into())
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}
