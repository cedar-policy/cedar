use crate::entities::Entities;
use crate::extensions::Extensions;
use crate::{entities::Dereference, parser::Loc};
use nonempty::nonempty;
use smol_str::SmolStr;
use std::sync::Arc;

use super::concrete::{BinaryArithmetic, Evaluator, Relation, SetOp};
use super::{
    err, names, split, stack_size_check, BinaryOp, BorrowedRestrictedExpr, EntityUIDEntry,
    EvaluationError, Expr, ExprKind, Literal, PartialValue, Policy, Request, RestrictedEvaluator,
    Result, SlotEnv, StaticallyTyped, Type, TypeError, Unknown, Value, ValueKind, Var,
};
use itertools::Either;

impl RestrictedEvaluator<'_> {
    /// Interpret a `RestrictedExpr` into a `Value` in this evaluation environment.
    ///
    /// May return an error, for instance if an extension function returns an error
    ///
    /// INVARIANT: If this returns a residual, the residual expression must be a valid restricted expression.
    pub fn partial_interpret(&self, expr: BorrowedRestrictedExpr<'_>) -> Result<PartialValue> {
        stack_size_check()?;

        let res = self.partial_interpret_internal(&expr);

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

    /// Internal function to interpret a `RestrictedExpr`. (External callers,
    /// use `interpret()` or `partial_interpret()`.)
    ///
    /// Part of the reason this exists, instead of inlining this into
    /// `partial_interpret()`, is so that we can use `?` inside this function
    /// without immediately shortcircuiting into a return from
    /// `partial_interpret()` -- ie, so we can make sure the source locations of
    /// all errors are set properly before returning them from
    /// `partial_interpret()`.
    ///
    /// INVARIANT: If this returns a residual, the residual expression must be a valid restricted expression.
    fn partial_interpret_internal(
        &self,
        expr: &BorrowedRestrictedExpr<'_>,
    ) -> Result<PartialValue> {
        match expr.as_ref().expr_kind() {
            ExprKind::Lit(lit) => Ok(lit.clone().into()),
            ExprKind::Set(items) => {
                let vals = items
                    .iter()
                    .map(|item| self.partial_interpret(BorrowedRestrictedExpr::new_unchecked(item))) // assuming the invariant holds for `e`, it will hold here
                    .collect::<Result<Vec<_>>>()?;
                match split(vals) {
                    Either::Left(values) => Ok(Value::set(values, expr.source_loc().cloned()).into()),
                    Either::Right(residuals) => Ok(Expr::set(residuals).into()),
                }
            }
            ExprKind::Unknown(u) => Ok(PartialValue::unknown(u.clone())),
            ExprKind::Record(map) => {
                let map = map
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.partial_interpret(BorrowedRestrictedExpr::new_unchecked(v))?))) // assuming the invariant holds for `e`, it will hold here
                    .collect::<Result<Vec<_>>>()?;
                let (names, attrs) : (Vec<_>, Vec<_>) = map.into_iter().unzip();
                match split(attrs) {
                    Either::Left(values) => Ok(Value::record(names.into_iter().zip(values), expr.source_loc().cloned()).into()),
                    Either::Right(residuals) => {
                        // PANIC SAFETY: can't have a duplicate key here because `names` is the set of keys of the input `BTreeMap`
                        #[allow(clippy::expect_used)]
                        Ok(
                            Expr::record(names.into_iter().zip(residuals))
                                .expect("can't have a duplicate key here because `names` is the set of keys of the input `BTreeMap`")
                                .into()
                        )
                    }
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

/// Evaluator object.
///
/// Conceptually keeps the evaluation environment as part of its internal state,
/// because we will be repeatedly invoking the evaluator on every policy in a
/// Slice.
pub struct PartialEvaluator<'e> {
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
    entities: &'e Entities,
    /// Extensions which are active for this evaluation
    extensions: &'e Extensions<'e>,
}

impl std::fmt::Debug for PartialEvaluator<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<Evaluator with principal = {:?}, action = {:?}, resource = {:?}",
            &self.principal, &self.action, &self.resource
        )
    }
}

impl<'e> PartialEvaluator<'e> {
    /// Partially evaluate the given `Policy`, returning one of:
    /// 1) A boolean, if complete evaluation was possible
    /// 2) An error, if the policy is guaranteed to error
    /// 3) A residual, if complete evaluation was impossible
    ///    The bool indicates whether the policy applies, ie, "is satisfied" for the
    ///    current `request`.
    ///    This is _different than_ "if the current `request` should be allowed" --
    ///    it doesn't consider whether we're processing a `Permit` policy or a
    ///    `Forbid` policy.
    pub fn partial_evaluate(&self, p: &Policy) -> Result<Either<bool, Expr>> {
        match self.partial_interpret(&p.condition(), p.env())? {
            PartialValue::Value(v) => v.get_as_bool().map(Either::Left),
            PartialValue::Residual(e) => Ok(Either::Right(e)),
        }
    }

    /// Interpret an `Expr` in an empty `SlotEnv`. Also checks that the source
    /// location is propagated to the result.
    #[cfg(test)]
    pub fn interpret_inline_policy(&self, e: &Expr) -> Result<Value> {
        use std::collections::HashMap;

        match self.partial_interpret(e, &HashMap::new())? {
            PartialValue::Value(v) => {
                debug_assert!(e.source_loc().is_some() == v.source_loc().is_some());
                Ok(v)
            }
            PartialValue::Residual(r) => {
                debug_assert!(e.source_loc().is_some() == r.source_loc().is_some());
                Err(err::EvaluationError::non_value(r))
            }
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
                    None => PartialValue::unknown(Unknown::new_untyped("context")),
                    Some(ctx) => ctx.into(),
                }
            },
            entities,
            extensions,
        }
    }

    /// Evaluation of conditionals
    /// Must be sure to respect short-circuiting semantics
    fn eval_if(
        &self,
        guard: &Expr,
        consequent: &Arc<Expr>,
        alternative: &Arc<Expr>,
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
                Ok(Expr::ite_arc(Arc::new(guard), consequent.clone(), alternative.clone()).into())
            }
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
    ) -> Result<PartialValue> {
        match self.partial_interpret(expr, slots)? {
            // PE Cases
            PartialValue::Residual(res) => {
                match res.expr_kind() {
                    ExprKind::Record(map) => {
                        // If we have a residual record, we evaluate as follows:
                        // 1) If it's safe to project, we can project. We can evaluate to see if this attribute can become a value
                        // 2) If it's not safe to project, we can check to see if the requested key exists in the record
                        //    if it doesn't, we can fail early
                        if res.is_projectable() {
                            map.as_ref()
                                .iter()
                                .filter_map(|(k, v)| if k == attr { Some(v) } else { None })
                                .next()
                                .ok_or_else(|| {
                                    EvaluationError::record_attr_does_not_exist(
                                        attr.clone(),
                                        map.keys(),
                                        map.len(),
                                        source_loc.cloned(),
                                    )
                                })
                                .and_then(|e| self.partial_interpret(e, slots))
                        } else if map.keys().any(|k| k == attr) {
                            Ok(PartialValue::Residual(Expr::get_attr(
                                Expr::record_arc(Arc::clone(map)),
                                attr.clone(),
                            )))
                        } else {
                            Err(EvaluationError::record_attr_does_not_exist(
                                attr.clone(),
                                map.keys(),
                                map.len(),
                                source_loc.cloned(),
                            ))
                        }
                    }
                    // We got a residual, that is not a record at the top level
                    _ => Ok(PartialValue::Residual(Expr::get_attr(res, attr.clone()))),
                }
            }
            PartialValue::Value(Value {
                value: ValueKind::Record(record),
                ..
            }) => record
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
                .map(|v| PartialValue::Value(v.clone())),
            PartialValue::Value(Value {
                value: ValueKind::Lit(Literal::EntityUID(uid)),
                loc,
            }) => match self.entities.entity(uid.as_ref()) {
                Dereference::NoSuchEntity => {
                    // intentionally using the location of the euid (the LHS) and not the entire GetAttr expression
                    Err(EvaluationError::entity_does_not_exist(uid.clone(), loc))
                }
                Dereference::Residual(r) => {
                    Ok(PartialValue::Residual(Expr::get_attr(r, attr.clone())))
                }
                Dereference::Data(entity) => entity
                    .get(attr)
                    .ok_or_else(|| {
                        EvaluationError::entity_attr_does_not_exist(
                            uid,
                            attr.clone(),
                            entity.keys(),
                            entity.get_tag(attr).is_some(),
                            entity.attrs_len(),
                            source_loc.cloned(),
                        )
                    })
                    .cloned(),
            },
            PartialValue::Value(v) => {
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

    /// Interpret an `Expr` into a `Value` in this evaluation environment.
    ///
    /// May return a residual expression, if the input expression is symbolic.
    /// May return an error, for instance if the `Expr` tries to access an
    /// attribute that doesn't exist.
    pub fn partial_interpret(&self, expr: &Expr, slots: &SlotEnv) -> Result<PartialValue> {
        stack_size_check()?;

        let res = self.partial_interpret_internal(expr, slots);

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
    fn partial_interpret_internal(&self, expr: &Expr, slots: &SlotEnv) -> Result<PartialValue> {
        let loc = expr.source_loc(); // the `loc` describing the location of the entire expression
        match expr.expr_kind() {
            ExprKind::Lit(lit) => Ok(lit.clone().into()),
            ExprKind::Slot(id) => slots
                .get(id)
                .ok_or_else(|| err::EvaluationError::unlinked_slot(*id, loc.cloned()))
                .map(|euid| PartialValue::from(euid.clone())),
            ExprKind::Var(v) => match v {
                Var::Principal => Ok(self.principal.evaluate(*v)),
                Var::Action => Ok(self.action.evaluate(*v)),
                Var::Resource => Ok(self.resource.evaluate(*v)),
                Var::Context => Ok(self.context.clone()),
            },
            ExprKind::Unknown(_) => Ok(PartialValue::Residual(expr.clone())),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => self.eval_if(test_expr, then_expr, else_expr, slots),
            ExprKind::And { left, right } => {
                match self.partial_interpret(left, slots)? {
                    // PE Case
                    PartialValue::Residual(e) => {
                        Ok(PartialValue::Residual(Expr::and(e, right.as_ref().clone())))
                    }
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
                    PartialValue::Residual(r) => {
                        Ok(PartialValue::Residual(Expr::or(r, right.as_ref().clone())))
                    }
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
                PartialValue::Value(arg) => Evaluator::eval_unary(op, arg, loc).map(Into::into),
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
                    BinaryOp::Eq => {
                        Evaluator::eval_relation(Relation::Eq, arg1, arg2).map(Into::into)
                    }
                    BinaryOp::Less => {
                        Evaluator::eval_relation(Relation::Less, arg1, arg2).map(Into::into)
                    }
                    BinaryOp::LessEq => {
                        Evaluator::eval_relation(Relation::LessEq, arg1, arg2).map(Into::into)
                    }
                    BinaryOp::Add => {
                        Evaluator::eval_binary_arithmetic(BinaryArithmetic::Add, arg1, arg2, loc)
                            .map(Into::into)
                    }
                    BinaryOp::Sub => {
                        Evaluator::eval_binary_arithmetic(BinaryArithmetic::Sub, arg1, arg2, loc)
                            .map(Into::into)
                    }
                    BinaryOp::Mul => {
                        Evaluator::eval_binary_arithmetic(BinaryArithmetic::Mul, arg1, arg2, loc)
                            .map(Into::into)
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
                            Dereference::Residual(r) => Ok(PartialValue::Residual(
                                Expr::binary_app(BinaryOp::In, r, arg2.into()),
                            )),
                            Dereference::NoSuchEntity => {
                                Evaluator::eval_in(uid1, None, arg2).map(Into::into)
                            }
                            Dereference::Data(entity1) => {
                                Evaluator::eval_in(uid1, Some(entity1), arg2).map(Into::into)
                            }
                        }
                    }
                    // contains, which works on Sets
                    BinaryOp::Contains => Evaluator::eval_contains(arg1, arg2).map(Into::into),
                    // ContainsAll and ContainsAny, which work on Sets
                    BinaryOp::ContainsAll => {
                        Evaluator::eval_set_op(SetOp::All, arg1, arg2).map(Into::into)
                    }
                    BinaryOp::ContainsAny => {
                        Evaluator::eval_set_op(SetOp::Any, arg1, arg2).map(Into::into)
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
                                    Dereference::Residual(r) => Ok(PartialValue::Residual(
                                        Expr::get_tag(r, Expr::val(tag.clone())),
                                    )),
                                    Dereference::Data(entity) => entity
                                        .get_tag(tag)
                                        .ok_or_else(|| {
                                            EvaluationError::entity_tag_does_not_exist(
                                                Arc::new(uid.clone()),
                                                tag.clone(),
                                                entity.tag_keys(),
                                                entity.get(tag).is_some(),
                                                entity.tags_len(),
                                                loc.cloned(), // intentionally using the location of the entire `GetTag` expression
                                            )
                                        })
                                        .cloned(),
                                }
                            }
                            BinaryOp::HasTag => match self.entities.entity(uid) {
                                Dereference::NoSuchEntity => Ok(false.into()),
                                Dereference::Residual(r) => Ok(PartialValue::Residual(
                                    Expr::has_tag(r, Expr::val(tag.clone())),
                                )),
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
            ExprKind::GetAttr { expr, attr } => self.get_attr(expr.as_ref(), attr, slots, loc),
            ExprKind::HasAttr { expr, attr } => match self.partial_interpret(expr, slots)? {
                PartialValue::Value(Value {
                    value: ValueKind::Record(record),
                    ..
                }) => Ok(record.get(attr).is_some().into()),
                PartialValue::Value(Value {
                    value: ValueKind::Lit(Literal::EntityUID(uid)),
                    ..
                }) => match self.entities.entity(&uid) {
                    Dereference::NoSuchEntity => Ok(false.into()),
                    Dereference::Residual(r) => {
                        Ok(PartialValue::Residual(Expr::has_attr(r, attr.clone())))
                    }
                    Dereference::Data(e) => Ok(e.get(attr).is_some().into()),
                },
                PartialValue::Value(val) => Err(err::EvaluationError::type_error(
                    nonempty![
                        Type::Record,
                        Type::entity_type(names::ANY_ENTITY_TYPE.clone())
                    ],
                    &val,
                )),
                PartialValue::Residual(r) => Ok(Expr::has_attr(r, attr.clone()).into()),
            },
            ExprKind::Like { expr, pattern } => {
                let v = self.partial_interpret(expr, slots)?;
                match v {
                    PartialValue::Value(v) => {
                        Ok((pattern.wildcard_match(v.get_as_string()?)).into())
                    }
                    PartialValue::Residual(r) => Ok(Expr::like(r, pattern.clone()).into()),
                }
            }
            ExprKind::Is { expr, entity_type } => {
                let v = self.partial_interpret(expr, slots)?;
                match v {
                    PartialValue::Value(v) => {
                        Ok((v.get_as_entity()?.entity_type() == entity_type).into())
                    }
                    PartialValue::Residual(r) => {
                        Ok(Expr::is_entity_type(r, entity_type.clone()).into())
                    }
                }
            }
            ExprKind::Set(items) => {
                let vals = items
                    .iter()
                    .map(|item| self.partial_interpret(item, slots))
                    .collect::<Result<Vec<_>>>()?;
                match split(vals) {
                    Either::Left(vals) => Ok(Value::set(vals, loc.cloned()).into()),
                    Either::Right(r) => Ok(Expr::set(r).into()),
                }
            }
            ExprKind::Record(map) => {
                let map = map
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.partial_interpret(v, slots)?)))
                    .collect::<Result<Vec<_>>>()?;
                let (names, evalled): (Vec<SmolStr>, Vec<PartialValue>) = map.into_iter().unzip();
                match split(evalled) {
                    Either::Left(vals) => {
                        Ok(Value::record(names.into_iter().zip(vals), loc.cloned()).into())
                    }
                    Either::Right(rs) => {
                        // PANIC SAFETY: can't have a duplicate key here because `names` is the set of keys of the input `BTreeMap`
                        #[allow(clippy::expect_used)]
                        Ok(
                            Expr::record(names.into_iter().zip(rs))
                                .expect("can't have a duplicate key here because `names` is the set of keys of the input `BTreeMap`")
                                .into()
                        )
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use cool_asserts::assert_matches;
    use itertools::Either;

    use crate::{
        ast::{
            expression_construction_errors, BinaryOp, Context, EntityUID, EntityUIDEntry, Expr,
            PartialValue, Pattern, PolicyID, Request, RequestSchemaAllPass, RestrictedExpr,
            UnaryOp, Unknown, Value, ValueKind, Var,
        },
        entities::Entities,
        evaluator::{
            test::{basic_entities, basic_request, empty_request},
            RestrictedEvaluator,
        },
        extensions::Extensions,
        parser::{self, parse_policyset},
    };

    use super::PartialEvaluator;
    use std::str::FromStr;

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
            EntityUIDEntry::Unknown { loc: None },
            EntityUIDEntry::Unknown { loc: None },
            EntityUIDEntry::Unknown { loc: None },
            Some(Context::empty()),
            Some(&RequestSchemaAllPass),
            Extensions::none(),
        )
        .unwrap();
        let es = Entities::new();
        let e = PartialEvaluator::new(q, &es, Extensions::none());
        match e.partial_evaluate(p).expect("eval error") {
            Either::Left(_) => panic!("Evalled to a value"),
            Either::Right(expr) => {
                println!("{expr}");
                assert!(expr.contains_unknown());
                let m: HashMap<_, _> = [("principal".into(), Value::from(euid))]
                    .into_iter()
                    .collect();
                let new_expr = expr.substitute_typed(&m).unwrap();
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
        let context = Context::from_expr(rexpr.as_borrowed(), Extensions::none()).unwrap();
        let q = Request::new(
            (euid.clone(), None),
            (euid.clone(), None),
            (euid, None),
            context,
            Some(&RequestSchemaAllPass),
            Extensions::none(),
        )
        .unwrap();
        let es = Entities::new();
        let eval = PartialEvaluator::new(q, &es, Extensions::none());
        eval.partial_eval_expr(&e).unwrap()
    }

    #[test]
    fn partial_contexts1() {
        // { "cell" : <unknown> }
        let c_expr =
            Expr::record([("cell".into(), Expr::unknown(Unknown::new_untyped("cell")))]).unwrap();
        let expr = Expr::binary_app(
            BinaryOp::Eq,
            Expr::get_attr(Expr::var(Var::Context), "cell".into()),
            Expr::val(2),
        );
        let expected = Expr::binary_app(
            BinaryOp::Eq,
            Expr::unknown(Unknown::new_untyped("cell")),
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
            ("cell".into(), Expr::unknown(Unknown::new_untyped("cell"))),
        ])
        .unwrap();
        // context["cell"] == 2
        let expr = Expr::binary_app(
            BinaryOp::Eq,
            Expr::get_attr(Expr::var(Var::Context), "cell".into()),
            Expr::val(2),
        );
        let r = partial_context_test(c_expr.clone(), expr);
        let expected = Expr::binary_app(
            BinaryOp::Eq,
            Expr::unknown(Unknown::new_untyped("cell")),
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
        let row =
            Expr::record([("row".into(), Expr::unknown(Unknown::new_untyped("row")))]).unwrap();
        //assert!(row.is_partially_projectable());
        let c_expr =
            Expr::record([("loc".into(), Expr::val("test")), ("cell".into(), row)]).unwrap();
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
        let expected = Expr::binary_app(
            BinaryOp::Eq,
            Expr::unknown(Unknown::new_untyped("row")),
            Expr::val(2),
        );
        assert_eq!(r, Either::Right(expected));
    }

    #[test]
    fn partial_contexts4() {
        // { "loc" : "test", "cell" : { "row" : <unknown>, "col" : <unknown> } }
        let row = Expr::record([
            ("row".into(), Expr::unknown(Unknown::new_untyped("row"))),
            ("col".into(), Expr::unknown(Unknown::new_untyped("col"))),
        ])
        .unwrap();
        //assert!(row.is_partially_projectable());
        let c_expr =
            Expr::record([("loc".into(), Expr::val("test")), ("cell".into(), row)]).unwrap();
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
        let expected = Expr::binary_app(
            BinaryOp::Eq,
            Expr::unknown(Unknown::new_untyped("row")),
            Expr::val(2),
        );
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
        let expected = Expr::binary_app(
            BinaryOp::Eq,
            Expr::unknown(Unknown::new_untyped("col")),
            Expr::val(2),
        );
        assert_eq!(r, Either::Right(expected));
    }

    #[test]
    fn partial_context_fail() {
        let context = Context::from_expr(
            RestrictedExpr::new_unchecked(
                Expr::record([
                    ("a".into(), Expr::val(3)),
                    ("b".into(), Expr::unknown(Unknown::new_untyped("b"))),
                ])
                .unwrap(),
            )
            .as_borrowed(),
            Extensions::none(),
        )
        .unwrap();
        let euid: EntityUID = r#"Test::"test""#.parse().unwrap();
        let q = Request::new(
            (euid.clone(), None),
            (euid.clone(), None),
            (euid, None),
            context,
            Some(&RequestSchemaAllPass),
            Extensions::none(),
        )
        .unwrap();
        let es = Entities::new();
        let eval = PartialEvaluator::new(q, &es, Extensions::none());
        let e = Expr::get_attr(Expr::var(Var::Context), "foo".into());
        assert_matches!(eval.partial_eval_expr(&e), Err(_))
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

        let c_expr = RestrictedExpr::new(
            Expr::record([("cell".into(), Expr::unknown(Unknown::new_untyped("cell")))]).unwrap(),
        )
        .expect("should qualify as restricted");
        let context = Context::from_expr(c_expr.as_borrowed(), Extensions::none()).unwrap();

        let q = Request::new(
            (p, None),
            (a, None),
            (r, None),
            context,
            Some(&RequestSchemaAllPass),
            Extensions::none(),
        )
        .unwrap();
        let eval = PartialEvaluator::new(q, &es, Extensions::none());

        let result = eval.partial_evaluate(policy).expect("Eval error");
        match result {
            Either::Left(_) => panic!("Got a value"),
            Either::Right(r) => {
                println!("{r}");
            }
        }
    }

    #[test]
    fn if_semantics_residual_guard() {
        let a = Expr::unknown(Unknown::new_untyped("guard"));
        let b = Expr::and(Expr::val(1), Expr::val(2));
        let c = Expr::val(true);

        let e = Expr::ite(a, b.clone(), c);

        let es = Entities::new();

        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(
            r,
            PartialValue::Residual(Expr::ite(
                Expr::unknown(Unknown::new_untyped("guard")),
                b,
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

        let q = Request::new(
            (EntityUID::with_eid("p"), None),
            (EntityUID::with_eid("a"), None),
            (EntityUID::with_eid("r"), None),
            Context::from_expr(
                RestrictedExpr::new_unchecked(
                    Expr::record([(
                        "condition".into(),
                        Expr::unknown(Unknown::new_untyped("unknown_condition")),
                    )])
                    .unwrap(),
                )
                .as_borrowed(),
                Extensions::none(),
            )
            .unwrap(),
            Some(&RequestSchemaAllPass),
            Extensions::none(),
        )
        .unwrap();
        let eval = PartialEvaluator::new(q, &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(
            r,
            PartialValue::Residual(Expr::ite(
                Expr::binary_app(
                    BinaryOp::Eq,
                    Expr::unknown(Unknown::new_untyped("unknown_condition")),
                    Expr::val("value"),
                ),
                b,
                c
            ))
        );
    }

    #[test]
    fn if_semantics_both_err() {
        let a = Expr::unknown(Unknown::new_untyped("guard"));
        let b = Expr::and(Expr::val(1), Expr::val(2));
        let c = Expr::or(Expr::val(1), Expr::val(3));

        let e = Expr::ite(a, b.clone(), c.clone());

        let es = Entities::new();

        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        assert_eq!(
            eval.partial_interpret(&e, &HashMap::new()).unwrap(),
            PartialValue::Residual(Expr::ite(
                Expr::unknown(Unknown::new_untyped("guard")),
                b,
                c
            ))
        );
    }

    #[test]
    fn and_semantics1() {
        // Left-hand-side evaluates to `false`, should short-circuit to value
        let e = Expr::and(
            Expr::binary_app(BinaryOp::Eq, Expr::val(1), Expr::val(2)),
            Expr::and(Expr::unknown(Unknown::new_untyped("a")), Expr::val(false)),
        );

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Value(Value::from(false)));
    }

    #[test]
    fn and_semantics2() {
        // Left hand sides evaluates to `true`, can't drop it due to dynamic types
        let e = Expr::and(
            Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(2)),
            Expr::and(Expr::unknown(Unknown::new_untyped("a")), Expr::val(false)),
        );

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(
            r,
            PartialValue::Residual(Expr::and(
                Expr::val(true),
                Expr::and(Expr::unknown(Unknown::new_untyped("a")), Expr::val(false))
            ))
        );
    }

    #[test]
    fn and_semantics3() {
        // Errors on left hand side should propagate
        let e = Expr::and(
            Expr::binary_app(BinaryOp::Add, Expr::val("hello"), Expr::val(2)),
            Expr::and(Expr::unknown(Unknown::new_untyped("a")), Expr::val(false)),
        );

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        assert_matches!(eval.partial_interpret(&e, &HashMap::new()), Err(_));
    }

    #[test]
    fn and_semantics4() {
        // Left hand is residual, errors on right hand side should _not_ propagate
        let e = Expr::and(
            Expr::binary_app(
                BinaryOp::Eq,
                Expr::unknown(Unknown::new_untyped("a")),
                Expr::val(2),
            ),
            Expr::and(Expr::val("hello"), Expr::val("bye")),
        );

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        assert_matches!(eval.partial_interpret(&e, &HashMap::new()), Ok(_));
    }

    #[test]
    fn or_semantics1() {
        // Left-hand-side evaluates to `true`, should short-circuit to value

        let e = Expr::or(
            Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(2)),
            Expr::and(Expr::unknown(Unknown::new_untyped("a")), Expr::val(false)),
        );

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Value(Value::from(true)));
    }

    #[test]
    fn or_semantics2() {
        // Left hand sides evaluates to `false`, can't drop it due to dynamic types
        let e = Expr::or(
            Expr::binary_app(BinaryOp::Eq, Expr::val(1), Expr::val(2)),
            Expr::and(Expr::unknown(Unknown::new_untyped("a")), Expr::val(false)),
        );

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(
            r,
            PartialValue::Residual(Expr::or(
                Expr::val(false),
                Expr::and(Expr::unknown(Unknown::new_untyped("a")), Expr::val(false))
            ))
        );
    }

    #[test]
    fn or_semantics3() {
        // Errors on left hand side should propagate
        let e = Expr::or(
            Expr::binary_app(BinaryOp::Add, Expr::val("hello"), Expr::val(2)),
            Expr::and(Expr::unknown(Unknown::new_untyped("a")), Expr::val(false)),
        );

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        assert_matches!(eval.partial_interpret(&e, &HashMap::new()), Err(_));
    }

    #[test]
    fn or_semantics4() {
        // Left hand is residual, errors on right hand side should _not_ propagate
        let e = Expr::or(
            Expr::binary_app(
                BinaryOp::Eq,
                Expr::unknown(Unknown::new_untyped("a")),
                Expr::val(2),
            ),
            Expr::and(Expr::val("hello"), Expr::val("bye")),
        );

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        assert_matches!(eval.partial_interpret(&e, &HashMap::new()), Ok(_));
    }

    #[test]
    fn record_semantics_err() {
        let a = Expr::get_attr(
            Expr::record([("value".into(), Expr::unknown(Unknown::new_untyped("test")))]).unwrap(),
            "notpresent".into(),
        );

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        assert_matches!(eval.partial_interpret(&a, &HashMap::new()), Err(_));
    }

    #[test]
    fn record_semantics_key_present() {
        let a = Expr::get_attr(
            Expr::record([("value".into(), Expr::unknown(Unknown::new_untyped("test")))]).unwrap(),
            "value".into(),
        );

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&a, &HashMap::new()).unwrap();

        let expected = PartialValue::unknown(Unknown::new_untyped("test"));

        assert_eq!(r, expected);
    }

    #[test]
    fn record_semantics_missing_attr() {
        let a = Expr::get_attr(
            Expr::record([
                ("a".into(), Expr::unknown(Unknown::new_untyped("a"))),
                ("b".into(), Expr::unknown(Unknown::new_untyped("c"))),
            ])
            .unwrap(),
            "c".into(),
        );

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        assert_matches!(eval.partial_interpret(&a, &HashMap::new()), Err(_));
    }

    #[test]
    fn record_semantics_mult_unknowns() {
        let a = Expr::get_attr(
            Expr::record([
                ("a".into(), Expr::unknown(Unknown::new_untyped("a"))),
                ("b".into(), Expr::unknown(Unknown::new_untyped("b"))),
            ])
            .unwrap(),
            "b".into(),
        );

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&a, &HashMap::new()).unwrap();

        let expected = PartialValue::unknown(Unknown::new_untyped("b"));

        assert_eq!(r, expected);
    }

    #[test]
    fn partial_if_noerrors() {
        let guard = Expr::get_attr(Expr::unknown(Unknown::new_untyped("a")), "field".into());
        let cons = Expr::val(1);
        let alt = Expr::val(2);
        let e = Expr::ite(guard.clone(), cons, alt);

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::ite(guard, Expr::val(1), Expr::val(2));

        assert_eq!(r, PartialValue::Residual(expected));
    }

    #[test]
    fn parital_if_cons_error() {
        let guard = Expr::get_attr(Expr::unknown(Unknown::new_untyped("a")), "field".into());
        let cons = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val(true));
        let alt = Expr::val(2);
        let e = Expr::ite(guard.clone(), cons.clone(), alt);

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::ite(guard, cons, Expr::val(2));

        assert_eq!(r, PartialValue::Residual(expected));
    }

    #[test]
    fn parital_if_alt_error() {
        let guard = Expr::get_attr(Expr::unknown(Unknown::new_untyped("a")), "field".into());
        let cons = Expr::val(2);
        let alt = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val(true));
        let e = Expr::ite(guard.clone(), cons, alt.clone());

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::ite(guard, Expr::val(2), alt);
        assert_eq!(r, PartialValue::Residual(expected));
    }

    #[test]
    fn parital_if_both_error() {
        let guard = Expr::get_attr(Expr::unknown(Unknown::new_untyped("a")), "field".into());
        let cons = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val(true));
        let alt = Expr::less(Expr::val("hello"), Expr::val("bye"));
        let e = Expr::ite(guard.clone(), cons.clone(), alt.clone());

        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        assert_eq!(
            eval.partial_interpret(&e, &HashMap::new()).unwrap(),
            PartialValue::Residual(Expr::ite(guard, cons, alt))
        );
    }

    // err && res -> err
    #[test]
    fn partial_and_err_res() {
        let lhs = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val("test"));
        let rhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let e = Expr::and(lhs, rhs);
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        assert_matches!(eval.partial_interpret(&e, &HashMap::new()), Err(_));
    }

    // err || res -> err
    #[test]
    fn partial_or_err_res() {
        let lhs = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val("test"));
        let rhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let e = Expr::or(lhs, rhs);
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        assert_matches!(eval.partial_interpret(&e, &HashMap::new()), Err(_));
    }

    // true && res -> true && res
    #[test]
    fn partial_and_true_res() {
        let lhs = Expr::binary_app(BinaryOp::Eq, Expr::val(1), Expr::val(1));
        let rhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let e = Expr::and(lhs, rhs);
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::and(
            Expr::val(true),
            Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into()),
        );
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // false && res -> false
    #[test]
    fn partial_and_false_res() {
        let lhs = Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(1));
        let rhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let e = Expr::and(lhs, rhs);
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Value(Value::from(false)));
    }

    // res && true -> res && true
    #[test]
    fn partial_and_res_true() {
        let lhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let rhs = Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(2));
        let e = Expr::and(lhs.clone(), rhs.clone());
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        let expected = Expr::and(lhs, rhs);
        assert_eq!(r, PartialValue::Residual(expected));
    }

    #[test]
    fn partial_and_res_false() {
        let lhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let rhs = Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(1));
        let e = Expr::and(lhs.clone(), rhs.clone());
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        let expected = Expr::and(lhs, rhs);
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // res && res -> res && res
    #[test]
    fn partial_and_res_res() {
        let lhs = Expr::unknown(Unknown::new_untyped("b"));
        let rhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let e = Expr::and(lhs, rhs);
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::and(
            Expr::unknown(Unknown::new_untyped("b")),
            Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into()),
        );
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // res && err -> res && err
    #[test]
    fn partial_and_res_err() {
        let lhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let rhs = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val("oops"));
        let e = Expr::and(lhs, rhs.clone());
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::and(
            Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into()),
            rhs,
        );
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // true || res -> true
    #[test]
    fn partial_or_true_res() {
        let lhs = Expr::binary_app(BinaryOp::Eq, Expr::val(1), Expr::val(1));
        let rhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let e = Expr::or(lhs, rhs);
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Value(Value::from(true)));
    }

    // false || res -> false || res
    #[test]
    fn partial_or_false_res() {
        let lhs = Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(1));
        let rhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let e = Expr::or(lhs, rhs);
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        let expected = Expr::or(
            Expr::val(false),
            Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into()),
        );
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // res || true -> res || true
    #[test]
    fn partial_or_res_true() {
        let lhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let rhs = Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(2));
        let e = Expr::or(lhs.clone(), rhs.clone());
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        let expected = Expr::or(lhs, rhs);
        assert_eq!(r, PartialValue::Residual(expected));
    }

    #[test]
    fn partial_or_res_false() {
        let lhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let rhs = Expr::binary_app(BinaryOp::Eq, Expr::val(2), Expr::val(1));
        let e = Expr::or(lhs.clone(), rhs.clone());
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        let expected = Expr::or(lhs, rhs);
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // res || res -> res || res
    #[test]
    fn partial_or_res_res() {
        let lhs = Expr::unknown(Unknown::new_untyped("b"));
        let rhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let e = Expr::or(lhs, rhs);
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::or(
            Expr::unknown(Unknown::new_untyped("b")),
            Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into()),
        );
        assert_eq!(r, PartialValue::Residual(expected));
    }

    // res || err -> res || err
    #[test]
    fn partial_or_res_err() {
        let lhs = Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into());
        let rhs = Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val("oops"));
        let e = Expr::or(lhs, rhs.clone());
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        let expected = Expr::or(
            Expr::get_attr(Expr::unknown(Unknown::new_untyped("test")), "field".into()),
            rhs,
        );
        assert_eq!(r, PartialValue::Residual(expected));
    }

    #[test]
    fn partial_unop() {
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let e = Expr::unary_app(UnaryOp::Neg, Expr::unknown(Unknown::new_untyped("a")));
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Residual(e));

        let e = Expr::unary_app(UnaryOp::Not, Expr::unknown(Unknown::new_untyped("a")));
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Residual(e));

        let e = Expr::unary_app(UnaryOp::IsEmpty, Expr::unknown(Unknown::new_untyped("a")));
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Residual(e));
    }

    #[test]
    fn partial_binop() {
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

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
                Expr::unknown(Unknown::new_untyped("a")),
            );
            let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
            let expected = Expr::binary_app(
                binop,
                Expr::val(3),
                Expr::unknown(Unknown::new_untyped("a")),
            );
            assert_eq!(r, PartialValue::Residual(expected));
            // ensure PE propagates left side errors
            let e = Expr::binary_app(
                binop,
                Expr::binary_app(BinaryOp::Add, Expr::val("hello"), Expr::val(2)),
                Expr::unknown(Unknown::new_untyped("a")),
            );
            assert_matches!(eval.partial_interpret(&e, &HashMap::new()), Err(_));
            // ensure PE evaluates right side
            let e = Expr::binary_app(
                binop,
                Expr::unknown(Unknown::new_untyped("a")),
                Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val(2)),
            );
            let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
            let expected = Expr::binary_app(
                binop,
                Expr::unknown(Unknown::new_untyped("a")),
                Expr::val(3),
            );
            assert_eq!(r, PartialValue::Residual(expected));
            // ensure PE propagates right side errors
            let e = Expr::binary_app(
                binop,
                Expr::unknown(Unknown::new_untyped("a")),
                Expr::binary_app(BinaryOp::Add, Expr::val("hello"), Expr::val(2)),
            );
            assert_matches!(eval.partial_interpret(&e, &HashMap::new()), Err(_));
            // Both left and right residuals
            let e = Expr::binary_app(
                binop,
                Expr::unknown(Unknown::new_untyped("a")),
                Expr::unknown(Unknown::new_untyped("b")),
            );
            let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
            let expected = Expr::binary_app(
                binop,
                Expr::unknown(Unknown::new_untyped("a")),
                Expr::unknown(Unknown::new_untyped("b")),
            );
            assert_eq!(r, PartialValue::Residual(expected));
        }
    }

    #[test]
    fn partial_mul() {
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let e = Expr::mul(Expr::unknown(Unknown::new_untyped("a")), Expr::val(32));
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Residual(e));
    }

    #[test]
    fn partial_ext_constructors() {
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let e = Expr::call_extension_fn(
            "ip".parse().unwrap(),
            vec![Expr::unknown(Unknown::new_untyped("a"))],
        );

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Residual(e));
    }

    #[cfg(feature = "ipaddr")]
    #[test]
    fn partial_ext_unfold() {
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::all_available());

        let a = Expr::call_extension_fn("ip".parse().unwrap(), vec![Expr::val("127.0.0.1/32")]);
        let b = Expr::unknown(Unknown::new_untyped("a"));
        let e = Expr::call_extension_fn("isInRange".parse().unwrap(), vec![a, b]);

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Residual(e));

        let b = Expr::call_extension_fn("ip".parse().unwrap(), vec![Expr::val("127.0.0.1/32")]);
        let a = Expr::unknown(Unknown::new_untyped("a"));
        let e = Expr::call_extension_fn("isInRange".parse().unwrap(), vec![a, b]);

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Residual(e));

        let b = Expr::call_extension_fn("ip".parse().unwrap(), vec![Expr::val("invalid")]);
        let a = Expr::unknown(Unknown::new_untyped("a"));
        let e = Expr::call_extension_fn("isInRange".parse().unwrap(), vec![a, b]);

        assert_matches!(eval.partial_interpret(&e, &HashMap::new()), Err(_));
    }

    #[test]
    fn partial_like() {
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let e = Expr::like(
            Expr::unknown(Unknown::new_untyped("a")),
            Pattern::from(vec![]),
        );

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Residual(e));
    }

    #[test]
    fn partial_is() {
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let e = Expr::is_entity_type(
            Expr::unknown(Unknown::new_untyped("a")),
            "User".parse().unwrap(),
        );

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Residual(e));
    }

    #[test]
    fn partial_hasattr() {
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let e = Expr::has_attr(Expr::unknown(Unknown::new_untyped("a")), "test".into());

        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();

        assert_eq!(r, PartialValue::Residual(e));
    }

    #[test]
    fn partial_set() {
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let e = Expr::set([
            Expr::val(1),
            Expr::unknown(Unknown::new_untyped("a")),
            Expr::val(2),
        ]);
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Residual(e));

        let e = Expr::set([
            Expr::val(1),
            Expr::unknown(Unknown::new_untyped("a")),
            Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val(2)),
        ]);
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(
            r,
            PartialValue::Residual(Expr::set([
                Expr::val(1),
                Expr::unknown(Unknown::new_untyped("a")),
                Expr::val(3)
            ]))
        );

        let e = Expr::set([
            Expr::val(1),
            Expr::unknown(Unknown::new_untyped("a")),
            Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val("a")),
        ]);
        assert_matches!(eval.partial_interpret(&e, &HashMap::new()), Err(_));
    }

    #[test]
    fn partial_record() {
        let es = Entities::new();
        let eval = PartialEvaluator::new(empty_request(), &es, Extensions::none());

        let e = Expr::record([
            ("a".into(), Expr::val(1)),
            ("b".into(), Expr::unknown(Unknown::new_untyped("a"))),
            ("c".into(), Expr::val(2)),
        ])
        .unwrap();
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(r, PartialValue::Residual(e));

        let e = Expr::record([
            ("a".into(), Expr::val(1)),
            ("a".into(), Expr::unknown(Unknown::new_untyped("a"))),
        ]);
        assert_eq!(
            e,
            Err(expression_construction_errors::DuplicateKeyError {
                key: "a".into(),
                context: "in record literal",
            }
            .into())
        );

        let e = Expr::record([
            ("a".into(), Expr::unknown(Unknown::new_untyped("a"))),
            ("a".into(), Expr::val(1)),
        ]);
        assert_eq!(
            e,
            Err(expression_construction_errors::DuplicateKeyError {
                key: "a".into(),
                context: "in record literal",
            }
            .into())
        );

        let e = Expr::record([
            ("a".into(), Expr::val(1)),
            ("b".into(), Expr::unknown(Unknown::new_untyped("a"))),
            (
                "c".into(),
                Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val(2)),
            ),
        ])
        .unwrap();
        let r = eval.partial_interpret(&e, &HashMap::new()).unwrap();
        assert_eq!(
            r,
            PartialValue::Residual(
                Expr::record([
                    ("a".into(), Expr::val(1)),
                    ("b".into(), Expr::unknown(Unknown::new_untyped("a"))),
                    ("c".into(), Expr::val(3))
                ])
                .unwrap()
            )
        );

        let e = Expr::record([
            ("a".into(), Expr::val(1)),
            ("b".into(), Expr::unknown(Unknown::new_untyped("a"))),
            (
                "c".into(),
                Expr::binary_app(BinaryOp::Add, Expr::val(1), Expr::val("hello")),
            ),
        ])
        .unwrap();
        assert_matches!(eval.partial_interpret(&e, &HashMap::new()), Err(_));
    }

    #[test]
    fn small() {
        let e = parser::parse_expr("[[1]]").unwrap();
        let re = RestrictedExpr::new(e).unwrap();
        let eval = RestrictedEvaluator::new(Extensions::none());
        let r = eval.partial_interpret(re.as_borrowed()).unwrap();
        assert_matches!(r, PartialValue::Value(Value { value: ValueKind::Set(set), .. }) => {
            assert_eq!(set.len(), 1);
        });
    }

    #[test]
    fn unprojectable_residual() {
        let q = basic_request();
        let entities = basic_entities();
        let eval = PartialEvaluator::new(q, &entities, Extensions::none());

        let e = Expr::get_attr(
            Expr::record([
                (
                    "a".into(),
                    Expr::binary_app(
                        BinaryOp::Add,
                        Expr::unknown(Unknown::new_untyped("a")),
                        Expr::val(3),
                    ),
                ),
                ("b".into(), Expr::val(83)),
            ])
            .unwrap(),
            "b".into(),
        );
        let r = eval.partial_eval_expr(&e).unwrap();
        assert_eq!(r, Either::Right(e));

        let e = Expr::get_attr(
            Expr::record([(
                "a".into(),
                Expr::binary_app(
                    BinaryOp::Add,
                    Expr::unknown(Unknown::new_untyped("a")),
                    Expr::val(3),
                ),
            )])
            .unwrap(),
            "b".into(),
        );
        assert_matches!(eval.partial_eval_expr(&e), Err(_));
    }

    #[cfg(feature = "partial-eval")]
    #[test]
    fn partial_entity_stores_in_set() {
        use crate::{ast::Type, evaluator::test::rich_entities};

        let q = basic_request();
        let entities = rich_entities().partial();
        let child = EntityUID::with_eid("child");
        let second = EntityUID::with_eid("joseph");
        let missing = EntityUID::with_eid("non-present");
        let parent = EntityUID::with_eid("parent");
        let eval = PartialEvaluator::new(q, &entities, Extensions::none());

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
            Expr::unknown(Unknown::new_with_type(
                format!("{missing}"),
                Type::Entity {
                    ty: EntityUID::test_entity_type(),
                },
            )),
            Expr::set([Expr::val(parent.clone()), Expr::val(second.clone())]),
        );
        let expected_residual2 = Expr::binary_app(
            BinaryOp::In,
            Expr::unknown(Unknown::new_with_type(
                format!("{missing}"),
                Type::Entity {
                    ty: EntityUID::test_entity_type(),
                },
            )),
            Expr::set([Expr::val(second), Expr::val(parent)]),
        );

        // Either ordering is valid
        assert!(r == Either::Right(expected_residual) || r == Either::Right(expected_residual2));
    }

    #[cfg(feature = "partial-eval")]
    #[test]
    fn partial_entity_stores_in() {
        use crate::{ast::Type, evaluator::test::rich_entities};

        let q = basic_request();
        let entities = rich_entities().partial();
        let child = EntityUID::with_eid("child");
        let missing = EntityUID::with_eid("non-present");
        let parent = EntityUID::with_eid("parent");
        let eval = PartialEvaluator::new(q, &entities, Extensions::none());

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
            Expr::unknown(Unknown::new_with_type(
                format!("{missing}"),
                Type::Entity {
                    ty: EntityUID::test_entity_type(),
                },
            )),
            Expr::val(parent),
        );
        assert_eq!(r, Either::Right(expected_residual));
    }

    #[cfg(feature = "partial-eval")]
    #[test]
    fn partial_entity_stores_hasattr() {
        use crate::{ast::Type, evaluator::test::rich_entities};

        let q = basic_request();
        let entities = rich_entities().partial();
        let has_attr = EntityUID::with_eid("entity_with_attrs");
        let missing = EntityUID::with_eid("missing");
        let eval = PartialEvaluator::new(q, &entities, Extensions::none());

        let e = Expr::has_attr(Expr::val(has_attr), "spoon".into());
        let r = eval.partial_eval_expr(&e).unwrap();
        assert_eq!(r, Either::Left(true.into()));

        let e = Expr::has_attr(Expr::val(missing.clone()), "spoon".into());
        let r = eval.partial_eval_expr(&e).unwrap();
        let expected_residual = Expr::has_attr(
            Expr::unknown(Unknown::new_with_type(
                format!("{missing}"),
                Type::Entity {
                    ty: EntityUID::test_entity_type(),
                },
            )),
            "spoon".into(),
        );
        assert_eq!(r, Either::Right(expected_residual));
    }

    #[cfg(feature = "partial-eval")]
    #[test]
    fn partial_entity_stores_getattr() {
        use crate::{ast::Type, evaluator::test::rich_entities};

        let q = basic_request();
        let entities = rich_entities().partial();
        let has_attr = EntityUID::with_eid("entity_with_attrs");
        let missing = EntityUID::with_eid("missing");
        let eval = PartialEvaluator::new(q, &entities, Extensions::none());

        let e = Expr::get_attr(Expr::val(has_attr), "spoon".into());
        let r = eval.partial_eval_expr(&e).unwrap();
        assert_eq!(r, Either::Left(787.into()));

        let e = Expr::get_attr(Expr::val(missing.clone()), "spoon".into());
        let r = eval.partial_eval_expr(&e).unwrap();
        let expected_residual = Expr::get_attr(
            Expr::unknown(Unknown::new_with_type(
                format!("{missing}"),
                Type::Entity {
                    ty: EntityUID::test_entity_type(),
                },
            )),
            "spoon".into(),
        );
        assert_eq!(r, Either::Right(expected_residual));
    }
}
