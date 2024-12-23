use crate::{entities::Dereference, parser::Loc};
use nonempty::nonempty;
use smol_str::SmolStr;
use std::sync::Arc;

use super::concrete::{BinaryArithmetic, Relation, SetOp};
use super::{
    err, names, split, stack_size_check, BinaryOp, BorrowedRestrictedExpr, EvaluationError,
    Evaluator, Expr, ExprKind, Literal, PartialValue, RestrictedEvaluator, Result, SlotEnv,
    StaticallyTyped, Type, TypeError, Value, ValueKind, Var,
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

impl Evaluator<'_> {
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
                PartialValue::Value(arg) => Self::eval_unary(op, arg, loc).map(Into::into),
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
                    BinaryOp::Eq => Self::eval_relation(Relation::Eq, arg1, arg2).map(Into::into),
                    BinaryOp::Less => {
                        Self::eval_relation(Relation::Less, arg1, arg2).map(Into::into)
                    }
                    BinaryOp::LessEq => {
                        Self::eval_relation(Relation::LessEq, arg1, arg2).map(Into::into)
                    }
                    BinaryOp::Add => {
                        Self::eval_binary_arithmetic(BinaryArithmetic::Add, arg1, arg2, loc)
                            .map(Into::into)
                    }
                    BinaryOp::Sub => {
                        Self::eval_binary_arithmetic(BinaryArithmetic::Sub, arg1, arg2, loc)
                            .map(Into::into)
                    }
                    BinaryOp::Mul => {
                        Self::eval_binary_arithmetic(BinaryArithmetic::Mul, arg1, arg2, loc)
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
                                Self::eval_in(uid1, None, arg2).map(Into::into)
                            }
                            Dereference::Data(entity1) => {
                                Self::eval_in(uid1, Some(entity1), arg2).map(Into::into)
                            }
                        }
                    }
                    // contains, which works on Sets
                    BinaryOp::Contains => Self::eval_contains(arg1, arg2).map(Into::into),
                    // ContainsAll and ContainsAny, which work on Sets
                    BinaryOp::ContainsAll => {
                        Self::eval_set_op(SetOp::All, arg1, arg2).map(Into::into)
                    }
                    BinaryOp::ContainsAny => {
                        Self::eval_set_op(SetOp::Any, arg1, arg2).map(Into::into)
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
