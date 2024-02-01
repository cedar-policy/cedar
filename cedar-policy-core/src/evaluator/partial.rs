use either::Either;

use crate::entities::Dereference;

use super::{
    err, err::Result, stack_size_check, BinaryOp, BorrowedRestrictedExpr, EntityType,
    EvaluationError, EvaluationErrorKind, Evaluator, Expr, ExprKind, IntegerOverflowError,
    PartialValue, Policy, RestrictedEvaluator, Set, SlotEnv, StaticallyTyped, Type, UnaryOp, Value,
    ValueKind, Var,
};

use smol_str::SmolStr;

impl<'e> RestrictedEvaluator<'e> {
    /// Interpret a `RestrictedExpr` into a `Value` in this evaluation environment.
    ///
    /// May return an error, for instance if an extension function returns an error
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
                        let efunc = self.extensions.func(fn_name).map_err(|err| EvaluationError::extension_function_lookup(err, expr.source_loc().cloned()))?;
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

impl<'e> Evaluator<'e> {
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
            } => self.eval_if_partial(test_expr, then_expr, else_expr, slots),
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
                            None => Err(EvaluationError::integer_overflow(
                                IntegerOverflowError::UnaryOp { op: *op, arg },
                                loc.cloned(),
                            )),
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
                                None => Err(EvaluationError::integer_overflow(
                                    IntegerOverflowError::BinaryOp {
                                        op: *op,
                                        arg1,
                                        arg2,
                                    },
                                    loc.cloned(),
                                )),
                            },
                            BinaryOp::Sub => match i1.checked_sub(i2) {
                                Some(diff) => Ok(diff.into()),
                                None => Err(EvaluationError::integer_overflow(
                                    IntegerOverflowError::BinaryOp {
                                        op: *op,
                                        arg1,
                                        arg2,
                                    },
                                    loc.cloned(),
                                )),
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
                                    match arg2.type_of() {
                                        Type::Set => e.set_advice("`in` is for checking the entity hierarchy; use `.contains()` to test set membership".into()),
                                        Type::Record => e.set_advice("`in` is for checking the entity hierarchy; use `has` to test if a record has a key".into()),
                                        _ => {}
                                    }
                                };
                                e
                            })?;
                        match self.entities.entity(uid1) {
                            Dereference::Residual(r) => Ok(PartialValue::Residual(
                                Expr::binary_app(BinaryOp::In, r, arg2.into()),
                            )),
                            Dereference::NoSuchEntity => Ok(self.eval_in(uid1, None, arg2)?.into()),
                            Dereference::Data(entity1) => {
                                Ok(self.eval_in(uid1, Some(entity1), arg2)?.into())
                            }
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
                }
            }
            ExprKind::MulByConst { arg, constant } => match self.partial_interpret(arg, slots)? {
                PartialValue::Value(arg) => {
                    let i1 = arg.get_as_long()?;
                    match i1.checked_mul(*constant) {
                        Some(prod) => Ok(prod.into()),
                        None => Err(EvaluationError::integer_overflow(
                            IntegerOverflowError::Multiplication {
                                arg,
                                constant: *constant,
                            },
                            loc.cloned(),
                        )),
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
                        let efunc = self.extensions.func(fn_name).map_err(|err| {
                            EvaluationError::extension_function_lookup(err, loc.cloned())
                        })?;
                        efunc.call(&vals)
                    }
                    Either::Right(residuals) => Ok(PartialValue::Residual(
                        Expr::call_extension_fn(fn_name.clone(), residuals.collect()),
                    )),
                }
            }
            ExprKind::GetAttr { expr, attr } => {
                self.get_attr_partial(expr.as_ref(), attr, slots, loc)
            }
            ExprKind::HasAttr { expr, attr } => match self.partial_interpret(expr, slots)? {
                PartialValue::Value(val) => Ok(self.has_attr(val, attr)?.into()),
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
            ExprKind::Is { expr, entity_type } => {
                let v = self.partial_interpret(expr, slots)?;
                match v {
                    PartialValue::Value(v) => Ok(match v.get_as_entity()?.entity_type() {
                        EntityType::Specified(expr_entity_type) => entity_type == expr_entity_type,
                        EntityType::Unspecified => false,
                    }
                    .into()),
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

/// Collect an iterator of either residuals or values into one of the following
///  a) An iterator over values, if everything evaluated to values
///  b) An iterator over residuals expressions, if anything only evaluated to a residual
/// Order is preserved.
pub(crate) fn split<I>(i: I) -> Either<impl Iterator<Item = Value>, impl Iterator<Item = Expr>>
where
    I: IntoIterator<Item = PartialValue>,
{
    let mut values = vec![];
    let mut residuals = vec![];

    for item in i.into_iter() {
        match item {
            PartialValue::Value(a) => {
                if residuals.is_empty() {
                    values.push(a)
                } else {
                    residuals.push(a.into())
                }
            }
            PartialValue::Residual(r) => {
                residuals.push(r);
            }
        }
    }

    if residuals.is_empty() {
        Either::Left(values.into_iter())
    } else {
        let mut exprs: Vec<Expr> = values.into_iter().map(|x| x.into()).collect();
        exprs.append(&mut residuals);
        Either::Right(exprs.into_iter())
    }
}
