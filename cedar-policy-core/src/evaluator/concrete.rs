use std::sync::Arc;

use crate::{entities::Dereference, extensions::Extensions, parser::Loc};

use super::{
    err, names, stack_size_check, BinaryOp, BinaryOpOverflowError, Entity, EntityUID,
    EvaluationError, Evaluator, Expr, ExprKind, IntegerOverflowError, Literal, Result, Set,
    SlotEnv, StaticallyTyped, Type, TypeError, UnaryOp, UnaryOpOverflowError, Value, ValueKind,
    Var,
};

use nonempty::nonempty;
use smol_str::SmolStr;

impl Evaluator<'_> {
    /// Evaluation of conditionals
    /// Must be sure to respect short-circuiting semantics
    fn eval_if_concrete(
        &self,
        guard: &Expr,
        consequent: &Arc<Expr>,
        alternative: &Arc<Expr>,
        slots: &SlotEnv,
    ) -> Result<Value> {
        if self.interpret(guard, slots)?.get_as_bool()? {
            self.interpret(consequent, slots)
        } else {
            self.interpret(alternative, slots)
        }
    }

    pub(crate) fn eval_in_concrete(
        &self,
        uid1: &EntityUID,
        entity1: Option<&Entity>,
        arg2: Value,
    ) -> Result<Value> {
        // `rhs` is a list of all the UIDs for which we need to
        // check if `uid1` is a descendant of
        let rhs = match arg2.value {
            ValueKind::Lit(Literal::EntityUID(uid)) => vec![(*uid).clone()],
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

    /// We don't use the `source_loc()` on `expr` because that's only the loc
    /// for the LHS of the GetAttr. `source_loc` argument should be the loc for
    /// the entire GetAttr expression
    fn get_attr_concrete(
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
                .cloned(),
            Value {
                value: ValueKind::Lit(Literal::EntityUID(uid)),
                loc,
            } => match self.entities.entity(uid.as_ref()) {
                Dereference::NoSuchEntity => {
                    // intentionally using the location of the euid (the LHS) and not the entire GetAttr expression
                    Err(EvaluationError::entity_does_not_exist(uid.clone(), loc))
                }
                Dereference::Residual(_) => Err(EvaluationError::non_value(expr.clone())),
                Dereference::Data(entity) => match entity.get(attr) {
                    None => Err(EvaluationError::entity_attr_does_not_exist(
                        uid,
                        attr.clone(),
                        entity.keys(),
                        entity.get_tag(attr).is_some(),
                        entity.attrs_len(),
                        source_loc.cloned(),
                    )),
                    Some(v) => v
                        .clone()
                        .try_into()
                        .map_err(|_| EvaluationError::non_value(expr.clone())),
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

    /// Interpret an `Expr` into a `Value` in this evaluation environment.
    ///
    /// May return a residual expression, if the input expression is symbolic.
    /// May return an error, for instance if the `Expr` tries to access an
    /// attribute that doesn't exist.
    pub fn interpret(&self, expr: &Expr, slots: &SlotEnv) -> Result<Value> {
        stack_size_check()?;

        let res = self.interpret_internal(expr, slots);

        // set the returned value's source location to the same source location
        // as the input expression had.
        // we do this here so that we don't have to set/propagate the source
        // location in every arm of the big `match` in `interpret_internal()`.
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
    /// `interpret()`.)
    ///
    /// Part of the reason this exists, instead of inlining this into
    /// `interpret()`, is so that we can use `?` inside this function
    /// without immediately shortcircuiting into a return from
    /// `interpret()` -- ie, so we can make sure the source locations of
    /// all errors are set properly before returning them from
    /// `interpret()`.
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
                Var::Principal => self.principal.evaluate(*v),
                Var::Action => self.action.evaluate(*v),
                Var::Resource => self.resource.evaluate(*v),
                Var::Context => self.context.clone(),
            }
            .try_into()
            .map_err(|_| EvaluationError::non_value(expr.clone())),
            ExprKind::Unknown(_) => Err(EvaluationError::non_value(expr.clone())),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => self.eval_if_concrete(test_expr, then_expr, else_expr, slots),
            ExprKind::And { left, right } => {
                if self.interpret(&left, slots)?.get_as_bool()? {
                    self.interpret(&right, slots)
                } else {
                    // We can short circuit here
                    Ok(false.into())
                }
            }
            ExprKind::Or { left, right } => {
                if self.interpret(&left, slots)?.get_as_bool()? {
                    // We can short circuit here
                    Ok(true.into())
                } else {
                    self.interpret(&right, slots)
                }
            }
            // TODO: make it a function
            ExprKind::UnaryApp { op, arg } => {
                let arg = self.interpret(&arg, slots)?;
                match op {
                    UnaryOp::Not => match arg.get_as_bool()? {
                        true => Ok(false.into()),
                        false => Ok(true.into()),
                    },
                    UnaryOp::Neg => {
                        let i = arg.get_as_long()?;
                        match i.checked_neg() {
                            Some(v) => Ok(v.into()),
                            None => Err(IntegerOverflowError::UnaryOp(UnaryOpOverflowError {
                                op: *op,
                                arg,
                                source_loc: loc.cloned(),
                            })
                            .into()),
                        }
                    }
                    UnaryOp::IsEmpty => {
                        let s = arg.get_as_set()?;
                        Ok(s.is_empty().into())
                    }
                }
            }
            // TODO: make it a function
            ExprKind::BinaryApp { op, arg1, arg2 } => {
                let (arg1, arg2) = (self.interpret(arg1, slots)?, self.interpret(arg2, slots)?);
                match op {
                    BinaryOp::Eq => Ok((arg1 == arg2).into()),
                    // comparison and arithmetic operators, which only work on Longs
                    BinaryOp::Less | BinaryOp::LessEq => {
                        let long_op = if matches!(op, BinaryOp::Less) {
                            |x, y| x < y
                        } else {
                            |x, y| x <= y
                        };
                        let ext_op = if matches!(op, BinaryOp::Less) {
                            |x, y| x < y
                        } else {
                            |x, y| x <= y
                        };
                        match (arg1.value_kind(), arg2.value_kind()) {
                            (
                                ValueKind::Lit(Literal::Long(x)),
                                ValueKind::Lit(Literal::Long(y)),
                            ) => Ok(long_op(x, y).into()),
                            (ValueKind::ExtensionValue(x), ValueKind::ExtensionValue(y))
                                if x.supports_operator_overloading()
                                    && y.supports_operator_overloading()
                                    && x.typename() == y.typename() =>
                            {
                                Ok(ext_op(x, y).into())
                            }
                            // throw type errors
                            (ValueKind::Lit(Literal::Long(_)), _) => Err(EvaluationError::type_error_single(Type::Long, &arg2)),
                            (_, ValueKind::Lit(Literal::Long(_))) => Err(EvaluationError::type_error_single(Type::Long, &arg1)),
                            (ValueKind::ExtensionValue(x), _) if x.supports_operator_overloading() => Err(EvaluationError::type_error_single(Type::Extension { name: x.typename() }, &arg2)),
                            (_, ValueKind::ExtensionValue(y)) if y.supports_operator_overloading() => Err(EvaluationError::type_error_single(Type::Extension { name: y.typename() }, &arg1)),
                            (ValueKind::ExtensionValue(x), ValueKind::ExtensionValue(y)) if x.typename() == y.typename() => Err(EvaluationError::type_error_with_advice(Extensions::types_with_operator_overloading().map(|name| Type::Extension { name} ), &arg1, "Only extension types `datetime` and `duration` support operator overloading".to_string())),
                            _ => {
                                let mut expected_types = Extensions::types_with_operator_overloading().map(|name| Type::Extension { name });
                                expected_types.push(Type::Long);
                                Err(EvaluationError::type_error_with_advice(expected_types, &arg1, "Only `Long` and extension types `datetime`, `duration` support comparison".to_string()))
                            }
                        }
                    }
                    BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => {
                        let i1 = arg1.get_as_long()?;
                        let i2 = arg2.get_as_long()?;
                        match op {
                            BinaryOp::Add => match i1.checked_add(i2) {
                                Some(sum) => Ok(sum.into()),
                                None => {
                                    Err(IntegerOverflowError::BinaryOp(BinaryOpOverflowError {
                                        op: *op,
                                        arg1,
                                        arg2,
                                        source_loc: loc.cloned(),
                                    })
                                    .into())
                                }
                            },
                            BinaryOp::Sub => match i1.checked_sub(i2) {
                                Some(diff) => Ok(diff.into()),
                                None => {
                                    Err(IntegerOverflowError::BinaryOp(BinaryOpOverflowError {
                                        op: *op,
                                        arg1,
                                        arg2,
                                        source_loc: loc.cloned(),
                                    })
                                    .into())
                                }
                            },
                            BinaryOp::Mul => match i1.checked_mul(i2) {
                                Some(prod) => Ok(prod.into()),
                                None => {
                                    Err(IntegerOverflowError::BinaryOp(BinaryOpOverflowError {
                                        op: *op,
                                        arg1,
                                        arg2,
                                        source_loc: loc.cloned(),
                                    })
                                    .into())
                                }
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
                            Dereference::Residual(_) => {
                                Err(EvaluationError::non_value(expr.clone()))
                            }
                            Dereference::NoSuchEntity => self.eval_in_concrete(uid1, None, arg2),
                            Dereference::Data(entity1) => {
                                self.eval_in_concrete(uid1, Some(entity1), arg2)
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
                                    Dereference::Residual(_) => {
                                        Err(EvaluationError::non_value(expr.clone()))
                                    }
                                    Dereference::Data(entity) => match entity.get_tag(tag) {
                                        None => Err(EvaluationError::entity_tag_does_not_exist(
                                            Arc::new(uid.clone()),
                                            tag.clone(),
                                            entity.tag_keys(),
                                            entity.get(tag).is_some(),
                                            entity.tags_len(),
                                            loc.cloned(), // intentionally using the location of the entire `GetTag` expression
                                        )),
                                        Some(v) => v
                                            .clone()
                                            .try_into()
                                            .map_err(|_| EvaluationError::non_value(expr.clone())),
                                    },
                                }
                            }
                            BinaryOp::HasTag => match self.entities.entity(uid) {
                                Dereference::NoSuchEntity => Ok(false.into()),
                                Dereference::Residual(_) => {
                                    Err(EvaluationError::non_value(expr.clone()))
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
                efunc
                    .call(&args)?
                    .try_into()
                    .map_err(|_| EvaluationError::non_value(expr.clone()))
            }
            ExprKind::GetAttr { expr, attr } => {
                self.get_attr_concrete(expr.as_ref(), attr, slots, loc)
            }
            ExprKind::HasAttr { expr, attr } => match self.interpret(expr, slots)? {
                Value {
                    value: ValueKind::Record(record),
                    ..
                } => Ok(record.get(attr).is_some().into()),
                Value {
                    value: ValueKind::Lit(Literal::EntityUID(uid)),
                    ..
                } => match self.entities.entity(&uid) {
                    Dereference::NoSuchEntity => Ok(false.into()),
                    Dereference::Residual(_) => {
                        Err(EvaluationError::non_value(expr.as_ref().clone()))
                    }
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
                Ok(Value::set(vals, loc.cloned()))
            }
            ExprKind::Record(map) => {
                let map = map
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.interpret(v, slots)?)))
                    .collect::<Result<Vec<_>>>()?;

                Ok(Value::record(map, loc.cloned()))
            }
        }
    }
}
