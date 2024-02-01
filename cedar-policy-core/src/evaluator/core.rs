use crate::{
    entities::{Dereference, Entities},
    extensions::Extensions,
};

use super::{
    err, err::Result, names, stack_size_check, BinaryOp, BorrowedRestrictedExpr, EntityType,
    EntityUIDEntry, EvaluationError, Expr, ExprKind, IntegerOverflowError, Literal, PartialValue,
    Policy, Request, Set, SlotEnv, Type, UnaryOp, Unknown, Value, ValueKind, Var,
};

use nonempty::nonempty;
use smol_str::SmolStr;

/// Evaluator object.
///
/// Conceptually keeps the evaluation environment as part of its internal state,
/// because we will be repeatedly invoking the evaluator on every policy in a
/// Slice.
pub struct Evaluator<'e> {
    /// `Principal` for the current request
    pub(super) principal: EntityUIDEntry,
    /// `Action` for the current request
    pub(super) action: EntityUIDEntry,
    /// `Resource` for the current request
    pub(super) resource: EntityUIDEntry,
    /// `Context` for the current request; this will be a Record type
    pub(super) context: PartialValue,
    /// Entities which we use to resolve entity references.
    ///
    /// This is a reference, because the `Evaluator` doesn't need ownership of
    /// (or need to modify) the `Entities`. One advantage of this is that you
    /// could create multiple `Evaluator`s without copying the `Entities`.
    pub(super) entities: &'e Entities,
    /// Extensions which are active for this evaluation
    pub(super) extensions: &'e Extensions<'e>,
}

/// Evaluator for "restricted" expressions. See notes on `RestrictedExpr`.
#[derive(Debug)]
pub struct RestrictedEvaluator<'e> {
    /// Extensions which are active for this evaluation
    pub(super) extensions: &'e Extensions<'e>,
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
                    None => PartialValue::unknown(Unknown::new_untyped("context")),
                    Some(ctx) => ctx.into(),
                }
            },
            entities,
            extensions,
        }
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

    /// Interpret an `Expr` into a `Value` in this evaluation environment.
    ///
    /// Ensures the result is not a residual.
    /// May return an error, for instance if the `Expr` tries to access an
    /// attribute that doesn't exist.
    pub fn interpret(&self, e: &Expr, slots: &SlotEnv) -> Result<Value> {
        stack_size_check()?;
        let res = self.interpret_internal(e, slots);

        // set the returned value's source location to the same source location
        // as the input expression had.
        // we do this here so that we don't have to set/propagate the source
        // location in every arm of the big `match` in `interpret_internal()`.
        // also, if there is an error, set its source location to the source
        // location of the input expression as well, unless it already had a
        // more specific location
        res.map(|pval| pval.with_maybe_source_loc(e.source_loc().cloned()))
            .map_err(|err| match err.source_loc() {
                None => err.with_maybe_source_loc(e.source_loc().cloned()),
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
    fn interpret_internal(&self, expr: &Expr, slots: &SlotEnv) -> Result<Value> {
        let loc = expr.source_loc(); // the `loc` describing the location of the entire expression
        match expr.expr_kind() {
            ExprKind::Lit(lit) => Ok(lit.clone().into()),
            ExprKind::Slot(id) => slots
                .get(id)
                .ok_or_else(|| err::EvaluationError::unlinked_slot(*id, loc.cloned()))
                .map(|euid| Value::from(euid.clone())),
            ExprKind::Var(v) => match v {
                Var::Principal => Ok(self.principal.evaluate(*v).try_into()?),
                Var::Action => Ok(self.action.evaluate(*v).try_into()?),
                Var::Resource => Ok(self.resource.evaluate(*v).try_into()?),
                Var::Context => Ok(self.context.clone().try_into()?),
            },
            ExprKind::Unknown(_) => Err(EvaluationError::non_value(expr.clone())),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                if self.interpret(test_expr, slots)?.get_as_bool()? {
                    self.interpret(then_expr, slots)
                } else {
                    self.interpret(else_expr, slots)
                }
            }
            ExprKind::And { left, right } => {
                if self.interpret(left, slots)?.get_as_bool()? {
                    Ok(self.interpret(right, slots)?.get_as_bool()?.into())
                } else {
                    // We can short circuit here
                    Ok(false.into())
                }
            }
            ExprKind::Or { left, right } => {
                if self.interpret(left, slots)?.get_as_bool()? {
                    // We can short circuit here
                    Ok(true.into())
                } else {
                    Ok(self.interpret(right, slots)?.get_as_bool()?.into())
                }
            }
            ExprKind::UnaryApp { op, arg } => {
                let arg = self.interpret(arg, slots)?;
                match op {
                    UnaryOp::Not => arg.get_as_bool().map(|b| (!b).into()),
                    UnaryOp::Neg => arg
                        .get_as_long()?
                        .checked_neg()
                        .map(Value::from)
                        .ok_or_else(|| {
                            EvaluationError::integer_overflow(
                                IntegerOverflowError::UnaryOp { op: *op, arg },
                                loc.cloned(),
                            )
                        }),
                }
            }
            ExprKind::BinaryApp { op, arg1, arg2 } => {
                let (arg1, arg2) = (self.interpret(arg1, slots)?, self.interpret(arg2, slots)?);
                // Borrow from cedar-spec
                match (op, &arg1, &arg2) {
                    (BinaryOp::Eq, arg1, arg2) => Ok((arg1 == arg2).into()),
                    // comparison and arithmetic operators, which only work on Longs
                    (
                        BinaryOp::Less,
                        Value {
                            value: ValueKind::Lit(Literal::Long(i1)),
                            ..
                        },
                        Value {
                            value: ValueKind::Lit(Literal::Long(i2)),
                            ..
                        },
                    ) => Ok((i1 < i2).into()),
                    (
                        BinaryOp::LessEq,
                        Value {
                            value: ValueKind::Lit(Literal::Long(i1)),
                            ..
                        },
                        Value {
                            value: ValueKind::Lit(Literal::Long(i2)),
                            ..
                        },
                    ) => Ok((i1 <= i2).into()),
                    // arithmetic
                    (
                        BinaryOp::Add,
                        Value {
                            value: ValueKind::Lit(Literal::Long(i1)),
                            ..
                        },
                        Value {
                            value: ValueKind::Lit(Literal::Long(i2)),
                            ..
                        },
                    ) => i1.checked_add(*i2).map(Value::from).ok_or_else(|| {
                        EvaluationError::integer_overflow(
                            IntegerOverflowError::BinaryOp {
                                op: *op,
                                arg1,
                                arg2,
                            },
                            loc.cloned(),
                        )
                    }),
                    (
                        BinaryOp::Sub,
                        Value {
                            value: ValueKind::Lit(Literal::Long(i1)),
                            ..
                        },
                        Value {
                            value: ValueKind::Lit(Literal::Long(i2)),
                            ..
                        },
                    ) => i1.checked_sub(*i2).map(Value::from).ok_or_else(|| {
                        EvaluationError::integer_overflow(
                            IntegerOverflowError::BinaryOp {
                                op: *op,
                                arg1,
                                arg2,
                            },
                            loc.cloned(),
                        )
                    }),
                    // this pattern should match all type errors for integer binary ops
                    (BinaryOp::Less, _, _)
                    | (BinaryOp::LessEq, _, _)
                    | (BinaryOp::Add, _, _)
                    | (BinaryOp::Sub, _, _) => {
                        let culprit = if arg1.get_as_long().is_err() {
                            arg1
                        } else {
                            arg2
                        };
                        Err(EvaluationError::type_error_with_advice(
                            nonempty![Type::Long],
                            &culprit,
                            format!("operation `{op}` should have integer operands"),
                        ))
                    }
                    // hierarchy membership operator; see note on `BinaryOp::In`
                    (
                        BinaryOp::In,
                        Value {
                            value: ValueKind::Lit(Literal::EntityUID(uid1)),
                            ..
                        },
                        _,
                    ) => {
                        match self.entities.entity(&uid1) {
                            Dereference::Residual(r) => Ok(PartialValue::Residual(
                                Expr::binary_app(BinaryOp::In, r, arg2.into()),
                            )
                            .try_into()?),
                            Dereference::NoSuchEntity => self.eval_in(&uid1, None, arg2),
                            Dereference::Data(entity1) => self.eval_in(&uid1, Some(entity1), arg2),
                        }
                    }
                    (
                        BinaryOp::In,
                        _,
                        Value {
                            value: ValueKind::Set(_),
                            ..
                        },
                    ) => Err(EvaluationError::type_error_with_advice(
                        nonempty![Type::entity_type(names::ANY_ENTITY_TYPE.clone())],
                        &arg1,
                        "`in` is for checking the entity hierarchy;
                        \
                        use `.contains()` to test set membership"
                            .into(),
                    )),
                    (
                        BinaryOp::In,
                        _,
                        Value {
                            value: ValueKind::Record(_),
                            ..
                        },
                    ) => Err(EvaluationError::type_error_with_advice(
                        nonempty![Type::entity_type(names::ANY_ENTITY_TYPE.clone())],
                        &arg1,
                        "`in` is for checking the entity hierarchy;
                        \
                        use `has` to test if a record has a key"
                            .into(),
                    )),
                    (BinaryOp::In, _, _) => Err(EvaluationError::type_error_with_advice(
                        nonempty![Type::entity_type(names::ANY_ENTITY_TYPE.clone())],
                        &arg1,
                        "the LHS of `in` should be an entity".into(),
                    )),
                    // contains, which works on Sets
                    (BinaryOp::Contains, _, _) => match arg1.value {
                        ValueKind::Set(Set { fast: Some(h), .. }) => Ok(arg2
                            .try_as_lit()
                            .map_or(false, |lit| h.contains(lit))
                            .into()),
                        ValueKind::Set(Set {
                            fast: None,
                            authoritative,
                        }) => Ok((authoritative.contains(&arg2)).into()),
                        _ => Err(EvaluationError::type_error_single(Type::Set, &arg1)),
                    },
                    // ContainsAll and ContainsAny, which work on Sets
                    (
                        BinaryOp::ContainsAll,
                        Value {
                            value:
                                ValueKind::Set(Set {
                                    authoritative: _,
                                    fast: Some(arg1_set),
                                }),
                            ..
                        },
                        Value {
                            value:
                                ValueKind::Set(Set {
                                    authoritative: _,
                                    fast: Some(arg2_set),
                                }),
                            ..
                        },
                    ) => Ok((arg2_set.is_subset(&arg1_set)).into()),
                    (
                        BinaryOp::ContainsAny,
                        Value {
                            value:
                                ValueKind::Set(Set {
                                    authoritative: _,
                                    fast: Some(arg1_set),
                                }),
                            ..
                        },
                        Value {
                            value:
                                ValueKind::Set(Set {
                                    authoritative: _,
                                    fast: Some(arg2_set),
                                }),
                            ..
                        },
                    ) => Ok((arg2_set.is_disjoint(&arg1_set)).into()),
                    (
                        BinaryOp::ContainsAll,
                        Value {
                            value: ValueKind::Set(arg1_set),
                            ..
                        },
                        Value {
                            value: ValueKind::Set(arg2_set),
                            ..
                        },
                    ) => Ok(arg2_set
                        .authoritative
                        .iter()
                        .all(|item| arg1_set.authoritative.contains(item))
                        .into()),
                    (
                        BinaryOp::ContainsAny,
                        Value {
                            value: ValueKind::Set(arg1_set),
                            ..
                        },
                        Value {
                            value: ValueKind::Set(arg2_set),
                            ..
                        },
                    ) => Ok(arg1_set
                        .authoritative
                        .iter()
                        .any(|item| arg2_set.authoritative.contains(item))
                        .into()),
                    (BinaryOp::ContainsAll, _, _) | (BinaryOp::ContainsAny, _, _) => {
                        let culprit = if arg1.get_as_set().is_err() {
                            arg1
                        } else {
                            arg2
                        };
                        Err(EvaluationError::type_error_with_advice(
                            nonempty![Type::Set],
                            &culprit,
                            format!("operation `{op}` should have set operands"),
                        ))
                    }
                }
            }
            ExprKind::MulByConst { arg, constant } => {
                let arg = self.interpret(&arg, slots)?;
                arg.get_as_long()?
                    .checked_mul(*constant)
                    .map(Value::from)
                    .ok_or_else(|| {
                        EvaluationError::integer_overflow(
                            IntegerOverflowError::Multiplication {
                                arg,
                                constant: *constant,
                            },
                            loc.cloned(),
                        )
                    })
            }
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let efunc = self
                    .extensions
                    .func(&fn_name)
                    .map_err(|err| EvaluationError::extension_function_lookup(err, loc.cloned()))?;
                let args = args
                    .iter()
                    .map(|arg| self.interpret(arg, slots).into())
                    .collect::<Result<Vec<_>>>()?;
                Ok(efunc.call(&args)?.try_into()?)
            }
            ExprKind::GetAttr { expr, attr } => {
                self.get_attr(self.interpret(expr, slots)?, attr, loc)
            }
            ExprKind::HasAttr { expr, attr } => self.has_attr(self.interpret(expr, slots)?, attr),
            ExprKind::Like { expr, pattern } => {
                let v = self.interpret(expr, slots)?.get_as_string()?.clone();
                Ok((pattern.wildcard_match(&v)).into())
            }
            ExprKind::Is { expr, entity_type } => {
                let v = self.interpret(expr, slots)?.get_as_entity()?.clone();
                Ok(match v.entity_type() {
                    EntityType::Specified(expr_entity_type) => entity_type == expr_entity_type,
                    EntityType::Unspecified => false,
                }
                .into())
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
                let (names, evalled): (Vec<SmolStr>, Vec<Value>) = map.into_iter().unzip();
                Ok(Value::record(names.into_iter().zip(evalled), loc.cloned()))
            }
        }
    }
}

impl<'e> std::fmt::Debug for Evaluator<'e> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<Evaluator with principal = {:?}, action = {:?}, resource = {:?}",
            &self.principal, &self.action, &self.resource
        )
    }
}
