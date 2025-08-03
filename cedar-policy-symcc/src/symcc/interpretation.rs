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

//! This module defines Interpretation and how
//! can SymRequest/SymEntities be interpreted with
//! an Interpretation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use cedar_policy::EntityTypeName;
use cedar_policy_core::ast::Expr;

use super::enforcer::footprint;
use super::env::{SymEntities, SymEntityData, SymRequest};
use super::function::{Udf, UnaryFunction};
use super::op::{ExtOp, Op, Uuf};
use super::tags::SymTags;
use super::term::{Term, TermPrim, TermVar};
use super::type_abbrevs::EntityUID;
use super::{factory, SymEnv};

/// An interpretation extracted from an SMT model consists of
/// - A map from variables (principal, action, resource, context) to literals
/// - A map from UUF to UDFs
#[derive(Debug)]
pub struct Interpretation<'a> {
    pub vars: BTreeMap<TermVar, Term>,
    pub funs: BTreeMap<Uuf, Udf>,
    pub env: &'a SymEnv,
}

impl<'a> Interpretation<'a> {
    pub fn default(env: &'a SymEnv) -> Self {
        Self {
            vars: BTreeMap::new(),
            funs: BTreeMap::new(),
            env,
        }
    }
}

impl Interpretation<'_> {
    /// Interprets variables as terms, and use the default literal if not found.
    pub fn interpret_var(&self, var: &TermVar) -> Term {
        self.vars
            .get(var)
            .cloned()
            .unwrap_or_else(|| var.ty.default_literal(self.env))
    }

    /// Interprets uninterpreted functions as interpreted functions, and use the
    /// default UDF if not found.
    pub fn interpret_fun(&self, fun: &Uuf) -> Udf {
        self.funs
            .get(fun)
            .cloned()
            .unwrap_or_else(|| fun.default_udf(self.env))
    }

    /// Our acyclicity constraints only apply to the footprint,
    /// but SMT solver may choose to add additional elements
    /// that introduce cycles in the ancestor functions.
    ///
    /// This function repairs that by mappinng all inputs in the
    /// ancestor functions taht are not in the footprint to empty sets
    ///
    /// Corresponds to `Interpretation.cex` in `Counterexample.lean`
    pub fn repair_as_counterexample<'b>(&self, exprs: impl Iterator<Item = &'b Expr>) -> Self {
        let mut footprint_uids = BTreeSet::new();

        // Interpret every term in the footprint to collect concrete EUIDs
        // occurring in them
        for term in exprs.flat_map(|e| footprint(e, self.env).collect::<Vec<_>>()) {
            term.interpret(self)
                .get_all_entity_uids(&mut footprint_uids);
        }

        let mut funs = self.funs.clone();

        // Repair all ancestor functions
        for (ety, ent_data) in self.env.entities.iter() {
            for fun in ent_data.ancestors.values() {
                if let UnaryFunction::Uuf(uuf) = fun {
                    funs.insert(
                        uuf.clone(),
                        uuf.repair_as_counterexample(ety, &footprint_uids, self),
                    );
                }
            }
        }

        Self {
            vars: self.vars.clone(),
            funs,
            env: self.env,
        }
    }
}

impl Uuf {
    /// Corresponds to `UUF.cexAncestors` in `Counterexample.lean`.
    fn repair_as_counterexample(
        &self,
        arg_ety: &EntityTypeName,
        footprints: &BTreeSet<EntityUID>,
        interp: &Interpretation<'_>,
    ) -> Udf {
        // Get the current, potentially incorrect interpretation
        let udf = interp.interpret_fun(self);

        // Generate a new look-up table only including the footprints (of the right type)
        let new_table = footprints
            .iter()
            .filter_map(|uid| {
                if uid.type_name() == arg_ety {
                    let t = Term::Prim(TermPrim::Entity(uid.clone()));
                    // In the domain of this ancestor function
                    Some((t.clone(), factory::app(UnaryFunction::Udf(udf.clone()), t)))
                } else {
                    None
                }
            })
            .collect();

        Udf {
            table: new_table,
            default: udf.out.default_literal(interp.env), // i.e., empty set
            ..udf
        }
    }
}

impl Term {
    /// Recursively interprets a term, substituting variables with
    /// their interpretations.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> Term {
        match self {
            Term::Prim(..) | Term::None(..) => self.clone(),
            Term::Var(var) => interp.interpret_var(var),
            Term::Some(t) => Term::Some(Arc::new(t.interpret(interp))),

            Term::Set { elts, elts_ty } => Term::Set {
                elts: Arc::new(elts.iter().map(|t| t.interpret(interp)).collect()),
                elts_ty: elts_ty.clone(),
            },

            Term::Record(rec) => Term::Record(Arc::new(
                rec.iter()
                    .map(|(k, v)| (k.clone(), v.interpret(interp)))
                    .collect(),
            )),

            Term::App { op, args, ret_ty } => match (op, args.as_slice()) {
                (Op::Not, [arg]) => factory::not(arg.interpret(interp)),
                (Op::And, [arg1, arg2]) => {
                    factory::and(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Or, [arg1, arg2]) => {
                    factory::or(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Eq, [arg1, arg2]) => {
                    factory::eq(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Ite, [arg1, arg2, arg3]) => factory::ite(
                    arg1.interpret(interp),
                    arg2.interpret(interp),
                    arg3.interpret(interp),
                ),

                (Op::Uuf(uuf), [arg]) => factory::app(
                    UnaryFunction::Udf(interp.interpret_fun(uuf)),
                    arg.interpret(interp),
                ),

                (Op::Bvneg, [arg]) => factory::bvneg(arg.interpret(interp)),

                (Op::Bvadd, [arg1, arg2]) => {
                    factory::bvadd(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Bvsub, [arg1, arg2]) => {
                    factory::bvsub(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Bvmul, [arg1, arg2]) => {
                    factory::bvmul(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Bvsdiv, [arg1, arg2]) => {
                    factory::bvsdiv(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Bvudiv, [arg1, arg2]) => {
                    factory::bvudiv(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Bvshl, [arg1, arg2]) => {
                    factory::bvshl(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Bvlshr, [arg1, arg2]) => {
                    factory::bvlshr(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Bvslt, [arg1, arg2]) => {
                    factory::bvslt(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Bvsle, [arg1, arg2]) => {
                    factory::bvsle(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Bvult, [arg1, arg2]) => {
                    factory::bvult(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Bvule, [arg1, arg2]) => {
                    factory::bvule(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Bvnego, [arg]) => factory::bvnego(arg.interpret(interp)),

                (Op::Bvsaddo, [arg1, arg2]) => {
                    factory::bvsaddo(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Bvsmulo, [arg1, arg2]) => {
                    factory::bvsmulo(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::Bvssubo, [arg1, arg2]) => {
                    factory::bvssubo(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::ZeroExtend(n), [arg]) => factory::zero_extend(*n, arg.interpret(interp)),

                (Op::SetMember, [arg1, arg2]) => {
                    factory::set_member(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::SetSubset, [arg1, arg2]) => {
                    factory::set_subset(arg1.interpret(interp), arg2.interpret(interp))
                }

                (Op::SetInter, [arg1, arg2]) => {
                    factory::set_inter(arg1.interpret(interp), arg2.interpret(interp))
                }

                // Factory.option.get' in the Lean version
                (Op::OptionGet, [arg]) => {
                    let arg = arg.interpret(interp);

                    if let Term::None(ty) = arg {
                        ty.default_literal(interp.env)
                    } else {
                        factory::option_get(arg)
                    }
                }

                (Op::RecordGet(smol_str), [arg]) => {
                    factory::record_get(arg.interpret(interp), smol_str)
                }

                (Op::StringLike(ord_pattern), [arg]) => {
                    factory::string_like(arg.interpret(interp), ord_pattern.clone())
                }

                (Op::Ext(ext_op), [arg]) => match ext_op {
                    ExtOp::DecimalVal => factory::ext_decimal_val(arg.interpret(interp)),
                    ExtOp::IpaddrIsV4 => factory::ext_ipaddr_is_v4(arg.interpret(interp)),
                    ExtOp::IpaddrAddrV4 => factory::ext_ipaddr_addr_v4(arg.interpret(interp)),
                    ExtOp::IpaddrPrefixV4 => factory::ext_ipaddr_prefix_v4(arg.interpret(interp)),
                    ExtOp::IpaddrAddrV6 => factory::ext_ipaddr_addr_v6(arg.interpret(interp)),
                    ExtOp::IpaddrPrefixV6 => factory::ext_ipaddr_prefix_v6(arg.interpret(interp)),
                    ExtOp::DatetimeVal => factory::ext_datetime_val(arg.interpret(interp)),
                    ExtOp::DatetimeOfBitVec => {
                        factory::ext_datetime_of_bitvec(arg.interpret(interp))
                    }
                    ExtOp::DurationVal => factory::ext_duration_val(arg.interpret(interp)),
                    ExtOp::DurationOfBitVec => {
                        factory::ext_duration_of_bitvec(arg.interpret(interp))
                    }
                },

                // Otherwise leave the application as it but
                // interpret the arguments
                (op, args) => Term::App {
                    op: op.clone(),
                    args: Arc::new(args.iter().map(|t| t.interpret(interp)).collect()),
                    ret_ty: ret_ty.clone(),
                },
            },
        }
    }
}

impl SymRequest {
    /// Interprets a [`SymRequest`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> SymRequest {
        SymRequest {
            principal: self.principal.interpret(interp),
            action: self.action.interpret(interp),
            resource: self.resource.interpret(interp),
            context: self.context.interpret(interp),
        }
    }
}

impl UnaryFunction {
    /// Interprets a [`UnaryFunction`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> UnaryFunction {
        match self {
            UnaryFunction::Udf(..) => self.clone(),
            UnaryFunction::Uuf(uuf) => UnaryFunction::Udf(interp.interpret_fun(uuf)),
        }
    }
}

impl SymTags {
    /// Interprets a [`SymTags`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> SymTags {
        SymTags {
            keys: self.keys.interpret(interp),
            vals: self.vals.interpret(interp),
        }
    }
}

impl SymEntityData {
    /// Interpret a [`SymEntityData`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> SymEntityData {
        SymEntityData {
            attrs: self.attrs.interpret(interp),
            ancestors: self
                .ancestors
                .iter()
                .map(|(ent, fun)| (ent.clone(), fun.interpret(interp)))
                .collect(),
            members: self.members.clone(),
            tags: self.tags.as_ref().map(|tags| tags.interpret(interp)),
        }
    }
}

impl SymEntities {
    /// Interpret a [`SymEntities`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> SymEntities {
        SymEntities(
            self.0
                .iter()
                .map(|(ent, data)| (ent.clone(), data.interpret(interp)))
                .collect(),
        )
    }
}

impl SymEnv {
    /// Interpret a [`SymEnv`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> SymEnv {
        SymEnv {
            entities: self.entities.interpret(interp),
            request: self.request.interpret(interp),
        }
    }
}

#[cfg(test)]
mod interpret_test {
    use std::str::FromStr;

    use cedar_policy::{RequestEnv, Schema};

    use crate::symcc::compiler::compile;

    use super::*;

    #[track_caller]
    pub fn pretty_panic<T>(e: impl miette::Diagnostic + Send + Sync + 'static) -> T {
        panic!("{:?}", miette::Report::new(e))
    }

    fn test_schema() -> Schema {
        let schema = r#"
            entity Thing;
            entity User in [User];
            action View appliesTo {
                principal: [User],
                resource: [Thing],
                context: {
                    x: Long,
                    y: Long,
                    a: Bool,
                    b: Bool,
                    dt1: datetime,
                    dt2: datetime,
                    d1: duration,
                    d2: duration,
                    ip1: ipaddr,
                    ip2: ipaddr,
                    ip3: ipaddr,
                    s1: Set<Long>,
                    s2: Set<Long>,
                    dc1: decimal,
                    dc2: decimal,
                    str: String,
                }
            };
        "#;
        Schema::from_cedarschema_str(schema)
            .unwrap_or_else(pretty_panic)
            .0
    }

    fn request_env() -> RequestEnv {
        RequestEnv::new(
            "User".parse().unwrap(),
            "Action::\"View\"".parse().unwrap(),
            "Thing".parse().unwrap(),
        )
    }

    fn sym_env() -> SymEnv {
        SymEnv::new(&test_schema(), &request_env()).expect("Malformed sym env.")
    }

    fn parse_expr(str: &str) -> Expr {
        Expr::from_str(str).expect(format!("Could not parse expression: {str}").as_str())
    }

    fn test_valid_bool_interp_expr(str: &str, interp: &Interpretation<'_>, res: bool) {
        let term = compile(&parse_expr(str), &sym_env()).unwrap();
        let term_interp = term.interpret(interp);
        assert_eq!(
            term_interp,
            Term::Some(Arc::new(Term::Prim(TermPrim::Bool(res)))),
            "{str}"
        );
        // Check idempotency
        assert_eq!(term_interp, term_interp.interpret(interp));
    }

    #[test]
    fn test_interp_term_builtin() {
        let symenv = sym_env();
        let interp = Interpretation::default(&symenv);
        test_valid_bool_interp_expr(
            "context.x + context.y == context.y + context.x",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "context.x + context.y == context.y + context.x",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "context.x < context.y || context.x == context.y || context.x > context.y",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "context.x * context.y == context.y * context.x",
            &interp,
            true,
        );
        test_valid_bool_interp_expr("--context.x == context.x", &interp, true);
        test_valid_bool_interp_expr(
            "(!context.a && !context.b) == !(context.a || context.b)",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "(if context.a then context.x else context.y) == (if !context.a then context.y else context.x)",
            &interp,
            true,
        );
        test_valid_bool_interp_expr("context.x + 1 == context.x", &interp, false);
        test_valid_bool_interp_expr(r#"context.str like "*""#, &interp, true);
    }

    #[test]
    fn test_interp_term_set() {
        let symenv = sym_env();
        let interp = Interpretation::default(&symenv);
        test_valid_bool_interp_expr(
            "!(context.s1.containsAll(context.s2) && context.s2.containsAll(context.s1)) || context.s1 == context.s2",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "!(context.s1.containsAll(context.s2) && context.s2.contains(10)) || context.s1.contains(10)",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "!(context.s1.contains(10) && context.s2.contains(10)) || context.s1.containsAny(context.s2)",
            &interp,
            true,
        );
    }

    #[test]
    fn test_interp_term_decimal() {
        let symenv = sym_env();
        let interp = Interpretation::default(&symenv);
        test_valid_bool_interp_expr(
            "context.dc1.lessThan(context.dc2) || context.dc1 == context.dc2 || context.dc1.greaterThan(context.dc2)",
            &interp,
            true,
        );
    }

    #[test]
    fn test_interp_term_datetime() {
        let symenv = sym_env();
        let interp = Interpretation::default(&symenv);
        test_valid_bool_interp_expr(
            "context.dt1.offset(context.d1).offset(context.d2) == context.dt1.offset(context.d2).offset(context.d1)",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            r#"
            !(context.dt1 >= context.dt2 && context.dt2 >= datetime("1970-01-01")) ||
            context.dt1.durationSince(context.dt2) >= duration("0ms")
            "#,
            &interp,
            true,
        );
    }

    #[test]
    fn test_interp_term_ipaddr() {
        let symenv = sym_env();
        let interp = Interpretation::default(&symenv);
        test_valid_bool_interp_expr(
            "context.ip1.isIpv4() || context.ip1.isIpv6()",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "!(context.ip1.isIpv4() && context.ip1.isIpv6())",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "!(context.ip1.isInRange(context.ip2) && context.ip2.isInRange(context.ip3)) || context.ip1.isInRange(context.ip3)",
            &interp,
            true,
        );
    }
}
