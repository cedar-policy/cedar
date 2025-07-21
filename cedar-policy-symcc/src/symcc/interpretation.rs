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
pub struct Interpretation {
    pub vars: BTreeMap<TermVar, Term>,
    pub funs: BTreeMap<Uuf, Udf>,
}

impl Default for Interpretation {
    /// The default interpretation is empty, i.e.,
    /// any variable or UUF is interpted as the default of their types.
    fn default() -> Self {
        Self {
            vars: BTreeMap::new(),
            funs: BTreeMap::new(),
        }
    }
}

impl Interpretation {
    /// Interprets variables as terms, and use the default literal if not found.
    pub fn interpret_var(&self, var: &TermVar) -> Term {
        self.vars
            .get(var)
            .cloned()
            .unwrap_or_else(|| var.ty.default_literal())
    }

    /// Interprets uninterpreted functions as interpreted functions, and use the
    /// default UDF if not found.
    pub fn interpret_fun(&self, fun: &Uuf) -> Udf {
        self.funs
            .get(fun)
            .cloned()
            .unwrap_or_else(|| fun.default_udf())
    }

    /// Our acyclicity constraints only apply to the footprint,
    /// but SMT solver may choose to add additional elements
    /// that introduce cycles in the ancestor functions.
    ///
    /// This function repairs that by mappinng all inputs in the
    /// ancestor functions taht are not in the footprint to empty sets
    ///
    /// Corresponds to `Interpretation.cex` in `Counterexample.lean`
    pub fn repair_as_counterexample<'a>(
        &self,
        exprs: impl Iterator<Item = &'a Expr>,
        env: &SymEnv,
    ) -> Self {
        let mut footprint_uids = BTreeSet::new();

        // Interpret every term in the footprint to collect concrete EUIDs
        // occurring in them
        for term in exprs.flat_map(|e| footprint(e, env).collect::<Vec<_>>()) {
            term.interpret(self)
                .get_all_entity_uids(&mut footprint_uids);
        }

        let mut funs = self.funs.clone();

        // Repair all ancestor functions
        for (ety, ent_data) in env.entities.iter() {
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
        }
    }
}

impl Uuf {
    /// Corresponds to `UUF.cexAncestors` in `Counterexample.lean`.
    fn repair_as_counterexample(
        &self,
        arg_ety: &EntityTypeName,
        footprints: &BTreeSet<EntityUID>,
        interp: &Interpretation,
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
            default: udf.out.default_literal(), // i.e., empty set
            ..udf
        }
    }
}

impl Term {
    /// Recursively interprets a term, substituting variables with
    /// their interpretations.
    pub fn interpret(&self, interp: &Interpretation) -> Term {
        match self {
            Term::Prim(..) | Term::None(..) => self.clone(),
            Term::Var(var) => interp.interpret_var(var),
            Term::Some(t) => Term::Some(Box::new(t.interpret(interp))),

            Term::Set { elts, elts_ty } => Term::Set {
                elts: elts.iter().map(|t| t.interpret(interp)).collect(),
                elts_ty: elts_ty.clone(),
            },

            Term::Record(rec) => Term::Record(
                rec.iter()
                    .map(|(k, v)| (k.clone(), v.interpret(interp)))
                    .collect(),
            ),

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
                        ty.default_literal()
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
                    args: args.iter().map(|t| t.interpret(interp)).collect(),
                    ret_ty: ret_ty.clone(),
                },
            },
        }
    }
}

impl SymRequest {
    /// Interprets a [`SymRequest`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation) -> SymRequest {
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
    pub fn interpret(&self, interp: &Interpretation) -> UnaryFunction {
        match self {
            UnaryFunction::Udf(..) => self.clone(),
            UnaryFunction::Uuf(uuf) => UnaryFunction::Udf(interp.interpret_fun(uuf)),
        }
    }
}

impl SymTags {
    /// Interprets a [`SymTags`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation) -> SymTags {
        SymTags {
            keys: self.keys.interpret(interp),
            vals: self.vals.interpret(interp),
        }
    }
}

impl SymEntityData {
    /// Interpret a [`SymEntityData`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation) -> SymEntityData {
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
    pub fn interpret(&self, interp: &Interpretation) -> SymEntities {
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
    pub fn interpret(&self, interp: &Interpretation) -> SymEnv {
        SymEnv {
            entities: self.entities.interpret(interp),
            request: self.request.interpret(interp),
        }
    }
}
