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

//! This module builds on top of concretizer to
//! convert a [`SymEnv`]'s [`Interpretation`]
//! to an actual concrete environment ([`Env`]).
//!
//! In particular, this module includes procedures to
//! "repair" a raw [`Interpretation`] to restrict domains
//! of the ancestor functions to only the footprint entity UIDs,
//! ensuring that the resulting entity hierarchy is acyclic
//! and transitive (assuming the suitable acyclicity and transitivity
//! constraints are satisfied for the footprint).

use std::{collections::BTreeSet, sync::Arc};

use cedar_policy_core::ast::Expr;

use super::concretizer::{ConcretizeError, Env};
use super::enforcer::footprint;
use super::env::SymEnv;
use super::factory;
use super::function::{Udf, UnaryFunction};
use super::interpretation::Interpretation;
use super::op::Uuf;
use super::term::{Term, TermPrim};
use super::term_type::TermTypeInner;
use super::type_abbrevs::{EntityType, EntityUID};
use hashconsing::HConsign;

impl Uuf {
    /// Corresponds to `UUF.repairAncestors` in `Extractor.lean`.
    fn repair_as_counterexample(
        &self,
        arg_ety: &EntityType,
        footprints: &BTreeSet<EntityUID>,
        interp: &Interpretation<'_>,
        h: &mut HConsign<TermTypeInner>,
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
                    Some((
                        t.clone(),
                        factory::app(UnaryFunction::Udf(Arc::new(udf.clone())), t, h),
                    ))
                } else {
                    None
                }
            })
            .collect();

        Udf {
            table: Arc::new(new_table),
            default: udf.default.clone(),
            arg: udf.arg.clone(),
            out: udf.out,
        }
    }
}

impl Interpretation<'_> {
    /// Our acyclicity constraints only apply to the footprint,
    /// but SMT solver may choose to add additional elements
    /// that introduce cycles in the ancestor functions.
    ///
    /// This function repairs that by mappinng all inputs in the
    /// ancestor functions that are not in the footprint to empty sets
    ///
    /// Corresponds to `Interpretation.repair` in `Extractor.lean`
    pub fn repair_as_counterexample<'b>(&self, exprs: impl Iterator<Item = &'b Expr>) -> Self {
        let mut h = HConsign::empty();
        let mut footprint_uids = BTreeSet::new();

        // Interpret every term in the footprint to collect concrete EUIDs
        // occurring in them
        for e in exprs {
            for term in footprint(e, self.env, &mut h) {
                term.interpret(self, &mut h)
                    .get_all_entity_uids(&mut footprint_uids);
            }
        }

        let mut funs = self.funs.clone();

        // Repair all ancestor functions
        for (ety, ent_data) in self.env.entities.iter() {
            for fun in ent_data.ancestors.values() {
                if let UnaryFunction::Uuf(uuf) = fun {
                    funs.insert(
                        uuf.as_ref().clone(),
                        uuf.repair_as_counterexample(ety, &footprint_uids, self, &mut h),
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

impl SymEnv {
    /// Similar to `SymEnv::concretize`, but it in addition
    /// repairs the interpretation to ensure that the entity hierarchy
    /// to remove entities outside the given footprint.
    ///
    /// Corresponds to `SymEnv.extract?` in `Extractor.lean`.
    pub fn extract<'a>(
        &self,
        exprs: impl Iterator<Item = &'a Expr>,
        interp: &Interpretation<'_>,
    ) -> Result<Env, ConcretizeError> {
        let mut h = HConsign::empty();
        let exprs = exprs.collect::<Vec<_>>();
        let interp = interp.repair_as_counterexample(exprs.iter().copied());
        self.interpret(&interp, &mut h)
            .concretize(exprs.into_iter(), &mut h)
    }
}
