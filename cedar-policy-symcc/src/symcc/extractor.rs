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

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::{collections::BTreeSet, sync::Arc};

use cedar_policy_core::ast::Expr;

use super::concretizer::{ConcretizeError, Env};
use super::enforcer::footprints;
use super::env::{SymEntities, SymEntityData, SymEnv};
use super::factory;
use super::function::{Udf, UnaryFunction};
use super::interpretation::Interpretation;
use super::op::Uuf;
use super::term::{Term, TermPrim};
use super::term_type::TermType;
use super::type_abbrevs::EntityUID;

impl UnaryFunction {
    /// Corresponds to `UnaryFunction.uuf?` in `Extractor.lean`.
    fn uuf(&self) -> Option<&Uuf> {
        match self {
            UnaryFunction::Uuf(u) => Some(u),
            UnaryFunction::Udf(_) => None,
        }
    }
}

impl SymEntityData {
    /// Corresponds to `SymEntityData.uufAncestors` in `Extractor.lean`.
    ///
    /// Returns an iterator, rather than a Set as in the Lean, but the caller
    /// (`SymEntities::uuf_ancestors()`) will eliminate duplicates.
    fn uuf_ancestors(&self) -> impl Iterator<Item = &Uuf> {
        self.ancestors.values().filter_map(|f| f.uuf())
    }
}

impl SymEntities {
    /// Corresponds to `SymEntities.uufAncestors` in `Extractor.lean`.
    fn uuf_ancestors(&self) -> BTreeSet<&Uuf> {
        self.values()
            .flat_map(|edata| edata.uuf_ancestors())
            .collect()
    }
}

impl Uuf {
    /// Corresponds to `UUF.repairAncestors` in `Extractor.lean`.
    fn repair_as_counterexample(
        &self,
        footprints: &BTreeSet<EntityUID>,
        interp: &Interpretation<'_>,
    ) -> Udf {
        // Get the current, potentially incorrect interpretation
        let udf = interp.interpret_fun(self);

        let entry = |udf: &Udf, uid| -> Option<(Term, Term)> {
            let t = Term::Prim(TermPrim::Entity(uid));
            if &t.type_of() == &udf.arg {
                Some((
                    t.clone(),
                    factory::app(UnaryFunction::Udf(Arc::new(udf.clone())), t),
                ))
            } else {
                None
            }
        };

        // Generate a new look-up table only including the footprints (of the right type)
        let new_table = footprints
            .iter()
            .filter_map(|uid| entry(&udf, uid.clone()))
            .collect();

        Udf {
            table: Arc::new(new_table),
            default: match &udf.out {
                TermType::Set { ty } => factory::set_of([], (**ty).clone()),
                _ => udf.default,
            },
            ..udf
        }
    }
}

impl Interpretation<'_> {
    /// Our acyclicity constraints only apply to the footprint,
    /// but SMT solver may choose to add additional elements
    /// that introduce cycles in the ancestor functions.
    ///
    /// This function repairs that by mapping all inputs in the
    /// ancestor functions that are not in the footprint to empty sets
    ///
    /// Corresponds to `Interpretation.repair` in `Extractor.lean`
    pub fn repair_as_counterexample<'b>(&self, exprs: impl Iterator<Item = &'b Expr>) -> Self {
        let mut footprint_uids = BTreeSet::new();

        // Interpret every term in the footprint to collect concrete EUIDs
        // occurring in them
        for term in footprints(exprs, self.env) {
            term.interpret(self)
                .get_all_entity_uids(&mut footprint_uids);
        }
        // At this point, `footprint_uids` corresponds to `footprintUIDs` in the Lean

        let footprint_ancestors: BTreeMap<&Uuf, Udf> = self
            .env
            .entities
            .uuf_ancestors()
            .into_iter()
            .map(|f| (f, f.repair_as_counterexample(&footprint_uids, self)))
            .collect();

        // `funs` will be the existing `self.funs` for all entries except ones in `footprint_ancestors`
        let mut funs = self.funs.clone();
        for (uuf, udf) in footprint_ancestors {
            funs.insert(uuf.clone(), udf);
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
    pub fn extract<E: Borrow<Expr>>(
        &self,
        exprs: impl IntoIterator<Item = E>,
        interp: &Interpretation<'_>,
    ) -> Result<Env, ConcretizeError> {
        let exprs = exprs.into_iter().collect::<Vec<_>>();
        let interp = interp.repair_as_counterexample(exprs.iter().map(Borrow::borrow));
        self.interpret(&interp).concretize(exprs)
    }
}
