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

//! This module includes functions to convert
//! literal Term/SymRequest/SymEntities to their
//! concrete versions

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use cedar_policy::{Entities, EntityId, EntityTypeName, EntityUid, Request};
use cedar_policy_core::ast::{
    Context, Entity, EntityAttrEvaluationError, Expr, Literal, Set, Value, ValueKind,
};
use cedar_policy_core::entities::{NoEntitiesSchema, TCComputation};
use cedar_policy_core::extensions::Extensions;
use miette::Diagnostic;
use num_bigint::{BigInt, TryFromBigIntError};
use ref_cast::RefCast;
use smol_str::SmolStr;
use thiserror::Error;

use crate::symcc::factory;

use super::env::{SymEntities, SymEntityData, SymRequest};
use super::ext::ExtError;
use super::function::{Udf, UnaryFunction};
use super::term::{Term, TermPrim};
use super::SymEnv;

/// Errors that happen during concretization, i.e., the process
/// of converting literal [`Term`]s back to representatinos in
/// [`cedar_policy`]/[`cedar_policy_core`].
#[derive(Debug, Diagnostic, Error)]
pub enum ConcretizeError {
    /// Expecting a literal entity.
    #[error("Not a literal entity: {0:?}")]
    NotLiteralEntity(Term),
    /// Expecting a literal string.
    #[error("Not a literal string: {0:?}")]
    NotLiteralString(Term),
    /// Cannot convert a term to a value.
    #[error("Unable to convert {0:?} to a value")]
    UnableToConvertToValue(Term),
    /// Cannot convert a term to a context.
    #[error("Unable to convert {0:?} to a context")]
    UnableToConvertToContext(Term),
    /// Unable to construct entity.
    #[error("Unable to construct a valid entity")]
    UnableToConstructEntity(#[from] EntityAttrEvaluationError),
    /// Entity type not found.
    #[error("Entity type not found: {0}")]
    EntityTypeNotFound(EntityTypeName),
    /// Unable to falidate request.
    #[error("Request validation error")]
    RequestValidationError(#[from] cedar_policy::RequestValidationError),
    /// Errors when constructing entity.
    #[error("Unable to construct entities")]
    EntitiesError(#[from] cedar_policy::entities_errors::EntitiesError),
    /// Fail to convert from big integer.
    #[error("Unable to convert BitVec to integer")]
    TryFromBigIntError(#[from] TryFromBigIntError<BigInt>),
    /// Extension error.
    #[error("extension error")]
    ExtError(#[from] ExtError),
    /// Unsupported expression.
    #[error("unsupported expression: {0}")]
    UnsupportedExpr(Expr),
}

/// A concrete environment recovered from a [`SymEnv`].
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct Env {
    pub request: Request,
    pub entities: Entities,
}

/// Tries to extract an `EntityUid` from a `Term`.
/// Corresponds to `Term.entityUID?` in `Concretize.lean`
impl TryFrom<&Term> for EntityUid {
    type Error = ConcretizeError;

    fn try_from(term: &Term) -> Result<Self, Self::Error> {
        if let Term::Prim(TermPrim::Entity(uid)) = term {
            Ok(uid.clone())
        } else {
            Err(ConcretizeError::NotLiteralEntity(term.clone()))
        }
    }
}

/// Tries to extract a set of `EntityUid`'s from a `Term`.
/// Corresponds `Term.setOfEntityUIDs?` in `Concretize.lean`
impl TryFrom<&Term> for BTreeSet<EntityUid> {
    type Error = ConcretizeError;

    fn try_from(term: &Term) -> Result<Self, Self::Error> {
        if let Term::Set { elts, .. } = term {
            Ok(elts
                .iter()
                .map(|t| t.try_into())
                .collect::<Result<_, _>>()?)
        } else {
            Err(ConcretizeError::NotLiteralEntity(term.clone()))
        }
    }
}

/// Tries to convert a `Term` to a string.
impl TryFrom<&Term> for String {
    type Error = ConcretizeError;

    fn try_from(term: &Term) -> Result<Self, Self::Error> {
        if let Term::Prim(TermPrim::String(s)) = term {
            Ok(s.clone())
        } else {
            Err(ConcretizeError::NotLiteralString(term.clone()))
        }
    }
}

/// Tries to extract a set of `Strings`'s from a `Term`.
impl TryFrom<&Term> for BTreeSet<String> {
    type Error = ConcretizeError;

    fn try_from(term: &Term) -> Result<Self, Self::Error> {
        if let Term::Set { elts, .. } = term {
            Ok(elts
                .iter()
                .map(|t| t.try_into())
                .collect::<Result<_, _>>()?)
        } else {
            Err(ConcretizeError::NotLiteralEntity(term.clone()))
        }
    }
}

impl TryFrom<&Term> for Value {
    type Error = ConcretizeError;

    fn try_from(term: &Term) -> Result<Self, Self::Error> {
        match term {
            Term::Prim(TermPrim::Bool(b)) => {
                Ok(Value::new(ValueKind::Lit(Literal::Bool(*b)), None))
            }

            Term::Prim(TermPrim::Bitvec(v)) => Ok(Value::new(
                ValueKind::Lit(Literal::Long(v.to_int().try_into()?)),
                None,
            )),

            Term::Prim(TermPrim::String(s)) => {
                Ok(Value::new(ValueKind::Lit(Literal::String(s.into())), None))
            }

            Term::Prim(TermPrim::Entity(uid)) => Ok(Value::new(
                ValueKind::Lit(Literal::EntityUID(Arc::new(uid.clone().into()))),
                None,
            )),

            Term::Prim(TermPrim::Ext(ext)) => Ok(Self::try_from(ext)?),

            Term::Set { elts, .. } => Ok(Value::new(
                ValueKind::Set(Set::new(
                    elts.iter()
                        .map(|t| t.try_into())
                        .collect::<Result<Vec<_>, _>>()?,
                )),
                None,
            )),

            Term::Record(rec) => Ok(Value::new(
                ValueKind::Record(Arc::new(
                    rec.iter()
                        .map(|(k, v)| {
                            if let Term::Some(t) = v {
                                Ok(Some((k.clone(), t.as_ref().try_into()?)))
                            } else if let Term::None(_) = v {
                                // None fields are simply ignored
                                Ok(None)
                            } else {
                                Ok(Some((k.clone(), v.try_into()?)))
                            }
                        })
                        .collect::<Result<Vec<Option<_>>, ConcretizeError>>()?
                        .into_iter()
                        .flatten()
                        .collect(),
                )),
                None,
            )),

            // Otherwise it's not convertable
            _ => Err(ConcretizeError::UnableToConvertToValue(term.clone())),
        }
    }
}

impl SymRequest {
    pub fn concretize(&self) -> Result<Request, ConcretizeError> {
        Ok(Request::new(
            (&self.principal).try_into()?,
            (&self.action).try_into()?,
            (&self.resource).try_into()?,
            Context::Value(self.context.try_into_record()?).into(),
            None, // TODO: schema == None disables request validation
        )?)
    }

    fn get_all_entity_uids(&self, uids: &mut BTreeSet<EntityUid>) {
        self.context.get_all_entity_uids(uids);
        self.principal.get_all_entity_uids(uids);
        self.action.get_all_entity_uids(uids);
        self.resource.get_all_entity_uids(uids);
    }
}

impl Term {
    /// Tries to convert a term into a record
    /// Corresponds to `Term.recordValue?` in `Concretize.lean`
    fn try_into_record(&self) -> Result<Arc<BTreeMap<SmolStr, Value>>, ConcretizeError> {
        if let Value {
            value: ValueKind::Record(record),
            ..
        } = self.try_into()?
        {
            Ok(record)
        } else {
            Err(ConcretizeError::UnableToConvertToContext(self.clone()))
        }
    }

    /// Collect all entity UIDs occurring in the term
    pub(crate) fn get_all_entity_uids(&self, uids: &mut BTreeSet<EntityUid>) {
        match self {
            Term::Prim(TermPrim::Entity(uid)) => {
                uids.insert(uid.clone());
            }

            Term::Some(t) => {
                t.get_all_entity_uids(uids);
            }

            Term::Set { elts, .. } => {
                for t in elts.iter() {
                    t.get_all_entity_uids(uids);
                }
            }

            Term::Record(rec) => {
                for t in rec.values() {
                    t.get_all_entity_uids(uids);
                }
            }

            Term::App { args, .. } => {
                for t in args.iter() {
                    t.get_all_entity_uids(uids);
                }
            }

            _ => {}
        }
    }
}

impl Udf {
    fn get_all_entity_uids(&self, uids: &mut BTreeSet<EntityUid>) {
        self.default.get_all_entity_uids(uids);
        for (k, v) in &self.table {
            k.get_all_entity_uids(uids);
            v.get_all_entity_uids(uids);
        }
    }
}

impl UnaryFunction {
    /// Corresponds to `UnaryFunction.entityUIDs` in `Concretize.lean`
    fn get_all_entity_uids(&self, uids: &mut BTreeSet<EntityUid>) {
        match self {
            UnaryFunction::Udf(udf) => udf.get_all_entity_uids(uids),
            UnaryFunction::Uuf(_) => {}
        }
    }
}

impl SymEntityData {
    /// Concretizes a particular entity.
    pub fn concretize(&self, euid: &EntityUid) -> Result<Entity, ConcretizeError> {
        let tuid = Term::Prim(TermPrim::Entity(euid.clone()));

        let concrete_attrs = factory::app(self.attrs.clone(), tuid.clone()).try_into_record()?;

        // For each ancestor entity type, apply the suitable ancestor function
        // to obtain a concrete set of ancestor EUIDs
        let concrete_ancestors = self
            .ancestors
            .values()
            .map(|ancestor| {
                let euids: BTreeSet<EntityUid> =
                    (&factory::app(ancestor.clone(), tuid.clone())).try_into()?;

                Ok(euids.into_iter().map(|euid| euid.as_ref().clone()))
            })
            .collect::<Result<Vec<_>, ConcretizeError>>()?
            .into_iter()
            .flatten()
            .collect::<HashSet<_>>();

        // Read tags from the model
        let tags = if let Some(tags) = &self.tags {
            // Get all valid tag keys first
            let keys: BTreeSet<String> =
                (&factory::app(tags.keys.clone(), tuid.clone())).try_into()?;

            keys.into_iter()
                .map(|k| {
                    // Using get_tag_unchecked here since we know already that k is in the key set
                    let val: Value = (&tags
                        .get_tag_unchecked(tuid.clone(), Term::Prim(TermPrim::String(k.clone()))))
                        .try_into()?;

                    Ok((k.into(), val.into()))
                })
                .collect::<Result<_, ConcretizeError>>()?
        } else {
            BTreeMap::new()
        };

        Ok(Entity::new(
            euid.as_ref().clone(),
            concrete_attrs
                .as_ref()
                .clone()
                .into_iter()
                .map(|(k, v)| (k, v.into())),
            HashSet::new(),
            concrete_ancestors,
            tags,
            Extensions::all_available(),
        )?)
    }

    /// Corresponds to `SymEntityData.entityUIDs` in `Concretize.lean`
    fn get_all_entity_uids(&self, ety: &EntityTypeName, uids: &mut BTreeSet<EntityUid>) {
        if let Some(members) = &self.members {
            for member in members {
                uids.insert(EntityUid::from_type_name_and_id(
                    ety.clone(),
                    EntityId::new(member),
                ));
            }
        }

        self.attrs.get_all_entity_uids(uids);

        for ancestor in self.ancestors.values() {
            ancestor.get_all_entity_uids(uids);
        }

        if let Some(tags) = &self.tags {
            // tags.keys.get_all_entity_uids(uids);
            tags.vals.get_all_entity_uids(uids);
        }
    }
}

impl SymEntities {
    /// Concretizes a literal SymEntities to Entities
    pub fn concretize(&self, all_euids: &BTreeSet<EntityUid>) -> Result<Entities, ConcretizeError> {
        let mut entities = Vec::new();

        for euid in all_euids {
            let sym_entity_data =
                self.0
                    .get(euid.type_name())
                    .ok_or(ConcretizeError::EntityTypeNotFound(
                        euid.type_name().clone(),
                    ))?;

            entities.push(sym_entity_data.concretize(euid)?);
        }

        // As the internal cedar_policy_core::entities::Entities
        let internal_entities = cedar_policy_core::entities::Entities::from_entities(
            entities.into_iter(),
            None::<&NoEntitiesSchema>,
            // We already put all ancestors into parents
            // and leave indirect_ancestors empty
            TCComputation::AssumeAlreadyComputed,
            Extensions::all_available(),
        )?;

        Ok(Entities::ref_cast(&internal_entities).clone())
    }

    /// Corresponds to `SymEntities.entityUIDs` in `Concretize.lean`
    fn get_all_entity_uids(&self, uids: &mut BTreeSet<EntityUid>) {
        for (ety, data) in self.0.iter() {
            data.get_all_entity_uids(ety, uids);
        }
    }
}

impl SymEnv {
    /// Corresponds to `Prim.entityUIDs` in `Concretize.lean`
    fn get_all_entity_uids_in_literal(lit: &Literal, uids: &mut BTreeSet<EntityUid>) {
        if let Literal::EntityUID(euid) = lit {
            uids.insert(euid.as_ref().clone().into());
        }
    }

    /// Corresponds to `Expr.entityUIDs` in `Concretize.lean`
    fn get_all_entity_uids_in_expr(
        expr: &Expr,
        uids: &mut BTreeSet<EntityUid>,
    ) -> Result<(), ConcretizeError> {
        use cedar_policy_core::ast::ExprKind::*;
        match expr.expr_kind() {
            Lit(lit) => Self::get_all_entity_uids_in_literal(lit, uids),
            Var(..) => {}
            If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                Self::get_all_entity_uids_in_expr(test_expr, uids)?;
                Self::get_all_entity_uids_in_expr(then_expr, uids)?;
                Self::get_all_entity_uids_in_expr(else_expr, uids)?;
            }
            And { left, right } => {
                Self::get_all_entity_uids_in_expr(left, uids)?;
                Self::get_all_entity_uids_in_expr(right, uids)?;
            }
            Or { left, right } => {
                Self::get_all_entity_uids_in_expr(left, uids)?;
                Self::get_all_entity_uids_in_expr(right, uids)?;
            }
            UnaryApp { arg, .. } => {
                Self::get_all_entity_uids_in_expr(arg, uids)?;
            }
            BinaryApp { arg1, arg2, .. } => {
                Self::get_all_entity_uids_in_expr(arg1, uids)?;
                Self::get_all_entity_uids_in_expr(arg2, uids)?;
            }
            ExtensionFunctionApp { args, .. } => {
                for arg in args.iter() {
                    Self::get_all_entity_uids_in_expr(arg, uids)?;
                }
            }
            GetAttr { expr, .. } | HasAttr { expr, .. } | Like { expr, .. } | Is { expr, .. } => {
                Self::get_all_entity_uids_in_expr(expr, uids)?;
            }
            Set(exprs) => {
                for expr in exprs.iter() {
                    Self::get_all_entity_uids_in_expr(expr, uids)?;
                }
            }
            Record(rec) => {
                for expr in rec.values() {
                    Self::get_all_entity_uids_in_expr(expr, uids)?;
                }
            }
            _ => return Err(ConcretizeError::UnsupportedExpr(expr.clone())),
        }
        Ok(())
    }

    /// Concretizes a literal [`SymEnv`] to a concrete [`Env`].
    ///
    /// In most cases, one should use [`SymEnv::extract`] instead
    /// to ensure well-formed output [`Env`].
    pub(crate) fn concretize<'a>(
        &self,
        exprs: impl Iterator<Item = &'a Expr>,
    ) -> Result<Env, ConcretizeError> {
        let mut uids = BTreeSet::new();
        self.request.get_all_entity_uids(&mut uids);
        self.entities.get_all_entity_uids(&mut uids);

        // Instead of using `footprint` and `Term::get_all_entity_uids`,
        // we collect EUIDs in expressions directly to avoid incorrect
        // short-circuiting in an incomplete entity store.
        for expr in exprs {
            Self::get_all_entity_uids_in_expr(expr, &mut uids)?;
        }

        Ok(Env {
            request: self.request.concretize()?,
            entities: self.entities.concretize(&uids)?,
        })
    }
}
