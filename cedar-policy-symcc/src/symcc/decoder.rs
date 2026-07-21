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

//! This module defines the Cedar decoder, which is the inverse of the encoder
//! that parses a subset of SMT-LIB terms and commands required for (get-model)

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use cedar_policy::{EntityId, EntityUid};
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

use crate::symcc::bitvec::BitVecError;
use crate::symcc::decoder::sexpr::SExprParseError;
use crate::symcc::env::SymEntityData;
use crate::symcc::extension_types::ipaddr::{
    CIDRv4, CIDRv6, IPv4Addr, IPv4Prefix, IPv6Addr, IPv6Prefix,
};
use crate::symcc::type_abbrevs::{ExtType, Width, SIXTY_FOUR};
use crate::SymEnv;

use super::bitvec::BitVec;
use super::encoder::Encoder;
use super::ext::Ext;
use super::extension_types::datetime::{Datetime, Duration};
use super::extension_types::decimal::Decimal;
use super::extension_types::ipaddr::IPNet;
use super::factory;
use super::function::Udf;
use super::interpretation::Interpretation;
use super::op::Uuf;
use super::term::{Term, TermPrim, TermVar};
use super::term_type::TermType;

mod sexpr;
use sexpr::{parse_sexpr, SExpr};

/// Errors during decoding, i.e., converting SMT terms
/// to our internal [`Term`] representation.
#[derive(Debug, Diagnostic, Error)]
pub enum DecodeError {
    /// Error parsing an s-expression
    #[error(transparent)]
    SExprParse(#[from] SExprParseError),
    /// Failed to parse an SMT numeral.
    #[error("Invalid numeric token: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    /// Integer overflow.
    #[error("Integer overflow")]
    IntegerOverflow,
    /// Model of an unexpected form returned by the solver.
    #[error("Model of an unexpected form returned by the solver")]
    UnexpectedModel,
    /// Unknown SMT type.
    #[error("Unknown SMT type: {0}")]
    UnknownType(SExpr),
    /// Unknown SMT literal.
    #[error("Unknown SMT literal: {0}")]
    UnknownLiteral(SExpr),
    /// Unmatched types.
    #[error("Unmatched type: expected {0:?}, found {1:?}")]
    UnmatchedType(TermType, TermType),
    /// Unmatched field type.
    #[error("Unmatched field type: expected {0:?}, found {1:?}")]
    UnmatchedFieldType(TermType, TermType),
    /// Invalid set type.
    #[error("Invalid set type: {0}")]
    InvalidSetType(SExpr),
    /// Invalid option type.
    #[error("Invalid option type: {0}")]
    InvalidOptionType(SExpr),
    /// `set.union` applied to non-literals.
    #[error("set.union applied to non-literals {0:?} and {1:?}")]
    SetUnionNonLiterals(Term, Term),
    /// Unmatched record type fields.
    #[error("Unmatched record type fields")]
    UnmatchedRecordType,
    /// Unknown variable.
    #[error("Unknown variable: {0}")]
    UnknownVariable(String),
    /// Unknown unary function.
    #[error("Unknown unary function: {0}")]
    UnknownUUF(String),
    /// Unexpected form of unary function model.
    #[error("Unexpected form of unary function model: {0}")]
    UnexpectedUnaryFunctionForm(SExpr),
    /// Bit-vector error.
    #[error("Bit-vector error")]
    BitVecError(#[from] BitVecError),
    /// Bitvector of a zero width, which we do not support.
    #[error("Bitvector of zero width")]
    ZeroWidthBitVec,
}

/// Maps from SMT symbols their corresponding variables
/// (principal, action, resource) and entity types.
#[derive(Debug)]
pub struct IdMaps<'a> {
    types: BTreeMap<&'a SmolStr, &'a TermType>,
    vars: BTreeMap<&'a SmolStr, &'a TermVar>,
    uufs: BTreeMap<&'a SmolStr, &'a Uuf>,
    enums: BTreeMap<SmolStr, EntityUid>,
}

impl<'a> IdMaps<'a> {
    /// Extracts the reverse mapping from SMT symbols to
    /// Term-level names from the encoder state.
    pub fn from_encoder<S>(encoder: &'a Encoder<'_, S>) -> Self {
        let mut types = BTreeMap::new();
        let mut vars = BTreeMap::new();
        let mut uufs = BTreeMap::new();
        let mut enums = BTreeMap::new();

        for (term, enc) in &encoder.types {
            types.insert(enc, term);
        }

        for (term, enc) in &encoder.terms {
            if let Term::Var(var) = term {
                vars.insert(enc, var);
            }
        }

        for (uuf, id) in &encoder.uufs {
            uufs.insert(id, uuf);
        }

        for (&entity_type, &enum_ids) in &encoder.enums {
            if let Some(entity_type_id) = encoder.types.get(&TermType::Entity {
                ety: entity_type.clone(),
            }) {
                for (i, enum_id) in enum_ids.iter().enumerate() {
                    enums.insert(
                        super::encoder::enum_id(entity_type_id, i),
                        EntityUid::from_type_name_and_id(
                            entity_type.clone(),
                            EntityId::new(enum_id),
                        ),
                    );
                }
            }
        }

        Self {
            types,
            vars,
            uufs,
            enums,
        }
    }
}

impl TermType {
    /// Default literal of a type.
    /// Used as placeholders for SMT partial applications.
    pub fn default_literal(&self, env: &SymEnv) -> Term {
        match self {
            TermType::Bool => Term::Prim(TermPrim::Bool(false)),
            TermType::Bitvec { n } => Term::Prim(TermPrim::Bitvec(BitVec::of_u128(*n, 0))),
            TermType::String => Term::Prim(TermPrim::String(SmolStr::new_static(""))),

            TermType::Entity { ety } => {
                // If the entity is an enum type, we return the first enum
                let eid = if let Some(SymEntityData {
                    members: Some(eids),
                    ..
                }) = env.entities.get(ety)
                {
                    if let Some(eid) = eids.first() {
                        eid
                    } else {
                        "" // This case should not happen on a well-formed `SymEnv`
                    }
                } else {
                    ""
                };
                Term::Prim(TermPrim::Entity(EntityUid::from_type_name_and_id(
                    ety.clone(),
                    EntityId::new(eid),
                )))
            }

            TermType::Ext { xty } => match xty {
                ExtType::Decimal => Term::Prim(TermPrim::Ext(Ext::Decimal { d: Decimal(0) })),

                ExtType::DateTime => Term::Prim(TermPrim::Ext(Ext::Datetime {
                    dt: Datetime::default(),
                })),

                ExtType::Duration => Term::Prim(TermPrim::Ext(Ext::Duration {
                    d: Duration::default(),
                })),

                ExtType::IpAddr => Term::Prim(TermPrim::Ext(Ext::Ipaddr {
                    ip: IPNet::default(),
                })),
            },

            TermType::Option { ty } => Term::None(ty.as_ref().clone()),

            TermType::Set { ty } => Term::Set {
                elts: Arc::new(BTreeSet::new()),
                elts_ty: ty.as_ref().clone(),
            },

            TermType::Record { rty } => Term::Record(Arc::new(
                rty.iter()
                    .map(|(k, v)| (k.clone(), v.default_literal(env)))
                    .collect(),
            )),
        }
    }
}

impl Uuf {
    /// Similar to [`TermType::default_literal`], but for [`Uuf`].
    pub fn default_udf(&self, env: &SymEnv) -> Udf {
        Udf {
            arg: self.arg.clone(),
            out: self.out.clone(),
            table: Arc::new(BTreeMap::new()),
            default: self.out.default_literal(env),
        }
    }
}

impl SExpr {
    /// Checks if the [`SExpr`] is the given symbol.
    fn is_symbol(&self, s: &str) -> bool {
        match self {
            SExpr::Symbol(sym) => sym == s,
            _ => false,
        }
    }

    /// Checks if the [`SExpr`] is an `App` where the target function is the given symbol.
    fn is_app_of(&self, s: &str) -> bool {
        matches!(self, SExpr::App(sexprs) if sexprs.first().is_some_and(|e| e.is_symbol(s)))
    }

    /// If this [`SExpr`] is an `App` applying the function named `func`, returns its arguments
    /// (excluding the function symbol itself).
    fn as_app(&self, func: &str) -> Option<&[SExpr]> {
        match self {
            SExpr::App(sexprs) => match sexprs.as_slice() {
                [SExpr::Symbol(f), args @ ..] if f == func => Some(args),
                _ => None,
            },
            _ => None,
        }
    }

    /// If this [`SExpr`] is an `App` applying the function named `func` to
    /// exactly `N` arguments, returns those arguments (excluding the function symbol itself).
    fn as_app_n<const N: usize>(&self, func: &str) -> Option<&[SExpr; N]> {
        self.as_app(func)
            .and_then(|args| <&[SExpr; N]>::try_from(args).ok())
    }

    /// Decodes [`TermType`] from an [`SExpr`].
    pub fn decode_type(&self, id_maps: &IdMaps<'_>) -> Result<TermType, DecodeError> {
        match self {
            // Atomic types
            SExpr::Symbol(s) => {
                match s.as_str() {
                    "Bool" => Ok(TermType::Bool),
                    "String" => Ok(TermType::String),
                    "Decimal" => Ok(TermType::Ext {
                        xty: ExtType::Decimal,
                    }),
                    "IPAddr" => Ok(TermType::Ext {
                        xty: ExtType::IpAddr,
                    }),
                    "Duration" => Ok(TermType::Ext {
                        xty: ExtType::Duration,
                    }),
                    "Datetime" => Ok(TermType::Ext {
                        xty: ExtType::DateTime,
                    }),

                    // Entity or record type
                    _ => id_maps
                        .types
                        .get(s)
                        .copied()
                        .cloned()
                        .ok_or_else(|| DecodeError::UnknownType(self.clone())),
                }
            }

            // Parametrized types
            SExpr::App(args) => {
                match args.as_slice() {
                    // (_ BitVec n)
                    [SExpr::Symbol(app), SExpr::Symbol(bit_vec), SExpr::Numeral(n)]
                        if app == "_" && bit_vec == "BitVec" =>
                    {
                        let n = u32::try_from(*n).map_err(|_| DecodeError::IntegerOverflow)?;
                        let n = Width::new(n).ok_or(DecodeError::ZeroWidthBitVec)?;
                        Ok(TermType::Bitvec { n })
                    }

                    // (Option x)
                    [SExpr::Symbol(option), param] if option == "Option" => {
                        let ty = param.decode_type(id_maps)?;
                        Ok(TermType::option_of(ty))
                    }

                    // (Set x)
                    [SExpr::Symbol(set), param] if set == "Set" => {
                        let ty = param.decode_type(id_maps)?;
                        Ok(TermType::set_of(ty))
                    }

                    _ => Err(DecodeError::UnknownType(self.clone())),
                }
            }

            _ => Err(DecodeError::UnknownType(self.clone())),
        }
    }

    /// Decodes an [`SExpr`] as an entity UID or record.
    /// Corresponds to `SExpr.decodeLit.constructEntityOrRecord` in Lean.
    fn decode_entity_or_record(
        &self,
        id_maps: &IdMaps<'_>,
        name: &SmolStr,
        args: &[SExpr],
    ) -> Result<Term, DecodeError> {
        match (id_maps.types.get(name), args) {
            // Entity UID
            (Some(TermType::Entity { ety }), [SExpr::String(e)]) => {
                let uid = EntityUid::from_type_name_and_id(ety.clone(), EntityId::new(e));
                Ok(Term::Prim(TermPrim::Entity(uid)))
            }

            // Record
            (Some(TermType::Record { rty }), fields) => {
                if fields.len() != rty.len() {
                    return Err(DecodeError::UnmatchedRecordType);
                }

                let mut record = BTreeMap::new();

                for (field, (field_name, field_ty)) in fields.iter().zip(rty.iter()) {
                    let decoded_field = field.decode_literal_expecting(id_maps, Some(field_ty))?;
                    let decoded_field_ty = decoded_field.type_of();

                    if &decoded_field_ty != field_ty {
                        return Err(DecodeError::UnmatchedFieldType(
                            decoded_field_ty,
                            field_ty.clone(),
                        ));
                    }

                    record.insert(field_name.clone(), decoded_field);
                }

                Ok(Term::Record(Arc::new(record)))
            }

            _ => Err(DecodeError::UnknownLiteral(self.clone())),
        }
    }

    /// Helper function to decode more complex applications as literals.
    /// Corresponds to `SExpr.decodeLit.construct` in Lean.
    ///
    /// This function accepts an optional expected type which it uses to assign
    /// a type to a `none` expression without explicit type annotation (as is
    /// emitted by Z3), but it does not use this type to do any additional
    /// typechecking.
    fn decode_literal_app(
        &self,
        id_maps: &IdMaps<'_>,
        args: &[SExpr],
        expected_ty: Option<&TermType>,
    ) -> Result<Term, DecodeError> {
        match args {
            // Sometimes cvc5 does not simplify the terms in the model,
            // and having these custom interpreters alleviates such issues
            // (e.g., https://github.com/cvc5/cvc5/issues/11928).

            // (not <v>)
            [SExpr::Symbol(not_tok), v] if not_tok == "not" => {
                Ok(factory::not(v.decode_literal(id_maps)?))
            }

            // (or <v1> <v2>)
            [SExpr::Symbol(or_tok), v1, v2] if or_tok == "or" => Ok(factory::or(
                v1.decode_literal(id_maps)?,
                v2.decode_literal(id_maps)?,
            )),

            // (= <v1> <v2>)
            [SExpr::Symbol(eq_tok), v1, v2] if eq_tok == "=" => Ok(factory::eq(
                v1.decode_literal(id_maps)?,
                v2.decode_literal(id_maps)?,
            )),

            // (ite <cond> <then> <else>)
            [SExpr::Symbol(ite_tok), cond, true_branch, false_branch] if ite_tok == "ite" => {
                Ok(factory::ite(
                    cond.decode_literal(id_maps)?,
                    true_branch.decode_literal_expecting(id_maps, expected_ty)?,
                    false_branch.decode_literal_expecting(id_maps, expected_ty)?,
                ))
            }

            // (bvnego <v1>)
            [SExpr::Symbol(bvnego_tok), v] if bvnego_tok == "bvnego" => {
                Ok(factory::bvnego(v.decode_literal(id_maps)?))
            }

            // (bvsaddo <v1> <v2>)
            [SExpr::Symbol(bvsaddo_tok), v1, v2] if bvsaddo_tok == "bvsaddo" => Ok(
                factory::bvsaddo(v1.decode_literal(id_maps)?, v2.decode_literal(id_maps)?),
            ),

            // (bvsmulo <v1> <v2>)
            [SExpr::Symbol(bvsmulo_tok), v1, v2] if bvsmulo_tok == "bvsmulo" => Ok(
                factory::bvsmulo(v1.decode_literal(id_maps)?, v2.decode_literal(id_maps)?),
            ),

            // (as none <typ>)
            [SExpr::Symbol(as_tok), SExpr::Symbol(none), typ]
                if as_tok == "as" && none == "none" =>
            {
                match typ.decode_type(id_maps)? {
                    TermType::Option { ty } => Ok(Term::None(Arc::unwrap_or_clone(ty))),
                    _ => Err(DecodeError::InvalidOptionType(typ.clone())),
                }
            }

            // ((as some <typ>) <val>)
            #[expect(
                clippy::indexing_slicing,
                reason = "Slice of length 3 can be indexed by 0-2"
            )]
            [SExpr::App(as_some_typ), val]
                if as_some_typ.len() == 3
                    && as_some_typ[0].is_symbol("as")
                    && as_some_typ[1].is_symbol("some") =>
            {
                let ty = as_some_typ[2].decode_type(id_maps)?;
                let inner_ty = match &ty {
                    TermType::Option { ty } => Some(ty.as_ref()),
                    _ => None,
                };
                let val = Term::Some(Arc::new(val.decode_literal_expecting(id_maps, inner_ty)?));
                let val_ty = val.type_of();

                if val_ty != ty {
                    return Err(DecodeError::UnmatchedType(val_ty, ty));
                }

                Ok(val)
            }

            // (some <val>) without type annotation (Z3 produces this)
            [SExpr::Symbol(some), val] if some == "some" => {
                let inner_ty = match expected_ty {
                    None => None,
                    Some(TermType::Option { ty }) => Some(ty.as_ref()),
                    Some(_) => return Err(DecodeError::UnknownLiteral(self.clone())),
                };
                let val = val.decode_literal_expecting(id_maps, inner_ty)?;
                Ok(Term::Some(Arc::new(val)))
            }

            // (as set.empty <set_typ>)
            [SExpr::Symbol(as_tok), SExpr::Symbol(set_empty), typ]
                if as_tok == "as" && set_empty == "set.empty" =>
            {
                let ty = typ.decode_type(id_maps)?;

                match ty {
                    TermType::Set { ty } => Ok(Term::Set {
                        elts: Arc::new(BTreeSet::new()),
                        elts_ty: Arc::unwrap_or_clone(ty),
                    }),
                    _ => Err(DecodeError::InvalidSetType(typ.clone())),
                }
            }

            // (set.singleton <val>)
            [SExpr::Symbol(set_singleton), val] if set_singleton == "set.singleton" => {
                let elt_ty = match expected_ty {
                    None => None,
                    Some(TermType::Set { ty }) => Some(ty.as_ref()),
                    Some(_) => return Err(DecodeError::UnknownLiteral(self.clone())),
                };
                let val = val.decode_literal_expecting(id_maps, elt_ty)?;
                let val_ty = val.type_of();
                Ok(Term::Set {
                    elts: Arc::new(BTreeSet::from([val])),
                    elts_ty: val_ty,
                })
            }

            // (set.union <set1> <set2>)
            [SExpr::Symbol(set_union), set1, set2] if set_union == "set.union" => {
                let set1 = set1.decode_literal_expecting(id_maps, expected_ty)?;
                let set2 = set2.decode_literal_expecting(id_maps, expected_ty)?;
                let set1_ty = set1.type_of();
                let set2_ty = set2.type_of();

                if set1_ty != set2_ty {
                    return Err(DecodeError::UnmatchedType(set1_ty, set2_ty));
                }

                match (set1, set2) {
                    // Merge two set literals
                    (
                        Term::Set {
                            elts: elts1,
                            elts_ty,
                        },
                        Term::Set { elts: elts2, .. },
                    ) => Ok(Term::Set {
                        elts: Arc::new(elts1.union(&elts2).cloned().collect()),
                        elts_ty,
                    }),

                    (set1, set2) => Err(DecodeError::SetUnionNonLiterals(set1, set2)),
                }
            }

            // Decimal
            [SExpr::Symbol(decimal), SExpr::BitVec(bv)]
                if decimal == "Decimal" && bv.width() == SIXTY_FOUR =>
            {
                Ok(Term::Prim(TermPrim::Ext(Ext::Decimal {
                    d: Decimal(
                        bv.to_int()
                            .try_into()
                            .map_err(|_| DecodeError::UnknownLiteral(self.clone()))?,
                    ),
                })))
            }

            // Datetime
            [SExpr::Symbol(datetime), SExpr::BitVec(bv)]
                if datetime == "Datetime" && bv.width() == SIXTY_FOUR =>
            {
                let dt: i64 = bv
                    .to_int()
                    .try_into()
                    .map_err(|_| DecodeError::IntegerOverflow)?;
                Ok(Term::Prim(TermPrim::Ext(Ext::Datetime { dt: dt.into() })))
            }

            // Duration
            [SExpr::Symbol(duration), SExpr::BitVec(bv)]
                if duration == "Duration" && bv.width() == SIXTY_FOUR =>
            {
                let d: i64 = bv
                    .to_int()
                    .try_into()
                    .map_err(|_| DecodeError::IntegerOverflow)?;
                Ok(Term::Prim(TermPrim::Ext(Ext::Duration { d: d.into() })))
            }

            // IPv4/IPv6
            [SExpr::Symbol(ip), addr, prefix] if (ip == "V4" || ip == "V6") => {
                let addr = match addr.decode_literal(id_maps)? {
                    Term::Prim(TermPrim::Bitvec(bv)) => bv,
                    _ => Err(DecodeError::UnknownLiteral(self.clone()))?,
                };
                let prefix = match prefix.decode_literal(id_maps)? {
                    Term::Some(t) => match Arc::unwrap_or_clone(t) {
                        Term::Prim(TermPrim::Bitvec(bv)) => Some(bv),
                        _ => Err(DecodeError::UnknownLiteral(self.clone()))?,
                    },
                    Term::None(..) => None,
                    _ => Err(DecodeError::UnknownLiteral(self.clone()))?,
                };
                Ok(Term::Prim(TermPrim::Ext(Ext::Ipaddr {
                    ip: if ip == "V4" {
                        IPNet::V4(CIDRv4 {
                            addr: IPv4Addr::try_from_bitvec(addr)
                                .ok_or_else(|| DecodeError::UnknownLiteral(self.clone()))?,
                            prefix: IPv4Prefix::try_from_bitvec(prefix)
                                .ok_or_else(|| DecodeError::UnknownLiteral(self.clone()))?,
                        })
                    } else {
                        IPNet::V6(CIDRv6 {
                            addr: IPv6Addr::try_from_bitvec(addr)
                                .ok_or_else(|| DecodeError::UnknownLiteral(self.clone()))?,
                            prefix: IPv6Prefix::try_from_bitvec(prefix)
                                .ok_or_else(|| DecodeError::UnknownLiteral(self.clone()))?,
                        })
                    },
                })))
            }

            // (_ bvN W) bitvector literals.  Emitted by cvc5 if called with `--bv-print-consts-as-indexed-symbols`.
            [SExpr::Symbol(underscore), SExpr::Symbol(bv_val), SExpr::Numeral(w)]
                if underscore == "_" && bv_val.starts_with("bv") =>
            {
                #[expect(clippy::string_slice, reason = "starts_with guarantees len >= 2")]
                let val_str = &bv_val[2..];
                let val: u128 = val_str.parse().map_err(DecodeError::ParseIntError)?;
                let width = u32::try_from(*w).map_err(|_| DecodeError::IntegerOverflow)?;
                let width = Width::new(width).ok_or(DecodeError::ZeroWidthBitVec)?;
                // Check that `val` fits in declared width. If width is at least 128,
                // then all 128 bit vals must fit.
                if width.get() < 128 && val >= (1u128 << width.get()) {
                    return Err(DecodeError::IntegerOverflow);
                }
                Ok(Term::Prim(TermPrim::Bitvec(BitVec::of_u128(width, val))))
            }

            // Entity UID or record
            [SExpr::Symbol(name), rest_args @ ..] => {
                self.decode_entity_or_record(id_maps, name, rest_args)
            }

            _ => Err(DecodeError::UnknownLiteral(self.clone())),
        }
    }

    /// Decodes a literal (with only SMT constants and no bound variables).
    pub fn decode_literal(&self, id_maps: &IdMaps<'_>) -> Result<Term, DecodeError> {
        self.decode_literal_expecting(id_maps, None)
    }

    /// Decodes a literal term.
    ///
    /// This function accepts an optional expected type which it uses to assign
    /// a type to a `none` expression without explicit type annotation (as is
    /// emitted by Z3), but it does not use this type to do any additional
    /// typechecking.
    fn decode_literal_expecting(
        &self,
        id_maps: &IdMaps<'_>,
        expected_ty: Option<&TermType>,
    ) -> Result<Term, DecodeError> {
        match self {
            SExpr::BitVec(bv) => Ok(Term::Prim(TermPrim::Bitvec(bv.clone()))),
            SExpr::String(s) => Ok(Term::Prim(TermPrim::String(SmolStr::new(s)))),

            SExpr::Symbol(s) if s == "true" => Ok(Term::Prim(TermPrim::Bool(true))),
            SExpr::Symbol(s) if s == "false" => Ok(Term::Prim(TermPrim::Bool(false))),

            // Bare `none` without type annotation (Z3 produces this)
            SExpr::Symbol(s) if s == "none" => match expected_ty {
                Some(TermType::Option { ty }) => Ok(Term::None(ty.as_ref().clone())),
                _ => Err(DecodeError::UnknownLiteral(self.clone())),
            },

            // Empty record type
            SExpr::Symbol(s) if id_maps.types.contains_key(s) => {
                self.decode_entity_or_record(id_maps, s, &[])
            }

            // Entity enum
            SExpr::Symbol(e) => id_maps
                .enums
                .get(e.as_str())
                .cloned()
                .map(|uid| Term::Prim(TermPrim::Entity(uid)))
                .ok_or_else(|| DecodeError::UnknownLiteral(self.clone())),

            // More complex applications
            SExpr::App(args) => self.decode_literal_app(id_maps, args, expected_ty),

            _ => Err(DecodeError::UnknownLiteral(self.clone())),
        }
    }

    /// Decodes a constant definition in the model.
    pub fn decode_var(
        id_maps: &IdMaps<'_>,
        name: &SmolStr,
        typ: &SExpr,
        value: &SExpr,
    ) -> Result<(TermVar, Term), DecodeError> {
        let Some(&term_var) = id_maps.vars.get(name) else {
            return Err(DecodeError::UnknownVariable(name.to_string()));
        };

        let ty = typ.decode_type(id_maps)?;
        let val = value.decode_literal_expecting(id_maps, Some(&ty))?;
        let val_ty = val.type_of();

        if val_ty != ty {
            return Err(DecodeError::UnmatchedType(val_ty, ty));
        }

        if term_var.ty != ty {
            return Err(DecodeError::UnmatchedType(term_var.ty.clone(), ty));
        }

        Ok((term_var.clone(), val))
    }

    /// Decodes a unary function with the forms:
    /// * `(ite (= lit x) <lit> (ite (= <lit> x) default))`
    /// * `(or (= <literal> arg) (= <literal> arg))`
    /// * `(= <lit> arg)`
    ///
    /// TODO: generalize to other forms?
    pub fn decode_unary_function(
        id_maps: &IdMaps<'_>,
        name: &SmolStr,
        arg_name: &str,
        arg_typ: &SExpr,
        ret_typ: &SExpr,
        body: &SExpr,
    ) -> Result<(Uuf, Udf), DecodeError> {
        // First check if the SMT name actually corresponds to a UUF
        let Some(&uuf) = id_maps.uufs.get(name) else {
            return Err(DecodeError::UnknownUUF(name.to_string()));
        };

        // Check that argument type and return type match those of the UUF
        let arg_ty = arg_typ.decode_type(id_maps)?;
        let ret_ty = ret_typ.decode_type(id_maps)?;

        if arg_ty != uuf.arg {
            return Err(DecodeError::UnmatchedType(arg_ty, uuf.arg.clone()));
        }

        if ret_ty != uuf.out {
            return Err(DecodeError::UnmatchedType(ret_ty, uuf.out.clone()));
        }

        if body.is_app_of("or") {
            Self::decode_or_table(uuf, id_maps, arg_name, body)
        } else if body.is_app_of("=") {
            Self::decode_eq_table(uuf, id_maps, arg_name, body)
        } else {
            // `ite` case also handles constant functions without any conditions
            Self::decode_ite_table(uuf, id_maps, arg_name, &ret_ty, body)
        }
    }

    /// Decode UDF table `(ite (= lit x) <lit> (ite (= <lit> x) default))`
    fn decode_ite_table(
        uuf: &Uuf,
        id_maps: &IdMaps<'_>,
        arg_name: &str,
        ret_ty: &TermType,
        body: &SExpr,
    ) -> Result<(Uuf, Udf), DecodeError> {
        // Decode the body as a nested ite term
        let mut table = BTreeMap::new();

        let mut cur_body = body;

        while let Some([cond, then_expr, else_expr]) = cur_body.as_app_n("ite") {
            table.insert(
                Self::decode_eq_operand(arg_name, id_maps, cond)?,
                then_expr.decode_literal_expecting(id_maps, Some(ret_ty))?,
            );
            cur_body = else_expr;
        }

        // Next `App` isn't an `ite`, so decode it as the default value.
        let default = cur_body.decode_literal_expecting(id_maps, Some(ret_ty))?;
        Ok((
            uuf.clone(),
            Udf {
                arg: uuf.arg.clone(),
                out: uuf.out.clone(),
                table: Arc::new(table),
                default,
            },
        ))
    }

    /// Decode UDF table with a disjunction `(or (= <literal> arg) (= <literal> arg))`
    fn decode_or_table(
        uuf: &Uuf,
        id_maps: &IdMaps<'_>,
        arg_name: &str,
        body: &SExpr,
    ) -> Result<(Uuf, Udf), DecodeError> {
        let disjuncts = body
            .as_app("or")
            .ok_or_else(|| DecodeError::UnexpectedUnaryFunctionForm(body.clone()))?;

        let mut table = BTreeMap::new();

        for expr in disjuncts {
            table.insert(
                Self::decode_eq_operand(arg_name, id_maps, expr)?,
                Term::Prim(TermPrim::Bool(true)),
            );
        }

        Ok((
            uuf.clone(),
            Udf {
                arg: uuf.arg.clone(),
                out: uuf.out.clone(),
                table: Arc::new(table),
                default: Term::Prim(TermPrim::Bool(false)),
            },
        ))
    }

    /// Decode UDF table with a single entry `(= <lit> arg)`
    fn decode_eq_table(
        uuf: &Uuf,
        id_maps: &IdMaps<'_>,
        arg_name: &str,
        body: &SExpr,
    ) -> Result<(Uuf, Udf), DecodeError> {
        let cond_lit_term = Self::decode_eq_operand(arg_name, id_maps, body)?;
        Ok((
            uuf.clone(),
            Udf {
                arg: uuf.arg.clone(),
                out: uuf.out.clone(),
                table: Arc::new(BTreeMap::from([(
                    cond_lit_term,
                    Term::Prim(TermPrim::Bool(true)),
                )])),
                default: Term::Prim(TermPrim::Bool(false)),
            },
        ))
    }

    /// Get the literal in an s-expr with the shape `(= <lit> <arg>)` or `(= <arg> <lit>)`
    fn decode_eq_operand(
        arg_name: &str,
        id_maps: &IdMaps<'_>,
        eq: &SExpr,
    ) -> Result<Term, DecodeError> {
        let [lhs, rhs] = eq.as_app_n("=").ok_or(DecodeError::UnexpectedModel)?;

        if rhs.is_symbol(arg_name) {
            lhs
        } else if lhs.is_symbol(arg_name) {
            rhs
        } else {
            return Err(DecodeError::UnexpectedModel);
        }
        .decode_literal(id_maps)
    }

    /// Decodes the output of `(get-model)` to as [`Interpretation`].
    fn decode_model<'a>(
        &self,
        env: &'a SymEnv,
        id_maps: &IdMaps<'_>,
    ) -> Result<Interpretation<'a>, DecodeError> {
        let SExpr::App(cmds) = self else {
            return Err(DecodeError::UnexpectedModel);
        };

        let mut vars = BTreeMap::new();
        let mut funs = BTreeMap::new();

        // TODO: better error handling here
        for cmd in cmds {
            let SExpr::App(sub_exprs) = cmd else {
                return Err(DecodeError::UnexpectedModel);
            };

            // sub_exprs should be of the form
            // "define-fun" <name> (<args>) <ret_type> <body>
            match sub_exprs.as_slice() {
                [SExpr::Symbol(define_fun), SExpr::Symbol(name), SExpr::App(args), ret_ty, body]
                    if define_fun == "define-fun" =>
                {
                    match args.as_slice() {
                        // Decode unary function (skip if not a known UUF)
                        [SExpr::App(arg)] if arg.len() == 2 => match arg.as_slice() {
                            [SExpr::Symbol(arg_name), arg_ty] => {
                                if id_maps.uufs.contains_key(name) {
                                    let (uuf, udf) = Self::decode_unary_function(
                                        id_maps, name, arg_name, arg_ty, ret_ty, body,
                                    )?;
                                    funs.insert(uuf, udf);
                                }
                                // else: skip unknown unary functions (e.g., Z3 intermediate terms)
                            }
                            _ => return Err(DecodeError::UnexpectedModel),
                        },

                        // Decode SMT constant definition as interpretation to a Cedar variable
                        // (skip if not a known variable — Z3 includes define-fun entries
                        // for intermediate terms that aren't declare-const variables)
                        [] => {
                            if id_maps.vars.contains_key(name) {
                                let (term_var, term) =
                                    Self::decode_var(id_maps, name, ret_ty, body)?;
                                vars.insert(term_var, term);
                            }
                        }

                        _ => return Err(DecodeError::UnexpectedModel),
                    }
                }

                _ => return Err(DecodeError::UnexpectedModel),
            }
        }

        Ok(Interpretation { vars, funs, env })
    }
}

/// Decodes the output of `(get-model)` to as [`Interpretation`].
pub fn decode_model<'a>(
    model: &str,
    env: &'a SymEnv,
    id_maps: &IdMaps<'_>,
) -> Result<Interpretation<'a>, DecodeError> {
    let model_sexpr = parse_sexpr(model.as_bytes())?;
    model_sexpr.decode_model(env, id_maps)
}

#[cfg(test)]
mod test_decode {
    use std::{
        collections::BTreeMap,
        num::NonZeroU32,
        str::FromStr,
        sync::{Arc, LazyLock},
    };

    use cedar_policy::{EntityId, EntityTypeName, EntityUid, RequestEnv, Schema};
    use smol_str::SmolStr;

    use cool_asserts::assert_matches;

    use crate::{
        bitvec::BitVec,
        err::Term,
        op::Uuf,
        symcc::decoder::{sexpr::parse_sexpr, DecodeError, IdMaps},
        term::{TermPrim, TermVar},
        term_type::TermType,
        SymEnv,
    };

    static TEST_ENV: LazyLock<SymEnv> = LazyLock::new(|| {
        SymEnv::new(
            &Schema::from_cedarschema_str(
                "entity E; action A appliesTo { principal: [E], resource: [E] };",
            )
            .unwrap()
            .0,
            &RequestEnv::new(
                "E".parse().unwrap(),
                "Action::\"A\"".parse().unwrap(),
                "E".parse().unwrap(),
            ),
        )
        .expect("Malformed sym env.")
    });

    #[track_caller]
    fn assert_decode_var(model: &str, var: SmolStr, ty: TermType, expected: impl Into<Term>) {
        let sexpr = parse_sexpr(model.as_bytes()).expect("failed to parse model sexpr");
        let var = TermVar { id: var, ty };
        let actual = sexpr
            .decode_model(
                &TEST_ENV,
                &IdMaps {
                    types: BTreeMap::new(),
                    vars: BTreeMap::from([(&var.id, &var)]),
                    uufs: BTreeMap::new(),
                    enums: BTreeMap::new(),
                },
            )
            .expect("failed to decode model")
            .vars
            .get(&var)
            .expect("could not find expected var in model")
            .clone();
        assert_eq!(actual, expected.into());
    }

    #[test]
    fn decode_literals() {
        assert_decode_var(
            "((define-fun x () Bool true))",
            "x".into(),
            TermType::Bool,
            true,
        );
        assert_decode_var(
            "((define-fun x () Bool false))",
            "x".into(),
            TermType::Bool,
            false,
        );
        assert_decode_var(
            "((define-fun x () (_ BitVec 2) #b11))",
            "x".into(),
            TermType::Bitvec {
                n: NonZeroU32::new(2).unwrap(),
            },
            BitVec::of_i128(NonZeroU32::new(2).unwrap(), 3),
        );
        assert_decode_var(
            r#"((define-fun x () String "foo"))"#,
            "x".into(),
            TermType::String,
            SmolStr::new_static("foo"),
        );
        // Hex bitvec literal (#xNN)
        assert_decode_var(
            "((define-fun x () (_ BitVec 8) #xFF))",
            "x".into(),
            TermType::Bitvec {
                n: NonZeroU32::new(8).unwrap(),
            },
            BitVec::of_i128(NonZeroU32::new(8).unwrap(), -1),
        );
        // Indexed bitvec literal (_ bvN W)
        assert_decode_var(
            "((define-fun x () (_ BitVec 8) (_ bv42 8)))",
            "x".into(),
            TermType::Bitvec {
                n: NonZeroU32::new(8).unwrap(),
            },
            BitVec::of_u128(NonZeroU32::new(8).unwrap(), 42),
        );
    }

    #[test]
    fn decode_indexed_bv_err() {
        let id_maps = IdMaps {
            types: BTreeMap::new(),
            vars: BTreeMap::new(),
            uufs: BTreeMap::new(),
            enums: BTreeMap::new(),
        };
        assert_matches!(
            parse_sexpr(b"(_ bv0 0)").unwrap().decode_literal(&id_maps),
            Err(DecodeError::ZeroWidthBitVec)
        );
        assert_matches!(
            parse_sexpr(b"(_ bv256 8)")
                .unwrap()
                .decode_literal(&id_maps),
            Err(DecodeError::IntegerOverflow)
        );
    }

    /// Z3 includes `define-fun` entries in its model for intermediate terms
    /// (e.g., terms introduced by `define-fun` in the input), not just
    /// `declare-const` variables. The decoder should skip these unknown
    /// symbols rather than failing with `UnknownVariable`.
    ///
    /// Reproduces the model format seen when using Z3 4.12.5 as the solver:
    /// ```text
    /// (define-fun t0 () E0 (E0 "!0!"))    <-- the actual declare-const var
    /// (define-fun t3 () Bool (not ...))    <-- intermediate, not in IdMaps
    /// (define-fun t1 () E0 (E0 "a"))      <-- intermediate
    /// (define-fun t2 () Bool (= t0 ...))  <-- intermediate
    /// ```
    #[test]
    fn decode_model_skips_unknown_define_funs() {
        // Z3-style model with extra define-funs for intermediate terms.
        // The decoder should skip unknown names and still decode known vars.
        let z3_model = r#"(
            (define-fun t0 () Bool true)
            (define-fun t3 () Bool (not true))
        )"#;
        let sexpr = parse_sexpr(z3_model.as_bytes()).expect("failed to parse");
        let var = TermVar {
            id: "t0".into(),
            ty: TermType::Bool,
        };
        let result = sexpr.decode_model(
            &TEST_ENV,
            &IdMaps {
                types: BTreeMap::new(),
                vars: BTreeMap::from([(&var.id, &var)]), // only t0 in consts
                uufs: BTreeMap::new(),
                enums: BTreeMap::new(),
            },
        );
        let interp = result.expect("decode_model should skip unknown define-funs");
        let val = interp.vars.get(&var).expect("t0 should be in the model");
        assert_eq!(*val, Term::Prim(crate::symcc::term::TermPrim::Bool(true)));
    }

    #[test]
    fn decode_model_skips_unknown_unary_funs() {
        // Z3-style model with an unknown unary function (not in IdMaps.uufs).
        // The decoder should skip it.
        let z3_model = r#"(
            (define-fun t0 () Bool true)
            (define-fun unknown_fn ((x Bool)) Bool (ite (= true x) false true))
        )"#;
        let sexpr = parse_sexpr(z3_model.as_bytes()).expect("failed to parse");
        let var = TermVar {
            id: "t0".into(),
            ty: TermType::Bool,
        };
        let result = sexpr.decode_model(
            &TEST_ENV,
            &IdMaps {
                types: BTreeMap::new(),
                vars: BTreeMap::from([(&var.id, &var)]), // only t0 in consts
                uufs: BTreeMap::new(),
                enums: BTreeMap::new(),
            },
        );
        let interp = result.expect("decode_model should skip unknown unary funs");
        let val = interp.vars.get(&var).expect("t0 should be in the model");
        assert_eq!(*val, Term::Prim(crate::symcc::term::TermPrim::Bool(true)));
    }

    #[test]
    fn decode_application() {
        assert_decode_var(
            "((define-fun x () Bool (not true)))",
            "x".into(),
            TermType::Bool,
            false,
        );
        assert_decode_var(
            "((define-fun x () Bool (not (not true))))",
            "x".into(),
            TermType::Bool,
            true,
        );
        assert_decode_var(
            "((define-fun x () Bool (or false true)))",
            "x".into(),
            TermType::Bool,
            true,
        );
        assert_decode_var(
            "((define-fun x () Bool (= true false)))",
            "x".into(),
            TermType::Bool,
            false,
        );
        assert_decode_var(
            r#"((define-fun x () String (ite false "foo" "bar")))"#,
            "x".into(),
            TermType::String,
            SmolStr::new_static("bar"),
        );
        assert_decode_var(
            "((define-fun x () Bool (bvnego #b10)))",
            "x".into(),
            TermType::Bool,
            true,
        );
        assert_decode_var(
            "((define-fun x () Bool (bvsaddo #b01 #b01)))",
            "x".into(),
            TermType::Bool,
            true,
        );
        assert_decode_var(
            "((define-fun x () Bool (bvsmulo #b010 #b010)))",
            "x".into(),
            TermType::Bool,
            true,
        );
    }

    /// Z3 puts the bound variable on the lhs of `=` in ite-chains (i.e., for a uuf).
    /// `(ite (= x!0 <literal>) ...)` instead of cvc5's `(ite (= <literal> x) ...)`
    #[test]
    fn decode_z3_uuf_arg_on_left() {
        let entity_ty = TermType::Entity {
            ety: EntityTypeName::from_str("E0").unwrap().clone(),
        };
        let record_ty = TermType::Record {
            rty: Arc::new(BTreeMap::from([("admin".into(), TermType::Bool)])),
        };
        let uuf = Uuf {
            id: "attrs".into(),
            arg: entity_ty.clone(),
            out: record_ty.clone(),
        };
        let ety_id: SmolStr = "E0".into();
        let rty_id: SmolStr = "R0".into();
        let uuf_id: SmolStr = "f0".into();
        let id_maps = IdMaps {
            types: BTreeMap::from([(&ety_id, &entity_ty), (&rty_id, &record_ty)]),
            vars: BTreeMap::new(),
            uufs: BTreeMap::from([(&uuf_id, &uuf)]),
            enums: BTreeMap::new(),
        };

        // Z3 model for attrs[E] with two entities having different attrs
        let sexpr = parse_sexpr(
            br#"((define-fun f0 ((x!0 E0)) R0 (ite (= x!0 (E0 "bob")) (R0 false) (R0 true))))"#,
        )
        .unwrap();
        let udf = sexpr
            .decode_model(&TEST_ENV, &id_maps)
            .unwrap()
            .funs
            .remove(&uuf)
            .unwrap();
        let bob_key = Term::Prim(TermPrim::Entity(EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("E0").unwrap(),
            EntityId::new("bob"),
        )));
        let rec = |b| Term::Record(Arc::new(BTreeMap::from([("admin".into(), Term::from(b))])));
        assert_eq!(udf.table.get(&bob_key), Some(&rec(false)));
        assert_eq!(udf.default, rec(true));
    }

    #[test]
    fn decode_bool_uuf_eq() {
        let entity_ty = TermType::Entity {
            ety: EntityTypeName::from_str("E0").unwrap(),
        };
        let uuf = Uuf {
            id: "f".into(),
            arg: entity_ty.clone(),
            out: TermType::Bool,
        };
        let ety_id: SmolStr = "E0".into();
        let uuf_id: SmolStr = "f0".into();
        let id_maps = IdMaps {
            types: BTreeMap::from([(&ety_id, &entity_ty)]),
            vars: BTreeMap::new(),
            uufs: BTreeMap::from([(&uuf_id, &uuf)]),
            enums: BTreeMap::new(),
        };

        let sexpr =
            parse_sexpr(br#"((define-fun f0 ((_arg_1 E0)) Bool (= (E0 "") _arg_1)))"#).unwrap();
        let interp = sexpr
            .decode_model(&TEST_ENV, &id_maps)
            .expect("Bool-codomain UF model with `=` body should decode");
        let udf = interp.funs.get(&uuf).expect("f0 should be in the model");
        let empty_key = Term::Prim(TermPrim::Entity(EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("E0").unwrap(),
            EntityId::new(""),
        )));
        assert_eq!(udf.table.get(&empty_key), Some(&Term::from(true)));
        assert_eq!(udf.default, Term::from(false));
    }

    #[test]
    fn decode_bool_uuf_or() {
        let entity_ty = TermType::Entity {
            ety: EntityTypeName::from_str("E0").unwrap(),
        };
        let uuf = Uuf {
            id: "f".into(),
            arg: entity_ty.clone(),
            out: TermType::Bool,
        };
        let ety_id: SmolStr = "E0".into();
        let uuf_id: SmolStr = "f0".into();
        let id_maps = IdMaps {
            types: BTreeMap::from([(&ety_id, &entity_ty)]),
            vars: BTreeMap::new(),
            uufs: BTreeMap::from([(&uuf_id, &uuf)]),
            enums: BTreeMap::new(),
        };
        let key = |eid: &str| {
            Term::Prim(TermPrim::Entity(EntityUid::from_type_name_and_id(
                EntityTypeName::from_str("E0").unwrap(),
                EntityId::new(eid),
            )))
        };

        let sexpr = parse_sexpr(
            br#"((define-fun f0 ((_arg_1 E0)) Bool (or (= (E0 "a") _arg_1) (= _arg_1 (E0 "b")) (= _arg_1 (E0 "c")))))"#,
        )
        .unwrap();
        let interp = sexpr
            .decode_model(&TEST_ENV, &id_maps)
            .expect("cvc5 Bool-codomain UF model with `or` body should decode");
        let udf = interp.funs.get(&uuf).expect("f0 should be in the model");
        assert_eq!(udf.table.get(&key("a")), Some(&Term::from(true)));
        assert_eq!(udf.table.get(&key("b")), Some(&Term::from(true)));
        assert_eq!(udf.table.get(&key("c")), Some(&Term::from(true)));
        assert_eq!(udf.default, Term::from(false));
    }

    /// Z3 produces bare `none` / `(some val)` without type annotations.
    #[test]
    fn decode_z3_bare_none_and_some() {
        let opt_str = TermType::option_of(TermType::String);
        let rty = TermType::Record {
            rty: Arc::new(BTreeMap::from([("a".into(), opt_str.clone())])),
        };
        let type_id: SmolStr = "R0".into();

        // bare `none` in a record field
        let var = TermVar {
            id: "t0".into(),
            ty: rty.clone(),
        };
        let sexpr = parse_sexpr(b"((define-fun t0 () R0 (R0 none)))").unwrap();
        let interp = sexpr
            .decode_model(
                &TEST_ENV,
                &IdMaps {
                    types: BTreeMap::from([(&type_id, &rty)]),
                    vars: BTreeMap::from([(&var.id, &var)]),
                    uufs: BTreeMap::new(),
                    enums: BTreeMap::new(),
                },
            )
            .expect("bare none in record");
        assert_eq!(
            *interp.vars.get(&var).unwrap(),
            Term::Record(Arc::new(BTreeMap::from([(
                "a".into(),
                Term::None(TermType::String)
            )])))
        );

        // bare `(some "x")` in a record field
        let sexpr = parse_sexpr(br#"((define-fun t0 () R0 (R0 (some "x"))))"#).unwrap();
        let interp = sexpr
            .decode_model(
                &TEST_ENV,
                &IdMaps {
                    types: BTreeMap::from([(&type_id, &rty)]),
                    vars: BTreeMap::from([(&var.id, &var)]),
                    uufs: BTreeMap::new(),
                    enums: BTreeMap::new(),
                },
            )
            .expect("bare some in record");
        assert_eq!(
            *interp.vars.get(&var).unwrap(),
            Term::Record(Arc::new(BTreeMap::from([(
                "a".into(),
                Term::Some(Arc::new(Term::Prim(TermPrim::String("x".into()))))
            )])))
        );

        // bare `none` as a direct constant
        let var2 = TermVar {
            id: "t0".into(),
            ty: opt_str.clone(),
        };
        let sexpr = parse_sexpr(b"((define-fun t0 () (Option String) none))").unwrap();
        let interp = sexpr
            .decode_model(
                &TEST_ENV,
                &IdMaps {
                    types: BTreeMap::new(),
                    vars: BTreeMap::from([(&var2.id, &var2)]),
                    uufs: BTreeMap::new(),
                    enums: BTreeMap::new(),
                },
            )
            .expect("bare none as constant");
        assert_eq!(
            *interp.vars.get(&var2).unwrap(),
            Term::None(TermType::String)
        );
    }
}

#[cfg(test)]
mod test_decode_type_mismatch {
    use std::{collections::BTreeMap, num::NonZeroU32, sync::LazyLock};

    use cedar_policy::{RequestEnv, Schema};
    use cool_asserts::assert_matches;
    use smol_str::SmolStr;

    use crate::{
        op::Uuf,
        symcc::decoder::{sexpr::parse_sexpr, DecodeError, IdMaps},
        term::TermVar,
        term_type::TermType,
        SymEnv,
    };

    static TEST_ENV: LazyLock<SymEnv> = LazyLock::new(|| {
        SymEnv::new(
            &Schema::from_cedarschema_str(
                "entity E; action A appliesTo { principal: [E], resource: [E] };",
            )
            .unwrap()
            .0,
            &RequestEnv::new(
                "E".parse().unwrap(),
                "Action::\"A\"".parse().unwrap(),
                "E".parse().unwrap(),
            ),
        )
        .expect("Malformed sym env.")
    });

    #[test]
    fn env_var_model_mismatch() {
        let var = TermVar {
            id: "x".into(),
            ty: TermType::Bool,
        };
        let sexpr = parse_sexpr(br#"((define-fun x () String "hello"))"#).unwrap();
        let result = sexpr.decode_model(
            &TEST_ENV,
            &IdMaps {
                types: BTreeMap::new(),
                vars: BTreeMap::from([(&var.id, &var)]),
                uufs: BTreeMap::new(),
                enums: BTreeMap::new(),
            },
        );
        assert_matches!(
            result,
            Err(DecodeError::UnmatchedType(TermType::Bool, TermType::String))
        );
    }

    #[test]
    fn env_arg_model_mismatch() {
        let uuf = Uuf {
            id: "f".into(),
            arg: TermType::Bool,
            out: TermType::Bool,
        };
        let uuf_id: SmolStr = "f0".into();
        let sexpr =
            parse_sexpr(br#"((define-fun f0 ((x String)) Bool (ite (= x "a") true false)))"#)
                .unwrap();
        let result = sexpr.decode_model(
            &TEST_ENV,
            &IdMaps {
                types: BTreeMap::new(),
                vars: BTreeMap::new(),
                uufs: BTreeMap::from([(&uuf_id, &uuf)]),
                enums: BTreeMap::new(),
            },
        );
        assert_matches!(
            result,
            Err(DecodeError::UnmatchedType(TermType::String, TermType::Bool))
        );
    }

    #[test]
    fn env_ret_model_mismatch() {
        let uuf = Uuf {
            id: "f".into(),
            arg: TermType::Bool,
            out: TermType::Bool,
        };
        let uuf_id: SmolStr = "f0".into();
        let sexpr = parse_sexpr(br#"((define-fun f0 ((x Bool)) String (ite (= x true) "a" "b")))"#)
            .unwrap();
        let result = sexpr.decode_model(
            &TEST_ENV,
            &IdMaps {
                types: BTreeMap::new(),
                vars: BTreeMap::new(),
                uufs: BTreeMap::from([(&uuf_id, &uuf)]),
                enums: BTreeMap::new(),
            },
        );
        assert_matches!(
            result,
            Err(DecodeError::UnmatchedType(TermType::String, TermType::Bool))
        );
    }

    #[test]
    fn illtyped_model() {
        let var = TermVar {
            id: "x".into(),
            ty: TermType::Bitvec {
                n: NonZeroU32::new(8).unwrap(),
            },
        };
        let sexpr = parse_sexpr(b"((define-fun x () (_ BitVec 8) #b01))").unwrap();
        let result = sexpr.decode_model(
            &TEST_ENV,
            &IdMaps {
                types: BTreeMap::new(),
                vars: BTreeMap::from([(&var.id, &var)]),
                uufs: BTreeMap::new(),
                enums: BTreeMap::new(),
            },
        );
        assert_matches!(
            result,
            Err(DecodeError::UnmatchedType(val_ty, declared_ty))
                if val_ty == TermType::Bitvec { n: NonZeroU32::new(2).unwrap() }
                && declared_ty == TermType::Bitvec { n: NonZeroU32::new(8).unwrap() }
        );
    }

    /// Record constructor with wrong number of fields.
    #[test]
    fn record_field_count_mismatch() {
        use std::sync::Arc;
        let rty = TermType::Record {
            rty: Arc::new(BTreeMap::from([
                ("a".into(), TermType::Bool),
                ("b".into(), TermType::Bool),
            ])),
        };
        let rty_id: SmolStr = "R0".into();
        let var = TermVar {
            id: "x".into(),
            ty: rty.clone(),
        };
        // Record type has 2 fields but we only provide 1 argument
        let sexpr = parse_sexpr(b"((define-fun x () R0 (R0 true)))").unwrap();
        let result = sexpr.decode_model(
            &TEST_ENV,
            &IdMaps {
                types: BTreeMap::from([(&rty_id, &rty)]),
                vars: BTreeMap::from([(&var.id, &var)]),
                uufs: BTreeMap::new(),
                enums: BTreeMap::new(),
            },
        );
        assert_matches!(result, Err(DecodeError::UnmatchedRecordType));
    }

    /// Record field value has wrong type.
    #[test]
    fn record_field_type_mismatch() {
        use std::sync::Arc;
        let rty = TermType::Record {
            rty: Arc::new(BTreeMap::from([("name".into(), TermType::String)])),
        };
        let rty_id: SmolStr = "R0".into();
        let var = TermVar {
            id: "x".into(),
            ty: rty.clone(),
        };
        // Field expects String but gets Bool
        let sexpr = parse_sexpr(b"((define-fun x () R0 (R0 true)))").unwrap();
        let result = sexpr.decode_model(
            &TEST_ENV,
            &IdMaps {
                types: BTreeMap::from([(&rty_id, &rty)]),
                vars: BTreeMap::from([(&var.id, &var)]),
                uufs: BTreeMap::new(),
                enums: BTreeMap::new(),
            },
        );
        assert_matches!(result, Err(DecodeError::UnmatchedFieldType(..)));
    }

    #[test]
    fn entity_non_string_arg() {
        use cedar_policy::EntityTypeName;
        use std::str::FromStr;
        let ety = TermType::Entity {
            ety: EntityTypeName::from_str("E0").unwrap(),
        };
        let ety_id: SmolStr = "E0".into();
        let var = TermVar {
            id: "x".into(),
            ty: ety.clone(),
        };
        // Entity expects (E0 "id") but gets (E0 true)
        let sexpr = parse_sexpr(b"((define-fun x () E0 (E0 true)))").unwrap();
        let result = sexpr.decode_model(
            &TEST_ENV,
            &IdMaps {
                types: BTreeMap::from([(&ety_id, &ety)]),
                vars: BTreeMap::from([(&var.id, &var)]),
                uufs: BTreeMap::new(),
                enums: BTreeMap::new(),
            },
        );
        assert_matches!(result, Err(DecodeError::UnknownLiteral(..)));
    }
}

#[cfg(test)]
mod test_decode_unexpected_model {
    use std::{collections::BTreeMap, sync::LazyLock};

    use cedar_policy::{RequestEnv, Schema};
    use cool_asserts::assert_matches;
    use smol_str::SmolStr;

    use crate::{
        op::Uuf,
        symcc::decoder::{sexpr::parse_sexpr, DecodeError, IdMaps},
        term_type::TermType,
        SymEnv,
    };

    static TEST_ENV: LazyLock<SymEnv> = LazyLock::new(|| {
        SymEnv::new(
            &Schema::from_cedarschema_str(
                "entity E; action A appliesTo { principal: [E], resource: [E] };",
            )
            .unwrap()
            .0,
            &RequestEnv::new(
                "E".parse().unwrap(),
                "Action::\"A\"".parse().unwrap(),
                "E".parse().unwrap(),
            ),
        )
        .expect("Malformed sym env.")
    });

    fn empty_id_maps() -> IdMaps<'static> {
        IdMaps {
            types: BTreeMap::new(),
            vars: BTreeMap::new(),
            uufs: BTreeMap::new(),
            enums: BTreeMap::new(),
        }
    }

    #[rstest::rstest]
    #[case::top_level_not_app(b"true")]
    #[case::command_not_app(b"(42)")]
    #[case::not_define_fun(b"((declare-const x Bool))")]
    #[case::define_fun_too_few_parts(b"((define-fun x () Bool))")]
    #[case::define_fun_name_not_symbol(b"((define-fun 123 () Bool true))")]
    #[case::define_fun_args_not_app(b"((define-fun x foo Bool true))")]
    #[case::multi_arg_function(b"((define-fun f ((x Bool) (y Bool)) Bool true))")]
    fn unexpected_model(#[case] input: &[u8]) {
        let result = parse_sexpr(input)
            .unwrap()
            .decode_model(&TEST_ENV, &empty_id_maps());
        assert_matches!(result, Err(DecodeError::UnexpectedModel));
    }

    /// Unary function arg has wrong form: the inner pair is not [Symbol, type].
    #[test]
    fn unary_fun_arg_not_symbol() {
        let uuf = Uuf {
            id: "f".into(),
            arg: TermType::Bool,
            out: TermType::Bool,
        };
        let uuf_id: SmolStr = "f0".into();
        let sexpr = parse_sexpr(b"((define-fun f0 ((42 Bool)) Bool true))").unwrap();
        let result = sexpr.decode_model(
            &TEST_ENV,
            &IdMaps {
                types: BTreeMap::new(),
                vars: BTreeMap::new(),
                uufs: BTreeMap::from([(&uuf_id, &uuf)]),
                enums: BTreeMap::new(),
            },
        );
        assert_matches!(result, Err(DecodeError::UnexpectedModel));
    }

    #[rstest::rstest]
    #[case::eq_missing_operand(br#"((define-fun f0 ((x E0)) Bool (= x)))"#)]
    #[case::eq_extra_operand(br#"((define-fun f0 ((x E0)) Bool (= (E0 "a") x x)))"#)]
    #[case::ite_missing_else(br#"((define-fun f0 ((x E0)) Bool (ite (= (E0 "a") x) true)))"#)]
    #[case::ite_extra_arg(
        br#"((define-fun f0 ((x E0)) Bool (ite (= (E0 "a") x) true false false)))"#
    )]
    fn malformed_uuf_table(#[case] input: &[u8]) {
        let entity_ty = TermType::Entity {
            ety: "E0".parse().unwrap(),
        };
        let uuf = Uuf {
            id: "f".into(),
            arg: entity_ty.clone(),
            out: TermType::Bool,
        };
        let ety_id: SmolStr = "E0".into();
        let uuf_id: SmolStr = "f0".into();
        let id_maps = IdMaps {
            types: BTreeMap::from([(&ety_id, &entity_ty)]),
            vars: BTreeMap::new(),
            uufs: BTreeMap::from([(&uuf_id, &uuf)]),
            enums: BTreeMap::new(),
        };
        let err = parse_sexpr(input)
            .unwrap()
            .decode_model(&TEST_ENV, &id_maps);
        assert_matches!(
            err,
            Err(DecodeError::UnexpectedModel
                | DecodeError::UnknownLiteral(_)
                | DecodeError::UnexpectedUnaryFunctionForm(_))
        );
    }

    #[test]
    fn unknown_variable() {
        use crate::symcc::decoder::SExpr;
        let name: SmolStr = "unknown".into();
        let typ = SExpr::Symbol("Bool".into());
        let value = SExpr::Symbol("true".into());
        let result = SExpr::decode_var(&empty_id_maps(), &name, &typ, &value);
        assert_matches!(result, Err(DecodeError::UnknownVariable(v)) if v == "unknown");
    }

    #[test]
    fn unknown_uuf() {
        use crate::symcc::decoder::SExpr;
        let name: SmolStr = "unknown_f".into();
        let arg_typ = SExpr::Symbol("Bool".into());
        let ret_typ = SExpr::Symbol("Bool".into());
        let body = SExpr::Symbol("true".into());
        let result =
            SExpr::decode_unary_function(&empty_id_maps(), &name, "x", &arg_typ, &ret_typ, &body);
        assert_matches!(result, Err(DecodeError::UnknownUUF(v)) if v == "unknown_f");
    }
}
