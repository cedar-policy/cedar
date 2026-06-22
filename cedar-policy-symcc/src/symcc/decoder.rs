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
//! that parses a subset of SMT-LIB terms and commands required for `(get-model)`.
//!
//! # Z3 set model encodings
//!
//! Z3 represents finite sets in models using the same array/function-interpretation
//! machinery it uses for `Array` sorts. There is no single Z3 document that
//! enumerates every encoding Z3 may emit; the forms below are those we have
//! observed in solver output and handle (or intentionally reject) in this
//! decoder. For background, see the SMT-LIB [`get-model`] command and Z3's
//! documentation on [models] and [array models].
//!
//! [`get-model`]: https://smt-lib.org/productions-v2.6.html#command_get-model
//! [models]: https://z3prover.github.io/z3guide/docs/concepts/models
//! [array models]: https://z3prover.github.io/z3guide/docs/concepts/models#array-models
//!
//! ## Supported encodings
//!
//! **Existing support** (handled in `decode_literal_app`):
//!
//! - `(as set.empty <set-ty>)`
//! - `(set.singleton <val>)`
//! - `(set.union <set1> <set2>)` when both operands decode to set literals
//!
//! **Added for Z3 array/set models** (routed through `decode_set_array` from
//! `decode_literal_app`):
//!
//! - `((as const (Set <ty>)) <bool>)` — constant membership map; `true` means
//!   "all elements present" and `false` means the empty set
//! - `(store <set-array> <key> <bool>)` — point update on a membership map
//! - `(lambda ((x <ty>)) <body>)` — inline membership function
//! - `(_ as-array k!N)` — reference to a helper `define-fun` (collected as an
//!   auxiliary function before constants are decoded)
//!
//! For the array-based forms, reconstruction works by enumerating candidate
//! elements, evaluating membership at each candidate, and building a finite
//! Cedar `Set`. Boolean element types are enumerated as `{false, true}`; keys
//! introduced by nested `store` applications are also collected as candidates.
//!
//! Lambda and `as-array` bodies are interpreted by `eval_body`, which
//! supports `not`, `=`, `ite`, `and`, `or`, argument references, and literals.
//!
//! ## Intentionally unsupported encodings
//!
//! - Non-finite sets over non-enumerable element types (for example
//!   `((as const (Set String)) true)`) → [`DecodeError::NonFiniteSet`]
//! - Lambda/`as-array` bodies that use other operators (for example `xor`) →
//!   [`DecodeError::UnsupportedSetModel`]
//! - Array/set encodings that do not match the patterns above →
//!   [`DecodeError::UnsupportedSetModel`]
//! - `(set.union ...)` where either operand is not a set literal →
//!   [`DecodeError::SetUnionNonLiterals`]
//!
//! ## Tests
//!
//! Coverage is exercised by `decode_z3_bool_set_models`,
//! `decode_z3_as_array_set_model`, `decode_z3_nonfinite_set_errors`, and
//! `decode_z3_unsupported_set_model_errors` in this module's test suite.

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
    /// Cannot decode this set model as a finite Cedar set.
    ///
    /// Returned when Z3 describes membership with `((as const (Set T)) true)` (or
    /// a `store` chain rooted in such a constant map) and `T` is not enumerable.
    /// Only `Set Bool` can be reconstructed from a constant-`true` membership map.
    #[error("cannot decode a non-finite set model: {0}")]
    NonFiniteSet(SExpr),
    /// Unsupported Z3 set/array model form.
    ///
    /// Returned for array/set encodings that do not match the patterns documented
    /// on this module, including lambda/`as-array` bodies whose operators are not
    /// handled by `eval_body`.
    #[error("unsupported set/array model form: {0}")]
    UnsupportedSetModel(SExpr),
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

/// Z3 may emit helper functions such as `k!0` and refer to them from
/// `(_ as-array k!0)` set models. The tuple is `(arg_name, arg_ty, body)`.
type AuxFuns<'a> = BTreeMap<SmolStr, (SmolStr, &'a SExpr, &'a SExpr)>;

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
        aux_funs: &AuxFuns<'_>,
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
                    let decoded_field =
                        field.decode_literal_expecting(id_maps, aux_funs, Some(field_ty))?;
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

    fn expected_set_element_type(expected_ty: Option<&TermType>) -> Option<TermType> {
        match expected_ty {
            Some(TermType::Set { ty }) => Some(ty.as_ref().clone()),
            _ => None,
        }
    }

    fn decode_as_const_set_type(
        as_const: &[SExpr],
        id_maps: &IdMaps<'_>,
    ) -> Result<Option<TermType>, DecodeError> {
        match as_const {
            [as_tok, const_tok, set_ty]
                if as_tok.is_symbol("as") && const_tok.is_symbol("const") =>
            {
                match set_ty.decode_type(id_maps)? {
                    TermType::Set { ty } => Ok(Some(Arc::unwrap_or_clone(ty))),
                    _ => Err(DecodeError::InvalidSetType(set_ty.clone())),
                }
            }
            _ => Ok(None),
        }
    }

    fn lambda_parts(&self) -> Option<(&SmolStr, &SExpr, &SExpr)> {
        let SExpr::App(args) = self else {
            return None;
        };
        match args.as_slice() {
            [lambda, SExpr::App(binders), body] if lambda.is_symbol("lambda") => {
                match binders.as_slice() {
                    [SExpr::App(binder)] => match binder.as_slice() {
                        [SExpr::Symbol(arg_name), arg_ty] => Some((arg_name, arg_ty, body)),
                        _ => None,
                    },
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn as_array_name(&self) -> Option<&SmolStr> {
        let SExpr::App(args) = self else {
            return None;
        };
        match args.as_slice() {
            [underscore, as_array, SExpr::Symbol(name)]
                if underscore.is_symbol("_") && as_array.is_symbol("as-array") =>
            {
                Some(name)
            }
            _ => None,
        }
    }

    fn store_parts(&self) -> Option<(&SExpr, &SExpr, &SExpr)> {
        let SExpr::App(args) = self else {
            return None;
        };
        match args.as_slice() {
            [store, arr, key, val] if store.is_symbol("store") => Some((arr, key, val)),
            _ => None,
        }
    }

    fn decode_array_element_type(
        &self,
        id_maps: &IdMaps<'_>,
        aux_funs: &AuxFuns<'_>,
        expected_ty: Option<&TermType>,
    ) -> Result<TermType, DecodeError> {
        if let SExpr::App(args) = self {
            if let [SExpr::App(as_const), _] = args.as_slice() {
                if let Some(ty) = Self::decode_as_const_set_type(as_const, id_maps)? {
                    return Ok(ty);
                }
            }
        }

        if let Some((base, _, _)) = self.store_parts() {
            match base.decode_array_element_type(id_maps, aux_funs, None) {
                Ok(ty) => return Ok(ty),
                Err(DecodeError::UnsupportedSetModel(_)) => {}
                Err(err) => return Err(err),
            }
        }

        if let Some((_, arg_ty, _)) = self.lambda_parts() {
            return arg_ty.decode_type(id_maps);
        }

        if let Some(name) = self.as_array_name() {
            let Some((_, arg_ty, _)) = aux_funs.get(name) else {
                return Err(DecodeError::UnsupportedSetModel(self.clone()));
            };
            return arg_ty.decode_type(id_maps);
        }

        if let Some(ty) = Self::expected_set_element_type(expected_ty) {
            return Ok(ty);
        }

        Err(DecodeError::UnsupportedSetModel(self.clone()))
    }

    fn decode_bool_literal(
        expr: &SExpr,
        id_maps: &IdMaps<'_>,
        aux_funs: &AuxFuns<'_>,
    ) -> Result<bool, DecodeError> {
        match expr.decode_literal_expecting(id_maps, aux_funs, Some(&TermType::Bool))? {
            Term::Prim(TermPrim::Bool(b)) => Ok(b),
            _ => Err(DecodeError::UnsupportedSetModel(expr.clone())),
        }
    }

    fn decode_literal_with_type(
        expr: &SExpr,
        id_maps: &IdMaps<'_>,
        aux_funs: &AuxFuns<'_>,
        expected_ty: &TermType,
    ) -> Result<Term, DecodeError> {
        let term = expr.decode_literal_expecting(id_maps, aux_funs, Some(expected_ty))?;
        let term_ty = term.type_of();
        if term_ty != *expected_ty {
            return Err(DecodeError::UnmatchedType(term_ty, expected_ty.clone()));
        }
        Ok(term)
    }

    fn collect_candidates(
        &self,
        id_maps: &IdMaps<'_>,
        aux_funs: &AuxFuns<'_>,
        elem_ty: &TermType,
    ) -> Result<BTreeSet<Term>, DecodeError> {
        if elem_ty == &TermType::Bool {
            return Ok(BTreeSet::from([false.into(), true.into()]));
        }

        if let Some((base, key, _)) = self.store_parts() {
            let mut candidates = base.collect_candidates(id_maps, aux_funs, elem_ty)?;
            candidates.insert(Self::decode_literal_with_type(
                key, id_maps, aux_funs, elem_ty,
            )?);
            return Ok(candidates);
        }

        if let SExpr::App(args) = self {
            if let [SExpr::App(as_const), val] = args.as_slice() {
                if Self::decode_as_const_set_type(as_const, id_maps)?.is_some() {
                    return if Self::decode_bool_literal(val, id_maps, aux_funs)? {
                        Err(DecodeError::NonFiniteSet(self.clone()))
                    } else {
                        Ok(BTreeSet::new())
                    };
                }
            }
        }

        if self.lambda_parts().is_some() || self.as_array_name().is_some() {
            return Err(DecodeError::UnsupportedSetModel(self.clone()));
        }

        Err(DecodeError::UnsupportedSetModel(self.clone()))
    }

    fn eval_body(
        expr: &SExpr,
        id_maps: &IdMaps<'_>,
        aux_funs: &AuxFuns<'_>,
        arg_name: &SmolStr,
        elem: &Term,
    ) -> Result<Term, DecodeError> {
        match expr {
            SExpr::Symbol(sym) if sym == arg_name => Ok(elem.clone()),

            SExpr::App(args) => match args.as_slice() {
                [not_tok, val] if not_tok.is_symbol("not") => Ok(factory::not(Self::eval_body(
                    val, id_maps, aux_funs, arg_name, elem,
                )?)),

                [eq_tok, left, right] if eq_tok.is_symbol("=") => Ok(factory::eq(
                    Self::eval_body(left, id_maps, aux_funs, arg_name, elem)?,
                    Self::eval_body(right, id_maps, aux_funs, arg_name, elem)?,
                )),

                [ite_tok, cond, true_branch, false_branch] if ite_tok.is_symbol("ite") => {
                    Ok(factory::ite(
                        Self::eval_body(cond, id_maps, aux_funs, arg_name, elem)?,
                        Self::eval_body(true_branch, id_maps, aux_funs, arg_name, elem)?,
                        Self::eval_body(false_branch, id_maps, aux_funs, arg_name, elem)?,
                    ))
                }

                [and_tok, vals @ ..] if and_tok.is_symbol("and") => vals
                    .iter()
                    .map(|val| Self::eval_body(val, id_maps, aux_funs, arg_name, elem))
                    .try_fold(true.into(), |acc, val| Ok(factory::and(acc, val?))),

                [or_tok, vals @ ..] if or_tok.is_symbol("or") => vals
                    .iter()
                    .map(|val| Self::eval_body(val, id_maps, aux_funs, arg_name, elem))
                    .try_fold(false.into(), |acc, val| Ok(factory::or(acc, val?))),

                _ => expr
                    .decode_literal_expecting(id_maps, aux_funs, None)
                    .map_err(|_| DecodeError::UnsupportedSetModel(expr.clone())),
            },

            _ => expr
                .decode_literal_expecting(id_maps, aux_funs, None)
                .map_err(|_| DecodeError::UnsupportedSetModel(expr.clone())),
        }
    }

    fn eval_array_at(
        &self,
        id_maps: &IdMaps<'_>,
        aux_funs: &AuxFuns<'_>,
        elem_ty: &TermType,
        elem: &Term,
    ) -> Result<bool, DecodeError> {
        if let SExpr::App(args) = self {
            if let [SExpr::App(as_const), val] = args.as_slice() {
                if Self::decode_as_const_set_type(as_const, id_maps)?.is_some() {
                    return Self::decode_bool_literal(val, id_maps, aux_funs);
                }
            }
        }

        if let Some((base, key, val)) = self.store_parts() {
            let key = Self::decode_literal_with_type(key, id_maps, aux_funs, elem_ty)?;
            return if &key == elem {
                Self::decode_bool_literal(val, id_maps, aux_funs)
            } else {
                base.eval_array_at(id_maps, aux_funs, elem_ty, elem)
            };
        }

        if let Some((arg_name, arg_ty, body)) = self.lambda_parts() {
            let arg_ty = arg_ty.decode_type(id_maps)?;
            if arg_ty != *elem_ty {
                return Err(DecodeError::UnmatchedType(arg_ty, elem_ty.clone()));
            }
            return match Self::eval_body(body, id_maps, aux_funs, arg_name, elem)? {
                Term::Prim(TermPrim::Bool(b)) => Ok(b),
                _ => Err(DecodeError::UnsupportedSetModel(self.clone())),
            };
        }

        if let Some(name) = self.as_array_name() {
            let Some((arg_name, arg_ty, body)) = aux_funs.get(name) else {
                return Err(DecodeError::UnsupportedSetModel(self.clone()));
            };
            let arg_ty = arg_ty.decode_type(id_maps)?;
            if arg_ty != *elem_ty {
                return Err(DecodeError::UnmatchedType(arg_ty, elem_ty.clone()));
            }
            return match Self::eval_body(body, id_maps, aux_funs, arg_name, elem)? {
                Term::Prim(TermPrim::Bool(b)) => Ok(b),
                _ => Err(DecodeError::UnsupportedSetModel(self.clone())),
            };
        }

        Err(DecodeError::UnsupportedSetModel(self.clone()))
    }

    /// Decode Z3 array-based set models into a finite Cedar [`Term::Set`].
    ///
    /// Handles `((as const (Set T)) b)`, `(store ...)`, `(lambda ...)`, and
    /// `(_ as-array k!N)` forms. See the module-level "Z3 set model encodings"
    /// section for the full list of supported and unsupported shapes.
    fn decode_set_array(
        &self,
        id_maps: &IdMaps<'_>,
        aux_funs: &AuxFuns<'_>,
        expected_ty: Option<&TermType>,
    ) -> Result<Term, DecodeError> {
        let elem_ty = self.decode_array_element_type(id_maps, aux_funs, expected_ty)?;
        if let Some(expected_elem_ty) = Self::expected_set_element_type(expected_ty) {
            if elem_ty != expected_elem_ty {
                return Err(DecodeError::UnmatchedType(elem_ty, expected_elem_ty));
            }
        }

        let mut elts = BTreeSet::new();
        for candidate in self.collect_candidates(id_maps, aux_funs, &elem_ty)? {
            if self.eval_array_at(id_maps, aux_funs, &elem_ty, &candidate)? {
                elts.insert(candidate);
            }
        }

        Ok(Term::Set {
            elts: Arc::new(elts),
            elts_ty: elem_ty,
        })
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
        aux_funs: &AuxFuns<'_>,
        args: &[SExpr],
        expected_ty: Option<&TermType>,
    ) -> Result<Term, DecodeError> {
        match args {
            // Sometimes cvc5 does not simplify the terms in the model,
            // and having these custom interpreters alleviates such issues
            // (e.g., https://github.com/cvc5/cvc5/issues/11928).

            // (not <v>)
            [SExpr::Symbol(not_tok), v] if not_tok == "not" => Ok(factory::not(
                v.decode_literal_expecting(id_maps, aux_funs, None)?,
            )),

            // (or <v1> <v2>)
            [SExpr::Symbol(or_tok), v1, v2] if or_tok == "or" => Ok(factory::or(
                v1.decode_literal_expecting(id_maps, aux_funs, None)?,
                v2.decode_literal_expecting(id_maps, aux_funs, None)?,
            )),

            // (= <v1> <v2>)
            [SExpr::Symbol(eq_tok), v1, v2] if eq_tok == "=" => Ok(factory::eq(
                v1.decode_literal_expecting(id_maps, aux_funs, None)?,
                v2.decode_literal_expecting(id_maps, aux_funs, None)?,
            )),

            // (ite <cond> <then> <else>)
            [SExpr::Symbol(ite_tok), cond, true_branch, false_branch] if ite_tok == "ite" => {
                Ok(factory::ite(
                    cond.decode_literal_expecting(id_maps, aux_funs, None)?,
                    true_branch.decode_literal_expecting(id_maps, aux_funs, expected_ty)?,
                    false_branch.decode_literal_expecting(id_maps, aux_funs, expected_ty)?,
                ))
            }

            // (bvnego <v1>)
            [SExpr::Symbol(bvnego_tok), v] if bvnego_tok == "bvnego" => Ok(factory::bvnego(
                v.decode_literal_expecting(id_maps, aux_funs, None)?,
            )),

            // (bvsaddo <v1> <v2>)
            [SExpr::Symbol(bvsaddo_tok), v1, v2] if bvsaddo_tok == "bvsaddo" => {
                Ok(factory::bvsaddo(
                    v1.decode_literal_expecting(id_maps, aux_funs, None)?,
                    v2.decode_literal_expecting(id_maps, aux_funs, None)?,
                ))
            }

            // (bvsmulo <v1> <v2>)
            [SExpr::Symbol(bvsmulo_tok), v1, v2] if bvsmulo_tok == "bvsmulo" => {
                Ok(factory::bvsmulo(
                    v1.decode_literal_expecting(id_maps, aux_funs, None)?,
                    v2.decode_literal_expecting(id_maps, aux_funs, None)?,
                ))
            }

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
                let val = Term::Some(Arc::new(
                    val.decode_literal_expecting(id_maps, aux_funs, inner_ty)?,
                ));
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
                let val = val.decode_literal_expecting(id_maps, aux_funs, inner_ty)?;
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
                let val = val.decode_literal_expecting(id_maps, aux_funs, elt_ty)?;
                let val_ty = val.type_of();
                Ok(Term::Set {
                    elts: Arc::new(BTreeSet::from([val])),
                    elts_ty: val_ty,
                })
            }

            // (set.union <set1> <set2>)
            [SExpr::Symbol(set_union), set1, set2] if set_union == "set.union" => {
                let set1 = set1.decode_literal_expecting(id_maps, aux_funs, expected_ty)?;
                let set2 = set2.decode_literal_expecting(id_maps, aux_funs, expected_ty)?;
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

            // ((as const (Set <ty>)) <bool>)
            [SExpr::App(as_const), _]
                if Self::decode_as_const_set_type(as_const, id_maps)?.is_some() =>
            {
                self.decode_set_array(id_maps, aux_funs, expected_ty)
            }

            // (store <set-array> <key> <bool>)
            [SExpr::Symbol(store), _, _, _] if store == "store" => {
                self.decode_set_array(id_maps, aux_funs, expected_ty)
            }

            // (lambda ((x <ty>)) <body>)
            [SExpr::Symbol(lambda), SExpr::App(_), _] if lambda == "lambda" => {
                self.decode_set_array(id_maps, aux_funs, expected_ty)
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
                let addr = match addr.decode_literal_expecting(id_maps, aux_funs, None)? {
                    Term::Prim(TermPrim::Bitvec(bv)) => bv,
                    _ => Err(DecodeError::UnknownLiteral(self.clone()))?,
                };
                let prefix = match prefix.decode_literal_expecting(id_maps, aux_funs, None)? {
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

            // (_ as-array k!N)
            [SExpr::Symbol(underscore), SExpr::Symbol(as_array), SExpr::Symbol(_)]
                if underscore == "_" && as_array == "as-array" =>
            {
                self.decode_set_array(id_maps, aux_funs, expected_ty)
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
                self.decode_entity_or_record(id_maps, aux_funs, name, rest_args)
            }

            _ => Err(DecodeError::UnknownLiteral(self.clone())),
        }
    }

    /// Decodes a literal (with only SMT constants and no bound variables).
    pub fn decode_literal(&self, id_maps: &IdMaps<'_>) -> Result<Term, DecodeError> {
        self.decode_literal_expecting(id_maps, &BTreeMap::new(), None)
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
        aux_funs: &AuxFuns<'_>,
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
                self.decode_entity_or_record(id_maps, aux_funs, s, &[])
            }

            // Entity enum
            SExpr::Symbol(e) => id_maps
                .enums
                .get(e.as_str())
                .cloned()
                .map(|uid| Term::Prim(TermPrim::Entity(uid)))
                .ok_or_else(|| DecodeError::UnknownLiteral(self.clone())),

            // More complex applications
            SExpr::App(args) => self.decode_literal_app(id_maps, aux_funs, args, expected_ty),

            _ => Err(DecodeError::UnknownLiteral(self.clone())),
        }
    }

    /// Decodes a constant definition in the model.
    pub fn decode_var(
        id_maps: &IdMaps<'_>,
        aux_funs: &AuxFuns<'_>,
        name: &SmolStr,
        typ: &SExpr,
        value: &SExpr,
    ) -> Result<(TermVar, Term), DecodeError> {
        let Some(&term_var) = id_maps.vars.get(name) else {
            return Err(DecodeError::UnknownVariable(name.to_string()));
        };

        let ty = typ.decode_type(id_maps)?;
        let val = value.decode_literal_expecting(id_maps, aux_funs, Some(&ty))?;
        let val_ty = val.type_of();

        if val_ty != ty {
            return Err(DecodeError::UnmatchedType(val_ty, ty));
        }

        if term_var.ty != ty {
            return Err(DecodeError::UnmatchedType(term_var.ty.clone(), ty));
        }

        Ok((term_var.clone(), val))
    }

    /// Decodes a unary function in the form of
    /// `x. ite(<literal> == x, <literal>, ite(<literal> == x, <literal>, ...))`
    ///
    /// TODO: generalize to other forms?
    pub fn decode_unary_function(
        id_maps: &IdMaps<'_>,
        aux_funs: &AuxFuns<'_>,
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

        // Decode the body as a nested ite term
        let mut table = BTreeMap::new();

        let mut cur_body = body;

        loop {
            // Check if the body is of the form
            // (ite (= <literal> <arg_name>) <literal> <else>)
            // or
            // (ite (= <arg_name> <literal>) <literal> <else>)
            if let SExpr::App(exprs) = cur_body {
                #[expect(
                    clippy::indexing_slicing,
                    reason = "Slice of length 4 can be indexed by 0-3"
                )]
                if exprs.len() == 4 && exprs[0].is_symbol("ite") {
                    if let SExpr::App(args) = &exprs[1] {
                        if args.len() == 3 && args[0].is_symbol("=") {
                            // Find the literal the `ite` compares the argument against.
                            // This could be either the first or second `=` operand,
                            // depending on the solver.
                            let cond_lit_term = if args[2].is_symbol(arg_name) {
                                &args[1]
                            } else if args[1].is_symbol(arg_name) {
                                &args[2]
                            } else {
                                return Err(DecodeError::UnexpectedUnaryFunctionForm(body.clone()));
                            }
                            .decode_literal_expecting(id_maps, aux_funs, None)?;
                            let then_term = exprs[2].decode_literal_expecting(
                                id_maps,
                                aux_funs,
                                Some(&ret_ty),
                            )?;
                            table.insert(cond_lit_term, then_term);
                            cur_body = &exprs[3];
                            continue;
                        }
                    }
                }
            }

            // otherwise take as the default value
            // assuming it doesn't contain any bound variables
            let default = cur_body.decode_literal_expecting(id_maps, aux_funs, Some(&ret_ty))?;

            return Ok((
                uuf.clone(),
                Udf {
                    arg: uuf.arg.clone(),
                    out: uuf.out.clone(),
                    table: Arc::new(table),
                    default,
                },
            ));
        }
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
        let mut aux_funs = BTreeMap::new();

        // Z3 may emit helper functions (for example `k!0`) that are referenced
        // by `(_ as-array k!0)` set models. Collect their bodies before decoding
        // constants that may contain as-array references.
        for cmd in cmds {
            let SExpr::App(sub_exprs) = cmd else {
                return Err(DecodeError::UnexpectedModel);
            };

            match sub_exprs.as_slice() {
                [SExpr::Symbol(define_fun), SExpr::Symbol(name), SExpr::App(args), _ret_ty, body]
                    if define_fun == "define-fun" =>
                {
                    match args.as_slice() {
                        [SExpr::App(arg)] if arg.len() == 2 => match arg.as_slice() {
                            [SExpr::Symbol(arg_name), arg_ty] => {
                                aux_funs.insert(name.clone(), (arg_name.clone(), arg_ty, body));
                            }
                            _ => return Err(DecodeError::UnexpectedModel),
                        },
                        [] => {}
                        _ => return Err(DecodeError::UnexpectedModel),
                    }
                }

                _ => return Err(DecodeError::UnexpectedModel),
            }
        }

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
                                        id_maps, &aux_funs, name, arg_name, arg_ty, ret_ty, body,
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
                                    Self::decode_var(id_maps, &aux_funs, name, ret_ty, body)?;
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
        collections::{BTreeMap, BTreeSet},
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

    fn bool_set(elts: impl IntoIterator<Item = bool>) -> Term {
        Term::Set {
            elts: Arc::new(elts.into_iter().map(Term::from).collect::<BTreeSet<_>>()),
            elts_ty: TermType::Bool,
        }
    }

    fn string_set_var() -> TermVar {
        TermVar {
            id: "x".into(),
            ty: TermType::set_of(TermType::String),
        }
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
    fn decode_z3_bool_set_models() {
        assert_decode_var(
            "((define-fun x () (Set Bool) ((as const (Set Bool)) true)))",
            "x".into(),
            TermType::set_of(TermType::Bool),
            bool_set([false, true]),
        );
        assert_decode_var(
            "((define-fun x () (Set Bool) ((as const (Set Bool)) false)))",
            "x".into(),
            TermType::set_of(TermType::Bool),
            bool_set([]),
        );
        assert_decode_var(
            "((define-fun x () (Set Bool) (store ((as const (Set Bool)) true) true false)))",
            "x".into(),
            TermType::set_of(TermType::Bool),
            bool_set([false]),
        );
        assert_decode_var(
            "((define-fun x () (Set Bool) (lambda ((x!1 Bool)) x!1)))",
            "x".into(),
            TermType::set_of(TermType::Bool),
            bool_set([true]),
        );
        assert_decode_var(
            "((define-fun x () (Set Bool) (lambda ((x!0 Bool)) (ite (= x!0 true) false true))))",
            "x".into(),
            TermType::set_of(TermType::Bool),
            bool_set([false]),
        );
    }

    #[test]
    fn decode_z3_as_array_set_model() {
        assert_decode_var(
            r#"(
                (define-fun k!0 ((x Bool)) Bool x)
                (define-fun x () (Set Bool) (_ as-array k!0))
            )"#,
            "x".into(),
            TermType::set_of(TermType::Bool),
            bool_set([true]),
        );
    }

    #[test]
    fn decode_z3_nonfinite_set_errors() {
        let var = string_set_var();
        let id_maps = IdMaps {
            types: BTreeMap::new(),
            vars: BTreeMap::from([(&var.id, &var)]),
            uufs: BTreeMap::new(),
            enums: BTreeMap::new(),
        };

        let const_true =
            parse_sexpr(b"((define-fun x () (Set String) ((as const (Set String)) true)))")
                .unwrap();
        assert_matches!(
            const_true.decode_model(&TEST_ENV, &id_maps),
            Err(DecodeError::NonFiniteSet(_))
        );

        let store_over_const_true = parse_sexpr(
            br#"((define-fun x () (Set String) (store ((as const (Set String)) true) "a" false)))"#,
        )
        .unwrap();
        assert_matches!(
            store_over_const_true.decode_model(&TEST_ENV, &id_maps),
            Err(DecodeError::NonFiniteSet(_))
        );
    }

    #[test]
    fn decode_z3_unsupported_set_model_errors() {
        let var = TermVar {
            id: "x".into(),
            ty: TermType::set_of(TermType::Bool),
        };
        let id_maps = IdMaps {
            types: BTreeMap::new(),
            vars: BTreeMap::from([(&var.id, &var)]),
            uufs: BTreeMap::new(),
            enums: BTreeMap::new(),
        };

        let unsupported_lambda =
            parse_sexpr(b"((define-fun x () (Set Bool) (lambda ((x!0 Bool)) (xor x!0 true))))")
                .unwrap();
        assert_matches!(
            unsupported_lambda.decode_model(&TEST_ENV, &id_maps),
            Err(DecodeError::UnsupportedSetModel(_))
        );

        let unsupported_as_array = parse_sexpr(
            b"((define-fun k!0 ((x Bool)) Bool (xor x true)) (define-fun x () (Set Bool) (_ as-array k!0)))",
        )
        .unwrap();
        assert_matches!(
            unsupported_as_array.decode_model(&TEST_ENV, &id_maps),
            Err(DecodeError::UnsupportedSetModel(_))
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

    #[test]
    fn unknown_variable() {
        use crate::symcc::decoder::SExpr;
        let name: SmolStr = "unknown".into();
        let typ = SExpr::Symbol("Bool".into());
        let value = SExpr::Symbol("true".into());
        let result = SExpr::decode_var(&empty_id_maps(), &BTreeMap::new(), &name, &typ, &value);
        assert_matches!(result, Err(DecodeError::UnknownVariable(v)) if v == "unknown");
    }

    #[test]
    fn unknown_uuf() {
        use crate::symcc::decoder::SExpr;
        let name: SmolStr = "unknown_f".into();
        let arg_typ = SExpr::Symbol("Bool".into());
        let ret_typ = SExpr::Symbol("Bool".into());
        let body = SExpr::Symbol("true".into());
        let result = SExpr::decode_unary_function(
            &empty_id_maps(),
            &BTreeMap::new(),
            &name,
            "x",
            &arg_typ,
            &ret_typ,
            &body,
        );
        assert_matches!(result, Err(DecodeError::UnknownUUF(v)) if v == "unknown_f");
    }
}
