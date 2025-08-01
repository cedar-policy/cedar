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

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Display;
use std::io;
use std::sync::Arc;

use cedar_policy::{EntityId, EntityUid};
use itertools::Itertools;
use num_bigint::BigUint;

use thiserror::Error;

use crate::symcc::env::SymEntityData;
use crate::symcc::extension_types::ipaddr::{
    CIDRv4, CIDRv6, IPv4Addr, IPv4Prefix, IPv6Addr, IPv6Prefix,
};
use crate::symcc::term::TermX;
use crate::symcc::type_abbrevs::{ExtType, Width};
use crate::{symcc, SymEnv};

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

#[derive(Debug, Error)]
pub enum DecodeError {
    /// IO error
    #[error("IO error during decoding: {0}")]
    Io(#[from] io::Error),

    #[error("Unexpected end of input")]
    UnexpectedEnd,

    #[error("Invalid UTF-8 sequence: {0}")]
    UTF8Error(#[from] std::string::FromUtf8Error),

    #[error("Invalid numeric token: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Right parenthesis without left parenthesis")]
    RightParenWithoutLeftParen,

    #[error("Trailing tokens")]
    TrailingTokens,

    #[error("Model of unexpected form returned by the solver")]
    UnexpectedModel,

    #[error("Unknown type: {0}")]
    UnknownType(SExpr),

    #[error("Unknown literal: {0}")]
    UnknownLiteral(SExpr),

    #[error("Unmatched type: expected {0:?}, found {1:?}")]
    UnmatchedType(TermType, TermType),

    #[error("Unmatched field type: expected {0:?}, found {1:?}")]
    UnmatchedFieldType(TermType, TermType),

    #[error("Invalid set type: {0}")]
    InvalidSetType(SExpr),

    #[error("Invalid option type: {0}")]
    InvalidOptionType(SExpr),

    #[error("set.union applied to non-literals {0:?} and {1:?}")]
    SetUnionNonLiterals(Term, Term),

    #[error("Unmatched record type fields")]
    UnmatchedRecordType,

    #[error("Unknown variable: {0}")]
    UnknownVariable(String),

    #[error("Unknown unary function: {0}")]
    UnknownUUF(String),

    #[error("Unexpected unary function form: {0}")]
    UnexpectedUnaryFunctionForm(SExpr),

    #[error("Unexpected symcc result error: {0}.")]
    UnexpectedSymccResult(#[from] symcc::result::Error),
}

/// Types of tokens
#[derive(Debug)]
enum Token {
    LeftParen,
    RightParen,
    Atom(SExpr),
}

/// S-expressions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SExpr {
    BitVec(BitVec),
    Numeral(u128),
    String(String),
    Symbol(String),
    App(Vec<SExpr>),
}

/// Tokenizes a string of SMT-LIB 2 S-expressions
/// Reference: https://smtlib.github.io/jSMTLIB/SMTLIBTutorial.pdf, Table 3.1
fn tokenize(src: &[u8]) -> Result<Vec<Token>, DecodeError> {
    let mut i = 0;

    let mut in_str = false;
    let mut str_start = 0;

    let mut tokens = Vec::new();

    while i < src.len() {
        // PANIC SAFETY
        #[allow(
            clippy::indexing_slicing,
            reason = "i < src.len() thus indexing by i should not panic"
        )]
        let c = src[i];

        if in_str {
            match c {
                b'"' => {
                    // PANIC SAFETY
                    #[allow(
                        clippy::indexing_slicing,
                        reason = "i + 1 < src.len() thus indexing by i + 1 should not panic"
                    )]
                    if i + 1 < src.len() && src[i + 1] == b'"' {
                        // Two double quotes ("") is an escape sequence
                        // or a single double quote (") per SMT-LIB 2 spec
                        i += 2;
                    } else {
                        // String is terminated
                        // PANIC SAFETY
                        #[allow(
                            clippy::indexing_slicing,
                            reason = "invariant str_start <= i and i <= src.len() thus slicing should not panic"
                        )]
                        tokens.push(Token::Atom(SExpr::String(
                            String::from_utf8(src[str_start..i].to_vec())?.replace("\"\"", "\""),
                        )));
                        in_str = false;
                        i += 1;
                    }
                }

                _ => i += 1,
            }
        } else {
            match c {
                b'"' => {
                    in_str = true;
                    str_start = i + 1;
                    i += 1;
                }

                b'(' => {
                    tokens.push(Token::LeftParen);
                    i += 1;
                }

                b')' => {
                    tokens.push(Token::RightParen);
                    i += 1;
                }

                // Bit vector
                b'#' => {
                    if i + 1 < src.len() {
                        // PANIC SAFETY
                        #[allow(
                            clippy::indexing_slicing,
                            reason = "i + 1 < src.len() thus indexing by i + 1 should not panic"
                        )]
                        match src[i + 1] {
                            // Binary representation
                            b'b' => {
                                // Read until a non-0 and non-1 character
                                i += 2;
                                let start = i;
                                // PANIC SAFETY
                                #[allow(
                                    clippy::indexing_slicing,
                                    reason = "i < src.len() thus indexing by i should not panic"
                                )]
                                while i < src.len() && (src[i] == b'0' || src[i] == b'1') {
                                    i += 1;
                                }

                                let width: usize = i - start;
                                // PANIC SAFETY
                                #[allow(
                                    clippy::indexing_slicing,
                                    reason = "start <= i <= src.len() thus slicing should not panic"
                                )]
                                let num = String::from_utf8(src[start..i].to_vec())?;
                                let num = u128::from_str_radix(&num, 2)?;

                                // Do a sign-extension from i<width> to i<128>
                                let num =
                                    if width != 0 && width < 128 && (1u128 << width - 1) & num != 0
                                    {
                                        ((u128::MAX << width) | num) as i128
                                    } else {
                                        num as i128
                                    };

                                tokens.push(Token::Atom(SExpr::BitVec(
                                    BitVec::of_int(width as Width, num.into())
                                        .map_err(DecodeError::UnexpectedSymccResult)?,
                                )));
                            }

                            // TODO: support #x...
                            _ => return Err(DecodeError::UnexpectedEnd),
                        }
                    } else {
                        return Err(DecodeError::UnexpectedEnd);
                    }
                }

                // Numeral
                c if c.is_ascii_digit() => {
                    // Read until a non-digit
                    let start = i;
                    // PANIC SAFETY
                    #[allow(
                        clippy::indexing_slicing,
                        reason = "i < src.len() thus indexing by i should not panic"
                    )]
                    while i < src.len() && src[i].is_ascii_digit() {
                        i += 1;
                    }

                    // PANIC SAFETY
                    #[allow(
                        clippy::indexing_slicing,
                        reason = "start <= i <= src.len() ===> slicing should not panic"
                    )]
                    let num = String::from_utf8(src[start..i].to_vec())?;
                    let num = num.parse::<u128>()?;

                    tokens.push(Token::Atom(SExpr::Numeral(num)));
                }

                // Comment
                b';' => {
                    // PANIC SAFETY
                    #[allow(
                        clippy::indexing_slicing,
                        reason = "i < src.len() thus indexing src by i should not panic"
                    )]
                    while i < src.len() && src[i] != b'\n' {
                        i += 1;
                    }
                }

                c if c.is_ascii_whitespace() => i += 1,

                // Symbol
                // TODO: this doesn't quite align with the SMT-LIB 2 spec
                // e.g. we don't allow whitespaces in quoted symbols
                // but it should suffice for (get-model)
                _ => {
                    // Take until (, ), or whitespace
                    let start = i;
                    // PANIC SAFETY
                    #[allow(
                        clippy::indexing_slicing,
                        reason = "i < src.len() thus indexing by I should not panic"
                    )]
                    while i < src.len()
                        && src[i] != b'('
                        && src[i] != b')'
                        && src[i] != b';'
                        && src[i] != b'"'
                        && src[i] != b'#'
                        && !src[i].is_ascii_whitespace()
                    {
                        i += 1;
                    }
                    // PANIC SAFETY
                    #[allow(
                        clippy::indexing_slicing,
                        reason = "start <= i and i <= src.len ==> slicing should not panic"
                    )]
                    let symbol = String::from_utf8(src[start..i].to_vec())?;

                    tokens.push(Token::Atom(SExpr::Symbol(symbol)));
                }
            }
        }
    }

    if in_str {
        return Err(DecodeError::UnexpectedEnd);
    }

    Ok(tokens)
}

/// Parses the input source as an S-expression
pub fn parse_sexpr(src: &[u8]) -> Result<SExpr, DecodeError> {
    let mut stack = VecDeque::new();

    let tokens = tokenize(src)?;
    let token_count = tokens.len();

    for (i, token) in tokens.into_iter().enumerate() {
        match token {
            Token::LeftParen => stack.push_back(Vec::new()),
            Token::RightParen => {
                let Some(exprs) = stack.pop_back() else {
                    return Err(DecodeError::RightParenWithoutLeftParen);
                };

                if let Some(last) = stack.back_mut() {
                    last.push(SExpr::App(exprs));
                } else {
                    // Succeed if there is no trailing tokens
                    if i + 1 == token_count {
                        return Ok(SExpr::App(exprs));
                    } else {
                        return Err(DecodeError::TrailingTokens);
                    }
                }
            }
            Token::Atom(s) => {
                if let Some(last) = stack.back_mut() {
                    last.push(s);
                } else {
                    // Succeed if there is no trailing tokens
                    if i + 1 == token_count {
                        return Ok(s);
                    } else {
                        return Err(DecodeError::TrailingTokens);
                    }
                }
            }
        }
    }

    Err(DecodeError::UnexpectedEnd)
}

/// Maps from SMT symbols their corresponding variables
/// (principal, action, resource) and entity types.
#[derive(Debug)]
pub struct IdMaps {
    types: BTreeMap<String, TermType>,
    vars: BTreeMap<String, TermVar>,
    uufs: BTreeMap<String, Uuf>,
    enums: BTreeMap<String, EntityUid>,
}

impl IdMaps {
    /// Extracts the reverse mapping from SMT symbols to
    /// Term-level names from the encoder state.
    pub fn from_encoder<S>(encoder: &Encoder<'_, S>) -> Self {
        let mut types = BTreeMap::new();
        let mut vars = BTreeMap::new();
        let mut uufs = BTreeMap::new();
        let mut enums = BTreeMap::new();

        for (term, enc) in &encoder.types {
            types.insert(enc.clone(), term.clone());
        }

        for (term, enc) in &encoder.terms {
            if let TermX::Var(var) = term.as_ref() {
                vars.insert(enc.clone(), var.clone());
            }
        }

        for (uuf, id) in &encoder.uufs {
            uufs.insert(id.clone(), uuf.clone());
        }

        for (&entity_type, &enum_ids) in &encoder.enums {
            for (i, enum_id) in enum_ids.iter().enumerate() {
                let uid =
                    EntityUid::from_type_name_and_id(entity_type.clone(), EntityId::new(enum_id));

                if let Some(entity_type_id) = encoder.types.get(&TermType::Entity {
                    ety: entity_type.clone(),
                }) {
                    enums.insert(super::encoder::enum_id(entity_type_id, i), uid);
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
            TermType::Bool => TermX::Prim(TermPrim::Bool(false)).into(),
            TermType::Bitvec { n } =>
            {
                #[allow(
                    clippy::unwrap_used,
                    reason = "Assume the bit-vectors have the same width by construction for now."
                )]
                TermX::Prim(TermPrim::Bitvec(BitVec::of_nat(*n, BigUint::ZERO).unwrap())).into()
            }
            TermType::String => TermX::Prim(TermPrim::String("".to_string())).into(),

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
                TermX::Prim(TermPrim::Entity(EntityUid::from_type_name_and_id(
                    ety.clone(),
                    EntityId::new(eid),
                ))).into()
            }

            TermType::Ext { xty } => match xty {
                ExtType::Decimal => TermX::Prim(TermPrim::Ext(Ext::Decimal { d: Decimal(0) })).into(),

                ExtType::DateTime => TermX::Prim(TermPrim::Ext(Ext::Datetime {
                    dt: Datetime::default(),
                })).into(),

                ExtType::Duration => TermX::Prim(TermPrim::Ext(Ext::Duration {
                    d: Duration::default(),
                })).into(),

                ExtType::IpAddr => TermX::Prim(TermPrim::Ext(Ext::Ipaddr {
                    ip: IPNet::default(),
                })).into(),
            },

            TermType::Option { ty } => TermX::None(ty.as_ref().clone()).into(),

            TermType::Set { ty } => TermX::Set {
                elts: BTreeSet::new(),
                elts_ty: ty.as_ref().clone(),
            }.into(),

            TermType::Record { rty } => TermX::Record(
                rty.iter()
                    .map(|(k, v)| (k.clone(), v.default_literal(env)))
                    .collect(),
            ).into(),
        }
    }
}

impl Uuf {
    /// Similar to [`TermType::default_literal`], but for [`Uuf`].
    pub fn default_udf(&self, env: &SymEnv) -> Udf {
        Udf {
            arg: self.arg.clone(),
            out: self.out.clone(),
            table: BTreeMap::new(),
            default: self.out.default_literal(env),
        }
    }
}

impl SExpr {
    /// Checks if the [`SExpr`] is a symbol.
    fn is_symbol(&self, s: &str) -> bool {
        match self {
            SExpr::Symbol(sym) => sym == s,
            _ => false,
        }
    }

    /// Decodes [`TermType`] from an [`SExpr`].
    pub fn decode_type(&self, id_maps: &IdMaps) -> Result<TermType, DecodeError> {
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
                        Ok(TermType::Bitvec { n: *n as Width })
                    } // TODO: overflow?

                    // (Option x)
                    [SExpr::Symbol(option), param] if option == "Option" => {
                        let ty = param.decode_type(id_maps)?;
                        Ok(TermType::Option { ty: Arc::new(ty) })
                    }

                    // (Set x)
                    [SExpr::Symbol(set), param] if set == "Set" => {
                        let ty = param.decode_type(id_maps)?;
                        Ok(TermType::Set { ty: Arc::new(ty) })
                    }

                    _ => Err(DecodeError::UnknownType(self.clone())),
                }
            }

            _ => Err(DecodeError::UnknownType(self.clone())),
        }
    }

    /// Decodse a literal (with only SMT constants and no bound variables).
    pub fn decode_literal(&self, id_maps: &IdMaps) -> Result<Term, DecodeError> {
        match self {
            SExpr::BitVec(bv) => Ok(TermX::Prim(TermPrim::Bitvec(bv.clone())).into()),
            SExpr::String(s) => Ok(TermX::Prim(TermPrim::String(s.clone())).into()),

            SExpr::Symbol(s) if s == "true" => Ok(TermX::Prim(TermPrim::Bool(true)).into()),
            SExpr::Symbol(s) if s == "false" => Ok(TermX::Prim(TermPrim::Bool(false)).into()),

            // Entity enum
            SExpr::Symbol(e) => id_maps
                .enums
                .get(e)
                .cloned()
                .map(|uid| TermX::Prim(TermPrim::Entity(uid)).into())
                .ok_or_else(|| DecodeError::UnknownLiteral(self.clone())),

            // More complex applications
            SExpr::App(args) => {
                match args.as_slice() {
                    // Sometimes cvc5 does not simplify the terms in the model
                    // having these custom interpreters alleviates such issues
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
                    [SExpr::Symbol(ite_tok), cond, true_branch, false_branch]
                        if ite_tok == "ite" =>
                    {
                        Ok(factory::ite(
                            cond.decode_literal(id_maps)?,
                            true_branch.decode_literal(id_maps)?,
                            false_branch.decode_literal(id_maps)?,
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
                            TermType::Option { ty } => Ok(TermX::None(Arc::unwrap_or_clone(ty)).into()),
                            _ => Err(DecodeError::InvalidOptionType(typ.clone())),
                        }
                    }

                    // ((as some <typ>) <val>)
                    // PANIC SAFETY
                    #[allow(
                        clippy::indexing_slicing,
                        reason = "Slice of length 3 can be indexed by 0-2"
                    )]
                    [SExpr::App(as_some_typ), val]
                        if as_some_typ.len() == 3
                            && as_some_typ[0].is_symbol("as")
                            && as_some_typ[1].is_symbol("some") =>
                    {
                        let ty = as_some_typ[2].decode_type(id_maps)?;
                        let val = Term::new(TermX::Some(val.decode_literal(id_maps)?));
                        let val_ty = val.type_of();

                        if val_ty != ty {
                            return Err(DecodeError::UnmatchedType(val_ty, ty));
                        }

                        Ok(val)
                    }

                    // (as set.empty <set_typ>)
                    [SExpr::Symbol(as_tok), SExpr::Symbol(set_empty), typ]
                        if as_tok == "as" && set_empty == "set.empty" =>
                    {
                        let ty = typ.decode_type(id_maps)?;

                        match ty {
                            TermType::Set { ty } => Ok(TermX::Set {
                                elts: BTreeSet::new(),
                                elts_ty: Arc::unwrap_or_clone(ty),
                            }.into()),
                            _ => Err(DecodeError::InvalidSetType(typ.clone())),
                        }
                    }

                    // (set.singleton <val>)
                    [SExpr::Symbol(set_singleton), val] if set_singleton == "set.singleton" => {
                        let val = val.decode_literal(id_maps)?;
                        let val_ty = val.type_of();
                        Ok(TermX::Set {
                            elts: BTreeSet::from([val]),
                            elts_ty: val_ty,
                        }.into())
                    }

                    // (set.union <set1> <set2>)
                    [SExpr::Symbol(set_union), set1, set2] if set_union == "set.union" => {
                        let set1 = set1.decode_literal(id_maps)?;
                        let set2 = set2.decode_literal(id_maps)?;
                        let set1_ty = set1.type_of();
                        let set2_ty = set2.type_of();

                        if set1_ty != set2_ty {
                            return Err(DecodeError::UnmatchedType(set1_ty, set2_ty));
                        }

                        match (set1.to_owned(), set2.to_owned()) {
                            // Merge two set literals
                            (
                                TermX::Set {
                                    elts: elts1,
                                    elts_ty,
                                },
                                TermX::Set { elts: elts2, .. },
                            ) => Ok(TermX::Set {
                                elts: elts1.union(&elts2).cloned().collect(),
                                elts_ty,
                            }.into()),

                            (set1, set2) => Err(DecodeError::SetUnionNonLiterals(set1.into(), set2.into())),
                        }
                    }
                    // PANIC SAFETY
                    #[allow(
                        clippy::indexing_slicing,
                        reason = "Non-empty slice can be indexed by 0"
                    )]
                    args if !args.is_empty() && matches!(args[0], SExpr::Symbol(_)) => {
                        match &args[0] {
                            // Decimal
                            SExpr::Symbol(s) if s == "Decimal" && args.len() == 2 => {
                                if let SExpr::BitVec(bv) = &args[1] {
                                    if bv.width() == 64 {
                                        Ok(TermX::Prim(TermPrim::Ext(Ext::Decimal {
                                            d: Decimal(bv.to_int().try_into().or(Err(
                                                DecodeError::UnknownLiteral(self.clone()),
                                            ))?),
                                        })).into())
                                    } else {
                                        Err(DecodeError::UnknownLiteral(self.clone()))
                                    }
                                } else {
                                    Err(DecodeError::UnknownLiteral(self.clone()))
                                }
                            }

                            // Datetime
                            SExpr::Symbol(s) if s == "Datetime" && args.len() == 2 => {
                                if let SExpr::BitVec(bv) = &args[1] {
                                    if bv.width() == 64 {
                                        let dt: i128 = bv
                                            .to_int()
                                            .try_into()
                                            .or(Err(DecodeError::UnknownLiteral(self.clone())))?;
                                        Ok(TermX::Prim(TermPrim::Ext(Ext::Datetime {
                                            dt: dt.into(),
                                        })).into())
                                    } else {
                                        Err(DecodeError::UnknownLiteral(self.clone()))
                                    }
                                } else {
                                    Err(DecodeError::UnknownLiteral(self.clone()))
                                }
                            }

                            // Duration
                            SExpr::Symbol(s) if s == "Duration" && args.len() == 2 => {
                                if let SExpr::BitVec(bv) = &args[1] {
                                    if bv.width() == 64 {
                                        let d: i128 = bv
                                            .to_int()
                                            .try_into()
                                            .or(Err(DecodeError::UnknownLiteral(self.clone())))?;
                                        Ok(TermX::Prim(TermPrim::Ext(Ext::Duration { d: d.into() })).into())
                                    } else {
                                        Err(DecodeError::UnknownLiteral(self.clone()))
                                    }
                                } else {
                                    Err(DecodeError::UnknownLiteral(self.clone()))
                                }
                            }

                            // IPv4/IPv6
                            SExpr::Symbol(s) if (s == "V4" || s == "V6") && args.len() == 3 => {
                                let addr = args[1].decode_literal(id_maps)?;
                                let prefix = args[2].decode_literal(id_maps)?;

                                let addr = match addr.to_owned() {
                                    TermX::Prim(TermPrim::Bitvec(bv)) => bv,
                                    _ => Err(DecodeError::UnknownLiteral(self.clone()))?,
                                };
                                let prefix = match prefix.to_owned() {
                                    TermX::Some(t) => match t.to_owned() {
                                        TermX::Prim(TermPrim::Bitvec(bv)) => Some(bv),
                                        _ => Err(DecodeError::UnknownLiteral(self.clone()))?,
                                    },
                                    TermX::None(..) => None,
                                    _ => Err(DecodeError::UnknownLiteral(self.clone()))?,
                                };

                                Ok(TermX::Prim(TermPrim::Ext(Ext::Ipaddr {
                                    ip: if s == "V4" {
                                        IPNet::V4(CIDRv4 {
                                            addr: IPv4Addr { val: addr },
                                            prefix: IPv4Prefix { val: prefix },
                                        })
                                    } else {
                                        IPNet::V6(CIDRv6 {
                                            addr: IPv6Addr { val: addr },
                                            prefix: IPv6Prefix { val: prefix },
                                        })
                                    },
                                })).into())
                            }

                            SExpr::Symbol(s) => {
                                match (id_maps.types.get(s), &args[1..]) {
                                    // Entity UID
                                    (Some(TermType::Entity { ety }), [SExpr::String(e)]) => {
                                        let uid = EntityUid::from_type_name_and_id(
                                            ety.clone(),
                                            EntityId::new(e),
                                        );
                                        Ok(TermX::Prim(TermPrim::Entity(uid)).into())
                                    }

                                    // Record
                                    (Some(TermType::Record { rty }), fields) => {
                                        // Decode each field
                                        let decoded_fields = fields
                                            .iter()
                                            .map(|field| field.decode_literal(id_maps))
                                            .collect::<Result<Vec<_>, _>>()?;

                                        if decoded_fields.len() != rty.len() {
                                            return Err(DecodeError::UnmatchedRecordType);
                                        }

                                        let mut record = BTreeMap::new();

                                        // Check the type of each field and collect them into `record`
                                        for (decoded_field, (field_name, field_ty)) in
                                            decoded_fields.iter().zip(rty.iter())
                                        {
                                            let decoded_field_ty = decoded_field.type_of();

                                            if &decoded_field_ty != field_ty {
                                                return Err(DecodeError::UnmatchedFieldType(
                                                    decoded_field_ty,
                                                    field_ty.clone(),
                                                ));
                                            }

                                            record
                                                .insert(field_name.clone(), decoded_field.clone());
                                        }

                                        Ok(TermX::Record(record).into())
                                    }

                                    _ => Err(DecodeError::UnknownLiteral(self.clone())),
                                }
                            }

                            _ => Err(DecodeError::UnknownLiteral(self.clone())),
                        }
                    }

                    _ => Err(DecodeError::UnknownLiteral(self.clone())),
                }
            }

            _ => Err(DecodeError::UnknownLiteral(self.clone())),
        }
    }

    /// Decodes a constant definition in the model.
    pub fn decode_var(
        id_maps: &IdMaps,
        name: &str,
        typ: &SExpr,
        value: &SExpr,
    ) -> Result<(TermVar, Term), DecodeError> {
        let Some(term_var) = id_maps.vars.get(name) else {
            return Err(DecodeError::UnknownVariable(name.to_string()));
        };

        let ty = typ.decode_type(id_maps)?;
        let val = value.decode_literal(id_maps)?;
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
        id_maps: &IdMaps,
        name: &str,
        arg_name: &str,
        arg_typ: &SExpr,
        ret_typ: &SExpr,
        body: &SExpr,
    ) -> Result<(Uuf, Udf), DecodeError> {
        // First check if the SMT name actually corresponds to a UUF
        let Some(uuf) = id_maps.uufs.get(name) else {
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
            if let SExpr::App(exprs) = cur_body {
                // PANIC SAFETY
                #[allow(
                    clippy::indexing_slicing,
                    reason = "Slice of length 4 can be indexed by 0-3"
                )]
                if exprs.len() == 4 && exprs[0].is_symbol("ite") {
                    if let SExpr::App(args) = &exprs[1] {
                        if args.len() == 3 && args[0].is_symbol("=") {
                            if let SExpr::Symbol(arg) = &args[2] {
                                if arg != arg_name {
                                    return Err(DecodeError::UnexpectedUnaryFunctionForm(
                                        body.clone(),
                                    ));
                                }

                                let cond_term = args[1].decode_literal(id_maps)?;
                                let then_term = exprs[2].decode_literal(id_maps)?;

                                table.insert(cond_term, then_term);
                                cur_body = &exprs[3];
                                continue;
                            }
                        }
                    }
                }
            }

            // otherwise take as the default value
            // assuming it doesn't contain any bound variables
            let default = cur_body.decode_literal(id_maps)?;

            return Ok((
                uuf.clone(),
                Udf {
                    arg: uuf.arg.clone(),
                    out: uuf.out.clone(),
                    table,
                    default,
                },
            ));
        }
    }

    /// Decodes the output of `(get-model)` to as [`Interpretation`].
    pub fn decode_model<'a>(
        &self,
        env: &'a SymEnv,
        id_maps: &IdMaps,
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
                        // Decode unary function
                        [SExpr::App(arg)] if arg.len() == 2 => match arg.as_slice() {
                            [SExpr::Symbol(arg_name), arg_ty] => {
                                let (uuf, udf) = Self::decode_unary_function(
                                    id_maps, name, arg_name, arg_ty, ret_ty, body,
                                )?;
                                funs.insert(uuf, udf);
                            }
                            _ => return Err(DecodeError::UnexpectedModel),
                        },

                        // Decode SMT constant definition as interpretation to a Cedar variable
                        [] => {
                            let (term_var, term) = Self::decode_var(id_maps, name, ret_ty, body)?;
                            vars.insert(term_var, term);
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

impl Display for SExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SExpr::BitVec(bv) => write!(f, "{:?}", bv),
            SExpr::Numeral(n) => write!(f, "{}", n),
            SExpr::String(s) => write!(f, "\"{}\"", s),
            SExpr::Symbol(s) => write!(f, "{}", s),
            SExpr::App(exprs) => write!(f, "({})", exprs.iter().map(|e| e.to_string()).join(" ")),
        }
    }
}
