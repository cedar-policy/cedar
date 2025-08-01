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

//! This module defines the Cedar encoder, which translates a list of boolean Terms
//! into a list of SMT assertions. Term encoding is trusted.
//!
//!  We use the following type representations for primitive types:
//!  * `TermType.bool`:     builtin SMT `Bool` type
//!  * `TermType.string`:   builtin SMT `String` type
//!  * `TermType.bitvec n`: builtin SMT `(_ BitVec n)` type
//!
//!  We will represent non-primitive types as SMT algebraic data types:
//!  * `TermType.option T`: a parameterized SMT algebraic datatype of the same name,
//!    and with the constructors `(some (val T))` and `(none)`. For each constructor
//!    argument, SMTLib introduces a corresponding (total) selector function. We
//!    will translate `Term.some` nodes in the Term language as applications of the
//!    `val` selector function.
//!  * `TermType.entity E`: we represent Cedar entities of entity type E as values
//!    of the SMT algebraic datatype E with a single constructor, `(E (eid String))`.
//!    Each entity type E gets an uninterpreted function `f: E → Record_E` that maps
//!    instances of E to their attributes.  Similarly, each E
//!    gets N uninterpreted functions `g₁: E → Set E₁, ..., gₙ: E → Set Eₙ` that map
//!    each instance of E to its ancestor sets of the given types, as specified by
//!    the `memberOf` relation in the schema.
//!  * `TermType.Record (Map Attr TermType)`: we represent each record term type as
//!    an SMT algebraic datatype with a single constructor. The order of arguments
//!    to the constructor (the attributes) is important, so we fix that to be the
//!    lexicographic order on the attribute names of the underlying record type. We
//!    use the argument selector functions to translate `record.get` applications.
//!    We can't use raw Cedar attribute names for argument names because they may
//!    not be valid SMT identifiers. So, we'll keep a mapping from the attribute
//!    names to their unique SMT ids. In general, we'll name SMT record types as
//!    "R`<i>`" where `<i>` is a natural number and attributes within the record as
//!    "R`<i>`a`<j>`", where `<j>` is the attribute's position in the constructor argument
//!    list.
//!
//!  Similarly to types and attributes, all uninterpreted functions, variables, and
//!  Terms are mapped to their SMT encoding that conforms to the SMTLib syntax. We
//!  keep track of these mappings to ensure that each Term construct is translated
//!  to its SMT encoding exactly once.  This translation invariant is necessary for
//!  correctness in the case of record type declarations, UF names, and variable
//!  names; and it is necessary for compactness in the case of terms. In
//!  particular, the resulting SMT encoding will be in A-normal form (ANF): the body
//!  of every s-expression in the encoding consists of atomic subterms (identifiers
//!  or literals).

use anyhow::anyhow;
use async_recursion::async_recursion;
use itertools::Itertools;
use std::collections::{BTreeMap, BTreeSet};

use cedar_policy_core::ast::PatternElem;

use super::{
    bitvec::BitVec,
    env::SymEnv,
    ext::Ext,
    extension_types::ipaddr::{CIDRv4, CIDRv6, IPNet, IPv4Prefix, IPv6Prefix},
    op::{ExtOp, Op, Uuf},
    smtlib_script::SmtLibScript,
    term::{Term, TermPrim, TermVar},
    term_type::TermType,
    type_abbrevs::*,
};

use crate::symcc::extension_types::ipaddr::{V4_WIDTH, V6_WIDTH};

#[derive(Debug)]
pub struct Encoder<'a, S> {
    pub(super) terms: BTreeMap<Term, String>,
    pub(super) types: BTreeMap<TermType, String>,
    pub(super) uufs: BTreeMap<Uuf, String>,
    pub(super) enums: BTreeMap<&'a EntityType, &'a BTreeSet<String>>,
    script: S,
}

fn term_id(n: usize) -> String {
    format!("t{n}")
}

fn uuf_id(n: usize) -> String {
    format!("f{n}")
}

fn entity_type_id(n: usize) -> String {
    format!("E{n}")
}

pub(super) fn enum_id(e: &str, n: usize) -> String {
    format!("{e}_m{n}")
}

fn record_type_id(n: usize) -> String {
    format!("R{n}")
}

fn record_attr_id(r: &str, n: usize) -> String {
    format!("{r}_a{n}")
}

// We don't need these
// def typeNum : EncoderM Nat := do return (← get).types.size
// def termNum : EncoderM Nat := do return (← get).terms.size
// def uufNum  : EncoderM Nat := do return (← get).uufs.size

impl<'a, S> Encoder<'a, S> {
    /// Corresponds to `EncoderState.init` in Lean
    pub fn new(env: &'a SymEnv, script: S) -> Result<Self, anyhow::Error> {
        Ok(Encoder {
            terms: BTreeMap::new(),
            types: BTreeMap::new(),
            uufs: BTreeMap::new(),
            enums: env
                .entities
                .iter()
                .filter_map(|(ety, d)| Some((ety, d.members.as_ref()?)))
                .collect(),
            script,
        })
    }
}

impl<S: tokio::io::AsyncWrite + Unpin + Send> Encoder<'_, S> {
    /// Returns `id` to match the Lean
    pub async fn declare_type<'i>(
        &mut self,
        id: &'i str,
        mks: impl IntoIterator<Item = String>,
    ) -> Result<&'i str, anyhow::Error> {
        self.script.declare_datatype(id, vec![], mks).await?;
        Ok(id)
    }

    pub async fn declare_entity_type(&mut self, ety: &EntityType) -> Result<String, anyhow::Error> {
        let ety_id = entity_type_id(self.types.len());
        match self.enums.get(ety) {
            Some(members) => {
                self.script
                    .comment(&format!("{ety}::[{}]", members.iter().join(", ")))
                    .await?;
                let mks: Vec<_> = members
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format!("({})", enum_id(&ety_id, i)))
                    .collect();
                self.declare_type(&ety_id, mks).await.map(Into::into)
            }
            None => {
                self.script.comment(&ety.to_string()).await?;
                self.declare_type(&ety_id, [format!("({ety_id} (eid String))")])
                    .await
                    .map(Into::into)
            }
        }
    }

    pub async fn declare_ext_type(&mut self, ext_ty: &ExtType) -> Result<&str, anyhow::Error> {
        match ext_ty {
            ExtType::Decimal => {
                self.declare_type(
                    "Decimal",
                    ["(Decimal (decimalVal (_ BitVec 64)))".to_string()],
                )
                .await
            }
            ExtType::IpAddr => {
                self.declare_type(
                    "IPAddr",
                    [
                        "(V4 (addrV4 (_ BitVec 32)) (prefixV4 (Option (_ BitVec 5))))".to_string(),
                        "(V6 (addrV6 (_ BitVec 128)) (prefixV6 (Option (_ BitVec 7))))".to_string(),
                    ],
                )
                .await
            }
            ExtType::Duration => {
                self.declare_type(
                    "Duration",
                    ["(Duration (durationVal (_ BitVec 64)))".to_string()],
                )
                .await
            }
            ExtType::DateTime => {
                self.declare_type(
                    "Datetime",
                    ["(Datetime (datetimeVal (_ BitVec 64)))".to_string()],
                )
                .await
            }
        }
    }

    pub async fn declare_record_type<'r>(
        &mut self,
        rty: impl IntoIterator<Item = &'r (Attr, String)> + Clone,
    ) -> Result<String, anyhow::Error> {
        let rty_id = record_type_id(self.types.len());
        let mut attrs = rty
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, (_, ty))| format!("({} {})", record_attr_id(&rty_id, i), ty));
        self.script
            .comment(&format!(
                "{{{}}}",
                rty.into_iter().map(|(k, _)| k).join(", ")
            ))
            .await?;
        self.declare_type(&rty_id, [format!("({} {})", rty_id, attrs.join(" "))])
            .await
            .map(Into::into)
    }

    #[async_recursion]
    pub async fn encode_type(&mut self, ty: &TermType) -> Result<String, anyhow::Error> {
        match self.types.get(ty) {
            Some(enc) => Ok(enc.clone()),
            None => {
                let enc = match ty {
                    TermType::Bool => "Bool".to_string(),
                    TermType::String => "String".to_string(),
                    TermType::Bitvec { n } => format!("(_ BitVec {n})"),
                    TermType::Option { ref ty } => {
                        format!("(Option {})", self.encode_type(ty).await?)
                    }
                    TermType::Set { ty } => format!("(Set {})", self.encode_type(ty).await?),
                    TermType::Entity { ety } => self.declare_entity_type(ety).await?,
                    TermType::Ext { xty } => self.declare_ext_type(xty).await?.into(),
                    TermType::Record { rty } => {
                        let mut record_type = vec![];
                        for (k, v) in rty.iter() {
                            record_type.push((k.clone(), self.encode_type(v).await?));
                        }
                        self.declare_record_type(record_type.iter()).await?
                    }
                };
                self.types.insert(ty.clone(), enc.clone());
                Ok(enc)
            }
        }
    }

    pub async fn declare_var(
        &mut self,
        v: &TermVar,
        ty_enc: &str,
    ) -> Result<String, anyhow::Error> {
        let id = term_id(self.terms.len());
        self.script.comment(&format!("{:?}", v.id)).await?;
        self.script.declare_const(&id, ty_enc).await?;
        Ok(id)
    }

    pub async fn define_term(
        &mut self,
        ty_enc: &str,
        t_enc: &str,
    ) -> Result<String, anyhow::Error> {
        let id = term_id(self.terms.len());
        self.script.define_fun(&id, [], ty_enc, t_enc).await?;
        Ok(id)
    }

    pub async fn define_set<'s>(
        &mut self,
        ty_enc: &str,
        t_encs: impl IntoIterator<Item = &'s str>,
    ) -> Result<String, anyhow::Error> {
        let members = t_encs
            .into_iter()
            .fold(format!("(as set.empty {ty_enc})"), |acc, t| {
                format!("(set.insert {t} {acc})")
            });
        self.define_term(ty_enc, &members).await
    }

    pub async fn define_record<'s>(
        &mut self,
        ty_enc: &str,
        t_encs: impl IntoIterator<Item = &'s str>,
    ) -> Result<String, anyhow::Error> {
        self.define_term(
            ty_enc,
            &format!("({ty_enc} {})", t_encs.into_iter().join(" ")),
        )
        .await
    }

    pub async fn encode_uuf(&mut self, uuf: &Uuf) -> Result<String, anyhow::Error> {
        match self.uufs.get(uuf) {
            Some(enc) => Ok(enc.clone()),
            None => {
                let id = uuf_id(self.uufs.len());
                self.script.comment(&uuf.id).await?;
                let encoded_arg_type = self.encode_type(&uuf.arg).await?;
                let encoded_out_type = self.encode_type(&uuf.out).await?;
                self.script
                    .declare_fun(&id, [encoded_arg_type], &encoded_out_type)
                    .await?;
                self.uufs.insert(uuf.clone(), id.clone());
                Ok(id)
            }
        }
    }

    pub async fn define_entity(
        &mut self,
        ty_enc: &str,
        entity: &EntityUID,
    ) -> Result<String, anyhow::Error> {
        match self.enums.get(entity.type_name()) {
            Some(members) => {
                let entity_ind = match members.iter().position(|s| s ==  <EntityID as AsRef<str>>::as_ref(entity.id())) {
                    Some(ind) => ind,
                    None => return Err(anyhow!("members should contain entity.id()! Entity: {entity:?} \n Members: {members:?}"))
                };
                Ok(enum_id(ty_enc, entity_ind))
            }
            None => {
                self.define_term(
                    ty_enc,
                    &format!(
                        "({ty_enc} {})",
                        encode_string(<EntityID as AsRef<str>>::as_ref(entity.id()))
                    ),
                )
                .await
            }
        }
    }

    fn index_of_attr(a: &Attr, t_ty: &TermType) -> Result<usize, anyhow::Error> {
        // Getting the index of a key in `BTreeMap` should be ok
        // (it wouldn't be for `HashMap`)
        match t_ty {
            TermType::Record { rty } => match rty.keys().position(|k| k == a) {
                Some(ind) => Ok(ind),
                None => Err(anyhow!("Could not find {a:?} in {rty:?}")),
            },
            _ => Err(anyhow!("Bad term: (record.get {a} {t_ty:?})")),
        }
    }

    pub async fn define_record_get(
        &mut self,
        ty_enc: &str,
        a: &Attr,
        t_enc: &str,
        ty: &TermType,
    ) -> Result<String, anyhow::Error> {
        let r_id = match self.types.get(ty) {
            Some(t) => t,
            None => return Err(anyhow!("Could not find {ty:?} in {:?}", self.types)),
        };
        let a_id = Self::index_of_attr(a, ty)?;
        self.define_term(ty_enc, &format!("({} {t_enc})", record_attr_id(r_id, a_id)))
            .await
    }

    pub async fn define_app<'b>(
        &mut self,
        ty_enc: &str,
        op: &Op,
        t_encs: impl IntoIterator<Item = String>,
        ts: impl IntoIterator<Item = &'b Term>,
    ) -> Result<String, anyhow::Error> {
        let args = t_encs.into_iter().join(" ");
        let t = match ts.into_iter().next() {
            Some(t) => t.type_of(),
            None => return Err(anyhow!("cannot get type of non-existant type")),
        };
        match op {
            Op::RecordGet(a) => self.define_record_get(ty_enc, a, &args, &t).await,
            Op::StringLike(p) => {
                self.define_term(ty_enc, &format!("(str.in_re {args} {})", encode_pattern(p)))
                    .await
            }
            Op::Uuf(f) => {
                let encoded_uuf = self.encode_uuf(f).await?;
                self.define_term(ty_enc, &format!("({} {args})", encoded_uuf))
                    .await
            }
            _ => {
                self.define_term(ty_enc, &format!("({} {args})", encode_op(op)))
                    .await
            }
        }
    }

    #[async_recursion]
    pub async fn encode_term(&mut self, t: &Term) -> Result<String, anyhow::Error> {
        if let Some(enc) = self.terms.get(t) {
            return Ok(enc.clone());
        }
        let ty_enc = self.encode_type(&t.type_of()).await?;
        let enc = match &t {
            Term::Var(v) => self.declare_var(v, &ty_enc).await?,
            Term::Prim(p) => match p {
                TermPrim::Bool(b) => {
                    if *b {
                        "true".to_string()
                    } else {
                        "false".to_string()
                    }
                }
                TermPrim::Bitvec(bv) => encode_bitvec(bv),
                TermPrim::String(s) => encode_string(s),
                TermPrim::Entity(e) => self.define_entity(&ty_enc, e).await?,
                TermPrim::Ext(x) => self.define_term(&ty_enc, &encode_ext(x)).await?,
            },
            Term::None(_) => {
                self.define_term(&ty_enc, &format!("(as none {ty_enc})"))
                    .await?
            }
            Term::Some(t1) => {
                let encoded_term = self.encode_term(t1).await?;
                self.define_term(&ty_enc, &format!("(some {encoded_term})"))
                    .await?
            }
            Term::Set { elts, .. } => {
                let mut encoded_terms = vec![];
                for elt in elts.iter() {
                    encoded_terms.push(self.encode_term(elt).await?);
                }
                self.define_set(&ty_enc, encoded_terms.iter().map(|s| s.as_str()))
                    .await?
            }
            Term::Record(ats) => {
                let mut encoded_terms = vec![];
                for t in ats.values() {
                    encoded_terms.push(self.encode_term(t).await?);
                }
                self.define_record(&ty_enc, encoded_terms.iter().map(|s| s.as_str()))
                    .await?
            }
            Term::App {
                op: Op::Bvnego,
                args,
                ret_ty: TermType::Bool,
            } if args.len() == 1 => {
                // PANIC SAFETY
                #[allow(
                    clippy::indexing_slicing,
                    reason = "Slice of length 1 can be indexed by 0"
                )]
                let t = &args[0]; // guaranteed to exist because we already checked that `args.len() == 1`

                // don't encode bvnego itself, for compatibility with older CVC5 (bvnego was
                // introduced in CVC5 1.1.2)
                // this rewrite is done in the encoder and is thus trusted; see notes here in
                // the Lean
                match t.type_of() {
                    TermType::Bitvec { n } => {
                        // more fancy and possibly more optimized, but hard to prove termination in Lean:
                        // self.encode_term(&factory::eq(t, &BitVec::int_min(n))).await?
                        let t_enc = self.encode_term(t).await?;
                        self.define_app(
                            &ty_enc,
                            &Op::Eq,
                            [t_enc, encode_bitvec(&BitVec::int_min(n)?)],
                            [t, &BitVec::int_min(n)?.into()],
                        )
                        .await?
                    }
                    _ => {
                        // we could put anything here and be sound, because `Bvnego` should only be
                        // applied to Terms of type `Bitvec`
                        String::from("false")
                    }
                }
            }
            Term::App { op, args, .. } => {
                let mut encoded_terms = vec![];
                for arg in args.iter() {
                    encoded_terms.push(self.encode_term(arg).await?);
                }
                self.define_app(&ty_enc, op, encoded_terms, args.iter())
                    .await?
            }
        };
        self.terms.insert(t.clone(), enc.clone());
        Ok(enc)
    }

    /// Once you've generated `Asserts` with one of the functions in verifier.rs, you
    /// can use this function to encode them as SMTLib assertions.
    ///
    /// Note that `encode()` itself first resets the solver in order to define datatypes
    /// etc.
    ///
    /// In Lean, this is a standalone function which takes a `SymEnv`, uses that to
    /// construct an `Encoder` (`EncoderState` in Lean), and then does the encoding.
    /// Here in Rust, we have this as a method on `Encoder`, so the caller first
    /// constructs an `Encoder` themselves with the `SymEnv`, then calls this.
    pub async fn encode(
        &mut self,
        ts: impl IntoIterator<Item = Term>,
    ) -> Result<(), anyhow::Error> {
        self.script
            .declare_datatype(
                "Option",
                ["X"],
                ["(none)".to_string(), "(some (val X))".to_string()],
            )
            .await?;
        for t in ts {
            let id = self.encode_term(&t).await?;
            self.script.assert(&id).await?;
        }
        Ok(())
    }
}

// /-
// String printing has to be done carefully in the presence of
// non-ASCII characters.  See the SMTLib standard for the details:
// https://smtlib.cs.uiowa.edu/theories-UnicodeStrings.shtml. Here,
// we're assuming ASCII strings for simplicity.
//
// According to the standard, `""` is the only escape sequence
// in strings, which is interpreted as a single `"` character.
// -/
fn encode_string(s: &str) -> String {
    format!("\"{}\"", s.replace("\"", "\"\""))
}

fn encode_bitvec(bv: &BitVec) -> String {
    format!("(_ bv{} {})", bv.to_nat(), bv.width())
}

fn encode_ipaddr_prefix_v4(pre: &IPv4Prefix) -> String {
    match &pre.val {
        Some(pre) => format!("(some {})", encode_bitvec(&pre)),
        None => format!("(as none (Option (_ BitVec {V4_WIDTH})))"),
    }
}

fn encode_ipaddr_prefix_v6(pre: &IPv6Prefix) -> String {
    match &pre.val {
        Some(pre) => format!("(some {})", encode_bitvec(&pre)),
        None => format!("(as none (Option (_ BitVec {V6_WIDTH})))"),
    }
}

fn encode_ext(e: &Ext) -> String {
    match e {
        Ext::Decimal { d } => {
            #[allow(
                clippy::unwrap_used,
                reason = "Cannot panic because bitwidth is non-zero."
            )]
            let bv_enc = encode_bitvec(&BitVec::of_int(64, d.0.into()).unwrap());
            format!("(Decimal {bv_enc})")
        }
        Ext::Ipaddr {
            ip: IPNet::V4(CIDRv4 { addr, prefix }),
        } => {
            let addr = encode_bitvec(&addr.val);
            let pre = encode_ipaddr_prefix_v4(prefix);
            format!("(V4 {addr} {pre})")
        }
        Ext::Ipaddr {
            ip: IPNet::V6(CIDRv6 { addr, prefix }),
        } => {
            let addr = encode_bitvec(&addr.val);
            let pre = encode_ipaddr_prefix_v6(prefix);
            format!("(V6 {addr} {pre})")
        }
        Ext::Duration { d } => {
            #[allow(
                clippy::unwrap_used,
                reason = "Cannot panic because bitwidth is non-zero."
            )]
            let bv_enc = encode_bitvec(&BitVec::of_int(64, d.to_milliseconds().into()).unwrap());
            format!("(Duration {bv_enc})")
        }
        Ext::Datetime { dt } => {
            #[allow(
                clippy::unwrap_used,
                reason = "Cannot panic because bitwidth is non-zero."
            )]
            let bv_enc = encode_bitvec(&BitVec::of_i128(64, dt.into()).unwrap());
            format!("(Datetime {bv_enc})")
        }
    }
}

fn encode_ext_op(ext_op: &ExtOp) -> &'static str {
    match ext_op {
        ExtOp::DecimalVal => "decimalVal",
        ExtOp::IpaddrIsV4 => "(_ is V4)",
        ExtOp::IpaddrAddrV4 => "addrV4",
        ExtOp::IpaddrPrefixV4 => "prefixV4",
        ExtOp::IpaddrAddrV6 => "addrV6",
        ExtOp::IpaddrPrefixV6 => "prefixV6",
        ExtOp::DatetimeVal => "datetimeVal",
        ExtOp::DatetimeOfBitVec => "Datetime",
        ExtOp::DurationVal => "durationVal",
        ExtOp::DurationOfBitVec => "Duration",
    }
}

fn encode_op(op: &Op) -> String {
    match op {
        Op::Eq => "=".to_string(),
        Op::ZeroExtend(n) => format!("(_ zero_extend {n})"),
        Op::OptionGet => "val".to_string(),
        Op::Ext(xop) => encode_ext_op(xop).into(),
        _ => op.mk_name().into(),
    }
}

fn encode_pat_elem(pat_elem: PatternElem) -> String {
    match pat_elem {
        PatternElem::Wildcard => "(re.* re.allchar)".to_string(),
        PatternElem::Char(c) => format!("(str.to_re \"{c}\")"),
    }
}

fn encode_pattern(pattern: &OrdPattern) -> String {
    if pattern.get_elems().is_empty() {
        "(str.to_re \"\")".to_string()
    } else if pattern.get_elems().len() == 1 {
        // PANIC SAFETY
        #[allow(
            clippy::indexing_slicing,
            reason = "Slice of length 1 can be indexed by 0"
        )]
        encode_pat_elem(pattern.get_elems()[0])
    } else {
        format!(
            "(re.++ {})",
            pattern.iter().copied().map(encode_pat_elem).join(" ")
        )
    }
}

#[cfg(test)]
mod unit_tests {
    use std::{collections::BTreeSet, str::FromStr};

    use crate::symcc::env::{SymEntities, SymEnv, SymRequest};
    use cedar_policy::EntityTypeName;

    use super::Encoder;
    use crate::symcc::term_type::TermType;
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn declare_type() {
        let symenv = SymEnv {
            request: SymRequest::empty_sym_req(),
            entities: SymEntities(BTreeMap::new()),
        };
        let mut encoder = Encoder::new(&symenv, Vec::<u8>::new()).unwrap();
        encoder
            .declare_type("foo", ["(Bar1 (baz String))".to_string()])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn declare_entity_type() {
        let symenv = SymEnv {
            request: SymRequest::empty_sym_req(),
            entities: SymEntities(BTreeMap::new()),
        };
        let mut encoder = Encoder::new(&symenv, Vec::<u8>::new()).unwrap();
        let ety = cedar_policy::EntityTypeName::from_str("User").unwrap();
        let empty_set = BTreeSet::new();
        encoder.enums.insert(&ety, &empty_set);
        encoder.declare_entity_type(&ety).await.unwrap();
    }

    #[tokio::test]
    async fn declare_empty_record_type() {
        let symenv = SymEnv {
            request: SymRequest::empty_sym_req(),
            entities: SymEntities(BTreeMap::new()),
        };
        let mut encoder = Encoder::new(&symenv, Vec::<u8>::new()).unwrap();
        encoder.declare_record_type(vec![]).await.unwrap();
    }

    #[tokio::test]
    async fn declare_record_type() {
        let symenv = SymEnv {
            request: SymRequest::empty_sym_req(),
            entities: SymEntities(BTreeMap::new()),
        };
        let mut encoder = Encoder::new(&symenv, Vec::<u8>::new()).unwrap();
        encoder
            .declare_record_type([("foo".into(), "bar".to_string())].iter())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn encode_bool_type() {
        let symenv = SymEnv {
            request: SymRequest::empty_sym_req(),
            entities: SymEntities(BTreeMap::new()),
        };
        let mut encoder = Encoder::new(&symenv, Vec::<u8>::new()).unwrap();
        encoder.encode_type(&TermType::Bool).await.unwrap();
    }

    #[tokio::test]
    async fn encode_string_type() {
        let symenv = SymEnv {
            request: SymRequest::empty_sym_req(),
            entities: SymEntities(BTreeMap::new()),
        };
        let mut encoder = Encoder::new(&symenv, Vec::<u8>::new()).unwrap();
        encoder.encode_type(&TermType::String).await.unwrap();
    }

    #[tokio::test]
    async fn encode_uuf() {
        let symenv = SymEnv {
            request: SymRequest::empty_sym_req(),
            entities: SymEntities(BTreeMap::new()),
        };
        let mut encoder = Encoder::new(&symenv, Vec::<u8>::new()).unwrap();
        let my_uuf = crate::symcc::op::Uuf {
            id: "my_fun".to_string(),
            arg: TermType::Bool,
            out: TermType::Bool,
        };
        encoder.encode_uuf(&my_uuf).await.unwrap();
    }

    #[tokio::test]
    async fn define_entity() {
        use cedar_policy::EntityUid;
        let symenv = SymEnv {
            request: SymRequest::empty_sym_req(),
            entities: SymEntities(BTreeMap::new()),
        };
        let mut encoder = Encoder::new(&symenv, Vec::<u8>::new()).unwrap();
        let entity_type_name = EntityTypeName::from_str("User").unwrap();
        let entity = EntityUid::from_type_name_and_id(
            entity_type_name.clone(),
            cedar_policy::EntityId::from_str("alice").unwrap(),
        );
        let entity_ty_enc = encoder
            .encode_type(&TermType::Entity {
                ety: entity_type_name,
            })
            .await
            .unwrap();
        encoder
            .define_entity(&entity_ty_enc, &entity)
            .await
            .unwrap();
    }
}
