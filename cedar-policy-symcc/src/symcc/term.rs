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

//! A simply typed IR to which we reduce Cedar expressions during symbolic compilation.
//!
//! The Term language has a straightforward translation to SMTLib. It is designed to
//! reduce the semantic gap between Cedar and SMTLib, and to facilitate proofs of
//! soundness and completeness of the Cedar symbolic compiler.
//!
//! Terms should _not_ be created directly using `Term` constructors. Instead, they
//! should be created using the factory functions defined in `factory.rs`.
//! The factory functions check the types of their arguments, perform optimizations,
//! and ensure that applying them to well-formed terms results in well-formed terms.
//!
//! See `term_type.rs` and `op.rs` for definitions of Term types and operators.

use smol_str::SmolStr;

use super::bitvec::BitVec;
use super::ext::Ext;
use super::op::Op;
use super::term_type::TermType;
use super::type_abbrevs::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// A typed variable.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct TermVar {
    /// A unique identifier of the variable.
    pub id: SmolStr,
    /// Type of the variable.
    pub ty: TermType,
}

/// Primitive terms.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum TermPrim {
    /// Literal bool
    Bool(bool),
    /// Literal bitvec
    Bitvec(BitVec),
    /// Literal string
    String(SmolStr),
    /// Literal EntityUID
    Entity(EntityUID),
    /// Literal extension value
    Ext(Ext),
}

/// Intermediate representation of [`Term`]s.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum Term {
    /// Literal
    Prim(TermPrim),
    /// Variable
    Var(TermVar),
    /// None
    None(TermType),
    /// Some
    Some(Arc<Term>),
    /// Sets
    Set {
        /// Elements of the set (as `Term`)
        elts: Arc<BTreeSet<Term>>,
        /// Type shared by all elements of the set
        elts_ty: TermType,
    },
    /// Records
    Record(Arc<BTreeMap<Attr, Term>>),
    /// Function calls
    App {
        /// Function being called
        op: Op,
        /// Arguments
        args: Arc<Vec<Term>>,
        /// Return type of the function
        ret_ty: TermType,
    },
}

// Corresponding to the `Coe` instances in Lean
impl From<bool> for Term {
    fn from(b: bool) -> Self {
        if b {
            Term::Prim(TermPrim::Bool(true))
        } else {
            Term::Prim(TermPrim::Bool(false))
        }
    }
}

impl From<i64> for Term {
    fn from(i: i64) -> Self {
        Term::Prim(TermPrim::Bitvec(BitVec::of_int(SIXTY_FOUR, i.into())))
    }
}

impl From<BitVec> for Term {
    fn from(bv: BitVec) -> Self {
        Term::Prim(TermPrim::Bitvec(bv))
    }
}

impl From<SmolStr> for Term {
    fn from(s: SmolStr) -> Self {
        Term::Prim(TermPrim::String(s))
    }
}

impl From<EntityUID> for Term {
    fn from(uid: EntityUID) -> Self {
        Term::Prim(TermPrim::Entity(uid))
    }
}

impl From<Ext> for Term {
    fn from(ext: Ext) -> Self {
        Term::Prim(TermPrim::Ext(ext))
    }
}

impl From<TermVar> for Term {
    fn from(v: TermVar) -> Self {
        Term::Var(v)
    }
}

impl TermPrim {
    /// Returns the type of the primitive term.
    pub fn type_of(&self) -> TermType {
        match self {
            TermPrim::Bool(_) => TermType::Bool,
            TermPrim::Bitvec(v) => TermType::Bitvec { n: v.width() },
            TermPrim::String(_) => TermType::String,
            TermPrim::Entity(e) => TermType::Entity {
                ety: e.type_name().clone(),
            },
            TermPrim::Ext(Ext::Decimal { .. }) => TermType::Ext {
                xty: ExtType::Decimal,
            },
            TermPrim::Ext(Ext::Ipaddr { .. }) => TermType::Ext {
                xty: ExtType::IpAddr,
            },
            TermPrim::Ext(Ext::Duration { .. }) => TermType::Ext {
                xty: ExtType::Duration,
            },
            TermPrim::Ext(Ext::Datetime { .. }) => TermType::Ext {
                xty: ExtType::DateTime,
            },
        }
    }
}

impl Term {
    /// Computes the type of a term.
    pub fn type_of(&self) -> TermType {
        match self {
            Term::Prim(l) => l.type_of(),
            Term::Var(v) => v.ty.clone(),
            Term::None(ty) => TermType::option_of(ty.clone()),
            Term::Some(t) => TermType::option_of(t.type_of()),
            Term::Set { elts_ty, .. } => TermType::set_of(elts_ty.clone()),
            Term::Record(m) => {
                let rty = Arc::new(m.iter().map(|(k, v)| (k.clone(), v.type_of())).collect());
                TermType::Record { rty }
            }
            Term::App { ret_ty, .. } => ret_ty.clone(),
        }
    }

    /// Checks if the term is a literal, i.e., contains no variables or applications.
    pub fn is_literal(&self) -> bool {
        match self {
            Term::Prim(_) => true,
            Term::None(_) => true,
            Term::Some(t) => t.is_literal(),
            Term::Set { elts, .. } => elts.iter().all(Term::is_literal),
            Term::Record(m) => m.values().all(Term::is_literal),
            _ => false,
        }
    }
}
