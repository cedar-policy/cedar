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

use smol_str::{format_smolstr, SmolStr};

use super::bitvec::BitVec;
use super::ext::Ext;
use super::op::Op;
use super::term_type::TermType;
use super::type_abbrevs::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Deref,
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
/// Variants must be defined in alphabetical order.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum TermPrim {
    /// Literal bitvec
    Bitvec(BitVec),
    /// Literal bool
    Bool(bool),
    /// Literal EntityUID
    Entity(EntityUID),
    /// Literal extension value
    Ext(Ext),
    /// Literal string
    String(SmolStr),
}

/// Intermediate representation of [`Term`]s.
/// Variants must be defined in alphabetical order.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum Term {
    /// Function calls
    App {
        /// Function being called
        op: Op,
        /// Arguments
        args: Arc<Vec<Term>>,
        /// Return type of the function
        ret_ty: TermType,
    },
    /// None
    None(TermType),
    /// Literal
    Prim(TermPrim),
    /// Records
    Record(Arc<BTreeMap<Attr, Term>>),
    /// Sets
    Set {
        /// Elements of the set (as `Term`)
        elts: Arc<BTreeSet<Term>>,
        /// Type shared by all elements of the set
        elts_ty: TermType,
    },
    /// Some
    Some(Arc<Term>),
    /// Variable
    Var(TermVar),
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

impl std::fmt::Display for Term {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Term::Prim(prim) => write!(f, "{prim}"),
            Term::Var(var) => write!(f, "{}", var.id),
            Term::None(_) => write!(f, "None"),
            Term::Some(t) => write!(f, "Some({t})"),
            Term::Set { elts, .. } => {
                write!(f, "[")?;
                let mut first = true;
                for elt in elts.iter() {
                    if !first {
                        write!(f, ", ")?;
                    }
                    write!(f, "{elt}")?;
                    first = false;
                }
                write!(f, "]")
            }
            Term::Record(map) => {
                if map.is_empty() {
                    write!(f, "{{}}")
                } else {
                    write!(f, "{{ ")?;
                    let mut first = true;
                    for (k, v) in map.iter() {
                        if !first {
                            write!(f, ", ")?;
                        }
                        write!(f, "{k}: {v}")?;
                        first = false;
                    }
                    write!(f, " }}")
                }
            }
            Term::App { op, args, .. } => {
                write!(
                    f,
                    "{op}(",
                    op = match op {
                        Op::Ext(ext) => SmolStr::new(ext.mk_name()),
                        Op::Uuf(uuf) => uuf.id.clone(),
                        Op::RecordGet(attr) => format_smolstr!("getattr[\"{attr}\"]"),
                        Op::StringLike(pat) =>
                            format_smolstr!("like[\"{pat}\"]", pat = pat.deref()),
                        _ => SmolStr::new(op.mk_name()),
                    }
                )?;
                let mut first = true;
                for arg in args.iter() {
                    if !first {
                        write!(f, ", ")?;
                    }
                    write!(f, "{arg}")?;
                    first = false;
                }
                write!(f, ")")
            }
        }
    }
}

impl std::fmt::Display for TermPrim {
    #[expect(
        clippy::unwrap_used,
        reason = "for now, allowing panics in this Display impl intended for debugging"
    )]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TermPrim::Bool(b) => write!(f, "{b}"),
            TermPrim::Bitvec(bv) => write!(f, "{bv}"),
            TermPrim::String(s) => write!(f, "\"{s}\""),
            TermPrim::Entity(e) => write!(f, "{e}"),
            TermPrim::Ext(ext) => write!(
                f,
                "{}",
                cedar_policy_core::ast::Value::try_from(ext).unwrap()
            ),
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::factory;
    use super::*;

    use cedar_policy::EntityTypeName;
    use std::str::FromStr;

    #[test]
    fn term_display() {
        let term = Term::from(false);
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @"false");
        });

        let term = Term::from(334);
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @"(bv64 334)");
        });

        let term = Term::from(SmolStr::new_static("hello I am a string"));
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @r#""hello I am a string""#);
        });

        let term = Term::from(EntityUID::from_str("App::Domain::\"Component\"").unwrap());
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @r#"App::Domain::"Component""#);
        });

        let term = Term::from(TermVar {
            id: SmolStr::new_static("principal"),
            ty: TermType::Entity {
                ety: EntityTypeName::from_str("A::B::CDEFG").unwrap(),
            },
        });
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @"principal");
        });

        let term = Term::from(Ext::parse_decimal("-0.11").unwrap());
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @r#"decimal("-0.1100")"#);
        });

        let term = Term::from(Ext::parse_decimal("34567.8901").unwrap());
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @r#"decimal("34567.8901")"#);
        });

        let term = Term::from(Ext::parse_ip("192.168.0.0/24").unwrap());
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @r#"ip("192.168.0.0/24")"#);
        });

        let term = Term::from(Ext::parse_ip("ffee::1").unwrap());
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @r#"ip("ffee:0000:0000:0000:0000:0000:0000:0001/128")"#);
        });

        let term = Term::from(Ext::parse_duration("3m7s").unwrap());
        insta::with_settings!({ description => format!("{term:?}") }, {
            // TODO: this one isn't the prettiest, but could be that this
            // representation is helpful for someone debugging at the Term
            // level; not sure what's optimal here
            insta::assert_snapshot!(term.to_string(), @r#"duration("187000ms")"#);
        });

        let term = Term::from(Ext::parse_duration("1d0m76s111ms").unwrap());
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @r#"duration("86476111ms")"#);
        });

        let term = Term::from(Ext::parse_datetime("2001-07-07").unwrap());
        insta::with_settings!({ description => format!("{term:?}") }, {
            // TODO: not pretty
            insta::assert_snapshot!(term.to_string(), @r#"(datetime("1970-01-01")).offset(duration("994464000000ms"))"#);
        });

        let term = Term::from(Ext::parse_datetime("2010-12-31T11:59:59Z").unwrap());
        insta::with_settings!({ description => format!("{term:?}") }, {
            // TODO: not pretty
            insta::assert_snapshot!(term.to_string(), @r#"(datetime("1970-01-01")).offset(duration("1293796799000ms"))"#);
        });

        let term = Term::from(Ext::parse_datetime("2010-12-31T11:59:59.777Z").unwrap());
        insta::with_settings!({ description => format!("{term:?}") }, {
            // TODO: not pretty
            insta::assert_snapshot!(term.to_string(), @r#"(datetime("1970-01-01")).offset(duration("1293796799777ms"))"#);
        });

        let term = Term::from(Ext::parse_datetime("2010-12-31T11:59:59.777+1134").unwrap());
        insta::with_settings!({ description => format!("{term:?}") }, {
            // TODO: not pretty
            insta::assert_snapshot!(term.to_string(), @r#"(datetime("1970-01-01")).offset(duration("1293755159777ms"))"#);
        });

        let term = Term::Some(Arc::new(factory::set_of(
            [Term::from(36), Term::from(-1240)],
            TermType::Bitvec { n: SIXTY_FOUR },
        )));
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @"Some([(bv64 36), (bv64 18446744073709550376)])");
        });

        let term = factory::record_of([
            ("foo".into(), Term::from(-321)),
            ("bar".into(), Term::from(SmolStr::new_static("a string"))),
            (
                "weird key!".into(),
                Term::from(Ext::parse_decimal("2.222").unwrap()),
            ),
        ]);
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @r#"{ bar: "a string", foo: (bv64 18446744073709551295), weird key!: decimal("2.2220") }"#);
        });

        let context = Term::from(TermVar {
            id: SmolStr::new_static("context"),
            ty: TermType::Record {
                rty: Arc::new(
                    [
                        (SmolStr::new("foo"), TermType::Bitvec { n: SIXTY_FOUR }),
                        (SmolStr::new("abc"), TermType::Bool),
                        (SmolStr::new("def"), TermType::Bool),
                        (SmolStr::new("zyx"), TermType::Bool),
                        (SmolStr::new("path"), TermType::String),
                    ]
                    .into_iter()
                    .collect(),
                ),
            },
        });
        let term = factory::bvslt(
            factory::record_get(context.clone(), &SmolStr::new("foo")),
            Term::from(12),
        );
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @r#"bvslt(getattr["foo"](context), (bv64 12))"#);
        });

        let term = factory::and(
            factory::or(
                factory::record_get(context.clone(), &SmolStr::new("abc")),
                factory::record_get(context.clone(), &SmolStr::new("def")),
            ),
            factory::record_get(context.clone(), &SmolStr::new("zyx")),
        );
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @r#"and(or(getattr["abc"](context), getattr["def"](context)), getattr["zyx"](context))"#);
        });

        let term = factory::ite(
            factory::record_get(context.clone(), &SmolStr::new("abc")),
            Term::from(777),
            Term::from(888),
        );
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @r#"ite(getattr["abc"](context), (bv64 777), (bv64 888))"#);
        });

        let term = factory::string_like(
            factory::record_get(context, &SmolStr::new("path")),
            cedar_policy_core::ast::Pattern::from_iter([
                cedar_policy_core::ast::PatternElem::Char('a'),
                cedar_policy_core::ast::PatternElem::Wildcard,
                cedar_policy_core::ast::PatternElem::Char('z'),
            ])
            .into(),
        );
        insta::with_settings!({ description => format!("{term:?}") }, {
            insta::assert_snapshot!(term.to_string(), @r#"like["a*z"](getattr["path"](context))"#);
        });
    }
}
