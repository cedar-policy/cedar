/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

use crate::ast::*;
use crate::parser::Loc;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use itertools::Itertools;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use thiserror::Error;

/// This describes all the values which could be the dynamic result of evaluating an `Expr`.
/// Cloning is O(1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(into = "Expr")]
#[serde(try_from = "Expr")]
pub enum Value {
    /// anything that is a Literal can also be the dynamic result of evaluating an `Expr`
    Lit {
        /// the value
        lit: Literal,
        /// Source location associated with the value, if any
        loc: Option<Loc>,
    },
    /// Evaluating an `Expr` can result in a first-class set
    Set {
        /// the value
        set: Set,
        /// Source location associated with the value, if any
        loc: Option<Loc>,
    },
    /// Evaluating an `Expr` can result in a first-class anonymous record (keyed on String)
    Record {
        /// the value
        record: Arc<BTreeMap<SmolStr, Value>>,
        /// Source location associated with the value, if any
        loc: Option<Loc>,
    },
    /// Evaluating an `Expr` can result in an extension value
    ExtensionValue {
        /// the value
        ev: Arc<ExtensionValueWithArgs>,
        /// Source location associated with the value, if any
        loc: Option<Loc>,
    },
}

impl PartialOrd<Value> for Value {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // delegate to `Ord`
        Some(self.cmp(other))
    }
}

// Custom impl of `Ord`: ignore the `Loc`s
impl Ord for Value {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            // first the cases for values of the same kind: delegate to the Ord for those kinds, ignoring the `Loc`
            (Value::Lit { lit: selflit, .. }, Value::Lit { lit: otherlit, .. }) => {
                selflit.cmp(otherlit)
            }
            (Value::Set { set: selfset, .. }, Value::Set { set: otherset, .. }) => {
                selfset.cmp(otherset)
            }
            (
                Value::Record {
                    record: selfrecord, ..
                },
                Value::Record {
                    record: otherrecord,
                    ..
                },
            ) => selfrecord.cmp(otherrecord),
            (
                Value::ExtensionValue { ev: selfev, .. },
                Value::ExtensionValue { ev: otherev, .. },
            ) => selfev.cmp(otherev),
            // now the cases for values of different kinds: arbitrarily, Lit < Set < Record < ExtensionValue
            (Value::Lit { .. }, _) => std::cmp::Ordering::Less,
            (_, Value::Lit { .. }) => std::cmp::Ordering::Greater,
            (Value::Set { .. }, _) => std::cmp::Ordering::Less,
            (_, Value::Set { .. }) => std::cmp::Ordering::Greater,
            (Value::Record { .. }, _) => std::cmp::Ordering::Less,
            (_, Value::Record { .. }) => std::cmp::Ordering::Greater,
        }
    }
}

impl Value {
    /// Create a new empty set
    pub fn empty_set(loc: Option<Loc>) -> Self {
        Self::Set {
            set: Set {
                authoritative: Arc::new(BTreeSet::new()),
                fast: Some(Arc::new(HashSet::new())),
            },
            loc,
        }
    }

    /// Create a new empty record
    pub fn empty_record(loc: Option<Loc>) -> Self {
        Self::Record {
            record: Arc::new(BTreeMap::new()),
            loc,
        }
    }

    /// Create a set with the given `Value`s as elements
    pub fn set(vals: impl IntoIterator<Item = Value>, loc: Option<Loc>) -> Self {
        let authoritative: BTreeSet<Value> = vals.into_iter().collect();
        let fast: Option<Arc<HashSet<Literal>>> = authoritative
            .iter()
            .map(|v| v.try_as_lit().cloned())
            .collect::<Option<HashSet<Literal>>>()
            .map(Arc::new);
        Self::Set {
            set: Set {
                authoritative: Arc::new(authoritative),
                fast,
            },
            loc,
        }
    }

    /// Create a set with the given `Literal`s as elements
    ///
    /// the resulting `Value` will have the given `loc` attached, but its
    /// individual `Literal` elements will not have a source loc attached
    pub fn set_of_lits(lits: impl IntoIterator<Item = Literal>, loc: Option<Loc>) -> Self {
        let fast: HashSet<Literal> = lits.into_iter().collect();
        let authoritative: BTreeSet<Value> = fast
            .iter()
            .map(|lit| Value::Lit {
                lit: lit.clone(),
                loc: None,
            })
            .collect();
        Self::Set {
            set: Set {
                authoritative: Arc::new(authoritative),
                fast: Some(Arc::new(fast)),
            },
            loc,
        }
    }

    /// Create a record with the given (key, value) pairs
    pub fn record<K: Into<SmolStr>, V: Into<Value>>(
        pairs: impl IntoIterator<Item = (K, V)>,
        loc: Option<Loc>,
    ) -> Self {
        Self::Record {
            record: Arc::new(
                pairs
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            ),
            loc,
        }
    }

    /// Return the `Value`, but with the given `Loc` (or `None`)
    pub fn with_maybe_source_loc(self, loc: Option<Loc>) -> Self {
        match self {
            Value::Lit { lit, .. } => Value::Lit { lit, loc },
            Value::Set { set, .. } => Value::Set { set, loc },
            Value::Record { record, .. } => Value::Record { record, loc },
            Value::ExtensionValue { ev, .. } => Value::ExtensionValue { ev, loc },
        }
    }

    /// Get the `Loc` attached to this `Value`, if there is one
    pub fn source_loc(&self) -> Option<&Loc> {
        match self {
            Self::Lit { loc, .. } => loc.as_ref(),
            Self::Set { loc, .. } => loc.as_ref(),
            Self::Record { loc, .. } => loc.as_ref(),
            Self::ExtensionValue { loc, .. } => loc.as_ref(),
        }
    }

    /// If the value is a Literal, get a reference to the underlying Literal
    pub(crate) fn try_as_lit(&self) -> Option<&Literal> {
        match self {
            Self::Lit { lit, .. } => Some(lit),
            _ => None,
        }
    }

    /// The `PartialEq` and `Eq` implementations for `Value` ignore the source location.
    /// If you actually want to check that two values are equal _and_ have the
    /// same source location, you can use this.
    pub fn eq_and_same_source_loc(&self, other: &Self) -> bool {
        self == other && self.source_loc() == other.source_loc()
    }
}

#[derive(Debug, Error)]
/// An error that can be thrown converting an expression to a value
pub enum NotValue {
    /// General error for non-values
    #[error("not a value")]
    NotValue {
        /// Source location info for the expr that wasn't a value
        loc: Option<Loc>,
    },
}

impl Diagnostic for NotValue {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        match self {
            Self::NotValue { loc } => loc.as_ref().map(|loc| {
                Box::new(std::iter::once(miette::LabeledSpan::underline(loc.span)))
                    as Box<dyn Iterator<Item = _>>
            }),
        }
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        match self {
            Self::NotValue { loc } => loc.as_ref().map(|loc| &loc.src as &dyn miette::SourceCode),
        }
    }
}

impl TryFrom<Expr> for Value {
    type Error = NotValue;

    fn try_from(value: Expr) -> Result<Self, Self::Error> {
        let loc = value.source_loc().cloned();
        match value.into_expr_kind() {
            ExprKind::Lit(lit) => Ok(Value::Lit { lit, loc }),
            ExprKind::Unknown(_) => Err(NotValue::NotValue { loc }),
            ExprKind::Var(_) => Err(NotValue::NotValue { loc }),
            ExprKind::Slot(_) => Err(NotValue::NotValue { loc }),
            ExprKind::If { .. } => Err(NotValue::NotValue { loc }),
            ExprKind::And { .. } => Err(NotValue::NotValue { loc }),
            ExprKind::Or { .. } => Err(NotValue::NotValue { loc }),
            ExprKind::UnaryApp { .. } => Err(NotValue::NotValue { loc }),
            ExprKind::BinaryApp { .. } => Err(NotValue::NotValue { loc }),
            ExprKind::MulByConst { .. } => Err(NotValue::NotValue { loc }),
            ExprKind::ExtensionFunctionApp { .. } => Err(NotValue::NotValue { loc }),
            ExprKind::GetAttr { .. } => Err(NotValue::NotValue { loc }),
            ExprKind::HasAttr { .. } => Err(NotValue::NotValue { loc }),
            ExprKind::Like { .. } => Err(NotValue::NotValue { loc }),
            ExprKind::Is { .. } => Err(NotValue::NotValue { loc }),
            ExprKind::Set(members) => members
                .iter()
                .map(|e| e.clone().try_into())
                .collect::<Result<Set, _>>()
                .map(|set| Value::Set { set, loc }),
            ExprKind::Record(map) => map
                .iter()
                .map(|(k, v)| v.clone().try_into().map(|v: Value| (k.clone(), v)))
                .collect::<Result<BTreeMap<SmolStr, Value>, _>>()
                .map(|m| Value::Record {
                    record: Arc::new(m),
                    loc,
                }),
        }
    }
}

/// `Value`'s internal representation of a `Set`
#[derive(Debug, Clone)]
pub struct Set {
    /// the values in the set, stored in a `BTreeSet`
    pub authoritative: Arc<BTreeSet<Value>>,
    /// if possible, `HashSet<Literal>` representation of the set.
    /// (This is possible if all the elements are literals.)
    /// Some operations are much faster in this case.
    ///
    /// INVARIANT (FastRepr)
    /// we guarantee that if the elements are all
    /// literals, then this will be `Some`. (This allows us to further
    /// optimize e.g. equality checks between sets: for instance, we know
    /// that if one set has `fast` and another does not, the sets can't be
    /// equal.)
    pub fast: Option<Arc<HashSet<Literal>>>,
}

impl Set {
    /// Get the number of items in the set
    pub fn len(&self) -> usize {
        self.authoritative.len()
    }

    /// Convenience method to check if a set is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Borrowed iterator
    pub fn iter(&self) -> impl Iterator<Item = &Value> {
        self.authoritative.iter()
    }
}

impl FromIterator<Value> for Set {
    fn from_iter<T: IntoIterator<Item = Value>>(iter: T) -> Self {
        let (literals, non_literals): (BTreeSet<_>, BTreeSet<_>) = iter
            .into_iter()
            .partition(|v| matches!(v, Value::Lit { .. }));

        if non_literals.is_empty() {
            // INVARIANT (FastRepr)
            // There are 0 non-literals, so we need to populate `fast`
            Self {
                authoritative: Arc::new(literals.clone()), // non_literals is empty, so this drops no items
                fast: Some(Arc::new(
                    literals
                        .into_iter()
                        .map(|v| match v {
                            Value::Lit { lit, .. } => lit,
                            // PANIC SAFETY: This is unreachable as every item in `literals` matches Value::Lit
                            #[allow(clippy::unreachable)]
                            _ => unreachable!(),
                        })
                        .collect(),
                )),
            }
        } else {
            // INVARIANT (FastRepr)
            // There are non-literals, so we need `fast` should be `None`
            // We also need to add all the literals back into the set
            let mut all_items = non_literals;
            let mut literals = literals;
            all_items.append(&mut literals);
            Self {
                authoritative: Arc::new(all_items),
                fast: None,
            }
        }
    }
}

// Trying to derive `PartialEq` for `Value` fails with a compile error (at
// least, as of this writing) due to the `Arc<dyn>`, so we write out the
// implementation manually.
//
// This implementation also ignores the `Loc` of the values.
impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Lit { lit: lit1, .. }, Value::Lit { lit: lit2, .. }) => lit1 == lit2,
            (
                Value::Set {
                    set: Set {
                        fast: Some(rc1), ..
                    },
                    ..
                },
                Value::Set {
                    set: Set {
                        fast: Some(rc2), ..
                    },
                    ..
                },
            ) => rc1 == rc2,
            (
                Value::Set {
                    set: Set { fast: Some(_), .. },
                    ..
                },
                Value::Set {
                    set: Set { fast: None, .. },
                    ..
                },
            ) => false, // due to internal invariant documented on `Set`, we know that one set contains a non-literal and the other does not
            (
                Value::Set {
                    set: Set { fast: None, .. },
                    ..
                },
                Value::Set {
                    set: Set { fast: Some(_), .. },
                    ..
                },
            ) => false, // due to internal invariant documented on `Set`, we know that one set contains a non-literal and the other does not
            (
                Value::Set {
                    set: Set {
                        authoritative: a1, ..
                    },
                    ..
                },
                Value::Set {
                    set: Set {
                        authoritative: a2, ..
                    },
                    ..
                },
            ) => a1 == a2,
            (Value::Record { record: r1, .. }, Value::Record { record: r2, .. }) => r1 == r2,
            (Value::ExtensionValue { ev: ev1, .. }, Value::ExtensionValue { ev: ev2, .. }) => {
                ev1 == ev2
            }
            (_, _) => false, // values of different types are not equal
        }
    }
}

impl Eq for Value {}

// PartialEq on Set compares only the `authoritative` version
impl PartialEq for Set {
    fn eq(&self, other: &Self) -> bool {
        self.authoritative.as_ref() == other.authoritative.as_ref()
    }
}

impl Eq for Set {}

// PartialOrd on Set compares only the `authoritative` version; note that
// HashSet doesn't implement PartialOrd
impl PartialOrd<Set> for Set {
    fn partial_cmp(&self, other: &Set) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// Ord on Set compares only the `authoritative` version; note that HashSet
// doesn't implement Ord
impl Ord for Set {
    fn cmp(&self, other: &Set) -> std::cmp::Ordering {
        self.authoritative
            .as_ref()
            .cmp(other.authoritative.as_ref())
    }
}

impl StaticallyTyped for Value {
    fn type_of(&self) -> Type {
        match self {
            Self::Lit { lit, .. } => lit.type_of(),
            Self::Set { .. } => Type::Set,
            Self::Record { .. } => Type::Record,
            Self::ExtensionValue { ev, .. } => ev.type_of(),
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lit { lit, .. } => write!(f, "{}", lit),
            Self::Set {
                set:
                    Set {
                        fast,
                        authoritative,
                    },
                ..
            } => {
                match authoritative.len() {
                    0 => write!(f, "[]"),
                    n @ 1..=5 => {
                        write!(f, "[")?;
                        if let Some(rc) = fast {
                            // sort the elements, because we want the Display output to be
                            // deterministic, particularly for tests which check equality
                            // of error messages
                            for (i, item) in rc.as_ref().iter().sorted_unstable().enumerate() {
                                write!(f, "{item}")?;
                                if i < n - 1 {
                                    write!(f, ", ")?;
                                }
                            }
                        } else {
                            // don't need to sort the elements in this case because BTreeSet iterates
                            // in a deterministic order already
                            for (i, item) in authoritative.as_ref().iter().enumerate() {
                                write!(f, "{item}")?;
                                if i < n - 1 {
                                    write!(f, ", ")?;
                                }
                            }
                        }
                        write!(f, "]")?;
                        Ok(())
                    }
                    n => write!(f, "<set with {} elements>", n),
                }
            }
            Self::Record { record, .. } => {
                write!(f, "<first-class record with {} fields>", record.len())
            }
            Self::ExtensionValue { ev, .. } => write!(f, "{}", ev),
        }
    }
}

/// Create a `Value` directly from a `Vec<Value>`, or `Vec<T> where T: Into<Value>`
/// (so `Vec<Integer>`, `Vec<String>`, etc)
///
/// This impl does not propagate source location; the resulting `Value` will
/// have no source location info attached
impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Self::set(v.into_iter().map(Into::into), None)
    }
}

/// Create a `Value::Record` from a map of `String` to `Value`
///
/// This impl does not propagate source location; the resulting `Value` will
/// have no source location info attached
impl<S> From<BTreeMap<S, Value>> for Value
where
    S: Into<SmolStr>,
{
    fn from(map: BTreeMap<S, Value>) -> Self {
        Self::Record {
            record: Arc::new(map.into_iter().map(|(k, v)| (k.into(), v)).collect()),
            loc: None,
        }
    }
}

/// As above, create a `Value::Record` from a map of `SmolStr` to `Value`.
/// This implementation provides conversion from `HashMap` while the earlier
/// implementation provides conversion from `BTreeMap`.
///
/// This impl does not propagate source location; the resulting `Value` will
/// have no source location info attached
impl<S> From<HashMap<S, Value>> for Value
where
    S: Into<SmolStr>,
{
    fn from(map: HashMap<S, Value>) -> Self {
        Self::Record {
            record: Arc::new(map.into_iter().map(|(k, v)| (k.into(), v)).collect()),
            loc: None,
        }
    }
}

/// Create a `Value` directly from a `Vec` of `(String, Value)` pairs, which
/// will be interpreted as (field, value) pairs for a first-class record
///
/// This impl does not propagate source location; the resulting `Value` will
/// have no source location info attached
impl From<Vec<(SmolStr, Value)>> for Value {
    fn from(v: Vec<(SmolStr, Value)>) -> Self {
        Self::Record {
            record: Arc::new(v.into_iter().collect()),
            loc: None,
        }
    }
}

/// Create a `Value` directly from a `Literal`, or from anything that implements
/// `Into<Literal>` (so `Integer`, `&str`, `EntityUID`, etc)
///
/// This impl does not propagate source location; the resulting `Value` will
/// have no source location info attached
impl<T: Into<Literal>> From<T> for Value {
    fn from(lit: T) -> Self {
        Self::Lit {
            lit: lit.into(),
            loc: None,
        }
    }
}

impl PartialValue {
    /// Create a new `PartialValue` consisting of just this single `Unknown`
    pub fn unknown(u: Unknown) -> Self {
        Self::Residual(Expr::unknown(u))
    }

    /// Return the `PartialValue`, but with the given `Loc` (or `None`)
    pub fn with_maybe_source_loc(self, loc: Option<Loc>) -> Self {
        match self {
            Self::Value(v) => Self::Value(v.with_maybe_source_loc(loc)),
            Self::Residual(e) => Self::Residual(e.with_maybe_source_loc(loc)),
        }
    }
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn values() {
        assert_eq!(
            Value::from(true),
            Value::Lit {
                lit: Literal::Bool(true),
                loc: None,
            },
        );
        assert_eq!(
            Value::from(false),
            Value::Lit {
                lit: Literal::Bool(false),
                loc: None,
            },
        );
        assert_eq!(
            Value::from(23),
            Value::Lit {
                lit: Literal::Long(23),
                loc: None,
            },
        );
        assert_eq!(
            Value::from(-47),
            Value::Lit {
                lit: Literal::Long(-47),
                loc: None,
            },
        );
        assert_eq!(
            Value::from("hello"),
            Value::Lit {
                lit: Literal::String("hello".into()),
                loc: None,
            },
        );
        assert_eq!(
            Value::from("hello".to_owned()),
            Value::Lit {
                lit: Literal::String("hello".into()),
                loc: None,
            },
        );
        assert_eq!(
            Value::from(String::new()),
            Value::Lit {
                lit: Literal::String(SmolStr::default()),
                loc: None,
            },
        );
        assert_eq!(
            Value::from(""),
            Value::Lit {
                lit: Literal::String(SmolStr::default()),
                loc: None,
            },
        );
        assert_eq!(
            Value::from(vec![2, -3, 40]),
            Value::set(vec![Value::from(2), Value::from(-3), Value::from(40)], None),
        );
        assert_eq!(
            Value::from(vec![Literal::from(false), Literal::from("eggs")]),
            Value::set(vec![Value::from(false), Value::from("eggs")], None),
        );
        assert_eq!(
            Value::set(vec![Value::from(false), Value::from("eggs")], None),
            Value::set_of_lits(vec![Literal::from(false), Literal::from("eggs")], None),
        );

        let mut rec1: BTreeMap<SmolStr, Value> = BTreeMap::new();
        rec1.insert("ham".into(), 3.into());
        rec1.insert("eggs".into(), "hickory".into());
        assert_eq!(
            Value::from(rec1.clone()),
            Value::Record {
                record: Arc::new(rec1),
                loc: None,
            },
        );

        let mut rec2: BTreeMap<SmolStr, Value> = BTreeMap::new();
        rec2.insert("hi".into(), "ham".into());
        rec2.insert("eggs".into(), "hickory".into());
        assert_eq!(
            Value::from(vec![
                ("hi".into(), "ham".into()),
                ("eggs".into(), "hickory".into()),
            ]),
            Value::Record {
                record: Arc::new(rec2),
                loc: None,
            },
        );

        assert_eq!(
            Value::from(EntityUID::with_eid("foo")),
            Value::Lit {
                lit: Literal::EntityUID(Arc::new(EntityUID::with_eid("foo"))),
                loc: None,
            },
        );
    }

    #[test]
    fn value_types() {
        assert_eq!(Value::from(false).type_of(), Type::Bool);
        assert_eq!(Value::from(23).type_of(), Type::Long);
        assert_eq!(Value::from(-47).type_of(), Type::Long);
        assert_eq!(Value::from("hello").type_of(), Type::String);
        assert_eq!(Value::from(vec![2, -3, 40]).type_of(), Type::Set);
        assert_eq!(Value::empty_set(None).type_of(), Type::Set);
        assert_eq!(Value::empty_record(None).type_of(), Type::Record);
        assert_eq!(
            Value::from(vec![("hello".into(), Value::from("ham"))]).type_of(),
            Type::Record
        );
        assert_eq!(
            Value::from(EntityUID::with_eid("foo")).type_of(),
            Type::entity_type(
                Name::parse_unqualified_name("test_entity_type").expect("valid identifier")
            )
        );
    }

    #[test]
    fn test_set_is_empty_for_empty_set() {
        let set = Set {
            authoritative: Arc::new(BTreeSet::new()),
            fast: Some(Arc::new(HashSet::new())),
        };
        assert!(set.is_empty());
    }

    #[test]
    fn test_set_is_not_empty_for_set_with_values() {
        let set = Set {
            authoritative: Arc::new(BTreeSet::from([Value::from("abc")])),
            fast: None,
        };
        assert!(!set.is_empty());
    }

    #[test]
    fn pretty_printer() {
        assert_eq!(Value::from("abc").to_string(), r#""abc""#);
        assert_eq!(Value::from("\t").to_string(), r#""\t""#);
        assert_eq!(Value::from("🐈").to_string(), r#""🐈""#);
    }

    #[test]
    fn set_collect() {
        let v = vec![Value::Lit {
            lit: 1.into(),
            loc: None,
        }];
        let set: Set = v.into_iter().collect();
        assert_eq!(set.len(), 1);
        let v2 = vec![Value::Set { set, loc: None }];
        let set2: Set = v2.into_iter().collect();
        assert_eq!(set2.len(), 1);
    }
}
