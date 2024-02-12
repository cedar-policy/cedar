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
use std::collections::{BTreeMap, BTreeSet, HashSet};
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
pub struct Value {
    /// Underlying actual value
    pub value: ValueKind,
    /// Source location associated with the value, if any
    pub loc: Option<Loc>,
}

/// This describes all the values which could be the dynamic result of evaluating an `Expr`.
/// Cloning is O(1).
#[derive(Debug, Clone, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "Expr")]
#[serde(try_from = "Expr")]
pub enum ValueKind {
    /// anything that is a Literal can also be the dynamic result of evaluating an `Expr`
    Lit(Literal),
    /// Evaluating an `Expr` can result in a first-class set
    Set(Set),
    /// Evaluating an `Expr` can result in a first-class anonymous record (keyed on String)
    Record(Arc<BTreeMap<SmolStr, Value>>),
    /// Evaluating an `Expr` can result in an extension value
    ExtensionValue(Arc<ExtensionValueWithArgs>),
}

// Custom impl of `Ord`, ignoring the `Loc`s
impl Ord for Value {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl PartialOrd<Value> for Value {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // delegate to `Ord`
        Some(self.cmp(other))
    }
}

impl Value {
    /// Create a new empty set
    pub fn empty_set(loc: Option<Loc>) -> Self {
        Self {
            value: ValueKind::empty_set(),
            loc,
        }
    }

    /// Create a new empty record
    pub fn empty_record(loc: Option<Loc>) -> Self {
        Self {
            value: ValueKind::empty_record(),
            loc,
        }
    }

    /// Create a `Value` from anything that implements `Into<ValueKind>` and an
    /// optional source location
    pub fn new(value: impl Into<ValueKind>, loc: Option<Loc>) -> Self {
        Self {
            value: value.into(),
            loc,
        }
    }

    /// Create a set with the given `Value`s as elements
    pub fn set(vals: impl IntoIterator<Item = Value>, loc: Option<Loc>) -> Self {
        Self {
            value: ValueKind::set(vals),
            loc,
        }
    }

    /// Create a set with the given `Literal`s as elements
    ///
    /// the resulting `Value` will have the given `loc` attached, but its
    /// individual `Literal` elements will not have a source loc attached
    pub fn set_of_lits(lits: impl IntoIterator<Item = Literal>, loc: Option<Loc>) -> Self {
        Self {
            value: ValueKind::set_of_lits(lits),
            loc,
        }
    }

    /// Create a record with the given (key, value) pairs
    pub fn record<K: Into<SmolStr>, V: Into<Value>>(
        pairs: impl IntoIterator<Item = (K, V)>,
        loc: Option<Loc>,
    ) -> Self {
        Self {
            value: ValueKind::record(pairs),
            loc,
        }
    }

    /// Return the `Value`, but with the given `Loc` (or `None`)
    pub fn with_maybe_source_loc(self, loc: Option<Loc>) -> Self {
        Self { loc, ..self }
    }

    /// Get the `ValueKind` for this `Value`
    pub fn value_kind(&self) -> &ValueKind {
        &self.value
    }

    /// Get the `Loc` attached to this `Value`, if there is one
    pub fn source_loc(&self) -> Option<&Loc> {
        self.loc.as_ref()
    }

    /// If the value is a `Literal`, get a reference to the underlying `Literal`
    pub(crate) fn try_as_lit(&self) -> Option<&Literal> {
        self.value.try_as_lit()
    }

    /// The `PartialEq` and `Eq` implementations for `Value` ignore the source location.
    /// If you actually want to check that two values are equal _and_ have the
    /// same source location, you can use this.
    pub fn eq_and_same_source_loc(&self, other: &Self) -> bool {
        self == other && self.source_loc() == other.source_loc()
    }
}

impl ValueKind {
    /// Create a new empty set
    pub fn empty_set() -> Self {
        Self::Set(Set::empty())
    }

    /// Create a new empty record
    pub fn empty_record() -> Self {
        Self::Record(Arc::new(BTreeMap::new()))
    }

    /// Create a set with the given `Value`s as elements
    pub fn set(vals: impl IntoIterator<Item = Value>) -> Self {
        Self::Set(Set::new(vals))
    }

    /// Create a set with the given `Literal`s as elements
    pub fn set_of_lits(lits: impl IntoIterator<Item = Literal>) -> Self {
        Self::Set(Set::from_lits(lits))
    }

    /// Create a record with the given (key, value) pairs
    pub fn record<K: Into<SmolStr>, V: Into<Value>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        Self::Record(Arc::new(
            pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        ))
    }

    /// If the value is a `Literal`, get a reference to the underlying `Literal`
    pub(crate) fn try_as_lit(&self) -> Option<&Literal> {
        match &self {
            Self::Lit(lit) => Some(lit),
            _ => None,
        }
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

    fn try_from(expr: Expr) -> Result<Self, Self::Error> {
        let loc = expr.source_loc().cloned();
        Ok(Self {
            value: ValueKind::try_from(expr)?,
            loc,
        })
    }
}

impl TryFrom<Expr> for ValueKind {
    type Error = NotValue;

    fn try_from(expr: Expr) -> Result<Self, Self::Error> {
        let loc = expr.source_loc().cloned();
        match expr.into_expr_kind() {
            ExprKind::Lit(lit) => Ok(Self::Lit(lit)),
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
                .map(|e| Value::try_from(e.clone()))
                .collect::<Result<Set, _>>()
                .map(Self::Set),
            ExprKind::Record(map) => map
                .iter()
                .map(|(k, v)| Value::try_from(v.clone()).map(|v| (k.clone(), v)))
                .collect::<Result<BTreeMap<SmolStr, Value>, _>>()
                .map(|m| Self::Record(Arc::new(m))),
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
    /// Create an empty set
    pub fn empty() -> Self {
        Self {
            authoritative: Arc::new(BTreeSet::new()),
            fast: Some(Arc::new(HashSet::new())),
        }
    }

    /// Create a set with the given `Value`s as elements
    pub fn new(vals: impl IntoIterator<Item = Value>) -> Self {
        let authoritative: BTreeSet<Value> = vals.into_iter().collect();
        let fast: Option<Arc<HashSet<Literal>>> = authoritative
            .iter()
            .map(|v| v.try_as_lit().cloned())
            .collect::<Option<HashSet<Literal>>>()
            .map(Arc::new);
        Self {
            authoritative: Arc::new(authoritative),
            fast,
        }
    }

    /// Create a set with the given `Literal`s as elements
    pub fn from_lits(lits: impl IntoIterator<Item = Literal>) -> Self {
        let fast: HashSet<Literal> = lits.into_iter().collect();
        let authoritative: BTreeSet<Value> = fast
            .iter()
            .map(|lit| Value {
                value: ValueKind::Lit(lit.clone()),
                loc: None,
            })
            .collect();
        Self {
            authoritative: Arc::new(authoritative),
            fast: Some(Arc::new(fast)),
        }
    }

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
            .partition(|v| matches!(&v.value, ValueKind::Lit { .. }));

        if non_literals.is_empty() {
            Self::from_iter(literals.into_iter().map(|v| match v {
                Value {
                    value: ValueKind::Lit(lit),
                    ..
                } => lit,
                // PANIC SAFETY: This is unreachable as every item in `literals` matches ValueKind::Lit
                #[allow(clippy::unreachable)]
                _ => unreachable!(),
            }))
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

impl FromIterator<Literal> for Set {
    fn from_iter<T: IntoIterator<Item = Literal>>(iter: T) -> Self {
        // INVARIANT (FastRepr)
        // There are 0 non-literals, so we need to populate `fast`
        let fast: HashSet<Literal> = iter.into_iter().collect();
        Self {
            authoritative: Arc::new(fast.iter().cloned().map(Into::into).collect()),
            fast: Some(Arc::new(fast)),
        }
    }
}

// Trying to derive `PartialEq` for `ValueKind` fails with a compile error (at
// least, as of this writing) due to the `Arc<dyn>`, so we write out the
// implementation manually.
impl PartialEq for ValueKind {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ValueKind::Lit(lit1), ValueKind::Lit(lit2)) => lit1 == lit2,
            (ValueKind::Set(set1), ValueKind::Set(set2)) => set1 == set2,
            (ValueKind::Record(r1), ValueKind::Record(r2)) => r1 == r2,
            (ValueKind::ExtensionValue(ev1), ValueKind::ExtensionValue(ev2)) => ev1 == ev2,
            (_, _) => false, // values of different types are not equal
        }
    }
}

impl Eq for ValueKind {}

// The implementation of `PartialEq` for `Value` ignores the `Loc` of the values.
impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        self.value == other.value
    }
}

impl Eq for Value {}

// PartialEq on Set is optimized to take advantage of the internal invariant documented on `Set`
impl PartialEq for Set {
    fn eq(&self, other: &Self) -> bool {
        match (self.fast.as_ref(), other.fast.as_ref()) {
            (Some(rc1), Some(rc2)) => rc1 == rc2,
            (Some(_), None) => false, // due to internal invariant documented on `Set`, we know that one set contains a non-literal and the other does not
            (None, Some(_)) => false, // due to internal invariant documented on `Set`, we know that one set contains a non-literal and the other does not
            (None, None) => self.authoritative.as_ref() == other.authoritative.as_ref(),
        }
    }
}

impl Eq for Set {}

// Ord on Set compares only the `authoritative` version; note that HashSet
// doesn't implement Ord
impl Ord for Set {
    fn cmp(&self, other: &Set) -> std::cmp::Ordering {
        self.authoritative
            .as_ref()
            .cmp(other.authoritative.as_ref())
    }
}

impl PartialOrd<Set> for Set {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // delegate to `Ord`
        Some(self.cmp(other))
    }
}

impl StaticallyTyped for Value {
    fn type_of(&self) -> Type {
        self.value.type_of()
    }
}

impl StaticallyTyped for ValueKind {
    fn type_of(&self) -> Type {
        match self {
            Self::Lit(lit) => lit.type_of(),
            Self::Set(_) => Type::Set,
            Self::Record(_) => Type::Record,
            Self::ExtensionValue(ev) => ev.type_of(),
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl std::fmt::Display for ValueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lit(lit) => write!(f, "{}", lit),
            Self::Set(Set {
                fast,
                authoritative,
            }) => {
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
            Self::Record(record) => {
                write!(f, "<first-class record with {} fields>", record.len())
            }
            Self::ExtensionValue(ev) => write!(f, "{}", ev),
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

/// Create a `ValueKind` directly from a `Vec<Value>`, or `Vec<T> where T: Into<Value>`
/// (so `Vec<Integer>`, `Vec<String>`, etc)
impl<T: Into<Value>> From<Vec<T>> for ValueKind {
    fn from(v: Vec<T>) -> Self {
        Self::set(v.into_iter().map(Into::into))
    }
}

/// Create a `Value` directly from a `Literal`, or from anything that implements
/// `Into<Literal>` (so `Integer`, `&str`, `EntityUID`, etc)
///
/// This impl does not propagate source location; the resulting `Value` will
/// have no source location info attached
impl<T: Into<Literal>> From<T> for Value {
    fn from(lit: T) -> Self {
        Self {
            value: lit.into().into(),
            loc: None,
        }
    }
}

/// Create a `ValueKind` directly from a `Literal`, or from anything that implements
/// `Into<Literal>` (so `Integer`, `&str`, `EntityUID`, etc)
impl<T: Into<Literal>> From<T> for ValueKind {
    fn from(lit: T) -> Self {
        Self::Lit(lit.into())
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
            Value {
                value: ValueKind::Lit(Literal::Bool(true)),
                loc: None,
            },
        );
        assert_eq!(
            Value::from(false),
            Value {
                value: ValueKind::Lit(Literal::Bool(false)),
                loc: None,
            },
        );
        assert_eq!(
            Value::from(23),
            Value {
                value: ValueKind::Lit(Literal::Long(23)),
                loc: None,
            },
        );
        assert_eq!(
            Value::from(-47),
            Value {
                value: ValueKind::Lit(Literal::Long(-47)),
                loc: None,
            },
        );
        assert_eq!(
            Value::from("hello"),
            Value {
                value: ValueKind::Lit(Literal::String("hello".into())),
                loc: None,
            },
        );
        assert_eq!(
            Value::from("hello".to_owned()),
            Value {
                value: ValueKind::Lit(Literal::String("hello".into())),
                loc: None,
            },
        );
        assert_eq!(
            Value::from(String::new()),
            Value {
                value: ValueKind::Lit(Literal::String(SmolStr::default())),
                loc: None,
            },
        );
        assert_eq!(
            Value::from(""),
            Value {
                value: ValueKind::Lit(Literal::String(SmolStr::default())),
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
            Value::record(rec1.clone(), None),
            Value {
                value: ValueKind::Record(Arc::new(rec1)),
                loc: None,
            },
        );

        let mut rec2: BTreeMap<SmolStr, Value> = BTreeMap::new();
        rec2.insert("hi".into(), "ham".into());
        rec2.insert("eggs".into(), "hickory".into());
        assert_eq!(
            Value::record(vec![("hi", "ham"), ("eggs", "hickory"),], None),
            Value {
                value: ValueKind::Record(Arc::new(rec2)),
                loc: None,
            },
        );

        assert_eq!(
            Value::from(EntityUID::with_eid("foo")),
            Value {
                value: ValueKind::Lit(Literal::EntityUID(Arc::new(EntityUID::with_eid("foo")))),
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
            Value::record(vec![("hello", Value::from("ham"))], None).type_of(),
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
        let v = vec![Value {
            value: 1.into(),
            loc: None,
        }];
        let set: Set = v.into_iter().collect();
        assert_eq!(set.len(), 1);
        let v2 = vec![Value {
            value: ValueKind::Set(set),
            loc: None,
        }];
        let set2: Set = v2.into_iter().collect();
        assert_eq!(set2.len(), 1);
    }
}
