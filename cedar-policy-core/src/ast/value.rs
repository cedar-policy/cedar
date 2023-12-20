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
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use itertools::Itertools;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use thiserror::Error;

/// This describes all the values which could be the dynamic result of evaluating an `Expr`.
/// Cloning is O(1).
#[derive(Debug, Clone, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "Expr")]
#[serde(try_from = "Expr")]
pub enum Value {
    /// anything that is a Literal can also be the dynamic result of evaluating an `Expr`
    Lit(Literal),
    /// Evaluating an `Expr` can result in a first-class set
    Set(Set),
    /// Evaluating an `Expr` can result in a first-class anonymous record (keyed on String)
    Record(Arc<BTreeMap<SmolStr, Value>>),
    /// Evaluating an `Expr` can result in an extension value
    ExtensionValue(Arc<ExtensionValueWithArgs>),
}

#[derive(Debug, Diagnostic, Error)]
/// An error that can be thrown converting an expression to a value
pub enum NotValue {
    /// General error for non-values
    #[error("not a value")]
    NotValue,
}

impl TryFrom<Expr> for Value {
    type Error = NotValue;

    fn try_from(value: Expr) -> Result<Self, Self::Error> {
        match value.into_expr_kind() {
            ExprKind::Lit(lit) => Ok(Value::Lit(lit)),
            ExprKind::Unknown(_) => Err(NotValue::NotValue),
            ExprKind::Var(_) => Err(NotValue::NotValue),
            ExprKind::Slot(_) => Err(NotValue::NotValue),
            ExprKind::If { .. } => Err(NotValue::NotValue),
            ExprKind::And { .. } => Err(NotValue::NotValue),
            ExprKind::Or { .. } => Err(NotValue::NotValue),
            ExprKind::UnaryApp { .. } => Err(NotValue::NotValue),
            ExprKind::BinaryApp { .. } => Err(NotValue::NotValue),
            ExprKind::MulByConst { .. } => Err(NotValue::NotValue),
            ExprKind::ExtensionFunctionApp { .. } => Err(NotValue::NotValue),
            ExprKind::GetAttr { .. } => Err(NotValue::NotValue),
            ExprKind::HasAttr { .. } => Err(NotValue::NotValue),
            ExprKind::Like { .. } => Err(NotValue::NotValue),
            ExprKind::Is { .. } => Err(NotValue::NotValue),
            ExprKind::Set(members) => members
                .iter()
                .map(|e| e.clone().try_into())
                .collect::<Result<Set, _>>()
                .map(Value::Set),
            ExprKind::Record(map) => map
                .iter()
                .map(|(k, v)| v.clone().try_into().map(|v: Value| (k.clone(), v)))
                .collect::<Result<BTreeMap<SmolStr, Value>, _>>()
                .map(|m| Value::Record(Arc::new(m))),
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
        let (literals, non_literals): (BTreeSet<_>, BTreeSet<_>) =
            iter.into_iter().partition(|v| matches!(v, Value::Lit(_)));

        if non_literals.is_empty() {
            // INVARIANT (FastRepr)
            // There are 0 non-literals, so we need to populate `fast`
            Self {
                authoritative: Arc::new(literals.clone()), // non_literals is empty, so this drops no items
                fast: Some(Arc::new(
                    literals
                        .into_iter()
                        .map(|v| match v {
                            Value::Lit(lit) => lit,
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

impl Value {
    /// If the value is a Literal, get a reference to the underlying Literal
    pub(crate) fn try_as_lit(&self) -> Option<&Literal> {
        match self {
            Self::Lit(lit) => Some(lit),
            _ => None,
        }
    }
}

// Trying to derive `PartialEq` for `Value` fails with a compile error (at
// least, as of this writing) due to the `Arc<dyn>`, so we write out the
// implementation manually
impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Lit(l1), Value::Lit(l2)) => l1 == l2,
            (
                Value::Set(Set {
                    fast: Some(rc1), ..
                }),
                Value::Set(Set {
                    fast: Some(rc2), ..
                }),
            ) => rc1 == rc2,
            (Value::Set(Set { fast: Some(_), .. }), Value::Set(Set { fast: None, .. })) => false, // due to internal invariant documented on `Set`, we know that one set contains a non-literal and the other does not
            (Value::Set(Set { fast: None, .. }), Value::Set(Set { fast: Some(_), .. })) => false, // due to internal invariant documented on `Set`, we know that one set contains a non-literal and the other does not
            (
                Value::Set(Set {
                    authoritative: a1, ..
                }),
                Value::Set(Set {
                    authoritative: a2, ..
                }),
            ) => a1 == a2,
            (Value::Record(r1), Value::Record(r2)) => r1 == r2,
            (Value::ExtensionValue(ev1), Value::ExtensionValue(ev2)) => ev1 == ev2,
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
            Self::Lit(lit) => lit.type_of(),
            Self::Set(_) => Type::Set,
            Self::Record(_) => Type::Record,
            Self::ExtensionValue(ev) => ev.type_of(),
        }
    }
}

impl std::fmt::Display for Value {
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
            Self::Record(record) => write!(f, "<first-class record with {} fields>", record.len()),
            Self::ExtensionValue(ev) => write!(f, "{}", ev),
        }
    }
}

/// Create a `Value` directly from a `Vec<Value>`, or `Vec<T> where T: Into<Value>`
/// (so `Vec<Integer>`, `Vec<String>`, etc)
impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Self::set(v.into_iter().map(Into::into))
    }
}

/// Create a `Value::Record` from a map of `String` to `Value`
impl<S> From<BTreeMap<S, Value>> for Value
where
    S: Into<SmolStr>,
{
    fn from(map: BTreeMap<S, Value>) -> Self {
        Self::Record(Arc::new(
            map.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        ))
    }
}

/// As above, create a `Value::Record` from a map of `SmolStr` to `Value`.
/// This implementation provides conversion from `HashMap` while the earlier
/// implementation provides conversion from `BTreeMap`
impl<S> From<HashMap<S, Value>> for Value
where
    S: Into<SmolStr>,
{
    fn from(map: HashMap<S, Value>) -> Self {
        Self::Record(Arc::new(
            map.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        ))
    }
}

/// Create a `Value` directly from a `Vec` of `(String, Value)` pairs, which
/// will be interpreted as (field, value) pairs for a first-class record
impl From<Vec<(SmolStr, Value)>> for Value {
    fn from(v: Vec<(SmolStr, Value)>) -> Self {
        Self::Record(Arc::new(v.into_iter().collect()))
    }
}

/// Create a `Value` directly from a `Literal`, or from anything that implements
/// `Into<Literal>` (so `Integer`, `&str`, `EntityUID`, etc)
impl<T: Into<Literal>> From<T> for Value {
    fn from(lit: T) -> Self {
        Self::Lit(lit.into())
    }
}

impl Value {
    /// Create a new empty set
    pub fn empty_set() -> Self {
        Self::Set(Set {
            authoritative: Arc::new(BTreeSet::new()),
            fast: Some(Arc::new(HashSet::new())),
        })
    }

    /// Create a new empty record
    pub fn empty_record() -> Self {
        Self::Record(Arc::new(BTreeMap::new()))
    }

    /// Create a set with the given `Value`s as elements
    pub fn set(vals: impl IntoIterator<Item = Value>) -> Self {
        let authoritative: BTreeSet<Value> = vals.into_iter().collect();
        let fast: Option<HashSet<Literal>> = authoritative
            .iter()
            .map(|v| v.try_as_lit().cloned())
            .collect();
        if let Some(fast) = fast {
            Self::Set(Set {
                authoritative: Arc::new(authoritative),
                fast: Some(Arc::new(fast)),
            })
        } else {
            Self::Set(Set {
                authoritative: Arc::new(authoritative),
                fast: None,
            })
        }
    }

    /// Create a set with the given `Literal`s as elements
    pub fn set_of_lits(lits: impl IntoIterator<Item = Literal>) -> Self {
        let fast: HashSet<Literal> = lits.into_iter().collect();
        let authoritative: BTreeSet<Value> =
            fast.iter().map(|lit| Value::Lit(lit.clone())).collect();
        Self::Set(Set {
            authoritative: Arc::new(authoritative),
            fast: Some(Arc::new(fast)),
        })
    }
}

impl PartialValue {
    /// Create a new `PartialValue` consisting of just this single `Unknown`
    pub fn unknown(u: Unknown) -> Self {
        Self::Residual(Expr::unknown(u))
    }
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn values() {
        assert_eq!(Value::from(true), Value::Lit(Literal::Bool(true)));
        assert_eq!(Value::from(false), Value::Lit(Literal::Bool(false)));
        assert_eq!(Value::from(23), Value::Lit(Literal::Long(23)));
        assert_eq!(Value::from(-47), Value::Lit(Literal::Long(-47)));
        assert_eq!(
            Value::from("hello"),
            Value::Lit(Literal::String("hello".into()))
        );
        assert_eq!(
            Value::from("hello".to_owned()),
            Value::Lit(Literal::String("hello".into()))
        );
        assert_eq!(
            Value::from(String::new()),
            Value::Lit(Literal::String(SmolStr::default()))
        );
        assert_eq!(
            Value::from(""),
            Value::Lit(Literal::String(SmolStr::default()))
        );
        assert_eq!(
            Value::from(vec![2, -3, 40]),
            Value::set(vec![Value::from(2), Value::from(-3), Value::from(40)])
        );
        assert_eq!(
            Value::from(vec![Literal::from(false), Literal::from("eggs")]),
            Value::set(vec!(Value::from(false), Value::from("eggs")))
        );
        assert_eq!(
            Value::set(vec!(Value::from(false), Value::from("eggs"))),
            Value::set_of_lits(vec!(Literal::from(false), Literal::from("eggs")))
        );

        let mut rec1: BTreeMap<SmolStr, Value> = BTreeMap::new();
        rec1.insert("ham".into(), 3.into());
        rec1.insert("eggs".into(), "hickory".into());
        assert_eq!(Value::from(rec1.clone()), Value::Record(Arc::new(rec1)));

        let mut rec2: BTreeMap<SmolStr, Value> = BTreeMap::new();
        rec2.insert("hi".into(), "ham".into());
        rec2.insert("eggs".into(), "hickory".into());
        assert_eq!(
            Value::from(vec![
                ("hi".into(), "ham".into()),
                ("eggs".into(), "hickory".into())
            ]),
            Value::Record(Arc::new(rec2))
        );

        assert_eq!(
            Value::from(EntityUID::with_eid("foo")),
            Value::Lit(Literal::EntityUID(Arc::new(EntityUID::with_eid("foo"))))
        );
    }

    #[test]
    fn value_types() {
        assert_eq!(Value::from(false).type_of(), Type::Bool);
        assert_eq!(Value::from(23).type_of(), Type::Long);
        assert_eq!(Value::from(-47).type_of(), Type::Long);
        assert_eq!(Value::from("hello").type_of(), Type::String);
        assert_eq!(Value::from(vec![2, -3, 40]).type_of(), Type::Set);
        assert_eq!(Value::empty_set().type_of(), Type::Set);
        assert_eq!(Value::empty_record().type_of(), Type::Record);
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
        let v = vec![Value::Lit(1.into())];
        let s: Set = v.into_iter().collect();
        assert_eq!(s.len(), 1);
        let v2 = vec![Value::Set(s)];
        let s2: Set = v2.into_iter().collect();
        assert_eq!(s2.len(), 1);
    }
}
