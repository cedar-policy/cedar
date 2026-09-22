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

use smol_str::SmolStr;
use std::collections::BTreeSet;

use crate::ast::{Expr, ExprShapeOnly};

/// One half of a [`CapabilitySet`].
///
/// The empty and one-element cases are represented inline, without allocating:
/// a `has` check establishes exactly one capability, and a condition guarding a
/// single attribute is by far the most common shape, so those two cases dominate.
/// A `BTreeSet` allocates a node per element, which measurably dominated the cost
/// of the linter passes that thread these sets through every expression node.
///
/// `Many` is not used for fewer than two elements, but equality is defined over
/// the elements rather than the representation, so a missed normalization can
/// never make two equal sets compare unequal.
#[derive(Eq, Debug, Clone, Default)]
enum CapabilityHalf<'a> {
    #[default]
    Empty,
    One(Capability<'a>),
    Many(BTreeSet<Capability<'a>>),
}

impl<'a> CapabilityHalf<'a> {
    /// Build from a `BTreeSet`, collapsing to the inline cases when small so the
    /// representation stays canonical.
    fn from_set(set: BTreeSet<Capability<'a>>) -> Self {
        match set.len() {
            0 => Self::Empty,
            // `next().expect` cannot fail: the length is exactly 1.
            1 => Self::One(
                set.into_iter()
                    .next()
                    .expect("a set of length 1 has a first element"),
            ),
            _ => Self::Many(set),
        }
    }

    fn contains(&self, e: &Capability<'_>) -> bool {
        match self {
            Self::Empty => false,
            Self::One(c) => c == e,
            Self::Many(set) => set.contains(e),
        }
    }

    /// Every capability in either half.
    fn union(self, other: &Self) -> Self {
        match (self, other) {
            (Self::Empty, o) => o.clone(),
            (s, Self::Empty) => s,
            (Self::One(a), Self::One(b)) => {
                if &a == b {
                    Self::One(a)
                } else {
                    Self::Many(BTreeSet::from([a, b.clone()]))
                }
            }
            (Self::One(a), Self::Many(m)) => {
                let mut m = m.clone();
                m.insert(a);
                Self::Many(m)
            }
            // `m` already holds at least two elements, so it stays `Many`.
            (Self::Many(mut m), Self::One(b)) => {
                m.insert(b.clone());
                Self::Many(m)
            }
            (Self::Many(mut m), Self::Many(o)) => {
                m.extend(o.iter().cloned());
                Self::Many(m)
            }
        }
    }

    /// Only the capabilities in both halves.
    fn intersect(self, other: &Self) -> Self {
        match (self, other) {
            (Self::Empty, _) | (_, Self::Empty) => Self::Empty,
            (Self::One(a), o) => {
                if o.contains(&a) {
                    Self::One(a)
                } else {
                    Self::Empty
                }
            }
            (Self::Many(m), Self::One(b)) => {
                if m.contains(b) {
                    Self::One(b.clone())
                } else {
                    Self::Empty
                }
            }
            (Self::Many(mut m), Self::Many(o)) => {
                m.retain(|k| o.contains(k));
                Self::from_set(m)
            }
        }
    }
}

// Compares the capabilities held, not how they are represented, so that
// `One(c)` and a one-element `Many` are equal.
impl PartialEq for CapabilityHalf<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Empty, Self::Empty) => true,
            (Self::One(a), Self::One(b)) => a == b,
            (Self::Many(a), Self::Many(b)) => a == b,
            (Self::One(a), Self::Many(m)) | (Self::Many(m), Self::One(a)) => {
                m.len() == 1 && m.contains(a)
            }
            _ => false,
        }
    }
}

/// A set of capabilities. Used to represent knowledge about attribute existence
/// before and after evaluating an expression.
///
/// The `positive` half holds what is known when the expression evaluates to
/// `true`, the `negative` half what is known when it evaluates to `false`;
/// [`CapabilitySet::negate`] swaps them.
#[derive(Eq, PartialEq, Debug, Clone, Default)]
pub struct CapabilitySet<'a> {
    positive: CapabilityHalf<'a>,
    negative: CapabilityHalf<'a>,
}

impl<'a> CapabilitySet<'a> {
    /// An empty capability set
    pub fn new() -> Self {
        CapabilitySet {
            positive: CapabilityHalf::Empty,
            negative: CapabilityHalf::Empty,
        }
    }

    /// A capability set with a single [`Capability`]
    pub fn singleton(e: Capability<'a>) -> Self {
        CapabilitySet {
            positive: CapabilityHalf::One(e),
            negative: CapabilityHalf::Empty,
        }
    }

    /// The capabilities established by `self && other`: a conjunction is true
    /// when both sides are, so positive capabilities accumulate, and false when
    /// either is, so only negative capabilities common to both survive.
    pub fn and(mut self, other: &Self) -> Self {
        self.positive = self.positive.union(&other.positive);
        self.negative = self.negative.intersect(&other.negative);
        self
    }

    /// The capabilities established by `self || other`, the dual of
    /// [`CapabilitySet::and`].
    pub fn or(mut self, other: &Self) -> Self {
        self.positive = self.positive.intersect(&other.positive);
        self.negative = self.negative.union(&other.negative);
        self
    }

    /// Swaps positive and negative capabilities.
    pub fn negate(self) -> Self {
        CapabilitySet {
            positive: self.negative,
            negative: self.positive,
        }
    }

    /// Does this capability set contain the given [`Capability`]
    pub fn contains(&self, e: &Capability<'_>) -> bool {
        self.positive.contains(e)
    }

    /// Does this capability set contain the negation of the given [`Capability`]
    pub fn contains_negation(&self, e: &Capability<'_>) -> bool {
        self.negative.contains(e)
    }
}

/// Represent a single capability, which is an expression and some attribute that is
/// known to exist for that expression.
#[derive(Eq, PartialEq, Debug, Clone, PartialOrd, Ord)]
pub struct Capability<'a> {
    /// For this expression
    on_expr: ExprShapeOnly<'a, ()>,
    /// This attribute or tag is known to exist on that expression
    ///
    /// This expression represents the attribute or tag name. It should have type string.
    /// Often this is a string constant, but in the case of tags it can be an expression.
    attribute_or_tag: ExprShapeOnly<'a, ()>,
    /// Is `attribute_or_tag` an attribute name or a tag name
    kind: CapabilityKind,
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, PartialOrd, Ord)]
enum CapabilityKind {
    /// This capability is for accessing attributes
    Attribute,
    /// This capability is for accessing tags
    Tag,
}

impl<'a> Capability<'a> {
    /// Construct a new [`Capability`] stating that the attribute `attribute` is
    /// known to exist for the expression `on_expr`
    pub fn new_attribute(on_expr: &'a Expr<()>, attribute: SmolStr) -> Self {
        Self {
            on_expr: ExprShapeOnly::new_from_borrowed(on_expr),
            attribute_or_tag: ExprShapeOnly::new_from_owned(Expr::val(attribute)),
            kind: CapabilityKind::Attribute,
        }
    }

    /// Construct a new [`Capability`] stating that the attribute `attribute` is
    /// known to exist for the owned expression `on_expr`
    pub fn new_attribute_owned(on_expr: Expr<()>, attribute: SmolStr) -> Self {
        Self {
            on_expr: ExprShapeOnly::new_from_owned(on_expr),
            attribute_or_tag: ExprShapeOnly::new_from_owned(Expr::val(attribute)),
            kind: CapabilityKind::Attribute,
        }
    }

    /// Construct a new [`Capability`] stating that the tag `tag` is
    /// known to exist for the expression `on_expr`
    pub fn new_borrowed_tag(on_expr: &'a Expr<()>, tag: &'a Expr<()>) -> Self {
        Self {
            on_expr: ExprShapeOnly::new_from_borrowed(on_expr),
            attribute_or_tag: ExprShapeOnly::new_from_borrowed(tag),
            kind: CapabilityKind::Tag,
        }
    }

    /// Construct a new [`Capability`] stating that the tag `tag` is
    /// known to exist for the expression `on_expr`
    pub fn new_owned_tag(on_expr: &'a Expr<()>, tag: Expr<()>) -> Self {
        Self {
            on_expr: ExprShapeOnly::new_from_borrowed(on_expr),
            attribute_or_tag: ExprShapeOnly::new_from_owned(tag),
            kind: CapabilityKind::Tag,
        }
    }
}
