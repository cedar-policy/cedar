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

//! Various type abbreviations used throughout SymCC.

use num_bigint::{BigInt, BigUint};
use ref_cast::RefCast;
use smol_str::SmolStr;
use std::{cmp::Ordering, ops::Deref};

#[expect(missing_docs, reason = "existing code")]
pub type EntityType = cedar_policy::EntityTypeName;
#[expect(missing_docs, reason = "existing code")]
pub type EntityID = cedar_policy::EntityId;
#[expect(missing_docs, reason = "existing code")]
pub type EntityUID = cedar_policy::EntityUid;
#[expect(missing_docs, reason = "existing code")]
pub type Attr = SmolStr;
#[expect(missing_docs, reason = "existing code")]
pub type Prim = cedar_policy_core::ast::Literal;

#[expect(missing_docs, reason = "existing code")]
pub type Nat = BigUint;
#[expect(missing_docs, reason = "existing code")]
pub type Int = BigInt;
#[expect(missing_docs, reason = "existing code")]
pub type Width = u32;

/// Convert `ast::EntityType` into `EntityType` in O(1)
pub fn core_entity_type_into_entity_type(
    entity_type: &cedar_policy_core::ast::EntityType,
) -> &EntityType {
    EntityType::ref_cast(entity_type)
}

/// Convert `ast::EntityUID` into `EntityUID` in O(1)
pub fn core_uid_into_uid(uid: &cedar_policy_core::ast::EntityUID) -> &EntityUID {
    EntityUID::ref_cast(uid)
}

/// Types of extensions.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[expect(missing_docs, reason = "existing code")]
pub enum ExtType {
    IpAddr,
    Decimal,
    DateTime,
    Duration,
}

/// Converts [`u32`] to [`Nat`].
pub fn nat(v: u32) -> Nat {
    BigUint::from(v)
}

/// Natural numbers less than some upper bound (corresponds to the Lean Fin type)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Fin {
    upper_bound: Nat,
    v: Nat,
}

impl Fin {
    /// Tries to construct a [`Fin`] with the given bound.
    pub fn try_new(upper_bound: Nat, v: Nat) -> Option<Self> {
        if v < upper_bound {
            Some(Self { upper_bound, v })
        } else {
            None
        }
    }

    /// Converts to [`Nat`].
    pub fn to_nat(&self) -> Nat {
        self.v.clone()
    }
}

/// A wrapper for Cedar [`cedar_policy_core::ast::Pattern`]s.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct OrdPattern(cedar_policy_core::ast::Pattern);

impl From<cedar_policy_core::ast::Pattern> for OrdPattern {
    fn from(p: cedar_policy_core::ast::Pattern) -> Self {
        Self(p)
    }
}

impl Deref for OrdPattern {
    type Target = cedar_policy_core::ast::Pattern;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct OrdPatternElem(cedar_policy_core::ast::PatternElem);

impl From<cedar_policy_core::ast::PatternElem> for OrdPatternElem {
    fn from(e: cedar_policy_core::ast::PatternElem) -> Self {
        Self(e)
    }
}

impl PartialOrd for OrdPatternElem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrdPatternElem {
    fn cmp(&self, other: &Self) -> Ordering {
        use cedar_policy_core::ast::PatternElem;
        match (self.0, other.0) {
            (PatternElem::Char(c1), PatternElem::Char(c2)) => c1.cmp(&c2),
            (PatternElem::Wildcard, PatternElem::Wildcard) => Ordering::Equal,
            (PatternElem::Char(_), PatternElem::Wildcard) => Ordering::Less,
            (PatternElem::Wildcard, PatternElem::Char(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for OrdPattern {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrdPattern {
    fn cmp(&self, other: &Self) -> Ordering {
        self.get_elems()
            .iter()
            .copied()
            .map(OrdPatternElem::from)
            .cmp(other.get_elems().iter().copied().map(OrdPatternElem::from))
    }
}
