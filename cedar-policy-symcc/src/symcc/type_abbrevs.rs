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
use std::{cmp::Ordering, num::NonZeroU32, ops::Deref};

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
/// In our code, widths are not allowed to be 0.
///
/// In Lean, we do not enforce this at the type level, as our proofs ensure things all work properly.
/// Here in Rust, we enforce this at the type level using the standard library's `NonZeroU32`.
pub type Width = NonZeroU32;

/// Width of one bit
pub const ONE: Width = NonZeroU32::new(1).expect("1 is not 0"); // this `expect()` is evaluated at compile-time because this is a `const`. Clippy is smart enough not to require `expect_used` for this.
/// Width of two bits
pub const TWO: Width = NonZeroU32::new(2).expect("2 is not 0"); // this `expect()` is evaluated at compile-time because this is a `const`. Clippy is smart enough not to require `expect_used` for this.
/// Width of five bits
pub const FIVE: Width = NonZeroU32::new(5).expect("5 is not 0"); // this `expect()` is evaluated at compile-time because this is a `const`. Clippy is smart enough not to require `expect_used` for this.
/// Width of seven bits
pub const SEVEN: Width = NonZeroU32::new(7).expect("7 is not 0"); // this `expect()` is evaluated at compile-time because this is a `const`. Clippy is smart enough not to require `expect_used` for this.
/// Width of eight bits
pub const EIGHT: Width = NonZeroU32::new(8).expect("8 is not 0"); // this `expect()` is evaluated at compile-time because this is a `const`. Clippy is smart enough not to require `expect_used` for this.
/// Width of 16 bits
pub const SIXTEEN: Width = NonZeroU32::new(16).expect("16 is not 0"); // this `expect()` is evaluated at compile-time because this is a `const`. Clippy is smart enough not to require `expect_used` for this.
/// Width of 32 bits
pub const THIRTY_TWO: Width = NonZeroU32::new(32).expect("32 is not 0"); // this `expect()` is evaluated at compile-time because this is a `const`. Clippy is smart enough not to require `expect_used` for this.
/// Width of 64 bits
pub const SIXTY_FOUR: Width = NonZeroU32::new(64).expect("64 is not 0"); // this `expect()` is evaluated at compile-time because this is a `const`. Clippy is smart enough not to require `expect_used` for this.
/// Width of 120 bits
pub const HUNDRED_TWENTY: Width = NonZeroU32::new(120).expect("120 is not 0"); // this `expect()` is evaluated at compile-time because this is a `const`. Clippy is smart enough not to require `expect_used` for this.
/// Width of 128 bits
pub const HUNDRED_TWENTY_EIGHT: Width = NonZeroU32::new(128).expect("128 is not 0"); // this `expect()` is evaluated at compile-time because this is a `const`. Clippy is smart enough not to require `expect_used` for this.

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
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
