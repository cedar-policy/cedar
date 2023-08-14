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

use std::sync::Arc;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use super::PrincipalOrResource;
use crate::{parser::err::ParseError, FromNormalizedStr};

/// Arc::unwrap_or_clone() isn't stabilized as of this writing, but this is its implementation
//
// TODO: use `Arc::unwrap_or_clone()` once stable
pub fn unwrap_or_clone<T: Clone>(arc: Arc<T>) -> T {
    Arc::try_unwrap(arc).unwrap_or_else(|arc| (*arc).clone())
}

/// This is the `Name` type used to name types, functions, etc.
/// The name can include namespaces.
/// Clone is O(1).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Name {
    /// Basename
    pub(crate) id: Id,
    /// Namespaces
    pub(crate) path: Arc<Vec<Id>>,
}

impl Name {
    /// A full constructor for `Name`
    pub fn new(basename: Id, path: impl IntoIterator<Item = Id>) -> Self {
        Self {
            id: basename,
            path: Arc::new(path.into_iter().collect()),
        }
    }

    /// Create a `Name` with no path (no namespaces).
    pub fn unqualified_name(id: Id) -> Self {
        Self {
            id,
            path: Arc::new(vec![]),
        }
    }

    /// Create a `Name` with no path (no namespaces).
    /// Returns an error if `s` is not a valid identifier.
    pub fn parse_unqualified_name(s: &str) -> Result<Self, Vec<ParseError>> {
        Ok(Self {
            id: s.parse()?,
            path: Arc::new(vec![]),
        })
    }

    /// Given a type basename and a namespace (as a `Name` itself),
    /// return a `Name` representing the type's fully qualified name
    pub fn type_in_namespace(basename: Id, namespace: Name) -> Name {
        let mut path = unwrap_or_clone(namespace.path);
        path.push(namespace.id);
        Name::new(basename, path)
    }

    /// Get the basename of the `Name` (ie, with namespaces stripped).
    pub fn basename(&self) -> &Id {
        &self.id
    }

    /// Get the namespace of the `Name`, as components
    pub fn namespace_components(&self) -> impl Iterator<Item = &Id> {
        self.path.iter()
    }

    /// Get the full namespace of the `Name`, as a single string.
    ///
    /// Examples:
    /// - `foo::bar` --> the namespace is `"foo"`
    /// - `bar` --> the namespace is `""`
    /// - `foo::bar::baz` --> the namespace is `"foo::bar"`
    pub fn namespace(&self) -> String {
        self.path.iter().join("::")
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for elem in self.path.as_ref() {
            write!(f, "{}::", elem)?;
        }
        write!(f, "{}", self.id)?;
        Ok(())
    }
}

// allow `.parse()` on a string to make a `Name`
impl std::str::FromStr for Name {
    type Err = Vec<ParseError>;

    fn from_str(s: &str) -> Result<Self, Vec<ParseError>> {
        crate::parser::parse_name(s)
    }
}

impl FromNormalizedStr for Name {
    fn describe_self() -> &'static str {
        "Name"
    }
}

/// Identifier for a slot
/// Clone is O(1).
// This simply wraps a separate enum -- currently `ValidSlotId` -- in case we
// want to generalize later
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SlotId(ValidSlotId);

impl SlotId {
    /// Get the slot for `principal`
    pub fn principal() -> Self {
        Self(ValidSlotId::Principal)
    }

    /// Get the slot for `resource`
    pub fn resource() -> Self {
        Self(ValidSlotId::Resource)
    }

    /// Check if a slot represents a principal
    pub fn is_principal(&self) -> bool {
        matches!(self, Self(ValidSlotId::Principal))
    }

    /// Check if a slot represents a resource
    pub fn is_resource(&self) -> bool {
        matches!(self, Self(ValidSlotId::Resource))
    }
}

impl From<PrincipalOrResource> for SlotId {
    fn from(v: PrincipalOrResource) -> Self {
        match v {
            PrincipalOrResource::Principal => SlotId::principal(),
            PrincipalOrResource::Resource => SlotId::resource(),
        }
    }
}

impl std::fmt::Display for SlotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Two possible variants for Slots
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
enum ValidSlotId {
    #[serde(rename = "?principal")]
    Principal,
    #[serde(rename = "?resource")]
    Resource,
}

impl std::fmt::Display for ValidSlotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ValidSlotId::Principal => "principal",
            ValidSlotId::Resource => "resource",
        };
        write!(f, "?{s}")
    }
}

#[cfg(test)]
mod vars_test {
    use super::*;
    // Make sure the vars always parse correctly
    #[test]
    fn vars_correct() {
        SlotId::principal();
        SlotId::resource();
    }

    #[test]
    fn display() {
        assert_eq!(format!("{}", SlotId::principal()), "?principal")
    }
}

/// Identifiers. Anything in `Id` should be a valid identifier (and not contain,
/// for instance, spaces or characters like '+').
//
// For now, internally, `Id`s are just owned `SmolString`s.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Hash, PartialOrd, Ord)]
pub struct Id(SmolStr);

impl Id {
    /// Create a new `Id` from a `String`, where it is the caller's
    /// responsibility to ensure that the string is indeed a valid identifier.
    ///
    /// When possible, callers should not use this, and instead use `s.parse()`,
    /// which checks that `s` is a valid identifier, and returns a parse error
    /// if not.
    ///
    /// This method was created for the `From<cst::Ident> for Id` impl to use.
    /// Since `parser::parse_ident()` implicitly uses that `From` impl itself,
    /// if we tried to make that `From` impl go through `.parse()` like everyone
    /// else, we'd get infinite recursion.  And, we assert that `cst::Ident` is
    /// always already checked to contain a valid identifier, otherwise it would
    /// never have been created.
    pub(crate) fn new_unchecked(s: impl Into<SmolStr>) -> Id {
        Id(s.into())
    }

    /// Get the underlying string
    pub fn to_smolstr(self) -> SmolStr {
        self.0
    }
}

impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

// allow `.parse()` on a string to make an `Id`
impl std::str::FromStr for Id {
    type Err = Vec<ParseError>;

    fn from_str(s: &str) -> Result<Self, Vec<ParseError>> {
        crate::parser::parse_ident(s)
    }
}

impl FromNormalizedStr for Id {
    fn describe_self() -> &'static str {
        "Id"
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Id {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // identifier syntax:
        // IDENT     := ['_''a'-'z''A'-'Z']['_''a'-'z''A'-'Z''0'-'9']* - RESERVED
        // BOOL      := 'true' | 'false'
        // RESERVED  := BOOL | 'if' | 'then' | 'else' | 'in' | 'like' | 'has'

        let construct_list = |s: &str| s.chars().collect::<Vec<char>>();
        let list_concat = |s1: &[char], s2: &[char]| [s1, s2].concat();
        // the set of the first character of an identifier
        let head_letters = construct_list("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_");
        // the set of the remaining characters of an identifier
        let tail_letters = list_concat(&construct_list("0123456789"), &head_letters);
        // identifier character count minus 1
        let remaining_length = u.int_in_range(0..=16)?;
        let mut cs = vec![*u.choose(&head_letters)?];
        cs.extend(
            (0..remaining_length)
                .map(|_| u.choose(&tail_letters))
                .collect::<Result<Vec<&char>, _>>()?,
        );
        let mut s: String = cs.into_iter().collect();
        // Should the parsing fails, the string should be reserved word.
        // Append a `_` to create a valid Id.
        if crate::parser::parse_ident(&s).is_err() {
            s.push('_');
        }
        Ok(Self::new_unchecked(s))
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        arbitrary::size_hint::and_all(&[
            // for arbitrary length
            <usize as arbitrary::Arbitrary>::size_hint(depth),
            // for arbitrary choices
            // we use the size hint of a vector of `u8` to get an underestimate of bytes required by the sequence of choices.
            <Vec<u8> as arbitrary::Arbitrary>::size_hint(depth),
        ])
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn normalized_id() {
        Id::from_normalized_str("foo").expect("should be OK");
        Id::from_normalized_str("foo::bar").expect_err("shouldn't be OK");
        Id::from_normalized_str(r#"foo::"bar""#).expect_err("shouldn't be OK");
        Id::from_normalized_str(" foo").expect_err("shouldn't be OK");
        Id::from_normalized_str("foo ").expect_err("shouldn't be OK");
        Id::from_normalized_str("foo\n").expect_err("shouldn't be OK");
        Id::from_normalized_str("foo//comment").expect_err("shouldn't be OK");
    }

    #[test]
    fn normalized_name() {
        Name::from_normalized_str("foo").expect("should be OK");
        Name::from_normalized_str("foo::bar").expect("should be OK");
        Name::from_normalized_str(r#"foo::"bar""#).expect_err("shouldn't be OK");
        Name::from_normalized_str(" foo").expect_err("shouldn't be OK");
        Name::from_normalized_str("foo ").expect_err("shouldn't be OK");
        Name::from_normalized_str("foo\n").expect_err("shouldn't be OK");
        Name::from_normalized_str("foo//comment").expect_err("shouldn't be OK");
    }
}
