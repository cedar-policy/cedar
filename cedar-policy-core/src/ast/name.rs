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

use super::id::Id;
use itertools::Itertools;
use miette::Diagnostic;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use smol_str::ToSmolStr;
use std::fmt::Display;
use std::str::FromStr;
use std::sync::Arc;

use crate::parser::err::{ParseError, ParseErrors, ToASTError};
use crate::parser::Loc;
use crate::FromNormalizedStr;

use super::{PrincipalOrResource, UnreservedId};
use thiserror::Error;

/// This is the `ReservedName` type used to name types, functions, etc.
/// The name can include namespaces.
/// Clone is O(1).
/// Note that objects of this type can contain reserved `__cedar` components.
#[derive(Debug, Clone)]
pub struct ReservedName {
    /// Basename
    pub(crate) id: Id,
    /// Namespaces
    pub(crate) path: Arc<Vec<Id>>,
    /// Location of the name in source
    pub(crate) loc: Option<Loc>,
}

/// `PartialEq` implementation ignores the `loc`.
impl PartialEq for ReservedName {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.path == other.path
    }
}
impl Eq for ReservedName {}

impl std::hash::Hash for ReservedName {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // hash the ty and eid, in line with the `PartialEq` impl which compares
        // the ty and eid.
        self.id.hash(state);
        self.path.hash(state);
    }
}

impl PartialOrd for ReservedName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ReservedName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id).then(self.path.cmp(&other.path))
    }
}

/// A shortcut for `ReservedName::unqualified_name`
impl From<Id> for ReservedName {
    fn from(value: Id) -> Self {
        Self::unqualified_name(value)
    }
}

/// Convert a `ReservedName` to an `Id`
/// The error type is the unit type because the reason the conversion fails
/// is obvious
impl TryFrom<ReservedName> for Id {
    type Error = ();
    fn try_from(value: ReservedName) -> Result<Self, Self::Error> {
        if value.is_unqualified() {
            Ok(value.id)
        } else {
            Err(())
        }
    }
}

impl ReservedName {
    /// A full constructor for `ReservedName`
    pub fn new(basename: Id, path: impl IntoIterator<Item = Id>, loc: Option<Loc>) -> Self {
        Self {
            id: basename,
            path: Arc::new(path.into_iter().collect()),
            loc,
        }
    }

    /// Create a `ReservedName` with no path (no namespaces).
    pub fn unqualified_name(id: Id) -> Self {
        Self {
            id,
            path: Arc::new(vec![]),
            loc: None,
        }
    }

    /// Create a `ReservedName` with no path (no namespaces).
    /// Returns an error if `s` is not a valid identifier.
    pub fn parse_unqualified_name(s: &str) -> Result<Self, ParseErrors> {
        Ok(Self {
            id: s.parse()?,
            path: Arc::new(vec![]),
            loc: None,
        })
    }

    /// Given a type basename and a namespace (as a `ReservedName` itself),
    /// return a `ReservedName` representing the type's fully qualified name
    pub fn type_in_namespace(
        basename: Id,
        namespace: ReservedName,
        loc: Option<Loc>,
    ) -> ReservedName {
        let mut path = Arc::unwrap_or_clone(namespace.path);
        path.push(namespace.id);
        ReservedName::new(basename, path, loc)
    }

    /// Get the source location
    pub fn loc(&self) -> Option<&Loc> {
        self.loc.as_ref()
    }

    /// Get the basename of the `ReservedName` (ie, with namespaces stripped).
    pub fn basename(&self) -> &Id {
        &self.id
    }

    /// Get the namespace of the `ReservedName`, as components
    pub fn namespace_components(&self) -> impl Iterator<Item = &Id> {
        self.path.iter()
    }

    /// Get the full namespace of the `ReservedName`, as a single string.
    ///
    /// Examples:
    /// - `foo::bar` --> the namespace is `"foo"`
    /// - `bar` --> the namespace is `""`
    /// - `foo::bar::baz` --> the namespace is `"foo::bar"`
    pub fn namespace(&self) -> String {
        self.path.iter().join("::")
    }

    /// Qualify the name with a namespace
    ///
    /// When the name already has an explicit namespace, it doesn't make sense
    /// to prefix any namespace, and hence this method returns a copy of `self`.
    ///
    /// If `namespace` is `None`, that represents the empty namespace, so no
    /// prefixing will be done.
    ///
    /// When the name does not already have an explicit namespace, and
    /// `namespace` is `Some`, prefix it with the namespace.
    ///
    /// Examples:
    /// `A::B`.qualify_with(Some(C)) is just A::B
    /// `A`.qualify_with(Some(C)) is C::A
    /// `A`.qualify_with(Some(B::C)) is B::C::A
    /// `A`.qualify_with(None) is A
    pub fn qualify_with(&self, namespace: Option<&ReservedName>) -> ReservedName {
        if self.is_unqualified() {
            // Ideally, we want to implement `IntoIterator` for `Name`
            match namespace {
                Some(namespace) => Self::new(
                    self.basename().clone(),
                    namespace
                        .namespace_components()
                        .chain(std::iter::once(namespace.basename()))
                        .cloned(),
                    self.loc.clone(),
                ),
                None => self.clone(),
            }
        } else {
            self.clone()
        }
    }

    /// Test if a `ReservedName` is an `Id`
    pub fn is_unqualified(&self) -> bool {
        self.path.is_empty()
    }

    /// Test if a `ReservedName` is reserved
    /// i.e., any of its components matches `__cedar`
    pub fn is_reserved(&self) -> bool {
        self.path
            .iter()
            .chain(std::iter::once(&self.id))
            .any(|id| id.is_reserved())
    }
}

impl std::fmt::Display for ReservedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for elem in self.path.as_ref() {
            write!(f, "{}::", elem)?;
        }
        write!(f, "{}", self.id)?;
        Ok(())
    }
}

/// Serialize a `ReservedName` using its `Display` implementation
/// This serialization implementation is used in the JSON schema format.
impl Serialize for ReservedName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_smolstr().serialize(serializer)
    }
}

// allow `.parse()` on a string to make a `Name`
impl std::str::FromStr for ReservedName {
    type Err = ParseErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::parser::parse_name(s)
    }
}

impl FromNormalizedStr for ReservedName {
    fn describe_self() -> &'static str {
        "Reserved name"
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for ReservedName {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            id: u.arbitrary()?,
            path: u.arbitrary()?,
            loc: None,
        })
    }
}

struct NameVisitor;

impl<'de> serde::de::Visitor<'de> for NameVisitor {
    type Value = ReservedName;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a name consisting of an optional namespace and id")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        ReservedName::from_normalized_str(value)
            .map_err(|err| serde::de::Error::custom(format!("invalid name `{value}`: {err}")))
    }
}

/// Deserialize a `Name` using `from_normalized_str`
/// This deserialization implementation is used in the JSON schema format.
impl<'de> Deserialize<'de> for ReservedName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(NameVisitor)
    }
}

/// Identifier for a slot
/// Clone is O(1).
// This simply wraps a separate enum -- currently `ValidSlotId` -- in case we
// want to generalize later
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SlotId(pub(crate) ValidSlotId);

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
pub(crate) enum ValidSlotId {
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

/// [`SlotId`] plus a source location
#[derive(Debug, Clone)]
pub struct Slot {
    /// [`SlotId`]
    pub id: SlotId,
    /// Source location, if available
    pub loc: Option<Loc>,
}

/// `PartialEq` implementation ignores the `loc`. Slots are equal if their ids
/// are equal.
impl PartialEq for Slot {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for Slot {}

impl std::hash::Hash for Slot {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // hash only the id, in line with the `PartialEq` impl which compares
        // only the id
        self.id.hash(state);
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

/// A new type which indicates that the contained [`ReservedName`] does not contain
/// reserved `__cedar`, as specified by RFC 52
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Name(pub(crate) ReservedName);

impl Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Name {
    type Err = ParseErrors;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n: ReservedName = s.parse()?;
        n.try_into().map_err(ParseErrors::singleton)
    }
}

impl FromNormalizedStr for Name {
    fn describe_self() -> &'static str {
        "Name"
    }
}

impl Name {
    /// Qualify the name with an optional namespace
    /// This method has the same behavior as [`ReservedName::qualify_with`] except that
    /// the `namespace` argument is a `Option<&UnreservedName>`
    pub fn qualify_with(&self, namespace: Option<&Self>) -> Self {
        Self(self.as_ref().qualify_with(namespace.map(|n| n.as_ref())))
    }

    /// Create a [`Name`] with no path (no namespaces).
    /// Returns an error if `s` is not a valid identifier.
    pub fn parse_unqualified_name(s: &str) -> Result<Self, ParseErrors> {
        ReservedName::parse_unqualified_name(s)
            .and_then(|n| n.try_into().map_err(ParseErrors::singleton))
    }

    /// Create a [`Name`] with no path (no namespaces).
    pub fn unqualified_name(id: UnreservedId) -> Self {
        Self(ReservedName::unqualified_name(id.0))
    }

    /// Get the basename of the [`Name`] (ie, with namespaces stripped).
    /// Return a reference to [`Id`]
    pub fn basename_as_ref(&self) -> &Id {
        self.0.basename()
    }

    /// Get the basename of the [`Name`] (ie, with namespaces stripped).
    /// Return an [`UnreservedId`]
    pub fn basename(&self) -> UnreservedId {
        // PANIC SAFETY: Any component of a `UnreservedName` is a `UnreservedId`
        #![allow(clippy::unwrap_used)]
        self.0.basename().clone().try_into().unwrap()
    }
}

/// Error occurred when a reserved name is used
#[derive(Debug, Clone, PartialEq, Eq, Error, Diagnostic, Hash)]
#[error("The name `{0}` contains `__cedar`, which is reserved")]
pub struct ReservedNameError(pub(crate) ReservedName);

impl From<ReservedNameError> for ParseError {
    fn from(value: ReservedNameError) -> Self {
        ParseError::ToAST(ToASTError::new(
            value.clone().into(),
            match &value.0.loc {
                Some(loc) => loc.clone(),
                None => {
                    let name_str = value.0.to_string();
                    Loc::new(0..(name_str.len()), name_str.into())
                }
            },
        ))
    }
}

impl TryFrom<ReservedName> for Name {
    type Error = ReservedNameError;
    fn try_from(value: ReservedName) -> Result<Self, Self::Error> {
        if value.is_reserved() {
            Err(ReservedNameError(value))
        } else {
            Ok(Self(value))
        }
    }
}

impl From<Name> for ReservedName {
    fn from(value: Name) -> Self {
        value.0
    }
}

impl AsRef<ReservedName> for Name {
    fn as_ref(&self) -> &ReservedName {
        &self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn normalized_name() {
        ReservedName::from_normalized_str("foo").expect("should be OK");
        ReservedName::from_normalized_str("foo::bar").expect("should be OK");
        ReservedName::from_normalized_str(r#"foo::"bar""#).expect_err("shouldn't be OK");
        ReservedName::from_normalized_str(" foo").expect_err("shouldn't be OK");
        ReservedName::from_normalized_str("foo ").expect_err("shouldn't be OK");
        ReservedName::from_normalized_str("foo\n").expect_err("shouldn't be OK");
        ReservedName::from_normalized_str("foo//comment").expect_err("shouldn't be OK");
    }

    #[test]
    fn qualify_with() {
        assert_eq!(
            "foo::bar::baz",
            ReservedName::from_normalized_str("baz")
                .unwrap()
                .qualify_with(Some(&"foo::bar".parse().unwrap()))
                .to_smolstr()
        );
        assert_eq!(
            "C::D",
            ReservedName::from_normalized_str("C::D")
                .unwrap()
                .qualify_with(Some(&"A::B".parse().unwrap()))
                .to_smolstr()
        );
        assert_eq!(
            "A::B::C::D",
            ReservedName::from_normalized_str("D")
                .unwrap()
                .qualify_with(Some(&"A::B::C".parse().unwrap()))
                .to_smolstr()
        );
        assert_eq!(
            "B::C::D",
            ReservedName::from_normalized_str("B::C::D")
                .unwrap()
                .qualify_with(Some(&"A".parse().unwrap()))
                .to_smolstr()
        );
        assert_eq!(
            "A",
            ReservedName::from_normalized_str("A")
                .unwrap()
                .qualify_with(None)
                .to_smolstr()
        )
    }

    #[test]
    fn test_reserved() {
        for n in [
            "__cedar",
            "__cedar::A",
            "__cedar::A::B",
            "A::__cedar",
            "A::__cedar::B",
        ] {
            assert!(ReservedName::from_normalized_str(n).unwrap().is_reserved());
        }

        for n in ["__cedarr", "A::_cedar", "A::___cedar::B"] {
            assert!(!ReservedName::from_normalized_str(n).unwrap().is_reserved());
        }
    }
}
