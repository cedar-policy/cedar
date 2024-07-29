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
use ref_cast::RefCast;
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

/// Represents the name of an entity type, function, etc.
/// The name may include namespaces.
/// Clone is O(1).
///
/// This type may contain any name valid for use internally, including names
/// with reserved `__cedar` components (and also names without `__cedar`).
#[derive(Debug, Clone)]
pub struct InternalName {
    /// Basename
    pub(crate) id: Id,
    /// Namespaces
    pub(crate) path: Arc<Vec<Id>>,
    /// Location of the name in source
    pub(crate) loc: Option<Loc>,
}

/// `PartialEq` implementation ignores the `loc`.
impl PartialEq for InternalName {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.path == other.path
    }
}
impl Eq for InternalName {}

impl std::hash::Hash for InternalName {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // hash the id and path, in line with the `PartialEq` impl which
        // compares the id and path.
        self.id.hash(state);
        self.path.hash(state);
    }
}

impl PartialOrd for InternalName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for InternalName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id).then(self.path.cmp(&other.path))
    }
}

/// A shortcut for [`InternalName::unqualified_name`]
impl From<Id> for InternalName {
    fn from(value: Id) -> Self {
        Self::unqualified_name(value)
    }
}

/// Convert a [`InternalName`] to an [`Id`]
/// The error type is the unit type because the reason the conversion fails
/// is obvious
impl TryFrom<InternalName> for Id {
    type Error = ();
    fn try_from(value: InternalName) -> Result<Self, Self::Error> {
        if value.is_unqualified() {
            Ok(value.id)
        } else {
            Err(())
        }
    }
}

impl InternalName {
    /// A full constructor for [`InternalName`]
    pub fn new(basename: Id, path: impl IntoIterator<Item = Id>, loc: Option<Loc>) -> Self {
        Self {
            id: basename,
            path: Arc::new(path.into_iter().collect()),
            loc,
        }
    }

    /// Create an [`InternalName`] with no path (no namespaces).
    pub fn unqualified_name(id: Id) -> Self {
        Self {
            id,
            path: Arc::new(vec![]),
            loc: None,
        }
    }

    /// Get the [`InternalName`] representing the reserved `__cedar` namespace
    pub fn __cedar() -> Self {
        // using `Id::new_unchecked()` for performance reasons -- this function is called many times by validator code
        Self::unqualified_name(Id::new_unchecked("__cedar"))
    }

    /// Create an [`InternalName`] with no path (no namespaces).
    /// Returns an error if `s` is not a valid identifier.
    pub fn parse_unqualified_name(s: &str) -> Result<Self, ParseErrors> {
        Ok(Self {
            id: s.parse()?,
            path: Arc::new(vec![]),
            loc: None,
        })
    }

    /// Given a type basename and a namespace (as an [`InternalName`] itself),
    /// return an [`InternalName`] representing the type's fully qualified name
    pub fn type_in_namespace(
        basename: Id,
        namespace: InternalName,
        loc: Option<Loc>,
    ) -> InternalName {
        let mut path = Arc::unwrap_or_clone(namespace.path);
        path.push(namespace.id);
        InternalName::new(basename, path, loc)
    }

    /// Get the source location
    pub fn loc(&self) -> Option<&Loc> {
        self.loc.as_ref()
    }

    /// Get the basename of the [`InternalName`] (ie, with namespaces stripped).
    pub fn basename(&self) -> &Id {
        &self.id
    }

    /// Get the namespace of the [`InternalName`], as components
    pub fn namespace_components(&self) -> impl Iterator<Item = &Id> {
        self.path.iter()
    }

    /// Get the full namespace of the [`InternalName`], as a single string.
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
    /// If the name already has a non-empty namespace, this method does not
    /// apply any prefix and instead returns a copy of `self`.
    ///
    /// If `namespace` is `None`, that represents the empty namespace, so no
    /// prefixing will be done.
    ///
    /// If the name does not already have an explicit namespace (i.e., it's
    /// just a single `Id`), this applies `namespace` as a prefix (if it is
    /// present).
    ///
    /// Examples:
    /// - `A::B`.qualify_with(None) is `A::B`
    /// - `A::B`.qualify_with(Some(C)) is also `A::B`
    /// - `A`.qualify_with(None) is `A`
    /// - `A`.qualify_with(Some(C)) is `C::A`
    /// - `A`.qualify_with(Some(B::C)) is `B::C::A`
    pub fn qualify_with(&self, namespace: Option<&InternalName>) -> InternalName {
        if self.is_unqualified() {
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

    /// Like `qualify_with()`, but accepts a [`Name`] as the namespace to qualify with
    pub fn qualify_with_name(&self, namespace: Option<&Name>) -> InternalName {
        let ns = namespace.map(AsRef::as_ref);
        self.qualify_with(ns)
    }

    /// Test if an [`InternalName`] is an [`Id`]
    pub fn is_unqualified(&self) -> bool {
        self.path.is_empty()
    }

    /// Test if an [`InternalName`] is reserved
    /// i.e., any of its components matches `__cedar`
    pub fn is_reserved(&self) -> bool {
        self.path
            .iter()
            .chain(std::iter::once(&self.id))
            .any(|id| id.is_reserved())
    }
}

impl std::fmt::Display for InternalName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for elem in self.path.as_ref() {
            write!(f, "{}::", elem)?;
        }
        write!(f, "{}", self.id)?;
        Ok(())
    }
}

/// Serialize an [`InternalName`] using its `Display` implementation
/// This serialization implementation is used in the JSON schema format.
impl Serialize for InternalName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_smolstr().serialize(serializer)
    }
}

// allow `.parse()` on a string to make an [`InternalName`]
impl std::str::FromStr for InternalName {
    type Err = ParseErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::parser::parse_internal_name(s)
    }
}

impl FromNormalizedStr for InternalName {
    fn describe_self() -> &'static str {
        "internal name"
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for InternalName {
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
    type Value = InternalName;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a name consisting of an optional namespace and id")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        InternalName::from_normalized_str(value)
            .map_err(|err| serde::de::Error::custom(format!("invalid name `{value}`: {err}")))
    }
}

/// Deserialize an [`InternalName`] using `from_normalized_str`.
/// This deserialization implementation is used in the JSON schema format.
impl<'de> Deserialize<'de> for InternalName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(NameVisitor)
    }
}

/// Identifier for a slot
/// Clone is O(1).
// This simply wraps a separate enum -- currently [`ValidSlotId`] -- in case we
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

/// A new type which indicates that the contained [`InternalName`] does not
/// contain reserved `__cedar`, as specified by RFC 52.
/// This represents names which are legal for end-users to _define_, while
/// [`InternalName`] represents names which are legal for end-users to
/// _reference_.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, RefCast)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Name(pub(crate) InternalName);

impl From<UnreservedId> for Name {
    fn from(value: UnreservedId) -> Self {
        Self::unqualified_name(value)
    }
}

impl TryFrom<Name> for UnreservedId {
    type Error = ();
    fn try_from(value: Name) -> Result<Self, Self::Error> {
        if value.0.is_unqualified() {
            Ok(value.basename())
        } else {
            Err(())
        }
    }
}

impl Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Name {
    type Err = ParseErrors;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n: InternalName = s.parse()?;
        n.try_into().map_err(ParseErrors::singleton)
    }
}

impl FromNormalizedStr for Name {
    fn describe_self() -> &'static str {
        "Name"
    }
}

/// Deserialize a [`Name`] using `from_normalized_str`
/// This deserialization implementation is used in the JSON schema format.
impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_str(NameVisitor)
            .and_then(|n| n.try_into().map_err(serde::de::Error::custom))
    }
}

impl Name {
    /// Create a [`Name`] with no path (no namespaces).
    /// Returns an error if `s` is not a valid identifier.
    pub fn parse_unqualified_name(s: &str) -> Result<Self, ParseErrors> {
        InternalName::parse_unqualified_name(s)
            .and_then(|n| n.try_into().map_err(ParseErrors::singleton))
    }

    /// Create a [`Name`] with no path (no namespaces).
    pub fn unqualified_name(id: UnreservedId) -> Self {
        // This is safe (upholds the `Name` invariant) because `id` must be an `UnreservedId`
        Self(InternalName::unqualified_name(id.0))
    }

    /// Get the basename of the [`Name`] (ie, with namespaces stripped).
    /// Return a reference to [`Id`]
    pub fn basename_as_ref(&self) -> &Id {
        self.0.basename()
    }

    /// Get the basename of the [`Name`] (ie, with namespaces stripped).
    /// Return an [`UnreservedId`]
    pub fn basename(&self) -> UnreservedId {
        // PANIC SAFETY: Any component of a `Name` is a `UnreservedId`
        #![allow(clippy::unwrap_used)]
        self.0.basename().clone().try_into().unwrap()
    }

    /// Test if a [`Name`] is an [`Id`]
    pub fn is_unqualified(&self) -> bool {
        self.0.is_unqualified()
    }

    /// Qualify the name with an optional namespace
    ///
    /// This method has the same behavior as [`InternalName::qualify_with()`]
    pub fn qualify_with(&self, namespace: Option<&InternalName>) -> InternalName {
        self.0.qualify_with(namespace)
    }

    /// Qualify the name with an optional namespace
    ///
    /// This method has the same behavior as [`InternalName::qualify_with_name()`] except that
    /// it's guaranteed to return [`Name`], not [`InternalName`]
    pub fn qualify_with_name(&self, namespace: Option<&Self>) -> Self {
        // This is safe (upholds the `Name` invariant) because both `self` and `namespace`
        // cannot contain `__cedar` -- they were already `Name`s
        Self(self.as_ref().qualify_with(namespace.map(|n| n.as_ref())))
    }

    /// Get the source location
    pub fn loc(&self) -> Option<&Loc> {
        self.0.loc()
    }
}

/// Error when a reserved name is used where it is not allowed
#[derive(Debug, Clone, PartialEq, Eq, Error, Diagnostic, Hash)]
#[error("The name `{0}` contains `__cedar`, which is reserved")]
pub struct ReservedNameError(pub(crate) InternalName);

impl ReservedNameError {
    /// The [`InternalName`] which contained a reserved component
    pub fn name(&self) -> &InternalName {
        &self.0
    }
}

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

impl TryFrom<InternalName> for Name {
    type Error = ReservedNameError;
    fn try_from(value: InternalName) -> Result<Self, Self::Error> {
        if value.is_reserved() {
            Err(ReservedNameError(value))
        } else {
            Ok(Self(value))
        }
    }
}

impl<'a> TryFrom<&'a InternalName> for &'a Name {
    type Error = ReservedNameError;
    fn try_from(value: &'a InternalName) -> Result<&'a Name, ReservedNameError> {
        if value.is_reserved() {
            Err(ReservedNameError(value.clone()))
        } else {
            Ok(<Name as RefCast>::ref_cast(value))
        }
    }
}

impl From<Name> for InternalName {
    fn from(value: Name) -> Self {
        value.0
    }
}

impl AsRef<InternalName> for Name {
    fn as_ref(&self) -> &InternalName {
        &self.0
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Name {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let basename: UnreservedId = u.arbitrary()?;
        let path: Vec<UnreservedId> = u.arbitrary()?;
        let name = InternalName::new(basename.into(), path.into_iter().map(|id| id.into()), None);
        // PANIC SAFETY: `name` is made of `UnreservedId`s and thus should be a valid `Name`
        #[allow(clippy::unwrap_used)]
        Ok(name.try_into().unwrap())
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        <InternalName as arbitrary::Arbitrary>::size_hint(depth)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn normalized_name() {
        InternalName::from_normalized_str("foo").expect("should be OK");
        InternalName::from_normalized_str("foo::bar").expect("should be OK");
        InternalName::from_normalized_str(r#"foo::"bar""#).expect_err("shouldn't be OK");
        InternalName::from_normalized_str(" foo").expect_err("shouldn't be OK");
        InternalName::from_normalized_str("foo ").expect_err("shouldn't be OK");
        InternalName::from_normalized_str("foo\n").expect_err("shouldn't be OK");
        InternalName::from_normalized_str("foo//comment").expect_err("shouldn't be OK");
    }

    #[test]
    fn qualify_with() {
        assert_eq!(
            "foo::bar::baz",
            InternalName::from_normalized_str("baz")
                .unwrap()
                .qualify_with(Some(&"foo::bar".parse().unwrap()))
                .to_smolstr()
        );
        assert_eq!(
            "C::D",
            InternalName::from_normalized_str("C::D")
                .unwrap()
                .qualify_with(Some(&"A::B".parse().unwrap()))
                .to_smolstr()
        );
        assert_eq!(
            "A::B::C::D",
            InternalName::from_normalized_str("D")
                .unwrap()
                .qualify_with(Some(&"A::B::C".parse().unwrap()))
                .to_smolstr()
        );
        assert_eq!(
            "B::C::D",
            InternalName::from_normalized_str("B::C::D")
                .unwrap()
                .qualify_with(Some(&"A".parse().unwrap()))
                .to_smolstr()
        );
        assert_eq!(
            "A",
            InternalName::from_normalized_str("A")
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
            assert!(InternalName::from_normalized_str(n).unwrap().is_reserved());
        }

        for n in ["__cedarr", "A::_cedar", "A::___cedar::B"] {
            assert!(!InternalName::from_normalized_str(n).unwrap().is_reserved());
        }
    }
}
