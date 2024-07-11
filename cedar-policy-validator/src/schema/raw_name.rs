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

use cedar_policy_core::ast::{Id, Name, ReservedNameError, UncheckedName};
use cedar_policy_core::parser::Loc;
use serde::{Deserialize, Serialize};

/// A newtype which indicates that the contained `UncheckedName` may not yet be
/// fully-qualified.
///
/// You can convert it to a fully-qualified `UncheckedName` using `.qualify_with()`.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct RawUncheckedName(UncheckedName);

/// A newtype which indicates that the contained `Name` may not yet be
/// fully-qualified.
///
/// You can convert it to a fully-qualified `Name` using `.qualify_with()`.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct RawName(Name);

impl TryFrom<RawUncheckedName> for RawName {
    type Error = ReservedNameError;
    fn try_from(value: RawUncheckedName) -> Result<Self, Self::Error> {
        value.0.try_into().map(Self)
    }
}

impl RawName {
    /// Create a fully qualified `Name`
    pub fn qualify_with(self, ns: Option<&Name>) -> Name {
        self.0.qualify_with(ns)
    }
}

impl RawUncheckedName {
    /// Create a new [`RawUncheckedName`] from the given `Id`
    pub fn new(id: Id) -> Self {
        Self(UncheckedName::unqualified_name(id))
    }

    /// Create a new [`RawUncheckedName`] from the given `UncheckedName`.
    ///
    /// Note that if `name` includes explicit namespaces, the result will be a
    /// [`RawUncheckedName`] that also includes those explicit namespaces, as if that
    /// fully-qualified name appeared directly in the (JSON or human) schema
    /// format.
    /// If `name` does not include explicit namespaces, the result will be a
    /// [`RawUncheckedName`] that also does not include explicit namespaces, which may or
    /// may not translate back to the original input `name`, due to
    /// namespace-qualification rules.
    pub fn from_name(name: UncheckedName) -> Self {
        Self(name)
    }

    /// Create a new [`RawUncheckedName`] from a basename, namespace components as `Id`s, and optional source location
    pub fn from_components(
        basename: Id,
        namespace: impl IntoIterator<Item = Id>,
        loc: Option<Loc>,
    ) -> Self {
        Self(UncheckedName::new(basename, namespace, loc))
    }

    /// Create a new [`RawUncheckedName`] by parsing the provided string, which should contain
    /// an unqualified `UncheckedName` (no explicit namespaces)
    pub fn parse_unqualified_name(
        s: &str,
    ) -> Result<Self, cedar_policy_core::parser::err::ParseErrors> {
        UncheckedName::parse_unqualified_name(s).map(RawUncheckedName)
    }

    /// Create a new [`RawUncheckedName`] by parsing the provided string, which should contain
    /// a `UncheckedName` in normalized form.
    ///
    /// (See the [`cedar_policy_core::FromNormalizedStr`] trait.)
    pub fn from_normalized_str(
        s: &str,
    ) -> Result<Self, cedar_policy_core::parser::err::ParseErrors> {
        use cedar_policy_core::FromNormalizedStr;
        UncheckedName::from_normalized_str(s).map(RawUncheckedName)
    }

    /// Is this [`RawUncheckedName`] unqualified, that is, written without any _explicit_
    /// namespaces.
    /// (This method returning `true` does not imply that the [`RawUncheckedName`] will
    /// _eventually resolve_ to an unqualified name.)
    pub fn is_unqualified(&self) -> bool {
        self.0.is_unqualified()
    }

    /// Convert this [`RawUncheckedName`] to a `UncheckedName` by adding the given `ns` as its
    /// prefix, or by no-op if `ns` is `None`.
    ///
    /// Note that if the [`RawUncheckedName`] already had a non-empty explicit namespace,
    /// no additional prefixing will be done, even if `ns` is `Some`.
    pub fn qualify_with(self, ns: Option<&UncheckedName>) -> UncheckedName {
        self.0.qualify_with(ns)
    }

    /// Is this [`RawUncheckedName`] reserved, i.e., containing any components being `__cedar`
    pub fn is_reserved(&self) -> bool {
        self.0.is_reserved()
    }
}

impl std::fmt::Display for RawUncheckedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for RawUncheckedName {
    type Err = <UncheckedName as std::str::FromStr>::Err;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UncheckedName::from_str(s).map(RawUncheckedName)
    }
}
