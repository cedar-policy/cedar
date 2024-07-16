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

use cedar_policy_core::ast::{Name, UnreservedId};

use serde::{Deserialize, Serialize};

/// A newtype which indicates that the contained `Name` may not yet be
/// fully-qualified.
///
/// You can convert it to a fully-qualified `Name` using `.qualify_with()`.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct RawName(Name);

impl RawName {
    /// Create a new [`RawName`] from the given `Id`
    pub fn new(id: UnreservedId) -> Self {
        Self(Name::unqualified_name(id))
    }

    /// Create a new [`RawName`] from the given `Name`.
    ///
    /// Note that if `name` includes explicit namespaces, the result will be a
    /// [`RawName`] that also includes those explicit namespaces, as if that
    /// fully-qualified name appeared directly in the (JSON or human) schema
    /// format.
    /// If `name` does not include explicit namespaces, the result will be a
    /// [`RawName`] that also does not include explicit namespaces, which may or
    /// may not translate back to the original input `name`, due to
    /// namespace-qualification rules.
    pub fn from_name(name: Name) -> Self {
        Self(name)
    }

    /// Create a new [`RawName`] by parsing the provided string, which should contain
    /// an unqualified `Name` (no explicit namespaces)
    pub fn parse_unqualified_name(
        s: &str,
    ) -> Result<Self, cedar_policy_core::parser::err::ParseErrors> {
        Name::parse_unqualified_name(s).map(RawName)
    }

    /// Create a new [`RawName`] by parsing the provided string, which should contain
    /// a `Name` in normalized form.
    ///
    /// (See the [`cedar_policy_core::FromNormalizedStr`] trait.)
    pub fn from_normalized_str(
        s: &str,
    ) -> Result<Self, cedar_policy_core::parser::err::ParseErrors> {
        use cedar_policy_core::FromNormalizedStr;
        Name::from_normalized_str(s).map(RawName)
    }

    /// Convert this [`RawName`] to a `Name` by adding the given `ns` as its
    /// prefix, or by no-op if `ns` is `None`.
    ///
    /// Note that if the [`RawName`] already had a non-empty explicit namespace,
    /// no additional prefixing will be done, even if `ns` is `Some`.
    pub fn qualify_with(self, ns: Option<&Name>) -> Name {
        self.0.qualify_with(ns)
    }
}

impl std::fmt::Display for RawName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for RawName {
    type Err = <Name as std::str::FromStr>::Err;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Name::from_str(s).map(RawName)
    }
}
