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

use super::id::Id;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::parser::err::ParseErrors;
use crate::FromNormalizedStr;

use super::PrincipalOrResource;

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
    pub fn parse_unqualified_name(s: &str) -> Result<Self, ParseErrors> {
        Ok(Self {
            id: s.parse()?,
            path: Arc::new(vec![]),
        })
    }

    /// Given a type basename and a namespace (as a `Name` itself),
    /// return a `Name` representing the type's fully qualified name
    pub fn type_in_namespace(basename: Id, namespace: Name) -> Name {
        let mut path = Arc::unwrap_or_clone(namespace.path);
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
    type Err = ParseErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
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

#[cfg(test)]
mod test {

    use super::*;

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
