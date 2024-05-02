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

//! This module defines the publicly exported identifier types `PolicyId` and `EntityUid`.

use cedar_policy_core::ast;
use ref_cast::RefCast;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::str::FromStr;

/// Unique ids assigned to policies and templates.
///
/// A [`PolicyId`] can can be constructed using [`PolicyId::from_str`] or by
/// calling `parse()` on a string.
/// This implementation is [`Infallible`], so the parsed [`EntityId`] can be extracted safely.
/// Examples:
/// ```
/// # use cedar_policy::PolicyId;
/// let id = PolicyId::new("my-id");
/// let id : PolicyId = "my-id".parse().unwrap_or_else(|never| match never {});
/// # assert_eq!(id.as_ref(), "my-id");
/// ```
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize, RefCast)]
pub struct PolicyId(ast::PolicyID);

impl PolicyId {
    /// Construct a [`PolicyId`] from a source string
    pub fn new(id: impl AsRef<str>) -> Self {
        Self(ast::PolicyID::from_string(id.as_ref()))
    }

    /// Deconstruct an [`PolicyId`] to get the internal type.
    /// This function is only intended to be used internally.
    pub(crate) fn into_inner(self) -> ast::PolicyID {
        self.0
    }

    /// Deconstruct an [`PolicyId`] to get the internal type.
    /// This function is only intended to be used internally.
    pub(crate) fn as_inner(&self) -> &ast::PolicyID {
        &self.0
    }
}

impl FromStr for PolicyId {
    type Err = Infallible;

    /// Create a `PolicyId` from a string. Currently always returns `Ok()`.
    fn from_str(id: &str) -> Result<Self, Self::Err> {
        Ok(Self(ast::PolicyID::from_string(id)))
    }
}

impl std::fmt::Display for PolicyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for PolicyId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

/// Identifier portion of the [`EntityUid`] type.
///
/// All strings are valid [`EntityId`]s, and can be
/// constructed either using [`EntityId::new`]
/// or by using the implementation of [`FromStr`]. This implementation is [`Infallible`], so the
/// parsed [`EntityId`] can be extracted safely.
///
/// ```
/// # use cedar_policy::EntityId;
/// let id : EntityId = "my-id".parse().unwrap_or_else(|never| match never {});
/// # assert_eq!(id.as_ref(), "my-id");
/// ```
#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, RefCast)]
pub struct EntityId(ast::Eid);

impl EntityId {
    /// Construct an [`EntityId`] from a source string
    pub fn new(src: impl AsRef<str>) -> Self {
        match src.as_ref().parse() {
            Ok(eid) => eid,
            Err(infallible) => match infallible {},
        }
    }
}

impl FromStr for EntityId {
    type Err = Infallible;
    fn from_str(eid_str: &str) -> Result<Self, Self::Err> {
        Ok(Self(ast::Eid::new(eid_str)))
    }
}

impl AsRef<str> for EntityId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

// Note that this Display formatter will format the EntityId as it would be expected
// in the EntityUid string form. For instance, the `"alice"` in `User::"alice"`.
// This means it adds quotes and potentially performs some escaping.
impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents an entity type name. Consists of a namespace and the type name.
///
/// An `EntityTypeName` can can be constructed using
/// [`EntityTypeName::from_str`] or by calling `parse()` on a string. Unlike
/// [`EntityId::from_str`], _this can fail_, so it is important to properly
/// handle an `Err` result.
///
/// ```
/// # use cedar_policy::EntityTypeName;
/// let id : Result<EntityTypeName, _> = "Namespace::Type".parse();
/// # let id = id.unwrap();
/// # assert_eq!(id.basename(), "Type");
/// # assert_eq!(id.namespace(), "Namespace");
/// ```
#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, RefCast)]
pub struct EntityTypeName(ast::Name);

impl EntityTypeName {
    /// Get the basename of the `EntityTypeName` (ie, with namespaces stripped).
    /// ```
    /// # use cedar_policy::EntityTypeName;
    /// # use std::str::FromStr;
    /// let type_name = EntityTypeName::from_str("MySpace::User").unwrap();
    /// assert_eq!(type_name.basename(), "User");
    /// ```
    pub fn basename(&self) -> &str {
        self.0.basename().as_ref()
    }

    /// Get the namespace of the `EntityTypeName`, as components
    /// ```
    /// # use cedar_policy::EntityTypeName;
    /// # use std::str::FromStr;
    /// let type_name = EntityTypeName::from_str("Namespace::MySpace::User").unwrap();
    /// let mut components = type_name.namespace_components();
    /// assert_eq!(components.next(), Some("Namespace"));
    /// assert_eq!(components.next(), Some("MySpace"));
    /// assert_eq!(components.next(), None);
    /// ```
    pub fn namespace_components(&self) -> impl Iterator<Item = &str> {
        self.0.namespace_components().map(AsRef::as_ref)
    }

    /// Get the full namespace of the `EntityTypeName`, as a single string.
    /// ```
    /// # use cedar_policy::EntityTypeName;
    /// # use std::str::FromStr;
    /// let type_name = EntityTypeName::from_str("Namespace::MySpace::User").unwrap();
    /// let components = type_name.namespace();
    /// assert_eq!(components,"Namespace::MySpace");
    /// ```
    pub fn namespace(&self) -> String {
        self.0.namespace()
    }

    /// Construct an [`EntityTypeName`] from the internal type.
    /// This function is only intended to be used internally.
    pub(crate) fn new(ty: ast::Name) -> Self {
        Self(ty)
    }
}

impl std::fmt::Display for EntityTypeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique id for an entity, such as `User::"alice"`.
///
/// An `EntityUid` contains an [`EntityTypeName`] and [`EntityId`]. It can
/// be constructed from these components using
/// [`EntityUid::from_type_name_and_id`], parsed from a string using `.parse()`
/// (via [`EntityUid::from_str`]), or constructed from a JSON value using
/// [`EntityUid::from_json`].
///
// INVARIANT: this can never be an `ast::EntityType::Unspecified`
#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, RefCast)]
pub struct EntityUid(ast::EntityUID);

impl EntityUid {
    /// Returns the portion of the Euid that represents namespace and entity type
    /// ```
    /// # use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid};
    /// # use std::str::FromStr;
    /// let json_data = serde_json::json!({ "__entity": { "type": "User", "id": "alice" } });
    /// let euid = EntityUid::from_json(json_data).unwrap();
    /// assert_eq!(euid.type_name(), &EntityTypeName::from_str("User").unwrap());
    /// ```
    pub fn type_name(&self) -> &EntityTypeName {
        // PANIC SAFETY by invariant on struct
        #[allow(clippy::panic)]
        match self.0.entity_type() {
            ast::EntityType::Unspecified => panic!("Impossible to have an unspecified entity"),
            ast::EntityType::Specified(name) => EntityTypeName::ref_cast(name),
        }
    }

    /// Returns the id portion of the Euid
    /// ```
    /// # use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid};
    /// # use std::str::FromStr;
    /// let json_data = serde_json::json!({ "__entity": { "type": "User", "id": "alice" } });
    /// let euid = EntityUid::from_json(json_data).unwrap();
    /// assert_eq!(euid.id(), &EntityId::from_str("alice").unwrap());
    /// ```
    pub fn id(&self) -> &EntityId {
        EntityId::ref_cast(self.0.eid())
    }

    /// Creates `EntityUid` from `EntityTypeName` and `EntityId`
    ///```
    /// # use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid};
    /// # use std::str::FromStr;
    /// let eid = EntityId::from_str("alice").unwrap();
    /// let type_name: EntityTypeName = EntityTypeName::from_str("User").unwrap();
    /// let euid = EntityUid::from_type_name_and_id(type_name, eid);
    /// # assert_eq!(euid.type_name(), &EntityTypeName::from_str("User").unwrap());
    /// # assert_eq!(euid.id(), &EntityId::from_str("alice").unwrap());
    /// ```
    pub fn from_type_name_and_id(name: EntityTypeName, id: EntityId) -> Self {
        // INVARIANT: `from_components` always constructs a Concrete id
        Self(ast::EntityUID::from_components(name.0, id.0, None))
    }

    /// Testing utility for creating `EntityUids` a bit easier
    #[cfg(test)]
    pub(crate) fn from_strs(typename: &str, id: &str) -> Self {
        Self::from_type_name_and_id(
            EntityTypeName::from_str(typename).unwrap(),
            EntityId::from_str(id).unwrap(),
        )
    }

    /// Construct an [`EntityUid`] from the internal type.
    /// This function is only intended to be used internally.
    pub(crate) fn new(uid: ast::EntityUID) -> Self {
        Self(uid)
    }

    /// Deconstruct an [`EntityUid`] to get the internal type.
    /// This function is only intended to be used internally.
    pub(crate) fn into_inner(self) -> ast::EntityUID {
        self.0
    }

    /// Deconstruct an [`EntityUid`] to get the internal type.
    /// This function is only intended to be used internally.
    pub(crate) fn as_inner(&self) -> &ast::EntityUID {
        &self.0
    }
}

impl std::fmt::Display for EntityUid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
