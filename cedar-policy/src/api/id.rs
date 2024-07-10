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

//! This module defines the publicly exported identifier types including
//! `EntityUid` and `PolicyId`.

use crate::entities_json_errors::JsonDeserializationError;
use crate::ParseErrors;
use cedar_policy_core::ast;
use cedar_policy_core::entities::json::err::JsonDeserializationErrorContext;
use cedar_policy_core::FromNormalizedStr;
use ref_cast::RefCast;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::convert::Infallible;
use std::str::FromStr;

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
///
/// `EntityId` does not implement `Display`, partly because it is unclear
/// whether `Display` should produce an escaped representation or an unescaped
/// representation (see [#884](https://github.com/cedar-policy/cedar/issues/884)).
/// To get an escaped representation, use `.escaped()`.
/// To get an unescaped representation, use `.as_ref()`.
#[repr(transparent)]
#[allow(clippy::module_name_repetitions)]
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

    /// Get the contents of the `EntityId` as an escaped string
    pub fn escaped(&self) -> SmolStr {
        self.0.escaped()
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
pub struct EntityTypeName(ast::EntityType);

impl EntityTypeName {
    /// Get the basename of the `EntityTypeName` (ie, with namespaces stripped).
    /// ```
    /// # use cedar_policy::EntityTypeName;
    /// # use std::str::FromStr;
    /// let type_name = EntityTypeName::from_str("MySpace::User").unwrap();
    /// assert_eq!(type_name.basename(), "User");
    /// ```
    pub fn basename(&self) -> &str {
        self.0.name().basename().as_ref()
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
        self.0.name().namespace_components().map(AsRef::as_ref)
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
        self.0.name().namespace()
    }
}

/// This `FromStr` implementation requires the _normalized_ representation of the
/// type name. See <https://github.com/cedar-policy/rfcs/pull/9/>.
impl FromStr for EntityTypeName {
    type Err = ParseErrors;

    fn from_str(namespace_type_str: &str) -> Result<Self, Self::Err> {
        ast::Name::from_normalized_str(namespace_type_str)
            .map(|name| Self(ast::EntityType::from(name)))
            .map_err(Into::into)
    }
}

impl std::fmt::Display for EntityTypeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[doc(hidden)]
impl From<ast::Name> for EntityTypeName {
    fn from(name: ast::Name) -> Self {
        Self(name.into())
    }
}

#[doc(hidden)]
impl From<ast::EntityType> for EntityTypeName {
    fn from(ty: ast::EntityType) -> Self {
        Self(ty)
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
        EntityTypeName::ref_cast(self.0.entity_type())
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

    /// Creates `EntityUid` from a JSON value, which should have
    /// either the implicit or explicit `__entity` form.
    /// ```
    /// # use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid};
    /// # use std::str::FromStr;
    /// let json_data = serde_json::json!({ "__entity": { "type": "User", "id": "123abc" } });
    /// let euid = EntityUid::from_json(json_data).unwrap();
    /// # assert_eq!(euid.type_name(), &EntityTypeName::from_str("User").unwrap());
    /// # assert_eq!(euid.id(), &EntityId::from_str("123abc").unwrap());
    /// ```
    #[allow(clippy::result_large_err)]
    pub fn from_json(json: serde_json::Value) -> Result<Self, impl miette::Diagnostic> {
        let parsed: cedar_policy_core::entities::EntityUidJson = serde_json::from_value(json)?;
        Ok::<Self, JsonDeserializationError>(
            parsed
                .into_euid(|| JsonDeserializationErrorContext::EntityUid)?
                .into(),
        )
    }

    /// Testing utility for creating `EntityUids` a bit easier
    #[cfg(test)]
    pub(crate) fn from_strs(typename: &str, id: &str) -> Self {
        Self::from_type_name_and_id(
            EntityTypeName::from_str(typename).unwrap(),
            EntityId::from_str(id).unwrap(),
        )
    }
}

impl FromStr for EntityUid {
    type Err = ParseErrors;

    /// Parse an [`EntityUid`].
    ///
    /// An [`EntityUid`] consists of an [`EntityTypeName`] followed by a quoted [`EntityId`].
    /// The two are joined by a `::`.
    /// For the formal grammar, see <https://docs.cedarpolicy.com/policies/syntax-grammar.html#entity>
    ///
    /// Examples:
    /// ```
    ///  # use cedar_policy::EntityUid;
    ///  let euid: EntityUid = r#"Foo::Bar::"george""#.parse().unwrap();
    ///  // Get the type of this euid (`Foo::Bar`)
    ///  euid.type_name();
    ///  // Or the id
    ///  euid.id();
    /// ```
    ///
    /// This [`FromStr`] implementation requires the _normalized_ representation of the
    /// UID. See <https://github.com/cedar-policy/rfcs/pull/9/>.
    ///
    /// A note on safety:
    ///
    /// __DO NOT__ create [`EntityUid`]'s via string concatenation.
    /// If you have separate components of an [`EntityUid`], use [`EntityUid::from_type_name_and_id`]
    fn from_str(uid_str: &str) -> Result<Self, Self::Err> {
        ast::EntityUID::from_normalized_str(uid_str)
            .map(Into::into)
            .map_err(Into::into)
    }
}

impl std::fmt::Display for EntityUid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[doc(hidden)]
impl AsRef<ast::EntityUID> for EntityUid {
    fn as_ref(&self) -> &ast::EntityUID {
        &self.0
    }
}

#[doc(hidden)]
impl From<EntityUid> for ast::EntityUID {
    fn from(uid: EntityUid) -> Self {
        uid.0
    }
}

#[doc(hidden)]
impl From<ast::EntityUID> for EntityUid {
    fn from(uid: ast::EntityUID) -> Self {
        Self(uid)
    }
}

/// Unique ids assigned to policies and templates.
///
/// A [`PolicyId`] can can be constructed using [`PolicyId::new`] or by calling
/// `parse()` on a string. The `parse()` implementation is [`Infallible`], so
/// the parsed [`EntityId`] can be extracted safely.
/// Examples:
/// ```
/// # use cedar_policy::PolicyId;
/// let id = PolicyId::new("my-id");
/// let id : PolicyId = "my-id".parse().unwrap_or_else(|never| match never {});
/// # assert_eq!(AsRef::<str>::as_ref(&id), "my-id");
/// ```
#[repr(transparent)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize, RefCast)]
pub struct PolicyId(ast::PolicyID);

impl PolicyId {
    /// Construct a [`PolicyId`] from a source string
    pub fn new(id: impl AsRef<str>) -> Self {
        Self(ast::PolicyID::from_string(id.as_ref()))
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

#[doc(hidden)]
impl AsRef<ast::PolicyID> for PolicyId {
    fn as_ref(&self) -> &ast::PolicyID {
        &self.0
    }
}

#[doc(hidden)]
impl From<PolicyId> for ast::PolicyID {
    fn from(uid: PolicyId) -> Self {
        uid.0
    }
}

/// Identifier for a Template slot
#[repr(transparent)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, RefCast, Serialize, Deserialize)]
pub struct SlotId(ast::SlotId);

impl SlotId {
    /// Get the slot for `principal`
    pub fn principal() -> Self {
        Self(ast::SlotId::principal())
    }

    /// Get the slot for `resource`
    pub fn resource() -> Self {
        Self(ast::SlotId::resource())
    }
}

impl std::fmt::Display for SlotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[doc(hidden)]
impl From<ast::SlotId> for SlotId {
    fn from(a: ast::SlotId) -> Self {
        Self(a)
    }
}

#[doc(hidden)]
impl From<SlotId> for ast::SlotId {
    fn from(s: SlotId) -> Self {
        s.0
    }
}
