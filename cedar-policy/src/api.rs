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

//! This module contains the public library api
#![allow(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::similar_names,
    clippy::result_large_err, // see #878
)]

mod id;
#[cfg(feature = "entity-manifest")]
use cedar_policy_core::validator::entity_manifest;
// TODO (#1157) implement wrappers for these structs before they become public
#[cfg(feature = "entity-manifest")]
pub use cedar_policy_core::validator::entity_manifest::{
    AccessTrie, EntityManifest, EntityRoot, Fields, RootAccessTrie,
};
use cedar_policy_core::validator::json_schema;
use cedar_policy_core::validator::typecheck::{PolicyCheck, Typechecker};
pub use id::*;

#[cfg(feature = "deprecated-schema-compat")]
mod deprecated_schema_compat;

mod err;
pub use err::*;

pub use ast::Effect;
pub use authorizer::Decision;
#[cfg(feature = "partial-eval")]
use cedar_policy_core::ast::BorrowedRestrictedExpr;
use cedar_policy_core::ast::{self, RequestSchema, RestrictedExpr};
use cedar_policy_core::authorizer;
use cedar_policy_core::entities::{ContextSchema, Dereference};
use cedar_policy_core::est::{self, TemplateLink};
use cedar_policy_core::evaluator::Evaluator;
#[cfg(feature = "partial-eval")]
use cedar_policy_core::evaluator::RestrictedEvaluator;
use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::parser;
use cedar_policy_core::FromNormalizedStr;
use itertools::{Either, Itertools};
use miette::Diagnostic;
use ref_cast::RefCast;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::str::FromStr;
use std::sync::Arc;

// PANIC SAFETY: `CARGO_PKG_VERSION` should return a valid SemVer version string
#[allow(clippy::unwrap_used)]
pub(crate) mod version {
    use semver::Version;
    use std::sync::LazyLock;

    // Cedar Rust SDK Semantic Versioning version
    static SDK_VERSION: LazyLock<Version> =
        LazyLock::new(|| env!("CARGO_PKG_VERSION").parse().unwrap());
    // Cedar language version
    // The patch version field may be unnecessary
    static LANG_VERSION: LazyLock<Version> = LazyLock::new(|| Version::new(4, 3, 0));

    /// Get the Cedar SDK Semantic Versioning version
    #[allow(clippy::module_name_repetitions)]
    pub fn get_sdk_version() -> Version {
        SDK_VERSION.clone()
    }
    /// Get the Cedar language version
    #[allow(clippy::module_name_repetitions)]
    pub fn get_lang_version() -> Version {
        LANG_VERSION.clone()
    }
}

/// Entity datatype
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq, RefCast, Hash)]
pub struct Entity(pub(crate) ast::Entity);

#[doc(hidden)] // because this converts to a private/internal type
impl AsRef<ast::Entity> for Entity {
    fn as_ref(&self) -> &ast::Entity {
        &self.0
    }
}

#[doc(hidden)]
impl From<ast::Entity> for Entity {
    fn from(entity: ast::Entity) -> Self {
        Self(entity)
    }
}

impl Entity {
    /// Create a new `Entity` with this Uid, attributes, and parents (and no tags).
    ///
    /// Attribute values are specified here as "restricted expressions".
    /// See docs on `RestrictedExpression`
    /// ```
    /// # use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};
    /// # use std::collections::{HashMap, HashSet};
    /// # use std::str::FromStr;
    /// let eid = EntityId::from_str("alice").unwrap();
    /// let type_name = EntityTypeName::from_str("User").unwrap();
    /// let euid = EntityUid::from_type_name_and_id(type_name, eid);
    /// let attrs = HashMap::from([
    ///     ("age".to_string(), RestrictedExpression::from_str("21").unwrap()),
    ///     ("department".to_string(), RestrictedExpression::from_str("\"CS\"").unwrap()),
    /// ]);
    /// let parent_eid = EntityId::from_str("admin").unwrap();
    /// let parent_type_name = EntityTypeName::from_str("Group").unwrap();
    /// let parent_euid = EntityUid::from_type_name_and_id(parent_type_name, parent_eid);
    /// let parents = HashSet::from([parent_euid]);
    /// let entity = Entity::new(euid, attrs, parents);
    ///```
    pub fn new(
        uid: EntityUid,
        attrs: HashMap<String, RestrictedExpression>,
        parents: HashSet<EntityUid>,
    ) -> Result<Self, EntityAttrEvaluationError> {
        Self::new_with_tags(uid, attrs, parents, [])
    }

    /// Create a new `Entity` with no attributes or tags.
    ///
    /// Unlike [`Entity::new()`], this constructor cannot error.
    /// (The only source of errors in `Entity::new()` are attributes.)
    pub fn new_no_attrs(uid: EntityUid, parents: HashSet<EntityUid>) -> Self {
        // note that we take a "parents" parameter here; we will compute TC when
        // the `Entities` object is created
        Self(ast::Entity::new_with_attr_partial_value(
            uid.into(),
            [],
            HashSet::new(),
            parents.into_iter().map(EntityUid::into).collect(),
            [],
        ))
    }

    /// Create a new `Entity` with this Uid, attributes, parents, and tags.
    ///
    /// Attribute and tag values are specified here as "restricted expressions".
    /// See docs on [`RestrictedExpression`].
    pub fn new_with_tags(
        uid: EntityUid,
        attrs: impl IntoIterator<Item = (String, RestrictedExpression)>,
        parents: impl IntoIterator<Item = EntityUid>,
        tags: impl IntoIterator<Item = (String, RestrictedExpression)>,
    ) -> Result<Self, EntityAttrEvaluationError> {
        // note that we take a "parents" parameter here, not "ancestors"; we
        // will compute TC when the `Entities` object is created
        Ok(Self(ast::Entity::new(
            uid.into(),
            attrs.into_iter().map(|(k, v)| (k.into(), v.0)),
            HashSet::new(),
            parents.into_iter().map(EntityUid::into).collect(),
            tags.into_iter().map(|(k, v)| (k.into(), v.0)),
            Extensions::all_available(),
        )?))
    }

    /// Create a new `Entity` with this Uid, no attributes, and no parents.
    /// ```
    /// # use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid};
    /// # use std::str::FromStr;
    /// let eid = EntityId::from_str("alice").unwrap();
    /// let type_name = EntityTypeName::from_str("User").unwrap();
    /// let euid = EntityUid::from_type_name_and_id(type_name, eid);
    /// let alice = Entity::with_uid(euid);
    /// # cool_asserts::assert_matches!(alice.attr("age"), None);
    /// ```
    pub fn with_uid(uid: EntityUid) -> Self {
        Self(ast::Entity::with_uid(uid.into()))
    }

    /// Get the Uid of this entity
    /// ```
    /// # use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid};
    /// # use std::str::FromStr;
    /// # let eid = EntityId::from_str("alice").unwrap();
    /// let type_name = EntityTypeName::from_str("User").unwrap();
    /// let euid = EntityUid::from_type_name_and_id(type_name, eid);
    /// let alice = Entity::with_uid(euid.clone());
    /// assert_eq!(alice.uid(), euid);
    /// ```
    pub fn uid(&self) -> EntityUid {
        self.0.uid().clone().into()
    }

    /// Get the value for the given attribute, or `None` if not present.
    ///
    /// This can also return Some(Err) if the attribute is not a value (i.e., is
    /// unknown due to partial evaluation).
    /// ```
    /// # use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, EvalResult, RestrictedExpression};
    /// # use std::collections::{HashMap, HashSet};
    /// # use std::str::FromStr;
    /// let eid = EntityId::from_str("alice").unwrap();
    /// let type_name = EntityTypeName::from_str("User").unwrap();
    /// let euid = EntityUid::from_type_name_and_id(type_name, eid);
    /// let attrs = HashMap::from([
    ///     ("age".to_string(), RestrictedExpression::from_str("21").unwrap()),
    ///     ("department".to_string(), RestrictedExpression::from_str("\"CS\"").unwrap()),
    /// ]);
    /// let entity = Entity::new(euid, attrs, HashSet::new()).unwrap();
    /// assert_eq!(entity.attr("age").unwrap().unwrap(), EvalResult::Long(21));
    /// assert_eq!(entity.attr("department").unwrap().unwrap(), EvalResult::String("CS".to_string()));
    /// assert!(entity.attr("foo").is_none());
    /// ```
    pub fn attr(&self, attr: &str) -> Option<Result<EvalResult, PartialValueToValueError>> {
        match ast::Value::try_from(self.0.get(attr)?.clone()) {
            Ok(v) => Some(Ok(EvalResult::from(v))),
            Err(e) => Some(Err(e)),
        }
    }

    /// Get the value for the given tag, or `None` if not present.
    ///
    /// This can also return Some(Err) if the tag is not a value (i.e., is
    /// unknown due to partial evaluation).
    pub fn tag(&self, tag: &str) -> Option<Result<EvalResult, PartialValueToValueError>> {
        match ast::Value::try_from(self.0.get_tag(tag)?.clone()) {
            Ok(v) => Some(Ok(EvalResult::from(v))),
            Err(e) => Some(Err(e)),
        }
    }

    /// Consume the entity and return the entity's owned Uid, attributes and parents.
    pub fn into_inner(
        self,
    ) -> (
        EntityUid,
        HashMap<String, RestrictedExpression>,
        HashSet<EntityUid>,
    ) {
        let (uid, attrs, ancestors, mut parents, _) = self.0.into_inner();
        parents.extend(ancestors);

        let attrs = attrs
            .into_iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    match v {
                        ast::PartialValue::Value(val) => {
                            RestrictedExpression(ast::RestrictedExpr::from(val))
                        }
                        ast::PartialValue::Residual(exp) => {
                            RestrictedExpression(ast::RestrictedExpr::new_unchecked(exp))
                        }
                    },
                )
            })
            .collect();

        (
            uid.into(),
            attrs,
            parents.into_iter().map(Into::into).collect(),
        )
    }

    /// Parse an entity from an in-memory JSON value
    /// If a schema is provided, it is handled identically to [`Entities::from_json_str`]
    pub fn from_json_value(
        value: serde_json::Value,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_core::validator::CoreSchema::new(&s.0));
        let eparser = cedar_policy_core::entities::EntityJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        );
        eparser.single_from_json_value(value).map(Self)
    }

    /// Parse an entity from a JSON string
    /// If a schema is provided, it is handled identically to [`Entities::from_json_str`]
    pub fn from_json_str(
        src: impl AsRef<str>,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_core::validator::CoreSchema::new(&s.0));
        let eparser = cedar_policy_core::entities::EntityJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        );
        eparser.single_from_json_str(src).map(Self)
    }

    /// Parse an entity from a JSON reader
    /// If a schema is provided, it is handled identically to [`Entities::from_json_str`]
    pub fn from_json_file(f: impl Read, schema: Option<&Schema>) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_core::validator::CoreSchema::new(&s.0));
        let eparser = cedar_policy_core::entities::EntityJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        );
        eparser.single_from_json_file(f).map(Self)
    }

    /// Dump an `Entity` object into an entity JSON file.
    ///
    /// The resulting JSON will be suitable for parsing in via
    /// `from_json_*`, and will be parse-able even with no [`Schema`].
    ///
    /// To read an `Entity` object from JSON , use
    /// [`Self::from_json_file`], [`Self::from_json_value`], or [`Self::from_json_str`].
    pub fn write_to_json(&self, f: impl std::io::Write) -> Result<(), EntitiesError> {
        self.0.write_to_json(f)
    }

    /// Dump an `Entity` object into an in-memory JSON object.
    ///
    /// The resulting JSON will be suitable for parsing in via
    /// `from_json_*`, and will be parse-able even with no `Schema`.
    ///
    /// To read an `Entity` object from JSON , use
    /// [`Self::from_json_file`], [`Self::from_json_value`], or [`Self::from_json_str`].
    pub fn to_json_value(&self) -> Result<serde_json::Value, EntitiesError> {
        self.0.to_json_value()
    }

    /// Dump an `Entity` object into a JSON string.
    ///
    /// The resulting JSON will be suitable for parsing in via
    /// `from_json_*`, and will be parse-able even with no `Schema`.
    ///
    /// To read an `Entity` object from JSON , use
    /// [`Self::from_json_file`], [`Self::from_json_value`], or [`Self::from_json_str`].
    pub fn to_json_string(&self) -> Result<String, EntitiesError> {
        self.0.to_json_string()
    }
}

impl std::fmt::Display for Entity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents an entity hierarchy, and allows looking up `Entity` objects by
/// Uid.
#[repr(transparent)]
#[derive(Debug, Clone, Default, PartialEq, Eq, RefCast)]
pub struct Entities(pub(crate) cedar_policy_core::entities::Entities);

#[doc(hidden)] // because this converts to a private/internal type
impl AsRef<cedar_policy_core::entities::Entities> for Entities {
    fn as_ref(&self) -> &cedar_policy_core::entities::Entities {
        &self.0
    }
}

#[doc(hidden)]
impl From<cedar_policy_core::entities::Entities> for Entities {
    fn from(entities: cedar_policy_core::entities::Entities) -> Self {
        Self(entities)
    }
}

use entities_errors::EntitiesError;

impl Entities {
    /// Create a fresh `Entities` with no entities
    /// ```
    /// # use cedar_policy::Entities;
    /// let entities = Entities::empty();
    /// ```
    pub fn empty() -> Self {
        Self(cedar_policy_core::entities::Entities::new())
    }

    /// Get the `Entity` with the given Uid, if any
    pub fn get(&self, uid: &EntityUid) -> Option<&Entity> {
        match self.0.entity(uid.as_ref()) {
            Dereference::Residual(_) | Dereference::NoSuchEntity => None,
            Dereference::Data(e) => Some(Entity::ref_cast(e)),
        }
    }

    /// Transform the store into a partial store, where
    /// attempting to dereference a non-existent `EntityUid` results in
    /// a residual instead of an error.
    #[doc = include_str!("../experimental_warning.md")]
    #[must_use]
    #[cfg(feature = "partial-eval")]
    pub fn partial(self) -> Self {
        Self(self.0.partial())
    }

    /// Iterate over the `Entity`'s in the `Entities`
    pub fn iter(&self) -> impl Iterator<Item = &Entity> {
        self.0.iter().map(Entity::ref_cast)
    }

    /// Create an `Entities` object with the given entities.
    ///
    /// `schema` represents a source of `Action` entities, which will be added
    /// to the entities provided.
    /// (If any `Action` entities are present in the provided entities, and a
    /// `schema` is also provided, each `Action` entity in the provided entities
    /// must exactly match its definition in the schema or an error is
    /// returned.)
    ///
    /// If a `schema` is present, this function will also ensure that the
    /// produced entities fully conform to the `schema` -- for instance, it will
    /// error if attributes have the wrong types (e.g., string instead of
    /// integer), or if required attributes are missing or superfluous
    /// attributes are provided.
    /// ## Errors
    /// - [`EntitiesError::Duplicate`] if there are any duplicate entities in `entities`
    /// - [`EntitiesError::InvalidEntity`] if `schema` is not none and any entities do not conform
    ///   to the schema
    pub fn from_entities(
        entities: impl IntoIterator<Item = Entity>,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        cedar_policy_core::entities::Entities::from_entities(
            entities.into_iter().map(|e| e.0),
            schema
                .map(|s| cedar_policy_core::validator::CoreSchema::new(&s.0))
                .as_ref(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
            Extensions::all_available(),
        )
        .map(Entities)
    }

    /// Add all of the [`Entity`]s in the collection to this [`Entities`]
    /// structure, re-computing the transitive closure.
    ///
    /// If a `schema` is provided, this method will ensure that the added
    /// entities fully conform to the schema -- for instance, it will error if
    /// attributes have the wrong types (e.g., string instead of integer), or if
    /// required attributes are missing or superfluous attributes are provided.
    /// (This method will not add action entities from the `schema`.)
    ///
    /// Re-computing the transitive closure can be expensive, so it is advised
    /// to not call this method in a loop.
    /// ## Errors
    /// - [`EntitiesError::Duplicate`] if there is a pair of non-identical entities in `entities` with the same Entity UID,
    ///   or there is an entity in `entities` with the same Entity UID as a non-identical entity in this structure
    /// - [`EntitiesError::InvalidEntity`] if `schema` is not none and any entities do not conform
    ///   to the schema
    pub fn add_entities(
        self,
        entities: impl IntoIterator<Item = Entity>,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        Ok(Self(
            self.0.add_entities(
                entities.into_iter().map(|e| Arc::new(e.0)),
                schema
                    .map(|s| cedar_policy_core::validator::CoreSchema::new(&s.0))
                    .as_ref(),
                cedar_policy_core::entities::TCComputation::ComputeNow,
                Extensions::all_available(),
            )?,
        ))
    }

    /// Removes each of the [`EntityUid`]s in the iterator
    /// from this [`Entities`] structure, re-computing the transitive
    /// closure after removing all edges to/from the removed entities.
    ///
    /// Re-computing the transitive closure can be expensive, so it is
    /// advised to not call this method in a loop.
    pub fn remove_entities(
        self,
        entity_ids: impl IntoIterator<Item = EntityUid>,
    ) -> Result<Self, EntitiesError> {
        Ok(Self(self.0.remove_entities(
            entity_ids.into_iter().map(|euid| euid.0),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        )?))
    }

    /// Updates or adds all of the [`Entity`]s in the collection to this [`Entities`]
    /// structure, re-computing the transitive closure.
    ///
    /// If a `schema` is provided, this method will ensure that the added
    /// entities fully conform to the schema -- for instance, it will error if
    /// attributes have the wrong types (e.g., string instead of integer), or if
    /// required attributes are missing or superfluous attributes are provided.
    /// (This method will not add action entities from the `schema`.)
    ///
    /// Re-computing the transitive closure can be expensive, so it is advised
    /// to not call this method in a loop.
    /// ## Errors
    /// - [`EntitiesError::InvalidEntity`] if `schema` is not none and any entities do not conform
    ///   to the schema
    pub fn upsert_entities(
        self,
        entities: impl IntoIterator<Item = Entity>,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        Ok(Self(
            self.0.upsert_entities(
                entities.into_iter().map(|e| Arc::new(e.0)),
                schema
                    .map(|s| cedar_policy_core::validator::CoreSchema::new(&s.0))
                    .as_ref(),
                cedar_policy_core::entities::TCComputation::ComputeNow,
                Extensions::all_available(),
            )?,
        ))
    }

    /// Parse an entities JSON file (in [&str] form) and add them into this
    /// [`Entities`] structure, re-computing the transitive closure
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit.
    /// This method will also ensure that the added entities fully conform to the
    /// schema -- for instance, it will error if attributes have the wrong types
    /// (e.g., string instead of integer), or if required attributes are missing
    /// or superfluous attributes are provided.
    /// (This method will not add action entities from the `schema`.)
    ///
    /// Re-computing the transitive closure can be expensive, so it is advised
    /// to not call this method in a loop.
    /// ## Errors
    /// - [`EntitiesError::Duplicate`] if there is a pair of non-identical entities in
    ///   `entities` with the same Entity UID, or there is an entity in `entities` with the
    ///   same Entity UID as a non-identical entity in this structure
    /// - [`EntitiesError::InvalidEntity`] if `schema` is not none and any entities do not conform
    ///   to the schema
    /// - [`EntitiesError::Deserialization`] if there are errors while parsing the json
    pub fn add_entities_from_json_str(
        self,
        json: &str,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_core::validator::CoreSchema::new(&s.0));
        let eparser = cedar_policy_core::entities::EntityJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        );
        let new_entities = eparser.iter_from_json_str(json)?.map(Arc::new);
        Ok(Self(self.0.add_entities(
            new_entities,
            schema.as_ref(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
            Extensions::all_available(),
        )?))
    }

    /// Parse an entities JSON file (in [`serde_json::Value`] form) and add them
    /// into this [`Entities`] structure, re-computing the transitive closure
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit.
    /// This method will also ensure that the added entities fully conform to the
    /// schema -- for instance, it will error if attributes have the wrong types
    /// (e.g., string instead of integer), or if required attributes are missing
    /// or superfluous attributes are provided.
    /// (This method will not add action entities from the `schema`.)
    ///
    /// Re-computing the transitive closure can be expensive, so it is advised
    /// to not call this method in a loop.
    /// ## Errors
    /// - [`EntitiesError::Duplicate`] if there is a pair of non-identical entities in
    ///   `entities` with the same Entity UID, or there is an entity in `entities` with the same
    ///   Entity UID as a non-identical entity in this structure
    /// - [`EntitiesError::InvalidEntity`] if `schema` is not none and any entities do not conform
    ///   to the schema
    /// - [`EntitiesError::Deserialization`] if there are errors while parsing the json
    pub fn add_entities_from_json_value(
        self,
        json: serde_json::Value,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_core::validator::CoreSchema::new(&s.0));
        let eparser = cedar_policy_core::entities::EntityJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        );
        let new_entities = eparser.iter_from_json_value(json)?.map(Arc::new);
        Ok(Self(self.0.add_entities(
            new_entities,
            schema.as_ref(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
            Extensions::all_available(),
        )?))
    }

    /// Parse an entities JSON file (in [`std::io::Read`] form) and add them
    /// into this [`Entities`] structure, re-computing the transitive closure
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit.
    /// This method will also ensure that the added entities fully conform to the
    /// schema -- for instance, it will error if attributes have the wrong types
    /// (e.g., string instead of integer), or if required attributes are missing
    /// or superfluous attributes are provided.
    /// (This method will not add action entities from the `schema`.)
    ///
    /// Re-computing the transitive closure can be expensive, so it is advised
    /// to not call this method in a loop.
    ///
    /// ## Errors
    /// - [`EntitiesError::Duplicate`] if there is a pair of non-identical entities in `entities`
    ///   with the same Entity UID, or there is an entity in `entities` with the same Entity UID as a
    ///   non-identical entity in this structure
    /// - [`EntitiesError::InvalidEntity`] if `schema` is not none and any entities do not conform
    ///   to the schema
    /// - [`EntitiesError::Deserialization`] if there are errors while parsing the json
    pub fn add_entities_from_json_file(
        self,
        json: impl std::io::Read,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_core::validator::CoreSchema::new(&s.0));
        let eparser = cedar_policy_core::entities::EntityJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        );
        let new_entities = eparser.iter_from_json_file(json)?.map(Arc::new);
        Ok(Self(self.0.add_entities(
            new_entities,
            schema.as_ref(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
            Extensions::all_available(),
        )?))
    }

    /// Parse an entities JSON file (in `&str` form) into an `Entities` object
    ///
    /// `schema` represents a source of `Action` entities, which will be added
    /// to the entities parsed from JSON.
    /// (If any `Action` entities are present in the JSON, and a `schema` is
    /// also provided, each `Action` entity in the JSON must exactly match its
    /// definition in the schema or an error is returned.)
    ///
    /// If a `schema` is present, this will also inform the parsing: for
    /// instance, it will allow `__entity` and `__extn` escapes to be implicit.
    ///
    /// Finally, if a `schema` is present, this function will ensure
    /// that the produced entities fully conform to the `schema` -- for
    /// instance, it will error if attributes have the wrong types (e.g., string
    /// instead of integer), or if required attributes are missing or
    /// superfluous attributes are provided.
    ///
    /// ## Errors
    /// - [`EntitiesError::Duplicate`] if there are any duplicate entities in `entities`
    /// - [`EntitiesError::InvalidEntity`] if `schema` is not none and any entities do not conform
    ///   to the schema
    /// - [`EntitiesError::Deserialization`] if there are errors while parsing the json
    ///
    /// ```
    /// # use cedar_policy::{Entities, EntityId, EntityTypeName, EntityUid, EvalResult, Request,PolicySet};
    /// # use std::str::FromStr;
    /// let data =r#"
    /// [
    /// {
    ///   "uid": {"type":"User","id":"alice"},
    ///   "attrs": {
    ///     "age":19,
    ///     "ip_addr":{"__extn":{"fn":"ip", "arg":"10.0.1.101"}}
    ///   },
    ///   "parents": [{"type":"Group","id":"admin"}]
    /// },
    /// {
    ///   "uid": {"type":"Group","id":"admin"},
    ///   "attrs": {},
    ///   "parents": []
    /// }
    /// ]
    /// "#;
    /// let entities = Entities::from_json_str(data, None).unwrap();
    /// # let euid = EntityUid::from_str(r#"User::"alice""#).unwrap();
    /// # let entity = entities.get(&euid).unwrap();
    /// # assert_eq!(entity.attr("age").unwrap().unwrap(), EvalResult::Long(19));
    /// # let ip = entity.attr("ip_addr").unwrap().unwrap();
    /// # assert_eq!(ip, EvalResult::ExtensionValue("ip(\"10.0.1.101\")".to_string()));
    /// ```
    pub fn from_json_str(json: &str, schema: Option<&Schema>) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_core::validator::CoreSchema::new(&s.0));
        let eparser = cedar_policy_core::entities::EntityJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        );
        eparser.from_json_str(json).map(Entities)
    }

    /// Parse an entities JSON file (in `serde_json::Value` form) into an
    /// `Entities` object
    ///
    /// `schema` represents a source of `Action` entities, which will be added
    /// to the entities parsed from JSON.
    /// (If any `Action` entities are present in the JSON, and a `schema` is
    /// also provided, each `Action` entity in the JSON must exactly match its
    /// definition in the schema or an error is returned.)
    ///
    /// If a `schema` is present, this will also inform the parsing: for
    /// instance, it will allow `__entity` and `__extn` escapes to be implicit.
    ///
    /// Finally, if a `schema` is present, this function will ensure
    /// that the produced entities fully conform to the `schema` -- for
    /// instance, it will error if attributes have the wrong types (e.g., string
    /// instead of integer), or if required attributes are missing or
    /// superfluous attributes are provided.
    ///
    /// ## Errors
    /// - [`EntitiesError::Duplicate`] if there are any duplicate entities in `entities`
    /// - [`EntitiesError::InvalidEntity`]if `schema` is not none and any entities do not conform
    ///   to the schema
    /// - [`EntitiesError::Deserialization`] if there are errors while parsing the json
    ///
    /// ```
    /// # use cedar_policy::{Entities, EntityId, EntityTypeName, EntityUid, EvalResult, Request,PolicySet};
    /// let data =serde_json::json!(
    /// [
    /// {
    ///   "uid": {"type":"User","id":"alice"},
    ///   "attrs": {
    ///     "age":19,
    ///     "ip_addr":{"__extn":{"fn":"ip", "arg":"10.0.1.101"}}
    ///   },
    ///   "parents": [{"type":"Group","id":"admin"}]
    /// },
    /// {
    ///   "uid": {"type":"Group","id":"admin"},
    ///   "attrs": {},
    ///   "parents": []
    /// }
    /// ]
    /// );
    /// let entities = Entities::from_json_value(data, None).unwrap();
    /// ```
    pub fn from_json_value(
        json: serde_json::Value,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_core::validator::CoreSchema::new(&s.0));
        let eparser = cedar_policy_core::entities::EntityJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        );
        eparser.from_json_value(json).map(Entities)
    }

    /// Parse an entities JSON file (in `std::io::Read` form) into an `Entities`
    /// object
    ///
    /// `schema` represents a source of `Action` entities, which will be added
    /// to the entities parsed from JSON.
    /// (If any `Action` entities are present in the JSON, and a `schema` is
    /// also provided, each `Action` entity in the JSON must exactly match its
    /// definition in the schema or an error is returned.)
    ///
    /// If a `schema` is present, this will also inform the parsing: for
    /// instance, it will allow `__entity` and `__extn` escapes to be implicit.
    ///
    /// Finally, if a `schema` is present, this function will ensure
    /// that the produced entities fully conform to the `schema` -- for
    /// instance, it will error if attributes have the wrong types (e.g., string
    /// instead of integer), or if required attributes are missing or
    /// superfluous attributes are provided.
    ///
    /// ## Errors
    /// - [`EntitiesError::Duplicate`] if there are any duplicate entities in `entities`
    /// - [`EntitiesError::InvalidEntity`] if `schema` is not none and any entities do not conform
    ///   to the schema
    /// - [`EntitiesError::Deserialization`] if there are errors while parsing the json
    pub fn from_json_file(
        json: impl std::io::Read,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_core::validator::CoreSchema::new(&s.0));
        let eparser = cedar_policy_core::entities::EntityJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        );
        eparser.from_json_file(json).map(Entities)
    }

    /// Is entity `a` an ancestor of entity `b`?
    /// Same semantics as `b in a` in the Cedar language
    pub fn is_ancestor_of(&self, a: &EntityUid, b: &EntityUid) -> bool {
        match self.0.entity(b.as_ref()) {
            Dereference::Data(b) => b.is_descendant_of(a.as_ref()),
            _ => a == b, // if b doesn't exist, `b in a` is only true if `b == a`
        }
    }

    /// Get an iterator over the ancestors of the given Euid.
    /// Returns `None` if the given `Euid` does not exist.
    pub fn ancestors<'a>(
        &'a self,
        euid: &EntityUid,
    ) -> Option<impl Iterator<Item = &'a EntityUid>> {
        let entity = match self.0.entity(euid.as_ref()) {
            Dereference::Residual(_) | Dereference::NoSuchEntity => None,
            Dereference::Data(e) => Some(e),
        }?;
        Some(entity.ancestors().map(EntityUid::ref_cast))
    }

    /// Returns the number of `Entity`s in the `Entities`
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the `Entities` contains no `Entity`s
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Dump an `Entities` object into an entities JSON file.
    ///
    /// The resulting JSON will be suitable for parsing in via
    /// `from_json_*`, and will be parse-able even with no `Schema`.
    ///
    /// To read an `Entities` object from an entities JSON file, use
    /// `from_json_file`.
    pub fn write_to_json(&self, f: impl std::io::Write) -> std::result::Result<(), EntitiesError> {
        self.0.write_to_json(f)
    }

    #[doc = include_str!("../experimental_warning.md")]
    /// Visualize an `Entities` object in the graphviz `dot`
    /// format. Entity visualization is best-effort and not well tested.
    /// Feel free to submit an issue if you are using this feature and would like it improved.
    pub fn to_dot_str(&self) -> String {
        let mut dot_str = String::new();
        // PANIC SAFETY: Writing to the String `dot_str` cannot fail, so `to_dot_str` will not return an `Err` result.
        #[allow(clippy::unwrap_used)]
        self.0.to_dot_str(&mut dot_str).unwrap();
        dot_str
    }
}

/// Validates scope variables against the provided schema
///
/// Returns Ok(()) if the context is valid according to the schema, or an error otherwise
///
/// This validation is already handled by `Request::new`, so there is no need to separately call
/// if you are validating the whole request
pub fn validate_scope_variables(
    principal: &EntityUid,
    action: &EntityUid,
    resource: &EntityUid,
    schema: &Schema,
) -> std::result::Result<(), RequestValidationError> {
    Ok(RequestSchema::validate_scope_variables(
        &schema.0,
        Some(&principal.0),
        Some(&action.0),
        Some(&resource.0),
    )?)
}

/// Utilities for defining `IntoIterator` over `Entities`
pub mod entities {

    /// `IntoIter` iterator for `Entities`
    #[derive(Debug)]
    pub struct IntoIter {
        pub(super) inner: <cedar_policy_core::entities::Entities as IntoIterator>::IntoIter,
    }

    impl Iterator for IntoIter {
        type Item = super::Entity;

        fn next(&mut self) -> Option<Self::Item> {
            self.inner.next().map(super::Entity)
        }
        fn size_hint(&self) -> (usize, Option<usize>) {
            self.inner.size_hint()
        }
    }
}

impl IntoIterator for Entities {
    type Item = Entity;
    type IntoIter = entities::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter {
            inner: self.0.into_iter(),
        }
    }
}

/// Authorizer object, which provides responses to authorization queries
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct Authorizer(authorizer::Authorizer);

#[doc(hidden)] // because this converts to a private/internal type
impl AsRef<authorizer::Authorizer> for Authorizer {
    fn as_ref(&self) -> &authorizer::Authorizer {
        &self.0
    }
}

impl Default for Authorizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Authorizer {
    /// Create a new `Authorizer`
    ///
    /// The authorizer uses the `stacker` crate to manage stack size and tries to use a sane default.
    /// If the default is not right for you, you can try wrapping the authorizer or individual calls
    /// to `is_authorized` in `stacker::grow`.
    /// Note that on platforms not supported by `stacker` (e.g., Wasm, Android),
    /// the authorizer will simply assume that the stack size is sufficient. As a result, large inputs
    /// may result in stack overflows and crashing the process.
    /// But on all platforms supported by `stacker` (Linux, macOS, ...), Cedar will return the
    /// graceful error `RecursionLimit` instead of crashing.
    /// ```
    /// # use cedar_policy::{Authorizer, Context, Entities, EntityId, EntityTypeName,
    /// # EntityUid, Request,PolicySet};
    /// # use std::str::FromStr;
    /// # // create a request
    /// # let p_eid = EntityId::from_str("alice").unwrap();
    /// # let p_name: EntityTypeName = EntityTypeName::from_str("User").unwrap();
    /// # let p = EntityUid::from_type_name_and_id(p_name, p_eid);
    /// #
    /// # let a_eid = EntityId::from_str("view").unwrap();
    /// # let a_name: EntityTypeName = EntityTypeName::from_str("Action").unwrap();
    /// # let a = EntityUid::from_type_name_and_id(a_name, a_eid);
    /// #
    /// # let r_eid = EntityId::from_str("trip").unwrap();
    /// # let r_name: EntityTypeName = EntityTypeName::from_str("Album").unwrap();
    /// # let r = EntityUid::from_type_name_and_id(r_name, r_eid);
    /// #
    /// # let c = Context::empty();
    /// #
    /// # let request: Request = Request::new(p, a, r, c, None).unwrap();
    /// #
    /// # // create a policy
    /// # let s = r#"permit(
    /// #     principal == User::"alice",
    /// #     action == Action::"view",
    /// #     resource == Album::"trip"
    /// #   )when{
    /// #     principal.ip_addr.isIpv4()
    /// #   };
    /// # "#;
    /// # let policy = PolicySet::from_str(s).expect("policy error");
    /// # // create entities
    /// # let e = r#"[
    /// #     {
    /// #         "uid": {"type":"User","id":"alice"},
    /// #         "attrs": {
    /// #             "age":19,
    /// #             "ip_addr":{"__extn":{"fn":"ip", "arg":"10.0.1.101"}}
    /// #         },
    /// #         "parents": []
    /// #     }
    /// # ]"#;
    /// # let entities = Entities::from_json_str(e, None).expect("entity error");
    /// let authorizer = Authorizer::new();
    /// let r = authorizer.is_authorized(&request, &policy, &entities);
    /// ```
    pub fn new() -> Self {
        Self(authorizer::Authorizer::new())
    }

    /// Returns an authorization response for `r` with respect to the given
    /// `PolicySet` and `Entities`.
    ///
    /// The language spec and formal model give a precise definition of how this
    /// is computed.
    /// ```
    /// # use cedar_policy::{Authorizer,Context,Decision,Entities,EntityId,EntityTypeName, EntityUid, Request,PolicySet};
    /// # use std::str::FromStr;
    /// // create a request
    /// let p_eid = EntityId::from_str("alice").unwrap();
    /// let p_name: EntityTypeName = EntityTypeName::from_str("User").unwrap();
    /// let p = EntityUid::from_type_name_and_id(p_name, p_eid);
    ///
    /// let a_eid = EntityId::from_str("view").unwrap();
    /// let a_name: EntityTypeName = EntityTypeName::from_str("Action").unwrap();
    /// let a = EntityUid::from_type_name_and_id(a_name, a_eid);
    ///
    /// let r_eid = EntityId::from_str("trip").unwrap();
    /// let r_name: EntityTypeName = EntityTypeName::from_str("Album").unwrap();
    /// let r = EntityUid::from_type_name_and_id(r_name, r_eid);
    ///
    /// let c = Context::empty();
    ///
    /// let request: Request = Request::new(p, a, r, c, None).unwrap();
    ///
    /// // create a policy
    /// let s = r#"
    /// permit (
    ///   principal == User::"alice",
    ///   action == Action::"view",
    ///   resource == Album::"trip"
    /// )
    /// when { principal.ip_addr.isIpv4() };
    /// "#;
    /// let policy = PolicySet::from_str(s).expect("policy error");
    ///
    /// // create entities
    /// let e = r#"[
    ///     {
    ///         "uid": {"type":"User","id":"alice"},
    ///         "attrs": {
    ///             "age":19,
    ///             "ip_addr":{"__extn":{"fn":"ip", "arg":"10.0.1.101"}}
    ///         },
    ///         "parents": []
    ///     }
    /// ]"#;
    /// let entities = Entities::from_json_str(e, None).expect("entity error");
    ///
    /// let authorizer = Authorizer::new();
    /// let response = authorizer.is_authorized(&request, &policy, &entities);
    /// assert_eq!(response.decision(), Decision::Allow);
    /// ```
    pub fn is_authorized(&self, r: &Request, p: &PolicySet, e: &Entities) -> Response {
        self.0.is_authorized(r.0.clone(), &p.ast, &e.0).into()
    }

    /// A partially evaluated authorization request.
    /// The Authorizer will attempt to make as much progress as possible in the presence of unknowns.
    /// If the Authorizer can reach a response, it will return that response.
    /// Otherwise, it will return a list of residual policies that still need to be evaluated.
    #[doc = include_str!("../experimental_warning.md")]
    #[cfg(feature = "partial-eval")]
    pub fn is_authorized_partial(
        &self,
        query: &Request,
        policy_set: &PolicySet,
        entities: &Entities,
    ) -> PartialResponse {
        let response = self
            .0
            .is_authorized_core(query.0.clone(), &policy_set.ast, &entities.0);
        PartialResponse(response)
    }
}

/// Authorization response returned from the `Authorizer`
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Response {
    /// Authorization decision
    pub(crate) decision: Decision,
    /// Diagnostics providing more information on how this decision was reached
    pub(crate) diagnostics: Diagnostics,
}

/// A partially evaluated authorization response.
///
/// Splits the results into several categories: satisfied, false, and residual for each policy effect.
/// Also tracks all the errors that were encountered during evaluation.
#[doc = include_str!("../experimental_warning.md")]
#[cfg(feature = "partial-eval")]
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct PartialResponse(cedar_policy_core::authorizer::PartialResponse);

#[cfg(feature = "partial-eval")]
impl PartialResponse {
    /// Attempt to reach a partial decision; the presence of residuals may result in returning [`None`],
    /// indicating that a decision could not be reached given the unknowns
    pub fn decision(&self) -> Option<Decision> {
        self.0.decision()
    }

    /// Convert this response into a concrete evaluation response.
    /// All residuals are treated as errors
    pub fn concretize(self) -> Response {
        self.0.concretize().into()
    }

    /// Returns the set of [`Policy`]s that were definitely satisfied.
    /// This will be the set of policies (both `permit` and `forbid`) that evaluated to `true`
    pub fn definitely_satisfied(&self) -> impl Iterator<Item = Policy> + '_ {
        self.0.definitely_satisfied().map(Policy::from_ast)
    }

    /// Returns the set of [`PolicyId`]s that encountered errors
    pub fn definitely_errored(&self) -> impl Iterator<Item = &PolicyId> {
        self.0.definitely_errored().map(PolicyId::ref_cast)
    }

    /// Returns an over-approximation of the set of determining policies
    ///
    /// This is all policies that may be determining for any substitution of the unknowns.
    /// Policies not in this set will not affect the final decision, regardless of any
    /// substitutions.
    ///
    /// For more information on what counts as "determining" see: <https://docs.cedarpolicy.com/auth/authorization.html#request-authorization>
    pub fn may_be_determining(&self) -> impl Iterator<Item = Policy> + '_ {
        self.0.may_be_determining().map(Policy::from_ast)
    }

    /// Returns an under-approximation of the set of determining policies
    ///
    /// This is all policies that must be determining for all possible substitutions of the unknowns.
    /// This set will include policies that evaluated to `true` and are guaranteed to be
    /// contributing to the final authorization decision.
    ///
    /// For more information on what counts as "determining" see: <https://docs.cedarpolicy.com/auth/authorization.html#request-authorization>
    pub fn must_be_determining(&self) -> impl Iterator<Item = Policy> + '_ {
        self.0.must_be_determining().map(Policy::from_ast)
    }

    /// Returns the set of non-trivial (meaning more than just `true` or `false`) residuals expressions
    pub fn nontrivial_residuals(&'_ self) -> impl Iterator<Item = Policy> + '_ {
        self.0.nontrivial_residuals().map(Policy::from_ast)
    }

    /// Returns every policy as a residual expression
    pub fn all_residuals(&'_ self) -> impl Iterator<Item = Policy> + '_ {
        self.0.all_residuals().map(Policy::from_ast)
    }

    /// Returns all unknown entities during the evaluation of the response
    pub fn unknown_entities(&self) -> HashSet<EntityUid> {
        let mut entity_uids = HashSet::new();
        for policy in self.0.all_residuals() {
            entity_uids.extend(policy.unknown_entities().into_iter().map(Into::into));
        }
        entity_uids
    }

    /// Return the residual for a given [`PolicyId`], if it exists in the response
    pub fn get(&self, id: &PolicyId) -> Option<Policy> {
        self.0.get(id.as_ref()).map(Policy::from_ast)
    }

    /// Attempt to re-authorize this response given a mapping from unknowns to values.
    #[allow(clippy::needless_pass_by_value)]
    #[deprecated = "use reauthorize_with_bindings"]
    pub fn reauthorize(
        &self,
        mapping: HashMap<SmolStr, RestrictedExpression>,
        auth: &Authorizer,
        es: &Entities,
    ) -> Result<Self, ReauthorizationError> {
        self.reauthorize_with_bindings(mapping.iter().map(|(k, v)| (k.as_str(), v)), auth, es)
    }

    /// Attempt to re-authorize this response given a mapping from unknowns to values, provided as an iterator.
    /// Exhausts the iterator, returning any evaluation errors in the restricted expressions, regardless whether there is a matching unknown.
    pub fn reauthorize_with_bindings<'m>(
        &self,
        mapping: impl IntoIterator<Item = (&'m str, &'m RestrictedExpression)>,
        auth: &Authorizer,
        es: &Entities,
    ) -> Result<Self, ReauthorizationError> {
        let exts = Extensions::all_available();
        let evaluator = RestrictedEvaluator::new(exts);
        let mapping = mapping
            .into_iter()
            .map(|(name, expr)| {
                evaluator
                    .interpret(BorrowedRestrictedExpr::new_unchecked(expr.0.as_ref()))
                    .map(|v| (name.into(), v))
            })
            .collect::<Result<HashMap<_, _>, EvaluationError>>()?;
        let r = self.0.reauthorize(&mapping, &auth.0, &es.0)?;
        Ok(Self(r))
    }
}

#[cfg(feature = "partial-eval")]
#[doc(hidden)]
impl From<cedar_policy_core::authorizer::PartialResponse> for PartialResponse {
    fn from(pr: cedar_policy_core::authorizer::PartialResponse) -> Self {
        Self(pr)
    }
}

/// Diagnostics providing more information on how a `Decision` was reached
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Diagnostics {
    /// `PolicyId`s of the policies that contributed to the decision.
    /// If no policies applied to the request, this set will be empty.
    reason: HashSet<PolicyId>,
    /// Errors that occurred during authorization. The errors should be
    /// treated as unordered, since policies may be evaluated in any order.
    errors: Vec<AuthorizationError>,
}

#[doc(hidden)]
impl From<authorizer::Diagnostics> for Diagnostics {
    fn from(diagnostics: authorizer::Diagnostics) -> Self {
        Self {
            reason: diagnostics.reason.into_iter().map(PolicyId::new).collect(),
            errors: diagnostics.errors.into_iter().map(Into::into).collect(),
        }
    }
}

impl Diagnostics {
    /// Get the `PolicyId`s of the policies that contributed to the decision.
    /// If no policies applied to the request, this set will be empty.
    /// ```
    /// # use cedar_policy::{Authorizer, Context, Decision, Entities, EntityId, EntityTypeName,
    /// # EntityUid, Request,PolicySet};
    /// # use std::str::FromStr;
    /// # // create a request
    /// # let p_eid = EntityId::from_str("alice").unwrap();
    /// # let p_name: EntityTypeName = EntityTypeName::from_str("User").unwrap();
    /// # let p = EntityUid::from_type_name_and_id(p_name, p_eid);
    /// #
    /// # let a_eid = EntityId::from_str("view").unwrap();
    /// # let a_name: EntityTypeName = EntityTypeName::from_str("Action").unwrap();
    /// # let a = EntityUid::from_type_name_and_id(a_name, a_eid);
    /// #
    /// # let r_eid = EntityId::from_str("trip").unwrap();
    /// # let r_name: EntityTypeName = EntityTypeName::from_str("Album").unwrap();
    /// # let r = EntityUid::from_type_name_and_id(r_name, r_eid);
    /// #
    /// # let c = Context::empty();
    /// #
    /// # let request: Request = Request::new(p, a, r, c, None).unwrap();
    /// #
    /// # // create a policy
    /// # let s = r#"permit(
    /// #     principal == User::"alice",
    /// #     action == Action::"view",
    /// #     resource == Album::"trip"
    /// #   )when{
    /// #     principal.ip_addr.isIpv4()
    /// #   };
    /// # "#;
    /// # let policy = PolicySet::from_str(s).expect("policy error");
    /// # // create entities
    /// # let e = r#"[
    /// #     {
    /// #         "uid": {"type":"User","id":"alice"},
    /// #         "attrs": {
    /// #             "age":19,
    /// #             "ip_addr":{"__extn":{"fn":"ip", "arg":"10.0.1.101"}}
    /// #         },
    /// #         "parents": []
    /// #     }
    /// # ]"#;
    /// # let entities = Entities::from_json_str(e, None).expect("entity error");
    /// let authorizer = Authorizer::new();
    /// let response = authorizer.is_authorized(&request, &policy, &entities);
    /// match response.decision() {
    ///     Decision::Allow => println!("ALLOW"),
    ///     Decision::Deny => println!("DENY"),
    /// }
    /// println!("note: this decision was due to the following policies:");
    /// for reason in response.diagnostics().reason() {
    ///     println!("{}", reason);
    /// }
    /// ```
    pub fn reason(&self) -> impl Iterator<Item = &PolicyId> {
        self.reason.iter()
    }

    /// Get the errors that occurred during authorization. The errors should be
    /// treated as unordered, since policies may be evaluated in any order.
    /// ```
    /// # use cedar_policy::{Authorizer, Context, Decision, Entities, EntityId, EntityTypeName,
    /// # EntityUid, Request,PolicySet};
    /// # use std::str::FromStr;
    /// # // create a request
    /// # let p_eid = EntityId::from_str("alice").unwrap();
    /// # let p_name: EntityTypeName = EntityTypeName::from_str("User").unwrap();
    /// # let p = EntityUid::from_type_name_and_id(p_name, p_eid);
    /// #
    /// # let a_eid = EntityId::from_str("view").unwrap();
    /// # let a_name: EntityTypeName = EntityTypeName::from_str("Action").unwrap();
    /// # let a = EntityUid::from_type_name_and_id(a_name, a_eid);
    /// #
    /// # let r_eid = EntityId::from_str("trip").unwrap();
    /// # let r_name: EntityTypeName = EntityTypeName::from_str("Album").unwrap();
    /// # let r = EntityUid::from_type_name_and_id(r_name, r_eid);
    /// #
    /// # let c = Context::empty();
    /// #
    /// # let request: Request = Request::new(p, a, r, c, None).unwrap();
    /// #
    /// # // create a policy
    /// # let s = r#"permit(
    /// #     principal == User::"alice",
    /// #     action == Action::"view",
    /// #     resource == Album::"trip"
    /// #   )when{
    /// #     principal.ip_addr.isIpv4()
    /// #   };
    /// # "#;
    /// # let policy = PolicySet::from_str(s).expect("policy error");
    /// # // create entities
    /// # let e = r#"[
    /// #     {
    /// #         "uid": {"type":"User","id":"alice"},
    /// #         "attrs": {
    /// #             "age":19,
    /// #             "ip_addr":{"__extn":{"fn":"ip", "arg":"10.0.1.101"}}
    /// #         },
    /// #         "parents": []
    /// #     }
    /// # ]"#;
    /// # let entities = Entities::from_json_str(e, None).expect("entity error");
    /// let authorizer = Authorizer::new();
    /// let response = authorizer.is_authorized(&request, &policy, &entities);
    /// match response.decision() {
    ///     Decision::Allow => println!("ALLOW"),
    ///     Decision::Deny => println!("DENY"),
    /// }
    /// for err in response.diagnostics().errors() {
    ///     println!("{}", err);
    /// }
    /// ```
    pub fn errors(&self) -> impl Iterator<Item = &AuthorizationError> + '_ {
        self.errors.iter()
    }

    /// Consume the `Diagnostics`, producing owned versions of `reason()` and `errors()`
    pub(crate) fn into_components(
        self,
    ) -> (
        impl Iterator<Item = PolicyId>,
        impl Iterator<Item = AuthorizationError>,
    ) {
        (self.reason.into_iter(), self.errors.into_iter())
    }
}

impl Response {
    /// Create a new `Response`
    pub fn new(
        decision: Decision,
        reason: HashSet<PolicyId>,
        errors: Vec<AuthorizationError>,
    ) -> Self {
        Self {
            decision,
            diagnostics: Diagnostics { reason, errors },
        }
    }

    /// Get the authorization decision
    pub fn decision(&self) -> Decision {
        self.decision
    }

    /// Get the authorization diagnostics
    pub fn diagnostics(&self) -> &Diagnostics {
        &self.diagnostics
    }
}

#[doc(hidden)]
impl From<authorizer::Response> for Response {
    fn from(a: authorizer::Response) -> Self {
        Self {
            decision: a.decision,
            diagnostics: a.diagnostics.into(),
        }
    }
}

/// Used to select how a policy will be validated.
#[derive(Default, Eq, PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum ValidationMode {
    /// Validate that policies do not contain any type errors, and additionally
    /// have a restricted form which is amenable for analysis.
    #[default]
    Strict,
    /// Validate that policies do not contain any type errors.
    #[doc = include_str!("../experimental_warning.md")]
    #[cfg(feature = "permissive-validate")]
    Permissive,
    /// Validate using a partial schema. Policies may contain type errors.
    #[doc = include_str!("../experimental_warning.md")]
    #[cfg(feature = "partial-validate")]
    Partial,
}

#[doc(hidden)]
impl From<ValidationMode> for cedar_policy_core::validator::ValidationMode {
    fn from(mode: ValidationMode) -> Self {
        match mode {
            ValidationMode::Strict => Self::Strict,
            #[cfg(feature = "permissive-validate")]
            ValidationMode::Permissive => Self::Permissive,
            #[cfg(feature = "partial-validate")]
            ValidationMode::Partial => Self::Partial,
        }
    }
}

/// Validator object, which provides policy validation and typechecking.
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct Validator(cedar_policy_core::validator::Validator);

#[doc(hidden)] // because this converts to a private/internal type
impl AsRef<cedar_policy_core::validator::Validator> for Validator {
    fn as_ref(&self) -> &cedar_policy_core::validator::Validator {
        &self.0
    }
}

impl Validator {
    /// Construct a new `Validator` to validate policies using the given
    /// `Schema`.
    pub fn new(schema: Schema) -> Self {
        Self(cedar_policy_core::validator::Validator::new(schema.0))
    }

    /// Get the `Schema` this `Validator` is using.
    pub fn schema(&self) -> &Schema {
        RefCast::ref_cast(self.0.schema())
    }

    /// Validate all policies in a policy set, collecting all validation errors
    /// found into the returned `ValidationResult`. Each error is returned together with the
    /// policy id of the policy where the error was found. If a policy id
    /// included in the input policy set does not appear in the output iterator, then
    /// that policy passed the validator. If the function `validation_passed`
    /// returns true, then there were no validation errors found, so all
    /// policies in the policy set have passed the validator.
    pub fn validate(&self, pset: &PolicySet, mode: ValidationMode) -> ValidationResult {
        ValidationResult::from(self.0.validate(&pset.ast, mode.into()))
    }

    /// Validate all policies in a policy set, collecting all validation errors
    /// found into the returned `ValidationResult`. If validation passes, run level
    /// validation (RFC 76). Each error is returned together with the policy id of the policy
    /// where the error was found. If a policy id included in the input policy set does not
    /// appear in the output iterator, then that policy passed the validator. If the function
    /// `validation_passed` returns true, then there were no validation errors found, so
    /// all policies in the policy set have passed the validator.
    pub fn validate_with_level(
        &self,
        pset: &PolicySet,
        mode: ValidationMode,
        max_deref_level: u32,
    ) -> ValidationResult {
        ValidationResult::from(
            self.0
                .validate_with_level(&pset.ast, mode.into(), max_deref_level),
        )
    }
}

/// Contains all the type information used to construct a `Schema` that can be
/// used to validate a policy.
#[derive(Debug, Clone)]
pub struct SchemaFragment {
    value: cedar_policy_core::validator::ValidatorSchemaFragment<
        cedar_policy_core::validator::ConditionalName,
        cedar_policy_core::validator::ConditionalName,
    >,
    lossless:
        cedar_policy_core::validator::json_schema::Fragment<cedar_policy_core::validator::RawName>,
}

#[doc(hidden)] // because this converts to a private/internal type
impl
    AsRef<
        cedar_policy_core::validator::ValidatorSchemaFragment<
            cedar_policy_core::validator::ConditionalName,
            cedar_policy_core::validator::ConditionalName,
        >,
    > for SchemaFragment
{
    fn as_ref(
        &self,
    ) -> &cedar_policy_core::validator::ValidatorSchemaFragment<
        cedar_policy_core::validator::ConditionalName,
        cedar_policy_core::validator::ConditionalName,
    > {
        &self.value
    }
}

fn get_annotation_by_key(
    annotations: &est::Annotations,
    annotation_key: impl AsRef<str>,
) -> Option<&str> {
    annotations
        .0
        .get(&annotation_key.as_ref().parse().ok()?)
        .map(|value| annotation_value_to_str_ref(value.as_ref()))
}

fn annotation_value_to_str_ref(value: Option<&ast::Annotation>) -> &str {
    value.map_or("", |a| a.as_ref())
}

fn annotations_to_pairs(annotations: &est::Annotations) -> impl Iterator<Item = (&str, &str)> {
    annotations
        .0
        .iter()
        .map(|(key, value)| (key.as_ref(), annotation_value_to_str_ref(value.as_ref())))
}

impl SchemaFragment {
    /// Get annotations of a non-empty namespace.
    ///
    /// We do not allow namespace-level annotations on the empty namespace.
    ///
    /// Returns `None` if `namespace` is not found in the [`SchemaFragment`]
    pub fn namespace_annotations(
        &self,
        namespace: EntityNamespace,
    ) -> Option<impl Iterator<Item = (&str, &str)>> {
        self.lossless
            .0
            .get(&Some(namespace.0))
            .map(|ns_def| annotations_to_pairs(&ns_def.annotations))
    }

    /// Get annotation value of a non-empty namespace by annotation key
    /// `annotation_key`
    ///
    /// We do not allow namespace-level annotations on the empty namespace.
    ///
    /// Returns `None` if `namespace` is not found in the [`SchemaFragment`]
    /// or `annotation_key` is not a valid annotation key
    /// or it does not exist
    pub fn namespace_annotation(
        &self,
        namespace: EntityNamespace,
        annotation_key: impl AsRef<str>,
    ) -> Option<&str> {
        let ns = self.lossless.0.get(&Some(namespace.0))?;
        get_annotation_by_key(&ns.annotations, annotation_key)
    }

    /// Get annotations of a common type declaration
    ///
    /// Returns `None` if `namespace` is not found in the [`SchemaFragment`] or
    /// `ty` is not a valid common type ID or `ty` is not found in the
    /// corresponding namespace definition
    pub fn common_type_annotations(
        &self,
        namespace: Option<EntityNamespace>,
        ty: &str,
    ) -> Option<impl Iterator<Item = (&str, &str)>> {
        let ns_def = self.lossless.0.get(&namespace.map(|n| n.0))?;
        let ty = json_schema::CommonTypeId::new(ast::UnreservedId::from_normalized_str(ty).ok()?)
            .ok()?;
        ns_def
            .common_types
            .get(&ty)
            .map(|ty| annotations_to_pairs(&ty.annotations))
    }

    /// Get annotation value of a common type declaration by annotation key
    /// `annotation_key`
    ///
    /// Returns `None` if `namespace` is not found in the [`SchemaFragment`]
    /// or `ty` is not a valid common type ID
    /// or `ty` is not found in the corresponding namespace definition
    /// or `annotation_key` is not a valid annotation key
    /// or it does not exist
    pub fn common_type_annotation(
        &self,
        namespace: Option<EntityNamespace>,
        ty: &str,
        annotation_key: impl AsRef<str>,
    ) -> Option<&str> {
        let ns_def = self.lossless.0.get(&namespace.map(|n| n.0))?;
        let ty = json_schema::CommonTypeId::new(ast::UnreservedId::from_normalized_str(ty).ok()?)
            .ok()?;
        get_annotation_by_key(&ns_def.common_types.get(&ty)?.annotations, annotation_key)
    }

    /// Get annotations of an entity type declaration
    ///
    /// Returns `None` if `namespace` is not found in the [`SchemaFragment`] or
    /// `ty` is not a valid entity type name or `ty` is not found in the
    /// corresponding namespace definition
    pub fn entity_type_annotations(
        &self,
        namespace: Option<EntityNamespace>,
        ty: &str,
    ) -> Option<impl Iterator<Item = (&str, &str)>> {
        let ns_def = self.lossless.0.get(&namespace.map(|n| n.0))?;
        let ty = ast::UnreservedId::from_normalized_str(ty).ok()?;
        ns_def
            .entity_types
            .get(&ty)
            .map(|ty| annotations_to_pairs(&ty.annotations))
    }

    /// Get annotation value of an entity type declaration by annotation key
    /// `annotation_key`
    ///
    /// Returns `None` if `namespace` is not found in the [`SchemaFragment`]
    /// or `ty` is not a valid entity type name
    /// or `ty` is not found in the corresponding namespace definition
    /// or `annotation_key` is not a valid annotation key
    /// or it does not exist
    pub fn entity_type_annotation(
        &self,
        namespace: Option<EntityNamespace>,
        ty: &str,
        annotation_key: impl AsRef<str>,
    ) -> Option<&str> {
        let ns_def = self.lossless.0.get(&namespace.map(|n| n.0))?;
        let ty = ast::UnreservedId::from_normalized_str(ty).ok()?;
        get_annotation_by_key(&ns_def.entity_types.get(&ty)?.annotations, annotation_key)
    }

    /// Get annotations of an action declaration
    ///
    /// Returns `None` if `namespace` is not found in the [`SchemaFragment`] or
    /// `id` is not found in the corresponding namespace definition
    pub fn action_annotations(
        &self,
        namespace: Option<EntityNamespace>,
        id: &EntityId,
    ) -> Option<impl Iterator<Item = (&str, &str)>> {
        let ns_def = self.lossless.0.get(&namespace.map(|n| n.0))?;
        ns_def
            .actions
            .get(id.unescaped())
            .map(|a| annotations_to_pairs(&a.annotations))
    }

    /// Get annotation value of an action declaration by annotation key
    /// `annotation_key`
    ///
    /// Returns `None` if `namespace` is not found in the [`SchemaFragment`]
    /// or `id` is not found in the corresponding namespace definition
    /// or `annotation_key` is not a valid annotation key
    /// or it does not exist
    pub fn action_annotation(
        &self,
        namespace: Option<EntityNamespace>,
        id: &EntityId,
        annotation_key: impl AsRef<str>,
    ) -> Option<&str> {
        let ns_def = self.lossless.0.get(&namespace.map(|n| n.0))?;
        get_annotation_by_key(
            &ns_def.actions.get(id.unescaped())?.annotations,
            annotation_key,
        )
    }

    /// Extract namespaces defined in this [`SchemaFragment`].
    ///
    /// `None` indicates the empty namespace.
    pub fn namespaces(&self) -> impl Iterator<Item = Option<EntityNamespace>> + '_ {
        self.value.namespaces().filter_map(|ns| {
            match ns.map(|ns| ast::Name::try_from(ns.clone())) {
                Some(Ok(n)) => Some(Some(EntityNamespace(n))),
                None => Some(None), // empty namespace, which we want to surface to the user
                Some(Err(_)) => {
                    // if the `SchemaFragment` contains namespaces with
                    // reserved `__cedar` components, that's an internal
                    // implementation detail; hide that from the user.
                    // Also note that `EntityNamespace` is backed by `Name`
                    // which can't even contain names with reserved
                    // `__cedar` components.
                    None
                }
            }
        })
    }

    /// Create a [`SchemaFragment`] from a string containing JSON in the
    /// JSON schema format.
    pub fn from_json_str(src: &str) -> Result<Self, SchemaError> {
        let lossless = cedar_policy_core::validator::json_schema::Fragment::from_json_str(src)?;
        Ok(Self {
            value: lossless.clone().try_into()?,
            lossless,
        })
    }

    /// Create a [`SchemaFragment`] from a JSON value (which should be an
    /// object of the shape required for the JSON schema format).
    pub fn from_json_value(json: serde_json::Value) -> Result<Self, SchemaError> {
        let lossless = cedar_policy_core::validator::json_schema::Fragment::from_json_value(json)?;
        Ok(Self {
            value: lossless.clone().try_into()?,
            lossless,
        })
    }

    /// Parse a [`SchemaFragment`] from a reader containing the Cedar schema syntax
    pub fn from_cedarschema_file(
        r: impl std::io::Read,
    ) -> Result<(Self, impl Iterator<Item = SchemaWarning>), CedarSchemaError> {
        let (lossless, warnings) =
            cedar_policy_core::validator::json_schema::Fragment::from_cedarschema_file(
                r,
                Extensions::all_available(),
            )?;
        Ok((
            Self {
                value: lossless.clone().try_into()?,
                lossless,
            },
            warnings,
        ))
    }

    /// Parse a [`SchemaFragment`] from a string containing the Cedar schema syntax
    pub fn from_cedarschema_str(
        src: &str,
    ) -> Result<(Self, impl Iterator<Item = SchemaWarning>), CedarSchemaError> {
        let (lossless, warnings) =
            cedar_policy_core::validator::json_schema::Fragment::from_cedarschema_str(
                src,
                Extensions::all_available(),
            )?;
        Ok((
            Self {
                value: lossless.clone().try_into()?,
                lossless,
            },
            warnings,
        ))
    }

    /// Create a [`SchemaFragment`] directly from a JSON file (which should
    /// contain an object of the shape required for the JSON schema format).
    pub fn from_json_file(file: impl std::io::Read) -> Result<Self, SchemaError> {
        let lossless = cedar_policy_core::validator::json_schema::Fragment::from_json_file(file)?;
        Ok(Self {
            value: lossless.clone().try_into()?,
            lossless,
        })
    }

    /// Serialize this [`SchemaFragment`] as a JSON value
    pub fn to_json_value(self) -> Result<serde_json::Value, SchemaError> {
        serde_json::to_value(self.lossless).map_err(|e| SchemaError::JsonSerialization(e.into()))
    }

    /// Serialize this [`SchemaFragment`] as a JSON string
    pub fn to_json_string(&self) -> Result<String, SchemaError> {
        serde_json::to_string(&self.lossless).map_err(|e| SchemaError::JsonSerialization(e.into()))
    }

    /// Serialize this [`SchemaFragment`] into a string in the Cedar schema
    /// syntax
    pub fn to_cedarschema(&self) -> Result<String, ToCedarSchemaError> {
        let str = self.lossless.to_cedarschema()?;
        Ok(str)
    }
}

impl TryInto<Schema> for SchemaFragment {
    type Error = SchemaError;

    /// Convert [`SchemaFragment`] into a [`Schema`]. To build the [`Schema`] we
    /// need to have all entity types defined, so an error will be returned if
    /// any undeclared entity types are referenced in the schema fragment.
    fn try_into(self) -> Result<Schema, Self::Error> {
        Ok(Schema(
            cedar_policy_core::validator::ValidatorSchema::from_schema_fragments(
                [self.value],
                Extensions::all_available(),
            )?,
        ))
    }
}

impl FromStr for SchemaFragment {
    type Err = CedarSchemaError;
    /// Construct [`SchemaFragment`] from a string containing a schema formatted
    /// in the Cedar schema format. This can fail if the string is not a valid
    /// schema. This function does not check for consistency in the schema
    /// (e.g., references to undefined entities) because this is not required
    /// until a `Schema` is constructed.
    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Self::from_cedarschema_str(src).map(|(frag, _)| frag)
    }
}

/// Object containing schema information used by the validator.
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct Schema(pub(crate) cedar_policy_core::validator::ValidatorSchema);

#[doc(hidden)] // because this converts to a private/internal type
impl AsRef<cedar_policy_core::validator::ValidatorSchema> for Schema {
    fn as_ref(&self) -> &cedar_policy_core::validator::ValidatorSchema {
        &self.0
    }
}

#[doc(hidden)]
impl From<cedar_policy_core::validator::ValidatorSchema> for Schema {
    fn from(schema: cedar_policy_core::validator::ValidatorSchema) -> Self {
        Self(schema)
    }
}

impl FromStr for Schema {
    type Err = CedarSchemaError;

    /// Construct a [`Schema`] from a string containing a schema formatted in
    /// the Cedar schema format. This can fail if it is not possible to parse a
    /// schema from the string, or if errors in values in the schema are
    /// uncovered after parsing. For instance, when an entity attribute name is
    /// found to not be a valid attribute name according to the Cedar
    /// grammar.
    fn from_str(schema_src: &str) -> Result<Self, Self::Err> {
        Self::from_cedarschema_str(schema_src).map(|(schema, _)| schema)
    }
}

impl Schema {
    /// Create a [`Schema`] from multiple [`SchemaFragment`]. The individual
    /// fragments may reference entity or common types that are not declared in that
    /// fragment, but all referenced entity and common types must be declared in some
    /// fragment.
    pub fn from_schema_fragments(
        fragments: impl IntoIterator<Item = SchemaFragment>,
    ) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_core::validator::ValidatorSchema::from_schema_fragments(
                fragments.into_iter().map(|f| f.value),
                Extensions::all_available(),
            )?,
        ))
    }

    /// Create a [`Schema`] from a JSON value (which should be an object of the
    /// shape required for the JSON schema format).
    pub fn from_json_value(json: serde_json::Value) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_core::validator::ValidatorSchema::from_json_value(
                json,
                Extensions::all_available(),
            )?,
        ))
    }

    /// Create a [`Schema`] from a string containing JSON in the appropriate
    /// shape.
    pub fn from_json_str(json: &str) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_core::validator::ValidatorSchema::from_json_str(
                json,
                Extensions::all_available(),
            )?,
        ))
    }

    /// Create a [`Schema`] directly from a file containing JSON in the
    /// appropriate shape.
    pub fn from_json_file(file: impl std::io::Read) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_core::validator::ValidatorSchema::from_json_file(
                file,
                Extensions::all_available(),
            )?,
        ))
    }

    /// Parse the schema from a reader, in the Cedar schema format.
    pub fn from_cedarschema_file(
        file: impl std::io::Read,
    ) -> Result<(Self, impl Iterator<Item = SchemaWarning> + 'static), CedarSchemaError> {
        let (schema, warnings) =
            cedar_policy_core::validator::ValidatorSchema::from_cedarschema_file(
                file,
                Extensions::all_available(),
            )?;
        Ok((Self(schema), warnings))
    }

    /// Parse the schema from a string, in the Cedar schema format.
    pub fn from_cedarschema_str(
        src: &str,
    ) -> Result<(Self, impl Iterator<Item = SchemaWarning>), CedarSchemaError> {
        let (schema, warnings) =
            cedar_policy_core::validator::ValidatorSchema::from_cedarschema_str(
                src,
                Extensions::all_available(),
            )?;
        Ok((Self(schema), warnings))
    }

    /// Extract from the schema an [`Entities`] containing the action entities
    /// declared in the schema.
    pub fn action_entities(&self) -> Result<Entities, EntitiesError> {
        Ok(Entities(self.0.action_entities()?))
    }

    /// Returns an iterator over every entity type that can be a principal for any action in this schema
    ///
    /// Note: this iterator may contain duplicates.
    ///
    /// # Examples
    /// Here's an example of using a [`std::collections::HashSet`] to get a de-duplicated set of principals
    /// ```
    /// use std::collections::HashSet;
    /// use cedar_policy::Schema;
    /// let schema : Schema = r#"
    ///     entity User;
    ///     entity Folder;
    ///     action Access appliesTo {
    ///         principal : User,
    ///         resource : Folder,
    ///     };
    ///     action Delete appliesTo {
    ///         principal : User,
    ///         resource : Folder,
    ///     };
    /// "#.parse().unwrap();
    /// let principals = schema.principals().collect::<HashSet<_>>();
    /// assert_eq!(principals, HashSet::from([&"User".parse().unwrap()]));
    /// ```
    pub fn principals(&self) -> impl Iterator<Item = &EntityTypeName> {
        self.0.principals().map(RefCast::ref_cast)
    }

    /// Returns an iterator over every entity type that can be a resource for any action in this schema
    ///
    /// Note: this iterator may contain duplicates.
    /// # Examples
    /// Here's an example of using a [`std::collections::HashSet`] to get a de-duplicated set of resources
    /// ```
    /// use std::collections::HashSet;
    /// use cedar_policy::Schema;
    /// let schema : Schema = r#"
    ///     entity User;
    ///     entity Folder;
    ///     action Access appliesTo {
    ///         principal : User,
    ///         resource : Folder,
    ///     };
    ///     action Delete appliesTo {
    ///         principal : User,
    ///         resource : Folder,
    ///     };
    /// "#.parse().unwrap();
    /// let resources = schema.resources().collect::<HashSet<_>>();
    /// assert_eq!(resources, HashSet::from([&"Folder".parse().unwrap()]));
    /// ```
    pub fn resources(&self) -> impl Iterator<Item = &EntityTypeName> {
        self.0.resources().map(RefCast::ref_cast)
    }

    /// Returns an iterator over every entity type that can be a principal for `action` in this schema
    ///
    /// ## Errors
    ///
    /// Returns [`None`] if `action` is not found in the schema
    pub fn principals_for_action(
        &self,
        action: &EntityUid,
    ) -> Option<impl Iterator<Item = &EntityTypeName>> {
        self.0
            .principals_for_action(&action.0)
            .map(|iter| iter.map(RefCast::ref_cast))
    }

    /// Returns an iterator over every entity type that can be a resource for `action` in this schema
    ///
    /// ## Errors
    ///
    /// Returns [`None`] if `action` is not found in the schema
    pub fn resources_for_action(
        &self,
        action: &EntityUid,
    ) -> Option<impl Iterator<Item = &EntityTypeName>> {
        self.0
            .resources_for_action(&action.0)
            .map(|iter| iter.map(RefCast::ref_cast))
    }

    /// Returns an iterator over all the [`RequestEnv`]s that are valid
    /// according to this schema.
    pub fn request_envs(&self) -> impl Iterator<Item = RequestEnv> + '_ {
        self.0
            .unlinked_request_envs(cedar_policy_core::validator::ValidationMode::Strict)
            .map(Into::into)
    }

    /// Returns an iterator over all the entity types that can be an ancestor of `ty`
    ///
    /// ## Errors
    ///
    /// Returns [`None`] if the `ty` is not found in the schema
    pub fn ancestors<'a>(
        &'a self,
        ty: &'a EntityTypeName,
    ) -> Option<impl Iterator<Item = &'a EntityTypeName> + 'a> {
        self.0
            .ancestors(&ty.0)
            .map(|iter| iter.map(RefCast::ref_cast))
    }

    /// Returns an iterator over all the action groups defined in this schema
    pub fn action_groups(&self) -> impl Iterator<Item = &EntityUid> {
        self.0.action_groups().map(RefCast::ref_cast)
    }

    /// Returns an iterator over all entity types defined in this schema
    pub fn entity_types(&self) -> impl Iterator<Item = &EntityTypeName> {
        self.0
            .entity_types()
            .map(|ety| RefCast::ref_cast(ety.name()))
    }

    /// Returns an iterator over all actions defined in this schema
    pub fn actions(&self) -> impl Iterator<Item = &EntityUid> {
        self.0.actions().map(RefCast::ref_cast)
    }
}

/// Contains the result of policy validation.
///
/// The result includes the list of issues found by validation and whether validation succeeds or fails.
/// Validation succeeds if there are no fatal errors. There may still be
/// non-fatal warnings present when validation passes.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    validation_errors: Vec<ValidationError>,
    validation_warnings: Vec<ValidationWarning>,
}

impl ValidationResult {
    /// True when validation passes. There are no errors, but there may be
    /// non-fatal warnings. Use [`ValidationResult::validation_passed_without_warnings`]
    /// to check that there are also no warnings.
    pub fn validation_passed(&self) -> bool {
        self.validation_errors.is_empty()
    }

    /// True when validation passes (i.e., there are no errors) and there are
    /// additionally no non-fatal warnings.
    pub fn validation_passed_without_warnings(&self) -> bool {
        self.validation_errors.is_empty() && self.validation_warnings.is_empty()
    }

    /// Get an iterator over the errors found by the validator.
    pub fn validation_errors(&self) -> impl Iterator<Item = &ValidationError> {
        self.validation_errors.iter()
    }

    /// Get an iterator over the warnings found by the validator.
    pub fn validation_warnings(&self) -> impl Iterator<Item = &ValidationWarning> {
        self.validation_warnings.iter()
    }

    fn first_error_or_warning(&self) -> Option<&dyn Diagnostic> {
        self.validation_errors
            .first()
            .map(|e| e as &dyn Diagnostic)
            .or_else(|| {
                self.validation_warnings
                    .first()
                    .map(|w| w as &dyn Diagnostic)
            })
    }

    pub(crate) fn into_errors_and_warnings(
        self,
    ) -> (
        impl Iterator<Item = ValidationError>,
        impl Iterator<Item = ValidationWarning>,
    ) {
        (
            self.validation_errors.into_iter(),
            self.validation_warnings.into_iter(),
        )
    }
}

#[doc(hidden)]
impl From<cedar_policy_core::validator::ValidationResult> for ValidationResult {
    fn from(r: cedar_policy_core::validator::ValidationResult) -> Self {
        let (errors, warnings) = r.into_errors_and_warnings();
        Self {
            validation_errors: errors.map(ValidationError::from).collect(),
            validation_warnings: warnings.map(ValidationWarning::from).collect(),
        }
    }
}

impl std::fmt::Display for ValidationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.first_error_or_warning() {
            Some(diagnostic) => write!(f, "{diagnostic}"),
            None => write!(f, "no errors or warnings"),
        }
    }
}

impl std::error::Error for ValidationResult {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.first_error_or_warning()
            .and_then(std::error::Error::source)
    }

    #[allow(deprecated)]
    fn description(&self) -> &str {
        self.first_error_or_warning()
            .map_or("no errors or warnings", std::error::Error::description)
    }

    #[allow(deprecated)]
    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.first_error_or_warning()
            .and_then(std::error::Error::cause)
    }
}

// Except for `.related()`, and `.severity` everything is forwarded to the first
// error, or to the first warning if there are no errors. This is done for the
// same reason as policy parse errors.
impl Diagnostic for ValidationResult {
    fn related(&self) -> Option<Box<dyn Iterator<Item = &dyn Diagnostic> + '_>> {
        let mut related = self
            .validation_errors
            .iter()
            .map(|err| err as &dyn Diagnostic)
            .chain(
                self.validation_warnings
                    .iter()
                    .map(|warn| warn as &dyn Diagnostic),
            );
        related.next().map(move |first| match first.related() {
            Some(first_related) => Box::new(first_related.chain(related)),
            None => Box::new(related) as Box<dyn Iterator<Item = _>>,
        })
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.first_error_or_warning()
            .map_or(Some(miette::Severity::Advice), Diagnostic::severity)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        self.first_error_or_warning().and_then(Diagnostic::labels)
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.first_error_or_warning()
            .and_then(Diagnostic::source_code)
    }

    fn code(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        self.first_error_or_warning().and_then(Diagnostic::code)
    }

    fn url(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        self.first_error_or_warning().and_then(Diagnostic::url)
    }

    fn help(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        self.first_error_or_warning().and_then(Diagnostic::help)
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.first_error_or_warning()
            .and_then(Diagnostic::diagnostic_source)
    }
}

/// Scan a set of policies for potentially confusing/obfuscating text.
///
/// These checks are also provided through [`Validator::validate`] which provides more
/// comprehensive error detection, but this function can be used to check for
/// confusable strings without defining a schema.
pub fn confusable_string_checker<'a>(
    templates: impl Iterator<Item = &'a Template> + 'a,
) -> impl Iterator<Item = ValidationWarning> + 'a {
    cedar_policy_core::validator::confusable_string_checks(templates.map(|t| &t.ast))
        .map(std::convert::Into::into)
}

/// Represents a namespace.
///
/// An `EntityNamespace` can can be constructed using
/// [`EntityNamespace::from_str`] or by calling `parse()` on a string.
/// _This can fail_, so it is important to properly handle an `Err` result.
///
/// ```
/// # use cedar_policy::EntityNamespace;
/// let id : Result<EntityNamespace, _> = "My::Name::Space".parse();
/// # assert_eq!(id.unwrap().to_string(), "My::Name::Space".to_string());
/// ```
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntityNamespace(pub(crate) ast::Name);

#[doc(hidden)] // because this converts to a private/internal type
impl AsRef<ast::Name> for EntityNamespace {
    fn as_ref(&self) -> &ast::Name {
        &self.0
    }
}

/// This `FromStr` implementation requires the _normalized_ representation of the
/// namespace. See <https://github.com/cedar-policy/rfcs/pull/9/>.
impl FromStr for EntityNamespace {
    type Err = ParseErrors;

    fn from_str(namespace_str: &str) -> Result<Self, Self::Err> {
        ast::Name::from_normalized_str(namespace_str)
            .map(EntityNamespace)
            .map_err(Into::into)
    }
}

impl std::fmt::Display for EntityNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Default)]
/// A struct representing a `PolicySet` as a series of strings for ser/de.
/// A `PolicySet` that contains template-linked policies cannot be
/// represented as this struct.
pub(crate) struct StringifiedPolicySet {
    /// The static policies in the set
    pub policies: Vec<String>,
    /// The policy templates in the set
    pub policy_templates: Vec<String>,
}

/// Represents a set of `Policy`s
#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    /// AST representation. Technically partially redundant with the other fields.
    /// Internally, we ensure that the duplicated information remains consistent.
    pub(crate) ast: ast::PolicySet,
    /// Policies in the set (this includes both static policies and template linked-policies)
    policies: HashMap<PolicyId, Policy>,
    /// Templates in the set
    templates: HashMap<PolicyId, Template>,
}

impl PartialEq for PolicySet {
    fn eq(&self, other: &Self) -> bool {
        // eq is based on just the `ast`
        self.ast.eq(&other.ast)
    }
}
impl Eq for PolicySet {}

#[doc(hidden)] // because this converts to a private/internal type
impl AsRef<ast::PolicySet> for PolicySet {
    fn as_ref(&self) -> &ast::PolicySet {
        &self.ast
    }
}

#[doc(hidden)]
impl TryFrom<ast::PolicySet> for PolicySet {
    type Error = PolicySetError;
    fn try_from(pset: ast::PolicySet) -> Result<Self, Self::Error> {
        Self::from_ast(pset)
    }
}

impl FromStr for PolicySet {
    type Err = ParseErrors;

    /// Create a policy set from multiple statements.
    ///
    /// Policy ids will default to "policy*" with numbers from 0.
    /// If you load more policies, do not use the default id, or there will be conflicts.
    ///
    /// See [`Policy`] for more.
    fn from_str(policies: &str) -> Result<Self, Self::Err> {
        let (texts, pset) = parser::parse_policyset_and_also_return_policy_text(policies)?;
        // PANIC SAFETY: By the invariant on `parse_policyset_and_also_return_policy_text(policies)`, every `PolicyId` in `pset.policies()` occurs as a key in `text`.
        #[allow(clippy::expect_used)]
        let policies = pset.policies().map(|p|
            (
                PolicyId::new(p.id().clone()),
                Policy { lossless: LosslessPolicy::policy_or_template_text(*texts.get(p.id()).expect("internal invariant violation: policy id exists in asts but not texts")), ast: p.clone() }
            )
        ).collect();
        // PANIC SAFETY: By the same invariant, every `PolicyId` in `pset.templates()` also occurs as a key in `text`.
        #[allow(clippy::expect_used)]
        let templates = pset.templates().map(|t|
            (
                PolicyId::new(t.id().clone()),
                Template { lossless: LosslessPolicy::policy_or_template_text(*texts.get(t.id()).expect("internal invariant violation: template id exists in asts but not ests")), ast: t.clone() }
            )
        ).collect();
        Ok(Self {
            ast: pset,
            policies,
            templates,
        })
    }
}

impl PolicySet {
    /// Build the policy set AST from the EST
    fn from_est(est: &est::PolicySet) -> Result<Self, PolicySetError> {
        let ast: ast::PolicySet = est.clone().try_into()?;
        // PANIC SAFETY: Since conversion from EST to AST succeeded, every `PolicyId` in `ast.policies()` occurs in `est`
        #[allow(clippy::expect_used)]
        let policies = ast
            .policies()
            .map(|p| {
                (
                    PolicyId::new(p.id().clone()),
                    Policy {
                        lossless: LosslessPolicy::Est(est.get_policy(p.id()).expect(
                            "internal invariant violation: policy id exists in asts but not ests",
                        )),
                        ast: p.clone(),
                    },
                )
            })
            .collect();
        // PANIC SAFETY: Since conversion from EST to AST succeeded, every `PolicyId` in `ast.templates()` occurs in `est`
        #[allow(clippy::expect_used)]
        let templates = ast
            .templates()
            .map(|t| {
                (
                    PolicyId::new(t.id().clone()),
                    Template {
                        lossless: LosslessPolicy::Est(est.get_template(t.id()).expect(
                            "internal invariant violation: template id exists in asts but not ests",
                        )),
                        ast: t.clone(),
                    },
                )
            })
            .collect();
        Ok(Self {
            ast,
            policies,
            templates,
        })
    }

    /// Build the [`PolicySet`] from just the AST information
    #[cfg_attr(not(feature = "protobufs"), allow(dead_code))]
    pub(crate) fn from_ast(ast: ast::PolicySet) -> Result<Self, PolicySetError> {
        Self::from_policies(ast.into_policies().map(Policy::from_ast))
    }

    /// Deserialize the [`PolicySet`] from a JSON string
    pub fn from_json_str(src: impl AsRef<str>) -> Result<Self, PolicySetError> {
        let est: est::PolicySet = serde_json::from_str(src.as_ref())
            .map_err(|e| policy_set_errors::JsonPolicySetError { inner: e })?;
        Self::from_est(&est)
    }

    /// Deserialize the [`PolicySet`] from a JSON value
    pub fn from_json_value(src: serde_json::Value) -> Result<Self, PolicySetError> {
        let est: est::PolicySet = serde_json::from_value(src)
            .map_err(|e| policy_set_errors::JsonPolicySetError { inner: e })?;
        Self::from_est(&est)
    }

    /// Deserialize the [`PolicySet`] from a JSON reader
    pub fn from_json_file(r: impl std::io::Read) -> Result<Self, PolicySetError> {
        let est: est::PolicySet = serde_json::from_reader(r)
            .map_err(|e| policy_set_errors::JsonPolicySetError { inner: e })?;
        Self::from_est(&est)
    }

    /// Serialize the [`PolicySet`] as a JSON value
    pub fn to_json(self) -> Result<serde_json::Value, PolicySetError> {
        let est = self.est()?;
        let value = serde_json::to_value(est)
            .map_err(|e| policy_set_errors::JsonPolicySetError { inner: e })?;
        Ok(value)
    }

    /// Get the EST representation of the [`PolicySet`]
    fn est(self) -> Result<est::PolicySet, PolicyToJsonError> {
        let (static_policies, template_links): (Vec<_>, Vec<_>) =
            fold_partition(self.policies, is_static_or_link)?;
        let static_policies = static_policies.into_iter().collect::<HashMap<_, _>>();
        let templates = self
            .templates
            .into_iter()
            .map(|(id, template)| {
                template
                    .lossless
                    .est(|| template.ast.clone().into())
                    .map(|est| (id.into(), est))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        let est = est::PolicySet {
            templates,
            static_policies,
            template_links,
        };

        Ok(est)
    }

    /// Get the human-readable Cedar syntax representation of this policy set.
    /// This function is primarily intended for rendering JSON policies in the
    /// human-readable syntax, but it will also return the original policy text
    /// (though possibly re-ordering policies within the policy set) when the
    /// policy-set contains policies parsed from the human-readable syntax.
    ///
    /// This will return `None` if there are any linked policies in the policy
    /// set because they cannot be directly rendered in Cedar syntax. It also
    /// cannot record policy ids because these cannot be specified in the Cedar
    /// syntax. The policies may be reordered, so parsing the resulting string
    /// with [`PolicySet::from_str`] is likely to yield different policy id
    /// assignments. For these reasons you should prefer serializing as JSON (or protobuf) and
    /// only using this function to obtain a representation to display to human
    /// users.
    ///
    /// This function does not format the policy according to any particular
    /// rules.  Policy formatting can be done through the Cedar policy CLI or
    /// the `cedar-policy-formatter` crate.
    pub fn to_cedar(&self) -> Option<String> {
        match self.stringify() {
            Some(StringifiedPolicySet {
                policies,
                policy_templates,
            }) => {
                let policies_as_vec = policies
                    .into_iter()
                    .chain(policy_templates)
                    .collect::<Vec<_>>();
                Some(policies_as_vec.join("\n\n"))
            }
            None => None,
        }
    }

    /// Get the human-readable Cedar syntax representation of this policy set,
    /// as a vec of strings. This function is useful to break up a large cedar
    /// file containing many policies into individual policies.
    ///
    /// This will return `None` if there are any linked policies in the policy
    /// set because they cannot be directly rendered in Cedar syntax. It also
    /// cannot record policy ids because these cannot be specified in the Cedar
    /// syntax. The policies may be reordered, so parsing the resulting string
    /// with [`PolicySet::from_str`] is likely to yield different policy id
    /// assignments. For these reasons you should prefer serializing as JSON (or protobuf) and
    /// only using this function to obtain a compact cedar representation,
    /// perhaps for storage purposes.
    ///
    /// This function does not format the policy according to any particular
    /// rules.  Policy formatting can be done through the Cedar policy CLI or
    /// the `cedar-policy-formatter` crate.
    pub(crate) fn stringify(&self) -> Option<StringifiedPolicySet> {
        let policies = self
            .policies
            .values()
            // We'd like to print policies in a deterministic order, so we sort
            // before printing, hoping that the size of policy sets is fairly
            // small.
            .sorted_by_key(|p| AsRef::<str>::as_ref(p.id()))
            .map(Policy::to_cedar)
            .collect::<Option<Vec<_>>>()?;
        let policy_templates = self
            .templates
            .values()
            .sorted_by_key(|t| AsRef::<str>::as_ref(t.id()))
            .map(Template::to_cedar)
            .collect_vec();

        Some(StringifiedPolicySet {
            policies,
            policy_templates,
        })
    }

    /// Create a fresh empty `PolicySet`
    pub fn new() -> Self {
        Self {
            ast: ast::PolicySet::new(),
            policies: HashMap::new(),
            templates: HashMap::new(),
        }
    }

    /// Create a `PolicySet` from the given policies
    pub fn from_policies(
        policies: impl IntoIterator<Item = Policy>,
    ) -> Result<Self, PolicySetError> {
        let mut set = Self::new();
        for policy in policies {
            set.add(policy)?;
        }
        Ok(set)
    }

    /// Helper function for `merge_policyset`
    /// Merges two sets and avoids name clashes by using the provided
    /// renaming. The type parameter `T` allows this code to be used for
    /// both Templates and Policies.
    fn merge_sets<T>(
        this: &mut HashMap<PolicyId, T>,
        other: &HashMap<PolicyId, T>,
        renaming: &HashMap<PolicyId, PolicyId>,
    ) where
        T: PartialEq + Clone,
    {
        for (pid, ot) in other {
            match renaming.get(pid) {
                Some(new_pid) => {
                    this.insert(new_pid.clone(), ot.clone());
                }
                None => {
                    if this.get(pid).is_none() {
                        this.insert(pid.clone(), ot.clone());
                    }
                    // If pid is not in the renaming but is in both
                    // this and other, then by assumption
                    // the element at pid in this and other are equal
                    // i.e., the renaming is expected to track all
                    // conflicting pids.
                }
            }
        }
    }

    /// Merges this `PolicySet` with another `PolicySet`.
    /// This `PolicySet` is modified while the other `PolicySet`
    /// remains unchanged.
    ///
    /// The flag `rename_duplicates` controls the expected behavior
    /// when a `PolicyId` in this and the other `PolicySet` conflict.
    ///
    /// When `rename_duplicates` is false, conflicting `PolicyId`s result
    /// in a `PolicySetError::AlreadyDefined` error.
    ///
    /// Otherwise, when `rename_duplicates` is true, conflicting `PolicyId`s from
    /// the other `PolicySet` are automatically renamed to avoid conflict.
    /// This renaming is returned as a Hashmap from the old `PolicyId` to the
    /// renamed `PolicyId`.
    pub fn merge(
        &mut self,
        other: &Self,
        rename_duplicates: bool,
    ) -> Result<HashMap<PolicyId, PolicyId>, PolicySetError> {
        match self.ast.merge_policyset(&other.ast, rename_duplicates) {
            Ok(renaming) => {
                let renaming: HashMap<PolicyId, PolicyId> = renaming
                    .into_iter()
                    .map(|(old_pid, new_pid)| (PolicyId::new(old_pid), PolicyId::new(new_pid)))
                    .collect();
                Self::merge_sets(&mut self.templates, &other.templates, &renaming);
                Self::merge_sets(&mut self.policies, &other.policies, &renaming);
                Ok(renaming)
            }
            Err(ast::PolicySetError::Occupied { id }) => Err(PolicySetError::AlreadyDefined(
                policy_set_errors::AlreadyDefined {
                    id: PolicyId::new(id),
                },
            )),
        }
    }

    /// Add an static policy to the `PolicySet`. To add a template instance, use
    /// `link` instead. This function will return an error (and not modify
    /// the `PolicySet`) if a template-linked policy is passed in.
    pub fn add(&mut self, policy: Policy) -> Result<(), PolicySetError> {
        if policy.is_static() {
            let id = PolicyId::new(policy.ast.id().clone());
            self.ast.add(policy.ast.clone())?;
            self.policies.insert(id, policy);
            Ok(())
        } else {
            Err(PolicySetError::ExpectedStatic(
                policy_set_errors::ExpectedStatic::new(),
            ))
        }
    }

    /// Remove a static `Policy` from the `PolicySet`.
    ///
    /// This will error if the policy is not a static policy.
    pub fn remove_static(&mut self, policy_id: PolicyId) -> Result<Policy, PolicySetError> {
        let Some(policy) = self.policies.remove(&policy_id) else {
            return Err(PolicySetError::PolicyNonexistent(
                policy_set_errors::PolicyNonexistentError { policy_id },
            ));
        };
        if self
            .ast
            .remove_static(&ast::PolicyID::from_string(&policy_id))
            .is_ok()
        {
            Ok(policy)
        } else {
            //Restore self.policies
            self.policies.insert(policy_id.clone(), policy);
            Err(PolicySetError::PolicyNonexistent(
                policy_set_errors::PolicyNonexistentError { policy_id },
            ))
        }
    }

    /// Add a `Template` to the `PolicySet`
    pub fn add_template(&mut self, template: Template) -> Result<(), PolicySetError> {
        let id = PolicyId::new(template.ast.id().clone());
        self.ast.add_template(template.ast.clone())?;
        self.templates.insert(id, template);
        Ok(())
    }

    /// Remove a `Template` from the `PolicySet`.
    ///
    /// This will error if any policy is linked to the template.
    /// This will error if `policy_id` is not a template.
    pub fn remove_template(&mut self, template_id: PolicyId) -> Result<Template, PolicySetError> {
        let Some(template) = self.templates.remove(&template_id) else {
            return Err(PolicySetError::TemplateNonexistent(
                policy_set_errors::TemplateNonexistentError { template_id },
            ));
        };
        // If self.templates and self.ast disagree, authorization cannot be trusted.
        // PANIC SAFETY: We just found the policy in self.templates.
        #[allow(clippy::panic)]
        match self
            .ast
            .remove_template(&ast::PolicyID::from_string(&template_id))
        {
            Ok(_) => Ok(template),
            Err(ast::PolicySetTemplateRemovalError::RemoveTemplateWithLinksError(_)) => {
                self.templates.insert(template_id.clone(), template);
                Err(PolicySetError::RemoveTemplateWithActiveLinks(
                    policy_set_errors::RemoveTemplateWithActiveLinksError { template_id },
                ))
            }
            Err(ast::PolicySetTemplateRemovalError::NotTemplateError(_)) => {
                self.templates.insert(template_id.clone(), template);
                Err(PolicySetError::RemoveTemplateNotTemplate(
                    policy_set_errors::RemoveTemplateNotTemplateError { template_id },
                ))
            }
            Err(ast::PolicySetTemplateRemovalError::RemovePolicyNoTemplateError(_)) => {
                panic!("Found template policy in self.templates but not in self.ast");
            }
        }
    }

    /// Get policies linked to a `Template` in the `PolicySet`.
    /// If any policy is linked to the template, this will error
    pub fn get_linked_policies(
        &self,
        template_id: PolicyId,
    ) -> Result<impl Iterator<Item = &PolicyId>, PolicySetError> {
        self.ast
            .get_linked_policies(&ast::PolicyID::from_string(&template_id))
            .map_or_else(
                |_| {
                    Err(PolicySetError::TemplateNonexistent(
                        policy_set_errors::TemplateNonexistentError { template_id },
                    ))
                },
                |v| Ok(v.map(PolicyId::ref_cast)),
            )
    }

    /// Iterate over all the `Policy`s in the `PolicySet`.
    ///
    /// This will include both static and template-linked policies.
    pub fn policies(&self) -> impl Iterator<Item = &Policy> {
        self.policies.values()
    }

    /// Iterate over the `Template`'s in the `PolicySet`.
    pub fn templates(&self) -> impl Iterator<Item = &Template> {
        self.templates.values()
    }

    /// Get a `Template` by its `PolicyId`
    pub fn template(&self, id: &PolicyId) -> Option<&Template> {
        self.templates.get(id)
    }

    /// Get a `Policy` by its `PolicyId`
    pub fn policy(&self, id: &PolicyId) -> Option<&Policy> {
        self.policies.get(id)
    }

    /// Extract annotation data from a `Policy` by its `PolicyId` and annotation key.
    /// If the annotation is present without an explicit value (e.g., `@annotation`),
    /// then this function returns `Some("")`. It returns `None` only when the
    /// annotation is not present.
    pub fn annotation(&self, id: &PolicyId, key: impl AsRef<str>) -> Option<&str> {
        self.ast
            .get(id.as_ref())?
            .annotation(&key.as_ref().parse().ok()?)
            .map(AsRef::as_ref)
    }

    /// Extract annotation data from a `Template` by its `PolicyId` and annotation key.
    /// If the annotation is present without an explicit value (e.g., `@annotation`),
    /// then this function returns `Some("")`. It returns `None` only when the
    /// annotation is not present.
    pub fn template_annotation(&self, id: &PolicyId, key: impl AsRef<str>) -> Option<&str> {
        self.ast
            .get_template(id.as_ref())?
            .annotation(&key.as_ref().parse().ok()?)
            .map(AsRef::as_ref)
    }

    /// Returns true iff the `PolicySet` is empty
    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(
            self.ast.is_empty(),
            self.policies.is_empty() && self.templates.is_empty()
        );
        self.ast.is_empty()
    }

    /// Returns the number of `Policy`s in the `PolicySet`.
    ///
    /// This will include both static and template-linked policies.
    pub fn num_of_policies(&self) -> usize {
        self.policies.len()
    }

    /// Returns the number of `Template`s in the `PolicySet`.
    pub fn num_of_templates(&self) -> usize {
        self.templates.len()
    }

    /// Attempt to link a template and add the new template-linked policy to the policy set.
    /// If link fails, the `PolicySet` is not modified.
    /// Failure can happen for three reasons
    ///   1) The map passed in `vals` may not match the slots in the template
    ///   2) The `new_id` may conflict w/ a policy that already exists in the set
    ///   3) `template_id` does not correspond to a template. Either the id is
    ///      not in the policy set, or it is in the policy set but is either a
    ///      linked or static policy rather than a template
    #[allow(clippy::needless_pass_by_value)]
    pub fn link(
        &mut self,
        template_id: PolicyId,
        new_id: PolicyId,
        vals: HashMap<SlotId, EntityUid>,
    ) -> Result<(), PolicySetError> {
        let unwrapped_vals: HashMap<ast::SlotId, ast::EntityUID> = vals
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect();

        // Try to get the template with the id we're linking from.  We do this
        // _before_ calling `self.ast.link` because `link` mutates the policy
        // set by creating a new link entry in a hashmap. This happens even when
        // trying to link a static policy, which we want to error on here.
        let Some(template) = self.templates.get(&template_id) else {
            return Err(if self.policies.contains_key(&template_id) {
                policy_set_errors::ExpectedTemplate::new().into()
            } else {
                policy_set_errors::LinkingError {
                    inner: ast::LinkingError::NoSuchTemplate {
                        id: template_id.into(),
                    },
                }
                .into()
            });
        };

        let linked_ast = self.ast.link(
            template_id.into(),
            new_id.clone().into(),
            unwrapped_vals.clone(),
        )?;

        // PANIC SAFETY: `lossless.link()` will not fail after `ast.link()` succeeds
        #[allow(clippy::expect_used)]
        let linked_lossless = template
            .lossless
            .clone()
            .link(unwrapped_vals.iter().map(|(k, v)| (*k, v)))
            // The only error case for `lossless.link()` is a template with
            // slots which are not filled by the provided values. `ast.link()`
            // will have already errored if there are any unfilled slots in the
            // template.
            .expect("ast.link() didn't fail above, so this shouldn't fail");
        self.policies.insert(
            new_id,
            Policy {
                ast: linked_ast.clone(),
                lossless: linked_lossless,
            },
        );
        Ok(())
    }

    /// Get all the unknown entities from the policy set
    #[doc = include_str!("../experimental_warning.md")]
    #[cfg(feature = "partial-eval")]
    pub fn unknown_entities(&self) -> HashSet<EntityUid> {
        let mut entity_uids = HashSet::new();
        for policy in self.policies.values() {
            entity_uids.extend(policy.unknown_entities());
        }
        entity_uids
    }

    /// Unlink a template-linked policy from the policy set.
    /// Returns the policy that was unlinked.
    pub fn unlink(&mut self, policy_id: PolicyId) -> Result<Policy, PolicySetError> {
        let Some(policy) = self.policies.remove(&policy_id) else {
            return Err(PolicySetError::LinkNonexistent(
                policy_set_errors::LinkNonexistentError { policy_id },
            ));
        };
        // If self.policies and self.ast disagree, authorization cannot be trusted.
        // PANIC SAFETY: We just found the policy in self.policies.
        #[allow(clippy::panic)]
        match self.ast.unlink(&ast::PolicyID::from_string(&policy_id)) {
            Ok(_) => Ok(policy),
            Err(ast::PolicySetUnlinkError::NotLinkError(_)) => {
                //Restore self.policies
                self.policies.insert(policy_id.clone(), policy);
                Err(PolicySetError::UnlinkLinkNotLink(
                    policy_set_errors::UnlinkLinkNotLinkError { policy_id },
                ))
            }
            Err(ast::PolicySetUnlinkError::UnlinkingError(_)) => {
                panic!("Found linked policy in self.policies but not in self.ast")
            }
        }
    }

    /// Attempt to parse a [`PolicySet`] from source, without retaining source information.
    ///
    /// Policy ids will default to "policy*" with numbers from 0.
    /// If you load more policies, do not use the default id, or there will be conflicts.
    ///
    /// See [`Policy`] for more.
    ///
    /// Similar to [`PolicySet::from_str`], but does not retain the original source
    /// code or its locations. This allows for faster parsing and reduced memory
    /// usage, but limits the ability to provide detailed error messages.
    ///
    /// Only available with the "raw-parsing" feature.
    #[cfg(feature = "raw-parsing")]
    pub fn parse_raw(policies: &str) -> Option<Self> {
        let pset = parser::parse_policyset_raw(policies).ok()?;
        let policies = pset
            .policies()
            .map(|p| {
                (
                    PolicyId::new(p.id().clone()),
                    Policy {
                        lossless: LosslessPolicy::policy_or_template_text(None::<&str>),
                        ast: p.clone(),
                    },
                )
            })
            .collect();
        let templates = pset
            .templates()
            .map(|t| {
                (
                    PolicyId::new(t.id().clone()),
                    Template {
                        lossless: LosslessPolicy::policy_or_template_text(None::<&str>),
                        ast: t.clone(),
                    },
                )
            })
            .collect();
        Some(Self {
            ast: pset,
            policies,
            templates,
        })
    }
}

impl std::fmt::Display for PolicySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // prefer to display the lossless format
        let mut policies = self.policies().peekable();
        while let Some(policy) = policies.next() {
            policy.lossless.fmt(|| policy.ast.clone().into(), f)?;
            if policies.peek().is_some() {
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

/// Given a [`PolicyId`] and a [`Policy`], determine if the policy represents a static policy or a
/// link
fn is_static_or_link(
    (id, policy): (PolicyId, Policy),
) -> Result<Either<(ast::PolicyID, est::Policy), TemplateLink>, PolicyToJsonError> {
    match policy.template_id() {
        Some(template_id) => {
            let values = policy
                .ast
                .env()
                .iter()
                .map(|(id, euid)| (*id, euid.clone()))
                .collect();
            Ok(Either::Right(TemplateLink {
                new_id: id.into(),
                template_id: template_id.clone().into(),
                values,
            }))
        }
        None => policy
            .lossless
            .est(|| policy.ast.clone().into())
            .map(|est| Either::Left((id.into(), est))),
    }
}

/// Like [`itertools::Itertools::partition_map`], but accepts a function that can fail.
/// The first invocation of `f` that fails causes the whole computation to fail
#[allow(clippy::redundant_pub_crate)] // can't be private because it's used in tests
pub(crate) fn fold_partition<T, A, B, E>(
    i: impl IntoIterator<Item = T>,
    f: impl Fn(T) -> Result<Either<A, B>, E>,
) -> Result<(Vec<A>, Vec<B>), E> {
    let mut lefts = vec![];
    let mut rights = vec![];

    for item in i {
        match f(item)? {
            Either::Left(left) => lefts.push(left),
            Either::Right(right) => rights.push(right),
        }
    }

    Ok((lefts, rights))
}

/// The "type" of a [`Request`], i.e., the [`EntityTypeName`]s of principal
/// and resource, and the [`EntityUid`] of action
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestEnv {
    pub(crate) principal: EntityTypeName,
    pub(crate) action: EntityUid,
    pub(crate) resource: EntityTypeName,
}

impl RequestEnv {
    /// Construct a [`RequestEnv`]
    pub fn new(principal: EntityTypeName, action: EntityUid, resource: EntityTypeName) -> Self {
        Self {
            principal,
            action,
            resource,
        }
    }
    /// Get the principal type name
    pub fn principal(&self) -> &EntityTypeName {
        &self.principal
    }

    /// Get the action [`EntityUid`]
    pub fn action(&self) -> &EntityUid {
        &self.action
    }

    /// Get the resource type name
    pub fn resource(&self) -> &EntityTypeName {
        &self.resource
    }
}

#[doc(hidden)]
impl From<cedar_policy_core::validator::types::RequestEnv<'_>> for RequestEnv {
    fn from(renv: cedar_policy_core::validator::types::RequestEnv<'_>) -> Self {
        match renv {
            cedar_policy_core::validator::types::RequestEnv::DeclaredAction {
                principal,
                action,
                resource,
                ..
            } => Self {
                principal: principal.clone().into(),
                action: action.clone().into(),
                resource: resource.clone().into(),
            },
            // PANIC SAFETY: partial validation is not enabled and hence `RequestEnv::UndeclaredAction` should not show up
            #[allow(clippy::unreachable)]
            cedar_policy_core::validator::types::RequestEnv::UndeclaredAction => {
                unreachable!("used unsupported feature")
            }
        }
    }
}

/// Get valid request envs for an `ast::Template`
///
/// This function is called by [`Template::get_valid_request_envs`] and
/// [`Policy::get_valid_request_envs`]
fn get_valid_request_envs(ast: &ast::Template, s: &Schema) -> impl Iterator<Item = RequestEnv> {
    let tc = Typechecker::new(
        &s.0,
        cedar_policy_core::validator::ValidationMode::default(),
    );
    tc.typecheck_by_request_env(ast)
        .into_iter()
        .filter_map(|(env, pc)| {
            if matches!(pc, PolicyCheck::Success(_)) {
                Some(env.into())
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
}

/// Policy template datatype
//
// NOTE: Unlike the internal type [`ast::Template`], this type only supports
// templates. The `Template` constructors will return an error if provided with
// a static policy.
#[derive(Debug, Clone)]
pub struct Template {
    /// AST representation of the template, used for most operations.
    /// In particular, the `ast` contains the authoritative `PolicyId` for the template.
    pub(crate) ast: ast::Template,

    /// Some "lossless" representation of the template, whichever is most
    /// convenient to provide (and can be provided with the least overhead).
    /// This is used just for `to_json()`.
    /// We can't just derive this on-demand from `ast`, because the AST is lossy:
    /// we can't reconstruct an accurate CST/EST/policy-text from the AST, but
    /// we can from the EST (modulo whitespace and a few other things like the
    /// order of annotations).
    ///
    /// This is a `LosslessPolicy` (rather than something like `LosslessTemplate`)
    /// because the EST doesn't distinguish between static policies and templates.
    pub(crate) lossless: LosslessPolicy,
}

impl PartialEq for Template {
    fn eq(&self, other: &Self) -> bool {
        // eq is based on just the `ast`
        self.ast.eq(&other.ast)
    }
}
impl Eq for Template {}

#[doc(hidden)] // because this converts to a private/internal type
impl AsRef<ast::Template> for Template {
    fn as_ref(&self) -> &ast::Template {
        &self.ast
    }
}

#[doc(hidden)]
impl From<ast::Template> for Template {
    fn from(template: ast::Template) -> Self {
        Self::from_ast(template)
    }
}

impl Template {
    /// Attempt to parse a [`Template`] from source.
    /// Returns an error if the input is a static policy (i.e., has no slots).
    /// If `id` is Some, then the resulting template will have that `id`.
    /// If the `id` is None, the parser will use the default "policy0".
    /// The behavior around None may change in the future.
    pub fn parse(id: Option<PolicyId>, src: impl AsRef<str>) -> Result<Self, ParseErrors> {
        let ast = parser::parse_template(id.map(Into::into), src.as_ref())?;
        Ok(Self {
            ast,
            lossless: LosslessPolicy::policy_or_template_text(Some(src.as_ref())),
        })
    }

    /// Attempt to parse a [`Template`] from source, without retaining source information.
    /// Returns `None` if the input is a static policy (i.e., has no slots).
    /// If `id` is Some, then the resulting template will have that `id`.
    /// If the `id` is None, the parser will use the default "policy0".
    /// The behavior around None may change in the future.
    ///
    /// Similar to [`Template::parse`], but does not retain the original source
    /// code or its locations. This allows for faster parsing and reduced memory
    /// usage, but limits the ability to provide detailed error messages.
    ///
    /// Only available with the "raw-parsing" feature.
    #[cfg(feature = "raw-parsing")]
    pub fn parse_raw(id: Option<PolicyId>, src: impl AsRef<str>) -> Result<Self, ParseErrors> {
        let ast = parser::parse_template_raw(id.map(Into::into), src.as_ref())?;
        Ok(Self {
            ast,
            lossless: LosslessPolicy::policy_or_template_text(Some(src.as_ref())),
        })
    }

    /// Get the `PolicyId` of this `Template`
    pub fn id(&self) -> &PolicyId {
        PolicyId::ref_cast(self.ast.id())
    }

    /// Clone this `Template` with a new `PolicyId`
    #[must_use]
    pub fn new_id(&self, id: PolicyId) -> Self {
        Self {
            ast: self.ast.new_id(id.into()),
            lossless: self.lossless.clone(), // Lossless representation doesn't include the `PolicyId`
        }
    }

    /// Get the `Effect` (`Forbid` or `Permit`) of this `Template`
    pub fn effect(&self) -> Effect {
        self.ast.effect()
    }

    /// Get an annotation value of this `Template`.
    /// If the annotation is present without an explicit value (e.g., `@annotation`),
    /// then this function returns `Some("")`. Returns `None` when the
    /// annotation is not present or when `key` is not a valid annotation identifier.
    pub fn annotation(&self, key: impl AsRef<str>) -> Option<&str> {
        self.ast
            .annotation(&key.as_ref().parse().ok()?)
            .map(AsRef::as_ref)
    }

    /// Iterate through annotation data of this `Template` as key-value pairs.
    /// Annotations which do not have an explicit value (e.g., `@annotation`),
    /// are included in the iterator with the value `""`.
    pub fn annotations(&self) -> impl Iterator<Item = (&str, &str)> {
        self.ast
            .annotations()
            .map(|(k, v)| (k.as_ref(), v.as_ref()))
    }

    /// Iterate over the open slots in this `Template`
    pub fn slots(&self) -> impl Iterator<Item = &SlotId> {
        self.ast.slots().map(|slot| SlotId::ref_cast(&slot.id))
    }

    /// Get the scope constraint on this policy's principal
    pub fn principal_constraint(&self) -> TemplatePrincipalConstraint {
        match self.ast.principal_constraint().as_inner() {
            ast::PrincipalOrResourceConstraint::Any => TemplatePrincipalConstraint::Any,
            ast::PrincipalOrResourceConstraint::In(eref) => {
                TemplatePrincipalConstraint::In(match eref {
                    ast::EntityReference::EUID(e) => Some(e.as_ref().clone().into()),
                    ast::EntityReference::Slot(_) => None,
                })
            }
            ast::PrincipalOrResourceConstraint::Eq(eref) => {
                TemplatePrincipalConstraint::Eq(match eref {
                    ast::EntityReference::EUID(e) => Some(e.as_ref().clone().into()),
                    ast::EntityReference::Slot(_) => None,
                })
            }
            ast::PrincipalOrResourceConstraint::Is(entity_type) => {
                TemplatePrincipalConstraint::Is(entity_type.as_ref().clone().into())
            }
            ast::PrincipalOrResourceConstraint::IsIn(entity_type, eref) => {
                TemplatePrincipalConstraint::IsIn(
                    entity_type.as_ref().clone().into(),
                    match eref {
                        ast::EntityReference::EUID(e) => Some(e.as_ref().clone().into()),
                        ast::EntityReference::Slot(_) => None,
                    },
                )
            }
        }
    }

    /// Get the scope constraint on this policy's action
    pub fn action_constraint(&self) -> ActionConstraint {
        // Clone the data from Core to be consistent with the other constraints
        match self.ast.action_constraint() {
            ast::ActionConstraint::Any => ActionConstraint::Any,
            ast::ActionConstraint::In(ids) => {
                ActionConstraint::In(ids.iter().map(|id| id.as_ref().clone().into()).collect())
            }
            ast::ActionConstraint::Eq(id) => ActionConstraint::Eq(id.as_ref().clone().into()),
            #[cfg(feature = "tolerant-ast")]
            ast::ActionConstraint::ErrorConstraint => {
                // We will only have an ErrorConstraint if we are using a parser that allows Error nodes
                // It is not recommended to evaluate an AST that allows error nodes
                // If somehow someone tries to evaluate an AST that includes an Action constraint error, we will
                // treat it as `Any`
                ActionConstraint::Any
            }
        }
    }

    /// Get the scope constraint on this policy's resource
    pub fn resource_constraint(&self) -> TemplateResourceConstraint {
        match self.ast.resource_constraint().as_inner() {
            ast::PrincipalOrResourceConstraint::Any => TemplateResourceConstraint::Any,
            ast::PrincipalOrResourceConstraint::In(eref) => {
                TemplateResourceConstraint::In(match eref {
                    ast::EntityReference::EUID(e) => Some(e.as_ref().clone().into()),
                    ast::EntityReference::Slot(_) => None,
                })
            }
            ast::PrincipalOrResourceConstraint::Eq(eref) => {
                TemplateResourceConstraint::Eq(match eref {
                    ast::EntityReference::EUID(e) => Some(e.as_ref().clone().into()),
                    ast::EntityReference::Slot(_) => None,
                })
            }
            ast::PrincipalOrResourceConstraint::Is(entity_type) => {
                TemplateResourceConstraint::Is(entity_type.as_ref().clone().into())
            }
            ast::PrincipalOrResourceConstraint::IsIn(entity_type, eref) => {
                TemplateResourceConstraint::IsIn(
                    entity_type.as_ref().clone().into(),
                    match eref {
                        ast::EntityReference::EUID(e) => Some(e.as_ref().clone().into()),
                        ast::EntityReference::Slot(_) => None,
                    },
                )
            }
        }
    }

    /// Create a [`Template`] from its JSON representation.
    /// Returns an error if the input is a static policy (i.e., has no slots).
    /// If `id` is Some, the policy will be given that Policy Id.
    /// If `id` is None, then "JSON policy" will be used.
    /// The behavior around None may change in the future.
    pub fn from_json(
        id: Option<PolicyId>,
        json: serde_json::Value,
    ) -> Result<Self, PolicyFromJsonError> {
        let est: est::Policy = serde_json::from_value(json)
            .map_err(|e| entities_json_errors::JsonDeserializationError::Serde(e.into()))
            .map_err(cedar_policy_core::est::FromJsonError::from)?;
        Self::from_est(id, est)
    }

    fn from_est(id: Option<PolicyId>, est: est::Policy) -> Result<Self, PolicyFromJsonError> {
        Ok(Self {
            ast: est.clone().try_into_ast_template(id.map(PolicyId::into))?,
            lossless: LosslessPolicy::Est(est),
        })
    }

    #[cfg_attr(not(feature = "protobufs"), allow(dead_code))]
    pub(crate) fn from_ast(ast: ast::Template) -> Self {
        Self {
            lossless: LosslessPolicy::Est(ast.clone().into()),
            ast,
        }
    }

    /// Get the JSON representation of this `Template`.
    pub fn to_json(&self) -> Result<serde_json::Value, PolicyToJsonError> {
        let est = self.lossless.est(|| self.ast.clone().into())?;
        serde_json::to_value(est).map_err(Into::into)
    }

    /// Get the human-readable Cedar syntax representation of this template.
    /// This function is primarily intended for rendering JSON policies in the
    /// human-readable syntax, but it will also return the original policy text
    /// when given a policy parsed from the human-readable syntax.
    ///
    /// It also does not format the policy according to any particular rules.
    /// Policy formatting can be done through the Cedar policy CLI or
    /// the `cedar-policy-formatter` crate.
    pub fn to_cedar(&self) -> String {
        match &self.lossless {
            LosslessPolicy::Empty | LosslessPolicy::Est(_) => self.ast.to_string(),
            LosslessPolicy::Text { text, .. } => text.clone(),
        }
    }

    /// Get the valid [`RequestEnv`]s for this template, according to the schema.
    ///
    /// That is, all the [`RequestEnv`]s in the schema for which this template is
    /// not trivially false.
    pub fn get_valid_request_envs(&self, s: &Schema) -> impl Iterator<Item = RequestEnv> {
        get_valid_request_envs(&self.ast, s)
    }
}

impl std::fmt::Display for Template {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // prefer to display the lossless format
        self.lossless.fmt(|| self.ast.clone().into(), f)
    }
}

impl FromStr for Template {
    type Err = ParseErrors;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Self::parse(None, src)
    }
}

/// Scope constraint on policy principals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalConstraint {
    /// Un-constrained
    Any,
    /// Must be In the given [`EntityUid`]
    In(EntityUid),
    /// Must be equal to the given [`EntityUid`]
    Eq(EntityUid),
    /// Must be the given [`EntityTypeName`]
    Is(EntityTypeName),
    /// Must be the given [`EntityTypeName`], and `in` the [`EntityUid`]
    IsIn(EntityTypeName, EntityUid),
}

/// Scope constraint on policy principals for templates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplatePrincipalConstraint {
    /// Un-constrained
    Any,
    /// Must be In the given [`EntityUid`].
    /// If [`None`], then it is a template slot.
    In(Option<EntityUid>),
    /// Must be equal to the given [`EntityUid`].
    /// If [`None`], then it is a template slot.
    Eq(Option<EntityUid>),
    /// Must be the given [`EntityTypeName`].
    Is(EntityTypeName),
    /// Must be the given [`EntityTypeName`], and `in` the [`EntityUid`].
    /// If the [`EntityUid`] is [`Option::None`], then it is a template slot.
    IsIn(EntityTypeName, Option<EntityUid>),
}

impl TemplatePrincipalConstraint {
    /// Does this constraint contain a slot?
    pub fn has_slot(&self) -> bool {
        match self {
            Self::Any | Self::Is(_) => false,
            Self::In(o) | Self::Eq(o) | Self::IsIn(_, o) => o.is_none(),
        }
    }
}

/// Scope constraint on policy actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionConstraint {
    /// Un-constrained
    Any,
    /// Must be In the given [`EntityUid`]
    In(Vec<EntityUid>),
    /// Must be equal to the given [`EntityUid]`
    Eq(EntityUid),
}

/// Scope constraint on policy resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceConstraint {
    /// Un-constrained
    Any,
    /// Must be In the given [`EntityUid`]
    In(EntityUid),
    /// Must be equal to the given [`EntityUid`]
    Eq(EntityUid),
    /// Must be the given [`EntityTypeName`]
    Is(EntityTypeName),
    /// Must be the given [`EntityTypeName`], and `in` the [`EntityUid`]
    IsIn(EntityTypeName, EntityUid),
}

/// Scope constraint on policy resources for templates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateResourceConstraint {
    /// Un-constrained
    Any,
    /// Must be In the given [`EntityUid`].
    /// If [`None`], then it is a template slot.
    In(Option<EntityUid>),
    /// Must be equal to the given [`EntityUid`].
    /// If [`None`], then it is a template slot.
    Eq(Option<EntityUid>),
    /// Must be the given [`EntityTypeName`].
    Is(EntityTypeName),
    /// Must be the given [`EntityTypeName`], and `in` the [`EntityUid`].
    /// If the [`EntityUid`] is [`Option::None`], then it is a template slot.
    IsIn(EntityTypeName, Option<EntityUid>),
}

impl TemplateResourceConstraint {
    /// Does this constraint contain a slot?
    pub fn has_slot(&self) -> bool {
        match self {
            Self::Any | Self::Is(_) => false,
            Self::In(o) | Self::Eq(o) | Self::IsIn(_, o) => o.is_none(),
        }
    }
}

/// Structure for a `Policy`. Includes both static policies and template-linked policies.
#[derive(Debug, Clone)]
pub struct Policy {
    /// AST representation of the policy, used for most operations.
    /// In particular, the `ast` contains the authoritative `PolicyId` for the policy.
    pub(crate) ast: ast::Policy,
    /// Some "lossless" representation of the policy, whichever is most
    /// convenient to provide (and can be provided with the least overhead).
    /// This is used just for `to_json()`.
    /// We can't just derive this on-demand from `ast`, because the AST is lossy:
    /// we can't reconstruct an accurate CST/EST/policy-text from the AST, but
    /// we can from the EST (modulo whitespace and a few other things like the
    /// order of annotations).
    pub(crate) lossless: LosslessPolicy,
}

impl PartialEq for Policy {
    fn eq(&self, other: &Self) -> bool {
        // eq is based on just the `ast`
        self.ast.eq(&other.ast)
    }
}
impl Eq for Policy {}

#[doc(hidden)] // because this converts to a private/internal type
impl AsRef<ast::Policy> for Policy {
    fn as_ref(&self) -> &ast::Policy {
        &self.ast
    }
}

#[doc(hidden)]
impl From<ast::Policy> for Policy {
    fn from(policy: ast::Policy) -> Self {
        Self::from_ast(policy)
    }
}

#[doc(hidden)]
impl From<ast::StaticPolicy> for Policy {
    fn from(policy: ast::StaticPolicy) -> Self {
        ast::Policy::from(policy).into()
    }
}

impl Policy {
    /// Get the `PolicyId` of the `Template` this is linked to.
    /// If this is a static policy, this will return `None`.
    pub fn template_id(&self) -> Option<&PolicyId> {
        if self.is_static() {
            None
        } else {
            Some(PolicyId::ref_cast(self.ast.template().id()))
        }
    }

    /// Get the values this `Template` is linked to, expressed as a map from `SlotId` to `EntityUid`.
    /// If this is a static policy, this will return `None`.
    pub fn template_links(&self) -> Option<HashMap<SlotId, EntityUid>> {
        if self.is_static() {
            None
        } else {
            let wrapped_vals: HashMap<SlotId, EntityUid> = self
                .ast
                .env()
                .iter()
                .map(|(key, value)| ((*key).into(), value.clone().into()))
                .collect();
            Some(wrapped_vals)
        }
    }

    /// Get the `Effect` (`Permit` or `Forbid`) for this instance
    pub fn effect(&self) -> Effect {
        self.ast.effect()
    }

    /// Get an annotation value of this template-linked or static policy.
    /// If the annotation is present without an explicit value (e.g., `@annotation`),
    /// then this function returns `Some("")`. Returns `None` when the
    /// annotation is not present or when `key` is not a valid annotations identifier.
    pub fn annotation(&self, key: impl AsRef<str>) -> Option<&str> {
        self.ast
            .annotation(&key.as_ref().parse().ok()?)
            .map(AsRef::as_ref)
    }

    /// Iterate through annotation data of this template-linked or static policy.
    /// Annotations which do not have an explicit value (e.g., `@annotation`),
    /// are included in the iterator with the value `""`.
    pub fn annotations(&self) -> impl Iterator<Item = (&str, &str)> {
        self.ast
            .annotations()
            .map(|(k, v)| (k.as_ref(), v.as_ref()))
    }

    /// Get the `PolicyId` for this template-linked or static policy
    pub fn id(&self) -> &PolicyId {
        PolicyId::ref_cast(self.ast.id())
    }

    /// Clone this `Policy` with a new `PolicyId`
    #[must_use]
    pub fn new_id(&self, id: PolicyId) -> Self {
        Self {
            ast: self.ast.new_id(id.into()),
            lossless: self.lossless.clone(), // Lossless representation doesn't include the `PolicyId`
        }
    }

    /// Returns `true` if this is a static policy, `false` otherwise.
    pub fn is_static(&self) -> bool {
        self.ast.is_static()
    }

    /// Get the scope constraint on this policy's principal
    pub fn principal_constraint(&self) -> PrincipalConstraint {
        let slot_id = ast::SlotId::principal();
        match self.ast.template().principal_constraint().as_inner() {
            ast::PrincipalOrResourceConstraint::Any => PrincipalConstraint::Any,
            ast::PrincipalOrResourceConstraint::In(eref) => {
                PrincipalConstraint::In(self.convert_entity_reference(eref, slot_id).clone())
            }
            ast::PrincipalOrResourceConstraint::Eq(eref) => {
                PrincipalConstraint::Eq(self.convert_entity_reference(eref, slot_id).clone())
            }
            ast::PrincipalOrResourceConstraint::Is(entity_type) => {
                PrincipalConstraint::Is(entity_type.as_ref().clone().into())
            }
            ast::PrincipalOrResourceConstraint::IsIn(entity_type, eref) => {
                PrincipalConstraint::IsIn(
                    entity_type.as_ref().clone().into(),
                    self.convert_entity_reference(eref, slot_id).clone(),
                )
            }
        }
    }

    /// Get the scope constraint on this policy's action
    pub fn action_constraint(&self) -> ActionConstraint {
        // Clone the data from Core to be consistant with the other constraints
        match self.ast.template().action_constraint() {
            ast::ActionConstraint::Any => ActionConstraint::Any,
            ast::ActionConstraint::In(ids) => ActionConstraint::In(
                ids.iter()
                    .map(|euid| EntityUid::ref_cast(euid.as_ref()))
                    .cloned()
                    .collect(),
            ),
            ast::ActionConstraint::Eq(id) => ActionConstraint::Eq(EntityUid::ref_cast(id).clone()),
            #[cfg(feature = "tolerant-ast")]
            ast::ActionConstraint::ErrorConstraint => {
                // We will only have an ErrorConstraint if we are using a parser that allows Error nodes
                // It is not recommended to evaluate an AST that allows error nodes
                // If somehow someone tries to evaluate an AST that includes an Action constraint error, we will
                // treat it as `Any`
                ActionConstraint::Any
            }
        }
    }

    /// Get the scope constraint on this policy's resource
    pub fn resource_constraint(&self) -> ResourceConstraint {
        let slot_id = ast::SlotId::resource();
        match self.ast.template().resource_constraint().as_inner() {
            ast::PrincipalOrResourceConstraint::Any => ResourceConstraint::Any,
            ast::PrincipalOrResourceConstraint::In(eref) => {
                ResourceConstraint::In(self.convert_entity_reference(eref, slot_id).clone())
            }
            ast::PrincipalOrResourceConstraint::Eq(eref) => {
                ResourceConstraint::Eq(self.convert_entity_reference(eref, slot_id).clone())
            }
            ast::PrincipalOrResourceConstraint::Is(entity_type) => {
                ResourceConstraint::Is(entity_type.as_ref().clone().into())
            }
            ast::PrincipalOrResourceConstraint::IsIn(entity_type, eref) => {
                ResourceConstraint::IsIn(
                    entity_type.as_ref().clone().into(),
                    self.convert_entity_reference(eref, slot_id).clone(),
                )
            }
        }
    }

    /// To avoid panicking, this function may only be called when `slot` is the
    /// `SlotId` corresponding to the scope constraint from which the entity
    /// reference `r` was extracted. I.e., If `r` is taken from the principal
    /// scope constraint, `slot` must be `?principal`. This ensures that the
    /// `SlotId` exists in the policy (and therefore the slot environment map)
    /// whenever the `EntityReference` `r` is the Slot variant.
    fn convert_entity_reference<'a>(
        &'a self,
        r: &'a ast::EntityReference,
        slot: ast::SlotId,
    ) -> &'a EntityUid {
        match r {
            ast::EntityReference::EUID(euid) => EntityUid::ref_cast(euid),
            // PANIC SAFETY: This `unwrap` here is safe due the invariant (values total map) on policies.
            #[allow(clippy::unwrap_used)]
            ast::EntityReference::Slot(_) => {
                EntityUid::ref_cast(self.ast.env().get(&slot).unwrap())
            }
        }
    }

    /// Parse a single policy.
    /// If `id` is Some, the policy will be given that Policy Id.
    /// If `id` is None, then "policy0" will be used.
    /// The behavior around None may change in the future.
    ///
    /// This can fail if the policy fails to parse.
    /// It can also fail if a template was passed in, as this function only accepts static
    /// policies
    pub fn parse(id: Option<PolicyId>, policy_src: impl AsRef<str>) -> Result<Self, ParseErrors> {
        let inline_ast = parser::parse_policy(id.map(Into::into), policy_src.as_ref())?;
        let (_, ast) = ast::Template::link_static_policy(inline_ast);
        Ok(Self {
            ast,
            lossless: LosslessPolicy::policy_or_template_text(Some(policy_src.as_ref())),
        })
    }

    /// Create a `Policy` from its JSON representation.
    /// If `id` is Some, the policy will be given that Policy Id.
    /// If `id` is None, then "JSON policy" will be used.
    /// The behavior around None may change in the future.
    ///
    /// ```
    /// # use cedar_policy::{Policy, PolicyId};
    ///
    /// let json: serde_json::Value = serde_json::json!(
    ///        {
    ///            "effect":"permit",
    ///            "principal":{
    ///            "op":"==",
    ///            "entity":{
    ///                "type":"User",
    ///                "id":"bob"
    ///            }
    ///            },
    ///            "action":{
    ///            "op":"==",
    ///            "entity":{
    ///                "type":"Action",
    ///                "id":"view"
    ///            }
    ///            },
    ///            "resource":{
    ///            "op":"==",
    ///            "entity":{
    ///                "type":"Album",
    ///                "id":"trip"
    ///            }
    ///            },
    ///            "conditions":[
    ///            {
    ///                "kind":"when",
    ///                "body":{
    ///                   ">":{
    ///                        "left":{
    ///                        ".":{
    ///                            "left":{
    ///                                "Var":"principal"
    ///                            },
    ///                            "attr":"age"
    ///                        }
    ///                        },
    ///                        "right":{
    ///                        "Value":18
    ///                        }
    ///                    }
    ///                }
    ///            }
    ///            ]
    ///        }
    /// );
    /// let json_policy = Policy::from_json(None, json).unwrap();
    /// let src = r#"
    ///   permit(
    ///     principal == User::"bob",
    ///     action == Action::"view",
    ///     resource == Album::"trip"
    ///   )
    ///   when { principal.age > 18 };"#;
    /// let text_policy = Policy::parse(None, src).unwrap();
    /// assert_eq!(json_policy.to_json().unwrap(), text_policy.to_json().unwrap());
    /// ```
    pub fn from_json(
        id: Option<PolicyId>,
        json: serde_json::Value,
    ) -> Result<Self, PolicyFromJsonError> {
        let est: est::Policy = serde_json::from_value(json)
            .map_err(|e| entities_json_errors::JsonDeserializationError::Serde(e.into()))
            .map_err(cedar_policy_core::est::FromJsonError::from)?;
        Self::from_est(id, est)
    }

    /// Get the valid [`RequestEnv`]s for this policy, according to the schema.
    ///
    /// That is, all the [`RequestEnv`]s in the schema for which this policy is
    /// not trivially false.
    pub fn get_valid_request_envs(&self, s: &Schema) -> impl Iterator<Item = RequestEnv> {
        get_valid_request_envs(self.ast.template(), s)
    }

    /// Get all entity literals occuring in a `Policy`
    pub fn entity_literals(&self) -> Vec<EntityUid> {
        self.ast
            .condition()
            .subexpressions()
            .filter_map(|e| match e.expr_kind() {
                cedar_policy_core::ast::ExprKind::Lit(
                    cedar_policy_core::ast::Literal::EntityUID(euid),
                ) => Some(EntityUid((*euid).as_ref().clone())),
                _ => None,
            })
            .collect()
    }

    /// Return a new policy where all occurrences of key `EntityUid`s are replaced by value `EntityUid`
    /// (as a single, non-sequential substitution).
    pub fn sub_entity_literals(
        &self,
        mapping: BTreeMap<EntityUid, EntityUid>,
    ) -> Result<Self, PolicyFromJsonError> {
        // PANIC SAFETY: This can't fail for a policy that was already constructed
        #[allow(clippy::expect_used)]
        let cloned_est = self
            .lossless
            .est(|| self.ast.clone().into())
            .expect("Internal error, failed to construct est.");

        let mapping = mapping.into_iter().map(|(k, v)| (k.0, v.0)).collect();

        // PANIC SAFETY: This can't fail for a policy that was already constructed
        #[allow(clippy::expect_used)]
        let est = cloned_est
            .sub_entity_literals(&mapping)
            .expect("Internal error, failed to sub entity literals.");

        let ast = match est.clone().try_into_ast_policy(Some(self.ast.id().clone())) {
            Ok(ast) => ast,
            Err(e) => return Err(e.into()),
        };

        Ok(Self {
            ast,
            lossless: LosslessPolicy::Est(est),
        })
    }

    fn from_est(id: Option<PolicyId>, est: est::Policy) -> Result<Self, PolicyFromJsonError> {
        Ok(Self {
            ast: est.clone().try_into_ast_policy(id.map(PolicyId::into))?,
            lossless: LosslessPolicy::Est(est),
        })
    }

    /// Get the JSON representation of this `Policy`.
    ///  ```
    /// # use cedar_policy::Policy;
    /// let src = r#"
    ///   permit(
    ///     principal == User::"bob",
    ///     action == Action::"view",
    ///     resource == Album::"trip"
    ///   )
    ///   when { principal.age > 18 };"#;
    ///
    /// let policy = Policy::parse(None, src).unwrap();
    /// println!("{}", policy);
    /// // convert the policy to JSON
    /// let json = policy.to_json().unwrap();
    /// println!("{}", json);
    /// assert_eq!(json, Policy::from_json(None, json.clone()).unwrap().to_json().unwrap());
    /// ```
    pub fn to_json(&self) -> Result<serde_json::Value, PolicyToJsonError> {
        let est = self.lossless.est(|| self.ast.clone().into())?;
        serde_json::to_value(est).map_err(Into::into)
    }

    /// Get the human-readable Cedar syntax representation of this policy. This
    /// function is primarily intended for rendering JSON policies in the
    /// human-readable syntax, but it will also return the original policy text
    /// when given a policy parsed from the human-readable syntax.
    ///
    /// It will return `None` for linked policies because they cannot be
    /// directly rendered in Cedar syntax. You can instead render the unlinked
    /// template if you do not need to preserve links. If serializing links is
    /// important, then you will need to serialize the whole policy set
    /// containing the template and link to JSON (or protobuf).
    ///
    /// It also does not format the policy according to any particular rules.
    /// Policy formatting can be done through the Cedar policy CLI or
    /// the `cedar-policy-formatter` crate.
    pub fn to_cedar(&self) -> Option<String> {
        match &self.lossless {
            LosslessPolicy::Empty | LosslessPolicy::Est(_) => Some(self.ast.to_string()),
            LosslessPolicy::Text { text, slots } => {
                if slots.is_empty() {
                    Some(text.clone())
                } else {
                    None
                }
            }
        }
    }

    /// Attempt to parse a [`Policy`] from source, without retaining source information.
    /// If `id` is Some, the policy will be given that Policy Id.
    /// If `id` is None, then "policy0" will be used.
    /// The behavior around None may change in the future.
    ///
    /// This can fail if the policy fails to parse.
    /// It can also fail if a template was passed in, as this function only accepts static
    /// policies.
    ///
    /// Similar to [`Policy::parse`], but does not retain the original source
    /// code or its locations. This allows for faster parsing and reduced memory
    /// usage, but limits the ability to provide detailed error messages.
    ///
    /// Only available with the "raw-parsing" feature.
    #[cfg(feature = "raw-parsing")]
    pub fn parse_raw(id: Option<PolicyId>, policy_src: impl AsRef<str>) -> Option<Self> {
        let inline_ast = parser::parse_policy_raw(id.map(Into::into), policy_src.as_ref()).ok()?;
        let (_, ast) = ast::Template::link_static_policy(inline_ast);
        Some(Self {
            ast,
            lossless: LosslessPolicy::policy_or_template_text(Some(policy_src.as_ref())),
        })
    }

    /// Get all the unknown entities from the policy
    #[doc = include_str!("../experimental_warning.md")]
    #[cfg(feature = "partial-eval")]
    pub fn unknown_entities(&self) -> HashSet<EntityUid> {
        self.ast
            .unknown_entities()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Create a `Policy` from its AST representation only. The `LosslessPolicy`
    /// will reflect the AST structure. When possible, don't use this method and
    /// create the `Policy` from the policy text, CST, or EST instead, as the
    /// conversion to AST is lossy. ESTs for policies generated by this method
    /// will reflect the AST and not the original policy syntax.
    #[cfg_attr(
        not(any(feature = "partial-eval", feature = "protobufs")),
        allow(unused)
    )]
    pub(crate) fn from_ast(ast: ast::Policy) -> Self {
        let text = ast.to_string(); // assume that pretty-printing is faster than `est::Policy::from(ast.clone())`; is that true?
        Self {
            ast,
            lossless: LosslessPolicy::policy_or_template_text(Some(text)),
        }
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // prefer to display the lossless format
        self.lossless.fmt(|| self.ast.clone().into(), f)
    }
}

impl FromStr for Policy {
    type Err = ParseErrors;
    /// Create a policy
    ///
    /// Important note: Policies have ids, but this interface does not
    /// allow them to be set. It will use the default "policy0", which
    /// may cause id conflicts if not handled. Use `Policy::parse` to set
    /// the id when parsing, or `Policy::new_id` to clone a policy with
    /// a new id.
    fn from_str(policy: &str) -> Result<Self, Self::Err> {
        Self::parse(None, policy)
    }
}

/// See comments on `Policy` and `Template`.
///
/// This structure can be used for static policies, linked policies, and templates.
#[derive(Debug, Clone)]
pub(crate) enum LosslessPolicy {
    /// An empty representation
    Empty,
    /// EST representation
    Est(est::Policy),
    /// Text representation
    Text {
        /// actual policy text, of the policy or template
        text: String,
        /// For linked policies, map of slot to UID. Only linked policies have
        /// this; static policies and (unlinked) templates have an empty map
        /// here
        slots: HashMap<ast::SlotId, ast::EntityUID>,
    },
}

impl LosslessPolicy {
    /// Create a new `LosslessPolicy` from the text of a policy or template.
    fn policy_or_template_text(text: Option<impl Into<String>>) -> Self {
        text.map_or(Self::Empty, |text| Self::Text {
            text: text.into(),
            slots: HashMap::new(),
        })
    }

    /// Get the EST representation of this static policy, linked policy, or template.
    fn est(
        &self,
        fallback_est: impl FnOnce() -> est::Policy,
    ) -> Result<est::Policy, PolicyToJsonError> {
        match self {
            // Fall back to the `policy` AST if the lossless representation is empty
            Self::Empty => Ok(fallback_est()),
            Self::Est(est) => Ok(est.clone()),
            Self::Text { text, slots } => {
                let est =
                    parser::parse_policy_or_template_to_est(text).map_err(ParseErrors::from)?;
                if slots.is_empty() {
                    Ok(est)
                } else {
                    let unwrapped_vals = slots.iter().map(|(k, v)| (*k, v.into())).collect();
                    Ok(est.link(&unwrapped_vals)?)
                }
            }
        }
    }

    fn link<'a>(
        self,
        vals: impl IntoIterator<Item = (ast::SlotId, &'a ast::EntityUID)>,
    ) -> Result<Self, est::LinkingError> {
        match self {
            Self::Empty => Ok(Self::Empty),
            Self::Est(est) => {
                let unwrapped_est_vals: HashMap<
                    ast::SlotId,
                    cedar_policy_core::entities::EntityUidJson,
                > = vals.into_iter().map(|(k, v)| (k, v.into())).collect();
                Ok(Self::Est(est.link(&unwrapped_est_vals)?))
            }
            Self::Text { text, slots } => {
                debug_assert!(
                    slots.is_empty(),
                    "shouldn't call link() on an already-linked policy"
                );
                let slots = vals.into_iter().map(|(k, v)| (k, v.clone())).collect();
                Ok(Self::Text { text, slots })
            }
        }
    }

    fn fmt(
        &self,
        fallback_est: impl FnOnce() -> est::Policy,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::Empty => match self.est(fallback_est) {
                Ok(est) => write!(f, "{est}"),
                Err(e) => write!(f, "<invalid policy: {e}>"),
            },
            Self::Est(est) => write!(f, "{est}"),
            Self::Text { text, slots } => {
                if slots.is_empty() {
                    write!(f, "{text}")
                } else {
                    // need to replace placeholders according to `slots`.
                    // just find-and-replace wouldn't be safe/perfect, we
                    // want to use the actual parser; right now we reuse
                    // another implementation by just converting to EST and
                    // printing that
                    match self.est(fallback_est) {
                        Ok(est) => write!(f, "{est}"),
                        Err(e) => write!(f, "<invalid linked policy: {e}>"),
                    }
                }
            }
        }
    }
}

/// Expressions to be evaluated
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct Expression(pub(crate) ast::Expr);

#[doc(hidden)] // because this converts to a private/internal type
impl AsRef<ast::Expr> for Expression {
    fn as_ref(&self) -> &ast::Expr {
        &self.0
    }
}

#[doc(hidden)]
impl From<ast::Expr> for Expression {
    fn from(expr: ast::Expr) -> Self {
        Self(expr)
    }
}

impl Expression {
    /// Create an expression representing a literal string.
    pub fn new_string(value: String) -> Self {
        Self(ast::Expr::val(value))
    }

    /// Create an expression representing a literal bool.
    pub fn new_bool(value: bool) -> Self {
        Self(ast::Expr::val(value))
    }

    /// Create an expression representing a literal long.
    pub fn new_long(value: ast::Integer) -> Self {
        Self(ast::Expr::val(value))
    }

    /// Create an expression representing a record.
    ///
    /// Error if any key appears two or more times in `fields`.
    pub fn new_record(
        fields: impl IntoIterator<Item = (String, Self)>,
    ) -> Result<Self, ExpressionConstructionError> {
        Ok(Self(ast::Expr::record(
            fields.into_iter().map(|(k, v)| (SmolStr::from(k), v.0)),
        )?))
    }

    /// Create an expression representing a Set.
    pub fn new_set(values: impl IntoIterator<Item = Self>) -> Self {
        Self(ast::Expr::set(values.into_iter().map(|v| v.0)))
    }

    /// Create an expression representing an ip address.
    /// This function does not perform error checking on the source string,
    /// it creates an expression that calls the `ip` constructor.
    pub fn new_ip(src: impl AsRef<str>) -> Self {
        let src_expr = ast::Expr::val(src.as_ref());
        Self(ast::Expr::call_extension_fn(
            ip_extension_name(),
            vec![src_expr],
        ))
    }

    /// Create an expression representing a fixed precision decimal number.
    /// This function does not perform error checking on the source string,
    /// it creates an expression that calls the `decimal` constructor.
    pub fn new_decimal(src: impl AsRef<str>) -> Self {
        let src_expr = ast::Expr::val(src.as_ref());
        Self(ast::Expr::call_extension_fn(
            decimal_extension_name(),
            vec![src_expr],
        ))
    }

    /// Create an expression representing a particular instant of time.
    /// This function does not perform error checking on the source string,
    /// it creates an expression that calls the `datetime` constructor.
    pub fn new_datetime(src: impl AsRef<str>) -> Self {
        let src_expr = ast::Expr::val(src.as_ref());
        Self(ast::Expr::call_extension_fn(
            datetime_extension_name(),
            vec![src_expr],
        ))
    }

    /// Create an expression representing a duration of time.
    /// This function does not perform error checking on the source string,
    /// it creates an expression that calls the `datetime` constructor.
    pub fn new_duration(src: impl AsRef<str>) -> Self {
        let src_expr = ast::Expr::val(src.as_ref());
        Self(ast::Expr::call_extension_fn(
            duration_extension_name(),
            vec![src_expr],
        ))
    }
}

#[cfg(test)]
impl Expression {
    /// Deconstruct an [`Expression`] to get the internal type.
    /// This function is only intended to be used internally.
    pub(crate) fn into_inner(self) -> ast::Expr {
        self.0
    }
}

impl FromStr for Expression {
    type Err = ParseErrors;

    /// create an Expression using Cedar syntax
    fn from_str(expression: &str) -> Result<Self, Self::Err> {
        ast::Expr::from_str(expression)
            .map(Expression)
            .map_err(Into::into)
    }
}

impl std::fmt::Display for Expression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

/// "Restricted" expressions are used for attribute values and `context`.
///
/// Restricted expressions can contain only the following:
///   - bool, int, and string literals
///   - literal `EntityUid`s such as `User::"alice"`
///   - extension function calls, where the arguments must be other things
///     on this list
///   - set and record literals, where the values must be other things on
///     this list
///
/// That means the following are not allowed in restricted expressions:
///   - `principal`, `action`, `resource`, `context`
///   - builtin operators and functions, including `.`, `in`, `has`, `like`,
///     `.contains()`
///   - if-then-else expressions
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct RestrictedExpression(ast::RestrictedExpr);

#[doc(hidden)] // because this converts to a private/internal type
impl AsRef<ast::RestrictedExpr> for RestrictedExpression {
    fn as_ref(&self) -> &ast::RestrictedExpr {
        &self.0
    }
}

impl RestrictedExpression {
    /// Create an expression representing a literal string.
    pub fn new_string(value: String) -> Self {
        Self(ast::RestrictedExpr::val(value))
    }

    /// Create an expression representing a literal bool.
    pub fn new_bool(value: bool) -> Self {
        Self(ast::RestrictedExpr::val(value))
    }

    /// Create an expression representing a literal long.
    pub fn new_long(value: ast::Integer) -> Self {
        Self(ast::RestrictedExpr::val(value))
    }

    /// Create an expression representing a literal `EntityUid`.
    pub fn new_entity_uid(value: EntityUid) -> Self {
        Self(ast::RestrictedExpr::val(ast::EntityUID::from(value)))
    }

    /// Create an expression representing a record.
    ///
    /// Error if any key appears two or more times in `fields`.
    pub fn new_record(
        fields: impl IntoIterator<Item = (String, Self)>,
    ) -> Result<Self, ExpressionConstructionError> {
        Ok(Self(ast::RestrictedExpr::record(
            fields.into_iter().map(|(k, v)| (SmolStr::from(k), v.0)),
        )?))
    }

    /// Create an expression representing a Set.
    pub fn new_set(values: impl IntoIterator<Item = Self>) -> Self {
        Self(ast::RestrictedExpr::set(values.into_iter().map(|v| v.0)))
    }

    /// Create an expression representing an ip address.
    /// This function does not perform error checking on the source string,
    /// it creates an expression that calls the `ip` constructor.
    pub fn new_ip(src: impl AsRef<str>) -> Self {
        let src_expr = ast::RestrictedExpr::val(src.as_ref());
        Self(ast::RestrictedExpr::call_extension_fn(
            ip_extension_name(),
            [src_expr],
        ))
    }

    /// Create an expression representing a fixed precision decimal number.
    /// This function does not perform error checking on the source string,
    /// it creates an expression that calls the `decimal` constructor.
    pub fn new_decimal(src: impl AsRef<str>) -> Self {
        let src_expr = ast::RestrictedExpr::val(src.as_ref());
        Self(ast::RestrictedExpr::call_extension_fn(
            decimal_extension_name(),
            [src_expr],
        ))
    }

    /// Create an expression representing a particular instant of time.
    /// This function does not perform error checking on the source string,
    /// it creates an expression that calls the `datetime` constructor.
    pub fn new_datetime(src: impl AsRef<str>) -> Self {
        let src_expr = ast::RestrictedExpr::val(src.as_ref());
        Self(ast::RestrictedExpr::call_extension_fn(
            datetime_extension_name(),
            [src_expr],
        ))
    }

    /// Create an expression representing a duration of time.
    /// This function does not perform error checking on the source string,
    /// it creates an expression that calls the `datetime` constructor.
    pub fn new_duration(src: impl AsRef<str>) -> Self {
        let src_expr = ast::RestrictedExpr::val(src.as_ref());
        Self(ast::RestrictedExpr::call_extension_fn(
            duration_extension_name(),
            [src_expr],
        ))
    }

    /// Create an unknown expression
    #[cfg(feature = "partial-eval")]
    pub fn new_unknown(name: impl AsRef<str>) -> Self {
        Self(ast::RestrictedExpr::unknown(ast::Unknown::new_untyped(
            name.as_ref(),
        )))
    }
}

#[cfg(test)]
impl RestrictedExpression {
    /// Deconstruct an [`RestrictedExpression`] to get the internal type.
    /// This function is only intended to be used internally.
    pub(crate) fn into_inner(self) -> ast::RestrictedExpr {
        self.0
    }
}

fn decimal_extension_name() -> ast::Name {
    // PANIC SAFETY: This is a constant and is known to be safe, verified by a test
    #[allow(clippy::unwrap_used)]
    ast::Name::unqualified_name("decimal".parse().unwrap())
}

fn ip_extension_name() -> ast::Name {
    // PANIC SAFETY: This is a constant and is known to be safe, verified by a test
    #[allow(clippy::unwrap_used)]
    ast::Name::unqualified_name("ip".parse().unwrap())
}

fn datetime_extension_name() -> ast::Name {
    // PANIC SAFETY: This is a constant and is known to be safe, verified by a test
    #[allow(clippy::unwrap_used)]
    ast::Name::unqualified_name("datetime".parse().unwrap())
}

fn duration_extension_name() -> ast::Name {
    // PANIC SAFETY: This is a constant and is known to be safe, verified by a test
    #[allow(clippy::unwrap_used)]
    ast::Name::unqualified_name("duration".parse().unwrap())
}

impl FromStr for RestrictedExpression {
    type Err = RestrictedExpressionParseError;

    /// create a `RestrictedExpression` using Cedar syntax
    fn from_str(expression: &str) -> Result<Self, Self::Err> {
        ast::RestrictedExpr::from_str(expression)
            .map(RestrictedExpression)
            .map_err(Into::into)
    }
}

/// Builder for a [`Request`]
///
/// The default for principal, action, resource, and context fields is Unknown
/// for partial evaluation.
#[doc = include_str!("../experimental_warning.md")]
#[cfg(feature = "partial-eval")]
#[derive(Debug, Clone)]
pub struct RequestBuilder<S> {
    principal: ast::EntityUIDEntry,
    action: ast::EntityUIDEntry,
    resource: ast::EntityUIDEntry,
    /// Here, `None` means unknown
    context: Option<ast::Context>,
    schema: S,
}

/// A marker type that indicates [`Schema`] is not set for a request
#[doc = include_str!("../experimental_warning.md")]
#[cfg(feature = "partial-eval")]
#[derive(Debug, Clone, Copy)]
pub struct UnsetSchema;

#[cfg(feature = "partial-eval")]
impl Default for RequestBuilder<UnsetSchema> {
    fn default() -> Self {
        Self {
            principal: ast::EntityUIDEntry::unknown(),
            action: ast::EntityUIDEntry::unknown(),
            resource: ast::EntityUIDEntry::unknown(),
            context: None,
            schema: UnsetSchema,
        }
    }
}

#[cfg(feature = "partial-eval")]
impl<S> RequestBuilder<S> {
    /// Set the principal.
    ///
    /// Note that you can create the `EntityUid` using `.parse()` on any
    /// string (via the `FromStr` implementation for `EntityUid`).
    #[must_use]
    pub fn principal(self, principal: EntityUid) -> Self {
        Self {
            principal: ast::EntityUIDEntry::known(principal.into(), None),
            ..self
        }
    }

    /// Set the principal to be unknown, but known to belong to a certain entity type.
    ///
    /// This information is taken into account when evaluating 'is', '==' and '!=' expressions.
    #[must_use]
    pub fn unknown_principal_with_type(self, principal_type: EntityTypeName) -> Self {
        Self {
            principal: ast::EntityUIDEntry::unknown_with_type(principal_type.0, None),
            ..self
        }
    }

    /// Set the action.
    ///
    /// Note that you can create the `EntityUid` using `.parse()` on any
    /// string (via the `FromStr` implementation for `EntityUid`).
    #[must_use]
    pub fn action(self, action: EntityUid) -> Self {
        Self {
            action: ast::EntityUIDEntry::known(action.into(), None),
            ..self
        }
    }

    /// Set the resource.
    ///
    /// Note that you can create the `EntityUid` using `.parse()` on any
    /// string (via the `FromStr` implementation for `EntityUid`).
    #[must_use]
    pub fn resource(self, resource: EntityUid) -> Self {
        Self {
            resource: ast::EntityUIDEntry::known(resource.into(), None),
            ..self
        }
    }

    /// Set the resource to be unknown, but known to belong to a certain entity type.
    ///
    /// This information is taken into account when evaluating 'is', '==' and '!=' expressions.
    #[must_use]
    pub fn unknown_resource_with_type(self, resource_type: EntityTypeName) -> Self {
        Self {
            resource: ast::EntityUIDEntry::unknown_with_type(resource_type.0, None),
            ..self
        }
    }

    /// Set the context.
    #[must_use]
    pub fn context(self, context: Context) -> Self {
        Self {
            context: Some(context.0),
            ..self
        }
    }
}

#[cfg(feature = "partial-eval")]
impl RequestBuilder<UnsetSchema> {
    /// Set the schema. If present, this will be used for request validation.
    #[must_use]
    pub fn schema(self, schema: &Schema) -> RequestBuilder<&Schema> {
        RequestBuilder {
            principal: self.principal,
            action: self.action,
            resource: self.resource,
            context: self.context,
            schema,
        }
    }

    /// Create the [`Request`]
    pub fn build(self) -> Request {
        Request(ast::Request::new_unchecked(
            self.principal,
            self.action,
            self.resource,
            self.context,
        ))
    }
}

#[cfg(feature = "partial-eval")]
impl RequestBuilder<&Schema> {
    /// Create the [`Request`]
    pub fn build(self) -> Result<Request, RequestValidationError> {
        Ok(Request(ast::Request::new_with_unknowns(
            self.principal,
            self.action,
            self.resource,
            self.context,
            Some(&self.schema.0),
            Extensions::all_available(),
        )?))
    }
}

/// An authorization request is a tuple `<P, A, R, C>` where
/// * P is the principal [`EntityUid`],
/// * A is the action [`EntityUid`],
/// * R is the resource [`EntityUid`], and
/// * C is the request [`Context`] record.
///
/// It represents an authorization request asking the question, "Can this
/// principal take this action on this resource in this context?"
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct Request(pub(crate) ast::Request);

#[doc(hidden)] // because this converts to a private/internal type
impl AsRef<ast::Request> for Request {
    fn as_ref(&self) -> &ast::Request {
        &self.0
    }
}

#[doc(hidden)]
impl From<ast::Request> for Request {
    fn from(req: ast::Request) -> Self {
        Self(req)
    }
}

impl Request {
    /// Create a [`RequestBuilder`]
    #[doc = include_str!("../experimental_warning.md")]
    #[cfg(feature = "partial-eval")]
    pub fn builder() -> RequestBuilder<UnsetSchema> {
        RequestBuilder::default()
    }

    /// Create a Request.
    ///
    /// Note that you can create the `EntityUid`s using `.parse()` on any
    /// string (via the `FromStr` implementation for `EntityUid`).
    /// The principal, action, and resource fields are optional to support
    /// the case where these fields do not contribute to authorization
    /// decisions (e.g., because they are not used in your policies).
    /// If any of the fields are `None`, we will automatically generate
    /// a unique entity UID that is not equal to any UID in the store.
    ///
    /// If `schema` is present, this constructor will validate that the
    /// `Request` complies with the given `schema`.
    pub fn new(
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Context,
        schema: Option<&Schema>,
    ) -> Result<Self, RequestValidationError> {
        Ok(Self(ast::Request::new(
            (principal.into(), None),
            (action.into(), None),
            (resource.into(), None),
            context.0,
            schema.map(|schema| &schema.0),
            Extensions::all_available(),
        )?))
    }

    /// Get the context component of the request. Returns `None` if the context is
    /// "unknown" (i.e., constructed using the partial evaluation APIs).
    pub fn context(&self) -> Option<&Context> {
        self.0.context().map(Context::ref_cast)
    }

    /// Get the principal component of the request. Returns `None` if the principal is
    /// "unknown" (i.e., constructed using the partial evaluation APIs).
    pub fn principal(&self) -> Option<&EntityUid> {
        match self.0.principal() {
            ast::EntityUIDEntry::Known { euid, .. } => Some(EntityUid::ref_cast(euid.as_ref())),
            ast::EntityUIDEntry::Unknown { .. } => None,
        }
    }

    /// Get the action component of the request. Returns `None` if the action is
    /// "unknown" (i.e., constructed using the partial evaluation APIs).
    pub fn action(&self) -> Option<&EntityUid> {
        match self.0.action() {
            ast::EntityUIDEntry::Known { euid, .. } => Some(EntityUid::ref_cast(euid.as_ref())),
            ast::EntityUIDEntry::Unknown { .. } => None,
        }
    }

    /// Get the resource component of the request. Returns `None` if the resource is
    /// "unknown" (i.e., constructed using the partial evaluation APIs).
    pub fn resource(&self) -> Option<&EntityUid> {
        match self.0.resource() {
            ast::EntityUIDEntry::Known { euid, .. } => Some(EntityUid::ref_cast(euid.as_ref())),
            ast::EntityUIDEntry::Unknown { .. } => None,
        }
    }
}

/// the Context object for an authorization request
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct Context(ast::Context);

#[doc(hidden)] // because this converts to a private/internal type
impl AsRef<ast::Context> for Context {
    fn as_ref(&self) -> &ast::Context {
        &self.0
    }
}

impl Context {
    /// Create an empty `Context`
    /// ```
    /// # use cedar_policy::Context;
    /// let context = Context::empty();
    /// ```
    pub fn empty() -> Self {
        Self(ast::Context::empty())
    }

    /// Create a `Context` from a map of key to "restricted expression",
    /// or a Vec of `(key, restricted expression)` pairs, or any other iterator
    /// of `(key, restricted expression)` pairs.
    /// ```
    /// # use cedar_policy::{Context, EntityUid, RestrictedExpression, Request};
    /// # use std::str::FromStr;
    /// let context = Context::from_pairs([
    ///   ("key".to_string(), RestrictedExpression::from_str(r#""value""#).unwrap()),
    ///   ("age".to_string(), RestrictedExpression::from_str("18").unwrap()),
    /// ]).unwrap();
    /// # // create a request
    /// # let p = EntityUid::from_str(r#"User::"alice""#).unwrap();
    /// # let a = EntityUid::from_str(r#"Action::"view""#).unwrap();
    /// # let r = EntityUid::from_str(r#"Album::"trip""#).unwrap();
    /// # let request: Request = Request::new(p, a, r, context, None).unwrap();
    /// ```
    pub fn from_pairs(
        pairs: impl IntoIterator<Item = (String, RestrictedExpression)>,
    ) -> Result<Self, ContextCreationError> {
        Ok(Self(ast::Context::from_pairs(
            pairs.into_iter().map(|(k, v)| (SmolStr::from(k), v.0)),
            Extensions::all_available(),
        )?))
    }

    /// Retrieves a value from the Context by its key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to look up in the context
    ///
    /// # Returns
    ///
    /// * `Some(EvalResult)` - If the key exists in the context, returns its value
    /// * `None` - If the key doesn't exist or if the context is not a Value type
    ///
    /// # Examples
    ///
    /// ```
    /// # use cedar_policy::{Context, Request, EntityUid};
    /// # use std::str::FromStr;
    /// let context = Context::from_json_str(r#"{"rayId": "abc123"}"#, None).unwrap();
    /// if let Some(value) = context.get("rayId") {
    ///     // value here is an EvalResult, convertible from the internal Value type
    ///     println!("Found value: {:?}", value);
    /// }
    /// assert_eq!(context.get("nonexistent"), None);
    /// ```
    pub fn get(&self, key: &str) -> Option<EvalResult> {
        match &self.0 {
            ast::Context::Value(map) => map.get(key).map(|v| EvalResult::from(v.clone())),
            ast::Context::RestrictedResidual(_) => None,
        }
    }

    /// Create a `Context` from a string containing JSON (which must be a JSON
    /// object, not any other JSON type, or you will get an error here).
    /// JSON here must use the `__entity` and `__extn` escapes for entity
    /// references, extension values, etc.
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit, and it will error
    /// if attributes have the wrong types (e.g., string instead of integer).
    /// Since different Actions have different schemas for `Context`, you also
    /// must specify the `Action` for schema-based parsing.
    /// ```
    /// # use cedar_policy::{Context, EntityUid, RestrictedExpression, Request};
    /// # use std::str::FromStr;
    /// let json_data = r#"{
    ///     "sub": "1234",
    ///     "groups": {
    ///         "1234": {
    ///             "group_id": "abcd",
    ///             "group_name": "test-group"
    ///         }
    ///     }
    /// }"#;
    /// let context = Context::from_json_str(json_data, None).unwrap();
    /// # // create a request
    /// # let p = EntityUid::from_str(r#"User::"alice""#).unwrap();
    /// # let a = EntityUid::from_str(r#"Action::"view""#).unwrap();
    /// # let r = EntityUid::from_str(r#"Album::"trip""#).unwrap();
    /// # let request: Request = Request::new(p, a, r, context, None).unwrap();
    /// ```
    pub fn from_json_str(
        json: &str,
        schema: Option<(&Schema, &EntityUid)>,
    ) -> Result<Self, ContextJsonError> {
        let schema = schema
            .map(|(s, uid)| Self::get_context_schema(s, uid))
            .transpose()?;
        let context = cedar_policy_core::entities::ContextJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
        )
        .from_json_str(json)?;
        Ok(Self(context))
    }

    /// Create a `Context` from a `serde_json::Value` (which must be a JSON object,
    /// not any other JSON type, or you will get an error here).
    /// JSON here must use the `__entity` and `__extn` escapes for entity
    /// references, extension values, etc.
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit, and it will error
    /// if attributes have the wrong types (e.g., string instead of integer).
    /// Since different Actions have different schemas for `Context`, you also
    /// must specify the `Action` for schema-based parsing.
    /// ```
    /// # use cedar_policy::{Context, EntityUid, EntityId, EntityTypeName, RestrictedExpression, Request, Schema};
    /// # use std::str::FromStr;
    /// let schema_json = serde_json::json!(
    ///     {
    ///       "": {
    ///         "entityTypes": {
    ///           "User": {},
    ///           "Album": {},
    ///         },
    ///         "actions": {
    ///           "view": {
    ///              "appliesTo": {
    ///                "principalTypes": ["User"],
    ///                "resourceTypes": ["Album"],
    ///                "context": {
    ///                  "type": "Record",
    ///                  "attributes": {
    ///                    "sub": { "type": "Long" }
    ///                  }
    ///                }
    ///              }
    ///           }
    ///         }
    ///       }
    ///     });
    /// let schema = Schema::from_json_value(schema_json).unwrap();
    ///
    /// let a_eid = EntityId::from_str("view").unwrap();
    /// let a_name: EntityTypeName = EntityTypeName::from_str("Action").unwrap();
    /// let action = EntityUid::from_type_name_and_id(a_name, a_eid);
    /// let data = serde_json::json!({
    ///     "sub": 1234
    /// });
    /// let context = Context::from_json_value(data, Some((&schema, &action))).unwrap();
    /// # let p = EntityUid::from_str(r#"User::"alice""#).unwrap();
    /// # let r = EntityUid::from_str(r#"Album::"trip""#).unwrap();
    /// # let request: Request = Request::new(p, action, r, context, Some(&schema)).unwrap();
    /// ```
    pub fn from_json_value(
        json: serde_json::Value,
        schema: Option<(&Schema, &EntityUid)>,
    ) -> Result<Self, ContextJsonError> {
        let schema = schema
            .map(|(s, uid)| Self::get_context_schema(s, uid))
            .transpose()?;
        let context = cedar_policy_core::entities::ContextJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
        )
        .from_json_value(json)?;
        Ok(Self(context))
    }

    /// Create a `Context` from a JSON file.  The JSON file must contain a JSON
    /// object, not any other JSON type, or you will get an error here.
    /// JSON here must use the `__entity` and `__extn` escapes for entity
    /// references, extension values, etc.
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit, and it will error
    /// if attributes have the wrong types (e.g., string instead of integer).
    /// Since different Actions have different schemas for `Context`, you also
    /// must specify the `Action` for schema-based parsing.
    /// ```no_run
    /// # use cedar_policy::{Context, RestrictedExpression};
    /// # use cedar_policy::{Entities, EntityId, EntityTypeName, EntityUid, Request,PolicySet};
    /// # use std::collections::HashMap;
    /// # use std::str::FromStr;
    /// # use std::fs::File;
    /// let mut json = File::open("json_file.json").unwrap();
    /// let context = Context::from_json_file(&json, None).unwrap();
    /// # // create a request
    /// # let p_eid = EntityId::from_str("alice").unwrap();
    /// # let p_name: EntityTypeName = EntityTypeName::from_str("User").unwrap();
    /// # let p = EntityUid::from_type_name_and_id(p_name, p_eid);
    /// #
    /// # let a_eid = EntityId::from_str("view").unwrap();
    /// # let a_name: EntityTypeName = EntityTypeName::from_str("Action").unwrap();
    /// # let a = EntityUid::from_type_name_and_id(a_name, a_eid);
    /// # let r_eid = EntityId::from_str("trip").unwrap();
    /// # let r_name: EntityTypeName = EntityTypeName::from_str("Album").unwrap();
    /// # let r = EntityUid::from_type_name_and_id(r_name, r_eid);
    /// # let request: Request = Request::new(p, a, r, context, None).unwrap();
    /// ```
    pub fn from_json_file(
        json: impl std::io::Read,
        schema: Option<(&Schema, &EntityUid)>,
    ) -> Result<Self, ContextJsonError> {
        let schema = schema
            .map(|(s, uid)| Self::get_context_schema(s, uid))
            .transpose()?;
        let context = cedar_policy_core::entities::ContextJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
        )
        .from_json_file(json)?;
        Ok(Self(context))
    }

    /// Internal helper function to convert `(&Schema, &EntityUid)` to `impl ContextSchema`
    fn get_context_schema(
        schema: &Schema,
        action: &EntityUid,
    ) -> Result<impl ContextSchema, ContextJsonError> {
        cedar_policy_core::validator::context_schema_for_action(&schema.0, action.as_ref())
            .ok_or_else(|| ContextJsonError::missing_action(action.clone()))
    }

    /// Merge this [`Context`] with another context (or iterator over
    /// `(String, RestrictedExpression)` pairs), returning an error if the two
    /// contain overlapping keys
    pub fn merge(
        self,
        other_context: impl IntoIterator<Item = (String, RestrictedExpression)>,
    ) -> Result<Self, ContextCreationError> {
        Self::from_pairs(self.into_iter().chain(other_context))
    }

    /// Validates this context against the provided schema
    ///
    /// Returns Ok(()) if the context is valid according to the schema, or an error otherwise
    ///
    /// This validation is already handled by `Request::new`, so there is no need to separately call
    /// if you are validating the whole request
    pub fn validate(
        &self,
        schema: &crate::Schema,
        action: &EntityUid,
    ) -> std::result::Result<(), RequestValidationError> {
        // Call the validate_context function from coreschema.rs
        Ok(RequestSchema::validate_context(
            &schema.0,
            &self.0,
            action.as_ref(),
            Extensions::all_available(),
        )?)
    }
}

/// Utilities for implementing `IntoIterator` for `Context`
mod context {
    use super::{ast, RestrictedExpression};

    /// `IntoIter` iterator for `Context`
    #[derive(Debug)]
    pub struct IntoIter {
        pub(super) inner: <ast::Context as IntoIterator>::IntoIter,
    }

    impl Iterator for IntoIter {
        type Item = (String, RestrictedExpression);

        fn next(&mut self) -> Option<Self::Item> {
            self.inner
                .next()
                .map(|(k, v)| (k.to_string(), RestrictedExpression(v)))
        }
    }
}

impl IntoIterator for Context {
    type Item = (String, RestrictedExpression);

    type IntoIter = context::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter {
            inner: self.0.into_iter(),
        }
    }
}

#[doc(hidden)]
impl From<ast::Context> for Context {
    fn from(c: ast::Context) -> Self {
        Self(c)
    }
}

impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Result of Evaluation
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvalResult {
    /// Boolean value
    Bool(bool),
    /// Signed integer value
    Long(ast::Integer),
    /// String value
    String(String),
    /// Entity Uid
    EntityUid(EntityUid),
    /// A first-class set
    Set(Set),
    /// A first-class anonymous record
    Record(Record),
    /// An extension value, currently limited to String results
    ExtensionValue(String),
    // ExtensionValue(std::sync::Arc<dyn InternalExtensionValue>),
}

/// Sets of Cedar values
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct Set(BTreeSet<EvalResult>);

impl Set {
    /// Iterate over the members of the set
    pub fn iter(&self) -> impl Iterator<Item = &EvalResult> {
        self.0.iter()
    }

    /// Is a given element in the set
    pub fn contains(&self, elem: &EvalResult) -> bool {
        self.0.contains(elem)
    }

    /// Get the number of members of the set
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Test if the set is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A record of Cedar values
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct Record(BTreeMap<String, EvalResult>);

impl Record {
    /// Iterate over the attribute/value pairs in the record
    pub fn iter(&self) -> impl Iterator<Item = (&String, &EvalResult)> {
        self.0.iter()
    }

    /// Check if a given attribute is in the record
    pub fn contains_attribute(&self, key: impl AsRef<str>) -> bool {
        self.0.contains_key(key.as_ref())
    }

    /// Get a given attribute from the record
    pub fn get(&self, key: impl AsRef<str>) -> Option<&EvalResult> {
        self.0.get(key.as_ref())
    }

    /// Get the number of attributes in the record
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Test if the record is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[doc(hidden)]
impl From<ast::Value> for EvalResult {
    fn from(v: ast::Value) -> Self {
        match v.value {
            ast::ValueKind::Lit(ast::Literal::Bool(b)) => Self::Bool(b),
            ast::ValueKind::Lit(ast::Literal::Long(i)) => Self::Long(i),
            ast::ValueKind::Lit(ast::Literal::String(s)) => Self::String(s.to_string()),
            ast::ValueKind::Lit(ast::Literal::EntityUID(e)) => {
                Self::EntityUid(ast::EntityUID::clone(&e).into())
            }
            ast::ValueKind::Set(set) => Self::Set(Set(set
                .authoritative
                .iter()
                .map(|v| v.clone().into())
                .collect())),
            ast::ValueKind::Record(record) => Self::Record(Record(
                record
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.clone().into()))
                    .collect(),
            )),
            ast::ValueKind::ExtensionValue(ev) => {
                Self::ExtensionValue(RestrictedExpr::from(ev.as_ref().clone()).to_string())
            }
        }
    }
}
impl std::fmt::Display for EvalResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(b) => write!(f, "{b}"),
            Self::Long(l) => write!(f, "{l}"),
            Self::String(s) => write!(f, "\"{}\"", s.escape_debug()),
            Self::EntityUid(uid) => write!(f, "{uid}"),
            Self::Set(s) => {
                write!(f, "[")?;
                for (i, ev) in s.iter().enumerate() {
                    write!(f, "{ev}")?;
                    if (i + 1) < s.len() {
                        write!(f, ", ")?;
                    }
                }
                write!(f, "]")?;
                Ok(())
            }
            Self::Record(r) => {
                write!(f, "{{")?;
                for (i, (k, v)) in r.iter().enumerate() {
                    write!(f, "\"{}\": {v}", k.escape_debug())?;
                    if (i + 1) < r.len() {
                        write!(f, ", ")?;
                    }
                }
                write!(f, "}}")?;
                Ok(())
            }
            Self::ExtensionValue(s) => write!(f, "{s}"),
        }
    }
}

/// Evaluates an expression.
///
/// If evaluation results in an error (e.g., attempting to access a non-existent Entity or Record,
/// passing the wrong number of arguments to a function etc.), that error is returned as a String
pub fn eval_expression(
    request: &Request,
    entities: &Entities,
    expr: &Expression,
) -> Result<EvalResult, EvaluationError> {
    let all_ext = Extensions::all_available();
    let eval = Evaluator::new(request.0.clone(), &entities.0, all_ext);
    Ok(EvalResult::from(
        // Evaluate under the empty slot map, as an expression should not have slots
        eval.interpret(&expr.0, &ast::SlotEnv::new())?,
    ))
}

// These are the same tests in validator, just ensuring all the plumbing is done correctly
#[cfg(test)]
mod test_access {
    use cedar_policy_core::{ast, parser::AsLocRef};

    use super::*;

    fn schema() -> Schema {
        let src = r#"
        type Task = {
    "id": Long,
    "name": String,
    "state": String,
};

type T = String;

type Tasks = Set<Task>;
entity List in [Application] = {
  "editors": Team,
  "name": String,
  "owner": User,
  "readers": Team,
  "tasks": Tasks,
};
entity Application;
entity User in [Team, Application] = {
  "joblevel": Long,
  "location": String,
};

entity CoolList;

entity Team in [Team, Application];

action Read, Write, Create;

action DeleteList, EditShare, UpdateList, CreateTask, UpdateTask, DeleteTask in Write appliesTo {
    principal: [User],
    resource : [List]
};

action GetList in Read appliesTo {
    principal : [User],
    resource : [List, CoolList]
};

action GetLists in Read appliesTo {
    principal : [User],
    resource : [Application]
};

action CreateList in Create appliesTo {
    principal : [User],
    resource : [Application]
};

        "#;

        src.parse().unwrap()
    }

    #[test]
    fn principals() {
        let schema = schema();
        let principals = schema.principals().collect::<HashSet<_>>();
        assert_eq!(principals.len(), 1);
        let user: EntityTypeName = "User".parse().unwrap();
        assert!(principals.contains(&user));
        let principals = schema.principals().collect::<Vec<_>>();
        assert!(principals.len() > 1);
        assert!(principals.iter().all(|ety| **ety == user));
        assert!(principals.iter().all(|ety| ety.0.loc().is_some()));

        let et = ast::EntityType::EntityType(ast::Name::from_normalized_str("User").unwrap());
        let et = schema.0.get_entity_type(&et).unwrap();
        assert!(et.loc.as_loc_ref().is_some());
    }

    #[cfg(feature = "extended-schema")]
    #[test]
    fn common_types_extended() {
        use cool_asserts::assert_matches;

        use cedar_policy_core::validator::{
            types::{EntityRecordKind, Type},
            ValidatorCommonType,
        };

        let schema = schema();
        assert_eq!(schema.0.common_types().collect::<HashSet<_>>().len(), 3);
        let task_type = ValidatorCommonType {
            name: "Task".into(),
            name_loc: None,
            type_loc: None,
        };
        assert!(schema.0.common_types().contains(&task_type));

        let tasks_type = ValidatorCommonType {
            name: "Tasks".into(),
            name_loc: None,
            type_loc: None,
        };
        assert!(schema.0.common_types().contains(&tasks_type));
        assert!(schema.0.common_types().all(|ct| ct.name_loc.is_some()));
        assert!(schema.0.common_types().all(|ct| ct.type_loc.is_some()));

        let tasks_type = ValidatorCommonType {
            name: "T".into(),
            name_loc: None,
            type_loc: None,
        };
        assert!(schema.0.common_types().contains(&tasks_type));

        let et = ast::EntityType::EntityType(ast::Name::from_normalized_str("List").unwrap());
        let et = schema.0.get_entity_type(&et).unwrap();
        let attrs = et.attributes();

        // Assert that attributes that are resolved from common types still get source locations
        let t = attrs.get_attr("tasks").unwrap();
        assert!(t.loc.is_some());
        assert_matches!(&t.attr_type, cedar_policy_core::validator::types::Type::Set { ref element_type } => {
            let el = *element_type.clone().unwrap();
            assert_matches!(el, Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => {
                assert!(attrs.get_attr("name").unwrap().loc.is_some());
                assert!(attrs.get_attr("id").unwrap().loc.is_some());
                assert!(attrs.get_attr("state").unwrap().loc.is_some());
            });
        });
    }

    #[cfg(feature = "extended-schema")]
    #[test]
    fn namespace_extended() {
        let schema = schema();
        assert_eq!(schema.0.namespaces().collect::<HashSet<_>>().len(), 1);
        let default_namespace = schema.0.namespaces().last().unwrap();
        assert_eq!(default_namespace.name, SmolStr::from("__cedar"));
        assert!(default_namespace.name_loc.is_none());
        assert!(default_namespace.def_loc.is_none());
    }

    #[test]
    fn empty_schema_principals_and_resources() {
        let empty: Schema = "".parse().unwrap();
        assert!(empty.principals().next().is_none());
        assert!(empty.resources().next().is_none());
    }

    #[test]
    fn resources() {
        let schema = schema();
        let resources = schema.resources().cloned().collect::<HashSet<_>>();
        let expected: HashSet<EntityTypeName> = HashSet::from([
            "List".parse().unwrap(),
            "Application".parse().unwrap(),
            "CoolList".parse().unwrap(),
        ]);
        assert_eq!(resources, expected);
        assert!(resources.iter().all(|ety| ety.0.loc().is_some()));
    }

    #[test]
    fn principals_for_action() {
        let schema = schema();
        let delete_list: EntityUid = r#"Action::"DeleteList""#.parse().unwrap();
        let delete_user: EntityUid = r#"Action::"DeleteUser""#.parse().unwrap();
        let got = schema
            .principals_for_action(&delete_list)
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(got, vec!["User".parse().unwrap()]);
        assert!(got.iter().all(|ety| ety.0.loc().is_some()));
        assert!(schema.principals_for_action(&delete_user).is_none());
    }

    #[test]
    fn resources_for_action() {
        let schema = schema();
        let delete_list: EntityUid = r#"Action::"DeleteList""#.parse().unwrap();
        let delete_user: EntityUid = r#"Action::"DeleteUser""#.parse().unwrap();
        let create_list: EntityUid = r#"Action::"CreateList""#.parse().unwrap();
        let get_list: EntityUid = r#"Action::"GetList""#.parse().unwrap();
        let got = schema
            .resources_for_action(&delete_list)
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(got, vec!["List".parse().unwrap()]);
        assert!(got.iter().all(|ety| ety.0.loc().is_some()));
        let got = schema
            .resources_for_action(&create_list)
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(got, vec!["Application".parse().unwrap()]);
        assert!(got.iter().all(|ety| ety.0.loc().is_some()));
        let got = schema
            .resources_for_action(&get_list)
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(
            got,
            HashSet::from(["List".parse().unwrap(), "CoolList".parse().unwrap()])
        );
        assert!(got.iter().all(|ety| ety.0.loc().is_some()));
        assert!(schema.principals_for_action(&delete_user).is_none());
    }

    #[test]
    fn principal_parents() {
        let schema = schema();
        let user: EntityTypeName = "User".parse().unwrap();
        let parents = schema
            .ancestors(&user)
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        assert!(parents.iter().all(|ety| ety.0.loc().is_some()));
        let expected = HashSet::from(["Team".parse().unwrap(), "Application".parse().unwrap()]);
        assert_eq!(parents, expected);
        let parents = schema
            .ancestors(&"List".parse().unwrap())
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        assert!(parents.iter().all(|ety| ety.0.loc().is_some()));
        let expected = HashSet::from(["Application".parse().unwrap()]);
        assert_eq!(parents, expected);
        assert!(schema.ancestors(&"Foo".parse().unwrap()).is_none());
        let parents = schema
            .ancestors(&"CoolList".parse().unwrap())
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        assert!(parents.iter().all(|ety| ety.0.loc().is_some()));
        let expected = HashSet::from([]);
        assert_eq!(parents, expected);
    }

    #[test]
    fn action_groups() {
        let schema = schema();
        let groups = schema.action_groups().cloned().collect::<HashSet<_>>();
        let expected = ["Read", "Write", "Create"]
            .into_iter()
            .map(|ty| format!("Action::\"{ty}\"").parse().unwrap())
            .collect::<HashSet<EntityUid>>();
        #[cfg(feature = "extended-schema")]
        assert!(groups.iter().all(|ety| ety.0.loc().is_some()));
        assert_eq!(groups, expected);
    }

    #[test]
    fn actions() {
        let schema = schema();
        let actions = schema.actions().cloned().collect::<HashSet<_>>();
        let expected = [
            "Read",
            "Write",
            "Create",
            "DeleteList",
            "EditShare",
            "UpdateList",
            "CreateTask",
            "UpdateTask",
            "DeleteTask",
            "GetList",
            "GetLists",
            "CreateList",
        ]
        .into_iter()
        .map(|ty| format!("Action::\"{ty}\"").parse().unwrap())
        .collect::<HashSet<EntityUid>>();
        assert_eq!(actions, expected);
        #[cfg(feature = "extended-schema")]
        assert!(actions.iter().all(|ety| ety.0.loc().is_some()));
    }

    #[test]
    fn entities() {
        let schema = schema();
        let entities = schema.entity_types().cloned().collect::<HashSet<_>>();
        let expected = ["List", "Application", "User", "CoolList", "Team"]
            .into_iter()
            .map(|ty| ty.parse().unwrap())
            .collect::<HashSet<EntityTypeName>>();
        assert_eq!(entities, expected);
    }
}

#[cfg(test)]
mod test_access_namespace {
    use super::*;

    fn schema() -> Schema {
        let src = r#"
        namespace Foo {
        type Task = {
    "id": Long,
    "name": String,
    "state": String,
};

type Tasks = Set<Task>;
entity List in [Application] = {
  "editors": Team,
  "name": String,
  "owner": User,
  "readers": Team,
  "tasks": Tasks,
};
entity Application;
entity User in [Team, Application] = {
  "joblevel": Long,
  "location": String,
};

entity CoolList;

entity Team in [Team, Application];

action Read, Write, Create;

action DeleteList, EditShare, UpdateList, CreateTask, UpdateTask, DeleteTask in Write appliesTo {
    principal: [User],
    resource : [List]
};

action GetList in Read appliesTo {
    principal : [User],
    resource : [List, CoolList]
};

action GetLists in Read appliesTo {
    principal : [User],
    resource : [Application]
};

action CreateList in Create appliesTo {
    principal : [User],
    resource : [Application]
};
    }

        "#;

        src.parse().unwrap()
    }

    #[test]
    fn principals() {
        let schema = schema();
        let principals = schema.principals().collect::<HashSet<_>>();
        assert_eq!(principals.len(), 1);
        let user: EntityTypeName = "Foo::User".parse().unwrap();
        assert!(principals.contains(&user));
        let principals = schema.principals().collect::<Vec<_>>();
        assert!(principals.len() > 1);
        assert!(principals.iter().all(|ety| **ety == user));
        assert!(principals.iter().all(|ety| ety.0.loc().is_some()));
    }

    #[test]
    fn empty_schema_principals_and_resources() {
        let empty: Schema = "".parse().unwrap();
        assert!(empty.principals().next().is_none());
        assert!(empty.resources().next().is_none());
    }

    #[test]
    fn resources() {
        let schema = schema();
        let resources = schema.resources().cloned().collect::<HashSet<_>>();
        let expected: HashSet<EntityTypeName> = HashSet::from([
            "Foo::List".parse().unwrap(),
            "Foo::Application".parse().unwrap(),
            "Foo::CoolList".parse().unwrap(),
        ]);
        assert_eq!(resources, expected);
        assert!(resources.iter().all(|ety| ety.0.loc().is_some()));
    }

    #[test]
    fn principals_for_action() {
        let schema = schema();
        let delete_list: EntityUid = r#"Foo::Action::"DeleteList""#.parse().unwrap();
        let delete_user: EntityUid = r#"Foo::Action::"DeleteUser""#.parse().unwrap();
        let got = schema
            .principals_for_action(&delete_list)
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(got, vec!["Foo::User".parse().unwrap()]);
        assert!(schema.principals_for_action(&delete_user).is_none());
    }

    #[test]
    fn resources_for_action() {
        let schema = schema();
        let delete_list: EntityUid = r#"Foo::Action::"DeleteList""#.parse().unwrap();
        let delete_user: EntityUid = r#"Foo::Action::"DeleteUser""#.parse().unwrap();
        let create_list: EntityUid = r#"Foo::Action::"CreateList""#.parse().unwrap();
        let get_list: EntityUid = r#"Foo::Action::"GetList""#.parse().unwrap();
        let got = schema
            .resources_for_action(&delete_list)
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        assert!(got.iter().all(|ety| ety.0.loc().is_some()));

        assert_eq!(got, vec!["Foo::List".parse().unwrap()]);
        let got = schema
            .resources_for_action(&create_list)
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(got, vec!["Foo::Application".parse().unwrap()]);
        assert!(got.iter().all(|ety| ety.0.loc().is_some()));

        let got = schema
            .resources_for_action(&get_list)
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(
            got,
            HashSet::from([
                "Foo::List".parse().unwrap(),
                "Foo::CoolList".parse().unwrap()
            ])
        );
        assert!(schema.principals_for_action(&delete_user).is_none());
    }

    #[test]
    fn principal_parents() {
        let schema = schema();
        let user: EntityTypeName = "Foo::User".parse().unwrap();
        let parents = schema
            .ancestors(&user)
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        let expected = HashSet::from([
            "Foo::Team".parse().unwrap(),
            "Foo::Application".parse().unwrap(),
        ]);
        assert_eq!(parents, expected);
        let parents = schema
            .ancestors(&"Foo::List".parse().unwrap())
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        let expected = HashSet::from(["Foo::Application".parse().unwrap()]);
        assert_eq!(parents, expected);
        assert!(schema.ancestors(&"Foo::Foo".parse().unwrap()).is_none());
        let parents = schema
            .ancestors(&"Foo::CoolList".parse().unwrap())
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        let expected = HashSet::from([]);
        assert_eq!(parents, expected);
    }

    #[test]
    fn action_groups() {
        let schema = schema();
        let groups = schema.action_groups().cloned().collect::<HashSet<_>>();
        let expected = ["Read", "Write", "Create"]
            .into_iter()
            .map(|ty| format!("Foo::Action::\"{ty}\"").parse().unwrap())
            .collect::<HashSet<EntityUid>>();
        assert_eq!(groups, expected);
    }

    #[test]
    fn actions() {
        let schema = schema();
        let actions = schema.actions().cloned().collect::<HashSet<_>>();
        let expected = [
            "Read",
            "Write",
            "Create",
            "DeleteList",
            "EditShare",
            "UpdateList",
            "CreateTask",
            "UpdateTask",
            "DeleteTask",
            "GetList",
            "GetLists",
            "CreateList",
        ]
        .into_iter()
        .map(|ty| format!("Foo::Action::\"{ty}\"").parse().unwrap())
        .collect::<HashSet<EntityUid>>();
        assert_eq!(actions, expected);
    }

    #[test]
    fn entities() {
        let schema = schema();
        let entities = schema.entity_types().cloned().collect::<HashSet<_>>();
        let expected = [
            "Foo::List",
            "Foo::Application",
            "Foo::User",
            "Foo::CoolList",
            "Foo::Team",
        ]
        .into_iter()
        .map(|ty| ty.parse().unwrap())
        .collect::<HashSet<EntityTypeName>>();
        assert_eq!(entities, expected);
    }

    #[test]
    fn test_request_context() {
        // Create a context with some test data
        let context =
            Context::from_json_str(r#"{"testKey": "testValue", "numKey": 42}"#, None).unwrap();

        // Create entity UIDs for the request
        let principal: EntityUid = "User::\"alice\"".parse().unwrap();
        let action: EntityUid = "Action::\"view\"".parse().unwrap();
        let resource: EntityUid = "Resource::\"doc123\"".parse().unwrap();

        // Create the request
        let request = Request::new(
            principal, action, resource, context, None, // no schema validation for this test
        )
        .unwrap();

        // Test context() method
        let retrieved_context = request.context().expect("Context should be present");

        // Test get() method on the retrieved context
        assert!(retrieved_context.get("testKey").is_some());
        assert!(retrieved_context.get("numKey").is_some());
        assert!(retrieved_context.get("nonexistent").is_none());
    }

    #[cfg(feature = "extended-schema")]
    #[test]
    fn namespace_extended() {
        let schema = schema();
        assert_eq!(schema.0.namespaces().collect::<HashSet<_>>().len(), 2);
        let default_namespace = schema
            .0
            .namespaces()
            .filter(|n| n.name == *"__cedar")
            .last()
            .unwrap();
        assert!(default_namespace.name_loc.is_none());
        assert!(default_namespace.def_loc.is_none());

        let default_namespace = schema
            .0
            .namespaces()
            .filter(|n| n.name == *"Foo")
            .last()
            .unwrap();
        assert!(default_namespace.name_loc.is_some());
        assert!(default_namespace.def_loc.is_some());
    }
}

#[cfg(test)]
mod test_lossless_empty {
    use super::{LosslessPolicy, Policy, PolicyId, Template};

    #[test]
    fn test_lossless_empty_policy() {
        const STATIC_POLICY_TEXT: &str = "permit(principal,action,resource);";
        let policy0 = Policy::parse(Some(PolicyId::new("policy0")), STATIC_POLICY_TEXT)
            .expect("Failed to parse");
        let lossy_policy0 = Policy {
            ast: policy0.ast.clone(),
            lossless: LosslessPolicy::policy_or_template_text(None::<&str>),
        };
        // The `to_cedar` representation becomes lossy since we didn't provide text
        assert_eq!(
            lossy_policy0.to_cedar(),
            Some(String::from(
                "permit(\n  principal,\n  action,\n  resource\n) when {\n  true\n};"
            ))
        );
        // The EST representation is obtained from the AST
        let lossy_policy0_est = lossy_policy0
            .lossless
            .est(|| policy0.ast.clone().into())
            .unwrap();
        assert_eq!(lossy_policy0_est, policy0.ast.into());
    }

    #[test]
    fn test_lossless_empty_template() {
        const TEMPLATE_TEXT: &str = "permit(principal == ?principal,action,resource);";
        let template0 = Template::parse(Some(PolicyId::new("template0")), TEMPLATE_TEXT)
            .expect("Failed to parse");
        let lossy_template0 = Template {
            ast: template0.ast.clone(),
            lossless: LosslessPolicy::policy_or_template_text(None::<&str>),
        };
        // The `to_cedar` representation becomes lossy since we didn't provide text
        assert_eq!(
            lossy_template0.to_cedar(),
            String::from(
                "permit(\n  principal == ?principal,\n  action,\n  resource\n) when {\n  true\n};"
            )
        );
        // The EST representation is obtained from the AST
        let lossy_template0_est = lossy_template0
            .lossless
            .est(|| template0.ast.clone().into())
            .unwrap();
        assert_eq!(lossy_template0_est, template0.ast.into());
    }
}

/// Given a schema and policy set, compute an entity manifest.
///
/// The policies must validate against the schema in strict mode,
/// otherwise an error is returned.
/// The manifest describes the data required to answer requests
/// for each action.
#[doc = include_str!("../experimental_warning.md")]
#[cfg(feature = "entity-manifest")]
pub fn compute_entity_manifest(
    validator: &Validator,
    pset: &PolicySet,
) -> Result<EntityManifest, EntityManifestError> {
    entity_manifest::compute_entity_manifest(&validator.0, &pset.ast)
        .map_err(std::convert::Into::into)
}
