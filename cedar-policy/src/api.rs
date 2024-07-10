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
pub use id::*;

mod err;
pub use err::*;

pub use ast::Effect;
pub use authorizer::Decision;
use cedar_policy_core::ast;
#[cfg(feature = "partial-eval")]
use cedar_policy_core::ast::BorrowedRestrictedExpr;
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

/// Entity datatype
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq, RefCast)]
pub struct Entity(ast::Entity);

impl Entity {
    /// Create a new `Entity` with this Uid, attributes, and parents.
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
        // note that we take a "parents" parameter here; we will compute TC when
        // the `Entities` object is created
        Ok(Self(ast::Entity::new(
            uid.into(),
            attrs
                .into_iter()
                .map(|(k, v)| (SmolStr::from(k), v.0))
                .collect(),
            parents.into_iter().map(EntityUid::into).collect(),
            &Extensions::all_available(),
        )?))
    }

    /// Create a new `Entity` with no attributes.
    ///
    /// Unlike [`Entity::new()`], this constructor cannot error.
    /// (The only source of errors in `Entity::new()` are attributes.)
    pub fn new_no_attrs(uid: EntityUid, parents: HashSet<EntityUid>) -> Self {
        // note that we take a "parents" parameter here; we will compute TC when
        // the `Entities` object is created
        Self(ast::Entity::new_with_attr_partial_value(
            uid.into(),
            HashMap::new(),
            parents.into_iter().map(EntityUid::into).collect(),
        ))
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
        let v = match ast::Value::try_from(self.0.get(attr)?.clone()) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        Some(Ok(EvalResult::from(v)))
    }

    /// Consume the entity and return the entity's owned Uid, attributes and parents.
    pub fn into_inner(
        self,
    ) -> (
        EntityUid,
        HashMap<String, RestrictedExpression>,
        HashSet<EntityUid>,
    ) {
        let (uid, attrs, ancestors) = self.0.into_inner();

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
            ancestors.into_iter().map(Into::into).collect(),
        )
    }

    /// Parse an entity from an in-memory JSON value
    /// If a schema is provided, it is handled identically to [`Entities::from_json_str`]
    pub fn from_json_value(
        value: serde_json::Value,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_validator::CoreSchema::new(&s.0));
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
        let schema = schema.map(|s| cedar_policy_validator::CoreSchema::new(&s.0));
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
        let schema = schema.map(|s| cedar_policy_validator::CoreSchema::new(&s.0));
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
    /// attempting to dereference a non-existent `EntityUID` results in
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
    pub fn from_entities(
        entities: impl IntoIterator<Item = Entity>,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        cedar_policy_core::entities::Entities::from_entities(
            entities.into_iter().map(|e| e.0),
            schema
                .map(|s| cedar_policy_validator::CoreSchema::new(&s.0))
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
    pub fn add_entities(
        self,
        entities: impl IntoIterator<Item = Entity>,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        Ok(Self(
            self.0.add_entities(
                entities.into_iter().map(|e| e.0),
                schema
                    .map(|s| cedar_policy_validator::CoreSchema::new(&s.0))
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
    pub fn add_entities_from_json_str(
        self,
        json: &str,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_validator::CoreSchema::new(&s.0));
        let eparser = cedar_policy_core::entities::EntityJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        );
        let new_entities = eparser.iter_from_json_str(json)?;
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
    pub fn add_entities_from_json_value(
        self,
        json: serde_json::Value,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_validator::CoreSchema::new(&s.0));
        let eparser = cedar_policy_core::entities::EntityJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        );
        let new_entities = eparser.iter_from_json_value(json)?;
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
    pub fn add_entities_from_json_file(
        self,
        json: impl std::io::Read,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_validator::CoreSchema::new(&s.0));
        let eparser = cedar_policy_core::entities::EntityJsonParser::new(
            schema.as_ref(),
            Extensions::all_available(),
            cedar_policy_core::entities::TCComputation::ComputeNow,
        );
        let new_entities = eparser.iter_from_json_file(json)?;
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
    /// # assert_eq!(ip, EvalResult::ExtensionValue("10.0.1.101/32".to_string()));
    /// ```
    pub fn from_json_str(json: &str, schema: Option<&Schema>) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_validator::CoreSchema::new(&s.0));
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
    ///   "uid": {"type":"Groupd","id":"admin"},
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
        let schema = schema.map(|s| cedar_policy_validator::CoreSchema::new(&s.0));
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
    pub fn from_json_file(
        json: impl std::io::Read,
        schema: Option<&Schema>,
    ) -> Result<Self, EntitiesError> {
        let schema = schema.map(|s| cedar_policy_validator::CoreSchema::new(&s.0));
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
        self.0.to_dot_str()
    }
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
#[derive(Debug, RefCast)]
pub struct Authorizer(authorizer::Authorizer);

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

    /// Return the residual for a given [`PolicyId`], if it exists in the response
    pub fn get(&self, id: &PolicyId) -> Option<Policy> {
        self.0.get(id.as_ref()).map(Policy::from_ast)
    }

    /// Attempt to re-authorize this response given a mapping from unknowns to values
    pub fn reauthorize(
        &self,
        mapping: HashMap<SmolStr, RestrictedExpression>,
        auth: &Authorizer,
        es: &Entities,
    ) -> Result<Self, ReauthorizationError> {
        let exts = Extensions::all_available();
        let evaluator = RestrictedEvaluator::new(&exts);
        let mapping = mapping
            .into_iter()
            .map(|(name, expr)| {
                evaluator
                    .interpret(BorrowedRestrictedExpr::new_unchecked(expr.0.as_ref()))
                    .map(|v| (name, v))
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
impl From<ValidationMode> for cedar_policy_validator::ValidationMode {
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
#[derive(Debug, RefCast)]
pub struct Validator(cedar_policy_validator::Validator);

impl Validator {
    /// Construct a new `Validator` to validate policies using the given
    /// `Schema`.
    pub fn new(schema: Schema) -> Self {
        Self(cedar_policy_validator::Validator::new(schema.0))
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
}

/// Contains all the type information used to construct a `Schema` that can be
/// used to validate a policy.
#[derive(Debug)]
pub struct SchemaFragment {
    value: cedar_policy_validator::ValidatorSchemaFragment,
    lossless: cedar_policy_validator::SchemaFragment<cedar_policy_validator::RawName>,
}

impl SchemaFragment {
    /// Extract namespaces defined in this `SchemaFragment`. Each namespace
    /// entry defines the name of the namespace and the entity types and actions
    /// that exist in the namespace.
    pub fn namespaces(&self) -> impl Iterator<Item = Option<EntityNamespace>> + '_ {
        self.value
            .namespaces()
            .map(|ns| ns.as_ref().map(|ns| EntityNamespace(ns.clone())))
    }

    /// Create an `SchemaFragment` from a JSON value (which should be an
    /// object of the shape required for Cedar schemas).
    pub fn from_json_value(json: serde_json::Value) -> Result<Self, SchemaError> {
        let lossless = cedar_policy_validator::SchemaFragment::from_json_value(json)?;
        Ok(Self {
            value: lossless.clone().try_into()?,
            lossless,
        })
    }

    /// Parse a [`SchemaFragment`] from a reader containing the natural schema syntax
    pub fn from_file_natural(
        r: impl std::io::Read,
    ) -> Result<(Self, impl Iterator<Item = SchemaWarning>), HumanSchemaError> {
        let (lossless, warnings) = cedar_policy_validator::SchemaFragment::from_file_natural(
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

    /// Parse a [`SchemaFragment`] from a string containing the natural schema syntax
    pub fn from_str_natural(
        src: &str,
    ) -> Result<(Self, impl Iterator<Item = SchemaWarning>), HumanSchemaError> {
        let (lossless, warnings) = cedar_policy_validator::SchemaFragment::from_str_natural(
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

    /// Create a [`SchemaFragment`] directly from a file.
    pub fn from_file(file: impl std::io::Read) -> Result<Self, SchemaError> {
        let lossless = cedar_policy_validator::SchemaFragment::from_file(file)?;
        Ok(Self {
            value: lossless.clone().try_into()?,
            lossless,
        })
    }

    /// Serialize this [`SchemaFragment`] as a json value
    pub fn to_json_value(self) -> Result<serde_json::Value, SchemaError> {
        serde_json::to_value(self.lossless).map_err(|e| SchemaError::JsonSerialization(e.into()))
    }

    /// Serialize this [`SchemaFragment`] as a json value
    pub fn as_json_string(&self) -> Result<String, SchemaError> {
        serde_json::to_string(&self.lossless).map_err(|e| SchemaError::JsonSerialization(e.into()))
    }

    /// Serialize this [`SchemaFragment`] into the natural syntax
    pub fn as_natural(&self) -> Result<String, ToHumanSyntaxError> {
        let str = self.lossless.as_natural_schema()?;
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
            cedar_policy_validator::ValidatorSchema::from_schema_fragments(
                [self.value],
                Extensions::all_available(),
            )?,
        ))
    }
}

impl FromStr for SchemaFragment {
    type Err = SchemaError;
    /// Construct `SchemaFragment` from a string containing a schema formatted
    /// in the cedar schema format. This can fail if the string is not valid
    /// JSON, or if the JSON structure does not form a valid schema. This
    /// function does not check for consistency in the schema (e.g., references
    /// to undefined entities) because this is not required until a `Schema` is
    /// constructed.
    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let lossless = cedar_policy_validator::SchemaFragment::from_json_str(src)?;
        Ok(Self {
            value: lossless.clone().try_into()?,
            lossless,
        })
    }
}

/// Object containing schema information used by the validator.
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct Schema(pub(crate) cedar_policy_validator::ValidatorSchema);

impl FromStr for Schema {
    type Err = SchemaError;

    /// Construct a schema from a string containing a schema formatted in the
    /// Cedar schema format. This can fail if it is not possible to parse a
    /// schema from the strings, or if errors in values in the schema are
    /// uncovered after parsing. For instance, when an entity attribute name is
    /// found to not be a valid attribute name according to the Cedar
    /// grammar.
    fn from_str(schema_src: &str) -> Result<Self, Self::Err> {
        Ok(Self(schema_src.parse()?))
    }
}

impl Schema {
    /// Create a `Schema` from multiple `SchemaFragment`. The individual
    /// fragments may references entity types that are not declared in that
    /// fragment, but all referenced entity types must be declared in some
    /// fragment.
    pub fn from_schema_fragments(
        fragments: impl IntoIterator<Item = SchemaFragment>,
    ) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_validator::ValidatorSchema::from_schema_fragments(
                fragments.into_iter().map(|f| f.value),
                Extensions::all_available(),
            )?,
        ))
    }

    /// Create a `Schema` from a JSON value (which should be an object of the
    /// shape required for Cedar schemas).
    pub fn from_json_value(json: serde_json::Value) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_validator::ValidatorSchema::from_json_value(
                json,
                Extensions::all_available(),
            )?,
        ))
    }

    /// Create a `Schema` from a string containing JSON in the appropriate
    /// shape.
    pub fn from_json_str(json: &str) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_validator::ValidatorSchema::from_json_str(
                json,
                Extensions::all_available(),
            )?,
        ))
    }

    /// Create a `Schema` directly from a file containing JSON in the
    /// appropriate shape.
    pub fn from_file(file: impl std::io::Read) -> Result<Self, SchemaError> {
        Ok(Self(cedar_policy_validator::ValidatorSchema::from_file(
            file,
            Extensions::all_available(),
        )?))
    }

    /// Parse the schema from a reader
    pub fn from_file_natural(
        file: impl std::io::Read,
    ) -> Result<(Self, impl Iterator<Item = SchemaWarning>), HumanSchemaError> {
        let (schema, warnings) = cedar_policy_validator::ValidatorSchema::from_file_natural(
            file,
            Extensions::all_available(),
        )?;
        Ok((Self(schema), warnings))
    }

    /// Parse the schema from a string
    pub fn from_str_natural(
        src: &str,
    ) -> Result<(Self, impl Iterator<Item = SchemaWarning>), HumanSchemaError> {
        let (schema, warnings) = cedar_policy_validator::ValidatorSchema::from_str_natural(
            src,
            Extensions::all_available(),
        )?;
        Ok((Self(schema), warnings))
    }

    /// Extract from the schema an `Entities` containing the action entities
    /// declared in the schema.
    pub fn action_entities(&self) -> Result<Entities, EntitiesError> {
        Ok(Entities(self.0.action_entities()?))
    }
}

/// Contains the result of policy validation. The result includes the list of
/// issues found by validation and whether validation succeeds or fails.
/// Validation succeeds if there are no fatal errors. There may still be
/// non-fatal warnings present when validation passes.
#[derive(Debug)]
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
impl From<cedar_policy_validator::ValidationResult> for ValidationResult {
    fn from(r: cedar_policy_validator::ValidationResult) -> Self {
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

/// Scan a set of policies for potentially confusing/obfuscating text. These
/// checks are also provided through [`Validator::validate`] which provides more
/// comprehensive error detection, but this function can be used to check for
/// confusable strings without defining a schema.
pub fn confusable_string_checker<'a>(
    templates: impl Iterator<Item = &'a Template> + 'a,
) -> impl Iterator<Item = ValidationWarning> + 'a {
    cedar_policy_validator::confusable_string_checks(templates.map(|t| &t.ast))
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
pub struct EntityNamespace(ast::Name);

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
            .map(|(id, template)| template.lossless.est().map(|est| (id.into(), est)))
            .collect::<Result<HashMap<_, _>, _>>()?;
        let est = est::PolicySet {
            templates,
            static_policies,
            template_links,
        };

        Ok(est)
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

    /// Extract annotation data from a `Policy` by its `PolicyId` and annotation key
    pub fn annotation<'a>(&'a self, id: &PolicyId, key: impl AsRef<str>) -> Option<&'a str> {
        self.ast
            .get(id.as_ref())?
            .annotation(&key.as_ref().parse().ok()?)
            .map(AsRef::as_ref)
    }

    /// Extract annotation data from a `Template` by its `PolicyId` and annotation key.
    //
    // TODO: unfortunate that this method returns `Option<String>` and the corresponding method
    // for policies (`.annotation()`) above returns `Option<&str>`, but this can't be changed
    // without a semver break
    pub fn template_annotation(&self, id: &PolicyId, key: impl AsRef<str>) -> Option<String> {
        self.ast
            .get_template(id.as_ref())?
            .annotation(&key.as_ref().parse().ok()?)
            .map(|annot| annot.val.to_string())
    }

    /// Returns true iff the `PolicySet` is empty
    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(
            self.ast.is_empty(),
            self.policies.is_empty() && self.templates.is_empty()
        );
        self.ast.is_empty()
    }

    /// Attempt to link a template and add the new template-linked policy to the policy set.
    /// If link fails, the `PolicySet` is not modified.
    /// Failure can happen for three reasons
    ///   1) The map passed in `vals` may not match the slots in the template
    ///   2) The `new_id` may conflict w/ a policy that already exists in the set
    ///   3) `template_id` does not correspond to a template. Either the id is
    ///   not in the policy set, or it is in the policy set but is either a
    ///   linked or static policy rather than a template
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
}

impl std::fmt::Display for PolicySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // prefer to display the lossless format
        write!(f, "{}", self.policies().map(|p| &p.lossless).join("\n"))
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
            .est()
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

/// Policy template datatype
#[derive(Debug, Clone)]
pub struct Template {
    /// AST representation of the template, used for most operations.
    /// In particular, the `ast` contains the authoritative `PolicyId` for the template.
    ast: ast::Template,

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
    lossless: LosslessPolicy,
}

impl PartialEq for Template {
    fn eq(&self, other: &Self) -> bool {
        // eq is based on just the `ast`
        self.ast.eq(&other.ast)
    }
}
impl Eq for Template {}

impl Template {
    /// Attempt to parse a `Template` from source.
    /// If `id` is Some, then the resulting template will have that `id`.
    /// If the `id` is None, the parser will use the default "policy0".
    /// The behavior around None may change in the future.
    pub fn parse(id: Option<PolicyId>, src: impl AsRef<str>) -> Result<Self, ParseErrors> {
        let ast = parser::parse_policy_template(id.map(Into::into), src.as_ref())?;
        Ok(Self {
            ast,
            lossless: LosslessPolicy::policy_or_template_text(src.as_ref()),
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

    /// Get an annotation value of this `Template`
    pub fn annotation(&self, key: impl AsRef<str>) -> Option<&str> {
        self.ast
            .annotation(&key.as_ref().parse().ok()?)
            .map(AsRef::as_ref)
    }

    /// Iterate through annotation data of this `Template` as key-value pairs
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
                    ast::EntityReference::Slot => None,
                })
            }
            ast::PrincipalOrResourceConstraint::Eq(eref) => {
                TemplatePrincipalConstraint::Eq(match eref {
                    ast::EntityReference::EUID(e) => Some(e.as_ref().clone().into()),
                    ast::EntityReference::Slot => None,
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
                        ast::EntityReference::Slot => None,
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
        }
    }

    /// Get the scope constraint on this policy's resource
    pub fn resource_constraint(&self) -> TemplateResourceConstraint {
        match self.ast.resource_constraint().as_inner() {
            ast::PrincipalOrResourceConstraint::Any => TemplateResourceConstraint::Any,
            ast::PrincipalOrResourceConstraint::In(eref) => {
                TemplateResourceConstraint::In(match eref {
                    ast::EntityReference::EUID(e) => Some(e.as_ref().clone().into()),
                    ast::EntityReference::Slot => None,
                })
            }
            ast::PrincipalOrResourceConstraint::Eq(eref) => {
                TemplateResourceConstraint::Eq(match eref {
                    ast::EntityReference::EUID(e) => Some(e.as_ref().clone().into()),
                    ast::EntityReference::Slot => None,
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
                        ast::EntityReference::Slot => None,
                    },
                )
            }
        }
    }

    /// Create a `Template` from its JSON representation.
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

    /// Get the JSON representation of this `Template`.
    pub fn to_json(&self) -> Result<serde_json::Value, PolicyToJsonError> {
        let est = self.lossless.est()?;
        serde_json::to_value(est).map_err(Into::into)
    }
}

impl std::fmt::Display for Template {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // prefer to display the lossless format
        self.lossless.fmt(f)
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
    ast: ast::Policy,
    /// Some "lossless" representation of the policy, whichever is most
    /// convenient to provide (and can be provided with the least overhead).
    /// This is used just for `to_json()`.
    /// We can't just derive this on-demand from `ast`, because the AST is lossy:
    /// we can't reconstruct an accurate CST/EST/policy-text from the AST, but
    /// we can from the EST (modulo whitespace and a few other things like the
    /// order of annotations).
    lossless: LosslessPolicy,
}

impl PartialEq for Policy {
    fn eq(&self, other: &Self) -> bool {
        // eq is based on just the `ast`
        self.ast.eq(&other.ast)
    }
}
impl Eq for Policy {}

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

    /// Get an annotation value of this template-linked or static policy
    pub fn annotation(&self, key: impl AsRef<str>) -> Option<&str> {
        self.ast
            .annotation(&key.as_ref().parse().ok()?)
            .map(AsRef::as_ref)
    }

    /// Iterate through annotation data of this template-linked or static policy
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
            ast::EntityReference::Slot => EntityUid::ref_cast(self.ast.env().get(&slot).unwrap()),
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
            lossless: LosslessPolicy::policy_or_template_text(policy_src.as_ref()),
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
        let est = self.lossless.est()?;
        serde_json::to_value(est).map_err(Into::into)
    }

    /// Get all the unknown entities from the policy
    #[doc = include_str!("../experimental_warning.md")]
    #[cfg(feature = "partial-eval")]
    pub fn unknown_entities(&self) -> HashSet<EntityUid> {
        self.ast
            .condition()
            .unknowns()
            .filter_map(
                |ast::Unknown {
                     name,
                     type_annotation,
                 }| {
                    if matches!(type_annotation, Some(ast::Type::Entity { .. })) {
                        EntityUid::from_str(name.as_str()).ok()
                    } else {
                        None
                    }
                },
            )
            .collect()
    }

    /// Create a `Policy` from its AST representation only. The `LosslessPolicy`
    /// will reflect the AST structure. When possible, don't use this method and
    /// create the `Policy` from the policy text, CST, or EST instead, as the
    /// conversion to AST is lossy. ESTs for policies generated by this method
    /// will reflect the AST and not the original policy syntax.
    #[cfg_attr(not(feature = "partial-eval"), allow(unused))]
    pub(crate) fn from_ast(ast: ast::Policy) -> Self {
        let text = ast.to_string(); // assume that pretty-printing is faster than `est::Policy::from(ast.clone())`; is that true?
        Self {
            ast,
            lossless: LosslessPolicy::policy_or_template_text(text),
        }
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // prefer to display the lossless format
        self.lossless.fmt(f)
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
enum LosslessPolicy {
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
    fn policy_or_template_text(text: impl Into<String>) -> Self {
        Self::Text {
            text: text.into(),
            slots: HashMap::new(),
        }
    }

    /// Get the EST representation of this static policy, linked policy, or template
    fn est(&self) -> Result<est::Policy, PolicyToJsonError> {
        match self {
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
}

impl std::fmt::Display for LosslessPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
                    match self.est() {
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
pub struct Expression(ast::Expr);

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

    /// Deconstruct an [`Expression`] to get the internal type.
    /// This function is only intended to be used internally.
    #[cfg(test)]
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

/// "Restricted" expressions are used for attribute values and `context`.
///
/// Restricted expressions can contain only the following:
///   - bool, int, and string literals
///   - literal `EntityUid`s such as `User::"alice"`
///   - extension function calls, where the arguments must be other things
///       on this list
///   - set and record literals, where the values must be other things on
///       this list
///
/// That means the following are not allowed in restricted expressions:
///   - `principal`, `action`, `resource`, `context`
///   - builtin operators and functions, including `.`, `in`, `has`, `like`,
///       `.contains()`
///   - if-then-else expressions
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct RestrictedExpression(ast::RestrictedExpr);

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

    /// Create an unknown expression
    #[cfg(feature = "partial-eval")]
    pub fn new_unknown(name: impl AsRef<str>) -> Self {
        Self(ast::RestrictedExpr::unknown(ast::Unknown::new_untyped(
            name.as_ref(),
        )))
    }

    /// Deconstruct an [`RestrictedExpression`] to get the internal type.
    /// This function is only intended to be used internally.
    #[cfg(test)]
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
#[derive(Debug)]
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
#[derive(Debug)]
pub struct UnsetSchema;

#[cfg(feature = "partial-eval")]
impl Default for RequestBuilder<UnsetSchema> {
    fn default() -> Self {
        Self {
            principal: ast::EntityUIDEntry::Unknown { loc: None },
            action: ast::EntityUIDEntry::Unknown { loc: None },
            resource: ast::EntityUIDEntry::Unknown { loc: None },
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
#[derive(Debug, RefCast)]
pub struct Request(pub(crate) ast::Request);

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
        cedar_policy_validator::context_schema_for_action(&schema.0, action.as_ref())
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
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
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
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord)]
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
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord)]
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
            ast::ValueKind::ExtensionValue(ev) => Self::ExtensionValue(ev.to_string()),
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
/// If evaluation results in an error (e.g., attempting to access a non-existent Entity or Record,
/// passing the wrong number of arguments to a function etc.), that error is returned as a String
pub fn eval_expression(
    request: &Request,
    entities: &Entities,
    expr: &Expression,
) -> Result<EvalResult, EvaluationError> {
    let all_ext = Extensions::all_available();
    let eval = Evaluator::new(request.0.clone(), &entities.0, &all_ext);
    Ok(EvalResult::from(
        // Evaluate under the empty slot map, as an expression should not have slots
        eval.interpret(&expr.0, &ast::SlotEnv::new())?,
    ))
}
