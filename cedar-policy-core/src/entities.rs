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

//! This module contains the `Entities` type and related functionality.

use crate::ast::*;
use crate::extensions::Extensions;
use crate::transitive_closure::{compute_tc, enforce_tc_and_dag};
use std::collections::{hash_map, HashMap};
use std::sync::Arc;

/// Module for checking that entities conform with a schema
pub mod conformance;
/// Module for error types
pub mod err;
pub mod json;
use json::err::JsonSerializationError;

pub use json::{
    AllEntitiesNoAttrsSchema, AttributeType, CedarValueJson, ContextJsonParser, ContextSchema,
    EntityJson, EntityJsonParser, EntityTypeDescription, EntityUidJson, FnAndArgs,
    NoEntitiesSchema, NoStaticContext, Schema, SchemaType, TypeAndId,
};

use conformance::EntitySchemaConformanceChecker;
use err::*;
#[cfg(feature = "partial-eval")]
use smol_str::ToSmolStr;

/// Represents an entity hierarchy, and allows looking up `Entity` objects by
/// UID.
//
/// Note that `Entities` is not `Serialize` itself -- use either the
/// `from_json_*()` and `write_to_json()` methods here, or the `proto` module in
/// `cedar-policy`, which is capable of ser/de both Core types like this and
/// `cedar-policy` types.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entities {
    /// Important internal invariant: for any `Entities` object that exists,
    /// the `ancestor` relation is transitively closed.
    entities: HashMap<EntityUID, Arc<Entity>>,

    /// The mode flag determines whether this store functions as a partial store or
    /// as a fully concrete store.
    /// Mode::Concrete means that the store is fully concrete, and failed dereferences are an error.
    /// Mode::Partial means the store is partial, and failed dereferences result in a residual.
    mode: Mode,
}

impl Entities {
    /// Create a fresh `Entities` with no entities
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
            mode: Mode::default(),
        }
    }

    /// Transform the store into a partial store, where
    /// attempting to dereference a non-existent EntityUID results in
    /// a residual instead of an error.
    #[cfg(feature = "partial-eval")]
    pub fn partial(self) -> Self {
        Self {
            entities: self.entities,
            mode: Mode::Partial,
        }
    }

    /// Is this a partial store (created with `.partial()`)
    pub fn is_partial(&self) -> bool {
        #[cfg(feature = "partial-eval")]
        let ret = self.mode == Mode::Partial;
        #[cfg(not(feature = "partial-eval"))]
        let ret = false;

        ret
    }

    /// Get the `Entity` with the given UID, if any
    pub fn entity(&self, uid: &EntityUID) -> Dereference<'_, Entity> {
        match self.entities.get(uid) {
            Some(e) => Dereference::Data(e),
            None => match self.mode {
                Mode::Concrete => Dereference::NoSuchEntity,
                #[cfg(feature = "partial-eval")]
                Mode::Partial => Dereference::Residual(Expr::unknown(Unknown::new_with_type(
                    uid.to_smolstr(),
                    Type::Entity {
                        ty: uid.entity_type().clone(),
                    },
                ))),
            },
        }
    }

    /// Iterate over the `Entity`s in the `Entities`
    pub fn iter(&self) -> impl Iterator<Item = &Entity> {
        self.entities.values().map(|e| e.as_ref())
    }

    /// Adds the [`crate::ast::Entity`]s in the iterator to this [`Entities`].
    /// Fails if
    ///  - there is a pair of non-identical entities in the passed iterator with the same Entity UID, or
    ///  - there is an entity in the passed iterator with the same Entity UID as a non-identical entity in this structure, or
    ///  - any error is encountered in the transitive closure computation.
    ///
    /// If `schema` is present, then the added entities will be validated
    /// against the `schema`, returning an error if they do not conform to the
    /// schema.
    /// (This method will not add action entities from the `schema`.)
    ///
    /// If you pass [`TCComputation::AssumeAlreadyComputed`], then the caller is
    /// responsible for ensuring that TC and DAG hold before calling this method.
    pub fn add_entities(
        mut self,
        collection: impl IntoIterator<Item = Arc<Entity>>,
        schema: Option<&impl Schema>,
        tc_computation: TCComputation,
        extensions: &Extensions<'_>,
    ) -> Result<Self> {
        let checker = schema.map(|schema| EntitySchemaConformanceChecker::new(schema, extensions));
        for entity in collection.into_iter() {
            if let Some(checker) = checker.as_ref() {
                checker.validate_entity(&entity)?;
            }
            update_entity_map(&mut self.entities, entity, false)?;
        }
        match tc_computation {
            TCComputation::AssumeAlreadyComputed => (),
            TCComputation::EnforceAlreadyComputed => enforce_tc_and_dag(&self.entities)?,
            TCComputation::ComputeNow => compute_tc(&mut self.entities, true)?,
        };
        Ok(self)
    }

    /// Removes the [`crate::ast::EntityUID`]s in the interator from this [`Entities`]
    /// Fails if any error is encountered in the transitive closure computation.
    ///
    /// If you pass [`TCComputation::AssumeAlreadyComputed`], then the caller is
    /// responsible for ensuring that TC and DAG hold before calling this method
    pub fn remove_entities(
        mut self,
        collection: impl IntoIterator<Item = EntityUID>,
        tc_computation: TCComputation,
    ) -> Result<Self> {
        for uid_to_remove in collection.into_iter() {
            match self.entities.remove(&uid_to_remove) {
                None => (),
                Some(entity_to_remove) => {
                    for entity in self.entities.values_mut() {
                        if entity.is_descendant_of(&uid_to_remove) {
                            // remove any direct or indirect link between `entity` and `entity_to_remove`
                            Arc::make_mut(entity).remove_indirect_ancestor(&uid_to_remove);
                            Arc::make_mut(entity).remove_parent(&uid_to_remove);
                            // remove any indirect link between `entity` and the ancestors of `entity_to_remove`
                            for ancestor_uid in entity_to_remove.ancestors() {
                                Arc::make_mut(entity).remove_indirect_ancestor(ancestor_uid);
                            }
                        }
                    }
                }
            }
        }
        match tc_computation {
            TCComputation::AssumeAlreadyComputed => (),
            TCComputation::EnforceAlreadyComputed => enforce_tc_and_dag(&self.entities)?,
            TCComputation::ComputeNow => compute_tc(&mut self.entities, true)?,
        }
        Ok(self)
    }

    /// Adds the [`crate::ast::Entity`]s in the iterator to this [`Entities`].
    /// Fails if any error is encountered in the transitive closure computation.
    ///
    /// When a duplicate is encountered, the value is overwritten by the latest version.
    ///
    /// If `schema` is present, then the added entities will be validated
    /// against the `schema`, returning an error if they do not conform to the
    /// schema.
    /// (This method will not add action entities from the `schema`.)
    ///
    /// If you pass [`TCComputation::AssumeAlreadyComputed`], then the caller is
    /// responsible for ensuring that TC and DAG hold before calling this method.
    pub fn upsert_entities(
        mut self,
        collection: impl IntoIterator<Item = Arc<Entity>>,
        schema: Option<&impl Schema>,
        tc_computation: TCComputation,
        extensions: &Extensions<'_>,
    ) -> Result<Self> {
        let checker = schema.map(|schema| EntitySchemaConformanceChecker::new(schema, extensions));
        for entity in collection.into_iter() {
            if let Some(checker) = checker.as_ref() {
                checker.validate_entity(&entity)?;
            }
            update_entity_map(&mut self.entities, entity, true)?;
        }
        match tc_computation {
            TCComputation::AssumeAlreadyComputed => (),
            TCComputation::EnforceAlreadyComputed => enforce_tc_and_dag(&self.entities)?,
            TCComputation::ComputeNow => compute_tc(&mut self.entities, true)?,
        };
        Ok(self)
    }

    /// Create an `Entities` object with the given entities.
    ///
    /// If `schema` is present, then action entities from that schema will also
    /// be added to the `Entities`.
    /// Also, the entities in `entities` will be validated against the `schema`,
    /// returning an error if they do not conform to the schema.
    ///
    /// If you pass `TCComputation::AssumeAlreadyComputed`, then the caller is
    /// responsible for ensuring that TC and DAG hold before calling this method.
    ///
    /// # Errors
    /// - [`EntitiesError::Duplicate`] if there is a pair of non-identical entities in
    ///   `entities` with the same Entity UID, or there is an entity in `entities` with the same
    ///   Entity UID as a non-identical entity in this structure
    /// - [`EntitiesError::TransitiveClosureError`] if `tc_computation ==
    ///   TCComputation::EnforceAlreadyComputed` and the entities are not transitively closed
    /// - [`EntitiesError::InvalidEntity`] if `schema` is not none and any entities do not conform
    ///   to the schema
    pub fn from_entities(
        entities: impl IntoIterator<Item = Entity>,
        schema: Option<&impl Schema>,
        tc_computation: TCComputation,
        extensions: &Extensions<'_>,
    ) -> Result<Self> {
        let mut entity_map = create_entity_map(entities.into_iter().map(Arc::new))?;
        if let Some(schema) = schema {
            // Validate non-action entities against schema.
            // We do this before adding the actions, because we trust the
            // actions were already validated as part of constructing the
            // `Schema`
            let checker = EntitySchemaConformanceChecker::new(schema, extensions);
            for entity in entity_map.values() {
                if !entity.uid().entity_type().is_action() {
                    checker.validate_entity(entity)?;
                }
            }
        }
        match tc_computation {
            TCComputation::AssumeAlreadyComputed => {}
            TCComputation::EnforceAlreadyComputed => {
                enforce_tc_and_dag(&entity_map)?;
            }
            TCComputation::ComputeNow => {
                compute_tc(&mut entity_map, true)?;
            }
        }
        // Now that TC has been enforced, we can check action entities for
        // conformance with the schema and add action entities to the store.
        // This is fine to do after TC because the action hierarchy in the
        // schema already satisfies TC, and action and non-action entities
        // can never be in the same hierarchy when using schema-based parsing.
        if let Some(schema) = schema {
            let checker = EntitySchemaConformanceChecker::new(schema, extensions);
            for entity in entity_map.values() {
                if entity.uid().entity_type().is_action() {
                    checker.validate_entity(entity)?;
                }
            }
            // Add the action entities from the schema
            entity_map.extend(
                schema
                    .action_entities()
                    .into_iter()
                    .map(|e: Arc<Entity>| (e.uid().clone(), e)),
            );
        }
        Ok(Self {
            entities: entity_map,
            mode: Mode::default(),
        })
    }

    /// Returns the length of the `Entities` object
    pub fn len(&self) -> usize {
        self.entities.len()
    }

    /// Returns `true` if the `Entities` object is empty
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    /// Convert an `Entities` object into a JSON value suitable for parsing in
    /// via `EntityJsonParser`.
    ///
    /// The returned JSON value will be parse-able even with no `Schema`.
    ///
    /// To parse an `Entities` object from a JSON value, use `EntityJsonParser`.
    pub fn to_json_value(&self) -> Result<serde_json::Value> {
        let ejsons: Vec<EntityJson> = self.to_ejsons()?;
        serde_json::to_value(ejsons)
            .map_err(JsonSerializationError::from)
            .map_err(Into::into)
    }

    /// Dump an `Entities` object into an entities JSON file.
    ///
    /// The resulting JSON will be suitable for parsing in via
    /// `EntityJsonParser`, and will be parse-able even with no `Schema`.
    ///
    /// To read an `Entities` object from an entities JSON file, use
    /// `EntityJsonParser`.
    pub fn write_to_json(&self, f: impl std::io::Write) -> Result<()> {
        let ejsons: Vec<EntityJson> = self.to_ejsons()?;
        serde_json::to_writer_pretty(f, &ejsons).map_err(JsonSerializationError::from)?;
        Ok(())
    }

    /// Internal helper function to convert this `Entities` into a `Vec<EntityJson>`
    fn to_ejsons(&self) -> Result<Vec<EntityJson>> {
        self.entities
            .values()
            .map(Arc::as_ref)
            .map(EntityJson::from_entity)
            .collect::<std::result::Result<_, JsonSerializationError>>()
            .map_err(Into::into)
    }

    fn get_entities_by_entity_type(&self) -> HashMap<EntityType, Vec<&Entity>> {
        let mut entities_by_type: HashMap<EntityType, Vec<&Entity>> = HashMap::new();
        for entity in self.iter() {
            let euid = entity.uid();
            let entity_type = euid.entity_type();
            if let Some(entities) = entities_by_type.get_mut(entity_type) {
                entities.push(entity);
            } else {
                entities_by_type.insert(entity_type.clone(), Vec::from([entity]));
            }
        }
        entities_by_type
    }

    /// Write entities into a DOT graph.  This function only returns an `Err`
    /// result on a failing `write!` to `f`, so it is infallible if the `Write`
    /// implementation cannot fail (e.g., `String`).
    pub fn to_dot_str(&self, f: &mut impl std::fmt::Write) -> std::fmt::Result {
        // write prelude
        write!(
            f,
            "strict digraph {{\n\tordering=\"out\"\n\tnode[shape=box]\n"
        )?;

        // From DOT language reference:
        // An ID is one of the following:
        // Any string of alphabetic ([a-zA-Z\200-\377]) characters, underscores ('_') or digits([0-9]), not beginning with a digit;
        // a numeral [-]?(.[0-9]⁺ | [0-9]⁺(.[0-9]*)? );
        // any double-quoted string ("...") possibly containing escaped quotes (\")¹;
        // an HTML string (<...>).
        // The best option to convert a `Name` or an `EntityUid` is to use double-quoted string.
        // The `escape_debug` method should be sufficient for our purpose.
        fn to_dot_id(f: &mut impl std::fmt::Write, v: &impl std::fmt::Display) -> std::fmt::Result {
            write!(f, "\"{}\"", v.to_string().escape_debug())
        }

        // write clusters (subgraphs)
        let entities_by_type = self.get_entities_by_entity_type();

        for (et, entities) in entities_by_type {
            write!(f, "\tsubgraph \"cluster_{et}\" {{\n\t\tlabel=",)?;
            to_dot_id(f, &et)?;
            writeln!(f)?;
            for entity in entities {
                write!(f, "\t\t")?;
                to_dot_id(f, &entity.uid())?;
                write!(f, " [label=")?;
                to_dot_id(f, &entity.uid().eid().escaped())?;
                writeln!(f, "]")?;
            }
            writeln!(f, "\t}}")?;
        }

        // adding edges
        for entity in self.iter() {
            for ancestor in entity.ancestors() {
                write!(f, "\t")?;
                to_dot_id(f, &entity.uid())?;
                write!(f, " -> ")?;
                to_dot_id(f, &ancestor)?;
                writeln!(f)?;
            }
        }
        writeln!(f, "}}")?;
        Ok(())
    }
}

/// Creates a map from EntityUIDs to Entities, erroring if there is a pair of Entity
/// instances with the same EntityUID that are not structurally equal.
fn create_entity_map(
    es: impl Iterator<Item = Arc<Entity>>,
) -> Result<HashMap<EntityUID, Arc<Entity>>> {
    let mut map: HashMap<EntityUID, Arc<Entity>> = HashMap::new();
    for e in es {
        update_entity_map(&mut map, e, false)?;
    }
    Ok(map)
}

/// Adds an entry to the specified map associating the EntityUID of the specified entity
/// to the specified entity. Checks whether there is an entity already in the map
/// with the same EntityUID as the specified entity. If such an entity is found and is
/// not structurally equal to the specified entity produces an error. Otherwise,
/// if a structurally equal entity is found, the state of the map is unchanged.
fn update_entity_map(
    map: &mut HashMap<EntityUID, Arc<Entity>>,
    entity: Arc<Entity>,
    allow_override: bool,
) -> Result<()> {
    match map.entry(entity.uid().clone()) {
        hash_map::Entry::Occupied(mut occupied_entry) => {
            if allow_override {
                occupied_entry.insert(entity);
            } else {
                // Check whether the occupying entity is structurally equal to the
                // entity being processed
                if !entity.deep_eq(occupied_entry.get()) {
                    let entry = occupied_entry.remove_entry();
                    return Err(EntitiesError::duplicate(entry.0));
                }
            }
        }
        hash_map::Entry::Vacant(v) => {
            v.insert(entity);
        }
    }
    Ok(())
}

impl IntoIterator for Entities {
    type Item = Entity;

    type IntoIter = std::iter::Map<
        std::collections::hash_map::IntoValues<EntityUID, Arc<Entity>>,
        fn(Arc<Entity>) -> Entity,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.entities.into_values().map(Arc::unwrap_or_clone)
    }
}

impl std::fmt::Display for Entities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.entities.is_empty() {
            write!(f, "<empty Entities>")
        } else {
            for e in self.entities.values() {
                writeln!(f, "{e}")?;
            }
            Ok(())
        }
    }
}

/// Results from dereferencing values from the Entity Store
#[derive(Debug, Clone)]
pub enum Dereference<'a, T> {
    /// No entity with the dereferenced EntityUID exists. This is an error.
    NoSuchEntity,
    /// The entity store has returned a residual
    Residual(Expr),
    /// The entity store has returned the requested data.
    Data(&'a T),
}

impl<'a, T> Dereference<'a, T>
where
    T: std::fmt::Debug,
{
    /// Returns the contained `Data` value, consuming the `self` value.
    ///
    /// Because this function may panic, its use is generally discouraged.
    /// Instead, prefer to use pattern matching and handle the `NoSuchEntity`
    /// and `Residual` cases explicitly.
    ///
    /// # Panics
    ///
    /// Panics if the self value is not `Data`.
    // PANIC SAFETY: This function is intended to panic, and says so in the documentation
    #[allow(clippy::panic)]
    pub fn unwrap(self) -> &'a T {
        match self {
            Self::Data(e) => e,
            e => panic!("unwrap() called on {e:?}"),
        }
    }

    /// Returns the contained `Data` value, consuming the `self` value.
    ///
    /// Because this function may panic, its use is generally discouraged.
    /// Instead, prefer to use pattern matching and handle the `NoSuchEntity`
    /// and `Residual` cases explicitly.
    ///
    /// # Panics
    ///
    /// Panics if the self value is not `Data`.
    // PANIC SAFETY: This function is intended to panic, and says so in the documentation
    #[allow(clippy::panic)]
    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    pub fn expect(self, msg: &str) -> &'a T {
        match self {
            Self::Data(e) => e,
            e => panic!("expect() called on {e:?}, msg: {msg}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Concrete,
    #[cfg(feature = "partial-eval")]
    Partial,
}

impl Default for Mode {
    fn default() -> Self {
        Self::Concrete
    }
}

/// Describes the option for how the TC (transitive closure) of the entity
/// hierarchy is computed
#[allow(dead_code)] // only `ComputeNow` is used currently, that's intentional
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TCComputation {
    /// Assume that the TC has already been computed and that the input is a DAG before the call of
    /// `Entities::from_entities`.
    AssumeAlreadyComputed,
    /// Enforce that the TC must have already been computed before the call of
    /// `Entities::from_entities`. If the given entities don't include all
    /// transitive hierarchy relations, return an error. Also checks for cycles and returns an error if found.
    EnforceAlreadyComputed,
    /// Compute the TC ourselves during the call of `Entities::from_entities`.
    /// This doesn't make any assumptions about the input, which can in fact
    /// contain just parent edges and not transitive ancestor edges. Also checks for cycles and returns an error if found.
    ComputeNow,
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
#[cfg(test)]
// PANIC SAFETY unit tests
#[allow(clippy::panic)]
#[allow(clippy::cognitive_complexity)]
mod json_parsing_tests {
    use super::*;
    use crate::{extensions::Extensions, test_utils::*, transitive_closure::TcError};
    use cool_asserts::assert_matches;
    use std::collections::HashSet;

    #[test]
    fn simple_json_parse1() {
        let v = serde_json::json!(
            [
                {
                    "uid" : { "type" : "A", "id" : "b"},
                    "attrs" : {},
                    "parents" : [ { "type" : "A", "id" : "c" }]
                }
            ]
        );
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        parser
            .from_json_value(v)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)));
    }

    #[test]
    fn enforces_tc_fail_cycle_almost() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let new = serde_json::json!([
            {
                "uid" : {
                    "type" : "Test",
                    "id" : "george"
                },
                "attrs" : { "foo" : 3},
                "parents" : [
                    {
                        "type" : "Test",
                        "id" : "george"
                    },
                    {
                        "type" : "Test",
                        "id" : "janet"
                    }
                ]
            }
        ]);

        let addl_entities = parser
            .iter_from_json_value(new)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)))
            .map(Arc::new);
        let err = simple_entities(&parser).add_entities(
            addl_entities,
            None::<&NoEntitiesSchema>,
            TCComputation::EnforceAlreadyComputed,
            Extensions::none(),
        );
        // Despite this being a cycle, alice doesn't have the appropriate edges to form the cycle, so we get this error
        let expected = TcError::missing_tc_edge(
            r#"Test::"janet""#.parse().unwrap(),
            r#"Test::"george""#.parse().unwrap(),
            r#"Test::"janet""#.parse().unwrap(),
        );
        assert_matches!(err, Err(EntitiesError::TransitiveClosureError(e)) => {
            assert_eq!(&expected, e.inner());
        });
    }

    #[test]
    fn enforces_tc_fail_connecting() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let new = serde_json::json!([
            {
                "uid" : {
                    "type" : "Test",
                    "id" : "george"
                },
                "attrs" : { "foo" : 3 },
                "parents" : [
                    {
                        "type" : "Test",
                        "id" : "henry"
                    }
                ]
            }
        ]);

        let addl_entities = parser
            .iter_from_json_value(new)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)))
            .map(Arc::new);
        let err = simple_entities(&parser).add_entities(
            addl_entities,
            None::<&NoEntitiesSchema>,
            TCComputation::EnforceAlreadyComputed,
            Extensions::all_available(),
        );
        let expected = TcError::missing_tc_edge(
            r#"Test::"janet""#.parse().unwrap(),
            r#"Test::"george""#.parse().unwrap(),
            r#"Test::"henry""#.parse().unwrap(),
        );
        assert_matches!(err, Err(EntitiesError::TransitiveClosureError(e)) => {
            assert_eq!(&expected, e.inner());
        });
    }

    #[test]
    fn enforces_tc_fail_missing_edge() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let new = serde_json::json!([
            {
                "uid" : {
                    "type" : "Test",
                    "id" : "jeff",
                },
                "attrs" : { "foo" : 3 },
                "parents" : [
                    {
                        "type" : "Test",
                        "id" : "alice"
                    }
                ]
            }
        ]);

        let addl_entities = parser
            .iter_from_json_value(new)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)))
            .map(Arc::new);
        let err = simple_entities(&parser).add_entities(
            addl_entities,
            None::<&NoEntitiesSchema>,
            TCComputation::EnforceAlreadyComputed,
            Extensions::all_available(),
        );
        let expected = TcError::missing_tc_edge(
            r#"Test::"jeff""#.parse().unwrap(),
            r#"Test::"alice""#.parse().unwrap(),
            r#"Test::"bob""#.parse().unwrap(),
        );
        assert_matches!(err, Err(EntitiesError::TransitiveClosureError(e)) => {
            assert_eq!(&expected, e.inner());
        });
    }

    #[test]
    fn enforces_tc_success() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let new = serde_json::json!([
            {
                "uid" : {
                    "type" : "Test",
                    "id" : "jeff"
                },
                "attrs" : { "foo" : 3 },
                "parents" : [
                    {
                        "type" : "Test",
                        "id" : "alice"
                    },
                    {
                        "type" : "Test",
                        "id" : "bob"
                    }
                ]
            }
        ]);

        let addl_entities = parser
            .iter_from_json_value(new)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)))
            .map(Arc::new);
        let es = simple_entities(&parser)
            .add_entities(
                addl_entities,
                None::<&NoEntitiesSchema>,
                TCComputation::EnforceAlreadyComputed,
                Extensions::all_available(),
            )
            .unwrap();
        let euid = r#"Test::"jeff""#.parse().unwrap();
        let jeff = es.entity(&euid).unwrap();
        assert!(jeff.is_descendant_of(&r#"Test::"alice""#.parse().unwrap()));
        assert!(jeff.is_descendant_of(&r#"Test::"bob""#.parse().unwrap()));
        assert!(!jeff.is_descendant_of(&r#"Test::"george""#.parse().unwrap()));
        simple_entities_still_sane(&es);
    }

    #[test]
    fn adds_extends_tc_connecting() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let new = serde_json::json!([
            {
                "uid" : {
                    "type" : "Test",
                    "id" : "george"
                },
                "attrs" : { "foo" : 3},
                "parents" : [
                    {
                        "type" : "Test",
                        "id" : "henry"
                    }
                ]
            }
        ]);

        let addl_entities = parser
            .iter_from_json_value(new)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)))
            .map(Arc::new);
        let es = simple_entities(&parser)
            .add_entities(
                addl_entities,
                None::<&NoEntitiesSchema>,
                TCComputation::ComputeNow,
                Extensions::all_available(),
            )
            .unwrap();
        let euid = r#"Test::"george""#.parse().unwrap();
        let jeff = es.entity(&euid).unwrap();
        assert!(jeff.is_descendant_of(&r#"Test::"henry""#.parse().unwrap()));
        let alice = es.entity(&r#"Test::"janet""#.parse().unwrap()).unwrap();
        assert!(alice.is_descendant_of(&r#"Test::"henry""#.parse().unwrap()));
        simple_entities_still_sane(&es);
    }

    #[test]
    fn adds_extends_tc() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let new = serde_json::json!([
            {
                "uid" : {
                    "type" : "Test",
                    "id" : "jeff"
                },
                "attrs" : {
                    "foo" : 3
                },
                "parents" : [
                    {
                        "type" : "Test",
                        "id" : "alice"
                    }
                ]
            }
        ]);

        let addl_entities = parser
            .iter_from_json_value(new)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)))
            .map(Arc::new);
        let es = simple_entities(&parser)
            .add_entities(
                addl_entities,
                None::<&NoEntitiesSchema>,
                TCComputation::ComputeNow,
                Extensions::all_available(),
            )
            .unwrap();
        let euid = r#"Test::"jeff""#.parse().unwrap();
        let jeff = es.entity(&euid).unwrap();
        assert!(jeff.is_descendant_of(&r#"Test::"alice""#.parse().unwrap()));
        assert!(jeff.is_descendant_of(&r#"Test::"bob""#.parse().unwrap()));
        simple_entities_still_sane(&es);
    }

    #[test]
    fn adds_works() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let new = serde_json::json!([
            {
                "uid" : {
                    "type" : "Test",
                    "id" : "jeff"
                },
                "attrs" : {
                    "foo" : 3
                },
                "parents" : [
                    {
                        "type" : "Test",
                        "id" : "susan"
                    }
                ]
            }
        ]);

        let addl_entities = parser
            .iter_from_json_value(new)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)))
            .map(Arc::new);
        let es = simple_entities(&parser)
            .add_entities(
                addl_entities,
                None::<&NoEntitiesSchema>,
                TCComputation::ComputeNow,
                Extensions::all_available(),
            )
            .unwrap();
        let euid = r#"Test::"jeff""#.parse().unwrap();
        let jeff = es.entity(&euid).unwrap();
        let value = jeff.get("foo").unwrap();
        assert_eq!(value, &PartialValue::from(3));
        assert!(jeff.is_descendant_of(&r#"Test::"susan""#.parse().unwrap()));
        simple_entities_still_sane(&es);
    }

    #[test]
    fn add_consistent_duplicates_in_iterator() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        // Create the entities to be added
        let new = serde_json::json!([
            {"uid":{ "type" : "Test", "id" : "ruby" }, "attrs" : {}, "parents" : []},
            {"uid":{ "type" : "Test", "id" : "jeff" }, "attrs" : {}, "parents" : []},
            {"uid":{ "type" : "Test", "id" : "jeff" }, "attrs" : {}, "parents" : []}]);
        let addl_entities = parser
            .iter_from_json_value(new)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)))
            .map(Arc::new);
        // Create an initial structure
        let original = simple_entities(&parser);
        let original_size = original.entities.len();
        // Add the new entities to an existing structure
        let es = original
            .add_entities(
                addl_entities,
                None::<&NoEntitiesSchema>,
                TCComputation::ComputeNow,
                Extensions::all_available(),
            )
            .unwrap();
        // Check that the original conditions of the structure still hold
        simple_entities_still_sane(&es);
        // Check that jeff has been added
        es.entity(&r#"Test::"jeff""#.parse().unwrap()).unwrap();
        // Check that ruby has been added
        es.entity(&r#"Test::"ruby""#.parse().unwrap()).unwrap();
        // Check that the size of the structure increased by exactly two
        assert_eq!(es.entities.len(), 2 + original_size);
    }

    #[test]
    fn add_inconsistent_duplicates_in_iterator() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        // Create the entities to be added
        let new = serde_json::json!([
            {"uid":{ "type" : "Test", "id" : "ruby" }, "attrs" : {"location": "France"}, "parents" : []},
            {"uid":{ "type" : "Test", "id" : "jeff" }, "attrs" : {"location": "France"}, "parents" : []},
            {"uid":{ "type" : "Test", "id" : "jeff" }, "attrs" : {}, "parents" : []}]);

        let addl_entities = parser
            .iter_from_json_value(new)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)))
            .map(Arc::new);
        // Create an initial structure
        let original = simple_entities(&parser);
        // Add the new entities to an existing structure
        let err = original
            .add_entities(
                addl_entities,
                None::<&NoEntitiesSchema>,
                TCComputation::ComputeNow,
                Extensions::all_available(),
            )
            .err()
            .unwrap();
        // Check that an error occurs indicating that an inconsistent duplicate was found
        let expected = r#"Test::"jeff""#.parse().unwrap();
        assert_matches!(err, EntitiesError::Duplicate(d) => assert_eq!(d.euid(), &expected));
    }

    #[test]
    fn add_consistent_duplicate() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        // Create the entities to be added
        let new = serde_json::json!([
            {"uid":{ "type" : "Test", "id" : "ruby" }, "attrs" : {}, "parents" : []},
            {"uid":{ "type" : "Test", "id" : "jeff" }, "attrs" : {}, "parents" : []}]);
        let addl_entities = parser
            .iter_from_json_value(new)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)))
            .map(Arc::new);
        // Create an initial structure
        let json = serde_json::json!([
            {"uid":{ "type" : "Test", "id" : "amy" }, "attrs" : {}, "parents" : []},
            {"uid":{ "type" : "Test", "id" : "jeff" }, "attrs" : {}, "parents" : []}]);
        let original = parser
            .from_json_value(json)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)));
        let original_size = original.entities.len();
        // Add the new entities to an existing structure
        let es = original
            .add_entities(
                addl_entities,
                None::<&NoEntitiesSchema>,
                TCComputation::ComputeNow,
                Extensions::all_available(),
            )
            .unwrap();
        // Check that jeff is still in the structure
        es.entity(&r#"Test::"jeff""#.parse().unwrap()).unwrap();
        // Check that amy is still in the structure
        es.entity(&r#"Test::"amy""#.parse().unwrap()).unwrap();
        // Check that ruby has been added
        es.entity(&r#"Test::"ruby""#.parse().unwrap()).unwrap();
        // Check that the size of the structure increased by exactly one
        assert_eq!(es.entities.len(), 1 + original_size);
    }

    #[test]
    fn add_inconsistent_duplicate() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        // Create the entities to be added
        let new = serde_json::json!([
            {"uid":{ "type" : "Test", "id" : "ruby" }, "attrs" : {}, "parents" : []},
            {"uid":{ "type" : "Test", "id" : "jeff" }, "attrs" : {"location": "England"}, "parents" : []}]);
        let addl_entities = parser
            .iter_from_json_value(new)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)))
            .map(Arc::new);
        // Create an initial structure
        let json = serde_json::json!([
            {"uid":{ "type" : "Test", "id" : "amy" }, "attrs" : {}, "parents" : []},
            {"uid":{ "type" : "Test", "id" : "jeff" }, "attrs" : {"location": "London"}, "parents" : []}]);
        let original = parser
            .from_json_value(json)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)));
        let err = original
            .add_entities(
                addl_entities,
                None::<&NoEntitiesSchema>,
                TCComputation::ComputeNow,
                Extensions::all_available(),
            )
            .err()
            .unwrap();
        // Check that an error occurs indicating that an inconsistent duplicate was found
        let expected = r#"Test::"jeff""#.parse().unwrap();
        assert_matches!(err, EntitiesError::Duplicate(d) => assert_eq!(d.euid(), &expected));
    }

    #[test]
    fn simple_entities_correct() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        simple_entities(&parser);
    }

    fn simple_entities(parser: &EntityJsonParser<'_, '_>) -> Entities {
        let json = serde_json::json!(
            [
                {
                    "uid" : { "type" : "Test", "id": "alice" },
                    "attrs" : { "bar" : 2},
                    "parents" : [
                        {
                            "type" : "Test",
                            "id" : "bob"
                        }
                    ]
                },
                {
                    "uid" : { "type" : "Test", "id" : "janet"},
                    "attrs" : { "bar" : 2},
                    "parents" : [
                        {
                            "type" : "Test",
                            "id" : "george"
                        }
                    ]
                },
                {
                    "uid" : { "type" : "Test", "id" : "bob"},
                    "attrs" : {},
                    "parents" : []
                },
                {
                    "uid" : { "type" : "Test", "id" : "henry"},
                    "attrs" : {},
                    "parents" : []
                },
            ]
        );
        parser
            .from_json_value(json)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)))
    }

    /// Ensure the initial conditions of the entities still hold
    fn simple_entities_still_sane(e: &Entities) {
        let bob = r#"Test::"bob""#.parse().unwrap();
        let alice = e.entity(&r#"Test::"alice""#.parse().unwrap()).unwrap();
        let bar = alice.get("bar").unwrap();
        assert_eq!(bar, &PartialValue::from(2));
        assert!(alice.is_descendant_of(&bob));
        let bob = e.entity(&bob).unwrap();
        assert!(bob.ancestors().next().is_none());
    }

    #[cfg(feature = "partial-eval")]
    #[test]
    fn basic_partial() {
        // Alice -> Jane -> Bob
        let json = serde_json::json!(
            [
            {
                "uid" : {
                    "type" : "test_entity_type",
                    "id" : "alice"
                },
                "attrs": {},
                "parents": [
                {
                    "type" : "test_entity_type",
                    "id" : "jane"
                }
                ]
            },
            {
                "uid" : {
                    "type" : "test_entity_type",
                    "id" : "jane"
                },
                "attrs": {},
                "parents": [
                {
                    "type" : "test_entity_type",
                    "id" : "bob",
                }
                ]
            },
            {
                "uid" : {
                    "type" : "test_entity_type",
                    "id" : "bob"
                },
                "attrs": {},
                "parents": []
            }
            ]
        );

        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let es = eparser
            .from_json_value(json)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)))
            .partial();

        let alice = es.entity(&EntityUID::with_eid("alice")).unwrap();
        // Double check transitive closure computation
        assert!(alice.is_descendant_of(&EntityUID::with_eid("bob")));

        let janice = es.entity(&EntityUID::with_eid("janice"));

        assert_matches!(janice, Dereference::Residual(_));
    }

    #[test]
    fn basic() {
        // Alice -> Jane -> Bob
        let json = serde_json::json!([
            {
                "uid" : {
                    "type" : "test_entity_type",
                    "id" : "alice"
                },
                "attrs": {},
                "parents": [
                    {
                        "type" : "test_entity_type",
                        "id" : "jane"
                    }
                ]
            },
            {
                "uid" : {
                    "type" : "test_entity_type",
                    "id" : "jane"
                },
                "attrs": {},
                "parents": [
                    {
                        "type" : "test_entity_type",
                        "id" : "bob"
                    }
                ]
            },
            {
                "uid" : {
                    "type" : "test_entity_type",
                    "id" : "bob"
                },
                "attrs": {},
                "parents": []
            },
            {
                "uid" : {
                    "type" : "test_entity_type",
                    "id" : "josephine"
                },
                "attrs": {},
                "parents": [],
                "tags": {}
            }
            ]
        );

        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let es = eparser
            .from_json_value(json)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)));

        let alice = es.entity(&EntityUID::with_eid("alice")).unwrap();
        // Double check transitive closure computation
        assert!(alice.is_descendant_of(&EntityUID::with_eid("bob")));
    }

    #[test]
    fn no_expr_escapes1() {
        let json = serde_json::json!(
        [
        {
            "uid" : r#"test_entity_type::"Alice""#,
            "attrs": {
                "bacon": "eggs",
                "pancakes": [1, 2, 3],
                "waffles": { "key": "value" },
                "toast" : { "__extn" : { "fn" : "decimal", "arg" : "33.47" }},
                "12345": { "__entity": { "type": "test_entity_type", "id": "bob" } },
                "a b c": { "__extn": { "fn": "ip", "arg": "222.222.222.0/24" } }
            },
            "parents": [
                { "__entity": { "type" : "test_entity_type", "id" : "bob"} },
                { "__entity": { "type": "test_entity_type", "id": "catherine" } }
            ]
        },
        ]);
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        assert_matches!(eparser.from_json_value(json.clone()), Err(e) => {
            expect_err(
                &json,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"in uid field of <unknown entity>, expected a literal entity reference, but got `"test_entity_type::\"Alice\""`"#)
                    .help(r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#)
                    .build()
            );
        });
    }

    #[test]
    fn no_expr_escapes2() {
        let json = serde_json::json!(
        [
        {
            "uid" : {
                "__expr" :
                    r#"test_entity_type::"Alice""#
            },
            "attrs": {
                "bacon": "eggs",
                "pancakes": [1, 2, 3],
                "waffles": { "key": "value" },
                "toast" : { "__extn" : { "fn" : "decimal", "arg" : "33.47" }},
                "12345": { "__entity": { "type": "test_entity_type", "id": "bob" } },
                "a b c": { "__extn": { "fn": "ip", "arg": "222.222.222.0/24" } }
            },
            "parents": [
                { "__entity": { "type" : "test_entity_type", "id" : "bob"} },
                { "__entity": { "type": "test_entity_type", "id": "catherine" } }
            ]
        }
        ]);
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        assert_matches!(eparser.from_json_value(json.clone()), Err(e) => {
            expect_err(
                &json,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"in uid field of <unknown entity>, the `__expr` escape is no longer supported"#)
                    .help(r#"to create an entity reference, use `__entity`; to create an extension value, use `__extn`; and for all other values, use JSON directly"#)
                    .build()
            );
        });
    }

    #[test]
    fn no_expr_escapes3() {
        let json = serde_json::json!(
        [
        {
            "uid" : {
                "type" : "test_entity_type",
                "id" : "Alice"
            },
            "attrs": {
                "bacon": "eggs",
                "pancakes": { "__expr" : "[1,2,3]" },
                "waffles": { "key": "value" },
                "toast" : { "__extn" : { "fn" : "decimal", "arg" : "33.47" }},
                "12345": { "__entity": { "type": "test_entity_type", "id": "bob" } },
                "a b c": { "__extn": { "fn": "ip", "arg": "222.222.222.0/24" } }
            },
            "parents": [
                { "__entity": { "type" : "test_entity_type", "id" : "bob"} },
                { "__entity": { "type": "test_entity_type", "id": "catherine" } }
            ]
        }
        ]);
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        assert_matches!(eparser.from_json_value(json.clone()), Err(e) => {
            expect_err(
                &json,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"in attribute `pancakes` on `test_entity_type::"Alice"`, the `__expr` escape is no longer supported"#)
                    .help(r#"to create an entity reference, use `__entity`; to create an extension value, use `__extn`; and for all other values, use JSON directly"#)
                    .build()
            );
        });
    }

    #[test]
    fn no_expr_escapes4() {
        let json = serde_json::json!(
        [
        {
            "uid" : {
                "type" : "test_entity_type",
                "id" : "Alice"
            },
            "attrs": {
                "bacon": "eggs",
                "waffles": { "key": "value" },
                "12345": { "__entity": { "type": "test_entity_type", "id": "bob" } },
                "a b c": { "__extn": { "fn": "ip", "arg": "222.222.222.0/24" } }
            },
            "parents": [
                { "__expr": "test_entity_type::\"Alice\"" },
                { "__entity": { "type": "test_entity_type", "id": "catherine" } }
            ]
        }
        ]);
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        assert_matches!(eparser.from_json_value(json.clone()), Err(e) => {
            expect_err(
                &json,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"in parents field of `test_entity_type::"Alice"`, the `__expr` escape is no longer supported"#)
                    .help(r#"to create an entity reference, use `__entity`; to create an extension value, use `__extn`; and for all other values, use JSON directly"#)
                    .build()
            );
        });
    }

    #[test]
    fn no_expr_escapes5() {
        let json = serde_json::json!(
        [
        {
            "uid" : {
                "type" : "test_entity_type",
                "id" : "Alice"
            },
            "attrs": {
                "bacon": "eggs",
                "waffles": { "key": "value" },
                "12345": { "__entity": { "type": "test_entity_type", "id": "bob" } },
                "a b c": { "__extn": { "fn": "ip", "arg": "222.222.222.0/24" } }
            },
            "parents": [
                "test_entity_type::\"bob\"",
                { "__entity": { "type": "test_entity_type", "id": "catherine" } }
            ]
        }
        ]);
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        assert_matches!(eparser.from_json_value(json.clone()), Err(e) => {
            expect_err(
                &json,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"in parents field of `test_entity_type::"Alice"`, expected a literal entity reference, but got `"test_entity_type::\"bob\""`"#)
                    .help(r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#)
                    .build()
            );
        });
    }

    #[cfg(feature = "ipaddr")]
    /// this one uses `__entity` and `__extn` escapes, in various positions
    #[test]
    fn more_escapes() {
        let json = serde_json::json!(
            [
            {
                "uid" : {
                    "type" : "test_entity_type",
                    "id" : "alice"
                },
                "attrs": {
                    "bacon": "eggs",
                    "pancakes": [1, 2, 3],
                    "waffles": { "key": "value" },
                    "toast" : { "__extn" : { "fn" : "decimal", "arg" : "33.47" }},
                    "12345": { "__entity": { "type": "test_entity_type", "id": "bob" } },
                    "a b c": { "__extn": { "fn": "ip", "arg": "222.222.222.0/24" } }
                },
                "parents": [
                    { "__entity": { "type" : "test_entity_type", "id" : "bob"} },
                    { "__entity": { "type": "test_entity_type", "id": "catherine" } }
                ]
            },
            {
                "uid" : {
                    "type" : "test_entity_type",
                    "id" : "bob"
                },
                "attrs": {},
                "parents": []
            },
            {
                "uid" : {
                    "type" : "test_entity_type",
                    "id" : "catherine"
                },
                "attrs": {},
                "parents": []
            }
            ]
        );

        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let es = eparser
            .from_json_value(json)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)));

        let alice = es.entity(&EntityUID::with_eid("alice")).unwrap();
        assert_eq!(alice.get("bacon"), Some(&PartialValue::from("eggs")));
        assert_eq!(
            alice.get("pancakes"),
            Some(&PartialValue::from(vec![
                Value::from(1),
                Value::from(2),
                Value::from(3),
            ])),
        );
        assert_eq!(
            alice.get("waffles"),
            Some(&PartialValue::from(Value::record(
                vec![("key", Value::from("value"),)],
                None
            ))),
        );
        assert_eq!(
            alice.get("toast").cloned().map(RestrictedExpr::try_from),
            Some(Ok(RestrictedExpr::call_extension_fn(
                "decimal".parse().expect("should be a valid Name"),
                vec![RestrictedExpr::val("33.47")],
            ))),
        );
        assert_eq!(
            alice.get("12345"),
            Some(&PartialValue::from(EntityUID::with_eid("bob"))),
        );
        assert_eq!(
            alice.get("a b c").cloned().map(RestrictedExpr::try_from),
            Some(Ok(RestrictedExpr::call_extension_fn(
                "ip".parse().expect("should be a valid Name"),
                vec![RestrictedExpr::val("222.222.222.0/24")],
            ))),
        );
        assert!(alice.is_descendant_of(&EntityUID::with_eid("bob")));
        assert!(alice.is_descendant_of(&EntityUID::with_eid("catherine")));
    }

    #[test]
    fn implicit_and_explicit_escapes() {
        // this one tests the implicit and explicit forms of `__entity` escapes
        // for the `uid` and `parents` fields
        let json = serde_json::json!(
            [
            {
                "uid": { "type" : "test_entity_type", "id" : "alice" },
                "attrs": {},
                "parents": [
                    { "type" : "test_entity_type", "id" : "bob" },
                    { "__entity": { "type": "test_entity_type", "id": "charles" } },
                    { "type": "test_entity_type", "id": "elaine" }
                ]
            },
            {
                "uid": { "__entity": { "type": "test_entity_type", "id": "bob" }},
                "attrs": {},
                "parents": []
            },
            {
                "uid" : {
                    "type" : "test_entity_type",
                    "id" : "charles"
                },
                "attrs" : {},
                "parents" : []
            },
            {
                "uid": { "type": "test_entity_type", "id": "darwin" },
                "attrs": {},
                "parents": []
            },
            {
                "uid": { "type": "test_entity_type", "id": "elaine" },
                "attrs": {},
                "parents" : [
                    {
                        "type" : "test_entity_type",
                        "id" : "darwin"
                    }
                ]
            }
            ]
        );

        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let es = eparser
            .from_json_value(json)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)));

        // check that all five entities exist
        let alice = es.entity(&EntityUID::with_eid("alice")).unwrap();
        let bob = es.entity(&EntityUID::with_eid("bob")).unwrap();
        let charles = es.entity(&EntityUID::with_eid("charles")).unwrap();
        let darwin = es.entity(&EntityUID::with_eid("darwin")).unwrap();
        let elaine = es.entity(&EntityUID::with_eid("elaine")).unwrap();

        // and check the parent relations
        assert!(alice.is_descendant_of(&EntityUID::with_eid("bob")));
        assert!(alice.is_descendant_of(&EntityUID::with_eid("charles")));
        assert!(alice.is_descendant_of(&EntityUID::with_eid("darwin")));
        assert!(alice.is_descendant_of(&EntityUID::with_eid("elaine")));
        assert_eq!(bob.ancestors().next(), None);
        assert_eq!(charles.ancestors().next(), None);
        assert_eq!(darwin.ancestors().next(), None);
        assert!(elaine.is_descendant_of(&EntityUID::with_eid("darwin")));
        assert!(!elaine.is_descendant_of(&EntityUID::with_eid("bob")));
    }

    #[test]
    fn uid_failures() {
        // various JSON constructs that are invalid in `uid` and `parents` fields
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);

        let json = serde_json::json!(
            [
            {
                "uid": "hello",
                "attrs": {},
                "parents": []
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in uid field of <unknown entity>, expected a literal entity reference, but got `"hello"`"#,
            ).help(
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": "\"hello\"",
                "attrs": {},
                "parents": []
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in uid field of <unknown entity>, expected a literal entity reference, but got `"\"hello\""`"#,
            ).help(
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "spam": "eggs" },
                "attrs": {},
                "parents": []
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in uid field of <unknown entity>, expected a literal entity reference, but got `{"spam":"eggs","type":"foo"}`"#,
            ).help(
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": {},
                "parents": "foo::\"help\""
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"invalid type: string "foo::\"help\"", expected a sequence"#
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": {},
                "parents": [
                    "foo::\"help\"",
                    { "__extn": { "fn": "ip", "arg": "222.222.222.0" } }
                ]
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in parents field of `foo::"bar"`, expected a literal entity reference, but got `"foo::\"help\""`"#,
            ).help(
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ).build());
        });
    }

    /// Test that `null` is properly rejected, with a sane error message, in
    /// various positions
    #[test]
    fn null_failures() {
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);

        let json = serde_json::json!(
            [
            {
                "uid": null,
                "attrs": {},
                "parents": [],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "in uid field of <unknown entity>, expected a literal entity reference, but got `null`",
            ).help(
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": null, "id": "bar" },
                "attrs": {},
                "parents": [],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in uid field of <unknown entity>, expected a literal entity reference, but got `{"id":"bar","type":null}`"#,
            ).help(
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": null },
                "attrs": {},
                "parents": [],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in uid field of <unknown entity>, expected a literal entity reference, but got `{"id":null,"type":"foo"}`"#,
            ).help(
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": null,
                "parents": [],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "invalid type: null, expected a map"
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": { "attr": null },
                "parents": [],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in attribute `attr` on `foo::"bar"`, found a `null`; JSON `null`s are not allowed in Cedar"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": { "attr": { "subattr": null } },
                "parents": [],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in attribute `attr` on `foo::"bar"`, found a `null`; JSON `null`s are not allowed in Cedar"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": { "attr": [ 3, null ] },
                "parents": [],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in attribute `attr` on `foo::"bar"`, found a `null`; JSON `null`s are not allowed in Cedar"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": { "attr": [ 3, { "subattr" : null } ] },
                "parents": [],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in attribute `attr` on `foo::"bar"`, found a `null`; JSON `null`s are not allowed in Cedar"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": { "__extn": { "fn": null, "args": [] } },
                "parents": [],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in attribute `__extn` on `foo::"bar"`, found a `null`; JSON `null`s are not allowed in Cedar"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": { "__extn": { "fn": "ip", "args": null } },
                "parents": [],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in attribute `__extn` on `foo::"bar"`, found a `null`; JSON `null`s are not allowed in Cedar"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": { "__extn": { "fn": "ip", "args": [ null ] } },
                "parents": [],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in attribute `__extn` on `foo::"bar"`, found a `null`; JSON `null`s are not allowed in Cedar"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": { "attr": 2 },
                "parents": null,
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "invalid type: null, expected a sequence"
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": { "attr": 2 },
                "parents": [ null ],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in parents field of `foo::"bar"`, expected a literal entity reference, but got `null`"#,
            ).help(
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": { "attr": 2 },
                "parents": [ { "type": "foo", "id": null } ],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in parents field of `foo::"bar"`, expected a literal entity reference, but got `{"id":null,"type":"foo"}`"#,
            ).help(
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ).build());
        });

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": { "attr": 2 },
                "parents": [ { "type": "foo", "id": "parent" }, null ],
            }
            ]
        );
        assert_matches!(eparser.from_json_value(json.clone()), Err(EntitiesError::Deserialization(e)) => {
            expect_err(&json, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"in parents field of `foo::"bar"`, expected a literal entity reference, but got `null`"#,
            ).help(
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ).build());
        });
    }

    /// helper function to round-trip an Entities (with no schema-based parsing)
    fn roundtrip(entities: &Entities) -> Result<Entities> {
        let mut buf = Vec::new();
        entities.write_to_json(&mut buf)?;
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        eparser.from_json_str(&String::from_utf8(buf).expect("should be valid UTF-8"))
    }

    /// helper function
    fn test_entities() -> [Entity; 4] {
        [
            Entity::with_uid(EntityUID::with_eid("test_principal")),
            Entity::with_uid(EntityUID::with_eid("test_action")),
            Entity::with_uid(EntityUID::with_eid("test_resource")),
            Entity::with_uid(EntityUID::with_eid("test")),
        ]
    }

    /// Test that we can take an Entities, write it to JSON, parse that JSON
    /// back in, and we have exactly the same Entities
    #[test]
    fn json_roundtripping() {
        let empty_entities = Entities::new();
        assert_eq!(
            empty_entities,
            roundtrip(&empty_entities).expect("should roundtrip without errors")
        );

        let entities = Entities::from_entities(
            test_entities(),
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::none(),
        )
        .expect("Failed to construct entities");
        assert_eq!(
            entities,
            roundtrip(&entities).expect("should roundtrip without errors")
        );

        let complicated_entity = Entity::new(
            EntityUID::with_eid("complicated"),
            [
                ("foo".into(), RestrictedExpr::val(false)),
                ("bar".into(), RestrictedExpr::val(-234)),
                ("ham".into(), RestrictedExpr::val(r"a b c * / ? \")),
                (
                    "123".into(),
                    RestrictedExpr::val(EntityUID::with_eid("mom")),
                ),
                (
                    "set".into(),
                    RestrictedExpr::set([
                        RestrictedExpr::val(0),
                        RestrictedExpr::val(EntityUID::with_eid("pancakes")),
                        RestrictedExpr::val("mmm"),
                    ]),
                ),
                (
                    "rec".into(),
                    RestrictedExpr::record([
                        ("nested".into(), RestrictedExpr::val("attr")),
                        (
                            "another".into(),
                            RestrictedExpr::val(EntityUID::with_eid("foo")),
                        ),
                    ])
                    .unwrap(),
                ),
                (
                    "src_ip".into(),
                    RestrictedExpr::call_extension_fn(
                        "ip".parse().expect("should be a valid Name"),
                        vec![RestrictedExpr::val("222.222.222.222")],
                    ),
                ),
            ],
            HashSet::new(),
            [
                EntityUID::with_eid("parent1"),
                EntityUID::with_eid("parent2"),
            ]
            .into_iter()
            .collect(),
            [
                // note that `foo` is also an attribute, with a different type
                ("foo".into(), RestrictedExpr::val(2345)),
                // note that `bar` is also an attribute, with the same type
                ("bar".into(), RestrictedExpr::val(-1)),
                // note that `pancakes` is not an attribute. Also note that, in
                // this non-schema world, tags need not all have the same type.
                (
                    "pancakes".into(),
                    RestrictedExpr::val(EntityUID::with_eid("pancakes")),
                ),
            ],
            Extensions::all_available(),
        )
        .unwrap();
        let entities = Entities::from_entities(
            [
                complicated_entity,
                Entity::with_uid(EntityUID::with_eid("parent1")),
                Entity::with_uid(EntityUID::with_eid("parent2")),
            ],
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::all_available(),
        )
        .expect("Failed to construct entities");
        assert_eq!(
            entities,
            roundtrip(&entities).expect("should roundtrip without errors")
        );

        let oops_entity = Entity::new(
            EntityUID::with_eid("oops"),
            [(
                // record literal that happens to look like an escape
                "oops".into(),
                RestrictedExpr::record([("__entity".into(), RestrictedExpr::val("hi"))]).unwrap(),
            )],
            HashSet::new(),
            [
                EntityUID::with_eid("parent1"),
                EntityUID::with_eid("parent2"),
            ]
            .into_iter()
            .collect(),
            [],
            Extensions::all_available(),
        )
        .unwrap();
        let entities = Entities::from_entities(
            [
                oops_entity,
                Entity::with_uid(EntityUID::with_eid("parent1")),
                Entity::with_uid(EntityUID::with_eid("parent2")),
            ],
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::all_available(),
        )
        .expect("Failed to construct entities");
        assert_matches!(
            roundtrip(&entities),
            Err(EntitiesError::Serialization(JsonSerializationError::ReservedKey(reserved))) if reserved.key().as_ref() == "__entity"
        );
    }

    /// test that an Action having a non-Action parent is an error
    #[test]
    fn bad_action_parent() {
        let json = serde_json::json!(
            [
                {
                    "uid": { "type": "XYZ::Action", "id": "view" },
                    "attrs": {},
                    "parents": [
                        { "type": "User", "id": "alice" }
                    ]
                }
            ]
        );
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        assert_matches!(eparser.from_json_value(json.clone()), Err(e) => {
            expect_err(
                &json,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"action `XYZ::Action::"view"` has a non-action parent `User::"alice"`"#)
                    .help(r#"parents of actions need to have type `Action` themselves, perhaps namespaced"#)
                    .build()
            );
        });
    }

    /// test that non-Action having an Action parent is not an error
    /// (not sure if this was intentional? but it's the current behavior, and if
    /// that behavior changes, we want to know)
    #[test]
    fn not_bad_action_parent() {
        let json = serde_json::json!(
            [
                {
                    "uid": { "type": "User", "id": "alice" },
                    "attrs": {},
                    "parents": [
                        { "type": "XYZ::Action", "id": "view" },
                    ]
                }
            ]
        );
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        eparser
            .from_json_value(json)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)));
    }

    /// test that duplicate keys in a record is an error
    #[test]
    fn duplicate_keys() {
        // this test uses string JSON because it needs to specify JSON containing duplicate
        // keys, and the `json!` macro would already eliminate the duplicate keys
        let json = r#"
            [
                {
                    "uid": { "type": "User", "id": "alice "},
                    "attrs": {
                        "foo": {
                            "hello": "goodbye",
                            "bar": 2,
                            "spam": "eggs",
                            "bar": 3
                        }
                    },
                    "parents": []
                }
            ]
        "#;
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        assert_matches!(eparser.from_json_str(json), Err(e) => {
            // TODO(#599): put the line-column information in `Diagnostic::labels()` instead of printing it in the error message
            expect_err(
                json,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"the key `bar` occurs two or more times in the same JSON object at line 11 column 25"#)
                    .build()
            );
        });
    }

    #[test]
    fn multi_arg_ext_func_calls() {
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);

        let json = serde_json::json!(
            {
                "uid": { "type": "User", "id": "alice "},
                    "attrs": {
                        "time": { "__extn": { "fn": "offset", "args": [{ "__extn": { "fn": "datetime", "arg": "1970-01-01" }}, { "__extn": { "fn": "duration", "arg": "1h" } }]}}
                    },
                    "parents": []
            }
        );

        assert_matches!(eparser.single_from_json_value(json), Ok(entity) => {
            assert_matches!(entity.get("time"), Some(PartialValue::Value(Value { value: ValueKind::ExtensionValue(v), .. })) => {
                assert_eq!(v.func, "offset".parse().unwrap());
                assert_eq!(v.args[0].to_string(), r#"datetime("1970-01-01")"#);
                assert_eq!(v.args[1].to_string(), r#"duration("3600000ms")"#);
            });
        });

        // It appears that additional attributes are simply ignored
        // PR #1697 doesn't alter this behavior
        let json = serde_json::json!(
            {
                "uid": { "type": "User", "id": "alice "},
                    "attrs": {
                        "time": { "__extn": { "fn": "offset", "args": [{ "__extn": { "fn": "datetime", "arg": "1970-01-01" }}, { "__extn": { "fn": "duration", "arg": "1h" } }], "aaargs": 42}}
                    },
                    "parents": []
            }
        );

        assert_matches!(eparser.single_from_json_value(json), Ok(entity) => {
            assert_matches!(entity.get("time"), Some(PartialValue::Value(Value { value: ValueKind::ExtensionValue(v), .. })) => {
                assert_eq!(v.func, "offset".parse().unwrap());
                assert_eq!(v.args[0].to_string(), r#"datetime("1970-01-01")"#);
                assert_eq!(v.args[1].to_string(), r#"duration("3600000ms")"#);
            });
        });
    }
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
#[allow(clippy::cognitive_complexity)]
#[cfg(test)]
mod entities_tests {
    use super::*;
    use cool_asserts::assert_matches;

    #[test]
    fn empty_entities() {
        let e = Entities::new();
        assert!(
            e.iter().next().is_none(),
            "The entity store should be empty"
        );
    }

    /// helper function
    fn test_entities() -> (Entity, Entity, Entity, Entity) {
        (
            Entity::with_uid(EntityUID::with_eid("test_principal")),
            Entity::with_uid(EntityUID::with_eid("test_action")),
            Entity::with_uid(EntityUID::with_eid("test_resource")),
            Entity::with_uid(EntityUID::with_eid("test")),
        )
    }

    #[test]
    fn test_len() {
        let (e0, e1, e2, e3) = test_entities();
        let v = vec![e0, e1, e2, e3];
        let es = Entities::from_entities(
            v,
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::all_available(),
        )
        .expect("Failed to construct entities");
        assert_eq!(es.len(), 4);
        assert!(!es.is_empty());
    }

    #[test]
    fn test_is_empty() {
        let es = Entities::from_entities(
            vec![],
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::all_available(),
        )
        .expect("Failed to construct entities");
        assert_eq!(es.len(), 0);
        assert!(es.is_empty());
    }

    #[test]
    fn test_iter() {
        let (e0, e1, e2, e3) = test_entities();
        let v = vec![e0.clone(), e1.clone(), e2.clone(), e3.clone()];
        let es = Entities::from_entities(
            v,
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::all_available(),
        )
        .expect("Failed to construct entities");
        let es_v = es.iter().collect::<Vec<_>>();
        assert!(es_v.len() == 4, "All entities should be in the vec");
        assert!(es_v.contains(&&e0));
        assert!(es_v.contains(&&e1));
        assert!(es_v.contains(&&e2));
        assert!(es_v.contains(&&e3));
    }

    #[test]
    fn test_enforce_already_computed_fail() {
        // Hierarchy
        // a -> b -> c
        // This isn't transitively closed, so it should fail
        let mut e1 = Entity::with_uid(EntityUID::with_eid("a"));
        let mut e2 = Entity::with_uid(EntityUID::with_eid("b"));
        let e3 = Entity::with_uid(EntityUID::with_eid("c"));
        e1.add_parent(EntityUID::with_eid("b"));
        e2.add_parent(EntityUID::with_eid("c"));

        let es = Entities::from_entities(
            vec![e1, e2, e3],
            None::<&NoEntitiesSchema>,
            TCComputation::EnforceAlreadyComputed,
            Extensions::all_available(),
        );
        match es {
            Ok(_) => panic!("Was not transitively closed!"),
            Err(EntitiesError::TransitiveClosureError(_)) => (),
            Err(_) => panic!("Wrong Error!"),
        };
    }

    #[test]
    fn test_enforce_already_computed_succeed() {
        // Hierarchy
        // a -> b -> c
        // a -> c
        // This is transitively closed, so it should succeed
        let mut e1 = Entity::with_uid(EntityUID::with_eid("a"));
        let mut e2 = Entity::with_uid(EntityUID::with_eid("b"));
        let e3 = Entity::with_uid(EntityUID::with_eid("c"));
        e1.add_parent(EntityUID::with_eid("b"));
        e1.add_indirect_ancestor(EntityUID::with_eid("c"));
        e2.add_parent(EntityUID::with_eid("c"));

        Entities::from_entities(
            vec![e1, e2, e3],
            None::<&NoEntitiesSchema>,
            TCComputation::EnforceAlreadyComputed,
            Extensions::all_available(),
        )
        .expect("Should have succeeded");
    }

    #[test]
    fn test_remove_entities() {
        // Original Hierarchy
        // F -> A
        // F -> D -> A, D -> B, D -> C
        // F -> E -> C
        let aid = EntityUID::with_eid("A");
        let a = Entity::with_uid(aid.clone());
        let bid = EntityUID::with_eid("B");
        let b = Entity::with_uid(bid.clone());
        let cid = EntityUID::with_eid("C");
        let c = Entity::with_uid(cid.clone());
        let did = EntityUID::with_eid("D");
        let mut d = Entity::with_uid(did.clone());
        let eid = EntityUID::with_eid("E");
        let mut e = Entity::with_uid(eid.clone());
        let fid = EntityUID::with_eid("F");
        let mut f = Entity::with_uid(fid.clone());
        f.add_parent(aid.clone());
        f.add_parent(did.clone());
        f.add_parent(eid.clone());
        d.add_parent(aid.clone());
        d.add_parent(bid.clone());
        d.add_parent(cid.clone());
        e.add_parent(cid.clone());

        // Construct original hierarchy
        let entities = Entities::from_entities(
            vec![a, b, c, d, e, f],
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::all_available(),
        )
        .expect("Failed to construct entities")
        // Remove D from hierarchy
        .remove_entities(vec![EntityUID::with_eid("D")], TCComputation::ComputeNow)
        .expect("Failed to remove entities");
        // Post-Removal Hierarchy
        // F -> A
        // F -> E -> C
        // B

        assert_matches!(entities.entity(&did), Dereference::NoSuchEntity);

        let e = entities.entity(&eid).unwrap();
        let f = entities.entity(&fid).unwrap();

        // Assert the existence of these edges in the hierarchy
        assert!(f.is_descendant_of(&aid));
        assert!(f.is_descendant_of(&eid));
        assert!(f.is_descendant_of(&cid));
        assert!(e.is_descendant_of(&cid));

        // Assert that there is no longer an edge from F to B
        // as the only link was through D
        assert!(!f.is_descendant_of(&bid));
    }

    #[test]
    fn test_upsert_entities() {
        // Original Hierarchy
        // F -> A
        // F -> D -> A, D -> B, D -> C
        // F -> E -> C
        let aid = EntityUID::with_eid("A");
        let a = Entity::with_uid(aid.clone());
        let bid = EntityUID::with_eid("B");
        let b = Entity::with_uid(bid.clone());
        let cid = EntityUID::with_eid("C");
        let c = Entity::with_uid(cid.clone());
        let did = EntityUID::with_eid("D");
        let mut d = Entity::with_uid(did.clone());
        let eid = EntityUID::with_eid("E");
        let mut e = Entity::with_uid(eid.clone());
        let fid = EntityUID::with_eid("F");
        let mut f = Entity::with_uid(fid.clone());
        f.add_parent(aid.clone());
        f.add_parent(did);
        f.add_parent(eid.clone());
        d.add_parent(aid);
        d.add_parent(bid);
        d.add_parent(cid.clone());
        e.add_parent(cid.clone());

        let mut f_updated = Entity::with_uid(fid.clone());
        f_updated.add_parent(cid.clone());

        let gid = EntityUID::with_eid("G");
        let mut g = Entity::with_uid(gid.clone());
        g.add_parent(fid.clone());

        let updates = vec![f_updated, g]
            .into_iter()
            .map(Arc::new)
            .collect::<Vec<_>>();
        // Construct original hierarchy
        let entities = Entities::from_entities(
            vec![a, b, c, d, e, f],
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::all_available(),
        )
        .expect("Failed to construct entities")
        // Apply updates
        .upsert_entities(
            updates,
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::all_available(),
        )
        .expect("Failed to remove entities");
        // Post-Update Hierarchy
        // G -> F -> C
        // D -> A, D -> B, D -> C
        // E -> C

        let g = entities.entity(&gid).unwrap();
        let f = entities.entity(&fid).unwrap();

        // Assert the existence of these edges in the hierarchy
        assert!(f.is_descendant_of(&cid));
        assert!(g.is_descendant_of(&cid));
        assert!(g.is_descendant_of(&fid));

        // Assert that there is no longer an edge from F to E
        assert!(!f.is_descendant_of(&eid));
    }
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
#[allow(clippy::cognitive_complexity)]
#[cfg(test)]
mod schema_based_parsing_tests {
    use super::json::NullEntityTypeDescription;
    use super::*;
    use crate::extensions::Extensions;
    use crate::test_utils::*;
    use cool_asserts::assert_matches;
    use nonempty::NonEmpty;
    use serde_json::json;
    use smol_str::SmolStr;
    use std::collections::{BTreeMap, HashSet};
    use std::sync::Arc;

    /// Mock schema impl used for most of these tests
    struct MockSchema;
    impl Schema for MockSchema {
        type EntityTypeDescription = MockEmployeeDescription;
        type ActionEntityIterator = std::iter::Empty<Arc<Entity>>;
        fn entity_type(&self, entity_type: &EntityType) -> Option<MockEmployeeDescription> {
            match entity_type.to_string().as_str() {
                "Employee" => Some(MockEmployeeDescription),
                _ => None,
            }
        }
        fn action(&self, action: &EntityUID) -> Option<Arc<Entity>> {
            match action.to_string().as_str() {
                r#"Action::"view""# => Some(Arc::new(Entity::new_with_attr_partial_value(
                    action.clone(),
                    [(SmolStr::from("foo"), PartialValue::from(34))],
                    HashSet::new(),
                    HashSet::from([r#"Action::"readOnly""#.parse().expect("valid uid")]),
                    [],
                ))),
                r#"Action::"readOnly""# => Some(Arc::new(Entity::with_uid(action.clone()))),
                _ => None,
            }
        }
        fn entity_types_with_basename<'a>(
            &'a self,
            basename: &'a UnreservedId,
        ) -> Box<dyn Iterator<Item = EntityType> + 'a> {
            match basename.as_ref() {
                "Employee" => Box::new(std::iter::once(EntityType::from(Name::unqualified_name(
                    basename.clone(),
                )))),
                "Action" => Box::new(std::iter::once(EntityType::from(Name::unqualified_name(
                    basename.clone(),
                )))),
                _ => Box::new(std::iter::empty()),
            }
        }
        fn action_entities(&self) -> Self::ActionEntityIterator {
            std::iter::empty()
        }
    }

    /// Mock schema impl with an entity type that doesn't have a tags declaration
    struct MockSchemaNoTags;
    impl Schema for MockSchemaNoTags {
        type EntityTypeDescription = NullEntityTypeDescription;
        type ActionEntityIterator = std::iter::Empty<Arc<Entity>>;
        fn entity_type(&self, entity_type: &EntityType) -> Option<NullEntityTypeDescription> {
            match entity_type.to_string().as_str() {
                "Employee" => Some(NullEntityTypeDescription::new("Employee".parse().unwrap())),
                _ => None,
            }
        }
        fn action(&self, action: &EntityUID) -> Option<Arc<Entity>> {
            match action.to_string().as_str() {
                r#"Action::"view""# => Some(Arc::new(Entity::with_uid(
                    r#"Action::"view""#.parse().expect("valid uid"),
                ))),
                _ => None,
            }
        }
        fn entity_types_with_basename<'a>(
            &'a self,
            basename: &'a UnreservedId,
        ) -> Box<dyn Iterator<Item = EntityType> + 'a> {
            match basename.as_ref() {
                "Employee" => Box::new(std::iter::once(EntityType::from(Name::unqualified_name(
                    basename.clone(),
                )))),
                "Action" => Box::new(std::iter::once(EntityType::from(Name::unqualified_name(
                    basename.clone(),
                )))),
                _ => Box::new(std::iter::empty()),
            }
        }
        fn action_entities(&self) -> Self::ActionEntityIterator {
            std::iter::empty()
        }
    }

    /// Mock schema impl for the `Employee` type used in most of these tests
    struct MockEmployeeDescription;
    impl EntityTypeDescription for MockEmployeeDescription {
        fn enum_entity_eids(&self) -> Option<NonEmpty<Eid>> {
            None
        }
        fn entity_type(&self) -> EntityType {
            EntityType::from(Name::parse_unqualified_name("Employee").expect("valid"))
        }

        fn attr_type(&self, attr: &str) -> Option<SchemaType> {
            let employee_ty = || SchemaType::Entity {
                ty: self.entity_type(),
            };
            let hr_ty = || SchemaType::Entity {
                ty: EntityType::from(Name::parse_unqualified_name("HR").expect("valid")),
            };
            match attr {
                "isFullTime" => Some(SchemaType::Bool),
                "numDirectReports" => Some(SchemaType::Long),
                "department" => Some(SchemaType::String),
                "manager" => Some(employee_ty()),
                "hr_contacts" => Some(SchemaType::Set {
                    element_ty: Box::new(hr_ty()),
                }),
                "json_blob" => Some(SchemaType::Record {
                    attrs: [
                        ("inner1".into(), AttributeType::required(SchemaType::Bool)),
                        ("inner2".into(), AttributeType::required(SchemaType::String)),
                        (
                            "inner3".into(),
                            AttributeType::required(SchemaType::Record {
                                attrs: BTreeMap::from([(
                                    "innerinner".into(),
                                    AttributeType::required(employee_ty()),
                                )]),
                                open_attrs: false,
                            }),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                    open_attrs: false,
                }),
                "home_ip" => Some(SchemaType::Extension {
                    name: Name::parse_unqualified_name("ipaddr").expect("valid"),
                }),
                "work_ip" => Some(SchemaType::Extension {
                    name: Name::parse_unqualified_name("ipaddr").expect("valid"),
                }),
                "trust_score" => Some(SchemaType::Extension {
                    name: Name::parse_unqualified_name("decimal").expect("valid"),
                }),
                "tricky" => Some(SchemaType::Record {
                    attrs: [
                        ("type".into(), AttributeType::required(SchemaType::String)),
                        ("id".into(), AttributeType::required(SchemaType::String)),
                    ]
                    .into_iter()
                    .collect(),
                    open_attrs: false,
                }),
                "start_date" => Some(SchemaType::Extension {
                    name: Name::parse_unqualified_name("datetime").expect("valid"),
                }),
                _ => None,
            }
        }

        fn tag_type(&self) -> Option<SchemaType> {
            Some(SchemaType::Set {
                element_ty: Box::new(SchemaType::String),
            })
        }

        fn required_attrs(&self) -> Box<dyn Iterator<Item = SmolStr>> {
            Box::new(
                [
                    "isFullTime",
                    "numDirectReports",
                    "department",
                    "manager",
                    "hr_contacts",
                    "json_blob",
                    "home_ip",
                    "work_ip",
                    "trust_score",
                ]
                .map(SmolStr::new_static)
                .into_iter(),
            )
        }

        fn allowed_parent_types(&self) -> Arc<HashSet<EntityType>> {
            Arc::new(HashSet::new())
        }

        fn open_attributes(&self) -> bool {
            false
        }
    }

    #[cfg(all(feature = "decimal", feature = "ipaddr"))]
    /// JSON that should parse differently with and without the above schema
    #[test]
    fn with_and_without_schema() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" },
                        "start_date": { "fn": "offset", "args": [
                            {"fn": "datetime", "arg": "1970-01-01"},
                            {"fn": "duration", "arg": "1h"}
                        ]}
                    },
                    "parents": [],
                    "tags": {
                        "someTag": ["pancakes"],
                    },
                }
            ]
        );
        // without schema-based parsing, `home_ip` and `trust_score` are
        // strings, `manager` and `work_ip` are Records, `hr_contacts` contains
        // Records, and `json_blob.inner3.innerinner` is a Record
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let parsed = eparser
            .from_json_value(entitiesjson.clone())
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)));
        assert_eq!(parsed.iter().count(), 1);
        let parsed = parsed
            .entity(&r#"Employee::"12UA45""#.parse().unwrap())
            .expect("that should be the employee id");
        let home_ip = parsed.get("home_ip").expect("home_ip attr should exist");
        assert_matches!(
            home_ip,
            &PartialValue::Value(Value {
                value: ValueKind::Lit(Literal::String(_)),
                ..
            }),
        );
        let trust_score = parsed
            .get("trust_score")
            .expect("trust_score attr should exist");
        assert_matches!(
            trust_score,
            &PartialValue::Value(Value {
                value: ValueKind::Lit(Literal::String(_)),
                ..
            }),
        );
        let manager = parsed.get("manager").expect("manager attr should exist");
        assert_matches!(
            manager,
            &PartialValue::Value(Value {
                value: ValueKind::Record(_),
                ..
            })
        );
        let work_ip = parsed.get("work_ip").expect("work_ip attr should exist");
        assert_matches!(
            work_ip,
            &PartialValue::Value(Value {
                value: ValueKind::Record(_),
                ..
            })
        );
        let hr_contacts = parsed
            .get("hr_contacts")
            .expect("hr_contacts attr should exist");
        assert_matches!(hr_contacts, PartialValue::Value(Value { value: ValueKind::Set(set), .. }) => {
            let contact = set.iter().next().expect("should be at least one contact");
            assert_matches!(contact, &Value { value: ValueKind::Record(_), .. });
        });
        let json_blob = parsed
            .get("json_blob")
            .expect("json_blob attr should exist");
        assert_matches!(json_blob, PartialValue::Value(Value { value: ValueKind::Record(record), .. }) => {
            let (_, inner1) = record
                .iter()
                .find(|(k, _)| *k == "inner1")
                .expect("inner1 attr should exist");
            assert_matches!(inner1, Value { value: ValueKind::Lit(Literal::Bool(_)), .. });
            let (_, inner3) = record
                .iter()
                .find(|(k, _)| *k == "inner3")
                .expect("inner3 attr should exist");
            assert_matches!(inner3, Value { value: ValueKind::Record(innerrecord), .. } => {
                let (_, innerinner) = innerrecord
                    .iter()
                    .find(|(k, _)| *k == "innerinner")
                    .expect("innerinner attr should exist");
                assert_matches!(innerinner, Value { value: ValueKind::Record(_), .. });
            });
        });
        // but with schema-based parsing, we get these other types
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        let parsed = eparser
            .from_json_value(entitiesjson)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)));
        assert_eq!(parsed.iter().count(), 1);
        let parsed = parsed
            .entity(&r#"Employee::"12UA45""#.parse().unwrap())
            .expect("that should be the employee id");
        let is_full_time = parsed
            .get("isFullTime")
            .expect("isFullTime attr should exist");
        assert_eq!(is_full_time, &PartialValue::Value(Value::from(true)),);
        let some_tag = parsed
            .get_tag("someTag")
            .expect("someTag attr should exist");
        assert_eq!(
            some_tag,
            &PartialValue::Value(Value::set(["pancakes".into()], None))
        );
        let num_direct_reports = parsed
            .get("numDirectReports")
            .expect("numDirectReports attr should exist");
        assert_eq!(num_direct_reports, &PartialValue::Value(Value::from(3)),);
        let department = parsed
            .get("department")
            .expect("department attr should exist");
        assert_eq!(department, &PartialValue::Value(Value::from("Sales")),);
        let manager = parsed.get("manager").expect("manager attr should exist");
        assert_eq!(
            manager,
            &PartialValue::Value(Value::from(
                "Employee::\"34FB87\"".parse::<EntityUID>().expect("valid")
            )),
        );
        let hr_contacts = parsed
            .get("hr_contacts")
            .expect("hr_contacts attr should exist");
        assert_matches!(hr_contacts, PartialValue::Value(Value { value: ValueKind::Set(set), .. }) => {
            let contact = set.iter().next().expect("should be at least one contact");
            assert_matches!(contact, &Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. });
        });
        let json_blob = parsed
            .get("json_blob")
            .expect("json_blob attr should exist");
        assert_matches!(json_blob, PartialValue::Value(Value { value: ValueKind::Record(record), .. }) => {
            let (_, inner1) = record
                .iter()
                .find(|(k, _)| *k == "inner1")
                .expect("inner1 attr should exist");
            assert_matches!(inner1, Value { value: ValueKind::Lit(Literal::Bool(_)), .. });
            let (_, inner3) = record
                .iter()
                .find(|(k, _)| *k == "inner3")
                .expect("inner3 attr should exist");
            assert_matches!(inner3, Value { value: ValueKind::Record(innerrecord), .. } => {
                let (_, innerinner) = innerrecord
                    .iter()
                    .find(|(k, _)| *k == "innerinner")
                    .expect("innerinner attr should exist");
                assert_matches!(innerinner, Value { value: ValueKind::Lit(Literal::EntityUID(_)), .. });
            });
        });
        assert_eq!(
            parsed.get("home_ip").cloned().map(RestrictedExpr::try_from),
            Some(Ok(RestrictedExpr::call_extension_fn(
                Name::parse_unqualified_name("ip").expect("valid"),
                vec![RestrictedExpr::val("222.222.222.101")]
            ))),
        );
        assert_eq!(
            parsed.get("work_ip").cloned().map(RestrictedExpr::try_from),
            Some(Ok(RestrictedExpr::call_extension_fn(
                Name::parse_unqualified_name("ip").expect("valid"),
                vec![RestrictedExpr::val("2.2.2.0/24")]
            ))),
        );
        assert_eq!(
            parsed
                .get("trust_score")
                .cloned()
                .map(RestrictedExpr::try_from),
            Some(Ok(RestrictedExpr::call_extension_fn(
                Name::parse_unqualified_name("decimal").expect("valid"),
                vec![RestrictedExpr::val("5.7")]
            ))),
        );
    }

    #[cfg(all(feature = "decimal", feature = "ipaddr"))]
    /// simple type mismatch with expected type
    #[test]
    fn type_mismatch_string_long() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": "3",
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"in attribute `numDirectReports` on `Employee::"12UA45"`, type mismatch: value was expected to have type long, but it actually has type string: `"3"`"#)
                    .build()
            );
        });
    }

    #[cfg(all(feature = "decimal", feature = "ipaddr"))]
    /// another simple type mismatch with expected type
    #[test]
    fn type_mismatch_entity_record() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": "34FB87",
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"in attribute `manager` on `Employee::"12UA45"`, expected a literal entity reference, but got `"34FB87"`"#)
                    .help(r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#)
                    .build()
            );
        });
    }

    #[cfg(all(feature = "decimal", feature = "ipaddr"))]
    /// type mismatch where we expect a set and get just a single element
    #[test]
    fn type_mismatch_set_element() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": { "type": "HR", "id": "aaaaa" },
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"in attribute `hr_contacts` on `Employee::"12UA45"`, type mismatch: value was expected to have type [`HR`], but it actually has type record: `{"id": "aaaaa", "type": "HR"}`"#)
                    .build()
            );
        });
    }

    #[cfg(all(feature = "decimal", feature = "ipaddr"))]
    /// type mismatch where we just get the wrong entity type
    #[test]
    fn type_mismatch_entity_types() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "HR", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"in attribute `manager` on `Employee::"12UA45"`, type mismatch: value was expected to have type `Employee`, but it actually has type (entity of type `HR`): `HR::"34FB87"`"#)
                    .build()
            );
        });
    }

    #[cfg(all(feature = "decimal", feature = "ipaddr"))]
    /// type mismatch where we're expecting an extension type and get a
    /// different extension type
    #[test]
    fn type_mismatch_extension_types() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": { "fn": "decimal", "arg": "3.33" },
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"in attribute `home_ip` on `Employee::"12UA45"`, type mismatch: value was expected to have type ipaddr, but it actually has type decimal: `decimal("3.33")`"#)
                    .build()
            );
        });
    }

    #[cfg(all(feature = "decimal", feature = "ipaddr"))]
    #[test]
    fn missing_record_attr() {
        // missing a record attribute entirely
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"in attribute `json_blob` on `Employee::"12UA45"`, expected the record to have an attribute `inner2`, but it does not"#)
                    .build()
            );
        });
    }

    #[cfg(all(feature = "decimal", feature = "ipaddr"))]
    /// record attribute has the wrong type
    #[test]
    fn type_mismatch_in_record_attr() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": 33,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error_starts_with("entity does not conform to the schema")
                    .source(r#"in attribute `json_blob` on `Employee::"12UA45"`, type mismatch: value was expected to have type bool, but it actually has type long: `33`"#)
                    .build()
            );
        });

        // this version with explicit __entity and __extn escapes should also pass
        let entitiesjson = json!(
            [
                {
                    "uid": { "__entity": { "type": "Employee", "id": "12UA45" } },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "__entity": { "type": "Employee", "id": "34FB87" } },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": { "__extn": { "fn": "ip", "arg": "222.222.222.101" } },
                        "work_ip": { "__extn": { "fn": "ip", "arg": "2.2.2.0/24" } },
                        "trust_score": { "__extn": { "fn": "decimal", "arg": "5.7" } },
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let _ = eparser
            .from_json_value(entitiesjson)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)));
    }

    /// tag has the wrong type
    #[test]
    fn type_mismatch_in_tag() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": [],
                    "tags": {
                        "someTag": "pancakes",
                    }
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        let expected_error_msg =
            ExpectedErrorMessageBuilder::error_starts_with("error during entity deserialization")
                .source(r#"in tag `someTag` on `Employee::"12UA45"`, type mismatch: value was expected to have type [string], but it actually has type string: `"pancakes"`"#)
                .build();
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &expected_error_msg,
            );
        });
    }

    #[cfg(all(feature = "decimal", feature = "ipaddr"))]
    /// unexpected record attribute
    #[test]
    fn unexpected_record_attr() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                            "inner4": "wat?"
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"in attribute `json_blob` on `Employee::"12UA45"`, record attribute `inner4` should not exist according to the schema"#)
                    .build()
            );
        });
    }

    #[cfg(all(feature = "decimal", feature = "ipaddr"))]
    /// entity is missing a required attribute
    #[test]
    fn missing_required_attr() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"expected entity `Employee::"12UA45"` to have attribute `numDirectReports`, but it does not"#)
                    .build()
            );
        });
    }

    #[cfg(all(feature = "decimal", feature = "ipaddr"))]
    /// unexpected entity attribute
    #[test]
    fn unexpected_entity_attr() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" },
                        "wat": "???",
                    },
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"attribute `wat` on `Employee::"12UA45"` should not exist according to the schema"#)
                    .build()
            );
        });
    }

    /// unexpected entity tag
    #[test]
    fn unexpected_entity_tag() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {},
                    "parents": [],
                    "tags": {
                        "someTag": 12,
                    }
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchemaNoTags),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"found a tag `someTag` on `Employee::"12UA45"`, but no tags should exist on `Employee::"12UA45"` according to the schema"#)
                    .build()
            );
        });
    }

    #[cfg(all(feature = "decimal", feature = "ipaddr"))]
    /// Test that involves parents of wrong types
    #[test]
    fn parents_wrong_type() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": [
                        { "type": "Employee", "id": "34FB87" }
                    ]
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"`Employee::"12UA45"` is not allowed to have an ancestor of type `Employee` according to the schema"#)
                    .build()
            );
        });
    }

    /// Test that involves an entity type not declared in the schema
    #[test]
    fn undeclared_entity_type() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "CEO", "id": "abcdef" },
                    "attrs": {},
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"entity `CEO::"abcdef"` has type `CEO` which is not declared in the schema"#)
                    .build()
            );
        });
    }

    /// Test that involves an action not declared in the schema
    #[test]
    fn undeclared_action() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Action", "id": "update" },
                    "attrs": {},
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"found action entity `Action::"update"`, but it was not declared as an action in the schema"#)
                    .build()
            );
        });
    }

    /// Test that involves an action also declared (identically) in the schema
    #[test]
    fn action_declared_both_places() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Action", "id": "view" },
                    "attrs": {
                        "foo": 34
                    },
                    "parents": [
                        { "type": "Action", "id": "readOnly" }
                    ]
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        let entities = eparser
            .from_json_value(entitiesjson)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)));
        assert_eq!(entities.iter().count(), 1);
        let expected_uid = r#"Action::"view""#.parse().expect("valid uid");
        let parsed_entity = match entities.entity(&expected_uid) {
            Dereference::Data(e) => e,
            _ => panic!("expected entity to exist and be concrete"),
        };
        assert_eq!(parsed_entity.uid(), &expected_uid);
    }

    /// Test that involves an action also declared in the schema, but an attribute has a different value (of the same type)
    #[test]
    fn action_attr_wrong_val() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Action", "id": "view" },
                    "attrs": {
                        "foo": 6789
                    },
                    "parents": [
                        { "type": "Action", "id": "readOnly" }
                    ]
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"definition of action `Action::"view"` does not match its schema declaration"#)
                    .help(r#"to use the schema's definition of `Action::"view"`, simply omit it from the entities input data"#)
                    .build()
            );
        });
    }

    /// Test that involves an action also declared in the schema, but an attribute has a different type
    #[test]
    fn action_attr_wrong_type() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Action", "id": "view" },
                    "attrs": {
                        "foo": "bar"
                    },
                    "parents": [
                        { "type": "Action", "id": "readOnly" }
                    ]
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"definition of action `Action::"view"` does not match its schema declaration"#)
                    .help(r#"to use the schema's definition of `Action::"view"`, simply omit it from the entities input data"#)
                    .build()
            );
        });
    }

    /// Test that involves an action also declared in the schema, but the schema has an attribute that the JSON does not
    #[test]
    fn action_attr_missing_in_json() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Action", "id": "view" },
                    "attrs": {},
                    "parents": [
                        { "type": "Action", "id": "readOnly" }
                    ]
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"definition of action `Action::"view"` does not match its schema declaration"#)
                    .help(r#"to use the schema's definition of `Action::"view"`, simply omit it from the entities input data"#)
                    .build()
            );
        });
    }

    /// Test that involves an action also declared in the schema, but the JSON has an attribute that the schema does not
    #[test]
    fn action_attr_missing_in_schema() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Action", "id": "view" },
                    "attrs": {
                        "foo": "bar",
                        "wow": false
                    },
                    "parents": [
                        { "type": "Action", "id": "readOnly" }
                    ]
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"definition of action `Action::"view"` does not match its schema declaration"#)
                    .help(r#"to use the schema's definition of `Action::"view"`, simply omit it from the entities input data"#)
                    .build()
            );
        });
    }

    /// Test that involves an action also declared in the schema, but the schema has a parent that the JSON does not
    #[test]
    fn action_parent_missing_in_json() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Action", "id": "view" },
                    "attrs": {
                        "foo": 34
                    },
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"definition of action `Action::"view"` does not match its schema declaration"#)
                    .help(r#"to use the schema's definition of `Action::"view"`, simply omit it from the entities input data"#)
                    .build()
            );
        });
    }

    /// Test that involves an action also declared in the schema, but the JSON has a parent that the schema does not
    #[test]
    fn action_parent_missing_in_schema() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Action", "id": "view" },
                    "attrs": {
                        "foo": 34
                    },
                    "parents": [
                        { "type": "Action", "id": "readOnly" },
                        { "type": "Action", "id": "coolActions" }
                    ]
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"definition of action `Action::"view"` does not match its schema declaration"#)
                    .help(r#"to use the schema's definition of `Action::"view"`, simply omit it from the entities input data"#)
                    .build()
            );
        });
    }

    /// Test that involves namespaced entity types
    #[test]
    fn namespaces() {
        use std::str::FromStr;

        struct MockSchema;
        impl Schema for MockSchema {
            type EntityTypeDescription = MockEmployeeDescription;
            type ActionEntityIterator = std::iter::Empty<Arc<Entity>>;
            fn entity_type(&self, entity_type: &EntityType) -> Option<MockEmployeeDescription> {
                if &entity_type.to_string() == "XYZCorp::Employee" {
                    Some(MockEmployeeDescription)
                } else {
                    None
                }
            }
            fn action(&self, _action: &EntityUID) -> Option<Arc<Entity>> {
                None
            }
            fn entity_types_with_basename<'a>(
                &'a self,
                basename: &'a UnreservedId,
            ) -> Box<dyn Iterator<Item = EntityType> + 'a> {
                match basename.as_ref() {
                    "Employee" => Box::new(std::iter::once(EntityType::from(
                        Name::from_str("XYZCorp::Employee").expect("valid name"),
                    ))),
                    _ => Box::new(std::iter::empty()),
                }
            }
            fn action_entities(&self) -> Self::ActionEntityIterator {
                std::iter::empty()
            }
        }

        struct MockEmployeeDescription;
        impl EntityTypeDescription for MockEmployeeDescription {
            fn enum_entity_eids(&self) -> Option<NonEmpty<Eid>> {
                None
            }
            fn entity_type(&self) -> EntityType {
                "XYZCorp::Employee".parse().expect("valid")
            }

            fn attr_type(&self, attr: &str) -> Option<SchemaType> {
                match attr {
                    "isFullTime" => Some(SchemaType::Bool),
                    "department" => Some(SchemaType::String),
                    "manager" => Some(SchemaType::Entity {
                        ty: self.entity_type(),
                    }),
                    _ => None,
                }
            }

            fn tag_type(&self) -> Option<SchemaType> {
                None
            }

            fn required_attrs(&self) -> Box<dyn Iterator<Item = SmolStr>> {
                Box::new(
                    ["isFullTime", "department", "manager"]
                        .map(SmolStr::new_static)
                        .into_iter(),
                )
            }

            fn allowed_parent_types(&self) -> Arc<HashSet<EntityType>> {
                Arc::new(HashSet::new())
            }

            fn open_attributes(&self) -> bool {
                false
            }
        }

        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "XYZCorp::Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "department": "Sales",
                        "manager": { "type": "XYZCorp::Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        let parsed = eparser
            .from_json_value(entitiesjson)
            .unwrap_or_else(|e| panic!("{:?}", &miette::Report::new(e)));
        assert_eq!(parsed.iter().count(), 1);
        let parsed = parsed
            .entity(&r#"XYZCorp::Employee::"12UA45""#.parse().unwrap())
            .expect("that should be the employee type and id");
        let is_full_time = parsed
            .get("isFullTime")
            .expect("isFullTime attr should exist");
        assert_eq!(is_full_time, &PartialValue::from(true));
        let department = parsed
            .get("department")
            .expect("department attr should exist");
        assert_eq!(department, &PartialValue::from("Sales"),);
        let manager = parsed.get("manager").expect("manager attr should exist");
        assert_eq!(
            manager,
            &PartialValue::from(
                "XYZCorp::Employee::\"34FB87\""
                    .parse::<EntityUID>()
                    .expect("valid")
            ),
        );

        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "XYZCorp::Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );

        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"in attribute `manager` on `XYZCorp::Employee::"12UA45"`, type mismatch: value was expected to have type `XYZCorp::Employee`, but it actually has type (entity of type `Employee`): `Employee::"34FB87"`"#)
                    .build()
            );
        });

        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "department": "Sales",
                        "manager": { "type": "XYZCorp::Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );

        assert_matches!(eparser.from_json_value(entitiesjson.clone()), Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                    .source(r#"entity `Employee::"12UA45"` has type `Employee` which is not declared in the schema"#)
                    .help(r#"did you mean `XYZCorp::Employee`?"#)
                    .build()
            );
        });
    }

    #[test]
    fn enumerated_entities() {
        struct MockSchema;
        struct StarTypeDescription;
        impl EntityTypeDescription for StarTypeDescription {
            fn entity_type(&self) -> EntityType {
                "Star".parse().unwrap()
            }

            fn attr_type(&self, _attr: &str) -> Option<SchemaType> {
                None
            }

            fn tag_type(&self) -> Option<SchemaType> {
                None
            }

            fn required_attrs<'s>(&'s self) -> Box<dyn Iterator<Item = SmolStr> + 's> {
                Box::new(std::iter::empty())
            }

            fn allowed_parent_types(&self) -> Arc<HashSet<EntityType>> {
                Arc::new(HashSet::new())
            }

            fn open_attributes(&self) -> bool {
                false
            }

            fn enum_entity_eids(&self) -> Option<NonEmpty<Eid>> {
                Some(nonempty::nonempty![Eid::new("🌎"), Eid::new("🌕"),])
            }
        }
        impl Schema for MockSchema {
            type EntityTypeDescription = StarTypeDescription;

            type ActionEntityIterator = std::iter::Empty<Arc<Entity>>;

            fn entity_type(&self, entity_type: &EntityType) -> Option<Self::EntityTypeDescription> {
                if entity_type == &"Star".parse::<EntityType>().unwrap() {
                    Some(StarTypeDescription)
                } else {
                    None
                }
            }

            fn action(&self, _action: &EntityUID) -> Option<Arc<Entity>> {
                None
            }

            fn entity_types_with_basename<'a>(
                &'a self,
                basename: &'a UnreservedId,
            ) -> Box<dyn Iterator<Item = EntityType> + 'a> {
                if basename == &"Star".parse::<UnreservedId>().unwrap() {
                    Box::new(std::iter::once("Star".parse::<EntityType>().unwrap()))
                } else {
                    Box::new(std::iter::empty())
                }
            }

            fn action_entities(&self) -> Self::ActionEntityIterator {
                std::iter::empty()
            }
        }

        let eparser = EntityJsonParser::new(
            Some(&MockSchema),
            Extensions::none(),
            TCComputation::ComputeNow,
        );

        assert_matches!(
            eparser.from_json_value(serde_json::json!([
                {
                    "uid": { "type": "Star", "id": "🌎" },
                    "attrs": {},
                    "parents": [],
                }
            ])),
            Ok(_)
        );

        let entitiesjson = serde_json::json!([
            {
                "uid": { "type": "Star", "id": "🪐" },
                "attrs": {},
                "parents": [],
            }
        ]);
        assert_matches!(eparser.from_json_value(entitiesjson.clone()),
        Err(e) => {
            expect_err(
                &entitiesjson,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                    .source(r#"entity `Star::"🪐"` is of an enumerated entity type, but `"🪐"` is not declared as a valid eid"#)
                    .help(r#"valid entity eids: "🌎", "🌕""#)
                    .build()
            );
        });
    }
}
