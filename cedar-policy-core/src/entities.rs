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

//! This module contains the `Entities` type and related functionality.

use crate::ast::*;
use crate::extensions::Extensions;
use crate::transitive_closure::{compute_tc, enforce_tc_and_dag};
use std::collections::{hash_map, HashMap};
use std::fmt::Write;
use std::sync::Arc;

use serde::Serialize;
use serde_with::serde_as;

mod conformance;
pub use conformance::*;
mod err;
pub use err::*;
mod json;
pub use json::*;

/// Represents an entity hierarchy, and allows looking up `Entity` objects by
/// UID.
//
/// Note that `Entities` is `Serialize`, but currently this is only used for the
/// FFI layer in DRT. All others use (and should use) the `from_json_*()` and
/// `write_to_json()` methods as necessary.
#[serde_as]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Entities {
    /// Serde cannot serialize a HashMap to JSON when the key to the map cannot
    /// be serialized to a JSON string. This is a limitation of the JSON format.
    /// `serde_as` annotation are used to serialize the data as associative
    /// lists instead.
    ///
    /// Important internal invariant: for any `Entities` object that exists, the
    /// the `ancestor` relation is transitively closed.
    #[serde_as(as = "Vec<(_, _)>")]
    entities: HashMap<EntityUID, Entity>,

    /// The mode flag determines whether this store functions as a partial store or
    /// as a fully concrete store.
    /// Mode::Concrete means that the store is fully concrete, and failed dereferences are an error.
    /// Mode::Partial means the store is partial, and failed dereferences result in a residual.
    #[serde(default)]
    #[serde(skip_deserializing)]
    #[serde(skip_serializing)]
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

    /// Get the `Entity` with the given UID, if any
    pub fn entity(&self, uid: &EntityUID) -> Dereference<'_, Entity> {
        match self.entities.get(uid) {
            Some(e) => Dereference::Data(e),
            None => match self.mode {
                Mode::Concrete => Dereference::NoSuchEntity,
                #[cfg(feature = "partial-eval")]
                Mode::Partial => Dereference::Residual(Expr::unknown(Unknown::new_with_type(
                    format!("{uid}"),
                    Type::Entity {
                        ty: uid.entity_type().clone(),
                    },
                ))),
            },
        }
    }

    /// Iterate over the `Entity`s in the `Entities`
    pub fn iter(&self) -> impl Iterator<Item = &Entity> {
        self.entities.values()
    }

    /// Adds the [`crate::ast::Entity`]s in the iterator to this [`Entities`].
    /// Fails if the passed iterator contains any duplicate entities with this structure,
    /// or if any error is encountered in the transitive closure computation.
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
        collection: impl IntoIterator<Item = Entity>,
        schema: Option<&impl Schema>,
        tc_computation: TCComputation,
        extensions: Extensions<'_>,
    ) -> Result<Self> {
        let checker = schema.map(|schema| EntitySchemaConformanceChecker::new(schema, extensions));
        for entity in collection.into_iter() {
            if let Some(checker) = checker.as_ref() {
                checker.validate_entity(&entity)?;
            }
            match self.entities.entry(entity.uid().clone()) {
                hash_map::Entry::Occupied(_) => {
                    return Err(EntitiesError::Duplicate(entity.uid().clone()))
                }
                hash_map::Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(entity);
                }
            }
        }
        match tc_computation {
            TCComputation::AssumeAlreadyComputed => (),
            TCComputation::EnforceAlreadyComputed => {
                enforce_tc_and_dag(&self.entities).map_err(Box::new)?
            }
            TCComputation::ComputeNow => compute_tc(&mut self.entities, true).map_err(Box::new)?,
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
    pub fn from_entities(
        entities: impl IntoIterator<Item = Entity>,
        schema: Option<&impl Schema>,
        tc_computation: TCComputation,
        extensions: Extensions<'_>,
    ) -> Result<Self> {
        let mut entity_map = create_entity_map(entities.into_iter())?;
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
                enforce_tc_and_dag(&entity_map).map_err(Box::new)?;
            }
            TCComputation::ComputeNow => {
                compute_tc(&mut entity_map, true).map_err(Box::new)?;
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
                    .map(|e| (e.uid().clone(), Arc::unwrap_or_clone(e))),
            );
        }
        Ok(Self {
            entities: entity_map,
            mode: Mode::default(),
        })
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

    /// Write entities into a DOT graph
    pub fn to_dot_str(&self) -> std::result::Result<String, std::fmt::Error> {
        let mut dot_str = String::new();
        // write prelude
        dot_str.write_str("strict digraph {\n\tordering=\"out\"\n\tnode[shape=box]\n")?;

        // From DOT language reference:
        // An ID is one of the following:
        // Any string of alphabetic ([a-zA-Z\200-\377]) characters, underscores ('_') or digits([0-9]), not beginning with a digit;
        // a numeral [-]?(.[0-9]⁺ | [0-9]⁺(.[0-9]*)? );
        // any double-quoted string ("...") possibly containing escaped quotes (\")¹;
        // an HTML string (<...>).
        // The best option to convert a `Name` or an `EntityUid` is to use double-quoted string.
        // The `escape_debug` method should be sufficient for our purpose.
        fn to_dot_id(v: &impl std::fmt::Display) -> String {
            format!("\"{}\"", v.to_string().escape_debug())
        }

        // write clusters (subgraphs)
        let entities_by_type = self.get_entities_by_entity_type();

        for (et, entities) in entities_by_type {
            dot_str.write_str(&format!(
                "\tsubgraph \"cluster_{et}\" {{\n\t\tlabel={}\n",
                to_dot_id(&et)
            ))?;
            for entity in entities {
                let euid = to_dot_id(&entity.uid());
                let label = format!(r#"[label={}]"#, to_dot_id(&entity.uid().eid()));
                dot_str.write_str(&format!("\t\t{euid} {label}\n"))?;
            }
            dot_str.write_str("\t}\n")?;
        }

        // adding edges
        for entity in self.iter() {
            for ancestor in entity.ancestors() {
                dot_str.write_str(&format!(
                    "\t{} -> {}\n",
                    to_dot_id(&entity.uid()),
                    to_dot_id(&ancestor)
                ))?;
            }
        }

        dot_str.write_str("}\n")?;
        Ok(dot_str)
    }
}

/// Create a map from EntityUids to Entities, erroring if there are any duplicates
fn create_entity_map(es: impl Iterator<Item = Entity>) -> Result<HashMap<EntityUID, Entity>> {
    let mut map = HashMap::new();
    for e in es {
        match map.entry(e.uid().clone()) {
            hash_map::Entry::Occupied(_) => return Err(EntitiesError::Duplicate(e.uid().clone())),
            hash_map::Entry::Vacant(v) => {
                v.insert(e);
            }
        };
    }
    Ok(map)
}

impl IntoIterator for Entities {
    type Item = Entity;

    type IntoIter = hash_map::IntoValues<EntityUID, Entity>;

    fn into_iter(self) -> Self::IntoIter {
        self.entities.into_values()
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
            e => panic!("unwrap() called on {:?}", e),
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
            e => panic!("expect() called on {:?}, msg: {msg}", e),
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
mod json_parsing_tests {

    use super::*;
    use crate::{extensions::Extensions, test_utils::*, transitive_closure::TcError};
    use cool_asserts::assert_matches;

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
        parser.from_json_value(v).unwrap();
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

        let addl_entities = parser.iter_from_json_value(new).unwrap();
        let err = simple_entities(&parser).add_entities(
            addl_entities,
            None::<&NoEntitiesSchema>,
            TCComputation::EnforceAlreadyComputed,
            Extensions::none(),
        );
        // Despite this being a cycle, alice doesn't have the appropriate edges to form the cycle, so we get this error
        let expected = TcError::MissingTcEdge {
            child: r#"Test::"janet""#.parse().unwrap(),
            parent: r#"Test::"george""#.parse().unwrap(),
            grandparent: r#"Test::"janet""#.parse().unwrap(),
        };
        assert_matches!(err, Err(EntitiesError::TransitiveClosureError(e)) => {
            assert_eq!(&expected, e.as_ref());
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

        let addl_entities = parser.iter_from_json_value(new).unwrap();
        let err = simple_entities(&parser).add_entities(
            addl_entities,
            None::<&NoEntitiesSchema>,
            TCComputation::EnforceAlreadyComputed,
            Extensions::all_available(),
        );
        let expected = TcError::MissingTcEdge {
            child: r#"Test::"janet""#.parse().unwrap(),
            parent: r#"Test::"george""#.parse().unwrap(),
            grandparent: r#"Test::"henry""#.parse().unwrap(),
        };
        assert_matches!(err, Err(EntitiesError::TransitiveClosureError(e)) => {
            assert_eq!(&expected, e.as_ref());
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

        let addl_entities = parser.iter_from_json_value(new).unwrap();
        let err = simple_entities(&parser).add_entities(
            addl_entities,
            None::<&NoEntitiesSchema>,
            TCComputation::EnforceAlreadyComputed,
            Extensions::all_available(),
        );
        let expected = TcError::MissingTcEdge {
            child: r#"Test::"jeff""#.parse().unwrap(),
            parent: r#"Test::"alice""#.parse().unwrap(),
            grandparent: r#"Test::"bob""#.parse().unwrap(),
        };
        assert_matches!(err, Err(EntitiesError::TransitiveClosureError(e)) => {
            assert_eq!(&expected, e.as_ref());
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

        let addl_entities = parser.iter_from_json_value(new).unwrap();
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

        let addl_entities = parser.iter_from_json_value(new).unwrap();
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

        let addl_entities = parser.iter_from_json_value(new).unwrap();
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

        let addl_entities = parser.iter_from_json_value(new).unwrap();
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
    fn add_duplicates_fail2() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let new = serde_json::json!([
            {"uid":{ "type" : "Test", "id" : "jeff" }, "attrs" : {}, "parents" : []},
            {"uid":{ "type" : "Test", "id" : "jeff" }, "attrs" : {}, "parents" : []}]);

        let addl_entities = parser.iter_from_json_value(new).unwrap();
        let err = simple_entities(&parser)
            .add_entities(
                addl_entities,
                None::<&NoEntitiesSchema>,
                TCComputation::ComputeNow,
                Extensions::all_available(),
            )
            .err()
            .unwrap();
        let expected = r#"Test::"jeff""#.parse().unwrap();
        assert_matches!(err, EntitiesError::Duplicate(e) => assert_eq!(e, expected));
    }

    #[test]
    fn add_duplicates_fail1() {
        let parser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let new = serde_json::json!([{"uid":{ "type": "Test", "id": "alice" }, "attrs" : {}, "parents" : []}]);
        let addl_entities = parser.iter_from_json_value(new).unwrap();
        let err = simple_entities(&parser).add_entities(
            addl_entities,
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::all_available(),
        );
        let expected = r#"Test::"alice""#.parse().unwrap();
        assert_matches!(err, Err(EntitiesError::Duplicate(e)) => assert_eq!(e, expected));
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
        parser.from_json_value(json).expect("JSON is correct")
    }

    /// Ensure the initial conditions of the entiites still hold
    fn simple_entities_still_sane(e: &Entities) {
        let bob = r#"Test::"bob""#.parse().unwrap();
        let alice = e.entity(&r#"Test::"alice""#.parse().unwrap()).unwrap();
        let bar = alice.get("bar").unwrap();
        assert_eq!(bar, &PartialValue::from(2));
        assert!(alice.is_descendant_of(&bob));
        let bob = e.entity(&bob).unwrap();
        assert!(bob.ancestors().collect::<Vec<_>>().is_empty());
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
            .expect("JSON is correct")
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
            }
            ]
        );

        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let es = eparser.from_json_value(json).expect("JSON is correct");

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
            expect_err(&json, &e, &ExpectedErrorMessage::error_and_help(
                r#"error during entity deserialization: in uid field of <unknown entity>, expected a literal entity reference, but got `"test_entity_type::\"Alice\""`"#,
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ));
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
            expect_err(&json, &e, &ExpectedErrorMessage::error_and_help(
                "error during entity deserialization: in uid field of <unknown entity>, the `__expr` escape is no longer supported",
                "to create an entity reference, use `__entity`; to create an extension value, use `__extn`; and for all other values, use JSON directly",
            ));
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
            expect_err(&json, &e, &ExpectedErrorMessage::error_and_help(
                r#"error during entity deserialization: in attribute `pancakes` on `test_entity_type::"Alice"`, the `__expr` escape is no longer supported"#,
                "to create an entity reference, use `__entity`; to create an extension value, use `__extn`; and for all other values, use JSON directly",
            ));
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
            expect_err(&json, &e, &ExpectedErrorMessage::error_and_help(
                r#"error during entity deserialization: in parents field of `test_entity_type::"Alice"`, the `__expr` escape is no longer supported"#,
                "to create an entity reference, use `__entity`; to create an extension value, use `__extn`; and for all other values, use JSON directly",
            ));
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
            expect_err(&json, &e, &ExpectedErrorMessage::error_and_help(
                r#"error during entity deserialization: in parents field of `test_entity_type::"Alice"`, expected a literal entity reference, but got `"test_entity_type::\"bob\""`"#,
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ));
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
        let es = eparser.from_json_value(json).expect("JSON is correct");

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
        let es = eparser.from_json_value(json).expect("JSON is correct");

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
            expect_err(&json, &e, &ExpectedErrorMessage::error_and_help(
                r#"in uid field of <unknown entity>, expected a literal entity reference, but got `"hello"`"#,
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ));
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
            expect_err(&json, &e, &ExpectedErrorMessage::error_and_help(
                r#"in uid field of <unknown entity>, expected a literal entity reference, but got `"\"hello\""`"#,
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ));
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
            expect_err(&json, &e, &ExpectedErrorMessage::error_and_help(
                r#"in uid field of <unknown entity>, expected a literal entity reference, but got `{"spam":"eggs","type":"foo"}`"#,
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ));
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
            expect_err(&json, &e, &ExpectedErrorMessage::error(
                r#"invalid type: string "foo::\"help\"", expected a sequence"#
            ));
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
            expect_err(&json, &e, &ExpectedErrorMessage::error_and_help(
                r#"in parents field of `foo::"bar"`, expected a literal entity reference, but got `"foo::\"help\""`"#,
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ));
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
    fn test_entities() -> (Entity, Entity, Entity, Entity) {
        (
            Entity::with_uid(EntityUID::with_eid("test_principal")),
            Entity::with_uid(EntityUID::with_eid("test_action")),
            Entity::with_uid(EntityUID::with_eid("test_resource")),
            Entity::with_uid(EntityUID::with_eid("test")),
        )
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

        let (e0, e1, e2, e3) = test_entities();
        let entities = Entities::from_entities(
            [e0, e1, e2, e3],
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
            ]
            .into_iter()
            .collect(),
            [
                EntityUID::with_eid("parent1"),
                EntityUID::with_eid("parent2"),
            ]
            .into_iter()
            .collect(),
            &Extensions::all_available(),
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
            )]
            .into_iter()
            .collect(),
            [
                EntityUID::with_eid("parent1"),
                EntityUID::with_eid("parent2"),
            ]
            .into_iter()
            .collect(),
            &Extensions::all_available(),
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
            Err(EntitiesError::Serialization(JsonSerializationError::ReservedKey { key })) if key.as_str() == "__entity"
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
            expect_err(&json, &e, &ExpectedErrorMessage::error_and_help(
                r#"error during entity deserialization: action `XYZ::Action::"view"` has a non-action parent `User::"alice"`"#,
                "parents of actions need to have type `Action` themselves, perhaps namespaced",
            ));
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
        assert_matches!(eparser.from_json_value(json), Ok(_));
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
            expect_err(json, &e, &ExpectedErrorMessage::error(
                r#"error during entity deserialization: the key `bar` occurs two or more times in the same JSON object at line 11 column 25"# // TODO: put the line-column information in `Diagnostic::labels()` instead of printing it in the error message
            ));
        });
    }
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
#[cfg(test)]
// PANIC SAFETY unit tests
#[allow(clippy::panic)]
mod entities_tests {
    use super::*;

    #[test]
    fn empty_entities() {
        let e = Entities::new();
        let es = e.iter().collect::<Vec<_>>();
        assert!(es.is_empty(), "This vec should be empty");
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
        e1.add_ancestor(EntityUID::with_eid("b"));
        e2.add_ancestor(EntityUID::with_eid("c"));

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
        e1.add_ancestor(EntityUID::with_eid("b"));
        e1.add_ancestor(EntityUID::with_eid("c"));
        e2.add_ancestor(EntityUID::with_eid("c"));

        Entities::from_entities(
            vec![e1, e2, e3],
            None::<&NoEntitiesSchema>,
            TCComputation::EnforceAlreadyComputed,
            Extensions::all_available(),
        )
        .expect("Should have succeeded");
    }
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
#[cfg(test)]
mod schema_based_parsing_tests {
    use super::*;
    use crate::extensions::Extensions;
    use crate::test_utils::*;
    use cool_asserts::assert_matches;
    use serde_json::json;
    use smol_str::SmolStr;
    use std::collections::HashSet;
    use std::sync::Arc;

    /// Mock schema impl used for these tests
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
                    [(SmolStr::from("foo"), PartialValue::from(34))]
                        .into_iter()
                        .collect(),
                    [r#"Action::"readOnly""#.parse().expect("valid uid")]
                        .into_iter()
                        .collect(),
                ))),
                r#"Action::"readOnly""# => Some(Arc::new(Entity::with_uid(
                    r#"Action::"readOnly""#.parse().expect("valid uid"),
                ))),
                _ => None,
            }
        }
        fn entity_types_with_basename<'a>(
            &'a self,
            basename: &'a Id,
        ) -> Box<dyn Iterator<Item = EntityType> + 'a> {
            match basename.as_ref() {
                "Employee" => Box::new(std::iter::once(EntityType::Specified(
                    Name::unqualified_name(basename.clone()),
                ))),
                "Action" => Box::new(std::iter::once(EntityType::Specified(
                    Name::unqualified_name(basename.clone()),
                ))),
                _ => Box::new(std::iter::empty()),
            }
        }
        fn action_entities(&self) -> Self::ActionEntityIterator {
            std::iter::empty()
        }
    }

    /// Mock schema impl for the `Employee` type used in these tests
    struct MockEmployeeDescription;
    impl EntityTypeDescription for MockEmployeeDescription {
        fn entity_type(&self) -> EntityType {
            EntityType::Specified(Name::parse_unqualified_name("Employee").expect("valid"))
        }

        fn attr_type(&self, attr: &str) -> Option<SchemaType> {
            let employee_ty = || SchemaType::Entity {
                ty: self.entity_type(),
            };
            let hr_ty = || SchemaType::Entity {
                ty: EntityType::Specified(Name::parse_unqualified_name("HR").expect("valid")),
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
                                attrs: [(
                                    "innerinner".into(),
                                    AttributeType::required(employee_ty()),
                                )]
                                .into_iter()
                                .collect(),
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
                _ => None,
            }
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
                .map(SmolStr::new)
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
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
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
            .expect("Should parse without error");
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
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 1);
        let parsed = parsed
            .entity(&r#"Employee::"12UA45""#.parse().unwrap())
            .expect("that should be the employee id");
        let is_full_time = parsed
            .get("isFullTime")
            .expect("isFullTime attr should exist");
        assert_eq!(is_full_time, &PartialValue::Value(Value::from(true)),);
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error(
                r#"entity does not conform to the schema: in attribute `numDirectReports` on `Employee::"12UA45"`, type mismatch: value was expected to have type long, but actually has type string: `"3"`"#
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error_and_help(
                r#"error during entity deserialization: in attribute `manager` on `Employee::"12UA45"`, expected a literal entity reference, but got `"34FB87"`"#,
                r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#,
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error(
                r#"error during entity deserialization: in attribute `hr_contacts` on `Employee::"12UA45"`, type mismatch: value was expected to have type (set of `HR`), but actually has type record with attributes: {"id" => (optional) string, "type" => (optional) string}: `{"id": "aaaaa", "type": "HR"}`"#
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error(
                r#"entity does not conform to the schema: in attribute `manager` on `Employee::"12UA45"`, type mismatch: value was expected to have type `Employee`, but actually has type `HR`: `HR::"34FB87"`"#
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error(
                r#"entity does not conform to the schema: in attribute `home_ip` on `Employee::"12UA45"`, type mismatch: value was expected to have type ipaddr, but actually has type decimal: `decimal("3.33")`"#
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error(
                r#"error during entity deserialization: in attribute `json_blob` on `Employee::"12UA45"`, expected the record to have an attribute `inner2`, but it does not"#
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error_starts_with(
                r#"entity does not conform to the schema: in attribute `json_blob` on `Employee::"12UA45"`, type mismatch: value was expected to have type record with attributes: "#
            ));
        });

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
            .expect("this version with explicit __entity and __extn escapes should also pass");
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error(
                r#"error during entity deserialization: in attribute `json_blob` on `Employee::"12UA45"`, record attribute `inner4` should not exist according to the schema"#
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error(
                r#"entity does not conform to the schema: expected entity `Employee::"12UA45"` to have attribute `numDirectReports`, but it does not"#
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error(
                r#"error during entity deserialization: attribute `wat` on `Employee::"12UA45"` should not exist according to the schema"#
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error(
                r#"entity does not conform to the schema: `Employee::"12UA45"` is not allowed to have an ancestor of type `Employee` according to the schema"#
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error(
                r#"error during entity deserialization: entity `CEO::"abcdef"` has type `CEO` which is not declared in the schema"#
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error(
                r#"error during entity deserialization: found action entity `Action::"update"`, but it was not declared as an action in the schema"#
            ));
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
            .expect("should parse sucessfully");
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error_and_help(
                r#"entity does not conform to the schema: definition of action `Action::"view"` does not match its schema declaration"#,
                r#"to use the schema's definition of `Action::"view"`, simply omit it from the entities input data"#,
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error_and_help(
                r#"entity does not conform to the schema: definition of action `Action::"view"` does not match its schema declaration"#,
                r#"to use the schema's definition of `Action::"view"`, simply omit it from the entities input data"#,
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error_and_help(
                r#"entity does not conform to the schema: definition of action `Action::"view"` does not match its schema declaration"#,
                r#"to use the schema's definition of `Action::"view"`, simply omit it from the entities input data"#,
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error_and_help(
                r#"error during entity deserialization: definition of action `Action::"view"` does not match its schema declaration"#,
                r#"to use the schema's definition of `Action::"view"`, simply omit it from the entities input data"#,
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error_and_help(
                r#"entity does not conform to the schema: definition of action `Action::"view"` does not match its schema declaration"#,
                r#"to use the schema's definition of `Action::"view"`, simply omit it from the entities input data"#,
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error_and_help(
                r#"entity does not conform to the schema: definition of action `Action::"view"` does not match its schema declaration"#,
                r#"to use the schema's definition of `Action::"view"`, simply omit it from the entities input data"#,
            ));
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
                basename: &'a Id,
            ) -> Box<dyn Iterator<Item = EntityType> + 'a> {
                match basename.as_ref() {
                    "Employee" => Box::new(std::iter::once(EntityType::Specified(
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
            fn entity_type(&self) -> EntityType {
                EntityType::Specified("XYZCorp::Employee".parse().expect("valid"))
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

            fn required_attrs(&self) -> Box<dyn Iterator<Item = SmolStr>> {
                Box::new(
                    ["isFullTime", "department", "manager"]
                        .map(SmolStr::new)
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
            .expect("Should parse without error");
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error(
                r#"entity does not conform to the schema: in attribute `manager` on `XYZCorp::Employee::"12UA45"`, type mismatch: value was expected to have type `XYZCorp::Employee`, but actually has type `Employee`: `Employee::"34FB87"`"#
            ));
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
            expect_err(&entitiesjson, &e, &ExpectedErrorMessage::error_and_help(
                r#"error during entity deserialization: entity `Employee::"12UA45"` has type `Employee` which is not declared in the schema"#,
                "did you mean `XYZCorp::Employee`?",
            ));
        });
    }
}
