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
use crate::transitive_closure::{compute_tc, enforce_tc_and_dag};
use std::collections::{hash_map, HashMap};

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

mod err;
pub use err::*;
mod json;
pub use json::*;

/// Represents an entity hierarchy, and allows looking up `Entity` objects by
/// UID.
//
/// Note that `Entities` is `Serialize` and `Deserialize`, but currently this is
/// only used for the Dafny-FFI layer in DRT. All others use (and should use) the
/// `from_json_*()` and `write_to_json()` methods as necessary.
#[serde_as]
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
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
                Mode::Partial => Dereference::Residual(Expr::unknown(format!("{uid}"))),
            },
        }
    }

    /// Iterate over the `Entity`s in the `Entities`
    pub fn iter(&self) -> impl Iterator<Item = &Entity> {
        self.entities.values()
    }

    /// Create an `Entities` object with the given entities.
    ///
    /// If you pass `TCComputation::AssumeAlreadyComputed`, then the caller is
    /// responsible for ensuring that TC and DAG hold before calling this method.
    pub fn from_entities(
        entities: impl IntoIterator<Item = Entity>,
        tc_computation: TCComputation,
    ) -> Result<Self> {
        let mut entity_map = entities.into_iter().map(|e| (e.uid(), e)).collect();
        match tc_computation {
            TCComputation::AssumeAlreadyComputed => {}
            TCComputation::EnforceAlreadyComputed => {
                enforce_tc_and_dag(&entity_map).map_err(Box::new)?;
            }
            TCComputation::ComputeNow => {
                compute_tc(&mut entity_map, true).map_err(Box::new)?;
            }
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
        let ejsons: Vec<EntityJSON> = self.to_ejsons()?;
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
        let ejsons: Vec<EntityJSON> = self.to_ejsons()?;
        serde_json::to_writer_pretty(f, &ejsons).map_err(JsonSerializationError::from)?;
        Ok(())
    }

    /// Internal helper function to convert this `Entities` into a `Vec<EntityJSON>`
    fn to_ejsons(&self) -> Result<Vec<EntityJSON>> {
        self.entities
            .values()
            .map(EntityJSON::from_entity)
            .collect::<std::result::Result<_, JsonSerializationError>>()
            .map_err(Into::into)
    }
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

#[cfg(test)]
mod json_parsing_tests {
    use super::*;
    use crate::extensions::Extensions;

    #[test]
    fn basic_partial() {
        // Alice -> Jane -> Bob
        let json = serde_json::json!(
            [
            {
                "uid": { "__expr": "test_entity_type::\"alice\"" },
                "attrs": {},
                "parents": [
                { "__expr": "test_entity_type::\"jane\"" }
                ]
            },
            {
                "uid": { "__expr": "test_entity_type::\"jane\"" },
                "attrs": {},
                "parents": [
                { "__expr": "test_entity_type::\"bob\"" }
                ]
            },
            {
                "uid": { "__expr": "test_entity_type::\"bob\"" },
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

        assert!(matches!(janice, Dereference::Residual(_)));
    }

    #[test]
    fn basic() {
        // Alice -> Jane -> Bob
        let json = serde_json::json!(
            [
            {
                "uid": { "__expr": "test_entity_type::\"alice\"" },
                "attrs": {},
                "parents": [
                { "__expr": "test_entity_type::\"jane\"" }
                ]
            },
            {
                "uid": { "__expr": "test_entity_type::\"jane\"" },
                "attrs": {},
                "parents": [
                { "__expr": "test_entity_type::\"bob\"" }
                ]
            },
            {
                "uid": { "__expr": "test_entity_type::\"bob\"" },
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

    /// helper function which tests whether attribute values are shape-equal
    fn assert_attr_vals_are_shape_equal(
        actual: Option<&RestrictedExpr>,
        expected: &RestrictedExpr,
    ) {
        assert_eq!(
            actual.map(|re| RestrictedExprShapeOnly::new(re.as_borrowed())),
            Some(RestrictedExprShapeOnly::new(expected.as_borrowed()))
        )
    }

    /// this one uses `__expr`, `__entity`, and `__extn` escapes, in various positions
    #[test]
    fn more_escapes() {
        let json = serde_json::json!(
            [
            {
                "uid": { "__entity": { "type": "test_entity_type", "id": "alice" } },
                "attrs": {
                    "bacon": "eggs",
                    "pancakes": [1, 2, 3],
                    "waffles": { "key": "value" },
                    "toast": { "__expr": "decimal(\"33.47\")" },
                    "12345": { "__entity": { "type": "test_entity_type", "id": "bob" } },
                    "a b c": { "__extn": { "fn": "ip", "arg": "222.222.222.0/24" } }
                },
                "parents": [
                    { "__expr": "test_entity_type::\"bob\"" },
                    { "__entity": { "type": "test_entity_type", "id": "catherine" } }
                ]
            },
            {
                "uid": { "__expr": "test_entity_type::\"bob\"" },
                "attrs": {},
                "parents": []
            },
            {
                "uid": { "__expr": "test_entity_type::\"catherine\"" },
                "attrs": {},
                "parents": []
            }
            ]
        );

        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let es = eparser.from_json_value(json).expect("JSON is correct");

        let alice = es.entity(&EntityUID::with_eid("alice")).unwrap();
        assert_attr_vals_are_shape_equal(alice.get("bacon"), &RestrictedExpr::val("eggs"));
        assert_attr_vals_are_shape_equal(
            alice.get("pancakes"),
            &RestrictedExpr::set([
                RestrictedExpr::val(1),
                RestrictedExpr::val(2),
                RestrictedExpr::val(3),
            ]),
        );
        assert_attr_vals_are_shape_equal(
            alice.get("waffles"),
            &RestrictedExpr::record([("key".into(), RestrictedExpr::val("value"))]),
        );
        assert_attr_vals_are_shape_equal(
            alice.get("toast"),
            &RestrictedExpr::call_extension_fn(
                "decimal".parse().expect("should be a valid Name"),
                vec![RestrictedExpr::val("33.47")],
            ),
        );
        assert_attr_vals_are_shape_equal(
            alice.get("12345"),
            &RestrictedExpr::val(EntityUID::with_eid("bob")),
        );
        assert_attr_vals_are_shape_equal(
            alice.get("a b c"),
            &RestrictedExpr::call_extension_fn(
                "ip".parse().expect("should be a valid Name"),
                vec![RestrictedExpr::val("222.222.222.0/24")],
            ),
        );
        assert!(alice.is_descendant_of(&EntityUID::with_eid("bob")));
        assert!(alice.is_descendant_of(&EntityUID::with_eid("catherine")));
    }

    #[test]
    fn implicit_and_explicit_escapes() {
        // this one tests the implicit and explicit forms of `__expr` and `__entity` escapes
        // for the `uid` and `parents` fields
        let json = serde_json::json!(
            [
            {
                "uid": { "__expr": "test_entity_type::\"alice\"" },
                "attrs": {},
                "parents": [
                    { "__expr": "test_entity_type::\"bob\"" },
                    { "__entity": { "type": "test_entity_type", "id": "charles" } },
                    "test_entity_type::\"darwin\"",
                    { "type": "test_entity_type", "id": "elaine" }
                ]
            },
            {
                "uid": { "__entity": { "type": "test_entity_type", "id": "bob" }},
                "attrs": {},
                "parents": []
            },
            {
                "uid": "test_entity_type::\"charles\"",
                "attrs": {},
                "parents": []
            },
            {
                "uid": { "type": "test_entity_type", "id": "darwin" },
                "attrs": {},
                "parents": []
            },
            {
                "uid": { "type": "test_entity_type", "id": "elaine" },
                "attrs": {},
                "parents": [ "test_entity_type::\"darwin\"" ]
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
        let err = eparser
            .from_json_value(json)
            .expect_err("should be an invalid uid field");
        match err {
            EntitiesError::DeserializationError(err) => {
                assert!(
                    err.to_string().contains(
                        "In uid field of <unknown entity>, expected a literal entity reference, but got \"hello\""
                    ),
                    "actual error message was {}",
                    err
                )
            }
            _ => panic!("expected deserialization error, got a different error: {err}"),
        }

        let json = serde_json::json!(
            [
            {
                "uid": "\"hello\"",
                "attrs": {},
                "parents": []
            }
            ]
        );
        let err = eparser
            .from_json_value(json)
            .expect_err("should be an invalid uid field");
        match err {
            EntitiesError::DeserializationError(err) => assert!(
                err.to_string()
                    .contains("expected a literal entity reference, but got \"hello\""),
                "actual error message was {}",
                err
            ),
            _ => panic!("expected deserialization error, got a different error: {err}"),
        }

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "spam": "eggs" },
                "attrs": {},
                "parents": []
            }
            ]
        );
        let err = eparser
            .from_json_value(json)
            .expect_err("should be an invalid uid field");
        match err {
            EntitiesError::DeserializationError(err) => assert!(err
                .to_string()
                .contains("did not match any variant of untagged enum")),
            _ => panic!("expected deserialization error, got a different error: {err}"),
        }

        let json = serde_json::json!(
            [
            {
                "uid": { "type": "foo", "id": "bar" },
                "attrs": {},
                "parents": "foo::\"help\""
            }
            ]
        );
        let err = eparser
            .from_json_value(json)
            .expect_err("should be an invalid parents field");
        match err {
            EntitiesError::DeserializationError(err) => {
                assert!(err.to_string().contains("invalid type: string"))
            }
            _ => panic!("expected deserialization error, got a different error: {err}"),
        }

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
        let err = eparser
            .from_json_value(json)
            .expect_err("should be an invalid parents field");
        match err {
            EntitiesError::DeserializationError(err) => assert!(err
                .to_string()
                .contains("did not match any variant of untagged enum")),
            _ => panic!("expected deserialization error, got a different error: {err}"),
        }
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
        let entities = Entities::from_entities([e0, e1, e2, e3], TCComputation::ComputeNow)
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
                ("ham".into(), RestrictedExpr::val(r#"a b c * / ? \"#)),
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
                    ]),
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
        );
        let entities = Entities::from_entities(
            [
                complicated_entity,
                Entity::with_uid(EntityUID::with_eid("parent1")),
                Entity::with_uid(EntityUID::with_eid("parent2")),
            ],
            TCComputation::ComputeNow,
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
                RestrictedExpr::record([("__entity".into(), RestrictedExpr::val("hi"))]),
            )]
            .into_iter()
            .collect(),
            [
                EntityUID::with_eid("parent1"),
                EntityUID::with_eid("parent2"),
            ]
            .into_iter()
            .collect(),
        );
        let entities = Entities::from_entities(
            [
                oops_entity,
                Entity::with_uid(EntityUID::with_eid("parent1")),
                Entity::with_uid(EntityUID::with_eid("parent2")),
            ],
            TCComputation::ComputeNow,
        )
        .expect("Failed to construct entities");
        assert!(matches!(
            roundtrip(&entities),
            Err(EntitiesError::SerializationError(JsonSerializationError::ReservedKey { key })) if key.as_str() == "__entity"
        ));
    }
}

#[cfg(test)]
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
        let es = Entities::from_entities(v, TCComputation::ComputeNow)
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

        let es = Entities::from_entities(vec![e1, e2, e3], TCComputation::EnforceAlreadyComputed);
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

        Entities::from_entities(vec![e1, e2, e3], TCComputation::EnforceAlreadyComputed)
            .expect("Should have succeeded");
    }
}

#[cfg(test)]
mod schema_based_parsing_tests {
    use super::*;
    use crate::extensions::Extensions;
    use serde_json::json;
    use smol_str::SmolStr;

    /// Mock schema impl used for these tests
    struct MockSchema;
    impl Schema for MockSchema {
        fn attr_type(&self, entity_type: &EntityType, attr: &str) -> Option<SchemaType> {
            let employee_ty = || SchemaType::Entity {
                ty: EntityType::Concrete(Name::parse_unqualified_name("Employee").expect("valid")),
            };
            let hr_ty = || SchemaType::Entity {
                ty: EntityType::Concrete(Name::parse_unqualified_name("HR").expect("valid")),
            };
            match entity_type.to_string().as_str() {
                "Employee" => match attr {
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
                                }),
                            ),
                        ]
                        .into_iter()
                        .collect(),
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
                    }),
                    _ => None,
                },
                _ => None,
            }
        }

        fn required_attrs(&self, _entity_type: &EntityType) -> Box<dyn Iterator<Item = SmolStr>> {
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
    }

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
        assert!(matches!(
            home_ip.expr_kind(),
            &ExprKind::Lit(Literal::String(_)),
        ));
        let trust_score = parsed
            .get("trust_score")
            .expect("trust_score attr should exist");
        assert!(matches!(
            trust_score.expr_kind(),
            &ExprKind::Lit(Literal::String(_)),
        ));
        let manager = parsed.get("manager").expect("manager attr should exist");
        assert!(matches!(manager.expr_kind(), &ExprKind::Record { .. }));
        let work_ip = parsed.get("work_ip").expect("work_ip attr should exist");
        assert!(matches!(work_ip.expr_kind(), &ExprKind::Record { .. }));
        let hr_contacts = parsed
            .get("hr_contacts")
            .expect("hr_contacts attr should exist");
        assert!(matches!(hr_contacts.expr_kind(), &ExprKind::Set(_)));
        let contact = {
            let ExprKind::Set(set) = hr_contacts.expr_kind() else { panic!("already checked it was Set") };
            set.iter().next().expect("should be at least one contact")
        };
        assert!(matches!(contact.expr_kind(), &ExprKind::Record { .. }));
        let json_blob = parsed
            .get("json_blob")
            .expect("json_blob attr should exist");
        let ExprKind::Record { pairs } = json_blob.expr_kind() else { panic!("expected json_blob to be a Record") };
        let (_, inner1) = pairs
            .iter()
            .find(|(k, _)| k == "inner1")
            .expect("inner1 attr should exist");
        assert!(matches!(
            inner1.expr_kind(),
            &ExprKind::Lit(Literal::Bool(_))
        ));
        let (_, inner3) = pairs
            .iter()
            .find(|(k, _)| k == "inner3")
            .expect("inner3 attr should exist");
        assert!(matches!(inner3.expr_kind(), &ExprKind::Record { .. }));
        let ExprKind::Record { pairs: innerpairs } = inner3.expr_kind() else { panic!("already checked it was Record") };
        let (_, innerinner) = innerpairs
            .iter()
            .find(|(k, _)| k == "innerinner")
            .expect("innerinner attr should exist");
        assert!(matches!(innerinner.expr_kind(), &ExprKind::Record { .. }));

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
        assert_eq!(
            RestrictedExprShapeOnly::new(is_full_time.as_borrowed()),
            RestrictedExprShapeOnly::new(RestrictedExpr::val(true).as_borrowed())
        );
        let num_direct_reports = parsed
            .get("numDirectReports")
            .expect("numDirectReports attr should exist");
        assert_eq!(
            RestrictedExprShapeOnly::new(num_direct_reports.as_borrowed()),
            RestrictedExprShapeOnly::new(RestrictedExpr::val(3).as_borrowed())
        );
        let department = parsed
            .get("department")
            .expect("department attr should exist");
        assert_eq!(
            RestrictedExprShapeOnly::new(department.as_borrowed()),
            RestrictedExprShapeOnly::new(RestrictedExpr::val("Sales").as_borrowed())
        );
        let manager = parsed.get("manager").expect("manager attr should exist");
        assert_eq!(
            RestrictedExprShapeOnly::new(manager.as_borrowed()),
            RestrictedExprShapeOnly::new(
                RestrictedExpr::val("Employee::\"34FB87\"".parse::<EntityUID>().expect("valid"))
                    .as_borrowed()
            )
        );
        let hr_contacts = parsed
            .get("hr_contacts")
            .expect("hr_contacts attr should exist");
        assert!(matches!(hr_contacts.expr_kind(), &ExprKind::Set(_)));
        let contact = {
            let ExprKind::Set(set) = hr_contacts.expr_kind() else { panic!("already checked it was Set") };
            set.iter().next().expect("should be at least one contact")
        };
        assert!(matches!(
            contact.expr_kind(),
            &ExprKind::Lit(Literal::EntityUID(_))
        ));
        let json_blob = parsed
            .get("json_blob")
            .expect("json_blob attr should exist");
        let ExprKind::Record { pairs } = json_blob.expr_kind() else { panic!("expected json_blob to be a Record") };
        let (_, inner1) = pairs
            .iter()
            .find(|(k, _)| k == "inner1")
            .expect("inner1 attr should exist");
        assert!(matches!(
            inner1.expr_kind(),
            &ExprKind::Lit(Literal::Bool(_))
        ));
        let (_, inner3) = pairs
            .iter()
            .find(|(k, _)| k == "inner3")
            .expect("inner3 attr should exist");
        assert!(matches!(inner3.expr_kind(), &ExprKind::Record { .. }));
        let ExprKind::Record { pairs: innerpairs } = inner3.expr_kind() else { panic!("already checked it was Record") };
        let (_, innerinner) = innerpairs
            .iter()
            .find(|(k, _)| k == "innerinner")
            .expect("innerinner attr should exist");
        assert!(matches!(
            innerinner.expr_kind(),
            &ExprKind::Lit(Literal::EntityUID(_))
        ));
        assert_eq!(
            parsed.get("home_ip"),
            Some(&RestrictedExpr::call_extension_fn(
                Name::parse_unqualified_name("ip").expect("valid"),
                vec![RestrictedExpr::val("222.222.222.101")]
            )),
        );
        assert_eq!(
            parsed.get("work_ip"),
            Some(&RestrictedExpr::call_extension_fn(
                Name::parse_unqualified_name("ip").expect("valid"),
                vec![RestrictedExpr::val("2.2.2.0/24")]
            )),
        );
        assert_eq!(
            parsed.get("trust_score"),
            Some(&RestrictedExpr::call_extension_fn(
                Name::parse_unqualified_name("decimal").expect("valid"),
                vec![RestrictedExpr::val("5.7")]
            )),
        );
    }

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
        let err = eparser
            .from_json_value(entitiesjson)
            .expect_err("should fail due to type mismatch on numDirectReports");
        assert!(
            err.to_string().contains(r#"In attribute "numDirectReports" on Employee::"12UA45", type mismatch: attribute was expected to have type long, but actually has type string"#),
            "actual error message was {}",
            err
        );
    }

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
        let err = eparser
            .from_json_value(entitiesjson)
            .expect_err("should fail due to type mismatch on manager");
        assert!(
            err.to_string()
                .contains(r#"In attribute "manager" on Employee::"12UA45", expected a literal entity reference, but got "34FB87""#),
            "actual error message was {}",
            err
        );
    }

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
        let err = eparser
            .from_json_value(entitiesjson)
            .expect_err("should fail due to type mismatch on hr_contacts");
        assert!(
            err.to_string().contains(r#"In attribute "hr_contacts" on Employee::"12UA45", type mismatch: attribute was expected to have type (set of (entity of type HR)), but actually has type record"#),
            "actual error message was {}",
            err
        );
    }

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
        let err = eparser
            .from_json_value(entitiesjson)
            .expect_err("should fail due to type mismatch on manager");
        assert!(
            err.to_string().contains(r#"In attribute "manager" on Employee::"12UA45", type mismatch: attribute was expected to have type (entity of type Employee), but actually has type (entity of type HR)"#),
            "actual error message was {}",
            err
        );
    }

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
        let err = eparser
            .from_json_value(entitiesjson)
            .expect_err("should fail due to type mismatch on home_ip");
        assert!(
            err.to_string().contains(r#"In attribute "home_ip" on Employee::"12UA45", type mismatch: attribute was expected to have type ipaddr, but actually has type decimal"#),
            "actual error message was {}",
            err
        );
    }

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
        let err = eparser
            .from_json_value(entitiesjson)
            .expect_err("should fail due to missing attribute \"inner2\"");
        assert!(
            err.to_string().contains(r#"In attribute "json_blob" on Employee::"12UA45", expected the record to have an attribute "inner2", but it didn't"#),
            "actual error message was {}",
            err
        );
    }

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
        let err = eparser
            .from_json_value(entitiesjson)
            .expect_err("should fail due to type mismatch on attribute \"inner1\"");
        assert!(
            err.to_string().contains(r#"In attribute "json_blob" on Employee::"12UA45", type mismatch: attribute was expected to have type record with attributes: "#),
            "actual error message was {}",
            err
        );

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
        let err = eparser
            .from_json_value(entitiesjson)
            .expect_err("should fail due to unexpected attribute \"inner4\"");
        assert!(
            err.to_string().contains(r#"In attribute "json_blob" on Employee::"12UA45", record attribute "inner4" shouldn't exist"#),
            "actual error message was {}",
            err
        );
    }

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
        let err = eparser
            .from_json_value(entitiesjson)
            .expect_err("should fail due to missing attribute \"numDirectReports\"");
        assert!(
            err.to_string().contains(r#"Expected Employee::"12UA45" to have an attribute "numDirectReports", but it didn't"#),
            "actual error message was {}",
            err
        );
    }

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
        let err = eparser
            .from_json_value(entitiesjson)
            .expect_err("should fail due to unexpected attribute \"wat\"");
        assert!(
            err.to_string().contains(
                r#"Attribute "wat" on Employee::"12UA45" shouldn't exist according to the schema"#
            ),
            "actual error message was {}",
            err
        );
    }

    /// Test that involves namespaced entity types
    #[test]
    fn namespaces() {
        struct MockSchema;
        impl Schema for MockSchema {
            fn attr_type(&self, entity_type: &EntityType, attr: &str) -> Option<SchemaType> {
                match entity_type.to_string().as_str() {
                    "XYZCorp::Employee" => match attr {
                        "isFullTime" => Some(SchemaType::Bool),
                        "department" => Some(SchemaType::String),
                        "manager" => Some(SchemaType::Entity {
                            ty: EntityType::Concrete("XYZCorp::Employee".parse().expect("valid")),
                        }),
                        _ => None,
                    },
                    _ => None,
                }
            }

            fn required_attrs(
                &self,
                _entity_type: &EntityType,
            ) -> Box<dyn Iterator<Item = SmolStr>> {
                Box::new(
                    ["isFullTime", "department", "manager"]
                        .map(SmolStr::new)
                        .into_iter(),
                )
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
        assert_eq!(
            RestrictedExprShapeOnly::new(is_full_time.as_borrowed()),
            RestrictedExprShapeOnly::new(RestrictedExpr::val(true).as_borrowed())
        );
        let department = parsed
            .get("department")
            .expect("department attr should exist");
        assert_eq!(
            RestrictedExprShapeOnly::new(department.as_borrowed()),
            RestrictedExprShapeOnly::new(RestrictedExpr::val("Sales").as_borrowed())
        );
        let manager = parsed.get("manager").expect("manager attr should exist");
        assert_eq!(
            RestrictedExprShapeOnly::new(manager.as_borrowed()),
            RestrictedExprShapeOnly::new(
                RestrictedExpr::val(
                    "XYZCorp::Employee::\"34FB87\""
                        .parse::<EntityUID>()
                        .expect("valid")
                )
                .as_borrowed()
            )
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

        let err = eparser
            .from_json_value(entitiesjson)
            .expect_err("should fail due to manager being wrong entity type (missing namespace)");
        assert!(
            err.to_string().contains(r#"In attribute "manager" on XYZCorp::Employee::"12UA45", type mismatch: attribute was expected to have type (entity of type XYZCorp::Employee), but actually has type (entity of type Employee)"#),
            "actual error message was {}",
            err
        );
    }
}
