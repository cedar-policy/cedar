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

//! This module contains partial entities.

use crate::ast::{Entity, PartialValueToValueError};
use crate::entities::conformance::err::EntitySchemaConformanceError;
use crate::entities::err::Duplicate;
use crate::entities::SchemaType;
use crate::entities::{Dereference, Entities, TCComputation};
use crate::tpe::err::{
    AncestorValidationError, EntitiesConsistencyError, EntitiesError, EntityConsistencyError,
    EntityValidationError, JsonDeserializationError, MismatchedAncestorError,
    MismatchedAttributeError, MismatchedTagError, MissingEntityError, UnknownAttributeError,
    UnknownEntityError, UnknownTagError,
};
use crate::transitive_closure::{enforce_tc_and_dag, TcError};
use crate::validator::{
    CoreSchema, EntityTypeDescription as CoreEntityTypeDescription, ValidatorSchema,
};
use crate::{
    ast::PartialValue,
    entities::{conformance::EntitySchemaConformanceChecker, Schema},
};
use crate::{
    ast::{EntityUID, Value},
    entities::{
        json::{err::JsonDeserializationErrorContext, ValueParser},
        EntityUidJson,
    },
    evaluator::RestrictedEvaluator,
    extensions::Extensions,
    jsonvalue::JsonValueWithNoDuplicateKeys,
};
use crate::{
    entities::{conformance::validate_euid, EntityTypeDescription},
    transitive_closure::{compute_tc, repair_tc, TCNode},
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde_as]
#[serde(transparent)]
struct DeduplicatedMap {
    #[serde_as(as = "serde_with::MapPreventDuplicates<_,_>")]
    pub map: HashMap<SmolStr, JsonValueWithNoDuplicateKeys>,
}

/// Serde JSON format for a single entity
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EntityJson {
    /// UID of the entity, specified in any form accepted by `EntityUidJson`
    uid: EntityUidJson,
    /// attributes, whose values can be any JSON value.
    /// (Probably a `CedarValueJson`, but for schema-based parsing, it could for
    /// instance be an `EntityUidJson` if we're expecting an entity reference,
    /// so for now we leave it in its raw json-value form, albeit not allowing
    /// any duplicate keys in any records that may occur in an attribute value
    /// (even nested).)
    #[serde(default)]
    // the annotation covers duplicates in this `HashMap` itself, while the `JsonValueWithNoDuplicateKeys` covers duplicates in any records contained in attribute values (including recursively)
    attrs: Option<DeduplicatedMap>,
    #[serde(default)]
    /// Parents of the entity, specified in any form accepted by `EntityUidJson`
    parents: Option<Vec<EntityUidJson>>,
    #[serde(default)]
    // the annotation covers duplicates in this `HashMap` itself, while the `JsonValueWithNoDuplicateKeys` covers duplicates in any records contained in tag values (including recursively)
    // Note that unlike the concrete JSON entity format, when the `tags` field
    // is missing, it means `tags` are unknown
    // This is because we need to represent `tags` being unknowns
    tags: Option<DeduplicatedMap>,
}

/// The partial entity
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialEntity {
    // The uid of the partial entity
    uid: EntityUID,
    // Optional attributes
    attrs: Option<BTreeMap<SmolStr, Value>>,
    // Optional ancestors
    ancestors: Option<HashSet<EntityUID>>,
    // Optional tags
    tags: Option<BTreeMap<SmolStr, Value>>,
}

// An `Entity` without unknowns is a `PartialEntity`
impl TryFrom<Entity> for PartialEntity {
    type Error = PartialValueToValueError;
    fn try_from(value: Entity) -> Result<Self, Self::Error> {
        let uid = value.uid().clone();
        let attrs = value
            .attrs()
            .map(|(a, v)| Ok((a.clone(), Value::try_from(v.clone())?)))
            .collect::<Result<BTreeMap<_, _>, PartialValueToValueError>>()?;
        let ancestors = value.ancestors().cloned().collect();
        let tags = value
            .tags()
            .map(|(a, v)| Ok((a.clone(), Value::try_from(v.clone())?)))
            .collect::<Result<BTreeMap<_, _>, PartialValueToValueError>>()?;
        Ok(Self {
            uid,
            attrs: Some(attrs),
            ancestors: Some(ancestors),
            tags: Some(tags),
        })
    }
}

impl PartialEntity {
    /// Construct a new [`PartialEntity`]
    pub fn new(
        uid: EntityUID,
        attrs: Option<BTreeMap<SmolStr, Value>>,
        ancestors: Option<HashSet<EntityUID>>,
        tags: Option<BTreeMap<SmolStr, Value>>,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntitiesError> {
        let e = Self {
            uid,
            attrs,
            ancestors,
            tags,
        };
        e.validate(schema)?;
        Ok(e)
    }

    /// Get the uid of this partial entity
    pub fn uid(&self) -> &EntityUID {
        &self.uid
    }

    /// Get the optional attributes of this partial entity
    pub fn attrs(&self) -> Option<&BTreeMap<SmolStr, Value>> {
        self.attrs.as_ref()
    }

    /// Get the optional ancestors of this partial entity
    pub fn ancestors(&self) -> Option<&HashSet<EntityUID>> {
        self.ancestors.as_ref()
    }

    /// Get the optional tags of this partial entity
    pub fn tags(&self) -> Option<&BTreeMap<SmolStr, Value>> {
        self.tags.as_ref()
    }

    /// Check if an [`Entity`] is consistent with a [`PartialEntity`]
    pub(crate) fn check_consistency(&self, entity: &Entity) -> Result<(), EntityConsistencyError> {
        // `Entity` stores values as the old `PartialValue`, but we should never see the unknown here.
        fn as_values<'a>(
            pairs: impl Iterator<Item = (&'a SmolStr, &'a PartialValue)>,
        ) -> Result<BTreeMap<SmolStr, Value>, SmolStr> {
            pairs
                .map(|(a, pv)| match pv {
                    PartialValue::Value(v) => Ok((a.clone(), v.clone())),
                    PartialValue::Residual(_) => Err(a.clone()),
                })
                .collect()
        }

        if let Some(attrs) = &self.attrs {
            let other_attrs = as_values(entity.attrs()).map_err(|attr| UnknownAttributeError {
                uid: self.uid.clone(),
                attr,
            })?;
            if attrs != &other_attrs {
                return Err(MismatchedAttributeError {
                    uid: self.uid.clone(),
                }
                .into());
            }
        }
        if let Some(ancestors) = &self.ancestors {
            let other_ancestors: HashSet<EntityUID> = entity.ancestors().cloned().collect();
            if ancestors != &other_ancestors {
                return Err(MismatchedAncestorError {
                    uid: self.uid.clone(),
                }
                .into());
            }
        }
        if let Some(tags) = &self.tags {
            let other_tags = as_values(entity.tags()).map_err(|tag| UnknownTagError {
                uid: self.uid.clone(),
                tag,
            })?;
            if tags != &other_tags {
                return Err(MismatchedTagError {
                    uid: self.uid.clone(),
                }
                .into());
            }
        }
        Ok(())
    }
}

/// Parse a JSON map of attribute/tag values into concrete [`Value`]s.
///
/// `type_of` returns the expected [`SchemaType`] for a given key (tag or attribute). If `uid`'s
/// entity type is not declared in the schema, an `UnexpectedEntityType` error
/// is raised.
fn parse_value_map(
    map: DeduplicatedMap,
    uid: &EntityUID,
    core_schema: &CoreSchema<'_>,
    vparser: &ValueParser<'_>,
    type_of: impl Fn(&CoreEntityTypeDescription, &str) -> Option<SchemaType>,
) -> Result<BTreeMap<SmolStr, Value>, JsonDeserializationError> {
    let eval = RestrictedEvaluator::new(Extensions::all_available());
    let ty = core_schema.entity_type(uid.entity_type()).ok_or_else(|| {
        JsonDeserializationError::Concrete(
            EntitySchemaConformanceError::unexpected_entity_type(core_schema, uid.clone()).into(),
        )
    })?;
    map.map
        .into_iter()
        .map(|(k, v)| {
            let expr =
                vparser.val_into_restricted_expr(v.into(), type_of(&ty, &k).as_ref(), &|| {
                    JsonDeserializationErrorContext::EntityAttribute {
                        uid: uid.clone(),
                        attr: k.clone(),
                    }
                })?;
            Ok((k, eval.interpret(expr.as_borrowed())?))
        })
        .collect()
}

/// Parse an [`EntityJson`] into a [`PartialEntity`] according to `schema`
pub fn parse_ejson(
    e: EntityJson,
    schema: &ValidatorSchema,
) -> Result<PartialEntity, JsonDeserializationError> {
    let uid = e
        .uid
        .into_euid(&|| JsonDeserializationErrorContext::EntityUid)?;
    let core_schema = CoreSchema::new(schema);
    let is_action = uid.is_action();

    let vparser = ValueParser::new(Extensions::all_available());
    let attrs = e
        .attrs
        .map(|m| {
            if is_action {
                parse_action_value_map(m, &uid, &vparser)
            } else {
                parse_value_map(m, &uid, &core_schema, &vparser, |ty, k| ty.attr_type(k))
            }
        })
        .transpose()?;

    let ancestors = e
        .parents
        .map(|parents| {
            parents
                .into_iter()
                .map(|parent| {
                    let parent_euid = parent
                        .into_euid(&|| JsonDeserializationErrorContext::EntityParents {
                            uid: uid.clone(),
                        })
                        .map_err(JsonDeserializationError::Concrete)?;
                    if is_action && !parent_euid.is_action() {
                        return Err(JsonDeserializationError::Concrete(
                            crate::entities::json::err::JsonDeserializationError::action_parent_is_not_action(
                                uid.clone(),
                                parent_euid,
                            ),
                        ));
                    }
                    Ok(parent_euid)
                })
                .collect::<Result<HashSet<_>, _>>()
        })
        .transpose()?;

    let tags = e
        .tags
        .map(|m| {
            if is_action {
                parse_action_value_map(m, &uid, &vparser)
            } else {
                parse_value_map(m, &uid, &core_schema, &vparser, |ty, _| ty.tag_type())
            }
        })
        .transpose()?;

    Ok(PartialEntity {
        uid,
        attrs,
        ancestors,
        tags,
    })
}

/// Parse a JSON map of attribute/tag values for an action entity into concrete
/// [`Value`]s.
///
/// Unlike [`parse_value_map`], this does not look the entity type up in the
/// schema (action entity types are not in the schema's entity-type table) and
/// parses each value with no expected type, matching how concrete entity
/// parsing treats actions.
fn parse_action_value_map(
    map: DeduplicatedMap,
    uid: &EntityUID,
    vparser: &ValueParser<'_>,
) -> Result<BTreeMap<SmolStr, Value>, JsonDeserializationError> {
    let eval = RestrictedEvaluator::new(Extensions::all_available());
    map.map
        .into_iter()
        .map(|(k, v)| {
            let expr = vparser.val_into_restricted_expr(v.into(), None, &|| {
                JsonDeserializationErrorContext::EntityAttribute {
                    uid: uid.clone(),
                    attr: k.clone(),
                }
            })?;
            Ok((k, eval.interpret(expr.as_borrowed())?))
        })
        .collect()
}

impl TCNode<EntityUID> for PartialEntity {
    fn add_edge_to(&mut self, k: EntityUID) {
        self.add_ancestor(k);
    }

    fn get_key(&self) -> EntityUID {
        self.uid.clone()
    }

    fn has_edge_to(&self, k: &EntityUID) -> bool {
        match self.ancestors.as_ref() {
            Some(ancestors) => ancestors.contains(k),
            None => false,
        }
    }

    fn out_edges(&self) -> Box<dyn Iterator<Item = &EntityUID> + '_> {
        match self.ancestors.as_ref() {
            Some(ancestors) => Box::new(ancestors.iter()),
            None => Box::new(std::iter::empty()),
        }
    }

    fn reset_edges(&mut self) {}
}

impl PartialEntity {
    /// This method should be only called on entities that have known ancestors
    pub(crate) fn add_ancestor(&mut self, uid: EntityUID) {
        #[expect(
            clippy::expect_used,
            reason = "this method should be only called on entities that have known ancestors"
        )]
        self.ancestors
            .as_mut()
            .expect("should not be unknown")
            .insert(uid);
    }

    /// Validate `self` according to `schema`
    pub fn validate(&self, schema: &ValidatorSchema) -> Result<(), EntityValidationError> {
        let core_schema = CoreSchema::new(schema);
        let uid = &self.uid;
        let etype = uid.entity_type();

        if self.uid.is_action() {
            // Actions are defined by the schema: any known components must be
            // consistent with the schema's action (unknowns are allowed), and
            // construction then substitutes the schema's action (see
            // `insert_actions`).
            let Some(action) = core_schema.action(uid) else {
                return Err(EntitySchemaConformanceError::undeclared_action(uid.clone()).into());
            };
            if self.check_consistency(action.as_ref()).is_err() {
                return Err(
                    EntitySchemaConformanceError::action_declaration_mismatch(uid.clone()).into(),
                );
            }
            return Ok(());
        }
        validate_euid(&core_schema, uid).map_err(EntitySchemaConformanceError::from)?;
        let schema_etype = core_schema.entity_type(etype).ok_or_else(|| {
            EntitySchemaConformanceError::unexpected_entity_type(&core_schema, uid.clone())
        })?;
        let checker =
            EntitySchemaConformanceChecker::new(&core_schema, Extensions::all_available());
        if let Some(ancestors) = &self.ancestors {
            checker.validate_entity_ancestors(uid, ancestors.iter(), &schema_etype)?;
        }
        if let Some(attrs) = &self.attrs {
            let attrs: BTreeMap<_, PartialValue> = attrs
                .iter()
                .map(|(a, v)| (a.clone(), v.clone().into()))
                .collect();
            checker.validate_entity_attributes(uid, attrs.iter(), &schema_etype)?;
        }
        if let Some(tags) = &self.tags {
            let tags: BTreeMap<_, PartialValue> = tags
                .iter()
                .map(|(a, v)| (a.clone(), v.clone().into()))
                .collect();
            checker.validate_tags(uid, tags.iter(), &schema_etype)?;
        }
        Ok(())
    }
}

// Validate if ancestors are well-formed
// i.e., ancestors of any ancestor of a `PartialEntity` should not be unknown
// This ensures that we can always compute a TC for entities with concrete
// ancestors
pub(crate) fn validate_concrete_ancestors_concrete(
    entities: &HashMap<EntityUID, PartialEntity>,
) -> Result<(), AncestorValidationError> {
    for e in entities.values() {
        if let Some(ancestors) = e.ancestors.as_ref() {
            for ancestor in ancestors {
                if let Some(ancestor_entity) = entities.get(ancestor) {
                    if ancestor_entity.ancestors.is_none() {
                        return Err(AncestorValidationError {
                            uid: e.uid.clone(),
                            ancestor: ancestor.clone(),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

/// The partial entity store
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialEntities {
    /// Important internal invariant: for any `Entities` object that exists,
    /// the `ancestor` relation is transitively closed.
    entities: HashMap<EntityUID, PartialEntity>,
}

impl PartialEntities {
    /// Get an empty partial entities
    pub fn new() -> Self {
        Self::default()
    }

    /// Get an iterator of entities
    pub fn entities(&self) -> impl Iterator<Item = &PartialEntity> {
        self.entities.values()
    }

    /// Compute transitive closure
    pub fn compute_tc(&mut self) -> Result<(), TcError<EntityUID>> {
        compute_tc(&mut self.entities, true)
    }

    /// Check that the tc is computed and forms a dag
    pub fn enforce_tc_and_dag(&self) -> Result<(), TcError<EntityUID>> {
        enforce_tc_and_dag(&self.entities)
    }

    /// Get the `PartialEntity` with this identifier
    pub fn get(&self, euid: &EntityUID) -> Option<&PartialEntity> {
        self.entities.get(euid)
    }

    /// Get the ancestors for this `PartialEntity`
    ///
    /// Returns ancestors if this entity exists and its ancestors are known. TPE treats missing
    /// entity and unknown ancestors identically. If you need to distinguish them, get the full
    /// partial entity (if it exists) using [`PartialEntities::get`].
    pub fn get_ancestors(&self, euid: &EntityUID) -> Option<&HashSet<EntityUID>> {
        self.get(euid).and_then(|e| e.ancestors())
    }

    /// Check if there is a `PartialEntity` with identifier
    pub fn contains_entity(&self, euid: &EntityUID) -> bool {
        self.entities.contains_key(euid)
    }

    /// Shared internal constructor for building from maps. Validates each
    /// entity, concreteness of the ancestor hierarchy, and optionally compute
    /// the transitive closure. Also inserts actions entities from the schema.
    fn from_entities_map(
        entities: HashMap<EntityUID, PartialEntity>,
        schema: &ValidatorSchema,
        compute_tc: bool,
    ) -> Result<Self, EntitiesError> {
        entities.values().try_for_each(|e| e.validate(schema))?;
        validate_concrete_ancestors_concrete(&entities)?;
        let mut entities = Self { entities };
        if compute_tc {
            entities.compute_tc()?;
        }
        entities.insert_actions(schema);
        Ok(entities)
    }

    fn collect_unique(
        entities: impl Iterator<Item = PartialEntity>,
    ) -> Result<HashMap<EntityUID, PartialEntity>, EntitiesError> {
        let mut map: HashMap<EntityUID, PartialEntity> = HashMap::new();
        for entity in entities {
            match map.entry(entity.uid.clone()) {
                Entry::Vacant(e) => {
                    e.insert(entity);
                }
                Entry::Occupied(e) => {
                    return Err(Duplicate {
                        euid: e.key().clone(),
                    }
                    .into())
                }
            }
        }
        Ok(map)
    }

    /// Construct `PartialEntities` from `Entities`, ensuring that the entities are valid.
    /// TC is already computed in the source `Entities`, so we skip recomputation.
    pub fn from_concrete(
        entities: Entities,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntitiesError> {
        let entities_map: HashMap<EntityUID, PartialEntity> = entities
            .into_iter()
            .map(|e| e.try_into().map(|e: PartialEntity| (e.uid.clone(), e)))
            .try_collect()?;
        // TC is already computed in the source Entities — the conversion to
        // PartialEntity preserves all ancestors (direct + indirect).
        Self::from_entities_map(entities_map, schema, false)
    }

    /// Construct `PartialEntities` from an iterator
    pub fn from_entities(
        entity_mappings: impl Iterator<Item = PartialEntity>,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntitiesError> {
        Self::from_entities_map(Self::collect_unique(entity_mappings)?, schema, true)
    }

    /// Add a partial entity without checking if it conforms to the schema,
    /// assuming the TC is already computed.
    /// Errors on duplicate entries.
    pub(crate) fn add_entity_trusted(
        &mut self,
        uid: EntityUID,
        entity: PartialEntity,
    ) -> Result<(), EntitiesError> {
        match self.entities.entry(uid) {
            Entry::Vacant(e) => {
                e.insert(entity);
            }
            Entry::Occupied(e) => {
                return Err(Duplicate {
                    euid: e.key().clone(),
                }
                .into())
            }
        }

        Ok(())
    }

    /// Add a set of partial entities to this store,
    /// erroring on duplicates.
    pub fn add_entities(
        &mut self,
        entity_mappings: impl Iterator<Item = (EntityUID, PartialEntity)>,
        schema: &ValidatorSchema,
        tc_computation: TCComputation,
    ) -> Result<(), EntitiesError> {
        let mut entities_touched: HashSet<EntityUID> = HashSet::new();
        for (id, entity) in entity_mappings {
            entity.validate(schema)?;
            entities_touched.insert(id.clone());
            self.add_entity_trusted(id, entity)?;
        }

        validate_concrete_ancestors_concrete(&self.entities)?;

        match tc_computation {
            TCComputation::AssumeAlreadyComputed => (),
            TCComputation::EnforceAlreadyComputed => {
                self.enforce_tc_and_dag()?;
            }
            TCComputation::ComputeNow => {
                for entity in self.entities.values() {
                    if let Some(ancestors) = entity.ancestors.as_ref() {
                        if !entities_touched.is_disjoint(ancestors) {
                            entities_touched.insert(entity.uid.clone());
                        }
                    }
                }
                repair_tc(&entities_touched, &mut self.entities, true)?;
            }
        }
        Ok(())
    }

    // Insert action entities from the schema
    // Overwriting existing action entities is fine because they should come
    // from schema or be consistent with schema anyways
    fn insert_actions(&mut self, schema: &ValidatorSchema) {
        for (uid, action) in &schema.actions {
            self.entities.insert(
                uid.clone(),
                #[expect(
                    clippy::unwrap_used,
                    reason = "action entities do not contain unknowns"
                )]
                action.as_ref().clone().try_into().unwrap(),
            );
        }
    }

    /// Construct [`PartialEntities`] from a JSON list
    pub fn from_json_value(
        value: serde_json::Value,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntitiesError> {
        let entities: Vec<EntityJson> = serde_json::from_value(value)
            .map_err(|e| JsonDeserializationError::Concrete(e.into()))?;
        let parsed = entities
            .into_iter()
            .map(|e| parse_ejson(e, schema))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_entities_map(Self::collect_unique(parsed.into_iter())?, schema, true)
    }

    /// Check if [`PartialEntities`] are consistent with [`Entities`]
    pub fn check_consistency(&self, concrete: &Entities) -> Result<(), EntitiesConsistencyError> {
        for (uid, e) in &self.entities {
            match concrete.entity(uid) {
                Dereference::NoSuchEntity => {
                    return Err(MissingEntityError { uid: uid.clone() }.into());
                }
                Dereference::Residual(_) => {
                    return Err(UnknownEntityError { uid: uid.clone() }.into());
                }
                Dereference::Data(entity) => e.check_consistency(entity)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap, HashSet};

    use crate::entities::TCComputation;
    use crate::test_utils::{expect_err, ExpectedErrorMessageBuilder};
    use crate::tpe::err::AncestorValidationError;
    use crate::validator::ValidatorSchema;
    use crate::{
        ast::{EntityUID, Value},
        extensions::Extensions,
    };
    use cool_asserts::assert_matches;

    use super::{
        parse_ejson, validate_concrete_ancestors_concrete, EntityJson, PartialEntities,
        PartialEntity,
    };

    #[track_caller]
    fn basic_schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
        entity A {
            a? : String,
            b? : Long,
            c? : {"x" : Bool}
        } tags Long;
         action a appliesTo {
           principal : A,
           resource : A
         };
        "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    #[test]
    fn basic() {
        let schema = basic_schema();
        // unlike the existing JSON format, absence of `tags` or `tags` being
        // `null` means unknown tags, as opposed to empty tags
        let json = serde_json::json!(
            {
                "uid" : {
                    "type" : "A",
                    "id" : "",
                },
                "tags" : null,
            }
        );
        let ejson: EntityJson = serde_json::from_value(json).expect("should parse");
        assert_matches!(parse_ejson(ejson, &schema), Ok(e) => {
            assert_eq!(e, PartialEntity { uid: r#"A::"""#.parse().unwrap(), attrs: None, ancestors: None, tags: None });
        });

        // empty tags need to be specified explicitly
        let schema = basic_schema();
        let json = serde_json::json!(
            {
                "uid" : {
                    "type" : "A",
                    "id" : "",
                },
                "tags" : {},
            }
        );
        let ejson: EntityJson = serde_json::from_value(json).expect("should parse");
        assert_matches!(parse_ejson(ejson, &schema), Ok(e) => {
            assert_eq!(e, PartialEntity { uid: r#"A::"""#.parse().unwrap(), attrs: None, ancestors: None, tags: Some(BTreeMap::default()) });
        });

        let schema = basic_schema();
        let json = serde_json::json!(
            {
                "uid" : {
                    "type" : "A",
                    "id" : "",
                },
                "parents" : [],
                "attrs" : {},
                "tags" : {},
            }
        );
        let ejson: EntityJson = serde_json::from_value(json).expect("should parse");
        assert_matches!(parse_ejson(ejson, &schema), Ok(e) => {
            assert_eq!(e, PartialEntity { uid: r#"A::"""#.parse().unwrap(), attrs: Some(BTreeMap::new()), ancestors: Some(HashSet::default()), tags: Some(BTreeMap::default()) });
        });

        let schema = basic_schema();
        let json = serde_json::json!(
            {
                "uid" : {
                    "type" : "A",
                    "id" : "",
                },
                "parents" : [],
                "attrs" : {
                    "b" : 1,
                    "c" : {"x": false},
                },
                "tags" : {},
            }
        );
        let ejson: EntityJson = serde_json::from_value(json).expect("should parse");
        assert_matches!(parse_ejson(ejson, &schema), Ok(e) => {
            assert_eq!(e, PartialEntity { uid: r#"A::"""#.parse().unwrap(), attrs: Some(BTreeMap::from_iter([("b".into(), 1.into()), ("c".into(), Value::record(std::iter::once(("x", false)), None)
            )])), ancestors: Some(HashSet::default()), tags: Some(BTreeMap::default()) });
        });
    }

    #[track_caller]
    fn in_schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            "entity A in [A] = { a: Bool } tags Long;",
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    fn in_entity(id: &str, ancestors: HashSet<EntityUID>) -> PartialEntity {
        PartialEntity {
            uid: format!(r#"A::"{id}""#).parse().unwrap(),
            attrs: Some(BTreeMap::from_iter([("a".into(), Value::from(true))])),
            ancestors: Some(ancestors),
            tags: Some(BTreeMap::new()),
        }
    }

    #[test]
    fn duplicate_entities() {
        let dup = in_entity("foo", HashSet::new());
        let err = PartialEntities::from_entities(vec![dup.clone(), dup].into_iter(), &in_schema())
            .expect_err("should fail to construct");
        expect_err(
            "",
            &miette::Report::new(err),
            &ExpectedErrorMessageBuilder::error(r#"duplicate entity entry `A::"foo"`"#).build(),
        );
    }

    #[test]
    fn cyclic_hierarchy() {
        let a = in_entity("a", HashSet::from_iter([r#"A::"b""#.parse().unwrap()]));
        let b = in_entity("b", HashSet::from_iter([r#"A::"a""#.parse().unwrap()]));
        let err = PartialEntities::from_entities(vec![a, b].into_iter(), &in_schema())
            .expect_err("should fail to construct");
        expect_err(
            "",
            &miette::Report::new(err),
            &ExpectedErrorMessageBuilder::error_starts_with(
                "input graph has a cycle containing vertex",
            )
            .build(),
        );
    }

    #[test]
    fn missing_tc_edge() {
        // `a`'s ancestor `b` is not itself an ancestor of `a`, so enforcing an
        // already-computed TC should fail with a missing-edge error.
        let mut entities = PartialEntities::new();
        let a = in_entity("a", HashSet::from_iter([r#"A::"b""#.parse().unwrap()]));
        let b = in_entity("b", HashSet::from_iter([r#"A::"c""#.parse().unwrap()]));
        let c = in_entity("c", HashSet::new());
        let err = entities
            .add_entities(
                vec![a, b, c].into_iter().map(|e| (e.uid.clone(), e)),
                &in_schema(),
                TCComputation::EnforceAlreadyComputed,
            )
            .expect_err("should fail to construct");
        expect_err(
            "",
            &miette::Report::new(err),
            &ExpectedErrorMessageBuilder::error_starts_with(
                "expected all transitive edges to exist",
            )
            .build(),
        );
    }

    #[test]
    fn invalid_hierarchy() {
        let uid_a: EntityUID = r#"A::"a""#.parse().unwrap();
        let uid_b: EntityUID = r#"A::"b""#.parse().unwrap();
        assert_matches!(
            validate_concrete_ancestors_concrete(&HashMap::from_iter([
                (
                    uid_a.clone(),
                    PartialEntity {
                        uid: uid_a,
                        ancestors: Some(HashSet::from_iter([uid_b.clone()])),
                        attrs: None,
                        tags: None
                    }
                ),
                (
                    uid_b.clone(),
                    PartialEntity {
                        uid: uid_b,
                        ancestors: None,
                        attrs: None,
                        tags: None
                    }
                )
            ])),
            Err(AncestorValidationError { .. })
        )
    }

    #[test]
    fn tc_computation() {
        let a = PartialEntity {
            uid: r#"E::"a""#.parse().unwrap(),
            attrs: None,
            ancestors: Some(HashSet::from_iter([
                r#"E::"b""#.parse().unwrap(),
                r#"E::"c""#.parse().unwrap(),
            ])),
            tags: None,
        };
        let b = PartialEntity {
            uid: r#"E::"b""#.parse().unwrap(),
            attrs: None,
            ancestors: Some(HashSet::from_iter([r#"E::"d""#.parse().unwrap()])),
            tags: None,
        };
        let c = PartialEntity {
            uid: r#"E::"c""#.parse().unwrap(),
            attrs: None,
            ancestors: Some(HashSet::from_iter([r#"E::"e""#.parse().unwrap()])),
            tags: None,
        };
        let e = PartialEntity {
            uid: r#"E::"e""#.parse().unwrap(),
            attrs: None,
            ancestors: Some(HashSet::from_iter([r#"E::"f""#.parse().unwrap()])),
            tags: None,
        };
        let x = PartialEntity {
            uid: r#"E::"x""#.parse().unwrap(),
            attrs: None,
            ancestors: None,
            tags: None,
        };
        let mut entities = PartialEntities {
            entities: vec![a, b, c, e, x]
                .into_iter()
                .map(|e| (e.uid.clone(), e))
                .collect(),
        };
        entities.compute_tc().expect("should compute tc");
        assert_eq!(
            entities
                .entities
                .get(&r#"E::"a""#.parse().unwrap())
                .as_ref()
                .unwrap()
                .ancestors
                .clone()
                .unwrap(),
            HashSet::from_iter([
                r#"E::"b""#.parse().unwrap(),
                r#"E::"c""#.parse().unwrap(),
                r#"E::"d""#.parse().unwrap(),
                r#"E::"e""#.parse().unwrap(),
                r#"E::"f""#.parse().unwrap()
            ])
        );
        assert_eq!(
            entities
                .entities
                .get(&r#"E::"b""#.parse().unwrap())
                .as_ref()
                .unwrap()
                .ancestors
                .clone()
                .unwrap(),
            HashSet::from_iter([r#"E::"d""#.parse().unwrap(),])
        );
        assert_eq!(
            entities
                .entities
                .get(&r#"E::"c""#.parse().unwrap())
                .as_ref()
                .unwrap()
                .ancestors
                .clone()
                .unwrap(),
            HashSet::from_iter([r#"E::"e""#.parse().unwrap(), r#"E::"f""#.parse().unwrap()])
        );
        assert_eq!(
            entities
                .entities
                .get(&r#"E::"e""#.parse().unwrap())
                .as_ref()
                .unwrap()
                .ancestors
                .clone()
                .unwrap(),
            HashSet::from_iter([r#"E::"f""#.parse().unwrap()])
        );
        assert_eq!(
            entities
                .entities
                .get(&r#"E::"x""#.parse().unwrap())
                .as_ref()
                .unwrap()
                .ancestors,
            None
        );
    }
}

#[cfg(test)]
mod test_validate {
    use super::*;
    use crate::entities::conformance::err::EntitySchemaConformanceError;
    use crate::tpe::err::EntityValidationError;
    use cool_asserts::assert_matches;

    fn test_schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
            entity User {
                name: String,
            } tags String;

            entity Resource;

            action view appliesTo {
                principal: User,
                resource: Resource
            };
            "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    #[test]
    fn valid_entity() {
        let schema = test_schema();
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: Some(BTreeMap::from_iter([("name".into(), Value::from("Alice"))])),
            ancestors: Some(HashSet::new()),
            tags: Some(BTreeMap::from_iter([(
                "department".into(),
                Value::from("Engineering"),
            )])),
        };

        assert_matches!(entity.validate(&schema), Ok(()));
    }

    #[test]
    fn invalid_unexpected_entity_type() {
        let schema = test_schema();
        let entity = PartialEntity {
            uid: "UnknownType::\"test\"".parse().unwrap(),
            attrs: None,
            ancestors: None,
            tags: None,
        };

        assert_matches!(
            entity.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::UnexpectedEntityType(_)
            ))
        );
    }

    #[test]
    fn invalid_entity_invalid_ancestor() {
        let schema = test_schema();
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: None,
            ancestors: Some(HashSet::from_iter(["Resource::\"doc1\"".parse().unwrap()])),
            tags: None,
        };

        assert_matches!(
            entity.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::InvalidAncestorType(_)
            ))
        );
    }

    #[test]
    fn invalid_entity_invalid_attr() {
        let schema = test_schema();
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: Some(BTreeMap::from_iter([("name".into(), Value::from(42))])),
            ancestors: None,
            tags: None,
        };

        assert_matches!(
            entity.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::TypeMismatch(_)
            ))
        );
    }

    #[test]
    fn invalid_entity_invalid_tag() {
        let schema = test_schema();
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: None,
            ancestors: None,
            tags: Some(BTreeMap::from_iter([(
                "department".into(),
                Value::from(42),
            )])),
        };

        assert_matches!(
            entity.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::TypeMismatch(_)
            ))
        );
    }
}

#[cfg(test)]
mod test_consistency {
    use cool_asserts::assert_matches;

    use crate::{
        ast::Entity,
        entities::{Entities, EntityJsonParser, TCComputation},
        extensions::Extensions,
        tpe::{self, entities::PartialEntities},
        validator::ValidatorSchema,
    };

    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            "entity A { a: Bool } tags Long;",
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    #[track_caller]
    fn parse_concrete_json(entity_json: serde_json::Value) -> Entity {
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        eparser.single_from_json_value(entity_json).unwrap()
    }

    #[test]
    fn consistent_eq_entity() {
        let entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(entity_json.clone()).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(entity_json);
        assert_matches!(partial_entity.check_consistency(&entity), Ok(()))
    }

    #[test]
    fn consistent_missing_attrs() {
        let partial_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let concrete_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(concrete_entity_json);
        assert_matches!(partial_entity.check_consistency(&entity), Ok(()))
    }

    #[test]
    fn consistent_missing_tags() {
        let partial_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let concrete_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(concrete_entity_json);
        assert_matches!(partial_entity.check_consistency(&entity), Ok(()))
    }

    #[test]
    fn consistent_missing_parents() {
        let partial_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
            }
        );
        let concrete_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(concrete_entity_json);
        assert_matches!(partial_entity.check_consistency(&entity), Ok(()))
    }

    #[test]
    fn not_consistent_different_attrs() {
        let partial_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": true },
            }
        );
        let concrete_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(concrete_entity_json);
        assert_matches!(
            partial_entity.check_consistency(&entity),
            Err(tpe::err::EntityConsistencyError::MismatchedAttribute(_))
        )
    }

    #[test]
    fn not_consistent_different_tags() {
        let partial_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "tags" : { "t": 1 },
            }
        );
        let concrete_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(concrete_entity_json);
        assert_matches!(
            partial_entity.check_consistency(&entity),
            Err(tpe::err::EntityConsistencyError::MismatchedTag(_))
        )
    }

    #[test]
    fn not_consistent_different_parents() {
        let partial_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "parents" : [ {"type": "A", "id": "baz"} ],  // Different parent
            }
        );
        let concrete_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],  // Different parent
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(concrete_entity_json);
        assert_matches!(
            partial_entity.check_consistency(&entity),
            Err(tpe::err::EntityConsistencyError::MismatchedAncestor(_))
        )
    }

    #[test]
    fn not_consistent_missing_entity() {
        let partial_entity_json = serde_json::json!(
            [{ "uid" : { "type" : "A", "id" : "foo", }, }]
        );
        let partial_entities = PartialEntities::from_json_value(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let concrete_entities = Entities::new();
        assert_matches!(
            partial_entities.check_consistency(&concrete_entities),
            Err(tpe::err::EntitiesConsistencyError::MissingEntity(_))
        )
    }
}

#[cfg(test)]
mod test_parse_ejson_errors {
    use crate::extensions::Extensions;
    use crate::test_utils::{expect_err, ExpectedErrorMessageBuilder};
    use crate::validator::ValidatorSchema;

    use super::{parse_ejson, EntityJson};

    #[track_caller]
    fn basic_schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
            entity A {
                a? : String,
                b? : Long,
                c? : {"x" : Bool}
            } tags Long;
            action a appliesTo {
                principal : A,
                resource : A
            };
            "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    #[track_caller]
    fn ext_schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
            entity E {
                d? : decimal,
            } tags decimal;
            "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    #[track_caller]
    fn assert_ejson_err(
        json: serde_json::Value,
        schema: &ValidatorSchema,
        msg: &crate::test_utils::ExpectedErrorMessage<'_>,
    ) {
        let ejson: EntityJson =
            serde_json::from_value(json.clone()).expect("should deserialize as EntityJson");
        let err = parse_ejson(ejson, schema).expect_err("should fail to parse");
        expect_err(&json, &miette::Report::new(err), msg);
    }

    #[test]
    fn uid_not_entity_ref() {
        let json = serde_json::json!({ "uid": 5 });
        assert_ejson_err(
            json,
            &basic_schema(),
            &ExpectedErrorMessageBuilder::error(
                "in uid field of <unknown entity>, expected a literal entity reference, but got `5`",
            )
            .help(r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#)
            .build(),
        );
    }

    #[test]
    fn attrs_unexpected_entity_type() {
        let json = serde_json::json!({
            "uid": { "type": "Undeclared", "id": "x" },
            "attrs": { "b": 1 },
        });
        assert_ejson_err(
            json,
            &basic_schema(),
            &ExpectedErrorMessageBuilder::error(
                r#"entity `Undeclared::"x"` has type `Undeclared` which is not declared in the schema"#,
            )
            .build(),
        );
    }

    #[test]
    fn attr_type_mismatch() {
        let json = serde_json::json!({
            "uid": { "type": "A", "id": "" },
            "attrs": { "c": 5 },
        });
        assert_ejson_err(
            json,
            &basic_schema(),
            &ExpectedErrorMessageBuilder::error_starts_with(
                r#"in attribute `c` on `A::""`, type mismatch: value was expected to have type"#,
            )
            .build(),
        );
    }

    #[test]
    fn attr_missing_required_record_attr() {
        let json = serde_json::json!({
            "uid": { "type": "A", "id": "" },
            "attrs": { "c": {} },
        });
        assert_ejson_err(
            json,
            &basic_schema(),
            &ExpectedErrorMessageBuilder::error(
                r#"in attribute `c` on `A::""`, expected the record to have an attribute `x`, but it does not"#,
            )
            .build(),
        );
    }

    #[test]
    fn attr_unexpected_record_attr() {
        let json = serde_json::json!({
            "uid": { "type": "A", "id": "" },
            "attrs": { "c": { "x": true, "y": 1 } },
        });
        assert_ejson_err(
            json,
            &basic_schema(),
            &ExpectedErrorMessageBuilder::error(
                r#"in attribute `c` on `A::""`, record attribute `y` should not exist according to the schema"#,
            )
            .build(),
        );
    }

    #[test]
    fn attr_eval_error() {
        let json = serde_json::json!({
            "uid": { "type": "E", "id": "x" },
            "attrs": { "d": { "fn": "decimal", "arg": "invalid" } },
        });
        assert_ejson_err(
            json,
            &ext_schema(),
            &ExpectedErrorMessageBuilder::error(
                "error while evaluating `decimal` extension function: `invalid` is not a well-formed decimal value",
            )
            .help("valid decimal strings look like `12.34`: digits are required on both sides of `.`, up to 4 fractional digits are allowed, and the value must be in range -922337203685477.5808 to 922337203685477.5807")
            .build(),
        );
    }

    #[test]
    fn tag_eval_error() {
        let json = serde_json::json!({
            "uid": { "type": "E", "id": "x" },
            "tags": { "t": { "fn": "decimal", "arg": "invalid" } },
        });
        assert_ejson_err(
            json,
            &ext_schema(),
            &ExpectedErrorMessageBuilder::error(
                "error while evaluating `decimal` extension function: `invalid` is not a well-formed decimal value",
            )
            .help("valid decimal strings look like `12.34`: digits are required on both sides of `.`, up to 4 fractional digits are allowed, and the value must be in range -922337203685477.5808 to 922337203685477.5807")
            .build(),
        );
    }

    #[test]
    fn tags_unexpected_entity_type() {
        let json = serde_json::json!({
            "uid": { "type": "Undeclared", "id": "x" },
            "tags": { "t": 1 },
        });
        assert_ejson_err(
            json,
            &basic_schema(),
            &ExpectedErrorMessageBuilder::error(
                r#"entity `Undeclared::"x"` has type `Undeclared` which is not declared in the schema"#,
            )
            .build(),
        );
    }

    #[test]
    fn parent_not_entity_ref() {
        let json = serde_json::json!({
            "uid": { "type": "A", "id": "" },
            "parents": [ 5 ],
        });
        assert_ejson_err(
            json,
            &basic_schema(),
            &ExpectedErrorMessageBuilder::error(
                r#"in parents field of `A::""`, expected a literal entity reference, but got `5`"#,
            )
            .help(r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#)
            .build(),
        );
    }
}

#[cfg(test)]
mod action_entities {
    use super::PartialEntities;
    use crate::ast::EntityUID;
    use crate::entities::conformance::err::EntitySchemaConformanceError;
    use crate::extensions::Extensions;
    use crate::tpe::entities::PartialEntity;
    use crate::tpe::err::{EntitiesError, EntityValidationError, JsonDeserializationError};
    use crate::validator::ValidatorSchema;
    use cool_asserts::assert_matches;

    // `read` is an action group; `view` is a member of it and applies to `E`.
    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
            entity E;
            action read;
            action view in [read] appliesTo { principal : E, resource : E };
            "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    // Parse a single-entity JSON list and return the stored action entity.
    fn parse_view(json: serde_json::Value) -> Result<PartialEntity, EntitiesError> {
        let uid: EntityUID = "Action::\"view\"".parse().unwrap();
        PartialEntities::from_json_value(json, &schema())
            .map(|es| es.get(&uid).unwrap().clone())
    }

    // Compact projection of an action entity for assertions: its uid rendered
    // via `Display` plus its (sorted) known ancestor uids.
    fn summary(e: &PartialEntity) -> (String, Vec<String>) {
        let mut ancestors: Vec<String> = e
            .ancestors()
            .into_iter()
            .flatten()
            .map(ToString::to_string)
            .collect();
        ancestors.sort();
        (e.uid().to_string(), ancestors)
    }

    #[test]
    fn action_with_unknown_components_is_substituted_by_schema() {
        // An action supplied with all components unknown is consistent with the
        // schema, so construction substitutes the schema's fully-known action
        // (empty attrs/tags, `read` ancestor).
        let entity = parse_view(serde_json::json!([{
            "uid": { "type": "Action", "id": "view" },
        }]))
        .unwrap();
        assert_eq!(
            summary(&entity),
            ("Action::\"view\"".to_string(), vec![
                "Action::\"read\"".to_string()
            ])
        );
        assert_eq!(entity.attrs(), Some(&std::collections::BTreeMap::new()));
    }

    #[test]
    fn action_matching_schema_is_substituted_by_schema() {
        // Supplying the components explicitly and consistently with the schema
        // also succeeds and yields the same substituted schema action.
        let entity = parse_view(serde_json::json!([{
            "uid": { "type": "Action", "id": "view" },
            "attrs": {},
            "tags": {},
            "parents": [ { "type": "Action", "id": "read" } ],
        }]))
        .unwrap();
        assert_eq!(
            summary(&entity),
            ("Action::\"view\"".to_string(), vec![
                "Action::\"read\"".to_string()
            ])
        );
    }

    fn assert_declaration_mismatch(json: serde_json::Value) {
        assert_matches!(
            parse_view(json),
            Err(EntitiesError::Validation(EntityValidationError::Concrete(
                EntitySchemaConformanceError::ActionDeclarationMismatch(_)
            )))
        );
    }

    #[test]
    fn action_with_unexpected_attr_fails() {
        assert_declaration_mismatch(serde_json::json!([{
            "uid": { "type": "Action", "id": "view" },
            "attrs": { "foo": 1 },
        }]));
    }

    #[test]
    fn action_with_unexpected_tag_fails() {
        assert_declaration_mismatch(serde_json::json!([{
            "uid": { "type": "Action", "id": "view" },
            "tags": { "foo": 1 },
        }]));
    }

    #[test]
    fn action_with_incorrect_ancestors_fails() {
        // `view`'s only schema ancestor is `read`; declaring no parents is
        // inconsistent with the schema.
        assert_declaration_mismatch(serde_json::json!([{
            "uid": { "type": "Action", "id": "view" },
            "parents": [],
        }]));
    }

    #[test]
    fn undeclared_action_fails() {
        assert_matches!(
            parse_view(serde_json::json!([{
                "uid": { "type": "Action", "id": "nonexistent" },
            }])),
            Err(EntitiesError::Validation(EntityValidationError::Concrete(
                EntitySchemaConformanceError::UndeclaredAction(_)
            )))
        );
    }

    #[test]
    fn action_parent_is_not_action_fails_at_parse() {
        // A non-action parent is rejected at parse time, mirroring concrete
        // entity parsing.
        assert_matches!(
            parse_view(serde_json::json!([{
                "uid": { "type": "Action", "id": "view" },
                "parents": [ { "type": "E", "id": "e" } ],
            }])),
            Err(EntitiesError::Deserialization(
                JsonDeserializationError::Concrete(_)
            ))
        );
    }
}
