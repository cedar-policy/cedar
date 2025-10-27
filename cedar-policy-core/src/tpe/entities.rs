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
use crate::entities::{Dereference, Entities, TCComputation};
use crate::tpe::err::{
    AncestorValidationError, EntitiesConsistencyError, EntitiesError, EntityConsistencyError,
    EntityValidationError, JsonDeserializationError, MismatchedActionAncestorsError,
    MismatchedAncestorError, MismatchedAttributeError, MismatchedTagError, MissingEntityError,
    UnexpectedActionError, UnknownActionComponentError, UnknownAttributeError, UnknownEntityError,
    UnknownTagError,
};
use crate::transitive_closure::{enforce_tc_and_dag, TcError};
use crate::validator::{CoreSchema, ValidatorSchema};
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
    entities::{
        conformance::{err::UnexpectedEntityTypeError, validate_euid},
        EntityTypeDescription,
    },
    transitive_closure::{compute_tc, TCNode},
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
    pub(crate) uid: EntityUID,
    // Optional attributes
    pub(crate) attrs: Option<BTreeMap<SmolStr, Value>>,
    // Optional ancestors
    pub(crate) ancestors: Option<HashSet<EntityUID>>,
    // Optional tags
    pub(crate) tags: Option<BTreeMap<SmolStr, Value>>,
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
    ) -> std::result::Result<Self, EntitiesError> {
        let e = Self {
            uid,
            attrs,
            ancestors,
            tags,
        };
        e.validate(schema)?;
        Ok(e)
    }
    /// Check if an [`Entity`] is consistent with a [`PartialEntity`]
    pub(crate) fn check_consistency(
        &self,
        entity: &Entity,
    ) -> std::result::Result<(), EntityConsistencyError> {
        if let Some(attrs) = &self.attrs {
            let other_attrs = entity
                .attrs()
                .map(|(a, pv)| match pv {
                    PartialValue::Value(v) => Ok((a.clone(), v.clone())),
                    PartialValue::Residual(_) => Err(UnknownAttributeError {
                        uid: self.uid.clone(),
                        attr: a.clone(),
                    }
                    .into()),
                })
                .collect::<std::result::Result<BTreeMap<_, _>, EntityConsistencyError>>()?;

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
            let other_tags = entity
                .tags()
                .map(|(a, pv)| match pv {
                    PartialValue::Value(v) => Ok((a.clone(), v.clone())),
                    PartialValue::Residual(_) => Err(UnknownTagError {
                        uid: self.uid.clone(),
                        tag: a.clone(),
                    }
                    .into()),
                })
                .collect::<std::result::Result<BTreeMap<_, _>, EntityConsistencyError>>()?;
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

/// Parse an [`EntityJson`] into a [`PartialEntity`] according to `schema`
pub fn parse_ejson(
    e: EntityJson,
    schema: &ValidatorSchema,
) -> std::result::Result<PartialEntity, JsonDeserializationError> {
    let uid = e
        .uid
        .into_euid(|| JsonDeserializationErrorContext::EntityUid)?;
    let core_schema = CoreSchema::new(schema);

    if uid.is_action() {
        return Err(UnexpectedActionError { action: uid }.into());
    }
    let vparser = ValueParser::new(Extensions::all_available());
    let eval = RestrictedEvaluator::new(Extensions::all_available());
    let attrs = e
        .attrs
        .map(|m| {
            m.map
                .into_iter()
                .map(|(k, v)| {
                    if let Some(ty) = core_schema.entity_type(uid.entity_type()) {
                        Ok((
                            k.clone(),
                            eval.interpret(
                                vparser
                                    .val_into_restricted_expr(
                                        v.into(),
                                        ty.attr_type(&k).as_ref(),
                                        || JsonDeserializationErrorContext::EntityAttribute {
                                            uid: uid.clone(),
                                            attr: k.clone(),
                                        },
                                    )?
                                    .as_borrowed(),
                            )?,
                        ))
                    } else {
                        Err(JsonDeserializationError::Concrete(
                            crate::entities::json::err::JsonDeserializationError::from(
                                EntitySchemaConformanceError::UnexpectedEntityType(
                                    UnexpectedEntityTypeError {
                                        uid: uid.clone(),
                                        suggested_types: core_schema
                                            .entity_types_with_basename(
                                                &uid.entity_type().name().basename(),
                                            )
                                            .collect(),
                                    },
                                ),
                            ),
                        ))
                    }
                })
                .collect::<std::result::Result<BTreeMap<_, _>, _>>()
        })
        .transpose()?;

    let ancestors = e
        .parents
        .map(|parents| {
            parents
                .into_iter()
                .map(|parent| {
                    parent
                        .into_euid(|| JsonDeserializationErrorContext::EntityParents {
                            uid: uid.clone(),
                        })
                        .map_err(JsonDeserializationError::Concrete)
                })
                .collect::<std::result::Result<HashSet<_>, _>>()
        })
        .transpose()?;

    let tags = e
        .tags
        .map(|m| {
            m.map
                .into_iter()
                .map(|(k, v)| {
                    if let Some(ty) = core_schema.entity_type(uid.entity_type()) {
                        Ok((
                            k.clone(),
                            eval.interpret(
                                vparser
                                    .val_into_restricted_expr(
                                        v.into(),
                                        ty.tag_type().as_ref(),
                                        || JsonDeserializationErrorContext::EntityAttribute {
                                            uid: uid.clone(),
                                            attr: k.clone(),
                                        },
                                    )?
                                    .as_borrowed(),
                            )?,
                        ))
                    } else {
                        Err(JsonDeserializationError::Concrete(
                            crate::entities::json::err::JsonDeserializationError::from(
                                EntitySchemaConformanceError::UnexpectedEntityType(
                                    UnexpectedEntityTypeError {
                                        uid: uid.clone(),
                                        suggested_types: core_schema
                                            .entity_types_with_basename(
                                                &uid.entity_type().name().basename(),
                                            )
                                            .collect(),
                                    },
                                ),
                            ),
                        ))
                    }
                })
                .collect::<std::result::Result<BTreeMap<_, _>, _>>()
        })
        .transpose()?;

    Ok(PartialEntity {
        uid,
        attrs,
        ancestors,
        tags,
    })
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
        // PANIC SAFETY: this method should be only called on entities that have known ancestors
        #[allow(clippy::expect_used)]
        self.ancestors
            .as_mut()
            .expect("should not be unknown")
            .insert(uid);
    }

    /// Validate `self` according to `schema`
    pub fn validate(
        &self,
        schema: &ValidatorSchema,
    ) -> std::result::Result<(), EntityValidationError> {
        let core_schema = CoreSchema::new(schema);
        let uid = &self.uid;
        let etype = uid.entity_type();

        if self.uid.is_action() {
            if self.attrs.is_none() || self.tags.is_none() {
                return Err(UnknownActionComponentError {
                    action: uid.clone(),
                }
                .into());
            }
            if let Some(attrs) = &self.attrs {
                if let Some((attr, _)) = attrs.first_key_value() {
                    return Err(EntitySchemaConformanceError::unexpected_entity_attr(
                        uid.clone(),
                        attr.clone(),
                    )
                    .into());
                }
            }
            if let Some(tags) = &self.tags {
                if let Some((tag, _)) = tags.first_key_value() {
                    return Err(EntitySchemaConformanceError::unexpected_entity_tag(
                        uid.clone(),
                        tag.clone(),
                    )
                    .into());
                }
            }
            if let Some(action) = core_schema.action(uid) {
                if let Some(ancestors) = &self.ancestors {
                    let schema_ancestors: HashSet<EntityUID> =
                        action.ancestors().cloned().collect();
                    if &schema_ancestors != ancestors {
                        return Err(MismatchedActionAncestorsError {
                            action: uid.clone(),
                        }
                        .into());
                    }
                } else {
                    return Err(UnknownActionComponentError {
                        action: uid.clone(),
                    }
                    .into());
                }
            } else {
                return Err(EntitySchemaConformanceError::UndeclaredAction(
                    crate::entities::conformance::err::UndeclaredAction { uid: uid.clone() },
                )
                .into());
            }
            return Ok(());
        }
        validate_euid(&core_schema, uid).map_err(EntitySchemaConformanceError::from)?;
        let schema_etype = core_schema
            .entity_type(etype)
            .ok_or_else(|| {
                let suggested_types = core_schema
                    .entity_types_with_basename(&etype.name().basename())
                    .collect();
                UnexpectedEntityTypeError {
                    uid: uid.clone(),
                    suggested_types,
                }
            })
            .map_err(EntitySchemaConformanceError::from)?;
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
pub(crate) fn validate_ancestors(
    entities: &HashMap<EntityUID, PartialEntity>,
) -> std::result::Result<(), AncestorValidationError> {
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
    pub fn compute_tc(&mut self) -> std::result::Result<(), TcError<EntityUID>> {
        compute_tc(&mut self.entities, true)
    }

    /// Check that the tc is computed and forms a dag
    pub fn enforce_tc_and_dag(&self) -> std::result::Result<(), TcError<EntityUID>> {
        enforce_tc_and_dag(&self.entities)
    }

    /// Get the `PartialEntity` with this identifier
    pub fn get(&self, euid: &EntityUID) -> Option<&PartialEntity> {
        self.entities.get(euid)
    }

    /// Check if there is a `PartialEntity` with identifier
    pub fn contains_entity(&self, euid: &EntityUID) -> bool {
        self.entities.contains_key(euid)
    }

    fn from_entities_map(
        entities: HashMap<EntityUID, PartialEntity>,
        schema: &ValidatorSchema,
    ) -> std::result::Result<Self, EntitiesError> {
        entities.values().try_for_each(|e| e.validate(schema))?;
        validate_ancestors(&entities)?;
        let mut entities = Self { entities };
        entities.compute_tc()?;
        entities.insert_actions(schema);
        Ok(entities)
    }

    /// Construct `PartialEntities` from `Entities`, ensuring that the entities are valid.
    pub fn from_concrete(
        entities: Entities,
        schema: &ValidatorSchema,
    ) -> std::result::Result<Self, EntitiesError> {
        let entities_map = entities
            .into_iter()
            .map(|e| e.try_into().map(|e: PartialEntity| (e.uid.clone(), e)))
            .try_collect()?;
        Self::from_entities_map(entities_map, schema)
    }

    /// Construct `PartialEntities` from an iterator
    pub fn from_entities(
        entity_mappings: impl Iterator<Item = PartialEntity>,
        schema: &ValidatorSchema,
    ) -> std::result::Result<Self, EntitiesError> {
        let mut entities: HashMap<EntityUID, PartialEntity> = HashMap::new();
        for entity in entity_mappings {
            use std::collections::hash_map::Entry;
            match entities.entry(entity.uid.clone()) {
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
        Self::from_entities_map(entities, schema)
    }

    /// Add a partial entity without checking if it conforms to the schema,
    /// assuming the TC is already computed.
    /// Errors on duplicate entries.
    pub(crate) fn add_entity_trusted(
        &mut self,
        uid: EntityUID,
        entity: PartialEntity,
    ) -> std::result::Result<(), EntitiesError> {
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
    ) -> std::result::Result<(), EntitiesError> {
        for (id, entity) in entity_mappings {
            entity.validate(schema)?;
            self.add_entity_trusted(id, entity)?;
        }

        validate_ancestors(&self.entities)?;

        match tc_computation {
            TCComputation::AssumeAlreadyComputed => (),
            TCComputation::EnforceAlreadyComputed => {
                self.enforce_tc_and_dag()?;
            }
            TCComputation::ComputeNow => {
                self.compute_tc()?;
            }
        }
        Ok(())
    }

    /// Like `from_entities` but do not perform any validation and tc
    /// computation. Callers must ensure these invariants are maintained.
    pub fn from_entities_unchecked(
        entities: impl Iterator<Item = (EntityUID, PartialEntity)>,
    ) -> Self {
        Self {
            entities: entities.collect(),
        }
    }

    // Insert action entities from the schema
    // Overwriting existing action entities is fine because they should come
    // from schema or be consistent with schema anyways
    fn insert_actions(&mut self, schema: &ValidatorSchema) {
        for (uid, action) in &schema.actions {
            self.entities.insert(
                uid.clone(),
                // PANIC SAFETY: action entities do not contain unknowns
                #[allow(clippy::unwrap_used)]
                action.as_ref().clone().try_into().unwrap(),
            );
        }
    }

    /// Construct [`PartialEntities`] from a JSON list
    pub fn from_json_value(
        value: serde_json::Value,
        schema: &ValidatorSchema,
    ) -> std::result::Result<Self, EntitiesError> {
        let entities: Vec<EntityJson> = serde_json::from_value(value)
            .map_err(|e| JsonDeserializationError::Concrete(e.into()))?;
        let mut partial_entities = PartialEntities::default();
        for e in entities {
            let partial_entity = parse_ejson(e, schema)?;
            partial_entity.validate(schema)?;
            partial_entities
                .entities
                .insert(partial_entity.uid.clone(), partial_entity);
        }
        validate_ancestors(&partial_entities.entities)?;
        partial_entities.compute_tc()?;

        // Insert actions from the schema
        partial_entities.insert_actions(schema);
        Ok(partial_entities)
    }

    /// Check if [`PartialEntities`] are consistent with [`Entities`]
    pub fn check_consistency(
        &self,
        concrete: &Entities,
    ) -> std::result::Result<(), EntitiesConsistencyError> {
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

    use crate::tpe::err::AncestorValidationError;
    use crate::validator::ValidatorSchema;
    use crate::{
        ast::{EntityUID, Value},
        extensions::Extensions,
    };
    use cool_asserts::assert_matches;

    use super::{parse_ejson, validate_ancestors, EntityJson, PartialEntities, PartialEntity};

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

    #[test]
    fn invalid_hierarchy() {
        let uid_a: EntityUID = r#"A::"a""#.parse().unwrap();
        let uid_b: EntityUID = r#"A::"b""#.parse().unwrap();
        assert_matches!(
            validate_ancestors(&HashMap::from_iter([
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
    use crate::tpe::err::{
        EntityValidationError, MismatchedActionAncestorsError, UnknownActionComponentError,
    };
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
    fn valid_action() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: Some(BTreeMap::new()),
            ancestors: Some(HashSet::new()),
            tags: Some(BTreeMap::new()),
        };

        assert_matches!(action.validate(&schema), Ok(()));
    }

    #[test]
    fn invalid_action_with_unknown_ancestors() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: Some(BTreeMap::new()),
            ancestors: None,
            tags: Some(BTreeMap::new()),
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::UnknownActionComponent(
                UnknownActionComponentError { .. }
            ))
        );
    }

    #[test]
    fn invalid_action_with_unknown_tags() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: Some(BTreeMap::new()),
            ancestors: Some(HashSet::new()),
            tags: None,
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::UnknownActionComponent(
                UnknownActionComponentError { .. }
            ))
        );
    }

    #[test]
    fn invalid_action_with_unknown_attrs() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: None,
            ancestors: Some(HashSet::new()),
            tags: Some(BTreeMap::new()),
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::UnknownActionComponent(
                UnknownActionComponentError { .. }
            ))
        );
    }

    #[test]
    fn invalid_action_with_unexpected_attr() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: Some(BTreeMap::from_iter([(
                "unexpected_attr".into(),
                Value::from("value"),
            )])),
            ancestors: Some(HashSet::new()),
            tags: Some(BTreeMap::new()),
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::UnexpectedEntityAttr(_)
            ))
        );
    }

    #[test]
    fn invalid_action_with_unexpected_tag() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: Some(BTreeMap::new()),
            ancestors: Some(HashSet::new()),
            tags: Some(BTreeMap::from_iter([(
                "unexpected_tag".into(),
                Value::from("value"),
            )])),
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::UnexpectedEntityTag(_)
            ))
        );
    }

    #[test]
    fn invalid_action_with_incorrect_ancestors() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: Some(BTreeMap::new()),
            ancestors: Some(HashSet::from_iter(["Action::\"other\"".parse().unwrap()])),
            tags: Some(BTreeMap::new()),
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::MismatchedActionAncestors(
                MismatchedActionAncestorsError { .. }
            ))
        );
    }

    #[test]
    fn invalid_unexpected_action() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"other\"".parse().unwrap(),
            attrs: Some(BTreeMap::new()),
            ancestors: Some(HashSet::new()),
            tags: Some(BTreeMap::new()),
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::UndeclaredAction(_)
            ))
        );
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
