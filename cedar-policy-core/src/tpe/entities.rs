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
    /// The uid of the partial entity
    pub uid: EntityUID,
    /// Optional attributes
    pub attrs: Option<BTreeMap<SmolStr, Value>>,
    /// Optional ancestors
    pub ancestors: Option<HashSet<EntityUID>>,
    /// Optional tags
    pub tags: Option<BTreeMap<SmolStr, Value>>,
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
    pub(crate) entities: HashMap<EntityUID, PartialEntity>,
}

// `Entities` without unknowns are `PartialEntities`
impl TryFrom<Entities> for PartialEntities {
    type Error = PartialValueToValueError;
    fn try_from(entities: Entities) -> Result<Self, Self::Error> {
        let mut partial_entities = PartialEntities::default();
        for e in entities.into_iter() {
            let partial_entity: PartialEntity = e.try_into()?;
            partial_entities
                .entities
                .insert(partial_entity.uid.clone(), partial_entity);
        }
        Ok(partial_entities)
    }
}

impl PartialEntities {
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

    /// Construct `PartialEntities` from an iterator
    pub fn from_entities(
        entity_mappings: impl Iterator<Item = (EntityUID, PartialEntity)>,
        schema: &ValidatorSchema,
    ) -> std::result::Result<Self, EntitiesError> {
        let mut entities: HashMap<EntityUID, PartialEntity> = HashMap::new();
        for (uid, entity) in entity_mappings {
            use std::collections::hash_map::Entry;
            match entities.entry(uid) {
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
        for e in entities.values() {
            e.validate(schema)?;
        }
        validate_ancestors(&entities)?;
        let mut entities = Self { entities };
        entities.compute_tc()?;
        Ok(entities)
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
            self.add_entity_trusted(id, entity);
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

    /// Like `from_entities` but do not perform any validation and tc computation
    pub fn from_entities_unchecked(
        entities: impl Iterator<Item = (EntityUID, PartialEntity)>,
    ) -> Self {
        Self {
            entities: entities.collect(),
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
        for (uid, action) in &schema.actions {
            partial_entities.entities.insert(
                uid.clone(),
                PartialEntity {
                    uid: uid.clone(),
                    attrs: Some(BTreeMap::default()),
                    ancestors: Some(action.ancestors().cloned().collect()),
                    tags: Some(BTreeMap::default()),
                },
            );
        }
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
        assert!(validate_ancestors(&HashMap::from_iter([
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
        ]))
        .is_err())
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
