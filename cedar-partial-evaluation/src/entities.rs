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

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Ok;
use cedar_policy_core::{
    ast::PartialValue,
    entities::{conformance::EntitySchemaConformanceChecker, Schema},
};
use cedar_policy_core::{
    ast::{EntityUID, Value},
    entities::{
        json::{err::JsonDeserializationErrorContext, ValueParser},
        EntityUidJson,
    },
    evaluator::RestrictedEvaluator,
    extensions::Extensions,
    jsonvalue::JsonValueWithNoDuplicateKeys,
};
use cedar_policy_core::{
    entities::{
        conformance::{
            err::{EntitySchemaConformanceError, UnexpectedEntityTypeError},
            validate_euid,
        },
        EntityTypeDescription,
    },
    transitive_closure::{compute_tc, TCNode},
};
use cedar_policy_validator::{CoreSchema, ValidatorSchema};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde_as]
#[serde(transparent)]
pub struct DeduplicatedMap {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialEntity {
    pub uid: EntityUID,
    pub attrs: Option<BTreeMap<SmolStr, Value>>,
    pub ancestors: Option<HashSet<EntityUID>>,
    pub tags: Option<BTreeMap<SmolStr, Value>>,
}

pub fn parse_ejson(e: EntityJson, schema: &ValidatorSchema) -> anyhow::Result<PartialEntity> {
    //TODO: parse action
    let uid = e
        .uid
        .into_euid(|| JsonDeserializationErrorContext::EntityUid)?;
    let core_schema = CoreSchema::new(schema);
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
                        Err(anyhow::anyhow!("unknown entity type"))
                    }
                })
                .collect::<anyhow::Result<BTreeMap<_, _>>>()
        })
        .transpose()?;

    let ancestors = e
        .parents
        .map(|parents| {
            parents
                .into_iter()
                .map(|parent| {
                    Ok(
                        parent.into_euid(|| JsonDeserializationErrorContext::EntityParents {
                            uid: uid.clone(),
                        })?,
                    )
                })
                .collect::<anyhow::Result<HashSet<_>>>()
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
                        Err(anyhow::anyhow!("unknown entity type"))
                    }
                })
                .collect::<anyhow::Result<BTreeMap<_, _>>>()
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
    pub(crate) fn add_ancestor(&mut self, uid: EntityUID) {
        // PANIC SAFETY: this method should be only called on entities that have known ancestors
        #[allow(clippy::expect_used)]
        self.ancestors
            .as_mut()
            .expect("should not be unknown")
            .insert(uid);
    }

    pub(crate) fn validate(&self, schema: &ValidatorSchema) -> anyhow::Result<()> {
        //TODO: validate action
        let core_schema = CoreSchema::new(schema);
        let uid = &self.uid;
        let etype = uid.entity_type();

        validate_euid(&core_schema, uid)
            .map_err(|e| EntitySchemaConformanceError::InvalidEnumEntity(e.into()))?;
        let schema_etype = core_schema.entity_type(etype).ok_or_else(|| {
            let suggested_types = core_schema
                .entity_types_with_basename(&etype.name().basename())
                .collect();
            UnexpectedEntityTypeError {
                uid: uid.clone(),
                suggested_types,
            }
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

// Validate if parents are well-formed
// i.e., if parents of any parent of a `PartialEntity` should not be unknown
// This ensures that we can always compute a TC for entities with concrete
// parents
pub(crate) fn validate_parents(entities: &HashMap<EntityUID, PartialEntity>) -> anyhow::Result<()> {
    for e in entities.values() {
        if let Some(ancestors) = e.ancestors.as_ref() {
            for ancestor in ancestors {
                if let Some(ancestor_entity) = entities.get(ancestor) {
                    if ancestor_entity.ancestors.is_none() {
                        return Err(anyhow::anyhow!(
                            "{} has invalid ancestor {}",
                            e.uid,
                            ancestor
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialEntities {
    /// Important internal invariant: for any `Entities` object that exists,
    /// the `ancestor` relation is transitively closed.
    pub entities: HashMap<EntityUID, PartialEntity>,
}

impl PartialEntities {
    pub fn compute_tc(&mut self) -> anyhow::Result<()> {
        Ok(compute_tc(&mut self.entities, true)?)
    }

    pub fn from_json_value(
        value: serde_json::Value,
        schema: &ValidatorSchema,
    ) -> anyhow::Result<Self> {
        let entities: Vec<EntityJson> = serde_json::from_value(value)
            .map_err(|e| anyhow::anyhow!("failed to parse entities: {}", e))?;
        let mut partial_entities = PartialEntities::default();
        for e in entities {
            let partial_entity = parse_ejson(e, schema)?;
            partial_entity.validate(schema)?;
            partial_entities
                .entities
                .insert(partial_entity.uid.clone(), partial_entity);
        }
        validate_parents(&partial_entities.entities)?;
        partial_entities.compute_tc()?;
        Ok(partial_entities)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap, HashSet};

    use cedar_policy_core::{
        ast::{EntityUID, Value},
        extensions::Extensions,
    };
    use cedar_policy_validator::ValidatorSchema;
    use cool_asserts::assert_matches;

    use super::{parse_ejson, validate_parents, EntityJson, PartialEntities, PartialEntity};

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
        assert!(validate_parents(&HashMap::from_iter([
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
