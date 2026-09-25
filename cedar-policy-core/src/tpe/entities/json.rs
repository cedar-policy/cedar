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

//! The JSON format for partial entities and request contexts.
//!
//! The concrete entity JSON format plus one key, `knowledge`. Knowledge is
//! defined outside fo the usual `attrs` and `tags` objects to ensure the there
//! can be no confusion between a concrete attribute and an unknown attribute
//! with some inline annotation.

use super::{PartialEntities, PartialEntity};
use crate::ast::EntityUID;
use crate::entities::conformance::err::EntitySchemaConformanceError;
use crate::entities::json::err::{JsonDeserializationErrorContext, JsonSerializationError};
use crate::entities::json::{CedarValueJson, ValueParser};
use crate::entities::{EntityUidJson, SchemaType};
use crate::evaluator::RestrictedEvaluator;
use crate::extensions::Extensions;
use crate::jsonvalue::JsonValueWithNoDuplicateKeys;
use crate::tpe::err::{
    ContextNotValidError, ContextUndeclaredActionError, EntitiesError, JsonDeserializationError,
    KnowledgeContradictionError, KnowledgeJsonError, KnowledgeMalformedNodeError,
    KnowledgeNotARecordError, KnowledgeUndeclaredKeyError,
};
use crate::tpe::value::{AttrState, PartialRecord};
use crate::validator::{
    types::{Attributes, Type},
    CoreSchema, ValidatorSchema,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap, HashSet};

// `#[serde_as]` must precede the derive; after it, `MapPreventDuplicates` silently does nothing.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
struct DeduplicatedMap {
    #[serde_as(as = "serde_with::MapPreventDuplicates<_,_>")]
    pub map: HashMap<SmolStr, JsonValueWithNoDuplicateKeys>,
}

/// Serde JSON format for a single entity
///
/// The concrete format plus one key, `knowledge`. Knowledge is out of band because every JSON type is
/// already a legal Cedar value, so an in-band marker could collide with real data.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntityJson {
    /// UID of the entity, specified in any form accepted by `EntityUidJson`
    uid: EntityUidJson,
    /// attributes, whose values can be any JSON value.
    /// (Probably a `CedarValueJson`, but for schema-based parsing, it could for
    /// instance be an `EntityUidJson` if we're expecting an entity reference,
    /// so for now we leave it in its raw json-value form, albeit not allowing
    /// any duplicate keys in any records that may occur in an attribute value
    /// (even nested).)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    // the annotation covers duplicates in this `HashMap` itself, while the `JsonValueWithNoDuplicateKeys` covers duplicates in any records contained in attribute values (including recursively)
    attrs: Option<DeduplicatedMap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Parents of the entity, specified in any form accepted by `EntityUidJson`
    parents: Option<Vec<EntityUidJson>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    // the annotation covers duplicates in this `HashMap` itself, while the `JsonValueWithNoDuplicateKeys` covers duplicates in any records contained in tag values (including recursively)
    // Note that unlike the concrete JSON entity format, when the `tags` field
    // is missing, it means `tags` are unknown
    // This is because we need to represent `tags` being unknowns
    tags: Option<DeduplicatedMap>,
    /// What is known, but not valued, about individual attributes and tags
    #[serde(default, skip_serializing_if = "Option::is_none")]
    knowledge: Option<EntityKnowledgeJson>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EntityKnowledgeJson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attrs: Option<JsonValueWithNoDuplicateKeys>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tags: Option<JsonValueWithNoDuplicateKeys>,
}
/// Split a [`PartialRecord`] into the value map and knowledge map [`EntityJson`] carries
fn split_partial_record(
    rec: &PartialRecord,
) -> Result<(DeduplicatedMap, Option<JsonValueWithNoDuplicateKeys>), JsonSerializationError> {
    let (values, knowledge) = split_partial_record_inner(rec)?;
    Ok((
        DeduplicatedMap {
            map: values
                .into_iter()
                .map(|(k, v)| (SmolStr::from(k), v.into()))
                .collect(),
        },
        (!knowledge.is_empty()).then(|| serde_json::Value::Object(knowledge).into()),
    ))
}

fn split_partial_record_inner(
    rec: &PartialRecord,
) -> Result<
    (
        serde_json::Map<String, serde_json::Value>,
        serde_json::Map<String, serde_json::Value>,
    ),
    JsonSerializationError,
> {
    let mut values = serde_json::Map::new();
    let mut knowledge = serde_json::Map::new();
    for (key, state) in rec.attrs() {
        match state {
            AttrState::Value(v) => {
                values.insert(
                    key.to_string(),
                    serde_json::to_value(CedarValueJson::from_value(v.clone())?)?,
                );
            }
            AttrState::Present => {
                knowledge.insert(key.to_string(), KnownState::Present.as_str().into());
            }
            AttrState::Absent => {
                knowledge.insert(key.to_string(), KnownState::Absent.as_str().into());
            }
            AttrState::Unknown => {}
            AttrState::PartialRecord(inner) => {
                let (inner_values, inner_knowledge) = split_partial_record_inner(inner)?;
                if !inner_values.is_empty() {
                    values.insert(key.to_string(), serde_json::Value::Object(inner_values));
                }
                if !inner_knowledge.is_empty() {
                    knowledge.insert(key.to_string(), serde_json::Value::Object(inner_knowledge));
                }
            }
        }
    }
    Ok((values, knowledge))
}

impl PartialEntity {
    /// Serialize to the [`EntityJson`] form that [`parse_ejson`] reads
    fn to_ejson(&self) -> Result<EntityJson, JsonSerializationError> {
        let (attrs, attrs_knowledge) = self
            .attrs
            .as_ref()
            .map(split_partial_record)
            .transpose()?
            .unzip();
        let (tags, tags_knowledge) = self
            .tags
            .as_ref()
            .map(split_partial_record)
            .transpose()?
            .unzip();
        let knowledge = EntityKnowledgeJson {
            attrs: attrs_knowledge.flatten(),
            tags: tags_knowledge.flatten(),
        };
        Ok(EntityJson {
            uid: EntityUidJson::from(&self.uid),
            attrs,
            parents: self.ancestors.as_ref().map(|ancestors| {
                // Sort for a deterministic encoding; `ancestors` is a `HashSet`.
                let mut sorted: Vec<&EntityUID> = ancestors.iter().collect();
                sorted.sort();
                sorted.into_iter().map(EntityUidJson::from).collect()
            }),
            tags,
            knowledge: (knowledge.attrs.is_some() || knowledge.tags.is_some()).then_some(knowledge),
        })
    }
}

impl PartialEntities {
    /// Serialize parital entities to JSON
    pub fn to_json_value(&self) -> Result<serde_json::Value, EntitiesError> {
        let mut ejsons = self
            .entities()
            .filter(|e| !e.uid().is_action())
            .map(|e| Ok((e.uid().clone(), e.to_ejson()?)))
            .collect::<Result<Vec<_>, JsonSerializationError>>()?;
        ejsons.sort_by(|(a, _), (b, _)| a.cmp(b));
        serde_json::to_value(ejsons.into_iter().map(|(_, e)| e).collect::<Vec<_>>())
            .map_err(JsonSerializationError::from)
            .map_err(Into::into)
    }

    /// Parse partial entites from a JSON value
    pub fn from_json_value(
        value: serde_json::Value,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntitiesError> {
        Self::from_ejsons(
            serde_json::from_value(value)
                .map_err(|e| JsonDeserializationError::Concrete(e.into()))?,
            schema,
        )
    }

    /// Parse partial entites from a JSON string
    pub fn from_json_str(json: &str, schema: &ValidatorSchema) -> Result<Self, EntitiesError> {
        Self::from_ejsons(
            serde_json::from_str(json).map_err(|e| JsonDeserializationError::Concrete(e.into()))?,
            schema,
        )
    }

    fn from_ejsons(
        entities: Vec<EntityJson>,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntitiesError> {
        let parsed = entities
            .into_iter()
            .map(|e| parse_ejson(e, schema))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_entities_map(Self::collect_unique(parsed.into_iter())?, schema, true)
    }
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
    let unexpected_type = || {
        JsonDeserializationError::Concrete(
            EntitySchemaConformanceError::unexpected_entity_type(&core_schema, uid.clone()).into(),
        )
    };
    let vet = schema
        .get_entity_type(uid.entity_type())
        .ok_or_else(unexpected_type)?;
    let knowledge = e.knowledge.unwrap_or(EntityKnowledgeJson {
        attrs: None,
        tags: None,
    });
    let attrs = build_partial_record(
        e.attrs,
        knowledge.attrs.map(Into::into),
        Position::Attrs {
            uid: &uid,
            tys: vet.attributes(),
        },
    )?;

    let ancestors = e
        .parents
        .map(|parents| {
            parents
                .into_iter()
                .map(|parent| {
                    parent
                        .into_euid(&|| JsonDeserializationErrorContext::EntityParents {
                            uid: uid.clone(),
                        })
                        .map_err(JsonDeserializationError::Concrete)
                })
                .collect::<Result<HashSet<_>, _>>()
        })
        .transpose()?;

    let tags = build_partial_record(
        e.tags,
        knowledge.tags.map(Into::into),
        Position::Tags {
            uid: &uid,
            ty: vet.tag_type(),
        },
    )?;

    Ok(PartialEntity {
        uid,
        attrs,
        ancestors,
        tags,
    })
}

#[derive(Debug, Clone, Copy)]
enum Position<'a> {
    /// An entity's attributes, or the fields of a record nested in an attribute or a tag
    Attrs {
        uid: &'a EntityUID,
        tys: &'a Attributes,
    },
    /// The top level of an entity's tags.
    Tags {
        uid: &'a EntityUID,
        ty: Option<&'a Type>,
    },
    /// A request context, or the fields of a record nested in one
    Context { tys: &'a Attributes },
}

impl<'a> Position<'a> {
    /// The type the schema declares for `key` here (if declared)
    fn attr_ty(&self, key: &str) -> Option<Type> {
        match self {
            Position::Attrs { tys, .. } | Position::Context { tys } => {
                tys.get_attr(key).map(|at| at.attr_type.as_ref().clone())
            }
            Position::Tags { ty, .. } => ty.cloned(),
        }
    }

    /// This position with `tys` replaced, for descending into a nested record
    fn nested(&self, tys: &'a Attributes) -> Self {
        match self {
            Position::Context { .. } => Position::Context { tys },
            Position::Attrs { uid, .. } | Position::Tags { uid, .. } => {
                Position::Attrs { uid, tys }
            }
        }
    }

    /// How the concrete value parser names this position in its errors
    fn err_ctx(&self, attr: SmolStr) -> JsonDeserializationErrorContext {
        match self {
            Position::Attrs { uid, .. } | Position::Tags { uid, .. } => {
                JsonDeserializationErrorContext::EntityAttribute {
                    uid: (*uid).clone(),
                    attr,
                }
            }
            Position::Context { .. } => JsonDeserializationErrorContext::Context,
        }
    }

    /// The error for a key this position's declared type does not allow
    fn undeclared(&self, key: SmolStr) -> JsonDeserializationError {
        match self {
            Position::Attrs { uid, .. } => JsonDeserializationError::Concrete(
                EntitySchemaConformanceError::unexpected_entity_attr((*uid).clone(), key).into(),
            ),
            Position::Tags { uid, .. } => JsonDeserializationError::Concrete(
                EntitySchemaConformanceError::unexpected_entity_tag((*uid).clone(), key).into(),
            ),
            Position::Context { .. } => ContextNotValidError {}.into(),
        }
    }
}

/// What the `knowledge` map can state for a key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownState {
    /// The key exists, but its value is unknown
    Present,
    /// The key is known not to exist
    Absent,
}

impl KnownState {
    /// The JSON string this state is written with
    pub fn as_str(self) -> &'static str {
        match self {
            KnownState::Present => "present",
            KnownState::Absent => "absent",
        }
    }

    /// Parse a `knowledge` tree state string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "present" => Some(KnownState::Present),
            "absent" => Some(KnownState::Absent),
            _ => None,
        }
    }
}

fn build_partial_record(
    values: Option<DeduplicatedMap>,
    knowledge: Option<serde_json::Value>,
    at: Position<'_>,
) -> Result<Option<PartialRecord>, JsonDeserializationError> {
    if values.is_none() && knowledge.is_none() {
        return Ok(None);
    }
    let values = values.map(|m| {
        m.map
            .into_iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::from(v)))
            .collect::<serde_json::Map<_, _>>()
    });
    build_partial_record_inner(values, knowledge, at).map(Some)
}

/// Walk record values and knowledge together into one [`PartialRecord`]
fn build_partial_record_inner(
    values: Option<serde_json::Map<String, serde_json::Value>>,
    knowledge: Option<serde_json::Value>,
    at: Position<'_>,
) -> Result<PartialRecord, JsonDeserializationError> {
    let knowledge = match knowledge {
        None => serde_json::Map::new(),
        Some(serde_json::Value::Object(m)) => m,
        Some(_) => return Err(KnowledgeJsonError::from(KnowledgeMalformedNodeError {}).into()),
    };
    let mut values = values.unwrap_or_default();
    let eval = RestrictedEvaluator::new(Extensions::all_available());
    let mut out: BTreeMap<SmolStr, AttrState> = BTreeMap::new();

    for (key, node) in knowledge {
        let key = SmolStr::from(key);
        let Some(ty) = at.attr_ty(&key) else {
            return Err(KnowledgeJsonError::from(KnowledgeUndeclaredKeyError {}).into());
        };
        let value = values.remove(key.as_str());
        let state = match node {
            serde_json::Value::String(s) => {
                if value.is_some() {
                    return Err(KnowledgeJsonError::from(KnowledgeContradictionError {}).into());
                }
                match KnownState::from_str(&s) {
                    Some(KnownState::Present) => AttrState::Present,
                    Some(KnownState::Absent) => AttrState::Absent,
                    None => {
                        return Err(KnowledgeJsonError::from(KnowledgeMalformedNodeError {}).into())
                    }
                }
            }
            serde_json::Value::Object(fields) => {
                let Type::Record {
                    attrs: field_tys, ..
                } = ty
                else {
                    return Err(KnowledgeJsonError::from(KnowledgeNotARecordError {}).into());
                };
                let field_values = match value {
                    None => None,
                    Some(serde_json::Value::Object(m)) => Some(m),
                    Some(_) => {
                        return Err(KnowledgeJsonError::from(KnowledgeNotARecordError {}).into())
                    }
                };
                AttrState::PartialRecord(build_partial_record_inner(
                    field_values,
                    Some(serde_json::Value::Object(fields)),
                    at.nested(&field_tys),
                )?)
            }
            _ => return Err(KnowledgeJsonError::from(KnowledgeMalformedNodeError {}).into()),
        };
        out.insert(key, state);
    }

    let vparser = ValueParser::new(Extensions::all_available());
    for (key, value) in values {
        let key = SmolStr::from(key);
        let ty = at.attr_ty(&key).ok_or_else(|| at.undeclared(key.clone()))?;
        let schema_ty = SchemaType::try_from(ty.clone()).map_err(|_| at.undeclared(key.clone()))?;
        let expr = vparser
            .val_into_restricted_expr(value, Some(&schema_ty), &|| at.err_ctx(key.clone()))?;
        out.insert(key, AttrState::Value(eval.interpret(expr.as_borrowed())?));
    }
    Ok(out.into_iter().collect())
}

/// Parse a request context
pub fn parse_context_json(
    context: serde_json::Value,
    knowledge: Option<serde_json::Value>,
    action: &EntityUID,
    schema: &ValidatorSchema,
) -> Result<PartialRecord, JsonDeserializationError> {
    let Some(
        context_ty @ Type::Record {
            attrs: attr_tys, ..
        },
    ) = schema.get_action_id(action).map(|a| a.context_type())
    else {
        return Err(ContextUndeclaredActionError {
            action: action.clone(),
        }
        .into());
    };
    let serde_json::Value::Object(map) = context else {
        // Defer to the concrete parser so the error names the type mismatch.
        let schema_ty =
            SchemaType::try_from(context_ty.clone()).map_err(|_| ContextNotValidError {})?;
        ValueParser::new(Extensions::all_available()).val_into_restricted_expr(
            context,
            Some(&schema_ty),
            &|| JsonDeserializationErrorContext::Context,
        )?;
        return Err(ContextNotValidError {}.into());
    };
    build_partial_record_inner(Some(map), knowledge, Position::Context { tys: attr_tys })
}

#[cfg(test)]
mod partial_json_tests {
    use super::{parse_context_json, PartialEntities};
    use crate::ast::Value;
    use crate::extensions::Extensions;
    use crate::tpe::err::{EntitiesConsistencyError, EntityConsistencyError, KnowledgeJsonError};
    use crate::tpe::value::AttrState;
    use crate::validator::ValidatorSchema;
    use cool_asserts::assert_matches;

    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"entity U { name: String, nick?: String, meta: { a: Long, b?: Long } } tags Long;
               entity NoTags { name: String };
               action a appliesTo { principal: U, resource: U };"#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    fn alice() -> crate::ast::EntityUID {
        r#"U::"alice""#.parse().unwrap()
    }

    #[test]
    fn json_round_trip() {
        let schema = schema();
        let json = serde_json::json!([{
            "uid": {"type":"U","id":"alice"},
            "attrs": { "name": "Alice", "meta": {"a": 1, "b": 2} },
            "parents": [],
            "tags": {"t": 5},
            "knowledge": { "attrs": { "nick": "absent" }, "tags": { "u": "present" } },
        }]);
        let parsed = PartialEntities::from_json_value(json, &schema).unwrap();
        let written = parsed.to_json_value().unwrap();
        let reparsed =
            PartialEntities::from_json_value(written.clone(), &schema).unwrap_or_else(|e| {
                panic!("serialized partial entities should reparse: {e}\n{written}")
            });
        assert_eq!(parsed.get(&alice()), reparsed.get(&alice()));
    }

    #[test]
    fn serialized_shape() {
        let schema = schema();
        let parsed = PartialEntities::from_json_value(
            serde_json::json!([{
                "uid": {"type":"U","id":"alice"},
                "attrs": {"name": "Alice"},
                "parents": [],
                "knowledge": {"attrs": {"nick": "absent"}},
            }]),
            &schema,
        )
        .unwrap();
        let written = parsed.to_json_value().unwrap();
        assert_eq!(
            written,
            serde_json::json!([{
                "uid": {"__entity": {"type":"U","id":"alice"}},
                "attrs": {"name": "Alice"},
                "parents": [],
                "knowledge": {"attrs": {"nick": "absent"}},
            }]),
        );
    }

    #[test]
    fn knowledge_parses() {
        let ents = PartialEntities::from_json_value(
            serde_json::json!([{
                "uid": {"type":"U","id":"alice"},
                "attrs": {"name": "Alice"},
                "knowledge": {
                    "attrs": {"nick": "absent", "meta": "present"},
                    "tags": {"t": "present"},
                },
            }]),
            &schema(),
        )
        .unwrap();
        let attrs = ents.get_attrs(&alice()).unwrap();
        assert_eq!(attrs.attr("name"), &AttrState::Value(Value::from("Alice")));
        assert_eq!(attrs.attr("nick"), &AttrState::Absent);
        assert_eq!(attrs.attr("meta"), &AttrState::Present);
        assert_eq!(
            ents.get_tags(&alice()).unwrap().attr("t"),
            &AttrState::Present
        );
    }

    #[test]
    fn knowledge_without_values() {
        let ents = PartialEntities::from_json_value(
            serde_json::json!([{
                "uid": {"type":"U","id":"alice"},
                "knowledge": {"attrs": {"nick": "absent"}},
            }]),
            &schema(),
        )
        .unwrap();
        let attrs = ents.get_attrs(&alice()).unwrap();
        assert_eq!(attrs.attr("nick"), &AttrState::Absent);
        // Saying something about one attribute says nothing about the others.
        assert_eq!(attrs.attr("name"), &AttrState::Unknown);
    }

    #[test]
    fn nested_knowledge_refines_record_value() {
        let ents = PartialEntities::from_json_value(
            serde_json::json!([{
                "uid": {"type":"U","id":"alice"},
                "attrs": {"meta": {"a": 1}},
                "knowledge": {"attrs": {"meta": {"b": "present"}}},
            }]),
            &schema(),
        )
        .unwrap();
        assert_matches!(
            ents.get_attrs(&alice()).unwrap().attr("meta"),
            AttrState::PartialRecord(meta) => {
                assert_eq!(meta.attr("a"), &AttrState::Value(Value::from(1)));
                assert_eq!(meta.attr("b"), &AttrState::Present);
            }
        );
    }

    #[test]
    fn nested_knowledge_without_record_value() {
        let ents = PartialEntities::from_json_value(
            serde_json::json!([{
                "uid": {"type":"U","id":"alice"},
                "knowledge": {"attrs": {"meta": {"b": "absent"}}},
            }]),
            &schema(),
        )
        .unwrap();
        assert_matches!(
            ents.get_attrs(&alice()).unwrap().attr("meta"),
            AttrState::PartialRecord(meta) => {
                assert_eq!(meta.attr("b"), &AttrState::Absent);
                assert_eq!(meta.attr("a"), &AttrState::Unknown);
            }
        );
    }

    #[test]
    fn concrete_data_consistent_with_partial_from_same_json() {
        use crate::entities::{Entities, EntityJsonParser, TCComputation};
        use crate::validator::CoreSchema;

        let json = serde_json::json!([{
            "uid": {"type":"U","id":"alice"},
            "attrs": {"name":"Alice","nick":"Ali","meta":{"a":1,"b":2}},
            "parents": [],
            "tags": {"t": 5},
        }]);
        let schema = schema();
        let partial = PartialEntities::from_json_value(json.clone(), &schema).unwrap();

        let core = CoreSchema::new(&schema);
        let parser: EntityJsonParser<'_, '_, CoreSchema<'_>> = EntityJsonParser::new(
            Some(&core),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );
        let concrete: Entities = parser.from_json_value(json).unwrap();

        partial
            .check_consistency(&concrete)
            .expect("the same bytes must describe consistent data");
    }

    #[test]
    fn knowledge_consistent_with_matching_concrete() {
        use crate::entities::{Entities, EntityJsonParser, TCComputation};
        use crate::validator::CoreSchema;

        let schema = schema();
        let partial = PartialEntities::from_json_value(
            serde_json::json!([{
                "uid": {"type":"U","id":"alice"},
                "attrs": {"name":"Alice"},
                "parents": [],
                "knowledge": {"attrs": {"nick": "absent", "meta": "present"}},
            }]),
            &schema,
        )
        .unwrap();

        let core = CoreSchema::new(&schema);
        let parser: EntityJsonParser<'_, '_, CoreSchema<'_>> = EntityJsonParser::new(
            Some(&core),
            Extensions::all_available(),
            TCComputation::ComputeNow,
        );

        // `nick` really is absent and `meta` really is present: consistent.
        let ok: Entities = parser
            .from_json_value(serde_json::json!([{
                "uid": {"type":"U","id":"alice"},
                "attrs": {"name":"Alice","meta":{"a":1,"b":2}},
                "parents": [],
            }]))
            .unwrap();
        partial
            .check_consistency(&ok)
            .expect("concrete data satisfying the knowledge is consistent");

        // `nick` was declared absent but is present: must be rejected.
        let bad: Entities = parser
            .from_json_value(serde_json::json!([{
                "uid": {"type":"U","id":"alice"},
                "attrs": {"name":"Alice","nick":"Ali","meta":{"a":1,"b":2}},
                "parents": [],
            }]))
            .unwrap();
        assert_matches!(
            partial.check_consistency(&bad),
            Err(EntitiesConsistencyError::InconsistentEntity(
                EntityConsistencyError::MismatchedAttribute(_)
            ))
        );
    }

    #[test]
    fn tag_knowledge_respects_the_schema() {
        // `U` declares `tags Long`, so any tag name is allowed.
        PartialEntities::from_json_value(
            serde_json::json!([{
                "uid": {"type":"U","id":"alice"},
                "knowledge": {"tags": {"anything": "absent"}},
            }]),
            &schema(),
        )
        .expect("a declared tag type admits any tag name");

        // `NoTags` declares none, so stating one is an error rather than a silent no-op.
        assert_matches!(
            PartialEntities::from_json_value(
                serde_json::json!([{
                    "uid": {"type":"NoTags","id":"x"},
                    "knowledge": {"tags": {"t": "absent"}},
                }]),
                &schema(),
            ),
            Err(_)
        );
    }

    #[test]
    fn context_json() {
        let schema = ValidatorSchema::from_cedarschema_str(
            r#"entity U; entity D;
               action a appliesTo {
                 principal: U, resource: D,
                 context: { level: Long, tag?: String, nested: { x: Long, y: Long } }
               };"#,
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let action: crate::ast::EntityUID = r#"Action::"a""#.parse().unwrap();

        let ctx = parse_context_json(
            serde_json::json!({ "level": 5, "nested": { "x": 1 } }),
            Some(serde_json::json!({ "tag": "absent", "nested": { "y": "present" } })),
            &action,
            &schema,
        )
        .expect("should parse");
        assert_eq!(ctx.attr("tag"), &AttrState::Absent);
        assert_matches!(ctx.attr("level"), AttrState::Value(_));
        assert_matches!(ctx.attr("nested"), AttrState::PartialRecord(inner) => {
            assert_eq!(inner.attr("x"), &AttrState::Value(Value::from(1)));
            assert_eq!(inner.attr("y"), &AttrState::Present);
        });
        // A field named by neither is unknown.
        assert_eq!(ctx.attr("missing"), &AttrState::Unknown);

        // Concrete context JSON parses unchanged, with no knowledge at all.
        assert_matches!(
            parse_context_json(
                serde_json::json!({ "level": 5, "tag": "t", "nested": { "x": 1, "y": 2 } }),
                None,
                &action,
                &schema
            ),
            Ok(_)
        );
    }

    #[test]
    fn context_json_errors() {
        let schema = ValidatorSchema::from_cedarschema_str(
            r#"entity U; entity D;
               action a appliesTo { principal: U, resource: D, context: { level: Long } };"#,
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let action: crate::ast::EntityUID = r#"Action::"a""#.parse().unwrap();
        use crate::tpe::err::JsonDeserializationError as E;

        // An undeclared field is named, rather than being flattened into "context is not valid".
        assert_matches!(
            parse_context_json(serde_json::json!({ "levle": 1 }), None, &action, &schema),
            Err(E::ContextNotValid(_)),
        );
        // An undeclared field in the knowledge map, likewise.
        assert_matches!(
            parse_context_json(
                serde_json::json!({}),
                Some(serde_json::json!({ "levle": "absent" })),
                &action,
                &schema
            ),
            Err(E::Knowledge(KnowledgeJsonError::UndeclaredKey(_))) => {}
        );
        // An undeclared action is reported as such, not as an invalid context.
        assert_matches!(
            parse_context_json(
                serde_json::json!({}),
                None,
                &r#"Action::"nope""#.parse().unwrap(),
                &schema
            ),
            Err(E::ContextUndeclaredAction(_))
        );
        // A context that is not a JSON object at all names the type it should have had.
        assert_matches!(
            parse_context_json(serde_json::json!([]), None, &action, &schema),
            Err(E::Concrete(_))
        );
    }
}
