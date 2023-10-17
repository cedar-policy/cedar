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

use super::{
    EntityTypeDescription, EntityUidJSON, JSONValue, JsonDeserializationError,
    JsonDeserializationErrorContext, JsonSerializationError, NoEntitiesSchema, Schema, TypeAndId,
    ValueParser,
};
use crate::ast::{Entity, EntityType, EntityUID, RestrictedExpr};
use crate::entities::{
    type_of_rexpr, unwrap_or_clone, Entities, EntitiesError, EntitySchemaConformanceError,
    TCComputation, TypeOfRexprError,
};
use crate::extensions::Extensions;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::sync::Arc;

/// Serde JSON format for a single entity
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EntityJSON {
    /// UID of the entity, specified in any form accepted by `EntityUidJSON`
    uid: EntityUidJSON,
    /// attributes, whose values can be any JSON value.
    /// (Probably a `JSONValue`, but for schema-based parsing, it could for
    /// instance be an `EntityUidJSON` if we're expecting an entity reference,
    /// so for now we leave it in its raw `serde_json::Value` form.)
    attrs: HashMap<SmolStr, serde_json::Value>,
    /// Parents of the entity, specified in any form accepted by `EntityUidJSON`
    parents: Vec<EntityUidJSON>,
}

/// Struct used to parse entities from JSON.
#[derive(Debug, Clone)]
pub struct EntityJsonParser<'e, 's, S: Schema = NoEntitiesSchema> {
    /// `schema` represents a source of `Action` entities, which will be added
    /// to the entities parsed from JSON.
    /// (If any `Action` entities are present in the JSON, and a `schema` is
    /// also provided, those entities' definitions must match exactly or an
    /// error is returned.)
    ///
    /// If a `schema` is present, this will also inform the parsing: for
    /// instance, it will allow `__entity` and `__extn` escapes to be implicit.
    ///
    /// Finally, if a `schema` is present, the `EntityJsonParser` will ensure
    /// that the produced entities fully conform to the `schema` -- for
    /// instance, it will error if attributes have the wrong types (e.g., string
    /// instead of integer), or if required attributes are missing or
    /// superfluous attributes are provided.
    schema: Option<&'s S>,

    /// Extensions which are active for the JSON parsing.
    extensions: Extensions<'e>,

    /// Whether to compute, enforce, or assume TC for entities parsed using this
    /// parser.
    tc_computation: TCComputation,
}

/// Schema information about a single entity can take one of these forms:
enum EntitySchemaInfo<E: EntityTypeDescription> {
    /// There is no schema, i.e. we're not doing schema-based parsing
    NoSchema,
    /// The entity is an action, and here's the schema's copy of the
    /// `Entity` object for it
    Action(Arc<Entity>),
    /// The entity is a non-action, and here's the schema's information
    /// about its type
    NonAction(E),
}

impl<'e, 's, S: Schema> EntityJsonParser<'e, 's, S> {
    /// Create a new `EntityJsonParser`.
    ///
    /// `schema` represents a source of `Action` entities, which will be added
    /// to the entities parsed from JSON.
    /// (If any `Action` entities are present in the JSON, and a `schema` is
    /// also provided, those entities' definitions must match exactly or an
    /// error is returned.)
    ///
    /// If a `schema` is present, this will also inform the parsing: for
    /// instance, it will allow `__entity` and `__extn` escapes to be implicit.
    ///
    /// Finally, if a `schema` is present, the `EntityJsonParser` will ensure
    /// that the produced entities fully conform to the `schema` -- for
    /// instance, it will error if attributes have the wrong types (e.g., string
    /// instead of integer), or if required attributes are missing or
    /// superfluous attributes are provided.
    ///
    /// If you pass `TCComputation::AssumeAlreadyComputed`, then the caller is
    /// responsible for ensuring that TC holds before calling this method.
    pub fn new(
        schema: Option<&'s S>,
        extensions: Extensions<'e>,
        tc_computation: TCComputation,
    ) -> Self {
        Self {
            schema,
            extensions,
            tc_computation,
        }
    }

    /// Parse an entities JSON file (in [`&str`] form) into an [`Entities`] object.
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`.
    pub fn from_json_str(&self, json: &str) -> Result<Entities, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_str(json).map_err(JsonDeserializationError::from)?;
        self.parse_ejsons(ejsons)
    }

    /// Parse an entities JSON file (in [`serde_json::Value`] form) into an [`Entities`] object.
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`.
    pub fn from_json_value(&self, json: serde_json::Value) -> Result<Entities, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_value(json).map_err(JsonDeserializationError::from)?;
        self.parse_ejsons(ejsons)
    }

    /// Parse an entities JSON file (in [`std::io::Read`] form) into an [`Entities`] object.
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`.
    pub fn from_json_file(&self, json: impl std::io::Read) -> Result<Entities, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_reader(json).map_err(JsonDeserializationError::from)?;
        self.parse_ejsons(ejsons)
    }

    /// Parse an entities JSON file (in [`&str`] form) into an iterator over [`Entity`]s.
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`.
    pub fn iter_from_json_str(
        &self,
        json: &str,
    ) -> Result<impl Iterator<Item = Entity> + '_, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_str(json).map_err(JsonDeserializationError::from)?;
        self.iter_ejson_to_iter_entity(ejsons)
    }

    /// Parse an entities JSON file (in [`serde_json::Value`] form) into an iterator over [`Entity`]s.
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`.
    pub fn iter_from_json_value(
        &self,
        json: serde_json::Value,
    ) -> Result<impl Iterator<Item = Entity> + '_, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_value(json).map_err(JsonDeserializationError::from)?;
        self.iter_ejson_to_iter_entity(ejsons)
    }

    /// Parse an entities JSON file (in [`std::io::Read`] form) into an iterator over [`Entity`]s.
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`.
    pub fn iter_from_json_file(
        &self,
        json: impl std::io::Read,
    ) -> Result<impl Iterator<Item = Entity> + '_, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_reader(json).map_err(JsonDeserializationError::from)?;
        self.iter_ejson_to_iter_entity(ejsons)
    }

    /// internal function that converts an iterator over [`EntityJSON`] into an
    /// iterator over [`Entity`] and also adds any `Action` entities declared in
    /// `self.schema`.
    fn iter_ejson_to_iter_entity(
        &self,
        ejsons: impl IntoIterator<Item = EntityJSON>,
    ) -> Result<impl Iterator<Item = Entity> + '_, EntitiesError> {
        let mut entities: Vec<Entity> = ejsons
            .into_iter()
            .map(|ejson| self.parse_ejson(ejson).map_err(EntitiesError::from))
            .collect::<Result<_, _>>()?;
        if let Some(schema) = &self.schema {
            entities.extend(schema.action_entities().into_iter().map(unwrap_or_clone));
        }
        Ok(entities.into_iter())
    }

    /// internal function that creates an [`Entities`] from a stream of [`EntityJSON`].
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`, and validates all the entities
    /// against the schema.
    fn parse_ejsons(
        &self,
        ejsons: impl IntoIterator<Item = EntityJSON>,
    ) -> Result<Entities, EntitiesError> {
        let entities: Vec<Entity> = ejsons
            .into_iter()
            .map(|ejson| self.parse_ejson(ejson))
            .collect::<Result<_, _>>()?;
        Entities::from_entities(entities, self.schema, self.tc_computation, self.extensions)
    }

    /// internal function that parses an `EntityJSON` into an `Entity`
    ///
    /// This function is not responsible for fully validating the `Entity`
    /// against the `schema`; that happens on construction of an `Entities`
    fn parse_ejson(&self, ejson: EntityJSON) -> Result<Entity, JsonDeserializationError> {
        let uid = ejson
            .uid
            .into_euid(|| JsonDeserializationErrorContext::EntityUid)?;
        let etype = uid.entity_type();
        let entity_schema_info = match &self.schema {
            None => EntitySchemaInfo::NoSchema,
            Some(schema) => {
                if etype.is_action() {
                    EntitySchemaInfo::Action(schema.action(&uid).ok_or(
                        JsonDeserializationError::EntitySchemaConformance(
                            EntitySchemaConformanceError::UndeclaredAction { uid: uid.clone() },
                        ),
                    )?)
                } else {
                    EntitySchemaInfo::NonAction(schema.entity_type(etype).ok_or_else(|| {
                        let suggested_types = match etype {
                            EntityType::Concrete(name) => {
                                schema.entity_types_with_basename(name.basename()).collect()
                            }
                            EntityType::Unspecified => vec![],
                        };
                        JsonDeserializationError::EntitySchemaConformance(
                            EntitySchemaConformanceError::UnexpectedEntityType {
                                uid: uid.clone(),
                                suggested_types,
                            },
                        )
                    })?)
                }
            }
        };
        let vparser = ValueParser::new(self.extensions);
        let attrs: HashMap<SmolStr, RestrictedExpr> = ejson
            .attrs
            .into_iter()
            .map(|(k, v)| match &entity_schema_info {
                EntitySchemaInfo::NoSchema => Ok((
                    k.clone(),
                    vparser.val_into_rexpr(v, None, || {
                        JsonDeserializationErrorContext::EntityAttribute {
                            uid: uid.clone(),
                            attr: k.clone(),
                        }
                    })?,
                )),
                EntitySchemaInfo::NonAction(desc) => {
                    // Depending on the expected type, we may parse the contents
                    // of the attribute differently.
                    let rexpr = match desc.attr_type(&k) {
                        // `None` indicates the attribute shouldn't exist -- see
                        // docs on the `attr_type()` trait method
                        None => {
                            return Err(JsonDeserializationError::EntitySchemaConformance(
                                EntitySchemaConformanceError::UnexpectedEntityAttr {
                                    uid: uid.clone(),
                                    attr: k,
                                },
                            ))
                        }
                        Some(expected_ty) => {
                            vparser.val_into_rexpr(v, Some(&expected_ty), || {
                                JsonDeserializationErrorContext::EntityAttribute {
                                    uid: uid.clone(),
                                    attr: k.clone(),
                                }
                            })?
                        }
                    };
                    Ok((k.clone(), rexpr))
                }
                EntitySchemaInfo::Action(action) => {
                    // We'll do schema-based parsing assuming optimistically that
                    // the type in the JSON is the same as the type in the schema.
                    // (As of this writing, the schema doesn't actually tell us
                    // what type each action attribute is supposed to be)
                    let expected_rexpr = match action.get(&k) {
                        // `None` indicates the attribute isn't in the schema's
                        // copy of the action entity
                        None => {
                            return Err(JsonDeserializationError::EntitySchemaConformance(
                                EntitySchemaConformanceError::ActionDeclarationMismatch {
                                    uid: uid.clone(),
                                },
                            ))
                        }
                        Some(rexpr) => rexpr,
                    };
                    let expected_ty = type_of_rexpr(expected_rexpr.as_borrowed(), self.extensions)
                        .map_err(|e| match e {
                            TypeOfRexprError::HeterogeneousSet(err) => {
                                JsonDeserializationError::EntitySchemaConformance(
                                    EntitySchemaConformanceError::HeterogeneousSet {
                                        uid: uid.clone(),
                                        attr: k.clone(),
                                        err,
                                    },
                                )
                            }
                            TypeOfRexprError::Extension(err) => {
                                JsonDeserializationError::FailedExtensionFunctionLookup(err)
                            }
                        })?;
                    let actual_rexpr = vparser.val_into_rexpr(v, Some(&expected_ty), || {
                        JsonDeserializationErrorContext::EntityAttribute {
                            uid: uid.clone(),
                            attr: k.clone(),
                        }
                    })?;
                    if actual_rexpr == *expected_rexpr {
                        Ok((k, actual_rexpr))
                    } else {
                        Err(JsonDeserializationError::EntitySchemaConformance(
                            EntitySchemaConformanceError::ActionDeclarationMismatch {
                                uid: uid.clone(),
                            },
                        ))
                    }
                }
            })
            .collect::<Result<_, JsonDeserializationError>>()?;
        let is_parent_allowed = |parent_euid: &EntityUID| {
            // full validation isn't done in this function (see doc comments on
            // this function), but we do need to do the following check which
            // happens even when there is no schema
            if etype.is_action() {
                if parent_euid.is_action() {
                    Ok(())
                } else {
                    Err(JsonDeserializationError::ActionParentIsNotAction {
                        uid: uid.clone(),
                        parent: parent_euid.clone(),
                    })
                }
            } else {
                Ok(()) // all parents are allowed
            }
        };
        let parents = ejson
            .parents
            .into_iter()
            .map(|parent| {
                parent.into_euid(|| JsonDeserializationErrorContext::EntityParents {
                    uid: uid.clone(),
                })
            })
            .map(|res| {
                res.and_then(|parent_euid| {
                    is_parent_allowed(&parent_euid)?;
                    Ok(parent_euid)
                })
            })
            .collect::<Result<_, JsonDeserializationError>>()?;
        Ok(Entity::new(uid, attrs, parents))
    }
}

impl EntityJSON {
    /// Convert an `Entity` into an EntityJSON
    ///
    /// (for the reverse transformation, use `EntityJsonParser`)
    pub fn from_entity(entity: &Entity) -> Result<Self, JsonSerializationError> {
        Ok(Self {
            // for now, we encode `uid` and `parents` using an implied `__entity` escape
            uid: EntityUidJSON::ImplicitEntityEscape(TypeAndId::from(entity.uid())),
            attrs: entity
                .attrs()
                .map(|(k, expr)| Ok((k.into(), serde_json::to_value(JSONValue::from_expr(expr)?)?)))
                .collect::<Result<_, JsonSerializationError>>()?,
            parents: entity
                .ancestors()
                .map(|euid| EntityUidJSON::ImplicitEntityEscape(TypeAndId::from(euid.clone())))
                .collect(),
        })
    }
}
