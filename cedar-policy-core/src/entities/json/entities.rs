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
use crate::entities::{Entities, EntitiesError, TCComputation};
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
pub struct EntityJsonParser<'e, S: Schema = NoEntitiesSchema> {
    /// If a `schema` is present, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit.
    /// It will also ensure that the produced `Entities` fully conforms to the
    /// `schema` -- for instance, it will error if attributes have the wrong
    /// types (e.g., string instead of integer), or if required attributes are
    /// missing or superfluous attributes are provided.
    schema: Option<S>,

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

impl<'e, S: Schema> EntityJsonParser<'e, S> {
    /// Create a new `EntityJsonParser`.
    ///
    /// If a `schema` is present, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit.
    /// It will also ensure that the produced `Entities` fully conforms to the
    /// `schema` -- for instance, it will error if attributes have the wrong
    /// types (e.g., string instead of integer), or if required attributes are
    /// missing or superfluous attributes are provided.
    ///
    /// If you pass `TCComputation::AssumeAlreadyComputed`, then the caller is
    /// responsible for ensuring that TC holds before calling this method.
    pub fn new(
        schema: Option<S>,
        extensions: Extensions<'e>,
        tc_computation: TCComputation,
    ) -> Self {
        Self {
            schema,
            extensions,
            tc_computation,
        }
    }

    /// Parse an entities JSON file (in [`&str`] form) into an [`Entities`] object
    pub fn from_json_str(&self, json: &str) -> Result<Entities, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_str(json).map_err(JsonDeserializationError::from)?;
        self.parse_ejsons(ejsons)
    }

    /// Parse an entities JSON file (in [`serde_json::Value`] form) into an [`Entities`] object
    pub fn from_json_value(&self, json: serde_json::Value) -> Result<Entities, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_value(json).map_err(JsonDeserializationError::from)?;
        self.parse_ejsons(ejsons)
    }

    /// Parse an entities JSON file (in [`std::io::Read`] form) into an [`Entities`] object
    pub fn from_json_file(&self, json: impl std::io::Read) -> Result<Entities, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_reader(json).map_err(JsonDeserializationError::from)?;
        self.parse_ejsons(ejsons)
    }

    /// Parse an entities JSON file (in [`&str`] form) into an iterator over [`Entity`]s
    pub fn iter_from_json_str(
        &self,
        json: &str,
    ) -> Result<impl Iterator<Item = Result<Entity, EntitiesError>> + '_, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_str(json).map_err(JsonDeserializationError::from)?;
        Ok(ejsons
            .into_iter()
            .map(|ejson| self.parse_ejson(ejson).map_err(EntitiesError::from)))
    }

    /// Parse an entities JSON file (in [`serde_json::Value`] form) into an iterator over [`Entity`]s
    pub fn iter_from_json_value(
        &self,
        json: serde_json::Value,
    ) -> Result<impl Iterator<Item = Result<Entity, EntitiesError>> + '_, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_value(json).map_err(JsonDeserializationError::from)?;
        Ok(ejsons
            .into_iter()
            .map(|ejson| self.parse_ejson(ejson).map_err(EntitiesError::from)))
    }

    /// Parse an entities JSON file (in [`std::io::Read`] form) into an iterator over  [`Entity`]s
    pub fn iter_from_json_file(
        &self,
        json: impl std::io::Read,
    ) -> Result<impl Iterator<Item = Result<Entity, EntitiesError>> + '_, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_reader(json).map_err(JsonDeserializationError::from)?;
        Ok(ejsons
            .into_iter()
            .map(|ejson| self.parse_ejson(ejson).map_err(EntitiesError::from)))
    }

    /// internal function that creates an [`Entities`] from a stream of [`EntityJSON`]
    fn parse_ejsons(
        &self,
        ejsons: impl IntoIterator<Item = EntityJSON>,
    ) -> Result<Entities, EntitiesError> {
        let entities = ejsons
            .into_iter()
            .map(|ejson| self.parse_ejson(ejson))
            .collect::<Result<Vec<Entity>, _>>()?;
        Entities::from_entities(entities, self.tc_computation)
    }

    /// internal function that parses an `EntityJSON` into an `Entity`
    fn parse_ejson(&self, ejson: EntityJSON) -> Result<Entity, JsonDeserializationError> {
        let uid = ejson
            .uid
            .into_euid(|| JsonDeserializationErrorContext::EntityUid)?;
        let etype = uid.entity_type();
        let entity_schema_info =
            match &self.schema {
                None => EntitySchemaInfo::NoSchema,
                Some(schema) => {
                    if etype.is_action() {
                        EntitySchemaInfo::Action(schema.action(&uid).ok_or(
                            JsonDeserializationError::UndeclaredAction { uid: uid.clone() },
                        )?)
                    } else {
                        EntitySchemaInfo::NonAction(schema.entity_type(etype).ok_or_else(|| {
                            let basename = match etype {
                                EntityType::Concrete(name) => name.basename(),
                                // PANIC SAFETY: impossible to have the unspecified EntityType in JSON
                                #[allow(clippy::unreachable)]
                                EntityType::Unspecified => {
                                    unreachable!("unspecified EntityType in JSON")
                                }
                            };
                            JsonDeserializationError::UnexpectedEntityType {
                                uid: uid.clone(),
                                suggested_types: schema
                                    .entity_types_with_basename(basename)
                                    .collect(),
                            }
                        })?)
                    }
                }
            };
        match &entity_schema_info {
            EntitySchemaInfo::NoSchema => {} // no checks to do
            EntitySchemaInfo::Action(action) => {
                // here, we ensure that all the attributes on the schema's copy of the
                // action do exist in `ejson.attrs`. Later when consuming `ejson.attrs`,
                // we'll do the rest of the checks for attribute agreement.
                for schema_attr in action.attrs().keys() {
                    if !ejson.attrs.contains_key(schema_attr) {
                        return Err(JsonDeserializationError::ActionDeclarationMismatch { uid });
                    }
                }
            }
            EntitySchemaInfo::NonAction(etype_desc) => {
                // here, we ensure that all required attributes for `etype` are actually
                // included in `ejson.attrs`. Later when consuming `ejson.attrs` to build
                // `attrs`, we'll check for unexpected attributes.
                for required_attr in etype_desc.required_attrs() {
                    if ejson.attrs.contains_key(&required_attr) {
                        // all good
                    } else {
                        return Err(JsonDeserializationError::MissingRequiredEntityAttr {
                            uid,
                            attr: required_attr,
                        });
                    }
                }
            }
        }
        let vparser = ValueParser::new(self.extensions.clone());
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
                    let (rexpr, expected_ty) = match desc.attr_type(&k) {
                        // `None` indicates the attribute shouldn't exist -- see
                        // docs on the `attr_type()` trait method
                        None => {
                            return Err(JsonDeserializationError::UnexpectedEntityAttr {
                                uid: uid.clone(),
                                attr: k,
                            })
                        }
                        Some(expected_ty) => (
                            vparser.val_into_rexpr(v, Some(&expected_ty), || {
                                JsonDeserializationErrorContext::EntityAttribute {
                                    uid: uid.clone(),
                                    attr: k.clone(),
                                }
                            })?,
                            expected_ty,
                        ),
                    };
                    // typecheck: ensure that the final type of whatever we
                    // parsed actually does match the expected type. (For
                    // instance, this is where we check that we actually got the
                    // correct entity type when we expected an entity type, the
                    // correct extension type when we expected an extension
                    // type, or the correct type at all in other cases.)
                    let actual_ty = vparser.type_of_rexpr(rexpr.as_borrowed(), || {
                        JsonDeserializationErrorContext::EntityAttribute {
                            uid: uid.clone(),
                            attr: k.clone(),
                        }
                    })?;
                    if actual_ty.is_consistent_with(&expected_ty) {
                        Ok((k, rexpr))
                    } else {
                        Err(JsonDeserializationError::TypeMismatch {
                            ctx: Box::new(JsonDeserializationErrorContext::EntityAttribute {
                                uid: uid.clone(),
                                attr: k,
                            }),
                            expected: Box::new(expected_ty),
                            actual: Box::new(actual_ty),
                        })
                    }
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
                            return Err(JsonDeserializationError::ActionDeclarationMismatch {
                                uid: uid.clone(),
                            })
                        }
                        Some(rexpr) => rexpr,
                    };
                    let expected_ty =
                        vparser.type_of_rexpr(expected_rexpr.as_borrowed(), || {
                            JsonDeserializationErrorContext::EntityAttribute {
                                uid: uid.clone(),
                                attr: k.clone(),
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
                        Err(JsonDeserializationError::ActionDeclarationMismatch {
                            uid: uid.clone(),
                        })
                    }
                }
            })
            .collect::<Result<_, JsonDeserializationError>>()?;
        let is_parent_allowed = |parent_euid: &EntityUID| {
            match &entity_schema_info {
                EntitySchemaInfo::NoSchema => {
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
                }
                EntitySchemaInfo::Action(action) => {
                    // allowed iff the schema's copy also has this parent edge
                    if action.is_descendant_of(parent_euid) {
                        Ok(())
                    } else {
                        Err(JsonDeserializationError::ActionDeclarationMismatch {
                            uid: uid.clone(),
                        })
                    }
                }
                EntitySchemaInfo::NonAction(desc) => {
                    let parent_type = parent_euid.entity_type();
                    if desc.allowed_parent_types().contains(parent_type) {
                        Ok(())
                    } else {
                        Err(JsonDeserializationError::InvalidParentType {
                            ctx: Box::new(JsonDeserializationErrorContext::EntityParents {
                                uid: uid.clone(),
                            }),
                            uid: uid.clone(),
                            parent_ty: Box::new(parent_type.clone()),
                        })
                    }
                }
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
        match &entity_schema_info {
            EntitySchemaInfo::NoSchema => {}     // no checks to do
            EntitySchemaInfo::NonAction(_) => {} // no checks to do
            EntitySchemaInfo::Action(action) => {
                // check that the json entity and the schema declaration
                // fully agree on parents
                if parents != *action.ancestors_set() {
                    return Err(JsonDeserializationError::ActionDeclarationMismatch { uid });
                }
            }
        }
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
                .iter()
                .map(|(k, expr)| {
                    Ok((
                        k.clone(),
                        serde_json::to_value(JSONValue::from_expr(expr.as_borrowed())?)?,
                    ))
                })
                .collect::<Result<_, JsonSerializationError>>()?,
            parents: entity
                .ancestors()
                .map(|euid| EntityUidJSON::ImplicitEntityEscape(TypeAndId::from(euid.clone())))
                .collect(),
        })
    }
}
