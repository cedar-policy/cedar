use super::{
    EntityUidJSON, JSONValue, JsonDeserializationError, JsonDeserializationErrorContext,
    JsonSerializationError, SchemaType, TypeAndId, ValueParser,
};
use crate::ast::{Entity, EntityType, RestrictedExpr};
use crate::entities::{Entities, EntitiesError, TCComputation};
use crate::extensions::Extensions;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::HashMap;

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

/// Trait for `Schema`s that can inform the parsing of Entity JSON data
pub trait Schema {
    /// Do entities of the given type have the given attribute, and if so, what type?
    ///
    /// Returning `None` indicates that attribute should not exist.
    fn attr_type(&self, entity_type: &EntityType, attr: &str) -> Option<SchemaType>;

    /// Get the names of all the required attributes for the given entity type.
    fn required_attrs<'s>(
        &'s self,
        entity_type: &EntityType,
    ) -> Box<dyn Iterator<Item = SmolStr> + 's>;
}

/// Simple type that implements `Schema` by expecting no attributes to exist
#[derive(Debug, Clone)]
pub struct NullSchema;
impl Schema for NullSchema {
    fn attr_type(&self, _entity_type: &EntityType, _attr: &str) -> Option<SchemaType> {
        None
    }
    fn required_attrs(&self, _entity_type: &EntityType) -> Box<dyn Iterator<Item = SmolStr>> {
        Box::new(std::iter::empty())
    }
}

/// Struct used to parse entities from JSON.
#[derive(Debug, Clone)]
pub struct EntityJsonParser<'e, 's, S: Schema = NullSchema> {
    /// If a `schema` is present, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit, and it will error
    /// if attributes have the wrong types (e.g., string instead of integer).
    /// That does not mean it will fully enforce that the produced `Entities`
    /// conform to the `schema` -- for instance, as of this writing, it will not
    /// error for unexpected (additional) record attributes.
    schema: Option<&'s S>,

    /// Extensions which are active for the JSON parsing.
    extensions: Extensions<'e>,

    /// Whether to compute, enforce, or assume TC for entities parsed using this
    /// parser.
    tc_computation: TCComputation,
}

impl<'e, 's, S: Schema> EntityJsonParser<'e, 's, S> {
    /// Create a new `EntityJsonParser`.
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit, and it will error
    /// if attributes have the wrong types (e.g., string instead of integer).
    /// That does not mean it will fully enforce that the produced `Entities`
    /// conform to the `schema` -- for instance, as of this writing, it will not
    /// error for unexpected (additional) record attributes.
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

    /// Parse an entities JSON file (in `&str` form) into an `Entities` object
    pub fn from_json_str(&self, json: &str) -> Result<Entities, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_str(json).map_err(JsonDeserializationError::from)?;
        self.parse_ejsons(ejsons)
    }

    /// Parse an entities JSON file (in `serde_json::Value` form) into an `Entities` object
    pub fn from_json_value(&self, json: serde_json::Value) -> Result<Entities, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_value(json).map_err(JsonDeserializationError::from)?;
        self.parse_ejsons(ejsons)
    }

    /// Parse an entities JSON file (in `std::io::Read` form) into an `Entities` object
    pub fn from_json_file(&self, json: impl std::io::Read) -> Result<Entities, EntitiesError> {
        let ejsons: Vec<EntityJSON> =
            serde_json::from_reader(json).map_err(JsonDeserializationError::from)?;
        self.parse_ejsons(ejsons)
    }

    /// internal function that creates an `Entities` from a stream of `EntityJSON`
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
        // first, we ensure that all required attributes for `etype` are actually
        // included in `ejson.attrs`. Later when consuming `ejson.attrs` to build
        // `attrs`, we'll check for unexpected attributes.
        match self.schema {
            None => {}
            Some(schema) => {
                for required_attr in schema.required_attrs(etype) {
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
            .map(|(k, v)| match self.schema {
                None => Ok((
                    k.clone(),
                    vparser.val_into_rexpr(v, None, || {
                        JsonDeserializationErrorContext::EntityAttribute {
                            uid: uid.clone(),
                            attr: k.clone(),
                        }
                    })?,
                )),
                Some(schema) => {
                    // query the schema to get the expected type. Depending on
                    // the expected type, we may parse the contents of the
                    // attribute differently.
                    let (rexpr, expected_ty) = match schema.attr_type(etype, &k) {
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
                            ctx: JsonDeserializationErrorContext::EntityAttribute {
                                uid: uid.clone(),
                                attr: k,
                            },
                            expected: Box::new(expected_ty),
                            actual: Box::new(actual_ty),
                        })
                    }
                }
            })
            .collect::<Result<_, JsonDeserializationError>>()?;
        let parents = ejson
            .parents
            .into_iter()
            .map(|parent| {
                parent.into_euid(|| JsonDeserializationErrorContext::EntityParents {
                    uid: uid.clone(),
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
