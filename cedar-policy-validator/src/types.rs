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

//! Defines the type structure for typechecking and various utilities for
//! constructing and manipulating types.

use serde::Serialize;
use smol_str::SmolStr;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt::Display,
};

use cedar_policy_core::ast::{EntityType, EntityUID, Expr, ExprShapeOnly, Name};

use super::schema::{
    is_action_entity_type, ValidatorActionId, ValidatorEntityType, ValidatorSchema,
};

/// Contains the four variables bound in the type environment. These together
/// represent the full type of (principal, action, resource, context)
/// authorization request.
#[derive(Clone, Debug, PartialEq)]
pub struct RequestEnv<'a> {
    pub principal: &'a EntityType,
    pub action: &'a EntityUID,
    pub resource: &'a EntityType,
    pub context: &'a Attributes,

    pub principal_slot: Option<EntityType>,
    pub resource_slot: Option<EntityType>,
}

/// The main type structure.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Serialize)]
pub enum Type {
    /// Bottom type. Sub-type of all types.
    Never,

    /// The singleton boolean types: true and false.
    True,
    False,

    /// Primitive types: bool, long, and string.
    Primitive {
        #[serde(rename = "primitiveType")]
        primitive_type: Primitive,
    },

    /// The type of sets containing some type.
    Set {
        /// The type of the elements in the set, or None if it represents an
        /// arbitrary set type. This should only be None when the type is being
        /// used in a subtype comparison (commonly done through `expect_type` in
        /// `typecheck.rs`) or for error reporting through the `TypeError`
        /// structure.
        #[serde(rename = "elementType")]
        element_type: Option<Box<Type>>,
    },

    /// Record and entity types.
    EntityOrRecord(EntityRecordKind),

    // Extension types, like "ipaddr".
    ExtensionType {
        name: Name,
    },
}

impl Type {
    pub(crate) fn singleton_boolean(val: bool) -> Type {
        if val {
            Type::True
        } else {
            Type::False
        }
    }

    pub(crate) fn primitive_boolean() -> Type {
        Type::Primitive {
            primitive_type: Primitive::Bool,
        }
    }

    pub(crate) fn primitive_long() -> Type {
        Type::Primitive {
            primitive_type: Primitive::Long,
        }
    }

    pub(crate) fn primitive_string() -> Type {
        Type::Primitive {
            primitive_type: Primitive::String,
        }
    }

    /// Construct a type for a literal EUID. This type will be a named entity
    /// type for the type of the EntityUID.
    pub(crate) fn euid_literal(entity: EntityUID, schema: &ValidatorSchema) -> Option<Type> {
        match entity.entity_type() {
            EntityType::Unspecified => None,
            EntityType::Concrete(name) => {
                if is_action_entity_type(name) {
                    schema
                        .get_action_id(&entity)
                        .and_then(Type::entity_reference_from_action_id)
                } else {
                    schema
                        .get_entity_type(name)
                        .map(Type::entity_reference_from_entity_type)
                }
            }
        }
    }

    pub(crate) fn any_set() -> Type {
        Type::Set { element_type: None }
    }

    pub(crate) fn set(ety: Type) -> Type {
        Type::Set {
            element_type: Some(Box::new(ety)),
        }
    }

    pub(crate) fn any_record() -> Type {
        // OpenAttributes <: ClosedAttributes, so this makes `any_record` a
        // super type of all records.
        Type::record_with_attributes(None, OpenTag::OpenAttributes)
    }

    pub(crate) fn record_with_required_attributes(
        required_attrs: impl IntoIterator<Item = (SmolStr, Type)>,
        open_attributes: OpenTag,
    ) -> Type {
        Type::EntityOrRecord(EntityRecordKind::Record {
            attrs: Attributes::with_required_attributes(required_attrs),
            open_attributes,
        })
    }

    pub(crate) fn record_with_attributes(
        attrs: impl IntoIterator<Item = (SmolStr, AttributeType)>,
        open_attributes: OpenTag,
    ) -> Type {
        Type::EntityOrRecord(EntityRecordKind::Record {
            attrs: Attributes::with_attributes(attrs),
            open_attributes,
        })
    }

    pub(crate) fn entity_reference_from_entity_type(
        validator_entity_type: &ValidatorEntityType,
    ) -> Type {
        Type::named_entity_reference(validator_entity_type.name.clone())
    }

    pub(crate) fn entity_reference_from_action_id(
        validator_action_id: &ValidatorActionId,
    ) -> Option<Type> {
        match validator_action_id.name.entity_type() {
            EntityType::Concrete(name) => {
                Some(Type::EntityOrRecord(EntityRecordKind::ActionEntity {
                    name: name.clone(),
                    attrs: Attributes::with_attributes(validator_action_id.attribute_types.clone()),
                }))
            }
            EntityType::Unspecified => None,
        }
    }

    pub(crate) fn possibly_unspecified_entity_reference(ety: EntityType) -> Type {
        match ety {
            EntityType::Concrete(name) => Type::named_entity_reference(name),
            EntityType::Unspecified => Type::any_entity_reference(),
        }
    }

    pub(crate) fn named_entity_reference(name: Name) -> Type {
        Type::EntityOrRecord(EntityRecordKind::Entity(EntityLUB::single_entity(name)))
    }

    pub(crate) fn any_entity_reference() -> Type {
        Type::EntityOrRecord(EntityRecordKind::AnyEntity)
    }

    pub(crate) fn extension(name: Name) -> Type {
        Type::ExtensionType { name }
    }

    /// Implements a subtype relation for the type structure. This requires a
    /// `schema` so that the declared attributes for named entity types can be
    /// retrieved. This is used to determine subtyping between a named entity
    /// type and a record type.
    pub(crate) fn is_subtype(schema: &ValidatorSchema, ty0: &Type, ty1: &Type) -> bool {
        match (ty0, ty1) {
            // Never is a subtype of every type.
            (Type::Never, _) => true,

            (
                Type::True | Type::False,
                Type::Primitive {
                    primitive_type: Primitive::Bool,
                },
            ) => true,
            (Type::True, Type::True) => true,
            (Type::False, Type::False) => true,

            // Subtypes between two primitives only occurs when the primitive
            // types are the same.
            (Type::Primitive { primitive_type: _ }, Type::Primitive { primitive_type: _ }) => {
                ty0 == ty1
            }

            // A set type is a subtype other set type when its element type is a subtype.
            (
                Type::Set {
                    element_type: e_ty0,
                },
                Type::Set {
                    element_type: e_ty1,
                },
            ) => match (e_ty0, e_ty1) {
                (Some(e_ty0), Some(e_ty1)) => Type::is_subtype(schema, e_ty0, e_ty1),
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => true,
            },

            (Type::EntityOrRecord(rk0), Type::EntityOrRecord(rk1)) => {
                EntityRecordKind::is_subtype(schema, rk0, rk1)
            }

            // Subtypes between extension types only occurs when the extension
            // types are the same.
            (Type::ExtensionType { .. }, Type::ExtensionType { .. }) => ty0 == ty1,

            // If none of the above apply, then ty0 is not a subtype of ty1.
            _ => false,
        }
    }

    /// Compute the least upper bound of two types. This is a type such that each
    /// type is a subtype of the least upper bound.
    pub(crate) fn least_upper_bound(
        schema: &ValidatorSchema,
        ty0: &Type,
        ty1: &Type,
    ) -> Option<Type> {
        match (ty0, ty1) {
            _ if Type::is_subtype(schema, ty0, ty1) => Some(ty1.clone()),
            _ if Type::is_subtype(schema, ty1, ty0) => Some(ty0.clone()),

            (Type::True | Type::False, Type::True | Type::False) => Some(Type::primitive_boolean()),

            // `None` as an element type represents the top type for the set
            // element, so every other set is a subtype of set<None>, making a
            // least upper bound containing  set<None> and another set type
            // equal to set<None>. This case should be impossible due to the
            // subtype checks in the first two match cases, but we handle it
            // explicitly as an alternative to panicking if it occurs.
            (ty_lub @ Type::Set { element_type: None }, Type::Set { .. })
            | (Type::Set { .. }, ty_lub @ Type::Set { element_type: None }) => Some(ty_lub.clone()),

            // The least upper bound of two set types is a set with
            // an element type that is the element type least upper bound.
            (
                Type::Set {
                    element_type: Some(te0),
                },
                Type::Set {
                    element_type: Some(te1),
                },
            ) => Some(Type::set(Type::least_upper_bound(schema, te0, te1)?)),

            (Type::EntityOrRecord(rk0), Type::EntityOrRecord(rk1)) => Some(Type::EntityOrRecord(
                EntityRecordKind::least_upper_bound(schema, rk0, rk1)?,
            )),

            _ => None,
        }
    }

    // Return `true` if the parameter types are definitely disjoint, i.e., there
    // are no values which inhabit both types. It is tempting to say that types
    // are disjoint if neither is a subtype of the other, but this would be
    // incorrect for set types where the set can be empty.  set<int> and
    // set<bool> would then be considered disjoint, but both are inhabited by
    // the empty set. This function could safely decide that more types are
    // disjoint than it currently does, e.g., it is correct to say `long` and
    // `bool` are disjoint, but it is also safe to conservatively approximate
    // this function by deciding that fewer types are disjoint than are in
    // reality. Declaring types disjoint when they are not disjoint would, on
    // the other hand, cause soundness errors in the typechecker.
    pub(crate) fn are_types_disjoint(ty1: &Type, ty2: &Type) -> bool {
        match (ty1, ty2) {
            // Entity types least-upper-bounds that have no entity types in
            // common.
            (Type::EntityOrRecord(k1), Type::EntityOrRecord(k2)) => {
                match (k1.as_entity_lub(), k2.as_entity_lub()) {
                    (Some(lub1), Some(lub2)) => lub1.is_disjoint(&lub2),
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Given a list of types, compute the least upper bound of all types in the
    /// list. The least upper bound of an empty list is Never.
    pub(crate) fn reduce_to_least_upper_bound(
        schema: &ValidatorSchema,
        tys: &[Type],
    ) -> Option<Type> {
        tys.iter().fold(Some(Type::Never), |lub, next| {
            lub.and_then(|lub| Type::least_upper_bound(schema, &lub, next))
        })
    }

    /// Get the type of the specified attribute of an entity or record type.
    /// If the type is not an entity or record type, or does not have the
    /// required attribute, then `None` is returned.
    pub(crate) fn lookup_attribute_type(
        schema: &ValidatorSchema,
        ty: &Type,
        attr: &str,
    ) -> Option<AttributeType> {
        match ty {
            Type::EntityOrRecord(rk) => rk.get_attr(schema, attr),
            _ => None,
        }
    }

    /// Get all statically known attributes of an entity or record type.
    /// Returns an empty vector if no attributes or type is not an entity or record type.
    pub fn all_attributes(&self, schema: &ValidatorSchema) -> Vec<SmolStr> {
        match self {
            Type::EntityOrRecord(e) => e.all_attrs(schema),
            _ => vec![],
        }
    }

    /// Return true if the Type `ty` could possibly contain the attribute
    /// `attr`. Record and entity types can contain attributes, so we check if
    /// the type can contain the specific attribute. Other types cannot have
    /// attributes, so we return false.
    pub(crate) fn may_have_attr(schema: &ValidatorSchema, ty: &Type, attr: &str) -> bool {
        match ty {
            // Never, being the bottom type, is a subtype of EntityOrRecord, so
            // it could have any attributes.
            Type::Never => true,
            // An EntityOrRecord might have an open attributes record, in which
            // case it could have any attribute.
            Type::EntityOrRecord(k) if k.has_open_attributes_record() => true,
            // In this case and all following `EntityOrRecord` cases, we know it
            // does not have an open attributes record, so we know that an
            // attribute may not exist if it is not explicitly listed in the
            // type. For an entity, we look this up in the schema.  For an
            // entity least upper bound resulting from multiple entity
            // types, the type might have the attribute if any of the
            // constituent entity types have the attribute in the schema.
            Type::EntityOrRecord(EntityRecordKind::Entity(entity_lub)) => {
                entity_lub.lub_elements.iter().any(|entity| {
                    schema
                        .get_entity_type(entity)
                        .map_or(false, |entity_type| entity_type.attr(attr).is_some())
                })
            }
            // UBs of ActionEntities are AnyEntity. So if we have an ActionEntity here its attrs are known
            Type::EntityOrRecord(EntityRecordKind::ActionEntity { attrs, .. }) => {
                attrs.iter().any(|(found_attr, _)| attr.eq(found_attr))
            }
            // A record will have an attribute if the attribute is in its
            // attributes map. Records computed as a LUB may have an open
            // attributes record, but that is handled by the first match case.
            Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => {
                attrs.get_attr(attr).is_some()
            }
            // No other types may have attributes.
            _ => false,
        }
    }

    /// Return true if we know that any value in this type must be a specified
    /// entity. An unspecified entity has type `AnyEntity`, so `AnyEntity` might
    /// not be specified. Other entity types must be specified.
    pub(crate) fn must_be_specified_entity(ty: &Type) -> bool {
        matches!(
            ty,
            Type::EntityOrRecord(
                EntityRecordKind::Entity(_) | EntityRecordKind::ActionEntity { .. }
            )
        )
    }

    fn json_type(type_name: &str) -> serde_json::value::Map<String, serde_json::value::Value> {
        [("type".to_string(), type_name.into())]
            .into_iter()
            .collect()
    }

    fn to_type_json(&self) -> serde_json::value::Map<String, serde_json::value::Value> {
        match self {
            Type::Never => Type::json_type("Never"),
            Type::True => Type::json_type("True"),
            Type::False => Type::json_type("False"),
            Type::Primitive {
                primitive_type: Primitive::Bool,
            } => Type::json_type("Boolean"),
            Type::Primitive {
                primitive_type: Primitive::Long,
            } => Type::json_type("Long"),
            Type::Primitive {
                primitive_type: Primitive::String,
            } => Type::json_type("String"),
            Type::Set { element_type } => {
                let mut set_json = Type::json_type("Set");
                match element_type {
                    Some(e_ty) => {
                        set_json.insert("element".to_string(), (*e_ty).to_type_json().into());
                    }
                    None => (),
                }
                set_json
            }
            Type::EntityOrRecord(rk) => {
                let mut record_json = match rk {
                    EntityRecordKind::Record { .. } => Type::json_type("Record"),
                    EntityRecordKind::AnyEntity => Type::json_type("Entity"),
                    EntityRecordKind::Entity(entities) => entities.to_type_json(),
                    EntityRecordKind::ActionEntity { .. } => Type::json_type("ActionEntity"),
                };
                match rk {
                    EntityRecordKind::Record {
                        attrs,
                        open_attributes,
                    } => {
                        let attr_json = attrs
                            .iter()
                            .map(|(attr, attr_ty)| {
                                (attr.to_string(), {
                                    let mut attr_ty_json = attr_ty.attr_type.to_type_json();
                                    attr_ty_json
                                        .insert("required".to_string(), attr_ty.is_required.into());
                                    attr_ty_json.into()
                                })
                            })
                            .collect::<serde_json::value::Map<_, _>>();
                        record_json.insert("attributes".to_string(), attr_json.into());
                        if open_attributes.is_open() {
                            record_json.insert(
                                "additionalAttributes".to_string(),
                                open_attributes.is_open().into(),
                            );
                        }
                    }
                    EntityRecordKind::ActionEntity { name, attrs } => {
                        let attr_json = attrs
                            .iter()
                            .map(|(attr, attr_ty)| {
                                (attr.to_string(), {
                                    let mut attr_ty_json = attr_ty.attr_type.to_type_json();
                                    attr_ty_json
                                        .insert("required".to_string(), attr_ty.is_required.into());
                                    attr_ty_json.into()
                                })
                            })
                            .collect::<serde_json::value::Map<_, _>>();
                        record_json.insert("attributes".to_string(), attr_json.into());
                        record_json.insert("name".to_string(), name.to_string().into());
                    }
                    // In these case, we don't need to record attributes.
                    // `AnyEntity` does not have attributes while `Entity(_)`
                    // attributes are specified by the list of entities in the
                    // LUB.
                    EntityRecordKind::AnyEntity | EntityRecordKind::Entity(_) => {}
                }
                record_json
            }
            Type::ExtensionType { name } => {
                let mut ext_json = Type::json_type("Extension");
                ext_json.insert("name".into(), name.to_string().into());
                ext_json
            }
        }
    }

    /// Is this validator type "consistent with" the given Core SchemaType.
    /// Meaning, is there at least some value that could have this SchemaType and
    /// this validator type simultaneously.
    pub(crate) fn is_consistent_with(
        &self,
        core_type: &cedar_policy_core::entities::SchemaType,
    ) -> bool {
        use cedar_policy_core::ast::EntityType as CoreEntityType;
        use cedar_policy_core::entities::SchemaType as CoreSchemaType;
        match core_type {
            CoreSchemaType::Bool => matches!(
                self,
                Type::True
                    | Type::False
                    | Type::Primitive {
                        primitive_type: Primitive::Bool
                    }
            ),
            CoreSchemaType::Long => matches!(
                self,
                Type::Primitive {
                    primitive_type: Primitive::Long
                }
            ),
            CoreSchemaType::String => matches!(
                self,
                Type::Primitive {
                    primitive_type: Primitive::String
                }
            ),
            CoreSchemaType::Set { element_ty } => {
                matches!(self, Type::Set { element_type: Some(element_type) } if element_type.is_consistent_with(element_ty))
            }
            CoreSchemaType::EmptySet => matches!(self, Type::Set { .. }), // empty-set matches a set of any element type
            CoreSchemaType::Record { attrs } => match self {
                Type::EntityOrRecord(kind) => match kind {
                    EntityRecordKind::Record {
                        attrs: self_attrs, ..
                    } => {
                        attrs.iter().all(|(k, v)| {
                            match self_attrs.get_attr(k) {
                                Some(ty) => {
                                    // both have the attribute, doesn't matter
                                    // if one or both consider it required or
                                    // optional
                                    ty.attr_type.is_consistent_with(v.schema_type())
                                }
                                None => {
                                    // attrs has the attribute, self_attrs does not.
                                    // if required in attrs, incompatible.
                                    // otherwise fine
                                    !v.is_required()
                                }
                            }
                        }) && self_attrs.iter().all(|(k, v)| {
                            match attrs.get(k) {
                                Some(ty) => {
                                    // both have the attribute, doesn't matter
                                    // if one or both consider it required or
                                    // optional
                                    v.attr_type.is_consistent_with(ty.schema_type())
                                }
                                None => {
                                    // self_attrs has the attribute, attrs does not.
                                    // if required in self_attrs, incompatible.
                                    // otherwise fine
                                    !v.is_required
                                }
                            }
                        })
                    }
                    EntityRecordKind::Entity(_)
                    | EntityRecordKind::AnyEntity
                    | EntityRecordKind::ActionEntity { .. } => false,
                },
                _ => false,
            },
            CoreSchemaType::Entity {
                ty: CoreEntityType::Concrete(concrete_name),
            } => match self {
                Type::EntityOrRecord(kind) => match kind {
                    EntityRecordKind::Entity(lub) => {
                        lub.lub_elements.iter().any(|n| n == concrete_name)
                    }
                    EntityRecordKind::AnyEntity => true,
                    EntityRecordKind::Record { .. } => false,
                    EntityRecordKind::ActionEntity { name, .. } => concrete_name.eq(name),
                },
                _ => false,
            },
            CoreSchemaType::Entity {
                ty: CoreEntityType::Unspecified,
            } => match self {
                Type::EntityOrRecord(kind) => match kind {
                    EntityRecordKind::Entity(_) => false, // Entity(lub) is inconsistent with Unspecified
                    EntityRecordKind::AnyEntity => true,
                    EntityRecordKind::Record { .. } | EntityRecordKind::ActionEntity { .. } => {
                        false
                    }
                },
                _ => false,
            },
            CoreSchemaType::Extension { name } => {
                matches!(self, Type::ExtensionType { name: n } if name == n)
            }
        }
    }
}

impl Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::value::Value::Object(self.to_type_json())
        )
    }
}

impl TryFrom<Type> for cedar_policy_core::entities::SchemaType {
    type Error = String;
    fn try_from(ty: Type) -> Result<cedar_policy_core::entities::SchemaType, String> {
        use cedar_policy_core::entities::AttributeType as CoreAttributeType;
        use cedar_policy_core::entities::SchemaType as CoreSchemaType;
        match ty {
            Type::Never => Err("'Never' type is not representable in core::Type".into()),
            Type::True | Type::False => Ok(CoreSchemaType::Bool),
            Type::Primitive {
                primitive_type: Primitive::Bool,
            } => Ok(CoreSchemaType::Bool),
            Type::Primitive {
                primitive_type: Primitive::Long,
            } => Ok(CoreSchemaType::Long),
            Type::Primitive {
                primitive_type: Primitive::String,
            } => Ok(CoreSchemaType::String),
            Type::Set {
                element_type: Some(element_type),
            } => Ok(CoreSchemaType::Set {
                element_ty: Box::new(CoreSchemaType::try_from(*element_type)?),
            }),
            Type::Set { element_type: None } => {
                Err("Set<None> type is not representable in core::SchemaType".into())
            }
            Type::EntityOrRecord(kind @ EntityRecordKind::AnyEntity) => Err(format!(
                "any-entity type is not representable in core::Type: {:?}",
                kind
            )),
            Type::EntityOrRecord(EntityRecordKind::ActionEntity { name, .. }) => {
                Ok(CoreSchemaType::Entity {
                    ty: EntityType::Concrete(name),
                })
            }
            Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => {
                Ok(CoreSchemaType::Record {
                    attrs: {
                        attrs
                            .into_iter()
                            .map(|(k, v)| {
                                let schema_type = v.attr_type.try_into()?;
                                Ok((
                                    k,
                                    match v.is_required {
                                        true => CoreAttributeType::required(schema_type),
                                        false => CoreAttributeType::optional(schema_type),
                                    },
                                ))
                            })
                            .collect::<Result<_, String>>()?
                    },
                })
            }
            Type::EntityOrRecord(EntityRecordKind::Entity(lub)) => match lub.into_single_entity() {
                Some(name) => Ok(CoreSchemaType::Entity {
                    ty: EntityType::Concrete(name),
                }),
                None => {
                    Err("non-singleton LUB type is not representable in core::Type".to_string())
                }
            },
            Type::ExtensionType { name } => Ok(CoreSchemaType::Extension { name }),
        }
    }
}

/// Represents the least upper bound of multiple entity types. This can be used
/// to represent the least upper bound of a single entity type, in which case it
/// is exactly that entity type.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Serialize)]
pub struct EntityLUB {
    // INVARIANT: Non-empty set.
    lub_elements: BTreeSet<Name>,
}

impl EntityLUB {
    /// Create a least upper bound of a single entity type. This is the same as
    /// just that entity type.
    fn single_entity(entity_type_name: Name) -> Self {
        Self {
            lub_elements: [entity_type_name].into_iter().collect(),
        }
    }

    /// Check if this LUB is a singleton, and if so, return a reference to its entity type
    pub fn get_single_entity(&self) -> Option<&Name> {
        let mut names = self.lub_elements.iter();
        // PANIC SAFETY: Invariant on `lub_elements` guarantees the set is non-empty.
        #[allow(clippy::expect_used)]
        let first = names.next().expect("should have one element by invariant");
        match names.next() {
            Some(_) => None, // there are two or more names
            None => Some(first),
        }
    }

    /// Like `get_single_entity()`, but consumes the EntityLUB and produces an
    /// owned entity type name
    pub fn into_single_entity(self) -> Option<Name> {
        let mut names = self.lub_elements.into_iter();
        // PANIC SAFETY: Invariant on `lub_elements` guarantees the set is non-empty.
        #[allow(clippy::expect_used)]
        let first = names.next().expect("should have one element by invariant");
        match names.next() {
            Some(_) => None, // there are two or more names
            None => Some(first),
        }
    }

    /// Check if the entity least upper bound is a subtype of another. This is
    /// the case when the entity types in the least upper bound are a subset of
    /// the entity types in the other.
    fn is_subtype(&self, other: &EntityLUB) -> bool {
        self.lub_elements.is_subset(&other.lub_elements)
    }

    /// Retrieve the attributes and their types. If this is a single entity type,
    /// then return exactly the attributes stored in schema for that entity
    /// type. Otherwise, retrieve all attribute maps for all entities in the
    /// least upper bound and compute the least upper bound of these maps. This
    /// will keep only the common attributes with a type that is the least upper
    /// bound of the all the attribute type.
    fn get_attribute_types(&self, schema: &ValidatorSchema) -> Attributes {
        let mut lub_element_attributes = self.lub_elements.iter().map(|name| {
            schema
                .get_entity_type(name)
                .map(|entity_type| entity_type.attributes.clone())
                .unwrap_or_else(|| Attributes::with_attributes(None))
        });

        // If I wanted to write this as a fold over a possibly empty set, I
        // would need a bottom record type that would contain every attribute with a
        // bottom type. We don't have that, so I instead restrict EntityLUB to
        // be a least upper bound of one or more entities.
        // PANIC SAFETY: Invariant on `lub_elements` guarantees the set is non-empty.
        #[allow(clippy::expect_used)]
        let arbitrary_first = Attributes::with_attributes(
            lub_element_attributes
                .next()
                .expect("Invariant violated: EntityLUB set must be non-empty."),
        );
        lub_element_attributes.fold(arbitrary_first, |acc, elem| {
            Attributes::least_upper_bound(schema, &acc, &Attributes::with_attributes(elem))
        })
    }

    /// Generate the least upper bound of this EntityLUB and another. This
    /// returns an EntityLUB for the union of the entity types in both argument
    /// LUBs. The attributes of the LUB are not computed.
    fn least_upper_bound(&self, other: &EntityLUB) -> EntityLUB {
        EntityLUB {
            lub_elements: self
                .lub_elements
                .union(&other.lub_elements)
                .cloned()
                .collect::<BTreeSet<_>>(),
        }
    }

    /// Return true if the set of entity types composing this EntityLUB is
    /// disjoint from th entity types composing another LUB.
    pub(crate) fn is_disjoint(&self, other: &EntityLUB) -> bool {
        self.lub_elements.is_disjoint(&other.lub_elements)
    }

    /// An iterator over the entity type `Name`s in the set of entity types
    /// comprising this LUB.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Name> {
        self.lub_elements.iter()
    }

    fn to_type_json(&self) -> serde_json::value::Map<String, serde_json::value::Value> {
        let mut ordered_lub_elems = self.lub_elements.iter().collect::<Vec<_>>();
        // We want the display order of elements of the set to be consistent.
        ordered_lub_elems.sort();

        let mut lub_element_objs = ordered_lub_elems.iter().map(|name| {
            [
                ("type".to_string(), "Entity".into()),
                ("name".to_string(), name.to_string().into()),
            ]
            .into_iter()
            .collect()
        });
        if self.lub_elements.len() == 1 {
            // PANIC SAFETY: Invariant on `lub_elements` guarantees the set is non-empty.
            #[allow(clippy::expect_used)]
            lub_element_objs
                .next()
                .expect("Invariant violated: EntityLUB set must be non-empty.")
        } else {
            let mut entities_json = Type::json_type("Union");
            entities_json.insert(
                "elements".to_string(),
                lub_element_objs.collect::<Vec<_>>().into(),
            );
            entities_json
        }
    }
}

/// Represents the attributes of a record or entity type. Each attribute has an
/// identifier, a flag indicating weather it is required, and a type.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Serialize)]
pub struct Attributes {
    pub attrs: BTreeMap<SmolStr, AttributeType>,
}

impl Attributes {
    /// Construct an Attributes with some required attributes.
    pub(crate) fn with_required_attributes(
        required_attrs: impl IntoIterator<Item = (SmolStr, Type)>,
    ) -> Self {
        Self {
            attrs: required_attrs
                .into_iter()
                .map(|(attr, ty)| (attr, AttributeType::required_attribute(ty)))
                .collect(),
        }
    }

    /// Construct an Attributes with some attributes that may be required or
    /// optional.
    pub(crate) fn with_attributes(
        attrs: impl IntoIterator<Item = (SmolStr, AttributeType)>,
    ) -> Self {
        Self {
            attrs: attrs.into_iter().collect(),
        }
    }

    /// Iterate over the attributes of this record with their types
    pub fn iter(&self) -> impl Iterator<Item = (&SmolStr, &AttributeType)> {
        self.attrs.iter()
    }

    /// Iterate over the attribute names of this record
    pub fn keys(&self) -> impl Iterator<Item = &SmolStr> {
        self.attrs.keys()
    }

    /// Get a tuple containing a boolean flag specifying if a attribute is
    /// required in the record and the type of the attribute. Returns None when
    /// the attribute is not in the record.
    pub(crate) fn get_attr(&self, attr: &str) -> Option<&AttributeType> {
        self.attrs.get(attr)
    }

    pub(crate) fn is_subtype(&self, schema: &ValidatorSchema, other: &Attributes) -> bool {
        // For a one record type to subtype another, all the attributes of the
        // second must be present in the first, and each attribute types must
        // subtype the corresponding attribute type. If an attribute in the
        // first is not required (optional), then that attribute must also be
        // optional in the second.
        other.attrs.iter().all(|(k, other_ty)| {
            self.attrs
                .get(k)
                .map(|self_ty| {
                    (self_ty.is_required || !other_ty.is_required)
                        && Type::is_subtype(schema, &self_ty.attr_type, &other_ty.attr_type)
                })
                .unwrap_or(false)
        })
    }

    // Determine if the attributes subtype while only allowing for depth
    // subtyping. This forbids width subtyping, so there may not be attributes
    // present in the subtype that do not exist in the super type.
    pub(crate) fn is_subtype_depth_only(
        &self,
        schema: &ValidatorSchema,
        other: &Attributes,
    ) -> bool {
        other.attrs.keys().collect::<HashSet<_>>() == self.attrs.keys().collect::<HashSet<_>>()
            && self.is_subtype(schema, other)
    }

    pub(crate) fn least_upper_bound(
        schema: &ValidatorSchema,
        attrs0: &Attributes,
        attrs1: &Attributes,
    ) -> Attributes {
        Attributes::with_attributes(attrs0.attrs.iter().filter_map(move |(attr, ty0)| {
            let ty1 = attrs1.attrs.get(attr)?;
            Type::least_upper_bound(schema, &ty0.attr_type, &ty1.attr_type).map(|lub| {
                let is_lub_required = ty0.is_required && ty1.is_required;
                (attr.clone(), AttributeType::new(lub, is_lub_required))
            })
        }))
    }
}

impl IntoIterator for Attributes {
    type Item = (SmolStr, AttributeType);

    type IntoIter = <BTreeMap<SmolStr, AttributeType> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.attrs.into_iter()
    }
}

/// Used to tag record types to indicate if their attributes record is open or
/// closed.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Copy, Clone, Serialize)]
pub enum OpenTag {
    // The attributes are open. A value of this type may have attributes other
    // than those listed.
    OpenAttributes,
    // The attributes are closed. The attributes for a value of this type must
    // exactly match the attributes listed in the type.
    ClosedAttributes,
}

impl OpenTag {
    pub(crate) fn is_open(self) -> bool {
        match self {
            OpenTag::OpenAttributes => true,
            OpenTag::ClosedAttributes => false,
        }
    }
}

/// Represents whether a type is an entity type, record type, or could be either
///
/// The subtyping lattice for these types is that
/// Entity <: AnyEntity. Record does not subtype anything.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Serialize)]
pub enum EntityRecordKind {
    /// A record type, with these attributes
    Record {
        /// The attributes that we know must exist (or may exist in the case of
        /// optional attributes) for a record with this type along with the
        /// types the attributes must have if they do exist.
        attrs: Attributes,
        /// Encodes whether the attributes for this record are open or closed.
        open_attributes: OpenTag,
    },
    /// Any entity type
    AnyEntity,
    /// An entity reference type. An entity reference might be a reference to one
    /// of multiple possible entity types when the entity references is the
    /// result of a least upper bound. An arbitrary entity without a name is
    /// represented using the `AnyEntity` record kind.
    ///
    /// Attributes in this case are not stored inline but must be looked up in
    /// the schema, based on the elements of the EntityLUB.
    Entity(EntityLUB),

    ///We special case action entities. They store their attributes directly rather than
    ///Names
    ActionEntity { name: Name, attrs: Attributes },
}

impl EntityRecordKind {
    pub(crate) fn as_entity_lub(&self) -> Option<EntityLUB> {
        match self {
            EntityRecordKind::Record { .. } => None,
            EntityRecordKind::AnyEntity => None,
            EntityRecordKind::Entity(lub) => Some(lub.clone()),
            EntityRecordKind::ActionEntity { name, .. } => {
                Some(EntityLUB::single_entity(name.clone()))
            }
        }
    }

    /// Return `true` if this entity or record may have additional undeclared
    /// attributes.
    pub(crate) fn has_open_attributes_record(&self) -> bool {
        match self {
            // Records explicitly store this information.
            EntityRecordKind::Record {
                open_attributes, ..
            } => open_attributes.is_open(),
            // We know Actions never have additional attributes. This is true
            // because the upper bound for any two action entities is
            // `AnyEntity`, so if we have an ActionEntity here its attributes
            // are known precisely.
            EntityRecordKind::ActionEntity { .. } => false,
            // The `AnyEntity` type has no declared attributes, but it is a
            // super type of all other entity types which may have attributes,
            // so it clearly may have additional attributes.
            EntityRecordKind::AnyEntity => true,
            // An entity LUB may not have an open attributes record. The record
            // type returned by `get_attributes_type` _may_ be open, but even in
            // that case we can account for all attributes that might exist by
            // examining the elements of the LUB.
            EntityRecordKind::Entity(_) => false,
        }
    }

    pub(crate) fn get_attr(&self, schema: &ValidatorSchema, attr: &str) -> Option<AttributeType> {
        match self {
            EntityRecordKind::Record { attrs, .. } => attrs.get_attr(attr).cloned(),
            EntityRecordKind::ActionEntity { attrs, .. } => attrs.get_attr(attr).cloned(),
            EntityRecordKind::AnyEntity => None,
            EntityRecordKind::Entity(lub) => {
                lub.get_attribute_types(schema).get_attr(attr).cloned()
            }
        }
    }

    pub fn all_attrs(&self, schema: &ValidatorSchema) -> Vec<SmolStr> {
        // Wish the clone here could be avoided, but `get_attribute_types` returns an owned `Attributes`.
        match self {
            EntityRecordKind::Record { attrs, .. } => attrs.attrs.keys().cloned().collect(),
            EntityRecordKind::ActionEntity { attrs, .. } => attrs.attrs.keys().cloned().collect(),
            EntityRecordKind::AnyEntity => vec![],
            EntityRecordKind::Entity(lub) => {
                lub.get_attribute_types(schema).attrs.into_keys().collect()
            }
        }
    }

    pub(crate) fn least_upper_bound(
        schema: &ValidatorSchema,
        rk0: &EntityRecordKind,
        rk1: &EntityRecordKind,
    ) -> Option<EntityRecordKind> {
        use EntityRecordKind::*;
        match (rk0, rk1) {
            (
                Record {
                    attrs: attrs0,
                    open_attributes: open0,
                },
                Record {
                    attrs: attrs1,
                    open_attributes: open1,
                },
            ) => {
                let attrs = Attributes::least_upper_bound(schema, attrs0, attrs1);

                // Even though this function will never be called when the
                // records are in a subtype relation, it is still possible that
                // the LUB attribute set is the same the attribute key sets for
                // `rk0` and `rk1`. This occurs when `rk0` and `rk1` have
                // identical attribute keys sets with all corresponding
                // attributes having a LUB while at least one pair of
                // corresponding attributes is not in a subtype relation.
                // E.g., Given `{a: true}` and `{a: false}`, the LUB is `{a: bool}`,
                // and we know that `a` is the only attribute for this (closed)
                // record even though neither is subtype of the other.
                let open_attributes = if open0.is_open()
                    || open1.is_open()
                    || (attrs.keys().collect::<BTreeSet<_>>()
                        != (attrs0.keys().chain(attrs1.keys()).collect::<BTreeSet<_>>()))
                {
                    OpenTag::OpenAttributes
                } else {
                    OpenTag::ClosedAttributes
                };
                Some(Record {
                    attrs,
                    open_attributes,
                })
            }
            //We cannot take upper bounds of action entities because may_have_attr assumes the list of attrs it complete
            (ActionEntity { .. }, ActionEntity { .. }) => Some(AnyEntity),
            (Entity(lub0), Entity(lub1)) => Some(Entity(lub0.least_upper_bound(lub1))),

            (AnyEntity, AnyEntity)
            | (AnyEntity, Entity(_))
            | (Entity(_), AnyEntity)
            | (AnyEntity, ActionEntity { .. })
            | (ActionEntity { .. }, AnyEntity) => Some(AnyEntity),

            // Entity and record types do not have a least upper bound to avoid
            // a non-terminating case.
            (AnyEntity, Record { .. }) | (Record { .. }, AnyEntity) => None,
            (Record { .. }, Entity(_)) | (Entity(_), Record { .. }) => None,

            //Likewise, we can't mix action entities and records
            (ActionEntity { .. }, Record { .. }) | (Record { .. }, ActionEntity { .. }) => None,
            //Action entities can be mixed with Entities. In this case, the LUB is AnyEntity
            (ActionEntity { .. }, Entity(_)) | (Entity(_), ActionEntity { .. }) => Some(AnyEntity),
        }
    }

    /// Record/entity subtype is based on the lattice named entity <: arbitrary
    /// entity. We do not support subtyping between records and entities.
    pub(crate) fn is_subtype(
        schema: &ValidatorSchema,
        rk0: &EntityRecordKind,
        rk1: &EntityRecordKind,
    ) -> bool {
        use EntityRecordKind::*;
        match (rk0, rk1) {
            (
                Record {
                    attrs: attrs0,
                    open_attributes: open0,
                },
                Record {
                    attrs: attrs1,
                    open_attributes: open1,
                },
            ) => {
                // Closed attributes subtype open attributes. A record type with
                // open attributes may contain a value that is not in a record
                // type with closed attributes, so open attribute record types
                // can never subtype closed attribute record types.
                (!open0.is_open() || open1.is_open())
                // When `rk1` has open attributes, width subtyping applies since
                // there may be attributes in `rk0` that are not listed in
                // `rk1`.  When `rk1` is closed, a subtype of `rk1` may not have
                // any attributes that are not listed in `rk1`, so we apply
                // depth subtyping only.
                    && ((open1.is_open() && attrs0.is_subtype(schema, attrs1))
                        || attrs0.is_subtype_depth_only(schema, attrs1))
            }
            (ActionEntity { .. }, ActionEntity { .. }) => false,
            (Entity(lub0), Entity(lub1)) => lub0.is_subtype(lub1),
            (Entity(_) | ActionEntity { .. } | AnyEntity, AnyEntity) => true,

            // Entities cannot subtype records because their LUB is undefined to
            // avoid a non-terminating case.
            (Entity(_) | AnyEntity | ActionEntity { .. }, Record { .. }) => false,

            (Record { .. }, Entity(_) | AnyEntity | ActionEntity { .. }) => false,
            (ActionEntity { .. }, Entity(_)) => false,
            (AnyEntity, Entity(_)) => false,
            (Entity(_) | AnyEntity, ActionEntity { .. }) => false,
        }
    }
}

/// Contains the type of a record attribute and if the attribute is required.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Serialize)]
pub struct AttributeType {
    /// The type of the attribute.
    #[serde(rename = "attrType")]
    pub attr_type: Type,

    /// True when the attribute must be present. False if it is optional, and so
    /// may not be present in a record or entity.
    #[serde(rename = "isRequired")]
    pub is_required: bool,
}

impl AttributeType {
    /// Construct an AttributeType with some type that may be required or
    /// optional as specified by the `is_required` parameter.
    pub fn new(attr_type: Type, is_required: bool) -> Self {
        Self {
            attr_type,
            is_required,
        }
    }

    /// Construct an AttributeType for an attribute that must be present given
    /// the type of the attribute.
    pub fn required_attribute(attr_type: Type) -> Self {
        Self::new(attr_type, true)
    }
}

/// Represent the possible primitive types.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Serialize)]
pub enum Primitive {
    /// Primitive boolean type.
    Bool,
    /// Primitive long type.
    Long,
    /// Primitive string type.
    String,
}

/// A set of effects. Used to represent knowledge about attribute existence
/// before and after evaluating an expression.
#[derive(Eq, PartialEq, Debug, Clone, Default)]
pub struct EffectSet<'a>(HashSet<Effect<'a>>);

impl<'a> EffectSet<'a> {
    pub fn new() -> Self {
        EffectSet(HashSet::new())
    }

    pub fn singleton(e: Effect<'a>) -> Self {
        let mut set = Self::new();
        set.0.insert(e);
        set
    }

    pub fn union(&self, other: &Self) -> Self {
        EffectSet(self.0.union(&other.0).cloned().collect())
    }

    pub fn intersect(&self, other: &Self) -> Self {
        EffectSet(self.0.intersection(&other.0).cloned().collect())
    }

    pub fn contains(&self, e: &Effect) -> bool {
        self.0.contains(e)
    }
}

/// Represent a single effect, which is an expression and some attribute that is
/// known to exist for that expression.
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct Effect<'a> {
    on_expr: ExprShapeOnly<'a>,
    attribute: &'a str,
}

impl<'a> Effect<'a> {
    pub fn new(on_expr: &'a Expr, attribute: &'a str) -> Self {
        Self {
            on_expr: ExprShapeOnly::new(on_expr),
            attribute,
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::{ActionBehavior, SchemaType, ValidatorNamespaceDef};

    use super::*;

    impl Type {
        pub(crate) fn entity_lub<'a>(es: impl IntoIterator<Item = &'a str>) -> Type {
            let lub = EntityLUB {
                lub_elements: es.into_iter().map(|e| e.parse().unwrap()).collect(),
            };
            assert!(!lub.lub_elements.is_empty());
            Type::EntityOrRecord(EntityRecordKind::Entity(lub))
        }

        pub(crate) fn open_record_with_required_attributes(
            required_attrs: impl IntoIterator<Item = (SmolStr, Type)>,
        ) -> Type {
            Type::EntityOrRecord(EntityRecordKind::Record {
                attrs: Attributes::with_required_attributes(required_attrs),
                open_attributes: OpenTag::OpenAttributes,
            })
        }

        pub(crate) fn closed_record_with_required_attributes(
            required_attrs: impl IntoIterator<Item = (SmolStr, Type)>,
        ) -> Type {
            Type::record_with_required_attributes(required_attrs, OpenTag::ClosedAttributes)
        }

        pub(crate) fn open_record_with_attributes(
            attrs: impl IntoIterator<Item = (SmolStr, AttributeType)>,
        ) -> Type {
            Self::record_with_attributes(attrs, OpenTag::OpenAttributes)
        }

        pub(crate) fn closed_record_with_attributes(
            attrs: impl IntoIterator<Item = (SmolStr, AttributeType)>,
        ) -> Type {
            Self::record_with_attributes(attrs, OpenTag::ClosedAttributes)
        }
    }

    fn assert_least_upper_bound(schema: ValidatorSchema, lhs: Type, rhs: Type, lub: Option<Type>) {
        assert_eq!(
            Type::least_upper_bound(&schema, &lhs, &rhs),
            lub,
            "assert_least_upper_bound({:?}, {:?}, {:?})",
            lhs,
            rhs,
            lub
        );
    }

    fn assert_entity_lub(
        schema: ValidatorSchema,
        lhs: Type,
        rhs: Type,
        lub_names: &[&str],
        lub_attrs: &[(&str, Type)],
    ) {
        let lub = Type::least_upper_bound(&schema, &lhs, &rhs);
        match lub {
            Some(Type::EntityOrRecord(EntityRecordKind::Entity(entity_lub))) => {
                assert_eq!(
                    lub_names
                        .iter()
                        .map(|s| s.parse().expect("Expected valid entity type name."))
                        .collect::<BTreeSet<_>>(),
                    entity_lub.lub_elements,
                    "Incorrect entity types composing LUB."
                );
                assert_eq!(
                    Attributes::with_attributes(
                        lub_attrs
                            .iter()
                            .map(|(s, t)| (
                                AsRef::<str>::as_ref(s).into(),
                                AttributeType::required_attribute(t.clone())
                            ))
                            .collect::<BTreeMap<_, _>>()
                    ),
                    entity_lub.get_attribute_types(&schema),
                    "Incorrect computed record type for LUB."
                );
            }
            _ => panic!("Expected entity least upper bound."),
        }
    }

    fn empty_schema() -> ValidatorSchema {
        ValidatorSchema::empty()
    }

    fn assert_least_upper_bound_empty_schema(lhs: Type, rhs: Type, lub: Option<Type>) {
        assert_least_upper_bound(empty_schema(), lhs, rhs, lub);
    }

    #[test]
    fn test_primitive_lub() {
        assert_least_upper_bound_empty_schema(
            Type::False,
            Type::True,
            Some(Type::primitive_boolean()),
        );
        assert_least_upper_bound_empty_schema(Type::False, Type::False, Some(Type::False));
        assert_least_upper_bound_empty_schema(
            Type::False,
            Type::primitive_boolean(),
            Some(Type::primitive_boolean()),
        );

        assert_least_upper_bound_empty_schema(Type::True, Type::True, Some(Type::True));
        assert_least_upper_bound_empty_schema(
            Type::True,
            Type::False,
            Some(Type::primitive_boolean()),
        );
        assert_least_upper_bound_empty_schema(
            Type::True,
            Type::primitive_boolean(),
            Some(Type::primitive_boolean()),
        );

        assert_least_upper_bound_empty_schema(
            Type::primitive_boolean(),
            Type::False,
            Some(Type::primitive_boolean()),
        );
        assert_least_upper_bound_empty_schema(
            Type::primitive_boolean(),
            Type::True,
            Some(Type::primitive_boolean()),
        );
        assert_least_upper_bound_empty_schema(
            Type::primitive_boolean(),
            Type::primitive_boolean(),
            Some(Type::primitive_boolean()),
        );
        assert_least_upper_bound_empty_schema(
            Type::primitive_string(),
            Type::primitive_string(),
            Some(Type::primitive_string()),
        );

        assert_least_upper_bound_empty_schema(
            Type::primitive_long(),
            Type::primitive_long(),
            Some(Type::primitive_long()),
        );

        assert_least_upper_bound_empty_schema(Type::False, Type::primitive_string(), None);
        assert_least_upper_bound_empty_schema(Type::False, Type::primitive_long(), None);
        assert_least_upper_bound_empty_schema(Type::True, Type::primitive_string(), None);
        assert_least_upper_bound_empty_schema(Type::True, Type::primitive_long(), None);
        assert_least_upper_bound_empty_schema(
            Type::primitive_boolean(),
            Type::primitive_string(),
            None,
        );
        assert_least_upper_bound_empty_schema(
            Type::primitive_boolean(),
            Type::primitive_long(),
            None,
        );
        assert_least_upper_bound_empty_schema(
            Type::primitive_string(),
            Type::primitive_long(),
            None,
        );
    }

    #[test]
    fn test_extension_lub() {
        let ipaddr: Name = "ipaddr".parse().expect("should be a valid identifier");
        assert_least_upper_bound_empty_schema(
            Type::extension(ipaddr.clone()),
            Type::extension(ipaddr.clone()),
            Some(Type::extension(ipaddr.clone())),
        );
        assert_least_upper_bound_empty_schema(
            Type::extension(ipaddr.clone()),
            Type::extension("test".parse().expect("should be a valid identifier")),
            None,
        );
        assert_least_upper_bound_empty_schema(Type::extension(ipaddr.clone()), Type::False, None);
        assert_least_upper_bound_empty_schema(
            Type::extension(ipaddr.clone()),
            Type::primitive_string(),
            None,
        );
        assert_least_upper_bound_empty_schema(
            Type::extension(ipaddr),
            Type::any_entity_reference(),
            None,
        );
    }

    #[test]
    fn test_set_lub() {
        assert_least_upper_bound_empty_schema(
            Type::set(Type::True),
            Type::set(Type::True),
            Some(Type::set(Type::True)),
        );
        assert_least_upper_bound_empty_schema(
            Type::set(Type::False),
            Type::set(Type::True),
            Some(Type::set(Type::primitive_boolean())),
        );

        assert_least_upper_bound_empty_schema(
            Type::set(Type::primitive_boolean()),
            Type::set(Type::primitive_long()),
            None,
        );
        assert_least_upper_bound_empty_schema(
            Type::set(Type::primitive_boolean()),
            Type::primitive_boolean(),
            None,
        );
    }

    #[test]
    fn test_record_undef_lub() {
        assert_least_upper_bound_empty_schema(
            Type::open_record_with_attributes(None),
            Type::primitive_string(),
            None,
        );

        assert_least_upper_bound_empty_schema(
            Type::closed_record_with_attributes(None),
            Type::primitive_string(),
            None,
        );

        assert_least_upper_bound_empty_schema(
            Type::closed_record_with_attributes(None),
            Type::set(Type::primitive_boolean()),
            None,
        );
    }

    #[test]
    fn test_record_lub() {
        assert_least_upper_bound_empty_schema(
            Type::closed_record_with_attributes(None),
            Type::closed_record_with_attributes(None),
            Some(Type::closed_record_with_attributes(None)),
        );
        assert_least_upper_bound_empty_schema(
            Type::closed_record_with_attributes(None),
            Type::open_record_with_attributes(None),
            Some(Type::open_record_with_attributes(None)),
        );
        assert_least_upper_bound_empty_schema(
            Type::open_record_with_attributes(None),
            Type::closed_record_with_attributes(None),
            Some(Type::open_record_with_attributes(None)),
        );
        assert_least_upper_bound_empty_schema(
            Type::open_record_with_attributes(None),
            Type::open_record_with_attributes(None),
            Some(Type::open_record_with_attributes(None)),
        );

        assert_least_upper_bound_empty_schema(
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::False),
                ("bar".into(), Type::primitive_long()),
            ]),
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::primitive_string()),
                ("bar".into(), Type::primitive_long()),
            ]),
            Some(Type::open_record_with_required_attributes([(
                "bar".into(),
                Type::primitive_long(),
            )])),
        );

        assert_least_upper_bound_empty_schema(
            Type::closed_record_with_required_attributes([("bar".into(), Type::primitive_long())]),
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::primitive_string()),
                ("bar".into(), Type::primitive_long()),
            ]),
            Some(Type::open_record_with_required_attributes([(
                "bar".into(),
                Type::primitive_long(),
            )])),
        );

        assert_least_upper_bound_empty_schema(
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::False),
                ("bar".into(), Type::primitive_long()),
            ]),
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::True),
                ("baz".into(), Type::primitive_long()),
            ]),
            Some(Type::open_record_with_required_attributes([(
                "foo".into(),
                Type::primitive_boolean(),
            )])),
        );

        assert_least_upper_bound_empty_schema(
            Type::closed_record_with_required_attributes([("foo".into(), Type::False)]),
            Type::closed_record_with_required_attributes([("foo".into(), Type::True)]),
            Some(Type::closed_record_with_required_attributes([(
                "foo".into(),
                Type::primitive_boolean(),
            )])),
        );

        assert_least_upper_bound_empty_schema(
            Type::closed_record_with_attributes([
                (
                    "foo".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
                (
                    "bar".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
            ]),
            Type::closed_record_with_attributes([
                (
                    "foo".into(),
                    AttributeType::new(Type::primitive_long(), true),
                ),
                (
                    "bar".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
            ]),
            Some(Type::closed_record_with_attributes([
                (
                    "foo".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
                (
                    "bar".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
            ])),
        );

        assert_least_upper_bound_empty_schema(
            Type::closed_record_with_required_attributes([("a".into(), Type::primitive_long())]),
            Type::closed_record_with_attributes([]),
            Some(Type::open_record_with_attributes([])),
        );
    }

    fn simple_schema() -> ValidatorSchema {
        ValidatorSchema::from_schema_file(
            serde_json::from_value(serde_json::json!({ "":
            {
                "entityTypes": {
                    "foo": {},
                    "bar": {}
                },
                "actions": {}
            }}))
            .expect("Expected valid schema"),
            ActionBehavior::PermitAttributes,
        )
        .expect("Expected valid schema")
    }

    fn assert_least_upper_bound_simple_schema(lhs: Type, rhs: Type, lub: Option<Type>) {
        assert_least_upper_bound(simple_schema(), lhs, rhs, lub);
    }

    fn assert_entity_lub_attrs_simple_schema(
        lhs: Type,
        rhs: Type,
        lub_names: &[&str],
        lub_attrs: &[(&str, Type)],
    ) {
        assert_entity_lub(simple_schema(), lhs, rhs, lub_names, lub_attrs);
    }

    #[test]
    fn test_entity_lub() {
        assert_least_upper_bound_simple_schema(
            Type::any_entity_reference(),
            Type::any_entity_reference(),
            Some(Type::any_entity_reference()),
        );
        assert_entity_lub_attrs_simple_schema(
            Type::named_entity_reference_from_str("foo"),
            Type::named_entity_reference_from_str("bar"),
            &["foo", "bar"],
            &[],
        );
        assert_entity_lub_attrs_simple_schema(
            Type::named_entity_reference_from_str("foo"),
            Type::named_entity_reference_from_str("foo"),
            &["foo"],
            &[],
        );
        assert_least_upper_bound_simple_schema(
            Type::any_entity_reference(),
            Type::named_entity_reference_from_str("foo"),
            Some(Type::any_entity_reference()),
        );
        assert_least_upper_bound_simple_schema(
            Type::named_entity_reference_from_str("foo"),
            Type::primitive_boolean(),
            None,
        );
        assert_least_upper_bound_simple_schema(
            Type::named_entity_reference_from_str("foo"),
            Type::set(Type::any_entity_reference()),
            None,
        );
    }

    /// Test cases with entity type Action are interesting because Action
    /// does not need to be declared in the entity type list.
    #[test]
    fn test_action_entity_lub() {
        assert_entity_lub_attrs_simple_schema(
            Type::named_entity_reference_from_str("Action"),
            Type::named_entity_reference_from_str("Action"),
            &["Action"],
            &[],
        );
        assert_entity_lub_attrs_simple_schema(
            Type::named_entity_reference_from_str("Action"),
            Type::named_entity_reference_from_str("foo"),
            &["Action", "foo"],
            &[],
        );
        assert_least_upper_bound_simple_schema(
            Type::named_entity_reference_from_str("Action"),
            Type::any_entity_reference(),
            Some(Type::any_entity_reference()),
        );
    }

    fn attr_schema() -> ValidatorSchema {
        ValidatorSchema::from_schema_file(
            serde_json::from_value(serde_json::json!(
            {"": {
                "entityTypes": {
                    "foo": {},
                    "bar": {},
                    "baz": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": {"type": "Long"},
                                "b": {"type": "String"},
                                "c": {"type": "Entity", "name": "foo"}
                            }
                        }
                    },
                    "buz": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": {"type": "Long"},
                                "b": {"type": "Long"},
                                "c": {"type": "Entity", "name": "bar"}
                            }
                        }
                    }
                },
                "actions": {}
            }}))
            .expect("Expected valid schema"),
            ActionBehavior::PermitAttributes,
        )
        .expect("Expected valid schema")
    }

    fn assert_least_upper_bound_attr_schema(lhs: Type, rhs: Type, lub: Option<Type>) {
        assert_least_upper_bound(attr_schema(), lhs, rhs, lub);
    }

    fn assert_entity_lub_attrs_attr_schema(
        lhs: Type,
        rhs: Type,
        lub_names: &[&str],
        lub_attrs: &[(&str, Type)],
    ) {
        assert_entity_lub(attr_schema(), lhs, rhs, lub_names, lub_attrs);
    }

    #[test]
    fn test_entity_lub_with_attributes() {
        assert_entity_lub_attrs_attr_schema(
            Type::named_entity_reference_from_str("baz"),
            Type::named_entity_reference_from_str("baz"),
            &["baz"],
            &[
                ("a", Type::primitive_long()),
                ("b", Type::primitive_string()),
                ("c", Type::named_entity_reference_from_str("foo")),
            ],
        );
        assert_entity_lub_attrs_attr_schema(
            Type::named_entity_reference_from_str("baz"),
            Type::named_entity_reference_from_str("foo"),
            &["baz", "foo"],
            &[],
        );
        assert_entity_lub_attrs_attr_schema(
            Type::named_entity_reference_from_str("baz"),
            Type::named_entity_reference_from_str("buz"),
            &["baz", "buz"],
            &[
                ("a", Type::primitive_long()),
                (
                    "c",
                    Type::EntityOrRecord(EntityRecordKind::Entity(EntityLUB {
                        lub_elements: ["foo".to_string(), "bar".to_string()]
                            .into_iter()
                            .map(|n| n.parse().expect("Expected valid entity type name."))
                            .collect::<BTreeSet<_>>(),
                    })),
                ),
            ],
        );
    }

    #[test]
    fn test_record_entity_lub() {
        assert_least_upper_bound_empty_schema(
            Type::any_entity_reference(),
            Type::any_record(),
            None,
        );
        assert_least_upper_bound_empty_schema(
            Type::closed_record_with_attributes(None),
            Type::any_entity_reference(),
            None,
        );
        assert_least_upper_bound_empty_schema(
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::False),
                ("bar".into(), Type::primitive_long()),
            ]),
            Type::any_entity_reference(),
            None,
        );
        assert_least_upper_bound_attr_schema(
            Type::named_entity_reference_from_str("foo"),
            Type::any_record(),
            None,
        );
        assert_least_upper_bound_attr_schema(
            Type::named_entity_reference_from_str("baz"),
            Type::any_record(),
            None,
        );
        assert_least_upper_bound_attr_schema(
            Type::named_entity_reference_from_str("buz"),
            Type::closed_record_with_required_attributes(vec![
                ("a".into(), Type::primitive_long()),
                ("b".into(), Type::primitive_long()),
                ("c".into(), Type::named_entity_reference_from_str("bar")),
            ]),
            None,
        );
    }

    // Direct test of LUB computation which causes a non-termination bug.
    #[test]
    fn record_entity_lub_non_term() {
        let schema = ValidatorSchema::from_schema_file(
            serde_json::from_value(serde_json::json!(
            {"": {
                "entityTypes": {
                    "U": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "foo": {
                                    "type": "Record",
                                    "attributes": {
                                        "foo": {
                                            "type": "Entity",
                                            "name": "U"
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "actions": {}
            }}))
            .expect("Expected valid schema"),
            ActionBehavior::PermitAttributes,
        )
        .expect("Expected valid schema");

        assert_least_upper_bound(
            schema,
            Type::named_entity_reference_from_str("U"),
            Type::closed_record_with_required_attributes([(
                "foo".into(),
                Type::named_entity_reference_from_str("U"),
            )]),
            None,
        );
    }

    fn rec_schema() -> ValidatorSchema {
        ValidatorSchema::from_schema_file(
            serde_json::from_value(serde_json::json!(
                {"": {
                    "entityTypes": {
                        "biz": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "c": {"type": "Entity", "name": "biz"}
                                }
                            }
                        },
                        "fiz": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "c": {"type": "Entity", "name": "fiz"}
                                }
                            }
                        }
                    },
                    "actions": {}
                }}
            ))
            .expect("Expected valid schema"),
            ActionBehavior::PermitAttributes,
        )
        .expect("Expected valid schema")
    }

    fn assert_entity_lub_attrs_rec_schema(
        lhs: Type,
        rhs: Type,
        lub_names: &[&str],
        lub_attrs: &[(&str, Type)],
    ) {
        assert_entity_lub(rec_schema(), lhs, rhs, lub_names, lub_attrs);
    }

    #[test]
    fn test_with_recursive_types() {
        assert_entity_lub_attrs_rec_schema(
            Type::named_entity_reference_from_str("biz"),
            Type::named_entity_reference_from_str("biz"),
            &["biz"],
            &[("c", Type::named_entity_reference_from_str("biz"))],
        );
        assert_entity_lub_attrs_rec_schema(
            Type::named_entity_reference_from_str("biz"),
            Type::named_entity_reference_from_str("fiz"),
            &["biz", "fiz"],
            &[(
                "c",
                Type::EntityOrRecord(EntityRecordKind::Entity(EntityLUB {
                    lub_elements: ["biz".to_string(), "fiz".to_string()]
                        .into_iter()
                        .map(|n| n.parse().expect("Expected valid entity type name."))
                        .collect::<BTreeSet<_>>(),
                })),
            )],
        );
    }

    fn assert_json_parses_to_schema_type(ty: Type) {
        let json_str = serde_json::value::Value::Object(ty.to_type_json()).to_string();
        println!("{}", json_str);
        let parsed_schema_type: SchemaType = serde_json::from_str(&json_str)
            .expect("JSON representation should have parsed into a schema type");
        let type_from_schema_type =
            ValidatorNamespaceDef::try_schema_type_into_validator_type(None, parsed_schema_type)
                .expect("Schema type should have converted to type.")
                .resolve_type_defs(&HashMap::new())
                .unwrap();
        assert_eq!(ty, type_from_schema_type);
    }

    #[test]
    fn json_display_of_schema_type_parses_to_schema_type() {
        assert_json_parses_to_schema_type(Type::primitive_boolean());
        assert_json_parses_to_schema_type(Type::primitive_long());
        assert_json_parses_to_schema_type(Type::primitive_string());
        assert_json_parses_to_schema_type(Type::set(Type::primitive_boolean()));
        assert_json_parses_to_schema_type(Type::set(Type::primitive_string()));
        assert_json_parses_to_schema_type(Type::set(Type::primitive_long()));
        assert_json_parses_to_schema_type(Type::named_entity_reference_from_str("Foo"));
        assert_json_parses_to_schema_type(Type::named_entity_reference_from_str("Foo::Bar"));
        assert_json_parses_to_schema_type(Type::named_entity_reference_from_str("Foo::Bar::Baz"));
        assert_json_parses_to_schema_type(Type::closed_record_with_attributes(None));
        assert_json_parses_to_schema_type(Type::closed_record_with_attributes([(
            "a".into(),
            AttributeType::required_attribute(Type::primitive_boolean()),
        )]));
        assert_json_parses_to_schema_type(Type::closed_record_with_attributes([
            (
                "a".into(),
                AttributeType::required_attribute(Type::primitive_boolean()),
            ),
            (
                "b".into(),
                AttributeType::new(Type::primitive_long(), false),
            ),
        ]));
    }

    fn assert_displays_as(ty: Type, repr: &str) {
        assert_eq!(
            ty.to_string(),
            repr,
            "Unexpected Display output for type {:?}",
            ty
        );
    }

    #[test]
    fn test_non_schema_type_display() {
        assert_displays_as(Type::Never, r#"{"type":"Never"}"#);
        assert_displays_as(Type::True, r#"{"type":"True"}"#);
        assert_displays_as(Type::False, r#"{"type":"False"}"#);
        assert_displays_as(Type::any_set(), r#"{"type":"Set"}"#);
        assert_displays_as(Type::any_entity_reference(), r#"{"type":"Entity"}"#);
        assert_displays_as(
            Type::least_upper_bound(
                &ValidatorSchema::empty(),
                &Type::named_entity_reference_from_str("Foo"),
                &Type::named_entity_reference_from_str("Bar"),
            )
            .expect("Expected a least upper bound to exist."),
            r#"{"type":"Union","elements":[{"type":"Entity","name":"Bar"},{"type":"Entity","name":"Foo"}]}"#,
        );
    }

    #[test]
    #[cfg(feature = "ipaddr")]
    fn text_extension_type_dislay() {
        let ipaddr = Name::parse_unqualified_name("ipaddr").expect("should be a valid identifier");
        assert_json_parses_to_schema_type(Type::extension(ipaddr));
    }
}
