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

//! Defines functions for converting from the 2.5.x schema structures into the
//! current version schema structures.

use std::collections::HashMap;

use crate::validator::json_schema::{
    self, ActionEntityUID, ActionType, ApplySpec, AttributesOrContext, CommonType, EntityType,
    EntityTypeKind, Fragment, NamespaceDefinition, RecordType, StandardEntityType, Type,
    TypeOfAttribute, TypeVariant,
};
use crate::validator::{schema_errors::JsonDeserializationError, RawName, SchemaError};
use crate::validator::{ActionBehavior, ValidatorSchema};

use super::json_schema as compat;
use crate::extensions::Extensions;
use crate::{
    ast::{Name, UnreservedId},
    est::Annotations,
    FromNormalizedStr,
};
use itertools::Itertools;

impl ValidatorSchema {
    /// Construct a [`ValidatorSchema`] from a JSON value in the appropriate
    /// shape.
    pub fn from_deprecated_json_value(
        json: serde_json::Value,
        extensions: &Extensions<'_>,
    ) -> Result<Self, SchemaError> {
        Self::from_schema_frag(
            json_schema::Fragment::<RawName>::from_deprecated_json_value(json)?,
            ActionBehavior::default(),
            extensions,
        )
    }

    /// Construct a [`ValidatorSchema`] from a string containing JSON in the
    /// appropriate shape.
    pub fn from_deprecated_json_str(
        json: &str,
        extensions: &Extensions<'_>,
    ) -> Result<Self, SchemaError> {
        Self::from_schema_frag(
            json_schema::Fragment::<RawName>::from_deprecated_json_str(json)?,
            ActionBehavior::default(),
            extensions,
        )
    }

    /// Construct a [`ValidatorSchema`] directly from a file containing JSON
    /// in the appropriate shape.
    pub fn from_deprecated_json_file(
        file: impl std::io::Read,
        extensions: &Extensions<'_>,
    ) -> Result<Self, SchemaError> {
        Self::from_schema_frag(
            json_schema::Fragment::<RawName>::from_deprecated_json_file(file)?,
            ActionBehavior::default(),
            extensions,
        )
    }
}

impl Fragment<RawName> {
    /// Create a [`Fragment`] from a JSON value (which should be an object
    /// of the appropriate shape).
    pub fn from_deprecated_json_value(json: serde_json::Value) -> Result<Self, SchemaError> {
        let compat: compat::SchemaFragment = serde_json::from_value(json).map_err(|e| {
            SchemaError::JsonDeserialization(JsonDeserializationError::new(e, None))
        })?;
        compat
            .try_into()
            .map_err(|e| SchemaError::JsonDeserialization(JsonDeserializationError::new(e, None)))
    }

    /// Create a [`Fragment`] from a string containing JSON (which should
    /// be an object of the appropriate shape).
    pub fn from_deprecated_json_str(json: &str) -> Result<Self, SchemaError> {
        let compat: compat::SchemaFragment = serde_json::from_str(json).map_err(|e| {
            SchemaError::JsonDeserialization(JsonDeserializationError::new(e, Some(json)))
        })?;
        compat
            .try_into()
            .map_err(|e| SchemaError::JsonDeserialization(JsonDeserializationError::new(e, None)))
    }

    /// Create a [`Fragment`] directly from a file containing a JSON object.
    pub fn from_deprecated_json_file(file: impl std::io::Read) -> Result<Self, SchemaError> {
        let compat: compat::SchemaFragment = serde_json::from_reader(file).map_err(|e| {
            SchemaError::JsonDeserialization(JsonDeserializationError::new(e, None))
        })?;
        compat
            .try_into()
            .map_err(|e| SchemaError::JsonDeserialization(JsonDeserializationError::new(e, None)))
    }
}

impl TryFrom<compat::SchemaFragment> for Fragment<RawName> {
    type Error = serde_json::Error;

    fn try_from(value: compat::SchemaFragment) -> Result<Self, Self::Error> {
        Ok(Self(
            value
                .0
                .into_iter()
                .map(|(name, nsdef)| -> Result<_, Self::Error> {
                    let name: Option<Name> = if name.is_empty() {
                        None
                    } else {
                        Some(Name::from_normalized_str(&name).map_err(|err| {
                            serde::de::Error::custom(format!("invalid namespace `{name}`: {err}"))
                        })?)
                    };
                    Ok((name, nsdef.try_into()?))
                })
                .try_collect()?,
        ))
    }
}

impl TryFrom<compat::NamespaceDefinition> for NamespaceDefinition<RawName> {
    type Error = serde_json::Error;

    fn try_from(value: compat::NamespaceDefinition) -> Result<Self, Self::Error> {
        Ok(Self {
            common_types: value
                .common_types
                .into_iter()
                .map(|(id, ty)| -> Result<_, Self::Error> { Ok((id, ty.try_into()?)) })
                .try_collect()?,
            entity_types: value
                .entity_types
                .into_iter()
                .map(|(id, ety)| -> Result<_, Self::Error> { Ok((id, ety.try_into()?)) })
                .try_collect()?,
            actions: value
                .actions
                .into_iter()
                .map(|(id, aty)| aty.try_into().map(|aty| (id, aty)))
                .try_collect()?,
            annotations: Annotations::new(),
            #[cfg(feature = "extended-schema")]
            loc: None,
        })
    }
}

impl TryFrom<compat::SchemaType> for CommonType<RawName> {
    type Error = serde_json::Error;

    fn try_from(value: compat::SchemaType) -> Result<Self, Self::Error> {
        Ok(Self {
            ty: value.try_into()?,
            annotations: Annotations::new(),
            loc: None,
        })
    }
}

impl TryFrom<compat::SchemaType> for Type<RawName> {
    type Error = serde_json::Error;

    fn try_from(value: compat::SchemaType) -> Result<Self, Self::Error> {
        Ok(match value {
            compat::SchemaType::Type(schema_type_variant) => Self::Type {
                ty: schema_type_variant.try_into()?,
                loc: None,
            },
            compat::SchemaType::TypeDef { type_name } => Self::CommonTypeRef {
                type_name: RawName::from_normalized_str(&type_name).map_err(|err| {
                    serde::de::Error::custom(format!("invalid common type `{type_name}`: {err}"))
                })?,
                loc: None,
            },
        })
    }
}

impl TryFrom<compat::SchemaTypeVariant> for TypeVariant<RawName> {
    type Error = serde_json::Error;

    fn try_from(value: compat::SchemaTypeVariant) -> Result<Self, Self::Error> {
        Ok(match value {
            compat::SchemaTypeVariant::String => Self::String,
            compat::SchemaTypeVariant::Long => Self::Long,
            compat::SchemaTypeVariant::Boolean => Self::Boolean,
            compat::SchemaTypeVariant::Set { element } => Self::Set {
                element: Box::new((*element).try_into()?),
            },
            compat::SchemaTypeVariant::Record {
                attributes,
                additional_attributes,
            } => Self::Record(RecordType {
                attributes: attributes
                    .into_iter()
                    .map(|(id, ty)| ty.try_into().map(|ty| (id, ty)))
                    .try_collect()?,
                additional_attributes,
            }),
            compat::SchemaTypeVariant::Entity { name } => Self::Entity {
                name: RawName::from_normalized_str(&name).map_err(|err| {
                    serde::de::Error::custom(format!("invalid entity type `{name}`: {err}"))
                })?,
            },
            compat::SchemaTypeVariant::Extension { name } => Self::Extension {
                name: UnreservedId::from_normalized_str(&name).map_err(|err| {
                    serde::de::Error::custom(format!("invalid extension type `{name}`: {err}"))
                })?,
            },
        })
    }
}

impl TryFrom<compat::EntityType> for EntityType<RawName> {
    type Error = serde_json::Error;

    fn try_from(value: compat::EntityType) -> Result<Self, Self::Error> {
        Ok(Self {
            kind: EntityTypeKind::Standard(StandardEntityType {
                member_of_types: value.member_of_types,
                shape: value.shape.try_into()?,
                tags: None,
            }),
            annotations: Annotations::new(),
            loc: None,
        })
    }
}

impl TryFrom<compat::ActionType> for ActionType<RawName> {
    type Error = serde_json::Error;

    fn try_from(value: compat::ActionType) -> Result<Self, Self::Error> {
        Ok(Self {
            // We don't support action attributes, so we don't need to actually
            // implement conversion. If `attributes` is not `None`, then we'll
            // include a dummy attributes map so that later conversion will
            // correctly report an error.
            attributes: value.attributes.map(|_attrs| HashMap::from([])),
            applies_to: value
                .applies_to
                .map(|applies_to| applies_to.try_into())
                .transpose()?,
            member_of: value
                .member_of
                .map(|member_of| {
                    member_of
                        .into_iter()
                        .map(|aid| aid.try_into())
                        .try_collect()
                })
                .transpose()?,
            annotations: Annotations::new(),
            loc: None,
            #[cfg(feature = "extended-schema")]
            defn_loc: None,
        })
    }
}

impl TryFrom<compat::AttributesOrContext> for AttributesOrContext<RawName> {
    type Error = serde_json::Error;

    fn try_from(value: compat::AttributesOrContext) -> Result<Self, Self::Error> {
        Ok(Self(value.0.try_into()?))
    }
}

impl TryFrom<compat::ApplySpec> for ApplySpec<RawName> {
    type Error = serde_json::Error;

    fn try_from(value: compat::ApplySpec) -> Result<Self, Self::Error> {
        // Current schema format requires that are explicitly defined when
        // providing an `appliesTo`. We could considering converting these to
        // empty lists to provide an even more permissive compatibility layer.
        let Some(resource_types) = value.resource_types else {
            return Err(serde::de::Error::missing_field("resourceTypes"));
        };
        let Some(principal_types) = value.principal_types else {
            return Err(serde::de::Error::missing_field("principalTypes"));
        };

        Ok(Self {
            resource_types,
            principal_types,
            context: value.context.try_into()?,
        })
    }
}

impl TryFrom<compat::ActionEntityUID> for ActionEntityUID<RawName> {
    type Error = serde_json::Error;

    fn try_from(value: compat::ActionEntityUID) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            ty: value.ty,
            #[cfg(feature = "extended-schema")]
            loc: None,
        })
    }
}

impl TryFrom<compat::TypeOfAttribute> for TypeOfAttribute<RawName> {
    type Error = serde_json::Error;

    fn try_from(value: compat::TypeOfAttribute) -> Result<Self, Self::Error> {
        Ok(Self {
            ty: value.ty.try_into()?,
            annotations: Annotations::new(),
            required: value.required,
            #[cfg(feature = "extended-schema")]
            loc: None,
        })
    }
}
