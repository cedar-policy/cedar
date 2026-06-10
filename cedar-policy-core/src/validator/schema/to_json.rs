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

use crate::{
    ast::{EntityType, EntityUID, InternalName, Name},
    est::Annotations,
    validator::{
        json_schema,
        types::{BoolType, EntityKind, OpenTag, Type},
        RawName, ValidatorActionId, ValidatorEntityType, ValidatorEntityTypeKind, ValidatorSchema,
    },
};
use itertools::Itertools;
use smol_str::ToSmolStr;

fn validator_type_to_json_type(ty: &Type) -> Result<json_schema::Type<RawName>, String> {
    let mk_type = |variant| {
        Ok(json_schema::Type::Type {
            ty: variant,
            loc: None,
        })
    };
    match ty {
        Type::Bool(BoolType::AnyBool) => mk_type(json_schema::TypeVariant::Boolean),
        Type::Long => mk_type(json_schema::TypeVariant::Long),
        Type::String => mk_type(json_schema::TypeVariant::String),
        Type::Set { element_type } => {
            let element = match element_type {
                Some(et) => validator_type_to_json_type(et)?,
                None => return Err("Set with unknown element type not supported".to_string()),
            };
            mk_type(json_schema::TypeVariant::Set {
                element: Box::new(element),
            })
        }
        Type::Record {
            attrs,
            open_attributes,
        } => {
            let attributes = attrs
                .iter()
                .map(|(name, attr_type)| {
                    Ok((
                        name.clone(),
                        json_schema::TypeOfAttribute {
                            ty: validator_type_to_json_type(&attr_type.attr_type)?,
                            required: attr_type.is_required,
                            annotations: Annotations::new(),
                            #[cfg(feature = "extended-schema")]
                            loc: None,
                        },
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, String>>()?;

            mk_type(json_schema::TypeVariant::Record(json_schema::RecordType {
                attributes,
                additional_attributes: *open_attributes == OpenTag::OpenAttributes,
            }))
        }
        Type::Entity(EntityKind::Entity(lub)) => {
            if let Some(entity_type) = lub.get_single_entity() {
                mk_type(json_schema::TypeVariant::EntityOrCommon {
                    type_name: RawName::from_name(entity_type.as_ref().as_ref().clone()),
                })
            } else {
                Err("Entity LUB with multiple types not supported".to_string())
            }
        }
        Type::ExtensionType { name } => Ok(json_schema::Type::Type {
            ty: json_schema::TypeVariant::Extension {
                name: name.basename(),
            },
            loc: None,
        }),
        _ => Err("Unsupported type for conversion".to_string()),
    }
}

impl ValidatorSchema {
    /// Converts a `ValidatorSchema` into a `json_schema::Fragment`.
    /// Roundtripping through this function gives a semantically equivalent
    /// schema but will lose formatting, annotations, and common type
    /// definitions. It will also inline the transitive closure of the entity
    /// hierarchy for each entity type and action.
    pub fn to_json_schema(&self) -> Result<json_schema::Fragment<RawName>, String> {
        let mut namespaces = HashMap::new();

        let mut entity_ancestors = self.entity_ancestors();
        for (entity_type, validator_entity_type) in &self.entity_types {
            if let Some(ancestors) = entity_ancestors.remove(&entity_type) {
                let namespace = entity_type.as_ref().as_ref().path.clone();
                let entity_name = entity_type.as_ref().basename().clone();
                let json_entity_type = validator_entity_type.to_json_entity_type(ancestors)?;
                let (entity_types, _) = namespaces
                    .entry(namespace)
                    .or_insert_with(|| (BTreeMap::new(), BTreeMap::new()));
                entity_types.insert(entity_name, json_entity_type);
            }
        }

        for (action_uid, validator_action_id) in &self.action_ids {
            if let Some(action) = self.actions.get(action_uid) {
                let namespace = action_uid.entity_type().as_ref().as_ref().path.clone();
                let action_name = action_uid.eid().as_ref().to_smolstr();
                let json_action_type = validator_action_id
                    .to_json_action_type(action.ancestors().cloned().collect())?;

                let (_, action_types) = namespaces
                    .entry(namespace)
                    .or_insert_with(|| (BTreeMap::new(), BTreeMap::new()));
                action_types.insert(action_name, json_action_type);
            }
        }

        let mut namespace_definitions = BTreeMap::new();
        for (namespace, (entity_types, action_types)) in namespaces {
            let namespace = {
                let mut namespace = namespace.as_ref().clone();
                if let Some(id) = namespace.pop() {
                    Some(
                        Name::try_from(InternalName::new(id, namespace.into_iter(), None))
                            .map_err(|e| e.to_string())?,
                    )
                } else {
                    None
                }
            };
            let namespace_def = json_schema::NamespaceDefinition {
                common_types: BTreeMap::new(),
                entity_types,
                actions: action_types,
                annotations: Annotations::new(),
                #[cfg(feature = "extended-schema")]
                loc: None,
            };
            namespace_definitions.insert(namespace, namespace_def);
        }

        Ok(json_schema::Fragment(namespace_definitions))
    }

    /// Converts a `ValidatorSchema` into a Cedar schema string.
    /// This first converts to JSON schema format and then to Cedar syntax.
    pub fn to_cedar_schema(&self) -> Result<String, String> {
        let fragment = self.to_json_schema()?;
        fragment.to_cedarschema().map_err(|e| e.to_string())
    }

    fn entity_ancestors(&self) -> HashMap<EntityType, HashSet<EntityType>> {
        self.entity_types
            .keys()
            .map(|ety| {
                let ancestors = self
                    .entity_types
                    .iter()
                    .filter(|(_, parent_vety)| parent_vety.descendants.contains(ety))
                    .map(|(parent_ety, _)| parent_ety.clone())
                    .collect();
                (ety.clone(), ancestors)
            })
            .collect()
    }
}

impl ValidatorActionId {
    fn to_json_action_type(
        &self,
        ancestors: HashSet<EntityUID>,
    ) -> Result<json_schema::ActionType<RawName>, String> {
        // Convert ancestors to member_of (JSON schema format)
        let member_of: Option<Vec<json_schema::ActionEntityUID<RawName>>> = if ancestors.is_empty()
        {
            None
        } else {
            // Sort for deterministic output
            Some(
                ancestors
                    .into_iter()
                    .sorted()
                    .map(|action_uid| json_schema::ActionEntityUID {
                        ty: Some(RawName::from_name(
                            action_uid.entity_type().as_ref().as_ref().clone(),
                        )),
                        id: action_uid.eid().as_ref().to_smolstr(),
                        #[cfg(feature = "extended-schema")]
                        loc: None,
                    })
                    .collect(),
            )
        };

        Ok(json_schema::ActionType {
            attributes: None,
            applies_to: Some(json_schema::ApplySpec {
                resource_types: self
                    .applies_to
                    .applicable_resource_types()
                    .map(|et| RawName::from_name(et.as_ref().as_ref().clone()))
                    .sorted()
                    .collect(),
                principal_types: self
                    .applies_to
                    .applicable_principal_types()
                    .map(|et| RawName::from_name(et.as_ref().as_ref().clone()))
                    .sorted()
                    .collect(),
                context: json_schema::AttributesOrContext(validator_type_to_json_type(
                    &self.context,
                )?),
            }),
            member_of,
            annotations: Annotations::new(),
            loc: self.loc.clone(),
            #[cfg(feature = "extended-schema")]
            defn_loc: None,
        })
    }
}

impl ValidatorEntityType {
    fn to_json_entity_type(
        &self,
        ancestors: HashSet<EntityType>,
    ) -> Result<json_schema::EntityType<RawName>, String> {
        let kind = match &self.kind {
            ValidatorEntityTypeKind::Standard(std_type) => {
                let attributes = self
                    .attributes
                    .iter()
                    .map(|(name, attr_type)| {
                        Ok((
                            name.clone(),
                            json_schema::TypeOfAttribute {
                                ty: validator_type_to_json_type(&attr_type.attr_type)?,
                                required: attr_type.is_required,
                                annotations: Annotations::new(),
                                #[cfg(feature = "extended-schema")]
                                loc: None,
                            },
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>, String>>()?;

                let member_of_types: Vec<RawName> = ancestors
                    .into_iter()
                    .map(|entity_type| RawName::from_name(entity_type.as_ref().as_ref().clone()))
                    .sorted()
                    .collect();

                json_schema::EntityTypeKind::Standard(json_schema::StandardEntityType {
                    member_of_types,
                    shape: json_schema::AttributesOrContext(json_schema::Type::Type {
                        ty: json_schema::TypeVariant::Record(json_schema::RecordType {
                            attributes,
                            additional_attributes: std_type.open_attributes
                                == crate::validator::types::OpenTag::OpenAttributes,
                        }),
                        loc: None,
                    }),
                    tags: std_type
                        .tags
                        .as_ref()
                        .map(validator_type_to_json_type)
                        .transpose()?,
                })
            }
            ValidatorEntityTypeKind::Enum(choices) => json_schema::EntityTypeKind::Enum {
                choices: choices.clone(),
            },
        };

        Ok(json_schema::EntityType {
            kind,
            annotations: Annotations::new(),
            loc: self.loc.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::extensions::Extensions;
    use crate::validator::ValidatorSchema;

    #[test]
    fn test_to_json_schema_basic() {
        let schema = ValidatorSchema::empty();
        let fragment = schema.to_json_schema().unwrap();
        assert_eq!(fragment.0.len(), 0);
    }

    #[test]
    fn test_roundtrip_schemas() {
        insta::glob!(
            "../../../../cedar-policy/src/ffi/test_schemas/",
            "*.cedarschema",
            |path| {
                let cedar_schema = std::fs::read_to_string(path).unwrap();

                // Parse the original Cedar schema and then convert back to a cedar
                // schema, which goes JSON, testing the logic in this file.
                let (original_schema, _) = ValidatorSchema::from_cedarschema_str(
                    &cedar_schema,
                    &Extensions::all_available(),
                )
                .expect("Failed to parse original Cedar schema");
                let roundtrip_result = original_schema
                    .to_cedar_schema()
                    .expect("Failed to convert schema to Cedar format");

                // Parse again to assert that the roundtripped schema is equivalent.
                let (roundtrip_schema, _) = ValidatorSchema::from_cedarschema_str(
                    &roundtrip_result,
                    &Extensions::all_available(),
                )
                .expect("Failed to parse roundtrip Cedar schema");
                similar_asserts::assert_eq!(roundtrip_schema, original_schema);

                // Snapshot the middle cedar schema text so we can check that it
                // looks reasonable to a human.
                insta::assert_snapshot!(roundtrip_result);
            }
        );
    }
}
