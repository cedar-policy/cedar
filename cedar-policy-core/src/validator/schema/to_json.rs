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

//! FIXME: Vibe coded. I've looked at snapshot tests, but need to check implementation
//! Defines conversion from the schema structures used internally by the
//! validator back to JSON.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{
    ast::{EntityType, EntityUID, Name, UnreservedId},
    est::Annotations,
    validator::{
        RawName, ValidatorActionId, ValidatorEntityType, ValidatorEntityTypeKind, ValidatorSchema,
        json_schema, types::{Type, OpenTag},
    },
};
use smol_str::SmolStr;

fn validator_type_to_json_type(ty: &Type) -> Result<json_schema::Type<RawName>, String> {
    match ty {
        Type::Primitive { primitive_type } => {
            use crate::validator::types::Primitive;
            let variant = match primitive_type {
                Primitive::Bool => json_schema::TypeVariant::Boolean,
                Primitive::Long => json_schema::TypeVariant::Long,
                Primitive::String => json_schema::TypeVariant::String,
            };
            Ok(json_schema::Type::Type { ty: variant, loc: None })
        }
        Type::Set { element_type } => {
            let element = match element_type {
                Some(et) => validator_type_to_json_type(et)?,
                None => return Err("Set with unknown element type not supported".to_string()),
            };
            Ok(json_schema::Type::Type {
                ty: json_schema::TypeVariant::Set {
                    element: Box::new(element),
                },
                loc: None,
            })
        }
        Type::EntityOrRecord(kind) => {
            use crate::validator::types::EntityRecordKind;
            match kind {
                EntityRecordKind::Record { attrs, open_attributes } => {
                    let attributes = attrs.iter().map(|(name, attr_type)| {
                        Ok((name.clone(), json_schema::TypeOfAttribute {
                            ty: validator_type_to_json_type(&attr_type.attr_type)?,
                            required: attr_type.is_required,
                            annotations: Annotations::new(),
                        }))
                    }).collect::<Result<BTreeMap<_, _>, String>>()?;
                    
                    Ok(json_schema::Type::Type {
                        ty: json_schema::TypeVariant::Record(json_schema::RecordType {
                            attributes,
                            additional_attributes: *open_attributes == OpenTag::OpenAttributes,
                        }),
                        loc: None,
                    })
                }
                EntityRecordKind::Entity(lub) => {
                    if let Some(entity_type) = lub.get_single_entity() {
                        Ok(json_schema::Type::Type {
                            ty: json_schema::TypeVariant::EntityOrCommon {
                                type_name: RawName::from_name(entity_type.as_ref().as_ref().clone()),
                            },
                            loc: None,
                        })
                    } else {
                        Err("Entity LUB with multiple types not supported".to_string())
                    }
                }
                _ => Err("Unsupported entity/record type".to_string()),
            }
        }
        Type::ExtensionType { name } => {
            Ok(json_schema::Type::Type {
                ty: json_schema::TypeVariant::Extension {
                    name: name.basename().clone(),
                },
                loc: None,
            })
        }
        _ => Err("Unsupported type for conversion".to_string()),
    }
}

impl ValidatorSchema {
    /// Converts a `ValidatorSchema` into a `json_schema::Fragment`.
    /// Roundtripping through this function gives a semantically equivalent
    /// schema but will lose formatting, annotations, and common type
    /// definition. It will also result in the inlining the transitive closure
    /// of the entity hierarchy at for each entity type and action.
    pub fn to_json_schema(&self) -> Result<json_schema::Fragment<RawName>, String> {
        // 1. Un-invert the entity type and action hierarchy so we get back to the `entity type -> ancestors` mapping.
        let uninverted_entity_types = self.uninverted_entity_types();
        let uninverted_actions = self.uninverted_actions();
        
        // 2-3. Procedures for converting are implemented as trait methods
        
        // 4. Group entity types and action types by their namespace
        let mut namespaces: HashMap<Option<Name>, (BTreeMap<UnreservedId, json_schema::EntityType<RawName>>, BTreeMap<SmolStr, json_schema::ActionType<RawName>>)> = HashMap::new();
        
        // Process entity types
        for (entity_type, (validator_entity_type, ancestors)) in uninverted_entity_types {
            let namespace = {
                let ns_str = entity_type.as_ref().as_ref().namespace();
                if ns_str.is_empty() { None } else { Some(ns_str.parse().map_err(|e| format!("Invalid namespace: {}", e))?) }
            };
            let entity_name = entity_type.as_ref().basename().clone();
            let json_entity_type = validator_entity_type.to_json_entity_type(ancestors)?;
            
            let (entity_types, _) = namespaces.entry(namespace).or_insert_with(|| (BTreeMap::new(), BTreeMap::new()));
            entity_types.insert(entity_name, json_entity_type);
        }
        
        // Process actions
        for (action_uid, (validator_action_id, ancestors)) in uninverted_actions {
            let namespace = {
                let ns_str = action_uid.entity_type().as_ref().as_ref().namespace();
                if ns_str.is_empty() { None } else { Some(ns_str.parse().map_err(|e| format!("Invalid namespace: {}", e))?) }
            };
            let action_name = SmolStr::from(action_uid.eid().as_ref().to_string());
            let json_action_type = validator_action_id.to_json_action_type(ancestors)?;
            
            let (_, action_types) = namespaces.entry(namespace).or_insert_with(|| (BTreeMap::new(), BTreeMap::new()));
            action_types.insert(action_name, json_action_type);
        }
        
        // 5. Convert each namespace to a NamespaceDefinition
        let mut namespace_definitions = BTreeMap::new();
        for (namespace, (entity_types, action_types)) in namespaces {
            let namespace_def = json_schema::NamespaceDefinition {
                common_types: BTreeMap::new(), // Common types are not preserved in roundtrip
                entity_types,
                actions: action_types,
                annotations: Annotations::new(),
            };
            namespace_definitions.insert(namespace, namespace_def);
        }
        
        // 6. Gather into a Fragment
        Ok(json_schema::Fragment(namespace_definitions))
    }

    /// Converts a `ValidatorSchema` into a Cedar schema string.
    /// This first converts to JSON schema format and then to Cedar syntax.
    pub fn to_cedar_schema(&self) -> Result<String, String> {
        let fragment = self.to_json_schema()?;
        fragment.to_cedarschema().map_err(|e| e.to_string())
    }

    fn uninverted_entity_types(&self) -> HashMap<EntityType, (ValidatorEntityType, HashSet<EntityType>)> {
        // Compute direct ancestors of each type from the transitive closure stored in descendants
        let mut result = HashMap::new();
        
        // Initialize all entity types with empty ancestor sets
        for (entity_type, validator_entity_type) in &self.entity_types {
            result.insert(entity_type.clone(), (validator_entity_type.clone(), HashSet::new()));
        }
        
        // For each entity type, find its direct parents
        for (child_type, _) in &self.entity_types {
            let mut direct_parents = HashSet::new();
            
            // Find all potential parents (those who have this child in their descendants)
            let mut all_parents = HashSet::new();
            for (parent_type, parent_validator) in &self.entity_types {
                if parent_validator.descendants.contains(child_type) {
                    all_parents.insert(parent_type.clone());
                }
            }
            
            // A parent is direct if no other potential parent is a descendant of this parent
            // In other words, this parent doesn't have any other potential parent in its descendants
            for parent in &all_parents {
                let mut is_direct = true;
                if let Some(parent_validator) = self.entity_types.get(parent) {
                    for other_parent in &all_parents {
                        if parent != other_parent && parent_validator.descendants.contains(other_parent) {
                            is_direct = false;
                            break;
                        }
                    }
                }
                if is_direct {
                    direct_parents.insert(parent.clone());
                }
            }
            
            if let Some((_, ancestors)) = result.get_mut(child_type) {
                *ancestors = direct_parents;
            }
        }
        
        result
    }

    fn uninverted_actions(&self) -> HashMap<EntityUID, (ValidatorActionId, HashSet<EntityUID>)> {
        // Compute ancestors of each action from descendants
        let mut result = HashMap::new();
        
        // Initialize all actions with empty ancestor sets
        for (action_id, validator_action_id) in &self.action_ids {
            result.insert(action_id.clone(), (validator_action_id.clone(), HashSet::new()));
        }
        
        // For each action, add it as an ancestor to all its descendants
        for (action_id, validator_action_id) in &self.action_ids {
            for descendant in &validator_action_id.descendants {
                if let Some((_, ancestors)) = result.get_mut(descendant) {
                    ancestors.insert(action_id.clone());
                }
            }
        }
        
        result
    }
}

impl ValidatorActionId {
    fn to_json_action_type(&self, ancestors: HashSet<EntityUID>) -> Result<json_schema::ActionType<RawName>, String> {
        // Convert ancestors to member_of (JSON schema format)
        let member_of: Option<Vec<json_schema::ActionEntityUID<RawName>>> = if ancestors.is_empty() {
            None
        } else {
            // Sort for deterministic output
            let mut ancestor_vec: Vec<_> = ancestors.into_iter().collect();
            ancestor_vec.sort();
            Some(ancestor_vec
                .into_iter()
                .map(|action_uid| json_schema::ActionEntityUID {
                    ty: None, // Use default Action type
                    id: SmolStr::from(action_uid.eid().as_ref().to_string()),
                })
                .collect())
        };
        
        Ok(json_schema::ActionType {
            attributes: None,
            applies_to: Some(json_schema::ApplySpec {
                resource_types: {
                    let mut types: Vec<_> = self.applies_to.applicable_resource_types()
                        .map(|et| RawName::from_name(et.as_ref().as_ref().clone()))
                        .collect();
                    types.sort();
                    types
                },
                principal_types: {
                    let mut types: Vec<_> = self.applies_to.applicable_principal_types()
                        .map(|et| RawName::from_name(et.as_ref().as_ref().clone()))
                        .collect();
                    types.sort();
                    types
                },
                context: json_schema::AttributesOrContext(
                    validator_type_to_json_type(&self.context)?
                ),
            }),
            member_of,
            annotations: Annotations::new(),
            loc: self.loc.clone(),
        })
    }
}

impl ValidatorEntityType {
    fn to_json_entity_type(&self, ancestors: HashSet<EntityType>) -> Result<json_schema::EntityType<RawName>, String> {
        // Convert ancestors to member_of_types (JSON schema format)
        // Sort for deterministic output
        let mut ancestor_vec: Vec<_> = ancestors.into_iter().collect();
        ancestor_vec.sort();
        let member_of_types: Vec<RawName> = ancestor_vec
            .into_iter()
            .map(|entity_type| RawName::from_name(entity_type.as_ref().as_ref().clone()))
            .collect();
        
        let kind = match &self.kind {
            ValidatorEntityTypeKind::Standard(std_type) => {
                let attributes = self.attributes.iter().map(|(name, attr_type)| {
                    Ok((name.clone(), json_schema::TypeOfAttribute {
                        ty: validator_type_to_json_type(&attr_type.attr_type)?,
                        required: attr_type.is_required,
                        annotations: Annotations::new(),
                    }))
                }).collect::<Result<BTreeMap<_, _>, String>>()?;
                
                json_schema::EntityTypeKind::Standard(json_schema::StandardEntityType {
                    member_of_types,
                    shape: json_schema::AttributesOrContext(
                        json_schema::Type::Type {
                            ty: json_schema::TypeVariant::Record(
                                json_schema::RecordType {
                                    attributes,
                                    additional_attributes: std_type.open_attributes == crate::validator::types::OpenTag::OpenAttributes,
                                }
                            ),
                            loc: None,
                        }
                    ),
                    tags: std_type.tags.as_ref().map(|tag_type| validator_type_to_json_type(tag_type)).transpose()?,
                })
            }
            ValidatorEntityTypeKind::Enum(choices) => {
                json_schema::EntityTypeKind::Enum {
                    choices: choices.clone(),
                }
            }
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
    use crate::validator::ValidatorSchema;
    
    #[test]
    fn test_to_json_schema_basic() {
        // Create a simple schema with no entity types or actions
        let schema = ValidatorSchema::empty();
        
        // Test that to_json_schema works without panicking
        let result = schema.to_json_schema();
        assert!(result.is_ok());
        
        let fragment = result.unwrap();
        // Empty schema should have no namespaces
        assert_eq!(fragment.0.len(), 0);
    }
    
    #[test]
    fn test_to_json_schema_with_simple_types() {
        use crate::validator::json_schema;
        use crate::extensions::Extensions;
        
        // Test with a simple schema that has entity types and actions
        let schema_json = serde_json::json!({
            "": {
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "name": { "type": "String" }
                            }
                        }
                    }
                },
                "actions": {
                    "view": {
                        "appliesTo": {
                            "principalTypes": ["User"],
                            "resourceTypes": ["User"],
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "ip": { "type": "String" }
                                }
                            }
                        }
                    }
                }
            }
        });
        
        let schema = ValidatorSchema::from_json_value(schema_json, &Extensions::all_available()).unwrap();
        let result = schema.to_json_schema();
        assert!(result.is_ok());
        
        let fragment = result.unwrap();
        assert_eq!(fragment.0.len(), 1);
        
        // Check that we have the expected entity type and action
        let namespace_def = fragment.0.get(&None).unwrap();
        assert_eq!(namespace_def.entity_types.len(), 1);
        assert_eq!(namespace_def.actions.len(), 1);
        
        // Verify entity type has attributes
        let user_type = namespace_def.entity_types.values().next().unwrap();
        if let json_schema::EntityTypeKind::Standard(std_type) = &user_type.kind {
            if let json_schema::AttributesOrContext(json_schema::Type::Type { ty: json_schema::TypeVariant::Record(record), .. }) = &std_type.shape {
                assert_eq!(record.attributes.len(), 1);
                assert!(record.attributes.contains_key("name"));
            } else {
                panic!("Expected record type for entity shape");
            }
        } else {
            panic!("Expected standard entity type");
        }
        
        // Verify action has context
        let view_action = namespace_def.actions.values().next().unwrap();
        if let Some(applies_to) = &view_action.applies_to {
            if let json_schema::AttributesOrContext(json_schema::Type::Type { ty: json_schema::TypeVariant::Record(record), .. }) = &applies_to.context {
                assert_eq!(record.attributes.len(), 1);
                assert!(record.attributes.contains_key("ip"));
            } else {
                panic!("Expected record type for action context");
            }
        } else {
            panic!("Expected applies_to for action");
        }
    }
    
    #[test]
    fn test_to_cedar_schema() {
        use crate::extensions::Extensions;
        
        // Test with a simple schema
        let schema_json = serde_json::json!({
            "": {
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "name": { "type": "String" }
                            }
                        }
                    }
                },
                "actions": {
                    "view": {
                        "appliesTo": {
                            "principalTypes": ["User"],
                            "resourceTypes": ["User"]
                        }
                    }
                }
            }
        });
        
        let schema = ValidatorSchema::from_json_value(schema_json, &Extensions::all_available()).unwrap();
        let result = schema.to_cedar_schema();
        assert!(result.is_ok());
        
        let cedar_schema = result.unwrap();
        // Should contain entity type and action definitions
        assert!(cedar_schema.contains("entity User"));
        assert!(cedar_schema.contains("\"view\""));
        assert!(cedar_schema.contains("appliesTo"));
    }
    
    #[test]
    fn test_roundtrip_schemas() {
        use crate::extensions::Extensions;
        
        insta::glob!("test_schemas/*.cedarschema", |path| {
            let cedar_schema = std::fs::read_to_string(path).unwrap();
            
            // Parse the original Cedar schema
            let (original_schema, _) = ValidatorSchema::from_cedarschema_str(
                &cedar_schema, 
                &Extensions::all_available()
            ).expect("Failed to parse original Cedar schema");
            
            // Convert to Cedar schema string via JSON roundtrip
            let roundtrip_result = original_schema.to_cedar_schema()
                .expect("Failed to convert schema to Cedar format");
            
            // Create snapshot - insta will use the filename as the snapshot name
            insta::assert_snapshot!(roundtrip_result);
            
            // Verify the roundtrip result can be parsed back
            let (roundtrip_schema, _) = ValidatorSchema::from_cedarschema_str(
                &roundtrip_result,
                &Extensions::all_available()
            ).expect("Failed to parse roundtrip Cedar schema");
        });
    }
}
