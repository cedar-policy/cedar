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

//! Annotate entity manifest with type information.

use crate::ast::{RequestType, Var};

use crate::validator::entity_manifest::AccessTermNotFoundError;
use crate::validator::types::EntityRecordKind;
use crate::validator::{
    entity_manifest::{AccessDag, AccessTerm, AccessTermVariant, EntityManifest, RequestTypePaths},
    types::Type,
    ValidatorSchema,
};
// Import errors directly
use crate::validator::entity_manifest::errors::{
    MismatchedEntityManifestError, MismatchedExpectedEntityError,
    MismatchedExpectedEntityOrRecordError, MismatchedMissingEntityError,
    MismatchedNotStrictSchemaError,
};

impl EntityManifest {
    /// Given an untyped entity manifest and the schema that produced it,
    /// return a newly typed entity manifest.
    /// Makes the types field of the manifest Some instead of None
    pub(crate) fn add_types(
        mut self,
        schema: &ValidatorSchema,
    ) -> Result<EntityManifest, MismatchedEntityManifestError> {
        // Type each PathsForRequestType
        for paths_for_request_type in self.per_action.values_mut() {
            paths_for_request_type.add_types(schema)?;
        }

        Ok(self)
    }
}

impl RequestTypePaths {
    /// Type-annotate this [`PathsForRequestType`], given the schema.
    pub(crate) fn add_types(
        &mut self,
        schema: &ValidatorSchema,
    ) -> Result<(), MismatchedEntityManifestError> {
        // Initialize the types vector with None for each path in the DAG

        // Process each access path in topological order
        // Since the DAG structure ensures that all dependencies are processed before dependents,
        // we can simply iterate through the paths in order of their IDs
        for path in self.dag.manifest_store.iter() {
            self.dag
                .types
                .push(self.type_path(path, &self.request_type, schema, &self.dag)?);
        }

        Ok(())
    }

    /// Helper method to type a single path.
    /// When the type does not exist in the schema, it returns `None`.
    fn type_path(
        &self,
        variant: &AccessTermVariant,
        request_type: &RequestType,
        schema: &ValidatorSchema,
        dag: &AccessDag,
    ) -> Result<Option<Type>, MismatchedEntityManifestError> {
        let res = match variant {
            AccessTermVariant::Var(var) => {
                // Type the variable based on its kind
                let ty = match var {
                    Var::Action => {
                        Type::euid_literal(&request_type.action, schema).ok_or_else(|| {
                            MismatchedMissingEntityError {
                                entity: request_type.action.clone(),
                            }
                        })?
                    }
                    Var::Principal => Type::named_entity_reference(request_type.principal.clone()),
                    Var::Resource => Type::named_entity_reference(request_type.resource.clone()),
                    Var::Context => schema
                        .get_action_id(&request_type.action.clone())
                        .ok_or_else(|| MismatchedMissingEntityError {
                            entity: request_type.action.clone(),
                        })?
                        .context
                        .clone(),
                };

                ty
            }
            AccessTermVariant::Literal(lit) => {
                Type::euid_literal(lit, schema).ok_or_else(|| MismatchedMissingEntityError {
                    entity: lit.clone(),
                })?
            }
            AccessTermVariant::String(_) => {
                // String literals have String type
                Type::primitive_string()
            }
            AccessTermVariant::Attribute { of, attr } => {
                // Get the type of the base expression (should already be typed)
                let Some(Some(of_type)) = self.dag.types.get(of.id) else {
                    return Ok(None);
                };

                // Get the attribute type from the base type
                match of_type {
                    Type::EntityOrRecord(entity_or_record_ty) => {
                        let attributes = match entity_or_record_ty {
                            EntityRecordKind::Record {
                                attrs,
                                open_attributes: _,
                            } => attrs.clone(),
                            EntityRecordKind::AnyEntity => {
                                return Err(MismatchedNotStrictSchemaError {}.into());
                            }
                            EntityRecordKind::Entity(entitylub) => {
                                let entity_ty = schema
                                    .get_entity_type(
                                        entitylub
                                            .get_single_entity()
                                            .ok_or(MismatchedNotStrictSchemaError {})?,
                                    )
                                    .ok_or(MismatchedNotStrictSchemaError {})?;
                                entity_ty.attributes().clone()
                            }
                            EntityRecordKind::ActionEntity { name: _, attrs } => attrs.clone(),
                        };

                        if let Some(attr_type) = attributes.get_attr(attr) {
                            attr_type.attr_type.clone()
                        } else {
                            // The attribute was not found, but this can happen
                            // for example with `has` statements on types without the attribute.
                            // In this case, we return None to indicate that the attribute is not present.
                            return Ok(None);
                        }
                    }
                    _ => {
                        return Err(MismatchedExpectedEntityOrRecordError {
                            found_type: of_type.clone(),
                        }
                        .into());
                    }
                }
            }
            AccessTermVariant::Tag {
                of: access_path,
                tag: tag_path,
            } => {
                let Some(Some(access_path_type)) = self.dag.types.get(access_path.id) else {
                    return Ok(None);
                };
                // of should be an entity type with a tag type
                if let Type::EntityOrRecord(EntityRecordKind::Entity(entitylub)) = access_path_type
                {
                    let entity_ty = schema
                        .get_entity_type(
                            entitylub
                                .get_single_entity()
                                .ok_or(MismatchedNotStrictSchemaError {})?,
                        )
                        .ok_or(MismatchedNotStrictSchemaError {})?;
                    entity_ty.tag_type().unwrap().clone() // todo fix unwrap
                } else {
                    return Err(MismatchedExpectedEntityError {
                        found_type: access_path_type.clone(),
                    }
                    .into());
                }
            }
            AccessTermVariant::Ancestor { of: _, ancestor: _ } => {
                // Ancestor checks result in boolean values
                Type::True
            }
        };

        Ok(Some(res))
    }
}
