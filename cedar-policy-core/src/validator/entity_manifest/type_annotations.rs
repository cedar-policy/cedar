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

use std::collections::HashMap;

use crate::ast::{RequestType, Var};

use crate::validator::entity_manifest::{
    AccessPath, AccessPathNotFoundError, AccessPathVariant, AccessPaths, PathsForRequestType,
};
use crate::validator::{
    entity_manifest::{
        AccessDag, EntityManifest, EntityRoot, MismatchedEntityManifestError,
        MismatchedMissingEntityError, MismatchedNotStrictSchemaError,
    },
    types::{Attributes, EntityRecordKind, Type},
    ValidatorSchema,
};

impl EntityManifest {
    /// Given an untyped entity manifest and the schema that produced it,
    /// return a newly typed entity manifest.
    /// Makes the types field of the manifest Some instead of None
    pub(crate) fn to_typed(
        &self,
        schema: &ValidatorSchema,
    ) -> Result<EntityManifest, MismatchedEntityManifestError> {
        // Create a new entity manifest with the same structure
        let mut typed_manifest = self.clone();

        // Type each PathsForRequestType
        for (_request_type, paths_for_request_type) in &mut typed_manifest.per_action {
            *paths_for_request_type = paths_for_request_type.to_typed(schema)?;
        }

        Ok(typed_manifest)
    }
}

impl PathsForRequestType {
    /// Type-annotate this PathsForRequestType, given the schema.
    pub(crate) fn to_typed(
        &self,
        schema: &ValidatorSchema,
    ) -> Result<PathsForRequestType, MismatchedEntityManifestError> {
        // Create a new PathsForRequestType with the same structure
        let mut typed_paths = self.clone();

        // Initialize the types vector with None for each path in the DAG
        let mut types = vec![None; typed_paths.dag.manifest_store.len()];

        // Process each access path
        for path in &typed_paths.access_paths.paths {
            // Type the path and all its subpaths
            self.type_path_and_subpaths(
                path,
                &self.request_type,
                schema,
                &mut types,
                &typed_paths.dag,
            )?;
        }

        // Set the types field in the DAG
        typed_paths.dag.types = Some(types.into_iter().flatten().collect());

        Ok(typed_paths)
    }

    /// Helper method to type a path and all its subpaths
    fn type_path_and_subpaths(
        &self,
        path: &AccessPath,
        request_type: &RequestType,
        schema: &ValidatorSchema,
        types: &mut Vec<Option<Type>>,
        dag: &AccessDag,
    ) -> Result<(), MismatchedEntityManifestError> {
        // Skip if already typed
        if types[path.id].is_some() {
            return Ok(());
        }

        // Get the variant for this path
        let variant = match path.get_variant(dag) {
            Ok(v) => v,
            Err(e) => return Err(AccessPathNotFoundError { path_id: path.id }),
        };

        match variant {
            AccessPathVariant::Var(var) => {
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

                // Store the type in the types vector
                types[path.id] = Some(ty);
            }
            AccessPathVariant::Literal(_) => {}
            AccessPathVariant::String(_) => {
                // String literals have String type
                types[path.id] = Some(Type::primitive_string());
            }
            AccessPathVariant::Attribute { of, attr } => {
                // First, ensure the base path is typed
                self.type_path_and_subpaths(of, request_type, schema, types, dag)?;

                // Get the type of the base expression
                let of_type = types[of.id]
                    .as_ref()
                    .ok_or_else(|| MismatchedNotStrictSchemaError {})?;

                // Get the attribute type from the base type
                match of_type {
                    Type::EntityOrRecord(entity_or_record_ty) => {
                        let attributes = match entity_or_record_ty {
                            EntityRecordKind::Record {
                                attrs,
                                open_attributes: _,
                            } => attrs,
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
                            EntityRecordKind::ActionEntity { name: _, attrs } => attrs,
                        };

                        // Get the attribute type
                        if let Some(attr_type) = attributes.get_attr(attr) {
                            types[path.id] = Some(attr_type.attr_type.clone());
                        } else {
                            // If the schema doesn't mention this attribute, it's safe to drop it
                            // This can happen with the `has` operator on a type that doesn't have the attribute
                        }
                    }
                    _ => {
                        // Non-entity and non-record types don't have attributes
                        // This should be caught by the typechecker, but we'll handle it gracefully
                    }
                }
            }
            AccessPathVariant::Tag { of, tag } => {
                // First, ensure the base paths are typed
                self.type_path_and_subpaths(of, request_type, schema, types, dag)?;
                self.type_path_and_subpaths(tag, request_type, schema, types, dag)?;

                // Tags are not fully supported yet, but we'll handle them as strings
                types[path.id] = Some(Type::primitive_string());
            }
            AccessPathVariant::Ancestor { of, ancestor } => {
                // First, ensure the base paths are typed
                self.type_path_and_subpaths(of, request_type, schema, types, dag)?;
                self.type_path_and_subpaths(ancestor, request_type, schema, types, dag)?;

                // Ancestor checks result in boolean values
                types[path.id] = Some(Type::True);
            }
        };

        // Process all children of this path
        let children = path.children(dag);
        for child in children {
            self.type_path_and_subpaths(&child, request_type, schema, types, dag)?;
        }

        Ok(())
    }
}
