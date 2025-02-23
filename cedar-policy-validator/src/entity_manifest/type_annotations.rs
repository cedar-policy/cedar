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

use cedar_policy_core::ast::{RequestType, Var};

use crate::{
    entity_manifest::{
        AccessTrie, EntityManifest, EntityRoot, Fields, MismatchedEntityManifestError,
        MismatchedMissingEntityError, MismatchedNotStrictSchemaError, RootAccessTrie,
    },
    types::{Attributes, EntityRecordKind, Type},
    ValidatorSchema,
};

impl EntityManifest {
    /// Given an untyped entity manifest and the schema that produced it,
    /// return a newly typed entity manifest.
    pub(crate) fn to_typed(
        &self,
        schema: &ValidatorSchema,
    ) -> Result<EntityManifest, MismatchedEntityManifestError> {
        Ok(
            EntityManifest {
                per_action:
                    self.per_action
                        .iter()
                        .map(|(key, val)| Ok((key.clone(), val.to_typed(key, schema)?)))
                        .collect::<Result<
                            HashMap<RequestType, RootAccessTrie>,
                            MismatchedEntityManifestError,
                        >>()?,
            },
        )
    }
}

impl RootAccessTrie {
    /// Type-annotate this primary slice, given the type of
    /// the request and the schema.
    pub(crate) fn to_typed(
        &self,
        request_type: &RequestType,
        schema: &ValidatorSchema,
    ) -> Result<RootAccessTrie, MismatchedEntityManifestError> {
        Ok(RootAccessTrie {
            trie: self
                .trie
                .iter()
                .map(|(key, slice)| {
                    Ok((
                        key.clone(),
                        match key {
                            EntityRoot::Literal(lit) => slice.to_typed(
                                request_type,
                                &Type::euid_literal(lit, schema).ok_or_else(|| {
                                    MismatchedMissingEntityError {
                                        entity: lit.clone(),
                                    }
                                })?,
                                schema,
                            )?,
                            EntityRoot::Var(Var::Action) => {
                                let ty = Type::euid_literal(&request_type.action, schema)
                                    .ok_or_else(|| MismatchedMissingEntityError {
                                        entity: request_type.action.clone(),
                                    })?;
                                slice.to_typed(request_type, &ty, schema)?
                            }
                            EntityRoot::Var(Var::Principal) => slice.to_typed(
                                request_type,
                                &Type::named_entity_reference(request_type.principal.clone()),
                                schema,
                            )?,
                            EntityRoot::Var(Var::Resource) => slice.to_typed(
                                request_type,
                                &Type::named_entity_reference(request_type.resource.clone()),
                                schema,
                            )?,
                            EntityRoot::Var(Var::Context) => {
                                let ty = &schema
                                    .get_action_id(&request_type.action.clone())
                                    .ok_or_else(|| MismatchedMissingEntityError {
                                        entity: request_type.action.clone(),
                                    })?
                                    .context;
                                slice.to_typed(request_type, ty, schema)?
                            }
                        },
                    ))
                })
                .collect::<Result<HashMap<EntityRoot, AccessTrie>, MismatchedEntityManifestError>>(
                )?,
        })
    }
}

impl AccessTrie {
    pub(crate) fn to_typed(
        &self,
        request_type: &RequestType,
        ty: &Type,
        schema: &ValidatorSchema,
    ) -> Result<AccessTrie, MismatchedEntityManifestError> {
        let children: Fields = match ty {
            Type::Never
            | Type::True
            | Type::False
            | Type::Primitive { .. }
            | Type::Set { .. }
            | Type::ExtensionType { .. } => {
                assert!(self.children.is_empty());
                HashMap::default()
            }
            Type::EntityOrRecord(entity_or_record_ty) => {
                let attributes: &Attributes = match entity_or_record_ty {
                    EntityRecordKind::Record {
                        attrs,
                        open_attributes: _,
                    } => attrs,
                    EntityRecordKind::AnyEntity => Err(MismatchedNotStrictSchemaError {})?,
                    // PANIC SAFETY: entity LUB should succeed after strict validation, and so should looking up the resulting type
                    #[allow(clippy::unwrap_used)]
                    EntityRecordKind::Entity(entitylub) => {
                        let entity_ty = schema
                            .get_entity_type(
                                entitylub
                                    .get_single_entity()
                                    .ok_or(MismatchedNotStrictSchemaError {})?,
                            )
                            .ok_or(MismatchedNotStrictSchemaError {})?;
                        entity_ty.attributes()
                    }
                    EntityRecordKind::ActionEntity { name: _, attrs } => attrs,
                };

                let mut new_children = HashMap::new();
                for (field, child) in self.children.iter() {
                    // if the schema doesn't mention an attribute,
                    // it's safe to drop it.
                    // this can come up with the `has` operator
                    // on a type that doesn't have the attribute
                    if let Some(ty) = attributes.get_attr(field) {
                        new_children.insert(
                            field.clone(),
                            Box::new(child.to_typed(request_type, &ty.attr_type, schema)?),
                        );
                    }
                }
                new_children
            }
        };

        Ok(AccessTrie {
            children,
            node_type: Some(ty.clone()),
            ancestors_trie: self.ancestors_trie.to_typed(request_type, schema)?,
            is_ancestor: self.is_ancestor,
        })
    }
}
