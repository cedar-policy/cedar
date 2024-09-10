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
    entity_manifest::{AccessTrie, EntityManifest, EntityRoot, Fields, RootAccessTrie},
    types::{Attributes, EntityRecordKind, Type},
    ValidatorSchema,
};

impl EntityManifest {
    /// Given an untyped entity manifest and the schema that produced it,
    /// return a newly typed entity manifest.
    pub(crate) fn to_typed(&self, schema: &ValidatorSchema) -> EntityManifest {
        EntityManifest {
            per_action: self
                .per_action
                .iter()
                .map(|(key, val)| (key.clone(), val.to_typed(key, schema)))
                .collect(),
        }
    }
}

impl RootAccessTrie {
    /// Type-annotate this primary slice, given the type of
    /// the request and the schema.
    pub(crate) fn to_typed(
        &self,
        request_type: &RequestType,
        schema: &ValidatorSchema,
    ) -> RootAccessTrie {
        RootAccessTrie {
            trie: self
                .trie
                .iter()
                .map(|(key, slice)| {
                    (
                        key.clone(),
                        match key {
                            // PANIC SAFETY: literal is checked against the schema during typechecking
                            #[allow(clippy::unwrap_used)]
                            EntityRoot::Literal(lit) => slice.to_typed(
                                request_type,
                                &Type::euid_literal(lit.clone(), schema).unwrap(),
                                schema,
                            ),
                            // PANIC SAFETY: action literal is checked against the schema during typechecking
                            EntityRoot::Var(Var::Action) => {
                                let ty = Type::euid_literal(request_type.action.clone(), schema)
                                    .unwrap();
                                slice.to_typed(request_type, &ty, schema)
                            }
                            EntityRoot::Var(Var::Principal) => slice.to_typed(
                                request_type,
                                &Type::named_entity_reference(request_type.principal.clone()),
                                schema,
                            ),
                            EntityRoot::Var(Var::Resource) => slice.to_typed(
                                request_type,
                                &Type::named_entity_reference(request_type.resource.clone()),
                                schema,
                            ),
                            EntityRoot::Var(Var::Context) => {
                                let ty =
                                    &schema.get_action_id(&request_type.action).unwrap().context;
                                slice.to_typed(request_type, ty, schema)
                            }
                        },
                    )
                })
                .collect(),
        }
    }
}

impl AccessTrie {
    pub(crate) fn to_typed(
        &self,
        request_type: &RequestType,
        ty: &Type,
        schema: &ValidatorSchema,
    ) -> AccessTrie {
        let children: Fields = match ty {
            Type::Never
            | Type::True
            | Type::False
            | Type::Primitive { .. }
            | Type::Set { .. }
            | Type::ExtensionType { .. } => {
                assert!(self.children.len() == 0);
                HashMap::default()
            }
            Type::EntityOrRecord(entity_or_record_ty) => {
                let attributes: &Attributes = match entity_or_record_ty {
                    EntityRecordKind::Record {
                        attrs,
                        open_attributes: _,
                    } => attrs,
                    // PANIC SAFETY: strict validation shouldn't produce the AnyEntity type
                    #[allow(clippy::panic)]
                    EntityRecordKind::AnyEntity => {
                        panic!("Strict validation resulted in AnyEntity")
                    }
                    EntityRecordKind::Entity(entitylub) => {
                        let entity_ty = schema
                            .get_entity_type(entitylub.get_single_entity().unwrap())
                            .unwrap();
                        &entity_ty.attributes
                    }
                    EntityRecordKind::ActionEntity { name: _, attrs } => attrs,
                };

                self.children
                    .iter()
                    .map(|(field, child)| {
                        let ty = attributes.attrs.get(field).unwrap();
                        (
                            field.clone(),
                            Box::new(child.to_typed(&request_type, &ty.attr_type, schema)),
                        )
                    })
                    .collect()
            }
        };

        AccessTrie {
            children,
            node_type: Some(ty.clone()),
            ancestors_trie: self.ancestors_trie.to_typed(request_type, schema),
            is_ancestor: self.is_ancestor,
        }
    }
}
