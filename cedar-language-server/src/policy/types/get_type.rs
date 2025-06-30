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

use std::collections::HashMap;

use cedar_policy_core::ast::EntityType;
use cedar_policy_core::validator::{
    types::{AttributeType, Attributes, EntityRecordKind, Type},
    ValidatorEntityType, ValidatorSchema,
};
use itertools::Itertools;

use super::{
    cedar::{CedarTypeKind, ContextKind, EntityTypeKind},
    DocumentContext,
};

#[derive(Debug, Clone)]
pub(crate) struct TypeInferenceContext<'a> {
    pub(crate) document_context: &'a DocumentContext<'a>,
    base_type: Option<CedarTypeKind>,
    attr_path: Vec<String>,
}

impl<'a> From<&'a DocumentContext<'_>> for TypeInferenceContext<'a> {
    fn from(value: &'a DocumentContext<'_>) -> Self {
        TypeInferenceContext::new(value)
    }
}

impl<'a> TypeInferenceContext<'a> {
    #[must_use]
    pub(crate) fn new(document_context: &'a DocumentContext<'_>) -> Self {
        Self {
            document_context,
            base_type: None,
            attr_path: vec![],
        }
    }

    pub(crate) fn add_attr(&mut self, attr: &str) {
        self.attr_path.push(attr.to_string());
    }

    pub(crate) fn set_base_type(&mut self, base_type: CedarTypeKind) {
        self.base_type = Some(base_type);
    }

    #[must_use]
    pub(crate) fn get_base_type_attrs(&'a self) -> Option<AttributeCollection<'a>> {
        let schema = self.document_context.schema()?;
        let base_type = self.base_type.as_ref()?;

        match base_type {
            CedarTypeKind::EntityType(EntityTypeKind::Concrete(et)) => schema
                .get_entity_type(et)
                .map(|vet| AttributeCollection::from_attributes(vet.attributes())),
            CedarTypeKind::EntityType(EntityTypeKind::Set(set)) => {
                let entity_pairs = set
                    .iter()
                    .map(std::convert::AsRef::as_ref)
                    .filter_map(|et| schema.get_entity_type(et).map(|vet| (et, vet)))
                    .collect::<Vec<_>>();

                if entity_pairs.is_empty() {
                    None
                } else {
                    Some(AttributeCollection::from_entity_types(
                        entity_pairs.into_iter(),
                    ))
                }
            }
            CedarTypeKind::EntityType(EntityTypeKind::AnyPrincipal) => {
                let entity_pairs = schema
                    .principals()
                    .unique()
                    .filter_map(|et| schema.get_entity_type(et).map(|vet| (et, vet)))
                    .collect::<Vec<_>>();

                if entity_pairs.is_empty() {
                    None
                } else {
                    Some(AttributeCollection::from_entity_types(
                        entity_pairs.into_iter(),
                    ))
                }
            }
            CedarTypeKind::EntityType(EntityTypeKind::AnyResource) => {
                let entity_pairs = schema
                    .resources()
                    .unique()
                    .filter_map(|et| schema.get_entity_type(et).map(|vet| (et, vet)))
                    .collect::<Vec<_>>();

                if entity_pairs.is_empty() {
                    None
                } else {
                    Some(AttributeCollection::from_entity_types(
                        entity_pairs.into_iter(),
                    ))
                }
            }
            CedarTypeKind::Context(ContextKind::AnyContext) => {
                let attrs = schema
                    .action_ids()
                    .map(cedar_policy_core::validator::ValidatorActionId::context_type)
                    .filter_map(|ty| match ty {
                        Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => Some(attrs),
                        _ => None,
                    })
                    .flat_map(cedar_policy_core::validator::types::Attributes::iter)
                    .map(|(k, v)| AttributeInfo::new(k.as_str(), v))
                    .collect();
                Some(AttributeCollection::from_attributes_vec(attrs))
            }
            CedarTypeKind::Context(ContextKind::Action(entity_uid)) => schema
                .get_action_id(entity_uid)
                .map(cedar_policy_core::validator::ValidatorActionId::context_type)
                .and_then(|ty| match ty {
                    Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => {
                        Some(AttributeCollection::from_attributes(attrs))
                    }
                    _ => None,
                }),
            CedarTypeKind::Context(ContextKind::ActionSet(set)) => {
                let attrs = set
                    .iter()
                    .filter_map(|action| schema.get_action_id(action))
                    .map(cedar_policy_core::validator::ValidatorActionId::context_type)
                    .filter_map(|ty| match ty {
                        Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => Some(attrs),
                        _ => None,
                    })
                    .flat_map(cedar_policy_core::validator::types::Attributes::iter)
                    .map(|(k, v)| AttributeInfo::new(k.as_str(), v))
                    .collect();
                Some(AttributeCollection::from_attributes_vec(attrs))
            }
            _ => None,
        }
    }

    #[must_use]
    pub(crate) fn follow_attribute_path(
        &'a self,
        initial_attrs: AttributeCollection<'a>,
    ) -> Vec<AttributeInfo<'a>> {
        // Early return if we have no schema or empty path
        let Some(schema) = self.document_context.schema() else {
            return vec![];
        };

        if self.attr_path.is_empty() {
            return vec![];
        }

        // Follow the path segments
        let Some((final_attr, path_segments)) = self.attr_path.split_last() else {
            return vec![];
        };

        // Traverse the path
        let mut current_attrs = initial_attrs;

        for segment in path_segments {
            match current_attrs.follow_attribute(segment, schema) {
                Some(next_attrs) => current_attrs = next_attrs,
                None => return vec![],
            }
        }

        // Get the final attribute
        current_attrs
            .get_by_name(final_attr)
            .into_iter()
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AttributeInfo<'a> {
    /// Name of the attribute
    name: &'a str,
    /// Type information for the attribute
    pub(crate) attr_type: &'a AttributeType,
}

impl<'a> AttributeInfo<'a> {
    /// Get the type of the attribute
    #[must_use]
    pub(crate) fn new(name: &'a str, attr_type: &'a AttributeType) -> Self {
        Self { name, attr_type }
    }
}

/// Collection of attributes with efficient access methods
#[derive(Debug, Clone)]
pub(crate) struct AttributeCollection<'a> {
    /// All attribute infos in this collection
    attributes: Vec<AttributeInfo<'a>>,
    /// Optional name-based index for faster lookups
    /// INVARIANT: all elements of vectors in this map are indexes into
    /// `attributes`, so they must be less than `attributes.len()`.
    name_index: HashMap<&'a str, Vec<usize>>,
}

impl<'a> AttributeCollection<'a> {
    /// Create a new collection from Attributes object
    pub(crate) fn from_attributes(attrs: &'a Attributes) -> Self {
        let mut attributes = Vec::new();
        let mut name_index = HashMap::new();

        for (idx, (name, attr_type)) in attrs.iter().enumerate() {
            attributes.push(AttributeInfo {
                name: name.as_str(),
                attr_type,
            });

            // We push an element into `attribute` for every iteration fo this
            // loops, so `idx` will always be a valid index into `attributes`.
            name_index
                .entry(name.as_str())
                .or_insert_with(Vec::new)
                .push(idx);
        }

        Self {
            attributes,
            name_index,
        }
    }

    /// Create from multiple entity types
    pub(crate) fn from_entity_types<I>(entity_types: I) -> Self
    where
        I: Iterator<Item = (&'a EntityType, &'a ValidatorEntityType)>,
    {
        let mut attributes = Vec::new();

        for (_, validator_et) in entity_types {
            for (name, attr_type) in validator_et.attributes().iter() {
                attributes.push(AttributeInfo {
                    name: name.as_str(),
                    attr_type,
                });
            }
        }

        Self::from_attributes_vec(attributes)
    }

    /// Create from a vector of `AttributeInfo` objects
    pub(crate) fn from_attributes_vec(attributes: Vec<AttributeInfo<'a>>) -> Self {
        let mut name_index = HashMap::new();

        for (idx, attr) in attributes.iter().enumerate() {
            // `idx` comes from `enumerate` on `attributes`, so it will always
            // be a valid index into `attributes`.
            name_index
                .entry(attr.name)
                .or_insert_with(Vec::new)
                .push(idx);
        }

        Self {
            attributes,
            name_index,
        }
    }

    /// Get all attribute infos with the given name
    #[must_use]
    pub(crate) fn get_by_name(&self, name: &str) -> Vec<&AttributeInfo<'a>> {
        self.name_index.get(name).map_or_else(Vec::new, |indices| {
            // PANIC SAFETY: From invariant on `name_index`, every stored index is a valid index into attributes.
            #[allow(clippy::indexing_slicing)]
            indices.iter().map(|&idx| &self.attributes[idx]).collect()
        })
    }

    /// Follow an attribute path through this collection
    #[must_use]
    pub(crate) fn follow_attribute(&self, attr: &str, schema: &'a ValidatorSchema) -> Option<Self> {
        let matching_attrs = self.get_by_name(attr);
        if matching_attrs.is_empty() {
            return None;
        }

        let mut next_attributes = Vec::new();

        for attr_info in matching_attrs {
            match &attr_info.attr_type.attr_type {
                Type::EntityOrRecord(EntityRecordKind::Entity(lub)) => {
                    if let Some(et) = lub.get_single_entity() {
                        if let Some(vet) = schema.get_entity_type(et) {
                            for (attr_name, attr_type) in vet.attributes().iter() {
                                next_attributes.push(AttributeInfo {
                                    name: attr_name.as_str(),
                                    attr_type,
                                });
                            }
                        }
                    }
                }
                Type::EntityOrRecord(
                    EntityRecordKind::Record { attrs, .. }
                    | EntityRecordKind::ActionEntity { attrs, .. },
                ) => {
                    for (attr_name, attr_type) in attrs.iter() {
                        next_attributes.push(AttributeInfo {
                            name: attr_name.as_str(),
                            attr_type,
                        });
                    }
                }
                _ => {} // Other types can't have attributes to follow
            }
        }

        if next_attributes.is_empty() {
            None
        } else {
            Some(AttributeCollection::from_attributes_vec(next_attributes))
        }
    }
}

/// A trait for determining the Cedar type of an expression or component.
///
/// This trait allows various Cedar language constructs to report their types,
/// which is essential for providing accurate completions, type checking,
/// and other language features in the Cedar language server.
pub(crate) trait GetType {
    /// Gets the Cedar type of this expression or component.
    fn get_type(&self, cx: &DocumentContext<'_>) -> Option<CedarTypeKind>;
    fn get_type_with_cx(&self, cx: &mut TypeInferenceContext<'_>) -> Option<CedarTypeKind> {
        self.get_type(cx.document_context)
    }
}
