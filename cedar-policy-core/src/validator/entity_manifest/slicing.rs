//! Entity Slicing

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::ast::Var;
use crate::entities::Dereference;
use crate::validator::entity_manifest::manifest_helpers::AccessTrie;
use crate::{
    ast::{Entity, EntityUID, Literal, PartialValue, Request, Value, ValueKind},
    entities::Entities,
};
use smol_str::SmolStr;

// Import errors directly
use crate::validator::entity_manifest::err::{
    EntityFieldMissingError, EntityMissingError, EntitySliceError, EntityTagMissingError,
    ExpectedEntityError, ExpectedEntityOrRecordError, ExpectedStringError, PartialContextError,
    PartialEntityError, PartialRequestError, RecordFieldMissingError,
};
use crate::validator::entity_manifest::loader::{
    load_entities, AncestorsRequest, EntityLoader, EntityRequest, EntityRequests,
};
use crate::validator::entity_manifest::{AccessDag, AccessTerm, AccessTermVariant, EntityManifest};

impl EntityManifest {
    /// Use this entity manifest to
    /// find an entity slice using an existing [`Entities`] store.
    pub fn slice_entities(
        &self,
        entities: &Entities,
        request: &Request,
    ) -> Result<Entities, EntitySliceError> {
        let mut slicer = EntitySlicer { entities };
        load_entities(self, request, &mut slicer)
    }
}

struct EntitySlicer<'a> {
    entities: &'a Entities,
}

impl EntityLoader for EntitySlicer<'_> {
    fn load_entities(&mut self, to_load: &EntityRequests) -> Result<Vec<Entity>, EntitySliceError> {
        let mut res = vec![];
        for request in to_load {
            if let Dereference::Data(entity) = self.entities.entity(&request.entity_id) {
                // filter down the entity fields to those requested
                res.push(request.slice_entity(entity)?);
            }
        }

        Ok(res)
    }

    fn load_ancestors(
        &mut self,
        entities: &[AncestorsRequest],
    ) -> Result<Vec<HashSet<EntityUID>>, EntitySliceError> {
        let mut res = vec![];

        for request in entities {
            if let Dereference::Data(entity) = self.entities.entity(&request.entity_id) {
                let mut ancestors = HashSet::new();

                for required_ancestor in &request.ancestors {
                    if entity.is_descendant_of(required_ancestor) {
                        ancestors.insert(required_ancestor.clone());
                    }
                }

                res.push(ancestors);
            } else {
                // if the entity isn't there, we don't need any ancestors
                res.push(HashSet::new());
            }
        }

        Ok(res)
    }
}

impl EntityRequest {
    /// Slice the entity using the request precisely
    fn slice_entity(&self, entity: &Entity) -> Result<Entity, EntitySliceError> {
        let mut new_entity = HashMap::<SmolStr, PartialValue>::new();
        for (field, slice) in &self.access_trie.fields {
            // only slice when field is available
            if let Some(pval) = entity.get(field).cloned() {
                let PartialValue::Value(val) = pval else {
                    return Err(PartialEntityError {}.into());
                };
                let sliced = slice.slice_val(&val)?;

                new_entity.insert(field.clone(), PartialValue::Value(sliced));
            }
        }

        let mut tags = HashMap::<SmolStr, PartialValue>::new();

        for (tag, slice) in &self.tags {
            // only slice when tag is available
            if let Some(pval) = entity.get_tag(tag).cloned() {
                let PartialValue::Value(val) = pval else {
                    return Err(PartialEntityError {}.into());
                };
                let sliced = slice.slice_val(&val)?;
                tags.insert(tag.clone(), PartialValue::Value(sliced));
            }
        }

        Ok(Entity::new_with_attr_partial_value(
            entity.uid().clone(),
            new_entity,
            Default::default(),
            Default::default(),
            tags,
        ))
    }
}

impl AccessTrie {
    fn slice_val(&self, val: &Value) -> Result<Value, EntitySliceError> {
        Ok(match val.value_kind() {
            ValueKind::Lit(Literal::EntityUID(_)) => {
                // entities shouldn't need to be dereferenced
                assert!(self.fields.is_empty());
                val.clone()
            }
            ValueKind::Set(_) | ValueKind::ExtensionValue(_) | ValueKind::Lit(_) => {
                if !self.fields.is_empty() {
                    return Err(ExpectedEntityOrRecordError {
                        non_record_entity_value: val.clone(),
                    }
                    .into());
                }

                val.clone()
            }
            ValueKind::Record(record) => {
                let mut new_map = BTreeMap::<SmolStr, Value>::new();
                for (field, slice) in &self.fields {
                    // only slice when field is available
                    if let Some(v) = record.get(field) {
                        new_map.insert(field.clone(), slice.slice_val(v)?);
                    }
                }

                Value::new(ValueKind::record(new_map), None)
            }
        })
    }
}

impl AccessTerm {
    /// Compute the value for this access term using the provided entities map.
    /// This function can dereference entities using the `entity_map`.
    pub(crate) fn compute_value(
        self,
        entities_map: &HashMap<EntityUID, Entity>,
        store: &AccessDag,
        request: &Request,
    ) -> Result<Value, EntitySliceError> {
        // Get the variant for this term
        let variant = self
            .get_variant(store)
            .map_err(|_| EntitySliceError::PartialRequest(PartialRequestError {}))?;

        match variant {
            // For literal entity UIDs, return the entity UID as a value
            AccessTermVariant::Literal(euid) => Ok(Value::from(Literal::EntityUID(
                std::sync::Arc::new(euid.clone()),
            ))),

            // For string literals, return the string value
            AccessTermVariant::String(s) => Ok(Value::from(Literal::String(s.clone()))),

            // For attribute access, first compute the value of the base entity/record
            // then extract the attribute from it
            AccessTermVariant::Attribute { of, attr } => {
                // First, compute the value of the base entity/record
                let base_value = of.compute_value(entities_map, store, request)?;

                match base_value.value_kind() {
                    // If it's an entity UID, look up the entity and get the attribute
                    ValueKind::Lit(Literal::EntityUID(euid)) => {
                        if let Some(entity) = entities_map.get(&(**euid)) {
                            if let Some(PartialValue::Value(attr_value)) = entity.get(attr) {
                                Ok(attr_value.clone())
                            } else {
                                // Attribute not found, return an appropriate error
                                Err(EntityFieldMissingError {
                                    entity: entity.clone(),
                                    field: attr.clone(),
                                }
                                .into())
                            }
                        } else {
                            // Entity not found, return an appropriate error
                            Err(EntityMissingError {
                                entity_id: (**euid).clone(),
                            }
                            .into())
                        }
                    }

                    // If it's a record, get the attribute directly
                    ValueKind::Record(record) => {
                        if let Some(attr_value) = record.get(attr) {
                            Ok(attr_value.clone())
                        } else {
                            // Attribute not found, return an appropriate error
                            Err(RecordFieldMissingError {
                                field: attr.clone(),
                            }
                            .into())
                        }
                    }

                    // Other value types don't have attributes
                    _ => Err(ExpectedEntityOrRecordError {
                        non_record_entity_value: base_value,
                    }
                    .into()),
                }
            }

            // For tag access, first compute the value of the base entity
            // then extract the tag from it
            AccessTermVariant::Tag { of, tag } => {
                // First, compute the value of the base entity
                let base_value = of.compute_value(entities_map, store, request)?;

                match base_value.value_kind() {
                    // If it's an entity UID, look up the entity and get the tag
                    ValueKind::Lit(Literal::EntityUID(euid)) => {
                        if let Some(_entity) = entities_map.get(&(**euid)) {
                            // Compute the tag name
                            let tag_value = tag.compute_value(entities_map, store, request)?;

                            if let ValueKind::Lit(Literal::String(_tag_name)) =
                                tag_value.value_kind()
                            {
                                // get the tag from the entity
                                if let Some(PartialValue::Value(tag_value)) =
                                    _entity.get_tag(_tag_name)
                                {
                                    Ok(tag_value.clone())
                                } else {
                                    // Tag not found, return an appropriate error
                                    Err(EntityTagMissingError {
                                        entity: _entity.clone(),
                                        tag: _tag_name.clone(),
                                    }
                                    .into())
                                }
                            } else {
                                // Tag name is not a string
                                Err(ExpectedStringError {
                                    found_value: tag_value,
                                }
                                .into())
                            }
                        } else {
                            // Entity not found, return an appropriate error
                            Err(EntityMissingError {
                                entity_id: (**euid).clone(),
                            }
                            .into())
                        }
                    }

                    // Other value types don't have tags
                    _ => Err(ExpectedEntityError {
                        found_value: base_value,
                    }
                    .into()),
                }
            }

            // PANIC SAFETY: `compute_value` is only called on child access terms, but nothing has an ancestor node as a child.
            #[allow(clippy::panic)]
            AccessTermVariant::Ancestor { of: _, ancestor: _ } => {
                panic!("Ill-typed entity manifest: Tried to compute value of ancestor access term");
            }

            AccessTermVariant::Var(var) => {
                // Get the value from the request based on the variable
                match var {
                    Var::Principal => {
                        if let Some(principal) = request.principal().uid() {
                            Ok(Value::from(Literal::EntityUID(std::sync::Arc::new(
                                principal.clone(),
                            ))))
                        } else {
                            Err(EntitySliceError::PartialRequest(PartialRequestError {}))
                        }
                    }
                    Var::Action => {
                        if let Some(action) = request.action().uid() {
                            Ok(Value::from(Literal::EntityUID(std::sync::Arc::new(
                                action.clone(),
                            ))))
                        } else {
                            Err(EntitySliceError::PartialRequest(PartialRequestError {}))
                        }
                    }
                    Var::Resource => {
                        if let Some(resource) = request.resource().uid() {
                            Ok(Value::from(Literal::EntityUID(std::sync::Arc::new(
                                resource.clone(),
                            ))))
                        } else {
                            Err(EntitySliceError::PartialRequest(PartialRequestError {}))
                        }
                    }
                    Var::Context => {
                        // Context variables are not supported in entity slicing
                        Err(EntitySliceError::PartialContext(PartialContextError {}))
                    }
                }
            }
        }
    }
}
