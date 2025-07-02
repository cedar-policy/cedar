//! Entity Slicing

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Display;

use crate::entities::err::EntitiesError;
use crate::entities::Dereference;
use crate::{
    ast::{Entity, EntityUID, Literal, PartialValue, Request, Value, ValueKind},
    entities::Entities,
};
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

use crate::validator::entity_manifest::loader::{
    load_entities, AccessTrie, AncestorsRequest, EntityAnswer, EntityLoader, EntityRequest,
};
use crate::validator::entity_manifest::{
    AccessDag, AccessPath, AccessPathVariant, AccessPaths, EntityManifest, PartialRequestError,
};

/// Error when expressions are partial during entity
/// slicing.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("entity slicing requires fully concrete policies. Got a policy with an unknown expression")]
pub struct PartialExpressionError {}

impl Diagnostic for PartialExpressionError {}

/// Error when expressions are partial during entity
/// slicing.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("entity slicing requires fully concrete policies. Got a policy with an unknown expression")]
pub struct IncompatibleEntityManifestError {
    non_record_entity_value: Value,
}

impl Diagnostic for IncompatibleEntityManifestError {
    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(format!(
            "expected entity or record during entity loading. Got value: {}",
            self.non_record_entity_value
        )))
    }
}

/// Error when entities are partial during entity manifest computation.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("entity slicing requires fully concrete entities. Got a partial entity")]
pub struct PartialEntityError {}

impl Diagnostic for PartialEntityError {}

/// Error when an entity loader returns the wrong number of entities.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("entity loader returned the wrong number of entities. Expected {expected} but got {got} entities")]
pub struct WrongNumberOfEntitiesError {
    pub(crate) expected: usize,
    pub(crate) got: usize,
}

/// Error when an entity loader returns a value missing an attribute.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("entity loader produced entity with value {value}. Expected value to be a record with attribute {attribute}")]
pub struct NonRecordValueError {
    pub(crate) value: Value,
    pub(crate) attribute: SmolStr,
}

/// Context was partial during entity loading
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("entity loader produced a partial context. Expected a concrete value")]
pub struct PartialContextError {}

/// Error when an entity is missing a required field
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("entity {entity} is missing required field {field}")]
pub struct EntityFieldMissingError {
    pub(crate) entity: Entity,
    pub(crate) field: SmolStr,
}

impl Diagnostic for EntityFieldMissingError {}

/// Error when a required entity is missing
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("required entity {entity_id} was not found")]
pub struct EntityMissingError {
    pub(crate) entity_id: EntityUID,
}

impl Diagnostic for EntityMissingError {}

/// Error when a record is missing a required field
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("record is missing required field {field}")]
pub struct RecordFieldMissingError {
    pub(crate) field: SmolStr,
}

impl Diagnostic for RecordFieldMissingError {}

/// Error when an entity type was expected but a different value was found
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("expected entity type but found {found_value}")]
pub struct ExpectedEntityTypeError {
    pub(crate) found_value: Value,
}

impl Diagnostic for ExpectedEntityTypeError {
    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(format!(
            "expected an entity type but found value: {}",
            self.found_value
        )))
    }
}

/// An error generated by entity slicing.
/// TODO make public API wrapper
#[derive(Debug, Error, Diagnostic)]
pub enum EntitySliceError {
    /// An entities error was encountered
    #[error(transparent)]
    #[diagnostic(transparent)]
    Entities(#[from] EntitiesError),

    /// The request was partial
    #[error(transparent)]
    PartialRequest(#[from] PartialRequestError),
    /// A policy was partial
    #[error(transparent)]
    PartialExpression(#[from] PartialExpressionError),

    /// During entity loading, attempted to load from
    /// a type without fields.
    #[error(transparent)]
    IncompatibleEntityManifest(#[from] IncompatibleEntityManifestError),

    /// Found a partial entity during entity loading.
    #[error(transparent)]
    PartialEntity(#[from] PartialEntityError),

    /// The entity loader returned a partial context.
    #[error(transparent)]
    PartialContext(#[from] PartialContextError),

    /// The entity loader produced the wrong number of entities.
    #[error(transparent)]
    WrongNumberOfEntities(#[from] WrongNumberOfEntitiesError),

    /// During loading, a required field wasn't provided
    #[error(transparent)]
    EntityFieldMissing(#[from] EntityFieldMissingError),

    /// During loading, a required entity was missing
    #[error(transparent)]
    EntityMissing(#[from] EntityMissingError),

    /// During loading, a record was missing a required field
    #[error(transparent)]
    RecordFieldMissing(#[from] RecordFieldMissingError),

    /// While loading entities, expected an entity type
    /// but encountered a different value.
    /// Could be an out-of-date manifest after a schema change.
    #[error(transparent)]
    ExpectedEntityType(#[from] ExpectedEntityTypeError),
}

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
    fn load_entities(
        &mut self,
        to_load: &[EntityRequest],
        store: AccessDag,
    ) -> Result<Vec<EntityAnswer>, EntitySliceError> {
        let mut res = vec![];
        for request in to_load {
            if let Dereference::Data(entity) = self.entities.entity(&request.entity_id) {
                // filter down the entity fields to those requested
                res.push(Some(request.access_trie.slice_entity(entity)?));
            } else {
                res.push(None);
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

impl AccessTrie {
    /// Given an entities store, an entity id, and a resulting store
    /// Slice the entities and put them in the resulting store.
    fn slice_entity(&self, entity: &Entity) -> Result<Entity, EntitySliceError> {
        let mut new_entity = HashMap::<SmolStr, PartialValue>::new();
        for (field, slice) in &self.fields {
            // only slice when field is available
            if let Some(pval) = entity.get(field).cloned() {
                let PartialValue::Value(val) = pval else {
                    return Err(PartialEntityError {}.into());
                };
                let sliced = slice.slice_val(&val)?;

                new_entity.insert(field.clone(), PartialValue::Value(sliced));
            }
        }

        Ok(Entity::new_with_attr_partial_value(
            entity.uid().clone(),
            new_entity,
            Default::default(),
            Default::default(),
            [], // TODO: entity slicing does not yet support tags
        ))
    }

    fn slice_val(&self, val: &Value) -> Result<Value, EntitySliceError> {
        Ok(match val.value_kind() {
            ValueKind::Lit(Literal::EntityUID(_)) => {
                // entities shouldn't need to be dereferenced
                assert!(self.fields.is_empty());
                val.clone()
            }
            ValueKind::Set(_) | ValueKind::ExtensionValue(_) | ValueKind::Lit(_) => {
                if !self.fields.is_empty() {
                    return Err(IncompatibleEntityManifestError {
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

impl AccessPath {
    /// Compute the value for this access path using the provided entities map.
    /// This function can dereference entities using the entity_map.
    pub fn compute_value(
        &self,
        entities_map: &HashMap<EntityUID, Entity>,
        store: &AccessDag,
        request: &Request,
    ) -> Result<Value, EntitySliceError> {
        // Get the variant for this path
        let variant = self
            .get_variant(store)
            .map_err(|_| EntitySliceError::PartialRequest(PartialRequestError {}))?;

        match variant {
            // For literal entity UIDs, return the entity UID as a value
            AccessPathVariant::Literal(euid) => Ok(Value::from(Literal::EntityUID(
                std::sync::Arc::new(euid.clone()),
            ))),

            // For string literals, return the string value
            AccessPathVariant::String(s) => Ok(Value::from(Literal::String(s.clone()))),

            // For attribute access, first compute the value of the base entity/record
            // then extract the attribute from it
            AccessPathVariant::Attribute { of, attr } => {
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
                    _ => Err(IncompatibleEntityManifestError {
                        non_record_entity_value: base_value,
                    }
                    .into()),
                }
            }

            // For tag access, first compute the value of the base entity
            // then extract the tag from it
            AccessPathVariant::Tag { of, tag } => {
                // First, compute the value of the base entity
                let base_value = of.compute_value(entities_map, store, request)?;

                match base_value.value_kind() {
                    // If it's an entity UID, look up the entity and get the tag
                    ValueKind::Lit(Literal::EntityUID(euid)) => {
                        if let Some(entity) = entities_map.get(&(**euid)) {
                            // Compute the tag name
                            let tag_value = tag.compute_value(entities_map, store, request)?;

                            if let ValueKind::Lit(Literal::String(tag_name)) =
                                tag_value.value_kind()
                            {
                                // TODO: Implement tag access once entity slicing supports tags
                                // For now, return an error as tags are not yet supported
                                Err(EntitySliceError::IncompatibleEntityManifest(
                                    IncompatibleEntityManifestError {
                                        non_record_entity_value: base_value,
                                    },
                                ))
                            } else {
                                // Tag name is not a string
                                Err(IncompatibleEntityManifestError {
                                    non_record_entity_value: tag_value,
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
                    _ => Err(IncompatibleEntityManifestError {
                        non_record_entity_value: base_value,
                    }
                    .into()),
                }
            }

            AccessPathVariant::Ancestor { of, ancestor } => {
                // PANIC SAFETY: Ancestor nodes are not computed by the loader.
                panic!("Attempting to compute value for ancestor node");
            }

            AccessPathVariant::Var(var) => {
                // Get the value from the request based on the variable
                match var {
                    crate::ast::Var::Principal => {
                        if let Some(principal) = request.principal().uid() {
                            Ok(Value::from(Literal::EntityUID(std::sync::Arc::new(
                                principal.clone(),
                            ))))
                        } else {
                            Err(EntitySliceError::PartialRequest(PartialRequestError {}))
                        }
                    }
                    crate::ast::Var::Action => {
                        if let Some(action) = request.action().uid() {
                            Ok(Value::from(Literal::EntityUID(std::sync::Arc::new(
                                action.clone(),
                            ))))
                        } else {
                            Err(EntitySliceError::PartialRequest(PartialRequestError {}))
                        }
                    }
                    crate::ast::Var::Resource => {
                        if let Some(resource) = request.resource().uid() {
                            Ok(Value::from(Literal::EntityUID(std::sync::Arc::new(
                                resource.clone(),
                            ))))
                        } else {
                            Err(EntitySliceError::PartialRequest(PartialRequestError {}))
                        }
                    }
                    crate::ast::Var::Context => {
                        // Context variables are not supported in entity slicing
                        Err(EntitySliceError::PartialContext(PartialContextError {}))
                    }
                }
            }
        }
    }
}
