use super::SchemaType;
use crate::ast::{Entity, EntityType, EntityUID};
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Trait for `Schema`s that can inform the parsing of Entity JSON data
pub trait Schema {
    /// Type returned by `entity_type()`. Must implement the `EntityTypeDescription` trait
    type EntityTypeDescription: EntityTypeDescription;

    /// Get an `EntityTypeDescription` for the given entity type, or `None` if that
    /// entity type is not declared in the schema (in which case entities of that
    /// type should not appear in the JSON data).
    fn entity_type(&self, entity_type: &EntityType) -> Option<Self::EntityTypeDescription>;

    /// Get the entity information for the given action, or `None` if that
    /// action is not declared in the schema (in which case this action should
    /// not appear in the JSON data).
    fn action(&self, action: &EntityUID) -> Option<Arc<Entity>>;
}

/// Simple type that implements `Schema` by expecting no entities to exist at all
#[derive(Debug, Clone)]
pub struct NoEntitiesSchema;
impl Schema for NoEntitiesSchema {
    type EntityTypeDescription = NullEntityTypeDescription;
    fn entity_type(&self, _entity_type: &EntityType) -> Option<NullEntityTypeDescription> {
        None
    }
    fn action(&self, _action: &EntityUID) -> Option<Arc<Entity>> {
        None
    }
}

/// Simple type that implements `Schema` by allowing entities of all types to
/// exist, and allowing all actions to exist, but expecting no attributes or
/// parents on any entity (action or otherwise)
#[derive(Debug, Clone)]
pub struct AllEntitiesNoAttrsSchema;
impl Schema for AllEntitiesNoAttrsSchema {
    type EntityTypeDescription = NullEntityTypeDescription;
    fn entity_type(&self, entity_type: &EntityType) -> Option<NullEntityTypeDescription> {
        Some(NullEntityTypeDescription {
            ty: entity_type.clone(),
        })
    }
    fn action(&self, action: &EntityUID) -> Option<Arc<Entity>> {
        Some(Arc::new(Entity::new(
            action.clone(),
            HashMap::new(),
            HashSet::new(),
        )))
    }
}

/// Trait for a schema's description of an individual entity type
pub trait EntityTypeDescription {
    /// Get the `EntityType` this `EntityTypeDescription` is describing
    fn entity_type(&self) -> EntityType;

    /// Do entities of this type have the given attribute, and if so, what type?
    ///
    /// Returning `None` indicates that attribute should not exist.
    fn attr_type(&self, attr: &str) -> Option<SchemaType>;

    /// Get the names of all the required attributes for this entity type.
    fn required_attrs<'s>(&'s self) -> Box<dyn Iterator<Item = SmolStr> + 's>;

    /// Get the entity types which are allowed to be parents of this entity type.
    fn allowed_parent_types(&self) -> Arc<HashSet<EntityType>>;
}

/// Simple type that implements `EntityTypeDescription` by expecting no
/// attributes to exist
#[derive(Debug, Clone)]
pub struct NullEntityTypeDescription {
    /// null description for this type
    ty: EntityType,
}
impl EntityTypeDescription for NullEntityTypeDescription {
    fn entity_type(&self) -> EntityType {
        self.ty.clone()
    }
    fn attr_type(&self, _attr: &str) -> Option<SchemaType> {
        None
    }
    fn required_attrs(&self) -> Box<dyn Iterator<Item = SmolStr>> {
        Box::new(std::iter::empty())
    }
    fn allowed_parent_types(&self) -> Arc<HashSet<EntityType>> {
        Arc::new(HashSet::new())
    }
}
