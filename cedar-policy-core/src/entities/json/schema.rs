use super::SchemaType;
use crate::ast::EntityType;
use smol_str::SmolStr;
use std::collections::HashSet;

/// Trait for `Schema`s that can inform the parsing of Entity JSON data
pub trait Schema {
    /// Do entities of the given type have the given attribute, and if so, what type?
    ///
    /// Returning `None` indicates that attribute should not exist.
    fn attr_type(&self, entity_type: &EntityType, attr: &str) -> Option<SchemaType>;

    /// Get the names of all the required attributes for the given entity type.
    fn required_attrs<'s>(
        &'s self,
        entity_type: &EntityType,
    ) -> Box<dyn Iterator<Item = SmolStr> + 's>;

    /// Get the entity types which are allowed to be parents of the given entity type.
    fn allowed_parent_types<'s>(&'s self, entity_type: &EntityType) -> HashSet<EntityType>;
}

/// Simple type that implements `Schema` by expecting no attributes or parents to exist
#[derive(Debug, Clone)]
pub struct NullSchema;
impl Schema for NullSchema {
    fn attr_type(&self, _entity_type: &EntityType, _attr: &str) -> Option<SchemaType> {
        None
    }
    fn required_attrs(&self, _entity_type: &EntityType) -> Box<dyn Iterator<Item = SmolStr>> {
        Box::new(std::iter::empty())
    }
    fn allowed_parent_types(&self, _entity_type: &EntityType) -> HashSet<EntityType> {
        HashSet::new()
    }
}
