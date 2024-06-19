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

use super::SchemaType;
use crate::ast::{Entity, EntityType, EntityUID, Id, Name};
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Trait for `Schema`s that can inform the parsing of Entity JSON data
pub trait Schema {
    /// Type returned by `entity_type()`. Must implement the `EntityTypeDescription` trait
    type EntityTypeDescription: EntityTypeDescription;

    /// Type returned by `action_entities()`
    type ActionEntityIterator: IntoIterator<Item = Arc<Entity>>;

    /// Get an `EntityTypeDescription` for the given entity type, or `None` if that
    /// entity type is not declared in the schema (in which case entities of that
    /// type should not appear in the JSON data).
    fn entity_type(&self, entity_type: &EntityType) -> Option<Self::EntityTypeDescription>;

    /// Get the entity information for the given action, or `None` if that
    /// action is not declared in the schema (in which case this action should
    /// not appear in the JSON data).
    fn action(&self, action: &EntityUID) -> Option<Arc<Entity>>;

    /// Get the names of all entity types declared in the schema that have the
    /// given basename (in the sense of `Name::basename()`).
    fn entity_types_with_basename<'a>(
        &'a self,
        basename: &'a Id,
    ) -> Box<dyn Iterator<Item = EntityType> + 'a>;

    /// Get all the actions declared in the schema
    fn action_entities(&self) -> Self::ActionEntityIterator;
}

/// Simple type that implements `Schema` by expecting no entities to exist at all
#[derive(Debug, Clone)]
pub struct NoEntitiesSchema;
impl Schema for NoEntitiesSchema {
    type EntityTypeDescription = NullEntityTypeDescription;
    type ActionEntityIterator = std::iter::Empty<Arc<Entity>>;
    fn entity_type(&self, _entity_type: &EntityType) -> Option<NullEntityTypeDescription> {
        None
    }
    fn action(&self, _action: &EntityUID) -> Option<Arc<Entity>> {
        None
    }
    fn entity_types_with_basename<'a>(
        &'a self,
        _basename: &'a Id,
    ) -> Box<dyn Iterator<Item = EntityType> + 'a> {
        Box::new(std::iter::empty())
    }
    fn action_entities(&self) -> std::iter::Empty<Arc<Entity>> {
        std::iter::empty()
    }
}

/// Simple type that implements `Schema` by allowing entities of all types to
/// exist, and allowing all actions to exist, but expecting no attributes or
/// parents on any entity (action or otherwise).
///
/// This type returns an empty iterator for `action_entities()`, which is kind
/// of inconsistent with its behavior on `action()`. But it works out -- the
/// result is that, in `EntityJsonParser`, all actions encountered in JSON data
/// are allowed to exist without error, but no additional actions from the
/// schema are added.
#[derive(Debug, Clone)]
pub struct AllEntitiesNoAttrsSchema;
impl Schema for AllEntitiesNoAttrsSchema {
    type EntityTypeDescription = NullEntityTypeDescription;
    type ActionEntityIterator = std::iter::Empty<Arc<Entity>>;
    fn entity_type(&self, entity_type: &EntityType) -> Option<NullEntityTypeDescription> {
        Some(NullEntityTypeDescription {
            ty: entity_type.clone(),
        })
    }
    fn action(&self, action: &EntityUID) -> Option<Arc<Entity>> {
        Some(Arc::new(Entity::new_with_attr_partial_value(
            action.clone(),
            HashMap::new(),
            HashSet::new(),
        )))
    }
    fn entity_types_with_basename<'a>(
        &'a self,
        basename: &'a Id,
    ) -> Box<dyn Iterator<Item = EntityType> + 'a> {
        Box::new(std::iter::once(EntityType::from(Name::unqualified_name(
            basename.clone(),
        ))))
    }
    fn action_entities(&self) -> std::iter::Empty<Arc<Entity>> {
        std::iter::empty()
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

    /// May entities with this type have attributes other than those specified
    /// in the schema
    fn open_attributes(&self) -> bool;
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
    fn open_attributes(&self) -> bool {
        false
    }
}
