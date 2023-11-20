//! This module contains the definition of `ValidatorEntityType`

use serde::Serialize;
use smol_str::SmolStr;
use std::collections::HashSet;

use cedar_policy_core::{
    ast::{EntityType, Name},
    transitive_closure::TCNode,
};

use crate::types::{AttributeType, Attributes, OpenTag};

/// Contains entity type information for use by the validator. The contents of
/// the struct are the same as the schema entity type structure, but the
/// `member_of` relation is reversed to instead be `descendants`.
#[derive(Clone, Debug, Serialize)]
pub struct ValidatorEntityType {
    /// The name of the entity type.
    pub(crate) name: Name,

    /// The set of entity types that can be members of this entity type. When
    /// this structure is initially constructed, the field will contain direct
    /// children, but it will be updated to contain the closure of all
    /// descendants before it is used in any validation.
    pub descendants: HashSet<Name>,

    /// The attributes associated with this entity. Keys are the attribute
    /// identifiers while the values are the type of the attribute.
    pub(crate) attributes: Attributes,

    /// Indicates that this entity type may have additional attributes
    /// other than the declared attributes that may be accessed under partial
    /// schema validation. We do not know if they are present, and do not know
    /// their type when they are present. Attempting to access an undeclared
    /// attribute under standard validation is an error regardless of this flag.
    pub(crate) open_attributes: OpenTag,
}

impl ValidatorEntityType {
    /// Get the type of the attribute with the given name, if it exists
    pub fn attr(&self, attr: &str) -> Option<&AttributeType> {
        self.attributes.get_attr(attr)
    }

    /// An iterator over the attributes of this entity
    pub fn attributes(&self) -> impl Iterator<Item = (&SmolStr, &AttributeType)> {
        self.attributes.iter()
    }

    /// Return `true` if this entity type has an `EntityType` declared as a
    /// possible descendant in the schema. This takes an `EntityType` rather
    /// than a `Name`, It's not possible to declare the unspecified entity type
    /// is a descendant of an entity type in the schema, so we can return false
    /// in the unspecified case.
    pub fn has_descendant_entity_type(&self, ety: &EntityType) -> bool {
        match ety {
            EntityType::Specified(ety) => self.descendants.contains(ety),
            EntityType::Unspecified => false,
        }
    }
}

impl TCNode<Name> for ValidatorEntityType {
    fn get_key(&self) -> Name {
        self.name.clone()
    }

    fn add_edge_to(&mut self, k: Name) {
        self.descendants.insert(k);
    }

    fn out_edges(&self) -> Box<dyn Iterator<Item = &Name> + '_> {
        Box::new(self.descendants.iter())
    }

    fn has_edge_to(&self, e: &Name) -> bool {
        self.descendants.contains(e)
    }
}
