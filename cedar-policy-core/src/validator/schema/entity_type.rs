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

//! This module contains the definition of `ValidatorEntityType`

use nonempty::NonEmpty;
use serde::Serialize;
use smol_str::SmolStr;
use std::collections::HashSet;

use crate::{ast::EntityType, parser::Loc, transitive_closure::TCNode};

use crate::validator::types::{AttributeType, Attributes, OpenTag, Type};

/// Contains entity type information for use by the validator. The contents of
/// the struct are the same as the schema entity type structure, but the
/// `member_of` relation is reversed to instead be `descendants`.
#[derive(Clone, Debug, Serialize)]
pub struct ValidatorEntityType {
    /// The name of the entity type.
    pub(crate) name: EntityType,

    /// The set of entity types that can be members of this entity type. When
    /// this structure is initially constructed, the field will contain direct
    /// children, but it will be updated to contain the closure of all
    /// descendants before it is used in any validation.
    pub descendants: HashSet<EntityType>,

    /// The kind of entity type: enumerated and standard
    pub kind: ValidatorEntityTypeKind,

    /// The attributes associated with this entity.
    ///
    /// For enumerated entities, this is always empty.
    pub(crate) attributes: Attributes,

    /// Source location - if available
    #[serde(skip)]
    pub loc: Option<Loc>,
}

/// The kind of validator entity types.
///
/// It can either be a standard (non-enum) entity type, or
/// an enumerated entity type
#[derive(Clone, Debug, Serialize)]
pub enum ValidatorEntityTypeKind {
    /// Standard, aka non-enum
    Standard(StandardValidatorEntityType),
    /// Enumerated
    Enum(NonEmpty<SmolStr>),
}

#[derive(Clone, Debug, Serialize)]
pub struct StandardValidatorEntityType {
    /// Indicates that this entity type may have additional attributes
    /// other than the declared attributes that may be accessed under partial
    /// schema validation. We do not know if they are present, and do not know
    /// their type when they are present. Attempting to access an undeclared
    /// attribute under standard validation is an error regardless of this flag.
    pub(crate) open_attributes: OpenTag,

    /// Tag type for this entity type. `None` indicates that entities of this
    /// type are not allowed to have tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tags: Option<Type>,
}

impl ValidatorEntityType {
    /// Construct a new standard `ValidatorEntityType`.
    ///
    /// This constructor assumes that `descendants` has TC already computed.
    /// That is, caller is responsible for TC.
    pub fn new_standard(
        name: EntityType,
        descendants: impl IntoIterator<Item = EntityType>,
        attributes: Attributes,
        open_attributes: OpenTag,
        tags: Option<Type>,
        loc: Option<Loc>,
    ) -> Self {
        Self {
            name,
            descendants: descendants.into_iter().collect(),
            attributes,
            kind: ValidatorEntityTypeKind::Standard(StandardValidatorEntityType {
                open_attributes,
                tags,
            }),
            loc,
        }
    }

    /// Construct a new enumerated `ValidatorEntityType`.
    ///
    /// This constructor assumes that `descendants` has TC already computed.
    /// That is, caller is responsible for TC.
    pub fn new_enum(
        name: EntityType,
        descendants: impl IntoIterator<Item = EntityType>,
        values: NonEmpty<SmolStr>,
        loc: Option<Loc>,
    ) -> Self {
        Self {
            name,
            descendants: descendants.into_iter().collect(),
            attributes: Attributes::with_attributes([]),
            kind: ValidatorEntityTypeKind::Enum(values),
            loc,
        }
    }

    /// The name of the entity type
    pub fn name(&self) -> &EntityType {
        &self.name
    }

    /// Attribute types for this entity.
    ///
    /// For enumerated entity types, this will always be empty.
    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    /// Get the type of the attribute with the given name, if it exists
    pub fn attr(&self, attr: &str) -> Option<&AttributeType> {
        self.attributes.get_attr(attr)
    }

    /// Return `true` if this entity type has an [`EntityType`] declared as a
    /// possible descendant in the schema.
    pub fn has_descendant_entity_type(&self, ety: &EntityType) -> bool {
        self.descendants.contains(ety)
    }

    /// Return the [`OpenTag`] which indicates whether this entity type may have
    /// additional attributes other than the declared attributes.
    /// This is used for partial schema validation. Attempting to access an
    /// undeclared attribute under standard validation is an error regardless of
    /// the [`OpenTag`] here.
    pub fn open_attributes(&self) -> OpenTag {
        match &self.kind {
            ValidatorEntityTypeKind::Enum(_) => OpenTag::ClosedAttributes,
            ValidatorEntityTypeKind::Standard(ty) => ty.open_attributes,
        }
    }

    /// Get the type of tags on this entity. `None` indicates that entities of
    /// this type are not allowed to have tags.
    pub fn tag_type(&self) -> Option<&Type> {
        match &self.kind {
            ValidatorEntityTypeKind::Enum(_) => None,
            ValidatorEntityTypeKind::Standard(ty) => ty.tag_type(),
        }
    }
}

impl StandardValidatorEntityType {
    /// Get the type of tags on this entity. `None` indicates that entities of
    /// this type are not allowed to have tags.
    pub fn tag_type(&self) -> Option<&Type> {
        self.tags.as_ref()
    }
}

impl TCNode<EntityType> for ValidatorEntityType {
    fn get_key(&self) -> EntityType {
        self.name.clone()
    }

    fn add_edge_to(&mut self, k: EntityType) {
        self.descendants.insert(k);
    }

    fn out_edges(&self) -> Box<dyn Iterator<Item = &EntityType> + '_> {
        Box::new(self.descendants.iter())
    }

    fn has_edge_to(&self, e: &EntityType) -> bool {
        self.descendants.contains(e)
    }

    // No-op as schema based TCs do not update
    fn reset_edges(&mut self) {}
}
