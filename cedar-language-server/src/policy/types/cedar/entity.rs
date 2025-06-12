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

use std::fmt::Display;
use std::{collections::BTreeSet, hash::Hash, sync::Arc};

use cedar_policy_core::ast::EntityType;
use cedar_policy_core::validator::ValidatorSchema;
use itertools::Itertools;

use super::{Attribute, CedarTypeKind};

/// Represents the type of a principal or resource entity in Cedar policies.
///
/// This enum captures the various ways entity types can be constrained or specified
/// in policies based on the principal/resource declarations and action constraints.
/// It helps the language server determine valid attributes, entity types, and other
/// completions when working with principal and resource variables.
///
/// In Cedar policies, entity types appear in declarations like:
/// ```cedar
/// permit(principal == User::"alice", action, resource);
/// permit(principal in Group::"admins", action, resource);
/// permit(principal, action == Action::"get", resource);
/// ```
///
/// The specific variant is determined by:
/// 1. The policy's principal/resource constraint (e.g., equality, membership, or type constraint)
/// 2. The action constraint, which may further restrict possible principal or resource types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum EntityTypeKind {
    /// Represents a single concrete entity type.
    ///
    /// This is used when the entity is constrained to a specific type, such as
    /// with an `is` constraint (`principal is User`) or when the action constraint
    /// uniquely determines the entity type.
    Concrete(Arc<EntityType>),
    /// Represents a set of possible entity types.
    ///
    /// This is used when the entity could be one of several types, such as
    /// with certain action constraints that allow multiple principal or resource types.
    Set(BTreeSet<Arc<EntityType>>),
    /// Represents any principal entity type.
    ///
    /// This is specifically used for unconstrained principals when some schema
    /// information is available, allowing the language server to suggest only
    /// attributes and types valid for principals.
    AnyPrincipal,
    /// Represents any resource entity type.
    ///
    /// This is specifically used for unconstrained resources when some schema
    /// information is available, allowing the language server to suggest only
    /// attributes and types valid for resources.
    AnyResource,
}

impl From<Arc<EntityType>> for EntityTypeKind {
    fn from(value: Arc<EntityType>) -> Self {
        Self::Concrete(value)
    }
}

impl EntityTypeKind {
    #[must_use]
    pub(crate) fn attribute_type(
        &self,
        attr: &str,
        schema: &ValidatorSchema,
    ) -> Option<CedarTypeKind> {
        match self {
            Self::Concrete(entity_type) => {
                Self::get_entity_attribute_type(entity_type, attr, schema)
            }
            Self::Set(entity_types) => entity_types
                .iter()
                .map(|et| Self::get_entity_attribute_type(et, attr, schema))
                .find(std::option::Option::is_some)
                .flatten(),
            Self::AnyPrincipal => schema
                .principals()
                .map(|et| Self::get_entity_attribute_type(et, attr, schema))
                .find(std::option::Option::is_some)
                .flatten(),
            Self::AnyResource => schema
                .resources()
                .map(|et| Self::get_entity_attribute_type(et, attr, schema))
                .find(std::option::Option::is_some)
                .flatten(),
        }
    }

    #[must_use]
    pub(crate) fn get_entity_attribute_type(
        et: &EntityType,
        attr: &str,
        schema: &ValidatorSchema,
    ) -> Option<CedarTypeKind> {
        let vet = schema.get_entity_type(et)?;
        let attr_ty = vet.attr(attr)?.clone();
        let c_ty = CedarTypeKind::from(attr_ty.attr_type);

        Some(c_ty)
    }

    #[must_use]
    pub(crate) fn attributes(&self, schema: Option<&ValidatorSchema>) -> Vec<Attribute> {
        let Some(schema) = schema else {
            return vec![];
        };

        match self {
            Self::Concrete(entity_type) => Self::entity_type_attributes(schema.into(), entity_type),
            Self::Set(entities) => entities
                .iter()
                .flat_map(|entity| Self::entity_type_attributes(schema.into(), entity).into_iter())
                .collect(),
            Self::AnyPrincipal => schema
                .principals()
                .unique()
                .map(|entity_type| {
                    CedarTypeKind::EntityType(Self::Concrete(entity_type.clone().into()))
                })
                .flat_map(|ct| ct.attributes(Some(schema)).into_iter())
                .collect(),
            Self::AnyResource => schema
                .resources()
                .unique()
                .map(|entity_type| {
                    CedarTypeKind::EntityType(Self::Concrete(entity_type.clone().into()))
                })
                .flat_map(|ct| ct.attributes(Some(schema)).into_iter())
                .collect(),
        }
    }

    #[must_use]
    pub(crate) fn entity_type_attributes(
        schema: Option<&ValidatorSchema>,
        et: &EntityType,
    ) -> Vec<Attribute> {
        let Some(schema) = schema else {
            return vec![];
        };

        schema.get_entity_type(et).map_or(vec![], |entity| {
            entity.attributes().iter().map(Attribute::from).collect()
        })
    }
}

impl Display for EntityTypeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Self::Concrete(entity_type) => entity_type.to_string(),
            Self::Set(btree_set) => btree_set
                .iter()
                .map(std::string::ToString::to_string)
                .join("|"),
            Self::AnyPrincipal => "AnyPrincipal".to_string(),
            Self::AnyResource => "AnyResource".to_string(),
        };
        write!(f, "{str}")
    }
}
