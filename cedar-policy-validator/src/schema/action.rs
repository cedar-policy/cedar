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

//! This module contains the definition of `ValidatorActionId` and the types it relies on

use cedar_policy_core::{
    ast::{EntityType, EntityUID, PartialValueSerializedAsExpr},
    transitive_closure::TCNode,
};
use serde::Serialize;
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashSet};

use crate::types::{Attributes, Type};

/// Contains information about actions used by the validator.  The contents of
/// the struct are the same as the schema entity type structure, but the
/// `member_of` relation is reversed to instead be `descendants`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorActionId {
    /// The name of the action.
    pub(crate) name: EntityUID,

    /// The principals and resources that the action can be applied to.
    pub(crate) applies_to: ValidatorApplySpec,

    /// The set of actions that can be members of this action. When this
    /// structure is initially constructed, the field will contain direct
    /// children, but it will be updated to contain the closure of all
    /// descendants before it is used in any validation.
    pub(crate) descendants: HashSet<EntityUID>,

    /// The type of the context record associated with this action.
    pub(crate) context: Type,

    /// The attribute types for this action, used for typechecking.
    pub(crate) attribute_types: Attributes,

    /// The actual attribute value for this action, used to construct an
    /// `Entity` for this action. Could also be used for more precise
    /// typechecking by partial evaluation.
    ///
    /// Attributes are serialized as `RestrictedExpr`s, so that roundtripping
    /// works seamlessly.
    pub(crate) attributes: BTreeMap<SmolStr, PartialValueSerializedAsExpr>,
}

impl ValidatorActionId {
    /// The `Type` that this action requires for its context.
    ///
    /// This always returns a closed record type.
    pub fn context_type(&self) -> &Type {
        &self.context
    }

    /// The `EntityType`s that can be the `principal` for this action.
    pub fn applies_to_principals(&self) -> impl Iterator<Item = &EntityType> {
        self.applies_to.principal_apply_spec.iter()
    }

    /// The `EntityType`s that can be the `resource` for this action.
    pub fn applies_to_resources(&self) -> impl Iterator<Item = &EntityType> {
        self.applies_to.resource_apply_spec.iter()
    }
}

impl TCNode<EntityUID> for ValidatorActionId {
    fn get_key(&self) -> EntityUID {
        self.name.clone()
    }

    fn add_edge_to(&mut self, k: EntityUID) {
        self.descendants.insert(k);
    }

    fn out_edges(&self) -> Box<dyn Iterator<Item = &EntityUID> + '_> {
        Box::new(self.descendants.iter())
    }

    fn has_edge_to(&self, e: &EntityUID) -> bool {
        self.descendants.contains(e)
    }
}

/// The principals and resources that an action can be applied to.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ValidatorApplySpec {
    /// The principal entity types the action can be applied to.
    principal_apply_spec: HashSet<EntityType>,

    /// The resource entity types the action can be applied to.
    resource_apply_spec: HashSet<EntityType>,
}

impl ValidatorApplySpec {
    /// Create an apply spec for an action that can only be applied to some
    /// specific entities.
    pub fn new(
        principal_apply_spec: HashSet<EntityType>,
        resource_apply_spec: HashSet<EntityType>,
    ) -> Self {
        Self {
            principal_apply_spec,
            resource_apply_spec,
        }
    }

    /// Is the given principal type applicable for this spec?
    pub fn is_applicable_principal_type(&self, ty: &EntityType) -> bool {
        self.principal_apply_spec.contains(ty)
    }

    /// Get the applicable principal types for this spec.
    pub fn applicable_principal_types(&self) -> impl Iterator<Item = &EntityType> {
        self.principal_apply_spec.iter()
    }

    /// Is the given resource type applicable for this spec?
    pub fn is_applicable_resource_type(&self, ty: &EntityType) -> bool {
        self.resource_apply_spec.contains(ty)
    }

    /// Get the applicable resource types for this spec.
    pub fn applicable_resource_types(&self) -> impl Iterator<Item = &EntityType> {
        self.resource_apply_spec.iter()
    }
}
