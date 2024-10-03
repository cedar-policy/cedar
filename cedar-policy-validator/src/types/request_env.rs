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

use cedar_policy_core::ast::{EntityType, EntityUID, RequestType};

use crate::ValidatorSchema;

use super::Type;

/// Represents a request type environment. In principle, this contains full
/// types for the four variables (principal, action, resource, context).
#[derive(Clone, Debug, PartialEq)]
pub struct RequestEnv<'a> {
    /// Principal type
    pub principal: &'a EntityType,
    /// Action
    pub action: &'a EntityUID,
    /// Resource type
    pub resource: &'a EntityType,
    /// Context type
    pub context: &'a Type,

    /// Binding for the ?principal slot, if any
    pub principal_slot: Option<EntityType>,
    /// Binding for the ?resource slot, if any
    pub resource_slot: Option<EntityType>,
}

impl<'a> RequestEnv<'a> {
    /// Return the types of each of the elements of this request.
    pub fn to_request_type(&self) -> RequestType {
        RequestType {
            principal: self.principal.clone(),
            action: self.action.clone(),
            resource: self.resource.clone(),
        }
    }

    /// The principal type for this request environment, as an [`EntityType`].
    pub fn principal_entity_type(&self) -> &'a EntityType {
        self.principal
    }

    /// [`Type`] of the `principal` for this request environment
    pub fn principal_type(&self) -> Type {
        Type::named_entity_reference(self.principal.clone())
    }

    /// The action for this request environment, as an [`EntityUID`].
    pub fn action_entity_uid(&self) -> &'a EntityUID {
        self.action
    }

    /// [`Type`] of the `action` for this request environment
    pub fn action_type(&self, schema: &ValidatorSchema) -> Option<Type> {
        Type::euid_literal(self.action.clone(), schema)
    }

    /// The resource type for this request environment, as an [`EntityType`].
    pub fn resource_entity_type(&self) -> &'a EntityType {
        self.resource
    }

    /// [`Type`] of the `resource` for this request environment
    pub fn resource_type(&self) -> Type {
        Type::named_entity_reference(self.resource.clone())
    }

    /// [`Type`] of the `context` for this request environment
    pub fn context_type(&self) -> Type {
        self.context.clone()
    }

    /// Type of the ?principal slot for this request environment, as an [`EntityType`].
    /// `None` may indicates  that this slot doesn't exist.
    pub fn principal_slot(&self) -> &Option<EntityType> {
        &self.principal_slot
    }

    /// Type of the ?resource slot for this request environment, as an [`EntityType`].
    /// `None` may indicates  that this slot doesn't exist.
    pub fn resource_slot(&self) -> &Option<EntityType> {
        &self.resource_slot
    }
}
