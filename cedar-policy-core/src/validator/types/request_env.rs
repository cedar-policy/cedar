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

use crate::ast::{EntityType, EntityUID, RequestType};

use crate::validator::ValidatorSchema;

use super::Type;

/// Represents a request type environment. In principle, this contains full
/// types for the four variables (principal, action, resource, context).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestEnv<'a> {
    /// Contains the four variables bound in the type environment. These together
    /// represent the full type of (principal, action, resource, context)
    /// authorization request.
    DeclaredAction {
        /// Principal type
        principal: &'a EntityType,
        /// Action
        action: &'a EntityUID,
        /// Resource type
        resource: &'a EntityType,
        /// Context type
        context: &'a Type,

        /// Binding for the ?principal slot, if any
        principal_slot: Option<EntityType>,
        /// Binding for the ?resource slot, if any
        resource_slot: Option<EntityType>,
    },
    /// Only in partial schema validation, the action might not have been
    /// declared in the schema, so this encodes the environment where we know
    /// nothing about the environment.
    UndeclaredAction,
}

impl<'a> RequestEnv<'a> {
    /// Return the types of each of the elements of this request.
    /// Returns [`None`] when the request is not fully concrete.
    pub fn to_request_type(&self) -> Option<RequestType> {
        match self {
            RequestEnv::DeclaredAction {
                principal,
                action,
                resource,
                context: _,
                principal_slot: _,
                resource_slot: _,
            } => Some(RequestType {
                principal: (*principal).clone(),
                action: (*action).clone(),
                resource: (*resource).clone(),
            }),
            RequestEnv::UndeclaredAction => None,
        }
    }

    /// The principal type for this request environment, as an [`EntityType`].
    /// `None` indicates we don't know (only possible in partial schema validation).
    pub fn principal_entity_type(&self) -> Option<&'a EntityType> {
        match self {
            RequestEnv::UndeclaredAction => None,
            RequestEnv::DeclaredAction { principal, .. } => Some(principal),
        }
    }

    /// [`Type`] of the `principal` for this request environment
    pub fn principal_type(&self) -> Type {
        match self.principal_entity_type() {
            Some(principal) => Type::named_entity_reference(principal.clone()),
            None => Type::any_entity_reference(),
        }
    }

    /// The action for this request environment, as an [`EntityUID`].
    /// `None` indicates we don't know (only possible in partial schema validation).
    pub fn action_entity_uid(&self) -> Option<&'a EntityUID> {
        match self {
            RequestEnv::UndeclaredAction => None,
            RequestEnv::DeclaredAction { action, .. } => Some(action),
        }
    }

    /// [`Type`] of the `action` for this request environment
    pub fn action_type(&self, schema: &ValidatorSchema) -> Option<Type> {
        match self.action_entity_uid() {
            Some(action) => Type::euid_literal(action, schema),
            None => Some(Type::any_entity_reference()),
        }
    }

    /// The resource type for this request environment, as an [`EntityType`].
    /// `None` indicates we don't know (only possible in partial schema validation).
    pub fn resource_entity_type(&self) -> Option<&'a EntityType> {
        match self {
            RequestEnv::UndeclaredAction => None,
            RequestEnv::DeclaredAction { resource, .. } => Some(resource),
        }
    }

    /// [`Type`] of the `resource` for this request environment
    pub fn resource_type(&self) -> Type {
        match self.resource_entity_type() {
            Some(resource) => Type::named_entity_reference(resource.clone()),
            None => Type::any_entity_reference(),
        }
    }

    /// [`Type`] of the `context` for this request environment
    pub fn context_type(&self) -> Type {
        match self {
            RequestEnv::UndeclaredAction => Type::any_record(),
            RequestEnv::DeclaredAction { context, .. } => (*context).clone(),
        }
    }

    /// Type of the ?principal slot for this request environment, as an [`EntityType`].
    /// `None` may indicate we don't know (in partial schema validation) or that
    /// this slot doesn't exist.
    pub fn principal_slot(&self) -> &Option<EntityType> {
        match self {
            RequestEnv::UndeclaredAction => &None,
            RequestEnv::DeclaredAction { principal_slot, .. } => principal_slot,
        }
    }

    /// Type of the ?resource slot for this request environment, as an [`EntityType`].
    /// `None` may indicate we don't know (in partial schema validation) or that
    /// this slot doesn't exist.
    pub fn resource_slot(&self) -> &Option<EntityType> {
        match self {
            RequestEnv::UndeclaredAction => &None,
            RequestEnv::DeclaredAction { resource_slot, .. } => resource_slot,
        }
    }
}
