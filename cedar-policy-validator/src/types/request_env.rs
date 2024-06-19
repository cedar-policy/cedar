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

use cedar_policy_core::ast::{EntityType, EntityUID};

use crate::ValidatorSchema;

use super::Type;

#[derive(Clone, Debug, PartialEq)]
pub enum RequestEnv<'a> {
    /// Contains the four variables bound in the type environment. These together
    /// represent the full type of (principal, action, resource, context)
    /// authorization request.
    DeclaredAction {
        principal: &'a EntityType,
        action: &'a EntityUID,
        resource: &'a EntityType,
        context: &'a Type,

        principal_slot: Option<EntityType>,
        resource_slot: Option<EntityType>,
    },
    /// Only in partial schema validation, the action might not have been
    /// declared in the schema, so this encodes the environment where we know
    /// nothing about the environment.
    UndeclaredAction,
}

impl<'a> RequestEnv<'a> {
    pub fn principal_entity_type(&self) -> Option<&'a EntityType> {
        match self {
            RequestEnv::UndeclaredAction => None,
            RequestEnv::DeclaredAction { principal, .. } => Some(principal),
        }
    }

    pub fn principal_type(&self) -> Type {
        match self.principal_entity_type() {
            Some(principal) => Type::named_entity_reference(principal.clone()),
            None => Type::any_entity_reference(),
        }
    }

    pub fn action_entity_uid(&self) -> Option<&'a EntityUID> {
        match self {
            RequestEnv::UndeclaredAction => None,
            RequestEnv::DeclaredAction { action, .. } => Some(action),
        }
    }

    pub fn action_type(&self, schema: &ValidatorSchema) -> Option<Type> {
        match self.action_entity_uid() {
            Some(action) => Type::euid_literal(action.clone(), schema),
            None => Some(Type::any_entity_reference()),
        }
    }

    pub fn resource_entity_type(&self) -> Option<&'a EntityType> {
        match self {
            RequestEnv::UndeclaredAction => None,
            RequestEnv::DeclaredAction { resource, .. } => Some(resource),
        }
    }

    pub fn resource_type(&self) -> Type {
        match self.resource_entity_type() {
            Some(resource) => Type::named_entity_reference(resource.clone()),
            None => Type::any_entity_reference(),
        }
    }

    pub fn context_type(&self) -> Type {
        match self {
            RequestEnv::UndeclaredAction => Type::any_record(),
            RequestEnv::DeclaredAction { context, .. } => (*context).clone(),
        }
    }

    pub fn principal_slot(&self) -> &Option<EntityType> {
        match self {
            RequestEnv::UndeclaredAction => &None,
            RequestEnv::DeclaredAction { principal_slot, .. } => principal_slot,
        }
    }

    pub fn resource_slot(&self) -> &Option<EntityType> {
        match self {
            RequestEnv::UndeclaredAction => &None,
            RequestEnv::DeclaredAction { resource_slot, .. } => resource_slot,
        }
    }
}
