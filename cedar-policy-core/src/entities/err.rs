/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

use super::EntityUID;
use crate::transitive_closure;
use thiserror::Error;

/// Error type for errors raised in entities.rs.
#[derive(Debug, Error)]
pub enum EntitiesError {
    /// Error occurring in serialization of entities
    #[error("entities serialization error: {0}")]
    Serialization(#[from] crate::entities::JsonSerializationError),
    /// Error occurring in deserialization of entities
    #[error("entities deserialization error: {0}")]
    Deserialization(#[from] crate::entities::JsonDeserializationError),
    /// Error constructing the `[crate::entities::Entities]` as there is a duplicate Entity UID
    #[error("Duplicate entity entry: {0}")]
    Duplicate(EntityUID),
    /// Errors occurring while computing or enforcing transitive closure on the
    /// entity hierarchy.
    #[error("transitive closure computation/enforcement error: {0}")]
    TransitiveClosureError(#[from] Box<transitive_closure::TcError<EntityUID>>),
}

/// An error which is thrown when an error occurs accessing an entity's attribute
#[derive(Debug, Error)]
pub enum EntityAttrAccessError<T: std::error::Error> {
    /// The entity does not exist
    UnknownEntity,
    /// The entity exists but the attribute does not
    UnknownAttr,
    /// Some other error occured (e.g. network failed)
    AccessError(T),
}

/// Error which is thrown when accessing an entity (e.g. to check the presence of an attribute)
#[derive(Debug, Error)]
pub enum EntityAccessError<T: std::error::Error> {
    /// The entity does not exist
    UnknownEntity,
    /// Some other error occured (e.g. network failed)
    AccessError(T),
}

impl<T: std::error::Error> EntityAttrAccessError<T> {
    /// Handle the missing attribute situation by returning Ok(u) if the attribute is missing
    /// and keeping the error otherwise
    pub fn handle_attr<U>(self, u: U) -> std::result::Result<U, EntityAccessError<T>> {
        match self {
            EntityAttrAccessError::UnknownAttr => Ok(u),
            EntityAttrAccessError::UnknownEntity => Err(EntityAccessError::UnknownEntity),
            EntityAttrAccessError::AccessError(t) => Err(EntityAccessError::AccessError(t)),
        }
    }
}

impl<T: std::error::Error> From<EntityAccessError<T>> for EntityAttrAccessError<T> {
    fn from(value: EntityAccessError<T>) -> Self {
        match value {
            EntityAccessError::UnknownEntity => EntityAttrAccessError::UnknownEntity,
            EntityAccessError::AccessError(t) => EntityAttrAccessError::AccessError(t),
        }
    }
}

impl<T: std::error::Error> From<T> for EntityAccessError<T> {
    fn from(value: T) -> Self {
        EntityAccessError::AccessError(value)
    }
}

impl<T: std::error::Error> From<T> for EntityAttrAccessError<T> {
    fn from(value: T) -> Self {
        EntityAttrAccessError::AccessError(value)
    }
}

/// Type alias for convenience
pub type Result<T> = std::result::Result<T, EntitiesError>;
