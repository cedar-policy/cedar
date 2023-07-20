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
    /// Errors occurring while computing or enforcing transitive closure on the
    /// entity hierarchy.
    #[error("transitive closure computation/enforcement error: {0}")]
    TransitiveClosureError(#[from] Box<transitive_closure::TcError<EntityUID>>),
}

/// Type alias for convenience
pub type Result<T> = std::result::Result<T, EntitiesError>;
