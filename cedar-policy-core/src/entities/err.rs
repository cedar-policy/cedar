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

use super::EntityUID;
use crate::transitive_closure;
use miette::Diagnostic;
use thiserror::Error;

/// Error type for errors raised in entities.rs.
#[derive(Debug, Diagnostic, Error)]
pub enum EntitiesError {
    /// Error occurring in serialization of entities
    #[error("error during entity serialization: {0}")]
    #[diagnostic(transparent)]
    Serialization(#[from] crate::entities::JsonSerializationError),
    /// Error occurring in deserialization of entities
    #[error("error during entity deserialization: {0}")]
    #[diagnostic(transparent)]
    Deserialization(#[from] crate::entities::JsonDeserializationError),
    /// Error constructing the `[crate::entities::Entities]` as there is a duplicate Entity UID
    #[error("duplicate entity entry `{0}`")]
    Duplicate(EntityUID),
    /// Errors occurring while computing or enforcing transitive closure on the
    /// entity hierarchy.
    #[error("transitive closure computation/enforcement error: {0}")]
    #[diagnostic(transparent)]
    TransitiveClosureError(#[from] Box<transitive_closure::TcError<EntityUID>>),
    /// Error because an entity doesn't conform to the schema
    #[error("entity does not conform to the schema: {0}")]
    #[diagnostic(transparent)]
    InvalidEntity(#[from] crate::entities::EntitySchemaConformanceError),
}

/// Type alias for convenience
pub type Result<T> = std::result::Result<T, EntitiesError>;
