use super::EntityUID;
use crate::transitive_closure;
use std::io;
use thiserror::Error;

/// Error type for errors raised in entities.rs.
#[derive(Debug, Error)]
pub enum EntitiesError {
    /// Error occurring in serialization of entities
    #[error("error while serializing entities: {0}")]
    SerializationError(#[from] crate::entities::JsonSerializationError),
    /// Error occurring in deserialization of entities
    #[error("error while deserializing entities: {0}")]
    DeserializationError(#[from] crate::entities::JsonDeserializationError),
    /// Error as a result of a failed IO operation.
    #[error("IO error from the entities module: {0}")]
    IOError(#[from] io::Error),
    /// Errors occurring while computing or enforcing transitive closure on the
    /// entity hierarchy.
    #[error("transitive closure error: {0}")]
    TransitiveClosureError(#[from] Box<transitive_closure::Err<EntityUID>>),
}

/// Type alias for convenience
pub type Result<T> = std::result::Result<T, EntitiesError>;
