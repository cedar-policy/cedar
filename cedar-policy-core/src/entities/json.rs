//! This module contains functionality for serializing and deserializing Cedar
//! values, entities, Contexts, etc to and from JSON.

/// Representation of a Cedar value in JSON, and functionality for parsing it.
/// Shared by both entity-attribute and context parsers.
mod jsonvalue;
pub use jsonvalue::*;

/// Parser for `Entities`, with related functionality.
mod entities;
pub use entities::*;

/// Parser for `Context`, with related functionality.
mod context;
pub use context::*;

/// Types which schema-based parsing expects for Cedar values.
mod schema_types;
pub use schema_types::*;

/// Error types for JSON serialization and deserialization
mod err;
pub use err::*;
