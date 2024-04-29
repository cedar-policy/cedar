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

//! This module contains functionality for serializing and deserializing Cedar
//! values, entities, Contexts, etc to and from JSON.

/// Representation of a Cedar value in JSON, and functionality for parsing it.
/// Shared by both entity-attribute and context parsers.
mod value;
pub use value::*;

/// Parser for `Entities`, with related functionality.
mod entities;
pub use entities::*;

/// Parser for `Context`, with related functionality.
mod context;
pub use context::*;

/// the `Schema` trait and related types/traits, used for schema-based parsing.
mod schema;
pub use schema::*;

/// Types which schema-based parsing expects for Cedar values.
mod schema_types;
pub use schema_types::*;

/// Error types for JSON serialization and deserialization
mod err;
pub use err::*;
