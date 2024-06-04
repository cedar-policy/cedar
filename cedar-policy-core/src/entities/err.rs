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

/// Errors in serializing, deserializing, and processing of Entities
#[derive(Debug, Diagnostic, Error)]
pub enum EntitiesError {
    /// Error occurring in serialization of entities
    #[error("error during entity serialization: {0}")]
    #[diagnostic(transparent)]
    Serialization(#[from] crate::entities::json::err::JsonSerializationError),
    /// Error occurring in deserialization of entities
    #[error("error during entity deserialization: {0}")]
    #[diagnostic(transparent)]
    Deserialization(#[from] crate::entities::json::err::JsonDeserializationError),
    /// Error constructing the Entities collection as there is a duplicate Entity UID
    #[error(transparent)]
    #[diagnostic(transparent)]
    Duplicate(Duplicate),
    /// Errors occurring while computing or enforcing transitive closure on the
    /// entity hierarchy.
    #[error("transitive closure computation/enforcement error: {0}")]
    #[diagnostic(transparent)]
    TransitiveClosureError(#[from] TransitiveClosureError),
    /// Error because an entity doesn't conform to the schema
    #[error("entity does not conform to the schema: {0}")]
    #[diagnostic(transparent)]
    InvalidEntity(#[from] crate::entities::conformance::err::EntitySchemaConformanceError),
}

impl EntitiesError {
    pub(crate) fn duplicate(euid: EntityUID) -> Self {
        Self::Duplicate(Duplicate { euid })
    }
}

impl From<transitive_closure::TcError<EntityUID>> for EntitiesError {
    fn from(value: transitive_closure::TcError<EntityUID>) -> Self {
        let tc: TransitiveClosureError = value.into();
        tc.into()
    }
}

#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
/// Errors occurring while computing or enforcing transitive closure on the
/// entity hierarchy.
pub struct TransitiveClosureError {
    err: Box<transitive_closure::TcError<EntityUID>>,
}

impl TransitiveClosureError {
    #[cfg(test)]
    pub(crate) fn inner(&self) -> &transitive_closure::TcError<EntityUID> {
        self.err.as_ref()
    }
}

impl From<transitive_closure::TcError<EntityUID>> for TransitiveClosureError {
    fn from(v: transitive_closure::TcError<EntityUID>) -> Self {
        Self { err: Box::new(v) }
    }
}

#[derive(Debug, PartialEq, Eq, Error, Diagnostic)]
#[error("duplicate entity entry `{}`", .euid)]
/// Error type for entity sets containing duplicate entity uids
pub struct Duplicate {
    /// The [`EntityUID`] that was duplicated
    euid: EntityUID,
}

impl Duplicate {
    #[cfg(test)]
    pub(crate) fn euid(&self) -> &EntityUID {
        &self.euid
    }
}

/// Type alias for convenience
pub type Result<T> = std::result::Result<T, EntitiesError>;
