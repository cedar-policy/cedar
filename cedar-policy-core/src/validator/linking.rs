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

//! Linking of partial schemas ([RFC 116](https://github.com/cedar-policy/rfcs/pull/116)).
//!
//! Linking resolves a name declared `external` in one schema against a
//! definition of the same name in another. A declaration left without a
//! definition stays `external`, so the result may itself be partial.

use crate::validator::{IncompleteSchemaError, ValidatorSchema};
use miette::Diagnostic;
use thiserror::Error;

/// Errors reported by [`Linker::link`], and by the callers that require a
/// linked schema to be complete.
///
/// Separate from [`SchemaError`](crate::validator::SchemaError) on purpose.
/// Constructing a partial schema succeeds, so incompleteness is not a
/// construction failure, and linking has failure modes that no schema
/// constructor can produce.
#[derive(Debug, Diagnostic, Error)]
#[non_exhaustive]
pub enum LinkError {
    /// The schema still declares some entity types or actions `external`
    /// (RFC 116) rather than defining them.
    #[error(transparent)]
    #[diagnostic(transparent)]
    IncompleteSchema(#[from] IncompleteSchemaError),
}

/// Links a set of schemas into one.
#[derive(Debug)]
pub struct Linker {
    /// The schemas to link.
    schemas: Vec<ValidatorSchema>,
}

impl Linker {
    /// Construct a [`Linker`] over `schemas`.
    pub fn new(schemas: impl IntoIterator<Item = ValidatorSchema>) -> Self {
        Self {
            schemas: schemas.into_iter().collect(),
        }
    }

    /// Link the schemas into one.
    #[expect(
        clippy::todo,
        reason = "signature only; RFC 116 linking is unimplemented"
    )]
    pub fn link(self) -> Result<ValidatorSchema, LinkError> {
        let _schemas = self.schemas;
        todo!("RFC 116 schema linking")
    }
}
