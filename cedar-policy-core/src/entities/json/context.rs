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

use super::{
    err::{JsonDeserializationError, JsonDeserializationErrorContext},
    SchemaType, ValueParser,
};
use crate::ast::{Context, ContextCreationError};
use crate::extensions::Extensions;
use miette::Diagnostic;
use std::collections::BTreeMap;
use thiserror::Error;

/// Trait for schemas that can inform the parsing of Context data
pub trait ContextSchema {
    /// `SchemaType` (expected to be a `Record`) for the context.
    fn context_type(&self) -> SchemaType;
}

/// Simple type that implements `ContextSchema` by expecting an empty context
#[derive(Debug, Clone)]
pub struct NullContextSchema;
impl ContextSchema for NullContextSchema {
    fn context_type(&self) -> SchemaType {
        SchemaType::Record {
            attrs: BTreeMap::new(),
            open_attrs: false,
        }
    }
}

/// Struct used to parse context from JSON.
#[derive(Debug, Clone)]
pub struct ContextJsonParser<'e, 's, S: ContextSchema = NullContextSchema> {
    /// If a `schema` is present, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit.
    /// It will also ensure that the produced `Context` fully conforms to the
    /// `schema` -- for instance, it will error if attributes have the wrong
    /// types (e.g., string instead of integer), or if required attributes are
    /// missing or superfluous attributes are provided.
    schema: Option<&'s S>,

    /// Extensions which are active for the JSON parsing.
    extensions: &'e Extensions<'e>,
}

impl<'e, 's, S: ContextSchema> ContextJsonParser<'e, 's, S> {
    /// Create a new `ContextJsonParser`.
    ///
    /// If a `schema` is present, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit.
    /// It will also ensure that the produced `Context` fully conforms to the
    /// `schema` -- for instance, it will error if attributes have the wrong
    /// types (e.g., string instead of integer), or if required attributes are
    /// missing or superfluous attributes are provided.
    pub fn new(schema: Option<&'s S>, extensions: &'e Extensions<'e>) -> Self {
        Self { schema, extensions }
    }

    /// Parse context JSON (in `&str` form) into a `Context` object
    pub fn from_json_str(&self, json: &str) -> Result<Context, ContextJsonDeserializationError> {
        let val =
            serde_json::from_str(json).map_err(|e| JsonDeserializationError::Serde(e.into()))?;
        self.from_json_value(val)
    }

    /// Parse context JSON (in `serde_json::Value` form) into a `Context` object
    pub fn from_json_value(
        &self,
        json: serde_json::Value,
    ) -> Result<Context, ContextJsonDeserializationError> {
        let vparser = ValueParser::new(self.extensions);
        let expected_ty = self.schema.map(|s| s.context_type());
        let rexpr = vparser.val_into_restricted_expr(json, expected_ty.as_ref(), || {
            JsonDeserializationErrorContext::Context
        })?;
        Context::from_expr(rexpr.as_borrowed(), self.extensions)
            .map_err(ContextJsonDeserializationError::ContextCreation)
    }

    /// Parse context JSON (in `std::io::Read` form) into a `Context` object
    pub fn from_json_file(
        &self,
        json: impl std::io::Read,
    ) -> Result<Context, ContextJsonDeserializationError> {
        let val = serde_json::from_reader(json).map_err(JsonDeserializationError::from)?;
        self.from_json_value(val)
    }
}

/// Errors possible when deserializing request context from JSON
#[derive(Debug, Diagnostic, Error)]
pub enum ContextJsonDeserializationError {
    /// Any JSON deserialization error
    ///
    /// (Note: as of this writing, `JsonDeserializationError` actually contains
    /// many variants that aren't possible here)
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonDeserialization(#[from] JsonDeserializationError),
    /// Error constructing the `Context` itself
    #[error(transparent)]
    #[diagnostic(transparent)]
    ContextCreation(#[from] ContextCreationError),
}
