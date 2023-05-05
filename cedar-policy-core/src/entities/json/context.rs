use super::{JsonDeserializationError, JsonDeserializationErrorContext, SchemaType, ValueParser};
use crate::ast::{Context, ExprKind};
use crate::extensions::Extensions;
use std::collections::HashMap;

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
            attrs: HashMap::new(),
        }
    }
}

/// Struct used to parse context from JSON.
#[derive(Debug, Clone)]
pub struct ContextJsonParser<'e, 's, S: ContextSchema = NullContextSchema> {
    /// If a `schema` is present, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit, and it will error
    /// if attributes have the wrong types (e.g., string instead of integer).
    /// That does not mean it will fully enforce that the produced `Context`
    /// conform to the `schema` -- for instance, as of this writing, it will not
    /// error for unexpected (additional) record attributes.
    schema: Option<&'s S>,

    /// Extensions which are active for the JSON parsing.
    extensions: Extensions<'e>,
}

impl<'e, 's, S: ContextSchema> ContextJsonParser<'e, 's, S> {
    /// Create a new `ContextJsonParser`.
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit, and it will error
    /// if attributes have the wrong types (e.g., string instead of integer).
    /// That does not mean it will fully enforce that the produced `Entities`
    /// conform to the `schema` -- for instance, as of this writing, it will not
    /// error for unexpected (additional) record attributes.
    pub fn new(schema: Option<&'s S>, extensions: Extensions<'e>) -> Self {
        Self { schema, extensions }
    }

    /// Parse context JSON (in `&str` form) into a `Context` object
    pub fn from_json_str(&self, json: &str) -> Result<Context, JsonDeserializationError> {
        let val = serde_json::from_str(json)?;
        self.from_json_value(val)
    }

    /// Parse context JSON (in `serde_json::Value` form) into a `Context` object
    pub fn from_json_value(
        &self,
        json: serde_json::Value,
    ) -> Result<Context, JsonDeserializationError> {
        let vparser = ValueParser::new(self.extensions.clone());
        let expected_ty = self.schema.map(|s| s.context_type());
        let rexpr = vparser.val_into_rexpr(json, expected_ty.as_ref(), || {
            JsonDeserializationErrorContext::Context
        })?;
        match rexpr.expr_kind() {
            ExprKind::Record { .. } => Ok(Context::from_expr(rexpr)),
            _ => Err(JsonDeserializationError::ExpectedContextToBeRecord {
                got: Box::new(rexpr),
            }),
        }
    }

    /// Parse context JSON (in `std::io::Read` form) into a `Context` object
    pub fn from_json_file(
        &self,
        json: impl std::io::Read,
    ) -> Result<Context, JsonDeserializationError> {
        let val = serde_json::from_reader(json).map_err(JsonDeserializationError::from)?;
        self.from_json_value(val)
    }
}
