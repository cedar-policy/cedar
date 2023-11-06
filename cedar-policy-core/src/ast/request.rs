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

use crate::entities::{ContextJsonParser, JsonDeserializationError, NullContextSchema};
use crate::extensions::Extensions;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::sync::Arc;

use super::{
    BorrowedRestrictedExpr, EntityUID, Expr, ExprConstructionError, ExprKind, Literal,
    PartialValue, RestrictedExpr, Value, Var,
};

/// Represents the request tuple <P, A, R, C> (see the Cedar design doc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Principal associated with the request
    pub(crate) principal: EntityUIDEntry,

    /// Action associated with the request
    pub(crate) action: EntityUIDEntry,

    /// Resource associated with the request
    pub(crate) resource: EntityUIDEntry,

    /// Context associated with the request.
    /// `None` means that variable will result in a residual for partial evaluation.
    pub(crate) context: Option<Context>,
}

/// An entry in a request for a Entity UID.
/// It may either be a concrete EUID
/// or an unknown in the case of partial evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntityUIDEntry {
    /// A concrete (but perhaps unspecified) EntityUID
    Concrete(Arc<EntityUID>),
    /// An EntityUID left as unknown for partial evaluation
    Unknown,
}

impl EntityUIDEntry {
    /// Evaluate the entry to either:
    /// A value, if the entry is concrete
    /// An unknown corresponding to the passed `var`
    pub fn evaluate(&self, var: Var) -> PartialValue {
        match self {
            EntityUIDEntry::Concrete(euid) => Value::Lit(Literal::EntityUID(euid.clone())).into(),
            EntityUIDEntry::Unknown => Expr::unknown(var.to_string()).into(),
        }
    }

    /// Create an entry with a concrete EntityUID
    pub fn concrete(euid: EntityUID) -> Self {
        Self::Concrete(Arc::new(euid))
    }

    /// Get the UID of the entry, or `None` if it is unknown (partial evaluation)
    pub fn uid(&self) -> Option<&EntityUID> {
        match self {
            Self::Concrete(euid) => Some(euid),
            Self::Unknown => None,
        }
    }
}

impl Request {
    /// Default constructor.
    ///
    /// If `schema` is provided, this constructor validates that this `Request`
    /// complies with the given `schema`.
    pub fn new<S: RequestSchema>(
        principal: EntityUID,
        action: EntityUID,
        resource: EntityUID,
        context: Context,
        schema: Option<&S>,
        extensions: Extensions<'_>,
    ) -> Result<Self, S::Error> {
        let req = Self {
            principal: EntityUIDEntry::concrete(principal),
            action: EntityUIDEntry::concrete(action),
            resource: EntityUIDEntry::concrete(resource),
            context: Some(context),
        };
        if let Some(schema) = schema {
            schema.validate_request(&req, extensions)?;
        }
        Ok(req)
    }

    /// Create a new `Request` with potentially unknown (for partial eval) variables.
    ///
    /// If `schema` is provided, this constructor validates that this `Request`
    /// complies with the given `schema` (at least to the extent that we can
    /// validate with the given information)
    pub fn new_with_unknowns<S: RequestSchema>(
        principal: EntityUIDEntry,
        action: EntityUIDEntry,
        resource: EntityUIDEntry,
        context: Option<Context>,
        schema: Option<&S>,
        extensions: Extensions<'_>,
    ) -> Result<Self, S::Error> {
        let req = Self {
            principal,
            action,
            resource,
            context,
        };
        if let Some(schema) = schema {
            schema.validate_request(&req, extensions)?;
        }
        Ok(req)
    }

    /// Get the principal associated with the request
    pub fn principal(&self) -> &EntityUIDEntry {
        &self.principal
    }

    /// Get the action associated with the request
    pub fn action(&self) -> &EntityUIDEntry {
        &self.action
    }

    /// Get the resource associated with the request
    pub fn resource(&self) -> &EntityUIDEntry {
        &self.resource
    }

    /// Get the context associated with the request
    /// Returning `None` means the variable is unknown, and will result in a residual expression
    pub fn context(&self) -> Option<&Context> {
        self.context.as_ref()
    }
}

impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_euid = |maybe_euid: &EntityUIDEntry| match maybe_euid {
            EntityUIDEntry::Concrete(euid) => format!("{euid}"),
            EntityUIDEntry::Unknown => "unknown".to_string(),
        };
        write!(
            f,
            "request with principal {}, action {}, resource {}, and context {}",
            display_euid(&self.principal),
            display_euid(&self.action),
            display_euid(&self.resource),
            match &self.context {
                Some(x) => format!("{x}"),
                None => "unknown".to_string(),
            }
        )
    }
}

/// `Context` field of a `Request`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Context {
    /// an `Expr::Record` that qualifies as a "restricted expression"
    /// INVARIANT: This must be of the variant `Record`
    /// TODO: This should be refactored if possible to require this runtime invariant
    #[serde(flatten)]
    context: RestrictedExpr,
}

impl Context {
    /// Create an empty `Context`
    pub fn empty() -> Self {
        // PANIC SAFETY: empty set of keys cannot contain a duplicate key
        #[allow(clippy::expect_used)]
        Self::from_pairs([]).expect("empty set of keys cannot contain a duplicate key")
    }

    /// Create a `Context` from a `RestrictedExpr`, which must be a `Record`.
    /// If it is not a `Record`, then this function returns `Err` (returning
    /// ownership of the non-record expression), otherwise it returns `Ok` of
    /// a context for that record.
    pub fn from_expr(expr: RestrictedExpr) -> Result<Self, RestrictedExpr> {
        match expr.expr_kind() {
            // INVARIANT: `context` must be a `Record`, which is guaranteed by the match case.
            ExprKind::Record { .. } => Ok(Self { context: expr }),
            _ => Err(expr),
        }
    }

    /// Create a `Context` from a map of key to `RestrictedExpr`, or a Vec of
    /// `(key, RestrictedExpr)` pairs, or any other iterator of `(key, RestrictedExpr)` pairs
    // INVARIANT: always constructs a record
    pub fn from_pairs(
        pairs: impl IntoIterator<Item = (SmolStr, RestrictedExpr)>,
    ) -> Result<Self, ExprConstructionError> {
        // INVARIANT this always constructs a record
        Ok(Self {
            context: RestrictedExpr::record(pairs)?,
        })
    }

    /// Create a `Context` from a string containing JSON (which must be a JSON
    /// object, not any other JSON type, or you will get an error here).
    /// JSON here must use the `__entity` and `__extn` escapes for entity
    /// references, extension values, etc.
    ///
    /// For schema-based parsing, use `ContextJsonParser`.
    pub fn from_json_str(json: &str) -> Result<Self, JsonDeserializationError> {
        // INVARIANT `.from_json_str` always produces an expression of variant `Record`
        ContextJsonParser::new(None::<&NullContextSchema>, Extensions::all_available())
            .from_json_str(json)
    }

    /// Create a `Context` from a `serde_json::Value` (which must be a JSON
    /// object, not any other JSON type, or you will get an error here).
    /// JSON here must use the `__entity` and `__extn` escapes for entity
    /// references, extension values, etc.
    ///
    /// For schema-based parsing, use `ContextJsonParser`.
    pub fn from_json_value(json: serde_json::Value) -> Result<Self, JsonDeserializationError> {
        // INVARIANT `.from_json_value` always produces an expression of variant `Record`
        ContextJsonParser::new(None::<&NullContextSchema>, Extensions::all_available())
            .from_json_value(json)
    }

    /// Create a `Context` from a JSON file.  The JSON file must contain a JSON
    /// object, not any other JSON type, or you will get an error here.
    /// JSON here must use the `__entity` and `__extn` escapes for entity
    /// references, extension values, etc.
    ///
    /// For schema-based parsing, use `ContextJsonParser`.
    pub fn from_json_file(json: impl std::io::Read) -> Result<Self, JsonDeserializationError> {
        // INVARIANT `.from_json_file` always produces an expression of variant `Record`
        ContextJsonParser::new(None::<&NullContextSchema>, Extensions::all_available())
            .from_json_file(json)
    }

    /// Iterate over the (key, value) pairs in the `Context`
    // PANIC SAFETY: This is safe due to the invariant on `self.context`, `self.context` must always be a record
    #[allow(clippy::panic)]
    pub fn iter(&self) -> impl Iterator<Item = (&str, BorrowedRestrictedExpr<'_>)> {
        // PANIC SAFETY invariant on `self.context` ensures that it is a Record
        #[allow(clippy::panic)]
        match self.context.as_ref().expr_kind() {
            ExprKind::Record(map) => map
                .iter()
                .map(|(k, v)| (k.as_str(), BorrowedRestrictedExpr::new_unchecked(v))), // given that the invariant holds for `self.context`, it will hold here
            e => panic!("internal invariant violation: expected Expr::Record, got {e:?}"),
        }
    }
}

impl AsRef<RestrictedExpr> for Context {
    fn as_ref(&self) -> &RestrictedExpr {
        &self.context
    }
}

impl std::default::Default for Context {
    fn default() -> Context {
        Context::empty()
    }
}

impl std::fmt::Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.context)
    }
}

/// Trait for schemas capable of validating `Request`s
pub trait RequestSchema {
    /// Error type returned when a request fails validation
    type Error: std::error::Error;
    /// Validate the given `request`, returning `Err` if it fails validation
    fn validate_request<'a>(
        &self,
        request: &Request,
        extensions: Extensions<'a>,
    ) -> Result<(), Self::Error>;
}

/// A `RequestSchema` that does no validation and always reports a passing result
#[derive(Debug, Clone)]
pub struct RequestSchemaAllPass;
impl RequestSchema for RequestSchemaAllPass {
    type Error = std::convert::Infallible;
    fn validate_request<'a>(
        &self,
        _request: &Request,
        _extensions: Extensions<'a>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn test_json_from_str_non_record() {
        let src = "1";
        assert!(super::Context::from_json_str(src).is_err());
    }
}
