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

use crate::entities::json::{
    ContextJsonDeserializationError, ContextJsonParser, NullContextSchema,
};
use crate::evaluator::{EvaluationError, RestrictedEvaluator};
use crate::extensions::Extensions;
use crate::parser::MaybeLoc;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use smol_str::{SmolStr, ToSmolStr};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use thiserror::Error;

use super::{
    BorrowedRestrictedExpr, BoundedDisplay, EntityType, EntityUID, Expr, ExprKind,
    ExpressionConstructionError, PartialValue, RestrictedExpr, Unknown, Value, ValueKind, Var,
};

/// Represents the request tuple <P, A, R, C> (see the Cedar design doc).
#[derive(Debug, Clone)]
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

/// Represents the principal type, resource type, and action UID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestType {
    /// Principal type
    pub principal: EntityType,
    /// Action type
    pub action: EntityUID,
    /// Resource type
    pub resource: EntityType,
}

/// An entry in a request for a Entity UID.
/// It may either be a concrete EUID
/// or an unknown in the case of partial evaluation
#[derive(Debug, Clone)]
pub enum EntityUIDEntry {
    /// A concrete EntityUID
    Known {
        /// The concrete `EntityUID`
        euid: Arc<EntityUID>,
        /// Source location associated with the `EntityUIDEntry`, if any
        loc: MaybeLoc,
    },
    /// An EntityUID left as unknown for partial evaluation
    Unknown {
        /// The type of the unknown EntityUID, if known.
        ty: Option<EntityType>,

        /// Source location associated with the `EntityUIDEntry`, if any
        loc: MaybeLoc,
    },
}

impl From<EntityUID> for EntityUIDEntry {
    fn from(euid: EntityUID) -> Self {
        Self::Known {
            euid: Arc::new(euid.clone()),
            loc: match &euid {
                EntityUID::EntityUID(euid) => euid.loc(),
                #[cfg(feature = "tolerant-ast")]
                EntityUID::Error => None,
            },
        }
    }
}

impl EntityUIDEntry {
    /// Evaluate the entry to either:
    /// A value, if the entry is concrete
    /// An unknown corresponding to the passed `var`
    pub fn evaluate(&self, var: Var) -> PartialValue {
        match self {
            EntityUIDEntry::Known { euid, loc } => {
                Value::new(Arc::unwrap_or_clone(Arc::clone(euid)), loc.clone()).into()
            }
            EntityUIDEntry::Unknown { ty: None, loc } => {
                Expr::unknown(Unknown::new_untyped(var.to_smolstr()))
                    .with_maybe_source_loc(loc.clone())
                    .into()
            }
            EntityUIDEntry::Unknown {
                ty: Some(known_type),
                loc,
            } => Expr::unknown(Unknown::new_with_type(
                var.to_smolstr(),
                super::Type::Entity {
                    ty: known_type.clone(),
                },
            ))
            .with_maybe_source_loc(loc.clone())
            .into(),
        }
    }

    /// Create an entry with a concrete EntityUID and the given source location
    pub fn known(euid: EntityUID, loc: MaybeLoc) -> Self {
        Self::Known {
            euid: Arc::new(euid),
            loc,
        }
    }

    /// Create an entry with an entirely unknown EntityUID
    pub fn unknown() -> Self {
        Self::Unknown {
            ty: None,
            loc: None,
        }
    }

    /// Create an entry with an unknown EntityUID but known EntityType
    pub fn unknown_with_type(ty: EntityType, loc: MaybeLoc) -> Self {
        Self::Unknown { ty: Some(ty), loc }
    }

    /// Get the UID of the entry, or `None` if it is unknown (partial evaluation)
    pub fn uid(&self) -> Option<&EntityUID> {
        match self {
            Self::Known { euid, .. } => Some(euid),
            Self::Unknown { .. } => None,
        }
    }

    /// Get the type of the entry, or `None` if it is unknown (partial evaluation with no type annotation)
    pub fn get_type(&self) -> Option<&EntityType> {
        match self {
            Self::Known { euid, .. } => Some(euid.entity_type()),
            Self::Unknown { ty, .. } => ty.as_ref(),
        }
    }
}

impl Request {
    /// Default constructor.
    ///
    /// If `schema` is provided, this constructor validates that this `Request`
    /// complies with the given `schema`.
    pub fn new<S: RequestSchema>(
        principal: (EntityUID, MaybeLoc),
        action: (EntityUID, MaybeLoc),
        resource: (EntityUID, MaybeLoc),
        context: Context,
        schema: Option<&S>,
        extensions: &Extensions<'_>,
    ) -> Result<Self, S::Error> {
        let req = Self {
            principal: EntityUIDEntry::known(principal.0, principal.1),
            action: EntityUIDEntry::known(action.0, action.1),
            resource: EntityUIDEntry::known(resource.0, resource.1),
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
        extensions: &Extensions<'_>,
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

    /// Create a new `Request` with potentially unknown (for partial eval) variables/context
    /// and without schema validation.
    pub fn new_unchecked(
        principal: EntityUIDEntry,
        action: EntityUIDEntry,
        resource: EntityUIDEntry,
        context: Option<Context>,
    ) -> Self {
        Self {
            principal,
            action,
            resource,
            context,
        }
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

    /// Get the request types that correspond to this request.
    /// This includes the types of the principal, action, and resource.
    /// [`RequestType`] is used by the entity manifest.
    /// The context type is implied by the action's type.
    /// Returns `None` if the request is not fully concrete.
    pub fn to_request_type(&self) -> Option<RequestType> {
        Some(RequestType {
            principal: self.principal().uid()?.entity_type().clone(),
            action: self.action().uid()?.clone(),
            resource: self.resource().uid()?.entity_type().clone(),
        })
    }
}

impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_euid = |maybe_euid: &EntityUIDEntry| match maybe_euid {
            EntityUIDEntry::Known { euid, .. } => format!("{euid}"),
            EntityUIDEntry::Unknown { ty: None, .. } => "unknown".to_string(),
            EntityUIDEntry::Unknown {
                ty: Some(known_type),
                ..
            } => format!("unknown of type {known_type}"),
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Context {
    /// The context is a concrete value.
    Value(Arc<BTreeMap<SmolStr, Value>>),
    /// The context is a residual expression, containing some unknown value in
    /// the record attributes.
    /// INVARIANT(restricted): Each `Expr` in this map must be a `RestrictedExpr`.
    /// INVARIANT(unknown): At least one `Expr` must contain an `unknown`.
    RestrictedResidual(Arc<BTreeMap<SmolStr, Expr>>),
}

impl Context {
    /// Create an empty `Context`
    pub fn empty() -> Self {
        Self::Value(Arc::new(BTreeMap::new()))
    }

    /// Create a `Context` from a `PartialValue` without checking that the
    /// residual is a restricted expression.  This function does check that the
    /// value or residual is a record and returns `Err` when it is not.
    ///
    /// INVARIANT: if `value` is a residual, then it must be a valid restricted expression.
    fn from_restricted_partial_val_unchecked(
        value: PartialValue,
    ) -> Result<Self, ContextCreationError> {
        match value {
            PartialValue::Value(v) => {
                if let ValueKind::Record(attrs) = v.value {
                    Ok(Context::Value(attrs))
                } else {
                    Err(ContextCreationError::not_a_record(v.into()))
                }
            }
            PartialValue::Residual(e) => {
                if let ExprKind::Record(attrs) = e.expr_kind() {
                    // From the invariant on `PartialValue::Residual`, there is
                    // an unknown in `e`. It is a record, so there must be an
                    // unknown in one of the attributes expressions, satisfying
                    // INVARIANT(unknown). From the invariant on this function,
                    // `e` is a valid restricted expression, satisfying
                    // INVARIANT(restricted).
                    Ok(Context::RestrictedResidual(attrs.clone()))
                } else {
                    Err(ContextCreationError::not_a_record(e))
                }
            }
        }
    }

    /// Create a `Context` from a `RestrictedExpr`, which must be a `Record`.
    ///
    /// `extensions` provides the `Extensions` which should be active for
    /// evaluating the `RestrictedExpr`.
    pub fn from_expr(
        expr: BorrowedRestrictedExpr<'_>,
        extensions: &Extensions<'_>,
    ) -> Result<Self, ContextCreationError> {
        match expr.expr_kind() {
            ExprKind::Record { .. } => {
                let evaluator = RestrictedEvaluator::new(extensions);
                let pval = evaluator.partial_interpret(expr)?;
                // The invariant on `from_restricted_partial_val_unchecked`
                // is satisfied because `expr` is a restricted expression,
                // and must still be restricted after `partial_interpret`.
                // The function call cannot return `Err` because `expr` is a
                // record, and partially evaluating a record expression will
                // yield a record expression or a record value.
                // PANIC SAFETY: See above
                #[allow(clippy::expect_used)]
                Ok(Self::from_restricted_partial_val_unchecked(pval).expect(
                    "`from_restricted_partial_val_unchecked` should succeed when called on a record.",
                ))
            }
            _ => Err(ContextCreationError::not_a_record(expr.to_owned().into())),
        }
    }

    /// Create a `Context` from a map of key to `RestrictedExpr`, or a Vec of
    /// `(key, RestrictedExpr)` pairs, or any other iterator of `(key, RestrictedExpr)` pairs
    ///
    /// `extensions` provides the `Extensions` which should be active for
    /// evaluating the `RestrictedExpr`.
    pub fn from_pairs(
        pairs: impl IntoIterator<Item = (SmolStr, RestrictedExpr)>,
        extensions: &Extensions<'_>,
    ) -> Result<Self, ContextCreationError> {
        match RestrictedExpr::record(pairs) {
            Ok(record) => Self::from_expr(record.as_borrowed(), extensions),
            Err(ExpressionConstructionError::DuplicateKey(err)) => Err(
                ExpressionConstructionError::DuplicateKey(err.with_context("in context")).into(),
            ),
        }
    }

    /// Create a `Context` from a string containing JSON (which must be a JSON
    /// object, not any other JSON type, or you will get an error here).
    /// JSON here must use the `__entity` and `__extn` escapes for entity
    /// references, extension values, etc.
    ///
    /// For schema-based parsing, use `ContextJsonParser`.
    pub fn from_json_str(json: &str) -> Result<Self, ContextJsonDeserializationError> {
        ContextJsonParser::new(None::<&NullContextSchema>, Extensions::all_available())
            .from_json_str(json)
    }

    /// Create a `Context` from a `serde_json::Value` (which must be a JSON
    /// object, not any other JSON type, or you will get an error here).
    /// JSON here must use the `__entity` and `__extn` escapes for entity
    /// references, extension values, etc.
    ///
    /// For schema-based parsing, use `ContextJsonParser`.
    pub fn from_json_value(
        json: serde_json::Value,
    ) -> Result<Self, ContextJsonDeserializationError> {
        ContextJsonParser::new(None::<&NullContextSchema>, Extensions::all_available())
            .from_json_value(json)
    }

    /// Create a `Context` from a JSON file.  The JSON file must contain a JSON
    /// object, not any other JSON type, or you will get an error here.
    /// JSON here must use the `__entity` and `__extn` escapes for entity
    /// references, extension values, etc.
    ///
    /// For schema-based parsing, use `ContextJsonParser`.
    pub fn from_json_file(
        json: impl std::io::Read,
    ) -> Result<Self, ContextJsonDeserializationError> {
        ContextJsonParser::new(None::<&NullContextSchema>, Extensions::all_available())
            .from_json_file(json)
    }

    /// Get the number of keys in this `Context`.
    pub fn num_keys(&self) -> usize {
        match self {
            Context::Value(record) => record.len(),
            Context::RestrictedResidual(record) => record.len(),
        }
    }

    /// Private helper function to implement `into_iter()` for `Context`.
    /// Gets an iterator over the (key, value) pairs in the `Context`, cloning
    /// only if necessary.
    ///
    /// Note that some error messages rely on this function returning keys in
    /// sorted order, or else the error message will not be fully deterministic.
    fn into_pairs(self) -> Box<dyn Iterator<Item = (SmolStr, RestrictedExpr)>> {
        match self {
            Context::Value(record) => Box::new(
                Arc::unwrap_or_clone(record)
                    .into_iter()
                    .map(|(k, v)| (k, RestrictedExpr::from(v))),
            ),
            Context::RestrictedResidual(record) => Box::new(
                Arc::unwrap_or_clone(record)
                    .into_iter()
                    // By INVARIANT(restricted), all attributes expressions are
                    // restricted expressions.
                    .map(|(k, v)| (k, RestrictedExpr::new_unchecked(v))),
            ),
        }
    }

    /// Substitute unknowns with concrete values in this context. If this is
    /// already a `Context::Value`, then this returns `self` unchanged and will
    /// not error. Otherwise delegate to [`Expr::substitute`].
    pub fn substitute(self, mapping: &HashMap<SmolStr, Value>) -> Result<Self, EvaluationError> {
        match self {
            Context::RestrictedResidual(residual_context) => {
                // From Invariant(Restricted), `residual_context` contains only
                // restricted expressions, so `Expr::record_arc` of the attributes
                // will also be a restricted expression. This doesn't change after
                // substitution, so we know `expr` must be a restricted expression.
                let expr = Expr::record_arc(residual_context).substitute(mapping);
                let expr = BorrowedRestrictedExpr::new_unchecked(&expr);

                let extns = Extensions::all_available();
                let eval = RestrictedEvaluator::new(extns);
                let partial_value = eval.partial_interpret(expr)?;

                // The invariant on `from_restricted_partial_val_unchecked`
                // is satisfied because `expr` is restricted and must still be
                // restricted after `partial_interpret`.
                // The function call cannot fail because because `expr` was
                // constructed as a record, and substitution and partial
                // evaluation does not change this.
                // PANIC SAFETY: See above
                #[allow(clippy::expect_used)]
                Ok(
                    Self::from_restricted_partial_val_unchecked(partial_value).expect(
                        "`from_restricted_partial_val_unchecked` should succeed when called on a record.",
                    ),
                )
            }
            Context::Value(_) => Ok(self),
        }
    }
}

/// Utilities for implementing `IntoIterator` for `Context`
mod iter {
    use super::*;

    /// `IntoIter` iterator for `Context`
    pub struct IntoIter(pub(super) Box<dyn Iterator<Item = (SmolStr, RestrictedExpr)>>);

    impl std::fmt::Debug for IntoIter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "IntoIter(<context>)")
        }
    }

    impl Iterator for IntoIter {
        type Item = (SmolStr, RestrictedExpr);

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }
    }
}

impl IntoIterator for Context {
    type Item = (SmolStr, RestrictedExpr);
    type IntoIter = iter::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        iter::IntoIter(self.into_pairs())
    }
}

impl From<Context> for RestrictedExpr {
    fn from(value: Context) -> Self {
        match value {
            Context::Value(attrs) => Value::record_arc(attrs, None).into(),
            Context::RestrictedResidual(attrs) => {
                // By INVARIANT(restricted), all attributes expressions are
                // restricted expressions, so the result of `record_arc` will be
                // a restricted expression.
                RestrictedExpr::new_unchecked(Expr::record_arc(attrs))
            }
        }
    }
}

impl From<Context> for PartialValue {
    fn from(ctx: Context) -> PartialValue {
        match ctx {
            Context::Value(attrs) => Value::record_arc(attrs, None).into(),
            Context::RestrictedResidual(attrs) => {
                // A `PartialValue::Residual` must contain an unknown in the
                // expression. By INVARIANT(unknown), at least one expr in
                // `attrs` contains an unknown, so the `record_arc` expression
                // contains at least one unknown.
                PartialValue::Residual(Expr::record_arc(attrs))
            }
        }
    }
}

impl std::default::Default for Context {
    fn default() -> Context {
        Context::empty()
    }
}

impl std::fmt::Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", PartialValue::from(self.clone()))
    }
}

impl BoundedDisplay for Context {
    fn fmt(&self, f: &mut impl std::fmt::Write, n: Option<usize>) -> std::fmt::Result {
        BoundedDisplay::fmt(&PartialValue::from(self.clone()), f, n)
    }
}

/// Errors while trying to create a `Context`
#[derive(Debug, Diagnostic, Error)]
pub enum ContextCreationError {
    /// Tried to create a `Context` out of something other than a record
    #[error(transparent)]
    #[diagnostic(transparent)]
    NotARecord(#[from] context_creation_errors::NotARecord),
    /// Error evaluating the expression given for the `Context`
    #[error(transparent)]
    #[diagnostic(transparent)]
    Evaluation(#[from] EvaluationError),
    /// Error constructing a record for the `Context`.
    /// Only returned by `Context::from_pairs()` and `Context::merge()`
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExpressionConstruction(#[from] ExpressionConstructionError),
}

impl ContextCreationError {
    pub(crate) fn not_a_record(expr: Expr) -> Self {
        Self::NotARecord(context_creation_errors::NotARecord {
            expr: Box::new(expr),
        })
    }
}

/// Error subtypes for [`ContextCreationError`]
pub mod context_creation_errors {
    use super::Expr;
    use crate::impl_diagnostic_from_method_on_field;
    use miette::Diagnostic;
    use thiserror::Error;

    /// Error type for an expression that needed to be a record, but is not
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Error)]
    #[error("expression is not a record: {expr}")]
    pub struct NotARecord {
        /// Expression which is not a record
        pub(super) expr: Box<Expr>,
    }

    // custom impl of `Diagnostic`: take source location from the `expr` field's `.source_loc()` method
    impl Diagnostic for NotARecord {
        impl_diagnostic_from_method_on_field!(expr, source_loc);
    }
}

/// Trait for schemas capable of validating `Request`s
pub trait RequestSchema {
    /// Error type returned when a request fails validation
    type Error: miette::Diagnostic;
    /// Validate the given `request`, returning `Err` if it fails validation
    fn validate_request(
        &self,
        request: &Request,
        extensions: &Extensions<'_>,
    ) -> Result<(), Self::Error>;

    /// Validate the given `context`, returning `Err` if it fails validation
    fn validate_context<'a>(
        &self,
        context: &Context,
        action: &EntityUID,
        extensions: &Extensions<'a>,
    ) -> std::result::Result<(), Self::Error>;

    /// Validate the scope variables, returning `Err` if it fails validation
    fn validate_scope_variables(
        &self,
        principal: Option<&EntityUID>,
        action: Option<&EntityUID>,
        resource: Option<&EntityUID>,
    ) -> std::result::Result<(), Self::Error>;
}

/// A `RequestSchema` that does no validation and always reports a passing result
#[derive(Debug, Clone)]
pub struct RequestSchemaAllPass;
impl RequestSchema for RequestSchemaAllPass {
    type Error = Infallible;
    fn validate_request(
        &self,
        _request: &Request,
        _extensions: &Extensions<'_>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn validate_context<'a>(
        &self,
        _context: &Context,
        _action: &EntityUID,
        _extensions: &Extensions<'a>,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn validate_scope_variables(
        &self,
        _principal: Option<&EntityUID>,
        _action: Option<&EntityUID>,
        _resource: Option<&EntityUID>,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}

/// Wrapper around `std::convert::Infallible` which also implements
/// `miette::Diagnostic`
#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
pub struct Infallible(pub std::convert::Infallible);

#[cfg(test)]
mod test {
    use super::*;
    use cool_asserts::assert_matches;

    #[test]
    fn test_json_from_str_non_record() {
        assert_matches!(
            Context::from_expr(RestrictedExpr::val("1").as_borrowed(), Extensions::none()),
            Err(ContextCreationError::NotARecord { .. })
        );
        assert_matches!(
            Context::from_json_str("1"),
            Err(ContextJsonDeserializationError::ContextCreation(
                ContextCreationError::NotARecord { .. }
            ))
        );
    }
}
