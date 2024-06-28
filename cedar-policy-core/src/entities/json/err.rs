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

use std::fmt::Display;

use super::{HeterogeneousSetError, SchemaType};
use crate::ast::{
    BorrowedRestrictedExpr, ContextCreationError, EntityAttrEvaluationError, EntityUID, Expr,
    ExprKind, Name, PartialValue, PolicyID, RestrictedExpr, RestrictedExprError,
};
use crate::entities::conformance::EntitySchemaConformanceError;
use crate::extensions::ExtensionFunctionLookupError;
use crate::parser::err::ParseErrors;
use either::Either;
use itertools::Itertools;
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

/// Escape kind
#[derive(Debug)]
pub enum EscapeKind {
    /// Escape `__entity`
    Entity,
    /// Escape `__extn`
    Extension,
}

impl Display for EscapeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Entity => write!(f, "__entity"),
            Self::Extension => write!(f, "__extn"),
        }
    }
}

/// Errors thrown during deserialization from JSON
#[derive(Debug, Diagnostic, Error)]
pub enum JsonDeserializationError {
    /// Error thrown by the `serde_json` crate
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    /// Contents of an escape failed to parse.
    #[error("failed to parse escape `{kind}`: {value}, errors: {errs}")]
    #[diagnostic(help("{}", match .kind {
        EscapeKind::Entity => r#"an __entity escape should have a value like `{ "type": "SomeType", "id": "SomeId" }`"#,
        EscapeKind::Extension => r#"an __extn escape should have a value like `{ "fn": "SomeFn", "arg": "SomeArg" }`"#,
    }))]
    ParseEscape {
        /// Escape kind
        kind: EscapeKind,
        /// Escape value at fault
        value: String,
        /// Parse errors
        #[diagnostic(transparent)]
        errs: ParseErrors,
    },
    /// Restricted expression error
    #[error(transparent)]
    #[diagnostic(transparent)]
    RestrictedExpressionError(#[from] RestrictedExprError),
    /// A field that needs to be a literal entity reference, was some other JSON value
    #[error("{ctx}, expected a literal entity reference, but got `{}`", display_json_value(.got.as_ref()))]
    #[diagnostic(help(
        r#"literal entity references can be made with `{{ "type": "SomeType", "id": "SomeId" }}`"#
    ))]
    ExpectedLiteralEntityRef {
        /// Context of this error
        ctx: Box<JsonDeserializationErrorContext>,
        /// the expression we got instead
        got: Box<Either<serde_json::Value, Expr>>,
    },
    /// A field that needs to be an extension value, was some other JSON value
    #[error("{ctx}, expected an extension value, but got `{}`", display_json_value(.got.as_ref()))]
    #[diagnostic(help(
        r#"extension values can be made with `{{ "fn": "SomeFn", "id": "SomeId" }}`"#
    ))]
    ExpectedExtnValue {
        /// Context of this error
        ctx: Box<JsonDeserializationErrorContext>,
        /// the expression we got instead
        got: Box<Either<serde_json::Value, Expr>>,
    },
    /// Errors creating the request context from JSON
    #[error("while parsing context, {0}")]
    #[diagnostic(transparent)]
    ContextCreation(#[from] ContextCreationError),
    /// Parents of actions should be actions, but this action has a non-action parent
    #[error("action `{uid}` has a non-action parent `{parent}`")]
    #[diagnostic(help(
        "parents of actions need to have type `Action` themselves, perhaps namespaced"
    ))]
    ActionParentIsNotAction {
        /// Action entity that had the invalid parent
        uid: EntityUID,
        /// Parent that is invalid
        parent: EntityUID,
    },
    /// Schema-based parsing needed an implicit extension constructor, but no suitable
    /// constructor was found
    #[error("{ctx}, missing extension constructor for {arg_type} -> {return_type}")]
    #[diagnostic(help("expected a value of type {return_type} because of the schema"))]
    MissingImpliedConstructor {
        /// Context of this error
        ctx: Box<JsonDeserializationErrorContext>,
        /// return type of the constructor we were looking for
        return_type: Box<SchemaType>,
        /// argument type of the constructor we were looking for
        arg_type: Box<SchemaType>,
    },
    /// The same key appears two or more times in a single record
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateKey(DuplicateKey),
    /// Error when evaluating an entity attribute
    #[error(transparent)]
    #[diagnostic(transparent)]
    EntityAttributeEvaluation(#[from] EntityAttrEvaluationError),
    /// During schema-based parsing, encountered an entity which does not
    /// conform to the schema.
    ///
    /// This error contains the `Entity` analogues some of the other errors
    /// listed below, among other things.
    #[error(transparent)]
    #[diagnostic(transparent)]
    EntitySchemaConformance(EntitySchemaConformanceError),
    /// During schema-based parsing, encountered this attribute on a record, but
    /// that attribute shouldn't exist on that record
    #[error("{ctx}, record attribute `{record_attr}` should not exist according to the schema")]
    UnexpectedRecordAttr {
        /// Context of this error
        ctx: Box<JsonDeserializationErrorContext>,
        /// Name of the (Record) attribute which was unexpected
        record_attr: SmolStr,
    },
    /// During schema-based parsing, didn't encounter this attribute of a
    /// record, but that attribute should have existed
    #[error("{ctx}, expected the record to have an attribute `{record_attr}`, but it does not")]
    MissingRequiredRecordAttr {
        /// Context of this error
        ctx: Box<JsonDeserializationErrorContext>,
        /// Name of the (Record) attribute which was expected
        record_attr: SmolStr,
    },
    /// During schema-based parsing, found a different type than the schema indicated.
    ///
    /// (This is used in all cases except inside entity attributes; type mismatches in
    /// entity attributes are reported as `Self::EntitySchemaConformance`. As of
    /// this writing, that means this should only be used for schema-based
    /// parsing of the `Context`.)
    #[error("{ctx}, {err}")]
    TypeMismatch {
        /// Context of this error, which will be something other than `EntityAttribute`.
        /// (Type mismatches in entity attributes are reported as
        /// `Self::EntitySchemaConformance`.)
        ctx: Box<JsonDeserializationErrorContext>,
        /// Underlying error
        #[diagnostic(transparent)]
        err: TypeMismatchError,
    },
    /// During schema-based parsing, found a set whose elements don't all have
    /// the same type.  This doesn't match any possible schema.
    ///
    /// (This is used in all cases except inside entity attributes;
    /// heterogeneous sets in entity attributes are reported as
    /// `Self::EntitySchemaConformance`. As of this writing, that means this
    /// should only be used for schema-based parsing of the `Context`. Note that
    /// for non-schema-based parsing, heterogeneous sets are not an error.)
    #[error("{ctx}, {err}")]
    HeterogeneousSet {
        /// Context of this error, which will be something other than `EntityAttribute`.
        /// (Heterogeneous sets in entity attributes are reported as
        /// `Self::EntitySchemaConformance`.)
        ctx: Box<JsonDeserializationErrorContext>,
        /// Underlying error
        #[diagnostic(transparent)]
        err: HeterogeneousSetError,
    },
    /// During schema-based parsing, error looking up an extension function.
    /// This error can occur during schema-based parsing because that may
    /// require getting information about any extension functions referenced in
    /// the JSON.
    ///
    /// (This is used in all cases except inside entity attributes; extension
    /// function lookup errors in entity attributes are reported as
    /// `Self::EntitySchemaConformance`. As of this writing, that means this
    /// should only be used for schema-based parsing of the `Context`.)
    #[error("{ctx}, {err}")]
    ExtensionFunctionLookup {
        /// Context of this error, which will be something other than
        /// `EntityAttribute`.
        /// (Extension function lookup errors in entity attributes are reported
        /// as `Self::EntitySchemaConformance`.)
        ctx: Box<JsonDeserializationErrorContext>,
        /// Underlying error
        #[diagnostic(transparent)]
        err: ExtensionFunctionLookupError,
    },
    /// During schema-based parsing, found an unknown in an _argument_ to an
    /// extension function being processed in implicit-constructor form. This is
    /// not currently supported.
    /// To pass an unknown to an extension function, use the
    /// explicit-constructor form.
    #[error("{ctx}, argument `{arg}` to implicit constructor contains an unknown; this is not currently supported")]
    #[diagnostic(help(
        r#"expected an extension value here because of the schema. To pass an unknown to an extension function, use the explicit constructor form: `{{ "fn": "SomeFn", "arg": "SomeArg" }}`"#
    ))]
    UnknownInImplicitConstructorArg {
        /// Context of this error
        ctx: Box<JsonDeserializationErrorContext>,
        /// Argument which contains an unknown
        arg: Box<RestrictedExpr>,
    },
    /// Raised when a JsonValue contains the no longer supported `__expr` escape
    #[error("{0}, the `__expr` escape is no longer supported")]
    #[diagnostic(help("to create an entity reference, use `__entity`; to create an extension value, use `__extn`; and for all other values, use JSON directly"))]
    ExprTag(Box<JsonDeserializationErrorContext>),
    /// Raised when the input JSON contains a `null`
    #[error("{0}, found a `null`; JSON `null`s are not allowed in Cedar")]
    Null(Box<JsonDeserializationErrorContext>),
}

impl JsonDeserializationError {
    pub(crate) fn duplicate_key(
        ctx: JsonDeserializationErrorContext,
        key: impl Into<SmolStr>,
    ) -> Self {
        Self::DuplicateKey(DuplicateKey {
            ctx: Box::new(ctx),
            key: key.into(),
        })
    }
}

#[derive(Debug, Error, Diagnostic)]
#[error("{}, duplicate key `{}` in record", .ctx, .key)]
/// Error type for records having duplicate keys
pub struct DuplicateKey {
    /// Context of this error
    ctx: Box<JsonDeserializationErrorContext>,
    /// The key that appeared two or more times
    key: SmolStr,
}

/// Errors thrown during serialization to JSON
#[derive(Debug, Diagnostic, Error)]
pub enum JsonSerializationError {
    /// Error thrown by `serde_json`
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    /// Extension-function calls with 0 arguments are not currently supported in
    /// our JSON format.
    #[error("unsupported call to `{func}` with 0 arguments")]
    #[diagnostic(help(
        "extension function calls with 0 arguments are not currently supported in our JSON format"
    ))]
    ExtnCall0Arguments {
        /// Name of the function which was called with 0 arguments
        func: Name,
    },
    /// Extension-function calls with 2 or more arguments are not currently
    /// supported in our JSON format.
    #[error("unsupported call to `{func}` with 2 or more arguments")]
    #[diagnostic(help("extension function calls with 2 or more arguments are not currently supported in our JSON format"))]
    ExtnCall2OrMoreArguments {
        /// Name of the function which was called with 2 or more arguments
        func: Name,
    },
    /// Encountered a `Record` which can't be serialized to JSON because it
    /// contains a key which is reserved as a JSON escape.
    #[error("record uses reserved key `{key}`")]
    ReservedKey {
        /// Reserved key which was used by the `Record`
        key: SmolStr,
    },
    /// Encountered an `ExprKind` which we didn't expect. Either a case is
    /// missing in `CedarValueJson::from_expr()`, or an internal invariant was
    /// violated and there is a non-restricted expression in `RestrictedExpr`
    #[error("unexpected restricted expression `{kind:?}`")]
    UnexpectedRestrictedExprKind {
        /// `ExprKind` which we didn't expect to find
        kind: ExprKind,
    },
    /// Encountered a (partial-evaluation) residual which can't be encoded in
    /// JSON
    #[error("cannot encode residual as JSON: {residual}")]
    Residual {
        /// Residual which can't be encoded in JSON
        residual: Expr,
    },
}

/// Gives information about the context of a JSON deserialization error (e.g.,
/// where we were in the JSON document).
#[derive(Debug, Clone)]
pub enum JsonDeserializationErrorContext {
    /// The error occurred while deserializing the attribute `attr` of an entity.
    EntityAttribute {
        /// Entity where the error occurred
        uid: EntityUID,
        /// Attribute where the error occurred
        attr: SmolStr,
    },
    /// The error occurred while deserializing the `parents` field of an entity.
    EntityParents {
        /// Entity where the error occurred
        uid: EntityUID,
    },
    /// The error occurred while deserializing the `uid` field of an entity.
    EntityUid,
    /// The error occurred while deserializing the `Context`.
    Context,
    /// The error occurred while deserializing a policy in JSON (EST) form.
    Policy {
        /// ID of the policy we were deserializing
        id: PolicyID,
    },
    /// The error occured while deserializing a template link
    TemplateLink,
    /// The context was unknown, this shouldn't surface to users
    Unknown,
}

/// Type mismatch error (in terms of `SchemaType`)
#[derive(Debug, Diagnostic, Error)]
#[error("type mismatch: value was expected to have type {expected}, but {}: `{}`",
    match .actual_ty {
        Some(actual_ty) => format!("actually has type {actual_ty}"),
        None => "it does not".to_string(),
    },
    match .actual_val {
        Either::Left(pval) => format!("{pval}"),
        Either::Right(expr) => display_restricted_expr(expr.as_borrowed()),
    }
)]
pub struct TypeMismatchError {
    /// Type which was expected
    pub expected: Box<SchemaType>,
    /// Type which was encountered instead. May be `None` in the case that
    /// the encountered value was an `Unknown` with insufficient type
    /// information to produce a `SchemaType`
    pub actual_ty: Option<Box<SchemaType>>,
    /// Value which doesn't have the expected type; represented as either a
    /// PartialValue or RestrictedExpr, whichever is more convenient for the
    /// caller
    pub actual_val: Either<PartialValue, Box<RestrictedExpr>>,
}

impl std::fmt::Display for JsonDeserializationErrorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EntityAttribute { uid, attr } => write!(f, "in attribute `{attr}` on `{uid}`"),
            Self::EntityParents { uid } => write!(f, "in parents field of `{uid}`"),
            Self::EntityUid => write!(f, "in uid field of <unknown entity>"),
            Self::Context => write!(f, "while parsing context"),
            Self::Policy { id } => write!(f, "while parsing JSON policy `{id}`"),
            Self::TemplateLink => write!(f, "while parsing a template link"),
            Self::Unknown => write!(f, "parsing context was unknown, please file a bug report at https://github.com/cedar-policy/cedar so we can improve this error message"),
        }
    }
}

fn display_json_value(v: &Either<serde_json::Value, Expr>) -> String {
    match v {
        Either::Left(json) => display_value(json),
        Either::Right(e) => e.to_string(),
    }
}

/// Display a `serde_json::Value`, but sorting object attributes, so that the
/// output is deterministic (important for tests that check equality of error
/// messages).
///
/// Note that this doesn't sort array elements, because JSON arrays are ordered,
/// so all JSON-handling functions naturally preserve order for arrays and thus
/// provide a deterministic output.
fn display_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Array(contents) => {
            format!("[{}]", contents.iter().map(display_value).join(", "))
        }
        serde_json::Value::Object(map) => {
            let mut v: Vec<_> = map.iter().collect();
            // We sort the keys here so that our error messages are consistent and defined
            v.sort_by_key(|p| p.0);
            let display_kv = |kv: &(&String, &serde_json::Value)| format!("\"{}\":{}", kv.0, kv.1);
            format!("{{{}}}", v.iter().map(display_kv).join(","))
        }
        other => other.to_string(),
    }
}

/// Display a `RestrictedExpr`, but sorting record attributes and set elements,
/// so that the output is deterministic (important for tests that check equality
/// of error messages).
fn display_restricted_expr(expr: BorrowedRestrictedExpr<'_>) -> String {
    match expr.expr_kind() {
        ExprKind::Set(elements) => {
            let restricted_exprs = elements.iter().map(BorrowedRestrictedExpr::new_unchecked); // since the RestrictedExpr invariant holds for the input, it holds for all set elements
            format!(
                "[{}]",
                restricted_exprs
                    .map(display_restricted_expr)
                    .sorted_unstable()
                    .join(", ")
            )
        }
        ExprKind::Record(m) => {
            format!(
                "{{{}}}",
                m.iter()
                    .sorted_unstable_by_key(|(k, _)| SmolStr::clone(k))
                    .map(|(k, v)| format!("\"{}\": {}", k.escape_debug(), v))
                    .join(", ")
            )
        }
        _ => format!("{expr}"), // all other cases: use the normal Display
    }
}
