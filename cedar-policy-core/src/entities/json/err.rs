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
    BorrowedRestrictedExpr, EntityAttrEvaluationError, EntityUID, Expr, ExprKind, PartialValue,
    PolicyID, RestrictedExpr, RestrictedExpressionError,
};
use crate::entities::conformance::err::EntitySchemaConformanceError;
use crate::entities::{Name, ReservedNameError};
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
#[non_exhaustive]
pub enum JsonDeserializationError {
    /// Error thrown by the `serde_json` crate
    #[error(transparent)]
    #[diagnostic(transparent)]
    Serde(#[from] JsonError),
    /// Contents of an escape failed to parse.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ParseEscape(ParseEscape),
    /// Restricted expression error
    #[error(transparent)]
    #[diagnostic(transparent)]
    RestrictedExpressionError(#[from] RestrictedExpressionError),
    /// A field that needs to be a literal entity reference, was some other JSON value
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExpectedLiteralEntityRef(ExpectedLiteralEntityRef),
    /// A field that needs to be an extension value, was some other JSON value
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExpectedExtnValue(ExpectedExtnValue),
    /// Parents of actions should be actions, but this action has a non-action parent
    #[error(transparent)]
    #[diagnostic(transparent)]
    ActionParentIsNotAction(ActionParentIsNotAction),
    /// Schema-based parsing needed an implicit extension constructor, but no suitable
    /// constructor was found
    #[error(transparent)]
    #[diagnostic(transparent)]
    MissingImpliedConstructor(MissingImpliedConstructor),
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
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnexpectedRecordAttr(UnexpectedRecordAttr),
    /// During schema-based parsing, didn't encounter this attribute of a
    /// record, but that attribute should have existed
    #[error(transparent)]
    #[diagnostic(transparent)]
    MissingRequiredRecordAttr(MissingRequiredRecordAttr),
    /// During schema-based parsing, found a different type than the schema indicated.
    ///
    /// (This is used in all cases except inside entity attributes; type mismatches in
    /// entity attributes are reported as `Self::EntitySchemaConformance`. As of
    /// this writing, that means this should only be used for schema-based
    /// parsing of the `Context`.)
    #[error(transparent)]
    #[diagnostic(transparent)]
    TypeMismatch(TypeMismatch),
    /// During schema-based parsing, found a set whose elements don't all have
    /// the same type.  This doesn't match any possible schema.
    ///
    /// (This is used in all cases except inside entity attributes;
    /// heterogeneous sets in entity attributes are reported as
    /// `Self::EntitySchemaConformance`. As of this writing, that means this
    /// should only be used for schema-based parsing of the `Context`. Note that
    /// for non-schema-based parsing, heterogeneous sets are not an error.)
    #[error(transparent)]
    #[diagnostic(transparent)]
    HeterogeneousSet(HeterogeneousSet),
    /// During schema-based parsing, error looking up an extension function.
    /// This error can occur during schema-based parsing because that may
    /// require getting information about any extension functions referenced in
    /// the JSON.
    ///
    /// (This is used in all cases except inside entity attributes; extension
    /// function lookup errors in entity attributes are reported as
    /// `Self::EntitySchemaConformance`. As of this writing, that means this
    /// should only be used for schema-based parsing of the `Context`.)
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExtensionFunctionLookup(ExtensionFunctionLookup),
    /// During schema-based parsing, found an unknown in an _argument_ to an
    /// extension function being processed in implicit-constructor form. This is
    /// not currently supported.
    /// To pass an unknown to an extension function, use the
    /// explicit-constructor form.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnknownInImplicitConstructorArg(UnknownInImplicitConstructorArg),
    /// Raised when a JsonValue contains the no longer supported `__expr` escape
    #[error("{0}, the `__expr` escape is no longer supported")]
    #[diagnostic(help("to create an entity reference, use `__entity`; to create an extension value, use `__extn`; and for all other values, use JSON directly"))]
    ExprTag(Box<JsonDeserializationErrorContext>),
    /// Raised when the input JSON contains a `null`
    #[error("{0}, found a `null`; JSON `null`s are not allowed in Cedar")]
    Null(Box<JsonDeserializationErrorContext>),
    /// Returned when a name contains `__cedar`
    #[error(transparent)]
    #[diagnostic(transparent)]
    ReservedName(#[from] ReservedNameError),
}

impl JsonDeserializationError {
    pub(crate) fn parse_escape(
        kind: EscapeKind,
        value: impl Into<String>,
        errs: ParseErrors,
    ) -> Self {
        Self::ParseEscape(ParseEscape {
            kind,
            value: value.into(),
            errs,
        })
    }

    pub(crate) fn expected_entity_ref(
        ctx: JsonDeserializationErrorContext,
        got: Either<serde_json::Value, Expr>,
    ) -> Self {
        Self::ExpectedLiteralEntityRef(ExpectedLiteralEntityRef {
            ctx: Box::new(ctx),
            got: Box::new(got),
        })
    }

    pub(crate) fn expected_extn_value(
        ctx: JsonDeserializationErrorContext,
        got: Either<serde_json::Value, Expr>,
    ) -> Self {
        Self::ExpectedExtnValue(ExpectedExtnValue {
            ctx: Box::new(ctx),
            got: Box::new(got),
        })
    }

    pub(crate) fn action_parent_is_not_action(uid: EntityUID, parent: EntityUID) -> Self {
        Self::ActionParentIsNotAction(ActionParentIsNotAction { uid, parent })
    }

    pub(crate) fn missing_implied_constructor(
        ctx: JsonDeserializationErrorContext,
        return_type: SchemaType,
        arg_type: SchemaType,
    ) -> Self {
        Self::MissingImpliedConstructor(MissingImpliedConstructor {
            ctx: Box::new(ctx),
            return_type: Box::new(return_type),
            arg_type: Box::new(arg_type),
        })
    }

    pub(crate) fn duplicate_key(
        ctx: JsonDeserializationErrorContext,
        key: impl Into<SmolStr>,
    ) -> Self {
        Self::DuplicateKey(DuplicateKey {
            ctx: Box::new(ctx),
            key: key.into(),
        })
    }

    pub(crate) fn unexpected_record_attr(
        ctx: JsonDeserializationErrorContext,
        record_attr: impl Into<SmolStr>,
    ) -> Self {
        Self::UnexpectedRecordAttr(UnexpectedRecordAttr {
            ctx: Box::new(ctx),
            record_attr: record_attr.into(),
        })
    }

    pub(crate) fn missing_required_record_attr(
        ctx: JsonDeserializationErrorContext,
        record_attr: impl Into<SmolStr>,
    ) -> Self {
        Self::MissingRequiredRecordAttr(MissingRequiredRecordAttr {
            ctx: Box::new(ctx),
            record_attr: record_attr.into(),
        })
    }

    pub(crate) fn type_mismatch(
        ctx: JsonDeserializationErrorContext,
        err: TypeMismatchError,
    ) -> Self {
        Self::TypeMismatch(TypeMismatch {
            ctx: Box::new(ctx),
            err,
        })
    }

    pub(crate) fn heterogeneous_set(
        ctx: JsonDeserializationErrorContext,
        err: HeterogeneousSetError,
    ) -> Self {
        Self::HeterogeneousSet(HeterogeneousSet {
            ctx: Box::new(ctx),
            err,
        })
    }

    pub(crate) fn extension_function_lookup(
        ctx: JsonDeserializationErrorContext,
        err: ExtensionFunctionLookupError,
    ) -> Self {
        Self::ExtensionFunctionLookup(ExtensionFunctionLookup {
            ctx: Box::new(ctx),
            err,
        })
    }

    pub(crate) fn unknown_in_implicit_constructor_arg(
        ctx: JsonDeserializationErrorContext,
        arg: RestrictedExpr,
    ) -> Self {
        Self::UnknownInImplicitConstructorArg(UnknownInImplicitConstructorArg {
            ctx: Box::new(ctx),
            arg: Box::new(arg),
        })
    }
}

#[derive(Debug, Error, Diagnostic)]
#[error("{}, argument `{}` to implicit constructor contains an unknown; this is not currently supported", .ctx, .arg)]
#[diagnostic(help(
        r#"expected an extension value here because of the schema. To pass an unknown to an extension function, use the explicit constructor form: `{{ "fn": "SomeFn", "arg": "SomeArg" }}`"#
    ))]
/// Error type for constructors containing an unknown
pub struct UnknownInImplicitConstructorArg {
    /// Context of this error
    ctx: Box<JsonDeserializationErrorContext>,
    /// Argument which contains an unknown
    arg: Box<RestrictedExpr>,
}
#[derive(Debug, Error, Diagnostic)]
#[error("{ctx}, {err}")]
/// Error type for heterogeneous sets
pub struct HeterogeneousSet {
    /// Context of this error, which will be something other than `EntityAttribute`.
    /// (Heterogeneous sets in entity attributes are reported as
    /// `Self::EntitySchemaConformance`.)
    ctx: Box<JsonDeserializationErrorContext>,
    /// Underlying error
    #[diagnostic(transparent)]
    err: HeterogeneousSetError,
}

#[derive(Debug, Error, Diagnostic)]
#[error("{ctx}, {err}")]
/// Error type for extension function lookup errors
pub struct ExtensionFunctionLookup {
    /// Context of this error, which will be something other than
    /// `EntityAttribute`.
    /// (Extension function lookup errors in entity attributes are reported
    /// as `Self::EntitySchemaConformance`.)
    ctx: Box<JsonDeserializationErrorContext>,
    /// Underlying error
    #[diagnostic(transparent)]
    err: ExtensionFunctionLookupError,
}

#[derive(Debug, Error, Diagnostic)]
#[error("{ctx}, {err}")]
/// General error for type mismatches
pub struct TypeMismatch {
    /// Context of this error, which will be something other than `EntityAttribute`.
    /// (Type mismatches in entity attributes are reported as
    /// `Self::EntitySchemaConformance`.)
    ctx: Box<JsonDeserializationErrorContext>,
    /// Underlying error
    #[diagnostic(transparent)]
    err: TypeMismatchError,
}

#[derive(Debug, Error, Diagnostic)]
#[error("{}, expected the record to have an attribute `{}`, but it does not", .ctx, .record_attr)]
/// Error type for a record missing a required attr
pub struct MissingRequiredRecordAttr {
    /// Context of this error
    ctx: Box<JsonDeserializationErrorContext>,
    /// Name of the (Record) attribute which was expected
    record_attr: SmolStr,
}

#[derive(Debug, Diagnostic, Error)]
#[error("{}, record attribute `{}` should not exist according to the schema", .ctx, .record_attr)]
/// Error type for record attributes that should not exist
pub struct UnexpectedRecordAttr {
    /// Context of this error
    ctx: Box<JsonDeserializationErrorContext>,
    /// Name of the (Record) attribute which was unexpected
    record_attr: SmolStr,
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

#[derive(Debug, Error, Diagnostic)]
#[error("{}, missing extension constructor for {} -> {}", .ctx, .arg_type, .return_type)]
#[diagnostic(help("expected a value of type {} because of the schema", .return_type))]
/// Error type for missing extesnsion contructors
pub struct MissingImpliedConstructor {
    /// Context of this error
    ctx: Box<JsonDeserializationErrorContext>,
    /// return type of the constructor we were looking for
    return_type: Box<SchemaType>,
    /// argument type of the constructor we were looking for
    arg_type: Box<SchemaType>,
}

#[derive(Debug, Error, Diagnostic)]
#[error("action `{}` has a non-action parent `{}`", .uid, .parent)]
#[diagnostic(help("parents of actions need to have type `Action` themselves, perhaps namespaced"))]
/// Error type for action  parents not having type `Action`
pub struct ActionParentIsNotAction {
    /// Action entity that had the invalid parent
    uid: EntityUID,
    /// Parent that is invalid
    parent: EntityUID,
}

#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse escape `{kind}`: {value}, errors: {errs}")]
#[diagnostic(help("{}", match .kind {
        EscapeKind::Entity => r#"an __entity escape should have a value like `{ "type": "SomeType", "id": "SomeId" }`"#,
        EscapeKind::Extension => r#"an __extn escape should have a value like `{ "fn": "SomeFn", "arg": "SomeArg" }`"#,
    }))]
/// Error type for incorrect escaping
pub struct ParseEscape {
    /// Escape kind
    kind: EscapeKind,
    /// Escape value at fault
    value: String,
    /// Parse errors
    #[diagnostic(transparent)]
    errs: ParseErrors,
}

#[derive(Debug, Error, Diagnostic)]
#[error("{}, expected a literal entity reference, but got `{}`", .ctx, display_json_value(.got.as_ref()))]
#[diagnostic(help(
    r#"literal entity references can be made with `{{ "type": "SomeType", "id": "SomeId" }}`"#
))]
/// Error type for getting any expression other than an entity reference
pub struct ExpectedLiteralEntityRef {
    /// Context of this error
    ctx: Box<JsonDeserializationErrorContext>,
    /// the expression we got instead
    got: Box<Either<serde_json::Value, Expr>>,
}

#[derive(Debug, Error, Diagnostic)]
#[error("{}, expected an extension value, but got `{}`", .ctx, display_json_value(.got.as_ref()))]
#[diagnostic(help(r#"extension values can be made with `{{ "fn": "SomeFn", "id": "SomeId" }}`"#))]
/// Error type for getting any expression other than en extesion value
pub struct ExpectedExtnValue {
    /// Context of this error
    ctx: Box<JsonDeserializationErrorContext>,
    /// the expression we got instead
    got: Box<Either<serde_json::Value, Expr>>,
}

#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
/// Wrapper type for errors from `serde_json`
pub struct JsonError(#[from] serde_json::Error);

impl From<serde_json::Error> for JsonDeserializationError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serde(JsonError(value))
    }
}

impl From<serde_json::Error> for JsonSerializationError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serde(JsonError(value))
    }
}

/// Errors thrown during serialization to JSON
#[derive(Debug, Diagnostic, Error)]
#[non_exhaustive]
pub enum JsonSerializationError {
    /// Error thrown by `serde_json`
    #[error(transparent)]
    #[diagnostic(transparent)]
    Serde(#[from] JsonError),
    /// Extension-function calls with 0 arguments are not currently supported in
    /// our JSON format.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExtnCall0Arguments(ExtnCall0Arguments),
    /// Extension-function calls with 2 or more arguments are not currently
    /// supported in our JSON format.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExtnCall2OrMoreArguments(ExtnCall2OrMoreArguments),
    /// Encountered a `Record` which can't be serialized to JSON because it
    /// contains a key which is reserved as a JSON escape.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ReservedKey(ReservedKey),
    /// Encountered an `ExprKind` which we didn't expect. Either a case is
    /// missing in `CedarValueJson::from_expr()`, or an internal invariant was
    /// violated and there is a non-restricted expression in `RestrictedExpr`
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnexpectedRestrictedExprKind(UnexpectedRestrictedExprKind),
    /// Encountered a (partial-evaluation) residual which can't be encoded in
    /// JSON
    #[error(transparent)]
    #[diagnostic(transparent)]
    Residual(Residual),
}

impl JsonSerializationError {
    pub(crate) fn call_0_args(func: Name) -> Self {
        Self::ExtnCall0Arguments(ExtnCall0Arguments { func })
    }

    pub(crate) fn call_2_or_more_args(func: Name) -> Self {
        Self::ExtnCall2OrMoreArguments(ExtnCall2OrMoreArguments { func })
    }

    pub(crate) fn reserved_key(key: impl Into<SmolStr>) -> Self {
        Self::ReservedKey(ReservedKey { key: key.into() })
    }

    pub(crate) fn unexpected_restricted_expr_kind(kind: ExprKind) -> Self {
        Self::UnexpectedRestrictedExprKind(UnexpectedRestrictedExprKind { kind })
    }

    pub(crate) fn residual(residual: Expr) -> Self {
        Self::Residual(Residual { residual })
    }
}

/// Error type for extension functions called w/ 0 arguments
#[derive(Debug, Error, Diagnostic)]
#[error("unsupported call to `{}` with 0 arguments", .func)]
#[diagnostic(help(
    "extension function calls with 0 arguments are not currently supported in our JSON format"
))]
pub struct ExtnCall0Arguments {
    /// Name of the function which was called with 0 arguments
    func: Name,
}

/// Error type for extension functions called w/ 2+ arguments
#[derive(Debug, Error, Diagnostic)]
#[error("unsupported call to `{}` with 2 or more arguments", .func)]
#[diagnostic(help("extension function calls with 2 or more arguments are not currently supported in our JSON format"))]
pub struct ExtnCall2OrMoreArguments {
    /// Name of the function called w/ 2 or more arguments
    func: Name,
}

/// Error type for using a reserved key in a record
#[derive(Debug, Error, Diagnostic)]
#[error("record uses reserved key `{}`", .key)]
pub struct ReservedKey {
    /// The reserved key used
    key: SmolStr,
}

impl ReservedKey {
    /// The reserved keyword used as a key
    pub fn key(&self) -> impl AsRef<str> + '_ {
        &self.key
    }
}

/// Error type for a restricted expression containing a non-restricted expression
#[derive(Debug, Error, Diagnostic)]
#[error("unexpected restricted expression `{:?}`", .kind)]
pub struct UnexpectedRestrictedExprKind {
    /// The [`ExprKind`] we didn't expend to find
    kind: ExprKind,
}

/// Error type for residuals that can't be serialized
#[derive(Debug, Error, Diagnostic)]
#[error("cannot encode residual as JSON: {}", .residual)]
pub struct Residual {
    /// The residual that can't be serialized
    residual: Expr,
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
